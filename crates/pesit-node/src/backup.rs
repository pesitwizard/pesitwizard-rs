//! Configuration backup and restore: export every configuration table (and certificate material)
//! as one JSON bundle, and import it back.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use pesit_app::audit::Outcome;
use pesit_app::http::ApiError;
use pesit_app::store::JsonStore;
use pesit_app::time::now_iso;
use serde_json::{json, Value};

use crate::api::App;

/// Store tables carried in a backup (configuration only — not transfer records).
pub const CONFIG_TABLES: [&str; 9] = [
    "partners",
    "virtual_files",
    "remote_partners",
    "servers",
    "remote_servers",
    "client_partners",
    "connectors",
    "schedules",
    "pki",
];

/// Shared-policy tables replicated live across the cluster (listeners stay node-local).
pub const CLUSTER_TABLES: [&str; 4] = ["partners", "virtual_files", "remote_partners", "schedules"];

/// Backup routes (merged into the admin router).
pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/backup", get(export))
        .route("/api/v1/backup/restore", post(restore))
}

/// Snapshot every configuration table as a `{table: [rows]}` object.
pub fn dump(store: &JsonStore) -> Result<Value, ApiError> {
    dump_only(store, &CONFIG_TABLES)
}

/// Sign a bundle: add a detached ECDSA signature over the canonical bytes of the bundle without
/// its `signature` field, if a local CA is available. A bundle without a CA is left unsigned.
#[must_use]
pub fn sign_bundle(pki: Option<&crate::pki::PkiState>, bundle: Value) -> Value {
    use base64::Engine;
    let Value::Object(mut map) = bundle else {
        return bundle;
    };
    map.remove("signature");
    let canonical = serde_json::to_vec(&Value::Object(map.clone())).unwrap_or_default();
    if let Some(sig) = pki.and_then(|p| p.sign_data(&canonical)) {
        let value = base64::engine::general_purpose::STANDARD.encode(sig);
        map.insert(
            "signature".into(),
            json!({ "algorithm": pesit_pki::sign::ALGORITHM, "value": value }),
        );
    }
    Value::Object(map)
}

/// Verify a bundle's signature, if present, against the CA certificate embedded in it. An unsigned
/// bundle passes. Returns an error only when a present signature does not verify.
pub fn verify_bundle(bundle: &Value) -> Result<(), String> {
    use base64::Engine;
    let Some(sig_obj) = bundle.get("signature") else {
        return Ok(());
    };
    let value = sig_obj
        .get("value")
        .and_then(Value::as_str)
        .ok_or("signature has no value")?;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| "signature is not valid base64")?;
    let cert = bundle
        .get("pki")
        .and_then(|p| p.get("ca"))
        .and_then(|c| c.get("certificate"))
        .and_then(Value::as_str)
        .ok_or("signed bundle carries no CA certificate to verify against")?;
    let mut map = bundle
        .as_object()
        .cloned()
        .ok_or("bundle is not an object")?;
    map.remove("signature");
    let canonical = serde_json::to_vec(&Value::Object(map)).map_err(|e| e.to_string())?;
    match pesit_pki::sign::verify_bytes(cert, &canonical, &sig) {
        Ok(true) => Ok(()),
        Ok(false) => Err("bundle signature does not verify against its CA".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// Snapshot a chosen set of tables as a `{table: [rows]}` object.
pub fn dump_only(store: &JsonStore, which: &[&str]) -> Result<Value, ApiError> {
    let mut tables = serde_json::Map::new();
    for t in which.iter().copied() {
        store.ensure_table(t)?;
        let rows: Vec<Value> = store.list(t)?;
        tables.insert(t.to_owned(), Value::Array(rows));
    }
    Ok(Value::Object(tables))
}

async fn export(State(app): State<Arc<App>>) -> Result<Json<Value>, ApiError> {
    let tables = dump(&app.store)?;
    let pki = app
        .pki
        .as_ref()
        .map_or(Value::Null, |p| p.export_material());
    app.audit
        .record("system", "backup", None, None, Outcome::Success, None);
    let bundle = json!({
        "version": 1,
        "generatedAt": now_iso(),
        "node": env!("CARGO_PKG_VERSION"),
        "tables": tables,
        "pki": pki,
    });
    Ok(Json(sign_bundle(app.pki.as_deref(), bundle)))
}

/// Apply a `{table: [rows]}` map to the store, returning how many records were written.
pub fn apply_tables(
    store: &JsonStore,
    tables: &serde_json::Map<String, Value>,
) -> Result<usize, ApiError> {
    let mut restored = 0usize;
    for (table, rows) in tables {
        if !CONFIG_TABLES.contains(&table.as_str()) {
            continue;
        }
        store.ensure_table(table)?;
        let Value::Array(items) = rows else { continue };
        for item in items {
            if let Some(key) = backup_key(table, item) {
                store.put(table, &key, item)?;
                restored += 1;
            }
        }
    }
    Ok(restored)
}

async fn restore(
    State(app): State<Arc<App>>,
    Json(bundle): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    verify_bundle(&bundle).map_err(|e| ApiError::bad_request(format!("backup rejected: {e}")))?;
    let tables = bundle
        .get("tables")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let restored = apply_tables(&app.store, &tables)?;
    if let Some(p) = &app.pki {
        if let Some(pki_val) = bundle.get("pki").filter(|v| !v.is_null()) {
            p.import_material(pki_val)
                .map_err(|e| ApiError::internal(e.to_string()))?;
        }
    }
    app.audit.record(
        "system",
        "restore",
        None,
        None,
        Outcome::Success,
        Some(format!("{restored} records")),
    );
    tracing::info!("restored {restored} configuration records from a backup");
    Ok(Json(json!({ "restored": restored })))
}

/// The store key for a row of `table` (id fields differ across tables).
pub fn backup_key(table: &str, item: &Value) -> Option<String> {
    let field = match table {
        "servers" => "serverId",
        "pki" => return Some("vault".to_owned()),
        _ => "id",
    };
    item.get(field).and_then(|v| v.as_str()).map(str::to_owned)
}
