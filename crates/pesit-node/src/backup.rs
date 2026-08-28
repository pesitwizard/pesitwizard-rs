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
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::App;

/// Store tables carried in a backup (configuration only — not transfer records).
const CONFIG_TABLES: [&str; 7] = [
    "partners",
    "virtual_files",
    "remote_partners",
    "servers",
    "remote_servers",
    "client_partners",
    "pki",
];

/// Backup routes (merged into the admin router).
pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/backup", get(export))
        .route("/api/v1/backup/restore", post(restore))
}

fn dump(store: &JsonStore) -> Result<Value, ApiError> {
    let mut tables = serde_json::Map::new();
    for t in CONFIG_TABLES {
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
    Ok(Json(json!({
        "version": 1,
        "generatedAt": now_iso(),
        "node": env!("CARGO_PKG_VERSION"),
        "tables": tables,
        "pki": pki,
    })))
}

/// A restore request.
#[derive(Deserialize)]
struct RestoreBundle {
    #[serde(default)]
    tables: serde_json::Map<String, Value>,
    #[serde(default)]
    pki: Value,
}

async fn restore(
    State(app): State<Arc<App>>,
    Json(bundle): Json<RestoreBundle>,
) -> Result<Json<Value>, ApiError> {
    let mut restored = 0usize;
    for (table, rows) in &bundle.tables {
        if !CONFIG_TABLES.contains(&table.as_str()) {
            continue;
        }
        app.store.ensure_table(table)?;
        let Value::Array(items) = rows else { continue };
        for item in items {
            if let Some(key) = backup_key(table, item) {
                app.store.put(table, &key, item)?;
                restored += 1;
            }
        }
    }
    if let Some(p) = &app.pki {
        if !bundle.pki.is_null() {
            p.import_material(&bundle.pki)
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
fn backup_key(table: &str, item: &Value) -> Option<String> {
    let field = match table {
        "servers" => "serverId",
        "pki" => return Some("vault".to_owned()),
        _ => "id",
    };
    item.get(field).and_then(|v| v.as_str()).map(str::to_owned)
}
