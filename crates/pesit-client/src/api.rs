//! REST API (compatible with the Java PeSIT Wizard client endpoints used by the tooling).

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use pesit_app::http::{health, ApiError};
use pesit_app::store::JsonStore;
use pesit_app::time::now_iso;
use serde::Deserialize;
use serde_json::json;

use crate::engine::Engine;
use crate::model::{
    tables, MessageRequest, Partner, PesitServer, TransferHistory, TransferRequest,
    TransferResponse, TransferStatus,
};

/// Application state.
pub struct App {
    /// Store.
    pub store: Arc<JsonStore>,
    /// Engine.
    pub engine: Arc<Engine>,
    /// Directory where uploaded certificates are kept.
    pub tls_dir: PathBuf,
}

type AppState = State<Arc<App>>;
type ApiResult<T> = Result<T, ApiError>;

/// Build the router.
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/actuator/health", get(|| async { health() }))
        .route("/actuator/health/liveness", get(|| async { health() }))
        .route("/actuator/health/readiness", get(|| async { health() }))
        .route("/actuator/info", get(info))
        .route("/api/v1/servers", get(list_servers).post(create_server))
        .route("/api/v1/servers/enabled", get(enabled_servers))
        .route("/api/v1/servers/default", get(default_server))
        .route("/api/v1/servers/name/{name}", get(server_by_name))
        .route(
            "/api/v1/servers/{id}",
            get(get_server).put(update_server).delete(delete_server),
        )
        .route("/api/v1/servers/{id}/default", post(set_default))
        .route("/api/v1/servers/{id}/test", post(test_server))
        .route(
            "/api/v1/servers/{id}/tls/truststore",
            post(upload_truststore).delete(delete_truststore),
        )
        .route("/api/v1/servers/{id}/tls/keystore", post(upload_keystore))
        .route("/api/v1/partners", get(list_partners).post(create_partner))
        .route(
            "/api/v1/partners/{id}",
            get(get_partner).put(update_partner).delete(delete_partner),
        )
        .route("/api/v1/transfers", get(list_transfers))
        .route("/api/v1/transfers/send", post(send))
        .route("/api/v1/transfers/receive", post(receive))
        .route("/api/v1/transfers/message", post(message))
        .route("/api/v1/transfers/history", get(list_transfers))
        .route("/api/v1/transfers/stats", get(stats))
        .route("/api/v1/transfers/resumable", get(resumable))
        .route("/api/v1/transfers/correlation/{cid}", get(by_correlation))
        .route("/api/v1/transfers/{id}", get(get_transfer))
        .route("/api/v1/transfers/{id}/cancel", post(cancel))
        .route("/api/v1/transfers/{id}/retry", post(retry))
        .route("/api/v1/transfers/{id}/resume", post(retry))
        .route("/api/v1/transfers/{id}/replay", post(replay))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(app)
}

async fn info() -> Json<serde_json::Value> {
    Json(
        json!({ "app": { "name": "pesitwizard-client", "version": env!("CARGO_PKG_VERSION"), "implementation": "rust" } }),
    )
}

// ---- servers ----

fn find_server(store: &JsonStore, id: &str) -> ApiResult<PesitServer> {
    if let Some(s) = store.get::<PesitServer>(tables::SERVERS, id)? {
        return Ok(s);
    }
    let all: Vec<PesitServer> = store.list(tables::SERVERS)?;
    all.into_iter()
        .find(|s| s.name == id)
        .ok_or_else(|| ApiError::not_found(format!("server '{id}' not found")))
}

fn validate_server(s: &PesitServer) -> ApiResult<()> {
    if s.name.trim().is_empty() {
        return Err(ApiError::bad_request("name is required"));
    }
    if s.host.trim().is_empty() {
        return Err(ApiError::bad_request("host is required"));
    }
    if s.port == 0 {
        return Err(ApiError::bad_request("port is required"));
    }
    Ok(())
}

fn refresh_tls_flags(s: &mut PesitServer) {
    s.truststore_configured = s.ca_file.is_some();
    s.keystore_configured = s.cert_file.is_some() && s.key_file.is_some();
}

async fn list_servers(State(app): AppState) -> ApiResult<Json<Vec<PesitServer>>> {
    Ok(Json(app.store.list(tables::SERVERS)?))
}

async fn enabled_servers(State(app): AppState) -> ApiResult<Json<Vec<PesitServer>>> {
    let all: Vec<PesitServer> = app.store.list(tables::SERVERS)?;
    Ok(Json(all.into_iter().filter(|s| s.enabled).collect()))
}

async fn default_server(State(app): AppState) -> ApiResult<Json<PesitServer>> {
    app.engine.resolve_server(None).map(Json)
}

async fn server_by_name(
    State(app): AppState,
    Path(name): Path<String>,
) -> ApiResult<Json<PesitServer>> {
    find_server(&app.store, &name).map(Json)
}

async fn get_server(State(app): AppState, Path(id): Path<String>) -> ApiResult<Json<PesitServer>> {
    find_server(&app.store, &id).map(Json)
}

async fn create_server(
    State(app): AppState,
    Json(mut s): Json<PesitServer>,
) -> ApiResult<(StatusCode, Json<PesitServer>)> {
    validate_server(&s)?;
    let all: Vec<PesitServer> = app.store.list(tables::SERVERS)?;
    if all.iter().any(|o| o.name == s.name) {
        return Err(ApiError::conflict(format!(
            "server '{}' already exists",
            s.name
        )));
    }
    s.id = uuid::Uuid::new_v4().to_string();
    s.created_at = Some(now_iso());
    s.updated_at = Some(now_iso());
    refresh_tls_flags(&mut s);
    if s.default_server {
        for mut o in all {
            if o.default_server {
                o.default_server = false;
                app.store.put(tables::SERVERS, &o.id.clone(), &o)?;
            }
        }
    }
    app.store.put(tables::SERVERS, &s.id, &s)?;
    tracing::info!("server '{}' created ({}:{})", s.name, s.host, s.port);
    Ok((StatusCode::CREATED, Json(s)))
}

async fn update_server(
    State(app): AppState,
    Path(id): Path<String>,
    Json(mut s): Json<PesitServer>,
) -> ApiResult<Json<PesitServer>> {
    let existing = find_server(&app.store, &id)?;
    validate_server(&s)?;
    s.id.clone_from(&existing.id);
    s.created_at = existing.created_at;
    s.updated_at = Some(now_iso());
    if s.ca_file.is_none() {
        s.ca_file = existing.ca_file;
    }
    if s.cert_file.is_none() {
        s.cert_file = existing.cert_file;
        s.key_file = existing.key_file;
    }
    refresh_tls_flags(&mut s);
    app.store.put(tables::SERVERS, &s.id, &s)?;
    Ok(Json(s))
}

async fn delete_server(State(app): AppState, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let s = find_server(&app.store, &id)?;
    app.store.delete(tables::SERVERS, &s.id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_default(State(app): AppState, Path(id): Path<String>) -> ApiResult<Json<PesitServer>> {
    let target = find_server(&app.store, &id)?;
    let all: Vec<PesitServer> = app.store.list(tables::SERVERS)?;
    let mut result = target.clone();
    for mut o in all {
        let is_target = o.id == target.id;
        if o.default_server != is_target {
            o.default_server = is_target;
            o.updated_at = Some(now_iso());
            app.store.put(tables::SERVERS, &o.id.clone(), &o)?;
        }
        if is_target {
            result = o;
        }
    }
    Ok(Json(result))
}

async fn test_server(
    State(app): AppState,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let s = find_server(&app.store, &id)?;
    match app.engine.test_connection(&s).await {
        Ok(d) => Ok(Json(
            json!({ "success": true, "message": format!("connected to {}:{} in {} ms", s.host, s.port, d.as_millis()), "latencyMs": d.as_millis() as u64 }),
        )),
        Err(e) => Ok(Json(json!({ "success": false, "message": e }))),
    }
}

/// Read a multipart upload: returns (file bytes, file name, password).
async fn read_upload(mut mp: Multipart) -> ApiResult<(Vec<u8>, String, Option<String>)> {
    let mut data = Vec::new();
    let mut name = String::new();
    let mut password = None;
    while let Some(field) = mp
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?
    {
        match field.name().unwrap_or("") {
            "file" => {
                name = field.file_name().unwrap_or("upload").to_owned();
                data = field
                    .bytes()
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?
                    .to_vec();
            }
            "password" => password = field.text().await.ok().filter(|p| !p.is_empty()),
            _ => {}
        }
    }
    if data.is_empty() {
        return Err(ApiError::bad_request("missing 'file' part"));
    }
    Ok((data, name, password))
}

fn is_pem(data: &[u8]) -> bool {
    data.windows(11).any(|w| w == b"-----BEGIN ")
}

async fn upload_truststore(
    State(app): AppState,
    Path(id): Path<String>,
    mp: Multipart,
) -> ApiResult<Json<serde_json::Value>> {
    let mut s = find_server(&app.store, &id)?;
    let (data, name, _password) = read_upload(mp).await?;
    if !is_pem(&data) {
        return Ok(Json(
            json!({ "success": false, "error": format!("'{name}' is not a PEM file: PKCS#12 truststores are not supported, upload the CA certificate(s) in PEM format") }),
        ));
    }
    let certs = rustls_pem_count(&data);
    if certs == 0 {
        return Ok(Json(
            json!({ "success": false, "error": "no certificate found in the uploaded file" }),
        ));
    }
    let dir = app.tls_dir.join(&s.id);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("ca.pem");
    std::fs::write(&path, &data)?;
    s.ca_file = Some(path.to_string_lossy().into_owned());
    s.tls_enabled = true;
    refresh_tls_flags(&mut s);
    s.updated_at = Some(now_iso());
    app.store.put(tables::SERVERS, &s.id, &s)?;
    Ok(Json(
        json!({ "success": true, "message": format!("CA certificate uploaded and validated successfully ({certs} certificate(s))"), "certificates": certs }),
    ))
}

async fn delete_truststore(
    State(app): AppState,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let mut s = find_server(&app.store, &id)?;
    if let Some(p) = s.ca_file.take() {
        let _ = std::fs::remove_file(p);
    }
    refresh_tls_flags(&mut s);
    app.store.put(tables::SERVERS, &s.id, &s)?;
    Ok(Json(json!({ "success": true })))
}

async fn upload_keystore(
    State(app): AppState,
    Path(id): Path<String>,
    mp: Multipart,
) -> ApiResult<Json<serde_json::Value>> {
    let mut s = find_server(&app.store, &id)?;
    let (data, name, _password) = read_upload(mp).await?;
    if !is_pem(&data) {
        return Ok(Json(
            json!({ "success": false, "error": format!("'{name}' is not a PEM file: upload a PEM bundle containing the client certificate and its private key") }),
        ));
    }
    let dir = app.tls_dir.join(&s.id);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("client.pem");
    std::fs::write(&path, &data)?;
    s.cert_file = Some(path.to_string_lossy().into_owned());
    s.key_file = Some(path.to_string_lossy().into_owned());
    refresh_tls_flags(&mut s);
    s.updated_at = Some(now_iso());
    app.store.put(tables::SERVERS, &s.id, &s)?;
    Ok(Json(
        json!({ "success": true, "message": "client certificate uploaded" }),
    ))
}

fn rustls_pem_count(data: &[u8]) -> usize {
    data.windows(27)
        .filter(|w| *w == b"-----BEGIN CERTIFICATE-----")
        .count()
}

// ---- partners ----

async fn list_partners(State(app): AppState) -> ApiResult<Json<Vec<Partner>>> {
    Ok(Json(app.store.list(tables::PARTNERS)?))
}

async fn get_partner(State(app): AppState, Path(id): Path<String>) -> ApiResult<Json<Partner>> {
    app.store
        .get::<Partner>(tables::PARTNERS, &id)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("partner '{id}' not found")))
}

async fn create_partner(
    State(app): AppState,
    Json(mut p): Json<Partner>,
) -> ApiResult<(StatusCode, Json<Partner>)> {
    if p.partner_id.trim().is_empty() {
        return Err(ApiError::bad_request("partnerId is required"));
    }
    let all: Vec<Partner> = app.store.list(tables::PARTNERS)?;
    if all.iter().any(|o| o.partner_id == p.partner_id) {
        return Err(ApiError::conflict(format!(
            "partner '{}' already exists",
            p.partner_id
        )));
    }
    p.id = uuid::Uuid::new_v4().to_string();
    p.created_at = Some(now_iso());
    p.updated_at = Some(now_iso());
    app.store.put(tables::PARTNERS, &p.id, &p)?;
    Ok((StatusCode::CREATED, Json(p)))
}

async fn update_partner(
    State(app): AppState,
    Path(id): Path<String>,
    Json(mut p): Json<Partner>,
) -> ApiResult<Json<Partner>> {
    let existing: Partner = app
        .store
        .get(tables::PARTNERS, &id)?
        .ok_or_else(|| ApiError::not_found(format!("partner '{id}' not found")))?;
    p.id = existing.id;
    p.created_at = existing.created_at;
    p.updated_at = Some(now_iso());
    app.store.put(tables::PARTNERS, &p.id, &p)?;
    Ok(Json(p))
}

async fn delete_partner(State(app): AppState, Path(id): Path<String>) -> ApiResult<StatusCode> {
    if app.store.delete(tables::PARTNERS, &id)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format!("partner '{id}' not found")))
    }
}

// ---- transfers ----

async fn send(
    State(app): AppState,
    Json(req): Json<TransferRequest>,
) -> ApiResult<(StatusCode, Json<TransferResponse>)> {
    let h = app.engine.submit_send(req)?;
    Ok((StatusCode::ACCEPTED, Json(TransferResponse::from(&h))))
}

async fn receive(
    State(app): AppState,
    Json(req): Json<TransferRequest>,
) -> ApiResult<(StatusCode, Json<TransferResponse>)> {
    let h = app.engine.submit_receive(req)?;
    Ok((StatusCode::ACCEPTED, Json(TransferResponse::from(&h))))
}

async fn message(
    State(app): AppState,
    Json(req): Json<MessageRequest>,
) -> ApiResult<Json<TransferResponse>> {
    app.engine.send_message(req).await.map(Json)
}

/// List filters.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListQuery {
    /// Maximum records (newest first).
    pub limit: Option<usize>,
    /// Status filter.
    pub status: Option<String>,
    /// Direction filter.
    pub direction: Option<String>,
}

async fn list_transfers(
    State(app): AppState,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<TransferHistory>>> {
    let all: Vec<TransferHistory> = app.store.list_recent(tables::TRANSFERS, 10_000)?;
    let status = q.status.map(|s| s.to_ascii_uppercase());
    let direction = q.direction.map(|s| s.to_ascii_uppercase());
    let as_str = |v: serde_json::Value| v.as_str().map(str::to_owned);
    Ok(Json(
        all.into_iter()
            .filter(|h| {
                status.as_ref().is_none_or(|s| {
                    serde_json::to_value(h.status)
                        .ok()
                        .and_then(as_str)
                        .as_deref()
                        == Some(s)
                })
            })
            .filter(|h| {
                direction.as_ref().is_none_or(|d| {
                    h.direction
                        .and_then(|x| serde_json::to_value(x).ok())
                        .and_then(as_str)
                        .as_deref()
                        == Some(d)
                })
            })
            .take(q.limit.unwrap_or(100))
            .collect(),
    ))
}

async fn get_transfer(
    State(app): AppState,
    Path(id): Path<String>,
) -> ApiResult<Json<TransferHistory>> {
    app.engine
        .get(&id)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("transfer '{id}' not found")))
}

async fn by_correlation(
    State(app): AppState,
    Path(cid): Path<String>,
) -> ApiResult<Json<Vec<TransferHistory>>> {
    let all: Vec<TransferHistory> = app.store.list_recent(tables::TRANSFERS, 10_000)?;
    let found: Vec<TransferHistory> = all
        .into_iter()
        .filter(|h| h.correlation_id.as_deref() == Some(cid.as_str()))
        .collect();
    if found.is_empty() {
        return Err(ApiError::not_found(format!(
            "no transfer with correlation id '{cid}'"
        )));
    }
    Ok(Json(found))
}

async fn resumable(State(app): AppState) -> ApiResult<Json<Vec<TransferHistory>>> {
    let all: Vec<TransferHistory> = app.store.list_recent(tables::TRANSFERS, 10_000)?;
    Ok(Json(
        all.into_iter()
            .filter(|h| {
                h.last_sync_point > 0
                    && matches!(
                        h.status,
                        TransferStatus::Interrupted
                            | TransferStatus::Failed
                            | TransferStatus::Cancelled
                    )
            })
            .collect(),
    ))
}

async fn cancel(
    State(app): AppState,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let Some(h) = app.engine.get(&id)? else {
        return Err(ApiError::not_found(format!("transfer '{id}' not found")));
    };
    if app.engine.cancel(&id) {
        Ok(Json(
            json!({ "message": "Cancellation requested", "transferId": id, "status": "CANCELLING" }),
        ))
    } else {
        Err(ApiError::conflict(format!(
            "transfer '{id}' is not running (status {:?})",
            h.status
        )))
    }
}

async fn retry(
    State(app): AppState,
    Path(id): Path<String>,
) -> ApiResult<(StatusCode, Json<TransferResponse>)> {
    let h = app.engine.retry(&id)?;
    Ok((StatusCode::ACCEPTED, Json(TransferResponse::from(&h))))
}

async fn replay(
    State(app): AppState,
    Path(id): Path<String>,
) -> ApiResult<(StatusCode, Json<TransferResponse>)> {
    let Some(prev) = app.engine.get(&id)? else {
        return Err(ApiError::not_found(format!("transfer '{id}' not found")));
    };
    let mut req = prev.request.clone().unwrap_or_default();
    req.server = prev.server_id.clone().or(req.server);
    req.filename.clone_from(&prev.local_filename);
    req.remote_filename.clone_from(&prev.remote_filename);
    req.partner_id.clone_from(&prev.partner_id);
    req.resume_from_transfer_id = None;
    let h = match prev.direction {
        Some(crate::model::TransferDirection::Receive) => app.engine.submit_receive(req)?,
        _ => app.engine.submit_send(req)?,
    };
    Ok((StatusCode::ACCEPTED, Json(TransferResponse::from(&h))))
}

async fn stats(State(app): AppState) -> ApiResult<Json<serde_json::Value>> {
    let all: Vec<TransferHistory> = app.store.list(tables::TRANSFERS)?;
    let count = |s: TransferStatus| all.iter().filter(|h| h.status == s).count();
    Ok(Json(json!({
        "total": all.len(),
        "completed": count(TransferStatus::Completed),
        "failed": count(TransferStatus::Failed),
        "inProgress": count(TransferStatus::InProgress) + count(TransferStatus::Pending),
        "cancelled": count(TransferStatus::Cancelled),
        "interrupted": count(TransferStatus::Interrupted),
        "bytesTransferred": all.iter().filter(|h| h.status == TransferStatus::Completed).map(|h| h.bytes_transferred).sum::<u64>(),
    })))
}
