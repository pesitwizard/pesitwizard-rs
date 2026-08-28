//! REST API (compatible with the Java PeSIT Wizard server endpoints used by the tooling).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{middleware, Json, Router};
use pesit_app::http::{health, require_api_key, ApiError};
use pesit_app::store::JsonStore;
use pesit_app::time::now_iso;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::manager::{ManagerError, ServerManager};
use crate::model::{
    tables, Partner, PesitServerConfig, RemotePartner, TransferRecord, TransferStatus, VirtualFile,
};

/// Shared application state.
pub struct App {
    /// Document store.
    pub store: Arc<JsonStore>,
    /// Listener manager.
    pub manager: Arc<ServerManager>,
    /// API key (None = open).
    pub api_key: Option<HeaderValue>,
    /// Certificate / CA management (None = disabled).
    pub pki: Option<std::sync::Arc<crate::pki::PkiState>>,
    /// Audit log.
    pub audit: std::sync::Arc<pesit_app::audit::AuditLog>,
}

type AppState = State<Arc<App>>;
type ApiResult<T> = Result<T, ApiError>;

impl From<ManagerError> for ApiError {
    fn from(e: ManagerError) -> Self {
        match e {
            ManagerError::NotFound(_) => ApiError::not_found(e.to_string()),
            ManagerError::AlreadyRunning(_) | ManagerError::NotRunning(_) => {
                ApiError::conflict(e.to_string())
            }
            ManagerError::Bind(..) | ManagerError::Tls(_) | ManagerError::Store(_) => {
                ApiError::internal(e)
            }
        }
    }
}

/// Build the router.
pub fn router(app: Arc<App>) -> Router {
    let key = app.api_key.clone();
    Router::new()
        .route("/", get(ui))
        .route("/ui", get(ui))
        .route("/actuator/health", get(|| async { health() }))
        .route("/actuator/health/liveness", get(|| async { health() }))
        .route("/actuator/health/readiness", get(|| async { health() }))
        .route("/actuator/info", get(info))
        .route("/api/v1/servers", get(list_servers).post(create_server))
        .route(
            "/api/v1/servers/{id}",
            get(get_server).put(update_server).delete(delete_server),
        )
        .route("/api/v1/servers/{id}/start", post(start_server))
        .route("/api/v1/servers/{id}/stop", post(stop_server))
        .route("/api/v1/servers/{id}/status", get(server_status))
        .route(
            "/api/v1/config/partners",
            get(list::<Partner>).post(create::<Partner>),
        )
        .route(
            "/api/v1/config/partners/{id}",
            get(get_one::<Partner>)
                .put(update::<Partner>)
                .delete(delete::<Partner>),
        )
        .route(
            "/api/v1/config/files",
            get(list::<VirtualFile>).post(create::<VirtualFile>),
        )
        .route(
            "/api/v1/config/files/{id}",
            get(get_one::<VirtualFile>)
                .put(update::<VirtualFile>)
                .delete(delete::<VirtualFile>),
        )
        .route(
            "/api/v1/config/remote-partners",
            get(list::<RemotePartner>).post(create::<RemotePartner>),
        )
        .route(
            "/api/v1/config/remote-partners/{id}",
            get(get_one::<RemotePartner>)
                .put(update::<RemotePartner>)
                .delete(delete::<RemotePartner>),
        )
        .route("/api/v1/transfers", get(list_transfers))
        .route("/api/v1/transfers/active", get(active_transfers))
        .route("/api/v1/transfers/stats", get(transfer_stats))
        .route("/api/v1/transfers/{id}", get(get_transfer))
        .route("/api/v1/transfers/{id}/cancel", post(cancel_transfer))
        .route(
            "/api/v1/transfers/partner/{partnerId}",
            get(transfers_by_partner),
        )
        .route(
            "/api/v1/transfers/status/{status}",
            get(transfers_by_status),
        )
        .merge(crate::pki::routes())
        .merge(crate::audit::routes())
        .merge(crate::backup::routes())
        .layer(middleware::from_fn(move |req, next| {
            require_api_key(key.clone(), req, next)
        }))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(app)
}

async fn ui() -> Html<&'static str> {
    Html(include_str!("web/app.html"))
}

async fn info() -> Json<serde_json::Value> {
    Json(
        json!({ "app": { "name": "pesitwizard-server", "version": env!("CARGO_PKG_VERSION"), "implementation": "rust" } }),
    )
}

// ---- generic configuration entities ----

/// A configuration entity stored by id.
trait Entity: Serialize + DeserializeOwned + Send + 'static {
    const TABLE: &'static str;
    const NAME: &'static str;
    fn id(&self) -> &str;
    fn set_id(&mut self, id: &str);
    fn touch(&mut self, created: bool);
    fn validate(&self) -> Result<(), String> {
        if self.id().trim().is_empty() {
            return Err("id is required".into());
        }
        Ok(())
    }
}

macro_rules! entity {
    ($t:ty, $table:expr, $name:expr) => {
        impl Entity for $t {
            const TABLE: &'static str = $table;
            const NAME: &'static str = $name;
            fn id(&self) -> &str {
                &self.id
            }
            fn set_id(&mut self, id: &str) {
                self.id = id.to_owned();
            }
            fn touch(&mut self, created: bool) {
                if created || self.created_at.is_none() {
                    self.created_at = Some(now_iso());
                }
                self.updated_at = Some(now_iso());
            }
        }
    };
}
entity!(Partner, tables::PARTNERS, "Partner");
entity!(VirtualFile, tables::FILES, "Virtual file");
entity!(RemotePartner, tables::REMOTE_PARTNERS, "Remote partner");

async fn list<T: Entity>(State(app): AppState) -> ApiResult<Json<Vec<T>>> {
    Ok(Json(app.store.list(T::TABLE)?))
}

async fn get_one<T: Entity>(State(app): AppState, Path(id): Path<String>) -> ApiResult<Json<T>> {
    app.store
        .get::<T>(T::TABLE, &id)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("{} '{id}' not found", T::NAME)))
}

async fn create<T: Entity>(
    State(app): AppState,
    Json(mut body): Json<T>,
) -> ApiResult<(StatusCode, Json<T>)> {
    body.validate().map_err(ApiError::bad_request)?;
    if app.store.exists(T::TABLE, body.id())? {
        return Err(ApiError::conflict(format!(
            "{} '{}' already exists",
            T::NAME,
            body.id()
        )));
    }
    body.touch(true);
    app.store.put(T::TABLE, body.id(), &body)?;
    app.audit
        .success("config", "create", format!("{}:{}", T::NAME, body.id()));
    tracing::info!("{} '{}' created", T::NAME, body.id());
    Ok((StatusCode::CREATED, Json(body)))
}

async fn update<T: Entity>(
    State(app): AppState,
    Path(id): Path<String>,
    Json(mut body): Json<T>,
) -> ApiResult<Json<T>> {
    let Some(existing) = app.store.get::<T>(T::TABLE, &id)? else {
        return Err(ApiError::not_found(format!("{} '{id}' not found", T::NAME)));
    };
    body.set_id(&id);
    body.validate().map_err(ApiError::bad_request)?;
    body.touch(false);
    drop(existing);
    app.store.put(T::TABLE, &id, &body)?;
    Ok(Json(body))
}

async fn delete<T: Entity>(State(app): AppState, Path(id): Path<String>) -> ApiResult<StatusCode> {
    if app.store.delete(T::TABLE, &id)? {
        app.audit
            .success("config", "delete", format!("{}:{id}", T::NAME));
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format!("{} '{id}' not found", T::NAME)))
    }
}

// ---- listeners ----

async fn list_servers(State(app): AppState) -> ApiResult<Json<Vec<PesitServerConfig>>> {
    let mut servers: Vec<PesitServerConfig> = app.store.list(tables::SERVERS)?;
    for s in &mut servers {
        s.status = app.manager.status(s).status;
    }
    Ok(Json(servers))
}

fn validate_server(cfg: &PesitServerConfig) -> Result<(), ApiError> {
    if cfg.server_id.trim().is_empty() {
        return Err(ApiError::bad_request("serverId is required"));
    }
    if cfg.port == 0 {
        return Err(ApiError::bad_request("port is required"));
    }
    if cfg.max_entity_size < 64 {
        return Err(ApiError::bad_request("maxEntitySize must be at least 64"));
    }
    if cfg.sync_window > 16 {
        return Err(ApiError::bad_request("syncWindow must be between 0 and 16"));
    }
    Ok(())
}

async fn create_server(
    State(app): AppState,
    Json(mut cfg): Json<PesitServerConfig>,
) -> ApiResult<(StatusCode, Json<PesitServerConfig>)> {
    validate_server(&cfg)?;
    if app.store.exists(tables::SERVERS, &cfg.server_id)? {
        return Err(ApiError::conflict(format!(
            "server '{}' already exists",
            cfg.server_id
        )));
    }
    let others: Vec<PesitServerConfig> = app.store.list(tables::SERVERS)?;
    if others
        .iter()
        .any(|o| o.port == cfg.port && o.bind_address == cfg.bind_address)
    {
        return Err(ApiError::conflict(format!(
            "port {} is already used by another server",
            cfg.port
        )));
    }
    cfg.id = Some(app.store.next_counter("server_id")?);
    cfg.created_at = Some(now_iso());
    cfg.updated_at = Some(now_iso());
    cfg.status = crate::model::ServerStatus::Stopped;
    app.store.put(tables::SERVERS, &cfg.server_id, &cfg)?;
    app.audit.success("listener", "create", &cfg.server_id);
    tracing::info!("server '{}' created (port {})", cfg.server_id, cfg.port);
    if cfg.auto_start {
        if let Err(e) = app.manager.start(&cfg.server_id).await {
            tracing::error!("auto-start of '{}' failed: {e}", cfg.server_id);
        }
    }
    let stored = app
        .store
        .get(tables::SERVERS, &cfg.server_id)?
        .unwrap_or(cfg);
    Ok((StatusCode::CREATED, Json(stored)))
}

async fn get_server(
    State(app): AppState,
    Path(id): Path<String>,
) -> ApiResult<Json<PesitServerConfig>> {
    let mut cfg: PesitServerConfig = app
        .store
        .get(tables::SERVERS, &id)?
        .ok_or_else(|| ApiError::not_found(format!("server '{id}' not found")))?;
    cfg.status = app.manager.status(&cfg).status;
    Ok(Json(cfg))
}

async fn update_server(
    State(app): AppState,
    Path(id): Path<String>,
    Json(mut cfg): Json<PesitServerConfig>,
) -> ApiResult<Json<PesitServerConfig>> {
    let existing: PesitServerConfig = app
        .store
        .get(tables::SERVERS, &id)?
        .ok_or_else(|| ApiError::not_found(format!("server '{id}' not found")))?;
    cfg.server_id.clone_from(&id);
    validate_server(&cfg)?;
    cfg.id = existing.id;
    cfg.created_at = existing.created_at;
    cfg.last_started_at = existing.last_started_at;
    cfg.last_stopped_at = existing.last_stopped_at;
    cfg.status = existing.status;
    cfg.updated_at = Some(now_iso());
    app.store.put(tables::SERVERS, &id, &cfg)?;
    if app.manager.is_running(&id) {
        tracing::info!("server '{id}' updated; restart it to apply the new settings");
    }
    Ok(Json(cfg))
}

async fn delete_server(State(app): AppState, Path(id): Path<String>) -> ApiResult<StatusCode> {
    if app.manager.is_running(&id) {
        app.manager.stop(&id)?;
    }
    if app.store.delete(tables::SERVERS, &id)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format!("server '{id}' not found")))
    }
}

async fn start_server(
    State(app): AppState,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    app.manager.start(&id).await?;
    Ok(Json(
        json!({ "message": "Server started", "serverId": id, "status": "RUNNING" }),
    ))
}

async fn stop_server(
    State(app): AppState,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    app.manager.stop(&id)?;
    Ok(Json(
        json!({ "message": "Server stopped", "serverId": id, "status": "STOPPED" }),
    ))
}

async fn server_status(
    State(app): AppState,
    Path(id): Path<String>,
) -> ApiResult<Json<crate::model::ServerStatusResponse>> {
    let cfg: PesitServerConfig = app
        .store
        .get(tables::SERVERS, &id)?
        .ok_or_else(|| ApiError::not_found(format!("server '{id}' not found")))?;
    Ok(Json(app.manager.status(&cfg)))
}

// ---- transfers ----

/// Transfer list filters.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferQuery {
    /// Maximum number of records (newest first).
    pub limit: Option<usize>,
    /// Direction filter.
    pub direction: Option<String>,
    /// Status filter.
    pub status: Option<String>,
    /// Partner filter.
    pub partner_id: Option<String>,
    /// Listener filter.
    pub server_id: Option<String>,
}

fn filter_transfers(records: Vec<TransferRecord>, q: &TransferQuery) -> Vec<TransferRecord> {
    let up = |s: &Option<String>| s.as_ref().map(|s| s.to_ascii_uppercase());
    let (direction, status, partner, server) = (
        up(&q.direction),
        up(&q.status),
        q.partner_id.clone(),
        q.server_id.clone(),
    );
    records
        .into_iter()
        .filter(|r| {
            direction.as_ref().is_none_or(|d| {
                r.direction
                    .and_then(|x| serde_json::to_value(x).ok())
                    .and_then(|v| v.as_str().map(str::to_owned))
                    == Some(d.clone())
            })
        })
        .filter(|r| {
            status.as_ref().is_none_or(|s| {
                serde_json::to_value(r.status)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    == Some(s.clone())
            })
        })
        .filter(|r| {
            partner
                .as_ref()
                .is_none_or(|p| r.partner_id.as_deref() == Some(p.as_str()))
        })
        .filter(|r| {
            server
                .as_ref()
                .is_none_or(|s| r.server_id.as_deref() == Some(s.as_str()))
        })
        .take(q.limit.unwrap_or(100))
        .collect()
}

async fn list_transfers(
    State(app): AppState,
    Query(q): Query<TransferQuery>,
) -> ApiResult<Json<Vec<TransferRecord>>> {
    let records: Vec<TransferRecord> = app.store.list_recent(tables::TRANSFERS, 10_000)?;
    Ok(Json(filter_transfers(records, &q)))
}

async fn active_transfers(State(app): AppState) -> ApiResult<Json<Vec<TransferRecord>>> {
    let records: Vec<TransferRecord> = app.store.list_recent(tables::TRANSFERS, 10_000)?;
    Ok(Json(
        records
            .into_iter()
            .filter(|r| {
                matches!(
                    r.status,
                    TransferStatus::Initiated | TransferStatus::InProgress | TransferStatus::Paused
                )
            })
            .collect(),
    ))
}

async fn transfers_by_partner(
    State(app): AppState,
    Path(partner_id): Path<String>,
) -> ApiResult<Json<Vec<TransferRecord>>> {
    let records: Vec<TransferRecord> = app.store.list_recent(tables::TRANSFERS, 10_000)?;
    Ok(Json(filter_transfers(
        records,
        &TransferQuery {
            partner_id: Some(partner_id),
            ..TransferQuery::default()
        },
    )))
}

async fn transfers_by_status(
    State(app): AppState,
    Path(status): Path<String>,
) -> ApiResult<Json<Vec<TransferRecord>>> {
    let records: Vec<TransferRecord> = app.store.list_recent(tables::TRANSFERS, 10_000)?;
    Ok(Json(filter_transfers(
        records,
        &TransferQuery {
            status: Some(status),
            ..TransferQuery::default()
        },
    )))
}

async fn get_transfer(
    State(app): AppState,
    Path(id): Path<String>,
) -> ApiResult<Json<TransferRecord>> {
    app.store
        .get::<TransferRecord>(tables::TRANSFERS, &id)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("transfer '{id}' not found")))
}

async fn cancel_transfer(
    State(app): AppState,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let Some(record) = app.store.get::<TransferRecord>(tables::TRANSFERS, &id)? else {
        return Err(ApiError::not_found(format!("transfer '{id}' not found")));
    };
    if app.manager.cancels.cancel(&id) {
        Ok(Json(
            json!({ "message": "Cancellation requested", "transferId": id, "status": "CANCELLING" }),
        ))
    } else {
        Err(ApiError::conflict(format!(
            "transfer '{id}' is not in progress (status {:?})",
            record.status
        )))
    }
}

async fn transfer_stats(State(app): AppState) -> ApiResult<Json<serde_json::Value>> {
    let records: Vec<TransferRecord> = app.store.list(tables::TRANSFERS)?;
    let count = |s: TransferStatus| records.iter().filter(|r| r.status == s).count();
    let bytes: u64 = records
        .iter()
        .filter(|r| r.status == TransferStatus::Completed)
        .map(|r| r.bytes_transferred)
        .sum();
    Ok(Json(json!({
        "total": records.len(),
        "completed": count(TransferStatus::Completed),
        "failed": count(TransferStatus::Failed),
        "inProgress": count(TransferStatus::InProgress) + count(TransferStatus::Initiated),
        "interrupted": count(TransferStatus::Interrupted),
        "cancelled": count(TransferStatus::Cancelled),
        "bytesTransferred": bytes,
    })))
}
