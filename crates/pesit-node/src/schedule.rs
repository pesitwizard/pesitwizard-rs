//! Scheduled transfers: recurring send / receive jobs, driven by the cluster leader (or always,
//! when the node runs standalone), so a job fires once across the cluster.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use pesit_app::audit::{AuditLog, Outcome};
use pesit_app::http::ApiError;
use pesit_app::store::JsonStore;
use pesit_app::time::{now_iso, now_millis};
use pesit_client::engine::Engine;
use pesit_client::model::TransferRequest;
use pesit_cluster::Cluster;
use serde::{Deserialize, Serialize};

use crate::api::App;

const TABLE: &str = "schedules";

/// A recurring transfer job.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScheduledTransfer {
    /// Identifier.
    pub id: String,
    /// Human name.
    pub name: String,
    /// Enabled.
    pub enabled: bool,
    /// `send` or `receive`.
    pub direction: String,
    /// The transfer to run.
    pub request: TransferRequest,
    /// Interval between runs, in seconds.
    pub interval_seconds: u64,
    /// Last run time (RFC 3339).
    pub last_run: Option<String>,
    /// Outcome of the last run.
    pub last_status: Option<String>,
    /// Next run (epoch milliseconds).
    pub next_run_ms: i64,
    /// Creation time.
    pub created_at: Option<String>,
    /// Update time.
    pub updated_at: Option<String>,
}

impl Default for ScheduledTransfer {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            enabled: true,
            direction: "send".into(),
            request: TransferRequest::default(),
            interval_seconds: 3600,
            last_run: None,
            last_status: None,
            next_run_ms: 0,
            created_at: None,
            updated_at: None,
        }
    }
}

/// Schedule routes (merged into the admin router).
pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/schedules", get(list).post(create))
        .route(
            "/api/v1/schedules/{id}",
            get(get_one).put(update).delete(delete),
        )
        .route("/api/v1/schedules/{id}/run", post(run_now))
}

async fn list(State(app): State<Arc<App>>) -> Result<Json<Vec<ScheduledTransfer>>, ApiError> {
    app.store.ensure_table(TABLE)?;
    Ok(Json(app.store.list(TABLE)?))
}

async fn get_one(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
) -> Result<Json<ScheduledTransfer>, ApiError> {
    app.store
        .get::<ScheduledTransfer>(TABLE, &id)?
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("schedule '{id}' not found")))
}

async fn create(
    State(app): State<Arc<App>>,
    Json(mut s): Json<ScheduledTransfer>,
) -> Result<(StatusCode, Json<ScheduledTransfer>), ApiError> {
    if s.name.trim().is_empty() {
        return Err(ApiError::bad_request("name is required"));
    }
    if s.interval_seconds == 0 {
        return Err(ApiError::bad_request("intervalSeconds must be at least 1"));
    }
    app.store.ensure_table(TABLE)?;
    s.id = uuid::Uuid::new_v4().to_string();
    s.created_at = Some(now_iso());
    s.updated_at = Some(now_iso());
    s.next_run_ms = now_millis() + (s.interval_seconds as i64) * 1000;
    app.store.put(TABLE, &s.id, &s)?;
    app.audit.success("schedule", "create", &s.name);
    Ok((StatusCode::CREATED, Json(s)))
}

async fn update(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    Json(mut s): Json<ScheduledTransfer>,
) -> Result<Json<ScheduledTransfer>, ApiError> {
    let existing: ScheduledTransfer = app
        .store
        .get(TABLE, &id)?
        .ok_or_else(|| ApiError::not_found(format!("schedule '{id}' not found")))?;
    s.id = existing.id;
    s.created_at = existing.created_at;
    s.last_run = existing.last_run;
    s.last_status = existing.last_status;
    s.updated_at = Some(now_iso());
    if s.next_run_ms == 0 {
        s.next_run_ms = now_millis() + (s.interval_seconds.max(1) as i64) * 1000;
    }
    app.store.put(TABLE, &id, &s)?;
    Ok(Json(s))
}

async fn delete(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if app.store.delete(TABLE, &id)? {
        app.audit.success("schedule", "delete", &id);
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format!("schedule '{id}' not found")))
    }
}

async fn run_now(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut s: ScheduledTransfer = app
        .store
        .get(TABLE, &id)?
        .ok_or_else(|| ApiError::not_found(format!("schedule '{id}' not found")))?;
    let outcome = trigger(&app.engine, &s);
    s.last_run = Some(now_iso());
    s.last_status = Some(outcome.clone());
    app.store.put(TABLE, &id, &s)?;
    app.audit.success("schedule", "run", &s.name);
    Ok(Json(serde_json::json!({ "status": outcome })))
}

fn trigger(engine: &Arc<Engine>, s: &ScheduledTransfer) -> String {
    let result = if s.direction.eq_ignore_ascii_case("receive") {
        engine.submit_receive(s.request.clone())
    } else {
        engine.submit_send(s.request.clone())
    };
    match result {
        Ok(h) => format!("queued {}", h.id),
        Err(e) => format!("error: {}", e.message),
    }
}

/// Spawn the scheduler loop. It only fires on the cluster leader (or always when standalone).
pub fn spawn(
    store: Arc<JsonStore>,
    engine: Arc<Engine>,
    cluster: Option<Arc<Cluster>>,
    audit: Arc<AuditLog>,
) {
    let _ = store.ensure_table(TABLE);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            if cluster.as_ref().is_some_and(|c| !c.is_leader()) {
                continue;
            }
            let now = now_millis();
            let schedules: Vec<ScheduledTransfer> = store.list(TABLE).unwrap_or_default();
            for mut s in schedules {
                if !s.enabled || s.next_run_ms > now {
                    continue;
                }
                let outcome = trigger(&engine, &s);
                let ok = outcome.starts_with("queued");
                tracing::info!("schedule '{}' fired: {outcome}", s.name);
                audit.record(
                    "schedule",
                    "run",
                    Some(s.name.clone()),
                    None,
                    if ok {
                        Outcome::Success
                    } else {
                        Outcome::Failure
                    },
                    Some(outcome.clone()),
                );
                s.last_run = Some(now_iso());
                s.last_status = Some(outcome);
                s.next_run_ms = now + (s.interval_seconds.max(1) as i64) * 1000;
                s.updated_at = Some(now_iso());
                if let Err(e) = store.put(TABLE, &s.id, &s) {
                    tracing::warn!("cannot persist schedule '{}': {e}", s.id);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_serde_and_defaults() {
        let json = r#"{"name":"nightly","direction":"receive","intervalSeconds":900,"request":{"server":"cx","remoteFilename":"PWSEND"}}"#;
        let s: ScheduledTransfer = serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.name, "nightly");
        assert_eq!(s.direction, "receive");
        assert_eq!(s.interval_seconds, 900);
        assert!(s.enabled, "enabled defaults to true");
        assert_eq!(s.request.server.as_deref(), Some("cx"));
        // a fresh schedule with no next_run is due immediately relative to a future tick
        let due = ScheduledTransfer {
            next_run_ms: 0,
            ..ScheduledTransfer::default()
        };
        assert!(due.next_run_ms <= now_millis());
    }
}
