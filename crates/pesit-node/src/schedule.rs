//! Scheduled transfers: recurring send / receive jobs, distributed across live cluster members
//! (each node owns a deterministic slice by schedule id), so a job fires exactly once cluster-wide.

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
    /// Interval between runs, in seconds (used when `cron` is unset).
    pub interval_seconds: u64,
    /// Cron expression (5, 6 or 7 fields); when set it drives the schedule instead of the interval.
    pub cron: Option<String>,
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
            cron: None,
            last_run: None,
            last_status: None,
            next_run_ms: 0,
            created_at: None,
            updated_at: None,
        }
    }
}

/// Normalise a cron expression to the 6/7-field form the parser expects: a bare 5-field
/// expression (minute hour day month weekday) gets a leading `0` seconds field.
fn cron_expr(raw: &str) -> String {
    let raw = raw.trim();
    if raw.split_whitespace().count() == 5 {
        format!("0 {raw}")
    } else {
        raw.to_owned()
    }
}

/// Parse a cron expression, returning a human-readable error on failure.
fn parse_cron(expr: &str) -> Result<cron::Schedule, String> {
    use std::str::FromStr;
    cron::Schedule::from_str(&cron_expr(expr)).map_err(|e| e.to_string())
}

/// Next run time (epoch millis) after `from_ms`: the next cron occurrence when a valid cron
/// expression is set, otherwise `from_ms` plus the interval.
fn next_run_after(s: &ScheduledTransfer, from_ms: i64) -> i64 {
    if let Some(expr) = s.cron.as_deref().filter(|e| !e.trim().is_empty()) {
        if let Ok(sched) = parse_cron(expr) {
            let from =
                chrono::DateTime::from_timestamp_millis(from_ms).unwrap_or_else(chrono::Utc::now);
            if let Some(next) = sched.after(&from).next() {
                return next.timestamp_millis();
            }
        }
    }
    from_ms + (s.interval_seconds.max(1) as i64) * 1000
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
    if let Some(expr) = s.cron.as_deref().filter(|e| !e.trim().is_empty()) {
        parse_cron(expr)
            .map_err(|e| ApiError::bad_request(format!("invalid cron expression: {e}")))?;
    } else if s.interval_seconds == 0 {
        return Err(ApiError::bad_request(
            "intervalSeconds must be at least 1, or set a cron expression",
        ));
    }
    app.store.ensure_table(TABLE)?;
    s.id = uuid::Uuid::new_v4().to_string();
    s.created_at = Some(now_iso());
    s.updated_at = Some(now_iso());
    s.next_run_ms = next_run_after(&s, now_millis());
    app.store.put(TABLE, &s.id, &s)?;
    crate::cluster::publish(&app, "put", TABLE, &s.id, serde_json::to_value(&s).ok()).await;
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
    if let Some(expr) = s.cron.as_deref().filter(|e| !e.trim().is_empty()) {
        parse_cron(expr)
            .map_err(|e| ApiError::bad_request(format!("invalid cron expression: {e}")))?;
    }
    if s.next_run_ms == 0 {
        s.next_run_ms = next_run_after(&s, now_millis());
    }
    app.store.put(TABLE, &id, &s)?;
    crate::cluster::publish(&app, "put", TABLE, &id, serde_json::to_value(&s).ok()).await;
    Ok(Json(s))
}

async fn delete(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if app.store.delete(TABLE, &id)? {
        crate::cluster::publish(&app, "delete", TABLE, &id, None).await;
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

/// Spawn the scheduler loop. Schedules are distributed across live cluster members by ownership,
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
            // Distribute schedules across live cluster members: each node owns a deterministic
            // slice by schedule id, so a due job fires exactly once and the load spreads. A
            // standalone node owns everything.
            let (my_index, member_count) = match cluster.as_ref() {
                Some(c) => {
                    let mut ids: Vec<String> =
                        c.members().await.into_iter().map(|m| m.node_id).collect();
                    ids.sort();
                    let idx = ids.iter().position(|id| id == c.node_id()).unwrap_or(0);
                    (idx, ids.len().max(1))
                }
                None => (0, 1),
            };
            let now = now_millis();
            let schedules: Vec<ScheduledTransfer> = store.list(TABLE).unwrap_or_default();
            for mut s in schedules {
                if !s.enabled || s.next_run_ms > now || owner_index(&s.id, member_count) != my_index
                {
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
                s.next_run_ms = next_run_after(&s, now);
                s.updated_at = Some(now_iso());
                if let Err(e) = store.put(TABLE, &s.id, &s) {
                    tracing::warn!("cannot persist schedule '{}': {e}", s.id);
                }
                // Replicate the new next-run time so peers stay consistent for failover.
                if let Some(c) = cluster.as_ref() {
                    c.publish_config("put", TABLE, &s.id, serde_json::to_value(&s).ok())
                        .await;
                }
            }
        }
    });
}

/// Deterministic owner slot for a schedule among `member_count` sorted members (FNV-1a of the id).
fn owner_index(schedule_id: &str, member_count: usize) -> usize {
    if member_count <= 1 {
        return 0;
    }
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in schedule_id.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash % member_count as u64) as usize
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

    #[test]
    fn cron_normalisation_and_next_run() {
        // A 5-field expression gains a leading seconds field; 6/7 fields are kept.
        assert_eq!(cron_expr("0 2 * * *"), "0 0 2 * * *");
        assert_eq!(cron_expr("*/5 * * * * *"), "*/5 * * * * *");
        assert!(parse_cron("0 2 * * *").is_ok());
        assert!(parse_cron("clearly not cron").is_err());

        let from = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap_or_else(|e| panic!("{e}"))
            .timestamp_millis();

        // Daily at 02:00 UTC -> next run is 02:00 the same day.
        let daily = ScheduledTransfer {
            cron: Some("0 2 * * *".into()),
            ..ScheduledTransfer::default()
        };
        let next = next_run_after(&daily, from);
        assert_eq!(
            chrono::DateTime::from_timestamp_millis(next)
                .unwrap_or_else(|| panic!("bad ms"))
                .to_rfc3339(),
            "2026-01-01T02:00:00+00:00"
        );

        // An invalid cron falls back to the interval.
        let bad = ScheduledTransfer {
            cron: Some("bogus".into()),
            interval_seconds: 60,
            ..ScheduledTransfer::default()
        };
        assert_eq!(next_run_after(&bad, from), from + 60 * 1000);

        // No cron -> interval.
        let interval = ScheduledTransfer {
            interval_seconds: 900,
            ..ScheduledTransfer::default()
        };
        assert_eq!(next_run_after(&interval, from), from + 900 * 1000);
    }

    #[test]
    fn owner_index_distributes_deterministically() {
        // Deterministic and single-member ownership.
        assert_eq!(owner_index("abc", 3), owner_index("abc", 3));
        assert_eq!(owner_index("anything", 1), 0);
        assert_eq!(owner_index("x", 0), 0);
        // Across many ids every slot of a 3-node cluster is used.
        let mut slots = [0usize; 3];
        for i in 0..300 {
            slots[owner_index(&format!("sched-{i}"), 3)] += 1;
        }
        assert!(
            slots.iter().all(|&c| c > 0),
            "every node should own some schedules: {slots:?}"
        );
    }
}
