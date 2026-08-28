//! Audit log REST endpoints (the log itself lives in `pesit_app::audit`).

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use pesit_app::audit::AuditEvent;
use serde::Deserialize;
use serde_json::json;

use crate::api::App;

/// Audit routes (merged into the admin router).
pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/audit", get(list))
        .route("/api/v1/audit/stats", get(stats))
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditQuery {
    limit: Option<usize>,
    category: Option<String>,
}

async fn list(State(app): State<Arc<App>>, Query(q): Query<AuditQuery>) -> Json<Vec<AuditEvent>> {
    Json(
        app.audit
            .filtered(q.category.as_deref(), q.limit.unwrap_or(200)),
    )
}

async fn stats(State(app): State<Arc<App>>) -> Json<serde_json::Value> {
    let (total, success, failure) = app.audit.stats();
    Json(json!({ "total": total, "success": success, "failure": failure }))
}
