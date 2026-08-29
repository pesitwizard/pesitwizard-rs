//! Prometheus metrics exposition at `/metrics`.
//!
//! Served unauthenticated (like `/actuator/health`), since a Prometheus scraper does not send the
//! admin API key. Values are derived from the shared store on each scrape: transfer records
//! accumulate, so the `*_total` series behave as counters until records are purged.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::Value;

use crate::api::App;
use crate::model::tables;

const OUTBOUND_TABLE: &str = "outbound_transfers";

/// Metrics routes, merged into the router outside the API-key layer.
pub fn routes() -> Router<Arc<App>> {
    Router::new().route("/metrics", get(metrics))
}

fn status_of(v: &Value) -> String {
    v.get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_ascii_lowercase()
}

fn completed_bytes(list: &[Value]) -> u64 {
    list.iter()
        .filter(|v| status_of(v) == "completed")
        .filter_map(|v| v.get("bytesTransferred").and_then(Value::as_u64))
        .sum()
}

fn gauge(out: &mut String, name: &str, help: &str, val: usize) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    let _ = writeln!(out, "{name} {val}");
}

async fn metrics(State(app): State<Arc<App>>) -> Response {
    let mut out = String::new();

    let _ = writeln!(out, "# HELP pesitwizard_build_info Build information.");
    let _ = writeln!(out, "# TYPE pesitwizard_build_info gauge");
    let _ = writeln!(
        out,
        "pesitwizard_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );

    let inbound: Vec<Value> = app.store.list(tables::TRANSFERS).unwrap_or_default();
    let outbound: Vec<Value> = app.store.list(OUTBOUND_TABLE).unwrap_or_default();
    let kinds = [("inbound", &inbound), ("outbound", &outbound)];

    let _ = writeln!(
        out,
        "# HELP pesitwizard_transfers_total Transfers by kind (inbound = served, outbound = initiated) and status."
    );
    let _ = writeln!(out, "# TYPE pesitwizard_transfers_total counter");
    for (kind, list) in kinds {
        let mut by_status: BTreeMap<String, u64> = BTreeMap::new();
        for v in list {
            *by_status.entry(status_of(v)).or_default() += 1;
        }
        for (status, n) in by_status {
            let _ = writeln!(
                out,
                "pesitwizard_transfers_total{{kind=\"{kind}\",status=\"{status}\"}} {n}"
            );
        }
    }

    let _ = writeln!(
        out,
        "# HELP pesitwizard_bytes_transferred_total Bytes transferred by completed transfers, by kind."
    );
    let _ = writeln!(out, "# TYPE pesitwizard_bytes_transferred_total counter");
    for (kind, list) in kinds {
        let _ = writeln!(
            out,
            "pesitwizard_bytes_transferred_total{{kind=\"{kind}\"}} {}",
            completed_bytes(list)
        );
    }

    let partners = app
        .store
        .list::<Value>(tables::PARTNERS)
        .map_or(0, |v| v.len());
    let files = app
        .store
        .list::<Value>(tables::FILES)
        .map_or(0, |v| v.len());
    let servers: Vec<Value> = app.store.list(tables::SERVERS).unwrap_or_default();
    let up = servers
        .iter()
        .filter(|v| {
            v.get("serverId")
                .and_then(Value::as_str)
                .is_some_and(|id| app.manager.is_running(id))
        })
        .count();

    gauge(
        &mut out,
        "pesitwizard_partners",
        "Configured partners.",
        partners,
    );
    gauge(
        &mut out,
        "pesitwizard_virtual_files",
        "Configured virtual files.",
        files,
    );
    gauge(
        &mut out,
        "pesitwizard_listeners",
        "Configured listeners.",
        servers.len(),
    );
    gauge(
        &mut out,
        "pesitwizard_listeners_up",
        "Running listeners.",
        up,
    );

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn status_and_completed_bytes() {
        let records = vec![
            json!({ "status": "COMPLETED", "bytesTransferred": 100 }),
            json!({ "status": "COMPLETED", "bytesTransferred": 250 }),
            json!({ "status": "FAILED", "bytesTransferred": 40 }),
            json!({ "status": "IN_PROGRESS", "bytesTransferred": 10 }),
            json!({}),
        ];
        // Status is lowercased; a missing status reads as "unknown".
        assert_eq!(status_of(&records[0]), "completed");
        assert_eq!(status_of(&records[2]), "failed");
        assert_eq!(status_of(&records[4]), "unknown");
        // Only completed transfers contribute to the byte counter.
        assert_eq!(completed_bytes(&records), 350);
        assert_eq!(completed_bytes(&[]), 0);
    }
}
