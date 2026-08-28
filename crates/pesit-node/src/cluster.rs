//! Node integration of the NATS / JetStream cluster: a handler that replicates configuration
//! changes through the shared store, and the `/api/v1/cluster` status endpoint.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use pesit_app::store::JsonStore;
use pesit_cluster::{ClusterHandler, ConfigChange};
use serde_json::{json, Value};

use crate::api::App;
use crate::backup;

/// Applies remote configuration changes to the local store and serves snapshots to joining peers.
pub struct NodeClusterHandler {
    store: Arc<JsonStore>,
}

impl NodeClusterHandler {
    /// Create the handler over the shared store.
    #[must_use]
    pub fn new(store: Arc<JsonStore>) -> Self {
        Self { store }
    }
}

impl ClusterHandler for NodeClusterHandler {
    fn apply(&self, change: &ConfigChange) {
        if !backup::CLUSTER_TABLES.contains(&change.table.as_str()) {
            return;
        }
        let _ = self.store.ensure_table(&change.table);
        let result = match change.op.as_str() {
            "delete" => self.store.delete(&change.table, &change.key).map(|_| ()),
            _ => match &change.doc {
                Some(doc) => self.store.put(&change.table, &change.key, doc),
                None => Ok(()),
            },
        };
        if let Err(e) = result {
            tracing::warn!(
                "cluster: cannot apply {} {}:{}: {e}",
                change.op,
                change.table,
                change.key
            );
        }
    }

    fn snapshot(&self) -> Value {
        json!({ "tables": backup::dump_only(&self.store, &backup::CLUSTER_TABLES).unwrap_or(Value::Null) })
    }

    fn restore(&self, snapshot: &Value) {
        if let Some(tables) = snapshot.get("tables").and_then(Value::as_object) {
            match backup::apply_tables(&self.store, tables) {
                Ok(n) => tracing::info!("cluster: applied {n} configuration records from a peer"),
                Err(e) => tracing::warn!("cluster: snapshot restore failed: {e:?}"),
            }
        }
    }
}

/// Cluster status routes (merged into the admin router).
pub fn routes() -> Router<Arc<App>> {
    Router::new().route("/api/v1/cluster", get(status))
}

async fn status(State(app): State<Arc<App>>) -> Json<Value> {
    let Some(cluster) = &app.cluster else {
        return Json(json!({ "enabled": false }));
    };
    let members = cluster.members().await;
    let leader = cluster.leader().await;
    Json(json!({
        "enabled": true,
        "nodeId": cluster.node_id(),
        "isLeader": cluster.is_leader(),
        "leader": leader,
        "members": members,
    }))
}

/// Publish a configuration change to the cluster, if clustering is enabled.
pub async fn publish(app: &App, op: &str, table: &str, key: &str, doc: Option<Value>) {
    if let Some(cluster) = &app.cluster {
        cluster.publish_config(op, table, key, doc).await;
    }
}

/// Build the cluster handler for a node.
#[must_use]
pub fn handler(store: Arc<JsonStore>) -> Arc<dyn ClusterHandler> {
    Arc::new(NodeClusterHandler::new(store))
}
