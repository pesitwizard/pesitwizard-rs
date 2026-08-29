//! Clustering for PeSIT Wizard over NATS / JetStream.
//!
//! Provides node membership (heartbeats in a JetStream KV bucket with a TTL), leader election
//! (a KV lease), and configuration propagation (a change is published to every node, and a joining
//! node catches up by requesting a full snapshot from a peer).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_nats::jetstream::kv::{Config as KvConfig, Store};
use futures::StreamExt;
use serde::{Deserialize, Serialize};

/// Cluster error.
#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    /// Connection / NATS error.
    #[error("nats: {0}")]
    Nats(String),
}

fn nats<E: std::fmt::Display>(e: E) -> ClusterError {
    ClusterError::Nats(e.to_string())
}

/// Cluster configuration.
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    /// NATS server URL (e.g. `nats://nats:4222`).
    pub url: String,
    /// Logical cluster name (namespaces the buckets and subjects).
    pub name: String,
    /// This node's identifier.
    pub node_id: String,
    /// This node's reachable address (host:port of the admin API).
    pub node_addr: String,
    /// Software version.
    pub version: String,
    /// Heartbeat interval.
    pub heartbeat: Duration,
}

/// Membership information published by each node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberInfo {
    /// Node identifier.
    pub node_id: String,
    /// Admin API address.
    pub addr: String,
    /// Software version.
    pub version: String,
    /// Last heartbeat (RFC 3339).
    pub last_seen: String,
}

/// A configuration change to replicate across the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigChange {
    /// Originating node.
    pub origin: String,
    /// `put` or `delete`.
    pub op: String,
    /// Store table.
    pub table: String,
    /// Row key.
    pub key: String,
    /// Row document (for `put`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<serde_json::Value>,
}

/// Application hook: apply remote changes and provide / restore a full snapshot.
pub trait ClusterHandler: Send + Sync + 'static {
    /// Apply a configuration change received from another node.
    fn apply(&self, change: &ConfigChange);
    /// A full configuration snapshot to hand to a joining node.
    fn snapshot(&self) -> serde_json::Value;
    /// Restore a full snapshot received when joining.
    fn restore(&self, snapshot: &serde_json::Value);
}

/// A live cluster membership.
pub struct Cluster {
    client: async_nats::Client,
    cfg: ClusterConfig,
    members_kv: Store,
    leader_kv: Store,
    is_leader: AtomicBool,
    config_subject: String,
    sync_subject: String,
}

fn now_iso() -> String {
    // avoid a chrono dependency here; the node stamps precise times elsewhere.
    // async-nats requires a tokio runtime, so a coarse monotonic-free stamp is fine for last_seen.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format!("@{secs}")
}

impl Cluster {
    /// Join the cluster: connect, catch up from a peer, and start the background tasks.
    pub async fn join(
        cfg: ClusterConfig,
        handler: Arc<dyn ClusterHandler>,
    ) -> Result<Arc<Self>, ClusterError> {
        let client = async_nats::connect(&cfg.url).await.map_err(nats)?;
        let js = async_nats::jetstream::new(client.clone());
        let members_kv = js
            .create_key_value(KvConfig {
                bucket: format!("pesit_{}_members", cfg.name),
                history: 1,
                max_age: cfg.heartbeat * 3,
                ..Default::default()
            })
            .await
            .map_err(nats)?;
        let leader_kv = js
            .create_key_value(KvConfig {
                bucket: format!("pesit_{}_leader", cfg.name),
                history: 1,
                max_age: cfg.heartbeat * 2,
                ..Default::default()
            })
            .await
            .map_err(nats)?;

        let config_subject = format!("pesit.{}.config", cfg.name);
        let sync_subject = format!("pesit.{}.sync", cfg.name);

        // Catch up: ask a peer for the current configuration (before we start responding ourselves).
        let sync = tokio::time::timeout(
            Duration::from_secs(2),
            client.request(sync_subject.clone(), bytes::Bytes::new()),
        )
        .await;
        if let Ok(Ok(msg)) = sync {
            if let Ok(snapshot) = serde_json::from_slice::<serde_json::Value>(&msg.payload) {
                tracing::info!("cluster: syncing configuration from a peer");
                handler.restore(&snapshot);
            }
        } else {
            tracing::info!("cluster: no peer answered; this is the first node");
        }

        let cluster = Arc::new(Self {
            client,
            cfg,
            members_kv,
            leader_kv,
            is_leader: AtomicBool::new(false),
            config_subject,
            sync_subject,
        });

        cluster.clone().spawn_heartbeat();
        cluster.clone().spawn_leader();
        cluster
            .clone()
            .spawn_config_subscriber(Arc::clone(&handler));
        cluster.clone().spawn_sync_responder(handler);
        tracing::info!(
            "cluster '{}' joined as '{}' via {}",
            cluster.cfg.name,
            cluster.cfg.node_id,
            cluster.cfg.url
        );
        Ok(cluster)
    }

    fn member_bytes(&self) -> bytes::Bytes {
        let info = MemberInfo {
            node_id: self.cfg.node_id.clone(),
            addr: self.cfg.node_addr.clone(),
            version: self.cfg.version.clone(),
            last_seen: now_iso(),
        };
        serde_json::to_vec(&info).unwrap_or_default().into()
    }

    fn spawn_heartbeat(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(self.cfg.heartbeat);
            loop {
                tick.tick().await;
                if let Err(e) = self
                    .members_kv
                    .put(&self.cfg.node_id, self.member_bytes())
                    .await
                {
                    tracing::warn!("cluster heartbeat failed: {e}");
                }
            }
        });
    }

    fn spawn_leader(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(self.cfg.heartbeat / 2);
            let id = self.cfg.node_id.clone();
            loop {
                tick.tick().await;
                let held = match self.leader_kv.entry("leader").await {
                    Ok(Some(entry)) => Some(String::from_utf8_lossy(&entry.value).into_owned()),
                    _ => None,
                };
                match held {
                    Some(holder) if holder == id => {
                        let _ = self
                            .leader_kv
                            .put("leader", bytes::Bytes::from(id.clone()))
                            .await;
                        self.set_leader(true);
                    }
                    Some(_) => self.set_leader(false),
                    None => {
                        let won = self
                            .leader_kv
                            .create("leader", bytes::Bytes::from(id.clone()))
                            .await
                            .is_ok();
                        self.set_leader(won);
                    }
                }
            }
        });
    }

    fn set_leader(&self, leader: bool) {
        if self.is_leader.swap(leader, Ordering::Relaxed) != leader {
            if leader {
                tracing::info!("cluster: this node is now the leader");
            } else {
                tracing::info!("cluster: this node is no longer the leader");
            }
        }
    }

    fn spawn_config_subscriber(self: Arc<Self>, handler: Arc<dyn ClusterHandler>) {
        tokio::spawn(async move {
            let Ok(mut sub) = self.client.subscribe(self.config_subject.clone()).await else {
                tracing::error!("cluster: cannot subscribe to config changes");
                return;
            };
            while let Some(msg) = sub.next().await {
                let Ok(change) = serde_json::from_slice::<ConfigChange>(&msg.payload) else {
                    continue;
                };
                if change.origin == self.cfg.node_id {
                    continue;
                }
                tracing::debug!(
                    "cluster: applying {} {}:{} from {}",
                    change.op,
                    change.table,
                    change.key,
                    change.origin
                );
                handler.apply(&change);
            }
        });
    }

    fn spawn_sync_responder(self: Arc<Self>, handler: Arc<dyn ClusterHandler>) {
        tokio::spawn(async move {
            let Ok(mut sub) = self.client.subscribe(self.sync_subject.clone()).await else {
                return;
            };
            while let Some(msg) = sub.next().await {
                let Some(reply) = msg.reply else { continue };
                let snapshot = handler.snapshot();
                let payload = serde_json::to_vec(&snapshot).unwrap_or_default();
                let _ = self.client.publish(reply, payload.into()).await;
            }
        });
    }

    /// Publish a configuration change to the cluster.
    pub async fn publish_config(
        &self,
        op: &str,
        table: &str,
        key: &str,
        doc: Option<serde_json::Value>,
    ) {
        let change = ConfigChange {
            origin: self.cfg.node_id.clone(),
            op: op.to_owned(),
            table: table.to_owned(),
            key: key.to_owned(),
            doc,
        };
        if let Ok(payload) = serde_json::to_vec(&change) {
            if let Err(e) = self
                .client
                .publish(self.config_subject.clone(), payload.into())
                .await
            {
                tracing::warn!("cluster: cannot publish config change: {e}");
            }
        }
    }

    /// Whether this node currently holds the leader lease.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.is_leader.load(Ordering::Relaxed)
    }

    /// This node's identifier.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.cfg.node_id
    }

    /// The current leader, if any.
    pub async fn leader(&self) -> Option<String> {
        match self.leader_kv.entry("leader").await {
            Ok(Some(entry)) => Some(String::from_utf8_lossy(&entry.value).into_owned()),
            _ => None,
        }
    }

    /// The current cluster members.
    pub async fn members(&self) -> Vec<MemberInfo> {
        let mut out = Vec::new();
        let Ok(mut keys) = self.members_kv.keys().await else {
            return out;
        };
        while let Some(Ok(key)) = keys.next().await {
            if let Ok(Some(bytes)) = self.members_kv.get(&key).await {
                if let Ok(info) = serde_json::from_slice::<MemberInfo>(&bytes) {
                    out.push(info);
                }
            }
        }
        out.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_change_round_trips() {
        let change = ConfigChange {
            origin: "node-a".into(),
            op: "put".into(),
            table: "partners".into(),
            key: "P1".into(),
            doc: Some(serde_json::json!({ "id": "P1", "accessType": "BOTH" })),
        };
        let bytes = serde_json::to_vec(&change).unwrap_or_default();
        let back: ConfigChange = serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(back.origin, "node-a");
        assert_eq!(back.op, "put");
        assert_eq!(back.table, "partners");
        assert_eq!(
            back.doc.and_then(|d| d
                .get("accessType")
                .and_then(|v| v.as_str().map(str::to_owned))),
            Some("BOTH".into())
        );
        // a delete carries no document
        let del = ConfigChange {
            origin: "n".into(),
            op: "delete".into(),
            table: "partners".into(),
            key: "P1".into(),
            doc: None,
        };
        let json = serde_json::to_string(&del).unwrap_or_default();
        assert!(
            !json.contains("doc"),
            "delete must omit the doc field: {json}"
        );
    }

    #[test]
    fn member_info_serde() {
        let m = MemberInfo {
            node_id: "node-b".into(),
            addr: "0.0.0.0:8080".into(),
            version: "0.1.0".into(),
            last_seen: "@1700".into(),
        };
        let v = serde_json::to_value(&m).unwrap_or_default();
        assert_eq!(v.get("nodeId").and_then(|x| x.as_str()), Some("node-b"));
        assert_eq!(v.get("addr").and_then(|x| x.as_str()), Some("0.0.0.0:8080"));
    }
}
