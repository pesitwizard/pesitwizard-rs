//! An append-only audit log stored alongside the configuration.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::store::JsonStore;
use crate::time::now_iso;

/// The audit table name.
pub const TABLE: &str = "audit";

/// Outcome of an audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Outcome {
    /// The action succeeded.
    Success,
    /// The action failed.
    Failure,
}

/// One audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    /// Unique identifier.
    pub id: String,
    /// Time (RFC 3339).
    pub timestamp: String,
    /// Category (`config`, `listener`, `certificate`, `vault`, `transfer`, `session`).
    pub category: String,
    /// Action (`create`, `update`, `delete`, `start`, `stop`, `issue`, ...).
    pub action: String,
    /// Object acted upon.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Who / what triggered it (partner, remote address, `api`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Free-text detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Outcome.
    pub outcome: Outcome,
}

/// Default cap on retained audit events (0 disables retention).
pub const DEFAULT_MAX_ENTRIES: usize = 50_000;
/// Prune at most once every this many writes, to amortise the cost.
const PRUNE_INTERVAL: u64 = 256;

/// Records audit events into the shared store (best-effort; never fails a request).
#[derive(Clone)]
pub struct AuditLog {
    store: Arc<JsonStore>,
    max_entries: usize,
    writes: Arc<std::sync::atomic::AtomicU64>,
}

impl AuditLog {
    /// Create the log with the default retention cap.
    pub fn new(store: Arc<JsonStore>) -> Result<Self, crate::store::StoreError> {
        Self::with_retention(store, DEFAULT_MAX_ENTRIES)
    }

    /// Create the log, keeping at most `max_entries` events (0 = unlimited). Prunes once now.
    pub fn with_retention(
        store: Arc<JsonStore>,
        max_entries: usize,
    ) -> Result<Self, crate::store::StoreError> {
        store.ensure_table(TABLE)?;
        if max_entries > 0 {
            if let Err(e) = store.prune_oldest(TABLE, max_entries) {
                tracing::warn!("cannot prune audit log: {e}");
            }
        }
        Ok(Self {
            store,
            max_entries,
            writes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// Record an event (best-effort).
    pub fn record(
        &self,
        category: &str,
        action: &str,
        target: Option<String>,
        actor: Option<String>,
        outcome: Outcome,
        detail: Option<String>,
    ) {
        let ev = AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: now_iso(),
            category: category.to_owned(),
            action: action.to_owned(),
            target,
            actor,
            detail,
            outcome,
        };
        if let Err(e) = self.store.put(TABLE, &ev.id, &ev) {
            tracing::warn!("cannot write audit event: {e}");
        }
        // Bound the table periodically so the append-only log does not grow without limit.
        if self.max_entries > 0
            && self
                .writes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                % PRUNE_INTERVAL
                == 0
        {
            if let Err(e) = self.store.prune_oldest(TABLE, self.max_entries) {
                tracing::warn!("cannot prune audit log: {e}");
            }
        }
    }

    /// A successful action.
    pub fn success(&self, category: &str, action: &str, target: impl Into<String>) {
        self.record(
            category,
            action,
            Some(target.into()),
            None,
            Outcome::Success,
            None,
        );
    }

    /// A failed action, with a reason.
    pub fn failure(
        &self,
        category: &str,
        action: &str,
        target: impl Into<String>,
        reason: impl Into<String>,
    ) {
        self.record(
            category,
            action,
            Some(target.into()),
            None,
            Outcome::Failure,
            Some(reason.into()),
        );
    }

    /// The most recent events, newest first.
    pub fn recent(&self, limit: usize) -> Vec<AuditEvent> {
        self.store.list_recent(TABLE, limit).unwrap_or_default()
    }

    /// The most recent events matching an optional category, newest first.
    pub fn filtered(&self, category: Option<&str>, limit: usize) -> Vec<AuditEvent> {
        let all: Vec<AuditEvent> = self.store.list_recent(TABLE, 5000).unwrap_or_default();
        all.into_iter()
            .filter(|e| category.is_none_or(|c| e.category.eq_ignore_ascii_case(c)))
            .take(limit)
            .collect()
    }

    /// Count by outcome and category over the whole log.
    #[must_use]
    pub fn stats(&self) -> (usize, usize, usize) {
        let all: Vec<AuditEvent> = self.store.list(TABLE).unwrap_or_default();
        let failures = all.iter().filter(|e| e.outcome == Outcome::Failure).count();
        (all.len(), all.len() - failures, failures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn records_and_lists_newest_first() {
        let store =
            Arc::new(JsonStore::open(Path::new(":memory:")).unwrap_or_else(|e| panic!("{e}")));
        let log = AuditLog::new(store).unwrap_or_else(|e| panic!("{e}"));
        log.success("config", "create", "partner:A");
        log.success("listener", "start", "SRV1");
        log.failure("config", "create", "partner:A", "already exists");
        let recent = log.recent(10);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].action, "create");
        assert_eq!(recent[0].outcome, Outcome::Failure);
        assert_eq!(recent[0].detail.as_deref(), Some("already exists"));
        assert_eq!(log.filtered(Some("listener"), 10).len(), 1);
        assert_eq!(log.filtered(Some("config"), 10).len(), 2);
        assert_eq!(log.stats(), (3, 2, 1));
    }

    #[test]
    fn retention_caps_the_log_to_the_newest_entries() {
        let store =
            Arc::new(JsonStore::open(Path::new(":memory:")).unwrap_or_else(|e| panic!("{e}")));
        let log = AuditLog::with_retention(Arc::clone(&store), 0).unwrap_or_else(|e| panic!("{e}"));
        for i in 0..10 {
            log.success("test", "write", format!("t{i}"));
        }
        assert_eq!(store.count(TABLE).unwrap_or_default(), 10);

        // Reopening with a cap prunes down to the newest entries at construction.
        let capped =
            AuditLog::with_retention(Arc::clone(&store), 3).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(store.count(TABLE).unwrap_or_default(), 3);
        let recent = capped.recent(10);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].target.as_deref(), Some("t9"));
        assert_eq!(recent[2].target.as_deref(), Some("t7"));
    }
}
