//! A tiny document store on SQLite: each table maps a string key to a JSON document.
//!
//! Configuration objects and transfer records are small and few; keeping them as JSON keeps the
//! REST DTOs and the storage format identical.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Store error.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite error.
    #[error("database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// JSON (de)serialisation error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// The mutex protecting the connection was poisoned.
    #[error("database lock poisoned")]
    Poisoned,
}

/// JSON document store.
pub struct JsonStore {
    conn: Mutex<Connection>,
}

impl JsonStore {
    /// Open (or create) the store at `path`; `":memory:"` gives a private in-memory store.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = if path.as_os_str() == ":memory:" {
            Connection::open_in_memory()?
        } else {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            Connection::open(path)?
        };
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StoreError> {
        self.conn.lock().map_err(|_| StoreError::Poisoned)
    }

    /// Create a table if it does not exist.
    pub fn ensure_table(&self, table: &str) -> Result<(), StoreError> {
        let conn = self.lock()?;
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {table} (key TEXT PRIMARY KEY, doc TEXT NOT NULL, seq INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS {table}_seq ON {table}(seq);"
        ))?;
        Ok(())
    }

    /// Insert or replace a document (the insertion order is kept for existing keys).
    pub fn put<T: Serialize>(&self, table: &str, key: &str, doc: &T) -> Result<(), StoreError> {
        let json = serde_json::to_string(doc)?;
        let conn = self.lock()?;
        let seq: Option<i64> = conn
            .query_row(
                &format!("SELECT seq FROM {table} WHERE key = ?1"),
                params![key],
                |r| r.get(0),
            )
            .optional()?;
        let seq = match seq {
            Some(s) => s,
            None => conn.query_row(
                &format!("SELECT COALESCE(MAX(seq), 0) + 1 FROM {table}"),
                [],
                |r| r.get(0),
            )?,
        };
        conn.execute(
            &format!("INSERT OR REPLACE INTO {table} (key, doc, seq) VALUES (?1, ?2, ?3)"),
            params![key, json, seq],
        )?;
        Ok(())
    }

    /// Fetch a document.
    pub fn get<T: DeserializeOwned>(
        &self,
        table: &str,
        key: &str,
    ) -> Result<Option<T>, StoreError> {
        let conn = self.lock()?;
        let json: Option<String> = conn
            .query_row(
                &format!("SELECT doc FROM {table} WHERE key = ?1"),
                params![key],
                |r| r.get(0),
            )
            .optional()?;
        json.map(|j| serde_json::from_str(&j))
            .transpose()
            .map_err(Into::into)
    }

    /// Whether a key exists.
    pub fn exists(&self, table: &str, key: &str) -> Result<bool, StoreError> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE key = ?1"),
            params![key],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Delete a document; returns whether it existed.
    pub fn delete(&self, table: &str, key: &str) -> Result<bool, StoreError> {
        let conn = self.lock()?;
        Ok(conn.execute(&format!("DELETE FROM {table} WHERE key = ?1"), params![key])? > 0)
    }

    /// All documents in insertion order.
    pub fn list<T: DeserializeOwned>(&self, table: &str) -> Result<Vec<T>, StoreError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(&format!("SELECT doc FROM {table} ORDER BY seq"))?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
    }

    /// The `limit` most recently inserted documents, newest first.
    pub fn list_recent<T: DeserializeOwned>(
        &self,
        table: &str,
        limit: usize,
    ) -> Result<Vec<T>, StoreError> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(&format!(
            "SELECT doc FROM {table} ORDER BY seq DESC LIMIT ?1"
        ))?;
        let rows = stmt.query_map(params![limit as i64], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
    }

    /// Number of documents.
    pub fn count(&self, table: &str) -> Result<usize, StoreError> {
        let conn = self.lock()?;
        let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
        Ok(n.max(0) as usize)
    }

    /// Delete all but the `keep` most recently inserted documents; returns the number removed.
    /// Used to bound append-only tables such as the audit log.
    pub fn prune_oldest(&self, table: &str, keep: usize) -> Result<usize, StoreError> {
        let conn = self.lock()?;
        let removed = conn.execute(
            &format!(
                "DELETE FROM {table} WHERE seq NOT IN \
                 (SELECT seq FROM {table} ORDER BY seq DESC LIMIT ?1)"
            ),
            params![keep as i64],
        )?;
        Ok(removed)
    }

    /// Read-modify-write a document; returns `false` when the key does not exist.
    pub fn update<T: Serialize + DeserializeOwned>(
        &self,
        table: &str,
        key: &str,
        f: impl FnOnce(&mut T),
    ) -> Result<bool, StoreError> {
        let Some(mut doc) = self.get::<T>(table, key)? else {
            return Ok(false);
        };
        f(&mut doc);
        self.put(table, key, &doc)?;
        Ok(true)
    }

    /// Next value of a named counter (persisted).
    pub fn next_counter(&self, name: &str) -> Result<u64, StoreError> {
        let conn = self.lock()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL)",
        )?;
        conn.execute("INSERT INTO counters (name, value) VALUES (?1, 1) ON CONFLICT(name) DO UPDATE SET value = value + 1", params![name])?;
        let v: i64 = conn.query_row(
            "SELECT value FROM counters WHERE name = ?1",
            params![name],
            |r| r.get(0),
        )?;
        Ok(v.max(0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Doc {
        name: String,
        n: u32,
    }

    #[test]
    fn crud() {
        let s = JsonStore::open(Path::new(":memory:")).unwrap_or_else(|e| panic!("{e}"));
        s.ensure_table("docs").unwrap_or_default();
        s.put(
            "docs",
            "a",
            &Doc {
                name: "A".into(),
                n: 1,
            },
        )
        .unwrap_or_default();
        s.put(
            "docs",
            "b",
            &Doc {
                name: "B".into(),
                n: 2,
            },
        )
        .unwrap_or_default();
        s.put(
            "docs",
            "a",
            &Doc {
                name: "A2".into(),
                n: 3,
            },
        )
        .unwrap_or_default();
        assert_eq!(
            s.get::<Doc>("docs", "a")
                .unwrap_or_default()
                .map(|d| d.name),
            Some("A2".into())
        );
        let all: Vec<Doc> = s.list("docs").unwrap_or_default();
        assert_eq!(
            all.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            vec!["A2", "B"]
        );
        let recent: Vec<Doc> = s.list_recent("docs", 1).unwrap_or_default();
        assert_eq!(recent[0].name, "B");
        assert!(s
            .update::<Doc>("docs", "b", |d| d.n = 9)
            .unwrap_or_default());
        assert_eq!(
            s.get::<Doc>("docs", "b").unwrap_or_default().map(|d| d.n),
            Some(9)
        );
        assert!(s.delete("docs", "a").unwrap_or_default());
        assert!(!s.delete("docs", "a").unwrap_or_default());
        assert_eq!(s.count("docs").unwrap_or_default(), 1);
        assert_eq!(s.next_counter("t").unwrap_or_default(), 1);
        assert_eq!(s.next_counter("t").unwrap_or_default(), 2);
    }
}
