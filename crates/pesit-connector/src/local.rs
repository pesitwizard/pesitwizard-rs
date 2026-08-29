//! Local filesystem backend (stage between a base directory and the transfer working file).

use std::path::{Path, PathBuf};

/// A local-directory connector.
#[derive(Debug, Clone)]
pub struct LocalConnector {
    base: PathBuf,
}

impl LocalConnector {
    /// Rooted at `base`.
    #[must_use]
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    fn resolve(&self, remote: &str) -> PathBuf {
        self.base.join(remote.trim_start_matches('/'))
    }

    /// Copy `remote` (relative to the base) to `dest`; returns bytes copied.
    pub async fn fetch(&self, remote: &str, dest: &Path) -> std::io::Result<u64> {
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(self.resolve(remote), dest).await
    }

    /// Copy `src` to `remote` (relative to the base).
    pub async fn store(&self, src: &Path, remote: &str) -> std::io::Result<()> {
        let dest = self.resolve(remote);
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(src, dest).await.map(|_| ())
    }

    /// Check the base directory exists.
    pub async fn test(&self) -> std::io::Result<()> {
        tokio::fs::metadata(&self.base).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_round_trip() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let base = dir.path().join("store");
        let c = LocalConnector::new(&base);
        // put a file into the connector, then fetch it back out
        let src = dir.path().join("src.dat");
        tokio::fs::write(&src, b"hello connector")
            .await
            .unwrap_or_default();
        c.store(&src, "sub/out.dat")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(base.join("sub/out.dat").exists());
        let dest = dir.path().join("back.dat");
        let n = c
            .fetch("sub/out.dat", &dest)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(n, 15);
        assert_eq!(
            tokio::fs::read(&dest).await.unwrap_or_default(),
            b"hello connector"
        );
        assert!(c.test().await.is_ok());
    }
}
