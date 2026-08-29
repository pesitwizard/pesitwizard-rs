//! Storage connectors: stage files between the node and object / file backends (S3, SFTP, local).
//!
//! Connectors bridge remote storage into the transfer engines by *staging*: a send fetches the
//! remote object into a local working file, and a receive writes a local working file that is then
//! uploaded to the remote.

use std::path::Path;

pub mod local;
pub mod s3;
pub mod sftp;

pub use local::LocalConnector;
pub use s3::{S3Config, S3Connector};
pub use sftp::{SftpConfig, SftpConnector};

/// Connector error.
#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    /// S3 backend error.
    #[error(transparent)]
    S3(#[from] s3::S3Error),
    /// SFTP backend error.
    #[error(transparent)]
    Sftp(#[from] sftp::SftpError),
    /// Local backend error.
    #[error("local: {0}")]
    Local(String),
}

/// A configured storage backend.
#[derive(Clone)]
pub enum Connector {
    /// Local directory.
    Local(LocalConnector),
    /// S3-compatible object storage.
    S3(S3Connector),
    /// SFTP server.
    Sftp(SftpConnector),
}

/// Total attempts (initial try plus retries) for a transient connector operation.
const MAX_ATTEMPTS: u32 = 3;
/// Backoff before the first retry; doubled after each failed attempt.
const RETRY_BASE_DELAY: std::time::Duration = std::time::Duration::from_millis(200);

impl Connector {
    /// Download `remote` into the local `dest` file; returns bytes copied. Retries transient
    /// failures with exponential backoff.
    pub async fn fetch(&self, remote: &str, dest: &Path) -> Result<u64, ConnectorError> {
        let mut delay = RETRY_BASE_DELAY;
        for attempt in 1..=MAX_ATTEMPTS {
            let r = match self {
                Connector::Local(c) => c
                    .fetch(remote, dest)
                    .await
                    .map_err(|e| ConnectorError::Local(e.to_string())),
                Connector::S3(c) => c.fetch(remote, dest).await.map_err(ConnectorError::from),
                Connector::Sftp(c) => c.fetch(remote, dest).await.map_err(ConnectorError::from),
            };
            match r {
                Ok(v) => return Ok(v),
                Err(e) if attempt < MAX_ATTEMPTS => {
                    tracing::warn!(
                        "connector {} fetch '{remote}' attempt {attempt}/{MAX_ATTEMPTS} failed: {e}; retrying in {delay:?}",
                        self.kind()
                    );
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!("loop returns on the last attempt")
    }

    /// Upload the local `src` file to `remote`. Retries transient failures with exponential backoff.
    pub async fn store(&self, src: &Path, remote: &str) -> Result<(), ConnectorError> {
        let mut delay = RETRY_BASE_DELAY;
        for attempt in 1..=MAX_ATTEMPTS {
            let r = match self {
                Connector::Local(c) => c
                    .store(src, remote)
                    .await
                    .map_err(|e| ConnectorError::Local(e.to_string())),
                Connector::S3(c) => c.store(src, remote).await.map_err(ConnectorError::from),
                Connector::Sftp(c) => c.store(src, remote).await.map_err(ConnectorError::from),
            };
            match r {
                Ok(()) => return Ok(()),
                Err(e) if attempt < MAX_ATTEMPTS => {
                    tracing::warn!(
                        "connector {} store '{remote}' attempt {attempt}/{MAX_ATTEMPTS} failed: {e}; retrying in {delay:?}",
                        self.kind()
                    );
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!("loop returns on the last attempt")
    }

    /// Check connectivity to the backend.
    pub async fn test(&self) -> Result<(), ConnectorError> {
        match self {
            Connector::Local(c) => c
                .test()
                .await
                .map_err(|e| ConnectorError::Local(e.to_string())),
            Connector::S3(c) => Ok(c.test().await?),
            Connector::Sftp(c) => Ok(c.test().await?),
        }
    }

    /// Backend kind.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Connector::Local(_) => "local",
            Connector::S3(_) => "s3",
            Connector::Sftp(_) => "sftp",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalConnector;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn fetch_retries_with_backoff_then_fails() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let c = Connector::Local(LocalConnector::new(dir.path()));
        let dest = dir.path().join("out.dat");
        let start = Instant::now();
        let r = c.fetch("does-not-exist.dat", &dest).await;
        assert!(r.is_err(), "fetching a missing object must fail");
        // Two retries between three attempts => at least 200ms + 400ms of backoff.
        assert!(
            start.elapsed() >= Duration::from_millis(600),
            "expected exponential backoff between attempts, elapsed {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn store_then_fetch_round_trip_succeeds() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let c = Connector::Local(LocalConnector::new(dir.path()));
        let src = dir.path().join("src.dat");
        std::fs::write(&src, b"hello").unwrap_or_else(|e| panic!("{e}"));
        c.store(&src, "stored.dat")
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let dest = dir.path().join("back.dat");
        let n = c
            .fetch("stored.dat", &dest)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(n, 5);
        assert_eq!(std::fs::read(&dest).unwrap_or_default(), b"hello");
    }
}
