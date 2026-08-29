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
enum Backend {
    /// Local directory.
    Local(LocalConnector),
    /// S3-compatible object storage.
    S3(S3Connector),
    /// SFTP server.
    Sftp(SftpConnector),
}

/// Default attempts (initial try plus retries) for a transient connector operation.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;
/// Backoff before the first retry; doubled after each failed attempt.
const RETRY_BASE_DELAY: std::time::Duration = std::time::Duration::from_millis(200);

/// A storage connector: a backend plus a retry policy for transient failures.
#[derive(Clone)]
pub struct Connector {
    backend: Backend,
    max_attempts: u32,
}

impl Connector {
    fn wrap(backend: Backend) -> Self {
        Self {
            backend,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// A local-directory connector.
    #[must_use]
    pub fn local(c: LocalConnector) -> Self {
        Self::wrap(Backend::Local(c))
    }

    /// An S3 connector.
    #[must_use]
    pub fn s3(c: S3Connector) -> Self {
        Self::wrap(Backend::S3(c))
    }

    /// An SFTP connector.
    #[must_use]
    pub fn sftp(c: SftpConnector) -> Self {
        Self::wrap(Backend::Sftp(c))
    }

    /// Set the number of attempts (clamped to at least 1) for transient failures.
    #[must_use]
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts.max(1);
        self
    }

    /// Download `remote` into the local `dest` file; returns bytes copied. Retries transient
    /// failures with exponential backoff.
    pub async fn fetch(&self, remote: &str, dest: &Path) -> Result<u64, ConnectorError> {
        let mut delay = RETRY_BASE_DELAY;
        for attempt in 1..=self.max_attempts {
            let r = match &self.backend {
                Backend::Local(c) => c
                    .fetch(remote, dest)
                    .await
                    .map_err(|e| ConnectorError::Local(e.to_string())),
                Backend::S3(c) => c.fetch(remote, dest).await.map_err(ConnectorError::from),
                Backend::Sftp(c) => c.fetch(remote, dest).await.map_err(ConnectorError::from),
            };
            match r {
                Ok(v) => return Ok(v),
                Err(e) if attempt < self.max_attempts => {
                    tracing::warn!(
                        "connector {} fetch '{remote}' attempt {attempt}/{} failed: {e}; retrying in {delay:?}",
                        self.kind(),
                        self.max_attempts
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
        for attempt in 1..=self.max_attempts {
            let r = match &self.backend {
                Backend::Local(c) => c
                    .store(src, remote)
                    .await
                    .map_err(|e| ConnectorError::Local(e.to_string())),
                Backend::S3(c) => c.store(src, remote).await.map_err(ConnectorError::from),
                Backend::Sftp(c) => c.store(src, remote).await.map_err(ConnectorError::from),
            };
            match r {
                Ok(()) => return Ok(()),
                Err(e) if attempt < self.max_attempts => {
                    tracing::warn!(
                        "connector {} store '{remote}' attempt {attempt}/{} failed: {e}; retrying in {delay:?}",
                        self.kind(),
                        self.max_attempts
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
        match &self.backend {
            Backend::Local(c) => c
                .test()
                .await
                .map_err(|e| ConnectorError::Local(e.to_string())),
            Backend::S3(c) => Ok(c.test().await?),
            Backend::Sftp(c) => Ok(c.test().await?),
        }
    }

    /// Backend kind.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match &self.backend {
            Backend::Local(_) => "local",
            Backend::S3(_) => "s3",
            Backend::Sftp(_) => "sftp",
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
        let c = Connector::local(LocalConnector::new(dir.path()));
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
    async fn max_attempts_one_does_not_retry() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let c = Connector::local(LocalConnector::new(dir.path())).with_max_attempts(1);
        let dest = dir.path().join("out.dat");
        let start = Instant::now();
        assert!(c.fetch("missing.dat", &dest).await.is_err());
        // A single attempt means no backoff sleeps.
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "with one attempt there must be no retry backoff, elapsed {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn store_then_fetch_round_trip_succeeds() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let c = Connector::local(LocalConnector::new(dir.path()));
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
