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

impl Connector {
    /// Download `remote` into the local `dest` file; returns bytes copied.
    pub async fn fetch(&self, remote: &str, dest: &Path) -> Result<u64, ConnectorError> {
        match self {
            Connector::Local(c) => c
                .fetch(remote, dest)
                .await
                .map_err(|e| ConnectorError::Local(e.to_string())),
            Connector::S3(c) => Ok(c.fetch(remote, dest).await?),
            Connector::Sftp(c) => Ok(c.fetch(remote, dest).await?),
        }
    }

    /// Upload the local `src` file to `remote`.
    pub async fn store(&self, src: &Path, remote: &str) -> Result<(), ConnectorError> {
        match self {
            Connector::Local(c) => c
                .store(src, remote)
                .await
                .map_err(|e| ConnectorError::Local(e.to_string())),
            Connector::S3(c) => Ok(c.store(src, remote).await?),
            Connector::Sftp(c) => Ok(c.store(src, remote).await?),
        }
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
