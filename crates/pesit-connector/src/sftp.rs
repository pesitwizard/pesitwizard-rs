//! SFTP backend (over SSH, password authentication).

use std::path::Path;
use std::sync::Arc;

use russh::client::{self, Handle};
use russh_sftp::client::SftpSession;
use tokio::io::AsyncWriteExt;

/// SFTP connector error.
#[derive(Debug, thiserror::Error)]
pub enum SftpError {
    /// SSH transport error.
    #[error("ssh: {0}")]
    Ssh(String),
    /// SFTP protocol error.
    #[error("sftp: {0}")]
    Sftp(String),
    /// Authentication failed.
    #[error("SFTP authentication failed")]
    Auth,
    /// Local I/O error.
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// SFTP configuration.
#[derive(Debug, Clone)]
pub struct SftpConfig {
    /// Host.
    pub host: String,
    /// Port (default 22).
    pub port: u16,
    /// Username.
    pub user: String,
    /// Password.
    pub password: Option<String>,
    /// Base directory prepended to remote paths.
    pub base_path: Option<String>,
}

struct AcceptAll;
impl client::Handler for AcceptAll {
    type Error = russh::Error;
    #[allow(clippy::unused_async_trait_impl)]
    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// An SFTP connector (a fresh SSH connection is opened per operation).
#[derive(Debug, Clone)]
pub struct SftpConnector {
    cfg: SftpConfig,
}

impl SftpConnector {
    /// Build from configuration.
    #[must_use]
    pub fn new(cfg: SftpConfig) -> Self {
        Self { cfg }
    }

    fn path(&self, remote: &str) -> String {
        match &self.cfg.base_path {
            Some(base) if !base.is_empty() => format!(
                "{}/{}",
                base.trim_end_matches('/'),
                remote.trim_start_matches('/')
            ),
            _ => remote.to_owned(),
        }
    }

    async fn connect(&self) -> Result<(Handle<AcceptAll>, SftpSession), SftpError> {
        let config = Arc::new(client::Config::default());
        let mut handle =
            client::connect(config, (self.cfg.host.as_str(), self.cfg.port), AcceptAll)
                .await
                .map_err(|e| SftpError::Ssh(e.to_string()))?;
        let password = self.cfg.password.clone().unwrap_or_default();
        let authed = handle
            .authenticate_password(&self.cfg.user, password)
            .await
            .map_err(|e| SftpError::Ssh(e.to_string()))?;
        if !authed.success() {
            return Err(SftpError::Auth);
        }
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| SftpError::Ssh(e.to_string()))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| SftpError::Ssh(e.to_string()))?;
        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| SftpError::Sftp(e.to_string()))?;
        Ok((handle, sftp))
    }

    /// Download `remote` to `dest`; returns bytes copied.
    pub async fn fetch(&self, remote: &str, dest: &Path) -> Result<u64, SftpError> {
        let (_handle, sftp) = self.connect().await?;
        let mut file = sftp
            .open(self.path(remote))
            .await
            .map_err(|e| SftpError::Sftp(e.to_string()))?;
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut out = tokio::fs::File::create(dest).await?;
        let n = tokio::io::copy(&mut file, &mut out).await?;
        out.flush().await?;
        Ok(n)
    }

    /// Upload `src` to `remote`.
    pub async fn store(&self, src: &Path, remote: &str) -> Result<(), SftpError> {
        let (_handle, sftp) = self.connect().await?;
        let mut input = tokio::fs::File::open(src).await?;
        let mut file = sftp
            .create(self.path(remote))
            .await
            .map_err(|e| SftpError::Sftp(e.to_string()))?;
        tokio::io::copy(&mut input, &mut file).await?;
        file.shutdown().await?;
        Ok(())
    }

    /// Check connectivity (open the SFTP subsystem and stat the base).
    pub async fn test(&self) -> Result<(), SftpError> {
        let (_handle, sftp) = self.connect().await?;
        let dir = self.cfg.base_path.clone().unwrap_or_else(|| ".".into());
        sftp.read_dir(dir)
            .await
            .map_err(|e| SftpError::Sftp(e.to_string()))?;
        Ok(())
    }
}
