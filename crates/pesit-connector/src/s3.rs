//! S3-compatible object storage backend (AWS S3, MinIO, ...).

use std::path::Path;

use aws_sdk_s3::config::{BehaviorVersion, Region};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;

/// S3 connector error.
#[derive(Debug, thiserror::Error)]
pub enum S3Error {
    /// Any S3 / transport failure.
    #[error("s3: {0}")]
    S3(String),
    /// Local I/O error.
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

fn err<E: std::fmt::Display>(e: E) -> S3Error {
    S3Error::S3(e.to_string())
}

/// Configuration of an S3-compatible bucket.
#[derive(Debug, Clone)]
pub struct S3Config {
    /// Bucket name.
    pub bucket: String,
    /// Region (default `us-east-1`).
    pub region: Option<String>,
    /// Custom endpoint (for MinIO / non-AWS).
    pub endpoint: Option<String>,
    /// Access key id.
    pub access_key: Option<String>,
    /// Secret access key.
    pub secret_key: Option<String>,
    /// Use path-style addressing (required by MinIO).
    pub path_style: bool,
}

/// An S3 connector.
#[derive(Clone)]
pub struct S3Connector {
    client: Client,
    bucket: String,
}

impl S3Connector {
    /// Build a client from the configuration.
    pub fn connect(cfg: &S3Config) -> Self {
        let region = Region::new(cfg.region.clone().unwrap_or_else(|| "us-east-1".into()));
        let mut builder = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(region)
            .force_path_style(cfg.path_style);
        if let Some(ep) = &cfg.endpoint {
            builder = builder.endpoint_url(ep);
        }
        if let (Some(ak), Some(sk)) = (&cfg.access_key, &cfg.secret_key) {
            builder = builder.credentials_provider(aws_sdk_s3::config::Credentials::new(
                ak,
                sk,
                None,
                None,
                "pesit-connector",
            ));
        }
        Self {
            client: Client::from_conf(builder.build()),
            bucket: cfg.bucket.clone(),
        }
    }

    /// Download `key` to `dest`; returns the number of bytes written.
    pub async fn fetch(&self, key: &str, dest: &Path) -> Result<u64, S3Error> {
        let mut resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(err)?;
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut file = tokio::fs::File::create(dest).await?;
        let mut total = 0u64;
        while let Some(chunk) = resp.body.try_next().await.map_err(err)? {
            tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await?;
            total += chunk.len() as u64;
        }
        tokio::io::AsyncWriteExt::flush(&mut file).await?;
        Ok(total)
    }

    /// Upload the file at `src` to `key`.
    pub async fn store(&self, src: &Path, key: &str) -> Result<(), S3Error> {
        let body = ByteStream::from_path(src).await.map_err(err)?;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(body)
            .send()
            .await
            .map_err(err)?;
        Ok(())
    }

    /// Check connectivity by listing the bucket (head).
    pub async fn test(&self) -> Result<(), S3Error> {
        self.client
            .list_objects_v2()
            .bucket(&self.bucket)
            .max_keys(1)
            .send()
            .await
            .map_err(err)?;
        Ok(())
    }
}
