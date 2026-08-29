//! Process-level settings (environment / command line / optional YAML bootstrap file).

use std::path::PathBuf;

use clap::Args;
use pesit_client::engine::EngineSettings;
use pesit_io::tls::{TlsClientSettings, TlsServerSettings, TlsVersion};
use serde::Deserialize;

use crate::model::{Partner, PesitServerConfig, RemotePartner, VirtualFile};

fn min_tls(protocol: &str) -> TlsVersion {
    match protocol.to_ascii_uppercase().as_str() {
        "TLSV1.3" | "TLS1.3" | "1.3" => TlsVersion::V1_3,
        _ => TlsVersion::V1_2,
    }
}

/// Shared options of the `pesitwizard` node (global so they work with any subcommand).
#[derive(Debug, Args)]
pub struct NodeOptions {
    /// Admin / server REST API port (partners, virtual files, listeners, inbound records, web UI).
    #[arg(long, env = "PESIT_API_PORT", default_value_t = 8080, global = true)]
    pub api_port: u16,
    /// Transfer / client REST API port (remote servers, send/receive/message, outbound history).
    #[arg(
        long,
        env = "PESIT_TRANSFER_PORT",
        default_value_t = 9081,
        global = true
    )]
    pub transfer_port: u16,
    /// REST API bind address.
    #[arg(long, env = "PESIT_API_BIND", default_value = "0.0.0.0", global = true)]
    pub api_bind: String,
    /// API key required in `X-API-Key` for the admin API (`/api/**`); unset = no authentication.
    #[arg(long, env = "PESIT_API_KEY", global = true)]
    pub api_key: Option<String>,
    /// Disable admin API authentication even when a key is set.
    #[arg(long, env = "PESIT_SECURITY_ENABLED", default_value_t = true, action = clap::ArgAction::Set, global = true)]
    pub security_enabled: bool,
    /// SQLite database file (shared by both roles).
    #[arg(
        long,
        env = "PESIT_DB",
        default_value = "/data/pesitwizard.db",
        global = true
    )]
    pub db: PathBuf,
    /// Directory for certificate / CA material.
    #[arg(
        long,
        env = "PESIT_PKI_DIR",
        default_value = "/data/pki",
        global = true
    )]
    pub pki_dir: PathBuf,
    /// Checkpoint directory for inbound (server) transfers.
    #[arg(
        long,
        env = "PESIT_CHECKPOINT_DIR",
        default_value = "/data/checkpoints",
        global = true
    )]
    pub checkpoint_dir: PathBuf,
    /// Checkpoint directory for outbound (client) transfers.
    #[arg(
        long,
        env = "PESIT_CLIENT_CHECKPOINT_DIR",
        default_value = "/data/checkpoints-out",
        global = true
    )]
    pub client_checkpoint_dir: PathBuf,
    /// Directory for received files initiated by us (outbound receive).
    #[arg(
        long,
        env = "PESIT_CLIENT_RECEIVE_DIR",
        default_value = "/data/received",
        global = true
    )]
    pub receive_dir: PathBuf,
    /// Directory where uploaded client TLS material is stored.
    #[arg(
        long,
        env = "PESIT_CLIENT_TLS_DIR",
        default_value = "/data/tls",
        global = true
    )]
    pub client_tls_dir: PathBuf,
    /// Our default PeSIT identifier (PI 3) when initiating transfers.
    #[arg(
        long,
        env = "PESIT_CLIENT_ID",
        default_value = "PWCLIENT",
        global = true
    )]
    pub client_id: String,
    /// YAML bootstrap file (partners / files / remotePartners / servers).
    #[arg(long, env = "PESIT_CONFIG", global = true)]
    pub config: Option<PathBuf>,
    /// Auto-rotate managed keystores this many days before expiry (0 = disabled).
    #[arg(
        long,
        env = "PESIT_CERT_ROTATION_DAYS",
        default_value_t = 0,
        global = true
    )]
    pub cert_rotation_days: i64,
    /// Maximum audit-log entries to retain; the oldest are pruned (0 = unlimited).
    #[arg(
        long,
        env = "PESIT_AUDIT_MAX_ENTRIES",
        default_value_t = 50_000,
        global = true
    )]
    pub audit_max_entries: usize,
    /// Node identifier reported in transfer records and cluster membership.
    #[arg(long, env = "PESIT_NODE_ID", default_value = "node-1", global = true)]
    pub node_id: String,
    /// NATS URL to join a cluster (e.g. nats://nats:4222); unset = standalone.
    #[arg(long, env = "PESIT_CLUSTER_NATS", global = true)]
    pub cluster_nats: Option<String>,
    /// Cluster name (namespaces NATS buckets and subjects).
    #[arg(
        long,
        env = "PESIT_CLUSTER_NAME",
        default_value = "default",
        global = true
    )]
    pub cluster_name: String,
    /// Address other nodes use to reach this node's admin API (host:port). Defaults to $HOSTNAME:api_port.
    #[arg(long, env = "PESIT_CLUSTER_ADVERTISE", global = true)]
    pub advertise_addr: Option<String>,
    /// Default synchronisation interval (KB) for outbound transfers.
    #[arg(
        long,
        env = "PESIT_CLIENT_SYNC_KB",
        default_value_t = 100,
        global = true
    )]
    pub client_sync_kb: u16,
    /// Acknowledgement window for outbound transfers.
    #[arg(
        long,
        env = "PESIT_CLIENT_SYNC_WINDOW",
        default_value_t = 4,
        global = true
    )]
    pub client_sync_window: u8,
    /// Default record length (PI 32) for outbound transfers.
    #[arg(
        long,
        env = "PESIT_CLIENT_RECORD_LENGTH",
        default_value_t = 4096,
        global = true
    )]
    pub client_record_length: u32,
    /// Default maximum entity size (PI 25) for outbound transfers.
    #[arg(
        long,
        env = "PESIT_CLIENT_MAX_ENTITY",
        default_value_t = 65535,
        global = true
    )]
    pub client_max_entity: u16,

    // ---- inbound TLS (listener certificates) ----
    /// Enable TLS on listeners flagged `sslEnabled`.
    #[arg(long, env = "PESIT_SSL_ENABLED", default_value_t = false, action = clap::ArgAction::Set, global = true)]
    pub ssl_enabled: bool,
    /// Server certificate chain (PEM).
    #[arg(long, env = "PESIT_SSL_CERT_PATH", global = true)]
    pub ssl_cert: Option<String>,
    /// Server private key (PEM).
    #[arg(long, env = "PESIT_SSL_KEY_PATH", global = true)]
    pub ssl_key: Option<String>,
    /// CA certificates used to verify client certificates (PEM).
    #[arg(long, env = "PESIT_SSL_CA_CERT_PATH", global = true)]
    pub ssl_ca: Option<String>,
    /// Client authentication for listeners: NONE, WANT or NEED.
    #[arg(
        long,
        env = "PESIT_SSL_CLIENT_AUTH",
        default_value = "NONE",
        global = true
    )]
    pub ssl_client_auth: String,
    /// Minimum TLS protocol for listeners: TLSv1.2 or TLSv1.3.
    #[arg(
        long,
        env = "PESIT_SSL_PROTOCOL",
        default_value = "TLSv1.2",
        global = true
    )]
    pub ssl_protocol: String,

    // ---- outbound TLS (defaults when connecting to a server) ----
    /// Default CA bundle (PEM) trusted when connecting to TLS servers.
    #[arg(long, env = "PESIT_CLIENT_SSL_CA_CERT_PATH", global = true)]
    pub client_ssl_ca: Option<String>,
    /// Default client certificate (PEM) for mutual TLS.
    #[arg(long, env = "PESIT_CLIENT_SSL_CERT_PATH", global = true)]
    pub client_ssl_cert: Option<String>,
    /// Default client private key (PEM).
    #[arg(long, env = "PESIT_CLIENT_SSL_KEY_PATH", global = true)]
    pub client_ssl_key: Option<String>,
    /// Skip TLS certificate verification for outbound connections (testing only).
    #[arg(
        long,
        env = "PESIT_CLIENT_SSL_INSECURE",
        default_value_t = false,
        global = true
    )]
    pub client_ssl_insecure: bool,
    /// Minimum TLS protocol for outbound connections.
    #[arg(
        long,
        env = "PESIT_CLIENT_SSL_PROTOCOL",
        default_value = "TLSv1.2",
        global = true
    )]
    pub client_ssl_protocol: String,
}

impl NodeOptions {
    /// TLS settings for the listeners, when TLS is enabled and configured.
    pub fn listener_tls(&self) -> anyhow::Result<Option<TlsServerSettings>> {
        if !self.ssl_enabled {
            return Ok(None);
        }
        let (Some(cert), Some(key)) = (&self.ssl_cert, &self.ssl_key) else {
            anyhow::bail!(
                "PESIT_SSL_ENABLED is set but PESIT_SSL_CERT_PATH / PESIT_SSL_KEY_PATH are missing"
            );
        };
        Ok(Some(TlsServerSettings {
            cert_file: cert.clone(),
            key_file: key.clone(),
            ca_file: self.ssl_ca.clone(),
            require_client_cert: self.ssl_client_auth.eq_ignore_ascii_case("NEED"),
            min_version: Some(min_tls(&self.ssl_protocol)),
        }))
    }

    /// Default TLS settings used when connecting to a TLS server that has none of its own.
    #[must_use]
    pub fn client_tls_defaults(&self) -> TlsClientSettings {
        TlsClientSettings {
            ca_file: self.client_ssl_ca.clone(),
            cert_file: self.client_ssl_cert.clone(),
            key_file: self.client_ssl_key.clone(),
            verify_hostname: None,
            insecure: self.client_ssl_insecure,
            min_version: Some(min_tls(&self.client_ssl_protocol)),
        }
    }

    /// Settings for the outbound transfer engine.
    #[must_use]
    pub fn engine_settings(&self) -> EngineSettings {
        EngineSettings {
            checkpoint_dir: self.client_checkpoint_dir.clone(),
            receive_dir: self.receive_dir.clone(),
            requester_id: self.client_id.clone(),
            sync_interval_kb: self.client_sync_kb,
            sync_window: self.client_sync_window,
            record_length: self.client_record_length,
            max_entity_size: self.client_max_entity,
            tls_defaults: self.client_tls_defaults(),
        }
    }
}

/// Optional YAML bootstrap file.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Bootstrap {
    /// Partners to upsert.
    pub partners: Vec<Partner>,
    /// Virtual files to upsert.
    pub files: Vec<VirtualFile>,
    /// Remote partners to upsert.
    pub remote_partners: Vec<RemotePartner>,
    /// Listeners to upsert.
    pub servers: Vec<PesitServerConfig>,
}

impl Bootstrap {
    /// Load from a YAML file.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(serde_yaml::from_str(&text)?)
    }
}
