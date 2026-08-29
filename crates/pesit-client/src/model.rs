//! REST / storage models, JSON-compatible with the Java PeSIT Wizard client.

use serde::{Deserialize, Serialize};

/// A remote PeSIT server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PesitServer {
    /// Identifier (UUID).
    pub id: String,
    /// Unique name.
    pub name: String,
    /// Host name or address.
    pub host: String,
    /// Port.
    pub port: u16,
    /// PeSIT identifier of the server (PI 4).
    pub server_id: String,
    /// Description.
    pub description: Option<String>,
    /// TLS.
    pub tls_enabled: bool,
    /// Verify the host name against the certificate.
    pub hostname_verification: bool,
    /// Skip certificate verification entirely (testing only).
    pub insecure: bool,
    /// CA bundle (PEM file) used to verify the server certificate.
    pub ca_file: Option<String>,
    /// Client certificate (PEM file) for mutual TLS.
    pub cert_file: Option<String>,
    /// Client private key (PEM file).
    pub key_file: Option<String>,
    /// Transport header on TLS connections (Connect:Express `TCPIP_HEADER`).
    pub tcpip_header: bool,
    /// Whether a truststore was uploaded.
    pub truststore_configured: bool,
    /// Whether a keystore was uploaded.
    pub keystore_configured: bool,
    /// TCP connection timeout (ms).
    pub connection_timeout: u64,
    /// Read timeout (ms).
    pub read_timeout: u64,
    /// Enabled.
    pub enabled: bool,
    /// Default server.
    pub default_server: bool,
    /// Use the CRC option (PI 1).
    pub crc_enabled: bool,
    /// Send a pre-connection identification (Connect:Express partner types T/O).
    pub preconnect_id: Option<String>,
    /// Pre-connection password.
    pub preconnect_password: Option<String>,
    /// Creation time.
    pub created_at: Option<String>,
    /// Update time.
    pub updated_at: Option<String>,
}

impl Default for PesitServer {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            host: String::new(),
            port: 5000,
            server_id: String::new(),
            description: None,
            tls_enabled: false,
            hostname_verification: true,
            insecure: false,
            ca_file: None,
            cert_file: None,
            key_file: None,
            tcpip_header: true,
            truststore_configured: false,
            keystore_configured: false,
            connection_timeout: 30_000,
            read_timeout: 60_000,
            enabled: true,
            default_server: false,
            crc_enabled: false,
            preconnect_id: None,
            preconnect_password: None,
            created_at: None,
            updated_at: None,
        }
    }
}

/// Partner credentials (our identity towards a server).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
#[allow(clippy::struct_field_names)]
pub struct Partner {
    /// Identifier (UUID).
    pub id: String,
    /// PeSIT identifier (PI 3).
    pub partner_id: String,
    /// Description.
    pub description: Option<String>,
    /// Password (PI 5).
    pub password: Option<String>,
    /// Creation time.
    pub created_at: Option<String>,
    /// Update time.
    pub updated_at: Option<String>,
}

/// Transfer request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TransferRequest {
    /// Server name or id (default server when absent).
    pub server: Option<String>,
    /// Our PeSIT identifier (PI 3).
    pub partner_id: Option<String>,
    /// Password (PI 5).
    pub password: Option<String>,
    /// Local file (source when sending, destination when receiving).
    pub filename: Option<String>,
    /// Virtual file name on the server (PI 12).
    pub remote_filename: Option<String>,
    /// Alias of `remoteFilename`.
    pub virtual_file: Option<String>,
    /// File type (PI 11).
    pub file_type: Option<u64>,
    /// Named transfer configuration (unused, kept for compatibility).
    pub transfer_config: Option<String>,
    /// Correlation identifier.
    pub correlation_id: Option<String>,
    /// Compression (PI 21).
    pub compression_enabled: Option<bool>,
    /// Priority (PI 17).
    pub priority: Option<u8>,
    /// Synchronisation points.
    pub sync_points_enabled: Option<bool>,
    /// Synchronisation interval in bytes.
    pub sync_point_interval_bytes: Option<u64>,
    /// Synchronisation interval in KB (values above 65535 are taken as bytes).
    pub sync_point_interval: Option<u64>,
    /// Resynchronisation.
    pub resync_enabled: Option<bool>,
    /// Restart the given transfer from its last checkpoint.
    pub resume_from_transfer_id: Option<String>,
    /// Record length (PI 32).
    pub record_length: Option<u32>,
    /// Text mode (lines instead of binary chunks).
    pub text: Option<bool>,
    /// EBCDIC data code (PI 16 = 1): translate article bytes ASCII/Latin-1 ↔ EBCDIC CP037.
    pub ebcdic: Option<bool>,
    /// CRC option.
    pub crc_enabled: Option<bool>,
    /// Maximum entity size (PI 25).
    pub max_entity_size: Option<u16>,
}

impl TransferRequest {
    /// Virtual file name.
    #[must_use]
    pub fn virtual_file(&self) -> Option<&str> {
        self.remote_filename
            .as_deref()
            .or(self.virtual_file.as_deref())
            .filter(|s| !s.is_empty())
    }

    /// Synchronisation interval in KB when enabled.
    #[must_use]
    pub fn sync_interval_kb(&self, default_kb: u16) -> u16 {
        if let Some(b) = self.sync_point_interval_bytes {
            return (b / 1024).clamp(1, 0xFFFE) as u16;
        }
        match self.sync_point_interval {
            Some(v) if v > 0xFFFF => (v / 1024).clamp(1, 0xFFFE) as u16,
            Some(v) if v > 0 => v.min(0xFFFE) as u16,
            _ => default_kb,
        }
    }
}

/// Message request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MessageRequest {
    /// Server name or id.
    pub server: Option<String>,
    /// Our PeSIT identifier (PI 3).
    pub partner_id: Option<String>,
    /// Password.
    pub password: Option<String>,
    /// Message text (PI 91).
    pub message: String,
    /// Logical name carried in PGI 9 (PI 12).
    pub message_name: Option<String>,
    /// Correlation identifier.
    pub correlation_id: Option<String>,
    /// Expect a reply.
    pub expects_reply: bool,
}

/// Transfer direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TransferDirection {
    /// F.CREATE / F.WRITE.
    Send,
    /// F.SELECT / F.READ.
    Receive,
    /// F.MESSAGE.
    Message,
}

/// Transfer status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferStatus {
    /// Queued.
    #[default]
    Pending,
    /// Running.
    InProgress,
    /// Done.
    Completed,
    /// Failed.
    Failed,
    /// Cancelled by the operator.
    Cancelled,
    /// Interrupted by the server (restartable).
    Interrupted,
}

impl TransferStatus {
    /// Terminal state.
    #[must_use]
    pub const fn is_final(self) -> bool {
        !matches!(self, Self::Pending | Self::InProgress)
    }
}

/// Transfer history record (returned by `GET /api/v1/transfers/{id}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TransferHistory {
    /// Identifier (UUID).
    pub id: String,
    /// Server identifier.
    pub server_id: Option<String>,
    /// Server name.
    pub server_name: Option<String>,
    /// Our PeSIT identifier.
    pub partner_id: Option<String>,
    /// Direction.
    pub direction: Option<TransferDirection>,
    /// Local file.
    pub local_filename: Option<String>,
    /// Virtual file.
    pub remote_filename: Option<String>,
    /// Size.
    pub file_size: Option<u64>,
    /// Bytes transferred.
    pub bytes_transferred: u64,
    /// Status.
    pub status: TransferStatus,
    /// Error message.
    pub error_message: Option<String>,
    /// PeSIT diagnostic (`D2-205`...).
    pub diagnostic_code: Option<String>,
    /// SHA-256 of the file.
    pub checksum: Option<String>,
    /// Correlation identifier.
    pub correlation_id: Option<String>,
    /// Synchronisation points used.
    pub sync_points_enabled: bool,
    /// Last synchronisation point.
    pub last_sync_point: u32,
    /// Bytes at the last synchronisation point.
    pub bytes_at_last_sync_point: u64,
    /// PeSIT transfer identifier (PI 13).
    pub pesit_transfer_id: u32,
    /// Original request (for retries).
    pub request: Option<TransferRequest>,
    /// Start time.
    pub started_at: Option<String>,
    /// Completion time.
    pub completed_at: Option<String>,
    /// Creation time.
    pub created_at: Option<String>,
}

impl Default for TransferHistory {
    fn default() -> Self {
        Self {
            id: String::new(),
            server_id: None,
            server_name: None,
            partner_id: None,
            direction: None,
            local_filename: None,
            remote_filename: None,
            file_size: None,
            bytes_transferred: 0,
            status: TransferStatus::Pending,
            error_message: None,
            diagnostic_code: None,
            checksum: None,
            correlation_id: None,
            sync_points_enabled: false,
            last_sync_point: 0,
            bytes_at_last_sync_point: 0,
            pesit_transfer_id: 0,
            request: None,
            started_at: None,
            completed_at: None,
            created_at: None,
        }
    }
}

/// Response of `POST /api/v1/transfers/send|receive|message`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferResponse {
    /// Transfer identifier.
    pub transfer_id: String,
    /// Correlation identifier.
    pub correlation_id: Option<String>,
    /// Direction.
    pub direction: Option<TransferDirection>,
    /// Status.
    pub status: TransferStatus,
    /// Server name.
    pub server_name: Option<String>,
    /// Local file.
    pub local_filename: Option<String>,
    /// Virtual file.
    pub remote_filename: Option<String>,
    /// Size.
    pub file_size: Option<u64>,
    /// Bytes transferred.
    pub bytes_transferred: u64,
    /// Checksum.
    pub checksum: Option<String>,
    /// Error message.
    pub error_message: Option<String>,
    /// Diagnostic.
    pub diagnostic_code: Option<String>,
    /// Start.
    pub started_at: Option<String>,
    /// End.
    pub completed_at: Option<String>,
    /// Duration in ms.
    pub duration_ms: Option<i64>,
    /// Reply message (messages only).
    pub reply: Option<String>,
}

impl From<&TransferHistory> for TransferResponse {
    fn from(h: &TransferHistory) -> Self {
        let duration = match (&h.started_at, &h.completed_at) {
            (Some(s), Some(e)) => pesit_app::time::parse_millis(e)
                .zip(pesit_app::time::parse_millis(s))
                .map(|(e, s)| e - s),
            _ => None,
        };
        Self {
            transfer_id: h.id.clone(),
            correlation_id: h.correlation_id.clone(),
            direction: h.direction,
            status: h.status,
            server_name: h.server_name.clone(),
            local_filename: h.local_filename.clone(),
            remote_filename: h.remote_filename.clone(),
            file_size: h.file_size,
            bytes_transferred: h.bytes_transferred,
            checksum: h.checksum.clone(),
            error_message: h.error_message.clone(),
            diagnostic_code: h.diagnostic_code.clone(),
            started_at: h.started_at.clone(),
            completed_at: h.completed_at.clone(),
            duration_ms: duration,
            reply: None,
        }
    }
}

/// Store tables.
pub mod tables {
    /// Remote servers we connect to.
    pub const SERVERS: &str = "remote_servers";
    /// Our identities / credentials towards servers.
    pub const PARTNERS: &str = "client_partners";
    /// Outbound transfer history.
    pub const TRANSFERS: &str = "outbound_transfers";
    /// All.
    pub const ALL: [&str; 3] = [SERVERS, PARTNERS, TRANSFERS];
}
