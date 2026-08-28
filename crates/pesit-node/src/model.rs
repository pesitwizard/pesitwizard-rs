//! REST / storage models, JSON-compatible with the Java PeSIT Wizard server.

use serde::{Deserialize, Serialize};

/// Partner access rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AccessType {
    /// Only F.SELECT (the partner reads).
    Read,
    /// Only F.CREATE (the partner writes).
    Write,
    /// Both.
    #[default]
    Both,
}

impl AccessType {
    /// The partner may send files to us.
    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Write | Self::Both)
    }

    /// The partner may read files from us.
    #[must_use]
    pub const fn can_read(self) -> bool {
        matches!(self, Self::Read | Self::Both)
    }
}

/// A partner allowed to connect.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Partner {
    /// Identifier (PI 3 of the CONNECT).
    pub id: String,
    /// Description.
    pub description: Option<String>,
    /// Password (PI 5); empty or absent = no check.
    pub password: Option<String>,
    /// Enabled.
    pub enabled: bool,
    /// Access rights.
    pub access_type: AccessType,
    /// Maximum simultaneous connections.
    pub max_connections: u32,
    /// Comma-separated list of allowed virtual files (glob `*` allowed); empty = all.
    pub allowed_files: Option<String>,
    /// Pre-connection password expected when the partner sends one (Connect:Express DPCPSW).
    pub preconnect_password: Option<String>,
    /// Creation time.
    pub created_at: Option<String>,
    /// Update time.
    pub updated_at: Option<String>,
}

impl Default for Partner {
    fn default() -> Self {
        Self {
            id: String::new(),
            description: None,
            password: None,
            enabled: true,
            access_type: AccessType::Both,
            max_connections: 10,
            allowed_files: None,
            preconnect_password: None,
            created_at: None,
            updated_at: None,
        }
    }
}

impl Partner {
    /// Whether `file` is allowed by `allowed_files`.
    #[must_use]
    pub fn can_access_file(&self, file: &str) -> bool {
        let Some(list) = self
            .allowed_files
            .as_deref()
            .filter(|l| !l.trim().is_empty())
        else {
            return true;
        };
        list.split(',').map(str::trim).any(|p| glob_match(p, file))
    }
}

/// Minimal glob matching (`*` and `?`).
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    fn rec(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => rec(&p[1..], t) || (!t.is_empty() && rec(p, &t[1..])),
            (Some(b'?'), Some(_)) => rec(&p[1..], &t[1..]),
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => rec(&p[1..], &t[1..]),
            _ => false,
        }
    }
    rec(pattern.as_bytes(), text.as_bytes())
}

/// Virtual file direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Direction {
    /// Partners write it (F.CREATE).
    Receive,
    /// Partners read it (F.SELECT).
    Send,
    /// Both.
    #[default]
    Both,
}

/// A virtual (logical) file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VirtualFile {
    /// Identifier (PI 12).
    pub id: String,
    /// Description.
    pub description: Option<String>,
    /// Enabled.
    pub enabled: bool,
    /// Direction.
    pub direction: Direction,
    /// Directory where received files are stored (defaults to the server's).
    pub receive_directory: Option<String>,
    /// Physical file sent on F.SELECT.
    pub send_file: Option<String>,
    /// Name pattern of received files (`${virtualFile}`, `${transferId}`, `${timestamp}`, `${date}`, `${time}`, `${partnerId}`).
    pub receive_filename_pattern: String,
    /// Overwrite an existing file.
    pub overwrite: bool,
    /// Maximum size in bytes (0 = unlimited).
    pub max_file_size: u64,
    /// File type (PI 11).
    pub file_type: u32,
    /// Record length (PI 32).
    pub record_length: u32,
    /// Record format (PI 31): 0x80 variable, 0x00 fixed.
    pub record_format: u32,
    /// Text mode: articles are lines (LF stripped/added) instead of binary chunks.
    pub text: bool,
    /// Creation time.
    pub created_at: Option<String>,
    /// Update time.
    pub updated_at: Option<String>,
}

impl Default for VirtualFile {
    fn default() -> Self {
        Self {
            id: String::new(),
            description: None,
            enabled: true,
            direction: Direction::Both,
            receive_directory: None,
            send_file: None,
            receive_filename_pattern: "${virtualFile}_${timestamp}".into(),
            overwrite: false,
            max_file_size: 0,
            file_type: 0,
            record_length: 1024,
            record_format: 0x80,
            text: false,
            created_at: None,
            updated_at: None,
        }
    }
}

impl VirtualFile {
    /// Partners may write it.
    #[must_use]
    pub const fn can_receive(&self) -> bool {
        matches!(self.direction, Direction::Receive | Direction::Both)
    }

    /// Partners may read it.
    #[must_use]
    pub const fn can_send(&self) -> bool {
        matches!(self.direction, Direction::Send | Direction::Both)
    }

    /// Record format used for the physical file.
    #[must_use]
    pub fn record_format(&self) -> pesit_core::article::RecordFormat {
        use pesit_core::article::RecordFormat;
        let variable = self.record_format & 0x80 != 0;
        match (self.text, variable) {
            (true, true) => RecordFormat::Tv,
            (true, false) => RecordFormat::Tf,
            (false, true) => RecordFormat::Bu,
            (false, false) => RecordFormat::Bf,
        }
    }
}

/// A remote partner (server) that this instance can connect to (client-side configuration kept
/// for API compatibility).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
#[allow(clippy::struct_field_names)]
pub struct RemotePartner {
    /// Identifier.
    pub id: String,
    /// Description.
    pub description: Option<String>,
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Our identifier when connecting (PI 3).
    pub local_partner_id: Option<String>,
    /// Remote identifier (PI 4).
    pub remote_partner_id: Option<String>,
    /// Enabled.
    pub enabled: bool,
    /// Maximum connections.
    pub max_connections: u32,
    /// TLS.
    pub tls_enabled: bool,
    /// Creation time.
    pub created_at: Option<String>,
    /// Update time.
    pub updated_at: Option<String>,
}

impl Default for RemotePartner {
    fn default() -> Self {
        Self {
            id: String::new(),
            description: None,
            host: String::new(),
            port: 5000,
            local_partner_id: None,
            remote_partner_id: None,
            enabled: true,
            max_connections: 5,
            tls_enabled: false,
            created_at: None,
            updated_at: None,
        }
    }
}

/// Listener status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ServerStatus {
    /// Not listening.
    #[default]
    Stopped,
    /// Starting.
    Starting,
    /// Listening.
    Running,
    /// Stopping.
    Stopping,
    /// Failed to start.
    Error,
}

/// A PeSIT listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PesitServerConfig {
    /// Numeric identifier (kept for compatibility).
    pub id: Option<u64>,
    /// Identifier (PI 4 accepted by this listener; empty = any).
    pub server_id: String,
    /// TCP port.
    pub port: u16,
    /// Bind address.
    pub bind_address: String,
    /// Protocol version (2 = PeSIT E).
    pub protocol_version: u8,
    /// Maximum simultaneous sessions.
    pub max_connections: u32,
    /// Connection / idle timeout in milliseconds.
    pub connection_timeout: u64,
    /// Read timeout in milliseconds during transfers.
    pub read_timeout: u64,
    /// Default receive directory.
    pub receive_directory: String,
    /// Default send directory.
    pub send_directory: String,
    /// Maximum entity size (PI 25).
    pub max_entity_size: u16,
    /// Synchronisation points.
    pub sync_points_enabled: bool,
    /// Synchronisation interval in KB.
    pub sync_interval_kb: u16,
    /// Acknowledgement window (0 = no ACK(SYN)).
    pub sync_window: u8,
    /// Resynchronisation.
    pub resync_enabled: bool,
    /// Start with the process.
    pub auto_start: bool,
    /// TLS listener (uses the process TLS settings).
    pub ssl_enabled: bool,
    /// Name of a managed keystore to use for this listener's TLS identity (overrides the process cert).
    pub ssl_keystore: Option<String>,
    /// Name of a managed truststore to verify client certificates.
    pub ssl_truststore: Option<String>,
    /// Transport header on TLS connections (Connect:Express `TCPIP_HEADER`).
    pub tcpip_header: bool,
    /// Compression capability (0 none, 1 horizontal, 2 vertical, 3 mixed).
    pub compression: u8,
    /// Status.
    pub status: ServerStatus,
    /// Creation time.
    pub created_at: Option<String>,
    /// Update time.
    pub updated_at: Option<String>,
    /// Last start time.
    pub last_started_at: Option<String>,
    /// Last stop time.
    pub last_stopped_at: Option<String>,
}

impl Default for PesitServerConfig {
    fn default() -> Self {
        Self {
            id: None,
            server_id: String::new(),
            port: 5001,
            bind_address: "0.0.0.0".into(),
            protocol_version: 2,
            max_connections: 100,
            connection_timeout: 30_000,
            read_timeout: 60_000,
            receive_directory: "/data/received".into(),
            send_directory: "/data/send".into(),
            max_entity_size: 4096,
            sync_points_enabled: true,
            sync_interval_kb: 32,
            sync_window: 4,
            resync_enabled: true,
            auto_start: false,
            ssl_enabled: false,
            ssl_keystore: None,
            ssl_truststore: None,
            tcpip_header: true,
            compression: 0,
            status: ServerStatus::Stopped,
            created_at: None,
            updated_at: None,
            last_started_at: None,
            last_stopped_at: None,
        }
    }
}

/// Status response of a listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatusResponse {
    /// Identifier.
    pub server_id: String,
    /// Status.
    pub status: ServerStatus,
    /// Listening.
    pub running: bool,
    /// Sessions in progress.
    pub active_connections: usize,
    /// Port.
    pub port: u16,
}

/// Transfer direction from the server's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TransferDirection {
    /// The partner reads (F.SELECT): the server sends.
    Send,
    /// The partner writes (F.CREATE): the server receives.
    Receive,
    /// A message.
    Message,
}

/// Transfer status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferStatus {
    /// Request received.
    #[default]
    Initiated,
    /// Data phase.
    InProgress,
    /// Paused.
    Paused,
    /// Interrupted (restartable).
    Interrupted,
    /// Completed.
    Completed,
    /// Failed.
    Failed,
    /// Cancelled.
    Cancelled,
}

/// A transfer record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TransferRecord {
    /// Numeric identifier.
    pub id: Option<u64>,
    /// Transfer identifier (unique key).
    pub transfer_id: String,
    /// PeSIT transfer identifier (PI 13).
    pub pesit_transfer_id: u32,
    /// Session identifier.
    pub session_id: Option<String>,
    /// Listener identifier.
    pub server_id: Option<String>,
    /// Node identifier.
    pub node_id: Option<String>,
    /// Direction.
    pub direction: Option<TransferDirection>,
    /// Status.
    pub status: TransferStatus,
    /// Partner identifier.
    pub partner_id: Option<String>,
    /// Virtual file name.
    pub filename: Option<String>,
    /// Physical path.
    pub local_path: Option<String>,
    /// Announced or actual size.
    pub file_size: Option<u64>,
    /// Bytes transferred.
    pub bytes_transferred: u64,
    /// Progress in percent.
    pub progress_percent: u8,
    /// Last synchronisation point.
    pub last_sync_point: u32,
    /// Bytes at the last synchronisation point.
    pub bytes_at_last_sync_point: u64,
    /// Start time.
    pub started_at: Option<String>,
    /// Completion time.
    pub completed_at: Option<String>,
    /// Update time.
    pub updated_at: Option<String>,
    /// Remote address.
    pub remote_address: Option<String>,
    /// Error code (PeSIT diagnostic).
    pub error_code: Option<String>,
    /// Error message.
    pub error_message: Option<String>,
    /// Checksum of the file.
    pub checksum: Option<String>,
    /// Checksum algorithm.
    pub checksum_algorithm: String,
    /// Parent transfer (restart).
    pub parent_transfer_id: Option<String>,
    /// Free metadata.
    pub metadata: Option<String>,
}

impl Default for TransferRecord {
    fn default() -> Self {
        Self {
            id: None,
            transfer_id: String::new(),
            pesit_transfer_id: 0,
            session_id: None,
            server_id: None,
            node_id: None,
            direction: None,
            status: TransferStatus::Initiated,
            partner_id: None,
            filename: None,
            local_path: None,
            file_size: None,
            bytes_transferred: 0,
            progress_percent: 0,
            last_sync_point: 0,
            bytes_at_last_sync_point: 0,
            started_at: None,
            completed_at: None,
            updated_at: None,
            remote_address: None,
            error_code: None,
            error_message: None,
            checksum: None,
            checksum_algorithm: "SHA-256".into(),
            parent_transfer_id: None,
            metadata: None,
        }
    }
}

/// Store table names.
pub mod tables {
    /// Partners.
    pub const PARTNERS: &str = "partners";
    /// Virtual files.
    pub const FILES: &str = "virtual_files";
    /// Remote partners.
    pub const REMOTE_PARTNERS: &str = "remote_partners";
    /// Listeners.
    pub const SERVERS: &str = "servers";
    /// Transfers.
    pub const TRANSFERS: &str = "transfers";
    /// All tables.
    pub const ALL: [&str; 5] = [PARTNERS, FILES, REMOTE_PARTNERS, SERVERS, TRANSFERS];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globbing() {
        assert!(glob_match("PW*", "PWSEND"));
        assert!(glob_match("pwsend", "PWSEND"));
        assert!(!glob_match("PW?", "PWSEND"));
        assert!(glob_match("*", ""));
        let p = Partner {
            allowed_files: Some("A*, B".into()),
            ..Partner::default()
        };
        assert!(p.can_access_file("ABC"));
        assert!(p.can_access_file("B"));
        assert!(!p.can_access_file("C"));
    }

    #[test]
    fn json_defaults_match_java() {
        let p: Partner = serde_json::from_str(r#"{"id":"PWSRV01","description":"x","password":"","enabled":true,"accessType":"BOTH","maxConnections":10}"#).unwrap_or_default();
        assert_eq!(p.access_type, AccessType::Both);
        let vf: VirtualFile = serde_json::from_str(r#"{"id":"PWSEND","direction":"RECEIVE","receiveDirectory":"/data/received","receiveFilenamePattern":"from_cx_${transferId}","overwrite":false,"recordLength":4096,"recordFormat":0}"#).unwrap_or_default();
        assert_eq!(vf.record_format(), pesit_core::article::RecordFormat::Bf);
        assert!(vf.can_receive() && !vf.can_send());
        let s: PesitServerConfig = serde_json::from_str(r#"{"serverId":"PWSERVER","port":5001,"maxEntitySize":32768,"syncPointsEnabled":true,"syncIntervalKb":256,"autoStart":true}"#).unwrap_or_default();
        assert_eq!(s.max_entity_size, 32768);
        assert_eq!(
            serde_json::to_value(&s)
                .ok()
                .and_then(|v| v.get("status").cloned()),
            Some(serde_json::json!("STOPPED"))
        );
    }
}
