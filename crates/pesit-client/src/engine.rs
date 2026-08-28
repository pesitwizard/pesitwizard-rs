//! Transfer execution: resolves the server, opens the connection and drives a requester session.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pesit_app::audit::{AuditLog, Outcome};
use pesit_app::http::ApiError;
use pesit_app::store::JsonStore;
use pesit_app::time::{now_iso, pesit_now};
use pesit_core::builder::FileSpec;
use pesit_core::params::{AccessType, ArticleFormat, Compression, SyncOption, Version};
use pesit_core::{Diagnostic, FpduKind};
use pesit_io::checkpoint::{CheckpointStore, FileCheckpoints};
use pesit_io::datapath::{Control, DataEnd, Progress};
use pesit_io::io::{FileSink, FileSource};
use pesit_io::requester::{Preconnect, Requester, RequesterConfig, TransferSpec};
use pesit_io::tls::{self, TlsClientSettings, TlsVersion};
use pesit_io::transport::Framing;
use pesit_io::{BoxedStream, SessionError};
use rustc_hash::FxHashMap;
use tokio::sync::watch;

use crate::model::{
    tables, MessageRequest, Partner, PesitServer, TransferDirection, TransferHistory,
    TransferRequest, TransferResponse, TransferStatus,
};

/// Engine settings.
#[derive(Debug, Clone)]
pub struct EngineSettings {
    /// Checkpoint directory.
    pub checkpoint_dir: PathBuf,
    /// Default directory for received files when `filename` is relative or absent.
    pub receive_dir: PathBuf,
    /// Default PeSIT identifier (PI 3) when the request has no `partnerId`.
    pub requester_id: String,
    /// Default synchronisation interval in KB.
    pub sync_interval_kb: u16,
    /// Acknowledgement window.
    pub sync_window: u8,
    /// Default record length.
    pub record_length: u32,
    /// Default maximum entity size (PI 25).
    pub max_entity_size: u16,
    /// TLS client settings used when a server has none of its own.
    pub tls_defaults: TlsClientSettings,
}

/// Runs transfers.
pub struct Engine {
    store: Arc<JsonStore>,
    settings: EngineSettings,
    audit: Arc<AuditLog>,
    cancels: Mutex<FxHashMap<String, watch::Sender<bool>>>,
}

impl Engine {
    /// Create the engine.
    #[must_use]
    pub fn new(store: Arc<JsonStore>, settings: EngineSettings, audit: Arc<AuditLog>) -> Self {
        Self {
            store,
            settings,
            audit,
            cancels: Mutex::new(FxHashMap::default()),
        }
    }

    /// Resolve a server by name, id, or the default one.
    pub fn resolve_server(&self, name: Option<&str>) -> Result<PesitServer, ApiError> {
        let servers: Vec<PesitServer> = self.store.list(tables::SERVERS)?;
        let found = match name.filter(|n| !n.is_empty()) {
            Some(n) => servers.into_iter().find(|s| s.name == n || s.id == n),
            None => servers.into_iter().find(|s| s.default_server && s.enabled),
        };
        found.ok_or_else(|| {
            ApiError::not_found(format!(
                "server '{}' not found",
                name.unwrap_or("<default>")
            ))
        })
    }

    fn password_for(&self, partner_id: &str, explicit: Option<&str>) -> Option<String> {
        if let Some(p) = explicit.filter(|p| !p.is_empty()) {
            return Some(p.to_owned());
        }
        let partners: Vec<Partner> = self.store.list(tables::PARTNERS).unwrap_or_default();
        partners
            .into_iter()
            .find(|p| p.partner_id == partner_id)
            .and_then(|p| p.password)
            .filter(|p| !p.is_empty())
    }

    fn requester_config(
        &self,
        server: &PesitServer,
        partner_id: &str,
        password: Option<&str>,
        req: &TransferRequest,
        access: AccessType,
    ) -> RequesterConfig {
        let sync_enabled = req.sync_points_enabled.unwrap_or(true);
        RequesterConfig {
            requester_id: partner_id.to_owned(),
            server_id: server.server_id.clone(),
            password: self.password_for(partner_id, password),
            version: Version::E,
            sync: if sync_enabled {
                SyncOption {
                    interval_kb: req.sync_interval_kb(self.settings.sync_interval_kb),
                    window: self.settings.sync_window,
                }
            } else {
                SyncOption::NONE
            },
            resync: req.resync_enabled.unwrap_or(true),
            crc: req.crc_enabled.unwrap_or(server.crc_enabled),
            compression: if req.compression_enabled.unwrap_or(false) {
                Compression::Mixed
            } else {
                Compression::None
            },
            max_entity: req.max_entity_size.unwrap_or(self.settings.max_entity_size),
            multi_article: true,
            preconnect: server
                .preconnect_id
                .as_ref()
                .filter(|i| !i.is_empty())
                .map(|id| Preconnect {
                    identifier: id.clone(),
                    password: server.preconnect_password.clone().unwrap_or_default(),
                }),
            timeout: Duration::from_millis(server.read_timeout.max(1000)),
            free_message: None,
            access,
        }
    }

    /// Open the transport to a server (TCP + optional TLS).
    pub async fn open(&self, server: &PesitServer) -> Result<(BoxedStream, Framing), SessionError> {
        let addr = format!("{}:{}", server.host, server.port);
        let connect = tokio::net::TcpStream::connect(&addr);
        let stream = tokio::time::timeout(
            Duration::from_millis(server.connection_timeout.max(1000)),
            connect,
        )
        .await
        .map_err(|_| SessionError::Timeout("TCP connection"))?
        .map_err(|e| {
            SessionError::Transport(pesit_io::transport::TransportError::Io(
                std::io::Error::new(e.kind(), format!("connect {addr}: {e}")),
            ))
        })?;
        let _ = stream.set_nodelay(true);
        if !server.tls_enabled {
            return Ok((Box::pin(stream), Framing::LengthPrefixed));
        }
        let d = &self.settings.tls_defaults;
        let settings = TlsClientSettings {
            ca_file: server.ca_file.clone().or_else(|| d.ca_file.clone()),
            cert_file: server.cert_file.clone().or_else(|| d.cert_file.clone()),
            key_file: server.key_file.clone().or_else(|| d.key_file.clone()),
            verify_hostname: Some(server.hostname_verification),
            insecure: server.insecure || d.insecure,
            min_version: d.min_version.or(Some(TlsVersion::V1_2)),
        };
        let connector = tls::connector(&settings)
            .map_err(|e| SessionError::Negotiation(format!("TLS configuration: {e}")))?;
        let name =
            tls::server_name(&server.host).map_err(|e| SessionError::Negotiation(e.to_string()))?;
        let stream = connector
            .connect(name, stream)
            .await
            .map_err(|e| SessionError::Transport(pesit_io::transport::TransportError::Io(e)))?;
        Ok((
            Box::pin(stream),
            if server.tcpip_header {
                Framing::LengthPrefixed
            } else {
                Framing::Raw
            },
        ))
    }

    fn history_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    fn save(&self, h: &TransferHistory) {
        if let Err(e) = self.store.put(tables::TRANSFERS, &h.id, h) {
            tracing::error!("cannot save transfer {}: {e}", h.id);
        }
    }

    fn update(&self, id: &str, f: impl FnOnce(&mut TransferHistory)) {
        let _ = self
            .store
            .update::<TransferHistory>(tables::TRANSFERS, id, f);
    }

    /// Transfer record.
    pub fn get(&self, id: &str) -> Result<Option<TransferHistory>, ApiError> {
        Ok(self.store.get(tables::TRANSFERS, id)?)
    }

    /// Request cancellation; returns whether the transfer was running.
    pub fn cancel(&self, id: &str) -> bool {
        self.cancels
            .lock()
            .ok()
            .and_then(|c| c.get(id).map(|tx| tx.send(true).is_ok()))
            .unwrap_or(false)
    }

    fn register_cancel(&self, id: &str) -> watch::Receiver<bool> {
        let (tx, rx) = watch::channel(false);
        if let Ok(mut c) = self.cancels.lock() {
            c.insert(id.to_owned(), tx);
        }
        rx
    }

    fn unregister_cancel(&self, id: &str) {
        if let Ok(mut c) = self.cancels.lock() {
            c.remove(id);
        }
    }

    fn checkpoints(&self, history_id: &str) -> std::io::Result<FileCheckpoints> {
        FileCheckpoints::open(
            self.settings
                .checkpoint_dir
                .join(format!("{history_id}.json")),
        )
    }

    /// Validate and queue a send; the transfer runs in the background.
    pub fn submit_send(
        self: &Arc<Self>,
        req: TransferRequest,
    ) -> Result<TransferHistory, ApiError> {
        let server = self.resolve_server(req.server.as_deref())?;
        let Some(local) = req.filename.as_deref().filter(|f| !f.is_empty()) else {
            return Err(ApiError::bad_request("filename is required"));
        };
        let Some(remote) = req.virtual_file() else {
            return Err(ApiError::bad_request("remoteFilename is required"));
        };
        let meta = std::fs::metadata(local)
            .map_err(|e| ApiError::bad_request(format!("file not found: {local} ({e})")))?;
        if !meta.is_file() {
            return Err(ApiError::bad_request(format!(
                "{local} is not a regular file"
            )));
        }
        let partner_id = req
            .partner_id
            .clone()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| self.settings.requester_id.clone());
        let mut history = TransferHistory {
            id: Self::history_id(),
            server_id: Some(server.id.clone()),
            server_name: Some(server.name.clone()),
            partner_id: Some(partner_id),
            direction: Some(TransferDirection::Send),
            local_filename: Some(local.to_owned()),
            remote_filename: Some(remote.to_owned()),
            file_size: Some(meta.len()),
            status: TransferStatus::InProgress,
            correlation_id: req.correlation_id.clone(),
            sync_points_enabled: req.sync_points_enabled.unwrap_or(true),
            request: Some(req.clone()),
            started_at: Some(now_iso()),
            created_at: Some(now_iso()),
            ..TransferHistory::default()
        };
        // restart: reuse the PeSIT transfer id of the interrupted transfer
        let resume = req
            .resume_from_transfer_id
            .as_deref()
            .and_then(|id| self.get(id).ok().flatten());
        if let Some(prev) = &resume {
            history.pesit_transfer_id = prev.pesit_transfer_id;
            history.last_sync_point = prev.last_sync_point;
            history.bytes_at_last_sync_point = prev.bytes_at_last_sync_point;
        }
        self.save(&history);
        let engine = Arc::clone(self);
        let h = history.clone();
        tokio::spawn(async move { engine.run_send(h, server, req, resume).await });
        Ok(history)
    }

    /// Validate and queue a receive.
    pub fn submit_receive(
        self: &Arc<Self>,
        req: TransferRequest,
    ) -> Result<TransferHistory, ApiError> {
        let server = self.resolve_server(req.server.as_deref())?;
        let Some(remote) = req.virtual_file() else {
            return Err(ApiError::bad_request("remoteFilename is required"));
        };
        let local = match req.filename.as_deref().filter(|f| !f.is_empty()) {
            Some(f) if Path::new(f).is_absolute() => PathBuf::from(f),
            Some(f) => self.settings.receive_dir.join(f),
            None => self
                .settings
                .receive_dir
                .join(format!("{remote}_{}", pesit_app::time::now_compact())),
        };
        let partner_id = req
            .partner_id
            .clone()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| self.settings.requester_id.clone());
        let mut history = TransferHistory {
            id: Self::history_id(),
            server_id: Some(server.id.clone()),
            server_name: Some(server.name.clone()),
            partner_id: Some(partner_id),
            direction: Some(TransferDirection::Receive),
            local_filename: Some(local.to_string_lossy().into_owned()),
            remote_filename: Some(remote.to_owned()),
            status: TransferStatus::InProgress,
            correlation_id: req.correlation_id.clone(),
            sync_points_enabled: req.sync_points_enabled.unwrap_or(true),
            request: Some(req.clone()),
            started_at: Some(now_iso()),
            created_at: Some(now_iso()),
            ..TransferHistory::default()
        };
        let resume = req
            .resume_from_transfer_id
            .as_deref()
            .and_then(|id| self.get(id).ok().flatten());
        if let Some(prev) = &resume {
            history.pesit_transfer_id = prev.pesit_transfer_id;
            history.last_sync_point = prev.last_sync_point;
            history.bytes_at_last_sync_point = prev.bytes_at_last_sync_point;
            history.local_filename.clone_from(&prev.local_filename);
        }
        self.save(&history);
        let engine = Arc::clone(self);
        let h = history.clone();
        tokio::spawn(async move { engine.run_receive(h, server, req, resume).await });
        Ok(history)
    }

    /// Retry a finished transfer (restarting from its last checkpoint when possible).
    pub fn retry(self: &Arc<Self>, id: &str) -> Result<TransferHistory, ApiError> {
        let Some(prev) = self.get(id)? else {
            return Err(ApiError::not_found(format!("transfer '{id}' not found")));
        };
        if !prev.status.is_final() {
            return Err(ApiError::conflict(format!(
                "transfer '{id}' is still running"
            )));
        }
        let mut req = prev.request.clone().unwrap_or_default();
        req.server = prev.server_id.clone().or(req.server);
        req.filename.clone_from(&prev.local_filename);
        req.remote_filename.clone_from(&prev.remote_filename);
        req.partner_id.clone_from(&prev.partner_id);
        req.resume_from_transfer_id = (prev.last_sync_point > 0
            && matches!(
                prev.status,
                TransferStatus::Interrupted | TransferStatus::Failed | TransferStatus::Cancelled
            ))
        .then(|| id.to_owned());
        match prev.direction {
            Some(TransferDirection::Receive) => self.submit_receive(req),
            _ => self.submit_send(req),
        }
    }

    fn progress_updater(&self, id: String) -> impl FnMut(Progress) + Send + '_ {
        let mut last = Instant::now();
        let mut last_bytes = 0u64;
        let mut last_sync = 0u32;
        move |p: Progress| {
            let sync_changed = p.sync != last_sync;
            if !sync_changed
                && p.data_bytes.saturating_sub(last_bytes) < 1 << 20
                && last.elapsed() < Duration::from_secs(1)
            {
                return;
            }
            last = Instant::now();
            last_bytes = p.data_bytes;
            last_sync = p.sync;
            self.update(&id, |h| {
                h.bytes_transferred = p.data_bytes;
                if h.file_size.is_none() {
                    h.file_size = p.total_hint;
                }
                if sync_changed {
                    h.last_sync_point = p.sync;
                    h.bytes_at_last_sync_point = p.data_bytes;
                }
            });
        }
    }

    fn file_spec(
        &self,
        req: &TransferRequest,
        remote: &str,
        size: Option<u64>,
        pesit_id: u32,
        resume: bool,
    ) -> FileSpec {
        let record_length = req
            .record_length
            .unwrap_or(self.settings.record_length)
            .clamp(1, 0xFFFF) as u16;
        FileSpec {
            file_type: req.file_type.unwrap_or(0),
            file_name: remote.to_owned(),
            transfer_id: pesit_id,
            restarted: resume,
            priority: req.priority.unwrap_or(0),
            max_entity_size: req.max_entity_size.unwrap_or(self.settings.max_entity_size),
            article_format: ArticleFormat::Variable,
            article_length: record_length,
            organisation: Some(0),
            reservation_unit: size.map(|_| 0),
            max_reservation: size.map_or(0, |s| s.div_ceil(1024)),
            creation_date: Some(pesit_now()),
            ..FileSpec::default()
        }
    }

    fn record_format(req: &TransferRequest) -> pesit_core::article::RecordFormat {
        if req.text.unwrap_or(false) {
            pesit_core::article::RecordFormat::Tv
        } else {
            pesit_core::article::RecordFormat::Bu
        }
    }

    fn finish(
        &self,
        id: &str,
        outcome: Result<(u64, DataEnd, Diagnostic, Option<String>), SessionError>,
    ) {
        self.unregister_cancel(id);
        let audit_ok = matches!(&outcome, Ok((_, DataEnd::Completed, d, _)) if d.is_ok());
        self.update(id, |h| {
            h.completed_at = Some(now_iso());
            match outcome {
                Ok((bytes, DataEnd::Completed, diag, checksum)) if diag.is_ok() => {
                    h.status = TransferStatus::Completed;
                    h.bytes_transferred = bytes;
                    h.checksum = checksum;
                    if h.file_size.is_none() {
                        h.file_size = Some(bytes);
                    }
                }
                Ok((bytes, DataEnd::Interrupted { by_peer, diag, .. }, _, _)) => {
                    h.status = if by_peer {
                        TransferStatus::Interrupted
                    } else {
                        TransferStatus::Cancelled
                    };
                    h.bytes_transferred = bytes;
                    h.diagnostic_code = Some(format!("{diag:?}"));
                    h.error_message = Some(diag.to_string());
                }
                Ok((bytes, end, diag, _)) => {
                    h.status = TransferStatus::Failed;
                    h.bytes_transferred = bytes;
                    let d = if let DataEnd::EndedWithError(d) = end {
                        d
                    } else {
                        diag
                    };
                    h.diagnostic_code = Some(format!("{d:?}"));
                    h.error_message = Some(d.to_string());
                }
                Err(e) => {
                    h.status = TransferStatus::Failed;
                    h.diagnostic_code = Some(format!("{:?}", e.abort_diag()));
                    h.error_message = Some(e.to_string());
                }
            }
        });
        if let Ok(Some(h)) = self.get(id) {
            let action = h
                .direction
                .and_then(|d| serde_json::to_value(d).ok())
                .and_then(|v| v.as_str().map(str::to_ascii_lowercase))
                .unwrap_or_else(|| "transfer".into());
            let target = format!(
                "{} -> {}",
                h.local_filename.as_deref().unwrap_or("-"),
                h.server_name.as_deref().unwrap_or("-")
            );
            self.audit.record(
                "transfer",
                &action,
                Some(target),
                h.partner_id.clone(),
                if audit_ok {
                    Outcome::Success
                } else {
                    Outcome::Failure
                },
                h.error_message.clone(),
            );
        }
    }

    async fn run_send(
        self: Arc<Self>,
        history: TransferHistory,
        server: PesitServer,
        req: TransferRequest,
        resume: Option<TransferHistory>,
    ) {
        let id = history.id.clone();
        let outcome = self.do_send(&history, &server, &req, resume.as_ref()).await;
        match &outcome {
            Ok((bytes, end, diag, _)) => {
                tracing::info!("transfer {id}: {end:?} {diag} ({bytes} bytes)");
            }
            Err(e) => tracing::warn!("transfer {id} failed: {e}"),
        }
        self.finish(&id, outcome);
    }

    async fn do_send(
        &self,
        history: &TransferHistory,
        server: &PesitServer,
        req: &TransferRequest,
        resume: Option<&TransferHistory>,
    ) -> Result<(u64, DataEnd, Diagnostic, Option<String>), SessionError> {
        let local = history.local_filename.clone().unwrap_or_default();
        let remote = history.remote_filename.clone().unwrap_or_default();
        let partner_id = history.partner_id.clone().unwrap_or_default();
        let size = history.file_size;
        let mut source = FileSource::open(
            Path::new(&local),
            Self::record_format(req),
            req.record_length.unwrap_or(self.settings.record_length) as usize,
        )?;
        let cancel = self.register_cancel(&history.id);
        let (checkpoints_id, restart) = match resume {
            Some(prev) => {
                let cps = self.checkpoints(&prev.id)?;
                let last = cps.last_acknowledged().or_else(|| cps.last());
                (prev.id.clone(), last)
            }
            None => (history.id.clone(), None),
        };
        let mut checkpoints = self.checkpoints(&checkpoints_id)?;
        let pesit_id = if restart.is_some() && history.pesit_transfer_id != 0 {
            history.pesit_transfer_id
        } else {
            (self.store.next_counter("pesit_transfer_id").unwrap_or(1) % 0x00FF_FFFF).max(1) as u32
        };
        self.update(&history.id, |h| h.pesit_transfer_id = pesit_id);
        let spec = TransferSpec {
            file: self.file_spec(req, &remote, size, pesit_id, restart.is_some()),
            restart,
        };
        let (stream, framing) = self.open(server).await?;
        let cfg = self.requester_config(
            server,
            &partner_id,
            req.password.as_deref(),
            req,
            AccessType::Write,
        );
        let mut session = Requester::connect(stream, framing, cfg).await?;
        let mut progress = self.progress_updater(history.id.clone());
        let mut ctrl = Control {
            cancel: Some(cancel),
            progress: &mut progress,
        };
        let result = session
            .send_file(&spec, &mut source, &mut checkpoints, &mut ctrl)
            .await;
        match result {
            Ok(out) => {
                let _ = session.release().await;
                let checksum = (out.is_complete())
                    .then(|| sha256_file(Path::new(&local)))
                    .flatten();
                Ok((out.data.data_bytes, out.data.end, out.diag, checksum))
            }
            Err(e) => {
                close_after_error(session, &e).await;
                if resume.is_some() && is_restart_refusal(&e) {
                    tracing::warn!(
                        "peer refused the restart of {} ({e}); retransferring from the beginning",
                        history.id
                    );
                    self.reset_for_full_retry(history);
                    return Box::pin(self.do_send(history, server, req, None)).await;
                }
                Err(e)
            }
        }
    }

    async fn run_receive(
        self: Arc<Self>,
        history: TransferHistory,
        server: PesitServer,
        req: TransferRequest,
        resume: Option<TransferHistory>,
    ) {
        let id = history.id.clone();
        let outcome = self
            .do_receive(&history, &server, &req, resume.as_ref())
            .await;
        match &outcome {
            Ok((bytes, end, diag, _)) => {
                tracing::info!("transfer {id}: {end:?} {diag} ({bytes} bytes)");
            }
            Err(e) => tracing::warn!("transfer {id} failed: {e}"),
        }
        self.finish(&id, outcome);
    }

    async fn do_receive(
        &self,
        history: &TransferHistory,
        server: &PesitServer,
        req: &TransferRequest,
        resume: Option<&TransferHistory>,
    ) -> Result<(u64, DataEnd, Diagnostic, Option<String>), SessionError> {
        let local = PathBuf::from(history.local_filename.clone().unwrap_or_default());
        let remote = history.remote_filename.clone().unwrap_or_default();
        let partner_id = history.partner_id.clone().unwrap_or_default();
        let cancel = self.register_cancel(&history.id);
        let (checkpoints_id, restart) = match resume {
            Some(prev) => {
                let cps = self.checkpoints(&prev.id)?;
                (
                    prev.id.clone(),
                    cps.last()
                        .filter(|_| pesit_io::io::part_path(&local).exists()),
                )
            }
            None => (history.id.clone(), None),
        };
        let mut checkpoints = self.checkpoints(&checkpoints_id)?;
        let mut sink = FileSink::create(
            &local,
            Self::record_format(req),
            restart.map(|c| pesit_io::io::Position {
                file_offset: c.file_offset,
                data_bytes: c.data_bytes,
                articles: c.articles,
            }),
        )?;
        let pesit_id = if restart.is_some() {
            history.pesit_transfer_id
        } else {
            0
        };
        let spec = TransferSpec {
            file: self.file_spec(req, &remote, None, pesit_id, restart.is_some()),
            restart,
        };
        let (stream, framing) = self.open(server).await?;
        let cfg = self.requester_config(
            server,
            &partner_id,
            req.password.as_deref(),
            req,
            AccessType::Read,
        );
        let mut session = Requester::connect(stream, framing, cfg).await?;
        let mut progress = self.progress_updater(history.id.clone());
        let mut ctrl = Control {
            cancel: Some(cancel),
            progress: &mut progress,
        };
        let result = session
            .receive_file(&spec, &mut sink, &mut checkpoints, &mut ctrl)
            .await;
        match result {
            Ok(out) => {
                let _ = session.release().await;
                self.update(&history.id, |h| h.pesit_transfer_id = out.transfer_id);
                let checksum = out.is_complete().then(|| sha256_file(&local)).flatten();
                Ok((out.data.data_bytes, out.data.end, out.diag, checksum))
            }
            Err(e) => {
                close_after_error(session, &e).await;
                if resume.is_some() && is_restart_refusal(&e) {
                    tracing::warn!(
                        "peer refused the restart of {} ({e}); receiving from the beginning",
                        history.id
                    );
                    self.reset_for_full_retry(history);
                    let _ = std::fs::remove_file(pesit_io::io::part_path(&local));
                    return Box::pin(self.do_receive(history, server, req, None)).await;
                }
                Err(e)
            }
        }
    }

    /// Reset a transfer's checkpoints so that a refused restart falls back to a full transfer.
    fn reset_for_full_retry(&self, history: &TransferHistory) {
        self.update(&history.id, |h| {
            h.last_sync_point = 0;
            h.bytes_at_last_sync_point = 0;
            h.bytes_transferred = 0;
        });
        if let Ok(mut cps) = self.checkpoints(&history.id) {
            let _ = cps.clear();
        }
    }

    /// Send a message synchronously.
    pub async fn send_message(&self, req: MessageRequest) -> Result<TransferResponse, ApiError> {
        let server = self.resolve_server(req.server.as_deref())?;
        let partner_id = req
            .partner_id
            .clone()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| self.settings.requester_id.clone());
        let mut history = TransferHistory {
            id: Self::history_id(),
            server_id: Some(server.id.clone()),
            server_name: Some(server.name.clone()),
            partner_id: Some(partner_id.clone()),
            direction: Some(TransferDirection::Message),
            remote_filename: req.message_name.clone(),
            file_size: Some(req.message.len() as u64),
            status: TransferStatus::InProgress,
            correlation_id: req.correlation_id.clone(),
            started_at: Some(now_iso()),
            created_at: Some(now_iso()),
            ..TransferHistory::default()
        };
        self.save(&history);
        let treq = TransferRequest {
            password: req.password.clone(),
            sync_points_enabled: Some(false),
            ..TransferRequest::default()
        };
        let outcome: Result<pesit_io::requester::MessageOutcome, SessionError> = async {
            let (stream, framing) = self.open(&server).await?;
            let cfg = self.requester_config(
                &server,
                &partner_id,
                req.password.as_deref(),
                &treq,
                AccessType::Mixed,
            );
            let mut session = Requester::connect(stream, framing, cfg).await?;
            let spec = FileSpec {
                file_name: req.message_name.clone().unwrap_or_else(|| "MESSAGE".into()),
                transfer_id: (self.store.next_counter("pesit_transfer_id").unwrap_or(1)
                    % 0x00FF_FFFF)
                    .max(1) as u32,
                ..FileSpec::default()
            };
            let r = session
                .send_message(&spec, req.message.as_bytes(), req.expects_reply)
                .await;
            match r {
                Ok(m) => {
                    let _ = session.release().await;
                    Ok(m)
                }
                Err(e) => {
                    close_after_error(session, &e).await;
                    Err(e)
                }
            }
        }
        .await;
        history.completed_at = Some(now_iso());
        let mut reply = None;
        match outcome {
            Ok(m) if m.diag.is_ok() => {
                history.status = TransferStatus::Completed;
                history.bytes_transferred = req.message.len() as u64;
                reply = m.reply.map(|r| String::from_utf8_lossy(&r).into_owned());
            }
            Ok(m) => {
                history.status = TransferStatus::Failed;
                history.diagnostic_code = Some(format!("{:?}", m.diag));
                history.error_message = Some(m.diag.to_string());
            }
            Err(e) => {
                history.status = TransferStatus::Failed;
                history.diagnostic_code = Some(format!("{:?}", e.abort_diag()));
                history.error_message = Some(e.to_string());
            }
        }
        self.save(&history);
        let mut resp = TransferResponse::from(&history);
        resp.reply = reply;
        Ok(resp)
    }

    /// Test the TCP/TLS connectivity of a server (no PeSIT exchange).
    pub async fn test_connection(&self, server: &PesitServer) -> Result<Duration, String> {
        let start = Instant::now();
        self.open(server)
            .await
            .map(|_| start.elapsed())
            .map_err(|e| e.to_string())
    }
}

/// Whether an error is the peer refusing a restart at the file-selection phase (CREATE / SELECT),
/// in which case the transfer can be retried from the beginning.
fn is_restart_refusal(e: &SessionError) -> bool {
    matches!(
        e,
        SessionError::Refused {
            request: FpduKind::Create | FpduKind::Select,
            ..
        }
    )
}

/// Close a session after a failed request: a refusal leaves the session usable (F.RELEASE),
/// anything else is aborted (nothing is sent when the peer already aborted or vanished).
async fn close_after_error(session: Requester, e: &SessionError) {
    match e {
        SessionError::Refused { .. } => {
            let _ = session.release().await;
        }
        SessionError::Aborted { .. } | SessionError::Transport(_) => drop(session),
        _ => session.abort(e.abort_diag()).await,
    }
}

/// SHA-256 of a file, hex encoded.
#[must_use]
pub fn sha256_file(path: &Path) -> Option<String> {
    use sha2::Digest;
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex::encode(h.finalize()))
}
