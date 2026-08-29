//! Server-side PeSIT behaviour: partner authentication, virtual file resolution, transfer records.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use pesit_app::store::JsonStore;
use pesit_app::time::{now_compact, now_iso, now_time, pesit_now, today};
use pesit_core::builder::FileSpec;
use pesit_core::params::{
    AccessType as PesitAccess, ArticleFormat, Compression, RequestedAttributes, SyncOption,
};
use pesit_core::Diagnostic;
use pesit_io::checkpoint::{CheckpointStore, FileCheckpoints};
use pesit_io::datapath::{DataEnd, Progress};
use pesit_io::io::{part_path, FileSink, FileSource, Position};
use pesit_io::responder::{
    ConnectAccept, ConnectRequest, CreateAccept, Refusal, SelectAccept, ServerHandler, SessionInfo,
    TransferEvent,
};
use pesit_io::SessionError;
use rustc_hash::FxHashMap;
use tokio::sync::watch;

use crate::model::{
    tables, Partner, PesitServerConfig, TransferDirection, TransferRecord, TransferStatus,
    VirtualFile,
};

/// Registry of cancellation flags for transfers in progress, keyed by transfer record id.
#[derive(Default)]
pub struct CancelRegistry {
    flags: Mutex<FxHashMap<String, watch::Sender<bool>>>,
}

impl CancelRegistry {
    fn register(&self, id: &str) -> watch::Receiver<bool> {
        let (tx, rx) = watch::channel(false);
        if let Ok(mut f) = self.flags.lock() {
            f.insert(id.to_owned(), tx);
        }
        rx
    }

    fn remove(&self, id: &str) {
        if let Ok(mut f) = self.flags.lock() {
            f.remove(id);
        }
    }

    /// Request the cancellation of a transfer; returns whether it was in progress.
    pub fn cancel(&self, id: &str) -> bool {
        self.flags
            .lock()
            .ok()
            .and_then(|f| f.get(id).map(|tx| tx.send(true).is_ok()))
            .unwrap_or(false)
    }
}

struct Active {
    record_id: String,
    file_size: Option<u64>,
    last_update: Instant,
    last_bytes: u64,
    last_sync: u32,
    /// Receive: upload the staged file to (connector id, remote key, local temp) on completion.
    connector_upload: Option<(String, String, PathBuf)>,
    /// Send: local staging file to delete when the transfer ends.
    connector_temp: Option<PathBuf>,
}

/// The PeSIT Wizard server handler.
pub struct PwHandler {
    store: Arc<JsonStore>,
    server: PesitServerConfig,
    checkpoint_dir: PathBuf,
    node_id: String,
    cancels: Arc<CancelRegistry>,
    active: Mutex<FxHashMap<u64, Active>>,
    next_handle: AtomicU64,
}

fn refusal(diag: Diagnostic, msg: impl Into<String>) -> Refusal {
    let msg = msg.into();
    tracing::warn!("refused: {diag} - {msg}");
    Refusal::with_message(diag, msg)
}

fn io_refusal(e: &std::io::Error, what: &str) -> Refusal {
    let diag = match e.kind() {
        std::io::ErrorKind::NotFound => Diagnostic::FILE_NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => Diagnostic::CANNOT_OPEN,
        _ => Diagnostic::SYSTEM_ERROR,
    };
    refusal(diag, format!("{what}: {e}"))
}

fn position_of(cp: pesit_io::checkpoint::Checkpoint) -> Position {
    Position {
        file_offset: cp.file_offset,
        data_bytes: cp.data_bytes,
        articles: cp.articles,
    }
}

impl PwHandler {
    /// Create the handler of one listener.
    #[must_use]
    pub fn new(
        store: Arc<JsonStore>,
        server: PesitServerConfig,
        checkpoint_dir: PathBuf,
        node_id: String,
        cancels: Arc<CancelRegistry>,
    ) -> Self {
        Self {
            store,
            server,
            checkpoint_dir,
            node_id,
            cancels,
            active: Mutex::new(FxHashMap::default()),
            next_handle: AtomicU64::new(1),
        }
    }

    fn partner(&self, id: &str) -> Option<Partner> {
        self.store.get(tables::PARTNERS, id).ok().flatten()
    }

    fn virtual_file(&self, id: &str) -> Option<VirtualFile> {
        self.store.get(tables::FILES, id).ok().flatten()
    }

    fn checkpoints(&self, key: &str) -> std::io::Result<FileCheckpoints> {
        FileCheckpoints::open(
            self.checkpoint_dir
                .join(&self.server.server_id)
                .join(format!("{key}.json")),
        )
    }

    fn pesit_transfer_id(&self, requested: u32) -> u32 {
        if requested != 0 {
            return requested;
        }
        (self.store.next_counter("pesit_transfer_id").unwrap_or(1) % 0x00FF_FFFF).max(1) as u32
    }

    /// Key identifying a transfer across restarts.
    fn restart_key(session: &SessionInfo, file: &FileSpec, tid: u32) -> String {
        format!("{}_{}_{}", session.requester, file.file_name, tid).replace(
            |c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-',
            "_",
        )
    }

    fn interrupted_record(&self, partner: &str, file: &str, tid: u32) -> Option<TransferRecord> {
        let all: Vec<TransferRecord> = self.store.list(tables::TRANSFERS).ok()?;
        all.into_iter().rev().find(|r| {
            r.status == TransferStatus::Interrupted
                && r.pesit_transfer_id == tid
                && r.partner_id.as_deref() == Some(partner)
                && r.filename.as_deref() == Some(file)
                && r.server_id.as_deref() == Some(self.server.server_id.as_str())
        })
    }

    fn receive_path(
        &self,
        vf: &VirtualFile,
        session: &SessionInfo,
        file: &FileSpec,
        tid: u32,
    ) -> PathBuf {
        let dir = vf
            .receive_directory
            .clone()
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| self.server.receive_directory.clone());
        let pattern = if vf.receive_filename_pattern.is_empty() {
            "${virtualFile}_${timestamp}"
        } else {
            vf.receive_filename_pattern.as_str()
        };
        let tid_s = tid.to_string();
        let name = pesit_app::http::resolve_placeholders(
            pattern,
            &[
                ("virtualFile", file.file_name.as_str()),
                ("transferId", tid_s.as_str()),
                ("timestamp", now_compact().as_str()),
                ("date", today().as_str()),
                ("time", now_time().as_str()),
                ("partnerId", session.requester.as_str()),
                ("serverId", self.server.server_id.as_str()),
            ],
        );
        Path::new(&dir).join(name)
    }

    fn new_record(
        &self,
        session: &SessionInfo,
        direction: TransferDirection,
        partner: &str,
        file: &FileSpec,
        tid: u32,
        local_path: Option<&Path>,
    ) -> TransferRecord {
        TransferRecord {
            transfer_id: uuid::Uuid::new_v4().to_string(),
            pesit_transfer_id: tid,
            session_id: Some(session.id.clone()),
            server_id: Some(self.server.server_id.clone()),
            node_id: Some(self.node_id.clone()),
            direction: Some(direction),
            status: TransferStatus::Initiated,
            partner_id: Some(partner.to_owned()),
            filename: Some(file.file_name.clone()),
            local_path: local_path.map(|p| p.to_string_lossy().into_owned()),
            file_size: (file.max_reservation > 0).then(|| file.max_reservation * 1024),
            started_at: Some(now_iso()),
            updated_at: Some(now_iso()),
            remote_address: Some(session.remote_addr.clone()),
            ..TransferRecord::default()
        }
    }

    fn register(&self, record: TransferRecord) -> Result<u64, Refusal> {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.store
            .put(tables::TRANSFERS, &record.transfer_id, &record)
            .map_err(|e| refusal(Diagnostic::SYSTEM_ERROR, e.to_string()))?;
        if let Ok(mut a) = self.active.lock() {
            a.insert(
                handle,
                Active {
                    record_id: record.transfer_id.clone(),
                    file_size: record.file_size,
                    last_update: Instant::now(),
                    last_bytes: 0,
                    last_sync: 0,
                    connector_upload: None,
                    connector_temp: None,
                },
            );
        }
        Ok(handle)
    }

    fn update_record(&self, record_id: &str, f: impl FnOnce(&mut TransferRecord)) {
        if let Err(e) = self
            .store
            .update::<TransferRecord>(tables::TRANSFERS, record_id, |r| {
                f(r);
                r.updated_at = Some(now_iso());
            })
        {
            tracing::error!("cannot update transfer record {record_id}: {e}");
        }
    }

    /// Mutate an active transfer entry.
    fn set_active(&self, handle: u64, f: impl FnOnce(&mut Active)) {
        if let Ok(mut a) = self.active.lock() {
            if let Some(x) = a.get_mut(&handle) {
                f(x);
            }
        }
    }

    /// A local staging file path.
    fn staging_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("pesitwizard-staging");
        let _ = std::fs::create_dir_all(&dir);
        let safe: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        dir.join(format!("{}-{safe}", uuid::Uuid::new_v4().simple()))
    }

    /// The remote key of a connector-backed virtual file.
    fn connector_key(
        &self,
        vf: &VirtualFile,
        session: &SessionInfo,
        file: &FileSpec,
        tid: u32,
        default: &str,
    ) -> String {
        let Some(pattern) = vf.connector_path.as_deref().filter(|c| !c.is_empty()) else {
            return default.to_owned();
        };
        let tid_s = tid.to_string();
        pesit_app::http::resolve_placeholders(
            pattern,
            &[
                ("virtualFile", file.file_name.as_str()),
                ("transferId", tid_s.as_str()),
                ("timestamp", now_compact().as_str()),
                ("date", today().as_str()),
                ("time", now_time().as_str()),
                ("partnerId", session.requester.as_str()),
                ("serverId", self.server.server_id.as_str()),
            ],
        )
    }

    /// Fetch a connector object into a local file (blocking on the async connector).
    fn stage_fetch(&self, connector_id: &str, remote: &str, dest: &Path) -> Result<(), Refusal> {
        let store = Arc::clone(&self.store);
        let (cid, remote, dest) = (connector_id.to_owned(), remote.to_owned(), dest.to_owned());
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let connector = crate::connector::build(&store, &cid).map_err(|e| {
                    refusal(
                        Diagnostic::CANNOT_OPEN,
                        format!("connector '{cid}': {}", e.message),
                    )
                })?;
                connector.fetch(&remote, &dest).await.map_err(|e| {
                    refusal(
                        Diagnostic::IO_ERROR,
                        format!("connector fetch '{remote}': {e}"),
                    )
                })?;
                Ok::<(), Refusal>(())
            })
        })
    }

    /// Upload a local file to a connector object (blocking on the async connector).
    fn stage_store(&self, connector_id: &str, remote: &str, src: &Path) -> Result<(), String> {
        let store = Arc::clone(&self.store);
        let (cid, remote, src) = (connector_id.to_owned(), remote.to_owned(), src.to_owned());
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let connector = crate::connector::build(&store, &cid).map_err(|e| e.message)?;
                connector
                    .store(&src, &remote)
                    .await
                    .map_err(|e| e.to_string())
            })
        })
    }

    fn check_partner(
        &self,
        session: &SessionInfo,
        file: &FileSpec,
        write: bool,
    ) -> Result<Partner, Refusal> {
        let Some(partner) = self.partner(&session.requester) else {
            return Err(refusal(
                Diagnostic::CALLER_UNKNOWN,
                format!("partner '{}' not configured", session.requester),
            ));
        };
        let allowed = if write {
            partner.access_type.can_write()
        } else {
            partner.access_type.can_read()
        };
        if !allowed {
            return Err(refusal(
                Diagnostic::TRANSFER_REFUSED,
                format!(
                    "partner '{}' is not allowed to {}",
                    partner.id,
                    if write { "send" } else { "receive" }
                ),
            ));
        }
        if !partner.can_access_file(&file.file_name) {
            return Err(refusal(
                Diagnostic::TRANSFER_REFUSED,
                format!(
                    "partner '{}' may not access '{}'",
                    partner.id, file.file_name
                ),
            ));
        }
        Ok(partner)
    }
}

impl ServerHandler for PwHandler {
    fn authenticate(&self, req: &ConnectRequest) -> Result<ConnectAccept, Refusal> {
        let Some(partner) = self.partner(&req.requester) else {
            return Err(refusal(
                Diagnostic::CALLER_UNKNOWN,
                format!("partner '{}' not configured", req.requester),
            ));
        };
        if !partner.enabled {
            return Err(refusal(
                Diagnostic::CALLER_NOT_AUTHORISED,
                format!("partner '{}' is disabled", partner.id),
            ));
        }
        if let Some(expected) = partner.password.as_deref().filter(|p| !p.is_empty()) {
            let provided = req.password.as_deref().unwrap_or("").trim();
            if provided != expected {
                return Err(refusal(
                    Diagnostic::CALLER_NOT_AUTHORISED,
                    format!("invalid password for partner '{}'", partner.id),
                ));
            }
        }
        if let (Some((_, pwd)), Some(expected)) = (
            &req.preconnect,
            partner
                .preconnect_password
                .as_deref()
                .filter(|p| !p.is_empty()),
        ) {
            if pwd.trim() != expected {
                return Err(refusal(
                    Diagnostic::CALLER_NOT_AUTHORISED,
                    format!(
                        "invalid pre-connection password for partner '{}'",
                        partner.id
                    ),
                ));
            }
        }
        let allowed = match req.access {
            PesitAccess::Write => partner.access_type.can_write(),
            PesitAccess::Read => partner.access_type.can_read(),
            PesitAccess::Mixed => partner.access_type.can_read() || partner.access_type.can_write(),
        };
        if !allowed {
            return Err(refusal(
                Diagnostic::CALLER_NOT_AUTHORISED,
                format!(
                    "partner '{}' not authorised for {:?} access",
                    partner.id, req.access
                ),
            ));
        }
        if !self.server.server_id.is_empty()
            && !req.server.is_empty()
            && !req.server.eq_ignore_ascii_case(&self.server.server_id)
        {
            tracing::info!(
                "partner {} addressed server '{}' (listener is '{}')",
                req.requester,
                req.server,
                self.server.server_id
            );
        }
        let sync = if self.server.sync_points_enabled {
            SyncOption {
                interval_kb: self.server.sync_interval_kb,
                window: self.server.sync_window,
            }
        } else {
            SyncOption::NONE
        };
        Ok(ConnectAccept {
            sync,
            resync: self.server.resync_enabled,
            compression: Compression::from_code(self.server.compression)
                .unwrap_or(Compression::None),
            multi_article: true,
            max_entity: self.server.max_entity_size,
            free_message: None,
        })
    }

    fn create(&self, session: &SessionInfo, file: &FileSpec) -> Result<CreateAccept, Refusal> {
        let partner = self.check_partner(session, file, true)?;
        let Some(vf) = self.virtual_file(&file.file_name) else {
            return Err(refusal(
                Diagnostic::TRANSFER_REFUSED,
                format!("virtual file '{}' not configured", file.file_name),
            ));
        };
        if !vf.enabled || !vf.can_receive() {
            return Err(refusal(
                Diagnostic::TRANSFER_REFUSED,
                format!(
                    "virtual file '{}' does not accept incoming transfers",
                    vf.id
                ),
            ));
        }
        if vf.max_file_size > 0 && file.max_reservation * 1024 > vf.max_file_size {
            return Err(refusal(
                Diagnostic::DISK_QUOTA,
                format!(
                    "file larger than the {} bytes allowed for '{}'",
                    vf.max_file_size, vf.id
                ),
            ));
        }
        let tid = self.pesit_transfer_id(file.transfer_id);
        let key = Self::restart_key(session, file, tid);
        let mut checkpoints = self
            .checkpoints(&key)
            .map_err(|e| io_refusal(&e, "checkpoint store"))?;
        let previous = if file.restarted {
            self.interrupted_record(&partner.id, &file.file_name, tid)
        } else {
            None
        };
        let (path, restart) = if let Some(prev) = &previous {
            let path = prev
                .local_path
                .as_deref()
                .map_or_else(|| self.receive_path(&vf, session, file, tid), PathBuf::from);
            let restart = checkpoints.last().filter(|_| part_path(&path).exists());
            if restart.is_none() {
                let _ = checkpoints.clear();
            }
            (path, restart)
        } else {
            let _ = checkpoints.clear();
            let path = self.receive_path(&vf, session, file, tid);
            if path.exists() && !vf.overwrite {
                return Err(refusal(
                    Diagnostic::FILE_EXISTS,
                    format!("{} already exists", path.display()),
                ));
            }
            (path, None)
        };
        let connector = vf.connector.clone().filter(|c| !c.is_empty());
        let (path, restart) = if connector.is_some() {
            (Self::staging_path(&format!("recv-{}-{tid}", vf.id)), None)
        } else {
            (path, restart)
        };
        let sink = FileSink::create(&path, vf.record_format(), restart.map(position_of))
            .map_err(|e| io_refusal(&e, "cannot create file"))?;
        let mut record = self.new_record(
            session,
            TransferDirection::Receive,
            &partner.id,
            file,
            tid,
            Some(&path),
        );
        record.parent_transfer_id = previous.as_ref().map(|p| p.transfer_id.clone());
        if let Some(cp) = restart {
            record.bytes_transferred = cp.data_bytes;
            record.last_sync_point = cp.sync;
            record.bytes_at_last_sync_point = cp.data_bytes;
        }
        let record_id = record.transfer_id.clone();
        let handle = self.register(record)?;
        if let Some(cid) = &connector {
            let default = path
                .file_name()
                .map_or_else(|| vf.id.clone(), |n| n.to_string_lossy().into_owned());
            let remote = self.connector_key(&vf, session, file, tid, &default);
            let p = path.clone();
            let cid = cid.clone();
            self.set_active(handle, move |a| a.connector_upload = Some((cid, remote, p)));
        }
        self.cancels.register(&record_id);
        tracing::info!(
            "[{}] {} sends '{}' (transfer {tid}) to {}{}",
            session.id,
            partner.id,
            file.file_name,
            path.display(),
            restart
                .map(|c| format!(", restart at sync point {}", c.sync))
                .unwrap_or_default()
        );
        Ok(CreateAccept {
            sink: Box::new(sink),
            checkpoints: Box::new(checkpoints),
            transfer_id: Some(tid),
            restart,
            max_article: vf.record_length as usize,
            handle,
            free_message: None,
        })
    }

    fn select(
        &self,
        session: &SessionInfo,
        file: &FileSpec,
        _attrs: RequestedAttributes,
    ) -> Result<SelectAccept, Refusal> {
        let partner = self.check_partner(session, file, false)?;
        let Some(vf) = self.virtual_file(&file.file_name) else {
            return Err(refusal(
                Diagnostic::FILE_NOT_FOUND,
                format!("virtual file '{}' not configured", file.file_name),
            ));
        };
        if !vf.enabled || !vf.can_send() {
            return Err(refusal(
                Diagnostic::TRANSFER_REFUSED,
                format!("virtual file '{}' cannot be read", vf.id),
            ));
        }
        let tid = self.pesit_transfer_id(file.transfer_id);
        let connector = vf.connector.clone().filter(|c| !c.is_empty());
        let path = if let Some(cid) = &connector {
            let temp = Self::staging_path(&format!("send-{}-{tid}", vf.id));
            let remote = self.connector_key(&vf, session, file, tid, &vf.id);
            self.stage_fetch(cid, &remote, &temp)?;
            temp
        } else {
            vf.send_file.clone().filter(|p| !p.is_empty()).map_or_else(
                || Path::new(&self.server.send_directory).join(&vf.id),
                PathBuf::from,
            )
        };
        let meta =
            std::fs::metadata(&path).map_err(|e| io_refusal(&e, &path.display().to_string()))?;
        let source = FileSource::open(&path, vf.record_format(), vf.record_length as usize)
            .map_err(|e| io_refusal(&e, "cannot open file"))?;
        let key = Self::restart_key(session, file, tid);
        let mut checkpoints = self
            .checkpoints(&key)
            .map_err(|e| io_refusal(&e, "checkpoint store"))?;
        if !file.restarted {
            let _ = checkpoints.clear();
        }
        let mut spec = file.clone();
        spec.transfer_id = tid;
        spec.file_type = if file.file_type != 0 {
            file.file_type
        } else {
            u64::from(vf.file_type)
        };
        spec.article_format = if vf.record_format & 0x80 != 0 {
            ArticleFormat::Variable
        } else {
            ArticleFormat::Fixed
        };
        spec.article_length = vf.record_length.min(0xFFFF) as u16;
        spec.organisation = Some(0);
        spec.max_reservation = meta.len().div_ceil(1024);
        spec.reservation_unit = Some(0);
        spec.creation_date = Some(meta.modified().ok().map_or_else(pesit_now, |t| {
            chrono::DateTime::<chrono::Utc>::from(t)
                .format("%y%m%d%H%M%S")
                .to_string()
        }));
        spec.label = vf
            .description
            .clone()
            .filter(|d| !d.is_empty())
            .map(|d| d.chars().take(80).collect());
        let mut record = self.new_record(
            session,
            TransferDirection::Send,
            &partner.id,
            file,
            tid,
            Some(&path),
        );
        record.file_size = Some(meta.len());
        let record_id = record.transfer_id.clone();
        let handle = self.register(record)?;
        if connector.is_some() {
            let p = path.clone();
            self.set_active(handle, move |a| a.connector_temp = Some(p));
        }
        self.cancels.register(&record_id);
        tracing::info!(
            "[{}] {} reads '{}' (transfer {tid}) from {} ({} bytes)",
            session.id,
            partner.id,
            file.file_name,
            path.display(),
            meta.len()
        );
        Ok(SelectAccept {
            source: Box::new(source),
            checkpoints: Box::new(checkpoints),
            spec,
            handle,
        })
    }

    fn message(
        &self,
        session: &SessionInfo,
        file: &FileSpec,
        message: &[u8],
        expects_reply: bool,
    ) -> Result<Option<Vec<u8>>, Refusal> {
        let text = String::from_utf8_lossy(message).into_owned();
        tracing::info!(
            "[{}] message from {} ('{}'): {}",
            session.id,
            session.requester,
            file.file_name,
            text
        );
        let mut record = self.new_record(
            session,
            TransferDirection::Message,
            &session.requester,
            file,
            file.transfer_id,
            None,
        );
        record.status = TransferStatus::Completed;
        record.bytes_transferred = message.len() as u64;
        record.completed_at = Some(now_iso());
        record.metadata = Some(text);
        let _ = self
            .store
            .put(tables::TRANSFERS, &record.transfer_id, &record);
        Ok(expects_reply.then(|| b"OK".to_vec()))
    }

    fn transfer_event(&self, session: &SessionInfo, handle: u64, event: TransferEvent) {
        let Ok(mut active) = self.active.lock() else {
            return;
        };
        let Some(a) = active.get_mut(&handle) else {
            return;
        };
        let record_id = a.record_id.clone();
        match event {
            TransferEvent::Started { transfer_id, from } => {
                a.last_sync = from.sync;
                a.last_bytes = from.data_bytes;
                self.update_record(&record_id, |r| {
                    r.status = TransferStatus::InProgress;
                    r.pesit_transfer_id = transfer_id;
                    r.bytes_transferred = from.data_bytes;
                    r.last_sync_point = from.sync;
                    r.bytes_at_last_sync_point = from.data_bytes;
                });
            }
            TransferEvent::Progress(p) => {
                let sync_changed = p.sync != a.last_sync;
                if !sync_changed
                    && p.data_bytes.saturating_sub(a.last_bytes) < 1 << 20
                    && a.last_update.elapsed().as_secs() < 1
                {
                    return;
                }
                a.last_update = Instant::now();
                a.last_bytes = p.data_bytes;
                a.last_sync = p.sync;
                let total = a.file_size.or(p.total_hint);
                self.update_record(&record_id, |r| apply_progress(r, p, total, sync_changed));
            }
            TransferEvent::Ended { data, diag } => {
                let removed = active.remove(&handle);
                drop(active);
                self.cancels.remove(&record_id);
                let checksum = self
                    .store
                    .get::<TransferRecord>(tables::TRANSFERS, &record_id)
                    .ok()
                    .flatten()
                    .and_then(|r| {
                        if data.end == DataEnd::Completed
                            && diag.is_ok()
                            && r.direction == Some(TransferDirection::Receive)
                        {
                            r.local_path.and_then(|p| sha256_file(Path::new(&p)))
                        } else {
                            None
                        }
                    });
                self.update_record(&record_id, |r| {
                    r.bytes_transferred = data.data_bytes;
                    r.completed_at = Some(now_iso());
                    r.last_sync_point = data.last_sync;
                    match data.end {
                        DataEnd::Completed if diag.is_ok() => {
                            r.status = TransferStatus::Completed;
                            r.progress_percent = 100;
                            r.file_size = r.file_size.filter(|s| *s > 0).or(Some(data.data_bytes));
                            r.checksum.clone_from(&checksum);
                        }
                        DataEnd::Completed | DataEnd::EndedWithError(_) => {
                            r.status = TransferStatus::Failed;
                            let d = if let DataEnd::EndedWithError(d) = data.end {
                                d
                            } else {
                                diag
                            };
                            r.error_code = Some(format!("{d:?}"));
                            r.error_message = Some(d.to_string());
                        }
                        DataEnd::Interrupted {
                            code,
                            diag: d,
                            by_peer,
                        } => {
                            r.status = if by_peer {
                                TransferStatus::Interrupted
                            } else {
                                TransferStatus::Cancelled
                            };
                            r.error_code = Some(format!("{d:?}"));
                            r.error_message = Some(format!(
                                "{d} (end code {code:?}, by {})",
                                if by_peer { "partner" } else { "operator" }
                            ));
                        }
                    }
                });
                tracing::info!(
                    "[{}] transfer {record_id} ended: {:?} {diag}",
                    session.id,
                    data.end
                );
                if let Some(a) = removed {
                    let completed = data.end == DataEnd::Completed && diag.is_ok();
                    if let Some((cid, remote, temp)) = a.connector_upload {
                        if completed {
                            match self.stage_store(&cid, &remote, &temp) {
                                Ok(()) => {
                                    self.update_record(&record_id, |r| {
                                        r.local_path = Some(format!("{cid}:{remote}"));
                                    });
                                    tracing::info!(
                                        "[{}] uploaded {record_id} to connector '{cid}' ({remote})",
                                        session.id
                                    );
                                }
                                Err(e) => self.update_record(&record_id, |r| {
                                    r.status = TransferStatus::Failed;
                                    r.error_message = Some(format!("connector upload failed: {e}"));
                                }),
                            }
                        }
                        let _ = std::fs::remove_file(&temp);
                    }
                    if let Some(temp) = a.connector_temp {
                        let _ = std::fs::remove_file(&temp);
                    }
                }
            }
            TransferEvent::Failed(msg) => {
                let removed = active.remove(&handle);
                drop(active);
                self.cancels.remove(&record_id);
                self.update_record(&record_id, |r| {
                    r.status = if r.last_sync_point > 0 {
                        TransferStatus::Interrupted
                    } else {
                        TransferStatus::Failed
                    };
                    r.completed_at = Some(now_iso());
                    r.error_message = Some(msg.clone());
                });
                tracing::warn!("[{}] transfer {record_id} failed: {msg}", session.id);
                if let Some(a) = removed {
                    if let Some((_, _, temp)) = a.connector_upload {
                        let _ = std::fs::remove_file(&temp);
                    }
                    if let Some(temp) = a.connector_temp {
                        let _ = std::fs::remove_file(&temp);
                    }
                }
            }
        }
    }

    fn session_closed(&self, session: &SessionInfo, error: Option<&SessionError>) {
        match error {
            None => tracing::info!("[{}] session with {} closed", session.id, session.requester),
            Some(e) => tracing::warn!(
                "[{}] session with {} ended with error: {e}",
                session.id,
                session.requester
            ),
        }
    }

    fn cancel_flag(&self, _session: &SessionInfo, handle: u64) -> Option<watch::Receiver<bool>> {
        let record_id = self.active.lock().ok()?.get(&handle)?.record_id.clone();
        self.cancels
            .flags
            .lock()
            .ok()?
            .get(&record_id)
            .map(watch::Sender::subscribe)
    }
}

fn apply_progress(r: &mut TransferRecord, p: Progress, total: Option<u64>, sync_changed: bool) {
    r.status = TransferStatus::InProgress;
    r.bytes_transferred = p.data_bytes;
    if let Some(t) = total.filter(|t| *t > 0) {
        r.progress_percent = ((p.data_bytes.saturating_mul(100)) / t).min(100) as u8;
        r.file_size = Some(t);
    }
    if sync_changed {
        r.last_sync_point = p.sync;
        r.bytes_at_last_sync_point = p.data_bytes;
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

#[cfg(test)]
mod tests {
    use super::*;
    use pesit_core::params::Version;
    use pesit_io::requester::Negotiated;

    fn setup() -> (Arc<JsonStore>, PwHandler, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let store =
            Arc::new(JsonStore::open(Path::new(":memory:")).unwrap_or_else(|e| panic!("{e}")));
        for t in tables::ALL {
            store.ensure_table(t).unwrap_or_default();
        }
        store
            .put(
                tables::PARTNERS,
                "P1",
                &Partner {
                    id: "P1".into(),
                    password: Some("pw".into()),
                    ..Partner::default()
                },
            )
            .unwrap_or_default();
        store
            .put(
                tables::FILES,
                "IN",
                &VirtualFile {
                    id: "IN".into(),
                    direction: crate::model::Direction::Receive,
                    receive_directory: Some(dir.path().join("in").to_string_lossy().into_owned()),
                    receive_filename_pattern: "${virtualFile}_${transferId}".into(),
                    ..VirtualFile::default()
                },
            )
            .unwrap_or_default();
        std::fs::write(dir.path().join("OUT"), b"hello").unwrap_or_default();
        store
            .put(
                tables::FILES,
                "OUT",
                &VirtualFile {
                    id: "OUT".into(),
                    direction: crate::model::Direction::Send,
                    send_file: Some(dir.path().join("OUT").to_string_lossy().into_owned()),
                    ..VirtualFile::default()
                },
            )
            .unwrap_or_default();
        let server = PesitServerConfig {
            server_id: "S".into(),
            ..PesitServerConfig::default()
        };
        let handler = PwHandler::new(
            Arc::clone(&store),
            server,
            dir.path().join("cp"),
            "node".into(),
            Arc::new(CancelRegistry::default()),
        );
        (store, handler, dir)
    }

    fn connect(requester: &str, password: Option<&str>) -> ConnectRequest {
        ConnectRequest {
            requester: requester.into(),
            server: "S".into(),
            password: password.map(str::to_owned),
            version: Version::E,
            sync: SyncOption {
                interval_kb: 8,
                window: 2,
            },
            access: PesitAccess::Mixed,
            resync: true,
            crc: false,
            free_message: None,
            preconnect: None,
            remote_addr: "test".into(),
        }
    }

    fn session() -> SessionInfo {
        SessionInfo {
            id: "s1".into(),
            requester: "P1".into(),
            server: "S".into(),
            remote_addr: "test".into(),
            negotiated: Negotiated {
                version: Version::E,
                sync: SyncOption {
                    interval_kb: 8,
                    window: 2,
                },
                resync: true,
                crc: false,
            },
        }
    }

    #[test]
    fn authentication() {
        let (_store, h, _dir) = setup();
        assert_eq!(
            h.authenticate(&connect("NOBODY", None))
                .err()
                .map(|r| r.diag),
            Some(Diagnostic::CALLER_UNKNOWN)
        );
        assert_eq!(
            h.authenticate(&connect("P1", Some("bad")))
                .err()
                .map(|r| r.diag),
            Some(Diagnostic::CALLER_NOT_AUTHORISED)
        );
        let ok = h
            .authenticate(&connect("P1", Some("pw")))
            .unwrap_or_else(|r| panic!("{}", r.diag));
        assert_eq!(ok.sync.interval_kb, 32);
    }

    #[test]
    fn create_select_and_records() {
        let (store, h, dir) = setup();
        let s = session();
        let spec = FileSpec {
            file_name: "IN".into(),
            transfer_id: 7,
            ..FileSpec::default()
        };
        let mut accepted = h.create(&s, &spec).unwrap_or_else(|r| panic!("{}", r.diag));
        assert_eq!(accepted.transfer_id, Some(7));
        accepted.sink.write_article(b"abc").unwrap_or_default();
        accepted.sink.finish().unwrap_or_default();
        assert_eq!(
            std::fs::read(dir.path().join("in").join("IN_7")).unwrap_or_default(),
            b"abc"
        );
        h.transfer_event(
            &s,
            accepted.handle,
            TransferEvent::Ended {
                data: pesit_io::datapath::DataResult {
                    end: DataEnd::Completed,
                    data_bytes: 3,
                    articles: 1,
                    last_sync: 0,
                },
                diag: Diagnostic::OK,
            },
        );
        let records: Vec<TransferRecord> = store.list(tables::TRANSFERS).unwrap_or_default();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status, TransferStatus::Completed);
        assert_eq!(records[0].bytes_transferred, 3);
        assert!(records[0].checksum.is_some());
        // second CREATE of the same file without overwrite is refused
        assert_eq!(
            h.create(&s, &spec).err().map(|r| r.diag),
            Some(Diagnostic::FILE_EXISTS)
        );
        // unknown virtual file
        let unknown = FileSpec {
            file_name: "NOPE".into(),
            ..FileSpec::default()
        };
        assert_eq!(
            h.create(&s, &unknown).err().map(|r| r.diag),
            Some(Diagnostic::TRANSFER_REFUSED)
        );
        assert_eq!(
            h.select(&s, &unknown, RequestedAttributes::ALL)
                .err()
                .map(|r| r.diag),
            Some(Diagnostic::FILE_NOT_FOUND)
        );
        // select
        let out = FileSpec {
            file_name: "OUT".into(),
            ..FileSpec::default()
        };
        let sel = h
            .select(&s, &out, RequestedAttributes::ALL)
            .unwrap_or_else(|r| panic!("{}", r.diag));
        assert_eq!(sel.spec.max_reservation, 1);
        assert_eq!(sel.spec.article_length, 1024);
        assert_ne!(sel.spec.transfer_id, 0);
    }
}
