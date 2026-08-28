//! Server side of a PeSIT session.

use std::sync::Arc;
use std::time::Duration;

use pesit_core::builder::{self, FileSpec};
use pesit_core::params::{
    AccessType, Compression, FpduExt, RequestedAttributes, SyncOption, Version,
};
use pesit_core::state::{Event, LocalEvent, Machine, Role, State};
use pesit_core::{ebcdic, Diagnostic, Fpdu, FpduKind, Pi};

use crate::checkpoint::{Checkpoint, CheckpointStore};
use crate::datapath::{self, Control, DataEnd, DataParams, DataResult, Progress};
use crate::error::SessionError;
use crate::io::{ArticleSink, ArticleSource, Position};
use crate::link::Link;
use crate::requester::Negotiated;
use crate::transport::{BoxedStream, Framing};

/// A refusal returned by the handler.
#[derive(Debug, Clone)]
pub struct Refusal {
    /// Diagnostic (PI 2).
    pub diag: Diagnostic,
    /// Optional explanation (PI 99 / PI 92).
    pub message: Option<String>,
}

impl Refusal {
    /// Refusal with a diagnostic only.
    #[must_use]
    pub const fn new(diag: Diagnostic) -> Self {
        Self {
            diag,
            message: None,
        }
    }

    /// Refusal with an explanation.
    #[must_use]
    pub fn with_message(diag: Diagnostic, message: impl Into<String>) -> Self {
        Self {
            diag,
            message: Some(message.into()),
        }
    }
}

/// Content of a F.CONNECT indication.
#[derive(Debug, Clone)]
pub struct ConnectRequest {
    /// Requester identifier (PI 3).
    pub requester: String,
    /// Server identifier (PI 4).
    pub server: String,
    /// Password (PI 5).
    pub password: Option<String>,
    /// Requested version (PI 6).
    pub version: Version,
    /// Proposed synchronisation option (PI 7).
    pub sync: SyncOption,
    /// Access type (PI 22).
    pub access: AccessType,
    /// Resynchronisation proposed (PI 22).
    pub resync: bool,
    /// CRC option (PI 1).
    pub crc: bool,
    /// Free message (PI 99).
    pub free_message: Option<String>,
    /// Pre-connection identification when one was received.
    pub preconnect: Option<(String, String)>,
    /// Remote address.
    pub remote_addr: String,
}

/// Local capabilities accepted for a connection.
#[derive(Debug, Clone)]
pub struct ConnectAccept {
    /// Local synchronisation capability (negotiated with the proposal).
    pub sync: SyncOption,
    /// Accept resynchronisation.
    pub resync: bool,
    /// Compression capability (negotiated at ORF).
    pub compression: Compression,
    /// Multi-article DTFs when sending.
    pub multi_article: bool,
    /// Local maximum entity size (PI 25).
    pub max_entity: u16,
    /// Free message for ACONNECT (PI 99).
    pub free_message: Option<String>,
}

impl Default for ConnectAccept {
    fn default() -> Self {
        Self {
            sync: SyncOption {
                interval_kb: 32,
                window: 4,
            },
            resync: true,
            compression: Compression::None,
            multi_article: true,
            max_entity: 0xFFFF,
            free_message: None,
        }
    }
}

/// Information about the session passed to the handler.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session identifier.
    pub id: String,
    /// Requester identifier.
    pub requester: String,
    /// Server identifier.
    pub server: String,
    /// Remote address.
    pub remote_addr: String,
    /// Negotiated parameters.
    pub negotiated: Negotiated,
}

/// Resources for a file the requester wants to write (F.CREATE).
pub struct CreateAccept {
    /// Where the articles go.
    pub sink: Box<dyn ArticleSink>,
    /// Checkpoints of this transfer.
    pub checkpoints: Box<dyn CheckpointStore>,
    /// Transfer identifier to return (PI 13); `None` keeps the requester's.
    pub transfer_id: Option<u32>,
    /// Restart point offered when the requester restarts an interrupted transfer.
    pub restart: Option<Checkpoint>,
    /// Maximum article length accepted (0 = unbounded).
    pub max_article: usize,
    /// Opaque transfer handle for events.
    pub handle: u64,
    /// Free message for ACK(CREATE) (PI 99).
    pub free_message: Option<String>,
}

/// Resources for a file the requester wants to read (F.SELECT).
pub struct SelectAccept {
    /// Articles to send.
    pub source: Box<dyn ArticleSource>,
    /// Checkpoints of this transfer.
    pub checkpoints: Box<dyn CheckpointStore>,
    /// Attributes of the file (returned in ACK(SELECT)).
    pub spec: FileSpec,
    /// Opaque transfer handle for events.
    pub handle: u64,
}

/// Transfer lifecycle events.
#[derive(Debug, Clone)]
pub enum TransferEvent {
    /// Data phase started from the given checkpoint.
    Started {
        /// Assigned transfer identifier.
        transfer_id: u32,
        /// Checkpoint the transfer starts from.
        from: Checkpoint,
    },
    /// Progress notification.
    Progress(Progress),
    /// Transfer ended (data phase result + closing diagnostic).
    Ended {
        /// Data phase result.
        data: DataResult,
        /// Diagnostic from the requester's TRANS.END / CRF.
        diag: Diagnostic,
    },
    /// Transfer failed with an error.
    Failed(String),
}

/// Callbacks implemented by the server application.
pub trait ServerHandler: Send + Sync {
    /// Authenticate a connection request.
    fn authenticate(&self, req: &ConnectRequest) -> Result<ConnectAccept, Refusal>;
    /// The requester wants to send a file.
    fn create(&self, session: &SessionInfo, file: &FileSpec) -> Result<CreateAccept, Refusal>;
    /// The requester wants to receive a file.
    fn select(
        &self,
        session: &SessionInfo,
        file: &FileSpec,
        attrs: RequestedAttributes,
    ) -> Result<SelectAccept, Refusal>;
    /// A message was received; return the reply when one is expected.
    fn message(
        &self,
        session: &SessionInfo,
        file: &FileSpec,
        message: &[u8],
        expects_reply: bool,
    ) -> Result<Option<Vec<u8>>, Refusal>;
    /// Transfer lifecycle event.
    fn transfer_event(&self, session: &SessionInfo, handle: u64, event: TransferEvent);
    /// The session ended (normally or not).
    fn session_closed(&self, session: &SessionInfo, error: Option<&SessionError>);
    /// Cancellation flag for a transfer (polled by the data phase).
    fn cancel_flag(
        &self,
        _session: &SessionInfo,
        _handle: u64,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        None
    }
}

/// Server-side session configuration.
#[derive(Debug, Clone)]
pub struct ResponderConfig {
    /// Session identifier (for logs and events).
    pub session_id: String,
    /// Connection identifier assigned to this session (octet 6 of our FPDUs).
    pub conn_id: u8,
    /// Watchdog timeout during transfers.
    pub timeout: Duration,
    /// Idle timeout between transfers.
    pub idle_timeout: Duration,
    /// Remote address.
    pub remote_addr: String,
}

/// Serve one PeSIT session on `stream`.
pub async fn serve(
    stream: BoxedStream,
    framing: Framing,
    cfg: ResponderConfig,
    handler: Arc<dyn ServerHandler>,
) -> Result<(), SessionError> {
    let mut session = Responder {
        link: Link::new(stream, framing),
        machine: Machine::new(Role::Server),
        cfg,
        handler,
        peer_id: 0,
        info: None,
        accept: ConnectAccept::default(),
    };
    let result = session.run().await;
    if let Some(info) = &session.info {
        session.handler.session_closed(info, result.as_ref().err());
    }
    if let Err(e) = &result {
        if session.machine.state() != State::Cn01
            && !matches!(e, SessionError::Aborted { .. } | SessionError::Transport(_))
        {
            let _ = session
                .link
                .send(&builder::abort(
                    session.peer_id,
                    session.cfg.conn_id,
                    e.abort_diag(),
                ))
                .await;
        }
    }
    session.link.close().await;
    result
}

struct Responder {
    link: Link,
    machine: Machine,
    cfg: ResponderConfig,
    handler: Arc<dyn ServerHandler>,
    peer_id: u8,
    info: Option<SessionInfo>,
    accept: ConnectAccept,
}

impl Responder {
    fn info(&self) -> Result<&SessionInfo, SessionError> {
        self.info.as_ref().ok_or(SessionError::Protocol {
            state: State::Cn01,
            kind: FpduKind::Connect,
        })
    }

    fn apply_local(&mut self, ev: LocalEvent) -> Result<(), SessionError> {
        self.machine
            .apply(Event::local(ev))
            .map(|_| ())
            .map_err(|e| SessionError::Negotiation(e.to_string()))
    }

    fn apply_received(&mut self, f: &Fpdu) -> Result<bool, SessionError> {
        if f.kind == FpduKind::Abort {
            self.machine
                .apply(Event::received(FpduKind::Abort, false))
                .ok();
            return Err(SessionError::Aborted {
                diag: f.diag_or_ok(),
                message: f.get_text(Pi::FreeMessage),
            });
        }
        self.machine
            .apply(Event::received(f.kind, f.is_negative()))
            .map_err(|_| SessionError::Protocol {
                state: self.machine.state(),
                kind: f.kind,
            })
    }

    /// Wait for a FPDU of kind `expect`, ignoring FPDUs the state tables ignore.
    async fn expect(&mut self, expect: FpduKind, timeout: Duration) -> Result<Fpdu, SessionError> {
        loop {
            let f = self.link.recv(timeout).await?;
            if self.apply_received(&f)? {
                continue;
            }
            if f.kind != expect {
                return Err(SessionError::Protocol {
                    state: self.machine.state(),
                    kind: f.kind,
                });
            }
            return Ok(f);
        }
    }

    async fn run(&mut self) -> Result<(), SessionError> {
        // pre-connection and F.CONNECT
        let mut entity = self.link.recv_entity(self.cfg.idle_timeout).await?;
        let mut preconnect = None;
        if ebcdic::is_preconnect(&entity) {
            preconnect = ebcdic::parse_preconnect(&entity);
            self.link.send_entity(&ebcdic::PRECONNECT_ACK).await?;
            entity = self.link.recv_entity(self.cfg.idle_timeout).await?;
        }
        // CRC detection: the CONNECT entity carries a CRC when PI 1 = 1 (the entity is then 2 bytes longer)
        let fpdu_len = entity
            .get(0..2)
            .map_or(0, |b| usize::from(u16::from_be_bytes([b[0], b[1]])));
        let crc = entity.len() == fpdu_len + pesit_core::crc::CRC_LEN;
        self.link.set_crc(crc);
        let connect = pesit_core::frame::split_entity(&entity, crc)?
            .first()
            .map(|b| Fpdu::decode(b))
            .transpose()?
            .ok_or(SessionError::Transport(
                crate::transport::TransportError::Invalid(entity.len()),
            ))?;
        if connect.kind != FpduKind::Connect {
            return Err(SessionError::Protocol {
                state: self.machine.state(),
                kind: connect.kind,
            });
        }
        self.apply_received(&connect)?;
        self.peer_id = connect.id_src;
        let req = ConnectRequest {
            requester: connect.get_text(Pi::Requester).unwrap_or_default(),
            server: connect.get_text(Pi::Server).unwrap_or_default(),
            password: connect.get_text(Pi::AccessControl),
            version: connect.version().unwrap_or(Version::E),
            sync: connect.sync_option().unwrap_or(SyncOption::NONE),
            access: connect.access_type().unwrap_or(AccessType::Mixed),
            resync: connect.get_num(Pi::Resync).unwrap_or(0) == 1,
            crc: connect.get_num(Pi::Crc).unwrap_or(0) == 1,
            free_message: connect.get_text(Pi::FreeMessage),
            preconnect,
            remote_addr: self.cfg.remote_addr.clone(),
        };
        if req.crc != crc {
            return Err(SessionError::Decode(pesit_core::fpdu::DecodeError {
                diag: Diagnostic::INVALID_PARAMETER,
                detail: "PI 1 does not match the presence of a CRC".into(),
            }));
        }
        let accept = match self.handler.authenticate(&req) {
            Ok(a) => a,
            Err(r) => {
                self.apply_local(LocalEvent::Reject)?;
                self.link
                    .send(&builder::rconnect(
                        self.peer_id,
                        r.diag,
                        r.message.as_deref(),
                    ))
                    .await?;
                return Err(SessionError::Refused {
                    request: FpduKind::Connect,
                    diag: r.diag,
                    message: r.message,
                });
            }
        };
        let version = if req.version == Version::D {
            Version::D
        } else {
            Version::E
        };
        let sync = SyncOption::negotiate(req.sync, accept.sync);
        let resync = req.resync && accept.resync;
        let negotiated = Negotiated {
            version,
            sync,
            resync,
            crc,
        };
        self.info = Some(SessionInfo {
            id: self.cfg.session_id.clone(),
            requester: req.requester.clone(),
            server: req.server.clone(),
            remote_addr: req.remote_addr.clone(),
            negotiated,
        });
        self.accept = accept;
        self.apply_local(LocalEvent::Accept)?;
        self.link
            .send(&builder::aconnect(
                self.peer_id,
                self.cfg.conn_id,
                version,
                sync,
                resync,
                self.accept.free_message.as_deref(),
            ))
            .await?;
        tracing::debug!(
            ?negotiated,
            "session {} established with {}",
            self.cfg.session_id,
            req.requester
        );

        // file selection phase
        loop {
            let f = self.link.recv(self.cfg.idle_timeout).await?;
            match f.kind {
                FpduKind::Create => {
                    self.apply_received(&f)?;
                    if !req.access.allows_write() {
                        self.refuse_create(
                            Refusal::new(Diagnostic::SELECT_NEGOTIATION),
                            f.transfer_id().unwrap_or(0),
                        )
                        .await?;
                        continue;
                    }
                    self.handle_create(&f).await?;
                }
                FpduKind::Select => {
                    self.apply_received(&f)?;
                    if !req.access.allows_read() {
                        self.apply_local(LocalEvent::Reject)?;
                        self.link
                            .send(&builder::nack_select(
                                self.peer_id,
                                Diagnostic::SELECT_NEGOTIATION,
                                None,
                            ))
                            .await?;
                        continue;
                    }
                    self.handle_select(&f).await?;
                }
                FpduKind::Msg | FpduKind::MsgDm => {
                    self.apply_received(&f)?;
                    self.handle_message(f).await?;
                }
                FpduKind::Release => {
                    self.apply_received(&f)?;
                    self.apply_local(LocalEvent::Accept)?;
                    self.link
                        .send(&builder::relconf(self.peer_id, self.cfg.conn_id))
                        .await?;
                    return Ok(());
                }
                _ => {
                    if !self.apply_received(&f)? {
                        return Err(SessionError::Protocol {
                            state: self.machine.state(),
                            kind: f.kind,
                        });
                    }
                }
            }
        }
    }

    async fn refuse_create(&mut self, r: Refusal, transfer_id: u32) -> Result<(), SessionError> {
        self.apply_local(LocalEvent::Reject)?;
        self.link
            .send(&builder::ack_create(
                self.peer_id,
                r.diag,
                Some(transfer_id),
                0,
                r.message.as_deref(),
            ))
            .await
    }

    async fn handle_create(&mut self, f: &Fpdu) -> Result<(), SessionError> {
        let spec = FileSpec::from_fpdu(f);
        let info = self.info()?.clone();
        let accept = match self.handler.create(&info, &spec) {
            Ok(a) => a,
            Err(r) => return self.refuse_create(r, spec.transfer_id).await,
        };
        let CreateAccept {
            mut sink,
            mut checkpoints,
            transfer_id,
            restart,
            max_article,
            handle,
            free_message,
        } = accept;
        let transfer_id = transfer_id.unwrap_or(spec.transfer_id);
        let max_entity = usize::from(
            spec.max_entity_size
                .max(pesit_core::fpdu::HEADER_LEN as u16 + 1),
        )
        .min(usize::from(self.accept.max_entity));
        self.apply_local(LocalEvent::Accept)?;
        self.link
            .send(&builder::ack_create(
                self.peer_id,
                Diagnostic::OK,
                Some(transfer_id),
                max_entity as u16,
                free_message.as_deref(),
            ))
            .await?;
        let result = self
            .run_write(
                &info,
                &spec,
                sink.as_mut(),
                checkpoints.as_mut(),
                restart,
                max_article,
                max_entity,
                transfer_id,
                handle,
            )
            .await;
        match &result {
            Ok((data, diag)) => {
                if data.end == DataEnd::Completed && diag.is_ok() {
                    sink.finish()?;
                    checkpoints.clear()?;
                }
                self.handler.transfer_event(
                    &info,
                    handle,
                    TransferEvent::Ended {
                        data: *data,
                        diag: *diag,
                    },
                );
            }
            Err(e) => {
                self.handler
                    .transfer_event(&info, handle, TransferEvent::Failed(e.to_string()));
            }
        }
        result.map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_write(
        &mut self,
        info: &SessionInfo,
        spec: &FileSpec,
        sink: &mut dyn ArticleSink,
        checkpoints: &mut dyn CheckpointStore,
        restart: Option<Checkpoint>,
        max_article: usize,
        max_entity: usize,
        transfer_id: u32,
        handle: u64,
    ) -> Result<(DataResult, Diagnostic), SessionError> {
        let orf = self.expect(FpduKind::Orf, self.cfg.timeout).await?;
        let compression = Compression::negotiate(
            orf.compression().unwrap_or(Compression::None),
            self.accept.compression,
        );
        self.apply_local(LocalEvent::Accept)?;
        self.link
            .send(&builder::ack_orf(self.peer_id, Diagnostic::OK, compression))
            .await?;
        let _write = self.expect(FpduKind::Write, self.cfg.timeout).await?;
        let start = if spec.restarted {
            restart.unwrap_or_default()
        } else {
            Checkpoint::default()
        };
        self.apply_local(LocalEvent::Accept)?;
        self.link
            .send(&builder::ack_write(
                self.peer_id,
                Diagnostic::OK,
                start.sync,
            ))
            .await?;
        sink.truncate(Position {
            file_offset: start.file_offset,
            data_bytes: start.data_bytes,
            articles: start.articles,
        })?;
        if start.sync == 0 {
            checkpoints.clear()?;
        }
        self.handler.transfer_event(
            info,
            handle,
            TransferEvent::Started {
                transfer_id,
                from: start,
            },
        );
        let params = DataParams {
            peer_id: self.peer_id,
            sync: info.negotiated.sync,
            resync: info.negotiated.resync,
            compression,
            crc: info.negotiated.crc,
            max_entity,
            multi_article: self.accept.multi_article,
            max_article: if max_article == 0 {
                usize::from(spec.article_length)
            } else {
                max_article
            },
            timeout: self.cfg.timeout,
            role: Role::Server,
        };
        let handler = Arc::clone(&self.handler);
        let info2 = info.clone();
        let mut progress =
            move |p: Progress| handler.transfer_event(&info2, handle, TransferEvent::Progress(p));
        let mut ctrl = Control {
            cancel: self.handler.cancel_flag(info, handle),
            progress: &mut progress,
        };
        let data = datapath::receive_data(
            &mut self.link,
            &mut self.machine,
            &params,
            sink,
            checkpoints,
            start,
            &mut ctrl,
        )
        .await?;
        let diag = self.close_transfer(&data).await?;
        Ok((data, diag))
    }

    async fn handle_select(&mut self, f: &Fpdu) -> Result<(), SessionError> {
        let spec = FileSpec::from_fpdu(f);
        let attrs = f
            .get_num(Pi::RequestedAttributes)
            .map_or(RequestedAttributes::ALL, |n| {
                RequestedAttributes::from_code(n as u8)
            });
        let info = self.info()?.clone();
        let accept = match self.handler.select(&info, &spec, attrs) {
            Ok(a) => a,
            Err(r) => {
                self.apply_local(LocalEvent::Reject)?;
                return self
                    .link
                    .send(&builder::nack_select(
                        self.peer_id,
                        r.diag,
                        r.message.as_deref(),
                    ))
                    .await;
            }
        };
        let SelectAccept {
            mut source,
            mut checkpoints,
            spec: mut answer,
            handle,
        } = accept;
        let max_entity = usize::from(
            spec.max_entity_size
                .max(pesit_core::fpdu::HEADER_LEN as u16 + 1),
        )
        .min(usize::from(self.accept.max_entity));
        answer.max_entity_size = max_entity as u16;
        if answer.transfer_id == 0 {
            answer.transfer_id = spec.transfer_id;
        }
        let transfer_id = answer.transfer_id;
        self.apply_local(LocalEvent::Accept)?;
        self.link
            .send(&answer.ack_select(self.peer_id, attrs))
            .await?;
        let result = self
            .run_read(
                &info,
                &answer,
                source.as_mut(),
                checkpoints.as_mut(),
                max_entity,
                transfer_id,
                handle,
            )
            .await;
        match &result {
            Ok((data, diag)) => {
                if data.end == DataEnd::Completed && diag.is_ok() {
                    checkpoints.clear()?;
                }
                self.handler.transfer_event(
                    &info,
                    handle,
                    TransferEvent::Ended {
                        data: *data,
                        diag: *diag,
                    },
                );
            }
            Err(e) => {
                self.handler
                    .transfer_event(&info, handle, TransferEvent::Failed(e.to_string()));
            }
        }
        result.map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_read(
        &mut self,
        info: &SessionInfo,
        spec: &FileSpec,
        source: &mut dyn ArticleSource,
        checkpoints: &mut dyn CheckpointStore,
        max_entity: usize,
        transfer_id: u32,
        handle: u64,
    ) -> Result<(DataResult, Diagnostic), SessionError> {
        let orf = self.expect(FpduKind::Orf, self.cfg.timeout).await?;
        let compression = Compression::negotiate(
            orf.compression().unwrap_or(Compression::None),
            self.accept.compression,
        );
        self.apply_local(LocalEvent::Accept)?;
        self.link
            .send(&builder::ack_orf(self.peer_id, Diagnostic::OK, compression))
            .await?;
        let read = self.expect(FpduKind::Read, self.cfg.timeout).await?;
        let point = read.restart_point().unwrap_or(0);
        let start = if point == 0 {
            Checkpoint::default()
        } else if let Some(cp) = checkpoints.get(point) {
            cp
        } else {
            self.apply_local(LocalEvent::Reject)?;
            self.link
                .send(&builder::ack_read(
                    self.peer_id,
                    Diagnostic::RESTART_UNKNOWN_SYNC,
                ))
                .await?;
            return Err(SessionError::Negotiation(format!(
                "requester asked to restart at unknown sync point {point}"
            )));
        };
        self.apply_local(LocalEvent::Accept)?;
        self.link
            .send(&builder::ack_read(self.peer_id, Diagnostic::OK))
            .await?;
        if start.sync == 0 {
            checkpoints.clear()?;
        }
        self.handler.transfer_event(
            info,
            handle,
            TransferEvent::Started {
                transfer_id,
                from: start,
            },
        );
        let params = DataParams {
            peer_id: self.peer_id,
            sync: info.negotiated.sync,
            resync: info.negotiated.resync,
            compression,
            crc: info.negotiated.crc,
            max_entity,
            multi_article: self.accept.multi_article,
            max_article: usize::from(spec.article_length),
            timeout: self.cfg.timeout,
            role: Role::Server,
        };
        let handler = Arc::clone(&self.handler);
        let info2 = info.clone();
        let mut progress =
            move |p: Progress| handler.transfer_event(&info2, handle, TransferEvent::Progress(p));
        let mut ctrl = Control {
            cancel: self.handler.cancel_flag(info, handle),
            progress: &mut progress,
        };
        let data = datapath::send_data(
            &mut self.link,
            &mut self.machine,
            &params,
            source,
            checkpoints,
            start,
            &mut ctrl,
        )
        .await?;
        let diag = self.close_transfer(&data).await?;
        Ok((data, diag))
    }

    /// Server side of the end of a transfer: TRANS.END (unless interrupted), CRF, DESELECT.
    async fn close_transfer(&mut self, data: &DataResult) -> Result<Diagnostic, SessionError> {
        let mut diag = Diagnostic::OK;
        loop {
            let f = self.link.recv(self.cfg.timeout).await?;
            if self.apply_received(&f)? {
                continue;
            }
            match f.kind {
                FpduKind::TransEnd => {
                    let d = f.diag_or_ok();
                    if !d.is_ok() {
                        diag = d;
                    }
                    let ack = match datapath::check_counts(&f, data.data_bytes, data.articles) {
                        Ok(()) => builder::ack_trans_end(
                            self.peer_id,
                            Diagnostic::OK,
                            Some(data.data_bytes),
                            Some(data.articles),
                        ),
                        Err(e) => {
                            tracing::warn!("{e}");
                            diag = Diagnostic::INVALID_COUNTS;
                            builder::ack_trans_end(
                                self.peer_id,
                                diag,
                                Some(data.data_bytes),
                                Some(data.articles),
                            )
                        }
                    };
                    self.apply_local(LocalEvent::Accept)?;
                    self.link.send(&ack).await?;
                }
                FpduKind::Crf => {
                    let d = f.diag_or_ok();
                    if !d.is_ok() {
                        diag = d;
                    }
                    self.apply_local(LocalEvent::Accept)?;
                    self.link
                        .send(&builder::ack_crf(self.peer_id, Diagnostic::OK))
                        .await?;
                }
                FpduKind::Deselect => {
                    self.apply_local(LocalEvent::Accept)?;
                    self.link
                        .send(&builder::ack_deselect(self.peer_id, Diagnostic::OK))
                        .await?;
                    return Ok(diag);
                }
                _ => {
                    return Err(SessionError::Protocol {
                        state: self.machine.state(),
                        kind: f.kind,
                    })
                }
            }
        }
    }

    async fn handle_message(&mut self, first: Fpdu) -> Result<(), SessionError> {
        let spec = FileSpec::from_fpdu(&first);
        let expects_reply = first
            .get_num(Pi::RequestedAttributes)
            .is_some_and(|a| a & 1 == 1);
        let mut message = first
            .get(Pi::Message)
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        if first.kind == FpduKind::MsgDm {
            loop {
                let seg = self.link.recv(self.cfg.timeout).await?;
                if self.apply_received(&seg)? {
                    continue;
                }
                match seg.kind {
                    FpduKind::MsgMm | FpduKind::MsgFm => {
                        message.extend_from_slice(seg.get(Pi::Message).unwrap_or(&[]));
                        if seg.kind == FpduKind::MsgFm {
                            break;
                        }
                    }
                    k => {
                        return Err(SessionError::Protocol {
                            state: self.machine.state(),
                            kind: k,
                        })
                    }
                }
            }
        }
        let info = self.info()?.clone();
        let ack = match self.handler.message(&info, &spec, &message, expects_reply) {
            Ok(reply) => builder::ack_msg(
                self.peer_id,
                Diagnostic::OK,
                Some(spec.transfer_id),
                reply.as_deref(),
            ),
            Err(r) => builder::ack_msg(
                self.peer_id,
                r.diag,
                Some(spec.transfer_id),
                r.message.as_deref().map(str::as_bytes),
            ),
        };
        self.apply_local(LocalEvent::Accept)?;
        self.link.send(&ack).await
    }
}
