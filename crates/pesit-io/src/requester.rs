//! Requester (client) side of a PeSIT session: connection, file transfers, messages.

use std::time::Duration;

use pesit_core::builder::{self, ConnectParams, FileSpec};
use pesit_core::params::{
    AccessType, Compression, EndCode, FpduExt, RequestedAttributes, SyncOption, Version,
};
use pesit_core::state::{Event, LocalEvent, Machine, Role};
use pesit_core::{ebcdic, Diagnostic, Fpdu, FpduKind, Pi};

use crate::checkpoint::{Checkpoint, CheckpointStore};
use crate::datapath::{self, Control, DataEnd, DataParams, DataResult};
use crate::error::SessionError;
use crate::io::{ArticleSink, ArticleSource};
use crate::link::Link;
use crate::transport::{BoxedStream, Framing};

/// Pre-connection identification (partner types T/O of Connect:Express).
#[derive(Debug, Clone)]
pub struct Preconnect {
    /// Identifier (≤ 8 characters).
    pub identifier: String,
    /// Password (≤ 8 characters).
    pub password: String,
}

/// Session parameters of a requester.
#[derive(Debug, Clone)]
pub struct RequesterConfig {
    /// Our identifier (PI 3).
    pub requester_id: String,
    /// Identifier of the server (PI 4).
    pub server_id: String,
    /// Connection password (PI 5).
    pub password: Option<String>,
    /// Protocol version to propose (PI 6).
    pub version: Version,
    /// Proposed synchronisation option (PI 7).
    pub sync: SyncOption,
    /// Propose resynchronisation (PI 22).
    pub resync: bool,
    /// Use the CRC option (PI 1).
    pub crc: bool,
    /// Desired compression (PI 21, negotiated at ORF).
    pub compression: Compression,
    /// Maximum entity size to propose (PI 25).
    pub max_entity: u16,
    /// Pack several articles per DTF (PI 25 permitting).
    pub multi_article: bool,
    /// Optional pre-connection message.
    pub preconnect: Option<Preconnect>,
    /// Watchdog timeout.
    pub timeout: Duration,
    /// Free message sent in CONNECT (PI 99).
    pub free_message: Option<String>,
    /// Access type requested for the session (PI 22).
    pub access: AccessType,
}

impl Default for RequesterConfig {
    fn default() -> Self {
        Self {
            requester_id: String::new(),
            server_id: String::new(),
            password: None,
            version: Version::E,
            sync: SyncOption {
                interval_kb: 32,
                window: 4,
            },
            resync: true,
            crc: false,
            compression: Compression::None,
            max_entity: 0xFFFF,
            multi_article: true,
            preconnect: None,
            timeout: Duration::from_secs(60),
            free_message: None,
            access: AccessType::Mixed,
        }
    }
}

/// Parameters negotiated at connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    /// Protocol version.
    pub version: Version,
    /// Synchronisation option.
    pub sync: SyncOption,
    /// Resynchronisation allowed.
    pub resync: bool,
    /// CRC option active.
    pub crc: bool,
}

/// Description of a file to send or receive.
#[derive(Debug, Clone, Default)]
pub struct TransferSpec {
    /// File attributes for CREATE/SELECT.
    pub file: FileSpec,
    /// Restart an interrupted transfer from this checkpoint (the peer decides the actual point).
    pub restart: Option<Checkpoint>,
}

/// Outcome of a file transfer.
#[derive(Debug, Clone)]
pub struct TransferOutcome {
    /// Transfer identifier (PI 13) as assigned by the server.
    pub transfer_id: u32,
    /// Data phase result.
    pub data: DataResult,
    /// Attributes returned by the server (ACK(SELECT) / ACK(CREATE)).
    pub remote: FileSpec,
    /// Checkpoint the transfer actually started from.
    pub started_from: Checkpoint,
    /// Diagnostic of the closing phase (CRF/ACK(TRANS.END)).
    pub diag: Diagnostic,
}

impl TransferOutcome {
    /// Whether the file was completely transferred.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.data.end == DataEnd::Completed && self.diag.is_ok()
    }
}

/// Outcome of a message.
#[derive(Debug, Clone)]
pub struct MessageOutcome {
    /// Diagnostic of the ACK(MSG).
    pub diag: Diagnostic,
    /// Reply message (PI 91) when the server sent one.
    pub reply: Option<Vec<u8>>,
}

/// An established requester session.
pub struct Requester {
    link: Link,
    machine: Machine,
    cfg: RequesterConfig,
    my_id: u8,
    peer_id: u8,
    negotiated: Negotiated,
    max_entity: usize,
}

impl Requester {
    /// Establish a session over a connected stream (pre-connection + F.CONNECT).
    pub async fn connect(
        stream: BoxedStream,
        framing: Framing,
        cfg: RequesterConfig,
    ) -> Result<Self, SessionError> {
        let mut link = Link::new(stream, framing);
        let mut machine = Machine::new(Role::Requester);
        if let Some(pc) = &cfg.preconnect {
            let msg = ebcdic::preconnect_message(&pc.identifier, &pc.password);
            link.send_entity(&msg).await?;
            let reply = link.recv_entity(cfg.timeout).await?;
            if reply.len() < ebcdic::PRECONNECT_ACK.len() || reply[..4] != ebcdic::PRECONNECT_ACK {
                return Err(SessionError::PreconnectRefused);
            }
        }
        link.set_crc(cfg.crc);
        let my_id = 1u8;
        let connect = ConnectParams {
            requester: cfg.requester_id.clone(),
            server: cfg.server_id.clone(),
            password: cfg.password.clone(),
            version: cfg.version,
            sync: cfg.sync,
            access: cfg.access,
            resync: cfg.resync,
            crc: cfg.crc,
            timeout: None,
            free_message: cfg.free_message.clone(),
        }
        .build(my_id);
        machine
            .apply(Event::local(LocalEvent::Connect))
            .map_err(|e| SessionError::Negotiation(e.to_string()))?;
        link.send(&connect).await?;
        let reply = link.recv(cfg.timeout).await?;
        match reply.kind {
            FpduKind::Aconnect => {
                machine
                    .apply(Event::received(FpduKind::Aconnect, false))
                    .map_err(|_| SessionError::Protocol {
                        state: machine.state(),
                        kind: reply.kind,
                    })?;
            }
            FpduKind::Rconnect => {
                machine
                    .apply(Event::received(FpduKind::Rconnect, false))
                    .ok();
                return Err(SessionError::Refused {
                    request: FpduKind::Connect,
                    diag: reply.diag_or_ok(),
                    message: reply.get_text(Pi::FreeMessage),
                });
            }
            FpduKind::Abort => {
                return Err(SessionError::Aborted {
                    diag: reply.diag_or_ok(),
                    message: reply.get_text(Pi::FreeMessage),
                });
            }
            k => {
                return Err(SessionError::Protocol {
                    state: machine.state(),
                    kind: k,
                })
            }
        }
        let peer_id = reply.id_src;
        let version = reply.version().unwrap_or(cfg.version);
        let sync = SyncOption::negotiate(cfg.sync, reply.sync_option().unwrap_or(SyncOption::NONE));
        let resync = cfg.resync && reply.get_num(Pi::Resync).unwrap_or(0) == 1;
        let negotiated = Negotiated {
            version,
            sync,
            resync,
            crc: cfg.crc,
        };
        tracing::debug!(?negotiated, "connected to {}", cfg.server_id);
        let max_entity = usize::from(cfg.max_entity);
        Ok(Self {
            link,
            machine,
            cfg,
            my_id,
            peer_id,
            negotiated,
            max_entity,
        })
    }

    /// Negotiated session parameters.
    #[must_use]
    pub const fn negotiated(&self) -> Negotiated {
        self.negotiated
    }

    /// Our connection identifier.
    #[must_use]
    pub const fn id(&self) -> u8 {
        self.my_id
    }

    /// Send `fpdu` after applying `event`, then wait for `expect` (or its negative form / ABORT).
    async fn request(
        &mut self,
        fpdu: &Fpdu,
        event: LocalEvent,
        expect: FpduKind,
    ) -> Result<Fpdu, SessionError> {
        self.machine
            .apply(Event::local(event))
            .map_err(|e| SessionError::Negotiation(e.to_string()))?;
        self.link.send(fpdu).await?;
        loop {
            let reply = self.link.recv(self.cfg.timeout).await?;
            if reply.kind == FpduKind::Abort {
                self.machine
                    .apply(Event::received(FpduKind::Abort, false))
                    .ok();
                return Err(SessionError::Aborted {
                    diag: reply.diag_or_ok(),
                    message: reply.get_text(Pi::FreeMessage),
                });
            }
            let negative = reply.is_negative();
            let ignored = self
                .machine
                .apply(Event::received(reply.kind, negative))
                .map_err(|_| SessionError::Protocol {
                    state: self.machine.state(),
                    kind: reply.kind,
                })?;
            if ignored {
                continue;
            }
            if reply.kind != expect {
                return Err(SessionError::Protocol {
                    state: self.machine.state(),
                    kind: reply.kind,
                });
            }
            if negative {
                return Err(SessionError::Refused {
                    request: fpdu.kind,
                    diag: reply.diag_or_ok(),
                    message: reply
                        .get_text(Pi::FreeMessage)
                        .or_else(|| reply.get_text(Pi::DiagComplement)),
                });
            }
            return Ok(reply);
        }
    }

    fn data_params(
        &self,
        compression: Compression,
        max_entity: usize,
        max_article: usize,
    ) -> DataParams {
        DataParams {
            peer_id: self.peer_id,
            sync: self.negotiated.sync,
            resync: self.negotiated.resync,
            compression,
            crc: self.negotiated.crc,
            max_entity,
            multi_article: self.cfg.multi_article,
            max_article,
            timeout: self.cfg.timeout,
            role: Role::Requester,
        }
    }

    /// Send a file (F.CREATE / F.WRITE).
    pub async fn send_file(
        &mut self,
        spec: &TransferSpec,
        source: &mut dyn ArticleSource,
        checkpoints: &mut dyn CheckpointStore,
        ctrl: &mut Control<'_>,
    ) -> Result<TransferOutcome, SessionError> {
        let mut file = spec.file.clone();
        file.restarted = spec.restart.is_some();
        if file.max_entity_size == 0 {
            file.max_entity_size = self.cfg.max_entity;
        }
        let ack = self
            .request(
                &file.create(self.peer_id),
                LocalEvent::Create,
                FpduKind::AckCreate,
            )
            .await?;
        let transfer_id = ack.transfer_id().unwrap_or(file.transfer_id);
        let max_entity = ack
            .max_entity_size()
            .map_or(usize::from(file.max_entity_size), |m| {
                usize::from(m).min(usize::from(file.max_entity_size))
            });
        self.max_entity = max_entity;
        let remote = FileSpec::from_fpdu(&ack);

        let ack = self
            .request(
                &builder::orf(self.peer_id, self.cfg.compression),
                LocalEvent::Open,
                FpduKind::AckOrf,
            )
            .await?;
        let compression = Compression::negotiate(
            self.cfg.compression,
            ack.compression().unwrap_or(Compression::None),
        );

        let ack = self
            .request(
                &builder::write(self.peer_id),
                LocalEvent::Write,
                FpduKind::AckWrite,
            )
            .await?;
        let point = ack.restart_point().unwrap_or(0);
        let start = if file.restarted && point != 0 {
            checkpoints.get(point).ok_or_else(|| {
                SessionError::Negotiation(format!(
                    "server requested restart at unknown sync point {point}"
                ))
            })?
        } else {
            Checkpoint::default()
        };
        if start.sync == 0 {
            checkpoints.clear()?;
        }
        let params = self.data_params(compression, max_entity, usize::from(file.article_length));
        let data = datapath::send_data(
            &mut self.link,
            &mut self.machine,
            &params,
            source,
            checkpoints,
            start,
            ctrl,
        )
        .await?;
        let diag = self.close_transfer(&data).await?;
        if data.end == DataEnd::Completed && diag.is_ok() {
            checkpoints.clear()?;
        }
        Ok(TransferOutcome {
            transfer_id,
            data,
            remote,
            started_from: start,
            diag,
        })
    }

    /// Receive a file (F.SELECT / F.READ). `open_sink` is called with the attributes returned by
    /// the server and the checkpoint to restart from, and must return a positioned sink.
    pub async fn receive_file(
        &mut self,
        spec: &TransferSpec,
        sink: &mut dyn ArticleSink,
        checkpoints: &mut dyn CheckpointStore,
        ctrl: &mut Control<'_>,
    ) -> Result<TransferOutcome, SessionError> {
        let mut file = spec.file.clone();
        file.restarted = spec.restart.is_some();
        if file.max_entity_size == 0 {
            file.max_entity_size = self.cfg.max_entity;
        }
        let ack = self
            .request(
                &file.select(self.peer_id, RequestedAttributes::ALL),
                LocalEvent::Select,
                FpduKind::AckSelect,
            )
            .await?;
        let transfer_id = ack.transfer_id().unwrap_or(file.transfer_id);
        let max_entity = ack
            .max_entity_size()
            .map_or(usize::from(file.max_entity_size), |m| {
                usize::from(m).min(usize::from(file.max_entity_size))
            });
        self.max_entity = max_entity;
        let remote = FileSpec::from_fpdu(&ack);

        let ack = self
            .request(
                &builder::orf(self.peer_id, self.cfg.compression),
                LocalEvent::Open,
                FpduKind::AckOrf,
            )
            .await?;
        let compression = Compression::negotiate(
            self.cfg.compression,
            ack.compression().unwrap_or(Compression::None),
        );

        let requested = spec.restart.map_or(0, |c| c.sync);
        let start = if requested == 0 {
            Checkpoint::default()
        } else {
            checkpoints.get(requested).ok_or_else(|| {
                SessionError::Negotiation(format!("unknown local sync point {requested}"))
            })?
        };
        let ack = self
            .request(
                &builder::read(self.peer_id, start.sync),
                LocalEvent::Read,
                FpduKind::AckRead,
            )
            .await?;
        // the server may not honour the restart point: ACK(READ) carries no PI 18, the data
        // phase restarts where we asked (§4.4.15) — otherwise it refuses with a diagnostic.
        drop(ack);
        if start.sync == 0 {
            checkpoints.clear()?;
            sink.truncate(crate::io::Position::default())?;
        } else {
            sink.truncate(crate::io::Position {
                file_offset: start.file_offset,
                data_bytes: start.data_bytes,
                articles: start.articles,
            })?;
        }
        let params = self.data_params(
            compression,
            max_entity,
            usize::from(remote.article_length.max(file.article_length)),
        );
        let data = datapath::receive_data(
            &mut self.link,
            &mut self.machine,
            &params,
            sink,
            checkpoints,
            start,
            ctrl,
        )
        .await?;
        let diag = self.close_transfer(&data).await?;
        if data.end == DataEnd::Completed && diag.is_ok() {
            sink.finish()?;
            checkpoints.clear()?;
        }
        Ok(TransferOutcome {
            transfer_id,
            data,
            remote,
            started_from: start,
            diag,
        })
    }

    /// TRANS.END (when the data phase completed), CRF and DESELECT.
    async fn close_transfer(&mut self, data: &DataResult) -> Result<Diagnostic, SessionError> {
        let mut diag = Diagnostic::OK;
        match data.end {
            DataEnd::Completed | DataEnd::EndedWithError(_) => {
                let te =
                    builder::trans_end(self.peer_id, Some(data.data_bytes), Some(data.articles));
                match self
                    .request(&te, LocalEvent::TransferEnd, FpduKind::AckTransEnd)
                    .await
                {
                    Ok(ack) => {
                        datapath::check_counts(&ack, data.data_bytes, data.articles)?;
                    }
                    Err(SessionError::Refused { diag: d, .. }) => diag = d,
                    Err(e) => return Err(e),
                }
            }
            DataEnd::Interrupted { .. } => {}
        }
        match self
            .request(
                &builder::crf(self.peer_id, Diagnostic::OK),
                LocalEvent::Close,
                FpduKind::AckCrf,
            )
            .await
        {
            Ok(_) => {}
            Err(SessionError::Refused { diag: d, .. }) => diag = d,
            Err(e) => return Err(e),
        }
        match self
            .request(
                &builder::deselect(self.peer_id, Diagnostic::OK),
                LocalEvent::Deselect,
                FpduKind::AckDeselect,
            )
            .await
        {
            Ok(_) => {}
            Err(SessionError::Refused { diag: d, .. }) => diag = d,
            Err(e) => return Err(e),
        }
        Ok(diag)
    }

    /// Send a message (F.MESSAGE), segmented when it does not fit in one entity.
    pub async fn send_message(
        &mut self,
        file: &FileSpec,
        message: &[u8],
        expects_reply: bool,
    ) -> Result<MessageOutcome, SessionError> {
        let first = builder::msg(FpduKind::Msg, self.peer_id, file, expects_reply, None);
        let overhead = first.encoded_len() + 3 + if self.negotiated.crc { 2 } else { 0 };
        let room = self.max_entity.saturating_sub(overhead).max(1);
        let ack = if message.len() <= room {
            self.request(
                &builder::msg(
                    FpduKind::Msg,
                    self.peer_id,
                    file,
                    expects_reply,
                    Some(message),
                ),
                LocalEvent::Message,
                FpduKind::AckMsg,
            )
            .await?
        } else {
            let (head, rest) = message.split_at(room);
            self.machine
                .apply(Event::local(LocalEvent::Message))
                .map_err(|e| SessionError::Negotiation(e.to_string()))?;
            self.link
                .send(&builder::msg(
                    FpduKind::MsgDm,
                    self.peer_id,
                    file,
                    expects_reply,
                    Some(head),
                ))
                .await?;
            let seg_room = self
                .max_entity
                .saturating_sub(
                    pesit_core::fpdu::HEADER_LEN + 3 + 3 + if self.negotiated.crc { 2 } else { 0 },
                )
                .max(1);
            let chunks: Vec<&[u8]> = rest.chunks(seg_room).collect();
            let n = chunks.len();
            for (i, chunk) in chunks.iter().enumerate() {
                let kind = if i + 1 == n {
                    FpduKind::MsgFm
                } else {
                    FpduKind::MsgMm
                };
                self.link
                    .send(&builder::msg_segment(kind, self.peer_id, chunk))
                    .await?;
            }
            self.machine
                .apply(Event::local(LocalEvent::DataEnd))
                .map_err(|e| SessionError::Negotiation(e.to_string()))?;
            self.link.recv(self.cfg.timeout).await.and_then(|reply| {
                if reply.kind == FpduKind::Abort {
                    self.machine
                        .apply(Event::received(FpduKind::Abort, false))
                        .ok();
                    return Err(SessionError::Aborted {
                        diag: reply.diag_or_ok(),
                        message: reply.get_text(Pi::FreeMessage),
                    });
                }
                let negative = reply.is_negative();
                self.machine
                    .apply(Event::received(reply.kind, negative))
                    .map_err(|_| SessionError::Protocol {
                        state: self.machine.state(),
                        kind: reply.kind,
                    })?;
                if reply.kind != FpduKind::AckMsg {
                    return Err(SessionError::Protocol {
                        state: self.machine.state(),
                        kind: reply.kind,
                    });
                }
                if negative {
                    return Err(SessionError::Refused {
                        request: FpduKind::Msg,
                        diag: reply.diag_or_ok(),
                        message: reply.get_text(Pi::FreeMessage),
                    });
                }
                Ok(reply)
            })?
        };
        Ok(MessageOutcome {
            diag: ack.diag_or_ok(),
            reply: ack.get(Pi::Message).map(<[u8]>::to_vec),
        })
    }

    /// Release the session (F.RELEASE) and close the link.
    pub async fn release(mut self) -> Result<(), SessionError> {
        let r = self
            .request(
                &builder::release(self.peer_id, self.my_id, Diagnostic::OK),
                LocalEvent::Release,
                FpduKind::Relconf,
            )
            .await;
        self.link.close().await;
        r.map(|_| ())
    }

    /// Abort the session (F.ABORT) and close the link.
    pub async fn abort(mut self, diag: Diagnostic) {
        self.machine.apply(Event::local(LocalEvent::Abort)).ok();
        let _ = self
            .link
            .send(&builder::abort(self.peer_id, self.my_id, diag))
            .await;
        self.link.close().await;
    }

    /// Interrupt code used when the requester cancels.
    #[must_use]
    pub const fn cancel_code() -> EndCode {
        EndCode::CancelByRequester
    }
}
