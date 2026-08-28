//! The data transfer phase, shared by both roles: sending articles with synchronisation points,
//! receiving them, resynchronisation and interruption (§4.4.20 – §4.4.30).

use std::collections::VecDeque;
use std::time::Duration;

use tokio::sync::watch;

use pesit_core::article::{ArticlePacker, Reassembler};
use pesit_core::builder;
use pesit_core::compress::{Compressor, Decompressor};
use pesit_core::frame::EntityBuilder;
use pesit_core::params::{Compression, EndCode, FpduExt, SyncOption};
use pesit_core::state::{Event, LocalEvent, Machine, Role};
use pesit_core::{Diagnostic, Fpdu, FpduKind};

use crate::checkpoint::{Checkpoint, CheckpointStore};
use crate::error::SessionError;
use crate::io::{ArticleSink, ArticleSource, Position};
use crate::link::Link;

/// Default synchronisation interval when the peer left it undefined (PI 7 = FFFF).
pub const DEFAULT_SYNC_INTERVAL: u64 = 1024 * 1024;

/// Negotiated parameters of a data transfer.
#[derive(Debug, Clone)]
pub struct DataParams {
    /// Connection id of the peer (octet 5 of the FPDUs we send).
    pub peer_id: u8,
    /// Negotiated synchronisation option.
    pub sync: SyncOption,
    /// Whether F.RESTART (RESYN) was negotiated.
    pub resync: bool,
    /// Negotiated compression.
    pub compression: Compression,
    /// Whether the CRC option is active.
    pub crc: bool,
    /// Negotiated maximum entity size (PI 25).
    pub max_entity: usize,
    /// Pack several articles per DTF.
    pub multi_article: bool,
    /// Maximum article length (PI 32), used to size buffers (0 = unbounded).
    pub max_article: usize,
    /// Watchdog timeout while waiting for the peer.
    pub timeout: Duration,
    /// Local role (for the interruption code).
    pub role: Role,
}

/// Progress notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Progress {
    /// Data bytes transferred so far.
    pub data_bytes: u64,
    /// Articles transferred so far.
    pub articles: u64,
    /// Last synchronisation point number.
    pub sync: u32,
    /// Expected total size when known.
    pub total_hint: Option<u64>,
}

/// Runtime controls of a transfer.
pub struct Control<'a> {
    /// Cancellation flag (set to `true` to interrupt the transfer with F.CANCEL).
    pub cancel: Option<watch::Receiver<bool>>,
    /// Progress callback.
    pub progress: &'a mut (dyn FnMut(Progress) + Send),
}

impl Control<'_> {
    fn cancelled(&self) -> bool {
        self.cancel.as_ref().is_some_and(|c| *c.borrow())
    }
}

/// How the data phase ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataEnd {
    /// DTF.END with a success diagnostic.
    Completed,
    /// DTF.END carried an error diagnostic (sender side problem).
    EndedWithError(Diagnostic),
    /// The transfer was interrupted with IDT.
    Interrupted {
        /// End of transfer code (PI 19).
        code: EndCode,
        /// Diagnostic carried by IDT.
        diag: Diagnostic,
        /// Whether the peer initiated the interruption.
        by_peer: bool,
    },
}

/// Result of the data phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataResult {
    /// How it ended.
    pub end: DataEnd,
    /// Data bytes transferred (PI 27 semantics).
    pub data_bytes: u64,
    /// Articles transferred.
    pub articles: u64,
    /// Last synchronisation point number used.
    pub last_sync: u32,
}

fn position_of(cp: Checkpoint) -> Position {
    Position {
        file_offset: cp.file_offset,
        data_bytes: cp.data_bytes,
        articles: cp.articles,
    }
}

fn peer_message(f: &Fpdu) -> Option<String> {
    f.get_text(pesit_core::Pi::FreeMessage)
        .or_else(|| f.get_text(pesit_core::Pi::DiagComplement))
}

/// Error for a FPDU that the state machine rejects.
fn protocol_error(machine: Machine, kind: FpduKind) -> SessionError {
    SessionError::Protocol {
        state: machine.state(),
        kind,
    }
}

/// Apply a received FPDU to the machine, mapping ABORT to an error.
fn apply_received(machine: &mut Machine, f: &Fpdu) -> Result<bool, SessionError> {
    if f.kind == FpduKind::Abort {
        machine.apply(Event::received(FpduKind::Abort, false)).ok();
        return Err(SessionError::Aborted {
            diag: f.diag_or_ok(),
            message: peer_message(f),
        });
    }
    machine
        .apply(Event::received(f.kind, f.is_negative()))
        .map_err(|_| protocol_error(*machine, f.kind))
}

/// Send an IDT and wait for its acknowledgement (collisions handled).
async fn interrupt(
    link: &mut Link,
    machine: &mut Machine,
    params: &DataParams,
    diag: Diagnostic,
    code: EndCode,
) -> Result<(), SessionError> {
    machine
        .apply(Event::local(LocalEvent::Cancel))
        .map_err(|e| SessionError::Negotiation(e.to_string()))?;
    link.send(&builder::idt(params.peer_id, diag, code)).await?;
    loop {
        let f = link.recv(params.timeout).await?;
        match f.kind {
            FpduKind::AckIdt => {
                apply_received(machine, &f)?;
                return Ok(());
            }
            FpduKind::Idt => {
                // both sides interrupted at the same time: acknowledge the peer's IDT
                apply_received(machine, &f)?;
                link.send(&builder::ack_idt(params.peer_id)).await?;
                machine.apply(Event::local(LocalEvent::Accept)).ok();
                return Ok(());
            }
            _ => {
                // data, SYN, ACK(SYN)... still in flight: ignored per the state tables
                apply_received(machine, &f)?;
            }
        }
    }
}

/// Send the articles of `source` as DTF FPDUs until end of file or interruption.
///
/// `start` is the checkpoint the transfer (re)starts from; `source` is rewound to it.
pub async fn send_data(
    link: &mut Link,
    machine: &mut Machine,
    params: &DataParams,
    source: &mut dyn ArticleSource,
    checkpoints: &mut dyn CheckpointStore,
    start: Checkpoint,
    ctrl: &mut Control<'_>,
) -> Result<DataResult, SessionError> {
    let crc_cost = if params.crc {
        pesit_core::crc::CRC_LEN
    } else {
        0
    };
    let mut packer = ArticlePacker::new(
        params.peer_id,
        params.max_entity.saturating_sub(crc_cost),
        params.multi_article,
    );
    let mut entity = EntityBuilder::new(params.max_entity, params.crc);
    let mut compressor = (params.compression != Compression::None)
        .then(|| Compressor::new(params.compression, params.max_article.max(1)));
    let interval = if params.sync.enabled() {
        Some(
            params
                .sync
                .interval_bytes()
                .unwrap_or(DEFAULT_SYNC_INTERVAL),
        )
    } else {
        None
    };
    let window = usize::from(params.sync.window);
    let total_hint = source.size_hint();

    source.rewind(position_of(start))?;
    let mut data_bytes = start.data_bytes;
    let mut articles = start.articles;
    let mut sync_no = start.sync;
    let mut bytes_since_sync: u64 = 0;
    let mut unacked: VecDeque<u32> = VecDeque::new();
    let mut prev_pos = source.position();

    // Handle an asynchronous FPDU received while sending. Returns `Some` when the data phase ends.
    macro_rules! handle_async {
        ($f:expr) => {{
            let f: Fpdu = $f;
            match f.kind {
                FpduKind::AckSyn => {
                    apply_received(machine, &f)?;
                    let n = f.sync_number().unwrap_or(0);
                    while unacked.front().is_some_and(|u| *u <= n) {
                        unacked.pop_front();
                    }
                    checkpoints.acknowledge(n)?;
                    None
                }
                FpduKind::Resyn => {
                    apply_received(machine, &f)?;
                    if !params.resync {
                        return Err(SessionError::Negotiation(
                            "RESYN received but resynchronisation was not negotiated".into(),
                        ));
                    }
                    let requested = f.restart_point().unwrap_or(0);
                    let cp = if requested == 0 {
                        Checkpoint::default()
                    } else {
                        checkpoints.get(requested).unwrap_or_default()
                    };
                    link.send(&builder::ack_resyn(params.peer_id, cp.sync))
                        .await?;
                    machine
                        .apply(Event::local(LocalEvent::Accept))
                        .map_err(|e| SessionError::Negotiation(e.to_string()))?;
                    // rewind everything to the checkpoint
                    source.rewind(position_of(cp))?;
                    prev_pos = source.position();
                    let _ = packer.flush();
                    let _ = entity.take();
                    if let Some(c) = compressor.as_mut() {
                        c.sync_point();
                    }
                    data_bytes = cp.data_bytes;
                    articles = cp.articles;
                    sync_no = cp.sync;
                    bytes_since_sync = 0;
                    unacked.clear();
                    None
                }
                FpduKind::Idt => {
                    apply_received(machine, &f)?;
                    let _ = entity.take();
                    link.send(&builder::ack_idt(params.peer_id)).await?;
                    machine
                        .apply(Event::local(LocalEvent::Accept))
                        .map_err(|e| SessionError::Negotiation(e.to_string()))?;
                    Some(DataEnd::Interrupted {
                        code: f.end_code().unwrap_or(EndCode::Other(0)),
                        diag: f.diag_or_ok(),
                        by_peer: true,
                    })
                }
                _ => {
                    apply_received(machine, &f)?;
                    None
                }
            }
        }};
    }

    loop {
        // asynchronous FPDUs from the peer
        while let Some(f) = link.try_recv()? {
            if let Some(end) = handle_async!(f) {
                return Ok(DataResult {
                    end,
                    data_bytes,
                    articles,
                    last_sync: sync_no,
                });
            }
        }
        // local cancellation
        if ctrl.cancelled() {
            if !entity.is_empty() {
                link.send_entity(&entity.take()).await?;
            }
            let code = if params.role == Role::Requester {
                EndCode::CancelByRequester
            } else {
                EndCode::CancelByServer
            };
            interrupt(link, machine, params, Diagnostic::VOLUNTARY_STOP, code).await?;
            return Ok(DataResult {
                end: DataEnd::Interrupted {
                    code,
                    diag: Diagnostic::VOLUNTARY_STOP,
                    by_peer: false,
                },
                data_bytes,
                articles,
                last_sync: sync_no,
            });
        }
        // acknowledgement window
        if window > 0 && unacked.len() >= window {
            let f = link.recv(params.timeout).await?;
            if let Some(end) = handle_async!(f) {
                return Ok(DataResult {
                    end,
                    data_bytes,
                    articles,
                    last_sync: sync_no,
                });
            }
            continue;
        }
        // next article
        let Some(article) = source.next_article()? else {
            break;
        };
        let mut wire = match compressor.as_mut() {
            Some(c) => c.compress(&article),
            None => article.clone(),
        };
        // synchronisation point before this article when it would exceed the interval
        if let Some(iv) = interval {
            if bytes_since_sync > 0 && bytes_since_sync + wire.len() as u64 > iv {
                if let Some(f) = packer.flush() {
                    if !entity.fits(f.encoded_len()) {
                        link.send_entity(&entity.take()).await?;
                    }
                    entity
                        .push(&f)
                        .map_err(|e| SessionError::Negotiation(e.to_string()))?;
                }
                sync_no += 1;
                let syn = builder::syn(params.peer_id, sync_no);
                if !entity.fits(syn.encoded_len()) {
                    link.send_entity(&entity.take()).await?;
                }
                entity
                    .push(&syn)
                    .map_err(|e| SessionError::Negotiation(e.to_string()))?;
                link.send_entity(&entity.take()).await?;
                machine
                    .apply(Event::local(LocalEvent::Sync))
                    .map_err(|e| SessionError::Negotiation(e.to_string()))?;
                checkpoints.record(Checkpoint {
                    sync: sync_no,
                    file_offset: prev_pos.file_offset,
                    data_bytes,
                    articles,
                })?;
                if window > 0 {
                    unacked.push_back(sync_no);
                }
                bytes_since_sync = 0;
                if let Some(c) = compressor.as_mut() {
                    c.sync_point();
                    wire = c.compress(&article);
                }
            }
        }
        for f in packer.push(&wire) {
            if !entity.fits(f.encoded_len()) {
                link.send_entity(&entity.take()).await?;
            }
            entity
                .push(&f)
                .map_err(|e| SessionError::Negotiation(e.to_string()))?;
        }
        if entity.remaining() < pesit_core::fpdu::HEADER_LEN + 1 {
            link.send_entity(&entity.take()).await?;
        }
        machine
            .apply(Event::local(LocalEvent::SendData))
            .map_err(|e| SessionError::Negotiation(e.to_string()))?;
        data_bytes += wire.len() as u64;
        articles += 1;
        bytes_since_sync += wire.len() as u64;
        prev_pos = source.position();
        (ctrl.progress)(Progress {
            data_bytes,
            articles,
            sync: sync_no,
            total_hint,
        });
    }
    // end of data
    if let Some(f) = packer.flush() {
        if !entity.fits(f.encoded_len()) {
            link.send_entity(&entity.take()).await?;
        }
        entity
            .push(&f)
            .map_err(|e| SessionError::Negotiation(e.to_string()))?;
    }
    let end = builder::dtf_end(params.peer_id, Diagnostic::OK);
    if !entity.fits(end.encoded_len()) {
        link.send_entity(&entity.take()).await?;
    }
    entity
        .push(&end)
        .map_err(|e| SessionError::Negotiation(e.to_string()))?;
    link.send_entity(&entity.take()).await?;
    machine
        .apply(Event::local(LocalEvent::DataEnd))
        .map_err(|e| SessionError::Negotiation(e.to_string()))?;
    (ctrl.progress)(Progress {
        data_bytes,
        articles,
        sync: sync_no,
        total_hint,
    });
    Ok(DataResult {
        end: DataEnd::Completed,
        data_bytes,
        articles,
        last_sync: sync_no,
    })
}

/// Receive DTF FPDUs into `sink` until DTF.END or interruption.
///
/// `start` is the checkpoint the transfer (re)starts from; the sink must already be positioned.
pub async fn receive_data(
    link: &mut Link,
    machine: &mut Machine,
    params: &DataParams,
    sink: &mut dyn ArticleSink,
    checkpoints: &mut dyn CheckpointStore,
    start: Checkpoint,
    ctrl: &mut Control<'_>,
) -> Result<DataResult, SessionError> {
    let mut reassembler = Reassembler::new(params.max_article);
    let mut decompressor = (params.compression != Compression::None)
        .then(|| Decompressor::new(params.max_article.max(1)));
    let mut data_bytes = start.data_bytes;
    let mut articles = start.articles;
    let mut last_sync = start.sync;
    let total_hint = None;

    loop {
        if ctrl.cancelled() {
            let code = if params.role == Role::Requester {
                EndCode::CancelByRequester
            } else {
                EndCode::CancelByServer
            };
            interrupt(link, machine, params, Diagnostic::VOLUNTARY_STOP, code).await?;
            return Ok(DataResult {
                end: DataEnd::Interrupted {
                    code,
                    diag: Diagnostic::VOLUNTARY_STOP,
                    by_peer: false,
                },
                data_bytes,
                articles,
                last_sync,
            });
        }
        let f = match link.recv(params.timeout).await {
            Ok(f) => f,
            Err(SessionError::Decode(e))
                if e.diag == Diagnostic::TRANSMISSION_ERROR && params.resync =>
            {
                // CRC error during the data phase: resynchronise from the last checkpoint (§4.3.2.3)
                tracing::warn!(
                    "CRC error, requesting resynchronisation from sync point {last_sync}"
                );
                machine
                    .apply(Event::local(LocalEvent::Resync))
                    .map_err(|e| SessionError::Negotiation(e.to_string()))?;
                link.send(&builder::resyn(
                    params.peer_id,
                    Diagnostic::TRANSMISSION_ERROR,
                    last_sync,
                ))
                .await?;
                let ack = loop {
                    let g = link.recv(params.timeout).await?;
                    if g.kind == FpduKind::AckResyn {
                        break g;
                    }
                    if g.kind == FpduKind::Abort {
                        apply_received(machine, &g)?;
                    }
                };
                apply_received(machine, &ack)?;
                let point = ack.restart_point().unwrap_or(0);
                let cp = if point == 0 {
                    Checkpoint::default()
                } else {
                    checkpoints.get(point).ok_or_else(|| {
                        SessionError::Negotiation(format!(
                            "unknown restart point {point} in ACK(RESYN)"
                        ))
                    })?
                };
                sink.truncate(position_of(cp))?;
                data_bytes = cp.data_bytes;
                articles = cp.articles;
                last_sync = cp.sync;
                reassembler = Reassembler::new(params.max_article);
                continue;
            }
            Err(e) => return Err(e),
        };
        match f.kind {
            k if k.is_data() => {
                apply_received(machine, &f)?;
                for article in reassembler.feed(&f)? {
                    let wire_len = article.len() as u64;
                    match decompressor.as_mut() {
                        Some(d) => sink.write_article(d.decompress(&article)?)?,
                        None => sink.write_article(&article)?,
                    }
                    data_bytes += wire_len;
                    articles += 1;
                }
                (ctrl.progress)(Progress {
                    data_bytes,
                    articles,
                    sync: last_sync,
                    total_hint,
                });
            }
            FpduKind::Syn => {
                apply_received(machine, &f)?;
                let n = f.sync_number().unwrap_or(last_sync + 1);
                let pos = sink.checkpoint()?;
                checkpoints.record(Checkpoint {
                    sync: n,
                    file_offset: pos.file_offset,
                    data_bytes,
                    articles,
                })?;
                last_sync = n;
                if params.sync.window != 0 || !params.sync.enabled() {
                    link.send(&builder::ack_syn(params.peer_id, n)).await?;
                    machine
                        .apply(Event::local(LocalEvent::Accept))
                        .map_err(|e| SessionError::Negotiation(e.to_string()))?;
                }
            }
            FpduKind::DtfEnd => {
                apply_received(machine, &f)?;
                let diag = f.diag_or_ok();
                let end = if diag.is_ok() {
                    DataEnd::Completed
                } else {
                    DataEnd::EndedWithError(diag)
                };
                (ctrl.progress)(Progress {
                    data_bytes,
                    articles,
                    sync: last_sync,
                    total_hint,
                });
                return Ok(DataResult {
                    end,
                    data_bytes,
                    articles,
                    last_sync,
                });
            }
            FpduKind::Resyn => {
                apply_received(machine, &f)?;
                let requested = f.restart_point().unwrap_or(0);
                let cp = if requested == 0 {
                    Some(Checkpoint::default())
                } else {
                    checkpoints.get(requested)
                };
                // unknown point: restart from the beginning (§3.6.3 p)
                let cp = cp.unwrap_or_default();
                sink.truncate(position_of(cp))?;
                data_bytes = cp.data_bytes;
                articles = cp.articles;
                last_sync = cp.sync;
                reassembler = Reassembler::new(params.max_article);
                link.send(&builder::ack_resyn(params.peer_id, cp.sync))
                    .await?;
                machine
                    .apply(Event::local(LocalEvent::Accept))
                    .map_err(|e| SessionError::Negotiation(e.to_string()))?;
            }
            FpduKind::Idt => {
                apply_received(machine, &f)?;
                link.send(&builder::ack_idt(params.peer_id)).await?;
                machine
                    .apply(Event::local(LocalEvent::Accept))
                    .map_err(|e| SessionError::Negotiation(e.to_string()))?;
                return Ok(DataResult {
                    end: DataEnd::Interrupted {
                        code: f.end_code().unwrap_or(EndCode::Other(0)),
                        diag: f.diag_or_ok(),
                        by_peer: true,
                    },
                    data_bytes,
                    articles,
                    last_sync,
                });
            }
            _ => {
                apply_received(machine, &f)?;
            }
        }
    }
}

/// Validate the PI 27 / PI 28 counters of a TRANS.END or ACK(TRANS.END) against local counters.
pub fn check_counts(f: &Fpdu, data_bytes: u64, articles: u64) -> Result<(), SessionError> {
    if let Some(b) = f.get_num(pesit_core::Pi::ByteCount) {
        if b != data_bytes {
            return Err(SessionError::Counts(format!(
                "peer counted {b} data bytes, {data_bytes} transferred"
            )));
        }
    }
    if let Some(a) = f.get_num(pesit_core::Pi::ArticleCount) {
        if a != articles {
            return Err(SessionError::Counts(format!(
                "peer counted {a} articles, {articles} transferred"
            )));
        }
    }
    Ok(())
}
