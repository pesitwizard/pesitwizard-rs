//! A full-duplex FPDU link: a background task reads entities from the transport and queues their
//! FPDUs, so that the session engines can poll for asynchronous FPDUs (ACK(SYN), RESYN, IDT,
//! ABORT) while they are sending data.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use pesit_core::frame;
use pesit_core::Fpdu;

use crate::error::SessionError;
use crate::transport::{self, BoxedStream, FrameWriter, Framing, TransportError};

/// Capacity of the entity queue between the reader task and the consumer.
const QUEUE: usize = 64;

/// Full-duplex FPDU link.
pub struct Link {
    writer: FrameWriter,
    rx: mpsc::Receiver<Result<Vec<u8>, TransportError>>,
    pending: VecDeque<Fpdu>,
    crc: Arc<AtomicBool>,
    reader: JoinHandle<()>,
    max_entity: usize,
    closed: bool,
    /// Trace of the last received raw entity (for diagnostics).
    pub trace: bool,
}

impl Link {
    /// Wrap a connected stream.
    #[must_use]
    pub fn new(stream: BoxedStream, framing: Framing) -> Self {
        let (mut reader, writer, crc) = transport::split(stream, framing, transport::MAX_ENTITY);
        let (tx, rx) = mpsc::channel(QUEUE);
        let task = tokio::spawn(async move {
            loop {
                let item = reader.read_entity().await;
                let stop = item.is_err();
                if tx.send(item).await.is_err() || stop {
                    break;
                }
            }
        });
        Self {
            writer,
            rx,
            pending: VecDeque::new(),
            crc,
            reader: task,
            max_entity: 0xFFFF,
            closed: false,
            trace: false,
        }
    }

    /// Enable or disable CRC handling (after negotiation).
    pub fn set_crc(&mut self, on: bool) {
        self.crc.store(on, Ordering::Relaxed);
    }

    /// Whether CRC is enabled.
    #[must_use]
    pub fn crc(&self) -> bool {
        self.crc.load(Ordering::Relaxed)
    }

    /// Set the negotiated maximum entity size (PI 25) used to bound outgoing entities.
    pub fn set_max_entity(&mut self, max: usize) {
        self.max_entity = max.clamp(pesit_core::fpdu::HEADER_LEN + 1, 0xFFFF);
    }

    /// Negotiated maximum entity size.
    #[must_use]
    pub const fn max_entity(&self) -> usize {
        self.max_entity
    }

    /// Send one FPDU as its own entity.
    pub async fn send(&mut self, fpdu: &Fpdu) -> Result<(), SessionError> {
        tracing::trace!(target: "pesit::fpdu", "send {fpdu:?}");
        let entity = frame::single_entity(fpdu, self.crc())
            .map_err(|e| SessionError::Negotiation(e.to_string()))?;
        self.send_entity(&entity).await
    }

    /// Send an already framed entity (possibly several concatenated FPDUs).
    pub async fn send_entity(&mut self, entity: &[u8]) -> Result<(), SessionError> {
        self.writer.write_entity(entity).await?;
        Ok(())
    }

    /// Send raw bytes without framing (pre-connection when the peer expects none).
    pub async fn send_raw(&mut self, bytes: &[u8]) -> Result<(), SessionError> {
        self.writer.write_raw(bytes).await?;
        Ok(())
    }

    /// Receive the next raw entity (used for the pre-connection exchange).
    pub async fn recv_entity(&mut self, timeout: Duration) -> Result<Vec<u8>, SessionError> {
        if self.closed {
            return Err(TransportError::Closed.into());
        }
        match tokio::time::timeout(timeout, self.rx.recv()).await {
            Ok(Some(Ok(e))) => Ok(e),
            Ok(Some(Err(e))) => {
                self.closed = true;
                Err(e.into())
            }
            Ok(None) => {
                self.closed = true;
                Err(TransportError::Closed.into())
            }
            Err(_) => Err(SessionError::Timeout("data from the peer")),
        }
    }

    /// Receive the next FPDU, waiting at most `timeout`.
    pub async fn recv(&mut self, timeout: Duration) -> Result<Fpdu, SessionError> {
        if let Some(f) = self.pending.pop_front() {
            return Ok(f);
        }
        let entity = self.recv_entity(timeout).await?;
        self.queue_entity(&entity)?;
        self.pending
            .pop_front()
            .ok_or_else(|| TransportError::Invalid(entity.len()).into())
    }

    /// Return the next FPDU if one is already available, without waiting.
    pub fn try_recv(&mut self) -> Result<Option<Fpdu>, SessionError> {
        if let Some(f) = self.pending.pop_front() {
            return Ok(Some(f));
        }
        if self.closed {
            return Ok(None);
        }
        match self.rx.try_recv() {
            Ok(Ok(entity)) => {
                self.queue_entity(&entity)?;
                Ok(self.pending.pop_front())
            }
            Ok(Err(e)) => {
                self.closed = true;
                Err(e.into())
            }
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                self.closed = true;
                Err(TransportError::Closed.into())
            }
        }
    }

    /// Push back an FPDU so that the next `recv` returns it.
    pub fn unread(&mut self, fpdu: Fpdu) {
        self.pending.push_front(fpdu);
    }

    fn queue_entity(&mut self, entity: &[u8]) -> Result<(), SessionError> {
        for bytes in frame::split_entity(entity, self.crc())? {
            let f = Fpdu::decode(bytes)?;
            tracing::trace!(target: "pesit::fpdu", "recv {f:?}");
            self.pending.push_back(f);
        }
        Ok(())
    }

    /// Close the link.
    pub async fn close(mut self) {
        let _ = self.writer.shutdown().await;
        self.reader.abort();
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pesit_core::{FpduKind, Pi};

    #[tokio::test]
    async fn send_and_receive() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let mut la = Link::new(Box::pin(a), Framing::LengthPrefixed);
        let mut lb = Link::new(Box::pin(b), Framing::LengthPrefixed);
        let f = Fpdu::new(FpduKind::Syn)
            .with_ids(1, 0)
            .with_num(Pi::SyncNumber, 3);
        la.send(&f).await.unwrap_or_default();
        assert_eq!(
            lb.recv(Duration::from_secs(1))
                .await
                .unwrap_or_else(|e| panic!("{e}")),
            f
        );
        assert!(lb.try_recv().unwrap_or_default().is_none());
        // concatenated entity
        let mut eb = frame::EntityBuilder::new(100, false);
        eb.push(&Fpdu::data(FpduKind::Dtf, 1, 0, vec![1, 2]))
            .unwrap_or_default();
        eb.push(&f).unwrap_or_default();
        la.send_entity(&eb.take()).await.unwrap_or_default();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            lb.try_recv().unwrap_or_default().map(|f| f.kind),
            Some(FpduKind::Dtf)
        );
        assert_eq!(
            lb.try_recv().unwrap_or_default().map(|f| f.kind),
            Some(FpduKind::Syn)
        );
        drop(la);
        assert!(matches!(
            lb.recv(Duration::from_secs(1)).await,
            Err(SessionError::Transport(TransportError::Closed))
        ));
    }

    #[tokio::test]
    async fn timeout() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let _la = Link::new(Box::pin(a), Framing::Raw);
        let mut lb = Link::new(Box::pin(b), Framing::Raw);
        assert!(matches!(
            lb.recv(Duration::from_millis(50)).await,
            Err(SessionError::Timeout(_))
        ));
    }
}
