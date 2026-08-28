//! Data entity framing over a byte stream and the pre-connection exchange.
//!
//! * [`Framing::LengthPrefixed`] (plain TCP, and TLS with C:X `TCPIP_HEADER=Y`): every entity is
//!   preceded by a 2-byte big-endian length that does not count itself.
//! * [`Framing::Raw`] (TLS, C:X `TCPIP_HEADER=N`): FPDUs are written back to back; the reader
//!   delimits them with the FPDU length field (plus the two CRC bytes when negotiated).
//!
//! The 24-byte EBCDIC pre-connection message and its 4-byte answer are recognised whatever the
//! framing (some implementations send them without the length prefix).

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use pesit_core::crc::CRC_LEN;
use pesit_core::ebcdic;
use pesit_core::fpdu::HEADER_LEN;

/// Any async duplex byte stream.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Boxed duplex stream (TCP or TLS).
pub type BoxedStream = Pin<Box<dyn AsyncStream>>;

/// Entity framing on the byte stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Framing {
    /// 2-byte big-endian length before each entity (mandatory on plain TCP).
    #[default]
    LengthPrefixed,
    /// No length prefix; one FPDU per unit (TLS without header).
    Raw,
}

/// Largest entity accepted from the network (FPDU length field + prefix + CRC).
pub const MAX_ENTITY: usize = 0xFFFF + 2 + CRC_LEN;

/// Transport error.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Socket error.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// The peer closed the connection.
    #[error("connection closed by the peer")]
    Closed,
    /// An entity larger than the limit was announced.
    #[error("entity of {0} bytes exceeds the limit of {1} bytes")]
    TooLarge(usize, usize),
    /// An entity shorter than a FPDU header was received.
    #[error("invalid entity of {0} bytes")]
    Invalid(usize),
}

/// Reader side of a framed stream.
pub struct FrameReader {
    inner: ReadHalf<BoxedStream>,
    framing: Framing,
    crc: Arc<AtomicBool>,
    max_len: usize,
    first: bool,
    /// Whether the CRC presence still has to be probed on the first FPDU (raw framing).
    probe_crc: bool,
}

impl FrameReader {
    /// Maximum entity length accepted.
    #[must_use]
    pub const fn max_len(&self) -> usize {
        self.max_len
    }

    /// Read the next entity. For [`Framing::Raw`] this is exactly one FPDU (with its CRC bytes
    /// when enabled); for [`Framing::LengthPrefixed`] it may contain several FPDUs.
    pub async fn read_entity(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut head = [0u8; 2];
        read_exact_or_closed(&mut self.inner, &mut head).await?;
        let first = std::mem::replace(&mut self.first, false);
        // Pre-connection message or answer sent without a length prefix.
        if first && head == [ebcdic::PRECONNECT_MAGIC[0], ebcdic::PRECONNECT_MAGIC[1]] {
            let mut rest = [0u8; ebcdic::PRECONNECT_LEN - 2];
            read_exact_or_closed(&mut self.inner, &mut rest).await?;
            let mut v = head.to_vec();
            v.extend_from_slice(&rest);
            return Ok(v);
        }
        if first
            && (head == [ebcdic::PRECONNECT_ACK[0], ebcdic::PRECONNECT_ACK[1]]
                || head == [ebcdic::PRECONNECT_NAK[0], ebcdic::PRECONNECT_NAK[1]])
        {
            let mut rest = [0u8; 2];
            read_exact_or_closed(&mut self.inner, &mut rest).await?;
            let mut v = head.to_vec();
            v.extend_from_slice(&rest);
            return Ok(v);
        }
        let declared = usize::from(u16::from_be_bytes(head));
        match self.framing {
            Framing::LengthPrefixed => {
                if declared > self.max_len {
                    return Err(TransportError::TooLarge(declared, self.max_len));
                }
                if declared == 0 {
                    return Err(TransportError::Invalid(0));
                }
                let mut v = vec![0u8; declared];
                read_exact_or_closed(&mut self.inner, &mut v).await?;
                Ok(v)
            }
            Framing::Raw => {
                // `declared` is the FPDU length field (which counts itself)
                if declared < HEADER_LEN {
                    return Err(TransportError::Invalid(declared));
                }
                let extra = if self.crc.load(Ordering::Relaxed) {
                    CRC_LEN
                } else {
                    0
                };
                if declared + extra > self.max_len {
                    return Err(TransportError::TooLarge(declared + extra, self.max_len));
                }
                let mut v = vec![0u8; declared + extra];
                v[..2].copy_from_slice(&head);
                read_exact_or_closed(&mut self.inner, &mut v[2..]).await?;
                // Without a transport header the receiver of a CONNECT cannot know whether a
                // CRC follows: look at PI 1 of the CONNECT itself.
                if std::mem::replace(&mut self.probe_crc, false)
                    && extra == 0
                    && v.get(2..4) == Some(&[0x40, 0x20])
                    && connect_requests_crc(&v)
                {
                    let mut crc = [0u8; CRC_LEN];
                    read_exact_or_closed(&mut self.inner, &mut crc).await?;
                    v.extend_from_slice(&crc);
                    self.crc.store(true, Ordering::Relaxed);
                }
                Ok(v)
            }
        }
    }
}

/// Whether a raw CONNECT FPDU carries PI 1 = 1.
fn connect_requests_crc(fpdu: &[u8]) -> bool {
    pesit_core::Fpdu::decode_lenient(fpdu).is_ok_and(|f| f.get_num(pesit_core::Pi::Crc) == Some(1))
}

async fn read_exact_or_closed<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut [u8],
) -> Result<(), TransportError> {
    match r.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(TransportError::Closed),
        Err(e) => Err(TransportError::Io(e)),
    }
}

/// Writer side of a framed stream.
pub struct FrameWriter {
    inner: WriteHalf<BoxedStream>,
    framing: Framing,
}

impl FrameWriter {
    /// Write one entity with the configured framing.
    pub async fn write_entity(&mut self, entity: &[u8]) -> Result<(), TransportError> {
        if entity.len() > 0xFFFF {
            return Err(TransportError::TooLarge(entity.len(), 0xFFFF));
        }
        match self.framing {
            Framing::LengthPrefixed => {
                let mut buf = Vec::with_capacity(entity.len() + 2);
                buf.extend_from_slice(&(entity.len() as u16).to_be_bytes());
                buf.extend_from_slice(entity);
                self.inner.write_all(&buf).await?;
            }
            Framing::Raw => self.inner.write_all(entity).await?,
        }
        self.inner.flush().await?;
        Ok(())
    }

    /// Write raw bytes (pre-connection messages when the peer expects no prefix).
    pub async fn write_raw(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.inner.write_all(bytes).await?;
        self.inner.flush().await?;
        Ok(())
    }

    /// Shut the write side down.
    pub async fn shutdown(&mut self) -> Result<(), TransportError> {
        self.inner.shutdown().await?;
        Ok(())
    }
}

/// Split a stream into a framed reader and writer sharing the CRC flag.
#[must_use]
pub fn split(
    stream: BoxedStream,
    framing: Framing,
    max_len: usize,
) -> (FrameReader, FrameWriter, Arc<AtomicBool>) {
    let (r, w) = tokio::io::split(stream);
    let crc = Arc::new(AtomicBool::new(false));
    (
        FrameReader {
            inner: r,
            framing,
            crc: Arc::clone(&crc),
            max_len: max_len.min(MAX_ENTITY),
            first: true,
            probe_crc: true,
        },
        FrameWriter { inner: w, framing },
        crc,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(framing: Framing) -> (FrameReader, FrameWriter, FrameReader, FrameWriter) {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (ra, wa, _) = split(Box::pin(a), framing, MAX_ENTITY);
        let (rb, wb, _) = split(Box::pin(b), framing, MAX_ENTITY);
        (ra, wa, rb, wb)
    }

    #[tokio::test]
    async fn length_prefixed_round_trip() {
        let (mut ra, _wa, _rb, mut wb) = pair(Framing::LengthPrefixed);
        let e1 = vec![0, 6, 0xC0, 0x02, 1, 0];
        let e2 = vec![0, 8, 0xC0, 0x03, 1, 0, 20, 1];
        wb.write_entity(&e1).await.unwrap_or_default();
        wb.write_entity(&e2).await.unwrap_or_default();
        assert_eq!(ra.read_entity().await.unwrap_or_default(), e1);
        assert_eq!(ra.read_entity().await.unwrap_or_default(), e2);
    }

    #[tokio::test]
    async fn raw_round_trip_with_crc() {
        let (mut ra, _wa, _rb, mut wb) = pair(Framing::Raw);
        ra.crc.store(true, Ordering::Relaxed);
        let mut e1 = vec![0, 6, 0xC0, 0x02, 1, 0];
        pesit_core::crc::append(&mut e1);
        let mut e2 = vec![0, 8, 0xC0, 0x03, 1, 0, 20, 1];
        pesit_core::crc::append(&mut e2);
        let mut both = e1.clone();
        both.extend_from_slice(&e2);
        wb.write_entity(&both).await.unwrap_or_default();
        assert_eq!(ra.read_entity().await.unwrap_or_default(), e1);
        assert_eq!(ra.read_entity().await.unwrap_or_default(), e2);
    }

    #[tokio::test]
    async fn preconnect_without_prefix() {
        let (mut ra, _wa, _rb, mut wb) = pair(Framing::LengthPrefixed);
        let m = ebcdic::preconnect_message("ID", "PW");
        wb.write_raw(&m).await.unwrap_or_default();
        wb.write_entity(&[0, 6, 0xC0, 0x02, 1, 0])
            .await
            .unwrap_or_default();
        assert_eq!(ra.read_entity().await.unwrap_or_default(), m.to_vec());
        assert_eq!(
            ra.read_entity().await.unwrap_or_default(),
            vec![0, 6, 0xC0, 0x02, 1, 0]
        );
    }

    #[tokio::test]
    async fn closed_and_too_large() {
        let (mut ra, _wa, rb, wb) = pair(Framing::LengthPrefixed);
        drop((rb, wb));
        assert!(matches!(
            ra.read_entity().await,
            Err(TransportError::Closed)
        ));
        let (mut ra, _wa, _rb, mut wb) = pair(Framing::LengthPrefixed);
        ra.max_len = 10;
        wb.write_entity(&[0u8; 20]).await.unwrap_or_default();
        assert!(matches!(
            ra.read_entity().await,
            Err(TransportError::TooLarge(20, 10))
        ));
    }
}
