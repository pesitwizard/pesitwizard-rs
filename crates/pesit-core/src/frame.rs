//! Data entity (NSDU) helpers: concatenation of FPDUs (§4.5), CRC handling and splitting of a
//! received entity into its FPDUs.

use crate::crc;
use crate::fpdu::{DecodeError, Fpdu, FpduKind, HEADER_LEN};

/// Split a received data entity into the FPDU byte slices it contains.
///
/// When `crc` is set every FPDU is followed by two check bytes which are verified and stripped.
/// Returns the FPDU slices (each starting with its own length field).
pub fn split_entity(entity: &[u8], crc: bool) -> Result<Vec<&[u8]>, DecodeError> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < entity.len() {
        if entity.len() - pos < HEADER_LEN {
            return Err(DecodeError {
                diag: crate::Diagnostic::REMOTE_PROTOCOL_ERROR,
                detail: format!("{} trailing bytes cannot form a FPDU", entity.len() - pos),
            });
        }
        let len = usize::from(u16::from_be_bytes([entity[pos], entity[pos + 1]]));
        if len < HEADER_LEN || pos + len > entity.len() {
            return Err(DecodeError {
                diag: crate::Diagnostic::REMOTE_PROTOCOL_ERROR,
                detail: format!(
                    "invalid FPDU length {len} at offset {pos} of a {} byte entity",
                    entity.len()
                ),
            });
        }
        let fpdu = &entity[pos..pos + len];
        pos += len;
        if crc {
            let Some(with_crc) = entity.get(pos - len..pos + crc::CRC_LEN) else {
                return Err(DecodeError {
                    diag: crate::Diagnostic::TRANSMISSION_ERROR,
                    detail: "missing CRC after FPDU".to_owned(),
                });
            };
            if !crc::verify(with_crc) {
                return Err(DecodeError {
                    diag: crate::Diagnostic::TRANSMISSION_ERROR,
                    detail: "CRC error".to_owned(),
                });
            }
            pos += crc::CRC_LEN;
        }
        out.push(fpdu);
    }
    Ok(out)
}

/// Decode every FPDU of an entity (strict template validation).
pub fn decode_entity(entity: &[u8], crc: bool) -> Result<Vec<Fpdu>, DecodeError> {
    split_entity(entity, crc)?
        .into_iter()
        .map(Fpdu::decode)
        .collect()
}

/// Builder accumulating FPDUs into one data entity bounded by the negotiated entity size.
#[derive(Debug)]
pub struct EntityBuilder {
    buf: Vec<u8>,
    max_len: usize,
    crc: bool,
    count: usize,
}

impl EntityBuilder {
    /// Create a builder for entities of at most `max_len` bytes (PI 25).
    #[must_use]
    pub fn new(max_len: usize, crc: bool) -> Self {
        Self {
            buf: Vec::with_capacity(max_len.min(1 << 16)),
            max_len,
            crc,
            count: 0,
        }
    }

    /// Bytes an encoded FPDU of `fpdu_len` bytes occupies in the entity.
    #[must_use]
    pub const fn cost(&self, fpdu_len: usize) -> usize {
        if self.crc {
            fpdu_len + crc::CRC_LEN
        } else {
            fpdu_len
        }
    }

    /// Whether an FPDU of `fpdu_len` bytes still fits. With CRC no concatenation is allowed.
    #[must_use]
    pub fn fits(&self, fpdu_len: usize) -> bool {
        if self.crc && self.count > 0 {
            return false;
        }
        self.buf.len() + self.cost(fpdu_len) <= self.max_len
    }

    /// Largest FPDU length that can still be appended.
    #[must_use]
    pub fn remaining(&self) -> usize {
        if self.crc && self.count > 0 {
            return 0;
        }
        self.max_len
            .saturating_sub(self.buf.len() + if self.crc { crc::CRC_LEN } else { 0 })
    }

    /// Append an already encoded FPDU (must fit; check with [`fits`](Self::fits)).
    pub fn push_encoded(&mut self, fpdu: &[u8]) {
        debug_assert!(self.fits(fpdu.len()));
        self.buf.extend_from_slice(fpdu);
        if self.crc {
            let c = crc::compute(fpdu);
            self.buf.extend_from_slice(&c);
        }
        self.count += 1;
    }

    /// Encode and append an FPDU.
    pub fn push(&mut self, fpdu: &Fpdu) -> Result<(), crate::fpdu::EncodeError> {
        let start = self.buf.len();
        fpdu.encode_into(&mut self.buf)?;
        if self.crc {
            let c = crc::compute(&self.buf[start..]);
            self.buf.extend_from_slice(&c);
        }
        self.count += 1;
        Ok(())
    }

    /// Number of FPDUs accumulated.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Whether nothing was accumulated.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Current entity length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Take the accumulated entity, leaving the builder empty.
    pub fn take(&mut self) -> Vec<u8> {
        self.count = 0;
        std::mem::take(&mut self.buf)
    }
}

/// Encode a single FPDU as its own entity (with CRC if negotiated).
pub fn single_entity(fpdu: &Fpdu, crc: bool) -> Result<Vec<u8>, crate::fpdu::EncodeError> {
    let mut v = fpdu.encode()?;
    if crc {
        crc::append(&mut v);
    }
    Ok(v)
}

/// Peek the kind of the first FPDU of an entity.
#[must_use]
pub fn peek_kind(entity: &[u8]) -> Option<FpduKind> {
    entity
        .get(2..4)
        .and_then(|b| FpduKind::from_codes(b[0], b[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pi::Pi;

    #[test]
    fn concat_and_split() {
        let mut b = EntityBuilder::new(64, false);
        let dtf = Fpdu::data(FpduKind::Dtf, 5, 0, vec![1, 2, 3, 4]);
        let syn = Fpdu::new(FpduKind::Syn)
            .with_ids(5, 0)
            .with_num(Pi::SyncNumber, 7);
        assert!(b.fits(dtf.encoded_len()));
        b.push(&dtf).unwrap_or_default();
        b.push(&syn).unwrap_or_default();
        assert_eq!(b.count(), 2);
        let entity = b.take();
        let parts = split_entity(&entity, false).unwrap_or_default();
        assert_eq!(parts.len(), 2);
        let fpdus = decode_entity(&entity, false).unwrap_or_default();
        assert_eq!(fpdus[0], dtf);
        assert_eq!(fpdus[1], syn);
        assert!(b.is_empty());
    }

    #[test]
    fn crc_entities() {
        let mut b = EntityBuilder::new(64, true);
        let syn = Fpdu::new(FpduKind::Syn)
            .with_ids(5, 0)
            .with_num(Pi::SyncNumber, 7);
        b.push(&syn).unwrap_or_default();
        assert!(!b.fits(6)); // no concatenation with CRC
        let entity = b.take();
        assert_eq!(entity.len(), syn.encoded_len() + 2);
        let fpdus = decode_entity(&entity, true).unwrap_or_default();
        assert_eq!(fpdus, vec![syn]);
        let mut bad = entity.clone();
        bad[7] ^= 0xFF;
        assert_eq!(
            split_entity(&bad, true).err().map(|e| e.diag),
            Some(crate::Diagnostic::TRANSMISSION_ERROR)
        );
        assert!(split_entity(&entity, false).is_err());
    }

    #[test]
    fn remaining_space() {
        let mut b = EntityBuilder::new(20, false);
        assert_eq!(b.remaining(), 20);
        b.push_encoded(&[0, 6, 0, 0, 1, 0]);
        assert_eq!(b.remaining(), 14);
        assert!(!b.fits(15));
    }
}
