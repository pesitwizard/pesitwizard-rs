//! PeSIT data compression (PI 21, annex A of the specification).
//!
//! The algorithms and the on-the-wire format were recovered from Connect:Express
//! against the reference implementation), which is the reference
//! implementation PeSIT Wizard interoperates with.
//!
//! An article is compressed chunk by chunk (chunks of at most [`CHUNK`] bytes). Every chunk
//! becomes a sequence of *strings*, each introduced by a one byte header:
//!
//! * `0x00 | n` (n = 1..63): `n` literal bytes follow;
//! * `0x80 | n` (n = 2..63): the following byte is repeated `n` times (horizontal compression);
//! * `0xC0 | n` (n = 1..63): `n` bytes are identical to the reference article at the same
//!   offset (vertical compression); nothing follows the header.
//!
//! The reference article is the previously transmitted article, kept in a persistent buffer
//! which is overwritten from its beginning by each article (bytes beyond the length of the last
//! article keep older content, on both sides). After a synchronisation point the first article is
//! always sent as literal strings ([`Mode::Literal`]) so that a restart from that point does not
//! depend on the reference.

use crate::params::Compression;

/// Maximum chunk length and maximum string count (6 bits).
pub const CHUNK: usize = 63;

/// Compression mode applied to one article.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Literal strings only (`n` + bytes); used after a synchronisation point.
    Literal,
    /// Horizontal compression.
    Horizontal,
    /// Vertical compression against the reference.
    Vertical,
    /// Vertical, with horizontally compressed differences.
    Mixed,
}

impl From<Compression> for Mode {
    fn from(c: Compression) -> Self {
        match c {
            Compression::None => Mode::Literal,
            Compression::Horizontal => Mode::Horizontal,
            Compression::Vertical => Mode::Vertical,
            Compression::Mixed => Mode::Mixed,
        }
    }
}

/// Error returned when compressed data is malformed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecompressError {
    /// A string header of the form `0x40 | n` was found.
    #[error("invalid compression string header {0:#04x}")]
    InvalidHeader(u8),
    /// The compressed data ends in the middle of a string.
    #[error("truncated compressed data")]
    Truncated,
    /// The decompressed article exceeds the maximum article length.
    #[error("decompressed article exceeds {0} bytes")]
    TooLong(usize),
}

/// Compress an article. `reference` must be at least as long as `article`.
#[must_use]
pub fn compress(mode: Mode, article: &[u8], reference: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(article.len() + article.len() / CHUNK + 2);
    let mut pos = 0;
    while pos < article.len() {
        let n = CHUNK.min(article.len() - pos);
        let chunk = &article[pos..pos + n];
        let refc = &reference[pos..pos + n];
        match mode {
            Mode::Literal => {
                out.push(n as u8);
                out.extend_from_slice(chunk);
            }
            Mode::Horizontal => horizontal(&mut out, chunk),
            Mode::Vertical => vertical(&mut out, chunk, refc, false),
            Mode::Mixed => vertical(&mut out, chunk, refc, true),
        }
        pos += n;
    }
    out
}

/// Horizontal (run-length) compression of one chunk (≤ 63 bytes), Connect:Express `r_comphor`.
fn horizontal(out: &mut Vec<u8>, chunk: &[u8]) {
    let Some(&first) = chunk.first() else { return };
    let mut header = out.len();
    out.push(1);
    out.push(first);
    let mut literal = true;
    let mut cur = first;
    for &b in &chunk[1..] {
        if b == cur {
            if literal {
                if out[header] == 1 {
                    // a one byte literal becomes a run of two
                    out[header] = 0x82;
                } else {
                    // detach the last literal byte into a new run
                    out[header] -= 1;
                    header = out.len() - 1;
                    out[header] = 0x82;
                    out.push(cur);
                }
                literal = false;
            } else {
                out[header] += 1;
            }
        } else {
            cur = b;
            if literal {
                out[header] += 1;
                out.push(b);
            } else {
                header = out.len();
                out.push(1);
                out.push(b);
                literal = true;
            }
        }
    }
}

/// Vertical (or mixed) compression of one chunk against the reference chunk.
fn vertical(out: &mut Vec<u8>, chunk: &[u8], reference: &[u8], mixed: bool) {
    let mut pos = 0;
    while pos < chunk.len() {
        let equal = chunk[pos..]
            .iter()
            .zip(&reference[pos..])
            .take_while(|(a, b)| a == b)
            .count();
        if equal > 0 {
            out.push(0xC0 | equal as u8);
            pos += equal;
            continue;
        }
        let diff = chunk[pos..]
            .iter()
            .zip(&reference[pos..])
            .take_while(|(a, b)| a != b)
            .count();
        if mixed {
            horizontal(out, &chunk[pos..pos + diff]);
        } else {
            out.push(diff as u8);
            out.extend_from_slice(&chunk[pos..pos + diff]);
        }
        pos += diff;
    }
}

/// Decompress an article into `out` (cleared first), using `reference` for vertical strings.
/// `max_len` bounds the decompressed size.
pub fn decompress(
    compressed: &[u8],
    reference: &[u8],
    max_len: usize,
    out: &mut Vec<u8>,
) -> Result<(), DecompressError> {
    out.clear();
    let mut pos = 0;
    while pos < compressed.len() {
        let h = compressed[pos];
        pos += 1;
        let n = usize::from(h & 0x3F);
        let need = |len: usize| {
            if out.len() + len > max_len {
                Err(DecompressError::TooLong(max_len))
            } else {
                Ok(())
            }
        };
        match h & 0xC0 {
            0xC0 => {
                need(n)?;
                let start = out.len();
                let Some(src) = reference.get(start..start + n) else {
                    return Err(DecompressError::TooLong(reference.len()));
                };
                out.extend_from_slice(src);
            }
            0x80 => {
                let Some(&b) = compressed.get(pos) else {
                    return Err(DecompressError::Truncated);
                };
                pos += 1;
                let n = usize::from(h & 0x7F);
                need(n)?;
                out.extend(std::iter::repeat_n(b, n));
            }
            0x00 => {
                let Some(src) = compressed.get(pos..pos + n) else {
                    return Err(DecompressError::Truncated);
                };
                need(n)?;
                out.extend_from_slice(src);
                pos += n;
            }
            _ => return Err(DecompressError::InvalidHeader(h)),
        }
    }
    Ok(())
}

/// Persistent reference buffer shared by both ends of a compressed transfer.
#[derive(Debug, Clone)]
pub struct Reference {
    buf: Vec<u8>,
}

impl Reference {
    /// New zero-filled reference for articles of at most `max_article` bytes.
    #[must_use]
    pub fn new(max_article: usize) -> Self {
        Self {
            buf: vec![0; max_article.max(1)],
        }
    }

    /// Reference bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Record `article` as the last transmitted article (overwrites the beginning of the buffer).
    pub fn update(&mut self, article: &[u8]) {
        if article.len() > self.buf.len() {
            self.buf.resize(article.len(), 0);
        }
        self.buf[..article.len()].copy_from_slice(article);
    }

    /// Capacity of the buffer.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }
}

/// Stateful compressor: applies the negotiated compression, switches to literal mode for the
/// first article after a synchronisation point and maintains the reference.
#[derive(Debug, Clone)]
pub struct Compressor {
    compression: Compression,
    reference: Reference,
    after_sync: bool,
}

impl Compressor {
    /// New compressor for the negotiated `compression` and articles of at most `max_article`.
    #[must_use]
    pub fn new(compression: Compression, max_article: usize) -> Self {
        Self {
            compression,
            reference: Reference::new(max_article),
            after_sync: true,
        }
    }

    /// Whether any transformation is applied.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        !matches!(self.compression, Compression::None)
    }

    /// Notify that a synchronisation point was emitted: the next article is sent literal.
    pub fn sync_point(&mut self) {
        self.after_sync = true;
    }

    /// Compress an article (returns the wire form).
    #[must_use]
    pub fn compress(&mut self, article: &[u8]) -> Vec<u8> {
        if article.len() > self.reference.capacity() {
            self.reference.buf.resize(article.len(), 0);
        }
        let mode = if self.after_sync {
            Mode::Literal
        } else {
            Mode::from(self.compression)
        };
        let out = compress(mode, article, self.reference.as_slice());
        self.reference.update(article);
        self.after_sync = false;
        out
    }
}

/// Stateful decompressor maintaining the reference article.
#[derive(Debug, Clone)]
pub struct Decompressor {
    reference: Reference,
    max_article: usize,
    scratch: Vec<u8>,
}

impl Decompressor {
    /// New decompressor for articles of at most `max_article` bytes.
    #[must_use]
    pub fn new(max_article: usize) -> Self {
        Self {
            reference: Reference::new(max_article),
            max_article: max_article.max(1),
            scratch: Vec::new(),
        }
    }

    /// Decompress an article; the result is valid until the next call.
    pub fn decompress(&mut self, compressed: &[u8]) -> Result<&[u8], DecompressError> {
        let mut out = std::mem::take(&mut self.scratch);
        let res = decompress(
            compressed,
            self.reference.as_slice(),
            self.max_article,
            &mut out,
        );
        self.scratch = out;
        res?;
        self.reference.update(&self.scratch);
        Ok(&self.scratch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(mode: Mode, article: &[u8], reference: &[u8]) -> Vec<u8> {
        let c = compress(mode, article, reference);
        let mut out = Vec::new();
        decompress(&c, reference, 1 << 16, &mut out).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(out, article, "mode {mode:?}");
        c
    }

    #[test]
    fn literal() {
        let a = vec![7u8; 130];
        let c = round_trip(Mode::Literal, &a, &[0; 130]);
        assert_eq!(c.len(), 130 + 3);
        assert_eq!(c[0], 63);
        assert_eq!(c[64], 63);
        assert_eq!(c[128], 4);
    }

    #[test]
    fn horizontal_runs() {
        let a = b"aaaaabcdddddddddefggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        let r = vec![0; a.len()];
        let c = round_trip(Mode::Horizontal, a, &r);
        assert!(c.len() < a.len());
        // "aaaaa" -> 0x85 'a'; "bc" -> 2 'b' 'c'; "ddddddddd" -> 0x89 'd'; "ef" -> 2 'e' 'f' ...
        assert_eq!(&c[..8], &[0x85, b'a', 2, b'b', b'c', 0x89, b'd', 2]);
        round_trip(Mode::Horizontal, b"x", &[0]);
        round_trip(Mode::Horizontal, b"xy", &[0, 0]);
        round_trip(Mode::Horizontal, b"xx", &[0, 0]);
        round_trip(Mode::Horizontal, b"xxy", &[0, 0, 0]);
        round_trip(Mode::Horizontal, b"abcabcaabbcc", &[0; 12]);
        round_trip(Mode::Horizontal, &[9u8; 63], &[0; 63]);
        round_trip(Mode::Horizontal, &[9u8; 64], &[0; 64]);
    }

    #[test]
    fn vertical_and_mixed() {
        let reference: Vec<u8> = (0..200u32).map(|i| (i % 7) as u8).collect();
        let mut a = reference.clone();
        a[10] = 99;
        a[11] = 99;
        a[150..160].copy_from_slice(&[5; 10]);
        let cv = round_trip(Mode::Vertical, &a, &reference);
        let cm = round_trip(Mode::Mixed, &a, &reference);
        assert!(cv.len() < a.len());
        assert!(cm.len() <= cv.len());
        assert_eq!(cv[0], 0xC0 | 0x0A);
        round_trip(Mode::Vertical, &a, &[0; 200]);
        round_trip(Mode::Mixed, &a, &[0; 200]);
        round_trip(Mode::Vertical, &reference, &reference);
    }

    #[test]
    fn stateful_round_trip() {
        let mut comp = Compressor::new(Compression::Mixed, 64);
        let mut dec = Decompressor::new(64);
        let articles: Vec<Vec<u8>> = vec![
            b"hello world".to_vec(),
            b"hello there".to_vec(),
            b"hello".to_vec(),
            vec![1; 64],
            vec![1; 60],
        ];
        for (i, a) in articles.iter().enumerate() {
            if i == 3 {
                comp.sync_point();
            }
            let c = comp.compress(a);
            if i == 0 || i == 3 {
                assert_eq!(c[0] & 0xC0, 0, "literal after sync point");
            }
            assert_eq!(dec.decompress(&c).unwrap_or_default(), a.as_slice());
        }
    }

    #[test]
    fn errors() {
        let mut out = Vec::new();
        assert_eq!(
            decompress(&[0x41], &[0; 4], 16, &mut out),
            Err(DecompressError::InvalidHeader(0x41))
        );
        assert_eq!(
            decompress(&[0x83], &[0; 4], 16, &mut out),
            Err(DecompressError::Truncated)
        );
        assert_eq!(
            decompress(&[3, 1, 2], &[0; 4], 16, &mut out),
            Err(DecompressError::Truncated)
        );
        assert_eq!(
            decompress(&[0x84, 1], &[0; 4], 2, &mut out),
            Err(DecompressError::TooLong(2))
        );
    }
}
