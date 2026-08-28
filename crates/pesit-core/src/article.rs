//! Articles: record formats, packing of articles into data entities (multi-article DTF),
//! segmentation of long articles (DTFDA/DTFMA/DTFFA) and their reassembly (§4.4.20, §4.7.1 b).

use crate::fpdu::{Fpdu, FpduKind, HEADER_LEN};

/// Physical record formats, named after the Connect:Express file definition codes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordFormat {
    /// `BU` — binary undefined: the file is cut into articles of the record length, the last
    /// one may be shorter (default for arbitrary files).
    #[default]
    Bu,
    /// `BF` — binary fixed: every article has exactly the record length.
    Bf,
    /// `BV` — binary variable: like `BU` but announced as variable format.
    Bv,
    /// `TV` — text variable: one article per line, line feed removed on emission and appended on
    /// reception.
    Tv,
    /// `TF` — text fixed: one article per line, padded with spaces to the record length.
    Tf,
}

impl RecordFormat {
    /// Article format announced in PI 31.
    #[must_use]
    pub const fn article_format(self) -> crate::params::ArticleFormat {
        match self {
            RecordFormat::Bf | RecordFormat::Tf => crate::params::ArticleFormat::Fixed,
            RecordFormat::Bu | RecordFormat::Bv | RecordFormat::Tv => {
                crate::params::ArticleFormat::Variable
            }
        }
    }

    /// Whether articles are lines of text.
    #[must_use]
    pub const fn is_text(self) -> bool {
        matches!(self, RecordFormat::Tv | RecordFormat::Tf)
    }

    /// Two-letter code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            RecordFormat::Bu => "BU",
            RecordFormat::Bf => "BF",
            RecordFormat::Bv => "BV",
            RecordFormat::Tv => "TV",
            RecordFormat::Tf => "TF",
        }
    }

    /// Parse a two-letter code (case-insensitive).
    #[must_use]
    pub fn parse(code: &str) -> Option<Self> {
        match code.to_ascii_uppercase().as_str() {
            "BU" => Some(RecordFormat::Bu),
            "BF" => Some(RecordFormat::Bf),
            "BV" => Some(RecordFormat::Bv),
            "TV" => Some(RecordFormat::Tv),
            "TF" => Some(RecordFormat::Tf),
            _ => None,
        }
    }
}

/// Error produced when cutting a file into articles.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// Fixed format and the file size is not a multiple of the record length (C:X TRC 5010).
    #[error("unfilled last record: {0} bytes for a record length of {1}")]
    UnfilledRecord(usize, usize),
    /// A text line is longer than the record length.
    #[error("line of {0} bytes exceeds the record length {1}")]
    LineTooLong(usize, usize),
}

/// Cut a byte stream into articles according to a record format.
///
/// Feed data with [`push`](Self::push), take complete articles with [`next`](Self::next) and
/// call [`finish`](Self::finish) at end of stream.
#[derive(Debug)]
pub struct ArticleCutter {
    format: RecordFormat,
    record_len: usize,
    buf: Vec<u8>,
    pos: usize,
}

impl ArticleCutter {
    /// New cutter. `record_len` must be > 0.
    #[must_use]
    pub fn new(format: RecordFormat, record_len: usize) -> Self {
        Self {
            format,
            record_len: record_len.max(1),
            buf: Vec::new(),
            pos: 0,
        }
    }

    /// Append raw file bytes.
    pub fn push(&mut self, data: &[u8]) {
        if self.pos > 0 && self.pos >= self.buf.len() / 2 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// Next complete article, if enough data is buffered.
    pub fn next_article(&mut self) -> Result<Option<Vec<u8>>, RecordError> {
        let avail = &self.buf[self.pos..];
        match self.format {
            RecordFormat::Bu | RecordFormat::Bf | RecordFormat::Bv => {
                if avail.len() >= self.record_len {
                    let a = avail[..self.record_len].to_vec();
                    self.pos += self.record_len;
                    Ok(Some(a))
                } else {
                    Ok(None)
                }
            }
            RecordFormat::Tv | RecordFormat::Tf => match avail.iter().position(|b| *b == b'\n') {
                Some(nl) => {
                    let line = &avail[..nl];
                    let line = line.strip_suffix(b"\r").unwrap_or(line);
                    let article = self.text_article(line)?;
                    self.pos += nl + 1;
                    Ok(Some(article))
                }
                None => Ok(None),
            },
        }
    }

    /// Number of input bytes buffered but not yet consumed as articles.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Flush the last (partial) article at end of stream.
    pub fn finish(&mut self) -> Result<Option<Vec<u8>>, RecordError> {
        let rest = self.buf[self.pos..].to_vec();
        self.pos = self.buf.len();
        if rest.is_empty() {
            return Ok(None);
        }
        match self.format {
            RecordFormat::Bu | RecordFormat::Bv => Ok(Some(rest)),
            RecordFormat::Bf => Err(RecordError::UnfilledRecord(rest.len(), self.record_len)),
            RecordFormat::Tv | RecordFormat::Tf => {
                let line = rest.strip_suffix(b"\r").unwrap_or(&rest);
                self.text_article(line).map(Some)
            }
        }
    }

    fn text_article(&self, line: &[u8]) -> Result<Vec<u8>, RecordError> {
        if line.len() > self.record_len {
            return Err(RecordError::LineTooLong(line.len(), self.record_len));
        }
        let mut a = line.to_vec();
        if self.format == RecordFormat::Tf {
            a.resize(self.record_len, b' ');
        }
        if a.is_empty() {
            // Connect:Express replaces empty records by a space (REC_EMPTY)
            a.push(b' ');
        }
        Ok(a)
    }
}

/// Convert a received article into the bytes to write to the physical file.
#[must_use]
pub fn article_to_bytes(format: RecordFormat, article: &[u8]) -> Vec<u8> {
    if format.is_text() {
        let trimmed = if format == RecordFormat::Tf {
            trim_trailing_spaces(article)
        } else {
            article
        };
        let mut v = Vec::with_capacity(trimmed.len() + 1);
        v.extend_from_slice(trimmed);
        v.push(b'\n');
        v
    } else {
        article.to_vec()
    }
}

fn trim_trailing_spaces(a: &[u8]) -> &[u8] {
    let end = a.iter().rposition(|b| *b != b' ').map_or(0, |i| i + 1);
    &a[..end]
}

/// Maximum number of articles in one multi-article DTF (octet 6 is a byte).
pub const MAX_ARTICLES_PER_DTF: usize = 255;

/// Packs articles into DTF FPDUs bounded by the entity size, using multi-article DTFs and
/// segmentation (DTFDA/DTFMA/DTFFA) when an article does not fit.
#[derive(Debug)]
pub struct ArticlePacker {
    id_dst: u8,
    max_dtf_len: usize,
    multi_article: bool,
    pending: Vec<u8>,
    pending_count: usize,
}

impl ArticlePacker {
    /// `max_dtf_len` is the largest FPDU (header included) that may be emitted, i.e. the
    /// negotiated entity size (minus CRC if any). `multi_article` enables packing several
    /// articles in one DTF.
    #[must_use]
    pub fn new(id_dst: u8, max_dtf_len: usize, multi_article: bool) -> Self {
        Self {
            id_dst,
            max_dtf_len: max_dtf_len.max(HEADER_LEN + 1),
            multi_article,
            pending: Vec::new(),
            pending_count: 0,
        }
    }

    /// Largest article payload transportable in a single mono-article DTF.
    #[must_use]
    pub const fn max_single(&self) -> usize {
        self.max_dtf_len - HEADER_LEN
    }

    /// Add an article; returns the FPDUs that became ready (possibly none).
    #[must_use]
    pub fn push(&mut self, article: &[u8]) -> Vec<Fpdu> {
        let mut out = Vec::new();
        let max_single = self.max_single();
        if article.len() > max_single {
            // segmentation: flush pending articles first
            self.flush_into(&mut out);
            let mut chunks = article.chunks(max_single).peekable();
            let mut first = true;
            while let Some(c) = chunks.next() {
                let last = chunks.peek().is_none();
                let kind = match (first, last) {
                    (true, _) => FpduKind::DtfDa,
                    (false, false) => FpduKind::DtfMa,
                    (false, true) => FpduKind::DtfFa,
                };
                out.push(Fpdu::data(kind, self.id_dst, 0, c.to_vec()));
                first = false;
            }
            return out;
        }
        if !self.multi_article {
            out.push(Fpdu::data(FpduKind::Dtf, self.id_dst, 0, article.to_vec()));
            return out;
        }
        let needed = 2 + article.len();
        if self.pending_count > 0
            && (HEADER_LEN + self.pending.len() + needed > self.max_dtf_len
                || self.pending_count >= MAX_ARTICLES_PER_DTF)
        {
            self.flush_into(&mut out);
        }
        self.pending
            .extend_from_slice(&(article.len() as u16).to_be_bytes());
        self.pending.extend_from_slice(article);
        self.pending_count += 1;
        out
    }

    /// Flush the pending multi-article DTF, if any.
    #[must_use]
    pub fn flush(&mut self) -> Option<Fpdu> {
        let mut v = Vec::new();
        self.flush_into(&mut v);
        v.pop()
    }

    fn flush_into(&mut self, out: &mut Vec<Fpdu>) {
        if self.pending_count == 0 {
            return;
        }
        let data = std::mem::take(&mut self.pending);
        let fpdu = if self.pending_count == 1 {
            // a single article is sent as a mono-article DTF (no length prefix)
            Fpdu::data(FpduKind::Dtf, self.id_dst, 0, data[2..].to_vec())
        } else {
            Fpdu::data(FpduKind::Dtf, self.id_dst, self.pending_count as u8, data)
        };
        self.pending_count = 0;
        out.push(fpdu);
    }

    /// Whether articles are pending.
    #[must_use]
    pub const fn has_pending(&self) -> bool {
        self.pending_count > 0
    }
}

/// Extract the articles carried by a data FPDU.
///
/// For a multi-article DTF (`id_src > 0`) the two-byte length prefixes are decoded; otherwise the
/// whole content is one article (or a fragment for DTFDA/DTFMA/DTFFA).
pub fn articles_of(fpdu: &Fpdu) -> Result<Vec<&[u8]>, crate::fpdu::DecodeError> {
    if fpdu.kind == FpduKind::Dtf && fpdu.id_src > 0 {
        let mut out = Vec::with_capacity(usize::from(fpdu.id_src));
        let mut pos = 0;
        let data = &fpdu.data;
        while pos < data.len() {
            let Some(l) = data.get(pos..pos + 2) else {
                return Err(bad_multi("truncated article length"));
            };
            let len = usize::from(u16::from_be_bytes([l[0], l[1]]));
            let start = pos + 2;
            let Some(a) = data.get(start..start + len) else {
                return Err(bad_multi("article length exceeds the FPDU"));
            };
            out.push(a);
            pos = start + len;
        }
        if out.len() != usize::from(fpdu.id_src) {
            return Err(bad_multi(format!(
                "{} articles announced, {} found",
                fpdu.id_src,
                out.len()
            )));
        }
        Ok(out)
    } else {
        Ok(vec![fpdu.data.as_slice()])
    }
}

fn bad_multi(detail: impl Into<String>) -> crate::fpdu::DecodeError {
    crate::fpdu::DecodeError {
        diag: crate::Diagnostic::REMOTE_PROTOCOL_ERROR,
        detail: detail.into(),
    }
}

/// Reassembles segmented articles (DTFDA + DTFMA* + DTFFA) on reception.
#[derive(Debug, Default)]
pub struct Reassembler {
    partial: Option<Vec<u8>>,
    max_len: usize,
}

/// Error while reassembling a segmented article.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReassemblyError {
    /// DTFMA/DTFFA received without a preceding DTFDA.
    #[error("{0} received without a DTFDA")]
    NoStart(FpduKind),
    /// DTF/DTFDA received while an article was being reassembled.
    #[error("{0} received while an article is being reassembled")]
    Interleaved(FpduKind),
    /// The reassembled article exceeds the announced article length.
    #[error("segmented article exceeds {0} bytes")]
    TooLong(usize),
}

impl Reassembler {
    /// New reassembler; `max_len` = 0 for no limit.
    #[must_use]
    pub fn new(max_len: usize) -> Self {
        Self {
            partial: None,
            max_len,
        }
    }

    /// Whether a segmented article is being reassembled.
    #[must_use]
    pub const fn in_progress(&self) -> bool {
        self.partial.is_some()
    }

    /// Feed a data FPDU; returns the complete articles it yields.
    pub fn feed(&mut self, fpdu: &Fpdu) -> Result<Vec<Vec<u8>>, ReassemblyError> {
        match fpdu.kind {
            FpduKind::Dtf => {
                if self.partial.is_some() {
                    return Err(ReassemblyError::Interleaved(fpdu.kind));
                }
                Ok(articles_of(fpdu)
                    .map_err(|_| ReassemblyError::Interleaved(fpdu.kind))?
                    .into_iter()
                    .map(<[u8]>::to_vec)
                    .collect())
            }
            FpduKind::DtfDa => {
                if self.partial.is_some() {
                    return Err(ReassemblyError::Interleaved(fpdu.kind));
                }
                self.check(fpdu.data.len())?;
                self.partial = Some(fpdu.data.clone());
                Ok(Vec::new())
            }
            FpduKind::DtfMa | FpduKind::DtfFa => {
                let Some(mut p) = self.partial.take() else {
                    return Err(ReassemblyError::NoStart(fpdu.kind));
                };
                self.check(p.len() + fpdu.data.len())?;
                p.extend_from_slice(&fpdu.data);
                if fpdu.kind == FpduKind::DtfMa {
                    self.partial = Some(p);
                    Ok(Vec::new())
                } else {
                    Ok(vec![p])
                }
            }
            _ => Ok(Vec::new()),
        }
    }

    fn check(&self, len: usize) -> Result<(), ReassemblyError> {
        if self.max_len > 0 && len > self.max_len {
            Err(ReassemblyError::TooLong(self.max_len))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cut_binary() {
        let mut c = ArticleCutter::new(RecordFormat::Bu, 4);
        c.push(b"abcdefghij");
        assert_eq!(c.next_article().unwrap_or_default(), Some(b"abcd".to_vec()));
        assert_eq!(c.next_article().unwrap_or_default(), Some(b"efgh".to_vec()));
        assert_eq!(c.next_article().unwrap_or_default(), None);
        assert_eq!(c.finish().unwrap_or_default(), Some(b"ij".to_vec()));
        let mut f = ArticleCutter::new(RecordFormat::Bf, 4);
        f.push(b"abcdef");
        assert_eq!(f.next_article().unwrap_or_default(), Some(b"abcd".to_vec()));
        assert_eq!(f.finish(), Err(RecordError::UnfilledRecord(2, 4)));
    }

    #[test]
    fn cut_text() {
        let mut c = ArticleCutter::new(RecordFormat::Tv, 10);
        c.push(b"hello\r\nworld\n\nlast");
        assert_eq!(
            c.next_article().unwrap_or_default(),
            Some(b"hello".to_vec())
        );
        assert_eq!(
            c.next_article().unwrap_or_default(),
            Some(b"world".to_vec())
        );
        assert_eq!(c.next_article().unwrap_or_default(), Some(b" ".to_vec()));
        assert_eq!(c.next_article().unwrap_or_default(), None);
        assert_eq!(c.finish().unwrap_or_default(), Some(b"last".to_vec()));
        let mut f = ArticleCutter::new(RecordFormat::Tf, 6);
        f.push(b"ab\ntoolongline\n");
        assert_eq!(
            f.next_article().unwrap_or_default(),
            Some(b"ab    ".to_vec())
        );
        assert_eq!(f.next_article(), Err(RecordError::LineTooLong(11, 6)));
        assert_eq!(
            article_to_bytes(RecordFormat::Tf, b"ab    "),
            b"ab\n".to_vec()
        );
        assert_eq!(article_to_bytes(RecordFormat::Tv, b"ab"), b"ab\n".to_vec());
        assert_eq!(article_to_bytes(RecordFormat::Bu, b"ab"), b"ab".to_vec());
    }

    #[test]
    fn pack_multi_article() {
        let mut p = ArticlePacker::new(9, 6 + 20, true);
        assert!(p.push(b"12345").is_empty()); // 7 bytes pending
        assert!(p.push(b"67890").is_empty()); // 14
        let out = p.push(b"abcdefg"); // 9 more would exceed 20 -> flush
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, FpduKind::Dtf);
        assert_eq!(out[0].id_src, 2);
        assert_eq!(
            articles_of(&out[0]).unwrap_or_default(),
            vec![&b"12345"[..], &b"67890"[..]]
        );
        let f = p.flush().map(|f| (f.id_src, f.data));
        assert_eq!(f, Some((0, b"abcdefg".to_vec())));
        assert!(p.flush().is_none());
    }

    #[test]
    fn segmentation() {
        let mut p = ArticlePacker::new(9, 6 + 4, true);
        assert!(p.push(b"ab").is_empty());
        let out = p.push(b"0123456789");
        let kinds: Vec<_> = out.iter().map(|f| f.kind).collect();
        assert_eq!(
            kinds,
            vec![
                FpduKind::Dtf,
                FpduKind::DtfDa,
                FpduKind::DtfMa,
                FpduKind::DtfFa
            ]
        );
        let mut r = Reassembler::new(0);
        let mut got = Vec::new();
        for f in &out {
            got.extend(r.feed(f).unwrap_or_default());
        }
        assert_eq!(got, vec![b"ab".to_vec(), b"0123456789".to_vec()]);
        assert_eq!(
            r.feed(&Fpdu::data(FpduKind::DtfFa, 9, 0, vec![1])),
            Err(ReassemblyError::NoStart(FpduKind::DtfFa))
        );
    }

    #[test]
    fn bad_multi_article() {
        let f = Fpdu::data(FpduKind::Dtf, 1, 2, vec![0, 1, b'a']);
        assert!(articles_of(&f).is_err());
    }
}
