//! Article sources and sinks.
//!
//! The engines consume articles from an [`ArticleSource`] when sending and push them into an
//! [`ArticleSink`] when receiving. Positions are expressed as [`Position`] so that
//! resynchronisation and restarts can rewind or truncate the underlying file.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use pesit_core::article::{article_to_bytes, ArticleCutter, RecordFormat};

/// Position in a source or sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Position {
    /// Offset in the physical file.
    pub file_offset: u64,
    /// Article data bytes produced/consumed so far.
    pub data_bytes: u64,
    /// Articles produced/consumed so far.
    pub articles: u64,
}

/// Producer of articles (sending side).
pub trait ArticleSource: Send {
    /// Next article, or `None` at end of file.
    fn next_article(&mut self) -> io::Result<Option<Vec<u8>>>;
    /// Current position (after the last article returned).
    fn position(&self) -> Position;
    /// Rewind so that the next article is the one following `pos`.
    fn rewind(&mut self, pos: Position) -> io::Result<()>;
    /// Total size of the underlying data in bytes, if known.
    fn size_hint(&self) -> Option<u64>;
}

/// Consumer of articles (receiving side).
pub trait ArticleSink: Send {
    /// Store one article.
    fn write_article(&mut self, article: &[u8]) -> io::Result<()>;
    /// Flush everything to stable storage and return the current position.
    fn checkpoint(&mut self) -> io::Result<Position>;
    /// Discard everything after `pos`.
    fn truncate(&mut self, pos: Position) -> io::Result<()>;
    /// Current position.
    fn position(&self) -> Position;
    /// Complete the sink (flush, close, rename temporary files...).
    fn finish(&mut self) -> io::Result<()>;
}

/// File-backed article source.
pub struct FileSource {
    reader: BufReader<File>,
    format: RecordFormat,
    record_len: usize,
    cutter: ArticleCutter,
    pos: Position,
    file_pos: u64,
    eof: bool,
    size: u64,
}

impl FileSource {
    /// Open a file and cut it according to `format` / `record_len`.
    pub fn open(path: &Path, format: RecordFormat, record_len: usize) -> io::Result<Self> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            reader: BufReader::with_capacity(1 << 16, file),
            format,
            record_len,
            cutter: ArticleCutter::new(format, record_len),
            pos: Position::default(),
            file_pos: 0,
            eof: false,
            size,
        })
    }

    fn fill(&mut self) -> io::Result<bool> {
        let buf = self.reader.fill_buf()?;
        if buf.is_empty() {
            self.eof = true;
            return Ok(false);
        }
        let n = buf.len();
        self.cutter.push(buf);
        self.reader.consume(n);
        self.file_pos += n as u64;
        Ok(true)
    }
}

impl ArticleSource for FileSource {
    fn next_article(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(a) = self
                .cutter
                .next_article()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            {
                self.pos.articles += 1;
                self.pos.data_bytes += a.len() as u64;
                self.pos.file_offset = self.file_pos - self.cutter.buffered() as u64;
                return Ok(Some(a));
            }
            if self.eof {
                let last = self
                    .cutter
                    .finish()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                if let Some(a) = &last {
                    self.pos.articles += 1;
                    self.pos.data_bytes += a.len() as u64;
                    self.pos.file_offset = self.file_pos;
                }
                return Ok(last);
            }
            self.fill()?;
        }
    }

    fn position(&self) -> Position {
        self.pos
    }

    fn rewind(&mut self, pos: Position) -> io::Result<()> {
        self.reader.seek(SeekFrom::Start(pos.file_offset))?;
        self.cutter = ArticleCutter::new(self.format, self.record_len);
        self.file_pos = pos.file_offset;
        self.pos = pos;
        self.eof = false;
        Ok(())
    }

    fn size_hint(&self) -> Option<u64> {
        Some(self.size)
    }
}

/// File-backed article sink writing to a temporary name, renamed on completion.
pub struct FileSink {
    final_path: PathBuf,
    tmp_path: PathBuf,
    writer: BufWriter<File>,
    format: RecordFormat,
    pos: Position,
    finished: bool,
}

impl FileSink {
    /// Create the sink. Data is written to `<path>.part` and renamed to `path` by `finish`.
    /// When `resume_from` is given the existing partial file is kept and truncated to it.
    pub fn create(
        path: &Path,
        format: RecordFormat,
        resume_from: Option<Position>,
    ) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let tmp_path = part_path(path);
        let mut opts = OpenOptions::new();
        opts.write(true).create(true);
        let pos = if let Some(p) = resume_from {
            let f = opts.open(&tmp_path)?;
            f.set_len(p.file_offset)?;
            p
        } else {
            opts.truncate(true);
            Position::default()
        };
        let mut file = opts.open(&tmp_path)?;
        file.seek(SeekFrom::Start(pos.file_offset))?;
        Ok(Self {
            final_path: path.to_owned(),
            tmp_path,
            writer: BufWriter::with_capacity(1 << 16, file),
            format,
            pos,
            finished: false,
        })
    }

    /// Final path of the file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.final_path
    }

    /// Remove the partial file (transfer failed and will not be restarted).
    pub fn discard(self) -> io::Result<()> {
        drop(self.writer);
        match std::fs::remove_file(&self.tmp_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Name of the temporary file used while receiving `path`.
#[must_use]
pub fn part_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".part");
    path.with_file_name(name)
}

impl ArticleSink for FileSink {
    fn write_article(&mut self, article: &[u8]) -> io::Result<()> {
        let bytes = article_to_bytes(self.format, article);
        self.writer.write_all(&bytes)?;
        self.pos.file_offset += bytes.len() as u64;
        self.pos.data_bytes += article.len() as u64;
        self.pos.articles += 1;
        Ok(())
    }

    fn checkpoint(&mut self) -> io::Result<Position> {
        self.writer.flush()?;
        self.writer.get_ref().sync_data()?;
        Ok(self.pos)
    }

    fn truncate(&mut self, pos: Position) -> io::Result<()> {
        self.writer.flush()?;
        let f = self.writer.get_mut();
        f.set_len(pos.file_offset)?;
        f.seek(SeekFrom::Start(pos.file_offset))?;
        self.pos = pos;
        Ok(())
    }

    fn position(&self) -> Position {
        self.pos
    }

    fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        std::fs::rename(&self.tmp_path, &self.final_path)?;
        self.finished = true;
        Ok(())
    }
}

/// In-memory article source (tests, messages).
#[derive(Debug, Default)]
pub struct VecSource {
    articles: Vec<Vec<u8>>,
    index: usize,
    pos: Position,
}

impl VecSource {
    /// Source yielding the given articles.
    #[must_use]
    pub fn new(articles: Vec<Vec<u8>>) -> Self {
        Self {
            articles,
            index: 0,
            pos: Position::default(),
        }
    }

    /// Source cutting `data` into articles of `record_len` bytes.
    #[must_use]
    pub fn from_bytes(data: &[u8], record_len: usize) -> Self {
        Self::new(data.chunks(record_len.max(1)).map(<[u8]>::to_vec).collect())
    }
}

impl ArticleSource for VecSource {
    fn next_article(&mut self) -> io::Result<Option<Vec<u8>>> {
        let Some(a) = self.articles.get(self.index) else {
            return Ok(None);
        };
        self.index += 1;
        self.pos.articles += 1;
        self.pos.data_bytes += a.len() as u64;
        self.pos.file_offset = self.pos.data_bytes;
        Ok(Some(a.clone()))
    }

    fn position(&self) -> Position {
        self.pos
    }

    fn rewind(&mut self, pos: Position) -> io::Result<()> {
        self.index = pos.articles as usize;
        self.pos = pos;
        Ok(())
    }

    fn size_hint(&self) -> Option<u64> {
        Some(self.articles.iter().map(|a| a.len() as u64).sum())
    }
}

/// In-memory article sink.
#[derive(Debug, Default)]
pub struct VecSink {
    /// Received articles.
    pub articles: Vec<Vec<u8>>,
    pos: Position,
    /// Whether `finish` was called.
    pub finished: bool,
}

impl VecSink {
    /// Empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Concatenation of all received articles.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        self.articles.concat()
    }
}

impl ArticleSink for VecSink {
    fn write_article(&mut self, article: &[u8]) -> io::Result<()> {
        self.articles.push(article.to_vec());
        self.pos.articles += 1;
        self.pos.data_bytes += article.len() as u64;
        self.pos.file_offset = self.pos.data_bytes;
        Ok(())
    }

    fn checkpoint(&mut self) -> io::Result<Position> {
        Ok(self.pos)
    }

    fn truncate(&mut self, pos: Position) -> io::Result<()> {
        self.articles.truncate(pos.articles as usize);
        self.pos = pos;
        Ok(())
    }

    fn position(&self) -> Position {
        self.pos
    }

    fn finish(&mut self) -> io::Result<()> {
        self.finished = true;
        Ok(())
    }
}

/// Read a whole file into memory (helper for small files/messages).
pub fn read_all(path: &Path) -> io::Result<Vec<u8>> {
    let mut v = Vec::new();
    File::open(path)?.read_to_end(&mut v)?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_source_and_sink_round_trip() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let src = dir.path().join("in.txt");
        std::fs::write(&src, b"line one\nline two\n\nlast").unwrap_or_default();
        let mut s = FileSource::open(&src, RecordFormat::Tv, 80).unwrap_or_else(|e| panic!("{e}"));
        let mut articles = Vec::new();
        while let Some(a) = s.next_article().unwrap_or_default() {
            articles.push(a);
        }
        assert_eq!(
            articles,
            vec![
                b"line one".to_vec(),
                b"line two".to_vec(),
                b" ".to_vec(),
                b"last".to_vec()
            ]
        );
        assert_eq!(s.position().articles, 4);
        // rewind to after the first article and re-read
        s.rewind(Position {
            file_offset: 9,
            data_bytes: 8,
            articles: 1,
        })
        .unwrap_or_default();
        assert_eq!(
            s.next_article().unwrap_or_default(),
            Some(b"line two".to_vec())
        );

        let dst = dir.path().join("out.txt");
        let mut k =
            FileSink::create(&dst, RecordFormat::Tv, None).unwrap_or_else(|e| panic!("{e}"));
        k.write_article(b"line one").unwrap_or_default();
        let cp = k.checkpoint().unwrap_or_default();
        k.write_article(b"garbage").unwrap_or_default();
        k.truncate(cp).unwrap_or_default();
        k.write_article(b"line two").unwrap_or_default();
        k.finish().unwrap_or_default();
        assert_eq!(
            std::fs::read(&dst).unwrap_or_default(),
            b"line one\nline two\n"
        );
        assert!(!part_path(&dst).exists());
    }

    #[test]
    fn binary_source_positions() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let src = dir.path().join("in.bin");
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        std::fs::write(&src, &data).unwrap_or_default();
        let mut s = FileSource::open(&src, RecordFormat::Bu, 300).unwrap_or_else(|e| panic!("{e}"));
        let a = s.next_article().unwrap_or_default().unwrap_or_default();
        assert_eq!(a.len(), 300);
        assert_eq!(
            s.position(),
            Position {
                file_offset: 300,
                data_bytes: 300,
                articles: 1
            }
        );
        let _ = s.next_article();
        let _ = s.next_article();
        let last = s.next_article().unwrap_or_default().unwrap_or_default();
        assert_eq!(last.len(), 100);
        assert_eq!(s.next_article().unwrap_or_default(), None);
        s.rewind(Position {
            file_offset: 300,
            data_bytes: 300,
            articles: 1,
        })
        .unwrap_or_default();
        assert_eq!(
            s.next_article().unwrap_or_default().map(|a| a[0]),
            Some(data[300])
        );
        assert_eq!(s.size_hint(), Some(1000));
    }
}
