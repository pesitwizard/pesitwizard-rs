//! Synchronisation point bookkeeping used for resynchronisation and restarts.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

/// Position of a synchronisation point in a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Checkpoint {
    /// Synchronisation point number (0 = beginning of the file).
    pub sync: u32,
    /// Offset in the physical file.
    pub file_offset: u64,
    /// Data bytes transmitted so far (PI 27 semantics).
    pub data_bytes: u64,
    /// Articles transmitted so far.
    pub articles: u64,
}

/// Storage of the checkpoints of one transfer.
pub trait CheckpointStore: Send {
    /// Record a checkpoint.
    fn record(&mut self, cp: Checkpoint) -> io::Result<()>;
    /// Look a checkpoint up by synchronisation point number (0 returns the default checkpoint).
    fn get(&self, sync: u32) -> Option<Checkpoint>;
    /// Last recorded checkpoint.
    fn last(&self) -> Option<Checkpoint>;
    /// Last checkpoint acknowledged by the peer (sender side).
    fn last_acknowledged(&self) -> Option<Checkpoint>;
    /// Mark checkpoints up to `sync` as acknowledged.
    fn acknowledge(&mut self, sync: u32) -> io::Result<()>;
    /// Forget everything (transfer completed).
    fn clear(&mut self) -> io::Result<()>;
}

/// In-memory checkpoint store.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct MemoryCheckpoints {
    points: BTreeMap<u32, Checkpoint>,
    acknowledged: u32,
}

impl MemoryCheckpoints {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// All recorded checkpoints in order.
    #[must_use]
    pub fn all(&self) -> Vec<Checkpoint> {
        self.points.values().copied().collect()
    }
}

impl CheckpointStore for MemoryCheckpoints {
    fn record(&mut self, cp: Checkpoint) -> io::Result<()> {
        self.points.insert(cp.sync, cp);
        Ok(())
    }

    fn get(&self, sync: u32) -> Option<Checkpoint> {
        if sync == 0 {
            return Some(Checkpoint::default());
        }
        self.points.get(&sync).copied()
    }

    fn last(&self) -> Option<Checkpoint> {
        self.points.values().next_back().copied()
    }

    fn last_acknowledged(&self) -> Option<Checkpoint> {
        if self.acknowledged == 0 {
            return None;
        }
        self.points.get(&self.acknowledged).copied()
    }

    fn acknowledge(&mut self, sync: u32) -> io::Result<()> {
        self.acknowledged = self.acknowledged.max(sync);
        // checkpoints before the acknowledged one are no longer needed
        let keep: BTreeMap<_, _> = self
            .points
            .range(self.acknowledged..)
            .map(|(k, v)| (*k, *v))
            .collect();
        self.points = keep;
        Ok(())
    }

    fn clear(&mut self) -> io::Result<()> {
        self.points.clear();
        self.acknowledged = 0;
        Ok(())
    }
}

/// Checkpoint store persisted as a JSON file (one file per transfer key).
#[derive(Debug)]
pub struct FileCheckpoints {
    path: PathBuf,
    mem: MemoryCheckpoints,
}

impl FileCheckpoints {
    /// Open (or create) the store at `path`.
    pub fn open(path: PathBuf) -> io::Result<Self> {
        let mem = match std::fs::read(&path) {
            Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => MemoryCheckpoints::default(),
            Err(e) => return Err(e),
        };
        Ok(Self { path, mem })
    }

    fn save(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec(&self.mem).map_err(io::Error::other)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, &self.path)
    }

    /// Path of the store.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl CheckpointStore for FileCheckpoints {
    fn record(&mut self, cp: Checkpoint) -> io::Result<()> {
        self.mem.record(cp)?;
        self.save()
    }

    fn get(&self, sync: u32) -> Option<Checkpoint> {
        self.mem.get(sync)
    }

    fn last(&self) -> Option<Checkpoint> {
        self.mem.last()
    }

    fn last_acknowledged(&self) -> Option<Checkpoint> {
        self.mem.last_acknowledged()
    }

    fn acknowledge(&mut self, sync: u32) -> io::Result<()> {
        self.mem.acknowledge(sync)?;
        self.save()
    }

    fn clear(&mut self) -> io::Result<()> {
        self.mem.clear()?;
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store() {
        let mut s = MemoryCheckpoints::new();
        for i in 1..=3 {
            s.record(Checkpoint {
                sync: i,
                file_offset: u64::from(i) * 100,
                data_bytes: u64::from(i) * 100,
                articles: u64::from(i),
            })
            .unwrap_or_default();
        }
        assert_eq!(s.get(0), Some(Checkpoint::default()));
        assert_eq!(s.get(2).map(|c| c.file_offset), Some(200));
        assert_eq!(s.last().map(|c| c.sync), Some(3));
        assert_eq!(s.last_acknowledged(), None);
        s.acknowledge(2).unwrap_or_default();
        assert_eq!(s.last_acknowledged().map(|c| c.sync), Some(2));
        assert_eq!(s.get(1), None);
        assert_eq!(s.get(3).map(|c| c.sync), Some(3));
    }

    #[test]
    fn file_store() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("cp").join("t1.json");
        let mut s = FileCheckpoints::open(path.clone()).unwrap_or_else(|e| panic!("{e}"));
        s.record(Checkpoint {
            sync: 1,
            file_offset: 5,
            data_bytes: 5,
            articles: 1,
        })
        .unwrap_or_default();
        let s2 = FileCheckpoints::open(path.clone()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s2.last().map(|c| c.file_offset), Some(5));
        s.clear().unwrap_or_default();
        assert!(!path.exists());
    }
}
