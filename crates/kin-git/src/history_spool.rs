// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Private temporary storage for ordered import changes, verified on every read.

use std::collections::BTreeMap;
use std::io::Write;
#[cfg(test)]
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;

use kin_model::{ChangeOrigin, GitObjectId, SemanticChange, SemanticChangeId};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::error::{GitError, Result};

/// Names a spool on disk for whoever finds one a kill left behind.
///
/// `NamedTempFile` unlinks on drop and a `SIGKILL` runs no destructor, so the
/// file this prefix names is exactly what an out-of-memory kill strands. The
/// kill this whole spool exists to prevent is the one that strands it, so the
/// name has to be legible without a process to ask.
const SPOOL_PREFIX: &str = ".kin-history-spool-";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    offset: u64,
    len: u64,
    digest: [u8; 32],
    id: SemanticChangeId,
    oid: GitObjectId,
}

#[derive(Debug)]
struct Storage {
    file: NamedTempFile,
    records: Vec<Record>,
    by_id: BTreeMap<SemanticChangeId, usize>,
    by_oid: BTreeMap<GitObjectId, usize>,
    bytes: u64,
}

/// Immutable, cloneable history. Only record indexes remain resident in memory.
#[derive(Debug, Clone)]
pub struct SemanticChangeSpool(Arc<Storage>);

impl PartialEq for SemanticChangeSpool {
    fn eq(&self, other: &Self) -> bool {
        self.0.records == other.0.records
            && self
                .iter()
                .zip(other.iter())
                .all(|(a, b)| matches!((a, b), (Ok(a), Ok(b)) if a == b))
    }
}

impl SemanticChangeSpool {
    pub fn len(&self) -> usize {
        self.0.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.records.is_empty()
    }
    pub fn ids(&self) -> impl ExactSizeIterator<Item = SemanticChangeId> + '_ {
        self.0.records.iter().map(|record| record.id)
    }
    pub fn iter(&self) -> impl ExactSizeIterator<Item = Result<SemanticChange>> + '_ {
        (0..self.len()).map(|index| {
            self.read_at(index)?
                .ok_or_else(|| invalid("missing indexed record"))
        })
    }
    pub fn read_by_id(&self, id: &SemanticChangeId) -> Result<Option<SemanticChange>> {
        self.0
            .by_id
            .get(id)
            .map_or(Ok(None), |index| self.read_at(*index))
    }
    pub fn read_by_oid(&self, oid: &GitObjectId) -> Result<Option<SemanticChange>> {
        self.0
            .by_oid
            .get(oid)
            .map_or(Ok(None), |index| self.read_at(*index))
    }
    pub fn read_at(&self, index: usize) -> Result<Option<SemanticChange>> {
        let Some(record) = self.0.records.get(index) else {
            return Ok(None);
        };
        let path = self.0.file.path();
        // Keep pathname disappearance and replacement observable even though
        // positioned reads use the original held file on Unix.
        let metadata = std::fs::metadata(path).map_err(|error| GitError::io(path, error))?;
        if metadata.len() != self.0.bytes {
            return Err(invalid("history spool length changed"));
        }
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::MetadataExt;
            let held = self
                .0
                .file
                .as_file()
                .metadata()
                .map_err(|error| GitError::io(path, error))?;
            if (metadata.dev(), metadata.ino()) != (held.dev(), held.ino()) {
                return Err(invalid("history spool file replaced"));
            }
            self.0.file.as_file()
        };
        #[cfg(windows)]
        let reopened = self
            .0
            .file
            .reopen()
            .map_err(|error| GitError::io(path, error))?;
        #[cfg(windows)]
        let file = &reopened;
        let len = usize::try_from(record.len)
            .map_err(|_| invalid("record length exceeds address space"))?;
        let mut bytes = vec![0; len];
        read_at_offset(file, &mut bytes, record.offset)
            .map_err(|error| GitError::io(path, error))?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if digest != record.digest {
            return Err(invalid("history spool checksum mismatch"));
        }
        let change: SemanticChange =
            serde_json::from_slice(&bytes).map_err(|error| invalid(&error.to_string()))?;
        if change.id != record.id || change.origin != (ChangeOrigin::GitCommit { oid: record.oid })
        {
            return Err(invalid("history spool identity mismatch"));
        }
        Ok(Some(change))
    }
    /// Explicit compatibility adapter for callers which already own a history.
    ///
    /// `directory` is where the spool file is written, and it carries the same
    /// requirement [`SemanticChangeSpoolWriter::new_in`] states.
    pub fn from_changes(
        directory: &Path,
        changes: impl IntoIterator<Item = SemanticChange>,
    ) -> Result<Self> {
        let mut writer = SemanticChangeSpoolWriter::new_in(directory)?;
        for change in changes {
            writer.append(change)?;
        }
        writer.finish()
    }
}

/// Read one record without sharing a seek cursor between concurrent readers.
#[cfg(unix)]
fn read_at_offset(file: &std::fs::File, buffer: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buffer, offset)
}

#[cfg(windows)]
fn read_at_offset(file: &std::fs::File, buffer: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut filled = 0usize;
    while filled < buffer.len() {
        let read = match file.seek_read(&mut buffer[filled..], offset + filled as u64) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "history spool record ended before its recorded length",
            ));
        }
        filled += read;
    }
    Ok(())
}

pub(crate) struct SemanticChangeSpoolWriter(Storage);

impl SemanticChangeSpoolWriter {
    /// Spool into `directory`, which the caller chooses and owns.
    ///
    /// Deliberately not `std::env::temp_dir()`. This spool exists to keep a
    /// history off the heap, and on a host where `/tmp` is tmpfs, which is the
    /// default on most Linux distributions and inside most containers, writing
    /// it there puts every byte back in RAM and undoes the change. The caller
    /// knows which filesystem it is converting on; this constructor does not,
    /// and guessing is what makes the defect invisible. The bodies are also the
    /// size of the history being imported, so a small `/tmp` is a second way to
    /// fail on a conversion that would otherwise succeed.
    ///
    /// Every caller inside this crate passes its blob store's root, which for
    /// a `kin init` conversion is the per-init `.kin-git-capture-<uuid>`
    /// staging directory beside the source repository. That puts the spool on
    /// the repository's own filesystem and inside the one tree the next init's
    /// reap and `kin doctor --reclaim-staging` already scan by name, so a
    /// conversion the kernel kills strands nothing invisible.
    ///
    /// A blob store's root is safe to write into: it addresses content under
    /// two-hex-character shard directories and documents that every other
    /// top-level entry is ignored, by enumeration and by compaction alike.
    pub(crate) fn new_in(directory: &Path) -> Result<Self> {
        Ok(Self(Storage {
            file: tempfile::Builder::new()
                .prefix(SPOOL_PREFIX)
                .tempfile_in(directory)
                .map_err(|error| GitError::io(directory, error))?,
            records: Vec::new(),
            by_id: BTreeMap::new(),
            by_oid: BTreeMap::new(),
            bytes: 0,
        }))
    }
    pub(crate) fn len(&self) -> usize {
        self.0.records.len()
    }
    pub(crate) fn append(&mut self, change: SemanticChange) -> Result<()> {
        let ChangeOrigin::GitCommit { oid } = change.origin else {
            return Err(invalid("native origin in imported history"));
        };
        if self.0.by_id.contains_key(&change.id) || self.0.by_oid.contains_key(&oid) {
            return Err(invalid("duplicate identity in imported history"));
        }
        let bytes = serde_json::to_vec(&change).map_err(|error| invalid(&error.to_string()))?;
        let len = u64::try_from(bytes.len()).map_err(|_| invalid("record length overflow"))?;
        let end = self
            .0
            .bytes
            .checked_add(len)
            .ok_or_else(|| invalid("history length overflow"))?;
        self.0
            .file
            .write_all(&bytes)
            .map_err(|error| GitError::io(self.0.file.path(), error))?;
        let index = self.0.records.len();
        self.0.records.push(Record {
            offset: self.0.bytes,
            len,
            digest: Sha256::digest(&bytes).into(),
            id: change.id,
            oid,
        });
        self.0.by_id.insert(change.id, index);
        self.0.by_oid.insert(oid, index);
        self.0.bytes = end;
        Ok(())
    }
    pub(crate) fn finish(mut self) -> Result<SemanticChangeSpool> {
        self.0
            .file
            .flush()
            .map_err(|error| GitError::io(self.0.file.path(), error))?;
        Ok(SemanticChangeSpool(Arc::new(self.0)))
    }
}

fn invalid(message: &str) -> GitError {
    GitError::InvalidSnapshot(message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{AuthorId, Hash256, Timestamp};

    /// One spool directory for this module's cases, alive for the whole binary.
    ///
    /// A `TempDir` bound to the call would be removed the moment the statement
    /// ended, and `read_at` stats the spool by path on every call, so every
    /// later read would fail on a directory that is no longer there.
    fn spool_dir() -> &'static Path {
        static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        DIR.get_or_init(|| tempfile::tempdir().unwrap()).path()
    }

    fn change(seed: u8) -> SemanticChange {
        SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([seed; 32])),
            origin: ChangeOrigin::GitCommit {
                oid: GitObjectId::sha1([seed; 20]),
            },
            parents: Vec::new(),
            timestamp: Timestamp::from(chrono::DateTime::from_timestamp(0, 0).unwrap()),
            author: AuthorId::new("spool-test"),
            message: seed.to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            external_reference_deltas: Vec::new(),
        }
    }

    /// The spool goes where the caller said, and says so on disk.
    ///
    /// The default `std::env::temp_dir()` this replaced was two defects at
    /// once. On a host where `/tmp` is tmpfs, spooling a history there puts it
    /// straight back in RAM, which is the exact cost this spool exists to
    /// avoid, and it is invisible: every test passes and the conversion simply
    /// runs out of memory on the machine it was meant to fit. And a
    /// `NamedTempFile` unlinks on drop, which `SIGKILL` never runs, so an
    /// out-of-memory kill strands a history-sized file under a name
    /// `kin doctor --reclaim-staging` does not scan for.
    ///
    /// Breaking it: put `NamedTempFile::new()` back in `new_in` and this fails
    /// on an empty directory.
    #[test]
    fn a_spool_is_written_where_its_caller_put_it_and_is_named_for_a_reader() {
        let directory = tempfile::tempdir().unwrap();
        let spool = SemanticChangeSpool::from_changes(directory.path(), [change(1)]).unwrap();

        let names = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            names.len(),
            1,
            "the spool must be the one thing in the directory it was given: {names:?}"
        );
        assert!(
            names[0].starts_with(SPOOL_PREFIX),
            "a stranded spool has to be identifiable by name alone: {}",
            names[0]
        );
        // Named where the caller put it AND still readable from there, so this
        // cannot pass on a file the spool no longer uses.
        assert_eq!(spool.read_at(0).unwrap(), Some(change(1)));
    }

    #[test]
    fn spool_preserves_owned_records_order_and_indexes() {
        let records = vec![change(1), change(2)];
        let spool = SemanticChangeSpool::from_changes(spool_dir(), records.clone()).unwrap();
        assert_eq!(spool.iter().collect::<Result<Vec<_>>>().unwrap(), records);
        assert_eq!(
            spool.ids().collect::<Vec<_>>(),
            records.iter().map(|c| c.id).collect::<Vec<_>>()
        );
        assert_eq!(
            spool.read_by_id(&records[1].id).unwrap(),
            Some(records[1].clone())
        );
        assert_eq!(
            spool.read_by_oid(&GitObjectId::sha1([1; 20])).unwrap(),
            Some(records[0].clone())
        );
        assert_eq!(spool.read_at(2).unwrap(), None);
        assert_eq!(spool.read_by_id(&change(3).id).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn spool_refuses_same_length_path_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let spool = SemanticChangeSpool::from_changes(directory.path(), [change(1)]).unwrap();
        assert_eq!(spool.read_at(0).unwrap(), Some(change(1)));
        let path = spool.0.file.path();
        let replacement = directory.path().join("replacement");
        std::fs::copy(path, &replacement).unwrap();
        std::fs::rename(replacement, path).unwrap();
        assert_eq!(std::fs::metadata(path).unwrap().len(), spool.0.bytes);
        assert!(
            spool.read_at(0).is_err(),
            "a replacement cannot authenticate the held file"
        );
    }

    #[test]
    fn spool_clones_read_independent_offsets_concurrently() {
        let records = (1..=16).map(change).collect::<Vec<_>>();
        let spool = SemanticChangeSpool::from_changes(spool_dir(), records.clone()).unwrap();
        std::thread::scope(|scope| {
            for worker in 0..4 {
                let spool = spool.clone();
                let records = &records;
                scope.spawn(move || {
                    for round in 0..64 {
                        let index = (round * 7 + worker) % records.len();
                        assert_eq!(
                            spool.read_at(index).unwrap().as_ref(),
                            Some(&records[index])
                        );
                    }
                });
            }
        });
    }

    #[test]
    fn spool_refuses_duplicate_ids_and_duplicate_oids() {
        assert!(SemanticChangeSpool::from_changes(spool_dir(), [change(1), change(1)]).is_err());
        let mut duplicate_oid = change(2);
        duplicate_oid.origin = change(1).origin;
        assert!(
            SemanticChangeSpool::from_changes(spool_dir(), [change(1), duplicate_oid]).is_err()
        );
    }

    #[test]
    fn spool_refuses_valid_same_length_message_tampering() {
        let original = change(1);
        let spool = SemanticChangeSpool::from_changes(spool_dir(), [original.clone()]).unwrap();
        assert_eq!(spool.read_at(0).unwrap(), Some(original.clone()));
        let mut tampered = original;
        tampered.message = "9".to_string();
        let bytes = serde_json::to_vec(&tampered).unwrap();
        assert_eq!(bytes.len() as u64, spool.0.records[0].len);
        assert_eq!(
            serde_json::from_slice::<SemanticChange>(&bytes).unwrap(),
            tampered
        );
        let mut file = spool.0.file.reopen().unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&bytes).unwrap();
        file.flush().unwrap();
        assert!(
            matches!(spool.read_at(0), Err(GitError::InvalidSnapshot(message))
            if message == "history spool checksum mismatch")
        );
    }

    #[test]
    fn spool_refuses_index_identity_corruption_with_intact_digest() {
        for corrupt_oid in [false, true] {
            let original = change(1);
            let mut spool =
                SemanticChangeSpool::from_changes(spool_dir(), [original.clone()]).unwrap();
            assert_eq!(spool.read_at(0).unwrap(), Some(original.clone()));
            let storage = Arc::get_mut(&mut spool.0).unwrap();
            let record = &mut storage.records[0];
            let digest = record.digest;
            if corrupt_oid {
                record.oid = GitObjectId::sha1([2; 20]);
            } else {
                record.id = change(2).id;
            }
            assert_eq!(record.digest, digest);
            let mut bytes = Vec::new();
            storage
                .file
                .reopen()
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes)), digest);
            assert_eq!(
                serde_json::from_slice::<SemanticChange>(&bytes).unwrap(),
                original
            );
            assert!(
                matches!(spool.read_at(0), Err(GitError::InvalidSnapshot(message))
                if message == "history spool identity mismatch")
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn spool_refuses_removed_path() {
        let spool = SemanticChangeSpool::from_changes(spool_dir(), [change(1)]).unwrap();
        std::fs::remove_file(spool.0.file.path()).unwrap();
        assert!(spool.read_at(0).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn spool_reads_authenticated_handle_after_path_removal() {
        let original = change(1);
        let spool = SemanticChangeSpool::from_changes(spool_dir(), [original.clone()]).unwrap();
        std::fs::remove_file(spool.0.file.path()).unwrap();
        assert_eq!(spool.read_at(0).unwrap(), Some(original));
        spool.0.file.as_file().set_len(1).unwrap();
        assert!(spool.read_at(0).is_err());
    }

    #[test]
    fn spool_refuses_truncated_tampered_and_appended_bodies() {
        for mode in 1..4 {
            let spool = SemanticChangeSpool::from_changes(spool_dir(), [change(1)]).unwrap();
            match mode {
                1 => spool.0.file.as_file().set_len(1).unwrap(),
                2 => {
                    let mut file = spool.0.file.reopen().unwrap();
                    file.write_all(b"!").unwrap();
                }
                _ => spool.0.file.as_file().set_len(spool.0.bytes + 1).unwrap(),
            }
            assert!(spool.read_at(0).is_err(), "corruption mode {mode}");
        }
    }

    #[test]
    fn spool_refuses_reordered_record_bytes() {
        let spool = SemanticChangeSpool::from_changes(spool_dir(), [change(1), change(2)]).unwrap();
        let mut file = spool.0.file.reopen().unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        let split = spool.0.records[0].len as usize;
        bytes.rotate_left(split);
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&bytes).unwrap();
        assert!(spool.read_at(0).is_err());
    }
}
