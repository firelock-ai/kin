// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Private temporary storage for ordered import changes, verified on every read.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use kin_model::{ChangeOrigin, GitObjectId, SemanticChange, SemanticChangeId};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::error::{GitError, Result};

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
        let mut file = self
            .0
            .file
            .reopen()
            .map_err(|error| GitError::io(path, error))?;
        if file
            .metadata()
            .map_err(|error| GitError::io(path, error))?
            .len()
            != self.0.bytes
        {
            return Err(invalid("history spool length changed"));
        }
        file.seek(SeekFrom::Start(record.offset))
            .map_err(|error| GitError::io(path, error))?;
        let len = usize::try_from(record.len)
            .map_err(|_| invalid("record length exceeds address space"))?;
        let mut bytes = vec![0; len];
        file.read_exact(&mut bytes)
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
    pub fn from_changes(changes: impl IntoIterator<Item = SemanticChange>) -> Result<Self> {
        let mut writer = SemanticChangeSpoolWriter::new()?;
        for change in changes {
            writer.append(change)?;
        }
        writer.finish()
    }
}

pub(crate) struct SemanticChangeSpoolWriter(Storage);

impl SemanticChangeSpoolWriter {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self(Storage {
            file: NamedTempFile::new()
                .map_err(|error| GitError::io(std::env::temp_dir(), error))?,
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

    #[test]
    fn spool_preserves_owned_records_order_and_indexes() {
        let records = vec![change(1), change(2)];
        let spool = SemanticChangeSpool::from_changes(records.clone()).unwrap();
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

    #[test]
    fn spool_refuses_duplicate_ids_and_duplicate_oids() {
        assert!(SemanticChangeSpool::from_changes([change(1), change(1)]).is_err());
        let mut duplicate_oid = change(2);
        duplicate_oid.origin = change(1).origin;
        assert!(SemanticChangeSpool::from_changes([change(1), duplicate_oid]).is_err());
    }

    #[test]
    fn spool_refuses_valid_same_length_message_tampering() {
        let original = change(1);
        let spool = SemanticChangeSpool::from_changes([original.clone()]).unwrap();
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
            let mut spool = SemanticChangeSpool::from_changes([original.clone()]).unwrap();
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

    #[test]
    fn spool_refuses_missing_truncated_tampered_and_appended_bodies() {
        for mode in 0..4 {
            let spool = SemanticChangeSpool::from_changes([change(1)]).unwrap();
            let path = spool.0.file.path();
            match mode {
                0 => std::fs::remove_file(path).unwrap(),
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
        let spool = SemanticChangeSpool::from_changes([change(1), change(2)]).unwrap();
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
