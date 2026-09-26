// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;
use crate::storage::session_publication::{
    invalid, PreparedSessionRecord, MAX_SESSION_PUBLICATION_BYTES,
};

pub(super) const LOCAL_AUTHORITY_SESSION_VERSION: u32 = 5;
const SURFACE: &str = "session-publications";

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::storage) enum PreparationFault {
    PayloadAfterRename,
    BeforeAcknowledgement,
    AcknowledgementAfterRename,
}
#[cfg(test)]
thread_local! {
    static PREPARATION_FAULT: std::cell::Cell<Option<PreparationFault>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
fn take_fault(expected: PreparationFault) -> bool {
    PREPARATION_FAULT.with(|fault| {
        if fault.get() == Some(expected) {
            fault.set(None);
            true
        } else {
            false
        }
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct SessionPublicationAcknowledgement {
    operation: String,
    payload_sha256: String,
    predecessor_authority: String,
    predecessor_backend_generation: Generation,
    /// None means active. Completed evidence remains acknowledged forever in
    /// this first protocol; neither promotion nor recovery may discard it.
    committed_generation: Option<Generation>,
}

impl DurableAuthorityIdentity {
    pub(crate) fn session_binding(&self) -> Result<String, KinDbError> {
        let bytes = serde_json::to_vec(&(
            &self.snapshot_generation,
            &self.snapshot_sha256,
            &self.frames,
        ))
        .map_err(invalid)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
}

impl LocalAuthorityRecord {
    pub(super) fn supports_frames(&self) -> bool {
        matches!(
            self.version,
            LOCAL_AUTHORITY_FRAME_JOURNAL_VERSION | LOCAL_AUTHORITY_SESSION_VERSION
        )
    }
    pub(super) fn active_session(&self) -> Option<&SessionPublicationAcknowledgement> {
        self.session_publications
            .iter()
            .find(|entry| entry.committed_generation.is_none())
    }
    pub(super) fn refuse_active_session(&self) -> Result<(), KinDbError> {
        if let Some(entry) = self.active_session() {
            return Err(invalid(format!(
                "operation {} fences ordinary authority writers",
                entry.operation
            )));
        }
        Ok(())
    }
    pub(super) fn validate_session_shape(&self) -> Result<(), KinDbError> {
        if self.version != LOCAL_AUTHORITY_SESSION_VERSION && !self.session_publications.is_empty()
        {
            return Err(invalid("acknowledgements require local authority format 5"));
        }
        if self.version == LOCAL_AUTHORITY_SESSION_VERSION && self.session_publications.is_empty() {
            return Err(invalid("format 5 requires retained preparation evidence"));
        }
        let mut operations = std::collections::BTreeSet::new();
        let mut active = 0;
        for entry in &self.session_publications {
            let operation = kin_model::OperationId::from_uuid(
                uuid::Uuid::parse_str(&entry.operation).map_err(invalid)?,
            );
            if operation.to_string() != entry.operation
                || !operations.insert(&entry.operation)
                || entry.payload_sha256.len() != 64
                || !entry
                    .payload_sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                || entry.predecessor_authority.len() != 64
            {
                return Err(invalid(
                    "noncanonical or duplicate preparation acknowledgement",
                ));
            }
            match entry.committed_generation {
                None => {
                    active += 1;
                    if entry.predecessor_backend_generation != self.head_generation {
                        return Err(invalid("active preparation no longer names the head"));
                    }
                }
                Some(generation)
                    if entry.predecessor_backend_generation.checked_add(1) == Some(generation)
                        && generation <= self.head_generation => {}
                _ => return Err(invalid("invalid prepared commit generation")),
            }
        }
        if active > 1 {
            return Err(invalid("multiple active preparations"));
        }
        Ok(())
    }
}

impl LocalFileBackend {
    #[cfg(test)]
    pub(in crate::storage) fn fail_next_session_preparation(fault: PreparationFault) {
        PREPARATION_FAULT.with(|slot| slot.set(Some(fault)));
    }
    fn read_session_file(
        surface: &LocalSurfaceCapability,
        leaf: &Path,
    ) -> Result<Vec<u8>, KinDbError> {
        let mut file = mmap::open_regular_nofollow_at(
            &surface.directory,
            leaf,
            &surface.display_path,
            "prepared session publication",
        )?;
        let metadata = file.metadata().map_err(invalid)?;
        if Self::session_file_links(&file, &metadata)? != 1 {
            return Err(invalid("prepared record must have exactly one link"));
        }
        if metadata.len() > MAX_SESSION_PUBLICATION_BYTES {
            return Err(invalid(
                "prepared publication exceeds explicit 256 MiB limit",
            ));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_SESSION_PUBLICATION_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(invalid)?;
        let after = file.metadata().map_err(invalid)?;
        if Self::session_file_links(&file, &after)? != 1 {
            return Err(invalid("prepared record link identity changed"));
        }
        if bytes.len() as u64 != metadata.len() || after.len() != metadata.len() {
            return Err(invalid("prepared record size changed during read"));
        }
        Ok(bytes)
    }
    #[cfg(unix)]
    fn session_file_links(
        _: &std::fs::File,
        metadata: &std::fs::Metadata,
    ) -> Result<u64, KinDbError> {
        Ok(metadata.nlink())
    }

    #[cfg(windows)]
    fn session_file_links(file: &std::fs::File, _: &std::fs::Metadata) -> Result<u64, KinDbError> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the file owns this live handle and the output has the exact
        // structure required by GetFileInformationByHandle.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut information) }
            == 0
        {
            return Err(invalid(std::io::Error::last_os_error()));
        }
        Ok(u64::from(information.nNumberOfLinks))
    }

    #[cfg(not(any(unix, windows)))]
    fn session_file_links(_: &std::fs::File, _: &std::fs::Metadata) -> Result<u64, KinDbError> {
        Err(invalid(
            "prepared record link custody is unsupported on this platform",
        ))
    }

    fn session_leaf(operation: &str) -> PathBuf {
        PathBuf::from(format!("{operation}.ksp"))
    }

    fn read_session_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
        entry: &SessionPublicationAcknowledgement,
    ) -> Result<Vec<u8>, KinDbError> {
        let surface = namespace
            .surface(SURFACE, false)?
            .ok_or_else(|| invalid("acknowledged preparation surface is missing"))?;
        let leaf = Self::session_leaf(&entry.operation);
        let bytes = Self::read_session_file(&surface, &leaf)?;
        if hex::encode(Sha256::digest(&bytes)) != entry.payload_sha256 {
            return Err(invalid("acknowledged preparation digest mismatch"));
        }
        let payload = PreparedSessionRecord::decode(&bytes)?;
        if payload.transaction.operation_id.to_string() != entry.operation
            || payload.transaction.repository_id.as_str() != namespace.repo_id
            || payload.predecessor_authority != entry.predecessor_authority
            || payload.predecessor_backend_generation != entry.predecessor_backend_generation
        {
            return Err(invalid("preparation acknowledgement differs from payload"));
        }
        namespace.confirm_surface_visible(&surface)?;
        Ok(bytes)
    }

    pub(super) fn validate_session_records_unlocked(
        &self,
        namespace: &LocalRepositoryCapability,
        record: &LocalAuthorityRecord,
    ) -> Result<(), KinDbError> {
        record.validate_session_shape()?;
        for entry in &record.session_publications {
            self.read_session_unlocked(namespace, entry)?;
        }
        Ok(())
    }

    pub(in crate::storage) fn install_session_publication(
        &self,
        frozen: &LocalAuthorityFreezeLock,
        payload: &PreparedSessionRecord,
    ) -> Result<String, KinDbError> {
        let namespace = frozen.namespace();
        let mut record = self
            .read_authority_record_unlocked(namespace)?
            .ok_or_else(|| invalid("preparation requires existing authority"))?;
        if payload.predecessor_authority != frozen.identity().session_binding()?
            || payload.predecessor_backend_generation != record.head_generation
            || payload.transaction.repository_id.as_str() != namespace.repo_id
        {
            return Err(invalid(
                "preparation predecessor differs from retained authority",
            ));
        }
        let bytes = payload.encode()?;
        let mut digest = hex::encode(Sha256::digest(&bytes));
        let operation = payload.transaction.operation_id.to_string();
        if let Some(existing) = record
            .session_publications
            .iter()
            .find(|entry| entry.operation == operation)
        {
            let acknowledged = self.read_session_unlocked(namespace, existing)?;
            if existing.committed_generation.is_some()
                || PreparedSessionRecord::decode(&acknowledged)?.content_digest()?
                    != payload.content_digest()?
            {
                return Err(invalid(
                    "operation already names another or completed preparation",
                ));
            }
            namespace.sync_parent(Self::authority_relative_path())?;
            self.confirm_repository_visible(namespace)?;
            return Ok(existing.payload_sha256.clone());
        }
        record.refuse_active_session()?;
        let surface = namespace
            .surface(SURFACE, true)?
            .ok_or_else(|| invalid("preparation surface vanished"))?;
        let leaf = Self::session_leaf(&operation);
        if surface.exists(&leaf)? {
            mmap::confirm_installed_write_at(
                &surface.directory,
                &leaf,
                &surface.display_path,
                true,
            )?;
            let existing = Self::read_session_file(&surface, &leaf)?;
            if PreparedSessionRecord::decode(&existing)?.content_digest()?
                != payload.content_digest()?
            {
                return Err(invalid(
                    "immutable operation preparation already has different bytes",
                ));
            }
            // Replay the exact immutable bytes, even if an equivalent map
            // would serialize in a different order in this process. Its first
            // install may have lost the parent-directory acknowledgement.
            mmap::sync_parent_dir_at(&surface.directory, &leaf, &surface.display_path)?;
            digest = hex::encode(Sha256::digest(&existing));
        } else {
            #[cfg(test)]
            if take_fault(PreparationFault::PayloadAfterRename) {
                mmap::fail_parent_sync_after(2);
            }
            surface.atomic_write(&leaf, &bytes)?;
        }
        namespace.confirm_surface_visible(&surface)?;
        #[cfg(any(test, feature = "test-support"))]
        crate::session_publication_test_support::notify(
            &namespace.display_path,
            payload.transaction.operation_id,
            payload.receipt.transaction_hash,
            &digest,
        );
        record.version = LOCAL_AUTHORITY_SESSION_VERSION;
        record
            .session_publications
            .push(SessionPublicationAcknowledgement {
                operation,
                payload_sha256: digest.clone(),
                predecessor_authority: payload.predecessor_authority.clone(),
                predecessor_backend_generation: payload.predecessor_backend_generation,
                committed_generation: None,
            });
        record.validate_session_shape()?;
        #[cfg(test)]
        if take_fault(PreparationFault::BeforeAcknowledgement) {
            return Err(invalid(
                "injected interruption before preparation acknowledgement",
            ));
        }
        #[cfg(test)]
        if take_fault(PreparationFault::AcknowledgementAfterRename) {
            mmap::fail_parent_sync_after(2);
        }
        self.write_authority_unlocked(namespace, &record)?;
        self.confirm_repository_visible(namespace)
            .map_err(|error| {
                KinDbError::SnapshotPersistenceIndeterminate(format!(
                    "prepared acknowledgement installed but namespace confirmation failed: {error}"
                ))
            })?;
        Ok(digest)
    }

    /// An unacknowledged candidate grants no authority. Its original clock is
    /// reusable only after the manager repeats every admission/verifier check
    /// and installation proves the resulting complete record is identical.
    pub(in crate::storage) fn load_unacknowledged_session_candidate(
        &self,
        repo: &str,
        operation: kin_model::OperationId,
    ) -> Result<Option<PreparedSessionRecord>, KinDbError> {
        let lock = self.acquire_existing_lock(repo)?;
        let record = self
            .read_authority_record_unlocked(&lock.namespace)?
            .ok_or_else(|| invalid("unacknowledged candidate requires existing authority"))?;
        if record
            .session_publications
            .iter()
            .any(|entry| entry.operation == operation.to_string())
        {
            return Ok(None);
        }
        let Some(surface) = lock.namespace.surface(SURFACE, false)? else {
            return Ok(None);
        };
        let leaf = Self::session_leaf(&operation.to_string());
        if !surface.exists(&leaf)? {
            return Ok(None);
        }
        mmap::confirm_installed_write_at(&surface.directory, &leaf, &surface.display_path, true)?;
        let payload = PreparedSessionRecord::decode(&Self::read_session_file(&surface, &leaf)?)?;
        if payload.transaction.operation_id != operation
            || payload.transaction.repository_id.as_str() != repo
        {
            return Err(invalid(
                "unacknowledged candidate has another operation or repository",
            ));
        }
        lock.namespace.confirm_surface_visible(&surface)?;
        self.confirm_repository_visible(&lock.namespace)?;
        Ok(Some(payload))
    }

    pub(crate) fn load_session_publication(
        &self,
        repo: &str,
        operation: Option<kin_model::OperationId>,
    ) -> Result<Option<(Vec<u8>, String, bool)>, KinDbError> {
        let lock = self.acquire_existing_lock(repo)?;
        let Some(record) = self.read_authority_record_unlocked(&lock.namespace)? else {
            return Ok(None);
        };
        let entry = match operation {
            Some(operation) => record
                .session_publications
                .iter()
                .find(|entry| entry.operation == operation.to_string()),
            None => record.active_session(),
        };
        entry
            .map(|entry| {
                Ok((
                    self.read_session_unlocked(&lock.namespace, entry)?,
                    entry.payload_sha256.clone(),
                    entry.committed_generation.is_some(),
                ))
            })
            .transpose()
    }

    pub(super) fn authorize_session_snapshot(
        &self,
        namespace: &LocalRepositoryCapability,
        record: Option<&LocalAuthorityRecord>,
        authorization: Option<&str>,
        expected_gen: Generation,
    ) -> Result<(), KinDbError> {
        let Some(record) = record else {
            return if authorization.is_none() {
                Ok(())
            } else {
                Err(invalid("prepared authority is absent"))
            };
        };
        match authorization {
            None => record.refuse_active_session(),
            Some(digest) => {
                let entry = record
                    .session_publications
                    .iter()
                    .find(|entry| entry.payload_sha256 == digest)
                    .ok_or_else(|| invalid("prepared commit lacks acknowledgement"))?;
                if entry.predecessor_backend_generation != expected_gen
                    || record
                        .active_session()
                        .is_some_and(|active| active != entry)
                {
                    return Err(invalid(
                        "prepared commit does not own the exact active operation",
                    ));
                }
                self.read_session_unlocked(namespace, entry)?;
                Ok(())
            }
        }
    }

    pub(super) fn session_records_after_snapshot(
        record: Option<&LocalAuthorityRecord>,
        authorization: Option<&str>,
        generation: Generation,
    ) -> Vec<SessionPublicationAcknowledgement> {
        let mut entries = record
            .map(|r| r.session_publications.clone())
            .unwrap_or_default();
        if let Some(digest) = authorization {
            for entry in &mut entries {
                if entry.payload_sha256 == digest {
                    entry.committed_generation = Some(generation);
                }
            }
        }
        entries
    }

    pub(crate) fn save_prepared_session_snapshot_and_freeze(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_cursor: SnapshotCursor,
        history: u32,
        digest: &str,
    ) -> Result<(SnapshotCursor, LocalAuthorityFreezeLock), KinDbError> {
        self.save_snapshot_and_freeze_inner(
            repo_id,
            data,
            expected_cursor,
            Some(history),
            Some(digest),
        )
    }
}
