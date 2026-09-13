// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Immutable draft revisions. Only the exact repository writer can apply text.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use kin_mcp::entity_drafts::*;

#[path = "entity_drafts_apply.rs"]
mod application;
pub(crate) use application::call as apply;
use serde::{Deserialize, Serialize};

const STORE_DIR: &str = "entity-drafts-v1";
const LOCK_FILE: &str = "store.lock";
const MAX_RECORD_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct DraftLimits {
    pub body_bytes: usize,
    pub total_bytes: u64,
    pub drafts: usize,
    pub revisions: usize,
}

impl Default for DraftLimits {
    fn default() -> Self {
        Self {
            body_bytes: 8 * 1024 * 1024,
            total_bytes: 512 * 1024 * 1024,
            drafts: 4096,
            revisions: 65_536,
        }
    }
}

impl DraftLimits {
    fn from_env() -> Result<Self> {
        Self::read_with(|name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(error) => Err(error.to_string()),
        })
    }

    fn read_with(
        mut get: impl FnMut(&str) -> std::result::Result<Option<String>, String>,
    ) -> Result<Self> {
        let mut limit = |name: &str, default: u64, maximum: u64| -> Result<u64> {
            let error = || {
                refuse("draft_admission_config_invalid", format!("{name} must be a positive integer at most {maximum}. Existing drafts remain readable; correct admission configuration before Save or Apply."))
            };
            match get(name).map_err(|_| error())? {
                None => Ok(default),
                Some(value) => value
                    .parse::<u64>()
                    .ok()
                    .filter(|value| (1..=maximum).contains(value))
                    .ok_or_else(error),
            }
        };
        let defaults = Self::default();
        Ok(Self {
            body_bytes: limit(
                "KIN_DRAFT_MAX_BODY_BYTES",
                defaults.body_bytes as u64,
                16 * 1024 * 1024,
            )? as usize,
            total_bytes: limit(
                "KIN_DRAFT_MAX_STORAGE_BYTES",
                defaults.total_bytes,
                16 * 1024 * 1024 * 1024,
            )?,
            drafts: limit("KIN_DRAFT_MAX_DRAFTS", defaults.drafts as u64, 65_536)? as usize,
            revisions: limit(
                "KIN_DRAFT_MAX_REVISIONS",
                defaults.revisions as u64,
                1_000_000,
            )? as usize,
        })
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{code}: {message}")]
pub(crate) struct DraftError {
    pub code: &'static str,
    pub message: String,
}

type Result<T> = std::result::Result<T, DraftError>;

fn refuse(code: &'static str, message: impl Into<String>) -> DraftError {
    DraftError {
        code,
        message: message.into(),
    }
}

fn io(error: impl std::fmt::Display) -> DraftError {
    refuse("draft_storage_unavailable", error.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftEnvelope {
    record_hash: String,
    draft: EntityDraft,
}

impl DraftEnvelope {
    fn new(draft: EntityDraft) -> Result<Self> {
        Ok(Self {
            record_hash: digest(&draft)?,
            draft,
        })
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| refuse("draft_corrupt", format!("invalid draft record: {error}")))?;
        if value.record_hash != digest(&value.draft)? {
            return Err(refuse(
                "draft_corrupt",
                "draft identity, revision, source base or content failed its integrity check",
            ));
        }
        validate_record(&value.draft)?;
        Ok(value)
    }
}

fn digest(value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(io)?;
    Ok(kin_blobs::digest(&bytes).to_string())
}

fn validate_record(draft: &EntityDraft) -> Result<()> {
    let base = &draft.original_source_base;
    base.validate()
        .map_err(|error| refuse("draft_corrupt", error))?;
    if draft.revision == 0
        || draft.content_revision == 0
        || draft.content_revision > draft.revision
        || draft.previous_record_hash.is_none() != (draft.revision == 1)
        || draft.scope.repository_id.as_str() != base.context.repository_id
        || draft.scope.workspace_id.to_string() != base.context.workspace_id
        || draft.scope.entity_id != base.entity_id
        || draft.original_body.len() != base.end_byte - base.start_byte
        || kin_blobs::digest(draft.original_body.as_bytes()).to_string() != base.body_hash
    {
        return Err(refuse(
            "draft_corrupt",
            "draft original body, source identity and revision are inconsistent",
        ));
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub(crate) struct DraftSaved {
    pub schema: &'static str,
    pub draft: EntityDraft,
    pub already_saved: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct DraftListing {
    pub schema: &'static str,
    pub drafts: Vec<DraftSummary>,
    pub next_cursor: Option<uuid::Uuid>,
    pub recovery_evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DraftWritePhase {
    ParentDirectorySync,
    CreateTemporary,
    Write,
    FileSync,
    Publish,
    DirectorySync,
    BeforeApplyDispatch,
    BeforeApplyReceipt,
}

/// The authenticated caller supplies the owner; payloads cannot select one.
pub(crate) struct DraftStore {
    root: PathBuf,
    context: crate::local_repository_authority::LocalRepositoryAuthorityContext,
    owner: DraftOwner,
    limits: DraftLimits,
    admission_error: Option<DraftError>,
    #[cfg(test)]
    pub fail_phase: Option<DraftWritePhase>,
    #[cfg(test)]
    pub temporary_id: Option<uuid::Uuid>,
    #[cfg(all(test, unix))]
    symlink_target: Option<PathBuf>,
}

#[cfg(all(test, unix))]
#[derive(Debug, Clone, Default)]
pub(crate) struct DraftTestFault {
    pub phase: Option<DraftWritePhase>,
    pub temporary_id: Option<uuid::Uuid>,
    pub symlink_target: Option<PathBuf>,
    pub limits: Option<DraftLimits>,
    pub admission_error: Option<String>,
}

#[cfg(all(test, unix))]
static TEST_FAULTS: std::sync::LazyLock<std::sync::Mutex<BTreeMap<PathBuf, DraftTestFault>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(BTreeMap::new()));

#[cfg(all(test, unix))]
pub(crate) struct DraftFaultGuard(PathBuf);

#[cfg(all(test, unix))]
impl DraftFaultGuard {
    pub(crate) fn set(layout: &kin_core::KinLayout, fault: DraftTestFault) -> Self {
        let root = layout.root().join(STORE_DIR);
        TEST_FAULTS.lock().unwrap().insert(root.clone(), fault);
        Self(root)
    }
}

#[cfg(all(test, unix))]
impl Drop for DraftFaultGuard {
    fn drop(&mut self) {
        TEST_FAULTS.lock().unwrap().remove(&self.0);
    }
}

struct LockedStore {
    _lock: File,
    records: BTreeMap<uuid::Uuid, BTreeMap<u64, PathBuf>>,
    total_bytes: u64,
    revisions: usize,
    recovery_evidence: Vec<String>,
}

impl DraftStore {
    pub(crate) fn from_state(state: &crate::state::DaemonState, owner: DraftOwner) -> Result<Self> {
        let context =
            crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)
                .map_err(io)?;
        context.revalidate_pinned_namespace().map_err(io)?;
        let configured = DraftLimits::from_env();
        let store = Self {
            root: state.layout.root().join(STORE_DIR),
            context,
            owner,
            limits: configured.as_ref().copied().unwrap_or_default(),
            admission_error: configured.err(),
            #[cfg(test)]
            fail_phase: None,
            #[cfg(test)]
            temporary_id: None,
            #[cfg(all(test, unix))]
            symlink_target: None,
        };
        #[cfg(all(test, unix))]
        let store = {
            let mut store = store;
            if let Some(fault) = TEST_FAULTS.lock().unwrap().get(&store.root) {
                store.fail_phase = fault.phase;
                store.temporary_id = fault.temporary_id;
                store.symlink_target = fault.symlink_target.clone();
                store.admission_error = fault
                    .admission_error
                    .as_ref()
                    .map(|message| refuse("draft_admission_config_invalid", message.clone()));
                if let Some(limits) = fault.limits {
                    store.limits = limits;
                }
            }
            store
        };
        Ok(store)
    }

    fn check_scope(&self, draft: &EntityDraft) -> Result<()> {
        if &draft.scope.repository_id != self.context.repository_id()
            || draft.scope.workspace_id != self.context.workspace_id()
            || draft.scope.owner != self.owner
        {
            return Err(refuse(
                "draft_scope_mismatch",
                "the draft belongs to another repository, workspace or owner",
            ));
        }
        Ok(())
    }

    fn locked(&self, write: bool) -> Result<Option<LockedStore>> {
        if write {
            require_durability_platform()?;
            if let Some(error) = &self.admission_error {
                return Err(error.clone());
            }
        }
        self.context.revalidate_pinned_namespace().map_err(io)?;
        match std::fs::symlink_metadata(&self.root) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(refuse(
                    "draft_recovery_required",
                    "draft store path is not a regular directory",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !write {
                    return Ok(None);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    let mut builder = std::fs::DirBuilder::new();
                    builder.mode(0o700);
                    builder.create(&self.root).map_err(io)?;
                }
                #[cfg(not(unix))]
                std::fs::DirBuilder::new().create(&self.root).map_err(io)?;
            }
            Err(error) => return Err(io(error)),
        }
        // A prior attempt may have created the directory but failed before
        // syncing its parent. Every write must establish that durable link.
        if write {
            self.phase(DraftWritePhase::ParentDirectorySync)?;
            sync_dir(self.root.parent().expect("draft store has a parent")).map_err(io)?;
        }
        let lock_path = self.root.join(LOCK_FILE);
        let mut options = regular_options();
        options.read(true).write(true).create(true);
        let lock = options.open(&lock_path).map_err(io)?;
        if !lock.metadata().map_err(io)?.is_file() {
            return Err(refuse(
                "draft_recovery_required",
                "draft lock is not a regular file",
            ));
        }
        fs2::FileExt::lock_exclusive(&lock).map_err(io)?;
        self.context.revalidate_pinned_namespace().map_err(io)?;
        let mut locked = self.scan(lock)?;
        if write && !locked.recovery_evidence.is_empty() {
            self.recover_completed_temporaries(&locked.recovery_evidence)?;
            locked = self.scan(locked._lock)?;
            if !locked.recovery_evidence.is_empty() {
                return Err(refuse(
                    "draft_recovery_required",
                    format!(
                        "unresolved draft recovery evidence is preserved: {}",
                        locked.recovery_evidence.join(", ")
                    ),
                ));
            }
        }
        Ok(Some(locked))
    }

    fn scan(&self, lock: File) -> Result<LockedStore> {
        let mut result = LockedStore {
            _lock: lock,
            records: BTreeMap::new(),
            total_bytes: 0,
            revisions: 0,
            recovery_evidence: Vec::new(),
        };
        for entry in std::fs::read_dir(&self.root).map_err(io)? {
            let entry = entry.map_err(io)?;
            let name = entry.file_name().into_string().map_err(|_| {
                refuse(
                    "draft_recovery_required",
                    "draft store contains a non-UTF8 filename",
                )
            })?;
            if name == LOCK_FILE {
                continue;
            }
            let meta = std::fs::symlink_metadata(entry.path()).map_err(io)?;
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err(refuse(
                    "draft_recovery_required",
                    format!("draft entry is not a regular file: {name}"),
                ));
            }
            result.total_bytes = result
                .total_bytes
                .checked_add(meta.len())
                .ok_or_else(|| refuse("draft_quota", "draft storage size overflow"))?;
            match parse_record_name(&name) {
                Some((id, revision)) => {
                    result
                        .records
                        .entry(id)
                        .or_default()
                        .insert(revision, entry.path());
                    result.revisions += 1;
                }
                None => result.recovery_evidence.push(name),
            }
        }
        result.recovery_evidence.sort();
        Ok(result)
    }

    fn recover_completed_temporaries(&self, names: &[String]) -> Result<()> {
        for name in names {
            if !name.starts_with(".pending-") || uuid::Uuid::parse_str(&name[9..]).is_err() {
                continue;
            }
            let path = self.root.join(name);
            let Ok(bytes) = read_regular(&path) else {
                continue;
            };
            let Ok(record) = DraftEnvelope::decode(&bytes) else {
                continue;
            };
            if self.check_scope(&record.draft).is_err() {
                continue;
            }
            let final_path = self.record_path(record.draft.draft_id, record.draft.revision);
            if read_regular(&final_path).is_ok_and(|published| published == bytes) {
                // Exact published bytes prove this temporary is a duplicate,
                // not an unacknowledged or unknown attempt to publish.
                regular_options()
                    .read(true)
                    .open(&final_path)
                    .map_err(io)?
                    .sync_all()
                    .map_err(io)?;
                sync_dir(&self.root).map_err(io)?;
                std::fs::remove_file(path).map_err(io)?;
                sync_dir(&self.root).map_err(io)?;
            }
        }
        Ok(())
    }

    fn record_path(&self, id: uuid::Uuid, revision: u64) -> PathBuf {
        self.root.join(format!("{id}.{revision:020}.json"))
    }

    fn load(
        &self,
        locked: &LockedStore,
        id: uuid::Uuid,
        revision: Option<u64>,
    ) -> Result<DraftEnvelope> {
        let revisions = locked
            .records
            .get(&id)
            .ok_or_else(|| refuse("draft_not_found", "draft not found"))?;
        let (&number, path) = match revision {
            Some(number) => revisions.get_key_value(&number),
            None => revisions.last_key_value(),
        }
        .ok_or_else(|| refuse("draft_not_found", "draft revision not found"))?;
        let record = DraftEnvelope::decode(&read_regular(path)?)?;
        if record.draft.draft_id != id || record.draft.revision != number {
            return Err(refuse(
                "draft_corrupt",
                "draft filename and persisted identity disagree",
            ));
        }
        self.check_scope(&record.draft)?;
        Ok(record)
    }

    pub(crate) fn read(&self, request: DraftRead) -> Result<EntityDraft> {
        let locked = self
            .locked(false)?
            .ok_or_else(|| refuse("draft_not_found", "draft not found"))?;
        Ok(self
            .load(&locked, request.draft_id, request.revision)?
            .draft)
    }

    pub(crate) fn list(&self, request: DraftList) -> Result<DraftListing> {
        let limit = request.limit.unwrap_or(50);
        if !(1..=200).contains(&limit) {
            return Err(refuse(
                "draft_invalid_request",
                "draft list limit must be 1..200",
            ));
        }
        let mut listing = DraftListing {
            schema: "kin.entity.drafts.v1",
            drafts: Vec::new(),
            next_cursor: None,
            recovery_evidence: Vec::new(),
        };
        let Some(locked) = self.locked(false)? else {
            return Ok(listing);
        };
        for &id in locked.records.keys() {
            if request.after.is_some_and(|after| id <= after) {
                continue;
            }
            let record = self.load(&locked, id, None)?;
            if request
                .entity_id
                .is_some_and(|entity| record.draft.scope.entity_id != entity)
            {
                continue;
            }
            if listing.drafts.len() == limit {
                listing.next_cursor = listing.drafts.last().map(|draft| draft.draft_id);
                break;
            }
            listing.drafts.push(DraftSummary::from(&record.draft));
        }
        listing.recovery_evidence = locked.recovery_evidence;
        Ok(listing)
    }

    pub(crate) fn create(&self, request: DraftCreate) -> Result<DraftSaved> {
        request
            .original_source_base
            .validate()
            .map_err(|error| refuse("draft_invalid_request", error))?;
        let request_hash = digest(&("create", &request))?;
        let locked = self.locked(true)?.expect("write opened the store");
        if locked.records.contains_key(&request.draft_id) {
            return self.replay(&locked, request.draft_id, 1, &request_hash);
        }
        let base = request.original_source_base;
        let draft = EntityDraft {
            schema: DraftSchema::V1,
            draft_id: request.draft_id,
            revision: 1,
            content_revision: 1,
            scope: DraftScope {
                repository_id: self.context.repository_id().clone(),
                workspace_id: self.context.workspace_id(),
                entity_id: base.entity_id,
                owner: self.owner.clone(),
            },
            original_body: request.original_body,
            original_source_base: base,
            body: request.body,
            previous_record_hash: None,
            request_hash,
            pending_apply: None,
            applied_receipt: None,
        };
        validate_record(&draft).map_err(|error| refuse("draft_invalid_request", error.message))?;
        self.publish(&locked, DraftEnvelope::new(draft)?)
    }

    pub(crate) fn save(&self, request: DraftSave) -> Result<DraftSaved> {
        let revision = request
            .expected_revision
            .checked_add(1)
            .filter(|_| request.expected_revision > 0)
            .ok_or_else(|| {
                refuse(
                    "draft_invalid_request",
                    "expected_revision must be a positive incrementable revision",
                )
            })?;
        let request_hash = digest(&("save", &request))?;
        let locked = self.locked(true)?.expect("write opened the store");
        let current = self.load(&locked, request.draft_id, None)?;
        if current.draft.revision != request.expected_revision {
            return self.replay(&locked, request.draft_id, revision, &request_hash);
        }
        let mut draft = current.draft;
        draft.revision = revision;
        draft.previous_record_hash = Some(current.record_hash);
        draft.request_hash = request_hash;
        draft.body = request.body;
        draft.content_revision = revision;
        self.publish(&locked, DraftEnvelope::new(draft)?)
    }

    fn replay(
        &self,
        locked: &LockedStore,
        id: uuid::Uuid,
        revision: u64,
        request_hash: &str,
    ) -> Result<DraftSaved> {
        let record = self.load(locked, id, Some(revision)).map_err(|error| {
            if error.code == "draft_not_found" {
                refuse(
                    "draft_revision_conflict",
                    "the draft has a different saved revision; read it before resolving your text",
                )
            } else {
                error
            }
        })?;
        if record.draft.request_hash != request_hash {
            return Err(refuse("draft_revision_conflict", "the draft revision is already bound to different work; read it before resolving your text"));
        }
        regular_options()
            .read(true)
            .open(self.record_path(id, revision))
            .map_err(io)?
            .sync_all()
            .map_err(io)?;
        sync_dir(&self.root).map_err(io)?;
        Ok(DraftSaved {
            schema: "kin.entity.draft.saved.v1",
            draft: record.draft,
            already_saved: true,
        })
    }

    fn publish(&self, locked: &LockedStore, record: DraftEnvelope) -> Result<DraftSaved> {
        self.check_scope(&record.draft)?;
        if record.draft.body.len() > self.limits.body_bytes
            || record.draft.original_body.len() > self.limits.body_bytes
        {
            return Err(refuse(
                "draft_quota",
                "draft text exceeds KIN_DRAFT_MAX_BODY_BYTES; previous revisions remain intact. Raise the bounded admission setting and retry identical arguments.",
            ));
        }
        let bytes = serde_json::to_vec(&record).map_err(io)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES
            || locked.total_bytes.saturating_add(bytes.len() as u64) > self.limits.total_bytes
            || locked.revisions >= self.limits.revisions
            || (!locked.records.contains_key(&record.draft.draft_id)
                && locked.records.len() >= self.limits.drafts)
        {
            return Err(refuse(
                "draft_quota",
                "draft storage quota reached; previous revisions remain intact. Raise KIN_DRAFT_MAX_STORAGE_BYTES, KIN_DRAFT_MAX_DRAFTS or KIN_DRAFT_MAX_REVISIONS within their documented bounds and retry identical arguments. Read/list remain available.",
            ));
        }
        let temporary_id = uuid::Uuid::new_v4();
        #[cfg(test)]
        let temporary_id = self.temporary_id.unwrap_or(temporary_id);
        let temporary = self.root.join(format!(".pending-{temporary_id}"));
        let final_path = self.record_path(record.draft.draft_id, record.draft.revision);
        self.phase(DraftWritePhase::CreateTemporary)?;
        let mut file = regular_options()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(io)?;
        let mut published = false;
        let result = (|| -> Result<()> {
            self.phase(DraftWritePhase::Write)?;
            file.write_all(&bytes).map_err(io)?;
            self.phase(DraftWritePhase::FileSync)?;
            file.sync_all().map_err(io)?;
            self.context.revalidate_pinned_namespace().map_err(io)?;
            self.phase(DraftWritePhase::Publish)?;
            // Link atomically without replacing an existing revision or following
            // a destination symlink. The file was exclusively created by us.
            std::fs::hard_link(&temporary, &final_path).map_err(io)?;
            published = true;
            self.phase(DraftWritePhase::DirectorySync)?;
            sync_dir(&self.root).map_err(io)?;
            Ok(())
        })();
        if result.is_ok() || !published {
            // Only this call's exclusive temporary is ours to remove. On an
            // uncertain publication keep it for proven-duplicate recovery.
            let _ = std::fs::remove_file(&temporary);
        }
        result?;
        Ok(DraftSaved {
            schema: "kin.entity.draft.saved.v1",
            draft: record.draft,
            already_saved: false,
        })
    }

    fn phase(&self, phase: DraftWritePhase) -> Result<()> {
        #[cfg(all(test, unix))]
        if phase == DraftWritePhase::CreateTemporary {
            if let (Some(id), Some(target)) = (self.temporary_id, &self.symlink_target) {
                std::os::unix::fs::symlink(target, self.root.join(format!(".pending-{id}")))
                    .map_err(io)?;
            }
        }
        #[cfg(test)]
        if self.fail_phase == Some(phase) {
            return Err(io(format!("injected draft {phase:?} failure")));
        }
        let _ = phase;
        Ok(())
    }
}

fn parse_record_name(name: &str) -> Option<(uuid::Uuid, u64)> {
    let stem = name.strip_suffix(".json")?;
    let (id, revision) = stem.split_once('.')?;
    let id: uuid::Uuid = id.parse().ok()?;
    let revision: u64 = revision.parse().ok()?;
    (revision > 0 && name == format!("{id}.{revision:020}.json")).then_some((id, revision))
}

fn regular_options() -> OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
        options
    }
    #[cfg(not(unix))]
    OpenOptions::new()
}

fn read_regular(path: &Path) -> Result<Vec<u8>> {
    let mut file = regular_options().read(true).open(path).map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() || meta.len() > MAX_RECORD_BYTES {
        return Err(refuse(
            "draft_corrupt",
            "draft evidence is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(refuse(
            "draft_corrupt",
            "draft record exceeds its byte bound",
        ));
    }
    Ok(bytes)
}

fn sync_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        regular_options().read(true).open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported,
        "durable entity drafts require a verified directory synchronization implementation on this platform"))
    }
}

fn require_durability_platform() -> Result<()> {
    if !cfg!(unix) {
        return Err(refuse("draft_durability_unsupported", "Durable Save is unavailable on this platform; verified directory synchronization is required. Keep your text. Existing draft bytes are preserved."));
    }
    Ok(())
}

pub(crate) fn call(
    state: &crate::state::DaemonState,
    name: &str,
    arguments: &std::collections::HashMap<String, serde_json::Value>,
    authenticated: bool,
) -> kin_mcp::ToolCallResult {
    let result = (|| -> Result<serde_json::Value> {
        if !authenticated {
            return Err(refuse(
                "draft_authentication_required",
                "durable drafts require an enforced local bearer owner",
            ));
        }
        if !state
            .is_initialized
            .load(std::sync::atomic::Ordering::Relaxed)
            || state.storage_backend.is_some()
        {
            return Err(refuse(
                "draft_repository_unavailable",
                "durable entity drafts require an initialized local repository daemon",
            ));
        }
        let store = DraftStore::from_state(state, DraftOwner::LocalBearerV1)?;
        let args = serde_json::to_value(arguments).map_err(io)?;
        fn parse<T: serde::de::DeserializeOwned>(args: serde_json::Value) -> Result<T> {
            serde_json::from_value(args)
                .map_err(|error| refuse("draft_invalid_request", error.to_string()))
        }
        if matches!(name, "kin_draft_create" | "kin_draft_save") {
            require_durability_platform()?;
        }
        match name {
            "kin_draft_capabilities" => {
                if !arguments.is_empty() {
                    return Err(refuse(
                        "draft_invalid_request",
                        "capabilities accepts no arguments",
                    ));
                }
                let probe = require_durability_platform()
                    .and_then(|()| store.admission_error.clone().map_or(Ok(()), Err))
                    .and_then(|()| sync_dir(state.layout.root()).map_err(io));
                Ok(
                    serde_json::json!({"schema":"kin.entity.draft.capabilities.v1",
                    "durable_save_supported":probe.is_ok(), "apply_supported":probe.is_ok(),
                    "limits":store.limits, "refusal":probe.err().map(|error| serde_json::json!({"code":error.code,"message":error.message}))}),
                )
            }
            "kin_draft_create" => serde_json::to_value(store.create(parse(args)?)?).map_err(io),
            "kin_draft_save" => serde_json::to_value(store.save(parse(args)?)?).map_err(io),
            "kin_draft_read" => serde_json::to_value(store.read(parse(args)?)?).map_err(io),
            "kin_draft_list" => serde_json::to_value(store.list(parse(args)?)?).map_err(io),
            _ => Err(refuse(
                "draft_invalid_request",
                "unknown durable draft operation",
            )),
        }
    })();
    match result {
        Ok(value) => kin_mcp::ToolCallResult::text(value.to_string()),
        Err(error) => kin_mcp::ToolCallResult::error(serde_json::json!({
            "schema":"kin.entity.draft.refusal.v1", "code":error.code, "message":error.message,
            "repository_source_applied":false,
            "remedy":"Keep your draft text. Read the saved revision to resolve a conflict; inspect preserved evidence for a storage or corruption refusal. No previous revision is deleted."
        }).to_string()),
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    #[test]
    fn durable_entity_draft_admission_config_is_positive_bounded_and_explicit() {
        let configured = DraftLimits::read_with(|name| {
            Ok(Some(
                match name {
                    "KIN_DRAFT_MAX_BODY_BYTES" => "1024",
                    "KIN_DRAFT_MAX_STORAGE_BYTES" => "1048576",
                    "KIN_DRAFT_MAX_DRAFTS" => "10",
                    "KIN_DRAFT_MAX_REVISIONS" => "100",
                    _ => unreachable!(),
                }
                .into(),
            ))
        })
        .unwrap();
        assert_eq!(
            (
                configured.body_bytes,
                configured.total_bytes,
                configured.drafts,
                configured.revisions
            ),
            (1024, 1048576, 10, 100)
        );
        for name in [
            "KIN_DRAFT_MAX_BODY_BYTES",
            "KIN_DRAFT_MAX_STORAGE_BYTES",
            "KIN_DRAFT_MAX_DRAFTS",
            "KIN_DRAFT_MAX_REVISIONS",
        ] {
            for value in ["0", "-1", "unlimited", "18446744073709551615"] {
                let error = DraftLimits::read_with(|key| Ok((key == name).then(|| value.into())))
                    .unwrap_err();
                assert_eq!(error.code, "draft_admission_config_invalid");
                assert!(error.message.contains(name));
            }
        }
    }
}
