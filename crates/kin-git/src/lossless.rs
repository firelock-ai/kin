// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Lossless Git migration boundary.
//!
//! This module preserves Git as an exact external format without making it an
//! authority path inside Kin. Every reachable raw object body is verified
//! against both its Git object ID and Kin's blob CAS before its descriptor is
//! returned. Rehydration performs the inverse operation in a private staging
//! repository and publishes the destination only after an exact recapture.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[cfg(unix)]
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

use gix::bstr::ByteSlice;
use gix::objs::tree::EntryKind;
use gix::objs::{Find as _, Write as _};
use kin_blobs::BlobStore;
use kin_model::{
    ExternalObjectId, ExternalObjectKind, ExternalObjectRecord, GitObjectId, RefName, RefTarget,
    RepositoryId, RepositoryRef, RepositoryRefState, WorkspaceHead,
};

use crate::error::{GitError, Result};

#[cfg(unix)]
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

// How many times this process has decompressed a snapshot's whole object
// closure.
//
// Counted because the cost is invisible from any one call site. Every caller
// that wants the closure asks [`validate_snapshot`] for it, and that call
// reads and verifies EVERY object body in the repository, so a conversion that
// asked once per caller paid a whole-repository decompression per caller. On a 1,200-commit flask corpus that is 162.5 MiB decompressed
// against 13 MB packed, per rebuild, and it was the dominant repeated wall
// clock cost of `kin init` before anyone counted it.
//
// Per-thread rather than global, and that is what makes it usable as a test
// assertion. A conversion is a sequential pipeline on one thread, so a
// thread-local counts exactly the rebuilds its own caller provoked; a process
// global would be polluted by any test running beside it, and `cargo test`
// runs tests as threads in one process. Reading a delta around a call is
// therefore exact here without serializing the suite or adding a dependency
// to force it.
std::thread_local! {
    static CLOSURE_RECONSTRUCTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };

    // The most recently decompressed closure, and the exact object set it was
    // decompressed from.
    //
    // Capacity one on purpose. A conversion works one object set at a time and
    // asks for it repeatedly, so one slot captures every repeat ask while
    // bounding what is held: the flask corpus's closure is 162.5 MiB, and a
    // cache that grew would trade the wall for a memory wall.
    static CLOSURE_CACHE: std::cell::RefCell<Option<(ClosureKey, Rc<ClosureBodies>)>> =
        const { std::cell::RefCell::new(None) };
}

/// What a decompressed closure is a function of.
///
/// The object records themselves, which carry every object's identity, kind and
/// CAS body hash. That is the entire input to the decompression below, which is
/// what makes it sound as a cache key: two snapshots with equal records read
/// the same bodies out of the same CAS and verify the same descriptors against
/// them, so a hit cannot hand a caller a closure built from different objects.
///
/// Compared rather than hashed, so the match is exact rather than
/// collision-resistant. Kin's import proofs are load-bearing and a closure that
/// satisfied a proof by hash collision would be exactly the failure this key
/// exists to make impossible. The comparison walks records without touching
/// bodies, so it costs a pointer walk against the whole-repository read it
/// avoids.
///
/// Keying on something coarser, the tree root for instance, would not have this
/// property: two object sets can share a root and differ elsewhere, and a hit
/// would then satisfy a proof with a closure the proof never covered.
#[derive(PartialEq)]
struct ClosureKey {
    object_format: GitObjectFormat,
    objects: Vec<ExternalObjectRecord>,
}

type ClosureBodies = BTreeMap<ExternalObjectId, Vec<u8>>;

/// Whether a caller may be handed a closure this thread already decompressed.
///
/// The cache key covers the object DESCRIPTORS, not the state of the CAS they
/// point at, so a hit asserts something the key cannot see: that the bodies are
/// still there and still those bytes. Inside one conversion that holds, because
/// nothing mutates the CAS underneath a pipeline that is only reading it.
///
/// It does not hold for every caller, and the difference is not a detail.
/// `rehydrate_lossless_git_repository` documents that it preflights all CAS
/// bodies before mutating the filesystem, so its contract INCLUDES proving the
/// CAS can supply them right now. A shared closure would let it write an export
/// from bytes it never re-read, and a deleted body would stop failing closed.
/// It reads fresh.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ClosureSharing {
    /// Re-use this thread's closure when the object set is identical.
    Shared,
    /// Read every body from the CAS, whatever is cached.
    ///
    /// For callers whose contract is that the CAS holds these bodies NOW, which
    /// only a read can establish.
    Fresh,
}

fn closure_key(snapshot: &LosslessGitRepository) -> ClosureKey {
    ClosureKey {
        object_format: snapshot.object_format,
        objects: snapshot.objects.clone(),
    }
}

/// How many whole-closure decompressions this thread has performed.
///
/// Read it either side of a conversion and subtract. The number that matters is
/// the delta, not the total.
pub fn closure_reconstruction_count() -> usize {
    CLOSURE_RECONSTRUCTIONS.with(std::cell::Cell::get)
}

#[cfg(all(unix, test))]
std::thread_local! {
    static FAIL_NEXT_PUBLICATION_PARENT_SYNC: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(all(unix, test))]
fn inject_next_publication_parent_sync_failure() {
    FAIL_NEXT_PUBLICATION_PARENT_SYNC.set(true);
}

#[cfg(all(unix, test))]
fn fail_publication_parent_sync_if_injected(output_path: &Path) -> Result<()> {
    FAIL_NEXT_PUBLICATION_PARENT_SYNC.with(|fail| {
        if fail.replace(false) {
            Err(GitError::Other(format!(
                "injected Git publication parent sync failure at {}",
                output_path.display()
            )))
        } else {
            Ok(())
        }
    })
}

#[cfg(all(unix, not(test)))]
fn fail_publication_parent_sync_if_injected(_output_path: &Path) -> Result<()> {
    Ok(())
}

/// Hash algorithm used by the source Git object database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitObjectFormat {
    Sha1,
    Sha256,
}

impl std::fmt::Display for GitObjectFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha1 => formatter.write_str("sha1"),
            Self::Sha256 => formatter.write_str("sha256"),
        }
    }
}

/// Exact Git repository state admitted at the migration boundary.
///
/// Object bodies live in `BlobStore`, addressed by each record's `body_hash`.
/// `refs` contains every `refs/*` reference, including symbolic refs. `head`
/// is workspace-local and distinguishes symbolic (born or unborn) from
/// detached state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LosslessGitRepository {
    pub repository_id: RepositoryId,
    pub object_format: GitObjectFormat,
    pub objects: Vec<ExternalObjectRecord>,
    pub refs: RepositoryRefState,
    pub head: WorkspaceHead,
}

/// Result of atomically rehydrating an exact Git repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRehydrationResult {
    pub git_repo_path: PathBuf,
    pub objects_written: usize,
    pub refs_written: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RawTarget {
    Direct(gix::ObjectId),
    Symbolic(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawRef {
    name: Vec<u8>,
    target: RawTarget,
}

#[derive(Debug, Clone)]
struct PendingObject {
    oid: gix::ObjectId,
    expected_kind: Option<ExternalObjectKind>,
    context: String,
}

/// Capture every object reachable from every `refs/*` reference and detached
/// `HEAD`, preserving raw object bodies, exact refs, and exact HEAD state.
///
/// Gitlinks are retained inside raw tree bodies but are deliberately not
/// traversed as local objects: their OIDs name commits in another repository.
/// Shallow repositories and any missing, malformed, or hash-invalid reachable
/// objects fail closed.
pub fn capture_lossless_git_repository(
    repo_path: &Path,
    repository_id: RepositoryId,
    blob_store: &BlobStore,
) -> Result<LosslessGitRepository> {
    let repo = open_repo(repo_path)?;
    reject_shallow_repository(&repo)?;
    let object_format = object_format(&repo)?;

    let mut raw_refs = collect_refs(&repo)?;
    raw_refs.sort_by(|left, right| left.name.cmp(&right.name));
    ensure_unique_ref_names(&raw_refs)?;
    let raw_head = collect_head(&repo)?;

    let mut pending = VecDeque::new();
    for repository_ref in &raw_refs {
        if let RawTarget::Direct(oid) = repository_ref.target {
            pending.push_back(PendingObject {
                oid,
                expected_kind: None,
                context: format!("ref {}", display_bytes(&repository_ref.name)),
            });
        }
    }
    if let RawTarget::Direct(oid) = raw_head {
        pending.push_back(PendingObject {
            oid,
            expected_kind: None,
            context: "detached HEAD".to_string(),
        });
    }

    let (mut objects, object_kinds) = capture_objects(&repo, blob_store, pending)?;
    objects.sort_by_key(|record| record.object);
    reject_shallow_repository(&repo)?;
    let mut confirmed_refs = collect_refs(&repo)?;
    confirmed_refs.sort_by(|left, right| left.name.cmp(&right.name));
    let confirmed_head = collect_head(&repo)?;
    if confirmed_refs != raw_refs || confirmed_head != raw_head {
        return Err(GitError::InvalidSnapshot(
            "Git refs or HEAD changed during lossless capture; retry".to_string(),
        ));
    }

    let refs = RepositoryRefState {
        refs: raw_refs
            .into_iter()
            .map(|repository_ref| {
                let name = ref_name(repository_ref.name)?;
                let target = exact_ref_target(repository_ref.target, &object_kinds)?;
                Ok(RepositoryRef {
                    repository_id: repository_id.clone(),
                    name,
                    target,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        default_ref: match &raw_head {
            RawTarget::Symbolic(target) => Some(ref_name(target.clone())?),
            RawTarget::Direct(_) => None,
        },
    };
    refs.validate()?;

    let head = match raw_head {
        RawTarget::Symbolic(target) => WorkspaceHead::Symbolic {
            target: ref_name(target)?,
        },
        RawTarget::Direct(oid) => WorkspaceHead::Detached {
            target: exact_ref_target(RawTarget::Direct(oid), &object_kinds)?,
        },
    };

    let snapshot = LosslessGitRepository {
        repository_id,
        object_format,
        objects,
        refs,
        head,
    };
    validate_snapshot(&snapshot, blob_store)?;
    Ok(snapshot)
}

/// Rehydrate an exact SHA-1 Git repository from a lossless snapshot.
///
/// The destination must not exist. All CAS bodies and graph closure are
/// preflighted before filesystem mutation. Objects, refs, and HEAD are then
/// built in a private sibling directory, recaptured exactly, and published
/// through a retained output-parent capability. Platforms without that
/// namespace primitive fail before creating the export. SHA-256 fails before
/// creating any output until gix's writer is enabled and covered by the same
/// exact acceptance gate.
pub fn rehydrate_lossless_git_repository(
    snapshot: &LosslessGitRepository,
    blob_store: &BlobStore,
    output_path: &Path,
) -> Result<GitRehydrationResult> {
    if snapshot.object_format != GitObjectFormat::Sha1 {
        return Err(GitError::UnsupportedObjectFormat(
            snapshot.object_format.to_string(),
        ));
    }
    reject_existing_destination(output_path)?;
    // Fresh, never shared. This function's contract is that every CAS body is
    // preflighted before the filesystem is touched, and only a read establishes
    // that the CAS still holds them. Handing it a closure decompressed earlier
    // in this process would let an export be written from bytes nobody re-read,
    // and a body deleted since would stop failing closed.
    let bodies = validate_snapshot_with(snapshot, blob_store, ClosureSharing::Fresh)?;

    let parent = output_path.parent().ok_or_else(|| {
        GitError::InvalidSnapshot(format!(
            "rehydration destination {} has no parent",
            output_path.display()
        ))
    })?;
    require_anchored_publication_platform(output_path)?;
    let mut staging = claim_staging_path(parent)?;
    let build_result = build_staging_repository(snapshot, &bodies, blob_store, staging.path());
    if let Err(error) = build_result {
        return Err(staging.cleanup_after_error(error));
    }
    if let Err(error) = publish_staging(&mut staging, output_path) {
        return Err(staging.cleanup_after_error(error));
    }

    Ok(GitRehydrationResult {
        git_repo_path: output_path.to_path_buf(),
        objects_written: snapshot.objects.len(),
        refs_written: snapshot.refs.refs.len(),
    })
}

pub(crate) fn open_repo(path: &Path) -> Result<gix::Repository> {
    let dot_git = path.join(".git");
    let open_path = if dot_git.is_dir() { &dot_git } else { path };
    // Exact migration must see the repository's physical object database and
    // complete ref namespace, independent of ambient Git namespaces, global
    // config, or replacement-object interpretation. In gix, a true
    // `core.useReplaceRefs` value is the internal no-replace toggle populated
    // by `GIT_NO_REPLACE_OBJECTS`.
    let options = gix::open::Options::isolated()
        .strict_config(true)
        .config_overrides(["core.useReplaceRefs=true"]);
    gix::open_opts(open_path, options)
        .map_err(|error| GitError::Git(format!("open {}: {error}", path.display())))
}

pub(crate) fn reject_shallow_repository(repo: &gix::Repository) -> Result<()> {
    let shallow = repo
        .shallow_commits()
        .map_err(|error| GitError::Git(format!("read shallow boundary: {error}")))?;
    if shallow.as_ref().is_some_and(|commits| !commits.is_empty()) {
        return Err(GitError::ShallowRepository);
    }
    Ok(())
}

fn object_format(repo: &gix::Repository) -> Result<GitObjectFormat> {
    match repo.object_hash().len_in_bytes() {
        20 => Ok(GitObjectFormat::Sha1),
        32 => Ok(GitObjectFormat::Sha256),
        width => Err(GitError::UnsupportedObjectFormat(format!(
            "unknown-{width}-byte"
        ))),
    }
}

fn collect_refs(repo: &gix::Repository) -> Result<Vec<RawRef>> {
    let platform = repo
        .references()
        .map_err(|error| GitError::Git(format!("open reference store: {error}")))?;
    let references = platform
        .all()
        .map_err(|error| GitError::Git(format!("iterate refs: {error}")))?;
    references
        .map(|reference| {
            let reference =
                reference.map_err(|error| GitError::Git(format!("read ref: {error}")))?;
            let name = reference.name().as_bstr().to_vec();
            if !name.starts_with(b"refs/") {
                return Err(GitError::InvalidSnapshot(format!(
                    "reference iterator returned non-refs name {}",
                    display_bytes(&name)
                )));
            }
            let target = raw_target(reference.target())?;
            Ok(RawRef { name, target })
        })
        .collect()
}

fn collect_head(repo: &gix::Repository) -> Result<RawTarget> {
    let head = repo
        .find_reference("HEAD")
        .map_err(|error| GitError::Git(format!("read HEAD: {error}")))?;
    raw_target(head.target())
}

fn raw_target(target: gix::refs::TargetRef<'_>) -> Result<RawTarget> {
    if let Some(oid) = target.try_id() {
        return Ok(RawTarget::Direct(oid.to_owned()));
    }
    let target = target.try_name().ok_or_else(|| {
        GitError::InvalidSnapshot("Git ref target is neither direct nor symbolic".to_string())
    })?;
    Ok(RawTarget::Symbolic(target.as_bstr().to_vec()))
}

fn ensure_unique_ref_names(refs: &[RawRef]) -> Result<()> {
    for pair in refs.windows(2) {
        if pair[0].name == pair[1].name {
            return Err(GitError::InvalidSnapshot(format!(
                "duplicate ref {}",
                display_bytes(&pair[0].name)
            )));
        }
    }
    Ok(())
}

fn capture_objects(
    repo: &gix::Repository,
    blob_store: &BlobStore,
    mut pending: VecDeque<PendingObject>,
) -> Result<(
    Vec<ExternalObjectRecord>,
    BTreeMap<GitObjectId, ExternalObjectKind>,
)> {
    let mut records = Vec::new();
    let mut object_kinds = BTreeMap::new();

    while let Some(next) = pending.pop_front() {
        let model_oid = git_object_id(next.oid)?;
        if let Some(actual_kind) = object_kinds.get(&model_oid) {
            if let Some(expected_kind) = next.expected_kind {
                ensure_expected_kind(model_oid, *actual_kind, expected_kind, &next.context)?;
            }
            continue;
        }

        // Read the physical ODB directly. Repository::find_object() fabricates
        // the well-known empty tree even when that reachable object is missing,
        // which would turn a partial repository into an apparently complete
        // snapshot.
        let mut body = Vec::new();
        let kind = match repo.objects.try_find(&next.oid, &mut body) {
            Ok(Some(object)) => object.kind,
            Ok(None) => {
                return Err(GitError::MissingObject {
                    oid: next.oid.to_string(),
                    context: next.context.clone(),
                })
            }
            Err(error) => {
                return Err(GitError::CorruptObject {
                    oid: next.oid.to_string(),
                    reason: error.to_string(),
                })
            }
        };
        let kind = external_kind(kind);
        if let Some(expected_kind) = next.expected_kind {
            ensure_expected_kind(model_oid, kind, expected_kind, &next.context)?;
        }

        let record = ExternalObjectRecord::from_raw(kind, model_oid, &body).map_err(|error| {
            GitError::CorruptObject {
                oid: model_oid.to_string(),
                reason: error.to_string(),
            }
        })?;
        persist_verified_body(blob_store, &record, &body)?;
        enqueue_dependencies(model_oid, kind, &body, &next.context, &mut pending)?;

        object_kinds.insert(model_oid, kind);
        records.push(record);
    }

    Ok((records, object_kinds))
}

fn enqueue_dependencies(
    object_id: GitObjectId,
    object_kind: ExternalObjectKind,
    body: &[u8],
    context: &str,
    pending: &mut VecDeque<PendingObject>,
) -> Result<()> {
    let hash_kind = match object_id {
        GitObjectId::Sha1(_) => gix::hash::Kind::Sha1,
        GitObjectId::Sha256(_) => gix::hash::Kind::Sha256,
    };
    match object_kind {
        ExternalObjectKind::Commit => {
            let decoded = gix::objs::CommitRef::from_bytes(body, hash_kind).map_err(|error| {
                GitError::CorruptObject {
                    oid: object_id.to_string(),
                    reason: format!("decode commit: {error}"),
                }
            })?;
            pending.push_back(PendingObject {
                oid: decoded.tree(),
                expected_kind: Some(ExternalObjectKind::Tree),
                context: format!("tree of commit {object_id} reached from {context}"),
            });
            for parent in decoded.parents() {
                pending.push_back(PendingObject {
                    oid: parent,
                    expected_kind: Some(ExternalObjectKind::Commit),
                    context: format!("parent of commit {object_id} reached from {context}"),
                });
            }
        }
        ExternalObjectKind::Tree => {
            let decoded = gix::objs::TreeRef::from_bytes(body, hash_kind).map_err(|error| {
                GitError::CorruptObject {
                    oid: object_id.to_string(),
                    reason: format!("decode tree: {error}"),
                }
            })?;
            validate_tree_structure(&decoded.entries).map_err(|reason| {
                GitError::CorruptObject {
                    oid: object_id.to_string(),
                    reason,
                }
            })?;
            for entry in decoded.entries {
                let expected_kind = tree_entry_dependency_kind(entry.mode).map_err(|mode| {
                    GitError::CorruptObject {
                        oid: object_id.to_string(),
                        reason: format!("unsupported tree entry mode {mode:#o}"),
                    }
                })?;
                if let Some(expected_kind) = expected_kind {
                    pending.push_back(PendingObject {
                        oid: entry.oid.to_owned(),
                        expected_kind: Some(expected_kind),
                        context: format!(
                            "tree entry {} in {object_id} reached from {context}",
                            display_bytes(entry.filename)
                        ),
                    });
                }
            }
        }
        ExternalObjectKind::Tag => {
            let decoded = gix::objs::TagRef::from_bytes(body, hash_kind).map_err(|error| {
                GitError::CorruptObject {
                    oid: object_id.to_string(),
                    reason: format!("decode tag: {error}"),
                }
            })?;
            pending.push_back(PendingObject {
                oid: decoded.target(),
                expected_kind: Some(external_kind(decoded.target_kind)),
                context: format!("target of annotated tag {object_id} reached from {context}"),
            });
        }
        ExternalObjectKind::Blob => {}
    }
    Ok(())
}

fn external_kind(kind: gix::objs::Kind) -> ExternalObjectKind {
    match kind {
        gix::objs::Kind::Commit => ExternalObjectKind::Commit,
        gix::objs::Kind::Tree => ExternalObjectKind::Tree,
        gix::objs::Kind::Blob => ExternalObjectKind::Blob,
        gix::objs::Kind::Tag => ExternalObjectKind::Tag,
    }
}

fn tree_entry_dependency_kind(
    mode: gix::objs::tree::EntryMode,
) -> std::result::Result<Option<ExternalObjectKind>, u16> {
    match mode.kind() {
        EntryKind::Tree => Ok(Some(ExternalObjectKind::Tree)),
        EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => {
            Ok(Some(ExternalObjectKind::Blob))
        }
        EntryKind::Commit if mode.value() == 0o160000 => Ok(None),
        EntryKind::Commit => Err(mode.value()),
    }
}

fn validate_tree_structure(
    entries: &[gix::objs::tree::EntryRef<'_>],
) -> std::result::Result<(), String> {
    for entry in entries {
        if entry.filename.is_empty() {
            return Err("tree entry has an empty filename".to_string());
        }
        if entry.filename.contains(&b'/') {
            return Err(format!(
                "tree entry {} contains a path separator",
                display_bytes(entry.filename)
            ));
        }
    }

    if let Some(entries) = entries.windows(2).find(|entries| entries[0] >= entries[1]) {
        return Err(format!(
            "tree entries are not in canonical order: {} then {}",
            display_bytes(entries[0].filename),
            display_bytes(entries[1].filename)
        ));
    }

    Ok(())
}

fn gix_kind(kind: ExternalObjectKind) -> gix::objs::Kind {
    match kind {
        ExternalObjectKind::Commit => gix::objs::Kind::Commit,
        ExternalObjectKind::Tree => gix::objs::Kind::Tree,
        ExternalObjectKind::Blob => gix::objs::Kind::Blob,
        ExternalObjectKind::Tag => gix::objs::Kind::Tag,
    }
}

fn ensure_expected_kind(
    oid: GitObjectId,
    actual: ExternalObjectKind,
    expected: ExternalObjectKind,
    context: &str,
) -> Result<()> {
    if actual != expected {
        return Err(GitError::CorruptObject {
            oid: oid.to_string(),
            reason: format!("{context} requires a {expected:?}, but the object is {actual:?}"),
        });
    }
    Ok(())
}

fn persist_verified_body(
    blob_store: &BlobStore,
    record: &ExternalObjectRecord,
    body: &[u8],
) -> Result<()> {
    let stored_hash = blob_store.write(body)?;
    if stored_hash != record.body_hash {
        return Err(GitError::CorruptObject {
            oid: record.object.oid.to_string(),
            reason: format!(
                "CAS returned {}, descriptor requires {}",
                stored_hash, record.body_hash
            ),
        });
    }
    let persisted = blob_store.read(&record.body_hash)?;
    record
        .validate_raw(&persisted)
        .map_err(|error| GitError::CorruptObject {
            oid: record.object.oid.to_string(),
            reason: format!("persisted CAS body failed validation: {error}"),
        })
}

fn ref_name(bytes: Vec<u8>) -> Result<RefName> {
    RefName::from_bytes(bytes)
        .map_err(|error| GitError::InvalidSnapshot(format!("invalid ref name: {error}")))
}

fn exact_ref_target(
    target: RawTarget,
    object_kinds: &BTreeMap<GitObjectId, ExternalObjectKind>,
) -> Result<RefTarget> {
    match target {
        RawTarget::Symbolic(target) => Ok(RefTarget::symbolic(ref_name(target)?)),
        RawTarget::Direct(oid) => {
            let oid = git_object_id(oid)?;
            let kind = object_kinds
                .get(&oid)
                .copied()
                .ok_or_else(|| GitError::MissingObject {
                    oid: oid.to_string(),
                    context: "direct ref target".to_string(),
                })?;
            Ok(RefTarget::external_object(ExternalObjectId::new(kind, oid)))
        }
    }
}

fn git_object_id(oid: gix::ObjectId) -> Result<GitObjectId> {
    match oid.as_bytes() {
        bytes if bytes.len() == 20 => {
            let mut exact = [0_u8; 20];
            exact.copy_from_slice(bytes);
            Ok(GitObjectId::sha1(exact))
        }
        bytes if bytes.len() == 32 => {
            let mut exact = [0_u8; 32];
            exact.copy_from_slice(bytes);
            Ok(GitObjectId::sha256(exact))
        }
        bytes => Err(GitError::UnsupportedObjectFormat(format!(
            "{}-byte object ID",
            bytes.len()
        ))),
    }
}

fn gix_object_id(oid: GitObjectId) -> Result<gix::ObjectId> {
    gix::ObjectId::from_hex(oid.to_string().as_bytes())
        .map_err(|error| GitError::InvalidSnapshot(format!("invalid Git object ID: {error}")))
}

/// Validate a snapshot and hand back its decompressed object closure.
///
/// The closure is returned SHARED rather than owned, because a conversion asks
/// several times over the same objects and a per-caller copy of it is the same
/// whole-repository cost this sharing exists to remove: on the flask corpus the
/// map is 162.5 MiB. Callers read it; nobody mutates it.
pub(crate) fn validate_snapshot(
    snapshot: &LosslessGitRepository,
    blob_store: &BlobStore,
) -> Result<Rc<ClosureBodies>> {
    validate_snapshot_with(snapshot, blob_store, ClosureSharing::Shared)
}

/// [`validate_snapshot`], with the caller stating whether a shared closure is
/// sound for what it is about to do.
fn validate_snapshot_with(
    snapshot: &LosslessGitRepository,
    blob_store: &BlobStore,
    sharing: ClosureSharing,
) -> Result<Rc<ClosureBodies>> {
    snapshot.refs.validate()?;
    for repository_ref in &snapshot.refs.refs {
        if repository_ref.repository_id != snapshot.repository_id {
            return Err(GitError::InvalidSnapshot(format!(
                "ref {} belongs to repository {}, not {}",
                repository_ref.name, repository_ref.repository_id, snapshot.repository_id
            )));
        }
    }
    validate_head_and_default(snapshot)?;

    let bodies = decompressed_closure(snapshot, blob_store, sharing)?;

    // Outside the shared closure on purpose. Reachability is a function of the
    // refs and HEAD as well as the objects, and those are NOT part of the cache
    // key, so two snapshots that share an object set can still disagree about
    // what is reachable from it. Re-walking is cheap next to decompressing, and
    // a proof that only ran on a cache miss would be a proof that stopped
    // running.
    validate_reachable_closure(snapshot, &bodies)?;
    Ok(bodies)
}

/// The snapshot's object bodies, decompressed once per distinct object set.
///
/// A conversion asks for the same closure at every step, and each ask used to
/// re-read and re-verify every object body in the repository. This returns the
/// previous answer when the object set is byte-for-byte the one it was built
/// from, and rebuilds otherwise.
///
/// What is shared is the DECOMPRESSION, never a verdict. The per-object
/// descriptor check below runs on every body the first time that object set is
/// seen, and a hit is only possible when the key covering every object ID, kind
/// and CAS body hash matches, so a hit re-uses bodies that were verified
/// against these exact descriptors and no others. Everything a proof actually
/// asserts, the derived plan and the reachable closure, is recomputed by the
/// caller either way.
fn decompressed_closure(
    snapshot: &LosslessGitRepository,
    blob_store: &BlobStore,
    sharing: ClosureSharing,
) -> Result<Rc<ClosureBodies>> {
    let key = closure_key(snapshot);
    if sharing == ClosureSharing::Shared {
        if let Some(shared) = CLOSURE_CACHE.with(|cache| {
            cache
                .borrow()
                .as_ref()
                .filter(|(cached, _)| *cached == key)
                .map(|(_, bodies)| Rc::clone(bodies))
        }) {
            return Ok(shared);
        }
    }

    // Counted here rather than at the function entry, because a hit above costs
    // nothing and everything before it is cheap ref arithmetic. The loop below
    // is the whole-repository decompression this counter exists to make
    // visible.
    CLOSURE_RECONSTRUCTIONS.with(|count| count.set(count.get() + 1));

    let mut bodies = BTreeMap::new();
    let mut object_ids = BTreeSet::new();
    for record in &snapshot.objects {
        if object_format_for_oid(record.object.oid) != snapshot.object_format {
            return Err(GitError::InvalidSnapshot(format!(
                "object {} does not use snapshot format {}",
                record.object.oid, snapshot.object_format
            )));
        }
        let body = blob_store.read(&record.body_hash)?;
        record.validate_raw(&body).map_err(|error| {
            GitError::InvalidSnapshot(format!(
                "object {} descriptor/body mismatch: {error}",
                record.object.oid
            ))
        })?;
        if bodies.insert(record.object, body).is_some() {
            return Err(GitError::InvalidSnapshot(format!(
                "duplicate object {}",
                record.object.oid
            )));
        }
        if !object_ids.insert(record.object.oid) {
            return Err(GitError::InvalidSnapshot(format!(
                "object ID {} is repeated with more than one object kind",
                record.object.oid
            )));
        }
    }

    // Published only after every body passed, so a rejected object set leaves
    // nothing behind for the next caller to hit.
    let shared = Rc::new(bodies);
    CLOSURE_CACHE.with(|cache| {
        *cache.borrow_mut() = Some((key, Rc::clone(&shared)));
    });
    Ok(shared)
}

fn validate_head_and_default(snapshot: &LosslessGitRepository) -> Result<()> {
    match (&snapshot.head, &snapshot.refs.default_ref) {
        (WorkspaceHead::Symbolic { target }, Some(default)) if target == default => Ok(()),
        (WorkspaceHead::Symbolic { target }, Some(default)) => Err(GitError::InvalidSnapshot(
            format!("symbolic HEAD {target} disagrees with default ref {default}"),
        )),
        (WorkspaceHead::Symbolic { .. }, None) => Err(GitError::InvalidSnapshot(
            "symbolic HEAD requires an exact default ref".to_string(),
        )),
        (WorkspaceHead::Detached { target }, None) => match target {
            RefTarget::ExternalObject { .. } => Ok(()),
            RefTarget::Change { .. } => Err(GitError::InvalidSnapshot(
                "detached exact Git HEAD cannot target a native Kin change".to_string(),
            )),
            RefTarget::Symbolic { .. } => Err(GitError::InvalidSnapshot(
                "detached HEAD cannot have a symbolic target".to_string(),
            )),
        },
        (WorkspaceHead::Detached { .. }, Some(default)) => Err(GitError::InvalidSnapshot(format!(
            "detached HEAD cannot materialize repository default ref {default}"
        ))),
    }
}

fn validate_reachable_closure(
    snapshot: &LosslessGitRepository,
    bodies: &BTreeMap<ExternalObjectId, Vec<u8>>,
) -> Result<()> {
    let mut pending = VecDeque::new();
    for repository_ref in &snapshot.refs.refs {
        enqueue_ref_target(&repository_ref.target, &mut pending)?;
    }
    enqueue_head_target(&snapshot.head, &mut pending)?;

    let mut reached = BTreeSet::new();
    while let Some((object, expected_kind, context)) = pending.pop_front() {
        if let Some(expected_kind) = expected_kind {
            ensure_expected_kind(object.oid, object.kind, expected_kind, &context)?;
        }
        if !reached.insert(object) {
            continue;
        }
        let body = bodies.get(&object).ok_or_else(|| GitError::MissingObject {
            oid: object.oid.to_string(),
            context: context.clone(),
        })?;
        enqueue_raw_dependencies(snapshot.object_format, object, body, &context, &mut pending)?;
    }

    if reached.len() != bodies.len() {
        let unreachable = bodies
            .keys()
            .find(|object| !reached.contains(object))
            .expect("different set lengths imply one unreachable object");
        return Err(GitError::InvalidSnapshot(format!(
            "object {} is not reachable from refs or detached HEAD",
            unreachable.oid
        )));
    }
    Ok(())
}

fn enqueue_ref_target(
    target: &RefTarget,
    pending: &mut VecDeque<(ExternalObjectId, Option<ExternalObjectKind>, String)>,
) -> Result<()> {
    match target {
        RefTarget::ExternalObject { object } => {
            pending.push_back((*object, None, "direct repository ref".to_string()));
            Ok(())
        }
        RefTarget::Symbolic { .. } => Ok(()),
        RefTarget::Change { change_id } => Err(GitError::InvalidSnapshot(format!(
            "exact Git ref cannot target native Kin change {change_id}"
        ))),
    }
}

fn enqueue_head_target(
    head: &WorkspaceHead,
    pending: &mut VecDeque<(ExternalObjectId, Option<ExternalObjectKind>, String)>,
) -> Result<()> {
    match head {
        WorkspaceHead::Symbolic { .. } => Ok(()),
        WorkspaceHead::Detached {
            target: RefTarget::ExternalObject { object },
        } => {
            pending.push_back((*object, None, "detached HEAD".to_string()));
            Ok(())
        }
        WorkspaceHead::Detached {
            target: RefTarget::Change { change_id },
        } => Err(GitError::InvalidSnapshot(format!(
            "detached exact Git HEAD cannot target native Kin change {change_id}"
        ))),
        WorkspaceHead::Detached {
            target: RefTarget::Symbolic { .. },
        } => Err(GitError::InvalidSnapshot(
            "detached HEAD cannot have a symbolic target".to_string(),
        )),
    }
}

fn enqueue_raw_dependencies(
    object_format: GitObjectFormat,
    object: ExternalObjectId,
    body: &[u8],
    context: &str,
    pending: &mut VecDeque<(ExternalObjectId, Option<ExternalObjectKind>, String)>,
) -> Result<()> {
    let hash_kind = match object_format {
        GitObjectFormat::Sha1 => gix::hash::Kind::Sha1,
        GitObjectFormat::Sha256 => gix::hash::Kind::Sha256,
    };
    match object.kind {
        ExternalObjectKind::Commit => {
            let commit = gix::objs::CommitRef::from_bytes(body, hash_kind).map_err(|error| {
                GitError::InvalidSnapshot(format!("decode commit {}: {error}", object.oid))
            })?;
            pending.push_back((
                external_object_id(ExternalObjectKind::Tree, commit.tree())?,
                Some(ExternalObjectKind::Tree),
                format!("tree of commit {} reached from {context}", object.oid),
            ));
            for parent in commit.parents() {
                pending.push_back((
                    external_object_id(ExternalObjectKind::Commit, parent)?,
                    Some(ExternalObjectKind::Commit),
                    format!("parent of commit {} reached from {context}", object.oid),
                ));
            }
        }
        ExternalObjectKind::Tree => {
            let tree = gix::objs::TreeRef::from_bytes(body, hash_kind).map_err(|error| {
                GitError::InvalidSnapshot(format!("decode tree {}: {error}", object.oid))
            })?;
            validate_tree_structure(&tree.entries).map_err(|reason| {
                GitError::InvalidSnapshot(format!("invalid tree {}: {reason}", object.oid))
            })?;
            for entry in tree.entries {
                let kind = tree_entry_dependency_kind(entry.mode).map_err(|mode| {
                    GitError::InvalidSnapshot(format!(
                        "invalid tree {}: unsupported entry mode {mode:#o}",
                        object.oid
                    ))
                })?;
                if let Some(kind) = kind {
                    pending.push_back((
                        external_object_id(kind, entry.oid.to_owned())?,
                        Some(kind),
                        format!(
                            "tree entry {} in {} reached from {context}",
                            display_bytes(entry.filename),
                            object.oid
                        ),
                    ));
                }
            }
        }
        ExternalObjectKind::Tag => {
            let tag = gix::objs::TagRef::from_bytes(body, hash_kind).map_err(|error| {
                GitError::InvalidSnapshot(format!("decode tag {}: {error}", object.oid))
            })?;
            let kind = external_kind(tag.target_kind);
            pending.push_back((
                external_object_id(kind, tag.target())?,
                Some(kind),
                format!(
                    "target of annotated tag {} reached from {context}",
                    object.oid
                ),
            ));
        }
        ExternalObjectKind::Blob => {}
    }
    Ok(())
}

fn external_object_id(kind: ExternalObjectKind, oid: gix::ObjectId) -> Result<ExternalObjectId> {
    Ok(ExternalObjectId::new(kind, git_object_id(oid)?))
}

fn object_format_for_oid(oid: GitObjectId) -> GitObjectFormat {
    match oid {
        GitObjectId::Sha1(_) => GitObjectFormat::Sha1,
        GitObjectId::Sha256(_) => GitObjectFormat::Sha256,
    }
}

pub(crate) fn reject_existing_destination(output_path: &Path) -> Result<()> {
    match fs::symlink_metadata(output_path) {
        Ok(_) => Err(GitError::DestinationExists(
            output_path.display().to_string(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(GitError::io(output_path, error)),
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublicationIdentity {
    device: u64,
    inode: u64,
}

/// An owner-private Git stage bound to its original namespace parent.
///
/// The path exists only for builders that still require a pathname. Final
/// publication, rollback, and cleanup use the retained handles and identities,
/// so a replacement of the ambient parent cannot redirect a mutation.
pub(crate) struct ClaimedStaging {
    path: PathBuf,
    #[cfg(unix)]
    parent_display: PathBuf,
    #[cfg(unix)]
    name: OsString,
    published: bool,
    #[cfg(unix)]
    parent: cap_std::fs::Dir,
    #[cfg(unix)]
    parent_identity: PublicationIdentity,
    #[cfg(unix)]
    directory: cap_std::fs::Dir,
    #[cfg(unix)]
    directory_identity: PublicationIdentity,
}

impl ClaimedStaging {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn cleanup_after_error(&mut self, error: GitError) -> GitError {
        match self.cleanup() {
            Ok(()) => error,
            Err(cleanup) => GitError::Other(format!(
                "{error}; retained-capability staging cleanup also failed at {}: {cleanup}",
                self.path.display()
            )),
        }
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.published {
            return Ok(());
        }
        #[cfg(unix)]
        {
            self.revalidate_retained_stage()?;
            clear_publication_directory(&self.directory, &self.path)?;
            rustix::fs::unlinkat(&self.parent, &self.name, rustix::fs::AtFlags::REMOVEDIR)
                .map_err(|error| GitError::io(&self.path, error.into()))?;
            sync_publication_directory_capability(&self.parent, &self.parent_display)?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Err(unsupported_anchored_publication(&self.path))
        }
    }

    #[cfg(unix)]
    fn revalidate_retained_parent(&self) -> Result<()> {
        if publication_directory_identity(&self.parent)
            .map_err(|error| GitError::io(&self.parent_display, error))?
            != self.parent_identity
        {
            return Err(GitError::Other(format!(
                "retained Git publication parent {} changed identity",
                self.parent_display.display()
            )));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn revalidate_visible_parent(&self) -> Result<()> {
        self.revalidate_retained_parent()?;
        let visible = open_publication_directory_nofollow(&self.parent_display)
            .map_err(|error| GitError::io(&self.parent_display, error))?;
        if publication_directory_identity(&visible)
            .map_err(|error| GitError::io(&self.parent_display, error))?
            != self.parent_identity
        {
            return Err(GitError::Other(format!(
                "Git publication parent {} was replaced while retained",
                self.parent_display.display()
            )));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn revalidate_retained_stage(&self) -> Result<()> {
        self.revalidate_retained_parent()?;
        if publication_directory_identity(&self.directory)
            .map_err(|error| GitError::io(&self.path, error))?
            != self.directory_identity
        {
            return Err(GitError::Other(format!(
                "retained Git staging directory {} changed identity",
                self.path.display()
            )));
        }
        let named = open_publication_child_directory_nofollow(&self.parent, &self.name)
            .map_err(|error| GitError::io(&self.path, error))?;
        if publication_directory_identity(&named)
            .map_err(|error| GitError::io(&self.path, error))?
            != self.directory_identity
        {
            return Err(GitError::Other(format!(
                "Git staging directory {} was replaced while retained",
                self.path.display()
            )));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn revalidate_visible_stage(&self) -> Result<()> {
        self.revalidate_visible_parent()?;
        self.revalidate_retained_stage()
    }
}

pub(crate) fn claim_staging_path(parent: &Path) -> Result<ClaimedStaging> {
    #[cfg(unix)]
    {
        let parent_handle = open_publication_directory_nofollow(parent)
            .map_err(|error| GitError::io(parent, error))?;
        let parent_identity = publication_directory_identity(&parent_handle)
            .map_err(|error| GitError::io(parent, error))?;
        loop {
            let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = OsString::from(format!(
                ".kin-git-rehydrate-{}-{sequence}",
                std::process::id()
            ));
            let candidate = parent.join(&name);
            match rustix::fs::mkdirat(
                &parent_handle,
                &name,
                rustix::fs::Mode::from_raw_mode(0o700),
            ) {
                Ok(()) => {
                    sync_publication_directory_capability(&parent_handle, parent)?;
                    let directory =
                        open_publication_child_directory_nofollow(&parent_handle, &name)
                            .map_err(|error| GitError::io(&candidate, error))?;
                    let directory_identity = publication_directory_identity(&directory)
                        .map_err(|error| GitError::io(&candidate, error))?;
                    let staging = ClaimedStaging {
                        path: candidate,
                        parent_display: parent.to_path_buf(),
                        name,
                        published: false,
                        parent: parent_handle,
                        parent_identity,
                        directory,
                        directory_identity,
                    };
                    staging.revalidate_visible_stage()?;
                    return Ok(staging);
                }
                Err(error) if error == rustix::io::Errno::EXIST => continue,
                Err(error) => return Err(GitError::io(&candidate, error.into())),
            }
        }
    }
    #[cfg(not(unix))]
    {
        Err(unsupported_anchored_publication(parent))
    }
}

pub(crate) fn require_anchored_publication_platform(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let _ = path;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(unsupported_anchored_publication(path))
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationHookPoint {
    AfterNamespaceMutation,
}

pub(crate) fn publish_staging(staging: &mut ClaimedStaging, output_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        publish_staging_with_hook(staging, output_path, |_| {})
    }
    #[cfg(not(unix))]
    {
        let _ = staging;
        Err(unsupported_anchored_publication(output_path))
    }
}

#[cfg(unix)]
fn publish_staging_with_hook(
    staging: &mut ClaimedStaging,
    output_path: &Path,
    mut hook: impl FnMut(PublicationHookPoint),
) -> Result<()> {
    let output_parent = output_path.parent().ok_or_else(|| {
        GitError::InvalidSnapshot(format!(
            "Git publication destination {} has no parent",
            output_path.display()
        ))
    })?;
    let output_name = output_path.file_name().ok_or_else(|| {
        GitError::InvalidSnapshot(format!(
            "Git publication destination {} has no file name",
            output_path.display()
        ))
    })?;
    validate_publication_component(output_name, output_path)?;
    if output_parent != staging.parent_display {
        return Err(GitError::Other(format!(
            "Git destination parent {} differs from the retained staging parent {}",
            output_parent.display(),
            staging.parent_display.display()
        )));
    }
    let retained_output_parent = open_publication_directory_nofollow(output_parent)
        .map_err(|error| GitError::io(output_parent, error))?;
    if publication_directory_identity(&retained_output_parent)
        .map_err(|error| GitError::io(output_parent, error))?
        != staging.parent_identity
    {
        return Err(GitError::Other(format!(
            "Git staging parent {} and destination parent {} are not the same retained directory",
            staging.parent_display.display(),
            output_parent.display()
        )));
    }

    staging.revalidate_visible_stage()?;
    ensure_publication_name_absent(&staging.parent, output_name, output_path)?;
    sync_git_directory_capability(&staging.directory, &staging.path)?;
    staging.revalidate_visible_stage()?;
    ensure_publication_name_absent(&staging.parent, output_name, output_path)?;

    rustix::fs::renameat_with(
        &staging.parent,
        &staging.name,
        &retained_output_parent,
        output_name,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            GitError::DestinationExists(output_path.display().to_string())
        } else {
            GitError::io(output_path, error.into())
        }
    })?;

    hook(PublicationHookPoint::AfterNamespaceMutation);

    let post_publication = fail_publication_parent_sync_if_injected(output_path)
        .and_then(|()| {
            sync_publication_directory_capability(&staging.parent, &staging.parent_display)
        })
        .and_then(|()| {
            validate_publication_name_identity(
                &staging.parent,
                output_name,
                staging.directory_identity,
                output_path,
            )
        })
        .and_then(|()| staging.revalidate_visible_parent());
    if let Err(error) = post_publication {
        let rollback = rustix::fs::renameat_with(
            &staging.parent,
            output_name,
            &staging.parent,
            &staging.name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|rollback| GitError::io(&staging.path, rollback.into()))
        .and_then(|()| {
            sync_publication_directory_capability(&staging.parent, &staging.parent_display)
        })
        .and_then(|()| staging.revalidate_retained_stage());
        return Err(GitError::Other(format!(
            "Git staging was renamed to {}, but durable retained-parent publication failed: \
             {error}; rollback: {}",
            output_path.display(),
            rollback
                .map(|()| "restored the private staging name".to_string())
                .unwrap_or_else(|rollback| rollback.to_string())
        )));
    }

    staging.published = true;
    Ok(())
}

#[cfg(not(unix))]
fn unsupported_anchored_publication(path: &Path) -> GitError {
    GitError::Other(format!(
        "retained-capability Git publication is unsupported on this platform: {}",
        path.display()
    ))
}

#[cfg(unix)]
fn publication_directory_identity(
    directory: &cap_std::fs::Dir,
) -> std::io::Result<PublicationIdentity> {
    use cap_std::fs::MetadataExt as _;

    directory
        .dir_metadata()
        .map(|metadata| PublicationIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
}

#[cfg(unix)]
fn open_publication_directory_nofollow(path: &Path) -> std::io::Result<cap_std::fs::Dir> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(|fd| cap_std::fs::Dir::from_std_file(fd.into()))
    .map_err(Into::into)
}

#[cfg(unix)]
fn open_publication_child_directory_nofollow(
    parent: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
) -> std::io::Result<cap_std::fs::Dir> {
    rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(|fd| cap_std::fs::Dir::from_std_file(fd.into()))
    .map_err(Into::into)
}

#[cfg(unix)]
fn sync_publication_directory_capability(
    directory: &cap_std::fs::Dir,
    display: &Path,
) -> Result<()> {
    rustix::fs::fsync(directory).map_err(|error| GitError::io(display, std::io::Error::from(error)))
}

#[cfg(unix)]
fn sync_git_directory_capability(directory: &cap_std::fs::Dir, display: &Path) -> Result<()> {
    let children = directory
        .entries()
        .map_err(|error| GitError::io(display, error))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|error| GitError::io(display, error))
        })
        .collect::<Result<Vec<_>>>()?;
    for name in children {
        let child_display = display.join(&name);
        let metadata = directory
            .symlink_metadata(&name)
            .map_err(|error| GitError::io(&child_display, error))?;
        if metadata.file_type().is_symlink() {
            return Err(GitError::InvalidSnapshot(format!(
                "staged Git repository contains a symbolic link at {}",
                child_display.display()
            )));
        }
        if metadata.is_dir() {
            let child = open_publication_child_directory_nofollow(directory, &name)
                .map_err(|error| GitError::io(&child_display, error))?;
            sync_git_directory_capability(&child, &child_display)?;
            continue;
        }
        if metadata.is_file() {
            let file = rustix::fs::openat(
                directory,
                &name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map(fs::File::from)
            .map_err(|error| GitError::io(&child_display, error.into()))?;
            if !file
                .metadata()
                .map_err(|error| GitError::io(&child_display, error))?
                .is_file()
            {
                return Err(GitError::InvalidSnapshot(format!(
                    "staged Git file changed kind while syncing {}",
                    child_display.display()
                )));
            }
            file.sync_all()
                .map_err(|error| GitError::io(&child_display, error))?;
            continue;
        }
        return Err(GitError::InvalidSnapshot(format!(
            "staged Git repository contains an unsupported filesystem object at {}",
            child_display.display()
        )));
    }
    sync_publication_directory_capability(directory, display)
}

#[cfg(unix)]
fn clear_publication_directory(directory: &cap_std::fs::Dir, display: &Path) -> Result<()> {
    let children = directory
        .entries()
        .map_err(|error| GitError::io(display, error))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|error| GitError::io(display, error))
        })
        .collect::<Result<Vec<_>>>()?;
    for name in children {
        let child_display = display.join(&name);
        let metadata = directory
            .symlink_metadata(&name)
            .map_err(|error| GitError::io(&child_display, error))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            let child = open_publication_child_directory_nofollow(directory, &name)
                .map_err(|error| GitError::io(&child_display, error))?;
            clear_publication_directory(&child, &child_display)?;
            rustix::fs::unlinkat(directory, &name, rustix::fs::AtFlags::REMOVEDIR)
                .map_err(|error| GitError::io(&child_display, error.into()))?;
        } else {
            rustix::fs::unlinkat(directory, &name, rustix::fs::AtFlags::empty())
                .map_err(|error| GitError::io(&child_display, error.into()))?;
        }
    }
    sync_publication_directory_capability(directory, display)
}

#[cfg(unix)]
fn validate_publication_component(name: &std::ffi::OsStr, display: &Path) -> Result<()> {
    let mut components = Path::new(name).components();
    if !matches!(
        components.next(),
        Some(std::path::Component::Normal(component)) if component == name
    ) || components.next().is_some()
    {
        return Err(GitError::InvalidSnapshot(format!(
            "Git publication destination is not one safe path component: {}",
            display.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_publication_name_absent(
    parent: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    display: &Path,
) -> Result<()> {
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(GitError::io(display, error)),
        Ok(_) => Err(GitError::DestinationExists(display.display().to_string())),
    }
}

#[cfg(unix)]
fn validate_publication_name_identity(
    parent: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    expected: PublicationIdentity,
    display: &Path,
) -> Result<()> {
    let named = open_publication_child_directory_nofollow(parent, name)
        .map_err(|error| GitError::io(display, error))?;
    if publication_directory_identity(&named).map_err(|error| GitError::io(display, error))?
        != expected
    {
        return Err(GitError::Other(format!(
            "published Git directory {} changed identity",
            display.display()
        )));
    }
    Ok(())
}

/// Make every regular file and directory in a fully built Git repository
/// durable before an authority handoff.
///
/// The traversal rejects symbolic links and unsupported filesystem objects,
/// flushes children before parents, and opens Unix files/directories with
/// `NOFOLLOW`. Namespace publication must still durably sync the destination
/// parent after moving this tree into place.
pub fn sync_git_repository_for_authority_handoff(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| GitError::io(path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(GitError::InvalidSnapshot(format!(
            "staged Git repository contains a symbolic link at {}",
            path.display()
        )));
    }
    if metadata.is_file() {
        return sync_publication_file(path);
    }
    if !metadata.is_dir() {
        return Err(GitError::InvalidSnapshot(format!(
            "staged Git repository contains an unsupported filesystem object at {}",
            path.display()
        )));
    }

    let children = fs::read_dir(path)
        .map_err(|error| GitError::io(path, error))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| GitError::io(path, error))
        })
        .collect::<Result<Vec<_>>>()?;
    for child in children {
        sync_git_repository_for_authority_handoff(&child)?;
    }
    sync_publication_directory(path)
}

#[cfg(unix)]
fn sync_publication_file(path: &Path) -> Result<()> {
    let file = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map(fs::File::from)
    .map_err(|error| GitError::io(path, error.into()))?;
    if !file
        .metadata()
        .map_err(|error| GitError::io(path, error))?
        .is_file()
    {
        return Err(GitError::InvalidSnapshot(format!(
            "staged Git file changed kind while syncing {}",
            path.display()
        )));
    }
    file.sync_all().map_err(|error| GitError::io(path, error))
}

#[cfg(windows)]
fn sync_publication_file(path: &Path) -> Result<()> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| GitError::io(path, error))?;
    if !file
        .metadata()
        .map_err(|error| GitError::io(path, error))?
        .is_file()
    {
        return Err(GitError::InvalidSnapshot(format!(
            "staged Git file changed kind while syncing {}",
            path.display()
        )));
    }
    file.sync_all().map_err(|error| GitError::io(path, error))
}

#[cfg(not(any(unix, windows)))]
fn sync_publication_file(path: &Path) -> Result<()> {
    Err(GitError::Other(format!(
        "durable Git publication is unsupported on this platform: {}",
        path.display()
    )))
}

#[cfg(unix)]
fn sync_publication_directory(path: &Path) -> Result<()> {
    let directory = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map(fs::File::from)
    .map_err(|error| GitError::io(path, error.into()))?;
    directory
        .sync_all()
        .map_err(|error| GitError::io(path, error))
}

#[cfg(windows)]
fn sync_publication_directory(path: &Path) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| GitError::io(path, error))?;
    directory
        .sync_all()
        .map_err(|error| GitError::io(path, error))
}

#[cfg(not(any(unix, windows)))]
fn sync_publication_directory(path: &Path) -> Result<()> {
    Err(GitError::Other(format!(
        "durable Git directory publication is unsupported on this platform: {}",
        path.display()
    )))
}

fn build_staging_repository(
    snapshot: &LosslessGitRepository,
    bodies: &BTreeMap<ExternalObjectId, Vec<u8>>,
    blob_store: &BlobStore,
    staging: &Path,
) -> Result<()> {
    let repo = gix::init_bare(staging)
        .map_err(|error| GitError::Git(format!("initialize {}: {error}", staging.display())))?;

    for record in &snapshot.objects {
        let body = bodies
            .get(&record.object)
            .expect("validated snapshot has every descriptor body");
        let written = repo
            .write_buf(gix_kind(record.object.kind), body)
            .map_err(|error| {
                GitError::Git(format!("write object {}: {error}", record.object.oid))
            })?;
        let written = git_object_id(written)?;
        if written != record.object.oid {
            return Err(GitError::InvalidSnapshot(format!(
                "writing object {} produced {written}",
                record.object.oid
            )));
        }
    }

    let mut edits = Vec::with_capacity(snapshot.refs.refs.len() + 1);
    for repository_ref in &snapshot.refs.refs {
        edits.push(ref_edit(
            repository_ref.name.as_bytes(),
            &repository_ref.target,
        )?);
    }
    edits.push(head_edit(&snapshot.head)?);
    repo.edit_references_as(edits, None)
        .map_err(|error| GitError::Git(format!("write refs and HEAD: {error}")))?;
    drop(repo);

    let recaptured =
        capture_lossless_git_repository(staging, snapshot.repository_id.clone(), blob_store)?;
    if recaptured != *snapshot {
        return Err(GitError::InvalidSnapshot(
            "rehydrated repository did not recapture byte-exactly".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn ref_edit(name: &[u8], target: &RefTarget) -> Result<gix::refs::transaction::RefEdit> {
    let name = gix::bstr::BString::from(name.to_vec())
        .try_into()
        .map_err(|error| GitError::InvalidSnapshot(format!("invalid Git ref name: {error}")))?;
    Ok(gix::refs::transaction::RefEdit {
        name,
        deref: false,
        change: gix::refs::transaction::Change::Update {
            expected: gix::refs::transaction::PreviousValue::MustNotExist,
            new: gix_ref_target(target)?,
            log: gix::refs::transaction::LogChange {
                mode: gix::refs::transaction::RefLog::AndReference,
                force_create_reflog: false,
                message: gix::bstr::BString::default(),
            },
        },
    })
}

pub(crate) fn head_edit(head: &WorkspaceHead) -> Result<gix::refs::transaction::RefEdit> {
    let target = match head {
        WorkspaceHead::Symbolic { target } => {
            gix::refs::Target::Symbolic(gix_full_name(target.as_bytes())?)
        }
        WorkspaceHead::Detached { target } => gix_ref_target(target)?,
    };
    Ok(gix::refs::transaction::RefEdit {
        name: "HEAD"
            .try_into()
            .map_err(|error| GitError::InvalidSnapshot(format!("invalid HEAD name: {error}")))?,
        deref: false,
        change: gix::refs::transaction::Change::Update {
            expected: gix::refs::transaction::PreviousValue::Any,
            new: target,
            log: gix::refs::transaction::LogChange {
                mode: gix::refs::transaction::RefLog::AndReference,
                force_create_reflog: false,
                message: gix::bstr::BString::default(),
            },
        },
    })
}

fn gix_ref_target(target: &RefTarget) -> Result<gix::refs::Target> {
    match target {
        RefTarget::ExternalObject { object } => {
            Ok(gix::refs::Target::Object(gix_object_id(object.oid)?))
        }
        RefTarget::Symbolic { target } => Ok(gix::refs::Target::Symbolic(gix_full_name(
            target.as_bytes(),
        )?)),
        RefTarget::Change { change_id } => Err(GitError::InvalidSnapshot(format!(
            "exact Git ref cannot target native Kin change {change_id}"
        ))),
    }
}

fn gix_full_name(bytes: &[u8]) -> Result<gix::refs::FullName> {
    gix::bstr::BString::from(bytes.to_vec())
        .try_into()
        .map_err(|error| GitError::InvalidSnapshot(format!("invalid Git ref name: {error}")))
}

fn display_bytes(bytes: &[u8]) -> String {
    bytes.as_bstr().to_str_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::process::Output;

    use pretty_assertions::assert_eq;
    use tempfile::{tempdir, TempDir};

    use super::*;
    use crate::test_support::fixture_git;

    /// Gitlink target recorded by the polyglot fixture, which is never a
    /// capturable object in the source repository.
    #[cfg(unix)]
    const POLYGLOT_GITLINK_OID: &str = "4242424242424242424242424242424242424242";

    struct Fixture {
        _root: TempDir,
        repo: PathBuf,
        cas_root: PathBuf,
        blob_store: BlobStore,
        first_commit: String,
    }

    #[cfg(unix)]
    #[test]
    fn durable_publication_rejects_an_unflushable_staging_tree_before_rename() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let mut staging = claim_staging_path(root.path()).unwrap();
        let staging_path = staging.path().to_path_buf();
        let destination = root.path().join("published.git");
        fs::write(staging_path.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        symlink("HEAD", staging_path.join("raced-link")).unwrap();

        let error = publish_staging(&mut staging, &destination)
            .expect_err("publication must flush and validate the complete stage before rename");
        assert!(
            error.to_string().contains("symbolic link"),
            "unexpected durable-publication error: {error}"
        );
        assert!(
            staging_path.is_dir(),
            "failed prepublication durability proof must retain the private stage"
        );
        assert!(
            !destination.exists(),
            "failed durability proof must not expose a destination"
        );
    }

    #[cfg(unix)]
    #[test]
    fn destination_parent_sync_failure_rolls_back_to_the_durable_private_stage() {
        let root = tempdir().unwrap();
        let mut staging = claim_staging_path(root.path()).unwrap();
        let staging_path = staging.path().to_path_buf();
        let destination = root.path().join("published.git");
        fs::write(staging_path.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        inject_next_publication_parent_sync_failure();

        let error = publish_staging(&mut staging, &destination)
            .expect_err("an unacknowledged destination namespace must not remain published");
        assert!(
            error.to_string().contains("retained-parent publication")
                && error
                    .to_string()
                    .contains("restored the private staging name"),
            "unexpected parent-sync failure: {error}"
        );
        assert!(
            staging_path.is_dir(),
            "failed destination sync must restore the durable private stage"
        );
        assert!(
            staging_path.join("HEAD").is_file(),
            "durable stage contents must survive namespace rollback"
        );
        assert!(
            !destination.exists(),
            "destination whose parent was not synced must be unpublished"
        );
    }

    #[cfg(unix)]
    #[test]
    fn publication_parent_replacement_rolls_back_without_touching_replacement_namespace() {
        let outer = tempdir().unwrap();
        let parent = outer.path().join("publication-parent");
        let displaced_parent = outer.path().join("publication-parent.displaced");
        fs::create_dir(&parent).unwrap();
        let mut staging = claim_staging_path(&parent).unwrap();
        let staging_name = staging.name.clone();
        fs::write(staging.path().join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        let destination = parent.join("published.git");

        let error = publish_staging_with_hook(&mut staging, &destination, |point| {
            if point == PublicationHookPoint::AfterNamespaceMutation {
                fs::rename(&parent, &displaced_parent).unwrap();
                fs::create_dir(&parent).unwrap();
                fs::write(parent.join("replacement-marker"), b"replacement").unwrap();
            }
        })
        .expect_err("a replaced visible publication parent must block success");

        assert!(error.to_string().contains("publication parent"));
        assert_eq!(
            fs::read(parent.join("replacement-marker")).unwrap(),
            b"replacement"
        );
        assert!(!parent.join("published.git").exists());
        assert!(!parent.join(&staging_name).exists());
        assert!(!displaced_parent.join("published.git").exists());
        assert!(displaced_parent.join(&staging_name).is_dir());
        assert_eq!(
            fs::read(displaced_parent.join(&staging_name).join("HEAD")).unwrap(),
            b"ref: refs/heads/main\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn staging_cleanup_cannot_delete_from_a_replacement_parent() {
        let outer = tempdir().unwrap();
        let parent = outer.path().join("publication-parent");
        let displaced_parent = outer.path().join("publication-parent.displaced");
        fs::create_dir(&parent).unwrap();
        let mut staging = claim_staging_path(&parent).unwrap();
        let staging_name = staging.name.clone();
        fs::write(staging.path().join("owned-marker"), b"owned").unwrap();

        fs::rename(&parent, &displaced_parent).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::create_dir(parent.join(&staging_name)).unwrap();
        fs::write(
            parent.join(&staging_name).join("replacement-marker"),
            b"replacement",
        )
        .unwrap();

        staging
            .cleanup()
            .expect("cleanup must stay bound to the retained original parent");

        assert_eq!(
            fs::read(parent.join(&staging_name).join("replacement-marker")).unwrap(),
            b"replacement"
        );
        assert!(!displaced_parent.join(&staging_name).exists());
    }

    impl Fixture {
        #[cfg(unix)]
        fn polyglot() -> Self {
            use std::os::unix::fs::{symlink, PermissionsExt};

            let root = tempdir().unwrap();
            let repo = root.path().join("source");
            fs::create_dir(&repo).unwrap();
            git_ok(&repo, ["init", "--initial-branch=main"]);
            configure_git(&repo);

            write(&repo, "Cargo.toml", b"[package]\nname = \"mixed\"\n");
            write(&repo, "src/lib.rs", b"pub fn rust_value() -> u8 { 7 }\n");
            write(
                &repo,
                "package.json",
                br#"{"scripts":{"test":"node src/app.ts"}}"#,
            );
            write(&repo, "src/app.ts", b"export const tsValue: number = 8;\n");
            write(
                &repo,
                "pyproject.toml",
                b"[project]\nname = \"mixed-python\"\n",
            );
            write(
                &repo,
                "python/app.py",
                b"def python_value():\n    return 9\n",
            );
            write(
                &repo,
                "compose.yaml",
                b"services:\n  app:\n    build: .\n    environment:\n      MODE: test\n",
            );
            write(
                &repo,
                "Dockerfile",
                b"FROM scratch\nCOPY config/app.yaml /app.yaml\n",
            );
            write(
                &repo,
                ".github/workflows/ci.yml",
                b"name: ci\non: [push]\njobs: {}\n",
            );
            write(&repo, "config/app.yaml", b"feature:\n  enabled: true\n");
            write(
                &repo,
                "NOTICE.txt",
                b"This is unrelated legal and operational text.\n",
            );
            write(&repo, "assets/raw.bin", &[0, 255, 1, 128, b'\n', 0, 42]);
            write(&repo, "scripts/tool.sh", b"#!/bin/sh\nprintf 'kin\\n'\n");
            let executable = repo.join("scripts/tool.sh");
            let mut permissions = fs::metadata(&executable).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&executable, permissions).unwrap();
            symlink("config/app.yaml", repo.join("config-link")).unwrap();

            git_ok(&repo, ["add", "--all"]);
            let non_utf8_oid = git_stdin_text(
                &repo,
                ["hash-object", "-w", "--stdin"],
                &[0xde, 0xad, 0xbe, 0xef],
            );
            let mut index_entry = format!("100644 {non_utf8_oid}\t").into_bytes();
            index_entry.extend_from_slice(b"odd-\xff.bin\0");
            git_stdin_ok(&repo, ["update-index", "-z", "--index-info"], &index_entry);
            git_ok(
                &repo,
                [
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    &format!("160000,{POLYGLOT_GITLINK_OID},vendor/sub"),
                ],
            );
            git_ok(&repo, ["commit", "-m", "initial exact tree"]);
            let first_commit = git_text(&repo, ["rev-parse", "HEAD"]);

            git_ok(&repo, ["switch", "-c", "feature"]);
            write(&repo, "src/app.ts", b"export const tsValue: number = 10;\n");
            git_ok(&repo, ["add", "src/app.ts"]);
            git_ok(&repo, ["commit", "-m", "change typescript"]);

            git_ok(&repo, ["switch", "main"]);
            write(
                &repo,
                "python/app.py",
                b"def python_value():\n    return 11\n",
            );
            git_ok(&repo, ["add", "python/app.py"]);
            git_ok(&repo, ["commit", "-m", "change python"]);
            git_ok(
                &repo,
                ["merge", "--no-ff", "feature", "-m", "merge feature"],
            );
            git_ok(&repo, ["tag", "-a", "release-v1", "-m", "annotated"]);
            git_ok(&repo, ["tag", "lightweight", &first_commit]);
            let merge_commit = git_text(&repo, ["rev-parse", "HEAD"]);
            git_ok(&repo, ["replace", &first_commit, &merge_commit]);
            git_ok(
                &repo,
                ["symbolic-ref", "refs/aliases/stable", "refs/heads/main"],
            );

            let cas_root = root.path().join("cas");
            let blob_store = BlobStore::new(cas_root.clone()).unwrap();
            Self {
                _root: root,
                repo,
                cas_root,
                blob_store,
                first_commit,
            }
        }

        fn simple() -> Self {
            let root = tempdir().unwrap();
            let repo = root.path().join("source");
            fs::create_dir(&repo).unwrap();
            git_ok(&repo, ["init", "--initial-branch=main"]);
            configure_git(&repo);
            write(&repo, "README.md", b"exact\n");
            git_ok(&repo, ["add", "README.md"]);
            git_ok(&repo, ["commit", "-m", "initial"]);
            let first_commit = git_text(&repo, ["rev-parse", "HEAD"]);
            let cas_root = root.path().join("cas");
            let blob_store = BlobStore::new(cas_root.clone()).unwrap();
            Self {
                _root: root,
                repo,
                cas_root,
                blob_store,
                first_commit,
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn polyglot_repository_roundtrips_every_object_ref_and_head_exactly() {
        let fixture = Fixture::polyglot();
        let repository_id = RepositoryId::new("polyglot").unwrap();
        let snapshot = capture_lossless_git_repository(
            &fixture.repo,
            repository_id.clone(),
            &fixture.blob_store,
        )
        .unwrap();

        assert!(snapshot
            .objects
            .iter()
            .any(|record| record.object.kind == ExternalObjectKind::Tag));
        assert!(snapshot
            .objects
            .iter()
            .any(|record| record.object.kind == ExternalObjectKind::Commit));
        assert!(snapshot
            .objects
            .iter()
            .any(|record| record.object.kind == ExternalObjectKind::Tree));
        assert!(snapshot
            .objects
            .iter()
            .any(|record| record.object.kind == ExternalObjectKind::Blob));
        assert!(!snapshot
            .objects
            .iter()
            .any(|record| record.object.oid.to_string() == POLYGLOT_GITLINK_OID));
        assert_eq!(
            snapshot.refs.default_ref.as_ref().unwrap().as_bytes(),
            b"refs/heads/main"
        );
        assert!(snapshot.refs.refs.iter().any(|repository_ref| {
            repository_ref.name.as_bytes() == b"refs/tags/release-v1"
                && matches!(
                    repository_ref.target,
                    RefTarget::ExternalObject {
                        object: ExternalObjectId {
                            kind: ExternalObjectKind::Tag,
                            ..
                        }
                    }
                )
        }));
        assert!(snapshot.refs.refs.iter().any(|repository_ref| {
            repository_ref.name.as_bytes() == b"refs/tags/lightweight"
                && matches!(
                    repository_ref.target,
                    RefTarget::ExternalObject {
                        object: ExternalObjectId {
                            kind: ExternalObjectKind::Commit,
                            ..
                        }
                    }
                )
        }));
        assert!(snapshot.refs.refs.iter().any(|repository_ref| {
            repository_ref.name.as_bytes() == b"refs/aliases/stable"
                && matches!(
                    &repository_ref.target,
                    RefTarget::Symbolic { target }
                        if target.as_bytes() == b"refs/heads/main"
                )
        }));
        assert!(snapshot
            .refs
            .refs
            .iter()
            .any(|repository_ref| repository_ref.name.as_bytes().starts_with(b"refs/replace/")));

        let output = fixture._root.path().join("rehydrated.git");
        let result =
            rehydrate_lossless_git_repository(&snapshot, &fixture.blob_store, &output).unwrap();
        assert_eq!(result.objects_written, snapshot.objects.len());
        assert_eq!(result.refs_written, snapshot.refs.refs.len());
        let recaptured =
            capture_lossless_git_repository(&output, repository_id, &fixture.blob_store).unwrap();
        assert_eq!(recaptured, snapshot);
        assert_raw_objects_match(&output, &snapshot, &fixture.blob_store);

        let tree = git_bytes(&output, ["ls-tree", "-r", "-z", "refs/heads/main"]);
        assert!(tree
            .windows(b"100755 blob ".len())
            .any(|window| window == b"100755 blob "));
        assert!(tree
            .windows(b"120000 blob ".len())
            .any(|window| window == b"120000 blob "));
        assert!(tree
            .windows(b"160000 commit ".len())
            .any(|window| window == b"160000 commit "));
        for path in [
            b"Cargo.toml".as_slice(),
            b"src/lib.rs",
            b"src/app.ts",
            b"python/app.py",
            b"compose.yaml",
            b"Dockerfile",
            b".github/workflows/ci.yml",
            b"config/app.yaml",
            b"NOTICE.txt",
            b"assets/raw.bin",
            b"odd-\xff.bin",
        ] {
            assert!(
                tree.windows(path.len()).any(|window| window == path),
                "missing path bytes {}",
                hex::encode(path)
            );
        }

        git_ok(
            &fixture.repo,
            ["checkout", "--detach", &fixture.first_commit],
        );
        let detached = capture_lossless_git_repository(
            &fixture.repo,
            RepositoryId::new("detached").unwrap(),
            &fixture.blob_store,
        )
        .unwrap();
        assert!(matches!(detached.head, WorkspaceHead::Detached { .. }));
        assert!(detached.refs.default_ref.is_none());
        let detached_output = fixture._root.path().join("detached.git");
        rehydrate_lossless_git_repository(&detached, &fixture.blob_store, &detached_output)
            .unwrap();
        assert_eq!(
            capture_lossless_git_repository(
                &detached_output,
                RepositoryId::new("detached").unwrap(),
                &fixture.blob_store,
            )
            .unwrap(),
            detached
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn lossless_publication_fails_closed_off_unix() {
        let root = tempdir().unwrap();
        let source = root.path().join("unborn");
        fs::create_dir(&source).unwrap();
        git_ok(&source, ["init", "--initial-branch=future"]);
        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let repository_id = RepositoryId::new("unborn").unwrap();
        let snapshot =
            capture_lossless_git_repository(&source, repository_id, &blob_store).unwrap();

        let output = root.path().join("rehydrated.git");
        let error = rehydrate_lossless_git_repository(&snapshot, &blob_store, &output)
            .expect_err("retained-capability publication must fail closed off unix");
        assert!(
            error.to_string().contains("unsupported on this platform"),
            "unexpected error: {error}"
        );
        assert!(!output.exists());
    }

    #[cfg(unix)]
    #[test]
    fn unborn_head_roundtrips_without_inventing_objects_or_refs() {
        let root = tempdir().unwrap();
        let source = root.path().join("unborn");
        fs::create_dir(&source).unwrap();
        git_ok(&source, ["init", "--initial-branch=future"]);
        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let repository_id = RepositoryId::new("unborn").unwrap();
        let snapshot =
            capture_lossless_git_repository(&source, repository_id.clone(), &blob_store).unwrap();

        assert!(snapshot.objects.is_empty());
        assert!(snapshot.refs.refs.is_empty());
        assert_eq!(
            snapshot.refs.default_ref.as_ref().unwrap().as_bytes(),
            b"refs/heads/future"
        );
        assert!(matches!(
            &snapshot.head,
            WorkspaceHead::Symbolic { target } if target.as_bytes() == b"refs/heads/future"
        ));

        let output = root.path().join("rehydrated.git");
        rehydrate_lossless_git_repository(&snapshot, &blob_store, &output).unwrap();
        let recaptured =
            capture_lossless_git_repository(&output, repository_id, &blob_store).unwrap();
        assert_eq!(recaptured, snapshot);
    }

    #[test]
    fn tampered_descriptor_and_cas_body_fail_before_destination_publication() {
        let fixture = Fixture::simple();
        let snapshot = capture_lossless_git_repository(
            &fixture.repo,
            RepositoryId::new("tamper").unwrap(),
            &fixture.blob_store,
        )
        .unwrap();

        let mut descriptor_tamper = snapshot.clone();
        descriptor_tamper.objects[0].body_len += 1;
        let descriptor_output = fixture._root.path().join("descriptor.git");
        assert!(matches!(
            rehydrate_lossless_git_repository(
                &descriptor_tamper,
                &fixture.blob_store,
                &descriptor_output
            ),
            Err(GitError::InvalidSnapshot(_))
        ));
        assert!(!descriptor_output.exists());

        let corrupt = &snapshot.objects[0];
        fs::write(cas_path(&fixture.cas_root, &corrupt.body_hash), b"tampered").unwrap();
        let cas_output = fixture._root.path().join("cas.git");
        assert!(matches!(
            rehydrate_lossless_git_repository(&snapshot, &fixture.blob_store, &cas_output),
            Err(GitError::Blob(_))
        ));
        assert!(!cas_output.exists());
    }

    #[test]
    fn a_warm_shared_closure_never_satisfies_rehydrations_cas_proof() {
        let fixture = Fixture::simple();
        let snapshot = capture_lossless_git_repository(
            &fixture.repo,
            RepositoryId::new("warm-closure").unwrap(),
            &fixture.blob_store,
        )
        .unwrap();

        // Assert the cache is warm rather than assume it. A body deleted while
        // the cache is cold gets re-read by any implementation, so that test
        // passes whatever rehydration does and would stop guarding this
        // boundary without ever failing.
        let before = closure_reconstruction_count();
        validate_snapshot(&snapshot, &fixture.blob_store).unwrap();
        assert_eq!(
            closure_reconstruction_count(),
            before,
            "a second shared validation of one object set must hit the cache",
        );

        fixture
            .blob_store
            .delete(&snapshot.objects[0].body_hash)
            .unwrap();

        // The shared closure is now stale in the only way it can be: the
        // descriptors are untouched, so the key still matches, and it still
        // hands out a body the CAS can no longer supply.
        let served = validate_snapshot(&snapshot, &fixture.blob_store).unwrap();
        assert!(
            served.contains_key(&snapshot.objects[0].object),
            "the shared closure must still hold the deleted body for this to prove anything",
        );

        // Rehydration reads fresh, so it fails closed on the CAS rather than
        // exporting from bytes nobody re-read.
        let output = fixture._root.path().join("warm-closure.git");
        assert!(matches!(
            rehydrate_lossless_git_repository(&snapshot, &fixture.blob_store, &output),
            Err(GitError::Blob(kin_blobs::BlobError::NotFound { .. }))
        ));
        assert!(!output.exists());
    }

    #[test]
    fn missing_cas_body_and_existing_destination_fail_closed() {
        let fixture = Fixture::simple();
        let snapshot = capture_lossless_git_repository(
            &fixture.repo,
            RepositoryId::new("missing-cas").unwrap(),
            &fixture.blob_store,
        )
        .unwrap();

        let existing = fixture._root.path().join("existing");
        fs::create_dir(&existing).unwrap();
        assert!(matches!(
            rehydrate_lossless_git_repository(&snapshot, &fixture.blob_store, &existing),
            Err(GitError::DestinationExists(_))
        ));

        fixture
            .blob_store
            .delete(&snapshot.objects[0].body_hash)
            .unwrap();
        let missing_output = fixture._root.path().join("missing-cas.git");
        assert!(matches!(
            rehydrate_lossless_git_repository(&snapshot, &fixture.blob_store, &missing_output),
            Err(GitError::Blob(kin_blobs::BlobError::NotFound { .. }))
        ));
        assert!(!missing_output.exists());
    }

    #[test]
    fn missing_source_object_and_shallow_repository_fail_closed() {
        let missing = Fixture::simple();
        let tree_oid = git_text(&missing.repo, ["rev-parse", "HEAD^{tree}"]);
        let object_path = loose_object_path(&missing.repo.join(".git"), &tree_oid);
        assert!(object_path.is_file());
        fs::remove_file(&object_path).unwrap();
        assert!(matches!(
            capture_lossless_git_repository(
                &missing.repo,
                RepositoryId::new("missing").unwrap(),
                &missing.blob_store,
            ),
            Err(GitError::MissingObject { .. }) | Err(GitError::CorruptObject { .. })
        ));

        let shallow = Fixture::simple();
        fs::write(
            shallow.repo.join(".git/shallow"),
            format!("{}\n", shallow.first_commit),
        )
        .unwrap();
        assert!(matches!(
            capture_lossless_git_repository(
                &shallow.repo,
                RepositoryId::new("shallow").unwrap(),
                &shallow.blob_store,
            ),
            Err(GitError::ShallowRepository)
        ));
    }

    /// `actions/checkout` clones at depth 1 by default, so this refusal is the
    /// first thing Kin says to anyone trying it inside GitHub Actions. Stating
    /// the property that was violated without stating the one command that fixes
    /// it leaves that user with nothing to do.
    #[test]
    fn the_shallow_refusal_names_its_recovery_command() {
        let message = GitError::ShallowRepository.to_string();
        assert!(
            message.contains("shallow Git repositories cannot be imported losslessly"),
            "the reason for the refusal is unchanged: {message}"
        );
        assert!(
            message.contains("git fetch --unshallow"),
            "must name the recovery command: {message}"
        );
        assert!(
            message.contains("fetch-depth: 0"),
            "must name the CI form of the same fix: {message}"
        );
    }

    #[test]
    fn sha256_capture_is_exact_but_rehydration_fails_before_creating_output() {
        let root = tempdir().unwrap();
        let source = root.path().join("sha256-source");
        fs::create_dir(&source).unwrap();
        git_ok(
            &source,
            ["init", "--object-format=sha256", "--initial-branch=main"],
        );
        configure_git(&source);
        write(
            &source,
            "compose.yaml",
            b"services:\n  api:\n    image: kin\n",
        );
        write(&source, "src/main.rs", b"fn main() {}\n");
        git_ok(&source, ["add", "--all"]);
        git_ok(&source, ["commit", "-m", "sha256 source"]);
        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &source,
            RepositoryId::new("sha256").unwrap(),
            &blob_store,
        )
        .unwrap();
        assert_eq!(snapshot.object_format, GitObjectFormat::Sha256);
        assert!(!snapshot.objects.is_empty());
        assert!(snapshot
            .objects
            .iter()
            .all(|record| matches!(record.object.oid, GitObjectId::Sha256(_))));
        validate_snapshot(&snapshot, &blob_store).unwrap();

        let output = root.path().join("sha256.git");
        assert!(matches!(
            rehydrate_lossless_git_repository(&snapshot, &blob_store, &output),
            Err(GitError::UnsupportedObjectFormat(format)) if format == "sha256"
        ));
        assert!(!output.exists());
    }

    fn configure_git(repo: &Path) {
        git_ok(repo, ["config", "user.name", "Kin Test"]);
        git_ok(repo, ["config", "user.email", "kin@example.invalid"]);
        git_ok(repo, ["config", "commit.gpgsign", "false"]);
        git_ok(repo, ["config", "tag.gpgsign", "false"]);
        git_ok(repo, ["config", "core.autocrlf", "false"]);
        git_ok(repo, ["config", "core.filemode", "true"]);
    }

    fn write(repo: &Path, path: &str, body: &[u8]) {
        let path = repo.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    fn git_ok<I, S>(repo: &Path, args: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = git_output(repo, args);
        assert!(
            output.status.success(),
            "git failed ({}):\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_text<I, S>(repo: &Path, args: I) -> String
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        String::from_utf8(git_bytes(repo, args))
            .unwrap()
            .trim()
            .to_string()
    }

    fn git_bytes<I, S>(repo: &Path, args: I) -> Vec<u8>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = git_output(repo, args);
        assert!(
            output.status.success(),
            "git failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn git_output<I, S>(repo: &Path, args: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        fixture_git().args(args).current_dir(repo).output().unwrap()
    }

    #[cfg(unix)]
    fn git_stdin_ok<I, S>(repo: &Path, args: I, stdin: &[u8])
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = git_stdin_output(repo, args, stdin);
        assert!(
            output.status.success(),
            "git failed ({}):\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    fn git_stdin_text<I, S>(repo: &Path, args: I, stdin: &[u8]) -> String
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = git_stdin_output(repo, args, stdin);
        assert!(
            output.status.success(),
            "git failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    #[cfg(unix)]
    fn git_stdin_output<I, S>(repo: &Path, args: I, stdin: &[u8]) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        fixture_git()
            .args(args)
            .current_dir(repo)
            .output_with_input(stdin)
            .unwrap()
    }

    #[cfg(unix)]
    fn assert_raw_objects_match(
        repo_path: &Path,
        snapshot: &LosslessGitRepository,
        blob_store: &BlobStore,
    ) {
        let repo = open_repo(repo_path).unwrap();
        for record in &snapshot.objects {
            let oid = gix_object_id(record.object.oid).unwrap();
            let object = repo.find_object(oid).unwrap();
            assert_eq!(external_kind(object.kind), record.object.kind);
            assert_eq!(object.data, blob_store.read(&record.body_hash).unwrap());
        }
    }

    fn cas_path(root: &Path, hash: &kin_model::Hash256) -> PathBuf {
        let hex = hash.to_string();
        root.join(&hex[..2]).join(&hex[2..])
    }

    fn loose_object_path(git_dir: &Path, oid: &str) -> PathBuf {
        git_dir.join("objects").join(&oid[..2]).join(&oid[2..])
    }
}
