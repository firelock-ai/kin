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
use std::fs;
use std::path::{Path, PathBuf};
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

static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
/// built in a private sibling directory, recaptured exactly, and atomically
/// renamed into place. SHA-256 fails before creating any output until gix's
/// writer is enabled and covered by the same exact acceptance gate.
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
    let bodies = validate_snapshot(snapshot, blob_store)?;

    let parent = output_path.parent().ok_or_else(|| {
        GitError::InvalidSnapshot(format!(
            "rehydration destination {} has no parent",
            output_path.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|error| GitError::io(parent, error))?;
    let staging = claim_staging_path(parent)?;
    let build_result = build_staging_repository(snapshot, &bodies, blob_store, &staging);
    if let Err(error) = build_result {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    if let Err(error) = publish_staging(&staging, output_path) {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }

    Ok(GitRehydrationResult {
        git_repo_path: output_path.to_path_buf(),
        objects_written: snapshot.objects.len(),
        refs_written: snapshot.refs.refs.len(),
    })
}

fn open_repo(path: &Path) -> Result<gix::Repository> {
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

fn reject_shallow_repository(repo: &gix::Repository) -> Result<()> {
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

fn validate_snapshot(
    snapshot: &LosslessGitRepository,
    blob_store: &BlobStore,
) -> Result<BTreeMap<ExternalObjectId, Vec<u8>>> {
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

    validate_reachable_closure(snapshot, &bodies)?;
    Ok(bodies)
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

fn reject_existing_destination(output_path: &Path) -> Result<()> {
    match fs::symlink_metadata(output_path) {
        Ok(_) => Err(GitError::DestinationExists(
            output_path.display().to_string(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(GitError::io(output_path, error)),
    }
}

fn claim_staging_path(parent: &Path) -> Result<PathBuf> {
    loop {
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".kin-git-rehydrate-{}-{sequence}",
            std::process::id()
        ));
        match create_private_directory(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(GitError::io(&candidate, error)),
        }
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
fn publish_staging(staging: &Path, output_path: &Path) -> Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staging,
        rustix::fs::CWD,
        output_path,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            GitError::DestinationExists(output_path.display().to_string())
        } else {
            GitError::io(output_path, error.into())
        }
    })
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
)))]
fn publish_staging(staging: &Path, output_path: &Path) -> Result<()> {
    // Windows rename already fails when the destination exists. Other targets
    // retain the explicit preflight check and fail any rename error closed.
    reject_existing_destination(output_path)?;
    fs::rename(staging, output_path).map_err(|error| GitError::io(output_path, error))
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

fn ref_edit(name: &[u8], target: &RefTarget) -> Result<gix::refs::transaction::RefEdit> {
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

fn head_edit(head: &WorkspaceHead) -> Result<gix::refs::transaction::RefEdit> {
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
    use std::io::Write as _;
    use std::process::{Command, Output};

    use pretty_assertions::assert_eq;
    use tempfile::{tempdir, TempDir};

    use super::*;

    struct Fixture {
        _root: TempDir,
        repo: PathBuf,
        cas_root: PathBuf,
        blob_store: BlobStore,
        first_commit: String,
        gitlink_oid: String,
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
            let gitlink_oid = "4242424242424242424242424242424242424242".to_string();
            git_ok(
                &repo,
                [
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    &format!("160000,{gitlink_oid},vendor/sub"),
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
                gitlink_oid,
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
                gitlink_oid: String::new(),
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
            .any(|record| record.object.oid.to_string() == fixture.gitlink_oid));
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
        Command::new("git")
            .args(args)
            .current_dir(repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", repo)
            .output()
            .unwrap()
    }

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

    fn git_stdin_output<I, S>(repo: &Path, args: I, stdin: &[u8]) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut child = Command::new("git")
            .args(args)
            .current_dir(repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", repo)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        child.wait_with_output().unwrap()
    }

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
