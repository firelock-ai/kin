// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Retained local repository-authority capability.
//!
//! Long-lived product processes must bind repository identity, workspace
//! identity, and the local storage root once at startup. Passing this value
//! through daemon-owned command and MCP handlers prevents a later request from
//! rediscovering mutable manifests or blessing a replaced `.kin/kindb` path.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use kin_db::{
    AuthorityPayloadStats, LocalFileBackend, LocalNamespaceProbe, RepositoryAuthorityManager,
    RepositoryAuthorityState, StorageBackend,
};
use kin_model::{
    EntityDelta, EntityId, RelationDelta, RelationId, RepositoryId, SemanticChangeId, WorkspaceId,
};

use crate::{KinError, KinLayout, KinManifest, Result};

/// Exact semantic counts derived from one immutable repository-authority lease.
///
/// This is deliberately not a summary of the daemon's mutable query graph.
/// Runtime reconcile and LSP work may add derived state to that live graph
/// without changing repository-v6 authority. The generations here identify the
/// durable view this summary answers for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableSemanticEnrichmentSummary {
    pub authority_generation: u64,
    pub workspace_generation: u64,
    pub entity_count: usize,
    pub relation_count: usize,
    /// Repository-wide immutable semantic changes sealed by this authority
    /// generation. Entity and relation counts remain workspace-scoped.
    pub semantic_change_count: usize,
}

/// Summarize one durable workspace without materializing its complete query graph.
///
/// Repository authority already validated every semantic payload and the
/// first-parent lineage semantics during admission. This read therefore needs
/// only to replay entity/relation identities along the workspace's exact base
/// lineage, then apply its cumulative semantic overlay. It does not clone a
/// graph snapshot, reconstruct the exact tree, read source CAS bodies, build
/// indices, or mix another authority generation into the result.
pub fn durable_semantic_enrichment_summary(
    authority: &RepositoryAuthorityState,
    workspace_id: &WorkspaceId,
) -> Result<DurableSemanticEnrichmentSummary> {
    let workspace = RepositoryAuthorityState::metadata(authority)
        .workspaces
        .iter()
        .find(|workspace| &workspace.workspace_id == workspace_id)
        .ok_or_else(|| {
            KinError::Graph(format!(
                "this repository's authority has no workspace {workspace_id}"
            ))
        })?;
    workspace
        .validate()
        .map_err(|error| KinError::Graph(error.to_string()))?;

    let mut entity_ids = HashSet::new();
    let mut relation_ids = HashSet::new();
    if let Some(target) = workspace.base_target.as_ref() {
        let head = authority
            .resolve_target_change_id(target)
            .map_err(|error| KinError::Graph(error.to_string()))?;
        replay_first_parent_semantic_ids(authority, head, &mut entity_ids, &mut relation_ids)?;
    }
    apply_entity_deltas(
        &mut entity_ids,
        workspace.semantic_overlay.entity_deltas(),
        "workspace semantic overlay",
    )?;
    apply_relation_deltas(
        &mut relation_ids,
        workspace.semantic_overlay.relation_deltas(),
        "workspace semantic overlay",
    )?;

    Ok(DurableSemanticEnrichmentSummary {
        authority_generation: authority.roots().generation,
        workspace_generation: workspace.generation,
        entity_count: entity_ids.len(),
        relation_count: relation_ids.len(),
        semantic_change_count: authority.snapshot().changes.len(),
    })
}

fn replay_first_parent_semantic_ids(
    authority: &RepositoryAuthorityState,
    head: SemanticChangeId,
    entity_ids: &mut HashSet<EntityId>,
    relation_ids: &mut HashSet<RelationId>,
) -> Result<()> {
    let changes = &authority.snapshot().changes;
    let mut reverse_lineage = Vec::new();
    let mut seen = HashSet::new();
    let mut current = Some(head);
    while let Some(change_id) = current {
        if !seen.insert(change_id) {
            return Err(KinError::Graph(format!(
                "cycle in durable first-parent history at change {change_id}"
            )));
        }
        let change = changes.get(&change_id).ok_or_else(|| {
            KinError::Graph(format!(
                "durable first-parent history is missing change {change_id}"
            ))
        })?;
        current = change.parents.first().copied();
        reverse_lineage.push(change);
    }

    for change in reverse_lineage.into_iter().rev() {
        let context = format!("semantic change {}", change.id);
        apply_entity_deltas(entity_ids, &change.entity_deltas, &context)?;
        apply_relation_deltas(relation_ids, &change.relation_deltas, &context)?;
    }
    Ok(())
}

fn apply_entity_deltas(
    ids: &mut HashSet<EntityId>,
    deltas: &[EntityDelta],
    context: &str,
) -> Result<()> {
    for delta in deltas {
        match delta {
            EntityDelta::Added { new } if !ids.insert(new.id) => {
                return Err(KinError::Graph(format!(
                    "{context} adds existing entity {}",
                    new.id
                )));
            }
            EntityDelta::Modified { old, new } => {
                if old.id != new.id || !ids.contains(&old.id) {
                    return Err(KinError::Graph(format!(
                        "{context} modifies missing or mismatched entity {}",
                        old.id
                    )));
                }
            }
            EntityDelta::Removed { old } if !ids.remove(&old.id) => {
                return Err(KinError::Graph(format!(
                    "{context} removes missing entity {}",
                    old.id
                )));
            }
            EntityDelta::Added { .. } | EntityDelta::Removed { .. } => {}
        }
    }
    Ok(())
}

fn apply_relation_deltas(
    ids: &mut HashSet<RelationId>,
    deltas: &[RelationDelta],
    context: &str,
) -> Result<()> {
    for delta in deltas {
        match delta {
            RelationDelta::Added { new } if !ids.insert(new.id) => {
                return Err(KinError::Graph(format!(
                    "{context} adds existing relation {}",
                    new.id
                )));
            }
            RelationDelta::Modified { old, new } => {
                if old.id != new.id || !ids.contains(&old.id) {
                    return Err(KinError::Graph(format!(
                        "{context} modifies missing or mismatched relation {}",
                        old.id
                    )));
                }
            }
            RelationDelta::Removed { old } if !ids.remove(&old.id) => {
                return Err(KinError::Graph(format!(
                    "{context} removes missing relation {}",
                    old.id
                )));
            }
            RelationDelta::Added { .. } | RelationDelta::Removed { .. } => {}
        }
    }
    Ok(())
}

/// Startup-pinned identity and storage capability for one local repository.
#[derive(Clone)]
pub struct LocalRepositoryAuthorityBinding {
    repository_id: RepositoryId,
    workspace_id: WorkspaceId,
    backend: Arc<LocalFileBackend>,
}

impl fmt::Debug for LocalRepositoryAuthorityBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalRepositoryAuthorityBinding")
            .field("repository_id", &self.repository_id)
            .field("workspace_id", &self.workspace_id)
            .field("backend", &"<retained local storage capability>")
            .finish()
    }
}

impl LocalRepositoryAuthorityBinding {
    /// Bind identities already validated by a daemon to its startup-opened
    /// local storage capability.
    pub fn from_parts(
        repository_id: RepositoryId,
        workspace_id: WorkspaceId,
        backend: Arc<LocalFileBackend>,
    ) -> Self {
        Self {
            repository_id,
            workspace_id,
            backend,
        }
    }

    /// Establish a binding once for a fresh one-shot CLI/offline process.
    ///
    /// Request handlers in a long-lived daemon must receive an existing
    /// binding instead of calling this constructor. This pins namespace
    /// identity only; the first authority open below also proves that the
    /// namespace still carries a persisted authority record.
    pub fn from_layout(layout: &KinLayout) -> Result<Self> {
        layout.check_version()?;
        let manifest = KinManifest::load(&layout.manifest_path())?;
        let repository_id = RepositoryId::new(manifest.repo_id).map_err(|error| {
            KinError::Other(format!(
                "repository manifest has an invalid repository identity: {error}"
            ))
        })?;
        let workspace_uuid = uuid::Uuid::parse_str(&manifest.workspace_id).map_err(|error| {
            KinError::Other(format!(
                "repository manifest has an invalid workspace identity: {error}"
            ))
        })?;
        let binding = Self::from_parts(
            repository_id,
            WorkspaceId::from_uuid(workspace_uuid),
            Arc::new(LocalFileBackend::new(layout.kindb_dir())),
        );
        binding.revalidate_pinned_namespace().map_err(|error| {
            KinError::Other(format!(
                "cannot pin repository authority namespace at startup: {error}"
            ))
        })?;
        Ok(binding)
    }

    pub fn repository_id(&self) -> &RepositoryId {
        &self.repository_id
    }

    pub fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Revalidate the retained storage root and per-repository authority
    /// namespace without acquiring the repository lock or decoding any
    /// snapshot.
    ///
    /// See [`revalidate_pinned_local_namespace`] for the exact property this
    /// refuses on.
    pub fn revalidate_pinned_namespace(&self) -> std::result::Result<(), PinnedNamespaceRefusal> {
        revalidate_pinned_local_namespace(&self.backend, &self.repository_id)
    }

    /// Open a coherent authority manager through the retained storage
    /// capability.
    ///
    /// KinDB revalidates both the pinned storage-root identity and the retained
    /// per-repository namespace identity here, and retains the per-repository
    /// capability on the first successful call. The same recovery must return
    /// a payload receipt: a bound repository namespace whose authority record
    /// disappeared is refused rather than reopened as an unpersisted
    /// generation-zero repository.
    ///
    /// This is one authority recovery and its one exclusive recovery lock: the
    /// revalidation ahead of it reads namespace identity from metadata alone,
    /// so naming a replaced namespace as such costs no second recovery. KinDB
    /// may separately persist a reusable history-validation proof after a full
    /// replay; that does not reload authority or decide whether a record exists.
    #[track_caller]
    pub fn open_manager(
        &self,
    ) -> std::result::Result<RepositoryAuthorityManager<LocalFileBackend>, kin_db::KinDbError> {
        open_persisted_local_repository_authority(
            self.repository_id.clone(),
            Arc::clone(&self.backend),
        )
        .map(|(manager, _payload_stats)| manager)
    }

    /// Open a coherent authority manager and keep the payload receipt that the
    /// same recovery produced.
    ///
    /// The receipt names the exact persisted snapshot bytes and acknowledged
    /// delta bytes this open selected, so a caller reports the payload it
    /// actually read rather than measuring storage afterwards. It is fixed at
    /// open and does not follow later commits.
    ///
    /// A successful bound-repository open always returns `Some`: recovery that
    /// finds no persisted authority is refused rather than treating an intact,
    /// previously initialized namespace as a fresh generation-zero repository.
    /// The optional shape remains for callers that already expose KinDB's
    /// payload-receipt type; use KinDB directly when deliberately constructing
    /// an unpersisted repository before its first commit.
    #[track_caller]
    pub fn open_manager_with_payload_stats(
        &self,
    ) -> std::result::Result<
        (
            RepositoryAuthorityManager<LocalFileBackend>,
            Option<AuthorityPayloadStats>,
        ),
        kin_db::KinDbError,
    > {
        open_persisted_local_repository_authority(
            self.repository_id.clone(),
            Arc::clone(&self.backend),
        )
        .map(|(manager, payload_stats)| (manager, Some(payload_stats)))
    }

    /// Read the repository-authority envelope without materializing the
    /// history the same bytes carry.
    ///
    /// A full open decodes every domain the snapshot holds, and on a converted
    /// repository that is the repository: psf/requests at 6493 commits writes a
    /// 1051.5 MiB snapshot whose change map dominates it. A caller that needs
    /// the envelope and then some bodies by content address does not need any
    /// of that, and this is the read for it.
    ///
    /// `None` means the envelope cannot be answered cheaply and correctly, so
    /// the caller must open in full. It is never a wrong answer: KinDB returns
    /// it when no persisted authority exists, when the acknowledged journal
    /// head is past the snapshot base, or when the snapshot carries no
    /// envelope.
    pub fn open_authority_metadata(
        &self,
    ) -> std::result::Result<
        Option<kin_db::RepositoryAuthorityMetadata<LocalFileBackend>>,
        kin_db::KinDbError,
    > {
        kin_db::RepositoryAuthorityMetadata::open(
            self.repository_id.clone(),
            Arc::clone(&self.backend),
        )
    }
}

/// Open an already initialized local repository through one coherent recovery.
///
/// A missing authority record is not a fresh repository when its namespace is
/// reached through a startup binding. KinDB deliberately permits an absent
/// record when constructing an unpersisted generation-zero repository, so this
/// boundary uses the payload receipt from the same recovery to retain the
/// stricter reopen contract without paying for a second load or lock.
#[track_caller]
pub fn open_persisted_local_repository_authority<B: StorageBackend + ?Sized + 'static>(
    repository_id: RepositoryId,
    backend: Arc<B>,
) -> std::result::Result<(RepositoryAuthorityManager<B>, AuthorityPayloadStats), kin_db::KinDbError>
{
    // The funnel, and the reason the attribution lives here rather than only on
    // kin-cli's wrapper.
    //
    // Measured on a converted psf/requests store: one `kin graph status`
    // performs twelve whole-store authority opens, and instrumenting kin-cli's
    // `ActiveRepositoryAuthority::open` attributed two of twenty-six across a
    // run. The other twenty-four never reach that type. Every path into kin-db's
    // recovery does reach THIS function, so a caller named here is a caller
    // named for all of them.
    //
    // `#[track_caller]` names the call site rather than a backtrace and costs
    // nothing at runtime. Info rather than debug, for the same reason as the
    // wrapper's: the count is what an operator needs when a read is slow, and a
    // level nobody turns on is a line nobody reads.
    let caller = std::panic::Location::caller();
    tracing::info!(
        repository = %repository_id,
        caller = %format_args!("{}:{}", caller.file(), caller.line()),
        "opening persisted repository authority, which re-verifies every persisted body"
    );
    let missing_repository_id = repository_id.clone();
    let (manager, payload_stats) =
        RepositoryAuthorityManager::open_with_payload_stats(repository_id, backend)?;
    let payload_stats = payload_stats.ok_or_else(|| {
        kin_db::KinDbError::StorageError(format!(
            "local storage authority namespace {missing_repository_id} has no persisted authority record"
        ))
    })?;
    Ok((manager, payload_stats))
}

/// Why revalidating a startup-pinned repository namespace refused.
///
/// The two arms carry different claims. [`Self::Identity`] says the exact
/// storage this process bound is gone, which a caller may report as a conflict
/// naming the repository. [`Self::Unavailable`] says the revalidation reached no
/// verdict about identity at all, so reporting it as a replaced repository would
/// be a false diagnosis.
#[derive(Debug)]
pub enum PinnedNamespaceRefusal {
    /// The pinned namespace was replaced or detached, or this storage does not
    /// hold the repository at all.
    Identity(kin_db::KinDbError),
    /// The namespace could not be revalidated for a reason that says nothing
    /// about identity: IO, permissions, or an entry that could not be read.
    Unavailable(kin_db::KinDbError),
}

impl PinnedNamespaceRefusal {
    pub fn is_identity_refusal(&self) -> bool {
        matches!(self, Self::Identity(_))
    }

    pub fn error(&self) -> &kin_db::KinDbError {
        match self {
            Self::Identity(error) | Self::Unavailable(error) => error,
        }
    }

    pub fn into_error(self) -> kin_db::KinDbError {
        match self {
            Self::Identity(error) | Self::Unavailable(error) => error,
        }
    }
}

impl fmt::Display for PinnedNamespaceRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.error())
    }
}

impl std::error::Error for PinnedNamespaceRefusal {}

/// Refuse `repository_id` unless `backend` still reaches the exact storage root
/// and per-repository authority namespace it has already pinned.
///
/// KinDB retains a per-repository storage capability the first time repository
/// authority is read through a backend, keyed on the namespace directory's
/// filesystem identity, and revalidates that identity on every later access.
/// Reading authority identity through the same retained backend therefore
/// refuses a repository directory replaced at the same ambient path, a detached
/// namespace, and a store that does not hold this repository at all.
///
/// This deliberately addresses the one repository by name rather than
/// enumerating the storage root. `.kin/kindb/` also holds snapshot, vector,
/// index, and generation files beside the repository namespaces, so a listing
/// pass answers for entries that carry no authority and are not this caller's
/// concern.
///
/// It answers the identity question only. Reading identity through a full
/// authority load conflated it with everything a load can fail on, so a
/// truncated snapshot, a missing lock file, or a quarantined state on a
/// namespace this process still reaches was reported as a replaced repository.
/// A fault that says nothing about identity is [`PinnedNamespaceRefusal::Unavailable`]
/// here, and the bind stays closed either way. An intact namespace whose
/// persisted authority record is absent passes this identity probe, then is
/// refused by [`open_persisted_local_repository_authority`] using the receipt
/// from its single authority recovery.
///
/// Ordering is load-bearing. The first read on a fresh backend is what takes
/// the pin, so a long-lived process must take it once at startup and revalidate
/// on every later authority bind; a swap that lands before the first read
/// becomes the baseline rather than a refusal.
pub fn revalidate_pinned_local_namespace(
    backend: &LocalFileBackend,
    repository_id: &RepositoryId,
) -> std::result::Result<(), PinnedNamespaceRefusal> {
    classify_pinned_namespace_probe(
        repository_id,
        backend.probe_pinned_repository_namespace(repository_id.as_str()),
    )
}

fn classify_pinned_namespace_probe(
    repository_id: &RepositoryId,
    probe: LocalNamespaceProbe,
) -> std::result::Result<(), PinnedNamespaceRefusal> {
    match probe {
        LocalNamespaceProbe::Retained => Ok(()),
        LocalNamespaceProbe::IdentityLost(fault) => {
            Err(PinnedNamespaceRefusal::Identity(fault.into_error()))
        }
        LocalNamespaceProbe::Absent => Err(PinnedNamespaceRefusal::Identity(
            kin_db::KinDbError::StorageError(format!(
                "local storage authority does not hold repository namespace {repository_id}"
            )),
        )),
        LocalNamespaceProbe::Unavailable(error) => Err(PinnedNamespaceRefusal::Unavailable(error)),
    }
}

#[cfg(test)]
mod payload_receipt_tests {
    use super::*;

    #[test]
    fn generation_zero_built_only_in_memory_reports_no_payload_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let kindb = directory.path().join("kindb");
        std::fs::create_dir_all(&kindb).unwrap();
        let (_manager, receipt) = RepositoryAuthorityManager::open_with_payload_stats(
            RepositoryId::new("payload-receipt-generation-zero").unwrap(),
            Arc::new(LocalFileBackend::new(&kindb)),
        )
        .unwrap();

        assert!(
            receipt.is_none(),
            "an authority never persisted has no serialized payload to receipt"
        );
    }

    #[test]
    fn reopening_persisted_authority_always_carries_a_payload_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let initialized = crate::init(directory.path()).unwrap();
        // A binding built from the layout after init is a genuine reopen: it
        // recovers persisted bytes rather than inheriting the in-memory state
        // of the process that wrote them.
        let binding = LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();

        let (_manager, receipt) = binding.open_manager_with_payload_stats().unwrap();

        // The only legal `None` is the memory-only generation-zero case above.
        // A reopen that recovered persisted authority and still reported no
        // receipt would be an unmeasured read reported as a successful one.
        let receipt = receipt.expect(
            "a successfully reopened persisted repository must receipt the payload it read",
        );
        assert!(
            receipt.snapshot_bytes() > 0,
            "a recovered snapshot cannot occupy zero serialized bytes"
        );
        assert_eq!(
            receipt.acknowledged_delta_count(),
            receipt.head_generation() - receipt.snapshot_generation(),
            "the receipt must account for every generation between snapshot and head"
        );
        assert_eq!(
            receipt.total_payload_bytes(),
            receipt.snapshot_bytes() + receipt.acknowledged_delta_bytes(),
            "total payload bytes must be the snapshot plus acknowledged deltas it names"
        );
    }

    #[test]
    fn authority_open_refuses_an_intact_namespace_missing_its_persisted_record() {
        let directory = tempfile::tempdir().unwrap();
        let initialized = crate::init(directory.path()).unwrap();
        let repository_id = RepositoryId::new(
            KinManifest::load(&initialized.layout.manifest_path())
                .unwrap()
                .repo_id,
        )
        .unwrap();
        let namespace = initialized.layout.kindb_dir().join(repository_id.as_str());
        let snapshots = namespace.join("snapshots");
        assert!(
            std::fs::read_dir(&snapshots).unwrap().any(|entry| entry
                .unwrap()
                .file_type()
                .unwrap()
                .is_file()),
            "fixture must retain persisted snapshot material"
        );
        std::fs::remove_file(namespace.join("authority.json")).unwrap();

        let binding = LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();
        binding
            .revalidate_pinned_namespace()
            .expect("the retained namespace identity itself is still intact");
        let error = match binding.open_manager() {
            Ok(_) => panic!("a bound namespace missing authority.json must fail closed"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("has no persisted authority record"),
            "unexpected missing-authority refusal: {error}"
        );
    }
}

#[cfg(test)]
mod namespace_probe_classification_tests {
    use super::*;

    #[test]
    fn unavailable_probe_is_a_non_identity_refusal() {
        let repository_id = RepositoryId::new("unavailable-probe-classification").unwrap();
        let refusal = classify_pinned_namespace_probe(
            &repository_id,
            LocalNamespaceProbe::Unavailable(kin_db::KinDbError::StorageError(
                "deterministic probe IO failure".to_string(),
            )),
        )
        .expect_err("an unavailable probe must refuse");

        assert!(
            matches!(&refusal, PinnedNamespaceRefusal::Unavailable(_)),
            "unavailable probe must retain the unavailable arm, got {refusal}"
        );
        assert!(
            !refusal.is_identity_refusal(),
            "an unavailable probe says nothing about namespace identity"
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn copy_directory(source: &std::path::Path, target: &std::path::Path) {
        std::fs::create_dir(target).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let source_path = entry.path();
            let target_path = target.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_directory(&source_path, &target_path);
            } else {
                std::fs::copy(source_path, target_path).unwrap();
            }
        }
    }

    #[test]
    fn retained_binding_rejects_identical_storage_root_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let initialized = crate::init(directory.path()).unwrap();
        let binding = LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();
        binding.open_manager().unwrap();

        let kindb = initialized.layout.kindb_dir();
        let replacement = initialized.layout.root().join("kindb-replacement");
        let original = initialized.layout.root().join("kindb-original");
        copy_directory(&kindb, &replacement);
        std::fs::rename(&kindb, &original).unwrap();
        std::fs::rename(&replacement, &kindb).unwrap();

        let error = match binding.open_manager() {
            Ok(_) => {
                panic!("retained binding must reject an identically copied path replacement")
            }
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("changed since this backend opened"),
            "unexpected root-replacement error: {error}"
        );
    }

    #[test]
    fn retained_binding_rejects_identical_repository_namespace_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let initialized = crate::init(directory.path()).unwrap();
        let binding = LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();
        // The pin is taken before the swap, which is what makes the replacement
        // detectable at all rather than becoming the new baseline.
        binding.open_manager().unwrap();

        let namespace = initialized
            .layout
            .kindb_dir()
            .join(binding.repository_id().as_str());
        let replacement = initialized.layout.root().join("namespace-replacement");
        let original = initialized.layout.root().join("namespace-original");
        copy_directory(&namespace, &replacement);
        std::fs::rename(&namespace, &original).unwrap();
        std::fs::rename(&replacement, &namespace).unwrap();

        let error = binding
            .revalidate_pinned_namespace()
            .expect_err("retained binding must refuse a replaced repository namespace");
        assert!(
            error.to_string().contains("refusing replacement authority"),
            "unexpected namespace-replacement revalidation error: {error}"
        );

        let error = match binding.open_manager() {
            Ok(_) => panic!("retained binding must refuse authority from a replaced namespace"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("refusing replacement authority"),
            "unexpected namespace-replacement authority error: {error}"
        );
    }

    #[test]
    fn retained_binding_rejects_detached_repository_namespace() {
        let directory = tempfile::tempdir().unwrap();
        let initialized = crate::init(directory.path()).unwrap();
        let binding = LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();
        binding.open_manager().unwrap();

        let namespace = initialized
            .layout
            .kindb_dir()
            .join(binding.repository_id().as_str());
        std::fs::rename(
            &namespace,
            initialized.layout.root().join("namespace-detached"),
        )
        .unwrap();

        let error = binding
            .revalidate_pinned_namespace()
            .expect_err("retained binding must refuse a detached repository namespace");
        assert!(
            error.to_string().contains("detached after this backend"),
            "unexpected detached-namespace revalidation error: {error}"
        );

        let error = match binding.open_manager() {
            Ok(_) => panic!("retained binding must refuse authority from a detached namespace"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("detached after this backend"),
            "unexpected detached-namespace authority error: {error}"
        );
    }

    #[test]
    fn binding_refuses_a_store_that_does_not_hold_its_repository() {
        let directory = tempfile::tempdir().unwrap();
        let mine_root = directory.path().join("mine");
        let other_root = directory.path().join("other");
        std::fs::create_dir_all(&mine_root).unwrap();
        std::fs::create_dir_all(&other_root).unwrap();
        let mine = crate::init(&mine_root).unwrap();
        let other = crate::init(&other_root).unwrap();
        let mine_binding = LocalRepositoryAuthorityBinding::from_layout(&mine.layout).unwrap();

        let wrong_store = LocalRepositoryAuthorityBinding::from_parts(
            mine_binding.repository_id().clone(),
            mine_binding.workspace_id(),
            Arc::new(LocalFileBackend::new(other.layout.kindb_dir())),
        );

        let error = wrong_store
            .revalidate_pinned_namespace()
            .expect_err("a binding must refuse a store that does not hold its repository");
        assert!(
            error.is_identity_refusal(),
            "a store that does not hold the repository is a namespace answer, not an IO fault"
        );
        assert!(
            error
                .to_string()
                .contains("does not hold repository namespace"),
            "unexpected wrong-store error: {error}"
        );
    }

    /// Revalidation answers the identity question alone. Riding a full
    /// authority load conflated it with everything a load can fail on, so a
    /// corrupt payload on a namespace this process still reaches was reported
    /// as a replaced repository. The bind still refuses, at the authority open,
    /// where the fault actually is.
    #[test]
    fn revalidation_passes_a_corrupt_payload_on_an_intact_namespace_to_the_authority_open() {
        let directory = tempfile::tempdir().unwrap();
        let initialized = crate::init(directory.path()).unwrap();
        let binding = LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();
        binding.open_manager().unwrap();

        let namespace = initialized
            .layout
            .kindb_dir()
            .join(binding.repository_id().as_str());
        std::fs::write(namespace.join("authority.json"), b"{ truncated").unwrap();
        for entry in std::fs::read_dir(namespace.join("snapshots")).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                std::fs::write(entry.path(), b"not a snapshot").unwrap();
            }
        }

        if let Err(refusal) = binding.revalidate_pinned_namespace() {
            panic!("a corrupt payload on an intact namespace is not a namespace-identity refusal, got {refusal}");
        }
        if binding.open_manager().is_ok() {
            panic!("the authority open must still refuse the corrupt payload");
        }
    }

    /// A namespace genuinely replaced under the retained binding is still an
    /// identity refusal, so narrowing the classification did not soften it.
    #[test]
    fn revalidation_classifies_a_replaced_namespace_as_an_identity_refusal() {
        let directory = tempfile::tempdir().unwrap();
        let initialized = crate::init(directory.path()).unwrap();
        let binding = LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();
        binding.open_manager().unwrap();

        let namespace = initialized
            .layout
            .kindb_dir()
            .join(binding.repository_id().as_str());
        let replacement = initialized.layout.root().join("namespace-replacement");
        copy_directory(&namespace, &replacement);
        std::fs::rename(
            &namespace,
            initialized.layout.root().join("namespace-original"),
        )
        .unwrap();
        std::fs::rename(&replacement, &namespace).unwrap();

        let refusal = binding
            .revalidate_pinned_namespace()
            .expect_err("a replaced namespace must refuse");
        assert!(
            refusal.is_identity_refusal(),
            "a replaced namespace must be classified as identity, got {refusal}"
        );
        assert!(
            refusal
                .to_string()
                .contains("refusing replacement authority"),
            "unexpected replacement refusal: {refusal}"
        );
    }

    /// A detached namespace is the other structural identity answer.
    #[test]
    fn revalidation_classifies_a_detached_namespace_as_an_identity_refusal() {
        let directory = tempfile::tempdir().unwrap();
        let initialized = crate::init(directory.path()).unwrap();
        let binding = LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();
        binding.open_manager().unwrap();

        let namespace = initialized
            .layout
            .kindb_dir()
            .join(binding.repository_id().as_str());
        std::fs::rename(
            &namespace,
            initialized.layout.root().join("namespace-detached"),
        )
        .unwrap();

        let refusal = binding
            .revalidate_pinned_namespace()
            .expect_err("a detached namespace must refuse");
        assert!(
            refusal.is_identity_refusal(),
            "a detached namespace must be classified as identity, got {refusal}"
        );
        assert!(
            refusal
                .to_string()
                .contains("detached after this backend opened"),
            "unexpected detachment refusal: {refusal}"
        );
    }
}
