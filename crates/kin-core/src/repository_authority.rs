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
    AuthorityPayloadStats, LocalFileBackend, RepositoryAuthorityManager, RepositoryAuthorityState,
    StorageBackend,
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
                "repository-v6 authority has no workspace {workspace_id}"
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
    /// binding instead of calling this constructor.
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
    /// namespace without decoding the full graph snapshot.
    ///
    /// See [`revalidate_pinned_local_namespace`] for the exact property this
    /// refuses on.
    pub fn revalidate_pinned_namespace(&self) -> std::result::Result<(), kin_db::KinDbError> {
        revalidate_pinned_local_namespace(&self.backend, &self.repository_id)
    }

    /// Open a coherent authority manager through the retained storage
    /// capability.
    ///
    /// KinDB revalidates both the pinned storage-root identity and the
    /// retained per-repository namespace identity here, and retains the
    /// per-repository capability on the first successful call.
    pub fn open_manager(
        &self,
    ) -> std::result::Result<RepositoryAuthorityManager<LocalFileBackend>, kin_db::KinDbError> {
        RepositoryAuthorityManager::open(self.repository_id.clone(), Arc::clone(&self.backend))
    }

    /// Open a coherent authority manager and keep the payload receipt that the
    /// same recovery produced.
    ///
    /// The receipt names the exact persisted snapshot bytes and acknowledged
    /// delta bytes this open selected, so a caller reports the payload it
    /// actually read rather than measuring storage afterwards. It is fixed at
    /// open and does not follow later commits.
    ///
    /// `None` means recovery found no persisted authority and generation zero
    /// was constructed only in memory. A reopen of a repository that has
    /// persisted authority always carries a receipt; treating `None` as an
    /// ordinary outcome there would report an unmeasured payload as a
    /// successful read.
    pub fn open_manager_with_payload_stats(
        &self,
    ) -> std::result::Result<
        (
            RepositoryAuthorityManager<LocalFileBackend>,
            Option<AuthorityPayloadStats>,
        ),
        kin_db::KinDbError,
    > {
        RepositoryAuthorityManager::open_with_payload_stats(
            self.repository_id.clone(),
            Arc::clone(&self.backend),
        )
    }
}

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
/// Ordering is load-bearing. The first read on a fresh backend is what takes
/// the pin, so a long-lived process must take it once at startup and revalidate
/// on every later authority bind; a swap that lands before the first read
/// becomes the baseline rather than a refusal.
pub fn revalidate_pinned_local_namespace(
    backend: &LocalFileBackend,
    repository_id: &RepositoryId,
) -> std::result::Result<(), kin_db::KinDbError> {
    match backend.load_snapshot_authority(repository_id.as_str())? {
        Some(_) => Ok(()),
        None => Err(kin_db::KinDbError::StorageError(format!(
            "local storage authority does not hold repository namespace {repository_id}"
        ))),
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
        let binding = LocalRepositoryAuthorityBinding::from_parts(
            RepositoryId::new("payload-receipt-generation-zero").unwrap(),
            WorkspaceId::from_uuid(uuid::Uuid::from_u128(1)),
            Arc::new(LocalFileBackend::new(&kindb)),
        );

        let (_manager, receipt) = binding.open_manager_with_payload_stats().unwrap();

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
            error
                .to_string()
                .contains("does not hold repository namespace"),
            "unexpected wrong-store error: {error}"
        );
    }
}
