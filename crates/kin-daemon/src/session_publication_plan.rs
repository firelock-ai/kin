// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! One unpublished semantic successor for an exact disposable-session observation.
//!
//! The caller owns coordination, graph publication and reconciler guards from
//! live capture through finalization. This module neither projects primary files
//! nor acknowledges/commits a preparation. Immutable CAS copies are the only IO
//! it may publish. Selected partial sources refuse before acknowledgement.

use std::collections::{BTreeMap, BTreeSet};

use kin_db::{GraphSnapshot, InMemoryGraph, LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{
    AuthorId, EffectiveAdmissionPolicyStamp, EntityStore, FilePathId, Hash256, ModelError,
    ParseCompleteness, ParseState, RepoPath, RepositoryTransaction, SharedAdmissionPolicy,
    TransactionDelta, TreeEntry, WorkspaceExpectation, WorkspaceMutation, WorkspaceSemanticDelta,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use kin_reconcile::{
    PreparedAdmittedSourceBatch, PreparedBatchAdoption, PreparedBatchSource, Reconciler,
};

use crate::error::{DaemonError, Result};
use crate::repository_commit as retirement;
use crate::source_cas::read_publishable_source;
use crate::DaemonState;

type Authority = RepositoryAuthorityManager<LocalFileBackend>;

/// Immutable plan. `observed` is the actual live predecessor, independently of
/// the durable selected predecessor used to encode `transaction`.
pub(crate) struct PreparedSessionPlan {
    transaction: RepositoryTransaction,
    observed: GraphSnapshot,
    sources: PreparedSessionSourceState,
}

impl PreparedSessionPlan {
    pub(crate) fn transaction(&self) -> &RepositoryTransaction {
        &self.transaction
    }
    #[cfg(test)]
    pub(crate) fn observed(&self) -> &GraphSnapshot {
        &self.observed
    }
    pub(crate) fn successor(&self) -> &GraphSnapshot {
        self.sources.prepared.snapshot()
    }
    pub(crate) fn source_state(&self) -> &PreparedSessionSourceState {
        &self.sources
    }
    pub(crate) fn into_parts(
        self,
    ) -> (
        RepositoryTransaction,
        GraphSnapshot,
        PreparedSessionSourceState,
    ) {
        (self.transaction, self.observed, self.sources)
    }
}

/// Preflighted cache adoption, not permission to publish. Consume only on the
/// original reconciler after exact durable/live installation under the guards.
pub(crate) struct PreparedSessionSourceState {
    prepared: PreparedAdmittedSourceBatch,
    adoption: PreparedBatchAdoption,
    live_delta: TransactionDelta,
    facet_invalidations: Vec<FilePathId>,
    nonsemantic_paths: Vec<RepoPath>,
}

/// Finalization still owes layout/facet persistence; adopting caches is not
/// complete session success. No parsing or source lookup is needed here.
pub(crate) struct AdoptedSessionSources {
    pub(crate) sources: Vec<PreparedBatchSource>,
    pub(crate) live_delta: TransactionDelta,
    pub(crate) facet_invalidations: Vec<FilePathId>,
    /// Exact tree membership was prepared, but no complete semantic extraction
    /// is claimed for these structured/shallow/opaque/non-UTF8 inputs.
    pub(crate) nonsemantic_paths: Vec<RepoPath>,
}

impl PreparedSessionSourceState {
    #[cfg(test)]
    pub(crate) fn sources(&self) -> &[PreparedBatchSource] {
        self.prepared.sources()
    }
    pub(crate) fn live_delta(&self) -> &TransactionDelta {
        &self.live_delta
    }
    pub(crate) fn nonsemantic_paths(&self) -> &[RepoPath] {
        &self.nonsemantic_paths
    }
    pub(crate) fn collision_warnings(&self) -> &[kin_model::IntentSummary] {
        self.adoption.collision_warnings()
    }
    pub(crate) fn adopt(self, reconciler: &mut Reconciler) -> AdoptedSessionSources {
        let sources = self.prepared.sources().to_vec();
        reconciler.adopt_admitted_source_batch(self.adoption);
        AdoptedSessionSources {
            sources,
            live_delta: self.live_delta,
            facet_invalidations: self.facet_invalidations,
            nonsemantic_paths: self.nonsemantic_paths,
        }
    }
}

fn refused(message: impl Into<String>) -> DaemonError {
    DaemonError::SemanticReadmissionFailed(message.into())
}

fn same_observation(left: &GraphSnapshot, right: &GraphSnapshot) -> bool {
    left.entities == right.entities
        && left.relations == right.relations
        && left.external_references == right.external_references
        && left.resolved_tree == right.resolved_tree
        && left.verified_binding_history == right.verified_binding_history
}

/// Build from the single captured live observation supplied by the owner. The
/// final live read is only an equality fence, never another planning input.
pub(crate) fn prepare(
    state: &DaemonState,
    reconciler: &Reconciler,
    authority: &Authority,
    observation: &kin_cli::commands::reconcile::SessionReconcileObservation,
    observed: GraphSnapshot,
) -> Result<PreparedSessionPlan> {
    observation
        .revalidate_retained_capability(&state.layout)
        .map_err(|error| refused(error.to_string()))?;
    let base = observation.base();
    if state.storage_backend.is_some()
        || base.repository_id.as_str() != state.cached_repo_id
        || state.local_repository_workspace_id() != Some(base.source_workspace.workspace_id)
        || observed.resolved_tree != base.source_workspace.tree
        || !same_observation(&observed, &state.graph.semantic_observation())
    {
        return Err(refused(
            "captured session predecessor does not match local live authority",
        ));
    }
    let durable = {
        let lease = authority.read_authority();
        let current = lease
            .metadata()
            .workspaces
            .iter()
            .find(|w| w.workspace_id == base.source_workspace.workspace_id)
            .ok_or_else(|| refused("session workspace is absent from authority"))?;
        if lease.roots() != &base.authority_roots || current != &base.source_workspace {
            return Err(refused(
                "session authority moved; prepared planning never rebases or reconstructs replay",
            ));
        }
        lease
            .workspace_graph_snapshot(&current.workspace_id)?
            .ok_or_else(|| refused("session has no durable selected semantic predecessor"))?
    };
    let tree_deltas =
        kin_core::exact_tree_correction(&observed.resolved_tree, observation.desired_tree())?;
    if tree_deltas.is_empty() || tree_deltas != observation.deltas() {
        return Err(refused(
            "prepared session requires its exact nonempty observed tree transition",
        ));
    }
    // The batch API reads ingestion CAS. Restore it only from verified durable
    // source when needed, and make every captured/new source durable before a
    // caller can acknowledge this plan. These writes do not move authority.
    let hashes: BTreeSet<_> = observed
        .resolved_tree
        .artifacts()
        .chain(observation.desired_tree().artifacts())
        .filter_map(|a| a.entry.blob_identity())
        .chain(observed.entities.values().filter_map(|e| {
            e.metadata
                .extra
                .get("blob_hash")
                .and_then(|v| v.as_str())
                .and_then(|v| Hash256::from_hex(v).ok())
        }))
        .collect();
    for hash in hashes {
        let source = read_publishable_source(&state.blobs, authority, hash)?;
        if state.blobs.write(source.body())?.0 != *hash.as_bytes() {
            return Err(refused("session source CAS identity changed"));
        }
        if let Some(body) = source.body_to_publish() {
            authority.save_source_blob(hash, body)?;
        }
    }
    let staged = InMemoryGraph::from_snapshot_without_text_index(observed.clone())?;
    let vacated = retirement::VacatedPaths::from_deltas(&tree_deltas);
    let moves = retirement::session_artifact_moves(&tree_deltas);
    let module_moves =
        retirement::plan_session_module_relocations(&state.blobs, authority, &tree_deltas)?;
    let retired = retirement::retire_semantics_on_vacated(&observed, &vacated)?;
    let mut initial = TransactionDelta {
        tree_deltas: tree_deltas.clone(),
        entity_deltas: retired.entity_deltas().to_vec(),
        relation_deltas: retired.relation_deltas().to_vec(),
        ..Default::default()
    };
    initial
        .relation_deltas
        .extend(retirement::plan_moved_source_coverage_withdrawals(
            &staged, &moves,
        )?);
    retirement::plan_move_binding_transition(
        &staged,
        &state.blobs,
        authority,
        &moves,
        &mut initial.relation_deltas,
    )?;
    kin_reconcile::relocate_binding_obligations(&staged, &moves, &mut initial.relation_deltas)?;
    for (from, to) in &moves {
        initial
            .entity_deltas
            .extend(retirement::plan_session_entity_relocations(
                &staged, from, to,
            )?);
    }
    retirement::bind_session_module_relocations(&mut initial.entity_deltas, &module_moves)?;
    kin_model::validate_transaction_delta(&initial)?;
    staged.apply_transaction_delta(&initial)?;

    let mut affected = BTreeSet::new();
    for delta in &tree_deltas {
        if let Some(new) = delta.new_state() {
            affected.insert(new.path.clone());
        }
    }
    // Retiring a destination owes rederivation to its surviving exact callers.
    // These nominations come from held relation endpoints, never a name search.
    for delta in &initial.relation_deltas {
        let old = match delta {
            kin_model::RelationDelta::Removed { old }
            | kin_model::RelationDelta::Modified { old, .. } => old,
            kin_model::RelationDelta::Added { .. } => continue,
        };
        if let Some(source) = old
            .src
            .as_entity()
            .and_then(|id| observed.entities.get(&id))
        {
            if let Some(file) = &source.file_origin {
                let path = RepoPath::from_utf8(file.0.clone())
                    .map_err(|error| refused(error.to_string()))?;
                if staged.resolved_tree().artifact_at_path(&path).is_some() {
                    affected.insert(path);
                }
            }
        }
    }
    if let Some(project) = kin_index::rust_project::affected_source_batch(
        &observed.resolved_tree,
        observation.desired_tree(),
        Default::default(),
    )
    .map_err(|error| refused(error.to_string()))?
    {
        for file in project.affected_sources {
            affected
                .insert(RepoPath::from_utf8(file.0).map_err(|error| refused(error.to_string()))?);
        }
    }
    let mut files = Vec::new();
    let mut nonsemantic_paths = Vec::new();
    let pipeline = kin_index::IndexPipeline::new();
    for path in &affected {
        let Some(artifact) = observation.desired_tree().artifact_at_path(path) else {
            continue;
        };
        // The original artifact certificate is refusal-only ownership
        // evidence, including for entity-free sources and byte-path moves.
        // It does not certify current source binding or completeness.
        let held_certificate = observed
            .resolved_tree
            .get(&artifact.artifact_id)
            .is_some_and(|old| {
                old.path.as_utf8().is_some_and(|old_path| {
                    observed.relations.values().any(|relation| {
                        kin_index::is_parse_coverage_relation(
                            relation,
                            old_path,
                            artifact.artifact_id,
                        )
                    })
                })
            });
        let Some(file) = path.as_utf8().map(FilePathId::new) else {
            if held_certificate {
                return Err(refused("session source lost complete semantic extraction at a non-UTF8 path; no preparation acknowledged"));
            }
            nonsemantic_paths.push(path.clone());
            continue;
        };
        // Moves have already relocated declarations into this private graph.
        let held_source = held_certificate
            || !staged
                .query_entities(&kin_model::EntityFilter {
                    file_path: Some(file.clone()),
                    ..Default::default()
                })?
                .is_empty();
        let lost_extraction = || {
            refused(format!(
            "session source {file} lost complete semantic extraction; no preparation acknowledged"
        ))
        };
        let TreeEntry::Blob { hash, .. } = artifact.entry else {
            if held_source {
                return Err(lost_extraction());
            }
            nonsemantic_paths.push(path.clone());
            continue;
        };
        let digest = kin_blobs::Hash256::from_bytes(*hash.as_bytes());
        let body = state.blobs.read(&digest)?;
        match pipeline.index_any_content(&file, &body, digest)? {
            kin_index::IndexedAny::EntitySource(indexed) => {
                if !matches!(indexed.parse_state, ParseState::Valid)
                    || indexed.file_layout.parse_completeness != ParseCompleteness::Full
                {
                    return Err(refused(format!(
                        "session source {file} is partial; no preparation acknowledged"
                    )));
                }
                files.push(file);
            }
            _ => {
                if held_source {
                    return Err(lost_extraction());
                }
                nonsemantic_paths.push(path.clone());
            }
        }
    }
    let pre_batch = staged.semantic_observation();
    let predecessor = kin_model::graph::ResolvedGraphState {
        entities: observed.entities.clone(),
        relations: observed.relations.clone(),
        external_references: observed.external_references.clone(),
        tree: observed.resolved_tree.clone(),
        ..Default::default()
    };
    let prepared = Reconciler::prepare_admitted_source_batch(
        pre_batch.clone(),
        &files,
        &state.blobs,
        &[predecessor],
    )?;
    let batch_delta = semantic_delta(&pre_batch, prepared.snapshot())?;
    let mut live_delta = semantic_delta(&observed, prepared.snapshot())?;
    live_delta.tree_deltas = tree_deltas.clone();
    if !same_observation(&observed, &state.graph.semantic_observation()) {
        return Err(refused("live graph changed after prepared session capture"));
    }
    let adoption = reconciler.preflight_admitted_source_batch_from_observation(
        &prepared,
        &staged,
        &batch_delta,
        &observed,
        &live_delta,
        &state.blobs,
    )?;
    let semantic = semantic_delta(&durable, prepared.snapshot())?;
    let mut lengths = BTreeMap::new();
    let (policy, _) = SharedAdmissionPolicy::derive_from_tree_with_allowances(
        Some(&base.source_workspace.shared_admission_policy),
        observation.desired_tree(),
        |hash| {
            if let Some(length) = lengths.get(&hash) {
                return Ok(*length);
            }
            let source = read_publishable_source(&state.blobs, authority, hash)
                .map_err(|error| ModelError::InvalidOperation(error.to_string()))?;
            let length = u64::try_from(source.body().len())
                .map_err(|error| ModelError::InvalidOperation(error.to_string()))?;
            lengths.insert(hash, length);
            Ok(length)
        },
        |hash| {
            read_publishable_source(&state.blobs, authority, hash)
                .map(|source| source.body().to_vec())
                .map_err(|e| ModelError::InvalidOperation(e.to_string()))
        },
    )?;
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: base.reconcile_operation_id,
        repository_id: base.repository_id.clone(),
        expected_generation: base.authority_roots.generation,
        expected_roots: base.authority_roots.clone(),
        actor: AuthorId::new("kin-session-reconcile"),
        reason: "publish exact prepared disposable-session semantics".into(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id: base.source_workspace.workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: base.source_workspace.generation,
                head: base.source_workspace.head.clone(),
                base_target: base.source_workspace.base_target.clone(),
                base_tree_hash: base.source_workspace.base_tree_hash,
                tree_hash: base.source_workspace.tree_hash,
                semantic_overlay_hash: base.source_workspace.semantic_overlay_hash,
                admission_policy: base.source_workspace.admission_policy,
            },
            new_generation: base
                .source_workspace
                .generation
                .checked_add(1)
                .ok_or_else(|| refused("session workspace generation exhausted"))?,
            new_head: base.source_workspace.head.clone(),
            new_base_target: base.source_workspace.base_target.clone(),
            new_base_tree_hash: base.source_workspace.base_tree_hash,
            tree_deltas: tree_deltas.clone(),
            new_tree_hash: kin_model::compute_resolved_tree_hash(observation.desired_tree())?,
            semantic_delta: WorkspaceSemanticDelta::new_with_external_references(
                semantic.entity_deltas,
                semantic.relation_deltas,
                semantic.external_reference_deltas,
            )?,
            new_shared_admission_policy: policy.clone(),
            new_admission_policy: EffectiveAdmissionPolicyStamp {
                shared: policy.stamp(),
                local: base.source_workspace.admission_policy.local,
            },
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };
    transaction.validate()?;
    let facet_invalidations = tree_deltas
        .iter()
        .filter_map(|delta| delta.old_state())
        .filter_map(|old| old.path.as_utf8().map(FilePathId::new))
        .collect();
    Ok(PreparedSessionPlan {
        transaction,
        observed,
        sources: PreparedSessionSourceState {
            prepared,
            adoption,
            live_delta,
            facet_invalidations,
            nonsemantic_paths,
        },
    })
}

/// Reuse the canonical entity/relation differ; external references are immutable
/// identities and require exact add/remove treatment rather than silent loss.
fn semantic_delta(before: &GraphSnapshot, after: &GraphSnapshot) -> Result<TransactionDelta> {
    let semantic = kin_core::diff_workspace_semantics(
        &before.entities,
        &before.relations,
        &after.entities,
        &after.relations,
    )?;
    let mut references = Vec::new();
    for (id, old) in &before.external_references {
        match after.external_references.get(id) {
            None => {
                references.push(kin_model::ExternalReferenceDelta::Removed { old: old.clone() })
            }
            Some(new) if new != old => {
                return Err(refused(
                    "session rewrote an immutable external reference identity",
                ))
            }
            _ => {}
        }
    }
    for (id, new) in &after.external_references {
        if !before.external_references.contains_key(id) {
            references.push(kin_model::ExternalReferenceDelta::Added { new: new.clone() });
        }
    }
    Ok(TransactionDelta {
        entity_deltas: semantic.entity_deltas().to_vec(),
        relation_deltas: semantic.relation_deltas().to_vec(),
        external_reference_deltas: references,
        ..Default::default()
    })
}

#[cfg(test)]
#[path = "session_publication_plan_test.rs"]
mod tests;
