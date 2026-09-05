// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Repository-v6 native commit publication.
//!
//! Filesystem observation belongs to the serialized reconcile/admission
//! boundary. This module consumes only the admitted live graph, immutable blob
//! CAS, and one persisted repository-authority lease. History, exact tree,
//! workspace base, and the named ref advance in one storage compare-and-swap.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{
    compute_resolved_tree_hash, compute_semantic_change_id, AuthorId, ChangeOrigin,
    EffectiveAdmissionPolicyStamp, Hash256, ModelError, OperationId, RefExpectation, RefMutation,
    RefName, RefTarget, RefUpdatePolicy, RepoPath, RepositoryCommitOutcome,
    RepositoryCommitReceipt, RepositoryTransaction, RootBundle, SemanticChange, SemanticChangeId,
    SharedAdmissionPolicy, Timestamp, WorkspaceExpectation, WorkspaceHead, WorkspaceId,
    WorkspaceMutation, WorkspaceSemanticDelta, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};

use crate::commit_deltas::compute_deltas_vs_repository_authority;
use crate::error::{DaemonError, Result};
use crate::local_repository_authority::LocalRepositoryAuthorityContext;
use crate::source_cas::read_publishable_source;

type ProjectionEntry = (kin_model::RepoPath, kin_model::TreeEntry, Arc<[u8]>);

/// Where one native commit publishes.
///
/// A workspace whose head names a branch publishes onto that branch: the branch
/// is what moves, and the head goes on naming it. A workspace whose head is
/// detached owns its own head, because nothing else in the repository names
/// where it stands, so the head itself advances to the new change and no ref is
/// invented on the author's behalf.
///
/// This is graph vocabulary rather than a Git shape borrowed for convenience. A
/// workspace parked at a change with no branch is expressible with no file and
/// no Git in the picture, `kin_model::WorkspaceHead::Detached` already accepts a
/// `RefTarget::Change`, and the change keeps its parent, so provenance is
/// unbroken either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeCommitTarget {
    /// The branch the workspace head names, which this commit fast-forwards.
    Branch(RefName),
    /// The workspace's own detached head, which this commit advances.
    DetachedHead,
}

impl NativeCommitTarget {
    /// The branch this commit moves, or `None` on a detached head.
    pub fn branch(&self) -> Option<&RefName> {
        match self {
            Self::Branch(name) => Some(name),
            Self::DetachedHead => None,
        }
    }
}

/// Complete immutable plan for one native repository transaction.
///
/// `source_hashes` name bodies already present in the daemon's admitted blob
/// CAS. They are copied into repository-owned CAS immediately before the
/// authority compare-and-swap; raw checkout bytes are never consulted.
///
/// The plan also carries the repository authority it was read from, still open.
/// Opening one is O(store): it decodes the whole persisted authority and then
/// re-verifies every body in repository CAS against its content address, which
/// kin-db does unconditionally on every open. A commit that planned against one
/// open authority and then published through a second paid that twice for one
/// change. Carrying it is what makes the plan and the publication the same
/// authority rather than two reads of the same generation, so the roots the
/// transaction expects and the roots the publication compare-and-swaps against
/// are the same in-memory state.
pub struct NativeCommitPlan {
    pub change: SemanticChange,
    pub transaction: RepositoryTransaction,
    pub target: NativeCommitTarget,
    pub entity_count: usize,
    pub relation_count: usize,
    pub file_count: usize,
    /// Files this change publishes that the caller's own operations did not
    /// author, carried in from working-tree content the workspace had already
    /// admitted ahead of its base change.
    ///
    /// Always empty for a caller that does not declare which files it authored,
    /// because a planner cannot tell an unclaimed file from an authored one,
    /// and an unclaimed file must never be reported as carried on a guess.
    pub carried_pending_files: Vec<RepoPath>,
    /// Entity scopes whose published history this transaction changes.
    pub entity_scope_ids: Vec<kin_model::EntityId>,
    previous_tree: kin_model::ResolvedTree,
    target_tree: kin_model::ResolvedTree,
    source_hashes: Vec<Hash256>,
    authority: RepositoryAuthorityManager<LocalFileBackend>,
}

#[derive(Debug)]
pub struct NativeCommitResult {
    pub change: SemanticChange,
    pub receipt: RepositoryCommitReceipt,
    pub target: NativeCommitTarget,
    pub entity_count: usize,
    pub relation_count: usize,
    pub file_count: usize,
}

/// One coherent, clean workspace authority base for a prospective native
/// commit.
///
/// The graph is materialized from the workspace lease, not from the daemon's
/// mutable query overlay. `roots` must still match when the final plan is
/// constructed; repository publication independently repeats the same CAS.
pub struct NativeCommitBase {
    pub graph: kin_db::InMemoryGraph,
    pub roots: RootBundle,
    pub tree: kin_model::ResolvedTree,
}

/// Result of durably admitting one exact working-tree transition.
///
/// This advances workspace authority only. It does not manufacture a semantic
/// history node or move a named ref: dirty Compose/config/binary/unsupported
/// artifacts remain dirty workspace state until an explicit Kin commit.
#[derive(Debug)]
pub struct WorkspaceAdmissionResult {
    pub receipt: RepositoryCommitReceipt,
    pub workspace_id: WorkspaceId,
    pub tree_hash: Hash256,
    pub file_count: usize,
}

/// One exact workspace transition that a complete host scan actually proved.
///
/// The constructor requires [`kin_index::CompleteScanToken`], which only a
/// fully successful repository walk mints, so publication cannot be handed a
/// tree assembled from a partial walk or from nothing at all. It also binds the
/// authority roots and the workspace tree the transition was planned against,
/// which is what lets publication refuse a stale desired tree instead of
/// silently replanning it against newer authority.
#[derive(Debug)]
pub(crate) struct AdmittedWorkspaceTree {
    previous_tree: kin_model::ResolvedTree,
    desired_tree: kin_model::ResolvedTree,
    expected_roots: RootBundle,
    /// Held, not read: the proof does its work by being impossible to supply
    /// without a completed walk, and by staying attached to the tree it
    /// proved.
    #[allow(dead_code)]
    completion: kin_index::CompleteScanToken,
}

impl AdmittedWorkspaceTree {
    pub(crate) fn from_complete_observation(
        completion: kin_index::CompleteScanToken,
        expected_roots: RootBundle,
        previous_tree: kin_model::ResolvedTree,
        desired_tree: kin_model::ResolvedTree,
    ) -> Self {
        Self {
            previous_tree,
            desired_tree,
            expected_roots,
            completion,
        }
    }
}

/// The exact tree repository authority currently records for this workspace.
///
/// The derived graph's counterpart, and the answer `kin status` reports while
/// `kin graph status` reports the graph's own. The two agreeing is the invariant
/// a deferred admission is opened against and the one a failed commit has to
/// restore. It lives here rather than beside its caller because the lease
/// accessor it reads shares a method name with a filesystem probe, and this is
/// the module where that accessor is already accounted for.
pub(crate) fn authority_workspace_tree(
    authority_context: &LocalRepositoryAuthorityContext,
) -> Result<kin_model::ResolvedTree> {
    let workspace_id = authority_context.workspace_id();
    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    let lease = authority.read_authority();
    lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
        .map(|workspace| workspace.tree.clone())
        .ok_or_else(|| {
            invalid(format!(
                "repository authority has no local workspace {workspace_id}"
            ))
        })
}

/// Admit `desired_tree` for a test by taking a real host walk first.
///
/// `CompleteScanToken` cannot be minted outside `kin-index`, so a test cannot
/// fabricate an admission any more than production can. It has to walk the
/// working directory and carry back the proof that the walk finished.
#[cfg(test)]
pub(crate) fn admitted_workspace_tree_for_test(
    working_dir: &std::path::Path,
    expected_roots: RootBundle,
    previous_tree: kin_model::ResolvedTree,
    desired_tree: kin_model::ResolvedTree,
) -> AdmittedWorkspaceTree {
    let ignore = kin_index::RepositoryIgnore::load(working_dir).expect("load repository ignore");
    let scan = kin_index::scan_repository(
        working_dir,
        &ignore,
        previous_tree
            .artifacts_by_path()
            .map(|artifact| &artifact.path),
    )
    .expect("complete host walk");
    AdmittedWorkspaceTree::from_complete_observation(
        scan.completion(),
        expected_roots,
        previous_tree,
        desired_tree,
    )
}

/// Immutable session-reconcile plan bound to the authority lease captured when
/// the disposable session was materialized.
pub struct SessionWorkspaceAdmissionPlan {
    pub transaction: RepositoryTransaction,
    pub previous_tree: kin_model::ResolvedTree,
    pub target_tree: kin_model::ResolvedTree,
    pub deltas: Vec<kin_model::TreeDelta>,
    /// The paths this transition leaves with nothing at them, and the artifact
    /// identities that held them. The transaction retires their semantics
    /// against authority's own graph; the handler derives the live graph's
    /// retirement from the live graph with the same set, because the two can
    /// hold different payloads for the same entity and each must drop its own.
    pub vacated: VacatedPaths,
    pub(crate) module_relocations: Vec<SessionModuleRelocation>,
    pub workspace_id: WorkspaceId,
    source_hashes: Vec<Hash256>,
    recovered_receipt: Option<RepositoryCommitReceipt>,
}

#[derive(Debug)]
pub struct SessionWorkspaceAdmissionResult {
    pub receipt: RepositoryCommitReceipt,
    pub workspace_id: WorkspaceId,
    pub tree_hash: Hash256,
    pub file_count: usize,
    pub idempotent_replay: bool,
}

/// Build one exact session admission against the session's retained roots and
/// complete source workspace.
///
/// Planning takes the sealed observation rather than a loose base and tree, so
/// the retained no-follow directory capability is still held here and can be
/// re-proved before anything is planned against it. A caller cannot reach this
/// boundary with a desired tree that no retained walk produced.
///
/// Unlike the ambient filesystem synchronizer, this never silently rebases
/// onto a newer workspace. The only accepted moved-authority state is the
/// exact durable receipt for this session's caller-stable operation and
/// transaction hash.
pub(crate) fn plan_session_workspace_admission(
    layout: &kin_core::KinLayout,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    observation: &kin_cli::commands::reconcile::SessionReconcileObservation,
) -> Result<SessionWorkspaceAdmissionPlan> {
    observation
        .revalidate_retained_capability(layout)
        .map_err(|error| invalid(error.to_string()))?;
    let base = observation.base();
    let desired_tree = observation.desired_tree();
    let repository_id = authority_context.repository_id().clone();
    let workspace_id = authority_context.workspace_id();
    if base.repository_id != repository_id
        || base.source_workspace.repository_id != repository_id
        || base.source_workspace.workspace_id != workspace_id
    {
        return Err(invalid(
            "session base repository/workspace identity does not match this repository",
        ));
    }
    base.authority_roots.validate()?;
    base.source_workspace.validate()?;
    let deltas = kin_core::exact_tree_correction(&base.source_workspace.tree, desired_tree)?;
    if deltas.is_empty() {
        return Err(invalid(
            "session workspace admission planner rejects empty transitions",
        ));
    }

    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    // An entity may not outlive the path that owns it. kin-db refuses a
    // transition that leaves one on a path the staged tree no longer carries,
    // and names the remedy in its own message: carry the exact removal in the
    // same delta. This admission is the caller that owes it. Without this a
    // session that deleted a source file could not reconcile at all, the
    // refusal surfaced as a 500, and the file's entities kept answering
    // queries with nothing on disk behind them.
    let vacated = VacatedPaths::from_deltas(&deltas);
    let moves = session_artifact_moves(&deltas);
    let module_relocations = plan_session_module_relocations(blobs, &authority, &deltas)?;
    let semantic_delta = if vacated.is_empty() && moves.is_empty() {
        WorkspaceSemanticDelta::default()
    } else {
        let snapshot = {
            let lease = authority.read_authority();
            let mut snapshot = lease.workspace_graph_snapshot(&workspace_id)?;
            let current = lease
                .metadata()
                .workspaces
                .iter()
                .find(|workspace| workspace.workspace_id == workspace_id)
                .ok_or_else(|| invalid("session workspace is absent from authority"))?;
            if current != &base.source_workspace {
                if let Some(snapshot) = &mut snapshot {
                    restore_retained_session_semantics(snapshot, current, &base.source_workspace)?;
                }
            }
            snapshot
        };
        match snapshot {
            Some(snapshot) => {
                let retirement = retire_semantics_on_vacated(&snapshot, &vacated)?;
                let mut entities = retirement.entity_deltas().to_vec();
                if !moves.is_empty() {
                    let graph = kin_db::InMemoryGraph::from_snapshot_without_text_index(snapshot)?;
                    for (from, to) in &moves {
                        entities.extend(plan_session_entity_relocations(&graph, from, to)?);
                    }
                    bind_session_module_relocations(&mut entities, &module_relocations)?;
                }
                WorkspaceSemanticDelta::new(entities, retirement.relation_deltas().to_vec())?
            }
            None => WorkspaceSemanticDelta::default(),
        }
    };
    let mut source_lengths = std::collections::BTreeMap::new();
    let (shared_policy, _) = SharedAdmissionPolicy::derive_from_tree_with_allowances(
        Some(&base.source_workspace.shared_admission_policy),
        desired_tree,
        |hash| {
            if let Some(length) = source_lengths.get(&hash) {
                return Ok(*length);
            }
            let source = read_publishable_source(blobs, &authority, hash).map_err(|error| {
                ModelError::InvalidOperation(format!(
                    "{error}, while deriving the exact session admission policy"
                ))
            })?;
            let length = u64::try_from(source.body().len()).map_err(|_| {
                ModelError::InvalidOperation(format!(
                    "exact session admission-policy source {hash} exceeds u64"
                ))
            })?;
            source_lengths.insert(hash, length);
            Ok(length)
        },
        |hash| {
            read_publishable_source(blobs, &authority, hash)
                .map(|source| source.body().to_vec())
                .map_err(|error| {
                    ModelError::InvalidOperation(format!(
                        "{error}, while reading the approvals the exact session policy derives"
                    ))
                })
        },
    )?;
    let tree_hash = compute_resolved_tree_hash(desired_tree)?;
    let new_generation = base
        .source_workspace
        .generation
        .checked_add(1)
        .ok_or_else(|| invalid("session workspace generation exhausted"))?;
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: base.reconcile_operation_id,
        repository_id: repository_id.clone(),
        expected_generation: base.authority_roots.generation,
        expected_roots: base.authority_roots.clone(),
        actor: AuthorId::new("kin-session-reconcile"),
        reason: "admit exact disposable-session observation".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: base.source_workspace.generation,
                head: base.source_workspace.head.clone(),
                base_target: base.source_workspace.base_target.clone(),
                base_tree_hash: base.source_workspace.base_tree_hash,
                tree_hash: base.source_workspace.tree_hash,
                semantic_overlay_hash: base.source_workspace.semantic_overlay_hash,
                admission_policy: base.source_workspace.admission_policy,
            },
            new_generation,
            new_head: base.source_workspace.head.clone(),
            new_base_target: base.source_workspace.base_target.clone(),
            new_base_tree_hash: base.source_workspace.base_tree_hash,
            tree_deltas: deltas.clone(),
            new_tree_hash: tree_hash,
            semantic_delta,
            new_shared_admission_policy: shared_policy.clone(),
            new_admission_policy: EffectiveAdmissionPolicyStamp {
                shared: shared_policy.stamp(),
                local: base.source_workspace.admission_policy.local,
            },
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };
    transaction.validate()?;
    let transaction_hash = transaction.transaction_hash()?;

    let mut source_hashes = BTreeSet::new();
    for delta in &deltas {
        if let Some(hash) = delta
            .new_state()
            .and_then(|located| located.entry.blob_identity())
        {
            source_hashes.insert(hash);
        }
    }
    source_hashes.extend(shared_policy.sources.iter().map(|source| source.body_hash));

    let lease = authority.read_authority();
    let current_workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
        .ok_or_else(|| {
            invalid(format!(
                "repository authority has no workspace {workspace_id}"
            ))
        })?;
    let exact_base_is_current =
        lease.roots() == &base.authority_roots && current_workspace == &base.source_workspace;
    let recovered_receipt = if exact_base_is_current {
        None
    } else {
        // Whole rather than as persisted, and already validated against the
        // operation it names: a persisted receipt stopped repeating that record
        // in kin-db 0.7.89 (FIR-3064), and `rejoined_receipt` does the pairing
        // and the validation the `validate` here used to do.
        let receipt = kin_core::rejoined_receipt(lease.metadata(), base.reconcile_operation_id)
            .ok_or_else(|| {
                invalid(
                    "repository authority moved after session materialization; exact reconcile \
                     does not silently rebase",
                )
            })?;
        if receipt.transaction_hash != transaction_hash || current_workspace.tree != *desired_tree {
            return Err(invalid(
                "session operation already names a different authority transition",
            ));
        }
        Some(receipt)
    };
    drop(lease);

    Ok(SessionWorkspaceAdmissionPlan {
        transaction,
        previous_tree: base.source_workspace.tree.clone(),
        target_tree: desired_tree.clone(),
        deltas,
        vacated,
        module_relocations,
        workspace_id,
        source_hashes: source_hashes.into_iter().collect(),
        recovered_receipt,
    })
}

#[derive(Clone)]
pub(crate) struct SessionModuleRelocation {
    from: kin_model::FilePathId,
    to: kin_model::FilePathId,
    old_name: String,
    old_signature: String,
    new_name: String,
    new_signature: String,
}

/// A file module's name can derive from its path. Parse the same immutable
/// body at both locations and bind modules by exact kind, fingerprint and
/// source span, never by a guessed basename. This lets the subsequent ordinary
/// reconciliation retain their IDs even when their parser-owned names change.
fn plan_session_module_relocations(
    blobs: &kin_blobs::BlobStore,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    deltas: &[kin_model::TreeDelta],
) -> Result<Vec<SessionModuleRelocation>> {
    let pipeline = kin_index::IndexPipeline::new();
    let mut bindings = Vec::new();
    for delta in deltas {
        let kin_model::TreeDelta::Updated { old, new, .. } = delta else {
            continue;
        };
        if old.path == new.path || old.entry != new.entry {
            continue;
        }
        let kin_model::TreeEntry::Blob { hash, .. } = new.entry else {
            continue;
        };
        let (Some(from), Some(to)) = (old.path.as_utf8(), new.path.as_utf8()) else {
            continue;
        };
        let from = kin_model::FilePathId::new(from);
        let to = kin_model::FilePathId::new(to);
        let body = read_publishable_source(blobs, authority, hash)?;
        let digest = kin_blobs::Hash256::from_bytes(*hash.as_bytes());
        let before = pipeline
            .index_any_content(&from, body.body(), digest)
            .map_err(|error| invalid(format!("parse moved source {from}: {error}")))?;
        let after = pipeline
            .index_any_content(&to, body.body(), digest)
            .map_err(|error| invalid(format!("parse moved source {to}: {error}")))?;
        let (
            kin_index::IndexedAny::EntitySource(before),
            kin_index::IndexedAny::EntitySource(after),
        ) = (before, after)
        else {
            continue;
        };
        let mut claimed = std::collections::HashSet::new();
        for old_module in before
            .entities
            .iter()
            .filter(|entity| entity.kind == kin_model::EntityKind::Module)
        {
            if before.language != after.language
                || !matches!(before.parse_state, kin_model::ParseState::Valid)
                || !matches!(after.parse_state, kin_model::ParseState::Valid)
            {
                return Err(invalid(format!(
                    "moved module in {from} requires complete parses in the same language at {to}"
                )));
            }
            let matches = after
                .entities
                .iter()
                .filter(|entity| {
                    let mut relocated_span = entity.span.clone();
                    if let Some(span) = &mut relocated_span {
                        span.file = from.clone();
                    }
                    entity.kind == old_module.kind
                        && entity.fingerprint.algorithm == old_module.fingerprint.algorithm
                        && entity.fingerprint.ast_hash == old_module.fingerprint.ast_hash
                        && entity.fingerprint.behavior_hash == old_module.fingerprint.behavior_hash
                        && relocated_span.is_some()
                        && relocated_span == old_module.span
                })
                .collect::<Vec<_>>();
            let [new_module] = matches.as_slice() else {
                return Err(invalid(format!(
                    "moved module in {from} has no unambiguous exact-byte identity at {to}"
                )));
            };
            if !claimed.insert(new_module.id) {
                return Err(invalid(format!(
                    "moved modules in {from} share one exact-byte identity at {to}"
                )));
            }
            bindings.push(SessionModuleRelocation {
                from: from.clone(),
                to: to.clone(),
                old_name: old_module.name.clone(),
                old_signature: old_module.signature.clone(),
                new_name: new_module.name.clone(),
                new_signature: new_module.signature.clone(),
            });
        }
    }
    Ok(bindings)
}

pub(crate) fn bind_session_module_relocations(
    deltas: &mut [kin_model::EntityDelta],
    bindings: &[SessionModuleRelocation],
) -> Result<()> {
    for binding in bindings {
        let mut matched = false;
        for delta in deltas.iter_mut() {
            let kin_model::EntityDelta::Modified { old, new } = delta else {
                continue;
            };
            if old.kind == kin_model::EntityKind::Module
                && old.file_origin.as_ref() == Some(&binding.from)
                && new.file_origin.as_ref() == Some(&binding.to)
                && old.name == binding.old_name
                && old.signature == binding.old_signature
            {
                if matched {
                    return Err(invalid(
                        "more than one graph module claims the moved parser identity",
                    ));
                }
                matched = true;
                new.name.clone_from(&binding.new_name);
                new.signature.clone_from(&binding.new_signature);
            }
        }
    }
    Ok(())
}

/// Recover the semantic input of an exact session retry from persisted
/// overlays over the same immutable base. Replanning against the already
/// relocated workspace would produce an empty delta and a different hash.
/// The caller still requires the reconstructed transaction hash to match the
/// original durable receipt before it can return an idempotent result.
fn restore_retained_session_semantics(
    snapshot: &mut kin_db::GraphSnapshot,
    current: &kin_model::WorkspaceState,
    retained: &kin_model::WorkspaceState,
) -> Result<()> {
    if current.base_target != retained.base_target
        || current.base_tree_hash != retained.base_tree_hash
        || current.semantic_overlay.external_reference_deltas()
            != retained.semantic_overlay.external_reference_deltas()
    {
        return Err(invalid(
            "session retry no longer shares its retained semantic base",
        ));
    }
    for delta in current.semantic_overlay.entity_deltas() {
        if snapshot.entities.get(&delta.target_id()) != delta.new_state() {
            return Err(invalid(
                "current session entity overlay does not match authority",
            ));
        }
        match delta.old_state() {
            Some(old) => {
                snapshot.entities.insert(old.id, old.clone());
            }
            None => {
                snapshot.entities.remove(&delta.target_id());
            }
        }
    }
    for delta in current.semantic_overlay.relation_deltas() {
        if snapshot.relations.get(&delta.target_id()) != delta.new_state() {
            return Err(invalid(
                "current session relation overlay does not match authority",
            ));
        }
        match delta.old_state() {
            Some(old) => {
                snapshot.relations.insert(old.id, old.clone());
            }
            None => {
                snapshot.relations.remove(&delta.target_id());
            }
        }
    }
    for delta in retained.semantic_overlay.entity_deltas() {
        if snapshot.entities.get(&delta.target_id()) != delta.old_state() {
            return Err(invalid(
                "retained session entity overlay does not match its base",
            ));
        }
        match delta.new_state() {
            Some(new) => {
                snapshot.entities.insert(new.id, new.clone());
            }
            None => {
                snapshot.entities.remove(&delta.target_id());
            }
        }
    }
    for delta in retained.semantic_overlay.relation_deltas() {
        if snapshot.relations.get(&delta.target_id()) != delta.old_state() {
            return Err(invalid(
                "retained session relation overlay does not match its base",
            ));
        }
        match delta.new_state() {
            Some(new) => {
                snapshot.relations.insert(new.id, new.clone());
            }
            None => {
                snapshot.relations.remove(&delta.target_id());
            }
        }
    }
    snapshot.resolved_tree = retained.tree.clone();
    Ok(())
}

/// The paths a tree transition leaves with nothing at them, and the artifact
/// identities that held them.
///
/// A removed artifact whose old path no new state holds. A surviving artifact
/// keeps its semantic identity when its path changes; its entities relocate
/// in the same transaction as the tree. Paths are kept only in their
/// UTF-8 rendering, because only those can own entities; artifact identities
/// are kept for every vacated entry, because the cross-file linker binds
/// relations to artifact nodes whatever the path is made of.
#[derive(Debug, Clone, Default)]
pub struct VacatedPaths {
    pub paths: BTreeSet<String>,
    pub artifacts: std::collections::HashSet<kin_model::ArtifactId>,
}

impl VacatedPaths {
    pub(crate) fn from_deltas(deltas: &[kin_model::TreeDelta]) -> Self {
        let kept = deltas
            .iter()
            .filter_map(|delta| delta.new_state().map(|new| new.path.clone()))
            .collect::<BTreeSet<_>>();
        let mut vacated = Self::default();
        for delta in deltas {
            if delta.new_state().is_some() {
                continue;
            }
            let Some(old) = delta.old_state() else {
                continue;
            };
            if kept.contains(&old.path) {
                continue;
            }
            vacated.artifacts.insert(delta.artifact_id());
            if let Some(path) = old.path.as_utf8() {
                vacated.paths.insert(path.to_string());
            }
        }
        vacated
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }
}

/// Artifact identity, carried by the exact tree delta, binds each relocation.
/// Entity deltas are planned from each graph's own payloads before any move is
/// applied, so swaps cannot accidentally relocate an entity twice.
pub(crate) fn session_artifact_moves(
    deltas: &[kin_model::TreeDelta],
) -> Vec<(kin_model::FilePathId, kin_model::FilePathId)> {
    deltas
        .iter()
        .filter_map(|delta| {
            let kin_model::TreeDelta::Updated { old, new, .. } = delta else {
                return None;
            };
            if old.path == new.path {
                return None;
            }
            Some((
                kin_model::FilePathId::new(old.path.as_utf8()?),
                kin_model::FilePathId::new(new.path.as_utf8()?),
            ))
        })
        .collect()
}

pub(crate) fn plan_session_entity_relocations(
    graph: &kin_db::InMemoryGraph,
    from: &kin_model::FilePathId,
    to: &kin_model::FilePathId,
) -> Result<Vec<kin_model::EntityDelta>> {
    let mut deltas = crate::mcp_commit::plan_entity_relocations(graph, from, to)?;
    for delta in &mut deltas {
        if let kin_model::EntityDelta::Modified { new, .. } = delta {
            if let Some(span) = &mut new.span {
                span.file = to.clone();
            }
        }
    }
    Ok(deltas)
}

/// The canonical semantic transition that retires everything one graph holds
/// on a vacated path: every entity the path owns, every relation with such an
/// entity at either end, and every relation bound to the vacated artifact node
/// itself.
///
/// The last of those is the half a per-entity retirement misses. The
/// cross-file linker mints file-level `Imports` and `Includes` edges between
/// artifact nodes, which no entity reaches, and kin-db validates every relation
/// endpoint against the staged artifact set on each transaction. One surviving
/// edge fails the whole transaction with "unadmitted destination endpoint", so
/// deleting a file another file imports could not reconcile at all until these
/// were retired beside the entities. `retire_artifact_node_relations` in
/// `loop_runner` is the same rule applied to the live graph by the watcher.
///
/// This is the authority side only. The reconcile handler retires the same
/// vacated set from the live graph with [`retire_live_semantics_on_vacated`],
/// which reads that graph's own payloads through targeted queries, because the
/// two graphs can hold different payloads for the same entity: a readmission
/// after an earlier session moves the live graph's spans and leaves authority's
/// where the last commit put them. kin-db requires a removal's old payload to
/// match the graph it is applied to exactly, so a delta derived against one
/// graph and applied to the other is refused after authority has already moved,
/// which splits the two. Each graph deriving its own retirement is what keeps
/// them level.
pub(crate) fn retire_semantics_on_vacated(
    snapshot: &kin_db::GraphSnapshot,
    vacated: &VacatedPaths,
) -> Result<WorkspaceSemanticDelta> {
    let mut desired_entities = snapshot.entities.clone();
    let mut retired = std::collections::HashSet::new();
    for (entity_id, entity) in &snapshot.entities {
        let owned_by_vacated = entity
            .file_origin
            .as_ref()
            .is_some_and(|origin| vacated.paths.contains(&origin.0));
        if owned_by_vacated {
            desired_entities.remove(entity_id);
            retired.insert(*entity_id);
        }
    }
    let departs = |node: &kin_model::GraphNodeId| match node {
        kin_model::GraphNodeId::Entity(entity_id) => retired.contains(entity_id),
        kin_model::GraphNodeId::Artifact(artifact_id) => vacated.artifacts.contains(artifact_id),
        _ => false,
    };
    let mut desired_relations = snapshot.relations.clone();
    desired_relations.retain(|_, relation| !departs(&relation.src) && !departs(&relation.dst));
    kin_core::diff_workspace_semantics(
        &snapshot.entities,
        &snapshot.relations,
        &desired_entities,
        &desired_relations,
    )
    .map_err(Into::into)
}

/// The live graph's own retirement of a vacated set, read through targeted
/// queries rather than a snapshot of the whole store.
///
/// The first cut of this diffed `state.graph.to_snapshot()`, which deep-clones
/// every sub-store and the change DAG on each vacating reconcile, on the exact
/// path a one-file commit on a converted `psf/requests` already peaks past the
/// stranger's memory ceiling. This reads only what leaves: the entities each
/// vacated path owns, every relation bound to one of those entities, and every
/// relation bound to a vacated artifact node, the same three reads the watcher's
/// removal path makes. The payloads are the live graph's own, which is the whole
/// point of deriving this here rather than carrying authority's delta over.
pub(crate) fn retire_live_semantics_on_vacated(
    graph: &kin_db::InMemoryGraph,
    vacated: &VacatedPaths,
) -> Result<(Vec<kin_model::EntityDelta>, Vec<kin_model::RelationDelta>)> {
    use kin_model::EntityStore as _;
    let mut entity_deltas = Vec::new();
    let mut departing_relations = std::collections::HashMap::new();
    for path in &vacated.paths {
        let owned = graph.query_entities(&kin_model::EntityFilter {
            file_path: Some(kin_model::FilePathId::new(path)),
            ..Default::default()
        })?;
        for entity in owned {
            for relation in
                graph.get_all_relations_for_node(&kin_model::GraphNodeId::Entity(entity.id))?
            {
                departing_relations.insert(relation.id, relation);
            }
            entity_deltas.push(kin_model::EntityDelta::Removed { old: entity });
        }
    }
    for artifact_id in &vacated.artifacts {
        for relation in
            graph.get_all_relations_for_node(&kin_model::GraphNodeId::Artifact(*artifact_id))?
        {
            departing_relations.insert(relation.id, relation);
        }
    }
    let mut relation_deltas = departing_relations
        .into_values()
        .map(|old| kin_model::RelationDelta::Removed { old })
        .collect::<Vec<_>>();
    entity_deltas.sort_by_key(kin_model::EntityDelta::target_id);
    relation_deltas.sort_by_key(kin_model::RelationDelta::target_id);
    Ok((entity_deltas, relation_deltas))
}

/// Persist session-observed immutable bodies and linearize the exact primary
/// projection with one workspace-only repository transaction.
pub(crate) fn commit_session_workspace_admission(
    layout: &kin_core::KinLayout,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    plan: SessionWorkspaceAdmissionPlan,
) -> Result<SessionWorkspaceAdmissionResult> {
    let repository_id = authority_context.repository_id().clone();
    if plan.transaction.repository_id != repository_id {
        return Err(invalid(format!(
            "session admission plan belongs to {}, not {}",
            plan.transaction.repository_id, repository_id
        )));
    }
    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    for hash in &plan.source_hashes {
        if let Some(body) = read_publishable_source(blobs, &authority, *hash)?.body_to_publish() {
            authority.save_source_blob(*hash, body)?;
        }
    }

    let tree_hash = compute_resolved_tree_hash(&plan.target_tree)?;
    let (receipt, replayed) = if let Some(receipt) = plan.recovered_receipt {
        // A prior attempt crossed authority. Recovery must prove that the
        // primary projection is the same exact complete tree before reporting
        // success; graph-only members use their typed host proof.
        let freeze = kin_core::ExactProjectionFreeze::acquire_existing(layout.working_dir())?;
        let verification = freeze.verify_resolved_tree_from_blobs(&plan.target_tree, blobs)?;
        freeze.revalidate_resolved_tree_from_blobs(&verification, &plan.target_tree, blobs)?;
        (receipt, true)
    } else {
        let mut body_cache = BTreeMap::new();
        let target_entries =
            load_projection_entries(&authority, &plan.target_tree, &mut body_cache)?;
        let previous_entries =
            load_projection_entries(&authority, &plan.previous_tree, &mut body_cache)?;
        let (_, receipt) = kin_core::reconcile_source_tree_and_commit_repository_transaction(
            layout.working_dir(),
            &plan.previous_tree,
            &plan.target_tree,
            previous_entries
                .iter()
                .map(|(path, entry, body)| (path, *entry, body.as_ref())),
            target_entries
                .iter()
                .map(|(path, entry, body)| (path, *entry, body.as_ref())),
            &authority,
            plan.transaction,
        )?;
        let replayed = receipt.outcome == RepositoryCommitOutcome::IdempotentReplay;
        (receipt, replayed)
    };
    receipt.validate()?;
    Ok(SessionWorkspaceAdmissionResult {
        receipt,
        workspace_id: plan.workspace_id,
        tree_hash,
        file_count: plan.deltas.len(),
        idempotent_replay: replayed,
    })
}

/// Atomically publish one exact graph-owned workspace tree.
///
/// The caller has already performed the explicit filesystem-ingestion scan and
/// carries its completion proof in `admitted`. This boundary consumes only that
/// admitted exact tree plus bodies the repository already owns or the
/// non-authoritative ingestion CAS still stages, copies newly referenced bodies
/// into repository CAS, and compare-and-swaps the workspace. It never creates a
/// history node or advances a ref.
///
/// Bodies are read from ingestion staging first and from repository CAS when
/// staging no longer has them. Staging is not authority and promises no
/// retention, so a source the repository already published stays publishable
/// whether or not its staged copy survives.
///
/// Authority that moved after the observation was planned fails the whole
/// publication. The desired tree describes one transition out of one observed
/// prior tree; re-deriving it against a newer workspace would publish a
/// transition nobody observed, and would silently revert whatever moved
/// authority in the meantime.
pub(crate) fn publish_workspace_tree(
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    admitted: &AdmittedWorkspaceTree,
    operation_id: OperationId,
    actor: AuthorId,
) -> Result<Option<WorkspaceAdmissionResult>> {
    let desired_tree = &admitted.desired_tree;
    let repository_id = authority_context.repository_id().clone();
    let workspace_id = authority_context.workspace_id();
    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    let lease = authority.read_authority();
    if lease.roots() != &admitted.expected_roots {
        return Err(invalid(
            "repository authority moved after the complete workspace observation was planned; \
             exact admission does not replan a stale desired tree against newer authority",
        ));
    }
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
        .ok_or_else(|| {
            invalid(format!(
                "repository authority has no local workspace {workspace_id}"
            ))
        })?
        .clone();
    if workspace.repository_id != repository_id {
        return Err(invalid(format!(
            "workspace {} belongs to {}, not {}",
            workspace.workspace_id, workspace.repository_id, repository_id
        )));
    }
    if workspace.tree != admitted.previous_tree {
        return Err(invalid(
            "the complete workspace observation was planned against a tree that is not this \
             workspace's authority tree; exact admission does not replan a stale desired tree \
             against newer authority",
        ));
    }
    if workspace.tree == *desired_tree {
        return Ok(None);
    }

    let tree_deltas = kin_core::exact_tree_correction(&workspace.tree, desired_tree)?;
    let mut source_lengths = std::collections::BTreeMap::new();
    let (shared_policy, _) = SharedAdmissionPolicy::derive_from_tree_with_allowances(
        Some(&workspace.shared_admission_policy),
        desired_tree,
        |hash| {
            if let Some(length) = source_lengths.get(&hash) {
                return Ok(*length);
            }
            // Every rule file in the desired tree is measured here, changed or
            // not, because the policy is derived from the whole tree rather
            // than from what moved.
            let source = read_publishable_source(blobs, &authority, hash).map_err(|error| {
                ModelError::InvalidOperation(format!(
                    "{error}, while deriving the admitted workspace policy"
                ))
            })?;
            let length = u64::try_from(source.body().len()).map_err(|_| {
                ModelError::InvalidOperation(format!(
                    "admitted workspace policy source {hash} exceeds u64"
                ))
            })?;
            source_lengths.insert(hash, length);
            Ok(length)
        },
        |hash| {
            read_publishable_source(blobs, &authority, hash)
                .map(|source| source.body().to_vec())
                .map_err(|error| {
                    ModelError::InvalidOperation(format!(
                "{error}, while reading the approvals the admitted workspace policy derives"
            ))
                })
        },
    )?;
    let tree_hash = compute_resolved_tree_hash(desired_tree)?;
    let new_generation = workspace.generation.checked_add(1).ok_or_else(|| {
        invalid(format!(
            "workspace {} generation exhausted",
            workspace.workspace_id
        ))
    })?;
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id,
        repository_id,
        expected_generation: lease.roots().generation,
        expected_roots: lease.roots().clone(),
        actor,
        reason: "admit exact graph-owned workspace tree".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: workspace.generation,
                head: workspace.head.clone(),
                base_target: workspace.base_target.clone(),
                base_tree_hash: workspace.base_tree_hash,
                tree_hash: workspace.tree_hash,
                semantic_overlay_hash: workspace.semantic_overlay_hash,
                admission_policy: workspace.admission_policy,
            },
            new_generation,
            new_head: workspace.head,
            new_base_target: workspace.base_target,
            new_base_tree_hash: workspace.base_tree_hash,
            tree_deltas: tree_deltas.clone(),
            new_tree_hash: tree_hash,
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: shared_policy.clone(),
            new_admission_policy: EffectiveAdmissionPolicyStamp {
                shared: shared_policy.stamp(),
                local: workspace.admission_policy.local,
            },
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };
    transaction.validate()?;

    let mut source_hashes = BTreeSet::new();
    for delta in &tree_deltas {
        if let Some(hash) = delta
            .new_state()
            .and_then(|located| located.entry.blob_identity())
        {
            source_hashes.insert(hash);
        }
    }
    source_hashes.extend(shared_policy.sources.iter().map(|source| source.body_hash));
    drop(lease);

    // Copying a staged body into repository CAS is how a newly referenced
    // source becomes durable. An unchanged rule source is already there and
    // needs no copy.
    for hash in source_hashes {
        if let Some(body) = read_publishable_source(blobs, &authority, hash)?.body_to_publish() {
            authority.save_source_blob(hash, body)?;
        }
    }
    let receipt = authority.commit_repository_transaction(transaction)?;
    receipt.validate()?;
    Ok(Some(WorkspaceAdmissionResult {
        receipt,
        workspace_id,
        tree_hash,
        file_count: tree_deltas.len(),
    }))
}

/// An explicit replacement of the exact change the caller selected.
#[derive(Debug, Clone)]
pub(crate) struct NativeAmend {
    pub expected_head: SemanticChangeId,
    pub message: Option<String>,
}

/// Check the selected head before filesystem admission can mutate the workspace.
pub(crate) fn validate_native_amend_head(
    authority_context: &LocalRepositoryAuthorityContext,
    expected_head: SemanticChangeId,
) -> Result<()> {
    let authority = authority_context.open()?;
    let lease = authority.read_authority();
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority_context.workspace_id())
        .ok_or_else(|| invalid("repository authority has no local workspace"))?;
    let (_, _, head) = resolve_commit_base(
        lease.metadata(),
        &workspace.head,
        workspace.base_target.as_ref(),
    )?;
    require_amend_head(head, expected_head)
}

fn require_amend_head(head: Option<SemanticChangeId>, expected: SemanticChangeId) -> Result<()> {
    match head {
        None => Err(invalid("cannot amend an unborn workspace; create a commit first")),
        Some(actual) if actual != expected => Err(invalid(format!(
            "cannot amend {expected}: workspace HEAD is now {actual}; inspect the current change and retry"
        ))),
        Some(_) => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_native_amend(
    graph: &kin_db::InMemoryGraph,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    operation_id: OperationId,
    timestamp: Timestamp,
    actor: AuthorId,
    amend: &NativeAmend,
) -> Result<NativeCommitPlan> {
    plan_native_commit_inner(
        graph,
        blobs,
        authority_context,
        operation_id,
        timestamp,
        actor,
        None,
        &|_| String::new(),
        None,
        Some(amend),
        SemanticCurrency::DaemonMaintained,
    )
}

/// Construct one exact native transaction without mutating repository
/// authority.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_native_commit(
    graph: &kin_db::InMemoryGraph,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    operation_id: OperationId,
    timestamp: Timestamp,
    author: AuthorId,
    message: String,
) -> Result<NativeCommitPlan> {
    plan_native_commit_inner(
        graph,
        blobs,
        authority_context,
        operation_id,
        timestamp,
        author,
        None,
        &|_| message.clone(),
        None,
        None,
        SemanticCurrency::DaemonMaintained,
    )
}

/// Construct one exact native transaction against the authority generation
/// from which `base` was materialized.
///
/// This closes the read-plan race where a caller could build a prospective
/// graph from generation N while the generic planner silently based its delta
/// on generation N+1. Publication still performs the storage CAS, so a move
/// after planning also fails closed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_native_commit_from_base(
    graph: &kin_db::InMemoryGraph,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    operation_id: OperationId,
    timestamp: Timestamp,
    author: AuthorId,
    message: String,
    base: &NativeCommitBase,
) -> Result<NativeCommitPlan> {
    plan_native_commit_inner(
        graph,
        blobs,
        authority_context,
        operation_id,
        timestamp,
        author,
        None,
        &|_| message.clone(),
        Some(&base.roots),
        None,
        SemanticCurrency::AuthoritySnapshot,
    )
}

/// Plan one exact native transaction whose message states which of the files it
/// publishes the caller did not author.
///
/// A workspace can hold working-tree content its base change does not carry:
/// the admission path advances the workspace tree without advancing its base,
/// and it publishes no change, so that content sits ahead of history with no
/// authorship attached to it. It is already inside the prospective graph a
/// caller plans against, because the workspace graph takes its resolved tree
/// from the workspace, so a commit either publishes it or reverts the working
/// files that hold it. It gets published, and this is what makes that
/// publication say so.
///
/// `authored_files` names the files the caller's own operations produced. Every
/// other file this change publishes came from the pending tree, and the rendered
/// message is handed exactly that list, so the record cannot name a different
/// set than the one it published: the message is settled after the tree deltas
/// are computed and before the change is identified by its hash.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_native_commit_from_base_declaring_carry(
    graph: &kin_db::InMemoryGraph,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    operation_id: OperationId,
    timestamp: Timestamp,
    author: AuthorId,
    authored_files: &BTreeSet<RepoPath>,
    message: &dyn Fn(&[RepoPath]) -> String,
    base: &NativeCommitBase,
) -> Result<NativeCommitPlan> {
    plan_native_commit_inner(
        graph,
        blobs,
        authority_context,
        operation_id,
        timestamp,
        author,
        Some(authored_files),
        message,
        Some(&base.roots),
        None,
        SemanticCurrency::AuthoritySnapshot,
    )
}

/// The paths one change publishes that its author's own operations did not
/// write.
///
/// One definition, because two callers need the same answer from different
/// starting points: the planner has the authored set in hand, and a commit
/// resumed after an interruption recovers it from the staged operations. If
/// these ever computed the fold differently, a resumed commit would describe
/// itself differently from the one it is resuming.
pub(crate) fn carried_pending_paths(
    tree_deltas: &[kin_model::TreeDelta],
    authored: &BTreeSet<RepoPath>,
) -> Vec<RepoPath> {
    let mut carried = tree_deltas
        .iter()
        // A pending deletion moves the tree exactly as a pending edit does, and
        // is the transition a reader is least likely to expect, so it is named
        // through its old state rather than dropped for having no new one.
        .filter_map(|delta| delta.new_state().or_else(|| delta.old_state()))
        .map(|located| located.path.clone())
        .filter(|path| !authored.contains(path))
        .collect::<Vec<_>>();
    carried.sort();
    carried.dedup();
    carried
}

#[allow(clippy::too_many_arguments)]
/// One entity as a parse of the file's own bytes reproduces it: what it is,
/// what it is called, exactly which bytes it spans, and what those bytes are.
///
/// Every field is derived from the source and recorded by the graph, and none is
/// a generated id. Ids are deliberately absent: the reconciler keeps an entity's
/// id stable across an edit that moves it (`stable_entity_ids` in kin-reconcile),
/// so ids agree on a store that is stale, which is backwards for this question.
///
/// The span and the behaviour hash answer different edits, and both are needed.
/// An insertion moves every span after it and leaves the bodies alone. A
/// same-length body edit, `return 1` becoming `return 2`, leaves every span
/// exactly where it was and changes the token stream, so `behavior_hash`, the
/// hash of the entity's own source text, is the only field that moves. A
/// comparison on spans alone would seal the second one.
///
/// Every entity carrying a span is keyed, whatever role it holds, because the
/// role is the parser's verdict about the PATH rather than about whether the
/// repository owns the entity: `kin_index::classify_file_role` stamps `Test` on
/// everything parsed out of a test path, and `Vendored`, `Generated`, `Docs` and
/// `External` on their own trees. Keeping only `EntityRole::Source` compared an
/// empty key set against an empty key set for every one of those paths, so a
/// stale test file passed whatever its bytes did. The role is part of the key
/// too, so a file that moves into a test tree and re-parses under a new role
/// does not read as unchanged.
fn semantic_keys(entities: &[kin_model::Entity]) -> Vec<String> {
    let mut keys = entities
        .iter()
        .filter_map(|entity| {
            let span = entity.span.as_ref()?;
            Some(format!(
                "{:?}\u{1f}{:?}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
                entity.role,
                entity.kind,
                entity.name,
                span.start_byte,
                span.end_byte,
                entity.fingerprint.behavior_hash,
            ))
        })
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

/// Whether the entities the graph holds for one path and the entities a parse of
/// that path's own bytes produces are the same set.
///
/// Compared in both directions, as sorted multisets. One direction is not
/// enough: a declaration appended to the end of a file leaves every entity the
/// graph already held exactly where it was, with the same bytes, so a
/// held-to-fresh scan finds all of them and reports nothing while the graph is
/// missing an entity the change is about to seal bytes for.
pub(crate) fn semantics_follow_the_bytes(
    held: &[kin_model::Entity],
    fresh: &[kin_model::Entity],
) -> bool {
    semantic_keys(held) == semantic_keys(fresh)
}

/// Which of a change's tree deltas the check covers.
///
/// A path the change UPDATES can hold entities derived from the bytes it is
/// replacing. A path it ADDS cannot hold stale entities, but that is not the same
/// as holding a complete parse: a source file whose bytes reached the tree and
/// whose enrichment was lost holds no entities at all, and a change that seals it
/// leaves every declaration in it unanswerable. Both are the same defect seen
/// from different sides, so both are checked.
///
/// The exception is the FIRST admission into a repository with no head at all.
/// Its delta is the whole tree, every path in it is added, and checking them
/// would parse the entire repository at the one moment nothing has had a chance
/// to go stale: the admission that derived those entities ran inside the same
/// command. So an import pays no parse at all, and every commit after it stays
/// bounded to its own changed paths rather than to the repository. An amend of
/// the root is not that case, however few parents it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealedPathScope {
    /// Every path this change seals bytes for.
    AddedAndUpdated,
    /// Only the paths it updates, which for a root change is none of them.
    UpdatedOnly,
}

/// Whether the graph a plan is being built from is one the daemon keeps level
/// with its own tree.
///
/// The CLI route plans from the daemon's live derived graph. The reconcile keeps
/// that graph's entities level with the tree it holds, a path whose parse has
/// not landed there is the window this check exists to close, and the route can
/// re-derive it and ask again.
///
/// The MCP route plans from repository authority's own workspace graph snapshot
/// ([`load_native_commit_base`]), applies only the staged operations to it, and
/// deliberately carries pending working-tree content in as bytes. A working-tree
/// admission advances the workspace tree with no semantic delta, so authority's
/// snapshot holds the pre-edit entities for a carried path by design and there is
/// nothing on that path to re-derive from. Checking there would refuse the
/// carried-pending flow rather than catch a race. That surface seals new bytes
/// against older spans for a carried file for the same underlying reason and
/// needs its own answer; this check does not pretend to give it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SemanticCurrency {
    /// The daemon's live derived graph, which the reconcile keeps current.
    DaemonMaintained,
    /// A repository-authority workspace snapshot, which nothing re-derives.
    AuthoritySnapshot,
}

/// Paths this commit is about to seal whose graph entities a parse of the bytes
/// it is sealing does not reproduce.
///
/// A change's tree half and entity half are both read from one live graph, and
/// that graph is allowed to be behind itself for a window. An exact-tree
/// admission moves a path's bytes into repository authority on its own, and the
/// enrichment that re-derives that path's entities runs after it, can be lost
/// with the daemon that ran it, and does not survive a restart, because entities
/// reach durable authority only inside a semantic change. A commit planned
/// inside that window seals the new bytes against entities derived from the old
/// ones, and reports no entity delta at all, because the graph's entities still
/// equal the parent change's. `loop_runner` already names the class in the
/// comment above its own semantic-debt drain: an empty transition means the
/// working copy and the graph agree about bytes, not that the graph agrees with
/// itself. That drain repairs the paths some writer recorded; this refuses the
/// ones nobody did.
///
/// Answered from graph-owned truth alone. The resolved tree names a body, the
/// body is read from the content-addressed stores this commit already publishes
/// from, and the parse of it is compared against the entities the graph holds.
/// Nothing here reads the working copy.
///
/// Bounded to the tree delta, and inside it to the paths [`SealedPathScope`]
/// admits: a path the change removes seals no bytes and is never in scope, and a
/// root change checks nothing at all, so an import commit whose delta is the
/// whole tree pays no parse.
pub(crate) fn paths_whose_semantics_the_sealed_bytes_do_not_reproduce(
    graph: &kin_db::InMemoryGraph,
    blobs: &kin_blobs::BlobStore,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    tree_deltas: &[kin_model::TreeDelta],
    scope: SealedPathScope,
) -> Result<Vec<RepoPath>> {
    use kin_model::EntityStore;

    let mut behind = Vec::new();
    let pipeline = kin_index::IndexPipeline::new();
    for delta in tree_deltas {
        // A removal seals no bytes, so it is never in scope.
        let new = match (scope, delta) {
            (_, kin_model::TreeDelta::Updated { new, .. }) => new,
            (SealedPathScope::AddedAndUpdated, kin_model::TreeDelta::Added { new, .. }) => new,
            _ => continue,
        };
        // Symlinks and gitlinks are never parsed as source owned by the link
        // path, which is the rule the layout backfill and the readmission both
        // apply.
        let kin_model::TreeEntry::Blob { hash, .. } = new.entry else {
            continue;
        };
        let Some(path) = new.path.as_utf8() else {
            continue;
        };
        if !matches!(
            kin_index::FileClassifier::classify(std::path::Path::new(path)),
            kin_index::FileClassification::EntitySource
        ) {
            continue;
        }
        // A body neither store holds is a different refusal, and the publication
        // this plan feeds makes it by name. Staying quiet here leaves that one
        // intact instead of replacing it with a staleness verdict this cannot
        // reach.
        let Ok(source) = read_publishable_source(blobs, authority, hash) else {
            continue;
        };
        let content = source.body();
        // Content decides the facet exactly as admission decides it: a path
        // whose extension says source but whose bytes are opaque belongs to
        // another facet and holds no source spans of its own.
        if !matches!(
            kin_index::FileClassifier::classify_with_content(std::path::Path::new(path), content),
            kin_index::FileClassification::EntitySource
        ) {
            continue;
        }
        let file_id = kin_model::FilePathId::new(path);
        let Ok(indexed) = pipeline.index_file_content_with_tests(
            &file_id,
            content,
            kin_blobs::Hash256::from_bytes(*hash.as_bytes()),
        ) else {
            continue;
        };
        let indexed = indexed.indexed_file;
        // Only a clean parse can say the graph's entities are wrong. A file the
        // parser could not read whole keeps the entities its last readable
        // version produced, deliberately: the daemon reconciles under
        // `ReconcilePolicy::FallbackToLkg`, an author mid-edit produces this
        // constantly, and a fresh parse of a half-written file disagrees with
        // the graph for a reason that has nothing to do with the window this
        // check exists to close. Refusing on it would leave a caller holding one
        // broken file unable to record anything at all, which is the outcome
        // `drain_semantic_debt` already declines to produce for the same reason.
        if !matches!(indexed.parse_state, kin_model::ParseState::Valid) {
            continue;
        }
        let held = graph.query_entities(&kin_model::EntityFilter {
            file_path: Some(file_id.clone()),
            ..Default::default()
        })?;
        // No skip for a path the graph holds nothing at: a clean parse that
        // produces entities where the graph has none is the same defect one step
        // further along, and the comparison below already says so.
        if !semantics_follow_the_bytes(&held, &indexed.entities) {
            behind.push(new.path.clone());
        }
    }
    Ok(behind)
}

fn plan_native_commit_inner(
    graph: &kin_db::InMemoryGraph,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    operation_id: OperationId,
    timestamp: Timestamp,
    author: AuthorId,
    authored_files: Option<&BTreeSet<RepoPath>>,
    message: &dyn Fn(&[RepoPath]) -> String,
    expected_roots: Option<&RootBundle>,
    amend: Option<&NativeAmend>,
    currency: SemanticCurrency,
) -> Result<NativeCommitPlan> {
    let repository_id = authority_context.repository_id().clone();
    let workspace_id = authority_context.workspace_id();
    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    let lease = authority.read_authority();
    if expected_roots.is_some_and(|expected| expected != lease.roots()) {
        return Err(invalid(
            "repository authority moved after the prospective commit base was read",
        ));
    }
    let metadata = lease.metadata();
    let workspace = metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
        .ok_or_else(|| {
            invalid(format!(
                "repository authority has no local workspace {workspace_id}"
            ))
        })?
        .clone();
    if workspace.repository_id != repository_id {
        return Err(invalid(format!(
            "workspace {} belongs to {}, not {}",
            workspace.workspace_id, workspace.repository_id, repository_id
        )));
    }

    let (commit_target, current_ref_target, head) =
        resolve_commit_base(metadata, &workspace.head, workspace.base_target.as_ref())?;
    let previous_change = if let Some(amend) = amend {
        require_amend_head(head, amend.expected_head)?;
        Some(
            lease
                .snapshot()
                .changes
                .get(&amend.expected_head)
                .ok_or_else(|| invalid("amend target is missing from repository history"))?,
        )
    } else {
        None
    };
    let parents = previous_change
        .map(|change| change.parents.clone())
        .unwrap_or_else(|| head.into_iter().collect());
    let parent = parents.first().copied();
    let parent_policy = match parent {
        Some(parent) => Some(
            metadata
                .admission_policies
                .iter()
                .find(|candidate| candidate.change_id == parent)
                .and_then(|candidate| candidate.policy.clone())
                .ok_or_else(|| {
                    invalid(format!(
                        "native commit parent {parent} has no resolved shared admission policy"
                    ))
                })?,
        ),
        None => None,
    };

    // Both sides of the semantic diff are whole copies of the graph and neither
    // is read again once the delta exists, so both are scoped to the diff and
    // freed before the phase that follows.
    //
    // `InMemoryGraph::to_snapshot` deep-clones every sub-store, the change DAG
    // included, so on a converted repository it is a copy of the store rather
    // than a copy of the workspace. Left at function scope it stayed resident
    // through `plan_compute_deltas`, which is where a one-file commit on a
    // 1.0 GB psf/requests store reaches its resident-set peak, and through the
    // whole authority publication after it. It has nothing to contribute to
    // either.
    let workspace_semantic_delta = {
        let authority_workspace_graph =
            lease
                .workspace_graph_snapshot(&workspace_id)?
                .ok_or_else(|| {
                    invalid(format!(
                        "repository authority has no graph snapshot for workspace {workspace_id}"
                    ))
                })?;
        let desired_workspace_graph =
            crate::mcp_commit::timed_commit_phase("plan_snapshot_clone", || graph.to_snapshot());
        crate::mcp_commit::timed_commit_phase("plan_diff_semantics", || {
            kin_core::diff_workspace_semantics(
                &authority_workspace_graph.entities,
                &authority_workspace_graph.relations,
                &desired_workspace_graph.entities,
                &desired_workspace_graph.relations,
            )
        })?
    };
    let deltas = crate::mcp_commit::timed_commit_phase("plan_compute_deltas", || {
        compute_deltas_vs_repository_authority(graph, lease.snapshot(), parent.as_ref())
    })?;
    // A graph the daemon keeps current has to agree with itself before either
    // half of it is sealed. Its own phase, so what this costs is attributed
    // rather than folded into the planning around it.
    let semantics_behind_tree = match currency {
        SemanticCurrency::AuthoritySnapshot => Vec::new(),
        SemanticCurrency::DaemonMaintained => {
            crate::mcp_commit::timed_commit_phase("plan_verify_semantics_follow_bytes", || {
                paths_whose_semantics_the_sealed_bytes_do_not_reproduce(
                    graph,
                    blobs,
                    &authority,
                    &deltas.tree_deltas,
                    // The EXISTING head, not this change's parentage. An
                    // amend keeps its target's parents, so amending the root
                    // produces a change with none while the repository has a
                    // head, a published tree and every chance to have gone
                    // stale. Reading parentage as proof of first admission let
                    // a root amend seal whatever the graph held.
                    if head.is_some() {
                        SealedPathScope::AddedAndUpdated
                    } else {
                        SealedPathScope::UpdatedOnly
                    },
                )
            })?
        }
    };
    if !semantics_behind_tree.is_empty() {
        return Err(DaemonError::SemanticsBehindTree {
            paths: semantics_behind_tree
                .iter()
                .map(ToString::to_string)
                .collect(),
        });
    }
    let mut source_lengths = std::collections::BTreeMap::new();
    let (shared_policy, admission_policy_delta) =
        crate::mcp_commit::timed_commit_phase("plan_derive_admission_policy", || {
            SharedAdmissionPolicy::derive_from_tree_with_allowances(
                parent_policy.as_ref(),
                &deltas.expected_tree,
                |hash| {
                    if let Some(length) = source_lengths.get(&hash) {
                        return Ok(*length);
                    }
                    let source =
                        read_publishable_source(blobs, &authority, hash).map_err(|error| {
                            ModelError::InvalidOperation(format!(
                                "{error}, while deriving the graph-owned admission policy"
                            ))
                        })?;
                    let length = u64::try_from(source.body().len()).map_err(|_| {
                        ModelError::InvalidOperation(format!(
                            "graph-owned admission source {hash} exceeds u64"
                        ))
                    })?;
                    source_lengths.insert(hash, length);
                    Ok(length)
                },
                |hash| {
                    read_publishable_source(blobs, &authority, hash)
                        .map(|source| source.body().to_vec())
                        .map_err(|error| {
                            ModelError::InvalidOperation(format!(
                "{error}, while reading the approvals the graph-owned policy derives"
            ))
                        })
                },
            )
        })?;

    // Settled here, not before planning: the message may have to name what this
    // change carried in, and that set is not known until the published tree
    // deltas are.
    let carried_pending_files = authored_files
        .map(|authored| carried_pending_paths(&deltas.tree_deltas, authored))
        .unwrap_or_default();
    let message = match (amend, previous_change) {
        (Some(amend), Some(previous)) => amend
            .message
            .clone()
            .unwrap_or_else(|| previous.message.clone()),
        _ => message(&carried_pending_files),
    };
    if message.trim().is_empty() {
        return Err(invalid("native commit message must not be empty"));
    }

    let entity_count = deltas.entity_deltas.len();
    let relation_count = deltas.relation_deltas.len();
    let file_count = deltas.tree_deltas.len();
    let mut change = SemanticChange {
        id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
        origin: ChangeOrigin::Native,
        parents,
        timestamp,
        author: previous_change
            .map(|change| change.author.clone())
            .unwrap_or_else(|| author.clone()),
        message,
        entity_deltas: deltas.entity_deltas,
        relation_deltas: deltas.relation_deltas,
        tree_deltas: deltas.tree_deltas,
        admission_policy_delta,
        projected_files: Vec::new(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
        external_reference_deltas: Vec::new(),
    };
    change.id = compute_semantic_change_id(&change)?;
    let entity_scope_ids = change
        .entity_deltas
        .iter()
        .chain(
            previous_change
                .into_iter()
                .flat_map(|previous| previous.entity_deltas.iter()),
        )
        .map(kin_model::EntityDelta::target_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let tree_hash = compute_resolved_tree_hash(&deltas.expected_tree)?;
    let workspace_tree_deltas =
        kin_core::exact_tree_correction(&workspace.tree, &deltas.expected_tree)?;
    let workspace_generation = workspace.generation.checked_add(1).ok_or_else(|| {
        invalid(format!(
            "workspace {} generation exhausted",
            workspace.workspace_id
        ))
    })?;
    let new_target = RefTarget::change(change.id);
    // A branch commit leaves the head naming its branch and moves the branch. A
    // detached commit moves the head itself and touches no ref, which is what
    // keeps the head equal to the base that advanced beneath it.
    let (new_head, ref_mutations) = match &commit_target {
        NativeCommitTarget::Branch(branch) => (
            workspace.head.clone(),
            vec![RefMutation {
                name: branch.clone(),
                expected: current_ref_target
                    .map(|target| RefExpectation::MustEqual { target })
                    .unwrap_or(RefExpectation::MustNotExist),
                new_target: Some(new_target.clone()),
                policy: if amend.is_some() {
                    RefUpdatePolicy::ForceWithLease
                } else {
                    RefUpdatePolicy::FastForwardOnly
                },
            }],
        ),
        NativeCommitTarget::DetachedHead => (
            WorkspaceHead::Detached {
                target: new_target.clone(),
            },
            Vec::new(),
        ),
    };
    let workspace_mutation = WorkspaceMutation {
        workspace_id,
        expected: WorkspaceExpectation::MustEqual {
            generation: workspace.generation,
            head: workspace.head.clone(),
            base_target: workspace.base_target.clone(),
            base_tree_hash: workspace.base_tree_hash,
            tree_hash: workspace.tree_hash,
            semantic_overlay_hash: workspace.semantic_overlay_hash,
            admission_policy: workspace.admission_policy,
        },
        new_generation: workspace_generation,
        new_head,
        new_base_target: Some(new_target.clone()),
        new_base_tree_hash: Some(tree_hash),
        tree_deltas: workspace_tree_deltas,
        new_tree_hash: tree_hash,
        semantic_delta: workspace_semantic_delta,
        new_shared_admission_policy: shared_policy.clone(),
        new_admission_policy: EffectiveAdmissionPolicyStamp {
            shared: shared_policy.stamp(),
            local: workspace.admission_policy.local,
        },
    };
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id,
        repository_id,
        expected_generation: lease.roots().generation,
        expected_roots: lease.roots().clone(),
        actor: author,
        reason: match amend {
            Some(amend) => format!("amend native semantic change {}", amend.expected_head),
            None => "publish admitted native semantic change".to_string(),
        },
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: vec![change.clone()],
        aliases: Vec::new(),
        ref_mutations,
        default_ref_mutation: None,
        workspace_mutation: Some(workspace_mutation),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };
    transaction.validate()?;

    let mut source_hashes = BTreeSet::new();
    for delta in &change.tree_deltas {
        if let Some(hash) = delta
            .new_state()
            .and_then(|located| located.entry.blob_identity())
        {
            source_hashes.insert(hash);
        }
    }
    source_hashes.extend(shared_policy.sources.iter().map(|source| source.body_hash));

    // The lease is a read of this authority and the plan carries the authority
    // itself, so the read ends here and the open does not.
    drop(lease);
    Ok(NativeCommitPlan {
        change,
        transaction,
        target: commit_target,
        entity_count,
        relation_count,
        file_count,
        carried_pending_files,
        entity_scope_ids,
        previous_tree: workspace.tree,
        target_tree: deltas.expected_tree,
        source_hashes: source_hashes.into_iter().collect(),
        authority,
    })
}

/// Load one local workspace from repository-v6 authority as a commit base.
///
/// A workspace holding a pending tree is not refused here, and the difference
/// between that and the rule this replaces is the difference between an agent
/// that can write to a repository somebody works in and one that cannot.
/// Admission advances the workspace tree without advancing its base and
/// publishes no change, so ordinary editing leaves every used workspace ahead of
/// its base change permanently: the state never clears itself, and the refusal's
/// own remedy could not reach it, because there was no graph-owned change to
/// seal.
///
/// Refusing it never kept that content out of a commit either. The workspace
/// graph takes its resolved tree from the workspace, so the pending content is
/// inside the prospective graph every caller plans against, and a commit that
/// excluded it would have to revert the working files that hold it. What the
/// refusal actually bought was silence about a fold that was going to happen
/// anyway once the guard was lifted, which is why the caller that lifts it
/// declares the fold instead: see
/// [`plan_native_commit_from_base_declaring_carry`].
pub(crate) fn load_native_commit_base(
    authority_context: &LocalRepositoryAuthorityContext,
) -> Result<NativeCommitBase> {
    let workspace_id = authority_context.workspace_id();
    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    let lease = authority.read_authority();
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
        .ok_or_else(|| {
            invalid(format!(
                "repository authority has no local workspace {workspace_id}"
            ))
        })?;
    let tree = workspace.tree.clone();
    let snapshot = lease
        .workspace_graph_snapshot(&workspace_id)?
        .ok_or_else(|| {
            invalid(format!(
                "repository authority has no graph snapshot for workspace {workspace_id}"
            ))
        })?;
    let roots = lease.roots().clone();
    drop(lease);
    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot)?;
    Ok(NativeCommitBase { graph, roots, tree })
}

/// Load one immutable source body directly from repository-owned CAS.
pub(crate) fn load_native_source_blob(
    authority_context: &LocalRepositoryAuthorityContext,
    hash: Hash256,
) -> Result<Vec<u8>> {
    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    authority.load_source_blob(hash)?.ok_or_else(|| {
        invalid(format!(
            "repository source CAS is missing exact body {hash}"
        ))
    })
}

/// Recover the exact native change and receipt for a caller-stable operation.
///
/// A daemon can use this after restart or an indeterminate local persistence
/// acknowledgement. No transaction is rebuilt and no branch is advanced.
pub(crate) fn recover_native_commit(
    authority_context: &LocalRepositoryAuthorityContext,
    operation_id: OperationId,
) -> Result<Option<NativeCommitResult>> {
    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    let lease = authority.read_authority();
    let Some(receipt) = kin_core::rejoined_receipt(lease.metadata(), operation_id) else {
        return Ok(None);
    };
    // Reading the record's two shapes belongs to kin-core, because the CLI's own
    // recovery asks the same question of the same record and the two cannot
    // afford different answers. The multiple-targets refusal stays here: it is
    // this path's own consistency check on a receipt it is about to report as a
    // single native commit, not part of what the record says.
    if receipt
        .operation
        .ref_mutations
        .iter()
        .filter(|mutation| matches!(mutation.new_target, Some(RefTarget::Change { .. })))
        .count()
        > 1
    {
        return Err(invalid(format!(
            "repository receipt for MCP operation {operation_id} has multiple native change targets"
        )));
    }
    let published = kin_core::published_change(&receipt.operation).ok_or_else(|| {
        invalid(format!(
            "repository receipt for MCP operation {operation_id} has no native change target"
        ))
    })?;
    let change_id = published.change_id;
    let target = match published.branch {
        Some(branch) => NativeCommitTarget::Branch(branch),
        None => NativeCommitTarget::DetachedHead,
    };
    let change = lease
        .snapshot()
        .changes
        .get(&change_id)
        .cloned()
        .ok_or_else(|| {
            invalid(format!(
                "repository receipt for MCP operation {operation_id} references missing change {change_id}"
            ))
        })?;
    Ok(Some(NativeCommitResult {
        entity_count: change.entity_deltas.len(),
        relation_count: change.relation_deltas.len(),
        file_count: change.tree_deltas.len(),
        change,
        receipt,
        target,
    }))
}

/// Persist immutable bodies, then atomically publish the complete repository
/// transaction.
///
/// Product commit paths use [`commit_native_plan_with_projection`], which also
/// linearizes the working-tree transition. This bare variant exists so tests
/// can exercise repository authority publication on its own.
#[cfg(test)]
pub(crate) fn commit_native_plan(
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    plan: NativeCommitPlan,
) -> Result<NativeCommitResult> {
    let repository_id = authority_context.repository_id().clone();
    if plan.transaction.repository_id != repository_id {
        return Err(invalid(format!(
            "native plan belongs to {}, not {}",
            plan.transaction.repository_id, repository_id
        )));
    }
    let authority = plan.authority;
    for hash in &plan.source_hashes {
        if let Some(body) = read_publishable_source(blobs, &authority, *hash)?.body_to_publish() {
            authority.save_source_blob(*hash, body)?;
        }
    }
    let receipt = authority.commit_repository_transaction(plan.transaction)?;
    receipt.validate()?;
    Ok(NativeCommitResult {
        change: plan.change,
        receipt,
        target: plan.target,
        entity_count: plan.entity_count,
        relation_count: plan.relation_count,
        file_count: plan.file_count,
    })
}

/// Persist this workspace's base graph section after the commit that moved its
/// base past the last one.
///
/// `kin init` writes a section (`kin-cli/src/commands/init.rs`, through
/// `materialize_workspace_base_offline`) and nothing else did, so the first
/// commit in a repository built with Kin left `kin doctor` reporting
/// `✗ Graph section DEGRADED ... kin graph materialize writes one`, with the
/// setup footer calling it a host limit, on a store holding one change. Journey
/// GAP-4.
///
/// Through the authority this commit already holds, so it costs no second
/// O(store) open: opening one decodes the whole persisted authority and
/// re-verifies every body in repository CAS, which is the cost
/// `commit_native_plan_with_working_copy_proof` carries the planned authority
/// forward to avoid paying twice.
///
/// Unconditional, and that is the deliberate part. kin-db's writer recomputes
/// the fold it memoizes from history rather than from the section it replaces,
/// and its own doc says "ordinary publish deliberately does not pay this
/// capture's memory cost", so the obvious shape here is a size bound that leaves
/// large stores alone. That shape is wrong, because the fold is paid once either
/// way: a store whose section a commit invalidated pays it at EVERY open until
/// somebody runs `kin graph materialize`, and a store whose commit refreshed it
/// pays it once and opens clean until the next commit. Measured on 2026-09-05 on
/// an admitted express store of 470 MiB, an open with a refused section reported
/// `authority_open=37922ms` with `folded_changes=3834`, and that reading repeats
/// on every open of that store. A daemon restarts more often than a person
/// commits, the idle window guarantees it, and an open blocks the first question
/// a session asks while a commit is a heavy operation the caller already chose
/// to wait for. So the fold moves to the commit, on every store, and the elapsed
/// time is logged on every commit that pays it.
///
/// Never fatal, and deliberately not part of the receipt. The repository
/// transaction above is durable and the change is committed; a memoization that
/// did not persist is a slower next open, not a failed commit, and turning one
/// into the other would be a strictly worse product than the row this fixes.
fn refresh_workspace_base_graph_section(
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    repository_id: &kin_model::RepositoryId,
    workspace_id: WorkspaceId,
) {
    let changes_in_store = authority.read_authority().snapshot().changes.len();
    let started = std::time::Instant::now();
    let outcome = crate::mcp_commit::timed_commit_phase("materialize_graph_section", || {
        authority.materialize_workspace_base_graph_section(repository_id, &workspace_id)
    });
    let elapsed_ms = started.elapsed().as_millis();
    match outcome {
        Ok(Some(outcome)) => tracing::info!(
            repository = %repository_id,
            workspace = %workspace_id,
            changes_in_store,
            elapsed_ms,
            outcome = ?outcome,
            "refreshed the workspace base graph section after a native commit"
        ),
        Ok(None) => tracing::info!(
            repository = %repository_id,
            workspace = %workspace_id,
            "no workspace to refresh a graph section for"
        ),
        Err(error) => tracing::warn!(
            repository = %repository_id,
            workspace = %workspace_id,
            elapsed_ms,
            %error,
            "the workspace base graph section did not persist after this commit, so the next \
             open folds this base out of history; `kin graph materialize` writes one"
        ),
    }
}

/// Atomically project and publish one native repository transaction.
///
/// Source bodies are copied into repository CAS first, then the exact prior
/// and target trees are loaded back through that immutable authority. The
/// projection recovery journal linearizes the working-tree transition with
/// the repository transaction: a pre-commit failure restores the prior tree,
/// while recovery after a durable authority commit finalizes the target tree.
/// No graph-commit-then-best-effort-projection state is observable.
pub(crate) fn commit_native_plan_with_projection(
    layout: &kin_core::KinLayout,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    plan: NativeCommitPlan,
) -> Result<NativeCommitResult> {
    commit_native_plan_with_working_copy_proof(
        layout,
        blobs,
        authority_context,
        plan,
        WorkingCopyProof::MatchesPreviousTree,
    )
}

/// Publish one native repository transaction that also carries the exact tree
/// transition a completed host walk observed.
///
/// The commit seam derives its target tree from a complete filesystem scan
/// taken moments earlier under the same coordination gate, so the tree
/// transition it carries is a statement about bytes that are already on disk.
/// Saying so here lets one repository-authority successor carry both that tree
/// transition and the semantic change, instead of publishing the tree in its
/// own successor first and paying a second O(store) preparation and snapshot
/// for the change.
///
/// `observed` is that walk's proof, and it is a parameter rather than a flag
/// for the reason [`AdmittedWorkspaceTree`] exists at all: it cannot be
/// constructed without a [`kin_index::CompleteScanToken`], so a collapsed
/// commit cannot be assembled from a partial walk. Standalone publication has
/// required that proof since it was introduced, and folding the tree into this
/// transaction moves where the tree crosses authority without moving what has
/// to be true before it does.
///
/// The proof is checked against the plan rather than merely accompanying it.
/// A token proves some walk completed; it does not say which tree that walk
/// proved, and a plan built against a different pair of trees would publish a
/// transition nobody observed while carrying a genuine token for a different
/// one.
pub(crate) fn commit_native_plan_with_observed_target_tree(
    layout: &kin_core::KinLayout,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    plan: NativeCommitPlan,
    observed: &AdmittedWorkspaceTree,
) -> Result<NativeCommitResult> {
    if observed.previous_tree != plan.previous_tree {
        // The recovery is named here because this is the first thing a wedged
        // daemon says, and on its own the sentence above describes the mismatch
        // without telling anyone what to do about it. A derived graph that has
        // outrun repository authority is not cleared by admitting again, by
        // committing again, or by editing the file: each of those plans out of
        // the same graph tree and reaches the same refusal, wearing a different
        // message every time.
        return Err(invalid(
            "the completed host walk was planned out of a different workspace tree than this \
             commit publishes from; a collapsed commit may not carry a tree transition no walk \
             observed. The derived graph this daemon answers from is ahead of repository \
             authority, and no later command clears that on its own: run `kin daemon stop` and \
             then this command again",
        ));
    }
    if observed.desired_tree != plan.target_tree {
        return Err(invalid(
            "the completed host walk observed a different working tree than this commit \
             publishes; a collapsed commit may not carry a tree transition no walk observed",
        ));
    }
    commit_native_plan_with_working_copy_proof(
        layout,
        blobs,
        authority_context,
        plan,
        WorkingCopyProof::ObservedTargetTree,
    )
}

/// What the caller knows about the working copy the transaction publishes over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkingCopyProof {
    /// The working copy still holds the plan's previous tree. A tree
    /// transition is a namespace mutation and is journalled as one.
    MatchesPreviousTree,
    /// A complete scan observed the working copy already holding the plan's
    /// target tree. A tree transition is verified rather than written.
    ObservedTargetTree,
}

fn commit_native_plan_with_working_copy_proof(
    layout: &kin_core::KinLayout,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    plan: NativeCommitPlan,
    working_copy: WorkingCopyProof,
) -> Result<NativeCommitResult> {
    let repository_id = authority_context.repository_id().clone();
    if plan.transaction.repository_id != repository_id {
        return Err(invalid(format!(
            "native plan belongs to {}, not {}",
            plan.transaction.repository_id, repository_id
        )));
    }
    // The plan carries the authority it planned against, still open. The phase
    // keeps its name and its place in the table so a reader can compare a trace
    // against an older one; what it now measures is the handoff, and a commit
    // whose plan and publication share one authority reports it as the near-zero
    // span it is. A second open here would decode the whole persisted authority
    // and re-verify every body in repository CAS a second time for one change.
    let authority =
        crate::mcp_commit::timed_commit_phase("open_repository_authority", || plan.authority);
    crate::mcp_commit::timed_commit_phase("stage_changed_source_blobs", || {
        for hash in &plan.source_hashes {
            if let Some(body) = read_publishable_source(blobs, &authority, *hash)?.body_to_publish()
            {
                authority.save_source_blob(*hash, body)?;
            }
        }
        Ok::<(), DaemonError>(())
    })?;

    let mut body_cache = BTreeMap::new();
    let target_entries = crate::mcp_commit::timed_commit_phase("load_projection_entries", || {
        load_projection_entries(&authority, &plan.target_tree, &mut body_cache)
    })?;
    let (projected, receipt) = if plan.previous_tree == plan.target_tree {
        crate::mcp_commit::timed_commit_phase("reconcile_workspace_and_commit_authority", || {
            kin_core::verify_unchanged_source_tree_and_commit_repository_transaction(
                layout.working_dir(),
                &plan.target_tree,
                target_entries
                    .iter()
                    .map(|(path, entry, body)| (path, *entry, body.as_ref())),
                &authority,
                plan.transaction,
            )
        })?
    } else {
        let previous_entries =
            crate::mcp_commit::timed_commit_phase("load_previous_projection_entries", || {
                load_projection_entries(&authority, &plan.previous_tree, &mut body_cache)
            })?;
        match working_copy {
            WorkingCopyProof::ObservedTargetTree => crate::mcp_commit::timed_commit_phase(
                "reconcile_workspace_and_commit_authority",
                || {
                    kin_core::verify_observed_target_tree_and_commit_repository_transaction(
                        layout.working_dir(),
                        &plan.previous_tree,
                        &plan.target_tree,
                        previous_entries
                            .iter()
                            .map(|(path, entry, body)| (path, *entry, body.as_ref())),
                        target_entries
                            .iter()
                            .map(|(path, entry, body)| (path, *entry, body.as_ref())),
                        &authority,
                        plan.transaction,
                    )
                },
            )?,
            WorkingCopyProof::MatchesPreviousTree => crate::mcp_commit::timed_commit_phase(
                "reconcile_workspace_and_commit_authority",
                || {
                    kin_core::reconcile_source_tree_and_commit_repository_transaction(
                        layout.working_dir(),
                        &plan.previous_tree,
                        &plan.target_tree,
                        previous_entries
                            .iter()
                            .map(|(path, entry, body)| (path, *entry, body.as_ref())),
                        target_entries
                            .iter()
                            .map(|(path, entry, body)| (path, *entry, body.as_ref())),
                        &authority,
                        plan.transaction,
                    )
                },
            )?,
        }
    };
    let materializable = materializable_artifact_count(&plan.target_tree)?;
    if projected != materializable {
        return Err(invalid(format!(
            "exact projection verified {projected} source artifacts but target authority contains \
             {materializable} materializable artifacts"
        )));
    }
    receipt.validate()?;
    refresh_workspace_base_graph_section(
        &authority,
        &repository_id,
        authority_context.workspace_id(),
    );
    Ok(NativeCommitResult {
        change: plan.change,
        receipt,
        target: plan.target,
        entity_count: plan.entity_count,
        relation_count: plan.relation_count,
        file_count: plan.file_count,
    })
}

fn load_projection_entries(
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    tree: &kin_model::ResolvedTree,
    body_cache: &mut BTreeMap<Hash256, Arc<[u8]>>,
) -> Result<Vec<ProjectionEntry>> {
    let mut entries = Vec::with_capacity(materializable_artifact_count(tree)?);
    for artifact in tree.artifacts_by_path() {
        if kin_core::source_projection_disposition(&artifact.path, artifact.entry)?
            != kin_core::SourceProjectionDisposition::Materialized
        {
            continue;
        }
        let hash = artifact.entry.blob_identity().ok_or_else(|| {
            invalid(format!(
                "materializable repository entry {} has no source identity",
                artifact.path
            ))
        })?;
        let body = if let Some(body) = body_cache.get(&hash) {
            Arc::clone(body)
        } else {
            let body: Arc<[u8]> = authority
                .load_source_blob(hash)?
                .ok_or_else(|| {
                    invalid(format!(
                        "repository source CAS is missing {} for {}",
                        hash, artifact.path
                    ))
                })?
                .into();
            body_cache.insert(hash, Arc::clone(&body));
            body
        };
        entries.push((artifact.path.clone(), artifact.entry, body));
    }
    Ok(entries)
}

fn materializable_artifact_count(tree: &kin_model::ResolvedTree) -> Result<usize> {
    let mut count = 0;
    for artifact in tree.artifacts_by_path() {
        if kin_core::source_projection_disposition(&artifact.path, artifact.entry)?
            == kin_core::SourceProjectionDisposition::Materialized
        {
            count += 1;
        }
    }
    Ok(count)
}

/// Where a prospective native commit publishes, and what its parent is.
///
/// The second element is the compare-and-swap expectation for the branch ref a
/// symbolic commit fast-forwards, and is always `None` on a detached head,
/// which moves no ref at all.
///
/// A detached workspace used to be refused here outright. It is not refused any
/// more, because the refusal answered a question the model had already
/// answered: `kin_model`'s `validate_head_base` accepts a detached head whose
/// target is a `RefTarget::Change`, and requires that head to equal the
/// workspace base. A commit advances the base to the new change, so a detached
/// head that stayed put would contradict its own base and the transaction would
/// be refused one layer down. That is what made the old refusal load-bearing,
/// and it is also what says the fix: the head moves with the base.
fn resolve_commit_base(
    metadata: &kin_db::PersistedRepositoryAuthority,
    head: &WorkspaceHead,
    workspace_base: Option<&RefTarget>,
) -> Result<(
    NativeCommitTarget,
    Option<RefTarget>,
    Option<SemanticChangeId>,
)> {
    match head {
        WorkspaceHead::Symbolic { target: branch } => {
            let current = metadata
                .ref_state
                .refs
                .iter()
                .find(|repository_ref| repository_ref.name == *branch)
                .map(|repository_ref| repository_ref.target.clone());
            if current.as_ref() != workspace_base {
                return Err(invalid(format!(
                    "workspace base does not match current symbolic ref {branch}; refresh or rebase before commit"
                )));
            }
            let parent = match current.as_ref() {
                None => None,
                Some(target) => Some(parent_change_at(metadata, target)?),
            };
            Ok((NativeCommitTarget::Branch(branch.clone()), current, parent))
        }
        WorkspaceHead::Detached { target } => {
            // Durable authority already binds these two together, so a
            // disagreement is a store nobody should commit onto rather than a
            // choice between two readings of where the workspace stands.
            if workspace_base != Some(target) {
                return Err(invalid(
                    "detached workspace HEAD does not match the workspace base; refresh before commit",
                ));
            }
            let parent = parent_change_at(metadata, target)?;
            Ok((NativeCommitTarget::DetachedHead, None, Some(parent)))
        }
    }
}

/// The semantic change one resolved authority target names.
///
/// A change names itself. An external Git commit names the change it was
/// admitted as, and a commit with no alias is a store that cannot describe its
/// own base. A symbolic target is not resolved at all, which durable authority
/// already refuses for both a workspace base and a detached head, so this arm
/// is a refusal rather than an assumption.
fn parent_change_at(
    metadata: &kin_db::PersistedRepositoryAuthority,
    target: &RefTarget,
) -> Result<SemanticChangeId> {
    match target {
        RefTarget::Change { change_id } => Ok(*change_id),
        RefTarget::ExternalObject { object } => metadata
            .aliases
            .iter()
            .find(|alias| alias.oid == object.oid)
            .map(|alias| alias.change_id)
            .ok_or_else(|| {
                invalid(format!(
                    "workspace base external commit {} has no semantic alias",
                    object.oid
                ))
            }),
        RefTarget::Symbolic { target } => Err(invalid(format!(
            "native commit does not yet mutate symbolic ref chain ending at {target}"
        ))),
    }
}

fn invalid(message: impl Into<String>) -> DaemonError {
    ModelError::InvalidOperation(message.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        ArtifactId, EntityStore, LocatedEntry, RepoPath, RepositoryAuthorityStore,
        ResolvedArtifact, ResolvedTree, TransactionDelta, TreeDelta, TreeEntry,
    };

    fn add_artifact(
        graph: &kin_db::InMemoryGraph,
        blobs: &kin_blobs::BlobStore,
        path: &[u8],
        bytes: &[u8],
        entry: impl FnOnce(Hash256) -> TreeEntry,
    ) -> ResolvedArtifact {
        let digest = blobs.write(bytes).unwrap();
        let artifact = ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_bytes(path.to_vec()).unwrap(),
            entry(Hash256::from_bytes(digest.0)),
        );
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: artifact.artifact_id,
                    new: LocatedEntry::new(artifact.path.clone(), artifact.entry),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();
        artifact
    }

    fn fixed_timestamp() -> Timestamp {
        Timestamp::from(
            chrono::DateTime::parse_from_rfc3339("2026-07-26T12:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
    }

    fn reopen(init: &kin_core::InitResult) -> RepositoryAuthorityManager<LocalFileBackend> {
        RepositoryAuthorityManager::open(
            init.repository_id.clone(),
            Arc::new(LocalFileBackend::new(init.layout.kindb_dir())),
        )
        .unwrap()
    }

    fn test_authority_context(layout: &kin_core::KinLayout) -> LocalRepositoryAuthorityContext {
        LocalRepositoryAuthorityContext::from_layout_for_test(layout).unwrap()
    }

    fn publish_workspace_tree(
        layout: &kin_core::KinLayout,
        blobs: &kin_blobs::BlobStore,
        desired_tree: &ResolvedTree,
        operation_id: OperationId,
        actor: AuthorId,
    ) -> Result<Option<WorkspaceAdmissionResult>> {
        let context = test_authority_context(layout);
        let authority = context.open()?;
        let lease = authority.read_authority();
        let expected_roots = lease.roots().clone();
        let previous_tree = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == context.workspace_id())
            .map(|workspace| workspace.tree.clone())
            .unwrap_or_default();
        drop(lease);
        let admitted = super::admitted_workspace_tree_for_test(
            layout.working_dir(),
            expected_roots,
            previous_tree,
            desired_tree.clone(),
        );
        super::publish_workspace_tree(blobs, &context, &admitted, operation_id, actor)
    }

    #[allow(clippy::too_many_arguments)]
    fn plan_native_commit(
        layout: &kin_core::KinLayout,
        graph: &kin_db::InMemoryGraph,
        blobs: &kin_blobs::BlobStore,
        operation_id: OperationId,
        timestamp: Timestamp,
        author: AuthorId,
        message: String,
    ) -> Result<NativeCommitPlan> {
        super::plan_native_commit(
            graph,
            blobs,
            &test_authority_context(layout),
            operation_id,
            timestamp,
            author,
            message,
        )
    }

    fn commit_native_plan(
        layout: &kin_core::KinLayout,
        blobs: &kin_blobs::BlobStore,
        plan: NativeCommitPlan,
    ) -> Result<NativeCommitResult> {
        super::commit_native_plan(blobs, &test_authority_context(layout), plan)
    }

    fn commit_native_plan_with_projection(
        layout: &kin_core::KinLayout,
        blobs: &kin_blobs::BlobStore,
        plan: NativeCommitPlan,
    ) -> Result<NativeCommitResult> {
        super::commit_native_plan_with_projection(
            layout,
            blobs,
            &test_authority_context(layout),
            plan,
        )
    }

    /// One commit opens the repository authority exactly once.
    ///
    /// An open is O(store) rather than a cheap handle: kin-db decodes the whole
    /// persisted authority and then re-verifies every body in repository CAS
    /// against its content address, unconditionally, on every one. A commit that
    /// planned against one open authority and then published through a second
    /// paid that whole cost twice to record one change, so the plan carries the
    /// authority it planned against and the publication consumes it.
    ///
    /// The count is the invariant, not the timing. A publication that opens its
    /// own authority again fails the second assertion here whatever the store
    /// costs to open, including on a fixture small enough for the duplicate to
    /// be invisible in wall time.
    #[test]
    fn one_commit_opens_the_repository_authority_once() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        add_artifact(
            &graph,
            &blobs,
            b"api.py",
            b"def get():\n    pass\n",
            |hash| TreeEntry::blob(hash, false),
        );

        crate::local_repository_authority::reset_authority_open_count();
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("commitwall"),
            "publish one artifact".to_string(),
        )
        .unwrap();
        assert_eq!(
            crate::local_repository_authority::authority_open_count(),
            1,
            "planning must open the repository authority exactly once"
        );

        commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();
        assert_eq!(
            crate::local_repository_authority::authority_open_count(),
            1,
            "the publication opened a second repository authority instead of consuming the \
             one the plan carries; every open decodes the whole persisted authority and \
             re-verifies every body in repository CAS, so this commit paid that twice"
        );
    }

    /// A desired tree describes one transition out of one observed prior tree.
    /// Once authority has moved past that prior tree, re-deriving the same
    /// desired tree against the newer workspace would publish a transition
    /// nobody observed and silently revert whatever moved authority. The stale
    /// admission must be refused instead.
    #[test]
    fn stale_desired_tree_is_refused_against_newer_authority() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        let observed = add_artifact(&graph, &blobs, b"observed.txt", b"observed\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let concurrent = add_artifact(
            &graph,
            &blobs,
            b"concurrent.txt",
            b"published by someone else\n",
            |hash| TreeEntry::blob(hash, false),
        );

        let context = test_authority_context(&init.layout);
        let roots_at_observation = context.open().unwrap().read_authority().roots().clone();
        let previous_tree = ResolvedTree::default();

        // The observation is planned against the empty workspace tree.
        let stale = super::admitted_workspace_tree_for_test(
            init.layout.working_dir(),
            roots_at_observation.clone(),
            previous_tree.clone(),
            ResolvedTree::from_artifacts([observed]).unwrap(),
        );

        // Authority moves before the stale admission reaches publication.
        publish_workspace_tree(
            &init.layout,
            &blobs,
            &ResolvedTree::from_artifacts([concurrent.clone()]).unwrap(),
            OperationId::new(),
            AuthorId::new("concurrent-writer"),
        )
        .unwrap()
        .expect("the concurrent transition must advance authority");

        let roots_after_concurrent = context.open().unwrap().read_authority().roots().clone();
        assert_ne!(roots_at_observation, roots_after_concurrent);

        let error = super::publish_workspace_tree(
            &blobs,
            &context,
            &stale,
            OperationId::new(),
            AuthorId::new("stale-observer"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not replan a stale desired tree against newer authority"),
            "{error}"
        );

        let lease = context.open().unwrap().read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap()
            .clone();
        drop(lease);
        assert_eq!(
            workspace.tree,
            ResolvedTree::from_artifacts([concurrent]).unwrap(),
            "the refused stale admission must not revert the concurrent transition"
        );
        assert!(workspace
            .tree
            .artifact_at_path(&kin_model::RepoPath::from_utf8("observed.txt").unwrap())
            .is_none());
    }

    /// The same refusal applies when authority did not move but the plan was
    /// taken against a tree that was never this workspace's authority tree.
    #[test]
    fn desired_tree_planned_against_a_foreign_prior_tree_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let invented = add_artifact(
            &graph,
            &blobs,
            b"invented.txt",
            b"never admitted\n",
            |hash| TreeEntry::blob(hash, false),
        );
        let desired = add_artifact(&graph, &blobs, b"desired.txt", b"desired\n", |hash| {
            TreeEntry::blob(hash, false)
        });

        let context = test_authority_context(&init.layout);
        let roots = context.open().unwrap().read_authority().roots().clone();
        let admitted = super::admitted_workspace_tree_for_test(
            init.layout.working_dir(),
            roots,
            ResolvedTree::from_artifacts([invented]).unwrap(),
            ResolvedTree::from_artifacts([desired]).unwrap(),
        );

        let error = super::publish_workspace_tree(
            &blobs,
            &context,
            &admitted,
            OperationId::new(),
            AuthorId::new("foreign-base-observer"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not replan a stale desired tree against newer authority"),
            "{error}"
        );
    }

    #[test]
    fn workspace_admission_persists_dirty_exact_tree_without_history_or_ref_move() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let compose = add_artifact(
            &graph,
            &blobs,
            b"compose.yaml",
            b"services:\n  app:\n    image: kin:test\n",
            |hash| TreeEntry::blob(hash, false),
        );
        let opaque = add_artifact(
            &graph,
            &blobs,
            b"assets/model.bin",
            &[0, 0xff, 0x41, 0x00],
            |hash| TreeEntry::blob(hash, false),
        );
        let symlink = add_artifact(
            &graph,
            &blobs,
            b"current-compose",
            b"compose.yaml",
            TreeEntry::symlink,
        );
        let desired = ResolvedTree::from_artifacts([compose, opaque, symlink]).unwrap();

        let initial_authority = reopen(&init);
        let initial_lease = initial_authority.read_authority();
        let initial_workspace = initial_lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap()
            .clone();
        let initial_refs = initial_lease.metadata().ref_state.clone();
        drop(initial_lease);

        let result = publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("dogfood"),
        )
        .unwrap()
        .expect("dirty exact tree must advance workspace authority");
        assert_eq!(result.receipt.generation, 2);
        assert_eq!(result.workspace_id, init.workspace_id);
        assert_eq!(result.file_count, 3);
        assert_eq!(
            result.tree_hash,
            compute_resolved_tree_hash(&desired).unwrap()
        );

        let authority = reopen(&init);
        let lease = authority.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        assert_eq!(workspace.tree, desired);
        assert_eq!(workspace.head, initial_workspace.head);
        assert_eq!(workspace.base_target, initial_workspace.base_target);
        assert_eq!(workspace.base_tree_hash, initial_workspace.base_tree_hash);
        assert!(workspace.is_dirty());
        assert_eq!(lease.metadata().ref_state, initial_refs);
        assert!(lease.snapshot().changes.is_empty());
        for artifact in desired.artifacts() {
            if let Some(hash) = artifact.entry.blob_identity() {
                assert_eq!(
                    authority.load_source_blob(hash).unwrap().as_deref(),
                    Some(blobs.read(&hash).unwrap().as_slice())
                );
            }
        }
        drop(lease);

        assert!(publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("dogfood"),
        )
        .unwrap()
        .is_none());
        assert_eq!(reopen(&init).read_authority().roots().generation, 2);
    }

    /// Publication must not depend on ingestion staging still holding a body the
    /// repository already owns.
    ///
    /// Every `.gitignore` and `.kinignore` blob in the desired tree is measured
    /// on every publication, because the shared admission policy is derived from
    /// the whole tree and not from what changed. Bounding one tick to what moved
    /// removed the per-scan rewrite that used to restage every leaf ahead of
    /// every publication, so that read now has to reach the store that actually
    /// promises the body. Staging is not authority and keeps no retention
    /// promise; a store that loses it while its authority survives must still
    /// publish, instead of failing every admission until someone happens to edit
    /// a rule file.
    #[test]
    fn an_unchanged_rule_source_publishes_after_ingestion_staging_is_lost() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        let rules = add_artifact(&graph, &blobs, b".gitignore", b"target/\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let first = add_artifact(
            &graph,
            &blobs,
            b"first.rs",
            b"pub fn first() {}\n",
            |hash| TreeEntry::blob(hash, false),
        );
        publish_workspace_tree(
            &init.layout,
            &blobs,
            &ResolvedTree::from_artifacts([rules.clone(), first.clone()]).unwrap(),
            OperationId::new(),
            AuthorId::new("fir2152"),
        )
        .unwrap()
        .expect("the first transition must advance workspace authority");

        // Lose the staging directory the way a restore that carries the
        // authority database but not a directory named like a cache does.
        let rules_hash = rules.entry.blob_identity().unwrap();
        std::fs::remove_dir_all(init.layout.ingest_cas_dir()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        assert!(
            blobs.read(&rules_hash).is_err(),
            "the fixture only proves anything while the staged rule body is genuinely gone"
        );

        let second = add_artifact(
            &graph,
            &blobs,
            b"second.rs",
            b"pub fn second() {}\n",
            |hash| TreeEntry::blob(hash, false),
        );
        let desired = ResolvedTree::from_artifacts([rules.clone(), first, second]).unwrap();
        let result = publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("fir2152"),
        )
        .unwrap()
        .expect("a transition that leaves the rule file untouched must still advance authority");
        assert_eq!(result.receipt.generation, 3);

        let authority = reopen(&init);
        let lease = authority.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        assert_eq!(workspace.tree, desired);
        assert_eq!(
            workspace
                .shared_admission_policy
                .sources
                .iter()
                .map(|source| source.path.clone())
                .collect::<Vec<_>>(),
            vec![rules.path.clone()],
            "the derived policy still names the rule file whose body only authority holds"
        );
    }

    /// Publish a rule file and one source, lose the whole staging directory,
    /// then publish a second source through `publish`.
    ///
    /// The second transition has to read one body from each store: the new
    /// file's is staged, and the untouched `.gitignore` the policy still
    /// measures is only in repository CAS.
    fn publish_across_a_lost_staging_directory(
        publish: fn(
            &kin_core::KinLayout,
            &kin_blobs::BlobStore,
            NativeCommitPlan,
        ) -> Result<NativeCommitResult>,
    ) -> (tempfile::TempDir, kin_core::InitResult) {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        let rules = add_artifact(&graph, &blobs, b".gitignore", b"target/\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        add_artifact(
            &graph,
            &blobs,
            b"first.rs",
            b"pub fn first() {}\n",
            |hash| TreeEntry::blob(hash, false),
        );
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("fir2171"),
            "publish the rule file and one source".to_string(),
        )
        .unwrap();
        publish(&init.layout, &blobs, plan).unwrap();

        // Lose the staging directory the way a restore that carries the
        // authority database but not a directory named like a cache does.
        let rules_hash = rules.entry.blob_identity().unwrap();
        std::fs::remove_dir_all(init.layout.ingest_cas_dir()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        assert!(
            blobs
                .read(&kin_blobs::Hash256::from_bytes(*rules_hash.as_bytes()))
                .is_err(),
            "the fixture only proves anything while the staged rule body is genuinely gone"
        );

        add_artifact(
            &graph,
            &blobs,
            b"second.rs",
            b"pub fn second() {}\n",
            |hash| TreeEntry::blob(hash, false),
        );
        // Its semantics land with its bytes, as an admission derives them.
        derive_entities_into_graph(&graph, &blobs, "second.rs", b"pub fn second() {}\n");
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("fir2171"),
            "publish a change that leaves the rule file untouched".to_string(),
        )
        .unwrap();
        let result = publish(&init.layout, &blobs, plan).unwrap();
        assert_eq!(result.receipt.generation, 3);

        let authority = reopen(&init);
        assert_eq!(
            authority.load_source_blob(rules_hash).unwrap().as_deref(),
            Some(b"target/\n".as_slice()),
            "the rule body the commit measured is the one authority already held"
        );
        (root, init)
    }

    /// The same loss on the native commit path, which reads unchanged bodies
    /// twice: once to measure every rule file while deriving the policy, and
    /// once to copy every source the change references into repository CAS.
    /// Neither read is bounded to what moved, so an untouched `.gitignore` is
    /// consulted by every commit forever, and before this both reads went to
    /// ingestion staging alone.
    #[test]
    fn a_native_commit_publishes_after_ingestion_staging_is_lost() {
        let (root, _init) =
            publish_across_a_lost_staging_directory(commit_native_plan_with_projection);
        assert_eq!(
            std::fs::read(root.path().join("second.rs")).unwrap(),
            b"pub fn second() {}\n",
            "the projecting path still materializes what it published"
        );
    }

    /// The bare publication path carries its own copy loop, and tests reach
    /// authority through it. A test helper that reads one store where product
    /// code reads two would pass while the thing it stands in for fails.
    #[test]
    fn a_bare_native_publication_publishes_after_ingestion_staging_is_lost() {
        let (root, _init) = publish_across_a_lost_staging_directory(commit_native_plan);
        assert!(
            !root.path().join("second.rs").exists(),
            "publication without projection is what distinguishes this path from the other"
        );
    }

    /// The control that keeps the fallback from swallowing a real loss. A body
    /// no store holds is not an unchanged body that authority already owns, and
    /// a publication that cannot find one must still refuse, as the typed blob
    /// absence rather than as a sentence.
    #[test]
    fn a_native_commit_still_refuses_a_body_neither_store_holds() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        add_artifact(&graph, &blobs, b".gitignore", b"target/\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("fir2171"),
            "publish the rule file".to_string(),
        )
        .unwrap();
        commit_native_plan(&init.layout, &blobs, plan).unwrap();

        // Staged and never published, then lost: the one body that is genuinely
        // gone rather than merely unstaged.
        add_artifact(
            &graph,
            &blobs,
            b"orphan.rs",
            b"pub fn orphan() {}\n",
            |hash| TreeEntry::blob(hash, false),
        );
        std::fs::remove_dir_all(init.layout.ingest_cas_dir()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();

        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("fir2171"),
            "publish a body no store holds".to_string(),
        )
        .expect("the rule file authority still owns lets planning get as far as publication");
        let error = commit_native_plan(&init.layout, &blobs, plan)
            .expect_err("a body neither store holds cannot be published");
        assert!(
            matches!(error, DaemonError::Blob(_)),
            "absence stays the typed blob failure a caller can match on: {error}"
        );
    }

    #[test]
    fn workspace_admission_cannot_invent_unverified_gitlink_authority() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let desired = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("vendor/semantic-engine").unwrap(),
            TreeEntry::gitlink(kin_model::GitObjectId::sha1([0x73; 20])),
        )])
        .unwrap();

        let error = publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("dogfood"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("without verified Git external authority"),
            "unexpected external-authority rejection: {error}"
        );
        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(lease.roots().generation, 1);
        assert!(lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap()
            .tree
            .is_empty());
    }

    #[test]
    fn workspace_admission_missing_body_cannot_advance_authority() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let desired = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("compose.yaml").unwrap(),
            TreeEntry::blob(Hash256::from_bytes([0xee; 32]), false),
        )])
        .unwrap();

        let error = publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("dogfood"),
        )
        .unwrap_err();
        assert!(
            matches!(
                &error,
                DaemonError::Blob(kin_blobs::BlobError::NotFound { .. })
            ),
            "missing admitted body must surface the typed blob absence, got {error:?}"
        );
        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(lease.roots().generation, 1);
        assert!(lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap()
            .tree
            .is_empty());
    }

    #[test]
    fn native_commit_atomically_projects_exact_non_code_tree_and_ref() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let compose = add_artifact(
            &graph,
            &blobs,
            b"compose.yaml",
            b"services:\n  app:\n    image: kin:test\n",
            |hash| TreeEntry::blob(hash, false),
        );
        let dockerfile = add_artifact(&graph, &blobs, b"Dockerfile", b"FROM scratch\n", |hash| {
            TreeEntry::blob(hash, true)
        });
        let opaque = add_artifact(
            &graph,
            &blobs,
            b"assets/model.bin",
            &[0, 0xff, 0x41, 0x00],
            |hash| TreeEntry::blob(hash, false),
        );
        let symlink = add_artifact(
            &graph,
            &blobs,
            b"current-compose",
            b"compose.yaml",
            TreeEntry::symlink,
        );

        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("dogfood"),
            "commit exact repository artifacts".to_string(),
        )
        .unwrap();
        assert_eq!(plan.file_count, 4);
        let result = commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();
        assert_eq!(result.receipt.generation, 2);
        assert_eq!(
            std::fs::read(root.path().join("compose.yaml")).unwrap(),
            b"services:\n  app:\n    image: kin:test\n"
        );
        assert_eq!(
            std::fs::read(root.path().join("Dockerfile")).unwrap(),
            b"FROM scratch\n"
        );
        assert_eq!(
            std::fs::read(root.path().join("assets/model.bin")).unwrap(),
            [0, 0xff, 0x41, 0x00]
        );
        assert_eq!(
            std::fs::read_link(root.path().join("current-compose")).unwrap(),
            std::path::PathBuf::from("compose.yaml")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_ne!(
                std::fs::metadata(root.path().join("Dockerfile"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
        }

        let authority = reopen(&init);
        let lease = authority.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        let expected =
            ResolvedTree::from_artifacts([compose, dockerfile, opaque, symlink]).unwrap();
        assert_eq!(workspace.tree, expected);
        assert_eq!(
            workspace.base_target,
            Some(RefTarget::change(result.change.id))
        );
        assert_eq!(
            authority
                .get_repository_ref(
                    &init.repository_id,
                    result
                        .target
                        .branch()
                        .expect("a workspace on a branch publishes onto that branch"),
                )
                .unwrap()
                .unwrap()
                .target,
            RefTarget::change(result.change.id)
        );
        for artifact in expected.artifacts() {
            if let Some(hash) = artifact.entry.blob_identity() {
                assert!(authority.load_source_blob(hash).unwrap().is_some());
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_commit_preserves_host_unrepresentable_byte_exact_path() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let raw_path = b"assets/icon-\xff.bin";
        let body = b"\0opaque non-code bytes\xff";
        let artifact = add_artifact(&graph, &blobs, raw_path, body, |hash| {
            TreeEntry::blob(hash, false)
        });
        let desired = ResolvedTree::from_artifacts([artifact]).unwrap();

        publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("admission"),
        )
        .unwrap()
        .expect("raw path must enter workspace authority before commit");
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("dogfood"),
            "commit byte-exact unsupported artifact".to_string(),
        )
        .unwrap();
        let result = commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();

        assert_eq!(result.receipt.generation, 3);
        assert!(
            !root.path().join("assets").exists(),
            "host-unrepresentable repository path must remain graph-only"
        );
        let authority = reopen(&init);
        let lease = authority.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        assert_eq!(workspace.tree, desired);
        let raw = workspace
            .tree
            .artifact_at_path(&RepoPath::from_bytes(raw_path.to_vec()).unwrap())
            .unwrap();
        let digest = raw.entry.blob_identity().unwrap();
        assert_eq!(
            authority.load_source_blob(digest).unwrap().as_deref(),
            Some(body.as_slice())
        );
        assert_eq!(
            authority
                .get_repository_ref(
                    &init.repository_id,
                    result
                        .target
                        .branch()
                        .expect("a workspace on a branch publishes onto that branch"),
                )
                .unwrap()
                .unwrap()
                .target,
            RefTarget::change(result.change.id)
        );
    }

    /// Park the workspace on its own base with no branch naming it.
    ///
    /// This is where a repository converted while Git's HEAD was detached
    /// stands from admission onward: `init.rs` maps a direct raw Git HEAD onto
    /// `WorkspaceHead::Detached`, and nothing re-reads Git afterwards. Reaching
    /// that state through an ordinary workspace mutation rather than through a
    /// Git conversion keeps these tests in one crate, and the state is the same
    /// state because durable authority is what both produce.
    fn detach_workspace_head(layout: &kin_core::KinLayout) -> RepositoryCommitReceipt {
        let context = test_authority_context(layout);
        let authority = context.open().unwrap();
        let lease = authority.read_authority();
        let metadata = lease.metadata();
        let workspace = metadata
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == context.workspace_id())
            .expect("the test repository has one workspace")
            .clone();
        let base = workspace
            .base_target
            .clone()
            .expect("a detached head binds a base, so commit at least once first");
        let base_change = lease.resolve_target_change_id(&base).unwrap();
        let shared = metadata
            .admission_policies
            .iter()
            .find(|resolved| resolved.change_id == base_change)
            .and_then(|resolved| resolved.policy.clone())
            .expect("the base change carries a resolved shared admission policy");
        let roots = lease.roots().clone();
        drop(lease);
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: context.repository_id().clone(),
            expected_generation: roots.generation,
            expected_roots: roots,
            actor: AuthorId::new("detach"),
            reason: "park this workspace on its base with no branch".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: Some(WorkspaceMutation {
                workspace_id: workspace.workspace_id,
                expected: WorkspaceExpectation::MustEqual {
                    generation: workspace.generation,
                    head: workspace.head.clone(),
                    base_target: workspace.base_target.clone(),
                    base_tree_hash: workspace.base_tree_hash,
                    tree_hash: workspace.tree_hash,
                    semantic_overlay_hash: workspace.semantic_overlay_hash,
                    admission_policy: workspace.admission_policy,
                },
                new_generation: workspace.generation + 1,
                new_head: WorkspaceHead::Detached {
                    target: base.clone(),
                },
                new_base_target: Some(base),
                new_base_tree_hash: workspace.base_tree_hash,
                tree_deltas: Vec::new(),
                new_tree_hash: workspace.tree_hash,
                semantic_delta: WorkspaceSemanticDelta::default(),
                new_shared_admission_policy: shared.clone(),
                new_admission_policy: EffectiveAdmissionPolicyStamp {
                    shared: shared.stamp(),
                    local: workspace.admission_policy.local,
                },
            }),
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
            collaboration_delta: None,
        };
        authority
            .commit_repository_transaction(transaction)
            .expect("parking a workspace on its own base is a legal workspace mutation")
    }

    /// The state both arms below start from: one committed change on
    /// `refs/heads/main`, with a second artifact staged for the commit under
    /// test.
    fn repository_with_one_change() -> (
        tempfile::TempDir,
        kin_core::InitResult,
        kin_blobs::BlobStore,
        kin_db::InMemoryGraph,
        SemanticChangeId,
    ) {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        add_artifact(&graph, &blobs, b"first.txt", b"one\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("author"),
            "first change".to_string(),
        )
        .unwrap();
        let first_change = commit_native_plan_with_projection(&init.layout, &blobs, plan)
            .unwrap()
            .change
            .id;
        (root, init, blobs, graph, first_change)
    }

    fn plan_amend_for_test(
        init: &kin_core::InitResult,
        blobs: &kin_blobs::BlobStore,
        graph: &kin_db::InMemoryGraph,
        expected_head: SemanticChangeId,
        message: Option<&str>,
    ) -> Result<NativeCommitPlan> {
        super::plan_native_amend(
            graph,
            blobs,
            &test_authority_context(&init.layout),
            OperationId::new(),
            Timestamp::now(),
            AuthorId::new("amending actor"),
            &NativeAmend {
                expected_head,
                message: message.map(str::to_owned),
            },
        )
    }

    #[test]
    fn amend_root_preserves_authorship_and_pending_tree_after_reopen() {
        let (_root, init, blobs, graph, first) = repository_with_one_change();
        let original = reopen(&init).read_authority().snapshot().changes[&first].clone();
        add_artifact(&graph, &blobs, b"pending.bin", &[0, 255, 4], |hash| {
            TreeEntry::blob(hash, true)
        });
        let plan = plan_amend_for_test(&init, &blobs, &graph, first, None).unwrap();
        assert!(
            plan.change.parents.is_empty(),
            "amending a root must not make its old head a parent"
        );
        assert_eq!(plan.change.author, original.author);
        assert_eq!(plan.change.message, original.message);
        assert_eq!(plan.transaction.actor, AuthorId::new("amending actor"));
        assert_eq!(
            plan.transaction.ref_mutations[0].policy,
            RefUpdatePolicy::ForceWithLease
        );
        assert_eq!(
            plan.transaction.ref_mutations[0].expected,
            RefExpectation::MustEqual {
                target: RefTarget::change(first)
            }
        );
        let result = commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();
        assert_ne!(result.change.id, first);
        let recovered = super::recover_native_commit(
            &test_authority_context(&init.layout),
            result.receipt.operation_id,
        )
        .unwrap()
        .expect("amend receipt must be recoverable");
        assert_eq!(recovered.change.id, result.change.id);
        assert_eq!(recovered.target, result.target);
        assert_eq!(
            std::fs::read(init.layout.working_dir().join("pending.bin")).unwrap(),
            [0, 255, 4]
        );
        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(
            lease.snapshot().changes[&first],
            original,
            "amend must retain the old immutable change"
        );
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        assert_eq!(
            workspace.base_target,
            Some(RefTarget::change(result.change.id))
        );
        assert!(!workspace.is_dirty(), "the full working state was included");
        let materialized = lease
            .workspace_graph_snapshot(&init.workspace_id)
            .unwrap()
            .unwrap();
        assert_eq!(materialized.resolved_tree, graph.resolved_tree());
    }

    #[test]
    fn amend_preserves_every_merge_parent_and_can_replace_message() {
        let (_root, init, blobs, graph, first) = repository_with_one_change();
        let second_plan = plan_next_commit(&init, &blobs, &graph, b"second.txt").unwrap();
        let second = commit_native_plan_with_projection(&init.layout, &blobs, second_plan)
            .unwrap()
            .change
            .id;
        let mut merge = plan_next_commit(&init, &blobs, &graph, b"third.txt").unwrap();
        merge.change.parents = vec![second, first];
        merge.change.id = compute_semantic_change_id(&merge.change).unwrap();
        merge.transaction.changes = vec![merge.change.clone()];
        merge.transaction.ref_mutations[0].new_target = Some(RefTarget::change(merge.change.id));
        merge
            .transaction
            .workspace_mutation
            .as_mut()
            .unwrap()
            .new_base_target = Some(RefTarget::change(merge.change.id));
        let merged = commit_native_plan_with_projection(&init.layout, &blobs, merge)
            .unwrap()
            .change;
        let plan = plan_amend_for_test(&init, &blobs, &graph, merged.id, Some("corrected message"))
            .unwrap();
        assert_eq!(plan.change.parents, vec![second, first]);
        assert_eq!(plan.change.message, "corrected message");
        let amended = commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();
        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(lease.snapshot().changes[&merged.id], merged);
        let mut snapshot = lease.snapshot().clone();
        snapshot.repository_authority = None;
        let history = kin_db::InMemoryGraph::from_snapshot(snapshot).unwrap();
        use kin_model::ChangeStore as _;
        assert_eq!(
            history.resolve_graph_at(&amended.change.id).unwrap().tree,
            graph.resolved_tree()
        );
    }

    #[test]
    fn amend_detached_head_moves_only_its_workspace() {
        let (_root, init, blobs, graph, first) = repository_with_one_change();
        detach_workspace_head(&init.layout);
        let plan =
            plan_amend_for_test(&init, &blobs, &graph, first, Some("detached correction")).unwrap();
        assert!(plan.transaction.ref_mutations.is_empty());
        assert!(plan.change.parents.is_empty());
        let amended = commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();
        let workspace = workspace_state(&init);
        assert_eq!(
            workspace.head,
            WorkspaceHead::Detached {
                target: RefTarget::change(amended.change.id)
            }
        );
        assert_eq!(
            reopen(&init)
                .get_repository_ref(&init.repository_id, &RefName::branch(b"main").unwrap())
                .unwrap()
                .unwrap()
                .target,
            RefTarget::change(first)
        );
    }

    #[test]
    fn amend_refuses_unborn_stale_selection_and_stale_publication() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let unknown = SemanticChangeId::from_hash(Hash256::from_bytes([42; 32]));
        let error = plan_amend_for_test(&init, &blobs, &graph, unknown, None)
            .err()
            .expect("unborn amend must fail");
        assert!(error.to_string().contains("unborn"), "{error}");
        let (_root, init, blobs, graph, first) = repository_with_one_change();
        let stale =
            plan_amend_for_test(&init, &blobs, &graph, first, Some("stale correction")).unwrap();
        let winner = plan_next_commit(&init, &blobs, &graph, b"winner.txt").unwrap();
        let winner = commit_native_plan_with_projection(&init.layout, &blobs, winner)
            .unwrap()
            .change
            .id;
        let error = plan_amend_for_test(&init, &blobs, &graph, first, None)
            .err()
            .expect("stale amend must fail");
        assert!(error.to_string().contains("HEAD is now"), "{error}");
        let error = super::validate_native_amend_head(&test_authority_context(&init.layout), first)
            .unwrap_err();
        assert!(error.to_string().contains("HEAD is now"), "{error}");
        let before = reopen(&init).read_authority().roots().clone();
        let error = commit_native_plan(&init.layout, &blobs, stale).unwrap_err();
        assert!(error.to_string().contains("generation mismatch"), "{error}");
        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(*lease.roots(), before);
        assert_eq!(lease.snapshot().changes.len(), 2);
        assert_eq!(
            workspace_state(&init).base_target,
            Some(RefTarget::change(winner))
        );
    }

    /// Stage a second artifact and plan the commit under test.
    /// The path is a parameter because a test that commits twice must add two
    /// different files. Adding the same path twice does not fail at the add; it
    /// fails much later, inside the transaction, with `repository path
    /// second.txt remains occupied after applying the transaction`, which reads
    /// like a product defect rather than a fixture that asked for the impossible.
    fn plan_next_commit(
        init: &kin_core::InitResult,
        blobs: &kin_blobs::BlobStore,
        graph: &kin_db::InMemoryGraph,
        path: &[u8],
    ) -> Result<NativeCommitPlan> {
        add_artifact(graph, blobs, path, b"more\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        plan_native_commit(
            &init.layout,
            graph,
            blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("author"),
            "second change".to_string(),
        )
    }

    fn workspace_state(init: &kin_core::InitResult) -> kin_model::WorkspaceState {
        let authority = reopen(init);
        let lease = authority.read_authority();
        let state = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap()
            .clone();
        state
    }

    /// The control. A workspace whose head names a branch keeps naming it, and
    /// the branch is what moves.
    ///
    /// It is written beside the detached arm on purpose: the two differ in
    /// exactly the three facts asserted here, and a change that moved a branch
    /// commit onto the detached path would pass every assertion in the arm
    /// below while failing this one.
    #[test]
    fn a_commit_on_a_branch_moves_the_branch_and_leaves_the_head_naming_it() {
        let (_root, init, blobs, graph, first_change) = repository_with_one_change();
        let plan = plan_next_commit(&init, &blobs, &graph, b"second.txt").unwrap();
        assert_eq!(
            plan.target,
            NativeCommitTarget::Branch(
                kin_model::RefName::from_bytes(b"refs/heads/main".to_vec()).unwrap()
            ),
            "a workspace head naming a branch publishes onto that branch"
        );
        assert_eq!(
            plan.transaction.ref_mutations.len(),
            1,
            "a branch commit fast-forwards exactly one ref"
        );
        let result = commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();
        let workspace = workspace_state(&init);
        assert_eq!(
            workspace.head,
            WorkspaceHead::Symbolic {
                target: kin_model::RefName::from_bytes(b"refs/heads/main".to_vec()).unwrap()
            },
            "the head goes on naming its branch"
        );
        assert_eq!(
            reopen(&init)
                .get_repository_ref(
                    &init.repository_id,
                    &kin_model::RefName::from_bytes(b"refs/heads/main".to_vec()).unwrap()
                )
                .unwrap()
                .unwrap()
                .target,
            RefTarget::change(result.change.id),
            "the branch advanced to the new change"
        );
        assert_eq!(result.change.parents, vec![first_change]);
    }

    /// FIR-3012. A workspace parked on its own base commits, advancing that
    /// head to the change it just made and moving no branch.
    ///
    /// This is the everyday state after `git clone` then `git checkout <tag>`
    /// then `kin init`, which used to refuse every commit forever with
    /// `native repository commit requires a symbolic workspace HEAD`, after
    /// paying the whole planning cost first.
    #[test]
    fn a_detached_workspace_head_advances_to_the_change_it_commits() {
        let (_root, init, blobs, graph, first_change) = repository_with_one_change();
        let _ = detach_workspace_head(&init.layout);
        let before = workspace_state(&init);
        assert_eq!(
            before.head,
            WorkspaceHead::Detached {
                target: RefTarget::change(first_change)
            },
            "the fixture must actually be detached, or this test asserts about nothing"
        );

        let plan = plan_next_commit(&init, &blobs, &graph, b"second.txt").unwrap();
        assert_eq!(
            plan.target,
            NativeCommitTarget::DetachedHead,
            "a detached workspace publishes onto its own head"
        );
        assert!(
            plan.transaction.ref_mutations.is_empty(),
            "a detached commit invents no ref on the author's behalf"
        );
        let result = commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();

        assert_eq!(
            result.change.parents,
            vec![first_change],
            "the detached commit descends from the change the head stood on"
        );
        let workspace = workspace_state(&init);
        assert_eq!(
            workspace.head,
            WorkspaceHead::Detached {
                target: RefTarget::change(result.change.id)
            },
            "the detached head advanced to the change it just made"
        );
        assert_eq!(
            workspace.base_target,
            Some(RefTarget::change(result.change.id)),
            "the base advanced with the head, which is the invariant validate_head_base binds"
        );
        assert_eq!(
            reopen(&init)
                .get_repository_ref(
                    &init.repository_id,
                    &kin_model::RefName::from_bytes(b"refs/heads/main".to_vec()).unwrap()
                )
                .unwrap()
                .unwrap()
                .target,
            RefTarget::change(first_change),
            "no branch moved, so the branch the fixture left behind is where it was"
        );

        // The join with kin-cli. `landed_change_in` there reads exactly these
        // two fields off the operation record to answer "did my commit land",
        // and it can only be right if this is the shape a detached commit
        // writes. Asserting it here means neither side is trusting a string the
        // other side also wrote down.
        assert!(
            result.receipt.operation.ref_mutations.is_empty(),
            "the record a recovery reads carries no ref mutation"
        );
        assert_eq!(
            result
                .receipt
                .operation
                .workspace_mutation
                .as_ref()
                .map(|workspace| workspace.new_head.clone()),
            Some(WorkspaceHead::Detached {
                target: RefTarget::change(result.change.id)
            }),
            "the record names the change on the head the workspace mutation advanced"
        );
    }

    /// FIR-3038. `kin_core::published_change` reads a REAL receipt of every
    /// shape a commit writes, and refuses one that only looks like a commit.
    ///
    /// Both recovery paths, the daemon's here and the CLI's in `kin-cli`, call
    /// that one function to answer "did my commit land" after a caller lost the
    /// reply. Before this it was written twice, and both copies were tested
    /// against inputs their own authors wrote down, so nothing proved either
    /// answered correctly for a record a real commit produced. This drives it
    /// from the durable receipts three real transactions leave behind.
    ///
    /// The third arm is the one that decides the test. A workspace parked on its
    /// own base publishes nothing, and its record carries a head moved onto a
    /// change, which is byte-identical in shape to what a detached commit
    /// writes. A reader that keyed on the shapes alone would report that park as
    /// a landed commit, and a suite whose absent arm used something obviously
    /// different would never see it.
    #[test]
    fn a_receipt_names_the_change_its_operation_published_and_nothing_else() {
        let (_root, init, blobs, graph, first_change) = repository_with_one_change();

        // Arm one, a real commit on a branch.
        let plan = plan_next_commit(&init, &blobs, &graph, b"second.txt").unwrap();
        let on_branch = commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();
        let branch_published = kin_core::published_change(&on_branch.receipt.operation)
            .expect("a branch commit published a change");
        assert_eq!(
            branch_published.change_id, on_branch.change.id,
            "the receipt names the change this commit actually made"
        );
        assert_eq!(
            branch_published.branch,
            Some(kin_model::RefName::from_bytes(b"refs/heads/main".to_vec()).unwrap()),
            "and the branch it moved"
        );

        // Arm three, the park. Taken before the detached commit so its receipt
        // is graded on its own, and it is where the head-onto-a-change shape
        // appears without a change behind it.
        let parked = detach_workspace_head(&init.layout);
        assert!(
            matches!(
                parked
                    .operation
                    .workspace_mutation
                    .as_ref()
                    .map(|workspace| &workspace.new_head),
                Some(WorkspaceHead::Detached {
                    target: RefTarget::Change { .. }
                })
            ),
            "the park must write the same head shape a detached commit does, or this arm \
             grades nothing"
        );
        assert_eq!(
            kin_core::published_change(&parked.operation),
            None,
            "a workspace parked on its own base published no change, whatever its head looks like"
        );
        assert_eq!(
            parked.operation.roots_before.history, parked.operation.roots_after.history,
            "and the reason is readable in the record: it left change history standing"
        );

        // Arm two, a real commit on that detached head. A different path,
        // because the branch arm above already published second.txt.
        let plan = plan_next_commit(&init, &blobs, &graph, b"third.txt");
        let detached = match plan {
            Ok(plan) => commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap(),
            Err(error) => panic!("a detached workspace must commit: {error}"),
        };
        let detached_published = kin_core::published_change(&detached.receipt.operation)
            .expect("a detached commit published a change");
        assert_eq!(
            detached_published.change_id, detached.change.id,
            "the receipt names the change the detached commit made"
        );
        assert_eq!(
            detached_published.branch, None,
            "and says no branch names it"
        );
        assert_ne!(
            detached.receipt.operation.roots_before.history,
            detached.receipt.operation.roots_after.history,
            "a published change moves change history, which is what separates it from the park"
        );

        // The three answers are distinct, so no arm is satisfied by another's.
        assert_ne!(branch_published.change_id, detached_published.change_id);
        assert_ne!(branch_published.change_id, first_change);
    }

    /// A detached commit is recoverable by the operation id that made it.
    ///
    /// The recovery path used to read only ref mutations, so a detached commit,
    /// which has none, would have read as an operation that never landed. That
    /// is the worst possible answer here: the caller reaching this code has
    /// already lost the reply and is deciding whether to commit again.
    #[test]
    fn a_detached_commit_is_recovered_by_its_operation_id() {
        let (_root, init, blobs, graph, _first_change) = repository_with_one_change();
        let _ = detach_workspace_head(&init.layout);
        add_artifact(&graph, &blobs, b"second.txt", b"two\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let operation_id = OperationId::new();
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            operation_id,
            fixed_timestamp(),
            AuthorId::new("author"),
            "second change".to_string(),
        )
        .unwrap();
        let committed = commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();

        let recovered =
            super::recover_native_commit(&test_authority_context(&init.layout), operation_id)
                .unwrap()
                .expect("a landed detached commit is recoverable by its operation id");
        assert_eq!(recovered.change.id, committed.change.id);
        assert_eq!(recovered.target, NativeCommitTarget::DetachedHead);
    }

    #[test]
    fn stale_plan_cannot_split_change_workspace_and_ref_authority() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        add_artifact(&graph, &blobs, b"compose.yaml", b"services: {}\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let winner = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("winner"),
            "winner".to_string(),
        )
        .unwrap();
        let winner_id = winner.change.id;
        let stale = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("stale"),
            "stale".to_string(),
        )
        .unwrap();
        commit_native_plan(&init.layout, &blobs, winner).unwrap();
        // The refusal comes from the durable compare-and-swap. A plan carries
        // the authority it planned against, so publishing a stale plan no
        // longer re-reads authority first and cannot notice the move before
        // preparing its successor; kin-db refuses the write itself because the
        // persisted base generation is not the one the successor was built on.
        // The refusal is what matters and it is unconditional: the successor
        // exists only in memory, and nothing durable moved, which the state
        // assertions below check rather than assume.
        let error = commit_native_plan(&init.layout, &blobs, stale).unwrap_err();
        let refusal = error.to_string();
        assert!(
            refusal.contains("generation mismatch") && refusal.contains("another writer committed"),
            "a stale plan must be refused naming the generation conflict, got: {refusal}"
        );

        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(lease.roots().generation, 2);
        let default_ref = lease.metadata().ref_state.default_ref.as_ref().unwrap();
        assert_eq!(
            authority
                .get_repository_ref(&init.repository_id, default_ref)
                .unwrap()
                .unwrap()
                .target,
            RefTarget::change(winner_id)
        );
        assert_eq!(lease.snapshot().changes.len(), 1);
    }

    /// An exclusion rule takes effect from the generation AFTER the one that
    /// publishes it, so the transaction introducing a rule is judged by the
    /// policy already in force rather than by the one it is about to install.
    /// The contract is stated on kin-db's `judging_shared_policy`; this is its
    /// kin-side half, and it is deliberately the inverse of what this test
    /// asserted before kin-db 0.7.30. Judging a transaction by its own new rule
    /// livelocked: the rule file could never land, because landing it required
    /// admitting content the unlanded rule already excluded, and every retry
    /// failed identically.
    #[test]
    fn a_rule_and_the_content_it_will_exclude_land_together_then_the_rule_bites() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        add_artifact(&graph, &blobs, b".gitignore", b"*.secret\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        add_artifact(&graph, &blobs, b"one.secret", b"not admitted\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("dogfood"),
            "publish the rule beside the content it will exclude".to_string(),
        )
        .unwrap();
        commit_native_plan(&init.layout, &blobs, plan).unwrap();

        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(lease.roots().generation, 2);
        assert_eq!(lease.snapshot().changes.len(), 1);
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        assert_eq!(workspace.tree.len(), 2);
        drop(lease);
        drop(authority);

        // The rule is in force from here, so the next new path under it is
        // refused, and refused without moving authority.
        add_artifact(&graph, &blobs, b"two.secret", b"also secret\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("dogfood"),
            "must fail admission under the rule now in force".to_string(),
        )
        .unwrap();
        let error = commit_native_plan(&init.layout, &blobs, plan).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("excluded by the exact graph-owned admission policy"),
            "unexpected error: {error}"
        );

        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(lease.roots().generation, 2);
        assert_eq!(lease.snapshot().changes.len(), 1);
    }

    #[test]
    fn missing_graph_blob_fails_before_repository_authority_moves() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let artifact = ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("compose.yaml").unwrap(),
            TreeEntry::blob(Hash256::from_bytes([0xee; 32]), false),
        );
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: artifact.artifact_id,
                    new: LocatedEntry::new(artifact.path, artifact.entry),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("dogfood"),
            "missing body".to_string(),
        )
        .unwrap();
        let error = commit_native_plan(&init.layout, &blobs, plan).unwrap_err();
        assert!(
            matches!(
                &error,
                DaemonError::Blob(kin_blobs::BlobError::NotFound { .. })
            ),
            "missing graph body must surface the typed blob absence, got {error:?}"
        );
        assert_eq!(reopen(&init).read_authority().roots().generation, 1);
    }

    /// A body the credential scanner blocks.
    ///
    /// Every test using it proves that claim on its own refusal arm rather than
    /// assuming it. A fixture whose secret the scanner never flagged would let
    /// the approval arm pass with the derivation site reverted and approvals
    /// ignored, which is the shape of a check that cannot fail.
    const BLOCKED_SECRET: &[u8] = b"API_TOKEN = \"sk-proj-abcd1234efgh5678ijkl\"\n";

    /// The path the scanner names when it refuses [`BLOCKED_SECRET`].
    const BLOCKED_PATH: &[u8] = b"notekeeper/client.py";

    /// The bytes of a tracked approval set, in the format kin-model parses.
    ///
    /// Written out here rather than produced by the writer that ships in the
    /// CLI, because a fixture generating the file with the code under test
    /// could agree with itself while both drifted from the format the published
    /// kin-model actually reads.
    fn approval_file(path: &str, digest: Hash256, approver: &str) -> Vec<u8> {
        format!(
            "# approvals for this fixture\n\
             kin-allowances 1\n\
             {path}\t{digest}\tblob\t{approver}\tpinned by the test covering this derivation site\n"
        )
        .into_bytes()
    }

    fn blob_hash(artifact: &ResolvedArtifact) -> Hash256 {
        match artifact.entry {
            TreeEntry::Blob { hash, .. } => hash,
            other => panic!("fixture artifact must be a blob, found {other:?}"),
        }
    }

    /// The approvals a planned transition carries into authority.
    fn planned_approvals(
        transaction: &RepositoryTransaction,
    ) -> Vec<kin_model::SensitiveArtifactAllowance> {
        transaction
            .workspace_mutation
            .as_ref()
            .expect("a workspace transition carries a workspace mutation")
            .new_shared_admission_policy
            .sensitive_allowances
            .clone()
    }

    /// The graph-owned policy a native commit derives has to be derived through
    /// the entry point that reads a tracked `.kin-allowances`, or an approval a
    /// reviewer can see in the diff never reaches admission.
    ///
    /// Reverting `plan_native_commit_inner`'s derivation to `derive_from_tree`
    /// fails the approved arm below, because the compatibility entry point
    /// refuses by name the moment the tree carries approvals it cannot read.
    /// The refused arm is what makes that meaningful: it proves this fixture's
    /// body really is blocked, so the approved arm is passing because the
    /// approval was read rather than because nothing was ever in the way.
    #[test]
    fn a_native_commit_derives_the_approvals_its_tree_carries() {
        let refused = tempfile::tempdir().unwrap();
        let init = kin_core::init(refused.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        add_artifact(&graph, &blobs, BLOCKED_PATH, BLOCKED_SECRET, |hash| {
            TreeEntry::blob(hash, false)
        });
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("credscan"),
            "publish a secret with no approval".to_string(),
        )
        .unwrap();
        let error = commit_native_plan(&init.layout, &blobs, plan).unwrap_err();
        assert!(
            error.to_string().contains("notekeeper/client.py"),
            "this fixture's body must be one the scanner actually blocks, or the approved \
             arm below proves nothing: {error}"
        );

        let approved = tempfile::tempdir().unwrap();
        let init = kin_core::init(approved.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let secret = add_artifact(&graph, &blobs, BLOCKED_PATH, BLOCKED_SECRET, |hash| {
            TreeEntry::blob(hash, false)
        });
        let approvals = approval_file(
            "notekeeper/client.py",
            blob_hash(&secret),
            "credscan@firelock.ai",
        );
        add_artifact(&graph, &blobs, b".kin-allowances", &approvals, |hash| {
            TreeEntry::blob(hash, false)
        });

        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("credscan"),
            "publish the secret beside the approval that clears it".to_string(),
        )
        .unwrap_or_else(|error| {
            panic!(
                "planning a native commit whose tree carries .kin-allowances must derive its \
                 approvals rather than refusing: {error}"
            )
        });
        let approvals = planned_approvals(&plan.transaction);
        assert_eq!(
            approvals.len(),
            1,
            "the planned policy must carry the one approval the tree declares: {approvals:?}"
        );
        assert_eq!(approvals[0].path.as_utf8().unwrap(), "notekeeper/client.py");
        assert_eq!(approvals[0].content_hash, blob_hash(&secret));

        commit_native_plan(&init.layout, &blobs, plan).unwrap_or_else(|error| {
            panic!("the approved secret must publish rather than being refused: {error}")
        });

        let authority = reopen(&init);
        let lease = authority.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        assert_eq!(
            workspace.shared_admission_policy.sensitive_allowances.len(),
            1,
            "the approval has to reach durable authority, not just the plan"
        );
    }

    /// The same property for the workspace-admission derivation, which is the
    /// site a dirty working tree reaches rather than a commit.
    ///
    /// Reverting `publish_workspace_tree`'s derivation fails the approved arm
    /// here and leaves the commit test above untouched, which is what makes
    /// these two separate tests rather than one.
    #[test]
    fn admitting_a_workspace_tree_derives_the_approvals_it_carries() {
        let refused = tempfile::tempdir().unwrap();
        let init = kin_core::init(refused.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let secret = add_artifact(&graph, &blobs, BLOCKED_PATH, BLOCKED_SECRET, |hash| {
            TreeEntry::blob(hash, false)
        });
        let error = publish_workspace_tree(
            &init.layout,
            &blobs,
            &ResolvedTree::from_artifacts([secret.clone()]).unwrap(),
            OperationId::new(),
            AuthorId::new("credscan"),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("notekeeper/client.py"),
            "this fixture's body must be one the scanner actually blocks, or the approved \
             arm below proves nothing: {error}"
        );

        let approved = tempfile::tempdir().unwrap();
        let init = kin_core::init(approved.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let secret = add_artifact(&graph, &blobs, BLOCKED_PATH, BLOCKED_SECRET, |hash| {
            TreeEntry::blob(hash, false)
        });
        let approvals = approval_file(
            "notekeeper/client.py",
            blob_hash(&secret),
            "credscan@firelock.ai",
        );
        let allowance = add_artifact(&graph, &blobs, b".kin-allowances", &approvals, |hash| {
            TreeEntry::blob(hash, false)
        });

        publish_workspace_tree(
            &init.layout,
            &blobs,
            &ResolvedTree::from_artifacts([secret.clone(), allowance]).unwrap(),
            OperationId::new(),
            AuthorId::new("credscan"),
        )
        .unwrap_or_else(|error| {
            panic!(
                "admitting a workspace tree carrying .kin-allowances must derive its approvals \
                 rather than refusing: {error}"
            )
        })
        .expect("the transition must advance authority");

        let authority = reopen(&init);
        let lease = authority.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        let carried = &workspace.shared_admission_policy.sensitive_allowances;
        assert_eq!(
            carried.len(),
            1,
            "the admitted workspace policy must carry the tree's one approval: {carried:?}"
        );
        assert_eq!(carried[0].content_hash, blob_hash(&secret));
    }

    /// Source a parse can place, and the same file with an import prepended so
    /// every span after it moves.
    const SESSIONS_BEFORE: &[u8] = b"def alpha():\n    return 1\n\n\ndef beta():\n    return 2\n";
    const SESSIONS_AFTER: &[u8] =
        b"import os\n\n\ndef alpha():\n    return 1\n\n\ndef beta():\n    return 2\n";
    /// The same file with one literal swapped for another of the same width, so
    /// every entity keeps exactly the bytes it held and only the token stream
    /// under it moves.
    const SESSIONS_SAME_LENGTH: &[u8] =
        b"def alpha():\n    return 9\n\n\ndef beta():\n    return 2\n";
    /// The same file with a declaration appended, so every entity the graph
    /// holds survives byte-identical and the parse produces one it does not.
    const SESSIONS_APPENDED: &[u8] = b"def alpha():\n    return 1\n\n\ndef beta():\n                                           return 2\n\n\ndef gamma():\n    return 3\n";

    /// Put the entities a parse of `bytes` produces into the graph, the way the
    /// reconcile that follows an admission does.
    fn derive_entities_into_graph(
        graph: &kin_db::InMemoryGraph,
        blobs: &kin_blobs::BlobStore,
        path: &str,
        bytes: &[u8],
    ) -> Vec<kin_model::Entity> {
        let file_id = kin_model::FilePathId::new(path);
        let digest = blobs.write(bytes).unwrap();
        let entities = kin_index::IndexPipeline::new()
            .index_file_content_with_tests(&file_id, bytes, digest)
            .unwrap()
            .indexed_file
            .entities;
        assert!(
            !entities.is_empty(),
            "the fixture must parse to at least one entity, or nothing below can go stale"
        );
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: entities
                    .iter()
                    .cloned()
                    .map(|new| kin_model::EntityDelta::Added { new })
                    .collect(),
                ..TransactionDelta::default()
            })
            .unwrap();
        entities
    }

    /// Move one artifact's bytes in the tree and touch nothing else, which is
    /// what an exact-tree admission whose enrichment half never ran leaves
    /// behind.
    fn update_artifact_bytes(
        graph: &kin_db::InMemoryGraph,
        blobs: &kin_blobs::BlobStore,
        artifact: &ResolvedArtifact,
        bytes: &[u8],
    ) -> ResolvedArtifact {
        let digest = blobs.write(bytes).unwrap();
        let entry = TreeEntry::blob(Hash256::from_bytes(digest.0), false);
        graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id: artifact.artifact_id,
                    old: LocatedEntry::new(artifact.path.clone(), artifact.entry),
                    new: LocatedEntry::new(artifact.path.clone(), entry),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        ResolvedArtifact::new(artifact.artifact_id, artifact.path.clone(), entry)
    }

    /// Retire the entities one parse produced and install the ones the current
    /// bytes produce, which is what the reconcile lands when it finally runs.
    fn replace_entities_in_graph(
        graph: &kin_db::InMemoryGraph,
        blobs: &kin_blobs::BlobStore,
        path: &str,
        held: &[kin_model::Entity],
        bytes: &[u8],
    ) {
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: held
                    .iter()
                    .cloned()
                    .map(|old| kin_model::EntityDelta::Removed { old })
                    .collect(),
                ..TransactionDelta::default()
            })
            .unwrap();
        derive_entities_into_graph(graph, blobs, path, bytes);
    }

    /// Publish one file, then move its bytes in the tree without re-deriving its
    /// semantics, and ask for a commit.
    fn commit_then_move_bytes_without_reparsing(
        init: &kin_core::InitResult,
        graph: &kin_db::InMemoryGraph,
        blobs: &kin_blobs::BlobStore,
        after: &[u8],
    ) -> Vec<kin_model::Entity> {
        commit_then_move_bytes_without_reparsing_at(init, graph, blobs, "sessions.py", after)
    }

    /// The same fixture at a path the caller names, so a test tree can be
    /// exercised beside a production one.
    fn commit_then_move_bytes_without_reparsing_at(
        init: &kin_core::InitResult,
        graph: &kin_db::InMemoryGraph,
        blobs: &kin_blobs::BlobStore,
        path: &str,
        after: &[u8],
    ) -> Vec<kin_model::Entity> {
        let artifact = add_artifact(graph, blobs, path.as_bytes(), SESSIONS_BEFORE, |hash| {
            TreeEntry::blob(hash, false)
        });
        let held = derive_entities_into_graph(graph, blobs, path, SESSIONS_BEFORE);
        let plan = plan_native_commit(
            &init.layout,
            graph,
            blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("commitrace"),
            "publish the pre-edit file".to_string(),
        )
        .expect("the pre-edit commit plans, so the barrier below is not refusing everything");
        commit_native_plan_with_projection(&init.layout, blobs, plan).unwrap();
        update_artifact_bytes(graph, blobs, &artifact, after);
        held
    }

    /// A commit must not seal a tree delta over a path whose graph entities a
    /// parse of the bytes it is sealing does not reproduce.
    ///
    /// This is the FIR-3201 restart window seen from the commit side. An exact
    /// tree reaches authority, the enrichment half that would re-derive its
    /// entities does not run or does not survive, and the planner reads the tree
    /// half and the entity half out of one graph that no longer agrees with
    /// itself. The change it seals then records the new bytes against spans
    /// derived from the old ones, and reports the entity delta as empty because
    /// the graph's entities still equal the parent change's.
    ///
    /// Falsify by removing the barrier from `plan_native_commit_inner`: the plan
    /// comes back `Ok` and this assertion fails.
    #[test]
    fn a_commit_refuses_a_path_whose_semantics_the_sealed_bytes_do_not_reproduce() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        commit_then_move_bytes_without_reparsing(&init, &graph, &blobs, SESSIONS_AFTER);

        let refusal = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("commitrace"),
            "publish the edit".to_string(),
        );
        let Some(error) = refusal.err() else {
            panic!(
                "the commit sealed a tree delta for sessions.py against entities derived from the \
                 pre-edit bytes; the change records the new bytes and reports no entity delta at \
                 all, which is the psf/requests entities=0 result"
            );
        };
        let message = error.to_string();
        assert!(
            message.contains("sessions.py"),
            "the refusal has to name the path whose reconcile has not landed, or a caller cannot \
             act on it: {message}"
        );
    }

    /// A path this change ADDS whose semantics never landed is caught too.
    ///
    /// "No earlier parse to be stale against" is not the same as "a complete
    /// current parse". A source file admitted into the tree whose enrichment was
    /// lost carries no entities at all, and a change that seals its bytes leaves
    /// every declaration in it unanswerable, which is the FIR-2606 shape rather
    /// than the FIR-3201 one. The comparison already says so; the question is
    /// only whether the check looks at added paths.
    ///
    /// Falsify by scoping the check to `TreeDelta::Updated` alone: the plan comes
    /// back `Ok` and this assertion fails.
    #[test]
    fn a_commit_refuses_a_new_source_path_the_graph_holds_no_semantics_for() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        // One published file, so the change under test has a parent and is not
        // the root change whose delta is the whole tree.
        add_artifact(&graph, &blobs, b"sessions.py", SESSIONS_BEFORE, |hash| {
            TreeEntry::blob(hash, false)
        });
        derive_entities_into_graph(&graph, &blobs, "sessions.py", SESSIONS_BEFORE);
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("commitrace"),
            "publish the first file".to_string(),
        )
        .expect("the root commit plans, so the refusal below is about the added path");
        commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();

        // A second source file reaches the tree and nothing parses it.
        add_artifact(&graph, &blobs, b"helpers.py", SESSIONS_BEFORE, |hash| {
            TreeEntry::blob(hash, false)
        });

        let refusal = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("commitrace"),
            "publish the new file".to_string(),
        );
        let Some(error) = refusal.err() else {
            panic!(
                "the commit sealed a new source file the graph holds no entity for, so every \
                 declaration in it answers as though it is not there"
            );
        };
        assert!(
            error.to_string().contains("helpers.py"),
            "the refusal has to name the path: {error}"
        );
    }

    /// A declaration the graph is missing does not follow the bytes.
    ///
    /// The direction claim, tested where it can be stated exactly rather than
    /// through a fixture. Every entity the graph holds is reproduced by the
    /// parse, so a scan from held into fresh finds all of them and reports
    /// nothing, while the parse produces one the graph does not hold and the
    /// change is about to seal bytes for it.
    ///
    /// Falsify by comparing one direction only, the held keys against the fresh
    /// ones: the second assertion fails.
    #[test]
    fn a_declaration_the_graph_is_missing_does_not_follow_the_bytes() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let file_id = kin_model::FilePathId::new("sessions.py");
        let digest = blobs.write(SESSIONS_BEFORE).unwrap();
        let parsed = kin_index::IndexPipeline::new()
            .index_file_content_with_tests(&file_id, SESSIONS_BEFORE, digest)
            .unwrap()
            .indexed_file
            .entities;
        assert!(
            parsed.len() >= 2,
            "the fixture must parse to at least two entities, or one cannot go missing: {parsed:?}"
        );
        let held = &parsed[..parsed.len() - 1];

        assert!(
            super::semantics_follow_the_bytes(&parsed, &parsed),
            "one set has to agree with itself, or this test proves nothing"
        );
        assert!(
            !super::semantics_follow_the_bytes(held, &parsed),
            "a declaration the bytes produce and the graph does not hold has to be reported; a \
             scan from held into fresh finds every held key and says the graph is current"
        );
    }

    /// A same-length body edit is caught, which a comparison on spans cannot do.
    ///
    /// `return 1` becoming `return 9` leaves every entity at exactly the bytes it
    /// held, so kind, name and both span offsets match and the only field that
    /// moves is `behavior_hash`, the hash of the entity's own source text. The
    /// change would seal the new bytes against semantics that describe the old
    /// ones, and every span in it would be correct, which is what makes this
    /// shape the one a span check waves through.
    ///
    /// Falsify by dropping `behavior_hash` from `semantic_keys`: the plan comes
    /// back `Ok` and this assertion fails.
    #[test]
    fn a_commit_refuses_a_same_length_body_edit_its_semantics_did_not_follow() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        commit_then_move_bytes_without_reparsing(&init, &graph, &blobs, SESSIONS_SAME_LENGTH);

        let refusal = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("commitrace"),
            "publish the same-length edit".to_string(),
        );
        let Some(error) = refusal.err() else {
            panic!(
                "the commit sealed bytes whose entity bodies the graph does not hold; every span \
                 in the change is correct and every body under it describes the previous bytes"
            );
        };
        assert!(
            error.to_string().contains("sessions.py"),
            "the refusal has to name the path: {error}"
        );
    }

    /// A declaration the sealed bytes add and the graph does not hold is caught,
    /// which a one-way comparison cannot do.
    ///
    /// Appending `gamma` leaves `alpha` and `beta` byte-identical, so a scan from
    /// the graph's entities into a fresh parse finds every one of them and
    /// reports nothing, while the change seals bytes for a declaration no query
    /// can answer about.
    ///
    /// Falsify by removing the barrier: the plan comes back `Ok` and this
    /// assertion fails. The direction of the comparison has its own test below,
    /// because appending to this fixture moves the preceding declaration's own
    /// key too, so a one-way scan already reports it and this case cannot tell
    /// the two comparisons apart.
    #[test]
    fn a_commit_refuses_a_declaration_the_sealed_bytes_add_that_the_graph_lacks() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        commit_then_move_bytes_without_reparsing(&init, &graph, &blobs, SESSIONS_APPENDED);

        let refusal = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("commitrace"),
            "publish the appended declaration".to_string(),
        );
        let Some(error) = refusal.err() else {
            panic!(
                "the commit sealed bytes carrying a declaration the graph holds no entity for, so \
                 the file answers as though that declaration is not there"
            );
        };
        assert!(
            error.to_string().contains("sessions.py"),
            "the refusal has to name the path: {error}"
        );
    }

    /// The same commit plans once the re-derivation has landed.
    ///
    /// The positive control for the test above. Without it a barrier that
    /// refused every commit would pass, and the refusal has to clear itself the
    /// moment the graph agrees with its own tree.
    /// A path the repository classifies as TEST is checked like any other.
    ///
    /// `kin_index::classify_file_role` gives every entity parsed out of a test
    /// path the `Test` role, and a comparison that kept only `EntityRole::Source`
    /// compared an empty key set against an empty key set for all of them, so a
    /// test file passed the barrier whatever its bytes did. Those entities are
    /// the repository's own, derived by the same parse from the same tree-named
    /// body, and a test file sealed against semantics that describe older bytes
    /// answers questions about declarations that are not there exactly as a
    /// production file does.
    ///
    /// Falsify by restoring the `EntityRole::Source` filter in `semantic_keys`:
    /// the plan comes back `Ok` and this assertion fails.
    #[test]
    fn a_commit_refuses_a_test_path_whose_semantics_the_sealed_bytes_do_not_reproduce() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        let held = commit_then_move_bytes_without_reparsing_at(
            &init,
            &graph,
            &blobs,
            "tests/test_sessions.py",
            SESSIONS_SAME_LENGTH,
        );
        // The premise, asserted rather than assumed: this path really does parse
        // to Test-role entities, so the arm below exercises the roles the old
        // filter dropped rather than passing for the ordinary reason.
        assert!(
            !held.is_empty()
                && held
                    .iter()
                    .all(|entity| entity.role == kin_model::EntityRole::Test),
            "the fixture must parse to Test-role entities: {:?}",
            held.iter().map(|entity| entity.role).collect::<Vec<_>>()
        );

        let refusal = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("commitrace"),
            "publish the test file's edit".to_string(),
        );
        let Some(error) = refusal.err() else {
            panic!(
                "the commit sealed a test path's new bytes against entities derived from the old \
                 ones; every declaration in it now answers from spans and bodies that describe \
                 the previous version"
            );
        };
        assert!(
            error.to_string().contains("tests/test_sessions.py"),
            "the refusal has to name the path: {error}"
        );

        // The positive control on the same path: once the re-derivation lands,
        // the same commit plans, so the roles are not simply refused.
        replace_entities_in_graph(
            &graph,
            &blobs,
            "tests/test_sessions.py",
            &held,
            SESSIONS_SAME_LENGTH,
        );
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("commitrace"),
            "publish the test file's edit".to_string(),
        )
        .expect("the same commit plans once the test path's semantics have caught up");
        assert!(
            !plan.change.entity_deltas.is_empty(),
            "the re-derived commit has to carry the entity delta the refused one was missing"
        );
    }

    /// A test path this change ADDS with no semantics at all is caught too.
    ///
    /// The Source-only filter dropped the fresh Test entities as well as the held
    /// ones, so an added test file whose enrichment never landed compared empty
    /// against empty and was sealed with nothing answering for it.
    ///
    /// Falsify by restoring the `EntityRole::Source` filter in `semantic_keys`:
    /// the plan comes back `Ok` and this assertion fails.
    #[test]
    fn a_commit_refuses_a_new_test_path_the_graph_holds_no_semantics_for() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        // One published file, so the change under test has a parent and is not
        // the first admission, whose delta is the whole tree.
        add_artifact(&graph, &blobs, b"sessions.py", SESSIONS_BEFORE, |hash| {
            TreeEntry::blob(hash, false)
        });
        derive_entities_into_graph(&graph, &blobs, "sessions.py", SESSIONS_BEFORE);
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("commitrace"),
            "publish the first file".to_string(),
        )
        .expect("the first commit plans, so the refusal below is about the added path");
        commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();

        // The bytes reach the tree and the enrichment does not, which is the
        // state a lost derived-graph pass leaves behind.
        add_artifact(
            &graph,
            &blobs,
            b"tests/test_sessions.py",
            SESSIONS_BEFORE,
            |hash| TreeEntry::blob(hash, false),
        );

        let refusal = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("commitrace"),
            "publish the new test file".to_string(),
        );
        let Some(error) = refusal.err() else {
            panic!(
                "the commit sealed a new test file the graph holds no entity for, so every \
                 declaration in it answers as though it is not there"
            );
        };
        assert!(
            error.to_string().contains("tests/test_sessions.py"),
            "the refusal has to name the path: {error}"
        );
    }

    /// Amending the ROOT change is not a first admission.
    ///
    /// An amend keeps its target's parents, so amending the root produces a
    /// change with none while the repository has a head, a published tree and
    /// every chance to have gone stale since. A scope keyed on the change's own
    /// parentage read that as the import case and checked nothing, so this exact
    /// one-commit repository could seal the replacement root over stale spans.
    ///
    /// Falsify by restoring the `parent.is_some()` discriminator in
    /// `plan_native_commit_inner`: the plan comes back `Ok` and this assertion
    /// fails.
    #[test]
    fn an_amend_of_the_root_refuses_a_path_whose_semantics_the_sealed_bytes_do_not_reproduce() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        let artifact = add_artifact(&graph, &blobs, b"sessions.py", SESSIONS_BEFORE, |hash| {
            TreeEntry::blob(hash, false)
        });
        derive_entities_into_graph(&graph, &blobs, "sessions.py", SESSIONS_BEFORE);
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("commitrace"),
            "publish the root".to_string(),
        )
        .expect("the root commit plans, so the refusal below is about the amend");
        let root_change = commit_native_plan_with_projection(&init.layout, &blobs, plan)
            .unwrap()
            .change
            .id;

        // The same lost-enrichment window as the ordinary commit case: the bytes
        // move in the tree and no parse follows them.
        update_artifact_bytes(&graph, &blobs, &artifact, SESSIONS_AFTER);

        let refusal = plan_amend_for_test(&init, &blobs, &graph, root_change, None);
        let Some(error) = refusal.err() else {
            panic!(
                "the amend sealed the replacement root over entities derived from the pre-edit \
                 bytes, because its own parentage is empty by design and that was read as proof \
                 nothing had gone stale yet"
            );
        };
        assert!(
            error.to_string().contains("sessions.py"),
            "the refusal has to name the path: {error}"
        );
    }

    #[test]
    fn a_commit_plans_the_edit_once_its_semantics_have_been_re_derived() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        let held = commit_then_move_bytes_without_reparsing(&init, &graph, &blobs, SESSIONS_AFTER);
        replace_entities_in_graph(&graph, &blobs, "sessions.py", &held, SESSIONS_AFTER);

        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("commitrace"),
            "publish the edit".to_string(),
        )
        .expect("a path whose semantics were re-derived from its own bytes must commit");
        assert_eq!(
            plan.file_count, 1,
            "the change still carries the one file whose bytes moved"
        );
        assert!(
            plan.entity_count > 0,
            "the re-derived spans must reach the change as entity deltas, or the commit is still \
             recording bytes with no semantics"
        );
    }
}
