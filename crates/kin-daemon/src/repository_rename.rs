// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Graph-native repository-v6 rename execution.
//!
//! The planner reads one exact workspace graph and source bodies only from
//! repository CAS. Changed bodies are reparsed in memory, the renamed entity's
//! graph identity is retained explicitly, and the exact tree plus semantic
//! delta publish through the native repository transaction/projection journal.

use anyhow::{bail, Context, Result};
use axum::http::StatusCode;
use kin_cli::commands::rename::{
    plan_rename, RenameEdit, RenamePlan, RenameReport, RenameRequest, RenameResponse,
};
use kin_model::{
    ChangeStore, EntityDelta, EntityKind, EntityStore, FileLayout, FilePathId, GraphNodeId,
    Hash256, LocatedEntry, ParseCompleteness, RepoPath, SourceRegion, TransactionDelta, TreeDelta,
    TreeEntry,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::local_repository_authority::{
    require_fresh_daemon_workspace, LocalRepositoryAuthorityContext,
};
use crate::repository_commit::{
    commit_native_plan_with_projection, load_native_commit_base, load_native_source_blob,
    plan_native_commit_from_base, recover_native_commit, NativeCommitResult,
};
use crate::state::{DaemonEvent, DaemonState};

struct RenameExecution {
    response: RenameResponse,
    finalization: Option<RenameFinalization>,
}

struct RenameFinalization {
    committed: NativeCommitResult,
    authority_freeze: kin_db::LocalRepositoryAuthorityFreeze,
    previous_tree: kin_model::ResolvedTree,
    desired_tree: kin_model::ResolvedTree,
    planned_delta: TransactionDelta,
    layouts: Vec<FileLayout>,
}

const RENAME_METADATA_SCHEMA: &str = "kin.repository-rename-receipt.v1";
const RENAME_METADATA_PREFIX: &str = "Kin-Rename-Metadata: ";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RenameCommitMetadata {
    schema: String,
    request_binding: Hash256,
    entity_id: kin_model::EntityId,
    entity_kind: EntityKind,
    old_name: String,
    new_name: String,
    declaration_file: FilePathId,
    edited_files: Vec<FilePathId>,
    edit_count: usize,
}

pub(crate) fn execute(
    state: &DaemonState,
    request: &RenameRequest,
) -> std::result::Result<RenameResponse, (StatusCode, String)> {
    let graph_mutation = state.begin_graph_authority_mutation();
    let persistence = state.persist_lock.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "daemon persistence lock poisoned".to_string(),
        )
    })?;
    let previous_graph_root = hex::encode(state.graph.compute_root_hash());
    let RenameExecution {
        response,
        finalization,
    } = plan_commit_and_retain_authority(state, request).map_err(rename_error)?;
    let Some(execution) = finalization else {
        drop(persistence);
        drop(graph_mutation);
        return Ok(response);
    };

    if state
        .graph
        .get_change(&execution.committed.change.id)
        .map_err(internal_error)?
        .is_none()
    {
        state
            .graph
            .create_changes(vec![execution.committed.change.clone()])
            .map_err(internal_error)?;
    }
    let finalization = state
        .finalize_local_repository_commit(
            &execution.committed.receipt,
            &execution.authority_freeze,
            &execution.planned_delta,
            &execution.previous_tree,
            &execution.desired_tree,
        )
        .map_err(internal_error)?;
    for layout in execution.layouts {
        state
            .graph
            .upsert_file_layout(&layout)
            .map_err(internal_error)?;
    }
    if finalization.graph_changed {
        let current_graph_root = hex::encode(state.graph.compute_root_hash());
        state.bump_version();
        state.emit_event(DaemonEvent::GraphRootChanged {
            old_root_hash: Some(previous_graph_root),
            new_root_hash: current_graph_root,
        });
    } else if finalization.generation_advanced {
        state.mark_dirty();
    }
    if finalization.generation_advanced {
        state.emit_event(DaemonEvent::RepositoryAuthorityChanged {
            repository_id: execution.committed.receipt.repository_id.to_string(),
            operation_id: execution.committed.receipt.operation_id,
            previous_generation: execution.committed.receipt.roots_before.generation,
            new_generation: execution.committed.receipt.generation,
        });
    }
    drop(persistence);
    drop(graph_mutation);
    Ok(response)
}

fn plan_commit_and_retain_authority(
    state: &DaemonState,
    request: &RenameRequest,
) -> Result<RenameExecution> {
    let authority_context = LocalRepositoryAuthorityContext::from_state(state)
        .context("bind startup-pinned repository authority for rename")?;
    authority_context
        .revalidate_pinned_namespace()
        .map_err(|refusal| refusal.into_error())
        .context("revalidate startup-pinned repository namespace for rename")?;

    if let Some(recovered) = recover_native_commit(&authority_context, request.operation_id)? {
        return recover_committed_rename(state, request, &authority_context, recovered);
    }

    let base = load_native_commit_base(&authority_context)
        .context("load clean exact repository workspace for rename")?;
    require_fresh_daemon_workspace(
        state,
        &base.roots,
        &base.graph.to_snapshot(),
        "renaming an entity",
    )
    .context("bind rename plan to the daemon's exact repository generation")?;
    // File layouts are derived graph coverage, not repository history
    // semantics. Repository-v6 materializes the exact entity/relation/tree
    // authority while the daemon retains parse-coverage layouts beside it.
    // Copy only those layouts onto the authority graph used for planning;
    // target identity, relations, spans, and source bodies still all come
    // from the exact pinned repository generation.
    let planning_graph = kin_db::InMemoryGraph::from_snapshot(base.graph.to_snapshot())?;
    for layout in state.graph.list_file_layouts()? {
        planning_graph.upsert_file_layout(&layout)?;
    }
    let plan = plan_rename(&planning_graph, request, |_path, hash| {
        Ok(load_native_source_blob(&authority_context, hash)?)
    })?;
    let metadata = RenameCommitMetadata::from_plan(request, &plan)?;
    let (prospective, layouts) = apply_plan_in_memory(state, &authority_context, &base, &plan)?;
    prove_plan_postconditions(&base.graph, &prospective, &plan)?;

    let previous_tree = base.tree.clone();
    let desired_tree = prospective.resolved_tree();
    let native = plan_native_commit_from_base(
        &prospective,
        state.blobs.as_ref(),
        &authority_context,
        request.operation_id,
        kin_model::Timestamp::now(),
        request.actor.clone(),
        rename_change_message(&metadata)?,
        &base,
    )
    .context("plan one exact repository-v6 rename transaction")?;
    if native.change.tree_deltas.is_empty() || native.change.entity_deltas.is_empty() {
        bail!(
            "the rename produced only half of the change it has to publish, either the file edits \
             or the graph edits but not both, so kin refused a partial publication; nothing was \
             written, so re-run the rename and report it if it repeats"
        );
    }
    let planned_delta = TransactionDelta {
        admission_policy_delta: native.change.admission_policy_delta.clone(),
        ..TransactionDelta::default()
    };
    let (committed, authority_freeze, idempotent) = match commit_native_plan_with_projection(
        &state.layout,
        state.blobs.as_ref(),
        &authority_context,
        native,
    ) {
        Ok(committed) => {
            if matches!(
                committed.receipt.outcome,
                kin_model::RepositoryCommitOutcome::IdempotentReplay
            ) {
                return recover_committed_rename(state, request, &authority_context, committed);
            }
            let authority = authority_context.open()?;
            let freeze = authority
                .freeze_current_authority(&committed.receipt.roots_after)
                .context("retain committed rename repository authority")?;
            (committed, freeze, false)
        }
        Err(commit_error) => {
            let Some(recovered) = recover_native_commit(&authority_context, request.operation_id)?
            else {
                bail!("exact rename publication failed before authority moved: {commit_error}");
            };
            return recover_committed_rename(state, request, &authority_context, recovered);
        }
    };
    let response = response_for(&metadata, &committed, idempotent, request.json)?;
    Ok(RenameExecution {
        response,
        finalization: Some(RenameFinalization {
            committed,
            authority_freeze,
            previous_tree,
            desired_tree,
            planned_delta,
            layouts,
        }),
    })
}

fn recover_committed_rename(
    state: &DaemonState,
    request: &RenameRequest,
    authority_context: &LocalRepositoryAuthorityContext,
    committed: NativeCommitResult,
) -> Result<RenameExecution> {
    let metadata = rename_metadata_from_change(&committed.change.message)?;
    if metadata.request_binding != rename_request_binding(request)? {
        bail!(
            "rename operation {} was already committed for a different request",
            request.operation_id
        );
    }
    validate_recovered_metadata(&metadata, &committed)?;
    let receipt = committed.receipt.clone();
    let current = load_native_commit_base(authority_context)?;
    if current.roots.generation < receipt.generation {
        bail!(
            "repository authority generation {} is behind recovered rename generation {}; refusing inconsistent operation history",
            current.roots.generation,
            receipt.generation,
        );
    }
    if current.roots.generation == receipt.generation && current.roots != receipt.roots_after {
        bail!(
            "repository authority diverges from recovered rename generation {}; refusing ambiguous operation history",
            receipt.generation
        );
    }
    let response = response_for(&metadata, &committed, true, request.json)?;
    if current.roots != receipt.roots_after {
        // A later serialized transaction is already authoritative. The
        // operation receipt and bound change are immutable historical truth;
        // replay the original outcome without trying to reinstall or finalize
        // an old generation over the current workspace.
        return Ok(RenameExecution {
            response,
            finalization: None,
        });
    }
    let desired_tree = current.tree.clone();
    let inverse = committed
        .change
        .tree_deltas
        .iter()
        .map(TreeDelta::inverse)
        .collect::<Vec<_>>();
    let previous_tree = desired_tree
        .apply(&inverse)
        .context("reconstruct recovered rename prior tree")?;
    let layouts = rebuild_layouts(state, authority_context, &current, &committed.change)?;
    let authority = authority_context.open()?;
    let authority_freeze = authority
        .freeze_current_authority(&receipt.roots_after)
        .context("retain recovered rename repository authority")?;
    Ok(RenameExecution {
        response,
        finalization: Some(RenameFinalization {
            committed,
            authority_freeze,
            previous_tree,
            desired_tree,
            planned_delta: TransactionDelta::default(),
            layouts,
        }),
    })
}

fn rename_request_binding(request: &RenameRequest) -> Result<Hash256> {
    let binding = serde_json::to_vec(&(
        request.symbol.as_str(),
        request.new_name.as_str(),
        request.file.as_deref(),
        request.line,
        request.column,
        &request.actor,
    ))
    .context("encode exact rename request binding")?;
    Ok(Hash256::from_bytes(kin_blobs::digest(&binding).0))
}

impl RenameCommitMetadata {
    fn from_plan(request: &RenameRequest, plan: &RenamePlan) -> Result<Self> {
        let mut edited_files = plan
            .edits
            .iter()
            .map(|edit| edit.file.clone())
            .collect::<Vec<_>>();
        edited_files.sort_by(|left, right| left.0.cmp(&right.0));
        edited_files.dedup();
        Ok(Self {
            schema: RENAME_METADATA_SCHEMA.to_string(),
            request_binding: rename_request_binding(request)?,
            entity_id: plan.entity_id,
            entity_kind: plan.entity_kind,
            old_name: plan.old_name.clone(),
            new_name: plan.new_name.clone(),
            declaration_file: plan.declaration_file.clone(),
            edited_files,
            edit_count: plan.edits.len(),
        })
    }
}

fn rename_change_message(metadata: &RenameCommitMetadata) -> Result<String> {
    let encoded =
        serde_json::to_string(metadata).context("encode durable rename receipt metadata")?;
    Ok(format!(
        "Rename {} to {}\n\n{}{}",
        metadata.old_name, metadata.new_name, RENAME_METADATA_PREFIX, encoded
    ))
}

fn rename_metadata_from_change(message: &str) -> Result<RenameCommitMetadata> {
    let encoded = message
        .lines()
        .find_map(|line| line.strip_prefix(RENAME_METADATA_PREFIX))
        .ok_or_else(|| {
            anyhow::anyhow!("recovered rename change has no durable receipt metadata")
        })?;
    let metadata: RenameCommitMetadata =
        serde_json::from_str(encoded).context("decode durable rename receipt metadata")?;
    if metadata.schema != RENAME_METADATA_SCHEMA {
        bail!(
            "recovered rename metadata schema '{}' is unsupported",
            metadata.schema
        );
    }
    Ok(metadata)
}

fn validate_recovered_metadata(
    metadata: &RenameCommitMetadata,
    committed: &NativeCommitResult,
) -> Result<()> {
    if metadata.edit_count == 0
        || metadata.edited_files.is_empty()
        || !metadata.edited_files.contains(&metadata.declaration_file)
    {
        bail!("recovered rename metadata does not describe a complete source edit set");
    }
    let identity_delta = committed.change.entity_deltas.iter().any(|delta| {
        matches!(
            delta,
            EntityDelta::Modified { old, new }
                if old.id == metadata.entity_id
                    && new.id == metadata.entity_id
                    && old.kind == metadata.entity_kind
                    && new.kind == metadata.entity_kind
                    && old.name == metadata.old_name
                    && new.name == metadata.new_name
        )
    });
    if !identity_delta {
        bail!(
            "recovered rename change does not carry its metadata-bound identity-preserving entity delta"
        );
    }
    let mut changed_files = committed
        .change
        .tree_deltas
        .iter()
        .filter_map(|delta| delta.new_state())
        .map(|located| {
            located
                .path
                .as_utf8()
                .map(FilePathId::new)
                .ok_or_else(|| anyhow::anyhow!("recovered rename source path is not UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    changed_files.sort_by(|left, right| left.0.cmp(&right.0));
    changed_files.dedup();
    if changed_files != metadata.edited_files {
        bail!("recovered rename source delta set disagrees with durable receipt metadata");
    }
    Ok(())
}

fn apply_plan_in_memory(
    state: &DaemonState,
    authority_context: &LocalRepositoryAuthorityContext,
    base: &crate::repository_commit::NativeCommitBase,
    plan: &RenamePlan,
) -> Result<(kin_db::InMemoryGraph, Vec<FileLayout>)> {
    let prospective = kin_db::InMemoryGraph::from_snapshot(base.graph.to_snapshot())
        .context("create prospective rename graph")?;
    let mut by_file = BTreeMap::<String, Vec<RenameEdit>>::new();
    for edit in &plan.edits {
        by_file
            .entry(edit.file.0.clone())
            .or_default()
            .push(edit.clone());
    }
    let pipeline = kin_index::IndexPipeline::new();
    let mut layouts = Vec::new();
    for (file_path, mut edits) in by_file {
        let file_id = FilePathId::new(file_path);
        edits.sort_by_key(|edit| edit.start_byte);
        validate_non_overlapping_edits(&file_id, &edits)?;
        let path = RepoPath::from_utf8(file_id.0.clone())?;
        let artifact = prospective
            .resolved_tree()
            .artifact_at_path(&path)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("rename source {file_id} left the exact tree"))?;
        let (old_hash, executable) = match artifact.entry {
            TreeEntry::Blob { hash, executable } => (hash, executable),
            _ => bail!("rename source {file_id} is not a regular repository source blob"),
        };
        let original = load_native_source_blob(authority_context, old_hash)?;
        let projected = apply_edits(&file_id, &original, &edits)?;
        let digest = state.blobs.write(&projected)?;
        let new_hash = Hash256::from_bytes(digest.0);
        prospective.apply_transaction_delta(&TransactionDelta {
            tree_deltas: vec![TreeDelta::Updated {
                artifact_id: artifact.artifact_id,
                old: artifact.located_entry(),
                new: LocatedEntry::new(path, TreeEntry::blob(new_hash, executable)),
            }],
            ..TransactionDelta::default()
        })?;

        let indexed = pipeline
            .index_any_content(&file_id, &projected, digest)
            .with_context(|| format!("reparse renamed exact source {file_id}"))?;
        let kin_index::IndexedAny::EntitySource(mut indexed) = indexed else {
            bail!("renamed source {file_id} no longer classifies as entity source");
        };
        if indexed.file_layout.parse_completeness != ParseCompleteness::Full {
            bail!(
                "renamed source {file_id} reparsed with {} coverage; refusing incomplete semantic authority",
                indexed.file_layout.parse_completeness.bucket()
            );
        }
        if file_id == plan.declaration_file {
            retain_target_identity(&mut indexed, plan)?;
        }
        let mut reconciler = kin_reconcile::Reconciler::new(std::path::PathBuf::new());
        let reconcile = reconciler
            .reconcile_indexed_content(&indexed, state.blobs.as_ref(), &prospective)
            .with_context(|| format!("derive renamed semantics for {file_id}"))?;
        if let Some(delta) = reconcile.delta.entity_deltas.iter().find(|delta| {
            matches!(
                delta,
                EntityDelta::Added { .. } | EntityDelta::Removed { .. }
            )
        }) {
            bail!(
                "rename of {} would create or remove an entity while reparsing {file_id} ({delta:?}); refusing identity loss",
                plan.entity_id
            );
        }
        prospective
            .apply_transaction_delta(&reconcile.delta)
            .with_context(|| format!("apply renamed semantics for {file_id}"))?;
        let layout = reconciler
            .projection()
            .get_layout(&file_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("rename reparse produced no layout for {file_id}"))?;
        prospective.upsert_file_layout(&layout)?;
        layouts.push(layout);
    }
    Ok((prospective, layouts))
}

fn retain_target_identity(indexed: &mut kin_index::IndexedFile, plan: &RenamePlan) -> Result<()> {
    let candidates = indexed
        .entities
        .iter()
        .enumerate()
        .filter(|(_, entity)| entity.name == plan.new_name && entity.kind == plan.entity_kind)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let [index] = candidates.as_slice() else {
        bail!(
            "renamed declaration reparsed into {} candidate identities named '{}' of kind {:?}; expected exactly one",
            candidates.len(),
            plan.new_name,
            plan.entity_kind
        );
    };
    let parsed_id = indexed.entities[*index].id;
    if indexed
        .entities
        .iter()
        .enumerate()
        .any(|(other, entity)| other != *index && entity.id == plan.entity_id)
    {
        bail!(
            "renamed target identity {} collides with another parsed entity",
            plan.entity_id
        );
    }
    indexed.entities[*index].id = plan.entity_id;
    for relation in &mut indexed.relations {
        if relation.src == GraphNodeId::Entity(parsed_id) {
            relation.src = GraphNodeId::Entity(plan.entity_id);
        }
        if relation.dst == GraphNodeId::Entity(parsed_id) {
            relation.dst = GraphNodeId::Entity(plan.entity_id);
        }
    }
    for relation in &mut indexed.unresolved_relations {
        if relation.src_entity_id == parsed_id {
            relation.src_entity_id = plan.entity_id;
        }
    }
    for region in &mut indexed.file_layout.regions {
        if let SourceRegion::EntityRef { entity_id, .. } = region {
            if *entity_id == parsed_id {
                *entity_id = plan.entity_id;
            }
        }
    }
    Ok(())
}

fn validate_non_overlapping_edits(file: &FilePathId, edits: &[RenameEdit]) -> Result<()> {
    for pair in edits.windows(2) {
        if pair[0].end_byte > pair[1].start_byte {
            bail!(
                "rename plan contains overlapping edits in {file}: {}..{} and {}..{}",
                pair[0].start_byte,
                pair[0].end_byte,
                pair[1].start_byte,
                pair[1].end_byte
            );
        }
    }
    Ok(())
}

fn apply_edits(file: &FilePathId, original: &[u8], edits: &[RenameEdit]) -> Result<Vec<u8>> {
    let mut projected = original.to_vec();
    for edit in edits.iter().rev() {
        if edit.end_byte > original.len() || edit.start_byte >= edit.end_byte {
            bail!("rename edit for {file} is outside its exact source body");
        }
        if original.get(edit.start_byte..edit.end_byte) != Some(edit.old_text.as_bytes()) {
            bail!(
                "rename edit for {file} no longer matches '{}' at {}..{} in repository CAS",
                edit.old_text,
                edit.start_byte,
                edit.end_byte
            );
        }
        projected.splice(
            edit.start_byte..edit.end_byte,
            edit.new_text.as_bytes().iter().copied(),
        );
    }
    Ok(projected)
}

fn prove_plan_postconditions(
    before: &kin_db::InMemoryGraph,
    after: &kin_db::InMemoryGraph,
    plan: &RenamePlan,
) -> Result<()> {
    let old = before.get_entity(&plan.entity_id)?.ok_or_else(|| {
        anyhow::anyhow!(
            "the entity {} being renamed is no longer in this repository's authority base, so \
                 kin refused the rename; nothing was written, so run `kin status` and try again",
            plan.entity_id
        )
    })?;
    let new = after.get_entity(&plan.entity_id)?.ok_or_else(|| {
        anyhow::anyhow!(
            "the entity {} being renamed did not survive reparsing the edited source, so kin \
                 refused the rename; nothing was written, so check the file still parses and try \
                 again",
            plan.entity_id
        )
    })?;
    if old.name != plan.old_name || new.name != plan.new_name || old.kind != new.kind {
        bail!(
            "rename did not preserve graph identity {} across '{}' -> '{}'",
            plan.entity_id,
            plan.old_name,
            plan.new_name
        );
    }
    let before_snapshot = before.to_snapshot();
    let after_snapshot = after.to_snapshot();
    let before_ids = before_snapshot
        .relations
        .keys()
        .copied()
        .collect::<BTreeSet<_>>();
    let after_ids = after_snapshot
        .relations
        .keys()
        .copied()
        .collect::<BTreeSet<_>>();
    if before_ids != after_ids {
        let dropped = before_ids
            .difference(&after_ids)
            .copied()
            .collect::<Vec<_>>();
        let added = after_ids
            .difference(&before_ids)
            .copied()
            .collect::<Vec<_>>();
        bail!(
            "reparsing the renamed source changed which relations this repository holds, \
             dropping {dropped:?} and adding {added:?}, so kin refused the rename rather than \
             publish semantic drift; nothing was written"
        );
    }
    for (relation_id, prior) in &before_snapshot.relations {
        let current = after_snapshot
            .relations
            .get(relation_id)
            .expect("relation identity sets were proven equal");
        if prior.kind != current.kind || prior.src != current.src || prior.dst != current.dst {
            bail!(
                "rename reparse rewired graph relation {} from {:?} {} -> {} to {:?} {} -> {}; refusing semantic drift",
                relation_id,
                prior.kind,
                prior.src,
                prior.dst,
                current.kind,
                current.src,
                current.dst
            );
        }
    }
    if plan
        .relation_ids
        .iter()
        .any(|relation_id| !after_snapshot.relations.contains_key(relation_id))
    {
        bail!(
            "reparsing the renamed source lost a relation that had selected one of the edit \
             sites, so kin refused the rename rather than publish an incomplete one; nothing was \
             written"
        );
    }
    Ok(())
}

fn response_for(
    metadata: &RenameCommitMetadata,
    committed: &NativeCommitResult,
    idempotent: bool,
    json: bool,
) -> Result<RenameResponse> {
    let report = RenameReport {
        authority: "repository-v6 graph + source CAS".to_string(),
        operation_id: committed.receipt.operation_id,
        change_id: committed.change.id,
        authority_generation: committed.receipt.generation,
        entity_id: metadata.entity_id,
        old_name: metadata.old_name.clone(),
        new_name: metadata.new_name.clone(),
        edited_files: metadata.edited_files.clone(),
        edit_count: metadata.edit_count,
        idempotent,
    };
    let lines = if json {
        Vec::new()
    } else if idempotent {
        vec![
            format!(
                "Recovered committed rename {} -> {} ({} original exact edit(s) across {} file(s)); no new edits applied",
                report.old_name,
                report.new_name,
                report.edit_count,
                report.edited_files.len()
            ),
            format!(
                "Repository-v6 change {} remains at generation {}",
                report.change_id, report.authority_generation
            ),
        ]
    } else {
        vec![
            format!(
                "Renamed {} -> {} across {} exact edit(s) in {} file(s)",
                report.old_name,
                report.new_name,
                report.edit_count,
                report.edited_files.len()
            ),
            format!(
                "Repository-v6 change {} committed at generation {}",
                report.change_id, report.authority_generation
            ),
        ]
    };
    Ok(RenameResponse {
        lines,
        report: Some(report),
    })
}

fn rebuild_layouts(
    state: &DaemonState,
    authority_context: &LocalRepositoryAuthorityContext,
    current: &crate::repository_commit::NativeCommitBase,
    change: &kin_model::SemanticChange,
) -> Result<Vec<FileLayout>> {
    let pipeline = kin_index::IndexPipeline::new();
    let changed = change
        .tree_deltas
        .iter()
        .filter_map(|delta| delta.new_state())
        .filter_map(|located| located.path.as_utf8().map(FilePathId::new))
        .collect::<HashSet<_>>();
    let mut layouts = Vec::new();
    for file_id in changed {
        let path = RepoPath::from_utf8(file_id.0.clone())?;
        let artifact = current
            .tree
            .artifact_at_path(&path)
            .ok_or_else(|| anyhow::anyhow!("recovered rename source {file_id} is absent"))?;
        let hash = artifact
            .entry
            .blob_identity()
            .ok_or_else(|| anyhow::anyhow!("recovered rename source {file_id} is not a blob"))?;
        let body = load_native_source_blob(authority_context, hash)?;
        let digest = state.blobs.write(&body)?;
        let indexed = pipeline.index_any_content(&file_id, &body, digest)?;
        let kin_index::IndexedAny::EntitySource(indexed) = indexed else {
            bail!("recovered rename source {file_id} is no longer entity source");
        };
        let mut layout = indexed.file_layout;
        stabilize_recovered_layout(&mut layout, &indexed.entities, &current.graph)?;
        layouts.push(layout);
    }
    Ok(layouts)
}

fn stabilize_recovered_layout(
    layout: &mut FileLayout,
    parsed: &[kin_model::Entity],
    graph: &kin_db::InMemoryGraph,
) -> Result<()> {
    let entities = graph.query_entities(&kin_model::EntityFilter {
        file_path: Some(layout.file_id.clone()),
        ..kin_model::EntityFilter::default()
    })?;
    for region in &mut layout.regions {
        let SourceRegion::EntityRef { entity_id, .. } = region else {
            continue;
        };
        let parsed_entity = parsed
            .iter()
            .find(|entity| entity.id == *entity_id)
            .ok_or_else(|| anyhow::anyhow!("recovered layout references unknown parsed entity"))?;
        let matches = entities
            .iter()
            .filter(|entity| entity.name == parsed_entity.name && entity.kind == parsed_entity.kind)
            .collect::<Vec<_>>();
        let [matched] = matches.as_slice() else {
            bail!(
                "recovered layout entity '{}' of kind {:?} maps to {} authority identities",
                parsed_entity.name,
                parsed_entity.kind,
                matches.len()
            );
        };
        *entity_id = matched.id;
    }
    Ok(())
}

fn rename_error(error: anyhow::Error) -> (StatusCode, String) {
    let message = crate::error::cause_first(&error);
    let status = if message.contains("not a simple source identifier") {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::CONFLICT
    };
    (status, message)
}

fn internal_error(error: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, OnceLock};

    use kin_model::work::{
        Annotation, AnnotationId, AnnotationKind, IdentityRef, SemanticAnchor, StalenessState,
        WorkScope,
    };
    use kin_model::{AuthorId, RelationDelta, RelationId, RelationKind, Timestamp, WorkStore};

    fn install_test_registry_override() {
        static REGISTRY_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();
        let _guard = crate::test_env_lock();
        let path = REGISTRY_PATH.get_or_init(|| {
            let root = std::env::temp_dir().join(format!(
                "kin-daemon-rename-registry-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let path = root.join("registry.toml");
            kin_core::registry::KinRegistry { repos: Vec::new() }
                .save_to(&path)
                .unwrap();
            path
        });
        kin_core::test_env::install_process_wide("KIN_REGISTRY_PATH", path);
    }

    struct RenameFixture {
        _root: tempfile::TempDir,
        state: Arc<DaemonState>,
        target_id: kin_model::EntityId,
        relation_id: RelationId,
        target_file: FilePathId,
        caller_file: FilePathId,
    }

    fn exact_rename_fixture() -> RenameFixture {
        install_test_registry_override();
        let root = tempfile::tempdir().unwrap();
        let layout = kin_core::init(root.path()).unwrap().layout;
        let state = Arc::new(DaemonState::open(layout).unwrap());
        let target_file = FilePathId::new("src/target.rs");
        let caller_file = FilePathId::new("src/caller.rs");
        let target_body = b"pub fn target() -> u32 { 7 }\n";
        let caller_body = b"pub fn caller() -> u32 { target() + target() }\n";
        std::fs::create_dir_all(root.path().join("src")).unwrap();
        std::fs::write(root.path().join(&target_file.0), target_body).unwrap();
        std::fs::write(root.path().join(&caller_file.0), caller_body).unwrap();

        let target_digest = state.blobs.write(target_body).unwrap();
        let caller_digest = state.blobs.write(caller_body).unwrap();
        let pipeline = kin_index::IndexPipeline::new();
        let kin_index::IndexedAny::EntitySource(target_indexed) = pipeline
            .index_any_content(&target_file, target_body, target_digest)
            .unwrap()
        else {
            panic!("target fixture must classify as source");
        };
        let kin_index::IndexedAny::EntitySource(caller_indexed) = pipeline
            .index_any_content(&caller_file, caller_body, caller_digest)
            .unwrap()
        else {
            panic!("caller fixture must classify as source");
        };
        let target = target_indexed
            .entities
            .iter()
            .find(|entity| entity.name == "target")
            .unwrap()
            .clone();
        let caller = caller_indexed
            .entities
            .iter()
            .find(|entity| entity.name == "caller")
            .unwrap()
            .clone();
        let target_artifact = kin_model::ArtifactId::new();
        let caller_artifact = kin_model::ArtifactId::new();
        let artifact_ids = kin_index::linker::ArtifactIdentityMap::from([
            (target_file.0.clone(), target_artifact),
            (caller_file.0.clone(), caller_artifact),
        ]);
        let parse_data = [
            kin_index::FileParseData {
                file_path: target_file.0.clone(),
                entities: target_indexed.entities.clone(),
                relations: target_indexed.extracted_relations.clone(),
                imports: target_indexed.imports.clone(),
            },
            kin_index::FileParseData {
                file_path: caller_file.0.clone(),
                entities: caller_indexed.entities.clone(),
                relations: caller_indexed.extracted_relations.clone(),
                imports: caller_indexed.imports.clone(),
            },
        ];
        let completeness = kin_index::FileParseCompletenessMap::from([
            (
                target_file.0.clone(),
                target_indexed.file_layout.parse_completeness.clone(),
            ),
            (
                caller_file.0.clone(),
                caller_indexed.file_layout.parse_completeness.clone(),
            ),
        ]);
        let linked =
            kin_index::link_cross_file_with_completeness(&parse_data, &artifact_ids, &completeness)
                .unwrap();
        let relation = linked
            .iter()
            .find(|relation| {
                relation.kind == RelationKind::Calls
                    && relation.src == GraphNodeId::Entity(caller.id)
                    && relation.dst == GraphNodeId::Entity(target.id)
            })
            .expect("real linker must resolve the repeated caller/target edge");
        assert!(relation
            .evidence
            .iter()
            .all(|evidence| evidence.source_span.is_none()));
        assert_eq!(
            relation
                .evidence
                .iter()
                .map(|evidence| evidence.occurrence_count)
                .sum::<u32>(),
            2
        );
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: target_indexed
                    .entities
                    .iter()
                    .chain(&caller_indexed.entities)
                    .cloned()
                    .map(|new| EntityDelta::Added { new })
                    .collect(),
                relation_deltas: linked
                    .iter()
                    .cloned()
                    .map(|new| RelationDelta::Added { new })
                    .collect(),
                tree_deltas: vec![
                    TreeDelta::Added {
                        artifact_id: target_artifact,
                        new: LocatedEntry::new(
                            RepoPath::from_utf8(target_file.0.clone()).unwrap(),
                            TreeEntry::blob(Hash256::from_bytes(target_digest.0), false),
                        ),
                    },
                    TreeDelta::Added {
                        artifact_id: caller_artifact,
                        new: LocatedEntry::new(
                            RepoPath::from_utf8(caller_file.0.clone()).unwrap(),
                            TreeEntry::blob(Hash256::from_bytes(caller_digest.0), false),
                        ),
                    },
                ],
                ..TransactionDelta::default()
            })
            .unwrap();
        state
            .graph
            .upsert_file_layout(&target_indexed.file_layout)
            .unwrap();
        state
            .graph
            .upsert_file_layout(&caller_indexed.file_layout)
            .unwrap();
        let authority_context = LocalRepositoryAuthorityContext::from_state(&state).unwrap();
        let native = crate::repository_commit::plan_native_commit(
            &state.graph,
            state.blobs.as_ref(),
            &authority_context,
            kin_model::OperationId::new(),
            Timestamp::now(),
            AuthorId::new("rename-fixture"),
            "Install exact rename fixture".to_string(),
        )
        .unwrap();
        let committed = crate::repository_commit::commit_native_plan(
            state.blobs.as_ref(),
            &authority_context,
            native,
        )
        .unwrap();
        state
            .graph
            .create_changes(vec![committed.change.clone()])
            .unwrap();
        state
            .record_repository_authority_commit(committed.receipt.generation)
            .unwrap();

        RenameFixture {
            _root: root,
            state,
            target_id: target.id,
            relation_id: relation.id,
            target_file,
            caller_file,
        }
    }

    #[test]
    fn exact_edit_application_refuses_a_moved_token() {
        let file = FilePathId::new("src/lib.rs");
        let edit = RenameEdit {
            file: file.clone(),
            start_byte: 3,
            end_byte: 9,
            start_line: 1,
            start_col: 3,
            end_line: 1,
            end_col: 9,
            old_text: "target".to_string(),
            new_text: "renamed".to_string(),
            reason: "declaration".to_string(),
            declaration: true,
        };
        let error = apply_edits(&file, b"fn other() {}", &[edit]).unwrap_err();
        assert!(error.to_string().contains("no longer matches"));
    }

    #[test]
    fn repository_rename_commits_tree_and_semantics_and_replays_by_operation() {
        let fixture = exact_rename_fixture();
        let operation_id = kin_model::OperationId::new();
        let request = RenameRequest {
            symbol: "target".to_string(),
            new_name: "renamed_target".to_string(),
            file: Some(fixture.target_file.0.clone()),
            line: Some(1),
            column: None,
            json: true,
            operation_id,
            actor: AuthorId::new("rename-test"),
        };

        let first = execute(&fixture.state, &request).unwrap();
        let report = first.report.unwrap();
        assert_eq!(report.operation_id, operation_id);
        assert_eq!(report.entity_id, fixture.target_id);
        assert_eq!(report.edit_count, 3);
        assert_eq!(report.edited_files.len(), 2);
        assert!(!report.idempotent);
        assert_eq!(
            std::fs::read_to_string(
                fixture
                    .state
                    .layout
                    .working_dir()
                    .join(&fixture.target_file.0)
            )
            .unwrap(),
            "pub fn renamed_target() -> u32 { 7 }\n"
        );
        assert_eq!(
            std::fs::read_to_string(
                fixture
                    .state
                    .layout
                    .working_dir()
                    .join(&fixture.caller_file.0)
            )
            .unwrap(),
            "pub fn caller() -> u32 { renamed_target() + renamed_target() }\n"
        );

        let live_target = fixture
            .state
            .graph
            .get_entity(&fixture.target_id)
            .unwrap()
            .unwrap();
        assert_eq!(live_target.name, "renamed_target");
        assert!(fixture
            .state
            .graph
            .to_snapshot()
            .relations
            .contains_key(&fixture.relation_id));
        let authority_context =
            LocalRepositoryAuthorityContext::from_state(&fixture.state).unwrap();
        let authority_base = load_native_commit_base(&authority_context).unwrap();
        assert_eq!(
            authority_base
                .graph
                .get_entity(&fixture.target_id)
                .unwrap()
                .unwrap()
                .name,
            "renamed_target"
        );
        assert!(authority_base
            .graph
            .to_snapshot()
            .relations
            .contains_key(&fixture.relation_id));

        let mut mismatched = request.clone();
        mismatched.file = Some(fixture.caller_file.0.clone());
        let mut selector_mismatch = request.clone();
        selector_mismatch.symbol = "module::target".to_string();
        let mut name_mismatch = request.clone();
        name_mismatch.new_name = "other_target".to_string();
        let mut line_mismatch = request.clone();
        line_mismatch.line = Some(2);
        let mut column_mismatch = request.clone();
        column_mismatch.column = Some(0);
        let mut actor_mismatch = request.clone();
        actor_mismatch.actor = AuthorId::new("different-actor");
        for changed in [
            mismatched,
            selector_mismatch,
            name_mismatch,
            line_mismatch,
            column_mismatch,
            actor_mismatch,
        ] {
            let (_, mismatch) = execute(&fixture.state, &changed).unwrap_err();
            assert!(mismatch.contains("already committed for a different request"));
        }

        let mut text_request = request.clone();
        text_request.json = false;
        let replay = execute(&fixture.state, &text_request).unwrap();
        let replay_report = replay.report.unwrap();
        assert!(replay_report.idempotent);
        assert_eq!(replay_report.edit_count, 3);

        let reopened = Arc::new(DaemonState::open(fixture.state.layout.clone()).unwrap());
        let restart_replay = execute(&reopened, &request).unwrap();
        let restart_report = restart_replay.report.unwrap();
        assert!(restart_report.idempotent);
        assert_eq!(restart_report.edit_count, 3);
        assert_eq!(
            reopened
                .graph
                .get_entity(&fixture.target_id)
                .unwrap()
                .unwrap()
                .name,
            "renamed_target"
        );
    }

    #[test]
    fn qualified_selector_replays_the_canonical_committed_report() {
        let fixture = exact_rename_fixture();
        let request = RenameRequest {
            symbol: "module::target".to_string(),
            new_name: "renamed_target".to_string(),
            file: Some(fixture.target_file.0.clone()),
            line: Some(1),
            column: Some(7),
            json: true,
            operation_id: kin_model::OperationId::new(),
            actor: AuthorId::new("qualified-rename-test"),
        };

        let first = execute(&fixture.state, &request).unwrap().report.unwrap();
        assert_eq!(first.old_name, "target");
        assert_eq!(first.new_name, "renamed_target");
        assert_eq!(first.edit_count, 3);
        assert!(!first.idempotent);

        let replay = execute(&fixture.state, &request).unwrap().report.unwrap();
        assert_eq!(replay.old_name, "target");
        assert_eq!(replay.entity_id, first.entity_id);
        assert_eq!(replay.edited_files, first.edited_files);
        assert_eq!(replay.edit_count, first.edit_count);
        assert!(replay.idempotent);
    }

    #[test]
    fn operation_replay_after_a_later_generation_returns_historical_outcome() {
        let fixture = exact_rename_fixture();
        let first_request = RenameRequest {
            symbol: "target".to_string(),
            new_name: "renamed_target".to_string(),
            file: Some(fixture.target_file.0.clone()),
            line: Some(1),
            column: None,
            json: true,
            operation_id: kin_model::OperationId::new(),
            actor: AuthorId::new("historical-rename-test"),
        };
        let first = execute(&fixture.state, &first_request)
            .unwrap()
            .report
            .unwrap();
        let second_request = RenameRequest {
            symbol: "renamed_target".to_string(),
            new_name: "final_target".to_string(),
            file: Some(fixture.target_file.0.clone()),
            line: Some(1),
            column: None,
            json: true,
            operation_id: kin_model::OperationId::new(),
            actor: AuthorId::new("later-rename-test"),
        };
        let second = execute(&fixture.state, &second_request)
            .unwrap()
            .report
            .unwrap();
        assert!(second.authority_generation > first.authority_generation);

        let replay = execute(&fixture.state, &first_request)
            .unwrap()
            .report
            .unwrap();
        assert!(replay.idempotent);
        assert_eq!(replay.change_id, first.change_id);
        assert_eq!(replay.authority_generation, first.authority_generation);
        assert_eq!(replay.old_name, first.old_name);
        assert_eq!(replay.new_name, first.new_name);
        assert_eq!(replay.edit_count, first.edit_count);
        assert_eq!(replay.edited_files, first.edited_files);
        assert_eq!(
            fixture
                .state
                .graph
                .get_entity(&fixture.target_id)
                .unwrap()
                .unwrap()
                .name,
            "final_target"
        );
    }

    #[test]
    fn repository_rename_refuses_unadmitted_working_tree_drift_without_moving_authority() {
        let fixture = exact_rename_fixture();
        let authority_context =
            LocalRepositoryAuthorityContext::from_state(&fixture.state).unwrap();
        let roots_before = authority_context
            .open()
            .unwrap()
            .read_authority()
            .roots()
            .clone();
        let graph_root_before = fixture.state.graph.compute_root_hash();
        let tree_before = fixture.state.graph.resolved_tree();
        std::fs::write(
            fixture
                .state
                .layout
                .working_dir()
                .join(&fixture.caller_file.0),
            b"pub fn caller() -> u32 { 99 }\n",
        )
        .unwrap();
        let request = RenameRequest {
            symbol: "target".to_string(),
            new_name: "renamed_target".to_string(),
            file: Some(fixture.target_file.0.clone()),
            line: Some(1),
            column: None,
            json: true,
            operation_id: kin_model::OperationId::new(),
            actor: AuthorId::new("rename-drift-test"),
        };

        let (status, message) = execute(&fixture.state, &request).unwrap_err();
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            message.contains("failed before authority moved"),
            "unexpected refusal: {message}"
        );
        let roots_after = authority_context
            .open()
            .unwrap()
            .read_authority()
            .roots()
            .clone();
        assert_eq!(roots_after, roots_before);
        assert_eq!(fixture.state.graph.compute_root_hash(), graph_root_before);
        assert_eq!(fixture.state.graph.resolved_tree(), tree_before);
    }

    /// `kin-model/src/work.rs` promises that annotations are anchored to entity
    /// identities rather than line numbers, "so they are designed to stay
    /// attached across renames and moves". Nothing tested that end to end.
    ///
    /// The promise only holds because `retain_target_identity` overwrites the
    /// reparsed entity's id with the pre-rename one. `EntityId::from_content`
    /// keys a UUIDv5 on file path, kind, name and start line, so the parser
    /// mints a different id for the renamed declaration and an annotation
    /// scoped to the old id would have nothing to resolve against. Asserting
    /// the id equals itself would prove none of that, so this drives the real
    /// rename and asks the graph what is still attached afterwards.
    #[test]
    fn rename_keeps_an_annotation_attached_to_the_renamed_entity() {
        let fixture = exact_rename_fixture();
        let before = fixture
            .state
            .graph
            .get_entity(&fixture.target_id)
            .unwrap()
            .unwrap();
        assert_eq!(before.name, "target");

        let annotation = Annotation {
            annotation_id: AnnotationId::new(),
            kind: AnnotationKind::Reasoning,
            body: "target returns 7 because the caller doubles it".to_string(),
            scopes: vec![WorkScope::Entity(fixture.target_id)],
            anchored_fingerprint: Some(SemanticAnchor {
                ast_hash: before.fingerprint.ast_hash,
                signature_hash: before.fingerprint.signature_hash,
            }),
            authored_by: IdentityRef::assistant("rename-annotation-test"),
            created_at: Timestamp::now(),
            staleness: StalenessState::Fresh,
        };
        fixture.state.graph.create_annotation(&annotation).unwrap();

        let ids_before = fixture
            .state
            .graph
            .to_snapshot()
            .entities
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();

        let request = RenameRequest {
            symbol: "target".to_string(),
            new_name: "renamed_target".to_string(),
            file: Some(fixture.target_file.0.clone()),
            line: Some(1),
            column: None,
            json: true,
            operation_id: kin_model::OperationId::new(),
            actor: AuthorId::new("rename-annotation-test"),
        };
        let report = execute(&fixture.state, &request).unwrap().report.unwrap();
        assert_eq!(report.entity_id, fixture.target_id);

        // The rename really happened, so the assertion below is about a renamed
        // entity rather than an untouched one.
        let after = fixture
            .state
            .graph
            .get_entity(&fixture.target_id)
            .unwrap()
            .unwrap();
        assert_eq!(after.name, "renamed_target");

        // Bind the test to identity rather than to the rename merely succeeding.
        // The annotation resolves by exact `WorkScope` equality, so it survives
        // only while the entity keeps the id it was anchored to. Comparing the
        // whole id set catches a re-key, a duplicate added under the new name,
        // and a drop, none of which the name assertion above would notice. This
        // mirrors the relation-set guard the rename already runs on itself.
        let ids_after = fixture
            .state
            .graph
            .to_snapshot()
            .entities
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(ids_after, ids_before);
        assert!(ids_after.contains(&fixture.target_id));

        let attached = fixture
            .state
            .graph
            .get_annotations_for_scope(&WorkScope::Entity(fixture.target_id))
            .unwrap();
        assert_eq!(
            attached
                .iter()
                .map(|ann| ann.annotation_id)
                .collect::<Vec<_>>(),
            vec![annotation.annotation_id],
            "the annotation anchored before the rename must still resolve from the entity scope"
        );
        assert_eq!(attached[0].body, annotation.body);
        assert_eq!(
            attached[0].scopes,
            vec![WorkScope::Entity(fixture.target_id)]
        );
    }
}
