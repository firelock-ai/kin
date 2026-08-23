// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use hashbrown::{HashMap, HashSet};
use parking_lot::RwLock;
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(any(feature = "embeddings", feature = "vector"))]
use std::sync::Arc;

#[cfg(feature = "embeddings")]
use crate::embed::CodeEmbedder;
use crate::error::KinDbError;
use crate::search::{
    opaque_artifact_fields, shallow_file_fields, structured_artifact_fields, TextIndex,
};
use crate::storage::change_validation::validate_semantic_change;
use crate::storage::format::LocateGraphSnapshot;
use crate::storage::merkle::{
    compute_live_retrieval_authority_hash, compute_locate_retrieval_authority_hash,
    compute_retrieval_authority_hash, compute_root_hash_generic, GraphHashSource, MerkleCache,
};
use crate::storage::{CollectionDelta, Generation, GraphSnapshot, GraphSnapshotDelta, VecDelta};
use crate::store::{
    ChangeStore, EntityStore, GraphStore, ProvenanceStore, ReviewStore, SessionStore,
    VerificationStore, WorkStore,
};
use crate::types::*;
#[cfg(feature = "vector")]
use crate::vector::VectorIndex;

use super::index::IndexSet;
use super::traverse;

#[cfg(all(feature = "embeddings", feature = "vector"))]
fn default_embedding_batch_size() -> usize {
    std::env::var("KIN_EMBED_BATCH_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or_else(|| {
            if crate::embed::resource_profile_is_throughput() {
                crate::embed::throughput_graph_chunk_size()
            } else {
                std::thread::available_parallelism()
                    .map(|threads| (threads.get() * 16).clamp(64, 192))
                    .unwrap_or(128)
            }
        })
}

/// Bounded look-ahead between the drain+prep producer and the forward (GPU)
/// stage: at most this many prepared batches may sit in flight, capping host
/// scratch memory while still letting prep run ahead of inference.
#[cfg(all(feature = "embeddings", feature = "vector"))]
const EMBED_PIPELINE_PREP_CAPACITY: usize = 2;

/// Bounded look-ahead between the forward stage and the persist consumer.
#[cfg(all(feature = "embeddings", feature = "vector"))]
const EMBED_PIPELINE_RESULT_CAPACITY: usize = 2;

/// Whether the staged embed pipeline should overlap prep/forward/persist instead
/// of running them strictly back to back.
///
/// Opt-in by design: the citable proof profile keeps the serial path so the
/// persisted vector order is byte-for-byte the established order. An explicit
/// `KIN_EMBED_PIPELINED` value overrides in either direction (`1`/`true`/`on`
/// forces pipelined, `0`/`false`/`off` forces serial); absent that, the pipeline
/// turns on only under the throughput resource profile.
#[cfg(all(feature = "embeddings", feature = "vector"))]
fn embed_pipeline_enabled() -> bool {
    if let Ok(raw) = std::env::var("KIN_EMBED_PIPELINED") {
        let value = raw.trim();
        if value.eq_ignore_ascii_case("1")
            || value.eq_ignore_ascii_case("true")
            || value.eq_ignore_ascii_case("on")
        {
            return true;
        }
        if value.eq_ignore_ascii_case("0")
            || value.eq_ignore_ascii_case("false")
            || value.eq_ignore_ascii_case("off")
        {
            return false;
        }
    }
    crate::embed::resource_profile_is_throughput()
}

/// Drive the three embed stages — drain+prep, forward, persist — as a bounded
/// producer→consumer pipeline so prep for batch N+2 and persist for batch N
/// overlap the GPU forward for batch N+1.
///
/// Determinism is preserved end to end: `drain_prep` is the single serial
/// producer (the established `EmbedSortKey` ordering authority), and both stage
/// channels are FIFO with exactly one consumer each, so persist observes batches
/// — and the keys within each batch — in precisely the drained order. The forward
/// stage runs one batch at a time (a single consumer), so GPU concurrency is
/// unchanged; only the CPU prep/persist stages overlap inference.
///
/// The first error from any stage is captured and returned; channel disconnection
/// then tears the remaining stages down without deadlock — when a consumer drops
/// its receiver, the upstream `send` fails rather than blocking.
#[cfg(all(feature = "embeddings", feature = "vector"))]
fn drive_embed_pipeline<P, F, G, H>(
    prep_capacity: usize,
    result_capacity: usize,
    drain_prep: P,
    forward: F,
    persist: G,
    abandon: H,
) -> Result<usize, KinDbError>
where
    P: FnMut() -> Result<Option<PreparedEmbedBatch>, KinDbError> + Send,
    F: Fn(
            PreparedEmbedBatch,
        ) -> Result<(PreparedEmbedBatch, Vec<(RetrievalKey, Vec<f32>)>), KinDbError>
        + Send,
    G: FnMut(PreparedEmbedBatch, Vec<(RetrievalKey, Vec<f32>)>) -> Result<usize, KinDbError>,
    H: Fn(PreparedEmbedBatch) + Send + Sync,
{
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::sync_channel,
        Arc,
    };

    let (prep_tx, prep_rx) = sync_channel::<PreparedEmbedBatch>(prep_capacity);
    let (result_tx, result_rx) =
        sync_channel::<(PreparedEmbedBatch, Vec<(RetrievalKey, Vec<f32>)>)>(result_capacity);
    let first_error: parking_lot::Mutex<Option<KinDbError>> = parking_lot::Mutex::new(None);
    let error_ref = &first_error;
    let abandon_ref = &abandon;
    let aborting = Arc::new(AtomicBool::new(false));

    let total = std::thread::scope(move |scope| -> usize {
        // DRAIN + PREP: the single serial producer. Dropping `prep_tx` when this
        // thread ends tells the forward stage that no more batches will arrive.
        let drain_aborting = Arc::clone(&aborting);
        scope.spawn(move || {
            let mut drain_prep = drain_prep;
            let prep_tx = prep_tx;
            loop {
                if drain_aborting.load(Ordering::Acquire) {
                    break;
                }
                match drain_prep() {
                    Ok(Some(prepared)) => {
                        if drain_aborting.load(Ordering::Acquire) {
                            abandon_ref(prepared);
                            break;
                        }
                        if let Err(err) = prep_tx.send(prepared) {
                            abandon_ref(err.0);
                            break; // forward stage gone; stop producing.
                        }
                    }
                    Ok(None) => break, // queue drained.
                    Err(error) => {
                        drain_aborting.store(true, Ordering::Release);
                        let mut slot = error_ref.lock();
                        if slot.is_none() {
                            *slot = Some(error);
                        }
                        break;
                    }
                }
            }
        });

        // FORWARD: one batch at a time. Holds no graph lock; carries `prepared`
        // through so persist writes in the exact drained key order.
        let forward_aborting = Arc::clone(&aborting);
        scope.spawn(move || {
            let result_tx = result_tx;
            while let Ok(prepared) = prep_rx.recv() {
                if forward_aborting.load(Ordering::Acquire) {
                    abandon_ref(prepared);
                    continue;
                }
                match forward(prepared) {
                    Ok(pair) => {
                        if let Err(err) = result_tx.send(pair) {
                            forward_aborting.store(true, Ordering::Release);
                            let (prepared, _embedded) = err.0;
                            abandon_ref(prepared);
                            break; // persist consumer gone; stop forwarding.
                        }
                    }
                    Err(error) => {
                        forward_aborting.store(true, Ordering::Release);
                        let mut slot = error_ref.lock();
                        if slot.is_none() {
                            *slot = Some(error);
                        }
                        break;
                    }
                }
            }
            if forward_aborting.load(Ordering::Acquire) {
                while let Ok(prepared) = prep_rx.recv() {
                    abandon_ref(prepared);
                }
            }
        });

        // PERSIST: runs on this scope thread, consuming results in FIFO order.
        // The `while let` ends when the forward stage disconnects the channel.
        let mut persist = persist;
        let mut total = 0usize;
        while let Ok((prepared, embedded)) = result_rx.recv() {
            match persist(prepared, embedded) {
                Ok(count) => total += count,
                Err(error) => {
                    aborting.store(true, Ordering::Release);
                    let mut slot = error_ref.lock();
                    if slot.is_none() {
                        *slot = Some(error);
                    }
                    break;
                }
            }
        }
        if aborting.load(Ordering::Acquire) {
            while let Ok((prepared, _embedded)) = result_rx.recv() {
                abandon_ref(prepared);
            }
        }
        // Drop the receiver so a forward thread parked on a full result channel
        // unblocks, letting the scope join every stage without deadlocking.
        drop(result_rx);
        total
    });

    if let Some(error) = first_error.into_inner() {
        return Err(error);
    }
    Ok(total)
}

const TEXT_INDEX_IMPORT_SOURCE_WEIGHT: f32 = 1.4;
const TEXT_INDEX_NEIGHBOR_NAME_WEIGHT: f32 = 1.0;
#[cfg(all(feature = "embeddings", feature = "vector"))]
const MAX_EMBED_CONTEXT_VALUES_PER_LABEL: usize = 3;
const VERIFICATION_RELATION_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x6a5a6d56593e4f4fb6f6f2e1de3d4f99);

fn coverage_percent(indexed: usize, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (indexed as f64 / total as f64) * 100.0
}

#[derive(Debug, PartialEq)]
struct SemanticChangePayload {
    canonical_json: serde_json::Value,
    exact_float_bits: Vec<u32>,
}

fn record_change_float(
    change_id: SemanticChangeId,
    field: &str,
    value: f32,
    bits: &mut Vec<u32>,
) -> Result<(), KinDbError> {
    if !value.is_finite() {
        return Err(KinDbError::StorageError(format!(
            "semantic change {change_id} contains non-finite {field}; refusing an ambiguous immutable payload"
        )));
    }
    bits.push(value.to_bits());
    Ok(())
}

fn record_entity_float_bits(
    change_id: SemanticChangeId,
    entity: &Entity,
    field: &str,
    bits: &mut Vec<u32>,
) -> Result<(), KinDbError> {
    record_change_float(change_id, field, entity.fingerprint.stability_score, bits)
}

fn semantic_change_payload(change: &SemanticChange) -> Result<SemanticChangePayload, KinDbError> {
    // JSON Value gives the non-floating structure a map-order-insensitive
    // structural representation. Track every f32 separately by IEEE-754 bits so
    // `-0.0` cannot collapse into `0.0`; reject NaN/Infinity before JSON can
    // lose or refuse them. Together these form a lossless immutable-ID guard.
    let mut exact_float_bits = Vec::new();
    for delta in &change.entity_deltas {
        match delta {
            EntityDelta::Added { new: entity } => record_entity_float_bits(
                change.id,
                entity,
                "entity fingerprint stability score",
                &mut exact_float_bits,
            )?,
            EntityDelta::Modified { old, new } => {
                record_entity_float_bits(
                    change.id,
                    old,
                    "old entity fingerprint stability score",
                    &mut exact_float_bits,
                )?;
                record_entity_float_bits(
                    change.id,
                    new,
                    "new entity fingerprint stability score",
                    &mut exact_float_bits,
                )?;
            }
            EntityDelta::Removed { old } => record_entity_float_bits(
                change.id,
                old,
                "removed entity fingerprint stability score",
                &mut exact_float_bits,
            )?,
        }
    }
    for delta in &change.relation_deltas {
        match delta {
            RelationDelta::Added { new } => {
                record_change_float(
                    change.id,
                    "relation confidence",
                    new.confidence,
                    &mut exact_float_bits,
                )?;
            }
            RelationDelta::Modified { old, new } => {
                record_change_float(
                    change.id,
                    "old relation confidence",
                    old.confidence,
                    &mut exact_float_bits,
                )?;
                record_change_float(
                    change.id,
                    "new relation confidence",
                    new.confidence,
                    &mut exact_float_bits,
                )?;
            }
            RelationDelta::Removed { old } => {
                record_change_float(
                    change.id,
                    "removed relation confidence",
                    old.confidence,
                    &mut exact_float_bits,
                )?;
            }
        }
    }
    Ok(SemanticChangePayload {
        canonical_json: serde_json::to_value(change)?,
        exact_float_bits,
    })
}

fn repo_path_for_file_path(path: &FilePathId) -> Result<RepoPath, KinDbError> {
    RepoPath::from_utf8(&path.0).map_err(|error| {
        KinDbError::StorageError(format!("invalid repository path {}: {error}", path.0))
    })
}

fn file_path_for_repo_path(path: &RepoPath) -> Option<FilePathId> {
    path.as_utf8().map(FilePathId::new)
}

fn tree_state_error(error: TreeStateError) -> KinDbError {
    KinDbError::StorageError(format!("repository tree transition rejected: {error}"))
}

/// Order a change DAG parents-first, borrowing rather than copying it.
///
/// The order is what callers need; the change bodies are not theirs to own.
/// Taking them by value meant a caller with a whole history in hand cloned it
/// once to hand it over and this function cloned it a second time into the
/// ordered vector, so ordering a history cost two more copies of it than
/// existed before the call. Both callers here run at whole-repository scale
/// during a conversion, and on a mid-size repository each of those copies is
/// over a gigabyte held at the moment the working set is already largest.
fn topologically_order_changes<'a, I>(changes: I) -> Vec<&'a SemanticChange>
where
    I: IntoIterator<Item = (&'a SemanticChangeId, &'a SemanticChange)>,
{
    let changes: HashMap<SemanticChangeId, &'a SemanticChange> = changes
        .into_iter()
        .map(|(id, change)| (*id, change))
        .collect();

    let mut ids = changes.keys().copied().collect::<Vec<_>>();
    ids.sort_by_key(|id| id.to_string());

    let mut visited = HashSet::new();
    let mut ordered = Vec::with_capacity(ids.len());
    enum Frame<'a> {
        Visit(SemanticChangeId),
        Emit(&'a SemanticChange),
    }
    for id in ids {
        let mut stack = vec![Frame::Visit(id)];
        while let Some(frame) = stack.pop() {
            match frame {
                Frame::Visit(change_id) => {
                    if !visited.insert(change_id) {
                        continue;
                    }
                    let Some(change) = changes.get(&change_id).copied() else {
                        continue;
                    };
                    stack.push(Frame::Emit(change));
                    for parent in change.parents.iter().rev() {
                        stack.push(Frame::Visit(*parent));
                    }
                }
                Frame::Emit(change) => ordered.push(change),
            }
        }
    }
    ordered
}

/// The entity state one lineage carries into a change.
///
/// `live` names the entity each revision currently publishes; `ended` keeps the
/// revision a removal closed so a later re-add in the same lineage names its
/// real predecessor instead of starting a detached chain.
#[derive(Clone, Default)]
struct LineageEntities {
    live: HashMap<EntityId, (std::sync::Arc<Entity>, EntityRevisionId)>,
    ended: HashMap<EntityId, EntityRevisionId>,
}

fn push_entity_revision(
    revisions: &mut HashMap<EntityId, Vec<EntityRevision>>,
    entity: Entity,
    change_id: SemanticChangeId,
    supersedes: Option<EntityRevisionId>,
) -> EntityRevisionId {
    let entries = revisions.entry(entity.id).or_default();
    if let Some(superseded) = supersedes.and_then(|previous| {
        entries
            .iter_mut()
            .find(|revision| revision.revision_id == previous)
    }) {
        superseded.mark_ended(change_id);
    }
    let revision = EntityRevision::new(entity, change_id, supersedes);
    let revision_id = revision.revision_id;
    entries.push(revision);
    revision_id
}

/// Derive every entity revision the change DAG publishes.
///
/// Each change is read against its first declared parent, the same material
/// lineage `resolve_graph_at` replays. Replaying the whole DAG as one flat
/// topological sequence instead folds divergent siblings into a single state,
/// so a merge that restates its second parent's transition looks like a stale
/// payload even though every lineage reaching it is consistent. Preconditions
/// are still enforced against the state each change was authored on, so an old
/// payload no parent published still fails closed.
///
/// `ordered` must list parents before children.
fn derive_entity_revisions_across_history(
    ordered: Vec<&SemanticChange>,
) -> Result<HashMap<EntityId, Vec<EntityRevision>>, KinDbError> {
    let mut pending_children: HashMap<SemanticChangeId, usize> = HashMap::new();
    for change in &ordered {
        if let Some(parent) = change.parents.first() {
            *pending_children.entry(*parent).or_insert(0) += 1;
        }
    }

    let mut states: HashMap<SemanticChangeId, LineageEntities> = HashMap::new();
    let mut revisions: HashMap<EntityId, Vec<EntityRevision>> = HashMap::new();

    for change in ordered {
        let change_id = change.id;
        // The last child to read a parent takes ownership of its state, so a
        // linear history moves one map forward rather than copying the whole
        // live entity set per change.
        let mut state = match change.parents.first() {
            Some(parent) => match pending_children.get_mut(parent) {
                Some(remaining) if *remaining <= 1 => {
                    *remaining = 0;
                    states.remove(parent).unwrap_or_default()
                }
                Some(remaining) => {
                    *remaining -= 1;
                    states.get(parent).cloned().unwrap_or_default()
                }
                None => LineageEntities::default(),
            },
            None => LineageEntities::default(),
        };

        for delta in &change.entity_deltas {
            match delta {
                EntityDelta::Added { new: entity } => {
                    if state.live.contains_key(&entity.id) {
                        return Err(kin_model::ModelError::Conflict(format!(
                            "change {change_id} adds existing entity {}",
                            entity.id
                        ))
                        .into());
                    }
                    let supersedes = state.ended.remove(&entity.id);
                    let revision_id =
                        push_entity_revision(&mut revisions, entity.clone(), change_id, supersedes);
                    state.live.insert(
                        entity.id,
                        (std::sync::Arc::new(entity.clone()), revision_id),
                    );
                }
                EntityDelta::Modified { old, new } => {
                    if old.id != new.id {
                        return Err(kin_model::ModelError::Conflict(format!(
                            "change {change_id} modifies entity {} into different identity {}",
                            old.id, new.id
                        ))
                        .into());
                    }
                    let supersedes = match state.live.get(&old.id) {
                        Some((live, revision_id)) if live.as_ref() == old => *revision_id,
                        _ => {
                            return Err(kin_model::ModelError::Conflict(format!(
                                "change {change_id} has stale old payload for entity {}",
                                old.id
                            ))
                            .into())
                        }
                    };
                    let revision_id = push_entity_revision(
                        &mut revisions,
                        new.clone(),
                        change_id,
                        Some(supersedes),
                    );
                    state
                        .live
                        .insert(new.id, (std::sync::Arc::new(new.clone()), revision_id));
                }
                EntityDelta::Removed { old } => {
                    let ended = match state.live.get(&old.id) {
                        Some((live, revision_id)) if live.as_ref() == old => *revision_id,
                        _ => {
                            return Err(kin_model::ModelError::Conflict(format!(
                                "change {change_id} has stale old payload for removed entity {}",
                                old.id
                            ))
                            .into())
                        }
                    };
                    if let Some(revision) = revisions.get_mut(&old.id).and_then(|entries| {
                        entries
                            .iter_mut()
                            .find(|revision| revision.revision_id == ended)
                    }) {
                        revision.mark_ended(change_id);
                    }
                    state.live.remove(&old.id);
                    state.ended.insert(old.id, ended);
                }
            }
        }

        // A change no other change builds on has no reader left, so its state
        // is dropped here instead of being retained for the whole derivation.
        if pending_children
            .get(&change_id)
            .is_some_and(|remaining| *remaining > 0)
        {
            states.insert(change_id, state);
        }
    }

    Ok(revisions)
}

fn find_artifact_revision<'a>(
    changes: impl IntoIterator<Item = (&'a SemanticChangeId, &'a SemanticChange)>,
    target: ArtifactRevisionId,
) -> Option<ArtifactRevision> {
    let mut active_by_change =
        HashMap::<SemanticChangeId, HashMap<ArtifactId, ArtifactRevisionId>>::new();
    for change in topologically_order_changes(changes) {
        let mut active = change
            .parents
            .first()
            .and_then(|parent| active_by_change.get(parent))
            .cloned()
            .unwrap_or_default();
        for delta in &change.tree_deltas {
            let artifact_id = delta.artifact_id();
            let Some(located) = delta.new_state() else {
                active.remove(&artifact_id);
                continue;
            };
            let mut predecessors = Vec::new();
            for parent in &change.parents {
                let Some(predecessor) = active_by_change
                    .get(parent)
                    .and_then(|parent_active| parent_active.get(&artifact_id))
                    .copied()
                else {
                    continue;
                };
                if !predecessors.contains(&predecessor) {
                    predecessors.push(predecessor);
                }
            }
            let revision = ArtifactRevision::new(
                artifact_id,
                located.path.clone(),
                located.entry,
                change.id,
                predecessors,
            );
            active.insert(artifact_id, revision.revision_id);
            if revision.revision_id == target {
                return Some(revision);
            }
        }
        active_by_change.insert(change.id, active);
    }
    None
}

fn entity_matches_revision(left: &Entity, right: &Entity) -> bool {
    left.id == right.id
        && left.kind == right.kind
        && left.name == right.name
        && left.language == right.language
        && left.fingerprint.ast_hash == right.fingerprint.ast_hash
        && left.fingerprint.signature_hash == right.fingerprint.signature_hash
        && left.fingerprint.behavior_hash == right.fingerprint.behavior_hash
        && left.file_origin == right.file_origin
        && left.span == right.span
        && left.signature == right.signature
        && left.visibility == right.visibility
        && left.role == right.role
        && left.doc_summary == right.doc_summary
        && left.metadata.extra == right.metadata.extra
        && left.lineage_parent == right.lineage_parent
}

fn lookup_entity_revision_id(
    revisions: &HashMap<EntityId, Vec<EntityRevision>>,
    entity: &Entity,
) -> Option<EntityRevisionId> {
    revisions
        .get(&entity.id)
        .and_then(|entries| {
            entries
                .iter()
                .rev()
                .find(|revision| entity_matches_revision(&revision.entity, entity))
        })
        .map(|revision| revision.revision_id)
}

/// Whether `entity`'s content matches the most recent recorded revision for its
/// id. Re-importing unchanged content (re-init mints a fresh change id, so the
/// deltas arrive again) must not append a redundant revision generation — that
/// is what bloated the graph and the vector index across re-init cycles.
fn entity_unchanged_since_last_revision(ent: &EntityData, entity: &Entity) -> bool {
    ent.entity_revisions
        .get(&entity.id)
        .and_then(|revs| revs.last())
        .is_some_and(|last| entity_matches_revision(&last.entity, entity))
}

/// One entity's revision-chain advance: the entity that gained a new HEAD
/// generation, and the HEAD id that advance superseded (`None` when the chain
/// had no prior generation).
///
/// Both halves are retrieval facts. The superseded id names a vector that is no
/// longer truth and must be evicted; the entity id names a revision key that
/// just entered truth and therefore needs a vector. Returning them together is
/// what keeps the two sides from drifting apart, which is exactly how a commit
/// used to retire coverage it never replaced.
type RevisionAdvance = (EntityId, Option<EntityRevisionId>);

/// Apply a change's entity deltas to the revision chains, returning one
/// [`RevisionAdvance`] per entity that gained a new generation.
///
/// The superseded HEAD ids let `prune_orphaned_vectors` evict exactly the
/// orphaned set without rescanning the whole index. The entity ids let
/// [`InMemoryGraph::admit_minted_revision_vectors`] give the newly-minted HEAD
/// revision keys a vector, since `graph_truth_retrievable_keys` starts counting
/// them as coverage the instant this function returns.
fn append_entity_revisions(ent: &mut EntityData, change: &SemanticChange) -> Vec<RevisionAdvance> {
    let mut advances = Vec::new();
    for delta in &change.entity_deltas {
        match delta {
            EntityDelta::Added { new: entity } => {
                if entity_unchanged_since_last_revision(ent, entity) {
                    continue;
                }
                let chain = ent.entity_revisions.entry(entity.id).or_default();
                advances.push((entity.id, chain.last().map(|prev| prev.revision_id)));
                chain.push(EntityRevision::new(entity.clone(), change.id, None));
            }
            EntityDelta::Modified { old, new } => {
                if entity_unchanged_since_last_revision(ent, new) {
                    continue;
                }
                let previous_revision = lookup_entity_revision_id(&ent.entity_revisions, old);
                let chain = ent.entity_revisions.entry(new.id).or_default();
                advances.push((new.id, chain.last().map(|prev| prev.revision_id)));
                chain.push(EntityRevision::new(
                    new.clone(),
                    change.id,
                    previous_revision,
                ));
            }
            EntityDelta::Removed { .. } => {}
        }
    }
    advances
}

/// The prior HEAD revision ids in a set of advances: the vectors this change
/// orphaned.
fn superseded_revision_ids(advances: &[RevisionAdvance]) -> Vec<EntityRevisionId> {
    advances
        .iter()
        .filter_map(|(_, superseded)| *superseded)
        .collect()
}

/// A revision key that entered graph truth in this change, with the key whose
/// vector can be carried onto it when the two format to byte-identical embed
/// text.
#[cfg(feature = "vector")]
#[derive(Debug, Clone, Copy)]
struct MintedRevision {
    /// The new HEAD revision key, now counted by
    /// `graph_truth_retrievable_keys` and therefore owed a vector.
    key: RetrievalKey,
    /// The revision key holding the vector this one can reuse verbatim.
    carry_from: Option<RetrievalKey>,
}

/// Decide, for every entity that gained a generation, whether its new HEAD
/// revision key can reuse the superseded generation's vector.
///
/// A revision key embeds `format_graph_entity_text(&rev.entity)` with no
/// neighborhood context (see `prepare_pending_embedding_batch`), so byte
/// equality of that formatting is the whole criterion — not a heuristic, and
/// not the fingerprint triple, which can agree while the formatted text does
/// not. Sorted by key so the resulting index upsert order does not depend on
/// delta order, matching the determinism the rest of the vector path keeps.
#[cfg(feature = "vector")]
fn plan_minted_revision_vectors(
    ent: &EntityData,
    advances: &[RevisionAdvance],
) -> Vec<MintedRevision> {
    let mut minted: Vec<MintedRevision> = advances
        .iter()
        .filter_map(|(entity_id, _)| {
            let chain = ent.entity_revisions.get(entity_id)?;
            let head = chain.last()?;
            let carry_from = chain
                .len()
                .checked_sub(2)
                .and_then(|index| chain.get(index))
                .filter(|prev| {
                    crate::embed::format_graph_entity_text(&prev.entity)
                        == crate::embed::format_graph_entity_text(&head.entity)
                })
                .map(|prev| RetrievalKey::EntityRevision(prev.revision_id));
            Some(MintedRevision {
                key: RetrievalKey::EntityRevision(head.revision_id),
                carry_from,
            })
        })
        .collect();
    minted.sort_unstable_by_key(|entry| entry.key);
    minted
}

/// The most recent (HEAD) revision id of every LIVE entity's revision chain.
///
/// `append_entity_revisions` pushes each new generation to the end of the
/// chain, so `revs.last()` is the live revision. Two exclusions keep this the
/// retrieval-truth set rather than the history set:
///
/// - Superseded generations. The vector index tracks at most one revision
///   vector per live entity; a superseded generation that a live re-embed
///   leaves behind is an orphan to reclaim, not retrieval truth that semantic
///   search should return as a second hit for the same entity.
/// - Chains whose owning entity the graph no longer holds. Whole-history
///   ingest derives a revision chain for every entity that ever existed, and
///   removing an entity ends its chain without deleting it, so a repository
///   with real history carries many chains keyed by ids absent from
///   `ent.entities`. Such a chain's head resolves only to a snapshot of a
///   dead entity: a vector under its key can never be served, retrieval must
///   drop it, and every drop is reported as a degradation. Admitting those
///   heads as truth made a freshly embedded store rank and drop them on every
///   query while the prune kept their vectors forever.
///
/// This is the single authority for "which revision keys are current", shared
/// by the prune target and the embedding-queue backfill so the two never
/// disagree (a disagreement would make the backfill re-embed a key the prune
/// immediately evicts, churning forever).
#[cfg(feature = "vector")]
fn latest_revision_ids(ent: &EntityData) -> impl Iterator<Item = EntityRevisionId> + '_ {
    ent.entity_revisions
        .iter()
        .filter(|(id, _)| ent.entities.contains_key(*id))
        .filter_map(|(_, revs)| revs.last().map(|rev| rev.revision_id))
}

fn entity_ids_for_relation(relation: &Relation) -> Vec<EntityId> {
    [relation.src.as_entity(), relation.dst.as_entity()]
        .into_iter()
        .flatten()
        .collect()
}

fn sorted_unique_entity_ids<I>(ids: I) -> Vec<EntityId>
where
    I: IntoIterator<Item = EntityId>,
{
    let mut ids: Vec<EntityId> = ids.into_iter().collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn relation_is_entity_only(relation: &Relation) -> bool {
    relation.src.as_entity().is_some() && relation.dst.as_entity().is_some()
}

/// Whether a modified entity would embed to byte-identical text.
///
/// An entity re-embeds iff the text that would be embedded for it changed.
/// That is narrower than "the entity payload changed": a transaction stamps
/// every entity in an edited file with the file's new blob hash and advances
/// the spans below an insertion, so a one-line comment produces a `Modified`
/// delta for every entity the file declares while leaving nearly all of their
/// embed text untouched. Those payload fields are real provenance and must
/// advance, but none of them reaches [`format_graph_entity_text`], so keying
/// invalidation on the formatted text keeps provenance whole while re-embedding
/// only what an embedder would actually read differently.
///
/// The comparison deliberately excludes graph-derived context lines. Those come
/// from the neighborhood at embed time, and every transition that changes them
/// arrives as a relation delta, which invalidates both endpoints on its own.
///
/// That relation-delta guarantee is a producer contract, not an engine one:
/// today's delta builders retire an entity's id on rename, so a neighbor whose
/// context line quotes the old name always sees relation rewrites in the same
/// transaction. A producer that instead emitted `Modified` with a changed name
/// under the SAME id, and no relation deltas, would leave skipped neighbors
/// holding context lines that quote the old name until something else
/// invalidates them. Any such producer must expand invalidation to the renamed
/// entity's graph neighbors itself.
#[cfg(feature = "vector")]
fn entity_embedding_text_unchanged(old: &Entity, new: &Entity) -> bool {
    crate::embed::format_graph_entity_text(old) == crate::embed::format_graph_entity_text(new)
}

/// Without the vector feature nothing is embedded, so nothing can be skipped
/// and the formatting work is not worth doing.
#[cfg(not(feature = "vector"))]
fn entity_embedding_text_unchanged(_old: &Entity, _new: &Entity) -> bool {
    false
}

fn entity_neighbor_for_relation(relation: &Relation, entity_id: &EntityId) -> Option<EntityId> {
    let current = GraphNodeId::Entity(*entity_id);
    if relation.src == current {
        relation.dst.as_entity()
    } else if relation.dst == current {
        relation.src.as_entity()
    } else {
        None
    }
}

fn collect_entity_refresh_targets(ent: &EntityData, seed_ids: &[EntityId]) -> Vec<EntityId> {
    let mut targets = HashSet::new();

    for entity_id in seed_ids {
        if ent.entities.contains_key(entity_id) {
            targets.insert(*entity_id);
        }

        for relation_id in ent.outgoing.get(entity_id).into_iter().flatten() {
            let Some(relation) = ent.relations.get(relation_id) else {
                continue;
            };
            let Some(neighbor_id) = entity_neighbor_for_relation(relation, entity_id) else {
                continue;
            };
            if ent.entities.contains_key(&neighbor_id) {
                targets.insert(neighbor_id);
            }
        }

        for relation_id in ent.incoming.get(entity_id).into_iter().flatten() {
            let Some(relation) = ent.relations.get(relation_id) else {
                continue;
            };
            let Some(neighbor_id) = entity_neighbor_for_relation(relation, entity_id) else {
                continue;
            };
            if ent.entities.contains_key(&neighbor_id) {
                targets.insert(neighbor_id);
            }
        }
    }

    targets.into_iter().collect()
}

fn insert_relation_indexes(ent: &mut EntityData, relation: &Relation) {
    ent.node_outgoing
        .entry(relation.src)
        .or_default()
        .push(relation.id);
    ent.node_incoming
        .entry(relation.dst)
        .or_default()
        .push(relation.id);
    if let Some(src) = relation.src.as_entity() {
        ent.outgoing.entry(src).or_default().push(relation.id);
    }
    if let Some(dst) = relation.dst.as_entity() {
        ent.incoming.entry(dst).or_default().push(relation.id);
    }
}

fn remove_relation_indexes(ent: &mut EntityData, relation: &Relation) {
    if let Some(out) = ent.node_outgoing.get_mut(&relation.src) {
        out.retain(|rid| *rid != relation.id);
        if out.is_empty() {
            ent.node_outgoing.remove(&relation.src);
        }
    }
    if let Some(inc) = ent.node_incoming.get_mut(&relation.dst) {
        inc.retain(|rid| *rid != relation.id);
        if inc.is_empty() {
            ent.node_incoming.remove(&relation.dst);
        }
    }
    if let Some(src) = relation.src.as_entity() {
        if let Some(out) = ent.outgoing.get_mut(&src) {
            out.retain(|rid| *rid != relation.id);
            if out.is_empty() {
                ent.outgoing.remove(&src);
            }
        }
    }
    if let Some(dst) = relation.dst.as_entity() {
        if let Some(inc) = ent.incoming.get_mut(&dst) {
            inc.retain(|rid| *rid != relation.id);
            if inc.is_empty() {
                ent.incoming.remove(&dst);
            }
        }
    }
}

fn build_relation_indexes(
    relations: &HashMap<RelationId, Relation>,
) -> (
    HashMap<EntityId, Vec<RelationId>>,
    HashMap<EntityId, Vec<RelationId>>,
    HashMap<GraphNodeId, Vec<RelationId>>,
    HashMap<GraphNodeId, Vec<RelationId>>,
) {
    let mut outgoing: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
    let mut incoming: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
    let mut node_outgoing: HashMap<GraphNodeId, Vec<RelationId>> = HashMap::new();
    let mut node_incoming: HashMap<GraphNodeId, Vec<RelationId>> = HashMap::new();

    for relation in relations.values() {
        node_outgoing
            .entry(relation.src)
            .or_default()
            .push(relation.id);
        node_incoming
            .entry(relation.dst)
            .or_default()
            .push(relation.id);
        if let Some(src) = relation.src.as_entity() {
            outgoing.entry(src).or_default().push(relation.id);
        }
        if let Some(dst) = relation.dst.as_entity() {
            incoming.entry(dst).or_default().push(relation.id);
        }
    }

    (outgoing, incoming, node_outgoing, node_incoming)
}

/// Whether a snapshot load reused the persisted entity-level adjacency or had
/// to rebuild it from `relations`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdjacencyReuse {
    /// The persisted `outgoing`/`incoming` maps were consistent with
    /// `relations` and were moved into the graph as-is (no rebuild).
    Reused,
    /// The persisted adjacency was missing or inconsistent, so the entity-level
    /// maps were rebuilt from `relations`.
    Rebuilt,
}

/// Build the relation adjacency indexes for a freshly loaded snapshot, reusing
/// the persisted entity-level `outgoing`/`incoming` maps when they are
/// consistent with `relations`.
///
/// The snapshot persists the entity-level adjacency (`outgoing`/`incoming`) but
/// historically `from_snapshot_inner` threw it away and rebuilt all four
/// adjacency maps from `relations` on every boot. This helper instead:
///
///   1. Always derives the node-level maps (`node_outgoing`/`node_incoming`)
///      from `relations` — those are keyed by `GraphNodeId` and are NOT
///      persisted, so they cannot be reused.
///   2. In that same single pass, tallies how many entity-keyed edges
///      `relations` implies.
///   3. If the persisted `outgoing`/`incoming` edge tallies match, the
///      persisted maps are trusted and moved in without reallocating or
///      re-hashing every entity key — the boot-time win. Otherwise (old
///      snapshot with no persisted adjacency, or an inconsistent one) the
///      entity-level maps are rebuilt from `relations` so a stale/missing
///      persisted adjacency can never yield an inconsistent in-memory graph.
///
/// Trust boundary: the snapshot body is SHA-256 checksum-verified before this
/// runs (see `GraphSnapshot::from_bytes`), and the writer maintains these maps
/// in lockstep with `relations`, so an edge-count match is a sound validity
/// signal — corruption is caught upstream and a writer that desynced the maps
/// would already have corrupted the live graph before saving.
pub(crate) fn build_relation_indexes_with_reuse(
    relations: &HashMap<RelationId, Relation>,
    persisted_outgoing: HashMap<EntityId, Vec<RelationId>>,
    persisted_incoming: HashMap<EntityId, Vec<RelationId>>,
) -> (
    HashMap<EntityId, Vec<RelationId>>,
    HashMap<EntityId, Vec<RelationId>>,
    HashMap<GraphNodeId, Vec<RelationId>>,
    HashMap<GraphNodeId, Vec<RelationId>>,
    AdjacencyReuse,
) {
    let mut node_outgoing: HashMap<GraphNodeId, Vec<RelationId>> = HashMap::new();
    let mut node_incoming: HashMap<GraphNodeId, Vec<RelationId>> = HashMap::new();
    let mut expected_outgoing_edges: usize = 0;
    let mut expected_incoming_edges: usize = 0;

    for relation in relations.values() {
        node_outgoing
            .entry(relation.src)
            .or_default()
            .push(relation.id);
        node_incoming
            .entry(relation.dst)
            .or_default()
            .push(relation.id);
        if relation.src.as_entity().is_some() {
            expected_outgoing_edges += 1;
        }
        if relation.dst.as_entity().is_some() {
            expected_incoming_edges += 1;
        }
    }

    let persisted_outgoing_edges: usize = persisted_outgoing.values().map(Vec::len).sum();
    let persisted_incoming_edges: usize = persisted_incoming.values().map(Vec::len).sum();

    if persisted_outgoing_edges == expected_outgoing_edges
        && persisted_incoming_edges == expected_incoming_edges
    {
        // Persisted entity-level adjacency is consistent with the loaded
        // relations — reuse it directly instead of rebuilding.
        (
            persisted_outgoing,
            persisted_incoming,
            node_outgoing,
            node_incoming,
            AdjacencyReuse::Reused,
        )
    } else {
        // Stale / missing / inconsistent persisted adjacency — rebuild the
        // entity-level maps from relations so the in-memory graph is correct.
        let mut outgoing: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        let mut incoming: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        for relation in relations.values() {
            if let Some(src) = relation.src.as_entity() {
                outgoing.entry(src).or_default().push(relation.id);
            }
            if let Some(dst) = relation.dst.as_entity() {
                incoming.entry(dst).or_default().push(relation.id);
            }
        }
        (
            outgoing,
            incoming,
            node_outgoing,
            node_incoming,
            AdjacencyReuse::Rebuilt,
        )
    }
}

fn verification_relation_id(kind: RelationKind, src: GraphNodeId, dst: GraphNodeId) -> RelationId {
    let payload = format!("{kind:?}|{src}|{dst}");
    RelationId(uuid::Uuid::new_v5(
        &VERIFICATION_RELATION_NAMESPACE,
        payload.as_bytes(),
    ))
}

fn verification_relation(kind: RelationKind, src: GraphNodeId, dst: GraphNodeId) -> Relation {
    Relation {
        id: verification_relation_id(kind, src, dst),
        kind,
        src,
        dst,
        confidence: 1.0,
        origin: RelationOrigin::Inferred,
        created_in: None,
        import_source: None,
        evidence: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Embedding status
// ---------------------------------------------------------------------------

/// Progress of the background embedding pipeline.
///
/// `pending` reports outstanding embedding work, defined as
/// `max(queue_length, total - indexed)`. `total` covers retrievable graph
/// objects that participate in semantic embedding: current entities,
/// historical entity revisions, and current artifacts. This deliberately covers
/// both queued-but-unembedded work and unindexed objects that have not yet been
/// queued (the latter is the steady state after loading a graph whose embedding
/// queues do not persist across restarts). Coverage gates that only inspect this
/// field stay correct without also reading `indexed` and `total`. Callers that
/// need the raw runtime queue length specifically should use
/// [`InMemoryGraph::pending_embeddings`] and
/// [`InMemoryGraph::pending_artifact_embeddings`] instead.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EmbeddingStatus {
    /// Outstanding embedding work: `max(queue_length, total - indexed)`.
    pub pending: usize,
    /// Retrievable graph objects currently in the HNSW vector index.
    pub indexed: usize,
    /// Total retrievable graph objects that require embeddings.
    pub total: usize,
}

/// Outcome counts from reconciling a salvaged vector sidecar against current
/// graph truth (see [`InMemoryGraph::reconcile_salvaged_vector_index`]).
#[cfg(feature = "vector")]
#[derive(Debug, Clone, Copy, Default)]
pub struct VectorSalvageStats {
    /// Keys retained in the index and now serving.
    pub retained: usize,
    /// Keys evicted because they are no longer in graph truth at all
    /// (superseded generations, dead chains, retired artifacts).
    pub evicted_orphans: usize,
    /// Artifact head keys retired because a stamp drift cannot prove their
    /// content identity per key.
    pub retired_artifact_vectors: usize,
    /// Entity head keys retired because the entity's current head revision has
    /// no vector, so the head vector predates the entity's current content.
    pub retired_stale_entity_heads: usize,
}

/// Graph-owned object resolved from a retrieval key.
#[derive(Debug, Clone)]
pub enum ResolvedRetrievalItem {
    Entity(Entity),
    ShallowFile(ShallowTrackedFile),
    StructuredArtifact(StructuredArtifact),
    OpaqueArtifact(OpaqueArtifact),
}

impl ResolvedRetrievalItem {
    pub fn file_path(&self) -> Option<FilePathId> {
        match self {
            Self::Entity(entity) => entity.file_origin.clone(),
            Self::ShallowFile(file) => Some(file.file_id.clone()),
            Self::StructuredArtifact(artifact) => Some(artifact.file_id.clone()),
            Self::OpaqueArtifact(artifact) => Some(artifact.file_id.clone()),
        }
    }
}

// ---------------------------------------------------------------------------
// Domain sub-stores
// ---------------------------------------------------------------------------

/// Core entity/relation graph data.
#[derive(Clone)]
struct EntityData {
    entities: HashMap<EntityId, Entity>,
    entity_revisions: HashMap<EntityId, Vec<EntityRevision>>,
    external_references: HashMap<ExternalReferenceId, ExternalReference>,
    relations: HashMap<RelationId, Relation>,
    /// Entity → outgoing relation IDs (entity's dependencies).
    outgoing: HashMap<EntityId, Vec<RelationId>>,
    /// Entity → incoming relation IDs (entity's callers/dependents).
    incoming: HashMap<EntityId, Vec<RelationId>>,
    /// Mixed-node outgoing adjacency used by Phase 9 traversal.
    node_outgoing: HashMap<GraphNodeId, Vec<RelationId>>,
    /// Mixed-node incoming adjacency used by Phase 9 traversal.
    node_incoming: HashMap<GraphNodeId, Vec<RelationId>>,
    /// Secondary indexes for fast lookup.
    indexes: IndexSet,
    /// Exact graph-owned repository tree and artifact identity authority.
    resolved_tree: ResolvedTree,
    /// Shallow file tracking (C2 tier).
    shallow_files: HashMap<FilePathId, ShallowTrackedFile>,
    /// Persisted file layouts for projection.
    file_layouts: HashMap<FilePathId, FileLayout>,
    /// Structured artifact tracking (C1 tier).
    structured_artifacts: HashMap<FilePathId, StructuredArtifact>,
    /// Opaque artifact tracking (C0 tier).
    opaque_artifacts: HashMap<FilePathId, OpaqueArtifact>,
}

impl GraphHashSource for EntityData {
    fn hash_entity(&self, id: &EntityId) -> Option<&Entity> {
        self.entities.get(id)
    }
    fn hash_relation(&self, id: &RelationId) -> Option<&Relation> {
        self.relations.get(id)
    }
    fn hash_outgoing(&self, id: &EntityId) -> Option<&[RelationId]> {
        self.outgoing.get(id).map(|v| v.as_slice())
    }
    fn hash_incoming(&self, id: &EntityId) -> Option<&[RelationId]> {
        self.incoming.get(id).map(|v| v.as_slice())
    }
    fn hash_entity_ids(&self) -> Vec<EntityId> {
        self.entities.keys().copied().collect()
    }
    fn hash_entity_count(&self) -> usize {
        self.entities.len()
    }
}

/// Semantic change DAG. Named refs are repository authority, not graph state.
#[derive(Clone)]
struct ChangeData {
    changes: HashMap<SemanticChangeId, SemanticChange>,
    /// Parent → children in the change DAG.
    change_children: HashMap<SemanticChangeId, Vec<SemanticChangeId>>,
}

/// Work items, annotations, links.
#[derive(Clone)]
struct WorkData {
    work_items: HashMap<WorkId, WorkItem>,
    annotations: HashMap<AnnotationId, Annotation>,
    work_links: Vec<WorkLink>,
}

/// Reviews, decisions, notes, discussions, assignments.
#[derive(Clone)]
struct ReviewData {
    reviews: HashMap<ReviewId, Review>,
    review_decisions: HashMap<ReviewId, Vec<ReviewDecision>>,
    review_notes: HashMap<ReviewNoteId, ReviewNote>,
    review_discussions: HashMap<ReviewDiscussionId, ReviewDiscussion>,
    review_assignments: HashMap<ReviewId, Vec<ReviewAssignment>>,
}

/// Verification: tests, coverage, contracts.
#[derive(Clone)]
struct VerificationData {
    test_cases: HashMap<TestId, TestCase>,
    assertions: HashMap<AssertionId, Assertion>,
    verification_runs: HashMap<VerificationRunId, VerificationRun>,
    mock_hints: Vec<MockHint>,
    contracts: HashMap<ContractId, Contract>,
}

/// Provenance: actors, delegations, approvals, audit.
#[derive(Clone)]
struct ProvenanceData {
    actors: HashMap<ActorId, Actor>,
    delegations: Vec<Delegation>,
    approvals: Vec<Approval>,
    audit_events: Vec<AuditEvent>,
}

/// Session/intent state (daemon).
#[derive(Clone)]
struct SessionData {
    sessions: HashMap<SessionId, AgentSession>,
    intents: HashMap<IntentId, Intent>,
    downstream_warnings: Vec<(IntentId, EntityId, String)>,
}

#[derive(Debug)]
struct PendingGraphDelta {
    delta: GraphSnapshotDelta,
    next_persistence_epoch: u64,
    in_flight_persistence: HashSet<u64>,
}

impl Default for PendingGraphDelta {
    fn default() -> Self {
        Self {
            delta: GraphSnapshotDelta::empty(0),
            next_persistence_epoch: 1,
            in_flight_persistence: HashSet::new(),
        }
    }
}

impl PendingGraphDelta {
    fn begin_persistence(&mut self) -> PersistenceEpoch {
        let mut epoch = self.next_persistence_epoch.max(1);
        while self.in_flight_persistence.contains(&epoch) {
            epoch = epoch.wrapping_add(1).max(1);
        }
        self.next_persistence_epoch = epoch.wrapping_add(1).max(1);
        self.in_flight_persistence.insert(epoch);
        PersistenceEpoch(epoch)
    }
}

/// Opaque acknowledgement token for one detached persistence batch.
///
/// Starting persistence atomically detaches the mutations captured by that
/// write. Mutations arriving while backend I/O is in flight accumulate in a
/// fresh buffer and therefore cannot be cleared by the older write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistenceEpoch(u64);

/// Whole-millisecond lap timer for one decomposed phase summary.
///
/// Each lap returns the milliseconds since the previous lap, so a summary event
/// carries one field per phase and the fields sum to the wall clock within
/// rounding.
struct PublicationPhaseTimer {
    last: std::time::Instant,
}

impl PublicationPhaseTimer {
    fn start() -> Self {
        Self {
            last: std::time::Instant::now(),
        }
    }

    fn lap_ms(&mut self) -> u128 {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_millis();
        self.last = now;
        elapsed
    }
}

/// Installing one immutable change into the live graph is O(change) work behind
/// three lock acquisitions. Past this bound the cost is not the change, so the
/// event names which term paid it.
const SLOW_CHANGE_INSTALL: std::time::Duration = std::time::Duration::from_millis(250);

fn delta_map_upsert<K, V>(delta: &mut CollectionDelta<K, V>, key: K, value: V)
where
    K: Eq + Clone,
    V: Clone,
{
    delta.removed.retain(|removed| removed != &key);
    if let Some((_, existing)) = delta
        .added
        .iter_mut()
        .find(|(existing_key, _)| existing_key == &key)
    {
        *existing = value;
        return;
    }
    if let Some((_, existing)) = delta
        .modified
        .iter_mut()
        .find(|(existing_key, _)| existing_key == &key)
    {
        *existing = value;
        return;
    }
    delta.modified.push((key, value));
}

#[derive(Clone, Copy)]
enum DeltaMapSlot {
    Added(usize),
    Modified(usize),
}

/// Apply many map-delta upserts with one key-to-slot index build.
///
/// `delta_map_upsert` deliberately preserves the first vector position for a
/// key, but finding that position with a linear scan for every item makes a
/// history-sized batch quadratic. This helper indexes the existing `added` and
/// `modified` slots once, retains the same added-before-modified lookup
/// semantics, and removes restored keys from `removed` in one stable pass.
fn delta_map_upsert_batch<K, V>(delta: &mut CollectionDelta<K, V>, updates: Vec<(K, V)>)
where
    K: Eq + std::hash::Hash + Clone,
{
    if updates.is_empty() {
        return;
    }

    let mut slots =
        HashMap::with_capacity(delta.added.len() + delta.modified.len() + updates.len());
    for (index, (key, _)) in delta.added.iter().enumerate() {
        slots
            .entry(key.clone())
            .or_insert(DeltaMapSlot::Added(index));
    }
    for (index, (key, _)) in delta.modified.iter().enumerate() {
        slots
            .entry(key.clone())
            .or_insert(DeltaMapSlot::Modified(index));
    }

    let mut restored = HashSet::with_capacity(updates.len());
    for (key, value) in updates {
        restored.insert(key.clone());
        match slots.get(&key).copied() {
            Some(DeltaMapSlot::Added(index)) => delta.added[index].1 = value,
            Some(DeltaMapSlot::Modified(index)) => delta.modified[index].1 = value,
            None => {
                let index = delta.modified.len();
                delta.modified.push((key.clone(), value));
                slots.insert(key, DeltaMapSlot::Modified(index));
            }
        }
    }

    // `retain` preserves the relative order of every unrelated removal, exactly
    // matching repeated `delta_map_upsert` calls without rescanning the vector.
    delta.removed.retain(|key| !restored.contains(key));
}

fn delta_map_remove<K, V>(delta: &mut CollectionDelta<K, V>, key: K)
where
    K: Eq + Clone,
{
    delta.added.retain(|(existing_key, _)| existing_key != &key);
    delta
        .modified
        .retain(|(existing_key, _)| existing_key != &key);
    if !delta.removed.iter().any(|removed| removed == &key) {
        delta.removed.push(key);
    }
}

fn delta_external_reference_add(
    delta: &mut CollectionDelta<ExternalReferenceId, ExternalReference>,
    reference: ExternalReference,
) {
    debug_assert!(delta.modified.is_empty());
    if let Some(position) = delta
        .removed
        .iter()
        .position(|removed| *removed == reference.id)
    {
        // The immutable record existed in the persistence base and was
        // removed earlier in this pending batch. Re-adding the same stable ID
        // restores the base state and cancels that removal.
        delta.removed.remove(position);
        return;
    }
    debug_assert!(!delta
        .added
        .iter()
        .any(|(existing, _)| *existing == reference.id));
    delta.added.push((reference.id, reference));
}

fn delta_external_reference_remove(
    delta: &mut CollectionDelta<ExternalReferenceId, ExternalReference>,
    id: ExternalReferenceId,
) {
    debug_assert!(delta.modified.is_empty());
    let before = delta.added.len();
    delta.added.retain(|(existing, _)| *existing != id);
    if delta.added.len() != before {
        // The record did not exist in the persistence base; adding and then
        // removing it inside one pending batch is a net no-op.
        return;
    }
    if !delta.removed.contains(&id) {
        delta.removed.push(id);
    }
}

fn delta_values_equal<V>(left: &V, right: &V) -> bool
where
    V: serde::Serialize,
{
    match (rmp_serde::to_vec(left), rmp_serde::to_vec(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn delta_vec_upsert_by_key<K, V, F>(delta: &mut VecDelta<V>, old: Option<V>, new: V, key_of: F)
where
    K: Eq,
    V: Clone + serde::Serialize,
    F: Fn(&V) -> K,
{
    let new_key = key_of(&new);
    delta.added.retain(|existing| key_of(existing) != new_key);

    let mut restored_base = false;
    delta.removed.retain(|removed| {
        if key_of(removed) != new_key {
            return true;
        }
        if delta_values_equal(removed, &new) {
            restored_base = true;
            false
        } else {
            true
        }
    });
    if restored_base {
        return;
    }

    if let Some(old) = old {
        if delta_values_equal(&old, &new) {
            return;
        }
        if !delta
            .removed
            .iter()
            .any(|removed| key_of(removed) == new_key)
        {
            delta.removed.push(old);
        }
    }
    delta.added.push(new);
}

fn delta_vec_remove_by_key<K, V, F>(delta: &mut VecDelta<V>, old: Option<V>, key: K, key_of: F)
where
    K: Eq,
    V: Clone,
    F: Fn(&V) -> K,
{
    let mut had_pending_add = false;
    delta.added.retain(|existing| {
        if key_of(existing) == key {
            had_pending_add = true;
            false
        } else {
            true
        }
    });
    if had_pending_add {
        return;
    }
    if let Some(old) = old {
        if !delta.removed.iter().any(|removed| key_of(removed) == key) {
            delta.removed.push(old);
        }
    }
}

fn record_edge_list_delta(pending: &mut PendingGraphDelta, ent: &EntityData, entity_id: EntityId) {
    match ent.outgoing.get(&entity_id).cloned() {
        Some(outgoing) => delta_map_upsert(&mut pending.delta.outgoing, entity_id, outgoing),
        None => delta_map_remove(&mut pending.delta.outgoing, entity_id),
    }
    match ent.incoming.get(&entity_id).cloned() {
        Some(incoming) => delta_map_upsert(&mut pending.delta.incoming, entity_id, incoming),
        None => delta_map_remove(&mut pending.delta.incoming, entity_id),
    }
}

fn record_relation_edge_delta(
    pending: &mut PendingGraphDelta,
    ent: &EntityData,
    relation: &Relation,
) {
    if let Some(src) = relation.src.as_entity() {
        record_edge_list_delta(pending, ent, src);
    }
    if let Some(dst) = relation.dst.as_entity() {
        record_edge_list_delta(pending, ent, dst);
    }
}

// ---------------------------------------------------------------------------
// Embedding queue — deterministic priority ordering
// ---------------------------------------------------------------------------

/// Recency class of a queued embedding item. Lower variants embed earlier.
///
/// `ChangedThisSync` covers entities/artifacts invalidated by a live graph
/// mutation (the incremental sync path: upsert/commit/relation edits).
/// `Backfill` covers bulk and "missing" re-queues (load-time backfill,
/// `queue_all_*`, `queue_missing_*`, manual bulk import). Declaration order is
/// the sort order, so a live change always outranks a backfill item.
///
/// The recency class is a deterministic property of *which producer enqueued
/// the item*, not of enqueue timing or map iteration order, so it never
/// reintroduces per-process nondeterminism into batch composition.
#[cfg(feature = "vector")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum EmbedRecency {
    /// Invalidated by a live graph mutation this sync — embed first.
    ChangedThisSync,
    /// Bulk / missing backfill — embed after changed-this-sync work.
    Backfill,
}

/// Deduplicating embedding work queue keyed by `K`.
///
/// Replaces the previous bare `HashSet<K>`: it still deduplicates (one embed
/// per key regardless of how many times it is enqueued) but additionally
/// records each key's [`EmbedRecency`] so the drain path can order work
/// deterministically by priority. The map's own iteration order is never
/// observed for batch composition — the drain always sorts by a total order —
/// so batch contents are identical across processes regardless of the
/// per-process HashMap seed.
#[cfg(feature = "vector")]
struct RecencyQueue<K: Eq + std::hash::Hash + Copy> {
    /// Canonical queued membership and current recency. Keys remain here while
    /// they are present in `frontier`; popping a batch removes them from both.
    items: hashbrown::HashMap<K, EmbedRecency>,
    /// Deterministic total order computed once for a stable queue snapshot.
    /// Repeated small drains pop this frontier instead of draining, selecting,
    /// and reinserting the entire backlog every batch.
    frontier: std::collections::VecDeque<K>,
    /// Any membership or priority change invalidates the cached ordering. The
    /// next drain rebuilds once from `items`, incorporating all new work.
    frontier_dirty: bool,
    #[cfg(test)]
    frontier_rebuilds: usize,
}

#[cfg(feature = "vector")]
impl<K: Eq + std::hash::Hash + Copy> Default for RecencyQueue<K> {
    fn default() -> Self {
        Self {
            items: hashbrown::HashMap::new(),
            frontier: std::collections::VecDeque::new(),
            frontier_dirty: false,
            #[cfg(test)]
            frontier_rebuilds: 0,
        }
    }
}

#[cfg(feature = "vector")]
impl<K: Eq + std::hash::Hash + Copy> RecencyQueue<K> {
    /// Enqueue `key`, deduplicating. If the key is already queued, keep the
    /// higher-priority (lower) recency so a live change is never demoted to
    /// backfill by a subsequent bulk re-queue.
    fn insert(&mut self, key: K, recency: EmbedRecency) {
        self.insert_inner(key, recency, false);
    }

    /// Enqueue work after a graph mutation that may have changed the key's
    /// tier or centrality. Even when membership and recency are unchanged, a
    /// cached entity frontier must be rebuilt against the new graph facts.
    fn insert_graph_priority_changed(&mut self, key: K, recency: EmbedRecency) {
        self.insert_inner(key, recency, true);
    }

    fn insert_inner(&mut self, key: K, recency: EmbedRecency, graph_priority_changed: bool) {
        match self.items.entry(key) {
            hashbrown::hash_map::Entry::Occupied(mut entry) => {
                if recency < *entry.get() {
                    *entry.get_mut() = recency;
                    self.frontier_dirty = true;
                } else if graph_priority_changed {
                    self.frontier_dirty = true;
                }
            }
            hashbrown::hash_map::Entry::Vacant(entry) => {
                entry.insert(recency);
                self.frontier_dirty = true;
            }
        }
    }

    /// Remove a key from the queue (e.g., when its entity is deleted).
    fn remove(&mut self, key: &K) -> bool {
        let removed = self.items.remove(key).is_some();
        if removed {
            // Leave the stale key in the deque for now. Rebuilding from the
            // canonical map on the next drain removes it without an O(n) scan
            // on every deletion.
            self.frontier_dirty = true;
        }
        removed
    }

    /// HashSet-style membership facade (used by tests; kept for parity with the
    /// previous queue type so call sites read identically).
    #[allow(dead_code)]
    fn contains(&self, key: &K) -> bool {
        self.items.contains_key(key)
    }

    #[allow(dead_code)]
    fn clear(&mut self) {
        self.items.clear();
        self.frontier.clear();
        self.frontier_dirty = false;
    }

    fn len(&self) -> usize {
        self.items.len()
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Whether the deterministic frontier must be rebuilt before it is popped.
    fn frontier_needs_rebuild(&self) -> bool {
        self.frontier_dirty || (self.frontier.is_empty() && !self.items.is_empty())
    }

    /// Replace the cached frontier with a deterministic ordering containing
    /// every currently queued key exactly once.
    fn install_frontier<I>(&mut self, ordered: I)
    where
        I: IntoIterator<Item = K>,
    {
        self.frontier = ordered.into_iter().collect();
        debug_assert_eq!(self.frontier.len(), self.items.len());
        self.frontier_dirty = false;
        #[cfg(test)]
        {
            self.frontier_rebuilds += 1;
        }
    }

    /// Pop up to `batch_size` items from a valid frontier. Membership remains
    /// authoritative in `items`, so stale deque entries can never escape even
    /// if a future caller violates the rebuild precondition.
    fn pop_frontier_batch(&mut self, batch_size: usize) -> Vec<(K, EmbedRecency)> {
        debug_assert!(!self.frontier_dirty);
        let mut batch = Vec::with_capacity(batch_size.min(self.items.len()));
        while batch.len() < batch_size {
            let Some(key) = self.frontier.pop_front() else {
                break;
            };
            if let Some(recency) = self.items.remove(&key) {
                batch.push((key, recency));
            }
        }
        batch
    }

    #[cfg(test)]
    fn drain_all(&mut self) -> Vec<(K, EmbedRecency)> {
        self.frontier.clear();
        self.frontier_dirty = false;
        self.items.drain().collect()
    }
}

// Embedding priority tiers. Lower tiers embed first, giving agents useful
// semantic coverage on the entities that matter (public API surface, then the
// rest of the live source) before historical revisions, tests, and generated
// code. The buckets are derived only from facts the graph already records
// (visibility / role / kind) — no new analysis pass.
#[cfg(feature = "vector")]
mod embed_tier {
    /// Public API contract surface (endpoints, interfaces, traits, schemas).
    pub const PUBLIC_API: u8 = 0;
    /// Other public source symbols.
    pub const PUBLIC_SOURCE: u8 = 1;
    /// Crate-visible source symbols.
    pub const CRATE_SOURCE: u8 = 2;
    /// Internal source symbols.
    pub const INTERNAL_SOURCE: u8 = 3;
    /// Private source symbols.
    pub const PRIVATE_SOURCE: u8 = 4;
    /// Historical (non-HEAD) entity revisions — embed after all live HEAD source.
    pub const REVISION: u8 = 5;
    /// Test code.
    pub const TEST: u8 = 6;
    /// Documentation entities.
    pub const DOCS: u8 = 7;
    /// Generated / vendored / external code and non-entity keys.
    pub const OTHER: u8 = 8;
}

/// Classify a HEAD entity into an [`embed_tier`] bucket from its visibility,
/// role, and kind. Public API surface ranks first; non-source roles last.
#[cfg(feature = "vector")]
fn entity_embed_tier(entity: &Entity) -> u8 {
    // Role dominates: non-source code always ranks after live source code.
    match entity.role {
        EntityRole::Test => return embed_tier::TEST,
        EntityRole::Docs => return embed_tier::DOCS,
        EntityRole::Generated | EntityRole::Vendored | EntityRole::External => {
            return embed_tier::OTHER
        }
        EntityRole::Source => {}
    }
    // A source-roled entity that is structurally a test still ranks as test.
    if matches!(entity.kind, EntityKind::Test) {
        return embed_tier::TEST;
    }
    let is_api_surface = matches!(
        entity.kind,
        EntityKind::ApiEndpoint
            | EntityKind::EventContract
            | EntityKind::Schema
            | EntityKind::Interface
            | EntityKind::TraitDef
    );
    match entity.visibility {
        Visibility::Public if is_api_surface => embed_tier::PUBLIC_API,
        Visibility::Public => embed_tier::PUBLIC_SOURCE,
        Visibility::Crate => embed_tier::CRATE_SOURCE,
        Visibility::Internal => embed_tier::INTERNAL_SOURCE,
        Visibility::Private => embed_tier::PRIVATE_SOURCE,
    }
}

/// Map an entity's incoming-relation degree (dependent/caller count, the cheap
/// centrality proxy the graph already maintains) to an ascending sort rank, so
/// that *higher* in-degree sorts *earlier*.
#[cfg(feature = "vector")]
fn embed_centrality_rank(in_degree: usize) -> u32 {
    u32::MAX - (in_degree.min(u32::MAX as usize) as u32)
}

/// Deterministic priority sort key for a queued embedding item. Sorts ascending
/// — the smallest key embeds first. Fields in precedence order:
/// 1. `tier` — semantic-importance bucket (public API ... generated; see [`embed_tier`])
/// 2. `recency` — changed-this-sync before bulk backfill
/// 3. `centrality_rank` — higher in-degree (more dependents) first
/// 4. `key` — `RetrievalKey` total order, the stable tiebreak on id
///
/// Because every field is a pure function of queue contents + current graph
/// state (and `key` is unique per queued item), the resulting order is a
/// deterministic total order — identical across processes regardless of how the
/// items were inserted.
#[cfg(feature = "vector")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct EmbedSortKey {
    tier: u8,
    recency: EmbedRecency,
    centrality_rank: u32,
    key: RetrievalKey,
}

/// Compute the [`EmbedSortKey`] for a queued entity key against current graph
/// state. HEAD entities draw tier and centrality from their own graph facts;
/// historical revisions trail live HEAD source at a fixed revision tier;
/// artifact keys (not normally present in the entity queue) sort last.
///
/// PERF: this is O(1) per key — two `HashMap` point lookups (`entities` and
/// `incoming`) plus `Vec::len`, and a constant-time `entity_embed_tier` match.
/// No graph traversal happens here, so building keys for an init backfill of
/// 20K–50K entities is O(n) and the surrounding drain sort is O(n log n).
#[cfg(feature = "vector")]
fn embed_sort_key_for(ent: &EntityData, key: RetrievalKey, recency: EmbedRecency) -> EmbedSortKey {
    let (tier, centrality_rank) = match key {
        RetrievalKey::Entity(id) => {
            let tier = ent
                .entities
                .get(&id)
                .map(entity_embed_tier)
                .unwrap_or(embed_tier::OTHER);
            // In-degree (dependents) is a direct adjacency-list length lookup —
            // O(1), no edge walk.
            let in_degree = ent.incoming.get(&id).map(|rels| rels.len()).unwrap_or(0);
            (tier, embed_centrality_rank(in_degree))
        }
        RetrievalKey::EntityRevision(_) => (embed_tier::REVISION, embed_centrality_rank(0)),
        RetrievalKey::Artifact(_) | RetrievalKey::ArtifactRevision(_) => {
            (embed_tier::OTHER, embed_centrality_rank(0))
        }
    };
    EmbedSortKey {
        tier,
        recency,
        centrality_rank,
        key,
    }
}

// ---------------------------------------------------------------------------
// InMemoryGraph — sharded by domain
// ---------------------------------------------------------------------------

/// In-memory graph engine with O(1) entity/relation lookup and secondary indexes.
///
/// Data is sharded into domain-specific sub-stores, each behind its own
/// `RwLock`. This allows independent domains (e.g., session heartbeats vs
/// entity queries) to proceed without contending on the same lock.
///
/// **Lock ordering** (to prevent deadlocks when acquiring multiple locks):
/// entities → changes → work → reviews → verification → provenance → sessions
/// Deferred Merkle refresh state: dirty seeds accumulated since the last root
/// reconciliation. See [`InMemoryGraph::flush_merkle`].
#[derive(Default)]
struct PendingMerkle {
    dirty: bool,
    seeds: HashSet<EntityId>,
}

/// Write access to [`EntityData`] that records the mutation in the graph's
/// truth epoch.
///
/// Embedding coverage is derived from entity truth, so a reader that caches a
/// coverage count has to know when truth moved under it. Routing every write
/// through this guard makes that complete by construction: any write at all
/// bumps the epoch, so a missed truth-changing site is not possible, and the
/// over-invalidation a non-truth write causes costs one recount rather than a
/// wrong answer.
struct TruthWriteGuard<'a> {
    guard: Option<parking_lot::RwLockWriteGuard<'a, EntityData>>,
    epoch: &'a AtomicU64,
}

impl std::ops::Deref for TruthWriteGuard<'_> {
    type Target = EntityData;

    fn deref(&self) -> &Self::Target {
        self.guard
            .as_ref()
            .expect("entity write guard is taken only while dropping")
    }
}

impl std::ops::DerefMut for TruthWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard
            .as_mut()
            .expect("entity write guard is taken only while dropping")
    }
}

impl Drop for TruthWriteGuard<'_> {
    fn drop(&mut self) {
        // Release the lock first, then bump. A reader that has already read the
        // new epoch is then guaranteed to observe the completed write when it
        // takes the read lock.
        drop(self.guard.take());
        self.epoch.fetch_add(1, Ordering::Release);
    }
}

/// A cached exact answer for [`InMemoryGraph::embedding_status`]'s `indexed`
/// and `total`.
///
/// Valid only while both tokens still match: `truth_epoch` covers the entity
/// side (which keys are owed a vector) and `index_token` covers the vector side
/// (which keys hold one). `index_token` is `None` when no index is loaded,
/// which keeps "no index at all" distinguishable from "an index holding
/// nothing". Both report `indexed = 0`, and an entry minted for one must never
/// be served to the other.
#[cfg(feature = "vector")]
#[derive(Clone, Copy)]
struct EmbeddingCoverage {
    truth_epoch: u64,
    index_token: Option<(u64, u64)>,
    indexed: usize,
    total: usize,
}

/// Incremental reconcile bookkeeping for the vector index.
///
/// `prune_orphaned_vectors` evicts index keys that have fallen out of graph
/// truth. The vast majority of those orphans come from one path — a live
/// re-embed appends a new entity revision, leaving the prior generation's
/// revision vector behind — whose exact key is known at mutation time. Tracking
/// that key set lets prune evict precisely those entries (`superseded`) without
/// the O(index) rescan. `full` forces the exhaustive scan after an untracked
/// truth change (a fresh build, a sidecar load, or an entity removal) where the
/// orphan set cannot be enumerated cheaply. It starts `true` so the first prune
/// of any graph always reconciles fully.
#[cfg(feature = "vector")]
struct VectorReconcileState {
    full: bool,
    superseded: HashSet<RetrievalKey>,
}

#[cfg(feature = "vector")]
impl Default for VectorReconcileState {
    fn default() -> Self {
        Self {
            full: true,
            superseded: HashSet::new(),
        }
    }
}

/// Throttle bookkeeping for the in-run vector-sidecar flush.
///
/// During a bulk embed the embedding queue stays non-empty for the whole run,
/// so `SnapshotManager::flush_embed_progress` must still land the derived
/// `.kvec` sidecar periodically — otherwise persisted coverage freezes at a
/// batch boundary while compute keeps advancing, and a persisted-progress
/// watchdog reaps the run as stalled. Writing the sidecar on every batch is the
/// other extreme: it re-serializes the whole growing index (O(index) per
/// batch), which is what motivated deferring it to the drain in the first
/// place. This state bounds both, checkpointing on a wall-clock interval OR a
/// batch count, whichever fires first, so persisted tracks compute at a cost
/// amortized across the run.
///
/// `last_flush` is `None` before the first in-run write so the very first
/// incremental flush lands progress immediately; each fire resets both fields.
#[cfg(feature = "vector")]
#[derive(Default)]
struct VectorSidecarFlushThrottle {
    last_flush: Option<std::time::Instant>,
    batches_since_flush: usize,
}

/// A drained, text-formatted embedding batch ready for inference.
///
/// Splitting the embed pipeline at this boundary lets a caller hold the graph
/// read lock for ONLY the CPU prep stage ([`InMemoryGraph::prepare_pending_embedding_batch`]),
/// run inference graph-lock-free ([`InMemoryGraph::embed_prepared_batch`]), then
/// persist under the vector-index lock ([`InMemoryGraph::persist_embedded_batch`]).
/// Prep for batch N+1, inference for batch N, and persist for batch N-1 can then
/// overlap instead of serializing behind a single lock held across the whole
/// pipeline. [`InMemoryGraph::process_embedding_queue`] composes the three stages.
#[cfg(all(feature = "embeddings", feature = "vector"))]
pub struct PreparedEmbedBatch {
    /// Keys whose text was successfully formatted (the work to embed).
    keys: Vec<RetrievalKey>,
    /// Formatted text, parallel to `keys`. Owned once here and never recopied.
    texts: Vec<String>,
    /// Recency for every drained key (including any whose entity was missing),
    /// so an error-requeue cannot demote changed-this-sync work to backfill.
    recency: hashbrown::HashMap<RetrievalKey, EmbedRecency>,
}

#[cfg(all(feature = "embeddings", feature = "vector"))]
impl PreparedEmbedBatch {
    /// Number of entities prepared for embedding.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the batch holds no embeddable entities.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

pub struct InMemoryGraph {
    /// Core entity/relation graph.
    entities: RwLock<EntityData>,
    /// Semantic change DAG. Repository refs live in the shared authority cell.
    changes: RwLock<ChangeData>,
    /// Work items, annotations, links.
    work: RwLock<WorkData>,
    /// Reviews, decisions, notes, discussions, assignments.
    reviews: RwLock<ReviewData>,
    /// Verification: tests, coverage, contracts.
    verification: RwLock<VerificationData>,
    /// Provenance: actors, delegations, approvals, audit.
    provenance: RwLock<ProvenanceData>,
    /// Session/intent state (already transient).
    sessions: RwLock<SessionData>,
    /// Optional full-text search index for ranked search queries.
    text_index: Option<TextIndex>,
    /// Merkle state for the entity/relation graph, reconciled lazily.
    merkle: parking_lot::RwLock<MerkleCache>,
    /// Deferred Merkle refresh state. Each mutation records its touched entities
    /// here; the root is reconciled against the live graph the next time it is
    /// read. The frozen subgraph hash makes a single refresh inherently
    /// O(component), so deferring keeps bulk ingestion to one batch Merkle build
    /// rather than one O(component) refresh per upsert.
    merkle_pending: parking_lot::Mutex<PendingMerkle>,
    /// Mutation-time delta journal for O(change) persistence flushes between commits.
    pending_delta: parking_lot::Mutex<PendingGraphDelta>,
    /// True when a mutation touched a domain not yet covered by the O(change) journal.
    full_snapshot_required: AtomicBool,
    /// True when the text index has uncommitted writes (upsert/remove without commit).
    text_dirty: AtomicBool,
    /// True when relation-derived text fields are stale and a full rebuild is
    /// needed before the next persist. Set by `upsert_relations_batch` to avoid
    /// 20K+ individual Tantivy upserts during bulk relation insertion.
    text_full_rebuild_required: AtomicBool,
    /// Code embedding model, lazily initialized on first embed call.
    #[cfg(feature = "embeddings")]
    embedder: parking_lot::Mutex<Option<Arc<CodeEmbedder>>>,
    /// HNSW vector index for semantic similarity search, lazily initialized.
    #[cfg(feature = "vector")]
    vector_index: parking_lot::Mutex<Option<Arc<VectorIndex>>>,
    /// Monotonic counter bumped by every [`TruthWriteGuard`] drop, i.e. by every
    /// write to [`EntityData`]. Reading it is how a cached derivation of entity
    /// truth knows whether truth has moved.
    truth_epoch: AtomicU64,
    /// Cached `(indexed, total)` embedding coverage, keyed on the truth epoch
    /// and the vector index's key-set token.
    ///
    /// Recomputing it costs one pass over graph truth plus one index scan, and
    /// the embed settle loops poll `embedding_status` every ten seconds for the
    /// length of a bulk embed. Between two vector batches nothing either token
    /// covers can change, so every poll in that window is answered from here.
    #[cfg(feature = "vector")]
    embedding_coverage: parking_lot::Mutex<Option<EmbeddingCoverage>>,
    /// How many times the coverage above was actually recomputed. Instrumentation
    /// for the tests that assert repeat polls are served from the cache; nothing
    /// in the engine reads it.
    #[cfg(feature = "vector")]
    embedding_coverage_scans: AtomicU64,
    /// Queue of entity keys that need embedding. Populated on upsert, drained
    /// by background workers or explicit `process_embedding_queue` calls.
    /// A [`RecencyQueue`] deduplicates (an entity modified twice only needs one
    /// embed) and records recency so the drain path can order work
    /// deterministically by priority (public-API/high-centrality and
    /// changed-this-sync entities first).
    #[cfg(feature = "vector")]
    embedding_queue: parking_lot::Mutex<RecencyQueue<RetrievalKey>>,
    /// Queue of artifact IDs that need embedding. This keeps artifact re-embed
    /// work targeted instead of forcing a full artifact pass on every embed run.
    #[cfg(feature = "vector")]
    artifact_embedding_queue: parking_lot::Mutex<RecencyQueue<ArtifactId>>,
    /// Incremental reconcile state for `prune_orphaned_vectors`. Tracks the exact
    /// set of vector keys orphaned by re-embeds (superseded entity revisions) so
    /// the common live-re-embed prune evicts only those keys instead of rescanning
    /// the whole index, and a `full` flag for untracked truth changes (load,
    /// (re)build, entity removal) that still demand a full index↔truth scan.
    #[cfg(feature = "vector")]
    vector_reconcile: parking_lot::Mutex<VectorReconcileState>,
    /// Throttle bookkeeping for the in-run vector-sidecar flush. See
    /// [`VectorSidecarFlushThrottle`] and
    /// [`InMemoryGraph::should_flush_vector_sidecar_now`].
    #[cfg(feature = "vector")]
    vector_sidecar_flush_throttle: parking_lot::Mutex<VectorSidecarFlushThrottle>,
    /// Per-stage wall-clock + call-count timing for the embed hot path (drain,
    /// prep, forward, persist, prune). The staged embed methods record into this;
    /// a completed embed run logs its delta at `info` and operator tooling can
    /// read a snapshot via [`InMemoryGraph::embed_stage_timings_snapshot`]. See
    /// [`crate::embed::EmbedStageTimings`].
    #[cfg(feature = "vector")]
    embed_stage_timings: crate::embed::EmbedStageTimings,
    /// Per-graph count of deferred Merkle refreshes that actually ran.
    /// Used by tests to prove that burst mutations collapse into one batch
    /// reconciliation. A per-instance counter avoids interference from other
    /// tests running in parallel (the old global counter was shared across the
    /// whole test process, causing spurious failures when concurrent tests
    /// triggered their own flushes).
    #[cfg(test)]
    merkle_flush_count: std::sync::atomic::AtomicUsize,
    /// One-shot fault injection for the post-authority transaction cleanup
    /// boundary. Keeps the retry-safety invariant adversarially testable.
    #[cfg(test)]
    fail_next_transaction_derived_cleanup: AtomicBool,
    #[cfg(test)]
    fail_next_text_rebuild: AtomicBool,
}

#[cfg(test)]
thread_local! {
    static CREATE_CHANGE_AFTER_REVISION_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_create_change_after_revision_hook(hook: impl FnOnce() + 'static) {
    CREATE_CHANGE_AFTER_REVISION_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_create_change_after_revision_hook() {
    CREATE_CHANGE_AFTER_REVISION_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_create_change_after_revision_hook() {}

#[cfg(all(test, feature = "vector"))]
thread_local! {
    static SAVE_VECTOR_INDEX_AFTER_DETACH_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce(&InMemoryGraph)>>> =
        std::cell::RefCell::new(None);
}

#[cfg(all(test, feature = "vector"))]
fn set_save_vector_index_after_detach_hook(hook: impl FnOnce(&InMemoryGraph) + 'static) {
    SAVE_VECTOR_INDEX_AFTER_DETACH_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

/// Observation point between detaching the index handle and saving it.
///
/// The save is the longest single operation the vector index has, so the
/// question a test must be able to ask is whether the `vector_index` slot is
/// still reachable while it runs. The hook runs on the saving thread, and
/// `parking_lot::Mutex` is not reentrant, so a `try_lock` inside it fails
/// exactly when the guard is still held.
#[cfg(all(test, feature = "vector"))]
fn run_save_vector_index_after_detach_hook(graph: &InMemoryGraph) {
    let hook = SAVE_VECTOR_INDEX_AFTER_DETACH_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(graph);
    }
}

#[cfg(all(not(test), feature = "vector"))]
fn run_save_vector_index_after_detach_hook(_graph: &InMemoryGraph) {}

#[cfg(all(test, feature = "vector"))]
thread_local! {
    static EMBEDDING_COVERAGE_BEFORE_COUNT_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce(&InMemoryGraph)>>> =
        std::cell::RefCell::new(None);
}

#[cfg(all(test, feature = "vector"))]
fn set_embedding_coverage_before_count_hook(hook: impl FnOnce(&InMemoryGraph) + 'static) {
    EMBEDDING_COVERAGE_BEFORE_COUNT_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

/// Observation point at the start of a coverage recount, after the index
/// handle has been cloned out of the `vector_index` slot.
///
/// The recount is the longest thing `embedding_status` does, and holding the
/// slot across it is what queued the embed worker's `get_vector_index` behind
/// a status poll. The hook runs on the counting thread and
/// `parking_lot::Mutex` is not reentrant, so a `try_lock` inside it fails
/// exactly when the guard is still held.
#[cfg(all(test, feature = "vector"))]
fn run_embedding_coverage_before_count_hook(graph: &InMemoryGraph) {
    let hook = EMBEDDING_COVERAGE_BEFORE_COUNT_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(graph);
    }
}

#[cfg(all(not(test), feature = "vector"))]
fn run_embedding_coverage_before_count_hook(_graph: &InMemoryGraph) {}

impl InMemoryGraph {
    /// Create a new empty in-memory graph (RAM-only text index).
    pub fn new() -> Self {
        Self::build(None)
    }

    /// Create a new empty in-memory graph with a persistent text index at
    /// the given directory path. The directory is created if it does not exist.
    pub fn with_text_index(text_index_path: PathBuf) -> Self {
        Self::build(Some(text_index_path))
    }

    fn build(text_index_path: Option<PathBuf>) -> Self {
        let text_index = match text_index_path.as_ref() {
            Some(p) => match TextIndex::open(Some(p)) {
                Ok(index) => Some(index),
                Err(err) => {
                    tracing::warn!(
                        "failed to open persistent text index at {}: {err}",
                        p.display()
                    );
                    TextIndex::new().ok()
                }
            },
            None => TextIndex::new().ok(),
        };
        let graph = Self {
            entities: RwLock::new(EntityData {
                entities: HashMap::new(),
                entity_revisions: HashMap::new(),
                external_references: HashMap::new(),
                relations: HashMap::new(),
                outgoing: HashMap::new(),
                incoming: HashMap::new(),
                node_outgoing: HashMap::new(),
                node_incoming: HashMap::new(),
                indexes: IndexSet::new(),
                resolved_tree: ResolvedTree::default(),
                shallow_files: HashMap::new(),
                file_layouts: HashMap::new(),
                structured_artifacts: HashMap::new(),
                opaque_artifacts: HashMap::new(),
            }),
            changes: RwLock::new(ChangeData {
                changes: HashMap::new(),
                change_children: HashMap::new(),
            }),
            work: RwLock::new(WorkData {
                work_items: HashMap::new(),
                annotations: HashMap::new(),
                work_links: Vec::new(),
            }),
            reviews: RwLock::new(ReviewData {
                reviews: HashMap::new(),
                review_decisions: HashMap::new(),
                review_notes: HashMap::new(),
                review_discussions: HashMap::new(),
                review_assignments: HashMap::new(),
            }),
            verification: RwLock::new(VerificationData {
                test_cases: HashMap::new(),
                assertions: HashMap::new(),
                verification_runs: HashMap::new(),
                mock_hints: Vec::new(),
                contracts: HashMap::new(),
            }),
            provenance: RwLock::new(ProvenanceData {
                actors: HashMap::new(),
                delegations: Vec::new(),
                approvals: Vec::new(),
                audit_events: Vec::new(),
            }),
            sessions: RwLock::new(SessionData {
                sessions: HashMap::new(),
                intents: HashMap::new(),
                downstream_warnings: Vec::new(),
            }),
            text_index,
            merkle: parking_lot::RwLock::new(MerkleCache::new()),
            merkle_pending: parking_lot::Mutex::new(PendingMerkle::default()),
            pending_delta: parking_lot::Mutex::new(PendingGraphDelta::default()),
            full_snapshot_required: AtomicBool::new(false),
            text_dirty: AtomicBool::new(false),
            text_full_rebuild_required: AtomicBool::new(false),
            #[cfg(feature = "embeddings")]
            embedder: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            vector_index: parking_lot::Mutex::new(None),
            truth_epoch: AtomicU64::new(0),
            #[cfg(feature = "vector")]
            embedding_coverage: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            embedding_coverage_scans: AtomicU64::new(0),
            #[cfg(feature = "vector")]
            embedding_queue: parking_lot::Mutex::new(RecencyQueue::default()),
            #[cfg(feature = "vector")]
            artifact_embedding_queue: parking_lot::Mutex::new(RecencyQueue::default()),
            #[cfg(feature = "vector")]
            vector_reconcile: parking_lot::Mutex::new(VectorReconcileState::default()),
            #[cfg(feature = "vector")]
            vector_sidecar_flush_throttle: parking_lot::Mutex::new(
                VectorSidecarFlushThrottle::default(),
            ),
            #[cfg(feature = "vector")]
            embed_stage_timings: crate::embed::EmbedStageTimings::default(),
            #[cfg(test)]
            merkle_flush_count: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            fail_next_transaction_derived_cleanup: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_text_rebuild: AtomicBool::new(false),
        };

        graph
    }

    /// Restore a graph from a snapshot (RAM-only text index).
    ///
    /// A RAM-only index starts empty, so this always rebuilds it over every
    /// entity. Callers that never search the restored graph want
    /// [`Self::from_snapshot_without_text_index`] instead.
    pub fn from_snapshot(snapshot: GraphSnapshot) -> Result<Self, KinDbError> {
        Self::from_snapshot_inner(snapshot, None, false, false)
    }

    /// Restore a graph from a snapshot (RAM-only text index).
    ///
    /// The graph root hash argument is accepted and ignored: text index
    /// currency is decided by the retrieval authority hash instead. Retained so
    /// callers already holding a root hash need not change.
    pub fn from_snapshot_with_root_hash(
        snapshot: GraphSnapshot,
        _expected_root_hash: [u8; 32],
    ) -> Result<Self, KinDbError> {
        Self::from_snapshot(snapshot)
    }

    /// Restore a graph from a snapshot without constructing any text index.
    ///
    /// This is intended for graph-only workflows such as warm-cache diffing or
    /// workspace materialization, where entity/file truth is needed but lexical
    /// retrieval is not. Those callers otherwise pay for a full text index
    /// rebuild over every entity and then drop it with the graph.
    ///
    /// Graph truth is unaffected: the text index is a derived retrieval surface,
    /// it is not part of a `GraphSnapshot`, and no snapshot, tree, or validation
    /// result depends on whether one was built.
    pub fn from_snapshot_without_text_index(snapshot: GraphSnapshot) -> Result<Self, KinDbError> {
        Self::from_snapshot_inner(snapshot, None, false, true)
    }

    /// Restore a graph from a snapshot whose change map was cloned from an
    /// already-admitted one.
    ///
    /// Identical to [`from_snapshot_without_text_index`] except that the
    /// change-map pass is carried rather than repeated. Every other admission
    /// check runs exactly as it does there.
    ///
    /// CARRY SITE. `snapshot.changes` must be a clone of the map `admitted`
    /// witnesses. That cannot be checked here without re-deriving the digests
    /// this exists to avoid, so it is the caller's obligation, the call sites
    /// are enumerated, and `carry_sites_stay_enumerated` fails if a new one
    /// appears.
    ///
    /// [`from_snapshot_without_text_index`]: Self::from_snapshot_without_text_index
    pub(crate) fn from_admitted_snapshot_without_text_index(
        snapshot: GraphSnapshot,
        admitted: &crate::storage::change_validation::AdmittedChangeMap<'_>,
    ) -> Result<Self, KinDbError> {
        {
            let carried = crate::storage::change_validation::AdmittedChangeMap::carried_from_clone(
                &snapshot.changes,
                admitted,
            );
            snapshot.validate_storage_admission_carrying(
                crate::storage::repository::GitProjectionTreeReplay::Required,
                &carried,
            )?;
        }
        Self::from_snapshot_inner_admitted(snapshot, None, false, true)
    }

    /// Restore a graph from a snapshot without constructing any text index.
    ///
    /// The graph root hash argument is accepted and ignored: text index
    /// currency is decided by the retrieval authority hash instead.
    pub fn from_snapshot_without_text_index_with_root_hash(
        snapshot: GraphSnapshot,
        _expected_root_hash: [u8; 32],
    ) -> Result<Self, KinDbError> {
        Self::from_snapshot_without_text_index(snapshot)
    }

    /// Restore a graph from a snapshot with a persistent text index at the
    /// given directory path.
    pub fn from_snapshot_with_text_index(
        snapshot: GraphSnapshot,
        text_index_path: PathBuf,
    ) -> Result<Self, KinDbError> {
        Self::from_snapshot_inner(snapshot, Some(text_index_path), false, false)
    }

    /// Restore a graph from a snapshot with a persistent text index loaded in
    /// read-only mode.
    pub fn from_snapshot_with_text_index_read_only(
        snapshot: GraphSnapshot,
        text_index_path: PathBuf,
    ) -> Result<Self, KinDbError> {
        Self::from_snapshot_inner(snapshot, Some(text_index_path), true, false)
    }

    /// Restore a graph from a snapshot with a persistent text index.
    ///
    /// The graph root hash argument is accepted and ignored: text index
    /// currency is decided by the retrieval authority hash instead.
    pub fn from_snapshot_with_text_index_and_root_hash(
        snapshot: GraphSnapshot,
        text_index_path: PathBuf,
        _expected_root_hash: [u8; 32],
    ) -> Result<Self, KinDbError> {
        Self::from_snapshot_with_text_index(snapshot, text_index_path)
    }

    /// Restore a graph from a snapshot with a persistent text index loaded in
    /// read-only mode.
    ///
    /// The graph root hash argument is accepted and ignored: text index
    /// currency is decided by the retrieval authority hash instead.
    pub fn from_snapshot_with_text_index_and_root_hash_read_only(
        snapshot: GraphSnapshot,
        text_index_path: PathBuf,
        _expected_root_hash: [u8; 32],
    ) -> Result<Self, KinDbError> {
        Self::from_snapshot_with_text_index_read_only(snapshot, text_index_path)
    }

    /// Restore a read-only graph from a lightweight locate snapshot.
    ///
    /// This avoids reconstructing an intermediate full `GraphSnapshot` just to
    /// immediately collect the same entity/relation maps into the in-memory
    /// graph stores again.
    pub(crate) fn from_locate_snapshot_read_only(
        snapshot: LocateGraphSnapshot,
        text_index_path: Option<PathBuf>,
        expected_root_hash: [u8; 32],
    ) -> Result<Self, KinDbError> {
        Self::from_locate_snapshot_inner(snapshot, text_index_path, expected_root_hash, true)
    }

    /// Restore a graph from a snapshot.
    ///
    /// This takes no expected graph root hash. It used to, and the value was
    /// what decided whether the persisted text index was still current. That
    /// job now belongs to the retrieval authority hash, which binds the
    /// repository tree and artifact enrichment domains the bare graph root does
    /// not cover, and which is computed below from the snapshot itself. Callers
    /// that hand one in are handing in a weaker identity for a decision that no
    /// longer uses it.
    ///
    /// So a root hash computed purely to reach this function is discarded work.
    /// It is also not safe to revive as a precomputed input: at least one caller
    /// supplies the *text index's own* recorded hash rather than the snapshot's
    /// root, which is harmless while the value is ignored and would let a stale
    /// index certify itself current if it were not.
    fn from_snapshot_inner(
        snapshot: GraphSnapshot,
        text_index_path: Option<PathBuf>,
        read_only: bool,
        skip_text_index: bool,
    ) -> Result<Self, KinDbError> {
        snapshot.validate_storage_admission()?;
        Self::from_snapshot_inner_admitted(snapshot, text_index_path, read_only, skip_text_index)
    }

    /// The graph build itself, for a snapshot whose storage admission the
    /// caller has already completed. Private: the two callers above are the
    /// only entry points, and each validates before reaching here.
    fn from_snapshot_inner_admitted(
        snapshot: GraphSnapshot,
        text_index_path: Option<PathBuf>,
        read_only: bool,
        skip_text_index: bool,
    ) -> Result<Self, KinDbError> {
        let retrieval_authority_hash = compute_retrieval_authority_hash(&snapshot);
        let GraphSnapshot {
            version: _,
            entities,
            relations,
            outgoing: persisted_outgoing,
            incoming: persisted_incoming,
            changes,
            change_children,
            work_items,
            annotations,
            work_links,
            reviews,
            review_decisions,
            review_notes,
            review_discussions,
            review_assignments,
            test_cases,
            assertions,
            verification_runs,
            mock_hints,
            contracts,
            actors,
            delegations,
            approvals,
            audit_events,
            shallow_files,
            file_layouts,
            structured_artifacts,
            opaque_artifacts,
            resolved_tree,
            sessions,
            intents,
            downstream_warnings,
            entity_revisions,
            // Repository authority is owned by the immutable publication
            // manager, never by this in-place mutable graph.
            repository_authority: _,
            external_references,
        } = snapshot;
        let entity_revisions: HashMap<EntityId, Vec<EntityRevision>> =
            if entity_revisions.is_empty() && !changes.is_empty() {
                // Named because it is the largest thing a conversion's
                // workspace lap does and it was invisible inside that lap.
                let _span = tracing::info_span!(
                    "kindb.graph.derive_entity_revisions",
                    changes = changes.len()
                )
                .entered();
                derive_entity_revisions_across_history(topologically_order_changes(changes.iter()))?
            } else {
                entity_revisions.into_iter().collect()
            };
        let _span = tracing::info_span!(
            "kindb.graph.from_snapshot",
            entities = entities.len(),
            relations = relations.len(),
            persistent_text_index = text_index_path.is_some(),
            read_only = read_only,
            skip_text_index = skip_text_index
        )
        .entered();
        let relations: HashMap<RelationId, Relation> = relations.into_iter().collect();
        let persisted_outgoing: HashMap<EntityId, Vec<RelationId>> =
            persisted_outgoing.into_iter().collect();
        let persisted_incoming: HashMap<EntityId, Vec<RelationId>> =
            persisted_incoming.into_iter().collect();
        let (outgoing, incoming, node_outgoing, node_incoming) = {
            let _span =
                tracing::info_span!("kindb.graph.from_snapshot.build_relation_indexes").entered();
            // Reuse the persisted entity-level adjacency when it is consistent
            // with the loaded relations rather than discarding and rebuilding
            // it on every boot. Node-level maps are always derived (they are
            // not persisted).
            let (outgoing, incoming, node_outgoing, node_incoming, reuse) =
                build_relation_indexes_with_reuse(
                    &relations,
                    persisted_outgoing,
                    persisted_incoming,
                );
            tracing::debug!(
                adjacency_reuse = ?reuse,
                "kindb.graph.from_snapshot.adjacency"
            );
            (outgoing, incoming, node_outgoing, node_incoming)
        };
        let text_index = if skip_text_index {
            None
        } else {
            let _span = tracing::info_span!(
                "kindb.graph.from_snapshot.open_text_index",
                persistent_text_index = text_index_path.is_some()
            )
            .entered();
            match text_index_path.as_ref() {
                Some(p) => match if read_only {
                    TextIndex::open_read_only(Some(p))
                } else {
                    TextIndex::open(Some(p))
                } {
                    Ok(index) => Some(index),
                    Err(err) => {
                        tracing::warn!(
                            "failed to open persistent text index at {}: {err}",
                            p.display()
                        );
                        TextIndex::new().ok()
                    }
                },
                None => TextIndex::new().ok(),
            }
        };
        let text_index_current = text_index
            .as_ref()
            .and_then(TextIndex::graph_root_hash)
            .map(|hash| hash == retrieval_authority_hash)
            .unwrap_or(false);
        let text_index_entity_coverage_current = if text_index_current {
            text_index
                .as_ref()
                .map(|index| {
                    entities.keys().all(|entity_id| {
                        index.contains_retrievable(&RetrievalKey::Entity(*entity_id))
                    })
                })
                .unwrap_or(false)
        } else {
            false
        };

        // Build secondary indexes in parallel using rayon.
        // Each chunk produces a partial IndexSet which we merge sequentially.
        // This is ~2-4x faster than a sequential loop for graphs >10K entities.
        let entity_vec: Vec<&Entity> = entities.values().collect();
        let indexes = {
            let _span =
                tracing::info_span!("kindb.graph.from_snapshot.build_entity_indexes").entered();
            if entity_vec.len() > 1024 {
                let chunk_indexes: Vec<IndexSet> = entity_vec
                    .par_chunks(4096)
                    .map(|chunk| {
                        let mut partial = IndexSet::new();
                        for entity in chunk {
                            partial.insert(
                                entity.id,
                                &entity.name,
                                entity.file_origin.as_ref(),
                                entity.kind,
                            );
                        }
                        partial
                    })
                    .collect();
                let mut merged = IndexSet::new();
                for partial in chunk_indexes {
                    merged.merge(partial);
                }
                merged
            } else {
                let mut indexes = IndexSet::new();
                for entity in &entity_vec {
                    indexes.insert(
                        entity.id,
                        &entity.name,
                        entity.file_origin.as_ref(),
                        entity.kind,
                    );
                }
                indexes
            }
        };

        let shallow_files: HashMap<FilePathId, ShallowTrackedFile> = shallow_files
            .into_iter()
            .map(|sf| (sf.file_id.clone(), sf))
            .collect();
        let file_layouts: HashMap<FilePathId, FileLayout> = file_layouts
            .into_iter()
            .map(|layout| (layout.file_id.clone(), layout))
            .collect();
        let structured_artifacts: HashMap<FilePathId, StructuredArtifact> = structured_artifacts
            .into_iter()
            .map(|artifact| (artifact.file_id.clone(), artifact))
            .collect();
        let opaque_artifacts: HashMap<FilePathId, OpaqueArtifact> = opaque_artifacts
            .into_iter()
            .map(|artifact| (artifact.file_id.clone(), artifact))
            .collect();
        let entity_data = EntityData {
            entities: entities.into_iter().collect(),
            entity_revisions,
            external_references: external_references.into_iter().collect(),
            relations,
            outgoing,
            incoming,
            node_outgoing,
            node_incoming,
            indexes,
            resolved_tree,
            shallow_files,
            file_layouts,
            structured_artifacts,
            opaque_artifacts,
        };
        let merkle = MerkleCache::from_source(&entity_data);

        let graph = Self {
            entities: RwLock::new(entity_data),
            changes: RwLock::new(ChangeData {
                changes: changes.into_iter().collect(),
                change_children: change_children.into_iter().collect(),
            }),
            work: RwLock::new(WorkData {
                work_items: work_items.into_iter().collect(),
                annotations: annotations.into_iter().collect(),
                work_links,
            }),
            reviews: RwLock::new(ReviewData {
                reviews: reviews.into_iter().collect(),
                review_decisions: review_decisions.into_iter().collect(),
                review_notes: review_notes.into_iter().map(|n| (n.note_id, n)).collect(),
                review_discussions: review_discussions
                    .into_iter()
                    .map(|d| (d.discussion_id, d))
                    .collect(),
                review_assignments: review_assignments.into_iter().collect(),
            }),
            verification: RwLock::new(VerificationData {
                test_cases: test_cases.into_iter().collect(),
                assertions: assertions.into_iter().collect(),
                verification_runs: verification_runs.into_iter().collect(),
                mock_hints,
                contracts: contracts.into_iter().collect(),
            }),
            provenance: RwLock::new(ProvenanceData {
                actors: actors.into_iter().collect(),
                delegations,
                approvals,
                audit_events,
            }),
            sessions: RwLock::new(SessionData {
                sessions: sessions.into_iter().collect(),
                intents: intents.into_iter().collect(),
                downstream_warnings,
            }),
            text_index,
            merkle: parking_lot::RwLock::new(merkle),
            merkle_pending: parking_lot::Mutex::new(PendingMerkle::default()),
            pending_delta: parking_lot::Mutex::new(PendingGraphDelta::default()),
            full_snapshot_required: AtomicBool::new(false),
            text_dirty: AtomicBool::new(false),
            text_full_rebuild_required: AtomicBool::new(false),
            #[cfg(feature = "embeddings")]
            embedder: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            vector_index: parking_lot::Mutex::new(None),
            truth_epoch: AtomicU64::new(0),
            #[cfg(feature = "vector")]
            embedding_coverage: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            embedding_coverage_scans: AtomicU64::new(0),
            #[cfg(feature = "vector")]
            embedding_queue: parking_lot::Mutex::new(RecencyQueue::default()),
            #[cfg(feature = "vector")]
            artifact_embedding_queue: parking_lot::Mutex::new(RecencyQueue::default()),
            #[cfg(feature = "vector")]
            vector_reconcile: parking_lot::Mutex::new(VectorReconcileState::default()),
            #[cfg(feature = "vector")]
            vector_sidecar_flush_throttle: parking_lot::Mutex::new(
                VectorSidecarFlushThrottle::default(),
            ),
            #[cfg(feature = "vector")]
            embed_stage_timings: crate::embed::EmbedStageTimings::default(),
            #[cfg(test)]
            merkle_flush_count: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            fail_next_transaction_derived_cleanup: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_text_rebuild: AtomicBool::new(false),
        };

        if !skip_text_index && (!text_index_current || !text_index_entity_coverage_current) {
            graph.try_rebuild_text_index_from_graph(&graph, retrieval_authority_hash)?;
        }

        Ok(graph)
    }

    fn from_locate_snapshot_inner(
        snapshot: LocateGraphSnapshot,
        text_index_path: Option<PathBuf>,
        expected_root_hash: [u8; 32],
        read_only: bool,
    ) -> Result<Self, KinDbError> {
        snapshot.validate_storage_admission()?;
        let retrieval_authority_hash =
            compute_locate_retrieval_authority_hash(&snapshot, expected_root_hash);
        let LocateGraphSnapshot {
            version: _,
            entities,
            relations,
            changes,
            entity_revisions,
            shallow_files,
            file_layouts,
            structured_artifacts,
            opaque_artifacts,
            resolved_tree,
            external_references,
        } = snapshot;
        let _span = tracing::info_span!(
            "kindb.graph.from_locate_snapshot",
            entities = entities.len(),
            relations = relations.len(),
            persistent_text_index = text_index_path.is_some(),
            read_only = read_only
        )
        .entered();
        let (outgoing, incoming, node_outgoing, node_incoming) = {
            let _span =
                tracing::info_span!("kindb.graph.from_locate_snapshot.build_relation_indexes")
                    .entered();
            build_relation_indexes(&relations)
        };
        let text_index = {
            let _span = tracing::info_span!(
                "kindb.graph.from_locate_snapshot.open_text_index",
                persistent_text_index = text_index_path.is_some()
            )
            .entered();
            match text_index_path.as_ref() {
                Some(p) => match if read_only {
                    TextIndex::open_read_only(Some(p))
                } else {
                    TextIndex::open(Some(p))
                } {
                    Ok(index) => Some(index),
                    Err(err) => {
                        tracing::warn!(
                            "failed to open persistent text index at {}: {err}",
                            p.display()
                        );
                        TextIndex::new().ok()
                    }
                },
                None => TextIndex::new().ok(),
            }
        };
        let text_index_current = text_index
            .as_ref()
            .and_then(TextIndex::graph_root_hash)
            .map(|hash| hash == retrieval_authority_hash)
            .unwrap_or(false);

        let entity_vec: Vec<&Entity> = entities.values().collect();
        let indexes = {
            let _span =
                tracing::info_span!("kindb.graph.from_locate_snapshot.build_entity_indexes")
                    .entered();
            if entity_vec.len() > 1024 {
                let chunk_indexes: Vec<IndexSet> = entity_vec
                    .par_chunks(4096)
                    .map(|chunk| {
                        let mut partial = IndexSet::new();
                        for entity in chunk {
                            partial.insert(
                                entity.id,
                                &entity.name,
                                entity.file_origin.as_ref(),
                                entity.kind,
                            );
                        }
                        partial
                    })
                    .collect();
                let mut merged = IndexSet::new();
                for partial in chunk_indexes {
                    merged.merge(partial);
                }
                merged
            } else {
                let mut indexes = IndexSet::new();
                for entity in &entity_vec {
                    indexes.insert(
                        entity.id,
                        &entity.name,
                        entity.file_origin.as_ref(),
                        entity.kind,
                    );
                }
                indexes
            }
        };

        let shallow_files: HashMap<FilePathId, ShallowTrackedFile> = shallow_files
            .into_iter()
            .map(|sf| (sf.file_id.clone(), sf))
            .collect();
        let file_layouts: HashMap<FilePathId, FileLayout> = file_layouts
            .into_iter()
            .map(|layout| (layout.file_id.clone(), layout))
            .collect();
        let structured_artifacts: HashMap<FilePathId, StructuredArtifact> = structured_artifacts
            .into_iter()
            .map(|artifact| (artifact.file_id.clone(), artifact))
            .collect();
        let opaque_artifacts: HashMap<FilePathId, OpaqueArtifact> = opaque_artifacts
            .into_iter()
            .map(|artifact| (artifact.file_id.clone(), artifact))
            .collect();
        let entity_data = EntityData {
            entities,
            entity_revisions: if entity_revisions.is_empty() && !changes.is_empty() {
                let _span = tracing::info_span!(
                    "kindb.graph.derive_entity_revisions",
                    changes = changes.len()
                )
                .entered();
                derive_entity_revisions_across_history(topologically_order_changes(changes.iter()))?
            } else {
                entity_revisions
            },
            external_references,
            relations,
            outgoing,
            incoming,
            node_outgoing,
            node_incoming,
            indexes,
            resolved_tree,
            shallow_files,
            file_layouts,
            structured_artifacts,
            opaque_artifacts,
        };
        let merkle = MerkleCache::from_source(&entity_data);

        let graph = Self {
            entities: RwLock::new(entity_data),
            changes: RwLock::new(ChangeData {
                changes,
                change_children: HashMap::new(),
            }),
            work: RwLock::new(WorkData {
                work_items: HashMap::new(),
                annotations: HashMap::new(),
                work_links: Vec::new(),
            }),
            reviews: RwLock::new(ReviewData {
                reviews: HashMap::new(),
                review_decisions: HashMap::new(),
                review_notes: HashMap::new(),
                review_discussions: HashMap::new(),
                review_assignments: HashMap::new(),
            }),
            verification: RwLock::new(VerificationData {
                test_cases: HashMap::new(),
                assertions: HashMap::new(),
                verification_runs: HashMap::new(),
                mock_hints: Vec::new(),
                contracts: HashMap::new(),
            }),
            provenance: RwLock::new(ProvenanceData {
                actors: HashMap::new(),
                delegations: Vec::new(),
                approvals: Vec::new(),
                audit_events: Vec::new(),
            }),
            sessions: RwLock::new(SessionData {
                sessions: HashMap::new(),
                intents: HashMap::new(),
                downstream_warnings: Vec::new(),
            }),
            text_index,
            merkle: parking_lot::RwLock::new(merkle),
            merkle_pending: parking_lot::Mutex::new(PendingMerkle::default()),
            pending_delta: parking_lot::Mutex::new(PendingGraphDelta::default()),
            full_snapshot_required: AtomicBool::new(false),
            text_dirty: AtomicBool::new(false),
            text_full_rebuild_required: AtomicBool::new(false),
            #[cfg(feature = "embeddings")]
            embedder: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            vector_index: parking_lot::Mutex::new(None),
            truth_epoch: AtomicU64::new(0),
            #[cfg(feature = "vector")]
            embedding_coverage: parking_lot::Mutex::new(None),
            #[cfg(feature = "vector")]
            embedding_coverage_scans: AtomicU64::new(0),
            #[cfg(feature = "vector")]
            embedding_queue: parking_lot::Mutex::new(RecencyQueue::default()),
            #[cfg(feature = "vector")]
            artifact_embedding_queue: parking_lot::Mutex::new(RecencyQueue::default()),
            #[cfg(feature = "vector")]
            vector_reconcile: parking_lot::Mutex::new(VectorReconcileState::default()),
            #[cfg(feature = "vector")]
            vector_sidecar_flush_throttle: parking_lot::Mutex::new(
                VectorSidecarFlushThrottle::default(),
            ),
            #[cfg(feature = "vector")]
            embed_stage_timings: crate::embed::EmbedStageTimings::default(),
            #[cfg(test)]
            merkle_flush_count: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            fail_next_transaction_derived_cleanup: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_text_rebuild: AtomicBool::new(false),
        };

        if !text_index_current {
            graph.try_rebuild_text_index_from_graph(&graph, retrieval_authority_hash)?;
        }

        Ok(graph)
    }

    fn try_rebuild_text_index_from_graph(
        &self,
        source: &InMemoryGraph,
        root_hash: [u8; 32],
    ) -> Result<(), KinDbError> {
        #[cfg(test)]
        text_index_rebuilds::record();
        let _span = tracing::info_span!("kindb.graph.rebuild_text_index_with_root_hash").entered();
        let docs = {
            let ent = source.entities.read();
            Self::collect_text_index_docs(&ent)?
        };
        self.try_rebuild_text_index_from_docs(docs, root_hash)
    }

    fn collect_text_index_docs(
        ent: &EntityData,
    ) -> Result<Vec<(RetrievalKey, Vec<(String, f32)>)>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.graph.rebuild_text_index.collect",
            entities = ent.entities.len(),
            shallow_files = ent.shallow_files.len(),
            structured_artifacts = ent.structured_artifacts.len(),
            opaque_artifacts = ent.opaque_artifacts.len()
        )
        .entered();
        let entity_docs = ent.entities.values().map(|entity| {
            let extra = collect_text_index_extra_fields(ent, &entity.id);
            let fields = if extra.is_empty() {
                crate::search::entity_fields(entity)
            } else {
                crate::search::entity_fields_with_extra(entity, &extra)
            };
            (RetrievalKey::Entity(entity.id), fields)
        });
        let artifact_docs = collect_artifact_text_index_docs(ent)?;
        Ok(entity_docs.chain(artifact_docs).collect())
    }

    fn try_rebuild_text_index_from_docs(
        &self,
        docs: Vec<(RetrievalKey, Vec<(String, f32)>)>,
        root_hash: [u8; 32],
    ) -> Result<(), KinDbError> {
        let Some(ref ti) = self.text_index else {
            self.text_dirty.store(false, Ordering::Release);
            self.text_full_rebuild_required
                .store(false, Ordering::Release);
            return Ok(());
        };
        #[cfg(test)]
        if self.fail_next_text_rebuild.swap(false, Ordering::AcqRel) {
            return Err(KinDbError::StorageError(
                "injected full text-index rebuild failure".to_string(),
            ));
        }

        {
            let _span = tracing::info_span!(
                "kindb.graph.rebuild_text_index.bulk_rebuild",
                docs = docs.len()
            )
            .entered();
            ti.rebuild_all_owned(docs)?;
        }

        {
            let _span = tracing::info_span!("kindb.graph.rebuild_text_index.commit").entered();
            ti.set_graph_root_hash(root_hash);
            ti.commit()?;
        }
        self.text_dirty.store(false, Ordering::Release);
        self.text_full_rebuild_required
            .store(false, Ordering::Release);
        Ok(())
    }

    #[inline]
    pub(crate) fn snapshot_root_hash_hint(&self) -> Option<[u8; 32]> {
        Some(self.compute_root_hash())
    }

    /// Current graph-root hash for the live entity/relation graph.
    ///
    /// This is the value a persisted vector-index sidecar must match before it
    /// can be trusted as graph-owned truth. Exposed so out-of-process callers
    /// (the daemon) can validate a sidecar against the live graph via
    /// [`SnapshotManager::load_vector_index_into_graph_if_valid`] instead of
    /// force-loading it unchecked.
    #[inline]
    pub fn snapshot_root_hash(&self) -> Option<[u8; 32]> {
        Some(self.compute_root_hash())
    }

    /// Record entities whose Merkle hashes are now stale.
    ///
    /// This only journals the touched seeds; the root is reconciled lazily by
    /// [`Self::flush_merkle`] on the next read. Deferring is what keeps bulk
    /// ingestion linear — thousands of single-relation upserts collapse into one
    /// batch Merkle build instead of one O(component) refresh apiece.
    #[inline]
    fn refresh_merkle_for_entities<I>(&self, _ent: &EntityData, seeds: I)
    where
        I: IntoIterator<Item = EntityId>,
    {
        let mut pending = self.merkle_pending.lock();
        pending.seeds.extend(seeds);
        pending.dirty = true;
    }

    /// Reconcile the deferred Merkle root against the live graph.
    ///
    /// Callers that read the root must run this first while holding a guard on
    /// `self.entities` (read or write) so the graph cannot mutate mid-refresh.
    /// `ent` is that already-held guard, passed in to avoid re-locking.
    fn flush_merkle(&self, ent: &EntityData) {
        let seeds = {
            let mut pending = self.merkle_pending.lock();
            if !pending.dirty {
                return;
            }
            pending.dirty = false;
            std::mem::take(&mut pending.seeds)
        };
        self.merkle.write().refresh_affected(ent, seeds);
        #[cfg(test)]
        self.merkle_flush_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    pub fn has_pending_delta(&self) -> bool {
        !self.pending_delta.lock().delta.is_empty()
    }

    pub fn take_pending_delta(&self, base_generation: Generation) -> Option<GraphSnapshotDelta> {
        let mut pending = self.pending_delta.lock();
        if pending.delta.is_empty() {
            return None;
        }
        let mut delta = GraphSnapshotDelta::empty(base_generation);
        std::mem::swap(&mut pending.delta, &mut delta);
        delta.base_generation = base_generation;
        Some(delta)
    }

    pub fn clear_pending_delta(&self) {
        self.pending_delta.lock().delta = GraphSnapshotDelta::empty(0);
    }

    pub fn pending_delta_snapshot(
        &self,
        base_generation: Generation,
    ) -> Option<GraphSnapshotDelta> {
        let pending = self.pending_delta.lock();
        if pending.delta.is_empty() {
            return None;
        }
        let mut delta = pending.delta.clone();
        delta.base_generation = base_generation;
        Some(delta)
    }

    /// Detach the currently pending delta for one backend write.
    ///
    /// Mutations arriving after this call are recorded in a fresh pending
    /// buffer. Call [`complete_persistence`](Self::complete_persistence) after
    /// the backend has durably committed the returned delta, or
    /// [`fail_persistence`](Self::fail_persistence) if it did not commit.
    pub fn begin_delta_persistence(
        &self,
        base_generation: Generation,
    ) -> Option<(GraphSnapshotDelta, PersistenceEpoch)> {
        let mut pending = self.pending_delta.lock();
        if pending.delta.is_empty() {
            return None;
        }
        let mut delta = GraphSnapshotDelta::empty(base_generation);
        std::mem::swap(&mut pending.delta, &mut delta);
        delta.base_generation = base_generation;
        let epoch = pending.begin_persistence();
        Some((delta, epoch))
    }

    /// Acknowledge one detached persistence batch after its authority commit.
    pub fn complete_persistence(&self, epoch: PersistenceEpoch) -> bool {
        self.pending_delta
            .lock()
            .in_flight_persistence
            .remove(&epoch.0)
    }

    /// Retire a failed detached persistence batch and force the next retry to
    /// serialize the complete live graph. The live graph still contains every
    /// mutation from the failed batch, while later mutations remain isolated in
    /// the fresh pending buffer.
    pub fn fail_persistence(&self, epoch: PersistenceEpoch) -> bool {
        let mut pending = self.pending_delta.lock();
        let removed = pending.in_flight_persistence.remove(&epoch.0);
        self.full_snapshot_required.store(true, Ordering::Release);
        removed
    }

    /// Persist derived sidecars only while the live graph is still exactly the
    /// state captured by `epoch` and `expected_root_hash`.
    ///
    /// All graph read guards and the pending-delta fence are held through the
    /// text rebuild and `persist_additional`. This uses the already-held entity
    /// guard to materialize text documents, avoiding both a recursive read lock
    /// and a second full `GraphSnapshot` allocation for large repositories.
    pub(crate) fn persist_derived_sidecars_for_epoch<T>(
        &self,
        epoch: PersistenceEpoch,
        expected_root_hash: [u8; 32],
        expected_retrieval_authority_hash: [u8; 32],
        persist_additional: impl FnOnce([u8; 32]) -> Result<T, KinDbError>,
    ) -> Result<bool, KinDbError> {
        let ent = self.entities.read();
        let chg = self.changes.read();
        let _wrk = self.work.read();
        let _rev = self.reviews.read();
        let _ver = self.verification.read();
        let _prv = self.provenance.read();
        let _ses = self.sessions.read();
        let pending = self.pending_delta.lock();
        self.flush_merkle(&ent);
        let current_root_hash = self.merkle.read().root_hash();
        let current_retrieval_authority_hash = compute_live_retrieval_authority_hash(
            current_root_hash,
            &ent.entities,
            &ent.relations,
            &chg.changes,
            &ent.entity_revisions,
            &ent.external_references,
            &ent.resolved_tree,
            &ent.shallow_files,
            &ent.file_layouts,
            &ent.structured_artifacts,
            &ent.opaque_artifacts,
        );
        let exact = current_root_hash == expected_root_hash
            && current_retrieval_authority_hash == expected_retrieval_authority_hash
            && pending.in_flight_persistence.contains(&epoch.0)
            && pending.delta.is_empty()
            && !self.full_snapshot_required.load(Ordering::Acquire);
        if !exact {
            return Ok(false);
        }
        let docs = Self::collect_text_index_docs(&ent)?;
        self.try_rebuild_text_index_from_docs(docs, expected_retrieval_authority_hash)?;
        persist_additional(expected_retrieval_authority_hash)?;
        Ok(true)
    }

    /// Commit any staged live text for current-process query coherence while
    /// stamping the persisted index as deliberately non-authoritative. A cold
    /// reopen will rebuild it from graph truth rather than accept a mixed epoch.
    pub(crate) fn invalidate_persisted_text_index(&self) -> Result<(), KinDbError> {
        if self.text_full_rebuild_required.load(Ordering::Acquire) {
            // The successful rebuild clears this flag. Preserve it on error so
            // a retry cannot stamp a still-stale live index as invalid-but-
            // coherent without first applying relation-derived text changes.
            return self.try_rebuild_text_index_from_graph(self, [0u8; 32]);
        }
        if let Some(ref ti) = self.text_index {
            ti.set_graph_root_hash([0u8; 32]);
            ti.commit()?;
        }
        self.text_dirty.store(false, Ordering::Release);
        Ok(())
    }

    pub fn full_snapshot_required(&self) -> bool {
        self.full_snapshot_required.load(Ordering::Acquire)
    }

    /// Whether graph truth contains work that has not yet been acknowledged by
    /// durable authority. This includes mutations waiting in the active delta,
    /// a detached batch still in backend I/O, and a forced full-snapshot retry.
    pub fn has_unpersisted_changes(&self) -> bool {
        let pending = self.pending_delta.lock();
        self.full_snapshot_required.load(Ordering::Acquire)
            || !pending.delta.is_empty()
            || !pending.in_flight_persistence.is_empty()
    }

    pub fn clear_full_snapshot_required(&self) {
        self.full_snapshot_required.store(false, Ordering::Release);
    }

    fn require_full_snapshot(&self) {
        let _pending = self.pending_delta.lock();
        self.full_snapshot_required.store(true, Ordering::Release);
    }

    fn record_entity_delta_upsert(&self, entity: Entity) {
        let mut pending = self.pending_delta.lock();
        delta_map_upsert(&mut pending.delta.entities, entity.id, entity);
    }

    fn record_entity_delta_remove(&self, entity_id: EntityId) {
        let mut pending = self.pending_delta.lock();
        delta_map_remove(&mut pending.delta.entities, entity_id);
        delta_map_remove(&mut pending.delta.entity_revisions, entity_id);
    }

    fn record_relation_delta_upsert(&self, ent: &EntityData, relation: Relation) {
        let mut pending = self.pending_delta.lock();
        delta_map_upsert(&mut pending.delta.relations, relation.id, relation.clone());
        record_relation_edge_delta(&mut pending, ent, &relation);
    }

    fn record_relation_delta_remove(&self, ent: &EntityData, relation: &Relation) {
        let mut pending = self.pending_delta.lock();
        delta_map_remove(&mut pending.delta.relations, relation.id);
        record_relation_edge_delta(&mut pending, ent, relation);
    }

    fn record_shallow_file_delta_upsert(
        &self,
        old: Option<ShallowTrackedFile>,
        new: ShallowTrackedFile,
    ) {
        let mut pending = self.pending_delta.lock();
        delta_vec_upsert_by_key(&mut pending.delta.shallow_files, old, new, |file| {
            file.file_id.clone()
        });
    }

    fn record_shallow_file_delta_remove(
        &self,
        old: Option<ShallowTrackedFile>,
        file_id: FilePathId,
    ) {
        let mut pending = self.pending_delta.lock();
        delta_vec_remove_by_key(&mut pending.delta.shallow_files, old, file_id, |file| {
            file.file_id.clone()
        });
    }

    fn record_file_layout_delta_upsert(&self, old: Option<FileLayout>, new: FileLayout) {
        let mut pending = self.pending_delta.lock();
        delta_vec_upsert_by_key(&mut pending.delta.file_layouts, old, new, |layout| {
            layout.file_id.clone()
        });
    }

    fn record_file_layout_delta_remove(&self, old: Option<FileLayout>, file_id: FilePathId) {
        let mut pending = self.pending_delta.lock();
        delta_vec_remove_by_key(&mut pending.delta.file_layouts, old, file_id, |layout| {
            layout.file_id.clone()
        });
    }

    fn record_structured_artifact_delta_upsert(
        &self,
        old: Option<StructuredArtifact>,
        new: StructuredArtifact,
    ) {
        let mut pending = self.pending_delta.lock();
        delta_vec_upsert_by_key(
            &mut pending.delta.structured_artifacts,
            old,
            new,
            |artifact| artifact.file_id.clone(),
        );
    }

    fn record_structured_artifact_delta_remove(
        &self,
        old: Option<StructuredArtifact>,
        file_id: FilePathId,
    ) {
        let mut pending = self.pending_delta.lock();
        delta_vec_remove_by_key(
            &mut pending.delta.structured_artifacts,
            old,
            file_id,
            |artifact| artifact.file_id.clone(),
        );
    }

    fn record_opaque_artifact_delta_upsert(
        &self,
        old: Option<OpaqueArtifact>,
        new: OpaqueArtifact,
    ) {
        let mut pending = self.pending_delta.lock();
        delta_vec_upsert_by_key(&mut pending.delta.opaque_artifacts, old, new, |artifact| {
            artifact.file_id.clone()
        });
    }

    fn record_opaque_artifact_delta_remove(
        &self,
        old: Option<OpaqueArtifact>,
        file_id: FilePathId,
    ) {
        let mut pending = self.pending_delta.lock();
        delta_vec_remove_by_key(
            &mut pending.delta.opaque_artifacts,
            old,
            file_id,
            |artifact| artifact.file_id.clone(),
        );
    }

    fn refresh_text_index_for_entities(&self, entity_ids: &[EntityId]) {
        let Some(ref ti) = self.text_index else {
            return;
        };

        let docs: Vec<(Entity, Vec<(String, f32)>)> = {
            let ent = self.entities.read();
            entity_ids
                .iter()
                .filter_map(|entity_id| {
                    ent.entities.get(entity_id).map(|entity| {
                        (
                            entity.clone(),
                            collect_text_index_extra_fields(&ent, entity_id),
                        )
                    })
                })
                .collect()
        };

        let batch: Vec<(&Entity, &[(String, f32)])> =
            docs.iter().map(|(e, f)| (e, f.as_slice())).collect();
        if let Err(error) = ti.upsert_with_extra_fields_batch(batch) {
            self.quarantine_text_index_after_authority_commit(
                "refreshing affected entity documents",
                &error,
            );
            return;
        }

        if !entity_ids.is_empty() {
            self.text_dirty.store(true, Ordering::Release);
        }
    }

    fn quarantine_text_index_after_authority_commit(
        &self,
        operation: &'static str,
        error: &KinDbError,
    ) {
        self.text_full_rebuild_required
            .store(true, Ordering::Release);
        self.text_dirty.store(true, Ordering::Release);
        tracing::error!(
            operation,
            error = %error,
            "derived text index failed after graph authority committed; quarantined for full rebuild"
        );
    }

    #[cfg(feature = "vector")]
    fn quarantine_vector_index_after_authority_commit(
        &self,
        operation: &'static str,
        error: &KinDbError,
    ) {
        tracing::error!(
            operation,
            error = %error,
            "derived vector index failed after graph authority committed; reset and queued for full rebuild"
        );
        self.reset_vector_index();
        self.queue_all_for_embedding();
        self.queue_all_artifacts_for_embedding();
        self.mark_vector_full_reconcile();
    }

    #[cfg(not(feature = "vector"))]
    fn quarantine_vector_index_after_authority_commit(
        &self,
        _operation: &'static str,
        _error: &KinDbError,
    ) {
    }

    fn upsert_retrievable_text_index(
        &self,
        key: RetrievalKey,
        fields: &[(String, f32)],
    ) -> Result<(), KinDbError> {
        let Some(ref ti) = self.text_index else {
            return Ok(());
        };

        let field_refs: Vec<(&str, f32)> = fields
            .iter()
            .map(|(text, weight)| (text.as_str(), *weight))
            .collect();
        ti.upsert_retrievable(key, &field_refs)?;
        self.text_dirty.store(true, Ordering::Release);
        Ok(())
    }

    fn remove_retrievable_text_index(&self, key: &RetrievalKey) -> Result<(), KinDbError> {
        let Some(ref ti) = self.text_index else {
            return Ok(());
        };

        ti.remove_retrievable(key)?;
        self.text_dirty.store(true, Ordering::Release);
        Ok(())
    }

    #[cfg(feature = "vector")]
    fn remove_retrievable_vector(&self, key: &RetrievalKey) -> Result<(), KinDbError> {
        if let Some(ref vi) = *self.vector_index.lock() {
            vi.remove_retrievable(key)?;
        }
        Ok(())
    }

    #[cfg(not(feature = "vector"))]
    fn remove_retrievable_vector(&self, _key: &RetrievalKey) -> Result<(), KinDbError> {
        Ok(())
    }

    #[cfg(feature = "vector")]
    fn invalidate_entities_for_embedding(&self, entity_ids: &[EntityId]) -> Result<(), KinDbError> {
        if entity_ids.is_empty() {
            return Ok(());
        }

        // Dedup, then SORT before removal. The removal order feeds the vector
        // index's free-list, and a `HashSet` iterates in per-process-random
        // order — so an unsorted remove sequence makes the HNSW slot history
        // (and thus live-search results) vary run to run. Sorting fixes the
        // remove/enqueue order deterministically.
        let mut unique_ids: Vec<EntityId> = entity_ids
            .iter()
            .copied()
            .collect::<HashSet<EntityId>>()
            .into_iter()
            .collect();
        unique_ids.sort();
        for entity_id in &unique_ids {
            self.remove_retrievable_vector(&RetrievalKey::Entity(*entity_id))?;
        }
        // Live mutation path: these entities changed this sync, so enqueue them
        // as `ChangedThisSync` (the highest recency tier) rather than backfill.
        let mut queue = self.embedding_queue.lock();
        for entity_id in &unique_ids {
            queue.insert_graph_priority_changed(
                RetrievalKey::Entity(*entity_id),
                EmbedRecency::ChangedThisSync,
            );
        }
        Ok(())
    }

    #[cfg(not(feature = "vector"))]
    fn invalidate_entities_for_embedding(
        &self,
        _entity_ids: &[EntityId],
    ) -> Result<(), KinDbError> {
        Ok(())
    }

    #[cfg(feature = "vector")]
    fn invalidate_artifact_for_embedding(&self, artifact_id: ArtifactId) -> Result<(), KinDbError> {
        self.remove_retrievable_vector(&RetrievalKey::Artifact(artifact_id))?;
        // Live mutation path: changed-this-sync recency.
        self.artifact_embedding_queue
            .lock()
            .insert(artifact_id, EmbedRecency::ChangedThisSync);
        Ok(())
    }

    #[cfg(not(feature = "vector"))]
    fn invalidate_artifact_for_embedding(
        &self,
        _artifact_id: ArtifactId,
    ) -> Result<(), KinDbError> {
        Ok(())
    }

    /// Serialize the live graph directly to snapshot bytes + Merkle root hash,
    /// without cloning the sub-stores.  Acquires read guards on all stores,
    /// computes the root hash from the live EntityData, creates a
    /// [`BorrowedGraphSnapshot`] for serialization, then drops the guards.
    ///
    /// Returns `(serialized_bytes, root_hash)`.
    pub fn serialize_snapshot_borrowed(
        &self,
    ) -> Result<(Vec<u8>, crate::storage::merkle::MerkleHash), KinDbError> {
        self.serialize_snapshot_borrowed_with_hash(None)
    }

    /// Like [`serialize_snapshot_borrowed`] but accepts a pre-computed root
    /// hash.  When `Some`, the expensive Merkle DAG traversal is skipped.
    pub fn serialize_snapshot_borrowed_with_hash(
        &self,
        precomputed_hash: Option<crate::storage::merkle::MerkleHash>,
    ) -> Result<(Vec<u8>, crate::storage::merkle::MerkleHash), KinDbError> {
        let (bytes, graph_root_hash, _, _) =
            self.serialize_snapshot_borrowed_inner(precomputed_hash, false)?;
        Ok((bytes, graph_root_hash))
    }

    /// Serialize one full-snapshot persistence batch and detach every pending
    /// mutation represented by those bytes. Later mutations accumulate in a
    /// fresh buffer while backend I/O is in flight.
    pub fn begin_snapshot_persistence(
        &self,
        precomputed_hash: Option<crate::storage::merkle::MerkleHash>,
    ) -> Result<
        (
            Vec<u8>,
            crate::storage::merkle::MerkleHash,
            PersistenceEpoch,
        ),
        KinDbError,
    > {
        let (bytes, graph_root_hash, _, epoch) =
            self.serialize_snapshot_borrowed_inner(precomputed_hash, true)?;
        Ok((
            bytes,
            graph_root_hash,
            epoch.expect("persistence serialization always allocates an epoch"),
        ))
    }

    /// Capture one full-snapshot persistence batch together with both the
    /// entity/relation Merkle root and the exact authority digest used to bind
    /// retrieval sidecars.
    pub fn begin_snapshot_persistence_with_retrieval_hash(
        &self,
        precomputed_hash: Option<crate::storage::merkle::MerkleHash>,
    ) -> Result<
        (
            Vec<u8>,
            crate::storage::merkle::MerkleHash,
            crate::storage::merkle::MerkleHash,
            PersistenceEpoch,
        ),
        KinDbError,
    > {
        let (bytes, graph_root_hash, retrieval_authority_hash, epoch) =
            self.serialize_snapshot_borrowed_inner(precomputed_hash, true)?;
        Ok((
            bytes,
            graph_root_hash,
            retrieval_authority_hash,
            epoch.expect("persistence serialization always allocates an epoch"),
        ))
    }

    fn serialize_snapshot_borrowed_inner(
        &self,
        precomputed_hash: Option<crate::storage::merkle::MerkleHash>,
        begin_persistence: bool,
    ) -> Result<
        (
            Vec<u8>,
            crate::storage::merkle::MerkleHash,
            crate::storage::merkle::MerkleHash,
            Option<PersistenceEpoch>,
        ),
        KinDbError,
    > {
        let _span = tracing::info_span!(
            "kindb.graph.serialize_snapshot_borrowed_with_hash",
            precomputed_hash = precomputed_hash.is_some(),
            begin_persistence
        )
        .entered();
        use crate::storage::format::BorrowedGraphSnapshot;

        let t0 = std::time::Instant::now();
        let ent = self.entities.read();
        let chg = self.changes.read();
        let wrk = self.work.read();
        let rev = self.reviews.read();
        let ver = self.verification.read();
        let prv = self.provenance.read();
        let ses = self.sessions.read();
        validate_entity_enrichment_admission(&ent)?;
        let t_lock = t0.elapsed();

        let t1 = std::time::Instant::now();
        let graph_root_hash = {
            let _span =
                tracing::info_span!("kindb.graph.serialize_snapshot.compute_root_hash").entered();
            self.flush_merkle(&ent);
            let current = self.merkle.read().root_hash();
            precomputed_hash
                .filter(|hash| *hash == current)
                .unwrap_or(current)
        };
        let t_hash = t1.elapsed();
        let retrieval_authority_hash = compute_live_retrieval_authority_hash(
            graph_root_hash,
            &ent.entities,
            &ent.relations,
            &chg.changes,
            &ent.entity_revisions,
            &ent.external_references,
            &ent.resolved_tree,
            &ent.shallow_files,
            &ent.file_layouts,
            &ent.structured_artifacts,
            &ent.opaque_artifacts,
        );

        let t2 = std::time::Instant::now();
        let bytes = {
            let _span = tracing::info_span!("kindb.graph.serialize_snapshot.encode").entered();
            let borrowed = BorrowedGraphSnapshot {
                entities: &ent.entities,
                entity_revisions: &ent.entity_revisions,
                external_references: &ent.external_references,
                relations: &ent.relations,
                outgoing: &ent.outgoing,
                incoming: &ent.incoming,
                resolved_tree: &ent.resolved_tree,
                shallow_files: &ent.shallow_files,
                file_layouts: &ent.file_layouts,
                structured_artifacts: &ent.structured_artifacts,
                opaque_artifacts: &ent.opaque_artifacts,
                changes: &chg.changes,
                change_children: &chg.change_children,
                work_items: &wrk.work_items,
                annotations: &wrk.annotations,
                work_links: &wrk.work_links,
                reviews: &rev.reviews,
                review_decisions: &rev.review_decisions,
                review_notes: &rev.review_notes,
                review_discussions: &rev.review_discussions,
                review_assignments: &rev.review_assignments,
                test_cases: &ver.test_cases,
                assertions: &ver.assertions,
                verification_runs: &ver.verification_runs,
                mock_hints: &ver.mock_hints,
                contracts: &ver.contracts,
                actors: &prv.actors,
                delegations: &prv.delegations,
                approvals: &prv.approvals,
                audit_events: &prv.audit_events,
                sessions: &ses.sessions,
                intents: &ses.intents,
                downstream_warnings: &ses.downstream_warnings,
            };
            borrowed.to_bytes_with_persisted_root_hash(graph_root_hash)?
        };
        let t_serialize = t2.elapsed();

        // All graph read guards are still held, so the serialized bytes and
        // detached mutation buffer describe one exact graph state. A writer
        // cannot mutate graph truth until this function returns; mutations
        // arriving afterwards land in the new pending buffer.
        let persistence_epoch = begin_persistence.then(|| {
            let mut pending = self.pending_delta.lock();
            pending.delta = GraphSnapshotDelta::empty(0);
            self.full_snapshot_required.store(false, Ordering::Release);
            pending.begin_persistence()
        });

        tracing::debug!(
            lock_ms = t_lock.as_secs_f64() * 1000.0,
            root_hash_ms = t_hash.as_secs_f64() * 1000.0,
            serialize_ms = t_serialize.as_secs_f64() * 1000.0,
            bytes = bytes.len(),
            "kindb.save_timer"
        );

        Ok((
            bytes,
            graph_root_hash,
            retrieval_authority_hash,
            persistence_epoch,
        ))
    }

    /// Return the exact authority digest that persisted lexical/vector
    /// sidecars must match before they can answer queries.
    #[cfg(any(feature = "vector", test))]
    pub(crate) fn retrieval_authority_hash(&self) -> [u8; 32] {
        let ent = self.entities.read();
        let chg = self.changes.read();
        self.flush_merkle(&ent);
        let graph_root_hash = self.merkle.read().root_hash();
        compute_live_retrieval_authority_hash(
            graph_root_hash,
            &ent.entities,
            &ent.relations,
            &chg.changes,
            &ent.entity_revisions,
            &ent.external_references,
            &ent.resolved_tree,
            &ent.shallow_files,
            &ent.file_layouts,
            &ent.structured_artifacts,
            &ent.opaque_artifacts,
        )
    }

    /// Return a snapshot of the exact graph-owned repository tree.
    pub fn resolved_tree(&self) -> ResolvedTree {
        self.entities.read().resolved_tree.clone()
    }

    /// Resolve a byte-exact repository path to its admitted artifact identity.
    pub fn artifact_id_at_path(&self, path: &RepoPath) -> Option<ArtifactId> {
        self.entities.read().resolved_tree.artifact_id_at_path(path)
    }

    /// Resolve an admitted artifact identity to its exact tree record.
    pub fn resolved_artifact(&self, id: &ArtifactId) -> Option<ResolvedArtifact> {
        self.entities.read().resolved_tree.get(id).cloned()
    }

    /// Resolve an admitted artifact identity to its byte-exact path.
    pub fn repo_path_for_artifact_id(&self, id: &ArtifactId) -> Option<RepoPath> {
        self.entities
            .read()
            .resolved_tree
            .get(id)
            .map(|artifact| artifact.path.clone())
    }

    fn require_artifact_id(&self, path: &FilePathId) -> Result<ArtifactId, KinDbError> {
        let repo_path = repo_path_for_file_path(path)?;
        self.artifact_id_at_path(&repo_path).ok_or_else(|| {
            KinDbError::StorageError(format!(
                "semantic enrichment requires an admitted repository artifact at {}",
                path.0
            ))
        })
    }

    /// Return all entity→entity edges in a single lock acquisition.
    ///
    /// Each entry is `(src_entity_id, relation_kind, dst_entity_id, confidence)`.
    /// Used by [`ReadIndex::from_graph`] to avoid 20K+ per-entity lock acquisitions.
    pub fn list_all_entity_edges(&self) -> Vec<(EntityId, RelationKind, EntityId, f32)> {
        let ent = self.entities.read();
        let mut edges = Vec::with_capacity(ent.relations.len());
        for rel in ent.relations.values() {
            if let (Some(src), Some(dst)) = (rel.src.as_entity(), rel.dst.as_entity()) {
                edges.push((src, rel.kind, dst, rel.confidence));
            }
        }
        edges
    }

    /// Resolve one persisted external symbol coordinate by its stable ID.
    pub fn get_external_reference(&self, id: &ExternalReferenceId) -> Option<ExternalReference> {
        self.entities.read().external_references.get(id).cloned()
    }

    /// Return every persisted external symbol coordinate.
    pub fn list_external_references(&self) -> Vec<ExternalReference> {
        let mut references: Vec<_> = self
            .entities
            .read()
            .external_references
            .values()
            .cloned()
            .collect();
        references.sort_unstable_by_key(|reference| reference.id);
        references
    }

    /// Whether two graphs agree on the semantic workspace: live entities, live
    /// relations, and the resolved tree.
    ///
    /// The obvious way to write this from outside the crate is to `to_snapshot`
    /// both sides and compare the three fields, and that is what the commit
    /// reply path did. A snapshot deep-clones every sub-store, including the
    /// entity revision history and the audit log, both of which grow with every
    /// commit a repository has ever taken, so comparing three maps cost two
    /// whole-graph clones per call. The reply path compares twice, which is four
    /// clones of everything, after the change is already durable.
    ///
    /// Reading the three fields under their own lock clones none of them. The
    /// comparison itself is unchanged: the same three fields, by value, both
    /// hash maps and therefore order-independent.
    ///
    /// Comparing a graph with itself short-circuits rather than taking the same
    /// lock twice, since a second read acquisition behind a waiting writer is a
    /// deadlock rather than a re-entrant read.
    pub fn semantic_workspace_matches(&self, other: &InMemoryGraph) -> bool {
        if std::ptr::eq(self, other) {
            return true;
        }
        let left = self.entities.read();
        let right = other.entities.read();
        left.entities == right.entities
            && left.relations == right.relations
            && left.resolved_tree == right.resolved_tree
    }

    pub fn to_snapshot(&self) -> GraphSnapshot {
        // Clone each sub-store under its own read lock, then drop the lock
        // immediately. Lock ordering: entities → changes → work → reviews
        // → verification → provenance → sessions.
        let ent = self.entities.read().clone();
        let chg = self.changes.read().clone();
        let wrk = self.work.read().clone();
        let rev = self.reviews.read().clone();
        let ver = self.verification.read().clone();
        let prv = self.provenance.read().clone();
        let ses = self.sessions.read().clone();

        Self::snapshot_from_stores(ent, chg, wrk, rev, ver, prv, ses)
    }

    /// Export this graph as a snapshot by consuming it.
    ///
    /// Identical in value to [`to_snapshot`] and different in cost. That one
    /// clones every store under its own read lock and then converts the clone,
    /// so a caller with no further use for the graph paid for a second copy of
    /// everything the snapshot was about to carry and held both across
    /// whatever it did next. This moves each store out instead, so the payload
    /// is rehashed into the snapshot's map type and never duplicated. Use it
    /// wherever the export is the graph's last reader; use `to_snapshot` where
    /// the graph goes on being queried.
    ///
    /// [`to_snapshot`]: Self::to_snapshot
    pub(crate) fn into_snapshot(self) -> GraphSnapshot {
        Self::snapshot_from_stores(
            self.entities.into_inner(),
            self.changes.into_inner(),
            self.work.into_inner(),
            self.reviews.into_inner(),
            self.verification.into_inner(),
            self.provenance.into_inner(),
            self.sessions.into_inner(),
        )
    }

    /// The one place a snapshot is assembled out of the seven stores, so a
    /// borrowed export and a consuming one cannot describe different graphs.
    fn snapshot_from_stores(
        ent: EntityData,
        chg: ChangeData,
        wrk: WorkData,
        rev: ReviewData,
        ver: VerificationData,
        prv: ProvenanceData,
        ses: SessionData,
    ) -> GraphSnapshot {
        GraphSnapshot {
            version: GraphSnapshot::CURRENT_VERSION,
            entities: ent.entities.into_iter().collect(),
            entity_revisions: ent.entity_revisions.into_iter().collect(),
            relations: ent.relations.into_iter().collect(),
            outgoing: ent.outgoing.into_iter().collect(),
            incoming: ent.incoming.into_iter().collect(),
            resolved_tree: ent.resolved_tree,
            shallow_files: ent.shallow_files.into_values().collect(),
            file_layouts: ent.file_layouts.into_values().collect(),
            structured_artifacts: ent.structured_artifacts.into_values().collect(),
            opaque_artifacts: ent.opaque_artifacts.into_values().collect(),
            changes: chg.changes.into_iter().collect(),
            change_children: chg.change_children.into_iter().collect(),
            work_items: wrk.work_items.into_iter().collect(),
            annotations: wrk.annotations.into_iter().collect(),
            work_links: wrk.work_links,
            reviews: rev.reviews.into_iter().collect(),
            review_decisions: rev.review_decisions.into_iter().collect(),
            review_notes: rev.review_notes.into_values().collect(),
            review_discussions: rev.review_discussions.into_values().collect(),
            review_assignments: rev.review_assignments.into_iter().collect(),
            test_cases: ver.test_cases.into_iter().collect(),
            assertions: ver.assertions.into_iter().collect(),
            verification_runs: ver.verification_runs.into_iter().collect(),
            mock_hints: ver.mock_hints,
            contracts: ver.contracts.into_iter().collect(),
            actors: prv.actors.into_iter().collect(),
            delegations: prv.delegations,
            approvals: prv.approvals,
            audit_events: prv.audit_events,
            sessions: ses.sessions.into_iter().collect(),
            intents: ses.intents.into_iter().collect(),
            downstream_warnings: ses.downstream_warnings,
            repository_authority: None,
            external_references: ent.external_references.into_iter().collect(),
        }
    }

    /// Export exactly the domains a workspace comparison reads, by consuming
    /// this graph.
    ///
    /// Identical in value to calling [`to_snapshot`] and keeping four of its
    /// fields, and very different in cost. `to_snapshot` clones every store
    /// under its own lock, so a caller that wanted entity truth also paid for
    /// a copy of the whole change map, the work, review, verification,
    /// provenance and session domains, and every adjacency and secondary index
    /// on the entity store, and then held all of it beside the four domains it
    /// actually read. This moves the entity store out and rehashes four of its
    /// maps into the snapshot's map type, copying no payload at all and
    /// freeing everything else at the call.
    ///
    /// [`to_snapshot`]: Self::to_snapshot
    pub(crate) fn into_workspace_graph_facts(self) -> crate::storage::format::WorkspaceGraphFacts {
        let ent = self.entities.into_inner();
        crate::storage::format::WorkspaceGraphFacts {
            entities: ent.entities.into_iter().collect(),
            relations: ent.relations.into_iter().collect(),
            external_references: ent.external_references.into_iter().collect(),
            resolved_tree: ent.resolved_tree,
        }
    }

    /// Compute the Merkle root hash directly from the live entity stores,
    /// without materialising a full `GraphSnapshot`.
    pub fn compute_root_hash(&self) -> crate::storage::merkle::MerkleHash {
        let ent = self.entities.read();
        self.flush_merkle(&ent);
        self.merkle.read().root_hash()
    }

    /// Recompute the canonical Merkle root hash directly from the live entity
    /// stores. This is the cold verification reference and does not replace the
    /// continuously-maintained live root.
    pub fn recompute_root_hash(&self) -> crate::storage::merkle::MerkleHash {
        let ent = self.entities.read();
        compute_root_hash_generic(&*ent, None)
    }

    /// Take the entity write lock through the guard that bumps the truth epoch.
    ///
    /// This is the only write path to [`EntityData`] in the engine, which is
    /// what makes [`InMemoryGraph::truth_epoch`] a complete record of truth
    /// movement. See [`TruthWriteGuard`].
    fn entities_write(&self) -> TruthWriteGuard<'_> {
        TruthWriteGuard {
            guard: Some(self.entities.write()),
            epoch: &self.truth_epoch,
        }
    }

    /// Number of entities in the graph.
    pub fn entity_count(&self) -> usize {
        self.entities.read().entities.len()
    }

    /// Number of relations in the graph.
    pub fn relation_count(&self) -> usize {
        self.entities.read().relations.len()
    }

    /// Return incoming and outgoing relations for any graph node.
    ///
    /// The `EntityStore` relation APIs intentionally expose entity-only edges.
    /// Locate and graph-native diagnostics also need artifact/module edges such
    /// as file includes, so they use this concrete mixed-node accessor.
    pub fn get_all_relations_for_node(
        &self,
        node: &GraphNodeId,
    ) -> Result<Vec<Relation>, KinDbError> {
        let ent = self.entities.read();
        let mut result = Vec::new();
        let mut seen = hashbrown::HashSet::new();

        if let Some(edge_ids) = ent.node_outgoing.get(node) {
            for rid in edge_ids {
                if let Some(rel) = ent.relations.get(rid) {
                    if seen.insert(rel.id) {
                        result.push(rel.clone());
                    }
                }
            }
        }

        if let Some(edge_ids) = ent.node_incoming.get(node) {
            for rid in edge_ids {
                if let Some(rel) = ent.relations.get(rid) {
                    if seen.insert(rel.id) {
                        result.push(rel.clone());
                    }
                }
            }
        }

        Ok(result)
    }

    /// Number of graph-owned non-entity retrievables.
    pub fn artifact_count(&self) -> usize {
        let ent = self.entities.read();
        ent.shallow_files.len() + ent.structured_artifacts.len() + ent.opaque_artifacts.len()
    }

    /// Collect comprehensive graph statistics for observability.
    pub fn graph_stats(&self) -> GraphStats {
        let ent = self.entities.read();
        let work = self.work.read();
        let reviews = self.reviews.read();
        let verification = self.verification.read();
        let sessions = self.sessions.read();
        let total_entities = ent.entities.len();
        let total_relations = ent.relations.len();
        let text_indexed_entity_count = self
            .text_index
            .as_ref()
            .map(|index| {
                ent.entities
                    .keys()
                    .filter(|entity_id| {
                        index.contains_retrievable(&RetrievalKey::Entity(**entity_id))
                    })
                    .count()
            })
            .unwrap_or(0);
        let embedding_status = self.embedding_status();
        #[cfg(feature = "vector")]
        let indexed_embedding_count = self
            .vector_index
            .lock()
            .as_ref()
            .map(|index| {
                ent.entities
                    .keys()
                    .filter(|entity_id| index.contains(entity_id))
                    .count()
            })
            .unwrap_or(0);
        #[cfg(not(feature = "vector"))]
        let indexed_embedding_count = 0usize;
        #[cfg(feature = "vector")]
        let pending_embedding_count = embedding_status
            .pending
            .max(total_entities.saturating_sub(indexed_embedding_count));
        #[cfg(not(feature = "vector"))]
        let pending_embedding_count = embedding_status.pending;

        let mut entity_counts = std::collections::HashMap::new();
        for entity in ent.entities.values() {
            *entity_counts
                .entry(format!("{:?}", entity.kind))
                .or_insert(0) += 1;
        }

        let mut relation_counts = std::collections::HashMap::new();
        for relation in ent.relations.values() {
            *relation_counts
                .entry(format!("{:?}", relation.kind))
                .or_insert(0) += 1;
        }

        let mut parse_completeness_counts = std::collections::HashMap::new();
        for layout in ent.file_layouts.values() {
            *parse_completeness_counts
                .entry(layout.parse_completeness.bucket().to_string())
                .or_insert(0) += 1;
        }

        let mut role_counts = std::collections::HashMap::new();
        for entity in ent.entities.values() {
            *role_counts.entry(format!("{:?}", entity.role)).or_insert(0) += 1;
        }

        GraphStats {
            total_entities,
            total_relations,
            entity_counts,
            relation_counts,
            parse_completeness_counts,
            shallow_file_count: ent.shallow_files.len(),
            file_layout_count: ent.file_layouts.len(),
            structured_artifact_count: ent.structured_artifacts.len(),
            opaque_artifact_count: ent.opaque_artifacts.len(),
            working_tree_entry_count: ent.resolved_tree.len(),
            text_indexed_entity_count,
            text_index_coverage_percent: coverage_percent(
                text_indexed_entity_count,
                total_entities,
            ),
            indexed_embedding_count,
            pending_embedding_count,
            embedding_coverage_percent: coverage_percent(indexed_embedding_count, total_entities),
            work_item_count: work.work_items.len(),
            test_case_count: verification.test_cases.len(),
            review_count: reviews.reviews.len(),
            session_count: sessions.sessions.len(),
            role_counts,
        }
    }

    /// Commit any pending text index writes and reload the reader.
    ///
    /// `upsert_entity` and `remove_entity` stage text index changes but defer
    /// the (expensive) tantivy commit. Callers should invoke this after a batch
    /// of writes so that subsequent `fuzzy_search` calls see the latest data.
    /// Calling this when the index is clean is a no-op.
    pub fn flush_text_index(&self) -> Result<(), KinDbError> {
        let _span = tracing::info_span!("kindb.flush_text_index").entered();
        // If a full rebuild was requested (e.g., after bulk relation insert),
        // do it now before committing. This regenerates all relation-derived
        // text fields in one pass instead of per-entity updates.
        if self.text_full_rebuild_required.load(Ordering::Acquire) {
            // Use a zero root hash — persist_text_index_with_root_hash sets the
            // real one. This just ensures the text content is rebuilt.
            return self.try_rebuild_text_index_from_graph(self, [0u8; 32]);
        }
        if self.text_dirty.swap(false, Ordering::AcqRel) {
            if let Some(ref ti) = self.text_index {
                if let Err(error) = ti.commit() {
                    self.text_dirty.store(true, Ordering::Release);
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    pub fn persist_text_index_with_root_hash(
        &self,
        graph_root_hash: [u8; 32],
    ) -> Result<(), KinDbError> {
        // If relation-derived fields are stale, do a full rebuild first.
        // This is set by upsert_relations_batch to amortize the cost of
        // 20K+ individual Tantivy upserts into one full rebuild at persist time.
        if self.text_full_rebuild_required.load(Ordering::Acquire) {
            return self.try_rebuild_text_index_from_graph(self, graph_root_hash);
        }

        if let Some(ref ti) = self.text_index {
            let root_hash_changed = ti.graph_root_hash() != Some(graph_root_hash);
            ti.set_graph_root_hash(graph_root_hash);
            if root_hash_changed {
                return ti.commit();
            }
            if !self.text_dirty.load(Ordering::Acquire)
                && !self.text_full_rebuild_required.load(Ordering::Acquire)
            {
                return Ok(());
            }
        }
        self.flush_text_index()
    }

    /// Full-text search across entity names, signatures, and file paths.
    ///
    /// Returns up to `limit` matching `(RetrievalKey, score)` pairs ranked by
    /// tantivy BM25 relevance. Returns an empty vec when no text index is
    /// available (e.g. the graph was built without one).
    pub fn text_search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<(RetrievalKey, f32)>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.text_search",
            query = %query,
            limit = limit
        )
        .entered();
        let Some(ref text_index) = self.text_index else {
            return Ok(Vec::new());
        };
        if self.text_full_rebuild_required.load(Ordering::Acquire) {
            return Err(KinDbError::StorageError(
                "derived text index is quarantined pending a full graph-authority rebuild"
                    .to_string(),
            ));
        }
        text_index.fuzzy_search(query, limit)
    }

    /// Document frequency of `term` in the text index (its rarest token's
    /// posting count), for IDF-style term-discrimination weighting by callers.
    /// Returns 0 when there is no text index or the term is unindexed.
    pub fn text_doc_frequency(&self, term: &str) -> usize {
        if self.text_full_rebuild_required.load(Ordering::Acquire) {
            return 0;
        }
        match self.text_index {
            Some(ref ti) => ti.doc_frequency(term),
            None => 0,
        }
    }

    /// Number of documents currently visible to text search (the N for IDF).
    /// Returns 0 when there is no text index.
    pub fn text_document_count(&self) -> usize {
        if self.text_full_rebuild_required.load(Ordering::Acquire) {
            return 0;
        }
        match self.text_index {
            Some(ref ti) => ti.live_document_count(),
            None => 0,
        }
    }

    pub fn resolve_retrieval_key(&self, key: &RetrievalKey) -> Option<ResolvedRetrievalItem> {
        let ent = self.entities.read();
        match key {
            RetrievalKey::Entity(entity_id) => ent
                .entities
                .get(entity_id)
                .cloned()
                .map(ResolvedRetrievalItem::Entity),
            RetrievalKey::EntityRevision(rev_id) => ent
                .entity_revisions
                .values()
                .flat_map(|revisions| revisions.iter())
                .find(|rev| rev.revision_id == *rev_id)
                .map(|rev| ResolvedRetrievalItem::Entity(rev.entity.clone())),
            RetrievalKey::Artifact(artifact_id) => {
                let file_path = file_path_for_repo_path(&ent.resolved_tree.get(artifact_id)?.path)?;
                ent.shallow_files
                    .get(&file_path)
                    .cloned()
                    .map(ResolvedRetrievalItem::ShallowFile)
                    .or_else(|| {
                        ent.structured_artifacts
                            .get(&file_path)
                            .cloned()
                            .map(ResolvedRetrievalItem::StructuredArtifact)
                    })
                    .or_else(|| {
                        ent.opaque_artifacts
                            .get(&file_path)
                            .cloned()
                            .map(ResolvedRetrievalItem::OpaqueArtifact)
                    })
            }
            RetrievalKey::ArtifactRevision(rev_id) => {
                let chg = self.changes.read();
                let revision = find_artifact_revision(chg.changes.iter(), *rev_id)?;
                let file_id = file_path_for_repo_path(&revision.path)?;
                let syntax_hash = revision.entry.blob_identity()?;
                Some(ResolvedRetrievalItem::ShallowFile(ShallowTrackedFile {
                    file_id,
                    language_hint: String::new(),
                    declaration_count: 0,
                    import_count: 0,
                    syntax_hash,
                    signature_hash: None,
                    declaration_names: vec![],
                    import_paths: vec![],
                }))
            }
        }
    }

    /// Get or lazily initialize the code embedder.
    ///
    /// Downloads the model from HuggingFace on first call (~270 MB).
    /// Subsequent calls return the cached instance.
    #[cfg(feature = "embeddings")]
    fn get_embedder(&self) -> Result<Arc<CodeEmbedder>, KinDbError> {
        let mut guard = self.embedder.lock();
        if let Some(ref e) = *guard {
            return Ok(Arc::clone(e));
        }
        let embedder = Arc::new(CodeEmbedder::new()?);
        *guard = Some(Arc::clone(&embedder));
        Ok(embedder)
    }

    /// Get or lazily initialize the HNSW vector index, self-healing a
    /// stale-dimension index in the process.
    ///
    /// This is the single sanctioned entry point to the in-memory vector index:
    /// the embed worker, semantic search, and every other caller reach it only
    /// through here. That is what lets the dimension-mismatch recovery be
    /// **exactly once**. When a persisted index of the wrong dimension is loaded
    /// against the live embedder (e.g. an older 384-dim `graph.kvec` vs a
    /// 768-dim model), the detect → reset → recreate steps all run under a
    /// single `vector_index` lock acquisition, so a racing caller can never
    /// observe the stale index and fire its own reset + full requeue. The old
    /// drop-the-guard-then-reset pattern allowed exactly that race, churning the
    /// embedding queue and pinning CPU; keeping the reset atomic is the kin-db
    /// side of the embed-worker dimension-loop contract.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    fn get_vector_index(&self) -> Result<Arc<VectorIndex>, KinDbError> {
        let embedder = self.get_embedder()?;
        let mut guard = self.vector_index.lock();

        let mut did_reset = false;
        if let Some(ref vi) = *guard {
            if vi.dimensions() == embedder.dimensions() {
                return Ok(Arc::clone(vi));
            }
            tracing::warn!(
                "LOUD WARNING: Vector index dimensions ({}) do not match embedder dimensions ({})! Resetting and re-queueing missing.",
                vi.dimensions(),
                embedder.dimensions()
            );
            // Inline reset under the held guard. Do NOT call
            // `self.reset_vector_index()` here: it re-locks `self.vector_index`
            // and would deadlock. Clearing in place keeps the swap atomic.
            *guard = None;
            did_reset = true;
        }

        let vi = Arc::new(VectorIndex::new(embedder.dimensions())?);
        *guard = Some(Arc::clone(&vi));
        drop(guard);

        if did_reset {
            // `queue_missing_*` lock `embedding_queue` + `entities` (never
            // `vector_index`), so they are safe to call now that the guard is
            // released. The fresh empty index reports every entity/artifact as
            // missing, re-queueing a full rebuild at the live embedder
            // dimension — and this runs once, only on the resetting caller.
            self.queue_missing_for_embedding();
            self.queue_missing_artifacts_for_embedding();
        }

        Ok(vi)
    }

    /// Embed specific entities and insert their vectors into the HNSW index.
    ///
    /// Called by explicit embedding flows when the vector index needs to be
    /// built or refreshed in-process.
    ///
    /// Returns the number of entities embedded.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    fn embed_entities(&self, entity_ids: &[EntityId]) -> Result<usize, KinDbError> {
        let _span =
            tracing::info_span!("kindb.embed_entities", entity_ids = entity_ids.len()).entered();
        use crate::embed::format_graph_entity_text_with_context;

        if entity_ids.is_empty() {
            return Ok(0);
        }

        let embedder = self.get_embedder()?;
        let vi = self.get_vector_index()?;

        // Collect text representations under read lock, then drop before inference.
        let entity_data: Vec<(EntityId, String)> = {
            let ent = self.entities.read();
            entity_ids
                .iter()
                .filter_map(|id| {
                    ent.entities.get(id).map(|e| {
                        let context_lines = collect_embedding_context_lines(&ent, id);
                        let text = format_graph_entity_text_with_context(e, &context_lines);
                        (e.id, text)
                    })
                })
                .collect()
        };

        if entity_data.is_empty() {
            return Ok(0);
        }

        let batch_size = default_embedding_batch_size();
        let mut count = 0;
        for chunk in entity_data.chunks(batch_size) {
            let texts: Vec<String> = chunk.iter().map(|(_, t)| t.clone()).collect();
            let vectors = embedder.embed_batch(&texts)?;
            for ((id, _), vec) in chunk.iter().zip(vectors.iter()) {
                vi.upsert(*id, vec)?;
                count += 1;
            }
        }

        Ok(count)
    }

    /// Batch-embed all entities in the graph.
    ///
    /// Convenience method that embeds every entity. Useful for initial
    /// indexing or rebuilding the vector index from scratch.
    ///
    /// Returns the number of entities embedded.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn build_embeddings(&self) -> Result<usize, KinDbError> {
        let _span = tracing::info_span!("kindb.build_embeddings").entered();
        let mut all_ids: Vec<EntityId> = {
            let ent = self.entities.read();
            ent.entities.keys().copied().collect()
        };
        // `entities.keys()` iterates in per-process HashMap order; embedding (and
        // therefore inserting into the order-sensitive HNSW) in that order builds a
        // different graph each run. Sort so a from-scratch build is byte-identical
        // across processes. (The incremental daemon path drains via the globally
        // sorted `EmbedSortKey`; this is the from-scratch/backfill convenience.)
        all_ids.sort_unstable();
        self.embed_entities(&all_ids)
    }

    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn build_embeddings(&self) -> Result<usize, KinDbError> {
        Ok(0)
    }

    /// Embed arbitrary retrieval documents and upsert them into the vector index.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn embed_retrievable_texts(
        &self,
        docs: &[(RetrievalKey, String)],
        batch_size: usize,
    ) -> Result<usize, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.embed_retrievable_texts",
            docs = docs.len(),
            batch_size = batch_size
        )
        .entered();
        if docs.is_empty() {
            return Ok(0);
        }

        let embedder = self.get_embedder()?;
        let vi = self.get_vector_index()?;
        let batch_size = batch_size.max(1);
        let mut count = 0usize;

        for chunk in docs.chunks(batch_size) {
            let texts: Vec<String> = chunk.iter().map(|(_, text)| text.clone()).collect();
            let vectors = embedder.embed_batch(&texts)?;
            for ((key, _), vector) in chunk.iter().zip(vectors.iter()) {
                vi.upsert_retrievable(*key, vector)?;
                count += 1;
            }
        }

        Ok(count)
    }

    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn embed_retrievable_texts(
        &self,
        _docs: &[(RetrievalKey, String)],
        _batch_size: usize,
    ) -> Result<usize, KinDbError> {
        Ok(0)
    }

    /// Load persisted HNSW bytes for internal index construction.
    ///
    /// Dimensions are read from the file — no embedder needed. This means
    /// semantic search works even when `embeddings` feature is off, as long
    /// as a pre-built index exists on disk.
    #[cfg(all(test, feature = "vector"))]
    pub(crate) fn load_vector_index(&self, path: &std::path::Path) -> Result<usize, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.load_vector_index",
            path = %path.display()
        )
        .entered();
        if !path.exists() {
            return Ok(0);
        }

        let loaded = VectorIndex::load_from_disk(path)?;
        let count = loaded.len();
        *self.vector_index.lock() = Some(Arc::new(loaded));
        // A loaded sidecar can carry stale-generation vectors that are orphans
        // relative to this graph's truth; force the next prune to scan fully.
        self.mark_vector_full_reconcile();
        Ok(count)
    }

    /// Load a persisted index only when its model and graph descriptor proves
    /// compatibility with `expected`.
    ///
    /// An incompatible or unreadable index is NOT installed and does NOT error;
    /// it returns
    /// [`VectorIndexLoad::Incompatible`] so the caller can archive + rebuild
    /// instead of crash-looping or serving silently-wrong neighbors. The in-memory
    /// index is left untouched on incompatibility.
    #[cfg(feature = "vector")]
    pub fn load_vector_index_compatible(
        &self,
        path: &std::path::Path,
        expected: &crate::vector::IndexDescriptor,
    ) -> crate::vector::VectorIndexLoad {
        use crate::vector::{IndexLoadOutcome, VectorIndexLoad};
        match VectorIndex::load_compatible(path, expected) {
            IndexLoadOutcome::Loaded(index) => {
                let count = index.len();
                *self.vector_index.lock() = Some(Arc::new(index));
                self.mark_vector_full_reconcile();
                VectorIndexLoad::Loaded(count)
            }
            IndexLoadOutcome::Incompatible(reason) => VectorIndexLoad::Incompatible(reason),
        }
    }

    #[cfg(feature = "vector")]
    pub fn save_vector_index(&self, path: &std::path::Path) -> Result<(), KinDbError> {
        let _span = tracing::info_span!(
            "kindb.save_vector_index",
            path = %path.display()
        )
        .entered();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to create vector index directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        // Only a graph that holds a populated index in memory writes the
        // sidecar. An in-memory `None` means the index was never loaded for
        // this graph (e.g. it was refused on reopen) — it does NOT mean the
        // repo has no vectors. Deleting the on-disk sidecar here would
        // silently destroy graph-owned truth that a later embed pass or a
        // matching reopen could have reused, so an unloaded index leaves the
        // persisted sidecar untouched. A sidecar that cannot serve the store
        // is judged on load by `load_vector_index_if_valid` (salvaged per key
        // on stamp drift, refused with its failing comparison named otherwise)
        // and rebuilt from the embedding queue, never by a destructive write
        // here.
        //
        // Detach the index handle before saving. `self.vector_index` guards the
        // slot — which index this graph serves — not the content of the index,
        // which kin-vector synchronizes itself; every other reader here already
        // clones the handle out and works outside the guard, including the
        // mutating prune and carry-forward paths. Holding it across the save is
        // what made an unrelated one-entity `create_change` wait: the save
        // performs the index's deferred HNSW insertion for every unindexed
        // vector before it writes, which is O(index), and
        // `admit_minted_revision_vectors` needs the same slot to decide whether
        // the new revision key owes a vector.
        let index = self.vector_index.lock().clone();
        run_save_vector_index_after_detach_hook(self);
        if let Some(index) = index {
            index.save(path)?;
        }

        Ok(())
    }

    /// Stamp the in-memory vector index's self-description (embedding model
    /// identity + graph provenance) so the next `save_vector_index` persists it
    /// into the `.kvec`. A later load can then prove the stored vectors were
    /// produced by the expected model/graph and refuse silently-wrong neighbors,
    /// independently of the sidecar metadata. No-op when no index is loaded.
    #[cfg(feature = "vector")]
    pub fn stamp_vector_index_descriptor(&self, descriptor: crate::vector::IndexDescriptor) {
        if let Some(ref index) = *self.vector_index.lock() {
            index.set_descriptor(descriptor);
        }
    }

    /// Return the loaded vector index's persisted compatibility descriptor.
    #[cfg(feature = "vector")]
    pub fn vector_index_descriptor(&self) -> Option<crate::vector::IndexDescriptor> {
        self.vector_index
            .lock()
            .as_ref()
            .map(|index| index.descriptor())
    }

    #[cfg(feature = "embeddings")]
    pub fn share_embedder_from(&self, source: &InMemoryGraph) {
        let source_embedder = source.embedder.lock().clone();
        if let Some(e) = source_embedder {
            *self.embedder.lock() = Some(e);
        }
    }

    /// Returns `(dimensions, indexed_count)` for the loaded vector index, or
    /// `None` when no index is loaded for this graph. Available with the
    /// `vector` feature alone — it reads index metadata and needs no embedder.
    #[cfg(feature = "vector")]
    pub fn vector_index_stats(&self) -> Option<(usize, usize)> {
        self.vector_index
            .lock()
            .as_ref()
            .map(|index| (index.dimensions(), index.len()))
    }

    /// Semantic similarity search across all embedded entities.
    ///
    /// Embeds the query text using the code embedding model, then searches
    /// the HNSW vector index for the nearest neighbours.
    ///
    /// Returns up to `limit` `(RetrievalKey, distance)` pairs sorted by similarity.
    /// Returns an empty vec when embeddings are not yet built or features
    /// are disabled.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn semantic_search(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<(RetrievalKey, f32)>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.semantic_search",
            query = %query,
            limit = limit
        )
        .entered();

        // An unpopulated vector index is a valid graph state, not an error:
        // `kin init` only queues embeddings, so the index can legitimately be
        // missing or empty until an explicit embed pass runs. Degrade to an
        // empty result here (callers fall back to text search) instead of
        // loading the embedder and failing. A populated index that then fails
        // to embed/search the query still surfaces the error via `?`.
        let vi = match &*self.vector_index.lock() {
            Some(vi) if !vi.is_empty() => Arc::clone(vi),
            _ => return Ok(Vec::new()),
        };

        let embedder = self.get_embedder()?;
        let vector = embedder.embed_text(query)?;
        vi.search_similar(&vector, limit)
    }

    /// Semantic similarity search (stub when features are disabled).
    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn semantic_search(
        &self,
        _query: &str,
        _limit: usize,
    ) -> Result<Vec<(RetrievalKey, f32)>, KinDbError> {
        Ok(Vec::new())
    }

    /// Batched semantic similarity search across all embedded entities.
    ///
    /// Embeds all query texts in a single `embed_batch` call (one forward pass)
    /// instead of N separate `embed_text` calls, then searches the HNSW vector
    /// index for each resulting vector.
    ///
    /// Returns one `Vec<(RetrievalKey, distance)>` per query, in input order.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn semantic_search_batch(
        &self,
        queries: &[&str],
        limit: usize,
    ) -> Result<Vec<Vec<(RetrievalKey, f32)>>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.semantic_search_batch",
            num_queries = queries.len(),
            limit = limit
        )
        .entered();

        if queries.is_empty() {
            return Ok(Vec::new());
        }

        // Mirror `semantic_search`: an empty/unpopulated index degrades to one
        // empty result per query rather than loading the embedder and failing.
        let vi = match &*self.vector_index.lock() {
            Some(vi) if !vi.is_empty() => Arc::clone(vi),
            _ => return Ok(vec![Vec::new(); queries.len()]),
        };

        let embedder = self.get_embedder()?;

        let texts: Vec<String> = queries.iter().map(|q| q.to_string()).collect();
        let vectors = embedder.embed_query_batch(&texts)?;

        let mut results = Vec::with_capacity(vectors.len());
        for vector in &vectors {
            results.push(vi.search_similar(vector, limit)?);
        }
        Ok(results)
    }

    /// Batched semantic similarity search with a predicate filter.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn semantic_search_batch_filtered<P>(
        &self,
        queries: &[&str],
        limit: usize,
        predicate: P,
    ) -> Result<Vec<Vec<(RetrievalKey, f32)>>, KinDbError>
    where
        P: Fn(&RetrievalKey) -> bool,
    {
        let _span = tracing::info_span!(
            "kindb.semantic_search_batch_filtered",
            num_queries = queries.len(),
            limit = limit
        )
        .entered();

        if queries.is_empty() {
            return Ok(Vec::new());
        }

        let vi = match &*self.vector_index.lock() {
            Some(vi) if !vi.is_empty() => Arc::clone(vi),
            _ => return Ok(vec![Vec::new(); queries.len()]),
        };

        let embedder = self.get_embedder()?;

        let texts: Vec<String> = queries.iter().map(|q| q.to_string()).collect();
        let vectors = embedder.embed_query_batch(&texts)?;

        let mut results = Vec::with_capacity(vectors.len());
        for vector in &vectors {
            results.push(vi.search_similar_filtered(vector, limit, &predicate)?);
        }
        Ok(results)
    }

    /// Batched semantic similarity search (stub when features are disabled).
    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn semantic_search_batch(
        &self,
        queries: &[&str],
        _limit: usize,
    ) -> Result<Vec<Vec<(RetrievalKey, f32)>>, KinDbError> {
        Ok(vec![Vec::new(); queries.len()])
    }

    // -----------------------------------------------------------------------
    // Embedding queue — progressive, non-blocking embedding pipeline
    // -----------------------------------------------------------------------

    /// Number of entities waiting to be embedded.
    #[cfg(feature = "vector")]
    pub fn pending_embeddings(&self) -> usize {
        self.embedding_queue.lock().len()
    }

    /// Number of entities waiting to be embedded (stub).
    #[cfg(not(feature = "vector"))]
    pub fn pending_embeddings(&self) -> usize {
        0
    }

    /// Number of artifacts waiting to be embedded.
    #[cfg(feature = "vector")]
    pub fn pending_artifact_embeddings(&self) -> usize {
        self.artifact_embedding_queue.lock().len()
    }

    /// Number of artifacts waiting to be embedded (stub).
    #[cfg(not(feature = "vector"))]
    pub fn pending_artifact_embeddings(&self) -> usize {
        0
    }

    /// Wall-clock interval between in-run vector-sidecar checkpoints. Matches the
    /// daemon's periodic-flush cadence and keeps a persisted-progress stall
    /// watchdog satisfied with a wide margin (typical stall windows are minutes).
    #[cfg(feature = "vector")]
    const VECTOR_SIDECAR_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

    /// Batch-count backstop between in-run vector-sidecar checkpoints. On
    /// hardware fast enough to embed more than this many batches within the time
    /// interval, checkpoint after this many incremental flushes instead of
    /// waiting the full interval — so persisted coverage never lags compute by
    /// more than this many batches of work, and a crash re-derives at most that
    /// much. Sized so the amortized per-run sidecar write cost stays O(index)
    /// overall rather than the O(index²) of a per-batch write: at the capped
    /// 64-entity batch this is ≤ 4096 vectors of new work between the full-index
    /// serializes that `save_vector_index_for_graph` performs.
    #[cfg(feature = "vector")]
    const VECTOR_SIDECAR_FLUSH_BATCHES: usize = 64;

    /// Decide whether an in-run vector-sidecar checkpoint is due, given the last
    /// checkpoint time, the batches seen since, and the current instant. Pure so
    /// the interval/backstop policy is unit-testable without wall-clock flakiness.
    ///
    /// The first checkpoint of a run (`last_flush == None`) is always due, so
    /// progress lands from the first batch; afterwards a checkpoint is due once
    /// either the time interval or the batch backstop is crossed.
    #[cfg(feature = "vector")]
    fn vector_sidecar_flush_due(
        last_flush: Option<std::time::Instant>,
        batches_since_flush: usize,
        now: std::time::Instant,
        interval: std::time::Duration,
        batch_backstop: usize,
    ) -> bool {
        match last_flush {
            None => true,
            Some(last) => {
                now.saturating_duration_since(last) >= interval
                    || batches_since_flush >= batch_backstop
            }
        }
    }

    /// Record one incremental in-run flush and report whether the derived vector
    /// sidecar should be checkpointed to disk now (see
    /// [`VectorSidecarFlushThrottle`]). Called by
    /// `SnapshotManager::flush_embed_progress` on every batch while the embed
    /// queue is still draining; the sidecar is a full O(index) serialize, so it
    /// is written on a throttle rather than every batch. Resets the throttle when
    /// it fires so the next window starts from this checkpoint.
    #[cfg(feature = "vector")]
    pub(crate) fn should_flush_vector_sidecar_now(&self) -> bool {
        let now = std::time::Instant::now();
        let mut throttle = self.vector_sidecar_flush_throttle.lock();
        throttle.batches_since_flush += 1;
        let due = Self::vector_sidecar_flush_due(
            throttle.last_flush,
            throttle.batches_since_flush,
            now,
            Self::VECTOR_SIDECAR_FLUSH_INTERVAL,
            Self::VECTOR_SIDECAR_FLUSH_BATCHES,
        );
        if due {
            throttle.last_flush = Some(now);
            throttle.batches_since_flush = 0;
        }
        due
    }

    /// Reset the in-run sidecar-flush throttle. Called when the embed queue
    /// drains (the sidecar is written unconditionally at completion) so the next
    /// run's first batch checkpoints immediately.
    #[cfg(feature = "vector")]
    pub(crate) fn reset_vector_sidecar_flush_throttle(&self) {
        let mut throttle = self.vector_sidecar_flush_throttle.lock();
        throttle.last_flush = None;
        throttle.batches_since_flush = 0;
    }

    /// Manually queue entity IDs for embedding (e.g., after bulk import).
    #[cfg(feature = "vector")]
    pub fn queue_for_embedding(&self, ids: &[EntityId]) {
        let mut queue = self.embedding_queue.lock();
        for id in ids {
            queue.insert(RetrievalKey::Entity(*id), EmbedRecency::Backfill);
        }
    }

    /// Manually queue retrieval keys for embedding.
    #[cfg(feature = "vector")]
    pub fn queue_keys_for_embedding(&self, keys: &[RetrievalKey]) {
        let mut queue = self.embedding_queue.lock();
        for key in keys {
            queue.insert(*key, EmbedRecency::Backfill);
        }
    }

    /// Manually queue artifact IDs for embedding.
    #[cfg(feature = "vector")]
    pub fn queue_artifacts_for_embedding(&self, ids: &[ArtifactId]) {
        let mut queue = self.artifact_embedding_queue.lock();
        for id in ids {
            queue.insert(*id, EmbedRecency::Backfill);
        }
    }

    /// Queue every entity in the graph for a from-scratch embedding pass: the
    /// HEAD revision of each entity plus every current HEAD entity.
    ///
    /// Only the latest revision of each entity is queued — superseded
    /// generations are not retrieval truth and would be evicted by
    /// `prune_orphaned_vectors`, so embedding them on a rebuild is pure waste
    /// (and reintroduces the doubled-vector state this convergence fixes).
    /// This matches the target set of `graph_truth_retrievable_keys`.
    #[cfg(feature = "vector")]
    pub fn queue_all_for_embedding(&self) {
        let mut queue = self.embedding_queue.lock();
        let ent = self.entities.read();

        // Queue the HEAD revision of each entity.
        for key in latest_revision_ids(&ent).map(RetrievalKey::EntityRevision) {
            queue.insert(key, EmbedRecency::Backfill);
        }

        // Queue all current HEAD entities
        for id in ent.entities.keys() {
            queue.insert(RetrievalKey::Entity(*id), EmbedRecency::Backfill);
        }
    }

    /// Queue all graph-owned artifacts for embedding.
    #[cfg(feature = "vector")]
    pub fn queue_all_artifacts_for_embedding(&self) {
        let ids = {
            let ent = self.entities.read();
            collect_artifact_ids(&ent)
        };
        self.queue_artifacts_for_embedding(&ids);
    }

    #[cfg(not(feature = "vector"))]
    pub fn queue_all_artifacts_for_embedding(&self) {}

    /// Queue only entities and revisions that do not already have vectors in the current index.
    #[cfg(feature = "vector")]
    pub fn queue_missing_for_embedding(&self) {
        let vector_index = self.vector_index.lock().clone();
        let mut queue = self.embedding_queue.lock();
        let ent = self.entities.read();

        // Queue only the missing HEAD revision of each entity. Superseded
        // generations are deliberately NOT enqueued: they are not retrieval
        // truth (see `graph_truth_retrievable_keys`) and `prune_orphaned_vectors`
        // evicts them — enqueuing them would re-embed a key the prune removes on
        // the next pass, churning forever.
        for key in latest_revision_ids(&ent).map(RetrievalKey::EntityRevision) {
            let missing = vector_index
                .as_ref()
                .map(|vi| !vi.contains_retrievable(&key))
                .unwrap_or(true);
            if missing {
                queue.insert(key, EmbedRecency::Backfill);
            }
        }

        // Queue missing HEAD entities
        for id in ent.entities.keys() {
            let key = RetrievalKey::Entity(*id);
            let missing = vector_index
                .as_ref()
                .map(|vi| !vi.contains_retrievable(&key))
                .unwrap_or(true);
            if missing {
                queue.insert(key, EmbedRecency::Backfill);
            }
        }
    }

    /// Propagate vectors from already-embedded revisions to later revisions with
    /// identical entity fingerprints, avoiding redundant GPU inference.
    ///
    /// Many consecutive revisions of the same entity share identical content —
    /// they were "modified" only because a neighbouring entity changed in the
    /// same commit, causing span/line-number shifts. When
    /// `(ast_hash, signature_hash, behavior_hash)` all match between a revision
    /// that already has a vector and one that does not, we can safely copy the
    /// vector instead of re-embedding.
    ///
    /// Returns the number of vectors propagated.
    #[cfg(feature = "vector")]
    pub fn propagate_revision_vectors(&self) -> usize {
        let _span = tracing::info_span!("kindb.propagate_revision_vectors").entered();

        // Clone the Arc out of the Mutex so we don't hold the lock during the
        // (potentially large) iteration.
        let vi = match self.vector_index.lock().clone() {
            Some(vi) => vi,
            None => return 0,
        };

        let ent = self.entities.read();

        // Build a global revision-id → EntityRevision lookup so we can resolve
        // `previous_revision: Option<EntityRevisionId>` cheaply.
        let mut rev_by_id: hashbrown::HashMap<EntityRevisionId, &EntityRevision> =
            hashbrown::HashMap::new();
        for revisions in ent.entity_revisions.values() {
            for rev in revisions {
                rev_by_id.insert(rev.revision_id, rev);
            }
        }

        let mut propagated: usize = 0;

        // Iterate revision chains in a deterministic order. `entity_revisions` is
        // a HashMap, so `.values()` visits chains in per-process order; because
        // each propagated vector is upserted into the order-sensitive HNSW, that
        // would make the built index (and the persisted `.kvec`) differ run to
        // run. Sort by the owning entity id so insertion order is reproducible.
        // Eligibility itself is order-independent — it depends only on fingerprints
        // and the fully-built `rev_by_id` lookup, plus the per-chain `last_vectored`
        // cursor — never on which chain ran first.
        let mut chain_owner_ids: Vec<EntityId> = ent.entity_revisions.keys().copied().collect();
        chain_owner_ids.sort_unstable();
        for owner_id in &chain_owner_ids {
            let revisions = &ent.entity_revisions[owner_id];
            // Walk the chronological revision list. Track the most recent
            // revision id that is known to have a vector (either because it was
            // already in the index, or because we just propagated one to it).
            let mut last_vectored: Option<EntityRevisionId> = None;

            for rev in revisions {
                let key = RetrievalKey::EntityRevision(rev.revision_id);

                if vi.contains_retrievable(&key) {
                    // Already embedded — remember it as a potential source.
                    last_vectored = Some(rev.revision_id);
                    continue;
                }

                // Missing vector. Try to propagate from `previous_revision` if
                // the fingerprints match.
                if let Some(prev_id) = &rev.previous_revision {
                    if let Some(prev_rev) = rev_by_id.get(prev_id) {
                        if prev_rev.entity.fingerprint.ast_hash == rev.entity.fingerprint.ast_hash
                            && prev_rev.entity.fingerprint.signature_hash
                                == rev.entity.fingerprint.signature_hash
                            && prev_rev.entity.fingerprint.behavior_hash
                                == rev.entity.fingerprint.behavior_hash
                        {
                            let source_key = RetrievalKey::EntityRevision(*prev_id);
                            if let Some(vector) = vi.get_retrievable(&source_key) {
                                let _ = vi.upsert_retrievable(key, &vector);
                                propagated += 1;
                                last_vectored = Some(rev.revision_id);
                                continue;
                            }
                        }
                    }
                }

                // Fallback: try the last vectored revision in the same entity's
                // chronological list (covers cases where `previous_revision` is
                // None but the prior sibling has an identical fingerprint).
                if let Some(source_id) = last_vectored {
                    if let Some(source_rev) = rev_by_id.get(&source_id) {
                        if source_rev.entity.fingerprint.ast_hash == rev.entity.fingerprint.ast_hash
                            && source_rev.entity.fingerprint.signature_hash
                                == rev.entity.fingerprint.signature_hash
                            && source_rev.entity.fingerprint.behavior_hash
                                == rev.entity.fingerprint.behavior_hash
                        {
                            let source_key = RetrievalKey::EntityRevision(source_id);
                            if let Some(vector) = vi.get_retrievable(&source_key) {
                                let _ = vi.upsert_retrievable(key, &vector);
                                propagated += 1;
                                last_vectored = Some(rev.revision_id);
                                continue;
                            }
                        }
                    }
                }

                // No propagation possible — this revision stays un-vectored and
                // will be picked up by the normal embedding queue.
            }
        }

        tracing::info!(
            propagated = propagated,
            "propagate_revision_vectors complete"
        );
        propagated
    }

    /// Propagate revision vectors (stub when vector feature is disabled).
    #[cfg(not(feature = "vector"))]
    pub fn propagate_revision_vectors(&self) -> usize {
        0
    }

    /// Queue only artifacts that do not already have vectors in the current index.
    #[cfg(feature = "vector")]
    pub fn queue_missing_artifacts_for_embedding(&self) {
        let vector_index = self.vector_index.lock().clone();
        let ids: Vec<ArtifactId> = {
            let ent = self.entities.read();
            collect_artifact_ids(&ent)
                .into_iter()
                .filter(|id| {
                    let key = RetrievalKey::Artifact(*id);
                    vector_index
                        .as_ref()
                        .map(|vi| !vi.contains_retrievable(&key))
                        .unwrap_or(true)
                })
                .collect()
        };
        self.queue_artifacts_for_embedding(&ids);
    }

    #[cfg(not(feature = "vector"))]
    pub fn queue_missing_artifacts_for_embedding(&self) {}

    /// Drop the in-memory vector index so the next embedding pass rebuilds it
    /// from scratch at the CURRENT embedder dimension.
    ///
    /// This is the rebuild path when a persisted index was produced at a
    /// different embedding dimension than the configured model. A normal embed pass reuses the loaded index
    /// and upserts fail with a dimension mismatch; clearing the in-memory index
    /// lets `queue_missing_for_embedding` re-queue every entity/artifact (the
    /// emptied index reports nothing as indexed) and `get_vector_index` lazily
    /// recreate the index sized to the live embedder.
    ///
    /// The on-disk sidecar is intentionally left untouched here: the per-batch
    /// persist that follows a rebuild overwrites it with the freshly-sized
    /// index, so there is no window where graph-owned vector truth is destroyed
    /// before its replacement exists.
    #[cfg(feature = "vector")]
    pub fn reset_vector_index(&self) {
        let _span = tracing::info_span!("kindb.reset_vector_index").entered();
        *self.vector_index.lock() = None;
    }

    #[cfg(not(feature = "vector"))]
    pub fn reset_vector_index(&self) {}

    /// Share another graph's vector index by cloning its `Arc`. The scoped
    /// graph can then search the HEAD index directly; callers filter results
    /// for scope membership (stable-key filtering in locate already does this).
    #[cfg(feature = "vector")]
    pub fn share_vector_index_from(&self, source: &InMemoryGraph) {
        let src_guard = source.vector_index.lock();
        if let Some(ref vi) = *src_guard {
            *self.vector_index.lock() = Some(Arc::clone(vi));
        }
    }

    #[cfg(not(feature = "vector"))]
    pub fn share_vector_index_from(&self, _source: &InMemoryGraph) {}

    /// Drain up to `batch_size` keys from the entity embedding queue in a
    /// deterministic order, leaving the remainder queued.
    ///
    /// This is the single ordering authority for entity embedding batches. The
    /// returned order is a pure function of the queued work (and, once the
    /// priority-signals layer lands, graph state); it never observes the
    /// queue's HashMap iteration order, so two processes that queued the same
    /// work drain identical batches in the identical order. That determinism is
    /// what removes the per-process batch-composition variance behind the embed
    /// determinism bug.
    #[cfg(feature = "vector")]
    fn drain_embedding_batch(&self, batch_size: usize) -> Vec<(RetrievalKey, EmbedRecency)> {
        let _drain_timer = self
            .embed_stage_timings
            .scope(crate::embed::EmbedStage::Drain);
        let batch_size = batch_size.max(1);
        let mut queue = self.embedding_queue.lock();
        if queue.is_empty() {
            return Vec::new();
        }

        // Compute the global deterministic priority order once for a stable
        // queue snapshot, then retain its leftover as a frontier. Subsequent
        // batches pop O(batch_size) work instead of draining and reinserting the
        // O(backlog) remainder. Any enqueue, removal, or recency promotion marks
        // the frontier dirty and folds the new work into one fresh global sort.
        if queue.frontier_needs_rebuild() {
            let ent = self.entities.read();
            let mut ordered: Vec<(EmbedSortKey, RetrievalKey)> = queue
                .items
                .iter()
                .map(|(key, recency)| (embed_sort_key_for(&ent, *key, *recency), *key))
                .collect();
            ordered.sort_unstable_by_key(|entry| entry.0);
            queue.install_frontier(ordered.into_iter().map(|(_, key)| key));
        }
        queue.pop_frontier_batch(batch_size)
    }

    /// Drain up to `batch_size` artifact IDs from the artifact embedding queue
    /// in a deterministic order, leaving the remainder queued.
    ///
    /// Mirrors [`InMemoryGraph::drain_embedding_batch`] for artifacts. This
    /// replaces the previous raw `HashSet::iter()` drain, whose per-process
    /// iteration order made artifact batch composition nondeterministic.
    #[cfg(feature = "vector")]
    fn drain_artifact_embedding_batch(&self, batch_size: usize) -> Vec<(ArtifactId, EmbedRecency)> {
        let batch_size = batch_size.max(1);
        let mut queue = self.artifact_embedding_queue.lock();
        if queue.is_empty() {
            return Vec::new();
        }

        // Deterministic total order: recency first (changed-this-sync before
        // backfill), then artifact id as the stable tiebreak. Cache the total
        // order exactly like the entity queue so stable bulk drains sort once.
        if queue.frontier_needs_rebuild() {
            let mut ordered: Vec<(EmbedRecency, ArtifactId)> = queue
                .items
                .iter()
                .map(|(id, recency)| (*recency, *id))
                .collect();
            ordered.sort_unstable();
            queue.install_frontier(ordered.into_iter().map(|(_, id)| id));
        }
        queue.pop_frontier_batch(batch_size)
    }

    /// Drain the current pending embedding work in batches, covering both the
    /// entity queue and the artifact queue.
    ///
    /// This is the graph-first incremental path: graph mutations enqueue
    /// changed entities and artifacts, and callers process only that pending
    /// work. Entity batches drain first; artifact batches follow through the
    /// same staged pipeline.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn process_all_pending_embeddings(&self, batch_size: usize) -> Result<usize, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.process_all_pending_embeddings",
            batch_size = batch_size
        )
        .entered();
        if embed_pipeline_enabled() {
            return self.process_all_pending_embeddings_pipelined(batch_size);
        }
        let timing_base = self.embed_stage_timings.snapshot();
        let mut total = 0usize;
        let initial_pending = self.pending_embeddings() + self.pending_artifact_embeddings();
        let start_time = std::time::Instant::now();
        loop {
            let pending = self.pending_embeddings() + self.pending_artifact_embeddings();
            if pending == 0 {
                break;
            }
            let processed = self.process_embedding_queue(batch_size)?;
            if processed == 0 {
                break;
            }
            total += processed;
            if initial_pending > 0 {
                let percent = (total * 100) / initial_pending;
                eprint!(
                    "\r  Embedding Graph Truth: [{}/{}] {}% | {:.1}s",
                    total,
                    initial_pending,
                    percent,
                    start_time.elapsed().as_secs_f64()
                );
            }
        }
        if initial_pending > 0 {
            eprintln!();
        }
        self.embed_stage_timings
            .snapshot()
            .since(&timing_base)
            .log_summary("serial");
        Ok(total)
    }

    /// Pipelined variant of [`InMemoryGraph::process_all_pending_embeddings`]:
    /// overlaps the drain+prep, forward, and persist stages on a bounded
    /// producer→consumer so the GPU forward for batch N+1 runs while the CPU preps
    /// batch N+2 and persists batch N.
    ///
    /// Opt-in via [`embed_pipeline_enabled`]; the serial path remains the default
    /// proof path. Output is byte-equivalent to the serial path (same drained
    /// batch sequence, same in-batch key order) modulo the pre-existing Metal
    /// float jitter, so the citable embed order is preserved.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn process_all_pending_embeddings_pipelined(
        &self,
        batch_size: usize,
    ) -> Result<usize, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.process_all_pending_embeddings_pipelined",
            batch_size = batch_size
        )
        .entered();

        let batch_size = batch_size.max(1);
        let initial_pending = self.pending_embeddings() + self.pending_artifact_embeddings();
        let start_time = std::time::Instant::now();
        let mut running_total = 0usize;
        let timing_base = self.embed_stage_timings.snapshot();

        let total = drive_embed_pipeline(
            EMBED_PIPELINE_PREP_CAPACITY,
            EMBED_PIPELINE_RESULT_CAPACITY,
            // DRAIN + PREP — the single serial ordering authority. Returns `None`
            // once a drain yields no embeddable work, exactly where the serial loop
            // stops on a zero-progress batch.
            || {
                let prepared = self.prepare_pending_embedding_batch(batch_size);
                if prepared.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(prepared))
                }
            },
            // FORWARD — one batch at a time on the GPU; carries `prepared` forward
            // so persist writes in the exact drained key order.
            |prepared| {
                let embedded = self.embed_prepared_batch(&prepared)?;
                Ok((prepared, embedded))
            },
            // PERSIST — preserves key order. The per-batch prune is suppressed
            // (`prune_on_empty = false`): the drain thread empties the queue while
            // batches are still in flight, so the serial path's "prune when the
            // queue is empty" gate would otherwise fire on every batch. The single
            // end-of-run prune below reproduces the serial path's one reconcile.
            |prepared, embedded| {
                let count = self.persist_embedded_batch_inner(embedded, &prepared, false)?;
                running_total += count;
                if initial_pending > 0 {
                    let percent = (running_total * 100) / initial_pending;
                    eprint!(
                        "\r  Embedding Graph Truth: [{}/{}] {}% | {:.1}s",
                        running_total,
                        initial_pending,
                        percent,
                        start_time.elapsed().as_secs_f64()
                    );
                }
                Ok(count)
            },
            |prepared| {
                self.requeue_embedding_keys(prepared.recency.keys().copied(), &prepared.recency);
            },
        )?;

        if initial_pending > 0 {
            eprintln!();
        }

        // Single end-of-drain reconcile, mirroring the serial path's one prune when
        // the queue empties. Gated on both queues being empty so an error-requeued
        // remainder is never pruned against a partially embedded index.
        if total > 0
            && self.embedding_queue.lock().is_empty()
            && self.artifact_embedding_queue.lock().is_empty()
        {
            self.prune_orphaned_vectors();
        }

        self.embed_stage_timings
            .snapshot()
            .since(&timing_base)
            .log_summary("pipelined");
        Ok(total)
    }

    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn process_all_pending_embeddings(&self, _batch_size: usize) -> Result<usize, KinDbError> {
        Ok(0)
    }

    /// A point-in-time snapshot of this graph's cumulative embed-stage timings
    /// (drain / prep / forward / persist / prune wall time + call counts). Cheap
    /// — it reads ten relaxed atomics — so operator tooling (e.g. `kin resources
    /// inspect`) can poll it without perturbing the embed hot path.
    #[cfg(feature = "vector")]
    pub fn embed_stage_timings_snapshot(&self) -> crate::embed::EmbedStageSnapshot {
        self.embed_stage_timings.snapshot()
    }

    /// Drain the current pending artifact embedding queue in batches.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn process_all_pending_artifact_embeddings(
        &self,
        batch_size: usize,
    ) -> Result<usize, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.process_all_pending_artifact_embeddings",
            batch_size = batch_size
        )
        .entered();
        let mut total = 0usize;
        let initial_pending = self.pending_artifact_embeddings();
        let start_time = std::time::Instant::now();
        loop {
            let pending = self.pending_artifact_embeddings();
            if pending == 0 {
                break;
            }
            let processed = self.process_artifact_embedding_queue(batch_size)?;
            if processed == 0 {
                break;
            }
            total += processed;
            if initial_pending > 0 {
                let percent = (total * 100) / initial_pending;
                eprint!(
                    "\r  Embedding Artifacts: [{}/{}] {}% | {:.1}s",
                    total,
                    initial_pending,
                    percent,
                    start_time.elapsed().as_secs_f64()
                );
            }
        }
        if initial_pending > 0 {
            eprintln!();
        }
        Ok(total)
    }

    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn process_all_pending_artifact_embeddings(
        &self,
        _batch_size: usize,
    ) -> Result<usize, KinDbError> {
        Ok(0)
    }

    /// Process up to `batch_size` items from the embedding queues.
    ///
    /// Drains keys from the entity queue (topping up remaining capacity from
    /// the artifact queue), generates embeddings via the CodeEmbedder, and
    /// inserts them into the HNSW VectorIndex.
    /// Returns the number of items successfully embedded.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn process_embedding_queue(&self, batch_size: usize) -> Result<usize, KinDbError> {
        let _span =
            tracing::info_span!("kindb.process_embedding_queue", batch_size = batch_size).entered();

        // Compose the three staged methods. A pipelining caller can instead drive
        // them on separate threads so prep for batch N+1, inference for batch N,
        // and persist for batch N-1 overlap; here they run back to back.
        let prepared = self.prepare_pending_embedding_batch(batch_size);
        if prepared.is_empty() {
            return Ok(0);
        }
        let embedded = self.embed_prepared_batch(&prepared)?;
        self.persist_embedded_batch(embedded, &prepared)
    }

    /// Stage 1 of the embed pipeline: drain a deterministic, priority-ordered
    /// batch and format each item's text. This is the ONLY stage that touches
    /// the entity graph — it acquires the `entities` read lock, formats every
    /// item, and releases it before returning — so a caller can run it for the
    /// next batch while the current batch is on the GPU.
    ///
    /// `drain_embedding_batch` is the single ordering authority: batch
    /// composition depends only on queue contents and graph state, never on map
    /// iteration order, so it is identical across processes.
    ///
    /// Once the entity queue runs dry, remaining batch capacity is topped up
    /// from the artifact embedding queue, so every consumer of the staged
    /// pipeline finishes a run with artifact vectors present instead of leaving
    /// that sub-space to a second hand-rolled drain loop. Entity work always
    /// drains first; artifacts never displace it within a batch.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn prepare_pending_embedding_batch(&self, batch_size: usize) -> PreparedEmbedBatch {
        use crate::embed::format_graph_entity_text;
        use crate::embed::format_graph_entity_text_with_context;

        let batch_size = batch_size.max(1);
        let mut batch = self.drain_embedding_batch(batch_size);
        if batch.len() < batch_size {
            batch.extend(
                self.drain_artifact_embedding_batch(batch_size - batch.len())
                    .into_iter()
                    .map(|(artifact_id, recency)| (RetrievalKey::Artifact(artifact_id), recency)),
            );
        }
        // Time only the text-format work; the drain above is timed inside
        // `drain_embedding_batch`, so the two stages never double-count.
        let _prep_timer = self
            .embed_stage_timings
            .scope(crate::embed::EmbedStage::Prep);
        let recency: hashbrown::HashMap<RetrievalKey, EmbedRecency> =
            batch.iter().copied().collect();

        let mut keys: Vec<RetrievalKey> = Vec::with_capacity(batch.len());
        let mut texts: Vec<String> = Vec::with_capacity(batch.len());
        if !batch.is_empty() {
            let ent = self.entities.read();

            // Build a lookup map for any EntityRevisionId in the batch.
            let mut rev_ids = hashbrown::HashSet::new();
            for (key, _) in &batch {
                if let RetrievalKey::EntityRevision(rev_id) = key {
                    rev_ids.insert(*rev_id);
                }
            }
            let mut rev_lookup = hashbrown::HashMap::new();
            if !rev_ids.is_empty() {
                'outer: for revisions_vec in ent.entity_revisions.values() {
                    for rev in revisions_vec {
                        if rev_ids.contains(&rev.revision_id) {
                            rev_lookup.insert(rev.revision_id, rev.clone());
                            if rev_lookup.len() == rev_ids.len() {
                                break 'outer;
                            }
                        }
                    }
                }
            }

            for (key, _) in &batch {
                match key {
                    RetrievalKey::Entity(entity_id) => {
                        if let Some(e) = ent.entities.get(entity_id) {
                            let context_lines = collect_embedding_context_lines(&ent, entity_id);
                            keys.push(*key);
                            texts.push(format_graph_entity_text_with_context(e, &context_lines));
                        }
                    }
                    RetrievalKey::EntityRevision(rev_id) => {
                        if let Some(rev) = rev_lookup.get(rev_id) {
                            keys.push(*key);
                            texts.push(format_graph_entity_text(&rev.entity));
                        }
                    }
                    RetrievalKey::Artifact(artifact_id) => {
                        if let Some((artifact_key, text)) =
                            artifact_embedding_doc(&ent, artifact_id)
                        {
                            keys.push(artifact_key);
                            texts.push(text);
                        } else {
                            // A queued artifact without a shallow/structured/opaque
                            // enrichment record has no embeddable document. Dropping
                            // it here mirrors `process_artifact_embedding_queue`,
                            // but say so instead of vanishing the key.
                            tracing::debug!(
                                artifact_id = %artifact_id.0,
                                "skipping queued artifact with no embedding doc source"
                            );
                        }
                    }
                    RetrievalKey::ArtifactRevision(_) => {
                        // No doc builder exists for historical artifact revisions;
                        // only the head artifact key is retrieval truth.
                        tracing::debug!(
                            "skipping artifact revision key with no embedding doc source"
                        );
                    }
                }
            }
        }

        PreparedEmbedBatch {
            keys,
            texts,
            recency,
        }
    }

    /// Stage 2 of the embed pipeline: run inference for a prepared batch. Holds
    /// no graph lock — only the brief embedder/index Arc clones — so it can run
    /// concurrently with another batch's prep or persist. On failure the batch is
    /// requeued (preserving recency) so no work is lost.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn embed_prepared_batch(
        &self,
        prepared: &PreparedEmbedBatch,
    ) -> Result<Vec<(RetrievalKey, Vec<f32>)>, KinDbError> {
        if prepared.keys.is_empty() {
            return Ok(Vec::new());
        }

        let embedder = match self.get_embedder() {
            Ok(embedder) => embedder,
            Err(err) => {
                self.requeue_embedding_keys(prepared.recency.keys().copied(), &prepared.recency);
                return Err(err);
            }
        };
        // Acquire the index now, before inference, so a stale-dimension reset (and
        // its full requeue) happens up front exactly as the monolithic path did.
        if let Err(err) = self.get_vector_index() {
            self.requeue_embedding_keys(prepared.recency.keys().copied(), &prepared.recency);
            return Err(err);
        }

        let forward_result = self
            .embed_stage_timings
            .time(crate::embed::EmbedStage::Forward, || {
                embedder.embed_batch(&prepared.texts)
            });
        let vectors = match forward_result {
            Ok(vectors) => vectors,
            Err(err) => {
                self.requeue_embedding_keys(prepared.keys.iter().copied(), &prepared.recency);
                return Err(err);
            }
        };
        Ok(prepared
            .keys
            .iter()
            .copied()
            .zip(vectors.into_iter())
            .collect())
    }

    /// Stage 3 of the embed pipeline: persist embedded vectors into the index and
    /// reconcile orphans when the queue drains. Touches only the vector index, so
    /// it can run concurrently with another batch's prep or inference. On failure
    /// the embedded keys are requeued.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn persist_embedded_batch(
        &self,
        embedded: Vec<(RetrievalKey, Vec<f32>)>,
        prepared: &PreparedEmbedBatch,
    ) -> Result<usize, KinDbError> {
        self.persist_embedded_batch_inner(embedded, prepared, true)
    }

    /// Persist worker shared by the serial and pipelined paths.
    ///
    /// `prune_on_empty` controls the live-retire reconcile. The serial path passes
    /// `true`: it persists each batch only after draining the next, so the prune
    /// fires exactly once, on the batch that empties the queue. The pipelined path
    /// passes `false` because its drain thread empties the queue while batches are
    /// still in flight — firing the gate on every persist — and instead prunes
    /// once after the whole run drains.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    fn persist_embedded_batch_inner(
        &self,
        embedded: Vec<(RetrievalKey, Vec<f32>)>,
        prepared: &PreparedEmbedBatch,
        prune_on_empty: bool,
    ) -> Result<usize, KinDbError> {
        if embedded.is_empty() {
            return Ok(0);
        }
        let keys: Vec<RetrievalKey> = embedded.iter().map(|(key, _)| *key).collect();

        let vi = match self.get_vector_index() {
            Ok(index) => index,
            Err(err) => {
                self.requeue_embedding_keys(keys.iter().copied(), &prepared.recency);
                return Err(err);
            }
        };

        let count = embedded.len();
        let persist_result = self
            .embed_stage_timings
            .time(crate::embed::EmbedStage::Persist, || {
                vi.upsert_retrievable_batch(embedded)
            });
        if let Err(err) = persist_result {
            self.requeue_embedding_keys(keys.iter().copied(), &prepared.recency);
            return Err(err);
        }

        // Live retire: when this batch drains the embed queues, a re-embed that
        // appended a new revision (and embedded its key) has left the entity's
        // prior revision vector behind. Reconcile the index to graph truth so the
        // superseded generation is retired now, instead of accumulating until the
        // next daemon boot's load-time reclaim. Gated on both queues being empty
        // so a multi-batch backfill prunes once at the end rather than per batch.
        if prune_on_empty
            && count > 0
            && self.embedding_queue.lock().is_empty()
            && self.artifact_embedding_queue.lock().is_empty()
        {
            self.prune_orphaned_vectors();
        }

        Ok(count)
    }

    /// Requeue embedding keys, restoring each key's recency so an error-requeue
    /// never silently demotes changed-this-sync work to backfill.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    fn requeue_embedding_keys<I: IntoIterator<Item = RetrievalKey>>(
        &self,
        keys: I,
        recency: &hashbrown::HashMap<RetrievalKey, EmbedRecency>,
    ) {
        let mut queue = self.embedding_queue.lock();
        for key in keys {
            let recency = recency.get(&key).copied().unwrap_or(EmbedRecency::Backfill);
            queue.insert(key, recency);
        }
    }

    /// Process embedding queue (stub when features are disabled).
    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn process_embedding_queue(&self, _batch_size: usize) -> Result<usize, KinDbError> {
        Ok(0)
    }

    /// Process up to `batch_size` artifacts from the embedding queue.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    pub fn process_artifact_embedding_queue(&self, batch_size: usize) -> Result<usize, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.process_artifact_embedding_queue",
            batch_size = batch_size
        )
        .entered();

        let batch_size = batch_size.max(1);

        // Deterministic, dedup-preserving drain (single ordering authority).
        let batch = self.drain_artifact_embedding_batch(batch_size);
        if batch.is_empty() {
            return Ok(0);
        }

        // Preserve each id's recency so an error-requeue cannot demote
        // changed-this-sync work to backfill.
        let batch_recency: hashbrown::HashMap<ArtifactId, EmbedRecency> =
            batch.iter().copied().collect();
        let ids: Vec<ArtifactId> = batch.iter().map(|(id, _)| *id).collect();

        let requeue = |ids: &[ArtifactId]| {
            if ids.is_empty() {
                return;
            }
            let mut queue = self.artifact_embedding_queue.lock();
            for id in ids {
                let recency = batch_recency
                    .get(id)
                    .copied()
                    .unwrap_or(EmbedRecency::Backfill);
                queue.insert(*id, recency);
            }
        };

        let docs: Vec<(ArtifactId, RetrievalKey, String)> = {
            let ent = self.entities.read();
            ids.iter()
                .filter_map(|artifact_id| {
                    artifact_embedding_doc(&ent, artifact_id)
                        .map(|(key, text)| (*artifact_id, key, text))
                })
                .collect()
        };

        // A drained id with no shallow/structured/opaque enrichment record has
        // no embeddable document and is deliberately not requeued (requeueing
        // work that cannot make progress spins forever). But dropping it in
        // silence is how a store reports "+0 artifacts" with nothing pending
        // while its tracked artifacts hold no vectors, so name the gap: the
        // remedy is an enrichment pass creating the record, not another embed.
        if docs.len() < ids.len() {
            tracing::warn!(
                dropped = ids.len() - docs.len(),
                drained = ids.len(),
                "artifact embedding batch dropped queued ids with no enrichment record; \
                 these artifacts cannot be embedded until enrichment recreates their records"
            );
        }

        if docs.is_empty() {
            return Ok(0);
        }

        let embedder = match self.get_embedder() {
            Ok(embedder) => embedder,
            Err(err) => {
                requeue(&ids);
                return Err(err);
            }
        };
        let vi = match self.get_vector_index() {
            Ok(index) => index,
            Err(err) => {
                requeue(&ids);
                return Err(err);
            }
        };

        let embed_batch_size = batch_size.max(1);
        let mut count = 0usize;
        for (chunk_idx, chunk) in docs.chunks(embed_batch_size).enumerate() {
            let texts: Vec<String> = chunk.iter().map(|(_, _, text)| text.clone()).collect();
            let vectors = match embedder.embed_batch(&texts) {
                Ok(vectors) => vectors,
                Err(err) => {
                    let remaining_ids: Vec<ArtifactId> = docs[chunk_idx * embed_batch_size..]
                        .iter()
                        .map(|(artifact_id, _, _)| *artifact_id)
                        .collect();
                    requeue(&remaining_ids);
                    return Err(err);
                }
            };

            for (item_idx, ((_, key, _), vector)) in chunk.iter().zip(vectors.iter()).enumerate() {
                if let Err(err) = vi.upsert_retrievable(*key, vector) {
                    let mut remaining_ids: Vec<ArtifactId> = chunk[item_idx..]
                        .iter()
                        .map(|(artifact_id, _, _)| *artifact_id)
                        .collect();
                    remaining_ids.extend(
                        docs[(chunk_idx + 1) * embed_batch_size..]
                            .iter()
                            .map(|(artifact_id, _, _)| *artifact_id),
                    );
                    requeue(&remaining_ids);
                    return Err(err);
                }
                count += 1;
            }
        }

        Ok(count)
    }

    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    pub fn process_artifact_embedding_queue(
        &self,
        _batch_size: usize,
    ) -> Result<usize, KinDbError> {
        Ok(0)
    }

    /// Every retrieval key that participates in semantic embedding under the
    /// CURRENT graph truth: the LATEST revision of each entity, all HEAD
    /// entities, and all graph-owned artifacts. This is the authoritative target
    /// set the vector index should converge to — a key in the index but absent
    /// here is a stale generation that must be evicted.
    ///
    /// Only the latest revision per entity is admitted (not every historical
    /// generation). The live `reconcile → re-embed` path appends a new
    /// `EntityRevision` each time an entity's content changes; admitting every
    /// generation as truth made `prune_orphaned_vectors` keep the superseded
    /// vectors forever (they are still "referenced" by the revision history), so
    /// each entity accumulated one vector per edit and `semantic_locate`
    /// returned it once per generation. Pinning truth to the head revision lets
    /// the existing prune reclaim those superseded generations, leaving one
    /// revision vector per live entity.
    #[cfg(feature = "vector")]
    fn graph_truth_retrievable_keys(&self) -> hashbrown::HashSet<RetrievalKey> {
        let ent = self.entities.read();
        let mut keys = hashbrown::HashSet::new();
        keys.extend(latest_revision_ids(&ent).map(RetrievalKey::EntityRevision));
        keys.extend(ent.entities.keys().map(|id| RetrievalKey::Entity(*id)));
        keys.extend(
            collect_artifact_ids(&ent)
                .into_iter()
                .map(RetrievalKey::Artifact),
        );
        keys
    }

    /// Evict vectors whose keys no longer exist in graph truth (generation
    /// eviction).
    ///
    /// Two sources feed generation accumulation, both reclaimed here:
    ///
    /// - Re-init mints fresh `SemanticChangeId`s, so every entity gets a
    ///   brand-new `EntityRevision` key each cycle. The prior generation's
    ///   revision keys — orphaned the moment the graph dropped them — keep their
    ///   vectors and the persisted sidecar carries them forward.
    /// - The live `reconcile → re-embed` path appends a new `EntityRevision`
    ///   each time an entity's content changes while its earlier generation
    ///   stays in the revision history. The superseded vector lingers because the
    ///   old revision is still "referenced"; truth (`graph_truth_retrievable_keys`)
    ///   admits only the head revision, so it falls out here.
    ///
    /// Across re-init/re-embed cycles the index otherwise accumulates
    /// generations that all compete in ANN retrieval and return the same entity
    /// once per generation.
    ///
    /// This reconciles the index back to graph truth: any indexed key not in the
    /// current retrievable set is removed. Returns the number of vectors evicted.
    /// Idempotent and cheap when the index is already clean.
    #[cfg(feature = "vector")]
    pub fn prune_orphaned_vectors(&self) -> usize {
        let _span = tracing::info_span!("kindb.prune_orphaned_vectors").entered();
        let _prune_timer = self
            .embed_stage_timings
            .scope(crate::embed::EmbedStage::Prune);

        let vi = match self.vector_index.lock().clone() {
            Some(vi) => vi,
            None => return 0,
        };

        // Take the reconcile decision under the lock: a full scan resets the
        // tracked state, the incremental path drains exactly the keys orphaned by
        // re-embeds since the last prune.
        let do_full = {
            let mut state = self.vector_reconcile.lock();
            if state.full {
                state.full = false;
                state.superseded.clear();
                true
            } else {
                false
            }
        };

        if !do_full {
            return self.prune_tracked_orphans(&vi);
        }

        let truth = self.graph_truth_retrievable_keys();
        let mut orphans: Vec<RetrievalKey> = vi
            .retrievable_keys()
            .into_iter()
            .filter(|key| !truth.contains(key))
            .collect();
        // `retrievable_keys()` returns keys in the index's per-process HashMap
        // order. Evicting in that order makes the resulting `free_list` push order
        // (and thus the slot a later re-embed reuses) vary across daemon boots,
        // which perturbs approximate-kNN neighbors at the candidate-set boundary.
        // Sort by the key's total order so eviction — and the index state it
        // leaves behind — is identical regardless of the map seed.
        orphans.sort_unstable();

        let mut evicted = 0usize;
        for key in &orphans {
            if vi.remove_retrievable(key).is_ok() {
                evicted += 1;
            }
        }

        if evicted > 0 {
            tracing::info!(evicted, "pruned orphaned vectors from index");
        }
        evicted
    }

    /// Incremental prune: evict only the vector keys recorded as superseded by
    /// re-embeds since the last reconcile, instead of rescanning the entire
    /// index or rebuilding the full truth set.
    ///
    /// Each tracked key is the prior HEAD revision of an entity that gained a
    /// newer generation. A revision id is `hash(entity_id, change_id)`, so a
    /// superseded revision can never be any entity's current HEAD again — it is
    /// definitively an orphan and is evicted directly. (Any untracked truth
    /// change — load, rebuild, removal — sets `full` instead, routing to the
    /// exhaustive scan, so this fast path only runs when the tracked set is the
    /// complete orphan set.) Evicting in sorted order keeps the resulting
    /// `free_list` deterministic, exactly as the full scan does.
    #[cfg(feature = "vector")]
    fn prune_tracked_orphans(&self, vi: &VectorIndex) -> usize {
        let mut tracked: Vec<RetrievalKey> = {
            let mut state = self.vector_reconcile.lock();
            state.superseded.drain().collect()
        };
        if tracked.is_empty() {
            return 0;
        }
        tracked.sort_unstable();

        let mut evicted = 0usize;
        for key in &tracked {
            if vi.remove_retrievable(key).is_ok() {
                evicted += 1;
            }
        }
        if evicted > 0 {
            tracing::info!(evicted, "pruned tracked orphaned vectors from index");
        }
        evicted
    }

    /// Record vectors orphaned by a tracked supersession (prior entity
    /// revisions replaced by a newer generation) for targeted eviction by the
    /// next [`InMemoryGraph::prune_orphaned_vectors`]. A no-op once a full
    /// reconcile is already pending — the full scan will subsume them.
    #[cfg(feature = "vector")]
    fn note_superseded_vectors(&self, revisions: &[EntityRevisionId]) {
        if revisions.is_empty() {
            return;
        }
        let mut state = self.vector_reconcile.lock();
        if state.full {
            return;
        }
        for rev in revisions {
            state.superseded.insert(RetrievalKey::EntityRevision(*rev));
        }
    }

    /// Reconcile a salvaged vector index — one loaded under a graph-authority
    /// stamp that no longer matches the reopened graph — down to the keys
    /// current truth can prove, so reuse never serves a vector the graph moved
    /// out from under.
    ///
    /// Per-key provability under stamp drift:
    ///
    /// - `EntityRevision` keys are content-addressed (`hash(entity_id,
    ///   change_id)`, and a revision's payload is immutable once minted), so
    ///   membership in current truth proves the vector: retained. Superseded
    ///   and dead-chain keys fall out of truth and are evicted by the full
    ///   prune.
    /// - `Entity` head keys are id-stable across content edits, so presence
    ///   proves nothing on its own. A content edit always mints a new head
    ///   revision, so a head whose current head-revision key is ALSO in the
    ///   index was flushed at-or-after that content and is retained; a head
    ///   whose current head revision has no vector predates the entity's
    ///   current content and is retired for re-embed. An entity with no
    ///   revision chain has no drift signal and is retained as-is.
    /// - `Artifact` keys are id-stable across content edits and artifacts mint
    ///   no embedded revision keys, so drift leaves no per-key proof at all:
    ///   every artifact vector is retired and re-derived from the current
    ///   artifact documents (byte-identical documents re-embed from the text
    ///   cache without inference).
    ///
    /// What this deliberately does not catch: a head vector whose own content
    /// is current but whose graph-derived context lines drifted (a
    /// relation-only change queued live and lost with the process). The live
    /// producer contract re-queues those endpoints while the daemon runs; after
    /// a restart they refresh on next touch. That bounded staleness replaces
    /// discarding the entire index on every reopen whose stamp moved.
    ///
    /// Eviction order is sorted, exactly like the prune, so the surviving index
    /// (and the slot order a later re-embed reuses) is deterministic across
    /// boots.
    #[cfg(feature = "vector")]
    pub fn reconcile_salvaged_vector_index(&self) -> VectorSalvageStats {
        let _span = tracing::info_span!("kindb.reconcile_salvaged_vector_index").entered();
        let vi = match self.vector_index.lock().clone() {
            Some(vi) => vi,
            None => return VectorSalvageStats::default(),
        };

        // Full generation eviction first: drops every key outside current
        // truth (the sidecar load marked a full reconcile pending).
        let evicted_orphans = self.prune_orphaned_vectors();

        let mut retire: Vec<RetrievalKey> = Vec::new();
        {
            let ent = self.entities.read();
            let head_by_entity: hashbrown::HashMap<EntityId, EntityRevisionId> = ent
                .entity_revisions
                .iter()
                .filter(|(id, _)| ent.entities.contains_key(*id))
                .filter_map(|(id, revs)| revs.last().map(|rev| (*id, rev.revision_id)))
                .collect();
            for key in vi.retrievable_keys() {
                match key {
                    RetrievalKey::Artifact(_) | RetrievalKey::ArtifactRevision(_) => {
                        retire.push(key);
                    }
                    RetrievalKey::Entity(id) => {
                        if let Some(head) = head_by_entity.get(&id) {
                            if !vi.contains_retrievable(&RetrievalKey::EntityRevision(*head)) {
                                retire.push(key);
                            }
                        }
                    }
                    RetrievalKey::EntityRevision(_) => {}
                }
            }
        }
        retire.sort_unstable();

        let mut retired_artifact_vectors = 0usize;
        let mut retired_stale_entity_heads = 0usize;
        for key in &retire {
            if vi.remove_retrievable(key).is_ok() {
                match key {
                    RetrievalKey::Artifact(_) | RetrievalKey::ArtifactRevision(_) => {
                        retired_artifact_vectors += 1;
                    }
                    _ => retired_stale_entity_heads += 1,
                }
            }
        }

        VectorSalvageStats {
            retained: vi.len(),
            evicted_orphans,
            retired_artifact_vectors,
            retired_stale_entity_heads,
        }
    }

    /// Return the current head revision id of a live entity's revision chain,
    /// or `None` when the entity is absent or carries no revision history.
    pub fn latest_revision_id_for(&self, entity_id: &EntityId) -> Option<EntityRevisionId> {
        let ent = self.entities.read();
        if !ent.entities.contains_key(entity_id) {
            return None;
        }
        ent.entity_revisions
            .get(entity_id)
            .and_then(|revs| revs.last().map(|rev| rev.revision_id))
    }

    /// Give every revision key this change minted a vector, or a place in the
    /// queue that will build one.
    ///
    /// A change appends a new HEAD `EntityRevision` for each entity it touches,
    /// and `graph_truth_retrievable_keys` counts HEAD revision keys as coverage,
    /// so the instant a change lands the store owes N new vectors while the
    /// prune retires the N it replaced. Nothing else fills them: the transaction
    /// path invalidates `RetrievalKey::Entity` only, and the background embed
    /// worker embeds what is queued rather than what is missing. Left alone,
    /// every commit permanently costs the store one vector per touched entity
    /// and the queue drains to empty with the work outstanding.
    ///
    /// Most of those keys need no inference. A file-wide edit restamps blob
    /// hashes and shifts spans, and neither reaches the formatted embed text, so
    /// the superseded generation's vector is the correct vector for the new key
    /// and is copied onto it. Only the keys whose text genuinely moved are
    /// queued, at `ChangedThisSync` — the same tier the live mutation path uses.
    #[cfg(feature = "vector")]
    fn admit_minted_revision_vectors(&self, minted: &[MintedRevision]) {
        if minted.is_empty() {
            return;
        }
        let vector_index = self.vector_index.lock().clone();
        let mut carried = 0usize;
        // Decide against the index first and take the queue lock once at the
        // end. Holding the queue across index calls would be the only place in
        // the engine where those two are nested, and a lock order that exists
        // nowhere else is a deadlock waiting for its second site.
        let mut to_queue: Vec<RetrievalKey> = Vec::new();
        for entry in minted {
            if let Some(vi) = vector_index.as_ref() {
                if vi.contains_retrievable(&entry.key) {
                    continue;
                }
                if let Some(source) = entry.carry_from {
                    if let Some(vector) = vi.get_retrievable(&source) {
                        if vi.upsert_retrievable(entry.key, &vector).is_ok() {
                            carried += 1;
                            continue;
                        }
                    }
                }
            }
            // No index yet, no vector to carry, or the carry failed. Queueing is
            // the honest answer in every one of those cases: the key is missing
            // and the store now says so.
            to_queue.push(entry.key);
        }
        let queued = to_queue.len();
        if queued > 0 {
            let mut queue = self.embedding_queue.lock();
            for key in to_queue {
                queue.insert_graph_priority_changed(key, EmbedRecency::ChangedThisSync);
            }
        }
        if carried > 0 || queued > 0 {
            tracing::debug!(carried, queued, "admitted minted revision vectors");
        }
    }

    /// Force the next [`InMemoryGraph::prune_orphaned_vectors`] to scan the whole
    /// index against graph truth. Called after an untracked truth change — a
    /// fresh build, a sidecar load, or an entity removal — whose orphan set
    /// cannot be enumerated incrementally.
    #[cfg(feature = "vector")]
    fn mark_vector_full_reconcile(&self) {
        let mut state = self.vector_reconcile.lock();
        state.full = true;
        state.superseded.clear();
    }

    /// Prune orphaned vectors (stub when vector feature is disabled).
    #[cfg(not(feature = "vector"))]
    pub fn prune_orphaned_vectors(&self) -> usize {
        0
    }

    /// Exact `(indexed, total)` embedding coverage, served from
    /// [`InMemoryGraph::embedding_coverage`] whenever neither graph truth nor
    /// the vector index has moved since it was computed.
    ///
    /// Two properties matter more than the caching, because both were how the
    /// old shape starved the embed worker it was polled to observe:
    ///
    /// - the `vector_index` mutex is held only long enough to clone the handle,
    ///   never across the count, so `get_vector_index` on the embed path is
    ///   never queued behind a status call;
    /// - the count itself is one index lock acquisition ([`VectorIndex::count_present`])
    ///   rather than one per key, so a status call waits for at most one
    ///   in-flight batch upsert instead of one per key in the graph.
    ///
    /// Both tokens are read BEFORE the counts. A mutation that lands while the
    /// count is running bumps its token past the recorded one, so the entry
    /// stored here is rejected by the next reader rather than served stale.
    #[cfg(feature = "vector")]
    fn embedding_coverage_counts(&self) -> (usize, usize) {
        let truth_epoch = self.truth_epoch.load(Ordering::Acquire);
        let index = self.vector_index.lock().clone();
        let index_token = index.as_ref().map(|vi| vi.key_set_token());

        if let Some(cached) = *self.embedding_coverage.lock() {
            if cached.truth_epoch == truth_epoch && cached.index_token == index_token {
                return (cached.indexed, cached.total);
            }
        }

        self.embedding_coverage_scans
            .fetch_add(1, Ordering::Relaxed);
        run_embedding_coverage_before_count_hook(self);
        let truth = self.graph_truth_retrievable_keys();
        let total = truth.len();
        // No index loaded is not the same as an index holding nothing: the first
        // has no coverage to report, the second has coverage zero. Both answer
        // `indexed = 0`; `index_token` is what keeps their cache entries apart.
        let indexed = index
            .as_ref()
            .map(|vi| vi.count_present(&truth))
            .unwrap_or(0);

        *self.embedding_coverage.lock() = Some(EmbeddingCoverage {
            truth_epoch,
            index_token,
            indexed,
            total,
        });
        (indexed, total)
    }

    /// Get the current embedding status.
    ///
    /// The returned `pending` field is `max(queue_length, total - indexed)` so
    /// that coverage gates remain correct when entities exist that have not
    /// yet been queued for embedding (the steady state after loading a graph
    /// whose embedding queue does not persist across restarts).
    pub fn embedding_status(&self) -> EmbeddingStatus {
        #[cfg(feature = "vector")]
        let (queue_len, indexed, total) = {
            let queue_len =
                self.embedding_queue.lock().len() + self.artifact_embedding_queue.lock().len();
            let (indexed, total) = self.embedding_coverage_counts();
            (queue_len, indexed, total)
        };
        #[cfg(not(feature = "vector"))]
        let (queue_len, indexed, total) = (0usize, 0usize, self.entity_count());

        let pending = queue_len.max(total.saturating_sub(indexed));
        EmbeddingStatus {
            pending,
            indexed,
            total,
        }
    }

    /// Batch-upsert multiple entities under a single write lock.
    ///
    /// This avoids the per-entity lock acquire/release overhead of calling
    /// `upsert_entity` in a loop. Index entries are updated incrementally
    /// for each entity (old entries removed, new entries inserted).
    pub fn batch_upsert_entities(&self, entities: &[Entity]) -> Result<(), KinDbError> {
        let mut ent = self.entities_write();
        let entity_ids: Vec<EntityId> = entities.iter().map(|entity| entity.id).collect();
        for entity in entities {
            if let Some(old) = ent.entities.remove(&entity.id) {
                // Delta optimization: skip index churn when indexed fields unchanged
                let name_changed = old.name != entity.name;
                let file_changed = old.file_origin != entity.file_origin;
                let kind_changed = old.kind != entity.kind;

                if name_changed || file_changed || kind_changed {
                    ent.indexes
                        .remove(&old.id, &old.name, old.file_origin.as_ref(), old.kind);
                    ent.indexes.insert(
                        entity.id,
                        &entity.name,
                        entity.file_origin.as_ref(),
                        entity.kind,
                    );
                }
            } else {
                ent.indexes.insert(
                    entity.id,
                    &entity.name,
                    entity.file_origin.as_ref(),
                    entity.kind,
                );
            }
            ent.entities.insert(entity.id, entity.clone());
        }
        for entity in entities {
            self.record_entity_delta_upsert(entity.clone());
        }
        let affected = collect_entity_refresh_targets(&ent, &entity_ids);
        self.refresh_merkle_for_entities(&ent, entity_ids.iter().copied());
        drop(ent);
        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;

        Ok(())
    }

    /// Batch-remove multiple entities under a single write lock.
    ///
    /// Removes each entity and its connected relations in one lock
    /// acquisition, avoiding per-entity lock overhead.
    pub fn batch_remove_entities(&self, ids: &[EntityId]) -> Result<(), KinDbError> {
        let mut ent = self.entities_write();
        let removed_ids: HashSet<EntityId> = ids.iter().copied().collect();
        let mut affected_neighbors = HashSet::new();
        for id in ids {
            if let Some(outgoing) = ent.outgoing.get(id) {
                for rel_id in outgoing {
                    if let Some(rel) = ent.relations.get(rel_id) {
                        if let Some(neighbor) = entity_neighbor_for_relation(rel, id) {
                            if !removed_ids.contains(&neighbor) {
                                affected_neighbors.insert(neighbor);
                            }
                        }
                    }
                }
            }
            if let Some(incoming) = ent.incoming.get(id) {
                for rel_id in incoming {
                    if let Some(rel) = ent.relations.get(rel_id) {
                        if let Some(neighbor) = entity_neighbor_for_relation(rel, id) {
                            if !removed_ids.contains(&neighbor) {
                                affected_neighbors.insert(neighbor);
                            }
                        }
                    }
                }
            }

            if let Some(entity) = ent.entities.remove(id) {
                ent.indexes.remove(
                    &entity.id,
                    &entity.name,
                    entity.file_origin.as_ref(),
                    entity.kind,
                );
            }
            let removed_relations = remove_relations_for_entity(&mut ent, id);
            self.record_entity_delta_remove(*id);
            for relation in &removed_relations {
                self.record_relation_delta_remove(&ent, relation);
            }
        }
        let merkle_seeds: Vec<EntityId> = removed_ids
            .iter()
            .copied()
            .chain(affected_neighbors.iter().copied())
            .collect();
        self.refresh_merkle_for_entities(&ent, merkle_seeds);
        drop(ent);

        if let Some(ref ti) = self.text_index {
            for id in ids {
                let _ = ti.remove(id);
            }
            self.text_dirty.store(true, Ordering::Release);
        }

        // Remove vectors for deleted entities.
        #[cfg(feature = "vector")]
        {
            let mut queue = self.embedding_queue.lock();
            for id in ids {
                queue.remove(&RetrievalKey::Entity(*id));
            }
            drop(queue);

            if let Some(ref vi) = *self.vector_index.lock() {
                for id in ids {
                    let _ = vi.remove(id);
                }
            }
        }

        let affected_neighbors: Vec<EntityId> = affected_neighbors.into_iter().collect();
        self.refresh_text_index_for_entities(&affected_neighbors);
        self.invalidate_entities_for_embedding(&affected_neighbors)?;

        Ok(())
    }

    // ---------------------------------------------------------------
    // Non-trait methods (needed by commit.rs, matching KuzuGraphStore)
    // ---------------------------------------------------------------

    /// Remove all outgoing relations for an entity.
    /// Called during re-linking after file re-parse.
    pub fn remove_outgoing_relations(&self, id: &EntityId) -> Result<(), KinDbError> {
        let mut ent = self.entities_write();
        let mut affected = HashSet::new();
        if let Some(rel_ids) = ent.outgoing.remove(id) {
            for rel_id in &rel_ids {
                if let Some(rel) = ent.relations.remove(rel_id) {
                    affected.extend(entity_ids_for_relation(&rel));
                    remove_relation_indexes(&mut ent, &rel);
                    self.record_relation_delta_remove(&ent, &rel);
                }
            }
        }
        let affected: Vec<EntityId> = affected.into_iter().collect();
        self.refresh_merkle_for_entities(
            &ent,
            std::iter::once(*id).chain(affected.iter().copied()),
        );
        drop(ent);

        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;
        Ok(())
    }

    /// Delete a shallow tracked file by file path.
    pub fn delete_shallow_file(&self, file_id: &FilePathId) -> Result<(), KinDbError> {
        let artifact_id = self.require_artifact_id(file_id)?;

        let mut ent = self.entities_write();
        let old = ent.shallow_files.remove(file_id);
        self.record_shallow_file_delta_remove(old, file_id.clone());
        drop(ent);

        let key = RetrievalKey::Artifact(artifact_id);
        self.remove_retrievable_text_index(&key)?;
        self.remove_retrievable_vector(&key)?;
        #[cfg(feature = "vector")]
        {
            self.artifact_embedding_queue.lock().remove(&artifact_id);
        }
        Ok(())
    }

    /// Get a single shallow tracked file.
    pub fn get_shallow_file(
        &self,
        file_id: &FilePathId,
    ) -> Result<Option<ShallowTrackedFile>, KinDbError> {
        Ok(self.entities.read().shallow_files.get(file_id).cloned())
    }

    // -------------------------------------------------------------------
    // Session/intent management — additional methods beyond SessionStore
    // (Core CRUD is in `impl SessionStore for InMemoryGraph` below.)
    // -------------------------------------------------------------------

    pub fn hard_collisions_for_entity(
        &self,
        entity_id: &EntityId,
        exclude_intent: &IntentId,
    ) -> Result<Vec<Intent>, KinDbError> {
        Ok(self
            .sessions
            .read()
            .intents
            .values()
            .filter(|i| {
                i.intent_id != *exclude_intent
                    && i.scopes
                        .iter()
                        .any(|s| matches!(s, IntentScope::Entity(eid) if eid == entity_id))
                    && i.lock_type == LockType::Hard
            })
            .cloned()
            .collect())
    }
    pub fn locks_for_entity(&self, entity_id: &EntityId) -> Result<Vec<Intent>, KinDbError> {
        Ok(self
            .sessions
            .read()
            .intents
            .values()
            .filter(|i| {
                i.scopes
                    .iter()
                    .any(|s| matches!(s, IntentScope::Entity(eid) if eid == entity_id))
                    && i.lock_type == LockType::Hard
            })
            .cloned()
            .collect())
    }
    pub fn downstream_warnings_for_entity(
        &self,
        entity_id: &EntityId,
    ) -> Result<Vec<Intent>, KinDbError> {
        let ses = self.sessions.read();
        let intent_ids: Vec<IntentId> = ses
            .downstream_warnings
            .iter()
            .filter(|(_, eid, _)| eid == entity_id)
            .map(|(iid, _, _)| *iid)
            .collect();
        Ok(intent_ids
            .iter()
            .filter_map(|iid| ses.intents.get(iid).cloned())
            .collect())
    }
    pub fn create_downstream_warning(
        &self,
        intent_id: &IntentId,
        entity_id: &EntityId,
        reason: &str,
    ) -> Result<(), KinDbError> {
        self.sessions.write().downstream_warnings.push((
            *intent_id,
            *entity_id,
            reason.to_string(),
        ));
        self.require_full_snapshot();
        Ok(())
    }

    // -------------------------------------------------------------------
    // Incremental indexing helpers
    // -------------------------------------------------------------------

    /// Remove all entities and their outgoing relations for entities in a given file.
    ///
    /// Incoming relations from OTHER files pointing to removed entities are kept
    /// (they become dangling but will be fixed during the cross-file linking phase).
    ///
    /// Returns the removed entity IDs.
    pub fn remove_entities_for_file(&self, path: &str) -> Vec<EntityId> {
        let mut ent = self.entities_write();

        // Find all entity IDs in this file via the file index.
        let entity_ids: Vec<EntityId> = ent.indexes.by_file(path).to_vec();

        if entity_ids.is_empty() {
            return Vec::new();
        }

        let entity_set: hashbrown::HashSet<EntityId> = entity_ids.iter().copied().collect();
        let mut merkle_seeds: HashSet<EntityId> = entity_ids.iter().copied().collect();

        for &eid in &entity_ids {
            // Remove the entity itself.
            if let Some(entity) = ent.entities.remove(&eid) {
                ent.indexes.remove(
                    &entity.id,
                    &entity.name,
                    entity.file_origin.as_ref(),
                    entity.kind,
                );
                self.record_entity_delta_remove(eid);
            }

            // Remove all outgoing relations from this entity.
            if let Some(out_rids) = ent.outgoing.remove(&eid) {
                for rid in &out_rids {
                    if let Some(rel) = ent.relations.remove(rid) {
                        remove_relation_indexes(&mut ent, &rel);
                        self.record_relation_delta_remove(&ent, &rel);
                    }
                }
            }

            // Remove incoming relations that originate from entities in the SAME file
            // (they were already removed above as outgoing from another entity in
            // entity_ids). For incoming relations from OTHER files, keep them as
            // dangling. We only need to clean up the incoming vec for this entity.
            if let Some(inc_rids) = ent.incoming.remove(&eid) {
                {
                    let mut pending = self.pending_delta.lock();
                    delta_map_remove(&mut pending.delta.incoming, eid);
                }
                for rid in &inc_rids {
                    // If the relation still exists, it's from an external file — keep it
                    // in the relations map but just remove from this entity's incoming vec
                    // (which we already did by removing the key). However we also need to
                    // check if the source is in the same file set — if so the relation
                    // was already removed above.
                    if let Some(rel) = ent.relations.get(rid) {
                        if let Some(src) = rel.src.as_entity() {
                            if entity_set.contains(&src) {
                                // Already removed as outgoing above — this is a leftover ref.
                                // The relation is already gone from ent.relations via the
                                // outgoing removal pass.
                            } else {
                                merkle_seeds.insert(src);
                            }
                        }
                        // If src is NOT in entity_set, this is a cross-file incoming
                        // relation. Keep the relation in ent.relations (dangling dst).
                    }
                }
            }
        }

        self.refresh_merkle_for_entities(&ent, merkle_seeds);

        entity_ids
    }

    /// Get all byte-exact paths present in the graph-owned repository tree.
    pub fn repository_paths(&self) -> Vec<RepoPath> {
        self.entities
            .read()
            .resolved_tree
            .artifacts_by_path()
            .map(|artifact| artifact.path.clone())
            .collect()
    }

    /// Admit or update one UTF-8 artifact through the real tree transaction
    /// path. Test-only ingestion helper; production callers supply identities
    /// and deltas at the import/reconcile boundary.
    #[cfg(test)]
    pub(crate) fn admit_artifact_for_test(&self, path: &str, entry: TreeEntry) -> ArtifactId {
        let path = RepoPath::from_utf8(path).expect("valid test repository path");
        let existing = self.resolved_tree().artifact_at_path(&path).cloned();
        let artifact_id = existing
            .as_ref()
            .map(|artifact| artifact.artifact_id)
            .unwrap_or_else(ArtifactId::new);
        if existing
            .as_ref()
            .is_some_and(|artifact| artifact.entry == entry)
        {
            return artifact_id;
        }
        let tree_delta = match existing {
            Some(artifact) => TreeDelta::Updated {
                artifact_id,
                old: artifact.located_entry(),
                new: LocatedEntry::new(path, entry),
            },
            None => TreeDelta::Added {
                artifact_id,
                new: LocatedEntry::new(path, entry),
            },
        };
        self.apply_transaction_delta(&TransactionDelta {
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: vec![tree_delta],
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        })
        .expect("test artifact admission");
        artifact_id
    }

    #[cfg(test)]
    pub(crate) fn tree_entry_for_test(&self, path: &str) -> Option<TreeEntry> {
        let path = RepoPath::from_utf8(path).ok()?;
        self.resolved_tree()
            .artifact_at_path(&path)
            .map(|artifact| artifact.entry)
    }

    #[cfg(test)]
    pub(crate) fn remove_admitted_artifact_for_test(&self, path: &str) -> Option<TreeEntry> {
        let path = RepoPath::from_utf8(path).ok()?;
        let artifact = self.resolved_tree().artifact_at_path(&path).cloned()?;
        self.apply_transaction_delta(&TransactionDelta {
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: vec![TreeDelta::Removed {
                artifact_id: artifact.artifact_id,
                old: artifact.located_entry(),
            }],
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        })
        .expect("test artifact removal");
        Some(artifact.entry)
    }

    /// Get file paths that have at least one entity (function, class, etc.).
    /// Unlike [`Self::repository_paths`], which returns every admitted artifact,
    /// this returns only files the parser extracted semantic entities from.
    pub fn entity_bearing_file_paths(&self) -> Vec<String> {
        self.entities.read().indexes.file.keys().cloned().collect()
    }
}

impl Default for InMemoryGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for InMemoryGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ent = self.entities.read();
        let chg = self.changes.read();
        f.debug_struct("InMemoryGraph")
            .field("entities", &ent.entities.len())
            .field("relations", &ent.relations.len())
            .field("changes", &chg.changes.len())
            .finish()
    }
}

/// Remove all relations connected to an entity, cleaning up both sides of each edge.
///
/// This is a shared helper used by `remove_entity` and `remove_entities_for_file`
/// to ensure relations are fully cleaned up (no dangling entries in `ent.relations`,
/// `ent.outgoing`, or `ent.incoming`).
fn remove_relations_for_entity(ent: &mut EntityData, entity_id: &EntityId) -> Vec<Relation> {
    // Collect all relation IDs from both directions
    let mut relation_ids = Vec::new();
    if let Some(outgoing) = ent.outgoing.get(entity_id) {
        relation_ids.extend(outgoing.iter().cloned());
    }
    if let Some(incoming) = ent.incoming.get(entity_id) {
        relation_ids.extend(incoming.iter().cloned());
    }

    // Remove each relation and clean up the other side's edge list
    let mut removed = Vec::new();
    for rel_id in &relation_ids {
        if let Some(rel) = ent.relations.remove(rel_id) {
            remove_relation_indexes(ent, &rel);
            removed.push(rel);
        }
    }

    // Remove the entity's own edge lists
    ent.outgoing.remove(entity_id);
    ent.incoming.remove(entity_id);
    removed
}

fn graph_node_is_admitted(
    node: GraphNodeId,
    entity_ids: &HashSet<EntityId>,
    artifact_ids: &HashSet<ArtifactId>,
    external_reference_ids: &HashSet<ExternalReferenceId>,
    work: &WorkData,
    verification: &VerificationData,
) -> bool {
    match node {
        GraphNodeId::Entity(id) => entity_ids.contains(&id),
        GraphNodeId::Artifact(id) => artifact_ids.contains(&id),
        GraphNodeId::Test(id) => verification.test_cases.contains_key(&id),
        GraphNodeId::Contract(id) => verification.contracts.contains_key(&id),
        GraphNodeId::Work(id) => work.work_items.contains_key(&id),
        GraphNodeId::VerificationRun(id) => verification.verification_runs.contains_key(&id),
        GraphNodeId::ExternalReference(id) => external_reference_ids.contains(&id),
    }
}

fn admitted_artifact_id(ent: &EntityData, file_id: &FilePathId) -> Result<ArtifactId, KinDbError> {
    let path = repo_path_for_file_path(file_id)?;
    ent.resolved_tree.artifact_id_at_path(&path).ok_or_else(|| {
        KinDbError::StorageError(format!(
            "semantic enrichment exists without admitted repository identity at {}",
            file_id.0
        ))
    })
}

fn validate_entity_enrichment_admission(ent: &EntityData) -> Result<(), KinDbError> {
    for file_id in ent
        .shallow_files
        .keys()
        .chain(ent.file_layouts.keys())
        .chain(ent.structured_artifacts.keys())
        .chain(ent.opaque_artifacts.keys())
    {
        admitted_artifact_id(ent, file_id)?;
    }
    Ok(())
}

fn tree_delta_invalidates_path_facets(delta: &TreeDelta) -> bool {
    match (delta.old_state(), delta.new_state()) {
        (Some(_), None) => true,
        (Some(old), Some(new)) if old.path != new.path => true,
        (
            Some(LocatedEntry {
                entry: TreeEntry::Blob { hash: old, .. },
                ..
            }),
            Some(LocatedEntry {
                entry: TreeEntry::Blob { hash: new, .. },
                ..
            }),
        ) => old != new,
        (Some(old), Some(new)) => old.entry != new.entry,
        (None, _) => false,
    }
}

fn collect_artifact_text_index_docs(
    ent: &EntityData,
) -> Result<Vec<(RetrievalKey, Vec<(String, f32)>)>, KinDbError> {
    let mut docs = Vec::with_capacity(
        ent.shallow_files.len() + ent.structured_artifacts.len() + ent.opaque_artifacts.len(),
    );
    for file in ent.shallow_files.values() {
        docs.push((
            RetrievalKey::Artifact(admitted_artifact_id(ent, &file.file_id)?),
            shallow_file_fields(file),
        ));
    }
    for artifact in ent.structured_artifacts.values() {
        docs.push((
            RetrievalKey::Artifact(admitted_artifact_id(ent, &artifact.file_id)?),
            structured_artifact_fields(artifact),
        ));
    }
    for artifact in ent.opaque_artifacts.values() {
        docs.push((
            RetrievalKey::Artifact(admitted_artifact_id(ent, &artifact.file_id)?),
            opaque_artifact_fields(artifact),
        ));
    }
    Ok(docs)
}

#[cfg(feature = "vector")]
fn collect_artifact_ids(ent: &EntityData) -> Vec<ArtifactId> {
    let mut ids = Vec::with_capacity(
        ent.shallow_files.len() + ent.structured_artifacts.len() + ent.opaque_artifacts.len(),
    );

    ids.extend(ent.shallow_files.keys().map(|file_id| {
        admitted_artifact_id(ent, file_id)
            .expect("validated shallow enrichment must have repository identity")
    }));
    ids.extend(ent.structured_artifacts.keys().map(|file_id| {
        admitted_artifact_id(ent, file_id)
            .expect("validated structured enrichment must have repository identity")
    }));
    ids.extend(ent.opaque_artifacts.keys().map(|file_id| {
        admitted_artifact_id(ent, file_id)
            .expect("validated opaque enrichment must have repository identity")
    }));

    ids
}

#[cfg(all(feature = "embeddings", feature = "vector"))]
fn artifact_embedding_doc(
    ent: &EntityData,
    artifact_id: &ArtifactId,
) -> Option<(RetrievalKey, String)> {
    let file_path = file_path_for_repo_path(&ent.resolved_tree.get(artifact_id)?.path)?;

    if let Some(file) = ent.shallow_files.get(&file_path) {
        return Some((
            RetrievalKey::Artifact(*artifact_id),
            crate::embed::format_shallow_text(file),
        ));
    }

    if let Some(artifact) = ent.structured_artifacts.get(&file_path) {
        return Some((
            RetrievalKey::Artifact(*artifact_id),
            crate::embed::format_artifact_text(artifact),
        ));
    }

    if let Some(artifact) = ent.opaque_artifacts.get(&file_path) {
        return Some((
            RetrievalKey::Artifact(*artifact_id),
            crate::embed::format_opaque_text(artifact),
        ));
    }

    None
}

fn collect_text_index_extra_fields(ent: &EntityData, entity_id: &EntityId) -> Vec<(String, f32)> {
    let mut fields = Vec::new();
    // Deduplicate by (tag, text) without allocating format strings.
    let mut seen_imports: HashSet<&str> = HashSet::new();
    let mut seen_neighbors: HashSet<&str> = HashSet::new();

    collect_relation_text_fields(
        ent,
        ent.outgoing.get(entity_id).into_iter().flatten(),
        entity_id,
        &mut seen_imports,
        &mut seen_neighbors,
        &mut fields,
    );
    collect_relation_text_fields(
        ent,
        ent.incoming.get(entity_id).into_iter().flatten(),
        entity_id,
        &mut seen_imports,
        &mut seen_neighbors,
        &mut fields,
    );

    fields
}

fn collect_relation_text_fields<'a>(
    ent: &'a EntityData,
    relation_ids: impl Iterator<Item = &'a RelationId>,
    entity_id: &EntityId,
    seen_imports: &mut HashSet<&'a str>,
    seen_neighbors: &mut HashSet<&'a str>,
    fields: &mut Vec<(String, f32)>,
) {
    for relation_id in relation_ids {
        let Some(relation) = ent.relations.get(relation_id) else {
            continue;
        };
        if relation.kind == RelationKind::Contains {
            continue;
        }

        if let Some(import_source) = relation.import_source.as_deref() {
            let import_source = import_source.trim();
            if !import_source.is_empty() && seen_imports.insert(import_source) {
                fields.push((import_source.to_string(), TEXT_INDEX_IMPORT_SOURCE_WEIGHT));
            }
        }

        let Some(neighbor_id) = entity_neighbor_for_relation(relation, entity_id) else {
            continue;
        };
        let Some(neighbor) = ent.entities.get(&neighbor_id) else {
            continue;
        };
        let neighbor_name = neighbor.name.trim();
        if !neighbor_name.is_empty() && seen_neighbors.insert(neighbor_name) {
            fields.push((neighbor_name.to_string(), TEXT_INDEX_NEIGHBOR_NAME_WEIGHT));
        }
    }
}

#[cfg(all(feature = "embeddings", feature = "vector"))]
fn collect_embedding_context_lines(ent: &EntityData, entity_id: &EntityId) -> Vec<String> {
    let mut candidates: Vec<(&'static str, String, f32)> = Vec::new();

    collect_relation_embedding_context(
        ent,
        ent.outgoing.get(entity_id).into_iter().flatten(),
        entity_id,
        true,
        &mut candidates,
    );

    candidates.sort_by(|a, b| {
        b.2.total_cmp(&a.2)
            .then_with(|| a.0.cmp(b.0))
            .then_with(|| a.1.cmp(&b.1))
    });

    let mut seen = HashSet::new();
    let mut per_label: HashMap<&'static str, usize> = HashMap::new();
    let mut lines = Vec::new();

    for (label, value, _) in candidates {
        let dedupe_key = format!("{label}\u{0}{value}");
        if !seen.insert(dedupe_key) {
            continue;
        }

        let count = per_label.entry(label).or_insert(0);
        if *count >= MAX_EMBED_CONTEXT_VALUES_PER_LABEL {
            continue;
        }
        *count += 1;
        lines.push(format!("{label}: {value}"));
    }

    lines
}

#[cfg(all(feature = "embeddings", feature = "vector"))]
fn collect_relation_embedding_context<'a>(
    ent: &EntityData,
    relation_ids: impl Iterator<Item = &'a RelationId>,
    entity_id: &EntityId,
    outgoing: bool,
    candidates: &mut Vec<(&'static str, String, f32)>,
) {
    for relation_id in relation_ids {
        let Some(relation) = ent.relations.get(relation_id) else {
            continue;
        };
        if relation.kind == RelationKind::Contains {
            continue;
        }

        let base_score = relation.confidence.max(0.0);

        if let Some(import_source) = relation.import_source.as_deref() {
            let import_source = import_source.trim();
            if !import_source.is_empty() {
                push_embedding_context_value(
                    candidates,
                    "import_source",
                    import_source,
                    base_score + 0.2,
                );
            }
        }

        let Some(neighbor_id) = entity_neighbor_for_relation(relation, entity_id) else {
            continue;
        };
        let Some(neighbor) = ent.entities.get(&neighbor_id) else {
            continue;
        };
        let neighbor_name = neighbor.name.trim();
        if neighbor_name.is_empty() {
            continue;
        }

        push_embedding_context_value(
            candidates,
            relation_embedding_label(relation.kind, outgoing),
            neighbor_name,
            base_score,
        );
    }
}

#[cfg(all(feature = "embeddings", feature = "vector"))]
fn push_embedding_context_value(
    candidates: &mut Vec<(&'static str, String, f32)>,
    label: &'static str,
    value: &str,
    score: f32,
) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    candidates.push((label, value.to_string(), score));
}

#[cfg(all(feature = "embeddings", feature = "vector"))]
fn relation_embedding_label(kind: RelationKind, outgoing: bool) -> &'static str {
    match (kind, outgoing) {
        (RelationKind::Calls, true) => "calls",
        (RelationKind::Calls, false) => "called_by",
        (RelationKind::Imports, true) => "imports",
        (RelationKind::Imports, false) => "imported_by",
        (RelationKind::Includes, true) => "includes",
        (RelationKind::Includes, false) => "included_by",
        (RelationKind::References, true) => "references",
        (RelationKind::References, false) => "referenced_by",
        (RelationKind::UsesMacro, true) => "uses_macro",
        (RelationKind::UsesMacro, false) => "macro_used_by",
        (RelationKind::Implements, true) => "implements",
        (RelationKind::Implements, false) => "implemented_by",
        (RelationKind::Extends, true) => "extends",
        (RelationKind::Extends, false) => "extended_by",
        (RelationKind::Tests, true) => "tests",
        (RelationKind::Tests, false) => "tested_by",
        (RelationKind::DependsOn, true) => "depends_on",
        (RelationKind::DependsOn, false) => "depended_on_by",
        (RelationKind::CoChanges, true) => "co_changes",
        (RelationKind::CoChanges, false) => "co_changed_with",
        (RelationKind::DefinesContract, true) => "defines_contract",
        (RelationKind::DefinesContract, false) => "defined_by",
        (RelationKind::ConsumesContract, true) => "consumes_contract",
        (RelationKind::ConsumesContract, false) => "consumed_by",
        (RelationKind::EmitsEvent, true) => "emits_event",
        (RelationKind::EmitsEvent, false) => "emitted_by",
        (RelationKind::OwnedBy, true) => "owned_by",
        (RelationKind::OwnedBy, false) => "owns",
        (RelationKind::DocumentedBy, true) => "documented_by",
        (RelationKind::DocumentedBy, false) => "documents",
        (RelationKind::Covers, true) => "covers",
        (RelationKind::Covers, false) => "covered_by",
        (RelationKind::DerivedFrom, true) => "derived_from",
        (RelationKind::DerivedFrom, false) => "derives",
        (RelationKind::OwnedByFile, true) => "owned_by_file",
        (RelationKind::OwnedByFile, false) => "owns_file",
        (RelationKind::Contains, _) => "contains",
        (RelationKind::Overrides, true) => "overrides",
        (RelationKind::Overrides, false) => "overridden_by",
        (RelationKind::Instantiates, true) => "instantiates",
        (RelationKind::Instantiates, false) => "instantiated_by",
        (RelationKind::UsesType, true) => "uses_type",
        (RelationKind::UsesType, false) => "type_used_by",
        (RelationKind::SubscribesTo, true) => "subscribes_to",
        (RelationKind::SubscribesTo, false) => "subscribed_by",
        (RelationKind::SendsMessage, true) => "sends_message",
        (RelationKind::SendsMessage, false) => "message_from",
        (RelationKind::Spawns, true) => "spawns",
        (RelationKind::Spawns, false) => "spawned_by",
    }
}

impl EntityStore for InMemoryGraph {
    type Error = KinDbError;

    fn artifact_id_at_path(&self, path: &RepoPath) -> Option<ArtifactId> {
        InMemoryGraph::artifact_id_at_path(self, path)
    }

    // -----------------------------------------------------------------------
    // Read operations — entities lock only
    // -----------------------------------------------------------------------

    fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>, KinDbError> {
        let _span = tracing::info_span!("kindb.get_entity").entered();
        Ok(self.entities.read().entities.get(id).cloned())
    }

    fn get_relations(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
    ) -> Result<Vec<Relation>, KinDbError> {
        let ent = self.entities.read();
        let mut result = Vec::new();

        if let Some(edge_ids) = ent.outgoing.get(id) {
            for rid in edge_ids {
                if let Some(rel) = ent.relations.get(rid) {
                    if relation_is_entity_only(rel)
                        && (kinds.is_empty() || kinds.contains(&rel.kind))
                    {
                        result.push(rel.clone());
                    }
                }
            }
        }

        // Canonical, insertion-order-independent ordering.
        result.sort_unstable_by_key(|r| r.id.0);
        Ok(result)
    }

    fn get_all_relations_for_entity(&self, id: &EntityId) -> Result<Vec<Relation>, KinDbError> {
        let _span = tracing::info_span!("kindb.get_all_relations_for_entity").entered();
        let ent = self.entities.read();
        let mut result = Vec::new();
        let mut seen = hashbrown::HashSet::new();

        // Outgoing
        if let Some(edge_ids) = ent.outgoing.get(id) {
            for rid in edge_ids {
                if let Some(rel) = ent.relations.get(rid) {
                    if relation_is_entity_only(rel) && seen.insert(rel.id) {
                        result.push(rel.clone());
                    }
                }
            }
        }

        // Incoming
        if let Some(edge_ids) = ent.incoming.get(id) {
            for rid in edge_ids {
                if let Some(rel) = ent.relations.get(rid) {
                    if relation_is_entity_only(rel) && seen.insert(rel.id) {
                        result.push(rel.clone());
                    }
                }
            }
        }

        // Canonical, insertion-order-independent ordering.
        result.sort_unstable_by_key(|r| r.id.0);
        Ok(result)
    }

    fn get_downstream_impact(
        &self,
        id: &EntityId,
        max_depth: u32,
    ) -> Result<Vec<Entity>, KinDbError> {
        let ent = self.entities.read();
        Ok(traverse::downstream_impact(
            id,
            max_depth,
            &ent.entities,
            &ent.incoming,
            &ent.relations,
        ))
    }

    fn get_dependency_neighborhood(
        &self,
        id: &EntityId,
        depth: u32,
    ) -> Result<SubGraph, KinDbError> {
        let _span =
            tracing::info_span!("kindb.get_dependency_neighborhood", depth = depth).entered();
        let ent = self.entities.read();
        Ok(traverse::bfs_neighborhood(
            id,
            depth,
            &ent.entities,
            &ent.relations,
            &ent.outgoing,
        ))
    }

    fn expand_neighborhood(
        &self,
        entity_ids: &[EntityId],
        edge_kinds: &[RelationKind],
        depth: u32,
    ) -> Result<SubGraph, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.expand_neighborhood",
            seeds = entity_ids.len(),
            edge_kinds = edge_kinds.len(),
            depth = depth
        )
        .entered();
        let ent = self.entities.read();
        Ok(traverse::expand_neighborhood(
            entity_ids,
            edge_kinds,
            depth,
            &ent.entities,
            &ent.relations,
            &ent.outgoing,
            &ent.incoming,
        ))
    }

    fn traverse(
        &self,
        start: &GraphNodeId,
        edge_kinds: &[RelationKind],
        depth: u32,
    ) -> Result<SubGraph, KinDbError> {
        let ent = self.entities.read();
        Ok(traverse::traverse(
            start,
            edge_kinds,
            depth,
            traverse::TraversalGraph {
                entities: &ent.entities,
                external_references: &ent.external_references,
                relations: &ent.relations,
                outgoing: &ent.node_outgoing,
                incoming: &ent.node_incoming,
            },
        ))
    }

    fn find_dead_code(&self) -> Result<Vec<Entity>, KinDbError> {
        let ent = self.entities.read();
        Ok(traverse::find_dead_code(
            &ent.entities,
            &ent.incoming,
            &ent.relations,
        ))
    }

    fn has_incoming_relation_kinds(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
        exclude_same_file: bool,
    ) -> Result<bool, KinDbError> {
        let ent = self.entities.read();
        let entity = match ent.entities.get(id) {
            Some(e) => e,
            None => return Ok(false),
        };
        Ok(traverse::has_incoming_of_kinds(
            id,
            entity,
            kinds,
            exclude_same_file,
            &ent.incoming,
            &ent.relations,
            &ent.entities,
        ))
    }

    fn query_entities(&self, filter: &EntityFilter) -> Result<Vec<Entity>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.query_entities",
            has_file = filter.file_path.is_some(),
            has_name = filter.name_pattern.is_some(),
            has_kinds = filter.kinds.as_ref().map(|kinds| kinds.len()).unwrap_or(0)
        )
        .entered();
        let ent = self.entities.read();

        // Only the name-pattern lookup produces a meaningful, deterministic
        // candidate order (exact matches ahead of token matches, id-sorted
        // within each group). The file/kind/all branches iterate hash sets in
        // arbitrary order, so their candidate order must NOT leak into the
        // result order — those fall back to a pure id-sort below.
        let candidate_order_is_ranked;
        let candidate_ids: Vec<EntityId> = if let Some(ref fp) = filter.file_path {
            candidate_order_is_ranked = false;
            ent.indexes.by_file(&fp.0).to_vec()
        } else if let Some(ref pattern) = filter.name_pattern {
            candidate_order_is_ranked = true;
            ent.indexes.by_name_pattern(pattern)
        } else if let Some(ref kinds) = filter.kinds {
            candidate_order_is_ranked = false;
            if kinds.len() == 1 {
                ent.indexes.by_kind(kinds[0]).to_vec()
            } else {
                ent.entities.keys().copied().collect()
            }
        } else {
            candidate_order_is_ranked = false;
            ent.entities.keys().copied().collect()
        };

        // Capture each id's rank position so the relevance order from the index
        // lookup survives the parallel filter below instead of being discarded.
        let rank: HashMap<EntityId, usize> = if candidate_order_is_ranked {
            candidate_ids
                .iter()
                .enumerate()
                .map(|(pos, eid)| (*eid, pos))
                .collect()
        } else {
            HashMap::new()
        };

        let mut results: Vec<Entity> = candidate_ids
            .par_iter()
            .filter_map(|eid| {
                ent.entities.get(eid).and_then(|entity| {
                    if matches_filter(entity, filter) {
                        Some(entity.clone())
                    } else {
                        None
                    }
                })
            })
            .collect();

        // Sort by rank ascending (position 0 = best match), then by entity id
        // as a total tie-break. When candidate order is not ranked the rank map
        // is empty, so every entity shares the same rank and the result is a
        // pure id-sort. Either way the id tie-break makes the order fully
        // deterministic regardless of hash iteration or rayon scheduling.
        results.sort_by(|a, b| {
            let ra = rank.get(&a.id).copied().unwrap_or(usize::MAX);
            let rb = rank.get(&b.id).copied().unwrap_or(usize::MAX);
            ra.cmp(&rb).then_with(|| a.id.cmp(&b.id))
        });
        Ok(results)
    }

    fn list_all_entities(&self) -> Result<Vec<Entity>, KinDbError> {
        Ok(self
            .entities
            .read()
            .entities
            .par_values()
            .cloned()
            .collect())
    }

    // -----------------------------------------------------------------------
    // Write operations — entities lock only
    // -----------------------------------------------------------------------

    fn upsert_entity(&self, entity: &Entity) -> Result<(), KinDbError> {
        let mut ent = self.entities_write();

        // Delta index update: only touch indexes when indexed fields change.
        if let Some(old) = ent.entities.remove(&entity.id) {
            let name_changed = old.name != entity.name;
            let file_changed = old.file_origin != entity.file_origin;
            let kind_changed = old.kind != entity.kind;

            if name_changed || file_changed || kind_changed {
                ent.indexes
                    .remove(&old.id, &old.name, old.file_origin.as_ref(), old.kind);
                ent.indexes.insert(
                    entity.id,
                    &entity.name,
                    entity.file_origin.as_ref(),
                    entity.kind,
                );
            }
        } else {
            // New entity — insert into indexes
            ent.indexes.insert(
                entity.id,
                &entity.name,
                entity.file_origin.as_ref(),
                entity.kind,
            );
        }

        ent.entities.insert(entity.id, entity.clone());
        let affected = collect_entity_refresh_targets(&ent, &[entity.id]);
        self.record_entity_delta_upsert(entity.clone());
        self.refresh_merkle_for_entities(&ent, std::iter::once(entity.id));
        drop(ent); // Release write lock before text index + embedding work.

        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;

        Ok(())
    }

    fn upsert_relation(&self, relation: &Relation) -> Result<(), KinDbError> {
        let mut ent = self.entities_write();
        let mut affected = HashSet::new();
        let mut merkle_seeds = Vec::new();

        // Remove old edge entries if updating
        if let Some(old) = ent.relations.remove(&relation.id) {
            affected.extend(entity_ids_for_relation(&old));
            merkle_seeds.extend(entity_ids_for_relation(&old));
            remove_relation_indexes(&mut ent, &old);
            self.record_relation_delta_remove(&ent, &old);
        }

        // Insert new edge entries
        insert_relation_indexes(&mut ent, relation);
        ent.relations.insert(relation.id, relation.clone());
        self.record_relation_delta_upsert(&ent, relation.clone());
        affected.extend(entity_ids_for_relation(relation));
        merkle_seeds.extend(entity_ids_for_relation(relation));
        let affected: Vec<EntityId> = affected.into_iter().collect();
        self.refresh_merkle_for_entities(&ent, merkle_seeds);
        drop(ent);
        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;
        Ok(())
    }

    fn remove_entity(&self, id: &EntityId) -> Result<(), KinDbError> {
        let mut ent = self.entities_write();

        let mut affected_neighbors = Vec::new();

        if let Some(entity) = ent.entities.remove(id) {
            ent.indexes.remove(
                &entity.id,
                &entity.name,
                entity.file_origin.as_ref(),
                entity.kind,
            );
            // Keep text index in sync (commit is deferred — call flush_text_index())
            if let Some(ref ti) = self.text_index {
                let _ = ti.remove(id);
                self.text_dirty.store(true, Ordering::Release);
            }

            if let Some(outgoing) = ent.outgoing.get(id) {
                for rel_id in outgoing {
                    if let Some(rel) = ent.relations.get(rel_id) {
                        if let Some(neighbor) = entity_neighbor_for_relation(rel, id) {
                            affected_neighbors.push(neighbor);
                        }
                    }
                }
            }
            if let Some(incoming) = ent.incoming.get(id) {
                for rel_id in incoming {
                    if let Some(rel) = ent.relations.get(rel_id) {
                        if let Some(neighbor) = entity_neighbor_for_relation(rel, id) {
                            affected_neighbors.push(neighbor);
                        }
                    }
                }
            }
        }

        // Clean up all connected relations and edge maps
        let removed_relations = remove_relations_for_entity(&mut ent, id);
        self.record_entity_delta_remove(*id);
        for relation in &removed_relations {
            self.record_relation_delta_remove(&ent, relation);
        }
        let merkle_seeds: Vec<EntityId> = std::iter::once(*id)
            .chain(affected_neighbors.iter().copied())
            .collect();
        self.refresh_merkle_for_entities(&ent, merkle_seeds);
        drop(ent);

        // Remove vector for deleted entity.
        #[cfg(feature = "vector")]
        {
            self.embedding_queue
                .lock()
                .remove(&RetrievalKey::Entity(*id));
            if let Some(ref vi) = *self.vector_index.lock() {
                let _ = vi.remove(id);
            }
            // Removal can leave revision-key vectors behind that the incremental
            // tracker does not enumerate; force a full reconcile to be safe.
            self.mark_vector_full_reconcile();
        }

        self.refresh_text_index_for_entities(&affected_neighbors);
        self.invalidate_entities_for_embedding(&affected_neighbors)?;

        Ok(())
    }

    fn remove_entities_batch(&self, ids: &[EntityId]) -> Result<(), KinDbError> {
        let mut ent = self.entities_write();
        let id_set: hashbrown::HashSet<EntityId> = ids.iter().copied().collect();
        let mut affected_neighbors = Vec::new();

        for id in ids {
            if let Some(entity) = ent.entities.remove(id) {
                ent.indexes.remove(
                    &entity.id,
                    &entity.name,
                    entity.file_origin.as_ref(),
                    entity.kind,
                );

                if let Some(outgoing) = ent.outgoing.get(id) {
                    for rel_id in outgoing {
                        if let Some(rel) = ent.relations.get(rel_id) {
                            if let Some(neighbor) = entity_neighbor_for_relation(rel, id) {
                                if !id_set.contains(&neighbor) {
                                    affected_neighbors.push(neighbor);
                                }
                            }
                        }
                    }
                }
                if let Some(incoming) = ent.incoming.get(id) {
                    for rel_id in incoming {
                        if let Some(rel) = ent.relations.get(rel_id) {
                            if let Some(neighbor) = entity_neighbor_for_relation(rel, id) {
                                if !id_set.contains(&neighbor) {
                                    affected_neighbors.push(neighbor);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Clean up all connected relations and edge maps
        for id in ids {
            let removed_relations = remove_relations_for_entity(&mut ent, id);
            self.record_entity_delta_remove(*id);
            for relation in &removed_relations {
                self.record_relation_delta_remove(&ent, relation);
            }
        }
        let merkle_seeds: Vec<EntityId> = ids
            .iter()
            .copied()
            .chain(affected_neighbors.iter().copied())
            .collect();
        self.refresh_merkle_for_entities(&ent, merkle_seeds);
        drop(ent);

        // Keep text index in sync (commit is deferred — call flush_text_index())
        if let Some(ref ti) = self.text_index {
            let _ = ti.remove_batch(ids)?;
            self.text_dirty.store(true, Ordering::Release);
        }

        // Remove vectors for deleted entities.
        #[cfg(feature = "vector")]
        {
            let mut eq = self.embedding_queue.lock();
            for id in ids {
                eq.remove(&RetrievalKey::Entity(*id));
            }
            if let Some(ref vi) = *self.vector_index.lock() {
                let _ = vi.remove_batch(ids)?;
            }
            self.mark_vector_full_reconcile();
        }

        affected_neighbors.sort_unstable();
        affected_neighbors.dedup();

        self.refresh_text_index_for_entities(&affected_neighbors);
        self.invalidate_entities_for_embedding(&affected_neighbors)?;

        Ok(())
    }

    fn remove_relation(&self, id: &RelationId) -> Result<(), KinDbError> {
        let mut ent = self.entities_write();
        let mut affected = Vec::new();

        if let Some(rel) = ent.relations.remove(id) {
            affected.extend(entity_ids_for_relation(&rel));
            let merkle_seeds = entity_ids_for_relation(&rel);
            remove_relation_indexes(&mut ent, &rel);
            self.record_relation_delta_remove(&ent, &rel);
            self.refresh_merkle_for_entities(&ent, merkle_seeds);
        }

        drop(ent);
        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;
        Ok(())
    }

    fn upsert_shallow_file(&self, shallow: &ShallowTrackedFile) -> Result<(), KinDbError> {
        let artifact_id = self.require_artifact_id(&shallow.file_id)?;
        let old = self
            .entities
            .write()
            .shallow_files
            .insert(shallow.file_id.clone(), shallow.clone());
        self.record_shallow_file_delta_upsert(old, shallow.clone());
        let key = RetrievalKey::Artifact(artifact_id);
        let fields = shallow_file_fields(shallow);
        self.upsert_retrievable_text_index(key, &fields)?;
        self.invalidate_artifact_for_embedding(artifact_id)?;
        Ok(())
    }

    fn list_shallow_files(&self) -> Result<Vec<ShallowTrackedFile>, KinDbError> {
        Ok(self
            .entities
            .read()
            .shallow_files
            .values()
            .cloned()
            .collect())
    }

    fn get_shallow_file(
        &self,
        file_id: &FilePathId,
    ) -> Result<Option<ShallowTrackedFile>, KinDbError> {
        Ok(self.entities.read().shallow_files.get(file_id).cloned())
    }

    fn upsert_structured_artifact(&self, artifact: &StructuredArtifact) -> Result<(), KinDbError> {
        let artifact_id = self.require_artifact_id(&artifact.file_id)?;
        let old = self
            .entities
            .write()
            .structured_artifacts
            .insert(artifact.file_id.clone(), artifact.clone());
        self.record_structured_artifact_delta_upsert(old, artifact.clone());
        let key = RetrievalKey::Artifact(artifact_id);
        let fields = structured_artifact_fields(artifact);
        self.upsert_retrievable_text_index(key, &fields)?;
        self.invalidate_artifact_for_embedding(artifact_id)?;
        Ok(())
    }

    fn list_structured_artifacts(&self) -> Result<Vec<StructuredArtifact>, KinDbError> {
        Ok(self
            .entities
            .read()
            .structured_artifacts
            .values()
            .cloned()
            .collect())
    }

    fn get_structured_artifact(
        &self,
        file_id: &FilePathId,
    ) -> Result<Option<StructuredArtifact>, KinDbError> {
        Ok(self
            .entities
            .read()
            .structured_artifacts
            .get(file_id)
            .cloned())
    }

    fn delete_structured_artifact(&self, file_id: &FilePathId) -> Result<(), KinDbError> {
        let artifact_id = self.require_artifact_id(file_id)?;

        let mut ent = self.entities_write();
        let old = ent.structured_artifacts.remove(file_id);
        self.record_structured_artifact_delta_remove(old, file_id.clone());
        drop(ent);

        let key = RetrievalKey::Artifact(artifact_id);
        self.remove_retrievable_text_index(&key)?;
        self.remove_retrievable_vector(&key)?;
        #[cfg(feature = "vector")]
        {
            self.artifact_embedding_queue.lock().remove(&artifact_id);
        }
        Ok(())
    }

    fn upsert_opaque_artifact(&self, artifact: &OpaqueArtifact) -> Result<(), KinDbError> {
        let artifact_id = self.require_artifact_id(&artifact.file_id)?;
        let old = self
            .entities
            .write()
            .opaque_artifacts
            .insert(artifact.file_id.clone(), artifact.clone());
        self.record_opaque_artifact_delta_upsert(old, artifact.clone());
        let key = RetrievalKey::Artifact(artifact_id);
        let fields = opaque_artifact_fields(artifact);
        self.upsert_retrievable_text_index(key, &fields)?;
        self.invalidate_artifact_for_embedding(artifact_id)?;
        Ok(())
    }

    fn list_opaque_artifacts(&self) -> Result<Vec<OpaqueArtifact>, KinDbError> {
        Ok(self
            .entities
            .read()
            .opaque_artifacts
            .values()
            .cloned()
            .collect())
    }

    fn get_opaque_artifact(
        &self,
        file_id: &FilePathId,
    ) -> Result<Option<OpaqueArtifact>, KinDbError> {
        Ok(self.entities.read().opaque_artifacts.get(file_id).cloned())
    }

    fn delete_opaque_artifact(&self, file_id: &FilePathId) -> Result<(), KinDbError> {
        let artifact_id = self.require_artifact_id(file_id)?;

        let mut ent = self.entities_write();
        let old = ent.opaque_artifacts.remove(file_id);
        self.record_opaque_artifact_delta_remove(old, file_id.clone());
        drop(ent);

        let key = RetrievalKey::Artifact(artifact_id);
        self.remove_retrievable_text_index(&key)?;
        self.remove_retrievable_vector(&key)?;
        #[cfg(feature = "vector")]
        {
            self.artifact_embedding_queue.lock().remove(&artifact_id);
        }
        Ok(())
    }

    fn upsert_file_layout(&self, layout: &FileLayout) -> Result<(), KinDbError> {
        self.require_artifact_id(&layout.file_id)?;
        let old = self
            .entities
            .write()
            .file_layouts
            .insert(layout.file_id.clone(), layout.clone());
        self.record_file_layout_delta_upsert(old, layout.clone());
        Ok(())
    }

    fn get_file_layout(&self, file_id: &FilePathId) -> Result<Option<FileLayout>, KinDbError> {
        Ok(self.entities.read().file_layouts.get(file_id).cloned())
    }

    fn list_file_layouts(&self) -> Result<Vec<FileLayout>, KinDbError> {
        Ok(self
            .entities
            .read()
            .file_layouts
            .values()
            .cloned()
            .collect())
    }

    fn get_tree_entry(&self, file_id: &FilePathId) -> Result<Option<TreeEntry>, KinDbError> {
        let path = repo_path_for_file_path(file_id)?;
        Ok(self
            .entities
            .read()
            .resolved_tree
            .artifact_at_path(&path)
            .map(|artifact| artifact.entry))
    }

    fn delete_file_layout(&self, file_id: &FilePathId) -> Result<(), KinDbError> {
        self.require_artifact_id(file_id)?;

        let mut ent = self.entities_write();
        let old = ent.file_layouts.remove(file_id);
        self.record_file_layout_delta_remove(old, file_id.clone());
        Ok(())
    }

    fn apply_transaction_delta(&self, delta: &TransactionDelta) -> Result<(), KinDbError> {
        kin_model::validate_transaction_delta(delta)?;
        if delta.admission_policy_delta.is_some() {
            return Err(KinDbError::StorageError(
                "admission policy is repository authority; commit it through \
                 commit_repository_transaction instead of mutating an InMemoryGraph"
                    .to_string(),
            ));
        }
        let mut affected = HashSet::new();
        // Affected entities whose embed text this transaction leaves byte
        // identical. They still refresh the text index and the merkle, because
        // their spans and blob provenance did move; they simply keep the vector
        // they already have. A later relation delta takes an id back out of
        // this set, since graph context does reach embed text.
        let mut embedding_text_unchanged: HashSet<EntityId> = HashSet::new();
        let mut deleted_entities = HashSet::new();
        let mut merkle_seeds = HashSet::new();
        let mut retired_artifact_indexes = HashSet::new();

        {
            let mut ent = self.entities_write();

            // Validate the complete identity-bearing tree transition against
            // one parent state before mutating any graph domain. ResolvedTree
            // removes every old location before inserting any new location, so
            // swaps, cycles, and remove-then-reuse are one atomic transaction.
            let staged_tree = ent
                .resolved_tree
                .apply(&delta.tree_deltas)
                .map_err(tree_state_error)?;

            // Validate every explicit old/new entity transition against one
            // pre-transaction state before changing authority. A tree change
            // never infers entity or relation deletion: those transitions must
            // be present in the self-inverting semantic delta.
            let mut prospective_entities = ent.entities.clone();
            let mut entities_requiring_tree_validation = HashSet::new();
            for entity_delta in &delta.entity_deltas {
                match entity_delta {
                    EntityDelta::Added { new: entity } => {
                        if prospective_entities.contains_key(&entity.id) {
                            return Err(KinDbError::StorageError(format!(
                                "transaction adds existing entity {}",
                                entity.id
                            )));
                        }
                        prospective_entities.insert(entity.id, entity.clone());
                        entities_requiring_tree_validation.insert(entity.id);
                    }
                    EntityDelta::Modified { old, new } => {
                        if old.id != new.id {
                            return Err(KinDbError::StorageError(format!(
                                "transaction entity modification changes identity from {} to {}",
                                old.id, new.id
                            )));
                        }
                        if prospective_entities.get(&old.id) != Some(old) {
                            return Err(KinDbError::StorageError(format!(
                                "transaction has stale old payload for entity {}",
                                old.id
                            )));
                        }
                        prospective_entities.insert(new.id, new.clone());
                        entities_requiring_tree_validation.insert(new.id);
                    }
                    EntityDelta::Removed { old } => {
                        if prospective_entities.get(&old.id) != Some(old) {
                            return Err(KinDbError::StorageError(format!(
                                "transaction has stale old payload for removed entity {}",
                                old.id
                            )));
                        }
                        prospective_entities.remove(&old.id);
                    }
                }
            }
            let invalidated_paths: HashSet<_> = delta
                .tree_deltas
                .iter()
                .filter_map(TreeDelta::old_state)
                .filter_map(|old| file_path_for_repo_path(&old.path))
                .collect();
            entities_requiring_tree_validation.extend(prospective_entities.values().filter_map(
                |entity| {
                    entity
                        .file_origin
                        .as_ref()
                        .is_some_and(|path| invalidated_paths.contains(path))
                        .then_some(entity.id)
                },
            ));
            for entity_id in entities_requiring_tree_validation {
                let Some(entity) = prospective_entities.get(&entity_id) else {
                    continue;
                };
                let Some(file_id) = entity.file_origin.as_ref() else {
                    continue;
                };
                let path = repo_path_for_file_path(file_id)?;
                if staged_tree.artifact_id_at_path(&path).is_none() {
                    return Err(KinDbError::StorageError(format!(
                        "transaction leaves entity {} on repository path {} absent from the staged tree; carry its exact entity removal or relocation in the same delta",
                        entity.id, file_id.0
                    )));
                }
            }
            let prospective_entity_ids: HashSet<EntityId> =
                prospective_entities.keys().copied().collect();

            let staged_artifact_ids: HashSet<ArtifactId> = staged_tree
                .artifacts()
                .map(|artifact| artifact.artifact_id)
                .collect();
            let mut prospective_external_references = ent.external_references.clone();
            for external_delta in &delta.external_reference_deltas {
                match external_delta {
                    ExternalReferenceDelta::Added { new } => {
                        new.validate().map_err(|error| {
                            KinDbError::StorageError(format!(
                                "transaction external reference {} is invalid: {error}",
                                new.id
                            ))
                        })?;
                        if prospective_external_references.contains_key(&new.id) {
                            return Err(KinDbError::StorageError(format!(
                                "transaction adds existing external reference {}",
                                new.id
                            )));
                        }
                        prospective_external_references.insert(new.id, new.clone());
                    }
                    ExternalReferenceDelta::Removed { old } => {
                        old.validate().map_err(|error| {
                            KinDbError::StorageError(format!(
                                "transaction external reference {} is invalid: {error}",
                                old.id
                            ))
                        })?;
                        if prospective_external_references.get(&old.id) != Some(old) {
                            return Err(KinDbError::StorageError(format!(
                                "transaction has stale old payload for removed external reference {}",
                                old.id
                            )));
                        }
                        prospective_external_references.remove(&old.id);
                    }
                }
            }
            let prospective_external_reference_ids: HashSet<ExternalReferenceId> =
                prospective_external_references.keys().copied().collect();
            let mut prospective_relations = ent.relations.clone();
            for relation_delta in &delta.relation_deltas {
                match relation_delta {
                    RelationDelta::Added { new } => {
                        if prospective_relations.contains_key(&new.id) {
                            return Err(KinDbError::StorageError(format!(
                                "transaction adds existing relation {}",
                                new.id
                            )));
                        }
                        prospective_relations.insert(new.id, new.clone());
                    }
                    RelationDelta::Modified { old, new } => {
                        if old.id != new.id {
                            return Err(KinDbError::StorageError(format!(
                                "transaction relation modification changes identity from {} to {}",
                                old.id, new.id
                            )));
                        }
                        if prospective_relations.get(&old.id) != Some(old) {
                            return Err(KinDbError::StorageError(format!(
                                "transaction has stale old payload for relation {}",
                                old.id
                            )));
                        }
                        prospective_relations.insert(new.id, new.clone());
                    }
                    RelationDelta::Removed { old } => {
                        if prospective_relations.get(&old.id) != Some(old) {
                            return Err(KinDbError::StorageError(format!(
                                "transaction has stale old payload for removed relation {}",
                                old.id
                            )));
                        }
                        prospective_relations.remove(&old.id);
                    }
                }
            }
            let work = self.work.read();
            let verification = self.verification.read();
            for relation in prospective_relations.values() {
                for (side, node) in [("source", relation.src), ("destination", relation.dst)] {
                    if !graph_node_is_admitted(
                        node,
                        &prospective_entity_ids,
                        &staged_artifact_ids,
                        &prospective_external_reference_ids,
                        &work,
                        &verification,
                    ) {
                        return Err(KinDbError::StorageError(format!(
                            "transaction relation {} has unadmitted {side} endpoint {node}",
                            relation.id
                        )));
                    }
                }
            }
            drop(verification);
            drop(work);

            // Keep the whole graph transaction in one persistence batch. The
            // normal record_* helpers take this lock per mutation; doing that
            // here would let a persistence detach split tree, facet, entity,
            // and relation effects across different durable deltas.
            let mut pending = self.pending_delta.lock();

            // 1. Retire path-keyed enrichment through the identity-bearing old
            // tree state before publishing the new tree. A later path lookup
            // cannot authenticate a cleanup after a removal or move, while the
            // validated TreeDelta still proves the exact ArtifactId, location,
            // and materialization being replaced. Keeping this under the same
            // entity lock makes the tree and its derived facets one atomic
            // graph-truth transition.
            for tree_delta in &delta.tree_deltas {
                if !tree_delta_invalidates_path_facets(tree_delta) {
                    continue;
                }
                let Some(old_state) = tree_delta.old_state() else {
                    continue;
                };
                let Some(file_id) = file_path_for_repo_path(&old_state.path) else {
                    continue;
                };
                let artifact_id = tree_delta.artifact_id();
                retired_artifact_indexes.insert(artifact_id);

                if let Some(old) = ent.file_layouts.remove(&file_id) {
                    delta_vec_remove_by_key(
                        &mut pending.delta.file_layouts,
                        Some(old),
                        file_id.clone(),
                        |layout| layout.file_id.clone(),
                    );
                }
                if let Some(old) = ent.shallow_files.remove(&file_id) {
                    delta_vec_remove_by_key(
                        &mut pending.delta.shallow_files,
                        Some(old),
                        file_id.clone(),
                        |file| file.file_id.clone(),
                    );
                    retired_artifact_indexes.insert(artifact_id);
                }
                if let Some(old) = ent.structured_artifacts.remove(&file_id) {
                    delta_vec_remove_by_key(
                        &mut pending.delta.structured_artifacts,
                        Some(old),
                        file_id.clone(),
                        |artifact| artifact.file_id.clone(),
                    );
                    retired_artifact_indexes.insert(artifact_id);
                }
                if let Some(old) = ent.opaque_artifacts.remove(&file_id) {
                    delta_vec_remove_by_key(
                        &mut pending.delta.opaque_artifacts,
                        Some(old),
                        file_id,
                        |artifact| artifact.file_id.clone(),
                    );
                    retired_artifact_indexes.insert(artifact_id);
                }
            }

            // 2. Publish exact repository-tree truth and its persistence delta.
            for tree_delta in &delta.tree_deltas {
                let artifact_id = tree_delta.artifact_id();
                if let Some(new) = tree_delta.new_state() {
                    delta_map_upsert(&mut pending.delta.resolved_tree, artifact_id, new.clone());
                } else {
                    delta_map_remove(&mut pending.delta.resolved_tree, artifact_id);
                }
            }
            ent.resolved_tree = staged_tree;

            // 3. Process entity deltas.
            for ent_delta in &delta.entity_deltas {
                match ent_delta {
                    EntityDelta::Added { new: entity } => {
                        ent.indexes.insert(
                            entity.id,
                            &entity.name,
                            entity.file_origin.as_ref(),
                            entity.kind,
                        );
                        ent.entities.insert(entity.id, entity.clone());
                        delta_map_upsert(&mut pending.delta.entities, entity.id, entity.clone());
                        affected.insert(entity.id);
                        merkle_seeds.insert(entity.id);
                        // Upstream validation permits one delta per entity, but
                        // the skip set must stay correct even for a caller that
                        // bypasses it: an addition is never skippable.
                        embedding_text_unchanged.remove(&entity.id);
                    }
                    EntityDelta::Modified { old, new: entity } => {
                        if ent.entities.remove(&entity.id).is_some() {
                            let name_changed = old.name != entity.name;
                            let file_changed = old.file_origin != entity.file_origin;
                            let kind_changed = old.kind != entity.kind;

                            if name_changed || file_changed || kind_changed {
                                ent.indexes.remove(
                                    &old.id,
                                    &old.name,
                                    old.file_origin.as_ref(),
                                    old.kind,
                                );
                                ent.indexes.insert(
                                    entity.id,
                                    &entity.name,
                                    entity.file_origin.as_ref(),
                                    entity.kind,
                                );
                            }
                        }

                        ent.entities.insert(entity.id, entity.clone());
                        delta_map_upsert(&mut pending.delta.entities, entity.id, entity.clone());
                        affected.insert(entity.id);
                        merkle_seeds.insert(entity.id);
                        if entity_embedding_text_unchanged(old, entity) {
                            embedding_text_unchanged.insert(entity.id);
                        } else {
                            // Keep the set correct under duplicate deltas for
                            // one id from a caller that skipped validation: a
                            // text-changing delta always wins over a skip.
                            embedding_text_unchanged.remove(&entity.id);
                        }
                    }
                    EntityDelta::Removed { old } => {
                        ent.entities.remove(&old.id);
                        ent.indexes
                            .remove(&old.id, &old.name, old.file_origin.as_ref(), old.kind);
                        delta_map_remove(&mut pending.delta.entities, old.id);
                        affected.insert(old.id);
                        merkle_seeds.insert(old.id);
                        deleted_entities.insert(old.id);
                    }
                }
            }

            // 4. Process immutable external-reference deltas before relations,
            // so one pending persistence batch can introduce a reference and
            // connect it without ever exposing a dangling endpoint.
            for external_delta in &delta.external_reference_deltas {
                match external_delta {
                    ExternalReferenceDelta::Added { new } => {
                        ent.external_references.insert(new.id, new.clone());
                        delta_external_reference_add(
                            &mut pending.delta.external_references,
                            new.clone(),
                        );
                    }
                    ExternalReferenceDelta::Removed { old } => {
                        ent.external_references.remove(&old.id);
                        delta_external_reference_remove(
                            &mut pending.delta.external_references,
                            old.id,
                        );
                    }
                }
            }

            // 5. Process relation deltas.
            for rel_delta in &delta.relation_deltas {
                match rel_delta {
                    RelationDelta::Added { new: relation } => {
                        insert_relation_indexes(&mut ent, relation);
                        ent.relations.insert(relation.id, relation.clone());
                        delta_map_upsert(
                            &mut pending.delta.relations,
                            relation.id,
                            relation.clone(),
                        );
                        record_relation_edge_delta(&mut pending, &ent, relation);
                        affected.extend(entity_ids_for_relation(relation));
                        merkle_seeds.extend(entity_ids_for_relation(relation));
                    }
                    RelationDelta::Modified { old, new } => {
                        ent.relations.remove(&old.id);
                        affected.extend(entity_ids_for_relation(old));
                        merkle_seeds.extend(entity_ids_for_relation(old));
                        remove_relation_indexes(&mut ent, old);
                        insert_relation_indexes(&mut ent, new);
                        ent.relations.insert(new.id, new.clone());
                        delta_map_upsert(&mut pending.delta.relations, new.id, new.clone());
                        record_relation_edge_delta(&mut pending, &ent, old);
                        record_relation_edge_delta(&mut pending, &ent, new);
                        affected.extend(entity_ids_for_relation(new));
                        merkle_seeds.extend(entity_ids_for_relation(new));
                    }
                    RelationDelta::Removed { old } => {
                        ent.relations.remove(&old.id);
                        affected.extend(entity_ids_for_relation(old));
                        merkle_seeds.extend(entity_ids_for_relation(old));
                        remove_relation_indexes(&mut ent, old);
                        delta_map_remove(&mut pending.delta.relations, old.id);
                        record_relation_edge_delta(&mut pending, &ent, old);
                    }
                }
            }
            // Embed text carries graph-derived context lines drawn from the
            // neighborhood, so an endpoint of any relation this transaction
            // touched embeds differently even when its own payload formats the
            // same. Take those ids back out of the skip set rather than
            // reasoning about them inside each relation arm.
            for rel_delta in &delta.relation_deltas {
                let endpoints = match rel_delta {
                    RelationDelta::Added { new } => entity_ids_for_relation(new),
                    RelationDelta::Removed { old } => entity_ids_for_relation(old),
                    RelationDelta::Modified { old, new } => entity_ids_for_relation(old)
                        .into_iter()
                        .chain(entity_ids_for_relation(new))
                        .collect(),
                };
                for entity_id in endpoints {
                    embedding_text_unchanged.remove(&entity_id);
                }
            }

            deleted_entities.retain(|entity_id| !ent.entities.contains_key(entity_id));
            self.refresh_merkle_for_entities(&ent, merkle_seeds.iter().copied());
        }

        // Authority is now committed. Every operation below touches only
        // derived retrieval state and must never turn this successful
        // transaction into an `Err` that a caller might retry against the new
        // tree. A failed cache mutation quarantines that cache for a rebuild.
        #[cfg(test)]
        let injected_derived_failure = self
            .fail_next_transaction_derived_cleanup
            .swap(false, Ordering::AcqRel);
        #[cfg(not(test))]
        let injected_derived_failure = false;
        let mut vector_quarantine_error = injected_derived_failure.then(|| {
            KinDbError::StorageError("injected post-authority vector cleanup failure".to_string())
        });
        if injected_derived_failure {
            let error = KinDbError::StorageError(
                "injected post-authority text cleanup failure".to_string(),
            );
            self.quarantine_text_index_after_authority_commit(
                "fault-injected transaction cleanup",
                &error,
            );
        }

        let mut deleted_entities: Vec<EntityId> = deleted_entities.into_iter().collect();
        deleted_entities.sort_unstable();
        if !injected_derived_failure && !deleted_entities.is_empty() {
            if let Some(ref text_index) = self.text_index {
                if let Err(error) = text_index.remove_batch(&deleted_entities) {
                    self.quarantine_text_index_after_authority_commit(
                        "retiring invalidated entities",
                        &error,
                    );
                } else {
                    self.text_dirty.store(true, Ordering::Release);
                }
            }
        }

        // 5. Retire derived retrieval state for exact-tree artifacts. Sort for
        // deterministic vector free-list reuse.
        let mut retired_artifact_indexes: Vec<ArtifactId> =
            retired_artifact_indexes.into_iter().collect();
        retired_artifact_indexes.sort_unstable();
        for artifact_id in &retired_artifact_indexes {
            let key = RetrievalKey::Artifact(*artifact_id);
            if !injected_derived_failure {
                if let Err(error) = self.remove_retrievable_text_index(&key) {
                    self.quarantine_text_index_after_authority_commit(
                        "retiring an invalidated artifact",
                        &error,
                    );
                }
            }
            if vector_quarantine_error.is_none() {
                if let Err(error) = self.remove_retrievable_vector(&key) {
                    vector_quarantine_error = Some(error);
                }
            }
        }
        #[cfg(feature = "vector")]
        {
            let mut queue = self.artifact_embedding_queue.lock();
            for artifact_id in &retired_artifact_indexes {
                queue.remove(artifact_id);
            }
        }

        // 6. Clean up deleted entities from the embedding queue / vector index
        #[cfg(feature = "vector")]
        {
            let mut eq = self.embedding_queue.lock();
            let vi_lock = self.vector_index.lock();
            for id in &deleted_entities {
                eq.remove(&RetrievalKey::Entity(*id));
                if let Some(ref vi) = *vi_lock {
                    if vector_quarantine_error.is_none() {
                        if let Err(error) = vi.remove(id) {
                            vector_quarantine_error = Some(error);
                        }
                    }
                }
            }
        }

        // 7. Invalidate / refresh text index & embeddings for affected entities
        let mut affected_list: Vec<EntityId> = affected
            .into_iter()
            .filter(|entity_id| !deleted_entities.contains(entity_id))
            .collect();
        affected_list.sort_unstable();
        if !affected_list.is_empty() {
            self.refresh_text_index_for_entities(&affected_list);
            // The text index refreshes for everything affected; embeddings do
            // not. Re-embedding is the expensive half by orders of magnitude,
            // and an entity whose embed text is byte identical would only get
            // its own vector back.
            let embed_list: Vec<EntityId> = affected_list
                .iter()
                .copied()
                .filter(|entity_id| !embedding_text_unchanged.contains(entity_id))
                .collect();
            if vector_quarantine_error.is_none() && !embed_list.is_empty() {
                if let Err(error) = self.invalidate_entities_for_embedding(&embed_list) {
                    vector_quarantine_error = Some(error);
                }
            }
        }
        if let Some(error) = vector_quarantine_error {
            self.quarantine_vector_index_after_authority_commit(
                "retiring exact-tree/entity retrieval state",
                &error,
            );
        }

        Ok(())
    }

    fn upsert_entities_batch(&self, entities: &[Entity]) -> Result<(), KinDbError> {
        if entities.is_empty() {
            return Ok(());
        }

        let affected = {
            let mut ent = self.entities_write();
            let mut all_affected = Vec::with_capacity(entities.len());

            for entity in entities {
                if let Some(old) = ent.entities.remove(&entity.id) {
                    let name_changed = old.name != entity.name;
                    let file_changed = old.file_origin != entity.file_origin;
                    let kind_changed = old.kind != entity.kind;

                    if name_changed || file_changed || kind_changed {
                        ent.indexes
                            .remove(&old.id, &old.name, old.file_origin.as_ref(), old.kind);
                        ent.indexes.insert(
                            entity.id,
                            &entity.name,
                            entity.file_origin.as_ref(),
                            entity.kind,
                        );
                    }
                } else {
                    ent.indexes.insert(
                        entity.id,
                        &entity.name,
                        entity.file_origin.as_ref(),
                        entity.kind,
                    );
                }

                ent.entities.insert(entity.id, entity.clone());
                self.record_entity_delta_upsert(entity.clone());
                all_affected.push(entity.id);
            }

            let affected = collect_entity_refresh_targets(&ent, &all_affected);
            self.refresh_merkle_for_entities(&ent, all_affected.iter().copied());
            affected
        };

        self.refresh_text_index_for_entities(&affected);
        self.invalidate_entities_for_embedding(&affected)?;

        Ok(())
    }

    fn upsert_relations_batch(&self, relations: &[Relation]) -> Result<(), KinDbError> {
        if relations.is_empty() {
            return Ok(());
        }

        let affected = {
            let mut ent = self.entities_write();
            let mut merkle_seeds = Vec::new();
            let mut affected = HashSet::new();

            ent.relations.reserve(relations.len());
            for relation in relations {
                if let Some(old) = ent.relations.remove(&relation.id) {
                    affected.extend(entity_ids_for_relation(&old));
                    merkle_seeds.extend(entity_ids_for_relation(&old));
                    remove_relation_indexes(&mut ent, &old);
                    self.record_relation_delta_remove(&ent, &old);
                }

                insert_relation_indexes(&mut ent, relation);
                ent.relations.insert(relation.id, relation.clone());
                self.record_relation_delta_upsert(&ent, relation.clone());
                affected.extend(entity_ids_for_relation(relation));
                merkle_seeds.extend(entity_ids_for_relation(relation));
            }
            self.refresh_merkle_for_entities(&ent, merkle_seeds);
            sorted_unique_entity_ids(affected)
        };

        // Relation-derived text fields are now stale for affected entities,
        // but doing 20K+ individual Tantivy upserts is too expensive during
        // bulk init. Instead, mark that a full rebuild is required — this will
        // be honored by persist_text_index_with_root_hash before saving.
        self.text_full_rebuild_required
            .store(true, Ordering::Release);
        self.invalidate_entities_for_embedding(&affected)?;

        Ok(())
    }

    fn replace_relations_of_kind(
        &self,
        kind: RelationKind,
        new_relations: Vec<Relation>,
    ) -> Result<(), KinDbError> {
        // Short-circuit: if no new relations and none of this kind exist, skip everything.
        if new_relations.is_empty() {
            let ent = self.entities.read();
            let has_existing = ent.relations.values().any(|r| r.kind == kind);
            if !has_existing {
                return Ok(());
            }
            drop(ent);
        }

        // Step 1: Off-lock — pre-build the new relations map with exact capacity
        let mut new_map: HashMap<RelationId, Relation> =
            HashMap::with_capacity(new_relations.len());
        for rel in new_relations {
            new_map.insert(rel.id, rel);
        }

        let mut new_relations: Vec<Relation> = new_map.into_values().collect();
        new_relations.sort_unstable_by_key(|relation| relation.id.0);

        // Step 2: Single write lock — retain non-kind + insert new + rebuild indexes
        let affected = {
            let mut ent = self.entities_write();
            let mut merkle_seeds = Vec::new();
            let mut affected = HashSet::new();

            // Remove all relations of this kind — O(N) scan, no per-relation index work
            let mut removed_relations: Vec<Relation> = ent
                .relations
                .values()
                .filter(|rel| rel.kind == kind)
                .cloned()
                .collect();
            removed_relations.sort_unstable_by_key(|relation| relation.id.0);
            ent.relations.retain(|_, rel| rel.kind != kind);

            for relation in &removed_relations {
                affected.extend(entity_ids_for_relation(relation));
                merkle_seeds.extend(entity_ids_for_relation(relation));
            }

            // Reserve and insert new relations
            ent.relations.reserve(new_relations.len());
            for rel in &new_relations {
                affected.extend(entity_ids_for_relation(rel));
                merkle_seeds.extend(entity_ids_for_relation(rel));
                ent.relations.insert(rel.id, rel.clone());
            }

            // Rebuild ALL adjacency indexes from scratch — O(R) total
            // Much faster than incremental remove+insert (O(R * degree) due to Vec::retain)
            let (outgoing, incoming, node_outgoing, node_incoming) =
                build_relation_indexes(&ent.relations);
            ent.outgoing = outgoing;
            ent.incoming = incoming;
            ent.node_outgoing = node_outgoing;
            ent.node_incoming = node_incoming;
            for relation in &removed_relations {
                self.record_relation_delta_remove(&ent, relation);
            }
            for relation in &new_relations {
                self.record_relation_delta_upsert(&ent, relation.clone());
            }
            self.refresh_merkle_for_entities(&ent, merkle_seeds);
            sorted_unique_entity_ids(affected)
        };

        self.text_full_rebuild_required
            .store(true, Ordering::Release);
        self.invalidate_entities_for_embedding(&affected)?;
        Ok(())
    }

    fn remove_relations_batch(&self, ids: &[&RelationId]) -> Result<(), KinDbError> {
        if ids.is_empty() {
            return Ok(());
        }

        let affected = {
            let mut ent = self.entities_write();
            let mut merkle_seeds = Vec::new();
            let mut affected = HashSet::new();

            for id in ids {
                if let Some(rel) = ent.relations.remove(*id) {
                    affected.extend(entity_ids_for_relation(&rel));
                    merkle_seeds.extend(entity_ids_for_relation(&rel));
                    remove_relation_indexes(&mut ent, &rel);
                    self.record_relation_delta_remove(&ent, &rel);
                }
            }
            self.refresh_merkle_for_entities(&ent, merkle_seeds);
            sorted_unique_entity_ids(affected)
        };

        // Defer text index rebuild like upsert_relations_batch.
        self.text_full_rebuild_required
            .store(true, Ordering::Release);
        self.invalidate_entities_for_embedding(&affected)?;

        Ok(())
    }
}

impl ChangeStore for InMemoryGraph {
    type Error = KinDbError;

    // -----------------------------------------------------------------------
    // Change DAG — changes lock only
    // -----------------------------------------------------------------------

    fn get_entity_history(&self, id: &EntityId) -> Result<Vec<SemanticChange>, KinDbError> {
        let chg = self.changes.read();
        // Find all changes that mention this entity in their deltas
        let mut history: Vec<SemanticChange> = chg
            .changes
            .values()
            .filter(|change| {
                change.entity_deltas.iter().any(|delta| match delta {
                    EntityDelta::Added { new } => new.id == *id,
                    EntityDelta::Modified { old, new } => old.id == *id || new.id == *id,
                    EntityDelta::Removed { old } => old.id == *id,
                })
            })
            .cloned()
            .collect();
        // Sort by timestamp ascending
        history.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(history)
    }

    fn find_merge_bases(
        &self,
        a: &SemanticChangeId,
        b: &SemanticChangeId,
    ) -> Result<Vec<SemanticChangeId>, KinDbError> {
        let chg = self.changes.read();

        // Collect all ancestors of `a`
        let mut ancestors_a: hashbrown::HashSet<SemanticChangeId> = hashbrown::HashSet::new();
        let mut stack = vec![*a];
        while let Some(cid) = stack.pop() {
            if ancestors_a.insert(cid) {
                if let Some(change) = chg.changes.get(&cid) {
                    stack.extend_from_slice(&change.parents);
                }
            }
        }

        // Walk ancestors of `b` with depth tracking, find common ancestors
        let mut bases: Vec<(SemanticChangeId, u32)> = Vec::new();
        let mut visited: hashbrown::HashSet<SemanticChangeId> = hashbrown::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back((*b, 0u32));
        while let Some((cid, depth)) = queue.pop_front() {
            if !visited.insert(cid) {
                continue;
            }
            if ancestors_a.contains(&cid) {
                bases.push((cid, depth));
                // Don't traverse further past a merge base
                continue;
            }
            if let Some(change) = chg.changes.get(&cid) {
                for parent in &change.parents {
                    queue.push_back((*parent, depth + 1));
                }
            }
        }

        // Return only the lowest-depth (nearest) common ancestors
        if let Some(min_depth) = bases.iter().map(|(_, d)| *d).min() {
            Ok(bases
                .into_iter()
                .filter(|(_, d)| *d == min_depth)
                .map(|(cid, _)| cid)
                .collect())
        } else {
            Ok(Vec::new())
        }
    }

    fn create_change(&self, change: &SemanticChange) -> Result<(), KinDbError> {
        let started = std::time::Instant::now();
        let mut timer = PublicationPhaseTimer::start();
        let payload = semantic_change_payload(change)?;
        validate_semantic_change(change)?;
        let payload_ms = timer.lap_ms();
        let mut ent = self.entities_write();
        let entities_lock_ms = timer.lap_ms();
        let mut chg = self.changes.write();
        let changes_lock_ms = timer.lap_ms();
        if let Some(existing) = chg.changes.get(&change.id) {
            if semantic_change_payload(existing)? == payload {
                return Ok(());
            }
            return Err(KinDbError::DuplicateChange(change.id.to_string()));
        }

        // Revisions, child edges, and the change payload are one durable
        // mutation. Keep the pending-delta lock for the entire authority
        // transition so a concurrent persistence detach cannot split them
        // across generations.
        let mut pending = self.pending_delta.lock();
        let pending_lock_ms = timer.lap_ms();
        let advances = append_entity_revisions(&mut ent, change);
        let superseded_revisions = superseded_revision_ids(&advances);
        #[cfg(feature = "vector")]
        let minted_revisions = plan_minted_revision_vectors(&ent, &advances);
        run_create_change_after_revision_hook();
        let revisions_ms = timer.lap_ms();
        let revision_updates: Vec<(EntityId, Vec<EntityRevision>)> = change
            .entity_deltas
            .iter()
            .map(|delta| match delta {
                EntityDelta::Added { new: entity } | EntityDelta::Modified { new: entity, .. } => {
                    entity.id
                }
                EntityDelta::Removed { old } => old.id,
            })
            .filter_map(|entity_id| {
                ent.entity_revisions
                    .get(&entity_id)
                    .cloned()
                    .map(|revisions| (entity_id, revisions))
            })
            .collect();
        for (entity_id, revisions) in revision_updates {
            delta_map_upsert(&mut pending.delta.entity_revisions, entity_id, revisions);
        }
        // Register in parent → children index
        for parent in &change.parents {
            let children = chg.change_children.entry(*parent).or_default();
            children.push(change.id);
            delta_map_upsert(
                &mut pending.delta.change_children,
                *parent,
                children.clone(),
            );
        }

        chg.changes.insert(change.id, change.clone());
        delta_map_upsert(&mut pending.delta.changes, change.id, change.clone());
        let pending_entity_revisions = pending.delta.entity_revisions.added.len()
            + pending.delta.entity_revisions.modified.len();
        let pending_changes =
            pending.delta.changes.added.len() + pending.delta.changes.modified.len();
        drop(pending);
        let pending_delta_ms = timer.lap_ms();

        #[cfg(feature = "vector")]
        let (admit_vectors_ms, note_vectors_ms) = {
            // Both guards go before the vector index is touched. The rest of the
            // engine reaches the index only after releasing the entity lock, and
            // the carry-forward reads a vector under the index lock.
            drop(chg);
            drop(ent);
            // Admit before noting: the carry-forward source is the very key the
            // prune is about to evict.
            self.admit_minted_revision_vectors(&minted_revisions);
            let admit_ms = timer.lap_ms();
            self.note_superseded_vectors(&superseded_revisions);
            (admit_ms, timer.lap_ms())
        };
        #[cfg(not(feature = "vector"))]
        let (admit_vectors_ms, note_vectors_ms) = {
            let _ = superseded_revisions;
            (timer.lap_ms(), 0)
        };
        let elapsed = started.elapsed();
        if elapsed >= SLOW_CHANGE_INSTALL {
            let elapsed_ms = elapsed.as_millis();
            tracing::info!(
                elapsed_ms,
                payload_ms,
                entities_lock_ms,
                changes_lock_ms,
                pending_lock_ms,
                revisions_ms,
                pending_delta_ms,
                admit_vectors_ms,
                note_vectors_ms,
                entity_deltas = change.entity_deltas.len(),
                relation_deltas = change.relation_deltas.len(),
                tree_deltas = change.tree_deltas.len(),
                pending_entity_revisions,
                pending_changes,
                "slow live graph change install"
            );
        }
        Ok(())
    }

    fn get_change(&self, id: &SemanticChangeId) -> Result<Option<SemanticChange>, KinDbError> {
        Ok(self.changes.read().changes.get(id).cloned())
    }

    fn get_changes_since(
        &self,
        base: &SemanticChangeId,
        head: &SemanticChangeId,
    ) -> Result<Vec<SemanticChange>, KinDbError> {
        let chg = self.changes.read();

        // Walk backwards from head collecting changes until we hit base
        let mut result = Vec::new();
        let mut visited: hashbrown::HashSet<SemanticChangeId> = hashbrown::HashSet::new();
        let mut stack = vec![*head];

        while let Some(cid) = stack.pop() {
            if cid == *base || !visited.insert(cid) {
                continue;
            }
            if let Some(change) = chg.changes.get(&cid) {
                result.push(change.clone());
                stack.extend_from_slice(&change.parents);
            }
        }

        // Reverse so oldest-first
        result.reverse();
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Memory re-anchor — rename-durable annotation recall (Track B)
// ---------------------------------------------------------------------------

/// How a recalled annotation matched the queried entity. Carried in the recall
/// payload so an agent knows the epistemic basis of the memory it is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecallMatchBasis {
    /// The annotation is scoped directly to this entity's current id.
    Id,
    /// Re-anchored by fingerprint: the annotation's original scoped entity no
    /// longer resolves (renamed/removed) and its anchor matches this entity.
    FingerprintReanchor,
    /// Fingerprint collision: the anchor matches, but the annotation's scoped
    /// entity is a DIFFERENT entity that is still live (shared/duplicated
    /// fingerprint, e.g. templated code). Excluded from recall by default.
    FingerprintCollision,
}

/// An annotation recalled for an entity, tagged with the epistemic signal an
/// agent needs: how it matched and how stale its anchor is relative to the
/// entity's current fingerprint.
#[derive(Debug, Clone)]
pub struct RecalledAnnotation {
    pub annotation: Annotation,
    pub match_basis: RecallMatchBasis,
    pub staleness: StalenessState,
    /// Whether the matched/owning entity shares the queried entity's file.
    /// Always true for an `Id` match; false (unknown) for a re-anchor whose
    /// original entity is gone.
    pub same_file: bool,
    /// Whether the matched/owning entity shares the queried entity's kind.
    pub same_kind: bool,
}

/// Options controlling [`InMemoryGraph::recall_for_entity_with`].
#[derive(Debug, Clone, Default)]
pub struct RecallOptions {
    /// Include `Stale` matches (anchor structurally diverged). Off by default.
    pub include_stale: bool,
    /// Include `FingerprintCollision` matches — memory owned by a *different*
    /// live entity that shares the fingerprint. Off by default so recall never
    /// silently hands an agent another entity's memory.
    pub include_fingerprint_collisions: bool,
}

/// Staleness of an anchor relative to an entity's current fingerprint.
fn anchor_staleness(anchor: &SemanticAnchor, fp: &SemanticFingerprint) -> StalenessState {
    let ast_match = anchor.ast_hash == fp.ast_hash;
    let sig_match = anchor.signature_hash == fp.signature_hash;
    if ast_match && sig_match {
        StalenessState::Fresh
    } else if ast_match {
        // Structure unchanged, signature changed — the memory may still apply.
        StalenessState::Suspect
    } else {
        StalenessState::Stale
    }
}

fn recall_basis_rank(b: RecallMatchBasis) -> u8 {
    match b {
        RecallMatchBasis::Id => 0,
        RecallMatchBasis::FingerprintReanchor => 1,
        RecallMatchBasis::FingerprintCollision => 2,
    }
}

fn recall_staleness_rank(s: StalenessState) -> u8 {
    match s {
        StalenessState::Fresh => 0,
        StalenessState::Suspect => 1,
        StalenessState::Stale => 2,
    }
}

impl InMemoryGraph {
    /// Resolve the repository tree at every requested change in one pass.
    ///
    /// [`ChangeStore::resolve_tree_at`] answers for one head by walking that
    /// head's whole first-parent lineage, taking the change-DAG lock once per
    /// ancestor and cloning each ancestor with all of its deltas. A caller that
    /// needs several trees over one history pays that walk once per tree, so a
    /// transaction carrying `M` changes over a history of depth `D` costs
    /// `M * D` change clones for what is one `D`-step fold.
    ///
    /// This takes the lock once, reads each lineage member by reference, and
    /// resolves the union of the requested lineages in a single first-parent
    /// forest walk. The trees it returns are the ones `resolve_tree_at` would
    /// have returned, and every refusal is the same refusal at the same change.
    ///
    /// The method is intentionally inherent rather than part of `ChangeStore`:
    /// a batch resolution over one shared lineage is a KinDB capability, while
    /// generic stores keep using the portable one-head trait method.
    pub(crate) fn resolve_trees_at(
        &self,
        targets: &[SemanticChangeId],
    ) -> Result<std::collections::BTreeMap<SemanticChangeId, ResolvedTree>, KinDbError> {
        let changes = self.changes.read();
        crate::storage::history_replay::resolve_first_parent_trees(&changes.changes, targets)
    }

    /// Register an ordered batch of semantic changes with one acquisition of
    /// the entity, change-DAG, and pending-delta locks.
    ///
    /// Hydration imports changes oldest-first. Calling [`ChangeStore::create_change`]
    /// for each item repeatedly acquires the same locks and clones every change
    /// twice (once for live state and once for the pending snapshot delta). This
    /// owned batch path preserves the exact input order while moving each change
    /// into live state and cloning it only for the pending delta.
    ///
    /// The method is intentionally inherent rather than part of `ChangeStore`:
    /// batch import is a KinDB capability, while generic stores can continue to
    /// use the portable one-change trait method.
    pub fn create_changes(&self, changes: Vec<SemanticChange>) -> Result<(), KinDbError> {
        if changes.is_empty() {
            return Ok(());
        }

        // Validate the complete immutable identity and exact payload of every
        // item before acquiring any graph lock. A spoofed later item therefore
        // cannot expose a partial batch or append a pending persistence delta.
        let mut validated = Vec::with_capacity(changes.len());
        for change in changes {
            let payload = semantic_change_payload(&change)?;
            validate_semantic_change(&change)?;
            validated.push((change, payload));
        }

        // Domain lock order is part of InMemoryGraph's deadlock contract:
        // entities -> changes. Holding both makes a batch appear as one ordered
        // import to readers instead of exposing a partially registered DAG.
        let mut ent = self.entities_write();
        let mut chg = self.changes.write();

        // Validate every ID before touching revisions, child indexes, live
        // changes, or pending deltas. Existing structurally equivalent,
        // bit-exact payloads are idempotent; a differing payload under the
        // same content identity is corruption and rejects the whole batch
        // atomically.
        let mut unique_changes = Vec::with_capacity(validated.len());
        let mut batch_payloads = HashMap::new();
        for (change, payload) in validated {
            if let Some(existing) = chg.changes.get(&change.id) {
                if semantic_change_payload(existing)? == payload {
                    continue;
                }
                return Err(KinDbError::DuplicateChange(change.id.to_string()));
            }
            if let Some(existing_payload) = batch_payloads.get(&change.id) {
                if existing_payload == &payload {
                    continue;
                }
                return Err(KinDbError::DuplicateChange(change.id.to_string()));
            }
            batch_payloads.insert(change.id, payload);
            unique_changes.push(change);
        }
        if unique_changes.is_empty() {
            return Ok(());
        }

        let mut pending = self.pending_delta.lock();

        let mut touched_entities = Vec::new();
        let mut seen_entities = HashSet::new();
        let mut touched_parents = Vec::new();
        let mut seen_parents = HashSet::new();
        let mut advances: Vec<RevisionAdvance> = Vec::new();
        let mut pending_changes = Vec::with_capacity(unique_changes.len());

        for change in unique_changes {
            advances.extend(append_entity_revisions(&mut ent, &change));
            for entity_id in change.entity_deltas.iter().map(|delta| match delta {
                EntityDelta::Added { new: entity } | EntityDelta::Modified { new: entity, .. } => {
                    entity.id
                }
                EntityDelta::Removed { old } => old.id,
            }) {
                // Sequential create_change records the first delta slot only
                // once a revision chain exists. A removal before an add has no
                // chain yet and therefore must not claim the earlier slot.
                if ent.entity_revisions.contains_key(&entity_id) && seen_entities.insert(entity_id)
                {
                    touched_entities.push(entity_id);
                }
            }

            for parent in &change.parents {
                let children = chg.change_children.entry(*parent).or_default();
                children.push(change.id);
                if seen_parents.insert(*parent) {
                    touched_parents.push(*parent);
                }
            }

            let change_id = change.id;
            // The pending delta and live graph both own the change. Clone once
            // for the delta, then move the original into the graph.
            pending_changes.push((change_id, change.clone()));
            chg.changes.insert(change_id, change);
        }

        delta_map_upsert_batch(&mut pending.delta.changes, pending_changes);

        // Sequential create_change updates the same pending-delta entry on
        // every occurrence. The indexed batch helper retains the first
        // insertion slot and replaces its value, so recording each
        // entity/parent once with its final batch state is byte-equivalent while
        // avoiding repeated clones and repeated linear scans.
        let revision_updates = touched_entities
            .into_iter()
            .filter_map(|entity_id| {
                ent.entity_revisions
                    .get(&entity_id)
                    .cloned()
                    .map(|revisions| (entity_id, revisions))
            })
            .collect();
        delta_map_upsert_batch(&mut pending.delta.entity_revisions, revision_updates);

        let child_updates = touched_parents
            .into_iter()
            .filter_map(|parent| {
                chg.change_children
                    .get(&parent)
                    .cloned()
                    .map(|children| (parent, children))
            })
            .collect();
        delta_map_upsert_batch(&mut pending.delta.change_children, child_updates);

        let superseded_revisions = superseded_revision_ids(&advances);
        #[cfg(feature = "vector")]
        {
            let minted_revisions = plan_minted_revision_vectors(&ent, &advances);
            drop(pending);
            drop(chg);
            drop(ent);
            self.admit_minted_revision_vectors(&minted_revisions);
            self.note_superseded_vectors(&superseded_revisions);
        }
        #[cfg(not(feature = "vector"))]
        let _ = superseded_revisions;

        Ok(())
    }

    /// Capture a rename-durable [`SemanticAnchor`] for an annotation from the
    /// first live entity scope it carries.
    ///
    /// An annotation deposited on `WorkScope::Entity(id)` is anchored to that id,
    /// but the id derives from (file, name, kind, line) — so a rename mints a new
    /// id and orphans the deposit. The entity's `SemanticFingerprint`
    /// (`ast_hash` + `signature_hash`) is rename-invariant (a pure rename changes
    /// only `name`), so recording it at deposit time lets recall re-anchor the
    /// memory by fingerprint after a rename. Returns `None` when no entity scope
    /// resolves to a live entity.
    fn capture_entity_anchor(&self, scopes: &[WorkScope]) -> Option<SemanticAnchor> {
        let ent = self.entities.read();
        scopes.iter().find_map(|scope| match scope {
            WorkScope::Entity(id) => ent.entities.get(id).map(|e| SemanticAnchor {
                ast_hash: e.fingerprint.ast_hash,
                signature_hash: e.fingerprint.signature_hash,
            }),
            _ => None,
        })
    }

    /// Recall annotations ("memory deposits") for an entity, re-anchoring across
    /// renames. Uses default [`RecallOptions`] (exclude `Stale` and fingerprint
    /// collisions).
    pub fn recall_for_entity(&self, entity_id: &EntityId) -> Vec<RecalledAnnotation> {
        self.recall_for_entity_with(entity_id, &RecallOptions::default())
    }

    /// Recall annotations for an entity by id OR by rename-durable fingerprint
    /// anchor, each tagged with its [`RecallMatchBasis`] and [`StalenessState`].
    ///
    /// An annotation matches when it is scoped to `entity_id` (basis `Id`), or
    /// when its `anchored_fingerprint` structurally matches the entity's current
    /// fingerprint (`ast_hash` equal). A fingerprint match is a
    /// `FingerprintReanchor` when the annotation's original scoped entity no
    /// longer resolves (a rename), or a `FingerprintCollision` when that scope
    /// still points at a different live entity (duplicated/templated code that
    /// happens to share a fingerprint). Collisions and `Stale` matches are
    /// excluded unless requested in `opts`.
    ///
    /// Results are returned in a deterministic total order: match basis
    /// (`Id` < re-anchor < collision), then staleness (fresh first), then
    /// same-file and same-kind preference, then annotation id.
    pub fn recall_for_entity_with(
        &self,
        entity_id: &EntityId,
        opts: &RecallOptions,
    ) -> Vec<RecalledAnnotation> {
        let ent = self.entities.read();
        let target = match ent.entities.get(entity_id) {
            Some(e) => e,
            None => return Vec::new(),
        };
        let target_fp = target.fingerprint.clone();
        let target_file = target.file_origin.clone();
        let target_kind = target.kind;

        let wrk = self.work.read();
        let mut out: Vec<RecalledAnnotation> = Vec::new();
        for ann in wrk.annotations.values() {
            let id_match = ann
                .scopes
                .iter()
                .any(|s| matches!(s, WorkScope::Entity(e) if e == entity_id));

            if id_match {
                // Staleness from the deposit-time anchor vs the current
                // fingerprint; without an anchor we cannot tell, so treat Fresh.
                let staleness = ann
                    .anchored_fingerprint
                    .as_ref()
                    .map(|a| anchor_staleness(a, &target_fp))
                    .unwrap_or(StalenessState::Fresh);
                if staleness == StalenessState::Stale && !opts.include_stale {
                    continue;
                }
                out.push(RecalledAnnotation {
                    annotation: ann.clone(),
                    match_basis: RecallMatchBasis::Id,
                    staleness,
                    same_file: true,
                    same_kind: true,
                });
                continue;
            }

            // Fingerprint re-anchor / collision: require a structural ast match.
            let anchor = match &ann.anchored_fingerprint {
                Some(a) if a.ast_hash == target_fp.ast_hash => a,
                _ => continue,
            };
            let staleness = anchor_staleness(anchor, &target_fp); // Fresh or Suspect

            // Does any entity scope still resolve to a LIVE entity != target?
            // If so this fingerprint match belongs to that living entity
            // (collision); otherwise the original is gone → a rename re-anchor.
            let owner = ann.scopes.iter().find_map(|s| match s {
                WorkScope::Entity(sid) if sid != entity_id => ent.entities.get(sid),
                _ => None,
            });

            let (match_basis, same_file, same_kind) = match owner {
                Some(o) => (
                    RecallMatchBasis::FingerprintCollision,
                    o.file_origin == target_file,
                    o.kind == target_kind,
                ),
                // Original entity gone — its file/kind are unknown, so we cannot
                // claim same-file/same-kind.
                None => (RecallMatchBasis::FingerprintReanchor, false, false),
            };

            if match_basis == RecallMatchBasis::FingerprintCollision
                && !opts.include_fingerprint_collisions
            {
                continue;
            }
            if staleness == StalenessState::Stale && !opts.include_stale {
                continue;
            }
            out.push(RecalledAnnotation {
                annotation: ann.clone(),
                match_basis,
                staleness,
                same_file,
                same_kind,
            });
        }

        // Deterministic total order: basis → staleness → same-file → same-kind →
        // annotation id. Prefers exact-id, fresh, same-file/same-kind memory.
        out.sort_by(|a, b| {
            recall_basis_rank(a.match_basis)
                .cmp(&recall_basis_rank(b.match_basis))
                .then(recall_staleness_rank(a.staleness).cmp(&recall_staleness_rank(b.staleness)))
                .then((!a.same_file).cmp(&(!b.same_file)))
                .then((!a.same_kind).cmp(&(!b.same_kind)))
                .then(
                    a.annotation
                        .annotation_id
                        .0
                        .cmp(&b.annotation.annotation_id.0),
                )
        });
        out
    }

    /// Actively re-scope orphaned annotations onto their renamed entity.
    ///
    /// For each annotation that has a fingerprint anchor but whose entity scopes
    /// no longer resolve to any live entity (the original was renamed/removed),
    /// find live entities whose fingerprint matches the anchor. When there is
    /// EXACTLY ONE such entity (an unambiguous rename target) append
    /// `WorkScope::Entity(new_id)` so future recall is an O(1) exact-id match.
    /// Ambiguous anchors (a fingerprint shared by several live entities —
    /// duplicated/templated code) are left untouched and continue to resolve via
    /// lazy fingerprint recall, so this never mis-anchors memory to the wrong
    /// duplicate. Returns the number of annotations re-scoped. Idempotent.
    ///
    /// This is the OPTIONAL active-detection path. kin-db never invokes it on its
    /// own (it is inert by default); the reconcile/sync path (kin-side) calls it
    /// behind a default-off flag after applying a graph diff.
    pub fn reanchor_orphaned_annotations(&self) -> usize {
        // Lock order: entities (read) BEFORE work (write).
        let ent = self.entities.read();
        let mut by_fp: HashMap<(Hash256, Hash256), Vec<EntityId>> = HashMap::new();
        for (id, e) in &ent.entities {
            by_fp
                .entry((e.fingerprint.ast_hash, e.fingerprint.signature_hash))
                .or_default()
                .push(*id);
        }

        let mut wrk = self.work.write();
        let mut count = 0usize;
        for ann in wrk.annotations.values_mut() {
            let anchor = match &ann.anchored_fingerprint {
                Some(a) => a,
                None => continue,
            };
            // Skip annotations already anchored to a live entity (not orphaned).
            let has_live_scope = ann
                .scopes
                .iter()
                .any(|s| matches!(s, WorkScope::Entity(id) if ent.entities.contains_key(id)));
            if has_live_scope {
                continue;
            }
            // Re-scope only on an UNAMBIGUOUS single fingerprint match.
            if let Some(ids) = by_fp.get(&(anchor.ast_hash, anchor.signature_hash)) {
                if ids.len() == 1 {
                    let new_id = ids[0];
                    let already = ann
                        .scopes
                        .iter()
                        .any(|s| matches!(s, WorkScope::Entity(id) if *id == new_id));
                    if !already {
                        ann.scopes.push(WorkScope::Entity(new_id));
                        count += 1;
                    }
                }
            }
        }
        count
    }
}

impl WorkStore for InMemoryGraph {
    type Error = KinDbError;

    // -----------------------------------------------------------------------
    // Work graph operations (Phase 8) — work lock only
    // -----------------------------------------------------------------------

    fn create_work_item(&self, item: &WorkItem) -> Result<(), KinDbError> {
        self.work
            .write()
            .work_items
            .insert(item.work_id, item.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_work_item(&self, id: &WorkId) -> Result<Option<WorkItem>, KinDbError> {
        Ok(self.work.read().work_items.get(id).cloned())
    }

    fn list_work_items(&self, filter: &WorkFilter) -> Result<Vec<WorkItem>, KinDbError> {
        let wrk = self.work.read();
        let results = wrk
            .work_items
            .values()
            .filter(|item| {
                if let Some(ref kinds) = filter.kinds {
                    if !kinds.contains(&item.kind) {
                        return false;
                    }
                }
                if let Some(ref statuses) = filter.statuses {
                    if !statuses.contains(&item.status) {
                        return false;
                    }
                }
                if let Some(ref scope) = filter.scope {
                    if !item.scopes.contains(scope) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        Ok(results)
    }

    fn update_work_status(&self, id: &WorkId, status: WorkStatus) -> Result<(), KinDbError> {
        let mut wrk = self.work.write();
        match wrk.work_items.get_mut(id) {
            Some(item) => {
                item.status = status;
                self.require_full_snapshot();
                Ok(())
            }
            None => Err(KinDbError::NotFound(format!("work item '{}'", id))),
        }
    }

    fn delete_work_item(&self, id: &WorkId) -> Result<(), KinDbError> {
        let mut wrk = self.work.write();
        wrk.work_items.remove(id);
        // Also remove associated links
        wrk.work_links.retain(|link| match link {
            WorkLink::Affects { work_id, .. } => work_id != id,
            WorkLink::DecomposesTo { parent, child } => parent != id && child != id,
            WorkLink::BlockedBy { blocked, blocker } => blocked != id && blocker != id,
            WorkLink::Implements { work_id, .. } => work_id != id,
            _ => true,
        });
        self.require_full_snapshot();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Annotation operations (Phase 8) — work lock only
    // -----------------------------------------------------------------------

    fn create_annotation(&self, ann: &Annotation) -> Result<(), KinDbError> {
        let mut ann = ann.clone();
        // Capture the rename-durable fingerprint anchor at deposit time when the
        // caller did not supply one (Track B memory re-anchor). Acquires the
        // entities read lock first, then the work write lock — never both at
        // once — respecting the entities → work lock order.
        if ann.anchored_fingerprint.is_none() {
            ann.anchored_fingerprint = self.capture_entity_anchor(&ann.scopes);
        }
        self.work.write().annotations.insert(ann.annotation_id, ann);
        self.require_full_snapshot();
        Ok(())
    }

    fn get_annotation(&self, id: &AnnotationId) -> Result<Option<Annotation>, KinDbError> {
        Ok(self.work.read().annotations.get(id).cloned())
    }

    fn list_annotations(&self, filter: &AnnotationFilter) -> Result<Vec<Annotation>, KinDbError> {
        let wrk = self.work.read();
        let results = wrk
            .annotations
            .values()
            .filter(|ann| {
                if let Some(ref kinds) = filter.kinds {
                    if !kinds.contains(&ann.kind) {
                        return false;
                    }
                }
                if let Some(ref scopes) = filter.scopes {
                    if !ann.scopes.iter().any(|s| scopes.contains(s)) {
                        return false;
                    }
                }
                if !filter.include_stale && ann.staleness == StalenessState::Stale {
                    return false;
                }
                true
            })
            .cloned()
            .collect();
        Ok(results)
    }

    fn update_annotation_staleness(
        &self,
        id: &AnnotationId,
        staleness: StalenessState,
    ) -> Result<(), KinDbError> {
        let mut wrk = self.work.write();
        match wrk.annotations.get_mut(id) {
            Some(ann) => {
                ann.staleness = staleness;
                self.require_full_snapshot();
                Ok(())
            }
            None => Err(KinDbError::NotFound(format!("annotation '{}'", id))),
        }
    }

    fn delete_annotation(&self, id: &AnnotationId) -> Result<(), KinDbError> {
        let mut wrk = self.work.write();
        wrk.annotations.remove(id);
        // Remove associated links
        wrk.work_links.retain(|link| match link {
            WorkLink::AttachedTo { annotation_id, .. } => annotation_id != id,
            WorkLink::Supersedes { new_id, old_id } => new_id != id && old_id != id,
            _ => true,
        });
        self.require_full_snapshot();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Work graph relationships (Phase 8) — work lock only
    // -----------------------------------------------------------------------

    fn create_work_link(&self, link: &WorkLink) -> Result<(), KinDbError> {
        let mut wrk = self.work.write();
        // Avoid duplicates
        if !wrk.work_links.contains(link) {
            wrk.work_links.push(link.clone());
            self.require_full_snapshot();
        }
        Ok(())
    }

    fn delete_work_link(&self, link: &WorkLink) -> Result<(), KinDbError> {
        self.work.write().work_links.retain(|l| l != link);
        self.require_full_snapshot();
        Ok(())
    }

    fn get_work_for_scope(&self, scope: &WorkScope) -> Result<Vec<WorkItem>, KinDbError> {
        let wrk = self.work.read();
        // Find work IDs that affect this scope
        let work_ids: Vec<WorkId> = wrk
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::Affects { work_id, scope: s } if s == scope => Some(*work_id),
                _ => None,
            })
            .collect();
        // Also include items whose scopes contain this scope directly
        let mut results: Vec<WorkItem> = wrk
            .work_items
            .values()
            .filter(|item| item.scopes.contains(scope) || work_ids.contains(&item.work_id))
            .cloned()
            .collect();
        results.dedup_by_key(|item| item.work_id);
        Ok(results)
    }

    fn get_annotations_for_scope(&self, scope: &WorkScope) -> Result<Vec<Annotation>, KinDbError> {
        let wrk = self.work.read();
        let results = wrk
            .annotations
            .values()
            .filter(|ann| ann.scopes.contains(scope))
            .cloned()
            .collect();
        Ok(results)
    }

    fn get_child_work_items(&self, parent: &WorkId) -> Result<Vec<WorkItem>, KinDbError> {
        let wrk = self.work.read();
        let child_ids: Vec<WorkId> = wrk
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::DecomposesTo { parent: p, child } if p == parent => Some(*child),
                _ => None,
            })
            .collect();
        let results = child_ids
            .iter()
            .filter_map(|id| wrk.work_items.get(id).cloned())
            .collect();
        Ok(results)
    }

    fn get_parent_work_items(&self, child: &WorkId) -> Result<Vec<WorkItem>, KinDbError> {
        let wrk = self.work.read();
        let parent_ids: Vec<WorkId> = wrk
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::DecomposesTo { parent, child: c } if c == child => Some(*parent),
                _ => None,
            })
            .collect();
        let results = parent_ids
            .iter()
            .filter_map(|id| wrk.work_items.get(id).cloned())
            .collect();
        Ok(results)
    }

    fn get_blockers(&self, work_id: &WorkId) -> Result<Vec<WorkItem>, KinDbError> {
        let wrk = self.work.read();
        let blocker_ids: Vec<WorkId> = wrk
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::BlockedBy { blocked, blocker } if blocked == work_id => Some(*blocker),
                _ => None,
            })
            .collect();
        let results = blocker_ids
            .iter()
            .filter_map(|id| wrk.work_items.get(id).cloned())
            .collect();
        Ok(results)
    }

    fn get_blocked_work_items(&self, work_id: &WorkId) -> Result<Vec<WorkItem>, KinDbError> {
        let wrk = self.work.read();
        let blocked_ids: Vec<WorkId> = wrk
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::BlockedBy { blocked, blocker } if blocker == work_id => Some(*blocked),
                _ => None,
            })
            .collect();
        let results = blocked_ids
            .iter()
            .filter_map(|id| wrk.work_items.get(id).cloned())
            .collect();
        Ok(results)
    }

    fn get_implementors(&self, work_id: &WorkId) -> Result<Vec<WorkScope>, KinDbError> {
        let wrk = self.work.read();
        let scopes = wrk
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::Implements {
                    scope,
                    work_id: wid,
                } if wid == work_id => Some(scope.clone()),
                _ => None,
            })
            .collect();
        Ok(scopes)
    }

    fn get_annotations_for_work_item(
        &self,
        work_id: &WorkId,
    ) -> Result<Vec<Annotation>, KinDbError> {
        let wrk = self.work.read();
        let annotation_ids: Vec<AnnotationId> = wrk
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::AttachedTo {
                    annotation_id,
                    target: AnnotationTarget::Work(id),
                } if id == work_id => Some(*annotation_id),
                _ => None,
            })
            .collect();
        let results = annotation_ids
            .iter()
            .filter_map(|id| wrk.annotations.get(id).cloned())
            .collect();
        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// ReviewStore implementation
// ---------------------------------------------------------------------------

impl ReviewStore for InMemoryGraph {
    type Error = KinDbError;

    fn create_review(&self, review: &Review) -> Result<(), KinDbError> {
        self.reviews
            .write()
            .reviews
            .insert(review.review_id, review.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_review(&self, id: &ReviewId) -> Result<Option<Review>, KinDbError> {
        Ok(self.reviews.read().reviews.get(id).cloned())
    }

    fn list_reviews(&self, filter: &ReviewFilter) -> Result<Vec<Review>, KinDbError> {
        let rev = self.reviews.read();
        let results = rev
            .reviews
            .values()
            .filter(|r| {
                if let Some(ref states) = filter.states {
                    if !states.contains(&r.state) {
                        return false;
                    }
                }
                if let Some(ref reviewer_name) = filter.reviewer {
                    // Check if this reviewer has an assignment for this review
                    if let Some(assignments) = rev.review_assignments.get(&r.review_id) {
                        if !assignments
                            .iter()
                            .any(|a| a.reviewer.name == *reviewer_name)
                        {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        Ok(results)
    }

    fn update_review_state(
        &self,
        id: &ReviewId,
        state: ReviewDecisionState,
    ) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        match rev.reviews.get_mut(id) {
            Some(review) => {
                review.state = state;
                review.updated_at = Timestamp::now();
                self.require_full_snapshot();
                Ok(())
            }
            None => Err(KinDbError::NotFound(format!("review '{}'", id))),
        }
    }

    fn delete_review(&self, id: &ReviewId) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        rev.reviews.remove(id);
        rev.review_decisions.remove(id);
        rev.review_assignments.remove(id);
        // Remove notes belonging to this review
        rev.review_notes.retain(|_, note| note.review_id != *id);
        // Remove discussions belonging to this review
        rev.review_discussions
            .retain(|_, disc| disc.review_id != *id);
        self.require_full_snapshot();
        Ok(())
    }

    fn add_review_decision(
        &self,
        id: &ReviewId,
        decision: &ReviewDecision,
    ) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        if !rev.reviews.contains_key(id) {
            return Err(KinDbError::NotFound(format!("review '{}'", id)));
        }
        rev.review_decisions
            .entry(*id)
            .or_default()
            .push(decision.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_review_decisions(&self, id: &ReviewId) -> Result<Vec<ReviewDecision>, KinDbError> {
        Ok(self
            .reviews
            .read()
            .review_decisions
            .get(id)
            .cloned()
            .unwrap_or_default())
    }

    fn add_review_note(&self, note: &ReviewNote) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        if !rev.reviews.contains_key(&note.review_id) {
            return Err(KinDbError::NotFound(format!("review '{}'", note.review_id)));
        }
        rev.review_notes.insert(note.note_id, note.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_review_notes(&self, id: &ReviewId) -> Result<Vec<ReviewNote>, KinDbError> {
        let rev = self.reviews.read();
        let results = rev
            .review_notes
            .values()
            .filter(|note| note.review_id == *id)
            .cloned()
            .collect();
        Ok(results)
    }

    fn delete_review_note(&self, note_id: &ReviewNoteId) -> Result<(), KinDbError> {
        self.reviews.write().review_notes.remove(note_id);
        self.require_full_snapshot();
        Ok(())
    }

    fn create_review_discussion(&self, discussion: &ReviewDiscussion) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        if !rev.reviews.contains_key(&discussion.review_id) {
            return Err(KinDbError::NotFound(format!(
                "review '{}'",
                discussion.review_id
            )));
        }
        rev.review_discussions
            .insert(discussion.discussion_id, discussion.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_review_discussions(&self, id: &ReviewId) -> Result<Vec<ReviewDiscussion>, KinDbError> {
        let rev = self.reviews.read();
        let results = rev
            .review_discussions
            .values()
            .filter(|disc| disc.review_id == *id)
            .cloned()
            .collect();
        Ok(results)
    }

    fn add_discussion_comment(
        &self,
        id: &ReviewDiscussionId,
        comment: &ReviewComment,
    ) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        match rev.review_discussions.get_mut(id) {
            Some(disc) => {
                disc.comments.push(comment.clone());
                self.require_full_snapshot();
                Ok(())
            }
            None => Err(KinDbError::NotFound(format!("review discussion '{}'", id))),
        }
    }

    fn set_discussion_state(
        &self,
        id: &ReviewDiscussionId,
        state: ReviewDiscussionState,
    ) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        match rev.review_discussions.get_mut(id) {
            Some(disc) => {
                disc.state = state;
                self.require_full_snapshot();
                Ok(())
            }
            None => Err(KinDbError::NotFound(format!("review discussion '{}'", id))),
        }
    }

    fn assign_reviewer(&self, assignment: &ReviewAssignment) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        if !rev.reviews.contains_key(&assignment.review_id) {
            return Err(KinDbError::NotFound(format!(
                "review '{}'",
                assignment.review_id
            )));
        }
        rev.review_assignments
            .entry(assignment.review_id)
            .or_default()
            .push(assignment.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_review_assignments(&self, id: &ReviewId) -> Result<Vec<ReviewAssignment>, KinDbError> {
        Ok(self
            .reviews
            .read()
            .review_assignments
            .get(id)
            .cloned()
            .unwrap_or_default())
    }

    fn remove_reviewer(&self, review_id: &ReviewId, reviewer: &str) -> Result<(), KinDbError> {
        let mut rev = self.reviews.write();
        if let Some(assignments) = rev.review_assignments.get_mut(review_id) {
            assignments.retain(|a| a.reviewer.name != reviewer);
        }
        self.require_full_snapshot();
        Ok(())
    }
}

impl VerificationStore for InMemoryGraph {
    type Error = KinDbError;

    // -----------------------------------------------------------------------
    // Verification graph operations (Phase 9) — verification + entities locks
    // -----------------------------------------------------------------------

    fn create_test_case(&self, test: &TestCase) -> Result<(), KinDbError> {
        let entity_scopes: Vec<EntityId> = {
            let ent = self.entities.read();
            let mut seen = HashSet::new();
            test.scopes
                .iter()
                .filter_map(|scope| match scope {
                    WorkScope::Entity(entity_id)
                        if ent.entities.contains_key(entity_id) && seen.insert(*entity_id) =>
                    {
                        Some(*entity_id)
                    }
                    _ => None,
                })
                .collect()
        };
        let mut ver = self.verification.write();
        ver.test_cases.insert(test.test_id, test.clone());
        drop(ver);
        if !entity_scopes.is_empty() {
            let relations: Vec<Relation> = entity_scopes
                .into_iter()
                .map(|entity_id| {
                    verification_relation(
                        RelationKind::Covers,
                        GraphNodeId::Test(test.test_id),
                        GraphNodeId::Entity(entity_id),
                    )
                })
                .collect();
            self.upsert_relations_batch(&relations)?;
        }
        self.require_full_snapshot();
        Ok(())
    }

    fn get_test_case(&self, id: &TestId) -> Result<Option<TestCase>, KinDbError> {
        Ok(self.verification.read().test_cases.get(id).cloned())
    }

    fn get_tests_for_entity(&self, id: &EntityId) -> Result<Vec<TestCase>, KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let mut seen = HashSet::new();
        Ok(ent
            .node_incoming
            .get(&GraphNodeId::Entity(*id))
            .into_iter()
            .flatten()
            .filter_map(|relation_id| ent.relations.get(relation_id))
            .filter_map(|relation| match (relation.kind, relation.src) {
                (RelationKind::Covers, GraphNodeId::Test(test_id)) => Some(test_id),
                _ => None,
            })
            .filter(|test_id| seen.insert(*test_id))
            .filter_map(|test_id| ver.test_cases.get(&test_id).cloned())
            .collect())
    }

    fn delete_test_case(&self, id: &TestId) -> Result<(), KinDbError> {
        let mut ent = self.entities_write();
        let mut ver = self.verification.write();
        let mut affected = HashSet::new();
        ver.test_cases.remove(id);
        ver.mock_hints.retain(|h| h.test_id != *id);
        let node = GraphNodeId::Test(*id);
        let mut relation_ids = Vec::new();
        if let Some(outgoing) = ent.node_outgoing.get(&node) {
            relation_ids.extend(outgoing.iter().copied());
        }
        if let Some(incoming) = ent.node_incoming.get(&node) {
            relation_ids.extend(incoming.iter().copied());
        }
        relation_ids.sort_unstable_by_key(|relation_id| relation_id.0);
        relation_ids.dedup();
        for relation_id in relation_ids {
            if let Some(relation) = ent.relations.remove(&relation_id) {
                affected.extend(entity_ids_for_relation(&relation));
                remove_relation_indexes(&mut ent, &relation);
            }
        }
        self.refresh_merkle_for_entities(&ent, affected.iter().copied());
        let affected = sorted_unique_entity_ids(affected);
        drop(ver);
        drop(ent);

        self.text_full_rebuild_required
            .store(true, Ordering::Release);
        self.invalidate_entities_for_embedding(&affected)?;
        self.require_full_snapshot();
        Ok(())
    }

    fn create_assertion(&self, assertion: &Assertion) -> Result<(), KinDbError> {
        self.verification
            .write()
            .assertions
            .insert(assertion.assertion_id, assertion.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_assertion(&self, id: &AssertionId) -> Result<Option<Assertion>, KinDbError> {
        Ok(self.verification.read().assertions.get(id).cloned())
    }

    fn get_coverage_summary(&self) -> Result<CoverageSummary, KinDbError> {
        // Lock ordering: entities → verification
        let ent = self.entities.read();
        let total = ent.entities.len();
        let covered_ids: std::collections::HashSet<EntityId> = ent
            .relations
            .values()
            .filter_map(
                |relation| match (relation.kind, relation.src, relation.dst) {
                    (
                        RelationKind::Covers,
                        GraphNodeId::Test(_),
                        GraphNodeId::Entity(entity_id),
                    ) => Some(entity_id),
                    _ => None,
                },
            )
            .collect();
        let covered = covered_ids.len();
        let ratio = if total > 0 {
            covered as f64 / total as f64
        } else {
            0.0
        };
        let missing: Vec<EntityId> = ent
            .entities
            .keys()
            .filter(|id| !covered_ids.contains(id))
            .copied()
            .collect();
        Ok(CoverageSummary {
            total_entities: total,
            covered_entities: covered,
            coverage_ratio: ratio,
            missing_proof: missing,
        })
    }

    // -----------------------------------------------------------------------
    // Verification runs (Phase 9 completion) — verification lock only
    // -----------------------------------------------------------------------

    fn create_verification_run(&self, run: &VerificationRun) -> Result<(), KinDbError> {
        self.verification
            .write()
            .verification_runs
            .insert(run.run_id, run.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_verification_run(
        &self,
        id: &VerificationRunId,
    ) -> Result<Option<VerificationRun>, KinDbError> {
        Ok(self.verification.read().verification_runs.get(id).cloned())
    }

    fn list_runs_for_test(&self, test_id: &TestId) -> Result<Vec<VerificationRun>, KinDbError> {
        let ver = self.verification.read();
        let results = ver
            .verification_runs
            .values()
            .filter(|run| run.test_ids.contains(test_id))
            .cloned()
            .collect();
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Test ↔ scope linking (Phase 9 completion) — verification lock only
    // -----------------------------------------------------------------------

    fn create_test_covers_entity(
        &self,
        test_id: &TestId,
        entity_id: &EntityId,
    ) -> Result<(), KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let test_exists = ver.test_cases.contains_key(test_id);
        let entity_exists = ent.entities.contains_key(entity_id);
        drop(ver);
        drop(ent);
        if !test_exists || !entity_exists {
            return Ok(());
        }
        self.upsert_relation(&verification_relation(
            RelationKind::Covers,
            GraphNodeId::Test(*test_id),
            GraphNodeId::Entity(*entity_id),
        ))
    }

    fn create_test_covers_contract(
        &self,
        test_id: &TestId,
        contract_id: &ContractId,
    ) -> Result<(), KinDbError> {
        let ver = self.verification.read();
        let test_exists = ver.test_cases.contains_key(test_id);
        let contract_exists = ver.contracts.contains_key(contract_id);
        drop(ver);
        if !test_exists || !contract_exists {
            return Ok(());
        }
        self.upsert_relation(&verification_relation(
            RelationKind::Covers,
            GraphNodeId::Test(*test_id),
            GraphNodeId::Contract(*contract_id),
        ))
    }

    fn create_test_verifies_work(
        &self,
        test_id: &TestId,
        work_id: &WorkId,
    ) -> Result<(), KinDbError> {
        let wrk = self.work.read();
        let ver = self.verification.read();
        let test_exists = ver.test_cases.contains_key(test_id);
        let work_exists = wrk.work_items.contains_key(work_id);
        drop(ver);
        drop(wrk);
        if !test_exists || !work_exists {
            return Ok(());
        }
        self.upsert_relation(&verification_relation(
            RelationKind::Covers,
            GraphNodeId::Test(*test_id),
            GraphNodeId::Work(*work_id),
        ))
    }

    fn get_tests_covering_contract(
        &self,
        contract_id: &ContractId,
    ) -> Result<Vec<TestCase>, KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let mut seen = HashSet::new();
        Ok(ent
            .node_incoming
            .get(&GraphNodeId::Contract(*contract_id))
            .into_iter()
            .flatten()
            .filter_map(|relation_id| ent.relations.get(relation_id))
            .filter_map(|relation| match (relation.kind, relation.src) {
                (RelationKind::Covers, GraphNodeId::Test(test_id)) => Some(test_id),
                _ => None,
            })
            .filter(|test_id| seen.insert(*test_id))
            .filter_map(|test_id| ver.test_cases.get(&test_id).cloned())
            .collect())
    }

    fn get_tests_verifying_work(&self, work_id: &WorkId) -> Result<Vec<TestCase>, KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let mut seen = HashSet::new();
        Ok(ent
            .node_incoming
            .get(&GraphNodeId::Work(*work_id))
            .into_iter()
            .flatten()
            .filter_map(|relation_id| ent.relations.get(relation_id))
            .filter_map(|relation| match (relation.kind, relation.src) {
                (RelationKind::Covers, GraphNodeId::Test(test_id)) => Some(test_id),
                _ => None,
            })
            .filter(|test_id| seen.insert(*test_id))
            .filter_map(|test_id| ver.test_cases.get(&test_id).cloned())
            .collect())
    }

    // -----------------------------------------------------------------------
    // Mock hints (Phase 9 completion) — verification lock only
    // -----------------------------------------------------------------------

    fn create_mock_hint(&self, hint: &MockHint) -> Result<(), KinDbError> {
        self.verification.write().mock_hints.push(hint.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_mock_hints_for_test(&self, test_id: &TestId) -> Result<Vec<MockHint>, KinDbError> {
        let ver = self.verification.read();
        let results = ver
            .mock_hints
            .iter()
            .filter(|h| h.test_id == *test_id)
            .cloned()
            .collect();
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Verification run → proof links (Phase 9 completion) — verification lock only
    // -----------------------------------------------------------------------

    fn link_run_proves_entity(
        &self,
        run_id: &VerificationRunId,
        entity_id: &EntityId,
    ) -> Result<(), KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let run_exists = ver.verification_runs.contains_key(run_id);
        let entity_exists = ent.entities.contains_key(entity_id);
        drop(ver);
        drop(ent);
        if !run_exists || !entity_exists {
            return Ok(());
        }
        self.upsert_relation(&verification_relation(
            RelationKind::DerivedFrom,
            GraphNodeId::VerificationRun(*run_id),
            GraphNodeId::Entity(*entity_id),
        ))
    }

    fn link_run_proves_work(
        &self,
        run_id: &VerificationRunId,
        work_id: &WorkId,
    ) -> Result<(), KinDbError> {
        let wrk = self.work.read();
        let ver = self.verification.read();
        let run_exists = ver.verification_runs.contains_key(run_id);
        let work_exists = wrk.work_items.contains_key(work_id);
        drop(ver);
        drop(wrk);
        if !run_exists || !work_exists {
            return Ok(());
        }
        self.upsert_relation(&verification_relation(
            RelationKind::DerivedFrom,
            GraphNodeId::VerificationRun(*run_id),
            GraphNodeId::Work(*work_id),
        ))
    }

    fn list_runs_proving_entity(
        &self,
        entity_id: &EntityId,
    ) -> Result<Vec<VerificationRun>, KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let mut seen = HashSet::new();
        Ok(ent
            .node_incoming
            .get(&GraphNodeId::Entity(*entity_id))
            .into_iter()
            .flatten()
            .filter_map(|relation_id| ent.relations.get(relation_id))
            .filter_map(|relation| match (relation.kind, relation.src) {
                (RelationKind::DerivedFrom, GraphNodeId::VerificationRun(run_id)) => Some(run_id),
                _ => None,
            })
            .filter(|run_id| seen.insert(*run_id))
            .filter_map(|run_id| ver.verification_runs.get(&run_id).cloned())
            .collect())
    }

    fn list_runs_proving_work(&self, work_id: &WorkId) -> Result<Vec<VerificationRun>, KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let mut seen = HashSet::new();
        Ok(ent
            .node_incoming
            .get(&GraphNodeId::Work(*work_id))
            .into_iter()
            .flatten()
            .filter_map(|relation_id| ent.relations.get(relation_id))
            .filter_map(|relation| match (relation.kind, relation.src) {
                (RelationKind::DerivedFrom, GraphNodeId::VerificationRun(run_id)) => Some(run_id),
                _ => None,
            })
            .filter(|run_id| seen.insert(*run_id))
            .filter_map(|run_id| ver.verification_runs.get(&run_id).cloned())
            .collect())
    }

    // -----------------------------------------------------------------------
    // Contract CRUD — verification lock only
    // -----------------------------------------------------------------------

    fn create_contract(&self, contract: &Contract) -> Result<(), KinDbError> {
        // Contract uses EntityId for its `id` field but the trait keys by ContractId.
        // We derive a ContractId from the contract's EntityId for storage.
        let key = ContractId(contract.id.0);
        self.verification
            .write()
            .contracts
            .insert(key, contract.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_contract(&self, id: &ContractId) -> Result<Option<Contract>, KinDbError> {
        Ok(self.verification.read().contracts.get(id).cloned())
    }

    fn list_contracts(&self) -> Result<Vec<Contract>, KinDbError> {
        Ok(self
            .verification
            .read()
            .contracts
            .values()
            .cloned()
            .collect())
    }

    // -----------------------------------------------------------------------
    // Contract coverage (Phase 9 completion) — verification lock only
    // -----------------------------------------------------------------------

    fn get_contract_coverage_summary(&self) -> Result<ContractCoverageSummary, KinDbError> {
        let ent = self.entities.read();
        let ver = self.verification.read();
        let total = ver.contracts.len();
        let covered_ids: std::collections::HashSet<ContractId> = ent
            .relations
            .values()
            .filter_map(
                |relation| match (relation.kind, relation.src, relation.dst) {
                    (
                        RelationKind::Covers,
                        GraphNodeId::Test(_),
                        GraphNodeId::Contract(contract_id),
                    ) => Some(contract_id),
                    _ => None,
                },
            )
            .collect();
        let covered = ver
            .contracts
            .keys()
            .filter(|cid| covered_ids.contains(cid))
            .count();
        let ratio = if total > 0 {
            covered as f64 / total as f64
        } else {
            0.0
        };
        let uncovered: Vec<ContractId> = ver
            .contracts
            .keys()
            .filter(|cid| !covered_ids.contains(cid))
            .copied()
            .collect();
        Ok(ContractCoverageSummary {
            total_contracts: total,
            covered_contracts: covered,
            coverage_ratio: ratio,
            uncovered_contract_ids: uncovered,
        })
    }
}

impl ProvenanceStore for InMemoryGraph {
    type Error = KinDbError;

    // -----------------------------------------------------------------------
    // Provenance operations (Phase 10) — provenance lock only
    // -----------------------------------------------------------------------

    fn create_actor(&self, actor: &Actor) -> Result<(), KinDbError> {
        self.provenance
            .write()
            .actors
            .insert(actor.actor_id, actor.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_actor(&self, id: &ActorId) -> Result<Option<Actor>, KinDbError> {
        Ok(self.provenance.read().actors.get(id).cloned())
    }

    fn list_actors(&self) -> Result<Vec<Actor>, KinDbError> {
        Ok(self.provenance.read().actors.values().cloned().collect())
    }

    fn create_delegation(&self, delegation: &Delegation) -> Result<(), KinDbError> {
        self.provenance.write().delegations.push(delegation.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_delegations_for_actor(&self, id: &ActorId) -> Result<Vec<Delegation>, KinDbError> {
        let prv = self.provenance.read();
        let results = prv
            .delegations
            .iter()
            .filter(|d| d.principal == *id || d.delegate == *id)
            .cloned()
            .collect();
        Ok(results)
    }

    fn create_approval(&self, approval: &Approval) -> Result<(), KinDbError> {
        self.provenance.write().approvals.push(approval.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_approvals_for_change(&self, id: &SemanticChangeId) -> Result<Vec<Approval>, KinDbError> {
        let prv = self.provenance.read();
        let results = prv
            .approvals
            .iter()
            .filter(|a| a.change_id == *id)
            .cloned()
            .collect();
        Ok(results)
    }

    fn record_audit_event(&self, event: &AuditEvent) -> Result<(), KinDbError> {
        self.provenance.write().audit_events.push(event.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn query_audit_events(
        &self,
        actor_id: Option<&ActorId>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, KinDbError> {
        let prv = self.provenance.read();
        let results: Vec<AuditEvent> = prv
            .audit_events
            .iter()
            .rev()
            .filter(|e| {
                if let Some(aid) = actor_id {
                    e.actor_id == *aid
                } else {
                    true
                }
            })
            .take(limit)
            .cloned()
            .collect();
        Ok(results)
    }
}

impl SessionStore for InMemoryGraph {
    type Error = KinDbError;

    fn upsert_session(&self, session: &AgentSession) -> Result<(), KinDbError> {
        self.sessions
            .write()
            .sessions
            .insert(session.session_id, session.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_session(&self, session_id: &SessionId) -> Result<Option<AgentSession>, KinDbError> {
        Ok(self.sessions.read().sessions.get(session_id).cloned())
    }

    fn delete_session(&self, session_id: &SessionId) -> Result<(), KinDbError> {
        self.sessions.write().sessions.remove(session_id);
        self.require_full_snapshot();
        Ok(())
    }

    fn list_sessions(&self) -> Result<Vec<AgentSession>, KinDbError> {
        Ok(self.sessions.read().sessions.values().cloned().collect())
    }

    fn update_heartbeat(
        &self,
        session_id: &SessionId,
        heartbeat: &crate::types::Timestamp,
    ) -> Result<(), KinDbError> {
        if let Some(session) = self.sessions.write().sessions.get_mut(session_id) {
            session.last_heartbeat = heartbeat.clone();
            self.require_full_snapshot();
        }
        Ok(())
    }

    fn register_intent(&self, intent: &Intent) -> Result<(), KinDbError> {
        self.sessions
            .write()
            .intents
            .insert(intent.intent_id, intent.clone());
        self.require_full_snapshot();
        Ok(())
    }

    fn get_intent(&self, intent_id: &IntentId) -> Result<Option<Intent>, KinDbError> {
        Ok(self.sessions.read().intents.get(intent_id).cloned())
    }

    fn delete_intent(&self, intent_id: &IntentId) -> Result<(), KinDbError> {
        self.sessions.write().intents.remove(intent_id);
        self.require_full_snapshot();
        Ok(())
    }

    fn list_intents_for_session(&self, session_id: &SessionId) -> Result<Vec<Intent>, KinDbError> {
        Ok(self
            .sessions
            .read()
            .intents
            .values()
            .filter(|i| i.session_id == *session_id)
            .cloned()
            .collect())
    }

    fn list_all_intents(&self) -> Result<Vec<Intent>, KinDbError> {
        Ok(self.sessions.read().intents.values().cloned().collect())
    }
}

impl GraphStore for InMemoryGraph {
    type Error = KinDbError;
}

/// Check whether an entity matches all filter criteria.
fn matches_filter(entity: &Entity, filter: &EntityFilter) -> bool {
    if let Some(ref kinds) = filter.kinds {
        if !kinds.contains(&entity.kind) {
            return false;
        }
    }

    if let Some(ref langs) = filter.languages {
        if !langs.contains(&entity.language) {
            return false;
        }
    }

    if let Some(ref pattern) = filter.name_pattern {
        let pat = pattern.to_lowercase();
        let name = entity.name.to_lowercase();
        if let Some(suffix) = pat.strip_prefix('*') {
            if !name.ends_with(suffix) {
                return false;
            }
        } else if let Some(prefix) = pat.strip_suffix('*') {
            if !name.starts_with(prefix) {
                return false;
            }
        } else if !name.contains(&pat) {
            return false;
        }
    }

    if let Some(ref fp) = filter.file_path {
        match &entity.file_origin {
            Some(origin) if origin == fp => {}
            _ => return false,
        }
    }

    if let Some(ref roles) = filter.roles {
        if !roles.contains(&entity.role) {
            return false;
        }
    }

    true
}

impl RetrievalKeyFileResolver for InMemoryGraph {
    fn file_path_for_retrieval_key(&self, key: RetrievalKey) -> Option<FilePathId> {
        self.resolve_retrieval_key(&key)
            .and_then(|item| item.file_path())
    }
}

/// Test-only census of full text index rebuilds.
///
/// A rebuild collects indexable text for every entity in the graph, so a
/// restore that builds an index nobody searches does that work for nothing.
/// Thread-local for the same reason as [`root_hash_passes`]: the test binary
/// runs tests in parallel.
#[cfg(test)]
pub(crate) mod text_index_rebuilds {
    use std::cell::Cell;

    thread_local! {
        static REBUILDS: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn record() {
        REBUILDS.with(|rebuilds| rebuilds.set(rebuilds.get() + 1));
    }

    /// Start counting from zero on this thread.
    pub(crate) fn reset() {
        REBUILDS.with(|rebuilds| rebuilds.set(0));
    }

    /// Rebuilds taken on this thread since the last [`reset`].
    pub(crate) fn count() -> u64 {
        REBUILDS.with(Cell::get)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::merkle::{compute_graph_root_hash, root_hash_passes};

    /// Restoring a graph takes exactly one whole-graph Merkle root pass.
    ///
    /// The pass is inside the retrieval authority hash, which is what decides
    /// text index currency. A second one used to run in the caller to produce an
    /// argument this path discarded, so the count is the evidence that the
    /// discarded pass is gone. Counting passes rather than timing them keeps the
    /// claim true on any store and any machine.
    #[test]
    fn snapshot_restore_takes_one_graph_root_pass() {
        let dir = tempfile::tempdir().unwrap();
        let mut snapshot = GraphSnapshot::empty();
        for name in ["parseRegistry", "renderRegistry", "flushRegistry"] {
            let entity = test_entity(name, "src/registry.rs");
            snapshot.entities.insert(entity.id, entity);
        }

        root_hash_passes::reset();
        let graph =
            InMemoryGraph::from_snapshot_with_text_index(snapshot, dir.path().join("text-index"))
                .unwrap();
        assert_eq!(
            root_hash_passes::count(),
            1,
            "restoring a graph should compute the graph root once, not once per caller"
        );

        // The pass that remains is the one whose result is actually used: the
        // retrieval authority hash the restored graph reports.
        root_hash_passes::reset();
        let expected = compute_retrieval_authority_hash(&graph.to_snapshot());
        assert_eq!(graph.retrieval_authority_hash(), expected);
        assert_eq!(root_hash_passes::count(), 1);
    }

    /// Workspace materialization restores a graph, applies one delta, hands the
    /// snapshot back out and drops the graph. It never searches it, so the text
    /// index it used to build was indexed over every entity and then discarded.
    ///
    /// Both halves are asserted: the rebuild is gone, and the snapshot that
    /// materialization actually returns is unchanged by its absence.
    #[test]
    fn materialization_skips_the_text_index_it_would_discard() {
        let mut snapshot = GraphSnapshot::empty();
        for name in ["parseRegistry", "renderRegistry", "flushRegistry"] {
            let entity = test_entity(name, "src/registry.rs");
            snapshot.entities.insert(entity.id, entity);
        }
        // One delta, applied to both graphs, so the two runs differ only in
        // whether a text index existed. Minting the artifact id per graph would
        // make them differ for an unrelated reason.
        let delta = TransactionDelta {
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: vec![TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("src/registry.rs").unwrap(),
                    TreeEntry::blob(Hash256::from_bytes([4; 32]), false),
                ),
            }],
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        text_index_rebuilds::reset();
        let indexed = InMemoryGraph::from_snapshot(snapshot.clone()).unwrap();
        assert_eq!(
            text_index_rebuilds::count(),
            1,
            "a RAM-only text index starts empty, so restoring one always rebuilds it"
        );
        indexed.apply_transaction_delta(&delta).unwrap();

        text_index_rebuilds::reset();
        let bare = InMemoryGraph::from_snapshot_without_text_index(snapshot).unwrap();
        assert_eq!(
            text_index_rebuilds::count(),
            0,
            "materialization must not build a text index it discards"
        );
        bare.apply_transaction_delta(&delta).unwrap();

        assert_eq!(
            compute_retrieval_authority_hash(&indexed.to_snapshot()),
            compute_retrieval_authority_hash(&bare.to_snapshot()),
            "skipping a derived retrieval surface must not change graph truth"
        );
    }

    /// The in-run vector-sidecar flush policy: the first checkpoint of a run is
    /// always due; afterwards a checkpoint is due once EITHER the time interval
    /// OR the batch backstop is crossed, whichever comes first. Pure, so both
    /// arms are exercised deterministically with synthetic instants.
    #[test]
    #[cfg(feature = "vector")]
    fn vector_sidecar_flush_due_honors_interval_and_batch_backstop() {
        use std::time::{Duration, Instant};
        let base = Instant::now();
        let interval = Duration::from_secs(30);
        let backstop = 64usize;

        // First checkpoint of a run is always due, whatever the counters say.
        assert!(InMemoryGraph::vector_sidecar_flush_due(
            None, 0, base, interval, backstop
        ));
        assert!(InMemoryGraph::vector_sidecar_flush_due(
            None, 1, base, interval, backstop
        ));

        // Within both bounds → not due.
        let last = Some(base);
        assert!(!InMemoryGraph::vector_sidecar_flush_due(
            last,
            1,
            base + Duration::from_secs(5),
            interval,
            backstop
        ));
        assert!(!InMemoryGraph::vector_sidecar_flush_due(
            last,
            backstop - 1,
            base + Duration::from_secs(29),
            interval,
            backstop
        ));

        // Time interval reached → due even with only one batch since.
        assert!(InMemoryGraph::vector_sidecar_flush_due(
            last,
            1,
            base + Duration::from_secs(30),
            interval,
            backstop
        ));

        // Batch backstop reached → due even well within the time interval.
        assert!(InMemoryGraph::vector_sidecar_flush_due(
            last,
            backstop,
            base + Duration::from_secs(1),
            interval,
            backstop
        ));
    }

    /// The stateful throttle: the first in-run flush lands the sidecar, immediate
    /// follow-ups within the window are throttled, and a drain-time reset re-arms
    /// the next run's first flush.
    #[test]
    #[cfg(feature = "vector")]
    fn should_flush_vector_sidecar_lands_first_then_throttles_until_reset() {
        let graph = InMemoryGraph::new();
        // First in-run flush lands immediately (persisted tracks compute from the
        // first batch).
        assert!(graph.should_flush_vector_sidecar_now());
        // Immediate follow-ups are throttled (< interval and < batch backstop).
        assert!(!graph.should_flush_vector_sidecar_now());
        assert!(!graph.should_flush_vector_sidecar_now());
        // A drain-time reset re-arms the first flush of the next run.
        graph.reset_vector_sidecar_flush_throttle();
        assert!(graph.should_flush_vector_sidecar_now());
    }

    #[test]
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    fn test_vector_index_dimension_mismatch_auto_recovery() {
        // See `crate::embed::EMBED_MODEL_DOWNLOAD_LOCK`: shares the HF Hub
        // cache download with
        // `embed::tests::default_dimensions_match_default_model`.
        let _download_guard = crate::embed::EMBED_MODEL_DOWNLOAD_LOCK.lock();
        let graph = InMemoryGraph::new();
        // Setup a vector index with a mismatching dimension (e.g. 100)
        let mismatched_vi = Arc::new(VectorIndex::new(100).unwrap());
        *graph.vector_index.lock() = Some(mismatched_vi);

        // Add some entities so we can verify they get queued for embedding
        let entity = test_entity("foo", "src/main.rs");
        graph.upsert_entities_batch(&[entity]).unwrap();

        // Clear the queue so we can verify the auto-recovery queues missing items
        graph.embedding_queue.lock().clear();
        assert_eq!(graph.pending_embeddings(), 0);

        // Fetch the vector index, which should trigger recovery because the embedder has a different dimension
        let vi = graph.get_vector_index().unwrap();

        // Dimensions should match the embedder now
        let embedder = graph.get_embedder().unwrap();
        assert_eq!(vi.dimensions(), embedder.dimensions());

        // The entity should be queued for embedding now
        assert_eq!(graph.pending_embeddings(), 1);
    }

    fn test_entity(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn seal_change(mut change: SemanticChange) -> SemanticChange {
        change.id =
            kin_model::compute_semantic_change_id(&change).expect("valid semantic change fixture");
        change
    }

    fn admit_change(graph: &InMemoryGraph, change: SemanticChange) -> SemanticChangeId {
        let change = seal_change(change);
        let id = change.id;
        graph.create_change(&change).expect("valid change fixture");
        id
    }

    fn assert_no_change_admission(graph: &InMemoryGraph) {
        let snapshot = graph.to_snapshot();
        assert!(snapshot.changes.is_empty());
        assert!(snapshot.entity_revisions.is_empty());
        assert!(snapshot.change_children.is_empty());
        assert!(snapshot.resolved_tree.is_empty());
        assert!(!graph.has_pending_delta());
    }

    fn test_repo_path(path: &str) -> RepoPath {
        RepoPath::from_utf8(path).unwrap()
    }

    fn test_located(path: &str, entry: TreeEntry) -> LocatedEntry {
        LocatedEntry::new(test_repo_path(path), entry)
    }

    fn admit_enrichment(
        graph: &InMemoryGraph,
        file_id: &FilePathId,
        content_hash: Hash256,
    ) -> ArtifactId {
        graph.admit_artifact_for_test(&file_id.0, TreeEntry::blob(content_hash, false))
    }

    #[test]
    fn transaction_applies_exact_non_language_tree_transitions() {
        let graph = InMemoryGraph::new();
        let file_id = FilePathId::new("compose.yaml");
        let artifact_id = ArtifactId::new();
        let regular = TreeEntry::blob(Hash256::from_bytes([0x11; 32]), false);
        let executable = TreeEntry::blob(Hash256::from_bytes([0x11; 32]), true);
        let symlink = TreeEntry::symlink(Hash256::from_bytes([0x22; 32]));

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: test_located(&file_id.0, regular),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();
        assert_eq!(graph.get_tree_entry(&file_id).unwrap(), Some(regular));

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: test_located(&file_id.0, regular),
                    new: test_located(&file_id.0, executable),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();
        assert_eq!(graph.get_tree_entry(&file_id).unwrap(), Some(executable));

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: test_located(&file_id.0, executable),
                    new: test_located(&file_id.0, symlink),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();
        assert_eq!(graph.get_tree_entry(&file_id).unwrap(), Some(symlink));
    }

    #[test]
    fn transaction_persists_and_traverses_external_references_atomically() {
        let graph = InMemoryGraph::new();
        let artifact_id = ArtifactId::new();
        let artifact_entry = TreeEntry::blob(Hash256::from_bytes([0x31; 32]), false);
        let reference =
            ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        let relation = Relation {
            id: RelationId::new(),
            src: GraphNodeId::Artifact(artifact_id),
            dst: GraphNodeId::ExternalReference(reference.id),
            kind: RelationKind::Imports,
            confidence: 1.0,
            origin: RelationOrigin::Lsp,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: vec![RelationDelta::Added {
                    new: relation.clone(),
                }],
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: test_located("src/client.py", artifact_entry),
                }],
                admission_policy_delta: None,
                external_reference_deltas: vec![ExternalReferenceDelta::Added {
                    new: reference.clone(),
                }],
            })
            .unwrap();

        assert_eq!(
            graph.get_external_reference(&reference.id),
            Some(reference.clone())
        );
        assert_eq!(graph.list_external_references(), vec![reference.clone()]);
        let pending = graph.pending_delta_snapshot(7).unwrap();
        assert_eq!(pending.external_references.added.len(), 1);
        assert_eq!(
            pending.external_references.added[0],
            (reference.id, reference.clone())
        );

        let traversed = graph
            .traverse(&GraphNodeId::Artifact(artifact_id), &[], 1)
            .unwrap();
        assert_eq!(
            traversed.external_references.get(&reference.id),
            Some(&reference)
        );
        assert!(traversed
            .nodes
            .contains(&GraphNodeId::ExternalReference(reference.id)));

        let snapshot = graph.to_snapshot();
        let owned_bytes = snapshot.to_bytes().unwrap();
        let owned_round_trip = GraphSnapshot::from_bytes(&owned_bytes).unwrap();
        assert_eq!(
            owned_round_trip.external_references.get(&reference.id),
            Some(&reference)
        );
        let reopened = InMemoryGraph::from_snapshot(owned_round_trip).unwrap();
        assert_eq!(
            reopened.get_external_reference(&reference.id),
            Some(reference.clone())
        );

        let (borrowed_bytes, _) = graph.serialize_snapshot_borrowed().unwrap();
        let borrowed_round_trip = GraphSnapshot::from_bytes(&borrowed_bytes).unwrap();
        assert_eq!(
            borrowed_round_trip.external_references.get(&reference.id),
            Some(&reference)
        );

        let error = graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: Vec::new(),
                admission_policy_delta: None,
                external_reference_deltas: vec![ExternalReferenceDelta::Removed {
                    old: reference.clone(),
                }],
            })
            .expect_err("a referenced external endpoint cannot be removed alone");
        assert!(error
            .to_string()
            .contains("unadmitted destination endpoint"));
        assert_eq!(
            graph.get_external_reference(&reference.id),
            Some(reference.clone())
        );

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: vec![RelationDelta::Removed {
                    old: relation.clone(),
                }],
                tree_deltas: Vec::new(),
                admission_policy_delta: None,
                external_reference_deltas: vec![ExternalReferenceDelta::Removed {
                    old: reference.clone(),
                }],
            })
            .unwrap();
        assert_eq!(graph.get_external_reference(&reference.id), None);
        assert!(!graph.to_snapshot().relations.contains_key(&relation.id));
        assert!(
            graph
                .pending_delta_snapshot(7)
                .unwrap()
                .external_references
                .is_empty(),
            "an add followed by an exact removal before persistence is a net no-op"
        );
    }

    #[test]
    fn tree_mode_only_update_preserves_content_derived_facets() {
        let graph = InMemoryGraph::new();
        let file_id = FilePathId::new("Makefile");
        let hash = Hash256::from_bytes([0x10; 32]);
        let regular = TreeEntry::blob(hash, false);
        let executable = TreeEntry::blob(hash, true);
        let artifact_id = graph.admit_artifact_for_test(&file_id.0, regular);
        let artifact = StructuredArtifact {
            file_id: file_id.clone(),
            kind: ArtifactKind::Makefile,
            content_hash: hash,
            text_preview: Some("build:".into()),
        };
        let entity = test_entity("make_target", &file_id.0);
        graph.upsert_entity(&entity).unwrap();
        graph.upsert_structured_artifact(&artifact).unwrap();
        graph.clear_pending_delta();

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: test_located(&file_id.0, regular),
                    new: test_located(&file_id.0, executable),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();

        assert_eq!(graph.get_tree_entry(&file_id).unwrap(), Some(executable));
        assert_eq!(
            graph
                .get_structured_artifact(&file_id)
                .unwrap()
                .expect("content-identical facet must remain")
                .content_hash,
            hash
        );
        assert!(
            graph.get_entity(&entity.id).unwrap().is_some(),
            "mode-only transitions must preserve entities derived from identical bytes"
        );
        let pending = graph
            .pending_delta_snapshot(0)
            .expect("mode transition must be persisted");
        assert!(pending.structured_artifacts.is_empty());
    }

    #[test]
    fn explicit_content_change_removals_preserve_semantic_revision_history() {
        let graph = InMemoryGraph::new();
        let changed_file = FilePathId::new("src/changed.rs");
        let neighbor_file = FilePathId::new("src/neighbor.rs");
        let old_entry = TreeEntry::blob(Hash256::from_bytes([0x12; 32]), false);
        let new_entry = TreeEntry::blob(Hash256::from_bytes([0x13; 32]), false);
        let artifact_id = graph.admit_artifact_for_test(&changed_file.0, old_entry);
        graph.admit_artifact_for_test(
            &neighbor_file.0,
            TreeEntry::blob(Hash256::from_bytes([0x14; 32]), false),
        );

        let retired = test_entity("retired", &changed_file.0);
        let neighbor = test_entity("neighbor", &neighbor_file.0);
        graph.upsert_entity(&retired).unwrap();
        graph.upsert_entity(&neighbor).unwrap();
        let relation = test_relation(retired.id, neighbor.id, RelationKind::Calls);
        graph.upsert_relation(&relation).unwrap();
        admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
                parents: Vec::new(),
                timestamp: Timestamp::now(),
                author: AuthorId::new("tester"),
                message: "record retired revision".into(),
                entity_deltas: vec![EntityDelta::Added {
                    new: retired.clone(),
                }],
                relation_deltas: Vec::new(),
                tree_deltas: Vec::new(),
                projected_files: vec![changed_file.clone()],
                spec_link: None,
                evidence: Vec::new(),
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );
        assert!(graph
            .to_snapshot()
            .entity_revisions
            .contains_key(&retired.id));
        graph.clear_pending_delta();

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![EntityDelta::Removed {
                    old: retired.clone(),
                }],
                relation_deltas: vec![RelationDelta::Removed {
                    old: relation.clone(),
                }],
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: test_located(&changed_file.0, old_entry),
                    new: test_located(&changed_file.0, new_entry),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();

        assert!(graph.get_entity(&retired.id).unwrap().is_none());
        assert!(graph.get_entity(&neighbor.id).unwrap().is_some());
        assert_eq!(graph.relation_count(), 0);
        let snapshot = graph.to_snapshot();
        assert!(
            snapshot.entity_revisions.contains_key(&retired.id),
            "removing live state must not erase immutable semantic revision history"
        );
        assert!(!snapshot.relations.contains_key(&relation.id));
        assert_eq!(
            graph.artifact_id_at_path(&test_repo_path(&changed_file.0)),
            Some(artifact_id),
            "the new exact artifact remains valid without semantic enrichment"
        );

        let pending = graph
            .pending_delta_snapshot(0)
            .expect("retirement and tree replacement must share one delta");
        assert!(pending.entities.removed.contains(&retired.id));
        assert!(!pending.entity_revisions.removed.contains(&retired.id));
        assert!(pending.relations.removed.contains(&relation.id));
        assert_eq!(pending.resolved_tree.modified.len(), 1);
    }

    #[test]
    fn content_change_retires_derived_but_preserves_manual_artifact_relations() {
        let graph = InMemoryGraph::new();
        let file_id = FilePathId::new("Dockerfile");
        let entity_file_id = FilePathId::new("src/main.rs");
        let old_entry = TreeEntry::blob(Hash256::from_bytes([0x31; 32]), false);
        let new_entry = TreeEntry::blob(Hash256::from_bytes([0x32; 32]), false);
        let artifact_id = graph.admit_artifact_for_test(&file_id.0, old_entry);
        graph.admit_artifact_for_test(
            &entity_file_id.0,
            TreeEntry::blob(Hash256::from_bytes([0x33; 32]), false),
        );
        let entity = test_entity("build_image", &entity_file_id.0);
        graph.upsert_entity(&entity).unwrap();
        let derived_relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::DependsOn,
            src: GraphNodeId::Entity(entity.id),
            dst: GraphNodeId::Artifact(artifact_id),
            confidence: 1.0,
            origin: RelationOrigin::Inferred,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        let manual_relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::OwnedByFile,
            src: GraphNodeId::Entity(entity.id),
            dst: GraphNodeId::Artifact(artifact_id),
            confidence: 1.0,
            origin: RelationOrigin::Manual,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        graph.upsert_relation(&derived_relation).unwrap();
        graph.upsert_relation(&manual_relation).unwrap();
        graph.clear_pending_delta();

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: vec![RelationDelta::Removed {
                    old: derived_relation.clone(),
                }],
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: test_located(&file_id.0, old_entry),
                    new: test_located(&file_id.0, new_entry),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();

        assert!(
            graph.get_entity(&entity.id).unwrap().is_some(),
            "an entity in a different unchanged file remains admitted"
        );
        assert_eq!(graph.relation_count(), 1);
        let snapshot = graph.to_snapshot();
        assert!(!snapshot.relations.contains_key(&derived_relation.id));
        assert!(snapshot.relations.contains_key(&manual_relation.id));
        let pending = graph
            .pending_delta_snapshot(0)
            .expect("artifact-edge retirement must share the exact-tree delta");
        assert!(pending.relations.removed.contains(&derived_relation.id));
        assert!(!pending.relations.removed.contains(&manual_relation.id));
        assert_eq!(pending.resolved_tree.modified.len(), 1);
    }

    #[test]
    fn pure_artifact_move_preserves_identity_relations() {
        let graph = InMemoryGraph::new();
        let old_path = "config/compose.yaml";
        let new_path = "deploy/compose.yaml";
        let entry = TreeEntry::blob(Hash256::from_bytes([0x34; 32]), false);
        let artifact_id = graph.admit_artifact_for_test(old_path, entry);
        graph.admit_artifact_for_test(
            "src/main.rs",
            TreeEntry::blob(Hash256::from_bytes([0x35; 32]), false),
        );
        let entity = test_entity("deploy", "src/main.rs");
        graph.upsert_entity(&entity).unwrap();
        let relations: Vec<Relation> = [RelationOrigin::Manual, RelationOrigin::Parsed]
            .into_iter()
            .map(|origin| Relation {
                id: RelationId::new(),
                kind: RelationKind::DependsOn,
                src: GraphNodeId::Entity(entity.id),
                dst: GraphNodeId::Artifact(artifact_id),
                confidence: 1.0,
                origin,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .collect();
        graph.upsert_relations_batch(&relations).unwrap();
        graph.clear_pending_delta();

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: test_located(old_path, entry),
                    new: test_located(new_path, entry),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();

        let snapshot = graph.to_snapshot();
        assert!(
            relations
                .iter()
                .all(|relation| snapshot.relations.contains_key(&relation.id)),
            "a pure location change cannot erase relations to stable artifact identity"
        );
        let pending = graph
            .pending_delta_snapshot(0)
            .expect("the move itself must be persisted");
        assert!(pending.relations.is_empty());
    }

    #[test]
    fn artifact_deletion_retires_all_incident_relation_origins() {
        let graph = InMemoryGraph::new();
        let artifact_path = "Dockerfile";
        let entry = TreeEntry::blob(Hash256::from_bytes([0x36; 32]), false);
        let artifact_id = graph.admit_artifact_for_test(artifact_path, entry);
        graph.admit_artifact_for_test(
            "src/main.rs",
            TreeEntry::blob(Hash256::from_bytes([0x37; 32]), false),
        );
        let entity = test_entity("image", "src/main.rs");
        graph.upsert_entity(&entity).unwrap();
        let relations: Vec<Relation> = [
            RelationOrigin::Parsed,
            RelationOrigin::Inferred,
            RelationOrigin::Manual,
            RelationOrigin::Lsp,
        ]
        .into_iter()
        .map(|origin| Relation {
            id: RelationId::new(),
            kind: RelationKind::DependsOn,
            src: GraphNodeId::Entity(entity.id),
            dst: GraphNodeId::Artifact(artifact_id),
            confidence: 1.0,
            origin,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        })
        .collect();
        graph.upsert_relations_batch(&relations).unwrap();
        graph.clear_pending_delta();

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: relations
                    .iter()
                    .cloned()
                    .map(|old| RelationDelta::Removed { old })
                    .collect(),
                tree_deltas: vec![TreeDelta::Removed {
                    artifact_id,
                    old: test_located(artifact_path, entry),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();

        assert_eq!(graph.relation_count(), 0);
        let pending = graph
            .pending_delta_snapshot(0)
            .expect("artifact and incident-edge retirement must be atomic");
        assert!(relations
            .iter()
            .all(|relation| pending.relations.removed.contains(&relation.id)));
    }

    #[test]
    fn transaction_rejects_entity_placement_absent_from_staged_tree() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("orphan", "src/missing.rs");

        let error = graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![EntityDelta::Added {
                    new: entity.clone(),
                }],
                relation_deltas: Vec::new(),
                tree_deltas: Vec::new(),
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap_err();

        assert!(error.to_string().contains("absent from the staged tree"));
        assert!(graph.get_entity(&entity.id).unwrap().is_none());
        assert!(graph.resolved_tree().is_empty());
        assert!(!graph.has_pending_delta());
    }

    #[test]
    fn tree_removal_requires_exact_entity_retirement_in_the_same_delta() {
        let graph = InMemoryGraph::new();
        let path = "src/owned.rs";
        let entry = TreeEntry::blob(Hash256::from_bytes([0x14; 32]), false);
        let artifact_id = graph.admit_artifact_for_test(path, entry);
        let entity = test_entity("owned", path);
        graph.upsert_entity(&entity).unwrap();
        graph.clear_pending_delta();

        let error = graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Removed {
                    artifact_id,
                    old: test_located(path, entry),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .expect_err("a tree transition cannot silently orphan semantic authority");

        assert!(error
            .to_string()
            .contains("carry its exact entity removal or relocation"));
        assert_eq!(
            graph
                .artifact_id_at_path(&test_repo_path(path))
                .expect("tree authority must remain"),
            artifact_id
        );
        assert_eq!(graph.get_entity(&entity.id).unwrap(), Some(entity));
        assert!(!graph.has_pending_delta());
    }

    #[test]
    fn transaction_rejects_unadmitted_relation_endpoint_before_any_mutation() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("would_land", "src/new.rs");
        let artifact_id = ArtifactId::new();
        let entry = TreeEntry::blob(Hash256::from_bytes([0x15; 32]), false);
        let relation = test_relation(entity.id, EntityId::new(), RelationKind::Calls);

        let error = graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![EntityDelta::Added {
                    new: entity.clone(),
                }],
                relation_deltas: vec![RelationDelta::Added { new: relation }],
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: test_located("src/new.rs", entry),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("unadmitted destination endpoint"));
        assert!(graph.get_entity(&entity.id).unwrap().is_none());
        assert!(graph.resolved_tree().is_empty());
        assert!(!graph.has_pending_delta());
    }

    #[test]
    fn post_authority_cache_failure_quarantines_without_retryable_error() {
        let dir = tempfile::tempdir().unwrap();
        let graph = InMemoryGraph::with_text_index(dir.path().join("text-index"));
        let file_id = FilePathId::new("src/fault.rs");
        let old_entry = TreeEntry::blob(Hash256::from_bytes([0x16; 32]), false);
        let new_entry = TreeEntry::blob(Hash256::from_bytes([0x17; 32]), false);
        let artifact_id = graph.admit_artifact_for_test(&file_id.0, old_entry);
        let entity = test_entity("faulted", &file_id.0);
        graph.upsert_entity(&entity).unwrap();
        graph.flush_text_index().unwrap();
        assert!(!graph.text_search("faulted", 10).unwrap().is_empty());
        graph.clear_pending_delta();
        graph
            .fail_next_transaction_derived_cleanup
            .store(true, Ordering::Release);

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![EntityDelta::Removed {
                    old: entity.clone(),
                }],
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: test_located(&file_id.0, old_entry),
                    new: test_located(&file_id.0, new_entry),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .expect("derived cache failure cannot reverse committed authority");

        assert!(graph.get_entity(&entity.id).unwrap().is_none());
        assert_eq!(graph.get_tree_entry(&file_id).unwrap(), Some(new_entry));
        assert!(graph.text_full_rebuild_required.load(Ordering::Acquire));
        assert!(
            graph
                .text_search("faulted", 10)
                .unwrap_err()
                .to_string()
                .contains("quarantined"),
            "a quarantined derived index must never answer from stale documents"
        );
        assert_eq!(graph.text_doc_frequency("faulted"), 0);
        assert_eq!(graph.text_document_count(), 0);
        graph.fail_next_text_rebuild.store(true, Ordering::Release);
        assert!(
            graph.flush_text_index().is_err(),
            "the deterministic rebuild failure must reach the caller"
        );
        assert!(
            graph.text_full_rebuild_required.load(Ordering::Acquire),
            "a failed rebuild cannot clear quarantine"
        );
        assert!(graph.text_search("faulted", 10).is_err());
        graph.flush_text_index().unwrap();
        assert!(!graph.text_full_rebuild_required.load(Ordering::Acquire));
        assert!(graph.text_search("faulted", 10).unwrap().is_empty());
        #[cfg(feature = "vector")]
        {
            assert!(graph.vector_index.lock().is_none());
            assert_eq!(
                graph.pending_artifact_embeddings(),
                0,
                "an exact artifact without enrichment has no vector document to rebuild"
            );
        }
    }

    #[test]
    fn tree_transaction_retires_old_path_facets_by_captured_identity() {
        let dir = tempfile::tempdir().unwrap();
        let graph = InMemoryGraph::with_text_index(dir.path().join("text-index"));
        let old_file_id = FilePathId::new("config/old.toml");
        let new_file_id = FilePathId::new("config/current.toml");
        let old_entry = TreeEntry::blob(Hash256::from_bytes([0x21; 32]), false);
        let new_entry = TreeEntry::blob(Hash256::from_bytes([0x22; 32]), false);
        let artifact_id = graph.admit_artifact_for_test(&old_file_id.0, old_entry);
        let shallow = ShallowTrackedFile {
            file_id: old_file_id.clone(),
            language_hint: "unsupported".into(),
            declaration_count: 1,
            import_count: 0,
            syntax_hash: Hash256::from_bytes([0x23; 32]),
            signature_hash: None,
            declaration_names: vec!["obsolete_shallow_marker".into()],
            import_paths: Vec::new(),
        };
        let layout = FileLayout {
            file_id: old_file_id.clone(),
            parse_completeness: ParseCompleteness::Full,
            imports: ImportSection {
                byte_range: 0..0,
                items: Vec::new(),
            },
            regions: Vec::new(),
        };
        let structured = StructuredArtifact {
            file_id: old_file_id.clone(),
            kind: ArtifactKind::CiConfig,
            content_hash: Hash256::from_bytes([0x24; 32]),
            text_preview: Some("obsolete structured marker".into()),
        };
        let opaque = OpaqueArtifact {
            file_id: old_file_id.clone(),
            content_hash: Hash256::from_bytes([0x25; 32]),
            mime_type: Some("application/octet-stream".into()),
            text_preview: Some("obsolete opaque marker".into()),
        };

        graph.upsert_shallow_file(&shallow).unwrap();
        graph.upsert_file_layout(&layout).unwrap();
        graph.upsert_structured_artifact(&structured).unwrap();
        graph.upsert_opaque_artifact(&opaque).unwrap();
        graph.flush_text_index().unwrap();
        graph.clear_pending_delta();

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: test_located(&old_file_id.0, old_entry),
                    new: test_located(&new_file_id.0, new_entry),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();

        assert!(graph.get_shallow_file(&old_file_id).unwrap().is_none());
        assert!(graph.get_file_layout(&old_file_id).unwrap().is_none());
        assert!(graph
            .get_structured_artifact(&old_file_id)
            .unwrap()
            .is_none());
        assert!(graph.get_opaque_artifact(&old_file_id).unwrap().is_none());
        assert_eq!(
            graph.artifact_id_at_path(&test_repo_path(&new_file_id.0)),
            Some(artifact_id)
        );
        assert!(graph
            .artifact_id_at_path(&test_repo_path(&old_file_id.0))
            .is_none());

        let pending = graph
            .pending_delta_snapshot(0)
            .expect("tree and facet removals must be persisted together");
        assert_eq!(pending.shallow_files.removed.len(), 1);
        assert_eq!(pending.shallow_files.removed[0].file_id, old_file_id);
        assert_eq!(pending.file_layouts.removed.len(), 1);
        assert_eq!(pending.file_layouts.removed[0].file_id, old_file_id);
        assert_eq!(pending.structured_artifacts.removed.len(), 1);
        assert_eq!(pending.structured_artifacts.removed[0].file_id, old_file_id);
        assert_eq!(pending.opaque_artifacts.removed.len(), 1);
        assert_eq!(pending.opaque_artifacts.removed[0].file_id, old_file_id);
        assert_eq!(
            pending.resolved_tree.modified,
            vec![(artifact_id, test_located(&new_file_id.0, new_entry))]
        );

        graph.flush_text_index().unwrap();
        let artifact_key = RetrievalKey::Artifact(artifact_id);
        assert!(!graph
            .text_search("obsolete opaque marker", 10)
            .unwrap()
            .iter()
            .any(|(key, _)| *key == artifact_key));
        #[cfg(feature = "vector")]
        assert!(!graph.artifact_embedding_queue.lock().contains(&artifact_id));
    }

    #[test]
    fn tree_removal_retires_facets_without_post_removal_path_lookup() {
        let graph = InMemoryGraph::new();
        let file_id = FilePathId::new("compose.yaml");
        let entry = TreeEntry::blob(Hash256::from_bytes([0x31; 32]), false);
        let artifact_id = graph.admit_artifact_for_test(&file_id.0, entry);
        let artifact = StructuredArtifact {
            file_id: file_id.clone(),
            kind: ArtifactKind::ComposeFile,
            content_hash: Hash256::from_bytes([0x32; 32]),
            text_preview: Some("services:".into()),
        };
        graph.upsert_structured_artifact(&artifact).unwrap();
        graph.clear_pending_delta();

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Removed {
                    artifact_id,
                    old: test_located(&file_id.0, entry),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();

        assert!(graph
            .artifact_id_at_path(&test_repo_path(&file_id.0))
            .is_none());
        assert!(graph.get_structured_artifact(&file_id).unwrap().is_none());
        let pending = graph
            .pending_delta_snapshot(0)
            .expect("tree and facet removal must share one persistence delta");
        assert_eq!(pending.resolved_tree.removed, vec![artifact_id]);
        assert_eq!(pending.structured_artifacts.removed.len(), 1);
        assert_eq!(pending.structured_artifacts.removed[0].file_id, file_id);
    }

    #[test]
    fn stale_tree_transition_rejects_all_graph_mutations_atomically() {
        let graph = InMemoryGraph::new();
        let file_id = FilePathId::new("Dockerfile");
        let current = TreeEntry::blob(Hash256::from_bytes([0x31; 32]), false);
        let stale = TreeEntry::blob(Hash256::from_bytes([0x32; 32]), false);
        let replacement = TreeEntry::blob(Hash256::from_bytes([0x33; 32]), true);
        let artifact_id = graph.admit_artifact_for_test(&file_id.0, current);
        let entity = test_entity("must_not_land", "src/lib.rs");

        let error = graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![EntityDelta::Added {
                    new: entity.clone(),
                }],
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: test_located(&file_id.0, stale),
                    new: test_located(&file_id.0, replacement),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("repository tree transition rejected"));
        assert_eq!(graph.get_tree_entry(&file_id).unwrap(), Some(current));
        assert!(graph.get_entity(&entity.id).unwrap().is_none());
    }

    #[test]
    fn stale_tree_transition_preserves_every_old_path_facet_atomically() {
        let graph = InMemoryGraph::new();
        let file_id = FilePathId::new("config/settings.yaml");
        let current = TreeEntry::blob(Hash256::from_bytes([0x41; 32]), false);
        let stale = TreeEntry::blob(Hash256::from_bytes([0x42; 32]), false);
        let replacement = TreeEntry::blob(Hash256::from_bytes([0x43; 32]), false);
        let artifact_id = graph.admit_artifact_for_test(&file_id.0, current);
        let shallow = ShallowTrackedFile {
            file_id: file_id.clone(),
            language_hint: "yaml".into(),
            declaration_count: 0,
            import_count: 0,
            syntax_hash: Hash256::from_bytes([0x44; 32]),
            signature_hash: None,
            declaration_names: Vec::new(),
            import_paths: Vec::new(),
        };
        let layout = FileLayout {
            file_id: file_id.clone(),
            parse_completeness: ParseCompleteness::Full,
            imports: ImportSection {
                byte_range: 0..0,
                items: Vec::new(),
            },
            regions: Vec::new(),
        };
        let structured = StructuredArtifact {
            file_id: file_id.clone(),
            kind: ArtifactKind::CiConfig,
            content_hash: Hash256::from_bytes([0x45; 32]),
            text_preview: Some("structured".into()),
        };
        let opaque = OpaqueArtifact {
            file_id: file_id.clone(),
            content_hash: Hash256::from_bytes([0x46; 32]),
            mime_type: None,
            text_preview: Some("opaque".into()),
        };
        graph.upsert_shallow_file(&shallow).unwrap();
        graph.upsert_file_layout(&layout).unwrap();
        graph.upsert_structured_artifact(&structured).unwrap();
        graph.upsert_opaque_artifact(&opaque).unwrap();
        graph.clear_pending_delta();

        let error = graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: test_located(&file_id.0, stale),
                    new: test_located(&file_id.0, replacement),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("repository tree transition rejected"));
        assert_eq!(graph.get_tree_entry(&file_id).unwrap(), Some(current));
        assert_eq!(
            graph
                .get_shallow_file(&file_id)
                .unwrap()
                .expect("shallow facet must remain")
                .syntax_hash,
            shallow.syntax_hash
        );
        assert_eq!(
            graph
                .get_file_layout(&file_id)
                .unwrap()
                .expect("layout facet must remain")
                .parse_completeness
                .bucket(),
            layout.parse_completeness.bucket()
        );
        assert_eq!(
            graph
                .get_structured_artifact(&file_id)
                .unwrap()
                .expect("structured facet must remain")
                .content_hash,
            structured.content_hash
        );
        assert_eq!(
            graph
                .get_opaque_artifact(&file_id)
                .unwrap()
                .expect("opaque facet must remain")
                .content_hash,
            opaque.content_hash
        );
        assert!(!graph.has_pending_delta());
    }

    fn test_relation(src: EntityId, dst: EntityId, kind: RelationKind) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    /// Once the graph is one connected component, adding relations one at a time
    /// (as test-materialization does) must not refresh the Merkle root per
    /// upsert — that is O(component) each, i.e. O(N^2) over the burst. Deferral
    /// collapses the whole burst into a single batch Merkle build at the next
    /// root read.
    #[test]
    fn single_relation_upserts_defer_to_one_batch_merkle() {
        let graph = InMemoryGraph::new();
        let n: usize = 12_000;
        let entities: Vec<Entity> = (0..n as u128)
            .map(|i| test_entity_with_id(i + 1, &format!("entity_{i}")))
            .collect();
        graph.batch_upsert_entities(&entities).unwrap();

        // Chain every entity so the whole graph is one weakly-connected
        // component — this is what makes a per-mutation refresh touch the entire
        // graph in the buggy path.
        let chain: Vec<Relation> = entities
            .windows(2)
            .map(|window| test_relation(window[0].id, window[1].id, RelationKind::Calls))
            .collect();
        graph.upsert_relations_batch(&chain).unwrap();

        // Reset per-graph counter after the setup batches so we only count
        // flushes triggered by the single-relation upsert loop below.
        // Using an instance counter (rather than the old process-wide global)
        // eliminates interference from other tests running concurrently.
        graph
            .merkle_flush_count
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let start = std::time::Instant::now();
        // Thousands of single-relation upserts, exactly like
        // materialize_discovered_tests' per-test `upsert_relation` loop.
        for i in 0..3_000usize {
            let src = entities[i % n].id;
            let dst = entities[(i * 7 + 1) % n].id;
            graph
                .upsert_relation(&test_relation(src, dst, RelationKind::Tests))
                .unwrap();
        }

        // Nothing has read the root, so not one refresh should have run.
        assert_eq!(
            graph
                .merkle_flush_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "single-entity upserts must defer Merkle work, not refresh eagerly"
        );

        // The first root read reconciles everything in exactly one batch build.
        let root = graph.compute_root_hash();
        let elapsed = start.elapsed();
        assert_eq!(
            graph
                .merkle_flush_count
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "reconciliation must be a single batch refresh, not one per mutation"
        );
        assert_eq!(
            root,
            compute_graph_root_hash(&graph.to_snapshot()),
            "deferred root must equal the cold frozen root"
        );
        // The old O(N^2) path is minutes for this size; deferral is well under
        // this generous bound.
        assert!(
            elapsed.as_secs() < 30,
            "3000 single-relation upserts + reconcile took {elapsed:?} — non-linear regression"
        );
    }

    // ----------------------------------------------------------------------
    // boot-time adjacency reuse
    // ----------------------------------------------------------------------

    /// When the persisted entity-level adjacency is consistent with relations,
    /// the loader reuses it as-is instead of recomputing from relations.
    #[test]
    fn adjacency_reuse_when_persisted_consistent() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let rel = test_relation(e1, e2, RelationKind::Calls);
        let rid = rel.id;
        let mut relations: HashMap<RelationId, Relation> = HashMap::new();
        relations.insert(rid, rel);

        // The exact adjacency a correct writer would persist.
        let mut persisted_outgoing: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        persisted_outgoing.insert(e1, vec![rid]);
        let mut persisted_incoming: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        persisted_incoming.insert(e2, vec![rid]);

        let (outgoing, incoming, node_outgoing, node_incoming, reuse) =
            build_relation_indexes_with_reuse(&relations, persisted_outgoing, persisted_incoming);

        assert_eq!(reuse, AdjacencyReuse::Reused);
        assert_eq!(outgoing.get(&e1), Some(&vec![rid]));
        assert_eq!(incoming.get(&e2), Some(&vec![rid]));
        // Node-level maps are never persisted, so they are always derived.
        assert_eq!(
            node_outgoing.get(&GraphNodeId::Entity(e1)),
            Some(&vec![rid])
        );
        assert_eq!(
            node_incoming.get(&GraphNodeId::Entity(e2)),
            Some(&vec![rid])
        );
    }

    /// Definitive "reuse, not recompute" proof: feed a persisted adjacency that
    /// is edge-count-consistent but maps the edge to DIFFERENT entities than the
    /// relations imply. A recompute would derive the correct mapping; reuse
    /// returns the persisted (deliberately divergent) mapping verbatim.
    #[test]
    fn adjacency_reuse_returns_persisted_not_recomputed() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let decoy_src = EntityId::new();
        let decoy_dst = EntityId::new();
        let rel = test_relation(e1, e2, RelationKind::Calls);
        let rid = rel.id;
        let mut relations: HashMap<RelationId, Relation> = HashMap::new();
        relations.insert(rid, rel);

        // Same edge COUNT (1 outgoing, 1 incoming) but mapped to decoy entities.
        let mut persisted_outgoing: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        persisted_outgoing.insert(decoy_src, vec![rid]);
        let mut persisted_incoming: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        persisted_incoming.insert(decoy_dst, vec![rid]);

        let (outgoing, incoming, _node_outgoing, _node_incoming, reuse) =
            build_relation_indexes_with_reuse(&relations, persisted_outgoing, persisted_incoming);

        assert_eq!(reuse, AdjacencyReuse::Reused);
        // Reused verbatim — the decoy mapping survives, proving no recompute ran.
        assert_eq!(outgoing.get(&decoy_src), Some(&vec![rid]));
        assert!(outgoing.get(&e1).is_none());
        assert_eq!(incoming.get(&decoy_dst), Some(&vec![rid]));
        assert!(incoming.get(&e2).is_none());
    }

    /// An empty persisted adjacency (e.g. an older snapshot that never wrote it)
    /// alongside real relations must be rebuilt, never trusted.
    #[test]
    fn adjacency_rebuild_when_persisted_empty() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let e3 = EntityId::new();
        let r1 = test_relation(e1, e2, RelationKind::Calls);
        let r2 = test_relation(e2, e3, RelationKind::Contains);
        let (rid1, rid2) = (r1.id, r2.id);
        let mut relations: HashMap<RelationId, Relation> = HashMap::new();
        relations.insert(rid1, r1);
        relations.insert(rid2, r2);

        let (outgoing, incoming, _node_outgoing, _node_incoming, reuse) =
            build_relation_indexes_with_reuse(&relations, HashMap::new(), HashMap::new());

        assert_eq!(reuse, AdjacencyReuse::Rebuilt);
        assert_eq!(outgoing.get(&e1), Some(&vec![rid1]));
        assert_eq!(outgoing.get(&e2), Some(&vec![rid2]));
        assert_eq!(incoming.get(&e2), Some(&vec![rid1]));
        assert_eq!(incoming.get(&e3), Some(&vec![rid2]));
    }

    /// A persisted adjacency whose edge tally disagrees with relations is
    /// inconsistent and must be rebuilt rather than reused.
    #[test]
    fn adjacency_rebuild_when_persisted_inconsistent() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let r1 = test_relation(e1, e2, RelationKind::Calls);
        let r2 = test_relation(e2, e1, RelationKind::Calls);
        let (rid1, rid2) = (r1.id, r2.id);
        let mut relations: HashMap<RelationId, Relation> = HashMap::new();
        relations.insert(rid1, r1);
        relations.insert(rid2, r2);

        // Persisted outgoing only records ONE of the two outgoing edges → tally
        // mismatch (1 != 2) forces a rebuild.
        let mut persisted_outgoing: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        persisted_outgoing.insert(e1, vec![rid1]);
        let mut persisted_incoming: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        persisted_incoming.insert(e2, vec![rid1]);
        persisted_incoming.insert(e1, vec![rid2]);

        let (outgoing, incoming, _node_outgoing, _node_incoming, reuse) =
            build_relation_indexes_with_reuse(&relations, persisted_outgoing, persisted_incoming);

        assert_eq!(reuse, AdjacencyReuse::Rebuilt);
        // Rebuilt correctly from relations: both edges present on both sides.
        assert_eq!(outgoing.get(&e1), Some(&vec![rid1]));
        assert_eq!(outgoing.get(&e2), Some(&vec![rid2]));
        assert_eq!(incoming.get(&e2), Some(&vec![rid1]));
        assert_eq!(incoming.get(&e1), Some(&vec![rid2]));
    }

    /// Empty relations + empty persisted adjacency is the trivial consistent
    /// case and counts as a (no-op) reuse.
    #[test]
    fn adjacency_reuse_when_graph_empty() {
        let relations: HashMap<RelationId, Relation> = HashMap::new();
        let (outgoing, incoming, node_outgoing, node_incoming, reuse) =
            build_relation_indexes_with_reuse(&relations, HashMap::new(), HashMap::new());
        assert_eq!(reuse, AdjacencyReuse::Reused);
        assert!(outgoing.is_empty());
        assert!(incoming.is_empty());
        assert!(node_outgoing.is_empty());
        assert!(node_incoming.is_empty());
    }

    /// End-to-end boot path: a snapshot carrying persisted adjacency loads into a
    /// graph whose neighbor queries match the relations (the reuse branch must
    /// produce a correct in-memory graph, not just a fast one).
    #[test]
    fn from_snapshot_with_persisted_adjacency_resolves_neighbors() {
        let e1 = test_entity("caller", "a.rs");
        let e2 = test_entity("callee", "b.rs");
        let rel = test_relation(e1.id, e2.id, RelationKind::Calls);
        let rid = rel.id;

        let mut snapshot = GraphSnapshot::empty();
        snapshot.entities.insert(e1.id, e1.clone());
        snapshot.entities.insert(e2.id, e2.clone());
        snapshot.relations.insert(rid, rel);
        // Persist a CONSISTENT entity-level adjacency so the reuse branch runs.
        snapshot.outgoing.insert(e1.id, vec![rid]);
        snapshot.incoming.insert(e2.id, vec![rid]);

        let graph = InMemoryGraph::from_snapshot(snapshot).unwrap();
        assert_eq!(graph.relation_count(), 1);
        // Reads the (reused) entity-level `outgoing` adjacency.
        let outgoing = graph.get_relations(&e1.id, &[]).unwrap();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].id, rid);
        assert_eq!(outgoing[0].dst, GraphNodeId::Entity(e2.id));
    }

    #[test]
    fn upsert_and_get_entity() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("foo", "src/main.rs");
        let id = entity.id;

        graph.upsert_entity(&entity).unwrap();
        let fetched = graph.get_entity(&id).unwrap().unwrap();
        assert_eq!(fetched.name, "foo");
        assert_eq!(graph.entity_count(), 1);
    }

    #[test]
    fn upsert_entity_overwrites() {
        let graph = InMemoryGraph::new();
        let mut entity = test_entity("foo", "src/main.rs");
        let id = entity.id;

        graph.upsert_entity(&entity).unwrap();
        entity.name = "bar".to_string();
        graph.upsert_entity(&entity).unwrap();

        let fetched = graph.get_entity(&id).unwrap().unwrap();
        assert_eq!(fetched.name, "bar");
        assert_eq!(graph.entity_count(), 1);
    }

    #[test]
    fn remove_entity_cleans_up() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("foo", "src/main.rs");
        let id = entity.id;

        graph.upsert_entity(&entity).unwrap();
        graph.remove_entity(&id).unwrap();

        assert!(graph.get_entity(&id).unwrap().is_none());
        assert_eq!(graph.entity_count(), 0);
    }

    #[test]
    fn remove_entity_cleans_up_relations_both_sides() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("caller", "a.rs");
        let e2 = test_entity("callee", "b.rs");
        let e3 = test_entity("other", "c.rs");

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();

        // e1 → e2 (outgoing from e1, incoming to e2)
        let rel1 = test_relation(e1.id, e2.id, RelationKind::Calls);
        // e3 → e2 (outgoing from e3, incoming to e2)
        let rel2 = test_relation(e3.id, e2.id, RelationKind::Calls);
        // e2 → e3 (outgoing from e2, incoming to e3)
        let rel3 = test_relation(e2.id, e3.id, RelationKind::Contains);

        graph.upsert_relation(&rel1).unwrap();
        graph.upsert_relation(&rel2).unwrap();
        graph.upsert_relation(&rel3).unwrap();

        assert_eq!(graph.relation_count(), 3);

        // Remove e2 — should clean up all 3 relations and both sides' edge vecs
        graph.remove_entity(&e2.id).unwrap();

        // e2 is gone
        assert!(graph.get_entity(&e2.id).unwrap().is_none());

        // All 3 relations should be removed from the relations map
        assert_eq!(
            graph.relation_count(),
            0,
            "all relations touching e2 should be removed"
        );

        // e1 should have no outgoing relations left (rel1 was e1→e2)
        let e1_rels = graph.get_relations(&e1.id, &[RelationKind::Calls]).unwrap();
        assert!(
            e1_rels.is_empty(),
            "e1 should have no outgoing calls after e2 removed"
        );

        // e3 should have no outgoing relations left (rel2 was e3→e2)
        let e3_out = graph.get_relations(&e3.id, &[RelationKind::Calls]).unwrap();
        assert!(
            e3_out.is_empty(),
            "e3 should have no outgoing calls after e2 removed"
        );

        // e3 should have no incoming relations left (rel3 was e2→e3)
        let e3_all = graph.get_all_relations_for_entity(&e3.id).unwrap();
        assert!(
            e3_all.is_empty(),
            "e3 should have no relations after e2 removed"
        );
    }

    #[test]
    fn upsert_and_get_relations() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("caller", "a.rs");
        let e2 = test_entity("callee", "b.rs");
        let rel = test_relation(e1.id, e2.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();

        // Outgoing from e1
        let rels = graph.get_relations(&e1.id, &[RelationKind::Calls]).unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].dst, GraphNodeId::Entity(e2.id));

        // All relations for e2 (incoming)
        let rels = graph.get_all_relations_for_entity(&e2.id).unwrap();
        assert_eq!(rels.len(), 1);
    }

    #[test]
    fn remove_relation() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("a", "a.rs");
        let e2 = test_entity("b", "b.rs");
        let rel = test_relation(e1.id, e2.id, RelationKind::Calls);
        let rid = rel.id;

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();
        graph.remove_relation(&rid).unwrap();

        assert!(graph.get_relations(&e1.id, &[]).unwrap().is_empty());
        assert_eq!(graph.relation_count(), 0);
    }

    #[test]
    fn merkle_root_stays_current_across_live_entity_relation_mutations() {
        fn assert_current(graph: &InMemoryGraph) {
            assert_eq!(
                graph.snapshot_root_hash(),
                Some(compute_graph_root_hash(&graph.to_snapshot())),
                "maintained live root must match cold recompute"
            );
        }

        let graph = InMemoryGraph::new();
        assert_current(&graph);

        let mut root = test_entity("root", "a.rs");
        let child = test_entity("child", "b.rs");
        let leaf = test_entity("leaf", "c.rs");
        graph.upsert_entity(&root).unwrap();
        graph.upsert_entity(&child).unwrap();
        graph.upsert_entity(&leaf).unwrap();
        assert_current(&graph);

        let root_to_child = test_relation(root.id, child.id, RelationKind::Calls);
        let child_to_leaf = test_relation(child.id, leaf.id, RelationKind::Calls);
        let leaf_to_root = test_relation(leaf.id, root.id, RelationKind::References);
        graph.upsert_relation(&root_to_child).unwrap();
        graph.upsert_relation(&child_to_leaf).unwrap();
        graph.upsert_relation(&leaf_to_root).unwrap();
        assert_current(&graph);

        root.name = "root_changed".to_string();
        root.signature = "fn root_changed()".to_string();
        graph.upsert_entity(&root).unwrap();
        assert_current(&graph);

        graph.remove_relation(&child_to_leaf.id).unwrap();
        assert_current(&graph);

        graph.remove_entity(&leaf.id).unwrap();
        assert_current(&graph);
    }

    #[test]
    fn relation_context_feeds_text_search() {
        let dir = tempfile::tempdir().unwrap();
        let graph = InMemoryGraph::with_text_index(dir.path().join("text-index"));
        let caller = test_entity("router", "src/router.rs");
        let callee = test_entity("parseExtensionRegistry", "src/extensions.rs");
        let mut rel = test_relation(caller.id, callee.id, RelationKind::Calls);
        rel.import_source = Some("pkg.extensions.registry".into());

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_relation(&rel).unwrap();
        graph.flush_text_index().unwrap();

        let import_hits = graph.text_search("extensions registry", 10).unwrap();
        assert!(
            import_hits
                .iter()
                .any(|(key, _)| *key == RetrievalKey::from(caller.id)),
            "caller should become searchable by import-source context"
        );

        let neighbor_hits = graph.text_search("parseExtensionRegistry", 10).unwrap();
        assert!(
            neighbor_hits
                .iter()
                .any(|(key, _)| *key == RetrievalKey::from(caller.id)),
            "caller should become searchable by direct graph neighbor names"
        );
    }

    #[test]
    fn removing_relation_retracts_relation_context_from_text_search() {
        let dir = tempfile::tempdir().unwrap();
        let graph = InMemoryGraph::with_text_index(dir.path().join("text-index"));
        let caller = test_entity("router", "src/router.rs");
        let callee = test_entity("handler", "src/handler.rs");
        let mut rel = test_relation(caller.id, callee.id, RelationKind::Calls);
        rel.import_source = Some("acme.internal.registry".into());
        let rel_id = rel.id;

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_relation(&rel).unwrap();
        graph.flush_text_index().unwrap();
        assert!(
            !graph
                .text_search("internal registry", 10)
                .unwrap()
                .is_empty(),
            "relation context should be searchable before removal"
        );

        graph.remove_relation(&rel_id).unwrap();
        graph.flush_text_index().unwrap();
        assert!(
            graph
                .text_search("internal registry", 10)
                .unwrap()
                .is_empty(),
            "relation context should disappear after removal"
        );
    }

    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn embedding_context_includes_relation_labels_and_import_sources() {
        let graph = InMemoryGraph::new();
        let caller = test_entity("router", "src/router.rs");
        let callee = test_entity("parseExtensionRegistry", "src/extensions.rs");
        let owner = test_entity("ExtensionManager", "src/manager.rs");

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_entity(&owner).unwrap();

        let mut calls = test_relation(caller.id, callee.id, RelationKind::Calls);
        calls.import_source = Some("pkg.extensions.registry".into());
        let owned_by = test_relation(caller.id, owner.id, RelationKind::OwnedBy);

        graph.upsert_relation(&calls).unwrap();
        graph.upsert_relation(&owned_by).unwrap();

        let context = {
            let ent = graph.entities.read();
            collect_embedding_context_lines(&ent, &caller.id)
        };

        assert!(
            context
                .iter()
                .any(|line| line == "calls: parseExtensionRegistry"),
            "outgoing relation labels should be preserved in embedding text"
        );
        assert!(
            context
                .iter()
                .any(|line| line == "owned_by: ExtensionManager"),
            "graph neighborhood names should be preserved in embedding text"
        );
        assert!(
            context
                .iter()
                .any(|line| line == "import_source: pkg.extensions.registry"),
            "import provenance should be preserved in embedding text"
        );
    }

    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn embedding_context_includes_cochange_relation_labels() {
        let graph = InMemoryGraph::new();
        let caller = test_entity("router", "src/router.rs");
        let peer = test_entity("registry", "src/registry.rs");

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&peer).unwrap();

        let cochange = test_relation(caller.id, peer.id, RelationKind::CoChanges);
        graph.upsert_relation(&cochange).unwrap();

        let context = {
            let ent = graph.entities.read();
            collect_embedding_context_lines(&ent, &caller.id)
        };

        assert!(
            context.iter().any(|line| line == "co_changes: registry"),
            "co-change labels should be preserved in embedding text"
        );
    }

    /// An unpopulated vector index is a valid graph state (`kin init` only
    /// queues embeddings), so semantic search degrades to an empty result and
    /// lets callers fall back to text search. Crucially it must NOT load the
    /// embedder — if it did, this test would attempt a model download. A fast,
    /// network-free `Ok(empty)` proves the degrade path avoids the fail-fast
    /// that made `kin search --semantic` error 100% of the time on a fresh repo.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn semantic_search_on_unpopulated_index_degrades_to_empty() {
        let graph = InMemoryGraph::new();
        graph
            .upsert_entity(&test_entity("router", "src/router.rs"))
            .unwrap();

        let results = graph
            .semantic_search("anything", 10)
            .expect("unpopulated semantic search must degrade, not error");
        assert!(
            results.is_empty(),
            "unpopulated index should yield no semantic hits"
        );

        let batch = graph
            .semantic_search_batch(&["a", "b"], 10)
            .expect("unpopulated batch semantic search must degrade, not error");
        assert_eq!(
            batch.len(),
            2,
            "batch search must return one (empty) result per query"
        );
        assert!(batch.iter().all(|hits| hits.is_empty()));
    }

    #[test]
    fn query_by_kind() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("func1", "a.rs");
        let mut e2 = test_entity("MyClass", "b.rs");
        e2.kind = EntityKind::Class;

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let filter = EntityFilter {
            kinds: Some(vec![EntityKind::Function]),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "func1");
    }

    #[test]
    fn query_by_name_pattern() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("getUser", "a.rs");
        let e2 = test_entity("getPost", "a.rs");
        let e3 = test_entity("deleteUser", "a.rs");

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();

        let filter = EntityFilter {
            name_pattern: Some("get*".to_string()),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn snapshot_restore_rebuilds_text_index() {
        let dir = tempfile::tempdir().unwrap();
        let mut snapshot = GraphSnapshot::empty();
        let mut entity = test_entity("parseExtensionRegistry", "src/extensions.rs");
        entity.doc_summary = Some("Parses the extension registry configuration".into());
        let entity_id = entity.id;
        snapshot.entities.insert(entity.id, entity);
        let artifact = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([9; 32]),
            text_preview: Some("build install".into()),
        };
        let artifact_file_id = artifact.file_id.clone();
        snapshot.structured_artifacts.push(artifact);
        let artifact_id = ArtifactId::new();
        snapshot.resolved_tree = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            artifact_id,
            test_repo_path(&artifact_file_id.0),
            TreeEntry::blob(Hash256::from_bytes([9; 32]), false),
        )])
        .unwrap();

        let graph =
            InMemoryGraph::from_snapshot_with_text_index(snapshot, dir.path().join("text-index"))
                .unwrap();

        // Current snapshots carry graph-assigned artifact identity explicitly;
        // restore consumes it without deriving identity from the path.
        assert_eq!(
            graph.artifact_id_at_path(&test_repo_path(&artifact_file_id.0)),
            Some(artifact_id)
        );
        let artifact_key = RetrievalKey::Artifact(artifact_id);

        let hits = graph.text_search("extension registry", 10).unwrap();
        assert!(
            hits.iter()
                .any(|(key, _)| *key == RetrievalKey::from(entity_id)),
            "snapshot restore should make entities immediately searchable"
        );

        let artifact_hits = graph.text_search("build install", 10).unwrap();
        assert!(
            artifact_hits.iter().any(|(key, _)| *key == artifact_key),
            "snapshot restore should rebuild artifact text documents too"
        );
    }

    #[test]
    fn text_search_and_resolution_support_artifact_keys() {
        let dir = tempfile::tempdir().unwrap();
        let graph = InMemoryGraph::with_text_index(dir.path().join("text-index"));
        let artifact = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([9; 32]),
            text_preview: Some("build install".into()),
        };
        admit_enrichment(&graph, &artifact.file_id, artifact.content_hash);
        graph.upsert_structured_artifact(&artifact).unwrap();
        graph.flush_text_index().unwrap();

        // Read back the identity assigned by explicit tree admission.
        let artifact_key = RetrievalKey::Artifact(
            graph
                .artifact_id_at_path(&test_repo_path(&artifact.file_id.0))
                .expect("admitted artifact must have a graph-owned id"),
        );

        let hits = graph.text_search("build install", 10).unwrap();
        assert!(hits.iter().any(|(key, _)| *key == artifact_key));

        let resolved = graph.resolve_retrieval_key(&artifact_key).unwrap();
        match resolved {
            ResolvedRetrievalItem::StructuredArtifact(found) => {
                assert_eq!(found.file_id.0, "Makefile");
            }
            other => panic!("expected structured artifact, got {other:?}"),
        }

        assert_eq!(
            graph.file_path_for_retrieval_key(artifact_key),
            Some(FilePathId::new("Makefile"))
        );
    }

    #[test]
    fn deleting_artifact_removes_text_search_hit() {
        let dir = tempfile::tempdir().unwrap();
        let graph = InMemoryGraph::with_text_index(dir.path().join("text-index"));
        let artifact = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([7; 32]),
            text_preview: Some("build clean".into()),
        };
        admit_enrichment(&graph, &artifact.file_id, artifact.content_hash);
        graph.upsert_structured_artifact(&artifact).unwrap();
        graph.flush_text_index().unwrap();

        // Capture the explicitly admitted identity before enrichment deletion.
        let artifact_key = RetrievalKey::Artifact(
            graph
                .artifact_id_at_path(&test_repo_path(&artifact.file_id.0))
                .expect("admitted artifact must have a graph-owned id"),
        );
        assert!(graph
            .text_search("build clean", 10)
            .unwrap()
            .iter()
            .any(|(key, _)| *key == artifact_key));

        graph.delete_structured_artifact(&artifact.file_id).unwrap();
        graph.flush_text_index().unwrap();

        assert!(!graph
            .text_search("build clean", 10)
            .unwrap()
            .iter()
            .any(|(key, _)| *key == artifact_key));
    }

    #[test]
    fn query_by_file() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("a", "src/main.rs");
        let e2 = test_entity("b", "src/lib.rs");

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let filter = EntityFilter {
            file_path: Some(FilePathId::new("src/main.rs")),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "a");
    }

    #[test]
    fn mixed_language_query_and_coverage_remain_truthful() {
        let graph = InMemoryGraph::new();
        let rust_entity = test_entity("compileRust", "src/lib.rs");
        let mut ts_entity = test_entity("renderTs", "web/app.ts");
        let mut py_entity = test_entity("trainPy", "tools/train.py");

        ts_entity.language = LanguageId::TypeScript;
        py_entity.language = LanguageId::Python;

        graph.upsert_entity(&rust_entity).unwrap();
        graph.upsert_entity(&ts_entity).unwrap();
        graph.upsert_entity(&py_entity).unwrap();

        let filter = EntityFilter {
            languages: Some(vec![LanguageId::Rust, LanguageId::TypeScript]),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        let names: std::collections::HashSet<_> =
            results.iter().map(|entity| entity.name.as_str()).collect();

        assert_eq!(results.len(), 2);
        assert!(names.contains("compileRust"));
        assert!(names.contains("renderTs"));
        assert!(!names.contains("trainPy"));

        let test_case = TestCase {
            test_id: TestId::new(),
            name: "test_render_ts".into(),
            language: "typescript".into(),
            kind: TestKind::Unit,
            scopes: vec![],
            runner: TestRunner::Jest,
            file_origin: Some(FilePathId::new("web/app.test.ts")),
        };

        graph.create_test_case(&test_case).unwrap();
        graph
            .create_test_covers_entity(&test_case.test_id, &ts_entity.id)
            .unwrap();

        let summary = graph.get_coverage_summary().unwrap();
        assert_eq!(summary.total_entities, 3);
        assert_eq!(summary.covered_entities, 1);
    }

    #[test]
    fn downstream_impact() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("core_fn", "a.rs");
        let e2 = test_entity("caller", "b.rs");
        let rel = test_relation(e2.id, e1.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();

        let impact = graph.get_downstream_impact(&e1.id, 10).unwrap();
        assert_eq!(impact.len(), 1);
        assert_eq!(impact[0].id, e2.id);
    }

    #[test]
    fn dependency_neighborhood() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("a", "a.rs");
        let e2 = test_entity("b", "b.rs");
        let e3 = test_entity("c", "c.rs");
        let r1 = test_relation(e1.id, e2.id, RelationKind::Calls);
        let r2 = test_relation(e2.id, e3.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();
        graph.upsert_relation(&r1).unwrap();
        graph.upsert_relation(&r2).unwrap();

        let sg = graph.get_dependency_neighborhood(&e1.id, 2).unwrap();
        assert_eq!(sg.entities.len(), 3);
        assert_eq!(sg.relations.len(), 2);
    }

    #[test]
    fn expand_neighborhood_filters_edge_kinds_bidirectionally() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("caller", "a.rs");
        let e2 = test_entity("anchor", "b.rs");
        let e3 = test_entity("importer", "c.rs");
        let e4 = test_entity("peer", "d.rs");
        let calls = test_relation(e1.id, e2.id, RelationKind::Calls);
        let imports = test_relation(e3.id, e2.id, RelationKind::Imports);
        let cochange = test_relation(e2.id, e4.id, RelationKind::CoChanges);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();
        graph.upsert_entity(&e4).unwrap();
        graph.upsert_relation(&calls).unwrap();
        graph.upsert_relation(&imports).unwrap();
        graph.upsert_relation(&cochange).unwrap();

        let sg = graph
            .expand_neighborhood(&[e2.id], &[RelationKind::Calls, RelationKind::CoChanges], 1)
            .unwrap();

        assert_eq!(sg.entities.len(), 3);
        assert!(sg.entities.contains_key(&e1.id));
        assert!(sg.entities.contains_key(&e2.id));
        assert!(sg.entities.contains_key(&e4.id));
        assert!(!sg.entities.contains_key(&e3.id));
        assert_eq!(sg.relations.len(), 2);
        assert!(sg.relations.iter().any(|rel| rel.id == calls.id));
        assert!(sg.relations.iter().any(|rel| rel.id == cochange.id));
        assert!(!sg.relations.iter().any(|rel| rel.id == imports.id));
    }

    #[test]
    fn dead_code_detection() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("used", "a.rs");
        let e2 = test_entity("unused", "b.rs");
        let e3 = test_entity("caller", "c.rs");
        let rel = test_relation(e3.id, e1.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();
        graph.upsert_relation(&rel).unwrap();

        let dead = graph.find_dead_code().unwrap();
        let dead_names: Vec<&str> = dead.iter().map(|e| e.name.as_str()).collect();
        assert!(dead_names.contains(&"unused"));
        assert!(dead_names.contains(&"caller"));
        assert!(!dead_names.contains(&"used"));
    }

    #[test]
    fn has_incoming_relation_kinds() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("target", "a.rs");
        let e2 = test_entity("caller", "b.rs");
        let rel = test_relation(e2.id, e1.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();

        assert!(graph
            .has_incoming_relation_kinds(&e1.id, &[RelationKind::Calls], false)
            .unwrap());
        assert!(!graph
            .has_incoming_relation_kinds(&e1.id, &[RelationKind::Imports], false)
            .unwrap());
    }

    #[test]
    fn change_dag_operations() {
        let graph = InMemoryGraph::new();

        let genesis = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([1; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "genesis".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });
        let genesis_id = genesis.id;
        graph.create_change(&genesis).unwrap();

        let child = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([2; 32])),
            parents: vec![genesis_id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "child".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });
        let child_id = child.id;
        graph.create_change(&child).unwrap();

        let fetched = graph.get_change(&child_id).unwrap().unwrap();
        assert_eq!(fetched.message, "child");

        let since = graph.get_changes_since(&genesis_id, &child_id).unwrap();
        assert_eq!(since.len(), 1);
        assert_eq!(since[0].message, "child");
    }

    #[test]
    fn create_change_is_idempotent_only_for_identical_payload() {
        let graph = InMemoryGraph::new();
        let parent = SemanticChangeId::from_hash(Hash256::from_bytes([0x31; 32]));
        let change = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x32; 32])),
            parents: vec![parent],
            timestamp: Timestamp::now(),
            author: AuthorId::new("agent"),
            message: "immutable payload".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });

        graph.create_change(&change).unwrap();
        graph
            .create_change(&change)
            .expect("identical retry is idempotent");
        let snapshot = graph.to_snapshot();
        assert_eq!(snapshot.changes.len(), 1);
        assert_eq!(
            snapshot.change_children.get(&parent),
            Some(&vec![change.id])
        );

        let mut conflicting = change.clone();
        conflicting.message = "different payload".to_string();
        let error = graph
            .create_change(&conflicting)
            .expect_err("same id with different payload must be rejected");
        assert!(matches!(error, KinDbError::Model(_)));
        assert_eq!(
            graph.get_change(&change.id).unwrap().unwrap().message,
            "immutable payload"
        );
        assert_eq!(
            graph.to_snapshot().change_children.get(&parent),
            Some(&vec![change.id])
        );
    }

    #[test]
    fn create_change_immutable_float_comparison_preserves_ieee_bits() {
        let graph = InMemoryGraph::new();
        let mut entity = test_entity("float_identity", "src/lib.rs");
        entity.fingerprint.stability_score = 0.0;
        let change = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x3d; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("agent"),
            message: "exact float payload".to_string(),
            entity_deltas: vec![EntityDelta::Added { new: entity }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });
        graph.create_change(&change).unwrap();

        let mut conflicting = change.clone();
        let EntityDelta::Added { new: entity } = &mut conflicting.entity_deltas[0] else {
            unreachable!("fixture contains one added entity")
        };
        entity.fingerprint.stability_score = -0.0;
        let error = graph
            .create_change(&conflicting)
            .expect_err("different IEEE-754 payload bits must not be idempotent");
        assert!(matches!(error, KinDbError::Model(_)));

        let stored = graph.get_change(&change.id).unwrap().unwrap();
        let EntityDelta::Added { new: entity } = &stored.entity_deltas[0] else {
            unreachable!("stored fixture contains one added entity")
        };
        assert_eq!(
            entity.fingerprint.stability_score.to_bits(),
            0.0f32.to_bits()
        );
    }

    #[test]
    fn create_change_rejects_non_finite_float_before_mutation() {
        let graph = InMemoryGraph::new();
        let mut entity = test_entity("non_finite", "src/lib.rs");
        entity.fingerprint.stability_score = f32::NAN;
        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x3e; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("agent"),
            message: "invalid float payload".to_string(),
            entity_deltas: vec![EntityDelta::Added { new: entity }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let error = graph
            .create_change(&change)
            .expect_err("non-finite immutable payloads must fail closed");
        assert!(error.to_string().contains("non-finite"));
        assert!(graph.to_snapshot().changes.is_empty());
        assert!(!graph.has_pending_delta());
    }

    #[test]
    fn create_change_rejects_spoofed_id_before_any_mutation() {
        let graph = InMemoryGraph::new();
        let spoofed = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x40; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("agent"),
            message: "spoofed".to_string(),
            entity_deltas: vec![EntityDelta::Added {
                new: test_entity("must_not_land", "src/lib.rs"),
            }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let error = graph
            .create_change(&spoofed)
            .expect_err("spoofed identity must fail closed");
        assert!(error.to_string().contains("recomputes to"));
        assert_no_change_admission(&graph);
    }

    #[test]
    fn public_snapshot_hydration_rejects_spoofed_change_identity() {
        let spoofed = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0xee; 32])),
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("attacker"),
            message: "spoofed hydration".into(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };
        let mut snapshot = GraphSnapshot::empty();
        snapshot.changes.insert(spoofed.id, spoofed);

        let error = InMemoryGraph::from_snapshot(snapshot)
            .expect_err("public hydration must validate immutable change identity");
        assert!(error.to_string().contains("semantic change"));
    }

    #[test]
    fn borrowed_snapshot_save_rejects_spoofed_change_identity() {
        let graph = InMemoryGraph::new();
        let spoofed = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0xed; 32])),
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("attacker"),
            message: "spoofed borrowed save".into(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };
        graph.changes.write().changes.insert(spoofed.id, spoofed);

        let error = graph
            .serialize_snapshot_borrowed()
            .expect_err("borrowed persistence must validate immutable change identity");
        assert!(error.to_string().contains("semantic change"));
    }

    #[test]
    fn create_change_cannot_be_detached_between_revision_children_and_change() {
        use std::sync::mpsc;
        use std::time::Duration;

        let graph = std::sync::Arc::new(InMemoryGraph::new());
        let parent = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("tester"),
            message: "parent".into(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });
        graph.create_change(&parent).unwrap();
        graph.clear_pending_delta();

        let entity = test_entity("atomic_change", "src/atomic.rs");
        let child = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            parents: vec![parent.id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("tester"),
            message: "child".into(),
            entity_deltas: vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            projected_files: vec![entity.file_origin.clone().unwrap()],
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });

        let (at_revision_tx, at_revision_rx) = mpsc::channel();
        let (continue_tx, continue_rx) = mpsc::channel();
        let creator_graph = graph.clone();
        let creator_change = child.clone();
        let creator = std::thread::spawn(move || {
            set_create_change_after_revision_hook(move || {
                at_revision_tx.send(()).unwrap();
                continue_rx.recv().unwrap();
            });
            creator_graph.create_change(&creator_change)
        });

        at_revision_rx.recv().unwrap();
        assert!(
            graph.pending_delta.try_lock().is_none(),
            "the pending-delta fence must already be held when revisions mutate"
        );

        let (detach_started_tx, detach_started_rx) = mpsc::channel();
        let (detached_tx, detached_rx) = mpsc::channel();
        let detach_graph = graph.clone();
        let detacher = std::thread::spawn(move || {
            detach_started_tx.send(()).unwrap();
            detached_tx
                .send(detach_graph.begin_delta_persistence(0))
                .unwrap();
        });
        detach_started_rx.recv().unwrap();
        assert!(
            detached_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "persistence detach must wait for the complete change batch"
        );

        continue_tx.send(()).unwrap();
        creator.join().unwrap().unwrap();
        let (delta, epoch) = detached_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .expect("the complete change batch must detach");
        detacher.join().unwrap();

        let has_change = delta
            .changes
            .added
            .iter()
            .chain(delta.changes.modified.iter())
            .any(|(id, value)| *id == child.id && value.id == child.id);
        let has_revisions = delta
            .entity_revisions
            .added
            .iter()
            .chain(delta.entity_revisions.modified.iter())
            .any(|(id, revisions)| *id == entity.id && !revisions.is_empty());
        let has_child_edge = delta
            .change_children
            .added
            .iter()
            .chain(delta.change_children.modified.iter())
            .any(|(id, children)| *id == parent.id && children.contains(&child.id));
        assert!(has_change && has_revisions && has_child_edge);
        assert!(graph.complete_persistence(epoch));
    }

    #[test]
    fn create_change_rejects_identical_spoofed_reinsertion() {
        let graph = InMemoryGraph::new();
        let spoofed = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x40; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("agent"),
            message: "same invalid retry".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        for _ in 0..2 {
            let error = graph
                .create_change(&spoofed)
                .expect_err("an identical spoofed retry is never idempotent");
            assert!(error.to_string().contains("recomputes to"));
        }
        assert_no_change_admission(&graph);
    }

    #[test]
    fn create_changes_rejects_later_spoof_before_any_mutation() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("must_not_land", "src/lib.rs");
        let first = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x41; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("agent"),
            message: "first".to_string(),
            entity_deltas: vec![EntityDelta::Added { new: entity }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });
        let mut spoofed = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x42; 32])),
            parents: vec![first.id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("agent"),
            message: "later spoof".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });
        spoofed.id = SemanticChangeId::from_hash(Hash256::from_bytes([0xff; 32]));
        let error = graph
            .create_changes(vec![first, spoofed])
            .expect_err("a spoofed later item must reject the whole batch");
        assert!(error.to_string().contains("recomputes to"));
        let snapshot = graph.to_snapshot();
        assert!(snapshot.changes.is_empty());
        assert!(snapshot.entity_revisions.is_empty());
        assert!(snapshot.change_children.is_empty());
        assert!(snapshot.resolved_tree.is_empty());
        assert!(!graph.has_pending_delta());
    }

    #[test]
    fn create_changes_float_conflict_rejects_the_whole_batch() {
        let graph = InMemoryGraph::new();
        let mut entity = test_entity("batch_float_identity", "src/lib.rs");
        entity.fingerprint.stability_score = 0.0;
        let first = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x42; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("agent"),
            message: "batch exact float payload".to_string(),
            entity_deltas: vec![EntityDelta::Added { new: entity }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });
        let mut conflicting = first.clone();
        let EntityDelta::Added { new: entity } = &mut conflicting.entity_deltas[0] else {
            unreachable!("fixture contains one added entity")
        };
        entity.fingerprint.stability_score = -0.0;

        let error = graph
            .create_changes(vec![first, conflicting])
            .expect_err("bit-distinct floats under one ID must reject the whole batch");
        assert!(matches!(error, KinDbError::Model(_)));
        let snapshot = graph.to_snapshot();
        assert!(snapshot.changes.is_empty());
        assert!(snapshot.entity_revisions.is_empty());
        assert!(!graph.has_pending_delta());
    }

    #[test]
    fn create_changes_non_finite_payload_rejects_prior_valid_entries_atomically() {
        let graph = InMemoryGraph::new();
        let valid = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x43; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("agent"),
            message: "valid first entry".to_string(),
            entity_deltas: vec![EntityDelta::Added {
                new: test_entity("valid", "src/valid.rs"),
            }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });
        let source = test_entity("source", "src/source.rs");
        let target = test_entity("target", "src/target.rs");
        let mut relation = test_relation(source.id, target.id, RelationKind::Calls);
        relation.confidence = f32::INFINITY;
        let invalid = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x44; 32])),
            parents: vec![valid.id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("agent"),
            message: "invalid later entry".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![RelationDelta::Added { new: relation }],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let error = graph
            .create_changes(vec![valid, invalid])
            .expect_err("a later non-finite payload must reject the batch before mutation");
        assert!(error.to_string().contains("non-finite relation confidence"));
        let snapshot = graph.to_snapshot();
        assert!(snapshot.changes.is_empty());
        assert!(snapshot.entity_revisions.is_empty());
        assert!(!graph.has_pending_delta());
    }

    #[test]
    fn create_changes_batch_matches_sequential_state_and_delta_bytes() {
        let sequential = InMemoryGraph::new();
        let batched = InMemoryGraph::new();

        let original = test_entity("target", "src/lib.rs");
        let mut modified = original.clone();
        modified.signature = "fn target(value: usize)".to_string();
        modified.fingerprint.signature_hash = Hash256::from_bytes([0x44; 32]);

        let timestamp = Timestamp::now();
        let genesis = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x11; 32])),
            parents: vec![],
            timestamp: timestamp.clone(),
            author: AuthorId::new("test"),
            message: "genesis".to_string(),
            entity_deltas: vec![EntityDelta::Added {
                new: original.clone(),
            }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });
        let genesis_id = genesis.id;
        let first_child = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x22; 32])),
            parents: vec![genesis_id],
            timestamp: timestamp.clone(),
            author: AuthorId::new("test"),
            message: "modify target".to_string(),
            entity_deltas: vec![EntityDelta::Modified {
                old: original.clone(),
                new: modified,
            }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });
        let first_child_id = first_child.id;
        let second_child = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x33; 32])),
            parents: vec![genesis_id],
            timestamp,
            author: AuthorId::new("test"),
            message: "sibling".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });
        let second_child_id = second_child.id;
        let changes = vec![genesis, first_child, second_child];

        for change in &changes {
            sequential.create_change(change).unwrap();
        }
        batched.create_changes(changes).unwrap();

        let sequential_snapshot = sequential.to_snapshot();
        let batched_snapshot = batched.to_snapshot();
        assert_eq!(
            compute_graph_root_hash(&sequential_snapshot),
            compute_graph_root_hash(&batched_snapshot),
            "batch registration must preserve the canonical graph root"
        );
        assert_eq!(
            sequential_snapshot.change_children.get(&genesis_id),
            Some(&vec![first_child_id, second_child_id]),
        );
        assert_eq!(
            batched_snapshot.change_children.get(&genesis_id),
            sequential_snapshot.change_children.get(&genesis_id),
            "parent-child registration must preserve input order"
        );
        assert_eq!(
            batched_snapshot
                .entity_revisions
                .get(&original.id)
                .map(Vec::len),
            Some(2),
            "batch registration must retain the complete revision lineage"
        );

        let sequential_delta = sequential.pending_delta_snapshot(0).unwrap();
        let batched_delta = batched.pending_delta_snapshot(0).unwrap();
        assert_eq!(
            sequential_delta.to_bytes().unwrap(),
            batched_delta.to_bytes().unwrap(),
            "batch and sequential writes must emit byte-identical snapshot deltas"
        );
    }

    #[test]
    fn delta_persistence_detaches_later_mutations_from_acknowledgement() {
        let graph = InMemoryGraph::new();
        let first = test_entity("first", "src/first.rs");
        let second = test_entity("second", "src/second.rs");
        assert!(!graph.has_unpersisted_changes());
        graph.upsert_entity(&first).unwrap();
        assert!(graph.has_unpersisted_changes());

        let (persisting, epoch) = graph
            .begin_delta_persistence(1)
            .expect("first mutation is pending");
        assert!(graph.has_unpersisted_changes());
        assert!(persisting
            .entities
            .modified
            .iter()
            .any(|(id, _)| id == &first.id));

        graph.upsert_entity(&second).unwrap();
        assert!(graph.complete_persistence(epoch));
        assert!(graph.has_unpersisted_changes());

        let next = graph
            .pending_delta_snapshot(2)
            .expect("later mutation remains pending");
        assert!(!next.entities.modified.iter().any(|(id, _)| id == &first.id));
        assert!(next
            .entities
            .modified
            .iter()
            .any(|(id, _)| id == &second.id));
    }

    #[test]
    fn full_snapshot_persistence_detaches_later_mutations() {
        let graph = InMemoryGraph::new();
        let first = test_entity("first", "src/first.rs");
        let second = test_entity("second", "src/second.rs");
        graph.upsert_entity(&first).unwrap();

        let (_bytes, _root, epoch) = graph.begin_snapshot_persistence(None).unwrap();
        graph.upsert_entity(&second).unwrap();
        assert!(graph.complete_persistence(epoch));

        let next = graph
            .pending_delta_snapshot(2)
            .expect("mutation after full snapshot capture remains pending");
        assert_eq!(next.entities.modified.len(), 1);
        assert_eq!(next.entities.modified[0].0, second.id);
    }

    #[test]
    fn acknowledged_persistence_is_clean_when_no_later_mutation_exists() {
        let graph = InMemoryGraph::new();
        graph
            .upsert_entity(&test_entity("only", "src/only.rs"))
            .unwrap();
        let (_delta, epoch) = graph.begin_delta_persistence(1).unwrap();
        assert!(graph.has_unpersisted_changes());
        assert!(graph.complete_persistence(epoch));
        assert!(!graph.has_unpersisted_changes());
    }

    #[test]
    fn failed_persistence_forces_full_retry_without_clearing_later_mutations() {
        let graph = InMemoryGraph::new();
        let first = test_entity("first", "src/first.rs");
        let second = test_entity("second", "src/second.rs");
        graph.upsert_entity(&first).unwrap();
        let (_persisting, epoch) = graph.begin_delta_persistence(1).unwrap();
        graph.upsert_entity(&second).unwrap();

        assert!(graph.fail_persistence(epoch));
        assert!(graph.full_snapshot_required());
        let later = graph.pending_delta_snapshot(1).unwrap();
        assert_eq!(later.entities.modified.len(), 1);
        assert_eq!(later.entities.modified[0].0, second.id);
    }

    #[test]
    fn create_changes_remove_before_add_matches_sequential_delta_bytes() {
        let sequential = InMemoryGraph::new();
        let batched = InMemoryGraph::new();
        let removed_then_added = test_entity("late", "src/late.rs");
        let other = test_entity("other", "src/other.rs");
        let timestamp = Timestamp::now();
        let make_change = |id_byte: u8, message: &str, entity_deltas: Vec<EntityDelta>| {
            seal_change(SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([id_byte; 32])),
                parents: vec![],
                timestamp: timestamp.clone(),
                author: AuthorId::new("test"),
                message: message.to_string(),
                entity_deltas,
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
        };
        let changes = vec![
            make_change(
                0x41,
                "remove before history is available",
                vec![EntityDelta::Removed {
                    old: removed_then_added.clone(),
                }],
            ),
            make_change(
                0x42,
                "add another entity first",
                vec![EntityDelta::Added { new: other }],
            ),
            make_change(
                0x43,
                "add the previously removed entity",
                vec![EntityDelta::Added {
                    new: removed_then_added,
                }],
            ),
        ];

        for change in &changes {
            sequential.create_change(change).unwrap();
        }
        batched.create_changes(changes).unwrap();

        assert_eq!(
            sequential
                .pending_delta_snapshot(0)
                .unwrap()
                .to_bytes()
                .unwrap(),
            batched
                .pending_delta_snapshot(0)
                .unwrap()
                .to_bytes()
                .unwrap(),
            "batch registration must preserve sequential delta slot order even when a removal precedes an add"
        );
    }

    #[test]
    fn delta_map_upsert_batch_preserves_sequential_slots_and_removals() {
        let base = CollectionDelta {
            added: vec![(1u64, 10u64)],
            modified: vec![(2, 20)],
            removed: vec![3, 4],
        };
        let updates = vec![(2, 21), (1, 11), (3, 30), (5, 50), (5, 51)];
        let mut sequential = base.clone();
        let mut batched = base;

        for (key, value) in &updates {
            delta_map_upsert(&mut sequential, *key, *value);
        }
        delta_map_upsert_batch(&mut batched, updates);

        assert_eq!(
            rmp_serde::to_vec(&sequential).unwrap(),
            rmp_serde::to_vec(&batched).unwrap(),
            "indexed upserts must preserve added/modified slot precedence and stable removal order"
        );
    }

    #[test]
    fn delta_map_upsert_batch_uses_linear_key_comparisons() {
        #[derive(Clone)]
        struct CountingKey {
            value: usize,
            comparisons: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        }

        impl PartialEq for CountingKey {
            fn eq(&self, other: &Self) -> bool {
                self.comparisons
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.value == other.value
            }
        }

        impl Eq for CountingKey {}

        impl std::hash::Hash for CountingKey {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                std::hash::Hash::hash(&self.value, state);
            }
        }

        let count = 2_048usize;
        let comparisons = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let key = |value| CountingKey {
            value,
            comparisons: std::sync::Arc::clone(&comparisons),
        };
        let mut delta = CollectionDelta::<CountingKey, usize>::default();
        delta.modified = (0..count).map(|value| (key(value), value)).collect();
        let updates = (0..count)
            .map(|value| (key(value), value + count))
            .collect();

        comparisons.store(0, std::sync::atomic::Ordering::Relaxed);
        delta_map_upsert_batch(&mut delta, updates);
        let observed = comparisons.load(std::sync::atomic::Ordering::Relaxed);

        assert!(
            observed < count * 32,
            "indexed batch upsert must stay linear-ish; observed {observed} key comparisons for {count} updates"
        );
        assert!(
            delta
                .modified
                .iter()
                .all(|(key, value)| *value == key.value + count),
            "every existing slot must be updated in place"
        );
    }

    #[test]
    fn create_changes_empty_batch_is_a_noop() {
        let graph = InMemoryGraph::new();
        graph.create_changes(Vec::new()).unwrap();
        assert!(!graph.has_pending_delta());
        assert!(graph.to_snapshot().changes.is_empty());
    }

    #[test]
    fn resolve_entity_at_replays_entity_deltas_for_target_head() {
        let graph = InMemoryGraph::new();

        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x11; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let entity_v1 = test_entity("foo", "src/lib.rs");
        let add_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x22; 32])),
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add foo".to_string(),
                entity_deltas: vec![EntityDelta::Added {
                    new: entity_v1.clone(),
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let mut entity_v2 = entity_v1.clone();
        entity_v2.signature = "fn foo(value: i32)".to_string();
        entity_v2.fingerprint.signature_hash = Hash256::from_bytes([0x33; 32]);

        let modify_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x33; 32])),
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify foo".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity_v1.clone(),
                    new: entity_v2.clone(),
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let at_add = graph
            .resolve_entity_at(&entity_v1.id, &add_id)
            .unwrap()
            .unwrap();
        assert_eq!(at_add.signature, entity_v1.signature);

        let at_modify = graph
            .resolve_entity_at(&entity_v1.id, &modify_id)
            .unwrap()
            .unwrap();
        assert_eq!(at_modify.signature, entity_v2.signature);
    }

    #[test]
    fn get_entity_revisions_at_tracks_revision_lineage_for_target_head() {
        let graph = InMemoryGraph::new();

        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x34; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let entity_v1 = test_entity("foo", "src/lib.rs");
        let add_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x35; 32])),
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add foo".to_string(),
                entity_deltas: vec![EntityDelta::Added {
                    new: entity_v1.clone(),
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let mut entity_v2 = entity_v1.clone();
        entity_v2.signature = "fn foo(value: i32)".to_string();
        entity_v2.fingerprint.signature_hash = Hash256::from_bytes([0x36; 32]);

        let modify_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x37; 32])),
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify foo".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity_v1.clone(),
                    new: entity_v2.clone(),
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let revisions = graph
            .get_entity_revisions_at(&entity_v1.id, &modify_id)
            .unwrap();
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].entity.signature, entity_v1.signature);
        assert_eq!(revisions[0].ended_by, Some(modify_id));
        assert_eq!(revisions[1].entity.signature, entity_v2.signature);
        assert_eq!(
            revisions[1].previous_revision,
            Some(revisions[0].revision_id)
        );
        assert_eq!(revisions[1].ended_by, None);
    }

    /// Every domain of two graph snapshots, compared by value.
    ///
    /// Destructured on purpose: adding a domain to `GraphSnapshot` breaks this
    /// function until somebody decides whether the new domain is part of what
    /// "the served graph equals a fresh build" means. A field list that only
    /// grew by hand would silently stop covering the thing it names.
    fn assert_graph_snapshots_identical(served: &GraphSnapshot, fresh: &GraphSnapshot) {
        let GraphSnapshot {
            version,
            entities,
            relations,
            outgoing,
            incoming,
            changes,
            change_children,
            work_items,
            annotations,
            work_links,
            reviews,
            review_decisions,
            review_notes,
            review_discussions,
            review_assignments,
            test_cases,
            assertions,
            verification_runs,
            mock_hints,
            contracts,
            actors,
            delegations,
            approvals,
            audit_events,
            shallow_files,
            file_layouts,
            structured_artifacts,
            opaque_artifacts,
            resolved_tree,
            sessions,
            intents,
            downstream_warnings,
            entity_revisions,
            repository_authority,
            external_references,
        } = served;
        assert_eq!(*version, fresh.version, "version");
        assert_eq!(*entities, fresh.entities, "entities");
        assert_eq!(*relations, fresh.relations, "relations");
        assert_eq!(*outgoing, fresh.outgoing, "outgoing");
        assert_eq!(*incoming, fresh.incoming, "incoming");
        assert_eq!(*changes, fresh.changes, "changes");
        assert_eq!(*change_children, fresh.change_children, "change_children");
        assert_eq!(*resolved_tree, fresh.resolved_tree, "resolved_tree");
        assert_eq!(
            *entity_revisions, fresh.entity_revisions,
            "entity_revisions"
        );
        assert_eq!(
            *external_references, fresh.external_references,
            "external_references"
        );
        assert_eq!(
            repository_authority.is_none(),
            fresh.repository_authority.is_none(),
            "repository_authority presence"
        );
        // The remaining domains carry kin-model types with no `PartialEq`, so
        // they are compared as canonically ordered encodings instead. Maps are
        // sorted by encoded key so only the order two `HashMap`s happen to
        // iterate in is removed, never a real difference.
        assert_eq!(
            snapshot_domain_map(work_items.iter()),
            snapshot_domain_map(fresh.work_items.iter()),
            "work_items"
        );
        assert_eq!(
            snapshot_domain_map(annotations.iter()),
            snapshot_domain_map(fresh.annotations.iter()),
            "annotations"
        );
        assert_eq!(
            snapshot_domain_value(work_links),
            snapshot_domain_value(&fresh.work_links),
            "work_links"
        );
        assert_eq!(
            snapshot_domain_map(reviews.iter()),
            snapshot_domain_map(fresh.reviews.iter()),
            "reviews"
        );
        assert_eq!(
            snapshot_domain_map(review_decisions.iter()),
            snapshot_domain_map(fresh.review_decisions.iter()),
            "review_decisions"
        );
        assert_eq!(
            snapshot_domain_value(review_notes),
            snapshot_domain_value(&fresh.review_notes),
            "review_notes"
        );
        assert_eq!(
            snapshot_domain_value(review_discussions),
            snapshot_domain_value(&fresh.review_discussions),
            "review_discussions"
        );
        assert_eq!(
            snapshot_domain_map(review_assignments.iter()),
            snapshot_domain_map(fresh.review_assignments.iter()),
            "review_assignments"
        );
        assert_eq!(
            snapshot_domain_map(test_cases.iter()),
            snapshot_domain_map(fresh.test_cases.iter()),
            "test_cases"
        );
        assert_eq!(
            snapshot_domain_map(assertions.iter()),
            snapshot_domain_map(fresh.assertions.iter()),
            "assertions"
        );
        assert_eq!(
            snapshot_domain_map(verification_runs.iter()),
            snapshot_domain_map(fresh.verification_runs.iter()),
            "verification_runs"
        );
        assert_eq!(
            snapshot_domain_value(mock_hints),
            snapshot_domain_value(&fresh.mock_hints),
            "mock_hints"
        );
        assert_eq!(
            snapshot_domain_map(contracts.iter()),
            snapshot_domain_map(fresh.contracts.iter()),
            "contracts"
        );
        assert_eq!(
            snapshot_domain_map(actors.iter()),
            snapshot_domain_map(fresh.actors.iter()),
            "actors"
        );
        assert_eq!(
            snapshot_domain_value(delegations),
            snapshot_domain_value(&fresh.delegations),
            "delegations"
        );
        assert_eq!(
            snapshot_domain_value(approvals),
            snapshot_domain_value(&fresh.approvals),
            "approvals"
        );
        assert_eq!(
            snapshot_domain_value(audit_events),
            snapshot_domain_value(&fresh.audit_events),
            "audit_events"
        );
        assert_eq!(
            snapshot_domain_value(shallow_files),
            snapshot_domain_value(&fresh.shallow_files),
            "shallow_files"
        );
        assert_eq!(
            snapshot_domain_value(file_layouts),
            snapshot_domain_value(&fresh.file_layouts),
            "file_layouts"
        );
        assert_eq!(
            snapshot_domain_value(structured_artifacts),
            snapshot_domain_value(&fresh.structured_artifacts),
            "structured_artifacts"
        );
        assert_eq!(
            snapshot_domain_value(opaque_artifacts),
            snapshot_domain_value(&fresh.opaque_artifacts),
            "opaque_artifacts"
        );
        assert_eq!(
            snapshot_domain_map(sessions.iter()),
            snapshot_domain_map(fresh.sessions.iter()),
            "sessions"
        );
        assert_eq!(
            snapshot_domain_map(intents.iter()),
            snapshot_domain_map(fresh.intents.iter()),
            "intents"
        );
        assert_eq!(
            snapshot_domain_value(downstream_warnings),
            snapshot_domain_value(&fresh.downstream_warnings),
            "downstream_warnings"
        );
    }

    fn snapshot_domain_value<T: serde::Serialize>(value: &T) -> Vec<u8> {
        rmp_serde::to_vec(value).expect("a snapshot domain encodes")
    }

    fn snapshot_domain_map<'a, K: serde::Serialize + 'a, V: serde::Serialize + 'a>(
        map: impl IntoIterator<Item = (&'a K, &'a V)>,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut entries: Vec<_> = map
            .into_iter()
            .map(|(key, value)| (snapshot_domain_value(key), snapshot_domain_value(value)))
            .collect();
        entries.sort();
        entries
    }

    /// A base graph with entities, relations, a tree and a genesis change: the
    /// shape a commit lands on, not an empty store.
    fn install_identity_base_graph() -> (InMemoryGraph, SemanticChangeId, Entity) {
        let graph = InMemoryGraph::new();
        let anchor = test_entity("existing_anchor", "src/anchor.rs");
        let neighbor = test_entity("existing_neighbor", "src/anchor.rs");
        graph.upsert_entity(&anchor).unwrap();
        graph.upsert_entity(&neighbor).unwrap();
        graph
            .upsert_relation(&test_relation(anchor.id, neighbor.id, RelationKind::Calls))
            .unwrap();
        let genesis = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x01; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![EntityDelta::Added {
                    new: anchor.clone(),
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );
        (graph, genesis, anchor)
    }

    fn install_identity_one_entity_change(
        parent: SemanticChangeId,
        entity: &Entity,
    ) -> SemanticChange {
        seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x02; 32])),
            parents: vec![parent],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "install one entity".to_string(),
            entity_deltas: vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        })
    }

    /// Installing a commit's own delta into the graph the daemon already holds
    /// must leave exactly the state a cold process would rebuild from the
    /// durable bytes.
    ///
    /// This is the invariant the commit path's `install_live_graph` phase rests
    /// on: it applies the change to the live query graph instead of rebuilding
    /// one, and every read served afterwards comes from that graph rather than
    /// from a reopen. Counting entities would not catch a delta that landed in
    /// the live maps but not in the derived adjacency or revision lineage, so
    /// the comparison is by value across every snapshot domain.
    #[test]
    fn live_change_install_is_value_identical_to_a_rebuild_from_durable_bytes() {
        let (graph, genesis, anchor) = install_identity_base_graph();
        let added = test_entity("freshly_committed", "src/committed.rs");
        let change = install_identity_one_entity_change(genesis, &added);
        let _ = anchor;

        graph.create_change(&change).unwrap();
        let served = graph.to_snapshot();

        let bytes = served.to_bytes().unwrap();
        let reopened = InMemoryGraph::from_snapshot(GraphSnapshot::from_bytes(&bytes).unwrap())
            .unwrap()
            .to_snapshot();

        assert_graph_snapshots_identical(&served, &reopened);
        assert!(
            served.changes.contains_key(&change.id),
            "the served graph must carry the installed change"
        );
        assert!(
            served.entity_revisions.contains_key(&added.id),
            "the served graph must carry the installed entity's revision chain"
        );
    }

    /// The control for the test above: a real difference in one domain must
    /// make the comparison fail. Without this, a comparison that silently
    /// stopped looking at anything would keep passing.
    #[test]
    #[should_panic(expected = "entity_revisions")]
    fn live_change_install_identity_fails_on_a_real_difference() {
        let (graph, genesis, _anchor) = install_identity_base_graph();
        let added = test_entity("freshly_committed", "src/committed.rs");
        let change = install_identity_one_entity_change(genesis, &added);
        graph.create_change(&change).unwrap();
        let served = graph.to_snapshot();

        let mut perturbed = served.clone();
        perturbed.entity_revisions.remove(&added.id);

        assert_graph_snapshots_identical(&served, &perturbed);
    }

    #[test]
    fn create_change_persists_entity_revision_lineage_in_snapshots() {
        let graph = InMemoryGraph::new();

        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x71; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let entity_v1 = test_entity("foo", "src/lib.rs");
        let add_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x72; 32])),
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add foo".to_string(),
                entity_deltas: vec![EntityDelta::Added {
                    new: entity_v1.clone(),
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let mut entity_v2 = entity_v1.clone();
        entity_v2.signature = "fn foo(value: i32)".to_string();
        entity_v2.fingerprint.signature_hash = Hash256::from_bytes([0x73; 32]);
        let modify_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x74; 32])),
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify foo".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity_v1.clone(),
                    new: entity_v2,
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let snapshot = graph.to_snapshot();
        let revisions = snapshot
            .entity_revisions
            .get(&entity_v1.id)
            .expect("entity revision chain should be persisted");
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].introduced_by, add_id);
        assert_eq!(revisions[1].introduced_by, modify_id);
        assert_eq!(
            revisions[1].previous_revision,
            Some(revisions[0].revision_id)
        );
    }

    #[test]
    fn from_snapshot_backfills_entity_revisions_from_change_history() {
        let graph = InMemoryGraph::new();

        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x75; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let entity_v1 = test_entity("foo", "src/lib.rs");
        let add_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x76; 32])),
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add foo".to_string(),
                entity_deltas: vec![EntityDelta::Added {
                    new: entity_v1.clone(),
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let mut entity_v2 = entity_v1.clone();
        entity_v2.signature = "fn foo(value: i32)".to_string();
        entity_v2.fingerprint.signature_hash = Hash256::from_bytes([0x77; 32]);
        let modify_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x78; 32])),
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify foo".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity_v1.clone(),
                    new: entity_v2,
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let mut snapshot = graph.to_snapshot();
        snapshot.entity_revisions.clear();

        let reloaded = InMemoryGraph::from_snapshot(snapshot).unwrap();
        let repaired = reloaded.to_snapshot();
        let revisions = repaired
            .entity_revisions
            .get(&entity_v1.id)
            .expect("reload should rebuild entity revision chain");
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].introduced_by, add_id);
        assert_eq!(revisions[1].introduced_by, modify_id);
        assert_eq!(
            revisions[1].previous_revision,
            Some(revisions[0].revision_id)
        );
    }

    /// Reloading a snapshot must rebuild the same revisions the live graph
    /// held, including the payload a merge inherited from its second parent.
    /// Backfilling along first-parent lineage alone loses it and the reload
    /// refuses its own history as stale.
    ///
    /// Upstream trigger: fd 10ea476e3174350860ef3a32c61c4c8d6e74ab55, its 91st
    /// commit, the first merge in fd whose second parent carries a source edit
    /// (src/main.rs) that the first-parent lineage never published.
    #[test]
    fn from_snapshot_backfills_entity_revisions_across_merge_history() {
        let graph = InMemoryGraph::new();

        let entity_v1 = test_entity("foo", "src/lib.rs");
        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x81; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add foo".to_string(),
                entity_deltas: vec![EntityDelta::Added {
                    new: entity_v1.clone(),
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let mut entity_v2 = entity_v1.clone();
        entity_v2.signature = "fn foo(value: i32)".to_string();
        entity_v2.fingerprint.signature_hash = Hash256::from_bytes([0x82; 32]);
        let branch_delta = vec![EntityDelta::Modified {
            old: entity_v1.clone(),
            new: entity_v2.clone(),
        }];
        let branch_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x83; 32])),
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "revise foo on a side branch".to_string(),
                entity_deltas: branch_delta.clone(),
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        // The merge takes the side branch's content, so its own delta restates
        // that transition against its first parent.
        let merge_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x84; 32])),
                parents: vec![genesis_id, branch_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "merge the side branch".to_string(),
                entity_deltas: branch_delta,
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let mut snapshot = graph.to_snapshot();
        snapshot.entity_revisions.clear();

        let reloaded = InMemoryGraph::from_snapshot(snapshot)
            .expect("merge history must reload without a stale-payload refusal");
        let repaired = reloaded.to_snapshot();
        let revisions = repaired
            .entity_revisions
            .get(&entity_v1.id)
            .expect("reload should rebuild entity revision chain");
        assert_eq!(
            revisions
                .iter()
                .map(|revision| revision.introduced_by)
                .collect::<Vec<_>>(),
            vec![genesis_id, branch_id, merge_id]
        );
        assert_eq!(revisions[0].previous_revision, None);
        // Both the side branch and the merge supersede the genesis revision:
        // each reads its own first parent, not a folded sibling state.
        assert_eq!(
            revisions[1].previous_revision,
            Some(revisions[0].revision_id)
        );
        assert_eq!(
            revisions[2].previous_revision,
            Some(revisions[0].revision_id)
        );
    }

    #[test]
    fn from_snapshot_refuses_an_old_payload_the_first_parent_never_published() {
        let graph = InMemoryGraph::new();

        let entity_v1 = test_entity("foo", "src/lib.rs");
        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x85; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add foo".to_string(),
                entity_deltas: vec![EntityDelta::Added {
                    new: entity_v1.clone(),
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let mut unpublished = entity_v1.clone();
        unpublished.signature = "fn foo(value: u64)".to_string();
        unpublished.fingerprint.signature_hash = Hash256::from_bytes([0x86; 32]);
        let mut replacement = unpublished.clone();
        replacement.signature = "fn foo(value: u128)".to_string();
        replacement.fingerprint.signature_hash = Hash256::from_bytes([0x87; 32]);
        admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x88; 32])),
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "revise a payload nobody published".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: unpublished,
                    new: replacement,
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let mut snapshot = graph.to_snapshot();
        snapshot.entity_revisions.clear();

        let Err(error) = InMemoryGraph::from_snapshot(snapshot) else {
            panic!("a payload no parent published must not rebuild into a revision chain");
        };
        assert!(
            error.to_string().contains("stale old payload for entity"),
            "unexpected revision derivation error: {error}"
        );
    }

    #[test]
    fn get_relation_revisions_at_replays_relation_lifecycle() {
        let graph = InMemoryGraph::new();

        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x38; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let caller = test_entity("caller", "src/lib.rs");
        let callee = test_entity("callee", "src/lib.rs");
        let rel = test_relation(caller.id, callee.id, RelationKind::Calls);

        let add_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x39; 32])),
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add graph".to_string(),
                entity_deltas: vec![
                    EntityDelta::Added {
                        new: caller.clone(),
                    },
                    EntityDelta::Added {
                        new: callee.clone(),
                    },
                ],
                relation_deltas: vec![RelationDelta::Added { new: rel.clone() }],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let remove_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x3a; 32])),
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "remove relation".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![RelationDelta::Removed { old: rel.clone() }],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let revisions = graph
            .get_relation_revisions_at(&rel.id, &remove_id)
            .unwrap();
        assert_eq!(revisions.len(), 1);
        assert_eq!(revisions[0].relation_id, rel.id);
        assert_eq!(revisions[0].introduced_by, add_id);
        assert_eq!(revisions[0].ended_by, Some(remove_id));
    }

    #[test]
    fn resolve_graph_at_replays_entities_and_relations() {
        let graph = InMemoryGraph::new();

        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x41; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let caller = test_entity("caller", "src/lib.rs");
        let callee = test_entity("callee", "src/lib.rs");
        let rel = test_relation(caller.id, callee.id, RelationKind::Calls);

        let add_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x42; 32])),
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add graph".to_string(),
                entity_deltas: vec![
                    EntityDelta::Added {
                        new: caller.clone(),
                    },
                    EntityDelta::Added {
                        new: callee.clone(),
                    },
                ],
                relation_deltas: vec![RelationDelta::Added { new: rel.clone() }],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let remove_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x43; 32])),
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "remove callee".to_string(),
                entity_deltas: vec![EntityDelta::Removed {
                    old: callee.clone(),
                }],
                relation_deltas: vec![RelationDelta::Removed { old: rel.clone() }],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let added_state = graph.resolve_graph_at(&add_id).unwrap();
        assert_eq!(added_state.entities.len(), 2);
        assert_eq!(added_state.relations.len(), 1);

        let removed_state = graph.resolve_graph_at(&remove_id).unwrap();
        assert!(removed_state.entities.contains_key(&caller.id));
        assert!(!removed_state.entities.contains_key(&callee.id));
        assert!(
            removed_state.relations.is_empty(),
            "entity and relation removal are both explicit in exact history"
        );
    }

    #[test]
    fn resolve_graph_at_replays_external_reference_lifecycle() {
        let graph = InMemoryGraph::new();
        let mut caller = test_entity("caller", "src/client.py");
        caller.file_origin = None;
        let reference =
            ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        let relation = Relation {
            id: RelationId::new(),
            src: GraphNodeId::Entity(caller.id),
            dst: GraphNodeId::ExternalReference(reference.id),
            kind: RelationKind::Imports,
            confidence: 1.0,
            origin: RelationOrigin::Lsp,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };

        let add_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x47; 32])),
                parents: Vec::new(),
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "bind resolved dependency".to_string(),
                entity_deltas: vec![EntityDelta::Added {
                    new: caller.clone(),
                }],
                relation_deltas: vec![RelationDelta::Added {
                    new: relation.clone(),
                }],
                tree_deltas: Vec::new(),
                projected_files: Vec::new(),
                spec_link: None,
                evidence: Vec::new(),
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: vec![ExternalReferenceDelta::Added {
                    new: reference.clone(),
                }],
            },
        );
        let remove_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x48; 32])),
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "retire resolved dependency".to_string(),
                entity_deltas: Vec::new(),
                relation_deltas: vec![RelationDelta::Removed {
                    old: relation.clone(),
                }],
                tree_deltas: Vec::new(),
                projected_files: Vec::new(),
                spec_link: None,
                evidence: Vec::new(),
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: vec![ExternalReferenceDelta::Removed {
                    old: reference.clone(),
                }],
            },
        );

        let added = graph.resolve_graph_at(&add_id).unwrap();
        assert_eq!(
            added.external_references.get(&reference.id),
            Some(&reference)
        );
        assert_eq!(added.relations.get(&relation.id), Some(&relation));

        let removed = graph.resolve_graph_at(&remove_id).unwrap();
        assert!(removed.external_references.is_empty());
        assert!(removed.relations.is_empty());
        assert!(removed.entities.contains_key(&caller.id));
    }

    #[test]
    fn resolve_graph_at_replays_tree_into_resolved_state() {
        let graph = InMemoryGraph::new();

        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x44; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let file_id = FilePathId::new("docs/config.json");
        let artifact_id = ArtifactId::new();
        let content_hash = Hash256::from_bytes([0x45; 32]);
        let add_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x46; 32])),
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: test_located(&file_id.0, TreeEntry::blob(content_hash, false)),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let state = graph.resolve_graph_at(&add_id).unwrap();
        assert_eq!(
            state.tree.get(&artifact_id).map(|artifact| artifact.entry),
            Some(TreeEntry::blob(content_hash, false))
        );
    }

    #[test]
    fn get_entity_history_at_filters_to_reachable_changes() {
        let graph = InMemoryGraph::new();

        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x51; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let entity = test_entity("foo", "src/lib.rs");
        let add_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x52; 32])),
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add foo".to_string(),
                entity_deltas: vec![EntityDelta::Added {
                    new: entity.clone(),
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let mut main_entity = entity.clone();
        main_entity.signature = "fn foo_main()".to_string();
        let main_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x53; 32])),
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "main change".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity.clone(),
                    new: main_entity,
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let mut feature_entity = entity.clone();
        feature_entity.signature = "fn foo_feature()".to_string();
        let _feature_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x54; 32])),
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "feature change".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity.clone(),
                    new: feature_entity,
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let history = graph.get_entity_history_at(&entity.id, &main_id).unwrap();
        let messages: Vec<_> = history.into_iter().map(|change| change.message).collect();
        assert_eq!(
            messages,
            vec!["add foo".to_string(), "main change".to_string()]
        );
    }

    #[test]
    fn get_entity_revisions_at_tracks_supersession_and_removal() {
        let graph = InMemoryGraph::new();

        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x55; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let entity_v1 = test_entity("foo", "src/lib.rs");
        let add_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x56; 32])),
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add foo".to_string(),
                entity_deltas: vec![EntityDelta::Added {
                    new: entity_v1.clone(),
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let mut entity_v2 = entity_v1.clone();
        entity_v2.signature = "fn foo(value: i32)".to_string();
        entity_v2.fingerprint.signature_hash = Hash256::from_bytes([0x57; 32]);

        let modify_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x58; 32])),
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify foo".to_string(),
                entity_deltas: vec![EntityDelta::Modified {
                    old: entity_v1.clone(),
                    new: entity_v2.clone(),
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let remove_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x59; 32])),
                parents: vec![modify_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "remove foo".to_string(),
                entity_deltas: vec![EntityDelta::Removed {
                    old: entity_v2.clone(),
                }],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let revisions = graph
            .get_entity_revisions_at(&entity_v1.id, &remove_id)
            .unwrap();
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].introduced_by, add_id);
        assert_eq!(revisions[0].ended_by, Some(modify_id));
        assert_eq!(revisions[1].introduced_by, modify_id);
        assert_eq!(
            revisions[1].previous_revision,
            Some(revisions[0].revision_id)
        );
        assert_eq!(revisions[1].ended_by, Some(remove_id));
        assert!(graph
            .resolve_entity_revision_at(&entity_v1.id, &remove_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn get_relation_revisions_at_tracks_add_remove_cycles() {
        let graph = InMemoryGraph::new();

        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x5a; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let caller = test_entity("caller", "src/lib.rs");
        let callee = test_entity("callee", "src/lib.rs");
        let rel = test_relation(caller.id, callee.id, RelationKind::Calls);
        let add_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x5b; 32])),
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add relation".to_string(),
                entity_deltas: vec![
                    EntityDelta::Added {
                        new: caller.clone(),
                    },
                    EntityDelta::Added {
                        new: callee.clone(),
                    },
                ],
                relation_deltas: vec![RelationDelta::Added { new: rel.clone() }],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let remove_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x5c; 32])),
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "remove relation".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![RelationDelta::Removed { old: rel.clone() }],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let revisions = graph
            .get_relation_revisions_at(&rel.id, &remove_id)
            .unwrap();
        assert_eq!(revisions.len(), 1);
        assert_eq!(revisions[0].introduced_by, add_id);
        assert_eq!(revisions[0].ended_by, Some(remove_id));
        assert!(graph
            .resolve_relation_revision_at(&rel.id, &remove_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn get_artifact_revisions_at_tracks_current_and_removed_content() {
        let graph = InMemoryGraph::new();

        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x66; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let file_id = FilePathId::new("docs/config.json");
        let artifact_id = ArtifactId::new();
        let v1 = Hash256::from_bytes([0x67; 32]);
        let add_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x68; 32])),
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: test_located(&file_id.0, TreeEntry::blob(v1, false)),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let v2 = Hash256::from_bytes([0x69; 32]);
        let modify_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x6a; 32])),
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: test_located(&file_id.0, TreeEntry::blob(v1, false)),
                    new: test_located(&file_id.0, TreeEntry::blob(v2, false)),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let remove_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x6b; 32])),
                parents: vec![modify_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "remove artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![TreeDelta::Removed {
                    artifact_id,
                    old: test_located(&file_id.0, TreeEntry::blob(v2, false)),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let revisions = graph
            .get_artifact_revisions_at(&artifact_id, &remove_id)
            .unwrap();
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].entry, TreeEntry::blob(v1, false));
        assert_eq!(revisions[1].entry, TreeEntry::blob(v2, false));
        assert!(graph
            .resolve_artifact_revision_at(&artifact_id, &remove_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn resolve_tree_at_replays_tree_deltas_for_target_head() {
        let graph = InMemoryGraph::new();

        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x61; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let file_id = FilePathId::new("docs/config.json");
        let artifact_id = ArtifactId::new();
        let v1 = Hash256::from_bytes([0x62; 32]);
        let add_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x63; 32])),
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: test_located(&file_id.0, TreeEntry::blob(v1, false)),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let v2 = Hash256::from_bytes([0x64; 32]);
        let modify_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x65; 32])),
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: test_located(&file_id.0, TreeEntry::blob(v1, false)),
                    new: test_located(&file_id.0, TreeEntry::blob(v2, false)),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let at_add = graph.resolve_tree_at(&add_id).unwrap();
        assert_eq!(
            at_add.get(&artifact_id).map(|artifact| artifact.entry),
            Some(TreeEntry::blob(v1, false))
        );

        let at_modify = graph.resolve_tree_at(&modify_id).unwrap();
        assert_eq!(
            at_modify.get(&artifact_id).map(|artifact| artifact.entry),
            Some(TreeEntry::blob(v2, false))
        );
    }

    #[test]
    fn get_artifact_revisions_at_replays_file_history() {
        let graph = InMemoryGraph::new();

        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x66; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let file_id = FilePathId::new("docs/config.json");
        let artifact_id = ArtifactId::new();
        let v1 = Hash256::from_bytes([0x67; 32]);
        let add_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x68; 32])),
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: test_located(&file_id.0, TreeEntry::blob(v1, false)),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let v2 = Hash256::from_bytes([0x69; 32]);
        let modify_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x6a; 32])),
                parents: vec![add_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "modify artifact".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: test_located(&file_id.0, TreeEntry::blob(v1, false)),
                    new: test_located(&file_id.0, TreeEntry::blob(v2, false)),
                }],
                projected_files: vec![file_id.clone()],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let revisions = graph
            .get_artifact_revisions_at(&artifact_id, &modify_id)
            .unwrap();
        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].entry, TreeEntry::blob(v1, false));
        assert_eq!(revisions[1].entry, TreeEntry::blob(v2, false));
        assert_eq!(
            revisions[1].predecessor_revisions,
            vec![revisions[0].revision_id]
        );
    }

    #[test]
    fn list_all_entities() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("a", "a.rs");
        let e2 = test_entity("b", "b.rs");

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let all = graph.list_all_entities().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn concurrent_read_access() {
        use std::sync::Arc;
        use std::thread;

        let graph = Arc::new(InMemoryGraph::new());
        let e = test_entity("concurrent", "a.rs");
        let id = e.id;
        graph.upsert_entity(&e).unwrap();

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let g = Arc::clone(&graph);
                thread::spawn(move || g.get_entity(&id).unwrap().unwrap().name)
            })
            .collect();

        for h in handles {
            assert_eq!(h.join().unwrap(), "concurrent");
        }
    }

    #[test]
    fn work_item_crud() {
        let graph = InMemoryGraph::new();
        let item = WorkItem {
            work_id: WorkId::new(),
            kind: WorkKind::Feature,
            title: "Add login".into(),
            description: "OAuth login".into(),
            status: WorkStatus::Proposed,
            priority: Priority::High,
            scopes: vec![],
            acceptance_criteria: vec![],
            external_refs: vec![],
            created_by: IdentityRef::human("alice"),
            created_at: Timestamp::now(),
        };
        let id = item.work_id;

        graph.create_work_item(&item).unwrap();
        let fetched = graph.get_work_item(&id).unwrap().unwrap();
        assert_eq!(fetched.title, "Add login");

        graph
            .update_work_status(&id, WorkStatus::InProgress)
            .unwrap();
        let updated = graph.get_work_item(&id).unwrap().unwrap();
        assert_eq!(updated.status, WorkStatus::InProgress);

        graph.delete_work_item(&id).unwrap();
        assert!(graph.get_work_item(&id).unwrap().is_none());
    }

    #[test]
    fn annotation_crud() {
        let graph = InMemoryGraph::new();
        let ann = Annotation {
            annotation_id: AnnotationId::new(),
            kind: AnnotationKind::Warning,
            body: "Deprecated API".into(),
            scopes: vec![],
            anchored_fingerprint: None,
            authored_by: IdentityRef::human("bob"),
            created_at: Timestamp::now(),
            staleness: StalenessState::Fresh,
        };
        let id = ann.annotation_id;

        graph.create_annotation(&ann).unwrap();
        let fetched = graph.get_annotation(&id).unwrap().unwrap();
        assert_eq!(fetched.body, "Deprecated API");

        graph
            .update_annotation_staleness(&id, StalenessState::Stale)
            .unwrap();
        let updated = graph.get_annotation(&id).unwrap().unwrap();
        assert_eq!(updated.staleness, StalenessState::Stale);

        graph.delete_annotation(&id).unwrap();
        assert!(graph.get_annotation(&id).unwrap().is_none());
    }

    #[test]
    fn test_case_and_coverage() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("target_fn", "src/lib.rs");
        let eid = entity.id;
        graph.upsert_entity(&entity).unwrap();

        let tc = TestCase {
            test_id: TestId::new(),
            name: "test_target".into(),
            language: "rust".into(),
            kind: TestKind::Unit,
            scopes: vec![],
            runner: TestRunner::Cargo,
            file_origin: None,
        };
        let tid = tc.test_id;

        graph.create_test_case(&tc).unwrap();
        graph.create_test_covers_entity(&tid, &eid).unwrap();

        let tests = graph.get_tests_for_entity(&eid).unwrap();
        assert_eq!(tests.len(), 1);

        let summary = graph.get_coverage_summary().unwrap();
        assert_eq!(summary.total_entities, 1);
        assert_eq!(summary.covered_entities, 1);
    }

    #[test]
    fn create_test_case_batches_entity_scope_cover_relations() {
        let graph = InMemoryGraph::new();
        let entity_a = test_entity("target_a", "src/lib.rs");
        let entity_b = test_entity("target_b", "src/lib.rs");
        graph.upsert_entity(&entity_a).unwrap();
        graph.upsert_entity(&entity_b).unwrap();

        let tc = TestCase {
            test_id: TestId::new(),
            name: "test_target".into(),
            language: "rust".into(),
            kind: TestKind::Unit,
            scopes: vec![
                WorkScope::Entity(entity_a.id),
                WorkScope::Entity(entity_b.id),
                WorkScope::Entity(entity_a.id),
            ],
            runner: TestRunner::Cargo,
            file_origin: None,
        };
        let tid = tc.test_id;

        graph.create_test_case(&tc).unwrap();

        let tests_a = graph.get_tests_for_entity(&entity_a.id).unwrap();
        let tests_b = graph.get_tests_for_entity(&entity_b.id).unwrap();
        assert_eq!(tests_a.len(), 1);
        assert_eq!(tests_b.len(), 1);
        assert_eq!(tests_a[0].test_id, tid);
        assert_eq!(tests_b[0].test_id, tid);
    }

    #[cfg(feature = "vector")]
    #[test]
    fn delete_test_case_requeues_indexed_relation_endpoints() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("target", "src/lib.rs");
        graph.upsert_entity(&entity).unwrap();
        let test_case = TestCase {
            test_id: TestId::new(),
            name: "test_target".into(),
            language: "rust".into(),
            kind: TestKind::Unit,
            scopes: vec![WorkScope::Entity(entity.id)],
            runner: TestRunner::Cargo,
            file_origin: None,
        };
        graph.create_test_case(&test_case).unwrap();

        let index = std::sync::Arc::new(crate::VectorIndex::new(2).unwrap());
        index.upsert(entity.id, &[1.0, 0.0]).unwrap();
        *graph.vector_index.lock() = Some(std::sync::Arc::clone(&index));
        graph.embedding_queue.lock().clear();

        graph.delete_test_case(&test_case.test_id).unwrap();

        assert!(graph
            .embedding_queue
            .lock()
            .contains(&RetrievalKey::Entity(entity.id)));
        assert!(!index.contains(&entity.id));
        assert_eq!(
            graph.snapshot_root_hash(),
            Some(compute_graph_root_hash(&graph.to_snapshot())),
            "bulk test-relation deletion must keep the maintained Merkle root current"
        );
    }

    #[test]
    fn traverse_crosses_verification_and_entity_edges() {
        let graph = InMemoryGraph::new();
        let covered = test_entity("target_fn", "src/lib.rs");
        let callee = test_entity("helper_fn", "src/lib.rs");
        graph.upsert_entity(&covered).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph
            .upsert_relation(&test_relation(covered.id, callee.id, RelationKind::Calls))
            .unwrap();

        let test_case = TestCase {
            test_id: TestId::new(),
            name: "test_target".into(),
            language: "rust".into(),
            kind: TestKind::Unit,
            scopes: vec![],
            runner: TestRunner::Cargo,
            file_origin: None,
        };
        graph.create_test_case(&test_case).unwrap();
        graph
            .create_test_covers_entity(&test_case.test_id, &covered.id)
            .unwrap();

        let traversal = graph
            .traverse(&GraphNodeId::Test(test_case.test_id), &[], 2)
            .unwrap();

        assert!(traversal
            .nodes
            .contains(&GraphNodeId::Test(test_case.test_id)));
        assert!(traversal.nodes.contains(&GraphNodeId::Entity(covered.id)));
        assert!(traversal.nodes.contains(&GraphNodeId::Entity(callee.id)));
        assert_eq!(traversal.entities.len(), 2);
        assert!(traversal
            .relations
            .iter()
            .any(|relation| relation.kind == RelationKind::Covers));
        assert!(traversal
            .relations
            .iter()
            .any(|relation| relation.kind == RelationKind::Calls));
    }

    #[test]
    fn actor_and_audit() {
        let graph = InMemoryGraph::new();
        let actor = Actor {
            actor_id: ActorId::new(),
            kind: ActorKind::Human,
            display_name: "Alice".into(),
            external_refs: vec![],
        };
        let aid = actor.actor_id;

        graph.create_actor(&actor).unwrap();
        let fetched = graph.get_actor(&aid).unwrap().unwrap();
        assert_eq!(fetched.display_name, "Alice");

        let event = AuditEvent {
            event_id: AuditEventId::new(),
            actor_id: aid,
            action: "commit".into(),
            target_scope: None,
            timestamp: Timestamp::now(),
            details: None,
        };
        graph.record_audit_event(&event).unwrap();

        let events = graph.query_audit_events(Some(&aid), 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "commit");
    }

    #[test]
    fn shallow_file_tracking() {
        let graph = InMemoryGraph::new();
        let sf = ShallowTrackedFile {
            file_id: FilePathId::new("lib.c"),
            language_hint: "c".into(),
            declaration_count: 5,
            import_count: 3,
            syntax_hash: Hash256::from_bytes([0xaa; 32]),
            signature_hash: None,
            declaration_names: vec!["decode".into()],
            import_paths: vec!["zstd.h".into()],
        };

        admit_enrichment(&graph, &sf.file_id, sf.syntax_hash);
        graph.upsert_shallow_file(&sf).unwrap();
        let files = graph.list_shallow_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].declaration_count, 5);
        let fetched = graph.get_shallow_file(&sf.file_id).unwrap().unwrap();
        assert_eq!(fetched.file_id, sf.file_id);
        assert_eq!(fetched.declaration_count, sf.declaration_count);
        assert_eq!(fetched.language_hint, sf.language_hint);

        // Upsert replaces
        let sf2 = ShallowTrackedFile {
            declaration_count: 10,
            ..sf.clone()
        };
        graph.upsert_shallow_file(&sf2).unwrap();
        let files = graph.list_shallow_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].declaration_count, 10);
        let fetched = graph.get_shallow_file(&sf2.file_id).unwrap().unwrap();
        assert_eq!(fetched.file_id, sf2.file_id);
        assert_eq!(fetched.declaration_count, sf2.declaration_count);
    }

    #[test]
    fn artifact_tracking() {
        let graph = InMemoryGraph::new();
        let structured = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([0xbb; 32]),
            text_preview: Some("build test".into()),
        };
        let opaque = OpaqueArtifact {
            file_id: FilePathId::new("assets/logo.svg"),
            content_hash: Hash256::from_bytes([0xcc; 32]),
            mime_type: Some("image/svg+xml".into()),
            text_preview: Some("<svg".into()),
        };

        admit_enrichment(&graph, &structured.file_id, structured.content_hash);
        admit_enrichment(&graph, &opaque.file_id, opaque.content_hash);
        graph.upsert_structured_artifact(&structured).unwrap();
        graph.upsert_opaque_artifact(&opaque).unwrap();

        let structured_files = graph.list_structured_artifacts().unwrap();
        let opaque_files = graph.list_opaque_artifacts().unwrap();
        assert_eq!(structured_files.len(), 1);
        assert_eq!(structured_files[0].kind, ArtifactKind::Makefile);
        assert_eq!(opaque_files.len(), 1);
        assert_eq!(opaque_files[0].mime_type.as_deref(), Some("image/svg+xml"));
        let fetched_structured = graph
            .get_structured_artifact(&structured.file_id)
            .unwrap()
            .unwrap();
        assert_eq!(fetched_structured.file_id, structured.file_id);
        assert_eq!(fetched_structured.kind, structured.kind);
        assert_eq!(fetched_structured.text_preview, structured.text_preview);
        let fetched_opaque = graph.get_opaque_artifact(&opaque.file_id).unwrap().unwrap();
        assert_eq!(fetched_opaque.file_id, opaque.file_id);
        assert_eq!(fetched_opaque.mime_type, opaque.mime_type);
        assert_eq!(fetched_opaque.text_preview, opaque.text_preview);
        assert!(graph
            .get_structured_artifact(&FilePathId::new("missing.file"))
            .unwrap()
            .is_none());

        graph
            .delete_structured_artifact(&structured.file_id)
            .unwrap();
        graph.delete_opaque_artifact(&opaque.file_id).unwrap();
        assert!(graph.list_structured_artifacts().unwrap().is_empty());
        assert!(graph.list_opaque_artifacts().unwrap().is_empty());
    }

    #[cfg(feature = "vector")]
    #[test]
    fn artifact_embedding_queue_tracks_shallow_structured_and_opaque_artifacts() {
        let graph = InMemoryGraph::new();
        let shallow = ShallowTrackedFile {
            file_id: FilePathId::new("src/lib.rs"),
            language_hint: "rust".into(),
            declaration_count: 2,
            import_count: 1,
            syntax_hash: Hash256::from_bytes([0x11; 32]),
            signature_hash: Some(Hash256::from_bytes([0x12; 32])),
            declaration_names: vec!["run".into()],
            import_paths: vec!["std::fmt".into()],
        };
        let structured = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([0x13; 32]),
            text_preview: Some("build test".into()),
        };
        let opaque = OpaqueArtifact {
            file_id: FilePathId::new("assets/logo.svg"),
            content_hash: Hash256::from_bytes([0x14; 32]),
            mime_type: Some("image/svg+xml".into()),
            text_preview: Some("<svg".into()),
        };

        admit_enrichment(&graph, &shallow.file_id, shallow.syntax_hash);
        admit_enrichment(&graph, &structured.file_id, structured.content_hash);
        admit_enrichment(&graph, &opaque.file_id, opaque.content_hash);
        graph.upsert_shallow_file(&shallow).unwrap();
        graph.upsert_structured_artifact(&structured).unwrap();
        graph.upsert_opaque_artifact(&opaque).unwrap();

        let shallow_id = graph
            .artifact_id_at_path(&test_repo_path(&shallow.file_id.0))
            .unwrap();
        let structured_id = graph
            .artifact_id_at_path(&test_repo_path(&structured.file_id.0))
            .unwrap();
        let opaque_id = graph
            .artifact_id_at_path(&test_repo_path(&opaque.file_id.0))
            .unwrap();

        {
            let queue = graph.artifact_embedding_queue.lock();
            assert!(queue.contains(&shallow_id));
            assert!(queue.contains(&structured_id));
            assert!(queue.contains(&opaque_id));
            assert_eq!(queue.len(), 3);
        }

        graph.delete_shallow_file(&shallow.file_id).unwrap();
        graph
            .delete_structured_artifact(&structured.file_id)
            .unwrap();
        graph.delete_opaque_artifact(&opaque.file_id).unwrap();

        let queue = graph.artifact_embedding_queue.lock();
        assert!(queue.is_empty());
    }

    #[test]
    fn file_layout_tracking() {
        let graph = InMemoryGraph::new();
        let file_id = FilePathId::new("src/lib.rs");
        let layout = FileLayout {
            file_id: file_id.clone(),
            parse_completeness: ParseCompleteness::Partial("1 parse error range(s)".into()),
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![SourceRegion::Trivia { byte_range: 0..12 }],
        };

        admit_enrichment(&graph, &file_id, Hash256::from_bytes([0x15; 32]));
        graph.upsert_file_layout(&layout).unwrap();
        let fetched = graph.get_file_layout(&file_id).unwrap().unwrap();
        assert_eq!(fetched.parse_completeness, layout.parse_completeness);
        assert_eq!(graph.list_file_layouts().unwrap().len(), 1);
        assert!(graph
            .artifact_id_at_path(&test_repo_path(&file_id.0))
            .is_some());

        graph.delete_file_layout(&file_id).unwrap();
        assert!(graph.get_file_layout(&file_id).unwrap().is_none());
        assert!(
            graph
                .artifact_id_at_path(&test_repo_path(&file_id.0))
                .is_some(),
            "deleting enrichment must not erase repository identity"
        );
    }

    #[test]
    fn artifact_identity_only_enters_through_tree_admission() {
        let path = FilePathId::new("src/lib.rs");
        let graph = InMemoryGraph::new();
        assert!(graph
            .artifact_id_at_path(&test_repo_path(&path.0))
            .is_none());

        let assigned = graph.admit_artifact_for_test(
            &path.0,
            TreeEntry::blob(Hash256::from_bytes([0; 32]), false),
        );

        assert_eq!(
            graph.artifact_id_at_path(&test_repo_path(&path.0)),
            Some(assigned)
        );
    }

    #[test]
    fn independent_graphs_assign_distinct_identities_to_the_same_path_history() {
        let original_path = FilePathId::new("src/original.rs");
        let renamed_path = FilePathId::new("src/current.rs");
        let left = InMemoryGraph::new();
        let right = InMemoryGraph::new();
        let entry = TreeEntry::blob(Hash256::from_bytes([1; 32]), false);

        let left_id = left.admit_artifact_for_test(&original_path.0, entry);
        let right_id = right.admit_artifact_for_test(&original_path.0, entry);
        assert_ne!(left_id, right_id);

        for (graph, artifact_id) in [(&left, left_id), (&right, right_id)] {
            graph
                .apply_transaction_delta(&TransactionDelta {
                    entity_deltas: Vec::new(),
                    relation_deltas: Vec::new(),
                    tree_deltas: vec![TreeDelta::Updated {
                        artifact_id,
                        old: test_located(&original_path.0, entry),
                        new: test_located(&renamed_path.0, entry),
                    }],
                    admission_policy_delta: None,
                    external_reference_deltas: Vec::new(),
                })
                .unwrap();
        }
        assert_eq!(
            left.artifact_id_at_path(&test_repo_path(&renamed_path.0)),
            Some(left_id)
        );
        assert_eq!(
            right.artifact_id_at_path(&test_repo_path(&renamed_path.0)),
            Some(right_id)
        );
    }

    #[test]
    fn delta_index_skips_unchanged_fields() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("myFunc", "src/main.rs");
        let id = entity.id;

        graph.upsert_entity(&entity).unwrap();

        // Upsert same entity with only non-indexed field changes (signature)
        let mut updated = entity.clone();
        updated.signature = "fn myFunc() -> bool".to_string();
        graph.upsert_entity(&updated).unwrap();

        // Index should still work correctly
        let ent = graph.entities.read();
        assert_eq!(ent.indexes.by_name_pattern("myfunc"), vec![id]);
        assert_eq!(ent.indexes.by_file("src/main.rs"), vec![id]);
        assert_eq!(ent.indexes.by_kind(EntityKind::Function), vec![id]);
        drop(ent);

        // Now change an indexed field (name)
        let mut renamed = updated.clone();
        renamed.name = "renamedFunc".to_string();
        graph.upsert_entity(&renamed).unwrap();

        let ent = graph.entities.read();
        assert!(ent.indexes.by_name_pattern("myfunc").is_empty());
        assert_eq!(ent.indexes.by_name_pattern("renamedfunc"), vec![id]);
        // File index should still have the entity
        assert_eq!(ent.indexes.by_file("src/main.rs"), vec![id]);
        drop(ent);

        // Change file_origin
        let mut moved = renamed.clone();
        moved.file_origin = Some(FilePathId::new("src/other.rs"));
        graph.upsert_entity(&moved).unwrap();

        let ent = graph.entities.read();
        assert!(ent.indexes.by_file("src/main.rs").is_empty());
        assert_eq!(ent.indexes.by_file("src/other.rs"), vec![id]);
        drop(ent);

        // Change kind
        let mut retyped = moved.clone();
        retyped.kind = EntityKind::Class;
        graph.upsert_entity(&retyped).unwrap();

        let ent = graph.entities.read();
        assert!(ent.indexes.by_kind(EntityKind::Function).is_empty());
        assert_eq!(ent.indexes.by_kind(EntityKind::Class), vec![id]);
    }

    #[test]
    fn delta_index_benchmark_unchanged_vs_changed() {
        // Populate a graph with 1000 entities
        let graph = InMemoryGraph::new();
        let mut entities = Vec::with_capacity(1000);
        for i in 0..1000 {
            let e = test_entity(&format!("entity_{i}"), &format!("src/mod_{}.rs", i / 50));
            graph.upsert_entity(&e).unwrap();
            entities.push(e);
        }

        // Benchmark: upsert all 1000 entities with only non-indexed changes (signature)
        let start = std::time::Instant::now();
        for e in &entities {
            let mut updated = e.clone();
            updated.signature = format!("fn {}() -> bool", e.name);
            graph.upsert_entity(&updated).unwrap();
        }
        let unchanged_elapsed = start.elapsed();

        // Benchmark: upsert all 1000 entities with indexed field change (name)
        let start = std::time::Instant::now();
        for (i, e) in entities.iter().enumerate() {
            let mut updated = e.clone();
            updated.name = format!("renamed_{i}");
            graph.upsert_entity(&updated).unwrap();
        }
        let changed_elapsed = start.elapsed();

        // The unchanged path should be faster since it skips index remove+insert.
        // We don't assert a specific ratio (hardware-dependent) but verify correctness.
        eprintln!(
            "Delta index benchmark (1000 entities): unchanged={:?}, changed={:?}, ratio={:.2}x",
            unchanged_elapsed,
            changed_elapsed,
            changed_elapsed.as_nanos() as f64 / unchanged_elapsed.as_nanos().max(1) as f64,
        );

        // Verify indexes are still correct after all mutations
        let ent = graph.entities.read();
        assert_eq!(ent.indexes.by_name_pattern("renamed_0").len(), 1);
        assert!(ent.indexes.by_name_pattern("entity_0").is_empty());
    }

    // -----------------------------------------------------------------------
    // Embedding queue tests
    // -----------------------------------------------------------------------

    #[test]
    fn upsert_queues_entity_for_embedding() {
        let graph = InMemoryGraph::new();
        let e = test_entity("foo", "src/main.rs");
        graph.upsert_entity(&e).unwrap();

        #[cfg(feature = "vector")]
        {
            let status = graph.embedding_status();
            assert_eq!(status.pending + status.indexed, 1);
        }
        #[cfg(not(feature = "vector"))]
        assert_eq!(graph.pending_embeddings(), 0);
    }

    #[test]
    fn batch_upsert_queues_entities_for_embedding() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");

        graph.batch_upsert_entities(&[e1, e2]).unwrap();

        #[cfg(feature = "vector")]
        {
            let status = graph.embedding_status();
            assert_eq!(status.pending + status.indexed, 2);
        }
    }

    #[test]
    fn embedding_queue_deduplicates() {
        let graph = InMemoryGraph::new();
        let e = test_entity("foo", "src/main.rs");

        // Upsert the same entity twice — should only be queued once
        graph.upsert_entity(&e).unwrap();
        graph.upsert_entity(&e).unwrap();

        #[cfg(feature = "vector")]
        {
            let status = graph.embedding_status();
            assert_eq!(status.pending + status.indexed, 1);
        }
    }

    #[test]
    fn remove_entity_clears_embedding_queue() {
        let graph = InMemoryGraph::new();
        let e = test_entity("foo", "src/main.rs");
        graph.upsert_entity(&e).unwrap();
        graph.remove_entity(&e.id).unwrap();

        #[cfg(feature = "vector")]
        {
            let status = graph.embedding_status();
            assert_eq!(status.pending, 0);
            assert_eq!(status.indexed, 0);
        }
    }

    #[test]
    fn batch_remove_entities_clear_embedding_queue() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        graph
            .batch_upsert_entities(&[e1.clone(), e2.clone()])
            .unwrap();
        graph.batch_remove_entities(&[e1.id, e2.id]).unwrap();

        #[cfg(feature = "vector")]
        {
            let status = graph.embedding_status();
            assert_eq!(status.pending, 0);
            assert_eq!(status.indexed, 0);
        }
    }

    #[test]
    fn queue_all_for_embedding() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        // Clear the queue (it was populated by upserts)
        #[cfg(feature = "vector")]
        {
            graph.embedding_queue.lock().clear();
            assert_eq!(graph.pending_embeddings(), 0);

            // Now queue all
            graph.queue_all_for_embedding();
            assert_eq!(graph.pending_embeddings(), 2);
        }
    }

    #[cfg(feature = "vector")]
    #[test]
    fn queue_missing_for_embedding_only_enqueues_unindexed_entities() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        index.upsert(e1.id, &[1.0, 0.0]).unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        graph.embedding_queue.lock().clear();
        graph.queue_missing_for_embedding();
        assert_eq!(graph.pending_embeddings(), 1);
    }

    #[cfg(feature = "vector")]
    #[test]
    fn reset_vector_index_requeues_every_entity_for_rebuild() {
        // Simulates a stale-dimension rebuild: a repo arrives with a loaded
        // index that already covers every entity, so a normal pass would queue
        // nothing. Resetting must drop the index and let a full re-queue happen
        // so the rebuild produces a fresh index at the live embedder dimension.
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        index.upsert(e1.id, &[1.0, 0.0]).unwrap();
        index.upsert(e2.id, &[0.0, 1.0]).unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        // Precondition: index is loaded and reports full coverage, so the
        // incremental path would queue nothing.
        assert!(graph.vector_index.lock().is_some());
        assert_eq!(graph.embedding_status().indexed, 2);
        graph.embedding_queue.lock().clear();
        graph.queue_missing_for_embedding();
        assert_eq!(
            graph.pending_embeddings(),
            0,
            "fully-indexed graph should queue nothing without a reset"
        );

        // Reset drops the in-memory index; a full re-queue now covers all entities.
        graph.reset_vector_index();
        assert!(graph.vector_index.lock().is_none());
        assert_eq!(graph.embedding_status().indexed, 0);
        graph.queue_missing_for_embedding();
        assert_eq!(
            graph.pending_embeddings(),
            2,
            "reset must re-queue every entity for a clean dimension rebuild"
        );
    }

    /// One entity carrying the provenance a file-wide edit stamps on every
    /// declaration in the file: the file's blob hash and a concrete span.
    #[cfg(feature = "vector")]
    fn entity_in_edited_file(name: &str, file: &str, blob_hash: &str, start_line: u32) -> Entity {
        let mut entity = test_entity(name, file);
        entity
            .metadata
            .extra
            .insert("blob_hash".into(), serde_json::json!(blob_hash));
        entity.span = Some(kin_model::SourceSpan {
            file: FilePathId::new(file),
            start_byte: start_line as usize * 40,
            end_byte: start_line as usize * 40 + 30,
            start_line,
            start_col: 0,
            end_line: start_line + 3,
            end_col: 1,
        });
        entity
    }

    /// Re-stamp an entity the way a comment-only edit does: the file's blob
    /// hash is new and every declaration below the insertion shifts down. No
    /// name, signature, doc summary, or body preview moves, so nothing that
    /// reaches embed text changes.
    #[cfg(feature = "vector")]
    fn restamp_for_unrelated_file_edit(
        entity: &Entity,
        blob_hash: &str,
        line_shift: u32,
    ) -> Entity {
        let mut moved = entity.clone();
        moved
            .metadata
            .extra
            .insert("blob_hash".into(), serde_json::json!(blob_hash));
        moved.span = entity.span.as_ref().map(|span| kin_model::SourceSpan {
            start_byte: span.start_byte + line_shift as usize * 40,
            end_byte: span.end_byte + line_shift as usize * 40,
            start_line: span.start_line + line_shift,
            end_line: span.end_line + line_shift,
            ..span.clone()
        });
        moved
    }

    #[cfg(feature = "vector")]
    fn modified_delta(old: &Entity, new: &Entity) -> TransactionDelta {
        TransactionDelta {
            entity_deltas: vec![EntityDelta::Modified {
                old: old.clone(),
                new: new.clone(),
            }],
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        }
    }

    /// A comment-only edit stamps a new blob hash on every entity the file
    /// declares and shifts the spans below it, so the transaction carries one
    /// `Modified` delta per entity in the file. That provenance is real and must
    /// advance. Re-embedding all of it is not: an entity whose embed text is
    /// byte identical would only get its own vector back.
    ///
    /// This is FIR-2181's mechanism at its narrowest. On the measured store a
    /// seven-line comment produced 633 entity deltas and 633 pending
    /// embeddings, of which exactly 2 had any embed text change at all.
    #[cfg(feature = "vector")]
    #[test]
    fn file_wide_edit_reembeds_only_entities_whose_embed_text_changed() {
        let graph = InMemoryGraph::new();
        let file = "src/engine/graph.rs";
        let untouched_a = entity_in_edited_file("prune_orphaned_vectors", file, "blob-1", 10);
        let untouched_b = entity_in_edited_file("process_embedding_queue", file, "blob-1", 200);
        let edited = entity_in_edited_file("apply_transaction_delta", file, "blob-1", 400);
        graph
            .batch_upsert_entities(&[untouched_a.clone(), untouched_b.clone(), edited.clone()])
            .unwrap();
        graph.admit_artifact_for_test(
            file,
            TreeEntry::blob(Hash256::from_bytes([0x11; 32]), false),
        );
        graph.embedding_queue.lock().clear();
        assert_eq!(graph.pending_embeddings(), 0);

        // The two entities the comment did not touch: new blob hash, shifted
        // span, nothing else.
        let moved_a = restamp_for_unrelated_file_edit(&untouched_a, "blob-2", 7);
        let moved_b = restamp_for_unrelated_file_edit(&untouched_b, "blob-2", 7);
        // The one entity whose source actually changed, which also carries the
        // same new blob hash and shift.
        let mut rewritten = restamp_for_unrelated_file_edit(&edited, "blob-2", 7);
        rewritten.signature = "fn apply_transaction_delta(&self, delta: &TransactionDelta)".into();

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![
                    EntityDelta::Modified {
                        old: untouched_a.clone(),
                        new: moved_a.clone(),
                    },
                    EntityDelta::Modified {
                        old: untouched_b.clone(),
                        new: moved_b.clone(),
                    },
                    EntityDelta::Modified {
                        old: edited.clone(),
                        new: rewritten.clone(),
                    },
                ],
                relation_deltas: Vec::new(),
                tree_deltas: Vec::new(),
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();

        assert_eq!(
            graph.pending_embeddings(),
            1,
            "only the entity whose embed text changed may re-embed"
        );
        let queue = graph.embedding_queue.lock();
        assert!(queue.contains(&RetrievalKey::Entity(rewritten.id)));
        assert!(!queue.contains(&RetrievalKey::Entity(moved_a.id)));
        assert!(!queue.contains(&RetrievalKey::Entity(moved_b.id)));
        drop(queue);

        // Provenance still advanced for all three. The graph holds the new
        // blob hash and the shifted spans even for the entities that kept
        // their vectors, which is what makes this a narrowing of invalidation
        // rather than a dropped write.
        for expected in [&moved_a, &moved_b, &rewritten] {
            let stored = graph.get_entity(&expected.id).unwrap().unwrap();
            assert_eq!(
                stored.metadata.extra.get("blob_hash"),
                Some(&serde_json::json!("blob-2"))
            );
            assert_eq!(stored.span.as_ref().map(|s| s.start_line), {
                expected.span.as_ref().map(|s| s.start_line)
            });
        }
    }

    /// The control that keeps the fix from over-pruning. Every field that
    /// reaches embed text must still invalidate on its own, or the narrowing
    /// silently serves stale vectors.
    #[cfg(feature = "vector")]
    #[test]
    fn every_embed_text_field_still_invalidates_on_its_own() {
        let file = "src/engine/graph.rs";
        let cases: Vec<(&str, Box<dyn Fn(&mut Entity)>)> = vec![
            (
                "name",
                Box::new(|e: &mut Entity| e.name = "renamed_symbol".into()),
            ),
            (
                "signature",
                Box::new(|e: &mut Entity| e.signature = "fn changed(arg: usize)".into()),
            ),
            (
                "doc_summary",
                Box::new(|e: &mut Entity| e.doc_summary = Some("A new summary line.".into())),
            ),
            (
                "body_preview",
                Box::new(|e: &mut Entity| {
                    e.metadata.extra.insert(
                        crate::embed::EMBEDDING_BODY_PREVIEW_KEY.into(),
                        serde_json::json!("let next = compute();"),
                    );
                }),
            ),
            (
                "kind",
                Box::new(|e: &mut Entity| e.kind = EntityKind::Class),
            ),
            (
                "file_origin",
                Box::new(|e: &mut Entity| e.file_origin = Some(FilePathId::new("src/moved.rs"))),
            ),
            (
                "file_import_context",
                Box::new(|e: &mut Entity| {
                    e.metadata.extra.insert(
                        crate::embed::FILE_IMPORT_CONTEXT_KEY.into(),
                        serde_json::json!("use crate::engine::graph::GraphTruth;"),
                    );
                }),
            ),
            (
                "file_surface_context",
                Box::new(|e: &mut Entity| {
                    e.metadata.extra.insert(
                        crate::embed::FILE_SURFACE_CONTEXT_KEY.into(),
                        serde_json::json!("pub fn surface_shape() -> Shape"),
                    );
                }),
            ),
        ];

        for (label, mutate) in cases {
            let graph = InMemoryGraph::new();
            let before = entity_in_edited_file("target_symbol", file, "blob-1", 10);
            graph.batch_upsert_entities(&[before.clone()]).unwrap();
            for path in [file, "src/moved.rs"] {
                graph.admit_artifact_for_test(
                    path,
                    TreeEntry::blob(Hash256::from_bytes([0x11; 32]), false),
                );
            }
            graph.embedding_queue.lock().clear();
            assert_eq!(
                graph.pending_embeddings(),
                0,
                "{label}: queue must start dry"
            );

            let mut after = restamp_for_unrelated_file_edit(&before, "blob-2", 7);
            mutate(&mut after);

            graph
                .apply_transaction_delta(&modified_delta(&before, &after))
                .unwrap();

            assert_eq!(
                graph.pending_embeddings(),
                1,
                "{label} reaches embed text and must still invalidate"
            );
        }
    }

    /// Embed text carries graph-derived context lines, so an entity whose own
    /// payload formats identically still embeds differently when a relation it
    /// takes part in changes. The skip set must yield to that.
    #[cfg(feature = "vector")]
    #[test]
    fn a_relation_delta_invalidates_an_endpoint_whose_own_text_is_unchanged() {
        let graph = InMemoryGraph::new();
        let file = "src/engine/graph.rs";
        let caller = entity_in_edited_file("caller", file, "blob-1", 10);
        let callee = entity_in_edited_file("callee", file, "blob-1", 90);
        graph
            .batch_upsert_entities(&[caller.clone(), callee.clone()])
            .unwrap();
        graph.admit_artifact_for_test(
            file,
            TreeEntry::blob(Hash256::from_bytes([0x11; 32]), false),
        );
        graph.embedding_queue.lock().clear();
        assert_eq!(graph.pending_embeddings(), 0);

        let moved_caller = restamp_for_unrelated_file_edit(&caller, "blob-2", 7);
        let moved_callee = restamp_for_unrelated_file_edit(&callee, "blob-2", 7);
        let relation = test_relation(caller.id, callee.id, RelationKind::Calls);

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![
                    EntityDelta::Modified {
                        old: caller.clone(),
                        new: moved_caller.clone(),
                    },
                    EntityDelta::Modified {
                        old: callee.clone(),
                        new: moved_callee.clone(),
                    },
                ],
                relation_deltas: vec![RelationDelta::Added {
                    new: relation.clone(),
                }],
                tree_deltas: Vec::new(),
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();

        assert_eq!(
            graph.pending_embeddings(),
            2,
            "both endpoints of a changed relation re-embed even with identical own text"
        );
    }

    /// What the snapshot-based comparison actually costs as history deepens,
    /// and what it costs to answer the same question without cloning.
    ///
    /// This is the measurement behind FIR-2258. The claim under test is narrow
    /// and falsifiable: the cost of comparing two graphs through `to_snapshot`
    /// is driven by the sub-stores a workspace comparison never reads, so it
    /// grows with a repository's history while the workspace itself stands
    /// still. If that were wrong, both columns would grow together and the
    /// ratio would stay flat.
    ///
    /// The `rebuild_us` column is measured beside the comparisons so the two
    /// candidate terms can be ranked instead of guessed at, and on this
    /// evidence it dominates: rebuilding the graph costs more than an order of
    /// magnitude what all of a commit's comparisons cost together. It is a
    /// lower bound on the real reload, which also opens the repository and
    /// deserializes off disk. It is printed and not asserted, because the
    /// ranking is what the reader needs and pinning it would turn a future
    /// improvement to the reload into a red test.
    ///
    /// Ignored by default because it is a timing measurement, not a gate. Run
    /// it with `cargo test --features vector -- --ignored --nocapture
    /// workspace_comparison_cost`. The assertions are deliberately loose: they
    /// fail only if the clone-free form stops being dramatically cheaper or the
    /// gap stops widening with history, both structural changes rather than a
    /// slow machine.
    #[cfg(feature = "vector")]
    #[test]
    #[ignore = "timing measurement for FIR-2258, not a gate"]
    fn workspace_comparison_cost_grows_with_history_the_comparison_never_reads() {
        /// One entity per declaration in a file, restamped once per generation
        /// exactly as a comment-only edit restamps every entity in its file.
        fn build(entities: usize, generations: u8) -> InMemoryGraph {
            let graph = InMemoryGraph::new();
            let file = "src/engine/graph.rs";
            let mut live: Vec<Entity> = (0..entities)
                .map(|index| {
                    entity_in_edited_file(&format!("entity_{index}"), file, "blob-0", index as u32)
                })
                .collect();
            apply_init_change(&graph, 0x01, &live);
            graph.admit_artifact_for_test(
                file,
                TreeEntry::blob(Hash256::from_bytes([0x11; 32]), false),
            );
            for generation in 1..=generations {
                let blob = format!("blob-{generation}");
                let moved: Vec<(Entity, Entity)> = live
                    .iter()
                    .map(|entity| {
                        (
                            entity.clone(),
                            restamp_for_unrelated_file_edit(entity, &blob, u32::from(generation)),
                        )
                    })
                    .collect();
                apply_commit_change(&graph, 0x02 + generation, &moved);
                live = moved.into_iter().map(|(_, new)| new).collect();
            }
            graph
        }

        /// The comparison exactly as the commit reply path wrote it before the
        /// engine could answer without cloning.
        fn matches_via_snapshot(left: &InMemoryGraph, right: &InMemoryGraph) -> bool {
            let left = left.to_snapshot();
            let right = right.to_snapshot();
            left.entities == right.entities
                && left.relations == right.relations
                && left.resolved_tree == right.resolved_tree
        }

        const ENTITIES: usize = 200;
        println!("entities={ENTITIES}  (one comparison, both sides)");
        // `rebuild_us` is the in-memory half of what the commit reply's
        // `load_native_commit_base` pays before either comparison runs. It is a
        // LOWER BOUND on that step: the real one also opens the repository and
        // deserializes the snapshot off disk, neither of which is timed here.
        // It is measured beside the comparisons so the two candidate terms can
        // be ranked rather than guessed at.
        println!("generations  snapshot_us  clone_free_us  ratio  rebuild_us");
        let mut ratios = Vec::new();
        for generations in [1u8, 8, 24] {
            let left = build(ENTITIES, generations);
            let right = InMemoryGraph::from_snapshot(left.to_snapshot()).unwrap();

            let started = std::time::Instant::now();
            assert!(matches_via_snapshot(&left, &right));
            let snapshot_us = started.elapsed().as_micros().max(1);

            let started = std::time::Instant::now();
            assert!(left.semantic_workspace_matches(&right));
            let clone_free_us = started.elapsed().as_micros().max(1);

            let carried = left.to_snapshot();
            let started = std::time::Instant::now();
            let rebuilt = InMemoryGraph::from_snapshot(carried).unwrap();
            let rebuild_us = started.elapsed().as_micros().max(1);
            assert!(left.semantic_workspace_matches(&rebuilt));

            let ratio = snapshot_us as f64 / clone_free_us as f64;
            println!(
                "{generations:>11}  {snapshot_us:>11}  {clone_free_us:>13}  {ratio:>5.1}x  {rebuild_us:>10}"
            );
            ratios.push(ratio);
        }

        // The workspace is identical in every row: same entities, same
        // relations, same tree. Only history deepened. If the snapshot form
        // were not paying for history, this would not hold.
        assert!(
            *ratios.last().unwrap() > 4.0,
            "the clone-free comparison must stay dramatically cheaper as history deepens; ratios {ratios:?}"
        );
        assert!(
            ratios.last().unwrap() > ratios.first().unwrap(),
            "the gap must widen with history, since history is what only the snapshot form reads; ratios {ratios:?}"
        );
    }

    /// The commit reply path compares the live graph against reloaded
    /// repository authority twice per commit, and used to do it by cloning both
    /// whole graphs each time. The comparison must read exactly the three
    /// workspace fields and stay blind to everything a snapshot also carries,
    /// or the cheap form is not the same question as the expensive one.
    #[cfg(feature = "vector")]
    #[test]
    fn workspace_equality_reads_entities_relations_and_tree_only() {
        let left = InMemoryGraph::new();
        let right = InMemoryGraph::new();
        assert!(
            left.semantic_workspace_matches(&right),
            "two empty graphs agree"
        );
        assert!(
            left.semantic_workspace_matches(&left),
            "a graph agrees with itself"
        );

        let entity = test_entity("foo", "src/a.rs");
        left.batch_upsert_entities(std::slice::from_ref(&entity))
            .unwrap();
        assert!(
            !left.semantic_workspace_matches(&right),
            "an entity present on one side is a workspace difference"
        );
        right
            .batch_upsert_entities(std::slice::from_ref(&entity))
            .unwrap();
        assert!(
            left.semantic_workspace_matches(&right),
            "the same entity on both sides agrees"
        );

        // Revision history and the change DAG are carried by a snapshot and are
        // not the workspace. Comparing through `to_snapshot` never
        // distinguished them either, so the cheap form has to stay equally
        // blind, and they are exactly the sub-stores whose growth made the
        // expensive form cost minutes.
        apply_init_change(&left, 0x01, std::slice::from_ref(&entity));
        assert!(
            left.semantic_workspace_matches(&right),
            "revision history and changes must not decide workspace equality"
        );
    }

    /// Drive one commit the way the transactional write path does: seal the
    /// change, which appends a revision generation per touched entity, then
    /// apply the same deltas to live entity state.
    #[cfg(feature = "vector")]
    fn apply_commit_change(graph: &InMemoryGraph, change_byte: u8, modified: &[(Entity, Entity)]) {
        let entity_deltas: Vec<EntityDelta> = modified
            .iter()
            .map(|(old, new)| EntityDelta::Modified {
                old: old.clone(),
                new: new.clone(),
            })
            .collect();
        let change = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([change_byte; 32])),
            parents: vec![],
            timestamp: Timestamp(
                chrono::DateTime::from_timestamp(1_700_000_000 + i64::from(change_byte), 0)
                    .expect("test timestamp is representable"),
            ),
            author: AuthorId::new("test"),
            message: "commit".to_string(),
            entity_deltas: entity_deltas.clone(),
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });
        graph.create_change(&change).unwrap();
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas,
                relation_deltas: Vec::new(),
                tree_deltas: Vec::new(),
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();
    }

    /// The embedding queue is what the background worker drains and what it
    /// reports as `remaining`, so a retrieval key missing its vector and absent
    /// from the queue is work nothing will ever do, announced as finished. The
    /// queue must always account for at least the coverage gap.
    #[cfg(feature = "vector")]
    fn assert_queue_accounts_for_missing_coverage(graph: &InMemoryGraph) {
        let status = graph.embedding_status();
        let missing = status.total.saturating_sub(status.indexed);
        let queued = graph.pending_embeddings();
        assert!(
            queued >= missing,
            "queue reports {queued} remaining while {missing} retrieval keys carry no vector"
        );
    }

    /// FIR-2254. Every commit appends a new HEAD `EntityRevision` per touched
    /// entity, and `graph_truth_retrievable_keys` counts HEAD revision keys as
    /// coverage, so a commit hands the store one retrieval key per touched
    /// entity with no vector behind it while the prune retires the generation
    /// each one replaced. Nothing filled them: the transaction path invalidates
    /// `RetrievalKey::Entity` only, the background worker embeds what is queued
    /// rather than what is missing, and the queue drained to empty with the work
    /// outstanding. A 3166-entity store lost 641 vectors to one comment-only
    /// edit, then 210 more to the next, and stayed down until an operator
    /// noticed the counter and ran `kin embed` by hand.
    ///
    /// A comment between declarations restamps blob hashes and shifts spans, and
    /// neither reaches the formatted embed text, so the superseded generation's
    /// vector is the correct vector for the key that replaced it and is carried
    /// onto it without inference.
    ///
    /// Discriminating: on the shipped behavior `indexed` falls by one per
    /// touched entity while the queue reads empty, so both assertions fail.
    #[cfg(feature = "vector")]
    #[test]
    fn comment_only_commit_keeps_vector_coverage_complete() {
        let graph = InMemoryGraph::new();
        let file = "src/engine/graph.rs";
        let untouched_a = entity_in_edited_file("prune_orphaned_vectors", file, "blob-1", 10);
        let untouched_b = entity_in_edited_file("process_embedding_queue", file, "blob-1", 200);
        let untouched_c = entity_in_edited_file("apply_transaction_delta", file, "blob-1", 400);
        let originals = [untouched_a, untouched_b, untouched_c];
        apply_init_change(&graph, 0x01, &originals);
        graph.admit_artifact_for_test(
            file,
            TreeEntry::blob(Hash256::from_bytes([0x11; 32]), false),
        );
        embed_all_retrievable(&graph);
        graph.embedding_queue.lock().clear();

        let before = graph.embedding_status();
        assert_eq!(
            before.indexed, before.total,
            "the fixture must start at full coverage"
        );
        assert_eq!(
            before.pending, 0,
            "the fixture must start with a drained queue"
        );

        let moved: Vec<(Entity, Entity)> = originals
            .iter()
            .map(|entity| {
                (
                    entity.clone(),
                    restamp_for_unrelated_file_edit(entity, "blob-2", 7),
                )
            })
            .collect();
        apply_commit_change(&graph, 0x02, &moved);

        let after = graph.embedding_status();
        assert_eq!(
            after.total, before.total,
            "the commit replaces revision keys one for one, so truth must not grow"
        );
        assert_eq!(
            after.indexed, after.total,
            "a comment-only commit must not cost the store vector coverage"
        );
        assert_eq!(
            after.pending, 0,
            "carried vectors leave nothing for the background pass to do"
        );
        assert_queue_accounts_for_missing_coverage(&graph);
    }

    /// The other half of FIR-2254's acceptance. When a commit does change embed
    /// text the vector cannot be carried, so the revision key it mints has to be
    /// QUEUED. Coverage that is short with an empty queue is the exact state the
    /// daemon reported as `remaining=0`: it drains what is queued, not what is
    /// missing, so an unqueued gap is never repaired and never announced.
    ///
    /// Discriminating: on the shipped behavior only the HEAD entity key is
    /// queued while two keys are short, so the accounting assertion fails.
    #[cfg(feature = "vector")]
    #[test]
    fn commit_queues_the_revision_key_whose_embed_text_changed() {
        let graph = InMemoryGraph::new();
        let file = "src/engine/graph.rs";
        let untouched_a = entity_in_edited_file("prune_orphaned_vectors", file, "blob-1", 10);
        let untouched_b = entity_in_edited_file("process_embedding_queue", file, "blob-1", 200);
        let edited = entity_in_edited_file("apply_transaction_delta", file, "blob-1", 400);
        apply_init_change(
            &graph,
            0x01,
            &[untouched_a.clone(), untouched_b.clone(), edited.clone()],
        );
        graph.admit_artifact_for_test(
            file,
            TreeEntry::blob(Hash256::from_bytes([0x11; 32]), false),
        );
        embed_all_retrievable(&graph);
        graph.embedding_queue.lock().clear();

        let mut rewritten = restamp_for_unrelated_file_edit(&edited, "blob-2", 7);
        rewritten.signature = "fn apply_transaction_delta(&self, delta: &TransactionDelta)".into();
        apply_commit_change(
            &graph,
            0x02,
            &[
                (
                    untouched_a.clone(),
                    restamp_for_unrelated_file_edit(&untouched_a, "blob-2", 7),
                ),
                (
                    untouched_b.clone(),
                    restamp_for_unrelated_file_edit(&untouched_b, "blob-2", 7),
                ),
                (edited.clone(), rewritten),
            ],
        );

        let status = graph.embedding_status();
        assert_eq!(
            status.total.saturating_sub(status.indexed),
            2,
            "only the rewritten entity's HEAD entity and HEAD revision keys lose their vectors"
        );
        assert_queue_accounts_for_missing_coverage(&graph);
    }

    /// Add `entities` to the graph under a fresh change id, recording one
    /// `EntityRevision` per entity (mirrors `kin init`, whose change id is seeded
    /// with a timestamp so every re-init mints new revision keys).
    #[cfg(feature = "vector")]
    fn apply_init_change(
        graph: &InMemoryGraph,
        change_byte: u8,
        entities: &[Entity],
    ) -> SemanticChange {
        let change = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([change_byte; 32])),
            parents: vec![],
            timestamp: Timestamp(
                chrono::DateTime::from_timestamp(1_700_000_000 + i64::from(change_byte), 0)
                    .expect("test timestamp is representable"),
            ),
            author: AuthorId::new("test"),
            message: "init".to_string(),
            entity_deltas: entities
                .iter()
                .map(|e| EntityDelta::Added { new: e.clone() })
                .collect(),
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });
        graph.create_change(&change).unwrap();
        graph.batch_upsert_entities(entities).unwrap();
        change
    }

    /// Synthetically "embed" every current graph-truth retrievable key by
    /// upserting a unit vector — exercises the index lifecycle without a GPU or
    /// the `embeddings` feature (so it cannot reach `get_vector_index`).
    #[cfg(feature = "vector")]
    fn embed_all_retrievable(graph: &InMemoryGraph) {
        {
            let mut guard = graph.vector_index.lock();
            if guard.is_none() {
                *guard = Some(Arc::new(VectorIndex::new(2).unwrap()));
            }
        }
        let vi = graph.vector_index.lock().clone().unwrap();
        for key in graph.graph_truth_retrievable_keys() {
            vi.upsert_retrievable(key, &[1.0, 0.0]).unwrap();
        }
    }

    /// Gate for #21: across init → embed → re-init → re-embed the vector index
    /// must converge to the true target count, not accumulate stale revision
    /// generations.
    ///
    /// Production re-init builds a FRESH graph under a new change id, so every
    /// entity gets a brand-new `EntityRevision` key. The prior generation's
    /// revision vectors survive only in the persisted sidecar; once that sidecar
    /// is loaded into the new graph they are orphans relative to current truth.
    /// `prune_orphaned_vectors` reconciles the index back to graph truth.
    #[cfg(feature = "vector")]
    #[test]
    fn reembed_after_reinit_converges_to_true_target_count() {
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        let entities = [e1, e2];
        let dir = tempfile::TempDir::new().unwrap();
        let sidecar = dir.path().join("vectors.kvec");

        // init (generation 1) → embed → persist sidecar
        let gen1 = InMemoryGraph::new();
        apply_init_change(&gen1, 0x01, &entities);
        let target = gen1.graph_truth_retrievable_keys().len();
        // 2 HEAD entities + 2 revisions (generation 1).
        assert_eq!(target, 4);
        embed_all_retrievable(&gen1);
        assert_eq!(gen1.vector_index_stats().unwrap().1, target);
        gen1.save_vector_index(&sidecar).unwrap();

        // re-init: a fresh graph under a NEW change id. Generation-1 revision
        // keys exist only in the sidecar now, not in this graph's truth.
        let gen2 = InMemoryGraph::new();
        apply_init_change(&gen2, 0x02, &entities);
        let target_after = gen2.graph_truth_retrievable_keys().len();
        assert_eq!(target_after, 4);

        // Reopen reuses the persisted sidecar (entity content unchanged → root
        // hash matches), dragging the generation-1 revision vectors back in.
        let loaded = gen2.load_vector_index(&sidecar).unwrap();
        assert_eq!(
            loaded, target,
            "sidecar carries the full generation-1 index"
        );

        // Re-embed the current generation. Its HEAD-entity keys replace, but the
        // generation-2 revision keys are new — so without eviction the index now
        // holds BOTH generations' revision vectors (stale-generation bloat).
        embed_all_retrievable(&gen2);
        let before_prune = gen2.vector_index_stats().unwrap().1;
        assert!(
            before_prune > target_after,
            "expected stale-generation accumulation before pruning ({before_prune} vs {target_after})"
        );

        // GATE: eviction reconciles the index to graph truth.
        let evicted = gen2.prune_orphaned_vectors();
        assert_eq!(evicted, before_prune - target_after);
        assert_eq!(
            gen2.vector_index_stats().unwrap().1,
            target_after,
            "index must equal the true target count after re-embed + prune"
        );

        // Idempotent: a clean index prunes nothing.
        assert_eq!(gen2.prune_orphaned_vectors(), 0);
    }

    /// Index keys that resolve through revision history to an entity the graph
    /// no longer holds. This mirrors the daemon's retired-key gate: retrieval
    /// ranks such a key, resolves it to a snapshot of a dead entity, drops it,
    /// and reports the drop as a `retired_entity_keys` degradation. The count
    /// here is therefore the number of degradation-producing keys the store
    /// would hand every query.
    #[cfg(feature = "vector")]
    fn count_index_keys_resolving_to_dead_entities(graph: &InMemoryGraph) -> usize {
        let vi = graph
            .vector_index
            .lock()
            .clone()
            .expect("vector index installed");
        vi.retrievable_keys()
            .into_iter()
            .filter(|key| match graph.resolve_retrieval_key(key) {
                Some(ResolvedRetrievalItem::Entity(entity)) => {
                    graph.get_entity(&entity.id).unwrap().is_none()
                }
                _ => false,
            })
            .count()
    }

    /// A store whose history contains a chain for an entity the graph no longer
    /// holds, embedded fresh to full coverage, must hand retrieval zero keys it
    /// can only drop. Whole-history ingest derives a revision chain for every
    /// entity that ever existed and removal ends a chain without deleting it,
    /// so truth admitting those chain heads made every query rank dead keys,
    /// drop them, and warn, while the prune kept their vectors and a re-embed
    /// re-queued them. Assertions are on counts and set membership so this
    /// fails when dead heads are admitted as truth again.
    #[cfg(feature = "vector")]
    #[test]
    fn fresh_full_coverage_over_dead_chain_history_holds_zero_retired_keys() {
        let live = test_entity("live_fn", "src/live.rs");
        let retired = test_entity("retired_fn", "src/retired.rs");
        let graph = InMemoryGraph::new();
        apply_init_change(&graph, 0x01, &[live.clone(), retired.clone()]);

        // History ends the retired entity's chain without deleting it.
        graph.remove_entity(&retired.id).unwrap();
        let (live_head_key, retired_head_key) = {
            let ent = graph.entities.read();
            assert!(
                ent.entity_revisions.contains_key(&retired.id),
                "removal must keep the revision chain (history is append-only)"
            );
            assert!(!ent.entities.contains_key(&retired.id));
            (
                RetrievalKey::EntityRevision(
                    ent.entity_revisions[&live.id].last().unwrap().revision_id,
                ),
                RetrievalKey::EntityRevision(
                    ent.entity_revisions[&retired.id]
                        .last()
                        .unwrap()
                        .revision_id,
                ),
            )
        };

        // Truth is the live set only: the dead chain's head is out, the live
        // entity's keys are in (positive controls prove the lookups can hit).
        let truth = graph.graph_truth_retrievable_keys();
        assert!(truth.contains(&RetrievalKey::Entity(live.id)));
        assert!(truth.contains(&live_head_key));
        assert!(!truth.contains(&retired_head_key));
        assert_eq!(truth.len(), 2);

        // Init-time invalidation queued work the synthetic embed below never
        // drains; drop it so `pending` reflects coverage alone.
        graph.embedding_queue.lock().clear();

        // A fresh full-coverage embed over this history mints no droppable key,
        // and coverage counts exactly the servable universe.
        embed_all_retrievable(&graph);
        let status = graph.embedding_status();
        assert_eq!((status.indexed, status.pending, status.total), (2, 0, 2));
        assert_eq!(count_index_keys_resolving_to_dead_entities(&graph), 0);

        // A full re-queue admits live keys and never the dead head, so a
        // re-embed cannot reintroduce what retrieval must drop.
        graph.queue_all_for_embedding();
        let queue = graph.embedding_queue.lock();
        assert!(queue.contains(&RetrievalKey::Entity(live.id)));
        assert!(queue.contains(&live_head_key));
        assert!(!queue.contains(&retired_head_key));
    }

    /// Retiring an entity that already has vectors must stay visible until
    /// reconciled, then actually reconcile: the surviving head-revision vector
    /// counts as a droppable key while it lingers, one prune evicts exactly
    /// that vector, and the missing-coverage backfill does not queue it back.
    /// This is the discriminating pair to the fresh-store gate above: a real
    /// retirement still surfaces, and the re-embed remediation genuinely
    /// resolves it instead of churning forever.
    #[cfg(feature = "vector")]
    #[test]
    fn retiring_an_embedded_entity_is_reclaimed_by_prune_not_requeued() {
        let live = test_entity("live_fn", "src/live.rs");
        let retired = test_entity("retired_fn", "src/retired.rs");
        let graph = InMemoryGraph::new();
        apply_init_change(&graph, 0x01, &[live.clone(), retired.clone()]);
        embed_all_retrievable(&graph);

        // Init-time invalidation queued work the synthetic embed above never
        // drains; drop it so `pending` reflects coverage alone.
        graph.embedding_queue.lock().clear();

        // Consume the initial full-reconcile flag on a clean store: nothing to
        // evict, nothing droppable.
        assert_eq!(graph.prune_orphaned_vectors(), 0);
        assert_eq!(count_index_keys_resolving_to_dead_entities(&graph), 0);

        let retired_head_key = {
            let ent = graph.entities.read();
            RetrievalKey::EntityRevision(
                ent.entity_revisions[&retired.id]
                    .last()
                    .unwrap()
                    .revision_id,
            )
        };

        // Removal drops the HEAD-entity vector immediately but the revision
        // vector survives until reconcile, so retrieval genuinely has one key
        // it must drop: the degradation channel carries real signal here.
        graph.remove_entity(&retired.id).unwrap();
        assert_eq!(count_index_keys_resolving_to_dead_entities(&graph), 1);

        // Removal forces a full reconcile; the prune evicts exactly the dead
        // head and the store returns to a zero-drop steady state.
        assert_eq!(graph.prune_orphaned_vectors(), 1);
        assert_eq!(count_index_keys_resolving_to_dead_entities(&graph), 0);
        let status = graph.embedding_status();
        assert_eq!((status.indexed, status.pending, status.total), (2, 0, 2));

        // The backfill agrees with the prune: nothing is missing, and the dead
        // head is not re-queued for embedding.
        graph.queue_missing_for_embedding();
        let queue = graph.embedding_queue.lock();
        assert_eq!(queue.len(), 0);
        assert!(!queue.contains(&retired_head_key));
    }

    /// Source-level convergence: re-importing unchanged content must not append a
    /// redundant revision generation, regardless of whether the re-init reused
    /// the same change id (same-second) or minted a fresh one. A genuine content
    /// change still records a new revision.
    #[cfg(feature = "vector")]
    #[test]
    fn reinit_over_unchanged_content_records_no_new_revision() {
        let e1 = test_entity("foo", "src/a.rs");
        let entities = [e1.clone()];
        let graph = InMemoryGraph::new();

        let rev_count = |g: &InMemoryGraph| -> usize {
            let ent = g.entities.read();
            ent.entity_revisions.values().map(|v| v.len()).sum()
        };

        let first_change = apply_init_change(&graph, 0x01, &entities);
        assert_eq!(rev_count(&graph), 1);
        assert_eq!(graph.graph_truth_retrievable_keys().len(), 2);

        // Retrying the exact same change payload is idempotent and does not
        // append a revision. Reusing the ID for a different payload is rejected
        // by the immutable-change guard.
        graph.create_change(&first_change).unwrap();
        graph.batch_upsert_entities(&entities).unwrap();
        assert_eq!(rev_count(&graph), 1, "same-id re-init must not duplicate");

        // Fresh change id (re-init seconds later) — still unchanged content, so
        // still no new generation.
        apply_init_change(&graph, 0x02, &entities);
        assert_eq!(rev_count(&graph), 1, "fresh-id re-init must converge");
        assert_eq!(graph.graph_truth_retrievable_keys().len(), 2);

        // A genuine content change DOES record a new revision.
        let mut changed = e1;
        changed.signature = "fn foo(x: i32)".to_string();
        changed.fingerprint.signature_hash = Hash256::from_bytes([7; 32]);
        apply_init_change(&graph, 0x03, &[changed]);
        assert_eq!(rev_count(&graph), 2, "real change must record a revision");
    }

    /// Build entity `e1` with a two-generation revision chain (revision 1
    /// superseded by revision 2, both retained in history) and return its
    /// (old, new) revision ids.
    #[cfg(feature = "vector")]
    fn two_revision_entity(
        graph: &InMemoryGraph,
        e1: &Entity,
    ) -> (EntityRevisionId, EntityRevisionId) {
        apply_init_change(graph, 0x01, std::slice::from_ref(e1));
        let mut changed = e1.clone();
        changed.signature = "fn foo(x: i32)".to_string();
        changed.fingerprint.signature_hash = Hash256::from_bytes([7; 32]);
        apply_init_change(graph, 0x02, &[changed]);

        let ent = graph.entities.read();
        let chain = ent
            .entity_revisions
            .get(&e1.id)
            .expect("entity must have a revision chain");
        assert_eq!(chain.len(), 2, "entity must hold an old + new revision");
        let pair = (chain[0].revision_id, chain[1].revision_id);
        assert_ne!(pair.0, pair.1, "the two generations must be distinct keys");
        pair
    }

    /// Live re-embed retire: a re-embed that appends a new revision
    /// for an entity must leave exactly ONE vector for that entity — the new
    /// revision's. The superseded generation is still referenced by the entity's
    /// revision history, so before the fix `prune_orphaned_vectors` (whose truth
    /// Saving the vector sidecar must not hold the slot that a commit's own
    /// change install needs.
    ///
    /// `save` performs the index's deferred HNSW insertion for every unindexed
    /// vector before it writes, which is O(index); `create_change` reaches the
    /// same slot in `admit_minted_revision_vectors` to decide whether the new
    /// revision key owes a vector. Holding the slot across the save is what put
    /// an 11.1 s wait inside a one-entity commit's `install_live_graph` phase on
    /// a 26.7k-entity store, with no work of its own to show for it.
    ///
    /// The hook runs on the saving thread and `parking_lot::Mutex` is not
    /// reentrant, so `try_lock` succeeding is exactly the proof that the guard
    /// is gone. Restoring the guard around the save fails this test.
    #[cfg(feature = "vector")]
    #[test]
    fn save_vector_index_releases_the_index_slot_before_saving() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("graph.kvec");
        let graph = InMemoryGraph::new();
        let entity = test_entity("saved_owner", "src/saved.rs");
        let vi = VectorIndex::new(2).unwrap();
        vi.upsert(entity.id, &[1.0f32, 0.0]).unwrap();
        vi.set_descriptor(crate::vector::IndexDescriptor {
            model_id: Some("test-model".to_string()),
            graph_root: Some("test-root".to_string()),
        });
        *graph.vector_index.lock() = Some(Arc::new(vi));

        let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let free = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed_hook = Arc::clone(&observed);
        let free_hook = Arc::clone(&free);
        set_save_vector_index_after_detach_hook(move |graph| {
            observed_hook.store(1, Ordering::SeqCst);
            free_hook.store(graph.vector_index.try_lock().is_some(), Ordering::SeqCst);
        });

        graph.save_vector_index(&path).unwrap();

        assert_eq!(
            observed.load(Ordering::SeqCst),
            1,
            "the observation point must run, or this test proves nothing"
        );
        assert!(
            free.load(Ordering::SeqCst),
            "the vector index slot must be reachable while the sidecar saves"
        );
        assert!(path.exists(), "the sidecar must still be written");
        let reloaded = VectorIndex::load_from_disk(&path).unwrap();
        assert_eq!(
            reloaded.get(&entity.id),
            Some(vec![1.0f32, 0.0]),
            "detaching the handle must not change what the save persists"
        );
    }

    /// admitted every generation) kept BOTH vectors and `semantic_locate`
    /// returned the entity twice with two distinct cosine scores. Discriminating:
    /// FAILS on the old all-revisions truth (evicts 0), PASSES on head-only truth.
    #[cfg(feature = "vector")]
    #[test]
    fn live_reembed_retires_superseded_revision_vector() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let (rev_old, rev_new) = two_revision_entity(&graph, &e1);

        // The doubled state a live re-embed leaves behind: revision 1's vector
        // (indexed earlier) AND revision 2's vector (the re-embed) both live,
        // each a DISTINCT vector under the SAME entity.
        let vi = VectorIndex::new(2).unwrap();
        let vec_old = [1.0f32, 0.0];
        let vec_new = [0.0f32, 1.0];
        vi.upsert_retrievable(RetrievalKey::EntityRevision(rev_old), &vec_old)
            .unwrap();
        vi.upsert_retrievable(RetrievalKey::EntityRevision(rev_new), &vec_new)
            .unwrap();
        vi.upsert(e1.id, &vec_new).unwrap(); // HEAD entity key (kept by truth)
        *graph.vector_index.lock() = Some(Arc::new(vi));

        let evicted = graph.prune_orphaned_vectors();
        assert_eq!(
            evicted, 1,
            "exactly the superseded revision-1 vector must be retired"
        );

        let vi = graph.vector_index.lock().clone().unwrap();
        assert!(
            vi.get_retrievable(&RetrievalKey::EntityRevision(rev_old))
                .is_none(),
            "superseded revision-1 vector must be gone"
        );
        assert_eq!(
            vi.get_retrievable(&RetrievalKey::EntityRevision(rev_new)),
            Some(vec_new.to_vec()),
            "head revision-2 vector must survive unchanged"
        );
        assert!(
            vi.contains(&e1.id),
            "HEAD entity vector is current truth and must remain"
        );
        // Idempotent once converged.
        assert_eq!(graph.prune_orphaned_vectors(), 0);
    }

    /// Incremental prune: after the first full reconcile, a subsequent re-embed
    /// supersession is retired by evicting ONLY the tracked orphan key — without
    /// rescanning the whole index — and the result matches what a full scan would
    /// have produced. Guards the incremental-prune fast path.
    #[cfg(feature = "vector")]
    #[test]
    fn prune_incremental_evicts_only_tracked_superseded_vectors() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let (rev_old, rev_new) = two_revision_entity(&graph, &e1);

        // Index the doubled state (retrievable keyspace, as the embed path does)
        // and let the FIRST prune reconcile fully (fresh graph ⇒ `full` is set),
        // retiring the generation-1 vector.
        let vi = VectorIndex::new(2).unwrap();
        vi.upsert_retrievable(RetrievalKey::EntityRevision(rev_old), &[1.0, 0.0])
            .unwrap();
        vi.upsert_retrievable(RetrievalKey::EntityRevision(rev_new), &[0.0, 1.0])
            .unwrap();
        vi.upsert_retrievable(RetrievalKey::Entity(e1.id), &[0.0, 1.0])
            .unwrap();
        *graph.vector_index.lock() = Some(Arc::new(vi));
        assert_eq!(
            graph.prune_orphaned_vectors(),
            1,
            "full reconcile retires the generation-1 revision"
        );

        // A second content change supersedes revision 2 through the normal
        // `create_change` path, which records revision 2 as a tracked orphan and
        // leaves the reconcile state incremental (no forced full scan).
        let mut changed = e1.clone();
        changed.signature = "fn foo(x: i64)".to_string();
        changed.fingerprint.signature_hash = Hash256::from_bytes([9; 32]);
        apply_init_change(&graph, 0x03, &[changed]);
        {
            let state = graph.vector_reconcile.lock();
            assert!(
                !state.full,
                "a tracked supersession must not force a full reconcile"
            );
            assert!(
                state
                    .superseded
                    .contains(&RetrievalKey::EntityRevision(rev_new)),
                "the superseded revision must be recorded for targeted eviction"
            );
        }
        let rev_newer = {
            let ent = graph.entities.read();
            ent.entity_revisions
                .get(&e1.id)
                .unwrap()
                .last()
                .unwrap()
                .revision_id
        };
        assert_ne!(rev_newer, rev_new);

        // Simulate the re-embed re-indexing the HEAD entity + new revision (the
        // upsert path invalidated the entity key); revision 2 lingers as the
        // orphan to reclaim.
        {
            let vi = graph.vector_index.lock().clone().unwrap();
            vi.upsert_retrievable(RetrievalKey::Entity(e1.id), &[0.5, 0.5])
                .unwrap();
            vi.upsert_retrievable(RetrievalKey::EntityRevision(rev_newer), &[0.5, 0.5])
                .unwrap();
        }

        // Incremental prune evicts exactly the tracked revision-2 vector.
        assert_eq!(
            graph.prune_orphaned_vectors(),
            1,
            "incremental prune retires the tracked superseded revision"
        );
        let vi = graph.vector_index.lock().clone().unwrap();
        assert!(
            vi.get_retrievable(&RetrievalKey::EntityRevision(rev_new))
                .is_none(),
            "superseded revision-2 vector must be gone"
        );
        assert!(
            vi.get_retrievable(&RetrievalKey::EntityRevision(rev_newer))
                .is_some(),
            "the new head revision vector must survive"
        );
        assert!(
            vi.get_retrievable(&RetrievalKey::Entity(e1.id)).is_some(),
            "HEAD entity vector must remain"
        );

        // Nothing tracked ⇒ idempotent no-op.
        assert_eq!(graph.prune_orphaned_vectors(), 0);
    }

    /// Load-time reclaim: an index already doubled on disk (a persisted state
    /// holding both revision generations of an entity) self-heals when
    /// reopened. Mirrors `load_vector_index_if_valid`'s load-then-prune sequence.
    /// Discriminating: the reclaim evicts 0 on the old truth, 1 on the fix.
    #[cfg(feature = "vector")]
    #[test]
    fn load_time_reclaim_heals_doubled_persisted_revision_index() {
        let e1 = test_entity("foo", "src/a.rs");
        let dir = tempfile::TempDir::new().unwrap();
        let sidecar = dir.path().join("vectors.kvec");

        // Persist a sidecar holding BOTH revision generations + the HEAD entity.
        let (rev_old, rev_new) = {
            let graph = InMemoryGraph::new();
            let (rev_old, rev_new) = two_revision_entity(&graph, &e1);
            let vi = VectorIndex::new(2).unwrap();
            vi.upsert_retrievable(RetrievalKey::EntityRevision(rev_old), &[1.0, 0.0])
                .unwrap();
            vi.upsert_retrievable(RetrievalKey::EntityRevision(rev_new), &[0.0, 1.0])
                .unwrap();
            vi.upsert(e1.id, &[0.0, 1.0]).unwrap();
            vi.save(&sidecar).unwrap();
            (rev_old, rev_new)
        };

        // A fresh graph at the SAME revision history reopens the doubled sidecar.
        // Revision ids are hash(entity_id, change_id) — deterministic across
        // graphs — so the persisted revision keys match this graph's history.
        let graph = InMemoryGraph::new();
        let (rev_old2, rev_new2) = two_revision_entity(&graph, &e1);
        assert_eq!((rev_old, rev_new), (rev_old2, rev_new2));

        let loaded = graph.load_vector_index(&sidecar).unwrap();
        assert_eq!(
            loaded, 3,
            "sidecar carries both revisions + the head entity"
        );

        let evicted = graph.prune_orphaned_vectors();
        assert_eq!(
            evicted, 1,
            "load-time reclaim retires the superseded revision"
        );

        let vi = graph.vector_index.lock().clone().unwrap();
        assert!(vi
            .get_retrievable(&RetrievalKey::EntityRevision(rev_old))
            .is_none());
        assert!(vi
            .get_retrievable(&RetrievalKey::EntityRevision(rev_new))
            .is_some());
    }

    #[cfg(feature = "vector")]
    #[test]
    fn queue_missing_for_embedding_only_enqueues_unindexed_artifacts() {
        let graph = InMemoryGraph::new();
        let structured = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([0x21; 32]),
            text_preview: Some("build".into()),
        };
        let opaque = OpaqueArtifact {
            file_id: FilePathId::new("assets/logo.svg"),
            content_hash: Hash256::from_bytes([0x22; 32]),
            mime_type: Some("image/svg+xml".into()),
            text_preview: Some("<svg".into()),
        };
        admit_enrichment(&graph, &structured.file_id, structured.content_hash);
        admit_enrichment(&graph, &opaque.file_id, opaque.content_hash);
        graph.upsert_structured_artifact(&structured).unwrap();
        graph.upsert_opaque_artifact(&opaque).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        // Use the explicitly admitted identity so the pre-seeded vector entry
        // matches the graph-owned repository tree.
        let structured_key = RetrievalKey::Artifact(
            graph
                .artifact_id_at_path(&test_repo_path(&structured.file_id.0))
                .unwrap(),
        );
        index
            .upsert_retrievable(structured_key, &[1.0, 0.0])
            .unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        graph.artifact_embedding_queue.lock().clear();
        graph.queue_missing_artifacts_for_embedding();

        let opaque_id = graph
            .artifact_id_at_path(&test_repo_path(&opaque.file_id.0))
            .unwrap();
        let queue = graph.artifact_embedding_queue.lock();
        assert_eq!(queue.len(), 1);
        assert!(queue.contains(&opaque_id));
    }

    #[cfg(feature = "vector")]
    #[test]
    fn upserting_entity_queues_neighbors_for_reembedding() {
        let graph = InMemoryGraph::new();
        let caller = test_entity("caller", "src/a.rs");
        let callee = test_entity("callee", "src/b.rs");
        let rel = test_relation(caller.id, callee.id, RelationKind::Calls);

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_relation(&rel).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        index.upsert(caller.id, &[1.0, 0.0]).unwrap();
        index.upsert(callee.id, &[0.0, 1.0]).unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        graph.embedding_queue.lock().clear();

        let mut renamed = callee.clone();
        renamed.name = "callee_v2".into();
        graph.upsert_entity(&renamed).unwrap();

        let queue = graph.embedding_queue.lock();
        assert!(queue.contains(&RetrievalKey::Entity(caller.id)));
        assert!(queue.contains(&RetrievalKey::Entity(callee.id)));
        drop(queue);

        let vector_index = graph.vector_index.lock();
        let vi = vector_index.as_ref().unwrap();
        assert!(!vi.contains(&caller.id));
        assert!(!vi.contains(&callee.id));
    }

    #[cfg(feature = "vector")]
    #[test]
    fn remove_relation_queues_affected_entities_for_reembedding() {
        let graph = InMemoryGraph::new();
        let caller = test_entity("caller", "src/a.rs");
        let callee = test_entity("callee", "src/b.rs");
        let rel = test_relation(caller.id, callee.id, RelationKind::Calls);

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_relation(&rel).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        index.upsert(caller.id, &[1.0, 0.0]).unwrap();
        index.upsert(callee.id, &[0.0, 1.0]).unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        graph.embedding_queue.lock().clear();
        graph.remove_relation(&rel.id).unwrap();

        let queue = graph.embedding_queue.lock();
        assert!(queue.contains(&RetrievalKey::Entity(caller.id)));
        assert!(queue.contains(&RetrievalKey::Entity(callee.id)));
        drop(queue);

        let vector_index = graph.vector_index.lock();
        let vi = vector_index.as_ref().unwrap();
        assert!(!vi.contains(&caller.id));
        assert!(!vi.contains(&callee.id));
    }

    #[cfg(feature = "vector")]
    #[test]
    fn relation_batch_replace_and_remove_requeue_indexed_endpoints() {
        let graph = InMemoryGraph::new();
        let old_source = test_entity("old_source", "src/a.rs");
        let shared = test_entity("shared", "src/b.rs");
        let new_target = test_entity("new_target", "src/c.rs");
        graph.upsert_entity(&old_source).unwrap();
        graph.upsert_entity(&shared).unwrap();
        graph.upsert_entity(&new_target).unwrap();

        let old = test_relation(old_source.id, shared.id, RelationKind::Calls);
        graph.upsert_relation(&old).unwrap();

        let index = std::sync::Arc::new(crate::VectorIndex::new(2).unwrap());
        index.upsert(old_source.id, &[1.0, 0.0]).unwrap();
        index.upsert(shared.id, &[0.0, 1.0]).unwrap();
        index.upsert(new_target.id, &[0.5, 0.5]).unwrap();
        *graph.vector_index.lock() = Some(std::sync::Arc::clone(&index));
        graph.embedding_queue.lock().clear();

        let replacement = test_relation(shared.id, new_target.id, RelationKind::Calls);
        graph
            .replace_relations_of_kind(RelationKind::Calls, vec![replacement.clone()])
            .unwrap();

        {
            let queue = graph.embedding_queue.lock();
            assert_eq!(queue.len(), 3, "old and new endpoints must be deduplicated");
            assert!(queue.contains(&RetrievalKey::Entity(old_source.id)));
            assert!(queue.contains(&RetrievalKey::Entity(shared.id)));
            assert!(queue.contains(&RetrievalKey::Entity(new_target.id)));
        }
        assert!(!index.contains(&old_source.id));
        assert!(!index.contains(&shared.id));
        assert!(!index.contains(&new_target.id));

        // Reinstall vectors to prove the removal path independently invalidates
        // and requeues both endpoints of the relation it deletes.
        index.upsert(shared.id, &[0.0, 1.0]).unwrap();
        index.upsert(new_target.id, &[0.5, 0.5]).unwrap();
        graph.embedding_queue.lock().clear();
        graph.remove_relations_batch(&[&replacement.id]).unwrap();

        let queue = graph.embedding_queue.lock();
        assert_eq!(queue.len(), 2);
        assert!(queue.contains(&RetrievalKey::Entity(shared.id)));
        assert!(queue.contains(&RetrievalKey::Entity(new_target.id)));
        drop(queue);
        assert!(!index.contains(&shared.id));
        assert!(!index.contains(&new_target.id));
    }

    #[cfg(feature = "vector")]
    #[test]
    fn remove_outgoing_relations_queues_affected_entities_for_reembedding() {
        let graph = InMemoryGraph::new();
        let caller = test_entity("caller", "src/a.rs");
        let callee_a = test_entity("callee_a", "src/b.rs");
        let callee_b = test_entity("callee_b", "src/c.rs");
        let rel_a = test_relation(caller.id, callee_a.id, RelationKind::Calls);
        let rel_b = test_relation(caller.id, callee_b.id, RelationKind::Calls);

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee_a).unwrap();
        graph.upsert_entity(&callee_b).unwrap();
        graph.upsert_relation(&rel_a).unwrap();
        graph.upsert_relation(&rel_b).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        index.upsert(caller.id, &[1.0, 0.0]).unwrap();
        index.upsert(callee_a.id, &[0.0, 1.0]).unwrap();
        index.upsert(callee_b.id, &[0.5, 0.5]).unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        graph.embedding_queue.lock().clear();
        graph.remove_outgoing_relations(&caller.id).unwrap();

        let queue = graph.embedding_queue.lock();
        assert!(queue.contains(&RetrievalKey::Entity(caller.id)));
        assert!(queue.contains(&RetrievalKey::Entity(callee_a.id)));
        assert!(queue.contains(&RetrievalKey::Entity(callee_b.id)));
        drop(queue);

        let vector_index = graph.vector_index.lock();
        let vi = vector_index.as_ref().unwrap();
        assert!(!vi.contains(&caller.id));
        assert!(!vi.contains(&callee_a.id));
        assert!(!vi.contains(&callee_b.id));
        assert!(graph
            .get_relations(&caller.id, &[RelationKind::Calls])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn embedding_status_reflects_state() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let status = graph.embedding_status();
        assert_eq!(status.total, 2);
        assert_eq!(status.indexed, 0);
        #[cfg(feature = "vector")]
        assert_eq!(status.pending, 2);
    }

    #[cfg(feature = "vector")]
    #[test]
    fn embedding_status_pending_covers_unindexed_when_queue_drained() {
        // Reproduces the operational case where a graph is reopened with some
        // entities already in the vector index but the embedding queue is
        // empty because it does not persist across restarts. Before this
        // regression test landed, `embedding_status().pending` returned the
        // raw queue length, so a coverage gate that inspected `pending`
        // alone saw zero outstanding work even though entities remained
        // unindexed. See SP-17 in the methodology paper.
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        let e3 = test_entity("baz", "src/c.rs");
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        index.upsert(e1.id, &[1.0, 0.0]).unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        graph.embedding_queue.lock().clear();
        assert_eq!(graph.pending_embeddings(), 0);

        let status = graph.embedding_status();
        assert_eq!(status.total, 3);
        assert_eq!(status.indexed, 1);
        assert_eq!(
            status.pending, 2,
            "pending must report outstanding work, not raw queue length"
        );
    }

    #[cfg(feature = "vector")]
    #[test]
    fn embedding_status_counts_unindexed_artifacts_when_queue_drained() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        graph.upsert_entity(&e1).unwrap();
        let artifact = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([0x45; 32]),
            text_preview: Some("build".into()),
        };
        admit_enrichment(&graph, &artifact.file_id, artifact.content_hash);
        graph.upsert_structured_artifact(&artifact).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let index = crate::VectorIndex::new(2).unwrap();
        index.upsert(e1.id, &[1.0, 0.0]).unwrap();
        index.save(&path).unwrap();
        graph.load_vector_index(&path).unwrap();

        graph.embedding_queue.lock().clear();
        graph.artifact_embedding_queue.lock().clear();
        assert_eq!(graph.pending_embeddings(), 0);
        assert_eq!(graph.pending_artifact_embeddings(), 0);

        let status = graph.embedding_status();
        assert_eq!(status.total, 2);
        assert_eq!(status.indexed, 1);
        assert_eq!(
            status.pending, 1,
            "pending must include unindexed artifacts even after queue state is lost"
        );
    }

    #[cfg(feature = "vector")]
    #[test]
    fn embedding_status_ignores_source_artifact_identities_without_embedding_docs() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/lib.rs");
        graph.upsert_entity(&e1).unwrap();

        // Source files can have graph-native artifact identities for relations
        // and projection, but only shallow/structured/opaque artifact records
        // have document text that the artifact embedder can vectorize.
        graph.admit_artifact_for_test(
            "src/lib.rs",
            TreeEntry::blob(Hash256::from_bytes([0x46; 32]), false),
        );

        let status = graph.embedding_status();
        assert_eq!(status.total, 1);
        assert_eq!(status.indexed, 0);
        assert_eq!(status.pending, 1);

        graph.artifact_embedding_queue.lock().clear();
        graph.queue_missing_artifacts_for_embedding();
        assert!(
            graph.artifact_embedding_queue.lock().is_empty(),
            "source-only artifact identities must not become unprocessable pending vectors"
        );
    }

    // This test exercises the stub path compiled when neither embeddings nor
    // vector features are active. With the default features ("vector" +
    // "embeddings" both on) the full implementation is compiled instead; that
    // path requires a real embedder and would fail here. Gate the test so it
    // only runs under the feature combination it was written for.
    #[cfg(not(all(feature = "embeddings", feature = "vector")))]
    #[test]
    fn process_embedding_queue_without_embeddings_is_noop() {
        // With just "vector" feature (no "embeddings"), process should return 0
        let graph = InMemoryGraph::new();
        let e = test_entity("foo", "src/main.rs");
        graph.upsert_entity(&e).unwrap();

        // This should be Ok(0) regardless of feature flags
        let result = graph.process_embedding_queue(64);
        assert!(result.is_ok());
    }

    #[test]
    fn graph_stats_counts_entities_and_relations() {
        let dir = tempfile::tempdir().unwrap();
        let graph = InMemoryGraph::with_text_index(dir.path().join("text-index"));

        // Insert two functions and one class
        let e1 = test_entity("foo", "src/a.rs");
        let e2 = test_entity("bar", "src/b.rs");
        let mut e3 = test_entity("MyClass", "src/c.rs");
        e3.kind = EntityKind::Class;

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();

        // Insert a Calls relation and a CoChanges relation
        let r1 = test_relation(e1.id, e2.id, RelationKind::Calls);
        let r2 = test_relation(e2.id, e3.id, RelationKind::CoChanges);
        graph.upsert_relation(&r1).unwrap();
        graph.upsert_relation(&r2).unwrap();

        // Add a shallow file
        let shallow = ShallowTrackedFile {
            file_id: FilePathId::new("README.md"),
            language_hint: "markdown".into(),
            declaration_count: 1,
            import_count: 0,
            syntax_hash: Hash256::from_bytes([0; 32]),
            signature_hash: None,
            declaration_names: vec!["README".into()],
            import_paths: vec![],
        };
        admit_enrichment(&graph, &shallow.file_id, shallow.syntax_hash);
        graph.upsert_shallow_file(&shallow).unwrap();

        let layout = FileLayout {
            file_id: FilePathId::new("src/a.rs"),
            parse_completeness: ParseCompleteness::Partial("1 parse error range(s)".into()),
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![SourceRegion::Trivia { byte_range: 0..8 }],
        };
        admit_enrichment(&graph, &layout.file_id, Hash256::from_bytes([1; 32]));
        graph.upsert_file_layout(&layout).unwrap();

        let structured = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([2; 32]),
            text_preview: Some("build test".into()),
        };
        admit_enrichment(&graph, &structured.file_id, structured.content_hash);
        graph.upsert_structured_artifact(&structured).unwrap();

        let opaque = OpaqueArtifact {
            file_id: FilePathId::new("assets/logo.svg"),
            content_hash: Hash256::from_bytes([3; 32]),
            mime_type: Some("image/svg+xml".into()),
            text_preview: Some("<svg".into()),
        };
        admit_enrichment(&graph, &opaque.file_id, opaque.content_hash);
        graph.upsert_opaque_artifact(&opaque).unwrap();

        // The source path was already admitted before its layout enrichment.
        graph.flush_text_index().unwrap();

        #[cfg(feature = "vector")]
        {
            let vector_path = dir.path().join("vectors.hnsw");
            let index = crate::vector::VectorIndex::new(4).unwrap();
            index.upsert(e1.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
            index.save(&vector_path).unwrap();
            graph.load_vector_index(&vector_path).unwrap();
        }

        let stats = graph.graph_stats();

        assert_eq!(stats.total_entities, 3);
        assert_eq!(stats.total_relations, 2);
        assert_eq!(stats.entity_counts.get("Function"), Some(&2));
        assert_eq!(stats.entity_counts.get("Class"), Some(&1));
        assert_eq!(stats.relation_counts.get("Calls"), Some(&1));
        assert_eq!(stats.relation_counts.get("CoChanges"), Some(&1));
        assert_eq!(stats.file_layout_count, 1);
        assert_eq!(stats.parse_completeness_counts.get("partial"), Some(&1));
        assert_eq!(stats.shallow_file_count, 1);
        assert_eq!(stats.structured_artifact_count, 1);
        assert_eq!(stats.opaque_artifact_count, 1);
        assert_eq!(stats.working_tree_entry_count, 4);
        assert_eq!(stats.text_indexed_entity_count, 3);
        assert!((stats.text_index_coverage_percent - 100.0).abs() < f64::EPSILON);
        #[cfg(feature = "vector")]
        assert_eq!(stats.indexed_embedding_count, 1);
        #[cfg(not(feature = "vector"))]
        assert_eq!(stats.indexed_embedding_count, 0);
        #[cfg(feature = "vector")]
        assert_eq!(stats.pending_embedding_count, 6);
        #[cfg(not(feature = "vector"))]
        assert_eq!(
            stats.pending_embedding_count, stats.total_entities,
            "without a vector index every entity remains an unindexed embedding gap"
        );
        #[cfg(feature = "vector")]
        assert!((stats.embedding_coverage_percent - 33.33333333333333).abs() < 0.001);
        #[cfg(not(feature = "vector"))]
        assert!((stats.embedding_coverage_percent - 0.0).abs() < f64::EPSILON);
        assert_eq!(stats.work_item_count, 0);
        assert_eq!(stats.test_case_count, 0);
        assert_eq!(stats.review_count, 0);
        assert_eq!(stats.session_count, 0);
        assert_eq!(stats.role_counts.get("Source"), Some(&3));
    }

    #[test]
    fn resolve_graph_at_handles_deep_linear_history_iteratively() {
        let graph = InMemoryGraph::new();

        let genesis_id = admit_change(
            &graph,
            SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0x5b; 32])),
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "genesis".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                origin: kin_model::ChangeOrigin::Native,
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            },
        );

        let mut previous = genesis_id;
        let mut head = genesis_id;
        for idx in 0..3_000u16 {
            let mut bytes = [0u8; 32];
            bytes[..2].copy_from_slice(&(idx + 1).to_be_bytes());
            let id = admit_change(
                &graph,
                SemanticChange {
                    id: SemanticChangeId::from_hash(Hash256::from_bytes(bytes)),
                    parents: vec![previous],
                    timestamp: Timestamp::now(),
                    author: AuthorId::new("test"),
                    message: format!("change {idx}"),
                    entity_deltas: vec![],
                    relation_deltas: vec![],
                    tree_deltas: vec![],
                    projected_files: vec![],
                    spec_link: None,
                    evidence: vec![],
                    risk_summary: None,
                    origin: kin_model::ChangeOrigin::Native,
                    admission_policy_delta: None,
                    external_reference_deltas: Vec::new(),
                },
            );
            previous = id;
            head = id;
        }

        let state = graph.resolve_graph_at(&head).unwrap();
        assert!(state.entities.is_empty());
        assert!(state.relations.is_empty());
        assert!(state.tree.is_empty());
    }

    fn test_entity_with_id(id_seed: u128, name: &str) -> Entity {
        Entity {
            id: EntityId(uuid::Uuid::from_u128(id_seed)),
            ..test_entity(name, "src/main.rs")
        }
    }

    /// The truth epoch is only a complete record of truth movement while
    /// [`InMemoryGraph::entities_write`] is the sole writer, and that is a
    /// property of the source rather than of any runtime state, so it is
    /// checked here. Exactly one raw acquisition may exist: the one inside the
    /// guard constructor itself.
    #[test]
    fn the_entity_write_guard_is_the_only_writer() {
        let source =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/graph.rs"))
                .expect("the engine source must be readable");

        // Both needles are assembled at run time. Spelled as literals they
        // would occur in this very file and count themselves, which would make
        // the guard pass on its own text.
        let guarded = format!("entities{}write()", "_");
        let raw = format!("entities{}write()", ".");

        assert!(
            source.matches(guarded.as_str()).count() > 1,
            "control: the guarded form must be present, or this test is reading the wrong file"
        );
        assert_eq!(
            source.matches(raw.as_str()).count(),
            1,
            "every entity write must go through the guard so the truth epoch stays complete"
        );
    }

    /// What `embedding_status` would answer if it recomputed from scratch,
    /// using the per-key probe the maintained counters replaced. Every coverage
    /// test compares against this, so a counter that drifts from graph truth
    /// fails here rather than in a two-hour embed.
    #[cfg(feature = "vector")]
    fn probe_coverage(graph: &InMemoryGraph) -> (usize, usize) {
        let truth = graph.graph_truth_retrievable_keys();
        let guard = graph.vector_index.lock();
        let indexed = guard
            .as_ref()
            .map(|vi| {
                truth
                    .iter()
                    .filter(|key| vi.contains_retrievable(key))
                    .count()
            })
            .unwrap_or(0);
        (indexed, truth.len())
    }

    #[cfg(feature = "vector")]
    fn coverage_fixture(count: u128, indexed: usize) -> (InMemoryGraph, Vec<Entity>) {
        let graph = InMemoryGraph::new();
        let entities: Vec<Entity> = (0..count)
            .map(|i| test_entity_with_id(0x2416_0000 + i, "cov"))
            .collect();
        graph.batch_upsert_entities(&entities).unwrap();

        let vi = VectorIndex::new(2).unwrap();
        for entity in entities.iter().take(indexed) {
            vi.upsert_retrievable(RetrievalKey::Entity(entity.id), &[1.0, 0.0])
                .unwrap();
        }
        *graph.vector_index.lock() = Some(Arc::new(vi));
        (graph, entities)
    }

    /// Coverage must equal the per-key probe it replaced, including the case
    /// that separates the two possible shortcuts: the index holding a key graph
    /// truth does not. `indexed` is the intersection, never the index's size.
    #[cfg(feature = "vector")]
    #[test]
    fn embedding_coverage_equals_the_per_key_probe_it_replaced() {
        let (graph, entities) = coverage_fixture(40, 17);
        {
            let vi = graph.vector_index.lock().clone().unwrap();
            let stranger = test_entity_with_id(0x2416_9999, "orphan");
            vi.upsert_retrievable(RetrievalKey::Entity(stranger.id), &[0.0, 1.0])
                .unwrap();
        }

        let status = graph.embedding_status();
        assert_eq!((status.indexed, status.total), probe_coverage(&graph));
        assert_eq!(status.indexed, 17, "only truth keys count as coverage");
        assert_eq!(status.total, entities.len());
        assert_eq!(
            graph.vector_index.lock().as_ref().unwrap().len(),
            18,
            "the index holds one more vector than coverage reports"
        );
    }

    /// The polled steady state: between two vector batches nothing that can
    /// change the answer has changed, so repeat polls must be answered from the
    /// maintained counters instead of rescanning graph truth and the index.
    #[cfg(feature = "vector")]
    #[test]
    fn embedding_status_serves_repeat_polls_without_rescanning() {
        let (graph, _) = coverage_fixture(40, 17);

        let first = graph.embedding_status();
        let scans = graph.embedding_coverage_scans.load(Ordering::Relaxed);
        for _ in 0..16 {
            let repeat = graph.embedding_status();
            assert_eq!(repeat.indexed, first.indexed);
            assert_eq!(repeat.total, first.total);
        }
        assert_eq!(
            graph.embedding_coverage_scans.load(Ordering::Relaxed),
            scans,
            "a poll that changed nothing must not rescan"
        );
    }

    /// Vectors arriving and being evicted must both move coverage. The eviction
    /// half is the drift guard: a counter that only ever increments reads as a
    /// finished embed forever once the index has been pruned under it.
    #[cfg(feature = "vector")]
    #[test]
    fn embedding_status_follows_vectors_into_and_out_of_the_index() {
        let (graph, entities) = coverage_fixture(40, 17);
        let before = graph.embedding_status();
        let scans = graph.embedding_coverage_scans.load(Ordering::Relaxed);

        let vi = graph.vector_index.lock().clone().unwrap();
        let key = RetrievalKey::Entity(entities[20].id);
        vi.upsert_retrievable(key, &[1.0, 0.0]).unwrap();
        let inserted = graph.embedding_status();
        assert_eq!(inserted.indexed, before.indexed + 1);
        assert_eq!((inserted.indexed, inserted.total), probe_coverage(&graph));

        vi.remove_retrievable(&key).unwrap();
        let evicted = graph.embedding_status();
        assert_eq!(evicted.indexed, before.indexed);
        assert_eq!((evicted.indexed, evicted.total), probe_coverage(&graph));
        assert!(
            graph.embedding_coverage_scans.load(Ordering::Relaxed) > scans,
            "a key set that moved must have forced a recount"
        );
    }

    /// Graph truth moving is the other half. Adding an entity owes a vector that
    /// does not exist yet, so `total` grows; removing one takes the obligation
    /// away again.
    ///
    /// Deliberately run with NO index loaded. An entity upsert also reaches the
    /// vector index through `invalidate_entities_for_embedding`, so with an
    /// index present the index token alone would bust the cache and this test
    /// would pass whether or not entity writes are tracked at all. With no
    /// index the truth epoch is the only thing that can notice, which is what
    /// makes the assertion discriminating.
    #[cfg(feature = "vector")]
    #[test]
    fn embedding_status_follows_graph_truth_moving() {
        let graph = InMemoryGraph::new();
        let entities: Vec<Entity> = (0..8u128)
            .map(|i| test_entity_with_id(0x2416_2000 + i, "cov"))
            .collect();
        graph.batch_upsert_entities(&entities).unwrap();
        assert!(graph.vector_index_stats().is_none());

        let before = graph.embedding_status();
        assert_eq!(before.total, entities.len());

        let fresh = test_entity_with_id(0x2416_8888, "fresh");
        graph.batch_upsert_entities(&[fresh.clone()]).unwrap();
        let grown = graph.embedding_status();
        assert_eq!(grown.total, before.total + 1);
        assert_eq!((grown.indexed, grown.total), probe_coverage(&graph));

        graph.batch_remove_entities(&[entities[0].id]).unwrap();
        let shrunk = graph.embedding_status();
        assert_eq!(shrunk.total, before.total, "one added, one removed");
        assert_eq!((shrunk.indexed, shrunk.total), probe_coverage(&graph));
    }

    /// Re-init mints a fresh revision key for every entity, so a superseded
    /// generation leaves graph truth the moment the change is applied, long
    /// before any prune evicts its vector. Coverage has to fall then, not when
    /// the index is finally reconciled.
    #[cfg(feature = "vector")]
    #[test]
    fn embedding_status_drops_a_superseded_revision_from_coverage() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("foo", "src/a.rs");
        let (rev_old, rev_new) = two_revision_entity(&graph, &e1);

        let vi = VectorIndex::new(2).unwrap();
        vi.upsert_retrievable(RetrievalKey::EntityRevision(rev_old), &[1.0, 0.0])
            .unwrap();
        vi.upsert_retrievable(RetrievalKey::EntityRevision(rev_new), &[0.0, 1.0])
            .unwrap();
        vi.upsert_retrievable(RetrievalKey::Entity(e1.id), &[0.0, 1.0])
            .unwrap();
        *graph.vector_index.lock() = Some(Arc::new(vi));

        let before = graph.embedding_status();
        assert_eq!((before.indexed, before.total), probe_coverage(&graph));
        let indexed_before = before.indexed;

        let mut changed = e1.clone();
        changed.signature = "fn foo(x: i64)".to_string();
        changed.fingerprint.signature_hash = Hash256::from_bytes([9; 32]);
        apply_init_change(&graph, 0x03, &[changed]);

        let after = graph.embedding_status();
        assert_eq!((after.indexed, after.total), probe_coverage(&graph));
        assert!(
            after.indexed < indexed_before,
            "the superseded revision must stop counting as coverage: {indexed_before} -> {}",
            after.indexed
        );
    }

    /// `indexed = 0` is structurally zero when no index is loaded, so a cache
    /// entry minted for that state must never be served to a graph that has
    /// since loaded one. `vector_index_stats().is_none()` is the test that tells
    /// the two apart, and it must still tell them apart after the counters land.
    #[cfg(feature = "vector")]
    #[test]
    fn embedding_status_keeps_an_absent_index_distinct_from_an_empty_one() {
        let graph = InMemoryGraph::new();
        let entities: Vec<Entity> = (0..8u128)
            .map(|i| test_entity_with_id(0x2416_1000 + i, "cov"))
            .collect();
        graph.batch_upsert_entities(&entities).unwrap();

        let absent = graph.embedding_status();
        assert_eq!(absent.indexed, 0);
        assert!(
            graph.vector_index_stats().is_none(),
            "no index is loaded, so this zero is structural"
        );

        *graph.vector_index.lock() = Some(Arc::new(VectorIndex::new(2).unwrap()));
        let empty = graph.embedding_status();
        assert_eq!(empty.indexed, 0);
        assert_eq!(empty.total, absent.total);
        assert_eq!(
            graph.vector_index_stats(),
            Some((2, 0)),
            "an empty index is loaded, so this zero is a real count"
        );

        let vi = graph.vector_index.lock().clone().unwrap();
        vi.upsert_retrievable(RetrievalKey::Entity(entities[0].id), &[1.0, 0.0])
            .unwrap();
        assert_eq!(
            graph.embedding_status().indexed,
            1,
            "the absent-index entry must not have been served to the loaded index"
        );
    }

    /// The starvation itself. Holding the `vector_index` slot across the count
    /// is what queued the embed worker's `get_vector_index` behind every status
    /// poll, so the slot has to be reachable while the count runs. The hook runs
    /// on the counting thread and `parking_lot::Mutex` is not reentrant, so
    /// `try_lock` succeeding is exactly the proof that the guard is gone.
    #[cfg(feature = "vector")]
    #[test]
    fn embedding_status_releases_the_index_slot_before_counting() {
        let (graph, _) = coverage_fixture(40, 17);
        let observed = Arc::new(AtomicBool::new(false));
        let free = Arc::new(AtomicBool::new(false));
        let observed_hook = Arc::clone(&observed);
        let free_hook = Arc::clone(&free);

        set_embedding_coverage_before_count_hook(move |graph| {
            observed_hook.store(true, Ordering::SeqCst);
            free_hook.store(graph.vector_index.try_lock().is_some(), Ordering::SeqCst);
        });

        let status = graph.embedding_status();

        assert!(
            observed.load(Ordering::SeqCst),
            "the observation point must run, or this test proves nothing"
        );
        assert!(
            free.load(Ordering::SeqCst),
            "the vector index slot must be reachable while coverage counts"
        );
        assert_eq!((status.indexed, status.total), probe_coverage(&graph));
    }

    /// Before/after for FIR-2416, on one host in one process.
    ///
    /// Arm A is the shape this fix replaced: materialize graph truth, then probe
    /// the index once per key while holding the `vector_index` slot. Arm B is
    /// `embedding_status` recomputing. Arm C is `embedding_status` answering a
    /// repeat poll from the maintained counters.
    ///
    /// The last three arms are the part that actually mattered on the gauntlet:
    /// how fast the embed persist stage lands batches with nothing else running,
    /// with arm A polling it, and with the shipped path polling it. The persist
    /// stage is modelled exactly as `persist_embedded_batch` does it, clone the
    /// handle out of the slot and batch-upsert, minus the embedder inference
    /// this test cannot run offline.
    #[cfg(feature = "vector")]
    #[test]
    #[ignore = "perf microbench; run with --ignored --nocapture"]
    fn embedding_status_scan_vs_counter_microbench() {
        use std::sync::atomic::AtomicUsize;
        use std::time::{Duration, Instant};

        const ENTITIES: u128 = 30_000;
        const BATCH: usize = 512;

        // A fresh graph and a fresh index per arm. The persist loop re-upserts
        // the same keys, which moves the index's free list, so arms sharing one
        // fixture measure the state their predecessor left behind rather than
        // each other.
        let fixture = || {
            let graph = InMemoryGraph::new();
            let entities: Vec<Entity> = (0..ENTITIES)
                .map(|i| test_entity_with_id(0x2416_0000_0000 + i, "bench"))
                .collect();
            graph.batch_upsert_entities(&entities).unwrap();

            let vi = VectorIndex::new(2).unwrap();
            for chunk in entities.chunks(BATCH) {
                let batch: Vec<(RetrievalKey, Vec<f32>)> = chunk
                    .iter()
                    .enumerate()
                    .map(|(i, e)| {
                        let t = i as f32 / BATCH as f32;
                        (RetrievalKey::Entity(e.id), vec![t, 1.0 - t])
                    })
                    .collect();
                vi.upsert_retrievable_batch(batch).unwrap();
            }
            *graph.vector_index.lock() = Some(Arc::new(vi));
            (graph, entities)
        };

        // The replaced shape: materialize truth, then probe the index once per
        // key with the `vector_index` slot held for the whole loop.
        let scan = |graph: &InMemoryGraph| {
            let truth = graph.graph_truth_retrievable_keys();
            let guard = graph.vector_index.lock();
            let indexed = guard
                .as_ref()
                .map(|vi| {
                    truth
                        .iter()
                        .filter(|key| vi.contains_retrievable(key))
                        .count()
                })
                .unwrap_or(0);
            (indexed, truth.len())
        };

        let (graph, entities) = fixture();

        let t = Instant::now();
        let a = scan(&graph);
        let arm_a = t.elapsed();

        graph.embedding_coverage.lock().take();
        let t = Instant::now();
        let b = graph.embedding_status();
        let arm_b = t.elapsed();

        let t = Instant::now();
        let c = graph.embedding_status();
        let arm_c = t.elapsed();

        assert_eq!(a, (b.indexed, b.total));
        assert_eq!((b.indexed, b.total), (c.indexed, c.total));
        eprintln!(
            "[FIR-2416] quiet host, truth={} indexed={}: A scan-under-slot {arm_a:?} | B recount {arm_b:?} | C cached {arm_c:?}",
            b.total, b.indexed
        );

        // The persist stage as `persist_embedded_batch` runs it: clone the
        // handle out of the slot, batch-upsert, minus the embedder inference
        // this test cannot run offline.
        // Returns (batches landed, worst slot acquisition). The slot wait is
        // the starvation itself: `persist_embedded_batch` reaches the index
        // through `get_vector_index`, which takes this mutex, and the replaced
        // status held it for the length of its scan. Batch counts on a shared
        // host move with whatever else is compiling; a blocked mutex
        // acquisition does not.
        let persist_window = |graph: &InMemoryGraph, entities: &[Entity], window: Duration| {
            let mut landed = 0usize;
            let mut worst_slot = Duration::ZERO;
            let start = Instant::now();
            let mut round = 0u32;
            while start.elapsed() < window {
                let slot = Instant::now();
                let vi = graph.vector_index.lock().clone().unwrap();
                worst_slot = worst_slot.max(slot.elapsed());
                let t = round as f32 / 1000.0;
                let batch: Vec<(RetrievalKey, Vec<f32>)> = entities[..BATCH]
                    .iter()
                    .map(|e| (RetrievalKey::Entity(e.id), vec![t, 1.0 - t]))
                    .collect();
                vi.upsert_retrievable_batch(batch).unwrap();
                landed += 1;
                round += 1;
            }
            (landed, worst_slot)
        };

        let window = Duration::from_secs(10);
        // One poll per 400 ms against a batch landing in tens of milliseconds
        // is well above the field's poll-to-batch ratio (a 10 s poll against a
        // 40 s batch), so this arm asks more of status than the gauntlet does.
        let cadence = Duration::from_millis(400);

        let arm = |poller: Option<bool>| -> (usize, Duration, usize, Duration, Duration) {
            let (graph, entities) = fixture();
            let Some(old) = poller else {
                let (landed, worst_slot) = persist_window(&graph, &entities, window);
                return (landed, worst_slot, 0, Duration::ZERO, Duration::ZERO);
            };
            let stop = AtomicBool::new(false);
            let polls = AtomicUsize::new(0);
            let total_us = AtomicUsize::new(0);
            let worst_us = AtomicUsize::new(0);
            let landed = std::thread::scope(|scope| {
                scope.spawn(|| {
                    while !stop.load(Ordering::Acquire) {
                        let t = Instant::now();
                        if old {
                            scan(&graph);
                        } else {
                            graph.embedding_status();
                        }
                        let us = t.elapsed().as_micros() as usize;
                        total_us.fetch_add(us, Ordering::Relaxed);
                        worst_us.fetch_max(us, Ordering::Relaxed);
                        polls.fetch_add(1, Ordering::Relaxed);
                        std::thread::sleep(cadence);
                    }
                });
                let landed = persist_window(&graph, &entities, window);
                stop.store(true, Ordering::Release);
                landed
            });
            let n = polls.load(Ordering::Relaxed).max(1);
            (
                landed.0,
                landed.1,
                polls.load(Ordering::Relaxed),
                Duration::from_micros((total_us.load(Ordering::Relaxed) / n) as u64),
                Duration::from_micros(worst_us.load(Ordering::Relaxed) as u64),
            )
        };

        let (alone, alone_slot, _, _, _) = arm(None);
        let (with_old, old_slot, old_polls, old_mean, old_worst) = arm(Some(true));
        let (with_new, new_slot, new_polls, new_mean, new_worst) = arm(Some(false));

        eprintln!(
            "[FIR-2416] poll latency under a live persist loop: old mean {old_mean:?} worst {old_worst:?} ({old_polls} polls) | new mean {new_mean:?} worst {new_worst:?} ({new_polls} polls)"
        );
        eprintln!(
            "[FIR-2416] worst wait for the index slot on the persist path: alone {alone_slot:?} | under old poller {old_slot:?} | under new poller {new_slot:?}"
        );
        eprintln!(
            "[FIR-2416] persist batches in {window:?}, one fresh fixture per arm: alone {alone} | under old poller {with_old} | under new poller {with_new} (this host's run-to-run spread swamps the difference; the slot wait above is the low-noise reading)"
        );
        let _ = entities;
    }

    #[test]
    fn query_entities_preserves_name_rank() {
        // An exact name match must rank ahead of a token/substring match, even
        // when the exact match has the larger entity id (so a bare id-sort
        // would put it last).
        let graph = InMemoryGraph::new();
        let exact = test_entity_with_id(0xff, "parse");
        let token = test_entity_with_id(0x01, "parseTableFromHtml");
        graph.upsert_entity(&exact).unwrap();
        graph.upsert_entity(&token).unwrap();

        let filter = EntityFilter {
            name_pattern: Some("parse".to_string()),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        let names: Vec<&str> = results.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["parse", "parseTableFromHtml"],
            "exact name match should outrank token match regardless of id"
        );
    }

    #[test]
    fn query_entities_tie_break_is_id_ascending() {
        // Entities at the same rank (all exact name matches) are ordered by id
        // ascending as the total tie-break.
        let graph = InMemoryGraph::new();
        let hi = test_entity_with_id(0x30, "dup");
        let lo = test_entity_with_id(0x10, "dup");
        let mid = test_entity_with_id(0x20, "dup");
        // Insert out of id order.
        graph.upsert_entity(&hi).unwrap();
        graph.upsert_entity(&lo).unwrap();
        graph.upsert_entity(&mid).unwrap();

        let filter = EntityFilter {
            name_pattern: Some("dup".to_string()),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        let ids: Vec<EntityId> = results.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![lo.id, mid.id, hi.id]);
    }

    #[test]
    fn query_entities_deterministic_across_calls() {
        // Same query against the same graph must produce a byte-identical
        // ordering on every call — no HashMap-iteration-order leakage.
        let graph = InMemoryGraph::new();
        for i in 0..32u128 {
            graph
                .upsert_entity(&test_entity_with_id(0x1000 + i, "handler"))
                .unwrap();
        }

        let filter = EntityFilter {
            name_pattern: Some("handler".to_string()),
            ..Default::default()
        };
        let first: Vec<EntityId> = graph
            .query_entities(&filter)
            .unwrap()
            .iter()
            .map(|e| e.id)
            .collect();
        for _ in 0..8 {
            let again: Vec<EntityId> = graph
                .query_entities(&filter)
                .unwrap()
                .iter()
                .map(|e| e.id)
                .collect();
            assert_eq!(again, first, "query_entities order must be deterministic");
        }
    }

    #[test]
    fn query_entities_non_name_queries_stay_id_sorted() {
        // File and kind queries draw candidates from hash sets in arbitrary
        // order. Their result order must remain a deterministic id-sort and
        // must not be perturbed by the name-rank path.
        let graph = InMemoryGraph::new();
        let ids: Vec<EntityId> = (0..24u128)
            .map(|i| {
                let e = test_entity_with_id(0x900 + i, &format!("fn_{i}"));
                graph.upsert_entity(&e).unwrap();
                e.id
            })
            .collect();
        let mut expected = ids.clone();
        expected.sort();

        let by_file = EntityFilter {
            file_path: Some(FilePathId::new("src/main.rs")),
            ..Default::default()
        };
        let file_ids: Vec<EntityId> = graph
            .query_entities(&by_file)
            .unwrap()
            .iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(file_ids, expected, "file query must be id-sorted");

        let by_kind = EntityFilter {
            kinds: Some(vec![EntityKind::Function]),
            ..Default::default()
        };
        let kind_ids: Vec<EntityId> = graph
            .query_entities(&by_kind)
            .unwrap()
            .iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(kind_ids, expected, "kind query must be id-sorted");
    }

    // -----------------------------------------------------------------------
    // Deterministic priority embedding queue (5.8/R5)
    // -----------------------------------------------------------------------

    #[cfg(feature = "vector")]
    #[test]
    fn recency_queue_dedups_and_keeps_highest_priority_recency() {
        let key = RetrievalKey::Entity(EntityId(uuid::Uuid::from_u128(1)));

        let mut q: RecencyQueue<RetrievalKey> = RecencyQueue::default();
        q.insert(key, EmbedRecency::Backfill);
        q.insert(key, EmbedRecency::Backfill);
        assert_eq!(q.len(), 1, "duplicate inserts must dedup to one entry");

        // Re-queuing as a live change upgrades recency (lower value wins).
        q.insert(key, EmbedRecency::ChangedThisSync);
        assert_eq!(q.len(), 1);
        assert_eq!(q.drain_all(), vec![(key, EmbedRecency::ChangedThisSync)]);

        // A later backfill must NOT downgrade an existing live-change entry.
        let mut q2: RecencyQueue<RetrievalKey> = RecencyQueue::default();
        q2.insert(key, EmbedRecency::ChangedThisSync);
        q2.insert(key, EmbedRecency::Backfill);
        assert_eq!(q2.drain_all(), vec![(key, EmbedRecency::ChangedThisSync)]);
    }

    /// Pin the INTENDED tier lattice (semantics, not implementation): a refactor
    /// that silently inverts any rung must fail here. Canonical order, earliest
    /// embed first:
    ///   PUBLIC_API < PUBLIC_SOURCE < CRATE_SOURCE < INTERNAL_SOURCE
    ///   < PRIVATE_SOURCE < REVISION < TEST < DOCS < OTHER
    #[cfg(feature = "vector")]
    #[test]
    fn entity_embed_tier_lattice_is_pinned_public_api_first_generated_last() {
        let with = |vis: Visibility, role: EntityRole, kind: EntityKind| -> Entity {
            let mut e = test_entity("e", "src/lib.rs");
            e.visibility = vis;
            e.role = role;
            e.kind = kind;
            e
        };

        // Public API contract surface (each API kind, when Public).
        for kind in [
            EntityKind::ApiEndpoint,
            EntityKind::EventContract,
            EntityKind::Schema,
            EntityKind::Interface,
            EntityKind::TraitDef,
        ] {
            assert_eq!(
                entity_embed_tier(&with(Visibility::Public, EntityRole::Source, kind)),
                embed_tier::PUBLIC_API,
                "{kind:?} @ Public must be the public-API tier"
            );
        }

        // Source code by visibility (non-API kinds).
        assert_eq!(
            entity_embed_tier(&with(
                Visibility::Public,
                EntityRole::Source,
                EntityKind::Function
            )),
            embed_tier::PUBLIC_SOURCE
        );
        assert_eq!(
            entity_embed_tier(&with(
                Visibility::Crate,
                EntityRole::Source,
                EntityKind::Function
            )),
            embed_tier::CRATE_SOURCE
        );
        assert_eq!(
            entity_embed_tier(&with(
                Visibility::Internal,
                EntityRole::Source,
                EntityKind::Function
            )),
            embed_tier::INTERNAL_SOURCE
        );
        assert_eq!(
            entity_embed_tier(&with(
                Visibility::Private,
                EntityRole::Source,
                EntityKind::Function
            )),
            embed_tier::PRIVATE_SOURCE
        );

        // Non-source roles trail all live source, regardless of visibility.
        assert_eq!(
            entity_embed_tier(&with(
                Visibility::Public,
                EntityRole::Test,
                EntityKind::Function
            )),
            embed_tier::TEST
        );
        // A source-roled but structurally-test entity is still a test.
        assert_eq!(
            entity_embed_tier(&with(
                Visibility::Public,
                EntityRole::Source,
                EntityKind::Test
            )),
            embed_tier::TEST
        );
        assert_eq!(
            entity_embed_tier(&with(
                Visibility::Public,
                EntityRole::Docs,
                EntityKind::DocumentNode
            )),
            embed_tier::DOCS
        );
        for role in [
            EntityRole::Generated,
            EntityRole::Vendored,
            EntityRole::External,
        ] {
            assert_eq!(
                entity_embed_tier(&with(Visibility::Public, role, EntityKind::Function)),
                embed_tier::OTHER,
                "{role:?} must be the trailing tier even when Public"
            );
        }

        // The full lattice is strictly ordered, earliest-embed first. REVISION
        // is not produced by entity_embed_tier (it is assigned to historical
        // revision keys in embed_sort_key_for) but is pinned in the chain so the
        // overall ordering contract is encoded in one place.
        assert!(
            embed_tier::PUBLIC_API < embed_tier::PUBLIC_SOURCE
                && embed_tier::PUBLIC_SOURCE < embed_tier::CRATE_SOURCE
                && embed_tier::CRATE_SOURCE < embed_tier::INTERNAL_SOURCE
                && embed_tier::INTERNAL_SOURCE < embed_tier::PRIVATE_SOURCE
                && embed_tier::PRIVATE_SOURCE < embed_tier::REVISION
                && embed_tier::REVISION < embed_tier::TEST
                && embed_tier::TEST < embed_tier::DOCS
                && embed_tier::DOCS < embed_tier::OTHER,
            "tier lattice must stay strictly ordered public-API → generated"
        );
    }

    #[cfg(feature = "vector")]
    #[test]
    fn embed_sort_key_precedence_is_tier_recency_centrality_id() {
        let k_lo = RetrievalKey::Entity(EntityId(uuid::Uuid::from_u128(1)));
        let k_hi = RetrievalKey::Entity(EntityId(uuid::Uuid::from_u128(2)));

        // Tier dominates recency and centrality.
        let better_tier = EmbedSortKey {
            tier: 0,
            recency: EmbedRecency::Backfill,
            centrality_rank: u32::MAX,
            key: k_hi,
        };
        let worse_tier = EmbedSortKey {
            tier: 1,
            recency: EmbedRecency::ChangedThisSync,
            centrality_rank: 0,
            key: k_lo,
        };
        assert!(better_tier < worse_tier);

        // Within a tier, recency dominates centrality.
        let changed = EmbedSortKey {
            tier: 1,
            recency: EmbedRecency::ChangedThisSync,
            centrality_rank: u32::MAX,
            key: k_hi,
        };
        let backfill = EmbedSortKey {
            tier: 1,
            recency: EmbedRecency::Backfill,
            centrality_rank: 0,
            key: k_lo,
        };
        assert!(changed < backfill);

        // Within tier+recency, higher in-degree (lower rank) embeds first.
        let high_centrality = EmbedSortKey {
            tier: 1,
            recency: EmbedRecency::Backfill,
            centrality_rank: embed_centrality_rank(10),
            key: k_hi,
        };
        let low_centrality = EmbedSortKey {
            tier: 1,
            recency: EmbedRecency::Backfill,
            centrality_rank: embed_centrality_rank(0),
            key: k_lo,
        };
        assert!(high_centrality < low_centrality);

        // All else equal, the key id is the stable tiebreak.
        let id_lo = EmbedSortKey {
            tier: 1,
            recency: EmbedRecency::Backfill,
            centrality_rank: embed_centrality_rank(0),
            key: k_lo,
        };
        let id_hi = EmbedSortKey {
            tier: 1,
            recency: EmbedRecency::Backfill,
            centrality_rank: embed_centrality_rank(0),
            key: k_hi,
        };
        assert!(id_lo < id_hi);
    }

    #[cfg(feature = "vector")]
    #[test]
    fn drain_embedding_batch_is_stable_across_insertion_orders() {
        // Same three entities, two different insertion orders -> identical drain.
        let mut alpha = test_entity_with_id(0x10, "alpha");
        alpha.visibility = Visibility::Private; // tier PRIVATE_SOURCE
        let mut beta = test_entity_with_id(0x20, "beta");
        beta.kind = EntityKind::Interface; // tier PUBLIC_API
        let gamma = test_entity_with_id(0x30, "gamma"); // tier PUBLIC_SOURCE

        let g1 = InMemoryGraph::new();
        for e in [&alpha, &beta, &gamma] {
            g1.upsert_entity(e).unwrap();
        }
        let g2 = InMemoryGraph::new();
        for e in [&gamma, &alpha, &beta] {
            g2.upsert_entity(e).unwrap();
        }

        let keys = |drained: Vec<(RetrievalKey, EmbedRecency)>| -> Vec<RetrievalKey> {
            drained.into_iter().map(|(k, _)| k).collect()
        };
        let order1 = keys(g1.drain_embedding_batch(100));
        let order2 = keys(g2.drain_embedding_batch(100));
        assert_eq!(
            order1, order2,
            "drain order must be independent of insertion / map-seed order"
        );

        // And it is the priority order: public API, then public source, then private.
        assert_eq!(
            order1,
            vec![
                RetrievalKey::Entity(beta.id),
                RetrievalKey::Entity(gamma.id),
                RetrievalKey::Entity(alpha.id),
            ]
        );
    }

    #[cfg(feature = "vector")]
    #[test]
    fn drain_embedding_batch_prioritizes_high_centrality_within_tier() {
        let g = InMemoryGraph::new();
        let hub = test_entity_with_id(0x60, "hub");
        let leaf = test_entity_with_id(0x61, "leaf");
        g.upsert_entity(&hub).unwrap();
        g.upsert_entity(&leaf).unwrap();

        // Give hub three incoming relations (in-degree 3); leaf stays at 0.
        for i in 0..3u128 {
            let dep = test_entity_with_id(0x70 + i, "dep");
            g.upsert_entity(&dep).unwrap();
            g.upsert_relation(&test_relation(dep.id, hub.id, RelationKind::Calls))
                .unwrap();
        }

        let order: Vec<RetrievalKey> = g
            .drain_embedding_batch(100)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        let pos = |id| {
            order
                .iter()
                .position(|k| *k == RetrievalKey::Entity(id))
                .unwrap()
        };
        // Same tier + recency; hub's higher in-degree must place it before leaf.
        assert!(
            pos(hub.id) < pos(leaf.id),
            "higher-centrality entity must embed earlier within a tier"
        );
    }

    #[cfg(feature = "vector")]
    #[test]
    fn drain_embedding_batch_orders_changed_this_sync_before_backfill() {
        let g = InMemoryGraph::new();
        // a.id < b.id, so an id-only sort would put `a` first; recency must flip it.
        let a = test_entity_with_id(0x40, "aaa");
        let b = test_entity_with_id(0x41, "bbb");
        g.upsert_entity(&a).unwrap();
        g.upsert_entity(&b).unwrap();

        g.embedding_queue.lock().clear();
        g.queue_for_embedding(&[a.id]); // a -> Backfill
        g.upsert_entity(&b).unwrap(); // b -> ChangedThisSync (live invalidate path)

        let order: Vec<RetrievalKey> = g
            .drain_embedding_batch(100)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            order,
            vec![RetrievalKey::Entity(b.id), RetrievalKey::Entity(a.id)],
            "changed-this-sync must embed before backfill despite a lower id"
        );
    }

    #[cfg(feature = "vector")]
    #[test]
    fn drain_embedding_batch_respects_batch_size_and_requeues_leftover() {
        let g = InMemoryGraph::new();
        let mut api = test_entity_with_id(0x80, "api");
        api.kind = EntityKind::Interface; // tier PUBLIC_API
        let pubfn = test_entity_with_id(0x81, "pubfn"); // tier PUBLIC_SOURCE
        let mut privfn = test_entity_with_id(0x82, "privfn");
        privfn.visibility = Visibility::Private; // tier PRIVATE_SOURCE
        g.upsert_entity(&privfn).unwrap();
        g.upsert_entity(&pubfn).unwrap();
        g.upsert_entity(&api).unwrap();

        // Batch of 1 -> only the highest-priority item (the API surface).
        let first = g.drain_embedding_batch(1);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, RetrievalKey::Entity(api.id));
        assert_eq!(g.pending_embeddings(), 2, "leftover must be requeued");

        // Next drain continues in priority order.
        let rest: Vec<RetrievalKey> = g
            .drain_embedding_batch(100)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            rest,
            vec![
                RetrievalKey::Entity(pubfn.id),
                RetrievalKey::Entity(privfn.id)
            ]
        );
        assert_eq!(g.pending_embeddings(), 0);
    }

    #[cfg(feature = "vector")]
    #[test]
    fn embedding_frontier_rebuilds_when_new_higher_priority_work_arrives() {
        let g = InMemoryGraph::new();
        let mut first = test_entity_with_id(0x91, "first");
        first.visibility = Visibility::Private;
        let mut second = test_entity_with_id(0x92, "second");
        second.visibility = Visibility::Private;
        g.upsert_entity(&first).unwrap();
        g.upsert_entity(&second).unwrap();
        g.embedding_queue.lock().clear();
        g.queue_for_embedding(&[first.id, second.id]);

        assert_eq!(g.drain_embedding_batch(1).len(), 1);
        assert_eq!(g.embedding_queue.lock().frontier_rebuilds, 1);

        // A newly changed public API outranks the cached private/backfill
        // leftover. Its enqueue invalidates and rebuilds the frontier once.
        let mut api = test_entity_with_id(0x93, "api");
        api.kind = EntityKind::Interface;
        g.upsert_entity(&api).unwrap();
        let next = g.drain_embedding_batch(1);
        assert_eq!(next[0].0, RetrievalKey::Entity(api.id));
        assert_eq!(g.embedding_queue.lock().frontier_rebuilds, 2);
    }

    #[cfg(feature = "vector")]
    #[test]
    fn embedding_frontier_rebuilds_when_existing_key_graph_priority_changes() {
        let g = InMemoryGraph::new();
        let mut first = test_entity_with_id(0x91, "first");
        first.visibility = Visibility::Private;
        let mut second = test_entity_with_id(0x92, "second");
        second.visibility = Visibility::Private;
        let mut promoted = test_entity_with_id(0x93, "promoted");
        promoted.visibility = Visibility::Private;
        g.upsert_entity(&first).unwrap();
        g.upsert_entity(&second).unwrap();
        g.upsert_entity(&promoted).unwrap();

        let first_batch = g.drain_embedding_batch(1);
        assert_eq!(first_batch[0].0, RetrievalKey::Entity(first.id));
        assert_eq!(g.embedding_queue.lock().frontier_rebuilds, 1);

        // `promoted` is already queued as ChangedThisSync. Its mutation keeps
        // the same membership and recency but changes the graph-derived tier,
        // so the cached remainder must still be invalidated.
        promoted.visibility = Visibility::Public;
        promoted.kind = EntityKind::Interface;
        g.upsert_entity(&promoted).unwrap();

        let next = g.drain_embedding_batch(1);
        assert_eq!(next[0].0, RetrievalKey::Entity(promoted.id));
        assert_eq!(g.embedding_queue.lock().frontier_rebuilds, 2);
    }

    #[cfg(feature = "vector")]
    #[test]
    fn relation_batch_add_rebuilds_frontier_for_changed_centrality() {
        let g = InMemoryGraph::new();
        let mut first = test_entity_with_id(0x91, "first");
        first.visibility = Visibility::Private;
        let mut second = test_entity_with_id(0x92, "second");
        second.visibility = Visibility::Private;
        let mut promoted = test_entity_with_id(0x93, "promoted");
        promoted.visibility = Visibility::Private;
        g.upsert_entity(&first).unwrap();
        g.upsert_entity(&second).unwrap();
        g.upsert_entity(&promoted).unwrap();

        let first_batch = g.drain_embedding_batch(1);
        assert_eq!(first_batch[0].0, RetrievalKey::Entity(first.id));
        assert_eq!(g.embedding_queue.lock().frontier_rebuilds, 1);

        // The incoming edge increases the higher-id entity's centrality while
        // it is already in the cached remainder. Batch relation mutation must
        // invalidate both endpoints after dropping the entity lock.
        let relation = test_relation(first.id, promoted.id, RelationKind::Calls);
        g.upsert_relations_batch(&[relation]).unwrap();

        let next = g.drain_embedding_batch(1);
        assert_eq!(next[0].0, RetrievalKey::Entity(promoted.id));
        assert_eq!(g.embedding_queue.lock().frontier_rebuilds, 2);
    }

    #[cfg(feature = "vector")]
    #[test]
    fn drain_artifact_embedding_batch_is_deterministic_and_recency_first() {
        let g = InMemoryGraph::new();
        // Pure queue-ordering test: ids are arbitrary distinct graph-assigned
        // values, not tied to any tracked path, so mint them directly.
        let id1 = ArtifactId::new();
        let id2 = ArtifactId::new();
        let id3 = ArtifactId::new();

        {
            let mut q = g.artifact_embedding_queue.lock();
            // Scrambled insertion order, mixed recency.
            q.insert(id3, EmbedRecency::Backfill);
            q.insert(id1, EmbedRecency::ChangedThisSync);
            q.insert(id2, EmbedRecency::Backfill);
            // Duplicate insert must dedup.
            q.insert(id2, EmbedRecency::Backfill);
        }
        assert_eq!(g.pending_artifact_embeddings(), 3);

        let order: Vec<ArtifactId> = g
            .drain_artifact_embedding_batch(100)
            .into_iter()
            .map(|(id, _)| id)
            .collect();

        // Changed-this-sync first, then backfill ids in ascending id order.
        let mut backfill = vec![id2, id3];
        backfill.sort();
        let mut expected = vec![id1];
        expected.extend(backfill);
        assert_eq!(order, expected);
    }

    /// Parity gate: popping a cached frontier in small batches must yield the
    /// IDENTICAL sequence to draining the whole queue in one shot. Equality
    /// proves the optimization changes only repeated queue bookkeeping, never
    /// the proof-sensitive global embedding order.
    #[cfg(feature = "vector")]
    #[test]
    fn drain_embedding_batch_frontier_matches_full_sort_and_builds_once() {
        let build = || {
            let g = InMemoryGraph::new();
            for i in 0..60u128 {
                let mut e = test_entity_with_id(0x200 + i, "e");
                e.visibility = match i % 4 {
                    0 => Visibility::Public,
                    1 => Visibility::Crate,
                    2 => Visibility::Internal,
                    _ => Visibility::Private,
                };
                if i.is_multiple_of(5) {
                    e.kind = EntityKind::Interface;
                }
                g.upsert_entity(&e).unwrap();
            }
            g
        };

        let g_full = build();
        let full: Vec<RetrievalKey> = g_full
            .drain_embedding_batch(10_000)
            .into_iter()
            .map(|(k, _)| k)
            .collect();

        let g_batched = build();
        let mut batched: Vec<RetrievalKey> = Vec::new();
        loop {
            let chunk = g_batched.drain_embedding_batch(7);
            if chunk.is_empty() {
                break;
            }
            batched.extend(chunk.into_iter().map(|(k, _)| k));
        }

        assert_eq!(
            full.len(),
            60,
            "the full drain must return every queued entity once"
        );
        assert_eq!(
            full, batched,
            "small-batch frontier pops must equal the full-sorted drain order"
        );
        assert_eq!(
            g_batched.embedding_queue.lock().frontier_rebuilds,
            1,
            "a stable backlog must be globally ordered once, not once per batch"
        );
    }

    /// Artifact-queue twin of the entity parity and one-build gate.
    #[cfg(feature = "vector")]
    #[test]
    fn drain_artifact_embedding_batch_frontier_matches_full_sort_and_builds_once() {
        let ids: Vec<ArtifactId> = (0..50).map(|_| ArtifactId::new()).collect();
        let fill = |g: &InMemoryGraph| {
            let mut q = g.artifact_embedding_queue.lock();
            for (i, id) in ids.iter().enumerate() {
                let recency = if i.is_multiple_of(3) {
                    EmbedRecency::ChangedThisSync
                } else {
                    EmbedRecency::Backfill
                };
                q.insert(*id, recency);
            }
        };

        let g_full = InMemoryGraph::new();
        fill(&g_full);
        let full: Vec<ArtifactId> = g_full
            .drain_artifact_embedding_batch(10_000)
            .into_iter()
            .map(|(id, _)| id)
            .collect();

        let g_batched = InMemoryGraph::new();
        fill(&g_batched);
        let mut batched: Vec<ArtifactId> = Vec::new();
        loop {
            let chunk = g_batched.drain_artifact_embedding_batch(6);
            if chunk.is_empty() {
                break;
            }
            batched.extend(chunk.into_iter().map(|(id, _)| id));
        }

        assert_eq!(
            full.len(),
            50,
            "the full drain must return every artifact once"
        );
        assert_eq!(
            full, batched,
            "artifact frontier pops must equal the full-sorted drain order"
        );
        assert_eq!(
            g_batched.artifact_embedding_queue.lock().frontier_rebuilds,
            1,
            "a stable artifact backlog must be globally ordered once"
        );
    }

    /// Stage-1 of the split embed pipeline: `prepare_pending_embedding_batch`
    /// drains the queue under the same deterministic ordering authority as
    /// `process_embedding_queue` and formats each entity's text — all under the
    /// graph read lock, with no GPU. (Stages 2/3 reach the embedder/index and are
    /// exercised on the GPU validation path.)
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn prepare_pending_embedding_batch_drains_in_priority_order() {
        let g = InMemoryGraph::new();
        let mut api = test_entity_with_id(0x90, "api");
        api.kind = EntityKind::Interface; // tier PUBLIC_API
        let pubfn = test_entity_with_id(0x91, "pubfn"); // tier PUBLIC_SOURCE
        g.upsert_entity(&api).unwrap();
        g.upsert_entity(&pubfn).unwrap();

        let prepared = g.prepare_pending_embedding_batch(100);
        assert_eq!(prepared.len(), 2);
        assert!(!prepared.is_empty());
        // Same drain authority as the monolithic path: API surface embeds first.
        assert_eq!(
            prepared.keys,
            vec![RetrievalKey::Entity(api.id), RetrievalKey::Entity(pubfn.id),],
            "prepare must drain in the deterministic priority order"
        );
        // Text is formatted parallel to keys and non-empty.
        assert_eq!(prepared.texts.len(), prepared.keys.len());
        assert!(prepared.texts.iter().all(|t| !t.is_empty()));
        // Prepare IS the draining stage: the queue is now empty.
        assert_eq!(g.pending_embeddings(), 0, "prepare drains the queue");
        // An empty queue prepares a no-op batch.
        assert!(g.prepare_pending_embedding_batch(100).is_empty());
    }

    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn prepare_pending_embedding_batch_formats_revision_and_preserves_skipped_recency() {
        let g = InMemoryGraph::new();
        let entity = test_entity_with_id(0x92, "rev_target");
        let (_rev_old, rev_new) = two_revision_entity(&g, &entity);
        let missing = RetrievalKey::Entity(EntityId(uuid::Uuid::from_u128(0xdead_beef)));

        {
            let mut queue = g.embedding_queue.lock();
            queue.clear();
            queue.insert(missing, EmbedRecency::ChangedThisSync);
            queue.insert(
                RetrievalKey::EntityRevision(rev_new),
                EmbedRecency::Backfill,
            );
        }

        let prepared = g.prepare_pending_embedding_batch(100);
        assert_eq!(
            prepared.keys,
            vec![RetrievalKey::EntityRevision(rev_new)],
            "only retrievable graph-backed keys should be prepared"
        );
        assert_eq!(prepared.texts.len(), 1);
        assert!(
            prepared.texts[0].contains("rev_target"),
            "revision text must be formatted from the revision entity"
        );
        assert_eq!(
            prepared.recency.get(&missing),
            Some(&EmbedRecency::ChangedThisSync),
            "recency metadata is retained for skipped keys so error requeue can preserve priority"
        );
        assert_eq!(
            prepared.recency.get(&RetrievalKey::EntityRevision(rev_new)),
            Some(&EmbedRecency::Backfill)
        );
    }

    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn prepare_pending_embedding_batch_tops_up_with_queued_artifacts() {
        let g = InMemoryGraph::new();
        let structured = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([0x31; 32]),
            text_preview: Some("build the workspace".into()),
        };
        let artifact_id = admit_enrichment(&g, &structured.file_id, structured.content_hash);
        g.upsert_structured_artifact(&structured).unwrap();
        assert_eq!(g.pending_artifact_embeddings(), 1);

        let prepared = g.prepare_pending_embedding_batch(10);
        assert_eq!(
            prepared.keys,
            vec![RetrievalKey::Artifact(artifact_id)],
            "an empty entity queue must top the batch up from the artifact queue"
        );
        assert_eq!(
            prepared.texts,
            vec![crate::embed::format_artifact_text(&structured)],
            "artifact text must come from the artifact embedding doc builder"
        );
        assert_eq!(
            prepared.recency.get(&RetrievalKey::Artifact(artifact_id)),
            Some(&EmbedRecency::ChangedThisSync),
            "the live-mutation recency tier must survive the top-up"
        );
        assert_eq!(
            g.pending_artifact_embeddings(),
            0,
            "prepare drains the artifact queue"
        );
    }

    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn prepare_pending_embedding_batch_formats_artifact_keys_from_the_entity_queue() {
        let g = InMemoryGraph::new();
        let shallow = ShallowTrackedFile {
            file_id: FilePathId::new("docs/AGENTS.md"),
            language_hint: "markdown".into(),
            declaration_count: 0,
            import_count: 0,
            syntax_hash: Hash256::from_bytes([0x32; 32]),
            signature_hash: None,
            declaration_names: vec!["Checks That Cannot Fail".into()],
            import_paths: vec![],
        };
        let artifact_id = admit_enrichment(&g, &shallow.file_id, shallow.syntax_hash);
        g.upsert_shallow_file(&shallow).unwrap();
        g.artifact_embedding_queue.lock().clear();

        g.queue_keys_for_embedding(&[RetrievalKey::Artifact(artifact_id)]);
        assert_eq!(g.pending_embeddings(), 1);

        let prepared = g.prepare_pending_embedding_batch(10);
        assert_eq!(
            prepared.keys,
            vec![RetrievalKey::Artifact(artifact_id)],
            "an artifact key in the unified queue must be prepared, not destroyed"
        );
        assert_eq!(
            prepared.texts,
            vec![crate::embed::format_shallow_text(&shallow)],
            "the shallow doc builder must format the artifact's text"
        );
        assert_eq!(g.pending_embeddings(), 0);
        assert_eq!(g.pending_artifact_embeddings(), 0);
    }

    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn prepare_pending_embedding_batch_drains_entities_before_artifact_topup() {
        let g = InMemoryGraph::new();
        let mut api = test_entity_with_id(0x93, "api");
        api.kind = EntityKind::Interface;
        let pubfn = test_entity_with_id(0x94, "pubfn");
        g.upsert_entity(&api).unwrap();
        g.upsert_entity(&pubfn).unwrap();
        let structured = StructuredArtifact {
            file_id: FilePathId::new("compose.yaml"),
            kind: ArtifactKind::ComposeFile,
            content_hash: Hash256::from_bytes([0x33; 32]),
            text_preview: Some("services".into()),
        };
        let artifact_id = admit_enrichment(&g, &structured.file_id, structured.content_hash);
        g.upsert_structured_artifact(&structured).unwrap();

        let first = g.prepare_pending_embedding_batch(2);
        assert_eq!(
            first.keys,
            vec![RetrievalKey::Entity(api.id), RetrievalKey::Entity(pubfn.id)],
            "a full entity batch must leave no capacity for artifact top-up"
        );
        assert_eq!(
            g.pending_artifact_embeddings(),
            1,
            "the artifact must wait for entity work to drain"
        );

        let second = g.prepare_pending_embedding_batch(2);
        assert_eq!(
            second.keys,
            vec![RetrievalKey::Artifact(artifact_id)],
            "the next batch must drain the queued artifact"
        );
        assert_eq!(g.pending_artifact_embeddings(), 0);
    }

    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn prepare_pending_embedding_batch_drains_doc_less_artifacts_without_stranding() {
        let g = InMemoryGraph::new();
        // A source-only artifact identity has no shallow/structured/opaque
        // enrichment record, so no embeddable document exists for it.
        let artifact_id = g.admit_artifact_for_test(
            "src/lib.rs",
            TreeEntry::blob(Hash256::from_bytes([0x34; 32]), false),
        );
        g.queue_artifacts_for_embedding(&[artifact_id]);
        assert_eq!(g.pending_artifact_embeddings(), 1);

        let prepared = g.prepare_pending_embedding_batch(10);
        assert!(
            prepared.is_empty(),
            "a doc-less artifact prepares no embeddable work"
        );
        assert_eq!(
            g.pending_artifact_embeddings(),
            0,
            "a doc-less artifact must drain rather than strand the queue"
        );
        assert_eq!(
            prepared.recency.get(&RetrievalKey::Artifact(artifact_id)),
            Some(&EmbedRecency::Backfill),
            "recency metadata is retained for skipped keys so error requeue can preserve priority"
        );
    }

    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn staged_embedding_helpers_handle_empty_batches_and_preserve_requeue_recency() {
        let g = InMemoryGraph::new();
        assert_eq!(g.process_embedding_queue(8).unwrap(), 0);

        let empty = PreparedEmbedBatch {
            keys: Vec::new(),
            texts: Vec::new(),
            recency: hashbrown::HashMap::new(),
        };
        assert!(g.embed_prepared_batch(&empty).unwrap().is_empty());
        assert_eq!(g.persist_embedded_batch(Vec::new(), &empty).unwrap(), 0);

        let changed = RetrievalKey::Entity(EntityId(uuid::Uuid::from_u128(0xbeef)));
        let defaulted = RetrievalKey::Entity(EntityId(uuid::Uuid::from_u128(0xcafe)));
        let mut recency = hashbrown::HashMap::new();
        recency.insert(changed, EmbedRecency::ChangedThisSync);

        g.requeue_embedding_keys([changed, defaulted], &recency);

        let queue = g.embedding_queue.lock();
        assert_eq!(
            queue.items.get(&changed),
            Some(&EmbedRecency::ChangedThisSync)
        );
        assert_eq!(queue.items.get(&defaulted), Some(&EmbedRecency::Backfill));
    }

    /// `prepare_pending_embedding_batch` must record exactly one drain and one
    /// prep against the stage-timing accumulator (the two never double-count),
    /// and must leave the GPU/index stages untouched on the CPU-only prep path.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn embed_stage_timing_records_drain_and_prep_once_per_prepare() {
        use crate::embed::EmbedStage;

        let g = InMemoryGraph::new();
        for i in 0..5u128 {
            let e = test_entity_with_id(0x300 + i, "e");
            g.upsert_entity(&e).unwrap();
        }

        let base = g.embed_stage_timings_snapshot();
        let prepared = g.prepare_pending_embedding_batch(3);
        assert!(!prepared.is_empty(), "upserts must have queued embed work");

        let delta = g.embed_stage_timings_snapshot().since(&base);
        assert_eq!(
            delta.stage(EmbedStage::Drain).calls,
            1,
            "one prepare drains exactly once"
        );
        assert_eq!(
            delta.stage(EmbedStage::Prep).calls,
            1,
            "one prepare formats exactly once"
        );
        // The forward/persist/prune stages need the embedder + index and must not
        // be touched by the CPU-only prep path.
        assert_eq!(delta.stage(EmbedStage::Forward).calls, 0);
        assert_eq!(delta.stage(EmbedStage::Persist).calls, 0);
        assert_eq!(delta.stage(EmbedStage::Prune).calls, 0);
    }

    /// The pipelined embed driver must persist exactly the serial path's
    /// (key, vector) sequence — same order, same values. A deterministic stub
    /// embedder (the vector is a pure function of the input text) lets this run on
    /// CPU with no GPU and no real model: any reordering or duplication introduced
    /// by the bounded producer→consumer pipeline shows up as a sequence mismatch.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn pipelined_embed_preserves_serial_persist_order() {
        // Deterministic per-text vector — no randomness, no model.
        fn stub_vector(text: &str) -> Vec<f32> {
            let mut acc = 0u32;
            for byte in text.bytes() {
                acc = acc.wrapping_mul(31).wrapping_add(byte as u32);
            }
            let base = acc as f32;
            vec![base, base + 1.0, base + 2.0, base + 3.0]
        }

        fn make_batch(ids: &[u128]) -> PreparedEmbedBatch {
            let keys: Vec<RetrievalKey> = ids
                .iter()
                .map(|n| RetrievalKey::Entity(EntityId(uuid::Uuid::from_u128(*n))))
                .collect();
            let texts: Vec<String> = ids.iter().map(|n| format!("entity-text-{n}")).collect();
            let recency = keys.iter().map(|k| (*k, EmbedRecency::Backfill)).collect();
            PreparedEmbedBatch {
                keys,
                texts,
                recency,
            }
        }

        // `fn` item (not a closure) so the same forward stage feeds both the serial
        // reference loop and the pipelined driver, which consumes it by value.
        fn forward(
            prepared: PreparedEmbedBatch,
        ) -> Result<(PreparedEmbedBatch, Vec<(RetrievalKey, Vec<f32>)>), KinDbError> {
            let embedded: Vec<(RetrievalKey, Vec<f32>)> = prepared
                .keys
                .iter()
                .zip(prepared.texts.iter())
                .map(|(key, text)| (*key, stub_vector(text)))
                .collect();
            Ok((prepared, embedded))
        }

        // Many batches of varying size so the bounded channels fill and the three
        // stages genuinely overlap across threads.
        let batch_id_lists: Vec<Vec<u128>> = (0..64u128)
            .map(|b| {
                let size = (b % 5) + 1;
                (0..size).map(|i| b * 100 + i + 1).collect()
            })
            .collect();

        // Serial reference: identical stub stages run strictly in sequence.
        let mut serial_order: Vec<(RetrievalKey, Vec<f32>)> = Vec::new();
        for ids in &batch_id_lists {
            let (_prepared, embedded) = forward(make_batch(ids)).unwrap();
            serial_order.extend(embedded);
        }

        // Pipelined: the real driver under test, same stub stages.
        let pipelined_order: std::sync::Mutex<Vec<(RetrievalKey, Vec<f32>)>> =
            std::sync::Mutex::new(Vec::new());
        let mut remaining = batch_id_lists.clone().into_iter();
        let total = drive_embed_pipeline(
            EMBED_PIPELINE_PREP_CAPACITY,
            EMBED_PIPELINE_RESULT_CAPACITY,
            move || Ok(remaining.next().map(|ids| make_batch(&ids))),
            forward,
            |_prepared, embedded: Vec<(RetrievalKey, Vec<f32>)>| {
                let count = embedded.len();
                pipelined_order.lock().unwrap().extend(embedded);
                Ok(count)
            },
            |_prepared| {},
        )
        .unwrap();

        let pipelined_order = pipelined_order.into_inner().unwrap();
        assert!(!serial_order.is_empty());
        assert_eq!(
            total,
            serial_order.len(),
            "pipeline must persist every prepared item exactly once"
        );
        assert_eq!(
            serial_order, pipelined_order,
            "pipelined persist order and values must equal the serial reference"
        );
    }

    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    fn pipelined_embed_abandons_every_drained_batch_on_persist_error() {
        let created = std::sync::Mutex::new(Vec::<RetrievalKey>::new());
        let abandoned = std::sync::Mutex::new(Vec::<RetrievalKey>::new());
        let mut remaining = (0..8u128).map(|n| vec![n + 1]);

        let err = drive_embed_pipeline(
            EMBED_PIPELINE_PREP_CAPACITY,
            EMBED_PIPELINE_RESULT_CAPACITY,
            || {
                let Some(ids) = remaining.next() else {
                    return Ok(None);
                };
                let prepared = {
                    let keys: Vec<RetrievalKey> = ids
                        .iter()
                        .map(|n| RetrievalKey::Entity(EntityId(uuid::Uuid::from_u128(*n))))
                        .collect();
                    created.lock().unwrap().extend(keys.iter().copied());
                    let recency = keys.iter().map(|k| (*k, EmbedRecency::Backfill)).collect();
                    PreparedEmbedBatch {
                        texts: keys.iter().map(|k| format!("{k:?}")).collect(),
                        keys,
                        recency,
                    }
                };
                Ok(Some(prepared))
            },
            |prepared| {
                let embedded = prepared
                    .keys
                    .iter()
                    .map(|key| (*key, vec![1.0, 2.0, 3.0, 4.0]))
                    .collect();
                Ok((prepared, embedded))
            },
            |prepared, _embedded| {
                abandoned
                    .lock()
                    .unwrap()
                    .extend(prepared.recency.keys().copied());
                Err(KinDbError::StorageError("persist failed".into()))
            },
            |prepared| {
                abandoned
                    .lock()
                    .unwrap()
                    .extend(prepared.recency.keys().copied());
            },
        )
        .unwrap_err();

        assert!(
            format!("{err}").contains("persist failed"),
            "the original persist error should be returned"
        );
        let mut created = created.into_inner().unwrap();
        let mut abandoned = abandoned.into_inner().unwrap();
        created.sort();
        abandoned.sort();
        assert_eq!(
            created, abandoned,
            "every drained prepared batch must be abandoned for requeue on pipeline failure"
        );
    }

    /// CPU microbench for the embed hot-path changes. Ignored by default;
    /// run with `cargo test -p kin-db --lib embed_hot_path_microbench -- --ignored --nocapture`.
    #[cfg(all(feature = "embeddings", feature = "vector"))]
    #[test]
    #[ignore = "perf microbench; run with --ignored --nocapture"]
    fn embed_hot_path_microbench() {
        use std::time::Instant;

        // S1 — per-batch text cloning vs borrowing the owned text buffer.
        let n = 5_000usize;
        let texts: Vec<String> = (0..n).map(|i| format!("{}{i}", "x".repeat(1024))).collect();
        let rounds = 50;
        let mut sink = 0usize;
        let t = Instant::now();
        for _ in 0..rounds {
            let cloned: Vec<String> = texts.to_vec();
            sink = sink.wrapping_add(cloned.len());
        }
        let old_clone = t.elapsed();
        let t = Instant::now();
        for _ in 0..rounds {
            let borrowed: &[String] = &texts[..];
            sink = sink.wrapping_add(borrowed.len());
        }
        let new_slice = t.elapsed();
        eprintln!(
            "[S1] text reuse {rounds}x{n} (~{} MB cloned/round): old clone {old_clone:?} vs new borrow {new_slice:?} (sink={sink})",
            n * 1024 / (1024 * 1024)
        );

        // S2 — repeated backlog partition/reinsert versus one global ordering
        // followed by O(batch) frontier pops. This excludes HashMap lock cost,
        // so it is a conservative view of the production improvement.
        let m = 20_000usize;
        let ids: Vec<ArtifactId> = (0..m).map(|_| ArtifactId::new()).collect();
        let batch = 256usize;
        let recency_of = |i: usize| {
            if i.is_multiple_of(4) {
                EmbedRecency::ChangedThisSync
            } else {
                EmbedRecency::Backfill
            }
        };
        let order = |a: &(ArtifactId, EmbedRecency), b: &(ArtifactId, EmbedRecency)| {
            a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0))
        };
        let base: Vec<(ArtifactId, EmbedRecency)> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| (*id, recency_of(i)))
            .collect();

        let t = Instant::now();
        let mut sink2 = 0u128;
        let mut old_queue = base.clone();
        while !old_queue.is_empty() {
            let take = batch.min(old_queue.len());
            if take < old_queue.len() {
                old_queue.select_nth_unstable_by(take, order);
            }
            let leftover = old_queue.split_off(take);
            old_queue.sort_unstable_by(order);
            sink2 ^= old_queue[0].0 .0.as_u128();
            old_queue = leftover;
        }
        let old_repartition = t.elapsed();

        let t = Instant::now();
        let mut ordered = base;
        ordered.sort_unstable_by(order);
        for chunk in ordered.chunks(batch) {
            sink2 ^= chunk[0].0 .0.as_u128();
        }
        let new_frontier = t.elapsed();
        eprintln!(
            "[S2] complete drain m={m} take={batch}: old repeated partition {old_repartition:?} vs cached frontier {new_frontier:?} (sink={sink2})"
        );

        // S3 — prune: full index scan vs incremental tracked eviction.
        let k = 30_000usize;
        let entities: Vec<Entity> = (0..k as u128)
            .map(|i| test_entity_with_id(0x10000 + i, "e"))
            .collect();
        let g = InMemoryGraph::new();
        g.batch_upsert_entities(&entities).unwrap();
        let orphan_keys: Vec<RetrievalKey> = (0..10u128)
            .map(|i| RetrievalKey::Entity(test_entity_with_id(0x9990_0000 + i, "orphan").id))
            .collect();
        let vi = VectorIndex::new(2).unwrap();
        for e in &entities {
            vi.upsert_retrievable(RetrievalKey::Entity(e.id), &[1.0, 0.0])
                .unwrap();
        }
        for key in &orphan_keys {
            vi.upsert_retrievable(*key, &[0.0, 1.0]).unwrap();
        }
        *g.vector_index.lock() = Some(Arc::new(vi));

        let t = Instant::now();
        let evicted_full = g.prune_orphaned_vectors();
        let full_scan = t.elapsed();

        {
            let vi = g.vector_index.lock().clone().unwrap();
            for key in &orphan_keys {
                vi.upsert_retrievable(*key, &[0.0, 1.0]).unwrap();
            }
        }
        {
            let mut st = g.vector_reconcile.lock();
            st.full = false;
            for key in &orphan_keys {
                st.superseded.insert(*key);
            }
        }
        let t = Instant::now();
        let evicted_inc = g.prune_orphaned_vectors();
        let incremental = t.elapsed();
        eprintln!(
            "[S3] prune index={} truth={k}: old full-scan {full_scan:?} (evicted {evicted_full}) vs new incremental {incremental:?} (evicted {evicted_inc})",
            k + orphan_keys.len()
        );
        assert_eq!(evicted_full, orphan_keys.len());
        assert_eq!(evicted_inc, orphan_keys.len());
    }

    /// Rider 1: the live invalidate (re-enqueue) path must UPGRADE an item
    /// already queued as Backfill to ChangedThisSync — a max-priority insert,
    /// never first-writer-wins — and must not duplicate it.
    #[cfg(feature = "vector")]
    #[test]
    fn invalidate_path_upgrades_queued_backfill_to_changed_this_sync() {
        let g = InMemoryGraph::new();
        // peer has the LOWER id, target the HIGHER id. Same tier + centrality.
        // If recency were ignored, the id tiebreak alone would order [peer, target];
        // an upgrade of `target` to ChangedThisSync must flip that to [target, peer].
        let peer = test_entity_with_id(0x90, "peer");
        let target = test_entity_with_id(0x91, "target");
        g.upsert_entity(&peer).unwrap();
        g.upsert_entity(&target).unwrap();

        // Establish a known baseline: both queued as Backfill.
        g.embedding_queue.lock().clear();
        g.queue_for_embedding(&[peer.id, target.id]);
        assert_eq!(g.pending_embeddings(), 2);

        // Live mutation re-enqueues `target` via the invalidate path.
        g.upsert_entity(&target).unwrap();
        assert_eq!(
            g.pending_embeddings(),
            2,
            "re-enqueue must upgrade in place, not add a duplicate"
        );

        let order: Vec<RetrievalKey> = g
            .drain_embedding_batch(100)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            order,
            vec![
                RetrievalKey::Entity(target.id),
                RetrievalKey::Entity(peer.id)
            ],
            "invalidate path must UPGRADE backfill→changed-this-sync (max policy), \
             flipping the id-tiebreak order"
        );
    }

    // -----------------------------------------------------------------------
    // Memory re-anchor — rename-durable annotation recall (Track B)
    // -----------------------------------------------------------------------

    #[test]
    fn deposit_captures_entity_fingerprint_anchor() {
        let graph = InMemoryGraph::new();
        let mut e = test_entity("foo", "src/lib.rs");
        e.fingerprint.ast_hash = Hash256::from_bytes([7; 32]);
        e.fingerprint.signature_hash = Hash256::from_bytes([9; 32]);
        graph.upsert_entity(&e).unwrap();

        // Deposit with no anchor — the store must capture the entity fingerprint.
        let ann = Annotation {
            annotation_id: AnnotationId::new(),
            kind: AnnotationKind::Instruction,
            body: "remember the invariant".into(),
            scopes: vec![WorkScope::Entity(e.id)],
            anchored_fingerprint: None,
            authored_by: IdentityRef::human("alice"),
            created_at: Timestamp::now(),
            staleness: StalenessState::Fresh,
        };
        graph.create_annotation(&ann).unwrap();
        let anchor = graph
            .get_annotation(&ann.annotation_id)
            .unwrap()
            .unwrap()
            .anchored_fingerprint
            .expect("deposit must capture the entity fingerprint anchor");
        assert_eq!(anchor.ast_hash, Hash256::from_bytes([7; 32]));
        assert_eq!(anchor.signature_hash, Hash256::from_bytes([9; 32]));

        // A caller-supplied anchor must be preserved, not overwritten.
        let custom = SemanticAnchor {
            ast_hash: Hash256::from_bytes([1; 32]),
            signature_hash: Hash256::from_bytes([2; 32]),
        };
        let ann2 = Annotation {
            annotation_id: AnnotationId::new(),
            anchored_fingerprint: Some(custom.clone()),
            ..ann.clone()
        };
        graph.create_annotation(&ann2).unwrap();
        assert_eq!(
            graph
                .get_annotation(&ann2.annotation_id)
                .unwrap()
                .unwrap()
                .anchored_fingerprint,
            Some(custom),
            "caller-supplied anchor must be preserved"
        );

        // No entity scope → no anchor captured.
        let ann3 = Annotation {
            annotation_id: AnnotationId::new(),
            scopes: vec![WorkScope::Artifact(FilePathId::new("src/lib.rs"))],
            anchored_fingerprint: None,
            ..ann.clone()
        };
        graph.create_annotation(&ann3).unwrap();
        assert!(graph
            .get_annotation(&ann3.annotation_id)
            .unwrap()
            .unwrap()
            .anchored_fingerprint
            .is_none());
    }

    /// Deposit an annotation on a scope (anchor captured by `create_annotation`).
    fn deposit_on(graph: &InMemoryGraph, ann_seed: u128, scope: WorkScope) -> AnnotationId {
        let id = AnnotationId(uuid::Uuid::from_u128(ann_seed));
        let ann = Annotation {
            annotation_id: id,
            kind: AnnotationKind::Instruction,
            body: "remembered detail".into(),
            scopes: vec![scope],
            anchored_fingerprint: None,
            authored_by: IdentityRef::human("t"),
            created_at: Timestamp::now(),
            staleness: StalenessState::Fresh,
        };
        graph.create_annotation(&ann).unwrap();
        id
    }

    fn entity_with_fp(seed: u128, name: &str, file: &str, ast: u8, sig: u8) -> Entity {
        let mut e = test_entity_with_id(seed, name);
        e.file_origin = Some(FilePathId::new(file));
        e.fingerprint.ast_hash = Hash256::from_bytes([ast; 32]);
        e.fingerprint.signature_hash = Hash256::from_bytes([sig; 32]);
        e
    }

    #[test]
    fn recall_by_exact_id_is_fresh() {
        let graph = InMemoryGraph::new();
        let e = entity_with_fp(0x100, "foo", "src/a.rs", 1, 2);
        graph.upsert_entity(&e).unwrap();
        deposit_on(&graph, 0xa1, WorkScope::Entity(e.id));

        let recalled = graph.recall_for_entity(&e.id);
        assert_eq!(recalled.len(), 1);
        assert_eq!(recalled[0].match_basis, RecallMatchBasis::Id);
        assert_eq!(recalled[0].staleness, StalenessState::Fresh);
    }

    #[test]
    fn recall_reanchors_across_rename() {
        let graph = InMemoryGraph::new();
        let old = entity_with_fp(0x200, "oldName", "src/a.rs", 5, 6);
        graph.upsert_entity(&old).unwrap();
        deposit_on(&graph, 0xb1, WorkScope::Entity(old.id)); // anchor = (5, 6)

        // Rename: the old entity is removed and a new entity (different id, same
        // file/kind/fingerprint, different name) takes its place.
        graph.remove_entity(&old.id).unwrap();
        let new = entity_with_fp(0x201, "newName", "src/a.rs", 5, 6);
        graph.upsert_entity(&new).unwrap();

        // Recall by the NEW id re-anchors the orphaned memory by fingerprint.
        let recalled = graph.recall_for_entity(&new.id);
        assert_eq!(recalled.len(), 1);
        assert_eq!(
            recalled[0].annotation.annotation_id,
            AnnotationId(uuid::Uuid::from_u128(0xb1))
        );
        assert_eq!(
            recalled[0].match_basis,
            RecallMatchBasis::FingerprintReanchor
        );
        assert_eq!(recalled[0].staleness, StalenessState::Fresh);

        // The old (now-removed) id resolves to nothing.
        assert!(graph.recall_for_entity(&old.id).is_empty());
    }

    #[test]
    fn recall_staleness_tiers_by_signature_then_ast_change() {
        let graph = InMemoryGraph::new();
        let e = entity_with_fp(0x300, "f", "src/a.rs", 3, 4);
        graph.upsert_entity(&e).unwrap();
        deposit_on(&graph, 0xc1, WorkScope::Entity(e.id)); // anchor = (3, 4)

        // Signature changes (ast unchanged) → Suspect, still recalled by default.
        graph
            .upsert_entity(&entity_with_fp(0x300, "f", "src/a.rs", 3, 44))
            .unwrap();
        let r = graph.recall_for_entity(&e.id);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].staleness, StalenessState::Suspect);

        // AST changes too → Stale: excluded by default, included on request.
        graph
            .upsert_entity(&entity_with_fp(0x300, "f", "src/a.rs", 33, 44))
            .unwrap();
        assert!(
            graph.recall_for_entity(&e.id).is_empty(),
            "Stale matches are excluded by default"
        );
        let r_all = graph.recall_for_entity_with(
            &e.id,
            &RecallOptions {
                include_stale: true,
                ..Default::default()
            },
        );
        assert_eq!(r_all.len(), 1);
        assert_eq!(r_all[0].staleness, StalenessState::Stale);
    }

    #[test]
    fn recall_excludes_fingerprint_collisions_by_default() {
        let graph = InMemoryGraph::new();
        // Two DIFFERENT live entities sharing a fingerprint (duplicated code).
        let x = entity_with_fp(0x400, "x", "src/x.rs", 8, 8);
        let y = entity_with_fp(0x401, "y", "src/y.rs", 8, 8);
        graph.upsert_entity(&x).unwrap();
        graph.upsert_entity(&y).unwrap();
        deposit_on(&graph, 0xd1, WorkScope::Entity(y.id)); // memory on Y

        // Recall for X: Y is still live, so its memory is a collision — excluded.
        assert!(
            graph.recall_for_entity(&x.id).is_empty(),
            "another live entity's memory must not surface by default"
        );

        // Opt-in surfaces it, tagged as a cross-file collision.
        let r = graph.recall_for_entity_with(
            &x.id,
            &RecallOptions {
                include_fingerprint_collisions: true,
                ..Default::default()
            },
        );
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].match_basis, RecallMatchBasis::FingerprintCollision);
        assert!(!r[0].same_file, "Y is in a different file than X");

        // Y itself recalls its own memory as an exact-id match.
        let ry = graph.recall_for_entity(&y.id);
        assert_eq!(ry.len(), 1);
        assert_eq!(ry[0].match_basis, RecallMatchBasis::Id);
    }

    #[test]
    fn reanchor_orphaned_annotations_rescopes_unique_rename() {
        let graph = InMemoryGraph::new();
        let old = entity_with_fp(0x500, "oldName", "src/a.rs", 5, 6);
        graph.upsert_entity(&old).unwrap();
        deposit_on(&graph, 0xe1, WorkScope::Entity(old.id));

        // Rename to a single new entity sharing the fingerprint.
        graph.remove_entity(&old.id).unwrap();
        let new = entity_with_fp(0x501, "newName", "src/a.rs", 5, 6);
        graph.upsert_entity(&new).unwrap();

        // Before active re-scope, recall resolves only via fingerprint re-anchor.
        assert_eq!(
            graph.recall_for_entity(&new.id)[0].match_basis,
            RecallMatchBasis::FingerprintReanchor
        );

        // Active re-scope appends the new entity scope (unambiguous match).
        assert_eq!(graph.reanchor_orphaned_annotations(), 1);
        let recalled = graph.recall_for_entity(&new.id);
        assert_eq!(recalled.len(), 1);
        assert_eq!(
            recalled[0].match_basis,
            RecallMatchBasis::Id,
            "after re-scope the memory is an exact-id match"
        );

        // Idempotent: a second pass changes nothing.
        assert_eq!(graph.reanchor_orphaned_annotations(), 0);
    }

    #[test]
    fn reanchor_skips_ambiguous_fingerprint() {
        let graph = InMemoryGraph::new();
        let old = entity_with_fp(0x600, "oldName", "src/a.rs", 7, 7);
        graph.upsert_entity(&old).unwrap();
        deposit_on(&graph, 0xf1, WorkScope::Entity(old.id));
        graph.remove_entity(&old.id).unwrap();

        // Two live entities now share the orphaned anchor's fingerprint.
        graph
            .upsert_entity(&entity_with_fp(0x601, "candA", "src/a.rs", 7, 7))
            .unwrap();
        graph
            .upsert_entity(&entity_with_fp(0x602, "candB", "src/b.rs", 7, 7))
            .unwrap();

        // Ambiguous → must NOT commit a re-scope (could mis-anchor to a duplicate).
        assert_eq!(graph.reanchor_orphaned_annotations(), 0);
        let ann = graph
            .get_annotation(&AnnotationId(uuid::Uuid::from_u128(0xf1)))
            .unwrap()
            .unwrap();
        assert_eq!(
            ann.scopes,
            vec![WorkScope::Entity(old.id)],
            "ambiguous anchors are left for lazy fingerprint recall, not committed"
        );
    }

    // -----------------------------------------------------------------------
    // Vector index self-description / dimension recovery (R2/R9, #10c)
    // -----------------------------------------------------------------------

    #[cfg(feature = "vector")]
    #[test]
    fn save_vector_index_persists_stamped_descriptor() {
        use crate::vector::{IndexDescriptor, IndexLoadOutcome};

        let graph = InMemoryGraph::new();
        let vi = crate::VectorIndex::new(2).unwrap();
        vi.upsert(EntityId::new(), &[1.0, 0.0]).unwrap();
        *graph.vector_index.lock() = Some(std::sync::Arc::new(vi));

        graph.stamp_vector_index_descriptor(IndexDescriptor {
            model_id: Some("model-A@1".into()),
            graph_root: Some("root-1".into()),
        });

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("g.kvec");
        graph.save_vector_index(&path).unwrap();

        // The persisted .kvec proves its own model/graph identity on load.
        assert!(matches!(
            crate::VectorIndex::load_compatible(
                &path,
                &IndexDescriptor {
                    model_id: Some("model-A@1".into()),
                    graph_root: Some("root-1".into()),
                },
            ),
            IndexLoadOutcome::Loaded(_)
        ));
        // A same-dimension model swap is caught from the stamp alone.
        assert!(matches!(
            crate::VectorIndex::load_compatible(
                &path,
                &IndexDescriptor {
                    model_id: Some("model-B@1".into()),
                    graph_root: Some("root-1".into()),
                },
            ),
            IndexLoadOutcome::Incompatible(_)
        ));
    }

    #[cfg(feature = "vector")]
    #[test]
    fn load_vector_index_compatible_rejects_swap_without_installing() {
        use crate::vector::{IndexDescriptor, VectorIndexLoad};

        // Persist a stamped index (model-A).
        let writer = InMemoryGraph::new();
        let vi = crate::VectorIndex::new(2).unwrap();
        vi.upsert(EntityId::new(), &[1.0, 0.0]).unwrap();
        *writer.vector_index.lock() = Some(std::sync::Arc::new(vi));
        writer.stamp_vector_index_descriptor(IndexDescriptor {
            model_id: Some("model-A@1".into()),
            graph_root: Some("root-1".into()),
        });
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("g.kvec");
        writer.save_vector_index(&path).unwrap();

        // A model-B expectation is rejected and NOT installed (no silent garbage).
        let graph = InMemoryGraph::new();
        let out = graph.load_vector_index_compatible(
            &path,
            &IndexDescriptor {
                model_id: Some("model-B@1".into()),
                graph_root: Some("root-1".into()),
            },
        );
        assert!(matches!(out, VectorIndexLoad::Incompatible(_)));
        assert!(
            graph.vector_index.lock().is_none(),
            "an incompatible index must never be installed"
        );

        // The matching expectation installs it.
        let out2 = graph.load_vector_index_compatible(
            &path,
            &IndexDescriptor {
                model_id: Some("model-A@1".into()),
                graph_root: Some("root-1".into()),
            },
        );
        assert!(matches!(out2, VectorIndexLoad::Loaded(1)));
        assert!(graph.vector_index.lock().is_some());
    }

    // ----------------------------------------------------------------------
    // Baseline graph determinism. Root hash and traversal output must
    // not depend on relation insertion order, must survive save/reopen, and (for
    // the parity baseline) must be content-determined rather than dependent on the
    // random entity/relation ids assigned at ingest. The fixture has a
    // multi-outgoing hub and a 2-cycle, which is where the sorted cycle-break in
    // MerkleCache::from_source is load-bearing.
    // ----------------------------------------------------------------------

    // hub --Calls--> {a,b,c,d} (multi-outgoing); a <-> b (2-cycle); c -> d -> e.
    fn determinism_fixture() -> (Vec<Entity>, Vec<Relation>) {
        let hub = test_entity("hub", "src/hub.rs");
        let a = test_entity("alpha", "src/a.rs");
        let b = test_entity("beta", "src/b.rs");
        let c = test_entity("gamma", "src/c.rs");
        let d = test_entity("delta", "src/d.rs");
        let e = test_entity("epsilon", "src/e.rs");
        let rels = vec![
            test_relation(hub.id, a.id, RelationKind::Calls),
            test_relation(hub.id, b.id, RelationKind::Calls),
            test_relation(hub.id, c.id, RelationKind::Calls),
            test_relation(hub.id, d.id, RelationKind::Calls),
            test_relation(a.id, b.id, RelationKind::Calls),
            test_relation(b.id, a.id, RelationKind::Calls),
            test_relation(c.id, d.id, RelationKind::Calls),
            test_relation(d.id, e.id, RelationKind::Calls),
        ];
        (vec![hub, a, b, c, d, e], rels)
    }

    fn determinism_build(ents: &[Entity], rels: &[Relation], order: &[usize]) -> InMemoryGraph {
        let g = InMemoryGraph::new();
        for e in ents {
            g.upsert_entity(e).unwrap();
        }
        for &i in order {
            g.upsert_relation(&rels[i]).unwrap();
        }
        g
    }

    const DETERMINISM_SHUFFLE: [usize; 8] = [7, 5, 2, 4, 0, 6, 3, 1];

    #[test]
    fn determinism_root_hash_independent_of_relation_insertion_order() {
        let (ents, rels) = determinism_fixture();
        let fwd: Vec<usize> = (0..rels.len()).collect();
        let g1 = determinism_build(&ents, &rels, &fwd);
        let g2 = determinism_build(&ents, &rels, &DETERMINISM_SHUFFLE);
        assert_eq!(
            g1.compute_root_hash(),
            g2.compute_root_hash(),
            "root must be independent of relation insertion order (multi-outgoing + cycle)"
        );
        assert_eq!(
            g1.compute_root_hash(),
            compute_graph_root_hash(&g1.to_snapshot()),
            "deferred InMemoryGraph root must equal the from_snapshot root"
        );
    }

    // Content-derived ids mirror production ingest (kin-parser `EntityId::from_content`
    // + kin-index `stable_relation_id`): identical source yields identical ids, which
    // is what makes the id-ordered cycle-break in MerkleCache::from_source stable.
    fn determinism_fixture_content_derived() -> (Vec<Entity>, Vec<Relation>) {
        let (mut ents, _) = determinism_fixture();
        for e in &mut ents {
            let file = e
                .file_origin
                .as_ref()
                .map(|f| f.0.clone())
                .unwrap_or_default();
            e.id = EntityId::from_content(&file, &e.name, &format!("{:?}", e.kind), 0);
        }
        let ids: Vec<EntityId> = ents.iter().map(|e| e.id).collect();
        let mk = |s: EntityId, d: EntityId| -> Relation {
            let mut r = test_relation(s, d, RelationKind::Calls);
            r.id = RelationId::from_content(&s.0.to_string(), &d.0.to_string(), "Calls");
            r
        };
        // hub->{a,b,c,d}; a<->b (cycle); c->d->e.
        let rels = vec![
            mk(ids[0], ids[1]),
            mk(ids[0], ids[2]),
            mk(ids[0], ids[3]),
            mk(ids[0], ids[4]),
            mk(ids[1], ids[2]),
            mk(ids[2], ids[1]),
            mk(ids[3], ids[4]),
            mk(ids[4], ids[5]),
        ];
        (ents, rels)
    }

    #[test]
    fn determinism_cyclic_root_is_stable_under_content_derived_ids() {
        // Production assigns content-derived ids, so two independent builds of the
        // same source yield identical ids and — despite the 2-cycle — an identical
        // root. This is why the graph/Merkle root is deterministic in production and
        // is ruled out as the parity-citable nondeterminism source. (The cycle-break
        // is id-ordered, so this stability is contingent on content-derived ids.)
        let fwd: Vec<usize> = (0..8).collect();
        let (e1, r1) = determinism_fixture_content_derived();
        let (e2, r2) = determinism_fixture_content_derived();
        let g1 = determinism_build(&e1, &r1, &fwd);
        let g2 = determinism_build(&e2, &r2, &fwd);
        assert_eq!(
            g1.compute_root_hash(),
            g2.compute_root_hash(),
            "with content-derived ids, the cyclic-graph root must be stable across builds"
        );
    }

    #[test]
    fn determinism_root_hash_stable_across_save_reopen() {
        let (ents, rels) = determinism_fixture();
        let fwd: Vec<usize> = (0..rels.len()).collect();
        let g = determinism_build(&ents, &rels, &fwd);
        let before = g.compute_root_hash();
        let reopened = InMemoryGraph::from_snapshot(g.to_snapshot()).unwrap();
        assert_eq!(
            before,
            reopened.compute_root_hash(),
            "root must survive to_snapshot -> from_snapshot"
        );
    }

    #[test]
    fn determinism_relation_and_neighborhood_ordering_independent_of_insertion_order() {
        let (ents, rels) = determinism_fixture();
        let hub = ents[0].id;
        let fwd: Vec<usize> = (0..rels.len()).collect();
        let g1 = determinism_build(&ents, &rels, &fwd);
        let g2 = determinism_build(&ents, &rels, &DETERMINISM_SHUFFLE);

        let rel_ids = |g: &InMemoryGraph| -> Vec<RelationId> {
            g.get_all_relations_for_entity(&hub)
                .unwrap()
                .iter()
                .map(|r| r.id)
                .collect()
        };
        assert_eq!(
            rel_ids(&g1),
            rel_ids(&g2),
            "get_all_relations_for_entity order must not depend on insertion order"
        );

        let sg1 = g1.get_dependency_neighborhood(&hub, 3).unwrap();
        let sg2 = g2.get_dependency_neighborhood(&hub, 3).unwrap();
        assert_eq!(
            sg1.nodes, sg2.nodes,
            "neighborhood node order must not depend on insertion order"
        );
        let nrel =
            |sg: &SubGraph| -> Vec<RelationId> { sg.relations.iter().map(|r| r.id).collect() };
        assert_eq!(
            nrel(&sg1),
            nrel(&sg2),
            "neighborhood relation order must not depend on insertion order"
        );
    }
}
