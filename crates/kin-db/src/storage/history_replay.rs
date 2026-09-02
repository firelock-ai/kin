// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Single-pass first-parent history replay for repository-authority admission.
//!
//! Repository admission and every unproven authority open must prove that the
//! persisted change DAG replays: each change's declared old payloads match the
//! state its first parent published, no change adds an identity that lineage
//! already carries, and no change leaves a relation dangling.
//!
//! Resolving that proof one change at a time walks from each change to genesis
//! and re-derives the whole graph, so a linear history costs `O(history^2)` in
//! walked changes and re-runs the whole-relation-set dangling scan once per
//! walked change. Material state has exactly one parent, the first ordered one,
//! so the changes form a first-parent forest: walking it once and carrying a
//! single state proves the same property at every node.
//!
//! Exactness is what makes this substitutable for the per-change replay rather
//! than an approximation of it:
//!
//! * Each change's state is uniquely determined, because its first-parent chain
//!   is unique. Validating a change once against that state is the same check
//!   the per-change replay performed once per target whose chain contained it.
//! * Rewinding a change applies the delta inverses in reverse order through the
//!   same validated transitions. Every inverse is fully determined by the delta
//!   itself: `Added` refuses unless the identity was absent, and `Modified` and
//!   `Removed` refuse unless the current payload equals the declared old one, so
//!   the pre-change value is exactly what the delta names.
//! * The dangling scan is narrowed to the endpoints a change can actually
//!   break. Given no relation dangled before the change, one can only dangle
//!   after it if the change asserted that relation or dropped one of its
//!   endpoint nodes, so checking those two sets is equivalent to rescanning
//!   every relation.
//!
//! The traversal ends by asserting the rewind restored the empty root state. A
//! state that does not come back to empty means the forward and inverse
//! transitions disagreed, and that fails the gate loudly instead of admitting
//! an unproven history.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::{Duration, Instant};

use kin_model::{
    Entity, EntityDelta, EntityId, ExternalReference, ExternalReferenceDelta, ExternalReferenceId,
    GraphNodeId, ModelError, Relation, RelationDelta, RelationId, ResolvedTree, SemanticChange,
    SemanticChangeId, TreeDelta,
};

use crate::error::KinDbError;

/// Wall-clock gap between progress reports for one long replay.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);

/// Replays below this many changes finish fast enough that reporting progress
/// would only add noise to every ordinary command.
const PROGRESS_MIN_TOTAL: usize = 1_000;

/// Changes validated between clock reads, so the cadence check cannot become a
/// measurable share of a replay that is otherwise pure in-memory work.
const PROGRESS_CLOCK_STRIDE: usize = 256;

fn storage(message: String) -> KinDbError {
    KinDbError::StorageError(message)
}

/// Periodic `validated / total, elapsed` reporting for one admission phase.
///
/// Long admissions previously ran for hours with no output at all, which left
/// an operator unable to tell a slow phase from a wedged one.
///
/// Every emit here carries the target of this module, which is the target a
/// `kin` command raises to `info` while admitting a repository. A phase that
/// reports from elsewhere in kin-db is silent to that command by default.
pub(crate) struct ReplayProgress {
    phase: &'static str,
    /// What one unit of this phase is, so a phase counting Git objects does not
    /// report them as changes.
    unit: &'static str,
    total: usize,
    validated: usize,
    started: Instant,
    last_report: Instant,
    /// Held per instance rather than read from the constant so a test can drive
    /// the periodic emit without waiting out a real interval.
    interval: Duration,
    reports: usize,
}

impl ReplayProgress {
    pub(crate) fn new(phase: &'static str, unit: &'static str, total: usize) -> Self {
        Self::with_interval(phase, unit, total, PROGRESS_INTERVAL)
    }

    fn with_interval(
        phase: &'static str,
        unit: &'static str,
        total: usize,
        interval: Duration,
    ) -> Self {
        let now = Instant::now();
        if total >= PROGRESS_MIN_TOTAL {
            tracing::info!(phase, unit, total, "kindb: validating {total} {unit}");
        }
        Self {
            phase,
            unit,
            total,
            validated: 0,
            started: now,
            last_report: now,
            interval,
            reports: 0,
        }
    }

    pub(crate) fn record(&mut self) {
        self.validated += 1;
        if self.total < PROGRESS_MIN_TOTAL || !self.validated.is_multiple_of(PROGRESS_CLOCK_STRIDE)
        {
            return;
        }
        let now = Instant::now();
        if now.duration_since(self.last_report) < self.interval {
            return;
        }
        self.last_report = now;
        self.reports += 1;
        let elapsed_secs = self.started.elapsed().as_secs();
        let (phase, unit, validated, total) = (self.phase, self.unit, self.validated, self.total);
        tracing::info!(
            phase,
            unit,
            validated,
            total,
            elapsed_secs,
            "kindb: validated {validated}/{total} {unit} in {elapsed_secs}s"
        );
    }

    pub(crate) fn finish(self) {
        if self.total < PROGRESS_MIN_TOTAL {
            return;
        }
        let elapsed_secs = self.started.elapsed().as_secs();
        let (phase, unit, validated) = (self.phase, self.unit, self.validated);
        tracing::info!(
            phase,
            unit,
            validated,
            elapsed_secs,
            "kindb: validated {validated} {unit} in {elapsed_secs}s"
        );
    }

    #[cfg(test)]
    fn reports(&self) -> usize {
        self.reports
    }

    /// Close the phase out when the replay refused.
    ///
    /// The error itself propagates, but without this the reporter opens a phase
    /// and never closes it, so a long refused admission reads as a run that
    /// simply stopped emitting. An observable terminus is the whole point.
    pub(crate) fn abandon(self) {
        if self.total < PROGRESS_MIN_TOTAL {
            return;
        }
        let elapsed_secs = self.started.elapsed().as_secs();
        let (phase, unit, validated) = (self.phase, self.unit, self.validated);
        tracing::info!(
            phase,
            unit,
            validated,
            elapsed_secs,
            "kindb: refused after validating {validated} {unit} in {elapsed_secs}s"
        );
    }
}

/// The exact state a first-parent replay carries between changes.
///
/// Entity revision timelines and tombstones are deliberately absent. Whole-graph
/// replay maintains both, but neither is ever read to decide a refusal, so
/// carrying them would add cost and an inverse problem without narrowing what
/// this gate accepts.
#[derive(Default)]
struct ReplayState {
    entities: HashMap<EntityId, Entity>,
    relations: HashMap<RelationId, Relation>,
    external_references: HashMap<ExternalReferenceId, ExternalReference>,
    tree: ResolvedTree,
    /// Relations naming each entity, so a removal checks its own referents
    /// instead of rescanning every relation in the graph.
    entity_referents: HashMap<EntityId, BTreeSet<RelationId>>,
    reference_referents: HashMap<ExternalReferenceId, BTreeSet<RelationId>>,
}

impl ReplayState {
    fn is_empty(&self) -> bool {
        self.entities.is_empty()
            && self.relations.is_empty()
            && self.external_references.is_empty()
            && self.tree.is_empty()
            && self.entity_referents.is_empty()
            && self.reference_referents.is_empty()
    }

    fn index_relation(&mut self, relation: &Relation) {
        for node in [relation.src, relation.dst] {
            match node {
                GraphNodeId::Entity(entity_id) => {
                    self.entity_referents
                        .entry(entity_id)
                        .or_default()
                        .insert(relation.id);
                }
                GraphNodeId::ExternalReference(reference_id) => {
                    self.reference_referents
                        .entry(reference_id)
                        .or_default()
                        .insert(relation.id);
                }
                GraphNodeId::Artifact(_)
                | GraphNodeId::Test(_)
                | GraphNodeId::Contract(_)
                | GraphNodeId::Work(_)
                | GraphNodeId::VerificationRun(_) => {}
            }
        }
    }

    fn unindex_relation(&mut self, relation: &Relation) {
        for node in [relation.src, relation.dst] {
            match node {
                GraphNodeId::Entity(entity_id) => {
                    if let Some(referents) = self.entity_referents.get_mut(&entity_id) {
                        referents.remove(&relation.id);
                        if referents.is_empty() {
                            self.entity_referents.remove(&entity_id);
                        }
                    }
                }
                GraphNodeId::ExternalReference(reference_id) => {
                    if let Some(referents) = self.reference_referents.get_mut(&reference_id) {
                        referents.remove(&relation.id);
                        if referents.is_empty() {
                            self.reference_referents.remove(&reference_id);
                        }
                    }
                }
                GraphNodeId::Artifact(_)
                | GraphNodeId::Test(_)
                | GraphNodeId::Contract(_)
                | GraphNodeId::Work(_)
                | GraphNodeId::VerificationRun(_) => {}
            }
        }
    }

    fn insert_relation(&mut self, relation: Relation) {
        if let Some(previous) = self.relations.insert(relation.id, relation.clone()) {
            self.unindex_relation(&previous);
        }
        self.index_relation(&relation);
    }

    fn remove_relation(&mut self, relation_id: RelationId) {
        if let Some(previous) = self.relations.remove(&relation_id) {
            self.unindex_relation(&previous);
        }
    }
}

/// Whether a change is being applied onto its first parent's state or unwound
/// back to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Forward,
    Rewind,
}

/// Prove that every change reachable from `targets` along first-parent lineage
/// replays exactly, in one pass over that forest.
///
/// `targets` are the changes whose lineage must be proven. Their first-parent
/// ancestors are proven with them, because a target's own transition is only
/// meaningful against the state its lineage published.
pub(crate) fn validate_first_parent_history(
    changes: &HashMap<SemanticChangeId, SemanticChange>,
    targets: &[SemanticChangeId],
) -> Result<(), KinDbError> {
    let lineage = collect_first_parent_lineage(changes, targets)?;
    let mut children: BTreeMap<SemanticChangeId, BTreeSet<SemanticChangeId>> = BTreeMap::new();
    let mut roots = BTreeSet::new();
    for change_id in &lineage {
        let change = lineage_change(changes, change_id)?;
        match change.parents.first() {
            // Every first parent of a lineage member is itself a lineage
            // member, so this edge always stays inside the walked forest.
            Some(first_parent) => {
                children
                    .entry(*first_parent)
                    .or_default()
                    .insert(*change_id);
            }
            None => {
                roots.insert(*change_id);
            }
        }
    }

    let mut progress = ReplayProgress::new("history_replay", "changes", lineage.len());
    match walk_first_parent_forest(changes, &lineage, &children, &roots, &mut progress) {
        Ok(()) => {
            progress.finish();
            Ok(())
        }
        Err(error) => {
            progress.abandon();
            Err(error)
        }
    }
}

/// Enter and unwind every lineage member exactly once, carrying one state.
fn walk_first_parent_forest(
    changes: &HashMap<SemanticChangeId, SemanticChange>,
    lineage: &BTreeSet<SemanticChangeId>,
    children: &BTreeMap<SemanticChangeId, BTreeSet<SemanticChangeId>>,
    roots: &BTreeSet<SemanticChangeId>,
    progress: &mut ReplayProgress,
) -> Result<(), KinDbError> {
    let mut frames = Vec::with_capacity(lineage.len().saturating_mul(2));
    for root in roots.iter().rev() {
        frames.push(Frame::Enter(*root));
    }
    let mut visited = HashSet::with_capacity(lineage.len());
    let mut state = ReplayState::default();
    while let Some(frame) = frames.pop() {
        match frame {
            Frame::Enter(change_id) => {
                if !visited.insert(change_id) {
                    return Err(ModelError::Conflict(format!(
                        "cycle in first-parent history at change {change_id}"
                    ))
                    .into());
                }
                let change = lineage_change(changes, &change_id)?;
                apply_change(&mut state, change, Step::Forward)?;
                progress.record();
                frames.push(Frame::Exit(change_id));
                if let Some(next) = children.get(&change_id) {
                    for child in next.iter().rev() {
                        frames.push(Frame::Enter(*child));
                    }
                }
            }
            Frame::Exit(change_id) => {
                let change = lineage_change(changes, &change_id)?;
                apply_change(&mut state, change, Step::Rewind)?;
            }
        }
    }

    if visited.len() != lineage.len() {
        let change_id = lineage
            .iter()
            .find(|change_id| !visited.contains(change_id))
            .expect("an unvisited lineage member exists when the counts differ");
        return Err(ModelError::Conflict(format!(
            "cycle in first-parent history at change {change_id}"
        ))
        .into());
    }
    if !state.is_empty() {
        return Err(storage(
            "first-parent history replay did not restore the empty root state".to_string(),
        ));
    }
    Ok(())
}

enum Frame {
    Enter(SemanticChangeId),
    Exit(SemanticChangeId),
}

/// Every change reachable from `targets` by following first parents.
///
/// The upward walk stops at the first already-collected change, so a shared
/// trunk is walked once no matter how many targets name it. That is what keeps
/// collection linear in the lineage rather than in targets times history.
fn collect_first_parent_lineage<S: LineageSource + ?Sized>(
    changes: &S,
    targets: &[SemanticChangeId],
) -> Result<BTreeSet<SemanticChangeId>, KinDbError> {
    // Ordered, so the change a cycle refusal names is the same on every run.
    let mut lineage = BTreeSet::new();
    for target in targets {
        let mut current = Some(*target);
        while let Some(change_id) = current {
            if !lineage.insert(change_id) {
                break;
            }
            let change = lineage_change(changes, &change_id)?;
            current = change.parents.first().copied();
        }
    }
    Ok(lineage)
}

fn lineage_change<'a, S: LineageSource + ?Sized>(
    changes: &'a S,
    change_id: &SemanticChangeId,
) -> Result<&'a SemanticChange, KinDbError> {
    changes
        .lineage_change(change_id)
        .ok_or_else(|| ModelError::ChangeNotFound(change_id.to_string()).into())
}

/// A read-only change lookup for first-parent traversal.
///
/// The persisted snapshot and the live graph hold their change maps in
/// different hash-map types, and both are walked by the same passes here.
/// Naming the one operation a traversal performs keeps a single walk
/// serving both instead of forcing either side to copy its map.
pub(crate) trait LineageSource {
    fn lineage_change(&self, change_id: &SemanticChangeId) -> Option<&SemanticChange>;
}

impl LineageSource for HashMap<SemanticChangeId, SemanticChange> {
    fn lineage_change(&self, change_id: &SemanticChangeId) -> Option<&SemanticChange> {
        self.get(change_id)
    }
}

impl LineageSource for hashbrown::HashMap<SemanticChangeId, SemanticChange> {
    fn lineage_change(&self, change_id: &SemanticChangeId) -> Option<&SemanticChange> {
        self.get(change_id)
    }
}

impl LineageSource for crate::storage::change_map::ChangeMap {
    fn lineage_change(&self, change_id: &SemanticChangeId) -> Option<&SemanticChange> {
        self.get(change_id)
    }
}

/// Resolve the exact repository tree at every target in one first-parent pass.
///
/// `ChangeStore::resolve_tree_at` resolves one head by collecting that head's
/// whole first-parent lineage into an owned vector, cloning every ancestor
/// change with all of its deltas, and folding the tree deltas over it. Asking
/// it for `M` heads over a history of depth `D` therefore costs `M * D` change
/// clones and `M * D` tree applications, and a caller that resolves a change
/// and its parent pays that twice for the same lineage.
///
/// This walks the union of those lineages once, exactly as
/// `validate_first_parent_history` walks the same forest for the replay proof,
/// carrying one `ResolvedTree` forward and restoring it at the branch points
/// where the forest divides. It reads each change through a borrow rather than
/// cloning it, and it clones a tree only at the changes the caller asked for.
///
/// Exactness, which is what makes this substitutable rather than an
/// approximation: `resolve_tree_at(head)` folds `ResolvedTree::default()`
/// through the tree deltas of `head`'s first-parent lineage in root-to-head
/// order, and a change's lineage is its first parent's lineage followed by the
/// change itself. Entering a node here applies exactly that node's deltas to
/// exactly its first parent's state, so the state at a node is the same fold
/// over the same sequence. Every refusal is raised at the same node, with the
/// same message, as the per-target resolution: a missing lineage member is
/// `ChangeNotFound`, a first-parent cycle is the same `Conflict` text the
/// replay walk uses, and a delta that does not apply is the same
/// `invalid repository tree transition in change ...` the model raises.
pub(crate) fn resolve_first_parent_trees<S: LineageSource + ?Sized>(
    changes: &S,
    targets: &[SemanticChangeId],
) -> Result<BTreeMap<SemanticChangeId, ResolvedTree>, KinDbError> {
    let wanted: BTreeSet<SemanticChangeId> = targets.iter().copied().collect();
    let lineage = collect_first_parent_lineage(changes, targets)?;
    let mut children: BTreeMap<SemanticChangeId, BTreeSet<SemanticChangeId>> = BTreeMap::new();
    let mut roots = BTreeSet::new();
    for change_id in &lineage {
        let change = lineage_change(changes, change_id)?;
        match change.parents.first() {
            // Every first parent of a lineage member is itself a lineage
            // member, so this edge always stays inside the walked forest.
            Some(first_parent) => {
                children
                    .entry(*first_parent)
                    .or_default()
                    .insert(*change_id);
            }
            None => {
                roots.insert(*change_id);
            }
        }
    }

    let mut frames: Vec<TreeFrame> = Vec::with_capacity(lineage.len().saturating_add(roots.len()));
    for root in roots.iter().rev() {
        // Each root begins from the empty tree, exactly as a per-target
        // resolution of anything in that root's subtree would.
        frames.push(TreeFrame::Enter(*root));
        frames.push(TreeFrame::Restore(ResolvedTree::default()));
    }
    let mut visited = HashSet::with_capacity(lineage.len());
    let mut trees = BTreeMap::new();
    let mut state = ResolvedTree::default();
    while let Some(frame) = frames.pop() {
        match frame {
            TreeFrame::Restore(tree) => state = tree,
            TreeFrame::Enter(change_id) => {
                if !visited.insert(change_id) {
                    return Err(ModelError::Conflict(format!(
                        "cycle in first-parent history at change {change_id}"
                    ))
                    .into());
                }
                let change = lineage_change(changes, &change_id)?;
                state = state.apply(&change.tree_deltas).map_err(|error| {
                    ModelError::Conflict(format!(
                        "invalid repository tree transition in change {}: {error}",
                        change.id
                    ))
                })?;
                if wanted.contains(&change_id) {
                    trees.insert(change_id, state.clone());
                }
                let Some(next) = children.get(&change_id) else {
                    continue;
                };
                // The first child popped inherits this node's state directly;
                // every later sibling needs it put back, so the branch point is
                // the only place a tree is copied for the walk itself.
                for (position, child) in next.iter().enumerate().rev() {
                    frames.push(TreeFrame::Enter(*child));
                    if position > 0 {
                        frames.push(TreeFrame::Restore(state.clone()));
                    }
                }
            }
        }
    }

    if visited.len() != lineage.len() {
        let change_id = lineage
            .iter()
            .find(|change_id| !visited.contains(change_id))
            .expect("an unvisited lineage member exists when the counts differ");
        return Err(ModelError::Conflict(format!(
            "cycle in first-parent history at change {change_id}"
        ))
        .into());
    }
    // A target the walk never reached would silently hand the caller no tree
    // where the per-target resolution would have raised, so say so instead.
    if let Some(missing) = wanted
        .iter()
        .find(|change_id| !trees.contains_key(change_id))
    {
        return Err(storage(format!(
            "first-parent tree resolution reached no state for change {missing}"
        )));
    }

    #[cfg(test)]
    record_lineage_steps(visited.len());

    Ok(trees)
}

/// Whether to enter a lineage member or put a branch point's state back.
enum TreeFrame {
    Enter(SemanticChangeId),
    Restore(ResolvedTree),
}

// Lineage members entered by every tree resolution on this thread, so a test
// can assert the cost SHAPE of one whole verification rather than its seconds.
// That shape is the whole point of the pass: resolving each target on its own
// enters that target's entire lineage, so targets times depth, where one pass
// over the union enters each member once. Production reads nothing from here;
// the counter exists only under `cfg(test)`.
#[cfg(test)]
thread_local! {
    pub(crate) static LINEAGE_STEPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn record_lineage_steps(steps: usize) {
    LINEAGE_STEPS.with(|counter| counter.set(counter.get().saturating_add(steps)));
}

/// Zero the lineage-step counter and report what it held.
#[cfg(test)]
pub(crate) fn take_lineage_steps() -> usize {
    LINEAGE_STEPS.with(|counter| counter.replace(0))
}

/// Apply or unwind one change's complete transition.
///
/// Forward order is entities, external references, relations, then the
/// repository tree. Rewind is the exact reverse.
///
/// Reverse order is not load-bearing today, and the reason is worth stating so
/// nobody reasons from the wrong premise. Within-order would only matter if one
/// change carried two deltas for one identity, and the model forbids exactly
/// that: change identity refuses a second delta for the same entity, relation,
/// external reference, or artifact, so no validly constructed change can reach
/// this function with a double touch. `a_change_cannot_touch_one_identity_twice`
/// pins that. Rewinding in reverse anyway keeps the unwind a strict mirror of the
/// forward application, so it stays correct if that rule is ever relaxed rather
/// than depending on it.
fn apply_change(
    state: &mut ReplayState,
    change: &SemanticChange,
    step: Step,
) -> Result<(), KinDbError> {
    let result = match step {
        Step::Forward => apply_forward(state, change),
        Step::Rewind => apply_rewind(state, change),
    };
    match step {
        Step::Forward => result,
        // A rewind failure is never a defect in the history being validated:
        // every inverse is determined by a transition this pass already
        // accepted. It means forward and inverse application disagreed, so the
        // gate fails loudly rather than reporting it as an invalid repository.
        Step::Rewind => result.map_err(|error| {
            storage(format!(
                "failed to rewind validated history replay at change {}: {error}",
                change.id
            ))
        }),
    }
}

fn apply_forward(state: &mut ReplayState, change: &SemanticChange) -> Result<(), KinDbError> {
    for delta in &change.entity_deltas {
        apply_entity_delta(state, change.id, delta)?;
    }
    for delta in &change.external_reference_deltas {
        apply_external_reference_delta(state, change.id, delta)?;
    }
    for delta in &change.relation_deltas {
        apply_relation_delta(state, change.id, delta)?;
    }
    apply_tree_deltas(state, change.id, &change.tree_deltas)?;
    validate_no_dangling_endpoints(state, change)
}

fn apply_rewind(state: &mut ReplayState, change: &SemanticChange) -> Result<(), KinDbError> {
    let inverse_tree: Vec<TreeDelta> = change
        .tree_deltas
        .iter()
        .rev()
        .map(TreeDelta::inverse)
        .collect();
    apply_tree_deltas(state, change.id, &inverse_tree)?;
    for delta in change.relation_deltas.iter().rev() {
        apply_relation_delta(state, change.id, &delta.inverse())?;
    }
    for delta in change.external_reference_deltas.iter().rev() {
        apply_external_reference_delta(state, change.id, &delta.inverse())?;
    }
    for delta in change.entity_deltas.iter().rev() {
        apply_entity_delta(state, change.id, &delta.inverse())?;
    }
    // The state being restored was proven when this change was entered, so
    // rescanning its endpoints would only re-derive an accepted conclusion.
    Ok(())
}

fn apply_entity_delta(
    state: &mut ReplayState,
    change_id: SemanticChangeId,
    delta: &EntityDelta,
) -> Result<(), KinDbError> {
    match delta {
        EntityDelta::Added { new } => {
            if state.entities.contains_key(&new.id) {
                return Err(ModelError::Conflict(format!(
                    "change {change_id} adds existing entity {}",
                    new.id
                ))
                .into());
            }
            state.entities.insert(new.id, new.clone());
        }
        EntityDelta::Modified { old, new } => {
            if old.id != new.id {
                return Err(ModelError::Conflict(format!(
                    "change {change_id} modifies entity {} into different identity {}",
                    old.id, new.id
                ))
                .into());
            }
            if state.entities.get(&old.id) != Some(old) {
                return Err(ModelError::Conflict(format!(
                    "change {change_id} has stale old payload for entity {}",
                    old.id
                ))
                .into());
            }
            state.entities.insert(new.id, new.clone());
        }
        EntityDelta::Removed { old } => {
            if state.entities.get(&old.id) != Some(old) {
                return Err(ModelError::Conflict(format!(
                    "change {change_id} has stale old payload for removed entity {}",
                    old.id
                ))
                .into());
            }
            state.entities.remove(&old.id);
        }
    }
    Ok(())
}

fn apply_external_reference_delta(
    state: &mut ReplayState,
    change_id: SemanticChangeId,
    delta: &ExternalReferenceDelta,
) -> Result<(), KinDbError> {
    match delta {
        ExternalReferenceDelta::Added { new } => {
            new.validate()?;
            if state.external_references.contains_key(&new.id) {
                return Err(ModelError::Conflict(format!(
                    "change {change_id} adds existing external reference {}",
                    new.id
                ))
                .into());
            }
            state.external_references.insert(new.id, new.clone());
        }
        ExternalReferenceDelta::Removed { old } => {
            old.validate()?;
            if state.external_references.get(&old.id) != Some(old) {
                return Err(ModelError::Conflict(format!(
                    "change {change_id} has stale old payload for removed external reference {}",
                    old.id
                ))
                .into());
            }
            state.external_references.remove(&old.id);
        }
    }
    Ok(())
}

fn apply_relation_delta(
    state: &mut ReplayState,
    change_id: SemanticChangeId,
    delta: &RelationDelta,
) -> Result<(), KinDbError> {
    match delta {
        RelationDelta::Added { new } => {
            if state.relations.contains_key(&new.id) {
                return Err(ModelError::Conflict(format!(
                    "change {change_id} adds existing relation {}",
                    new.id
                ))
                .into());
            }
            state.insert_relation(new.clone());
        }
        RelationDelta::Modified { old, new } => {
            if old.id != new.id {
                return Err(ModelError::Conflict(format!(
                    "change {change_id} modifies relation {} into different identity {}",
                    old.id, new.id
                ))
                .into());
            }
            if state.relations.get(&old.id) != Some(old) {
                return Err(ModelError::Conflict(format!(
                    "change {change_id} has stale old payload for relation {}",
                    old.id
                ))
                .into());
            }
            state.insert_relation(new.clone());
        }
        RelationDelta::Removed { old } => {
            if state.relations.get(&old.id) != Some(old) {
                return Err(ModelError::Conflict(format!(
                    "change {change_id} has stale old payload for removed relation {}",
                    old.id
                ))
                .into());
            }
            state.remove_relation(old.id);
        }
    }
    Ok(())
}

fn apply_tree_deltas(
    state: &mut ReplayState,
    change_id: SemanticChangeId,
    deltas: &[TreeDelta],
) -> Result<(), KinDbError> {
    // `ResolvedTree::apply` full-clones both of its indexes unconditionally, so
    // calling it for a change that touches no artifact costs two whole-tree
    // clones to produce the tree it was already holding. Most changes in a real
    // history touch no artifact at all, and this pass applies deltas in both
    // directions, so skipping the empty case removes the dominant per-change
    // allocation without changing the result: applying no deltas validates
    // nothing and returns an equal tree.
    if deltas.is_empty() {
        return Ok(());
    }
    state.tree = state.tree.apply(deltas).map_err(|error| {
        ModelError::Conflict(format!(
            "invalid repository tree transition in change {change_id}: {error}"
        ))
    })?;
    Ok(())
}

/// Refuse a change that leaves a relation pointing at a node it dropped.
///
/// Whole-graph replay rescans every relation after every change. Given the
/// invariant held before this change, only the relations it asserted and the
/// endpoint nodes it dropped can have broken it, so those are the only ones
/// examined here.
fn validate_no_dangling_endpoints(
    state: &ReplayState,
    change: &SemanticChange,
) -> Result<(), KinDbError> {
    for delta in &change.relation_deltas {
        let Some(relation) = state.relations.get(&delta.target_id()) else {
            continue;
        };
        for node in [relation.src, relation.dst] {
            match node {
                GraphNodeId::Entity(entity_id) => {
                    if !state.entities.contains_key(&entity_id) {
                        return Err(dangling_entity(change.id, relation.id, entity_id));
                    }
                }
                GraphNodeId::ExternalReference(reference_id) => {
                    if !state.external_references.contains_key(&reference_id) {
                        return Err(dangling_reference(change.id, relation.id, reference_id));
                    }
                }
                GraphNodeId::Artifact(_)
                | GraphNodeId::Test(_)
                | GraphNodeId::Contract(_)
                | GraphNodeId::Work(_)
                | GraphNodeId::VerificationRun(_) => {}
            }
        }
    }

    for delta in &change.entity_deltas {
        let entity_id = delta.target_id();
        if state.entities.contains_key(&entity_id) {
            continue;
        }
        if let Some(relation_id) = state
            .entity_referents
            .get(&entity_id)
            .and_then(|referents| referents.iter().next())
        {
            return Err(dangling_entity(change.id, *relation_id, entity_id));
        }
    }

    for delta in &change.external_reference_deltas {
        let reference_id = delta.target_id();
        if state.external_references.contains_key(&reference_id) {
            continue;
        }
        if let Some(relation_id) = state
            .reference_referents
            .get(&reference_id)
            .and_then(|referents| referents.iter().next())
        {
            return Err(dangling_reference(change.id, *relation_id, reference_id));
        }
    }

    Ok(())
}

fn dangling_entity(
    change_id: SemanticChangeId,
    relation_id: RelationId,
    entity_id: EntityId,
) -> KinDbError {
    ModelError::Conflict(format!(
        "change {change_id} leaves relation {relation_id} dangling from entity {entity_id}; \
         relation removal must be explicit"
    ))
    .into()
}

fn dangling_reference(
    change_id: SemanticChangeId,
    relation_id: RelationId,
    reference_id: ExternalReferenceId,
) -> KinDbError {
    ModelError::Conflict(format!(
        "change {change_id} leaves relation {relation_id} dangling from external reference \
         {reference_id}; relation removal must be explicit"
    ))
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    use kin_model::{
        compute_semantic_change_id, AuthorId, ChangeOrigin, ChangeStore, EntityKind,
        EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm, Hash256, LanguageId,
        LocatedEntry, RelationKind, RelationOrigin, RepoPath, SemanticFingerprint, Timestamp,
        TreeEntry, Visibility,
    };
    use kin_model::{ArtifactId, EntityRevision};
    use uuid::Uuid;

    /// The exact per-change replay this module replaced, over the same fixture.
    ///
    /// Reading changes straight out of the fixture map isolates the comparison
    /// to the replay itself: an `InMemoryGraph` would additionally revalidate
    /// storage admission and derive revision timelines, so a fixture refused
    /// there would never reach the behavior under test.
    struct LegacyReplayStore {
        changes: HashMap<SemanticChangeId, SemanticChange>,
    }

    impl ChangeStore for LegacyReplayStore {
        type Error = KinDbError;

        fn get_change(&self, id: &SemanticChangeId) -> Result<Option<SemanticChange>, Self::Error> {
            Ok(self.changes.get(id).cloned())
        }

        fn get_entity_history(&self, _id: &EntityId) -> Result<Vec<SemanticChange>, Self::Error> {
            unimplemented!("the replay under test never reads entity history")
        }

        fn get_entity_revisions(&self, _id: &EntityId) -> Result<Vec<EntityRevision>, Self::Error> {
            unimplemented!("the replay under test never reads entity revisions")
        }

        fn find_merge_bases(
            &self,
            _a: &SemanticChangeId,
            _b: &SemanticChangeId,
        ) -> Result<Vec<SemanticChangeId>, Self::Error> {
            unimplemented!("the replay under test never reads merge bases")
        }

        fn create_change(&self, _change: &SemanticChange) -> Result<(), Self::Error> {
            unimplemented!("the replay under test never writes")
        }

        fn get_changes_since(
            &self,
            _base: &SemanticChangeId,
            _head: &SemanticChangeId,
        ) -> Result<Vec<SemanticChange>, Self::Error> {
            unimplemented!("the replay under test never reads change ranges")
        }
    }

    fn legacy_outcome(
        changes: &HashMap<SemanticChangeId, SemanticChange>,
        targets: &[SemanticChangeId],
    ) -> Result<(), String> {
        let store = LegacyReplayStore {
            changes: changes.clone(),
        };
        for target in targets {
            store
                .build_change_order_at(target)
                .map_err(|error| error.to_string())?;
            store
                .resolve_graph_at(target)
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn incremental_outcome(
        changes: &HashMap<SemanticChangeId, SemanticChange>,
        targets: &[SemanticChangeId],
    ) -> Result<(), String> {
        validate_first_parent_history(changes, targets).map_err(|error| error.to_string())
    }

    /// Assert both replays reach the same verdict, with the same words.
    ///
    /// Message equality is asserted, not just the accept/refuse split, because
    /// an operator reading a refusal must not be able to tell which
    /// implementation produced it.
    ///
    /// It holds only for **single-violation** histories, which is why every
    /// fixture here carries exactly one, and it is not a general property of the
    /// two paths. Two known divergence classes, both on already-refused input:
    /// the per-change replay resolves every change's graph deltas before any
    /// change's tree deltas while this pass interleaves per change, so a history
    /// with both a tree fault and a graph fault can report either first; and a
    /// history with two dangling relations names whichever the underlying
    /// collection yields, a `HashMap` order for the per-change scan against the
    /// minimum `RelationId` here. Verdict equality is the property the version
    /// gate depends on, and that holds unconditionally.
    fn assert_replays_agree(
        label: &str,
        changes: &HashMap<SemanticChangeId, SemanticChange>,
        targets: &[SemanticChangeId],
    ) -> Result<(), String> {
        let legacy = legacy_outcome(changes, targets);
        let incremental = incremental_outcome(changes, targets);
        assert_eq!(
            legacy, incremental,
            "{label}: per-change replay and incremental replay disagree"
        );
        incremental
    }

    fn assert_agreed_refusal(
        label: &str,
        changes: &HashMap<SemanticChangeId, SemanticChange>,
        targets: &[SemanticChangeId],
        expected: &str,
    ) {
        let error = assert_replays_agree(label, changes, targets)
            .expect_err("an invalid history must be refused");
        assert!(
            error.contains(expected),
            "{label}: expected a refusal naming {expected:?}, got {error:?}"
        );
    }

    fn entity(name: &str, fingerprint_byte: u8) -> Entity {
        let path = format!("src/{name}.rs");
        Entity {
            id: EntityId::from_content(&path, name, "function", 1),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([fingerprint_byte; 32]),
                signature_hash: Hash256::from_bytes([fingerprint_byte.wrapping_add(1); 32]),
                behavior_hash: Hash256::from_bytes([fingerprint_byte.wrapping_add(2); 32]),
                equivalence_hash: Hash256::from_bytes([fingerprint_byte.wrapping_add(3); 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(&path)),
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

    fn revise(base: &Entity, fingerprint_byte: u8) -> Entity {
        let mut revised = base.clone();
        revised.signature = format!("fn {}(value: i{fingerprint_byte})", base.name);
        revised.fingerprint.signature_hash = Hash256::from_bytes([fingerprint_byte; 32]);
        revised
    }

    fn relation(src: GraphNodeId, dst: GraphNodeId, tag: &str) -> Relation {
        Relation {
            id: RelationId::from_content(&format!("{src:?}"), &format!("{dst:?}"), tag),
            kind: RelationKind::Calls,
            src,
            dst,
            confidence: 1.0,
            origin: RelationOrigin::Lsp,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    fn blob(path: &str, artifact: u128, byte: u8) -> (ArtifactId, LocatedEntry) {
        let repo_path = RepoPath::from_utf8(path).unwrap();
        (
            ArtifactId(Uuid::from_u128(artifact)),
            LocatedEntry::new(
                repo_path,
                TreeEntry::blob(Hash256::from_bytes([byte; 32]), false),
            ),
        )
    }

    /// One change with the given lineage and deltas, carrying its real identity.
    #[derive(Default)]
    struct ChangeSpec {
        parents: Vec<SemanticChangeId>,
        entity_deltas: Vec<EntityDelta>,
        relation_deltas: Vec<RelationDelta>,
        external_reference_deltas: Vec<ExternalReferenceDelta>,
        tree_deltas: Vec<TreeDelta>,
    }

    fn change(message: &str, spec: ChangeSpec) -> SemanticChange {
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: spec.parents,
            timestamp: Timestamp(
                chrono::DateTime::parse_from_rfc3339("2026-07-29T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            author: AuthorId::new("history-replay-test"),
            message: message.to_string(),
            entity_deltas: spec.entity_deltas,
            relation_deltas: spec.relation_deltas,
            tree_deltas: spec.tree_deltas,
            admission_policy_delta: None,
            external_reference_deltas: spec.external_reference_deltas,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        change.id = compute_semantic_change_id(&change).unwrap();
        change
    }

    fn history(
        changes: Vec<SemanticChange>,
    ) -> (
        HashMap<SemanticChangeId, SemanticChange>,
        Vec<SemanticChangeId>,
    ) {
        let mut targets: Vec<_> = changes.iter().map(|change| change.id).collect();
        targets.sort_unstable();
        targets.dedup();
        let map = changes
            .into_iter()
            .map(|change| (change.id, change))
            .collect();
        (map, targets)
    }

    /// The periodic emit is gated on a five-second interval, so a fixture that
    /// finishes in milliseconds crosses the count threshold and still never
    /// reaches the emit. Drive the reporter directly with a zero interval so the
    /// branch actually executes, and hold the threshold behavior with it.
    #[test]
    fn progress_reports_periodically_once_past_the_threshold() {
        let mut reporting =
            ReplayProgress::with_interval("test", "changes", PROGRESS_MIN_TOTAL, Duration::ZERO);
        for _ in 0..PROGRESS_CLOCK_STRIDE * 2 {
            reporting.record();
        }
        assert_eq!(
            reporting.reports(),
            2,
            "one report per stride is expected once the interval never blocks"
        );
        reporting.finish();

        let mut below = ReplayProgress::with_interval(
            "test",
            "changes",
            PROGRESS_MIN_TOTAL - 1,
            Duration::ZERO,
        );
        for _ in 0..PROGRESS_CLOCK_STRIDE * 2 {
            below.record();
        }
        assert_eq!(
            below.reports(),
            0,
            "a small replay must stay silent no matter how fast the interval elapses"
        );
        below.abandon();
    }

    /// A branching, merging history exercising every carried state at once.
    #[test]
    fn incremental_and_per_change_replay_agree_on_a_branching_history() {
        let alpha = entity("alpha", 0x11);
        let beta = entity("beta", 0x21);
        let alpha_revised = revise(&alpha, 0x31);
        let reference =
            ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        let internal = relation(
            GraphNodeId::Entity(alpha.id),
            GraphNodeId::Entity(beta.id),
            "calls",
        );
        let external = relation(
            GraphNodeId::Entity(beta.id),
            GraphNodeId::ExternalReference(reference.id),
            "imports",
        );
        let (root_artifact, root_entry) = blob("src/root.rs", 0xa1, 0x41);
        let (leaf_artifact, leaf_entry) = blob("src/leaf.rs", 0xa2, 0x51);

        let genesis = change(
            "seed both entities and a tree",
            ChangeSpec {
                entity_deltas: vec![
                    EntityDelta::Added { new: alpha.clone() },
                    EntityDelta::Added { new: beta.clone() },
                ],
                relation_deltas: vec![RelationDelta::Added {
                    new: internal.clone(),
                }],
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: root_artifact,
                    new: root_entry.clone(),
                }],
                ..ChangeSpec::default()
            },
        );
        let trunk = change(
            "revise alpha and take an external dependency",
            ChangeSpec {
                parents: vec![genesis.id],
                entity_deltas: vec![EntityDelta::Modified {
                    old: alpha.clone(),
                    new: alpha_revised.clone(),
                }],
                relation_deltas: vec![RelationDelta::Added {
                    new: external.clone(),
                }],
                external_reference_deltas: vec![ExternalReferenceDelta::Added {
                    new: reference.clone(),
                }],
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: leaf_artifact,
                    new: leaf_entry.clone(),
                }],
            },
        );
        // A sibling of `trunk` off the same parent. Its state must not carry any
        // of `trunk`'s deltas, which only holds if the rewind is exact.
        let sibling = change(
            "remove beta on a divergent branch",
            ChangeSpec {
                parents: vec![genesis.id],
                entity_deltas: vec![EntityDelta::Removed { old: beta.clone() }],
                relation_deltas: vec![RelationDelta::Removed {
                    old: internal.clone(),
                }],
                ..ChangeSpec::default()
            },
        );
        // A merge is material against its first parent only; `sibling` stays
        // ancestry, so beta is still present here.
        let merge = change(
            "merge the divergent branch",
            ChangeSpec {
                parents: vec![trunk.id, sibling.id],
                entity_deltas: vec![EntityDelta::Modified {
                    old: alpha_revised.clone(),
                    new: revise(&alpha, 0x61),
                }],
                tree_deltas: vec![TreeDelta::Removed {
                    artifact_id: leaf_artifact,
                    old: leaf_entry,
                }],
                ..ChangeSpec::default()
            },
        );

        let (changes, targets) = history(vec![genesis, trunk, sibling, merge]);
        assert_replays_agree("branching history", &changes, &targets)
            .expect("a coherent branching history must replay");
    }

    /// The rewind's within-change ordering can never be exercised, because the
    /// model refuses a change that carries two deltas for one identity.
    ///
    /// This is the fixture an earlier pass tried to write as a differential case
    /// and could not: change identity itself rejects the shape. Pinning the
    /// refusal here is what makes the ordering argument in `apply_change` checkable
    /// rather than asserted, and it fails loudly if the rule is ever relaxed, at
    /// which point that ordering stops being merely defensive.
    #[test]
    fn a_change_cannot_touch_one_identity_twice() {
        let first = entity("twice", 0x11);
        let revised = revise(&first, 0x12);
        let mut double = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: Vec::new(),
            timestamp: Timestamp(
                chrono::DateTime::parse_from_rfc3339("2026-07-29T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            author: AuthorId::new("history-replay-test"),
            message: "revise then drop the same identity".to_string(),
            entity_deltas: vec![
                EntityDelta::Modified {
                    old: first,
                    new: revised.clone(),
                },
                EntityDelta::Removed { old: revised },
            ],
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };

        let error = compute_semantic_change_id(&double)
            .expect_err("two deltas for one entity must not yield a change identity");
        assert!(
            error.to_string().contains("more than one delta for entity"),
            "unexpected double-touch refusal: {error}"
        );

        let relation_left = entity("relation_left", 0x21);
        let relation_right = entity("relation_right", 0x22);
        let call = relation(
            GraphNodeId::Entity(relation_left.id),
            GraphNodeId::Entity(relation_right.id),
            "calls twice",
        );
        double.entity_deltas = Vec::new();
        double.relation_deltas = vec![
            RelationDelta::Added { new: call.clone() },
            RelationDelta::Removed { old: call },
        ];
        let error = compute_semantic_change_id(&double)
            .expect_err("two deltas for one relation must not yield a change identity");
        assert!(
            error
                .to_string()
                .contains("more than one delta for relation"),
            "unexpected double-touch refusal: {error}"
        );

        let reference =
            ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        double.relation_deltas = Vec::new();
        double.external_reference_deltas = vec![
            ExternalReferenceDelta::Added {
                new: reference.clone(),
            },
            ExternalReferenceDelta::Removed { old: reference },
        ];
        let error = compute_semantic_change_id(&double)
            .expect_err("two deltas for one external reference must not yield a change identity");
        assert!(
            error
                .to_string()
                .contains("more than one delta for external reference"),
            "unexpected double-touch refusal: {error}"
        );

        // The same prohibition holds for the tree, so every delta domain is
        // pinned against reaching replay with a double touch.
        double.external_reference_deltas = Vec::new();
        let (artifact, entry) = blob("src/twice.rs", 0xc1, 0x41);
        double.tree_deltas = vec![
            TreeDelta::Added {
                artifact_id: artifact,
                new: entry.clone(),
            },
            TreeDelta::Removed {
                artifact_id: artifact,
                old: entry,
            },
        ];
        let error = compute_semantic_change_id(&double)
            .expect_err("two deltas for one artifact must not yield a change identity");
        assert!(
            error
                .to_string()
                .contains("more than one delta for artifact"),
            "unexpected double-touch refusal: {error}"
        );
    }

    /// The property a broken rewind breaks first: sibling branches that each
    /// introduce the same identity are both valid, and neither may observe the
    /// other's state.
    #[test]
    fn sibling_branches_never_observe_each_other() {
        let shared = entity("shared", 0x71);
        let genesis = change("empty root", ChangeSpec::default());
        let left = change(
            "add shared on the left branch",
            ChangeSpec {
                parents: vec![genesis.id],
                entity_deltas: vec![EntityDelta::Added {
                    new: shared.clone(),
                }],
                ..ChangeSpec::default()
            },
        );
        let right = change(
            "add the same identity on the right branch",
            ChangeSpec {
                parents: vec![genesis.id],
                entity_deltas: vec![EntityDelta::Added {
                    new: shared.clone(),
                }],
                ..ChangeSpec::default()
            },
        );

        let (changes, targets) = history(vec![genesis, left, right]);
        assert_replays_agree("sibling branches", &changes, &targets)
            .expect("divergent branches may each introduce the same identity");
    }

    #[test]
    fn refuses_adding_an_entity_its_lineage_already_carries() {
        let alpha = entity("alpha", 0x11);
        let genesis = change(
            "add alpha",
            ChangeSpec {
                entity_deltas: vec![EntityDelta::Added { new: alpha.clone() }],
                ..ChangeSpec::default()
            },
        );
        let duplicate = change(
            "add alpha again on the same lineage",
            ChangeSpec {
                parents: vec![genesis.id],
                entity_deltas: vec![EntityDelta::Added { new: alpha.clone() }],
                ..ChangeSpec::default()
            },
        );

        let (changes, targets) = history(vec![genesis, duplicate]);
        assert_agreed_refusal(
            "duplicate entity",
            &changes,
            &targets,
            "adds existing entity",
        );
    }

    #[test]
    fn refuses_an_entity_modification_with_a_stale_old_payload() {
        let alpha = entity("alpha", 0x11);
        let never_published = revise(&alpha, 0x22);
        let genesis = change(
            "add alpha",
            ChangeSpec {
                entity_deltas: vec![EntityDelta::Added { new: alpha }],
                ..ChangeSpec::default()
            },
        );
        let stale = change(
            "revise a payload this lineage never published",
            ChangeSpec {
                parents: vec![genesis.id],
                entity_deltas: vec![EntityDelta::Modified {
                    old: never_published.clone(),
                    new: revise(&never_published, 0x33),
                }],
                ..ChangeSpec::default()
            },
        );

        let (changes, targets) = history(vec![genesis, stale]);
        assert_agreed_refusal(
            "stale entity modification",
            &changes,
            &targets,
            "stale old payload for entity",
        );
    }

    #[test]
    fn refuses_an_entity_removal_with_a_stale_old_payload() {
        let alpha = entity("alpha", 0x11);
        let genesis = change(
            "add alpha",
            ChangeSpec {
                entity_deltas: vec![EntityDelta::Added { new: alpha.clone() }],
                ..ChangeSpec::default()
            },
        );
        let stale = change(
            "remove a payload this lineage never published",
            ChangeSpec {
                parents: vec![genesis.id],
                entity_deltas: vec![EntityDelta::Removed {
                    old: revise(&alpha, 0x44),
                }],
                ..ChangeSpec::default()
            },
        );

        let (changes, targets) = history(vec![genesis, stale]);
        assert_agreed_refusal(
            "stale entity removal",
            &changes,
            &targets,
            "stale old payload for removed entity",
        );
    }

    #[test]
    fn refuses_a_relation_its_lineage_already_carries() {
        let alpha = entity("alpha", 0x11);
        let beta = entity("beta", 0x21);
        let call = relation(
            GraphNodeId::Entity(alpha.id),
            GraphNodeId::Entity(beta.id),
            "calls",
        );
        let genesis = change(
            "add both entities and the call",
            ChangeSpec {
                entity_deltas: vec![
                    EntityDelta::Added { new: alpha },
                    EntityDelta::Added { new: beta },
                ],
                relation_deltas: vec![RelationDelta::Added { new: call.clone() }],
                ..ChangeSpec::default()
            },
        );
        let duplicate = change(
            "add the same relation again",
            ChangeSpec {
                parents: vec![genesis.id],
                relation_deltas: vec![RelationDelta::Added { new: call }],
                ..ChangeSpec::default()
            },
        );

        let (changes, targets) = history(vec![genesis, duplicate]);
        assert_agreed_refusal(
            "duplicate relation",
            &changes,
            &targets,
            "adds existing relation",
        );
    }

    #[test]
    fn refuses_a_relation_removal_with_a_stale_old_payload() {
        let alpha = entity("alpha", 0x11);
        let beta = entity("beta", 0x21);
        let call = relation(
            GraphNodeId::Entity(alpha.id),
            GraphNodeId::Entity(beta.id),
            "calls",
        );
        let mut drifted = call.clone();
        drifted.confidence = 0.5;
        let genesis = change(
            "add both entities and the call",
            ChangeSpec {
                entity_deltas: vec![
                    EntityDelta::Added { new: alpha },
                    EntityDelta::Added { new: beta },
                ],
                relation_deltas: vec![RelationDelta::Added { new: call }],
                ..ChangeSpec::default()
            },
        );
        let stale = change(
            "remove a relation payload this lineage never published",
            ChangeSpec {
                parents: vec![genesis.id],
                relation_deltas: vec![RelationDelta::Removed { old: drifted }],
                ..ChangeSpec::default()
            },
        );

        let (changes, targets) = history(vec![genesis, stale]);
        assert_agreed_refusal(
            "stale relation removal",
            &changes,
            &targets,
            "stale old payload for removed relation",
        );
    }

    /// The dangling scan narrowed to touched endpoints must still catch a
    /// removal that orphans a relation the same change never mentioned.
    #[test]
    fn refuses_an_entity_removal_that_orphans_an_untouched_relation() {
        let alpha = entity("alpha", 0x11);
        let beta = entity("beta", 0x21);
        let call = relation(
            GraphNodeId::Entity(alpha.id),
            GraphNodeId::Entity(beta.id),
            "calls",
        );
        let genesis = change(
            "add both entities and the call",
            ChangeSpec {
                entity_deltas: vec![
                    EntityDelta::Added { new: alpha },
                    EntityDelta::Added { new: beta.clone() },
                ],
                relation_deltas: vec![RelationDelta::Added { new: call }],
                ..ChangeSpec::default()
            },
        );
        let orphaning = change(
            "remove beta while the call still names it",
            ChangeSpec {
                parents: vec![genesis.id],
                entity_deltas: vec![EntityDelta::Removed { old: beta }],
                ..ChangeSpec::default()
            },
        );

        let (changes, targets) = history(vec![genesis, orphaning]);
        assert_agreed_refusal(
            "orphaned relation",
            &changes,
            &targets,
            "dangling from entity",
        );
    }

    #[test]
    fn refuses_a_relation_added_onto_an_absent_entity() {
        let alpha = entity("alpha", 0x11);
        let missing = entity("missing", 0x81);
        let call = relation(
            GraphNodeId::Entity(alpha.id),
            GraphNodeId::Entity(missing.id),
            "calls",
        );
        let genesis = change(
            "add only one endpoint",
            ChangeSpec {
                entity_deltas: vec![EntityDelta::Added { new: alpha }],
                ..ChangeSpec::default()
            },
        );
        let dangling = change(
            "add a relation naming an entity nobody published",
            ChangeSpec {
                parents: vec![genesis.id],
                relation_deltas: vec![RelationDelta::Added { new: call }],
                ..ChangeSpec::default()
            },
        );

        let (changes, targets) = history(vec![genesis, dangling]);
        assert_agreed_refusal(
            "relation onto an absent entity",
            &changes,
            &targets,
            "dangling from entity",
        );
    }

    #[test]
    fn refuses_an_external_reference_removal_that_orphans_a_relation() {
        let alpha = entity("alpha", 0x11);
        let reference =
            ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        let import = relation(
            GraphNodeId::Entity(alpha.id),
            GraphNodeId::ExternalReference(reference.id),
            "imports",
        );
        let genesis = change(
            "add the entity, the reference, and the import",
            ChangeSpec {
                entity_deltas: vec![EntityDelta::Added { new: alpha }],
                relation_deltas: vec![RelationDelta::Added { new: import }],
                external_reference_deltas: vec![ExternalReferenceDelta::Added {
                    new: reference.clone(),
                }],
                ..ChangeSpec::default()
            },
        );
        let orphaning = change(
            "drop the reference while the import still names it",
            ChangeSpec {
                parents: vec![genesis.id],
                external_reference_deltas: vec![ExternalReferenceDelta::Removed { old: reference }],
                ..ChangeSpec::default()
            },
        );

        let (changes, targets) = history(vec![genesis, orphaning]);
        assert_agreed_refusal(
            "orphaned external import",
            &changes,
            &targets,
            "dangling from external reference",
        );
    }

    #[test]
    fn refuses_an_invalid_repository_tree_transition() {
        let (artifact, entry) = blob("src/root.rs", 0xa3, 0x41);
        let (_, wrong_path) = blob("src/other.rs", 0xa4, 0x41);
        let genesis = change(
            "add one file",
            ChangeSpec {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: artifact,
                    new: entry,
                }],
                ..ChangeSpec::default()
            },
        );
        let tampered = change(
            "update the file from a path it never occupied",
            ChangeSpec {
                parents: vec![genesis.id],
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id: artifact,
                    old: wrong_path,
                    new: blob("src/root.rs", 0xa3, 0x99).1,
                }],
                ..ChangeSpec::default()
            },
        );

        let (changes, targets) = history(vec![genesis, tampered]);
        assert_agreed_refusal(
            "tampered tree transition",
            &changes,
            &targets,
            "invalid repository tree transition",
        );
    }

    #[test]
    fn refuses_a_change_whose_first_parent_is_absent() {
        let orphan = change(
            "claim a lineage nobody persisted",
            ChangeSpec {
                parents: vec![SemanticChangeId::from_hash(Hash256::from_bytes([0xaa; 32]))],
                ..ChangeSpec::default()
            },
        );
        let (changes, targets) = history(vec![orphan]);
        assert_replays_agree("absent first parent", &changes, &targets)
            .expect_err("a change whose first parent is not persisted must be refused");
    }

    /// Both replays refuse a first-parent cycle. Which change each names is not
    /// a contract: the per-change walk reports the head it started from, while
    /// one forest pass has no head to start from at all.
    #[test]
    fn refuses_a_first_parent_cycle() {
        let left = SemanticChangeId::from_hash(Hash256::from_bytes([0xb1; 32]));
        let right = SemanticChangeId::from_hash(Hash256::from_bytes([0xb2; 32]));
        let mut changes = HashMap::new();
        for (id, parent) in [(left, right), (right, left)] {
            let mut cyclic = change("cyclic", ChangeSpec::default());
            cyclic.id = id;
            cyclic.parents = vec![parent];
            changes.insert(id, cyclic);
        }
        let targets = vec![left, right];

        let legacy = legacy_outcome(&changes, &targets)
            .expect_err("the per-change replay must refuse a first-parent cycle");
        let incremental = incremental_outcome(&changes, &targets)
            .expect_err("the incremental replay must refuse a first-parent cycle");
        for (label, error) in [("per-change", legacy), ("incremental", incremental)] {
            assert!(
                error.contains("cycle in first-parent history"),
                "{label} replay refused a cycle for the wrong reason: {error}"
            );
        }
    }

    /// Measure the replaced per-change replay against the single pass.
    ///
    /// Ignored by default: it is a shape measurement for the owning lane, not a
    /// gate, and a wall-clock assertion would be flaky under a loaded host.
    /// Numbers from it are local dev-lane observations and are not citable.
    #[test]
    #[ignore = "timing measurement, run explicitly"]
    fn measures_per_change_against_single_pass_replay() {
        /// Above this the per-change replay is too slow to keep the measurement
        /// bounded, which is the finding rather than a limitation of it.
        const PER_CHANGE_CEILING: usize = 1_600;

        for trunk in [200usize, 400, 800, 1_600, 3_200] {
            let (changes, targets) = deep_history(trunk, 40);
            let legacy = (changes.len() <= PER_CHANGE_CEILING).then(|| {
                let started = Instant::now();
                legacy_outcome(&changes, &targets).expect("the fixture is a valid history");
                started.elapsed()
            });

            // Repeated so allocator warmup is not read as replay cost at the
            // sub-millisecond sizes.
            let mut single_pass = Duration::MAX;
            for _ in 0..5 {
                let started = Instant::now();
                validate_first_parent_history(&changes, &targets)
                    .expect("the fixture is a valid history");
                single_pass = single_pass.min(started.elapsed());
            }

            match legacy {
                Some(legacy) => println!(
                    "changes={} per_change={:?} single_pass={:?} speedup={:.1}x",
                    changes.len(),
                    legacy,
                    single_pass,
                    legacy.as_secs_f64() / single_pass.as_secs_f64().max(f64::EPSILON)
                ),
                None => println!(
                    "changes={} per_change=skipped single_pass={:?}",
                    changes.len(),
                    single_pass
                ),
            }
        }
    }

    /// The tree at every target, resolved one target at a time.
    ///
    /// This is exactly what `verify_native_change_admission` did before the
    /// single pass: one `ChangeStore::resolve_tree_at` per change and one per
    /// parent, each walking that head's whole first-parent lineage.
    fn per_target_trees(
        changes: &HashMap<SemanticChangeId, SemanticChange>,
        targets: &[SemanticChangeId],
    ) -> Result<BTreeMap<SemanticChangeId, ResolvedTree>, String> {
        let store = LegacyReplayStore {
            changes: changes.clone(),
        };
        let mut trees = BTreeMap::new();
        for target in targets {
            let tree = store
                .resolve_tree_at(target)
                .map_err(|error| error.to_string())?;
            trees.insert(*target, tree);
        }
        Ok(trees)
    }

    /// A history whose every step moves the tree, forking at one change.
    ///
    /// Adds, updates and removals all appear, so the fold is exercised rather
    /// than a chain of empty transitions, and the fork gives the walk a branch
    /// point where it has to put the parent's state back before entering the
    /// second child.
    fn forking_tree_history() -> (
        HashMap<SemanticChangeId, SemanticChange>,
        Vec<SemanticChangeId>,
    ) {
        let (first, first_entry) = blob("src/first.rs", 0xf01, 0x41);
        let (second, second_entry) = blob("src/second.rs", 0xf02, 0x42);
        let (third, third_entry) = blob("src/third.rs", 0xf03, 0x43);
        let revised_first = LocatedEntry::new(
            first_entry.path.clone(),
            TreeEntry::blob(Hash256::from_bytes([0x44; 32]), false),
        );
        let revised_third = LocatedEntry::new(
            third_entry.path.clone(),
            TreeEntry::blob(Hash256::from_bytes([0x45; 32]), false),
        );

        let root = change(
            "add the first artifact",
            ChangeSpec {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: first,
                    new: first_entry.clone(),
                }],
                ..ChangeSpec::default()
            },
        );
        let fork = change(
            "revise the first artifact",
            ChangeSpec {
                parents: vec![root.id],
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id: first,
                    old: first_entry.clone(),
                    new: revised_first.clone(),
                }],
                ..ChangeSpec::default()
            },
        );
        let left_add = change(
            "add the second artifact",
            ChangeSpec {
                parents: vec![fork.id],
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: second,
                    new: second_entry,
                }],
                ..ChangeSpec::default()
            },
        );
        let left_remove = change(
            "remove the first artifact",
            ChangeSpec {
                parents: vec![left_add.id],
                tree_deltas: vec![TreeDelta::Removed {
                    artifact_id: first,
                    old: revised_first,
                }],
                ..ChangeSpec::default()
            },
        );
        let right_add = change(
            "add the third artifact",
            ChangeSpec {
                parents: vec![fork.id],
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: third,
                    new: third_entry.clone(),
                }],
                ..ChangeSpec::default()
            },
        );
        let right_revise = change(
            "revise the third artifact",
            ChangeSpec {
                parents: vec![right_add.id],
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id: third,
                    old: third_entry,
                    new: revised_third,
                }],
                ..ChangeSpec::default()
            },
        );

        history(vec![
            root,
            fork,
            left_add,
            left_remove,
            right_add,
            right_revise,
        ])
    }

    /// The one pass must return the trees the per-target resolution returns.
    ///
    /// `ResolvedTree` compares by its identity and path indexes together, so
    /// this is state equality rather than a spot check on a few artifacts.
    #[test]
    fn one_pass_tree_resolution_matches_the_per_target_resolution() {
        for (label, (changes, targets)) in [
            ("forking", forking_tree_history()),
            ("deep trunk with tips", deep_history(24, 6)),
        ] {
            let expected = per_target_trees(&changes, &targets)
                .unwrap_or_else(|error| panic!("{label} fixture must resolve per target: {error}"));
            let resolved = resolve_first_parent_trees(&changes, &targets).unwrap_or_else(|error| {
                panic!("{label} fixture must resolve in one pass: {error}")
            });
            assert_eq!(
                resolved, expected,
                "{label}: the single pass resolved a different state than the per-target walk"
            );
            // A fixture whose trees are all empty would satisfy the comparison
            // above without ever exercising the fold.
            assert!(
                expected.values().any(|tree| !tree.is_empty()),
                "{label}: the fixture must carry a non-empty tree somewhere"
            );
        }
    }

    /// The pass walks the lineage once, not once per requested tree.
    ///
    /// This is the cost shape FIR-2569 is about, asserted as a count so it
    /// cannot flake on a loaded box the way seconds do.
    #[test]
    fn one_pass_tree_resolution_walks_the_lineage_once() {
        const TRUNK: usize = 120;
        const TIPS: usize = 8;

        let (changes, targets) = deep_history(TRUNK, TIPS);
        let lineage_members = TRUNK + 1 + TIPS;
        assert_eq!(targets.len(), lineage_members);

        take_lineage_steps();
        resolve_first_parent_trees(&changes, &targets)
            .expect("a deep history with many tips must resolve");
        let single_pass_steps = take_lineage_steps();
        assert_eq!(
            single_pass_steps, lineage_members,
            "one pass must enter each lineage member exactly once"
        );

        // The same trees, asked for one at a time: every trunk change walks its
        // own depth and every tip walks the whole trunk again.
        for target in &targets {
            resolve_first_parent_trees(&changes, std::slice::from_ref(target))
                .expect("each target resolves on its own");
        }
        let per_target_steps = take_lineage_steps();
        let trunk_steps = (lineage_members - TIPS) * (lineage_members - TIPS + 1) / 2;
        let tip_steps = TIPS * (lineage_members - TIPS + 1);
        assert_eq!(
            per_target_steps,
            trunk_steps + tip_steps,
            "the per-target walk must cost every target's own depth"
        );
        assert!(
            per_target_steps > lineage_members * 50,
            "the fixture must separate the two shapes by more than a constant: \
             one pass {single_pass_steps}, per target {per_target_steps}"
        );
    }

    /// A first-parent cycle is refused by the tree pass as well as the replay.
    #[test]
    fn one_pass_tree_resolution_refuses_a_first_parent_cycle() {
        let (mut changes, _) = forking_tree_history();
        let left = SemanticChangeId::from_hash(Hash256::from_bytes([0xc1; 32]));
        let right = SemanticChangeId::from_hash(Hash256::from_bytes([0xc2; 32]));
        for (id, parent) in [(left, right), (right, left)] {
            let mut cyclic = change("cyclic", ChangeSpec::default());
            cyclic.id = id;
            cyclic.parents = vec![parent];
            changes.insert(id, cyclic);
        }
        let targets = vec![left, right];

        let per_target = per_target_trees(&changes, &targets)
            .expect_err("the per-target resolution must refuse a first-parent cycle");
        let single = resolve_first_parent_trees(&changes, &targets)
            .expect_err("the single pass must refuse a first-parent cycle")
            .to_string();
        for (label, error) in [("per-target", per_target), ("single pass", single)] {
            assert!(
                error.contains("cycle in first-parent history"),
                "{label} resolution refused a cycle for the wrong reason: {error}"
            );
        }
    }

    /// A missing first parent is refused by both, and named the same way.
    #[test]
    fn one_pass_tree_resolution_refuses_a_missing_first_parent() {
        let (mut changes, targets) = forking_tree_history();
        let orphaned = SemanticChangeId::from_hash(Hash256::from_bytes([0xd1; 32]));
        let head = *targets.last().expect("the fixture has a head");
        changes
            .get_mut(&head)
            .expect("the head is in the fixture")
            .parents = vec![orphaned];

        let per_target = per_target_trees(&changes, &[head])
            .expect_err("the per-target resolution must refuse a missing first parent");
        let single = resolve_first_parent_trees(&changes, &[head])
            .expect_err("the single pass must refuse a missing first parent")
            .to_string();
        for (label, error) in [("per-target", per_target), ("single pass", single)] {
            assert!(
                error.contains(&orphaned.to_string()),
                "{label} resolution must name the absent change: {error}"
            );
        }
    }

    /// A deep trunk fanning out to many tips, which is the shape whose
    /// per-change replay cost grows with tips times history.
    ///
    /// Sized past `PROGRESS_MIN_TOTAL` on purpose, so the progress reporter's
    /// start, stride, and finish paths all execute here rather than only in the
    /// ignored measurement.
    #[test]
    fn replays_a_deep_history_with_many_tips() {
        const TRUNK: usize = 1_200;
        const TIPS: usize = 40;

        assert!(
            TRUNK + 1 + TIPS > PROGRESS_MIN_TOTAL,
            "the fixture must cross the progress threshold to exercise reporting"
        );

        let (changes, targets) = deep_history(TRUNK, TIPS);
        assert_eq!(changes.len(), TRUNK + 1 + TIPS);
        validate_first_parent_history(&changes, &targets)
            .expect("a deep history with many tips must replay");

        // Every tip shares the whole trunk, so the lineage is collected once
        // rather than once per tip.
        let lineage = collect_first_parent_lineage(&changes, &targets).unwrap();
        assert_eq!(lineage.len(), changes.len());
    }

    fn deep_history(
        trunk_steps: usize,
        tips: usize,
    ) -> (
        HashMap<SemanticChangeId, SemanticChange>,
        Vec<SemanticChangeId>,
    ) {
        let seed = entity("trunk", 0x11);
        let mut changes = vec![change(
            "seed the trunk",
            ChangeSpec {
                entity_deltas: vec![EntityDelta::Added { new: seed.clone() }],
                ..ChangeSpec::default()
            },
        )];
        let mut live = seed;
        for step in 0..trunk_steps {
            let next = revise(&live, u8::try_from(step % 200).unwrap().wrapping_add(1));
            let parent = changes.last().expect("the trunk always has a head").id;
            changes.push(change(
                &format!("trunk step {step}"),
                ChangeSpec {
                    parents: vec![parent],
                    entity_deltas: vec![EntityDelta::Modified {
                        old: live.clone(),
                        new: next.clone(),
                    }],
                    ..ChangeSpec::default()
                },
            ));
            live = next;
        }

        let head = changes.last().expect("the trunk always has a head").id;
        for tip in 0..tips {
            let (artifact, entry) = blob(
                &format!("src/tip{tip}.rs"),
                0xb000 + u128::try_from(tip).unwrap(),
                0x41,
            );
            changes.push(change(
                &format!("tip {tip}"),
                ChangeSpec {
                    parents: vec![head],
                    tree_deltas: vec![TreeDelta::Added {
                        artifact_id: artifact,
                        new: entry,
                    }],
                    ..ChangeSpec::default()
                },
            ));
        }

        history(changes)
    }
}
