// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

use kin_blobs::BlobStore;
use kin_index::{FileEvent, IndexPipeline};
use kin_model::preset::{BrokenAstBehavior, ReconcilePolicy, ValidationLevel};
use kin_model::{
    ConflictId, ConflictKind, ConflictObject, Entity, EntityDelta, EntityId, EntityKind,
    FilePathId, GraphNodeId, GraphStore, IntentScope, IntentSummary, ParseState, Relation,
    RelationDelta, RelationId, RelationKind, SessionId, SourceRegion, TransactionDelta,
};
use kin_projection::{project_entity_mutations_with_policy, ProjectionState};

use crate::collision::{
    check_signature_change, check_visibility_change, CollisionCheck, MergeConflict,
    MergeConflictKind, TrafficChecker,
};
use crate::cross_file::LiveCrossFileLinker;
use crate::error::{ReconcileError, Result};
use crate::lkg::LkgStore;

/// Whether a relation is one a parse pass could have produced.
///
/// The retire rules and the identity-matching below both turn on it, so they
/// cannot disagree about which edges this pass speaks for.
fn is_parser_derived(relation: &Relation) -> bool {
    matches!(
        relation.origin,
        kin_model::RelationOrigin::Parsed | kin_model::RelationOrigin::Inferred
    )
}

/// The existing relation a freshly derived parser edge keeps the identity of.
///
/// One logical edge can be held twice under one `(src, dst, kind)` key with two
/// ids: the parser's, and the language server's, which `kin-lsp` derives from
/// the same triple through its own namespace. Taking the lowest id of the
/// bucket therefore bound a re-derived parser payload onto whichever of the two
/// happened to sort first, and when that was the language-server edge, the
/// parser edge went unmatched and survived carrying its pre-edit span. A
/// comment-only commit then reported one call site at two lines, the stale one
/// stamped complete (FIR-2644).
///
/// So a parser edge only ever takes a parser-derived identity. When the bucket
/// holds none, the edge is new here even though the key is not: an enrichment
/// edge is a different fact from the parse that agrees with it, and overwriting
/// one with the other destroys the stronger of the two.
fn parser_identity_to_keep(bucket: Option<&Vec<Relation>>) -> Option<&Relation> {
    bucket?.iter().find(|relation| is_parser_derived(relation))
}

/// Every relation the graph holds at one node, in both directions and of every
/// kind, memoized for the pass.
///
/// `EntityStore::get_all_relations_for_entity` answers the entity-to-entity
/// question and filters everything else out, so an edge with one non-entity
/// endpoint is invisible through it. `traverse` at depth one reads the
/// mixed-node edge index instead and returns exactly the edges incident to the
/// node it starts from, which is the question both callers below are asking:
/// what identities does the graph already hold here, and what would this
/// removal strand.
fn relations_held_at<'a, G: GraphStore>(
    graph: &G,
    cache: &'a mut HashMap<GraphNodeId, HashMap<RelationId, Relation>>,
    node: GraphNodeId,
) -> Result<&'a HashMap<RelationId, Relation>> {
    if !cache.contains_key(&node) {
        let held = graph
            .traverse(&node, &[], 1)
            .map_err(|error| ReconcileError::Graph(error.to_string()))?
            .relations
            .into_iter()
            .filter(|relation| relation.src == node || relation.dst == node)
            .map(|relation| (relation.id, relation))
            .collect();
        cache.insert(node, held);
    }
    Ok(cache
        .get(&node)
        .expect("the entry was just inserted when it was absent"))
}

/// The relation the graph already holds under this identity, if any.
fn relation_already_held<G: GraphStore>(
    graph: &G,
    cache: &mut HashMap<GraphNodeId, HashMap<RelationId, Relation>>,
    candidate: &Relation,
) -> Result<Option<Relation>> {
    Ok(relations_held_at(graph, cache, candidate.src)?
        .get(&candidate.id)
        .cloned())
}

/// Carry one freshly derived edge into the delta under the identity the graph
/// actually holds for it.
///
/// A `TransactionDelta` may not add an identity the store already carries:
/// kin-db refuses the whole transition with `transaction adds existing
/// relation <id>`, and the reconcile caller logs that and drops the delta, so
/// a rename's entities never land while the other file's pass does. The pass
/// cannot see every such identity by key, because `existing_relations` is
/// gathered from the entities of the file being reconciled and the cross-file
/// pass also folds in edges SOURCED BY the files it just unblocked. Asking the
/// graph by identity is what closes that gap, and it is the same question
/// kin-db asks (FIR-2838).
fn push_relation_addition<G: GraphStore>(
    graph: &G,
    cache: &mut HashMap<GraphNodeId, HashMap<RelationId, Relation>>,
    delta: &mut TransactionDelta,
    spoken_for: &mut HashSet<RelationId>,
    new: Relation,
) -> Result<()> {
    if !spoken_for.insert(new.id) {
        debug!(
            relation_id = %new.id,
            kind = ?new.kind,
            "this delta already speaks for the relation identity; skipping the second claim"
        );
        return Ok(());
    }
    match relation_already_held(graph, cache, &new)? {
        Some(old) if old == new => {
            debug!(
                relation_id = %new.id,
                "the graph already holds this exact edge; adding it again would refuse the \
                 whole transition"
            );
        }
        Some(old) => {
            debug!(
                relation_id = %new.id,
                kind = ?new.kind,
                "the graph already holds this relation identity; carrying it as a modification"
            );
            delta
                .relation_deltas
                .push(RelationDelta::Modified { old, new });
        }
        None => delta.relation_deltas.push(RelationDelta::Added { new }),
    }
    Ok(())
}

/// One entity's declaration position before and after this pass.
type SpanMove = (kin_model::SourceSpan, kin_model::SourceSpan);

/// Re-anchor one evidence span through the declaration that contains it.
///
/// A relation this pass preserves rather than re-derives keeps the span the
/// resolver that minted it recorded, and a line-shifting edit above it makes
/// that span name a line the call is no longer on. Language-server edges are
/// the whole of this class in practice: nothing re-derives them on the reconcile
/// path, they are deliberately never retired here, and `find_references` reports
/// their spans as reference lines. The rc0550 run read one call site at two
/// lines because of it, the stale one stamped complete (FIR-2644).
///
/// Placement is proven, never guessed. The span is placed through the innermost
/// declaration whose PRE-EDIT lines contain it, and only when that declaration
/// merely moved: an equal line extent before and after is what makes the shift a
/// translation rather than a rewrite whose interior moved by some other amount.
/// Anything else returns `None`, which the caller turns into an absent span, so
/// the surface reports `no_evidence_span` instead of a line that may not carry
/// the call.
///
/// Columns are carried through unchanged, and bytes are shifted only when both
/// the declaration and the span carry real byte offsets: `kin-lsp` records a
/// position with zero bytes, and adding a delta to those would invent an offset.
fn reanchor_evidence_span(
    span: &kin_model::SourceSpan,
    moves: &[SpanMove],
) -> Option<kin_model::SourceSpan> {
    let (old, new) = moves
        .iter()
        .filter(|(old, _)| {
            old.file == span.file
                && old.start_line <= span.start_line
                && span.end_line <= old.end_line
        })
        .min_by_key(|(old, _)| old.end_line.saturating_sub(old.start_line))?;
    if old.end_line.saturating_sub(old.start_line) != new.end_line.saturating_sub(new.start_line) {
        return None;
    }
    let line_delta = i64::from(new.start_line) - i64::from(old.start_line);
    let start_line = u32::try_from(i64::from(span.start_line) + line_delta).ok()?;
    let end_line = u32::try_from(i64::from(span.end_line) + line_delta).ok()?;
    let shift_bytes = old.end_byte > old.start_byte && (span.start_byte > 0 || span.end_byte > 0);
    let byte_delta = new.start_byte as i64 - old.start_byte as i64;
    let (start_byte, end_byte) = if shift_bytes {
        (
            usize::try_from(span.start_byte as i64 + byte_delta).ok()?,
            usize::try_from(span.end_byte as i64 + byte_delta).ok()?,
        )
    } else {
        (span.start_byte, span.end_byte)
    };
    Some(kin_model::SourceSpan {
        file: span.file.clone(),
        start_byte,
        end_byte,
        start_line,
        start_col: span.start_col,
        end_line,
        end_col: span.end_col,
    })
}

/// The same relation with every evidence span that points into `file` placed
/// where this pass moved it, or `None` when nothing changed.
fn relation_with_reanchored_evidence(
    relation: &Relation,
    file: &FilePathId,
    moves: &[SpanMove],
) -> Option<Relation> {
    let mut updated = relation.clone();
    let mut changed = false;
    for evidence in &mut updated.evidence {
        let Some(span) = evidence.source_span.as_ref() else {
            continue;
        };
        if &span.file != file {
            continue;
        }
        let placed = reanchor_evidence_span(span, moves);
        if placed.as_ref() != evidence.source_span.as_ref() {
            evidence.source_span = placed;
            changed = true;
        }
    }
    changed.then_some(updated)
}

/// Outcome of reconciling a single file change.
#[derive(Debug)]
pub enum ReconcileOutcome {
    /// File parsed cleanly; an exact transaction was derived.
    Updated {
        file_id: FilePathId,
        added: Vec<EntityId>,
        modified: Vec<EntityId>,
        removed: Vec<EntityId>,
        /// Collision warnings from the traffic checker (soft locks).
        collision_warnings: Vec<IntentSummary>,
    },
    /// File had parse errors; LKG state retained, no graph changes.
    BrokenAst {
        file_id: FilePathId,
        error_ranges: Vec<(usize, usize)>,
    },
    /// Conflict detected that requires resolution.
    Conflict(ConflictObject),
    /// File was removed; entities cleaned up.
    FileRemoved {
        file_id: FilePathId,
        removed: Vec<EntityId>,
        /// Collision warnings from the traffic checker (soft locks).
        collision_warnings: Vec<IntentSummary>,
    },
}

/// One filesystem reconciliation result.
///
/// The delta is self-contained and self-inverting: every modification and
/// removal carries the complete old state observed in the graph. Callers must
/// commit it through an atomic graph or repository-authority transaction.
#[derive(Debug)]
pub struct ReconcileResult {
    pub outcome: ReconcileOutcome,
    pub delta: TransactionDelta,
}

impl ReconcileResult {
    fn validated(outcome: ReconcileOutcome, mut delta: TransactionDelta) -> Result<Self> {
        delta.entity_deltas.sort_by_key(EntityDelta::target_id);
        delta.relation_deltas.sort_by_key(RelationDelta::target_id);
        delta
            .tree_deltas
            .sort_by_key(kin_model::TreeDelta::artifact_id);
        kin_model::validate_transaction_delta(&delta)
            .map_err(|error| ReconcileError::InvalidTransaction(error.to_string()))?;
        Ok(Self { outcome, delta })
    }

    fn unchanged(outcome: ReconcileOutcome) -> Result<Self> {
        Self::validated(outcome, TransactionDelta::default())
    }

    pub fn into_parts(self) -> (ReconcileOutcome, TransactionDelta) {
        (self.outcome, self.delta)
    }
}

/// The reconciliation engine. Derives exact transactions from filesystem
/// input and projects committed transactions back to filesystem views.
///
/// Two directions:
/// - **File -> Transaction:** detect file edits and return one exact delta
/// - **Transaction -> File:** project committed mutations to a working view
pub struct Reconciler {
    pipeline: IndexPipeline,
    lkg: LkgStore,
    projection: ProjectionState,
    working_dir: PathBuf,
    /// Optional traffic checker for pre-mutation collision detection.
    traffic_checker: Option<Box<dyn TrafficChecker>>,
    /// Session ID of the caller (used for collision checks).
    session_id: Option<SessionId>,
    /// Reconcile policy controlling broken AST behavior, validation, and git shadow.
    policy: ReconcilePolicy,
    /// Cache of tree-sitter Trees keyed by file path, used for incremental parsing.
    tree_cache: HashMap<FilePathId, tree_sitter::Tree>,
    /// Cross-file relation resolution for the live path. Seeded from graph
    /// truth once, then kept current as files arrive.
    cross_file: LiveCrossFileLinker,
}

impl Reconciler {
    /// Create a new reconciler for the given working directory.
    ///
    /// Uses the default `ReconcilePolicy` (Brownfield).
    pub fn new(working_dir: PathBuf) -> Self {
        Self::with_policy(working_dir, ReconcilePolicy::default())
    }

    /// Create a new reconciler with an explicit policy.
    pub fn with_policy(working_dir: PathBuf, policy: ReconcilePolicy) -> Self {
        Self {
            pipeline: IndexPipeline::new(),
            lkg: LkgStore::new(),
            projection: ProjectionState::new(),
            working_dir,
            traffic_checker: None,
            session_id: None,
            policy,
            tree_cache: HashMap::new(),
            cross_file: LiveCrossFileLinker::new(),
        }
    }

    /// Get the current reconcile policy.
    pub fn policy(&self) -> &ReconcilePolicy {
        &self.policy
    }

    /// Seed only entity fingerprints from an existing graph.
    ///
    /// This is the daemon-startup fast path. The reconciler only consults LKG
    /// entity fingerprints during bootstrap, and walking per-entity relations
    /// on large persisted graphs adds minutes to daemon startup.
    pub fn seed_lkg_entities_from_graph<G: GraphStore>(&mut self, graph: &G) {
        if let Ok(entities) = graph.list_all_entities() {
            for entity in &entities {
                self.lkg.record(entity);
            }
            tracing::info!(
                count = self.lkg.len(),
                "seeded LKG entity baseline from graph snapshot"
            );
        }
    }

    /// Index the cross-file linker's entity universe from an existing graph.
    ///
    /// Without this the live path resolves every file against an empty
    /// universe, reports every destination missing, and falls back to the
    /// intra-file-only behavior this seam exists to end. One pass over graph
    /// entities per process, the same shape and place as
    /// [`Reconciler::seed_lkg_entities_from_graph`]; every write after it is
    /// bounded by the edited file and the files waiting on the names it
    /// defines, never by repository size.
    pub fn seed_cross_file_linker_from_graph<G: GraphStore>(&mut self, graph: &G) {
        self.cross_file.seed_from_graph(graph);
    }

    /// Access the cross-file linker (for inspection/testing).
    pub fn cross_file_linker(&self) -> &LiveCrossFileLinker {
        &self.cross_file
    }

    /// Set the traffic checker for pre-mutation collision detection.
    pub fn set_traffic_checker(&mut self, checker: Box<dyn TrafficChecker>) {
        self.traffic_checker = Some(checker);
    }

    /// Get the current session ID used for collision checks.
    pub fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    /// Set the session ID used for collision checks.
    pub fn set_session_id(&mut self, session_id: SessionId) {
        self.session_id = Some(session_id);
    }

    /// Clear the session ID, reverting to no caller identity for collision checks.
    pub fn clear_session_id(&mut self) {
        self.session_id = None;
    }

    /// Access the LKG store (for inspection/testing).
    pub fn lkg(&self) -> &LkgStore {
        &self.lkg
    }

    /// Access the projection state (for inspection/testing).
    pub fn projection(&self) -> &ProjectionState {
        &self.projection
    }

    /// Access the projection state mutably.
    pub fn projection_mut(&mut self) -> &mut ProjectionState {
        &mut self.projection
    }

    // ---------------------------------------------------------------
    // Direction 1: File -> Transaction
    // ---------------------------------------------------------------

    /// Reconcile a file change event. Parses the file, compares against
    /// current graph state, and returns one exact transaction delta.
    ///
    /// If the parse produces errors, the LKG state is retained and no
    /// graph changes are made.
    pub fn reconcile_file_change<G: GraphStore>(
        &mut self,
        event: &FileEvent,
        blob_store: &BlobStore,
        graph: &G,
    ) -> Result<ReconcileResult> {
        let event_path = match event {
            FileEvent::Changed(path) | FileEvent::Removed(path) => path,
        };
        let comparable_path = self.comparable_event_path(event_path);
        let path = comparable_path.as_path();
        if !self.should_track_path(path) {
            debug!(
                file = %event_path.display(),
                "excluded path reached reconcile; purging any existing graph state"
            );
            return self.reconcile_file_removal(path, graph);
        }

        match event {
            FileEvent::Changed(_) => self.reconcile_file_edit(path, blob_store, graph),
            FileEvent::Removed(_) => {
                // RACE CONDITION HARDENING: Verify the file is still absent
                // before committing entity removals. Editors that do atomic
                // saves (write temp → delete old → rename temp) produce a
                // transient Removed event followed by a Changed event. If
                // both events land in the same dedup batch the Removed event
                // may be the surviving one while the file already exists
                // again on disk. Treat this case as a file edit.
                if path.exists() {
                    debug!(
                        file = %path.display(),
                        "file exists at removal time — treating as edit (atomic-save race)"
                    );
                    return self.reconcile_file_edit(path, blob_store, graph);
                }
                self.reconcile_file_removal(path, graph)
            }
        }
    }

    /// Return a physical path that can be compared with the canonical
    /// repository root without dereferencing the event entry itself.
    ///
    /// macOS reports temporary-directory events through `/var` even when the
    /// repository root was opened through its canonical `/private/var` spelling.
    /// Canonicalizing only the closest existing parent preserves the identity of
    /// symlinks and removed paths while eliminating that alias. Missing parent
    /// components are appended lexically after the existing ancestor resolves.
    fn comparable_event_path(&self, path: &Path) -> PathBuf {
        if path.strip_prefix(&self.working_dir).is_ok() {
            return path.to_path_buf();
        }

        let Some(name) = path.file_name() else {
            return path.to_path_buf();
        };
        let Some(mut ancestor) = path.parent() else {
            return path.to_path_buf();
        };
        let mut missing = Vec::new();

        loop {
            match ancestor.canonicalize() {
                Ok(mut canonical) => {
                    for component in missing.iter().rev() {
                        canonical.push(component);
                    }
                    canonical.push(name);
                    return canonical;
                }
                Err(_) => {
                    let Some(component) = ancestor.file_name() else {
                        return path.to_path_buf();
                    };
                    missing.push(component.to_os_string());
                    let Some(parent) = ancestor.parent() else {
                        return path.to_path_buf();
                    };
                    ancestor = parent;
                }
            }
        }
    }

    fn should_track_path(&self, path: &Path) -> bool {
        path.strip_prefix(&self.working_dir)
            .map(kin_index::should_index_repo_relative_path)
            .unwrap_or(false)
    }

    /// Reconcile a file change event with an optional incremental parse hint.
    ///
    /// When an `edit_hint` is provided, the reconciler looks up the cached
    /// tree-sitter Tree for the file and uses incremental parsing (<5ms) instead
    /// of a full re-parse (50-100ms). The resulting tree is cached for the next
    /// change.
    ///
    /// Falls back to `reconcile_file_change` when no hint is provided.
    pub fn reconcile_file_change_with_hint<G: GraphStore>(
        &mut self,
        event: &FileEvent,
        blob_store: &BlobStore,
        graph: &G,
        edit_hint: Option<&kin_parser::EditHint>,
    ) -> Result<ReconcileResult> {
        match (event, edit_hint) {
            (FileEvent::Changed(path), Some(hint)) => {
                let comparable_path = self.comparable_event_path(path);
                if !self.should_track_path(&comparable_path) {
                    return self.reconcile_file_removal(&comparable_path, graph);
                }
                self.reconcile_file_edit_incremental(&comparable_path, blob_store, graph, hint)
            }
            // Delegate to reconcile_file_change which handles the
            // removal-but-file-exists race condition.
            _ => self.reconcile_file_change(event, blob_store, graph),
        }
    }

    /// Reconcile a file edit using incremental parsing.
    fn reconcile_file_edit_incremental<G: GraphStore>(
        &mut self,
        path: &Path,
        blob_store: &BlobStore,
        graph: &G,
        edit_hint: &kin_parser::EditHint,
    ) -> Result<ReconcileResult> {
        let file_id = kin_index::normalize_file_path_id(path, &self.working_dir);
        let old_tree = self.tree_cache.get(&file_id);

        let (indexed, tree) = self.pipeline.index_file_relative_with_hint(
            path,
            blob_store,
            &self.working_dir,
            old_tree,
            Some(edit_hint),
        )?;

        let result_file_id = indexed.file_id.clone();

        // Check for broken AST — behavior depends on policy.
        if let ParseState::Incomplete { error_ranges } = &indexed.parse_state {
            match self.policy.broken_ast_behavior {
                BrokenAstBehavior::Reject => {
                    warn!(
                        file = %path.display(),
                        errors = error_ranges.len(),
                        "broken AST rejected by policy"
                    );
                    return Err(ReconcileError::BrokenAstRejected {
                        file_id: result_file_id,
                        error_ranges: error_ranges.clone(),
                    });
                }
                BrokenAstBehavior::FallbackToLkg => {
                    warn!(
                        file = %path.display(),
                        errors = error_ranges.len(),
                        "broken AST, retaining LKG state"
                    );
                    // Still cache the tree even on broken AST — it's valid for
                    // incremental parse even if the content has errors.
                    self.tree_cache.insert(file_id, tree);
                    return ReconcileResult::unchanged(ReconcileOutcome::BrokenAst {
                        file_id: result_file_id,
                        error_ranges: error_ranges.clone(),
                    });
                }
            }
        }

        // RACE CONDITION HARDENING: Verify the file hasn't changed since we
        // indexed it. If modified mid-reconcile, defer to the next tick.
        match std::fs::read(path) {
            Ok(current_bytes) => {
                let current_hash = kin_blobs::digest(&current_bytes);
                if current_hash != indexed.blob_hash {
                    debug!(
                        file = %path.display(),
                        "file modified during reconcile (incremental), deferring to next tick"
                    );
                    return Err(ReconcileError::FileModifiedDuringReconcile {
                        path: path.display().to_string(),
                        expected_hash: format!("{}", indexed.blob_hash),
                        actual_hash: format!("{}", current_hash),
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(
                    file = %path.display(),
                    "file deleted during incremental reconcile, proceeding with blob content"
                );
            }
            Err(e) => {
                return Err(ReconcileError::Io {
                    path: path.display().to_string(),
                    source: e,
                });
            }
        }

        // Snapshot LKG before deriving the transaction so an error cannot publish
        // partially advanced reconcile state.
        let lkg_snapshot = self.lkg.clone();

        let result =
            self.reconcile_file_edit_inner(&indexed, &result_file_id, path, blob_store, graph);

        // On error, restore LKG to its pre-reconcile state.
        if result.is_err() {
            self.lkg = lkg_snapshot;
        } else {
            // Cache the tree for future incremental parses.
            self.tree_cache.insert(file_id, tree);
        }

        result
    }

    /// Reconcile a file edit (create or modify).
    ///
    /// Transactional: if derivation fails, the local LKG baseline is restored
    /// so a later attempt cannot observe partially advanced reconcile state.
    fn reconcile_file_edit<G: GraphStore>(
        &mut self,
        path: &Path,
        blob_store: &BlobStore,
        graph: &G,
    ) -> Result<ReconcileResult> {
        let indexed = self
            .pipeline
            .index_file_relative(path, blob_store, &self.working_dir)?;
        let file_id = indexed.file_id.clone();

        // Check for broken AST — behavior depends on policy.
        if let ParseState::Incomplete { error_ranges } = &indexed.parse_state {
            match self.policy.broken_ast_behavior {
                BrokenAstBehavior::Reject => {
                    warn!(
                        file = %path.display(),
                        errors = error_ranges.len(),
                        "broken AST rejected by policy"
                    );
                    return Err(ReconcileError::BrokenAstRejected {
                        file_id,
                        error_ranges: error_ranges.clone(),
                    });
                }
                BrokenAstBehavior::FallbackToLkg => {
                    warn!(
                        file = %path.display(),
                        errors = error_ranges.len(),
                        "broken AST, retaining LKG state"
                    );
                    return ReconcileResult::unchanged(ReconcileOutcome::BrokenAst {
                        file_id,
                        error_ranges: error_ranges.clone(),
                    });
                }
            }
        }

        // RACE CONDITION HARDENING: Verify the file hasn't changed since we
        // indexed it. If the file was modified between the index read and now,
        // the entities/spans we extracted are stale. Return a specific error
        // so the daemon can re-queue this file for the next tick.
        match std::fs::read(path) {
            Ok(current_bytes) => {
                let current_hash = kin_blobs::digest(&current_bytes);
                if current_hash != indexed.blob_hash {
                    debug!(
                        file = %path.display(),
                        "file modified during reconcile, deferring to next tick"
                    );
                    return Err(ReconcileError::FileModifiedDuringReconcile {
                        path: path.display().to_string(),
                        expected_hash: format!("{}", indexed.blob_hash),
                        actual_hash: format!("{}", current_hash),
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // File was deleted between index and now. This is safe to
                // proceed: blob content is already in the store, and the
                // entities/spans were extracted from the blob. The file
                // layout will be registered from blob content, not disk.
                debug!(
                    file = %path.display(),
                    "file deleted during reconcile, proceeding with blob content"
                );
            }
            Err(e) => {
                // Unexpected I/O error (permissions, disk failure, etc.).
                // Defer to next tick rather than proceeding with unverified data.
                return Err(ReconcileError::Io {
                    path: path.display().to_string(),
                    source: e,
                });
            }
        }

        // Snapshot LKG before deriving the transaction so an error cannot publish
        // partially advanced reconcile state.
        let lkg_snapshot = self.lkg.clone();

        let result = self.reconcile_file_edit_inner(&indexed, &file_id, path, blob_store, graph);

        // On error, restore LKG to its pre-reconcile state and drop this file
        // from the cross-file universe. Cloning the universe per write to undo
        // it would cost what this whole seam exists to avoid; forgetting the
        // one file it touched leaves the universe missing an entry rather than
        // holding a wrong one, and the next successful reconcile reinstalls it.
        if result.is_err() {
            self.lkg = lkg_snapshot;
            self.cross_file.forget_file(&file_id.0);
        }

        result
    }

    /// Inner implementation of reconcile_file_edit, separated so the caller
    /// can restore internal LKG state on error.
    ///
    /// This entrypoint derives the same semantic/layout transaction from bytes
    /// already parsed out of immutable repository CAS. It performs no host
    /// filesystem read or membership inference, making it suitable for
    /// graph-authority planners such as daemon-owned MCP commits.
    pub fn reconcile_indexed_content<G: GraphStore>(
        &mut self,
        indexed: &kin_index::IndexedFile,
        blob_store: &BlobStore,
        graph: &G,
    ) -> Result<ReconcileResult> {
        let lkg_snapshot = self.lkg.clone();
        let file_id = indexed.file_id.clone();
        let display_path = PathBuf::from(&file_id.0);
        let result =
            self.reconcile_file_edit_inner(indexed, &file_id, &display_path, blob_store, graph);
        if result.is_err() {
            self.lkg = lkg_snapshot;
            self.cross_file.forget_file(&file_id.0);
        }
        result
    }

    /// Inner implementation of reconcile_file_edit, separated so the caller
    /// can restore internal LKG state on error.
    fn reconcile_file_edit_inner<G: GraphStore>(
        &mut self,
        indexed: &kin_index::IndexedFile,
        file_id: &FilePathId,
        path: &Path,
        blob_store: &BlobStore,
        graph: &G,
    ) -> Result<ReconcileResult> {
        // Get existing entities for this file from the graph
        let existing = self.get_file_entities(graph, file_id)?;

        // Build scopes for collision checking: all entities that will be
        // affected (existing + new ones from parse).
        let mut affected_scopes: Vec<IntentScope> =
            existing.iter().map(|e| IntentScope::Entity(e.id)).collect();
        for new_entity in &indexed.entities {
            // Only add if not already covered by an existing entity
            let already = existing
                .iter()
                .any(|e| e.name == new_entity.name && e.kind == new_entity.kind);
            if !already {
                affected_scopes.push(IntentScope::Entity(new_entity.id));
            }
        }
        // Also check the file-level scope
        affected_scopes.push(IntentScope::Artifact(file_id.clone()));

        // Check for collisions before applying mutations
        let collision_warnings = self.check_scopes(&affected_scopes)?;

        let mut added = Vec::new();
        let mut modified = Vec::new();
        let mut removed = Vec::new();
        let mut stable_entity_ids = HashMap::new();
        // Where each declaration this pass matched sat before and after, which
        // is what lets a preserved relation's evidence be re-anchored rather
        // than left naming a pre-edit line.
        let mut entity_span_moves: Vec<SpanMove> = Vec::new();
        let mut delta = TransactionDelta::default();
        let blob_hash = serde_json::Value::String(indexed.blob_hash.to_string());

        // Every entity id this transaction already speaks for. One delta per
        // entity is the transaction invariant, so an id enters this set the
        // moment a delta names it and no later delta may name it again.
        let mut claimed: HashSet<EntityId> = HashSet::new();

        // Process new entities from the parse
        for new_entity in &indexed.entities {
            // Validate entity based on policy strictness.
            if let Some(reason) = validate_entity(new_entity) {
                match self.policy.validation_strictness {
                    ValidationLevel::Strict => {
                        return Err(ReconcileError::ValidationFailed {
                            entity_id: new_entity.id,
                            reason,
                        });
                    }
                    ValidationLevel::Lenient => {
                        warn!(
                            entity = %new_entity.name,
                            reason = %reason,
                            "entity validation warning (lenient mode)"
                        );
                    }
                }
            }

            // A graph-authoritative planner may deliberately retain an
            // existing identity while changing its source name (rename is the
            // canonical case). Parser-produced identities normally differ
            // after such a source edit, so the planner must explicitly remap
            // the parsed entity before reaching this boundary. Honor that
            // exact id first, while still requiring the entity kind to match;
            // ordinary filesystem reconciliation continues to match by name
            // and kind as before.
            //
            // Every pass skips an entity another parsed declaration already
            // claimed, so the match is one-to-one. Identity is derived from the
            // declaration's start line, so an edit above a declaration retires
            // the id the graph holds for it and drops it to the passes below.
            // A file that declares one name twice, which a cfg-gated pair and a
            // Python `@overload` group both do routinely, would otherwise
            // collapse both halves onto whichever half the graph returned
            // first.
            //
            // Name and kind alone cannot tell one member of such a group from
            // another, and `get_file_entities` returns graph-query order rather
            // than declaration order, so a line-shifting edit anywhere above the
            // group rotated its members onto each other: three declarations came
            // back as three modifications reporting signature transitions none
            // of them underwent, in mutually contradictory directions. The
            // declaration's own signature is what distinguishes group members,
            // so it is consulted before falling back to name and kind, and the
            // fallback pairs by nearest declaration position rather than by
            // whatever order the graph happened to return.
            let existing_match = existing
                .iter()
                .find(|entity| {
                    entity.id == new_entity.id
                        && entity.kind == new_entity.kind
                        && !claimed.contains(&entity.id)
                })
                .or_else(|| {
                    nearest_unclaimed(&existing, new_entity, &claimed, |candidate, parsed| {
                        candidate.signature == parsed.signature
                    })
                })
                .or_else(|| nearest_unclaimed(&existing, new_entity, &claimed, |_, _| true));

            match existing_match {
                Some(old) => {
                    claimed.insert(old.id);

                    let mut updated = new_entity.clone();
                    updated.id = old.id;
                    updated.lineage_parent = old.lineage_parent;
                    updated.created_in = old.created_in;
                    updated
                        .metadata
                        .extra
                        .insert("blob_hash".into(), blob_hash.clone());
                    stable_entity_ids.insert(new_entity.id, old.id);
                    if let (Some(was), Some(now)) = (old.span.as_ref(), updated.span.as_ref()) {
                        entity_span_moves.push((was.clone(), now.clone()));
                    }

                    // Compare the complete enrichment payload, not only the AST
                    // fingerprint. Span and blob provenance must advance even for
                    // source edits that are semantically equivalent.
                    if updated != *old {
                        self.lkg.record(&updated);
                        delta.entity_deltas.push(EntityDelta::Modified {
                            old: old.clone(),
                            new: updated,
                        });
                        modified.push(old.id);

                        debug!(
                            entity = %old.name,
                            id = %old.id,
                            "entity modified"
                        );
                    } else {
                        self.lkg.record(old);
                        debug!(
                            entity = %old.name,
                            "entity payload unchanged, skipping"
                        );
                    }
                }
                None => {
                    // New entity. Identity is derived from the file, name,
                    // kind, and start line, so two declarations sharing all
                    // four are one entity as far as the graph can tell and only
                    // the first of them can be carried.
                    let mut added_entity = new_entity.clone();
                    if !claimed.insert(added_entity.id) {
                        warn!(
                            entity = %added_entity.name,
                            id = %added_entity.id,
                            "declaration repeats an identity this transaction already carries, skipping"
                        );
                        continue;
                    }
                    added_entity
                        .metadata
                        .extra
                        .insert("blob_hash".into(), blob_hash.clone());
                    stable_entity_ids.insert(added_entity.id, added_entity.id);
                    delta.entity_deltas.push(EntityDelta::Added {
                        new: added_entity.clone(),
                    });
                    self.lkg.record(&added_entity);
                    added.push(added_entity.id);

                    debug!(
                        entity = %added_entity.name,
                        id = %added_entity.id,
                        "new entity added"
                    );
                }
            }
        }

        // Entities that existed before but are no longer in the file -> removed.
        // Claiming as we go keeps one delta per entity even if graph truth
        // handed back the same entity twice, and walking `existing` rather than
        // a map keeps the removal order the order the graph reported.
        for old in &existing {
            if claimed.insert(old.id) {
                delta
                    .entity_deltas
                    .push(EntityDelta::Removed { old: old.clone() });
                self.lkg.remove(&old.id);
                removed.push(old.id);
                debug!(id = %old.id, "entity removed from file");
            }
        }

        // Process relations: diff existing relations against newly parsed ones.
        //
        // Origin-filtered stale removal: a single-file reconcile is authoritative
        // for relations it could have re-derived on this pass. Two classes qualify.
        // Parser-derived edges with both endpoints inside this file have always
        // qualified. Cross-file edges this file sources now qualify too, because the
        // incremental cross-file linker below re-derives them, but only on the
        // evidence this pass actually holds: the file's own text. LSP-enrichment
        // edges, agent-created Manual edges, and edges this file merely receives are
        // still never re-derived here and must be preserved. We therefore track
        // origin alongside the relation ID so the removal loop can apply the
        // combined filter.
        let file_entity_node_ids: HashSet<GraphNodeId> = existing
            .iter()
            .map(|entity| GraphNodeId::Entity(entity.id))
            .chain(stable_entity_ids.values().copied().map(GraphNodeId::Entity))
            .collect();
        let removed_entity_ids: HashSet<EntityId> = removed.iter().copied().collect();

        // Resolve this file's cross-file relations, and re-bind the files that
        // were waiting on a name it defines.
        //
        // `IndexPipeline` matches every extracted relation against the parsed
        // file's own entities and defers the rest to a linker the live path
        // never ran, so before this a file written after `kin init` kept
        // intra-file edges forever. The linker is handed the identities this
        // transaction will actually commit rather than the raw parse
        // identities: a modified entity keeps the id already in the graph, and
        // resolving against the parse identity would mint edges into entities
        // the delta is about to discard.
        let stable_entities: Vec<Entity> = indexed
            .entities
            .iter()
            .filter_map(|entity| {
                let id = stable_entity_ids.get(&entity.id).copied()?;
                let mut stable = entity.clone();
                stable.id = id;
                Some(stable)
            })
            .collect();
        // A graph that gained files through a path that does not run reconcile
        // (`kin init` over an existing git history) leaves the universe behind.
        // A file the graph already has entities for that the linker never heard
        // of is the tell, and it re-indexes once.
        if !existing.is_empty() {
            self.cross_file.refresh_if_behind(graph, &file_id.0);
        }
        let cross_file = self.cross_file.resolve_after_edit(
            graph,
            &file_id.0,
            &stable_entities,
            &indexed.extracted_relations,
            &indexed.imports,
            kin_model::ParseCompleteness::from_parse_state(&indexed.parse_state),
        );

        // Collect existing relations for all entities in this file.
        type RelationKey = (GraphNodeId, GraphNodeId, RelationKind);
        let mut existing_relations: HashMap<RelationKey, Vec<Relation>> = HashMap::new();
        for entity in &existing {
            let relations = graph
                .get_all_relations_for_entity(&entity.id)
                .map_err(|error| ReconcileError::Graph(error.to_string()))?;
            for relation in relations {
                let bucket = existing_relations
                    .entry((relation.src, relation.dst, relation.kind))
                    .or_default();
                if !bucket.iter().any(|existing| existing.id == relation.id) {
                    bucket.push(relation);
                }
            }
        }
        for relations in existing_relations.values_mut() {
            relations.sort_by_key(|relation| relation.id);
        }

        // Build set of newly parsed relations keyed by (src, dst, kind).
        let mut new_relation_keys: HashSet<RelationKey> = HashSet::new();
        let mut matched_relation_ids = HashSet::new();
        // Every relation identity this delta already names, whatever it says
        // about it. kin-db allows one delta per relation and refuses the whole
        // transition otherwise, so the invariant is enforced here, once, at the
        // producer.
        let mut spoken_for: HashSet<RelationId> = HashSet::new();
        // Memoized per-node reads of what the graph holds, shared by the
        // identity check below and the removal collection further down.
        let mut held_relations: HashMap<GraphNodeId, HashMap<RelationId, Relation>> =
            HashMap::new();
        for relation in &indexed.relations {
            // Remap src/dst to stable IDs if they were matched to existing entities.
            let stable_src = relation
                .src
                .as_entity()
                .and_then(|id| stable_entity_ids.get(&id).copied())
                .map(GraphNodeId::Entity)
                .unwrap_or(relation.src);
            let stable_dst = relation
                .dst
                .as_entity()
                .and_then(|id| stable_entity_ids.get(&id).copied())
                .map(GraphNodeId::Entity)
                .unwrap_or(relation.dst);

            let key = (stable_src, stable_dst, relation.kind);
            if !new_relation_keys.insert(key) {
                return Err(ReconcileError::InvalidTransaction(format!(
                    "parser emitted duplicate {:?} relation from {} to {}",
                    relation.kind, stable_src, stable_dst
                )));
            }
            let mut stable_relation = relation.clone();
            stable_relation.src = stable_src;
            stable_relation.dst = stable_dst;

            if let Some(old) = parser_identity_to_keep(existing_relations.get(&key)) {
                matched_relation_ids.insert(old.id);
                spoken_for.insert(old.id);
                stable_relation.id = old.id;
                stable_relation.created_in = old.created_in;
                if stable_relation != *old {
                    delta.relation_deltas.push(RelationDelta::Modified {
                        old: old.clone(),
                        new: stable_relation,
                    });
                }
            } else {
                push_relation_addition(
                    graph,
                    &mut held_relations,
                    &mut delta,
                    &mut spoken_for,
                    stable_relation,
                )?;
            }
        }

        // Relations the incremental linker resolved, for this file and for any
        // file it just unblocked. Same identity and matching rules as the
        // parsed set above, with one difference: a key the parsed set already
        // carries is skipped rather than rejected, because a relation reaching
        // both resolvers is agreement rather than a parser fault.
        //
        // Both buckets are folded, the edges that leave the file and the ones
        // that stay inside it. The same-file half used to be dropped by the
        // linker pass on the ground that the pipeline's own per-file resolution
        // already carried it, and for `Calls` it does. It does not for
        // `Overrides`: `kin_index::linker` is the only producer of that kind,
        // and its base-class walk resolves a same-file base first, so a class
        // overriding a base declared beside it yields an edge this pass alone
        // can re-derive. Dropping it left the retire loop below looking at a
        // parser-derived edge with both endpoints in the file that this pass
        // had not produced, which is the `parser_authoritative` condition
        // exactly, so a comment-only edit deleted it and `find_references` lost
        // the caller it composed through that override (FIR-2644).
        //
        // Every endpoint is checked against graph truth first. The linker's
        // universe is in-memory and the graph is the authority, and the two can
        // drift: a caller that fails to apply a delta keeps its reconciler, so
        // the universe would hold entities the graph never admitted. Minting an
        // edge into one of those is not a wrong edge, it is a transaction the
        // store rejects outright, which would take the whole reconcile of an
        // unrelated file down with it. An endpoint this delta itself adds
        // counts as admitted; anything else must already be in the graph.
        //
        // An entity THIS delta removes is not admitted either, and that is the
        // half the graph-truth read cannot answer: it is still in the store
        // while the same transaction retires it, so `get_entity` says yes.
        //
        // Said plainly, because the comment above would otherwise claim more
        // than the line delivers: no input reaches this arm today. The
        // endpoints it judges come from the linker's universe, and
        // `install_file` replaced this file's entities there before the pass
        // resolved anything, so an entity this delta removes is already absent
        // from the set the linker could resolve to. Deleting the arm turned no
        // test red in the FIR-2838 falsification grid and that is recorded
        // rather than papered over. It stays as a precondition on a closure
        // whose whole job is deciding what may be an endpoint, not as a fix.
        let admits_entity = |id: EntityId| -> bool {
            if removed_entity_ids.contains(&id) {
                return false;
            }
            stable_entity_ids.values().any(|stable| *stable == id)
                || matches!(graph.get_entity(&id), Ok(Some(_)))
        };
        for relation in cross_file
            .resolved
            .iter()
            .chain(cross_file.same_file.iter())
        {
            let endpoints_admitted =
                [relation.src, relation.dst]
                    .into_iter()
                    .all(|node| match node {
                        GraphNodeId::Entity(id) => admits_entity(id),
                        _ => false,
                    });
            if !endpoints_admitted {
                debug!(
                    src = %relation.src,
                    dst = %relation.dst,
                    kind = ?relation.kind,
                    "cross-file edge skipped: an endpoint is not admitted graph truth"
                );
                continue;
            }
            let key = (relation.src, relation.dst, relation.kind);
            if !new_relation_keys.insert(key) {
                continue;
            }
            let mut linked = relation.clone();
            if let Some(old) = parser_identity_to_keep(existing_relations.get(&key)) {
                matched_relation_ids.insert(old.id);
                spoken_for.insert(old.id);
                linked.id = old.id;
                linked.created_in = old.created_in;
                if linked != *old {
                    delta.relation_deltas.push(RelationDelta::Modified {
                        old: old.clone(),
                        new: linked,
                    });
                }
            } else {
                push_relation_addition(
                    graph,
                    &mut held_relations,
                    &mut delta,
                    &mut spoken_for,
                    linked,
                )?;
            }
        }

        // Remove stale relations that no longer exist in the file.
        // Only remove a relation when this reconcile pass could have re-derived it.
        // Three cases now qualify, and each covers a distinct failure the others do
        // not:
        //   1. `parser_authoritative`. Parser-derived, both endpoints inside this
        //      file, and the key is absent from what this pass produced. The
        //      intra-file case: deleting a call between two functions in one file
        //      retires its edge.
        //   2. `duplicate_parser_relation`. Parser-derived, sourced by an entity of
        //      this file, and this pass DID produce that key. Retires the surplus
        //      copies so one logical edge keeps one parser identity after a
        //      resolver or id-derivation change. The destination may be outside
        //      the file: the authority is that this pass read this file and
        //      re-derived that exact edge from it.
        //   3. `cross_file_source_authoritative`. Parser-derived, sourced by an
        //      entity of this file, destination outside it, the cross-file pass ran,
        //      and this file's freshly parsed text no longer names that destination
        //      under any spelling. The case this file's edges could not reach before,
        //      and the one that keeps a deleted cross-file call site from leaving a
        //      permanent edge. It deliberately does NOT fire merely because the pass
        //      failed to re-derive the edge: an init-time batch-linked edge resolved
        //      at a tier the incremental universe cannot reach is still named by the
        //      source, so it survives. Nor does it fire on a recovered parse, where
        //      an absent name proves nothing.
        // Everything else is preserved: LSP-enrichment edges, agent-created Manual
        // edges, and any edge this file merely receives rather than sources.
        let mut retired_relation_ids: HashSet<RelationId> = HashSet::new();
        for ((src, dst, kind), relations) in &existing_relations {
            for relation in relations {
                if matched_relation_ids.contains(&relation.id) {
                    continue;
                }
                let touches_removed_entity = [relation.src, relation.dst]
                    .into_iter()
                    .filter_map(|node| node.as_entity())
                    .any(|entity_id| removed_entity_ids.contains(&entity_id));
                let both_in_file =
                    file_entity_node_ids.contains(src) && file_entity_node_ids.contains(dst);
                let parser_derived = is_parser_derived(relation);
                let parser_authoritative = parser_derived
                    && both_in_file
                    && !new_relation_keys.contains(&(*src, *dst, *kind));
                // A surplus parser copy of a key this pass just re-derived from
                // this file's own text, whether or not the destination is in
                // this file. Scoped to `src` rather than to both endpoints
                // because that is the half the authority rests on: the pass
                // read this file and produced that edge, so a second
                // parser-derived copy of it is an identity left behind by an
                // earlier resolver, not a second fact. Requiring the
                // destination to be in the file too is what let a cross-file
                // copy survive a re-anchor and report its pre-edit line beside
                // the current one (FIR-2644). Enrichment and Manual edges are
                // not parser-derived and are never collected here.
                let duplicate_parser_relation = parser_derived
                    && file_entity_node_ids.contains(src)
                    && new_relation_keys.contains(&(*src, *dst, *kind));
                let cross_file_source_authoritative = parser_derived
                    && !both_in_file
                    && cross_file.ran
                    && file_entity_node_ids.contains(src)
                    && !new_relation_keys.contains(&(*src, *dst, *kind))
                    && dst
                        .as_entity()
                        .and_then(|id| graph.get_entity(&id).ok().flatten())
                        .is_some_and(|entity| {
                            cross_file.referenced.can_retire(*kind, &entity.name)
                        });
                if touches_removed_entity
                    || parser_authoritative
                    || duplicate_parser_relation
                    || cross_file_source_authoritative
                {
                    retired_relation_ids.insert(relation.id);
                    spoken_for.insert(relation.id);
                    delta.relation_deltas.push(RelationDelta::Removed {
                        old: relation.clone(),
                    });
                    debug!(
                        relation_id = %relation.id,
                        src = %src,
                        dst = %dst,
                        "stale relation removed"
                    );
                }
            }
        }

        // A removal collects the edges that name it, all of them.
        //
        // The loop above walks `existing_relations`, which is gathered through
        // `get_all_relations_for_entity` and therefore holds entity-to-entity
        // edges only. An edge with one non-entity endpoint is invisible to it,
        // so a departing entity could leave one standing; kin-db then refuses
        // EVERY later transition on that store with `transaction relation <id>
        // has unadmitted destination endpoint entity:<id>`, which wedges the
        // whole repository for writes until the daemon restarts and the store
        // is rebuilt without the strand. kin's own error text calls that out:
        // "a removal is supposed to collect these edges itself" (FIR-2838).
        //
        // Reading each departing entity's node directly is what makes the
        // transition self-contained. Redirecting an incoming edge onto a
        // renamed successor is deliberately NOT done here: this pass holds no
        // evidence about the source file's current text, the source file's own
        // reconcile re-derives the edge against the new entity, and the
        // cross-file linker's waiting index exists to bind it the moment the
        // new name arrives. Dropping the edge with the entity it names is the
        // honest transition; inventing one is not.
        for entity_id in &removed_entity_ids {
            let node = GraphNodeId::Entity(*entity_id);
            let stranded: Vec<Relation> = relations_held_at(graph, &mut held_relations, node)?
                .values()
                .filter(|relation| !spoken_for.contains(&relation.id))
                .cloned()
                .collect();
            for relation in stranded {
                retired_relation_ids.insert(relation.id);
                spoken_for.insert(relation.id);
                debug!(
                    relation_id = %relation.id,
                    src = %relation.src,
                    dst = %relation.dst,
                    kind = ?relation.kind,
                    entity = %entity_id,
                    "collecting an edge bound to a departing entity so the transition strands none"
                );
                delta
                    .relation_deltas
                    .push(RelationDelta::Removed { old: relation });
            }
        }

        // Re-anchor what this pass preserved.
        //
        // Everything above either re-derives an edge, which replaces its
        // evidence outright, or retires it. What is left is the class the
        // reconcile path deliberately never rebuilds: language-server
        // enrichment, agent-created Manual edges, and anything else a resolver
        // outside this pass minted. Those keep the span they were recorded at,
        // and `find_references` publishes that span as a reference line, so
        // after a line-shifting edit the answer named a line the call had left.
        // Placing them through the declaration that contains them is the whole
        // of re-anchoring for this class; a span that cannot be placed is
        // cleared rather than carried, because an absent line and a wrong line
        // are different answers and only one of them is honest (FIR-2644).
        if !entity_span_moves.is_empty() {
            for relations in existing_relations.values() {
                for relation in relations {
                    if spoken_for.contains(&relation.id) {
                        continue;
                    }
                    let Some(placed) =
                        relation_with_reanchored_evidence(relation, file_id, &entity_span_moves)
                    else {
                        continue;
                    };
                    debug!(
                        relation_id = %relation.id,
                        kind = ?relation.kind,
                        "preserved relation re-anchored to the declaration that moved"
                    );
                    spoken_for.insert(relation.id);
                    delta.relation_deltas.push(RelationDelta::Modified {
                        old: relation.clone(),
                        new: placed,
                    });
                }
            }
        }

        // Artifact-level import and include edges. These never reach
        // `existing_relations`, because that set is gathered per entity and an
        // artifact edge has no entity endpoint, so the loop above cannot see
        // them at all. Reconcile them against graph truth: the pass re-derived
        // the complete import set of every file it resolved, from those files'
        // own declarations.
        // `spoken_for` already names every identity the deltas above claimed,
        // which is what this loop used to rebuild for itself out of
        // `delta.relation_deltas`. One set, so the artifact half and the entity
        // half cannot disagree about what has been claimed.
        if cross_file.ran {
            let produced_by_id: HashMap<RelationId, &Relation> = cross_file
                .artifact_imports
                .iter()
                .map(|relation| (relation.id, relation))
                .collect();
            let mut stored_ids: HashSet<RelationId> = HashSet::new();

            for artifact_id in &cross_file.source_artifacts {
                let node = GraphNodeId::Artifact(*artifact_id);
                let stored = graph
                    .traverse(&node, &[RelationKind::Imports, RelationKind::Includes], 1)
                    .map(|sub| sub.relations)
                    .unwrap_or_default();
                for relation in stored {
                    if relation.src != node {
                        continue;
                    }
                    if !stored_ids.insert(relation.id) {
                        continue;
                    }
                    match produced_by_id.get(&relation.id) {
                        Some(current) if **current == relation => {}
                        Some(current) => {
                            if spoken_for.insert(relation.id) {
                                delta.relation_deltas.push(RelationDelta::Modified {
                                    old: relation.clone(),
                                    new: (*current).clone(),
                                });
                            }
                        }
                        None => {
                            // Retire only what this pass could have re-derived:
                            // a complete parse, and a destination the linker
                            // knows. A destination it has never heard of is one
                            // module resolution could not have reached, so the
                            // edge's absence here says nothing about the source.
                            let destination_known = match relation.dst {
                                GraphNodeId::Artifact(id) => self.cross_file.knows_artifact(&id),
                                _ => false,
                            };
                            if cross_file.referenced.is_complete()
                                && destination_known
                                && spoken_for.insert(relation.id)
                            {
                                delta.relation_deltas.push(RelationDelta::Removed {
                                    old: relation.clone(),
                                });
                                debug!(
                                    relation_id = %relation.id,
                                    kind = ?relation.kind,
                                    "artifact import edge retired: the source no longer declares it"
                                );
                            }
                        }
                    }
                }
            }

            for relation in &cross_file.artifact_imports {
                if stored_ids.contains(&relation.id) {
                    continue;
                }
                let endpoints_admitted =
                    [relation.src, relation.dst]
                        .into_iter()
                        .all(|node| match node {
                            GraphNodeId::Artifact(id) => {
                                self.cross_file
                                    .path_of_artifact(&id)
                                    .and_then(|path| kin_model::RepoPath::from_utf8(path).ok())
                                    .and_then(|path| graph.artifact_id_at_path(&path))
                                    == Some(id)
                            }
                            _ => false,
                        });
                if !endpoints_admitted {
                    continue;
                }
                push_relation_addition(
                    graph,
                    &mut held_relations,
                    &mut delta,
                    &mut spoken_for,
                    relation.clone(),
                )?;
            }
        }

        let added_count = added.len();
        let modified_count = modified.len();
        let removed_count = removed.len();
        let warning_count = collision_warnings.len();
        let result = ReconcileResult::validated(
            ReconcileOutcome::Updated {
                file_id: file_id.clone(),
                added,
                modified,
                removed,
                collision_warnings,
            },
            delta,
        )?;

        // Register file layout in projection state so project_transaction_to_files
        // can splice mutations back into the file.
        //
        // RACE CONDITION HARDENING: Read from blob store (keyed by the hash
        // computed during indexing) instead of re-reading from disk. This
        // eliminates a TOCTOU race where the file could be modified between
        // the initial parse (which produced the entities/spans) and this
        // layout registration. The blob content is known to match the
        // byte ranges in entity spans.
        let file_content = blob_store.read(&indexed.blob_hash)?;
        let mut layout = indexed.file_layout.clone();
        layout.file_id = file_id.clone();
        for region in &mut layout.regions {
            if let SourceRegion::EntityRef { entity_id, .. } = region {
                if let Some(stable_id) = stable_entity_ids.get(entity_id) {
                    *entity_id = *stable_id;
                }
            }
        }
        self.projection.register_file(layout, file_content);

        // Git shadow maintenance: only when policy enables it.
        if self.policy.git_shadow {
            debug!(
                file = %path.display(),
                "git shadow enabled: marking file for shadow commit tracking"
            );
        }

        info!(
            file = %path.display(),
            added = added_count,
            modified = modified_count,
            removed = removed_count,
            warnings = warning_count,
            git_shadow = self.policy.git_shadow,
            "reconciled file edit"
        );

        Ok(result)
    }

    /// Reconcile a file removal.
    fn reconcile_file_removal<G: GraphStore>(
        &mut self,
        path: &Path,
        graph: &G,
    ) -> Result<ReconcileResult> {
        let file_id = self.file_path_id(path);
        let existing = self.get_file_entities(graph, &file_id)?;

        // Build scopes for collision checking
        let mut affected_scopes: Vec<IntentScope> =
            existing.iter().map(|e| IntentScope::Entity(e.id)).collect();
        affected_scopes.push(IntentScope::Artifact(file_id.clone()));

        // Check for collisions before applying mutations
        let collision_warnings = self.check_scopes(&affected_scopes)?;

        let mut removed = Vec::new();
        let mut relations = HashMap::new();

        // Drop the file from the cross-file universe and the waiting index
        // before deriving the removal, so a later file defining one of its
        // names does not try to re-bind a file that no longer exists.
        self.cross_file.forget_file(&file_id.0);

        for entity in &existing {
            for relation in graph
                .get_all_relations_for_entity(&entity.id)
                .map_err(|error| ReconcileError::Graph(error.to_string()))?
            {
                relations.insert(relation.id, relation);
            }
            self.lkg.remove(&entity.id);
            removed.push(entity.id);
        }
        let delta = TransactionDelta {
            entity_deltas: existing
                .into_iter()
                .map(|old| EntityDelta::Removed { old })
                .collect(),
            relation_deltas: relations
                .into_values()
                .map(|old| RelationDelta::Removed { old })
                .collect(),
            ..TransactionDelta::default()
        };
        let removed_count = removed.len();
        let warning_count = collision_warnings.len();
        let result = ReconcileResult::validated(
            ReconcileOutcome::FileRemoved {
                file_id: file_id.clone(),
                removed,
                collision_warnings,
            },
            delta,
        )?;
        self.projection.remove_file(&file_id);

        info!(
            file = %path.display(),
            removed = removed_count,
            warnings = warning_count,
            "reconciled file removal"
        );

        Ok(result)
    }

    // ---------------------------------------------------------------
    // Direction 2: Transaction -> File
    // ---------------------------------------------------------------

    /// Project exact transaction mutations to files.
    ///
    /// `entity_bodies` is projection payload, not graph authority. Every key
    /// must name an entity modified by `delta`; an unbound body fails loud.
    /// Metadata-only modifications may omit a body and reuse the cached exact
    /// span bytes.
    pub fn project_transaction_to_files(
        &mut self,
        delta: &TransactionDelta,
        entity_bodies: &HashMap<EntityId, Vec<u8>>,
    ) -> Result<(Vec<FilePathId>, Vec<IntentSummary>)> {
        kin_model::validate_transaction_delta(delta)
            .map_err(|error| ReconcileError::InvalidTransaction(error.to_string()))?;

        let modified_entities: HashMap<EntityId, &Entity> = delta
            .entity_deltas
            .iter()
            .filter_map(|entity_delta| match entity_delta {
                EntityDelta::Modified { new, .. } => Some((new.id, new)),
                EntityDelta::Added { .. } | EntityDelta::Removed { .. } => None,
            })
            .collect();

        if let Some(unbound) = entity_bodies
            .keys()
            .find(|entity_id| !modified_entities.contains_key(entity_id))
        {
            return Err(ReconcileError::InvalidTransaction(format!(
                "projection body for entity {unbound} has no matching modification"
            )));
        }

        if modified_entities.is_empty() {
            return Ok((vec![], vec![]));
        }

        // Check for collisions BEFORE body extraction — fail fast if blocked.
        let affected_scopes: Vec<IntentScope> = modified_entities
            .keys()
            .map(|id| IntentScope::Entity(*id))
            .collect();
        let collision_warnings = self.check_scopes(&affected_scopes)?;

        // Collect entity body text for modified entities.
        // The entity MUST have a source span pointing to the working-dir file.
        // Body extraction failure is a hard error — silently using the signature
        // would produce wrong data in the projected file.
        //
        // RACE CONDITION HARDENING: Prefer the projection state's cached content
        // (registered during the reconcile that produced these entity spans) over
        // re-reading from disk. The cached content is known to match the
        // byte ranges in entity spans. A disk read could see a newer version of
        // the file (written by a concurrent editor), causing span misalignment
        // and corrupt body extraction.
        let mut mutations: HashMap<EntityId, Vec<u8>> = HashMap::new();
        for (id, entity) in modified_entities {
            // Prefer an explicitly supplied entity body. This turns a graph
            // mutation into a real file edit. Fall back to exact span extraction
            // only for metadata-only modifications.
            let body = if let Some(supplied) = entity_bodies.get(&id) {
                supplied.clone()
            } else if let Some(ref span) = entity.span {
                // Membership first. Reading a path this projection did not
                // register would make the working copy an answer authority for
                // graph misses, which is the one thing this boundary must never
                // become. kin-vfs holds the identical line at its own staging
                // boundary (`KinWriter::read_staged`) in the same words, and the
                // two are one policy rather than two decisions that happen to
                // agree.
                //
                // The registered bytes are also the only ones these spans are
                // valid against: they were cached by the reconcile that produced
                // the spans, so a working-copy read could return a newer file
                // written by a concurrent editor and splice at misaligned
                // offsets. Refusing therefore costs nothing that was correct.
                let Some(contents) = self.projection.get_content(&span.file).map(<[u8]>::to_vec)
                else {
                    return Err(ReconcileError::BodyExtractionFailed {
                        entity_id: id,
                        reason: format!(
                            "no registered projection content for {}; graph-derived state missed \
                             and the working copy is not an answer authority",
                            span.file
                        ),
                    });
                };
                let start = span.start_byte;
                let end = span.end_byte;
                if end <= contents.len() && start < end {
                    contents[start..end].to_vec()
                } else {
                    return Err(ReconcileError::BodyExtractionFailed {
                        entity_id: id,
                        reason: format!(
                            "span {}..{} out of bounds for {} ({} bytes)",
                            start,
                            end,
                            span.file,
                            contents.len()
                        ),
                    });
                }
            } else {
                return Err(ReconcileError::BodyExtractionFailed {
                    entity_id: id,
                    reason: "entity has no source span".to_string(),
                });
            };
            mutations.insert(id, body);
        }

        let modified = project_entity_mutations_with_policy(
            &mut self.projection,
            &mutations,
            &self.working_dir,
            self.policy.formatting_policy,
            self.policy.projection_mode,
        )?;

        info!(
            files = modified.len(),
            warnings = collision_warnings.len(),
            "projected transaction mutations to working directory"
        );

        Ok((modified, collision_warnings))
    }

    // ---------------------------------------------------------------
    // Conflict detection
    // ---------------------------------------------------------------

    /// Detect conflicts between desired graph state and filesystem input.
    ///
    /// Called when both directions have pending changes for the same
    /// entity (e.g., human edits a file while an assistant commits a graph
    /// transaction).
    pub fn detect_conflict(
        &self,
        entity_id: &EntityId,
        desired_entity: &Entity,
        file_entity: &Entity,
    ) -> Option<ConflictObject> {
        // If both sides changed the entity differently, emit a conflict
        if desired_entity.fingerprint.ast_hash != file_entity.fingerprint.ast_hash {
            Some(ConflictObject {
                id: ConflictId::new(),
                kind: ConflictKind::StructuralCollision,
                desired_state: format!(
                    "Graph: {} (sig: {})",
                    desired_entity.name, desired_entity.signature
                ),
                current_state: format!(
                    "File: {} (sig: {})",
                    file_entity.name, file_entity.signature
                ),
                divergence_reason: "Entity modified in both graph transaction and filesystem input"
                    .to_string(),
                affected_entities: vec![*entity_id],
                affected_files: file_entity.file_origin.iter().cloned().collect(),
                suggested_resolutions: vec![
                    "Accept graph version".to_string(),
                    "Accept file version".to_string(),
                    "Manual merge required".to_string(),
                ],
                requires_human_review: true,
            })
        } else {
            None
        }
    }

    // ---------------------------------------------------------------
    // Merge analysis
    // ---------------------------------------------------------------

    /// Analyze a merge between two sets of entities (ours vs theirs).
    ///
    /// Both sides are presented as entity slices. Entities are matched by
    /// ID. Returns a `MergePreview` describing what would happen if the
    /// merge were applied.
    ///
    /// This method does NOT apply any changes — it is the dry-run engine.
    pub fn analyze_merge(ours: &[Entity], theirs: &[Entity]) -> MergePreview {
        let our_map: HashMap<EntityId, &Entity> = ours.iter().map(|e| (e.id, e)).collect();
        let their_map: HashMap<EntityId, &Entity> = theirs.iter().map(|e| (e.id, e)).collect();

        let mut conflicts = Vec::new();
        let mut added = Vec::new();
        let mut auto_resolved = Vec::new();

        // Check their entities against ours.
        for (id, their_entity) in &their_map {
            if let Some(our_entity) = our_map.get(id) {
                // Same entity ID exists on both sides — check for conflict.
                if our_entity.fingerprint.ast_hash != their_entity.fingerprint.ast_hash {
                    // Divergent modification.
                    let mut entity_conflicts = vec![MergeConflict {
                        entity_id: *id,
                        entity_name: their_entity.name.clone(),
                        file_origin: their_entity.file_origin.clone(),
                        kind: MergeConflictKind::Divergent,
                    }];

                    // Also check for signature and visibility changes.
                    if let Some(sig_conflict) = check_signature_change(our_entity, their_entity) {
                        entity_conflicts.push(MergeConflict {
                            entity_id: *id,
                            entity_name: their_entity.name.clone(),
                            file_origin: their_entity.file_origin.clone(),
                            kind: sig_conflict,
                        });
                    }
                    if let Some(vis_conflict) = check_visibility_change(our_entity, their_entity) {
                        entity_conflicts.push(MergeConflict {
                            entity_id: *id,
                            entity_name: their_entity.name.clone(),
                            file_origin: their_entity.file_origin.clone(),
                            kind: vis_conflict,
                        });
                    }
                    conflicts.extend(entity_conflicts);
                } else {
                    // Same fingerprint — convergent, auto-resolvable.
                    auto_resolved.push(*id);
                }
            } else {
                // Entity only in theirs — it's an addition.
                added.push(*id);
            }
        }

        // Check for name collisions: different entity IDs but same name+kind.
        // This is important for unrelated-history merges.
        let our_name_map: HashMap<(&str, EntityKind), EntityId> = ours
            .iter()
            .map(|e| ((e.name.as_str(), e.kind), e.id))
            .collect();

        for their_entity in theirs {
            let key = (their_entity.name.as_str(), their_entity.kind);
            if let Some(&our_id) = our_name_map.get(&key) {
                // Same name+kind but different ID — possible in unrelated history.
                if our_id != their_entity.id
                    && !conflicts.iter().any(|c| c.entity_id == their_entity.id)
                {
                    conflicts.push(MergeConflict {
                        entity_id: their_entity.id,
                        entity_name: their_entity.name.clone(),
                        file_origin: their_entity.file_origin.clone(),
                        kind: MergeConflictKind::AddAdd,
                    });
                }
            }
        }

        // Entities only in ours are kept as-is (no action needed).
        let kept: Vec<EntityId> = our_map
            .keys()
            .filter(|id| !their_map.contains_key(id))
            .copied()
            .collect();

        MergePreview {
            conflicts,
            added,
            auto_resolved,
            kept,
            files_affected: collect_affected_files(ours, theirs),
        }
    }

    /// Analyze an unrelated-history merge.
    ///
    /// When two branches share no common ancestor, all entities from both
    /// sides are treated as "added" relative to an empty baseline.
    /// Name collisions between the two sides are reported as conflicts.
    pub fn analyze_unrelated_merge(ours: &[Entity], theirs: &[Entity]) -> MergePreview {
        // For unrelated merges, all of "theirs" are additions, but we
        // check for name+kind collisions against "ours".
        let our_name_map: HashMap<(&str, EntityKind), &Entity> = ours
            .iter()
            .map(|e| ((e.name.as_str(), e.kind), e))
            .collect();

        let mut conflicts = Vec::new();
        let mut added = Vec::new();

        for their_entity in theirs {
            let key = (their_entity.name.as_str(), their_entity.kind);
            if let Some(our_entity) = our_name_map.get(&key) {
                // Name collision — check if it's the same content.
                if our_entity.fingerprint.ast_hash == their_entity.fingerprint.ast_hash {
                    // Identical content, auto-resolve by keeping ours.
                    // (No action needed — entity already exists.)
                } else {
                    conflicts.push(MergeConflict {
                        entity_id: their_entity.id,
                        entity_name: their_entity.name.clone(),
                        file_origin: their_entity.file_origin.clone(),
                        kind: MergeConflictKind::AddAdd,
                    });

                    // Also check for visibility changes on name-colliding entities.
                    if let Some(vis) = check_visibility_change(our_entity, their_entity) {
                        conflicts.push(MergeConflict {
                            entity_id: their_entity.id,
                            entity_name: their_entity.name.clone(),
                            file_origin: their_entity.file_origin.clone(),
                            kind: vis,
                        });
                    }
                }
            } else {
                // No collision — clean addition.
                added.push(their_entity.id);
            }
        }

        let kept: Vec<EntityId> = ours.iter().map(|e| e.id).collect();

        MergePreview {
            conflicts,
            added,
            auto_resolved: vec![],
            kept,
            files_affected: collect_affected_files(ours, theirs),
        }
    }

    // ---------------------------------------------------------------
    // 3-Way Semantic Merge via LCA
    // ---------------------------------------------------------------

    /// Perform a 3-way merge using the Lowest Common Ancestor (LCA) base state.
    ///
    /// Given:
    /// - `base`: the entity snapshot at the LCA (last common ancestor)
    /// - `ours`: our current entity state
    /// - `theirs`: the remote/incoming entity state
    ///
    /// Computes semantic deltas from `base` for each side, then merges:
    /// - Non-overlapping changes auto-merge (apply both)
    /// - Same entity modified differently on both sides → semantic conflict
    /// - Entity modified on one side, deleted on the other → ModifyDelete HardCollision
    ///
    /// Falls back to 2-way merge (`analyze_merge`) when no `base` is provided.
    pub fn analyze_merge_3way(base: &[Entity], ours: &[Entity], theirs: &[Entity]) -> MergePreview {
        let base_map: HashMap<EntityId, &Entity> = base.iter().map(|e| (e.id, e)).collect();
        let our_map: HashMap<EntityId, &Entity> = ours.iter().map(|e| (e.id, e)).collect();
        let their_map: HashMap<EntityId, &Entity> = theirs.iter().map(|e| (e.id, e)).collect();

        // Compute deltas from base for each side.
        let local_deltas = compute_semantic_deltas(&base_map, &our_map);
        let remote_deltas = compute_semantic_deltas(&base_map, &their_map);

        merge_deltas(
            &local_deltas,
            &remote_deltas,
            &base_map,
            &our_map,
            &their_map,
            ours,
            theirs,
        )
    }

    /// Find the LCA (Lowest Common Ancestor) of two change IDs in the change DAG.
    ///
    /// Walks the parent chains of both changes to find the most recent common
    /// ancestor. If no LCA exists (unrelated histories), returns `None`.
    ///
    /// The caller should use the entity snapshot at the LCA as the `base` for
    /// `analyze_merge_3way`. If `None`, fall back to `analyze_merge` (2-way).
    pub fn find_lca(
        local_head: &kin_model::SemanticChangeId,
        remote_head: &kin_model::SemanticChangeId,
        get_parents: &dyn Fn(&kin_model::SemanticChangeId) -> Vec<kin_model::SemanticChangeId>,
    ) -> Option<kin_model::SemanticChangeId> {
        if local_head == remote_head {
            return Some(*local_head);
        }

        // BFS from both heads simultaneously. First ID found in both visited sets is the LCA.
        let mut local_visited: HashSet<kin_model::SemanticChangeId> = HashSet::new();
        let mut remote_visited: HashSet<kin_model::SemanticChangeId> = HashSet::new();

        let mut local_frontier = vec![*local_head];
        let mut remote_frontier = vec![*remote_head];

        local_visited.insert(*local_head);
        remote_visited.insert(*remote_head);

        // Alternating BFS to find LCA efficiently.
        while !local_frontier.is_empty() || !remote_frontier.is_empty() {
            // Expand local frontier one level.
            if !local_frontier.is_empty() {
                let mut next_local = Vec::new();
                for id in &local_frontier {
                    // Check if remote has already visited this node.
                    if remote_visited.contains(id) {
                        return Some(*id);
                    }
                    for parent in get_parents(id) {
                        if local_visited.insert(parent) {
                            // Also check immediately.
                            if remote_visited.contains(&parent) {
                                return Some(parent);
                            }
                            next_local.push(parent);
                        }
                    }
                }
                local_frontier = next_local;
            }

            // Expand remote frontier one level.
            if !remote_frontier.is_empty() {
                let mut next_remote = Vec::new();
                for id in &remote_frontier {
                    if local_visited.contains(id) {
                        return Some(*id);
                    }
                    for parent in get_parents(id) {
                        if remote_visited.insert(parent) {
                            if local_visited.contains(&parent) {
                                return Some(parent);
                            }
                            next_remote.push(parent);
                        }
                    }
                }
                remote_frontier = next_remote;
            }
        }

        None // No common ancestor — unrelated histories.
    }

    // ---------------------------------------------------------------
    // Collision checking
    // ---------------------------------------------------------------

    /// Check collisions for a set of scopes. Returns Ok(warnings) if the
    /// mutation can proceed, or Err if blocked by a hard collision.
    ///
    /// If no traffic checker is configured, always returns Ok(empty warnings).
    fn check_scopes(&self, scopes: &[IntentScope]) -> Result<Vec<IntentSummary>> {
        let checker = match &self.traffic_checker {
            Some(c) => c,
            None => return Ok(vec![]),
        };
        let session = self.session_id.as_ref();

        let mut all_warnings = Vec::new();
        for scope in scopes {
            match checker.check_collisions(scope, session) {
                Ok(CollisionCheck::Clear) => {}
                Ok(CollisionCheck::Warnings(warnings)) => {
                    all_warnings.extend(warnings);
                }
                Ok(CollisionCheck::Blocked {
                    conflict: _,
                    blocking_intents,
                }) => {
                    return Err(ReconcileError::CollisionBlocked {
                        reason: format!(
                            "Hard collision on scope {:?}: {} blocking intent(s)",
                            scope,
                            blocking_intents.len()
                        ),
                        blocking_intents,
                    });
                }
                Err(e) => {
                    return Err(ReconcileError::TrafficCheck(e));
                }
            }
        }
        Ok(all_warnings)
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /// Construct a `FilePathId` from a filesystem path.
    ///
    /// Strips the working directory prefix and normalizes to forward slashes
    /// so that the edit and removal paths produce identical identifiers for
    /// the same file regardless of absolute vs relative input.
    fn file_path_id(&self, path: &Path) -> FilePathId {
        kin_index::normalize_file_path_id(path, &self.working_dir)
    }

    /// Get all entities for a file from graph authority.
    fn get_file_entities<G: GraphStore>(
        &self,
        graph: &G,
        file_id: &FilePathId,
    ) -> Result<Vec<Entity>> {
        use kin_model::EntityFilter;

        let filter = EntityFilter {
            file_path: Some(file_id.clone()),
            ..Default::default()
        };

        graph
            .query_entities(&filter)
            .map_err(|e| ReconcileError::Graph(e.to_string()))
    }
}

/// Result of merge analysis — a preview of what a merge would produce.
///
/// This is the output of `Reconciler::analyze_merge` and
/// `Reconciler::analyze_unrelated_merge`. It describes the merge outcome
/// without actually applying any changes.
#[derive(Debug, Clone)]
pub struct MergePreview {
    /// Conflicts that require resolution.
    pub conflicts: Vec<MergeConflict>,
    /// Entity IDs that would be added from the source branch.
    pub added: Vec<EntityId>,
    /// Entity IDs with convergent changes (auto-resolved).
    pub auto_resolved: Vec<EntityId>,
    /// Entity IDs kept from the target branch (unchanged).
    pub kept: Vec<EntityId>,
    /// Files that would be affected by the merge.
    pub files_affected: Vec<FilePathId>,
}

impl MergePreview {
    /// Whether the merge can proceed without manual intervention.
    pub fn is_clean(&self) -> bool {
        self.conflicts.is_empty()
    }

    /// Number of non-convergent conflicts requiring manual resolution.
    pub fn manual_conflict_count(&self) -> usize {
        self.conflicts
            .iter()
            .filter(|c| !matches!(c.kind, MergeConflictKind::Convergent))
            .count()
    }
}

/// Validate an entity for semantic correctness.
///
/// Returns `Some(reason)` if the entity is malformed, `None` if valid.
///
/// An empty signature is malformed for a declaration this repository parsed, and
/// correct for an external reference target: that target stands for a symbol
/// another repository owns, so no signature was ever observed and none can be.
/// Today only freshly parsed entities reach here, so the distinction is not
/// exercised, but the rule is stated over graph truth rather than over one
/// caller. Rejecting an external target would fail reconcile on every repository
/// with a cross-repo import.
fn validate_entity(entity: &Entity) -> Option<String> {
    if entity.name.is_empty() {
        return Some("entity name is empty".to_string());
    }
    if entity.signature.is_empty() && !kin_index::is_external_reference_target(entity) {
        return Some(format!("entity '{}' has an empty signature", entity.name));
    }
    None
}

/// Carry-forward candidate for one re-parsed declaration: the unclaimed
/// existing entity of the same name and kind that `accept` admits and whose
/// declaration sits nearest the parsed one.
///
/// Position breaks the tie rather than deciding the match, and it is the last
/// word rather than the first. Graph query order is not declaration order, so
/// the previous "first unclaimed candidate the graph returned" rule paired a
/// same-name group's members arbitrarily; distance in the file is at least a
/// property of the declarations themselves and orders them the way an author
/// reading the diff would. An entity with no span sorts last and is compared
/// by id, so the choice stays deterministic when nothing has a position.
fn nearest_unclaimed<'a>(
    existing: &'a [Entity],
    parsed: &Entity,
    claimed: &HashSet<EntityId>,
    accept: impl Fn(&Entity, &Entity) -> bool,
) -> Option<&'a Entity> {
    let parsed_line = parsed.span.as_ref().map(|span| span.start_line);
    existing
        .iter()
        .filter(|candidate| {
            candidate.name == parsed.name
                && candidate.kind == parsed.kind
                && !claimed.contains(&candidate.id)
                && accept(candidate, parsed)
        })
        .min_by_key(|candidate| {
            let distance = match (
                candidate.span.as_ref().map(|span| span.start_line),
                parsed_line,
            ) {
                (Some(candidate_line), Some(parsed_line)) => {
                    Some(candidate_line.abs_diff(parsed_line))
                }
                _ => None,
            };
            // `None` sorts after every `Some`, which is what puts a spanless
            // candidate last without a sentinel distance that a real span could
            // reach.
            (distance.is_none(), distance, candidate.id)
        })
}

/// Collect all unique file origins from both entity sets.
fn collect_affected_files(ours: &[Entity], theirs: &[Entity]) -> Vec<FilePathId> {
    let mut files = HashSet::new();
    for entity in ours.iter().chain(theirs.iter()) {
        if let Some(ref file) = entity.file_origin {
            files.insert(file.clone());
        }
    }
    let mut result: Vec<FilePathId> = files.into_iter().collect();
    result.sort_by_key(|a| a.to_string());
    result
}

// ---------------------------------------------------------------------------
// Semantic delta computation for 3-way merge
// ---------------------------------------------------------------------------

/// Classification of what happened to a single entity relative to a base state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticDeltaKind {
    /// Entity was added (not present in base).
    Added,
    /// Entity was modified (present in base with different fingerprint).
    Modified,
    /// Entity was deleted (present in base but not in this side).
    Deleted,
    /// Entity is unchanged from base.
    Unchanged,
}

/// A semantic delta for a single entity.
#[derive(Debug, Clone)]
pub struct SemanticDelta {
    pub entity_id: EntityId,
    pub kind: SemanticDeltaKind,
    pub file_origin: Option<FilePathId>,
}

/// Compute semantic deltas between a base state and a derived state.
///
/// For each entity:
/// - In derived but not base → Added
/// - In both, different fingerprint → Modified
/// - In both, same fingerprint → Unchanged
/// - In base but not derived → Deleted
fn compute_semantic_deltas(
    base: &HashMap<EntityId, &Entity>,
    derived: &HashMap<EntityId, &Entity>,
) -> HashMap<EntityId, SemanticDelta> {
    let mut deltas = HashMap::new();

    // Check all entities in the derived state.
    for (id, entity) in derived {
        let kind = if let Some(base_entity) = base.get(id) {
            if base_entity.fingerprint.ast_hash != entity.fingerprint.ast_hash {
                SemanticDeltaKind::Modified
            } else {
                SemanticDeltaKind::Unchanged
            }
        } else {
            SemanticDeltaKind::Added
        };
        deltas.insert(
            *id,
            SemanticDelta {
                entity_id: *id,
                kind,
                file_origin: entity.file_origin.clone(),
            },
        );
    }

    // Check for entities in base that are missing in derived (deletions).
    for (id, base_entity) in base {
        if !derived.contains_key(id) {
            deltas.insert(
                *id,
                SemanticDelta {
                    entity_id: *id,
                    kind: SemanticDeltaKind::Deleted,
                    file_origin: base_entity.file_origin.clone(),
                },
            );
        }
    }

    deltas
}

/// Merge two sets of semantic deltas (local and remote) to produce a MergePreview.
///
/// Rules:
/// - Both unchanged → no action (kept)
/// - One modified, other unchanged → auto-merge (accept the modification)
/// - One added, other doesn't have it → auto-merge (accept the addition)
/// - Both modified the same entity → Divergent conflict
/// - One modified, other deleted → ModifyDelete HardCollision
/// - Both deleted → auto-merge (both agree on deletion)
/// - Both added same ID with different content → AddAdd conflict
fn merge_deltas(
    local: &HashMap<EntityId, SemanticDelta>,
    remote: &HashMap<EntityId, SemanticDelta>,
    base_map: &HashMap<EntityId, &Entity>,
    our_map: &HashMap<EntityId, &Entity>,
    their_map: &HashMap<EntityId, &Entity>,
    ours: &[Entity],
    theirs: &[Entity],
) -> MergePreview {
    let mut conflicts = Vec::new();
    let mut added = Vec::new();
    let mut auto_resolved = Vec::new();
    let mut kept = Vec::new();

    // Collect all entity IDs across both delta sets.
    let all_ids: HashSet<EntityId> = local.keys().chain(remote.keys()).copied().collect();

    for id in &all_ids {
        let local_delta = local.get(id);
        let remote_delta = remote.get(id);

        match (local_delta.map(|d| &d.kind), remote_delta.map(|d| &d.kind)) {
            // Both unchanged or only present on one side as unchanged.
            (Some(SemanticDeltaKind::Unchanged), Some(SemanticDeltaKind::Unchanged)) => {
                kept.push(*id);
            }
            (Some(SemanticDeltaKind::Unchanged), None)
            | (None, Some(SemanticDeltaKind::Unchanged)) => {
                kept.push(*id);
            }

            // One modified, other unchanged → auto-merge.
            (Some(SemanticDeltaKind::Modified), Some(SemanticDeltaKind::Unchanged)) => {
                auto_resolved.push(*id);
            }
            (Some(SemanticDeltaKind::Unchanged), Some(SemanticDeltaKind::Modified)) => {
                auto_resolved.push(*id);
            }

            // Both modified → check if convergent or divergent.
            (Some(SemanticDeltaKind::Modified), Some(SemanticDeltaKind::Modified)) => {
                let our_entity = our_map.get(id);
                let their_entity = their_map.get(id);

                match (our_entity, their_entity) {
                    (Some(ours), Some(theirs)) => {
                        if ours.fingerprint.ast_hash == theirs.fingerprint.ast_hash {
                            // Convergent — both made the same change.
                            auto_resolved.push(*id);
                        } else {
                            // Divergent modification.
                            let mut entity_conflicts = vec![MergeConflict {
                                entity_id: *id,
                                entity_name: theirs.name.clone(),
                                file_origin: theirs.file_origin.clone(),
                                kind: MergeConflictKind::Divergent,
                            }];
                            if let Some(sig) = check_signature_change(ours, theirs) {
                                entity_conflicts.push(MergeConflict {
                                    entity_id: *id,
                                    entity_name: theirs.name.clone(),
                                    file_origin: theirs.file_origin.clone(),
                                    kind: sig,
                                });
                            }
                            if let Some(vis) = check_visibility_change(ours, theirs) {
                                entity_conflicts.push(MergeConflict {
                                    entity_id: *id,
                                    entity_name: theirs.name.clone(),
                                    file_origin: theirs.file_origin.clone(),
                                    kind: vis,
                                });
                            }
                            conflicts.extend(entity_conflicts);
                        }
                    }
                    _ => {
                        // Shouldn't happen if deltas are computed correctly.
                        kept.push(*id);
                    }
                }
            }

            // One modified, other deleted → ModifyDelete HardCollision.
            (Some(SemanticDeltaKind::Modified), Some(SemanticDeltaKind::Deleted)) => {
                let entity_name = our_map
                    .get(id)
                    .map(|e| e.name.clone())
                    .or_else(|| base_map.get(id).map(|e| e.name.clone()))
                    .unwrap_or_default();
                let file_origin = our_map
                    .get(id)
                    .and_then(|e| e.file_origin.clone())
                    .or_else(|| base_map.get(id).and_then(|e| e.file_origin.clone()));
                conflicts.push(MergeConflict {
                    entity_id: *id,
                    entity_name,
                    file_origin,
                    kind: MergeConflictKind::ModifyDelete,
                });
            }
            (Some(SemanticDeltaKind::Deleted), Some(SemanticDeltaKind::Modified)) => {
                let entity_name = their_map
                    .get(id)
                    .map(|e| e.name.clone())
                    .or_else(|| base_map.get(id).map(|e| e.name.clone()))
                    .unwrap_or_default();
                let file_origin = their_map
                    .get(id)
                    .and_then(|e| e.file_origin.clone())
                    .or_else(|| base_map.get(id).and_then(|e| e.file_origin.clone()));
                conflicts.push(MergeConflict {
                    entity_id: *id,
                    entity_name,
                    file_origin,
                    kind: MergeConflictKind::ModifyDelete,
                });
            }

            // Both deleted → auto-merge (agreement).
            (Some(SemanticDeltaKind::Deleted), Some(SemanticDeltaKind::Deleted)) => {
                auto_resolved.push(*id);
            }

            // One added, other has nothing → accept the addition.
            (Some(SemanticDeltaKind::Added), None) => {
                kept.push(*id); // Local addition, already in ours.
            }
            (None, Some(SemanticDeltaKind::Added)) => {
                added.push(*id); // Remote addition, needs to be merged in.
            }

            // Both added same entity ID → check if convergent or AddAdd.
            (Some(SemanticDeltaKind::Added), Some(SemanticDeltaKind::Added)) => {
                let our_entity = our_map.get(id);
                let their_entity = their_map.get(id);
                match (our_entity, their_entity) {
                    (Some(ours), Some(theirs)) => {
                        if ours.fingerprint.ast_hash == theirs.fingerprint.ast_hash {
                            auto_resolved.push(*id);
                        } else {
                            conflicts.push(MergeConflict {
                                entity_id: *id,
                                entity_name: theirs.name.clone(),
                                file_origin: theirs.file_origin.clone(),
                                kind: MergeConflictKind::AddAdd,
                            });
                        }
                    }
                    _ => {
                        added.push(*id);
                    }
                }
            }

            // One deleted, other unchanged → accept the deletion (auto-merge).
            (Some(SemanticDeltaKind::Deleted), Some(SemanticDeltaKind::Unchanged))
            | (Some(SemanticDeltaKind::Unchanged), Some(SemanticDeltaKind::Deleted)) => {
                auto_resolved.push(*id);
            }

            // One deleted, other not present → already gone.
            (Some(SemanticDeltaKind::Deleted), None) | (None, Some(SemanticDeltaKind::Deleted)) => {
                // Entity was deleted and doesn't exist on the other side.
                // No action needed.
            }

            // One modified, other not present at all (not even in base).
            (Some(SemanticDeltaKind::Modified), None) => {
                kept.push(*id);
            }
            (None, Some(SemanticDeltaKind::Modified)) => {
                added.push(*id);
            }

            // Both absent — shouldn't happen.
            (None, None) => {}

            // Added + Unchanged/Modified/Deleted — shouldn't happen with correct delta computation
            // since Added means not in base, and Unchanged/Modified/Deleted mean in base.
            (Some(SemanticDeltaKind::Added), Some(SemanticDeltaKind::Unchanged))
            | (Some(SemanticDeltaKind::Added), Some(SemanticDeltaKind::Modified))
            | (Some(SemanticDeltaKind::Added), Some(SemanticDeltaKind::Deleted))
            | (Some(SemanticDeltaKind::Unchanged), Some(SemanticDeltaKind::Added))
            | (Some(SemanticDeltaKind::Modified), Some(SemanticDeltaKind::Added))
            | (Some(SemanticDeltaKind::Deleted), Some(SemanticDeltaKind::Added)) => {
                // Inconsistent state — one side says entity is in base, other says not.
                // Treat as conflict for safety.
                let entity_name = our_map
                    .get(id)
                    .or_else(|| their_map.get(id))
                    .or_else(|| base_map.get(id))
                    .map(|e| e.name.clone())
                    .unwrap_or_default();
                let file_origin = our_map
                    .get(id)
                    .or_else(|| their_map.get(id))
                    .or_else(|| base_map.get(id))
                    .and_then(|e| e.file_origin.clone());
                conflicts.push(MergeConflict {
                    entity_id: *id,
                    entity_name,
                    file_origin,
                    kind: MergeConflictKind::Divergent,
                });
            }
        }
    }

    // Also check for name+kind collisions (different IDs, same name).
    let our_name_map: HashMap<(&str, EntityKind), EntityId> = ours
        .iter()
        .map(|e| ((e.name.as_str(), e.kind), e.id))
        .collect();
    for their_entity in theirs {
        let key = (their_entity.name.as_str(), their_entity.kind);
        if let Some(&our_id) = our_name_map.get(&key) {
            if our_id != their_entity.id
                && !conflicts.iter().any(|c| c.entity_id == their_entity.id)
            {
                conflicts.push(MergeConflict {
                    entity_id: their_entity.id,
                    entity_name: their_entity.name.clone(),
                    file_origin: their_entity.file_origin.clone(),
                    kind: MergeConflictKind::AddAdd,
                });
            }
        }
    }

    MergePreview {
        conflicts,
        added,
        auto_resolved,
        kept,
        files_affected: collect_affected_files(ours, theirs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        EntityKind, EntityMetadata, EntityRole, EntityStore, FingerprintAlgorithm, Hash256,
        LanguageId, SemanticFingerprint, Visibility,
    };

    fn make_entity(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0xaa; 32]),
                signature_hash: Hash256::from_bytes([0xbb; 32]),
                behavior_hash: Hash256::from_bytes([0xcc; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 0.95,
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

    #[test]
    fn reconciler_creates() {
        let dir = tempfile::tempdir().unwrap();
        let reconciler = Reconciler::new(dir.path().to_path_buf());
        assert!(reconciler.lkg().is_empty());
    }

    #[test]
    fn detect_conflict_when_both_sides_changed() {
        let dir = tempfile::tempdir().unwrap();
        let reconciler = Reconciler::new(dir.path().to_path_buf());

        let entity_id = EntityId::new();
        let mut desired_entity = make_entity("foo", "src/lib.rs");
        desired_entity.id = entity_id;
        desired_entity.fingerprint.ast_hash = Hash256::from_bytes([0x11; 32]);

        let mut file_entity = make_entity("foo", "src/lib.rs");
        file_entity.id = entity_id;
        file_entity.fingerprint.ast_hash = Hash256::from_bytes([0x22; 32]);

        let conflict = reconciler.detect_conflict(&entity_id, &desired_entity, &file_entity);
        assert!(conflict.is_some());
        let c = conflict.unwrap();
        assert_eq!(c.kind, ConflictKind::StructuralCollision);
        assert!(c.requires_human_review);
    }

    #[test]
    fn no_conflict_when_same_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let reconciler = Reconciler::new(dir.path().to_path_buf());

        let entity_id = EntityId::new();
        let mut e1 = make_entity("foo", "src/lib.rs");
        e1.id = entity_id;
        let mut e2 = make_entity("foo", "src/lib.rs");
        e2.id = entity_id;

        assert!(reconciler.detect_conflict(&entity_id, &e1, &e2).is_none());
    }

    #[test]
    fn lkg_records_on_reconcile() {
        let dir = tempfile::tempdir().unwrap();
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        let entity = make_entity("bar", "src/main.rs");
        let id = entity.id;

        reconciler.lkg.record(&entity);
        assert!(reconciler.lkg().get(&id).is_some());
    }

    /// Reconcile a file twice, returning the delta the second pass derived.
    fn reconcile_twice(first: &str, second: &str) -> Result<TransactionDelta> {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let blobs = BlobStore::new(root.join(".kin-blobs")).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let mut reconciler = Reconciler::new(root.clone());
        let path = root.join("hooks.rs");

        // Seed graph truth entity by entity. Committing the first delta whole
        // would need a staged tree carrying the artifact, and the tree plays no
        // part in how the second pass re-matches what it parses.
        std::fs::write(&path, first).unwrap();
        let seeded = reconciler
            .reconcile_file_change(&FileEvent::Changed(path.clone()), &blobs, &graph)?
            .delta;
        for entity_delta in &seeded.entity_deltas {
            if let EntityDelta::Added { new } = entity_delta {
                graph.upsert_entity(new).unwrap();
            }
        }

        std::fs::write(&path, second).unwrap();
        Ok(reconciler
            .reconcile_file_change(&FileEvent::Changed(path), &blobs, &graph)?
            .delta)
    }

    /// A file may declare one name twice, and each declaration is its own entity.
    ///
    /// Identity is derived from the declaration's start line, so an edit above a
    /// declaration invalidates the identity the graph holds for it. Re-matching
    /// then falls back to name and kind, and both parsed halves of a cfg-gated
    /// pair claimed whichever half the graph returned first. Two deltas for one
    /// entity is not a transaction, so the edit was refused whole and nothing in
    /// the file ever advanced again.
    #[test]
    fn an_edit_above_a_duplicated_declaration_yields_one_delta_per_entity() {
        let delta = reconcile_twice(
            "#[cfg(unix)]\npub fn hook() -> u32 { 1 }\n\n#[cfg(not(unix))]\npub fn hook() -> u32 { 2 }\n",
            "pub fn probe() -> u32 { 9 }\n\n#[cfg(unix)]\npub fn hook() -> u32 { 1 }\n\n#[cfg(not(unix))]\npub fn hook() -> u32 { 2 }\n",
        )
        .expect("an ordinary edit must derive a valid transaction");

        let mut targets = delta
            .entity_deltas
            .iter()
            .map(EntityDelta::target_id)
            .collect::<Vec<_>>();
        let before = targets.len();
        targets.sort();
        targets.dedup();
        assert_eq!(
            targets.len(),
            before,
            "the transaction carries more than one delta for some entity"
        );
        assert!(
            delta
                .entity_deltas
                .iter()
                .any(|entity_delta| matches!(entity_delta, EntityDelta::Added { new } if new.name == "probe")),
            "the added declaration never reached the transaction"
        );
    }

    /// Each half of a duplicated declaration keeps its own identity across an edit.
    ///
    /// Matching one parsed entity to one existing entity is what holds the
    /// invariant, and matching them to the same one both breaks the transaction
    /// and loses a declaration. Pin the surviving count, not only the delta shape.
    #[test]
    fn both_halves_of_a_duplicated_declaration_survive_an_edit() {
        let delta = reconcile_twice(
            "#[cfg(unix)]\npub fn hook() -> u32 { 1 }\n\n#[cfg(not(unix))]\npub fn hook() -> u32 { 2 }\n",
            "pub fn probe() -> u32 { 9 }\n\n#[cfg(unix)]\npub fn hook() -> u32 { 1 }\n\n#[cfg(not(unix))]\npub fn hook() -> u32 { 2 }\n",
        )
        .expect("an ordinary edit must derive a valid transaction");

        let removed = delta
            .entity_deltas
            .iter()
            .filter(|entity_delta| matches!(entity_delta, EntityDelta::Removed { .. }))
            .count();
        assert_eq!(
            removed, 0,
            "an edit that removed no declaration must remove no entity"
        );
        let hooks = delta
            .entity_deltas
            .iter()
            .filter(|entity_delta| {
                matches!(entity_delta, EntityDelta::Modified { new, .. } if new.name == "hook")
            })
            .count();
        assert_eq!(
            hooks, 2,
            "both halves of the duplicated declaration must advance"
        );
    }

    #[test]
    fn project_empty_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        let transaction = TransactionDelta::default();
        let (modified, warnings) = reconciler
            .project_transaction_to_files(&transaction, &HashMap::new())
            .unwrap();
        assert!(modified.is_empty());
        assert!(warnings.is_empty());
    }

    #[test]
    fn project_transaction_rejects_entity_without_source_span() {
        let dir = tempfile::tempdir().unwrap();
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        let mut entity = make_entity("missing_body", "src/lib.rs");
        entity.span = None;
        let entity_id = entity.id;
        let mut old = entity.clone();
        old.fingerprint.ast_hash = Hash256::from_bytes([0; 32]);
        let transaction = TransactionDelta {
            entity_deltas: vec![EntityDelta::Modified { old, new: entity }],
            ..TransactionDelta::default()
        };

        let result = reconciler.project_transaction_to_files(&transaction, &HashMap::new());
        match result.unwrap_err() {
            ReconcileError::BodyExtractionFailed {
                entity_id: failed_id,
                reason,
            } => {
                assert_eq!(failed_id, entity_id);
                assert!(reason.contains("no source span"));
            }
            other => panic!("expected BodyExtractionFailed, got: {:?}", other),
        }
    }

    /// A projection miss refuses instead of reading the working copy.
    ///
    /// The file is written to the working directory holding exactly the bytes
    /// the span is valid against, so a fallback that read it would succeed and
    /// return a correct-looking body. That is the point: the refusal must not
    /// depend on the file being absent, because absence is the easy case and
    /// presence is the one that silently makes the working copy an answer
    /// authority for a graph miss.
    #[test]
    fn project_transaction_refuses_a_projection_miss_rather_than_reading_the_working_copy() {
        let dir = tempfile::tempdir().unwrap();
        let source = "pub fn cached() -> u32 { 7 }\n";
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), source).unwrap();

        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        let mut entity = make_entity("cached", "src/lib.rs");
        entity.span = Some(kin_model::SourceSpan {
            file: FilePathId::new("src/lib.rs"),
            start_byte: 0,
            end_byte: source.len(),
            start_line: 1,
            start_col: 0,
            end_line: 1,
            end_col: source.len() as u32,
        });
        let entity_id = entity.id;
        let mut old = entity.clone();
        old.fingerprint.ast_hash = Hash256::from_bytes([0; 32]);
        let transaction = TransactionDelta {
            entity_deltas: vec![EntityDelta::Modified { old, new: entity }],
            ..TransactionDelta::default()
        };

        // Positive control. A refusal proves nothing unless the bytes a
        // fallback would have reached are really on disk and really readable.
        assert_eq!(
            std::fs::read(dir.path().join("src/lib.rs")).unwrap(),
            source.as_bytes(),
            "the working copy must hold the readable bytes this test refuses to read"
        );

        match reconciler
            .project_transaction_to_files(&transaction, &HashMap::new())
            .unwrap_err()
        {
            ReconcileError::BodyExtractionFailed {
                entity_id: failed_id,
                reason,
            } => {
                assert_eq!(failed_id, entity_id);
                assert!(
                    reason.contains("not an answer authority"),
                    "the refusal must say why it refused, got: {reason}"
                );
            }
            other => panic!("expected BodyExtractionFailed, got: {other:?}"),
        }
    }

    #[test]
    fn project_transaction_rejects_unbound_entity_body() {
        let dir = tempfile::tempdir().unwrap();
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        let entity_id = EntityId::new();
        let entity_bodies = HashMap::from([(entity_id, b"fn unbound() {}".to_vec())]);

        let error = reconciler
            .project_transaction_to_files(&TransactionDelta::default(), &entity_bodies)
            .unwrap_err();

        assert!(matches!(error, ReconcileError::InvalidTransaction(_)));
        assert!(error.to_string().contains(&entity_id.to_string()));
    }

    // ---------------------------------------------------------------
    // TrafficChecker integration tests
    // ---------------------------------------------------------------

    use kin_model::{IntentConflict, IntentId, LockType, Timestamp};

    /// Mock TrafficChecker that returns a configurable result.
    struct MockTrafficChecker {
        result: std::sync::Mutex<CollisionCheck>,
    }

    impl MockTrafficChecker {
        fn clear() -> Self {
            Self {
                result: std::sync::Mutex::new(CollisionCheck::Clear),
            }
        }

        fn blocked() -> Self {
            Self {
                result: std::sync::Mutex::new(CollisionCheck::Blocked {
                    conflict: IntentConflict::HardCollision,
                    blocking_intents: vec![IntentSummary {
                        intent_id: IntentId::new(),
                        session_id: SessionId::new(),
                        vendor: "other-agent".to_string(),
                        task_description: "editing same entity".to_string(),
                        lock_type: LockType::Hard,
                        registered_at: Timestamp::now(),
                    }],
                }),
            }
        }

        fn warnings() -> Self {
            Self {
                result: std::sync::Mutex::new(CollisionCheck::Warnings(vec![IntentSummary {
                    intent_id: IntentId::new(),
                    session_id: SessionId::new(),
                    vendor: "soft-agent".to_string(),
                    task_description: "soft lock nearby".to_string(),
                    lock_type: LockType::Soft,
                    registered_at: Timestamp::now(),
                }])),
            }
        }
    }

    impl TrafficChecker for MockTrafficChecker {
        fn check_collisions(
            &self,
            _scope: &IntentScope,
            _requesting_session: Option<&SessionId>,
        ) -> std::result::Result<CollisionCheck, String> {
            let mut guard = self.result.lock().unwrap();
            // Swap out the result so it can be consumed (enum is not Clone).
            let result = std::mem::replace(&mut *guard, CollisionCheck::Clear);
            Ok(result)
        }
    }

    /// A per-scope mock checker: returns different results depending on scope.
    struct PerScopeChecker {
        /// Map from entity ID to the collision result for that scope.
        responses: std::sync::Mutex<HashMap<EntityId, CollisionCheck>>,
    }

    impl PerScopeChecker {
        fn new(responses: HashMap<EntityId, CollisionCheck>) -> Self {
            Self {
                responses: std::sync::Mutex::new(responses),
            }
        }
    }

    impl TrafficChecker for PerScopeChecker {
        fn check_collisions(
            &self,
            scope: &IntentScope,
            _requesting_session: Option<&SessionId>,
        ) -> std::result::Result<CollisionCheck, String> {
            if let IntentScope::Entity(eid) = scope {
                let mut guard = self.responses.lock().unwrap();
                if let Some(result) = guard.remove(eid) {
                    return Ok(result);
                }
            }
            Ok(CollisionCheck::Clear)
        }
    }

    #[test]
    fn no_checker_mutation_proceeds() {
        // When no traffic checker is set, check_scopes returns empty warnings.
        let dir = tempfile::tempdir().unwrap();
        let reconciler = Reconciler::new(dir.path().to_path_buf());
        let entity_id = EntityId::new();
        let scopes = vec![IntentScope::Entity(entity_id)];
        let warnings = reconciler.check_scopes(&scopes).unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn clear_checker_mutation_proceeds() {
        // When checker returns Clear, mutation proceeds with no warnings.
        let dir = tempfile::tempdir().unwrap();
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        reconciler.set_traffic_checker(Box::new(MockTrafficChecker::clear()));
        reconciler.set_session_id(SessionId::new());

        let entity_id = EntityId::new();
        let scopes = vec![IntentScope::Entity(entity_id)];
        let warnings = reconciler.check_scopes(&scopes).unwrap();
        assert!(warnings.is_empty());
    }

    #[test]
    fn blocked_checker_rejects_mutation() {
        // When checker returns HardCollision, the mutation is rejected.
        let dir = tempfile::tempdir().unwrap();
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        reconciler.set_traffic_checker(Box::new(MockTrafficChecker::blocked()));
        reconciler.set_session_id(SessionId::new());

        let entity_id = EntityId::new();
        let scopes = vec![IntentScope::Entity(entity_id)];
        let result = reconciler.check_scopes(&scopes);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            ReconcileError::CollisionBlocked {
                reason,
                blocking_intents,
            } => {
                assert!(reason.contains("Hard collision"));
                assert_eq!(blocking_intents.len(), 1);
                assert_eq!(blocking_intents[0].vendor, "other-agent");
            }
            other => panic!("expected CollisionBlocked, got: {:?}", other),
        }
    }

    #[test]
    fn warnings_checker_allows_mutation_with_warnings() {
        // When checker returns Warnings, mutation proceeds but warnings returned.
        let dir = tempfile::tempdir().unwrap();
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        reconciler.set_traffic_checker(Box::new(MockTrafficChecker::warnings()));
        reconciler.set_session_id(SessionId::new());

        let entity_id = EntityId::new();
        let scopes = vec![IntentScope::Entity(entity_id)];
        let warnings = reconciler.check_scopes(&scopes).unwrap();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].vendor, "soft-agent");
        assert_eq!(warnings[0].lock_type, LockType::Soft);
    }

    #[test]
    fn multiple_scopes_checked_correctly() {
        // Test that check_scopes queries each scope independently and
        // aggregates warnings from multiple scopes.
        let dir = tempfile::tempdir().unwrap();
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());

        let entity_a = EntityId::new();
        let entity_b = EntityId::new();
        let entity_c = EntityId::new();

        let mut responses = HashMap::new();
        // entity_a: clear
        // entity_b: soft warning
        responses.insert(
            entity_b,
            CollisionCheck::Warnings(vec![IntentSummary {
                intent_id: IntentId::new(),
                session_id: SessionId::new(),
                vendor: "agent-b".to_string(),
                task_description: "soft lock on B".to_string(),
                lock_type: LockType::Soft,
                registered_at: Timestamp::now(),
            }]),
        );
        // entity_c: different soft warning
        responses.insert(
            entity_c,
            CollisionCheck::Warnings(vec![IntentSummary {
                intent_id: IntentId::new(),
                session_id: SessionId::new(),
                vendor: "agent-c".to_string(),
                task_description: "soft lock on C".to_string(),
                lock_type: LockType::Soft,
                registered_at: Timestamp::now(),
            }]),
        );

        reconciler.set_traffic_checker(Box::new(PerScopeChecker::new(responses)));
        reconciler.set_session_id(SessionId::new());

        let scopes = vec![
            IntentScope::Entity(entity_a),
            IntentScope::Entity(entity_b),
            IntentScope::Entity(entity_c),
        ];

        let warnings = reconciler.check_scopes(&scopes).unwrap();
        // Should have 2 warnings total (one from entity_b, one from entity_c)
        assert_eq!(warnings.len(), 2);
        let vendors: Vec<&str> = warnings.iter().map(|w| w.vendor.as_str()).collect();
        assert!(vendors.contains(&"agent-b"));
        assert!(vendors.contains(&"agent-c"));
    }

    #[test]
    fn project_transaction_blocked_by_collision() {
        // Verify that project_transaction_to_files rejects when checker blocks.
        let dir = tempfile::tempdir().unwrap();
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        reconciler.set_traffic_checker(Box::new(MockTrafficChecker::blocked()));
        reconciler.set_session_id(SessionId::new());

        let entity_id = EntityId::new();
        let mut entity = make_entity("blocked_fn", "src/lib.rs");
        entity.id = entity_id;
        let mut old = entity.clone();
        old.fingerprint.ast_hash = Hash256::from_bytes([0; 32]);
        let transaction = TransactionDelta {
            entity_deltas: vec![EntityDelta::Modified { old, new: entity }],
            ..TransactionDelta::default()
        };

        let result = reconciler.project_transaction_to_files(&transaction, &HashMap::new());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReconcileError::CollisionBlocked { .. }
        ));
    }

    // ---------------------------------------------------------------
    // Merge analysis tests
    // ---------------------------------------------------------------

    fn make_entity_with_id(id: EntityId, name: &str, file: &str) -> Entity {
        let mut e = make_entity(name, file);
        e.id = id;
        e
    }

    fn make_entity_with_hash(name: &str, file: &str, hash_byte: u8) -> Entity {
        let mut e = make_entity(name, file);
        e.fingerprint.ast_hash = Hash256::from_bytes([hash_byte; 32]);
        e
    }

    #[test]
    fn merge_clean_when_no_overlap() {
        // Two branches with completely different entities — clean merge.
        let ours = vec![make_entity("fn_a", "src/a.rs")];
        let theirs = vec![make_entity("fn_b", "src/b.rs")];

        let preview = Reconciler::analyze_merge(&ours, &theirs);
        assert!(preview.is_clean());
        assert_eq!(preview.added.len(), 1);
        assert_eq!(preview.kept.len(), 1);
        assert_eq!(preview.conflicts.len(), 0);
    }

    #[test]
    fn merge_detects_divergent_conflict() {
        // Same entity ID modified differently on both sides.
        let shared_id = EntityId::new();
        let our_entity = {
            let mut e = make_entity_with_id(shared_id, "foo", "src/lib.rs");
            e.fingerprint.ast_hash = Hash256::from_bytes([0x11; 32]);
            e
        };
        let their_entity = {
            let mut e = make_entity_with_id(shared_id, "foo", "src/lib.rs");
            e.fingerprint.ast_hash = Hash256::from_bytes([0x22; 32]);
            e
        };

        let preview = Reconciler::analyze_merge(&[our_entity], &[their_entity]);
        assert!(!preview.is_clean());
        assert!(preview
            .conflicts
            .iter()
            .any(|c| matches!(c.kind, MergeConflictKind::Divergent)));
    }

    #[test]
    fn merge_auto_resolves_convergent() {
        // Same entity ID with identical fingerprints on both sides.
        let shared_id = EntityId::new();
        let our_entity = make_entity_with_id(shared_id, "foo", "src/lib.rs");
        let their_entity = make_entity_with_id(shared_id, "foo", "src/lib.rs");

        let preview = Reconciler::analyze_merge(&[our_entity], &[their_entity]);
        assert!(preview.is_clean());
        assert_eq!(preview.auto_resolved.len(), 1);
        assert_eq!(preview.auto_resolved[0], shared_id);
    }

    #[test]
    fn merge_detects_signature_change() {
        // Same entity with different signature hashes.
        let shared_id = EntityId::new();
        let our_entity = {
            let mut e = make_entity_with_id(shared_id, "foo", "src/lib.rs");
            e.fingerprint.ast_hash = Hash256::from_bytes([0x11; 32]);
            e.fingerprint.signature_hash = Hash256::from_bytes([0xaa; 32]);
            e
        };
        let their_entity = {
            let mut e = make_entity_with_id(shared_id, "foo", "src/lib.rs");
            e.fingerprint.ast_hash = Hash256::from_bytes([0x22; 32]);
            e.fingerprint.signature_hash = Hash256::from_bytes([0xff; 32]);
            e
        };

        let preview = Reconciler::analyze_merge(&[our_entity], &[their_entity]);
        assert!(preview
            .conflicts
            .iter()
            .any(|c| matches!(c.kind, MergeConflictKind::SignatureChange)));
    }

    #[test]
    fn merge_detects_visibility_change() {
        // Same entity with different visibility.
        let shared_id = EntityId::new();
        let our_entity = {
            let mut e = make_entity_with_id(shared_id, "foo", "src/lib.rs");
            e.fingerprint.ast_hash = Hash256::from_bytes([0x11; 32]);
            e.visibility = Visibility::Public;
            e
        };
        let their_entity = {
            let mut e = make_entity_with_id(shared_id, "foo", "src/lib.rs");
            e.fingerprint.ast_hash = Hash256::from_bytes([0x22; 32]);
            e.visibility = Visibility::Private;
            e
        };

        let preview = Reconciler::analyze_merge(&[our_entity], &[their_entity]);
        assert!(preview
            .conflicts
            .iter()
            .any(|c| matches!(c.kind, MergeConflictKind::VisibilityChange { .. })));
    }

    #[test]
    fn merge_dry_run_produces_preview_without_side_effects() {
        // Verify that analyze_merge is pure — calling it twice gives identical results.
        let shared_id = EntityId::new();
        let ours = vec![make_entity_with_id(shared_id, "foo", "src/lib.rs")];
        let theirs = vec![make_entity("bar", "src/main.rs")];

        let preview1 = Reconciler::analyze_merge(&ours, &theirs);
        let preview2 = Reconciler::analyze_merge(&ours, &theirs);

        assert_eq!(preview1.added.len(), preview2.added.len());
        assert_eq!(preview1.kept.len(), preview2.kept.len());
        assert_eq!(preview1.conflicts.len(), preview2.conflicts.len());
        assert_eq!(preview1.auto_resolved.len(), preview2.auto_resolved.len());
        assert_eq!(preview1.files_affected.len(), preview2.files_affected.len());
    }

    #[test]
    fn unrelated_merge_detects_name_collision() {
        // Two branches with different entity IDs but same name+kind.
        let our_entity = make_entity_with_hash("collider", "src/lib.rs", 0x11);
        let their_entity = make_entity_with_hash("collider", "src/other.rs", 0x22);

        let preview = Reconciler::analyze_unrelated_merge(&[our_entity], &[their_entity]);
        assert!(!preview.is_clean());
        assert!(preview
            .conflicts
            .iter()
            .any(|c| matches!(c.kind, MergeConflictKind::AddAdd)));
    }

    #[test]
    fn unrelated_merge_clean_when_no_name_collision() {
        // Two branches with completely different entity names.
        let our_entity = make_entity("fn_a", "src/a.rs");
        let their_entity = make_entity("fn_b", "src/b.rs");

        let preview = Reconciler::analyze_unrelated_merge(&[our_entity], &[their_entity]);
        assert!(preview.is_clean());
        assert_eq!(preview.added.len(), 1);
        assert_eq!(preview.kept.len(), 1);
    }

    #[test]
    fn unrelated_merge_same_content_auto_resolves() {
        // Two branches with same name+kind AND same fingerprint — no conflict.
        let our_entity = make_entity("shared_fn", "src/lib.rs");
        let their_entity = make_entity("shared_fn", "src/lib.rs");

        let preview = Reconciler::analyze_unrelated_merge(&[our_entity], &[their_entity]);
        assert!(preview.is_clean());
        // The entity already exists with identical content, so no addition needed.
        assert_eq!(preview.added.len(), 0);
    }

    #[test]
    fn merge_preview_files_affected() {
        // Check that files_affected collects from both sides.
        let ours = vec![
            make_entity("fn_a", "src/a.rs"),
            make_entity("fn_b", "src/b.rs"),
        ];
        let theirs = vec![
            make_entity("fn_c", "src/c.rs"),
            make_entity("fn_d", "src/b.rs"), // shared file
        ];

        let preview = Reconciler::analyze_merge(&ours, &theirs);
        assert_eq!(preview.files_affected.len(), 3); // a.rs, b.rs, c.rs
    }

    #[test]
    fn merge_preview_manual_conflict_count() {
        let shared_id = EntityId::new();
        let our_entity = {
            let mut e = make_entity_with_id(shared_id, "foo", "src/lib.rs");
            e.fingerprint.ast_hash = Hash256::from_bytes([0x11; 32]);
            e
        };
        let their_entity = {
            let mut e = make_entity_with_id(shared_id, "foo", "src/lib.rs");
            e.fingerprint.ast_hash = Hash256::from_bytes([0x22; 32]);
            e
        };

        let preview = Reconciler::analyze_merge(&[our_entity], &[their_entity]);
        // At least 1 manual conflict (Divergent)
        assert!(preview.manual_conflict_count() >= 1);
    }

    // ---------------------------------------------------------------
    // Task 1.6: ModifyDelete detection tests
    // ---------------------------------------------------------------

    #[test]
    fn modify_delete_conflict_local_modify_remote_delete() {
        // Base has entity, ours modified it, theirs deleted it → ModifyDelete.
        let shared_id = EntityId::new();
        let base_entity = make_entity_with_id(shared_id, "foo", "src/lib.rs");

        let mut our_entity = make_entity_with_id(shared_id, "foo", "src/lib.rs");
        our_entity.fingerprint.ast_hash = Hash256::from_bytes([0x11; 32]); // Modified.

        // theirs: entity is missing (deleted).
        let base = vec![base_entity];
        let ours = vec![our_entity];
        let theirs: Vec<Entity> = vec![];

        let preview = Reconciler::analyze_merge_3way(&base, &ours, &theirs);
        assert!(!preview.is_clean());
        assert!(
            preview
                .conflicts
                .iter()
                .any(|c| matches!(c.kind, MergeConflictKind::ModifyDelete)
                    && c.entity_id == shared_id),
            "expected ModifyDelete conflict for entity {shared_id}"
        );
    }

    #[test]
    fn modify_delete_conflict_local_delete_remote_modify() {
        // Base has entity, ours deleted it, theirs modified it → ModifyDelete.
        let shared_id = EntityId::new();
        let base_entity = make_entity_with_id(shared_id, "foo", "src/lib.rs");

        let mut their_entity = make_entity_with_id(shared_id, "foo", "src/lib.rs");
        their_entity.fingerprint.ast_hash = Hash256::from_bytes([0x22; 32]); // Modified.

        let base = vec![base_entity];
        let ours: Vec<Entity> = vec![]; // Deleted.
        let theirs = vec![their_entity];

        let preview = Reconciler::analyze_merge_3way(&base, &ours, &theirs);
        assert!(!preview.is_clean());
        assert!(
            preview
                .conflicts
                .iter()
                .any(|c| matches!(c.kind, MergeConflictKind::ModifyDelete)
                    && c.entity_id == shared_id),
            "expected ModifyDelete conflict for entity {shared_id}"
        );
    }

    #[test]
    fn modify_different_entity_delete_different_entity_no_collision() {
        // Ours modifies entity A, theirs deletes entity B → no collision.
        let id_a = EntityId::new();
        let id_b = EntityId::new();

        let base_a = make_entity_with_id(id_a, "fn_a", "src/a.rs");
        let base_b = make_entity_with_id(id_b, "fn_b", "src/b.rs");

        let mut our_a = make_entity_with_id(id_a, "fn_a", "src/a.rs");
        our_a.fingerprint.ast_hash = Hash256::from_bytes([0x11; 32]); // Modified.
        let our_b = make_entity_with_id(id_b, "fn_b", "src/b.rs"); // Unchanged.

        let their_a = make_entity_with_id(id_a, "fn_a", "src/a.rs"); // Unchanged.
                                                                     // theirs: entity B is deleted.

        let base = vec![base_a, base_b];
        let ours = vec![our_a, our_b];
        let theirs = vec![their_a]; // B deleted.

        let preview = Reconciler::analyze_merge_3way(&base, &ours, &theirs);
        // No ModifyDelete conflict — A was modified only on ours and unchanged on theirs,
        // B was deleted on theirs and unchanged on ours.
        assert!(
            !preview
                .conflicts
                .iter()
                .any(|c| matches!(c.kind, MergeConflictKind::ModifyDelete)),
            "no ModifyDelete conflict expected when modify and delete are on different entities"
        );
        assert!(preview.is_clean());
    }

    // ---------------------------------------------------------------
    // Task 1.8: 3-way semantic merge via LCA tests
    // ---------------------------------------------------------------

    #[test]
    fn three_way_non_overlapping_changes_auto_merge() {
        // Base has A and B. Ours modifies A, theirs modifies B → clean auto-merge.
        let id_a = EntityId::new();
        let id_b = EntityId::new();

        let base_a = make_entity_with_id(id_a, "fn_a", "src/a.rs");
        let base_b = make_entity_with_id(id_b, "fn_b", "src/b.rs");

        let mut our_a = make_entity_with_id(id_a, "fn_a", "src/a.rs");
        our_a.fingerprint.ast_hash = Hash256::from_bytes([0x11; 32]);
        let our_b = make_entity_with_id(id_b, "fn_b", "src/b.rs"); // Unchanged.

        let their_a = make_entity_with_id(id_a, "fn_a", "src/a.rs"); // Unchanged.
        let mut their_b = make_entity_with_id(id_b, "fn_b", "src/b.rs");
        their_b.fingerprint.ast_hash = Hash256::from_bytes([0x22; 32]);

        let base = vec![base_a, base_b];
        let ours = vec![our_a, our_b];
        let theirs = vec![their_a, their_b];

        let preview = Reconciler::analyze_merge_3way(&base, &ours, &theirs);
        assert!(
            preview.is_clean(),
            "non-overlapping changes should auto-merge"
        );
        assert_eq!(
            preview.auto_resolved.len(),
            2,
            "both A and B should be auto-resolved"
        );
    }

    #[test]
    fn three_way_overlapping_modifications_conflict() {
        // Base has entity. Both sides modify it differently → conflict.
        let shared_id = EntityId::new();
        let base_entity = make_entity_with_id(shared_id, "foo", "src/lib.rs");

        let mut our_entity = make_entity_with_id(shared_id, "foo", "src/lib.rs");
        our_entity.fingerprint.ast_hash = Hash256::from_bytes([0x11; 32]);

        let mut their_entity = make_entity_with_id(shared_id, "foo", "src/lib.rs");
        their_entity.fingerprint.ast_hash = Hash256::from_bytes([0x22; 32]);

        let base = vec![base_entity];
        let ours = vec![our_entity];
        let theirs = vec![their_entity];

        let preview = Reconciler::analyze_merge_3way(&base, &ours, &theirs);
        assert!(!preview.is_clean());
        assert!(
            preview
                .conflicts
                .iter()
                .any(|c| matches!(c.kind, MergeConflictKind::Divergent)),
            "expected Divergent conflict for overlapping modifications"
        );
    }

    #[test]
    fn three_way_convergent_modifications_auto_resolve() {
        // Base has entity. Both sides made the SAME modification → convergent.
        let shared_id = EntityId::new();
        let base_entity = make_entity_with_id(shared_id, "foo", "src/lib.rs");

        let mut our_entity = make_entity_with_id(shared_id, "foo", "src/lib.rs");
        our_entity.fingerprint.ast_hash = Hash256::from_bytes([0x11; 32]);

        let mut their_entity = make_entity_with_id(shared_id, "foo", "src/lib.rs");
        their_entity.fingerprint.ast_hash = Hash256::from_bytes([0x11; 32]); // Same.

        let base = vec![base_entity];
        let ours = vec![our_entity];
        let theirs = vec![their_entity];

        let preview = Reconciler::analyze_merge_3way(&base, &ours, &theirs);
        assert!(
            preview.is_clean(),
            "convergent modifications should auto-resolve"
        );
        assert_eq!(preview.auto_resolved.len(), 1);
    }

    #[test]
    fn lca_correctly_identified_from_change_history() {
        // Simulate a change DAG:
        //   A → B → D (local head)
        //   A → C → E (remote head)
        // LCA should be A.
        let a = kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([0x01; 32]));
        let b = kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([0x02; 32]));
        let c = kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([0x03; 32]));
        let d = kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([0x04; 32]));
        let e = kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([0x05; 32]));

        let parents: HashMap<kin_model::SemanticChangeId, Vec<kin_model::SemanticChangeId>> = {
            let mut m = HashMap::new();
            m.insert(d, vec![b]);
            m.insert(b, vec![a]);
            m.insert(e, vec![c]);
            m.insert(c, vec![a]);
            m.insert(a, vec![]);
            m
        };

        let get_parents = |id: &kin_model::SemanticChangeId| -> Vec<kin_model::SemanticChangeId> {
            parents.get(id).cloned().unwrap_or_default()
        };

        let lca = Reconciler::find_lca(&d, &e, &get_parents);
        assert_eq!(lca, Some(a), "LCA should be the common ancestor A");
    }

    #[test]
    fn lca_returns_none_for_unrelated_histories() {
        // Two completely separate chains with no common ancestor.
        let a = kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([0x01; 32]));
        let b = kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([0x02; 32]));
        let c = kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([0x03; 32]));
        let d = kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([0x04; 32]));

        let parents: HashMap<kin_model::SemanticChangeId, Vec<kin_model::SemanticChangeId>> = {
            let mut m = HashMap::new();
            m.insert(b, vec![a]);
            m.insert(a, vec![]);
            m.insert(d, vec![c]);
            m.insert(c, vec![]);
            m
        };

        let get_parents = |id: &kin_model::SemanticChangeId| -> Vec<kin_model::SemanticChangeId> {
            parents.get(id).cloned().unwrap_or_default()
        };

        let lca = Reconciler::find_lca(&b, &d, &get_parents);
        assert_eq!(lca, None, "unrelated histories should have no LCA");
    }

    #[test]
    fn lca_same_head_returns_itself() {
        let a = kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([0x01; 32]));
        let lca = Reconciler::find_lca(&a, &a, &|_| vec![]);
        assert_eq!(lca, Some(a), "same head should return itself as LCA");
    }

    #[test]
    fn three_way_no_lca_falls_back_to_two_way() {
        // When no base is provided (empty base), the 3-way merge degrades
        // to treating all entities as "added" relative to the empty base.
        let our_entity = make_entity("fn_a", "src/a.rs");
        let their_entity = make_entity("fn_b", "src/b.rs");

        let base: Vec<Entity> = vec![]; // No common ancestor.
        let ours = vec![our_entity];
        let theirs = vec![their_entity];

        let preview = Reconciler::analyze_merge_3way(&base, &ours, &theirs);
        // Both sides added different entities — clean merge.
        assert!(
            preview.is_clean(),
            "empty base with non-overlapping adds should be clean"
        );
    }

    #[test]
    fn three_way_both_sides_delete_same_entity_auto_resolves() {
        // Base has entity, both sides delete it → auto-resolve (agreement).
        let shared_id = EntityId::new();
        let base_entity = make_entity_with_id(shared_id, "foo", "src/lib.rs");

        let base = vec![base_entity];
        let ours: Vec<Entity> = vec![]; // Deleted.
        let theirs: Vec<Entity> = vec![]; // Deleted.

        let preview = Reconciler::analyze_merge_3way(&base, &ours, &theirs);
        assert!(preview.is_clean(), "both-delete should auto-resolve");
        assert_eq!(preview.auto_resolved.len(), 1);
    }

    #[test]
    fn three_way_one_side_deletes_unchanged_entity_auto_resolves() {
        // Base has entity, ours keeps it unchanged, theirs deletes it → auto-resolve.
        let shared_id = EntityId::new();
        let base_entity = make_entity_with_id(shared_id, "foo", "src/lib.rs");
        let our_entity = make_entity_with_id(shared_id, "foo", "src/lib.rs"); // Unchanged.

        let base = vec![base_entity];
        let ours = vec![our_entity];
        let theirs: Vec<Entity> = vec![]; // Deleted.

        let preview = Reconciler::analyze_merge_3way(&base, &ours, &theirs);
        assert!(preview.is_clean(), "delete-unchanged should auto-resolve");
        assert_eq!(preview.auto_resolved.len(), 1);
    }

    #[test]
    fn three_way_remote_addition_is_accepted() {
        // Base is empty. Ours is empty. Theirs adds an entity → accepted.
        let their_entity = make_entity("new_fn", "src/new.rs");

        let base: Vec<Entity> = vec![];
        let ours: Vec<Entity> = vec![];
        let theirs = vec![their_entity.clone()];

        let preview = Reconciler::analyze_merge_3way(&base, &ours, &theirs);
        assert!(preview.is_clean());
        assert_eq!(preview.added.len(), 1);
        assert_eq!(preview.added[0], their_entity.id);
    }

    #[test]
    fn three_way_lca_merge_with_multiple_changes() {
        // Complex scenario: base has A, B, C.
        // Ours: modifies A, deletes C, adds D.
        // Theirs: modifies B, keeps A and C unchanged, adds E.
        // Expected: auto-merge all (no overlapping modifications, delete C is auto).
        let id_a = EntityId::new();
        let id_b = EntityId::new();
        let id_c = EntityId::new();

        let base_a = make_entity_with_id(id_a, "fn_a", "src/a.rs");
        let base_b = make_entity_with_id(id_b, "fn_b", "src/b.rs");
        let base_c = make_entity_with_id(id_c, "fn_c", "src/c.rs");

        let mut our_a = make_entity_with_id(id_a, "fn_a", "src/a.rs");
        our_a.fingerprint.ast_hash = Hash256::from_bytes([0x11; 32]);
        let our_b = make_entity_with_id(id_b, "fn_b", "src/b.rs"); // Unchanged.
                                                                   // C is deleted (not in ours).
        let our_d = make_entity("fn_d", "src/d.rs"); // New.

        let their_a = make_entity_with_id(id_a, "fn_a", "src/a.rs"); // Unchanged.
        let mut their_b = make_entity_with_id(id_b, "fn_b", "src/b.rs");
        their_b.fingerprint.ast_hash = Hash256::from_bytes([0x22; 32]);
        let their_c = make_entity_with_id(id_c, "fn_c", "src/c.rs"); // Unchanged.
        let their_e = make_entity("fn_e", "src/e.rs"); // New.

        let base = vec![base_a, base_b, base_c];
        let ours = vec![our_a, our_b, our_d];
        let theirs = vec![their_a, their_b, their_c, their_e];

        let preview = Reconciler::analyze_merge_3way(&base, &ours, &theirs);
        assert!(
            preview.is_clean(),
            "non-overlapping complex merge should be clean"
        );
        // A modified by us → auto-resolved
        // B modified by them → auto-resolved
        // C deleted by us, unchanged by them → auto-resolved
        // D added by us → kept
        // E added by them → added
        assert!(preview.auto_resolved.contains(&id_a));
        assert!(preview.auto_resolved.contains(&id_b));
        assert!(preview.auto_resolved.contains(&id_c));
    }

    // ---------------------------------------------------------------
    // World preset wiring tests
    // ---------------------------------------------------------------

    use kin_model::preset::WorldPreset;

    #[test]
    fn default_reconciler_uses_brownfield_policy() {
        let dir = tempfile::tempdir().unwrap();
        let reconciler = Reconciler::new(dir.path().to_path_buf());
        let policy = reconciler.policy();
        assert_eq!(policy.broken_ast_behavior, BrokenAstBehavior::FallbackToLkg);
        assert_eq!(policy.validation_strictness, ValidationLevel::Lenient);
        assert!(policy.git_shadow);
    }

    #[test]
    fn with_policy_uses_explicit_policy() {
        let dir = tempfile::tempdir().unwrap();
        let policy = WorldPreset::KinNative.to_policy();
        let reconciler = Reconciler::with_policy(dir.path().to_path_buf(), policy);
        assert_eq!(
            reconciler.policy().broken_ast_behavior,
            BrokenAstBehavior::Reject
        );
        assert_eq!(
            reconciler.policy().validation_strictness,
            ValidationLevel::Strict
        );
        assert!(!reconciler.policy().git_shadow);
    }

    #[test]
    fn agent_execution_preset_wired_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let policy = WorldPreset::AgentExecution.to_policy();
        let reconciler = Reconciler::with_policy(dir.path().to_path_buf(), policy);
        assert_eq!(
            reconciler.policy().broken_ast_behavior,
            BrokenAstBehavior::Reject
        );
        assert_eq!(
            reconciler.policy().formatting_policy,
            kin_model::preset::FormattingPolicy::Strip
        );
        assert_eq!(
            reconciler.policy().projection_mode,
            kin_model::preset::ProjectionMode::Compact
        );
        assert_eq!(
            reconciler.policy().validation_strictness,
            ValidationLevel::Strict
        );
        assert!(!reconciler.policy().git_shadow);
    }

    #[test]
    fn validate_entity_rejects_empty_name() {
        let mut entity = make_entity("test", "src/lib.rs");
        entity.name = String::new();
        let reason = super::validate_entity(&entity);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("empty"));
    }

    #[test]
    fn validate_entity_rejects_empty_signature() {
        let mut entity = make_entity("test", "src/lib.rs");
        entity.signature = String::new();
        let reason = super::validate_entity(&entity);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("empty signature"));
    }

    #[test]
    fn validate_entity_accepts_valid() {
        let entity = make_entity("test", "src/lib.rs");
        assert!(super::validate_entity(&entity).is_none());
    }

    /// An external reference target has no signature by construction, so the
    /// empty-signature rule must be stated about declarations this repository
    /// parsed rather than about every entity. A target still has to satisfy every
    /// other rule.
    #[test]
    fn validate_entity_accepts_an_external_reference_target_without_a_signature() {
        let mut entity = make_entity("do_work", "src/lib.rs");
        entity.signature = String::new();
        entity.file_origin = None;
        entity.role = kin_model::EntityRole::External;
        assert!(
            kin_index::is_external_reference_target(&entity),
            "the fixture must be the shape admission binds"
        );
        assert!(super::validate_entity(&entity).is_none());

        entity.name = String::new();
        assert!(
            super::validate_entity(&entity).is_some(),
            "an external target is not exempt from the other rules"
        );
    }

    #[test]
    fn graph_authoritative_reconcile_retains_explicit_identity_across_rename() {
        use kin_blobs::BlobStore;
        use kin_db::InMemoryGraph;
        use kin_index::IndexedFile;
        use kin_model::{EntityStore, FileLayout, ImportSection, ParseCompleteness, ParseState};

        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("objects")).unwrap();
        let graph = InMemoryGraph::new();
        let file = FilePathId::new("src/lib.rs");
        let old = make_entity("before", &file.0);
        graph.upsert_entity(&old).unwrap();

        let mut renamed = old.clone();
        renamed.name = "after".to_string();
        renamed.signature = "fn after()".to_string();
        let body = b"pub fn after() {}\n";
        let blob_hash = blob_store.write(body).unwrap();
        let indexed = IndexedFile {
            file_id: file.clone(),
            language: LanguageId::Rust,
            entities: vec![renamed.clone()],
            relations: vec![],
            unresolved_relations: vec![],
            file_layout: FileLayout {
                file_id: file,
                parse_completeness: ParseCompleteness::Full,
                imports: ImportSection {
                    byte_range: 0..0,
                    items: vec![],
                },
                regions: vec![],
            },
            parse_state: ParseState::Valid,
            blob_hash,
            extracted_relations: vec![],
            imports: vec![],
        };
        let mut reconciler = Reconciler::new(std::path::PathBuf::new());
        let result = reconciler
            .reconcile_indexed_content(&indexed, &blob_store, &graph)
            .unwrap();

        assert_eq!(result.delta.entity_deltas.len(), 1);
        assert!(matches!(
            &result.delta.entity_deltas[0],
            EntityDelta::Modified { old: prior, new }
                if prior.id == old.id
                    && prior.name == "before"
                    && new.id == old.id
                    && new.name == "after"
        ));
        assert!(!result.delta.entity_deltas.iter().any(|delta| matches!(
            delta,
            EntityDelta::Added { .. } | EntityDelta::Removed { .. }
        )));
    }

    // ---------------------------------------------------------------
    // origin-filtered stale-removal regression test
    // ---------------------------------------------------------------

    /// Verify that a single-file reconcile only removes relations it could have
    /// re-derived from that file's index pass.  The test builds a graph with five
    /// pre-existing relations on entities of `file_a`, then reconciles `file_a`
    /// with an IndexedFile that has no relations in the fresh parse:
    ///
    ///   1. cross_file_rel   – Parsed, src is in file_b             → SURVIVES
    ///   2. manual_rel       – Manual, src in file_a, dst in file_b  → SURVIVES
    ///   3. lsp_rel          – Lsp, src in file_a, dst in file_b     → SURVIVES
    ///   4. stale_same_file  – Parsed, both endpoints in file_a      → REMOVED
    ///   5. manual_same_file – Manual, both endpoints in file_a      → SURVIVES
    ///
    /// The test also asserts that the entity absent from the re-parse is removed.
    #[test]
    fn stale_removal_preserves_cross_file_lsp_manual_relations() {
        use kin_blobs::BlobStore;
        use kin_db::InMemoryGraph;
        use kin_index::IndexedFile;
        use kin_model::{
            EntityStore, FileLayout, ImportSection, ParseCompleteness, ParseState, Relation,
            RelationId, RelationKind, RelationOrigin,
        };

        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("objects")).unwrap();
        let graph = InMemoryGraph::new();

        let file_a = "src/a.rs";
        let file_b = "src/b.rs";
        let file_a_path = dir.path().join(file_a);
        std::fs::create_dir_all(file_a_path.parent().unwrap()).unwrap();

        // Write minimal content for file_a so blob_store.read() succeeds.
        let content: &[u8] = b"pub fn foo() -> i32 { 1 }\n";
        std::fs::write(&file_a_path, content).unwrap();
        let blob_hash = blob_store.write(content).unwrap();

        // Entities: entity_a and stale_entity in file_a; entity_b in file_b.
        let entity_a = make_entity("foo", file_a);
        let stale_entity = make_entity("old_func", file_a);
        let entity_b = make_entity("bar", file_b);

        graph.upsert_entity(&entity_a).unwrap();
        graph.upsert_entity(&stale_entity).unwrap();
        graph.upsert_entity(&entity_b).unwrap();

        // Helper closure to build a Relation value.
        let make_rel = |id: RelationId,
                        kind: RelationKind,
                        src: GraphNodeId,
                        dst: GraphNodeId,
                        origin: RelationOrigin| Relation {
            id,
            kind,
            src,
            dst,
            confidence: 1.0,
            origin,
            created_in: None,
            import_source: None,
            evidence: vec![],
        };

        let cross_file_rel_id = RelationId::new();
        let manual_rel_id = RelationId::new();
        let lsp_rel_id = RelationId::new();
        let stale_same_file_rel_id = RelationId::new();
        let manual_same_file_rel_id = RelationId::new();

        // 1. Cross-file Parsed: entity_b (file_b) → Calls → entity_a (file_a).
        //    Simulates the cross-file linker run at init time.
        graph
            .upsert_relation(&make_rel(
                cross_file_rel_id,
                RelationKind::Calls,
                GraphNodeId::Entity(entity_b.id),
                GraphNodeId::Entity(entity_a.id),
                RelationOrigin::Parsed,
            ))
            .unwrap();
        // 2. Manual: entity_a → References → entity_b.  Agent-created via MCP.
        graph
            .upsert_relation(&make_rel(
                manual_rel_id,
                RelationKind::References,
                GraphNodeId::Entity(entity_a.id),
                GraphNodeId::Entity(entity_b.id),
                RelationOrigin::Manual,
            ))
            .unwrap();
        // 3. LSP: entity_a → Calls → entity_b.  LSP-enrichment edge.
        graph
            .upsert_relation(&make_rel(
                lsp_rel_id,
                RelationKind::Calls,
                GraphNodeId::Entity(entity_a.id),
                GraphNodeId::Entity(entity_b.id),
                RelationOrigin::Lsp,
            ))
            .unwrap();
        // 4. Stale same-file Parsed: entity_a → Calls → stale_entity (both in file_a).
        //    This is the relation that the reconcile SHOULD remove — the re-parse no
        //    longer produces it because stale_entity was deleted from the file.
        graph
            .upsert_relation(&make_rel(
                stale_same_file_rel_id,
                RelationKind::Calls,
                GraphNodeId::Entity(entity_a.id),
                GraphNodeId::Entity(stale_entity.id),
                RelationOrigin::Parsed,
            ))
            .unwrap();
        // 5. Manual same-file: entity_a → OwnedBy → stale_entity.
        //    Removing stale_entity requires this relation's complete old state to
        //    be removed in the same exact transaction, regardless of origin.
        graph
            .upsert_relation(&make_rel(
                manual_same_file_rel_id,
                RelationKind::OwnedBy,
                GraphNodeId::Entity(entity_a.id),
                GraphNodeId::Entity(stale_entity.id),
                RelationOrigin::Manual,
            ))
            .unwrap();

        // Seed the reconciler LKG with the file_a entities.
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        reconciler.lkg.record(&entity_a);
        reconciler.lkg.record(&stale_entity);

        // Construct an IndexedFile that represents a re-parse of file_a:
        //   - entity_a is present (same name/kind → matched, no fingerprint change)
        //   - stale_entity is absent → produces an exact removal
        //   - relations is empty → no same-file relations re-derived
        let indexed = IndexedFile {
            file_id: FilePathId::new(file_a),
            language: kin_model::LanguageId::Rust,
            entities: vec![entity_a.clone()],
            relations: vec![],
            unresolved_relations: vec![],
            file_layout: FileLayout {
                file_id: FilePathId::new(file_a),
                parse_completeness: ParseCompleteness::Full,
                imports: ImportSection {
                    byte_range: 0..0,
                    items: vec![],
                },
                regions: vec![],
            },
            parse_state: ParseState::Valid,
            blob_hash,
            extracted_relations: vec![],
            imports: vec![],
        };

        let result = reconciler
            .reconcile_file_edit_inner(
                &indexed,
                &FilePathId::new(file_a),
                &file_a_path,
                &blob_store,
                &graph,
            )
            .expect("reconcile_file_edit_inner should succeed");
        let removed_relation_ids: HashSet<_> = result
            .delta
            .relation_deltas
            .iter()
            .filter_map(|delta| match delta {
                RelationDelta::Removed { old } => Some(old.id),
                RelationDelta::Added { .. } | RelationDelta::Modified { .. } => None,
            })
            .collect();

        // --- Relation survival assertions ---

        assert!(
            !removed_relation_ids.contains(&cross_file_rel_id),
            "cross-file Parsed edge must NOT be removed by single-file reconcile"
        );
        assert!(
            !removed_relation_ids.contains(&manual_rel_id),
            "Manual relation must NOT be removed by reconcile"
        );
        assert!(
            !removed_relation_ids.contains(&lsp_rel_id),
            "Lsp relation must NOT be removed by reconcile"
        );
        assert!(
            removed_relation_ids.contains(&stale_same_file_rel_id),
            "stale same-file Parsed relation MUST be removed by reconcile"
        );
        assert!(
            removed_relation_ids.contains(&manual_same_file_rel_id),
            "relation to a removed entity must be removed atomically"
        );

        // --- Entity removal assertion ---
        assert!(
            result.delta.entity_deltas.iter().any(
                |delta| matches!(delta, EntityDelta::Removed { old } if old.id == stale_entity.id)
            ),
            "stale_entity must have an exact removal (absent from re-parse)"
        );
    }

    // ------------------------------------------------------- FIR-2644 helpers

    fn span(file: &str, start_line: u32, end_line: u32) -> kin_model::SourceSpan {
        kin_model::SourceSpan {
            file: FilePathId::new(file),
            start_byte: 0,
            end_byte: 0,
            start_line,
            start_col: 0,
            end_line,
            end_col: 0,
        }
    }

    fn relation_of(origin: kin_model::RelationOrigin) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(EntityId::new()),
            dst: GraphNodeId::Entity(EntityId::new()),
            confidence: 1.0,
            origin,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    /// A parser edge must never take a language-server edge's identity.
    ///
    /// Both are held under one `(src, dst, kind)` key with two ids, and taking
    /// the lowest id bound the re-derived parser payload onto whichever sorted
    /// first. When that was the enrichment edge, the parser edge went unmatched
    /// and survived carrying its pre-edit span (FIR-2644).
    #[test]
    fn a_parser_edge_keeps_a_parser_identity_beside_an_enrichment_one() {
        let enrichment = relation_of(kin_model::RelationOrigin::Lsp);
        let parsed = relation_of(kin_model::RelationOrigin::Parsed);
        let bucket = vec![enrichment.clone(), parsed.clone()];
        assert_eq!(
            parser_identity_to_keep(Some(&bucket)).map(|relation| relation.id),
            Some(parsed.id),
            "the parser edge is the one whose identity a re-derived parse keeps"
        );
    }

    /// FALSIFICATION half: a bucket with no parser edge yields no identity, so
    /// the caller adds rather than overwriting the enrichment edge.
    #[test]
    fn an_enrichment_only_bucket_offers_no_identity_to_take_over() {
        let bucket = vec![
            relation_of(kin_model::RelationOrigin::Lsp),
            relation_of(kin_model::RelationOrigin::Manual),
        ];
        assert!(parser_identity_to_keep(Some(&bucket)).is_none());
        assert!(parser_identity_to_keep(None).is_none());
    }

    /// An `Inferred` edge is parser-derived on the same footing as a `Parsed`
    /// one, because the retire rules already treat the two as one class and a
    /// disagreement here would retire an edge the matcher refused to claim.
    #[test]
    fn an_inferred_edge_counts_as_a_parser_identity() {
        let inferred = relation_of(kin_model::RelationOrigin::Inferred);
        let bucket = vec![
            relation_of(kin_model::RelationOrigin::Lsp),
            inferred.clone(),
        ];
        assert_eq!(
            parser_identity_to_keep(Some(&bucket)).map(|relation| relation.id),
            Some(inferred.id)
        );
    }

    /// A declaration that only moved carries its interior with it.
    #[test]
    fn a_span_inside_a_declaration_that_moved_is_placed_where_it_moved_to() {
        let moves = vec![(span("sessions.py", 30, 40), span("sessions.py", 56, 66))];
        let placed = reanchor_evidence_span(&span("sessions.py", 34, 34), &moves)
            .expect("a translated declaration can place its interior");
        assert_eq!((placed.start_line, placed.end_line), (60, 60));
    }

    /// The innermost declaration decides, so a method inside a class is placed
    /// by the method rather than by the class it sits in.
    #[test]
    fn the_innermost_declaration_places_the_span() {
        let moves = vec![
            (span("sessions.py", 0, 80), span("sessions.py", 0, 106)),
            (span("sessions.py", 30, 40), span("sessions.py", 56, 66)),
        ];
        let placed = reanchor_evidence_span(&span("sessions.py", 34, 34), &moves)
            .expect("the method places it");
        assert_eq!((placed.start_line, placed.end_line), (60, 60));
    }

    /// FALSIFICATION: a declaration whose extent changed cannot say where its
    /// interior went, so the span is refused rather than shifted by a delta the
    /// interior may not share.
    #[test]
    fn a_declaration_that_grew_refuses_to_place_its_interior() {
        let moves = vec![(span("sessions.py", 30, 40), span("sessions.py", 56, 70))];
        assert!(reanchor_evidence_span(&span("sessions.py", 34, 34), &moves).is_none());
    }

    /// FALSIFICATION: a span no declaration contains is refused too. Guessing
    /// it from the file's overall shift would be a fabricated line.
    #[test]
    fn a_span_outside_every_declaration_is_refused() {
        let moves = vec![(span("sessions.py", 30, 40), span("sessions.py", 56, 66))];
        assert!(reanchor_evidence_span(&span("sessions.py", 5, 5), &moves).is_none());
    }

    /// A span in another file is not this pass's business and is left alone.
    #[test]
    fn a_span_in_another_file_is_left_untouched() {
        let moves = vec![(span("sessions.py", 30, 40), span("sessions.py", 56, 66))];
        let relation = {
            let mut relation = relation_of(kin_model::RelationOrigin::Lsp);
            relation.evidence = vec![kin_model::RelationEvidence {
                source_span: Some(span("adapters.py", 34, 34)),
                ..kin_model::RelationEvidence::default()
            }];
            relation
        };
        assert!(
            relation_with_reanchored_evidence(&relation, &FilePathId::new("sessions.py"), &moves)
                .is_none(),
            "a span this pass is not authoritative over must not be rewritten"
        );
    }

    /// A span that cannot be placed is cleared, not carried. An absent line and
    /// a wrong line are different answers and only one of them is honest.
    #[test]
    fn an_unplaceable_span_is_cleared_rather_than_carried() {
        let moves = vec![(span("sessions.py", 30, 40), span("sessions.py", 56, 70))];
        let mut relation = relation_of(kin_model::RelationOrigin::Lsp);
        relation.evidence = vec![kin_model::RelationEvidence {
            source_span: Some(span("sessions.py", 34, 34)),
            ..kin_model::RelationEvidence::default()
        }];
        let updated =
            relation_with_reanchored_evidence(&relation, &FilePathId::new("sessions.py"), &moves)
                .expect("the span changed, so a delta is owed");
        assert!(updated.evidence[0].source_span.is_none());
    }
}
