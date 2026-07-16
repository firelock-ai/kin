// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Graph→file projection seam for MCP transaction commits.
//!
//! After `kin_transaction_commit` applies entity mutations to the graph,
//! [`project_after_mcp_commit`] drives `project_overlay_to_files` so the
//! working-directory files stay in sync with graph truth. Without this step
//! the next reconcile tick re-parses the unchanged file, detects a fingerprint
//! mismatch (or a name mismatch for renames), and silently overwrites the
//! agent's graph mutations — file-wins LWW.
//!
//! # Chosen failure semantics
//!
//! The graph mutation is committed before projection is attempted. If projection
//! fails, the graph already reflects the agent's intent; the error is surfaced
//! loud to the caller (structured `McpProjectionError`) but the graph mutation
//! is **not rolled back**. This keeps the graph-side commit atomic and lets the
//! agent retry the projection or inspect the failure.
//!
//! # Conflict detection
//!
//! Before each splice is attempted, the current on-disk file content is compared
//! against the projection cache's last-reconciled snapshot at the entity's span.
//! A byte-range mismatch indicates a concurrent human file edit.  Conflicted
//! entities are **skipped** (not spliced); a structured [`kin_model::ConflictObject`]
//! is returned for each one so the caller can surface an actionable message.
//! Non-conflicted entities in the same overlay still project normally
//! (skip-conflicted, not abort-all).
//!
//! # Reparse-equivalence invariant
//!
//! After every successful splice, the projected bytes at the entity's span are
//! compared with the pre-projection cached bytes.  A mismatch means the CST
//! splice silently garbled the entity body — this is surfaced as a loud error,
//! never silent.  NOTE: this check verifies that the splice preserved the byte
//! representation, not that the file compiles; full compilation-at-runtime is
//! out of scope and is not attempted here.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use kin_index::FileEvent;
use kin_model::{ConflictObject, Entity, EntityId, FilePathId, GraphOverlay};
use kin_reconcile::{apply_overlay_to_graph, ReconcileError};

use crate::state::DaemonState;

/// A structured error from a failed MCP→file projection.
///
/// Names both the entity and the file so the caller can surface an actionable
/// message without requiring the agent to grep logs.
#[derive(Debug)]
pub struct McpProjectionError {
    /// The file that could not be projected (absent for span-less entities).
    pub file: Option<FilePathId>,
    /// The entity that triggered the projection failure.
    pub entity_id: EntityId,
    /// Human-readable reason for the failure.
    pub reason: String,
}

impl std::fmt::Display for McpProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.file {
            Some(fp) => write!(
                f,
                "projection failed for entity {} in {}: {}",
                self.entity_id, fp, self.reason
            ),
            None => write!(
                f,
                "projection failed for entity {}: {}",
                self.entity_id, self.reason
            ),
        }
    }
}

/// Project entity mutations from an MCP commit into the working-directory files.
///
/// Call this **after** the graph delta has been applied via
/// `apply_transaction_delta`. It builds a [`GraphOverlay`] from the
/// `pre_commit_entities` — the entities read from the graph *before* the commit
/// so they carry the source spans set by the last reconcile — and feeds that
/// overlay to [`kin_reconcile::Reconciler::project_overlay_to_files`].
///
/// # Arguments
///
/// * `state` — shared daemon state; the reconciler and projection locks are
///   acquired for the duration of the call.
/// * `pre_commit_entities` — entities looked up from the graph immediately
///   before the delta was applied. These must have their `span` and
///   `file_origin` populated (set during the preceding reconcile). Entities
///   without a span are silently skipped — new graph-only entities have no
///   file placement yet.
/// * `supplied_bodies` — new full UTF-8 source bytes for entities whose
///   staged operation carried a `body`, keyed by `EntityId`. When an entity has
///   a supplied body the projection writes that text into the file (rather than
///   re-splicing the file's own bytes — an identity no-op), so the agent's graph
///   mutation actually reaches disk. After projecting a body edit the file bytes
///   change, so each touched file is re-reconciled here to converge the
///   reconciler LKG baseline and the graph onto the projected source — without
///   that resync the next reconcile would see a fresh fingerprint, diverge from
///   the stale LKG, and clobber the agent's mutation (file-wins LWW).
///
/// # Returns
///
/// `Ok((modified_files, collision_warnings, conflicts))` on success, where
/// `conflicts` lists any entities that were skipped due to concurrent file edits
/// (skip-conflicted semantics).  A non-empty `conflicts` vec means
/// some entities were NOT projected; the caller should surface each conflict to
/// the agent.  Returns [`McpProjectionError`] naming the first failing entity +
/// file on a hard projection error.
pub async fn project_after_mcp_commit(
    state: &Arc<DaemonState>,
    pre_commit_entities: &[Entity],
    supplied_bodies: &HashMap<EntityId, Vec<u8>>,
) -> Result<
    (
        Vec<FilePathId>,
        Vec<kin_model::IntentSummary>,
        Vec<ConflictObject>,
    ),
    McpProjectionError,
> {
    let filesystem_reconcile_disabled = state.filesystem_reconcile_disabled();

    // Build a GraphOverlay with entity_mods for every entity that has a source
    // span (placement in a working-directory file). Span-less entities are new
    // graph-only nodes with no file home yet — skip them gracefully.
    let mut temp_overlay = GraphOverlay::default();
    for entity in pre_commit_entities {
        if entity.file_origin.is_some() && entity.span.is_some() {
            temp_overlay.entity_mods.insert(entity.id, entity.clone());
        }
    }

    if temp_overlay.entity_mods.is_empty() {
        // Nothing to project — all mutations were span-less (new entities or
        // relation-only operations). Not an error.
        return Ok((vec![], vec![], vec![]));
    }

    // Acquire the reconciler write lock — same locking discipline as loop_runner
    // and vfs_write_notify: hold the lock for the full duration of the projection
    // so we do not race with a concurrent reconcile tick that could invalidate
    // the projection cache entries we are about to use.
    let mut reconciler = state.reconciler.write().await;

    // -----------------------------------------------------------------------
    // Cold-projection priming.
    //
    // The reconciler's projection state (file layouts + content) is the map
    // `project_overlay_to_files` uses to locate each entity's byte region and
    // splice the new body in. On a freshly-started or restarted daemon that map
    // is cold: `DaemonState::open` seeds the reconciler's LKG from the persisted
    // graph but never registers any file layout (no reconcile tick has run yet).
    // With no layout for the entity's file, `project_entity_mutations_with_policy`
    // finds no region for the mutation and silently skips it — the graph commit
    // lands (root hash advances, ops_applied > 0) but `modified_files` comes back
    // empty and the working file is never touched. That is the silent
    // no-op the MCP write loop hit on the first commit after daemon start.
    //
    // Prime the projection from graph + disk truth before projecting: reconcile
    // each referenced file that is not yet registered, which parses the current
    // source and registers its layout + content. The detected overlay is
    // discarded — we only need the projection registration here, not a graph
    // mutation (the agent's commit already landed, and the no-clobber
    // resync below reconverges the graph onto the projected source afterwards).
    // Files missing from disk are left to the existing structured-error path.
    {
        let mut primed: HashSet<FilePathId> = HashSet::new();
        for entity in temp_overlay.entity_mods.values() {
            let Some(span) = &entity.span else {
                continue;
            };
            if reconciler.projection().get_content(&span.file).is_some() {
                continue;
            }
            if !primed.insert(span.file.clone()) {
                continue;
            }
            if filesystem_reconcile_disabled {
                return Err(McpProjectionError {
                    file: entity.file_origin.clone(),
                    entity_id: entity.id,
                    reason: format!(
                        "cold projection cannot be primed from filesystem bytes while {} is enabled; graph commit remains authoritative and no filesystem reparse was attempted",
                        crate::loop_runner::DISABLE_FILESYSTEM_RECONCILE_ENV
                    ),
                });
            }
            let path = state.layout.working_dir().join(span.file.0.as_str());
            if !path.exists() {
                continue;
            }
            let mut prime_overlay = GraphOverlay::default();
            reconciler
                .reconcile_file_change(
                    &FileEvent::Changed(path),
                    state.blobs.as_ref(),
                    state.graph.as_ref(),
                    &mut prime_overlay,
                )
                .map_err(|e| reconcile_err_to_projection_err(e, pre_commit_entities))?;
        }
    }

    // -----------------------------------------------------------------------
    // Conflict detection — skip-conflicted semantics.
    //
    // For each entity in the overlay, compare the current on-disk file bytes at
    // the entity's span against the projection cache's last-reconciled content.
    // A byte-range mismatch means a concurrent human file edit occurred between
    // the last reconcile and now.  Conflicted entities are removed from the
    // overlay and returned as structured ConflictObjects; non-conflicted entities
    // still project normally (abort-all would block all projections when only
    // one entity is touched by a human editor, which is the common partial-edit
    // case the concurrent-dogfood workflow exercises).
    // -----------------------------------------------------------------------
    let mut conflicts: Vec<ConflictObject> = Vec::new();
    let mut clean_overlay = GraphOverlay::default();

    for (entity_id, entity) in &temp_overlay.entity_mods {
        let Some(span) = &entity.span else {
            // Span-less entity: cannot have a concurrent file conflict, project it.
            clean_overlay.entity_mods.insert(*entity_id, entity.clone());
            continue;
        };

        // Get the last-reconciled content for this file from the projection cache.
        let cached_opt = reconciler
            .projection()
            .get_content(&span.file)
            .map(|b| b.to_vec());

        let Some(cached) = cached_opt else {
            // No cached content for this file: cannot compare, project it and let
            // the engine's own pre-write check (engine.rs line ~209) handle any
            // concurrent edit at the commit layer.
            clean_overlay.entity_mods.insert(*entity_id, entity.clone());
            continue;
        };

        // Read the current on-disk file to detect a concurrent human edit.
        let disk_bytes = {
            let file_path = state.layout.working_dir().join(span.file.0.as_str());
            std::fs::read(&file_path).unwrap_or_default()
        };

        // Extract bytes at the entity's span from both the cache and disk.
        let span_start = span.start_byte;
        let cache_span_end = span.end_byte.min(cached.len());
        let disk_span_end = span.end_byte.min(disk_bytes.len());

        let cached_at_span: &[u8] = if span_start < cache_span_end {
            &cached[span_start..cache_span_end]
        } else {
            &[]
        };
        let disk_at_span: &[u8] = if span_start < disk_span_end {
            &disk_bytes[span_start..disk_span_end]
        } else {
            &[]
        };

        if cached_at_span != disk_at_span {
            // Concurrent human edit detected: disk has different bytes at this
            // entity's span than the projection cache's last-reconciled snapshot.
            // Build a stub entity representing the disk state for detect_conflict.
            let disk_ast_hash =
                kin_blobs::Hash256::from_bytes(kin_blobs::digest_bytes(disk_at_span));
            let mut disk_entity_stub = entity.clone();
            disk_entity_stub.fingerprint.ast_hash = disk_ast_hash;

            if let Some(conflict) = reconciler.detect_conflict(entity_id, entity, &disk_entity_stub)
            {
                tracing::warn!(
                    entity_id = %entity_id,
                    file = %span.file,
                    "concurrent file edit at entity span — skipping projection, \
                     conflict surfaced to caller"
                );
                conflicts.push(conflict);
                continue; // skip this entity: do NOT splice over the human's edit
            }
        }

        clean_overlay.entity_mods.insert(*entity_id, entity.clone());
    }

    // Carry the agent-supplied new source text for each non-conflicted
    // entity onto the overlay. `project_overlay_to_files` prefers this over the
    // identity span-extract, so the file is written with the agent's new body.
    let clean_ids: Vec<EntityId> = clean_overlay.entity_mods.keys().copied().collect();
    for id in clean_ids {
        if let Some(body) = supplied_bodies.get(&id) {
            clean_overlay.entity_bodies.insert(id, body.clone());
        }
    }

    // If every entity had a conflict, nothing to project.
    if clean_overlay.entity_mods.is_empty() {
        return Ok((vec![], vec![], conflicts));
    }

    // -----------------------------------------------------------------------
    // Project the non-conflicted entities.
    // -----------------------------------------------------------------------
    // Snapshot the pre-projection cached content for the reparse-equivalence
    // check below.  We only need it for files that will actually be modified,
    // but collecting it here (before the mutable borrow of reconciler for the
    // projection call) is the cleanest approach under Rust's borrow rules.
    let pre_projection_content: std::collections::HashMap<FilePathId, Vec<u8>> = clean_overlay
        .entity_mods
        .values()
        .filter_map(|e| e.span.as_ref())
        .map(|span| {
            let content = reconciler
                .projection()
                .get_content(&span.file)
                .map(|b| b.to_vec())
                .unwrap_or_default();
            (span.file.clone(), content)
        })
        .collect();

    let (modified_files, collision_warnings) = reconciler
        .project_overlay_to_files(&clean_overlay)
        .map_err(|e| reconcile_err_to_projection_err(e, pre_commit_entities))?;

    // -----------------------------------------------------------------------
    // Reparse-equivalence invariant.
    //
    // For each entity that was projected, verify that the projected file content
    // at the entity's span is byte-identical to the pre-projection cached content.
    // A mismatch indicates the CST splice silently garbled the entity body — this
    // is surfaced as a loud structured error, never silent.
    //
    // NOTE: this verifies byte-level splice preservation, NOT that the file
    // compiles.  Full compilation-at-runtime is out of scope; the check is named
    // "reparse-equivalence" because it guards the engine contract that a subsequent
    // reconcile must NOT see the projected entity as changed (no-clobber invariant).
    // -----------------------------------------------------------------------
    for entity in clean_overlay.entity_mods.values() {
        // A body edit intentionally rewrites the bytes at the entity's
        // span, so byte preservation does NOT apply. The no-clobber guarantee for
        // body edits is enforced instead by the LKG/graph resync below (which
        // re-derives the entity from the projected source). The check still
        // guards metadata-only edits, which must remain byte-identical.
        if clean_overlay.entity_bodies.contains_key(&entity.id) {
            continue;
        }

        let Some(span) = &entity.span else {
            continue;
        };

        // Only check files that were actually modified.
        if !modified_files.contains(&span.file) {
            continue;
        }

        let post_content = reconciler.projection().get_content(&span.file);
        let Some(post) = post_content else {
            // Projection cache was not updated for this file (e.g. the engine
            // skipped it due to its own concurrent-edit check).  Not a
            // reparse-equivalence violation on our part.
            continue;
        };

        let pre = pre_projection_content.get(&span.file).map(|v| v.as_slice());
        let Some(pre) = pre else {
            continue;
        };

        // Extract the entity bytes at the span from both snapshots.
        let span_start = span.start_byte;
        let pre_end = span.end_byte.min(pre.len());
        let post_end = span.end_byte.min(post.len());

        let pre_at_span: &[u8] = if span_start < pre_end {
            &pre[span_start..pre_end]
        } else {
            &[]
        };
        let post_at_span: &[u8] = if span_start < post_end {
            &post[span_start..post_end]
        } else {
            &[]
        };

        if pre_at_span != post_at_span {
            // The splice altered the entity's bytes — this violates the
            // no-clobber contract and means the next reconcile will see the
            // entity as changed and may clobber the graph mutation.
            return Err(McpProjectionError {
                file: entity.file_origin.clone(),
                entity_id: entity.id,
                reason: format!(
                    "reparse-equivalence violation: splice altered entity bytes at {}..{} \
                     in {}; {pre_len} pre-projection bytes → {post_len} \
                     post-projection bytes",
                    span.start_byte,
                    span.end_byte,
                    span.file,
                    pre_len = pre_at_span.len(),
                    post_len = post_at_span.len(),
                ),
            });
        }
    }

    // -----------------------------------------------------------------------
    // No-clobber resync.
    //
    // A body edit rewrote the file's bytes, so the reconciler's LKG fingerprint
    // baseline (recorded by the previous reconcile) and the committed graph
    // entity are now stale relative to the projected source. Re-reconcile each
    // body-carried file so both converge onto what the file actually parses to.
    // Without this, the next reconcile tick re-parses a fresh fingerprint, finds
    // it differs from the stale LKG, and clobbers the agent's mutation
    // (file-wins LWW) — the very bug this carrier exists to close.
    //
    // Metadata-only edits carry no body and are skipped here: their projection is
    // byte-identical, so the LKG baseline already matches and no resync is needed.
    // -----------------------------------------------------------------------
    if !clean_overlay.entity_bodies.is_empty() && !filesystem_reconcile_disabled {
        let body_files: HashSet<FilePathId> = clean_overlay
            .entity_mods
            .values()
            .filter(|e| clean_overlay.entity_bodies.contains_key(&e.id))
            .filter_map(|e| e.span.as_ref().map(|s| s.file.clone()))
            .collect();

        for file_id in &modified_files {
            if !body_files.contains(file_id) {
                continue;
            }
            let path = state.layout.working_dir().join(file_id.0.as_str());
            let mut resync_overlay = GraphOverlay::default();
            reconciler
                .reconcile_file_change(
                    &FileEvent::Changed(path),
                    state.blobs.as_ref(),
                    state.graph.as_ref(),
                    &mut resync_overlay,
                )
                .map_err(|e| reconcile_err_to_projection_err(e, pre_commit_entities))?;
            apply_overlay_to_graph(state.graph.as_ref(), &mut resync_overlay).map_err(|e| {
                McpProjectionError {
                    file: Some(file_id.clone()),
                    entity_id: EntityId::default(),
                    reason: format!("no-clobber resync: failed to apply reconciled overlay: {e}"),
                }
            })?;
        }
    } else if !clean_overlay.entity_bodies.is_empty() {
        tracing::debug!(
            env = crate::loop_runner::DISABLE_FILESYSTEM_RECONCILE_ENV,
            "skipping post-projection filesystem reparse; graph remains authoritative"
        );
    }

    Ok((modified_files, collision_warnings, conflicts))
}

/// Convert a [`ReconcileError`] from `project_overlay_to_files` into a
/// [`McpProjectionError`] with as much entity + file context as available.
fn reconcile_err_to_projection_err(
    err: ReconcileError,
    pre_commit_entities: &[Entity],
) -> McpProjectionError {
    // Helper: resolve file_origin for a given entity_id from our snapshot.
    let file_for = |entity_id: &EntityId| -> Option<FilePathId> {
        pre_commit_entities
            .iter()
            .find(|e| e.id == *entity_id)
            .and_then(|e| e.file_origin.clone())
    };

    match &err {
        ReconcileError::BodyExtractionFailed { entity_id, reason } => McpProjectionError {
            file: file_for(entity_id),
            entity_id: *entity_id,
            reason: reason.clone(),
        },
        // CollisionBlocked does not carry an entity_id — use the first entity
        // as best-effort context since the scope check covers all overlay entities.
        _ => {
            let first = pre_commit_entities.first();
            McpProjectionError {
                file: first.and_then(|e| e.file_origin.clone()),
                entity_id: first.map(|e| e.id).unwrap_or_default(),
                reason: err.to_string(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use kin_blobs::BlobStore;
    use kin_db::EntityStore;
    use kin_index::FileEvent;
    use kin_model::{
        EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm, GraphOverlay,
        Hash256, LanguageId, SemanticFingerprint, SourceSpan, Visibility,
    };
    use kin_reconcile::{apply_overlay_to_graph, Reconciler};

    use crate::state::DaemonState;

    // ------------------------------------------------------------------
    // Test-state factory: builds a minimal DaemonState backed by a real
    // working directory so projection can write actual files.
    // ------------------------------------------------------------------

    fn make_test_state(working_dir: &std::path::Path) -> Arc<DaemonState> {
        let kin_dir = working_dir.join(".kin");
        std::fs::create_dir_all(kin_dir.join("objects")).unwrap();
        std::fs::create_dir_all(kin_dir.join("working")).unwrap();
        let layout = kin_core::KinLayout::new(kin_dir);
        kin_core::manifest::KinManifest::new()
            .save(&layout.manifest_path())
            .unwrap();
        Arc::new(DaemonState::open(layout).unwrap())
    }

    // ------------------------------------------------------------------
    // Assertion helper: reconcile the file and assert no entity changes.
    // ------------------------------------------------------------------

    fn assert_no_clobber(
        reconciler: &mut Reconciler,
        state: &Arc<DaemonState>,
        file_path: &std::path::Path,
    ) {
        let blob_store = BlobStore::new(state.layout.objects_dir()).expect("blob store must open");
        let mut overlay = GraphOverlay::default();
        reconciler
            .reconcile_file_change(
                &FileEvent::Changed(file_path.to_path_buf()),
                &blob_store,
                state.graph.as_ref(),
                &mut overlay,
            )
            .expect("reconcile must succeed");

        assert!(
            overlay.entity_mods.is_empty(),
            "reconcile after projection must produce no entity_mods (no-clobber); \
             got {} modification(s)",
            overlay.entity_mods.len()
        );
        assert!(
            overlay.entity_adds.is_empty(),
            "reconcile after projection must produce no entity_adds; got {} add(s)",
            overlay.entity_adds.len()
        );
        assert!(
            overlay.entity_removes.is_empty(),
            "reconcile after projection must produce no entity_removes; got {} removal(s)",
            overlay.entity_removes.len()
        );
    }

    // ------------------------------------------------------------------
    // Test 1 (a+b): project a modified entity → file written, no clobber.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn project_after_commit_writes_file_and_no_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let state = make_test_state(dir.path());
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);

        // Write a Rust source file with two functions so trivia preservation
        // can be verified (surrounding formatting must survive the projection).
        let rel = "src/lib.rs";
        let file_path = dir.path().join(rel);
        std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        let original = b"pub fn foo() -> i32 { 1 }\npub fn bar() -> i32 { 2 }\n";
        std::fs::write(&file_path, original).unwrap();

        let blob_store = BlobStore::new(state.layout.objects_dir()).expect("blob store must open");

        // Step 1: First reconcile — entities enter as entity_adds, LKG primed.
        let mut reconciler = state.reconciler.write().await;
        let mut overlay = GraphOverlay::default();
        reconciler
            .reconcile_file_change(
                &FileEvent::Changed(file_path.clone()),
                &blob_store,
                state.graph.as_ref(),
                &mut overlay,
            )
            .expect("first reconcile must succeed");

        // After the first reconcile, entity_adds contains the newly discovered
        // entities complete with source spans.  Grab "foo" from the overlay
        // directly — this is the pre-commit entity: spans already set, before
        // the agent's subsequent graph mutation.
        let pre_commit_entity = overlay
            .entity_adds
            .values()
            .find(|e| e.name == "foo")
            .cloned()
            .expect("foo must be present in the reconcile overlay");

        assert!(
            pre_commit_entity.span.is_some(),
            "pre-commit entity must have a span (set by reconcile)"
        );

        // Apply overlay to graph (normally done by loop_runner).
        apply_overlay_to_graph(state.graph.as_ref(), &mut overlay)
            .expect("apply overlay must succeed");

        // Step 2: Simulate the graph-side commit (agent updates entity metadata
        // without changing the file). The graph now has a modified fingerprint
        // while the file is still unchanged.
        let mut modified = pre_commit_entity.clone();
        modified.fingerprint.ast_hash = Hash256::from_bytes([0xab; 32]); // agent-set value
        state.graph.upsert_entity(&modified).unwrap();

        // Step 3: Call project_after_mcp_commit (the production hook).
        drop(reconciler); // release lock before calling the async helper
        let (modified_files, warnings, conflicts) = project_after_mcp_commit(
            &state,
            std::slice::from_ref(&pre_commit_entity),
            &HashMap::new(),
        )
        .await
        .expect("projection must succeed");

        assert_eq!(
            modified_files.len(),
            1,
            "exactly one file should be projected; got {}",
            modified_files.len()
        );
        assert!(
            warnings.is_empty(),
            "no collision warnings expected; got {}",
            warnings.len()
        );
        assert!(
            conflicts.is_empty(),
            "no conflicts expected (no concurrent edit); got {}",
            conflicts.len()
        );

        // Step 4 (assertion a): file exists with content — surrounding formatting
        // (the two-function layout + trailing newline) must be preserved.
        let on_disk = std::fs::read(&file_path).expect("projected file must exist on disk");
        assert_eq!(
            on_disk, original,
            "file content must be preserved (same bytes, formatting intact)"
        );

        // Step 5 (assertion b): a subsequent reconcile must produce NO entity
        // changes — the projection updated the projection cache so the LKG
        // comparison sees no delta (no-clobber guarantee).
        let mut reconciler2 = state.reconciler.write().await;
        assert_no_clobber(&mut reconciler2, &state, &file_path);
    }

    // ------------------------------------------------------------------
    // Test 1b: project a REAL body edit → file gets the agent's new
    // source text (not an identity no-op), then reconcile → no clobber.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn project_body_edit_writes_new_text_and_no_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let state = make_test_state(dir.path());
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let rel = "src/lib.rs";
        let file_path = dir.path().join(rel);
        std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        let original = b"pub fn foo() -> i32 { 1 }\npub fn bar() -> i32 { 2 }\n";
        std::fs::write(&file_path, original).unwrap();

        let blob_store = BlobStore::new(state.layout.objects_dir()).expect("blob store must open");

        // Step 1: reconcile — entities enter with spans; LKG primed at the
        // ORIGINAL body fingerprint.
        let mut reconciler = state.reconciler.write().await;
        let mut overlay = GraphOverlay::default();
        reconciler
            .reconcile_file_change(
                &FileEvent::Changed(file_path.clone()),
                &blob_store,
                state.graph.as_ref(),
                &mut overlay,
            )
            .expect("first reconcile must succeed");

        let pre_commit_entity = overlay
            .entity_adds
            .values()
            .find(|e| e.name == "foo")
            .cloned()
            .expect("foo must be present in the reconcile overlay");
        let span = pre_commit_entity
            .span
            .clone()
            .expect("foo must have a span");

        apply_overlay_to_graph(state.graph.as_ref(), &mut overlay)
            .expect("apply overlay must succeed");
        drop(reconciler);

        // The agent's NEW source for foo: take the exact bytes occupying foo's
        // span and rewrite the body literal, so the splice yields valid Rust.
        let orig_region = &original[span.start_byte..span.end_byte];
        let new_body = String::from_utf8_lossy(orig_region)
            .replace("{ 1 }", "{ 42 }")
            .into_bytes();
        assert_ne!(
            new_body.as_slice(),
            orig_region,
            "test setup: new body must differ from the original region"
        );

        // Step 2: simulate the graph-side commit of the body edit — the graph
        // entity is updated with the agent's intent (fingerprint changed); span
        // and file_origin are preserved, as collect_pre_commit_entities carries
        // them from the graph.
        let mut committed = pre_commit_entity.clone();
        committed.fingerprint.ast_hash = Hash256::from_bytes([0xcd; 32]);
        state.graph.upsert_entity(&committed).unwrap();

        // Revision-churn guard (baseline): the no-clobber resync must converge
        // LKG + graph via REVISION-FREE upsert — it must NOT mint a SemanticChange
        // or append an EntityRevision generation. A new head revision retires the
        // prior vector and re-embeds, so a revision minted here would mean spurious
        // re-embed churn on every MCP body edit. Capture the change-DAG and
        // revision-generation counts now; assert them identical immediately after
        // project_after_mcp_commit below.
        let snap_before = state.graph.to_snapshot();
        let changes_before = snap_before.changes.len();
        let revisions_before: usize = snap_before.entity_revisions.values().map(|v| v.len()).sum();

        // Step 3: project with the supplied body (the body carrier).
        let mut bodies = HashMap::new();
        bodies.insert(pre_commit_entity.id, new_body.clone());
        let (modified_files, warnings, conflicts) =
            project_after_mcp_commit(&state, std::slice::from_ref(&pre_commit_entity), &bodies)
                .await
                .expect("projection must succeed");

        assert_eq!(modified_files.len(), 1, "exactly one file projected");
        assert!(warnings.is_empty(), "no collision warnings expected");
        assert!(conflicts.is_empty(), "no conflicts expected");

        // Revision-churn guard (assertion): the resync minted NO new change and
        // NO new revision generation — convergence was revision-free, so there is
        // no spurious vector re-embed churn on a body edit. This pins the
        // resync seam against future refactors that might route it
        // through the change-minting commit path.
        let snap_after = state.graph.to_snapshot();
        assert_eq!(
            snap_after.changes.len(),
            changes_before,
            "no-clobber resync must mint no SemanticChange (revision-free convergence)"
        );
        let revisions_after: usize = snap_after.entity_revisions.values().map(|v| v.len()).sum();
        assert_eq!(
            revisions_after, revisions_before,
            "no-clobber resync must append no EntityRevision generation (no re-embed churn)"
        );

        // Step 4 (assertion a): the file now holds the agent's NEW text — a real
        // edit, NOT the identity splice the old write-loop produced.
        let on_disk = std::fs::read(&file_path).expect("projected file must exist");
        assert_ne!(
            on_disk, original,
            "file must change (not an identity no-op)"
        );
        let on_disk_str = String::from_utf8(on_disk).expect("projected file is utf-8");
        assert!(
            on_disk_str.contains("{ 42 }"),
            "file must contain the new body literal; got: {on_disk_str}"
        );
        assert!(
            !on_disk_str.contains("{ 1 }"),
            "old body literal must be gone; got: {on_disk_str}"
        );
        assert!(
            on_disk_str.contains("pub fn bar() -> i32 { 2 }"),
            "sibling entity bar must be preserved; got: {on_disk_str}"
        );

        // Step 5 (assertion b): a subsequent reconcile must produce NO entity
        // changes. The body edit changed the bytes, but the no-clobber resync drove
        // the reconciler LKG + graph onto the projected source, so the next
        // reconcile sees no delta — the agent's edit is NOT clobbered.
        let mut reconciler2 = state.reconciler.write().await;
        assert_no_clobber(&mut reconciler2, &state, &file_path);
    }

    #[tokio::test]
    async fn graph_only_projection_writes_derived_file_without_reingesting_it() {
        let dir = tempfile::tempdir().unwrap();
        let state = make_test_state(dir.path());
        let file_path = dir.path().join("src/lib.rs");
        std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        let original = b"pub fn foo() -> i32 { 1 }\npub fn bar() -> i32 { 2 }\n";
        std::fs::write(&file_path, original).unwrap();

        let blob_store = BlobStore::new(state.layout.objects_dir()).unwrap();
        let mut reconciler = state.reconciler.write().await;
        let mut overlay = GraphOverlay::default();
        reconciler
            .reconcile_file_change(
                &FileEvent::Changed(file_path.clone()),
                &blob_store,
                state.graph.as_ref(),
                &mut overlay,
            )
            .unwrap();
        let pre_commit_entity = overlay
            .entity_adds
            .values()
            .find(|entity| entity.name == "foo")
            .cloned()
            .unwrap();
        let span = pre_commit_entity.span.clone().unwrap();
        apply_overlay_to_graph(state.graph.as_ref(), &mut overlay).unwrap();
        drop(reconciler);

        let mut committed = pre_commit_entity.clone();
        committed.fingerprint.ast_hash = Hash256::from_bytes([0xee; 32]);
        state.graph.upsert_entity(&committed).unwrap();
        state
            .filesystem_reconcile_disabled
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let new_body = String::from_utf8_lossy(&original[span.start_byte..span.end_byte])
            .replace("{ 1 }", "{ 42 }")
            .into_bytes();
        let mut bodies = HashMap::new();
        bodies.insert(pre_commit_entity.id, new_body);
        let root_before = state.graph.compute_root_hash();

        let (modified_files, warnings, conflicts) =
            project_after_mcp_commit(&state, std::slice::from_ref(&pre_commit_entity), &bodies)
                .await
                .unwrap();

        assert_eq!(modified_files.len(), 1);
        assert!(warnings.is_empty());
        assert!(conflicts.is_empty());
        assert!(std::fs::read_to_string(&file_path)
            .unwrap()
            .contains("{ 42 }"));
        assert_eq!(
            state.graph.compute_root_hash(),
            root_before,
            "graph-only projection must not feed projected bytes back into graph authority"
        );
        assert_eq!(
            state
                .graph
                .get_entity(&pre_commit_entity.id)
                .unwrap()
                .unwrap()
                .fingerprint
                .ast_hash,
            Hash256::from_bytes([0xee; 32]),
            "the graph-side commit fingerprint must remain authoritative"
        );
    }

    #[tokio::test]
    async fn graph_only_cold_projection_fails_without_filesystem_priming() {
        let dir = tempfile::tempdir().unwrap();
        let state = make_test_state(dir.path());
        let file_path = dir.path().join("src/lib.rs");
        std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        let original = b"pub fn foo() -> i32 { 1 }\npub fn bar() -> i32 { 2 }\n";
        std::fs::write(&file_path, original).unwrap();

        // Seed graph truth with a separate reconciler so the daemon projection
        // remains cold and would have taken the compatibility prime path.
        let blob_store = BlobStore::new(state.layout.objects_dir()).unwrap();
        let mut discover = Reconciler::new(dir.path().to_path_buf());
        let mut overlay = GraphOverlay::default();
        discover
            .reconcile_file_change(
                &FileEvent::Changed(file_path.clone()),
                &blob_store,
                state.graph.as_ref(),
                &mut overlay,
            )
            .unwrap();
        let pre_commit_entity = overlay
            .entity_adds
            .values()
            .find(|entity| entity.name == "foo")
            .cloned()
            .unwrap();
        let span = pre_commit_entity.span.clone().unwrap();
        apply_overlay_to_graph(state.graph.as_ref(), &mut overlay).unwrap();

        let mut committed = pre_commit_entity.clone();
        committed.fingerprint.ast_hash = Hash256::from_bytes([0xef; 32]);
        state.graph.upsert_entity(&committed).unwrap();
        state
            .filesystem_reconcile_disabled
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let new_body = String::from_utf8_lossy(&original[span.start_byte..span.end_byte])
            .replace("{ 1 }", "{ 42 }")
            .into_bytes();
        let mut bodies = HashMap::new();
        bodies.insert(pre_commit_entity.id, new_body);
        let root_before = state.graph.compute_root_hash();

        let error =
            project_after_mcp_commit(&state, std::slice::from_ref(&pre_commit_entity), &bodies)
                .await
                .expect_err("graph-only cold projection must fail before filesystem priming");

        assert!(error.reason.contains("cold projection"), "{error}");
        assert!(
            error
                .reason
                .contains(crate::loop_runner::DISABLE_FILESYSTEM_RECONCILE_ENV),
            "{error}"
        );
        assert_eq!(state.graph.compute_root_hash(), root_before);
        assert_eq!(std::fs::read(&file_path).unwrap(), original);
        let reconciler = state.reconciler.read().await;
        assert!(
            reconciler.projection().get_content(&span.file).is_none(),
            "fail-closed graph-only projection must not prime from filesystem bytes"
        );
    }

    // ------------------------------------------------------------------
    // Test 1c: a body edit projected against a COLD reconciler
    // projection (no prior reconcile tick — the daemon-restart state) still
    // reaches disk. This is the silent-no-op regression: the graph commit
    // landed but `modified_files` came back empty because the reconciler's
    // projection had no layout for the entity's file. The fix primes the
    // projection from graph + disk truth before projecting.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn project_body_edit_primes_cold_projection_and_reaches_disk() {
        let dir = tempfile::tempdir().unwrap();
        let state = make_test_state(dir.path());
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let rel = "src/lib.rs";
        let file_path = dir.path().join(rel);
        std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        let original = b"pub fn foo() -> i32 { 1 }\npub fn bar() -> i32 { 2 }\n";
        std::fs::write(&file_path, original).unwrap();

        let blob_store = BlobStore::new(state.layout.objects_dir()).expect("blob store must open");

        // Discover the entity (with its deterministic id + span) and seed the
        // graph using a SEPARATE reconciler, so the daemon's own
        // `state.reconciler` projection stays COLD — exactly the post-restart
        // state where no reconcile tick has registered a file layout yet.
        let mut discover = Reconciler::new(dir.path().to_path_buf());
        let mut overlay = GraphOverlay::default();
        discover
            .reconcile_file_change(
                &FileEvent::Changed(file_path.clone()),
                &blob_store,
                state.graph.as_ref(),
                &mut overlay,
            )
            .expect("discovery reconcile must succeed");
        let pre_commit_entity = overlay
            .entity_adds
            .values()
            .find(|e| e.name == "foo")
            .cloned()
            .expect("foo must be present in the reconcile overlay");
        let span = pre_commit_entity
            .span
            .clone()
            .expect("foo must have a span");
        apply_overlay_to_graph(state.graph.as_ref(), &mut overlay)
            .expect("apply overlay must succeed");

        // Sanity: the daemon's projection is cold — no layout/content for the file.
        {
            let reconciler = state.reconciler.read().await;
            assert!(
                reconciler.projection().get_content(&span.file).is_none(),
                "precondition: daemon reconciler projection must be cold for this file"
            );
        }

        let orig_region = &original[span.start_byte..span.end_byte];
        let new_body = String::from_utf8_lossy(orig_region)
            .replace("{ 1 }", "{ 42 }")
            .into_bytes();

        let mut bodies = HashMap::new();
        bodies.insert(pre_commit_entity.id, new_body.clone());
        let (modified_files, _warnings, conflicts) =
            project_after_mcp_commit(&state, std::slice::from_ref(&pre_commit_entity), &bodies)
                .await
                .expect("projection must succeed");

        assert_eq!(
            modified_files.len(),
            1,
            "cold-projection body edit must still project exactly one file; \
             empty here is the silent no-op"
        );
        assert!(conflicts.is_empty(), "no conflicts expected");

        let on_disk = std::fs::read(&file_path).expect("projected file must exist");
        let on_disk_str = String::from_utf8(on_disk).expect("projected file is utf-8");
        assert!(
            on_disk_str.contains("{ 42 }"),
            "file must contain the new body literal; got: {on_disk_str}"
        );
        assert!(
            !on_disk_str.contains("{ 1 }"),
            "old body literal must be gone; got: {on_disk_str}"
        );
        assert!(
            on_disk_str.contains("pub fn bar() -> i32 { 2 }"),
            "sibling entity bar must be preserved; got: {on_disk_str}"
        );

        let mut reconciler2 = state.reconciler.write().await;
        assert_no_clobber(&mut reconciler2, &state, &file_path);
    }

    // ------------------------------------------------------------------
    // Test 2: entity without a span → no projection, no error.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn project_skips_span_less_entity_gracefully() {
        let dir = tempfile::tempdir().unwrap();
        let state = make_test_state(dir.path());
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);

        // Build a span-less entity (e.g. a new graph-created entity with no file
        // placement yet).
        let span_less = kin_model::Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "new_fn".to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0x01; 32]),
                signature_hash: Hash256::from_bytes([0x02; 32]),
                behavior_hash: Hash256::from_bytes([0x03; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: "fn new_fn()".to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let (modified_files, warnings, conflicts) =
            project_after_mcp_commit(&state, &[span_less], &HashMap::new())
                .await
                .expect("span-less entity must not cause an error");

        assert!(
            modified_files.is_empty(),
            "no files should be modified for a span-less entity"
        );
        assert!(warnings.is_empty(), "no warnings expected");
        assert!(conflicts.is_empty(), "no conflicts expected");
    }

    // ------------------------------------------------------------------
    // Test 3 (assertion c): projection failure surfaces a structured error.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn project_failure_surfaces_structured_error() {
        let dir = tempfile::tempdir().unwrap();
        let state = make_test_state(dir.path());
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);

        // Build an entity with a span pointing to a file that does NOT exist
        // and has not been registered in the projection cache.  This causes
        // project_overlay_to_files → BodyExtractionFailed.
        let entity_id = EntityId::new();
        let bad_entity = kin_model::Entity {
            id: entity_id,
            kind: EntityKind::Function,
            name: "ghost_fn".to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0xff; 32]),
                signature_hash: Hash256::from_bytes([0xfe; 32]),
                behavior_hash: Hash256::from_bytes([0xfd; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 0.5,
            },
            file_origin: Some(FilePathId::new("src/ghost.rs")),
            span: Some(SourceSpan {
                file: FilePathId::new("src/ghost.rs"),
                start_byte: 0,
                end_byte: 20,
                start_line: 0,
                start_col: 0,
                end_line: 0,
                end_col: 20,
            }),
            signature: "fn ghost_fn()".to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let result = project_after_mcp_commit(&state, &[bad_entity], &HashMap::new()).await;

        match result {
            Err(e) => {
                assert_eq!(
                    e.entity_id, entity_id,
                    "error must name the entity that failed"
                );
                assert!(e.file.is_some(), "error must name the file (src/ghost.rs)");
                assert!(
                    !e.reason.is_empty(),
                    "error must carry a non-empty reason string"
                );
                // Verify the Display impl produces a useful message.
                let msg = e.to_string();
                assert!(
                    msg.contains("ghost.rs") || msg.contains(&entity_id.to_string()),
                    "Display must mention the file or entity: {msg}"
                );
            }
            Ok(_) => panic!("expected a structured error for an entity with a stale/missing span"),
        }
    }

    // ------------------------------------------------------------------
    // Test 4: concurrent file edit → conflict surfaced, not spliced.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn concurrent_file_edit_surfaces_conflict_and_skips_projection() {
        let dir = tempfile::tempdir().unwrap();
        let state = make_test_state(dir.path());
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let rel = "src/lib.rs";
        let file_path = dir.path().join(rel);
        std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        let original = b"pub fn foo() -> i32 { 1 }\npub fn bar() -> i32 { 2 }\n";
        std::fs::write(&file_path, original).unwrap();

        let blob_store = BlobStore::new(state.layout.objects_dir()).expect("blob store must open");

        // Step 1: Reconcile to prime the projection cache.
        let mut reconciler = state.reconciler.write().await;
        let mut overlay = GraphOverlay::default();
        reconciler
            .reconcile_file_change(
                &FileEvent::Changed(file_path.clone()),
                &blob_store,
                state.graph.as_ref(),
                &mut overlay,
            )
            .expect("reconcile must succeed");

        let pre_commit_entity = overlay
            .entity_adds
            .values()
            .find(|e| e.name == "foo")
            .cloned()
            .expect("foo must be present");

        apply_overlay_to_graph(state.graph.as_ref(), &mut overlay).expect("apply must succeed");
        drop(reconciler);

        // Step 2: Simulate a concurrent human edit that modifies the file AFTER
        // reconcile but BEFORE the MCP commit's projection.
        let edited = b"pub fn foo() -> i32 { 999 }\npub fn bar() -> i32 { 2 }\n";
        std::fs::write(&file_path, edited).unwrap();

        // Step 3: Call project_after_mcp_commit — should detect the concurrent
        // edit and surface a conflict instead of splicing over it.
        let (modified_files, _warnings, conflicts) =
            project_after_mcp_commit(&state, &[pre_commit_entity], &HashMap::new())
                .await
                .expect("conflict detection must not hard-fail");

        // The conflicted entity must NOT have been projected.
        assert!(
            modified_files.is_empty(),
            "conflicted entity must not be projected; got {} modified files",
            modified_files.len()
        );

        // A conflict must be surfaced to the caller.
        assert!(
            !conflicts.is_empty(),
            "concurrent edit must surface a ConflictObject to the caller"
        );
        assert_eq!(
            conflicts[0].kind,
            kin_model::ConflictKind::StructuralCollision,
            "conflict kind must be StructuralCollision"
        );

        // The human's edits must be preserved on disk (not overwritten).
        let on_disk = std::fs::read(&file_path).expect("file must still exist");
        assert_eq!(
            on_disk, edited,
            "human's concurrent edits must be preserved (not spliced over)"
        );
    }

    // ------------------------------------------------------------------
    // Test 5: persist + reopen projection state cleanly.
    // ------------------------------------------------------------------
    // Verifies that rebuild_projection succeeds on a fresh DaemonState
    // without any persisted file layouts (the empty-graph case).
    #[tokio::test]
    async fn rebuild_projection_succeeds_on_empty_graph() {
        let dir = tempfile::tempdir().unwrap();
        let state = make_test_state(dir.path());
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);

        // Should complete without error even when no file layouts are persisted.
        state
            .rebuild_projection()
            .await
            .expect("rebuild_projection must succeed on empty graph");

        let proj = state.projection.read().await;
        assert!(
            proj.file_ids().is_empty(),
            "empty graph → empty projection state"
        );
    }

    // ------------------------------------------------------------------
    // Test 6: restart rebuild from persisted graph + blobs.
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn rebuild_projection_restores_from_persisted_graph_truth() {
        let dir = tempfile::tempdir().unwrap();
        let state = make_test_state(dir.path());
        state
            .is_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let rel = "src/lib.rs";
        let file_path = dir.path().join(rel);
        std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        let content = b"pub fn foo() -> i32 { 1 }\n";
        std::fs::write(&file_path, content).unwrap();

        let blob_store = BlobStore::new(state.layout.objects_dir()).expect("blob store must open");

        // Reconcile to populate the reconciler's projection and the graph.
        let mut reconciler = state.reconciler.write().await;
        let mut overlay = GraphOverlay::default();
        reconciler
            .reconcile_file_change(
                &FileEvent::Changed(file_path.clone()),
                &blob_store,
                state.graph.as_ref(),
                &mut overlay,
            )
            .expect("reconcile must succeed");
        apply_overlay_to_graph(state.graph.as_ref(), &mut overlay).unwrap();

        // Persist projection truth (layout + hash) to the graph so
        // rebuild_projection can restore it.
        let file_id = kin_model::FilePathId::new(rel);
        state
            .persist_projection_truth_from_reconcile(
                &reconciler,
                &kin_reconcile::ReconcileOutcome::Updated {
                    file_id: file_id.clone(),
                    added: vec![],
                    modified: vec![],
                    removed: vec![],
                    collision_warnings: vec![],
                },
            )
            .expect("persist_projection_truth must succeed");
        drop(reconciler);

        // Rebuild projection from persisted graph truth.
        state
            .rebuild_projection()
            .await
            .expect("rebuild_projection must succeed from persisted truth");

        let proj = state.projection.read().await;
        assert!(
            proj.file_ids().iter().any(|id| **id == file_id),
            "rebuilt projection must contain the persisted file"
        );
        assert!(
            proj.get_content(&file_id).is_some(),
            "rebuilt projection must have content for the persisted file"
        );
    }
}
