// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! FIR-929: Graph→file projection seam for MCP transaction commits.
//!
//! After `kin_transaction_commit` applies entity mutations to the graph,
//! [`project_after_mcp_commit`] drives `project_overlay_to_files` so the
//! working-directory files stay in sync with graph truth. Without this step
//! the next reconcile tick re-parses the unchanged file, detects a fingerprint
//! mismatch (or a name mismatch for renames), and silently overwrites the
//! agent's graph mutations — file-wins LWW.
//!
//! # Chosen failure semantics (FIR-929)
//!
//! The graph mutation is committed before projection is attempted. If projection
//! fails, the graph already reflects the agent's intent; the error is surfaced
//! loud to the caller (structured `McpProjectionError`) but the graph mutation
//! is **not rolled back**. This keeps the graph-side commit atomic and lets the
//! agent retry the projection or inspect the failure. See FIR-929 for rationale.
//!
//! # detect_conflict slot (FIR-904·3, NOT implemented here)
//!
//! Concurrent file edits are not detected in this changeset. The correct slot
//! for that check is inside [`project_after_mcp_commit`], between building
//! `temp_overlay` and calling `reconciler.project_overlay_to_files`. A
//! `detect_conflict` call would compare each overlay entity against the current
//! on-disk entity (via a fresh parse or projection snapshot) and return a
//! structured conflict before the splice is attempted.

use std::sync::Arc;

use kin_model::{Entity, EntityId, FilePathId, GraphOverlay};
use kin_reconcile::ReconcileError;

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
///
/// # Returns
///
/// `Ok((modified_files, collision_warnings))` on success, or a
/// [`McpProjectionError`] naming the first failing entity + file on error.
pub async fn project_after_mcp_commit(
    state: &Arc<DaemonState>,
    pre_commit_entities: &[Entity],
) -> Result<(Vec<FilePathId>, Vec<kin_model::IntentSummary>), McpProjectionError> {
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
        return Ok((vec![], vec![]));
    }

    // FIR-904·3 (detect_conflict) slot: before acquiring the reconciler lock,
    // this is the correct place to compare each entity in `temp_overlay.entity_mods`
    // against the current on-disk content to detect concurrent file edits.
    // Leave a precise breadcrumb: iterate `temp_overlay.entity_mods`, for each
    // entity read the current file bytes (from `state.projection` cache or disk),
    // parse the entity at its span, and compare fingerprints. A mismatch signals a
    // concurrent human edit — surface as a conflict rather than proceeding with
    // the stale splice. This check is intentionally absent here (FIR-929 scope).

    // Acquire the reconciler write lock — same locking discipline as loop_runner
    // and vfs_write_notify: hold the lock for the full duration of the projection
    // so we do not race with a concurrent reconcile tick that could invalidate
    // the projection cache entries we are about to use.
    let mut reconciler = state.reconciler.write().await;

    reconciler
        .project_overlay_to_files(&temp_overlay)
        .map_err(|e| reconcile_err_to_projection_err(e, pre_commit_entities))
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
        let (modified_files, warnings) =
            project_after_mcp_commit(&state, &[pre_commit_entity.clone()])
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

        let (modified_files, warnings) = project_after_mcp_commit(&state, &[span_less])
            .await
            .expect("span-less entity must not cause an error");

        assert!(
            modified_files.is_empty(),
            "no files should be modified for a span-less entity"
        );
        assert!(warnings.is_empty(), "no warnings expected");
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

        let result = project_after_mcp_commit(&state, &[bad_entity]).await;

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
}
