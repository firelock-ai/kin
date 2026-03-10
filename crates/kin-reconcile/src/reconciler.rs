use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

use kin_blobs::BlobStore;
use kin_index::{FileEvent, IndexPipeline};
use kin_model::{
    ConflictId, ConflictKind, ConflictObject, Entity, EntityId, FilePathId,
    GraphOverlay, GraphStore, IntentScope, IntentSummary, ParseState, SessionId,
};
use kin_projection::{project_entity_mutations, ProjectionState};

use crate::collision::{CollisionCheck, TrafficChecker};
use crate::error::{ReconcileError, Result};
use crate::lkg::LkgStore;

/// Outcome of reconciling a single file change.
#[derive(Debug)]
pub enum ReconcileOutcome {
    /// File parsed cleanly; overlay updated with new/modified/removed entities.
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

/// The reconciliation engine. Keeps the working copy overlay and working
/// directory files in sync.
///
/// Two directions:
/// - **File -> Overlay:** detect file edits, parse, update overlay
/// - **Overlay -> File:** detect overlay mutations, project to working dir
pub struct Reconciler {
    pipeline: IndexPipeline,
    lkg: LkgStore,
    projection: ProjectionState,
    working_dir: PathBuf,
    /// Optional traffic checker for pre-mutation collision detection.
    traffic_checker: Option<Box<dyn TrafficChecker>>,
    /// Session ID of the caller (used for collision checks).
    session_id: Option<SessionId>,
}

impl Reconciler {
    /// Create a new reconciler for the given working directory.
    pub fn new(working_dir: PathBuf) -> Self {
        Self {
            pipeline: IndexPipeline::new(),
            lkg: LkgStore::new(),
            projection: ProjectionState::new(),
            working_dir,
            traffic_checker: None,
            session_id: None,
        }
    }

    /// Set the traffic checker for pre-mutation collision detection.
    pub fn set_traffic_checker(&mut self, checker: Box<dyn TrafficChecker>) {
        self.traffic_checker = Some(checker);
    }

    /// Set the session ID used for collision checks.
    pub fn set_session_id(&mut self, session_id: SessionId) {
        self.session_id = Some(session_id);
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
    // Direction 1: File -> Overlay
    // ---------------------------------------------------------------

    /// Reconcile a file change event. Parses the file, compares against
    /// current graph state, and updates the overlay.
    ///
    /// If the parse produces errors, the LKG state is retained and no
    /// graph changes are made.
    pub fn reconcile_file_change<G: GraphStore>(
        &mut self,
        event: &FileEvent,
        blob_store: &BlobStore,
        graph: &G,
        overlay: &mut GraphOverlay,
    ) -> Result<ReconcileOutcome> {
        match event {
            FileEvent::Changed(path) => {
                self.reconcile_file_edit(path, blob_store, graph, overlay)
            }
            FileEvent::Removed(path) => {
                self.reconcile_file_removal(path, graph, overlay)
            }
        }
    }

    /// Reconcile a file edit (create or modify).
    fn reconcile_file_edit<G: GraphStore>(
        &mut self,
        path: &Path,
        blob_store: &BlobStore,
        graph: &G,
        overlay: &mut GraphOverlay,
    ) -> Result<ReconcileOutcome> {
        let indexed = self.pipeline.index_file(path, blob_store)?;
        let file_id = indexed.file_id.clone();

        // Check for broken AST
        if let ParseState::Incomplete { error_ranges } = &indexed.parse_state {
            warn!(
                file = %path.display(),
                errors = error_ranges.len(),
                "broken AST, retaining LKG state"
            );
            return Ok(ReconcileOutcome::BrokenAst {
                file_id,
                error_ranges: error_ranges.clone(),
            });
        }

        // Get existing entities for this file from the graph
        let existing = self.get_file_entities(graph, &file_id)?;

        // Build scopes for collision checking: all entities that will be
        // affected (existing + new ones from parse).
        let mut affected_scopes: Vec<IntentScope> = existing
            .iter()
            .map(|e| IntentScope::Entity(e.id))
            .collect();
        for new_entity in &indexed.entities {
            // Only add if not already covered by an existing entity
            let already = existing.iter().any(|e| e.name == new_entity.name && e.kind == new_entity.kind);
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

        // Track which existing entities we've matched
        let mut matched_existing: HashMap<EntityId, bool> = existing
            .iter()
            .map(|e| (e.id, false))
            .collect();

        // Process new entities from the parse
        for new_entity in &indexed.entities {
            // Try to match by name + kind against existing entities
            let existing_match = existing.iter().find(|e| {
                e.name == new_entity.name && e.kind == new_entity.kind
            });

            match existing_match {
                Some(old) => {
                    matched_existing.insert(old.id, true);

                    // Check if fingerprint actually changed
                    if self.lkg.has_changed(&old.id, &new_entity.fingerprint) {
                        // Real semantic change
                        let mut updated = new_entity.clone();
                        updated.id = old.id; // Preserve identity
                        updated.lineage_parent = old.lineage_parent;
                        updated.created_in = old.created_in;

                        overlay.entity_mods.insert(old.id, updated.clone());
                        self.lkg.record(updated.clone(), vec![]);
                        modified.push(old.id);

                        debug!(
                            entity = %old.name,
                            id = %old.id,
                            "entity modified"
                        );
                    } else {
                        // No semantic change (whitespace/formatting only)
                        debug!(
                            entity = %old.name,
                            "no semantic change, skipping"
                        );
                    }
                }
                None => {
                    // New entity
                    overlay.entity_adds.insert(new_entity.id, new_entity.clone());
                    self.lkg.record(new_entity.clone(), vec![]);
                    added.push(new_entity.id);

                    debug!(
                        entity = %new_entity.name,
                        id = %new_entity.id,
                        "new entity added"
                    );
                }
            }
        }

        // Entities that existed before but are no longer in the file -> removed
        for (id, matched) in &matched_existing {
            if !matched {
                overlay.entity_removes.push(*id);
                self.lkg.remove(id);
                removed.push(*id);
                debug!(id = %id, "entity removed from file");
            }
        }

        // Process relations
        for relation in &indexed.relations {
            overlay.relation_adds.insert(relation.id, relation.clone());
        }

        info!(
            file = %path.display(),
            added = added.len(),
            modified = modified.len(),
            removed = removed.len(),
            warnings = collision_warnings.len(),
            "reconciled file edit"
        );

        Ok(ReconcileOutcome::Updated {
            file_id,
            added,
            modified,
            removed,
            collision_warnings,
        })
    }

    /// Reconcile a file removal.
    fn reconcile_file_removal<G: GraphStore>(
        &mut self,
        path: &Path,
        graph: &G,
        overlay: &mut GraphOverlay,
    ) -> Result<ReconcileOutcome> {
        let file_id = FilePathId::new(path.display().to_string());
        let existing = self.get_file_entities(graph, &file_id)?;

        // Build scopes for collision checking
        let mut affected_scopes: Vec<IntentScope> = existing
            .iter()
            .map(|e| IntentScope::Entity(e.id))
            .collect();
        affected_scopes.push(IntentScope::Artifact(file_id.clone()));

        // Check for collisions before applying mutations
        let collision_warnings = self.check_scopes(&affected_scopes)?;

        let mut removed = Vec::new();

        for entity in &existing {
            overlay.entity_removes.push(entity.id);
            self.lkg.remove(&entity.id);
            removed.push(entity.id);
        }

        info!(
            file = %path.display(),
            removed = removed.len(),
            warnings = collision_warnings.len(),
            "reconciled file removal"
        );

        Ok(ReconcileOutcome::FileRemoved { file_id, removed, collision_warnings })
    }

    // ---------------------------------------------------------------
    // Direction 2: Overlay -> File
    // ---------------------------------------------------------------

    /// Result of projecting overlay mutations to files.
    ///
    /// Includes the list of modified files and any collision warnings.
    pub fn project_overlay_to_files(
        &mut self,
        overlay: &GraphOverlay,
    ) -> Result<(Vec<FilePathId>, Vec<IntentSummary>)> {
        let mut mutations: HashMap<EntityId, Vec<u8>> = HashMap::new();

        // Collect entity body text for modified entities
        for (id, entity) in &overlay.entity_mods {
            // Use the entity's signature + name as a minimal body
            // (full body would come from blob store in production)
            let body = entity.signature.as_bytes().to_vec();
            mutations.insert(*id, body);
        }

        if mutations.is_empty() {
            return Ok((vec![], vec![]));
        }

        // Build scopes for collision checking: every entity being mutated
        let affected_scopes: Vec<IntentScope> = overlay
            .entity_mods
            .keys()
            .map(|id| IntentScope::Entity(*id))
            .collect();

        // Check for collisions before applying mutations
        let collision_warnings = self.check_scopes(&affected_scopes)?;

        let modified = project_entity_mutations(
            &mut self.projection,
            &mutations,
            &self.working_dir,
        )?;

        info!(
            files = modified.len(),
            warnings = collision_warnings.len(),
            "projected overlay mutations to working directory"
        );

        Ok((modified, collision_warnings))
    }

    // ---------------------------------------------------------------
    // Conflict detection
    // ---------------------------------------------------------------

    /// Detect conflicts between overlay state and file state.
    ///
    /// Called when both directions have pending changes for the same
    /// entity (e.g., human edits a file while an assistant mutates the
    /// overlay).
    pub fn detect_conflict(
        &self,
        entity_id: &EntityId,
        overlay_entity: &Entity,
        file_entity: &Entity,
    ) -> Option<ConflictObject> {
        // If both sides changed the entity differently, emit a conflict
        if overlay_entity.fingerprint.ast_hash != file_entity.fingerprint.ast_hash {
            Some(ConflictObject {
                id: ConflictId::new(),
                kind: ConflictKind::StructuralCollision,
                desired_state: format!(
                    "Overlay: {} (sig: {})",
                    overlay_entity.name, overlay_entity.signature
                ),
                current_state: format!(
                    "File: {} (sig: {})",
                    file_entity.name, file_entity.signature
                ),
                divergence_reason: "Entity modified in both overlay and working file".to_string(),
                affected_entities: vec![*entity_id],
                affected_files: file_entity
                    .file_origin
                    .iter()
                    .cloned()
                    .collect(),
                suggested_resolutions: vec![
                    "Accept overlay version".to_string(),
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
    // Collision checking
    // ---------------------------------------------------------------

    /// Check collisions for a set of scopes. Returns Ok(warnings) if the
    /// mutation can proceed, or Err if blocked by a hard collision.
    ///
    /// If no traffic checker is configured, always returns Ok(empty warnings).
    fn check_scopes(
        &self,
        scopes: &[IntentScope],
    ) -> Result<Vec<IntentSummary>> {
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
                Ok(CollisionCheck::Blocked { conflict: _, blocking_intents }) => {
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

    /// Get all entities for a file from the graph, falling back to overlay.
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

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        EntityKind, EntityMetadata, FingerprintAlgorithm, Hash256, LanguageId,
        SemanticFingerprint, Visibility,
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
                stability_score: 0.95,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
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
        let mut overlay_entity = make_entity("foo", "src/lib.rs");
        overlay_entity.id = entity_id;
        overlay_entity.fingerprint.ast_hash = Hash256::from_bytes([0x11; 32]);

        let mut file_entity = make_entity("foo", "src/lib.rs");
        file_entity.id = entity_id;
        file_entity.fingerprint.ast_hash = Hash256::from_bytes([0x22; 32]);

        let conflict = reconciler.detect_conflict(
            &entity_id,
            &overlay_entity,
            &file_entity,
        );
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

        reconciler.lkg.record(entity, vec![]);
        assert!(reconciler.lkg().get(&id).is_some());
    }

    #[test]
    fn project_empty_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        let overlay = GraphOverlay::default();
        let (modified, warnings) = reconciler.project_overlay_to_files(&overlay).unwrap();
        assert!(modified.is_empty());
        assert!(warnings.is_empty());
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
                result: std::sync::Mutex::new(CollisionCheck::Warnings(vec![
                    IntentSummary {
                        intent_id: IntentId::new(),
                        session_id: SessionId::new(),
                        vendor: "soft-agent".to_string(),
                        task_description: "soft lock nearby".to_string(),
                        lock_type: LockType::Soft,
                        registered_at: Timestamp::now(),
                    },
                ])),
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
            ReconcileError::CollisionBlocked { reason, blocking_intents } => {
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
        responses.insert(entity_b, CollisionCheck::Warnings(vec![
            IntentSummary {
                intent_id: IntentId::new(),
                session_id: SessionId::new(),
                vendor: "agent-b".to_string(),
                task_description: "soft lock on B".to_string(),
                lock_type: LockType::Soft,
                registered_at: Timestamp::now(),
            },
        ]));
        // entity_c: different soft warning
        responses.insert(entity_c, CollisionCheck::Warnings(vec![
            IntentSummary {
                intent_id: IntentId::new(),
                session_id: SessionId::new(),
                vendor: "agent-c".to_string(),
                task_description: "soft lock on C".to_string(),
                lock_type: LockType::Soft,
                registered_at: Timestamp::now(),
            },
        ]));

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
    fn project_overlay_blocked_by_collision() {
        // Verify that project_overlay_to_files rejects when checker blocks.
        let dir = tempfile::tempdir().unwrap();
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        reconciler.set_traffic_checker(Box::new(MockTrafficChecker::blocked()));
        reconciler.set_session_id(SessionId::new());

        let entity_id = EntityId::new();
        let mut overlay = GraphOverlay::default();
        let entity = make_entity("blocked_fn", "src/lib.rs");
        overlay.entity_mods.insert(entity_id, entity);

        let result = reconciler.project_overlay_to_files(&overlay);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ReconcileError::CollisionBlocked { .. }
        ));
    }
}
