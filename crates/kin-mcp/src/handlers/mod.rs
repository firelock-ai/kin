// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod artifacts;
pub mod common;

// Handler submodules are public so each tool's rich `*_DESC` description const
// can live next to the handler that implements it, and be referenced by the
// MCP tool registry in `tools.rs`. Keeping the prose beside the code keeps the
// two from drifting apart.
pub mod bench;
pub mod entities;
pub mod provenance;
pub(crate) mod repository_authority;
pub mod review;
pub mod sessions;
pub mod verification;
pub mod work;

pub use repository_authority::{
    ActiveRepositoryAuthority, LocalRepositoryAuthorityBinding, RequestRepositoryAuthority,
};

use std::collections::HashMap;

use kin_model::graph::GraphStore;

use crate::error::{McpError, Result};
use crate::server::SessionAuthorityMode;
use crate::session::SessionRegistry;
use crate::types::ToolCallResult;

/// Dispatch a tool call to the appropriate handler.
pub async fn handle_tool_call<G: GraphStore>(
    tool_name: &str,
    arguments: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    match tool_name {
        // Exact repository membership and bytes
        "kin_artifact_list" => {
            artifacts::handle_artifact_list(arguments, store, repository_authority)
        }
        "kin_artifact_read" => {
            artifacts::handle_artifact_read(arguments, store, repository_authority)
        }
        // Entities
        "semantic_search" => entities::handle_semantic_search(arguments, store),
        "semantic_locate" => entities::handle_semantic_locate(arguments, store),
        "get_entity" => entities::handle_get_entity(arguments, store, repository_authority),
        "get_entity_source" | "get_entity_body" => {
            entities::handle_get_entity_source(arguments, store, repository_authority)
        }
        "get_entity_sources" => {
            entities::handle_get_entity_sources(arguments, store, repository_authority)
        }
        "get_context_pack" => {
            entities::handle_get_context_pack(arguments, store, sessions, repository_authority)
        }
        "trace_computation" => {
            entities::handle_trace_computation(arguments, store, sessions, repository_authority)
        }
        "trace_data_flow" => entities::handle_trace_data_flow(arguments, store),
        "find_references" => {
            entities::handle_find_references(arguments, store, repository_authority).await
        }
        "bulk_check_references" => entities::handle_bulk_check_references(arguments, store),
        "explore_codebase" => {
            entities::handle_explore_codebase(arguments, store, repository_authority)
        }
        "dead_code" => entities::handle_dead_code(arguments, store),
        "find_dead_code_seeded" => entities::handle_find_dead_code_seeded(arguments, store),
        "graph_neighborhood" => entities::handle_graph_neighborhood(arguments, store),
        // Review
        "semantic_diff" => review::handle_semantic_diff(arguments, store),
        "impact_analysis" => review::handle_impact_analysis(arguments, store, sessions).await,
        "semantic_review" => review::handle_semantic_review(arguments, store, sessions),
        "shadow_gate_report" => {
            review::handle_shadow_gate_report(arguments, store, repository_authority)
        }
        "entity_history" => review::handle_entity_history(arguments, store),
        // Sessions
        "register_session" => sessions::handle_register_session(arguments, sessions),
        "kin_session_start" => {
            sessions::handle_session_start(arguments, sessions, session_authority_mode).await
        }
        "kin_session_heartbeat" => {
            sessions::handle_session_heartbeat(arguments, sessions, session_authority_mode).await
        }
        "kin_session_end" => {
            sessions::handle_session_end(arguments, sessions, session_authority_mode).await
        }
        "kin_register_intent" => {
            sessions::handle_register_intent(arguments, sessions, session_authority_mode).await
        }
        "kin_release_intent" => {
            sessions::handle_release_intent(arguments, sessions, session_authority_mode).await
        }
        "kin_check_traffic" => {
            sessions::handle_check_traffic(arguments, sessions, session_authority_mode).await
        }
        "kin_transaction_begin" => {
            sessions::handle_transaction_begin(arguments, sessions, session_authority_mode).await
        }
        "kin_transaction_stage" => {
            sessions::handle_transaction_stage(arguments, sessions, session_authority_mode).await
        }
        "kin_transaction_validate" => {
            sessions::handle_transaction_validate(arguments, sessions, session_authority_mode).await
        }
        "kin_transaction_commit" => {
            sessions::handle_transaction_commit(arguments, store, sessions, session_authority_mode)
                .await
        }
        "kin_transaction_abort" => {
            sessions::handle_transaction_abort(arguments, sessions, session_authority_mode).await
        }
        // Work graph and annotations
        "kin_work_create" => work::handle_work_create(arguments, store),
        "kin_work_list" => work::handle_work_list(arguments, store),
        "kin_work_show" => work::handle_work_show(arguments, store),
        "kin_work_link" => work::handle_work_link(arguments, store),
        "kin_work_decompose" => work::handle_work_decompose(arguments, store),
        "kin_work_block" => work::handle_work_block(arguments, store),
        "kin_work_implement" => work::handle_work_implement(arguments, store),
        "kin_work_status" => work::handle_work_status(arguments, store),
        "kin_annotation_add" => work::handle_annotation_add(arguments, store),
        "kin_annotation_list" => work::handle_annotation_list(arguments, store),
        "kin_annotation_mark_resolved" => work::handle_annotation_mark_resolved(arguments, store),
        "kin_todo_import" => work::handle_todo_import(arguments, store),
        // Verification, security, release, contract
        "kin_verify_entity" => verification::handle_verify_entity(arguments, store),
        "kin_coverage_summary" => verification::handle_coverage_summary(store),
        "kin_security_scan" => verification::handle_security_scan(arguments, store),
        "kin_release_check" => {
            verification::handle_release_check(arguments, store, repository_authority)
        }
        "kin_contract_check" => verification::handle_contract_check(arguments, store),
        // Review mutations (Phase 11)
        "kin_review_create" => review::handle_review_create(arguments, store),
        "kin_review_decide" => review::handle_review_decide(arguments, store),
        "kin_review_note_add" => review::handle_review_note_add(arguments, store),
        "kin_review_discuss" => review::handle_review_discuss(arguments, store),
        "kin_review_discuss_reply" => review::handle_review_discuss_reply(arguments, store),
        "kin_review_discuss_resolve" => review::handle_review_discuss_resolve(arguments, store),
        "kin_review_assign" => review::handle_review_assign(arguments, store),
        "kin_review_unassign" => review::handle_review_unassign(arguments, store),
        "kin_review_list" => review::handle_review_list(arguments, store),
        "kin_review_get" => review::handle_review_get(arguments, store),
        // Provenance
        "kin_provenance_query" => provenance::handle_provenance_query(arguments, store),
        // Graph status
        "kin_graph_status" => entities::handle_graph_status(arguments, store),
        // Benchmark
        "benchmark" => bench::handle_benchmark(arguments, store),
        _ => Err(McpError::ToolNotFound(tool_name.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::common::*;
    use super::*;
    use base64::Engine as _;
    use kin_core::test_env::EnvVarGuard;
    use kin_db::{InMemoryGraph, KinDbError, LocalFileBackend, RepositoryAuthorityManager};
    use kin_model::change::SemanticChange;
    use kin_model::entity::Entity;
    use kin_model::entity::{EntityKind, Visibility};
    use kin_model::graph::{ChangeStore, EntityFilter, EntityStore, SubGraph};
    use kin_model::ids::*;
    use kin_model::relation::{Relation, RelationKind};
    use kin_model::session::{IntentScope, LockType, SessionCapabilities, SessionTransport};
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[derive(Default)]
    pub(super) struct EmptyStore {
        entities_by_file: HashMap<String, Vec<Entity>>,
        entities_by_id: HashMap<EntityId, Entity>,
        relations_by_entity: HashMap<EntityId, Vec<Relation>>,
        dead_entities: Vec<Entity>,
        live_entity_ids: HashSet<EntityId>,
        file_hashes: HashMap<FilePathId, Hash256>,
        repository_refs: Vec<(kin_model::RefName, SemanticChangeId)>,
        changes_by_id: HashMap<SemanticChangeId, SemanticChange>,
        actors_by_id: HashMap<kin_model::provenance::ActorId, kin_model::provenance::Actor>,
        approvals_by_change: HashMap<SemanticChangeId, Vec<kin_model::provenance::Approval>>,
    }

    impl EmptyStore {
        pub(super) fn insert_test_entity(&mut self, entity: Entity) {
            self.live_entity_ids.insert(entity.id);
            if let Some(file) = entity.file_origin.as_ref() {
                self.entities_by_file
                    .entry(file.0.clone())
                    .or_default()
                    .push(entity.clone());
            }
            self.entities_by_id.insert(entity.id, entity);
        }

        /// Wire `caller` as calling `callee`, indexed under BOTH endpoints so an
        /// impact walk finds it from either direction.
        pub(super) fn insert_test_calls_relation(&mut self, caller: &Entity, callee: &Entity) {
            let relation = Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: kin_model::GraphNodeId::Entity(caller.id),
                dst: kin_model::GraphNodeId::Entity(callee.id),
                confidence: 1.0,
                origin: kin_model::relation::RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: vec![],
            };
            self.relations_by_entity
                .entry(callee.id)
                .or_default()
                .push(relation.clone());
            self.relations_by_entity
                .entry(caller.id)
                .or_default()
                .push(relation);
        }
    }

    /// A minimal entity for impact-presentation fixtures. `start_row` is a GRAPH
    /// row (0-based); `None` leaves the entity spanless.
    pub(super) fn impact_probe_entity(name: &str, start_row: Option<u32>) -> Entity {
        let file_id = FilePathId::new(format!("src/{name}.ts"));
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([3; 32]),
                signature_hash: Hash256::from_bytes([3; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(file_id.clone()),
            span: start_row.map(|row| kin_model::entity::SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte: 40,
                start_line: row,
                start_col: 0,
                end_line: row + 2,
                end_col: 1,
            }),
            signature: format!("export function {name}()"),
            visibility: Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    thread_local! {
        static TEST_FILE_HASHES: std::cell::RefCell<HashMap<FilePathId, Hash256>> =
            std::cell::RefCell::new(HashMap::new());
    }

    fn reset_trace_source_registry() {
        TEST_FILE_HASHES.with(|map| map.borrow_mut().clear());
    }

    fn register_trace_source(file_id: &FilePathId, hash: Hash256) {
        TEST_FILE_HASHES.with(|map| {
            map.borrow_mut().insert(file_id.clone(), hash);
        });
    }

    fn build_exact_test_change(
        entities: Vec<Entity>,
        entries: Vec<(kin_model::ArtifactId, kin_model::RepoPath, Hash256)>,
    ) -> SemanticChange {
        exact_test_change(
            vec![],
            "admit exact MCP test tree",
            entities
                .into_iter()
                .map(|new| kin_model::EntityDelta::Added { new })
                .collect(),
            entries
                .into_iter()
                .map(|(artifact_id, path, hash)| kin_model::TreeDelta::Added {
                    artifact_id,
                    new: kin_model::LocatedEntry::new(
                        path,
                        kin_model::TreeEntry::blob(hash, false),
                    ),
                })
                .collect(),
        )
    }

    fn exact_test_change(
        parents: Vec<SemanticChangeId>,
        message: &str,
        entity_deltas: Vec<kin_model::EntityDelta>,
        tree_deltas: Vec<kin_model::TreeDelta>,
    ) -> SemanticChange {
        let admission_policy_delta = parents.is_empty().then(|| {
            kin_model::AdmissionPolicyDelta::initialize(kin_model::SharedAdmissionPolicy::empty(0))
        });
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            parents,
            timestamp: kin_model::Timestamp::now(),
            author: AuthorId::new("kin-mcp-test"),
            message: message.into(),
            entity_deltas,
            relation_deltas: vec![],
            tree_deltas,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta,
            external_reference_deltas: Vec::new(),
        };
        change.id = kin_model::compute_semantic_change_id(&change).unwrap();
        change
    }

    fn model_blob_hash(store: &kin_blobs::BlobStore, bytes: &[u8]) -> Hash256 {
        let hash = store.write(bytes).unwrap();
        Hash256::from_bytes(*hash.as_bytes())
    }

    fn open_test_repository_authority(
        root: &std::path::Path,
    ) -> (
        kin_model::RepositoryId,
        kin_model::WorkspaceId,
        RepositoryAuthorityManager<LocalFileBackend>,
    ) {
        let layout = kin_core::KinLayout::new(root.join(".kin"));
        let manifest = kin_core::KinManifest::load(&layout.manifest_path()).unwrap();
        let repository_id = kin_model::RepositoryId::new(manifest.repo_id).unwrap();
        let workspace_id = kin_model::WorkspaceId::from_uuid(
            uuid::Uuid::parse_str(&manifest.workspace_id).unwrap(),
        );
        let authority = RepositoryAuthorityManager::open(
            repository_id.clone(),
            Arc::new(LocalFileBackend::new(layout.kindb_dir())),
        )
        .unwrap();
        (repository_id, workspace_id, authority)
    }

    fn copy_test_source_bodies(
        root: &std::path::Path,
        authority: &RepositoryAuthorityManager<LocalFileBackend>,
        changes: &[SemanticChange],
    ) {
        let legacy = kin_blobs::BlobStore::new(root.join(".kin/objects")).unwrap();
        let mut copied = HashSet::new();
        for hash in changes
            .iter()
            .flat_map(|change| change.tree_deltas.iter())
            .filter_map(kin_model::TreeDelta::new_state)
            .filter_map(|located| located.entry.blob_identity())
        {
            if !copied.insert(hash) {
                continue;
            }
            let blob_hash = kin_blobs::Hash256::from_bytes(*hash.as_bytes());
            if let Ok(bytes) = legacy.read(&blob_hash) {
                authority.save_source_blob(hash, &bytes).unwrap();
            }
        }
    }

    fn test_source_blob_path(root: &std::path::Path, hash: Hash256) -> PathBuf {
        let manifest =
            kin_core::KinManifest::load(&root.join(".kin").join("manifest.json")).unwrap();
        let digest = hash.to_string();
        root.join(".kin")
            .join("kindb")
            .join(manifest.repo_id)
            .join("source-blobs")
            .join("sha256")
            .join(&digest[..2])
            .join(digest)
    }

    fn initialize_test_repository(root: &std::path::Path, initial_change: &SemanticChange) {
        assert!(
            initial_change.parents.is_empty(),
            "test repository bootstrap requires a root change"
        );
        let kin_dir = root.join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        fs::write(
            kin_dir.join("version"),
            kin_core::layout::KIN_LAYOUT_VERSION.to_string(),
        )
        .unwrap();
        kin_core::KinConfig::default()
            .save(&kin_dir.join("config.toml"))
            .unwrap();
        let manifest = kin_core::KinManifest::new();
        manifest.save(&kin_dir.join("manifest.json")).unwrap();
        fs::create_dir_all(kin_dir.join("kindb")).unwrap();

        let repository_id = kin_model::RepositoryId::new(manifest.repo_id).unwrap();
        let workspace_id = kin_model::WorkspaceId::from_uuid(
            uuid::Uuid::parse_str(&manifest.workspace_id).unwrap(),
        );
        let authority = RepositoryAuthorityManager::open(
            repository_id.clone(),
            Arc::new(LocalFileBackend::new(kin_dir.join("kindb"))),
        )
        .unwrap();
        copy_test_source_bodies(root, &authority, std::slice::from_ref(initial_change));

        let shared_policy = initial_change
            .admission_policy_delta
            .as_ref()
            .and_then(|delta| delta.new.clone())
            .expect("root test change must initialize shared admission policy");
        kin_core::initialize_repository_authority(
            &authority,
            repository_id,
            workspace_id,
            kin_model::AdmissionCase::Sensitive,
            kin_model::RefName::branch(b"main").unwrap(),
            shared_policy,
            Some(initial_change.clone()),
        )
        .unwrap();
    }

    fn advance_test_repository(root: &std::path::Path, change: &SemanticChange) {
        let (repository_id, workspace_id, authority) = open_test_repository_authority(root);
        copy_test_source_bodies(root, &authority, std::slice::from_ref(change));

        let lease = authority.read_authority();
        let roots = lease.roots().clone();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == workspace_id)
            .cloned()
            .unwrap();
        let default_ref = lease.metadata().ref_state.default_ref.clone().unwrap();
        let current_ref = lease
            .metadata()
            .ref_state
            .refs
            .iter()
            .find(|repository_ref| repository_ref.name == default_ref)
            .cloned()
            .unwrap();
        drop(lease);

        let target_tree = workspace.tree.apply(&change.tree_deltas).unwrap();
        let target_tree_hash = kin_model::compute_resolved_tree_hash(&target_tree).unwrap();
        let shared_policy = change
            .admission_policy_delta
            .as_ref()
            .and_then(|delta| delta.new.clone())
            .unwrap_or_else(|| workspace.shared_admission_policy.clone());
        let admission_policy = kin_model::EffectiveAdmissionPolicyStamp {
            shared: shared_policy.stamp(),
            local: workspace.admission_policy.local,
        };
        let new_target = kin_model::RefTarget::change(change.id);
        let transaction = kin_model::RepositoryTransaction {
            schema_version: kin_model::REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: kin_model::OperationId::new(),
            repository_id,
            expected_generation: roots.generation,
            expected_roots: roots,
            actor: AuthorId::new("kin-mcp-test"),
            reason: "advance exact MCP test repository".into(),
            external_objects: vec![],
            git_authority_delta: None,
            changes: vec![change.clone()],
            aliases: vec![],
            ref_mutations: vec![kin_model::RefMutation {
                name: default_ref,
                expected: kin_model::RefExpectation::MustEqual {
                    target: current_ref.target,
                },
                new_target: Some(new_target.clone()),
                policy: kin_model::RefUpdatePolicy::FastForwardOnly,
            }],
            default_ref_mutation: None,
            workspace_mutation: Some(kin_model::WorkspaceMutation {
                workspace_id,
                expected: kin_model::WorkspaceExpectation::MustEqual {
                    generation: workspace.generation,
                    head: workspace.head.clone(),
                    base_target: workspace.base_target.clone(),
                    base_tree_hash: workspace.base_tree_hash,
                    tree_hash: workspace.tree_hash,
                    semantic_overlay_hash: workspace.semantic_overlay_hash,
                    admission_policy: workspace.admission_policy,
                },
                new_generation: workspace.generation + 1,
                new_head: workspace.head,
                new_base_target: Some(new_target),
                new_base_tree_hash: Some(target_tree_hash),
                tree_deltas: change.tree_deltas.clone(),
                new_tree_hash: target_tree_hash,
                semantic_delta: kin_model::WorkspaceSemanticDelta::new(
                    change.entity_deltas.clone(),
                    change.relation_deltas.clone(),
                )
                .unwrap(),
                new_shared_admission_policy: shared_policy,
                new_admission_policy: admission_policy,
            }),
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        authority
            .commit_repository_transaction(transaction)
            .unwrap();
    }

    /// Advance the workspace's exact graph-owned tree at one path WITHOUT
    /// committing: the shape `publish_workspace_tree` produces on every editor
    /// save the daemon admits. Generation and tree hash move; `base_target` and
    /// `base_tree_hash` stay pinned; no change is recorded and no ref moves.
    ///
    /// This exists because `advance_test_repository` cannot express it. That
    /// helper sets `new_base_tree_hash == new_tree_hash`, so the workspace it
    /// leaves is always CLEAN, and a head read of a clean workspace is
    /// indistinguishable from a read at base. Every fixture in this family was
    /// built that way, which is why a head read could be pointed back at the base
    /// tree and the whole suite still passed.
    ///
    /// Returns the new blob digest so a caller can stamp it as an entity's
    /// recorded source provenance (or deliberately not stamp it).
    fn admit_test_workspace_tree(
        root: &std::path::Path,
        path: &kin_model::RepoPath,
        new_bytes: &[u8],
    ) -> Hash256 {
        let (repository_id, workspace_id, authority) = open_test_repository_authority(root);
        let legacy = kin_blobs::BlobStore::new(root.join(".kin/objects")).unwrap();
        let new_hash = model_blob_hash(&legacy, new_bytes);
        authority.save_source_blob(new_hash, new_bytes).unwrap();

        let lease = authority.read_authority();
        let roots = lease.roots().clone();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == workspace_id)
            .cloned()
            .unwrap();
        drop(lease);

        let old = workspace.tree.artifact_at_path(path).cloned().unwrap();
        let kin_model::change::TreeEntry::Blob { executable, .. } = old.entry else {
            panic!("test fixture path {path} is not a blob");
        };
        let deltas = vec![kin_model::TreeDelta::Updated {
            artifact_id: old.artifact_id,
            old: kin_model::LocatedEntry::new(old.path.clone(), old.entry.clone()),
            new: kin_model::LocatedEntry::new(
                old.path.clone(),
                kin_model::change::TreeEntry::Blob {
                    hash: new_hash,
                    executable,
                },
            ),
        }];
        let desired = workspace.tree.apply(&deltas).unwrap();
        let new_tree_hash = kin_model::compute_resolved_tree_hash(&desired).unwrap();

        let transaction = kin_model::RepositoryTransaction {
            schema_version: kin_model::REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: kin_model::OperationId::new(),
            repository_id,
            expected_generation: roots.generation,
            expected_roots: roots,
            actor: AuthorId::new("kin-mcp-test"),
            reason: "admit exact workspace tree without committing".into(),
            external_objects: vec![],
            git_authority_delta: None,
            // No history node and no ref movement: this is the whole point of the
            // shape. The tree moves past base and nothing commits it.
            changes: Vec::new(),
            aliases: vec![],
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: Some(kin_model::WorkspaceMutation {
                workspace_id,
                expected: kin_model::WorkspaceExpectation::MustEqual {
                    generation: workspace.generation,
                    head: workspace.head.clone(),
                    base_target: workspace.base_target.clone(),
                    base_tree_hash: workspace.base_tree_hash,
                    tree_hash: workspace.tree_hash,
                    semantic_overlay_hash: workspace.semantic_overlay_hash,
                    admission_policy: workspace.admission_policy,
                },
                new_generation: workspace.generation + 1,
                new_head: workspace.head.clone(),
                new_base_target: workspace.base_target.clone(),
                new_base_tree_hash: workspace.base_tree_hash,
                tree_deltas: deltas,
                new_tree_hash,
                // The admission path publishes an empty semantic delta: entity
                // spans are re-derived by a LATER transaction, which is exactly
                // the window a head read has to cope with.
                semantic_delta: kin_model::WorkspaceSemanticDelta::default(),
                new_shared_admission_policy: workspace.shared_admission_policy.clone(),
                new_admission_policy: workspace.admission_policy,
            }),
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        authority
            .commit_repository_transaction(transaction)
            .unwrap();
        new_hash
    }

    /// One source-backed entity spanning a whole file, for the divergent-tree
    /// fixtures below. `digest` becomes the entity's recorded source provenance
    /// when supplied; `None` leaves it unstamped.
    fn whole_file_entity(file_id: &FilePathId, content: &str, digest: Option<Hash256>) -> Entity {
        let mut metadata = kin_model::entity::EntityMetadata::default();
        if let Some(digest) = digest {
            metadata.extra.insert(
                "blob_hash".into(),
                serde_json::Value::String(digest.to_string()),
            );
        }
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "alpha".into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([7; 32]),
                signature_hash: Hash256::from_bytes([7; 32]),
                behavior_hash: Hash256::from_bytes([7; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id.clone(),
                start_byte: 0,
                end_byte: content.len(),
                start_line: 0,
                start_col: 0,
                end_line: 0,
                end_col: content.len() as u32,
            }),
            signature: "export function alpha()".into(),
            visibility: Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata,
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn initialize_release_test_repository(root: &std::path::Path, store: &EmptyStore) {
        if store.repository_refs.is_empty() {
            kin_core::init(root).unwrap();
            return;
        }

        let roots = store
            .changes_by_id
            .values()
            .filter(|change| change.parents.is_empty())
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(roots.len(), 1, "release fixture requires one history root");
        let root_change = roots[0].clone();
        initialize_test_repository(root, &root_change);

        let (repository_id, _, authority) = open_test_repository_authority(root);
        let lease = authority.read_authority();
        let roots = lease.roots().clone();
        let main = kin_model::RefName::branch(b"main").unwrap();
        let initial_main = lease
            .metadata()
            .ref_state
            .refs
            .iter()
            .find(|repository_ref| repository_ref.name == main)
            .cloned()
            .unwrap();
        drop(lease);

        let mut committed = HashSet::from([root_change.id]);
        let mut remaining = store
            .changes_by_id
            .values()
            .filter(|change| change.id != root_change.id)
            .cloned()
            .collect::<Vec<_>>();
        let mut ordered = Vec::with_capacity(remaining.len());
        while !remaining.is_empty() {
            let index = remaining
                .iter()
                .position(|change| {
                    change
                        .parents
                        .iter()
                        .all(|parent| committed.contains(parent))
                })
                .expect("release fixture history must be connected and acyclic");
            let change = remaining.remove(index);
            committed.insert(change.id);
            ordered.push(change);
        }

        let mut ref_mutations = Vec::new();
        for (name, head) in &store.repository_refs {
            let target = kin_model::RefTarget::change(*head);
            if *name == main {
                if target != initial_main.target {
                    ref_mutations.push(kin_model::RefMutation {
                        name: name.clone(),
                        expected: kin_model::RefExpectation::MustEqual {
                            target: initial_main.target.clone(),
                        },
                        new_target: Some(target),
                        policy: kin_model::RefUpdatePolicy::ForceWithLease,
                    });
                }
            } else {
                ref_mutations.push(kin_model::RefMutation {
                    name: name.clone(),
                    expected: kin_model::RefExpectation::MustNotExist,
                    new_target: Some(target),
                    policy: kin_model::RefUpdatePolicy::FastForwardOnly,
                });
            }
        }
        if ordered.is_empty() && ref_mutations.is_empty() {
            return;
        }
        let transaction = kin_model::RepositoryTransaction {
            schema_version: kin_model::REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: kin_model::OperationId::new(),
            repository_id,
            expected_generation: roots.generation,
            expected_roots: roots,
            actor: AuthorId::new("kin-mcp-release-test"),
            reason: "install exact release-check repository authority".into(),
            external_objects: vec![],
            git_authority_delta: None,
            changes: ordered,
            aliases: vec![],
            ref_mutations,
            default_ref_mutation: None,
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        authority
            .commit_repository_transaction(transaction)
            .unwrap();
    }

    pub(super) fn tool_result_json(result: ToolCallResult) -> serde_json::Value {
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text,
        };
        serde_json::from_str(text).unwrap()
    }

    fn install_empty_store_exact_tree(store: &mut EmptyStore, root: &std::path::Path) {
        let mut hashes = store.file_hashes.clone();
        TEST_FILE_HASHES.with(|registered| {
            hashes.extend(registered.borrow().clone());
        });
        let entries = hashes
            .into_iter()
            .map(|(file, hash)| {
                (
                    kin_model::ArtifactId::new(),
                    kin_model::RepoPath::from_utf8(file.0).unwrap(),
                    hash,
                )
            })
            .collect();
        let change =
            build_exact_test_change(store.entities_by_id.values().cloned().collect(), entries);
        store.changes_by_id.insert(change.id, change.clone());
        initialize_test_repository(root, &change);
    }

    /// The default arm: a request that opens authority for itself. Tests that
    /// bound the open COUNT depend on this staying the pinned arm, because a
    /// shared open would hold that count flat whether or not the path under
    /// test still holds authority once per request.
    fn test_repository_authority(root: &std::path::Path) -> RequestRepositoryAuthority {
        RequestRepositoryAuthority::pinned(test_repository_binding(root))
    }

    fn test_repository_binding(
        root: &std::path::Path,
    ) -> kin_core::LocalRepositoryAuthorityBinding {
        let layout = kin_core::KinLayout::discover(root)
            .expect("test repository authority must be discoverable");
        kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
            .expect("test repository authority must open")
    }

    impl kin_model::graph::EntityStore for EmptyStore {
        type Error = KinDbError;

        fn get_entity(&self, id: &EntityId) -> std::result::Result<Option<Entity>, Self::Error> {
            Ok(self.entities_by_id.get(id).cloned())
        }
        fn get_relations(
            &self,
            id: &EntityId,
            kinds: &[RelationKind],
        ) -> std::result::Result<Vec<Relation>, Self::Error> {
            Ok(self
                .relations_by_entity
                .get(id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|relation| kinds.contains(&relation.kind))
                .collect())
        }
        fn get_all_relations_for_entity(
            &self,
            id: &EntityId,
        ) -> std::result::Result<Vec<Relation>, Self::Error> {
            Ok(self
                .relations_by_entity
                .get(id)
                .cloned()
                .unwrap_or_default())
        }
        fn get_downstream_impact(
            &self,
            _: &EntityId,
            _: u32,
        ) -> std::result::Result<Vec<Entity>, Self::Error> {
            Ok(vec![])
        }
        fn get_dependency_neighborhood(
            &self,
            _: &EntityId,
            _: u32,
        ) -> std::result::Result<SubGraph, Self::Error> {
            Ok(SubGraph::default())
        }
        fn expand_neighborhood(
            &self,
            _: &[EntityId],
            _: &[RelationKind],
            _: u32,
        ) -> std::result::Result<SubGraph, Self::Error> {
            Ok(SubGraph::default())
        }
        fn find_dead_code(&self) -> std::result::Result<Vec<Entity>, Self::Error> {
            Ok(self.dead_entities.clone())
        }
        fn has_incoming_relation_kinds(
            &self,
            id: &EntityId,
            _: &[RelationKind],
            _: bool,
        ) -> std::result::Result<bool, Self::Error> {
            Ok(self.live_entity_ids.contains(id))
        }
        fn query_entities(
            &self,
            filter: &EntityFilter,
        ) -> std::result::Result<Vec<Entity>, Self::Error> {
            if let Some(file_path) = filter.file_path.as_ref() {
                return Ok(self
                    .entities_by_file
                    .get(&file_path.0)
                    .cloned()
                    .unwrap_or_default());
            }

            let mut entities = self.entities_by_id.values().cloned().collect::<Vec<_>>();
            if let Some(name_pattern) = filter.name_pattern.as_ref() {
                let needle = name_pattern.to_ascii_lowercase();
                entities.retain(|entity| entity.name.to_ascii_lowercase().contains(&needle));
            }
            Ok(entities)
        }
        fn list_all_entities(&self) -> std::result::Result<Vec<Entity>, Self::Error> {
            Ok(self.entities_by_id.values().cloned().collect())
        }
        fn upsert_entity(&self, _: &Entity) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn upsert_relation(&self, _: &Relation) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn remove_entity(&self, _: &EntityId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn remove_relation(&self, _: &RelationId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn upsert_shallow_file(
            &self,
            _: &kin_model::ShallowTrackedFile,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_shallow_files(
            &self,
        ) -> std::result::Result<Vec<kin_model::ShallowTrackedFile>, Self::Error> {
            Ok(vec![])
        }
        fn upsert_structured_artifact(
            &self,
            _: &kin_model::StructuredArtifact,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_structured_artifacts(
            &self,
        ) -> std::result::Result<Vec<kin_model::StructuredArtifact>, Self::Error> {
            Ok(vec![])
        }
        fn delete_structured_artifact(
            &self,
            _: &FilePathId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn upsert_opaque_artifact(
            &self,
            _: &kin_model::OpaqueArtifact,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_opaque_artifacts(
            &self,
        ) -> std::result::Result<Vec<kin_model::OpaqueArtifact>, Self::Error> {
            Ok(vec![])
        }
        fn delete_opaque_artifact(&self, _: &FilePathId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn upsert_file_layout(
            &self,
            _: &kin_model::FileLayout,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_file_layout(
            &self,
            _: &FilePathId,
        ) -> std::result::Result<Option<kin_model::FileLayout>, Self::Error> {
            Ok(None)
        }
        fn list_file_layouts(
            &self,
        ) -> std::result::Result<Vec<kin_model::FileLayout>, Self::Error> {
            Ok(vec![])
        }
        fn delete_file_layout(&self, _: &FilePathId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn artifact_id_at_path(&self, _: &kin_model::RepoPath) -> Option<kin_model::ArtifactId> {
            None
        }
        fn get_tree_entry(
            &self,
            _: &FilePathId,
        ) -> std::result::Result<Option<kin_model::TreeEntry>, Self::Error> {
            Ok(None)
        }
        fn apply_transaction_delta(
            &self,
            _: &kin_model::TransactionDelta,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn traverse(
            &self,
            _: &kin_model::GraphNodeId,
            _: &[RelationKind],
            _: u32,
        ) -> std::result::Result<SubGraph, Self::Error> {
            Ok(SubGraph::default())
        }
        fn get_shallow_file(
            &self,
            _: &FilePathId,
        ) -> std::result::Result<Option<kin_model::ShallowTrackedFile>, Self::Error> {
            Ok(None)
        }
        fn get_structured_artifact(
            &self,
            _: &FilePathId,
        ) -> std::result::Result<Option<kin_model::StructuredArtifact>, Self::Error> {
            Ok(None)
        }
        fn get_opaque_artifact(
            &self,
            _: &FilePathId,
        ) -> std::result::Result<Option<kin_model::OpaqueArtifact>, Self::Error> {
            Ok(None)
        }
    }

    impl kin_model::graph::ChangeStore for EmptyStore {
        type Error = KinDbError;

        fn get_entity_history(
            &self,
            _: &EntityId,
        ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
            Ok(vec![])
        }
        fn find_merge_bases(
            &self,
            _: &SemanticChangeId,
            _: &SemanticChangeId,
        ) -> std::result::Result<Vec<SemanticChangeId>, Self::Error> {
            Ok(vec![])
        }
        fn create_change(&self, _: &SemanticChange) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_change(
            &self,
            id: &SemanticChangeId,
        ) -> std::result::Result<Option<SemanticChange>, Self::Error> {
            Ok(self.changes_by_id.get(id).cloned())
        }
        fn get_changes_since(
            &self,
            _: &SemanticChangeId,
            _: &SemanticChangeId,
        ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
            Ok(vec![])
        }
    }

    impl kin_model::graph::WorkStore for EmptyStore {
        type Error = KinDbError;

        fn create_work_item(
            &self,
            _: &kin_model::WorkItem,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_work_item(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Option<kin_model::WorkItem>, Self::Error> {
            Ok(None)
        }
        fn list_work_items(
            &self,
            _: &kin_model::WorkFilter,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn update_work_status(
            &self,
            _: &kin_model::WorkId,
            _: kin_model::WorkStatus,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_work_item(&self, _: &kin_model::WorkId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_annotation(
            &self,
            _: &kin_model::Annotation,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_annotation(
            &self,
            _: &kin_model::AnnotationId,
        ) -> std::result::Result<Option<kin_model::Annotation>, Self::Error> {
            Ok(None)
        }
        fn list_annotations(
            &self,
            _: &kin_model::AnnotationFilter,
        ) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> {
            Ok(vec![])
        }
        fn update_annotation_staleness(
            &self,
            _: &kin_model::AnnotationId,
            _: kin_model::StalenessState,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_annotation(
            &self,
            _: &kin_model::AnnotationId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_work_link(
            &self,
            _: &kin_model::WorkLink,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_work_link(
            &self,
            _: &kin_model::WorkLink,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_work_for_scope(
            &self,
            _: &kin_model::WorkScope,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_annotations_for_scope(
            &self,
            _: &kin_model::WorkScope,
        ) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> {
            Ok(vec![])
        }
        fn get_child_work_items(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_parent_work_items(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_blockers(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_blocked_work_items(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_implementors(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkScope>, Self::Error> {
            Ok(vec![])
        }
        fn get_annotations_for_work_item(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> {
            Ok(vec![])
        }
    }

    impl kin_model::graph::ReviewStore for EmptyStore {
        type Error = KinDbError;

        fn create_review(
            &self,
            _: &kin_model::review::Review,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_review(
            &self,
            _: &kin_model::review::ReviewId,
        ) -> std::result::Result<Option<kin_model::review::Review>, Self::Error> {
            Ok(None)
        }
        fn list_reviews(
            &self,
            _: &kin_model::review::ReviewFilter,
        ) -> std::result::Result<Vec<kin_model::review::Review>, Self::Error> {
            Ok(vec![])
        }
        fn update_review_state(
            &self,
            _: &kin_model::review::ReviewId,
            _: kin_model::review::ReviewDecisionState,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_review(
            &self,
            _: &kin_model::review::ReviewId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn add_review_decision(
            &self,
            _: &kin_model::review::ReviewId,
            _: &kin_model::review::ReviewDecision,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_review_decisions(
            &self,
            _: &kin_model::review::ReviewId,
        ) -> std::result::Result<Vec<kin_model::review::ReviewDecision>, Self::Error> {
            Ok(vec![])
        }
        fn add_review_note(
            &self,
            _: &kin_model::review::ReviewNote,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_review_notes(
            &self,
            _: &kin_model::review::ReviewId,
        ) -> std::result::Result<Vec<kin_model::review::ReviewNote>, Self::Error> {
            Ok(vec![])
        }
        fn delete_review_note(
            &self,
            _: &kin_model::review::ReviewNoteId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_review_discussion(
            &self,
            _: &kin_model::review::ReviewDiscussion,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_review_discussions(
            &self,
            _: &kin_model::review::ReviewId,
        ) -> std::result::Result<Vec<kin_model::review::ReviewDiscussion>, Self::Error> {
            Ok(vec![])
        }
        fn add_discussion_comment(
            &self,
            _: &kin_model::review::ReviewDiscussionId,
            _: &kin_model::review::ReviewComment,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn set_discussion_state(
            &self,
            _: &kin_model::review::ReviewDiscussionId,
            _: kin_model::review::ReviewDiscussionState,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn assign_reviewer(
            &self,
            _: &kin_model::review::ReviewAssignment,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_review_assignments(
            &self,
            _: &kin_model::review::ReviewId,
        ) -> std::result::Result<Vec<kin_model::review::ReviewAssignment>, Self::Error> {
            Ok(vec![])
        }
        fn remove_reviewer(
            &self,
            _: &kin_model::review::ReviewId,
            _: &str,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
    }

    impl kin_model::graph::VerificationStore for EmptyStore {
        type Error = KinDbError;

        fn create_test_case(
            &self,
            _: &kin_model::verification::TestCase,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_test_case(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<Option<kin_model::verification::TestCase>, Self::Error> {
            Ok(None)
        }
        fn get_tests_for_entity(
            &self,
            _: &EntityId,
        ) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
            Ok(vec![])
        }
        fn delete_test_case(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_assertion(
            &self,
            _: &kin_model::verification::Assertion,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_assertion(
            &self,
            _: &kin_model::verification::AssertionId,
        ) -> std::result::Result<Option<kin_model::verification::Assertion>, Self::Error> {
            Ok(None)
        }
        fn get_coverage_summary(
            &self,
        ) -> std::result::Result<kin_model::verification::CoverageSummary, Self::Error> {
            Ok(kin_model::verification::CoverageSummary {
                total_entities: 0,
                covered_entities: 0,
                coverage_ratio: 0.0,
                missing_proof: vec![],
            })
        }
        fn create_verification_run(
            &self,
            _: &kin_model::verification::VerificationRun,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_verification_run(
            &self,
            _: &kin_model::verification::VerificationRunId,
        ) -> std::result::Result<Option<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(None)
        }
        fn list_runs_for_test(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(vec![])
        }
        fn create_test_covers_entity(
            &self,
            _: &kin_model::verification::TestId,
            _: &EntityId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_test_covers_contract(
            &self,
            _: &kin_model::verification::TestId,
            _: &ContractId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_test_verifies_work(
            &self,
            _: &kin_model::verification::TestId,
            _: &kin_model::WorkId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_tests_covering_contract(
            &self,
            _: &ContractId,
        ) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
            Ok(vec![])
        }
        fn get_tests_verifying_work(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
            Ok(vec![])
        }
        fn create_mock_hint(
            &self,
            _: &kin_model::verification::MockHint,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_mock_hints_for_test(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<Vec<kin_model::verification::MockHint>, Self::Error> {
            Ok(vec![])
        }
        fn link_run_proves_entity(
            &self,
            _: &kin_model::verification::VerificationRunId,
            _: &EntityId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn link_run_proves_work(
            &self,
            _: &kin_model::verification::VerificationRunId,
            _: &kin_model::WorkId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_runs_proving_entity(
            &self,
            _: &kin_model::EntityId,
        ) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(vec![])
        }
        fn list_runs_proving_work(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(vec![])
        }
        fn get_contract_coverage_summary(
            &self,
        ) -> std::result::Result<kin_model::verification::ContractCoverageSummary, Self::Error>
        {
            Ok(kin_model::verification::ContractCoverageSummary {
                total_contracts: 0,
                covered_contracts: 0,
                coverage_ratio: 0.0,
                uncovered_contract_ids: vec![],
            })
        }
        fn create_contract(
            &self,
            _: &kin_model::contract::Contract,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_contract(
            &self,
            _: &kin_model::ids::ContractId,
        ) -> std::result::Result<Option<kin_model::contract::Contract>, Self::Error> {
            Ok(None)
        }
        fn list_contracts(
            &self,
        ) -> std::result::Result<Vec<kin_model::contract::Contract>, Self::Error> {
            Ok(vec![])
        }
    }

    impl kin_model::graph::ProvenanceStore for EmptyStore {
        type Error = KinDbError;

        fn create_actor(
            &self,
            _: &kin_model::provenance::Actor,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_actor(
            &self,
            id: &kin_model::provenance::ActorId,
        ) -> std::result::Result<Option<kin_model::provenance::Actor>, Self::Error> {
            Ok(self.actors_by_id.get(id).cloned())
        }
        fn list_actors(
            &self,
        ) -> std::result::Result<Vec<kin_model::provenance::Actor>, Self::Error> {
            Ok(self.actors_by_id.values().cloned().collect())
        }
        fn create_delegation(
            &self,
            _: &kin_model::provenance::Delegation,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_delegations_for_actor(
            &self,
            _: &kin_model::provenance::ActorId,
        ) -> std::result::Result<Vec<kin_model::provenance::Delegation>, Self::Error> {
            Ok(vec![])
        }
        fn create_approval(
            &self,
            _: &kin_model::provenance::Approval,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_approvals_for_change(
            &self,
            id: &SemanticChangeId,
        ) -> std::result::Result<Vec<kin_model::provenance::Approval>, Self::Error> {
            Ok(self
                .approvals_by_change
                .get(id)
                .cloned()
                .unwrap_or_default())
        }
        fn record_audit_event(
            &self,
            _: &kin_model::provenance::AuditEvent,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn query_audit_events(
            &self,
            _: Option<&kin_model::provenance::ActorId>,
            _: usize,
        ) -> std::result::Result<Vec<kin_model::provenance::AuditEvent>, Self::Error> {
            Ok(vec![])
        }
    }

    impl kin_model::graph::SessionStore for EmptyStore {
        type Error = KinDbError;

        fn upsert_session(
            &self,
            _: &kin_model::session::AgentSession,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_session(
            &self,
            _: &kin_model::SessionId,
        ) -> std::result::Result<Option<kin_model::session::AgentSession>, Self::Error> {
            Ok(None)
        }
        fn delete_session(&self, _: &kin_model::SessionId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_sessions(
            &self,
        ) -> std::result::Result<Vec<kin_model::session::AgentSession>, Self::Error> {
            Ok(vec![])
        }
        fn update_heartbeat(
            &self,
            _: &kin_model::SessionId,
            _: &kin_model::timestamp::Timestamp,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn register_intent(
            &self,
            _: &kin_model::session::Intent,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_intent(
            &self,
            _: &kin_model::IntentId,
        ) -> std::result::Result<Option<kin_model::session::Intent>, Self::Error> {
            Ok(None)
        }
        fn delete_intent(&self, _: &kin_model::IntentId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_intents_for_session(
            &self,
            _: &kin_model::SessionId,
        ) -> std::result::Result<Vec<kin_model::session::Intent>, Self::Error> {
            Ok(vec![])
        }
        fn list_all_intents(
            &self,
        ) -> std::result::Result<Vec<kin_model::session::Intent>, Self::Error> {
            Ok(vec![])
        }
    }

    impl kin_model::graph::GraphStore for EmptyStore {
        type Error = KinDbError;
    }

    #[test]
    fn parse_entity_id_valid() {
        let id = EntityId::new().to_string();
        let result = parse_entity_id(&id);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_entity_id_invalid() {
        let result = parse_entity_id("not-a-uuid");
        assert!(result.is_err());
    }

    #[test]
    fn parse_change_id_valid() {
        let hex = "aa".repeat(32);
        let result = parse_change_id(&hex);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_change_id_invalid() {
        let result = parse_change_id("zzz");
        assert!(result.is_err());
    }

    #[test]
    fn parse_transport_values() {
        assert_eq!(parse_transport("mcp"), SessionTransport::Mcp);
        assert_eq!(parse_transport("cli"), SessionTransport::Cli);
        assert_eq!(parse_transport("wrapper"), SessionTransport::Wrapper);
        assert_eq!(parse_transport("ui"), SessionTransport::Ui);
        assert_eq!(parse_transport("unknown"), SessionTransport::Mcp);
    }

    #[test]
    fn parse_lock_type_values() {
        assert_eq!(parse_lock_type("soft"), LockType::Soft);
        assert_eq!(parse_lock_type("hard"), LockType::Hard);
        assert_eq!(parse_lock_type("anything"), LockType::Soft);
    }

    #[test]
    fn parse_session_id_valid() {
        let id = SessionId::new().to_string();
        let result = parse_session_id(&id);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_scopes_valid() {
        let entity_id = EntityId::new();
        let val = serde_json::json!([
            { "Entity": entity_id },
            { "Artifact": "src/main.rs" }
        ]);
        let result = parse_scopes(&val);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn parse_scopes_invalid() {
        let val = serde_json::json!("not an array");
        let result = parse_scopes(&val);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn unknown_tool_returns_error() {
        let store = EmptyStore::default();
        let sessions = SessionRegistry::new();
        let args = HashMap::new();
        let result = handle_tool_call(
            "nonexistent_tool",
            &args,
            &store,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
            None,
        )
        .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), McpError::ToolNotFound(_)));
    }

    #[tokio::test]
    async fn session_start_and_heartbeat_and_end() {
        let store = EmptyStore::default();
        let sessions = SessionRegistry::new();

        // Start a session
        let mut start_args = HashMap::new();
        start_args.insert("vendor".into(), serde_json::json!("claude-code"));
        start_args.insert("client_name".into(), serde_json::json!("test-client"));
        start_args.insert("cwd".into(), serde_json::json!("/project"));
        start_args.insert("transport".into(), serde_json::json!("mcp"));

        let result = handle_tool_call(
            "kin_session_start",
            &start_args,
            &store,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
            None,
        )
        .await
        .unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["status"], "active");
        assert_eq!(response["vendor"], "claude-code");

        let session_id = response["session_id"].as_str().unwrap().to_string();

        // Heartbeat
        let mut hb_args = HashMap::new();
        hb_args.insert("session_id".into(), serde_json::json!(session_id));
        let result = handle_tool_call(
            "kin_session_heartbeat",
            &hb_args,
            &store,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
            None,
        )
        .await
        .unwrap();
        assert!(result.is_error.is_none());

        // End session
        let mut end_args = HashMap::new();
        end_args.insert("session_id".into(), serde_json::json!(session_id));
        let result = handle_tool_call(
            "kin_session_end",
            &end_args,
            &store,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
            None,
        )
        .await
        .unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["status"], "ended");
    }

    #[tokio::test]
    async fn register_and_release_intent() {
        let sessions = SessionRegistry::new();

        // Start session first
        let session = sessions.start_agent_session(
            "codex",
            "test",
            SessionTransport::Cli,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities {
                can_write: true,
                ..SessionCapabilities::default()
            },
        );
        let session_id_str = session.session_id.to_string();

        let entity_id = EntityId::new();

        // Register intent
        let mut args = HashMap::new();
        args.insert("session_id".into(), serde_json::json!(session_id_str));
        args.insert(
            "scopes".into(),
            serde_json::json!([{ "Entity": entity_id }]),
        );
        args.insert("lock_type".into(), serde_json::json!("hard"));
        args.insert(
            "task_description".into(),
            serde_json::json!("editing auth module"),
        );

        let result = sessions::handle_register_intent(
            &args,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
        )
        .await
        .unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["status"], "registered");
        let intent_id = response["intent_id"].as_str().unwrap().to_string();

        // Release intent
        let mut release_args = HashMap::new();
        release_args.insert("session_id".into(), serde_json::json!(session_id_str));
        release_args.insert("intent_id".into(), serde_json::json!(intent_id));
        let result = sessions::handle_release_intent(
            &release_args,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
        )
        .await
        .unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["status"], "released");
    }

    #[tokio::test]
    async fn check_traffic_with_active_intents() {
        let sessions = SessionRegistry::new();

        let session = sessions.start_agent_session(
            "claude-code",
            "test",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/project"),
            SessionCapabilities::default(),
        );

        let entity_id = EntityId::new();
        sessions.register_intent(
            session.session_id,
            vec![IntentScope::Entity(entity_id)],
            LockType::Soft,
            "refactoring".into(),
            None,
        );

        let mut args = HashMap::new();
        args.insert(
            "scopes".into(),
            serde_json::json!([{ "Entity": entity_id }]),
        );
        let result =
            sessions::handle_check_traffic(&args, &sessions, SessionAuthorityMode::OfflineFallback)
                .await
                .unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["scope_count"], 1);
        let reports = response["reports"].as_array().unwrap();
        assert_eq!(reports.len(), 1);
        assert!(!reports[0]["active_intents"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn register_intent_without_session_fails() {
        let sessions = SessionRegistry::new();

        let mut args = HashMap::new();
        args.insert(
            "session_id".into(),
            serde_json::json!(SessionId::new().to_string()),
        );
        args.insert(
            "scopes".into(),
            serde_json::json!([{ "Entity": EntityId::new() }]),
        );
        args.insert("task_description".into(), serde_json::json!("test"));

        let result = sessions::handle_register_intent(
            &args,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
        )
        .await
        .unwrap();
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn get_optional_bool_test() {
        let mut args = HashMap::new();
        args.insert("flag".into(), serde_json::json!(false));
        assert!(!get_optional_bool(&args, "flag", true));
        assert!(get_optional_bool(&args, "missing", true));
    }

    #[test]
    fn function_filter_includes_methods() {
        let kinds = parse_kind_filter("function").unwrap();
        assert!(kinds.contains(&EntityKind::Function));
        assert!(kinds.contains(&EntityKind::Method));
    }

    #[test]
    fn language_filter_supports_aliases() {
        assert_eq!(
            parse_language_filter("js"),
            Some(vec![LanguageId::JavaScript])
        );
        assert_eq!(
            parse_language_filter("ts"),
            Some(vec![LanguageId::TypeScript])
        );
        assert_eq!(parse_language_filter("py"), Some(vec![LanguageId::Python]));
        assert_eq!(parse_language_filter("c"), Some(vec![LanguageId::C]));
        assert_eq!(parse_language_filter("c++"), Some(vec![LanguageId::Cpp]));
        assert_eq!(parse_language_filter("cs"), Some(vec![LanguageId::CSharp]));
        assert_eq!(parse_language_filter("rb"), Some(vec![LanguageId::Ruby]));
    }

    #[test]
    fn build_semantic_search_request_applies_language_and_kind_filters() {
        let mut args = HashMap::new();
        args.insert("query".into(), serde_json::json!("save"));
        args.insert("kind".into(), serde_json::json!("function"));
        args.insert("language".into(), serde_json::json!("javascript"));
        args.insert("limit".into(), serde_json::json!(7));

        let (query, limit, filter) = build_semantic_search_request(&args).unwrap();
        assert_eq!(query, "save");
        assert_eq!(limit, 7);
        assert_eq!(filter.languages, Some(vec![LanguageId::JavaScript]));

        let kinds = filter.kinds.unwrap();
        assert!(kinds.contains(&EntityKind::Function));
        assert!(kinds.contains(&EntityKind::Method));
    }

    struct GraphBackedSource {
        _dir: tempfile::TempDir,
        _env: EnvVarGuard,
        entity: Entity,
        hash: Hash256,
        artifact_id: kin_model::ArtifactId,
    }

    /// Build an entity whose body is materialized only in a graph-owned blob
    /// store (no source file on disk), discoverable via `KIN_SOURCE_ROOT`. The
    /// caller registers `hash` against the entity's file path in its store so
    /// the graph-first read path can resolve the body. Callers must hold
    /// `ENV_MUTEX` for the lifetime of the returned guard.
    fn make_source_backed_entity(content: &str) -> GraphBackedSource {
        let dir = tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        let env = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());

        let blob_store = kin_blobs::BlobStore::new(kin_dir.join("objects")).unwrap();
        let hash = blob_store.write(content.as_bytes()).unwrap();

        let file_id = kin_model::ids::FilePathId::new("validate.ts");
        let artifact_id = kin_model::ArtifactId::new();

        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "validate_probe_range_1d8f8275".into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 0.9,
            },
            file_origin: Some(file_id.clone()),
            // Graph spans carry tree-sitter rows, which are 0-based: an entity
            // occupying the whole file starts at row 0, not row 1. The fixture
            // states the graph convention so the presentation assertions below
            // are testing the conversion rather than agreeing with themselves.
            span: Some(kin_model::entity::SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte: content.len(),
                start_line: 0,
                start_col: 0,
                end_line: (content.lines().count() as u32).saturating_sub(1),
                end_col: 1,
            }),
            signature: "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean".into(),
            visibility: kin_model::entity::Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: Some("Validate an inclusive numeric range.".into()),
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        GraphBackedSource {
            _dir: dir,
            _env: env,
            entity,
            hash,
            artifact_id,
        }
    }

    fn make_signature_only_python_entity(content: &str) -> GraphBackedSource {
        let dir = tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        let env = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());

        let blob_store = kin_blobs::BlobStore::new(kin_dir.join("objects")).unwrap();
        let hash = blob_store.write(content.as_bytes()).unwrap();

        let file_id = kin_model::ids::FilePathId::new("validate.py");
        let artifact_id = kin_model::ArtifactId::new();
        let signature = content
            .lines()
            .next()
            .unwrap_or_default()
            .trim_end_matches(':')
            .to_string();
        let end_byte = content.lines().next().unwrap_or_default().len();

        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "validate_probe_range_f0cc1f1d".into(),
            language: LanguageId::Python,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([9; 32]),
                signature_hash: Hash256::from_bytes([10; 32]),
                behavior_hash: Hash256::from_bytes([11; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 0.9,
            },
            file_origin: Some(file_id.clone()),
            // 0-based graph rows: the signature line is row 0.
            span: Some(kin_model::entity::SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte,
                start_line: 0,
                start_col: 0,
                end_line: 0,
                end_col: end_byte as u32,
            }),
            signature,
            visibility: kin_model::entity::Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        GraphBackedSource {
            _dir: dir,
            _env: env,
            entity,
            hash,
            artifact_id,
        }
    }

    impl GraphBackedSource {
        fn install(&self, store: &InMemoryGraph) -> SemanticChangeId {
            use kin_model::graph::{ChangeStore, EntityStore};

            let change = build_exact_test_change(
                vec![self.entity.clone()],
                vec![(
                    self.artifact_id,
                    kin_model::RepoPath::from_utf8(
                        self.entity.file_origin.as_ref().unwrap().0.clone(),
                    )
                    .unwrap(),
                    self.hash,
                )],
            );
            store
                .apply_transaction_delta(&kin_model::TransactionDelta {
                    entity_deltas: change.entity_deltas.clone(),
                    relation_deltas: vec![],
                    tree_deltas: change.tree_deltas.clone(),
                    admission_policy_delta: None,
                    external_reference_deltas: Vec::new(),
                })
                .unwrap();
            store.create_change(&change).unwrap();
            initialize_test_repository(self._dir.path(), &change);
            change.id
        }
    }

    /// A bare name that matches several entities is unrecoverable unless the
    /// refusal carries the candidates: the caller cannot re-target what it
    /// cannot see. "use the entity id" alone is advice with no way to act on it.
    #[test]
    fn an_ambiguous_name_target_enumerates_its_candidates() {
        let store = kin_db::InMemoryGraph::new();
        let first = make_dead_code_entity("src/net/host.ts", "hostname", 12);
        let second = make_dead_code_entity("src/cli/host.ts", "hostname", 40);
        let third = make_dead_code_entity("src/util/host.ts", "hostname", 7);
        let unrelated = make_dead_code_entity("src/net/port.ts", "portname", 3);
        for entity in [&first, &second, &third, &unrelated] {
            store.upsert_entity(entity).unwrap();
        }

        let error = sessions::resolve_target_entity(&store, "hostname")
            .expect_err("three exact-name matches cannot resolve");
        assert!(error.contains("3 exact-name matches"), "{error}");
        for entity in [&first, &second, &third] {
            assert!(
                error.contains(&entity.id.to_string()),
                "every candidate id must be re-targetable: {error}"
            );
        }
        // `file:line` is pasted into an editor, so the candidate list carries the
        // 1-based line: the fixture's graph row 40 is line 41.
        assert!(error.contains("src/cli/host.ts:41"), "{error}");
        assert!(
            !error.contains(&unrelated.id.to_string()),
            "only exact-name matches are candidates: {error}"
        );

        // The unambiguous paths are unchanged.
        assert_eq!(
            sessions::resolve_target_entity(&store, "portname")
                .unwrap()
                .id,
            unrelated.id
        );
        assert!(sessions::resolve_target_entity(&store, "absent")
            .unwrap_err()
            .contains("not found in the graph"));
    }

    fn make_dead_code_entity(file_path: &str, name: &str, start_line: u32) -> Entity {
        let file_id = kin_model::ids::FilePathId::new(file_path);
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([4; 32]),
                signature_hash: Hash256::from_bytes([5; 32]),
                behavior_hash: Hash256::from_bytes([6; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 0.9,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte: 32,
                start_line,
                start_col: 0,
                end_line: start_line + 1,
                end_col: 1,
            }),
            signature: format!("export function {name}(): number"),
            visibility: Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    /// Build a trace entity whose body is materialized in the graph-owned blob
    /// store under `dir/.kin` and registered against the entity's relative file
    /// path. Callers must set `KIN_SOURCE_ROOT` to `dir` (so the layout is
    /// discoverable) and `reset_trace_source_registry()` at test entry.
    fn make_trace_entity(
        dir: &tempfile::TempDir,
        rel_path: &str,
        name: &str,
        kind: EntityKind,
        signature: &str,
        content: &str,
    ) -> Entity {
        let blob_store =
            kin_blobs::BlobStore::new(dir.path().join(".kin").join("objects")).unwrap();
        let hash = blob_store.write(content.as_bytes()).unwrap();

        let file_id = kin_model::ids::FilePathId::new(rel_path);
        register_trace_source(&file_id, hash);

        Entity {
            id: EntityId::new(),
            kind,
            name: name.into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([7; 32]),
                signature_hash: Hash256::from_bytes([8; 32]),
                behavior_hash: Hash256::from_bytes([9; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 0.9,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte: content.len(),
                start_line: 1,
                start_col: 0,
                end_line: content.lines().count() as u32,
                end_col: 1,
            }),
            signature: signature.into(),
            visibility: Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn insert_trace_relation(
        store: &mut EmptyStore,
        src: &Entity,
        dst: &Entity,
        kind: RelationKind,
    ) {
        let relation = Relation {
            id: RelationId::new(),
            kind,
            src: kin_model::GraphNodeId::Entity(src.id),
            dst: kin_model::GraphNodeId::Entity(dst.id),
            confidence: 1.0,
            origin: kin_model::relation::RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        store
            .relations_by_entity
            .entry(src.id)
            .or_default()
            .push(relation.clone());
        store
            .relations_by_entity
            .entry(dst.id)
            .or_default()
            .push(relation);
    }

    #[test]
    fn entity_response_json_includes_real_source_excerpt() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  if (value < minVal) {\n    return false;\n  }\n  return value <= maxVal;\n}\n";
        let source = make_source_backed_entity(content);
        let entity = &source.entity;

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(entity.id, entity.clone());
        store
            .file_hashes
            .insert(entity.file_origin.clone().unwrap(), source.hash);
        install_empty_store_exact_tree(&mut store, source._dir.path());
        let authority = test_repository_authority(source._dir.path());

        let value = entity_response_json(&store, entity, Some(&authority)).unwrap();
        let object = value.as_object().unwrap();
        let excerpt = object
            .get("source_excerpt")
            .and_then(|value| value.as_str())
            .unwrap();

        assert!(excerpt.contains("return value <= maxVal;"));
        assert_eq!(object.get("source").unwrap().as_str().unwrap(), "graph");
        assert_eq!(object.get("start_line").unwrap(), 1);
    }

    #[test]
    fn focal_context_json_prefers_real_source_excerpt() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  if (value < minVal) {\n    return false;\n  }\n  return value <= maxVal;\n}\n";
        let source = make_source_backed_entity(content);
        let entity = &source.entity;

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(entity.id, entity.clone());
        store
            .file_hashes
            .insert(entity.file_origin.clone().unwrap(), source.hash);
        install_empty_store_exact_tree(&mut store, source._dir.path());
        let authority = test_repository_authority(source._dir.path());

        let value = focal_context_json(&store, entity, false, Some(&authority)).unwrap();
        let object = value.as_object().unwrap();
        let body = object.get("body").and_then(|value| value.as_str()).unwrap();

        assert!(body.contains("return value <= maxVal;"));
        assert_ne!(body, entity.signature);
        assert_eq!(object.get("source").unwrap().as_str().unwrap(), "graph");
        assert_eq!(object.get("start_line").unwrap(), 1);
    }

    #[test]
    fn focal_context_json_surfaces_source_and_stale_markers() {
        // get_context_pack's focal entity must carry the graph source marker and
        // staleness flag in the response payload, matching get_entity_source.
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  return value <= maxVal;\n}\n";
        let source = make_source_backed_entity(content);
        let entity = &source.entity;

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(entity.id, entity.clone());
        store
            .file_hashes
            .insert(entity.file_origin.clone().unwrap(), source.hash);
        install_empty_store_exact_tree(&mut store, source._dir.path());
        let authority = test_repository_authority(source._dir.path());

        let value = focal_context_json(&store, entity, false, Some(&authority)).unwrap();
        let object = value.as_object().unwrap();

        let marker = object.get("source").and_then(|v| v.as_str()).unwrap();
        assert_eq!(
            marker, "graph",
            "focal source marker must reflect the graph read path, got: {marker}"
        );
        // This fixture's entity carries no recorded source digest, so the read
        // cannot prove the span was cut from these bytes and says exactly that.
        // The field it replaces (`stale`) was hardcoded false at every site and
        // had no `set(true)` anywhere in the tree, so it asserted freshness the
        // read never established.
        assert_eq!(
            object.get("span_coherence").and_then(|v| v.as_str()),
            Some("unverified"),
            "focal payload must report how coherent the span/bytes pair is"
        );
    }

    /// The one number an agent acts on must be the number an editor shows.
    ///
    /// Every surface below reads the SAME entity, whose span starts at graph row
    /// 0, so each must report line 1. Pinning them together is the point: the
    /// defect this replaces was not any single wrong number but two conventions
    /// living in one response set, where `get_entity` and `find_references`
    /// disagreed about where the same function starts.
    #[test]
    fn every_read_surface_reports_the_same_one_based_start_line() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  return value <= maxVal;\n}\n";
        let source = make_source_backed_entity(content);
        let entity = &source.entity;
        assert_eq!(
            entity.span.as_ref().unwrap().start_line,
            0,
            "fixture states graph truth: the entity begins on the file's first line, row 0"
        );

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(entity.id, entity.clone());
        store
            .file_hashes
            .insert(entity.file_origin.clone().unwrap(), source.hash);
        install_empty_store_exact_tree(&mut store, source._dir.path());
        let authority = test_repository_authority(source._dir.path());

        let entity_json = entity_response_json(&store, entity, Some(&authority)).unwrap();
        assert_eq!(
            entity_json["start_line"], 1,
            "get_entity must present row 0 as line 1"
        );

        let focal = focal_context_json(&store, entity, false, Some(&authority)).unwrap();
        assert_eq!(
            focal["start_line"], 1,
            "get_context_pack focal must agree with get_entity"
        );

        let summary = serde_json::to_value(SemanticSearchResult::from(entity.clone())).unwrap();
        assert_eq!(
            summary["start_line"], 1,
            "semantic_search must agree with get_entity"
        );

        // The raw graph span rides along untouched. It is a faithful
        // serialization of graph truth, and its byte offsets are read as offsets,
        // so presentation lives in the sibling fields rather than by rewriting it.
        assert_eq!(
            entity_json["span"]["start_line"], 0,
            "the nested span stays graph truth"
        );
    }

    /// `find_references` must answer "where is this used" with graph facts, not
    /// with a base position an agent has to count forward from.
    #[test]
    fn find_references_rows_carry_graph_owned_snippets_and_one_based_site_lines() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let caller_body = "export function probe_caller_4b21e0(): boolean {\n  // padding\n  return validate_probe_range_1d8f8275(1, 0, 2);\n}\n";
        let target = make_source_backed_entity(
            "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  return value <= maxVal;\n}\n",
        );

        // The caller lives in the same graph-owned repository as the target, with
        // its body in the same blob store, so its snippet is a graph read.
        let caller_file = FilePathId::new("caller.ts");
        let blob_store =
            kin_blobs::BlobStore::new(target._dir.path().join(".kin").join("objects")).unwrap();
        let caller_hash = model_blob_hash(&blob_store, caller_body.as_bytes());
        let mut caller = target.entity.clone();
        caller.id = EntityId::new();
        caller.name = "probe_caller_4b21e0".into();
        caller.signature = "export function probe_caller_4b21e0(): boolean".into();
        caller.file_origin = Some(caller_file.clone());
        caller.span = Some(kin_model::entity::SourceSpan {
            file: caller_file.clone(),
            start_byte: 0,
            end_byte: caller_body.len(),
            start_line: 0,
            start_col: 0,
            end_line: 3,
            end_col: 1,
        });

        let mut store = EmptyStore::default();
        store
            .entities_by_id
            .insert(target.entity.id, target.entity.clone());
        store.entities_by_id.insert(caller.id, caller.clone());
        store
            .file_hashes
            .insert(target.entity.file_origin.clone().unwrap(), target.hash);
        store.file_hashes.insert(caller_file.clone(), caller_hash);

        // The call sits on the third line of the caller, graph row 2.
        let call_site_row = 2;
        let relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: kin_model::GraphNodeId::Entity(caller.id),
            dst: kin_model::GraphNodeId::Entity(target.entity.id),
            confidence: 1.0,
            origin: kin_model::relation::RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![kin_model::relation::RelationEvidence {
                source_span: Some(kin_model::entity::SourceSpan {
                    file: caller_file,
                    start_byte: 63,
                    end_byte: 105,
                    start_line: call_site_row,
                    start_col: 2,
                    end_line: call_site_row,
                    end_col: 44,
                }),
                parser_rule: Some("call_expression".into()),
                token: Some("validate_probe_range_1d8f8275".into()),
                source_path: None,
                resolved_path: None,
                occurrence_count: 1,
                call_shape: None,
            }],
        };
        store
            .relations_by_entity
            .entry(target.entity.id)
            .or_default()
            .push(relation);

        install_empty_store_exact_tree(&mut store, target._dir.path());
        let authority = test_repository_authority(target._dir.path());

        let rows = collect_graph_reference_rows(
            &store,
            &target.entity.id,
            &[RelationKind::Calls],
            Some(&authority),
        )
        .unwrap();
        assert_eq!(rows.len(), 1, "one caller, one row: {rows:?}");
        let row = &rows[0];

        // The caller's body arrives with the reference, so an agent never has to
        // resolve the id back to a body to read the usage in context.
        let snippet = row
            .snippet
            .as_deref()
            .expect("a graph-owned caller body must produce a snippet, never null");
        assert!(
            snippet.contains("validate_probe_range_1d8f8275(1, 0, 2)"),
            "snippet must be the caller's real source: {snippet}"
        );

        assert_eq!(
            row.start_line,
            Some(1),
            "the caller's definition starts on line 1"
        );
        assert_eq!(
            row.reference_lines,
            vec![call_site_row + 1],
            "the call site is served as a graph fact at its own 1-based line"
        );
    }

    /// A context pack's focal body must be the same bytes a direct body read
    /// serves. When it silently diverged, an agent asked to modify the entity saw
    /// a signature stub and either refused or guessed.
    #[test]
    fn context_pack_focal_body_matches_the_direct_entity_source_read() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  if (value < minVal) {\n    return false;\n  }\n  return value <= maxVal;\n}\n";
        let source = make_source_backed_entity(content);
        let entity = &source.entity;

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(entity.id, entity.clone());
        store
            .file_hashes
            .insert(entity.file_origin.clone().unwrap(), source.hash);
        install_empty_store_exact_tree(&mut store, source._dir.path());
        let authority = test_repository_authority(source._dir.path());

        // Sibling surface: the direct body read an agent would fall back to.
        let direct = tool_result_json(
            entities::handle_get_entity_source(
                &HashMap::from([("entity_id".into(), serde_json::json!(entity.id.to_string()))]),
                &store,
                Some(&authority),
            )
            .unwrap(),
        );
        let direct_body = direct["body"].as_str().expect("direct read serves a body");

        let entry = kin_model::ContextEntry {
            entity_id: entity.id,
            projection_level: kin_model::ProjectionLevel::FullBody,
            content: project_full_body_stub(entity),
        };
        let focal = focal_context_json(&store, entity, false, Some(&authority)).unwrap();
        let focal_body = focal["body"]
            .as_str()
            .expect("focal body must be a string, never null, when the graph has the source");

        assert_eq!(
            focal_body, direct_body,
            "the context pack and the direct read must serve one body"
        );
        assert!(focal_body.contains("return value <= maxVal;"));
        assert_eq!(focal["source"], "graph");
        assert!(
            focal.get("body_unavailable").is_none(),
            "no gap is reported when the body was served"
        );
        // The regression this pins: the pack's own token-accounting stub must
        // never surface as the body.
        assert_ne!(focal_body, entry.content);
        assert!(
            !focal_body.starts_with("// validate_probe_range_1d8f8275 (Function"),
            "a synthesized comment header is not a body: {focal_body}"
        );
    }

    /// An entity with no source coordinates has no body, and the response says
    /// so instead of substituting text that looks like one.
    #[test]
    fn context_pack_reports_a_body_gap_rather_than_a_synthesized_body() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let source = make_source_backed_entity(
            "export function validate_probe_range_1d8f8275(): boolean {\n  return true;\n}\n",
        );
        // A declaration the graph knows by signature only: no span, so no bytes.
        let mut spanless = source.entity.clone();
        spanless.span = None;

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(spanless.id, spanless.clone());
        // The repository is otherwise coherent: the file is admitted and its blob
        // is present. Only the entity's span is missing, so the gap being tested
        // is the entity's own, not a broken repository.
        store
            .file_hashes
            .insert(source.entity.file_origin.clone().unwrap(), source.hash);
        install_empty_store_exact_tree(&mut store, source._dir.path());
        let authority = test_repository_authority(source._dir.path());

        let focal = focal_context_json(&store, &spanless, false, Some(&authority)).unwrap();

        assert!(
            focal["body"].is_null(),
            "an unavailable body is null, not a stub: {}",
            focal["body"]
        );
        let reason = focal["body_unavailable"]
            .as_str()
            .expect("a null body must be explained");
        assert!(
            reason.contains("no source span"),
            "the reason must name the missing coordinate: {reason}"
        );
        assert!(
            focal["start_line"].is_null(),
            "a spanless entity has no line to report"
        );
    }

    /// After a committed transaction moves an entity, the read surfaces must
    /// report where it is NOW. Serving the pre-commit position made agents
    /// "correct" right line numbers into wrong ones.
    #[test]
    fn committed_span_shift_updates_the_reported_start_line_and_body() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let before = "export function validate_probe_range_1d8f8275(value: number): boolean {\n  return value > 0;\n}\n";
        let source = make_source_backed_entity(before);
        let entity = &source.entity;

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(entity.id, entity.clone());
        store
            .file_hashes
            .insert(entity.file_origin.clone().unwrap(), source.hash);
        install_empty_store_exact_tree(&mut store, source._dir.path());
        let first_head = *store.changes_by_id.keys().next().unwrap();
        let authority = test_repository_authority(source._dir.path());

        assert_eq!(
            entity_response_json(&store, entity, Some(&authority)).unwrap()["start_line"],
            1,
            "before the commit the entity begins on line 1"
        );

        // Commit a change that prepends two lines to the file and shifts the
        // entity down, exactly the shape that produced stale line reasoning.
        let after = "// added header\n// added header\nexport function validate_probe_range_1d8f8275(value: number, searchDirs: string[]): boolean {\n  return value > 0;\n}\n";
        let blob_store =
            kin_blobs::BlobStore::new(source._dir.path().join(".kin").join("objects")).unwrap();
        let after_hash = model_blob_hash(&blob_store, after.as_bytes());
        let file_id = entity.file_origin.clone().unwrap();
        let path = kin_model::RepoPath::from_utf8(file_id.0.clone()).unwrap();
        let entity_start = after.find("export function").unwrap();

        let mut moved = entity.clone();
        moved.signature =
            "export function validate_probe_range_1d8f8275(value: number, searchDirs: string[]): boolean"
                .into();
        moved.span = Some(kin_model::entity::SourceSpan {
            file: file_id,
            start_byte: entity_start,
            end_byte: after.len(),
            // Two prepended lines put the definition on graph row 2.
            start_line: 2,
            start_col: 0,
            end_line: 4,
            end_col: 1,
        });

        // The bootstrap mints its own artifact ids, so the update has to name the
        // identity that actually occupies the path rather than the fixture's.
        let admitted = authority
            .open_fresh()
            .unwrap()
            .workspace()
            .unwrap()
            .tree
            .artifact_at_path(&path)
            .cloned()
            .expect("the bootstrap admitted the entity's file");
        let old_entry = kin_model::LocatedEntry::new(path.clone(), admitted.entry.clone());
        let new_entry =
            kin_model::LocatedEntry::new(path, kin_model::TreeEntry::blob(after_hash, false));
        let shift = exact_test_change(
            vec![first_head],
            "add a parameter and shift the definition down",
            vec![kin_model::EntityDelta::Modified {
                old: entity.clone(),
                new: moved.clone(),
            }],
            vec![kin_model::TreeDelta::Updated {
                artifact_id: admitted.artifact_id,
                old: old_entry,
                new: new_entry,
            }],
        );
        store.changes_by_id.insert(shift.id, shift.clone());
        store.entities_by_id.insert(moved.id, moved.clone());
        advance_test_repository(source._dir.path(), &shift);

        // The live graph now holds the moved entity, and the committed workspace
        // holds the new bytes. Every surface must agree on the new position.
        let after_json = entity_response_json(&store, &moved, Some(&authority)).unwrap();
        assert_eq!(
            after_json["start_line"], 3,
            "graph row 2 after the shift is line 3: {after_json}"
        );
        assert_eq!(after_json["source"], "graph");
        let excerpt = after_json["source_excerpt"].as_str().unwrap();
        assert!(
            excerpt.contains("searchDirs: string[]"),
            "the body must be the post-commit source: {excerpt}"
        );

        let focal = focal_context_json(&store, &moved, false, Some(&authority)).unwrap();
        assert_eq!(
            focal["start_line"], 3,
            "the context pack must not serve the pre-commit position"
        );
        assert!(focal["body"]
            .as_str()
            .expect("a committed body is readable")
            .contains("searchDirs: string[]"));
    }

    /// An agent restricted to the agent-default profile must be able to read an
    /// entity's real source through a tool that profile actually exposes.
    ///
    /// The profile ships the transaction write surface, so this is the difference
    /// between an agent that can complete a body update and one that has to guess
    /// the source it is replacing. Membership is asserted in `tools.rs`; this
    /// drives the in-profile tools against a graph-backed entity and checks that
    /// real bytes come back.
    #[test]
    fn the_agent_default_profile_can_read_a_real_entity_body() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let content = "export function validate_probe_range_1d8f8275(value: number, maxVal: number): boolean {\n  return value <= maxVal;\n}\n";
        let source = make_source_backed_entity(content);
        let entity = &source.entity;

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(entity.id, entity.clone());
        store
            .file_hashes
            .insert(entity.file_origin.clone().unwrap(), source.hash);
        install_empty_store_exact_tree(&mut store, source._dir.path());
        let authority = test_repository_authority(source._dir.path());
        let sessions = SessionRegistry::new();
        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(entity.id.to_string()),
        )]);

        // Membership is ASSERTED, not used as a guard.
        //
        // These were `if profile.contains(...)` blocks, which made the test pass
        // on revert: `get_context_pack` was already in the base profile and its
        // focal body already returned real source, so dropping the newly added
        // `get_entity_source` left the other block running and the test green. A
        // guard that skips the assertion when the thing under test is missing
        // cannot fail when the thing under test is missing.
        let profile: std::collections::HashSet<&str> = crate::tools::agent_default_tool_names()
            .iter()
            .copied()
            .collect();
        assert!(
            profile.contains("get_entity_source"),
            "the agent-default profile must carry a direct entity-body read"
        );
        assert!(
            profile.contains("get_context_pack"),
            "the agent-default profile must carry the context pack"
        );

        let value = tool_result_json(
            entities::handle_get_entity_source(&args, &store, Some(&authority)).unwrap(),
        );
        assert!(
            value["body"]
                .as_str()
                .is_some_and(|body| body.contains("return value <= maxVal;")),
            "get_entity_source must serve the real body: {value}"
        );

        let value = tool_result_json(
            entities::handle_get_context_pack(&args, &store, &sessions, Some(&authority)).unwrap(),
        );
        assert!(
            value["focal_entity"]["body"]
                .as_str()
                .is_some_and(|body| body.contains("return value <= maxVal;")),
            "get_context_pack focal body must serve the real body: {value}"
        );
    }

    /// Stand-in for the context builder's token-accounting projection, so the
    /// tests above assert against the exact text that used to leak into `body`.
    fn project_full_body_stub(entity: &Entity) -> String {
        format!(
            "// {} ({:?}, {})\n{}\n",
            entity.name, entity.kind, entity.language, entity.signature
        )
    }

    #[test]
    fn focal_context_json_expands_signature_only_python_span() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let content = "def validate_probe_range_f0cc1f1d(value: float, min_val: float, max_val: float) -> bool:\n    return min_val <= value and value <= max_val\n";
        let source = make_signature_only_python_entity(content);
        let entity = &source.entity;

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(entity.id, entity.clone());
        store
            .file_hashes
            .insert(entity.file_origin.clone().unwrap(), source.hash);
        install_empty_store_exact_tree(&mut store, source._dir.path());
        let authority = test_repository_authority(source._dir.path());

        let value = focal_context_json(&store, entity, false, Some(&authority)).unwrap();
        let object = value.as_object().unwrap();
        let body = object.get("body").and_then(|value| value.as_str()).unwrap();

        assert!(body.contains("value <= max_val"));
        assert_ne!(body.trim(), entity.signature);
    }

    #[test]
    fn handle_explore_codebase_trace_returns_ordered_bodies_and_constants() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_trace_source_registry();
        let dir = tempdir().unwrap();
        let _env = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());
        let tag = "trace9f31";

        let entry = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step4_{tag}.ts"),
            &format!("probeFinalTransform_{tag}"),
            EntityKind::Function,
            &format!("function probeFinalTransform_{tag}(n: number): number"),
            &format!(
                "export function probeFinalTransform_{tag}(n: number): number {{\n  return probeReduce_{tag}(n) + 17;\n}}\n"
            ),
        );
        let reduce_step = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step3_{tag}.ts"),
            &format!("probeReduce_{tag}"),
            EntityKind::Function,
            &format!("function probeReduce_{tag}(n: number): number"),
            &format!(
                "export function probeReduce_{tag}(n: number): number {{\n  return probeConditionalAdjust_{tag}(n) - 5;\n}}\n"
            ),
        );
        let import_only_step = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step2_{tag}.ts"),
            &format!("probeConditionalAdjust_{tag}"),
            EntityKind::Function,
            &format!("function probeConditionalAdjust_{tag}(n: number): number"),
            &format!(
                "export function probeConditionalAdjust_{tag}(n: number): number {{\n  return probeDoubleShifted_{tag}(n) + 3;\n}}\n"
            ),
        );
        let step = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step1_{tag}.ts"),
            &format!("probeDoubleShifted_{tag}"),
            EntityKind::Function,
            &format!("function probeDoubleShifted_{tag}(n: number): number"),
            &format!(
                "export function probeDoubleShifted_{tag}(n: number): number {{\n  return probeAddOffset_{tag}(n) * 2;\n}}\n"
            ),
        );
        let base_step = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step0_{tag}.ts"),
            &format!("probeAddOffset_{tag}"),
            EntityKind::Function,
            &format!("function probeAddOffset_{tag}(n: number): number"),
            &format!(
                "import {{ PROBE_BASE_{tag} }} from './base_{tag}';\n\nexport function probeAddOffset_{tag}(n: number): number {{\n  return n + PROBE_BASE_{tag};\n}}\n"
            ),
        );
        let constant = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/base_{tag}.ts"),
            &format!("PROBE_BASE_{tag}"),
            EntityKind::Constant,
            &format!("const PROBE_BASE_{tag}: number"),
            &format!("export const PROBE_BASE_{tag} = 13;\n"),
        );
        let decoy = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/decoy_transform_{tag}.ts"),
            &format!("probeFinalTransformAlt_{tag}"),
            EntityKind::Function,
            &format!("function probeFinalTransformAlt_{tag}(n: number): number"),
            &format!(
                "export function probeFinalTransformAlt_{tag}(n: number): number {{\n  return n * 100;\n}}\n"
            ),
        );

        let mut store = EmptyStore::default();
        for entity in [
            entry.clone(),
            reduce_step.clone(),
            import_only_step.clone(),
            step.clone(),
            base_step.clone(),
            constant.clone(),
            decoy.clone(),
        ] {
            store.entities_by_id.insert(entity.id, entity);
        }
        insert_trace_relation(&mut store, &entry, &reduce_step, RelationKind::Calls);
        insert_trace_relation(
            &mut store,
            &reduce_step,
            &import_only_step,
            RelationKind::Imports,
        );
        insert_trace_relation(&mut store, &import_only_step, &step, RelationKind::Calls);
        insert_trace_relation(&mut store, &reduce_step, &step, RelationKind::References);
        insert_trace_relation(&mut store, &step, &base_step, RelationKind::Calls);
        insert_trace_relation(&mut store, &base_step, &constant, RelationKind::Imports);
        install_empty_store_exact_tree(&mut store, dir.path());
        let authority = test_repository_authority(dir.path());

        let mut args = HashMap::new();
        args.insert("query".into(), serde_json::json!(entry.name));
        args.insert("strategy".into(), serde_json::json!("trace"));
        args.insert("token_budget".into(), serde_json::json!(8000));

        let result = entities::handle_explore_codebase(&args, &store, Some(&authority)).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let content = parsed["content"].as_str().unwrap();

        let entry_pos = content.find(&entry.name).unwrap();
        let reduce_pos = content.find(&reduce_step.name).unwrap();
        let import_only_pos = content.find(&import_only_step.name).unwrap();
        let step_pos = content.find(&step.name).unwrap();
        let base_step_pos = content.find(&base_step.name).unwrap();

        assert!(content.contains("## Ordered Call Chain"));
        assert!(entry_pos < reduce_pos);
        assert!(reduce_pos < import_only_pos);
        assert!(import_only_pos < step_pos);
        assert!(step_pos < base_step_pos);
        assert!(content.contains("Imported constants"));
        assert!(content.contains(&constant.name));
        assert!(content.contains("export const"));
        assert!(content.contains("## Similar Matches"));
        assert!(content.contains(&decoy.name));
        assert!(content.contains("return n + PROBE_BASE"));
    }

    #[test]
    fn handle_explore_codebase_trace_infers_constants_without_graph_edges() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_trace_source_registry();
        let dir = tempdir().unwrap();
        let _env = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());
        let tag = "traceconst";

        let step = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step1_{tag}.ts"),
            &format!("probeAddOffset_{tag}"),
            EntityKind::Function,
            &format!("function probeAddOffset_{tag}(n: number): number"),
            &format!(
                "import {{ PROBE_BASE_{tag} }} from './base_{tag}';\n\nexport function probeAddOffset_{tag}(n: number): number {{\n  return n + PROBE_BASE_{tag};\n}}\n"
            ),
        );
        let constant = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/base_{tag}.ts"),
            &format!("PROBE_BASE_{tag}"),
            EntityKind::Constant,
            &format!("const PROBE_BASE_{tag}: number"),
            &format!("export const PROBE_BASE_{tag} = 13;\n"),
        );

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(step.id, step.clone());
        store.entities_by_id.insert(constant.id, constant.clone());
        install_empty_store_exact_tree(&mut store, dir.path());
        let authority = test_repository_authority(dir.path());

        let mut args = HashMap::new();
        args.insert("query".into(), serde_json::json!(step.name));
        args.insert("strategy".into(), serde_json::json!("trace"));
        args.insert("token_budget".into(), serde_json::json!(8000));

        let result = entities::handle_explore_codebase(&args, &store, Some(&authority)).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let content = parsed["content"].as_str().unwrap();

        assert!(content.contains("Imported constants"));
        assert!(content.contains(&constant.name));
        assert!(content.contains("export const"));
    }

    #[test]
    fn handle_explore_codebase_trace_evaluates_rust_call_query() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_trace_source_registry();
        let dir = tempdir().unwrap();
        let _env = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());
        let tag = "traceeval";

        let entry = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step7_{tag}.rs"),
            &format!("probe_final_transform_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_final_transform_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_final_transform_{tag}(n: i64) -> i64 {{\n  probe_conditional_shift_{tag}(n) + 17\n}}\n"
            ),
        );
        let step6 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step6_{tag}.rs"),
            &format!("probe_conditional_shift_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_conditional_shift_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_conditional_shift_{tag}(n: i64) -> i64 {{\n  let amplified = probe_amplify_{tag}(n);\n  if amplified % 2 == 0 {{\n    amplified + 7\n  }} else {{\n    amplified - 11\n  }}\n}}\n"
            ),
        );
        let step5 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step5_{tag}.rs"),
            &format!("probe_amplify_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_amplify_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_amplify_{tag}(n: i64) -> i64 {{\n  probe_reduce_{tag}(n) * 3\n}}\n"
            ),
        );
        let step4 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step4_{tag}.rs"),
            &format!("probe_reduce_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_reduce_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_reduce_{tag}(n: i64) -> i64 {{\n  probe_conditional_adjust_{tag}(n) - 5\n}}\n"
            ),
        );
        let step3 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step3_{tag}.rs"),
            &format!("probe_conditional_adjust_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_conditional_adjust_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_conditional_adjust_{tag}(n: i64) -> i64 {{\n  let intermediate = probe_double_shifted_{tag}(n);\n  if intermediate % 2 == 0 {{\n    intermediate + 3\n  }} else {{\n    intermediate * 2\n  }}\n}}\n"
            ),
        );
        let step2 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step2_{tag}.rs"),
            &format!("probe_double_shifted_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_double_shifted_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_double_shifted_{tag}(n: i64) -> i64 {{\n  probe_add_offset_{tag}(n) * 2\n}}\n"
            ),
        );
        let step1 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step1_{tag}.rs"),
            &format!("probe_add_offset_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_add_offset_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_add_offset_{tag}(n: i64) -> i64 {{\n  n + PROBE_BASE_{tag}\n}}\n"
            ),
        );
        let constant = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/base_{tag}.rs"),
            &format!("PROBE_BASE_{tag}"),
            EntityKind::Constant,
            &format!("pub const PROBE_BASE_{tag}: i64"),
            &format!("pub const PROBE_BASE_{tag}: i64 = 13;\n"),
        );

        let mut store = EmptyStore::default();
        for entity in [
            entry.clone(),
            step6.clone(),
            step5.clone(),
            step4.clone(),
            step3.clone(),
            step2.clone(),
            step1.clone(),
            constant.clone(),
        ] {
            store.entities_by_id.insert(entity.id, entity);
        }

        insert_trace_relation(&mut store, &entry, &step6, RelationKind::Calls);
        insert_trace_relation(&mut store, &step6, &step5, RelationKind::Calls);
        insert_trace_relation(&mut store, &step5, &step4, RelationKind::Calls);
        insert_trace_relation(&mut store, &step4, &step3, RelationKind::Calls);
        insert_trace_relation(&mut store, &step3, &step2, RelationKind::Calls);
        insert_trace_relation(&mut store, &step2, &step1, RelationKind::Calls);
        insert_trace_relation(&mut store, &step1, &constant, RelationKind::Imports);
        install_empty_store_exact_tree(&mut store, dir.path());
        let authority = test_repository_authority(dir.path());

        let mut args = HashMap::new();
        args.insert(
            "query".into(),
            serde_json::json!(format!("{}(5)", entry.name)),
        );
        args.insert("strategy".into(), serde_json::json!("trace"));
        args.insert("token_budget".into(), serde_json::json!(8000));

        let result = entities::handle_explore_codebase(&args, &store, Some(&authority)).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let content = parsed["content"].as_str().unwrap();

        assert!(content.contains("## Evaluation Walkthrough"));
        assert!(content.contains("Input: 5"));
        assert!(content.contains("probe_add_offset"));
        assert!(content.contains("36 is even, so 36 + 3"));
        assert!(content.contains("102 is even, so 102 + 7"));
        assert!(content.contains("Final result: 126"));
    }

    #[test]
    fn handle_dead_code_scopes_to_requested_files() {
        let dead = make_dead_code_entity("src/probe_group0.ts", "probeDelta_1d8f8275", 10);
        let live = make_dead_code_entity("src/probe_group1.ts", "probeAlpha_1d8f8275", 20);
        let ignored = make_dead_code_entity("src/other.ts", "probeOutside_1d8f8275", 30);

        let mut store = EmptyStore::default();
        store
            .entities_by_file
            .insert("src/probe_group0.ts".into(), vec![dead.clone()]);
        store
            .entities_by_file
            .insert("src/probe_group1.ts".into(), vec![live.clone()]);
        store
            .entities_by_file
            .insert("src/other.ts".into(), vec![ignored.clone()]);
        store.live_entity_ids.insert(live.id);

        let mut args = HashMap::new();
        args.insert("limit".into(), serde_json::json!(50));
        args.insert(
            "files".into(),
            serde_json::json!(["src/probe_group0.ts", "src/probe_group1.ts"]),
        );

        let result = entities::handle_dead_code(&args, &store).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["name"], dead.name);
        assert_eq!(
            parsed[0]["file_origin"],
            dead.file_origin.as_ref().unwrap().0
        );
    }

    #[test]
    fn handle_dead_code_falls_back_to_global_query_without_files() {
        let dead = make_dead_code_entity("src/global.ts", "probeGlobal_1d8f8275", 5);
        let mut store = EmptyStore::default();
        store.dead_entities.push(dead.clone());

        let mut args = HashMap::new();
        args.insert("limit".into(), serde_json::json!(10));

        let result = entities::handle_dead_code(&args, &store).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["name"], dead.name);
    }

    #[test]
    fn semantic_search_result_is_compact_summary() {
        let entity = kin_model::entity::Entity {
            id: EntityId::new(),
            kind: EntityKind::Method,
            name: "SnapDocsApp.saveDocument".into(),
            language: LanguageId::JavaScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 0.9,
            },
            file_origin: Some(kin_model::ids::FilePathId::new("src/app.js")),
            span: Some(kin_model::entity::SourceSpan {
                file: kin_model::ids::FilePathId::new("src/app.js"),
                start_byte: 10,
                end_byte: 40,
                start_line: 12,
                start_col: 4,
                end_line: 16,
                end_col: 2,
            }),
            signature: "saveDocument(doc)".into(),
            visibility: kin_model::entity::Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: Some("Persist one document.".into()),
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let summary = SemanticSearchResult::from(entity);
        let value = serde_json::to_value(summary).unwrap();
        let object = value.as_object().unwrap();

        assert_eq!(object.get("name").unwrap(), "SnapDocsApp.saveDocument");
        assert_eq!(object.get("file_path").unwrap(), "src/app.js");
        // Graph row 12 is the 13th line of the file, and that is what an agent
        // opening `src/app.js` in an editor must be told.
        assert_eq!(object.get("start_line").unwrap(), 13);
        assert!(object.get("signature").is_some());
        assert!(object.get("fingerprint").is_none());
        assert!(object.get("metadata").is_none());
    }

    #[test]
    fn work_handlers_manage_relationships_and_status() {
        let store = InMemoryGraph::default();

        let mut feature_args = HashMap::new();
        feature_args.insert("kind".into(), serde_json::json!("feature"));
        feature_args.insert("title".into(), serde_json::json!("Ship hosted review"));
        let feature = work::handle_work_create(&feature_args, &store).unwrap();
        let feature_text = match &feature.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let feature_json: serde_json::Value = serde_json::from_str(&feature_text).unwrap();
        let feature_id = feature_json["work_id"].as_str().unwrap().to_string();

        let mut task_args = HashMap::new();
        task_args.insert("kind".into(), serde_json::json!("task"));
        task_args.insert(
            "title".into(),
            serde_json::json!("Wire semantic work graph"),
        );
        task_args.insert("scopes".into(), serde_json::json!(["artifact:src/lib.rs"]));
        let task = work::handle_work_create(&task_args, &store).unwrap();
        let task_text = match &task.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let task_json: serde_json::Value = serde_json::from_str(&task_text).unwrap();
        let task_id = task_json["work_id"].as_str().unwrap().to_string();

        let mut blocker_args = HashMap::new();
        blocker_args.insert("kind".into(), serde_json::json!("issue"));
        blocker_args.insert("title".into(), serde_json::json!("Resolve sync edge cases"));
        let blocker = work::handle_work_create(&blocker_args, &store).unwrap();
        let blocker_text = match &blocker.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let blocker_json: serde_json::Value = serde_json::from_str(&blocker_text).unwrap();
        let blocker_id = blocker_json["work_id"].as_str().unwrap().to_string();

        let mut decompose_args = HashMap::new();
        decompose_args.insert("parent_work_id".into(), serde_json::json!(feature_id));
        decompose_args.insert("child_work_id".into(), serde_json::json!(task_id.clone()));
        work::handle_work_decompose(&decompose_args, &store).unwrap();

        let mut block_args = HashMap::new();
        block_args.insert("blocked_work_id".into(), serde_json::json!(task_id.clone()));
        block_args.insert("blocker_work_id".into(), serde_json::json!(blocker_id));
        work::handle_work_block(&block_args, &store).unwrap();

        let mut implement_args = HashMap::new();
        implement_args.insert("work_id".into(), serde_json::json!(task_id.clone()));
        implement_args.insert("scopes".into(), serde_json::json!(["artifact:src/lib.rs"]));
        work::handle_work_implement(&implement_args, &store).unwrap();

        let mut status_args = HashMap::new();
        status_args.insert("work_id".into(), serde_json::json!(task_id.clone()));
        status_args.insert("status".into(), serde_json::json!("in_progress"));
        work::handle_work_status(&status_args, &store).unwrap();

        let mut show_args = HashMap::new();
        show_args.insert("work_id".into(), serde_json::json!(task_id));
        let shown = work::handle_work_show(&show_args, &store).unwrap();
        let shown_text = match &shown.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let shown_json: serde_json::Value = serde_json::from_str(&shown_text).unwrap();

        assert_eq!(shown_json["status"], "in_progress");
        assert_eq!(shown_json["parents"].as_array().unwrap().len(), 1);
        assert_eq!(shown_json["blockers"].as_array().unwrap().len(), 1);
        assert_eq!(shown_json["implementors"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn annotation_handlers_support_work_targets() {
        let store = InMemoryGraph::default();

        let mut create_args = HashMap::new();
        create_args.insert("kind".into(), serde_json::json!("task"));
        create_args.insert("title".into(), serde_json::json!("Track proof gaps"));
        create_args.insert(
            "scopes".into(),
            serde_json::json!(["artifact:src/proof.rs"]),
        );
        let work = work::handle_work_create(&create_args, &store).unwrap();
        let work_text = match &work.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let work_json: serde_json::Value = serde_json::from_str(&work_text).unwrap();
        let work_id = work_json["work_id"].as_str().unwrap().to_string();

        let mut add_args = HashMap::new();
        add_args.insert("kind".into(), serde_json::json!("reasoning"));
        add_args.insert(
            "body".into(),
            serde_json::json!("Keep this attached to the work object."),
        );
        add_args.insert(
            "targets".into(),
            serde_json::json!([format!("work:{}", work_id)]),
        );
        let added = work::handle_annotation_add(&add_args, &store).unwrap();
        let added_text = match &added.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let added_json: serde_json::Value = serde_json::from_str(&added_text).unwrap();
        assert_eq!(added_json["kind"], "reasoning");

        let mut list_args = HashMap::new();
        list_args.insert(
            "targets".into(),
            serde_json::json!([format!("work:{}", work_id)]),
        );
        let listed = work::handle_annotation_list(&list_args, &store).unwrap();
        let listed_text = match &listed.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let listed_json: serde_json::Value = serde_json::from_str(&listed_text).unwrap();
        assert_eq!(listed_json.as_array().unwrap().len(), 1);
        assert_eq!(listed_json[0]["scopes"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn get_context_pack_recalls_annotation_deposited_on_focal_entity() {
        // D.7 Track B (annotation deposit + recall): an annotation deposited on
        // an entity via kin_annotation_add must be recalled inside that entity's
        // get_context_pack response, through the real graph surfaces — no fake
        // or demo data, the same create/query path the product uses.
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  return value <= maxVal;\n}\n";
        let source = make_source_backed_entity(content);
        let entity = &source.entity;
        let store = InMemoryGraph::default();
        source.install(&store);
        let authority = test_repository_authority(source._dir.path());

        // Deposit via the real add handler against the entity scope.
        let mut add_args = HashMap::new();
        add_args.insert("kind".into(), serde_json::json!("warning"));
        add_args.insert(
            "body".into(),
            serde_json::json!("Bounds validated upstream; do not re-check here."),
        );
        add_args.insert(
            "targets".into(),
            serde_json::json!([format!("entity:{}", entity.id)]),
        );
        work::handle_annotation_add(&add_args, &store).unwrap();

        // Recall through get_context_pack (traffic off to keep the pack focused).
        let sessions = SessionRegistry::new();
        let mut args = HashMap::new();
        args.insert("entity_id".into(), serde_json::json!(entity.id.to_string()));
        args.insert("include_traffic".into(), serde_json::json!(false));
        let result =
            entities::handle_get_context_pack(&args, &store, &sessions, Some(&authority)).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();

        let annotations = response
            .get("annotations")
            .and_then(|v| v.as_array())
            .expect("context pack must recall annotations on the focal entity");
        assert!(
            !annotations.is_empty(),
            "expected the deposited annotation to be recalled, got none"
        );
        let rendered = serde_json::to_string(annotations).unwrap();
        assert!(
            rendered.contains("do not re-check here"),
            "recalled annotation body should be present; got: {rendered}"
        );
    }

    #[test]
    fn handle_trace_computation_returns_focal_body_for_entity_id() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  if (value < minVal) {\n    return false;\n  }\n  return value <= maxVal;\n}\n";
        let source = make_source_backed_entity(content);
        let entity = &source.entity;
        let store = InMemoryGraph::default();
        source.install(&store);
        let authority = test_repository_authority(source._dir.path());

        let sessions = SessionRegistry::new();
        let mut args = HashMap::new();
        args.insert("entity_id".into(), serde_json::json!(entity.id.to_string()));

        let result =
            entities::handle_trace_computation(&args, &store, &sessions, Some(&authority)).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();

        let focal = response
            .get("focal_entity")
            .expect("focal_entity present in trace_computation response");
        let body = focal
            .get("body")
            .and_then(|v| v.as_str())
            .expect("focal entity body");
        assert!(
            body.contains("return value <= maxVal;"),
            "trace_computation focal body should include the real source excerpt; got: {body}"
        );
        assert!(response.get("token_budget").is_some());
    }

    #[test]
    fn handle_trace_computation_resolves_query_to_entity() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  if (value < minVal) {\n    return false;\n  }\n  return value <= maxVal;\n}\n";
        let source = make_source_backed_entity(content);
        let entity = &source.entity;
        let store = InMemoryGraph::default();
        source.install(&store);
        let authority = test_repository_authority(source._dir.path());

        let sessions = SessionRegistry::new();
        let mut args = HashMap::new();
        args.insert("query".into(), serde_json::json!(entity.name.clone()));

        let result =
            entities::handle_trace_computation(&args, &store, &sessions, Some(&authority)).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        let focal_id = response
            .get("focal_entity")
            .and_then(|f| f.get("id"))
            .and_then(|v| v.as_str())
            .expect("focal_entity.id present");
        assert_eq!(focal_id, entity.id.to_string());
    }

    #[test]
    fn handle_trace_computation_requires_entity_id_or_query() {
        let store = InMemoryGraph::default();
        let sessions = SessionRegistry::new();
        let args = HashMap::new();

        let err = entities::handle_trace_computation(&args, &store, &sessions, None)
            .expect_err("missing entity_id and query should error");
        assert!(matches!(err, McpError::InvalidParams(_)));
    }

    #[tokio::test]
    async fn handle_transaction_handlers_lifecycle_fails_closed_without_exact_tree() {
        use crate::session::{McpMutationOperation, McpMutationPayload};
        use kin_db::InMemoryGraph;
        use kin_model::entity::{FingerprintAlgorithm, SemanticFingerprint};
        use kin_model::graph::EntityStore;
        use kin_model::ids::{Hash256, LanguageId};

        let store = InMemoryGraph::default();
        let sessions = SessionRegistry::new();
        sessions.set_coordination_mode(crate::session::CoordinationEnforcementMode::Enforce);
        let session_authority = SessionAuthorityMode::OfflineFallback;
        let session = sessions.start_agent_session(
            "codex",
            "transaction-lifecycle-test",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities {
                can_write: true,
                can_commit: true,
                ..SessionCapabilities::default()
            },
        );

        // 1. Begin transaction
        let mut begin_args = HashMap::new();
        begin_args.insert(
            "session_id".into(),
            serde_json::json!(session.session_id.to_string()),
        );
        begin_args.insert("scope".into(), serde_json::json!("src/lib.rs"));
        let begin_res =
            sessions::handle_transaction_begin(&begin_args, &sessions, session_authority)
                .await
                .unwrap();
        let begin_text = match &begin_res.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let begin_val: serde_json::Value = serde_json::from_str(&begin_text).unwrap();
        let tx_id = begin_val["transaction_id"].as_str().unwrap().to_string();

        // 2. Stage mutation (add entity)
        let entity = kin_model::Entity {
            id: EntityId::new(),
            kind: kin_model::entity::EntityKind::Function,
            name: "test_fn".into(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(kin_model::ids::FilePathId::new("src/test.rs")),
            span: None,
            signature: "fn test_fn()".into(),
            visibility: kin_model::entity::Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };
        let op = McpMutationOperation {
            verb: "create".into(),
            target: "".into(),
            payload: Some(McpMutationPayload::Entity(entity.clone())),
            body: None,
            description: "add test function".into(),
        };

        let mut stage_args = HashMap::new();
        stage_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        stage_args.insert("operations".into(), serde_json::json!(vec![op]));
        let stage_res =
            sessions::handle_transaction_stage(&stage_args, &sessions, session_authority)
                .await
                .unwrap();
        let stage_text = match &stage_res.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let stage_val: serde_json::Value = serde_json::from_str(&stage_text).unwrap();
        assert_eq!(stage_val["staged_count"].as_u64().unwrap(), 1);

        // 3. Validate transaction
        let mut val_args = HashMap::new();
        val_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        let val_res =
            sessions::handle_transaction_validate(&val_args, &sessions, session_authority)
                .await
                .unwrap();
        let val_text = match &val_res.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let val_val: serde_json::Value = serde_json::from_str(&val_text).unwrap();
        assert_eq!(val_val["state"].as_str().unwrap(), "validated");

        // 4. Commit transaction. A semantic entity cannot be introduced on a
        // repository path that is absent from the exact staged tree. The
        // legacy offline transaction payload has no source body/tree entry,
        // so it must fail closed instead of creating dangling graph truth.
        let mut commit_args = HashMap::new();
        commit_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        let commit_res =
            sessions::handle_transaction_commit(&commit_args, &store, &sessions, session_authority)
                .await
                .unwrap();
        assert_eq!(commit_res.is_error, Some(true));
        let commit_text = match &commit_res.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        assert!(commit_text.contains("absent from the staged tree"));
        assert!(store.get_entity(&entity.id).unwrap().is_none());
        assert_eq!(sessions.get_transaction(&tx_id).unwrap().state, "validated");
    }

    /// A graph-resident entity with no repository placement, so an in-process
    /// commit is not gated by kin-db's staged-tree consistency check and the
    /// assertions stay about commit-shape handling.
    fn placement_free_entity(name: &str) -> Entity {
        use kin_model::entity::{FingerprintAlgorithm, SemanticFingerprint};
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.into(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    /// Begin an offline transaction owned by a write-capable session.
    async fn begin_offline_transaction(sessions: &SessionRegistry, label: &'static str) -> String {
        let session = sessions.start_agent_session(
            "codex",
            label,
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities {
                can_write: true,
                can_commit: true,
                ..SessionCapabilities::default()
            },
        );
        let mut begin_args = HashMap::new();
        begin_args.insert(
            "session_id".into(),
            serde_json::json!(session.session_id.to_string()),
        );
        begin_args.insert("scope".into(), serde_json::json!("src/lib.rs"));
        let begin_res = sessions::handle_transaction_begin(
            &begin_args,
            sessions,
            SessionAuthorityMode::OfflineFallback,
        )
        .await
        .unwrap();
        let begin_text = match &begin_res.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let begin_val: serde_json::Value = serde_json::from_str(&begin_text).unwrap();
        begin_val["transaction_id"].as_str().unwrap().to_string()
    }

    fn tool_result_text(result: &crate::types::ToolCallResult) -> String {
        match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        }
    }

    #[tokio::test]
    async fn offline_commit_refuses_payload_less_source_update() {
        // A payload-less `update` carrying a target and a body is a real source
        // edit, but planning the exact span edit and projecting the new source
        // into the working file lives in the daemon. The in-process path has no
        // projection, so it must refuse the shape instead of applying a
        // same-entity no-op delta and reporting "committed", which would
        // report an agent's edit as durable while discarding the body.
        use crate::session::{McpMutationOperation, McpMutationPayload};

        let store = InMemoryGraph::default();
        let entity = placement_free_entity("value");
        store.upsert_entity(&entity).unwrap();
        let before = serde_json::to_value(&entity).unwrap();

        let sessions = SessionRegistry::new();
        sessions.set_coordination_mode(crate::session::CoordinationEnforcementMode::Warn);
        let session_authority = SessionAuthorityMode::OfflineFallback;
        let tx_id = begin_offline_transaction(&sessions, "offline-payload-less-refusal").await;

        // Staging still accepts the shape: the daemon commit path can honor it.
        let op = McpMutationOperation {
            verb: "update".into(),
            target: "value".into(),
            payload: None::<McpMutationPayload>,
            body: Some("pub fn value() -> u8 { 2 }".into()),
            description: "payload-less body update".into(),
        };
        let mut stage_args = HashMap::new();
        stage_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        stage_args.insert("operations".into(), serde_json::json!(vec![op]));
        let stage_res =
            sessions::handle_transaction_stage(&stage_args, &sessions, session_authority)
                .await
                .unwrap();
        assert_ne!(
            stage_res.is_error,
            Some(true),
            "staging must keep accepting the daemon-committable shape: {}",
            tool_result_text(&stage_res)
        );

        let mut commit_args = HashMap::new();
        commit_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        let commit_res =
            sessions::handle_transaction_commit(&commit_args, &store, &sessions, session_authority)
                .await
                .unwrap();

        assert_eq!(
            commit_res.is_error,
            Some(true),
            "in-process commit must refuse a payload-less source update"
        );
        let commit_text = tool_result_text(&commit_res);
        assert!(
            commit_text.contains("require the daemon commit path"),
            "message must name the daemon requirement, got: {commit_text}"
        );

        // Nothing was applied and the transaction is still usable.
        assert_eq!(sessions.get_transaction(&tx_id).unwrap().state, "active");
        let after = serde_json::to_value(store.get_entity(&entity.id).unwrap().unwrap()).unwrap();
        assert_eq!(
            before, after,
            "graph truth must be untouched by the refusal"
        );
    }

    #[tokio::test]
    async fn offline_commit_still_applies_entity_payload_operations() {
        // The refusal is scoped to the payload-less shape. An operation that
        // carries an entity payload still commits in-process exactly as before.
        use crate::session::{McpMutationOperation, McpMutationPayload};

        let store = InMemoryGraph::default();
        let entity = placement_free_entity("documented_value");
        store.upsert_entity(&entity).unwrap();

        let sessions = SessionRegistry::new();
        sessions.set_coordination_mode(crate::session::CoordinationEnforcementMode::Warn);
        let session_authority = SessionAuthorityMode::OfflineFallback;
        let tx_id = begin_offline_transaction(&sessions, "offline-entity-payload-commit").await;

        let mut updated = entity.clone();
        updated.doc_summary = Some("returns the configured value".into());
        let op = McpMutationOperation {
            verb: "update".into(),
            target: entity.id.to_string(),
            payload: Some(McpMutationPayload::Entity(updated)),
            body: None,
            description: "entity payload update".into(),
        };
        let mut stage_args = HashMap::new();
        stage_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        stage_args.insert("operations".into(), serde_json::json!(vec![op]));
        sessions::handle_transaction_stage(&stage_args, &sessions, session_authority)
            .await
            .unwrap();

        let mut commit_args = HashMap::new();
        commit_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        let commit_res =
            sessions::handle_transaction_commit(&commit_args, &store, &sessions, session_authority)
                .await
                .unwrap();

        let commit_text = tool_result_text(&commit_res);
        assert_ne!(
            commit_res.is_error,
            Some(true),
            "entity-payload commit must still succeed: {commit_text}"
        );
        let commit_val: serde_json::Value = serde_json::from_str(&commit_text).unwrap();
        assert_eq!(commit_val["status"].as_str().unwrap(), "committed");
        assert_eq!(commit_val["ops_applied"].as_u64().unwrap(), 1);
        assert_eq!(commit_val["empty"].as_bool().unwrap(), false);
        assert_eq!(
            store
                .get_entity(&entity.id)
                .unwrap()
                .unwrap()
                .doc_summary
                .as_deref(),
            Some("returns the configured value"),
            "the payload-ful update must reach graph truth"
        );
    }

    /// An entity payload sent alongside a source body must not commit the
    /// payload and drop the body.
    ///
    /// This is the shape that reported `status: committed, ops_applied: 1,
    /// empty: false` while the file it named never changed. The payload part
    /// applies cleanly, so nothing in the response looks wrong, and the source
    /// the agent actually wrote is gone with no signal that it was. A partial
    /// commit reported as a whole one is undetectable to the caller, which is
    /// why the whole operation is refused instead.
    #[tokio::test]
    async fn offline_commit_refuses_an_entity_payload_carrying_a_source_body() {
        use crate::session::{McpMutationOperation, McpMutationPayload};

        let store = InMemoryGraph::default();
        let entity = placement_free_entity("value");
        store.upsert_entity(&entity).unwrap();
        let before = serde_json::to_value(&entity).unwrap();

        let sessions = SessionRegistry::new();
        sessions.set_coordination_mode(crate::session::CoordinationEnforcementMode::Warn);
        let session_authority = SessionAuthorityMode::OfflineFallback;
        let tx_id = begin_offline_transaction(&sessions, "offline-payload-plus-body").await;

        let mut updated = entity.clone();
        updated.doc_summary = Some("returns the configured value".into());
        let op = McpMutationOperation {
            verb: "update".into(),
            target: entity.id.to_string(),
            payload: Some(McpMutationPayload::Entity(updated)),
            body: Some("pub fn value() -> u8 { 2 }".into()),
            description: "entity payload plus source body".into(),
        };
        let mut stage_args = HashMap::new();
        stage_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        stage_args.insert("operations".into(), serde_json::json!(vec![op]));
        let stage_res =
            sessions::handle_transaction_stage(&stage_args, &sessions, session_authority)
                .await
                .unwrap();
        assert_ne!(
            stage_res.is_error,
            Some(true),
            "staging must keep accepting the daemon-committable shape: {}",
            tool_result_text(&stage_res)
        );

        let mut commit_args = HashMap::new();
        commit_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        let commit_res =
            sessions::handle_transaction_commit(&commit_args, &store, &sessions, session_authority)
                .await
                .unwrap();

        assert_eq!(
            commit_res.is_error,
            Some(true),
            "a commit that cannot honor the body must refuse, not report success"
        );
        let commit_text = tool_result_text(&commit_res);
        assert!(
            commit_text.contains("require the daemon commit path"),
            "message must name the daemon requirement, got: {commit_text}"
        );
        assert!(
            commit_text.contains("source_body_requires_daemon_commit"),
            "refusal must carry its machine-readable code, got: {commit_text}"
        );

        assert_eq!(sessions.get_transaction(&tx_id).unwrap().state, "active");
        let after = serde_json::to_value(store.get_entity(&entity.id).unwrap().unwrap()).unwrap();
        assert_eq!(
            before, after,
            "no part of a body-carrying operation may reach graph truth on this path"
        );
    }

    /// The refusal follows the operations, not the way they were delivered.
    ///
    /// The inline array is advertised as the single-call convenience form, so
    /// it is the form an agent reaches for first. It must reach the same
    /// verdict as stage-then-commit rather than becoming the one route that
    /// reports success for a dropped body.
    #[tokio::test]
    async fn offline_commit_refuses_inline_operations_carrying_a_source_body() {
        use crate::session::{McpMutationOperation, McpMutationPayload};

        let store = InMemoryGraph::default();
        let entity = placement_free_entity("value");
        store.upsert_entity(&entity).unwrap();
        let before = serde_json::to_value(&entity).unwrap();

        let sessions = SessionRegistry::new();
        sessions.set_coordination_mode(crate::session::CoordinationEnforcementMode::Warn);
        let session_authority = SessionAuthorityMode::OfflineFallback;
        let tx_id = begin_offline_transaction(&sessions, "offline-inline-body").await;

        let mut updated = entity.clone();
        updated.doc_summary = Some("returns the configured value".into());
        let op = McpMutationOperation {
            verb: "update".into(),
            target: entity.id.to_string(),
            payload: Some(McpMutationPayload::Entity(updated)),
            body: Some("pub fn value() -> u8 { 2 }".into()),
            description: "inline entity payload plus source body".into(),
        };
        let mut commit_args = HashMap::new();
        commit_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        commit_args.insert("operations".into(), serde_json::json!(vec![op]));
        let commit_res =
            sessions::handle_transaction_commit(&commit_args, &store, &sessions, session_authority)
                .await
                .unwrap();

        assert_eq!(commit_res.is_error, Some(true));
        let commit_text = tool_result_text(&commit_res);
        assert!(
            commit_text.contains("source_body_requires_daemon_commit"),
            "inline delivery must reach the same typed refusal, got: {commit_text}"
        );
        let after = serde_json::to_value(store.get_entity(&entity.id).unwrap().unwrap()).unwrap();
        assert_eq!(before, after);
    }

    /// A refusal is parseable, not just readable.
    ///
    /// An agent that has to regex prose to decide whether to retry, restage, or
    /// escalate will get it wrong. The refusal carries a stable schema, code,
    /// and operation list so the decision is a field lookup.
    #[tokio::test]
    async fn commit_refusal_is_machine_readable() {
        use crate::session::{CommitRefusal, McpMutationOperation, McpMutationPayload};

        let store = InMemoryGraph::default();
        let entity = placement_free_entity("value");
        store.upsert_entity(&entity).unwrap();

        let sessions = SessionRegistry::new();
        sessions.set_coordination_mode(crate::session::CoordinationEnforcementMode::Warn);
        let session_authority = SessionAuthorityMode::OfflineFallback;
        let tx_id = begin_offline_transaction(&sessions, "offline-typed-refusal").await;

        let op = McpMutationOperation {
            verb: "update".into(),
            target: "value".into(),
            payload: None::<McpMutationPayload>,
            body: Some("pub fn value() -> u8 { 2 }".into()),
            description: "payload-less body update".into(),
        };
        let mut commit_args = HashMap::new();
        commit_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        commit_args.insert("operations".into(), serde_json::json!(vec![op]));
        let commit_res =
            sessions::handle_transaction_commit(&commit_args, &store, &sessions, session_authority)
                .await
                .unwrap();

        assert_eq!(commit_res.is_error, Some(true));
        let commit_text = tool_result_text(&commit_res);
        let evidence = commit_text
            .lines()
            .next_back()
            .expect("refusal renders its evidence on the last line");
        let refusal: CommitRefusal =
            serde_json::from_str(evidence).expect("refusal evidence must parse");
        assert_eq!(refusal.schema, CommitRefusal::SCHEMA);
        assert_eq!(
            refusal.code,
            crate::session::CommitRefusalCode::SourceBodyRequiresDaemonCommit
        );
        assert_eq!(refusal.transaction_id, tx_id);
        assert!(!refusal.applied, "a refusal never applied anything");
        assert_eq!(refusal.transaction_state, "active");
        assert_eq!(refusal.operations.len(), 1);
    }

    /// A field Kin does not model is named, not dropped.
    ///
    /// Serde ignores unknown keys, so an operation calling its source text
    /// `content` decoded to `body: None` and committed nothing while looking
    /// entirely well-formed. One misspelled word is the whole difference
    /// between a caller fixing it and a caller concluding inline commits are
    /// broken.
    #[tokio::test]
    async fn inline_operations_with_an_unmodelled_field_are_refused() {
        let store = InMemoryGraph::default();
        let entity = placement_free_entity("value");
        store.upsert_entity(&entity).unwrap();

        let sessions = SessionRegistry::new();
        sessions.set_coordination_mode(crate::session::CoordinationEnforcementMode::Warn);
        let session_authority = SessionAuthorityMode::OfflineFallback;
        let tx_id = begin_offline_transaction(&sessions, "offline-unknown-field").await;

        let mut commit_args = HashMap::new();
        commit_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        commit_args.insert(
            "operations".into(),
            serde_json::json!([{
                "verb": "update",
                "target": entity.id.to_string(),
                "content": "pub fn value() -> u8 { 2 }",
                "description": "misspelled body key",
            }]),
        );
        let err =
            sessions::handle_transaction_commit(&commit_args, &store, &sessions, session_authority)
                .await
                .expect_err("an unknown operation field must be refused");
        assert!(matches!(err, McpError::InvalidParams(_)));
        assert!(
            err.to_string().contains("'content'"),
            "the refusal must name the unknown field, got: {err}"
        );
        assert_eq!(sessions.get_transaction(&tx_id).unwrap().state, "active");
    }

    /// Across every operation shape, a commit either persists the content it
    /// was handed or refuses; it never reports success having dropped it.
    ///
    /// This is the invariant, stated once over the whole shape matrix rather
    /// than one shape at a time. On this path, which has no projection, the
    /// dividing line is simply whether the operation carries source text: if it
    /// does, the commit refuses, and if it does not, the commit applies
    /// everything the operation carried. Nothing lands in between.
    #[tokio::test]
    async fn no_commit_shape_reports_success_while_dropping_content() {
        use crate::session::{McpMutationOperation, McpMutationPayload};

        struct Shape {
            label: &'static str,
            body: Option<&'static str>,
            with_payload: bool,
        }
        let shapes = [
            Shape {
                label: "payload-less source edit",
                body: Some("pub fn value() -> u8 { 2 }"),
                with_payload: false,
            },
            Shape {
                label: "entity payload plus source edit",
                body: Some("pub fn value() -> u8 { 2 }"),
                with_payload: true,
            },
            Shape {
                label: "entity payload alone",
                body: None,
                with_payload: true,
            },
        ];

        for shape in shapes {
            let store = InMemoryGraph::default();
            let entity = placement_free_entity("value");
            store.upsert_entity(&entity).unwrap();

            let sessions = SessionRegistry::new();
            sessions.set_coordination_mode(crate::session::CoordinationEnforcementMode::Warn);
            let session_authority = SessionAuthorityMode::OfflineFallback;
            let tx_id = begin_offline_transaction(&sessions, "offline-shape-matrix").await;

            let mut updated = entity.clone();
            updated.doc_summary = Some("returns the configured value".into());
            let op = McpMutationOperation {
                verb: "update".into(),
                target: entity.id.to_string(),
                payload: shape
                    .with_payload
                    .then_some(McpMutationPayload::Entity(updated)),
                body: shape.body.map(str::to_string),
                description: shape.label.into(),
            };
            let mut commit_args = HashMap::new();
            commit_args.insert("transaction_id".into(), serde_json::json!(tx_id));
            commit_args.insert("operations".into(), serde_json::json!(vec![op]));
            let commit_res = sessions::handle_transaction_commit(
                &commit_args,
                &store,
                &sessions,
                session_authority,
            )
            .await
            .unwrap();

            let text = tool_result_text(&commit_res);
            let applied = store
                .get_entity(&entity.id)
                .unwrap()
                .unwrap()
                .doc_summary
                .is_some();
            if shape.body.is_some() {
                assert_eq!(
                    commit_res.is_error,
                    Some(true),
                    "{}: a body this path cannot write must refuse: {text}",
                    shape.label
                );
                assert!(
                    !applied,
                    "{}: a refusal must apply no part of the operation",
                    shape.label
                );
            } else {
                assert_ne!(
                    commit_res.is_error,
                    Some(true),
                    "{}: a body-free operation must still commit: {text}",
                    shape.label
                );
                assert!(
                    applied,
                    "{}: a reported commit must have applied its payload",
                    shape.label
                );
            }
        }
    }

    /// The widened refusal must be unreachable on the product surface.
    ///
    /// Refusing a body is only safe because `kin mcp start` pins
    /// `DaemonRequired`, and in that mode every arm of the delegate match
    /// returns before the in-process path is reached: a live daemon takes the
    /// commit, and an unreachable one gets `daemon_required_unavailable`. That
    /// invariant is the entire safety argument, and it currently holds only
    /// because `uses_daemon()` and `requires_daemon()` happen to return the same
    /// thing. They are separate methods, and the delegate match already carries
    /// the fall-through arm that a third mode would activate; the first mode
    /// that preferred a daemon but tolerated its absence would route product
    /// writes into a path that refuses every body-carrying operation.
    ///
    /// Pinned here so that change fails a test instead of failing a user.
    #[tokio::test]
    async fn daemon_required_mode_never_reaches_the_in_process_refusal() {
        use crate::session::{McpMutationOperation, McpMutationPayload};

        let store = InMemoryGraph::default();
        let entity = placement_free_entity("value");
        store.upsert_entity(&entity).unwrap();

        let sessions = SessionRegistry::new();
        sessions.set_coordination_mode(crate::session::CoordinationEnforcementMode::Warn);
        // Staged under OfflineFallback so the transaction exists locally; the
        // commit below is the call under test.
        let tx_id = begin_offline_transaction(&sessions, "daemon-required-refusal").await;
        sessions
            .stage_transaction(
                &tx_id,
                vec![McpMutationOperation {
                    verb: "update".into(),
                    target: entity.id.to_string(),
                    payload: None::<McpMutationPayload>,
                    body: Some("pub fn value() -> u8 { 2 }".into()),
                    description: "body update".into(),
                }],
            )
            .unwrap();

        let mut commit_args = HashMap::new();
        commit_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        let commit_res = sessions::handle_transaction_commit(
            &commit_args,
            &store,
            &sessions,
            SessionAuthorityMode::DaemonRequired,
        )
        .await
        .unwrap();

        let text = tool_result_text(&commit_res);
        assert!(
            !text.contains("source_body_requires_daemon_commit"),
            "the in-process refusal must be unreachable under DaemonRequired, got: {text}"
        );
        assert!(
            text.contains("daemon"),
            "an unreachable daemon must say so rather than refuse the operation: {text}"
        );
        assert_eq!(
            sessions.get_transaction(&tx_id).unwrap().state,
            "active",
            "delegation must not terminalize the transaction"
        );
    }

    #[tokio::test]
    async fn handle_transaction_stage_rejects_malformed_op_at_stage_time() {
        // D.7 Track A: a payload-less operation must fail loud at stage time —
        // before the transaction is even consulted — instead of being silently
        // dropped at commit. The transaction id here does not exist; validation
        // is expected to reject the operation first.
        use crate::session::{McpMutationOperation, McpMutationPayload};
        let sessions = SessionRegistry::new();
        let session_authority = SessionAuthorityMode::OfflineFallback;

        let op: McpMutationOperation = McpMutationOperation {
            verb: "create".into(),
            target: "function".into(),
            payload: None::<McpMutationPayload>,
            body: None,
            description: "add dummy".into(),
        };
        let mut stage_args = HashMap::new();
        stage_args.insert("transaction_id".into(), serde_json::json!("no-such-tx"));
        stage_args.insert("operations".into(), serde_json::json!(vec![op]));

        let err = sessions::handle_transaction_stage(&stage_args, &sessions, session_authority)
            .await
            .expect_err("payload-less op must be rejected at stage time");
        assert!(matches!(err, McpError::InvalidParams(_)));
        assert!(
            err.to_string().contains("missing payload"),
            "actionable stage-time message expected, got: {err}"
        );
    }

    use std::sync::{Mutex, OnceLock};
    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

    #[test]
    fn exact_artifact_tools_preserve_every_repository_leaf_without_entities() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());
        let blobs = kin_blobs::BlobStore::new(kin_dir.join("objects")).unwrap();

        let compose_path = kin_model::RepoPath::from_utf8("compose.yaml").unwrap();
        let lock_path = kin_model::RepoPath::from_utf8("Cargo.lock").unwrap();
        let unsupported_path = kin_model::RepoPath::from_utf8("legacy/handler.cob").unwrap();
        let binary_path =
            kin_model::RepoPath::from_bytes(b"assets/\xffpayload.bin".to_vec()).unwrap();
        let executable_path = kin_model::RepoPath::from_utf8("bin/kin-hook").unwrap();
        let symlink_path = kin_model::RepoPath::from_utf8("current-config").unwrap();
        let gitlink_path = kin_model::RepoPath::from_utf8("vendor/external").unwrap();

        let compose_bytes = b"services:\n  api:\n    image: kin:test\n";
        let lock_bytes = b"# graph-owned lockfile\n";
        let unsupported_bytes = b"IDENTIFICATION DIVISION.\n";
        let binary_bytes = b"\x00\xff\x80\x01KIN";
        let executable_bytes = b"#!/bin/sh\nexec kin \"$@\"\n";
        let symlink_target = b"config/\xffproduction.yaml";

        let compose_hash = model_blob_hash(&blobs, compose_bytes);
        let lock_hash = model_blob_hash(&blobs, lock_bytes);
        let unsupported_hash = model_blob_hash(&blobs, unsupported_bytes);
        let binary_hash = model_blob_hash(&blobs, binary_bytes);
        let executable_hash = model_blob_hash(&blobs, executable_bytes);
        let symlink_hash = model_blob_hash(&blobs, symlink_target);

        // A conflicting projection proves reads are content-addressed graph
        // reads, never ambient working-tree reads.
        fs::write(
            dir.path().join("compose.yaml"),
            b"filesystem fallback must never win\n",
        )
        .unwrap();

        let compose_id = kin_model::ArtifactId::new();
        let lock_id = kin_model::ArtifactId::new();
        let unsupported_id = kin_model::ArtifactId::new();
        let binary_id = kin_model::ArtifactId::new();
        let executable_id = kin_model::ArtifactId::new();
        let symlink_id = kin_model::ArtifactId::new();
        let gitlink_id = kin_model::ArtifactId::new();
        let gitlink_target = kin_model::GitObjectId::sha1([0x42; 20]);

        let change = exact_test_change(
            vec![],
            "admit every exact repository leaf",
            vec![],
            vec![
                kin_model::TreeDelta::Added {
                    artifact_id: compose_id,
                    new: kin_model::LocatedEntry::new(
                        compose_path.clone(),
                        kin_model::TreeEntry::blob(compose_hash, false),
                    ),
                },
                kin_model::TreeDelta::Added {
                    artifact_id: lock_id,
                    new: kin_model::LocatedEntry::new(
                        lock_path.clone(),
                        kin_model::TreeEntry::blob(lock_hash, false),
                    ),
                },
                kin_model::TreeDelta::Added {
                    artifact_id: unsupported_id,
                    new: kin_model::LocatedEntry::new(
                        unsupported_path.clone(),
                        kin_model::TreeEntry::blob(unsupported_hash, false),
                    ),
                },
                kin_model::TreeDelta::Added {
                    artifact_id: binary_id,
                    new: kin_model::LocatedEntry::new(
                        binary_path.clone(),
                        kin_model::TreeEntry::blob(binary_hash, false),
                    ),
                },
                kin_model::TreeDelta::Added {
                    artifact_id: executable_id,
                    new: kin_model::LocatedEntry::new(
                        executable_path.clone(),
                        kin_model::TreeEntry::blob(executable_hash, true),
                    ),
                },
                kin_model::TreeDelta::Added {
                    artifact_id: symlink_id,
                    new: kin_model::LocatedEntry::new(
                        symlink_path.clone(),
                        kin_model::TreeEntry::symlink(symlink_hash),
                    ),
                },
                kin_model::TreeDelta::Added {
                    artifact_id: gitlink_id,
                    new: kin_model::LocatedEntry::new(
                        gitlink_path.clone(),
                        kin_model::TreeEntry::gitlink(gitlink_target),
                    ),
                },
            ],
        );
        let store = InMemoryGraph::default();
        store.create_change(&change).unwrap();
        let authority_change = exact_test_change(
            vec![],
            "seed exact MCP content authority",
            vec![],
            change
                .tree_deltas
                .iter()
                .filter(|delta| {
                    !matches!(
                        delta.new_state().map(|located| located.entry),
                        Some(kin_model::TreeEntry::Gitlink { .. })
                    )
                })
                .cloned()
                .collect(),
        );
        initialize_test_repository(dir.path(), &authority_change);
        let authority = test_repository_authority(dir.path());
        assert!(
            store
                .query_entities(&EntityFilter::default())
                .unwrap()
                .is_empty(),
            "repository membership must not depend on parser-emitted entities"
        );

        let list = artifacts::handle_artifact_list(
            &HashMap::from([(
                "source_change_id".into(),
                serde_json::json!(change.id.to_string()),
            )]),
            &store,
            Some(&authority),
        )
        .unwrap();
        let listed = tool_result_json(list);
        assert_eq!(listed["artifact_count"], 7);
        let listed_artifacts = listed["artifacts"].as_array().unwrap();
        assert_eq!(listed_artifacts.len(), 7);

        let find_path = |path: &kin_model::RepoPath| {
            let wire = serde_json::to_value(path).unwrap();
            listed_artifacts
                .iter()
                .find(|artifact| artifact["path"] == wire)
                .unwrap()
        };
        assert_eq!(find_path(&compose_path)["entry"]["type"], "blob");
        assert_eq!(find_path(&lock_path)["entry"]["type"], "blob");
        assert_eq!(find_path(&unsupported_path)["entry"]["type"], "blob");
        assert_eq!(find_path(&executable_path)["entry"]["executable"], true);
        assert_eq!(find_path(&symlink_path)["entry"]["type"], "symlink");
        assert_eq!(find_path(&gitlink_path)["entry"]["type"], "gitlink");
        let binary_wire = find_path(&binary_path);
        assert_eq!(
            binary_wire["path"],
            serde_json::to_value(&binary_path).unwrap()
        );
        assert_eq!(binary_wire["path_label_lossy"], true);
        assert!(binary_wire["path_label"]
            .as_str()
            .unwrap()
            .contains('\u{fffd}'));

        let compose = tool_result_json(
            artifacts::handle_artifact_read(
                &HashMap::from([
                    (
                        "artifact_id".into(),
                        serde_json::to_value(compose_id).unwrap(),
                    ),
                    (
                        "source_change_id".into(),
                        serde_json::json!(change.id.to_string()),
                    ),
                ]),
                &store,
                Some(&authority),
            )
            .unwrap(),
        );
        assert_eq!(
            compose["content_base64"],
            base64::engine::general_purpose::STANDARD.encode(compose_bytes)
        );
        assert_eq!(
            compose["text_utf8"],
            std::str::from_utf8(compose_bytes).unwrap()
        );
        assert_ne!(compose["text_utf8"], "filesystem fallback must never win\n");

        let binary = tool_result_json(
            artifacts::handle_artifact_read(
                &HashMap::from([
                    ("path".into(), serde_json::to_value(&binary_path).unwrap()),
                    (
                        "source_change_id".into(),
                        serde_json::json!(change.id.to_string()),
                    ),
                ]),
                &store,
                Some(&authority),
            )
            .unwrap(),
        );
        assert_eq!(
            binary["content_base64"],
            base64::engine::general_purpose::STANDARD.encode(binary_bytes)
        );
        assert!(binary.get("text_utf8").is_none());

        let executable = tool_result_json(
            artifacts::handle_artifact_read(
                &HashMap::from([
                    (
                        "artifact_id".into(),
                        serde_json::to_value(executable_id).unwrap(),
                    ),
                    (
                        "path".into(),
                        serde_json::to_value(&executable_path).unwrap(),
                    ),
                    (
                        "source_change_id".into(),
                        serde_json::json!(change.id.to_string()),
                    ),
                ]),
                &store,
                Some(&authority),
            )
            .unwrap(),
        );
        assert_eq!(executable["artifact"]["entry"]["executable"], true);
        assert_eq!(
            executable["content_base64"],
            base64::engine::general_purpose::STANDARD.encode(executable_bytes)
        );

        let symlink = tool_result_json(
            artifacts::handle_artifact_read(
                &HashMap::from([
                    (
                        "artifact_id".into(),
                        serde_json::to_value(symlink_id).unwrap(),
                    ),
                    (
                        "source_change_id".into(),
                        serde_json::json!(change.id.to_string()),
                    ),
                ]),
                &store,
                Some(&authority),
            )
            .unwrap(),
        );
        assert_eq!(symlink["content_kind"], "symlink_target");
        assert_eq!(
            symlink["content_base64"],
            base64::engine::general_purpose::STANDARD.encode(symlink_target)
        );
        assert!(symlink.get("text_utf8").is_none());

        let gitlink = tool_result_json(
            artifacts::handle_artifact_read(
                &HashMap::from([
                    (
                        "artifact_id".into(),
                        serde_json::to_value(gitlink_id).unwrap(),
                    ),
                    (
                        "source_change_id".into(),
                        serde_json::json!(change.id.to_string()),
                    ),
                ]),
                &store,
                Some(&authority),
            )
            .unwrap(),
        );
        assert_eq!(gitlink["content_kind"], "gitlink_reference");
        assert_eq!(
            gitlink["git_object_id"],
            serde_json::to_value(gitlink_target).unwrap()
        );
        assert!(gitlink.get("content_base64").is_none());
    }

    #[test]
    fn exact_artifact_tools_fail_loud_on_missing_tree_blob_or_identity() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());

        let path = kin_model::RepoPath::from_utf8("missing.bin").unwrap();
        let artifact_id = kin_model::ArtifactId::new();
        let blobs = kin_blobs::BlobStore::new(kin_dir.join("objects")).unwrap();
        let missing_hash = model_blob_hash(&blobs, b"sealed then deliberately removed");
        let change = exact_test_change(
            vec![],
            "reference a deliberately missing blob",
            vec![],
            vec![kin_model::TreeDelta::Added {
                artifact_id,
                new: kin_model::LocatedEntry::new(
                    path.clone(),
                    kin_model::TreeEntry::blob(missing_hash, false),
                ),
            }],
        );
        let store = InMemoryGraph::default();
        store.create_change(&change).unwrap();
        initialize_test_repository(dir.path(), &change);
        let authority = test_repository_authority(dir.path());
        fs::remove_file(test_source_blob_path(dir.path(), missing_hash)).unwrap();
        fs::write(
            dir.path().join("missing.bin"),
            b"ambient bytes must not repair graph truth",
        )
        .unwrap();

        let missing_blob = artifacts::handle_artifact_read(
            &HashMap::from([
                (
                    "artifact_id".into(),
                    serde_json::to_value(artifact_id).unwrap(),
                ),
                (
                    "source_change_id".into(),
                    serde_json::json!(change.id.to_string()),
                ),
            ]),
            &store,
            Some(&authority),
        )
        .expect_err("a graph tree entry with no content-addressed blob must fail");
        assert!(missing_blob.to_string().contains("graph authority gap"));
        assert!(missing_blob
            .to_string()
            .contains("absent from immutable source CAS"));
        assert!(!missing_blob
            .to_string()
            .contains("ambient bytes must not repair graph truth"));

        let absent_path = artifacts::handle_artifact_read(
            &HashMap::from([
                (
                    "path".into(),
                    serde_json::to_value(kin_model::RepoPath::from_utf8("not-present").unwrap())
                        .unwrap(),
                ),
                (
                    "source_change_id".into(),
                    serde_json::json!(change.id.to_string()),
                ),
            ]),
            &store,
            Some(&authority),
        )
        .expect_err("an absent exact path must fail");
        assert!(absent_path.to_string().contains("exact path is absent"));

        let unknown_change = SemanticChangeId::from_hash(Hash256::from_bytes([0xee; 32]));
        let missing_tree = artifacts::handle_artifact_list(
            &HashMap::from([(
                "source_change_id".into(),
                serde_json::json!(unknown_change.to_string()),
            )]),
            &store,
            Some(&authority),
        )
        .expect_err("an unknown graph head must not produce an empty repository");
        assert!(missing_tree.to_string().contains("graph authority gap"));
        assert!(missing_tree
            .to_string()
            .contains("cannot resolve exact repository tree"));
    }

    #[test]
    fn exact_source_tracks_rename_identity_and_rejects_later_path_reuse() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let content = "export function validate_probe_range_1d8f8275() { return 42; }\n";
        let source = make_source_backed_entity(content);
        let store = InMemoryGraph::default();
        let first_head = source.install(&store);
        let authority = test_repository_authority(source._dir.path());
        let old_path = kin_model::RepoPath::from_utf8("validate.ts").unwrap();
        let renamed_path = kin_model::RepoPath::from_utf8("src/renamed.ts").unwrap();
        let old_entry =
            kin_model::LocatedEntry::new(old_path, kin_model::TreeEntry::blob(source.hash, false));
        let renamed_entry = kin_model::LocatedEntry::new(
            renamed_path.clone(),
            kin_model::TreeEntry::blob(source.hash, false),
        );
        let mut renamed_entity = source.entity.clone();
        let renamed_file = FilePathId::new("src/renamed.ts");
        renamed_entity.file_origin = Some(renamed_file.clone());
        renamed_entity.span.as_mut().unwrap().file = renamed_file;

        let rename = exact_test_change(
            vec![first_head],
            "rename source without changing its identity",
            vec![kin_model::EntityDelta::Modified {
                old: source.entity.clone(),
                new: renamed_entity.clone(),
            }],
            vec![kin_model::TreeDelta::Updated {
                artifact_id: source.artifact_id,
                old: old_entry,
                new: renamed_entry.clone(),
            }],
        );
        store.create_change(&rename).unwrap();
        advance_test_repository(source._dir.path(), &rename);

        let renamed_source =
            entity_response_json(&store, &renamed_entity, Some(&authority)).unwrap();
        assert_eq!(
            renamed_source["artifact_id"],
            serde_json::to_value(source.artifact_id).unwrap()
        );
        assert_eq!(
            renamed_source["artifact_path"],
            serde_json::to_value(&renamed_path).unwrap()
        );
        assert_eq!(
            renamed_source["source_excerpt"],
            content.trim_end_matches('\n')
        );

        let read_after_rename = tool_result_json(
            artifacts::handle_artifact_read(
                &HashMap::from([
                    (
                        "artifact_id".into(),
                        serde_json::to_value(source.artifact_id).unwrap(),
                    ),
                    (
                        "source_change_id".into(),
                        serde_json::json!(rename.id.to_string()),
                    ),
                ]),
                &store,
                Some(&authority),
            )
            .unwrap(),
        );
        assert_eq!(
            read_after_rename["artifact"]["path"],
            serde_json::to_value(&renamed_path).unwrap()
        );
        assert_eq!(
            read_after_rename["content_base64"],
            base64::engine::general_purpose::STANDARD.encode(content.as_bytes())
        );

        let replacement_id = kin_model::ArtifactId::new();
        let reuse = exact_test_change(
            vec![rename.id],
            "replace the path with a different artifact identity",
            vec![],
            vec![
                kin_model::TreeDelta::Removed {
                    artifact_id: source.artifact_id,
                    old: renamed_entry.clone(),
                },
                kin_model::TreeDelta::Added {
                    artifact_id: replacement_id,
                    new: renamed_entry,
                },
            ],
        );
        store.create_change(&reuse).unwrap();
        advance_test_repository(source._dir.path(), &reuse);

        let error = entity_response_json(&store, &renamed_entity, Some(&authority))
            .expect_err("an old entity revision must not read a replacement artifact");
        assert!(error
            .to_string()
            .contains("path 'src/renamed.ts' was reused"));

        let replacement = tool_result_json(
            artifacts::handle_artifact_read(
                &HashMap::from([
                    ("path".into(), serde_json::to_value(&renamed_path).unwrap()),
                    (
                        "source_change_id".into(),
                        serde_json::json!(reuse.id.to_string()),
                    ),
                ]),
                &store,
                Some(&authority),
            )
            .unwrap(),
        );
        assert_eq!(
            replacement["artifact"]["artifact_id"],
            serde_json::to_value(replacement_id).unwrap()
        );
    }

    #[test]
    fn test_entity_served_from_blob_store_file_deleted() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());

        let objects_dir = kin_dir.join("objects");
        let blob_store = kin_blobs::BlobStore::new(objects_dir).unwrap();

        let content = "export function test_blob() { return 42; }";
        let hash = blob_store.write(content.as_bytes()).unwrap();

        let file_path = "src/lib.rs";
        let file_id = FilePathId::new(file_path);

        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "test_blob".into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: hash,
                signature_hash: hash,
                behavior_hash: hash,
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id.clone(),
                start_byte: 0,
                end_byte: content.len(),
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: content.len() as u32,
            }),
            signature: "export function test_blob()".into(),
            visibility: Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(entity.id, entity.clone());
        store.file_hashes.insert(file_id, hash);
        install_empty_store_exact_tree(&mut store, dir.path());
        let authority = test_repository_authority(dir.path());

        let value = entity_response_json(&store, &entity, Some(&authority)).unwrap();
        let object = value.as_object().unwrap();
        let excerpt = object
            .get("source_excerpt")
            .and_then(|v| v.as_str())
            .unwrap();

        assert_eq!(excerpt, content);
        assert_eq!(
            object.get("span_coherence").and_then(|v| v.as_str()),
            Some("unverified"),
            "an entity with no recorded source digest must not claim a verified span"
        );
        assert_eq!(object.get("source").unwrap().as_str().unwrap(), "graph");
    }

    /// Which source digest the live entity records, relative to a workspace tree
    /// that has moved past its base.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SpanStamp {
        /// The reconciler has caught up: the span was derived from the bytes now
        /// in the tree.
        Current,
        /// The tree was admitted and the span has not been re-derived yet. This is
        /// the real window between the daemon's two transactions.
        Stale,
        /// No recorded provenance, so coherence cannot be checked either way.
        Absent,
    }

    /// Set up a repository whose exact tree has moved past its base at one path.
    ///
    /// Returns the entity (span covering the whole file), the graph store, the
    /// authority binding, and the digest now living at that path.
    fn divergent_tree_fixture(
        dir: &std::path::Path,
        before: &str,
        after: &str,
        stamp: SpanStamp,
    ) -> (Entity, EmptyStore, RequestRepositoryAuthority, Hash256) {
        let kin_dir = dir.join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        let blob_store = kin_blobs::BlobStore::new(kin_dir.join("objects")).unwrap();
        let before_hash = blob_store.write(before.as_bytes()).unwrap();

        let file_path = "src/alpha.ts";
        let file_id = FilePathId::new(file_path);
        let mut entity = whole_file_entity(&file_id, before, Some(before_hash));

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(entity.id, entity.clone());
        store.file_hashes.insert(file_id.clone(), before_hash);
        install_empty_store_exact_tree(&mut store, dir);

        // The tree moves. Whether the entity's recorded provenance moves with it
        // is what each caller varies, because that is the difference between a
        // read that can prove its span describes these bytes and one that cannot.
        let repo_path = kin_model::RepoPath::from_utf8(file_path.to_string()).unwrap();
        let after_hash = admit_test_workspace_tree(dir, &repo_path, after.as_bytes());

        match stamp {
            SpanStamp::Current => {
                entity.metadata.extra.insert(
                    "blob_hash".into(),
                    serde_json::Value::String(after_hash.to_string()),
                );
            }
            SpanStamp::Stale => {}
            SpanStamp::Absent => {
                entity.metadata.extra.remove("blob_hash");
            }
        }
        store.entities_by_id.insert(entity.id, entity.clone());
        let authority = test_repository_authority(dir);
        (entity, store, authority, after_hash)
    }

    /// A head read must serve the LIVE workspace tree, and must say the bytes are
    /// uncommitted when they are.
    ///
    /// This is the test the byte-source change never had. Both halves fail if the
    /// head arm is pointed back at the tree at `base_target`: the body comes back
    /// as the pre-admission content, and the provenance claims a committed change.
    ///
    /// The provenance half is the one that matters for truthfulness. These bytes
    /// exist in no change: `publish_workspace_tree` advances the tree without
    /// creating a history node or moving a ref, so stamping the base change id on
    /// them attests committed provenance for state no commit contains.
    #[test]
    fn head_read_serves_live_tree_bytes_and_marks_them_uncommitted() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());

        // Same length on purpose: the span still covers the whole file, so the
        // body is exactly one of the two contents and nothing is clipped. That
        // makes the assertion a clean discriminator between the two trees rather
        // than a statement about bounds.
        let before = "export function alpha() { return 1; }\n";
        let after = "export function alpha() { return 2; }\n";
        assert_eq!(before.len(), after.len(), "fixture must isolate content");

        let (entity, store, authority, after_hash) =
            divergent_tree_fixture(dir.path(), before, after, SpanStamp::Current);

        let source = read_entity_source_excerpt_detailed(
            &store,
            &entity,
            64,
            4096,
            Some(&authority),
            EntitySourceScope::WorkspaceHead,
        )
        .expect("head read must succeed against a workspace past its base")
        .expect("entity has source coordinates");

        // Compared on the distinguishing token rather than byte-for-byte: the
        // excerpt projection normalizes the trailing newline, and the assertion is
        // about WHICH tree was read, not about line endings.
        assert!(
            source.body.contains("return 2"),
            "a head read must serve the live workspace tree, got: {}",
            source.body
        );
        assert!(
            !source.body.contains("return 1"),
            "serving the tree at base is the defect this pins, got: {}",
            source.body
        );

        match &source.provenance {
            common::SourceProvenance::Workspace {
                base_change_id,
                generation,
                ..
            } => {
                assert!(
                    *generation >= 1,
                    "the admission advanced the workspace generation"
                );
                // The base change still exists and is still named -- it is just
                // named as the BASE, not as the source of these bytes.
                assert!(!base_change_id.to_string().is_empty());
            }
            other => {
                panic!("uncommitted tree bytes must not report committed provenance: {other:?}")
            }
        }
        assert_eq!(
            source.provenance.committed_change_id(),
            None,
            "no committed change contains these bytes, so none may be offered as containing them"
        );

        // And the emitted shape must not carry `source_change_id` at all, so a
        // consumer reading that key can never receive an id that excludes the body.
        let fields = common::source_provenance_fields(&source);
        assert_eq!(
            fields.get("source_state").and_then(|v| v.as_str()),
            Some("workspace")
        );
        assert!(
            !fields.contains_key("source_change_id"),
            "uncommitted bytes must not be stamped with a change id: {fields:?}"
        );
        assert!(fields.contains_key("base_change_id"));
        assert!(fields.contains_key("workspace_tree_hash"));
        assert_eq!(
            fields.get("span_coherence").and_then(|v| v.as_str()),
            Some("digest_verified")
        );
        let _ = after_hash;
    }

    /// The batch arm must disclose provenance on every row that carries a body.
    ///
    /// `get_entity_sources` returns up to 50 full bodies and exists so an agent can
    /// restate source it is about to overwrite, which makes it the arm where "these
    /// bytes are uncommitted" and "this span was never proven to describe them"
    /// matter most. It was the one body-serving arm that rendered neither: the
    /// refusal for provable incoherence reached it through the shared resolver, but
    /// the served-unverified half of the same rule emitted no signal at all.
    #[test]
    fn batch_source_rows_carry_provenance_beside_each_body() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());

        let before = "export function alpha() { return 1; }\n";
        let after = "export function alpha() { return 2; }\n";
        let (entity, store, authority, _) =
            divergent_tree_fixture(dir.path(), before, after, SpanStamp::Current);

        let args = HashMap::from([(
            "entity_ids".to_string(),
            serde_json::json!([entity.id.to_string()]),
        )]);
        let value = tool_result_json(
            entities::handle_get_entity_sources(&args, &store, Some(&authority)).unwrap(),
        );
        let row = &value["results"]
            .as_array()
            .unwrap_or_else(|| panic!("batch envelope must carry rows: {value}"))[0];

        assert!(
            row["body"].as_str().is_some_and(|b| b.contains("return 2")),
            "the row must carry the live body: {row}"
        );
        // The bytes are in no committed change, and the row says so rather than
        // naming one.
        assert_eq!(
            row["source_state"].as_str(),
            Some("workspace"),
            "a batch row over an uncommitted tree must disclose that: {row}"
        );
        assert!(
            row.get("source_change_id").is_none(),
            "no change contains these bytes, so none may be offered: {row}"
        );
        assert_eq!(row["span_coherence"].as_str(), Some("digest_verified"));
        assert!(row.get("workspace_tree_hash").is_some());
    }

    /// A span derived from one source must never be used to cut a different one.
    ///
    /// The graph and repository authority are separate stores updated by separate
    /// transactions: the daemon admits the exact tree first and re-derives entity
    /// spans afterwards. In between, the tree holds a path's new bytes and the
    /// graph holds the old offsets into it. Slicing one with the other returns
    /// text that is syntactically plausible and is not the entity's source, and a
    /// bounds check cannot see it because stale offsets still land inside the file.
    ///
    /// So the read refuses. Without the digest comparison this test gets a body
    /// back -- the wrong one -- and passes silently, which is precisely the
    /// failure mode that makes an agent restate someone else's code as this
    /// entity's implementation.
    #[test]
    fn head_read_refuses_a_span_that_was_derived_from_different_bytes() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());

        // The replacement is LONGER, so the recorded span stays comfortably in
        // bounds and the existing bounds check passes. That is the point: the
        // mis-slice this catches is invisible to a length test.
        let before = "export function alpha() { return 1; }\n";
        let after = "export function alpha() {\n  const extra = compute();\n  return extra;\n}\n";
        assert!(after.len() > before.len());

        // The entity still records the digest of `before` while the tree holds
        // `after`: the daemon has admitted the new source and not yet re-derived
        // this entity's span.
        let (entity, store, authority, _) =
            divergent_tree_fixture(dir.path(), before, after, SpanStamp::Stale);

        let outcome = read_entity_source_excerpt_detailed(
            &store,
            &entity,
            64,
            4096,
            Some(&authority),
            EntitySourceScope::WorkspaceHead,
        );

        let error = outcome.expect_err(
            "a span derived from other bytes must fail loudly, never serve a mis-sliced body",
        );
        let message = error.to_string();
        assert!(
            message.contains("does not describe these bytes"),
            "the refusal must name the incoherence, got: {message}"
        );
        assert!(
            message.contains("re-derived"),
            "the refusal must tell the caller this is transient and retryable, got: {message}"
        );
    }

    /// The digest check must not reject a read it cannot verify.
    ///
    /// Entities legitimately arrive without recorded source provenance, and a
    /// fresh clone whose admission populated the live graph is the exact case the
    /// head read exists to serve. Refusing those would re-close the body reads
    /// this whole change opened, so an unstamped entity is served and the response
    /// states that the pair was not checked rather than implying it was.
    #[test]
    fn head_read_serves_an_unstamped_entity_and_reports_the_span_unverified() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());

        let before = "export function alpha() { return 1; }\n";
        let after = "export function alpha() { return 2; }\n";
        let (entity, store, authority, _) =
            divergent_tree_fixture(dir.path(), before, after, SpanStamp::Absent);

        let source = read_entity_source_excerpt_detailed(
            &store,
            &entity,
            64,
            4096,
            Some(&authority),
            EntitySourceScope::WorkspaceHead,
        )
        .expect("an unstamped entity must still be readable")
        .expect("entity has source coordinates");

        assert!(
            source.body.contains("return 2"),
            "still the live tree, got: {}",
            source.body
        );
        assert_eq!(
            source.span_coherence,
            common::SpanCoherence::Unverified,
            "an unverifiable pair must be reported as unverified, not as coherent"
        );
    }

    /// Drive the PRODUCTION impact handler, not just its private helper.
    ///
    /// `annotate_impact_presentation_lines` had exactly two callers:
    /// `handle_impact_analysis` and a test that called the private helper
    /// directly. Deleting the production call broke nothing, so the wiring that
    /// actually reaches an agent was unpinned while the conversion itself looked
    /// well covered.
    ///
    /// It lives here rather than beside the helper because a handler test needs a
    /// `SessionRegistry`, and the runtime-boundary guard allows that only in files
    /// it has cleared; this module is entirely test code and is already on that
    /// list.
    #[tokio::test]
    async fn impact_analysis_handler_emits_one_based_lines_for_affected_callers() {
        let callee = impact_probe_entity("callee_probe_4c21", None);
        let caller = impact_probe_entity("caller_probe_4c21", Some(41));

        let mut store = EmptyStore::default();
        store.insert_test_entity(callee.clone());
        store.insert_test_entity(caller.clone());
        store.insert_test_calls_relation(&caller, &callee);

        let args = HashMap::from([
            (
                "entity_ids".to_string(),
                serde_json::json!([callee.id.to_string()]),
            ),
            ("include_traffic".to_string(), serde_json::json!(false)),
        ]);
        let sessions = SessionRegistry::new();

        let value = tool_result_json(
            review::handle_impact_analysis(&args, &store, &sessions)
                .await
                .unwrap(),
        );

        let rows = value["affected_callers"]
            .as_array()
            .unwrap_or_else(|| panic!("impact analysis must report callers: {value}"));
        assert!(
            !rows.is_empty(),
            "the fixture wires one caller, so the handler must report it: {value}"
        );
        assert_eq!(
            rows[0]["start_line"], 42,
            "graph row 41 must reach the agent as line 42: {}",
            rows[0]
        );
        // The nested raw span stays graph truth, the established convention.
        assert_eq!(rows[0]["span"]["start_line"], 41);
    }

    /// FIR-2217. Files mode reported a diff-mode complaint on a resolution
    /// failure.
    ///
    /// `impact_analysis {files: [...]}` on paths that resolve to no entities came
    /// back as "review error: no changes between base and head" when no base and
    /// no head had been passed. An agent reads that as a diff problem and starts
    /// looking for one, which is the wrong-cause error class this workspace
    /// polices. Tracked paths with no parser-emitted entities are the ordinary
    /// way to hit it: a workflow file is a real artifact and resolves to nothing.
    #[tokio::test]
    async fn impact_analysis_files_mode_names_a_resolution_miss_not_a_diff_complaint() {
        let store = InMemoryGraph::new();
        let present = impact_probe_entity("resolvable_probe_2217", Some(3));
        let present_path = present
            .file_origin
            .as_ref()
            .expect("the probe carries a file origin")
            .to_string();
        kin_model::graph::EntityStore::upsert_entity(&store, &present).unwrap();
        let sessions = SessionRegistry::new();

        let absent_args = HashMap::from([
            (
                "files".to_string(),
                serde_json::json!(["crates/kin-index/src/classifier.rs", ".github/workflows/release.yml"]),
            ),
            ("include_traffic".to_string(), serde_json::json!(false)),
        ]);
        let error = review::handle_impact_analysis(&absent_args, &store, &sessions)
            .await
            .expect_err("files resolving to no entities is an error, not an empty report")
            .to_string();

        assert!(
            error.contains("no entity resolved from the given files"),
            "the error must name the resolution miss: {error}"
        );
        assert!(
            !error.contains("no changes between base and head"),
            "a files-mode miss must not report a diff-mode complaint: {error}"
        );
        assert!(
            error.contains(".github/workflows/release.yml"),
            "the error must name the paths that resolved to nothing: {error}"
        );

        // The wording has to be one the envelope recognizes, or the tool fails
        // loudly and still carries no negative object beside it.
        let negative = crate::negative::resolution_miss_for(
            "impact_analysis",
            &error,
            &crate::Envelope::daemon(),
        )
        .expect("a files-mode miss must carry the standard negative object");
        assert_eq!(negative["kind"], serde_json::json!("scope_not_resolved"));

        // Positive control: a path that DOES resolve still produces a report, so
        // the new arm reads the resolution rather than rejecting files mode.
        let present_args = HashMap::from([
            ("files".to_string(), serde_json::json!([present_path])),
            ("include_traffic".to_string(), serde_json::json!(false)),
        ]);
        let value = tool_result_json(
            review::handle_impact_analysis(&present_args, &store, &sessions)
                .await
                .expect("a resolvable file must still yield an impact report"),
        );
        assert!(
            value.get("affected_callers").is_some() || value.get("changed_entities").is_some(),
            "the control must return a real report: {value}"
        );

        // Negative control on the envelope side: an unrelated failure from the
        // same tool must NOT be dressed up as a resolution miss.
        assert!(crate::negative::resolution_miss_for(
            "impact_analysis",
            "review error: graph store error: disk went away",
            &crate::Envelope::daemon(),
        )
        .is_none());
    }

    /// The artifact-identity binding is SKIPPED for an entity committed history
    /// has no revision for, and that skip is the fresh-clone case this read exists
    /// to serve.
    ///
    /// Only committed history knows which artifact introduced an entity, so a
    /// live-only entity has no prior binding to contradict and the check cannot
    /// run. That was argued but never tested: the existing rename/path-reuse test
    /// exercises only the `Some(introduced_by)` branch.
    ///
    /// Both halves are asserted here, because the skip is only defensible if
    /// something still guards the read. The recorded source digest is that guard:
    /// an entity whose span was derived from the bytes now at the path is served,
    /// and one whose span was not is refused, with no committed revision involved
    /// in either outcome.
    #[test]
    fn live_only_entity_skips_identity_binding_but_not_the_digest_check() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());
        let blob_store = kin_blobs::BlobStore::new(kin_dir.join("objects")).unwrap();

        let content = "export function orphan() { return 7; }\n";
        let hash = blob_store.write(content.as_bytes()).unwrap();
        let file_id = FilePathId::new("src/orphan.ts");

        // The tree carries the path; the initial change carries NO entity for it,
        // so committed history records no revision and the binding is skipped.
        let mut store = EmptyStore::default();
        store.file_hashes.insert(file_id.clone(), hash);
        install_empty_store_exact_tree(&mut store, dir.path());
        let authority = test_repository_authority(dir.path());

        let entity = whole_file_entity(&file_id, content, Some(hash));
        store.entities_by_id.insert(entity.id, entity.clone());
        assert!(
            committed_introducing_change_is_absent(&store, &entity),
            "the fixture must leave this entity out of committed history"
        );

        let source = read_entity_source_excerpt_detailed(
            &store,
            &entity,
            64,
            4096,
            Some(&authority),
            EntitySourceScope::WorkspaceHead,
        )
        .expect("a live-only entity must be readable; rejecting it was the original defect")
        .expect("entity has source coordinates");
        assert!(source.body.contains("return 7"));
        assert_eq!(source.span_coherence, common::SpanCoherence::DigestVerified);

        // Same entity, same skipped binding, but its span was derived from other
        // bytes: the read must still refuse.
        let mut stale = entity.clone();
        stale.metadata.extra.insert(
            "blob_hash".into(),
            serde_json::Value::String(Hash256::from_bytes([9; 32]).to_string()),
        );
        let error = read_entity_source_excerpt_detailed(
            &store,
            &stale,
            64,
            4096,
            Some(&authority),
            EntitySourceScope::WorkspaceHead,
        )
        .expect_err("a skipped identity binding must not mean an unguarded read");
        assert!(error.to_string().contains("does not describe these bytes"));
    }

    /// A page of retrieval hits derives repository authority ONCE, not once per
    /// hit.
    ///
    /// This is the bound FIR-1897 was filed on. `semantic_locate` fans a client
    /// `limit: 5` out to 40 daemon candidates, and the body projection re-opened
    /// the persisted authority and replayed the whole committed history for each
    /// one, so on a 23,683-blob store a single query ran past 44 minutes with no
    /// vector frame anywhere in the profile.
    ///
    /// The assertion is on COUNTS, not on elapsed time. An authority open is a
    /// full recovery and a replay walks all of history, so both cost whatever the
    /// store is worth; only their number is the query path's own property, and it
    /// is the one that has to stay flat as the store grows. A timing assertion on
    /// a tiny fixture would pass just as readily with the defect present.
    ///
    /// The second arm is the falsification. The one-shot entry point holds
    /// authority for exactly one read, which is the shape the whole projection
    /// had before this fix, and it must visibly regress the open count on the
    /// same fixture. Without it this test could be passing because the fixture is
    /// cheap rather than because the query path changed. Only the OPEN count is
    /// observable on that arm: it builds its session internally, so its replay
    /// count is unreachable from here and is deliberately not claimed.
    #[test]
    fn a_retrieval_page_derives_repository_authority_once() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());
        let blob_store = kin_blobs::BlobStore::new(kin_dir.join("objects")).unwrap();

        // A page of distinct entities in distinct files, all committed by one
        // change, which is the ordinary shape of a retrieval result set.
        const PAGE: usize = 6;
        let mut store = EmptyStore::default();
        let mut page = Vec::with_capacity(PAGE);
        for index in 0..PAGE {
            let content = format!("export function hit{index}() {{ return {index}; }}\n");
            let hash = blob_store.write(content.as_bytes()).unwrap();
            let file_id = FilePathId::new(format!("src/hit{index}.ts"));
            store.file_hashes.insert(file_id.clone(), hash);
            let entity = whole_file_entity(&file_id, &content, Some(hash));
            store.entities_by_id.insert(entity.id, entity.clone());
            page.push(entity);
        }
        install_empty_store_exact_tree(&mut store, dir.path());
        let authority = test_repository_authority(dir.path());

        // Opens on THIS thread, not process-wide. The global counter is the
        // honest process total, but a delta taken across a section of one test
        // is not that test's own number in a parallel binary. This assertion
        // used to be sound only because every kin-mcp test that can open
        // authority happens to hold `ENV_MUTEX`, which is a property of the
        // whole binary that nothing enforces; the lock below is still needed for
        // `KIN_SOURCE_ROOT`, but the count no longer depends on it.
        let opens = common::repository_authority_opens_on_this_thread;

        // Held arm: one session serves the whole page.
        let held = HeldSourceAuthority::new(&store, Some(&authority));
        let before_held = opens();
        for (index, entity) in page.iter().enumerate() {
            let snippet =
                read_bounded_entity_snippet_held(&held, entity, EntitySourceScope::WorkspaceHead)
                    .expect("every fixture entity has coherent graph-owned source")
                    .expect("every fixture entity has source coordinates");
            assert!(
                snippet.contains(&format!("hit{index}")),
                "hit {index} must serve its own body, not another entity's: {snippet}"
            );
        }
        let held_opens = opens() - before_held;
        assert_eq!(
            held_opens, 1,
            "a {PAGE}-hit page must open repository authority once; opening per hit is what \
             multiplied a full authority recovery by the page size"
        );
        // The invariant, stated exactly. Every hit resolves against the SAME base
        // change, so the committed state is ONE replay however long the page is.
        // The introducing TREE is keyed by `introduced_by`, which varies per
        // entity, so it is one replay per DISTINCT introducing change -- not one
        // per hit, and not a constant. This fixture commits all six entities in
        // one change, so D = 1 and the total is 2; that 2 is a property of the
        // fixture, and only the formula below is the property of the fix.
        let distinct_introducing_changes = 1;
        assert_eq!(
            held.replays_performed(),
            1 + distinct_introducing_changes,
            "the page must replay committed state once and the introducing tree once per \
             distinct introducing change, not either of them once per hit"
        );

        // Falsification: the pre-fix shape, one session per read, on this exact
        // fixture. If the counts above were an artifact of the fixture rather
        // than of the fix, these would match them.
        let before_one_shot = opens();
        for entity in &page {
            read_bounded_entity_snippet(
                &store,
                entity,
                Some(&authority),
                EntitySourceScope::WorkspaceHead,
            )
            .expect("the one-shot projection reads the same fixture")
            .expect("every fixture entity has source coordinates");
        }
        assert_eq!(
            opens() - before_one_shot,
            PAGE as u64,
            "the one-shot projection must still open once per read; if it does not, this test \
             cannot tell a held session apart from the defect it was written to catch"
        );
    }

    /// An entity the current workspace does not contain is history, not a gap.
    ///
    /// FIR-1935. The graph ingests whole reachable history, so it carries
    /// entities for files a repository deleted or renamed -- on the first
    /// repository this was tried against, `httpx/models.py`, deleted in 2020.
    /// The body projection reported that absence as an authority gap, and every
    /// surface projecting many entities turned one such candidate into a failed
    /// request.
    ///
    /// Three entities, and the middle one is the fix:
    /// - a live entity still projects its body, so the fix did not cost reads,
    /// - an entity whose path the workspace tree does not carry is classified as
    ///   history, which is what lets a page skip it,
    /// - a path the tree DOES carry whose bytes the graph cannot produce is
    ///   still a hard failure. Without that arm this test would pass just as
    ///   readily against a blanket swallow, which is the fix a hurry would have
    ///   written and which would have hidden every real projection break.
    #[test]
    fn an_entity_absent_at_the_current_generation_is_history_not_an_authority_gap() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_trace_source_registry();
        let dir = tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());
        let blob_store = kin_blobs::BlobStore::new(kin_dir.join("objects")).unwrap();

        let mut store = EmptyStore::default();

        // Live: in the workspace tree at the current generation.
        let live_content = "export function live() { return 1; }\n";
        let live_hash = blob_store.write(live_content.as_bytes()).unwrap();
        let live_file = FilePathId::new("src/live.ts");
        store.file_hashes.insert(live_file.clone(), live_hash);
        let live = whole_file_entity(&live_file, live_content, Some(live_hash));
        store.insert_test_entity(live.clone());

        // Historical: the graph holds the entity AND its bytes, and the current
        // workspace tree does not carry the path because history deleted it.
        // Every coordinate the projection needs is present except the one thing
        // that is legitimately gone, so nothing but the deletion can explain a
        // failure here.
        //
        // It is admitted to the store AFTER the tree is installed, and that
        // ordering is forced rather than cosmetic: admission refuses a
        // transaction that "leaves entity ... on repository path ... absent from
        // the staged tree", so this state cannot be minted inside one change at
        // all. It arises the way it arose on `httpx` -- from history, across
        // changes -- and the runtime condition the projection actually meets is
        // an entity in hand whose path the CURRENT tree lacks. That is what this
        // reproduces.
        let deleted_content = "export function deleted() { return 2; }\n";
        let deleted_hash = blob_store.write(deleted_content.as_bytes()).unwrap();
        let deleted_file = FilePathId::new("src/deleted.ts");
        let deleted = whole_file_entity(&deleted_file, deleted_content, Some(deleted_hash));

        install_empty_store_exact_tree(&mut store, dir.path());

        // Unservable: a path the workspace tree DOES carry, whose recorded span
        // was derived from other bytes. The graph owes an answer here and cannot
        // give a sound one, which is the genuine authority gap this fix must not
        // swallow.
        //
        // This is the gap the fixture can actually express. Two others were
        // tried first and are refused by admission itself, which is worth
        // recording: a tree entry whose blob is absent from the CAS is rejected
        // ("absent from immutable source CAS"), and a change leaving an entity
        // on a path absent from its staged tree is rejected too. The store will
        // not hold those shapes, so they cannot be reproduced here.
        let mut unservable = live.clone();
        unservable.id = EntityId::new();
        unservable.metadata.extra.insert(
            "blob_hash".into(),
            serde_json::Value::String(Hash256::from_bytes([42; 32]).to_string()),
        );
        store.insert_test_entity(deleted.clone());
        let authority = test_repository_authority(dir.path());
        let held = HeldSourceAuthority::new(&store, Some(&authority));

        let snippet =
            read_bounded_entity_snippet_held(&held, &live, EntitySourceScope::WorkspaceHead)
                .expect("a live entity must still project its body")
                .expect("the live entity has source coordinates");
        assert!(
            snippet.contains("return 1"),
            "the live entity must serve its own body: {snippet}"
        );

        let error =
            read_bounded_entity_snippet_held(&held, &deleted, EntitySourceScope::WorkspaceHead)
                .expect_err("the current workspace holds no body for a deleted file");
        assert!(
            common::is_absent_at_generation(&error),
            "a file history deleted must classify as history, not as an authority gap: {error}"
        );
        assert!(
            error.to_string().contains("src/deleted.ts"),
            "the message must name the path that is gone: {error}"
        );

        let error =
            read_bounded_entity_snippet_held(&held, &unservable, EntitySourceScope::WorkspaceHead)
                .expect_err("bytes the graph promised and cannot serve must fail the read");
        assert!(
            !common::is_absent_at_generation(&error),
            "a path the tree carries whose blob is unreadable is a real gap and must stay fatal; \
             classifying it as history is how this fix would become a blanket swallow: {error}"
        );
    }

    /// One caller deleted by history does not cost the whole reference set.
    ///
    /// The page-level half of FIR-1935, on the multi-entity surface this crate
    /// owns: `find_references` projects a body per referencing entity, so before
    /// the fix a single historical caller propagated its error out of the loop
    /// and the call returned nothing at all. The daemon's `semantic_locate` had
    /// the identical shape and is what the ticket was filed on.
    ///
    /// The assertion that matters is that the LIVE callers come back. A test
    /// that only asserted the call no longer errors would also pass if the fix
    /// dropped every row.
    #[test]
    fn a_reference_set_survives_a_caller_whose_file_history_deleted() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        reset_trace_source_registry();
        let dir = tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());
        let blob_store = kin_blobs::BlobStore::new(kin_dir.join("objects")).unwrap();

        const LIVE_CALLERS: usize = 3;
        let mut store = EmptyStore::default();
        let install = |store: &mut EmptyStore, name: &str| -> Entity {
            let content = format!("export function {name}() {{ return \"{name}\"; }}\n");
            let hash = blob_store.write(content.as_bytes()).unwrap();
            let file_id = FilePathId::new(format!("src/{name}.ts"));
            store.file_hashes.insert(file_id.clone(), hash);
            let entity = whole_file_entity(&file_id, &content, Some(hash));
            store.insert_test_entity(entity.clone());
            entity
        };
        let target = install(&mut store, "target");
        let live: Vec<Entity> = (0..LIVE_CALLERS)
            .map(|index| install(&mut store, &format!("caller{index}")))
            .collect();
        for caller in &live {
            store.insert_test_calls_relation(caller, &target);
        }
        install_empty_store_exact_tree(&mut store, dir.path());

        // The deleted caller joins the graph AFTER the tree is installed: its
        // path is absent from the current workspace, which admission forbids
        // within a single change and which history produces across changes. Its
        // bytes are written, so only the deletion can explain a failed read.
        let deleted_content = "export function deleted_caller() { return 0; }\n";
        let deleted_hash = blob_store.write(deleted_content.as_bytes()).unwrap();
        let deleted_file = FilePathId::new("src/deleted_caller.ts");
        let deleted = whole_file_entity(&deleted_file, deleted_content, Some(deleted_hash));
        store.insert_test_entity(deleted.clone());
        store.insert_test_calls_relation(&deleted, &target);

        let authority = test_repository_authority(dir.path());

        let rows = collect_graph_reference_rows(
            &store,
            &target.id,
            &[RelationKind::Calls],
            Some(&authority),
        )
        .expect("one caller deleted by history must not fail the whole reference set");

        assert_eq!(
            rows.len(),
            LIVE_CALLERS,
            "every live caller must be reported and the deleted one must not be: {rows:?}"
        );
        assert!(
            rows.iter().all(|row| row.snippet.is_some()),
            "every reported caller must still carry its graph-owned body: {rows:?}"
        );
        // Keyed on file_path, NOT on name: every fixture entity is named
        // "alpha", so a name-based assertion here could not fail and would be
        // no evidence at all.
        assert!(
            !rows
                .iter()
                .any(|row| row.file_path.as_deref() == Some("src/deleted_caller.ts")),
            "a caller whose file the current workspace does not contain is not a caller today: \
             {rows:?}"
        );
        assert!(
            rows.iter()
                .any(|row| row.file_path.as_deref() == Some("src/caller0.ts")),
            "the live callers must be the rows that came back: {rows:?}"
        );
    }

    /// `find_references` derives repository authority ONCE, not once per caller.
    ///
    /// `collect_graph_reference_rows` projects a bounded body per REFERENCING
    /// entity, so it has the same multi-entity shape as a retrieval page and had
    /// the same defect: a full authority recovery and a whole-history replay per
    /// caller found. It was missed when FIR-1897 was first scoped because the
    /// surface reads relations rather than running retrieval, and the ticket was
    /// written about `semantic_locate`.
    ///
    /// Same counting discipline as the page test above, and the same second arm
    /// so a cheap fixture cannot be mistaken for a fixed one.
    #[test]
    fn find_references_derives_repository_authority_once() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());
        let blob_store = kin_blobs::BlobStore::new(kin_dir.join("objects")).unwrap();

        // One target plus several callers, each in its own file, which is what a
        // real `find_references` answer looks like.
        const CALLERS: usize = 5;
        let mut store = EmptyStore::default();
        let install = |store: &mut EmptyStore, name: &str| -> Entity {
            let content = format!("export function {name}() {{ return \"{name}\"; }}\n");
            let hash = blob_store.write(content.as_bytes()).unwrap();
            let file_id = FilePathId::new(format!("src/{name}.ts"));
            store.file_hashes.insert(file_id.clone(), hash);
            let entity = whole_file_entity(&file_id, &content, Some(hash));
            store.insert_test_entity(entity.clone());
            entity
        };
        let target = install(&mut store, "target");
        let callers: Vec<Entity> = (0..CALLERS)
            .map(|index| install(&mut store, &format!("caller{index}")))
            .collect();
        for caller in &callers {
            store.insert_test_calls_relation(caller, &target);
        }
        install_empty_store_exact_tree(&mut store, dir.path());
        let authority = test_repository_authority(dir.path());

        let opens = common::repository_authority_opens_on_this_thread;

        let before_held = opens();
        let rows = collect_graph_reference_rows(
            &store,
            &target.id,
            &[RelationKind::Calls],
            Some(&authority),
        )
        .expect("every fixture caller has coherent graph-owned source");
        let held_opens = opens() - before_held;

        // Non-vacuity: the bound means nothing unless bodies were actually
        // projected for more than one caller.
        assert_eq!(
            rows.len(),
            CALLERS,
            "every caller must be reported: {rows:?}"
        );
        assert_eq!(
            rows.iter().filter(|row| row.snippet.is_some()).count(),
            CALLERS,
            "every reported caller must carry its graph-owned body: {rows:?}"
        );
        assert_eq!(
            held_opens, 1,
            "a {CALLERS}-caller reference set must open repository authority once; opening per \
             caller is the FIR-1897 shape on the `find_references` surface"
        );

        // Falsification: the pre-fix shape, one session per row, same fixture.
        let before_one_shot = opens();
        for caller in &callers {
            read_bounded_entity_snippet(
                &store,
                caller,
                Some(&authority),
                EntitySourceScope::WorkspaceHead,
            )
            .expect("the one-shot projection reads the same fixture")
            .expect("every fixture caller has source coordinates");
        }
        assert_eq!(
            opens() - before_one_shot,
            CALLERS as u64,
            "the one-shot projection must still open once per read; if it does not, this test \
             cannot tell a held session apart from the defect it was written to catch"
        );
    }

    /// True when committed history records no active revision for `entity`, which
    /// is the condition that skips the artifact-identity binding.
    fn committed_introducing_change_is_absent(store: &EmptyStore, entity: &Entity) -> bool {
        let authority_change = store
            .repository_refs
            .first()
            .map(|(_, change_id)| *change_id);
        let Some(change_id) = authority_change else {
            return true;
        };
        store
            .resolve_graph_at(&change_id)
            .map(|graph| {
                !graph
                    .entity_revisions
                    .get(&entity.id)
                    .is_some_and(|revisions| {
                        revisions.iter().any(|revision| revision.ended_by.is_none())
                    })
            })
            .unwrap_or(true)
    }

    #[test]
    fn test_graph_blob_miss_reports_gap_without_disk_fallback() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());

        let file_path = "src/lib.rs";
        let full_path = dir.path().join(file_path);
        fs::create_dir_all(full_path.parent().unwrap()).unwrap();

        let disk_content = "export function test_disk() { return 99; }";
        fs::write(&full_path, disk_content).unwrap();

        let file_id = FilePathId::new(file_path);
        let graph_content = "export function test_disk() { return 42; }";
        let graph_hash = kin_blobs::digest(graph_content.as_bytes());
        let legacy_store =
            kin_blobs::BlobStore::new(dir.path().join(".kin").join("objects")).unwrap();
        assert_eq!(
            legacy_store.write(graph_content.as_bytes()).unwrap(),
            graph_hash
        );

        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "test_disk".into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: graph_hash,
                signature_hash: graph_hash,
                behavior_hash: graph_hash,
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id.clone(),
                start_byte: 0,
                end_byte: disk_content.len(),
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: disk_content.len() as u32,
            }),
            signature: "export function test_disk()".into(),
            visibility: Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(entity.id, entity.clone());
        store.file_hashes.insert(file_id, graph_hash);
        install_empty_store_exact_tree(&mut store, dir.path());
        let authority = test_repository_authority(dir.path());
        fs::remove_file(test_source_blob_path(dir.path(), graph_hash)).unwrap();

        let before_misses = GRAPH_MISS_COUNT.load(std::sync::atomic::Ordering::SeqCst);

        let error = entity_response_json(&store, &entity, Some(&authority))
            .expect_err("a missing graph blob must fail the MCP read loudly");
        let message = error.to_string();
        assert!(
            message.contains("graph authority gap")
                && message.contains("absent from immutable source CAS"),
            "unexpected graph-miss error: {message}"
        );
        assert!(!message.contains(disk_content));

        let after_misses = GRAPH_MISS_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        assert!(after_misses >= before_misses + 1);
    }

    #[test]
    fn test_hash_mismatch_reports_gap_without_disk_fallback() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());

        let objects_dir = kin_dir.join("objects");
        let blob_store = kin_blobs::BlobStore::new(objects_dir).unwrap();

        let content = "export function test_mismatch() { return 42; }";
        let correct_hash = kin_blobs::digest(content.as_bytes());

        assert_eq!(blob_store.write(content.as_bytes()).unwrap(), correct_hash);

        // The correct content exists on disk, but the graph blob is corrupt
        let file_path = "src/lib.rs";
        let full_path = dir.path().join(file_path);
        fs::create_dir_all(full_path.parent().unwrap()).unwrap();
        fs::write(&full_path, content).unwrap();

        let file_id = FilePathId::new(file_path);
        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "test_mismatch".into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: correct_hash,
                signature_hash: correct_hash,
                behavior_hash: correct_hash,
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id.clone(),
                start_byte: 0,
                end_byte: content.len(),
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: content.len() as u32,
            }),
            signature: "export function test_mismatch()".into(),
            visibility: Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(entity.id, entity.clone());
        store.file_hashes.insert(file_id, correct_hash);
        install_empty_store_exact_tree(&mut store, dir.path());
        let authority = test_repository_authority(dir.path());
        fs::write(
            test_source_blob_path(dir.path(), correct_hash),
            b"corrupt content",
        )
        .unwrap();

        let before_misses = GRAPH_MISS_COUNT.load(std::sync::atomic::Ordering::SeqCst);

        let error = entity_response_json(&store, &entity, Some(&authority))
            .expect_err("a corrupt graph blob must fail the MCP read loudly");
        let message = error.to_string();
        assert!(
            message.contains("graph authority gap")
                && message.contains("immutable source blob digest mismatch"),
            "unexpected corrupt-blob error: {message}"
        );
        assert!(!message.contains(content));

        let after_misses = GRAPH_MISS_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        assert!(after_misses >= before_misses + 1);
    }

    // ── Governance handlers: release_check + security_scan ──────────────────

    fn gov_change(sequence: u8, parent: Option<SemanticChangeId>, author: &str) -> SemanticChange {
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            parents: parent.into_iter().collect(),
            timestamp: kin_model::timestamp::Timestamp::now(),
            author: AuthorId::new(author),
            message: format!("change {sequence}"),
            entity_deltas: vec![],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: parent.is_none().then(|| {
                kin_model::AdmissionPolicyDelta::initialize(
                    kin_model::SharedAdmissionPolicy::empty(0),
                )
            }),
            external_reference_deltas: Vec::new(),
        };
        change.id = kin_model::compute_semantic_change_id(&change).unwrap();
        change
    }

    fn gov_approver_id() -> kin_model::provenance::ActorId {
        kin_model::provenance::ActorId::from_hash(Hash256::from_bytes([0xa5; 32]))
    }

    fn register_gov_human_approver(store: &mut EmptyStore) {
        let actor = kin_model::provenance::Actor {
            actor_id: gov_approver_id(),
            kind: kin_model::provenance::ActorKind::Human,
            display_name: "reviewer".into(),
            external_refs: vec![],
        };
        store.actors_by_id.insert(actor.actor_id, actor);
    }

    fn add_gov_root(store: &mut EmptyStore) -> SemanticChangeId {
        let root = gov_change(0, None, "kin");
        let id = root.id;
        store.changes_by_id.insert(root.id, root);
        id
    }

    fn gov_approval(
        change: &SemanticChange,
        decision: kin_model::provenance::ApprovalDecision,
    ) -> kin_model::provenance::Approval {
        kin_model::provenance::Approval {
            approval_id: kin_model::provenance::ApprovalId::new(),
            change_id: change.id,
            approver: gov_approver_id(),
            decision,
            reason: "test".into(),
            timestamp: kin_model::timestamp::Timestamp::now(),
        }
    }

    fn gov_entity(name: &str, kind: EntityKind, visibility: Visibility) -> Entity {
        use kin_model::entity::{
            EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        };
        Entity {
            id: EntityId::new(),
            kind,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {}()", name),
            visibility,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    pub(super) fn release_check_result(
        store: &EmptyStore,
        args: &HashMap<String, serde_json::Value>,
    ) -> crate::error::Result<ToolCallResult> {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tempdir().unwrap();
        initialize_release_test_repository(dir.path(), store);
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        let authority = RequestRepositoryAuthority::pinned(
            kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout).unwrap(),
        );
        verification::handle_release_check(args, store, Some(&authority))
    }

    pub(super) fn with_empty_test_repository<T>(
        call: impl FnOnce(&RequestRepositoryAuthority) -> T,
    ) -> T {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tempdir().unwrap();
        let init = kin_core::init(dir.path()).unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());
        let authority = RequestRepositoryAuthority::pinned(
            kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap(),
        );
        call(&authority)
    }

    async fn call_release_check_with_args(
        store: &EmptyStore,
        args: HashMap<String, serde_json::Value>,
    ) -> serde_json::Value {
        let result = release_check_result(store, &args).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        serde_json::from_str(&text).unwrap()
    }

    async fn call_release_check(store: &EmptyStore, require_approval: bool) -> serde_json::Value {
        call_release_check_with_args(
            store,
            HashMap::from([(
                "require_approval".into(),
                serde_json::json!(require_approval),
            )]),
        )
        .await
    }

    #[tokio::test]
    async fn release_check_force_overrides_baseline_but_not_strict_source_proof() {
        let mut store = EmptyStore::default();
        let entity = gov_entity("unbound", EntityKind::Function, Visibility::Public);
        store.entities_by_id.insert(entity.id, entity.clone());
        let mut root = gov_change(0, None, "kin");
        root.entity_deltas = vec![kin_model::EntityDelta::Added { new: entity }];
        root.id = kin_model::compute_semantic_change_id(&root).unwrap();
        store.changes_by_id.insert(root.id, root.clone());
        store
            .repository_refs
            .push((kin_model::RefName::branch(b"main").unwrap(), root.id));

        let baseline = call_release_check_with_args(&store, HashMap::new()).await;
        assert_eq!(baseline["pass"], false);
        assert_eq!(baseline["coverage"]["missing_proof_count"], 1);

        let forced = call_release_check_with_args(
            &store,
            HashMap::from([("force".into(), serde_json::json!(true))]),
        )
        .await;
        assert_eq!(forced["pass"], true);

        let strict = call_release_check_with_args(
            &store,
            HashMap::from([
                ("force".into(), serde_json::json!(true)),
                ("require_proof".into(), serde_json::json!(true)),
            ]),
        )
        .await;
        assert_eq!(strict["pass"], false);
        assert!(strict["blockers"][0]
            .as_str()
            .unwrap()
            .contains("immutable source-bound"));
    }

    #[tokio::test]
    async fn release_check_binds_source_count_and_branch_cas_not_ambient_entities() {
        let mut store = EmptyStore::default();
        let source_entity = gov_entity("source", EntityKind::Function, Visibility::Public);
        let ambient_entity = gov_entity("ambient", EntityKind::Function, Visibility::Public);
        store
            .entities_by_id
            .insert(source_entity.id, source_entity.clone());
        store
            .entities_by_id
            .insert(ambient_entity.id, ambient_entity);

        let mut source = gov_change(0, None, "kin");
        source.entity_deltas = vec![kin_model::EntityDelta::Added { new: source_entity }];
        source.id = kin_model::compute_semantic_change_id(&source).unwrap();
        let advanced = gov_change(1, Some(source.id), "human");
        store.changes_by_id.insert(source.id, source.clone());
        store.changes_by_id.insert(advanced.id, advanced.clone());
        store
            .repository_refs
            .push((kin_model::RefName::branch(b"main").unwrap(), advanced.id));

        let response = call_release_check_with_args(
            &store,
            HashMap::from([
                ("force".into(), serde_json::json!(true)),
                (
                    "source_change_id".into(),
                    serde_json::json!(source.id.to_string()),
                ),
                ("expected_entity_count".into(), serde_json::json!(2)),
            ]),
        )
        .await;

        assert_eq!(response["pass"], false);
        assert_eq!(response["source_entity_count"], 1);
        let blockers = response["blockers"].as_array().unwrap();
        assert!(blockers.iter().any(|blocker| blocker
            .as_str()
            .unwrap()
            .contains("branch refs/heads/main moved")));
        assert!(blockers.iter().any(|blocker| blocker
            .as_str()
            .unwrap()
            .contains("expected entity count 2")));
    }

    #[tokio::test]
    async fn release_check_requires_source_authority_when_no_branch_exists() {
        let store = EmptyStore::default();
        let error = release_check_result(&store, &HashMap::new()).unwrap_err();
        assert!(matches!(error, crate::error::McpError::InvalidParams(_)));
        assert!(error.to_string().contains("requires branch"));
    }

    #[tokio::test]
    async fn release_check_blocks_on_unapproved_agent_change() {
        // The false-green this fix targets: an agent change with NO approval must
        // fail the gate. (Previously it passed because any audit event sufficed.)
        let mut store = EmptyStore::default();
        let root = add_gov_root(&mut store);
        let head = gov_change(1, Some(root), "claude-agent");
        store.changes_by_id.insert(head.id, head.clone());
        store
            .repository_refs
            .push((kin_model::RefName::branch(b"main").unwrap(), head.id));

        let response = call_release_check(&store, true).await;
        assert_eq!(response["pass"], false);
        let blockers = response["blockers"].as_array().unwrap();
        assert!(
            blockers
                .iter()
                .any(|b| b.as_str().unwrap().contains("lack human approval")),
            "blocker list must name the unapproved non-root change: {blockers:?}"
        );
    }

    #[tokio::test]
    async fn release_check_passes_when_agent_change_approved() {
        let mut store = EmptyStore::default();
        let root = add_gov_root(&mut store);
        register_gov_human_approver(&mut store);
        let head = gov_change(1, Some(root), "claude-agent");
        store.changes_by_id.insert(head.id, head.clone());
        store.approvals_by_change.insert(
            head.id,
            vec![gov_approval(
                &head,
                kin_model::provenance::ApprovalDecision::Approved,
            )],
        );
        store
            .repository_refs
            .push((kin_model::RefName::branch(b"main").unwrap(), head.id));

        let response = call_release_check(&store, true).await;
        assert_eq!(response["pass"], true, "approved agent change must pass");
    }

    #[tokio::test]
    async fn release_check_blocks_on_approved_then_mutated() {
        // c1 (agent, approved) <- c2 (agent, unapproved, HEAD): the later
        // unapproved mutation must block even though an earlier change is approved.
        let mut store = EmptyStore::default();
        let root = add_gov_root(&mut store);
        register_gov_human_approver(&mut store);
        let c1 = gov_change(1, Some(root), "agent-a");
        let c2 = gov_change(2, Some(c1.id), "agent-a");
        store.changes_by_id.insert(c1.id, c1.clone());
        store.changes_by_id.insert(c2.id, c2.clone());
        store.approvals_by_change.insert(
            c1.id,
            vec![gov_approval(
                &c1,
                kin_model::provenance::ApprovalDecision::Approved,
            )],
        );
        store
            .repository_refs
            .push((kin_model::RefName::branch(b"main").unwrap(), c2.id));

        let response = call_release_check(&store, true).await;
        assert_eq!(response["pass"], false);

        // Approving the head clears the gate.
        store.approvals_by_change.insert(
            c2.id,
            vec![gov_approval(
                &c2,
                kin_model::provenance::ApprovalDecision::Approved,
            )],
        );
        let response = call_release_check(&store, true).await;
        assert_eq!(response["pass"], true);
    }

    #[tokio::test]
    async fn release_check_display_name_cannot_bypass_approval() {
        let mut store = EmptyStore::default();
        let root = add_gov_root(&mut store);
        let head = gov_change(1, Some(root), "alice");
        store.changes_by_id.insert(head.id, head.clone());
        store
            .repository_refs
            .push((kin_model::RefName::branch(b"main").unwrap(), head.id));

        let response = call_release_check(&store, true).await;
        assert_eq!(
            response["pass"], false,
            "an unauthenticated author display name must not bypass approval"
        );
    }

    #[tokio::test]
    async fn release_check_approval_disabled_skips_gate() {
        // With require_approval=false, an unapproved agent change must NOT block.
        let mut store = EmptyStore::default();
        let root = add_gov_root(&mut store);
        let head = gov_change(1, Some(root), "claude-agent");
        store.changes_by_id.insert(head.id, head.clone());
        store
            .repository_refs
            .push((kin_model::RefName::branch(b"main").unwrap(), head.id));

        let response = call_release_check(&store, false).await;
        assert_eq!(response["pass"], true);
    }

    #[tokio::test]
    async fn security_scan_surfaces_untested_api_endpoint() {
        let mut store = EmptyStore::default();
        let api = gov_entity("login", EntityKind::ApiEndpoint, Visibility::Public);
        store.entities_by_id.insert(api.id, api);

        let sessions = SessionRegistry::new();
        let args = HashMap::new();
        let result = handle_tool_call(
            "kin_security_scan",
            &args,
            &store,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
            None,
        )
        .await
        .unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert!(response["finding_count"].as_u64().unwrap() >= 1);
        assert_eq!(response["severity_counts"]["high"], 1);
        let findings = response["findings"].as_array().unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f["finding_type"] == "untested-api" && f["severity"] == "high"),
            "untested API endpoint must appear as a high finding: {findings:?}"
        );
    }

    #[tokio::test]
    async fn security_scan_empty_graph_has_no_findings() {
        let store = EmptyStore::default();
        let sessions = SessionRegistry::new();
        let args = HashMap::new();
        let result = handle_tool_call(
            "kin_security_scan",
            &args,
            &store,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
            None,
        )
        .await
        .unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["finding_count"], 0);
    }

    #[tokio::test]
    async fn release_check_blockers_are_byte_stable() {
        // Two branches, each headed by a distinct unapproved agent change. The
        // blockers string concatenates change ids in the order branches are walked,
        // so the sort is what makes the output stable. Two identical-state calls
        // must produce byte-identical blockers.
        let mut store = EmptyStore::default();
        let root = add_gov_root(&mut store);
        let c_a = gov_change(0xAA, Some(root), "agent-a");
        let c_b = gov_change(0xBB, Some(root), "agent-b");
        store.changes_by_id.insert(c_a.id, c_a.clone());
        store.changes_by_id.insert(c_b.id, c_b.clone());
        store
            .repository_refs
            .push((kin_model::RefName::branch(b"feature").unwrap(), c_a.id));
        store
            .repository_refs
            .push((kin_model::RefName::branch(b"main").unwrap(), c_b.id));

        let first = call_release_check(&store, true).await;
        let second = call_release_check(&store, true).await;
        assert_eq!(first["pass"], false);
        assert_eq!(
            first["blockers"], second["blockers"],
            "blockers must be deterministic across identical-state runs"
        );
    }
}
