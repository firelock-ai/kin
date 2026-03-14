//! Shared test helpers for integration tests.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kin_db::InMemoryGraph;
use kin_model::{
    change::EntityDelta, AuthorId, BranchName, Entity, EntityId, EntityKind, EntityMetadata,
    FingerprintAlgorithm, Hash256, LanguageId, SemanticChange, SemanticChangeId,
    SemanticFingerprint, Timestamp, Visibility,
};

/// Set up a full Kin repository in a temp directory with a disk-backed graph store.
///
/// Returns (tempdir, graph_store, genesis_id).
pub fn init_kin_repo() -> (tempfile::TempDir, Arc<KuzuGraphStore>, SemanticChangeId) {
    let dir = tempfile::tempdir().unwrap();
    let init_result = kin_core::init(dir.path()).unwrap();

    // Use real disk-backed graph store — kin_core::init() already created
    // the genesis change and main branch in the on-disk KuzuDB, so we just
    // open it and read the genesis ID.
    let graph = Arc::new(KuzuGraphStore::open(&init_result.layout.graph_dir()).unwrap());

    let genesis = kin_core::build_genesis_change();
    let genesis_id = genesis.id;

    (dir, graph, genesis_id)
}

/// Create a test entity with the given name and file origin.
pub fn make_entity(name: &str, file: &str, kind: EntityKind) -> Entity {
    Entity {
        id: EntityId::new(),
        kind,
        name: name.to_string(),
        language: LanguageId::Rust,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0xaa; 32]),
            signature_hash: Hash256::from_bytes([0xbb; 32]),
            behavior_hash: Hash256::from_bytes([0xcc; 32]),
            stability_score: 0.95,
        },
        file_origin: Some(kin_model::FilePathId::new(file)),
        span: None,
        signature: format!("fn {name}()"),
        visibility: Visibility::Public,
        doc_summary: Some(format!("Does {name} things")),
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

/// Create a SemanticChange that adds entities.
pub fn make_change(
    parent: SemanticChangeId,
    entities: Vec<Entity>,
    message: &str,
) -> SemanticChange {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(message.as_bytes());
    hasher.update(uuid::Uuid::new_v4().as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    let id = SemanticChangeId::from_hash(Hash256::from_bytes(bytes));

    SemanticChange {
        id,
        parents: vec![parent],
        timestamp: Timestamp::now(),
        author: AuthorId::new("test"),
        message: message.to_string(),
        entity_deltas: entities.into_iter().map(EntityDelta::Added).collect(),
        relation_deltas: vec![],
        artifact_deltas: vec![],
        projected_files: vec![],
        spec_link: None,
        evidence: vec![],
        risk_summary: None,
        authored_on: Some(BranchName::new("main")),
    }
}

/// Write a Rust source file to a directory.
pub fn write_rust_file(dir: &Path, rel_path: &str, content: &str) -> PathBuf {
    let path = dir.join(rel_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, content).unwrap();
    path
}

/// Write a TypeScript source file to a directory.
pub fn write_ts_file(dir: &Path, rel_path: &str, content: &str) -> PathBuf {
    let path = dir.join(rel_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, content).unwrap();
    path
}
