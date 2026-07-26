// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared test helpers for integration tests.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kin_db::InMemoryGraph;
use kin_model::{
    Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, Hash256,
    LanguageId, SemanticChangeId, SemanticFingerprint, Visibility,
};

/// Set up an isolated graph fixture and temp working directory.
///
/// Repository-v6 authority acceptance creates and reopens a real repository
/// explicitly. Session, review, and verification tests use this helper only
/// for an in-memory semantic graph and must not treat it as repository truth.
pub fn init_kin_repo() -> (tempfile::TempDir, Arc<InMemoryGraph>, SemanticChangeId) {
    let dir = tempfile::tempdir().unwrap();
    let graph = Arc::new(InMemoryGraph::default());
    let fixture_root = SemanticChangeId::from_hash(Hash256::from_bytes([0; 32]));
    (dir, graph, fixture_root)
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
            equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
            stability_score: 0.95,
        },
        file_origin: Some(kin_model::FilePathId::new(file)),
        span: None,
        signature: format!("fn {name}()"),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: Some(format!("Does {name} things")),
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
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
