// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Versioned snapshot migration system.
//!
//! Each time the `Entity` or `GraphSnapshot` schema changes, bump
//! `CURRENT_VERSION` and add a `migrate_vN_to_vN1` step. Existing
//! snapshots auto-migrate on first load.

use crate::error::KinDbError;
use crate::storage::format::{GraphSnapshot, GraphSnapshotV4Legacy};
use kin_model::EntityRole;

/// Migrate a raw MessagePack snapshot body from `from_version` to
/// `current_version` by applying each step function in sequence.
pub fn migrate(
    raw_body: &[u8],
    from_version: u32,
    current_version: u32,
) -> Result<Vec<u8>, KinDbError> {
    let mut data = raw_body.to_vec();
    let mut version = from_version;

    while version < current_version {
        data = match version {
            5 => migrate_v5_to_v6(&data)?,
            _ => {
                return Err(KinDbError::StorageError(format!(
                    "no migration path from snapshot version {version}"
                )));
            }
        };
        version += 1;
    }

    Ok(data)
}

/// Classify a file path into an [`EntityRole`].
///
/// Rules:
/// - `test/`, `tests/`, `_test.`, `test_` → Test
/// - `cextern/`, `vendor/`, `extern/` → External
/// - Everything else → Source
pub fn classify_file_role(path: &str) -> EntityRole {
    let lower = path.to_ascii_lowercase();

    // Test paths
    if lower.starts_with("test/")
        || lower.starts_with("tests/")
        || lower.contains("/test/")
        || lower.contains("/tests/")
        || lower.contains("_test.")
        || lower.contains("/test_")
        || lower.starts_with("test_")
    {
        return EntityRole::Test;
    }

    // External / vendored paths
    if lower.starts_with("cextern/")
        || lower.starts_with("vendor/")
        || lower.starts_with("extern/")
        || lower.contains("/cextern/")
        || lower.contains("/vendor/")
        || lower.contains("/extern/")
    {
        return EntityRole::External;
    }

    EntityRole::Source
}

/// Migrate v5 → v6: convert legacy EntityId relation endpoints to
/// GraphNodeId and classify entity roles by file_origin path.
///
/// v5 snapshots store `Relation.src` and `Relation.dst` as bare
/// `EntityId` values.  v6 wraps them in `GraphNodeId::Entity(…)`.
/// v5 also has no `role` field on entities — `#[serde(default)]`
/// fills it as `Source`, then we reclassify by file path.
fn migrate_v5_to_v6(body: &[u8]) -> Result<Vec<u8>, KinDbError> {
    // Deserialize using the V4 legacy layout which has
    // LegacyEntityRelation (src/dst as bare EntityId).
    // The v5 on-disk relation format is identical to v4.
    let legacy: GraphSnapshotV4Legacy = rmp_serde::from_slice(body).map_err(|e| {
        KinDbError::StorageError(format!("v5→v6 migration: deserialization failed: {e}"))
    })?;

    // Convert to current layout — this wraps relation src/dst in
    // GraphNodeId::Entity(…) via From<LegacyEntityRelation>.
    let mut snapshot: GraphSnapshot = legacy.into();

    // Classify roles based on file_origin
    for entity in snapshot.entities.values_mut() {
        if let Some(ref file_origin) = entity.file_origin {
            entity.role = classify_file_role(&file_origin.0);
        }
        // Entities without file_origin keep the default (Source)
    }

    // Update the version stored inside the snapshot
    snapshot.version = 6;

    rmp_serde::to_vec(&snapshot).map_err(|e| {
        KinDbError::StorageError(format!("v5→v6 migration: re-serialization failed: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::format::LegacyEntityRelation;
    use kin_model::*;
    use sha2::{Digest, Sha256};

    fn make_entity(name: &str, file_path: Option<&str>) -> Entity {
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
                stability_score: 1.0,
            },
            file_origin: file_path.map(FilePathId::new),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source, // v5 default — no role stored
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn make_legacy_relation(src: EntityId, dst: EntityId) -> LegacyEntityRelation {
        LegacyEntityRelation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src,
            dst,
            confidence: 0.9,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
        }
    }

    /// Build a v5 snapshot body (MessagePack) using the legacy format
    /// (bare EntityId in relations, no role field serialized).
    fn build_v5_body(entities: Vec<Entity>) -> Vec<u8> {
        build_v5_body_with_relations(entities, vec![])
    }

    fn build_v5_body_with_relations(
        entities: Vec<Entity>,
        relations: Vec<LegacyEntityRelation>,
    ) -> Vec<u8> {
        let snap = GraphSnapshotV4Legacy {
            version: 5,
            entities: entities.into_iter().map(|e| (e.id, e)).collect(),
            relations: relations.into_iter().map(|r| (r.id, r)).collect(),
            outgoing: Default::default(),
            incoming: Default::default(),
            changes: Default::default(),
            change_children: Default::default(),
            branches: Default::default(),
            work_items: Default::default(),
            annotations: Default::default(),
            work_links: Default::default(),
            reviews: Default::default(),
            review_decisions: Default::default(),
            review_notes: Default::default(),
            review_discussions: Default::default(),
            review_assignments: Default::default(),
            test_cases: Default::default(),
            assertions: Default::default(),
            verification_runs: Default::default(),
            test_covers_entity: Default::default(),
            test_covers_contract: Default::default(),
            test_verifies_work: Default::default(),
            run_proves_entity: Default::default(),
            run_proves_work: Default::default(),
            mock_hints: Default::default(),
            contracts: Default::default(),
            actors: Default::default(),
            delegations: Default::default(),
            approvals: Default::default(),
            audit_events: Default::default(),
            shallow_files: Default::default(),
            file_layouts: Default::default(),
            structured_artifacts: Default::default(),
            opaque_artifacts: Default::default(),
            file_hashes: Default::default(),
            sessions: Default::default(),
            intents: Default::default(),
            downstream_warnings: Default::default(),
        };
        rmp_serde::to_vec(&snap).unwrap()
    }

    /// Build complete v5 on-disk bytes (header + body + checksum).
    fn build_v5_bytes(entities: Vec<Entity>) -> Vec<u8> {
        let body = build_v5_body(entities);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&5u32.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(&Sha256::digest(&body));
        bytes
    }

    #[test]
    fn classify_source_paths() {
        assert_eq!(classify_file_role("src/main.rs"), EntityRole::Source);
        assert_eq!(classify_file_role("lib/utils.py"), EntityRole::Source);
        assert_eq!(classify_file_role("pkg/core/engine.go"), EntityRole::Source);
    }

    #[test]
    fn classify_test_paths() {
        assert_eq!(classify_file_role("tests/unit.rs"), EntityRole::Test);
        assert_eq!(classify_file_role("test/helper.py"), EntityRole::Test);
        assert_eq!(classify_file_role("src/engine_test.go"), EntityRole::Test);
        assert_eq!(classify_file_role("src/test_engine.py"), EntityRole::Test);
        assert_eq!(
            classify_file_role("pkg/core/tests/integration.rs"),
            EntityRole::Test
        );
    }

    #[test]
    fn classify_external_paths() {
        assert_eq!(
            classify_file_role("vendor/github.com/pkg/errors/errors.go"),
            EntityRole::External
        );
        assert_eq!(
            classify_file_role("cextern/sqlite3/sqlite3.c"),
            EntityRole::External
        );
        assert_eq!(classify_file_role("extern/lib/dep.h"), EntityRole::External);
        assert_eq!(
            classify_file_role("third_party/vendor/lib.rs"),
            EntityRole::External
        );
    }

    #[test]
    fn migrate_v5_to_v6_classifies_roles() {
        let entities = vec![
            make_entity("source_fn", Some("src/main.rs")),
            make_entity("test_fn", Some("tests/test_main.rs")),
            make_entity("extern_fn", Some("vendor/dep/lib.rs")),
            make_entity("no_file", None),
        ];
        let ids: Vec<EntityId> = entities.iter().map(|e| e.id).collect();

        let v5_body = build_v5_body(entities);
        let v6_body = migrate(v5_body.as_slice(), 5, 6).unwrap();

        let snapshot: GraphSnapshot = rmp_serde::from_slice(&v6_body).unwrap();
        assert_eq!(snapshot.version, 6);
        assert_eq!(snapshot.entities[&ids[0]].role, EntityRole::Source);
        assert_eq!(snapshot.entities[&ids[1]].role, EntityRole::Test);
        assert_eq!(snapshot.entities[&ids[2]].role, EntityRole::External);
        assert_eq!(snapshot.entities[&ids[3]].role, EntityRole::Source); // no file → Source
    }

    #[test]
    fn migrate_unknown_version_errors() {
        let result = migrate(&[], 3, 6);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no migration path from snapshot version 3"));
    }

    #[test]
    fn migrate_same_version_is_noop() {
        let body = build_v5_body(vec![make_entity("f", Some("src/f.rs"))]);
        let result = migrate(&body, 5, 5).unwrap();
        assert_eq!(result, body); // unchanged
    }

    #[test]
    fn v5_snapshot_loads_via_from_bytes() {
        let entities = vec![
            make_entity("src_fn", Some("src/lib.rs")),
            make_entity("test_fn", Some("tests/foo.rs")),
        ];
        let src_id = entities[0].id;
        let test_id = entities[1].id;

        let bytes = build_v5_bytes(entities);
        let snapshot = GraphSnapshot::from_bytes(&bytes).unwrap();

        assert_eq!(snapshot.version, 6);
        assert_eq!(snapshot.entities[&src_id].role, EntityRole::Source);
        assert_eq!(snapshot.entities[&test_id].role, EntityRole::Test);
    }

    #[test]
    fn migrate_v5_to_v6_converts_legacy_relations() {
        let e1 = make_entity("caller", Some("src/caller.rs"));
        let e2 = make_entity("callee", Some("src/callee.rs"));
        let rel = make_legacy_relation(e1.id, e2.id);
        let rel_id = rel.id;
        let e1_id = e1.id;
        let e2_id = e2.id;

        let v5_body = build_v5_body_with_relations(vec![e1, e2], vec![rel]);
        let v6_body = migrate(&v5_body, 5, 6).unwrap();

        let snapshot: GraphSnapshot = rmp_serde::from_slice(&v6_body).unwrap();
        assert_eq!(snapshot.version, 6);
        let migrated_rel = &snapshot.relations[&rel_id];
        assert_eq!(migrated_rel.src, GraphNodeId::Entity(e1_id));
        assert_eq!(migrated_rel.dst, GraphNodeId::Entity(e2_id));
        assert_eq!(migrated_rel.kind, RelationKind::Calls);
    }

    #[test]
    fn v6_snapshot_loads_without_migration() {
        // Build a current (v6) snapshot and verify it loads directly
        let mut snap = GraphSnapshot::empty();
        let e = make_entity("direct", Some("src/direct.rs"));
        snap.entities.insert(e.id, e);

        let bytes = snap.to_bytes().unwrap();
        let loaded = GraphSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
        assert_eq!(loaded.entities.len(), 1);
    }
}
