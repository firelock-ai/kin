// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Fast read-only index for CLI queries.
//!
//! A slim representation of the graph containing only the fields
//! that search/trace/refs/overview need. Serialized with bincode
//! (not serde_json or msgpack) for minimal size and fast deserialization.
//!
//! The full GraphSnapshot is still used for write operations.
//! This index is a read-only acceleration layer.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::error::KinDbError;

/// Compact entity record for index-only queries.
/// Contains just enough to answer search/trace/refs/overview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntity {
    pub name: String,
    pub kind: u8, // EntityKind as u8 for compact serialization
    pub file_path: String,
    pub language: u8, // LanguageId as u8
    pub start_line: u32,
}

/// Compact relation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexRelation {
    pub kind: u8,     // RelationKind as u8
    pub dst_idx: u32, // Index into entities array
    pub confidence: f32,
}

/// The read-only index. Entities are stored in a flat array
/// for cache-friendly access. IDs map to array indices.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReadIndex {
    /// Version marker.
    pub version: u32,
    /// Entity names, kinds, files — indexed by position.
    pub entities: Vec<IndexEntity>,
    /// Entity UUID string → index in entities array.
    pub id_to_idx: HashMap<String, u32>,
    /// Name (lowercased) → list of entity indices.
    pub name_index: HashMap<String, Vec<u32>>,
    /// Outgoing relations per entity (by index).
    pub outgoing: Vec<Vec<IndexRelation>>,
    /// Incoming entity indices per entity (by index).
    pub incoming: Vec<Vec<u32>>,
    /// Kind counts for overview.
    pub kind_counts: HashMap<u8, u32>,
    /// Language counts for overview.
    pub language_counts: HashMap<u8, u32>,
    /// Total entity count.
    pub entity_count: u32,
    /// Total relation count.
    pub relation_count: u32,
}

const INDEX_MAGIC: [u8; 4] = *b"KIDX";
const INDEX_VERSION: u32 = 1;

impl ReadIndex {
    /// Build an index from the full in-memory graph.
    pub fn from_graph(graph: &crate::engine::InMemoryGraph) -> Result<Self, KinDbError> {
        use kin_model::EntityStore;

        let all_entities = graph.list_all_entities()?;
        let entity_count = all_entities.len() as u32;

        let mut entities = Vec::with_capacity(all_entities.len());
        let mut id_to_idx = HashMap::with_capacity(all_entities.len());
        let mut name_index: HashMap<String, Vec<u32>> = HashMap::new();
        let mut kind_counts: HashMap<u8, u32> = HashMap::new();
        let mut language_counts: HashMap<u8, u32> = HashMap::new();

        for (idx, entity) in all_entities.iter().enumerate() {
            let idx = idx as u32;
            let kind = entity.kind as u8;
            let lang = entity.language as u8;
            let file_path = entity
                .file_origin
                .as_ref()
                .map(|f| f.0.clone())
                .unwrap_or_default();
            let start_line = entity.span.as_ref().map(|s| s.start_line).unwrap_or(0);

            entities.push(IndexEntity {
                name: entity.name.clone(),
                kind,
                file_path,
                language: lang,
                start_line,
            });

            id_to_idx.insert(entity.id.to_string(), idx);
            name_index
                .entry(entity.name.to_lowercase())
                .or_default()
                .push(idx);
            *kind_counts.entry(kind).or_insert(0) += 1;
            *language_counts.entry(lang).or_insert(0) += 1;
        }

        // Build outgoing and incoming edge lists from a single batch read
        // (avoids 20K+ per-entity lock acquisitions).
        let mut outgoing = vec![Vec::new(); all_entities.len()];
        let mut incoming = vec![Vec::new(); all_entities.len()];
        let mut relation_count = 0u32;

        let all_edges = graph.list_all_entity_edges();
        for (src_id, kind, dst_id, confidence) in &all_edges {
            let Some(&src_idx) = id_to_idx.get(&src_id.to_string()) else { continue };
            let Some(&dst_idx) = id_to_idx.get(&dst_id.to_string()) else { continue };
            outgoing[src_idx as usize].push(IndexRelation {
                kind: *kind as u8,
                dst_idx,
                confidence: *confidence,
            });
            incoming[dst_idx as usize].push(src_idx);
            relation_count += 1;
        }

        // Deduplicate incoming
        for inc in &mut incoming {
            inc.sort_unstable();
            inc.dedup();
        }

        Ok(ReadIndex {
            version: INDEX_VERSION,
            entities,
            id_to_idx,
            name_index,
            outgoing,
            incoming,
            kind_counts,
            language_counts,
            entity_count,
            relation_count,
        })
    }

    /// Serialize the index to a file.
    ///
    /// Uses the same atomic write pattern as `mmap::atomic_write()`:
    /// write to tmp, fsync file, rename, fsync parent dir.
    pub fn save(&self, path: &Path) -> Result<(), KinDbError> {
        use std::fs::File;
        use std::io::Write;

        let mut buf = Vec::new();
        buf.extend_from_slice(&INDEX_MAGIC);
        buf.extend_from_slice(&INDEX_VERSION.to_le_bytes());

        let body = bincode::serialize(self)
            .map_err(|e| KinDbError::StorageError(format!("index serialization failed: {e}")))?;

        buf.extend_from_slice(&(body.len() as u64).to_le_bytes());
        buf.extend(&body);

        // Compute SHA-256 checksum over the full buffer
        use sha2::{Digest, Sha256};
        let checksum = Sha256::digest(&buf);
        buf.extend_from_slice(&checksum);

        let tmp = path.with_extension("tmp");
        {
            let mut file = File::create(&tmp)
                .map_err(|e| KinDbError::StorageError(format!("write failed: {e}")))?;
            file.write_all(&buf)
                .map_err(|e| KinDbError::StorageError(format!("write failed: {e}")))?;
            file.sync_all()
                .map_err(|e| KinDbError::StorageError(format!("fsync failed: {e}")))?;
        }

        std::fs::rename(&tmp, path)
            .map_err(|e| KinDbError::StorageError(format!("rename failed: {e}")))?;

        // fsync the parent directory so the rename is durable
        if let Some(parent) = path.parent() {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }

        Ok(())
    }

    /// Load the index from a file.
    ///
    /// Verifies the SHA-256 checksum if present (files with checksum are
    /// 32 bytes longer than header + body). Returns an error on mismatch,
    /// which signals the caller to rebuild the index.
    pub fn load(path: &Path) -> Result<Self, KinDbError> {
        let data = std::fs::read(path).map_err(|e| {
            KinDbError::StorageError(format!("failed to read {}: {e}", path.display()))
        })?;

        if data.len() < 16 {
            return Err(KinDbError::StorageError("index file too small".into()));
        }

        if data[0..4] != INDEX_MAGIC {
            return Err(KinDbError::StorageError("invalid index magic".into()));
        }

        let version = u32::from_le_bytes(data[4..8].try_into().map_err(|_| {
            KinDbError::SliceConversionError(
                "index version bytes: expected 4-byte slice".to_string(),
            )
        })?);
        if version != INDEX_VERSION {
            return Err(KinDbError::StorageError(format!(
                "unsupported index version: {version}"
            )));
        }

        let body_len = u64::from_le_bytes(data[8..16].try_into().map_err(|_| {
            KinDbError::SliceConversionError(
                "index body_len bytes: expected 8-byte slice".to_string(),
            )
        })?) as usize;

        let payload_end = 16 + body_len;
        if data.len() < payload_end {
            return Err(KinDbError::StorageError(
                "index file truncated: body extends past end of data".into(),
            ));
        }

        // Verify SHA-256 checksum if present
        if data.len() >= payload_end + 32 {
            use sha2::{Digest, Sha256};
            let stored_checksum = &data[payload_end..payload_end + 32];
            let computed = Sha256::digest(&data[..payload_end]);
            if computed.as_slice() != stored_checksum {
                return Err(KinDbError::StorageError(
                    "index checksum mismatch — file is corrupted, rebuild required".into(),
                ));
            }
        }

        let body = &data[16..payload_end];

        bincode::deserialize(body)
            .map_err(|e| KinDbError::StorageError(format!("index deserialization failed: {e}")))
    }

    /// Search entities by name (substring match).
    pub fn search_by_name(&self, pattern: &str) -> Vec<u32> {
        let pat = pattern.to_lowercase();
        self.name_index
            .iter()
            .filter(|(k, _)| k.contains(&pat))
            .flat_map(|(_, indices)| indices.iter().copied())
            .collect()
    }

    /// Get entity by UUID string.
    pub fn get_entity_idx(&self, id: &str) -> Option<u32> {
        self.id_to_idx.get(id).copied()
    }

    /// Get incoming entity indices (callers/importers).
    pub fn get_incoming(&self, idx: u32) -> &[u32] {
        self.incoming
            .get(idx as usize)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get outgoing relations.
    pub fn get_outgoing(&self, idx: u32) -> &[IndexRelation] {
        self.outgoing
            .get(idx as usize)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::InMemoryGraph;
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
        FingerprintAlgorithm, Hash256, LanguageId, SemanticFingerprint, Visibility,
    };

    fn make_entity(name: &str, language: LanguageId, file_path: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0x11; 32]),
                signature_hash: Hash256::from_bytes([0x22; 32]),
                behavior_hash: Hash256::from_bytes([0x33; 32]),
                stability_score: 0.95,
            },
            file_origin: Some(FilePathId::new(file_path)),
            span: None,
            signature: format!("fn {name}"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: Some(format!("entity {name}")),
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn from_graph_preserves_full_language_distribution() {
        let graph = InMemoryGraph::new();
        let entities = [
            make_entity("parseTs", LanguageId::TypeScript, "src/app.ts"),
            make_entity("parseRust", LanguageId::Rust, "src/lib.rs"),
            make_entity("parsePython", LanguageId::Python, "tools/job.py"),
            make_entity("parseGo", LanguageId::Go, "cmd/main.go"),
            make_entity("parseRustHelper", LanguageId::Rust, "src/helpers.rs"),
        ];

        for entity in &entities {
            graph.upsert_entity(entity).unwrap();
        }

        let index = ReadIndex::from_graph(&graph).unwrap();

        assert_eq!(index.entity_count, entities.len() as u32);
        assert_eq!(
            index.language_counts.len(),
            4,
            "polyglot repos should retain every seen language in the index",
        );
        assert_eq!(
            index.language_counts.get(&(LanguageId::Rust as u8)),
            Some(&2),
            "Rust count should preserve both Rust entities",
        );
        assert_eq!(
            index.language_counts.get(&(LanguageId::TypeScript as u8)),
            Some(&1),
        );
        assert_eq!(
            index.language_counts.get(&(LanguageId::Python as u8)),
            Some(&1),
        );
        assert_eq!(index.language_counts.get(&(LanguageId::Go as u8)), Some(&1),);
    }
}
