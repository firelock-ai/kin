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
    pub kind: u8,       // EntityKind as u8 for compact serialization
    pub file_path: String,
    pub language: u8,    // LanguageId as u8
    pub start_line: u32,
}

/// Compact relation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexRelation {
    pub kind: u8,        // RelationKind as u8
    pub dst_idx: u32,    // Index into entities array
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
        use kin_model::GraphStore;

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
            let start_line = entity
                .span
                .as_ref()
                .map(|s| s.start_line)
                .unwrap_or(0);

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

        // Build outgoing and incoming edge lists
        let mut outgoing = vec![Vec::new(); all_entities.len()];
        let mut incoming = vec![Vec::new(); all_entities.len()];
        let mut relation_count = 0u32;

        for entity in &all_entities {
            let src_idx = id_to_idx[&entity.id.to_string()];
            let rels = graph.get_all_relations_for_entity(&entity.id)?;
            for rel in &rels {
                if rel.src == entity.id {
                    if let Some(&dst_idx) = id_to_idx.get(&rel.dst.to_string()) {
                        outgoing[src_idx as usize].push(IndexRelation {
                            kind: rel.kind as u8,
                            dst_idx,
                            confidence: rel.confidence,
                        });
                        incoming[dst_idx as usize].push(src_idx);
                        relation_count += 1;
                    }
                }
            }
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
    pub fn save(&self, path: &Path) -> Result<(), KinDbError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&INDEX_MAGIC);
        buf.extend_from_slice(&INDEX_VERSION.to_le_bytes());

        let body = bincode::serialize(self).map_err(|e| {
            KinDbError::StorageError(format!("index serialization failed: {e}"))
        })?;

        buf.extend_from_slice(&(body.len() as u64).to_le_bytes());
        buf.extend(body);

        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &buf).map_err(|e| {
            KinDbError::StorageError(format!("write failed: {e}"))
        })?;
        std::fs::rename(&tmp, path).map_err(|e| {
            KinDbError::StorageError(format!("rename failed: {e}"))
        })?;

        Ok(())
    }

    /// Load the index from a file.
    pub fn load(path: &Path) -> Result<Self, KinDbError> {
        let data = std::fs::read(path).map_err(|e| {
            KinDbError::StorageError(format!("failed to read {}: {e}", path.display()))
        })?;

        if data.len() < 16 {
            return Err(KinDbError::StorageError("index file too small".into()));
        }

        if &data[0..4] != &INDEX_MAGIC {
            return Err(KinDbError::StorageError("invalid index magic".into()));
        }

        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version != INDEX_VERSION {
            return Err(KinDbError::StorageError(format!(
                "unsupported index version: {version}"
            )));
        }

        let body_len = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;
        let body = &data[16..16 + body_len];

        bincode::deserialize(body).map_err(|e| {
            KinDbError::StorageError(format!("index deserialization failed: {e}"))
        })
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
        self.incoming.get(idx as usize).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get outgoing relations.
    pub fn get_outgoing(&self, idx: u32) -> &[IndexRelation] {
        self.outgoing.get(idx as usize).map(|v| v.as_slice()).unwrap_or(&[])
    }
}
