// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Convert LSP responses into graph relations.
//!
//! The enrichment pipeline:
//! 1. For each entity in the graph, prepare a call hierarchy request
//! 2. Send to LSP server, get outgoing/incoming calls
//! 3. Match call targets against existing graph entities by file + position
//! 4. Produce Relations with RelationOrigin::Lsp

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tracing::{debug, warn};

use crate::lifecycle::LspServer;
use crate::protocol::{self, CallHierarchyItem, Position, TextDocumentIdentifier};
use crate::types::{
    EntityId, GraphNodeId, Relation, RelationId, RelationKind, RelationOrigin,
};
use crate::error::Result;

/// Result of enriching a single file via LSP.
#[derive(Debug, Default)]
pub struct EnrichmentResult {
    /// New relations discovered by LSP (type-resolved calls, references, etc.)
    pub relations: Vec<Relation>,
    /// Entities that LSP couldn't resolve (for diagnostics).
    pub unresolved: Vec<String>,
    /// Number of call hierarchy items processed.
    pub items_processed: usize,
}

/// Lightweight entity reference for matching LSP locations to graph entities.
#[derive(Debug, Clone)]
pub struct EntityRef {
    pub id: EntityId,
    pub name: String,
    pub file_path: String,
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
}

/// Spatial index: given a file URI and line number, find the matching entity.
pub struct EntityIndex {
    /// Map from file path → sorted list of (start_line, end_line, EntityRef)
    by_file: HashMap<String, Vec<EntityRef>>,
}

impl EntityIndex {
    /// Build an index from entity refs.
    pub fn new(entities: Vec<EntityRef>) -> Self {
        let mut by_file: HashMap<String, Vec<EntityRef>> = HashMap::new();
        for entity in entities {
            by_file
                .entry(entity.file_path.clone())
                .or_default()
                .push(entity);
        }
        // Sort each file's entities by start line for binary search.
        for entries in by_file.values_mut() {
            entries.sort_by_key(|e| e.start_line);
        }
        Self { by_file }
    }

    /// Find the entity at the given file URI and position.
    /// Matches the entity whose span contains the position.
    pub fn find_at(&self, uri: &str, line: u32) -> Option<&EntityRef> {
        let path = protocol::uri_to_path(uri)?;
        let path_str = path.to_string_lossy();
        // Try exact path match first, then suffix match.
        let entries = self.by_file.get(path_str.as_ref()).or_else(|| {
            self.by_file
                .iter()
                .find(|(k, _)| path_str.ends_with(k.as_str()) || k.ends_with(path_str.as_ref()))
                .map(|(_, v)| v)
        })?;

        // Find the entity whose span contains this line.
        entries
            .iter()
            .find(|e| line >= e.start_line && line <= e.end_line)
    }

    /// Find entity by name match (fallback when position doesn't match).
    pub fn find_by_name(&self, name: &str) -> Option<&EntityRef> {
        self.by_file
            .values()
            .flat_map(|entries| entries.iter())
            .find(|e| e.name == name || e.name.ends_with(&format!(".{}", name)))
    }
}

/// Query outgoing calls from a specific entity and produce Relations.
pub async fn enrich_entity_calls(
    server: &LspServer,
    caller: &EntityRef,
    index: &EntityIndex,
    workspace_root: &Path,
) -> Result<Vec<Relation>> {
    if !server.has_call_hierarchy() {
        return Ok(Vec::new());
    }

    let file_path = workspace_root.join(&caller.file_path);
    let uri = protocol::path_to_uri(&file_path);

    // Step 1: Prepare call hierarchy at the entity's position.
    let prepare_result = server
        .client
        .request(
            "textDocument/prepareCallHierarchy",
            protocol::CallHierarchyPrepareParams {
                text_document: TextDocumentIdentifier { uri: uri.clone() },
                position: Position {
                    line: caller.start_line,
                    character: caller.start_col,
                },
            },
        )
        .await;

    let items: Vec<CallHierarchyItem> = match prepare_result {
        Ok(value) => serde_json::from_value(value).unwrap_or_default(),
        Err(e) => {
            debug!(entity = %caller.name, error = %e, "prepareCallHierarchy failed");
            return Ok(Vec::new());
        }
    };

    if items.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2: Query outgoing calls for the first item (the entity itself).
    let item = &items[0];
    let outgoing_result = server
        .client
        .request(
            "callHierarchy/outgoingCalls",
            protocol::CallHierarchyOutgoingCallsParams {
                item: item.clone(),
            },
        )
        .await;

    let outgoing: Vec<protocol::CallHierarchyOutgoingCall> = match outgoing_result {
        Ok(value) => serde_json::from_value(value).unwrap_or_default(),
        Err(e) => {
            debug!(entity = %caller.name, error = %e, "outgoingCalls failed");
            return Ok(Vec::new());
        }
    };

    // Step 3: Match each outgoing call target to a graph entity.
    let mut relations = Vec::new();
    for call in &outgoing {
        let target_line = call.to.selection_range.start.line;
        let target_uri = &call.to.uri;

        // Try position-based match first, then name-based fallback.
        let target = index
            .find_at(target_uri, target_line)
            .or_else(|| index.find_by_name(&call.to.name));

        match target {
            Some(target_ref) => {
                relations.push(Relation {
                    id: RelationId::new(),
                    kind: RelationKind::Calls,
                    src: GraphNodeId::Entity(caller.id),
                    dst: GraphNodeId::Entity(target_ref.id),
                    confidence: 0.95,
                    origin: RelationOrigin::Lsp,
                    created_in: None,
                    import_source: None,
                });
            }
            None => {
                debug!(
                    caller = %caller.name,
                    target = %call.to.name,
                    "LSP call target not found in graph"
                );
            }
        }
    }

    Ok(relations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_index_finds_by_position() {
        let entities = vec![
            EntityRef {
                id: EntityId::new(),
                name: "foo".to_string(),
                file_path: "src/lib.rs".to_string(),
                start_line: 10,
                start_col: 0,
                end_line: 20,
            },
            EntityRef {
                id: EntityId::new(),
                name: "bar".to_string(),
                file_path: "src/lib.rs".to_string(),
                start_line: 25,
                start_col: 0,
                end_line: 35,
            },
        ];
        let index = EntityIndex::new(entities);

        let found = index.find_at("file:///project/src/lib.rs", 15);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "foo");

        let found = index.find_at("file:///project/src/lib.rs", 30);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "bar");

        // Outside any entity
        let found = index.find_at("file:///project/src/lib.rs", 22);
        assert!(found.is_none());
    }

    #[test]
    fn entity_index_finds_by_name() {
        let entities = vec![EntityRef {
            id: EntityId::new(),
            name: "Config.new".to_string(),
            file_path: "src/config.rs".to_string(),
            start_line: 5,
            start_col: 0,
            end_line: 10,
        }];
        let index = EntityIndex::new(entities);

        assert!(index.find_by_name("Config.new").is_some());
        assert!(index.find_by_name("new").is_some()); // suffix match
        assert!(index.find_by_name("nonexistent").is_none());
    }
}
