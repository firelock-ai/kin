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
use std::path::Path;

use tracing::debug;

use crate::error::Result;
use crate::lifecycle::LspServer;
use crate::protocol::{
    self, CallHierarchyItem, Position, TextDocumentIdentifier, TypeHierarchyItem,
    TypeHierarchyPrepareParams, TypeHierarchySupertypesParams,
};
use kin_model::{EntityId, GraphNodeId, Relation, RelationId, RelationKind, RelationOrigin};

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
    /// Position of the entity NAME (not declaration start).
    /// LSP prepareCallHierarchy needs cursor on the name, not the fn keyword.
    pub name_line: u32,
    pub name_col: u32,
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
                    line: caller.name_line,
                    character: caller.name_col,
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
            protocol::CallHierarchyOutgoingCallsParams { item: item.clone() },
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

/// Query type hierarchy supertypes for a method entity to detect Overrides relations.
/// If the method exists on a parent trait/type, emit an Overrides relation.
pub async fn enrich_entity_overrides(
    server: &LspServer,
    method: &EntityRef,
    index: &EntityIndex,
    workspace_root: &Path,
) -> Result<Vec<Relation>> {
    if !server.has_type_hierarchy() {
        return Ok(Vec::new());
    }

    // Only query methods (names containing '.'), not standalone functions.
    if !method.name.contains('.') {
        return Ok(Vec::new());
    }

    let method_short_name = method.name.rsplit('.').next().unwrap_or(&method.name);

    let file_path = workspace_root.join(&method.file_path);
    let uri = protocol::path_to_uri(&file_path);

    // Step 1: Prepare type hierarchy at the method's position.
    let prepare_result = server
        .client
        .request(
            "textDocument/prepareTypeHierarchy",
            TypeHierarchyPrepareParams {
                text_document: TextDocumentIdentifier { uri: uri.clone() },
                position: Position {
                    line: method.name_line,
                    character: method.start_col,
                },
            },
        )
        .await;

    let items: Vec<TypeHierarchyItem> = match prepare_result {
        Ok(value) => serde_json::from_value(value).unwrap_or_default(),
        Err(e) => {
            debug!(entity = %method.name, error = %e, "prepareTypeHierarchy failed");
            return Ok(Vec::new());
        }
    };

    if items.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2: Query supertypes for the first item.
    let item = &items[0];
    let supertypes_result = server
        .client
        .request(
            "typeHierarchy/supertypes",
            TypeHierarchySupertypesParams { item: item.clone() },
        )
        .await;

    let supertypes: Vec<TypeHierarchyItem> = match supertypes_result {
        Ok(value) => serde_json::from_value(value).unwrap_or_default(),
        Err(e) => {
            debug!(entity = %method.name, error = %e, "typeHierarchy/supertypes failed");
            return Ok(Vec::new());
        }
    };

    // Step 3: For each supertype, check if a method with the same name exists in the graph.
    let mut relations = Vec::new();
    for supertype in &supertypes {
        // Look for "SupertypeName.method_name" in the graph index.
        let candidate_name = format!("{}.{}", supertype.name, method_short_name);
        let target = index
            .find_at(&supertype.uri, supertype.selection_range.start.line)
            .or_else(|| index.find_by_name(&candidate_name));

        if let Some(target_ref) = target {
            relations.push(Relation {
                id: RelationId::new(),
                kind: RelationKind::Overrides,
                src: GraphNodeId::Entity(method.id),
                dst: GraphNodeId::Entity(target_ref.id),
                confidence: 0.90,
                origin: RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
            });
            debug!(
                method = %method.name,
                overrides = %target_ref.name,
                "discovered Overrides relation"
            );
        }
    }

    Ok(relations)
}

/// Query type definitions for entities referenced in a function's signature/body.
/// For each resolved type, find it in the graph index and emit UsesType relations.
pub async fn enrich_entity_uses_type(
    server: &LspServer,
    entity: &EntityRef,
    index: &EntityIndex,
    workspace_root: &Path,
) -> Result<Vec<Relation>> {
    if !server.has_type_definition() {
        return Ok(Vec::new());
    }

    let file_path = workspace_root.join(&entity.file_path);
    let uri = protocol::path_to_uri(&file_path);

    // Sample positions within the entity's span to discover type usages.
    // We query at every line within the entity to catch parameter types,
    // return types, and type references in the body.
    let mut relations = Vec::new();
    let mut seen_targets = std::collections::HashSet::new();

    for line in entity.start_line..=entity.end_line {
        let type_def_result = server
            .client
            .request(
                "textDocument/typeDefinition",
                protocol::TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier { uri: uri.clone() },
                    position: Position { line, character: 0 },
                },
            )
            .await;

        let locations: Vec<protocol::Location> = match type_def_result {
            Ok(value) => {
                // Response may be a single Location or an array of Locations.
                if let Ok(locs) = serde_json::from_value::<Vec<protocol::Location>>(value.clone()) {
                    locs
                } else if let Ok(loc) = serde_json::from_value::<protocol::Location>(value) {
                    vec![loc]
                } else {
                    continue;
                }
            }
            Err(_) => continue,
        };

        for loc in &locations {
            let target_line = loc.range.start.line;
            let target = index.find_at(&loc.uri, target_line).or_else(|| {
                // Try name extraction from the URI as a fallback.
                protocol::uri_to_path(&loc.uri)
                    .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().to_string()))
                    .and_then(|name| index.find_by_name(&name))
            });

            if let Some(target_ref) = target {
                // Skip self-references and duplicates.
                if target_ref.id == entity.id || !seen_targets.insert(target_ref.id) {
                    continue;
                }

                relations.push(Relation {
                    id: RelationId::new(),
                    kind: RelationKind::UsesType,
                    src: GraphNodeId::Entity(entity.id),
                    dst: GraphNodeId::Entity(target_ref.id),
                    confidence: 0.85,
                    origin: RelationOrigin::Lsp,
                    created_in: None,
                    import_source: None,
                });
                debug!(
                    entity = %entity.name,
                    uses_type = %target_ref.name,
                    "discovered UsesType relation"
                );
            }
        }
    }

    Ok(relations)
}

/// Query textDocument/references for an entity to find all references to it.
/// Returns References relations from the referencing entity to this entity.
pub async fn enrich_entity_references(
    server: &LspServer,
    entity: &EntityRef,
    index: &EntityIndex,
    workspace_root: &Path,
) -> Result<Vec<Relation>> {
    if !server.has_references() {
        return Ok(Vec::new());
    }

    let file_path = workspace_root.join(&entity.file_path);
    let uri = protocol::path_to_uri(&file_path);

    // Query references at the entity's name position.
    let result = server
        .client
        .request(
            "textDocument/references",
            serde_json::json!({
                "textDocument": { "uri": uri },
                "position": {
                    "line": entity.name_line,
                    "character": entity.name_col,
                },
                "context": { "includeDeclaration": false }
            }),
        )
        .await;

    let locations: Vec<protocol::Location> = match result {
        Ok(value) => serde_json::from_value(value).unwrap_or_default(),
        Err(e) => {
            debug!(entity = %entity.name, error = %e, "references query failed");
            return Ok(Vec::new());
        }
    };

    let mut relations = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for location in &locations {
        // Find the entity that contains this reference location.
        let ref_line = location.range.start.line;
        if let Some(referencing) = index.find_at(&location.uri, ref_line) {
            // Skip self-references.
            if referencing.id == entity.id {
                continue;
            }
            // Deduplicate.
            if !seen.insert(referencing.id) {
                continue;
            }
            relations.push(Relation {
                id: RelationId::new(),
                kind: RelationKind::References,
                src: GraphNodeId::Entity(referencing.id),
                dst: GraphNodeId::Entity(entity.id),
                confidence: 0.95,
                origin: RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
            });
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
                name_line: 10,
                name_col: 3,
            },
            EntityRef {
                id: EntityId::new(),
                name: "bar".to_string(),
                file_path: "src/lib.rs".to_string(),
                start_line: 25,
                start_col: 0,
                end_line: 35,
                name_line: 25,
                name_col: 3,
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
            name_line: 5,
            name_col: 7,
        }];
        let index = EntityIndex::new(entities);

        assert!(index.find_by_name("Config.new").is_some());
        assert!(index.find_by_name("new").is_some()); // suffix match
        assert!(index.find_by_name("nonexistent").is_none());
    }
}
