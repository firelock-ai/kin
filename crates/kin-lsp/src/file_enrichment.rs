// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! File-level LSP enrichment — extracts maximum relationships from a single file.
//!
//! Strategy: query textDocument/definition at every identifier position in the file.
//! Each resolved definition creates a relationship from the containing entity
//! to the target entity. This captures ALL references: function calls, type usage,
//! field access, method calls, trait references, imports — everything the type
//! system can resolve.
//!
//! This file-level pass captures references by querying every identifier and
//! then supplements them with call-hierarchy relations for every entity in the
//! file. That keeps the sweep broad while still emitting `Calls` edges.

use std::collections::HashSet;
use std::path::Path;

use crate::enrichment::{deterministic_relation_id, enrich_entity_calls, EntityIndex};
use crate::error::Result;
use crate::lifecycle::LspServer;
use crate::protocol;
use kin_model::{EntityId, GraphNodeId, Relation, RelationKind, RelationOrigin};

/// Result of enriching a single file.
#[derive(Debug, Default)]
pub struct FileEnrichmentResult {
    pub relations: Vec<Relation>,
    pub definitions_resolved: usize,
    pub positions_queried: usize,
}

/// Return the starting columns for identifier-like tokens in a single line.
///
/// This skips obvious comments and string literals at the token-scan level and
/// returns word starts so callers can probe LSP features at real symbol
/// positions instead of line 0.
pub(crate) fn identifier_positions_in_line(line_text: &str) -> Vec<u32> {
    let trimmed = line_text.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
        return Vec::new();
    }

    let chars: Vec<char> = line_text.chars().collect();
    let mut positions = Vec::new();
    let mut col = 0usize;
    let mut in_string = false;

    while col < chars.len() {
        let ch = chars[col];

        if ch == '"' && (col == 0 || chars[col - 1] != '\\') {
            in_string = !in_string;
            col += 1;
            continue;
        }
        if in_string {
            col += 1;
            continue;
        }

        if ch.is_alphabetic() || ch == '_' {
            let is_word_start =
                col == 0 || (!chars[col - 1].is_alphanumeric() && chars[col - 1] != '_');
            if is_word_start {
                positions.push(col as u32);
            }

            while col < chars.len() && (chars[col].is_alphanumeric() || chars[col] == '_') {
                col += 1;
            }
            continue;
        }

        col += 1;
    }

    positions
}

/// Enrich a file by querying textDocument/definition at every identifier position.
///
/// This is the maximum-extraction approach: for each line in the file, find
/// identifier-like tokens and query where they resolve to. Each resolution
/// that lands on a known graph entity becomes a relation.
pub async fn enrich_file_definitions(
    server: &LspServer,
    file_path: &Path,
    file_content: &str,
    entity_index: &EntityIndex,
    workspace_root: &Path,
) -> Result<FileEnrichmentResult> {
    let uri = protocol::path_to_uri(file_path);
    let rel_path = file_path
        .strip_prefix(workspace_root)
        .unwrap_or(file_path)
        .to_string_lossy()
        .to_string();

    // Deduplicate: (source_entity_id, target_entity_id, kind) → only emit once.
    let mut seen: HashSet<(EntityId, EntityId, &'static str)> = HashSet::new();
    let mut relations = Vec::new();
    let mut definitions_resolved = 0usize;
    let mut positions_queried = 0usize;

    // Scan each line for identifier positions.
    for (line_num, line_text) in file_content.lines().enumerate() {
        let line = line_num as u32;
        for col in identifier_positions_in_line(line_text) {
            positions_queried += 1;

            let def_result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                server.client.request(
                    "textDocument/definition",
                    protocol::TextDocumentPositionParams {
                        text_document: protocol::TextDocumentIdentifier { uri: uri.clone() },
                        position: protocol::Position {
                            line,
                            character: col,
                        },
                    },
                ),
            )
            .await;

            if let Ok(Ok(value)) = def_result {
                let locations: Vec<protocol::Location> =
                    serde_json::from_value::<Vec<protocol::Location>>(value.clone())
                        .unwrap_or_else(|_| {
                            serde_json::from_value::<protocol::Location>(value)
                                .map(|l| vec![l])
                                .unwrap_or_default()
                        });

                for location in &locations {
                    let target_line = location.range.start.line;
                    let target_uri = &location.uri;
                    let source = entity_index.find_at(&uri, line);
                    let target = entity_index.find_at(target_uri, target_line);

                    if let (Some(src), Some(dst)) = (source, target) {
                        if src.id == dst.id {
                            continue;
                        }

                        definitions_resolved += 1;

                        let kind_str = if target_uri.contains(&rel_path) {
                            "same_file"
                        } else {
                            "cross_file"
                        };

                        if !seen.insert((src.id, dst.id, kind_str)) {
                            continue;
                        }

                        relations.push(Relation {
                            id: deterministic_relation_id(RelationKind::References, src.id, dst.id),
                            kind: RelationKind::References,
                            src: GraphNodeId::Entity(src.id),
                            dst: GraphNodeId::Entity(dst.id),
                            confidence: 0.95,
                            origin: RelationOrigin::Lsp,
                            created_in: None,
                            import_source: None,
                            evidence: Vec::new(),
                        });
                    }
                }
            }
        }
    }

    // Add entity-level call hierarchy for every entity in this file. The
    // daemon already performs a per-entity pass, so we keep the relation IDs
    // deterministic to make repeated discovery idempotent.
    if server.has_call_hierarchy() {
        for entity in entity_index.entities_in_file(&rel_path) {
            let call_relations =
                enrich_entity_calls(server, entity, entity_index, workspace_root).await?;
            relations.extend(call_relations);
        }
    }

    Ok(FileEnrichmentResult {
        relations,
        definitions_resolved,
        positions_queried,
    })
}

#[cfg(test)]
mod tests {
    use super::identifier_positions_in_line;

    #[test]
    fn identifier_positions_include_real_tokens_not_line_zero() {
        let positions = identifier_positions_in_line("    let foo_bar = Baz::new();");
        assert!(positions.contains(&4));
        assert!(positions.contains(&8));
        assert!(positions.contains(&18));
        assert!(!positions.contains(&0));
    }
}
