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
    documents: Option<crate::enrichment::DocumentProvider<'_>>,
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
    let mut scoped_documents = crate::enrichment::ScopedDocuments::new(server, documents);

    // Scan each line for identifier positions.
    for (line_num, line_text) in file_content.lines().enumerate() {
        let line = line_num as u32;
        let positions = identifier_positions_in_line(line_text);
        positions_queried += positions.len();

        // The relation source depends only on the line (never the column), and
        // every relation emitted below requires it to be Some. Lines outside any
        // known entity span can therefore never contribute a relation, so skip
        // their per-identifier LSP round-trips. Output-identical: this removes
        // only queries whose results were structurally guaranteed to be dropped.
        let Some(source) = entity_index.find_at(&uri, line) else {
            continue;
        };

        for col in positions {
            // A member expression on a MODULE receiver is answered by its
            // member. Asked at the receiver, the server returns the module, and
            // `find_at` turns that into whichever entity holds the line, so
            // every file that names `express` was recorded as referencing
            // express's default export: 50 inbound edges on `createApplication`
            // against 32 real reference sites on `Router`, which had none.
            //
            // Value receivers keep their edges. `res` in `res.send(...)`
            // resolves to its own parameter in this file and says something
            // true about the enclosing function. The two are told apart by
            // where the server puts the receiver's definition, which is the
            // server answering rather than this code guessing.
            if let Some((_receiver, member_col, member_name)) =
                crate::enrichment::member_expression_at(line_text, col)
            {
                let receiver_definitions = crate::enrichment::locations_at(
                    server,
                    "textDocument/definition",
                    &uri,
                    line,
                    col,
                )
                .await;
                if crate::enrichment::receiver_names_a_module(&receiver_definitions, &rel_path) {
                    // Declining alone was not enough, and assuming otherwise is
                    // what left a named export unreferenced. This pass used to
                    // drop the receiver here reasoning that "the member's own
                    // position is queried by this same loop on its next turn".
                    // It is queried, and on express it answers
                    // `node_modules/router`, outside the ingested tree, so
                    // `find_at` finds nothing and no edge is minted. Removing
                    // the wrong edge left nothing in its place, and the
                    // reference surface reads this arm's `References` edges, so
                    // `exports.Router` stayed at zero counted references against
                    // 32 real call sites.
                    //
                    // The same equivalence join the UsesType arm uses supplies
                    // the right edge: two independently proven server answers
                    // naming the same place, never a name match.
                    for candidate in crate::enrichment::member_export_bindings(
                        server,
                        entity_index,
                        workspace_root,
                        &mut scoped_documents,
                        &rel_path,
                        &uri,
                        line,
                        col,
                        member_col,
                        &member_name,
                    )
                    .await
                    {
                        if source.id == candidate.id
                            || !seen.insert((source.id, candidate.id, "member_on_module"))
                        {
                            continue;
                        }
                        definitions_resolved += 1;
                        relations.push(Relation {
                            id: deterministic_relation_id(
                                RelationKind::References,
                                source.id,
                                candidate.id,
                            ),
                            kind: RelationKind::References,
                            src: GraphNodeId::Entity(source.id),
                            dst: GraphNodeId::Entity(candidate.id),
                            confidence: 0.85,
                            origin: RelationOrigin::Lsp,
                            created_in: None,
                            import_source: None,
                            evidence: crate::enrichment::query_position_evidence(
                                "lsp_member_on_module",
                                &rel_path,
                                &protocol::Range {
                                    start: protocol::Position {
                                        line,
                                        character: member_col,
                                    },
                                    end: protocol::Position {
                                        line,
                                        character: member_col,
                                    },
                                },
                            ),
                        });
                        tracing::debug!(
                            entity = %source.name,
                            member = %member_name,
                            references = %candidate.name,
                            "bound a member on a module receiver to its export"
                        );
                    }
                    // The receiver's own resolution is still not this entity's
                    // fact, whether or not the member bound to anything.
                    continue;
                }
            }

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
                    let Some(dst) = entity_index.find_at(target_uri, target_line) else {
                        continue;
                    };

                    if source.id == dst.id {
                        continue;
                    }

                    definitions_resolved += 1;

                    let kind_str = if target_uri.contains(&rel_path) {
                        "same_file"
                    } else {
                        "cross_file"
                    };

                    if !seen.insert((source.id, dst.id, kind_str)) {
                        continue;
                    }

                    relations.push(Relation {
                        id: deterministic_relation_id(RelationKind::References, source.id, dst.id),
                        kind: RelationKind::References,
                        src: GraphNodeId::Entity(source.id),
                        dst: GraphNodeId::Entity(dst.id),
                        confidence: 0.95,
                        origin: RelationOrigin::Lsp,
                        created_in: None,
                        import_source: None,
                        // The identifier position this pass ASKED about, which
                        // is the reference site in the source file: for
                        // `adapter.send(...)` inside `Session.send` that is the
                        // call line itself. Enrichment relations carried no
                        // evidence at all, so every edge a language server
                        // proved arrived with no reference site and consuming
                        // surfaces reported `no_evidence_span` for it. The
                        // position is already in hand, so this costs no extra
                        // round trip.
                        evidence: crate::enrichment::query_position_evidence(
                            "lsp_definition",
                            &rel_path,
                            &protocol::Range {
                                start: protocol::Position {
                                    line,
                                    character: col,
                                },
                                end: protocol::Position {
                                    line,
                                    character: col,
                                },
                            },
                        ),
                    });
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

    scoped_documents.close_all().await;

    Ok(FileEnrichmentResult {
        relations,
        definitions_resolved,
        positions_queried,
    })
}

#[cfg(test)]
mod tests {
    use super::identifier_positions_in_line;
    use crate::enrichment::{EntityIndex, EntityRef};
    use kin_model::EntityId;

    /// The source-line gate in `enrich_file_definitions` skips a line's LSP
    /// round-trips iff `entity_index.find_at(uri, line)` is None. This proves
    /// the gate fires only on lines outside every entity span — exactly the
    /// lines on which the source half of `(source, target)` is None and so no
    /// relation could ever be emitted. That makes the skip output-identical.
    #[test]
    fn source_line_gate_skips_only_lines_outside_entity_spans() {
        let uri = "file:///project/src/lib.rs";
        let entities = vec![
            EntityRef {
                id: EntityId::new(),
                name: "alpha".to_string(),
                file_path: "src/lib.rs".to_string(),
                start_line: 0,
                start_col: 0,
                end_line: 5,
                name_line: 0,
                name_col: 3,
            },
            EntityRef {
                id: EntityId::new(),
                name: "beta".to_string(),
                file_path: "src/lib.rs".to_string(),
                start_line: 20,
                start_col: 0,
                end_line: 25,
                name_line: 20,
                name_col: 3,
            },
        ];
        let index = EntityIndex::new(entities);

        // Inside an entity span → queried (find_at is Some).
        for line in [0u32, 3, 5, 20, 25] {
            assert!(
                index.find_at(uri, line).is_some(),
                "line {line} is inside an entity span and must be queried"
            );
        }
        // Outside any span (imports, blank lines, inter-entity gap, tail) →
        // gated out (find_at is None). These can never produce a relation.
        for line in [6u32, 12, 19, 26, 9_999] {
            assert!(
                index.find_at(uri, line).is_none(),
                "line {line} is outside every entity span and is safe to skip"
            );
        }
    }

    #[test]
    fn identifier_positions_include_real_tokens_not_line_zero() {
        let positions = identifier_positions_in_line("    let foo_bar = Baz::new();");
        assert!(positions.contains(&4));
        assert!(positions.contains(&8));
        assert!(positions.contains(&18));
        assert!(!positions.contains(&0));
    }

    /// Build a large, adversarial source string: several thousand lines,
    /// periodic very-long lines, unicode identifiers/strings/comments, and
    /// comment/string lines to exercise every branch of the scanner.
    fn synth_large_file(lines: usize) -> String {
        let mut out = String::with_capacity(lines * 80);
        for i in 0..lines {
            match i % 10 {
                0 => {
                    // Long line (~500 cols) packed with identifiers + a string.
                    out.push_str("    let ");
                    for j in 0..40 {
                        out.push_str(&format!(
                            "ident_{i}_{j} = compute_naïve_café(α_{j}, β_{j}); "
                        ));
                    }
                    out.push_str("\"a string with spaces and symbols !@#\"\n");
                }
                3 => out.push_str("    // a comment line with λμβδα and words galore\n"),
                6 => out
                    .push_str("    let msg = \"unicode 日本語 строка with many words inside\";\n"),
                _ => out.push_str(&format!(
                    "    let value_{i} = SomeType::method_call(arg_one, arg_two);\n"
                )),
            }
        }
        out
    }

    /// Honest local-CPU measurement of the per-identifier scanner that the
    /// enrichment loops (`enrich_file_definitions`, `enrich_entity_uses_type`)
    /// run before each LSP request. The LSP round-trip itself is not measured
    /// here — that is the dominant cost and cannot be batched output-identically
    /// (definition resolution is position-dependent). This isolates the only
    /// work a "single-pass / batch" refactor could remove.
    #[test]
    #[ignore = "wall-clock microbench; run explicitly with --ignored on a quiet machine"]
    fn measure_identifier_scan_throughput_on_large_unicode_file() {
        let lines = 5_000usize;
        let content = synth_large_file(lines);
        let bytes = content.len();

        // Warm up so we measure steady-state, not first-touch allocation.
        let mut warm = 0usize;
        for line in content.lines() {
            warm += identifier_positions_in_line(line).len();
        }
        assert!(warm > 0, "scanner must find identifiers");

        let reps = 50u32;
        let start = std::time::Instant::now();
        let mut total_idents = 0usize;
        for _ in 0..reps {
            for line in content.lines() {
                total_idents += identifier_positions_in_line(line).len();
            }
        }
        let elapsed = start.elapsed();

        let idents_per_rep = total_idents / reps as usize;
        let per_rep = elapsed / reps;
        let ns_per_ident = elapsed.as_nanos() as f64 / total_idents as f64;
        let mb_per_s = (bytes as f64 * reps as f64) / elapsed.as_secs_f64() / 1.0e6;

        println!(
            "[scan-bench] {lines} lines, {bytes} bytes, {idents_per_rep} idents/file | \
             per-file {:?} | {ns_per_ident:.1} ns/ident | {mb_per_s:.0} MB/s",
            per_rep
        );

        // Sanity ceiling: scanning one whole large file must stay far under a
        // single LSP round-trip (which carries a 2s per-request timeout and
        // tens-of-ms typical latency). If a refactor ever made this O(n^2),
        // this guard would catch it. Generous bound to avoid CI flakiness.
        assert!(
            per_rep < std::time::Duration::from_millis(50),
            "per-file identifier scan should be sub-50ms (was {per_rep:?}); \
             the loop is LSP-RPC-bound, not scan-bound"
        );
    }
}
