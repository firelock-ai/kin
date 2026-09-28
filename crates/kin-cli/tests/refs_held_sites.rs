// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin refs` prints a site as a caller's only when an edge it counts
//! recorded that site.
//!
//! On cli/cli at `14d339d9`, with gopls, `kin refs` answered
//! `Repository.RepoOwner` with `NewCreateContext ... (type_resolved) sites
//! 649,678,697,723`. gopls resolved 678 and 723 to `Repository.RepoOwner` and
//! 649 and 697 to `Interface.RepoOwner`, since those two are calls on a
//! `ghrepo.Interface` value. The parser's receiver fan-out recorded all four
//! against every method named `RepoOwner`, and the row printed the union of
//! its edges' sites under its strongest edge's resolution. `find_references`
//! read the store the same way, and a compiler-graded measurement of Go call
//! sites scored those sites as false. Both surfaces now hold such a site apart,
//! with the resolution the edge that recorded it earned.

use kin_cli::commands::refs::{
    build_bulk_refs_response, build_refs_response, BulkRefsRequest, RefsRequest,
};
use kin_db::InMemoryGraph;
use kin_model::{
    Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
    FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, Relation, RelationEvidence, RelationId,
    RelationKind, RelationOrigin, SemanticFingerprint, SourceSpan, Visibility,
};

const FAN_OUT: f32 = kin_index::resolution::RECEIVER_NAME_FANOUT_CONFIDENCE;
const CREATE_GO: &str = "pkg/cmd/pr/create/create.go";

fn entity(language: LanguageId, kind: EntityKind, name: &str, file: &str) -> Entity {
    Entity {
        id: EntityId::new(),
        kind,
        name: name.to_string(),
        language,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0; 32]),
            signature_hash: Hash256::from_bytes([0; 32]),
            behavior_hash: Hash256::from_bytes([0; 32]),
            equivalence_hash: Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        },
        file_origin: Some(FilePathId::new(file)),
        span: None,
        signature: name.to_string(),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: None,
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

/// An edge with one site per 1-based line in `lines`, all in `file`.
fn edge(
    src: &Entity,
    dst: &Entity,
    kind: RelationKind,
    origin: RelationOrigin,
    confidence: f32,
    file: &str,
    lines: &[u32],
) -> Relation {
    Relation {
        id: RelationId::new(),
        kind,
        src: GraphNodeId::Entity(src.id),
        dst: GraphNodeId::Entity(dst.id),
        confidence,
        origin,
        created_in: None,
        import_source: None,
        evidence: lines
            .iter()
            .map(|line| RelationEvidence {
                source_span: Some(SourceSpan {
                    file: FilePathId::new(file),
                    start_byte: 0,
                    end_byte: 1,
                    start_line: line - 1,
                    start_col: 0,
                    end_line: line - 1,
                    end_col: 1,
                }),
                occurrence_count: 1,
                ..RelationEvidence::default()
            })
            .collect(),
    }
}

fn healthy_envelope() -> kin_mcp::Envelope {
    kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
        "initialized": true,
        "graph_loaded": true,
        "graph_entity_count": 10,
        "graph_generation": 1,
    }))
}

/// A parser-certain multi-site edge must come through the linker, which
/// certifies each fresh occurrence before it combines their evidence.
fn linked_same_file_calls(src: &Entity, dst: &Entity, lines: &[u32]) -> Relation {
    assert_eq!(src.file_origin, dst.file_origin);
    let file = src.file_origin.as_ref().unwrap();
    let last_line = *lines.iter().max().expect("at least one call site");
    let mut caller = src.clone();
    caller.span = Some(SourceSpan {
        file: file.clone(),
        start_byte: 0,
        end_byte: last_line as usize * 10 + 2,
        start_line: 0,
        start_col: 0,
        end_line: last_line,
        end_col: 0,
    });
    let parsed = kin_index::FileParseData {
        file_path: file.0.clone(),
        entities: vec![caller, dst.clone()],
        relations: lines
            .iter()
            .map(|line| kin_parser::ExtractedRelation {
                kind: RelationKind::Calls,
                src_name: src.name.clone(),
                dst_name: dst.name.clone(),
                import_source: None,
                call_shape: None,
                receiver: None,
                site: Some(kin_parser::RelationSite {
                    start_byte: *line as usize * 10,
                    end_byte: *line as usize * 10 + 1,
                    start_line: line - 1,
                    start_col: 0,
                    end_line: line - 1,
                    end_col: 1,
                    syntactic_role: None,
                }),
            })
            .collect(),
        imports: vec![],
    };
    let artifacts = [(file.0.clone(), kin_model::ArtifactId::new())]
        .into_iter()
        .collect();
    let relation = kin_index::link_cross_file(&[parsed], &artifacts)
        .unwrap()
        .into_iter()
        .find(|relation| {
            relation.kind == RelationKind::Calls
                && relation.src == GraphNodeId::Entity(src.id)
                && relation.dst == GraphNodeId::Entity(dst.id)
        })
        .expect("the linker resolved the fixture's calls");
    assert_eq!(relation.origin, RelationOrigin::Parsed);
    assert_eq!(relation.confidence, 1.0);
    relation
}

fn refs_lines(graph: &InMemoryGraph, focal: &Entity) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    let response = build_refs_response(
        &layout,
        graph,
        &RefsRequest {
            entity: focal.id.to_string(),
            kind: "all".to_string(),
        },
        &healthy_envelope(),
    )
    .expect("refs response");
    assert!(response.error.is_none(), "{:?}", response.lines);
    response.lines
}

/// The row lines for `caller` at `resolution`, as printed.
fn rows<'a>(lines: &'a [String], caller: &str, resolution: &str) -> Vec<&'a str> {
    lines
        .iter()
        .map(String::as_str)
        .filter(|line| {
            line.starts_with(&format!("  {caller} [")) && line.contains(&format!("({resolution})"))
        })
        .collect()
}

/// How `kin refs` prints a site of a caller the graph holds no span for. Every
/// caller here is spanless, so a row prints one of these per site and the
/// exact lines are pinned at the collector instead, by [`partitioned_lines`].
const SITE: &str = "+? (caller has no span)";

/// `count` spanless sites, as a row prints them.
fn sites(count: usize) -> String {
    format!("sites {}", vec![SITE; count].join(", "))
}

/// The 1-based file lines of `caller`'s counted and held sites, read from the
/// collector `kin refs` reads and cut by the rule `kin refs` holds an edge
/// out of its count by: a receiver-name guess, or an edge below proven that is
/// not a call (`ReferenceEntry::edge_is_held`).
///
/// A row addresses each site inside its caller and never by a file line, and
/// a spanless caller cannot place one, so this is where the lines each part
/// holds are pinned; the printed rows are held to the same site counts.
fn partitioned_lines(
    graph: &InMemoryGraph,
    focal: &Entity,
    caller: &str,
) -> (Option<Vec<u32>>, Option<Vec<u32>>) {
    let row = kin_mcp::handlers::common::collect_graph_reference_rows(
        graph,
        &focal.id,
        &kin_mcp::handlers::common::default_reference_kinds(),
        None,
    )
    .expect("collect reference rows")
    .into_iter()
    .find(|row| row.name == caller)
    .unwrap_or_else(|| panic!("the collector holds no row for `{caller}`"));
    let (counted, held) = kin_mcp::handlers::common::split_reference_row(row, |edge| {
        edge.receiver_name_guess
            || (!edge.resolution.is_proven() && edge.kind != RelationKind::Calls)
    });
    (
        counted.map(|row| row.reference_lines),
        held.map(|row| row.reference_lines),
    )
}

#[test]
fn a_counted_go_caller_prints_only_its_proven_sites() {
    let graph = InMemoryGraph::new();
    let concrete = entity(
        LanguageId::Go,
        EntityKind::Method,
        "Repository.RepoOwner",
        "api/queries_repo.go",
    );
    let interface = entity(
        LanguageId::Go,
        EntityKind::Method,
        "Interface.RepoOwner",
        "internal/ghrepo/repo.go",
    );
    let caller = entity(
        LanguageId::Go,
        EntityKind::Function,
        "NewCreateContext",
        CREATE_GO,
    );
    for e in [&concrete, &interface, &caller] {
        graph.upsert_entity(e).unwrap();
    }
    for (target, proven) in [(&concrete, [678, 723]), (&interface, [649, 697])] {
        for kind in [RelationKind::Calls, RelationKind::References] {
            graph
                .upsert_relation(&edge(
                    &caller,
                    target,
                    kind,
                    RelationOrigin::Lsp,
                    0.95,
                    CREATE_GO,
                    &proven,
                ))
                .unwrap();
        }
        graph
            .upsert_relation(&edge(
                &caller,
                target,
                RelationKind::Calls,
                RelationOrigin::Inferred,
                FAN_OUT,
                CREATE_GO,
                &[649, 678, 697, 723],
            ))
            .unwrap();
    }

    for (focal, proven, held) in [
        (&concrete, [678, 723], [649, 697]),
        (&interface, [649, 697], [678, 723]),
    ] {
        assert_eq!(
            partitioned_lines(&graph, focal, "NewCreateContext"),
            (Some(proven.to_vec()), Some(held.to_vec())),
            "{} confirms only what gopls resolved to it",
            focal.name
        );
        let lines = refs_lines(&graph, focal);
        let joined = lines.join("\n");
        let counted = rows(&lines, "NewCreateContext", "type_resolved");
        assert_eq!(counted.len(), 1, "{joined}");
        assert!(
            counted[0].contains(&format!("(projection: {CREATE_GO})"))
                && counted[0].ends_with(&sites(proven.len())),
            "{} confirms only what gopls resolved to it: {joined}",
            focal.name
        );
        let guessed = rows(&lines, "NewCreateContext", "name_only");
        assert_eq!(guessed.len(), 1, "{joined}");
        assert!(
            guessed[0].ends_with(&format!(
                "{} (its proven sites are counted above)",
                sites(held.len())
            )),
            "the fan-out's other sites are held and say whose they are: {joined}"
        );
        assert!(
            joined.contains(
                "referenced by 1 entities, plus 1 unconfirmed candidate not in that count:"
            ),
            "{joined}"
        );
        assert!(
            joined.contains("1 receiver-name candidate not counted above"),
            "{joined}"
        );
    }
}

/// Python: every site a proven edge recorded stays on the counted row, a
/// caller with nothing weaker is printed exactly as before, and only the site
/// nothing proved is held.
#[test]
fn every_proven_python_call_site_stays_counted() {
    let graph = InMemoryGraph::new();
    let sessions = "src/requests/sessions.py";
    // Synthetic geometry: the parser-certain caller and destination share a
    // file. In the real requests repository HTTPAdapter.send is in adapters.py.
    let focal = entity(
        LanguageId::Python,
        EntityKind::Method,
        "HTTPAdapter.send",
        "src/requests/auth.py",
    );
    let session_send = entity(
        LanguageId::Python,
        EntityKind::Method,
        "Session.send",
        sessions,
    );
    let handle_401 = entity(
        LanguageId::Python,
        EntityKind::Method,
        "HTTPDigestAuth.handle_401",
        "src/requests/auth.py",
    );
    for e in [&focal, &session_send, &handle_401] {
        graph.upsert_entity(e).unwrap();
    }
    for relation in [
        edge(
            &session_send,
            &focal,
            RelationKind::Calls,
            RelationOrigin::Lsp,
            0.95,
            sessions,
            &[784],
        ),
        edge(
            &session_send,
            &focal,
            RelationKind::Calls,
            RelationOrigin::Inferred,
            FAN_OUT,
            sessions,
            &[784, 790],
        ),
        linked_same_file_calls(&handle_401, &focal, &[262, 281]),
    ] {
        graph.upsert_relation(&relation).unwrap();
    }

    assert_eq!(
        partitioned_lines(&graph, &focal, "HTTPDigestAuth.handle_401"),
        (Some(vec![262, 281]), None)
    );
    assert_eq!(
        partitioned_lines(&graph, &focal, "Session.send"),
        (Some(vec![784]), Some(vec![790]))
    );
    let lines = refs_lines(&graph, &focal);
    let joined = lines.join("\n");
    let parsed = rows(&lines, "HTTPDigestAuth.handle_401", "type_resolved");
    assert_eq!(parsed.len(), 1, "{joined}");
    assert!(parsed[0].ends_with(&sites(2)), "{joined}");
    let counted = rows(&lines, "Session.send", "type_resolved");
    assert_eq!(counted.len(), 1, "{joined}");
    assert!(counted[0].ends_with(&sites(1)), "{joined}");
    let held = rows(&lines, "Session.send", "name_only");
    assert_eq!(held.len(), 1, "{joined}");
    assert!(
        held[0].ends_with(&format!(
            "{} (its proven sites are counted above)",
            sites(1)
        )),
        "{joined}"
    );
    assert!(
        joined
            .contains("referenced by 2 entities, plus 1 unconfirmed candidate not in that count:"),
        "{joined}"
    );
}

/// A caller whose only call is a receiver-name guess, beside a bare name
/// match, is held rather than counted. Read as a row it had a `Calls` edge, so
/// the rule that keeps name-only calls counted kept it too, though that call
/// was the fan-out's guess.
#[test]
fn a_caller_with_nothing_this_surface_counts_is_held_whole() {
    let graph = InMemoryGraph::new();
    let file = "pkg/cmd/api/api.go";
    let focal = entity(
        LanguageId::Go,
        EntityKind::Method,
        "Client.RequestBody",
        "api/client.go",
    );
    let caller = entity(LanguageId::Go, EntityKind::Function, "apiRun", file);
    for e in [&focal, &caller] {
        graph.upsert_entity(e).unwrap();
    }
    for relation in [
        edge(
            &caller,
            &focal,
            RelationKind::References,
            RelationOrigin::Inferred,
            0.7,
            file,
            &[40],
        ),
        edge(
            &caller,
            &focal,
            RelationKind::Calls,
            RelationOrigin::Inferred,
            FAN_OUT,
            file,
            &[44],
        ),
    ] {
        graph.upsert_relation(&relation).unwrap();
    }

    let lines = refs_lines(&graph, &focal);
    let joined = lines.join("\n");
    assert!(
        joined.contains("No resolved incoming Calls, Imports, References relations, plus 1 unconfirmed candidate not in that count."),
        "{joined}"
    );
    assert_eq!(
        partitioned_lines(&graph, &focal, "apiRun"),
        (None, Some(vec![40, 44])),
        "nothing of this caller is counted"
    );
    let held = rows(&lines, "apiRun", "name_only");
    assert_eq!(held.len(), 1, "{joined}");
    assert!(held[0].ends_with(&sites(2)), "{joined}");
    assert!(
        !held[0].contains("counted above"),
        "nothing of this caller is counted: {joined}"
    );
}

/// The count `kin refs` leads with, read off its own headline.
fn headline_count(lines: &[String]) -> usize {
    let joined = lines.join("\n");
    if joined.contains("No resolved incoming") {
        return 0;
    }
    let headline = lines
        .iter()
        .find(|line| line.starts_with("referenced by "))
        .unwrap_or_else(|| panic!("no count line in {joined}"));
    headline
        .trim_start_matches("referenced by ")
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

/// `kin refs --bulk-json` counts one caller as `kin refs` does: a caller whose
/// only edge is a receiver-name guess, one holding a bare name match beside
/// that guess, and one making a parser-certain call. Both read the same
/// collector through the same per-edge rule, so the count agrees by
/// construction; this pins the rows a reader sees. The batch counted every
/// caller that was not all guesses, so the mixed caller read 1 and
/// `has_references: true` there while `kin refs` counted nothing.
///
/// A caller `kin refs` holds whole is disclosed, and while one is held a zero
/// is not an absence: the row is incomplete rather than a proved `false`.
#[test]
fn bulk_refs_counts_a_guess_a_name_match_and_a_proven_call_as_refs_does() {
    for (shape, expected) in [("guess", 0), ("mixed", 0), ("proven", 1)] {
        let graph = InMemoryGraph::new();
        let file = "pkg/cmd/api/api.go";
        let focal = entity(
            LanguageId::Go,
            EntityKind::Method,
            "Client.RequestBody",
            "api/client.go",
        );
        let caller = entity(LanguageId::Go, EntityKind::Function, "apiRun", file);
        for e in [&focal, &caller] {
            graph.upsert_entity(e).unwrap();
        }
        let guess = edge(
            &caller,
            &focal,
            RelationKind::Calls,
            RelationOrigin::Inferred,
            FAN_OUT,
            file,
            &[44],
        );
        let edges = match shape {
            "guess" => vec![guess],
            "mixed" => vec![
                guess,
                edge(
                    &caller,
                    &focal,
                    RelationKind::References,
                    RelationOrigin::Inferred,
                    0.7,
                    file,
                    &[40],
                ),
            ],
            _ => vec![edge(
                &caller,
                &focal,
                RelationKind::Calls,
                RelationOrigin::Parsed,
                1.0,
                file,
                &[48],
            )],
        };
        for relation in edges {
            graph.upsert_relation(&relation).unwrap();
        }

        let lines = refs_lines(&graph, &focal);
        let bulk = build_bulk_refs_response(
            &graph,
            &BulkRefsRequest {
                entity_ids: vec![focal.id.to_string()],
                kind: "any".to_string(),
                compact: true,
            },
        )
        .expect("bulk refs");
        let row = &bulk.results[0];
        assert_eq!(headline_count(&lines), expected, "{shape}: {lines:#?}");
        if expected > 0 {
            assert_eq!(row["reference_count"], expected, "{shape}: {row}");
            assert_eq!(row["has_references"], true, "{shape}: {row}");
            assert_eq!(row["unconfirmed_candidate_count"], 0, "{shape}: {row}");
            assert_eq!(bulk.with_references, 1, "{shape}");
            continue;
        }
        assert_eq!(
            row["known_reference_count"], 0,
            "{shape}: the batch counts what kin refs counts: {row}"
        );
        assert!(
            row["reference_count"].is_null() && row["has_references"].is_null(),
            "{shape}: a caller held whole is not a proved zero: {row}"
        );
        assert_eq!(row["reference_count_complete"], false, "{shape}: {row}");
        assert_eq!(row["verdict_complete"], false, "{shape}: {row}");
        assert_eq!(row["unconfirmed_candidate_count"], 1, "{shape}: {row}");
        assert_eq!(
            row["receiver_name_candidate_count"],
            if shape == "guess" { 1 } else { 0 },
            "{shape}: {row}"
        );
        assert_eq!(
            row["verdict_reason"], "unconfirmed candidate references remain",
            "{shape}: {row}"
        );
        assert_eq!(bulk.incomplete_verdict_count, 1, "{shape}");
        assert_eq!(bulk.without_references, 0, "{shape}");
    }
}

/// A dangling source beside a caller held whole: the known count is still the
/// callers counted, which is none, and the held caller and the missing source
/// are each stated apart, in both row shapes. Adding them in made this row read
/// `known_reference_count: 2` where nothing was counted.
#[test]
fn a_dangling_source_beside_a_held_caller_adds_nothing_to_the_known_count() {
    let graph = InMemoryGraph::new();
    let file = "pkg/cmd/api/api.go";
    let focal = entity(
        LanguageId::Go,
        EntityKind::Method,
        "Client.RequestBody",
        "api/client.go",
    );
    let caller = entity(LanguageId::Go, EntityKind::Function, "apiRun", file);
    // Its relation is in the graph and its entity record is not.
    let dangling = entity(LanguageId::Go, EntityKind::Function, "gone", "pkg/gone.go");
    for e in [&focal, &caller] {
        graph.upsert_entity(e).unwrap();
    }
    for relation in [
        edge(
            &caller,
            &focal,
            RelationKind::Calls,
            RelationOrigin::Inferred,
            FAN_OUT,
            file,
            &[44],
        ),
        edge(
            &caller,
            &focal,
            RelationKind::References,
            RelationOrigin::Inferred,
            0.7,
            file,
            &[40],
        ),
        edge(
            &dangling,
            &focal,
            RelationKind::Calls,
            RelationOrigin::Parsed,
            1.0,
            "pkg/gone.go",
            &[3],
        ),
    ] {
        graph.upsert_relation(&relation).unwrap();
    }

    for compact in [true, false] {
        let bulk = build_bulk_refs_response(
            &graph,
            &BulkRefsRequest {
                entity_ids: vec![focal.id.to_string()],
                kind: "any".to_string(),
                compact,
            },
        )
        .expect("bulk refs");
        let row = &bulk.results[0];
        assert_eq!(row["known_reference_count"], 0, "compact={compact}: {row}");
        assert_eq!(
            row["unconfirmed_candidate_count"], 1,
            "compact={compact}: {row}"
        );
        assert_eq!(
            row["receiver_name_candidate_count"], 0,
            "compact={compact}: {row}"
        );
        assert_eq!(
            row["missing_source_entity_count"], 1,
            "compact={compact}: {row}"
        );
        assert!(
            row["has_references"].is_null() && row["reference_count"].is_null(),
            "compact={compact}: {row}"
        );
        assert_eq!(
            row["reference_count_complete"], false,
            "compact={compact}: {row}"
        );
        assert_eq!(row["verdict_complete"], false, "compact={compact}: {row}");
        assert_eq!(bulk.incomplete_verdict_count, 1, "compact={compact}");
        assert_eq!(
            row.get("name").is_some(),
            !compact,
            "compact={compact}: {row}"
        );
    }
}
