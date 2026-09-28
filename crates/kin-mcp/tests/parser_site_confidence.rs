// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Real syntax -> batch/live/checkpoint linker -> persisted relation -> reference split.
//! No fabricated relation or language-server evidence participates in this fixture.

use kin_index::{
    link_cross_file, link_cross_file_incremental, FileParseData, IncrementalLinker,
    RelationResolution,
};
use kin_mcp::handlers::common::{reference_edges, split_reference_row, ReferenceRow};
use kin_model::{ArtifactId, Entity, EntityKind, FilePathId, Relation, RelationKind};
use kin_parser::{LanguageAdapter, PythonAdapter};

const ADAPTER: &str = "class HTTPAdapter:\n    def send(self, request):\n        return request\n";
const OTHER: &str = "class ForeignAdapter:\n    def send(self, request):\n        return None\n";

fn parse(path: &str, source: &str) -> FileParseData {
    let adapter = PythonAdapter;
    let file = FilePathId::new(path);
    let tree = adapter.parse(source.as_bytes()).unwrap();
    let output = adapter.extract(&tree, source.as_bytes(), &file).unwrap();
    let entities = output
        .entities
        .into_iter()
        .map(|entity| {
            let mut entity = entity.into_entity_with_source(
                adapter.language_id(),
                &file,
                Some(source.as_bytes()),
            );
            entity.metadata.extra.insert(
                "blob_hash".into(),
                serde_json::json!(kin_blobs::digest(source.as_bytes()).to_string()),
            );
            entity
        })
        .collect();
    FileParseData {
        file_path: path.into(),
        entities,
        relations: output.relations,
        imports: output.imports,
    }
}

fn fixture(body: &str) -> Vec<FileParseData> {
    vec![
        parse("adapters.py", ADAPTER),
        parse("foreign.py", OTHER),
        parse(
            "caller.py",
            &format!("from adapters import HTTPAdapter\n\ndef relay(known: HTTPAdapter, unknown, request):\n{body}"),
        ),
    ]
}

fn identity(files: &[FileParseData], file: &str, name: &str, kind: EntityKind) -> Entity {
    let found: Vec<_> = files
        .iter()
        .filter(|parsed| parsed.file_path == file)
        .flat_map(|parsed| parsed.entities.iter())
        .filter(|entity| entity.name == name && entity.kind == kind)
        .cloned()
        .collect();
    assert_eq!(found.len(), 1, "one exact declaration: {file}/{name}");
    found[0].clone()
}

fn link(files: &[FileParseData], mode: &str) -> Vec<Relation> {
    let artifact_ids = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    let relations = if mode == "batch" {
        link_cross_file(files, &artifact_ids).unwrap()
    } else {
        let mut linker = IncrementalLinker::new();
        for file in files {
            linker.add_file(
                &file.file_path,
                artifact_ids[&file.file_path],
                &file.entities,
            );
        }
        if mode == "checkpoint" {
            linker = IncrementalLinker::from_checkpoint_v1(linker.to_checkpoint_v1()).unwrap();
        }
        link_cross_file_incremental(files, &linker).unwrap()
    };
    // This is the native positional MessagePack delta encoder, including its
    // checksum and frame validation, not only a serde JSON reconstruction.
    let mut delta = kin_db::storage::GraphSnapshotDelta::empty(0);
    delta.relations.added = relations
        .iter()
        .map(|relation| (relation.id, relation.clone()))
        .collect();
    let encoded = delta.to_bytes().unwrap();
    let decoded = kin_db::storage::GraphSnapshotDelta::from_bytes(&encoded).unwrap();
    let decoded: Vec<_> = decoded
        .relations
        .added
        .into_iter()
        .map(|(_, relation)| relation)
        .collect();
    assert_eq!(decoded, relations);
    decoded
}

fn split(files: &[FileParseData], mode: &str) -> (Option<ReferenceRow>, Option<ReferenceRow>) {
    let caller = identity(files, "caller.py", "relay", EntityKind::Function);
    let target = identity(files, "adapters.py", "HTTPAdapter.send", EntityKind::Method);
    let relations = link(files, mode);
    let edges: Vec<_> = relations
        .iter()
        .filter(|edge| {
            edge.kind == RelationKind::Calls
                && edge.src.as_entity() == Some(caller.id)
                && edge.dst.as_entity() == Some(target.id)
        })
        .flat_map(|edge| {
            eprintln!(
                "{mode} persisted parser edge: {}",
                serde_json::to_string(edge).unwrap()
            );
            reference_edges(edge, caller.file_origin.as_ref())
        })
        .collect();
    assert!(
        !edges.is_empty(),
        "real parser must produce the proposed edge"
    );
    let lines = edges
        .iter()
        .flat_map(|edge| edge.lines.iter().copied())
        .collect();
    let row = ReferenceRow {
        entity_id: Some(caller.id.to_string()),
        name: caller.name.clone(),
        kind: Some("Function".into()),
        file_path: Some("caller.py".into()),
        reference_lines: lines,
        site_addresses: std::collections::BTreeMap::new(),
        reference_lines_partial: edges.iter().find_map(|edge| edge.site_contract_gap),
        reference_lines_absent: None,
        signature: Some(caller.signature),
        snippet: None,
        relation_kinds: vec![RelationKind::Calls],
        resolution: edges.iter().map(|edge| edge.resolution).max(),
        via_override_of: None,
        receiver_name_guess: edges.iter().all(|edge| edge.receiver_name_guess),
        role: Some(caller.role),
        edges,
    };
    split_reference_row(row, |edge| {
        edge.is_held_at(RelationResolution::ImportScoped)
    })
}

#[test]
fn a_proven_parser_site_does_not_confirm_a_sibling_untyped_receiver() {
    let files = fixture("    known.send(request)\n    unknown.send(request)\n");
    let observed = ["batch", "incremental", "checkpoint"].map(|mode| {
        let (confirmed, candidate) = split(&files, mode);
        (
            mode,
            confirmed.map(|row| row.reference_lines),
            candidate.map(|row| row.reference_lines),
        )
    });
    eprintln!("mixed typed-first results from all link paths: {observed:?}");
    assert_eq!(observed, ["batch", "incremental", "checkpoint"].map(|mode| (mode, Some(vec![4]), Some(vec![5]))),
        "the actual typed site must stay proven while every linking path withholds the untyped site");
}

#[test]
fn source_order_cannot_promote_the_untyped_parser_site() {
    let files = fixture("    unknown.send(request)\n    known.send(request)\n");
    let observed = ["batch", "incremental", "checkpoint"].map(|mode| {
        let (confirmed, candidate) = split(&files, mode);
        (
            mode,
            confirmed.map(|row| row.reference_lines),
            candidate.map(|row| row.reference_lines),
        )
    });
    eprintln!("mixed untyped-first results from all link paths: {observed:?}");
    assert_eq!(
        observed,
        ["batch", "incremental", "checkpoint"].map(|mode| (mode, Some(vec![5]), Some(vec![4]))),
        "source order cannot promote the first weak occurrence in any linking path"
    );
}

#[test]
fn two_proven_parser_sites_remain_confirmed() {
    let files = fixture("    known.send(request)\n    known.send(request)\n");
    for mode in ["batch", "incremental", "checkpoint"] {
        let (confirmed, candidate) = split(&files, mode);
        assert_eq!(
            confirmed.expect("real proven caller").reference_lines,
            vec![4, 5],
            "{mode}"
        );
        assert!(candidate.is_none(), "{mode}: no invented weak site");
    }
}

#[test]
fn an_untyped_parser_site_alone_stays_a_candidate() {
    let files = fixture("    unknown.send(request)\n");
    for mode in ["batch", "incremental", "checkpoint"] {
        let (confirmed, candidate) = split(&files, mode);
        assert!(confirmed.is_none(), "{mode}: no invented proof");
        assert_eq!(candidate.expect("real weak site").reference_lines, vec![4]);
    }
}

fn mixed_edge() -> Relation {
    let files = fixture("    known.send(request)\n    unknown.send(request)\n");
    let caller = identity(&files, "caller.py", "relay", EntityKind::Function);
    let target = identity(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    link(&files, "batch")
        .into_iter()
        .find(|edge| {
            edge.kind == RelationKind::Calls
                && edge.src.as_entity() == Some(caller.id)
                && edge.dst.as_entity() == Some(target.id)
        })
        .unwrap()
}

fn assert_sites_held(edge: &Relation) {
    let (sites, withheld) = kin_index::occurrence::proven_sites(edge);
    assert!(sites.is_empty());
    assert!(withheld);
    let groups = kin_index::occurrence::groups(edge);
    assert!(
        groups
            .iter()
            .any(|group| group.resolution.is_proven() && group.sites.is_empty()),
        "caller existence remains true"
    );
    assert!(groups.iter().any(|group| group.qualification_missing));
    assert!(kin_index::occurrence::call_shape_records(edge).is_none());
}

#[test]
fn legacy_native_read_holds_multisite_attribution_without_rewriting_identity() {
    let mut legacy = mixed_edge();
    legacy.evidence.retain(|record| {
        record.parser_rule.as_deref() != Some(kin_index::occurrence::OCCURRENCE_RULE)
    });
    let mut delta = kin_db::storage::GraphSnapshotDelta::empty(0);
    delta.relations.added.push((legacy.id, legacy.clone()));
    let restored = kin_db::storage::GraphSnapshotDelta::from_bytes(&delta.to_bytes().unwrap())
        .unwrap()
        .relations
        .added
        .remove(0)
        .1;
    assert_eq!(restored, legacy);
    assert_sites_held(&restored);
    let mut single = legacy.clone();
    single.evidence.retain(|record| {
        record
            .source_span
            .as_ref()
            .is_none_or(|span| span.start_line == 3)
    });
    assert_eq!(
        kin_index::occurrence::proven_sites(&single).0[0].start_line,
        3,
        "legacy single-site semantics preserved"
    );
}

#[test]
fn malformed_conflicting_foreign_and_unknown_metadata_hold_sites() {
    let original = mixed_edge();
    for mutation in [
        "bad_json",
        "foreign_edge",
        "unsupported_tier",
        "origin",
        "extra_field",
        "count",
        "version",
        "conflict",
        "evidence",
    ] {
        let mut edge = original.clone();
        let index = edge
            .evidence
            .iter()
            .position(|record| {
                record.parser_rule.as_deref() == Some(kin_index::occurrence::OCCURRENCE_RULE)
            })
            .unwrap();
        let mut payload: serde_json::Value =
            serde_json::from_str(edge.evidence[index].token.as_deref().unwrap()).unwrap();
        match mutation {
            "bad_json" => edge.evidence[index].token = Some("{".into()),
            "count" => edge.evidence[index].occurrence_count = 1,
            "version" => {
                edge.evidence[index].parser_rule = Some("parser_occurrence_resolution_v2".into())
            }
            "evidence" => {
                for record in &mut edge.evidence {
                    if record.source_span.is_some() {
                        record.token = Some("changed".into());
                    }
                }
            }
            "conflict" => {
                payload["confidence"] = serde_json::json!(0.7);
                let mut conflict = edge.evidence[index].clone();
                conflict.token = Some(payload.to_string());
                edge.evidence.push(conflict);
            }
            field => {
                match field {
                    "foreign_edge" => {
                        payload["relation_id"] =
                            serde_json::json!(kin_model::RelationId::new().to_string())
                    }
                    "unsupported_tier" => payload["confidence"] = serde_json::json!(0.91),
                    "origin" => payload["origin"] = serde_json::json!("Lsp"),
                    "extra_field" => payload["unknown"] = serde_json::json!(true),
                    _ => unreachable!(),
                };
                edge.evidence[index].token = Some(payload.to_string());
            }
        }
        assert_sites_held(&edge);
    }
}

#[test]
fn multiplicity_keyword_normalization_and_duplicate_metadata_do_not_lose_proof() {
    let files = fixture("    known.send(request=request, spare=request)\n    known.send(request=request, spare=request)\n");
    let caller = identity(&files, "caller.py", "relay", EntityKind::Function);
    let target = identity(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let mut edge = link(&files, "batch")
        .into_iter()
        .find(|edge| {
            edge.kind == RelationKind::Calls
                && edge.src.as_entity() == Some(caller.id)
                && edge.dst.as_entity() == Some(target.id)
        })
        .unwrap();
    let proof = edge
        .evidence
        .iter()
        .find(|record| {
            record.parser_rule.as_deref() == Some(kin_index::occurrence::OCCURRENCE_RULE)
        })
        .unwrap()
        .clone();
    edge.evidence.push(proof);
    for record in &mut edge.evidence {
        if record.source_span.is_some() {
            record.occurrence_count = 7;
            record.call_shape.as_mut().unwrap().keywords =
                vec!["spare".into(), "request".into(), "request".into()];
        }
    }
    let originals = kin_index::occurrence::call_shape_records(&edge)
        .expect("valid metadata is not an unshaped call");
    assert_eq!(originals.len(), 2);
    assert_eq!(
        originals
            .iter()
            .map(|record| record.occurrence_count)
            .sum::<u32>(),
        14
    );
    assert!(originals.iter().all(|record| record.call_shape.is_some()));
    let (sites, withheld) = kin_index::occurrence::proven_sites(&edge);
    assert_eq!(sites.len(), 2);
    assert!(!withheld);
}

#[test]
fn read_projection_is_idempotent_and_keeps_one_logical_edge() {
    use kin_model::EntityStore;
    let files = fixture("    known.send(request)\n    unknown.send(request)\n");
    let store = kin_db::InMemoryGraph::new();
    for file in &files {
        for entity in &file.entities {
            store.upsert_entity(entity).unwrap();
        }
    }
    let edge = mixed_edge();
    store.upsert_relation(&edge).unwrap();
    let mut rows = vec![edge.clone()];
    kin_index::relation_read::project_relations_for_read(&store, &mut rows).unwrap();
    kin_index::relation_read::project_relations_for_read(&store, &mut rows).unwrap();
    assert_eq!(rows, vec![edge.clone()]);
    let edges = reference_edges(&rows[0], Some(&FilePathId::new("caller.py")));
    assert_eq!(edges.len(), 2);
    assert_eq!(
        edges
            .iter()
            .filter(|edge| !edge.is_held_at(RelationResolution::ImportScoped))
            .flat_map(|edge| edge.lines.clone())
            .collect::<Vec<_>>(),
        vec![4]
    );
    assert_eq!(
        kin_index::occurrence::proven_sites(&edge)
            .0
            .iter()
            .map(|span| span.start_line)
            .collect::<Vec<_>>(),
        vec![3]
    );
}

#[test]
fn real_trace_and_path_withhold_untyped_site_with_explicit_disclosure() {
    use kin_model::EntityStore;
    use std::collections::HashMap;
    let files = fixture("    known.send(request)\n    unknown.send(request)\n");
    let store = kin_db::InMemoryGraph::new();
    for file in &files {
        for entity in &file.entities {
            store.upsert_entity(entity).unwrap();
        }
    }
    for edge in link(&files, "batch")
        .into_iter()
        .filter(|edge| edge.src.as_entity().is_some() && edge.dst.as_entity().is_some())
    {
        store.upsert_relation(&edge).unwrap();
    }
    let caller = identity(&files, "caller.py", "relay", EntityKind::Function);
    let target = identity(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let args = HashMap::from([
        ("focal".into(), serde_json::json!(caller.id.to_string())),
        ("direction".into(), serde_json::json!("calls")),
        ("depth".into(), serde_json::json!(1)),
    ]);
    let reply = kin_mcp::handlers::entities::handle_trace_data_flow(&args, &store).unwrap();
    let value = serde_json::to_value(reply).unwrap();
    let payload: serde_json::Value =
        serde_json::from_str(value["content"][0]["text"].as_str().unwrap()).unwrap();
    let chain = payload["chain"].as_array().unwrap();
    let row = chain
        .iter()
        .find(|row| row["entity_id"] == target.id.to_string())
        .unwrap();
    assert_eq!(row["reference_lines"], serde_json::json!([4]));
    assert_eq!(
        row["reference_lines_partial_reason"],
        "unconfirmed_sites_withheld"
    );
    let args = HashMap::from([
        ("from".into(), serde_json::json!(caller.id.to_string())),
        ("to".into(), serde_json::json!(target.id.to_string())),
    ]);
    let reply = kin_mcp::handlers::path::handle_trace_path(&args, &store).unwrap();
    let value = serde_json::to_value(reply).unwrap();
    let payload: serde_json::Value =
        serde_json::from_str(value["content"][0]["text"].as_str().unwrap()).unwrap();
    eprintln!("actual path: {payload}");
    let first = &payload["routes"][0]["steps"][0];
    assert_eq!(first["site_lines"], serde_json::json!([4]));
    assert_eq!(
        first["site_lines_partial_reason"],
        "unconfirmed_sites_withheld"
    );
}
