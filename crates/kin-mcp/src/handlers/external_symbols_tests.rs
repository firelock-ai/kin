// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A call a language server proved into a package outside the repository is a
//! call target every read tool names.
//!
//! The store below is the smallest one that holds such a call: `render` calls
//! `Array.map` from TypeScript's own library, proven under a tsserver proof
//! context, and calls `helper` inside the repository as well. Each test asks
//! one tool about one end of that edge and holds the shape the answer takes.

use std::collections::HashMap;

use kin_db::InMemoryGraph;
use kin_model::entity::SourceSpan;
use kin_model::ids::RelationId;
use kin_model::relation::{Relation, RelationOrigin};
use kin_model::{
    Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, ExternalReference,
    ExternalReferenceDelta, ExternalSymbol, FilePathId, FingerprintAlgorithm, GraphNodeId, Hash256,
    LanguageId, ProofContext, RelationEvidence, RelationKind, ResolutionRecord,
    ResolutionRecordDelta, ScipDescriptor, ScipPackage, SemanticFingerprint, TransactionDelta,
    Visibility,
};

use super::entities::{
    handle_find_references, handle_get_context_pack, handle_get_entity, handle_get_entity_source,
    handle_get_entity_sources, handle_graph_neighborhood, handle_trace_computation,
    handle_trace_data_flow,
};
use super::external_symbols::EXTERNAL_SYMBOL_NO_SOURCE;
use crate::session::SessionRegistry;
use crate::types::{ContentBlock, ToolCallResult};

const APP_TS: &str = "src/app.ts";

fn entity(kind: EntityKind, name: &str, start_line: u32, start_byte: usize) -> Entity {
    Entity {
        id: EntityId::new(),
        kind,
        name: name.to_string(),
        language: LanguageId::TypeScript,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0; 32]),
            signature_hash: Hash256::from_bytes([0; 32]),
            behavior_hash: Hash256::from_bytes([0; 32]),
            equivalence_hash: Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        },
        // No file origin: without repository authority a span-backed entity
        // with an origin cannot be read at all, and these tests hold what the
        // graph says about the edge, not a body read. The span still places
        // each site inside its caller. The body read that quotes a site's text
        // is held by the source-backed test beside the other body reads.
        file_origin: None,
        span: Some(SourceSpan {
            file: FilePathId::new(APP_TS),
            start_byte,
            end_byte: start_byte + 200,
            start_line,
            start_col: 0,
            end_line: start_line + 8,
            end_col: 1,
        }),
        signature: format!("function {name}()"),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: None,
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

fn array_map() -> ExternalSymbol {
    ExternalSymbol::new(
        ScipPackage::new("npm", "typescript", "5.6.3").unwrap(),
        vec![
            ScipDescriptor::namespace("lib.es5.d.ts"),
            ScipDescriptor::type_("Array"),
            ScipDescriptor::method("map"),
        ],
    )
    .unwrap()
}

fn tsserver() -> ProofContext {
    ProofContext {
        language: LanguageId::TypeScript,
        resolver: "lsp:tsserver".to_string(),
        resolver_version: "5.6.3".to_string(),
        configuration_hash: Hash256::from_bytes([1; 32]),
        environment_hash: Hash256::from_bytes([2; 32]),
        environment_summary: "typescript 5.6.3".to_string(),
    }
}

/// A site in `caller`'s file, `line` graph lines below its first and `byte`
/// bytes into it.
fn site_in(caller: &Entity, line: u32, byte: usize, token: &str, rule: &str) -> RelationEvidence {
    let span = caller.span.as_ref().unwrap();
    RelationEvidence {
        source_span: Some(SourceSpan {
            file: span.file.clone(),
            start_byte: span.start_byte + byte,
            end_byte: span.start_byte + byte + 3,
            start_line: span.start_line + line,
            start_col: 4,
            end_line: span.start_line + line,
            end_col: 7,
        }),
        parser_rule: Some(rule.to_string()),
        token: Some(token.to_string()),
        occurrence_count: 1,
        ..RelationEvidence::default()
    }
}

struct ExternalStore {
    store: InMemoryGraph,
    caller: Entity,
    helper: Entity,
    node: ExternalReference,
}

impl ExternalStore {
    fn address(&self) -> String {
        format!("external_reference:{}", self.node.id)
    }
}

fn external_store() -> ExternalStore {
    let store = InMemoryGraph::new();
    let caller = entity(EntityKind::Function, "render", 10, 100);
    let helper = entity(EntityKind::Function, "helper", 40, 900);
    store.upsert_entity(&caller).unwrap();
    store.upsert_entity(&helper).unwrap();
    store
        .upsert_relation(&Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(caller.id),
            dst: GraphNodeId::Entity(helper.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        })
        .unwrap();

    let node = array_map().to_reference().unwrap();
    let context = ResolutionRecord::ProofContext(tsserver());
    let token = context.id().context_token();
    let src = GraphNodeId::Entity(caller.id);
    let dst = GraphNodeId::ExternalReference(node.id);
    let call = Relation {
        id: RelationId::resolver(RelationKind::Calls, &src, &dst),
        kind: RelationKind::Calls,
        src,
        dst,
        confidence: 1.0,
        origin: RelationOrigin::Lsp,
        created_in: None,
        import_source: None,
        evidence: vec![
            site_in(&caller, 2, 30, &token, "lsp_definition"),
            site_in(&caller, 5, 80, &token, "lsp_definition"),
        ],
    };
    store
        .apply_transaction_delta(&TransactionDelta {
            relation_deltas: vec![kin_model::RelationDelta::Added { new: call }],
            external_reference_deltas: vec![ExternalReferenceDelta::Added { new: node.clone() }],
            resolution_record_deltas: vec![ResolutionRecordDelta::Added { new: context }],
            ..TransactionDelta::default()
        })
        .unwrap();
    ExternalStore {
        store,
        caller,
        helper,
        node,
    }
}

fn body(result: &ToolCallResult) -> serde_json::Value {
    let ContentBlock::Text { text } = result.content.first().expect("a content block");
    serde_json::from_str(text).unwrap_or_else(|_| serde_json::Value::String(text.clone()))
}

fn args(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), value.clone()))
        .collect()
}

fn get_entity(store: &InMemoryGraph, id: &str) -> ToolCallResult {
    handle_get_entity(&args(&[("entity_id", serde_json::json!(id))]), store, None).unwrap()
}

async fn find_references(store: &InMemoryGraph, id: &str) -> ToolCallResult {
    handle_find_references(&args(&[("entity_id", serde_json::json!(id))]), store, None)
        .await
        .unwrap()
}

fn neighborhood(store: &InMemoryGraph, id: &str, direction: &str) -> ToolCallResult {
    handle_graph_neighborhood(
        &args(&[
            ("entity_id", serde_json::json!(id)),
            ("direction", serde_json::json!(direction)),
            ("depth", serde_json::json!(1)),
        ]),
        store,
    )
    .unwrap()
}

/// The symbol record every surface serves for `Array.map`.
fn assert_array_map_record(row: &serde_json::Value, address: &str) {
    assert_eq!(row["kind"], "external_symbol", "{row:#}");
    assert_eq!(row["id"], address, "{row:#}");
    assert_eq!(row["name"], "Array.map", "{row:#}");
    assert_eq!(
        row["package"],
        serde_json::json!({"manager": "npm", "name": "typescript", "version": "5.6.3"}),
        "{row:#}"
    );
    assert_eq!(row["stdlib"], true, "{row:#}");
    assert_eq!(row["symbol"], "`lib.es5.d.ts`/Array#map().", "{row:#}");
}

/// The proof and sites a row about the `render -> Array.map` edge carries.
fn assert_render_calls_array_map(row: &serde_json::Value) {
    assert_eq!(row["site_state"], "proven_external", "{row:#}");
    assert_eq!(row["resolution"], "type_resolved", "{row:#}");
    let context = ResolutionRecord::ProofContext(tsserver()).id();
    assert_eq!(
        row["proof"],
        serde_json::json!({
            "resolver": "lsp:tsserver",
            "resolver_version": "5.6.3",
            "context": context.0.to_string(),
            "rule": "lsp_definition",
        }),
        "{row:#}"
    );
    let sites = row["sites"].as_array().expect("sites");
    let lines: Vec<u64> = sites
        .iter()
        .map(|site| site["line_in_entity"].as_u64().unwrap())
        .collect();
    assert_eq!(
        lines,
        [2, 5],
        "sites are addressed inside the caller: {row:#}"
    );
    for site in sites {
        assert!(
            site.get("callee").is_some(),
            "a site says what text it names, or why it cannot: {site:#}"
        );
        for key in ["line", "start_line", "file_path", "reference_lines"] {
            assert!(
                site.get(key).is_none(),
                "a site never carries a file line: {site:#}"
            );
        }
    }
}

#[test]
fn get_entity_answers_an_external_symbol_by_its_address() {
    let f = external_store();
    let address = f.address();
    let value = body(&get_entity(&f.store, &address));
    assert_array_map_record(&value, &address);
    assert_eq!(value["caller_count"], 1, "{value:#}");

    // The bare identity names the same node, the way an edge's typed end
    // spells it.
    let bare = body(&get_entity(&f.store, &f.node.id.to_string()));
    assert_array_map_record(&bare, &address);

    let missing = get_entity(
        &f.store,
        "external_reference:00000000-0000-8000-8000-000000000000",
    );
    assert_eq!(missing.is_error, Some(true));
}

#[test]
fn get_entity_lists_a_callers_proven_external_calls() {
    let f = external_store();
    let value = body(&get_entity(&f.store, &f.caller.id.to_string()));
    assert_eq!(value["name"], "render", "{value:#}");
    let calls = value["external_calls"].as_array().expect("external_calls");
    assert_eq!(calls.len(), 1, "{value:#}");
    assert_array_map_record(&calls[0], &f.address());
    assert_render_calls_array_map(&calls[0]);

    let helper = body(&get_entity(&f.store, &f.helper.id.to_string()));
    assert!(
        helper.get("external_calls").is_none(),
        "an entity with no external call carries no group: {helper:#}"
    );
}

#[test]
fn get_entity_source_refuses_an_external_symbol_without_reading_anything() {
    let f = external_store();
    for id in [f.address(), f.node.id.to_string()] {
        let result = handle_get_entity_source(
            &args(&[("entity_id", serde_json::json!(id))]),
            &f.store,
            None,
        )
        .unwrap();
        assert_eq!(result.is_error, Some(true), "{result:?}");
        let value = body(&result);
        assert_eq!(
            value["error"]["code"], EXTERNAL_SYMBOL_NO_SOURCE,
            "{value:#}"
        );
        let message = value["error"]["message"].as_str().unwrap();
        assert!(message.contains("Array.map"), "{message}");
        assert_eq!(value["error"]["id"], f.address(), "{value:#}");
    }

    let batch = body(
        &handle_get_entity_sources(
            &args(&[(
                "entity_ids",
                serde_json::json!([f.address(), f.caller.id.to_string()]),
            )]),
            &f.store,
            None,
        )
        .unwrap(),
    );
    let rows = batch["results"].as_array().expect("results");
    let external = rows
        .iter()
        .find(|row| row["id"] == f.address())
        .unwrap_or_else(|| panic!("no row for the external symbol: {batch:#}"));
    assert_eq!(
        external["reason"], EXTERNAL_SYMBOL_NO_SOURCE,
        "{external:#}"
    );
    assert!(external["body"].is_null(), "{external:#}");
}

#[tokio::test]
async fn find_references_lists_an_external_symbols_callers_with_their_sites() {
    let f = external_store();
    let address = f.address();
    let value = body(&find_references(&f.store, &address).await);
    assert_array_map_record(&value["focal_entity"], &address);
    assert_eq!(value["total_upstream"], 1, "{value:#}");
    assert_eq!(value["counts"]["referencing_entities"], 1, "{value:#}");
    assert_eq!(value["counts"]["reference_sites"], 2, "{value:#}");
    let rows = value["references"].as_array().expect("references");
    assert_eq!(rows.len(), 1, "{value:#}");
    let row = &rows[0];
    assert_eq!(row["entity_id"], f.caller.id.to_string(), "{row:#}");
    assert_eq!(row["name"], "render", "{row:#}");
    assert_eq!(
        row["relation_kinds"],
        serde_json::json!(["calls"]),
        "{row:#}"
    );
    assert_render_calls_array_map(row);

    // Restricted to a kind the symbol has no edge of, nothing is found.
    let imports = body(
        &handle_find_references(
            &args(&[
                ("entity_id", serde_json::json!(address)),
                ("relation_kinds", serde_json::json!(["imports"])),
            ]),
            &f.store,
            None,
        )
        .await
        .unwrap(),
    );
    assert_eq!(imports["total_upstream"], 0, "{imports:#}");
}

#[test]
fn graph_neighborhood_walks_from_a_caller_to_its_external_target_and_back() {
    let f = external_store();
    let address = f.address();

    let out = body(&neighborhood(&f.store, &f.caller.id.to_string(), "out"));
    let entities = out["entities"].as_array().expect("entities");
    let target = entities
        .iter()
        .find(|row| row["id"] == address)
        .unwrap_or_else(|| panic!("no external neighbor: {out:#}"));
    assert_array_map_record(target, &address);
    assert!(
        entities.iter().any(|row| row["name"] == "helper"),
        "the entity callee is still there: {out:#}"
    );
    let edge = out["relations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["to"] == address)
        .unwrap_or_else(|| panic!("no edge to the external neighbor: {out:#}"));
    assert_eq!(edge["kind"], "Calls", "{edge:#}");
    assert_eq!(edge["direction"], "outgoing", "{edge:#}");
    assert_eq!(edge["from"], f.caller.id.to_string(), "{edge:#}");
    assert_render_calls_array_map(edge);

    let back = body(&neighborhood(&f.store, &address, "in"));
    assert_eq!(back["focal_id"], address, "{back:#}");
    let rows = back["entities"].as_array().expect("entities");
    assert_array_map_record(&rows[0], &address);
    assert!(
        rows.iter().any(|row| row["id"] == f.caller.id.to_string()),
        "the caller is the symbol's neighbor: {back:#}"
    );
    let edge = &back["relations"][0];
    assert_eq!(edge["direction"], "incoming", "{edge:#}");
    assert_eq!(edge["from"], address, "{edge:#}");
    assert_render_calls_array_map(edge);
    assert_eq!(back["relation_count"], 1, "{back:#}");

    let nothing_out = body(&neighborhood(&f.store, &address, "out"));
    assert_eq!(nothing_out["relation_count"], 0, "{nothing_out:#}");
}

#[test]
fn get_context_pack_lists_the_focals_external_calls() {
    let f = external_store();
    let sessions = SessionRegistry::empty_for_test();
    let value = body(
        &handle_get_context_pack(
            &args(&[("entity_id", serde_json::json!(f.caller.id.to_string()))]),
            &f.store,
            &sessions,
            None,
        )
        .unwrap(),
    );
    let calls = value["external_calls"].as_array().expect("external_calls");
    assert_eq!(calls.len(), 1, "{value:#}");
    assert_array_map_record(&calls[0], &f.address());
    assert_render_calls_array_map(&calls[0]);
    assert_eq!(
        value["dependency_selection"]["external_calls_returned"], 1,
        "{value:#}"
    );
    assert!(
        value["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["name"] == "helper"),
        "the entity dependency is still a dependency: {value:#}"
    );
}

/// A pack cannot be built around a symbol outside the repository, and the
/// refusal names the tools that answer about it.
#[test]
fn get_context_pack_on_an_external_symbol_points_to_its_callers() {
    let f = external_store();
    let sessions = SessionRegistry::empty_for_test();
    let result = handle_get_context_pack(
        &args(&[("entity_id", serde_json::json!(f.address()))]),
        &f.store,
        &sessions,
        None,
    )
    .unwrap();
    assert_not_served(&result, "get_context_pack", "entity_id", &f.address());

    // `trace_computation` builds the same pack, and its refusal names itself.
    let traced = handle_trace_computation(
        &args(&[("entity_id", serde_json::json!(f.node.id.to_string()))]),
        &f.store,
        &sessions,
        None,
    )
    .unwrap();
    assert_not_served(&traced, "trace_computation", "entity_id", &f.address());
}

/// A pack built around several focals lists every focal's external calls,
/// each naming the focal that makes it.
#[test]
fn a_multi_focal_pack_lists_each_focals_external_calls() {
    let f = external_store();
    let sessions = SessionRegistry::empty_for_test();
    let value = body(
        &handle_get_context_pack(
            &args(&[
                (
                    "question_focals",
                    serde_json::json!([
                        {"entity_id": f.caller.id.to_string(), "route": "name", "query": "render"},
                        {"entity_id": f.helper.id.to_string(), "route": "name", "query": "helper"},
                    ]),
                ),
                ("depth", serde_json::json!(1)),
            ]),
            &f.store,
            &sessions,
            None,
        )
        .unwrap(),
    );
    let calls = value["external_calls"].as_array().expect("external_calls");
    assert_eq!(calls.len(), 1, "{value:#}");
    assert_array_map_record(&calls[0], &f.address());
    assert_render_calls_array_map(&calls[0]);
    assert_eq!(calls[0]["caller_id"], f.caller.id.to_string(), "{value:#}");
}

/// Beside other focals, an external `entity_id` is reported unresolved by
/// what it is, with the sentence and record a single-id pack refuses it
/// with, and the pack is built from the focals that are entities.
#[test]
fn a_multi_focal_pack_reports_an_external_entity_id_by_what_it_is() {
    let f = external_store();
    let sessions = SessionRegistry::empty_for_test();
    let value = body(
        &handle_get_context_pack(
            &args(&[
                ("entity_id", serde_json::json!(f.address())),
                (
                    "question_focals",
                    serde_json::json!([
                        {"entity_id": f.caller.id.to_string(), "route": "name", "query": "render"},
                    ]),
                ),
                ("depth", serde_json::json!(1)),
            ]),
            &f.store,
            &sessions,
            None,
        )
        .unwrap(),
    );
    let unresolved = value["unresolved"].as_array().expect("unresolved");
    assert_eq!(unresolved.len(), 1, "{value:#}");
    assert_eq!(unresolved[0]["query"], f.address(), "{value:#}");
    assert_eq!(
        unresolved[0]["reason"], "external_symbol_not_served",
        "{value:#}"
    );
    assert_array_map_record(&unresolved[0]["symbol"], &f.address());
    let detail = unresolved[0]["detail"].as_str().expect("detail");
    assert!(detail.contains("get_context_pack"), "{detail}");
    assert_eq!(value["external_calls"][0]["id"], f.address(), "{value:#}");
}

/// The daemon hands `entities` on as `question_focals`, and a symbol outside
/// the repository arrives there under its address. It is reported unresolved
/// by what it is, never dropped, and a pack of it alone is refused with that
/// row rather than built around nothing.
#[test]
fn a_question_focal_naming_an_external_symbol_is_reported_by_what_it_is() {
    let f = external_store();
    let sessions = SessionRegistry::empty_for_test();
    let external = serde_json::json!(
        {"entity_id": f.address(), "route": "id", "query": f.node.id.to_string()}
    );
    let value = body(
        &handle_get_context_pack(
            &args(&[
                (
                    "question_focals",
                    serde_json::json!([
                        external,
                        {"entity_id": f.caller.id.to_string(), "route": "name", "query": "render"},
                    ]),
                ),
                ("depth", serde_json::json!(1)),
            ]),
            &f.store,
            &sessions,
            None,
        )
        .unwrap(),
    );
    let unresolved = value["unresolved"].as_array().expect("unresolved");
    assert_eq!(unresolved.len(), 1, "{value:#}");
    assert_eq!(
        unresolved[0]["reason"], "external_symbol_not_served",
        "{value:#}"
    );
    assert_eq!(unresolved[0]["query"], f.node.id.to_string(), "{value:#}");
    assert_array_map_record(&unresolved[0]["symbol"], &f.address());

    let alone = handle_get_context_pack(
        &args(&[("question_focals", serde_json::json!([external]))]),
        &f.store,
        &sessions,
        None,
    )
    .unwrap();
    assert_eq!(alone.is_error, Some(true), "{alone:?}");
    let ContentBlock::Text { text } = &alone.content[0];
    assert!(text.contains("external_symbol_not_served"), "{text}");
    assert!(text.contains("Array.map"), "{text}");
}

/// A walk down the calls reaches the external symbol as a leaf step: named by
/// its address, marked external, stopped with `external_reference`, and
/// carrying the proof and sites the other surfaces carry. Every step keeps
/// one key set, the entity steps with the external keys null.
#[test]
fn trace_data_flow_reaches_an_external_call_as_a_leaf_step() {
    let f = external_store();
    let value = body(
        &handle_trace_data_flow(
            &args(&[
                ("focal", serde_json::json!(f.caller.id.to_string())),
                ("direction", serde_json::json!("calls")),
                ("depth", serde_json::json!(2)),
            ]),
            &f.store,
        )
        .unwrap(),
    );
    let steps = value["chain"].as_array().expect("chain");
    let external = steps
        .iter()
        .find(|step| step["entity_id"] == f.address())
        .unwrap_or_else(|| panic!("no external step: {value:#}"));
    assert_eq!(external["entity_name"], "Array.map", "{external:#}");
    assert_eq!(external["entity_kind"], "external_symbol", "{external:#}");
    assert_eq!(external["external"], true, "{external:#}");
    assert_eq!(external["terminal"], "external_reference", "{external:#}");
    assert_eq!(external["role"], "callee", "{external:#}");
    assert_eq!(external["relation_kind"], "Calls", "{external:#}");
    assert_eq!(external["parent_step"], 0, "{external:#}");
    assert!(external["entity_file"].is_null(), "{external:#}");
    assert!(external["start_line"].is_null(), "{external:#}");
    assert_eq!(
        external["reference_lines"],
        serde_json::json!([]),
        "{external:#}"
    );
    assert_eq!(
        external["reference_lines_absent_reason"], "sites_in_entity",
        "{external:#}"
    );
    assert_eq!(
        external["package"],
        serde_json::json!({"manager": "npm", "name": "typescript", "version": "5.6.3"}),
        "{external:#}"
    );
    assert_eq!(external["stdlib"], true, "{external:#}");
    assert_eq!(
        external["symbol"], "`lib.es5.d.ts`/Array#map().",
        "{external:#}"
    );
    assert_render_calls_array_map(external);

    let helper = steps
        .iter()
        .find(|step| step["entity_name"] == "helper")
        .unwrap_or_else(|| panic!("the entity callee is still a step: {value:#}"));
    for key in [
        "package",
        "stdlib",
        "symbol",
        "site_state",
        "proof",
        "sites",
    ] {
        assert!(helper[key].is_null(), "{key} on an entity step: {helper:#}");
    }
    let expected: Vec<&String> = steps[0].as_object().unwrap().keys().collect();
    for step in steps {
        let keys: Vec<&String> = step.as_object().unwrap().keys().collect();
        assert_eq!(keys, expected, "every step carries one key set: {step:#}");
    }

    // Walked the other way, nothing outside the repository calls into it.
    let callers = body(
        &handle_trace_data_flow(
            &args(&[
                ("focal", serde_json::json!(f.caller.id.to_string())),
                ("direction", serde_json::json!("callers")),
            ]),
            &f.store,
        )
        .unwrap(),
    );
    assert!(!callers.to_string().contains(&f.address()), "{callers:#}");
}

/// Every string an answer emits that names an external symbol.
fn external_addresses(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) if text.starts_with("external_reference:") => {
            out.push(text.clone());
        }
        serde_json::Value::Array(items) => {
            for item in items {
                external_addresses(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                external_addresses(item, out);
            }
        }
        _ => {}
    }
}

#[tokio::test]
async fn every_external_address_any_answer_emits_is_one_the_id_tools_accept() {
    let f = external_store();
    let sessions = SessionRegistry::empty_for_test();
    let caller = f.caller.id.to_string();
    let address = f.address();
    let answers = vec![
        body(&get_entity(&f.store, &caller)),
        body(&get_entity(&f.store, &address)),
        body(&find_references(&f.store, &address).await),
        body(&neighborhood(&f.store, &caller, "both")),
        body(&neighborhood(&f.store, &address, "both")),
        body(
            &handle_trace_data_flow(
                &args(&[
                    ("focal", serde_json::json!(caller)),
                    ("direction", serde_json::json!("calls")),
                ]),
                &f.store,
            )
            .unwrap(),
        ),
        body(
            &handle_get_context_pack(
                &args(&[("entity_id", serde_json::json!(caller))]),
                &f.store,
                &sessions,
                None,
            )
            .unwrap(),
        ),
    ];
    let mut emitted = Vec::new();
    for answer in &answers {
        external_addresses(answer, &mut emitted);
    }
    emitted.sort();
    emitted.dedup();
    assert_eq!(emitted, vec![address.clone()]);
    for id in &emitted {
        assert_ne!(
            get_entity(&f.store, id).is_error,
            Some(true),
            "get_entity {id}"
        );
        assert_ne!(
            find_references(&f.store, id).await.is_error,
            Some(true),
            "find_references {id}"
        );
        assert_ne!(
            neighborhood(&f.store, id, "both").is_error,
            Some(true),
            "graph_neighborhood {id}"
        );
    }
    // No answer serves a location for the external declaration: there is none.
    for answer in answers {
        let text = answer.to_string();
        assert!(!text.contains("file://"), "{text}");
        assert!(!text.contains("node_modules"), "{text}");
    }
}

/// Through the server's own chokepoint, where every answer is wrapped in the
/// `_kin` envelope and read by the verdict: an answer about an external symbol
/// keeps its shape there and the refusal stays a refusal.
#[tokio::test]
async fn external_answers_survive_the_envelope_and_verdict() {
    let f = external_store();
    let config = crate::server::McpServerConfig {
        session_authority_mode: crate::server::SessionAuthorityMode::OfflineFallback,
        ..Default::default()
    };
    let sessions = SessionRegistry::new();
    let address = f.address();
    let call = |tool: &'static str, arguments: serde_json::Value| {
        let message = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        })
        .to_string();
        let store = &f.store;
        let config = &config;
        let sessions = &sessions;
        async move {
            let response = crate::server::process_message(&message, store, config, sessions)
                .await
                .expect("a response");
            assert!(response.error.is_none(), "{tool}: {response:?}");
            let result: ToolCallResult =
                serde_json::from_value(response.result.expect("a result")).unwrap();
            (result.is_error, body(&result))
        }
    };

    let (error, value) = call("get_entity", serde_json::json!({"entity_id": address})).await;
    assert_ne!(error, Some(true), "{value:#}");
    assert_array_map_record(&value, &address);
    assert!(
        value.get(crate::envelope::ENVELOPE_KEY).is_some(),
        "{value:#}"
    );

    let (error, value) = call("find_references", serde_json::json!({"entity_id": address})).await;
    assert_ne!(error, Some(true), "{value:#}");
    assert_eq!(value["total_upstream"], 1, "{value:#}");
    assert_eq!(
        value["_kin"]["verdict"]["safe_to_conclude_absent"], false,
        "the callers a resolver proved are a floor, never a certified whole: {value:#}"
    );
    let notes = value[crate::envelope::ENVELOPE_KEY].to_string();
    assert!(
        !notes.contains("cross_repo_authority_unknown"),
        "an external focal is not an unknown cross-repo state: {notes}"
    );

    let (error, value) = call(
        "graph_neighborhood",
        serde_json::json!({"entity_id": f.caller.id.to_string(), "direction": "out", "depth": 1}),
    )
    .await;
    assert_ne!(error, Some(true), "{value:#}");
    assert!(
        value["entities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == address),
        "{value:#}"
    );

    let (error, value) = call(
        "get_context_pack",
        serde_json::json!({"entity_id": f.caller.id.to_string()}),
    )
    .await;
    assert_ne!(error, Some(true), "{value:#}");
    assert_eq!(value["external_calls"][0]["id"], address, "{value:#}");

    let (error, value) = call(
        "get_entity_source",
        serde_json::json!({"entity_id": address}),
    )
    .await;
    assert_eq!(error, Some(true), "{value:#}");
    assert!(
        value.to_string().contains(EXTERNAL_SYMBOL_NO_SOURCE),
        "{value:#}"
    );
}

/// The one refusal a tool that answers about repository entities gives a
/// symbol outside the repository, whichever tool it is: the shared code, the
/// tool and argument that met it, the symbol's record with its caller count,
/// the tools that do answer about it, and a sentence that never reads as a
/// miss.
fn assert_not_served(
    result: &ToolCallResult,
    tool: &str,
    argument: &str,
    address: &str,
) -> serde_json::Value {
    assert_eq!(result.is_error, Some(true), "{tool}: {result:?}");
    let value = body(result);
    let error = &value["error"];
    assert_eq!(error["code"], "external_symbol_not_served", "{value:#}");
    assert_eq!(error["tool"], tool, "{value:#}");
    assert_eq!(error["argument"], argument, "{value:#}");
    assert_eq!(error["id"], address, "{value:#}");
    assert_array_map_record(&error["symbol"], address);
    assert_eq!(error["symbol"]["caller_count"], 1, "{value:#}");
    assert_eq!(
        error["served_by"],
        serde_json::json!(["get_entity", "find_references", "graph_neighborhood"]),
        "{value:#}"
    );
    let message = error["message"].as_str().expect("a message");
    assert!(message.contains("Array.map"), "{message}");
    assert!(message.contains(tool), "{message}");
    assert!(message.contains("find_references"), "{message}");
    let lower = message.to_lowercase();
    assert!(
        !lower.contains("not found") && !lower.contains("no entity"),
        "a symbol the graph holds is never reported missing: {message}"
    );
    value
}

/// What a tool answers for an `external_reference:` address this graph holds
/// no symbol under: the absence `get_entity` reports, never an invalid id.
fn assert_unknown_address(result: &ToolCallResult, tool: &str) {
    assert_eq!(result.is_error, Some(true), "{tool}: {result:?}");
    let ContentBlock::Text { text } = &result.content[0];
    assert!(
        text.contains("External symbol not found: external_reference:"),
        "{tool}: {text}"
    );
}

const UNKNOWN_ADDRESS: &str = "external_reference:00000000-0000-8000-8000-000000000000";

fn ok_or_panic(tool: &str, result: crate::error::Result<ToolCallResult>) -> ToolCallResult {
    result.unwrap_or_else(|error| panic!("{tool} failed instead of answering: {error}"))
}

/// A change to a symbol outside the repository is not a change this graph can
/// analyze, and saying the id is invalid or missing would read as an absence.
/// `impact_analysis`, `semantic_review` and `semantic_diff` refuse it by what
/// it is, alone or beside a repository entity, by its address or its bare id.
#[tokio::test]
async fn change_tools_refuse_an_external_symbol_by_what_it_is() {
    let f = external_store();
    let sessions = SessionRegistry::empty_for_test();
    let address = f.address();
    for ids in [
        vec![address.clone()],
        vec![f.node.id.to_string()],
        vec![f.caller.id.to_string(), address.clone()],
    ] {
        let arguments = args(&[("entity_ids", serde_json::json!(ids))]);
        let impact = ok_or_panic(
            "impact_analysis",
            super::review::handle_impact_analysis(&arguments, &f.store, &sessions).await,
        );
        assert_not_served(&impact, "impact_analysis", "entity_ids", &address);
        let review = ok_or_panic(
            "semantic_review",
            super::review::handle_semantic_review(&arguments, &f.store, &sessions),
        );
        assert_not_served(&review, "semantic_review", "entity_ids", &address);
        let diff = ok_or_panic(
            "semantic_diff",
            super::review::handle_semantic_diff(&arguments, &f.store),
        );
        assert_not_served(&diff, "semantic_diff", "entity_ids", &address);
    }
    let unknown = args(&[("entity_ids", serde_json::json!([UNKNOWN_ADDRESS]))]);
    assert_unknown_address(
        &ok_or_panic(
            "impact_analysis",
            super::review::handle_impact_analysis(&unknown, &f.store, &sessions).await,
        ),
        "impact_analysis",
    );
}

/// `entity_history`, `kin_verify_entity` and `kin_provenance_query` read an
/// entity's revisions, linked tests and recorded changes, which a symbol
/// outside the repository has none of here.
#[test]
fn history_and_verification_refuse_an_external_symbol_by_what_it_is() {
    let f = external_store();
    let address = f.address();
    for id in [address.clone(), f.node.id.to_string()] {
        let arguments = args(&[("entity_id", serde_json::json!(id))]);
        let history = ok_or_panic(
            "entity_history",
            super::review::handle_entity_history(&arguments, &f.store),
        );
        assert_not_served(&history, "entity_history", "entity_id", &address);
        let verify = ok_or_panic(
            "kin_verify_entity",
            super::verification::handle_verify_entity(&arguments, &f.store),
        );
        assert_not_served(&verify, "kin_verify_entity", "entity_id", &address);
        let provenance = ok_or_panic(
            "kin_provenance_query",
            super::provenance::handle_provenance_query(&arguments, &f.store),
        );
        assert_not_served(&provenance, "kin_provenance_query", "entity_id", &address);
    }
    let unknown = args(&[("entity_id", serde_json::json!(UNKNOWN_ADDRESS))]);
    assert_unknown_address(
        &ok_or_panic(
            "entity_history",
            super::review::handle_entity_history(&unknown, &f.store),
        ),
        "entity_history",
    );
    assert_unknown_address(
        &ok_or_panic(
            "kin_verify_entity",
            super::verification::handle_verify_entity(&unknown, &f.store),
        ),
        "kin_verify_entity",
    );
}

/// A walk cannot start from a symbol whose body and edges are outside the
/// repository. `trace_data_flow` refuses it as a focal rather than reporting
/// no entity, and names the tools that list its callers.
#[test]
fn trace_data_flow_refuses_an_external_focal_by_what_it_is() {
    let f = external_store();
    let address = f.address();
    for id in [address.clone(), f.node.id.to_string()] {
        let result = ok_or_panic(
            "trace_data_flow",
            handle_trace_data_flow(&args(&[("focal", serde_json::json!(id))]), &f.store),
        );
        assert_not_served(&result, "trace_data_flow", "focal", &address);
    }
}

/// A route runs between repository entities. Either end naming a symbol
/// outside the repository is refused by what it is, on the MCP tool and on
/// the walk `kin path` reaches through the daemon.
#[test]
fn trace_path_refuses_an_external_end_by_what_it_is() {
    let f = external_store();
    let address = f.address();
    let caller = f.caller.id.to_string();
    for (from, to, end) in [
        (caller.clone(), address.clone(), "to"),
        (address.clone(), caller.clone(), "from"),
        (caller.clone(), f.node.id.to_string(), "to"),
    ] {
        let arguments = args(&[
            ("from", serde_json::json!(from)),
            ("to", serde_json::json!(to)),
        ]);
        let result = ok_or_panic(
            "trace_path",
            super::path::handle_trace_path(&arguments, &f.store),
        );
        assert_not_served(&result, "trace_path", end, &address);

        let request = super::path::request_from_args(&arguments).unwrap();
        let error = match super::path::build_path_response(&f.store, &request) {
            Ok(response) => panic!("a route was walked to {address}: {response:?}"),
            Err(error) => error,
        };
        assert!(
            !error.is_resolution_miss(),
            "a symbol the graph holds is not a miss: {error}"
        );
        let text = error.to_string();
        assert!(text.contains("Array.map"), "{text}");
        assert!(text.contains("find_references"), "{text}");
        assert!(!text.to_lowercase().contains("no entity"), "{text}");
    }
}

/// `bulk_check_references` classifies repository entities. An external id in
/// the batch gets a row that says what it is and which tool lists its
/// callers, in the shape every other error row has, and the rows beside it
/// are classified as before.
#[test]
fn bulk_check_references_names_an_external_symbol_in_its_row() {
    let f = external_store();
    let address = f.address();
    for compact in [true, false] {
        let value = body(&ok_or_panic(
            "bulk_check_references",
            super::entities::handle_bulk_check_references(
                &args(&[
                    (
                        "entity_ids",
                        serde_json::json!([
                            address,
                            f.node.id.to_string(),
                            f.helper.id.to_string()
                        ]),
                    ),
                    ("compact", serde_json::json!(compact)),
                ]),
                &f.store,
            ),
        ));
        let rows = value["results"].as_array().expect("results");
        for row in &rows[..2] {
            assert_eq!(row["error"], "external_symbol_not_served", "{row:#}");
            assert!(row["has_references"].is_null(), "{row:#}");
            assert_eq!(row["verdict_complete"], false, "{row:#}");
            assert_array_map_record(&row["symbol"], &address);
            let detail = row["detail"].as_str().expect("detail");
            assert!(detail.contains("Array.map"), "{detail}");
            assert!(detail.contains("find_references"), "{detail}");
        }
        assert_eq!(rows[2]["has_references"], true, "{value:#}");
        assert_eq!(value["error_count"], 2, "{value:#}");
    }
}

/// An annotation is anchored to a repository entity. Given a symbol outside
/// the repository, by any spelling, or an entity id this graph holds nothing
/// under, `kin_annotation_add` refuses and writes nothing, rather than storing
/// an annotation no entity will ever recall.
#[test]
fn annotation_add_refuses_an_external_symbol_and_an_unheld_entity() {
    use kin_model::WorkStore;
    let f = external_store();
    let address = f.address();
    let add = |target: String| {
        super::work::handle_annotation_add(
            &args(&[
                ("kind", serde_json::json!("warning")),
                ("body", serde_json::json!("never call this in a loop")),
                ("targets", serde_json::json!([target])),
            ]),
            &f.store,
        )
    };
    for target in [
        address.clone(),
        format!("entity:{}", f.node.id),
        f.node.id.to_string(),
    ] {
        let result = ok_or_panic("kin_annotation_add", add(target));
        assert_not_served(&result, "kin_annotation_add", "targets", &address);
    }
    let unheld = kin_model::EntityId::new();
    let result = ok_or_panic("kin_annotation_add", add(format!("entity:{unheld}")));
    assert_eq!(result.is_error, Some(true), "{result:?}");
    let value = body(&result);
    assert_eq!(value["error"]["code"], "entity_not_in_graph", "{value:#}");
    assert_eq!(value["error"]["id"], unheld.to_string(), "{value:#}");
    assert!(
        f.store
            .list_annotations(&kin_model::AnnotationFilter {
                include_stale: true,
                ..Default::default()
            })
            .unwrap()
            .is_empty(),
        "a refused target writes nothing"
    );

    // A held entity is annotated as before.
    let written = ok_or_panic("kin_annotation_add", add(format!("entity:{}", f.caller.id)));
    assert_ne!(written.is_error, Some(true), "{written:?}");
}

/// A review is scoped to repository entities. `kin_review_create` refuses a
/// symbol outside the repository in `entity_ids` by what it is, where its
/// address would otherwise be stored as a file path and its bare id as an
/// entity no review reaches, and writes nothing.
#[test]
fn review_create_refuses_an_external_symbol_rather_than_storing_it_as_a_path() {
    use kin_model::ReviewStore;
    let f = external_store();
    for id in [f.address(), f.node.id.to_string()] {
        let result = super::review::handle_review_create(
            &args(&[
                ("title", serde_json::json!("map callers")),
                ("entity_ids", serde_json::json!([id])),
            ]),
            &f.store,
        );
        let message = match result {
            Ok(answer) => panic!("{id} was scoped into a review: {answer:?}"),
            Err(error) => error.to_string(),
        };
        assert!(message.contains("Array.map"), "{message}");
        assert!(message.contains("kin_review_create"), "{message}");
        assert!(message.contains("find_references"), "{message}");
    }
    let unknown = super::review::handle_review_create(
        &args(&[
            ("title", serde_json::json!("map callers")),
            ("entity_ids", serde_json::json!([UNKNOWN_ADDRESS])),
        ]),
        &f.store,
    );
    let message = match unknown {
        Ok(answer) => panic!("an unknown address was scoped into a review: {answer:?}"),
        Err(error) => error.to_string(),
    };
    assert!(message.contains("External symbol not found"), "{message}");
    assert!(
        f.store
            .list_reviews(&kin_model::ReviewFilter::default())
            .unwrap()
            .is_empty(),
        "a refused review writes nothing"
    );
}

/// The cohesion rule, through the server's own chokepoint: no tool that takes
/// an entity id answers a symbol the graph holds with "not found" or an
/// invalid id. It answers about the symbol or refuses by what it is.
#[tokio::test]
async fn no_id_tool_reports_a_held_external_symbol_missing() {
    let f = external_store();
    let config = crate::server::McpServerConfig {
        session_authority_mode: crate::server::SessionAuthorityMode::OfflineFallback,
        ..Default::default()
    };
    let sessions = SessionRegistry::new();
    let address = f.address();
    let caller = f.caller.id.to_string();
    let calls: Vec<(&str, serde_json::Value)> = vec![
        ("get_entity", serde_json::json!({"entity_id": address})),
        (
            "get_entity_source",
            serde_json::json!({"entity_id": address}),
        ),
        ("find_references", serde_json::json!({"entity_id": address})),
        (
            "graph_neighborhood",
            serde_json::json!({"entity_id": address}),
        ),
        (
            "get_context_pack",
            serde_json::json!({"entity_id": address}),
        ),
        (
            "trace_computation",
            serde_json::json!({"entity_id": address}),
        ),
        ("trace_data_flow", serde_json::json!({"focal": address})),
        (
            "trace_path",
            serde_json::json!({"from": caller, "to": address}),
        ),
        (
            "impact_analysis",
            serde_json::json!({"entity_ids": [address]}),
        ),
        (
            "semantic_review",
            serde_json::json!({"entity_ids": [address]}),
        ),
        (
            "semantic_diff",
            serde_json::json!({"entity_ids": [address]}),
        ),
        ("entity_history", serde_json::json!({"entity_id": address})),
        (
            "kin_verify_entity",
            serde_json::json!({"entity_id": address}),
        ),
        (
            "kin_provenance_query",
            serde_json::json!({"entity_id": address}),
        ),
        (
            "bulk_check_references",
            serde_json::json!({"entity_ids": [address]}),
        ),
    ];
    for (tool, arguments) in calls {
        let message = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        })
        .to_string();
        let response = crate::server::process_message(&message, &f.store, &config, &sessions)
            .await
            .expect("a response");
        assert!(response.error.is_none(), "{tool}: {response:?}");
        let result: ToolCallResult =
            serde_json::from_value(response.result.expect("a result")).unwrap();
        let mut answer = body(&result);
        if let Some(object) = answer.as_object_mut() {
            object.remove(crate::envelope::ENVELOPE_KEY);
        }
        let text = answer.to_string().to_lowercase();
        for miss in ["not found", "no entity", "invalid entity_id", "not a uuid"] {
            assert!(!text.contains(miss), "{tool} said {miss:?}: {text}");
        }
        if result.is_error == Some(true) {
            assert!(
                text.contains("external_symbol_not_served")
                    || text.contains("external_symbol_has_no_repository_source"),
                "{tool} refused without the shared code: {text}"
            );
        }
    }
}
