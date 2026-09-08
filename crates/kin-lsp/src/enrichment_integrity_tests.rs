// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::enrichment::{self, EntityIndex, EntityRef};
use crate::lifecycle::LspServer;
use crate::{LspError, Result};
use kin_model::{EntityId, GraphNodeId, Relation, RelationKind};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

const PEER: &str = include_str!("enrichment_test_peer.py");
const PREPARE_CALL: &str = "textDocument/prepareCallHierarchy";
const CALLS: &str = "callHierarchy/outgoingCalls";
const PREPARE_TYPE: &str = "textDocument/prepareTypeHierarchy";
const SUPERTYPES: &str = "typeHierarchy/supertypes";
const REFERENCES: &str = "textDocument/references";
const TYPES: &str = "textDocument/typeDefinition";
const DEFINITION: &str = "textDocument/definition";

struct Fixture {
    root: PathBuf,
    source: EntityRef,
    target: EntityRef,
    index: EntityIndex,
}

impl Fixture {
    fn new(projected: Option<&str>) -> Self {
        let root = std::env::temp_dir().join(format!("kin-lsp-integrity-{}", EntityId::new()));
        std::fs::create_dir(&root).unwrap();
        if let Some(text) = projected {
            std::fs::write(root.join("source.py"), text).unwrap();
        }
        let entity = |name: &str, file: &str, line| EntityRef {
            id: EntityId::new(),
            name: name.into(),
            file_path: file.into(),
            start_line: line,
            start_col: 0,
            end_line: line,
            name_line: line,
            name_col: 0,
        };
        let source = entity("Caller.run", "source.py", 0);
        let target = entity("Base.run", "types.py", 10);
        let index = EntityIndex::new(vec![source.clone(), target.clone()]);
        Self {
            root,
            source,
            target,
            index,
        }
    }

    fn responses(&self) -> Value {
        let range = |line| json!({"start": {"line": line, "character": 0}, "end": {"line": line, "character": 4}});
        let item = |entity: &EntityRef| {
            json!({
                "name": entity.name, "kind": 6,
                "uri": crate::protocol::path_to_uri(&self.root.join(&entity.file_path)),
                "range": range(entity.start_line), "selectionRange": range(entity.start_line),
            })
        };
        let location = json!({
            "uri": crate::protocol::path_to_uri(&self.root.join(&self.target.file_path)),
            "range": range(self.target.start_line),
        });
        let mut parent = item(&self.target);
        parent["name"] = json!("Base");
        json!({
            PREPARE_CALL: {"result": [item(&self.source)]},
            CALLS: {"result": [{"to": item(&self.target), "fromRanges": [range(0)]}]},
            PREPARE_TYPE: {"result": [item(&self.source)]},
            SUPERTYPES: {"result": [parent]},
            REFERENCES: {"result": [location.clone()]},
            TYPES: {"result": [location.clone()]},
            DEFINITION: {"result": [location]},
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

async fn seen(server: &LspServer) -> Vec<Value> {
    serde_json::from_value(
        server
            .client
            .request("test/seen", Value::Null)
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn query(server: &LspServer, fixture: &Fixture, method: &str) -> Result<Vec<Relation>> {
    match method {
        PREPARE_CALL | CALLS => {
            enrichment::enrich_entity_calls(server, &fixture.source, &fixture.index, &fixture.root)
                .await
        }
        PREPARE_TYPE | SUPERTYPES => {
            enrichment::enrich_entity_overrides(
                server,
                &fixture.source,
                &fixture.index,
                &fixture.root,
            )
            .await
        }
        REFERENCES => {
            enrichment::enrich_entity_references(
                server,
                &fixture.source,
                &fixture.index,
                &fixture.root,
            )
            .await
        }
        TYPES => {
            enrichment::enrich_entity_uses_type(
                server,
                &fixture.source,
                &fixture.index,
                &fixture.root,
                Some(&|_| Some("Widget".into())),
            )
            .await
        }
        DEFINITION => crate::file_enrichment::enrich_file_definitions(
            server,
            &fixture.root.join("source.py"),
            "Widget",
            &fixture.index,
            &fixture.root,
            None,
        )
        .await
        .map(|answer| answer.relations),
        _ => unreachable!(),
    }
}

async fn rejected_response(method: &str, malformed: bool) {
    let f = Fixture::new(Some("Widget"));
    let mut responses = f.responses();
    responses[method] = if malformed {
        json!({"result": {"unexpected": true}})
    } else {
        json!({"error": {"code": -32603, "message": "injected integrity failure"}})
    };
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = query(&server, &f, method).await;
    let requests = seen(&server).await;
    assert_eq!(
        requests
            .iter()
            .filter(|request| request["method"] == method)
            .count(),
        1,
        "the actual failing RPC must be received"
    );
    assert!(
        answer.is_err(),
        "{method} must preserve failure instead of returning an empty success: {answer:?}"
    );
    if !malformed {
        assert!(matches!(answer, Err(LspError::JsonRpc(_))));
    }
}

macro_rules! rejects {
    ($error:ident, $malformed:ident, $method:expr) => {
        #[tokio::test]
        async fn $error() {
            rejected_response($method, false).await;
        }
        #[tokio::test]
        async fn $malformed() {
            rejected_response($method, true).await;
        }
    };
}
rejects!(call_prepare_rpc_error, call_prepare_malformed, PREPARE_CALL);
rejects!(outgoing_rpc_error, outgoing_malformed, CALLS);
rejects!(type_prepare_rpc_error, type_prepare_malformed, PREPARE_TYPE);
rejects!(supertypes_rpc_error, supertypes_malformed, SUPERTYPES);
rejects!(references_rpc_error, references_malformed, REFERENCES);
rejects!(uses_type_rpc_error, uses_type_malformed, TYPES);
rejects!(
    file_definition_rpc_error,
    file_definition_malformed,
    DEFINITION
);

#[tokio::test]
async fn successful_answers_keep_named_relations() {
    let f = Fixture::new(Some("Widget"));
    for (method, kind, reverse) in [
        (CALLS, RelationKind::Calls, false),
        (SUPERTYPES, RelationKind::Overrides, false),
        (REFERENCES, RelationKind::References, true),
        (TYPES, RelationKind::UsesType, false),
    ] {
        let server = LspServer::scripted_for_tests(PEER, f.responses());
        let relations = query(&server, &f, method).await.unwrap();
        let (src, dst) = if reverse {
            (f.target.id, f.source.id)
        } else {
            (f.source.id, f.target.id)
        };
        assert!(
            relations.iter().any(|r| r.kind == kind
                && r.src == GraphNodeId::Entity(src)
                && r.dst == GraphNodeId::Entity(dst)),
            "{method}: named edge missing"
        );
        assert!(seen(&server)
            .await
            .iter()
            .any(|request| request["method"] == method));
    }
}

#[tokio::test]
async fn successful_empty_and_unsupported_answers_remain_distinct_from_failure() {
    let f = Fixture::new(Some("Widget"));
    for method in [
        PREPARE_CALL,
        CALLS,
        PREPARE_TYPE,
        SUPERTYPES,
        REFERENCES,
        TYPES,
    ] {
        for empty in [json!([]), Value::Null] {
            let mut responses = f.responses();
            responses[method] = json!({"result": empty});
            let server = LspServer::scripted_for_tests(PEER, responses);
            assert!(
                query(&server, &f, method).await.unwrap().is_empty(),
                "{method}"
            );
            assert!(seen(&server)
                .await
                .iter()
                .any(|request| request["method"] == method));
        }
        let mut server = LspServer::scripted_for_tests(PEER, f.responses());
        server.capabilities = Default::default();
        assert!(query(&server, &f, method).await.unwrap().is_empty());
        assert!(
            seen(&server).await.is_empty(),
            "unsupported capability must make no request"
        );
    }
}

async fn uses_graph_source(projected: Option<&str>) {
    let f = Fixture::new(projected);
    let server = LspServer::scripted_for_tests(PEER, f.responses());
    let asked = AtomicUsize::new(0);
    let provider = |path: &str| {
        assert_eq!(path, "source.py");
        asked.fetch_add(1, Ordering::SeqCst);
        Some("Widget".to_owned())
    };
    let relations =
        enrichment::enrich_entity_uses_type(&server, &f.source, &f.index, &f.root, Some(&provider))
            .await
            .unwrap();
    assert_eq!(
        asked.load(Ordering::SeqCst),
        1,
        "primary text must come from repository authority"
    );
    assert!(
        relations
            .iter()
            .any(|r| r.kind == RelationKind::UsesType && r.dst == GraphNodeId::Entity(f.target.id)),
        "canonical text must yield the known edge"
    );
    let requests = seen(&server).await;
    assert!(requests.iter().any(
        |request| request["method"] == TYPES && request["params"]["position"]["character"] == 0
    ));
}

#[tokio::test]
async fn uses_type_with_absent_projection() {
    uses_graph_source(None).await;
}
#[tokio::test]
async fn uses_type_with_conflicting_projection() {
    uses_graph_source(Some("// stale projection")).await;
}

#[tokio::test]
async fn missing_graph_source_is_an_explicit_gap() {
    let f = Fixture::new(Some("Widget"));
    for provider in [
        None,
        Some(&(|_: &str| None) as enrichment::DocumentProvider<'_>),
    ] {
        let server = LspServer::scripted_for_tests(PEER, f.responses());
        let answer =
            enrichment::enrich_entity_uses_type(&server, &f.source, &f.index, &f.root, provider)
                .await;
        assert!(
            answer.is_err(),
            "projected bytes cannot fill missing graph text"
        );
        assert!(
            seen(&server).await.is_empty(),
            "no type query without authoritative positions"
        );
    }
}

#[tokio::test]
async fn valid_location_shapes_keep_the_selection_target() {
    let f = Fixture::new(Some("Widget"));
    let location = f.responses()[TYPES]["result"][0].clone();
    let mut wide_range = location["range"].clone();
    wide_range["start"]["line"] = json!(0);
    let link = json!({"targetUri": location["uri"], "targetRange": wide_range, "targetSelectionRange": location["range"]});
    for method in [TYPES, DEFINITION] {
        for shape in [
            location.clone(),
            json!([location.clone()]),
            json!([link.clone()]),
        ] {
            let mut responses = f.responses();
            responses[method] = json!({"result": shape});
            let mut server = LspServer::scripted_for_tests(PEER, responses);
            server.capabilities.call_hierarchy_provider = None;
            let answer = query(&server, &f, method).await.unwrap();
            assert_eq!(answer.len(), 1, "{method}");
            assert_eq!(answer[0].dst, GraphNodeId::Entity(f.target.id));
            assert_eq!(answer[0].src, GraphNodeId::Entity(f.source.id));
        }
    }
}

#[tokio::test]
async fn a_failed_cross_file_join_closes_its_opened_document() {
    let mut f = Fixture::new(None);
    f.target.name = "run".into();
    f.index = EntityIndex::new(vec![f.source.clone(), f.target.clone()]);
    let candidate_uri = crate::protocol::path_to_uri(&f.root.join(&f.target.file_path));
    for file_pass in [false, true] {
        let mut responses = f.responses();
        responses[format!("{DEFINITION}@{candidate_uri}#0")] =
            json!({"error": {"code": -32603, "message": "candidate query failed"}});
        let server = LspServer::scripted_for_tests(PEER, responses);
        let provider = |path: &str| match path {
            "source.py" => Some("module.run".into()),
            "types.py" => Some("run".into()),
            _ => None,
        };
        let answer = if file_pass {
            crate::file_enrichment::enrich_file_definitions(
                &server,
                &f.root.join("source.py"),
                "module.run",
                &f.index,
                &f.root,
                Some(&provider),
            )
            .await
            .map(|answer| answer.relations)
        } else {
            enrichment::enrich_entity_uses_type(
                &server,
                &f.source,
                &f.index,
                &f.root,
                Some(&provider),
            )
            .await
        };
        let messages = seen(&server).await;
        assert!(
            messages.iter().any(|m| m["method"] == DEFINITION
                && m["params"]["textDocument"]["uri"] == candidate_uri),
            "candidate failure must actually execute"
        );
        assert!(matches!(answer, Err(LspError::JsonRpc(_))), "{answer:?}");
        let lifecycle: Vec<_> = messages
            .iter()
            .filter(|m| {
                ["textDocument/didOpen", "textDocument/didClose"]
                    .iter()
                    .any(|method| m["method"] == *method)
            })
            .map(|m| m["method"].as_str().unwrap())
            .collect();
        assert_eq!(lifecycle, ["textDocument/didOpen", "textDocument/didClose"]);
    }
}

#[tokio::test]
async fn explicit_false_capabilities_do_not_query() {
    let f = Fixture::new(Some("Widget"));
    let mut server = LspServer::scripted_for_tests(PEER, f.responses());
    server.capabilities = serde_json::from_value(json!({
        "callHierarchyProvider": false, "typeHierarchyProvider": false,
        "typeDefinitionProvider": false, "referencesProvider": false,
        "definitionProvider": false,
    }))
    .unwrap();
    for method in [CALLS, SUPERTYPES, REFERENCES, TYPES, DEFINITION] {
        assert!(
            query(&server, &f, method).await.unwrap().is_empty(),
            "{method}"
        );
    }
    assert!(
        seen(&server).await.is_empty(),
        "disabled capabilities must send no RPC"
    );
}

#[tokio::test]
async fn unsupported_definition_keeps_supported_calls() {
    let f = Fixture::new(Some("Widget"));
    let mut server = LspServer::scripted_for_tests(PEER, f.responses());
    server.capabilities.definition_provider = None;
    let result = crate::file_enrichment::enrich_file_definitions(
        &server,
        &f.root.join("source.py"),
        "Widget",
        &f.index,
        &f.root,
        None,
    )
    .await
    .unwrap();
    assert!(result
        .relations
        .iter()
        .any(|r| r.kind == RelationKind::Calls && r.dst == GraphNodeId::Entity(f.target.id)));
    assert_eq!(result.positions_queried, 0);
    let requests = seen(&server).await;
    assert!(requests.iter().any(|m| m["method"] == CALLS));
    assert!(!requests.iter().any(|m| m["method"] == DEFINITION));
}

#[tokio::test]
async fn cancelled_join_closes_before_next_request() {
    let mut f = Fixture::new(None);
    f.target.name = "run".into();
    f.index = EntityIndex::new(vec![f.source.clone(), f.target.clone()]);
    let candidate_uri = crate::protocol::path_to_uri(&f.root.join(&f.target.file_path));
    for file_pass in [false, true] {
        let mut responses = f.responses();
        responses[format!("{DEFINITION}@{candidate_uri}#0")] = json!({"hold": true});
        let server = LspServer::scripted_for_tests(PEER, responses);
        let provider = |path: &str| match path {
            "source.py" => Some("module.run".into()),
            "types.py" => Some("run".into()),
            _ => None,
        };
        let mut pass = Box::pin(async {
            if file_pass {
                crate::file_enrichment::enrich_file_definitions(
                    &server,
                    &f.root.join("source.py"),
                    "module.run",
                    &f.index,
                    &f.root,
                    Some(&provider),
                )
                .await
                .map(|answer| answer.relations)
            } else {
                enrichment::enrich_entity_uses_type(
                    &server,
                    &f.source,
                    &f.index,
                    &f.root,
                    Some(&provider),
                )
                .await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let messages = tokio::select! {
                    result = &mut pass => panic!("held query must not finish: {result:?}"),
                    messages = seen(&server) => messages,
                };
                if messages.iter().any(|m| {
                    m["method"] == DEFINITION && m["params"]["textDocument"]["uri"] == candidate_uri
                }) {
                    break;
                }
            }
        })
        .await
        .expect("peer received the blocked candidate query");
        drop(pass);
        let messages = seen(&server).await;
        let lifecycle: Vec<_> = messages
            .iter()
            .filter(|m| {
                ["textDocument/didOpen", "textDocument/didClose"]
                    .iter()
                    .any(|method| m["method"] == *method)
            })
            .map(|m| m["method"].as_str().unwrap())
            .collect();
        assert_eq!(
            lifecycle,
            ["textDocument/didOpen", "textDocument/didClose"],
            "cancellation must close before subsequent traffic"
        );
    }
}

#[tokio::test]
async fn cancelled_open_ack_still_closes_the_document() {
    let f = Fixture::new(None);
    let server = LspServer::scripted_for_tests(PEER, f.responses());
    let provider = |_: &str| Some("Widget".into());
    let mut documents = enrichment::ScopedDocuments::new(&server, Some(&provider));
    let uri = crate::protocol::path_to_uri(&f.root.join("types.py"));
    let (entered, resume) = server.client.pause_next_write_ack();
    let mut opening = Box::pin(documents.ensure_open("types.py", &uri));
    tokio::select! {
        result = &mut opening => panic!("write ack is held: {result:?}"),
        _ = entered.notified() => {}
    }
    drop(opening);
    drop(documents);
    resume.notify_one();
    let messages = seen(&server).await;
    let methods: Vec<_> = messages
        .iter()
        .map(|m| m["method"].as_str().unwrap())
        .collect();
    assert_eq!(methods, ["textDocument/didOpen", "textDocument/didClose"]);
}

#[tokio::test]
async fn cancelled_close_ack_keeps_every_close_queued_once() {
    let f = Fixture::new(None);
    let server = LspServer::scripted_for_tests(PEER, f.responses());
    let provider = |_: &str| Some("Widget".into());
    let mut documents = enrichment::ScopedDocuments::new(&server, Some(&provider));
    for path in ["first.py", "second.py"] {
        assert!(documents
            .ensure_open(path, &crate::protocol::path_to_uri(&f.root.join(path)))
            .await
            .unwrap());
    }
    let (entered, resume) = server.client.pause_next_write_ack();
    let mut closing = Box::pin(documents.close_all());
    tokio::select! {
        result = &mut closing => panic!("close ack is held: {result:?}"),
        _ = entered.notified() => {}
    }
    drop(closing);
    drop(documents);
    resume.notify_one();
    let messages = seen(&server).await;
    assert_eq!(
        messages
            .iter()
            .filter(|m| m["method"] == "textDocument/didOpen")
            .count(),
        2
    );
    for path in ["first.py", "second.py"] {
        let uri = crate::protocol::path_to_uri(&f.root.join(path));
        assert_eq!(
            messages
                .iter()
                .filter(|m| m["method"] == "textDocument/didClose"
                    && m["params"]["textDocument"]["uri"] == uri)
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn blocked_cleanup_queue_fails_closed_without_successful_barriers() {
    let f = Fixture::new(None);
    let server = LspServer::scripted_for_tests(PEER, f.responses());
    let (entered, _resume) = server.client.pause_next_write_ack();
    let mut blocked = Box::pin(server.client.notify("test/block", Value::Null));
    tokio::select! {
        result = &mut blocked => panic!("write ack is held: {result:?}"),
        _ = entered.notified() => {}
    }
    let mut barriers = Vec::new();
    for _ in 0..64 {
        barriers.push(
            server
                .client
                .close_documents(vec!["file:///queued.py".into()])
                .unwrap(),
        );
    }
    assert!(server
        .client
        .close_documents(vec!["file:///overflow.py".into()])
        .is_err());
    assert!(blocked.await.is_err());
    for barrier in barriers {
        assert!(
            !matches!(barrier.await, Ok(Ok(()))),
            "invalidated writer cannot acknowledge cleanup success"
        );
    }
    assert!(server
        .client
        .request("test/seen", Value::Null)
        .await
        .is_err());
}

#[tokio::test]
async fn member_queries_respect_independently_disabled_capabilities() {
    let f = Fixture::new(None);
    for file_pass in [false, true] {
        let mut server = LspServer::scripted_for_tests(PEER, f.responses());
        let disabled = if file_pass {
            server.capabilities.type_definition_provider = Some(json!(false));
            TYPES
        } else {
            server.capabilities.definition_provider = Some(json!(false));
            DEFINITION
        };
        let provider = |_: &str| Some("module.run".into());
        let answer = if file_pass {
            crate::file_enrichment::enrich_file_definitions(
                &server,
                &f.root.join("source.py"),
                "module.run",
                &f.index,
                &f.root,
                Some(&provider),
            )
            .await
            .map(|result| result.relations)
        } else {
            enrichment::enrich_entity_uses_type(
                &server,
                &f.source,
                &f.index,
                &f.root,
                Some(&provider),
            )
            .await
        }
        .unwrap();
        assert!(answer
            .iter()
            .any(|relation| relation.dst == GraphNodeId::Entity(f.target.id)));
        let requests = seen(&server).await;
        assert!(!requests.iter().any(|request| request["method"] == disabled));
        assert!(!requests.is_empty(), "supported queries must still run");
    }
}

#[tokio::test]
async fn failed_drop_cleanup_invalidates_later_barriers() {
    let f = Fixture::new(None);
    let server = LspServer::scripted_for_tests(PEER, f.responses());
    let provider = |_: &str| Some("Widget".into());
    let mut documents = enrichment::ScopedDocuments::new(&server, Some(&provider));
    let uri = crate::protocol::path_to_uri(&f.root.join("types.py"));
    assert!(documents.ensure_open("types.py", &uri).await.unwrap());
    // The peer closes its read end before acknowledging, but keeps stdout
    // alive, so the cleanup write itself must detect the broken pipe.
    assert_eq!(
        server
            .client
            .request("test/close-input", Value::Null)
            .await
            .unwrap(),
        json!(true)
    );
    drop(documents);
    let barrier = match server.client.close_documents(Vec::new()) {
        Ok(done) => done.await.unwrap_or(Err(LspError::ServerDied)),
        Err(error) => Err(error),
    };
    assert!(
        barrier.is_err(),
        "failed unobserved cleanup must poison a later barrier"
    );
    assert!(server
        .client
        .request("test/seen", Value::Null)
        .await
        .is_err());
}
