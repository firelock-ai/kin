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
            declares_name: true,
            kind: kin_model::EntityKind::Function,
        };
        // Each provider below writes `Widget` where these declare it, so a
        // name query is asked at the name the admitted line spells.
        let source = entity("Caller.Widget", "source.py", 0);
        let target = entity("Base.Widget", "types.py", 10);
        let index = EntityIndex::new(vec![source.clone(), target.clone()], &root);
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
    let provider = |path: &str| match path {
        "source.py" => Some("Widget".to_owned()),
        "types.py" => Some(format!("{}Widget", "\n".repeat(10))),
        _ => None,
    };
    match method {
        PREPARE_CALL | CALLS => enrichment::enrich_entity_calls(
            server,
            &fixture.source,
            &fixture.index,
            &fixture.root,
            Some(&provider),
        )
        .await
        .map(|calls| calls.relations),
        PREPARE_TYPE | SUPERTYPES => {
            enrichment::enrich_entity_overrides(
                server,
                &fixture.source,
                &fixture.index,
                &fixture.root,
                Some(&provider),
            )
            .await
        }
        REFERENCES => {
            enrichment::enrich_entity_references(
                server,
                &fixture.source,
                &fixture.index,
                &fixture.root,
                Some(&provider),
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
        // The file pass keeps what it proved around a query that failed and
        // counts the failure instead of returning it. A pass that counted one
        // is graded here as the failure it is, never as an empty success.
        DEFINITION => crate::file_enrichment::enrich_file_definitions(
            server,
            &fixture.root.join("source.py"),
            "Widget",
            &fixture.index,
            &fixture.root,
            None,
        )
        .await
        .and_then(|answer| match answer.first_failure {
            Some(failure) if answer.failed_queries > 0 => Err(LspError::Protocol(failure)),
            _ => Ok(answer.relations),
        }),
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
    if !malformed && method != DEFINITION {
        assert!(matches!(answer, Err(LspError::JsonRpc(_))));
    }
    if !malformed && method == DEFINITION {
        assert!(
            matches!(&answer, Err(LspError::Protocol(failure)) if failure.contains("injected integrity failure")),
            "the file pass counts the failed definition and names it: {answer:?}"
        );
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
    f.index = EntityIndex::new(vec![f.source.clone(), f.target.clone()], &f.root);
    let candidate_uri = crate::protocol::path_to_uri(&f.root.join(&f.target.file_path));
    for file_pass in [false, true] {
        let mut responses = f.responses();
        responses[format!("{DEFINITION}@{candidate_uri}#0")] =
            json!({"error": {"code": -32603, "message": "candidate query failed"}});
        let server = LspServer::scripted_for_tests(PEER, responses);
        let provider = |path: &str| match path {
            "source.py" => Some("module.run".into()),
            "types.py" => Some(format!("{}run", "\n".repeat(10))),
            _ => None,
        };
        let answer = if file_pass {
            // The file pass keeps going past a failed join and counts it, so
            // the failure it must not hide is its count, not an `Err`.
            crate::file_enrichment::enrich_file_definitions(
                &server,
                &f.root.join("source.py"),
                "module.run",
                &f.index,
                &f.root,
                Some(&provider),
            )
            .await
            .and_then(|answer| match answer.first_failure {
                Some(failure) if answer.failed_queries > 0 => Err(LspError::Protocol(failure)),
                _ => Ok(answer.relations),
            })
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
        if file_pass {
            assert!(
                matches!(&answer, Err(LspError::Protocol(failure)) if failure.contains("candidate query failed")),
                "{answer:?}"
            );
        } else {
            assert!(matches!(answer, Err(LspError::JsonRpc(_))), "{answer:?}");
        }
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
    f.index = EntityIndex::new(vec![f.source.clone(), f.target.clone()], &f.root);
    let candidate_uri = crate::protocol::path_to_uri(&f.root.join(&f.target.file_path));
    for file_pass in [false, true] {
        let mut responses = f.responses();
        responses[format!("{DEFINITION}@{candidate_uri}#0")] = json!({"hold": true});
        let server = LspServer::scripted_for_tests(PEER, responses);
        let provider = |path: &str| match path {
            "source.py" => Some("module.run".into()),
            "types.py" => Some(format!("{}run", "\n".repeat(10))),
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

// Controlled protocol peer: these assertions exercise the actual enrichment
// producer, not a manually constructed relation or an installed language server.
#[tokio::test]
async fn fresh_lsp_call_uses_utf16_request_and_exact_source_bytes() {
    let text = "text = '😀'; work()";
    let start = text.find("work").unwrap();
    let utf16 = text[..start].encode_utf16().count() as u32;
    let mut f = Fixture::new(Some("a projection must not supply occurrence bytes"));
    f.source.name = "Caller.work".into();
    f.source.name_col = start as u32;
    f.index = EntityIndex::new(vec![f.source.clone(), f.target.clone()], &f.root);
    let mut responses = f.responses();
    responses[CALLS]["result"][0]["fromRanges"] = json!([{
        "start": {"line": 0, "character": utf16},
        "end": {"line": 0, "character": utf16 + 4}
    }]);
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = enrichment::enrich_entity_calls(
        &server,
        &f.source,
        &f.index,
        &f.root,
        Some(&|path| (path == "source.py").then(|| text.to_owned())),
    )
    .await
    .unwrap()
    .relations;
    let requests = seen(&server).await;
    let prepare = requests
        .iter()
        .find(|r| r["method"] == PREPARE_CALL)
        .unwrap();
    assert_eq!(prepare["params"]["position"]["character"], utf16);
    let span = answer[0].evidence[0].source_span.as_ref().unwrap();
    assert_eq!((span.start_byte, span.end_byte), (start, start + 4));
    assert_eq!(&text[span.start_byte..span.end_byte], "work");
    assert_eq!(
        (span.start_col, span.end_col),
        (start as u32, start as u32 + 4)
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn fresh_lsp_type_evidence_names_queried_caller_token_not_target_range() {
    let f = Fixture::new(Some("projection differs from admitted body"));
    let server = LspServer::scripted_for_tests(PEER, f.responses());
    let provider = |path: &str| (path == "source.py").then(|| "Widget".to_owned());
    let answer =
        enrichment::enrich_entity_uses_type(&server, &f.source, &f.index, &f.root, Some(&provider))
            .await
            .unwrap();
    let span = answer[0].evidence[0].source_span.as_ref().unwrap();
    assert_eq!(span.file.0, "source.py");
    assert_eq!((span.start_line, span.end_line), (0, 0));
    assert_eq!((span.start_byte, span.end_byte), (0, 6));
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn fresh_lsp_references_bind_each_returned_source_and_utf16_request() {
    let declared = "#😀 Widget";
    let referred = "#😀 Widget and Widget\r\n";
    let mut f = Fixture::new(None);
    f.source.name_col = declared.find("Widget").unwrap() as u32;
    f.target.start_line = 0;
    f.target.end_line = 0;
    f.target.name_line = 0;
    f.index = EntityIndex::new(vec![f.source.clone(), f.target.clone()], &f.root);
    let mut responses = f.responses();
    let offset = |byte: usize| referred[..byte].encode_utf16().count();
    responses[REFERENCES]["result"] = json!([
        {"uri": crate::protocol::path_to_uri(&f.root.join("types.py")),
         "range": {"start": {"line": 0, "character": offset(referred.find("Widget").unwrap())},
                   "end": {"line": 0, "character": offset(referred.find("Widget").unwrap()) + 6}}},
        {"uri": crate::protocol::path_to_uri(&f.root.join("types.py")),
         "range": {"start": {"line": 0, "character": offset(referred.rfind("Widget").unwrap())},
                   "end": {"line": 0, "character": offset(referred.rfind("Widget").unwrap()) + 6}}}
    ]);
    let provider = |file: &str| match file {
        "source.py" => Some(declared.to_owned()),
        "types.py" => Some(referred.to_owned()),
        _ => None,
    };
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = enrichment::enrich_entity_references(
        &server,
        &f.source,
        &f.index,
        &f.root,
        Some(&provider),
    )
    .await
    .unwrap();
    assert_eq!(answer.len(), 1);
    assert_eq!(answer[0].src, GraphNodeId::Entity(f.target.id));
    assert_eq!(answer[0].dst, GraphNodeId::Entity(f.source.id));
    let starts: Vec<_> = answer[0]
        .evidence
        .iter()
        .map(|e| {
            let span = e.source_span.as_ref().unwrap();
            assert_eq!(span.file.0, "types.py");
            assert_eq!(&referred[span.start_byte..span.end_byte], "Widget");
            span.start_byte
        })
        .collect();
    assert_eq!(
        starts,
        [
            referred.find("Widget").unwrap(),
            referred.rfind("Widget").unwrap()
        ]
    );
    let messages = seen(&server).await;
    let request = messages.iter().find(|m| m["method"] == REFERENCES).unwrap();
    assert_eq!(request["params"]["position"]["character"], 4);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn fresh_lsp_definition_uses_real_unicode_caller_token() {
    let text = "'😀'; Widget";
    let mut f = Fixture::new(Some("projection bytes differ"));
    f.source.end_line = 0;
    f.index = EntityIndex::new(vec![f.source.clone(), f.target.clone()], &f.root);
    let mut responses = f.responses();
    responses[DEFINITION] = json!({"result": null});
    let uri = crate::protocol::path_to_uri(&f.root.join("source.py"));
    let token = text.find("Widget").unwrap();
    let units = text[..token].encode_utf16().count();
    responses[format!("{DEFINITION}@{uri}#{units}")] = f.responses()[DEFINITION].clone();
    let mut server = LspServer::scripted_for_tests(PEER, responses);
    server.capabilities.call_hierarchy_provider = None;
    let answer = crate::file_enrichment::enrich_file_definitions(
        &server,
        &f.root.join("source.py"),
        text,
        &f.index,
        &f.root,
        None,
    )
    .await
    .unwrap();
    assert_eq!(answer.relations.len(), 1);
    let span = answer.relations[0].evidence[0]
        .source_span
        .as_ref()
        .unwrap();
    assert_eq!((span.start_byte, span.end_byte), (token, token + 6));
    assert_eq!(&text[span.start_byte..span.end_byte], "Widget");
    assert_eq!(span.file.0, "source.py");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn fresh_lsp_invalid_or_foreign_occurrences_refuse_the_answer() {
    let mut f = Fixture::new(None);
    f.source.name = "Caller.work".into();
    f.index = EntityIndex::new(vec![f.source.clone(), f.target.clone()], &f.root);
    for case in [
        "split_surrogate",
        "outside",
        "empty",
        "reversed",
        "foreign_prepare",
        "ambiguous_prepare",
    ] {
        let mut responses = f.responses();
        match case {
            "foreign_prepare" => {
                responses[PREPARE_CALL]["result"][0]["uri"] = json!("file:///foreign/source.py")
            }
            "ambiguous_prepare" => {
                let item = responses[PREPARE_CALL]["result"][0].clone();
                responses[PREPARE_CALL]["result"]
                    .as_array_mut()
                    .unwrap()
                    .push(item);
            }
            other => {
                let (start, end) = match other {
                    "split_surrogate" => (1, 2),
                    "outside" => (2, 100),
                    "empty" => (2, 2),
                    _ => (3, 2),
                };
                // A valid first result cannot hide a later invalid occurrence.
                responses[CALLS]["result"][0]["fromRanges"] = json!([
                    {"start":{"line":0,"character":3},"end":{"line":0,"character":7}},
                    {"start":{"line":0,"character":start},"end":{"line":0,"character":end}}
                ]);
            }
        }
        let server = LspServer::scripted_for_tests(PEER, responses);
        let answer = enrichment::enrich_entity_calls(
            &server,
            &f.source,
            &f.index,
            &f.root,
            Some(&|_| Some("😀 work".into())),
        )
        .await;
        assert!(answer.is_err(), "{case}: {answer:?}");
        let refused = if case.ends_with("_prepare") {
            PREPARE_CALL
        } else {
            CALLS
        };
        assert!(
            received(&server, refused).await,
            "{case}: the refusal must come from the {refused} answer, not from failing to ask"
        );
        server.shutdown().await.unwrap();
    }
}

/// Whether `server` received a `method` request, so a refusal came from its
/// answer and not from failing to ask it.
async fn received(server: &LspServer, method: &str) -> bool {
    seen(server)
        .await
        .iter()
        .any(|request| request["method"] == method)
}

#[tokio::test]
async fn fresh_lsp_missing_and_foreign_reference_sources_are_not_empty_successes() {
    let f = Fixture::new(Some("projection is not authority"));
    for foreign in [false, true] {
        let mut responses = f.responses();
        if foreign {
            responses[REFERENCES]["result"][0]["uri"] = json!("file:///foreign/types.py");
        }
        let server = LspServer::scripted_for_tests(PEER, responses);
        let provider = |file: &str| (file == "source.py").then(|| "Widget".to_owned());
        let answer = enrichment::enrich_entity_references(
            &server,
            &f.source,
            &f.index,
            &f.root,
            Some(&provider),
        )
        .await;
        assert!(answer.is_err());
        assert!(
            received(&server, REFERENCES).await,
            "foreign={foreign}: the refusal must come from the references answer"
        );
        server.shutdown().await.unwrap();
    }
    let server = LspServer::scripted_for_tests(PEER, f.responses());
    assert!(
        enrichment::enrich_entity_calls(&server, &f.source, &f.index, &f.root, None)
            .await
            .is_err()
    );
    assert!(seen(&server).await.is_empty());
    server.shutdown().await.unwrap();
}

const INITIALIZE_PEER: &str = r#"
import json,sys
selection=json.loads(sys.argv[1])
while True:
    headers={}
    while True:
        line=sys.stdin.buffer.readline()
        if not line: sys.exit(0)
        if line in (b'\n',b'\r\n'): break
        key,value=line.decode().split(':',1);headers[key.lower()]=value.strip()
    msg=json.loads(sys.stdin.buffer.read(int(headers['content-length'])))
    if 'id' not in msg: continue
    if msg['method']=='initialize':
        assert msg['params']['capabilities']['general']['positionEncodings']==['utf-16']
        result={'capabilities':selection}
    else: result=None
    data=json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':result}).encode()
    sys.stdout.buffer.write(f'Content-Length: {len(data)}\r\n\r\n'.encode()+data);sys.stdout.buffer.flush()
"#;

#[tokio::test]
async fn fresh_lsp_initialize_accepts_only_supported_position_encoding() {
    for (capabilities, accepted) in [
        (json!({}), true),
        (json!({"positionEncoding":"utf-16"}), true),
        (json!({"positionEncoding":"utf-8"}), false),
        (json!({"positionEncoding":"unknown"}), false),
        (json!({"positionEncoding":8}), false),
    ] {
        let selection = capabilities.to_string();
        let result = LspServer::start(
            "python3",
            &["-u", "-c", INITIALIZE_PEER, &selection],
            &std::env::temp_dir(),
            None,
            None,
        )
        .await;
        assert_eq!(result.is_ok(), accepted, "{capabilities}");
        if let Ok(server) = result {
            server.shutdown().await.unwrap();
        }
    }
}

#[tokio::test]
async fn fresh_lsp_validation_prepared_ranges_refuse_before_outgoing_query() {
    let f = Fixture::new(None);
    let range = |start, end| {
        json!({
            "start":{"line":0,"character":start},"end":{"line":0,"character":end}
        })
    };
    let text = "😀 Widget";
    let malformed = [
        ("column outside source", range(0, 9), range(999, 1000)),
        ("split surrogate", range(0, 9), range(1, 2)),
        ("reversed selection", range(0, 9), range(9, 3)),
        ("empty selection", range(0, 9), range(3, 3)),
        ("invalid enclosing endpoint", range(0, 999), range(3, 9)),
        (
            "selection outside enclosing range",
            range(0, 2),
            range(3, 9),
        ),
        (
            "out of document enclosing end",
            json!({
                "start":{"line":0,"character":0},"end":{"line":1,"character":0}
            }),
            range(3, 9),
        ),
    ];
    let mut accepted = Vec::new();
    for empty in [false, true] {
        for (label, enclosing, selection) in &malformed {
            let mut responses = f.responses();
            responses[PREPARE_CALL]["result"][0]["range"] = enclosing.clone();
            responses[PREPARE_CALL]["result"][0]["selectionRange"] = selection.clone();
            responses[CALLS]["result"][0]["fromRanges"] = json!([range(3, 9)]);
            if empty {
                responses[CALLS]["result"] = json!([]);
            }
            let server = LspServer::scripted_for_tests(PEER, responses);
            let answer = enrichment::enrich_entity_calls(
                &server,
                &f.source,
                &f.index,
                &f.root,
                Some(&|_| Some(text.into())),
            )
            .await;
            let requests = seen(&server).await;
            let prepared = requests.iter().any(|r| r["method"] == PREPARE_CALL);
            let outgoing_sent = requests.iter().any(|r| r["method"] == CALLS);
            if answer.is_ok() || !prepared || outgoing_sent {
                accepted.push(format!(
                    "{label}, empty={empty}: {answer:?}, prepared={prepared}, \
                     outgoing={outgoing_sent}"
                ));
            }
            server.shutdown().await.unwrap();
        }
    }
    assert!(
        accepted.is_empty(),
        "malformed preparation must fail on its prepare answer, before outgoing RPC: \
         {accepted:?}"
    );
}

#[tokio::test]
async fn fresh_lsp_validation_unmatched_local_reference_still_checks_source() {
    let f = Fixture::new(None);
    let mut responses = f.responses();
    responses[REFERENCES]["result"][0]["range"] = json!({
        "start":{"line":999,"character":0},"end":{"line":999,"character":4}
    });
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = enrichment::enrich_entity_references(
        &server,
        &f.source,
        &f.index,
        &f.root,
        Some(&|_| Some("Widget".into())),
    )
    .await;
    assert!(
        answer.is_err(),
        "invalid admitted source range cannot become a complete empty answer: {answer:?}"
    );
    assert!(received(&server, REFERENCES).await);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn fresh_lsp_validation_range_after_site_cap_is_not_hidden() {
    let f = Fixture::new(None);
    let mut responses = f.responses();
    let mut ranges: Vec<_> = (0..64)
        .map(|i| {
            json!({
                "start":{"line":0,"character":i},"end":{"line":0,"character":i+1}
            })
        })
        .collect();
    ranges.push(json!({"start":{"line":0,"character":999},"end":{"line":0,"character":1000}}));
    responses[CALLS]["result"][0]["fromRanges"] = json!(ranges);
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = enrichment::enrich_entity_calls(
        &server,
        &f.source,
        &f.index,
        &f.root,
        Some(&|_| Some(format!("Widget {}", "w".repeat(100)))),
    )
    .await;
    assert!(
        answer.is_err(),
        "cap cannot hide malformed evidence: {answer:?}"
    );
    assert!(received(&server, CALLS).await);
    server.shutdown().await.unwrap();
}

/// A call the server reports with no site at all proves nothing about the
/// caller. It is counted, and no edge is minted for it.
#[tokio::test]
async fn fresh_lsp_validation_empty_call_sites_are_unproven() {
    let f = Fixture::new(None);
    let mut responses = f.responses();
    responses[CALLS]["result"][0]["fromRanges"] = json!([]);
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = enrichment::enrich_entity_calls(
        &server,
        &f.source,
        &f.index,
        &f.root,
        Some(&|_| Some("Widget".into())),
    )
    .await
    .expect("an unproven call is counted, not a failed answer");
    assert!(
        answer.relations.is_empty(),
        "a Calls row without a site cannot manufacture occurrence evidence: {answer:?}"
    );
    assert_eq!(answer.unproven_calls, 1, "{answer:?}");
    assert!(received(&server, CALLS).await);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn fresh_lsp_validation_call_range_outside_queried_caller_is_not_an_edge() {
    let f = Fixture::new(None);
    let mut responses = f.responses();
    responses[CALLS]["result"][0]["fromRanges"] = json!([
        {"start":{"line":1,"character":0},"end":{"line":1,"character":4}}
    ]);
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = enrichment::enrich_entity_calls(
        &server,
        &f.source,
        &f.index,
        &f.root,
        Some(&|_| Some("Widget\nwork()".into())),
    )
    .await
    .expect("an unproven call is counted, not a failed answer");
    assert!(
        answer.relations.is_empty(),
        "another source line cannot be attributed to the queried caller: {answer:?}"
    );
    assert_eq!(answer.unproven_calls, 1, "{answer:?}");
    assert!(received(&server, CALLS).await);
    server.shutdown().await.unwrap();
}

/// A caller whose call hierarchy names three calls, one of them only at a line
/// outside the caller, and a fourth with one site inside and one outside.
struct ThreeCalls {
    root: PathBuf,
    caller: EntityRef,
    inside: [EntityRef; 2],
    outside: EntityRef,
    mixed: EntityRef,
    index: EntityIndex,
    text: String,
}

impl ThreeCalls {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("kin-lsp-calls-{}", EntityId::new()));
        std::fs::create_dir(&root).unwrap();
        let entity = |name: &str, file: &str, start: u32, end: u32| EntityRef {
            id: EntityId::new(),
            name: name.into(),
            file_path: file.into(),
            start_line: start,
            start_col: 0,
            end_line: end,
            name_line: start,
            name_col: 4,
            declares_name: true,
            kind: kin_model::EntityKind::Function,
        };
        // Line 0 is a decorator above the caller's own lines, which run 1 to 4.
        let text =
            "@wrap(audit())\ndef work():\n    first()\n    second()\n    third()\n".to_owned();
        let caller = entity("work", "source.py", 1, 4);
        let inside = [
            entity("first", "targets.py", 0, 1),
            entity("second", "targets.py", 2, 3),
        ];
        let outside = entity("audit", "targets.py", 4, 5);
        let mixed = entity("third", "targets.py", 6, 7);
        let index = EntityIndex::new(
            vec![
                caller.clone(),
                inside[0].clone(),
                inside[1].clone(),
                outside.clone(),
                mixed.clone(),
            ],
            &root,
        );
        Self {
            root,
            caller,
            inside,
            outside,
            mixed,
            index,
            text,
        }
    }

    fn uri(&self, file: &str) -> String {
        crate::protocol::path_to_uri(&self.root.join(file))
    }

    fn item(&self, entity: &EntityRef) -> Value {
        let line = entity.start_line;
        let width = entity.name.len() as u32;
        json!({
            "name": entity.name, "kind": 12, "uri": self.uri(&entity.file_path),
            "range": {"start": {"line": line, "character": 0},
                      "end": {"line": line, "character": 4 + width}},
            "selectionRange": {"start": {"line": line, "character": 4},
                               "end": {"line": line, "character": 4 + width}},
        })
    }

    /// The range of `token`, on the caller's `line`, in UTF-16 units.
    fn site(&self, line: u32, token: &str) -> Value {
        let text = self.text.lines().nth(line as usize).unwrap();
        let start = text.find(token).unwrap() as u32;
        json!({"start": {"line": line, "character": start},
               "end": {"line": line, "character": start + token.len() as u32}})
    }

    fn responses(&self) -> Value {
        json!({
            PREPARE_CALL: {"result": [self.item(&self.caller)]},
            CALLS: {"result": [
                {"to": self.item(&self.inside[0]), "fromRanges": [self.site(2, "first")]},
                {"to": self.item(&self.outside), "fromRanges": [self.site(0, "audit")]},
                {"to": self.item(&self.inside[1]), "fromRanges": [self.site(3, "second")]},
                {"to": self.item(&self.mixed),
                 "fromRanges": [self.site(0, "wrap"), self.site(4, "third")]},
            ]},
        })
    }

    async fn calls(&self, server: &LspServer) -> Result<enrichment::EntityCalls> {
        let text = self.text.clone();
        enrichment::enrich_entity_calls(
            server,
            &self.caller,
            &self.index,
            &self.root,
            Some(&move |path| (path == "source.py").then(|| text.clone())),
        )
        .await
    }
}

impl Drop for ThreeCalls {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

/// One call without a site inside the caller drops that call, not the caller.
///
/// A decorator's call sits on a line above the function it decorates, and a
/// server can report it among the function's own outgoing calls. That one call
/// used to refuse the whole answer, and the caller's two proven calls went
/// with it. Now the proven calls stand, the unproven one is counted and never
/// minted, and a call with sites on both sides keeps only the one inside.
#[tokio::test]
async fn an_out_of_range_call_drops_that_call_and_keeps_the_callers_others() {
    let f = ThreeCalls::new();
    let server = LspServer::scripted_for_tests(PEER, f.responses());
    let answer = f
        .calls(&server)
        .await
        .expect("the caller's proven calls stand");
    let edge = |target: &EntityRef| {
        answer
            .relations
            .iter()
            .find(|r| r.dst == GraphNodeId::Entity(target.id))
    };
    for target in &f.inside {
        let edge = edge(target).unwrap_or_else(|| panic!("{} survives: {answer:?}", target.name));
        assert_eq!(edge.src, GraphNodeId::Entity(f.caller.id));
        assert_eq!(edge.kind, RelationKind::Calls);
    }
    assert!(
        edge(&f.outside).is_none(),
        "a call with no site inside the caller is not an edge: {answer:?}"
    );
    assert_eq!(answer.unproven_calls, 1, "{answer:?}");
    let mixed = edge(&f.mixed).expect("a call with one site inside keeps its edge");
    let lines: Vec<u32> = mixed
        .evidence
        .iter()
        .map(|e| e.source_span.as_ref().unwrap().start_line)
        .collect();
    assert_eq!(lines, [4], "only the site inside the caller is evidence");
    assert_eq!(answer.relations.len(), 3, "{answer:?}");
    server.shutdown().await.unwrap();

    // The file pass keeps the proven calls, counts the unproven one, and
    // still holds the file back, since the answer was not proven whole.
    let server = LspServer::scripted_for_tests(PEER, f.responses());
    let pass = crate::file_enrichment::enrich_file_definitions(
        &server,
        &f.root.join("source.py"),
        &f.text,
        &f.index,
        &f.root,
        None,
    )
    .await
    .expect("only a server that can answer nothing ends the pass");
    for target in [&f.inside[0], &f.inside[1], &f.mixed] {
        assert!(
            has_edge(&pass.relations, RelationKind::Calls, target.id),
            "{}: {pass:?}",
            target.name
        );
    }
    assert!(!has_edge(
        &pass.relations,
        RelationKind::Calls,
        f.outside.id
    ));
    // The same server reports the same unplaceable call every time, so it is
    // refused, not owed: nothing holds the file back or names a failure.
    assert_eq!(
        (
            pass.failed_queries,
            pass.refused_queries,
            pass.unproven_calls
        ),
        (0, 1, 1),
        "{pass:?}"
    );
    assert_eq!(pass.first_failure, None, "{pass:?}");
    assert_eq!(pass.unprovable.len(), 1, "{pass:?}");
    let (entity, reason) = &pass.unprovable[0];
    assert_eq!(*entity, f.caller.id);
    assert!(
        reason.contains("work") && reason.contains("1 call(s)"),
        "{pass:?}"
    );
    assert!(pass.call_hierarchy_complete, "{pass:?}");
    server.shutdown().await.unwrap();
}

/// Several prepared items, exactly one of which is the caller at the position
/// that was asked: that one is queried.
///
/// The others here are an item in another file and an item in the caller's
/// file whose selection is not the asked name. Every such answer used to be
/// refused as ambiguous, and the caller lost all of its calls.
#[tokio::test]
async fn an_ambiguous_prepare_with_one_provable_item_proceeds() {
    let f = ThreeCalls::new();
    let mut responses = f.responses();
    let caller = f.item(&f.caller);
    let mut foreign = caller.clone();
    foreign["uri"] = json!(f.uri("elsewhere.py"));
    let mut beside = caller.clone();
    // The same line, and so the same innermost entity, but the selection is
    // `def`, not the name the query was asked at.
    beside["selectionRange"] = json!({"start": {"line": 1, "character": 0},
                                      "end": {"line": 1, "character": 3}});
    responses[PREPARE_CALL] = json!({"result": [foreign, beside, caller]});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = f
        .calls(&server)
        .await
        .expect("the one item that is the caller is chosen");
    assert!(
        answer
            .relations
            .iter()
            .any(|r| r.dst == GraphNodeId::Entity(f.inside[0].id)),
        "{answer:?}"
    );
    let requests = seen(&server).await;
    let outgoing = requests
        .iter()
        .find(|r| r["method"] == CALLS)
        .expect("the outgoing calls are asked");
    let chosen = f.item(&f.caller);
    assert_eq!(outgoing["params"]["item"]["uri"], chosen["uri"]);
    assert_eq!(
        outgoing["params"]["item"]["selectionRange"],
        chosen["selectionRange"]
    );
    server.shutdown().await.unwrap();
}

/// Several prepared items with no single one provably the caller are still
/// refused, before any outgoing query: choosing one would be a guess.
#[tokio::test]
async fn an_ambiguous_prepare_without_one_provable_item_is_refused() {
    let f = ThreeCalls::new();
    let caller = f.item(&f.caller);
    let mut foreign = caller.clone();
    foreign["uri"] = json!(f.uri("elsewhere.py"));
    // The caller's line, with a selection that is not the asked name.
    let mut unasked = caller.clone();
    unasked["selectionRange"] = json!({"start": {"line": 1, "character": 0},
                                       "end": {"line": 1, "character": 3}});
    // The decorator's line, which no entity owns.
    let mut unowned = caller.clone();
    unowned["range"] = json!({"start": {"line": 0, "character": 0},
                              "end": {"line": 0, "character": 5}});
    unowned["selectionRange"] = json!({"start": {"line": 0, "character": 1},
                                       "end": {"line": 0, "character": 5}});
    for (case, items) in [
        (
            "no item holds the asked name",
            json!([foreign.clone(), unasked]),
        ),
        ("two items are the caller", json!([caller.clone(), caller])),
        (
            "no item is on the caller's lines",
            json!([foreign, unowned]),
        ),
    ] {
        let mut responses = f.responses();
        responses[PREPARE_CALL] = json!({ "result": items });
        let server = LspServer::scripted_for_tests(PEER, responses);
        let answer = f.calls(&server).await;
        assert!(
            matches!(&answer, Err(LspError::Protocol(reason)) if reason.contains("ambiguous")),
            "{case}: {answer:?}"
        );
        assert!(received(&server, PREPARE_CALL).await, "{case}");
        assert!(
            !received(&server, CALLS).await,
            "{case}: refused on the prepare answer, before the outgoing query"
        );
        server.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn fresh_lsp_member_join_uses_cached_document_and_unicode_columns() {
    let text = "marker = \"😀\"; module.run";
    let candidate_text = "#😀 run";
    let mut f = Fixture::new(None);
    f.target.name = "run".into();
    f.target.start_line = 0;
    f.target.end_line = 0;
    f.target.name_line = 0;
    f.target.name_col = candidate_text.find("run").unwrap() as u32;
    f.index = EntityIndex::new(vec![f.source.clone(), f.target.clone()], &f.root);
    let source_uri = crate::protocol::path_to_uri(&f.root.join("source.py"));
    let candidate_uri = crate::protocol::path_to_uri(&f.root.join("types.py"));
    let units = |body: &str, token: &str| body[..body.find(token).unwrap()].encode_utf16().count();
    let location = |uri: &str| {
        json!({"uri":uri,"range":{
        "start":{"line":0,"character":0},"end":{"line":0,"character":3}}})
    };
    for file_pass in [false, true] {
        let mut responses = json!({});
        responses[format!("{DEFINITION}@{source_uri}#{}", units(text, "module"))] =
            json!({"result":[location(&candidate_uri)]});
        responses[format!("{TYPES}@{source_uri}#{}", units(text, "module"))] =
            json!({"result":[location(&candidate_uri)]});
        responses[format!("{DEFINITION}@{source_uri}#{}", units(text, "run"))] =
            json!({"result":[location("file:///dependency/run.py")]});
        responses[format!(
            "{DEFINITION}@{candidate_uri}#{}",
            units(candidate_text, "run")
        )] = json!({"result":[location("file:///dependency/run.py")]});
        let mut server = LspServer::scripted_for_tests(PEER, responses);
        server.capabilities.call_hierarchy_provider = None;
        let reads = AtomicUsize::new(0);
        let provider = |path: &str| match path {
            "source.py" => Some(text.to_owned()),
            "types.py" => {
                let call = reads.fetch_add(1, Ordering::SeqCst);
                Some(
                    if call == 0 {
                        candidate_text
                    } else {
                        "wrong second read"
                    }
                    .to_owned(),
                )
            }
            _ => None,
        };
        let answer = if file_pass {
            crate::file_enrichment::enrich_file_definitions(
                &server,
                &f.root.join("source.py"),
                text,
                &f.index,
                &f.root,
                Some(&provider),
            )
            .await
            .unwrap()
            .relations
        } else {
            enrichment::enrich_entity_uses_type(
                &server,
                &f.source,
                &f.index,
                &f.root,
                Some(&provider),
            )
            .await
            .unwrap()
        };
        assert_eq!(answer.len(), 1);
        assert_eq!(answer[0].dst, GraphNodeId::Entity(f.target.id));
        let span = answer[0].evidence[0].source_span.as_ref().unwrap();
        assert_eq!(&text[span.start_byte..span.end_byte], "run");
        assert_eq!(span.start_byte, text.find("run").unwrap());
        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "conversion must use bytes sent in didOpen"
        );
        let requests = seen(&server).await;
        let opened = requests
            .iter()
            .find(|m| m["method"] == "textDocument/didOpen")
            .unwrap();
        assert_eq!(opened["params"]["textDocument"]["text"], candidate_text);
        assert!(requests
            .iter()
            .any(|m| m["method"] == "textDocument/didClose"
                && m["params"]["textDocument"]["uri"] == candidate_uri));
        server.shutdown().await.unwrap();
    }
}

/// The file pass over the fixture, with its counts.
async fn file_pass_over(
    server: &LspServer,
    f: &Fixture,
    text: &str,
) -> crate::file_enrichment::FileEnrichmentResult {
    crate::file_enrichment::enrich_file_definitions(
        server,
        &f.root.join("source.py"),
        text,
        &f.index,
        &f.root,
        None,
    )
    .await
    .expect("only a server that can answer nothing ends the pass")
}

fn has_edge(relations: &[Relation], kind: RelationKind, dst: EntityId) -> bool {
    relations
        .iter()
        .any(|relation| relation.kind == kind && relation.dst == GraphNodeId::Entity(dst))
}

/// gopls declines a call hierarchy at a type, field or package clause with a
/// code-0 answer. The pass skips that declaration, counts the decline, holds
/// nothing back, and keeps the file's definition edges. An internal error on
/// the same request is a failure: counted, the file held back, and the proven
/// edges still kept.
#[tokio::test]
async fn a_declined_call_hierarchy_keeps_the_files_definition_edges() {
    let f = Fixture::new(None);
    let mut responses = f.responses();
    responses[PREPARE_CALL] = json!({"error": {"code": 0, "message": "Widget is not a function"}});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = file_pass_over(&server, &f, "Widget").await;
    assert_eq!(
        (answer.failed_queries, answer.declined_queries),
        (0, 1),
        "{answer:?}"
    );
    assert!(
        has_edge(&answer.relations, RelationKind::References, f.target.id),
        "{answer:?}"
    );
    assert!(
        !answer
            .relations
            .iter()
            .any(|r| r.kind == RelationKind::Calls),
        "{answer:?}"
    );

    let mut responses = f.responses();
    responses[PREPARE_CALL] = json!({"error": {"code": -32603, "message": "handler panicked"}});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = file_pass_over(&server, &f, "Widget").await;
    assert_eq!(
        (answer.failed_queries, answer.declined_queries),
        (1, 0),
        "{answer:?}"
    );
    assert!(answer
        .first_failure
        .as_deref()
        .is_some_and(|reason| reason.contains("call hierarchy")));
    assert!(
        has_edge(&answer.relations, RelationKind::References, f.target.id),
        "{answer:?}"
    );
}

/// A server that cannot load the file's package answers with the same code 0
/// as a decline. That is a failure, never a decline: the file pass counts it,
/// so the file is held back and asked about again, and the edges it did prove
/// stand. Wording known for another method is not a decline either.
#[tokio::test]
async fn a_package_the_server_cannot_load_is_a_failure_not_a_decline() {
    let f = Fixture::new(None);
    for message in [
        "no package metadata for file file:///w/source.py",
        "no identifier found",
    ] {
        let mut responses = f.responses();
        responses[DEFINITION] = json!({"error": {"code": 0, "message": message}});
        let server = LspServer::scripted_for_tests(PEER, responses);
        let answer = file_pass_over(&server, &f, "Widget").await;
        assert_eq!(
            (answer.failed_queries, answer.declined_queries),
            (1, 0),
            "{message}: {answer:?}"
        );
        assert!(
            has_edge(&answer.relations, RelationKind::Calls, f.target.id),
            "the call hierarchy after the failed position still runs: {answer:?}"
        );
    }
    let mut responses = f.responses();
    responses[REFERENCES] =
        json!({"error": {"code": 0, "message": "no package metadata for file"}});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = query(&server, &f, REFERENCES).await;
    assert!(matches!(answer, Err(LspError::JsonRpc(_))), "{answer:?}");
    let mut responses = f.responses();
    responses[REFERENCES] = json!({"error": {"code": 0, "message": "no identifier found"}});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = query(&server, &f, REFERENCES).await;
    assert!(
        matches!(answer, Err(ref error) if error.is_declined()),
        "the observed references decline: {answer:?}"
    );
}

/// A member expression whose receiver's type the server declines to locate
/// binds nothing, and the file keeps every other edge it proved.
///
/// gopls declines `typeDefinition` at a package-level value of an unnamed
/// struct type. The member-on-module join asked exactly that and failed the
/// whole file pass on the answer, which cost the file all of its definition
/// edges. An internal error on the same request is counted as a failure and
/// still keeps the file's other edges.
#[tokio::test]
async fn a_declined_receiver_type_binds_nothing_and_keeps_the_file() {
    let f = Fixture::new(None);
    for (error, failed) in [
        (
            json!({"code": 0, "message": "cannot find type name(s) from type struct{}"}),
            0,
        ),
        (json!({"code": -32603, "message": "handler panicked"}), 1),
    ] {
        let mut responses = f.responses();
        responses[TYPES] = json!({ "error": error });
        let mut server = LspServer::scripted_for_tests(PEER, responses);
        // The receiver join is under test. The caller's call hierarchy would be
        // asked at a name this text does not spell, and counted on its own.
        server.capabilities.call_hierarchy_provider = None;
        let answer = file_pass_over(&server, &f, "module.run").await;
        assert_eq!(answer.failed_queries, failed, "{answer:?}");
        assert!(
            has_edge(&answer.relations, RelationKind::References, f.target.id),
            "the member's own definition edge survives: {answer:?}"
        );
    }
}

/// The uses-type arm skips a declined position and asks about the next one.
/// It used to stop at its first declined position, which for every Go entity
/// is the `func` keyword, so Go produced no uses-type edge at all.
#[tokio::test]
async fn uses_type_skips_a_declined_position_and_keeps_asking() {
    let f = Fixture::new(None);
    let source_uri = crate::protocol::path_to_uri(&f.root.join("source.py"));
    let mut responses = f.responses();
    responses[format!("{TYPES}@{source_uri}#0")] =
        json!({"error": {"code": 0, "message": "no enclosing expression has a type"}});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let relations = enrichment::enrich_entity_uses_type(
        &server,
        &f.source,
        &f.index,
        &f.root,
        Some(&|_| Some("func Widget".into())),
    )
    .await
    .expect("a declined position is not a failed arm");
    assert!(
        has_edge(&relations, RelationKind::UsesType, f.target.id),
        "{relations:?}"
    );

    let mut responses = f.responses();
    responses[format!("{TYPES}@{source_uri}#0")] =
        json!({"error": {"code": 0, "message": "no package metadata for file"}});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = enrichment::enrich_entity_uses_type(
        &server,
        &f.source,
        &f.index,
        &f.root,
        Some(&|_| Some("func Widget".into())),
    )
    .await;
    assert!(
        matches!(answer, Err(LspError::JsonRpc(_))),
        "a position that got no considered answer fails the arm: {answer:?}"
    );
}

/// Flask's `examples/tutorial/flaskr/auth.py`, reduced to the two entities that
/// each used to fail its whole definitions pass: the module surface, whose
/// signature is its path so its name hint runs off the first line, and a
/// decorated function, whose signature leads with the decorator so its hint
/// lands on a parameter.
struct DecoratedFile {
    root: PathBuf,
    uri: String,
    helpers_uri: String,
    module: EntityRef,
    login: EntityRef,
    redirect: EntityRef,
    index: EntityIndex,
}

const DECORATED_PATH: &str = "examples/tutorial/flaskr/auth.py";
const DECORATED_TEXT: &str = "import functools\nfrom pkg import redirect\n\n\n@bp.route(\"/login\")\ndef login(next_url: str, remember: bool) -> str:\n    return redirect(next_url)\n";

impl DecoratedFile {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("kin-lsp-decorated-{}", EntityId::new()));
        let at = |name: &str, file: &str, start, end, hint, declares_name| EntityRef {
            id: EntityId::new(),
            name: name.into(),
            file_path: file.into(),
            start_line: start,
            start_col: 0,
            end_line: end,
            name_line: start,
            name_col: hint,
            declares_name,
            kind: kin_model::EntityKind::Function,
        };
        let module_signature = format!("module {DECORATED_PATH}");
        let login_signature = "@route def login(next_url: str, remember: bool) -> str";
        let module = at(
            "auth",
            DECORATED_PATH,
            0,
            6,
            module_signature.find("auth").unwrap() as u32,
            false,
        );
        let login = at(
            "login",
            DECORATED_PATH,
            5,
            6,
            login_signature.find("login").unwrap() as u32,
            true,
        );
        let redirect = at("redirect", "pkg/helpers.py", 0, 1, 4, true);
        let index = EntityIndex::new(vec![module.clone(), login.clone(), redirect.clone()], &root);
        Self {
            uri: crate::protocol::path_to_uri(&root.join(DECORATED_PATH)),
            helpers_uri: crate::protocol::path_to_uri(&root.join("pkg/helpers.py")),
            root,
            module,
            login,
            redirect,
            index,
        }
    }

    fn line_column(line: usize, token: &str) -> u32 {
        DECORATED_TEXT
            .lines()
            .nth(line)
            .unwrap()
            .find(token)
            .unwrap() as u32
    }

    /// A server that answers only at the tokens a real one would: the name
    /// `login` for the call hierarchy, and the two `redirect` identifiers for
    /// definitions. Anything asked anywhere else is an error.
    fn responses(&self) -> Value {
        let range = |line: u32, start: u32, end: u32| json!({"start": {"line": line, "character": start}, "end": {"line": line, "character": end}});
        let redirect_location = json!({"uri": self.helpers_uri, "range": range(0, 4, 12)});
        let login_item = json!({
            "name": "login", "kind": 12, "uri": self.uri,
            "range": {"start": {"line": 5, "character": 0}, "end": {"line": 6, "character": 29}},
            "selectionRange": range(5, 4, 9),
        });
        let redirect_item = json!({
            "name": "redirect", "kind": 12, "uri": self.helpers_uri,
            "range": range(0, 0, 12), "selectionRange": range(0, 4, 12),
        });
        let call_site = Self::line_column(6, "redirect");
        let mut responses = json!({
            PREPARE_CALL: {"error": {"code": -32603, "message": "asked away from the name"}},
            REFERENCES: {"error": {"code": -32603, "message": "asked away from the name"}},
            DEFINITION: {"result": null},
            CALLS: {"result": [{"to": redirect_item, "fromRanges": [range(6, call_site, call_site + 8)]}]},
        });
        responses[format!("{PREPARE_CALL}@{}#4", self.uri)] = json!({"result": [login_item]});
        responses[format!("{REFERENCES}@{}#4", self.uri)] = json!({"result": []});
        for (line, token) in [(1, "redirect"), (6, "redirect")] {
            responses[format!(
                "{DEFINITION}@{}#{}",
                self.uri,
                Self::line_column(line, token)
            )] = json!({"result": [redirect_location]});
        }
        responses
    }

    async fn file_pass(
        &self,
        server: &LspServer,
    ) -> Result<crate::file_enrichment::FileEnrichmentResult> {
        crate::file_enrichment::enrich_file_definitions(
            server,
            &self.root.join(DECORATED_PATH),
            DECORATED_TEXT,
            &self.index,
            &self.root,
            None,
        )
        .await
    }

    fn edge(&self, answer: &[Relation], kind: RelationKind, source: &EntityRef) -> bool {
        answer.iter().any(|relation| {
            relation.kind == kind
                && relation.src == GraphNodeId::Entity(source.id)
                && relation.dst == GraphNodeId::Entity(self.redirect.id)
        })
    }
}

#[tokio::test]
async fn a_decorated_definition_and_its_module_keep_the_files_definitions() {
    let f = DecoratedFile::new();
    let server = LspServer::scripted_for_tests(PEER, f.responses());
    let answer = f.file_pass(&server).await.unwrap();
    assert_eq!(answer.failed_queries, 0, "{answer:?}");
    assert!(
        f.edge(&answer.relations, RelationKind::References, &f.module),
        "the import line keeps its edge: {answer:?}"
    );
    assert!(
        f.edge(&answer.relations, RelationKind::References, &f.login),
        "the call site keeps its reference: {answer:?}"
    );
    assert!(
        f.edge(&answer.relations, RelationKind::Calls, &f.login),
        "the decorated function is asked at its name and keeps its call: {answer:?}"
    );
    let prepared: Vec<_> = seen(&server)
        .await
        .into_iter()
        .filter(|message| message["method"] == PREPARE_CALL)
        .map(|message| message["params"]["position"].clone())
        .collect();
    assert_eq!(
        prepared,
        [json!({"line": 5, "character": 4})],
        "only the function is asked about, and only at `login`, never at `next_url` or for the module"
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn one_unprovable_call_hierarchy_is_counted_without_emptying_the_file() {
    let f = DecoratedFile::new();
    let mut responses = f.responses();
    responses[format!("{PREPARE_CALL}@{}#4", f.uri)]["result"][0]["uri"] =
        json!("file:///foreign/examples/tutorial/flaskr/auth.py");
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = f.file_pass(&server).await.unwrap();
    assert_eq!(
        (answer.failed_queries, answer.refused_queries),
        (0, 1),
        "the unprovable answer is a refusal the caller can see, not owed work: {answer:?}"
    );
    assert_eq!(answer.first_failure, None, "{answer:?}");
    assert!(answer.call_hierarchy_complete, "{answer:?}");
    assert!(!f.edge(&answer.relations, RelationKind::Calls, &f.login));
    assert!(f.edge(&answer.relations, RelationKind::References, &f.module));
    assert!(f.edge(&answer.relations, RelationKind::References, &f.login));
    server.shutdown().await.unwrap();
}

/// A definition query TypeScript's compiler asserts on is refused, settled
/// as unprovable, and holds nothing owed: the same bytes assert the same way
/// every time, so asking again learns nothing.
#[tokio::test]
async fn a_typescript_internal_assertion_settles_its_query_as_unprovable() {
    use kin_model::EntityKind;
    let root = Workspace::new("debug-failure");
    let text = "function run() {\n      find(1)\n}\n";
    let run = entity_at("run", "source.ts", (0, 2), (0, 9), EntityKind::Function);
    let index = EntityIndex::new(vec![run.clone()], &root.0);
    let uri = root.uri("source.ts");
    let mut responses = json!({});
    responses[format!("{DEFINITION}@{uri}#6")] = json!({"error": {"code": 1, "message":
        "<main> TypeScript Server Error (5.6.3)\nDebug Failure.\nError: Debug Failure.\n    at getTextOfPropertyName (typescript.js:17277:16)"}});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let pass = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.0.join("source.ts"),
        text,
        &index,
        &root.0,
        None,
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();
    assert_eq!(
        (pass.failed_queries, pass.refused_queries),
        (0, 1),
        "{pass:?}"
    );
    assert_eq!(pass.first_failure, None, "{pass:?}");
    assert_eq!(pass.unprovable.len(), 1, "{pass:?}");
    assert_eq!(pass.unprovable[0].0, run.id);
}

#[tokio::test]
async fn per_entity_references_ask_at_the_declared_name_and_skip_a_module_surface() {
    let f = DecoratedFile::new();
    let server = LspServer::scripted_for_tests(PEER, f.responses());
    let provider = |path: &str| (path == DECORATED_PATH).then(|| DECORATED_TEXT.to_owned());
    for entity in [&f.login, &f.module] {
        let answer = enrichment::enrich_entity_references(
            &server,
            entity,
            &f.index,
            &f.root,
            Some(&provider),
        )
        .await;
        assert!(answer.unwrap().is_empty());
    }
    let asked: Vec<_> = seen(&server)
        .await
        .into_iter()
        .filter(|message| message["method"] == REFERENCES)
        .map(|message| message["params"]["position"].clone())
        .collect();
    assert_eq!(asked, [json!({"line": 5, "character": 4})]);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn decorated_python_same_spelling_queries_use_only_the_declaration_identity() {
    let root = held_root();
    for (line, signature, name, expected) in [
        ("def foo(foo):", "@de def foo(foo)", "foo", 4),
        ("class Foo(Foo):", "@de class Foo(Foo)", "Foo", 6),
        (
            "def cafe\u{0301}(cafe\u{0301}):",
            "@de def cafe\u{0301}(cafe\u{0301})",
            "cafe\u{0301}",
            4,
        ),
        (
            "class a\u{203f}b(a\u{203f}b):",
            "@de class a\u{203f}b(a\u{203f}b)",
            "a\u{203f}b",
            6,
        ),
    ] {
        let text = format!("@de\n{line}\n    pass\n");
        let mut entity = declared_at(
            name,
            "source.py",
            0,
            2,
            signature.find(name).unwrap() as u32,
        );
        entity.name_line = 1;
        let index = EntityIndex::new(vec![entity.clone()], &root);
        let provider = |path: &str| (path == "source.py").then(|| text.clone());
        let server = LspServer::scripted_for_tests(
            PEER,
            json!({
                REFERENCES: {"result": []}, PREPARE_CALL: {"result": []},
            }),
        );
        assert!(enrichment::enrich_entity_references(
            &server,
            &entity,
            &index,
            &root,
            Some(&provider),
        )
        .await
        .unwrap()
        .is_empty());
        if name == "foo" {
            assert!(enrichment::enrich_entity_calls(
                &server,
                &entity,
                &index,
                &root,
                Some(&provider),
            )
            .await
            .unwrap()
            .relations
            .is_empty());
        }
        let requests = seen(&server).await;
        let positions: Vec<_> = requests
            .iter()
            .filter(|request| request["method"] == REFERENCES || request["method"] == PREPARE_CALL)
            .map(|request| request["params"]["position"].clone())
            .collect();
        let count = if name == "foo" { 2 } else { 1 };
        assert_eq!(
            positions,
            vec![json!({"line": 1, "character": expected}); count]
        );
        assert!(!asked(&requests, REFERENCES, entity.name_col as usize));
        assert!(!asked(&requests, PREPARE_CALL, entity.name_col as usize));
        server.shutdown().await.unwrap();
    }

    let text = "@de\ndef other(foo):\n    pass\n";
    let mut entity = declared_at("foo", "source.py", 0, 2, 10);
    entity.name_line = 1;
    let index = EntityIndex::new(vec![entity.clone()], &root);
    let server = LspServer::scripted_for_tests(PEER, json!({REFERENCES: {"result": []}}));
    let refused = enrichment::enrich_entity_references(
        &server,
        &entity,
        &index,
        &root,
        Some(&|path: &str| (path == "source.py").then(|| text.to_owned())),
    )
    .await;
    assert!(refused.is_err());
    assert!(seen(&server)
        .await
        .iter()
        .all(|request| request["method"] != REFERENCES));
    server.shutdown().await.unwrap();
}

/// Flask's `get_db` reads `current_app.config`, and `current_app` is imported
/// from `flask`. Asked at the receiver, the server answers with the constant's
/// own declaration in another file. That answer used to be read as a module,
/// so the pass recorded nothing, and `find_references(current_app)` lost every
/// line that uses it as a receiver. A real module receiver still binds no edge
/// to the module, including `settings.DEBUG` where `settings.py` opens by
/// declaring a `settings` of its own: a module answers with an empty range.
#[tokio::test]
async fn an_imported_value_used_as_a_receiver_is_a_reference() {
    let root = std::env::temp_dir().join(format!("kin-lsp-value-receiver-{}", EntityId::new()));
    let text = "from pkg import current_app, flask\ndef get_db():\n    x = current_app.config\n    yy = flask.Blueprint\n    zzz = settings.DEBUG\n";
    let uri = crate::protocol::path_to_uri(&root.join("source.py"));
    let entity = |name: &str, file: &str, start, end, declares_name| EntityRef {
        id: EntityId::new(),
        name: name.into(),
        file_path: file.into(),
        start_line: start,
        start_col: 0,
        end_line: end,
        name_line: start,
        name_col: if name == "get_db" { 4 } else { 0 },
        declares_name,
        kind: kin_model::EntityKind::Function,
    };
    let get_db = entity("get_db", "source.py", 1, 4, true);
    let current_app = entity("current_app", "pkg/globals.py", 3, 5, true);
    let module = entity("pkg", "pkg/__init__.py", 0, 9, false);
    let settings = entity("settings", "conf/settings.py", 0, 0, true);
    let index = EntityIndex::new(
        vec![
            get_db.clone(),
            current_app.clone(),
            module.clone(),
            settings.clone(),
        ],
        &root,
    );
    let location = |file: &str, line: u32, end: u32| {
        json!([{"uri": crate::protocol::path_to_uri(&root.join(file)),
                "range": {"start": {"line": line, "character": 0}, "end": {"line": line, "character": end}}}])
    };
    let column = |line: usize, token: &str| text.lines().nth(line).unwrap().find(token).unwrap();
    let mut responses = json!({});
    responses[format!("{DEFINITION}@{uri}#{}", column(2, "current_app"))] =
        json!({"result": location("pkg/globals.py", 3, 11)});
    responses[format!("{DEFINITION}@{uri}#{}", column(3, "flask"))] =
        json!({"result": location("pkg/__init__.py", 0, 0)});
    responses[format!("{DEFINITION}@{uri}#{}", column(4, "settings"))] =
        json!({"result": location("conf/settings.py", 0, 0)});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.join("source.py"),
        text,
        &index,
        &root,
        None,
    )
    .await
    .unwrap();
    let edges: Vec<_> = answer
        .relations
        .iter()
        .map(|relation| (relation.kind, relation.src, relation.dst))
        .collect();
    assert_eq!(
        edges,
        [(
            RelationKind::References,
            GraphNodeId::Entity(get_db.id),
            GraphNodeId::Entity(current_app.id)
        )],
        "{answer:?}"
    );
    let span = answer.relations[0].evidence[0]
        .source_span
        .as_ref()
        .unwrap();
    assert_eq!(&text[span.start_byte..span.end_byte], "current_app");
    assert_eq!(span.start_line, 2);
    let asked_at_receiver = seen(&server)
        .await
        .into_iter()
        .filter(|message| {
            message["method"] == DEFINITION
                && message["params"]["position"]["character"] == column(2, "current_app")
        })
        .count();
    assert_eq!(
        asked_at_receiver, 1,
        "the edge is minted from the receiver's own answer, not from a second request"
    );
    server.shutdown().await.unwrap();
}

/// Under load one definition answer can miss its two-second window. That used
/// to fail the whole pass and throw away every relation the file had proven;
/// now it skips that identifier, counts it, and keeps going.
#[tokio::test]
async fn one_slow_definition_answer_skips_its_identifier_and_keeps_the_file() {
    let root = std::env::temp_dir().join(format!("kin-lsp-slow-answer-{}", EntityId::new()));
    let text = "def run():\n  alpha()\n      beta()\n";
    let uri = crate::protocol::path_to_uri(&root.join("source.py"));
    let entity = |name: &str, file: &str, start, end| EntityRef {
        id: EntityId::new(),
        name: name.into(),
        file_path: file.into(),
        start_line: start,
        start_col: 0,
        end_line: end,
        name_line: start,
        name_col: 4,
        declares_name: true,
        kind: kin_model::EntityKind::Function,
    };
    let run = entity("run", "source.py", 0, 2);
    let alpha = entity("alpha", "lib.py", 0, 1);
    let beta = entity("beta", "lib.py", 3, 4);
    let index = EntityIndex::new(vec![run.clone(), alpha.clone(), beta.clone()], &root);
    let mut responses = json!({});
    responses[format!("{DEFINITION}@{uri}#2")] = json!({"hold": true});
    responses[format!("{DEFINITION}@{uri}#6")] = json!({"result": [{
        "uri": crate::protocol::path_to_uri(&root.join("lib.py")),
        "range": {"start": {"line": 3, "character": 4}, "end": {"line": 3, "character": 8}},
    }]});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.join("source.py"),
        text,
        &index,
        &root,
        None,
    )
    .await
    .unwrap();
    assert_eq!(answer.failed_queries, 1, "{answer:?}");
    let edges: Vec<_> = answer
        .relations
        .iter()
        .map(|relation| (relation.src, relation.dst))
        .collect();
    assert_eq!(
        edges,
        [(GraphNodeId::Entity(run.id), GraphNodeId::Entity(beta.id))],
        "the identifier after the slow one still answers: {answer:?}"
    );
    server.shutdown().await.unwrap();
}

/// Every held request in `holds` times out. `answers` reply at a column of
/// `source.py`, and `anywhere` reply to a method wherever it is asked, which is
/// how an outgoing-calls request is keyed since it names no document. Returns
/// the pass over `text` in `source.py` and every request the server saw.
async fn pass_with_held_requests(
    text: &str,
    entities: Vec<EntityRef>,
    answers: &[(&str, usize, Value)],
    anywhere: &[(&str, Value)],
    holds: &[(&str, usize)],
) -> (
    Result<crate::file_enrichment::FileEnrichmentResult>,
    Vec<Value>,
) {
    let root = held_root();
    let uri = crate::protocol::path_to_uri(&root.join("source.py"));
    let mut responses = json!({});
    for (method, answer) in anywhere {
        responses[*method] = answer.clone();
    }
    for (method, column, answer) in answers {
        responses[format!("{method}@{uri}#{column}")] = answer.clone();
    }
    for (method, column) in holds {
        responses[format!("{method}@{uri}#{column}")] = json!({"hold": true});
    }
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.join("source.py"),
        text,
        &EntityIndex::new(entities, &root),
        &root,
        None,
    )
    .await;
    let requests = seen(&server).await;
    server.shutdown().await.unwrap();
    (answer, requests)
}

fn held_root() -> PathBuf {
    std::env::temp_dir().join("kin-lsp-held-requests")
}

fn declared_at(name: &str, file: &str, start: u32, end: u32, name_col: u32) -> EntityRef {
    EntityRef {
        id: EntityId::new(),
        name: name.into(),
        file_path: file.into(),
        start_line: start,
        start_col: 0,
        end_line: end,
        name_line: start,
        name_col,
        declares_name: true,
        kind: kin_model::EntityKind::Function,
    }
}

fn located(file: &str, line: u32, start: u32, end: u32) -> Value {
    json!({"result": [{
        "uri": crate::protocol::path_to_uri(&held_root().join(file)),
        "range": {"start": {"line": line, "character": start}, "end": {"line": line, "character": end}},
    }]})
}

fn edges_of(
    answer: &crate::file_enrichment::FileEnrichmentResult,
) -> Vec<(RelationKind, GraphNodeId, GraphNodeId)> {
    answer
        .relations
        .iter()
        .map(|relation| (relation.kind, relation.src, relation.dst))
        .collect()
}

fn asked(requests: &[Value], method: &str, column: usize) -> bool {
    requests.iter().any(|request| {
        request["method"] == method && request["params"]["position"]["character"] == column
    })
}

/// A receiver whose own definition query times out is skipped; the identifier
/// after it still answers and keeps its edge.
#[tokio::test]
async fn a_timed_out_receiver_query_skips_only_that_identifier() {
    let run = declared_at("run", "source.py", 0, 2, 4);
    let beta = declared_at("beta", "lib.py", 3, 4, 4);
    let (answer, _) = pass_with_held_requests(
        "def run():\n  alpha.go()\n      beta()\n",
        vec![run.clone(), beta.clone()],
        &[(DEFINITION, 6, located("lib.py", 3, 4, 8))],
        &[],
        &[(DEFINITION, 2)],
    )
    .await;
    let answer = answer.unwrap();
    assert_eq!(answer.failed_queries, 1, "{answer:?}");
    assert_eq!(
        edges_of(&answer),
        [(
            RelationKind::References,
            GraphNodeId::Entity(run.id),
            GraphNodeId::Entity(beta.id)
        )]
    );
}

/// A module receiver whose member join times out is skipped the same way.
#[tokio::test]
async fn a_timed_out_member_join_skips_only_that_identifier() {
    let run = declared_at("run", "source.py", 0, 2, 4);
    let beta = declared_at("beta", "lib.py", 3, 4, 4);
    let mut surface = declared_at("pkg", "pkg/__init__.py", 0, 9, 0);
    surface.declares_name = false;
    let (answer, requests) = pass_with_held_requests(
        "def run():\n  mod.go()\n        beta()\n",
        vec![run.clone(), beta.clone(), surface],
        &[
            (DEFINITION, 2, located("pkg/__init__.py", 0, 0, 0)),
            (DEFINITION, 8, located("lib.py", 3, 4, 8)),
        ],
        &[],
        &[(TYPES, 2)],
    )
    .await;
    let answer = answer.unwrap();
    assert!(asked(&requests, TYPES, 2), "the join's module query ran");
    assert_eq!(answer.failed_queries, 1, "{answer:?}");
    assert_eq!(
        edges_of(&answer),
        [(
            RelationKind::References,
            GraphNodeId::Entity(run.id),
            GraphNodeId::Entity(beta.id)
        )]
    );
}

/// One entity's call hierarchy timing out costs that entity its Calls edges;
/// the next entity in the file still gets its own.
#[tokio::test]
async fn a_timed_out_call_hierarchy_skips_only_that_entity() {
    let run = declared_at("run", "source.py", 0, 1, 4);
    let walk = declared_at("walk", "source.py", 2, 3, 5);
    let target = declared_at("target", "lib.py", 0, 1, 4);
    let root = held_root();
    let item = |entity: &EntityRef, line: u32, start: u32| {
        json!({
            "name": entity.name, "kind": 12,
            "uri": crate::protocol::path_to_uri(&root.join(&entity.file_path)),
            "range": {"start": {"line": line, "character": start}, "end": {"line": line, "character": start + entity.name.len() as u32}},
            "selectionRange": {"start": {"line": line, "character": start}, "end": {"line": line, "character": start + entity.name.len() as u32}},
        })
    };
    let (answer, requests) = pass_with_held_requests(
        "def run():\n    pass\ndef  walk():\n    target()\n",
        vec![run.clone(), walk.clone(), target.clone()],
        &[(PREPARE_CALL, 5, json!({"result": [item(&walk, 2, 5)]}))],
        &[(
            CALLS,
            json!({"result": [{"to": item(&target, 0, 4), "fromRanges": [
                {"start": {"line": 3, "character": 4}, "end": {"line": 3, "character": 10}}
            ]}]}),
        )],
        &[(PREPARE_CALL, 4)],
    )
    .await;
    let answer = answer.unwrap();
    assert!(asked(&requests, PREPARE_CALL, 4) && asked(&requests, PREPARE_CALL, 5));
    assert_eq!(answer.failed_queries, 1, "{answer:?}");
    assert!(
        !answer.call_hierarchy_complete,
        "an entity whose call hierarchy timed out is still to be asked: {answer:?}"
    );
    assert!(
        edges_of(&answer).contains(&(
            RelationKind::Calls,
            GraphNodeId::Entity(walk.id),
            GraphNodeId::Entity(target.id)
        )),
        "{answer:?}"
    );
}

/// Three timeouts in a row stop the pass: what was proven is kept, nothing
/// later in the file is asked, and no call hierarchy is attempted.
#[tokio::test]
async fn three_timeouts_in_a_row_stop_the_pass_with_what_it_proved() {
    let run = declared_at("run", "source.py", 0, 5, 4);
    let beta = declared_at("beta", "lib.py", 3, 4, 4);
    let (answer, requests) = pass_with_held_requests(
        "def run():\n  beta()\n      a()\n       b()\n        c()\n         d()\n",
        vec![run.clone(), beta.clone()],
        &[(DEFINITION, 2, located("lib.py", 3, 4, 8))],
        &[],
        &[(DEFINITION, 6), (DEFINITION, 7), (DEFINITION, 8)],
    )
    .await;
    let answer = answer.unwrap();
    assert_eq!(answer.failed_queries, 3, "{answer:?}");
    assert_eq!(
        edges_of(&answer),
        [(
            RelationKind::References,
            GraphNodeId::Entity(run.id),
            GraphNodeId::Entity(beta.id)
        )]
    );
    assert!(
        !asked(&requests, DEFINITION, 9),
        "nothing after the third timeout is asked"
    );
    assert!(!answer.call_hierarchy_complete, "{answer:?}");
    assert!(
        !requests
            .iter()
            .any(|request| request["method"] == PREPARE_CALL),
        "a server that stopped answering is not asked for call hierarchy"
    );
}

/// Flask's `Scaffold`: pyright answers `_static_folder` with the class
/// attribute and with the `self._static_folder = value` inside the property
/// setter. The second answer lands inside the setter's body, not on its
/// declaration, and it made the attribute's own line read as a reference to
/// the setter: one of main's wrong lines on the setter's `find_references`.
#[tokio::test]
async fn a_python_answer_inside_a_body_is_not_a_reference_to_that_body() {
    let scaffold = declared_at("Scaffold", "source.py", 0, 4, 6);
    let setter = declared_at("Scaffold.static_folder", "source.py", 3, 4, 8);
    let root = held_root();
    let both = json!({"result": [
        {"uri": crate::protocol::path_to_uri(&root.join("source.py")),
         "range": {"start": {"line": 1, "character": 4}, "end": {"line": 1, "character": 18}}},
        {"uri": crate::protocol::path_to_uri(&root.join("source.py")),
         "range": {"start": {"line": 4, "character": 13}, "end": {"line": 4, "character": 27}}},
    ]});
    let (answer, requests) = pass_with_held_requests(
        "class Scaffold:\n    _static_folder = None\n\n    def static_folder(self, value):\n        self._static_folder = value\n",
        vec![scaffold, setter],
        &[(DEFINITION, 4, both.clone()), (DEFINITION, 13, both)],
        &[],
        &[],
    )
    .await;
    let answer = answer.unwrap();
    assert!(
        asked(&requests, DEFINITION, 4),
        "the attribute was asked about"
    );
    assert_eq!(answer.failed_queries, 0);
    assert!(
        answer.relations.is_empty(),
        "no entity is referenced by the attribute's own line: {answer:?}"
    );
}

/// pyright answers a module with an empty range at the top of its file, and
/// `find_at` turned that into whatever the file's first line declares, so
/// `from .globals import current_app` read as a reference to the class
/// `globals.py` opens with. A module surface is what such an answer names.
#[tokio::test]
async fn a_python_module_answer_is_not_a_reference_to_the_first_declaration() {
    let surface = |name: &str, file: &str, end: u32| EntityRef {
        declares_name: false,
        kind: kin_model::EntityKind::Function,
        ..declared_at(name, file, 0, end, 0)
    };
    let importer = surface("source", "source.py", 1);
    let proxy = declared_at("_Proxy", "globals.py", 0, 1, 6);
    let helpers = surface("helpers", "helpers.py", 3);
    let (answer, requests) = pass_with_held_requests(
        "from .globals import current_app\nimport helpers\n",
        vec![importer.clone(), proxy, helpers.clone()],
        &[
            (DEFINITION, 6, located("globals.py", 0, 0, 0)),
            (DEFINITION, 7, located("helpers.py", 0, 0, 0)),
        ],
        &[],
        &[],
    )
    .await;
    let answer = answer.unwrap();
    assert!(
        asked(&requests, DEFINITION, 6),
        "the module name was asked about"
    );
    assert_eq!(answer.failed_queries, 0);
    assert_eq!(
        edges_of(&answer),
        [(
            RelationKind::References,
            GraphNodeId::Entity(importer.id),
            GraphNodeId::Entity(helpers.id)
        )],
        "an import names the module surface and never the class on its first line: {answer:?}"
    );
}

/// A candidate export whose declaration line does not spell its name cannot
/// be asked about. A TypeScript export with its decorator on its own line is
/// one: the adapter records no declaration line below the decorator. That
/// used to fail the whole file pass. Now the join is left unfinished and
/// counted, and every other edge in the file stands. The UsesType arm has no
/// partial answer, so it still reports the entity's failure.
#[tokio::test]
async fn an_unlocatable_candidate_costs_its_join_and_not_the_file() {
    let root = std::env::temp_dir().join(format!("kin-lsp-unlocated-{}", EntityId::new()));
    let text = "export function run() {\n  mod.go();\n    beta();\n}\n";
    let candidate_text = "@decorate\nexport function go() {}\n";
    let uri = crate::protocol::path_to_uri(&root.join("source.ts"));
    let module_uri = crate::protocol::path_to_uri(&root.join("lib/mod.ts"));
    let beta_uri = crate::protocol::path_to_uri(&root.join("lib/beta.ts"));
    let run = declared_at("run", "source.ts", 0, 3, 16);
    let go = declared_at("go", "lib/mod.ts", 0, 1, 16);
    let beta = declared_at("beta", "lib/beta.ts", 0, 0, 16);
    let index = EntityIndex::new(vec![run.clone(), go, beta.clone()], &root);
    let at = |target: &str, line: u32, start: u32, end: u32| {
        json!({"result": [{"uri": target, "range": {
            "start": {"line": line, "character": start},
            "end": {"line": line, "character": end}}}]})
    };
    let mut responses = json!({});
    // `mod` names its module, and a module answers with an empty range.
    responses[format!("{DEFINITION}@{uri}#2")] = at(&module_uri, 0, 0, 0);
    responses[format!("{TYPES}@{uri}#2")] = at(&module_uri, 0, 0, 0);
    // `go` resolves outside the tree, so its own turn mints nothing.
    responses[format!("{DEFINITION}@{uri}#6")] = at("file:///dependency/go.ts", 0, 0, 2);
    responses[format!("{DEFINITION}@{uri}#4")] = at(&beta_uri, 0, 16, 20);
    let provider = |path: &str| match path {
        "source.ts" => Some(text.to_owned()),
        "lib/mod.ts" => Some(candidate_text.to_owned()),
        _ => None,
    };

    let mut server = LspServer::scripted_for_tests(PEER, responses.clone());
    server.capabilities.call_hierarchy_provider = None;
    let answer = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.join("source.ts"),
        text,
        &index,
        &root,
        Some(&provider),
    )
    .await
    .expect("one candidate that cannot be asked about must not fail the file");
    assert_eq!(
        (answer.failed_queries, answer.refused_queries),
        (0, 1),
        "{answer:?}"
    );
    assert_eq!(
        answer.declined_queries, 0,
        "unasked is not a semantic decline"
    );
    assert_eq!(answer.first_failure, None, "{answer:?}");
    assert!(
        answer
            .unprovable
            .iter()
            .any(|(_, reason)| reason.contains("could not locate a candidate declaration")),
        "{answer:?}"
    );
    assert_eq!(
        edges_of(&answer),
        [(
            RelationKind::References,
            GraphNodeId::Entity(run.id),
            GraphNodeId::Entity(beta.id)
        )]
    );
    let requests = seen(&server).await;
    assert!(
        requests.iter().any(|request| request["method"] == TYPES),
        "the join asked for the receiver's module"
    );
    assert!(
        !requests
            .iter()
            .any(|request| request["method"] == DEFINITION
                && request["params"]["textDocument"]["uri"] == module_uri),
        "nothing is asked on a line that does not spell the candidate's name"
    );
    server.shutdown().await.unwrap();

    let server = LspServer::scripted_for_tests(PEER, responses);
    let uses = enrichment::enrich_entity_uses_type(&server, &run, &index, &root, Some(&provider))
        .await
        .expect_err("the UsesType arm reports the unfinished join as its failure");
    assert!(uses.to_string().contains("`go`"), "{uses}");
    server.shutdown().await.unwrap();
}

/// The UsesType arm reads a Python type answer the way the definitions pass
/// reads a definition. An empty answer names a module, not the class the
/// module opens with, and an answer inside the class body names something
/// declared there. Only the answer on the class's own name is its type.
#[tokio::test]
async fn a_python_type_answer_is_the_entity_only_on_its_own_name() {
    let root = std::env::temp_dir().join(format!("kin-lsp-type-answers-{}", EntityId::new()));
    let text = "def run(a, b, c):\n    pass\n";
    let uri = crate::protocol::path_to_uri(&root.join("source.py"));
    let globals = crate::protocol::path_to_uri(&root.join("globals.py"));
    let run = declared_at("run", "source.py", 0, 1, 4);
    let proxy = declared_at("_Proxy", "globals.py", 0, 2, 6);
    let index = EntityIndex::new(vec![run.clone(), proxy.clone()], &root);
    let at = |line: u32, start: u32, end: u32| {
        json!({"result": [{"uri": globals, "range": {
            "start": {"line": line, "character": start},
            "end": {"line": line, "character": end}}}]})
    };
    let column = |token: &str| text.lines().next().unwrap().find(token).unwrap();
    let mut responses = json!({});
    responses[format!("{TYPES}@{uri}#{}", column("a,"))] = at(0, 0, 0);
    responses[format!("{TYPES}@{uri}#{}", column("b,"))] = at(1, 4, 10);
    responses[format!("{TYPES}@{uri}#{}", column("c)"))] = at(0, 6, 12);
    let server = LspServer::scripted_for_tests(PEER, responses);
    let relations = enrichment::enrich_entity_uses_type(
        &server,
        &run,
        &index,
        &root,
        Some(&|_| Some(text.to_owned())),
    )
    .await
    .unwrap();
    assert_eq!(
        relations
            .iter()
            .map(|relation| (relation.kind, relation.dst))
            .collect::<Vec<_>>(),
        [(RelationKind::UsesType, GraphNodeId::Entity(proxy.id))],
        "{relations:?}"
    );
    let span = relations[0].evidence[0].source_span.as_ref().unwrap();
    assert_eq!(
        &text[span.start_byte..span.end_byte],
        "c",
        "the module answer at `a` and the body answer at `b` name nothing"
    );
    server.shutdown().await.unwrap();
}

/// Three call-hierarchy timeouts in a row stop asking. The entity after them
/// is not asked, and each timeout is counted.
#[tokio::test]
async fn three_call_hierarchy_timeouts_in_a_row_stop_asking() {
    let (answer, requests) = pass_with_held_requests(
        "def a():\n  def bb():\n    def ccc():\n      def dddd():\n",
        vec![
            declared_at("a", "source.py", 0, 0, 4),
            declared_at("bb", "source.py", 1, 1, 6),
            declared_at("ccc", "source.py", 2, 2, 8),
            declared_at("dddd", "source.py", 3, 3, 10),
        ],
        &[],
        &[],
        &[(PREPARE_CALL, 4), (PREPARE_CALL, 6), (PREPARE_CALL, 8)],
    )
    .await;
    let answer = answer.unwrap();
    assert_eq!(answer.failed_queries, 3, "{answer:?}");
    assert!(
        asked(&requests, PREPARE_CALL, 4)
            && asked(&requests, PREPARE_CALL, 6)
            && asked(&requests, PREPARE_CALL, 8)
    );
    assert!(
        !asked(&requests, PREPARE_CALL, 10),
        "the entity after the third timeout in a row is not asked"
    );
}

/// The answers gopls gives for a method, scripted: its `references` answer is
/// widened by the methods related to it through an interface, and only its
/// `definition` answer at each site says which declaration the site is.
mod go_method_references {
    use super::*;

    const IMPLEMENTATION: &str = "textDocument/implementation";

    const REPO: &str = "package repo\n\
                        \n\
                        type Interface interface {\n\
                        \tRepoOwner() string\n\
                        }\n\
                        \n\
                        type Concrete struct{}\n\
                        \n\
                        func (c Concrete) RepoOwner() string {\n\
                        \treturn \"\"\n\
                        }\n";
    const VIA: &str = "package via\n\
                       \n\
                       func ViaInterface(r repo.Interface) string {\n\
                       \treturn r.RepoOwner()\n\
                       }\n";
    const DIRECT: &str = "package direct\n\
                          \n\
                          func Direct(c repo.Concrete) string {\n\
                          \treturn c.RepoOwner()\n\
                          }\n";

    struct Go {
        root: PathBuf,
        interface_method: EntityRef,
        concrete_method: EntityRef,
        via: EntityRef,
        direct: EntityRef,
        index: EntityIndex,
    }

    impl Go {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("kin-lsp-go-refs-{}", EntityId::new()));
            std::fs::create_dir(&root).unwrap();
            let entity = |name: &str, file: &str, lines: (u32, u32), name_col, kind| EntityRef {
                id: EntityId::new(),
                name: name.into(),
                file_path: file.into(),
                start_line: lines.0,
                start_col: 0,
                end_line: lines.1,
                name_line: lines.0,
                name_col,
                declares_name: true,
                kind,
            };
            use kin_model::EntityKind::{Function, Method};
            let mut interface_method =
                entity("Interface.RepoOwner", "repo/repo.go", (3, 3), 1, Method);
            interface_method.start_col = 1;
            // The daemon's hint for a method comes from its stored signature,
            // `func(c Concrete) RepoOwner() string`, one column short of the
            // source's `func (c Concrete)`; the query is asked at the name.
            let concrete_method = entity("Concrete.RepoOwner", "repo/repo.go", (8, 10), 17, Method);
            let via = entity("ViaInterface", "via/via.go", (2, 4), 5, Function);
            let direct = entity("Direct", "direct/direct.go", (2, 4), 5, Function);
            let index = EntityIndex::new(
                vec![
                    interface_method.clone(),
                    concrete_method.clone(),
                    via.clone(),
                    direct.clone(),
                ],
                &root,
            );
            Self {
                root,
                interface_method,
                concrete_method,
                via,
                direct,
                index,
            }
        }

        fn uri(&self, file: &str) -> String {
            crate::protocol::path_to_uri(&self.root.join(file))
        }

        fn location(&self, file: &str, line: u32, start: u32, end: u32) -> Value {
            json!({"uri": self.uri(file), "range": {
                "start": {"line": line, "character": start},
                "end": {"line": line, "character": end}}})
        }

        /// What gopls v0.22.0 answers here. `references` names both calls,
        /// asked at either method, and `definition` names the one declaration
        /// each call resolves to. `implementation` at the concrete method names
        /// the interface method it corresponds to.
        fn responses(&self, implementation: Value) -> Value {
            let calls = json!([
                self.location("via/via.go", 3, 10, 19),
                self.location("direct/direct.go", 3, 10, 19),
            ]);
            let mut responses = json!({ REFERENCES: {"result": calls} });
            responses[format!("{IMPLEMENTATION}@{}#18", self.uri("repo/repo.go"))] =
                json!({ "result": implementation });
            responses[format!("{DEFINITION}@{}#10", self.uri("via/via.go"))] =
                json!({"result": [self.location("repo/repo.go", 3, 1, 10)]});
            responses[format!("{DEFINITION}@{}#10", self.uri("direct/direct.go"))] =
                json!({"result": [self.location("repo/repo.go", 8, 18, 27)]});
            responses
        }

        fn interface_method_location(&self) -> Value {
            json!([self.location("repo/repo.go", 3, 1, 10)])
        }

        async fn references(&self, server: &LspServer, entity: &EntityRef) -> Vec<Relation> {
            let provider = |file: &str| match file {
                "repo/repo.go" => Some(REPO.to_owned()),
                "via/via.go" => Some(VIA.to_owned()),
                "direct/direct.go" => Some(DIRECT.to_owned()),
                _ => None,
            };
            enrichment::enrich_entity_references(
                server,
                entity,
                &self.index,
                &self.root,
                Some(&provider),
            )
            .await
            .expect("the references arm answers")
        }
    }

    impl Drop for Go {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn sources(relations: &[Relation]) -> Vec<GraphNodeId> {
        relations.iter().map(|relation| relation.src).collect()
    }

    fn asked(requests: &[Value], method: &str) -> usize {
        requests
            .iter()
            .filter(|request| request["method"] == method)
            .count()
    }

    /// A call through the interface is not a reference to the concrete method
    /// its type checker never resolves it to. gopls names it anyway, because
    /// the concrete type satisfies the interface, and it was recorded as a
    /// proven caller.
    #[tokio::test]
    async fn an_interface_call_is_not_a_reference_to_the_concrete_method() {
        let go = Go::new();
        let server =
            LspServer::scripted_for_tests(PEER, go.responses(go.interface_method_location()));
        let relations = go.references(&server, &go.concrete_method).await;
        assert_eq!(
            sources(&relations),
            [GraphNodeId::Entity(go.direct.id)],
            "only the direct call resolves to Concrete.RepoOwner: {relations:?}"
        );
        assert!(relations
            .iter()
            .all(|relation| relation.dst == GraphNodeId::Entity(go.concrete_method.id)));
        let span = relations[0].evidence[0].source_span.as_ref().unwrap();
        assert_eq!(span.file.0, "direct/direct.go");
        assert_eq!(&DIRECT[span.start_byte..span.end_byte], "RepoOwner");
        let requests = seen(&server).await;
        let implementation = requests
            .iter()
            .find(|request| request["method"] == IMPLEMENTATION)
            .expect("the concrete method is asked what it corresponds to");
        assert_eq!(implementation["params"]["position"]["character"], 18);
        assert_eq!(asked(&requests, DEFINITION), 2, "each site is proven");
        server.shutdown().await.unwrap();
    }

    /// The same widening the other way round: a direct call of the concrete
    /// method is not a reference to the interface method it implements.
    #[tokio::test]
    async fn a_concrete_call_is_not_a_reference_to_the_interface_method() {
        let go = Go::new();
        let server =
            LspServer::scripted_for_tests(PEER, go.responses(go.interface_method_location()));
        let relations = go.references(&server, &go.interface_method).await;
        assert_eq!(
            sources(&relations),
            [GraphNodeId::Entity(go.via.id)],
            "only the call through the interface resolves to Interface.RepoOwner: {relations:?}"
        );
        let requests = seen(&server).await;
        assert_eq!(
            asked(&requests, IMPLEMENTATION),
            0,
            "an interface method's answer is always proven, so nothing is asked about it"
        );
        assert_eq!(asked(&requests, DEFINITION), 2);
        server.shutdown().await.unwrap();
    }

    /// A concrete method nothing dispatches to keeps the answer it was given,
    /// and no site is asked about again: gopls widens only through the
    /// interface methods `implementation` names.
    #[tokio::test]
    async fn a_method_no_interface_reaches_keeps_its_answer_unasked() {
        let go = Go::new();
        let server = LspServer::scripted_for_tests(PEER, go.responses(Value::Null));
        let relations = go.references(&server, &go.concrete_method).await;
        let mut found = sources(&relations);
        found.sort_by_key(|node| format!("{node:?}"));
        let mut expected = vec![
            GraphNodeId::Entity(go.via.id),
            GraphNodeId::Entity(go.direct.id),
        ];
        expected.sort_by_key(|node| format!("{node:?}"));
        assert_eq!(found, expected);
        let requests = seen(&server).await;
        assert_eq!(asked(&requests, IMPLEMENTATION), 1);
        assert_eq!(asked(&requests, DEFINITION), 0, "no site is re-asked");
        server.shutdown().await.unwrap();
    }

    /// A site whose definition the server cannot give is not proven, so it is
    /// not recorded; any other failure is the arm's.
    #[tokio::test]
    async fn an_unproven_site_is_not_recorded_and_a_failed_proof_fails_the_arm() {
        let go = Go::new();
        let mut responses = go.responses(go.interface_method_location());
        responses[format!("{DEFINITION}@{}#10", go.uri("direct/direct.go"))] =
            json!({"result": null});
        let server = LspServer::scripted_for_tests(PEER, responses);
        let relations = go.references(&server, &go.concrete_method).await;
        assert!(relations.is_empty(), "{relations:?}");
        server.shutdown().await.unwrap();

        let mut responses = go.responses(go.interface_method_location());
        responses[format!("{DEFINITION}@{}#10", go.uri("direct/direct.go"))] =
            json!({"error": {"code": -32603, "message": "injected definition failure"}});
        let server = LspServer::scripted_for_tests(PEER, responses);
        let provider = |file: &str| match file {
            "repo/repo.go" => Some(REPO.to_owned()),
            "via/via.go" => Some(VIA.to_owned()),
            "direct/direct.go" => Some(DIRECT.to_owned()),
            _ => None,
        };
        let answer = enrichment::enrich_entity_references(
            &server,
            &go.concrete_method,
            &go.index,
            &go.root,
            Some(&provider),
        )
        .await;
        assert!(
            matches!(answer, Err(LspError::JsonRpc(_))),
            "a proof that failed is the arm's failure, not an empty answer: {answer:?}"
        );
        server.shutdown().await.unwrap();
    }

    /// Python methods are not widened this way, so their answers are taken as
    /// given and nothing more is asked.
    #[tokio::test]
    async fn a_python_method_is_asked_nothing_more() {
        let f = Fixture::new(None);
        let mut method = f.source.clone();
        method.kind = kin_model::EntityKind::Method;
        let server = LspServer::scripted_for_tests(PEER, f.responses());
        let provider = |path: &str| match path {
            "source.py" => Some("Widget".to_owned()),
            "types.py" => Some(format!("{}Widget", "\n".repeat(10))),
            _ => None,
        };
        let relations = enrichment::enrich_entity_references(
            &server,
            &method,
            &f.index,
            &f.root,
            Some(&provider),
        )
        .await
        .unwrap();
        assert_eq!(sources(&relations), [GraphNodeId::Entity(f.target.id)]);
        let requests = seen(&server).await;
        assert_eq!(asked(&requests, IMPLEMENTATION), 0);
        assert_eq!(asked(&requests, DEFINITION), 0);
        server.shutdown().await.unwrap();
    }

    fn rules(relations: &[Relation]) -> Vec<Option<String>> {
        let mut rules: Vec<Option<String>> = relations
            .iter()
            .flat_map(|relation| relation.evidence.iter())
            .map(|evidence| evidence.parser_rule.clone())
            .collect();
        rules.dedup();
        rules
    }

    /// A Go method's sites carry the proven rule, whether each was proven by
    /// its definition or the method's answer could not have been widened, and
    /// any other entity's sites keep the rule they always had.
    ///
    /// Builds before the proof wrote a Go method's widened answer under the
    /// plain rule, and stores they enriched still hold those records. The two
    /// rules are how a reader tells the records apart.
    #[tokio::test]
    async fn a_go_methods_proven_sites_carry_their_own_rule() {
        let proven = || {
            vec![Some(
                kin_model::LSP_PROVEN_METHOD_REFERENCES_RULE.to_string(),
            )]
        };
        let go = Go::new();
        for (implementation, entity) in [
            (go.interface_method_location(), &go.concrete_method),
            (go.interface_method_location(), &go.interface_method),
            (Value::Null, &go.concrete_method),
        ] {
            let server = LspServer::scripted_for_tests(PEER, go.responses(implementation));
            let relations = go.references(&server, entity).await;
            assert!(!relations.is_empty(), "{}", entity.name);
            assert_eq!(
                rules(&relations),
                proven(),
                "{}: {relations:?}",
                entity.name
            );
            server.shutdown().await.unwrap();
        }

        let f = Fixture::new(None);
        let mut method = f.source.clone();
        method.kind = kin_model::EntityKind::Method;
        let server = LspServer::scripted_for_tests(PEER, f.responses());
        let provider = |path: &str| match path {
            "source.py" => Some("Widget".to_owned()),
            "types.py" => Some(format!("{}Widget", "\n".repeat(10))),
            _ => None,
        };
        let relations = enrichment::enrich_entity_references(
            &server,
            &method,
            &f.index,
            &f.root,
            Some(&provider),
        )
        .await
        .unwrap();
        assert_eq!(
            rules(&relations),
            [Some(kin_model::LSP_REFERENCES_RULE.to_string())],
            "a Python method's sites keep the plain rule: {relations:?}"
        );
        server.shutdown().await.unwrap();
    }
}

/// The references arm on files whose repository paths end each other.
///
/// cli/cli's attestation client has a namesake at the root:
/// `api/client_test.go` ends `pkg/cmd/attestation/api/client_test.go`, and
/// `api/client.go` ends `pkg/cmd/attestation/api/client.go`. Both files of
/// each pair declare something on the lines these answers name. Placing an
/// answer by suffix let each index's hash seed pick the file, and a wrong pick
/// either refused the whole answer, because the site's URI does not name the
/// file it was placed in, or dropped the site, because its definition was
/// placed in the root file's `NewClientFromHTTP`. Either way the query for
/// `Client.GetByRepoAndDigest` came back empty.
mod colliding_file_paths {
    use super::*;

    /// Where the checkout sits. The arm reads nothing from it.
    const ROOT: &str = "/work/cli";

    /// Fresh indexes, each hashing under its own seed. A seed-dependent
    /// placement is right for both answers in about a quarter of them.
    const BUILDS: usize = 64;

    const INTERFACE_FILE: &str = "pkg/cmd/attestation/api/client.go";
    const CALLER_FILE: &str = "pkg/cmd/attestation/api/client_test.go";

    fn declared(
        name: &str,
        file: &str,
        lines: (u32, u32),
        column: u32,
        kind: kin_model::EntityKind,
    ) -> EntityRef {
        EntityRef {
            id: EntityId::new(),
            name: name.into(),
            file_path: file.into(),
            start_line: lines.0,
            start_col: column,
            end_line: lines.1,
            name_line: lines.0,
            name_col: column,
            declares_name: true,
            kind,
        }
    }

    fn uri(file: &str) -> String {
        crate::protocol::path_to_uri(&std::path::Path::new(ROOT).join(file))
    }

    fn located(file: &str, line: u32, start: u32, end: u32) -> Value {
        json!({"uri": uri(file), "range": {
            "start": {"line": line, "character": start},
            "end": {"line": line, "character": end}}})
    }

    /// Text with `line` at 0-based `number` and blank lines before it.
    fn text_at(number: usize, line: &str) -> String {
        format!("{}{line}\n}}\n", "\n".repeat(number))
    }

    #[tokio::test]
    async fn a_colliding_file_is_never_the_one_an_answer_is_placed_in() {
        use kin_model::EntityKind::{Function, Method};
        // Spans as cli/cli c033f2961 has them, 0-based.
        let method = declared(
            "Client.GetByRepoAndDigest",
            INTERFACE_FILE,
            (27, 27),
            1,
            Method,
        );
        let caller = declared("TestGetByDigest", CALLER_FILE, (57, 72), 5, Function);
        let entities = vec![
            method.clone(),
            caller.clone(),
            declared("NewClientFromHTTP", "api/client.go", (27, 30), 5, Function),
            declared(
                "TestGraphQLError",
                "api/client_test.go",
                (46, 75),
                5,
                Function,
            ),
        ];
        // What gopls answers: the call in the attestation test, and that the
        // call resolves to the interface method it names.
        let server = LspServer::scripted_for_tests(
            PEER,
            json!({
                REFERENCES: {"result": [located(CALLER_FILE, 59, 24, 42)]},
                DEFINITION: {"result": [located(INTERFACE_FILE, 27, 1, 19)]},
            }),
        );
        let interface_text = text_at(
            27,
            "\tGetByRepoAndDigest(repo, digest string, limit int) ([]*Attestation, error)",
        );
        let caller_text = text_at(
            59,
            "\tattestations, err := c.GetByRepoAndDigest(testRepo, testDigest, DefaultLimit)",
        );
        let provider = |file: &str| match file {
            INTERFACE_FILE => Some(interface_text.clone()),
            CALLER_FILE => Some(caller_text.clone()),
            _ => None,
        };
        let root = std::path::Path::new(ROOT);

        let mut refused = Vec::new();
        let mut dropped = Vec::new();
        for build in 0..BUILDS {
            let index = EntityIndex::new(entities.clone(), root);
            match enrichment::enrich_entity_references(
                &server,
                &method,
                &index,
                root,
                Some(&provider),
            )
            .await
            {
                Err(error) => refused.push(format!("build {build}: {error}")),
                Ok(relations) if relations.is_empty() => {
                    dropped.push(format!("build {build}: the site was dropped"))
                }
                Ok(relations) => {
                    assert_eq!(relations.len(), 1, "build {build}: {relations:?}");
                    let relation = &relations[0];
                    assert_eq!(relation.src, GraphNodeId::Entity(caller.id));
                    assert_eq!(relation.dst, GraphNodeId::Entity(method.id));
                    let span = relation.evidence[0].source_span.as_ref().expect("a site");
                    assert_eq!((span.file.0.as_str(), span.start_line), (CALLER_FILE, 59));
                    assert_eq!(
                        &caller_text[span.start_byte..span.end_byte],
                        "GetByRepoAndDigest"
                    );
                }
            }
        }
        server.shutdown().await.unwrap();
        assert!(
            refused.is_empty() && dropped.is_empty(),
            "of {BUILDS} builds, {} refused the answer and {} dropped its one site:\n{}\n{}",
            refused.len(),
            dropped.len(),
            refused.join("\n"),
            dropped.join("\n"),
        );
    }

    /// The file enriched below, the root `api/client.go`, and the member
    /// expression in it: the receiver `attestation` at column 1 of line 3 and
    /// the member `NewLiveClient` at column 13.
    const ENRICHED_FILE: &str = "api/client.go";
    const ENRICHED_TEXT: &str = "package api\n\nfunc build(hc *http.Client) {\n\
                                 \tattestation.NewLiveClient(hc, host, logger)\n}\n";
    const RECEIVER_COLUMN: u32 = 1;
    const MEMBER_COLUMN: u32 = 13;

    /// A module cache path outside the checkout that also ends in
    /// `api/client.go`.
    const MODULE_CACHE_FILE: &str =
        "file:///home/dev/go/pkg/mod/github.com/cli/go-gh/v2@v2.11.2/pkg/api/client.go";

    /// Where the server resolves the receiver in `api/client.go`.
    #[derive(Clone, Copy, Debug)]
    enum ReceiverHome {
        /// `pkg/cmd/attestation/api/client.go`, which declares the member.
        CollidingFile,
        /// [`MODULE_CACHE_FILE`].
        ModuleCache,
    }

    fn enriched_provider(file: &str) -> Option<String> {
        match file {
            ENRICHED_FILE => Some(ENRICHED_TEXT.to_owned()),
            INTERFACE_FILE => Some(text_at(
                38,
                "func NewLiveClient(hc *http.Client, host string, l *ioconfig.Handler) *LiveClient {",
            )),
            _ => None,
        }
    }

    /// Whether the server was asked `method` at `column` of line 3 of the
    /// enriched file.
    fn asked_at(requests: &[Value], method: &str, column: u32) -> bool {
        requests.iter().any(|request| {
            request["method"] == method
                && request["params"]["textDocument"]["uri"] == uri(ENRICHED_FILE)
                && request["params"]["position"]["line"] == 3
                && request["params"]["position"]["character"] == column
        })
    }

    /// Whether `relations` holds a `kind` edge from `from` to `to` that the
    /// member join minted.
    fn joined(
        relations: &[Relation],
        kind: RelationKind,
        from: &EntityRef,
        to: &EntityRef,
    ) -> bool {
        relations.iter().any(|relation| {
            relation.kind == kind
                && relation.src == GraphNodeId::Entity(from.id)
                && relation.dst == GraphNodeId::Entity(to.id)
                && relation
                    .evidence
                    .iter()
                    .any(|evidence| evidence.parser_rule.as_deref() == Some("lsp_member_on_module"))
        })
    }

    /// A receiver resolved into another file is a module receiver, however
    /// that file's path ends, and its member is joined in both arms that ask.
    /// Matched by suffix, a definition in `pkg/cmd/attestation/api/client.go`
    /// or in a module cache path read as the enriched `api/client.go` itself,
    /// so the receiver was taken for a value there and the join was skipped.
    #[tokio::test]
    async fn a_receiver_resolved_into_a_file_whose_path_ends_like_this_one_is_joined() {
        use kin_model::EntityKind::Function;
        let root = std::path::Path::new(ROOT);
        let build = declared("build", ENRICHED_FILE, (2, 4), 5, Function);
        // `NewLiveClient` where cli/cli c033f2961 declares it, 0-based.
        let export = declared("NewLiveClient", INTERFACE_FILE, (38, 39), 5, Function);
        let index = EntityIndex::new(vec![build.clone(), export.clone()], root);
        let enriched = uri(ENRICHED_FILE);
        let at = |target: &str, line: u32, start: u32, end: u32| {
            json!({"result": [{"uri": target, "range": {
                "start": {"line": line, "character": start},
                "end": {"line": line, "character": end}}}]})
        };

        let mut skipped = Vec::new();
        let mut unbound = Vec::new();
        for home in [ReceiverHome::CollidingFile, ReceiverHome::ModuleCache] {
            let (package, member) = match home {
                ReceiverHome::CollidingFile => (
                    at(&uri(INTERFACE_FILE), 0, 0, 0),
                    at(&uri(INTERFACE_FILE), 38, 5, 18),
                ),
                ReceiverHome::ModuleCache => (
                    at(MODULE_CACHE_FILE, 0, 0, 0),
                    at(MODULE_CACHE_FILE, 40, 5, 18),
                ),
            };
            let mut responses = json!({});
            responses[format!("{DEFINITION}@{enriched}#{RECEIVER_COLUMN}")] = package.clone();
            responses[format!("{TYPES}@{enriched}#{RECEIVER_COLUMN}")] = package;
            responses[format!("{DEFINITION}@{enriched}#{MEMBER_COLUMN}")] = member.clone();
            responses[format!("{DEFINITION}@{}#5", uri(INTERFACE_FILE))] = member;

            let server = LspServer::scripted_for_tests(PEER, responses.clone());
            let uses = enrichment::enrich_entity_uses_type(
                &server,
                &build,
                &index,
                root,
                Some(&enriched_provider),
            )
            .await
            .expect("the UsesType arm answers");
            // The join asks where the member resolves. A value receiver's
            // turn asks only types, here and at the member's own turn.
            if !asked_at(&seen(&server).await, DEFINITION, MEMBER_COLUMN) {
                skipped.push(format!("the UsesType arm, receiver in the {home:?}"));
            }
            server.shutdown().await.unwrap();

            let server = LspServer::scripted_for_tests(PEER, responses);
            let file = crate::file_enrichment::enrich_file_definitions(
                &server,
                &root.join(ENRICHED_FILE),
                ENRICHED_TEXT,
                &index,
                root,
                Some(&enriched_provider),
            )
            .await
            .expect("the file pass answers");
            // The join asks which module the receiver names. Nothing else in
            // the file pass asks a type.
            if !asked_at(&seen(&server).await, TYPES, RECEIVER_COLUMN) {
                skipped.push(format!("the file pass, receiver in the {home:?}"));
            }
            server.shutdown().await.unwrap();

            match home {
                ReceiverHome::CollidingFile => {
                    if !joined(&uses, RelationKind::UsesType, &build, &export) {
                        unbound.push(format!("the UsesType arm: {uses:?}"));
                    }
                    if !joined(&file.relations, RelationKind::References, &build, &export) {
                        unbound.push(format!("the file pass: {:?}", file.relations));
                    }
                }
                // Nothing outside the checkout is a candidate, so the join
                // binds nothing there, and the receiver's own answer is no
                // edge either.
                ReceiverHome::ModuleCache => {
                    assert!(uses.is_empty(), "{uses:?}");
                    assert!(file.relations.is_empty(), "{:?}", file.relations);
                }
            }
        }
        assert!(
            skipped.is_empty() && unbound.is_empty(),
            "the member join was skipped in {} of 4 passes and bound nothing in {} of 2:\n{}\n{}",
            skipped.len(),
            unbound.len(),
            skipped.join("\n"),
            unbound.join("\n"),
        );
    }
}

/// The file pass hands back a site answer for exactly the identifiers whose
/// definition answer was definite.
///
/// `helper` answers at its own declaration in another file, so it proves that
/// entity. `dumps` answers in the standard library, outside the workspace, so
/// it proves the call leaves the repository. `cb` answers at the caller's own
/// parameter, which names no entity. `nothing` gets no answer, and `mixed`
/// gets two locations that disagree. None of the last three proves anything.
#[tokio::test]
async fn the_file_pass_answers_a_site_only_when_its_definition_is_definite() {
    let root = std::env::temp_dir().join(format!("kin-lsp-site-answers-{}", EntityId::new()));
    // The scripted server answers by column alone, so every answered
    // identifier starts at a column nothing else in the file starts at.
    let text = [
        "def run(cb):",
        "      helper(1)",
        "          dumps(2)",
        "            cb(3)",
        "              nothing(4)",
        "                mixed(5)",
        "",
    ]
    .join("\n");
    let uri = crate::protocol::path_to_uri(&root.join("source.py"));
    let lib = crate::protocol::path_to_uri(&root.join("lib.py"));
    let entity = |name: &str, file: &str, start, end, name_col| EntityRef {
        id: EntityId::new(),
        name: name.into(),
        file_path: file.into(),
        start_line: start,
        start_col: 0,
        end_line: end,
        name_line: start,
        name_col,
        declares_name: true,
        kind: kin_model::EntityKind::Function,
    };
    let run = entity("run", "source.py", 0, 5, 4);
    let helper = entity("helper", "lib.py", 3, 4, 4);
    let index = EntityIndex::new(vec![run.clone(), helper.clone()], &root);
    let at = |uri: &str, line: u32, start: u32, end: u32| {
        json!({"uri": uri, "range": {
            "start": {"line": line, "character": start},
            "end": {"line": line, "character": end}}})
    };
    let outside = "file:///usr/lib/python3.12/json/__init__.py";
    let mut responses = json!({});
    responses[format!("{DEFINITION}@{uri}#6")] = json!({"result": [at(&lib, 3, 4, 10)]});
    responses[format!("{DEFINITION}@{uri}#10")] = json!({"result": [at(outside, 182, 4, 9)]});
    responses[format!("{DEFINITION}@{uri}#12")] = json!({"result": [at(&uri, 0, 8, 10)]});
    responses[format!("{DEFINITION}@{uri}#16")] =
        json!({"result": [at(&lib, 3, 4, 10), at(outside, 7, 0, 5)]});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let answer = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.join("source.py"),
        &text,
        &index,
        &root,
        None,
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();

    let answers: Vec<_> = answer
        .site_answers
        .iter()
        .map(|site| {
            (
                &text[site.site.start_byte..site.site.end_byte],
                site.site.start_line,
                site.source,
                placed(&site.target),
                site.rule,
            )
        })
        .collect();
    assert_eq!(
        answers,
        [
            (
                "helper",
                1,
                run.id,
                Placed::Entity(helper.id),
                crate::call_sites::DEFINITION_RULE
            ),
            (
                "dumps",
                2,
                run.id,
                Placed::Outside,
                crate::call_sites::DEFINITION_RULE
            ),
        ],
        "{answer:?}"
    );
    // The reference edges the pass already minted are unchanged by it.
    let edges: Vec<_> = answer
        .relations
        .iter()
        .map(|relation| (relation.kind, relation.src, relation.dst))
        .collect();
    assert_eq!(
        edges,
        [(
            RelationKind::References,
            GraphNodeId::Entity(run.id),
            GraphNodeId::Entity(helper.id)
        )]
    );
}

/// A temporary workspace root for one test, removed when it is dropped.
struct Workspace(PathBuf);

impl Workspace {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!("kin-lsp-{label}-{}", EntityId::new()));
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    fn uri(&self, file: &str) -> String {
        crate::protocol::path_to_uri(&self.0.join(file))
    }

    fn at(&self, file: &str, line: u32, start: u32, end: u32) -> Value {
        json!({"uri": self.uri(file), "range": {
            "start": {"line": line, "character": start},
            "end": {"line": line, "character": end}}})
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn entity_at(
    name: &str,
    file: &str,
    (start, end): (u32, u32),
    (name_line, name_col): (u32, u32),
    kind: kin_model::EntityKind,
) -> EntityRef {
    EntityRef {
        id: EntityId::new(),
        name: name.into(),
        file_path: file.into(),
        start_line: start,
        start_col: 0,
        end_line: end,
        name_line,
        name_col,
        declares_name: EntityRef::kind_declares_name(kind),
        kind,
    }
}

/// Every site answer as (token text, line, source, target, rule).
fn site_answers_of<'t>(
    text: &'t str,
    pass: &crate::file_enrichment::FileEnrichmentResult,
) -> Vec<(&'t str, u32, EntityId, Placed, &'static str)> {
    pass.site_answers
        .iter()
        .map(|answer| {
            (
                &text[answer.site.start_byte..answer.site.end_byte],
                answer.site.start_line,
                answer.source,
                placed(&answer.target),
                answer.rule,
            )
        })
        .collect()
}

fn asked_at(requests: &[Value], method: &str, line: u32, column: u32) -> usize {
    requests
        .iter()
        .filter(|request| {
            request["method"] == method
                && request["params"]["position"]["line"] == line
                && request["params"]["position"]["character"] == column
        })
        .count()
}

/// A TypeScript overload signature is not an entity: Kin keeps one entity
/// for an overloaded function, spanning its implementation. The server names
/// the signature the call matched, which lies above that span, so the answer
/// used to land in the module and prove nothing. typeorm's `@Column()` is such
/// a function, and its property decorators were never proven. The signature
/// now proves the implementation below it.
#[tokio::test]
async fn an_answer_on_an_overload_signature_proves_the_implementation() {
    use kin_model::EntityKind;
    let root = Workspace::new("overload");
    let text = "function run() {\n    pick(1)\n}\n";
    let lib = [
        "export function pick(a: string): string",
        "export function pick(a: number): number",
        "// the implementation",
        "export function pick(a: any): any {",
        "  return a",
        "}",
    ]
    .join("\n");
    let run = entity_at("run", "source.ts", (0, 2), (0, 9), EntityKind::Function);
    let module = entity_at("lib", "lib.ts", (0, 5), (0, 0), EntityKind::Module);
    let pick = entity_at("pick", "lib.ts", (3, 5), (3, 16), EntityKind::Function);
    let index = EntityIndex::new(vec![run.clone(), module, pick.clone()], &root.0);
    let mut responses = json!({});
    responses[format!("{DEFINITION}@{}#4", root.uri("source.ts"))] =
        json!({"result": [root.at("lib.ts", 1, 16, 20)]});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let provider = |path: &str| (path == "lib.ts").then(|| lib.clone());
    let pass = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.0.join("source.ts"),
        text,
        &index,
        &root.0,
        Some(&provider),
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();
    assert_eq!(
        site_answers_of(text, &pass),
        [(
            "pick",
            1,
            run.id,
            Placed::Entity(pick.id),
            crate::call_sites::DEFINITION_RULE
        )],
        "{pass:?}"
    );
}

/// A call whose answer proves nothing says what the answer came to: a local
/// or a parameter of the caller is a binding, a declaration elsewhere in the
/// repository that the graph holds no entity for is outside the graph, and an
/// empty answer is no answer. A call site the pass asked at is never silent.
#[tokio::test]
async fn an_unproven_call_site_says_what_its_answer_came_to() {
    use crate::call_sites::UnprovenAnswer;
    use kin_model::EntityKind;
    let root = Workspace::new("unproven");
    // The scripted server answers by column alone, so each call sits at a
    // column no other identifier starts at.
    let text = "function run(cb) {\n  cb(1)\n    pick(2)\n      gone(3)\n}\n";
    let lib = "// pick is made here without a declaration Kin reads\nexport default make()\n";
    let run = entity_at("run", "source.ts", (0, 4), (0, 9), EntityKind::Function);
    let module = entity_at("lib", "lib.ts", (0, 1), (0, 0), EntityKind::Module);
    let index = EntityIndex::new(vec![run.clone(), module], &root.0);
    let mut responses = json!({});
    let source = root.uri("source.ts");
    for (column, answer) in [
        (2, json!([root.at("source.ts", 0, 13, 15)])),
        (4, json!([root.at("lib.ts", 1, 15, 19)])),
        (6, json!([])),
    ] {
        responses[format!("{DEFINITION}@{source}#{column}")] = json!({"result": answer});
    }
    let server = LspServer::scripted_for_tests(PEER, responses);
    let provider = |path: &str| (path == "lib.ts").then(|| lib.to_string());
    let pass = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.0.join("source.ts"),
        text,
        &index,
        &root.0,
        Some(&provider),
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();
    let said = |name: &str| {
        pass.unproven_sites
            .iter()
            .find(|site| &text[site.start_byte..site.end_byte] == name && site.source == run.id)
            .map(|site| site.answer)
    };
    assert_eq!(said("cb"), Some(UnprovenAnswer::Binding), "{pass:?}");
    assert_eq!(
        said("pick"),
        Some(UnprovenAnswer::OutsideTheGraph),
        "{pass:?}"
    );
    assert_eq!(said("gone"), Some(UnprovenAnswer::NoAnswer), "{pass:?}");
    assert!(pass.site_answers.is_empty(), "{pass:?}");
    assert!(!pass.stopped_early);
}

/// A signature of some other name, or another declaration between the
/// signature and the entity below it, maps nothing.
#[tokio::test]
async fn an_overload_is_mapped_only_across_signatures_of_its_own_name() {
    use kin_model::EntityKind;
    let root = Workspace::new("overload-refused");
    let text = "function run() {\n    pick(1)\n}\n";
    let lib = [
        "export function pick(a: string): string",
        "export function other(a: number): number",
        "export function pick(a: any): any {",
        "  return a",
        "}",
    ]
    .join("\n");
    let run = entity_at("run", "source.ts", (0, 2), (0, 9), EntityKind::Function);
    let module = entity_at("lib", "lib.ts", (0, 4), (0, 0), EntityKind::Module);
    let pick = entity_at("pick", "lib.ts", (2, 4), (2, 16), EntityKind::Function);
    let index = EntityIndex::new(vec![run.clone(), module, pick.clone()], &root.0);
    let mut responses = json!({});
    responses[format!("{DEFINITION}@{}#4", root.uri("source.ts"))] =
        json!({"result": [root.at("lib.ts", 0, 16, 20)]});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let provider = |path: &str| (path == "lib.ts").then(|| lib.clone());
    let pass = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.0.join("source.ts"),
        text,
        &index,
        &root.0,
        Some(&provider),
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();
    assert!(pass.site_answers.is_empty(), "{pass:?}");
}

/// `const { reject } = make()` binds `reject` locally, and the server answers
/// a call of it at that binding, which names no entity. One more definition
/// asked there lands on the declaration the binding takes its value from.
///
/// When that declaration is a slot a value flows into, an interface member,
/// a property or a field typed as a function, it is not what the call runs:
/// whatever implementation was stored there is. drizzle-orm's
/// `const { prepareTyping } = config; prepareTyping(chunk.encoder)` hopped to
/// `BuildQueryConfig.prepareTyping`, a property of an interface that
/// `PgDialect` and `GelDialect` fill. Proving the slot served a callee no
/// call runs and would retire the guesses that may be the ones that run, so
/// the site stays unresolved and the linker's candidates stand.
#[tokio::test]
async fn an_alias_hop_onto_a_value_slot_proves_nothing() {
    use kin_model::EntityKind;
    let root = Workspace::new("alias-slot");
    // The scripted server answers by column alone, so every answered
    // identifier starts at a column nothing else in the file starts at.
    let text = "function run() {\n  const { reject, typing, field } = make()\n      reject()\n        typing()\n            field()\n}\n";
    let lib = "interface Resolvers {\n  /** Rejects. */\n  reject(reason: string): void;\n}\nclass Config {\n  typing?: (encoder: string) => string;\n  field: Handler = defaultHandler;\n}\n";
    let run = entity_at("run", "source.ts", (0, 5), (0, 9), EntityKind::Function);
    let contract = entity_at(
        "Resolvers",
        "lib.ts",
        (0, 3),
        (0, 10),
        EntityKind::Interface,
    );
    let member = entity_at(
        "Resolvers.reject",
        "lib.ts",
        (2, 2),
        (2, 2),
        EntityKind::Method,
    );
    let config = entity_at("Config", "lib.ts", (4, 7), (4, 6), EntityKind::Class);
    let typing = entity_at(
        "Config.typing",
        "lib.ts",
        (5, 5),
        (5, 2),
        EntityKind::Method,
    );
    let field = entity_at("Config.field", "lib.ts", (6, 6), (6, 2), EntityKind::Field);
    let index = EntityIndex::new(
        vec![
            run.clone(),
            contract,
            member.clone(),
            config,
            typing.clone(),
            field.clone(),
        ],
        &root.0,
    );
    let source = root.uri("source.ts");
    let mut responses = json!({});
    // Each call answers at its binding; each binding answers at a slot.
    responses[format!("{DEFINITION}@{source}#6")] =
        json!({"result": [root.at("source.ts", 1, 10, 16)]});
    responses[format!("{DEFINITION}@{source}#10")] =
        json!({"result": [root.at("lib.ts", 2, 2, 8)]});
    responses[format!("{DEFINITION}@{source}#8")] =
        json!({"result": [root.at("source.ts", 1, 18, 24)]});
    responses[format!("{DEFINITION}@{source}#18")] =
        json!({"result": [root.at("lib.ts", 5, 2, 8)]});
    responses[format!("{DEFINITION}@{source}#12")] =
        json!({"result": [root.at("source.ts", 1, 26, 31)]});
    responses[format!("{DEFINITION}@{source}#26")] =
        json!({"result": [root.at("lib.ts", 6, 2, 7)]});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let texts = |path: &str| match path {
        "source.ts" => Some(text.to_owned()),
        "lib.ts" => Some(lib.to_owned()),
        _ => None,
    };
    let pass = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.0.join("source.ts"),
        text,
        &index,
        &root.0,
        Some(&texts),
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();
    let answers = site_answers_of(text, &pass);
    for (call, line) in [("reject", 2), ("typing", 3), ("field", 4)] {
        assert!(
            !answers
                .iter()
                .any(|answer| (answer.0, answer.1) == (call, line)),
            "{call}: {answers:?}"
        );
    }
    assert_eq!(pass.alias_hops, 0, "{pass:?}");
}

/// A hop that lands on a body that runs keeps its proof: a function-valued
/// const, a function expression, and a method with a body.
#[tokio::test]
async fn an_alias_hop_onto_a_callable_body_is_proven() {
    use kin_model::EntityKind;
    let root = Workspace::new("alias-callable");
    let text = "function run() {\n  const { arrow, expr, body } = make()\n      arrow()\n        expr()\n            body()\n}\n";
    let lib = "export const arrow = async (x: number): Promise<number> => x + 1;\nexport const expr = function (x) { return x; };\nclass Service {\n  body(x: number): number {\n    return x;\n  }\n}\n";
    let run = entity_at("run", "source.ts", (0, 5), (0, 9), EntityKind::Function);
    let arrow = entity_at("arrow", "lib.ts", (0, 0), (0, 13), EntityKind::Constant);
    let expr = entity_at("expr", "lib.ts", (1, 1), (1, 13), EntityKind::Constant);
    let service = entity_at("Service", "lib.ts", (2, 6), (2, 6), EntityKind::Class);
    let body = entity_at("Service.body", "lib.ts", (3, 5), (3, 2), EntityKind::Method);
    let index = EntityIndex::new(
        vec![
            run.clone(),
            arrow.clone(),
            expr.clone(),
            service,
            body.clone(),
        ],
        &root.0,
    );
    let source = root.uri("source.ts");
    let mut responses = json!({});
    responses[format!("{DEFINITION}@{source}#6")] =
        json!({"result": [root.at("source.ts", 1, 10, 15)]});
    responses[format!("{DEFINITION}@{source}#10")] =
        json!({"result": [root.at("lib.ts", 0, 13, 18)]});
    responses[format!("{DEFINITION}@{source}#8")] =
        json!({"result": [root.at("source.ts", 1, 17, 21)]});
    responses[format!("{DEFINITION}@{source}#17")] =
        json!({"result": [root.at("lib.ts", 1, 13, 17)]});
    responses[format!("{DEFINITION}@{source}#12")] =
        json!({"result": [root.at("source.ts", 1, 23, 27)]});
    responses[format!("{DEFINITION}@{source}#23")] =
        json!({"result": [root.at("lib.ts", 3, 2, 6)]});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let texts = |path: &str| match path {
        "source.ts" => Some(text.to_owned()),
        "lib.ts" => Some(lib.to_owned()),
        _ => None,
    };
    let pass = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.0.join("source.ts"),
        text,
        &index,
        &root.0,
        Some(&texts),
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();
    let answers = site_answers_of(text, &pass);
    for (name, line, target) in [
        ("arrow", 2, arrow.id),
        ("expr", 3, expr.id),
        ("body", 4, body.id),
    ] {
        assert!(
            answers.contains(&(
                name,
                line,
                run.id,
                Placed::Entity(target),
                crate::call_sites::DEFINITION_ALIAS_RULE
            )),
            "{name}: {answers:?}"
        );
    }
    assert_eq!(pass.alias_hops, 3, "{pass:?}");
}

/// A binding that answers with itself, like a plain local, proves nothing on
/// the second ask either.
#[tokio::test]
async fn a_local_that_answers_with_itself_is_not_hopped_into_a_proof() {
    use kin_model::EntityKind;
    let root = Workspace::new("alias-self");
    let text = "function run() {\n  const handler = make()\n      handler()\n}\n";
    let run = entity_at("run", "source.ts", (0, 3), (0, 9), EntityKind::Function);
    let index = EntityIndex::new(vec![run.clone()], &root.0);
    let source = root.uri("source.ts");
    let mut responses = json!({});
    responses[format!("{DEFINITION}@{source}#6")] =
        json!({"result": [root.at("source.ts", 1, 8, 15)]});
    responses[format!("{DEFINITION}@{source}#8")] =
        json!({"result": [root.at("source.ts", 1, 8, 15)]});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let pass = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.0.join("source.ts"),
        text,
        &index,
        &root.0,
        None,
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();
    assert!(pass.site_answers.is_empty(), "{pass:?}");
    assert_eq!(pass.alias_hops, 0);
}

/// Call hierarchy answers a call it resolved outside the repository by
/// naming that declaration, and the pass used to drop it at debug level. It
/// now refutes the in-repository guesses at that call's range, under the
/// call-hierarchy rule. A declaration in an installed copy of a module the
/// workspace itself provides is the repository's own code under another
/// path, so it refutes nothing.
#[tokio::test]
async fn call_hierarchy_outside_answers_refute_except_in_an_installed_copy() {
    use kin_model::EntityKind;
    let root = Workspace::new("hierarchy-outside");
    let text = "def run():\n    dumps(x)\n    get(y)\n";
    let run = entity_at("run", "source.py", (0, 2), (0, 4), EntityKind::Function);
    let provided = entity_at("get", "pkg/models.py", (0, 1), (0, 4), EntityKind::Function);
    let index = EntityIndex::new(vec![run.clone(), provided], &root.0);
    let item = |name: &str, uri: &str, line: u32, start: u32| {
        let end = start + name.len() as u32;
        json!({"name": name, "kind": 12, "uri": uri,
            "range": {"start": {"line": line, "character": start}, "end": {"line": line, "character": end}},
            "selectionRange": {"start": {"line": line, "character": start}, "end": {"line": line, "character": end}}})
    };
    let range = |line: u32, start: u32, end: u32| json!({"start": {"line": line, "character": start}, "end": {"line": line, "character": end}});
    let source = root.uri("source.py");
    let mut responses = json!({});
    responses[format!("{PREPARE_CALL}@{source}#4")] =
        json!({"result": [item("run", &source, 0, 4)]});
    responses[CALLS] = json!({"result": [
        {"to": item("dumps", "file:///usr/lib/python3.12/json/__init__.py", 182, 4),
         "fromRanges": [range(1, 4, 9)]},
        {"to": item("get", "file:///venv/lib/python3.12/site-packages/pkg/models.py", 50, 4),
         "fromRanges": [range(2, 4, 7)]},
    ]});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let pass = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.0.join("source.py"),
        text,
        &index,
        &root.0,
        None,
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();
    assert_eq!(
        site_answers_of(text, &pass),
        [(
            "dumps",
            1,
            run.id,
            Placed::Outside,
            crate::call_sites::CALL_HIERARCHY_RULE
        )],
        "{pass:?}"
    );
}

/// A repository that runs its own TypeScript keeps it under its own
/// `node_modules`, inside the workspace root. A definition there, in the
/// standard library's declarations, still leaves the repository and refutes
/// the in-repository guesses at its site. A workspace package pnpm links into
/// `node_modules` is the repository's source: a definition reached through
/// the link proves the declaration it names, and one in the package's own
/// build output refutes nothing.
#[cfg(unix)]
#[tokio::test]
async fn definitions_in_node_modules_refute_and_linked_workspace_sources_prove() {
    use kin_model::EntityKind;
    let root = Workspace::new("node-modules-definitions");
    let real = std::fs::canonicalize(&root.0).unwrap();
    let write = |relative: &str, text: &str| {
        let path = real.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    };
    write(
        "node_modules/.pnpm/typescript@5.6.3/node_modules/typescript/lib/lib.es5.d.ts",
        "interface Array<T> {}\n",
    );
    std::os::unix::fs::symlink(
        ".pnpm/typescript@5.6.3/node_modules/typescript",
        real.join("node_modules/typescript"),
    )
    .unwrap();
    write(
        "packages/pkg/src/lib.ts",
        "// the package\nexport function helper() {}\n",
    );
    write(
        "packages/pkg/dist/lib.d.ts",
        "export declare function built(): void;\n",
    );
    std::os::unix::fs::symlink("../packages/pkg", real.join("node_modules/pkg")).unwrap();

    // The scripted server answers by column alone, so every answered
    // identifier starts at a column nothing else in the file starts at.
    let text = "function run() {\n      find(1)\n        helper(2)\n          built(3)\n}\n";
    let run = entity_at("run", "source.ts", (0, 4), (0, 9), EntityKind::Function);
    let helper = entity_at(
        "helper",
        "packages/pkg/src/lib.ts",
        (1, 1),
        (1, 16),
        EntityKind::Function,
    );
    let index = EntityIndex::new(vec![run.clone(), helper.clone()], &real);
    let uri = crate::protocol::path_to_uri(&real.join("source.ts"));
    let at = |relative: &str, line: u32, start: u32, end: u32| {
        json!({"uri": crate::protocol::path_to_uri(&real.join(relative)), "range": {
            "start": {"line": line, "character": start},
            "end": {"line": line, "character": end}}})
    };
    let mut responses = json!({});
    responses[format!("{DEFINITION}@{uri}#6")] = json!({"result": [at(
        "node_modules/.pnpm/typescript@5.6.3/node_modules/typescript/lib/lib.es5.d.ts",
        1300,
        4,
        8
    )]});
    responses[format!("{DEFINITION}@{uri}#8")] =
        json!({"result": [at("node_modules/pkg/src/lib.ts", 1, 16, 22)]});
    responses[format!("{DEFINITION}@{uri}#10")] =
        json!({"result": [at("node_modules/pkg/dist/lib.d.ts", 0, 24, 29)]});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let pass = crate::file_enrichment::enrich_file_definitions(
        &server,
        &real.join("source.ts"),
        text,
        &index,
        &real,
        None,
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();
    assert_eq!(
        site_answers_of(text, &pass),
        [
            (
                "find",
                1,
                run.id,
                Placed::Outside,
                crate::call_sites::DEFINITION_RULE
            ),
            (
                "helper",
                2,
                run.id,
                Placed::Entity(helper.id),
                crate::call_sites::DEFINITION_RULE
            ),
        ],
        "{pass:?}"
    );
}

/// Call hierarchy that resolves a call into the repository's own
/// `node_modules` refutes the in-repository guesses at its range, as one that
/// resolves it outside the root does.
#[tokio::test]
async fn call_hierarchy_answers_in_node_modules_refute() {
    use kin_model::EntityKind;
    let root = Workspace::new("hierarchy-node-modules");
    let text = "function run() {\n    find(x)\n}\n";
    let run = entity_at("run", "source.ts", (0, 2), (0, 9), EntityKind::Function);
    let index = EntityIndex::new(vec![run.clone()], &root.0);
    let range = |line: u32, start: u32, end: u32| json!({"start": {"line": line, "character": start}, "end": {"line": line, "character": end}});
    let item = |name: &str, uri: &str, line: u32, start: u32| {
        let end = start + name.len() as u32;
        json!({"name": name, "kind": 12, "uri": uri,
            "range": range(line, start, end), "selectionRange": range(line, start, end)})
    };
    let source = root.uri("source.ts");
    let mut responses = json!({});
    responses[format!("{PREPARE_CALL}@{source}#9")] =
        json!({"result": [item("run", &source, 0, 9)]});
    responses[CALLS] = json!({"result": [
        {"to": item("find", &root.uri("node_modules/typescript/lib/lib.es2015.core.d.ts"), 40, 4),
         "fromRanges": [range(1, 4, 8)]},
    ]});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let pass = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.0.join("source.ts"),
        text,
        &index,
        &root.0,
        None,
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();
    assert_eq!(
        site_answers_of(text, &pass),
        [(
            "find",
            1,
            run.id,
            Placed::Outside,
            crate::call_sites::CALL_HIERARCHY_RULE
        )],
        "{pass:?}"
    );
}

/// A request the client stops waiting for is cancelled with the server,
/// after the request it names, and a request that was answered is not. A
/// server left to finish an abandoned request goes on computing: on
/// drizzle-orm one references query Kin had given up on grew tsserver to its
/// heap ceiling, and tsserver died of it.
#[tokio::test]
async fn a_request_the_client_stops_waiting_for_is_cancelled() {
    let server = LspServer::scripted_for_tests(
        PEER,
        json!({REFERENCES: {"hold": true}, DEFINITION: {"result": []}}),
    );
    server.client.request(DEFINITION, json!({})).await.unwrap();
    let abandoned = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        server.client.request(REFERENCES, json!({})),
    )
    .await;
    assert!(abandoned.is_err(), "the peer holds the references request");
    let sent = seen(&server).await;
    server.shutdown().await.unwrap();

    let methods: Vec<&str> = sent
        .iter()
        .filter_map(|message| message["method"].as_str())
        .collect();
    assert_eq!(
        methods,
        [DEFINITION, REFERENCES, "$/cancelRequest"],
        "{sent:?}"
    );
    assert_eq!(sent[2]["params"]["id"], sent[1]["id"], "{sent:?}");
}

/// A document's readiness is the server answering about it: an answer, even
/// an empty one or an error about the document, means it has taken the
/// document in. A server that never answers runs the budget out, and the
/// request is cancelled.
#[tokio::test]
async fn a_document_is_ready_when_the_server_answers_about_it() {
    const SYMBOLS: &str = "textDocument/documentSymbol";
    let budget = std::time::Duration::from_millis(300);
    let server = LspServer::scripted_for_tests(PEER, json!({SYMBOLS: {"result": []}}));
    assert!(server
        .wait_for_document("file:///w/a.ts", budget)
        .await
        .is_ok());
    server.shutdown().await.unwrap();
    let server = LspServer::scripted_for_tests(
        PEER,
        json!({SYMBOLS: {"error": {"code": 1, "message": "No Project."}}}),
    );
    assert!(server
        .wait_for_document("file:///w/a.ts", budget)
        .await
        .is_ok());
    server.shutdown().await.unwrap();
    let server = LspServer::scripted_for_tests(PEER, json!({SYMBOLS: {"hold": true}}));
    assert!(matches!(
        server.wait_for_document("file:///w/a.ts", budget).await,
        Err(LspError::Timeout)
    ));
    let sent = seen(&server).await;
    server.shutdown().await.unwrap();
    assert!(
        sent.iter()
            .any(|message| message["method"] == "$/cancelRequest"),
        "{sent:?}"
    );
}

/// typescript-language-server outlives its tsserver: it logs the exit and
/// then answers every request with an empty result. Kin used to read those
/// as nothing found, and on drizzle-orm every file after tsserver ran out of
/// heap was recorded as asked and answered with nothing. The report now ends
/// the connection, so the pass ends on a server that cannot answer, and the
/// server's departure names the report.
#[tokio::test]
async fn a_server_whose_backend_exited_ends_the_pass() {
    use kin_model::EntityKind;
    let root = Workspace::new("backend-exit");
    let text = "function run() {\n      find(1)\n        helper(2)\n}\n";
    let run = entity_at("run", "source.ts", (0, 3), (0, 9), EntityKind::Function);
    let index = EntityIndex::new(vec![run.clone()], &root.0);
    let uri = root.uri("source.ts");
    let exited = json!({"method": "window/logMessage", "params": {"type": 1,
        "message": "[lspserver] [tsclient] [tsserver] Exited. Code: null. Signal: SIGABRT"}});
    let mut responses = json!({});
    responses[format!("{DEFINITION}@{uri}#6")] = json!({"before": [exited], "result": null});
    let mut server = LspServer::scripted_for_tests_watching(
        PEER,
        responses,
        Default::default(),
        crate::client::ServerWatch {
            backend_exit_report: Some(crate::adapters::typescript::TSSERVER_EXIT_REPORT.into()),
        },
    );
    let pass = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.0.join("source.ts"),
        text,
        &index,
        &root.0,
        None,
    )
    .await;
    assert!(matches!(pass, Err(LspError::ServerDied)), "{pass:?}");
    assert!(server.is_disconnected());
    assert!(matches!(
        server.client.request(DEFINITION, json!({})).await,
        Err(LspError::ServerDied)
    ));
    let departure = server.departure().await;
    assert!(
        departure
            .exit
            .as_deref()
            .is_some_and(|exit| exit.contains("[tsserver] Exited. Code: null. Signal: SIGABRT")),
        "{departure:?}"
    );
    server.abandon().await;
}

/// Only an error-level report carrying the text the launch names counts:
/// the same words logged as information, and another error, leave the
/// server connected.
#[tokio::test]
async fn other_server_messages_do_not_end_the_connection() {
    let messages = json!([
        {"method": "window/logMessage", "params": {"type": 3,
            "message": "[tsclient] [tsserver] Exited. Code: 0. Signal: null"}},
        {"method": "window/logMessage", "params": {"type": 1,
            "message": "[tsclient] TypeScript Server Error (5.6.3) Debug Failure."}},
        {"method": "window/showMessage", "params": {"type": 2,
            "message": "[tsserver] Exited"}},
    ]);
    let server = LspServer::scripted_for_tests_watching(
        PEER,
        json!({DEFINITION: {"before": messages, "result": []}}),
        Default::default(),
        crate::client::ServerWatch {
            backend_exit_report: Some(crate::adapters::typescript::TSSERVER_EXIT_REPORT.into()),
        },
    );
    assert_eq!(
        server.client.request(DEFINITION, json!({})).await.unwrap(),
        json!([])
    );
    assert!(!server.is_disconnected());
    server.shutdown().await.unwrap();
}

/// A class's call hierarchy lists the calls its property decorators make,
/// and those sites lie inside the property's own lines. The call belongs to
/// the entity whose lines hold it, the same entity the parser records it
/// for, so the proof lands on the parser's edge instead of beside it.
#[tokio::test]
async fn a_call_inside_a_nested_member_is_attributed_to_that_member() {
    use kin_model::EntityKind;
    let root = Workspace::new("attribution");
    let text = "export class Post {\n    @PrimaryColumn() id: number\n    title: string\n}\n";
    let post = entity_at("Post", "source.ts", (0, 3), (0, 13), EntityKind::Class);
    let id = entity_at("Post.id", "source.ts", (1, 1), (1, 21), EntityKind::Method);
    let decorator = entity_at(
        "PrimaryColumn",
        "lib.ts",
        (0, 2),
        (0, 16),
        EntityKind::Function,
    );
    let index = EntityIndex::new(vec![post.clone(), id.clone(), decorator.clone()], &root.0);
    let source = root.uri("source.ts");
    let responses = json!({
        PREPARE_CALL: {"result": [{"name": "Post", "kind": 5, "uri": source,
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 3, "character": 1}},
            "selectionRange": {"start": {"line": 0, "character": 13}, "end": {"line": 0, "character": 17}}}]},
        CALLS: {"result": [{"to": {"name": "PrimaryColumn", "kind": 12, "uri": root.uri("lib.ts"),
            "range": {"start": {"line": 0, "character": 16}, "end": {"line": 0, "character": 29}},
            "selectionRange": {"start": {"line": 0, "character": 16}, "end": {"line": 0, "character": 29}}},
            "fromRanges": [{"start": {"line": 1, "character": 5}, "end": {"line": 1, "character": 18}}]}]},
    });
    let server = LspServer::scripted_for_tests(PEER, responses);
    let owned = text.to_owned();
    let calls = enrichment::enrich_entity_calls(
        &server,
        &post,
        &index,
        &root.0,
        Some(&move |path| (path == "source.ts").then(|| owned.clone())),
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();
    let edges: Vec<_> = calls
        .relations
        .iter()
        .map(|relation| (relation.src, relation.dst))
        .collect();
    assert_eq!(
        edges,
        [(
            GraphNodeId::Entity(id.id),
            GraphNodeId::Entity(decorator.id)
        )],
        "{calls:?}"
    );
}

/// A pass that has to stop early keeps what it proved, so it asks at the
/// identifiers that open a call before the others. Three slow answers used
/// to stop the pass before it ever reached the call below them.
#[tokio::test]
async fn call_sites_are_asked_before_the_other_identifiers() {
    let run = declared_at("run", "source.py", 0, 2, 4);
    let helper = declared_at("helper", "lib.py", 3, 4, 4);
    let (answer, requests) = pass_with_held_requests(
        "def run():\n  alpha beta gamma\n      helper()\n",
        vec![run.clone(), helper.clone()],
        &[(DEFINITION, 6, located("lib.py", 3, 4, 10))],
        &[],
        &[(DEFINITION, 2), (DEFINITION, 8), (DEFINITION, 13)],
    )
    .await;
    let answer = answer.unwrap();
    assert_eq!(asked_at(&requests, DEFINITION, 2, 6), 1, "{requests:?}");
    assert_eq!(
        answer
            .site_answers
            .iter()
            .map(|site| (site.site.start_line, placed(&site.target)))
            .collect::<Vec<_>>(),
        [(2, Placed::Entity(helper.id))],
        "{answer:?}"
    );
}

/// Keywords, comments and the insides of docstrings name no declaration, so
/// the pass does not ask about them; the call among them is still asked.
#[tokio::test]
async fn keywords_comments_and_docstrings_are_not_asked() {
    let run = declared_at("run", "source.py", 0, 5, 4);
    let text = "def run():\n    \"\"\"\n    helper words\n    \"\"\"\n    # helper again\n    return helper()\n";
    let (answer, requests) = pass_with_held_requests(text, vec![run.clone()], &[], &[], &[]).await;
    let answer = answer.unwrap();
    assert_eq!(
        asked_at(&requests, DEFINITION, 5, 11),
        1,
        "the call is asked"
    );
    assert_eq!(asked_at(&requests, DEFINITION, 0, 4), 1, "a name is asked");
    for (line, column, what) in [
        (0, 0, "`def`"),
        (2, 4, "a docstring word"),
        (2, 11, "a docstring word"),
        (4, 6, "a comment word"),
        (4, 13, "a comment word"),
        (5, 4, "`return`"),
    ] {
        assert_eq!(
            asked_at(&requests, DEFINITION, line, column),
            0,
            "{what} at {line}:{column} is not asked"
        );
    }
    assert_eq!(answer.definition_queries, 2, "{answer:?}");
    assert_eq!(answer.definition_queries_saved, 6, "{answer:?}");
}

/// A value receiver's definition is asked once. The pass asked it as a
/// receiver, to tell a module from a value, and then asked the very same
/// position again as an identifier.
#[tokio::test]
async fn a_value_receiver_is_asked_once() {
    let run = declared_at("run", "source.py", 0, 1, 4);
    let root = held_root();
    let at_self = json!({"result": [{
        "uri": crate::protocol::path_to_uri(&root.join("source.py")),
        "range": {"start": {"line": 0, "character": 8}, "end": {"line": 0, "character": 12}},
    }]});
    let (answer, requests) = pass_with_held_requests(
        "def run(self):\n    self.helper()\n",
        vec![run.clone()],
        &[(DEFINITION, 4, at_self)],
        &[],
        &[],
    )
    .await;
    let answer = answer.unwrap();
    assert_eq!(asked_at(&requests, DEFINITION, 1, 4), 1, "{requests:?}");
    assert_eq!(answer.definition_queries_saved, 2, "`def` and the reuse");
}

/// Asking call sites first does not move a reference edge's recorded site:
/// the edge still carries the earliest position that proved it, as it did
/// when the pass asked in source order.
#[tokio::test]
async fn a_reference_keeps_its_earliest_site_whatever_the_order_asked() {
    let run = declared_at("run", "source.py", 0, 2, 4);
    let helper = declared_at("helper", "lib.py", 3, 4, 4);
    let (answer, _) = pass_with_held_requests(
        "def run():\n    x = helper\n      helper()\n",
        vec![run.clone(), helper.clone()],
        &[
            (DEFINITION, 8, located("lib.py", 3, 4, 10)),
            (DEFINITION, 6, located("lib.py", 3, 4, 10)),
        ],
        &[],
        &[],
    )
    .await;
    let answer = answer.unwrap();
    let references: Vec<_> = answer
        .relations
        .iter()
        .filter(|relation| relation.kind == RelationKind::References)
        .map(|relation| {
            let site = relation.evidence[0].source_span.as_ref().unwrap();
            (relation.dst, site.start_line, site.start_col)
        })
        .collect();
    assert_eq!(
        references,
        [(GraphNodeId::Entity(helper.id), 1, 8)],
        "{answer:?}"
    );
}

/// TypeScript answers a call with the declaration of the signature it
/// resolved, and through a receiver typed as a union of classes that is one
/// constituent's method, whichever the checker created first. Such a call
/// proves no single declaration: not through a union-typed name, whose type
/// definition names both classes, and not through a cast to a union. A
/// receiver of one class still proves its call.
#[tokio::test]
async fn a_typescript_call_through_a_union_receiver_proves_nothing() {
    use kin_model::EntityKind;
    let root = Workspace::new("union-receiver");
    let text =
        "function run() {\n    d.wrap(1)\n       y = (d as A | B).wrap(2)\n        e.wrap(3)\n}\n";
    let run = entity_at("run", "source.ts", (0, 4), (0, 9), EntityKind::Function);
    let a = entity_at("A", "lib.ts", (0, 2), (0, 6), EntityKind::Class);
    let a_wrap = entity_at("A.wrap", "lib.ts", (1, 1), (1, 2), EntityKind::Method);
    let b = entity_at("B", "lib.ts", (3, 5), (3, 6), EntityKind::Class);
    let b_wrap = entity_at("B.wrap", "lib.ts", (4, 4), (4, 2), EntityKind::Method);
    let index = EntityIndex::new(vec![run.clone(), a, a_wrap.clone(), b, b_wrap], &root.0);
    let source = root.uri("source.ts");
    let mut responses = json!({});
    for column in [6, 24, 10] {
        responses[format!("{DEFINITION}@{source}#{column}")] =
            json!({"result": [root.at("lib.ts", 1, 2, 6)]});
    }
    responses[format!("{TYPES}@{source}#4")] =
        json!({"result": [root.at("lib.ts", 0, 6, 7), root.at("lib.ts", 3, 6, 7)]});
    responses[format!("{TYPES}@{source}#8")] = json!({"result": [root.at("lib.ts", 0, 6, 7)]});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let pass = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.0.join("source.ts"),
        text,
        &index,
        &root.0,
        None,
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();
    assert_eq!(
        site_answers_of(text, &pass),
        [(
            "wrap",
            3,
            run.id,
            Placed::Entity(a_wrap.id),
            crate::call_sites::DEFINITION_RULE
        )],
        "{pass:?}"
    );
}

/// Call hierarchy names an overloaded TypeScript function by the signature
/// the call matched, which lies above the one entity Kin keeps for it, and
/// names a function a macro generates at the top of a module by that module's
/// line. The first is a call of the implementation. The second names no
/// entity, and a call of a module surface is no call: nothing is minted.
#[tokio::test]
async fn call_hierarchy_targets_on_a_signature_or_a_module_line_are_placed_or_refused() {
    use kin_model::EntityKind;
    let root = Workspace::new("hierarchy-targets");
    let text = "function run() {\n    pick(1)\n    get(2)\n}\n";
    let lib = [
        "// overloads",
        "export function pick(a: string): string",
        "export function pick(a: number): number",
        "export function pick(a: any): any {",
        "  return a",
        "}",
    ]
    .join("\n");
    let run = entity_at("run", "source.ts", (0, 3), (0, 9), EntityKind::Function);
    let lib_module = entity_at("lib", "lib.ts", (0, 5), (0, 0), EntityKind::Module);
    let pick = entity_at("pick", "lib.ts", (3, 5), (3, 16), EntityKind::Function);
    let routing = entity_at("routing", "routing.ts", (0, 9), (0, 0), EntityKind::Module);
    let index = EntityIndex::new(
        vec![run.clone(), lib_module, pick.clone(), routing],
        &root.0,
    );
    let item = |name: &str, file: &str, line: u32, start: u32| {
        let end = start + name.len() as u32;
        json!({"name": name, "kind": 12, "uri": root.uri(file),
            "range": {"start": {"line": line, "character": start}, "end": {"line": line, "character": end}},
            "selectionRange": {"start": {"line": line, "character": start}, "end": {"line": line, "character": end}}})
    };
    let range = |line: u32, start: u32, end: u32| json!({"start": {"line": line, "character": start}, "end": {"line": line, "character": end}});
    let responses = json!({
        PREPARE_CALL: {"result": [item("run", "source.ts", 0, 9)]},
        CALLS: {"result": [
            {"to": item("pick", "lib.ts", 1, 16), "fromRanges": [range(1, 4, 8)]},
            {"to": item("get", "routing.ts", 4, 20), "fromRanges": [range(2, 4, 7)]},
        ]},
    });
    let server = LspServer::scripted_for_tests(PEER, responses);
    let own = text.to_owned();
    let provider = move |path: &str| match path {
        "source.ts" => Some(own.clone()),
        "lib.ts" => Some(lib.clone()),
        _ => None,
    };
    let calls = enrichment::enrich_entity_calls(&server, &run, &index, &root.0, Some(&provider))
        .await
        .unwrap();
    server.shutdown().await.unwrap();
    let edges: Vec<_> = calls
        .relations
        .iter()
        .map(|relation| (relation.src, relation.dst))
        .collect();
    assert_eq!(
        edges,
        [(GraphNodeId::Entity(run.id), GraphNodeId::Entity(pick.id))],
        "{calls:?}"
    );
    assert!(calls.outside_sites.is_empty(), "{calls:?}");
}

/// Where a site answer landed, as these tests compare it: the entity it names,
/// or outside the workspace wherever there.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Placed {
    Entity(EntityId),
    Outside,
}

fn placed(target: &crate::call_sites::SiteTarget) -> Placed {
    match target {
        crate::call_sites::SiteTarget::Entity(entity) => Placed::Entity(*entity),
        crate::call_sites::SiteTarget::Outside(_) => Placed::Outside,
    }
}

/// An answer outside the workspace is named as an external symbol from the
/// server's own symbols for the file it landed in and the package that holds
/// that file, and a place the symbols do not name stays unnamed.
#[tokio::test]
async fn the_file_pass_names_an_outside_answer_by_its_package_and_symbols() {
    let base = Workspace::new("external-names");
    let root = base.0.join("repo");
    std::fs::create_dir_all(&root).unwrap();
    let typescript = base.0.join("deps/node_modules/typescript");
    std::fs::create_dir_all(typescript.join("lib")).unwrap();
    std::fs::write(
        typescript.join("package.json"),
        r#"{"name":"typescript","version":"5.6.3"}"#,
    )
    .unwrap();
    let lib_path = typescript.join("lib/lib.es5.d.ts");
    std::fs::write(
        &lib_path,
        "interface Array<T> {\n    map(): void;\n    pop(): T;\n}\n",
    )
    .unwrap();
    let lib = crate::protocol::path_to_uri(&lib_path);

    let text = "function run(items) {\n  items.map(f)\n    xs.pop()\n}\n";
    let uri = crate::protocol::path_to_uri(&root.join("source.ts"));
    let run = entity_at(
        "run",
        "source.ts",
        (0, 3),
        (0, 9),
        kin_model::EntityKind::Function,
    );
    let index = EntityIndex::new(vec![run.clone()], &root);
    let at = |line: u32, start: u32, end: u32| {
        json!({"uri": lib, "range": {
            "start": {"line": line, "character": start},
            "end": {"line": line, "character": end}}})
    };
    let mut responses = json!({});
    // `map` lands on the name the symbols give; `pop` on a place they do not.
    responses[format!("{DEFINITION}@{uri}#8")] = json!({"result": [at(1, 4, 7)]});
    responses[format!("{DEFINITION}@{uri}#7")] = json!({"result": [at(2, 4, 7)]});
    responses[format!("textDocument/documentSymbol@{lib}#")] = json!({"result": [{
        "name": "Array",
        "kind": 11,
        "range": {"start": {"line": 0, "character": 0}, "end": {"line": 3, "character": 1}},
        "selectionRange": {"start": {"line": 0, "character": 10}, "end": {"line": 0, "character": 15}},
        "children": [{
            "name": "map",
            "kind": 6,
            "range": {"start": {"line": 1, "character": 4}, "end": {"line": 1, "character": 16}},
            "selectionRange": {"start": {"line": 1, "character": 4}, "end": {"line": 1, "character": 7}}
        }]
    }]});
    let server = LspServer::scripted_for_tests(PEER, responses);
    let pass = crate::file_enrichment::enrich_file_definitions(
        &server,
        &root.join("source.ts"),
        text,
        &index,
        &root,
        None,
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();

    let outside: Vec<_> = pass
        .site_answers
        .iter()
        .filter_map(|answer| match &answer.target {
            crate::call_sites::SiteTarget::Outside(location) => Some(location.clone()),
            crate::call_sites::SiteTarget::Entity(_) => None,
        })
        .collect();
    assert_eq!(
        outside
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2,
        "both calls leave the repository: {pass:?}"
    );
    let named: Vec<_> = pass
        .external_names
        .values()
        .map(|symbol| (symbol.package.encode(), symbol.encode_descriptors()))
        .collect();
    assert_eq!(
        named,
        [(
            "npm typescript 5.6.3".to_string(),
            "`lib.es5.d.ts`/Array#map().".to_string()
        )],
        "{pass:?}"
    );
    assert!(
        pass.external_names
            .keys()
            .all(|location| !location.uri.is_empty() && location.uri.starts_with("file://")),
        "the place is only a key for naming"
    );
}
