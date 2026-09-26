// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Controlled JSON-RPC peer, not an installed language server or semantic oracle.
// It exercises the production generator against captured admitted CAS text.
const LSP_SOURCE_SPANS_PEER: &str = r#"
import json,sys
responses=json.loads(sys.argv[1])
while True:
    headers={}
    while True:
        line=sys.stdin.buffer.readline()
        if not line: sys.exit(0)
        if line in (b'\n',b'\r\n'): break
        key,value=line.decode().split(':',1);headers[key.lower()]=value.strip()
    msg=json.loads(sys.stdin.buffer.read(int(headers['content-length'])))
    if 'id' not in msg: continue
    result=responses.get(msg['method'])
    data=json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':result}).encode()
    sys.stdout.buffer.write(f'Content-Length: {len(data)}\r\n\r\n'.encode()+data);sys.stdout.buffer.flush()
"#;

#[tokio::test]
async fn fresh_lsp_source_spans_preserve_prior_call_through_removal_and_cold_start() {
    use crate::daemon::lsp_publication::QueryInputs;
    const CALLER: &str = "def run(callback):\r\n    marker = \"😀\"; return callback()\r\n";
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("caller.py"), CALLER).unwrap();
    std::fs::write(repo.path().join("target.py"), "def work():\n    return 7\n").unwrap();
    waiting_admit(&state, "fresh LSP sources").await;
    waiting_commit(&state, "fresh LSP source baseline").await;
    let caller = waiting_entity(&state, "caller.py", "run");
    let target = waiting_entity(&state, "target.py", "work");
    let make_ref = |entity: &kin_model::Entity, name_col| {
        let span = entity.span.as_ref().unwrap();
        kin_lsp::EntityRef {
            id: entity.id,
            name: entity.name.clone(),
            file_path: entity.file_origin.as_ref().unwrap().0.clone(),
            start_line: span.start_line,
            start_col: span.start_col,
            end_line: span.end_line,
            name_line: span.start_line,
            name_col,
            declares_name: true,
            kind: kin_model::EntityKind::Function,
        }
    };
    let caller_ref = make_ref(&caller, 4);
    let target_ref = make_ref(&target, 4);
    let index =
        kin_lsp::EntityIndex::new(vec![caller_ref.clone(), target_ref.clone()], repo.path());
    let inputs = QueryInputs::capture(&state).await.unwrap();
    let text = inputs.document("caller.py").unwrap();
    assert_eq!(text, CALLER);
    let source_digest = kin_model::Hash256::from_bytes(kin_blobs::digest(CALLER.as_bytes()).0);
    let source_artifact = state
        .graph
        .resolved_tree()
        .artifact_at_path(&kin_model::RepoPath::from_utf8("caller.py").unwrap())
        .unwrap()
        .artifact_id;
    let item = |entity: &kin_lsp::EntityRef| {
        json!({
            "name":entity.name,"kind":12,
            "uri":kin_lsp::protocol::path_to_uri(&repo.path().join(&entity.file_path)),
            "range":{"start":{"line":entity.start_line,"character":0},"end":{"line":entity.end_line,"character":0}},
            "selectionRange":{"start":{"line":entity.name_line,"character":entity.name_col},"end":{"line":entity.name_line,"character":entity.name_col+entity.name.len() as u32}},
        })
    };
    let line = CALLER.lines().nth(1).unwrap();
    let column = line.find("callback").unwrap();
    let utf16 = line[..column].encode_utf16().count();
    let responses = json!({
        "initialize":{"capabilities":{"callHierarchyProvider":true,"positionEncoding":"utf-16"}},
        "textDocument/prepareCallHierarchy":[item(&caller_ref)],
        "callHierarchy/outgoingCalls":[{"to":item(&target_ref),"fromRanges":[{
            "start":{"line":1,"character":utf16},"end":{"line":1,"character":utf16+8}
        }]}]
    })
    .to_string();
    let server = kin_lsp::lifecycle::LspServer::start(
        "python3",
        &["-u", "-c", LSP_SOURCE_SPANS_PEER, &responses],
        repo.path(),
        None,
        None,
    )
    .await
    .unwrap();
    server
        .client
        .notify(
            "textDocument/didOpen",
            json!({"textDocument":{
                "uri":kin_lsp::protocol::path_to_uri(&repo.path().join("caller.py")),
                "languageId":"python","version":1,"text":text,
            }}),
        )
        .await
        .unwrap();
    let generated = kin_lsp::enrichment::enrich_entity_calls(
        &server,
        &caller_ref,
        &index,
        repo.path(),
        Some(&|path| inputs.document(path)),
    )
    .await
    .unwrap()
    .relations;
    server.shutdown().await.unwrap();
    assert_eq!(generated.len(), 1);
    let prior = generated[0].clone();
    let span = prior.evidence[0].source_span.as_ref().unwrap();
    assert_eq!(&CALLER[span.start_byte..span.end_byte], "callback");
    assert_eq!(span.start_byte, CALLER.rfind("callback").unwrap());
    assert_eq!(span.start_col, column as u32);
    assert_eq!(prior.origin, kin_model::RelationOrigin::Lsp);
    let mut pending = crate::daemon::PendingEnrichment::default();
    inputs
        .absorb(&state, &mut pending, generated)
        .await
        .unwrap();
    inputs.flush(&state, &mut pending).await.unwrap();
    assert_eq!(
        state.graph.semantic_observation().relations.get(&prior.id),
        Some(&prior)
    );
    state.save_snapshot().unwrap();
    assert_eq!(
        lsp_publication_durable(&state).relations.get(&prior.id),
        Some(&prior)
    );
    // This answer was already accepted and durable before ordinary removal;
    // the previous late-answer race is not the causal mechanism here.
    std::fs::remove_file(repo.path().join("target.py")).unwrap();
    waiting_admit(
        &state,
        "ordinary target deletion after fresh LSP publication",
    )
    .await;
    waiting_commit(&state, "retain exact fresh LSP prior binding").await;
    let check = |snapshot: &kin_db::GraphSnapshot| {
        assert!(!snapshot.entities.contains_key(&target.id));
        assert!(!snapshot.relations.contains_key(&prior.id));
        let relation = snapshot
            .relations
            .get(&kin_index::binding_debt::local_binding_debt_id(
                source_artifact,
            ))
            .unwrap();
        let debt = kin_index::binding_debt::decode_local_binding_debt(
            &kin_model::FilePathId::new("caller.py"),
            source_artifact,
            relation,
        )
        .unwrap()
        .unwrap();
        assert_eq!(debt.obligations.len(), 1);
        assert_eq!(debt.observed_source_digest, source_digest);
        assert_eq!(debt.obligations[0].source_digest, source_digest);
        assert_eq!(debt.obligations[0].retired_relation, prior);
        assert_eq!(debt.obligations[0].target_file.0, "target.py");
        debt
    };
    let warm = check(&state.graph.semantic_observation());
    let durable = check(&lsp_publication_durable(&state));
    assert_eq!(warm, durable);
    binding_disclosure_impact(&state, caller.id, true, "fresh LSP span warm removal").await;
    let layout = state.layout.clone();
    drop(inputs);
    drop(state);
    let cold = waiting_cold_start(layout).await;
    let reopened = check(&cold.graph.semantic_observation());
    assert_eq!(warm, reopened);
    binding_disclosure_impact(
        &cold,
        caller.id,
        true,
        "fresh LSP span canonical cold startup",
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(repo.path().join("caller.py")).unwrap(),
        CALLER
    );
    println!(
        "fresh LSP source span lifecycle: {}",
        json!({
            "fixture":"controlled protocol through production enrichment",
            "prior_relation":prior,"source_digest":source_digest,"warm_debt":warm,
            "durable_debt":durable,"cold_debt":reopened,
            "legacy_migration":false,"settlement_proved":false,
        })
    );
}
