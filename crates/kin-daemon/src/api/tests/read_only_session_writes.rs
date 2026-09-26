// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

/// Start a session through the served route, optionally under a
/// caller-allocated id and optionally declaring capabilities. `None` for the
/// capabilities omits the field, which is what a client that declares nothing
/// sends.
async fn start_session(
    state: &Arc<DaemonState>,
    session_id: Option<&str>,
    capabilities: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut request = serde_json::json!({
        "vendor": "codex",
        "client_name": "session-capability-test",
        "transport": "mcp",
        "cwd": state.layout.working_dir(),
    });
    if let Some(session_id) = session_id {
        request["session_id"] = serde_json::json!(session_id);
    }
    if let Some(capabilities) = capabilities {
        request["capabilities"] = capabilities;
    }
    let started = router(Arc::clone(state))
        .oneshot(
            Request::post("/session")
                .header("content-type", "application/json")
                .body(Body::from(request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::OK);
    let body = axum::body::to_bytes(started.into_body(), 64 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn end_session(state: &Arc<DaemonState>, session_id: &str) {
    let ended = router(Arc::clone(state))
        .oneshot(
            Request::delete(format!("/session/{session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ended.status(), StatusCode::OK);
}

/// End `session_id` and start it again declaring `capabilities`, the way a
/// client re-registers a session to resume retained work after a restart.
async fn restart_session_declaring(
    state: &Arc<DaemonState>,
    session_id: &str,
    capabilities: serde_json::Value,
) -> serde_json::Value {
    end_session(state, session_id).await;
    start_session(state, Some(session_id), Some(capabilities)).await
}

fn declared_capabilities(can_write: bool, can_commit: bool) -> serde_json::Value {
    serde_json::json!({
        "can_read": true,
        "can_write": can_write,
        "can_execute": false,
        "can_branch": false,
        "can_commit": can_commit,
        "max_concurrent_intents": 1
    })
}

/// Post `body` to `route`, naming `session` in `X-Kin-Session` when given, the
/// way the CLI does when `KIN_SESSION_ID` is set.
async fn post_as_session(
    state: &Arc<DaemonState>,
    route: &str,
    session: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, String) {
    let mut request = Request::post(route).header("content-type", "application/json");
    if let Some(session) = session {
        request = request.header("X-Kin-Session", session);
    }
    let response = router(Arc::clone(state))
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn commit_request(message: &str) -> serde_json::Value {
    serde_json::json!({
        "operation_id": kin_model::OperationId::new(),
        "timestamp": Timestamp::now(),
        "author": "Test Author <test@example.invalid>",
        "message": message,
    })
}

fn assert_read_only_refusal(result: &kin_mcp::ToolCallResult, door: &str) {
    let text = mcp_result_text(result);
    assert_eq!(
        result.is_error,
        Some(true),
        "{door} must refuse a read-only session: {text}"
    );
    assert!(text.starts_with("read_only_session: "), "{text}");
    assert!(text.contains(&format!("{door} writes")), "{text}");
    assert!(text.contains("can_write=false"), "{text}");
    assert!(text.contains("kin_session_start"), "{text}");
}

fn assert_cli_read_only_refusal(
    route: &str,
    door: &str,
    owner: &str,
    status: StatusCode,
    body: &str,
) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{route}: {body}");
    let refusal: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(refusal["error"], "read_only_session", "{route}: {refusal}");
    assert_eq!(refusal["session_id"], owner, "{route}: {refusal}");
    let message = refusal["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(&format!("{door} writes")),
        "{route}: {message}"
    );
    // Said for a shell: the remedy is the variable that named the session,
    // not an MCP tool the shell cannot call.
    assert!(
        message.contains("unset KIN_SESSION_ID"),
        "{route}: {message}"
    );
    // Not `kin with`: it starts an assistant in its own workspace from this
    // shell's environment, so with the variable still set its closeout
    // reconcile meets this same refusal.
    assert!(!message.contains("`kin with`"), "{route}: {message}");
    assert!(!message.contains("kin_session_start"), "{route}: {message}");
}

/// A session that declared itself read-only is refused at every door it could
/// write through, on a default install where coordination is not enforced.
/// Before, the declaration was reported back and checked nowhere, so the same
/// session could begin, stage and commit.
#[tokio::test]
#[serial_test::serial]
async fn a_read_only_session_is_refused_at_every_write_door() {
    let (dir, state, source) = source_base_fixture().await;
    assert!(
        !state.coordination_mode().is_enforcing(),
        "the default install is the case that let a read-only session write"
    );
    // Work the session staged while it could write, retained across its
    // restart, which is the one way a read-only session holds a transaction.
    let tx = source_base_stage(&state, source_base_operation(&source)).await;
    let owner = retained_transaction_value(&state, &tx)["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let owner_id = SessionId(Uuid::parse_str(&owner).unwrap());
    let started =
        restart_session_declaring(&state, &owner, declared_capabilities(false, false)).await;
    assert_eq!(started["capabilities"]["can_write"], false);
    assert_eq!(started["capability_policy"]["can_write"], "client_declared");

    let roots = source_base_roots(&state);
    let retained = retained_transaction_value(&state, &tx);
    let created = source_base_operation(&source);

    let begin = mcp_call_as(
        router(Arc::clone(&state)),
        "kin_transaction_begin",
        serde_json::json!({ "session_id": owner, "scope": "repository" }),
        owner_id,
    )
    .await;
    assert_read_only_refusal(&begin, "kin_transaction_begin");

    let stage = mcp_call_as(
        router(Arc::clone(&state)),
        "kin_transaction_stage",
        serde_json::json!({ "transaction_id": tx, "operations": [created.clone()] }),
        owner_id,
    )
    .await;
    assert_read_only_refusal(&stage, "kin_transaction_stage");

    for arguments in [
        serde_json::json!({ "transaction_id": tx }),
        serde_json::json!({ "transaction_id": tx, "operations": [source_base_operation(&source)] }),
    ] {
        let commit = mcp_call_as(
            router(Arc::clone(&state)),
            "kin_transaction_commit",
            arguments,
            owner_id,
        )
        .await;
        assert_read_only_refusal(&commit, "kin_transaction_commit");
        assert!(mcp_result_text(&commit).contains("can_commit=false"));
    }

    // kin_mutate, as the daemon dispatches an unkeyed call and as it runs a
    // keyed one under its durable request protocol.
    let mutate = mcp_call_as(
        router(Arc::clone(&state)),
        "kin_mutate",
        serde_json::json!({ "session_id": owner, "operations": [created.clone()] }),
        owner_id,
    )
    .await;
    assert_read_only_refusal(&mutate, "kin_mutate");
    let keyed = mutate_http(
        &state,
        "kin_mutate",
        serde_json::json!({"session_id":owner,"request_id":"read-only-request",
            "operations":[created],"summary":"refused entity edit"}),
        &owner,
    )
    .await;
    assert_read_only_refusal(&keyed, "kin_mutate");

    // `kin commit`, which names the session it runs in with X-Kin-Session. A
    // new file sits in the working copy, so a commit that got past the check
    // would admit and publish it.
    std::fs::write(
        dir.path().join("unexpected.py"),
        "def surprise():\n    return 1\n",
    )
    .unwrap();
    let (status, body) = post_as_session(
        &state,
        "/commands/commit",
        Some(&owner),
        commit_request("a commit from a read-only session"),
    )
    .await;
    assert_cli_read_only_refusal("/commands/commit", "kin commit", &owner, status, &body);
    // The same refusal for a session named only in the request body.
    let mut named_in_body = commit_request("a commit naming a read-only session");
    named_in_body["session_id"] = serde_json::json!(owner);
    let (status, body) = post_as_session(&state, "/commands/commit", None, named_in_body).await;
    assert_cli_read_only_refusal("/commands/commit", "kin commit", &owner, status, &body);

    // The other CLI writes that accept a session: `kin reconcile`, which
    // publishes a session workspace into the primary one, and `kin push` and
    // `kin pull`, which move refs on a remote and on this replica.
    let transfer = serde_json::json!({ "remote_base_url": "http://127.0.0.1:9" });
    for (route, door, body) in [
        (
            "/reconcile",
            "kin reconcile",
            serde_json::json!({ "session_dir": dir.path().join(".kin/runs/session-x") }),
        ),
        ("/commands/push", "kin push", transfer.clone()),
        ("/commands/pull", "kin pull", transfer),
    ] {
        let (status, response) = post_as_session(&state, route, Some(&owner), body).await;
        assert_cli_read_only_refusal(route, door, &owner, status, &response);
    }

    // Nothing any door carried moved authority, the retained transaction, or
    // the working copy's tracked source.
    assert_eq!(source_base_roots(&state), roots);
    assert_eq!(retained_transaction_value(&state, &tx), retained);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("src/value.rs")).unwrap(),
        SOURCE_BASE_ORIGINAL
    );
    assert!(
        !state
            .graph
            .resolved_tree()
            .artifacts_by_path()
            .any(|artifact| artifact.path.to_string() == "unexpected.py"),
        "the refused commit must not admit the working copy"
    );

    // The control: the same session started able to write passes the door it
    // was refused at, and the retained work publishes.
    let started =
        restart_session_declaring(&state, &owner, declared_capabilities(true, true)).await;
    assert_eq!(started["capabilities"]["can_write"], true);
    let commit = mcp_call_as(
        router(Arc::clone(&state)),
        "kin_transaction_commit",
        serde_json::json!({ "transaction_id": tx }),
        owner_id,
    )
    .await;
    assert_ne!(commit.is_error, Some(true), "{}", mcp_result_text(&commit));
    assert_eq!(source_base_roots(&state).generation, roots.generation + 1);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("src/value.rs")).unwrap(),
        SOURCE_BASE_ORIGINAL.replacen("{ 1 }", "{ 2 }", 1)
    );
}

/// The other side of the door: only a session that declared itself read-only
/// is refused. On a default install a session that declared nothing, and a
/// shell that names no session at all, still commit, reconcile, mutate and
/// reach the transfer routes. A `KIN_SESSION_ID` left in a shell that names a
/// session the daemon no longer holds, or that does not parse, holds its own
/// `kin commit` to nothing.
#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn a_default_install_and_a_stale_shell_session_still_write() {
    let repo = tempfile::tempdir().unwrap();
    let state = Arc::new(DaemonState::open(kin_core::init(repo.path()).unwrap().layout).unwrap());
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let singleton = session_runtime_lock(&state);
    let _runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    let app = router(Arc::clone(&state));

    // What a default install and an old shell leave behind.
    let undeclared = start_session(&state, None, None).await;
    assert_eq!(
        undeclared["capabilities"]["can_write"], true,
        "{undeclared}"
    );
    assert_eq!(
        undeclared["capabilities"]["can_commit"], true,
        "{undeclared}"
    );
    let undeclared = undeclared["session_id"].as_str().unwrap().to_string();
    let undeclared_id = SessionId(Uuid::parse_str(&undeclared).unwrap());
    let ended = start_session(&state, None, None).await["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    end_session(&state, &ended).await;
    let unknown = Uuid::new_v4().to_string();

    // `kin commit` with no session, with ids naming no live session, and with
    // the session that declared nothing.
    for (index, (label, session)) in [
        ("no session", None),
        ("an unknown session", Some(unknown.as_str())),
        ("an ended session", Some(ended.as_str())),
        ("an id that does not parse", Some("not-a-session")),
        ("a session that declared nothing", Some(undeclared.as_str())),
    ]
    .into_iter()
    .enumerate()
    {
        std::fs::write(
            repo.path().join(format!("commit_{index}.rs")),
            format!("pub fn commit_{index}() -> u32 {{ {index} }}\n"),
        )
        .unwrap();
        let (status, body) = post_as_session(
            &state,
            "/commands/commit",
            session,
            commit_request(&format!("commit with {label}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{label}: {body}");
    }

    // `kin reconcile` publishing a session workspace, the same three ways.
    for (index, (label, session)) in [
        ("no session", None),
        ("an unknown session", Some(unknown.as_str())),
        ("a session that declared nothing", Some(undeclared.as_str())),
    ]
    .into_iter()
    .enumerate()
    {
        let session_dir = state
            .layout
            .root()
            .join(format!("runs/session-default-install-{index}"));
        materialize_session_through_api(&app, &session_dir).await;
        std::fs::write(
            session_dir.join("commit_0.rs"),
            format!("pub fn commit_0() -> u32 {{ {} }}\n", 100 + index),
        )
        .unwrap();
        let (status, body) = post_as_session(
            &state,
            "/reconcile",
            session,
            serde_json::json!({ "session_dir": session_dir, "confirm_mass_deletion": false }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{label}: {body}");
    }

    // The session that declared nothing begins, stages and commits through
    // MCP, and publishes through a keyed kin_mutate.
    let begin = mcp_call_as(
        router(Arc::clone(&state)),
        "kin_transaction_begin",
        serde_json::json!({ "session_id": undeclared, "scope": "repository" }),
        undeclared_id,
    )
    .await;
    assert_ne!(begin.is_error, Some(true), "{}", mcp_result_text(&begin));
    let tx = tool_result_payload(&begin)["transaction_id"]
        .as_str()
        .unwrap()
        .to_string();
    // Each entity write carries the base of the version it replaces, read
    // fresh because every commit above and below moves the workspace.
    let current = source_base_read_named(&state, "commit_0").await;
    let write = source_base_replacement(
        &current,
        "pub fn commit_0() -> u32 { 200 }",
        "an entity write",
    );
    let stage = mcp_call_as(
        router(Arc::clone(&state)),
        "kin_transaction_stage",
        serde_json::json!({ "transaction_id": tx, "operations": [write] }),
        undeclared_id,
    )
    .await;
    assert_ne!(stage.is_error, Some(true), "{}", mcp_result_text(&stage));
    let commit = mcp_call_as(
        router(Arc::clone(&state)),
        "kin_transaction_commit",
        serde_json::json!({ "transaction_id": tx }),
        undeclared_id,
    )
    .await;
    assert_ne!(commit.is_error, Some(true), "{}", mcp_result_text(&commit));
    let current = source_base_read_named(&state, "commit_0").await;
    let write = source_base_replacement(
        &current,
        "pub fn commit_0() -> u32 { 300 }",
        "entity update with default capabilities",
    );
    let keyed = mutate_http(
        &state,
        "kin_mutate",
        serde_json::json!({"session_id":undeclared,"request_id":"default-install-request",
            "summary":"keyed entity update", "operations":[write]}),
        &undeclared,
    )
    .await;
    assert_ne!(keyed.is_error, Some(true), "{}", mcp_result_text(&keyed));
    assert_eq!(tool_result_payload(&commit)["modified_files"], serde_json::json!(["commit_0.rs"]));
    assert_eq!(tool_result_payload(&keyed)["modified_files"], serde_json::json!(["commit_0.rs"]));
    assert!(std::fs::read_to_string(repo.path().join("commit_0.rs")).unwrap().contains("{ 300 }"));

    // Push and pull pass the session check and reach the transfer itself,
    // which fails here only because nothing answers at the remote.
    for route in ["/commands/push", "/commands/pull"] {
        for session in [None, Some(unknown.as_str()), Some(undeclared.as_str())] {
            let (status, body) = post_as_session(
                &state,
                route,
                session,
                serde_json::json!({ "remote_base_url": "http://127.0.0.1:9" }),
            )
            .await;
            assert_ne!(status, StatusCode::FORBIDDEN, "{route} {session:?}: {body}");
            assert!(
                !body.contains("read_only_session"),
                "{route} {session:?}: {body}"
            );
        }
    }
}
