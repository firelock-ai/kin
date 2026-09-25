// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
// Included inside mcp_commit::tests to reuse exact publication fixtures.

fn lifecycle_base(
    state: &Arc<DaemonState>,
    entity: &Entity,
) -> kin_mcp::source_base::EntitySourceBase {
    let context = authority_context(state).unwrap();
    let authority = crate::api::held_repository_authority(state).unwrap();
    let lease = authority.read_authority();
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == context.workspace_id())
        .unwrap();
    let source_context =
        kin_mcp::source_base::SourceBaseContext::from_workspace(workspace).unwrap();
    let tree = state.graph.resolved_tree();
    let artifact = tree
        .artifact_at_path(&test_path(&entity.file_origin.as_ref().unwrap().0))
        .unwrap();
    let TreeEntry::Blob { hash, .. } = artifact.entry else {
        panic!("regular source")
    };
    let bytes = crate::repository_commit::load_native_source_blob(&context, hash).unwrap();
    let span = entity.span.as_ref().unwrap();
    kin_mcp::source_base::EntitySourceBase::from_exact_body(
        source_context,
        entity,
        artifact.artifact_id,
        hash,
        std::str::from_utf8(&bytes[span.start_byte..span.end_byte]).unwrap(),
    )
    .unwrap()
}

fn lifecycle_create(
    state: &Arc<DaemonState>,
    anchor: &Entity,
    placement: kin_mcp::entity_lifecycle::EntityPlacement,
    body: &str,
) -> kin_mcp::McpMutationOperation {
    kin_mcp::McpMutationOperation {
        verb: "create".into(),
        target: anchor.id.to_string(),
        body: None,
        destination: None,
        description: "create a bounded function".into(),
        payload: Some(kin_mcp::McpMutationPayload::EntityCreate(
            kin_mcp::entity_lifecycle::EntityCreate {
                source_base: Some(lifecycle_base(state, anchor)),
                placement: Some(placement),
                repository_base: None,
                unit: None,
                name: "added".into(),
                kind: kin_mcp::source_unit::DeclarationKind::Function,
                body: body.into(),
                imports: Vec::new(),
            },
        )),
    }
}

fn lifecycle_stage(
    sessions: &kin_mcp::SessionRegistry,
    operations: Vec<kin_mcp::McpMutationOperation>,
) -> HashMap<String, serde_json::Value> {
    kin_mcp::session::validate_semantic_operations(&operations).unwrap();
    let transaction = sessions
        .begin_transaction(TEST_SESSION, "entity lifecycle")
        .unwrap();
    sessions
        .stage_transaction(&transaction.transaction_id, operations)
        .unwrap();
    HashMap::from([(
        "transaction_id".into(),
        serde_json::json!(transaction.transaction_id),
    )])
}

#[test]
fn entity_lifecycle_create_edit_remove_preserves_siblings_and_reopens() {
    use kin_mcp::entity_lifecycle::EntityPlacement::{NewSourceUnit, SiblingAfter};
    for (file, original, creation, edited, placement, expected_file) in [
        (
            "src/lib.rs",
            "pub fn anchor() -> u8 { 1 }\n\npub fn sibling() -> u8 { 2 }\n",
            "pub fn added() -> u8 { 3 }",
            "pub fn added() -> u8 { 4 }",
            SiblingAfter,
            "src/lib.rs",
        ),
        (
            "pkg/source.py",
            "def anchor():\n    return 1\n\ndef sibling():\n    return 2\n",
            "def added():\n    return 3",
            "def added():\n    return 4",
            SiblingAfter,
            "pkg/source.py",
        ),
        (
            "pkg/source.py",
            "def anchor():\n    return 1\n\ndef sibling():\n    return 2\n",
            "def added():\n    return 3",
            "def added():\n    return 4",
            NewSourceUnit,
            "pkg/added.py",
        ),
        (
            "pkg/source.go",
            "package sample\n\nfunc anchor() int { return 1 }\n\nfunc sibling() int { return 2 }\n",
            "func added() int { return 3 }",
            "func added() int { return 4 }",
            SiblingAfter,
            "pkg/source.go",
        ),
        (
            "pkg/source.go",
            "package sample\n\nfunc anchor() int { return 1 }\n\nfunc sibling() int { return 2 }\n",
            "func added() int { return 3 }",
            "func added() int { return 4 }",
            NewSourceUnit,
            "pkg/added.go",
        ),
    ] {
        let (_dir, state) = test_state();
        let (anchor, _) = install_exact_source(&state, file, original.as_bytes(), "anchor");
        let sessions = test_sessions();
        let arguments = lifecycle_stage(
            &sessions,
            vec![lifecycle_create(&state, &anchor, placement, creation)],
        );
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "{file} {placement:?}: {}",
            result_text(&result)
        );
        let added = state
            .graph
            .query_entities(&EntityFilter {
                name_pattern: Some("added".into()),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .find(|entity| entity.name == "added" && entity.kind == kin_model::EntityKind::Function)
            .unwrap();
        assert_eq!(added.file_origin.as_ref().unwrap().0, expected_file);
        let disk = std::fs::read_to_string(state.layout.working_dir().join(expected_file)).unwrap();
        assert!(disk.contains(creation));
        if placement == NewSourceUnit {
            assert_eq!(
                std::fs::read_to_string(state.layout.working_dir().join(file)).unwrap(),
                original
            );
        }
        let edit = kin_mcp::McpMutationOperation {
            verb: "update".into(),
            target: added.id.to_string(),
            payload: Some(kin_mcp::McpMutationPayload::EntitySourceBase(
                lifecycle_base(&state, &added),
            )),
            body: Some(edited.into()),
            destination: None,
            description: "edit created entity".into(),
        };
        let args = lifecycle_stage(&sessions, vec![edit]);
        let result = commit_exact_transaction(&state, &sessions, &args, None);
        assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
        let layout = state.layout.clone();
        drop(state);
        let reopened = Arc::new(DaemonState::open(layout).unwrap());
        let fresh = reopened.graph.get_entity(&added.id).unwrap().unwrap();
        assert!(
            std::fs::read_to_string(reopened.layout.working_dir().join(expected_file))
                .unwrap()
                .contains(edited)
        );
        let remove = kin_mcp::McpMutationOperation {
            verb: "remove".into(),
            target: fresh.id.to_string(),
            payload: Some(kin_mcp::McpMutationPayload::EntityRemove(
                kin_mcp::entity_lifecycle::EntityRemove {
                    source_base: lifecycle_base(&reopened, &fresh),
                },
            )),
            body: None,
            destination: None,
            description: "remove just created entity".into(),
        };
        let args = lifecycle_stage(&sessions, vec![remove]);
        let result = commit_exact_transaction(&reopened, &sessions, &args, None);
        assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
        assert!(reopened.graph.get_entity(&fresh.id).unwrap().is_none());
        assert!(reopened.graph.get_entity(&anchor.id).unwrap().is_some());
        assert!(
            reopened
                .graph
                .resolved_tree()
                .artifact_at_path(&test_path(expected_file))
                .is_some(),
            "removal preserves the source unit"
        );
        let projected =
            std::fs::read_to_string(reopened.layout.working_dir().join(expected_file)).unwrap();
        assert!(!projected.contains("added"));
    }
}

#[test]
fn entity_lifecycle_refuses_extra_declarations_stale_base_and_unsupported_placement() {
    use kin_mcp::entity_lifecycle::EntityPlacement::{NewSourceUnit, SiblingAfter};
    for (placement, body, stale) in [
        (SiblingAfter, "fn added() {}\nfn hidden() {}", false),
        (SiblingAfter, "use std::fmt;\nfn added() {}", false),
        (SiblingAfter, "fn added() { fn nested() {} }", false),
        (NewSourceUnit, "fn added() {}", false),
        (SiblingAfter, "fn added() {}", true),
    ] {
        let (_dir, state) = test_state();
        let source = b"fn anchor() {}\nfn sibling() {}\n";
        let (anchor, _) = install_exact_source(&state, "src/lib.rs", source, "anchor");
        let sessions = test_sessions();
        let mut op = lifecycle_create(&state, &anchor, placement, body);
        if stale {
            let Some(kin_mcp::McpMutationPayload::EntityCreate(create)) = op.payload.as_mut()
            else {
                unreachable!()
            };
            create
                .source_base
                .as_mut()
                .unwrap()
                .context
                .workspace_generation += 1;
        }
        let before = load_native_commit_base(&state.layout).unwrap();
        let arguments = lifecycle_stage(&sessions, vec![op]);
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(result.is_error, Some(true), "{}", result_text(&result));
        assert_eq!(
            load_native_commit_base(&state.layout).unwrap().roots,
            before.roots
        );
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            source
        );
        assert!(!state.layout.working_dir().join("src/added.rs").exists());
    }
}

#[test]
fn entity_lifecycle_new_unit_receipt_recovers_after_publication_crash() {
    let (_dir, state) = test_state();
    let (anchor, _) = install_exact_source(
        &state,
        "pkg/source.py",
        b"def anchor():\n    return 1\n",
        "anchor",
    );
    let sessions = test_sessions();
    let op = lifecycle_create(
        &state,
        &anchor,
        kin_mcp::entity_lifecycle::EntityPlacement::NewSourceUnit,
        "def added():\n    return 2",
    );
    let arguments = lifecycle_stage(&sessions, vec![op]);
    state
        .mcp_fail_after_authority_once
        .store(true, Ordering::SeqCst);
    let result = commit_exact_transaction(&state, &sessions, &arguments, None);
    assert_eq!(result.is_error, Some(true), "{}", result_text(&result));
    let roots = load_native_commit_base(&state.layout).unwrap().roots;
    let layout = state.layout.clone();
    drop(state);
    let state = Arc::new(DaemonState::open(layout).unwrap());
    let retained = crate::api::mcp_session_registry_snapshot(&state).unwrap();
    let result = commit_exact_transaction(&state, &retained, &arguments, None);
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    assert_eq!(load_native_commit_base(&state.layout).unwrap().roots, roots);
    assert!(
        std::fs::read_to_string(state.layout.working_dir().join("pkg/added.py"))
            .unwrap()
            .contains("def added():")
    );
    let body: serde_json::Value = serde_json::from_str(result_text(&result)).unwrap();
    assert_eq!(body["already_applied"], true);
    assert_eq!(
        authored_files_from_staged(
            state.graph.as_ref(),
            &retained
                .get_transaction(arguments["transaction_id"].as_str().unwrap())
                .unwrap()
                .staged_operations
        ),
        Some(BTreeSet::from([test_path("pkg/added.py")]))
    );
}

#[test]
fn entity_lifecycle_occupied_new_unit_and_mixed_owner_edits_refuse_atomically() {
    use kin_mcp::entity_lifecycle::EntityPlacement::{NewSourceUnit, SiblingAfter};
    for occupied in [true, false] {
        let (_dir, state) = test_state();
        let original = b"def anchor():\n    return 1\n";
        let (anchor, _) = install_exact_source(&state, "pkg/source.py", original, "anchor");
        if occupied {
            install_exact_source(
                &state,
                "pkg/added.py",
                b"def occupied():\n    return 7\n",
                "occupied",
            );
        }
        let sessions = test_sessions();
        let mut operations = vec![lifecycle_create(
            &state,
            &anchor,
            if occupied {
                NewSourceUnit
            } else {
                SiblingAfter
            },
            "def added():\n    return 2",
        )];
        if !occupied {
            operations.push(kin_mcp::McpMutationOperation {
                verb: "update".into(),
                target: anchor.id.to_string(),
                payload: Some(kin_mcp::McpMutationPayload::EntitySourceBase(
                    lifecycle_base(&state, &anchor),
                )),
                body: Some("def anchor():\n    return 9".into()),
                destination: None,
                description: "conflicting owner edit".into(),
            });
        }
        let before = load_native_commit_base(&state.layout).unwrap().roots;
        let arguments = lifecycle_stage(&sessions, operations);
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(result.is_error, Some(true), "{}", result_text(&result));
        assert_eq!(
            load_native_commit_base(&state.layout).unwrap().roots,
            before
        );
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("pkg/source.py")).unwrap(),
            original
        );
        if occupied {
            assert_eq!(
                std::fs::read(state.layout.working_dir().join("pkg/added.py")).unwrap(),
                b"def occupied():\n    return 7\n"
            );
        }
    }
}

#[test]
fn entity_lifecycle_abort_survives_restart_without_creating_an_artifact() {
    let (_dir, state) = test_state();
    let (anchor, _) = install_exact_source(
        &state,
        "source.py",
        b"def anchor():\n    return 1\n",
        "anchor",
    );
    let sessions = test_sessions();
    let arguments = lifecycle_stage(
        &sessions,
        vec![lifecycle_create(
            &state,
            &anchor,
            kin_mcp::entity_lifecycle::EntityPlacement::NewSourceUnit,
            "def added():\n    return 2",
        )],
    );
    let transaction_id = arguments["transaction_id"].as_str().unwrap();
    let before = load_native_commit_base(&state.layout).unwrap().roots;
    sessions.abort_transaction(transaction_id).unwrap();
    persist_registry_checked(&state, &sessions).unwrap();
    let layout = state.layout.clone();
    drop(state);
    let state = Arc::new(DaemonState::open(layout).unwrap());
    let retained = crate::api::mcp_session_registry_snapshot(&state).unwrap();
    assert_eq!(
        retained.get_transaction(transaction_id).unwrap().state,
        "aborted"
    );
    assert_eq!(
        load_native_commit_base(&state.layout).unwrap().roots,
        before
    );
    let result = commit_exact_transaction(&state, &retained, &arguments, None);
    assert_eq!(result.is_error, Some(true), "{}", result_text(&result));
    assert!(!state.layout.working_dir().join("added.py").exists());
    assert!(state
        .graph
        .resolved_tree()
        .artifact_at_path(&test_path("added.py"))
        .is_none());
}

#[test]
fn entity_lifecycle_remove_retains_call_obligation_and_recovers_receipt() {
    let (_dir, state) = test_state();
    let (anchor, _) = install_exact_source(
        &state,
        "pkg/provider.go",
        b"package sample\n\nfunc anchor() int { return 1 }\n",
        "anchor",
    );
    install_exact_source(
        &state,
        "pkg/caller.go",
        b"package sample\n\nfunc caller() int { return anchor() }\n",
        "caller",
    );
    // This fixture helper imports each file independently. Seed the real
    // linker and reobserve the caller before claiming a cross-file binding.
    let mut reconciler = kin_reconcile::Reconciler::new(PathBuf::new());
    reconciler.seed_cross_file_linker_from_graph(state.graph.as_ref());
    let caller_file = FilePathId::new("pkg/caller.go");
    let caller_bytes = b"package sample\n\nfunc caller() int { return anchor() }\n";
    let digest = state.blobs.write(caller_bytes).unwrap();
    let kin_index::IndexedAny::EntitySource(indexed) = kin_index::IndexPipeline::new()
        .index_any_content(&caller_file, caller_bytes, digest)
        .unwrap()
    else {
        panic!("Go caller source")
    };
    let reconciled = reconciler
        .reconcile_indexed_content(&indexed, state.blobs.as_ref(), state.graph.as_ref())
        .unwrap();
    state
        .graph
        .apply_transaction_delta(&reconciled.delta)
        .unwrap();
    commit_live_graph(&state, "bind exact Go caller", true);
    let caller = state
        .graph
        .query_entities(&EntityFilter {
            name_pattern: Some("caller".into()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == "caller")
        .unwrap();
    let before_relations = state
        .graph
        .get_all_relations_for_entity(&anchor.id)
        .unwrap();
    assert!(
        before_relations
            .iter()
            .any(|relation| relation.kind == kin_model::RelationKind::Calls
                && relation.src == kin_model::GraphNodeId::Entity(caller.id)),
        "fixture must have a real caller binding"
    );
    let sessions = test_sessions();
    let remove = kin_mcp::McpMutationOperation {
        verb: "remove".into(),
        target: anchor.id.to_string(),
        payload: Some(kin_mcp::McpMutationPayload::EntityRemove(
            kin_mcp::entity_lifecycle::EntityRemove {
                source_base: lifecycle_base(&state, &anchor),
            },
        )),
        body: None,
        destination: None,
        description: "remove one referenced function".into(),
    };
    let arguments = lifecycle_stage(&sessions, vec![remove]);
    state
        .mcp_fail_after_authority_once
        .store(true, Ordering::SeqCst);
    let result = commit_exact_transaction(&state, &sessions, &arguments, None);
    assert_eq!(result.is_error, Some(true), "{}", result_text(&result));
    assert!(
        result_text(&result).contains("injected crash"),
        "{}",
        result_text(&result)
    );
    let roots = load_native_commit_base(&state.layout).unwrap().roots;
    let layout = state.layout.clone();
    drop(state);
    let state = Arc::new(DaemonState::open(layout).unwrap());
    let retained = crate::api::mcp_session_registry_snapshot(&state).unwrap();
    let result = commit_exact_transaction(&state, &retained, &arguments, None);
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    assert_eq!(load_native_commit_base(&state.layout).unwrap().roots, roots);
    assert!(state.graph.get_entity(&anchor.id).unwrap().is_none());
    assert!(state.graph.get_entity(&caller.id).unwrap().is_some());
    let snapshot = state.graph.to_snapshot();
    assert!(!snapshot
        .relations
        .values()
        .any(|relation| relation.dst == kin_model::GraphNodeId::Entity(anchor.id)));
    assert!(
        snapshot
            .relations
            .values()
            .any(kin_index::binding_debt::claims_local_binding_debt),
        "removed local binding must retain its unresolved obligation"
    );
    assert_eq!(
        authored_files_from_staged(
            state.graph.as_ref(),
            &retained
                .get_transaction(arguments["transaction_id"].as_str().unwrap())
                .unwrap()
                .staged_operations
        ),
        Some(BTreeSet::from([test_path("pkg/provider.go")]))
    );
    assert_eq!(
        std::fs::read_to_string(state.layout.working_dir().join("pkg/provider.go")).unwrap(),
        "package sample\n\n\n"
    );
}

#[test]
fn entity_lifecycle_go_package_collision_refuses_across_source_units() {
    let (_dir, state) = test_state();
    let (anchor, _) = install_exact_source(
        &state,
        "pkg/source.go",
        b"package sample\nfunc anchor() int { return 1 }\n",
        "anchor",
    );
    install_exact_source(
        &state,
        "pkg/other.go",
        b"package sample\nfunc added() int { return 9 }\n",
        "added",
    );
    let sessions = test_sessions();
    let before = load_native_commit_base(&state.layout).unwrap().roots;
    let arguments = lifecycle_stage(
        &sessions,
        vec![lifecycle_create(
            &state,
            &anchor,
            kin_mcp::entity_lifecycle::EntityPlacement::NewSourceUnit,
            "func added() int { return 2 }",
        )],
    );
    let result = commit_exact_transaction(&state, &sessions, &arguments, None);
    assert_eq!(result.is_error, Some(true), "{}", result_text(&result));
    assert!(
        result_text(&result).contains("already occupies"),
        "{}",
        result_text(&result)
    );
    assert_eq!(
        load_native_commit_base(&state.layout).unwrap().roots,
        before
    );
    assert!(!state.layout.working_dir().join("pkg/added.go").exists());
}

#[test]
fn entity_lifecycle_new_go_unit_refuses_unmodeled_build_owners() {
    for (file, source) in [
        (
            "pkg/source_test.go",
            "package sample\nfunc anchor() int { return 1 }\n",
        ),
        (
            "pkg/source_linux.go",
            "package sample\nfunc anchor() int { return 1 }\n",
        ),
        (
            "pkg/source.go",
            "//go:build linux\n\npackage sample\nfunc anchor() int { return 1 }\n",
        ),
        (
            "pkg/source.go",
            "// +build linux\n\npackage sample\nfunc anchor() int { return 1 }\n",
        ),
    ] {
        let (_dir, state) = test_state();
        let (anchor, _) = install_exact_source(&state, file, source.as_bytes(), "anchor");
        let sessions = test_sessions();
        let before = load_native_commit_base(&state.layout).unwrap().roots;
        let arguments = lifecycle_stage(
            &sessions,
            vec![lifecycle_create(
                &state,
                &anchor,
                kin_mcp::entity_lifecycle::EntityPlacement::NewSourceUnit,
                "func added() int { return 2 }",
            )],
        );
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(result.is_error, Some(true), "{}", result_text(&result));
        assert!(
            result_text(&result).contains("build-owner"),
            "{}",
            result_text(&result)
        );
        assert_eq!(
            load_native_commit_base(&state.layout).unwrap().roots,
            before
        );
        assert!(!state.layout.working_dir().join("pkg/added.go").exists());
    }
}

fn go_unit(package: &str, name: &str, test: bool) -> kin_mcp::source_unit::SourceUnit {
    kin_mcp::source_unit::SourceUnit::Go {
        package: package.into(),
        name: name.into(),
        role: if test {
            kin_mcp::source_unit::UnitRole::Test
        } else {
            kin_mcp::source_unit::UnitRole::Source
        },
    }
}

fn current_base(state: &Arc<DaemonState>) -> kin_mcp::source_unit::RepositoryBase {
    crate::unit_lifecycle::current_repository_base(state)
        .expect("a local workspace always has a repository base")
}

fn unit_create_op(
    base: &kin_mcp::source_unit::RepositoryBase,
    unit: kin_mcp::source_unit::SourceUnit,
    name: &str,
    kind: kin_mcp::source_unit::DeclarationKind,
    body: &str,
    imports: &[&str],
) -> kin_mcp::McpMutationOperation {
    kin_mcp::McpMutationOperation {
        verb: "create".into(),
        target: name.into(),
        payload: Some(kin_mcp::McpMutationPayload::EntityCreate(
            kin_mcp::entity_lifecycle::EntityCreate {
                source_base: None,
                placement: None,
                repository_base: Some(base.clone()),
                unit: Some(unit),
                name: name.into(),
                kind,
                body: body.into(),
                imports: imports
                    .iter()
                    .map(|path| kin_mcp::source_unit::ImportSpec::Path((*path).into()))
                    .collect(),
            },
        )),
        body: None,
        destination: None,
        description: format!("create {name}"),
    }
}

fn unit_imports_op(
    base: &kin_mcp::source_unit::RepositoryBase,
    unit: kin_mcp::source_unit::SourceUnit,
    add: &[&str],
    remove: &[&str],
) -> kin_mcp::McpMutationOperation {
    let spec = |path: &&str| kin_mcp::source_unit::ImportSpec::Path((*path).into());
    kin_mcp::McpMutationOperation {
        verb: "update".into(),
        target: unit.package_name().into(),
        payload: Some(kin_mcp::McpMutationPayload::UnitImports(
            kin_mcp::source_unit::UnitImports {
                repository_base: base.clone(),
                unit,
                add: add.iter().map(spec).collect(),
                remove: remove.iter().map(spec).collect(),
            },
        )),
        body: None,
        destination: None,
        description: "manage imports".into(),
    }
}

/// Commit through the daemon writer, aborting a refused transaction the way the
/// one-shot mutate does, so a test that meets many refusals never reaches the
/// session's transaction ceiling.
fn commit_unit_ops(
    state: &Arc<DaemonState>,
    sessions: &kin_mcp::SessionRegistry,
    operations: Vec<kin_mcp::McpMutationOperation>,
) -> kin_mcp::ToolCallResult {
    let arguments = lifecycle_stage(sessions, operations);
    let result = commit_exact_transaction(state, sessions, &arguments, None);
    if result.is_error == Some(true) {
        let transaction_id = arguments["transaction_id"].as_str().unwrap();
        let _ = sessions.abort_transaction(transaction_id);
    }
    result
}

fn project(state: &Arc<DaemonState>, path: &str) -> String {
    std::fs::read_to_string(state.layout.working_dir().join(path)).unwrap_or_default()
}

fn go_entity(state: &Arc<DaemonState>, name: &str) -> Entity {
    state
        .graph
        .query_entities(&EntityFilter {
            name_pattern: Some(name.into()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == name && !kin_model::is_file_module_surface(entity))
        .unwrap_or_else(|| panic!("{name} must be in the graph"))
}

const STORE_GO: &str = "package store

import (
\t\"errors\"
\t\"sync\"
)

const (
\tDefaultCapacity = 16
\tMaxKeyLength    = 64
)

var ErrNotFound = errors.New(\"not found\")

// Store keeps values by key.
type Store struct {
\tmu    sync.Mutex
\titems map[string]string
}

func (s *Store) Set(key, value string) {
\ts.mu.Lock()
\tdefer s.mu.Unlock()
\ts.items[key] = value
}

func (s *Store) Get(key string) (string, error) {
\ts.mu.Lock()
\tdefer s.mu.Unlock()
\tvalue, ok := s.items[key]
\tif !ok {
\t\treturn \"\", ErrNotFound
\t}
\treturn value, nil
}

type Getter interface {
\tGet(key string) (string, error)
}

func NewStore() *Store {
\treturn &Store{items: make(map[string]string, DefaultCapacity)}
}
";

fn store_package_ops(
    base: &kin_mcp::source_unit::RepositoryBase,
) -> Vec<kin_mcp::McpMutationOperation> {
    use kin_mcp::source_unit::DeclarationKind as Kind;
    let store = || go_unit("internal/store", "store", false);
    vec![
        unit_create_op(base, store(), "DefaultCapacity", Kind::Const, "const (\n\tDefaultCapacity = 16\n\tMaxKeyLength    = 64\n)", &[]),
        unit_create_op(base, store(), "ErrNotFound", Kind::Var, "var ErrNotFound = errors.New(\"not found\")", &["errors"]),
        unit_create_op(base, store(), "Store", Kind::Struct, "// Store keeps values by key.\ntype Store struct {\n\tmu    sync.Mutex\n\titems map[string]string\n}", &["sync"]),
        unit_create_op(base, store(), "Getter", Kind::Interface, "type Getter interface {\n\tGet(key string) (string, error)\n}", &[]),
        unit_create_op(base, store(), "NewStore", Kind::Function, "func NewStore() *Store {\n\treturn &Store{items: make(map[string]string, DefaultCapacity)}\n}", &[]),
        unit_create_op(base, store(), "Store.Set", Kind::Method, "func (s *Store) Set(key, value string) {\n\ts.mu.Lock()\n\tdefer s.mu.Unlock()\n\ts.items[key] = value\n}", &[]),
        unit_create_op(base, store(), "Store.Get", Kind::Method, "func (s *Store) Get(key string) (string, error) {\n\ts.mu.Lock()\n\tdefer s.mu.Unlock()\n\tvalue, ok := s.items[key]\n\tif !ok {\n\t\treturn \"\", ErrNotFound\n\t}\n\treturn value, nil\n}", &[]),
    ]
}

/// The greenfield path: from `kin init` on an empty directory, the first unit
/// and every Go declaration kind a small program needs are created by name and
/// kind, never by path, and each publication hands over the next base.
#[test]
fn unit_create_builds_a_multi_package_go_program_from_an_empty_repository() {
    use kin_mcp::source_unit::DeclarationKind as Kind;
    let (_dir, state) = test_state();
    assert_eq!(state.graph.resolved_tree().artifacts().count(), 0);
    let sessions = test_sessions();

    let result = commit_unit_ops(&state, &sessions, store_package_ops(&current_base(&state)));
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    let reply: serde_json::Value = serde_json::from_str(result_text(&result)).unwrap();
    assert_eq!(project(&state, "internal/store/store.go"), STORE_GO);
    let created = reply["created_entities"].as_array().unwrap();
    for (name, kind) in [
        ("DefaultCapacity", "constant"),
        ("MaxKeyLength", "constant"),
        ("ErrNotFound", "static_var"),
        ("Store", "class"),
        ("Getter", "interface"),
        ("NewStore", "function"),
        ("Store.Set", "method"),
        ("Store.Get", "method"),
    ] {
        assert!(
            created
                .iter()
                .any(|entity| entity["name"] == name && entity["kind"] == kind),
            "{name} {kind}: {reply}"
        );
        assert_eq!(
            go_entity(&state, name).file_origin.unwrap().0,
            "internal/store/store.go"
        );
    }
    let next: kin_mcp::source_unit::RepositoryBase =
        serde_json::from_value(reply["repository_base"].clone()).unwrap();
    assert_eq!(
        next,
        current_base(&state),
        "the reply hands over the next base"
    );

    let main_body = "func main() {\n\ts := store.NewStore()\n\ts.Set(\"greeting\", \"hello\")\n\tvalue, err := s.Get(\"greeting\")\n\tif err != nil {\n\t\tpanic(err)\n\t}\n\tfmt.Println(value)\n}";
    let test_unit = || go_unit("internal/store", "store", true);
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![
            unit_create_op(&next, go_unit(".", "main", false), "main", Kind::Function, main_body, &["fmt", "example.com/app/internal/store"]),
            unit_create_op(&next, test_unit(), "TestSetGet", Kind::Function, "func TestSetGet(t *testing.T) {\n\ts := NewStore()\n\ts.Set(\"a\", \"b\")\n\tif got, err := s.Get(\"a\"); err != nil || got != \"b\" {\n\t\tt.Fatalf(\"got %q %v\", got, err)\n\t}\n}", &["testing"]),
            unit_create_op(&next, test_unit(), "TestMissing", Kind::Function, "func TestMissing(t *testing.T) {\n\tif _, err := NewStore().Get(\"x\"); err != ErrNotFound {\n\t\tt.Fatalf(\"got %v\", err)\n\t}\n}", &[]),
        ],
    );
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    assert_eq!(
        project(&state, "main.go"),
        format!("package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/app/internal/store\"\n)\n\n{main_body}\n")
    );
    let tests = project(&state, "internal/store/store_test.go");
    assert!(
        tests.starts_with("package store\n\nimport (\n\t\"testing\"\n)\n\nfunc TestSetGet("),
        "{tests}"
    );
    assert!(tests.contains("\n\nfunc TestMissing("), "{tests}");
    assert_eq!(
        go_entity(&state, "TestMissing").file_origin.unwrap().0,
        "internal/store/store_test.go"
    );

    // Appending to a unit that already holds declarations keeps each one's
    // identity and exact bytes and places a method with its type's methods.
    let held = [
        "Store",
        "Store.Get",
        "Store.mu",
        "DefaultCapacity",
        "NewStore",
    ]
    .map(|name| (name, go_entity(&state, name).id));
    let len = "func (s *Store) Len() int {\n\ts.mu.Lock()\n\tdefer s.mu.Unlock()\n\treturn len(s.items)\n}";
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![unit_create_op(
            &current_base(&state),
            go_unit("internal/store", "store", false),
            "Store.Len",
            Kind::Method,
            len,
            &[],
        )],
    );
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    assert_eq!(
        project(&state, "internal/store/store.go"),
        STORE_GO.replace(
            "\treturn value, nil\n}\n",
            &format!("\treturn value, nil\n}}\n\n{len}\n")
        )
    );
    for (name, id) in held {
        assert_eq!(go_entity(&state, name).id, id, "{name} keeps its identity");
    }

    // Graph truth survives a restart: the created entities come back from
    // repository authority, not from this process.
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    for name in [
        "main",
        "Store",
        "Store.Get",
        "TestSetGet",
        "ErrNotFound",
        "Getter",
    ] {
        go_entity(&reopened, name);
    }
}

/// Imports are Kin-managed structure: a guarded patch and the import it needs
/// publish together, removal works, and a change already in place publishes
/// nothing.
#[test]
fn unit_imports_publish_with_a_patch_remove_and_stay_idempotent() {
    use kin_mcp::source_unit::DeclarationKind as Kind;
    let (_dir, state) = test_state();
    let sessions = test_sessions();
    let main = || go_unit(".", "main", false);
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![unit_create_op(
            &current_base(&state),
            main(),
            "main",
            Kind::Function,
            "func main() {\n\tfmt.Println(\"hi\")\n}",
            &["fmt"],
        )],
    );
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));

    let entity = go_entity(&state, "main");
    let patch = kin_mcp::McpMutationOperation {
        verb: "patch".into(),
        target: entity.id.to_string(),
        payload: Some(kin_mcp::McpMutationPayload::EntitySourcePatch(
            kin_mcp::source_base::EntitySourcePatch {
                source_base: lifecycle_base(&state, &entity),
                edits: vec![kin_mcp::source_base::EntityTextEdit {
                    old_text: "fmt.Println(\"hi\")".into(),
                    new_text: "os.Stdout.WriteString(strings.ToUpper(\"hi\"))".into(),
                }],
            },
        )),
        body: None,
        destination: None,
        description: "shout".into(),
    };
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![
            patch,
            unit_imports_op(&current_base(&state), main(), &["strings", "os"], &["fmt"]),
        ],
    );
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    assert_eq!(
        project(&state, "main.go"),
        "package main\n\nimport (\n\t\"os\"\n\t\"strings\"\n)\n\nfunc main() {\n\tos.Stdout.WriteString(strings.ToUpper(\"hi\"))\n}\n"
    );
    assert_eq!(
        go_entity(&state, "main").id,
        entity.id,
        "the patched entity keeps its identity"
    );

    let before = load_native_commit_base(&state.layout).unwrap().roots;
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![unit_imports_op(
            &current_base(&state),
            main(),
            &["os"],
            &["absent"],
        )],
    );
    assert_eq!(result.is_error, Some(true));
    assert!(
        result_text(&result).contains("unit_imports_unchanged"),
        "{}",
        result_text(&result)
    );
    assert_eq!(
        load_native_commit_base(&state.layout).unwrap().roots,
        before
    );
}

/// Every refusal leaves authority, the tree and the working copy untouched.
#[test]
fn unit_create_refuses_stale_base_occupied_names_and_foreign_packages_without_publication() {
    use kin_mcp::source_unit::DeclarationKind as Kind;
    let (_dir, state) = test_state();
    let sessions = test_sessions();

    // A base observed before another publication is stale: the refusal is a
    // structured conflict that retains the work and carries the current base,
    // so the retry is one step.
    let observed = current_base(&state);
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![unit_create_op(&observed, go_unit("cmd/tool", "main", false), "main", Kind::Function, "func main() {}", &[])],
    );
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![unit_create_op(&observed, go_unit(".", "main", false), "main", Kind::Function, "func main() {}", &[])],
    );
    assert_eq!(result.is_error, Some(true));
    assert!(
        kin_mcp::source_unit::is_repository_base_conflict(result_text(&result)),
        "{}",
        result_text(&result)
    );
    assert!(!state.layout.working_dir().join("main.go").exists());
    let refusal: serde_json::Value = serde_json::from_str(result_text(&result)).unwrap();
    let fresh: kin_mcp::source_unit::RepositoryBase =
        serde_json::from_value(refusal["current_repository_base"].clone()).unwrap();
    assert_eq!(fresh, current_base(&state));
    let retried = commit_unit_ops(
        &state,
        &sessions,
        vec![unit_create_op(&fresh, go_unit(".", "main", false), "main", Kind::Function, "func main() {}", &[])],
    );
    assert_ne!(retried.is_error, Some(true), "{}", result_text(&retried));
    assert_eq!(project(&state, "main.go"), "package main\n\nfunc main() {}\n");

    // A generation that advanced over an unchanged head and tree (a toolchain
    // run that published nothing) is not a conflict: unit work is planned
    // against the tree, and the tree is exactly what the caller observed.
    let mut advanced = current_base(&state);
    advanced.context.workspace_generation += 1;
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![unit_create_op(&advanced, go_unit(".", "main", false), "version", Kind::Const, "const version = \"0.1.0\"", &[])],
    );
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    // Any other difference is: a changed tree, head, repository or workspace.
    for (label, edit) in [
        ("tree", (|base: &mut kin_mcp::source_unit::RepositoryBase| base.context.workspace_tree_hash = "0".repeat(64)) as fn(&mut kin_mcp::source_unit::RepositoryBase)),
        ("head", |base| base.context.workspace_head_hash = "0".repeat(64)),
        ("workspace", |base| base.context.workspace_id = uuid::Uuid::new_v4().to_string()),
    ] {
        let mut changed = current_base(&state);
        edit(&mut changed);
        let result = commit_unit_ops(
            &state,
            &sessions,
            vec![unit_create_op(&changed, go_unit(".", "main", false), "Other", Kind::Function, "func Other() {}", &[])],
        );
        assert!(
            kin_mcp::source_unit::is_repository_base_conflict(result_text(&result)),
            "{label}: {}",
            result_text(&result)
        );
    }

    let result = commit_unit_ops(&state, &sessions, store_package_ops(&current_base(&state)));
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    let published = project(&state, "internal/store/store.go");

    let store = || go_unit("internal/store", "store", false);
    for (label, operations, reason) in [
        (
            "occupied name",
            vec![unit_create_op(
                &current_base(&state),
                store(),
                "Store",
                Kind::Struct,
                "type Store struct{}",
                &[],
            )],
            "already names a declaration",
        ),
        (
            "occupied name in the test unit of the same package",
            vec![unit_create_op(
                &current_base(&state),
                go_unit("internal/store", "store", true),
                "NewStore",
                Kind::Function,
                "func NewStore() {}",
                &[],
            )],
            "already names a declaration",
        ),
        (
            "foreign package in the same directory",
            vec![unit_create_op(
                &current_base(&state),
                go_unit("internal/store", "other", false),
                "Other",
                Kind::Function,
                "func Other() {}",
                &[],
            )],
            "occupied",
        ),
        (
            "method without its receiver type",
            vec![unit_create_op(
                &current_base(&state),
                store(),
                "Cache.Len",
                Kind::Method,
                "func (c *Cache) Len() int { return 0 }",
                &[],
            )],
            "receiver type Cache",
        ),
        (
            "one name created twice",
            vec![
                unit_create_op(
                    &current_base(&state),
                    store(),
                    "Twice",
                    Kind::Function,
                    "func Twice() {}",
                    &[],
                ),
                unit_create_op(
                    &current_base(&state),
                    store(),
                    "Twice",
                    Kind::Function,
                    "func Twice() {}",
                    &[],
                ),
            ],
            "two creations",
        ),
        (
            "an import already held under another name",
            vec![
                unit_create_op(
                    &current_base(&state),
                    store(),
                    "Extra",
                    Kind::Function,
                    "func Extra() {}",
                    &[],
                ),
                kin_mcp::McpMutationOperation {
                    verb: "update".into(),
                    target: "store".into(),
                    payload: Some(kin_mcp::McpMutationPayload::UnitImports(
                        kin_mcp::source_unit::UnitImports {
                            repository_base: current_base(&state),
                            unit: store(),
                            add: vec![kin_mcp::source_unit::ImportSpec::Named(
                                kin_mcp::source_unit::NamedImport {
                                    path: "sync".into(),
                                    alias: Some("s".into()),
                                },
                            )],
                            remove: Vec::new(),
                        },
                    )),
                    body: None,
                    destination: None,
                    description: "alias sync".into(),
                },
            ],
            "already imported",
        ),
    ] {
        let before = load_native_commit_base(&state.layout).unwrap().roots;
        let result = commit_unit_ops(&state, &sessions, operations);
        assert_eq!(result.is_error, Some(true), "{label}");
        assert!(
            result_text(&result).contains(reason),
            "{label}: {}",
            result_text(&result)
        );
        assert_eq!(
            load_native_commit_base(&state.layout).unwrap().roots,
            before,
            "{label}"
        );
        assert_eq!(
            project(&state, "internal/store/store.go"),
            published,
            "{label}"
        );
        assert!(
            !state
                .layout
                .working_dir()
                .join("internal/store/store_test.go")
                .exists(),
            "{label}"
        );
        assert!(
            !state
                .layout
                .working_dir()
                .join("internal/store/other.go")
                .exists(),
            "{label}"
        );
    }
}

/// One transaction may not publish a directory holding two packages, even
/// when neither unit exists yet and each is valid on its own. Only a package's
/// external test package may share its directory, in test units.
#[test]
fn unit_create_validates_package_identity_across_every_unit_in_a_transaction() {
    use kin_mcp::source_unit::DeclarationKind as Kind;
    let (_dir, state) = test_state();
    let sessions = test_sessions();
    for (label, operations) in [
        (
            "two source packages in the root directory",
            vec![
                unit_create_op(
                    &current_base(&state),
                    go_unit(".", "foo", false),
                    "Foo",
                    Kind::Function,
                    "func Foo() {}",
                    &[],
                ),
                unit_create_op(
                    &current_base(&state),
                    go_unit(".", "bar", false),
                    "Bar",
                    Kind::Function,
                    "func Bar() {}",
                    &[],
                ),
            ],
        ),
        (
            "test units of unrelated packages",
            vec![
                unit_create_op(
                    &current_base(&state),
                    go_unit("lib", "alpha", true),
                    "TestAlpha",
                    Kind::Function,
                    "func TestAlpha(t *testing.T) {}",
                    &["testing"],
                ),
                unit_create_op(
                    &current_base(&state),
                    go_unit("lib", "beta_test", true),
                    "TestBeta",
                    Kind::Function,
                    "func TestBeta(t *testing.T) {}",
                    &["testing"],
                ),
            ],
        ),
        (
            "an external test package in a source unit",
            vec![
                unit_create_op(
                    &current_base(&state),
                    go_unit("lib", "lib", false),
                    "Lib",
                    Kind::Function,
                    "func Lib() {}",
                    &[],
                ),
                unit_create_op(
                    &current_base(&state),
                    go_unit("lib", "lib_test", false),
                    "Helper",
                    Kind::Function,
                    "func Helper() {}",
                    &[],
                ),
            ],
        ),
    ] {
        let result = commit_unit_ops(&state, &sessions, operations);
        assert_eq!(result.is_error, Some(true), "{label}");
        assert!(
            result_text(&result).contains("occupied"),
            "{label}: {}",
            result_text(&result)
        );
        assert_eq!(
            state.graph.resolved_tree().artifacts().count(),
            0,
            "{label}"
        );
    }

    // A package, its internal test unit and its external test package share a
    // directory, and names are scoped to each package.
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![
            unit_create_op(&current_base(&state), go_unit("lib", "lib", false), "Value", Kind::Function, "func Value() int { return 1 }", &[]),
            unit_create_op(&current_base(&state), go_unit("lib", "lib", true), "TestValue", Kind::Function, "func TestValue(t *testing.T) {\n\tif Value() != 1 {\n\t\tt.Fatal(\"value\")\n\t}\n}", &["testing"]),
            unit_create_op(&current_base(&state), go_unit("lib", "lib_test", true), "Value", Kind::Function, "func Value() int { return lib.Value() }", &["example.com/app/lib"]),
        ],
    );
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    assert!(project(&state, "lib/lib.go").starts_with("package lib\n"));
    assert!(project(&state, "lib/lib_test.go").starts_with("package lib\n"));
    assert!(project(&state, "lib/lib_test_unit_test.go").starts_with("package lib_test\n"));

    // A platform-suffixed package name is kept exactly; its file stays
    // unconstrained.
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![unit_create_op(
            &current_base(&state),
            go_unit("sys", "sys_linux", false),
            "Name",
            Kind::Const,
            "const Name = \"sys\"",
            &[],
        )],
    );
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    assert_eq!(
        project(&state, "sys/sys_linux_unit.go"),
        "package sys_linux\n\nconst Name = \"sys\"\n"
    );
}

fn entity_bytes(state: &Arc<DaemonState>, entity: &Entity) -> String {
    let source = project(state, &entity.file_origin.as_ref().unwrap().0);
    let span = entity.span.as_ref().unwrap();
    source[span.start_byte..span.end_byte].to_string()
}

fn member_patch(
    state: &Arc<DaemonState>,
    entity: &Entity,
    old_text: &str,
    new_text: &str,
) -> kin_mcp::McpMutationOperation {
    kin_mcp::McpMutationOperation {
        verb: "patch".into(),
        target: entity.id.to_string(),
        payload: Some(kin_mcp::McpMutationPayload::EntitySourcePatch(
            kin_mcp::source_base::EntitySourcePatch {
                source_base: lifecycle_base(state, entity),
                edits: vec![kin_mcp::source_base::EntityTextEdit {
                    old_text: old_text.into(),
                    new_text: new_text.into(),
                }],
            },
        )),
        body: None,
        destination: None,
        description: "edit a member".into(),
    }
}

fn member_update(state: &Arc<DaemonState>, entity: &Entity, body: &str) -> kin_mcp::McpMutationOperation {
    kin_mcp::McpMutationOperation {
        verb: "update".into(),
        target: entity.id.to_string(),
        payload: Some(kin_mcp::McpMutationPayload::EntitySourceBase(lifecycle_base(
            state, entity,
        ))),
        body: Some(body.into()),
        destination: None,
        description: "rewrite the type".into(),
    }
}

fn absent(state: &Arc<DaemonState>, name: &str) -> bool {
    state
        .graph
        .query_entities(&EntityFilter {
            name_pattern: Some(name.into()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .all(|entity| entity.name != name)
}

/// Iterative greenfield work edits a type's members: a guarded patch or update
/// of a struct or interface may add, remove or rename the members nested inside
/// it. New members become entities, and untouched members keep their ids and
/// exact bytes.
#[test]
fn guarded_type_edits_add_remove_and_rename_nested_members() {
    use kin_mcp::source_unit::DeclarationKind as Kind;
    let (_dir, state) = test_state();
    let sessions = test_sessions();
    let store = || go_unit("internal/store", "store", false);
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![
            unit_create_op(&current_base(&state), store(), "Store", Kind::Struct, "type Store struct {\n\tmu    sync.Mutex\n\titems map[string]string\n}", &["sync"]),
            unit_create_op(&current_base(&state), store(), "Getter", Kind::Interface, "type Getter interface {\n\tGet(key string) (string, error)\n}", &[]),
        ],
    );
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    let held = |state: &Arc<DaemonState>, name: &str| {
        let entity = go_entity(state, name);
        (entity.id, entity_bytes(state, &entity))
    };
    let mu = held(&state, "Store.mu");
    let items = held(&state, "Store.items");
    let get = held(&state, "Getter.Get");

    // A patch adds a field.
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![member_patch(&state, &go_entity(&state, "Store"), "\titems map[string]string\n", "\titems map[string]string\n\tcount int\n")],
    );
    assert_ne!(result.is_error, Some(true), "add a field: {}", result_text(&result));
    let count = go_entity(&state, "Store.count");
    assert_eq!(count.kind, kin_model::EntityKind::Field);
    assert_eq!(entity_bytes(&state, &count), "count int");
    assert_eq!(held(&state, "Store.mu"), mu);
    assert_eq!(held(&state, "Store.items"), items);

    // A patch adds a method to an interface.
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![member_patch(&state, &go_entity(&state, "Getter"), "\tGet(key string) (string, error)\n", "\tGet(key string) (string, error)\n\tLen() int\n")],
    );
    assert_ne!(result.is_error, Some(true), "add an interface method: {}", result_text(&result));
    assert_eq!(go_entity(&state, "Getter.Len").kind, kin_model::EntityKind::Method);
    assert_eq!(held(&state, "Getter.Get"), get);

    // A whole-body update removes a field.
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![member_update(&state, &go_entity(&state, "Store"), "Store struct {\n\tmu    sync.Mutex\n\titems map[string]string\n}")],
    );
    assert_ne!(result.is_error, Some(true), "remove a field: {}", result_text(&result));
    assert!(absent(&state, "Store.count"));
    assert_eq!(held(&state, "Store.mu"), mu);
    assert_eq!(held(&state, "Store.items"), items);

    // A whole-body update renames a field.
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![member_update(&state, &go_entity(&state, "Store"), "Store struct {\n\tmu     sync.Mutex\n\tvalues map[string]string\n}")],
    );
    assert_ne!(result.is_error, Some(true), "rename a field: {}", result_text(&result));
    assert!(absent(&state, "Store.items"));
    assert_eq!(entity_bytes(&state, &go_entity(&state, "Store.values")), "values map[string]string");
    assert_eq!(go_entity(&state, "Store.mu").id, mu.0);
    assert_eq!(
        project(&state, "internal/store/store.go"),
        "package store\n\nimport (\n\t\"sync\"\n)\n\ntype Store struct {\n\tmu     sync.Mutex\n\tvalues map[string]string\n}\n\ntype Getter interface {\n\tGet(key string) (string, error)\n\tLen() int\n}\n"
    );

    // Members stay inside the type they belong to: an edit of one type cannot
    // create a top-level declaration beside it.
    let before = load_native_commit_base(&state.layout).unwrap().roots;
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![member_patch(&state, &go_entity(&state, "Getter"), "\tLen() int\n}", "\tLen() int\n}\n\ntype Extra int")],
    );
    assert_eq!(result.is_error, Some(true), "a top-level declaration smuggled into an edit");
    assert_eq!(load_native_commit_base(&state.layout).unwrap().roots, before);
}

/// `var _ Iface = (*T)(nil)` is created by name `_`; each assertion is its own
/// entity with a stable name derived from the assertion, so they can repeat.
#[test]
fn blank_interface_assertions_are_created_with_derived_identities() {
    use kin_mcp::source_unit::DeclarationKind as Kind;
    let (_dir, state) = test_state();
    let sessions = test_sessions();
    let store = || go_unit("internal/store", "store", false);
    let base = current_base(&state);
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![
            unit_create_op(&base, store(), "Getter", Kind::Interface, "type Getter interface {\n\tGet(key string) string\n}", &[]),
            unit_create_op(&base, store(), "Store", Kind::Struct, "type Store struct{}", &[]),
            unit_create_op(&base, store(), "Cache", Kind::Struct, "type Cache struct{}", &[]),
            unit_create_op(&base, store(), "Store.Get", Kind::Method, "func (s *Store) Get(key string) string { return key }", &[]),
            unit_create_op(&base, store(), "Cache.Get", Kind::Method, "func (c *Cache) Get(key string) string { return \"\" }", &[]),
            unit_create_op(&base, store(), "_", Kind::Var, "var _ Getter = (*Store)(nil)", &[]),
            unit_create_op(&base, store(), "_", Kind::Var, "var _ Getter = (*Cache)(nil)", &[]),
        ],
    );
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    let reply: serde_json::Value = serde_json::from_str(result_text(&result)).unwrap();
    for name in ["_ Getter = (*Store)(nil)", "_ Getter = (*Cache)(nil)"] {
        assert!(
            reply["created_entities"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entity| entity["name"] == name && entity["kind"] == "static_var"),
            "{name}: {reply}"
        );
    }
    let first = go_entity(&state, "_ Getter = (*Store)(nil)");
    assert_eq!(entity_bytes(&state, &first), "_ Getter = (*Store)(nil)");
    assert_ne!(first.id, go_entity(&state, "_ Getter = (*Cache)(nil)").id);

    // Blank specs that differ only inside a literal are distinct entities,
    // created together in one transaction.
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![
            unit_create_op(&current_base(&state), store(), "_", Kind::Var, "var _ = fmt.Sprint(\"a  b\")", &["fmt"]),
            unit_create_op(&current_base(&state), store(), "_", Kind::Var, "var _ = fmt.Sprint(\"a b\")", &["fmt"]),
        ],
    );
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    let spaced = go_entity(&state, "_ = fmt.Sprint(\"a  b\")");
    let single = go_entity(&state, "_ = fmt.Sprint(\"a b\")");
    assert_ne!(spaced.id, single.id);

    // The same assertion twice is a duplicate, refused without publication.
    let before = load_native_commit_base(&state.layout).unwrap().roots;
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![unit_create_op(&current_base(&state), store(), "_", Kind::Var, "var _ Getter = (*Store)(nil)", &[])],
    );
    assert_eq!(result.is_error, Some(true));
    assert!(result_text(&result).contains("already names a declaration"), "{}", result_text(&result));
    assert_eq!(load_native_commit_base(&state.layout).unwrap().roots, before);
}

/// A repository-base conflict on a transaction that also edits an existing
/// entity names that entity: the current repository base does not refresh
/// its source base, so the reply says to re-read it before the resend.
#[test]
fn a_mixed_conflict_names_the_entities_that_need_a_fresh_source_read() {
    use kin_mcp::source_unit::DeclarationKind as Kind;
    let (_dir, state) = test_state();
    let sessions = test_sessions();
    let main = || go_unit(".", "main", false);
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![unit_create_op(&current_base(&state), main(), "main", Kind::Function, "func main() {\n\tprintln(\"hi\")\n}", &[])],
    );
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    let observed = current_base(&state);
    let entity = go_entity(&state, "main");
    let patch = member_patch(&state, &entity, "println(\"hi\")", "fmt.Println(\"hi\")");
    // Another publication moves the tree after both reads.
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![unit_create_op(&observed, main(), "helper", Kind::Function, "func helper() {}", &[])],
    );
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![patch, unit_imports_op(&observed, main(), &["fmt"], &[])],
    );
    let refusal: serde_json::Value = serde_json::from_str(result_text(&result)).unwrap();
    assert_eq!(refusal["code"], "repository_base_conflict", "{refusal}");
    assert_eq!(
        refusal["source_reads_required"],
        serde_json::json!([{"operation": 0, "entity_id": entity.id}])
    );
    let next = refusal["next_step"].as_str().unwrap();
    assert!(next.contains("source (get_entity_source)") && next.contains("source_reads_required"), "{next}");
    let fresh: kin_mcp::source_unit::RepositoryBase =
        serde_json::from_value(refusal["current_repository_base"].clone()).unwrap();

    // Following next_step publishes: re-read the entity, rebuild the patch from
    // that read, and resend with the returned repository base.
    let entity = go_entity(&state, "main");
    let result = commit_unit_ops(
        &state,
        &sessions,
        vec![
            member_patch(&state, &entity, "println(\"hi\")", "fmt.Println(\"hi\")"),
            unit_imports_op(&fresh, main(), &["fmt"], &[]),
        ],
    );
    assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
    assert!(project(&state, "main.go").contains("import (\n\t\"fmt\"\n)"));
}
