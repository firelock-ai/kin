// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_db::{InMemoryGraph, SnapshotManager};
use kin_mcp::{handlers::entities::handle_get_context_pack, SessionRegistry};
use kin_model::*;
use std::collections::{BTreeMap, HashMap};

fn entity(name: &str, file: &str) -> Entity {
    Entity {
        id: EntityId::new(),
        kind: EntityKind::Function,
        name: name.into(),
        language: LanguageId::Rust,
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
        signature: format!("fn {name}()"),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: None,
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

fn edge(graph: &InMemoryGraph, src: &Entity, dst: &Entity, kind: RelationKind) {
    graph
        .upsert_relation(&Relation {
            id: RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src.id),
            dst: GraphNodeId::Entity(dst.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![],
        })
        .unwrap();
}

fn fixture(graph: &InMemoryGraph) -> EntityId {
    let nodes: Vec<_> = [
        "focal",
        "direct",
        "transitive",
        "far",
        "incoming",
        "structural",
        "unrelated",
    ]
    .iter()
    .map(|name| entity(name, &format!("src/{name}.rs")))
    .collect();
    let sibling = entity("sibling", "src/focal.rs");
    for node in nodes.iter().chain([&sibling]) {
        graph.upsert_entity(node).unwrap();
    }
    for (a, b, k) in [
        (0, 1, RelationKind::Calls),
        (1, 2, RelationKind::UsesType),
        (2, 3, RelationKind::Calls),
        (2, 0, RelationKind::Calls),
        (4, 0, RelationKind::Calls),
        (0, 5, RelationKind::Contains),
    ] {
        edge(graph, &nodes[a], &nodes[b], k);
    }
    let registry = SessionRegistry::new();
    let session = registry.start_agent_session(
        "test-vendor",
        "traffic",
        SessionTransport::Mcp,
        None,
        "/not-a-source-directory".into(),
        SessionCapabilities::default(),
    );
    graph.upsert_session(&session).unwrap();
    let mut scopes: Vec<_> = nodes
        .iter()
        .map(|node| (node.name.as_str(), vec![IntentScope::Entity(node.id)]))
        .collect();
    scopes.extend([
        (
            "file",
            vec![IntentScope::Artifact(FilePathId::new("src/focal.rs"))],
        ),
        ("sibling", vec![IntentScope::Entity(sibling.id)]),
        (
            "mixed",
            vec![
                IntentScope::Entity(nodes[2].id),
                IntentScope::Entity(nodes[1].id),
            ],
        ),
        ("missing", vec![IntentScope::Entity(EntityId::new())]),
    ]);
    for (label, scopes) in scopes {
        graph
            .register_intent(&Intent {
                intent_id: IntentId::new(),
                session_id: session.session_id,
                scopes,
                lock_type: LockType::Soft,
                task_description: label.into(),
                registered_at: Timestamp::now(),
                expires_at: None,
            })
            .unwrap();
    }
    nodes[0].id
}

fn read(graph: &InMemoryGraph, focal: EntityId, depth: u32, include: bool) -> serde_json::Value {
    let registry = SessionRegistry::new();
    registry.replace_agent_sessions_and_intents(
        graph.list_sessions().unwrap(),
        graph.list_all_intents().unwrap(),
    );
    let result = handle_get_context_pack(
        &HashMap::from([
            ("entity_id".into(), serde_json::json!(focal.to_string())),
            ("depth".into(), serde_json::json!(depth)),
            ("include_traffic".into(), serde_json::json!(include)),
            ("token_budget".into(), serde_json::json!(16000)),
        ]),
        graph,
        &registry,
        None,
    )
    .unwrap();
    let kin_mcp::types::ContentBlock::Text { text } = &result.content[0];
    serde_json::from_str(text).unwrap()
}

fn rows(value: &serde_json::Value) -> BTreeMap<String, String> {
    value["nearby_traffic"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| {
            (
                row["intent"]["task_description"].as_str().unwrap().into(),
                row["proximity"].as_str().unwrap().into(),
            )
        })
        .collect()
}

#[test]
fn context_traffic_real_handler_classifies_scopes_after_snapshot_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("graph.kndb");
    let manager = SnapshotManager::new(&path);
    let focal = fixture(&manager.graph());
    let expected = BTreeMap::from([
        ("focal".into(), "Direct".into()),
        ("direct".into(), "Direct".into()),
        ("transitive".into(), "Downstream".into()),
        ("file".into(), "SameFile".into()),
        ("sibling".into(), "SameFile".into()),
        ("mixed".into(), "Direct".into()),
    ]);
    let live = read(&manager.graph(), focal, 2, true);
    eprintln!("TRAFFIC_LIVE={live}");
    assert_eq!(rows(&live), expected);
    manager.save().unwrap();
    drop(manager);
    let reopened = SnapshotManager::open(&path).unwrap();
    assert_eq!(rows(&read(&reopened.graph(), focal, 2, true)), expected);
    assert!(rows(&read(&reopened.graph(), focal, 2, false)).is_empty());
    assert!(!rows(&read(&reopened.graph(), focal, 1, true)).contains_key("transitive"));
    assert!(!rows(&read(&reopened.graph(), focal, 0, true)).contains_key("direct"));
}

#[test]
fn context_traffic_summary_builder_uses_persisted_intent_scopes() {
    let graph = InMemoryGraph::new();
    let focal = fixture(&graph);
    let summaries: Vec<_> = graph
        .list_all_intents()
        .unwrap()
        .into_iter()
        .map(|intent| IntentSummary {
            intent_id: intent.intent_id,
            session_id: intent.session_id,
            vendor: "test-vendor".into(),
            task_description: intent.task_description,
            lock_type: intent.lock_type,
            registered_at: intent.registered_at,
        })
        .collect();
    let pack = kin_context::build_context_pack_with_traffic(
        &graph,
        &focal,
        &kin_context::ContextOptions {
            include_traffic: true,
            max_depth: 2,
            ..Default::default()
        },
        &summaries,
    )
    .unwrap();
    let actual: BTreeMap<_, _> = pack
        .traffic
        .iter()
        .map(|row| (row.intent.task_description.as_str(), row.proximity))
        .collect();
    eprintln!("TRAFFIC_SUMMARIES={actual:?}");
    assert_eq!(
        actual.get("transitive"),
        Some(&TrafficProximity::Downstream)
    );
    assert_eq!(actual.get("file"), Some(&TrafficProximity::SameFile));
    assert!(!actual.contains_key("unrelated"));
}

fn add_intent(graph: &InMemoryGraph, task: &str, scopes: Vec<IntentScope>) -> Intent {
    let session = graph.list_sessions().unwrap().remove(0);
    let intent = Intent {
        intent_id: IntentId::new(),
        session_id: session.session_id,
        scopes,
        lock_type: LockType::Soft,
        task_description: task.into(),
        registered_at: Timestamp::now(),
        expires_at: None,
    };
    graph.register_intent(&intent).unwrap();
    intent
}

#[test]
fn context_traffic_typed_contract_and_artifact_dependencies_are_observed() {
    let graph = InMemoryGraph::new();
    let focal = fixture(&graph);
    let contract = ContractId::new();
    graph
        .create_contract(&Contract {
            id: EntityId(contract.0),
            kind: ContractKind::TypedInterface,
            name: "traffic contract".into(),
            schema_hash: Hash256::from_bytes([3; 32]),
            producers: vec![],
            consumers: vec![],
            version: None,
        })
        .unwrap();
    let artifact = ArtifactId::new();
    graph
        .apply_transaction_delta(&TransactionDelta {
            tree_deltas: vec![TreeDelta::Added {
                artifact_id: artifact,
                new: LocatedEntry::new(
                    RepoPath::from_utf8("schema/spec.json").unwrap(),
                    TreeEntry::blob(Hash256::from_bytes([7; 32]), false),
                ),
            }],
            ..Default::default()
        })
        .unwrap();
    for target in [
        GraphNodeId::Contract(contract),
        GraphNodeId::Artifact(artifact),
    ] {
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::DependsOn,
                src: GraphNodeId::Entity(focal),
                dst: target,
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: vec![],
            })
            .unwrap();
    }
    add_intent(&graph, "contract", vec![IntentScope::Contract(contract)]);
    add_intent(
        &graph,
        "artifact",
        vec![IntentScope::Artifact(FilePathId::new("schema/spec.json"))],
    );
    let rows = rows(&read(&graph, focal, 2, true));
    assert_eq!(
        rows.get("contract").map(String::as_str),
        Some("Direct"),
        "{rows:?}"
    );
    assert_eq!(
        rows.get("artifact").map(String::as_str),
        Some("Direct"),
        "{rows:?}"
    );
}

#[test]
fn context_traffic_excludes_expired_or_orphaned_and_observes_release() {
    let graph = InMemoryGraph::new();
    let focal = fixture(&graph);
    let mut expired = add_intent(&graph, "expired", vec![IntentScope::Entity(focal)]);
    expired.expires_at =
        Some(serde_json::from_value(serde_json::json!("2000-01-01T00:00:00Z")).unwrap());
    graph.register_intent(&expired).unwrap();
    let mut orphan = add_intent(&graph, "orphan", vec![IntentScope::Entity(focal)]);
    orphan.session_id = SessionId::new();
    graph.register_intent(&orphan).unwrap();
    let active = add_intent(&graph, "released", vec![IntentScope::Entity(focal)]);
    let before = rows(&read(&graph, focal, 2, true));
    assert!(before.contains_key("released"));
    assert!(!before.contains_key("expired"));
    assert!(!before.contains_key("orphan"));
    graph.delete_intent(&active.intent_id).unwrap();
    assert!(!rows(&read(&graph, focal, 2, true)).contains_key("released"));
}

#[test]
fn context_traffic_preserves_strongest_scope_and_file_dependency_distance() {
    let graph = InMemoryGraph::new();
    let focal = fixture(&graph);
    add_intent(
        &graph,
        "direct_file",
        vec![IntentScope::Artifact(FilePathId::new("src/direct.rs"))],
    );
    add_intent(
        &graph,
        "transitive_file",
        vec![IntentScope::Artifact(FilePathId::new("src/transitive.rs"))],
    );
    add_intent(
        &graph,
        "same_before_transitive",
        vec![
            IntentScope::Artifact(FilePathId::new("src/transitive.rs")),
            IntentScope::Artifact(FilePathId::new("src/focal.rs")),
        ],
    );
    add_intent(
        &graph,
        "direct_before_same",
        vec![
            IntentScope::Artifact(FilePathId::new("src/focal.rs")),
            IntentScope::Entity(focal),
        ],
    );
    let rows = rows(&read(&graph, focal, 2, true));
    for (name, expected) in [
        ("direct_file", "Direct"),
        ("transitive_file", "Downstream"),
        ("same_before_transitive", "SameFile"),
        ("direct_before_same", "Direct"),
    ] {
        assert_eq!(rows.get(name).map(String::as_str), Some(expected));
    }
}

#[test]
fn context_traffic_missing_scope_proof_refuses_instead_of_direct() {
    let graph = InMemoryGraph::new();
    let focal = fixture(&graph);
    let summary = IntentSummary {
        intent_id: IntentId::new(),
        session_id: SessionId::new(),
        vendor: "unproven".into(),
        task_description: "unproven".into(),
        lock_type: LockType::Hard,
        registered_at: Timestamp::now(),
    };
    let error = kin_context::build_context_pack_with_traffic(
        &graph,
        &focal,
        &kin_context::ContextOptions {
            include_traffic: true,
            ..Default::default()
        },
        &[summary],
    )
    .unwrap_err();
    assert!(error.to_string().contains("no scope evidence"));
}

#[test]
fn context_traffic_bounds_expansion_and_preserves_the_output_budget() {
    let graph = InMemoryGraph::new();
    let focal = fixture(&graph);
    let scopes = vec![IntentScope::Entity(focal)];
    let oversized = add_intent(&graph, &"oversized ".repeat(1000), scopes);
    let registry = SessionRegistry::new();
    registry.replace_agent_sessions_and_intents(
        graph.list_sessions().unwrap(),
        graph.list_all_intents().unwrap(),
    );
    let (pack, _) = kin_context::build_context_pack_with_scoped_traffic_and_provenance(
        &graph,
        &focal,
        &kin_context::ContextOptions {
            include_traffic: true,
            budget: TokenBudget::Custom(500),
            ..Default::default()
        },
        &registry.context_traffic_snapshot(),
    )
    .unwrap();
    assert!(pack.actual_tokens <= 500);
    assert!(!pack
        .traffic
        .iter()
        .any(|row| row.intent.intent_id == oversized.intent_id));
    let focal_entity = graph.get_entity(&focal).unwrap().unwrap();
    for index in 0..4096 {
        let target = entity(&format!("wide_{index}"), "src/wide.rs");
        graph.upsert_entity(&target).unwrap();
        edge(&graph, &focal_entity, &target, RelationKind::Calls);
    }
    let error = kin_context::build_context_pack_with_scoped_traffic_and_provenance(
        &graph,
        &focal,
        &kin_context::ContextOptions {
            include_traffic: true,
            max_depth: 1,
            ..Default::default()
        },
        &registry.context_traffic_snapshot(),
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("traffic proximity node budget exceeded"));
}
