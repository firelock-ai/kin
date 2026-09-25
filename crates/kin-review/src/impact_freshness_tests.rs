// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;
use kin_model::{
    ArtifactId, EntityStore, FilePathId, Hash256, LocatedEntry, ParseCompleteness, RepoPath,
    TransactionDelta, TreeDelta, TreeEntry,
};

fn fixture(source: &[u8]) -> (kin_db::InMemoryGraph, ArtifactId, Relation) {
    let graph = kin_db::InMemoryGraph::new();
    let artifact = ArtifactId::new();
    let digest = kin_blobs::digest(source);
    graph
        .apply_transaction_delta(&TransactionDelta {
            tree_deltas: vec![TreeDelta::Added {
                artifact_id: artifact,
                new: LocatedEntry::new(
                    RepoPath::from_utf8("source.py").unwrap(),
                    TreeEntry::blob(Hash256::from_bytes(digest.0), false),
                ),
            }],
            ..Default::default()
        })
        .unwrap();
    let parsed = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(&FilePathId::new("source.py"), source, digest)
        .unwrap()
        .indexed_file;
    let mut certificate = kin_index::build_parse_coverage_relation(
        &kin_index::FileParseData {
            file_path: "source.py".into(),
            entities: parsed.entities.clone(),
            relations: parsed.extracted_relations,
            imports: parsed.imports,
        },
        artifact,
        &ParseCompleteness::from_parse_state(&parsed.parse_state),
        &HashSet::<String>::new(),
    );
    kin_index::bind_parse_coverage_source(
        &mut certificate,
        "source.py",
        Hash256::from_bytes(digest.0),
    );
    for entity in parsed.entities {
        graph.upsert_entity(&entity).unwrap();
    }
    graph.upsert_file_layout(&parsed.file_layout).unwrap();
    graph.upsert_relation(&certificate).unwrap();
    (graph, artifact, certificate)
}

fn complete(graph: &kin_db::InMemoryGraph) -> bool {
    LiveGraph(graph)
        .call_shape_parse_coverage_complete()
        .unwrap()
}

fn move_body(graph: &kin_db::InMemoryGraph, artifact: ArtifactId, body: &[u8]) {
    let tree = graph.resolved_tree();
    let old = tree
        .artifacts_by_path()
        .find(|item| item.artifact_id == artifact)
        .unwrap();
    graph
        .apply_transaction_delta(&TransactionDelta {
            tree_deltas: vec![TreeDelta::Updated {
                artifact_id: artifact,
                old: LocatedEntry::new(old.path.clone(), old.entry),
                new: LocatedEntry::new(
                    old.path.clone(),
                    TreeEntry::blob(Hash256::from_bytes(kin_blobs::digest(body).0), false),
                ),
            }],
            ..Default::default()
        })
        .unwrap();
}

#[test]
fn empty_and_nonempty_certificates_follow_exact_body_and_reopen() {
    for source in [b"".as_slice(), b"def value():\n    return 1\n".as_slice()] {
        let (graph, artifact, _) = fixture(source);
        assert!(complete(&graph));
        move_body(&graph, artifact, b"def changed():\n    return 2\n");
        assert!(!complete(&graph));
        let reopened = kin_db::InMemoryGraph::from_snapshot(graph.to_snapshot()).unwrap();
        assert!(!complete(&reopened));
    }
}

#[test]
fn newly_admitted_source_without_derived_rows_cannot_disappear_from_coverage() {
    let (graph, _, _) = fixture(b"def value():\n    return 1\n");
    assert!(complete(&graph));
    graph
        .apply_transaction_delta(&TransactionDelta {
            tree_deltas: vec![TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("new.h").unwrap(),
                    TreeEntry::blob(Hash256::from_bytes([9; 32]), false),
                ),
            }],
            ..Default::default()
        })
        .unwrap();
    assert!(!complete(&graph));
}

#[test]
fn legacy_full_needs_nonempty_unanimous_current_declarations() {
    let (graph, artifact, mut cert) =
        fixture(b"def value():\n    return 1\ndef second():\n    return 2\n");
    cert.evidence.pop();
    assert!(kin_index::is_parse_coverage_relation(
        &cert,
        "source.py",
        artifact
    ));
    graph.upsert_relation(&cert).unwrap();
    assert!(complete(&graph));
    let mut entity = graph.list_all_entities().unwrap().pop().unwrap();
    entity.metadata.extra.remove("blob_hash");
    graph.upsert_entity(&entity).unwrap();
    assert!(!complete(&graph));
    let (empty, _, mut cert) = fixture(b"");
    // The Python pipeline emits a module even for empty bytes. Exercise a
    // genuinely entity-free persisted source slice rather than assume otherwise.
    for entity in empty.list_all_entities().unwrap() {
        empty.remove_entity(&entity.id).unwrap();
    }
    assert!(empty.list_all_entities().unwrap().is_empty());
    assert!(
        complete(&empty),
        "the bound certificate proves an entity-free body"
    );
    cert.evidence.pop();
    empty.upsert_relation(&cert).unwrap();
    assert!(!complete(&empty));
}

#[test]
fn malformed_binding_cannot_fall_back_to_current_entity_digest() {
    let (graph, artifact, mut cert) = fixture(b"def value():\n    return 1\n");
    cert.evidence.last_mut().unwrap().source_path = Some("another.py".into());
    assert!(!kin_index::is_parse_coverage_relation(
        &cert,
        "source.py",
        artifact
    ));
    graph.upsert_relation(&cert).unwrap();
    assert!(!complete(&graph));
}

#[test]
fn current_opaque_source_name_is_excluded_but_stale_opaque_cannot_hide_source() {
    let graph = kin_db::InMemoryGraph::new();
    let artifact = ArtifactId::new();
    let hash = Hash256::from_bytes(kin_blobs::digest(b"\0binary").0);
    graph
        .apply_transaction_delta(&TransactionDelta {
            tree_deltas: vec![TreeDelta::Added {
                artifact_id: artifact,
                new: LocatedEntry::new(
                    RepoPath::from_utf8("source.py").unwrap(),
                    TreeEntry::blob(hash, false),
                ),
            }],
            ..Default::default()
        })
        .unwrap();
    graph
        .upsert_opaque_artifact(&kin_model::OpaqueArtifact {
            file_id: FilePathId::new("source.py"),
            content_hash: hash,
            mime_type: None,
            text_preview: None,
        })
        .unwrap();
    assert!(complete(&graph));
    move_body(&graph, artifact, b"def now_source():\n    pass\n");
    assert!(!complete(&graph));
}

#[test]
fn unavailable_changed_and_failed_tree_reads_refuse_completeness() {
    let (graph, artifact, _) = fixture(b"def value():\n    return 1\n");
    assert!(!live_call_shape_coverage_with_tree_read(&graph, || Ok(None)).unwrap());
    assert!(
        live_call_shape_coverage_with_tree_read(&graph, || Err(ReviewError::graph(
            std::io::Error::other("unreadable tree")
        )))
        .is_err()
    );
    let before = graph.resolved_tree();
    move_body(&graph, artifact, b"def changed():\n    return 2\n");
    let after = graph.resolved_tree();
    // Return the prior inventory while reading prior proof, then disclose a
    // concurrent admission at the final fence without changing proof fixtures.
    let (old_graph, _, _) = fixture(b"def value():\n    return 1\n");
    let old_tree = old_graph.resolved_tree();
    let mut reads = 0;
    assert!(!live_call_shape_coverage_with_tree_read(&old_graph, || {
        reads += 1;
        Ok(Some(if reads == 1 {
            old_tree.clone()
        } else {
            after.clone()
        }))
    })
    .unwrap());
    assert_eq!(reads, 2);
    assert_ne!(before, after);
}

#[cfg(unix)]
#[test]
fn non_utf8_asset_is_outside_source_scope_but_source_path_stays_unknown() {
    let (graph, _, _) = fixture(b"def value():\n    return 1\n");
    let admit = |path: &[u8]| {
        graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: ArtifactId::new(),
                    new: LocatedEntry::new(
                        RepoPath::from_bytes(path.to_vec()).unwrap(),
                        TreeEntry::blob(Hash256::from_bytes([0x77; 32]), false),
                    ),
                }],
                ..Default::default()
            })
            .unwrap();
    };
    admit(b"assets/\xff.png");
    assert!(
        complete(&graph),
        "a byte-exact non-source asset has no call-shape contract"
    );
    admit(b"source/\xff.py");
    assert!(
        !complete(&graph),
        "an admitted source without representable semantic evidence cannot be skipped"
    );
}

#[test]
#[ignore = "explicit diagnostic: builds bounded synthetic inventories and records cost without asserting timing"]
fn source_derivation_census_diagnostic_cost() {
    // A bounded synthetic parser-produced graph; these are diagnostic costs,
    // not product benchmark or concurrency claims. Fixture construction is not
    // timed, and every timed sample verifies the same real coverage predicate.
    let graph = kin_db::InMemoryGraph::new();
    let source = (0..20)
        .map(|i| format!("def value_{i}():\n    return {i}\n\n"))
        .collect::<String>();
    let digest = kin_blobs::digest(source.as_bytes());
    let pipeline = kin_index::IndexPipeline::new();
    let mut previous = 0;
    for files in [1, 32, 256, 1024] {
        for i in previous..files {
            let file = format!("source_{i}.py");
            let artifact = ArtifactId::new();
            graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![TreeDelta::Added {
                        artifact_id: artifact,
                        new: LocatedEntry::new(
                            RepoPath::from_utf8(&file).unwrap(),
                            TreeEntry::blob(Hash256::from_bytes(digest.0), false),
                        ),
                    }],
                    ..Default::default()
                })
                .unwrap();
            let parsed = pipeline
                .index_file_content_with_tests(&FilePathId::new(&file), source.as_bytes(), digest)
                .unwrap()
                .indexed_file;
            let mut certificate = kin_index::build_parse_coverage_relation(
                &kin_index::FileParseData {
                    file_path: file.clone(),
                    entities: parsed.entities.clone(),
                    relations: parsed.extracted_relations,
                    imports: parsed.imports,
                },
                artifact,
                &ParseCompleteness::from_parse_state(&parsed.parse_state),
                &HashSet::<String>::new(),
            );
            kin_index::bind_parse_coverage_source(
                &mut certificate,
                &file,
                Hash256::from_bytes(digest.0),
            );
            for entity in parsed.entities {
                graph.upsert_entity(&entity).unwrap();
            }
            graph.upsert_file_layout(&parsed.file_layout).unwrap();
            graph.upsert_relation(&certificate).unwrap();
        }
        assert!(complete(&graph));
        let mut samples = Vec::new();
        for _ in 0..9 {
            let started = std::time::Instant::now();
            assert!(complete(&graph));
            samples.push(started.elapsed().as_micros());
        }
        samples.sort_unstable();
        println!(
            "source-derivation-census-cost: {}",
            serde_json::json!({"fixture":"synthetic_python_parsed","files":files,"entities":graph.entity_count(),"relations":graph.relation_count(),"samples_us":samples,"median_us":samples[4],"max_us":samples[8],"implementation":"existing_live_call_shape_coverage_full_census"})
        );
        for selected in [false, true] {
            let paths = [RepoPath::from_utf8("source_0.py").unwrap()];
            let mut samples = Vec::new();
            let mut outcomes = Vec::new();
            for _ in 0..9 {
                let started = std::time::Instant::now();
                let result = graph.source_derivation_facts_with_reserved_relation(
                    kin_db::SourceDerivationLimits::default(),
                    selected.then_some(paths.as_slice()),
                    kin_index::binding_debt::local_binding_debt_id,
                );
                let outcome = match result {
                    Ok(facts) => {
                        let report = crate::source_derivation::inspect_source_derivation(&facts);
                        assert_eq!(
                            report.body_binding,
                            crate::source_derivation::SourceBinding::Current
                        );
                        assert_eq!(
                            report.prior_local_binding,
                            crate::source_derivation::PriorLocalBindingStatus::NoRecordedDebt
                        );
                        "current_body_no_recorded_debt".to_string()
                    }
                    Err(error) => format!("unproven:{error}"),
                };
                samples.push(started.elapsed().as_micros());
                outcomes.push(outcome);
            }
            samples.sort_unstable();
            println!(
                "source-derivation-bounded-cost: {}",
                serde_json::json!({"fixture":"synthetic_python_parsed","files":files,"entities":graph.entity_count(),"selected_file":selected,"samples_us":samples,"median_us":samples[4],"max_us":samples[8],"outcomes":outcomes,"implementation":"bounded_facts_plus_shared_report"})
            );
        }
        previous = files;
    }
}

fn source_report(
    graph: &kin_db::InMemoryGraph,
) -> crate::source_derivation::SourceDerivationReport {
    let facts = graph
        .source_derivation_facts_with_reserved_relation(
            kin_db::SourceDerivationLimits::default(),
            None,
            kin_index::binding_debt::local_binding_debt_id,
        )
        .unwrap();
    crate::source_derivation::inspect_source_derivation(&facts)
}

#[test]
fn source_report_separates_current_body_from_import_and_parse_completeness() {
    use crate::source_derivation::{DerivationCoverage, SourceBinding};
    let (graph, artifact, mut certificate) = fixture(b"def value():\n    return 1\n");
    let initial = source_report(&graph);
    assert_eq!(initial.body_binding, SourceBinding::Current);
    assert_eq!(initial.parse_coverage, DerivationCoverage::Complete);
    assert_eq!(initial.call_shape_parse_coverage_complete, complete(&graph));
    // Exact factory-valid import evidence can be unresolved while the source
    // and call-shape parser proofs remain unchanged.
    certificate.evidence[1].occurrence_count = 1;
    assert!(kin_index::is_parse_coverage_relation(
        &certificate,
        "source.py",
        artifact
    ));
    graph.upsert_relation(&certificate).unwrap();
    let unresolved = source_report(&graph);
    assert_eq!(unresolved.body_binding, SourceBinding::Current);
    assert_eq!(unresolved.import_resolution, DerivationCoverage::Incomplete);
    assert!(unresolved.call_shape_parse_coverage_complete);
    assert!(complete(&graph));
    certificate.evidence[0].parser_rule =
        Some(kin_index::CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1.into());
    certificate.evidence[0].token = Some("call-extraction-incomplete".into());
    assert!(kin_index::is_parse_coverage_relation(
        &certificate,
        "source.py",
        artifact
    ));
    graph.upsert_relation(&certificate).unwrap();
    let partial = source_report(&graph);
    assert_eq!(partial.body_binding, SourceBinding::Current);
    assert_eq!(partial.parse_coverage, DerivationCoverage::Unproven);
    assert_eq!(partial.call_extraction, DerivationCoverage::Incomplete);
    assert!(!partial.call_shape_parse_coverage_complete);
    assert!(!complete(&graph));
}

#[test]
fn source_report_binding_survives_reopen_and_needs_nonvacuous_evidence() {
    use crate::source_derivation::SourceBinding;
    for source in [b"".as_slice(), b"def value():\n    return 1\n".as_slice()] {
        let (graph, artifact, certificate) = fixture(source);
        assert_eq!(source_report(&graph).body_binding, SourceBinding::Current);
        move_body(&graph, artifact, b"def other():\n    return 2\n");
        let reopened = kin_db::InMemoryGraph::from_snapshot(graph.to_snapshot()).unwrap();
        assert_eq!(source_report(&reopened).body_binding, SourceBinding::Stale);
        assert!(!source_report(&reopened).call_shape_parse_coverage_complete);
        graph.remove_relation(&certificate.id).unwrap();
        assert_ne!(source_report(&graph).body_binding, SourceBinding::Current);
    }
}

#[test]
fn source_report_refusal_is_unknown_but_completed_empty_inventory_is_zero() {
    use crate::source_derivation::{SourceBinding, SourceDerivationReport};
    let graph = kin_db::InMemoryGraph::new();
    let empty = source_report(&graph);
    let json = serde_json::to_value(&empty).unwrap();
    assert_eq!(empty.body_binding, SourceBinding::Current);
    assert_eq!(json["full_adapter_sources"], 0);
    assert_eq!(json["excluded_artifacts"], 0);
    // Only a cap can refuse, and a cap counts graph content, so the refusal
    // needs an inventory larger than its cap.
    let (populated, _, _) = fixture(b"def value():\n    return 1\n");
    let error = populated
        .source_derivation_facts_with_reserved_relation(
            kin_db::SourceDerivationLimits {
                max_artifacts: 0,
                ..Default::default()
            },
            None,
            kin_index::binding_debt::local_binding_debt_id,
        )
        .unwrap_err();
    let refused = SourceDerivationReport::unproven(&error.to_string());
    let json = serde_json::to_value(&refused).unwrap();
    assert_eq!(refused.body_binding, SourceBinding::Unproven);
    assert!(json["full_adapter_sources"].is_null());
    assert!(json["excluded_artifacts"].is_null());
    assert_eq!(
        serde_json::from_value::<SourceDerivationReport>(json).unwrap(),
        refused
    );
}

fn binding_prerequisites(graph: &kin_db::InMemoryGraph) -> bool {
    LiveGraph(graph)
        .call_shape_binding_prerequisites_complete()
        .unwrap()
}

fn checked_binding_fixture(source: &[u8]) -> (kin_db::InMemoryGraph, ArtifactId) {
    // Establish a real native genesis, then use the same semantic derivation
    // verifier as live admission. A raw fixture cannot assert checked history.
    let root = tempfile::tempdir().unwrap();
    let initialized = kin_core::init(root.path()).unwrap();
    let authority = kin_db::RepositoryAuthorityManager::open(
        initialized.repository_id,
        std::sync::Arc::new(kin_db::LocalFileBackend::new(
            initialized.layout.kindb_dir(),
        )),
    )
    .unwrap();
    let before = authority
        .read_authority()
        .workspace_graph_snapshot(&initialized.workspace_id)
        .unwrap()
        .unwrap();
    authority
        .save_source_blob(Hash256::from_bytes(kin_blobs::digest(source).0), source)
        .unwrap();
    let (graph, artifact, _) = fixture(source);
    assert!(graph
        .qualify_binding_history_derivation(
            &before,
            &kin_index::binding_history::LocalBindingHistoryVerifier,
            &|digest| authority.load_source_blob(digest),
        )
        .unwrap());
    (graph, artifact)
}

fn debt_relation(artifact: ArtifactId, body: &[u8]) -> Relation {
    use kin_index::binding_debt::{
        build_local_binding_debt, LocalBindingDebt, LocalBindingObligation,
    };
    let digest = Hash256::from_bytes(kin_blobs::digest(body).0);
    let obligations = (0..2)
        .map(|n| LocalBindingObligation {
            retired_relation: Relation {
                id: kin_model::RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(EntityId::new()),
                dst: GraphNodeId::Entity(EntityId::new()),
                confidence: 1.0,
                origin: kin_model::RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: vec![],
            },
            source_name: "value".into(),
            source_digest: digest,
            prior_source_file: None,
            target_artifact: ArtifactId::new(),
            target_file: FilePathId::new(format!("target{n}.py")),
            target_name: "work".into(),
        })
        .collect();
    build_local_binding_debt(
        artifact,
        LocalBindingDebt {
            source_file: FilePathId::new("source.py"),
            observed_source_digest: digest,
            obligations,
        },
    )
    .unwrap()
}

#[test]
fn binding_debt_is_independent_of_full_parse_and_survives_persisted_reopen() {
    use crate::source_derivation::{DerivationCoverage, PriorLocalBindingStatus, SourceBinding};
    let body = b"def value():\n    return 1\n";
    let (graph, artifact) = checked_binding_fixture(body);
    assert!(binding_prerequisites(&graph));
    let checked = kin_db::InMemoryGraph::from_snapshot(graph.to_snapshot()).unwrap();
    let debt = debt_relation(artifact, body);
    graph.upsert_relation(&debt).unwrap();
    {
        let reopened = kin_db::InMemoryGraph::from_snapshot(graph.to_snapshot()).unwrap();
        for view in [&graph, &reopened] {
            let report = source_report(view);
            assert_eq!(report.body_binding, SourceBinding::Current);
            assert_eq!(report.parse_coverage, DerivationCoverage::Complete);
            assert!(complete(view));
            assert!(!binding_prerequisites(view));
            assert_eq!(
                report.prior_local_binding,
                PriorLocalBindingStatus::Outstanding
            );
            assert_eq!(report.outstanding_local_binding_obligations, Some(2));
        }
        graph.remove_relation(&debt.id).unwrap();
        // Removing a row alone is not a checked discharge. Here the exact
        // original, qualified observation is restored after the synthetic debt
        // control; production restores only a matching held authority view.
        assert!(!binding_prerequisites(&graph));
        assert!(graph.restore_binding_history_from(&checked));
        assert!(binding_prerequisites(&graph));
        assert_eq!(
            source_report(&graph).outstanding_local_binding_obligations,
            Some(0)
        );
    }
}

#[test]
fn binding_lookup_rejects_foreign_occupants_wrong_kind_claims_and_stale_debt() {
    use crate::source_derivation::PriorLocalBindingStatus;
    let body = b"def value():\n    return 1\n";
    for mutation in ["foreign", "wrong_kind_and_id", "stale", "malformed"] {
        let (graph, artifact, _) = fixture(body);
        let mut relation = debt_relation(artifact, body);
        match mutation {
            "foreign" => {
                relation.src = GraphNodeId::Entity(EntityId::new());
                relation.dst = relation.src;
                relation.kind = RelationKind::References;
                relation.evidence.clear();
            }
            "wrong_kind_and_id" => {
                relation.id = kin_model::RelationId::new();
                relation.kind = RelationKind::References;
            }
            "stale" => relation = debt_relation(artifact, b"def other():\n    pass\n"),
            "malformed" => relation.evidence[0].token = Some("invalid".into()),
            _ => unreachable!(),
        }
        graph.upsert_relation(&relation).unwrap();
        let report = source_report(&graph);
        assert!(complete(&graph), "{mutation}");
        assert!(!binding_prerequisites(&graph), "{mutation}");
        assert_eq!(
            report.prior_local_binding,
            PriorLocalBindingStatus::Unproven,
            "{mutation}"
        );
        assert_eq!(
            report.outstanding_local_binding_obligations, None,
            "{mutation}"
        );
    }
}

#[test]
fn unchecked_or_inconsistent_exact_binding_observation_is_unproven() {
    use crate::source_derivation::{
        inspect_local_binding, ExactBindingRecord, PriorLocalBindingStatus,
    };
    let body = b"def value():\n    return 1\n";
    let (graph, artifact, _) = fixture(body);
    let facts = graph
        .source_derivation_facts(kin_db::SourceDerivationLimits::default(), None)
        .unwrap();
    let report = crate::source_derivation::inspect_source_derivation(&facts);
    assert_eq!(
        report.prior_local_binding,
        PriorLocalBindingStatus::Unproven
    );
    assert!(report.call_shape_parse_coverage_complete);
    assert_eq!(report.outstanding_local_binding_obligations, None);
    let debt = debt_relation(artifact, body);
    let digest = Hash256::from_bytes(kin_blobs::digest(body).0);
    for exact in [ExactBindingRecord::Unavailable, ExactBindingRecord::Absent] {
        let observation = inspect_local_binding(
            "source.py",
            artifact,
            digest,
            &[&debt],
            exact,
            &kin_model::BindingHistoryObservation::Unproven,
        );
        assert_eq!(observation.status, PriorLocalBindingStatus::Unproven);
        assert_eq!(observation.count, None);
    }
    let empty = source_report(&kin_db::InMemoryGraph::new());
    assert_eq!(empty.prior_local_binding, PriorLocalBindingStatus::Unproven);
    assert_eq!(empty.outstanding_local_binding_obligations, None);
}

#[test]
#[ignore = "explicit diagnostic: bounded canonical multi-obligation payload, not a product latency benchmark"]
fn local_binding_payload_diagnostic_cost() {
    let body = b"def value():\n    return 1\n";
    let (graph, artifact, _) = fixture(body);
    let prototype = debt_relation(artifact, body);
    let mut debt = kin_index::binding_debt::decode_local_binding_debt(
        &FilePathId::new("source.py"),
        artifact,
        &prototype,
    )
    .unwrap()
    .unwrap();
    let original = debt.obligations[0].clone();
    debt.obligations = (0..64)
        .map(|_| {
            let mut obligation = original.clone();
            obligation.retired_relation.id = kin_model::RelationId::new();
            obligation
                .retired_relation
                .evidence
                .push(kin_model::RelationEvidence {
                    token: Some("x".repeat(1024)),
                    ..Default::default()
                });
            obligation
        })
        .collect();
    let relation = kin_index::binding_debt::build_local_binding_debt(artifact, debt).unwrap();
    let payload_bytes = relation.evidence[0].token.as_ref().unwrap().len();
    graph.upsert_relation(&relation).unwrap();
    let mut samples = Vec::new();
    for _ in 0..9 {
        let started = std::time::Instant::now();
        let facts = graph
            .source_derivation_facts_with_reserved_relation(
                kin_db::SourceDerivationLimits::default(),
                None,
                kin_index::binding_debt::local_binding_debt_id,
            )
            .unwrap();
        let report = crate::source_derivation::inspect_source_derivation(&facts);
        assert_eq!(
            report.prior_local_binding,
            crate::source_derivation::PriorLocalBindingStatus::Outstanding
        );
        assert_eq!(report.outstanding_local_binding_obligations, Some(64));
        assert!(report.call_shape_parse_coverage_complete);
        samples.push(started.elapsed().as_micros());
    }
    samples.sort_unstable();
    println!(
        "local-binding-payload-cost: {}",
        serde_json::json!({"sources":1,"obligations":64,"payload_bytes":payload_bytes,"samples_us":samples,"median_us":samples[4],"max_us":samples[8]})
    );
}
