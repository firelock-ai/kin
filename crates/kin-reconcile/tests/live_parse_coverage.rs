// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_blobs::BlobStore;
use kin_db::{InMemoryGraph, SnapshotManager};
use kin_index::{FileParseData, IndexPipeline, IndexedFile};
use kin_model::{
    ArtifactId, EntityStore, FilePathId, GraphNodeId, Hash256, LocatedEntry, ParseCompleteness,
    Relation, RelationDelta, RelationKind, RepoPath, TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::{ReconcileOutcome, Reconciler};
use std::collections::HashMap;
use std::sync::Arc;

struct Repo {
    root: tempfile::TempDir,
    blobs: BlobStore,
    graph: Arc<InMemoryGraph>,
    reconciler: Reconciler,
}
impl Repo {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(root.path().join("blobs")).unwrap();
        let reconciler = Reconciler::new(root.path().to_owned());
        Self {
            root,
            blobs,
            graph: Arc::new(InMemoryGraph::new()),
            reconciler,
        }
    }
    fn admit(&mut self, file: &str, source: &str) -> IndexedFile {
        let blob = self.blobs.write(source.as_bytes()).unwrap();
        let path = RepoPath::from_utf8(file.to_owned()).unwrap();
        let entry = TreeEntry::blob(Hash256::from_bytes(blob.0), false);
        let new = LocatedEntry::new(path.clone(), entry.clone());
        let change = match self.graph.get_tree_entry(&FilePathId::new(file)).unwrap() {
            Some(old) if old == entry => None,
            Some(old) => Some(TreeDelta::Updated {
                artifact_id: self.graph.artifact_id_at_path(&path).unwrap(),
                old: LocatedEntry::new(path, old),
                new,
            }),
            None => Some(TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new,
            }),
        };
        if let Some(change) = change {
            self.graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![change],
                    ..Default::default()
                })
                .unwrap();
        }
        IndexPipeline::new()
            .index_file_content_with_tests(&FilePathId::new(file), source.as_bytes(), blob)
            .unwrap()
            .indexed_file
    }
    fn observe(&mut self, indexed: &IndexedFile) -> kin_reconcile::ReconcileResult {
        let result = self
            .reconciler
            .reconcile_indexed_observation(indexed, &self.blobs, self.graph.as_ref())
            .unwrap();
        // These are the daemon's actual applied outcome classes. BrokenAst does
        // not apply a hidden delta and cannot withdraw a stale certificate.
        if matches!(
            result.outcome,
            ReconcileOutcome::Updated { .. }
                | ReconcileOutcome::PartiallyUpdated { .. }
                | ReconcileOutcome::FileRemoved { .. }
        ) {
            self.graph.apply_transaction_delta(&result.delta).unwrap();
        }
        result
    }
    fn artifact(&self, file: &str) -> ArtifactId {
        self.graph
            .artifact_id_at_path(&RepoPath::from_utf8(file.to_owned()).unwrap())
            .unwrap()
    }
    fn coverage(&self, file: &str) -> Vec<Relation> {
        let node = GraphNodeId::Artifact(self.artifact(file));
        self.graph
            .traverse(&node, &[RelationKind::DependsOn], 1)
            .unwrap()
            .relations
            .into_iter()
            .filter(|r| r.src == node && r.dst == node)
            .collect()
    }
    fn real_certificate(&self, indexed: &IndexedFile) -> Relation {
        let file = FileParseData {
            file_path: indexed.file_id.0.clone(),
            entities: indexed.entities.clone(),
            relations: indexed.extracted_relations.clone(),
            imports: indexed.imports.clone(),
        };
        let mut relation = kin_index::link_cross_file_with_completeness(
            &[file],
            &HashMap::from([(indexed.file_id.0.clone(), self.artifact(&indexed.file_id.0))]),
            &HashMap::from([(
                indexed.file_id.0.clone(),
                ParseCompleteness::from_parse_state(&indexed.parse_state),
            )]),
        )
        .unwrap()
        .into_iter()
        .find(|r| r.kind == RelationKind::DependsOn && r.src == r.dst)
        .unwrap();
        // A file that declares nothing holds no entity to carry its body hash,
        // so the batch linker leaves the certificate's source unbound while the
        // live path binds it from the admitted blob. The daemon and `kin init`
        // both take the live path, so the certificate a store actually holds
        // for such a file carries the digest, and comparing against the half
        // the batch path can reconstruct would grade the helper rather than the
        // product. `unanimous_entity_source_digest` says the same thing at its
        // own definition. This used to be unreachable for `src/app.js` only
        // because every JavaScript file minted a module entity whether or not
        // its bytes declared anything.
        if kin_index::parse_coverage_source_digest(&relation).is_none() {
            kin_index::bind_parse_coverage_source(
                &mut relation,
                &indexed.file_id.0,
                Hash256::from_bytes(*indexed.blob_hash.as_bytes()),
            );
        }
        relation
    }
    fn seed_real_certificate(&self, indexed: &IndexedFile) {
        let new = self.real_certificate(indexed);
        if self.coverage(&indexed.file_id.0).is_empty() {
            self.graph
                .apply_transaction_delta(&TransactionDelta {
                    relation_deltas: vec![RelationDelta::Added { new }],
                    ..Default::default()
                })
                .unwrap();
        }
    }
}
fn has_full(relations: &[Relation]) -> bool {
    relations
        .iter()
        .flat_map(|r| &r.evidence)
        .any(|e| e.parser_rule.as_deref() == Some(kin_index::CALL_SHAPE_PARSE_COVERAGE_FULL_V1))
}

#[test]
fn fresh_imported_call_admits_exact_parser_certificate() {
    let mut repo = Repo::new();
    let indexed = repo.admit(
        "src/app.js",
        "const remote = require('external-one');\nfunction run() { return remote(); }\n",
    );
    let expected = repo.real_certificate(&indexed);
    repo.observe(&indexed);
    assert_eq!(repo.coverage("src/app.js"), vec![expected]);
}

#[test]
fn empty_no_import_and_unused_import_files_have_coverage_without_a_first_call() {
    for source in [
        "",
        "function run() { return 1; }\n",
        "const remote = require('external-one');\n",
    ] {
        let mut repo = Repo::new();
        let indexed = repo.admit("src/app.js", source);
        let expected = repo.real_certificate(&indexed);
        repo.observe(&indexed);
        assert_eq!(repo.coverage("src/app.js"), vec![expected]);
    }
}

#[test]
fn broken_observation_withdraws_full_while_retaining_lkg_and_restores_after_reopen() {
    let mut repo = Repo::new();
    let good = "function run() { return 1; }\n";
    let indexed = repo.admit("src/app.js", good);
    repo.observe(&indexed);
    // Baseline control uses the real parser/linker certificate, not a marker
    // invented by this test, to expose stale-positive retention independently.
    repo.seed_real_certificate(&indexed);
    let original = repo.graph.list_all_entities().unwrap();
    let broken = repo.admit("src/app.js", "function run( {\n");
    assert!(matches!(
        broken.parse_state,
        kin_model::ParseState::Incomplete { .. }
    ));
    let result = repo.observe(&broken);
    assert!(
        !has_full(&repo.coverage("src/app.js")),
        "old full certificate survived an admitted broken observation: {:?}",
        result.outcome
    );
    assert_eq!(repo.graph.list_all_entities().unwrap(), original);
    assert!(
        matches!(result.outcome, ReconcileOutcome::PartiallyUpdated { ref modified, .. } if modified.is_empty())
    );
    let saved = repo.root.path().join("state.kindb");
    SnapshotManager::save_graph(&saved, repo.graph.as_ref()).unwrap();
    repo.graph = SnapshotManager::open_without_text_index(&saved)
        .unwrap()
        .graph();
    repo.reconciler = Reconciler::new(repo.root.path().to_owned());
    let restored = repo.admit("src/app.js", good);
    repo.observe(&restored);
    assert!(has_full(&repo.coverage("src/app.js")));
}

#[test]
fn valid_but_unrepresented_call_replaces_full_then_restores_same_identity() {
    let mut repo = Repo::new();
    let good = "def run(callbacks):\n    return 1\n";
    let initial = repo.admit("src/app.py", good);
    repo.observe(&initial);
    let full = repo.coverage("src/app.py").pop().unwrap();
    let uncertain = repo.admit(
        "src/app.py",
        "def run(callbacks):\n    return callbacks[0]()\n",
    );
    assert!(matches!(
        uncertain.parse_state,
        kin_model::ParseState::Valid
    ));
    assert!(uncertain
        .extracted_relations
        .iter()
        .any(kin_parser::is_call_extraction_incomplete_marker));
    repo.observe(&uncertain);
    let negative = repo.coverage("src/app.py");
    assert_eq!(negative.len(), 1);
    assert_eq!(negative[0].id, full.id);
    assert!(!has_full(&negative));
    assert!(negative[0].evidence.iter().any(|e| e.parser_rule.as_deref()
        == Some(kin_index::CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1)));
    let restored = repo.admit("src/app.py", good);
    repo.observe(&restored);
    assert_eq!(repo.coverage("src/app.py"), vec![full]);
    assert!(repo.observe(&restored).delta.relation_deltas.is_empty());
}

#[test]
fn verified_waiting_source_replay_refreshes_imports_without_promoting_extraction_coverage() {
    let mut repo = Repo::new();
    let caller = repo.admit(
        "caller.py",
        "from local import work\ndef run(callbacks):\n    work()\n    return callbacks[0]()\n",
    );
    repo.observe(&caller);
    let before = repo.coverage("caller.py");
    assert_eq!(before.len(), 1);
    assert!(!has_full(&before));
    let local = repo.admit("local.py", "def work():\n    return 1\n");
    let result = repo.observe(&local);
    assert!(result.delta.relation_deltas.iter().any(|d| matches!(d, RelationDelta::Added { new } if new.kind == RelationKind::Calls && new.dst.as_entity().is_some_and(|id| repo.graph.get_entity(&id).unwrap().is_some_and(|e| e.name == "work")))));
    let after = repo.coverage("caller.py");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].id, before[0].id);
    assert!(
        !has_full(&after),
        "a complete reparse retains the extraction gap"
    );
    assert_eq!(after[0].evidence[0], before[0].evidence[0]);
    assert_eq!(
        kin_index::parse_coverage_source_digest(&after[0]),
        kin_index::parse_coverage_source_digest(&before[0])
    );
    let imports = after[0]
        .evidence
        .iter()
        .find(|evidence| {
            evidence.parser_rule.as_deref() == Some(kin_index::IMPORT_RESOLUTION_COVERAGE_V1)
        })
        .unwrap();
    assert_eq!(imports.token.as_deref(), Some("1"));
    assert_eq!(imports.occurrence_count, 1);
}

#[test]
fn malformed_or_occupied_certificate_refuses_whole_plan() {
    for occupied in [false, true] {
        let mut repo = Repo::new();
        let indexed = repo.admit("src/app.js", "function run() { return 1; }\n");
        let mut held = repo.real_certificate(&indexed);
        if occupied {
            held.evidence.clear();
        } else {
            held.evidence[1].token = Some("999".into());
        }
        repo.graph
            .apply_transaction_delta(&TransactionDelta {
                relation_deltas: vec![RelationDelta::Added { new: held.clone() }],
                ..Default::default()
            })
            .unwrap();
        let result = repo.reconciler.reconcile_indexed_observation(
            &indexed,
            &repo.blobs,
            repo.graph.as_ref(),
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("parse coverage authority"));
        assert!(repo.graph.list_all_entities().unwrap().is_empty());
        assert_eq!(repo.coverage("src/app.js"), vec![held]);
    }
}

/// A store an earlier build wrote holds a one-entry certificate for every file
/// it parsed, from before the factory counted import resolution. Re-deriving
/// the file replaces it at the same identity instead of refusing the plan, so
/// an upgraded store's startup repair can complete.
#[test]
fn an_earlier_builds_certificate_is_replaced_by_the_fresh_one() {
    let mut repo = Repo::new();
    let indexed = repo.admit("src/app.js", "function run() { return 1; }\n");
    let fresh = repo.real_certificate(&indexed);
    let mut earlier = fresh.clone();
    earlier.evidence.truncate(1);
    earlier.created_in = Some(kin_model::SemanticChangeId::from_hash(Hash256::from_bytes(
        [7; 32],
    )));
    repo.graph
        .apply_transaction_delta(&TransactionDelta {
            relation_deltas: vec![RelationDelta::Added {
                new: earlier.clone(),
            }],
            ..Default::default()
        })
        .unwrap();
    let result = repo.observe(&indexed);
    assert!(
        result.delta.relation_deltas.iter().any(|delta| matches!(
            delta,
            RelationDelta::Modified { old, new } if *old == earlier && new.id == earlier.id
        )),
        "{:?}",
        result.delta.relation_deltas
    );
    let held = repo.coverage("src/app.js");
    assert_eq!(held.len(), 1);
    assert!(kin_index::is_parse_coverage_relation(
        &held[0],
        "src/app.js",
        repo.artifact("src/app.js")
    ));
    assert_eq!(
        held[0].created_in, earlier.created_in,
        "the replacement keeps the publication stamp"
    );
}

#[test]
fn stale_indexed_bytes_cannot_publish_or_withdraw_current_coverage() {
    let mut repo = Repo::new();
    let old = repo.admit("src/app.js", "function run() { return 1; }\n");
    repo.observe(&old);
    let current = repo.admit("src/app.js", "function run() { return 2; }\n");
    repo.observe(&current);
    let held = repo.coverage("src/app.js");
    let error = repo
        .reconciler
        .reconcile_indexed_observation(&old, &repo.blobs, repo.graph.as_ref())
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("indexed bytes are not the admitted file version"));
    assert_eq!(repo.coverage("src/app.js"), held);
}

#[test]
fn removal_collects_exact_certificate_and_preserves_unrelated_dependency() {
    let mut repo = Repo::new();
    let indexed = repo.admit("src/app.js", "function run() { return 1; }\n");
    repo.observe(&indexed);
    let canonical = repo.coverage("src/app.js").pop().unwrap();
    let mut unrelated = canonical.clone();
    unrelated.id = kin_model::RelationId::new();
    unrelated.origin = kin_model::RelationOrigin::Manual;
    unrelated.evidence.clear();
    repo.graph
        .apply_transaction_delta(&TransactionDelta {
            relation_deltas: vec![RelationDelta::Added {
                new: unrelated.clone(),
            }],
            ..Default::default()
        })
        .unwrap();
    let result = repo
        .reconciler
        .reconcile_file_change(
            &kin_index::FileEvent::Removed(repo.root.path().join("src/app.js")),
            &repo.blobs,
            repo.graph.as_ref(),
        )
        .unwrap();
    assert!(result
        .delta
        .relation_deltas
        .iter()
        .any(|d| matches!(d, RelationDelta::Removed { old } if old == &canonical)));
    repo.graph.apply_transaction_delta(&result.delta).unwrap();
    assert_eq!(repo.coverage("src/app.js"), vec![unrelated]);
}

#[test]
fn observed_partial_body_refresh_withdraws_full_and_keeps_call_identity() {
    let mut repo = Repo::new();
    let before = "int target(void) { return 1; }\nint caller(void) { return target(); }\nint good(void) { int value=1; return value; }\nint bad(void) { return 1; }\n";
    let indexed = repo.admit("test.c", before);
    repo.observe(&indexed);
    let original = repo.graph.list_all_entities().unwrap();
    let good = original.iter().find(|e| e.name == "good").unwrap();
    let caller = original.iter().find(|e| e.name == "caller").unwrap();
    let calls = repo
        .graph
        .get_relations(&caller.id, &[RelationKind::Calls])
        .unwrap();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].evidence.iter().any(
        |record| record.parser_rule.as_deref() == Some(kin_index::occurrence::OCCURRENCE_RULE)
    ));
    assert!(!kin_index::occurrence::proven_sites(&calls[0]).1);
    let after = "int target(void) { return 1; }\nint caller(void) {\n  return target(); }\nint good(void) { int renamed=1; return renamed; }\nint bad(void) { test_cond(1) }\n";
    let parsed = repo.admit("test.c", after);
    assert!(matches!(
        parsed.parse_state,
        kin_model::ParseState::Incomplete { .. }
    ));
    let host = repo.root.path().join("test.c");
    std::fs::write(&host, after).unwrap();
    let result = repo
        .reconciler
        .reconcile_file_change(
            &kin_index::FileEvent::Changed(host),
            &repo.blobs,
            repo.graph.as_ref(),
        )
        .unwrap();
    assert!(
        matches!(&result.outcome, ReconcileOutcome::PartiallyUpdated { modified, .. } if modified.contains(&good.id)),
        "{:?}",
        result.outcome
    );
    repo.graph.apply_transaction_delta(&result.delta).unwrap();
    assert!(!has_full(&repo.coverage("test.c")));
    assert_eq!(
        repo.graph
            .get_relations(&caller.id, &[RelationKind::Calls])
            .unwrap()
            .iter()
            .map(|r| r.id)
            .collect::<Vec<_>>(),
        calls.iter().map(|r| r.id).collect::<Vec<_>>()
    );
    let updated = repo
        .graph
        .get_relations(&caller.id, &[RelationKind::Calls])
        .unwrap();
    let (sites, withheld) = kin_index::occurrence::proven_sites(&updated[0]);
    assert!(
        !withheld,
        "source-proven partial refresh must preserve occurrence tier: {:?}",
        updated[0]
    );
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].start_line, 2, "the call moved to the next line");
}

#[test]
fn unused_local_import_counts_are_measured_from_graph_seed() {
    let mut repo = Repo::new();
    let local = repo.admit("local.py", "def work():\n    return 1\n");
    repo.observe(&local);
    repo.reconciler = Reconciler::new(repo.root.path().to_owned());
    let unused = repo.admit("app.py", "from local import work\n");
    repo.observe(&unused);
    let certificate = repo.coverage("app.py").pop().unwrap();
    let imports = certificate
        .evidence
        .iter()
        .find(|e| e.parser_rule.as_deref() == Some(kin_index::IMPORT_RESOLUTION_COVERAGE_V1))
        .unwrap();
    assert_eq!(imports.occurrence_count, 1);
    assert_eq!(imports.token.as_deref(), Some("1"));
}

#[test]
fn recreated_file_gets_coverage_for_its_new_artifact_only() {
    let mut repo = Repo::new();
    let indexed = repo.admit("app.js", "function run() { return 1; }\n");
    repo.observe(&indexed);
    let old = repo.coverage("app.js").pop().unwrap();
    let path = RepoPath::from_utf8("app.js").unwrap();
    let artifact = repo.artifact("app.js");
    let entry = repo
        .graph
        .get_tree_entry(&FilePathId::new("app.js"))
        .unwrap()
        .unwrap();
    let mut removal = repo
        .reconciler
        .reconcile_file_change(
            &kin_index::FileEvent::Removed(repo.root.path().join("app.js")),
            &repo.blobs,
            repo.graph.as_ref(),
        )
        .unwrap()
        .delta;
    removal.tree_deltas.push(TreeDelta::Removed {
        artifact_id: artifact,
        old: LocatedEntry::new(path, entry),
    });
    repo.graph.apply_transaction_delta(&removal).unwrap();
    let indexed = repo.admit("app.js", "function run() { return 2; }\n");
    repo.observe(&indexed);
    let new = repo.coverage("app.js").pop().unwrap();
    assert_ne!(new.id, old.id);
    assert_ne!(repo.artifact("app.js"), artifact);
    assert!(repo
        .graph
        .traverse(&GraphNodeId::Artifact(artifact), &[], 1)
        .unwrap()
        .relations
        .is_empty());
}
