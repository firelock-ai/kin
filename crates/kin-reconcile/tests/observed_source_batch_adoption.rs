// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Adoption must cover retirement staged before the complete-source batch.
//! All source input comes from an admitted tree and CAS; the serving graph and
//! reconciler remain unchanged until the whole checked transition is applied.

use std::sync::{Arc, Mutex};

use kin_blobs::BlobStore;
use kin_db::{GraphSnapshot, InMemoryGraph};
use kin_model::{
    ArtifactId, Entity, EntityDelta, EntityKind, EntityStore, ExternalReferenceDelta, FilePathId,
    GraphNodeId, Hash256, IntentScope, LocatedEntry, RelationDelta, RepoPath, TransactionDelta,
    TreeDelta, TreeEntry,
};
use kin_reconcile::{CollisionCheck, PreparedAdmittedSourceBatch, ReconcileError, Reconciler};

struct Traffic {
    blocked: Option<IntentScope>,
    seen: Arc<Mutex<Vec<IntentScope>>>,
}

impl kin_reconcile::TrafficChecker for Traffic {
    fn check_collisions(
        &self,
        scope: &IntentScope,
        _: Option<&kin_model::SessionId>,
    ) -> Result<CollisionCheck, String> {
        self.seen.lock().unwrap().push(scope.clone());
        Ok(if self.blocked.as_ref() == Some(scope) {
            CollisionCheck::Blocked {
                conflict: kin_model::IntentConflict::HardCollision,
                blocking_intents: vec![],
            }
        } else {
            CollisionCheck::Clear
        })
    }
}

fn clear_traffic(live: &mut Reconciler) {
    live.set_traffic_checker(Box::new(Traffic {
        blocked: None,
        seen: Default::default(),
    }));
}

struct Repo {
    _root: tempfile::TempDir,
    blobs: BlobStore,
    graph: InMemoryGraph,
    live: Reconciler,
}

impl Repo {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(root.path().join("blobs")).unwrap();
        let graph = InMemoryGraph::new();
        let files = [
            ("old.py", "def work(value):\n    return value + 1\n"),
            ("kept.py", "def keep(value):\n    return value * 2\n"),
        ];
        for (file, content) in files {
            let hash = blobs.write(content.as_bytes()).unwrap();
            graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![TreeDelta::Added {
                        artifact_id: ArtifactId::new(),
                        new: LocatedEntry::new(
                            RepoPath::from_utf8(file).unwrap(),
                            TreeEntry::blob(Hash256::from_bytes(hash.0), false),
                        ),
                    }],
                    ..Default::default()
                })
                .unwrap();
        }
        let selected: Vec<_> = files
            .iter()
            .map(|(file, _)| FilePathId::new(*file))
            .collect();
        let prepared =
            Reconciler::prepare_admitted_source_batch(graph.to_snapshot(), &selected, &blobs, &[])
                .unwrap();
        let delta = transition(&graph.to_snapshot(), prepared.snapshot());
        assert!(delta.tree_deltas.is_empty());
        let mut live = Reconciler::new(root.path().to_path_buf());
        clear_traffic(&mut live);
        let adoption = live
            .preflight_admitted_source_batch(&prepared, &graph, &delta, &blobs)
            .unwrap();
        graph.apply_transaction_delta(&delta).unwrap();
        live.adopt_admitted_source_batch(adoption);
        let repo = Self {
            _root: root,
            blobs,
            graph,
            live,
        };
        assert!(repo.live.lkg().get(&repo.work().id).is_some());
        assert!(repo.live.cross_file_linker().knows_file("old.py"));
        assert!(repo
            .live
            .projection()
            .get_layout(&FilePathId::new("old.py"))
            .is_some());
        repo
    }

    fn work(&self) -> Entity {
        let entities: Vec<_> = self
            .graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .filter(|entity| entity.kind == EntityKind::Function && entity.name == "work")
            .collect();
        assert_eq!(entities.len(), 1);
        entities.into_iter().next().unwrap()
    }

    fn prepare(&self, staged: &InMemoryGraph, files: &[&str]) -> PreparedAdmittedSourceBatch {
        let observed = self.graph.to_snapshot();
        let predecessor = kin_model::graph::ResolvedGraphState {
            entities: observed.entities,
            relations: observed.relations,
            external_references: observed.external_references,
            tree: observed.resolved_tree,
            ..Default::default()
        };
        Reconciler::prepare_admitted_source_batch(
            staged.to_snapshot(),
            &files
                .iter()
                .map(|file| FilePathId::new(*file))
                .collect::<Vec<_>>(),
            &self.blobs,
            &[predecessor],
        )
        .unwrap()
    }

    /// No surviving source calls the departing file in this fixture. Remove
    /// its exact declarations and incident rows atomically with its artifact.
    fn stage_deletion(&self) -> InMemoryGraph {
        let observed = self.graph.to_snapshot();
        let path = RepoPath::from_utf8("old.py").unwrap();
        let artifact = observed.resolved_tree.artifact_at_path(&path).unwrap();
        let departing: std::collections::HashSet<_> = observed
            .entities
            .values()
            .filter(|entity| entity.file_origin.as_ref() == Some(&FilePathId::new("old.py")))
            .map(|entity| entity.id)
            .collect();
        assert!(!departing.is_empty());
        let touches = |node: GraphNodeId| {
            node == GraphNodeId::Artifact(artifact.artifact_id)
                || node.as_entity().is_some_and(|id| departing.contains(&id))
        };
        let delta = TransactionDelta {
            tree_deltas: vec![TreeDelta::Removed {
                artifact_id: artifact.artifact_id,
                old: LocatedEntry::new(path, artifact.entry.clone()),
            }],
            entity_deltas: observed
                .entities
                .values()
                .filter(|entity| departing.contains(&entity.id))
                .map(|old| EntityDelta::Removed { old: old.clone() })
                .collect(),
            relation_deltas: observed
                .relations
                .values()
                .filter(|row| touches(row.src) || touches(row.dst))
                .map(|old| RelationDelta::Removed { old: old.clone() })
                .collect(),
            ..Default::default()
        };
        let staged = InMemoryGraph::from_snapshot(observed).unwrap();
        staged.apply_transaction_delta(&delta).unwrap();
        staged
    }
}

fn transition(before: &GraphSnapshot, after: &GraphSnapshot) -> TransactionDelta {
    let mut delta = TransactionDelta::default();
    for (id, old) in &before.entities {
        match after.entities.get(id) {
            None => delta
                .entity_deltas
                .push(EntityDelta::Removed { old: old.clone() }),
            Some(new) if new != old => delta.entity_deltas.push(EntityDelta::Modified {
                old: old.clone(),
                new: new.clone(),
            }),
            _ => {}
        }
    }
    for (id, new) in &after.entities {
        if !before.entities.contains_key(id) {
            delta
                .entity_deltas
                .push(EntityDelta::Added { new: new.clone() });
        }
    }
    for (id, old) in &before.relations {
        match after.relations.get(id) {
            None => delta
                .relation_deltas
                .push(RelationDelta::Removed { old: old.clone() }),
            Some(new) if new != old => delta.relation_deltas.push(RelationDelta::Modified {
                old: old.clone(),
                new: new.clone(),
            }),
            _ => {}
        }
    }
    for (id, new) in &after.relations {
        if !before.relations.contains_key(id) {
            delta
                .relation_deltas
                .push(RelationDelta::Added { new: new.clone() });
        }
    }
    for old in before.resolved_tree.artifacts_by_path() {
        let old_entry = LocatedEntry::new(old.path.clone(), old.entry.clone());
        match after.resolved_tree.get(&old.artifact_id) {
            None => delta.tree_deltas.push(TreeDelta::Removed {
                artifact_id: old.artifact_id,
                old: old_entry,
            }),
            Some(new) if new != old => delta.tree_deltas.push(TreeDelta::Updated {
                artifact_id: old.artifact_id,
                old: old_entry,
                new: LocatedEntry::new(new.path.clone(), new.entry.clone()),
            }),
            _ => {}
        }
    }
    for new in after.resolved_tree.artifacts_by_path() {
        if before.resolved_tree.get(&new.artifact_id).is_none() {
            delta.tree_deltas.push(TreeDelta::Added {
                artifact_id: new.artifact_id,
                new: LocatedEntry::new(new.path.clone(), new.entry.clone()),
            });
        }
    }
    for (id, old) in &before.external_references {
        match after.external_references.get(id) {
            None => delta
                .external_reference_deltas
                .push(ExternalReferenceDelta::Removed { old: old.clone() }),
            Some(new) => assert_eq!(old, new, "external identity remains immutable"),
        }
    }
    for (id, new) in &after.external_references {
        if !before.external_references.contains_key(id) {
            delta
                .external_reference_deltas
                .push(ExternalReferenceDelta::Added { new: new.clone() });
        }
    }
    delta
}

fn assert_graph_equal(actual: &GraphSnapshot, expected: &GraphSnapshot) {
    assert_eq!(actual.entities, expected.entities);
    assert_eq!(actual.relations, expected.relations);
    assert_eq!(actual.resolved_tree, expected.resolved_tree);
    assert_eq!(actual.external_references, expected.external_references);
}

fn cache_state(repo: &Repo) -> serde_json::Value {
    let mut entities = repo.graph.list_all_entities().unwrap();
    entities.sort_by_key(|entity| entity.id);
    let mut files = repo.live.projection().file_ids();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    serde_json::json!({
        "lkg_count": repo.live.lkg().len(),
        "lkg": entities.iter().map(|entity| {
            (entity.id, repo.live.lkg().get(&entity.id).map(|entry| &entry.fingerprint))
        }).collect::<Vec<_>>(),
        "projections": files.iter().map(|file| {
            (file, repo.live.projection().get_layout(file), repo.live.projection().get_content(file))
        }).collect::<Vec<_>>(),
        "pending": repo.live.cross_file_linker().pending_file_count(),
        "old_known": repo.live.cross_file_linker().knows_file("old.py"),
        "new_known": repo.live.cross_file_linker().knows_file("new.py"),
        "kept_known": repo.live.cross_file_linker().knows_file("kept.py"),
    })
}

#[test]
fn observed_zero_source_adoption_removes_pre_staged_deleted_lkg() {
    let mut repo = Repo::new();
    let removed = repo.work();
    let observed = repo.graph.to_snapshot();
    let before_cache = cache_state(&repo);
    let staged = repo.stage_deletion();
    let prepared = repo.prepare(&staged, &[]);
    assert!(
        prepared.sources().is_empty(),
        "exercise the zero-source path"
    );
    let batch = transition(&staged.to_snapshot(), prepared.snapshot());
    assert_eq!(
        batch,
        TransactionDelta::default(),
        "all retirement preceded the batch"
    );
    let whole = transition(&observed, prepared.snapshot());
    let adoption = repo
        .live
        .preflight_admitted_source_batch_from_observation(
            &prepared,
            &staged,
            &batch,
            &observed,
            &whole,
            &repo.blobs,
        )
        .unwrap();
    assert_eq!(cache_state(&repo), before_cache, "preflight cannot adopt");
    assert_graph_equal(&repo.graph.to_snapshot(), &observed);
    repo.graph.apply_transaction_delta(&whole).unwrap();
    repo.live.adopt_admitted_source_batch(adoption);
    assert!(repo.live.lkg().get(&removed.id).is_none());
    assert!(!repo.live.cross_file_linker().knows_file("old.py"));
    assert!(repo
        .live
        .projection()
        .get_layout(&FilePathId::new("old.py"))
        .is_none());
    assert!(repo
        .live
        .projection()
        .get_content(&FilePathId::new("old.py"))
        .is_none());
    assert!(repo.live.cross_file_linker().knows_file("kept.py"));
    assert!(repo
        .live
        .projection()
        .get_content(&FilePathId::new("kept.py"))
        .is_some());
    assert_graph_equal(&repo.graph.to_snapshot(), prepared.snapshot());
}

#[test]
fn observed_single_source_move_adopts_new_location_and_fingerprint() {
    let mut repo = Repo::new();
    let old = repo.work();
    let observed = repo.graph.to_snapshot();
    let before_cache = cache_state(&repo);
    let from = FilePathId::new("old.py");
    let to = FilePathId::new("new.py");
    let artifact = observed
        .resolved_tree
        .artifact_at_path(&RepoPath::from_utf8("old.py").unwrap())
        .unwrap();
    let content = b"def work(value):\n    return value + 99\n";
    let digest = repo.blobs.write(content).unwrap();
    let moved_entities = observed
        .entities
        .values()
        .filter(|entity| entity.file_origin.as_ref() == Some(&from))
        .map(|old| {
            let mut new = old.clone();
            new.file_origin = Some(to.clone());
            if let Some(span) = &mut new.span {
                span.file = to.clone();
            }
            EntityDelta::Modified {
                old: old.clone(),
                new,
            }
        })
        .collect();
    let coverage = observed
        .relations
        .values()
        .filter(|row| kin_index::is_parse_coverage_relation(row, "old.py", artifact.artifact_id))
        .map(|old| RelationDelta::Removed { old: old.clone() })
        .collect();
    let staged = InMemoryGraph::from_snapshot(observed.clone()).unwrap();
    staged
        .apply_transaction_delta(&TransactionDelta {
            tree_deltas: vec![TreeDelta::Updated {
                artifact_id: artifact.artifact_id,
                old: LocatedEntry::new(artifact.path.clone(), artifact.entry.clone()),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("new.py").unwrap(),
                    TreeEntry::blob(Hash256::from_bytes(digest.0), false),
                ),
            }],
            entity_deltas: moved_entities,
            relation_deltas: coverage,
            ..Default::default()
        })
        .unwrap();
    let prepared = repo.prepare(&staged, &["new.py"]);
    assert_eq!(prepared.sources().len(), 1);
    let expected = prepared
        .snapshot()
        .entities
        .get(&old.id)
        .expect("move keeps entity identity");
    assert_ne!(
        old.fingerprint, expected.fingerprint,
        "body edit makes LKG refresh observable"
    );
    assert_eq!(expected.file_origin, Some(to.clone()));
    assert_eq!(expected.span.as_ref().unwrap().file, to);
    let batch = transition(&staged.to_snapshot(), prepared.snapshot());
    assert!(batch.tree_deltas.is_empty());
    let whole = transition(&observed, prepared.snapshot());
    let adoption = repo
        .live
        .preflight_admitted_source_batch_from_observation(
            &prepared,
            &staged,
            &batch,
            &observed,
            &whole,
            &repo.blobs,
        )
        .unwrap();
    assert_eq!(cache_state(&repo), before_cache);
    repo.graph.apply_transaction_delta(&whole).unwrap();
    repo.live.adopt_admitted_source_batch(adoption);
    assert_eq!(
        repo.live.lkg().get(&old.id).unwrap().fingerprint,
        expected.fingerprint
    );
    assert!(!repo.live.cross_file_linker().knows_file("old.py"));
    assert_eq!(
        repo.live
            .cross_file_linker()
            .path_of_artifact(&artifact.artifact_id)
            .as_deref(),
        Some("new.py")
    );
    assert!(repo.live.projection().get_layout(&from).is_none());
    assert_eq!(
        repo.live.projection().get_content(&to),
        Some(content.as_slice())
    );
    assert_graph_equal(&repo.graph.to_snapshot(), prepared.snapshot());
}

#[test]
fn observed_retirement_checks_deleted_entity_and_file_collisions_without_adopting() {
    for entity_scope in [true, false] {
        let mut repo = Repo::new();
        let observed = repo.graph.to_snapshot();
        let before_cache = cache_state(&repo);
        let staged = repo.stage_deletion();
        let prepared = repo.prepare(&staged, &[]);
        let batch = transition(&staged.to_snapshot(), prepared.snapshot());
        let whole = transition(&observed, prepared.snapshot());
        let blocked = if entity_scope {
            IntentScope::Entity(repo.work().id)
        } else {
            IntentScope::Artifact(FilePathId::new("old.py"))
        };
        let seen = Arc::new(Mutex::new(Vec::new()));
        repo.live.set_traffic_checker(Box::new(Traffic {
            blocked: Some(blocked.clone()),
            seen: seen.clone(),
        }));
        let result = repo.live.preflight_admitted_source_batch_from_observation(
            &prepared,
            &staged,
            &batch,
            &observed,
            &whole,
            &repo.blobs,
        );
        assert!(
            matches!(result, Err(ReconcileError::CollisionBlocked { .. })),
            "{blocked:?}"
        );
        assert!(seen.lock().unwrap().contains(&blocked));
        assert_eq!(cache_state(&repo), before_cache);
        assert_graph_equal(&repo.graph.to_snapshot(), &observed);
    }
}

#[test]
fn observed_adoption_refuses_mismatched_or_forged_whole_delta_and_allows_exact_retry() {
    for forged_old_payload in [false, true] {
        let mut repo = Repo::new();
        let observed = repo.graph.to_snapshot();
        let before_cache = cache_state(&repo);
        let staged = repo.stage_deletion();
        let prepared = repo.prepare(&staged, &[]);
        let staged_before = staged.to_snapshot();
        let batch = transition(&staged_before, prepared.snapshot());
        let whole = transition(&observed, prepared.snapshot());
        let mut wrong = if forged_old_payload {
            whole.clone()
        } else {
            TransactionDelta::default()
        };
        if forged_old_payload {
            let EntityDelta::Removed { old } = &mut wrong.entity_deltas[0] else {
                panic!("deletion fixture");
            };
            old.signature.push_str(" forged predecessor");
        }
        assert!(
            repo.live
                .preflight_admitted_source_batch_from_observation(
                    &prepared,
                    &staged,
                    &batch,
                    &observed,
                    &wrong,
                    &repo.blobs,
                )
                .is_err(),
            "forged_old_payload={forged_old_payload}"
        );
        assert_eq!(cache_state(&repo), before_cache);
        assert_graph_equal(&repo.graph.to_snapshot(), &observed);
        assert_graph_equal(&staged.to_snapshot(), &staged_before);
        let adoption = repo
            .live
            .preflight_admitted_source_batch_from_observation(
                &prepared,
                &staged,
                &batch,
                &observed,
                &whole,
                &repo.blobs,
            )
            .unwrap();
        repo.graph.apply_transaction_delta(&whole).unwrap();
        repo.live.adopt_admitted_source_batch(adoption);
        assert_graph_equal(&repo.graph.to_snapshot(), prepared.snapshot());
        assert!(!repo.live.cross_file_linker().knows_file("old.py"));
    }
}
