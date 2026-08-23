// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-repo external references must exist in graph-owned truth the moment a
//! brownfield repository is admitted, with no edit and no filesystem rescan in
//! between.
//!
//! Two repositories are built as ordinary Git checkouts, admitted through the
//! real capture/plan/enrich/admit pipeline, and then handed to the spine
//! resolver exactly as the daemon hands it a captured graph. The provider side
//! supplies the entity the consumer's unresolved import names; the consumer
//! side must carry that import as a change-owned external-reference relation.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Output};

use kin_blobs::BlobStore;
use kin_git::{
    admit_semantic_git_import, capture_lossless_git_repository, plan_semantic_git_import,
};
use kin_index::{derive_historical_semantic_deltas, is_external_import_placeholder};
use kin_model::{
    ChangeStore, Entity, EntityDelta, Relation, RelationDelta, RepositoryId, SemanticChange,
};
use kin_spine::{
    collect_unresolved_imports, materialize_edges, resolve_imports, EntityEntry, SpineIndex,
};

/// One admitted repository, reduced to the entity and relation state its
/// first-parent history replays to.
struct AdmittedRepository {
    entities: Vec<Entity>,
    relations: Vec<Relation>,
}

#[test]
fn clean_brownfield_admission_binds_cross_repo_external_references() {
    let root = tempfile::tempdir().unwrap();

    let provider = admit_repository(
        &root.path().join("provider"),
        "provider",
        &[("src/lib.rs", "pub fn do_work() -> u32 {\n    7\n}\n")],
    );
    let consumer = admit_repository(
        &root.path().join("consumer"),
        "consumer",
        &[(
            "src/app.rs",
            "use provider::do_work;\n\npub fn run_task() -> u32 {\n    do_work()\n}\n",
        )],
    );

    // Both checkouts go away here, before a single assertion runs. Everything
    // below is answered from admitted graph truth alone, so the claim that no
    // query re-derives a cross-repo reference from the filesystem is what makes
    // this test pass rather than something it merely fails to exercise.
    drop(root);

    // The consumer's admitted history owns the external reference. Nothing has
    // edited the checkout, and no query has re-derived it from the filesystem.
    let external = consumer
        .relations
        .iter()
        .filter(|relation| is_external_import_placeholder(relation))
        .collect::<Vec<_>>();
    assert!(
        !external.is_empty(),
        "clean admission must bind the consumer's unresolved import as an \
         external-reference relation; admitted relations: {:?}",
        consumer
            .relations
            .iter()
            .map(|relation| (relation.kind, relation.import_source.clone()))
            .collect::<Vec<_>>()
    );
    assert!(
        external.iter().any(|relation| {
            relation.import_source.as_deref() == Some("provider")
                && relation
                    .evidence
                    .first()
                    .and_then(|evidence| evidence.token.as_deref())
                    == Some("do_work")
        }),
        "the external reference must name the import module and the real symbol"
    );

    // The spine resolver sees exactly what a daemon capture would hand it.
    let unresolved = collect_unresolved_imports(
        &consumer.entities,
        &consumer.relations,
        "consumer",
        &["provider".to_string()],
    );
    assert!(
        !unresolved.is_empty(),
        "the admitted external reference must reach the spine as an unresolved import"
    );

    let index = SpineIndex::new();
    index.register_repo(
        "provider",
        spine_entries("provider", &provider.entities),
        "",
    );
    index.register_repo(
        "consumer",
        spine_entries("consumer", &consumer.entities),
        "",
    );

    let resolutions = resolve_imports(&index, &unresolved);
    assert!(
        materialize_edges(&index, &unresolved, &resolutions) >= 1,
        "the provider repository must resolve the consumer's admitted external reference"
    );

    let edges = index.cross_repo_edges_from("consumer");
    let target = provider
        .entities
        .iter()
        .find(|entity| entity.name == "do_work")
        .expect("the provider repository defines do_work");
    assert!(
        edges
            .iter()
            .any(|edge| edge.dst_repo == "provider" && edge.dst_entity == target.id),
        "a cross-repo edge must bind the consumer call to the provider definition; edges: {edges:?}"
    );
}

/// Project admitted entities the way the daemon projects a captured graph into
/// the spine, so the fixture exercises the production entry shape.
fn spine_entries(repo_id: &str, entities: &[Entity]) -> Vec<EntityEntry> {
    entities
        .iter()
        .map(|entity| EntityEntry {
            repo_id: repo_id.to_string(),
            entity_id: entity.id,
            name: entity.name.clone(),
            kind: entity.kind,
            signature: entity.signature.clone(),
            fingerprint: entity.fingerprint.clone(),
            file_path: entity.file_origin.as_ref().map(|origin| origin.0.clone()),
            role: Some(entity.role),
        })
        .collect()
}

/// Build a Git repository from `files`, admit it exactly as `kin init` does,
/// and replay its first-parent history into entity and relation state.
fn admit_repository(dir: &Path, repository_id: &str, files: &[(&str, &str)]) -> AdmittedRepository {
    std::fs::create_dir_all(dir).unwrap();
    git_ok(dir, ["init", "--quiet", "--initial-branch", "main"]);
    git_ok(dir, ["config", "user.name", "Fixture"]);
    git_ok(dir, ["config", "user.email", "fixture@example.invalid"]);
    for (path, body) in files {
        let file = dir.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, body).unwrap();
    }
    git_ok(dir, ["add", "--all"]);
    git_ok(dir, ["commit", "--quiet", "--message", "seed"]);

    let blob_store = BlobStore::new(dir.join(".fixture-cas")).unwrap();
    let snapshot = capture_lossless_git_repository(
        dir,
        RepositoryId::new(repository_id).unwrap(),
        &blob_store,
    )
    .unwrap();
    let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
    let trees = plan
        .aliases
        .iter()
        .map(|alias| {
            (
                alias.change_id,
                plan.commit_trees
                    .get(&alias.oid)
                    .expect("every imported commit has an exact resolved tree")
                    .clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let bindings = derive_historical_semantic_deltas(&plan.changes, &trees, &blob_store)
        .unwrap()
        .into_iter()
        .map(|delta| {
            kin_git::HistoricalSemanticBinding::owned(
                delta.change_id,
                delta.entity_deltas,
                delta.relation_deltas,
            )
        })
        .collect::<Vec<_>>();
    let admitted = admit_semantic_git_import(
        &plan
            .with_historical_semantics(&blob_store, bindings)
            .unwrap(),
        &blob_store,
    )
    .unwrap();
    admitted.validate(&blob_store).unwrap();

    // Admitted history must still replay. An external reference that made
    // `resolve_graph_at` fail would trade a cross-repo answer for a broken
    // history surface.
    let graph = kin_db::InMemoryGraph::new();
    for change in &admitted.changes {
        graph.create_change(change).unwrap();
    }
    let head = admitted
        .changes
        .iter()
        .map(|change| change.id)
        .find(|candidate| {
            !admitted
                .changes
                .iter()
                .any(|change| change.parents.contains(candidate))
        })
        .expect("history must have a head");
    graph
        .resolve_graph_at(&head)
        .expect("admitted history must replay");

    replay_first_parent(&admitted.changes)
}

/// Apply every change's deltas in parent-first order, the way durable authority
/// replay derives the state a workspace reports.
///
/// The order is derived rather than approximated by parent count, which is an
/// all-ties no-op on a linear history and would silently produce wrong state the
/// first time this is pointed at a repository with more than one commit. A
/// parent outside this change set is treated as already applied, because a
/// caller may replay a subset.
fn replay_first_parent(changes: &[SemanticChange]) -> AdmittedRepository {
    let known: BTreeSet<_> = changes.iter().map(|change| change.id).collect();
    let mut applied = BTreeSet::new();
    let mut ordered = Vec::with_capacity(changes.len());
    while ordered.len() < changes.len() {
        let next = changes
            .iter()
            .find(|change| {
                !applied.contains(&change.id)
                    && change
                        .parents
                        .iter()
                        .all(|parent| !known.contains(parent) || applied.contains(parent))
            })
            .expect("the admitted change set must be a DAG rooted in this history");
        applied.insert(next.id);
        ordered.push(next);
    }

    let mut entities = BTreeMap::new();
    let mut relations = BTreeMap::new();
    for change in ordered {
        for delta in &change.entity_deltas {
            match delta {
                EntityDelta::Added { new } | EntityDelta::Modified { new, .. } => {
                    entities.insert(new.id, new.clone());
                }
                EntityDelta::Removed { old } => {
                    entities.remove(&old.id);
                }
            }
        }
        for delta in &change.relation_deltas {
            match delta {
                RelationDelta::Added { new } | RelationDelta::Modified { new, .. } => {
                    relations.insert(new.id, new.clone());
                }
                RelationDelta::Removed { old } => {
                    relations.remove(&old.id);
                }
            }
        }
    }

    AdmittedRepository {
        entities: entities.into_values().collect(),
        relations: relations.into_values().collect(),
    }
}

fn git_ok<I, S>(repo: &Path, args: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = git_output(repo, args);
    assert!(
        output.status.success(),
        "git failed ({}):\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_output<I, S>(repo: &Path, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new("git")
        // This fixture commits a repository and then admits it in the same
        // test. Git otherwise ends a commit by detaching
        // `git maintenance run --auto`, which outlives the commit and can hold
        // `objects/pack/multi-pack-index.lock` while the admission preflight
        // reads the object store and refuses on any lock it finds there.
        .args(["-c", "maintenance.auto=false", "-c", "gc.auto=0"])
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .env("HOME", repo)
        .output()
        .unwrap()
}
