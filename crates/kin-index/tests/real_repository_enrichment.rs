// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Whole-history enrichment proof against a real Git repository.
//!
//! Ignored by default. It needs a repository this tree cannot vendor, and cost
//! grows with history length times tree size, so it is minutes of work on a
//! repository of any real size. Point `KIN_REAL_REPOSITORY` at a non-shallow
//! clone and run it explicitly:
//!
//! ```sh
//! git clone https://github.com/sharkdp/fd /tmp/fd
//! KIN_REAL_REPOSITORY=/tmp/fd cargo test --release -p kin-index \
//!     --test real_repository_enrichment -- --ignored --nocapture
//! ```
//!
//! Shallow clones are rejected at capture, so history length cannot be varied
//! with `--depth`; truncate a full clone instead.

use std::collections::BTreeMap;
use std::path::Path;

use kin_blobs::BlobStore;
use kin_git::{
    admit_semantic_git_import, capture_lossless_git_repository, plan_semantic_git_import,
};
use kin_index::derive_historical_semantic_deltas;
use kin_model::{ChangeStore, RepositoryId};

#[test]
#[ignore]
fn a_real_repository_enriches_into_replayable_history() {
    let repository = std::env::var("KIN_REAL_REPOSITORY")
        .expect("set KIN_REAL_REPOSITORY to a non-shallow Git clone");
    let root = tempfile::tempdir().unwrap();
    let blob_store = BlobStore::new(root.path().join("cas")).unwrap();

    let snapshot = capture_lossless_git_repository(
        Path::new(&repository),
        RepositoryId::new("real-repository-enrichment").unwrap(),
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

    let deltas = derive_historical_semantic_deltas(&plan.changes, &trees, &blob_store).unwrap();
    let bindings = deltas
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

    // The graph must never publish a change its own replay rejects, so every
    // head is resolved rather than only the tip of the default branch.
    let graph = kin_db::InMemoryGraph::new();
    for change in &admitted.changes {
        graph.create_change(change).unwrap();
    }
    let heads = admitted
        .changes
        .iter()
        .map(|change| change.id)
        .filter(|candidate| {
            !admitted
                .changes
                .iter()
                .any(|change| change.parents.contains(candidate))
        })
        .collect::<Vec<_>>();
    assert!(!heads.is_empty(), "history must have at least one head");
    for head in &heads {
        let resolved = graph.resolve_graph_at(head).unwrap_or_else(|error| {
            panic!("admitted history must replay at {head}: {error}");
        });
        println!(
            "head {head}: {} entities, {} relations",
            resolved.entities.len(),
            resolved.relations.len()
        );
    }
    println!(
        "{} changes, {} heads enriched from {repository}",
        admitted.changes.len(),
        heads.len()
    );
}
