// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Role, read back out of the graph rather than off the in-memory parse.
//!
//! FIR-1940 item (b). Two gaps put the wrong role on real entities, and neither
//! was visible to the unit tests beside the classifier, because those assert on
//! `classify_file_role` and the defects live in what the pipeline does with its
//! answer.
//!
//! Gap 1: the test-filename rule listed eight literal extensions, so every
//! colocated framework test read as production source.
//!
//! Gap 2: the incremental path assigned the path role and skipped the in-file
//! test promotion the full-parse path applies, so a `#[test] fn` in a product
//! file was Test after a full parse and Source after an incremental reconcile.
//! The same code, two roles, decided by which path last touched the file.
//!
//! Every assertion below reads the role back AFTER `apply_to_graph`, because a
//! role that is correct in the `IndexedFile` and lost on the way to the store is
//! the same defect one layer down, and an in-memory assertion cannot see it.

use kin_blobs::BlobStore;
use kin_db::InMemoryGraph;
use kin_index::{apply_to_graph, IndexPipeline};
use kin_model::graph::EntityStore;
use kin_model::{
    ArtifactId, EntityFilter, EntityRole, FilePathId, Hash256, LocatedEntry, RepoPath,
    TransactionDelta, TreeDelta, TreeEntry,
};

/// Admit `path` into the repository tree.
///
/// `apply_to_graph` refuses semantic enrichment for a path repository authority
/// does not carry, which is the graph doing its job. The admission is keyed on
/// the file id the indexer actually produced rather than on the string this test
/// passed in, because the incremental path indexes a real file and carries the
/// path it read.
fn admit(graph: &InMemoryGraph, path: &str) {
    let repo_path = RepoPath::from_utf8(path.to_string()).expect("a usable repository path");
    if graph.artifact_id_at_path(&repo_path).is_some() {
        return;
    }
    graph
        .apply_transaction_delta(&TransactionDelta {
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: vec![TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(
                    repo_path,
                    TreeEntry::blob(Hash256::from_bytes([7; 32]), false),
                ),
            }],
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        })
        .expect("admission goes through the repository tree transaction");
}

/// Every role the graph holds for `path`, after the file has been applied.
fn roles_in_graph(graph: &InMemoryGraph, path: &str) -> Vec<(String, EntityRole)> {
    let mut rows: Vec<(String, EntityRole)> = graph
        .query_entities(&EntityFilter::default())
        .expect("the store answers")
        .into_iter()
        .filter(|entity| {
            entity
                .file_origin
                .as_ref()
                .is_some_and(|origin| origin.0 == path)
        })
        .map(|entity| (entity.name.clone(), entity.role))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows
}

/// Index `source` at `path` through the FULL-PARSE path and apply it.
fn ingest_batch(graph: &InMemoryGraph, path: &str, source: &str) {
    let pipeline = IndexPipeline::new();
    let file_id = FilePathId::new(path.to_string());
    let indexed = pipeline
        .index_file_content_with_tests(
            &file_id,
            source.as_bytes(),
            kin_blobs::digest(source.as_bytes()),
        )
        .expect("indexing succeeds")
        .indexed_file;
    admit(graph, &indexed.file_id.0);
    apply_to_graph(graph, &indexed).expect("apply succeeds");
}

/// Index `source` at `path` through the INCREMENTAL path and apply it.
///
/// This is the path gap 2 lived on, and it needs a real file and a blob store,
/// which is why it is not simply the call above with a flag.
fn ingest_incremental(
    graph: &InMemoryGraph,
    root: &std::path::Path,
    rel: &str,
    source: &str,
) -> String {
    let pipeline = IndexPipeline::new();
    let blob_store = BlobStore::new(root.join("cas")).expect("blob store");
    // A RELATIVE path, because the file id is keyed on what the indexer read and
    // repository authority refuses an absolute one. `root` is a tempdir created
    // under the current directory, so its final component plus `rel` is a real
    // path from here.
    let file = std::path::PathBuf::from(root.file_name().expect("a tempdir name")).join(rel);
    std::fs::create_dir_all(file.parent().expect("a parent")).expect("mkdir");
    std::fs::write(&file, source).expect("write");
    let (indexed, _tree) = pipeline
        .index_file_with_hint(&file, &blob_store, None, None)
        .expect("indexing succeeds");
    admit(graph, &indexed.file_id.0);
    apply_to_graph(graph, &indexed).expect("apply succeeds");
    indexed.file_id.0.clone()
}

const PY_SOURCE: &str = "def add(a, b):\n    return a + b\n";
const PY_TEST: &str = "def test_add():\n    assert True\n";
const TS_TEST: &str = "export function renders() { return 1; }\n";
const RS_MIXED: &str = r#"
pub fn parse_note(text: &str) -> usize {
    text.len()
}

#[test]
fn parse_note_counts_bytes() {
    assert_eq!(parse_note("ab"), 2);
}
"#;

/// A path-classified test file, a product file, and the colocated framework test
/// that gap 1 misread. All three read back from the graph.
#[test]
fn role_reaches_the_graph_for_every_path_convention() {
    let graph = InMemoryGraph::new();
    ingest_batch(&graph, "src/calc.py", PY_SOURCE);
    ingest_batch(&graph, "tests/test_calc.py", PY_TEST);
    // Gap 1: colocated, dot-delimited, and on an extension the old eight-literal
    // rule never listed.
    ingest_batch(&graph, "src/Widget.test.tsx", TS_TEST);

    let product = roles_in_graph(&graph, "src/calc.py");
    assert!(
        !product.is_empty() && product.iter().all(|(_, role)| *role == EntityRole::Source),
        "product code is Source: {product:?}"
    );

    let by_path = roles_in_graph(&graph, "tests/test_calc.py");
    assert!(
        !by_path.is_empty() && by_path.iter().all(|(_, role)| *role == EntityRole::Test),
        "a test directory and a test_ prefix is Test: {by_path:?}"
    );

    let colocated = roles_in_graph(&graph, "src/Widget.test.tsx");
    assert!(
        !colocated.is_empty() && colocated.iter().all(|(_, role)| *role == EntityRole::Test),
        "a colocated framework test is Test, which gap 1 got wrong: {colocated:?}"
    );
}

/// Gap 2, and the reason this file exists rather than another classifier unit
/// test: the role of the SAME source must not depend on which pipeline path
/// touched it. A batch-only fix passes the first assertion and leaves the
/// second, which is the shape kin#1123 caught in a different consumer.
#[test]
fn an_in_file_test_keeps_its_role_on_both_pipeline_paths() {
    let batch_graph = InMemoryGraph::new();
    ingest_batch(&batch_graph, "src/lib.rs", RS_MIXED);
    let batch = roles_in_graph(&batch_graph, "src/lib.rs");

    // Rooted under the current directory on purpose. The incremental entry
    // takes a real path and keys the file id on what it read, and repository
    // authority refuses an absolute path, so a relative root is what lets this
    // arm reach `apply_to_graph` at all. It is cleaned up when `root` drops.
    let root = tempfile::tempdir_in(".").expect("tempdir under the crate root");
    let incr_graph = InMemoryGraph::new();
    let incr_path = ingest_incremental(&incr_graph, root.path(), "src/lib.rs", RS_MIXED);
    let incremental = roles_in_graph(&incr_graph, &incr_path);

    let role_of = |rows: &[(String, EntityRole)], name: &str| -> Option<EntityRole> {
        rows.iter()
            .find(|(entity, _)| entity == name)
            .map(|(_, role)| *role)
    };

    assert_eq!(
        role_of(&batch, "parse_note_counts_bytes"),
        Some(EntityRole::Test),
        "the full-parse path promotes a #[test] fn in a product file: {batch:?}"
    );
    assert_eq!(
        role_of(&incremental, "parse_note_counts_bytes"),
        Some(EntityRole::Test),
        "and so must the incremental path, or role is decided by which path ran \
         last: {incremental:?}"
    );

    // The control that stops the promotion becoming "call everything in the file
    // a test". The product function beside it stays Source on both paths.
    assert_eq!(
        role_of(&batch, "parse_note"),
        Some(EntityRole::Source),
        "{batch:?}"
    );
    assert_eq!(
        role_of(&incremental, "parse_note"),
        Some(EntityRole::Source),
        "{incremental:?}"
    );
}
