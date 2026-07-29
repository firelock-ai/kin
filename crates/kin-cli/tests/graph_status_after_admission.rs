// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Reporting truth on a freshly admitted repository-v6 repository.
//!
//! Every case here admits a real Git repository through the exact admission
//! boundary and then reads the same workspace-materialized query graph the
//! daemon serves, so the verdicts under test are the verdicts a user gets.

// Exact Git admission is unix-only, so the whole binary is scoped to it.
#![cfg(unix)]

use std::fs;
use std::path::Path;

use kin_cli::commands::graph::{execute_graph_command, GraphCommandRequest};
use kin_cli::commands::status::{self, SemanticEnrichmentPresence};
use kin_model::{
    ArtifactKind, EntityStore, FilePathId, Hash256, OpaqueArtifact, StructuredArtifact,
};
use tempfile::tempdir;

mod common;

use common::Command;

fn run_git(path: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .current_dir(path)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A small repository whose tree mixes an entity source, a structured
/// artifact, and opaque bytes, so artifact coverage spans every facet class.
fn seed_repository(repo: &Path) {
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    run_git(repo, &["init", "--initial-branch=main"]);
    run_git(repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(repo, &["config", "user.name", "Kin"]);
    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn helper() -> u32 {\n    7\n}\n\npub fn caller() -> u32 {\n    helper() + 1\n}\n",
    )
    .expect("write entity source");
    fs::write(
        repo.join("compose.yaml"),
        b"services:\n  api:\n    build: .\n",
    )
    .expect("write structured artifact");
    fs::write(repo.join("payload.bin"), [0_u8, 255, 17, 0, 128, 42]).expect("write opaque bytes");
    run_git(repo, &["add", "--all"]);
    run_git(repo, &["commit", "-m", "exact mixed tree"]);
}

struct AdmittedRepository {
    layout: kin_core::KinLayout,
    binding: kin_core::LocalRepositoryAuthorityBinding,
}

fn admit(repo: &Path) -> AdmittedRepository {
    seed_repository(repo);
    let result = kin_core::init_from_git(repo).expect("admit exact Git repository authority");
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&result.layout)
        .expect("bind published repository authority");
    AdmittedRepository {
        layout: result.layout,
        binding,
    }
}

/// The exact query graph the daemon serves: the workspace-materialized
/// snapshot, not the raw authority snapshot.
fn workspace_query_graph(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
) -> kin_db::InMemoryGraph {
    let manager = binding.open_manager().expect("open authority manager");
    let lease = manager.read_authority();
    let snapshot = lease
        .workspace_graph_snapshot(&binding.workspace_id())
        .expect("materialize workspace graph snapshot")
        .expect("authority carries the manifest workspace");
    kin_db::InMemoryGraph::from_snapshot(snapshot).expect("load workspace query graph")
}

fn graph_status(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &kin_db::InMemoryGraph,
) -> kin_cli::commands::graph::GraphCommandResponse {
    execute_graph_command(binding, graph, &GraphCommandRequest::Status).expect("run graph status")
}

#[test]
fn graph_status_passes_on_a_healthy_freshly_admitted_repository() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    fs::create_dir_all(&repo).expect("create repo");
    let admitted = admit(&repo);
    let graph = workspace_query_graph(&admitted.binding);

    assert!(
        graph.list_all_entities().expect("list entities").len() >= 2,
        "admission derives the entity layer for supported sources"
    );
    assert_eq!(
        graph
            .list_structured_artifacts()
            .expect("list structured artifacts")
            .len()
            + graph
                .list_opaque_artifacts()
                .expect("list opaque artifacts")
                .len()
            + graph.list_file_layouts().expect("list layouts").len()
            + graph
                .list_shallow_files()
                .expect("list shallow files")
                .len(),
        0,
        "exact admission does not build the query-facing artifact facet layer"
    );

    let response = graph_status(&admitted.binding, &graph);

    assert!(
        response.error.is_none(),
        "healthy fresh admission must not fail graph status: {:?}\n{}",
        response.error,
        response.lines.join("\n")
    );
    assert!(
        response
            .lines
            .iter()
            .any(|line| line.contains("no query-facing enrichment facet")),
        "pending enrichment is still reported, as a note: {}",
        response.lines.join("\n")
    );
}

#[test]
fn graph_status_fails_on_a_facet_that_disagrees_with_exact_tree_truth() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    fs::create_dir_all(&repo).expect("create repo");
    let admitted = admit(&repo);
    let graph = workspace_query_graph(&admitted.binding);

    graph
        .upsert_opaque_artifact(&OpaqueArtifact {
            file_id: FilePathId::new("payload.bin"),
            content_hash: Hash256::from_bytes([0x5a; 32]),
            mime_type: Some("application/octet-stream".to_string()),
            text_preview: None,
        })
        .expect("record a facet whose content identity is wrong");
    graph
        .upsert_structured_artifact(&StructuredArtifact {
            file_id: FilePathId::new("compose.yaml"),
            kind: ArtifactKind::ComposeFile,
            content_hash: compose_content_hash(&graph),
            text_preview: None,
        })
        .expect("record a structured facet");
    graph
        .upsert_opaque_artifact(&OpaqueArtifact {
            file_id: FilePathId::new("compose.yaml"),
            content_hash: compose_content_hash(&graph),
            mime_type: None,
            text_preview: None,
        })
        .expect("record a second, conflicting facet for the same artifact");

    let response = graph_status(&admitted.binding, &graph);

    let error = response
        .error
        .expect("a facet that disagrees with exact tree truth fails closed");
    assert!(error.contains("critical graph health issue"), "{error}");
    assert!(
        response
            .lines
            .iter()
            .any(|line| line.contains("disagree with exact repository content identity")),
        "{}",
        response.lines.join("\n")
    );
    assert!(
        response
            .lines
            .iter()
            .any(|line| line.contains("conflicting enrichment facets")),
        "{}",
        response.lines.join("\n")
    );
}

fn compose_content_hash(graph: &kin_db::InMemoryGraph) -> Hash256 {
    let path = kin_model::RepoPath::from_utf8("compose.yaml").expect("exact repository path");
    match graph
        .resolved_tree()
        .artifact_at_path(&path)
        .expect("compose.yaml is admitted")
        .entry
    {
        kin_model::TreeEntry::Blob { hash, .. } => hash,
        entry => panic!("compose.yaml is a regular file, found {entry:?}"),
    }
}

#[test]
fn status_reports_the_enrichment_the_query_graph_actually_carries() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    fs::create_dir_all(&repo).expect("create repo");
    let admitted = admit(&repo);
    let graph = workspace_query_graph(&admitted.binding);
    let graph_entities = graph.list_all_entities().expect("list entities").len();
    let graph_relations = graph.graph_stats().total_relations;

    let report = status::inspect(&admitted.layout, &admitted.binding).expect("inspect status");

    assert_eq!(report.semantic_enrichment.entity_count, graph_entities);
    assert_eq!(report.semantic_enrichment.relation_count, graph_relations);
    assert_eq!(
        report.semantic_enrichment.presence,
        SemanticEnrichmentPresence::Present,
        "an enriched repository is not reported as unenriched"
    );
    assert!(report.semantic_enrichment.semantic_change_count > 0);
}

#[test]
fn status_reports_enrichment_absent_on_an_unenriched_repository() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("native");
    fs::create_dir_all(&repo).expect("create repo");
    let result = kin_core::init(&repo).expect("initialize unborn native authority");
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&result.layout)
        .expect("bind published repository authority");

    let report = status::inspect(&result.layout, &binding).expect("inspect status");

    assert_eq!(
        report.semantic_enrichment.presence,
        SemanticEnrichmentPresence::Absent
    );
    assert_eq!(report.semantic_enrichment.entity_count, 0);
    assert_eq!(report.semantic_enrichment.relation_count, 0);
}
