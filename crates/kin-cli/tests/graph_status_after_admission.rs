// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Reporting truth on a freshly admitted repository-v6 repository.
//!
//! Every case here admits a real Git repository through the exact admission
//! boundary. Durable status and the live query graph are exercised as distinct
//! views: they agree immediately after admission, while daemon routing tests
//! separately pin that later live-only enrichment does not rewrite authority.

use std::collections::BTreeSet;
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use kin_cli::commands::graph::{execute_graph_command, GraphCommandRequest};
use kin_cli::commands::status::{self, SemanticEnrichmentPresence, SemanticEnrichmentView};
use kin_model::{
    ArtifactKind, EntityStore, FilePathId, Hash256, OpaqueArtifact, StructuredArtifact,
};
use tempfile::tempdir;

mod common;

use common::Command;

struct IsolatedDaemon {
    child: Option<common::RuntimeOwnedChild>,
}

impl IsolatedDaemon {
    fn spawn(repo: &Path, runtime: &common::IsolatedDaemonRuntime) -> Self {
        let mut command = runtime.daemon_command();
        let child = command
            .arg("--repo")
            .arg(repo)
            .arg("--port")
            .arg("0")
            .env("KIN_DAEMON_DISABLE_LSP", "1")
            .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn_owned()
            .expect("spawn isolated kin-daemon");
        Self { child: Some(child) }
    }

    fn wait_until_serving(&mut self, kin_root: &Path) -> u16 {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let child = self.child.as_mut().expect("daemon child exists");
            if let Some(status) = child.try_wait().expect("inspect daemon child") {
                panic!("isolated daemon exited before readiness: {status}");
            }
            if let Some(port) = fs::read_to_string(kin_root.join("daemon.port"))
                .ok()
                .and_then(|value| value.trim().parse::<u16>().ok())
            {
                let address = SocketAddr::from(([127, 0, 0, 1], port));
                if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok() {
                    return port;
                }
            }
            assert!(
                Instant::now() < deadline,
                "isolated daemon did not become ready"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn stop(mut self) {
        let mut child = self.child.take().expect("daemon child exists");
        let _ = child.kill();
        let status = child.wait().expect("reap isolated daemon");
        assert!(
            child
                .try_wait()
                .expect("verify isolated daemon cleanup")
                .is_some(),
            "isolated daemon child survived cleanup: {status}"
        );
    }
}

impl Drop for IsolatedDaemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_git(path: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
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
    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn helper() -> u32 {\n    11\n}\n\npub fn replacement() -> u32 {\n    helper() + 2\n}\n",
    )
    .expect("write semantic add/modify/remove transition");
    run_git(repo, &["add", "--all"]);
    run_git(repo, &["commit", "-m", "advance semantic identities"]);
}

/// A repository whose cross-file facts are two imports of one symbol name from
/// two different external modules. This is what an ordinary repository looks
/// like part way through a migration, `use log::info` in one file beside
/// `use tracing::info` in another, and the same shape arises from
/// `anyhow::Result` beside `std::io::Result`, or `useState` imported from both
/// `react` and `preact/hooks`.
fn seed_repository_with_same_named_external_imports(repo: &Path) {
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    run_git(repo, &["init", "--initial-branch=main"]);
    run_git(repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(repo, &["config", "user.name", "Kin"]);
    fs::write(
        repo.join("src/legacy.rs"),
        b"extern crate log;\n\nuse log::info;\n\npub fn legacy() {\n    info();\n}\n",
    )
    .expect("write the importer on the old logger");
    fs::write(
        repo.join("src/current.rs"),
        b"extern crate tracing;\n\nuse tracing::info;\n\npub fn current() {\n    info();\n}\n",
    )
    .expect("write the importer on the new logger");
    run_git(repo, &["add", "--all"]);
    run_git(
        repo,
        &["commit", "-m", "two external modules, one symbol name"],
    );
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
    execute_graph_command(
        &kin_cli::commands::repository_authority::RequestRepositoryAuthority::pinned(
            binding.clone(),
        ),
        graph,
        &GraphCommandRequest::Status,
        &Default::default(),
        &Default::default(),
    )
    .expect("run graph status")
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

fn graph_validate(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &kin_db::InMemoryGraph,
) -> kin_cli::commands::graph::GraphCommandResponse {
    execute_graph_command(
        &kin_cli::commands::repository_authority::RequestRepositoryAuthority::pinned(
            binding.clone(),
        ),
        graph,
        &GraphCommandRequest::Validate,
        &Default::default(),
        &Default::default(),
    )
    .expect("run graph validate")
}

fn note_lines(response: &kin_cli::commands::graph::GraphCommandResponse) -> Vec<&String> {
    response
        .lines
        .iter()
        .filter(|line| line.starts_with('ℹ'))
        .collect()
}

/// Exact admission binds the entity layer and no facet layer, so a freshly
/// admitted repository is healthy with its enrichment still pending. Validate
/// must say so: passing silently makes a pending repository indistinguishable
/// from a fully enriched one, which is the same reporting loss on the validate
/// surface that the status surface was fixed for.
#[test]
fn graph_validate_reports_pending_enrichment_and_agrees_with_status() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    fs::create_dir_all(&repo).expect("create repo");
    let admitted = admit(&repo);
    let graph = workspace_query_graph(&admitted.binding);

    let validate = graph_validate(&admitted.binding, &graph);

    assert!(
        validate.error.is_none(),
        "pending enrichment is healthy, so validate must not fail: {:?}\n{}",
        validate.error,
        validate.lines.join("\n")
    );
    assert!(
        validate
            .lines
            .iter()
            .any(|line| line.contains("no query-facing enrichment facet")),
        "validate must surface the pending-enrichment note: {}",
        validate.lines.join("\n")
    );

    let status = graph_status(&admitted.binding, &graph);
    assert_eq!(
        note_lines(&validate),
        note_lines(&status),
        "validate and status must agree on note presence for one repo state"
    );
}

/// Admission binds one external reference target per unresolved import source,
/// and two imports of one symbol name produce two of them. Both carry that
/// symbol as their name, no file, no span, and the same uniform kind, so a
/// duplicate check that keys on name and declaration position alone sees one
/// entity recorded twice. Validate would then print a corruption report and exit
/// non-zero on a graph Kin had just written correctly, on any repository that
/// imports a common name such as `Error`, `Result`, or `info` from two modules.
#[test]
fn graph_validate_accepts_same_named_external_targets_from_different_modules() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    fs::create_dir_all(&repo).expect("create repo");
    seed_repository_with_same_named_external_imports(&repo);
    let result = kin_core::init_from_git(&repo).expect("admit exact Git repository authority");
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&result.layout)
        .expect("bind published repository authority");
    let graph = workspace_query_graph(&binding);

    // The shape under test has to be present, or passing proves nothing.
    let targets: Vec<_> = graph
        .list_all_entities()
        .expect("list entities")
        .into_iter()
        .filter(|entity| entity.name == "info" && entity.file_origin.is_none())
        .collect();
    assert_eq!(
        targets.len(),
        2,
        "admission binds one external target per import source: {targets:?}"
    );
    assert_eq!(
        targets
            .iter()
            .map(|entity| entity.id)
            .collect::<BTreeSet<_>>()
            .len(),
        2,
        "the two targets are distinct entities, not one recorded twice"
    );

    let validate = graph_validate(&binding, &graph);

    assert!(
        !validate.lines.iter().any(|line| line.contains("duplicate")),
        "two distinct external targets are not a duplicated entity: {}",
        validate.lines.join("\n")
    );
    assert!(
        validate.error.is_none(),
        "a healthy graph must not fail validate: {:?}\n{}",
        validate.error,
        validate.lines.join("\n")
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
fn status_reports_durable_admission_enrichment_from_one_authority_generation() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    fs::create_dir_all(&repo).expect("create repo");
    let admitted = admit(&repo);
    let graph = workspace_query_graph(&admitted.binding);
    let graph_entities = graph.list_all_entities().expect("list entities").len();
    let graph_relations = graph.graph_stats().total_relations;

    let report = status::inspect(
        &admitted.layout,
        &admitted.binding,
        status::EmbeddingCoverage::unobserved(status::EmbeddingCoverageUnobserved::NoRunningDaemon),
    )
    .expect("inspect status");

    assert_eq!(report.semantic_enrichment.entity_count, graph_entities);
    assert_eq!(report.semantic_enrichment.relation_count, graph_relations);
    assert_eq!(
        report.semantic_enrichment.presence,
        SemanticEnrichmentPresence::Present,
        "an enriched repository is not reported as unenriched"
    );
    assert_eq!(
        report.semantic_enrichment.view,
        SemanticEnrichmentView::DurableRepositoryAuthority
    );
    assert_eq!(
        report.semantic_enrichment.authority_generation,
        report.repository.generation
    );
    assert_eq!(
        report.semantic_enrichment.workspace_generation,
        report.workspace.generation
    );
    assert!(report.semantic_enrichment.semantic_change_count > 0);
}

/// Install a real vector index over every retrievable key this graph owns,
/// through kin-db's own compatibility-checked loader.
///
/// The vectors are fixture values; the index, the keys, and the load path are
/// the production ones. What the caller is measuring is where coverage is read
/// from, so the index has to be genuinely attached to the graph under test.
#[cfg(feature = "vector")]
fn install_full_vector_index(graph: &kin_db::InMemoryGraph, sidecar: &Path) -> usize {
    let snapshot = graph.to_snapshot();
    let mut keys: Vec<kin_model::RetrievalKey> = graph
        .list_all_entities()
        .expect("list entities")
        .iter()
        .map(|entity| kin_model::RetrievalKey::Entity(entity.id))
        .collect();
    keys.extend(
        snapshot
            .entity_revisions
            .values()
            .flat_map(|revisions| revisions.iter())
            .map(|revision| kin_model::RetrievalKey::EntityRevision(revision.revision_id)),
    );
    keys.extend(
        snapshot
            .resolved_tree
            .artifacts()
            .map(|artifact| kin_model::RetrievalKey::Artifact(artifact.artifact_id)),
    );

    let vectors = kin_db::VectorIndex::new(4).expect("create vector index");
    for (index, key) in keys.iter().enumerate() {
        let embedding = match index % 3 {
            0 => [1.0, 0.0, 0.0, 0.0],
            1 => [0.0, 1.0, 0.0, 0.0],
            _ => [0.0, 0.0, 1.0, 0.0],
        };
        vectors
            .upsert_retrievable(*key, &embedding)
            .expect("upsert retrievable vector");
    }

    let descriptor = kin_db::IndexDescriptor {
        model_id: Some("status-coverage-fixture@v1".to_string()),
        graph_root: Some(hex::encode(graph.compute_root_hash())),
    };
    vectors.set_descriptor(descriptor.clone());
    vectors.save(sidecar).expect("save vector index");
    assert!(
        matches!(
            graph.load_vector_index_compatible(sidecar, &descriptor),
            kin_db::VectorIndexLoad::Loaded(_)
        ),
        "the fixture sidecar must install into the graph it was built from"
    );
    keys.len()
}

/// Coverage must come from a graph that actually holds an index.
///
/// The regression this pins is not a wrong number, it is a well-formed one.
/// `embedding_status` answers `indexed = 0` for every retrievable object when
/// no vector index is installed, and a graph rebuilt from an authority snapshot
/// never has one. Reading coverage there reports zero on a fully embedded
/// repository. So the same graph is measured twice, once before an index is
/// attached and once after, and the two readings must differ in kind: an
/// absence first, then real counts.
#[cfg(feature = "vector")]
#[test]
fn status_reports_coverage_from_the_index_the_live_graph_carries() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    fs::create_dir_all(&repo).expect("create repo");
    let admitted = admit(&repo);
    let graph = workspace_query_graph(&admitted.binding);

    // Exactly the source a snapshot-derived read would have used. It carries no
    // index, so it must report that rather than counting zero against a total.
    assert_eq!(
        status::observe_embedding_coverage(&graph),
        status::EmbeddingCoverage::unobserved(
            status::EmbeddingCoverageUnobserved::NoVectorIndexAttached
        ),
        "a graph with no vector index must report an absence, never a coverage of zero"
    );

    let seeded = install_full_vector_index(&graph, &root.path().join("coverage.kvec"));
    assert!(seeded > 0, "the admitted graph must own retrievable keys");

    let coverage = status::observe_embedding_coverage(&graph);
    let status::EmbeddingCoverage::Observed {
        source,
        indexed,
        pending,
        total,
    } = coverage
    else {
        panic!("an attached index must produce an observation, found {coverage:?}");
    };
    assert_eq!(source, status::EmbeddingCoverageSource::LiveQueryGraph);
    assert!(
        indexed > 0,
        "an embedded repository must not report zero indexed objects \
         (indexed={indexed}, pending={pending}, total={total}, seeded={seeded})"
    );
    assert_eq!(
        indexed, total,
        "every retrievable key was seeded (pending={pending}, seeded={seeded})"
    );
    assert_eq!(
        pending, 0,
        "nothing is outstanding once every key is indexed"
    );

    // The same numbers have to survive the report and its wire form, or the
    // payload consumers read is not the observation that was taken.
    let report = status::inspect(&admitted.layout, &admitted.binding, coverage)
        .expect("inspect status with observed coverage");
    let encoded = serde_json::to_value(&report).expect("serialize status report");
    assert_eq!(encoded["schema"], "kin.status.v3");
    assert_eq!(encoded["embedding_coverage"]["state"], "observed");
    assert_eq!(
        encoded["embedding_coverage"]["indexed"],
        serde_json::json!(indexed)
    );
    assert!(
        encoded["embedding_coverage"]["indexed"].as_u64().unwrap() > 0,
        "the serialized payload must carry the nonzero coverage that was observed"
    );
    assert_eq!(
        serde_json::from_value::<status::StatusReport>(encoded)
            .expect("a report carrying observed coverage must round-trip")
            .embedding_coverage,
        coverage
    );
}

#[test]
fn status_reports_enrichment_absent_on_an_unenriched_repository() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("native");
    fs::create_dir_all(&repo).expect("create repo");
    let result = kin_core::init(&repo).expect("initialize unborn native authority");
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&result.layout)
        .expect("bind published repository authority");

    let report = status::inspect(
        &result.layout,
        &binding,
        status::EmbeddingCoverage::unobserved(status::EmbeddingCoverageUnobserved::NoRunningDaemon),
    )
    .expect("inspect status");

    assert_eq!(
        report.semantic_enrichment.presence,
        SemanticEnrichmentPresence::Absent
    );
    assert_eq!(report.semantic_enrichment.entity_count, 0);
    assert_eq!(report.semantic_enrichment.relation_count, 0);
}

#[test]
fn init_status_and_graph_status_use_their_real_durable_and_live_routes() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");
    seed_repository(&repo);

    let init = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["init", ".", "--json"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .current_dir(&repo)
        .output()
        .expect("run production kin init route");
    assert!(
        init.status.success(),
        "init stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    let init_payload: serde_json::Value =
        serde_json::from_slice(&init.stdout).expect("init emits JSON");

    let status = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["status", "--json"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("KIN_DAEMON_URL")
        .current_dir(&repo)
        .output()
        .expect("run production kin status route");
    assert!(
        status.status.success(),
        "status stdout={} stderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
    let status_payload: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("status emits JSON");
    assert_eq!(
        status_payload["semantic_enrichment"], init_payload["semantic_enrichment"],
        "init and status share the committed durable authority generation"
    );
    assert_eq!(
        status_payload["semantic_enrichment"]["view"],
        "durable_repository_authority"
    );

    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let mut daemon = IsolatedDaemon::spawn(&repo, &runtime);
    let port = daemon.wait_until_serving(&repo.join(".kin"));
    let graph_status = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["graph", "status"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("KIN_DAEMON_URL", format!("http://127.0.0.1:{port}"))
        .current_dir(&repo)
        .output()
        .expect("run production kin graph status route");
    daemon.stop();

    assert!(
        graph_status.status.success(),
        "graph status stdout={} stderr={}",
        String::from_utf8_lossy(&graph_status.stdout),
        String::from_utf8_lossy(&graph_status.stderr)
    );
    let graph_stdout = String::from_utf8_lossy(&graph_status.stdout);
    assert!(graph_stdout.contains("Entities:"), "{graph_stdout}");
    assert!(
        graph_stdout.contains("Entity-to-entity relations:"),
        "{graph_stdout}"
    );
}

/// FIR-2559 end to end, through the shipped binaries. A store the product has
/// just converted reports the admission that conversion performed, rather than
/// telling its owner that how far graph truth has fallen behind is unknown.
///
/// `--no-enrich` is load-bearing rather than a speed-up: it is what keeps the
/// conversion the only thing that could have written the marker. The enrichment
/// phase starts a daemon, whose ambient reconcile tick is one of the two writers
/// that existed before this, so a marker read after it would be evidence about
/// the tick instead. The read below therefore happens with no daemon in this
/// fixture's life at all.
///
/// The rendered line is asserted afterwards, once a daemon is serving, because
/// that is the sentence a user actually reads.
#[test]
fn a_converted_store_reports_its_admission_rather_than_unknown_freshness() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");
    seed_repository(&repo);

    let init = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["init", ".", "--json", "--no-enrich"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("KIN_DAEMON_URL")
        .current_dir(&repo)
        .output()
        .expect("run production kin init route");
    assert!(
        init.status.success(),
        "init stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    assert!(
        !repo.join(".kin/daemon.port").exists(),
        "no daemon ran for this store, so the marker below can only be the conversion's"
    );

    let layout = kin_core::KinLayout::discover(&repo).expect("the conversion published a store");
    let freshness = kin_core::last_admission::read(&layout);
    let recorded = match &freshness {
        kin_core::last_admission::LastAdmissionRead::Recorded(recorded) => recorded,
        other => panic!("a converted store must record its complete admission, read {other:?}"),
    };
    assert_eq!(
        recorded.tracked_artifacts, 3,
        "the record must cover the three files this repository commits"
    );

    let line = freshness.describe(chrono::Utc::now());
    assert!(
        line.contains("last complete admission"),
        "the freshness surface must name the admission: {line}"
    );
    assert!(
        !line.contains("unknown"),
        "and must not report unknown freshness on a store converted a moment ago: {line}"
    );

    // The same fact through the shipped `kin graph status` route, which is where
    // a user meets it.
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let mut daemon = IsolatedDaemon::spawn(&repo, &runtime);
    let port = daemon.wait_until_serving(&repo.join(".kin"));
    let graph_status = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["graph", "status"])
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("KIN_DAEMON_URL", format!("http://127.0.0.1:{port}"))
        .current_dir(&repo)
        .output()
        .expect("run production kin graph status route");
    daemon.stop();

    assert!(
        graph_status.status.success(),
        "graph status stdout={} stderr={}",
        String::from_utf8_lossy(&graph_status.stdout),
        String::from_utf8_lossy(&graph_status.stderr)
    );
    let graph_stdout = String::from_utf8_lossy(&graph_status.stdout);
    assert!(
        graph_stdout.contains("graph truth: last complete admission"),
        "{graph_stdout}"
    );
    assert!(
        !graph_stdout.contains("no complete admission is recorded"),
        "{graph_stdout}"
    );
}
