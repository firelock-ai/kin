// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Runtime graph⇄file drift detection for `kin doctor --drift [--heal]`.
//!
//! The graph is the source of truth; the working tree is a projection of it.
//! This check compares every exact graph-owned repository entry against the
//! current filesystem projection and classifies any divergence:
//!
//! * `drifted`   — the file exists on both sides but the on-disk bytes hash to
//!   something other than graph truth (edited out of band, truncated write, …).
//! * `missing`   — the graph tracks the file but the working tree does not
//!   project it (deleted or never written).
//! * `untracked` — the file is on disk but the graph has no record of it (added
//!   out of band, a skewed reconcile that never landed in the graph, …).
//!
//! Detection is a thin wrapper over `kin_db::engine::compute_diff`, observing
//! the filesystem through the exact repository-tree importer. Semantic
//! classification and language support do not affect membership.
//!
//! `--heal` restores drifted and missing files *from* graph-owned blob truth
//! *to* disk. Content only ever flows graph → disk: the drifted on-disk bytes
//! are never read back to decide truth, and untracked files (which the graph has
//! no truth for) are never silently absorbed.

use anyhow::{anyhow, Result};
use kin_model::{EntityFilter, EntityStore, FilePathId, RepoPath, TreeEntry};
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::init::collect_on_disk_tree_entries;

/// Classified graph⇄file drift. Serialized verbatim as the `--json` payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftReport {
    /// Files present on both sides whose on-disk hash differs from graph truth.
    pub drifted: Vec<RepoPath>,
    /// Files the graph tracks that are absent from the working tree.
    pub missing: Vec<RepoPath>,
    /// Files on disk the graph does not track.
    pub untracked: Vec<RepoPath>,
}

impl DriftReport {
    /// True when graph truth and the working tree fully agree.
    pub fn is_clean(&self) -> bool {
        self.drifted.is_empty() && self.missing.is_empty() && self.untracked.is_empty()
    }

    /// Total number of diverging files across all three classes.
    pub fn total(&self) -> usize {
        self.drifted.len() + self.missing.len() + self.untracked.len()
    }
}

/// Classify drift between graph truth and the on-disk file set.
///
/// Thin wrapper over `kin_db::engine::compute_diff`: `modified → drifted`,
/// `removed → missing`, `added → untracked`. No graph entry is hidden by
/// semantic-indexing policy: a reserved control path in graph truth is a
/// corruption signal, not something doctor silently filters. Each class is
/// sorted so the report is deterministic.
pub fn detect_drift(
    graph: &kin_db::InMemoryGraph,
    on_disk: &[(RepoPath, TreeEntry)],
) -> DriftReport {
    let diff = kin_db::engine::compute_diff(graph, on_disk);

    let mut drifted = diff.modified_files.clone();
    let mut missing = diff.removed_files.clone();
    let mut untracked = diff.added_files.clone();

    drifted.sort();
    missing.sort();
    untracked.sort();

    DriftReport {
        drifted,
        missing,
        untracked,
    }
}

/// Outcome of a `--heal` pass.
struct HealOutcome {
    /// Files restored to graph truth on disk.
    healed: Vec<RepoPath>,
    /// Files that could not be healed, with the reason.
    failed: Vec<(RepoPath, String)>,
}

/// `kin doctor --drift [--heal]`.
///
/// Opens the persisted graph read-only — so the check still works when the
/// daemon is down, which is exactly when an operator reaches for `kin doctor` —
/// enumerates and hashes on-disk source files the same way the indexer does,
/// classifies drift, optionally heals, and reports. Returns an error (a nonzero
/// exit) when unresolved drift remains, so the check is a loud CI tripwire.
pub async fn run(heal: bool, json: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow!("not a Kin repository (no .kin/ found)"))?;

    let snap = crate::backend::open_kindb_snapshot_read_only(&layout)
        .map_err(|e| anyhow!("failed to open graph store: {e}"))?;
    let graph = snap.graph();

    let source_root = kin_core::source_dir(&layout);
    let on_disk = collect_on_disk_tree_entries(&source_root)?;

    let report = detect_drift(graph.as_ref(), &on_disk);

    let heal_outcome = if heal {
        Some(heal_drift(&layout, graph.as_ref(), &source_root, &report)?)
    } else {
        None
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_report(graph.as_ref(), &report, heal_outcome.as_ref());
    }

    // A healed drifted/missing file is resolved; a failed heal or any untracked
    // file (which heal never touches) still counts as divergence.
    let unresolved = match &heal_outcome {
        Some(outcome) => !outcome.failed.is_empty() || !report.untracked.is_empty(),
        None => !report.is_clean(),
    };
    if unresolved {
        return Err(anyhow!(
            "graph⇄file drift detected: {} drifted, {} missing, {} untracked",
            report.drifted.len(),
            report.missing.len(),
            report.untracked.len()
        ));
    }
    Ok(())
}

/// Restore drifted and missing files from graph-owned truth. Untracked files
/// have no graph truth to project and are deliberately left alone — absorbing
/// them into the graph is reconcile's job, not the drift tripwire's.
fn heal_drift(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    source_root: &Path,
    report: &DriftReport,
) -> Result<HealOutcome> {
    let mut healed = Vec::new();
    let mut failed = Vec::new();
    for path in report.drifted.iter().chain(report.missing.iter()) {
        match heal_file(layout, graph, source_root, path) {
            Ok(()) => healed.push(path.clone()),
            Err(err) => failed.push((path.clone(), err.to_string())),
        }
    }
    Ok(HealOutcome { healed, failed })
}

/// Restore one entry to graph truth, including executable mode or symlink
/// identity. Content flows graph → disk only — drifted on-disk bytes are never
/// read to decide truth (Zero File-Search Authority).
fn heal_file(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    source_root: &Path,
    path: &RepoPath,
) -> Result<()> {
    let tree = graph.resolved_tree();
    let artifact = tree
        .artifact_at_path(path)
        .ok_or_else(|| anyhow!("graph has no exact tree entry for {path}"))?;
    let expected = artifact.entry;
    let blob_identity = expected.blob_identity().ok_or_else(|| {
        anyhow!(
            "artifact {:?} at {path} is a gitlink; child repository projection is required and doctor will not fabricate it",
            artifact.artifact_id
        )
    })?;
    let bytes = kin_core::read_blob_from_layout(layout, &blob_identity)
        .ok_or_else(|| anyhow!("graph-owned blob for {path} is unavailable; cannot heal"))?;
    // The blob must actually hash to the graph's expectation before we let it
    // overwrite the working tree.
    if kin_blobs::digest(&bytes) != blob_identity {
        return Err(anyhow!(
            "graph-owned blob for {path} failed its integrity check; refusing to write"
        ));
    }
    kin_core::materialize_source_entry(source_root, path, expected, &bytes)
        .map_err(|error| anyhow!("failed to materialize exact tree entry {path}: {error}"))?;
    Ok(())
}

fn print_human_report(
    graph: &kin_db::InMemoryGraph,
    report: &DriftReport,
    heal: Option<&HealOutcome>,
) {
    if report.is_clean() {
        println!("✓ No graph⇄file drift — the working tree matches graph truth.");
        return;
    }

    println!("⚠ Graph⇄file drift detected:");
    println!(
        "  {} drifted · {} missing · {} untracked",
        report.drifted.len(),
        report.missing.len(),
        report.untracked.len()
    );

    if !report.drifted.is_empty() {
        println!("\nDrifted (on-disk bytes ≠ graph truth):");
        for path in &report.drifted {
            print_file_with_entities(graph, path);
        }
    }
    if !report.missing.is_empty() {
        println!("\nMissing (graph truth has no on-disk file):");
        for path in &report.missing {
            print_file_with_entities(graph, path);
        }
    }
    if !report.untracked.is_empty() {
        println!("\nUntracked (on disk, absent from graph — not auto-healed):");
        for path in &report.untracked {
            println!("  • {path}");
        }
    }

    match heal {
        Some(outcome) => {
            println!("\nHeal:");
            if outcome.healed.is_empty() && outcome.failed.is_empty() {
                println!("  nothing to heal (no drifted or missing files).");
            }
            for path in &outcome.healed {
                println!("  ✓ restored {path} from graph truth");
            }
            for (path, err) in &outcome.failed {
                println!("  ✗ {path}: {err}");
            }
        }
        None if !report.drifted.is_empty() || !report.missing.is_empty() => {
            println!(
                "\nRun `kin doctor --heal` to restore drifted/missing files from graph truth."
            );
        }
        None => {}
    }
}

/// Print a diverging file plus the graph entities attributed to it, so drift is
/// attributable — "which entities, which file" — not just a bare path.
fn print_file_with_entities(graph: &kin_db::InMemoryGraph, path: &RepoPath) {
    println!("  • {path}");
    let Some(path_utf8) = path.as_utf8() else {
        println!("      (byte-exact non-UTF-8 path; no semantic entity enrichment)");
        return;
    };
    let filter = EntityFilter {
        file_path: Some(FilePathId::new(path_utf8)),
        ..Default::default()
    };
    if let Ok(entities) = graph.query_entities(&filter) {
        for entity in entities.iter().take(8) {
            println!("      - {:?} {}", entity.kind, entity.name);
        }
        if entities.len() > 8 {
            println!("      … {} more entities", entities.len() - 8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::{
        ArtifactId, AuthorId, ChangeStore, GitObjectId, Hash256, LocatedEntry, SemanticChange,
        SemanticChangeId, Timestamp, TreeDelta,
    };

    fn path(value: &str) -> RepoPath {
        RepoPath::from_utf8(value).unwrap()
    }

    fn regular(hash: [u8; 32]) -> TreeEntry {
        TreeEntry::blob(Hash256::from_bytes(hash), false)
    }

    fn graph_with_entries(files: Vec<(RepoPath, TreeEntry)>) -> InMemoryGraph {
        let graph = InMemoryGraph::new();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();

        let projected_files = files
            .iter()
            .filter_map(|(path, _)| path.as_utf8().map(|value| FilePathId::new(value)))
            .collect();
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x44; 32])),
            parents: vec![genesis.id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("doctor-test"),
            message: "seed exact doctor tree".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: files
                .into_iter()
                .map(|(path, entry)| TreeDelta::Added {
                    artifact_id: ArtifactId::new(),
                    new: LocatedEntry::new(path, entry),
                })
                .collect(),
            projected_files,
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            authored_on: None,
        };
        change.id = kin_model::compute_semantic_change_id(&change).unwrap();
        graph.create_change(&change).unwrap();
        graph
    }

    /// Build an in-memory graph whose exact blob truth is exactly `files`.
    fn graph_with(files: &[(&str, [u8; 32])]) -> InMemoryGraph {
        graph_with_entries(
            files
                .iter()
                .map(|(value, hash)| (path(value), regular(*hash)))
                .collect(),
        )
    }

    fn on_disk(files: &[(&str, [u8; 32])]) -> Vec<(RepoPath, TreeEntry)> {
        files
            .iter()
            .map(|(value, hash)| (path(value), regular(*hash)))
            .collect()
    }

    #[test]
    fn clean_when_disk_matches_graph() {
        let graph = graph_with(&[("src/lib.rs", [1; 32]), ("src/main.rs", [2; 32])]);
        let disk = on_disk(&[("src/lib.rs", [1; 32]), ("src/main.rs", [2; 32])]);
        let report = detect_drift(&graph, &disk);
        assert!(report.is_clean(), "expected clean, got {report:?}");
        assert_eq!(report.total(), 0);
    }

    #[test]
    fn file_edited_while_daemon_paused_is_drifted() {
        // Graph truth says lib.rs hashes to [1;32]; the file was edited while the
        // daemon (graph) was paused, so disk now hashes to something else.
        let graph = graph_with(&[("src/lib.rs", [1; 32])]);
        let disk = on_disk(&[("src/lib.rs", [9; 32])]);
        let report = detect_drift(&graph, &disk);
        assert_eq!(report.drifted, vec![path("src/lib.rs")]);
        assert!(report.missing.is_empty());
        assert!(report.untracked.is_empty());
    }

    #[test]
    fn truncated_write_is_drifted() {
        // A truncated / partial write leaves different bytes → a different hash.
        let graph = graph_with(&[("src/app.rs", [7; 32])]);
        let disk = on_disk(&[("src/app.rs", [0; 32])]);
        let report = detect_drift(&graph, &disk);
        assert_eq!(report.drifted, vec![path("src/app.rs")]);
        assert!(report.missing.is_empty());
        assert!(report.untracked.is_empty());
    }

    #[test]
    fn deleted_file_is_missing() {
        // Graph tracks two files; the working tree lost one.
        let graph = graph_with(&[("src/a.rs", [1; 32]), ("src/b.rs", [2; 32])]);
        let disk = on_disk(&[("src/a.rs", [1; 32])]);
        let report = detect_drift(&graph, &disk);
        assert_eq!(report.missing, vec![path("src/b.rs")]);
        assert!(report.drifted.is_empty());
        assert!(report.untracked.is_empty());
    }

    #[test]
    fn clock_skewed_reconcile_addition_is_untracked() {
        // A skewed reconcile left a file on disk the graph never recorded.
        let graph = graph_with(&[("src/a.rs", [1; 32])]);
        let disk = on_disk(&[("src/a.rs", [1; 32]), ("src/ghost.rs", [5; 32])]);
        let report = detect_drift(&graph, &disk);
        assert_eq!(report.untracked, vec![path("src/ghost.rs")]);
        assert!(report.drifted.is_empty());
        assert!(report.missing.is_empty());
    }

    #[test]
    fn stale_projection_mixes_all_three_classes() {
        // A stale projection: one file behind graph truth (drifted), one graph
        // file never written (missing), one stray file on disk (untracked).
        let graph = graph_with(&[("src/fresh.rs", [3; 32]), ("src/absent.rs", [4; 32])]);
        let disk = on_disk(&[("src/fresh.rs", [30; 32]), ("src/stray.rs", [8; 32])]);
        let report = detect_drift(&graph, &disk);
        assert_eq!(report.drifted, vec![path("src/fresh.rs")]);
        assert_eq!(report.missing, vec![path("src/absent.rs")]);
        assert_eq!(report.untracked, vec![path("src/stray.rs")]);
        assert!(!report.is_clean());
        assert_eq!(report.total(), 3);
    }

    #[test]
    fn results_are_sorted_deterministically() {
        let graph = graph_with(&[("src/z.rs", [1; 32]), ("src/a.rs", [2; 32])]);
        let disk = on_disk(&[("src/z.rs", [9; 32]), ("src/a.rs", [9; 32])]);
        let report = detect_drift(&graph, &disk);
        assert_eq!(report.drifted, vec![path("src/a.rs"), path("src/z.rs")]);
    }

    #[test]
    fn internal_control_plane_paths_are_not_hidden() {
        // Exact graph corruption is reported. Doctor must not carry forward the
        // legacy behavior that silently filtered reserved control paths.
        let graph = graph_with(&[
            ("src/lib.rs", [1; 32]),
            (".kin/snapshot/manifest.json", [5; 32]),
        ]);
        let disk = on_disk(&[("src/lib.rs", [1; 32])]);
        let report = detect_drift(&graph, &disk);
        assert_eq!(report.missing, vec![path(".kin/snapshot/manifest.json")]);
    }

    #[test]
    fn heal_restores_drifted_file_from_graph_truth() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;

        // Store the true content in the graph-owned blob store and record its
        // hash as graph truth.
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();
        let truth = b"pub fn answer() -> u32 { 42 }\n";
        let truth_hash = blob_store.write(truth).unwrap();
        let graph = graph_with_entries(vec![(
            path("src/answer.rs"),
            TreeEntry::blob(Hash256::from_bytes(*truth_hash.as_bytes()), false),
        )]);

        // The working tree holds a drifted copy.
        let source_root = kin_core::source_dir(&layout);
        let dest = source_root.join("src/answer.rs");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(&dest, b"// corrupted / drifted content\n").unwrap();

        let report = DriftReport {
            drifted: vec![path("src/answer.rs")],
            ..Default::default()
        };
        let outcome = heal_drift(&layout, &graph, &source_root, &report).unwrap();

        assert_eq!(outcome.healed, vec![path("src/answer.rs")]);
        assert!(
            outcome.failed.is_empty(),
            "unexpected failures: {:?}",
            outcome.failed
        );
        assert_eq!(std::fs::read(&dest).unwrap(), truth);
    }

    #[test]
    fn heal_rematerializes_missing_file() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;

        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();
        let truth = b"MISSING BUT KNOWN TO THE GRAPH\n";
        let truth_hash = blob_store.write(truth).unwrap();
        let graph = graph_with_entries(vec![(
            path("docs/notes.txt"),
            TreeEntry::blob(Hash256::from_bytes(*truth_hash.as_bytes()), false),
        )]);

        let source_root = kin_core::source_dir(&layout);
        let dest = source_root.join("docs/notes.txt");
        assert!(!dest.exists());

        let report = DriftReport {
            missing: vec![path("docs/notes.txt")],
            ..Default::default()
        };
        let outcome = heal_drift(&layout, &graph, &source_root, &report).unwrap();

        assert_eq!(outcome.healed, vec![path("docs/notes.txt")]);
        assert!(outcome.failed.is_empty());
        assert_eq!(std::fs::read(&dest).unwrap(), truth);
    }

    #[test]
    fn heal_fails_loudly_when_graph_blob_is_absent() {
        // The graph claims a hash but the blob was never stored: heal must report
        // the gap rather than silently adopting whatever is on disk.
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;

        let graph = graph_with(&[("src/orphan.rs", [123; 32])]);

        let source_root = kin_core::source_dir(&layout);
        let report = DriftReport {
            missing: vec![path("src/orphan.rs")],
            ..Default::default()
        };
        let outcome = heal_drift(&layout, &graph, &source_root, &report).unwrap();

        assert!(outcome.healed.is_empty());
        assert_eq!(outcome.failed.len(), 1);
        assert_eq!(outcome.failed[0].0, path("src/orphan.rs"));
        assert!(!source_root.join("src/orphan.rs").exists());
    }

    #[cfg(unix)]
    #[test]
    fn heal_preserves_executable_mode() {
        use std::os::unix::fs::PermissionsExt;

        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();
        let truth = b"#!/bin/sh\nexit 0\n";
        let truth_hash = blob_store.write(truth).unwrap();
        let script = path("bin/tool");
        let graph = graph_with_entries(vec![(
            script.clone(),
            TreeEntry::blob(Hash256::from_bytes(*truth_hash.as_bytes()), true),
        )]);
        let report = DriftReport {
            missing: vec![script.clone()],
            ..Default::default()
        };

        let outcome = heal_drift(&layout, &graph, &kin_core::source_dir(&layout), &report).unwrap();

        assert_eq!(outcome.healed, vec![script]);
        let mode = std::fs::metadata(repo.path().join("bin/tool"))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0);
    }

    #[cfg(unix)]
    #[test]
    fn heal_recreates_symlink_identity() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();
        let target_hash = blob_store.write(b"target.txt").unwrap();
        let link = path("current");
        let graph = graph_with_entries(vec![(
            link.clone(),
            TreeEntry::symlink(Hash256::from_bytes(*target_hash.as_bytes())),
        )]);
        let report = DriftReport {
            missing: vec![link.clone()],
            ..Default::default()
        };

        let outcome = heal_drift(&layout, &graph, &kin_core::source_dir(&layout), &report).unwrap();

        assert_eq!(outcome.healed, vec![link]);
        assert_eq!(
            std::fs::read_link(repo.path().join("current")).unwrap(),
            std::path::PathBuf::from("target.txt")
        );
    }

    #[test]
    fn heal_refuses_gitlink_without_child_projection() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let gitlink = path("vendor/child");
        let graph = graph_with_entries(vec![(
            gitlink.clone(),
            TreeEntry::gitlink(GitObjectId::sha1([0x55; 20])),
        )]);
        let report = DriftReport {
            missing: vec![gitlink.clone()],
            ..Default::default()
        };

        let outcome = heal_drift(&layout, &graph, &kin_core::source_dir(&layout), &report).unwrap();

        assert!(outcome.healed.is_empty());
        assert_eq!(outcome.failed[0].0, gitlink);
        assert!(outcome.failed[0].1.contains("child repository projection"));
    }

    #[test]
    fn drift_json_preserves_non_utf8_paths_losslessly() {
        let exact_path = RepoPath::from_bytes(b"assets/\xff.bin".to_vec()).unwrap();
        let graph = graph_with_entries(vec![(exact_path.clone(), regular([0x66; 32]))]);

        let report = detect_drift(&graph, &[]);

        assert_eq!(report.missing, vec![exact_path]);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(
            json["missing"][0]["bytes_hex"],
            serde_json::Value::String("6173736574732fff2e62696e".to_string())
        );
    }
}
