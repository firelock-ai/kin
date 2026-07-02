// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Runtime graph⇄file drift detection for `kin doctor --drift [--heal]`.
//!
//! The graph is the source of truth; the working tree is a projection of it.
//! This check compares the graph's expected content hash for every projected
//! source file against the bytes currently on disk and classifies any
//! divergence:
//!
//! * `drifted`   — the file exists on both sides but the on-disk bytes hash to
//!   something other than graph truth (edited out of band, truncated write, …).
//! * `missing`   — the graph tracks the file but the working tree does not
//!   project it (deleted or never written).
//! * `untracked` — the file is on disk but the graph has no record of it (added
//!   out of band, a skewed reconcile that never landed in the graph, …).
//!
//! Detection is a thin wrapper over `kin_db::engine::compute_diff`, hashing the
//! working tree through the exact same enumeration the indexer uses so the two
//! hash sets are directly comparable.
//!
//! `--heal` restores drifted and missing files *from* graph-owned blob truth
//! *to* disk. Content only ever flows graph → disk: the drifted on-disk bytes
//! are never read back to decide truth, and untracked files (which the graph has
//! no truth for) are never silently absorbed.

use anyhow::{anyhow, Result};
use kin_model::{EntityFilter, EntityStore, FilePathId};
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::init::{collect_on_disk_file_hashes, is_repo_owned_graph_path};

/// Classified graph⇄file drift. Serialized verbatim as the `--json` payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftReport {
    /// Files present on both sides whose on-disk hash differs from graph truth.
    pub drifted: Vec<String>,
    /// Files the graph tracks that are absent from the working tree.
    pub missing: Vec<String>,
    /// Files on disk the graph does not track.
    pub untracked: Vec<String>,
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
/// `removed → missing`, `added → untracked`. Internal control-plane paths
/// (`.kin/…`) the graph tracks but the working tree never projects are dropped
/// from `missing` so they cannot masquerade as drift. Each class is sorted so
/// the report is deterministic.
pub fn detect_drift(graph: &kin_db::InMemoryGraph, on_disk: &[(String, [u8; 32])]) -> DriftReport {
    let diff = kin_db::engine::compute_diff(graph, on_disk);

    let mut drifted = diff.modified_files.clone();
    let mut missing: Vec<String> = diff
        .removed_files
        .iter()
        .filter(|path| is_repo_owned_graph_path(path))
        .cloned()
        .collect();
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
    healed: Vec<String>,
    /// Files that could not be healed, with the reason.
    failed: Vec<(String, String)>,
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
    let on_disk = collect_on_disk_file_hashes(&source_root)?;

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

/// Restore one file to graph truth: read the blob the graph's file-hash points
/// to and write it to disk. Content flows graph → disk only — the drifted
/// on-disk bytes are never read to decide truth (Zero File-Search Authority).
fn heal_file(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    source_root: &Path,
    path: &str,
) -> Result<()> {
    // `InMemoryGraph::get_file_hash` is the inherent `&str -> Option<[u8; 32]>`
    // accessor — the same raw-hash space as `set_file_hash` and `compute_diff`.
    let expected_bytes = graph
        .get_file_hash(path)
        .ok_or_else(|| anyhow!("graph has no expected hash for {path}"))?;
    let expected = kin_model::Hash256::from_bytes(expected_bytes);
    let bytes = kin_core::read_blob_from_layout(layout, &expected)
        .ok_or_else(|| anyhow!("graph-owned blob for {path} is unavailable; cannot heal"))?;
    // The blob must actually hash to the graph's expectation before we let it
    // overwrite the working tree.
    if kin_blobs::digest(&bytes) != expected {
        return Err(anyhow!(
            "graph-owned blob for {path} failed its integrity check; refusing to write"
        ));
    }
    let dest = source_root.join(path);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("failed to create {}: {e}", parent.display()))?;
    }
    std::fs::write(&dest, &bytes)
        .map_err(|e| anyhow!("failed to write {}: {e}", dest.display()))?;
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
fn print_file_with_entities(graph: &kin_db::InMemoryGraph, path: &str) {
    println!("  • {path}");
    let filter = EntityFilter {
        file_path: Some(FilePathId::new(path)),
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

    /// Build an in-memory graph whose file-hash truth is exactly `files`.
    fn graph_with(files: &[(&str, [u8; 32])]) -> InMemoryGraph {
        let graph = InMemoryGraph::new();
        for (path, hash) in files {
            graph.set_file_hash(path, *hash);
        }
        graph
    }

    fn on_disk(files: &[(&str, [u8; 32])]) -> Vec<(String, [u8; 32])> {
        files
            .iter()
            .map(|(path, hash)| ((*path).to_string(), *hash))
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
        assert_eq!(report.drifted, vec!["src/lib.rs".to_string()]);
        assert!(report.missing.is_empty());
        assert!(report.untracked.is_empty());
    }

    #[test]
    fn truncated_write_is_drifted() {
        // A truncated / partial write leaves different bytes → a different hash.
        let graph = graph_with(&[("src/app.rs", [7; 32])]);
        let disk = on_disk(&[("src/app.rs", [0; 32])]);
        let report = detect_drift(&graph, &disk);
        assert_eq!(report.drifted, vec!["src/app.rs".to_string()]);
        assert!(report.missing.is_empty());
        assert!(report.untracked.is_empty());
    }

    #[test]
    fn deleted_file_is_missing() {
        // Graph tracks two files; the working tree lost one.
        let graph = graph_with(&[("src/a.rs", [1; 32]), ("src/b.rs", [2; 32])]);
        let disk = on_disk(&[("src/a.rs", [1; 32])]);
        let report = detect_drift(&graph, &disk);
        assert_eq!(report.missing, vec!["src/b.rs".to_string()]);
        assert!(report.drifted.is_empty());
        assert!(report.untracked.is_empty());
    }

    #[test]
    fn clock_skewed_reconcile_addition_is_untracked() {
        // A skewed reconcile left a file on disk the graph never recorded.
        let graph = graph_with(&[("src/a.rs", [1; 32])]);
        let disk = on_disk(&[("src/a.rs", [1; 32]), ("src/ghost.rs", [5; 32])]);
        let report = detect_drift(&graph, &disk);
        assert_eq!(report.untracked, vec!["src/ghost.rs".to_string()]);
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
        assert_eq!(report.drifted, vec!["src/fresh.rs".to_string()]);
        assert_eq!(report.missing, vec!["src/absent.rs".to_string()]);
        assert_eq!(report.untracked, vec!["src/stray.rs".to_string()]);
        assert!(!report.is_clean());
        assert_eq!(report.total(), 3);
    }

    #[test]
    fn results_are_sorted_deterministically() {
        let graph = graph_with(&[("src/z.rs", [1; 32]), ("src/a.rs", [2; 32])]);
        let disk = on_disk(&[("src/z.rs", [9; 32]), ("src/a.rs", [9; 32])]);
        let report = detect_drift(&graph, &disk);
        assert_eq!(
            report.drifted,
            vec!["src/a.rs".to_string(), "src/z.rs".to_string()]
        );
    }

    #[test]
    fn internal_control_plane_paths_are_not_missing() {
        // The graph tracks internal .kin/ paths the working tree never projects;
        // they must not masquerade as missing drift.
        let graph = graph_with(&[
            ("src/lib.rs", [1; 32]),
            (".kin/snapshot/manifest.json", [5; 32]),
        ]);
        let disk = on_disk(&[("src/lib.rs", [1; 32])]);
        let report = detect_drift(&graph, &disk);
        assert!(
            report.is_clean(),
            "internal paths leaked as drift: {report:?}"
        );
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
        blob_store.write(truth).unwrap();

        let graph = InMemoryGraph::new();
        graph.set_file_hash("src/answer.rs", kin_blobs::digest_bytes(truth));

        // The working tree holds a drifted copy.
        let source_root = kin_core::source_dir(&layout);
        let dest = source_root.join("src/answer.rs");
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::write(&dest, b"// corrupted / drifted content\n").unwrap();

        let report = DriftReport {
            drifted: vec!["src/answer.rs".to_string()],
            ..Default::default()
        };
        let outcome = heal_drift(&layout, &graph, &source_root, &report).unwrap();

        assert_eq!(outcome.healed, vec!["src/answer.rs".to_string()]);
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
        blob_store.write(truth).unwrap();

        let graph = InMemoryGraph::new();
        graph.set_file_hash("docs/notes.txt", kin_blobs::digest_bytes(truth));

        let source_root = kin_core::source_dir(&layout);
        let dest = source_root.join("docs/notes.txt");
        assert!(!dest.exists());

        let report = DriftReport {
            missing: vec!["docs/notes.txt".to_string()],
            ..Default::default()
        };
        let outcome = heal_drift(&layout, &graph, &source_root, &report).unwrap();

        assert_eq!(outcome.healed, vec!["docs/notes.txt".to_string()]);
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

        let graph = InMemoryGraph::new();
        graph.set_file_hash("src/orphan.rs", [123; 32]);

        let source_root = kin_core::source_dir(&layout);
        let report = DriftReport {
            missing: vec!["src/orphan.rs".to_string()],
            ..Default::default()
        };
        let outcome = heal_drift(&layout, &graph, &source_root, &report).unwrap();

        assert!(outcome.healed.is_empty());
        assert_eq!(outcome.failed.len(), 1);
        assert_eq!(outcome.failed[0].0, "src/orphan.rs");
        assert!(!source_root.join("src/orphan.rs").exists());
    }
}
