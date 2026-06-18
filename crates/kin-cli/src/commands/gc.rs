// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin gc` — reclaim space from the global `~/.kin` content cache.
//!
//! The init warm-start cache (`~/.kin/cache/init/<namespace>/<repo>/bundles/`)
//! keeps one graph bundle per git HEAD it has ever warmed, and never evicts
//! them, so a repo that is re-initialized often accumulates hundreds of
//! multi-GB bundles. `kin gc` prunes that cache toward a healthy size by
//! removing:
//!
//! - **orphaned bundles** — bundle dirs on disk that the repo's `manifest.json`
//!   no longer references at all; and
//! - **aged bundles** — referenced bundles older than `--max-age-days`, except
//!   the repo's `current_bundle_id`, which is always preserved.
//!
//! A reclaimed-but-still-referenced bundle is safe to remove: the next
//! `kin init` at that HEAD re-checks the bundle path, misses, and rebuilds it —
//! a cache miss, never corruption.
//!
//! `--dry-run` reports what would be reclaimed (and the total size) without
//! deleting anything.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::Result;
use serde::Deserialize;

/// Default age threshold: bundles older than this (and not the current bundle)
/// are reclaimed. Conservative enough that an actively re-initialized repo keeps
/// its recent warm bundles.
const DEFAULT_MAX_AGE_DAYS: u64 = 14;

/// Why a cache entry is being reclaimed — surfaced in the report so the action
/// is never silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReclaimReason {
    /// On disk but not referenced by the repo's manifest.
    Orphaned,
    /// Referenced but older than the age threshold (not the current bundle).
    Aged,
}

impl ReclaimReason {
    fn label(self) -> &'static str {
        match self {
            ReclaimReason::Orphaned => "orphaned",
            ReclaimReason::Aged => "aged",
        }
    }
}

/// A single reclaimable cache entry (a bundle directory).
#[derive(Debug, Clone)]
struct ReclaimEntry {
    path: PathBuf,
    bytes: u64,
    reason: ReclaimReason,
}

/// The set of entries a gc pass would reclaim, with the total size.
#[derive(Debug, Default)]
struct GcPlan {
    entries: Vec<ReclaimEntry>,
    total_bytes: u64,
}

impl GcPlan {
    fn push(&mut self, entry: ReclaimEntry) {
        self.total_bytes = self.total_bytes.saturating_add(entry.bytes);
        self.entries.push(entry);
    }
}

/// Minimal view of a warm-cache `manifest.json` — only the fields gc needs.
/// Resilient by design: unrelated fields are ignored and missing ones default,
/// so a manifest written by a newer or older build still parses.
#[derive(Debug, Deserialize, Default)]
struct CacheManifest {
    #[serde(default)]
    current_bundle_id: Option<String>,
    /// git HEAD → bundle id. Every value here is a referenced bundle.
    #[serde(default)]
    heads: std::collections::BTreeMap<String, String>,
}

impl CacheManifest {
    /// All bundle ids this manifest references (current + every head target).
    fn referenced_ids(&self) -> BTreeSet<String> {
        let mut ids: BTreeSet<String> = self.heads.values().cloned().collect();
        if let Some(current) = &self.current_bundle_id {
            ids.insert(current.clone());
        }
        ids
    }
}

/// Resolve the base directory that holds the init warm-cache namespaces.
///
/// Mirrors `kin init`'s resolution: an explicit `KIN_INIT_CACHE_DIR` wins,
/// otherwise `~/.kin/cache/init`. Returns `None` only when neither the env var
/// nor a home directory can be resolved.
fn init_cache_base() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("KIN_INIT_CACHE_DIR") {
        if !dir.trim().is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    directories::BaseDirs::new().map(|dirs| dirs.home_dir().join(".kin/cache/init"))
}

/// Total size in bytes of a directory tree. Best-effort: unreadable entries are
/// skipped (counted as zero) rather than failing the whole pass.
fn dir_size(path: &Path) -> u64 {
    let mut total = 0u64;
    let Ok(entries) = std::fs::read_dir(path) else {
        return std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    };
    for entry in entries.flatten() {
        let entry_path = entry.path();
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => total = total.saturating_add(dir_size(&entry_path)),
            Ok(_) => {
                total = total.saturating_add(entry.metadata().map(|m| m.len()).unwrap_or(0));
            }
            Err(_) => {}
        }
    }
    total
}

/// Whether `path`'s last-modified time is older than `max_age` relative to
/// `now`. A path whose mtime cannot be read is treated as NOT old (kept), so an
/// unreadable timestamp never causes deletion.
fn is_older_than(path: &Path, max_age: Duration, now: SystemTime) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    now.duration_since(modified)
        .map(|age| age > max_age)
        .unwrap_or(false)
}

/// Recursively locate warm-cache repo directories under `base`. A repo dir is
/// any directory that has both a `manifest.json` and a `bundles/` subdir; the
/// walk stops descending once it finds one. Depth-bounded so it cannot wander
/// arbitrarily deep, and works for both the namespaced home layout
/// (`<base>/<namespace>/<repo>`) and the flat `KIN_INIT_CACHE_DIR` layout.
fn find_repo_cache_dirs(base: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
        if depth > 4 {
            return;
        }
        if dir.join("manifest.json").is_file() && dir.join("bundles").is_dir() {
            out.push(dir.to_path_buf());
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                walk(&entry.path(), depth + 1, out);
            }
        }
    }
    let mut out = Vec::new();
    if base.is_dir() {
        walk(base, 0, &mut out);
    }
    out
}

/// Build the reclaim plan for a single repo cache dir.
fn plan_repo_cache(repo_dir: &Path, max_age: Duration, now: SystemTime, plan: &mut GcPlan) {
    // Only act on a parseable manifest: it tells us which bundle is current and
    // which are still referenced. Without it we cannot reclaim safely, so skip.
    let manifest_path = repo_dir.join("manifest.json");
    let Ok(contents) = std::fs::read_to_string(&manifest_path) else {
        return;
    };
    let Ok(manifest) = serde_json::from_str::<CacheManifest>(&contents) else {
        return;
    };
    let referenced = manifest.referenced_ids();

    let bundles_dir = repo_dir.join("bundles");
    let Ok(entries) = std::fs::read_dir(&bundles_dir) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
            continue;
        }
        let bundle_path = entry.path();
        let Some(id) = bundle_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
        else {
            continue;
        };

        // Never reclaim the active bundle.
        if manifest.current_bundle_id.as_deref() == Some(id.as_str()) {
            continue;
        }

        let reason = if !referenced.contains(&id) {
            Some(ReclaimReason::Orphaned)
        } else if is_older_than(&bundle_path, max_age, now) {
            Some(ReclaimReason::Aged)
        } else {
            None
        };

        if let Some(reason) = reason {
            let bytes = dir_size(&bundle_path);
            plan.push(ReclaimEntry {
                path: bundle_path,
                bytes,
                reason,
            });
        }
    }
}

/// Compute the full reclaim plan for the init warm-cache rooted at `base`.
/// Pure (no deletion) so it is unit-testable; `now` is injected for the same
/// reason.
fn plan_init_cache_gc(base: &Path, max_age: Duration, now: SystemTime) -> GcPlan {
    let mut plan = GcPlan::default();
    for repo_dir in find_repo_cache_dirs(base) {
        plan_repo_cache(&repo_dir, max_age, now, &mut plan);
    }
    plan
}

/// Render a byte count as a short human-readable string.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// `kin gc [--dry-run] [--max-age-days N]` — reclaim space from the init
/// warm-cache.
pub async fn run(dry_run: bool, max_age_days: Option<u64>) -> Result<()> {
    let max_age = Duration::from_secs(max_age_days.unwrap_or(DEFAULT_MAX_AGE_DAYS) * 24 * 60 * 60);
    let now = SystemTime::now();

    let Some(base) = init_cache_base() else {
        println!("kin gc: no init cache directory to scan (no home directory resolved)");
        return Ok(());
    };

    if !base.is_dir() {
        println!(
            "kin gc: init cache is empty (nothing at {})",
            base.display()
        );
        return Ok(());
    }

    let plan = plan_init_cache_gc(&base, max_age, now);

    if plan.entries.is_empty() {
        println!(
            "kin gc: nothing to reclaim under {} (max-age {} days)",
            base.display(),
            max_age_days.unwrap_or(DEFAULT_MAX_AGE_DAYS)
        );
        return Ok(());
    }

    let verb = if dry_run {
        "would reclaim"
    } else {
        "reclaiming"
    };
    println!(
        "kin gc: {verb} {} cache bundle(s), {} under {}",
        plan.entries.len(),
        human_bytes(plan.total_bytes),
        base.display()
    );

    let mut reclaimed_bytes = 0u64;
    let mut reclaimed_count = 0usize;
    for entry in &plan.entries {
        if dry_run {
            println!(
                "  [{}] {} ({})",
                entry.reason.label(),
                entry.path.display(),
                human_bytes(entry.bytes)
            );
            continue;
        }
        match std::fs::remove_dir_all(&entry.path) {
            Ok(()) => {
                reclaimed_bytes = reclaimed_bytes.saturating_add(entry.bytes);
                reclaimed_count += 1;
            }
            Err(err) => {
                eprintln!(
                    "kin gc: failed to remove {} ({}): {err}",
                    entry.path.display(),
                    entry.reason.label()
                );
            }
        }
    }

    if dry_run {
        println!(
            "kin gc: dry run — {} reclaimable across {} bundle(s). Re-run without --dry-run to delete.",
            human_bytes(plan.total_bytes),
            plan.entries.len()
        );
    } else {
        println!(
            "kin gc: reclaimed {} across {} bundle(s)",
            human_bytes(reclaimed_bytes),
            reclaimed_count
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Build a repo cache dir with the given bundles and manifest references.
    /// `bundle_files` maps bundle id → file bytes to write into it.
    fn make_repo_cache(
        repo: &Path,
        current: Option<&str>,
        head_targets: &[&str],
        bundles: &[(&str, usize)],
    ) {
        fs::create_dir_all(repo.join("bundles")).unwrap();
        for (id, size) in bundles {
            let bundle = repo.join("bundles").join(id);
            fs::create_dir_all(&bundle).unwrap();
            fs::write(bundle.join("graph.kndb"), vec![0u8; *size]).unwrap();
            fs::write(bundle.join(".ready"), b"1").unwrap();
        }
        let heads: std::collections::BTreeMap<String, String> = head_targets
            .iter()
            .enumerate()
            .map(|(i, b)| (format!("head{i}"), b.to_string()))
            .collect();
        let manifest = serde_json::json!({
            "schema": "v1",
            "current_bundle_id": current,
            "heads": heads,
        });
        fs::write(
            repo.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn reclaims_orphaned_bundles_not_referenced_by_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("ns").join("repo");
        // "cur" is current+referenced; "orphan" is on disk but unreferenced.
        make_repo_cache(&repo, Some("cur"), &["cur"], &[("cur", 10), ("orphan", 20)]);

        // max_age huge so age never triggers — isolate the orphaned rule.
        let plan = plan_init_cache_gc(
            dir.path(),
            Duration::from_secs(u64::MAX / 2),
            SystemTime::now(),
        );
        assert_eq!(plan.entries.len(), 1, "only the orphan should be reclaimed");
        assert_eq!(plan.entries[0].reason, ReclaimReason::Orphaned);
        assert!(plan.entries[0].path.ends_with("bundles/orphan"));
    }

    #[test]
    fn reclaims_aged_referenced_bundles_but_preserves_current() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("ns").join("repo");
        // Both referenced via heads; "cur" is current. With max_age 0 every
        // non-current bundle is "aged", but current must be preserved.
        make_repo_cache(
            &repo,
            Some("cur"),
            &["cur", "old"],
            &[("cur", 10), ("old", 30)],
        );

        let plan = plan_init_cache_gc(dir.path(), Duration::ZERO, SystemTime::now());
        assert_eq!(plan.entries.len(), 1, "current bundle must be preserved");
        assert_eq!(plan.entries[0].reason, ReclaimReason::Aged);
        assert!(plan.entries[0].path.ends_with("bundles/old"));
        // Whole bundle dir: graph.kndb (30) + .ready (1).
        assert_eq!(plan.total_bytes, 31);
    }

    #[test]
    fn keeps_recent_referenced_bundles() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("ns").join("repo");
        make_repo_cache(
            &repo,
            Some("cur"),
            &["cur", "recent"],
            &[("cur", 10), ("recent", 30)],
        );

        // Large max_age: "recent" is referenced and not old → kept. Nothing to do.
        let plan = plan_init_cache_gc(dir.path(), Duration::from_secs(3600), SystemTime::now());
        assert!(
            plan.entries.is_empty(),
            "recent referenced bundles must be kept"
        );
    }

    #[test]
    fn skips_repo_dirs_without_parseable_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("ns").join("repo");
        fs::create_dir_all(repo.join("bundles").join("b1")).unwrap();
        fs::write(
            repo.join("bundles").join("b1").join("graph.kndb"),
            vec![0u8; 40],
        )
        .unwrap();
        // No manifest.json → not a recognized repo cache dir → skipped entirely.
        let plan = plan_init_cache_gc(dir.path(), Duration::ZERO, SystemTime::now());
        assert!(plan.entries.is_empty());
    }

    #[test]
    fn finds_repo_in_flat_layout() {
        // KIN_INIT_CACHE_DIR layout has repo dirs directly under the base.
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        make_repo_cache(&repo, Some("cur"), &["cur"], &[("cur", 10), ("orphan", 20)]);

        let plan = plan_init_cache_gc(dir.path(), Duration::from_secs(3600), SystemTime::now());
        assert_eq!(plan.entries.len(), 1);
        assert!(plan.entries[0].path.ends_with("bundles/orphan"));
    }

    #[test]
    fn human_bytes_formats_units() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(1024 * 1024 * 1024), "1.0 GB");
    }
}
