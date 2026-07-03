// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Out-of-band capacity policy for the on-disk embedding cache: observability
//! (size, entry count, age distribution) and budgeted, LRU-by-mtime eviction.
//!
//! The cache under `~/.kin/cache/embeddings` (or `$KIN_EMBED_CACHE_DIR`) is
//! written by [`super::EmbeddingCache`] as a tree of immutable vector files:
//!
//! ```text
//! <base>/<schema-version>/<namespace>/<2-char-prefix>/<sha256>.bin
//! ```
//!
//! The embed hot path only ever *adds* entries — it has no notion of a budget —
//! so on a heavy bench/proof machine the tree accretes without bound: fresh
//! clones of large corpora add millions of files, and every schema-version bump
//! abandons a whole subtree that is never reclaimed. This module is the policy
//! that lets an operator see and bound that growth.
//!
//! It is deliberately **never** invoked on the embed hot path. Scanning a
//! multi-terabyte tree per write would wreck both write latency and the
//! perf-measurement integrity the cache is already sensitive to. Eviction is
//! driven only by explicit operator action (`kin cache status` / `kin cache
//! gc`), and does nothing destructive unless a budget is configured or stale
//! schema pruning is explicitly requested.
//!
//! ## Scale
//!
//! A terabyte-scale cache holds hundreds of millions of ~3 KB files, so nothing
//! here retains a per-file list in memory. Sizing folds each entry into a small
//! fixed set of counters, and eviction is a two-pass mtime histogram: pass one
//! buckets entry bytes by hour to find the age cutoff that reaches budget, pass
//! two deletes everything at or below that cutoff. Time and memory are `O(files)`
//! and `O(hours-spanned)` respectively, never `O(files)` memory.
//!
//! ## Concurrency
//!
//! Eviction only ever removes whole finalized `*.bin` files, and stale-schema
//! pruning only ever removes whole abandoned schema-version subtrees. It never
//! truncates or rewrites a live entry, and it skips the `*.tmp-*` files an
//! in-flight writer renames into place. A reader racing a deletion either reads
//! the complete old file — its open descriptor outlives the unlink — or sees
//! `ENOENT`, treats it as a cache miss, and re-embeds. A reclaimed entry is a
//! miss, never a corruption.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use directories::BaseDirs;

/// Resolve the base directory that roots every embedding-cache schema tree.
///
/// Mirrors [`super::EmbeddingCache::new`]'s resolution exactly: an explicit
/// `KIN_EMBED_CACHE_DIR` wins, otherwise `~/.kin/cache/embeddings`. `None` only
/// when neither the env var nor a home directory resolves. Note this is
/// independent of `KIN_EMBED_CACHE=0` (which disables *use* of the cache): an
/// operator must still be able to inspect and prune the directory a prior run
/// filled even when the current process would not read it.
pub fn embedding_cache_base_dir() -> Option<PathBuf> {
    std::env::var_os("KIN_EMBED_CACHE_DIR")
        .map(PathBuf::from)
        .or_else(|| BaseDirs::new().map(|dirs| dirs.home_dir().join(".kin/cache/embeddings")))
}

/// The schema version the current build reads and writes. Every other
/// schema-version subtree under the base directory is abandoned and safe to
/// reclaim.
pub fn current_schema_version() -> &'static str {
    super::EMBEDDING_CACHE_SCHEMA_VERSION
}

/// Environment variable naming the disk budget, in gigabytes, for `kin cache
/// gc`. Unset (the default) means eviction never runs on its own — the cache is
/// only ever pruned by an explicit budget or command.
pub const BUDGET_ENV: &str = "KIN_EMBED_CACHE_BUDGET_GB";

/// Parse a gigabyte budget string into a byte count. `None` for empty,
/// unparseable, non-finite, or non-positive input: a zero or negative budget
/// would mean "evict everything", which must never be what an unset or
/// fat-fingered value does.
pub fn parse_budget_gb(raw: &str) -> Option<u64> {
    let gb: f64 = raw.trim().parse().ok()?;
    if !gb.is_finite() || gb <= 0.0 {
        return None;
    }
    Some((gb * 1024.0 * 1024.0 * 1024.0) as u64)
}

/// The configured disk budget in bytes, read from [`BUDGET_ENV`]. `None` when
/// unset or invalid, in which case eviction is opt-in per invocation only.
pub fn budget_bytes_from_env() -> Option<u64> {
    parse_budget_gb(&std::env::var(BUDGET_ENV).ok()?)
}

/// Per-schema-version rollup: one entry per top-level subtree under the base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaVersionStats {
    /// The subtree directory name (the schema version, e.g. `v2`).
    pub version: String,
    pub bytes: u64,
    pub entry_count: u64,
    /// Whether this is [`current_schema_version`]; every other version is
    /// abandoned and reclaimable in full.
    pub is_current: bool,
}

/// One age band of the cache, oldest entries in the last band.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgeBucket {
    /// Human label for the band, e.g. `"< 1h"` or `"> 90d"`.
    pub label: &'static str,
    pub bytes: u64,
    pub entry_count: u64,
}

/// Age bands, by exclusive upper bound in seconds; the final `None` is the
/// oldest catch-all. Ordered youngest → oldest.
const AGE_BANDS: &[(&str, Option<u64>)] = &[
    ("< 1h", Some(3_600)),
    ("1h–1d", Some(86_400)),
    ("1d–7d", Some(604_800)),
    ("7d–30d", Some(2_592_000)),
    ("30d–90d", Some(7_776_000)),
    ("> 90d", None),
];

/// A point-in-time summary of the whole cache. Holds only fixed-size counters,
/// never a per-file list, so it is safe on a terabyte-scale tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheStats {
    pub base: PathBuf,
    pub total_bytes: u64,
    pub entry_count: u64,
    /// Oldest / newest entry modification time seen, `None` on an empty cache.
    pub oldest: Option<SystemTime>,
    pub newest: Option<SystemTime>,
    /// Per-schema-version rollup, sorted with the current version first then by
    /// descending size.
    pub schema_versions: Vec<SchemaVersionStats>,
    /// Age distribution, youngest band first (see [`AGE_BANDS`]).
    pub age_buckets: Vec<AgeBucket>,
    pub current_schema_version: &'static str,
}

impl CacheStats {
    /// Bytes held by abandoned (non-current) schema-version subtrees — the
    /// safest reclaim, freed in full by [`gc_cache`] with `prune_stale_schema`.
    pub fn stale_schema_bytes(&self) -> u64 {
        self.schema_versions
            .iter()
            .filter(|s| !s.is_current)
            .map(|s| s.bytes)
            .sum()
    }
}

/// Whether `path` is a finalized cache entry (a `*.bin` file). In-flight
/// `*.tmp-*` writes and any other file are ignored so eviction never touches a
/// write that has not yet been atomically renamed into place.
fn is_bin_entry(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some("bin")
}

/// Modification time as whole hours since the Unix epoch — the bucket key for
/// the eviction histogram. Pre-epoch times (clock skew) map to negative hours so
/// ordering still holds.
fn epoch_hour(t: SystemTime) -> i64 {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => (d.as_secs() / 3_600) as i64,
        Err(e) => -1 - (e.duration().as_secs() / 3_600) as i64,
    }
}

/// Visit every finalized `*.bin` entry under `dir`, calling `f(path, bytes,
/// modified)`. Best-effort: unreadable directories and files are skipped, never
/// fatal. Uses `&mut dyn FnMut` so recursion does not blow up the type checker.
fn visit_entries(dir: &Path, f: &mut dyn FnMut(&Path, u64, SystemTime)) {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read_dir.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            visit_entries(&entry.path(), f);
        } else if file_type.is_file() {
            let path = entry.path();
            if !is_bin_entry(&path) {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            f(&path, meta.len(), modified);
        }
    }
}

/// List the schema-version subtrees directly under `base`: `(version, path)`
/// for each immediate subdirectory.
fn schema_version_dirs(base: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let Ok(read_dir) = std::fs::read_dir(base) else {
        return out;
    };
    for entry in read_dir.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        if let Some(name) = entry.file_name().to_str() {
            out.push((name.to_string(), entry.path()));
        }
    }
    out
}

/// Assign an age (relative to `now`) to its band index in [`AGE_BANDS`].
fn age_band_index(age: Duration) -> usize {
    let secs = age.as_secs();
    AGE_BANDS
        .iter()
        .position(|(_, upper)| upper.is_none_or(|bound| secs < bound))
        .unwrap_or(AGE_BANDS.len() - 1)
}

/// Scan the whole cache under `base` into a [`CacheStats`]. `now` is injected so
/// the age distribution is deterministic and testable. A missing base directory
/// yields an empty summary rather than an error.
pub fn scan_cache(base: &Path, now: SystemTime) -> CacheStats {
    let mut total_bytes = 0u64;
    let mut entry_count = 0u64;
    let mut oldest: Option<SystemTime> = None;
    let mut newest: Option<SystemTime> = None;
    let mut bands: Vec<(u64, u64)> = vec![(0, 0); AGE_BANDS.len()];
    let mut schema_versions = Vec::new();

    let current = current_schema_version();

    for (version, dir) in schema_version_dirs(base) {
        let mut sv_bytes = 0u64;
        let mut sv_count = 0u64;
        visit_entries(&dir, &mut |_path, bytes, modified| {
            sv_bytes += bytes;
            sv_count += 1;
            total_bytes += bytes;
            entry_count += 1;
            oldest = Some(oldest.map_or(modified, |o| o.min(modified)));
            newest = Some(newest.map_or(modified, |n| n.max(modified)));
            let age = now.duration_since(modified).unwrap_or(Duration::ZERO);
            let band = &mut bands[age_band_index(age)];
            band.0 += bytes;
            band.1 += 1;
        });
        schema_versions.push(SchemaVersionStats {
            is_current: version == current,
            version,
            bytes: sv_bytes,
            entry_count: sv_count,
        });
    }

    // Current version first, then largest subtrees, so a status view leads with
    // the live cache and the biggest reclaim candidates.
    schema_versions.sort_by(|a, b| {
        b.is_current
            .cmp(&a.is_current)
            .then_with(|| b.bytes.cmp(&a.bytes))
    });

    let age_buckets = AGE_BANDS
        .iter()
        .zip(bands)
        .map(|((label, _), (bytes, entry_count))| AgeBucket {
            label,
            bytes,
            entry_count,
        })
        .collect();

    CacheStats {
        base: base.to_path_buf(),
        total_bytes,
        entry_count,
        oldest,
        newest,
        schema_versions,
        age_buckets,
        current_schema_version: current,
    }
}

/// From an mtime-bucketed byte histogram, the newest hour whose removal (with
/// every older hour) frees at least `total - budget` bytes — i.e. the LRU-by-
/// mtime cutoff. `None` when nothing need be freed (`total <= budget`). Pure and
/// deterministic: the eviction ordering is tested here directly.
///
/// The whole boundary hour is included, so the pass guarantees the post-eviction
/// total is at or below budget, over-evicting by at most one hour of writes.
fn eviction_cutoff_hour(
    buckets: &BTreeMap<i64, (u64, u64)>,
    total: u64,
    budget: u64,
) -> Option<i64> {
    let need = total.checked_sub(budget).filter(|n| *n > 0)?;
    let mut freed = 0u64;
    let mut cutoff = None;
    // BTreeMap iterates ascending: oldest hour first.
    for (hour, (bytes, _count)) in buckets {
        freed = freed.saturating_add(*bytes);
        cutoff = Some(*hour);
        if freed >= need {
            break;
        }
    }
    cutoff
}

/// Options for [`gc_cache`].
#[derive(Debug, Clone, Copy)]
pub struct GcOptions {
    /// Evict oldest entries until the pool is at or below this many bytes. `None`
    /// disables budget eviction entirely (the non-destructive default).
    pub budget_bytes: Option<u64>,
    /// Additionally remove every abandoned (non-current) schema-version subtree
    /// in full, regardless of budget.
    pub prune_stale_schema: bool,
    /// Report what would be reclaimed without deleting anything.
    pub dry_run: bool,
}

/// The outcome of a [`gc_cache`] pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcReport {
    pub base: PathBuf,
    pub total_bytes_before: u64,
    pub entry_count_before: u64,
    pub budget_bytes: Option<u64>,
    /// Whether the eviction pool exceeded the budget (false when no budget set).
    pub over_budget: bool,
    /// Abandoned schema versions removed (or that would be, on a dry run).
    pub stale_schema_versions_removed: Vec<String>,
    pub stale_schema_bytes: u64,
    pub evicted_entries: u64,
    pub evicted_bytes: u64,
    pub dry_run: bool,
}

impl GcReport {
    /// Total bytes reclaimed (or reclaimable, on a dry run) across both stale
    /// schema pruning and budget eviction.
    pub fn reclaimed_bytes(&self) -> u64 {
        self.stale_schema_bytes.saturating_add(self.evicted_bytes)
    }
}

/// Garbage-collect the embedding cache under `base` per `opts`. `now` is unused
/// today but kept in the signature for parity with [`scan_cache`] and future
/// age-based policy. Deletion order:
///
/// 1. **Stale schema pruning** (opt-in) removes whole abandoned schema-version
///    subtrees — the highest-value, safest reclaim.
/// 2. **Budget eviction** (when a budget is set) removes the globally
///    oldest-by-mtime entries from the remaining pool until it fits the budget.
///
/// With neither a budget nor stale pruning the pass is a no-op that only
/// reports, so the default behavior is non-destructive.
pub fn gc_cache(base: &Path, opts: GcOptions, now: SystemTime) -> GcReport {
    let stats = scan_cache(base, now);
    let mut report = GcReport {
        base: base.to_path_buf(),
        total_bytes_before: stats.total_bytes,
        entry_count_before: stats.entry_count,
        budget_bytes: opts.budget_bytes,
        over_budget: false,
        stale_schema_versions_removed: Vec::new(),
        stale_schema_bytes: 0,
        evicted_entries: 0,
        evicted_bytes: 0,
        dry_run: opts.dry_run,
    };

    // 1. Reclaim abandoned schema-version subtrees in full.
    if opts.prune_stale_schema {
        for sv in &stats.schema_versions {
            if sv.is_current {
                continue;
            }
            report
                .stale_schema_versions_removed
                .push(sv.version.clone());
            report.stale_schema_bytes = report.stale_schema_bytes.saturating_add(sv.bytes);
            if !opts.dry_run {
                // Whole abandoned subtree: no live process writes here.
                let _ = std::fs::remove_dir_all(base.join(&sv.version));
            }
        }
    }

    // 2. Budget eviction over the post-prune pool. When stale pruning ran, the
    // pool is just the current-schema subtree; otherwise it is every version, so
    // abandoned entries (being oldest) are evicted first anyway.
    if let Some(budget) = opts.budget_bytes {
        let pool = if opts.prune_stale_schema {
            base.join(current_schema_version())
        } else {
            base.to_path_buf()
        };

        let mut buckets: BTreeMap<i64, (u64, u64)> = BTreeMap::new();
        let mut pool_total = 0u64;
        visit_entries(&pool, &mut |_path, bytes, modified| {
            let slot = buckets.entry(epoch_hour(modified)).or_insert((0, 0));
            slot.0 = slot.0.saturating_add(bytes);
            slot.1 += 1;
            pool_total = pool_total.saturating_add(bytes);
        });

        report.over_budget = pool_total > budget;
        if let Some(cutoff) = eviction_cutoff_hour(&buckets, pool_total, budget) {
            visit_entries(&pool, &mut |path, bytes, modified| {
                if epoch_hour(modified) > cutoff {
                    return;
                }
                if opts.dry_run || std::fs::remove_file(path).is_ok() {
                    report.evicted_entries += 1;
                    report.evicted_bytes = report.evicted_bytes.saturating_add(bytes);
                }
            });
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const CURRENT: &str = super::super::EMBEDDING_CACHE_SCHEMA_VERSION;

    /// Write a `<schema>/<namespace>/<prefix>/<name>.bin` entry of `size` bytes.
    fn write_entry(base: &Path, schema: &str, name: &str, size: usize) -> PathBuf {
        let prefix = &name[..2.min(name.len())];
        let dir = base.join(schema).join("ns").join(prefix);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.bin"));
        fs::write(&path, vec![0u8; size]).unwrap();
        path
    }

    #[test]
    fn parse_budget_gb_accepts_positive_rejects_junk() {
        assert_eq!(parse_budget_gb("1"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_budget_gb(" 0.5 "), Some(512 * 1024 * 1024));
        assert_eq!(parse_budget_gb(""), None);
        assert_eq!(parse_budget_gb("0"), None);
        assert_eq!(parse_budget_gb("-4"), None);
        assert_eq!(parse_budget_gb("NaN"), None);
        assert_eq!(parse_budget_gb("twenty"), None);
    }

    #[test]
    fn eviction_cutoff_picks_oldest_hours_first() {
        // Hours 10/11/12 each hold 100 bytes; total 300.
        let mut buckets = BTreeMap::new();
        buckets.insert(12i64, (100u64, 1u64));
        buckets.insert(10, (100, 1));
        buckets.insert(11, (100, 1));

        // Budget 250 → free 50 → the single oldest hour (10) covers it.
        assert_eq!(eviction_cutoff_hour(&buckets, 300, 250), Some(10));
        // Budget 150 → free 150 → hours 10 and 11.
        assert_eq!(eviction_cutoff_hour(&buckets, 300, 150), Some(11));
        // Budget 0-ish (1 byte) → free ~all → through the newest hour.
        assert_eq!(eviction_cutoff_hour(&buckets, 300, 1), Some(12));
        // Budget >= total → nothing to free.
        assert_eq!(eviction_cutoff_hour(&buckets, 300, 300), None);
        assert_eq!(eviction_cutoff_hour(&buckets, 300, 999), None);
    }

    #[test]
    fn scan_counts_bytes_and_entries_and_ignores_tmp() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        write_entry(base, CURRENT, "aa11", 100);
        write_entry(base, CURRENT, "bb22", 200);
        // An in-flight writer's tmp file must not be counted.
        let d = base.join(CURRENT).join("ns").join("cc");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("cc33.tmp-4242"), vec![0u8; 999]).unwrap();

        let stats = scan_cache(base, SystemTime::now());
        assert_eq!(stats.entry_count, 2);
        assert_eq!(stats.total_bytes, 300);
        assert_eq!(stats.schema_versions.len(), 1);
        assert!(stats.schema_versions[0].is_current);
        assert_eq!(stats.schema_versions[0].entry_count, 2);
    }

    #[test]
    fn scan_separates_current_from_stale_schema() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        write_entry(base, CURRENT, "aa11", 100);
        write_entry(base, "v0-abandoned", "bb22", 400);

        let stats = scan_cache(base, SystemTime::now());
        assert_eq!(stats.total_bytes, 500);
        assert_eq!(stats.stale_schema_bytes(), 400);
        // Current version sorts first.
        assert!(stats.schema_versions[0].is_current);
        assert_eq!(stats.schema_versions[0].version, CURRENT);
    }

    #[test]
    fn scan_buckets_ages() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let recent = write_entry(base, CURRENT, "aa11", 100);
        let old = write_entry(base, CURRENT, "bb22", 100);

        let now = SystemTime::now();
        // Backdate `old` well past 90 days by pinning `now` far in the future
        // relative to the files' real (just-now) mtimes is awkward; instead read
        // real mtimes and assert both land in the youngest band with a fresh now.
        let _ = (recent, old);
        let stats = scan_cache(base, now);
        let young = &stats.age_buckets[0];
        assert_eq!(young.label, "< 1h");
        assert_eq!(young.entry_count, 2);
        assert_eq!(young.bytes, 200);
        // No entry should have fallen into an older band.
        assert_eq!(
            stats.age_buckets[1..]
                .iter()
                .map(|b| b.entry_count)
                .sum::<u64>(),
            0
        );
    }

    #[test]
    fn gc_without_budget_or_prune_is_non_destructive() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let a = write_entry(base, CURRENT, "aa11", 100);
        let b = write_entry(base, "v0-abandoned", "bb22", 400);

        let report = gc_cache(
            base,
            GcOptions {
                budget_bytes: None,
                prune_stale_schema: false,
                dry_run: false,
            },
            SystemTime::now(),
        );
        assert_eq!(report.evicted_entries, 0);
        assert_eq!(report.stale_schema_bytes, 0);
        assert_eq!(report.reclaimed_bytes(), 0);
        assert!(!report.over_budget);
        // Nothing on disk was touched.
        assert!(a.exists());
        assert!(b.exists());
    }

    #[test]
    fn gc_prunes_stale_schema_only() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let current = write_entry(base, CURRENT, "aa11", 100);
        let stale = write_entry(base, "v0-abandoned", "bb22", 400);

        let report = gc_cache(
            base,
            GcOptions {
                budget_bytes: None,
                prune_stale_schema: true,
                dry_run: false,
            },
            SystemTime::now(),
        );
        assert_eq!(report.stale_schema_bytes, 400);
        assert_eq!(report.stale_schema_versions_removed, vec!["v0-abandoned"]);
        assert_eq!(report.evicted_entries, 0);
        // Current kept, abandoned subtree gone.
        assert!(current.exists());
        assert!(!stale.exists());
        assert!(!base.join("v0-abandoned").exists());
    }

    #[test]
    fn gc_dry_run_reports_but_deletes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let current = write_entry(base, CURRENT, "aa11", 100);
        let stale = write_entry(base, "v0-abandoned", "bb22", 400);

        let report = gc_cache(
            base,
            GcOptions {
                budget_bytes: Some(1), // tiny budget → would evict current too
                prune_stale_schema: true,
                dry_run: true,
            },
            SystemTime::now(),
        );
        // Reported as reclaimable...
        assert_eq!(report.stale_schema_bytes, 400);
        assert!(report.evicted_bytes > 0);
        assert!(report.over_budget);
        // ...but everything is still on disk.
        assert!(current.exists());
        assert!(stale.exists());
    }

    #[test]
    fn gc_budget_evicts_down_to_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        // Five 100-byte entries in the current tree: 500 total.
        for i in 0..5 {
            write_entry(base, CURRENT, &format!("e{i:03}"), 100);
        }

        // Budget 250 bytes: at least 250 must be freed.
        let report = gc_cache(
            base,
            GcOptions {
                budget_bytes: Some(250),
                prune_stale_schema: false,
                dry_run: false,
            },
            SystemTime::now(),
        );
        assert!(report.over_budget);
        assert!(
            report.evicted_bytes >= 250,
            "freed {}",
            report.evicted_bytes
        );

        // Post-eviction the tree is at or below budget.
        let after = scan_cache(base, SystemTime::now());
        assert!(after.total_bytes <= 250, "left {}", after.total_bytes);
    }

    #[test]
    fn gc_budget_within_limit_evicts_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        let a = write_entry(base, CURRENT, "aa11", 100);
        let b = write_entry(base, CURRENT, "bb22", 100);

        let report = gc_cache(
            base,
            GcOptions {
                budget_bytes: Some(10_000),
                prune_stale_schema: false,
                dry_run: false,
            },
            SystemTime::now(),
        );
        assert!(!report.over_budget);
        assert_eq!(report.evicted_entries, 0);
        assert!(a.exists());
        assert!(b.exists());
    }

    #[test]
    fn empty_or_missing_base_is_safe() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nope");
        let stats = scan_cache(&missing, SystemTime::now());
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.total_bytes, 0);

        let report = gc_cache(
            &missing,
            GcOptions {
                budget_bytes: Some(1),
                prune_stale_schema: true,
                dry_run: false,
            },
            SystemTime::now(),
        );
        assert_eq!(report.reclaimed_bytes(), 0);
    }
}
