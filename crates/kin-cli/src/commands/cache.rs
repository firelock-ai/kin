// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin cache` — inspect and bound the on-disk embedding cache.
//!
//! kin-db writes embedding vectors under `~/.kin/cache/embeddings` (or
//! `$KIN_EMBED_CACHE_DIR`) and never evicts from the disk layer, so on a heavy
//! bench/proof machine that tree grows without bound. These subcommands are the
//! operator surface over the capacity policy that lives in
//! [`kin_db::embed::cache_admin`]:
//!
//! - `kin cache status` reports size, entry count, per-schema-version breakdown,
//!   and an age distribution, and warns loudly when a configured budget is
//!   exceeded. It names the directory it is about to read before reading it and
//!   streams entry counts as it walks, because on a bench-scale cache the walk
//!   runs for minutes and a silent command is indistinguishable from a hang.
//! - `kin cache gc` reclaims space: it can drop abandoned schema-version
//!   subtrees and evict the oldest entries down to a byte budget.
//!
//! Eviction is **non-destructive by default**: with no budget configured (via
//! `--budget-gb` or `KIN_EMBED_CACHE_BUDGET_GB`) and without
//! `--prune-stale-schema`, `kin cache gc` deletes nothing and only reports. All
//! deletion removes whole finalized entries (or whole abandoned subtrees), so a
//! concurrent reader either sees the entry or takes a cache miss — never a
//! corrupt read.

#[cfg(feature = "embeddings")]
use std::path::{Path, PathBuf};
#[cfg(feature = "embeddings")]
use std::time::{Duration, SystemTime};

use anyhow::Result;

#[cfg(feature = "embeddings")]
use kin_db::embed::cache_admin::{
    self, AgeBucket, CacheStats, GcOptions, GcReport, SchemaVersionStats,
};

/// Render a byte count as a short human-readable string.
#[cfg(feature = "embeddings")]
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

/// Render a duration as a coarse age string (`3d`, `2h`, `5m`, `10s`).
#[cfg(feature = "embeddings")]
fn human_age(age: Duration) -> String {
    let secs = age.as_secs();
    if secs >= 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs >= 3_600 {
        format!("{}h", secs / 3_600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// Age of `t` relative to `now`, clamped at zero for clock skew.
#[cfg(feature = "embeddings")]
fn age_of(t: SystemTime, now: SystemTime) -> Duration {
    now.duration_since(t).unwrap_or(Duration::ZERO)
}

/// Convert a `--budget-gb` flag / env value in gigabytes to bytes, rejecting
/// non-positive or non-finite input the same way the env parser does.
#[cfg(feature = "embeddings")]
fn budget_gb_to_bytes(gb: f64) -> Option<u64> {
    if !gb.is_finite() || gb <= 0.0 {
        return None;
    }
    Some((gb * 1024.0 * 1024.0 * 1024.0) as u64)
}

/// Resolve the effective budget in bytes: an explicit `--budget-gb` flag wins,
/// otherwise the `KIN_EMBED_CACHE_BUDGET_GB` environment default.
#[cfg(feature = "embeddings")]
fn resolve_budget(budget_gb: Option<f64>) -> Option<u64> {
    match budget_gb {
        Some(gb) => budget_gb_to_bytes(gb),
        None => cache_admin::budget_bytes_from_env(),
    }
}

/// Entries walked between progress reports. The walk is IO-bound on directory
/// reads, so reporting per entry would cost more than the scan; a report every
/// 25k entries puts several lines on a bench-scale cache and none on a small one.
#[cfg(feature = "embeddings")]
const SCAN_PROGRESS_INTERVAL: u64 = 25_000;

/// Age bands, by exclusive upper bound in seconds, youngest first.
///
/// A mirror of the private band table behind [`cache_admin::scan_cache`]. The
/// bands are duplicated rather than imported because the scan that owns them
/// takes no progress callback and cannot be bounded, and this command needs
/// both. [`streaming_scan_matches_the_kin_db_scan`] holds the two in agreement
/// by asserting the whole [`CacheStats`] is equal on a fixture, so a band that
/// changes upstream fails a test here rather than silently relabelling output.
#[cfg(feature = "embeddings")]
const AGE_BANDS: &[(&str, Option<u64>)] = &[
    ("< 1h", Some(3_600)),
    ("1h–1d", Some(86_400)),
    ("1d–7d", Some(604_800)),
    ("7d–30d", Some(2_592_000)),
    ("30d–90d", Some(7_776_000)),
    ("> 90d", None),
];

/// Whether a scan saw the whole cache or stopped at the caller's bound.
#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanBound {
    Complete,
    /// Stopped after `limit` entries; every total covers only those entries.
    Truncated { limit: u64 },
}

#[cfg(feature = "embeddings")]
impl ScanBound {
    fn is_complete(self) -> bool {
        self == ScanBound::Complete
    }
}

/// Assign an age to its band index in [`AGE_BANDS`].
#[cfg(feature = "embeddings")]
fn age_band_index(age: Duration) -> usize {
    let secs = age.as_secs();
    AGE_BANDS
        .iter()
        .position(|(_, upper)| upper.is_none_or(|bound| secs < bound))
        .unwrap_or(AGE_BANDS.len() - 1)
}

/// The schema-version subtrees directly under `base`, as `(version, path)`.
#[cfg(feature = "embeddings")]
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

/// Visit every finalized `*.bin` entry under `dir`, stopping once `remaining`
/// is exhausted. Returns false when the walk stopped early.
///
/// `truncated` is set only when an entry is actually refused, never merely
/// because the budget reached zero. A bound that lands exactly on the last
/// entry read the whole cache, and reporting that as partial would tell a
/// caller their totals understate a cache the walk had in fact finished.
///
/// Best-effort like the scan it mirrors: an unreadable directory or file is
/// skipped rather than fatal, so a cache with a stray permission is still
/// reportable. In-flight `*.tmp-*` writes are not entries and are ignored.
#[cfg(feature = "embeddings")]
fn visit_bounded(
    dir: &Path,
    remaining: &mut Option<u64>,
    truncated: &mut bool,
    f: &mut dyn FnMut(u64, SystemTime),
) -> bool {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return true;
    };
    for entry in read_dir.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            if !visit_bounded(&entry.path(), remaining, truncated, f) {
                return false;
            }
        } else if file_type.is_file() {
            if entry.path().extension().and_then(|e| e.to_str()) != Some("bin") {
                continue;
            }
            if remaining.is_some_and(|left| left == 0) {
                *truncated = true;
                return false;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            f(meta.len(), meta.modified().unwrap_or(SystemTime::UNIX_EPOCH));
            if let Some(left) = remaining.as_mut() {
                *left -= 1;
            }
        }
    }
    true
}

/// Scan the cache under `base`, calling `on_progress(entries, bytes)` every
/// [`SCAN_PROGRESS_INTERVAL`] entries and stopping after `limit` entries.
///
/// With `limit` unset this produces exactly what [`cache_admin::scan_cache`]
/// produces; the difference is that the caller can watch it and bound it.
#[cfg(feature = "embeddings")]
fn scan_cache_streaming(
    base: &Path,
    now: SystemTime,
    limit: Option<u64>,
    on_progress: &mut dyn FnMut(u64, u64),
) -> (CacheStats, ScanBound) {
    let mut total_bytes = 0u64;
    let mut entry_count = 0u64;
    let mut oldest: Option<SystemTime> = None;
    let mut newest: Option<SystemTime> = None;
    let mut bands: Vec<(u64, u64)> = vec![(0, 0); AGE_BANDS.len()];
    let mut schema_versions = Vec::new();
    let mut next_report = SCAN_PROGRESS_INTERVAL;

    let mut remaining = limit;
    let mut truncated = false;
    let mut walking = true;

    let current = cache_admin::current_schema_version();

    // Every subtree is still listed once the bound stops the walk, so the
    // schema-version rollup keeps naming the versions present on disk; only
    // their counts stop growing.
    for (version, dir) in schema_version_dirs(base) {
        let mut sv_bytes = 0u64;
        let mut sv_count = 0u64;
        if walking {
            walking = visit_bounded(&dir, &mut remaining, &mut truncated, &mut |bytes, modified| {
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
                if entry_count >= next_report {
                    on_progress(entry_count, total_bytes);
                    next_report += SCAN_PROGRESS_INTERVAL;
                }
            });
        }
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

    let stats = CacheStats {
        base: base.to_path_buf(),
        total_bytes,
        entry_count,
        oldest,
        newest,
        schema_versions,
        age_buckets,
        current_schema_version: current,
    };
    let bound = match limit {
        Some(limit) if truncated => ScanBound::Truncated { limit },
        _ => ScanBound::Complete,
    };
    (stats, bound)
}

/// `kin cache status [--json] [--limit N]` — report cache size, composition,
/// and age.
///
/// The resolved directory is named before the walk starts and entry counts
/// stream to stderr as it proceeds. Both exist because this walk is unbounded
/// by nature: the cache is never evicted from disk, so on a proof machine it
/// reaches hundreds of thousands of entries and the scan runs for minutes.
/// Printing only on completion made the command indistinguishable from a hang,
/// on the command `kin cache gc` recommends by name.
#[cfg(feature = "embeddings")]
pub async fn status(json: bool, limit: Option<u64>) -> Result<()> {
    use std::io::Write;

    let Some(base) = cache_admin::embedding_cache_base_dir() else {
        println!("kin cache status: no cache directory resolved (no home directory and KIN_EMBED_CACHE_DIR unset)");
        return Ok(());
    };

    // Name the tree before reading it. In JSON mode this goes to stderr so
    // stdout stays one parseable document.
    if json {
        eprintln!("kin cache status: scanning {}", base.display());
    } else {
        print_status_header(&base);
        let _ = std::io::stdout().flush();
    }

    let now = SystemTime::now();
    let mut progress = crate::progress::Progress::stderr();
    let mut reported = false;
    let (stats, bound) = scan_cache_streaming(&base, now, limit, &mut |entries, bytes| {
        reported = true;
        progress.update(format_args!(
            "scanned {entries} entries, {} so far",
            human_bytes(bytes)
        ));
    });
    if reported {
        progress.finish();
    }

    let budget = cache_admin::budget_bytes_from_env();
    if json {
        print_status_json(&stats, budget, now, bound);
    } else {
        print_status_body(&stats, budget, now, bound);
    }
    Ok(())
}

#[cfg(not(feature = "embeddings"))]
pub async fn status(_json: bool, _limit: Option<u64>) -> Result<()> {
    anyhow::bail!(
        "embedding cache management is unsupported in this build; install a Kin build with embedding support"
    )
}

/// The part of the human report that is known before the walk: what is being
/// read. Printed and flushed first so a long scan is attributable to a path.
#[cfg(feature = "embeddings")]
fn print_status_header(base: &Path) {
    println!("kin cache status");
    println!("  location: {}", base.display());
}

#[cfg(feature = "embeddings")]
fn print_status_body(
    stats: &CacheStats,
    budget: Option<u64>,
    now: SystemTime,
    bound: ScanBound,
) {
    if let ScanBound::Truncated { limit } = bound {
        println!(
            "  WARNING: stopped at the --limit of {limit} entries; every number below covers \
             only those entries and understates the cache"
        );
    }

    if stats.entry_count == 0 {
        println!("  cache is empty");
    } else {
        println!(
            "  size:     {} across {} entr{}",
            human_bytes(stats.total_bytes),
            stats.entry_count,
            if stats.entry_count == 1 { "y" } else { "ies" }
        );
        if let (Some(oldest), Some(newest)) = (stats.oldest, stats.newest) {
            println!(
                "  age:      oldest {}, newest {}",
                human_age(age_of(oldest, now)),
                human_age(age_of(newest, now))
            );
        }

        println!(
            "  schema versions (current is {}):",
            stats.current_schema_version
        );
        for sv in &stats.schema_versions {
            let tag = if sv.is_current {
                "current".to_string()
            } else {
                "stale — reclaim with: kin cache gc --prune-stale-schema".to_string()
            };
            println!(
                "    {:<20} {:>10}  {:>12} entries  ({tag})",
                sv.version,
                human_bytes(sv.bytes),
                sv.entry_count
            );
        }

        println!("  age distribution:");
        for bucket in &stats.age_buckets {
            if bucket.entry_count == 0 {
                continue;
            }
            println!(
                "    {:<8} {:>10}  {:>12} entries",
                bucket.label,
                human_bytes(bucket.bytes),
                bucket.entry_count
            );
        }
    }

    match budget {
        Some(budget_bytes) => {
            println!(
                "  budget:   {} ({})",
                human_bytes(budget_bytes),
                cache_admin::BUDGET_ENV
            );
            if stats.total_bytes > budget_bytes {
                let over = stats.total_bytes - budget_bytes;
                println!(
                    "  WARNING: cache is OVER BUDGET by {} — run `kin cache gc` to reclaim space",
                    human_bytes(over)
                );
            } else {
                println!("  within budget");
            }
        }
        None => {
            println!(
                "  budget:   not set — eviction is opt-in (set {} or pass `kin cache gc --budget-gb N`)",
                cache_admin::BUDGET_ENV
            );
        }
    }
}

#[cfg(feature = "embeddings")]
fn print_status_json(
    stats: &CacheStats,
    budget: Option<u64>,
    now: SystemTime,
    bound: ScanBound,
) {
    let schema_versions: Vec<_> = stats
        .schema_versions
        .iter()
        .map(|sv| {
            serde_json::json!({
                "version": sv.version,
                "bytes": sv.bytes,
                "entry_count": sv.entry_count,
                "is_current": sv.is_current,
            })
        })
        .collect();
    let age_buckets: Vec<_> = stats
        .age_buckets
        .iter()
        .map(|b| {
            serde_json::json!({
                "label": b.label,
                "bytes": b.bytes,
                "entry_count": b.entry_count,
            })
        })
        .collect();
    let payload = serde_json::json!({
        "base": stats.base.display().to_string(),
        "total_bytes": stats.total_bytes,
        "entry_count": stats.entry_count,
        "oldest_age_secs": stats.oldest.map(|t| age_of(t, now).as_secs()),
        "newest_age_secs": stats.newest.map(|t| age_of(t, now).as_secs()),
        "current_schema_version": stats.current_schema_version,
        "stale_schema_bytes": stats.stale_schema_bytes(),
        "schema_versions": schema_versions,
        "age_buckets": age_buckets,
        "budget_bytes": budget,
        "over_budget": budget.is_some_and(|b| stats.total_bytes > b),
        // A bounded scan reports real numbers for a subset of the cache, which
        // reads exactly like a small cache unless the document says otherwise.
        "scan_complete": bound.is_complete(),
        "scan_limit": match bound {
            ScanBound::Truncated { limit } => Some(limit),
            ScanBound::Complete => None,
        },
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    );
}

/// `kin cache gc [--dry-run] [--budget-gb N] [--prune-stale-schema]` — reclaim
/// space from the embedding cache.
#[cfg(feature = "embeddings")]
pub async fn gc(dry_run: bool, budget_gb: Option<f64>, prune_stale_schema: bool) -> Result<()> {
    let Some(base) = cache_admin::embedding_cache_base_dir() else {
        println!("kin cache gc: no cache directory resolved (no home directory and KIN_EMBED_CACHE_DIR unset)");
        return Ok(());
    };

    let budget_bytes = resolve_budget(budget_gb);

    if budget_bytes.is_none() && !prune_stale_schema {
        println!("kin cache gc: nothing to do — non-destructive default.");
        println!(
            "  set a budget (`--budget-gb N` or {}) to evict oldest entries,",
            cache_admin::BUDGET_ENV
        );
        println!("  and/or pass `--prune-stale-schema` to drop abandoned schema-version subtrees.");
        println!("  `kin cache status` shows current size.");
        return Ok(());
    }

    let report = cache_admin::gc_cache(
        &base,
        GcOptions {
            budget_bytes,
            prune_stale_schema,
            dry_run,
        },
        SystemTime::now(),
    );

    print_gc_report(&report);
    Ok(())
}

#[cfg(not(feature = "embeddings"))]
pub async fn gc(_dry_run: bool, _budget_gb: Option<f64>, _prune_stale_schema: bool) -> Result<()> {
    anyhow::bail!(
        "embedding cache management is unsupported in this build; install a Kin build with embedding support"
    )
}

#[cfg(feature = "embeddings")]
fn print_gc_report(report: &GcReport) {
    let verb = if report.dry_run {
        "would reclaim"
    } else {
        "reclaimed"
    };
    println!(
        "kin cache gc{}: {} across the cache at {}",
        if report.dry_run { " (dry run)" } else { "" },
        human_bytes(report.total_bytes_before),
        report.base.display()
    );

    if !report.stale_schema_versions_removed.is_empty() {
        let verb = if report.dry_run {
            "would drop"
        } else {
            "dropped"
        };
        println!(
            "  {verb} {} abandoned schema version(s) [{}]: {}",
            report.stale_schema_versions_removed.len(),
            human_bytes(report.stale_schema_bytes),
            report.stale_schema_versions_removed.join(", ")
        );
    }

    if let Some(budget) = report.budget_bytes {
        if report.over_budget {
            let verb = if report.dry_run {
                "would evict"
            } else {
                "evicted"
            };
            println!(
                "  over budget ({}): {verb} {} oldest entr{} ({})",
                human_bytes(budget),
                report.evicted_entries,
                if report.evicted_entries == 1 {
                    "y"
                } else {
                    "ies"
                },
                human_bytes(report.evicted_bytes)
            );
        } else {
            println!(
                "  within budget ({}) — no entries evicted",
                human_bytes(budget)
            );
        }
    }

    println!(
        "kin cache gc: {verb} {} total{}",
        human_bytes(report.reclaimed_bytes()),
        if report.dry_run {
            ". Re-run without --dry-run to delete."
        } else {
            ""
        }
    );
}

#[cfg(all(test, not(feature = "embeddings")))]
mod unsupported_tests {
    #[tokio::test]
    async fn cache_commands_fail_loud_when_embeddings_are_disabled() {
        for result in [
            super::status(false, None).await,
            super::gc(true, None, false).await,
        ] {
            let message = result.expect_err("vector-free cache command must be unsupported");
            assert!(message.to_string().contains("unsupported in this build"));
        }
    }
}

#[cfg(all(test, feature = "embeddings"))]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_formats_units() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn human_age_formats_coarsely() {
        assert_eq!(human_age(Duration::from_secs(5)), "5s");
        assert_eq!(human_age(Duration::from_secs(120)), "2m");
        assert_eq!(human_age(Duration::from_secs(7_200)), "2h");
        assert_eq!(human_age(Duration::from_secs(3 * 86_400)), "3d");
    }

    /// Build a cache fixture: `base/<version>/<shard>/<name>.bin`, plus the
    /// non-entry files a real cache carries, so the walk has something to skip.
    fn fixture(entries: &[(&str, &str, u64)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for (version, name, bytes) in entries {
            let shard = dir.path().join(version).join(&name[..2]);
            std::fs::create_dir_all(&shard).expect("mkdir");
            std::fs::write(shard.join(format!("{name}.bin")), vec![0u8; *bytes as usize])
                .expect("write entry");
            // An in-flight write is not a finalized entry and must not count.
            std::fs::write(shard.join(format!("{name}.tmp-1")), b"partial").expect("write tmp");
        }
        dir
    }

    fn scan(base: &Path, limit: Option<u64>) -> (CacheStats, ScanBound) {
        scan_cache_streaming(base, SystemTime::now(), limit, &mut |_, _| {})
    }

    /// The streaming walk exists only because [`cache_admin::scan_cache`] takes
    /// no progress callback and cannot be bounded. It must otherwise agree with
    /// it exactly, including the age-band labels duplicated above. Comparing the
    /// whole struct is what makes this test able to fail: a band renamed or
    /// rebounded upstream, a changed sort, or a skipped file all break equality.
    #[test]
    fn streaming_scan_matches_the_kin_db_scan() {
        let dir = fixture(&[
            ("v2", "aaaa", 4_096),
            ("v2", "bbbb", 128),
            ("v1", "cccc", 1_024),
        ]);
        let now = SystemTime::now();

        let (streamed, bound) = scan_cache_streaming(dir.path(), now, None, &mut |_, _| {});
        let authoritative = cache_admin::scan_cache(dir.path(), now);

        assert_eq!(streamed, authoritative);
        assert_eq!(bound, ScanBound::Complete);
        assert_eq!(streamed.entry_count, 3, "the .tmp- writes must not count");
        assert_eq!(streamed.total_bytes, 4_096 + 128 + 1_024);
    }

    /// An empty cache is a complete scan of nothing, not a truncated one.
    #[test]
    fn an_empty_cache_scans_complete() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (stats, bound) = scan(dir.path(), None);
        assert_eq!(stats.entry_count, 0);
        assert_eq!(bound, ScanBound::Complete);
        assert_eq!(stats, cache_admin::scan_cache(dir.path(), SystemTime::now()));
    }

    /// The bound stops the walk and says so. Without the [`ScanBound`] the
    /// partial totals are indistinguishable from a small cache.
    #[test]
    fn a_limit_stops_the_walk_and_reports_itself_as_partial() {
        let dir = fixture(&[
            ("v2", "aaaa", 100),
            ("v2", "bbbb", 100),
            ("v2", "cccc", 100),
            ("v2", "dddd", 100),
        ]);

        let (stats, bound) = scan(dir.path(), Some(2));
        assert_eq!(bound, ScanBound::Truncated { limit: 2 });
        assert_eq!(stats.entry_count, 2);
        assert_eq!(stats.total_bytes, 200);

        // A bound landing exactly on the last entry read the whole cache. This
        // is the case the budget-exhausted reading gets wrong, and calling it
        // partial would understate a total that is in fact exact.
        let (full, bound) = scan(dir.path(), Some(4));
        assert_eq!(bound, ScanBound::Complete);
        assert_eq!(full.entry_count, 4);
        assert_eq!(full, scan(dir.path(), None).0);
        let (over, bound) = scan(dir.path(), Some(99));
        assert_eq!(bound, ScanBound::Complete);
        assert_eq!(over.entry_count, 4);

        // Zero reads nothing, and must not pass itself off as a complete scan.
        let (none, bound) = scan(dir.path(), Some(0));
        assert_eq!(bound, ScanBound::Truncated { limit: 0 });
        assert_eq!(none.entry_count, 0);

        // But zero against an empty cache IS complete: nothing was refused.
        let empty = tempfile::tempdir().expect("tempdir");
        assert_eq!(scan(empty.path(), Some(0)).1, ScanBound::Complete);
    }

    /// Progress has to arrive while the walk is running, which is the whole
    /// point: the command was unusable because it printed only on completion.
    #[test]
    fn progress_reports_during_the_walk_and_counts_up() {
        let entries: Vec<(String, u64)> = (0..SCAN_PROGRESS_INTERVAL * 2 + 10)
            .map(|i| (format!("{i:08x}"), 1))
            .collect();
        let dir = tempfile::tempdir().expect("tempdir");
        let shard = dir.path().join("v2").join("sh");
        std::fs::create_dir_all(&shard).expect("mkdir");
        for (name, _) in &entries {
            std::fs::write(shard.join(format!("{name}.bin")), b"x").expect("write");
        }

        let mut seen: Vec<(u64, u64)> = Vec::new();
        let (stats, _) = scan_cache_streaming(
            dir.path(),
            SystemTime::now(),
            None,
            &mut |count, bytes| seen.push((count, bytes)),
        );

        assert_eq!(
            seen.len(),
            2,
            "one report per {SCAN_PROGRESS_INTERVAL} entries: {seen:?}"
        );
        assert_eq!(seen[0].0, SCAN_PROGRESS_INTERVAL);
        assert_eq!(seen[1].0, SCAN_PROGRESS_INTERVAL * 2);
        assert!(
            seen[0].0 < stats.entry_count,
            "the first report must land before the walk ends"
        );
        assert!(seen[1].1 > seen[0].1, "bytes must accumulate: {seen:?}");
    }

    #[test]
    fn budget_flag_overrides_and_validates() {
        assert_eq!(budget_gb_to_bytes(1.0), Some(1024 * 1024 * 1024));
        assert_eq!(budget_gb_to_bytes(0.0), None);
        assert_eq!(budget_gb_to_bytes(-1.0), None);
        assert_eq!(budget_gb_to_bytes(f64::NAN), None);
        // Explicit flag wins over env resolution.
        assert_eq!(resolve_budget(Some(2.0)), Some(2 * 1024 * 1024 * 1024));
    }
}
