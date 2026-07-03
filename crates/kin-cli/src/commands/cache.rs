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
//!   exceeded.
//! - `kin cache gc` reclaims space: it can drop abandoned schema-version
//!   subtrees and evict the oldest entries down to a byte budget.
//!
//! Eviction is **non-destructive by default**: with no budget configured (via
//! `--budget-gb` or `KIN_EMBED_CACHE_BUDGET_GB`) and without
//! `--prune-stale-schema`, `kin cache gc` deletes nothing and only reports. All
//! deletion removes whole finalized entries (or whole abandoned subtrees), so a
//! concurrent reader either sees the entry or takes a cache miss — never a
//! corrupt read.

use std::time::{Duration, SystemTime};

use anyhow::Result;

use kin_db::embed::cache_admin::{self, CacheStats, GcOptions, GcReport};

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

/// Render a duration as a coarse age string (`3d`, `2h`, `5m`, `10s`).
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
fn age_of(t: SystemTime, now: SystemTime) -> Duration {
    now.duration_since(t).unwrap_or(Duration::ZERO)
}

/// Convert a `--budget-gb` flag / env value in gigabytes to bytes, rejecting
/// non-positive or non-finite input the same way the env parser does.
fn budget_gb_to_bytes(gb: f64) -> Option<u64> {
    if !gb.is_finite() || gb <= 0.0 {
        return None;
    }
    Some((gb * 1024.0 * 1024.0 * 1024.0) as u64)
}

/// Resolve the effective budget in bytes: an explicit `--budget-gb` flag wins,
/// otherwise the `KIN_EMBED_CACHE_BUDGET_GB` environment default.
fn resolve_budget(budget_gb: Option<f64>) -> Option<u64> {
    match budget_gb {
        Some(gb) => budget_gb_to_bytes(gb),
        None => cache_admin::budget_bytes_from_env(),
    }
}

/// `kin cache status [--json]` — report cache size, composition, and age.
pub async fn status(json: bool) -> Result<()> {
    let Some(base) = cache_admin::embedding_cache_base_dir() else {
        println!("kin cache status: no cache directory resolved (no home directory and KIN_EMBED_CACHE_DIR unset)");
        return Ok(());
    };

    let now = SystemTime::now();
    let stats = cache_admin::scan_cache(&base, now);
    let budget = cache_admin::budget_bytes_from_env();

    if json {
        print_status_json(&stats, budget, now);
    } else {
        print_status_human(&stats, budget, now);
    }
    Ok(())
}

fn print_status_human(stats: &CacheStats, budget: Option<u64>, now: SystemTime) {
    println!("kin cache status");
    println!("  location: {}", stats.base.display());

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

fn print_status_json(stats: &CacheStats, budget: Option<u64>, now: SystemTime) {
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
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    );
}

/// `kin cache gc [--dry-run] [--budget-gb N] [--prune-stale-schema]` — reclaim
/// space from the embedding cache.
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

#[cfg(test)]
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
