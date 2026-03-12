use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::BenchmarkArm;
use super::shim_log::ShimLogEntry;
use crate::error::{BenchError, Result};

/// Return the canonical shim log file path for a given arm directory.
/// The file is placed inside `.bench-home/` to keep it co-located with
/// other benchmark artifacts and easy to find after a run.
pub fn shim_log_path(arm_dir: &Path) -> PathBuf {
    arm_dir.join(".bench-home").join("shim-log.jsonl")
}

/// Collect and parse a shim log after a benchmark run.
/// Returns `None` if the log file does not exist or is empty.
/// Malformed lines are silently skipped (the shim writes best-effort JSON).
pub fn collect_shim_log(arm_dir: &Path) -> Option<Vec<ShimLogEntry>> {
    let path = shim_log_path(arm_dir);
    if !path.exists() {
        return None;
    }
    let content = fs::read_to_string(&path).ok()?;
    if content.trim().is_empty() {
        return None;
    }
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<ShimLogEntry>(trimmed) {
            entries.push(entry);
        }
    }
    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

/// Conversion metrics from setting up the Kin arm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionMetrics {
    /// Which benchmark arm produced these metrics (e.g. "kin-compat", "kin-native").
    #[serde(default)]
    pub arm: String,
    pub repo_name: String,
    pub commit_sha: Option<String>,
    pub init_duration_ms: f64,
    pub commit_duration_ms: f64,
    pub kin_dir_size_bytes: u64,
    pub git_dir_size_bytes: u64,
    pub entity_count: u64,
    pub file_count: u64,
    pub total_setup_ms: f64,
    /// Whether this conversion was served from cache.
    #[serde(default)]
    pub cached: bool,
    /// When cached, the original conversion duration (init + commit) in ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_conversion_ms: Option<f64>,
    /// When cached, ISO 8601 timestamp of when the cache entry was built.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_at: Option<String>,
}

/// Sidecar metadata written alongside a cached prepared arm directory.
/// This is the immutable seed — never modified after creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheMeta {
    repo_name: String,
    commit_sha: String,
    entity_count: u64,
    file_count: u64,
    kin_dir_size_bytes: u64,
    /// Original conversion duration (init + commit) in ms.
    conversion_duration_ms: f64,
    /// Original init duration in ms.
    init_duration_ms: f64,
    /// Original commit duration in ms.
    commit_duration_ms: f64,
    /// Kin version string (from `kin --version`).
    kin_version: String,
    /// Kin build hash used in the cache key.
    kin_build_hash: String,
    /// Which arm mode: "compat" or "native".
    arm_mode: String,
    /// ISO 8601 timestamp of when this cache entry was created.
    cached_at: String,
}

/// Copy strategy for restoring from cache, following kin-runtime's MaterializeStrategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CopyStrategy {
    /// fs::copy uses CoW reflink on APFS/btrfs — fastest.
    Reflink,
    /// Hard links — fast, shared inodes.
    Hardlink,
    /// Full byte copy — slowest, always works.
    Copy,
}

/// A prepared benchmark workspace with 3 isolated arms.
pub struct BenchWorkspace {
    pub root: PathBuf,
    pub git_dir: PathBuf,
    pub kin_compat_dir: PathBuf,
    pub kin_native_dir: PathBuf,
    /// Conversion metrics for each Kin arm (compat and native).
    pub conversions: Vec<ConversionMetrics>,
}

impl BenchWorkspace {
    /// Set up a 3-arm benchmark workspace from a repository source.
    ///
    /// `repo` can be a URL (contains "://" or starts with "git@") or a local path.
    /// Creates 3 copies under a tempdir for git, kin-compat, and kin-native arms.
    /// Uses conversion cache by default. See `setup_with_options` for `fresh_conversion`.
    pub fn setup(repo: &str, kin_binary: &Path) -> Result<Self> {
        Self::setup_with_options(repo, kin_binary, false)
    }

    /// Like `setup`, but with cache control.
    ///
    /// When `fresh_conversion` is true (--fresh-conversion / --rebuild-cache),
    /// ignore existing cache entries but DO update the cache after conversion.
    pub fn setup_with_options(
        repo: &str,
        kin_binary: &Path,
        fresh_conversion: bool,
    ) -> Result<Self> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        // Include a random suffix to prevent collisions when running parallel benchmarks
        let rand_suffix: u32 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let root = bench_cache_root().join(format!("run-{ts}-{rand_suffix}"));
        fs::create_dir_all(&root).map_err(|e| BenchError::io(&root, e))?;

        let source_dir = root.join("_source");

        // Clone or copy
        eprintln!("Setup [1/5] Cloning source repo...");
        if repo.contains("://") || repo.starts_with("git@") {
            let status = Command::new("git")
                .args(["clone", "--depth", "1", repo])
                .arg(&source_dir)
                .status()
                .map_err(|e| BenchError::io(repo, e))?;
            if !status.success() {
                return Err(BenchError::Other(format!("git clone failed for {repo}")));
            }
        } else {
            let src = Path::new(repo);
            if !src.is_dir() {
                return Err(BenchError::Other(format!("not a directory: {repo}")));
            }
            // Use file:// URL to avoid --depth/--local warnings on local paths
            let file_url = format!("file://{}", src.display());
            let status = Command::new("git")
                .args(["clone", "--depth", "1", &file_url])
                .arg(&source_dir)
                .status()
                .map_err(|e| BenchError::io(repo, e))?;
            if !status.success() {
                // Fallback to recursive copy if not a git repo
                copy_dir_recursive(src, &source_dir)?;
            }
        }

        let git_dir = root.join("arm-git");
        let kin_compat_dir = root.join("arm-kin-compat");
        let kin_native_dir = root.join("arm-kin-native");

        copy_dir_recursive(&source_dir, &git_dir)?;
        copy_dir_recursive(&source_dir, &kin_compat_dir)?;
        copy_dir_recursive(&source_dir, &kin_native_dir)?;

        eprintln!("Setup [2/5] Preparing git arm...");
        prepare_git_arm(&git_dir)?;

        // Compute cache key components
        let canonical_repo = canonicalize_repo(repo);
        let source_commit_sha = get_commit_sha(&source_dir);
        let kin_version_info = get_kin_version(kin_binary);
        let kin_build_hash = compute_kin_build_hash(kin_binary, &kin_version_info);
        let repo_hash = hash_string(&canonical_repo);

        let commit_part = source_commit_sha.as_deref().unwrap_or("unknown");

        eprintln!("Setup [3/5] Preparing kin-compat arm...");
        let compat_cache_name = format!("{repo_hash}-{commit_part}-{kin_build_hash}-compat");
        let compat_conversion = prepare_arm_with_cache(
            &kin_compat_dir,
            kin_binary,
            false,
            &compat_cache_name,
            fresh_conversion,
            &kin_version_info,
            &kin_build_hash,
        )?;

        eprintln!("Setup [4/5] Preparing kin-native arm...");
        let native_cache_name = format!("{repo_hash}-{commit_part}-{kin_build_hash}-native");
        let native_conversion = prepare_arm_with_cache(
            &kin_native_dir,
            kin_binary,
            true,
            &native_cache_name,
            fresh_conversion,
            &kin_version_info,
            &kin_build_hash,
        )?;

        eprintln!("Setup [5/5] Verifying workspace...");

        Ok(Self {
            root,
            git_dir,
            kin_compat_dir,
            kin_native_dir,
            conversions: vec![compat_conversion, native_conversion],
        })
    }

    /// Get the directory for a given arm.
    pub fn arm_dir(&self, arm: BenchmarkArm) -> &Path {
        match arm {
            BenchmarkArm::Git => &self.git_dir,
            BenchmarkArm::KinCompat => &self.kin_compat_dir,
            BenchmarkArm::KinNative => &self.kin_native_dir,
        }
    }

    /// Clean up the workspace.
    pub fn cleanup(&self) -> Result<()> {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).map_err(|e| BenchError::io(&self.root, e))?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Git arm preparation
// ---------------------------------------------------------------------------

/// Prepare the pure-git arm by stripping all kin traces.
fn prepare_git_arm(dir: &Path) -> Result<()> {
    // Delete .kin/ directory
    let kin_dir = dir.join(".kin");
    if kin_dir.exists() {
        fs::remove_dir_all(&kin_dir).map_err(|e| BenchError::io(&kin_dir, e))?;
    }

    // Delete .mcp.json
    let mcp = dir.join(".mcp.json");
    if mcp.exists() {
        fs::remove_file(&mcp).map_err(|e| BenchError::io(&mcp, e))?;
    }

    // Strip kin-managed blocks from assistant config files
    let config_files = ["CLAUDE.md", "AGENTS.md", "CODEX.md", "GEMINI.md"];
    for name in &config_files {
        let path = dir.join(name);
        if path.exists() {
            strip_kin_managed_blocks(&path)?;
        }
    }

    // Strip kin entries from .claude/settings.json hooks
    let settings = dir.join(".claude").join("settings.json");
    if settings.exists() {
        strip_kin_from_settings(&settings)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Kin version / build hash
// ---------------------------------------------------------------------------

/// Get the kin version string from `kin --version`.
fn get_kin_version(kin_binary: &Path) -> String {
    Command::new(kin_binary)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Compute a short hash identifying this kin build. Uses the version string
/// plus the binary's modification time as a proxy for build identity.
fn compute_kin_build_hash(kin_binary: &Path, version_info: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(version_info.as_bytes());
    // Include binary mtime so dev builds with same version string still bust cache
    if let Ok(meta) = fs::metadata(kin_binary) {
        if let Ok(mtime) = meta.modified() {
            let epoch = mtime
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            hasher.update(epoch.to_le_bytes());
        }
        hasher.update(meta.len().to_le_bytes());
    }
    let full = format!("{:x}", hasher.finalize());
    // Use first 12 hex chars — enough uniqueness for cache keys
    full[..12].to_string()
}

// ---------------------------------------------------------------------------
// Cache key computation
// ---------------------------------------------------------------------------

/// Hash a string to a short hex prefix (first 16 chars of SHA-256).
fn hash_string(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let full = format!("{:x}", hasher.finalize());
    full[..16].to_string()
}

/// Canonicalize a repo source string for cache key computation.
fn canonicalize_repo(repo: &str) -> String {
    if repo.contains("://") || repo.starts_with("git@") {
        repo.to_string()
    } else {
        let path = Path::new(repo);
        path.canonicalize()
            .unwrap_or_else(|_| path.to_path_buf())
            .display()
            .to_string()
    }
}

/// Return the prepared-arm cache directory.
fn prepared_cache_dir() -> PathBuf {
    bench_cache_root().join("prepared")
}

// ---------------------------------------------------------------------------
// Copy strategies: reflink → hardlink → copy  (mirrors kin-runtime pattern)
// ---------------------------------------------------------------------------

/// Copy a directory tree using the best available strategy.
/// Tries reflink (CoW) first, then hardlink, then full copy.
fn copy_dir_smart(src: &Path, dst: &Path) -> Result<CopyStrategy> {
    // Try reflink (fs::copy on APFS/btrfs uses CoW automatically)
    match copy_dir_with_strategy(src, dst, CopyStrategy::Reflink) {
        Ok(()) => return Ok(CopyStrategy::Reflink),
        Err(_) => clean_dir_contents(dst),
    }

    // Try hardlink
    match copy_dir_with_strategy(src, dst, CopyStrategy::Hardlink) {
        Ok(()) => return Ok(CopyStrategy::Hardlink),
        Err(_) => clean_dir_contents(dst),
    }

    // Full copy always works
    copy_dir_with_strategy(src, dst, CopyStrategy::Copy)?;
    Ok(CopyStrategy::Copy)
}

fn copy_dir_with_strategy(src: &Path, dst: &Path, strategy: CopyStrategy) -> Result<()> {
    fs::create_dir_all(dst).map_err(|e| BenchError::io(dst, e))?;
    let entries = fs::read_dir(src).map_err(|e| BenchError::io(src, e))?;

    for entry in entries {
        let entry = entry.map_err(|e| BenchError::io(src, e))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let ft = entry.file_type().map_err(|e| BenchError::io(&src_path, e))?;

        if ft.is_dir() {
            copy_dir_with_strategy(&src_path, &dst_path, strategy)?;
        } else if ft.is_file() {
            match strategy {
                CopyStrategy::Reflink | CopyStrategy::Copy => {
                    fs::copy(&src_path, &dst_path)
                        .map_err(|e| BenchError::io(&src_path, e))?;
                }
                CopyStrategy::Hardlink => {
                    fs::hard_link(&src_path, &dst_path)
                        .map_err(|e| BenchError::io(&src_path, e))?;
                }
            }
        }
        // Skip symlinks and special files
    }

    Ok(())
}

/// Remove all contents of a directory without removing the directory itself.
fn clean_dir_contents(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let _ = fs::remove_dir_all(&path);
            } else {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cache: restore and write
// ---------------------------------------------------------------------------

/// Try to restore a cached prepared arm into the target arm directory.
/// The cache entry is an immutable seed — we always COPY into the run dir,
/// never benchmark inside the cached directory itself.
///
/// Returns `Some(ConversionMetrics)` on cache hit, `None` on miss.
fn try_restore_from_cache(
    cache_name: &str,
    arm_dir: &Path,
    arm_name: &str,
) -> Option<ConversionMetrics> {
    let cache_entry = prepared_cache_dir().join(cache_name);
    let cached_arm = cache_entry.join("arm");
    let meta_path = cache_entry.join("cache-meta.json");

    if !cached_arm.is_dir() || !meta_path.is_file() {
        return None;
    }

    let meta_content = fs::read_to_string(&meta_path).ok()?;
    let meta: CacheMeta = serde_json::from_str(&meta_content).ok()?;

    // Copy cached .kin/ into the RUN directory (never benchmark inside cache)
    let dst_kin = arm_dir.join(".kin");
    if dst_kin.exists() {
        fs::remove_dir_all(&dst_kin).ok();
    }
    let cached_kin = cached_arm.join(".kin");
    if !cached_kin.is_dir() {
        return None;
    }

    // Use smart copy: reflink → hardlink → copy
    copy_dir_smart(&cached_kin, &dst_kin).ok()?;

    // Also restore assistant docs from cache if present
    let doc_files = ["CLAUDE.md", "AGENTS.md", "CODEX.md", "GEMINI.md"];
    for name in &doc_files {
        let src_doc = cached_arm.join(name);
        if src_doc.is_file() {
            let _ = fs::copy(&src_doc, &arm_dir.join(name));
        }
    }

    eprintln!(
        "  Cache hit: restored {} ({} entities, {:.1} MB, built {})",
        arm_name,
        meta.entity_count,
        meta.kin_dir_size_bytes as f64 / (1024.0 * 1024.0),
        &meta.cached_at[..19.min(meta.cached_at.len())],
    );

    Some(ConversionMetrics {
        arm: arm_name.to_string(),
        repo_name: meta.repo_name,
        commit_sha: Some(meta.commit_sha),
        init_duration_ms: 0.0,
        commit_duration_ms: 0.0,
        kin_dir_size_bytes: meta.kin_dir_size_bytes,
        git_dir_size_bytes: dir_size(&arm_dir.join(".git")),
        entity_count: meta.entity_count,
        file_count: meta.file_count,
        total_setup_ms: 0.0,
        cached: true,
        original_conversion_ms: Some(meta.conversion_duration_ms),
        cached_at: Some(meta.cached_at),
    })
}

/// Write a prepared arm directory and sidecar to the cache.
/// Stores the complete prepared state (.kin/ + assistant docs) so that
/// cache restore produces a fully ready arm without needing `kin` commands.
fn write_to_cache(
    cache_name: &str,
    arm_dir: &Path,
    metrics: &ConversionMetrics,
    kin_version: &str,
    kin_build_hash: &str,
    arm_mode: &str,
) {
    let cache_entry = prepared_cache_dir().join(cache_name);
    if fs::create_dir_all(&cache_entry).is_err() {
        return;
    }

    let cached_arm = cache_entry.join("arm");
    if cached_arm.exists() {
        let _ = fs::remove_dir_all(&cached_arm);
    }
    if fs::create_dir_all(&cached_arm).is_err() {
        let _ = fs::remove_dir_all(&cache_entry);
        return;
    }

    // Copy .kin/ into cache
    let src_kin = arm_dir.join(".kin");
    let dst_kin = cached_arm.join(".kin");
    if copy_dir_recursive(&src_kin, &dst_kin).is_err() {
        let _ = fs::remove_dir_all(&cache_entry);
        return;
    }

    // Copy assistant docs into cache
    let doc_files = ["CLAUDE.md", "AGENTS.md", "CODEX.md", "GEMINI.md"];
    for name in &doc_files {
        let src_doc = arm_dir.join(name);
        if src_doc.is_file() {
            let _ = fs::copy(&src_doc, &cached_arm.join(name));
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    let meta = CacheMeta {
        repo_name: metrics.repo_name.clone(),
        commit_sha: metrics.commit_sha.clone().unwrap_or_default(),
        entity_count: metrics.entity_count,
        file_count: metrics.file_count,
        kin_dir_size_bytes: metrics.kin_dir_size_bytes,
        conversion_duration_ms: metrics.init_duration_ms + metrics.commit_duration_ms,
        init_duration_ms: metrics.init_duration_ms,
        commit_duration_ms: metrics.commit_duration_ms,
        kin_version: kin_version.to_string(),
        kin_build_hash: kin_build_hash.to_string(),
        arm_mode: arm_mode.to_string(),
        cached_at: now,
    };

    if let Ok(json) = serde_json::to_string_pretty(&meta) {
        let _ = fs::write(cache_entry.join("cache-meta.json"), json);
    }

    eprintln!(
        "  Cached {} ({} entities, {:.1} MB)",
        arm_mode,
        metrics.entity_count,
        metrics.kin_dir_size_bytes as f64 / (1024.0 * 1024.0),
    );
}

// ---------------------------------------------------------------------------
// Arm preparation with cache
// ---------------------------------------------------------------------------

/// Prepare a Kin arm, using cache when available.
///
/// `fresh_conversion`: if true, skip cache lookup but still update cache after conversion.
fn prepare_arm_with_cache(
    dir: &Path,
    kin_binary: &Path,
    native_mode: bool,
    cache_name: &str,
    fresh_conversion: bool,
    kin_version: &str,
    kin_build_hash: &str,
) -> Result<ConversionMetrics> {
    let arm_name = if native_mode { "kin-native" } else { "kin-compat" };
    let arm_mode = if native_mode { "native" } else { "compat" };

    // Try cache first (unless --fresh-conversion)
    if !fresh_conversion {
        if let Some(metrics) = try_restore_from_cache(cache_name, dir, arm_name) {
            return Ok(metrics);
        }
    }

    // Cache miss (or forced fresh) — do full conversion
    let metrics = prepare_kin_arm(dir, kin_binary, native_mode)?;

    // Always update cache (even on --fresh-conversion)
    write_to_cache(cache_name, dir, &metrics, kin_version, kin_build_hash, arm_mode);

    Ok(metrics)
}

/// Prepare a Kin arm: run kin init + commit, write assistant docs,
/// optionally switch to native mode.
fn prepare_kin_arm(dir: &Path, kin_binary: &Path, native_mode: bool) -> Result<ConversionMetrics> {
    let total_start = Instant::now();
    let repo_name = dir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let commit_sha = get_commit_sha(dir);

    // kin init
    let init_start = Instant::now();
    let init_status = Command::new(kin_binary)
        .arg("init")
        .current_dir(dir)
        .status()
        .map_err(|e| BenchError::io(kin_binary, e))?;
    let init_duration_ms = init_start.elapsed().as_secs_f64() * 1000.0;

    if !init_status.success() {
        return Err(BenchError::Other("kin init failed".to_string()));
    }

    // kin commit
    let commit_start = Instant::now();
    let commit_output = Command::new(kin_binary)
        .args(["commit", "-m", "initial semantic import"])
        .current_dir(dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| BenchError::io(kin_binary, e))?
        .wait_with_output()
        .map_err(|e| BenchError::io(kin_binary, e))?;
    let commit_duration_ms = commit_start.elapsed().as_secs_f64() * 1000.0;

    if !commit_output.status.success() {
        let stderr = String::from_utf8_lossy(&commit_output.stderr);
        return Err(BenchError::Other(format!("kin commit failed: {stderr}")));
    }

    // Try to extract entity count from commit output
    let stdout = String::from_utf8_lossy(&commit_output.stdout);
    let entity_count = extract_entity_count(&stdout);

    // Write assistant docs
    write_assistant_docs(dir, kin_binary, native_mode)?;

    // Measure directory sizes
    let kin_dir_size = dir_size(&dir.join(".kin"));
    let git_dir_size = dir_size(&dir.join(".git"));
    let file_count = count_files(dir);
    let total_setup_ms = total_start.elapsed().as_secs_f64() * 1000.0;

    let arm_name = if native_mode { "kin-native" } else { "kin-compat" };

    Ok(ConversionMetrics {
        arm: arm_name.to_string(),
        repo_name,
        commit_sha,
        init_duration_ms,
        commit_duration_ms,
        kin_dir_size_bytes: kin_dir_size,
        git_dir_size_bytes: git_dir_size,
        entity_count,
        file_count,
        total_setup_ms,
        cached: false,
        original_conversion_ms: None,
        cached_at: None,
    })
}

// ---------------------------------------------------------------------------
// Assistant docs
// ---------------------------------------------------------------------------

/// Run `kin overview --compact` and return a formatted section string.
fn run_kin_overview(dir: &Path, kin_binary: &Path) -> String {
    match Command::new(kin_binary)
        .args(["overview", "--compact"])
        .current_dir(dir)
        .output()
    {
        Ok(output) if output.status.success() => {
            let overview_text = String::from_utf8_lossy(&output.stdout);
            let trimmed = overview_text.trim();
            if trimmed.is_empty() {
                String::new()
            } else {
                let compact: String = trimmed
                    .lines()
                    .take(20)
                    .collect::<Vec<_>>()
                    .join("\n");
                format!("\n## Overview\n```\n{}\n```\n", compact)
            }
        }
        _ => String::new(),
    }
}

/// Write assistant config docs (CLAUDE.md, AGENTS.md, etc.) for a Kin arm.
fn write_assistant_docs(dir: &Path, kin_binary: &Path, native_mode: bool) -> Result<()> {
    let cli_docs = "\
# Kin — Semantic Code Search\n\
\n\
This repo has `kin` — find + read source in one command.\n\
\n\
```bash\n\
kin overview --compact              # entity counts by language/kind\n\
kin search <name> --show-body       # find entity + print source body\n\
kin search \"a|b\" --show-body        # OR-search (use specific names)\n\
```\n\
\n\
Tips:\n\
- Search for EXACT entity names (e.g. `ZodString`), not broad patterns\n\
- `--show-body` prints full source — keep `--limit 5` to avoid huge output\n\
- Matches entity NAMES only. Use grep for string/pattern matching.\n";

    let overview_section = run_kin_overview(dir, kin_binary);
    let full_docs = format!("{cli_docs}{overview_section}");

    let doc_files = ["CLAUDE.md", "AGENTS.md", "CODEX.md", "GEMINI.md"];
    for name in &doc_files {
        fs::write(dir.join(name), &full_docs).map_err(|e| BenchError::io(dir, e))?;
    }

    // Verify required Kin arm artifacts exist
    let mut missing: Vec<&str> = Vec::new();
    for artifact in &doc_files {
        if !dir.join(artifact).exists() {
            missing.push(artifact);
        }
    }
    if !missing.is_empty() {
        return Err(BenchError::Other(format!(
            "Kin arm setup incomplete — missing required artifacts: {}. \
             The benchmark cannot credibly compare arms without full Kin assistant configuration.",
            missing.join(", ")
        )));
    }

    if native_mode {
        let native_output = Command::new(kin_binary)
            .args(["mode", "native"])
            .current_dir(dir)
            .output()
            .map_err(|e| BenchError::io(kin_binary, e))?;
        if !native_output.status.success() {
            let stderr = String::from_utf8_lossy(&native_output.stderr);
            return Err(BenchError::Other(format!(
                "kin mode native failed: {stderr}"
            )));
        }

        if !overview_section.is_empty() {
            for name in &doc_files {
                let path = dir.join(name);
                if let Ok(existing) = fs::read_to_string(&path) {
                    fs::write(&path, format!("{existing}\n{overview_section}"))
                        .map_err(|e| BenchError::io(&path, e))?;
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Remove `<!-- kin:begin -->` to `<!-- kin:end -->` blocks from a file.
pub fn strip_kin_managed_blocks(file: &Path) -> Result<()> {
    let content = fs::read_to_string(file).map_err(|e| BenchError::io(file, e))?;
    let stripped = strip_kin_blocks_from_str(&content);
    if stripped != content {
        fs::write(file, stripped).map_err(|e| BenchError::io(file, e))?;
    }
    Ok(())
}

/// Strip kin-managed blocks from a string (for testability).
fn strip_kin_blocks_from_str(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut in_block = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "<!-- kin:begin -->" {
            in_block = true;
            continue;
        }
        if trimmed == "<!-- kin:end -->" {
            in_block = false;
            continue;
        }
        if !in_block {
            result.push_str(line);
            result.push('\n');
        }
    }

    // Remove trailing newline only if the original didn't have one
    if !content.ends_with('\n') && result.ends_with('\n') {
        result.pop();
    }

    result
}

/// Strip kin-related entries from .claude/settings.json.
fn strip_kin_from_settings(settings_path: &Path) -> Result<()> {
    let content = fs::read_to_string(settings_path).map_err(|e| BenchError::io(settings_path, e))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&content).map_err(BenchError::Json)?;

    let mut changed = false;

    // Remove kin-related hooks
    if let Some(obj) = value.as_object_mut() {
        for key in &["hooks", "mcpServers"] {
            if let Some(section) = obj.get_mut(*key) {
                if let Some(section_obj) = section.as_object_mut() {
                    let kin_keys: Vec<String> = section_obj
                        .keys()
                        .filter(|k| k.to_lowercase().contains("kin"))
                        .cloned()
                        .collect();
                    for k in kin_keys {
                        section_obj.remove(&k);
                        changed = true;
                    }
                }
            }
        }
    }

    if changed {
        let out = serde_json::to_string_pretty(&value).map_err(BenchError::Json)?;
        fs::write(settings_path, out).map_err(|e| BenchError::io(settings_path, e))?;
    }

    Ok(())
}

/// Get the current HEAD commit SHA.
fn get_commit_sha(dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(dir)
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Calculate recursive directory size in bytes.
pub fn dir_size(path: &Path) -> u64 {
    if !path.exists() {
        return 0;
    }
    let entries = match fs::read_dir(path) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    let mut total: u64 = 0;
    for entry in entries.flatten() {
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_file() {
            total += entry.metadata().map(|m| m.len()).unwrap_or(0);
        } else if ft.is_dir() {
            total += dir_size(&entry.path());
        }
    }
    total
}

/// Count regular files in a directory (excluding hidden dirs/files).
fn count_files(dir: &Path) -> u64 {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    let mut count: u64 = 0;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_file() {
            count += 1;
        } else if ft.is_dir() {
            count += count_files(&entry.path());
        }
    }
    count
}

/// Try to extract an entity count from kin commit output.
fn extract_entity_count(output: &str) -> u64 {
    for line in output.lines() {
        let lower = line.to_lowercase();
        if lower.contains("entit") {
            for word in line.split_whitespace() {
                if let Ok(n) = word.parse::<u64>() {
                    return n;
                }
            }
        }
    }
    0
}

fn bench_cache_root() -> PathBuf {
    if let Ok(cache_home) = std::env::var("XDG_CACHE_HOME") {
        return PathBuf::from(cache_home).join("kin-bench");
    }

    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        #[cfg(target_os = "macos")]
        {
            return home.join("Library").join("Caches").join("kin-bench");
        }
        #[cfg(not(target_os = "macos"))]
        {
            return home.join(".cache").join("kin-bench");
        }
    }

    std::env::temp_dir().join("kin-bench")
}

/// Remove benchmark workspaces older than `max_age_hours` from the cache directory.
/// This prevents disk bloat from accumulated benchmark runs.
pub fn cleanup_stale_workspaces(max_age_hours: u64) {
    let cache_root = bench_cache_root();
    if !cache_root.exists() {
        return;
    }

    let cutoff = std::time::SystemTime::now()
        - std::time::Duration::from_secs(max_age_hours * 3600);

    let entries = match fs::read_dir(&cache_root) {
        Ok(e) => e,
        Err(_) => return,
    };

    let mut cleaned = 0u64;
    let mut freed_bytes = 0u64;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("run-") {
            continue;
        }
        let modified = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok());
        if let Some(modified) = modified {
            if modified < cutoff {
                let size = dir_size(&entry.path());
                if fs::remove_dir_all(entry.path()).is_ok() {
                    cleaned += 1;
                    freed_bytes += size;
                }
            }
        }
    }

    if cleaned > 0 {
        let freed_mb = freed_bytes as f64 / (1024.0 * 1024.0);
        eprintln!(
            "Cleaned up {} stale benchmark workspace(s) ({:.1} MB freed)",
            cleaned, freed_mb
        );
    }
}

/// Create an isolated HOME directory for a benchmark arm.
/// Returns a list of environment variable overrides (key, value) pairs.
/// This prevents global user config from bleeding into benchmark runs.
pub fn create_isolated_env(
    arm_dir: &Path,
    arm: super::BenchmarkArm,
    kin_binary: &Path,
    native_restrict_discovery: bool,
    native_restrict_filesystem: bool,
) -> Result<Vec<(String, String)>> {
    let home_dir = arm_dir.join(".bench-home");
    fs::create_dir_all(&home_dir).map_err(|e| BenchError::io(&home_dir, e))?;

    // Create empty .claude dir to prevent Claude from reading global config
    let claude_dir = home_dir.join(".claude");
    fs::create_dir_all(&claude_dir).map_err(|e| BenchError::io(&claude_dir, e))?;

    let real_home = std::env::var("HOME").unwrap_or_default();
    let real_home = (!real_home.is_empty()).then(|| PathBuf::from(real_home));
    let gemini_auth_settings = real_home
        .as_deref()
        .and_then(read_gemini_auth_settings);

    // Gemini: preserve only the auth selector from the real settings file.
    if gemini_auth_settings.is_some() {
        let gemini_dir = home_dir.join(".gemini");
        fs::create_dir_all(&gemini_dir).map_err(|e| BenchError::io(&gemini_dir, e))?;
        let gemini_settings = render_gemini_settings(
            gemini_auth_settings.as_ref(),
            None,
        )?;
        fs::write(gemini_dir.join("settings.json"), gemini_settings)
            .map_err(|e| BenchError::io(&gemini_dir, e))?;
    }

    // Preserve auth artifacts from the real HOME into the isolated HOME.
    if let Some(real_home) = real_home.as_deref() {
        preserve_auth_artifacts(real_home, &home_dir)?;
    }

    let mut env = Vec::new();
    env.push(("HOME".to_string(), home_dir.display().to_string()));
    env.push((
        "XDG_CONFIG_HOME".to_string(),
        home_dir.join(".config").display().to_string(),
    ));
    env.push((
        "XDG_DATA_HOME".to_string(),
        home_dir.join(".local/share").display().to_string(),
    ));

    if matches!(
        arm,
        super::BenchmarkArm::KinCompat | super::BenchmarkArm::KinNative
    ) {
        let mut path_prefix = String::new();

        if arm == super::BenchmarkArm::KinNative {
            let shim_dir = arm_dir.join(".kin").join("shims");
            let source_root = arm_dir.join(".kin").join("source-root");
            if shim_dir.is_dir() {
                path_prefix = shim_dir.display().to_string();
                let original_path = std::env::var("PATH").unwrap_or_default();
                env.push(("KIN_SOURCE_ROOT".to_string(), source_root.display().to_string()));
                env.push(("KIN_ORIGINAL_PATH".to_string(), original_path));
                if native_restrict_filesystem {
                    env.push(("KIN_DISCOVERY_MODE".to_string(), "deny".to_string()));
                    env.push(("KIN_CONTENT_MODE".to_string(), "deny".to_string()));
                } else if native_restrict_discovery {
                    env.push(("KIN_DISCOVERY_MODE".to_string(), "deny".to_string()));
                }
                let log_path = shim_log_path(arm_dir);
                env.push(("KIN_SHIM_LOG".to_string(), log_path.display().to_string()));
            }
        }

        if let Some(kin_dir) = kin_binary.parent() {
            let mut path_value = String::new();
            if !path_prefix.is_empty() {
                path_value.push_str(&path_prefix);
                path_value.push(':');
            }
            path_value.push_str(&kin_dir.display().to_string());
            if let Ok(existing_path) = std::env::var("PATH") {
                path_value.push(':');
                path_value.push_str(&existing_path);
            }
            env.push(("PATH".to_string(), path_value));
        }
    }

    for var in &[
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
    ] {
        if let Ok(val) = std::env::var(var) {
            env.push((var.to_string(), val));
        }
    }

    Ok(env)
}

fn read_gemini_auth_settings(real_home: &Path) -> Option<Value> {
    let path = real_home.join(".gemini").join("settings.json");
    let content = fs::read_to_string(path).ok()?;
    let parsed: Value = serde_json::from_str(&content).ok()?;
    let auth = parsed.get("security")?.get("auth")?.clone();
    Some(json!({
        "security": {
            "auth": auth
        }
    }))
}

fn render_gemini_settings(auth_settings: Option<&Value>, kin_binary: Option<&Path>) -> Result<String> {
    let mut root = Map::new();

    if let Some(auth_settings) = auth_settings {
        if let Some(obj) = auth_settings.as_object() {
            for (key, value) in obj {
                root.insert(key.clone(), value.clone());
            }
        }
    }

    if let Some(kin_binary) = kin_binary {
        root.insert(
            "mcpServers".into(),
            json!({
                "kin": {
                    "command": kin_binary.display().to_string(),
                    "args": ["mcp", "start"]
                }
            }),
        );
    }

    serde_json::to_string_pretty(&Value::Object(root))
        .map_err(|e| BenchError::Other(format!("failed to render Gemini settings: {e}")))
}

/// Preserve auth-only artifacts from the real HOME into the isolated benchmark HOME.
fn preserve_auth_artifacts(real_home: &Path, isolated_home: &Path) -> Result<()> {
    let claude_auth_candidates = [
        "credentials.json",
        ".credentials.json",
        "auth.json",
        ".auth",
    ];
    let claude_dst = isolated_home.join(".claude");
    for file in &claude_auth_candidates {
        symlink_auth_file(&real_home.join(".claude").join(file), &claude_dst.join(file));
    }

    let codex_dst = isolated_home.join(".codex");
    fs::create_dir_all(&codex_dst).ok();
    symlink_auth_file(
        &real_home.join(".codex").join("auth.json"),
        &codex_dst.join("auth.json"),
    );

    let gemini_auth_files = ["oauth_creds.json", "google_accounts.json"];
    let gemini_dst = isolated_home.join(".gemini");
    fs::create_dir_all(&gemini_dst).ok();
    for file in &gemini_auth_files {
        symlink_auth_file(
            &real_home.join(".gemini").join(file),
            &gemini_dst.join(file),
        );
    }

    Ok(())
}

fn symlink_auth_file(src: &Path, dst: &Path) {
    if !src.exists() || dst.exists() {
        return;
    }
    #[cfg(unix)]
    {
        let _ = std::os::unix::fs::symlink(src, dst);
    }
    #[cfg(not(unix))]
    {
        let _ = fs::copy(src, dst);
    }
}

/// Copy a directory recursively (simple full-copy, no strategy selection).
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).map_err(|e| BenchError::io(dst, e))?;
    let entries = fs::read_dir(src).map_err(|e| BenchError::io(src, e))?;

    for entry in entries {
        let entry = entry.map_err(|e| BenchError::io(src, e))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let ft = entry.file_type().map_err(|e| BenchError::io(&src_path, e))?;

        if ft.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if ft.is_file() {
            fs::copy(&src_path, &dst_path).map_err(|e| BenchError::io(&src_path, e))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }
    use std::fs;

    #[test]
    fn strip_kin_blocks_removes_managed_content() {
        let input = "\
# Project\n\
\n\
Some content before.\n\
<!-- kin:begin -->\n\
This is kin-managed content.\n\
More kin stuff.\n\
<!-- kin:end -->\n\
Some content after.\n";

        let result = strip_kin_blocks_from_str(input);
        assert!(result.contains("Some content before."));
        assert!(result.contains("Some content after."));
        assert!(!result.contains("kin-managed content"));
        assert!(!result.contains("More kin stuff"));
        assert!(!result.contains("kin:begin"));
        assert!(!result.contains("kin:end"));
    }

    #[test]
    fn strip_kin_blocks_preserves_content_without_blocks() {
        let input = "# Just a normal file\n\nWith some content.\n";
        let result = strip_kin_blocks_from_str(input);
        assert_eq!(result, input);
    }

    #[test]
    fn strip_kin_blocks_handles_multiple_blocks() {
        let input = "\
Line 1\n\
<!-- kin:begin -->\n\
Block A\n\
<!-- kin:end -->\n\
Line 2\n\
<!-- kin:begin -->\n\
Block B\n\
<!-- kin:end -->\n\
Line 3\n";

        let result = strip_kin_blocks_from_str(input);
        assert!(result.contains("Line 1"));
        assert!(result.contains("Line 2"));
        assert!(result.contains("Line 3"));
        assert!(!result.contains("Block A"));
        assert!(!result.contains("Block B"));
    }

    #[test]
    fn strip_kin_blocks_handles_empty_input() {
        let result = strip_kin_blocks_from_str("");
        assert_eq!(result, "");
    }

    #[test]
    fn dir_size_returns_zero_for_missing() {
        assert_eq!(dir_size(Path::new("/nonexistent/path/unlikely")), 0);
    }

    #[test]
    fn dir_size_measures_files() {
        let tmp = std::env::temp_dir().join("kin-bench-test-dir-size");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join("a.txt"), "hello").unwrap();
        fs::write(tmp.join("b.txt"), "world!").unwrap();

        let size = dir_size(&tmp);
        assert!(size >= 11);

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn dir_size_measures_nested_dirs() {
        let tmp = std::env::temp_dir().join("kin-bench-test-dir-size-nested");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("sub")).unwrap();
        fs::write(tmp.join("a.txt"), "aaa").unwrap();
        fs::write(tmp.join("sub").join("b.txt"), "bbb").unwrap();

        let size = dir_size(&tmp);
        assert!(size >= 6);

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn extract_entity_count_parses_output() {
        assert_eq!(extract_entity_count("committed 42 entities"), 42);
        assert_eq!(extract_entity_count("nothing relevant"), 0);
        assert_eq!(
            extract_entity_count("indexed 100 entities across 5 files"),
            100
        );
    }

    #[test]
    fn copy_dir_recursive_works() {
        let tmp = std::env::temp_dir().join("kin-bench-test-copy");
        let _ = fs::remove_dir_all(&tmp);
        let src = tmp.join("src");
        let dst = tmp.join("dst");

        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.txt"), "alpha").unwrap();
        fs::write(src.join("sub").join("b.txt"), "beta").unwrap();

        copy_dir_recursive(&src, &dst).unwrap();

        assert_eq!(fs::read_to_string(dst.join("a.txt")).unwrap(), "alpha");
        assert_eq!(
            fs::read_to_string(dst.join("sub").join("b.txt")).unwrap(),
            "beta"
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn copy_dir_smart_produces_identical_tree() {
        let tmp = std::env::temp_dir().join("kin-bench-test-smart-copy");
        let _ = fs::remove_dir_all(&tmp);
        let src = tmp.join("src");
        let dst = tmp.join("dst");

        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.txt"), "alpha").unwrap();
        fs::write(src.join("sub").join("b.txt"), "beta").unwrap();

        let strategy = copy_dir_smart(&src, &dst).unwrap();
        // Should succeed with some strategy
        assert!(matches!(
            strategy,
            CopyStrategy::Reflink | CopyStrategy::Hardlink | CopyStrategy::Copy
        ));

        assert_eq!(fs::read_to_string(dst.join("a.txt")).unwrap(), "alpha");
        assert_eq!(
            fs::read_to_string(dst.join("sub").join("b.txt")).unwrap(),
            "beta"
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn copy_dir_with_hardlink_strategy() {
        let tmp = std::env::temp_dir().join("kin-bench-test-hardlink-copy");
        let _ = fs::remove_dir_all(&tmp);
        let src = tmp.join("src");
        let dst = tmp.join("dst");

        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("data.txt"), "linked-content").unwrap();

        copy_dir_with_strategy(&src, &dst, CopyStrategy::Hardlink).unwrap();

        assert_eq!(
            fs::read_to_string(dst.join("data.txt")).unwrap(),
            "linked-content"
        );

        // Verify it's a hard link (same inode)
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let src_ino = fs::metadata(src.join("data.txt")).unwrap().ino();
            let dst_ino = fs::metadata(dst.join("data.txt")).unwrap().ino();
            assert_eq!(src_ino, dst_ino, "hardlinked files should share inodes");
        }

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn conversion_metrics_serialization() {
        let m = ConversionMetrics {
            arm: "kin-compat".to_string(),
            repo_name: "test-repo".to_string(),
            commit_sha: Some("abc123".to_string()),
            init_duration_ms: 100.0,
            commit_duration_ms: 200.0,
            kin_dir_size_bytes: 1024,
            git_dir_size_bytes: 2048,
            entity_count: 50,
            file_count: 10,
            total_setup_ms: 300.0,
            cached: false,
            original_conversion_ms: None,
            cached_at: None,
        };

        let json = serde_json::to_string(&m).unwrap();
        let parsed: ConversionMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.arm, "kin-compat");
        assert_eq!(parsed.repo_name, "test-repo");
        assert_eq!(parsed.entity_count, 50);
        assert!(!parsed.cached);
        assert!(parsed.original_conversion_ms.is_none());
    }

    #[test]
    fn conversion_metrics_cached_defaults_false() {
        let json = r#"{"arm":"kin-compat","repo_name":"test","commit_sha":null,"init_duration_ms":0.0,"commit_duration_ms":0.0,"kin_dir_size_bytes":0,"git_dir_size_bytes":0,"entity_count":0,"file_count":0,"total_setup_ms":0.0}"#;
        let parsed: ConversionMetrics = serde_json::from_str(json).unwrap();
        assert!(!parsed.cached);
        assert!(parsed.original_conversion_ms.is_none());
        assert!(parsed.cached_at.is_none());
    }

    #[test]
    fn conversion_metrics_cached_with_original_timing() {
        let m = ConversionMetrics {
            arm: "kin-compat".to_string(),
            repo_name: "test-repo".to_string(),
            commit_sha: Some("abc123".to_string()),
            init_duration_ms: 0.0,
            commit_duration_ms: 0.0,
            kin_dir_size_bytes: 1024,
            git_dir_size_bytes: 2048,
            entity_count: 50,
            file_count: 10,
            total_setup_ms: 0.5,
            cached: true,
            original_conversion_ms: Some(45200.0),
            cached_at: Some("2026-03-12T10:00:00Z".to_string()),
        };

        let json = serde_json::to_string(&m).unwrap();
        let parsed: ConversionMetrics = serde_json::from_str(&json).unwrap();
        assert!(parsed.cached);
        assert_eq!(parsed.original_conversion_ms, Some(45200.0));
        assert_eq!(parsed.cached_at.as_deref(), Some("2026-03-12T10:00:00Z"));
    }

    #[test]
    fn hash_string_deterministic() {
        let h1 = hash_string("/path/to/repo");
        let h2 = hash_string("/path/to/repo");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);

        let h3 = hash_string("/other/repo");
        assert_ne!(h1, h3);
    }

    #[test]
    fn kin_build_hash_deterministic() {
        let h1 = compute_kin_build_hash(Path::new("/nonexistent/kin"), "kin 0.1.0");
        let h2 = compute_kin_build_hash(Path::new("/nonexistent/kin"), "kin 0.1.0");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 12);

        // Different version → different hash
        let h3 = compute_kin_build_hash(Path::new("/nonexistent/kin"), "kin 0.2.0");
        assert_ne!(h1, h3);
    }

    #[test]
    fn cache_roundtrip() {
        let tmp = std::env::temp_dir().join("kin-bench-test-cache-roundtrip-v2");
        let _ = fs::remove_dir_all(&tmp);

        // Create a fake arm dir with .kin/ and assistant docs
        let arm_dir = tmp.join("arm");
        fs::create_dir_all(arm_dir.join(".kin").join("graph")).unwrap();
        fs::write(arm_dir.join(".kin").join("config.json"), r#"{"version":1}"#).unwrap();
        fs::write(arm_dir.join(".kin").join("graph").join("data.db"), "fake-db-data").unwrap();
        fs::write(arm_dir.join("CLAUDE.md"), "# Kin docs").unwrap();
        fs::write(arm_dir.join("AGENTS.md"), "# Kin docs").unwrap();

        let metrics = ConversionMetrics {
            arm: "kin-compat".to_string(),
            repo_name: "test-repo".to_string(),
            commit_sha: Some("abc123".to_string()),
            init_duration_ms: 100.0,
            commit_duration_ms: 200.0,
            kin_dir_size_bytes: 1024,
            git_dir_size_bytes: 2048,
            entity_count: 50,
            file_count: 10,
            total_setup_ms: 300.0,
            cached: false,
            original_conversion_ms: None,
            cached_at: None,
        };

        let cache_name = "test-cache-roundtrip-v2";
        write_to_cache(cache_name, &arm_dir, &metrics, "kin 0.1.0", "abc123def456", "compat");

        // Verify cache entry exists
        let cache_entry = prepared_cache_dir().join(cache_name);
        assert!(cache_entry.join("arm").join(".kin").exists());
        assert!(cache_entry.join("cache-meta.json").exists());
        assert!(cache_entry.join("arm").join("CLAUDE.md").exists());

        // Verify sidecar has kin_version and arm_mode
        let meta_json = fs::read_to_string(cache_entry.join("cache-meta.json")).unwrap();
        let meta: CacheMeta = serde_json::from_str(&meta_json).unwrap();
        assert_eq!(meta.kin_version, "kin 0.1.0");
        assert_eq!(meta.kin_build_hash, "abc123def456");
        assert_eq!(meta.arm_mode, "compat");
        assert_eq!(meta.init_duration_ms, 100.0);
        assert_eq!(meta.commit_duration_ms, 200.0);

        // Restore into a new dir
        let restore_dir = tmp.join("restore");
        fs::create_dir_all(&restore_dir).unwrap();
        let restored = try_restore_from_cache(cache_name, &restore_dir, "kin-compat");
        assert!(restored.is_some());
        let restored = restored.unwrap();
        assert!(restored.cached);
        assert_eq!(restored.entity_count, 50);
        assert_eq!(restored.repo_name, "test-repo");
        assert_eq!(restored.original_conversion_ms, Some(300.0));
        assert!(restored.cached_at.is_some());

        // Verify .kin/ was copied into the run dir (not a reference to cache)
        assert!(restore_dir.join(".kin").join("config.json").exists());
        assert!(restore_dir.join(".kin").join("graph").join("data.db").exists());
        // Verify assistant docs were restored
        assert!(restore_dir.join("CLAUDE.md").exists());

        // Verify the cache dir is untouched (immutable seed)
        assert!(cache_entry.join("arm").join(".kin").join("config.json").exists());

        // Cleanup
        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(&cache_entry);
    }

    #[test]
    fn cache_meta_serialization() {
        let meta = CacheMeta {
            repo_name: "test-repo".to_string(),
            commit_sha: "abc123".to_string(),
            entity_count: 50,
            file_count: 10,
            kin_dir_size_bytes: 1024,
            conversion_duration_ms: 300.0,
            init_duration_ms: 100.0,
            commit_duration_ms: 200.0,
            kin_version: "kin 0.1.0".to_string(),
            kin_build_hash: "abc123def456".to_string(),
            arm_mode: "compat".to_string(),
            cached_at: "2026-03-12T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let parsed: CacheMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.repo_name, "test-repo");
        assert_eq!(parsed.entity_count, 50);
        assert_eq!(parsed.kin_version, "kin 0.1.0");
        assert_eq!(parsed.arm_mode, "compat");
    }

    #[test]
    fn per_arm_cache_names_differ() {
        let repo_hash = hash_string("/path/to/repo");
        let compat = format!("{repo_hash}-abc123-build456-compat");
        let native = format!("{repo_hash}-abc123-build456-native");
        assert_ne!(compat, native);
        assert!(compat.ends_with("-compat"));
        assert!(native.ends_with("-native"));
    }

    #[test]
    fn canonicalize_repo_handles_url() {
        let url = "https://github.com/org/repo.git";
        assert_eq!(canonicalize_repo(url), url);

        let ssh = "git@github.com:org/repo.git";
        assert_eq!(canonicalize_repo(ssh), ssh);
    }

    #[test]
    fn canonicalize_repo_handles_local_path() {
        let result = canonicalize_repo("/tmp");
        assert!(result.contains("tmp"));
    }

    #[test]
    fn create_isolated_env_creates_dirs_and_returns_overrides() {
        let tmp = std::env::temp_dir().join("kin-bench-test-isolated-env");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let dummy_bin = Path::new("/usr/local/bin/kin");
        let env =
            create_isolated_env(&tmp, super::BenchmarkArm::KinCompat, dummy_bin, false, false).unwrap();

        assert!(env.len() >= 3);
        assert_eq!(env[0].0, "HOME");
        assert_eq!(env[1].0, "XDG_CONFIG_HOME");
        assert_eq!(env[2].0, "XDG_DATA_HOME");

        let home_dir = tmp.join(".bench-home");
        assert!(home_dir.exists());
        assert!(home_dir.join(".claude").exists());
        assert_eq!(env[0].1, home_dir.display().to_string());
        assert!(
            env.iter()
                .any(|(k, v)| k == "PATH" && v.starts_with("/usr/local/bin")),
            "Kin arm should prepend kin binary dir to PATH"
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn create_isolated_env_works_for_all_arms() {
        let tmp = std::env::temp_dir().join("kin-bench-test-isolated-env-arms");
        let _ = fs::remove_dir_all(&tmp);

        let dummy_bin = Path::new("/usr/local/bin/kin");
        for arm in [
            super::BenchmarkArm::Git,
            super::BenchmarkArm::KinCompat,
            super::BenchmarkArm::KinNative,
        ] {
            let arm_dir = tmp.join(format!("{arm:?}"));
            fs::create_dir_all(&arm_dir).unwrap();
            let env = create_isolated_env(&arm_dir, arm, dummy_bin, false, false).unwrap();
            assert!(env.len() >= 3);
            assert!(arm_dir.join(".bench-home").exists());
        }

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn create_isolated_env_kin_arm_prepends_path() {
        let tmp = std::env::temp_dir().join("kin-bench-test-kin-arm-cli-first");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let dummy_bin = Path::new("/usr/local/bin/kin");
        let env =
            create_isolated_env(&tmp, super::BenchmarkArm::KinNative, dummy_bin, false, false).unwrap();

        assert!(
            env.iter()
                .any(|(k, v)| k == "PATH" && v.starts_with("/usr/local/bin")),
            "Kin arm should prepend kin binary dir to PATH"
        );

        let home = tmp.join(".bench-home");
        assert!(
            !home.join(".codex").join("config.toml").exists(),
            "CLI-first mode should not create Codex MCP config"
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn create_isolated_env_can_enable_native_discovery_restriction() {
        let tmp = std::env::temp_dir().join("kin-bench-test-native-discovery-restriction");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".kin").join("shims")).unwrap();
        fs::create_dir_all(tmp.join(".kin").join("source-root")).unwrap();

        let dummy_bin = Path::new("/usr/local/bin/kin");
        let env =
            create_isolated_env(&tmp, super::BenchmarkArm::KinNative, dummy_bin, true, false).unwrap();

        assert!(
            env.iter().any(|(k, v)| k == "KIN_DISCOVERY_MODE" && v == "deny"),
            "native restriction mode should set KIN_DISCOVERY_MODE=deny"
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn create_isolated_env_can_enable_native_filesystem_restriction() {
        let tmp = std::env::temp_dir().join("kin-bench-test-native-filesystem-restriction");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".kin").join("shims")).unwrap();
        fs::create_dir_all(tmp.join(".kin").join("source-root")).unwrap();

        let dummy_bin = Path::new("/usr/local/bin/kin");
        let env =
            create_isolated_env(&tmp, super::BenchmarkArm::KinNative, dummy_bin, false, true).unwrap();

        assert!(
            env.iter().any(|(k, v)| k == "KIN_DISCOVERY_MODE" && v == "deny"),
            "native filesystem restriction should set KIN_DISCOVERY_MODE=deny"
        );
        assert!(
            env.iter().any(|(k, v)| k == "KIN_CONTENT_MODE" && v == "deny"),
            "native filesystem restriction should set KIN_CONTENT_MODE=deny"
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn create_isolated_env_git_arm_does_not_seed_assistant_configs() {
        let _guard = env_lock();
        let tmp = std::env::temp_dir().join("kin-bench-test-git-arm-no-configs");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let dummy_bin = Path::new("/usr/local/bin/kin");
        let _env = create_isolated_env(&tmp, super::BenchmarkArm::Git, dummy_bin, false, false).unwrap();

        let home = tmp.join(".bench-home");
        assert!(
            !home.join(".codex").join("config.toml").exists(),
            ".codex/config.toml (MCP config) should not exist for Git arm"
        );

        let gemini_settings = home.join(".gemini").join("settings.json");
        if gemini_settings.exists() {
            let content = fs::read_to_string(&gemini_settings).unwrap();
            assert!(
                !content.contains("mcpServers"),
                ".gemini/settings.json should not contain MCP config for Git arm"
            );
        }

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn preserve_auth_artifacts_symlinks_existing_files() {
        let tmp = std::env::temp_dir().join("kin-bench-test-auth-preserve");
        let _ = fs::remove_dir_all(&tmp);

        let real_home = tmp.join("real-home");
        fs::create_dir_all(real_home.join(".codex")).unwrap();
        fs::write(real_home.join(".codex").join("auth.json"), r#"{"token":"test"}"#).unwrap();
        fs::create_dir_all(real_home.join(".gemini")).unwrap();
        fs::write(
            real_home.join(".gemini").join("oauth_creds.json"),
            r#"{"creds":"test"}"#,
        )
        .unwrap();

        let isolated_home = tmp.join("isolated-home");
        fs::create_dir_all(isolated_home.join(".claude")).unwrap();

        preserve_auth_artifacts(&real_home, &isolated_home).unwrap();

        let codex_auth = isolated_home.join(".codex").join("auth.json");
        assert!(codex_auth.exists(), "codex auth.json should be symlinked");
        #[cfg(unix)]
        assert!(
            codex_auth.symlink_metadata().unwrap().file_type().is_symlink(),
            "codex auth.json should be a symlink, not a copy"
        );

        let gemini_auth = isolated_home.join(".gemini").join("oauth_creds.json");
        assert!(gemini_auth.exists(), "gemini oauth_creds.json should be symlinked");

        assert!(
            !isolated_home.join(".claude").join("credentials.json").exists(),
            "non-existent Claude auth should not create a dangling symlink"
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn api_key_env_vars_passed_through() {
        let _guard = env_lock();
        let tmp = std::env::temp_dir().join("kin-bench-test-api-key-passthrough");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        std::env::set_var("ANTHROPIC_API_KEY", "test-key-12345");

        let dummy_bin = Path::new("/usr/local/bin/kin");
        let env = create_isolated_env(&tmp, super::BenchmarkArm::Git, dummy_bin, false, false).unwrap();

        let has_key = env.iter().any(|(k, v)| k == "ANTHROPIC_API_KEY" && v == "test-key-12345");
        assert!(has_key, "ANTHROPIC_API_KEY should be passed through");

        std::env::remove_var("ANTHROPIC_API_KEY");
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn read_gemini_auth_settings_extracts_auth_block() {
        let tmp = tempfile::tempdir().unwrap();
        let gemini_dir = tmp.path().join(".gemini");
        fs::create_dir_all(&gemini_dir).unwrap();
        fs::write(
            gemini_dir.join("settings.json"),
            r#"{"security":{"auth":{"selectedType":"oauth-personal"}},"ui":{"theme":"dark"}}"#,
        )
        .unwrap();

        let auth = read_gemini_auth_settings(tmp.path()).unwrap();
        assert_eq!(auth["security"]["auth"]["selectedType"], "oauth-personal");
        assert!(auth.get("ui").is_none());
    }

    #[test]
    fn render_gemini_settings_merges_auth_and_mcp() {
        let auth = json!({
            "security": {
                "auth": {
                    "selectedType": "oauth-personal"
                }
            }
        });

        let rendered = render_gemini_settings(Some(&auth), Some(Path::new("/usr/local/bin/kin"))).unwrap();
        let parsed: Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(parsed["security"]["auth"]["selectedType"], "oauth-personal");
        assert_eq!(parsed["mcpServers"]["kin"]["command"], "/usr/local/bin/kin");
        assert_eq!(parsed["mcpServers"]["kin"]["args"][0], "mcp");
        assert_eq!(parsed["mcpServers"]["kin"]["args"][1], "start");
    }

    #[test]
    fn create_isolated_env_sets_kin_shim_log_for_native_arm() {
        let tmp = std::env::temp_dir().join("kin-bench-test-shim-log-env");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join(".kin").join("shims")).unwrap();
        fs::create_dir_all(tmp.join(".kin").join("source-root")).unwrap();

        let dummy_bin = Path::new("/usr/local/bin/kin");
        let env =
            create_isolated_env(&tmp, super::BenchmarkArm::KinNative, dummy_bin, false, false).unwrap();

        let shim_log = env.iter().find(|(k, _)| k == "KIN_SHIM_LOG");
        assert!(
            shim_log.is_some(),
            "KIN_SHIM_LOG should be set for KinNative arm"
        );
        let log_path = &shim_log.unwrap().1;
        assert!(
            log_path.contains(".bench-home"),
            "shim log path should be inside .bench-home"
        );
        assert!(
            log_path.ends_with("shim-log.jsonl"),
            "shim log path should end with shim-log.jsonl"
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn create_isolated_env_no_shim_log_for_git_arm() {
        let tmp = std::env::temp_dir().join("kin-bench-test-no-shim-log-git");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let dummy_bin = Path::new("/usr/local/bin/kin");
        let env =
            create_isolated_env(&tmp, super::BenchmarkArm::Git, dummy_bin, false, false).unwrap();

        let shim_log = env.iter().find(|(k, _)| k == "KIN_SHIM_LOG");
        assert!(
            shim_log.is_none(),
            "KIN_SHIM_LOG should NOT be set for Git arm"
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn shim_log_path_is_deterministic() {
        let dir = Path::new("/tmp/bench-arm");
        let path = shim_log_path(dir);
        assert_eq!(path, PathBuf::from("/tmp/bench-arm/.bench-home/shim-log.jsonl"));
    }

    #[test]
    fn collect_shim_log_returns_none_when_no_file() {
        let tmp = tempfile::tempdir().unwrap();

        let result = collect_shim_log(tmp.path());
        assert!(result.is_none());
    }

    #[test]
    fn collect_shim_log_returns_none_for_empty_file() {
        let tmp = tempfile::tempdir().unwrap();
        let bench_home = tmp.path().join(".bench-home");
        fs::create_dir_all(&bench_home).unwrap();
        fs::write(bench_home.join("shim-log.jsonl"), "").unwrap();

        let result = collect_shim_log(tmp.path());
        assert!(result.is_none());
    }

    #[test]
    fn collect_shim_log_parses_valid_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let bench_home = tmp.path().join(".bench-home");
        fs::create_dir_all(&bench_home).unwrap();

        let content = concat!(
            r#"{"cmd":"cat","args":"","start_epoch_ms":1000,"end_epoch_ms":1012,"exit_code":0}"#,
            "\n",
            r#"{"cmd":"rg","args":"","start_epoch_ms":1020,"end_epoch_ms":1085,"exit_code":0}"#,
            "\n",
        );
        fs::write(bench_home.join("shim-log.jsonl"), content).unwrap();

        let entries = collect_shim_log(tmp.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].cmd, "cat");
        assert_eq!(entries[1].cmd, "rg");
    }

    #[test]
    fn collect_shim_log_skips_malformed_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let bench_home = tmp.path().join(".bench-home");
        fs::create_dir_all(&bench_home).unwrap();

        let content = concat!(
            r#"{"cmd":"cat","args":"","start_epoch_ms":1000,"end_epoch_ms":1012,"exit_code":0}"#,
            "\n",
            "this is not json\n",
            r#"{"cmd":"rg","args":"","start_epoch_ms":1020,"end_epoch_ms":1085,"exit_code":0}"#,
            "\n",
        );
        fs::write(bench_home.join("shim-log.jsonl"), content).unwrap();

        let entries = collect_shim_log(tmp.path()).unwrap();
        assert_eq!(entries.len(), 2);
    }
}
