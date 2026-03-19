use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::shim_log::ShimLogEntry;
use super::BenchmarkArm;
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

/// Files/directories that remain visible at the root of a native benchmark arm.
/// NOTE: `.git` AND `.kin` are deliberately excluded — the native arm uses
/// Kin's MCP tools for code access.  Keeping `.kin/` lets assistants bypass
/// MCP by reading `.kin/objects/` blobs directly with filesystem tools.
/// The entire `.kin/` directory is relocated outside the workspace; the MCP
/// wrapper script (`_kin-mcp.sh`) points the server at the relocated copy.
const NATIVE_CONTROL_ROOT_KEEP: &[&str] = &[
    "README.md",
    "AGENTS.md",
    "CLAUDE.md",
    "CODEX.md",
    "GEMINI.md",
    ".mcp.json",
    "_kin-mcp.sh",
    ".claude",
    ".bench-home",
];

/// Files/directories that remain visible at the root of a native-CLI benchmark arm.
/// Unlike the MCP native arm, `.kin` is KEPT so `kin` CLI commands work from cwd.
/// No MCP wrapper script is needed.
const NATIVE_CLI_CONTROL_ROOT_KEEP: &[&str] = &[
    "README.md",
    "AGENTS.md",
    "CLAUDE.md",
    "CODEX.md",
    "GEMINI.md",
    ".kin",
    ".claude",
    ".bench-home",
];

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

/// A prepared benchmark workspace with up to 5 isolated arms.
pub struct BenchWorkspace {
    pub root: PathBuf,
    pub git_dir: PathBuf,
    pub kin_compat_dir: PathBuf,
    pub kin_native_dir: PathBuf,
    /// Kin-native-cli arm directory — native workspace with kin CLI (no MCP).
    pub kin_native_cli_dir: Option<PathBuf>,
    /// Kin-codex-native arm directory (only set when kin-codex is available).
    pub kin_codex_native_dir: Option<PathBuf>,
    /// Conversion metrics for each Kin arm.
    pub conversions: Vec<ConversionMetrics>,
    /// Human-readable repository name extracted from the source URL/path.
    pub repo_name: String,
    /// Planted benchmark artifacts (if using validated task set).
    /// Metadata describing exactly what was planted and what the correct answers are.
    pub planted: Option<super::planted::PlantedArtifacts>,
}

/// Extract a human-readable repository name from a source URL or local path.
///
/// Examples:
///   "/tmp/bench-repos/fastapi"                    → "fastapi"
///   "https://github.com/colinhacks/zod.git"       → "zod"
///   "git@github.com:pallets/flask.git"            → "flask"
pub fn repo_display_name(repo_source: &str) -> String {
    let trimmed = repo_source.trim_end_matches('/');
    let candidate = trimmed
        .rsplit(['/', ':'])
        .next()
        .filter(|segment| !segment.is_empty())
        .unwrap_or(trimmed);
    candidate.trim_end_matches(".git").to_string()
}

impl BenchWorkspace {
    /// Set up a benchmark workspace from a repository source.
    ///
    /// `repo` can be a URL (contains "://" or starts with "git@") or a local path.
    /// Creates copies under a tempdir for git plus the enabled Kin arms.
    /// Uses conversion cache by default. See `setup_with_options` for `fresh_conversion`.
    pub fn setup(repo: &str, kin_binary: &Path) -> Result<Self> {
        Self::setup_with_options(repo, kin_binary, false, false)
    }

    /// Like `setup`, but with cache control.
    ///
    /// When `fresh_conversion` is true (--fresh-conversion / --rebuild-cache),
    /// ignore existing cache entries but DO update the cache after conversion.
    pub fn setup_with_options(
        repo: &str,
        kin_binary: &Path,
        fresh_conversion: bool,
        include_kin_codex_native: bool,
    ) -> Result<Self> {
        let real_repo_name = repo_display_name(repo);

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

        eprintln!("Setup [1/5] Cloning source repo...");
        prepare_source_checkout(repo, &source_dir)?;

        // Plant benchmark artifacts into source BEFORE arm copies.
        // Every arm gets identical planted files for fair comparison.
        eprintln!("Setup [1.5/5] Planting validated benchmark artifacts...");
        let planted = super::planted::plant_artifacts(&source_dir);
        eprintln!(
            "  Planted tag={} lang={} task_families=7 files={}",
            planted.tag,
            planted.language,
            planted.chain.chain_files.len()
                + planted.chain.decoy_files.len()
                + planted.impact.import_files.len()
                + planted.impact.decoy_files.len()
                + 3, // definition + bugfix + feature
        );

        let git_dir = root.join("arm-git");
        let kin_compat_dir = root.join("arm-kin-compat");
        let kin_native_dir = root.join("arm-kin-native");

        copy_dir_recursive(&source_dir, &git_dir)?;
        copy_dir_recursive(&source_dir, &kin_compat_dir)?;
        copy_dir_recursive(&source_dir, &kin_native_dir)?;

        eprintln!("Setup [2/5] Preparing git arm...");
        prepare_git_arm(&git_dir)?;

        // Compute cache key components.
        // Include the planted tag so the cache always misses when planted
        // artifacts are present — the Kin graph must index the planted files.
        let canonical_repo = canonicalize_repo(repo);
        let source_commit_sha = get_commit_sha(&source_dir);
        let kin_version_info = get_kin_version(kin_binary);
        let kin_build_hash = compute_kin_build_hash(kin_binary, &kin_version_info);
        let repo_hash = hash_string(&canonical_repo);

        let commit_part = source_commit_sha.as_deref().unwrap_or("unknown");
        let planted_suffix = format!("-planted-{}", planted.tag);

        eprintln!("Setup [3/5] Preparing kin-compat arm...");
        let compat_cache_name =
            format!("{repo_hash}-{commit_part}-{kin_build_hash}-compat{planted_suffix}");
        let mut compat_conversion = prepare_arm_with_cache(
            &kin_compat_dir,
            kin_binary,
            false,
            &compat_cache_name,
            fresh_conversion,
            &kin_version_info,
            &kin_build_hash,
            &real_repo_name,
        )?;
        if let Err(err) = verify_planted_search_targets(
            &kin_compat_dir,
            kin_binary,
            BenchmarkArm::KinCompat,
            &planted,
        ) {
            if compat_conversion.cached {
                eprintln!("  Cached kin-compat graph missing planted targets; rebuilding fresh...");
                fs::remove_dir_all(&kin_compat_dir)
                    .map_err(|e| BenchError::io(&kin_compat_dir, e))?;
                copy_dir_recursive(&source_dir, &kin_compat_dir)?;
                compat_conversion = prepare_arm_with_cache(
                    &kin_compat_dir,
                    kin_binary,
                    false,
                    &compat_cache_name,
                    true,
                    &kin_version_info,
                    &kin_build_hash,
                    &real_repo_name,
                )?;
                verify_planted_search_targets(
                    &kin_compat_dir,
                    kin_binary,
                    BenchmarkArm::KinCompat,
                    &planted,
                )?;
            } else {
                return Err(err);
            }
        }

        eprintln!("Setup [4/5] Preparing kin-native arm...");
        let native_cache_name =
            format!("{repo_hash}-{commit_part}-{kin_build_hash}-native{planted_suffix}");
        let mut native_conversion = if !fresh_conversion {
            if let Some(mut metrics) = try_restore_from_cache(
                &native_cache_name,
                &kin_native_dir,
                "kin-native",
                kin_binary,
                true,
            ) {
                metrics.repo_name = real_repo_name.clone();
                metrics
            } else {
                let metrics = prepare_native_from_compat(
                    &kin_native_dir,
                    &kin_compat_dir,
                    kin_binary,
                    compat_conversion.entity_count,
                    &real_repo_name,
                )?;
                write_to_cache(
                    &native_cache_name,
                    &kin_native_dir,
                    &metrics,
                    &kin_version_info,
                    &kin_build_hash,
                    "native",
                );
                metrics
            }
        } else {
            let metrics = prepare_native_from_compat(
                &kin_native_dir,
                &kin_compat_dir,
                kin_binary,
                compat_conversion.entity_count,
                &real_repo_name,
            )?;
            write_to_cache(
                &native_cache_name,
                &kin_native_dir,
                &metrics,
                &kin_version_info,
                &kin_build_hash,
                "native",
            );
            metrics
        };
        if let Err(err) = verify_planted_search_targets(
            &kin_native_dir,
            kin_binary,
            BenchmarkArm::KinNative,
            &planted,
        ) {
            if native_conversion.cached {
                eprintln!("  Cached kin-native graph missing planted targets; rebuilding fresh...");
                fs::remove_dir_all(&kin_native_dir)
                    .map_err(|e| BenchError::io(&kin_native_dir, e))?;
                copy_dir_recursive(&source_dir, &kin_native_dir)?;
                native_conversion = prepare_native_from_compat(
                    &kin_native_dir,
                    &kin_compat_dir,
                    kin_binary,
                    compat_conversion.entity_count,
                    &real_repo_name,
                )?;
                write_to_cache(
                    &native_cache_name,
                    &kin_native_dir,
                    &native_conversion,
                    &kin_version_info,
                    &kin_build_hash,
                    "native",
                );
                verify_planted_search_targets(
                    &kin_native_dir,
                    kin_binary,
                    BenchmarkArm::KinNative,
                    &planted,
                )?;
            } else {
                return Err(err);
            }
        }

        // --- kin-native-cli arm ---
        // Native workspace with .kin/ kept in place for CLI access (no MCP).
        eprintln!("Setup [5/7] Preparing kin-native-cli arm...");
        let native_cli_dir = root.join("arm-kin-native-cli");
        copy_dir_recursive(&source_dir, &native_cli_dir)?;
        let native_cli_conversion = prepare_native_cli_from_compat(
            &native_cli_dir,
            &kin_compat_dir,
            kin_binary,
            compat_conversion.entity_count,
            &real_repo_name,
        )?;
        verify_planted_search_targets(
            &native_cli_dir,
            kin_binary,
            BenchmarkArm::KinNativeCli,
            &planted,
        )?;

        // --- Optional kin-codex-native arm ---
        // Only set up when explicitly requested AND the kin-codex binary is
        // available on PATH. This keeps the default benchmark story focused on
        // the 4 core product arms.
        let kin_codex_available = include_kin_codex_native
            && super::detect::detect_available_clis()
                .iter()
                .any(|c| c.binary == "kin-codex");

        let (kin_codex_native_dir, codex_conversion) = if kin_codex_available {
            eprintln!("Setup [6/7] Preparing kin-codex-native arm...");
            let codex_dir = root.join("arm-kin-codex-native");
            copy_dir_recursive(&source_dir, &codex_dir)?;

            let codex_cache_name =
                format!("{repo_hash}-{commit_part}-{kin_build_hash}-codex-native{planted_suffix}");
            let mut codex_conversion = if !fresh_conversion {
                if let Some(mut metrics) = try_restore_from_cache_no_docs(
                    &codex_cache_name,
                    &codex_dir,
                    "kin-codex-native",
                    kin_binary,
                ) {
                    metrics.repo_name = real_repo_name.clone();
                    metrics
                } else {
                    let metrics = prepare_codex_native_from_compat(
                        &codex_dir,
                        &kin_compat_dir,
                        kin_binary,
                        compat_conversion.entity_count,
                        &real_repo_name,
                    )?;
                    write_to_cache(
                        &codex_cache_name,
                        &codex_dir,
                        &metrics,
                        &kin_version_info,
                        &kin_build_hash,
                        "codex-native",
                    );
                    metrics
                }
            } else {
                let metrics = prepare_codex_native_from_compat(
                    &codex_dir,
                    &kin_compat_dir,
                    kin_binary,
                    compat_conversion.entity_count,
                    &real_repo_name,
                )?;
                write_to_cache(
                    &codex_cache_name,
                    &codex_dir,
                    &metrics,
                    &kin_version_info,
                    &kin_build_hash,
                    "codex-native",
                );
                metrics
            };
            if let Err(err) = verify_planted_search_targets(
                &codex_dir,
                kin_binary,
                BenchmarkArm::KinCodexNative,
                &planted,
            ) {
                if codex_conversion.cached {
                    eprintln!(
                        "  Cached kin-codex-native graph missing planted targets; rebuilding fresh..."
                    );
                    fs::remove_dir_all(&codex_dir).map_err(|e| BenchError::io(&codex_dir, e))?;
                    copy_dir_recursive(&source_dir, &codex_dir)?;
                    codex_conversion = prepare_codex_native_from_compat(
                        &codex_dir,
                        &kin_compat_dir,
                        kin_binary,
                        compat_conversion.entity_count,
                        &real_repo_name,
                    )?;
                    write_to_cache(
                        &codex_cache_name,
                        &codex_dir,
                        &codex_conversion,
                        &kin_version_info,
                        &kin_build_hash,
                        "codex-native",
                    );
                    verify_planted_search_targets(
                        &codex_dir,
                        kin_binary,
                        BenchmarkArm::KinCodexNative,
                        &planted,
                    )?;
                } else {
                    return Err(err);
                }
            }
            (Some(codex_dir), Some(codex_conversion))
        } else {
            (None, None)
        };

        let step_label = if kin_codex_available { "7/7" } else { "6/6" };
        eprintln!("Setup [{step_label}] Verifying workspace...");

        let mut conversions = vec![compat_conversion, native_conversion, native_cli_conversion];
        if let Some(c) = codex_conversion {
            conversions.push(c);
        }

        Ok(Self {
            root,
            git_dir,
            kin_compat_dir,
            kin_native_dir,
            kin_native_cli_dir: Some(native_cli_dir),
            kin_codex_native_dir,
            conversions,
            repo_name: real_repo_name,
            planted: Some(planted),
        })
    }

    /// Get the directory for a given arm.
    pub fn arm_dir(&self, arm: BenchmarkArm) -> &Path {
        match arm {
            BenchmarkArm::Git => &self.git_dir,
            BenchmarkArm::KinCompat => &self.kin_compat_dir,
            BenchmarkArm::KinNative => &self.kin_native_dir,
            BenchmarkArm::KinNativeCli => self
                .kin_native_cli_dir
                .as_deref()
                .expect("kin-native-cli arm not available"),
            BenchmarkArm::KinCodexNative => self
                .kin_codex_native_dir
                .as_deref()
                .expect("kin-codex-native arm not available"),
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
    // Bench conversion caching should be stable across normal local rebuilds.
    // Use the explicit --fresh-conversion / --rebuild-cache flag when the
    // semantic import path changes and a cache bust is desired.
    let _ = kin_binary;
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

/// Return the cached-source directory.
fn source_checkout_cache_dir() -> PathBuf {
    bench_cache_root().join("source-checkouts")
}

fn prepare_source_checkout(repo: &str, source_dir: &Path) -> Result<()> {
    if let Some(cache_name) = source_checkout_cache_name(repo) {
        if try_restore_source_checkout_cache(&cache_name, source_dir) {
            return Ok(());
        }
        clone_or_copy_source(repo, source_dir)?;
        write_source_checkout_cache(&cache_name, source_dir);
        return Ok(());
    }

    clone_or_copy_source(repo, source_dir)
}

fn clone_or_copy_source(repo: &str, source_dir: &Path) -> Result<()> {
    if repo.contains("://") || repo.starts_with("git@") {
        let status = Command::new("git")
            .args(["clone", "--depth", "1", repo])
            .arg(source_dir)
            .status()
            .map_err(|e| BenchError::io(repo, e))?;
        if !status.success() {
            return Err(BenchError::Other(format!("git clone failed for {repo}")));
        }
        return Ok(());
    }

    let src = Path::new(repo);
    if !src.is_dir() {
        return Err(BenchError::Other(format!("not a directory: {repo}")));
    }

    let canonical_src = src.canonicalize().map_err(|e| BenchError::io(src, e))?;
    let file_url = format!("file://{}", canonical_src.display());
    let status = Command::new("git")
        .args(["clone", "--depth", "1", &file_url])
        .arg(source_dir)
        .status()
        .map_err(|e| BenchError::io(repo, e))?;
    if !status.success() {
        copy_dir_recursive(&canonical_src, source_dir)?;
    }
    Ok(())
}

fn source_checkout_cache_name(repo: &str) -> Option<String> {
    if repo.contains("://") || repo.starts_with("git@") {
        return None;
    }

    let src = Path::new(repo);
    if !src.is_dir() || !src.join(".git").exists() || !git_worktree_clean(src) {
        return None;
    }

    let canonical_repo = canonicalize_repo(repo);
    let commit_sha = get_commit_sha(src)?;
    Some(format!("{}-{}", hash_string(&canonical_repo), commit_sha))
}

fn git_worktree_clean(dir: &Path) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().is_empty())
        .unwrap_or(false)
}

fn try_restore_source_checkout_cache(cache_name: &str, source_dir: &Path) -> bool {
    let cache_entry = source_checkout_cache_dir().join(cache_name);
    if !cache_entry.is_dir() {
        return false;
    }

    if source_dir.exists() {
        let _ = fs::remove_dir_all(source_dir);
    }
    if fs::create_dir_all(source_dir).is_err() {
        return false;
    }

    if let Err(err) = copy_dir_smart(&cache_entry, source_dir) {
        eprintln!("  Source cache restore failed: {}", err);
        clean_dir_contents(source_dir);
        return false;
    }

    eprintln!("  Source cache hit: restored local checkout");
    true
}

fn write_source_checkout_cache(cache_name: &str, source_dir: &Path) {
    let cache_entry = source_checkout_cache_dir().join(cache_name);
    if cache_entry.exists() {
        let _ = fs::remove_dir_all(&cache_entry);
    }
    if fs::create_dir_all(&cache_entry).is_err() {
        return;
    }
    if copy_dir_recursive(source_dir, &cache_entry).is_err() {
        let _ = fs::remove_dir_all(&cache_entry);
        return;
    }
    eprintln!("  Cached source checkout");
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
        let ft = entry
            .file_type()
            .map_err(|e| BenchError::io(&src_path, e))?;

        if ft.is_dir() {
            copy_dir_with_strategy(&src_path, &dst_path, strategy)?;
        } else if ft.is_file() {
            match strategy {
                CopyStrategy::Reflink | CopyStrategy::Copy => {
                    fs::copy(&src_path, &dst_path).map_err(|e| BenchError::io(&src_path, e))?;
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
    kin_binary: &Path,
    native_mode: bool,
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
    if let Err(err) = copy_dir_smart(&cached_kin, &dst_kin) {
        eprintln!("  Cache restore failed for {} .kin copy: {}", arm_name, err);
        return None;
    }

    // Exclude .kin/ from ripgrep/grep so blob store doesn't pollute search results.
    let gitignore = arm_dir.join(".gitignore");
    let mut gi = fs::read_to_string(&gitignore).unwrap_or_default();
    if !gi.contains(".kin") {
        if !gi.ends_with('\n') && !gi.is_empty() {
            gi.push('\n');
        }
        gi.push_str(".kin/\n");
        if let Err(err) = fs::write(&gitignore, &gi) {
            eprintln!(
                "  Cache restore: failed to update .gitignore for {}: {}",
                arm_name, err
            );
        }
    }

    // Always regenerate assistant docs on restore so warm-cache runs pick up the latest
    // guidance instead of whatever happened to be embedded when the cache seed was built.
    if let Err(err) = write_assistant_docs(arm_dir, kin_binary, native_mode) {
        eprintln!(
            "  Cache restore failed for {} assistant docs: {}",
            arm_name, err
        );
        return None;
    }
    if native_mode {
        // Relocate .kin/ BEFORE pruning — prune would delete it since
        // .kin is not in NATIVE_CONTROL_ROOT_KEEP.
        if let Err(err) = relocate_kin_dir(arm_dir) {
            eprintln!("  Cache restore failed for {} relocate: {}", arm_name, err);
            return None;
        }
        if let Err(err) = prune_native_control_root(arm_dir) {
            eprintln!("  Cache restore failed for {} prune: {}", arm_name, err);
            return None;
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

/// Remove source-tree content from the root of a native benchmark arm, leaving only the
/// control-root surface visible. Source files still live under `.kin/source-root/`.
fn prune_native_control_root(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root).map_err(|e| BenchError::io(root, e))? {
        let entry = entry.map_err(|e| BenchError::io(root, e))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if NATIVE_CONTROL_ROOT_KEEP
            .iter()
            .any(|keep| name_str.eq_ignore_ascii_case(keep))
        {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            fs::remove_dir_all(&path).map_err(|e| BenchError::io(&path, e))?;
        } else {
            fs::remove_file(&path).map_err(|e| BenchError::io(&path, e))?;
        }
    }
    Ok(())
}

/// Move the entire `.kin/` directory to a sibling "shadow workspace" outside
/// the arm directory.  The shadow workspace is a directory that looks like a
/// normal Kin repo to `KinLayout::discover` (it has a `.kin/` child) but
/// is invisible to Claude because it's not under the cwd that Claude uses.
///
/// Layout:
///   <bench-root>/<arm-name>/          ← Claude's cwd (empty control root)
///   <bench-root>/_kin-ws-<arm-name>/  ← shadow workspace
///   <bench-root>/_kin-ws-<arm-name>/.kin/  ← the actual Kin data
fn relocate_kin_dir(arm_dir: &Path) -> Result<()> {
    let src = arm_dir.join(".kin");
    if !src.is_dir() {
        return Ok(());
    }
    let shadow_ws = shadow_workspace_dir(arm_dir);
    if shadow_ws.exists() {
        fs::remove_dir_all(&shadow_ws).map_err(|e| BenchError::io(&shadow_ws, e))?;
    }
    fs::create_dir_all(&shadow_ws).map_err(|e| BenchError::io(&shadow_ws, e))?;
    let dst = shadow_ws.join(".kin");
    fs::rename(&src, &dst).map_err(|e| BenchError::io(&src, e))?;
    Ok(())
}

/// The shadow workspace directory for a native arm.
/// `kin mcp start` runs with cwd set here so `KinLayout::discover` finds `.kin/`.
fn shadow_workspace_dir(arm_dir: &Path) -> PathBuf {
    let arm_name = arm_dir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    arm_dir
        .parent()
        .unwrap_or(arm_dir)
        .join(format!("_kin-ws-{arm_name}"))
}

/// Return the relocated `.kin/` path inside the shadow workspace.
fn relocated_kin_dir(arm_dir: &Path) -> PathBuf {
    shadow_workspace_dir(arm_dir).join(".kin")
}

/// Return the relocated source-root within the shadow workspace.
fn relocated_source_root(arm_dir: &Path) -> PathBuf {
    relocated_kin_dir(arm_dir).join("source-root")
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

    // Copy .kin/ into cache — may be in the arm dir (compat) or shadow workspace (native)
    let src_kin = {
        let in_arm = arm_dir.join(".kin");
        if in_arm.is_dir() {
            in_arm
        } else {
            relocated_kin_dir(arm_dir)
        }
    };
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
            let _ = fs::copy(&src_doc, cached_arm.join(name));
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
#[allow(clippy::too_many_arguments)]
fn prepare_arm_with_cache(
    dir: &Path,
    kin_binary: &Path,
    native_mode: bool,
    cache_name: &str,
    fresh_conversion: bool,
    kin_version: &str,
    kin_build_hash: &str,
    repo_name: &str,
) -> Result<ConversionMetrics> {
    let arm_name = if native_mode {
        "kin-native"
    } else {
        "kin-compat"
    };
    let arm_mode = if native_mode { "native" } else { "compat" };

    // Try cache first (unless --fresh-conversion)
    if !fresh_conversion {
        if let Some(mut metrics) =
            try_restore_from_cache(cache_name, dir, arm_name, kin_binary, native_mode)
        {
            metrics.repo_name = repo_name.to_string();
            return Ok(metrics);
        }
    }

    // Cache miss (or forced fresh) — do full conversion
    let metrics = prepare_kin_arm(dir, kin_binary, native_mode, repo_name)?;

    // Always update cache (even on --fresh-conversion)
    write_to_cache(
        cache_name,
        dir,
        &metrics,
        kin_version,
        kin_build_hash,
        arm_mode,
    );

    Ok(metrics)
}

/// Prepare a Kin arm: run kin init + commit, write assistant docs,
/// optionally switch to native mode.
fn prepare_kin_arm(
    dir: &Path,
    kin_binary: &Path,
    native_mode: bool,
    repo_name: &str,
) -> Result<ConversionMetrics> {
    let total_start = Instant::now();
    let repo_name = repo_name.to_string();
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

    // Exclude .kin/ from ripgrep/grep searches so the blob store doesn't
    // pollute tool results with duplicate matches.  Without this, the compat
    // arm's Grep results include hits inside .kin/objects/ — inflating token
    // counts and confusing the agent.  The git arm has no .kin/ directory, so
    // this levels the playing field.
    let gitignore = dir.join(".gitignore");
    let mut gi = fs::read_to_string(&gitignore).unwrap_or_default();
    if !gi.contains(".kin") {
        if !gi.ends_with('\n') && !gi.is_empty() {
            gi.push('\n');
        }
        gi.push_str(".kin/\n");
        fs::write(&gitignore, &gi).map_err(|e| BenchError::io(&gitignore, e))?;
    }

    // Write assistant docs (includes .mcp.json for native mode and `kin mode native`)
    write_assistant_docs(dir, kin_binary, native_mode)?;

    // Measure directory sizes BEFORE relocating .kin/ (native mode moves it out)
    let kin_dir_size = dir_size(&dir.join(".kin"));
    let git_dir_size = dir_size(&dir.join(".git"));

    // In native mode, relocate .kin/ first (prune would delete it since .kin
    // is not in NATIVE_CONTROL_ROOT_KEEP), then prune source files from root.
    if native_mode {
        relocate_kin_dir(dir)?;
        prune_native_control_root(dir)?;
    }

    // Count source files (now in shadow workspace for native mode).
    let file_count = count_files(&source_file_root(dir, native_mode));
    let total_setup_ms = total_start.elapsed().as_secs_f64() * 1000.0;

    let arm_name = if native_mode {
        "kin-native"
    } else {
        "kin-compat"
    };

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

/// Prepare a native arm by reusing the already-indexed compat arm and only switching
/// the repo layout to native mode. This avoids paying the semantic import cost twice.
fn prepare_native_from_compat(
    native_dir: &Path,
    compat_dir: &Path,
    kin_binary: &Path,
    entity_count: u64,
    repo_name: &str,
) -> Result<ConversionMetrics> {
    let total_start = Instant::now();
    let repo_name = repo_name.to_string();
    let commit_sha = get_commit_sha(native_dir);

    let native_kin = native_dir.join(".kin");
    if native_kin.exists() {
        fs::remove_dir_all(&native_kin).map_err(|e| BenchError::io(&native_kin, e))?;
    }
    let compat_kin = compat_dir.join(".kin");
    copy_dir_smart(&compat_kin, &native_kin)?;

    let doc_files = ["CLAUDE.md", "AGENTS.md", "CODEX.md", "GEMINI.md"];
    for name in &doc_files {
        let src_doc = compat_dir.join(name);
        if src_doc.is_file() {
            fs::copy(&src_doc, native_dir.join(name)).map_err(|e| BenchError::io(&src_doc, e))?;
        }
    }

    // Write native-mode assistant docs — this internally runs `kin mode native`
    // first (to move source files), then overwrites docs with our MCP-oriented
    // versions and writes .mcp.json.
    write_assistant_docs(native_dir, kin_binary, true)?;

    // Measure .kin/ size BEFORE relocating it
    let kin_dir_size = dir_size(&native_dir.join(".kin"));
    let git_dir_size = dir_size(&native_dir.join(".git"));
    // Relocate .kin/ first, then prune (prune would delete .kin/ since
    // it's not in NATIVE_CONTROL_ROOT_KEEP)
    relocate_kin_dir(native_dir)?;
    prune_native_control_root(native_dir)?;
    let file_count = count_files(&source_file_root(native_dir, true));
    let total_setup_ms = total_start.elapsed().as_secs_f64() * 1000.0;

    Ok(ConversionMetrics {
        arm: "kin-native".to_string(),
        repo_name,
        commit_sha,
        init_duration_ms: 0.0,
        commit_duration_ms: 0.0,
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

/// Prepare a kin-codex-native arm by reusing the already-indexed compat arm.
///
/// Unlike `prepare_native_from_compat`, this does NOT relocate `.kin/` or prune
/// source files.  kin-codex has built-in Kin tool handlers (`kin_trace`,
/// `kin_search`, etc.) that shell out to the `kin` binary and need `.kin/`
/// discoverable from the working directory.  Relocating would break them.
///
/// CLI-oriented docs are written so kin-codex (and any other codex-family CLI)
/// can find tools by name.  An MCP wrapper is also written for clients that
/// support MCP server discovery via `.mcp.json`.
fn prepare_codex_native_from_compat(
    codex_dir: &Path,
    compat_dir: &Path,
    kin_binary: &Path,
    entity_count: u64,
    repo_name: &str,
) -> Result<ConversionMetrics> {
    let total_start = Instant::now();
    let repo_name = repo_name.to_string();
    let commit_sha = get_commit_sha(codex_dir);

    let codex_kin = codex_dir.join(".kin");
    if codex_kin.exists() {
        fs::remove_dir_all(&codex_kin).map_err(|e| BenchError::io(&codex_kin, e))?;
    }
    let compat_kin = compat_dir.join(".kin");
    copy_dir_smart(&compat_kin, &codex_kin)?;

    // Switch to native mode — this moves source files into .kin/source-root/
    // but we keep .kin/ in the arm dir so kin-codex's built-in handlers work.
    let native_output = Command::new(kin_binary)
        .args(["mode", "native"])
        .current_dir(codex_dir)
        .output()
        .map_err(|e| BenchError::io(kin_binary, e))?;
    if !native_output.status.success() {
        let stderr = String::from_utf8_lossy(&native_output.stderr);
        return Err(BenchError::Other(format!(
            "kin mode native failed for kin-codex arm: {stderr}"
        )));
    }

    // Write CLI-oriented docs — kin-codex's built-in system prompt
    // (kin_instructions.rs) already tells the model to use kin_trace, kin_search,
    // etc., but AGENTS.md/CODEX.md provide the benchmark-specific quick-start.
    write_native_cli_docs(codex_dir, kin_binary)?;

    // Also write MCP wrapper for clients that support `.mcp.json`.
    write_mcp_wrapper(codex_dir, kin_binary)?;

    let kin_dir_size = dir_size(&codex_dir.join(".kin"));
    let git_dir_size = dir_size(&codex_dir.join(".git"));
    let file_count = count_files(&source_file_root(codex_dir, false));
    let total_setup_ms = total_start.elapsed().as_secs_f64() * 1000.0;

    Ok(ConversionMetrics {
        arm: "kin-codex-native".to_string(),
        repo_name,
        commit_sha,
        init_duration_ms: 0.0,
        commit_duration_ms: 0.0,
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

/// Prepare a kin-native-cli arm by reusing the already-indexed compat arm.
/// Like `prepare_native_from_compat` but:
/// - DOES NOT relocate .kin/ (keeps it in arm dir for CLI access)
/// - DOES NOT write MCP wrapper or .mcp.json
/// - Writes CLI-oriented CLAUDE.md docs
fn prepare_native_cli_from_compat(
    native_cli_dir: &Path,
    compat_dir: &Path,
    kin_binary: &Path,
    entity_count: u64,
    repo_name: &str,
) -> Result<ConversionMetrics> {
    let total_start = Instant::now();
    let repo_name = repo_name.to_string();
    let commit_sha = get_commit_sha(native_cli_dir);

    // Copy .kin/ from compat arm
    let native_cli_kin = native_cli_dir.join(".kin");
    if native_cli_kin.exists() {
        fs::remove_dir_all(&native_cli_kin).map_err(|e| BenchError::io(&native_cli_kin, e))?;
    }
    let compat_kin = compat_dir.join(".kin");
    copy_dir_smart(&compat_kin, &native_cli_kin)?;

    // Switch to native mode (moves source files into .kin/source-root/)
    let native_output = Command::new(kin_binary)
        .args(["mode", "native"])
        .current_dir(native_cli_dir)
        .output()
        .map_err(|e| BenchError::io(kin_binary, e))?;
    if !native_output.status.success() {
        let stderr = String::from_utf8_lossy(&native_output.stderr);
        return Err(BenchError::Other(format!(
            "kin mode native failed for kin-native-cli arm: {stderr}"
        )));
    }

    // Measure sizes
    let kin_dir_size = dir_size(&native_cli_dir.join(".kin"));
    let git_dir_size = dir_size(&native_cli_dir.join(".git"));

    // Write CLI-oriented assistant docs (NO MCP)
    write_native_cli_docs(native_cli_dir, kin_binary)?;

    // Prune control root but KEEP .kin/
    prune_native_cli_control_root(native_cli_dir)?;

    let file_count = count_files(&native_cli_dir.join(".kin").join("source-root"));
    let total_setup_ms = total_start.elapsed().as_secs_f64() * 1000.0;

    Ok(ConversionMetrics {
        arm: "kin-native-cli".to_string(),
        repo_name,
        commit_sha,
        init_duration_ms: 0.0,
        commit_duration_ms: 0.0,
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

/// Remove source-tree content from the root of a native-CLI benchmark arm,
/// keeping `.kin/` in place (unlike the MCP arm which relocates it).
fn prune_native_cli_control_root(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root).map_err(|e| BenchError::io(root, e))? {
        let entry = entry.map_err(|e| BenchError::io(root, e))?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if NATIVE_CLI_CONTROL_ROOT_KEEP
            .iter()
            .any(|keep| name_str.eq_ignore_ascii_case(keep))
        {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            fs::remove_dir_all(&path).map_err(|e| BenchError::io(&path, e))?;
        } else {
            fs::remove_file(&path).map_err(|e| BenchError::io(&path, e))?;
        }
    }
    Ok(())
}

/// Write CLI-oriented assistant docs for the native-cli arm.
fn write_native_cli_docs(dir: &Path, kin_binary: &Path) -> Result<()> {
    let overview_section = run_kin_overview(dir, kin_binary);
    let cli_docs = format!(
        "\
# Kin (Native CLI)\n\
\n\
Source files live under `.kin/source-root/`. Use Grep/Read on `.kin/source-root/` for find-and-fix tasks.\n\
`kin refs <Name>` — callers/importers. Answer from output directly, no need to read files.\n\
`kin trace <Name> --compact` — source + deps. ONLY for call-chain tracing.\n\
Do NOT use kin commands for simple grep-then-fix tasks.\n\
{overview_section}"
    );

    let doc_files = ["CLAUDE.md", "AGENTS.md", "CODEX.md", "GEMINI.md"];
    for name in &doc_files {
        fs::write(dir.join(name), &cli_docs).map_err(|e| BenchError::io(dir, e))?;
    }

    // Write benchmark hooks (compat-style — no MCP)
    write_claude_benchmark_hooks(dir, false)?;

    Ok(())
}

/// Try to restore a cached prepared arm for kin-codex-native.
///
/// Unlike the standard cache restore, this keeps `.kin/` in the arm directory
/// (no relocation, no source pruning) so kin-codex's built-in handlers can
/// find the graph.  CLI-oriented docs and MCP wrapper are written fresh.
fn try_restore_from_cache_no_docs(
    cache_name: &str,
    arm_dir: &Path,
    arm_name: &str,
    kin_binary: &Path,
) -> Option<ConversionMetrics> {
    let cache_entry = prepared_cache_dir().join(cache_name);
    let cached_arm = cache_entry.join("arm");
    let meta_path = cache_entry.join("cache-meta.json");

    if !cached_arm.is_dir() || !meta_path.is_file() {
        return None;
    }

    let meta_content = fs::read_to_string(&meta_path).ok()?;
    let meta: CacheMeta = serde_json::from_str(&meta_content).ok()?;

    // Copy cached .kin/ into the RUN directory
    let dst_kin = arm_dir.join(".kin");
    if dst_kin.exists() {
        fs::remove_dir_all(&dst_kin).ok();
    }
    let cached_kin = cached_arm.join(".kin");
    if !cached_kin.is_dir() {
        return None;
    }

    if let Err(err) = copy_dir_smart(&cached_kin, &dst_kin) {
        eprintln!("  Cache restore failed for {} .kin copy: {}", arm_name, err);
        return None;
    }

    // Exclude .kin/ from ripgrep/grep so blob store doesn't pollute search results.
    let gitignore = arm_dir.join(".gitignore");
    let mut gi = fs::read_to_string(&gitignore).unwrap_or_default();
    if !gi.contains(".kin") {
        if !gi.ends_with('\n') && !gi.is_empty() {
            gi.push('\n');
        }
        gi.push_str(".kin/\n");
        let _ = fs::write(&gitignore, &gi);
    }

    // Switch to native mode but keep .kin/ in the arm dir.
    let _ = Command::new(kin_binary)
        .args(["mode", "native"])
        .current_dir(arm_dir)
        .output();

    // Write CLI docs + MCP wrapper (fresh each run so paths are correct).
    if let Err(err) = write_native_cli_docs(arm_dir, kin_binary) {
        eprintln!("  Cache restore failed for {} docs: {}", arm_name, err);
        return None;
    }
    if let Err(err) = write_mcp_wrapper(arm_dir, kin_binary) {
        eprintln!(
            "  Cache restore failed for {} mcp wrapper: {}",
            arm_name, err
        );
        return None;
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
                let compact: String = trimmed.lines().take(20).collect::<Vec<_>>().join("\n");
                format!("\n## Overview\n```\n{}\n```\n", compact)
            }
        }
        _ => String::new(),
    }
}

/// Write assistant config docs (CLAUDE.md, AGENTS.md, etc.) for a Kin arm.
fn write_assistant_docs(dir: &Path, kin_binary: &Path, native_mode: bool) -> Result<()> {
    let cli_docs = if native_mode {
        "\
# Kin — Semantic Code Access via MCP\n\
\n\
IMPORTANT: Source files do NOT exist on the filesystem. There is no source code in this directory.\n\
All code access goes through the `kin` MCP tools listed below.\n\
\n\
Do NOT use Read, Glob, Grep, Bash, or any filesystem tool to look for source code. It will not work.\n\
\n\
## MCP tools for code access\n\
\n\
Use ONLY these MCP tools to find and read code:\n\
\n\
- `semantic_search` — exact symbol lookup. Start here when the task names a specific function, type, or method.\n\
- `get_context_pack` — focused pack with the entity's source body and nearby dependencies. Use this for source-body or implementation questions.\n\
- `find_references` — direct callers/importers/references for an exact symbol. Use this for caller-count and import-list questions.\n\
- `get_entity` — exact entity metadata by ID (name, kind, file, span). Use this only if you need metadata beyond the context pack.\n\
- `dead_code` — fastest way to list unreachable entities.\n\
- `explore_codebase` — use strategy=\"trace\" for call-chain questions, strategy=\"search\" only when the task is broad.\n\
\n\
## Workflow — KEEP IT MINIMAL\n\
\n\
1. If the task names an exact symbol, start with `semantic_search` on that symbol.\n\
2. For source-body questions, follow with `get_context_pack(id, compact=false)`. For caller/import questions, use `find_references(query=<ExactName>)` or `find_references(entity_id=<id>)`.\n\
3. For dead-code questions with named files, use `dead_code(files=[...], limit=50)`. Otherwise use `dead_code(limit=50)`. Use `explore_codebase(..., strategy=\"trace\")` only for full call-chain questions.\n\
4. Answer immediately. You should need at most 2 MCP calls.\n\
\n\
IMPORTANT: Do NOT repeat `semantic_search` on the same name or fan out into many neighborhood queries. Call the named MCP tools directly; do not use ToolSearch. After 1-2 calls you have enough context.\n"
    } else {
        "\
Default to Grep/Read — they work here just like any repo.\n\
`kin trace <Name> --compact` — ONLY for dependency-chain tracing (not find/fix tasks).\n\
`kin refs <Name> [--kind imports|calls]` — ONLY for caller/import counting.\n\
Do NOT kin-trace a symbol you can simply Grep for.\n"
    };

    // In native mode, `kin mode native` must run FIRST because it:
    //   (a) moves source files to .kin/source-root/
    //   (b) overwrites CLAUDE.md/AGENTS.md/etc with its own bootstrap docs
    // We then overwrite those docs with our benchmark-specific MCP-oriented versions.
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
    }

    let overview_section = run_kin_overview(dir, kin_binary);

    if native_mode {
        // In native mode, write MCP-oriented docs to CLAUDE.md (Claude supports
        // MCP via .mcp.json) and CLI-oriented docs to AGENTS.md/CODEX.md/GEMINI.md
        // (Codex/Gemini headless modes don't start MCP servers).
        let mcp_docs = format!("{cli_docs}{overview_section}");
        fs::write(dir.join("CLAUDE.md"), &mcp_docs).map_err(|e| BenchError::io(dir, e))?;

        let cli_native_docs = format!(
            "\
Source files are in .kin/source-root/. Use kin CLI for fast lookup:\n\
`kin trace <Name> --compact` — source + deps in one call. Read dep files from .kin/source-root/ directly after.\n\
`kin refs <Name> [--kind imports|calls]` — direct callers/importers with file paths.\n\
`kin search <Name> --show-body` — find entities by name.\n\
Max 2 traces. Use Read/Grep for file paths, not kin trace.\n\
{overview_section}"
        );
        for name in &["AGENTS.md", "CODEX.md", "GEMINI.md"] {
            fs::write(dir.join(name), &cli_native_docs).map_err(|e| BenchError::io(dir, e))?;
        }
    } else {
        // In compat mode, skip the overview section — it adds ~350 bytes of entity
        // stats that inflate input tokens without helping the agent.  Every extra
        // token costs ~2ms per LLM call, so leaner docs = faster on grep-only tasks.
        let doc_files = ["CLAUDE.md", "AGENTS.md", "CODEX.md", "GEMINI.md"];
        for name in &doc_files {
            fs::write(dir.join(name), cli_docs).map_err(|e| BenchError::io(dir, e))?;
        }
    }

    // In native mode, write a wrapper script + .mcp.json.  The wrapper script
    // cd's to the relocated .kin/ parent and sets KIN_SOURCE_ROOT before
    // launching `kin mcp start`.  This way the MCP server can access the graph
    // and blobs, but Claude's filesystem tools see an empty workspace.
    if native_mode {
        write_mcp_wrapper(dir, kin_binary)?;
    }

    write_claude_benchmark_hooks(dir, native_mode)?;

    // Verify required Kin arm artifacts exist
    let mut missing: Vec<&str> = Vec::new();
    for artifact in &["CLAUDE.md", "AGENTS.md", "CODEX.md", "GEMINI.md"] {
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

    Ok(())
}

/// Write the MCP wrapper script and `.mcp.json` for native mode.
///
/// The wrapper script (`_kin-mcp.sh`) lives inside the arm directory and:
///   1. `cd`s to the shadow workspace (where `.kin/` was relocated)
///   2. Sets `KIN_SOURCE_ROOT` so the MCP server finds source files
///   3. Execs `kin mcp start`
///
/// Because `KinLayout::discover` walks up from cwd looking for `.kin/`,
/// the wrapper must cd into the shadow workspace directory which contains
/// the `.kin/` subdirectory.
///
/// `.mcp.json` points at this wrapper so Claude's MCP client spawns the server
/// in the right directory while the arm workspace itself has NO `.kin/` at all.
fn write_mcp_wrapper(arm_dir: &Path, kin_binary: &Path) -> Result<()> {
    let shadow_ws = shadow_workspace_dir(arm_dir);
    let source_root = relocated_source_root(arm_dir);

    // The wrapper script needs absolute paths since it'll be invoked from
    // whatever cwd Claude's MCP client uses.
    let wrapper_path = arm_dir.join("_kin-mcp.sh");
    let script = format!(
        r#"#!/bin/sh
# MCP wrapper — launches kin MCP server against the shadow workspace.
# The shadow workspace contains .kin/ with the graph and blob store.
# Generated by kin bench; do not edit.
export KIN_SOURCE_ROOT="{source_root}"
export KIN_MCP_TOOL_PROFILE="benchmark"
cd "{shadow_ws}" || exit 1
exec "{kin_bin}" mcp start
"#,
        source_root = source_root.display(),
        shadow_ws = shadow_ws.display(),
        kin_bin = kin_binary.display(),
    );
    fs::write(&wrapper_path, &script).map_err(|e| BenchError::io(&wrapper_path, e))?;
    #[cfg(unix)]
    {
        let perms = std::fs::Permissions::from_mode(0o755);
        fs::set_permissions(&wrapper_path, perms).map_err(|e| BenchError::io(&wrapper_path, e))?;
    }

    // .mcp.json points at the wrapper script
    let mcp_config = serde_json::json!({
        "mcpServers": {
            "kin": {
                "command": wrapper_path.display().to_string(),
                "args": []
            }
        }
    });
    let mcp_path = arm_dir.join(".mcp.json");
    fs::write(
        &mcp_path,
        serde_json::to_string_pretty(&mcp_config).unwrap(),
    )
    .map_err(|e| BenchError::io(&mcp_path, e))?;

    Ok(())
}

fn write_claude_benchmark_hooks(dir: &Path, native_mode: bool) -> Result<()> {
    let claude_dir = dir.join(".claude");
    fs::create_dir_all(&claude_dir).map_err(|e| BenchError::io(&claude_dir, e))?;

    // No SessionStart hook — the guidance in CLAUDE.md is sufficient and
    // hooks add asymmetric overhead (kin arms pay python3 startup, git doesn't).

    // In native mode, deny filesystem access to .kin/source-root/ so Claude
    // must use MCP tools to access source code.  This mirrors production use
    // where source files live exclusively in Kin's object store.
    if native_mode {
        let settings = json!({
            "permissions": {
                "deny": [
                    "Read(.kin/source-root/**)",
                    "Glob(.kin/source-root/**)",
                    "Grep(.kin/source-root/**)"
                ]
            }
        });
        let settings_path = claude_dir.join("settings.json");
        let rendered = serde_json::to_string_pretty(&settings).map_err(BenchError::Json)?;
        fs::write(&settings_path, rendered).map_err(|e| BenchError::io(&settings_path, e))?;
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
    let content =
        fs::read_to_string(settings_path).map_err(|e| BenchError::io(settings_path, e))?;
    let mut value: serde_json::Value = serde_json::from_str(&content).map_err(BenchError::Json)?;

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

/// Return the file tree that should count as "the repo files" for a benchmark arm.
/// In native mode source may be at the relocated sibling path or `.kin/source-root/`.
fn source_file_root(dir: &Path, native_mode: bool) -> PathBuf {
    if native_mode {
        let relocated = relocated_source_root(dir);
        if relocated.is_dir() {
            relocated
        } else {
            dir.join(".kin").join("source-root")
        }
    } else {
        dir.to_path_buf()
    }
}

fn planted_search_terms(planted: &super::planted::PlantedArtifacts) -> Vec<String> {
    vec![
        planted.impact.type_name.clone(),
        planted.bugfix.function_name.clone(),
        planted.feature.function_name.clone(),
    ]
}

fn verify_planted_search_targets(
    arm_dir: &Path,
    kin_binary: &Path,
    arm: BenchmarkArm,
    planted: &super::planted::PlantedArtifacts,
) -> Result<()> {
    let (cwd, source_root) = match arm {
        BenchmarkArm::KinNative => (
            shadow_workspace_dir(arm_dir),
            Some(relocated_source_root(arm_dir)),
        ),
        _ => (arm_dir.to_path_buf(), None),
    };

    let mut missing = Vec::new();
    for term in planted_search_terms(planted) {
        let mut command = Command::new(kin_binary);
        command
            .arg("search")
            .arg(&term)
            .args(["--limit", "1"])
            .current_dir(&cwd);
        if let Some(root) = &source_root {
            command.env("KIN_SOURCE_ROOT", root);
        }
        let output = command
            .output()
            .map_err(|e| BenchError::io(kin_binary, e))?;
        if !output.status.success() {
            return Err(BenchError::Other(format!(
                "{} planted-target verification failed while searching for '{}'",
                arm, term
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim().is_empty() || stdout.contains("No entities matching") {
            missing.push(term);
        }
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(BenchError::Other(format!(
            "{} graph is missing planted targets: {}",
            arm,
            missing.join(", ")
        )))
    }
}

/// Try to extract an entity count from kin commit output.
fn extract_entity_count(output: &str) -> u64 {
    for line in output.lines() {
        let lower = line.to_lowercase();
        if lower.contains("entit") {
            for word in line.split_whitespace() {
                // Strip single leading/trailing punctuation (e.g., "(55" → "55", "55," → "55")
                let trimmed = word
                    .strip_prefix(|c: char| !c.is_ascii_digit())
                    .unwrap_or(word);
                let trimmed = trimmed
                    .strip_suffix(|c: char| !c.is_ascii_digit())
                    .unwrap_or(trimmed);
                // Only accept if the result is purely digits (reject "abc123")
                if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_digit()) {
                    if let Ok(n) = trimmed.parse::<u64>() {
                        if n > 0 {
                            return n;
                        }
                    }
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

    let cutoff =
        std::time::SystemTime::now() - std::time::Duration::from_secs(max_age_hours * 3600);

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
        let modified = entry.metadata().ok().and_then(|m| m.modified().ok());
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
    let gemini_auth_settings = real_home.as_deref().and_then(read_gemini_auth_settings);

    // Gemini: preserve only the auth selector from the real settings file.
    if gemini_auth_settings.is_some() {
        let gemini_dir = home_dir.join(".gemini");
        fs::create_dir_all(&gemini_dir).map_err(|e| BenchError::io(&gemini_dir, e))?;
        let gemini_settings = render_gemini_settings(gemini_auth_settings.as_ref(), None, &[])?;
        fs::write(gemini_dir.join("settings.json"), gemini_settings)
            .map_err(|e| BenchError::io(&gemini_dir, e))?;
    }

    // Preserve auth artifacts from the real HOME into the isolated HOME.
    if let Some(real_home) = real_home.as_deref() {
        preserve_auth_artifacts(real_home, &home_dir)?;
    }

    // Native MCP arms need assistant-local Codex config because Codex-family
    // clients read MCP server registration from ~/.codex/config.toml rather
    // than the repo-local .mcp.json used by Claude.
    if matches!(
        arm,
        super::BenchmarkArm::KinNative | super::BenchmarkArm::KinCodexNative
    ) {
        seed_codex_native_mcp_config(arm_dir, &home_dir)?;
        seed_gemini_native_mcp_config(arm_dir, &home_dir, gemini_auth_settings.as_ref())?;
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
        super::BenchmarkArm::KinCompat
            | super::BenchmarkArm::KinNative
            | super::BenchmarkArm::KinNativeCli
            | super::BenchmarkArm::KinCodexNative
    ) {
        let mut path_prefix = String::new();

        let is_native = matches!(
            arm,
            super::BenchmarkArm::KinNative | super::BenchmarkArm::KinCodexNative
        );
        if is_native {
            // Default native mode: .kin/ has been relocated entirely outside
            // the arm workspace.  The MCP wrapper script (_kin-mcp.sh) already
            // embeds KIN_SOURCE_ROOT and cd's to the right directory, so no
            // env overrides are needed for the MCP path.
            //
            // The shim-based approach (--native-restrict-*) is still available
            // for experimentation — but shims live inside the relocated .kin/.
            let kin_dir = relocated_kin_dir(arm_dir);
            let shim_dir = kin_dir.join("shims");
            let source_root = relocated_source_root(arm_dir);
            let use_shims = native_restrict_discovery || native_restrict_filesystem;
            if use_shims && shim_dir.is_dir() {
                path_prefix = shim_dir.display().to_string();
                let original_path = std::env::var("PATH").unwrap_or_default();
                env.push((
                    "KIN_SOURCE_ROOT".to_string(),
                    source_root.display().to_string(),
                ));
                env.push(("KIN_ORIGINAL_PATH".to_string(), original_path));
                if native_restrict_filesystem {
                    env.push(("KIN_DISCOVERY_MODE".to_string(), "deny".to_string()));
                    env.push(("KIN_CONTENT_MODE".to_string(), "deny".to_string()));
                    env.push(("KIN_SEARCH_MODE".to_string(), "precise".to_string()));
                    env.push(("KIN_TRACE_MODE".to_string(), "precise".to_string()));
                } else if native_restrict_discovery {
                    env.push(("KIN_DISCOVERY_MODE".to_string(), "deny".to_string()));
                    env.push(("KIN_SEARCH_MODE".to_string(), "precise".to_string()));
                    env.push(("KIN_TRACE_MODE".to_string(), "precise".to_string()));
                }
                let log_path = shim_log_path(arm_dir);
                env.push(("KIN_SHIM_LOG".to_string(), log_path.display().to_string()));
            }
            // In default MCP mode (no shims), KIN_SOURCE_ROOT is embedded
            // in the wrapper script — no env override needed for the assistant
            // subprocess.  The MCP server is a child of the wrapper, not the
            // assistant process.
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

    // Codex-family native arms need the fork-specific home hint so kin-codex
    // resolves auth/config from the isolated ~/.codex directory. Regular Codex
    // ignores KIN_CODEX_HOME, so this is safe to set for both native arms.
    if matches!(
        arm,
        super::BenchmarkArm::KinNative | super::BenchmarkArm::KinCodexNative
    ) {
        env.push(("KIN_MODE".to_string(), "native".to_string()));
        let codex_home = arm_dir.join(".bench-home").join(".codex");
        fs::create_dir_all(&codex_home).ok();
        env.push((
            "KIN_CODEX_HOME".to_string(),
            codex_home.display().to_string(),
        ));
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

fn toml_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn render_codex_settings(command: &Path) -> String {
    format!(
        "[mcp_servers.kin]\ncommand = \"{}\"\nargs = []\n",
        toml_escape(&command.display().to_string())
    )
}

fn seed_codex_native_mcp_config(arm_dir: &Path, home_dir: &Path) -> Result<()> {
    let wrapper_path = arm_dir.join("_kin-mcp.sh");
    if !wrapper_path.is_file() {
        return Ok(());
    }

    let codex_dir = home_dir.join(".codex");
    fs::create_dir_all(&codex_dir).map_err(|e| BenchError::io(&codex_dir, e))?;

    let config_path = codex_dir.join("config.toml");
    let rendered = render_codex_settings(&wrapper_path);
    fs::write(&config_path, rendered).map_err(|e| BenchError::io(&config_path, e))?;
    Ok(())
}

fn seed_gemini_native_mcp_config(
    arm_dir: &Path,
    home_dir: &Path,
    auth_settings: Option<&Value>,
) -> Result<()> {
    let wrapper_path = arm_dir.join("_kin-mcp.sh");
    if !wrapper_path.is_file() {
        return Ok(());
    }

    let gemini_dir = home_dir.join(".gemini");
    fs::create_dir_all(&gemini_dir).map_err(|e| BenchError::io(&gemini_dir, e))?;

    let settings_path = gemini_dir.join("settings.json");
    let rendered = render_gemini_settings(auth_settings, Some(&wrapper_path), &[])?;
    fs::write(&settings_path, rendered).map_err(|e| BenchError::io(&settings_path, e))?;
    Ok(())
}

fn render_gemini_settings(
    auth_settings: Option<&Value>,
    command: Option<&Path>,
    args: &[&str],
) -> Result<String> {
    let mut root = Map::new();

    if let Some(auth_settings) = auth_settings {
        if let Some(obj) = auth_settings.as_object() {
            for (key, value) in obj {
                root.insert(key.clone(), value.clone());
            }
        }
    }

    if let Some(command) = command {
        root.insert(
            "mcpServers".into(),
            json!({
                "kin": {
                    "command": command.display().to_string(),
                    "args": args
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
        symlink_auth_file(
            &real_home.join(".claude").join(file),
            &claude_dst.join(file),
        );
    }

    // macOS: Claude Code uses the login keychain ($HOME/Library/Keychains/login.keychain-db)
    // for OAuth credential storage. Overriding HOME breaks keychain lookups unless we
    // symlink the Keychains directory into the isolated home.
    symlink_auth_dir(
        &real_home.join("Library/Keychains"),
        &isolated_home.join("Library/Keychains"),
    );

    // Claude Code stores OAuth session data in ~/Library/Application Support/Claude/.
    // When HOME is overridden, Node's os.homedir() returns the new HOME, so Claude
    // looks for auth at $HOME/Library/Application Support/Claude/ — symlink the real
    // directory so it can find its OAuth tokens.
    symlink_auth_dir(
        &real_home.join("Library/Application Support/Claude"),
        &isolated_home.join("Library/Application Support/Claude"),
    );

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

/// Symlink an entire directory (e.g. Application Support/Claude) into the isolated home.
fn symlink_auth_dir(src: &Path, dst: &Path) {
    if !src.is_dir() || dst.exists() {
        return;
    }
    if let Some(parent) = dst.parent() {
        let _ = fs::create_dir_all(parent);
    }
    #[cfg(unix)]
    {
        let _ = std::os::unix::fs::symlink(src, dst);
    }
    #[cfg(not(unix))]
    {
        // On non-unix, skip directory symlinks — only file-level auth works.
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
        let ft = entry
            .file_type()
            .map_err(|e| BenchError::io(&src_path, e))?;

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
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn repo_display_name_extracts_basename() {
        assert_eq!(repo_display_name("/tmp/bench-repos/fastapi"), "fastapi");
        assert_eq!(
            repo_display_name("https://github.com/colinhacks/zod.git"),
            "zod"
        );
        assert_eq!(
            repo_display_name("git@github.com:pallets/flask.git"),
            "flask"
        );
        assert_eq!(repo_display_name("/some/path/express/"), "express");
    }

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
    #[cfg(unix)]
    fn write_assistant_docs_native_does_not_duplicate_overview() {
        let tmp = std::env::temp_dir().join("kin-bench-test-write-assistant-docs-native");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let kin_script = tmp.join("fake-kin.sh");
        fs::write(
            &kin_script,
            r#"#!/bin/bash
if [[ "$1" == "overview" ]]; then
  cat <<'EOF'
=== Kin Overview ===
Repository: test  |  Entities: 3  |  Files: 2
EOF
  exit 0
fi
if [[ "$1" == "mode" && "$2" == "native" ]]; then
  exit 0
fi
echo "unexpected args: $@" >&2
exit 1
"#,
        )
        .unwrap();
        let mut perms = fs::metadata(&kin_script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&kin_script, perms).unwrap();

        write_assistant_docs(&tmp, &kin_script, true).unwrap();

        let agents = fs::read_to_string(tmp.join("AGENTS.md")).unwrap();
        assert_eq!(agents.matches("## Overview").count(), 1);

        fs::remove_dir_all(&tmp).unwrap();
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
        // Real kin commit output format: parenthesized numbers
        assert_eq!(
            extract_entity_count(
                "Created semantic change abc123 on branch 'main' (55 entities, 1 relations, 201 files)"
            ),
            55
        );
        // Ensure we get entity count, not relation count
        assert_eq!(
            extract_entity_count(
                "Created semantic change abc123 on branch 'main' (2157 entities, 43 relations, 2886 files)"
            ),
            2157
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
        fs::write(
            arm_dir.join(".kin").join("graph").join("data.db"),
            "fake-db-data",
        )
        .unwrap();
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
        write_to_cache(
            cache_name,
            &arm_dir,
            &metrics,
            "kin 0.1.0",
            "abc123def456",
            "compat",
        );

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
        let restored = try_restore_from_cache(
            cache_name,
            &restore_dir,
            "kin-compat",
            Path::new("/usr/bin/true"),
            false,
        );
        assert!(restored.is_some());
        let restored = restored.unwrap();
        assert!(restored.cached);
        assert_eq!(restored.entity_count, 50);
        assert_eq!(restored.repo_name, "test-repo");
        assert_eq!(restored.original_conversion_ms, Some(300.0));
        assert!(restored.cached_at.is_some());

        // Verify .kin/ was copied into the run dir (not a reference to cache)
        assert!(restore_dir.join(".kin").join("config.json").exists());
        assert!(restore_dir
            .join(".kin")
            .join("graph")
            .join("data.db")
            .exists());
        // Verify assistant docs were restored
        assert!(restore_dir.join("CLAUDE.md").exists());

        // Verify the cache dir is untouched (immutable seed)
        assert!(cache_entry
            .join("arm")
            .join(".kin")
            .join("config.json")
            .exists());

        // Cleanup
        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(&cache_entry);
    }

    #[test]
    fn native_cache_restore_prunes_root_source_tree() {
        let tmp = std::env::temp_dir().join("kin-bench-test-native-cache-restore");
        let _ = fs::remove_dir_all(&tmp);

        let arm_dir = tmp.join("arm");
        fs::create_dir_all(arm_dir.join(".kin").join("source-root").join("packages")).unwrap();
        fs::write(
            arm_dir
                .join(".kin")
                .join("source-root")
                .join("packages")
                .join("keep.ts"),
            "export const keep = 1;",
        )
        .unwrap();
        fs::write(arm_dir.join("CLAUDE.md"), "# Kin native docs").unwrap();
        fs::write(arm_dir.join("AGENTS.md"), "# Kin native docs").unwrap();

        let metrics = ConversionMetrics {
            arm: "kin-native".to_string(),
            repo_name: "test-repo".to_string(),
            commit_sha: Some("abc123".to_string()),
            init_duration_ms: 0.0,
            commit_duration_ms: 0.0,
            kin_dir_size_bytes: 1024,
            git_dir_size_bytes: 2048,
            entity_count: 50,
            file_count: 1,
            total_setup_ms: 50.0,
            cached: false,
            original_conversion_ms: None,
            cached_at: None,
        };

        let cache_name = "test-native-cache-restore";
        write_to_cache(
            cache_name,
            &arm_dir,
            &metrics,
            "kin 0.1.0",
            "abc123def456",
            "native",
        );

        let restore_dir = tmp.join("restore");
        fs::create_dir_all(restore_dir.join("packages")).unwrap();
        fs::write(
            restore_dir.join("packages").join("stale.ts"),
            "export const stale = 1;",
        )
        .unwrap();
        fs::write(restore_dir.join("README.md"), "readme").unwrap();
        fs::write(restore_dir.join("LICENSE"), "license").unwrap();

        let restored = try_restore_from_cache(
            cache_name,
            &restore_dir,
            "kin-native",
            Path::new("/usr/bin/true"),
            true,
        );
        assert!(restored.is_some());

        // Source tree pruned from control root
        assert!(!restore_dir.join("packages").exists());
        // LICENSE pruned (not in NATIVE_CONTROL_ROOT_KEEP)
        assert!(!restore_dir.join("LICENSE").exists());
        // .kin/ relocated to shadow workspace
        assert!(
            !restore_dir.join(".kin").exists(),
            ".kin/ should be relocated out of arm dir"
        );
        let shadow = shadow_workspace_dir(&restore_dir);
        assert!(
            shadow
                .join(".kin")
                .join("source-root")
                .join("packages")
                .join("keep.ts")
                .exists(),
            "source-root should exist in shadow workspace"
        );
        // Only control-root artifacts survive
        assert!(restore_dir.join("CLAUDE.md").exists());
        assert!(restore_dir.join("AGENTS.md").exists());

        let cache_entry = prepared_cache_dir().join(cache_name);
        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(&cache_entry);
        let _ = fs::remove_dir_all(&shadow);
    }

    #[test]
    fn source_checkout_cache_roundtrip() {
        let tmp = std::env::temp_dir().join("kin-bench-test-source-cache-roundtrip");
        let _ = fs::remove_dir_all(&tmp);

        let source_dir = tmp.join("source");
        fs::create_dir_all(source_dir.join("packages").join("zod")).unwrap();
        fs::write(source_dir.join("README.md"), "# test repo").unwrap();
        fs::write(
            source_dir.join("packages").join("zod").join("index.ts"),
            "export const value = 1;",
        )
        .unwrap();

        let cache_name = "test-source-cache-roundtrip";
        write_source_checkout_cache(cache_name, &source_dir);

        let cache_entry = source_checkout_cache_dir().join(cache_name);
        assert!(cache_entry.join("README.md").exists());
        assert!(cache_entry
            .join("packages")
            .join("zod")
            .join("index.ts")
            .exists());

        let restore_dir = tmp.join("restore");
        assert!(try_restore_source_checkout_cache(cache_name, &restore_dir));
        assert!(restore_dir.join("README.md").exists());
        assert!(restore_dir
            .join("packages")
            .join("zod")
            .join("index.ts")
            .exists());

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
        let env = create_isolated_env(
            &tmp,
            super::BenchmarkArm::KinCompat,
            dummy_bin,
            false,
            false,
        )
        .unwrap();

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
            super::BenchmarkArm::KinNativeCli,
            super::BenchmarkArm::KinCodexNative,
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
    fn create_isolated_env_kin_native_cli_arm_prepends_path() {
        let tmp = std::env::temp_dir().join("kin-bench-test-kin-arm-cli-first");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let dummy_bin = Path::new("/usr/local/bin/kin");
        let env = create_isolated_env(
            &tmp,
            super::BenchmarkArm::KinNativeCli,
            dummy_bin,
            false,
            false,
        )
        .unwrap();

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
    fn create_isolated_env_native_mcp_writes_codex_config() {
        let tmp = std::env::temp_dir().join("kin-bench-test-native-mcp-codex-config");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        fs::write(tmp.join("_kin-mcp.sh"), "#!/bin/sh\nexit 0\n").unwrap();

        let dummy_bin = Path::new("/usr/local/bin/kin");
        let env = create_isolated_env(
            &tmp,
            super::BenchmarkArm::KinNative,
            dummy_bin,
            false,
            false,
        )
        .unwrap();

        let home = tmp.join(".bench-home");
        let config_path = home.join(".codex").join("config.toml");
        let content = fs::read_to_string(&config_path).unwrap();
        let gemini_settings =
            fs::read_to_string(home.join(".gemini").join("settings.json")).unwrap();

        assert!(content.contains("[mcp_servers.kin]"));
        assert!(content.contains("_kin-mcp.sh"));
        assert!(gemini_settings.contains("\"mcpServers\""));
        assert!(gemini_settings.contains("_kin-mcp.sh"));
        assert!(
            env.iter()
                .any(|(k, v)| k == "KIN_CODEX_HOME"
                    && v == &home.join(".codex").display().to_string()),
            "native MCP arm should tell kin-codex where the isolated codex home lives"
        );

        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn create_isolated_env_can_enable_native_discovery_restriction() {
        let tmp = std::env::temp_dir().join("kin-bench-test-native-discovery-restriction");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        // Shims live in the shadow workspace
        let shadow = shadow_workspace_dir(&tmp);
        fs::create_dir_all(shadow.join(".kin").join("shims")).unwrap();
        fs::create_dir_all(shadow.join(".kin").join("source-root")).unwrap();

        let dummy_bin = Path::new("/usr/local/bin/kin");
        let env = create_isolated_env(&tmp, super::BenchmarkArm::KinNative, dummy_bin, true, false)
            .unwrap();

        assert!(
            env.iter()
                .any(|(k, v)| k == "KIN_DISCOVERY_MODE" && v == "deny"),
            "native restriction mode should set KIN_DISCOVERY_MODE=deny"
        );

        fs::remove_dir_all(&tmp).unwrap();
        let _ = fs::remove_dir_all(&shadow);
    }

    #[test]
    fn create_isolated_env_can_enable_native_filesystem_restriction() {
        let tmp = std::env::temp_dir().join("kin-bench-test-native-filesystem-restriction");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let shadow = shadow_workspace_dir(&tmp);
        fs::create_dir_all(shadow.join(".kin").join("shims")).unwrap();
        fs::create_dir_all(shadow.join(".kin").join("source-root")).unwrap();

        let dummy_bin = Path::new("/usr/local/bin/kin");
        let env = create_isolated_env(&tmp, super::BenchmarkArm::KinNative, dummy_bin, false, true)
            .unwrap();

        assert!(
            env.iter()
                .any(|(k, v)| k == "KIN_DISCOVERY_MODE" && v == "deny"),
            "native filesystem restriction should set KIN_DISCOVERY_MODE=deny"
        );
        assert!(
            env.iter()
                .any(|(k, v)| k == "KIN_CONTENT_MODE" && v == "deny"),
            "native filesystem restriction should set KIN_CONTENT_MODE=deny"
        );

        fs::remove_dir_all(&tmp).unwrap();
        let _ = fs::remove_dir_all(&shadow);
    }

    #[test]
    fn create_isolated_env_git_arm_does_not_seed_assistant_configs() {
        let _guard = env_lock();
        let tmp = std::env::temp_dir().join("kin-bench-test-git-arm-no-configs");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let dummy_bin = Path::new("/usr/local/bin/kin");
        let _env =
            create_isolated_env(&tmp, super::BenchmarkArm::Git, dummy_bin, false, false).unwrap();

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
        fs::write(
            real_home.join(".codex").join("auth.json"),
            r#"{"token":"test"}"#,
        )
        .unwrap();
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
            codex_auth
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "codex auth.json should be a symlink, not a copy"
        );

        let gemini_auth = isolated_home.join(".gemini").join("oauth_creds.json");
        assert!(
            gemini_auth.exists(),
            "gemini oauth_creds.json should be symlinked"
        );

        assert!(
            !isolated_home
                .join(".claude")
                .join("credentials.json")
                .exists(),
            "non-existent Claude auth should not create a dangling symlink"
        );

        // Test Application Support directory symlink for Claude OAuth
        let app_support_src = real_home.join("Library/Application Support/Claude");
        fs::create_dir_all(&app_support_src).unwrap();
        fs::write(app_support_src.join("test-marker"), "ok").unwrap();

        // Re-run to pick up newly-created Application Support dir
        preserve_auth_artifacts(&real_home, &isolated_home).unwrap();

        let app_support_dst = isolated_home.join("Library/Application Support/Claude");
        assert!(
            app_support_dst.exists(),
            "Application Support/Claude should be symlinked for OAuth"
        );
        #[cfg(unix)]
        assert!(
            app_support_dst
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "Application Support/Claude should be a symlink, not a copy"
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
        let env =
            create_isolated_env(&tmp, super::BenchmarkArm::Git, dummy_bin, false, false).unwrap();

        let has_key = env
            .iter()
            .any(|(k, v)| k == "ANTHROPIC_API_KEY" && v == "test-key-12345");
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

        let rendered = render_gemini_settings(
            Some(&auth),
            Some(Path::new("/usr/local/bin/kin")),
            &["mcp", "start"],
        )
        .unwrap();
        let parsed: Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(parsed["security"]["auth"]["selectedType"], "oauth-personal");
        assert_eq!(parsed["mcpServers"]["kin"]["command"], "/usr/local/bin/kin");
        assert_eq!(parsed["mcpServers"]["kin"]["args"][0], "mcp");
        assert_eq!(parsed["mcpServers"]["kin"]["args"][1], "start");
    }

    #[test]
    fn create_isolated_env_no_shims_in_default_native_mcp_mode() {
        // Default native mode uses MCP — shims should NOT be injected.
        // KIN_SOURCE_ROOT is embedded in the MCP wrapper script, not set
        // in the assistant subprocess env.
        let tmp = std::env::temp_dir().join("kin-bench-test-no-shim-mcp");
        let _ = fs::remove_dir_all(&tmp);
        // Simulate relocated .kin/ in shadow workspace
        let shadow = shadow_workspace_dir(&tmp);
        fs::create_dir_all(shadow.join(".kin").join("shims")).unwrap();
        fs::create_dir_all(shadow.join(".kin").join("source-root")).unwrap();

        let dummy_bin = Path::new("/usr/local/bin/kin");
        let env = create_isolated_env(
            &tmp,
            super::BenchmarkArm::KinNative,
            dummy_bin,
            false,
            false,
        )
        .unwrap();

        let shim_log = env.iter().find(|(k, _)| k == "KIN_SHIM_LOG");
        assert!(
            shim_log.is_none(),
            "KIN_SHIM_LOG should NOT be set in default MCP native mode"
        );
        // KIN_SOURCE_ROOT should NOT be in the env — it's in the wrapper script
        let source_root = env.iter().find(|(k, _)| k == "KIN_SOURCE_ROOT");
        assert!(
            source_root.is_none(),
            "KIN_SOURCE_ROOT should NOT be in env in MCP mode (embedded in wrapper)"
        );

        fs::remove_dir_all(&tmp).unwrap();
        let _ = fs::remove_dir_all(&shadow);
    }

    #[test]
    fn create_isolated_env_sets_shims_with_restrict_flags() {
        // When restrict flags are passed, shims ARE injected (legacy CLI mode).
        // Shims live in the shadow workspace alongside the relocated .kin/.
        let tmp = std::env::temp_dir().join("kin-bench-test-shim-restrict");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let shadow = shadow_workspace_dir(&tmp);
        fs::create_dir_all(shadow.join(".kin").join("shims")).unwrap();
        fs::create_dir_all(shadow.join(".kin").join("source-root")).unwrap();

        let dummy_bin = Path::new("/usr/local/bin/kin");
        let env = create_isolated_env(&tmp, super::BenchmarkArm::KinNative, dummy_bin, true, false)
            .unwrap();

        let shim_log = env.iter().find(|(k, _)| k == "KIN_SHIM_LOG");
        assert!(
            shim_log.is_some(),
            "KIN_SHIM_LOG should be set when restrict flags are active"
        );

        fs::remove_dir_all(&tmp).unwrap();
        let _ = fs::remove_dir_all(&shadow);
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
        assert_eq!(
            path,
            PathBuf::from("/tmp/bench-arm/.bench-home/shim-log.jsonl")
        );
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
