// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Deliberate, bottom-up cross-repo release orchestrator for Kin.
//!
//! Kin already has an event-driven release wave: a registry publish fires a
//! repository_dispatch that opens a "bump <crate>" PR in each downstream. That
//! wave is reactive and eventual — it reaches a fixed point on its own, but the
//! whole front is never visible at once and the settle order is emergent.
//!
//! This module is the deliberate complement (`kin release plan` / `kin release
//! apply` / `kin release intent`). It reads registry truth plus the local
//! sibling manifests and answers, in one bottom-up view
//!
//! ```text
//! primitives -> kin-model -> kin-db -> kin -> kin-bench/kin-vfs/kin-lsp
//! ```
//!
//!   - which registry crates have a local version ahead of what is published
//!     (a publish is pending),
//!   - which downstream pins still lag a published crate (a bump is pending),
//!
//! and can deliberately apply the same pin bump the wave would, in a chosen
//! order. It never publishes — publishing stays in CI behind the version gate.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

const DEFAULT_REGISTRY_URL: &str = "https://kinlab.ai";

/// Registry-published crates in bottom-up order, paired with the repo that owns
/// each one. (`kin-vfs-core` ships from the `kin-vfs` repo; every other crate is
/// its own repo.)
const REGISTRY_CRATES: &[(&str, &str)] = &[
    ("kin-blobs", "kin-blobs"),
    ("kin-vector", "kin-vector"),
    ("kin-search", "kin-search"),
    ("kin-infer", "kin-infer"),
    ("kin-model", "kin-model"),
    ("kin-db", "kin-db"),
    ("kin-lsp", "kin-lsp"),
    ("kin-vfs-core", "kin-vfs"),
];

/// Repos whose manifests may pin the registry crates above.
const CONSUMER_REPOS: &[&str] = &[
    "kin-blobs",
    "kin-vector",
    "kin-search",
    "kin-infer",
    "kin-model",
    "kin-db",
    "kin-lsp",
    "kin",
    "kin-bench",
    "kin-vfs",
];

fn registry_url() -> String {
    std::env::var("KIN_REGISTRY_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_REGISTRY_URL.to_string())
        .trim_end_matches('/')
        .to_string()
}

/// Resolve the umbrella workspace root (the parent dir that holds the sibling
/// repos). `kin-release` derives this from `bin/`; here we walk up from the
/// current directory looking for the sibling layout, then fall back to
/// `KIN_WORKSPACE_ROOT`.
fn workspace_root() -> Result<PathBuf> {
    if let Ok(explicit) = std::env::var("KIN_WORKSPACE_ROOT") {
        let p = PathBuf::from(explicit);
        if p.is_dir() {
            return Ok(p);
        }
    }
    let start = std::env::current_dir().context("cannot read current directory")?;
    let mut dir = start.as_path();
    loop {
        if looks_like_workspace_root(dir) {
            return Ok(dir.to_path_buf());
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }
    bail!(
        "could not locate the umbrella workspace root above {} — run from inside the \
         kin-ecosystem checkout or set KIN_WORKSPACE_ROOT",
        start.display()
    )
}

/// The umbrella root holds sibling repos. Detect it by the presence of at least
/// `kin` and one of the lower primitives as direct child directories.
fn looks_like_workspace_root(dir: &Path) -> bool {
    let has = |name: &str| dir.join(name).join("Cargo.toml").is_file();
    has("kin") && (has("kin-model") || has("kin-db") || has("kin-blobs"))
}

// ── semver ───────────────────────────────────────────────────────────────────

/// Parse the numeric `(major, minor, patch)` core of a version, ignoring any
/// pre-release / build metadata. Matches the bash/python `parse_version`.
fn parse_version(v: &str) -> (u64, u64, u64) {
    let core = v.split(['-', '+']).next().unwrap_or(v);
    let mut parts = [0u64; 3];
    for (i, p) in core.split('.').take(3).enumerate() {
        parts[i] = p.parse().unwrap_or(0);
    }
    (parts[0], parts[1], parts[2])
}

/// The sparse-index path segment cargo registries use for a crate name.
fn sparse_index_path(name: &str) -> String {
    let name = name.to_lowercase();
    match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{}", &name[..1], name),
        _ => format!("{}/{}/{}", &name[..2], &name[2..4], name),
    }
}

/// The newest published, non-yanked version of `crate_name` in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Published {
    /// A concrete newest version string.
    Version(String),
    /// Index has no (non-yanked) versions, or the crate is absent (404).
    Unpublished,
    /// The registry query failed (network/HTTP error).
    Error,
}

async fn newest_published(client: &reqwest::Client, crate_name: &str) -> Published {
    let url = format!(
        "{}/registry/cargo/{}",
        registry_url(),
        sparse_index_path(crate_name)
    );
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return Published::Error,
    };
    if resp.status().as_u16() == 404 {
        return Published::Unpublished;
    }
    if !resp.status().is_success() {
        return Published::Error;
    }
    let body = match resp.text().await {
        Ok(b) => b,
        Err(_) => return Published::Error,
    };
    let mut versions: Vec<String> = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let obj: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let yanked = obj.get("yanked").and_then(|y| y.as_bool()).unwrap_or(false);
        if yanked {
            continue;
        }
        if let Some(vers) = obj.get("vers").and_then(|v| v.as_str()) {
            versions.push(vers.to_string());
        }
    }
    match versions.into_iter().max_by_key(|v| parse_version(v)) {
        Some(v) => Published::Version(v),
        None => Published::Unpublished,
    }
}

// ── local manifest reads ──────────────────────────────────────────────────────

/// Find the crate's own `[package]` manifest and parsed document. Looks at
/// `<repo>/Cargo.toml` and `<repo>/crates/<crate>/Cargo.toml` first, then scans.
fn find_manifest(ws: &Path, crate_name: &str, repo: &str) -> Option<(PathBuf, toml::Table)> {
    let candidates = [
        ws.join(repo).join("Cargo.toml"),
        ws.join(repo)
            .join("crates")
            .join(crate_name)
            .join("Cargo.toml"),
    ];
    for cand in candidates.iter() {
        if let Some(table) = parse_manifest_named(cand, crate_name) {
            return Some((cand.clone(), table));
        }
    }
    // Fall back to scanning the repo tree (skipping target/).
    let repo_dir = ws.join(repo);
    if let Ok(found) = scan_for_package(&repo_dir, crate_name) {
        return found;
    }
    None
}

fn parse_manifest_named(path: &Path, crate_name: &str) -> Option<toml::Table> {
    let text = std::fs::read_to_string(path).ok()?;
    let table: toml::Table = text.parse().ok()?;
    let name = table.get("package")?.get("name")?.as_str()?;
    if name == crate_name {
        Some(table)
    } else {
        None
    }
}

fn scan_for_package(repo_dir: &Path, crate_name: &str) -> Result<Option<(PathBuf, toml::Table)>> {
    if !repo_dir.is_dir() {
        return Ok(None);
    }
    let mut stack = vec![repo_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            if path.is_dir() {
                if name == "target" || name == ".git" {
                    continue;
                }
                stack.push(path);
            } else if name == "Cargo.toml" {
                if let Some(table) = parse_manifest_named(&path, crate_name) {
                    return Ok(Some((path, table)));
                }
            }
        }
    }
    Ok(None)
}

/// The crate's local declared version, honouring `version.workspace = true` by
/// reading the repo-root `[workspace.package].version`.
fn local_version(ws: &Path, crate_name: &str, repo: &str) -> Option<String> {
    let (_path, table) = find_manifest(ws, crate_name, repo)?;
    let pkg = table.get("package")?;
    if let Some(v) = pkg.get("version").and_then(|v| v.as_str()) {
        return Some(v.to_string());
    }
    // version.workspace = true -> read repo-root [workspace.package].version.
    let root = ws.join(repo).join("Cargo.toml");
    let text = std::fs::read_to_string(&root).ok()?;
    let root_table: toml::Table = text.parse().ok()?;
    root_table
        .get("workspace")?
        .get("package")?
        .get("version")?
        .as_str()
        .map(|s| s.to_string())
}

/// `{crate: pinned_version}` for `registry = "kin"` deps in a repo's root
/// manifest (where Kin keeps its `[workspace.dependencies]` pins). Considers the
/// standard dependency tables plus `[workspace.dependencies]` and target deps.
fn consumer_pins(ws: &Path, repo: &str) -> BTreeMap<String, String> {
    let mut pins = BTreeMap::new();
    let root = ws.join(repo).join("Cargo.toml");
    let text = match std::fs::read_to_string(&root) {
        Ok(t) => t,
        Err(_) => return pins,
    };
    let table: toml::Table = match text.parse() {
        Ok(t) => t,
        Err(_) => return pins,
    };
    let registry_names: std::collections::HashSet<&str> =
        REGISTRY_CRATES.iter().map(|(c, _)| *c).collect();

    let mut harvest = |dep_table: &toml::Value| {
        let Some(map) = dep_table.as_table() else {
            return;
        };
        for (key, spec) in map {
            let Some(spec) = spec.as_table() else {
                continue;
            };
            let name = spec
                .get("package")
                .and_then(|p| p.as_str())
                .unwrap_or(key.as_str());
            let is_kin = spec.get("registry").and_then(|r| r.as_str()) == Some("kin");
            if registry_names.contains(name) && is_kin {
                if let Some(ver) = spec.get("version").and_then(|v| v.as_str()) {
                    let cleaned = ver.trim_start_matches(['=', '^', '~', ' ']).to_string();
                    pins.insert(name.to_string(), cleaned);
                }
            }
        }
    };

    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(t) = table.get(key) {
            harvest(t);
        }
    }
    if let Some(ws_deps) = table
        .get("workspace")
        .and_then(|w| w.as_table())
        .and_then(|w| w.get("dependencies"))
    {
        harvest(ws_deps);
    }
    if let Some(target) = table.get("target").and_then(|t| t.as_table()) {
        for cfg in target.values() {
            if let Some(deps) = cfg.as_table().and_then(|c| c.get("dependencies")) {
                harvest(deps);
            }
        }
    }
    pins
}

// ── plan ──────────────────────────────────────────────────────────────────────

/// `kin release plan [--offline]` — read-only bottom-up release plan.
pub async fn plan(offline: bool) -> Result<()> {
    let ws = workspace_root()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("failed to build HTTP client")?;

    // Gather local versions + newest-published for every registry crate.
    let mut crate_local: BTreeMap<&str, Option<String>> = BTreeMap::new();
    let mut crate_newest: BTreeMap<&str, Published> = BTreeMap::new();
    for (crate_name, repo) in REGISTRY_CRATES {
        crate_local.insert(crate_name, local_version(&ws, crate_name, repo));
        let newest = if offline {
            Published::Unpublished // sentinel; not rendered in offline mode
        } else {
            newest_published(&client, crate_name).await
        };
        crate_newest.insert(crate_name, newest);
    }

    let pins_by_repo: BTreeMap<&str, BTreeMap<String, String>> = CONSUMER_REPOS
        .iter()
        .map(|r| (*r, consumer_pins(&ws, r)))
        .collect();

    // ── render ────────────────────────────────────────────────────────────────
    println!();
    if offline {
        println!("Kin release plan — bottom-up  (offline: registry not queried)");
    } else {
        println!("Kin release plan — bottom-up");
    }
    println!("{}", "=".repeat(64));
    println!(
        "  {:<14} {:<12} {:<14} status",
        "crate", "local", "published"
    );
    println!("  {}", "-".repeat(60));

    let mut needs_publish: Vec<&str> = Vec::new();
    for (crate_name, _repo) in REGISTRY_CRATES {
        let lv = crate_local.get(crate_name).cloned().flatten();
        let lv_disp = lv.clone().unwrap_or_else(|| "<none>".to_string());
        let newest = crate_newest
            .get(crate_name)
            .cloned()
            .unwrap_or(Published::Error);

        let (published_disp, status) = if offline {
            ("local-only".to_string(), "local-only".to_string())
        } else {
            match &newest {
                Published::Error => ("<error>".to_string(), "registry error".to_string()),
                Published::Unpublished => (
                    "<unpublished>".to_string(),
                    "UNPUBLISHED — first publish pending".to_string(),
                ),
                Published::Version(nv) => {
                    let status = match &lv {
                        None => "local version unknown".to_string(),
                        Some(lv) => {
                            let l = parse_version(lv);
                            let n = parse_version(nv);
                            if l > n {
                                format!("NEEDS PUBLISH — local ahead of {nv}")
                            } else if l < n {
                                format!("BEHIND registry {nv} (?)")
                            } else {
                                "up-to-date".to_string()
                            }
                        }
                    };
                    (nv.clone(), status)
                }
            }
        };

        if !offline {
            match &newest {
                Published::Unpublished => needs_publish.push(crate_name),
                Published::Version(nv) => {
                    if let Some(lv) = &lv {
                        if parse_version(lv) > parse_version(nv) {
                            needs_publish.push(crate_name);
                        }
                    }
                }
                Published::Error => {}
            }
        }

        println!("  {crate_name:<14} {lv_disp:<12} {published_disp:<14} {status}");
    }

    // Stale downstream pins (only meaningful when the registry was queried).
    let mut stale: Vec<(String, String, String, String)> = Vec::new();
    if !offline {
        for repo in CONSUMER_REPOS {
            if let Some(pins) = pins_by_repo.get(repo) {
                for (crate_name, pinned) in pins {
                    if let Some(Published::Version(nv)) = crate_newest.get(crate_name.as_str()) {
                        if parse_version(pinned) < parse_version(nv) {
                            stale.push((
                                repo.to_string(),
                                crate_name.clone(),
                                pinned.clone(),
                                nv.clone(),
                            ));
                        }
                    }
                }
            }
        }
    }

    println!();
    println!("Downstream pin status");
    println!("  {}", "-".repeat(60));
    if offline {
        println!("  (skipped — registry not queried in offline mode)");
    } else if stale.is_empty() {
        println!("  all registry pins are at the newest published version");
    } else {
        for (repo, crate_name, pinned, nv) in &stale {
            println!("  {repo:<12} pins {crate_name} {pinned} → newest {nv}  STALE");
        }
    }

    // ── ordered next actions ────────────────────────────────────────────────────
    println!();
    println!("Next bottom-up actions");
    println!("  {}", "-".repeat(60));
    if offline {
        println!("  run without --offline to compare against the registry");
    } else if needs_publish.is_empty() && stale.is_empty() {
        println!("  nothing pending — every registry crate is published and every pin is current");
    } else {
        let repo_of: BTreeMap<&str, &str> = REGISTRY_CRATES.iter().copied().collect();
        let mut n = 1;
        for crate_name in &needs_publish {
            let repo = repo_of.get(crate_name).copied().unwrap_or("?");
            let lv = crate_local
                .get(crate_name)
                .cloned()
                .flatten()
                .unwrap_or_else(|| "?".to_string());
            println!(
                "  {n}. publish {crate_name} ({lv}) — merge {repo} to main; CI publishes \
                 behind the version gate"
            );
            n += 1;
        }
        for (repo, crate_name, pinned, nv) in &stale {
            println!(
                "  {n}. bump {crate_name} {pinned}→{nv} in {repo}:  \
                 kin release apply {crate_name} {nv} {repo}"
            );
            n += 1;
        }
    }
    println!();
    Ok(())
}

// ── apply ─────────────────────────────────────────────────────────────────────

/// `kin release apply <crate> <version> [repo...]` — propagate a published crate
/// version into downstream `Cargo.toml` pins (registry = "kin"). Edits manifests
/// in place; refreshes the lock with `cargo update --precise` unless `--no-lock`.
/// Never commits, pushes, or publishes.
pub async fn apply(
    crate_name: String,
    version: String,
    repos: Vec<String>,
    refresh_lock: bool,
) -> Result<()> {
    let ws = workspace_root()?;
    let targets: Vec<String> = if repos.is_empty() {
        CONSUMER_REPOS.iter().map(|s| s.to_string()).collect()
    } else {
        repos
    };

    let mut changed = 0usize;
    for repo in &targets {
        let manifest = ws.join(repo).join("Cargo.toml");
        if !manifest.is_file() {
            eprintln!("kin release apply: skip '{repo}' (no Cargo.toml)");
            continue;
        }
        let updated = update_manifest_pin(&manifest, &crate_name, &version)
            .with_context(|| format!("failed to update {}", manifest.display()))?;
        if updated {
            println!(
                "kin release apply: {repo}: pinned {crate_name} = {version} \
                 (review + commit on a branch)"
            );
            changed += 1;
            if refresh_lock {
                refresh_lock_entry(&ws.join(repo), &crate_name, &version);
            }
        } else {
            println!("  {repo}: no {crate_name} pin to update");
        }
    }

    if changed == 0 {
        eprintln!("kin release apply: no repo pinned {crate_name}; nothing changed.");
    } else {
        println!(
            "kin release apply: complete — {changed} repo(s) updated. Nothing was \
             committed or pushed."
        );
        eprintln!(
            "kin release apply: verify each repo, then open one PR per repo (bottom-up) \
             for the captain to merge in order."
        );
    }
    Ok(())
}

/// Surgically rewrite `version = "..."` for the `registry = "kin"` dependency on
/// `crate_name` across every dependency table in a manifest, preserving the
/// file's formatting. Matches both a direct `crate_name = { ... }` entry and a
/// renamed `alias = { package = "crate_name", ... }` entry. Returns whether any
/// edit was made.
fn update_manifest_pin(manifest: &Path, crate_name: &str, version: &str) -> Result<bool> {
    let text = std::fs::read_to_string(manifest)
        .with_context(|| format!("cannot read {}", manifest.display()))?;
    let mut doc = text
        .parse::<toml_edit::DocumentMut>()
        .with_context(|| format!("cannot parse {} as TOML", manifest.display()))?;

    let mut changed = false;
    let root = doc.as_table_mut();
    bump_pins_in_table(root, crate_name, version, &mut changed);

    if changed {
        std::fs::write(manifest, doc.to_string())
            .with_context(|| format!("cannot write {}", manifest.display()))?;
    }
    Ok(changed)
}

/// Walk the dependency tables of a (sub)table — `dependencies`,
/// `dev-dependencies`, `build-dependencies`, `workspace.dependencies`, and any
/// `target.*.dependencies` — bumping the matching `registry = "kin"` pin.
fn bump_pins_in_table(
    table: &mut toml_edit::Table,
    crate_name: &str,
    version: &str,
    changed: &mut bool,
) {
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(dep_table) = table.get_mut(key).and_then(|i| i.as_table_like_mut()) {
            bump_pin_in_dep_table(dep_table, crate_name, version, changed);
        }
    }
    if let Some(ws) = table.get_mut("workspace").and_then(|i| i.as_table_mut()) {
        if let Some(dep_table) = ws
            .get_mut("dependencies")
            .and_then(|i| i.as_table_like_mut())
        {
            bump_pin_in_dep_table(dep_table, crate_name, version, changed);
        }
    }
    if let Some(target) = table.get_mut("target").and_then(|i| i.as_table_mut()) {
        for (_, cfg) in target.iter_mut() {
            if let Some(cfg_table) = cfg.as_table_like_mut() {
                if let Some(dep_table) = cfg_table
                    .get_mut("dependencies")
                    .and_then(|i| i.as_table_like_mut())
                {
                    bump_pin_in_dep_table(dep_table, crate_name, version, changed);
                }
            }
        }
    }
}

/// For one dependency table, find the entry whose effective package name is
/// `crate_name` and whose `registry` is `"kin"`, and set its `version`.
fn bump_pin_in_dep_table(
    dep_table: &mut dyn toml_edit::TableLike,
    crate_name: &str,
    version: &str,
    changed: &mut bool,
) {
    let keys: Vec<String> = dep_table.iter().map(|(k, _)| k.to_string()).collect();
    for key in keys {
        let Some(item) = dep_table.get_mut(&key) else {
            continue;
        };
        let Some(spec) = item.as_table_like_mut() else {
            continue;
        };
        let effective_name = spec
            .get("package")
            .and_then(|p| p.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| key.clone());
        let is_kin = spec.get("registry").and_then(|r| r.as_str()) == Some("kin");
        if effective_name == crate_name && is_kin {
            let current = spec.get("version").and_then(|v| v.as_str());
            if current != Some(version) {
                spec.insert("version", toml_edit::value(version));
                *changed = true;
            }
        }
    }
}

/// Refresh a single crate's `Cargo.lock` entry to the precise version, the same
/// way the CI dependency wave does. Best-effort: a failure is logged, not fatal,
/// because the manifest edit is the source of truth and the lock can be
/// regenerated. Never run for a path-patched lock (the umbrella rule forbids
/// committing one); this targets a registry pin.
fn refresh_lock_entry(repo_dir: &Path, crate_name: &str, version: &str) {
    if !repo_dir.join("Cargo.lock").is_file() {
        return;
    }
    let status = std::process::Command::new("cargo")
        .current_dir(repo_dir)
        .args(["update", "-p", crate_name, "--precise", version])
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!(
            "kin release apply: cargo update -p {crate_name} --precise {version} exited {} \
             in {} (manifest edited; re-lock manually)",
            s.code().unwrap_or(-1),
            repo_dir.display()
        ),
        Err(e) => eprintln!(
            "kin release apply: could not run cargo update in {}: {e} (manifest edited; \
             re-lock manually)",
            repo_dir.display()
        ),
    }
}

// ── intent ─────────────────────────────────────────────────────────────────────

/// `kin release intent <repo>` — release-intent gate for one repo.
///
/// For `kin`, this defers to the canonical `scripts/release-intent.mjs` gate
/// (tag-bound package versions == Cargo version, non-empty CHANGELOG section,
/// version strictly forward) — the same pre-tag gate the release captain runs.
/// For a library repo, it asserts the local version is ahead of the newest
/// published version and points at the registry-clean proof. Returns a non-zero
/// process exit on failure.
pub async fn intent(repo: String) -> Result<()> {
    let ws = workspace_root()?;
    let repo_dir = ws.join(&repo);
    if !repo_dir.is_dir() {
        bail!("repo '{repo}' not found at {}", repo_dir.display());
    }

    if repo == "kin" {
        return kin_intent(&repo_dir);
    }

    // Library repo: a release is "intended" when the local version is ahead of
    // the newest published version. The registry-clean proof is delegated to
    // `kin-dev release-check <repo>`.
    let crate_name = REGISTRY_CRATES
        .iter()
        .find(|(_, r)| *r == repo)
        .map(|(c, _)| *c)
        .ok_or_else(|| {
            anyhow::anyhow!("repo '{repo}' is not a registry-published crate; nothing to gate")
        })?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("failed to build HTTP client")?;

    let lv = local_version(&ws, crate_name, &repo);
    let nv = newest_published(&client, crate_name).await;

    println!("release-intent: {repo} ({crate_name})");
    println!(
        "  local version    : {}",
        lv.as_deref().unwrap_or("<unknown>")
    );
    let nv_disp = match &nv {
        Published::Version(v) => v.clone(),
        Published::Unpublished => "<unpublished>".to_string(),
        Published::Error => "<error>".to_string(),
    };
    println!("  newest published : {nv_disp}");

    let Some(lv) = lv else {
        println!("  FAIL: could not resolve local version");
        std::process::exit(1);
    };
    match nv {
        Published::Error => {
            println!("  FAIL: registry query failed");
            std::process::exit(1);
        }
        Published::Unpublished => {
            println!("  => publish intended: {crate_name}@{lv} is not yet published");
            println!("  prove registry-clean before publish:  bin/kin-dev release-check {repo}");
            Ok(())
        }
        Published::Version(nv) => {
            let l = parse_version(&lv);
            let n = parse_version(&nv);
            if l > n {
                println!("  => publish intended: {crate_name}@{lv} is not yet published");
                println!(
                    "  prove registry-clean before publish:  bin/kin-dev release-check {repo}"
                );
                Ok(())
            } else if l == n {
                println!(
                    "  => up-to-date: {crate_name}@{lv} already published; bump the version \
                     to release again"
                );
                std::process::exit(1);
            } else {
                println!("  FAIL: local {lv} is BEHIND published {nv}");
                std::process::exit(1);
            }
        }
    }
}

/// Run the canonical `kin` release-intent gate (`scripts/release-intent.mjs`).
/// Propagates its exit code: 0 = release intended / nothing to do, 1 = staged
/// but out of sync.
fn kin_intent(repo_dir: &Path) -> Result<()> {
    let gate = repo_dir.join("scripts").join("release-intent.mjs");
    if !gate.is_file() {
        bail!("kin release-intent gate not found at {}", gate.display());
    }
    let node = which::which("node")
        .map_err(|_| anyhow::anyhow!("node not found on PATH (required for the kin gate)"))?;
    println!("kin release-intent (node scripts/release-intent.mjs)");
    let status = std::process::Command::new(node)
        .current_dir(repo_dir)
        .arg("scripts/release-intent.mjs")
        .status()
        .context("failed to spawn node")?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_core_only() {
        assert_eq!(parse_version("1.2.3"), (1, 2, 3));
        assert_eq!(parse_version("0.2.24"), (0, 2, 24));
        assert_eq!(parse_version("1.2.3-rc.1"), (1, 2, 3));
        assert_eq!(parse_version("1.2.3+build5"), (1, 2, 3));
        assert_eq!(parse_version("2"), (2, 0, 0));
        assert_eq!(parse_version("1.5"), (1, 5, 0));
        // Non-numeric components degrade to 0, matching the python gate.
        assert_eq!(parse_version("x.y.z"), (0, 0, 0));
    }

    #[test]
    fn sparse_index_path_buckets() {
        assert_eq!(sparse_index_path("a"), "1/a");
        assert_eq!(sparse_index_path("ab"), "2/ab");
        assert_eq!(sparse_index_path("abc"), "3/a/abc");
        assert_eq!(sparse_index_path("kin-db"), "ki/n-/kin-db");
        assert_eq!(sparse_index_path("kin-model"), "ki/n-/kin-model");
        // Lower-cased.
        assert_eq!(sparse_index_path("Kin-DB"), "ki/n-/kin-db");
    }

    #[test]
    fn looks_like_root_requires_kin_and_primitive() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert!(!looks_like_workspace_root(root));
        std::fs::create_dir_all(root.join("kin")).unwrap();
        std::fs::write(root.join("kin").join("Cargo.toml"), "[package]\n").unwrap();
        // kin alone is not enough.
        assert!(!looks_like_workspace_root(root));
        std::fs::create_dir_all(root.join("kin-model")).unwrap();
        std::fs::write(root.join("kin-model").join("Cargo.toml"), "[package]\n").unwrap();
        assert!(looks_like_workspace_root(root));
    }

    #[test]
    fn local_version_reads_package_and_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path();
        // Direct [package] version.
        std::fs::create_dir_all(ws.join("kin-blobs")).unwrap();
        std::fs::write(
            ws.join("kin-blobs").join("Cargo.toml"),
            "[package]\nname = \"kin-blobs\"\nversion = \"0.3.1\"\n",
        )
        .unwrap();
        assert_eq!(
            local_version(ws, "kin-blobs", "kin-blobs"),
            Some("0.3.1".to_string())
        );

        // version.workspace = true -> repo-root [workspace.package].version.
        std::fs::create_dir_all(ws.join("kin-db")).unwrap();
        std::fs::write(
            ws.join("kin-db").join("Cargo.toml"),
            "[workspace.package]\nversion = \"0.2.24\"\n\n[package]\nname = \"kin-db\"\nversion.workspace = true\n",
        )
        .unwrap();
        assert_eq!(
            local_version(ws, "kin-db", "kin-db"),
            Some("0.2.24".to_string())
        );
    }

    #[test]
    fn consumer_pins_only_kin_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path();
        std::fs::create_dir_all(ws.join("kin")).unwrap();
        std::fs::write(
            ws.join("kin").join("Cargo.toml"),
            r#"
[package]
name = "kin"
version = "1.0.0"

[dependencies]
kin-db = { version = "0.2.20", registry = "kin" }
kin-model = { version = "=0.5.0", registry = "kin" }
serde = "1.0"
# A kin crate from crates.io (no registry = "kin") must be ignored.
kin-search = "9.9.9"
# A renamed dep pointing at a registry crate.
db-alias = { package = "kin-blobs", version = "0.3.0", registry = "kin" }
"#,
        )
        .unwrap();
        let pins = consumer_pins(ws, "kin");
        assert_eq!(pins.get("kin-db"), Some(&"0.2.20".to_string()));
        // Leading "=" is stripped.
        assert_eq!(pins.get("kin-model"), Some(&"0.5.0".to_string()));
        assert_eq!(pins.get("kin-blobs"), Some(&"0.3.0".to_string()));
        // crates.io kin-search (no registry) is excluded.
        assert!(!pins.contains_key("kin-search"));
    }

    #[test]
    fn update_manifest_pin_rewrites_only_kin_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        std::fs::write(
            &manifest,
            r#"[package]
name = "consumer"
version = "1.0.0"

[dependencies]
kin-db = { version = "0.2.20", registry = "kin" }
kin-other = { version = "1.0.0" }
db-alias = { package = "kin-db", version = "0.2.20", registry = "kin" }
"#,
        )
        .unwrap();

        let changed = update_manifest_pin(&manifest, "kin-db", "0.2.24").unwrap();
        assert!(changed);
        let out = std::fs::read_to_string(&manifest).unwrap();
        assert!(out.contains(r#"kin-db = { version = "0.2.24", registry = "kin" }"#));
        // Renamed alias to the same crate is also bumped.
        assert!(out.contains(r#"package = "kin-db", version = "0.2.24""#));
        // Unrelated dep untouched.
        assert!(out.contains(r#"kin-other = { version = "1.0.0" }"#));

        // Idempotent: a second apply at the same version is a no-op.
        let changed_again = update_manifest_pin(&manifest, "kin-db", "0.2.24").unwrap();
        assert!(!changed_again);
    }

    #[test]
    fn update_manifest_pin_handles_workspace_dependencies() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        std::fs::write(
            &manifest,
            r#"[workspace]
members = ["a"]

[workspace.dependencies]
kin-model = { version = "0.4.0", registry = "kin" }
"#,
        )
        .unwrap();
        let changed = update_manifest_pin(&manifest, "kin-model", "0.5.0").unwrap();
        assert!(changed);
        let out = std::fs::read_to_string(&manifest).unwrap();
        assert!(out.contains(r#"kin-model = { version = "0.5.0", registry = "kin" }"#));
    }

    #[test]
    fn update_manifest_pin_no_match_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        let original = r#"[dependencies]
kin-db = { version = "0.2.20" }
"#;
        std::fs::write(&manifest, original).unwrap();
        // No registry = "kin" -> not a managed pin -> no change.
        let changed = update_manifest_pin(&manifest, "kin-db", "0.2.24").unwrap();
        assert!(!changed);
        assert_eq!(std::fs::read_to_string(&manifest).unwrap(), original);
    }
}
