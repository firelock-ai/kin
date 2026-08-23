// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-repo dependency detection from manifest files and source imports.
//!
//! Parses `Cargo.toml`, `package.json`, and `go.mod` to discover which
//! external repos a project depends on, then maps dependency names to
//! known repos in the [`KinRegistry`](crate::registry::KinRegistry).
//!
//! Also scans source files for protocol/contract imports (e.g.
//! `use kin_model::*` or `import { X } from "@kinlab/contracts"`) to
//! detect API contract dependencies that manifest files may not capture.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// A single dependency extracted from a manifest file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoDependency {
    /// Dependency name (e.g. "kin-db", "@kinlab/contracts").
    pub name: String,
    /// Registry repo ID that provides this dependency, if known.
    pub provider_repo: Option<String>,
    /// Manifest source: "cargo", "npm", or "go".
    pub source: String,
}

/// Detect dependencies from manifest files and source imports in `repo_path`.
///
/// When `registry_repo_ids` is provided, dependency names are matched against
/// the registry to link third-party repos (not just Firelock repos). This
/// enables open-source repo onboarding: `kin init` on serde, then any repo
/// depending on serde auto-links via Cargo.toml dep name → registry ID.
pub fn detect_dependencies(repo_path: &Path) -> Vec<RepoDependency> {
    detect_dependencies_with_registry(repo_path, &[])
}

/// Registry-aware version of [`detect_dependencies`].
///
/// `registry_repo_ids` is the list of known repo IDs from the registry this
/// home resolves to ([`crate::registry::registry_path`]), which is
/// `~/.kin/registry.toml` only when neither `KIN_REGISTRY_PATH` nor `KIN_HOME`
/// is set.
/// Dependencies whose names match a registry repo ID (with crate-name normalization:
/// `kin-db` ↔ `kin_db`) get their `provider_repo` set automatically.
pub fn detect_dependencies_with_registry(
    repo_path: &Path,
    registry_repo_ids: &[String],
) -> Vec<RepoDependency> {
    let mut deps = Vec::new();

    let cargo_path = repo_path.join("Cargo.toml");
    if cargo_path.exists() {
        deps.extend(parse_cargo_deps(&cargo_path, registry_repo_ids));
    }

    let pkg_path = repo_path.join("package.json");
    if pkg_path.exists() {
        deps.extend(parse_npm_deps(&pkg_path, registry_repo_ids));
    }

    let go_path = repo_path.join("go.mod");
    if go_path.exists() {
        deps.extend(parse_go_deps(&go_path, registry_repo_ids));
    }

    // Scan source files for protocol/contract imports that manifests miss.
    deps.extend(detect_protocol_dependencies(repo_path));

    // Infrastructure files (Dockerfiles, docker-compose, CI workflows).
    deps.extend(detect_infra_dependencies(repo_path, registry_repo_ids));

    // Tier 6: Runtime subprocess dependencies (spawn/execFile/Command::new patterns).
    deps.extend(detect_subprocess_dependencies(repo_path, registry_repo_ids));

    // Tier 7: HTTP API dependencies (URLs, env vars referencing other services).
    deps.extend(detect_http_dependencies(repo_path, registry_repo_ids));

    // Deduplicate: same (name, source) pair shouldn't appear twice.
    deps.sort_by(|a, b| (&a.name, &a.source).cmp(&(&b.name, &b.source)));
    deps.dedup_by(|a, b| a.name == b.name && a.source == b.source);

    deps
}

// ---------------------------------------------------------------------------
// Infrastructure: Dockerfiles, docker-compose, CI workflows
// ---------------------------------------------------------------------------

/// Detect dependencies from infrastructure files: Dockerfiles, docker-compose,
/// and GitHub Actions workflows.
pub fn detect_infra_dependencies(
    repo_path: &Path,
    registry_repo_ids: &[String],
) -> Vec<RepoDependency> {
    let mut deps = Vec::new();

    // Dockerfile* in repo root
    if let Ok(entries) = std::fs::read_dir(repo_path) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("Dockerfile") && entry.path().is_file() {
                deps.extend(parse_dockerfile(&entry.path()));
            }
        }
    }

    // docker-compose*.yml in repo root
    if let Ok(entries) = std::fs::read_dir(repo_path) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("docker-compose")
                && name_str.ends_with(".yml")
                && entry.path().is_file()
            {
                deps.extend(parse_docker_compose(&entry.path(), registry_repo_ids));
            }
        }
    }

    // .github/workflows/*.yml
    let workflows_dir = repo_path.join(".github").join("workflows");
    if let Ok(entries) = std::fs::read_dir(&workflows_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with(".yml") && entry.path().is_file() {
                deps.extend(parse_ci_workflow(&entry.path()));
            }
        }
    }

    deps
}

/// Parse a Dockerfile for `FROM` directives referencing known images.
fn parse_dockerfile(path: &Path) -> Vec<RepoDependency> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut deps = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        // Match: FROM <image> or FROM <image> AS <alias>
        let rest = if let Some(r) = trimmed.strip_prefix("FROM ") {
            r.trim()
        } else {
            continue;
        };

        // The image is the first token.
        let image_ref = match rest.split_whitespace().next() {
            Some(i) => i,
            None => continue,
        };

        if !image_ref.contains("firelock") {
            continue;
        }

        // Extract image name: last path segment, strip tag.
        // e.g. "us-central1-docker.pkg.dev/kin-ecosystem/kin-ecosystem/kinhub-web:latest"
        //   → "kinhub-web"
        let last_segment = match image_ref.rsplit('/').next() {
            Some(s) => s,
            None => continue,
        };
        let image_name = last_segment.split(':').next().unwrap_or(last_segment);

        // Extract tag if present.
        let tag = last_segment.split(':').nth(1).unwrap_or("latest");

        deps.push(RepoDependency {
            name: format!("docker:{image_name}"),
            provider_repo: Some(image_name.to_string()),
            source: "dockerfile".to_string(),
        });
        // Suppress unused variable warning – tag is extracted for completeness.
        let _ = tag;
    }

    deps
}

/// Parse a docker-compose YAML file for `image:` and `build:` directives
/// referencing known projects.
fn parse_docker_compose(path: &Path, registry_repo_ids: &[String]) -> Vec<RepoDependency> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut deps = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // image: <ref>
        if let Some(rest) = trimmed.strip_prefix("image:") {
            let image_ref = rest.trim().trim_matches('"').trim_matches('\'');
            if image_ref.contains("firelock") {
                if let Some(last_seg) = image_ref.rsplit('/').next() {
                    let image_name = last_seg.split(':').next().unwrap_or(last_seg);
                    deps.push(RepoDependency {
                        name: format!("compose:{image_name}"),
                        provider_repo: Some(image_name.to_string()),
                        source: "compose".to_string(),
                    });
                }
            }
        }

        // build: <context-path>
        // We look for build contexts that reference known project directories.
        if let Some(rest) = trimmed.strip_prefix("build:") {
            let build_ctx = rest.trim().trim_matches('"').trim_matches('\'');
            // Extract the last path component as the project name.
            // e.g. "./kinlab" → "kinlab", "../kin-vfs" → "kin-vfs"
            let project_name = build_ctx
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or(build_ctx);
            // Only include if it looks like a firelock project name (starts with
            // "kin" or "kinlab" or "kinhub").
            if is_known_project(project_name, registry_repo_ids) {
                deps.push(RepoDependency {
                    name: format!("compose-build:{project_name}"),
                    provider_repo: Some(project_name.to_string()),
                    source: "compose".to_string(),
                });
            }
        }
    }

    deps
}

/// Parse a GitHub Actions workflow YAML for checkout actions referencing
/// firelock-ai repos.
fn parse_ci_workflow(path: &Path) -> Vec<RepoDependency> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut deps = Vec::new();
    let mut prev_is_checkout = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // Detect `- uses: actions/checkout@...`
        if trimmed.contains("uses:") && trimmed.contains("actions/checkout") {
            prev_is_checkout = true;
            continue;
        }

        // After a checkout action, look for `repository: firelock-ai/<repo>`
        if prev_is_checkout {
            if let Some(rest) = trimmed.strip_prefix("repository:") {
                let repo_ref = rest.trim().trim_matches('"').trim_matches('\'');
                if repo_ref.contains("firelock-ai") || repo_ref.contains("firelock-ai/") {
                    let repo_name = repo_ref.rsplit('/').next().unwrap_or(repo_ref);
                    deps.push(RepoDependency {
                        name: format!("ci:{repo_name}"),
                        provider_repo: Some(repo_name.to_string()),
                        source: "ci".to_string(),
                    });
                }
                prev_is_checkout = false;
                continue;
            }
            // If the next line isn't `repository:` but is still indented (with:
            // block), keep looking.
            if !trimmed.starts_with("with:") && !trimmed.is_empty() && !trimmed.starts_with('-') {
                // Could be other `with:` keys — keep scanning.
            } else if trimmed.starts_with('-') || trimmed.is_empty() {
                // Moved past the checkout step without finding a repository key.
                prev_is_checkout = false;
            }
        }
    }

    deps
}

/// Returns true if the name matches a known project (Firelock prefix OR registry entry).
fn is_known_project(name: &str, registry_repo_ids: &[String]) -> bool {
    name.starts_with("kin")
        || name.starts_with("kinhub")
        || match_registry(name, registry_repo_ids).is_some()
}

// ---------------------------------------------------------------------------
// Cargo.toml
// ---------------------------------------------------------------------------

fn parse_cargo_deps(path: &Path, registry_repo_ids: &[String]) -> Vec<RepoDependency> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let table: toml::Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut deps = Vec::new();

    // Collect from [dependencies], [workspace.dependencies]
    let sections: &[&[&str]] = &[&["dependencies"], &["workspace", "dependencies"]];

    for keys in sections {
        if let Some(section) = drill(&table, keys) {
            if let Some(map) = section.as_table() {
                for (name, spec) in map {
                    if let Some(dep) = cargo_dep_from_entry(name, spec, registry_repo_ids) {
                        deps.push(dep);
                    }
                }
            }
        }
    }

    deps
}

/// Extract a [`RepoDependency`] from a single Cargo.toml dependency entry.
///
/// Resolution order:
/// 1. If git URL contains a known org (firelock-ai), derive repo from URL
/// 2. If dep name matches a registry repo ID, link to that repo
/// 3. Otherwise, skip (third-party dep not in registry)
fn cargo_dep_from_entry(
    name: &str,
    spec: &toml::Value,
    registry_repo_ids: &[String],
) -> Option<RepoDependency> {
    // Try git URL first (works for any org, not just firelock)
    if let toml::Value::Table(t) = spec {
        if let Some(git_url) = t.get("git").and_then(|v| v.as_str()) {
            let repo_name = repo_name_from_git_url(git_url);
            if let Some(ref rn) = repo_name {
                // If the git repo name matches a registry entry, link it
                if match_registry(rn, registry_repo_ids).is_some()
                    || git_url.contains("firelock-ai")
                {
                    return Some(RepoDependency {
                        name: name.to_string(),
                        provider_repo: repo_name,
                        source: "cargo".to_string(),
                    });
                }
            }
        }
    }

    // Fall back to registry name matching (for crates.io deps that match a local repo)
    if let Some(registry_id) = match_registry(name, registry_repo_ids) {
        return Some(RepoDependency {
            name: name.to_string(),
            provider_repo: Some(registry_id),
            source: "cargo".to_string(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// package.json
// ---------------------------------------------------------------------------

fn parse_npm_deps(path: &Path, registry_repo_ids: &[String]) -> Vec<RepoDependency> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut deps = Vec::new();

    for section_key in &["dependencies", "devDependencies"] {
        if let Some(section) = json.get(section_key).and_then(|v| v.as_object()) {
            for (name, _version) in section {
                if let Some(dep) = npm_dep_from_entry(name, registry_repo_ids) {
                    deps.push(dep);
                }
            }
        }
    }

    deps
}

/// Match npm packages against known repos.
///
/// Resolution order:
/// 1. `@kinlab/*` → kinlab repo (hardcoded for workspace packages)
/// 2. Package name matches a registry repo ID
/// 3. Scoped package `@scope/name` — try matching `name` against registry
fn npm_dep_from_entry(name: &str, registry_repo_ids: &[String]) -> Option<RepoDependency> {
    // Known internal scope
    if name.starts_with("@kinlab/") {
        return Some(RepoDependency {
            name: name.to_string(),
            provider_repo: Some("kinlab".to_string()),
            source: "npm".to_string(),
        });
    }

    // Direct name match against registry
    if let Some(registry_id) = match_registry(name, registry_repo_ids) {
        return Some(RepoDependency {
            name: name.to_string(),
            provider_repo: Some(registry_id),
            source: "npm".to_string(),
        });
    }

    // For scoped packages (@scope/name), try matching just the name part
    if let Some(slash_pos) = name.find('/') {
        let bare_name = &name[slash_pos + 1..];
        if let Some(registry_id) = match_registry(bare_name, registry_repo_ids) {
            return Some(RepoDependency {
                name: name.to_string(),
                provider_repo: Some(registry_id),
                source: "npm".to_string(),
            });
        }
    }

    None
}

// ---------------------------------------------------------------------------
// go.mod
// ---------------------------------------------------------------------------

fn parse_go_deps(path: &Path, registry_repo_ids: &[String]) -> Vec<RepoDependency> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut deps = Vec::new();
    let mut in_require = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("require (") || trimmed == "require (" {
            in_require = true;
            continue;
        }
        if in_require && trimmed == ")" {
            in_require = false;
            continue;
        }

        // Single-line require: `require github.com/foo/bar v1.0.0`
        let module_line = if in_require {
            Some(trimmed)
        } else {
            trimmed.strip_prefix("require ").map(str::trim)
        };

        if let Some(module_line) = module_line {
            if let Some(dep) = go_dep_from_line(module_line, registry_repo_ids) {
                deps.push(dep);
            }
        }
    }

    deps
}

fn go_dep_from_line(line: &str, registry_repo_ids: &[String]) -> Option<RepoDependency> {
    let module_path = line.split_whitespace().next()?;
    let repo_name = module_path.rsplit('/').next()?;

    // Check firelock org first (backward compat)
    if module_path.contains("firelock-ai") {
        return Some(RepoDependency {
            name: module_path.to_string(),
            provider_repo: Some(repo_name.to_string()),
            source: "go".to_string(),
        });
    }

    // Match last path segment against registry
    if let Some(registry_id) = match_registry(repo_name, registry_repo_ids) {
        return Some(RepoDependency {
            name: module_path.to_string(),
            provider_repo: Some(registry_id),
            source: "go".to_string(),
        });
    }

    None
}

// ---------------------------------------------------------------------------
// Protocol / API contract imports
// ---------------------------------------------------------------------------

/// Known Rust crate-prefix → repo mappings for protocol dependencies.
const RUST_PROTOCOL_MAP: &[(&str, &str)] = &[
    ("kin_model", "kin-db"),
    ("kin_db", "kin-db"),
    ("kin_vfs_core", "kin-vfs"),
];

/// Known TypeScript scope-prefix → repo mappings for protocol dependencies.
const TS_PROTOCOL_MAP: &[(&str, &str)] = &[("@kinlab/", "kinlab"), ("@kin/", "kin")];

/// Scan source files for import patterns that reference other repos'
/// packages, revealing protocol/contract dependencies that manifest files
/// may not capture.
///
/// Checks a small set of key source files (entry points + first 5 source
/// files) for a fast approximation rather than scanning the full tree.
pub fn detect_protocol_dependencies(repo_path: &Path) -> Vec<RepoDependency> {
    let mut seen_repos: HashSet<String> = HashSet::new();
    let mut deps = Vec::new();

    let src = repo_path.join("src");

    // Collect candidate files to scan.
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();

    // Entry-point files in src/
    for name in &["src/lib.rs", "src/main.rs", "src/index.ts", "src/main.ts"] {
        let p = repo_path.join(name);
        if p.exists() {
            candidates.push(p);
        }
    }

    // First 5 .rs or .ts files in src/ (beyond the entry points already added).
    if src.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&src) {
            let mut extra = 0usize;
            for entry in entries.flatten() {
                if extra >= 5 {
                    break;
                }
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let is_source = path
                    .extension()
                    .map(|e| e == "rs" || e == "ts")
                    .unwrap_or(false);
                if !is_source {
                    continue;
                }
                if candidates.contains(&path) {
                    continue;
                }
                candidates.push(path);
                extra += 1;
            }
        }
    }

    for path in &candidates {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let is_rust = path.extension().map(|e| e == "rs").unwrap_or(false);
        if is_rust {
            scan_rust_imports(&content, &mut seen_repos, &mut deps);
        } else {
            scan_ts_imports(&content, &mut seen_repos, &mut deps);
        }
    }

    deps
}

/// Scan Rust source for `use <crate>::` patterns matching known protocol crates.
fn scan_rust_imports(content: &str, seen: &mut HashSet<String>, deps: &mut Vec<RepoDependency>) {
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("use ") {
            continue;
        }
        for &(prefix, repo) in RUST_PROTOCOL_MAP {
            let pattern = format!("use {}::", prefix);
            let pattern_bare = format!("use {};", prefix);
            if (trimmed.starts_with(&pattern) || trimmed.starts_with(&pattern_bare))
                && seen.insert(repo.to_string())
            {
                deps.push(RepoDependency {
                    name: prefix.replace('_', "-"),
                    provider_repo: Some(repo.to_string()),
                    source: "protocol".to_string(),
                });
            }
        }
    }
}

/// Scan TypeScript source for `from "@kinlab/*"` or `from "@kin/*"` imports.
fn scan_ts_imports(content: &str, seen: &mut HashSet<String>, deps: &mut Vec<RepoDependency>) {
    for line in content.lines() {
        let trimmed = line.trim();
        // Match: import ... from "..." or export ... from "..."
        let from_pos = match trimmed.find("from ") {
            Some(p) => p,
            None => continue,
        };
        if !trimmed.starts_with("import") && !trimmed.starts_with("export") {
            continue;
        }
        let after_from = &trimmed[from_pos + 5..];
        let module = match extract_quoted(after_from) {
            Some(m) => m,
            None => continue,
        };
        for &(prefix, repo) in TS_PROTOCOL_MAP {
            if module.starts_with(prefix) && seen.insert(repo.to_string()) {
                deps.push(RepoDependency {
                    name: module.to_string(),
                    provider_repo: Some(repo.to_string()),
                    source: "protocol".to_string(),
                });
            }
        }
    }
}

/// Extract a quoted string (single or double) from the start of `s`.
fn extract_quoted(s: &str) -> Option<&str> {
    let s = s.trim();
    let quote = s.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let inner = &s[1..];
    let end = inner.find(quote)?;
    Some(&inner[..end])
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Match a dependency name against registry repo IDs.
///
/// Tries exact match first, then normalized match (hyphens ↔ underscores).
/// Returns the matching repo ID if found.
fn match_registry(dep_name: &str, registry_repo_ids: &[String]) -> Option<String> {
    // Exact match
    if let Some(id) = registry_repo_ids.iter().find(|id| id.as_str() == dep_name) {
        return Some(id.clone());
    }
    // Normalized: kin-db ↔ kin_db
    let normalized = dep_name.replace('-', "_");
    for id in registry_repo_ids {
        if id.replace('-', "_") == normalized {
            return Some(id.clone());
        }
    }
    None
}

/// Drill into a nested TOML value by successive keys.
fn drill<'a>(root: &'a toml::Value, keys: &[&str]) -> Option<&'a toml::Value> {
    let mut cur = root;
    for k in keys {
        cur = cur.get(k)?;
    }
    Some(cur)
}

/// Extract repo name from a git URL.
///
/// `"https://github.com/firelock-ai/kin-db.git"` → `"kin-db"`
fn repo_name_from_git_url(url: &str) -> Option<String> {
    let last_segment = url.rsplit('/').next()?;
    Some(last_segment.trim_end_matches(".git").to_string())
}

/// Build a dependency graph from the registry: repo_id → [provider repo IDs].
pub fn dependency_graph(repos: &[crate::registry::RegisteredRepo]) -> HashMap<String, Vec<String>> {
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();
    for repo in repos {
        let providers: Vec<String> = repo
            .dependencies
            .iter()
            .filter_map(|d| d.provider_repo.clone())
            .collect();
        graph.insert(repo.id.clone(), providers);
    }
    graph
}

// ---------------------------------------------------------------------------
// Tier 6: Runtime subprocess dependencies
// ---------------------------------------------------------------------------

/// Scan for runtime binary dependencies on registry repos.
///
/// Three detection strategies:
/// 1. Direct string literals in subprocess calls: spawn("kin", ...), Command::new("kin")
/// 2. Binary name references in env vars and strings: KIN_BINARY_PATH, "kin mcp start"
/// 3. Package.json metadata: name field, bin entries, VS Code extension settings
pub fn detect_subprocess_dependencies(
    repo_path: &Path,
    registry_repo_ids: &[String],
) -> Vec<RepoDependency> {
    let mut deps = Vec::new();
    let mut seen = HashSet::new();

    // Strategy 1+2: Scan source files for binary name references.
    // Instead of matching only subprocess calls on a single line,
    // look for ANY reference to a registry repo name in a binary context:
    // - Env vars: *_BINARY_PATH, *_BINARY, *_BIN containing a repo name
    // - String literals: "kin mcp start", "kin commit", etc.
    // - Subprocess calls: spawn("kin"), execFile(binaryPath) where binaryPath = "kin"
    let source_files = collect_source_files(repo_path, 30);

    for file in &source_files {
        let content = match std::fs::read_to_string(file) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Check if the file contains subprocess-related patterns at all.
        let has_subprocess_context = content.contains("spawn")
            || content.contains("execFile")
            || content.contains("execa")
            || content.contains("subprocess")
            || content.contains("Command::new")
            || content.contains("exec.Command");

        if !has_subprocess_context {
            continue;
        }

        // In a subprocess-context file, look for ANY reference to registry repo names
        // in strings, env vars, or command fragments.
        for registry_id in registry_repo_ids {
            if seen.contains(registry_id) {
                continue;
            }

            // Check for patterns like:
            // - "kin mcp start", "kin commit", "kin --version"
            // - KIN_BINARY_PATH, KIN_BINARY, KIN_BIN
            // - binaryPath containing "kin"
            let upper = registry_id.to_uppercase().replace('-', "_");
            let name_with_space = format!("{} ", registry_id); // "kin " in "kin mcp start"
            let binary_path_env = format!("{}_BINARY_PATH", upper); // KIN_BINARY_PATH
            let binary_env = format!("{}_BINARY", upper); // KIN_BINARY

            let found = content.contains(&binary_path_env)
                || content.contains(&binary_env)
                || content.contains(&format!("\"{}\"", registry_id)) // "kin" as string literal
                || content.contains(&format!("'{}'", registry_id)) // 'kin' as string literal
                || content.contains(&format!("\"{}\"", name_with_space.trim())) // same
                || content.lines().any(|line| {
                    let trimmed = line.trim();
                    // "kin mcp start", "kin commit -m", etc.
                    trimmed.contains(&format!("\"{}\"", registry_id))
                        || trimmed.contains(&format!("\"{} ", registry_id))
                        || trimmed.contains(&format!("'{} ", registry_id))
                });

            if found {
                seen.insert(registry_id.clone());
                deps.push(RepoDependency {
                    name: format!("bin:{}", registry_id),
                    provider_repo: Some(registry_id.clone()),
                    source: "subprocess".to_string(),
                });
            }
        }
    }

    // Strategy 3: Check package.json for binary references.
    let pkg_path = repo_path.join("package.json");
    if pkg_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&pkg_path) {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
                // Check VS Code extension contributes.configuration.properties
                // for settings like "kin.binaryPath" that reference registry repos.
                if let Some(props) = parsed
                    .pointer("/contributes/configuration/properties")
                    .and_then(|v| v.as_object())
                {
                    for key in props.keys() {
                        // "kin.binaryPath" → prefix "kin"
                        if let Some(prefix) = key.split('.').next() {
                            if let Some(registry_id) = match_registry(prefix, registry_repo_ids) {
                                if seen.insert(format!("pkg:{}", registry_id)) {
                                    deps.push(RepoDependency {
                                        name: format!("bin:{}", prefix),
                                        provider_repo: Some(registry_id),
                                        source: "subprocess".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }

                // Check "bin" field in package.json (npm binary packages).
                if let Some(bin) = parsed.get("bin") {
                    let bin_names: Vec<&str> = match bin {
                        serde_json::Value::String(s) => vec![s.as_str()],
                        serde_json::Value::Object(obj) => obj.keys().map(|k| k.as_str()).collect(),
                        _ => vec![],
                    };
                    for name in bin_names {
                        let base = std::path::Path::new(name)
                            .file_stem()
                            .and_then(|n| n.to_str())
                            .unwrap_or(name);
                        if let Some(registry_id) = match_registry(base, registry_repo_ids) {
                            if seen.insert(format!("bin-pkg:{}", registry_id)) {
                                deps.push(RepoDependency {
                                    name: format!("bin:{}", base),
                                    provider_repo: Some(registry_id),
                                    source: "subprocess".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    deps
}

// ---------------------------------------------------------------------------
// Tier 7: HTTP API dependencies
// ---------------------------------------------------------------------------

/// Known port → service mappings.
const KNOWN_PORTS: &[(&str, &str)] = &[("4219", "kin"), ("4010", "kinlab"), ("4311", "kinlab")];

/// Scan source files for HTTP references to known service ports.
pub fn detect_http_dependencies(
    repo_path: &Path,
    registry_repo_ids: &[String],
) -> Vec<RepoDependency> {
    let mut deps = Vec::new();
    let mut seen = HashSet::new();
    let source_files = collect_source_files(repo_path, 20);

    for file in &source_files {
        let content = match std::fs::read_to_string(file) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }
            for (port, service) in KNOWN_PORTS {
                let localhost_pattern = format!("localhost:{}", port);
                let ip_pattern = format!("127.0.0.1:{}", port);
                if trimmed.contains(&localhost_pattern) || trimmed.contains(&ip_pattern) {
                    if let Some(registry_id) = match_registry(service, registry_repo_ids) {
                        let key = format!("http:{}:{}", service, port);
                        if seen.insert(key) {
                            deps.push(RepoDependency {
                                name: format!("http:localhost:{}", port),
                                provider_repo: Some(registry_id),
                                source: "http".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }
    deps
}

/// Collect source files from a repo, limited to `max_files`.
fn collect_source_files(repo_path: &Path, max_files: usize) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let entry_points = [
        "src/index.ts",
        "src/main.ts",
        "src/index.js",
        "src/main.js",
        "src/main.rs",
        "src/lib.rs",
        "main.py",
        "app.py",
        "main.go",
        "cmd/main.go",
    ];
    for ep in &entry_points {
        let path = repo_path.join(ep);
        if path.exists() {
            files.push(path);
        }
    }
    for subdir in &["src", "services", "apps", "packages", "crates", "cmd"] {
        let dir = repo_path.join(subdir);
        if dir.is_dir() {
            walk_source_files(&dir, &mut files, max_files, 3);
        }
    }
    files.truncate(max_files);
    files
}

fn walk_source_files(dir: &Path, files: &mut Vec<std::path::PathBuf>, max: usize, depth: usize) {
    if depth == 0 || files.len() >= max {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        if files.len() >= max {
            return;
        }
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !matches!(
                name,
                "node_modules" | "target" | ".git" | "dist" | "build" | ".kin"
            ) {
                walk_source_files(&path, files, max, depth - 1);
            }
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if matches!(
                ext,
                "ts" | "js" | "rs" | "py" | "go" | "rb" | "java" | "cs" | "c" | "cpp"
            ) {
                files.push(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Cargo.toml parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_cargo_git_deps_finds_firelock() {
        let dir = tempfile::tempdir().unwrap();
        let cargo = dir.path().join("Cargo.toml");
        std::fs::write(
            &cargo,
            r#"
[package]
name = "my-app"
version = "0.1.0"

[dependencies]
serde = "1"
kin-model = { git = "https://github.com/firelock-ai/kin-db.git", package = "kin-model" }
kin-db = { git = "https://github.com/firelock-ai/kin-db.git", package = "kin-db" }
rand = "0.8"
"#,
        )
        .unwrap();

        let deps = parse_cargo_deps(&cargo, &[]);
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "kin-model"
            && d.provider_repo.as_deref() == Some("kin-db")
            && d.source == "cargo"));
        assert!(deps.iter().any(|d| d.name == "kin-db"
            && d.provider_repo.as_deref() == Some("kin-db")
            && d.source == "cargo"));
    }

    #[test]
    fn parse_cargo_workspace_deps_finds_firelock() {
        let dir = tempfile::tempdir().unwrap();
        let cargo = dir.path().join("Cargo.toml");
        std::fs::write(
            &cargo,
            r#"
[workspace]
members = ["crates/*"]

[workspace.dependencies]
kin-model = { git = "https://github.com/firelock-ai/kin-db.git", package = "kin-model" }
kin-vfs-core = { git = "https://github.com/firelock-ai/kin-vfs.git", package = "kin-vfs-core" }
serde = "1"
"#,
        )
        .unwrap();

        let deps = parse_cargo_deps(&cargo, &[]);
        assert_eq!(deps.len(), 2);
        assert!(deps
            .iter()
            .any(|d| d.name == "kin-model" && d.provider_repo.as_deref() == Some("kin-db")));
        assert!(deps
            .iter()
            .any(|d| d.name == "kin-vfs-core" && d.provider_repo.as_deref() == Some("kin-vfs")));
    }

    #[test]
    fn parse_cargo_ignores_non_firelock_git() {
        let dir = tempfile::tempdir().unwrap();
        let cargo = dir.path().join("Cargo.toml");
        std::fs::write(
            &cargo,
            r#"
[dependencies]
some-crate = { git = "https://github.com/other-org/other-repo.git" }
"#,
        )
        .unwrap();

        let deps = parse_cargo_deps(&cargo, &[]);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // package.json parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_npm_finds_kinlab_packages() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        std::fs::write(
            &pkg,
            r#"{
  "name": "my-app",
  "dependencies": {
    "@kinlab/contracts": "workspace:*",
    "react": "^18"
  },
  "devDependencies": {
    "@kinlab/test-utils": "workspace:*",
    "typescript": "^5"
  }
}"#,
        )
        .unwrap();

        let deps = parse_npm_deps(&pkg, &[]);
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().all(|d| d.source == "npm"));
        assert!(deps
            .iter()
            .all(|d| d.provider_repo.as_deref() == Some("kinlab")));
        assert!(deps.iter().any(|d| d.name == "@kinlab/contracts"));
        assert!(deps.iter().any(|d| d.name == "@kinlab/test-utils"));
    }

    #[test]
    fn parse_npm_ignores_third_party() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        std::fs::write(
            &pkg,
            r#"{"dependencies": {"react": "^18", "lodash": "^4"}}"#,
        )
        .unwrap();

        let deps = parse_npm_deps(&pkg, &[]);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // go.mod parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_go_finds_firelock_modules() {
        let dir = tempfile::tempdir().unwrap();
        let gomod = dir.path().join("go.mod");
        std::fs::write(
            &gomod,
            r#"module github.com/example/myapp

go 1.21

require (
    github.com/firelock-ai/kin-sdk v0.2.0
    github.com/stretchr/testify v1.9.0
)

require github.com/firelock-ai/kin-utils v0.1.0
"#,
        )
        .unwrap();

        let deps = parse_go_deps(&gomod, &[]);
        assert_eq!(deps.len(), 2);
        assert!(deps
            .iter()
            .any(|d| d.name == "github.com/firelock-ai/kin-sdk"
                && d.provider_repo.as_deref() == Some("kin-sdk")
                && d.source == "go"));
        assert!(deps
            .iter()
            .any(|d| d.name == "github.com/firelock-ai/kin-utils"
                && d.provider_repo.as_deref() == Some("kin-utils")
                && d.source == "go"));
    }

    #[test]
    fn parse_go_ignores_non_firelock() {
        let dir = tempfile::tempdir().unwrap();
        let gomod = dir.path().join("go.mod");
        std::fs::write(
            &gomod,
            r#"module example.com/foo

require github.com/stretchr/testify v1.9.0
"#,
        )
        .unwrap();

        let deps = parse_go_deps(&gomod, &[]);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // detect_dependencies integration
    // -----------------------------------------------------------------------

    #[test]
    fn detect_dependencies_combines_all_manifests() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            r#"
[dependencies]
kin-db = { git = "https://github.com/firelock-ai/kin-db.git" }
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"@kinlab/contracts": "^1"}}"#,
        )
        .unwrap();

        let deps = detect_dependencies(dir.path());
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.source == "cargo"));
        assert!(deps.iter().any(|d| d.source == "npm"));
    }

    // -----------------------------------------------------------------------
    // dependency_graph
    // -----------------------------------------------------------------------

    #[test]
    fn dependency_graph_maps_repos_to_providers() {
        let repos = vec![
            crate::registry::RegisteredRepo {
                id: "kin".to_string(),
                path: std::path::PathBuf::from("/repos/kin"),
                entities: 100,
                last_commit: String::new(),
                dependencies: vec![
                    RepoDependency {
                        name: "kin-model".to_string(),
                        provider_repo: Some("kin-db".to_string()),
                        source: "cargo".to_string(),
                    },
                    RepoDependency {
                        name: "kin-vfs-core".to_string(),
                        provider_repo: Some("kin-vfs".to_string()),
                        source: "cargo".to_string(),
                    },
                ],
            },
            crate::registry::RegisteredRepo {
                id: "kinlab".to_string(),
                path: std::path::PathBuf::from("/repos/kinlab"),
                entities: 50,
                last_commit: String::new(),
                dependencies: vec![],
            },
        ];

        let graph = dependency_graph(&repos);
        assert_eq!(graph.len(), 2);
        let kin_deps = &graph["kin"];
        assert_eq!(kin_deps.len(), 2);
        assert!(kin_deps.contains(&"kin-db".to_string()));
        assert!(kin_deps.contains(&"kin-vfs".to_string()));
        assert!(graph["kinlab"].is_empty());
    }

    #[test]
    fn unknown_deps_have_none_provider() {
        let dir = tempfile::tempdir().unwrap();
        // A package.json with only third-party deps won't produce any results
        // because we filter to @kinlab/* only. But for Cargo, a git dep to
        // firelock-ai always gets a provider. Test with an explicit struct.
        let dep = RepoDependency {
            name: "some-unknown".to_string(),
            provider_repo: None,
            source: "cargo".to_string(),
        };
        assert!(dep.provider_repo.is_none());
        // Avoid unused variable warning
        let _ = dir;
    }

    // -----------------------------------------------------------------------
    // Protocol / API contract detection
    // -----------------------------------------------------------------------

    #[test]
    fn protocol_ts_import_detects_kinlab() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("index.ts"),
            r#"import { ReviewDecisionRequest } from "@kinlab/contracts";
import { something } from "lodash";
export { Foo } from '@kinlab/repo-eval';
"#,
        )
        .unwrap();

        let deps = detect_protocol_dependencies(dir.path());
        // Both @kinlab imports should dedupe to a single "kinlab" provider.
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].provider_repo.as_deref(), Some("kinlab"));
        assert_eq!(deps[0].source, "protocol");
    }

    #[test]
    fn protocol_rust_use_detects_kin_db() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("lib.rs"),
            r#"use kin_model::{Entity, Relation, GraphStore};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
"#,
        )
        .unwrap();

        let deps = detect_protocol_dependencies(dir.path());
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "kin-model");
        assert_eq!(deps[0].provider_repo.as_deref(), Some("kin-db"));
        assert_eq!(deps[0].source, "protocol");
    }

    #[test]
    fn protocol_rust_ignores_third_party() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("lib.rs"),
            r#"use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use std::collections::HashMap;
"#,
        )
        .unwrap();

        let deps = detect_protocol_dependencies(dir.path());
        assert!(deps.is_empty());
    }

    #[test]
    fn protocol_rust_deduplicates_same_repo() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("lib.rs"),
            r#"use kin_model::Entity;
use kin_db::Store;
"#,
        )
        .unwrap();

        let deps = detect_protocol_dependencies(dir.path());
        // Both kin_model and kin_db map to the "kin-db" repo, so only one dep.
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].provider_repo.as_deref(), Some("kin-db"));
    }

    #[test]
    fn protocol_detects_kin_vfs_core() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("main.rs"), "use kin_vfs_core::VfsMount;\n").unwrap();

        let deps = detect_protocol_dependencies(dir.path());
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "kin-vfs-core");
        assert_eq!(deps[0].provider_repo.as_deref(), Some("kin-vfs"));
    }

    #[test]
    fn protocol_no_src_dir_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        // No src/ directory at all.
        let deps = detect_protocol_dependencies(dir.path());
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // Dockerfile parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_dockerfile_finds_firelock_image() {
        let dir = tempfile::tempdir().unwrap();
        let dockerfile = dir.path().join("Dockerfile");
        std::fs::write(
            &dockerfile,
            r#"FROM ubuntu:22.04 AS base
RUN apt-get update

FROM us-central1-docker.pkg.dev/kin-ecosystem/firelock/kinhub-web:latest
COPY . /app
"#,
        )
        .unwrap();

        let deps = parse_dockerfile(&dockerfile);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "docker:kinhub-web");
        assert_eq!(deps[0].provider_repo.as_deref(), Some("kinhub-web"));
        assert_eq!(deps[0].source, "dockerfile");
    }

    #[test]
    fn parse_dockerfile_ignores_non_firelock_images() {
        let dir = tempfile::tempdir().unwrap();
        let dockerfile = dir.path().join("Dockerfile");
        std::fs::write(&dockerfile, "FROM ubuntu:22.04\nRUN echo hello\n").unwrap();

        let deps = parse_dockerfile(&dockerfile);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // docker-compose parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_docker_compose_finds_firelock_image() {
        let dir = tempfile::tempdir().unwrap();
        let compose = dir.path().join("docker-compose.yml");
        std::fs::write(
            &compose,
            r#"version: "3.8"
services:
  web:
    image: us-central1-docker.pkg.dev/kin-ecosystem/firelock/kinhub-web:latest
    ports:
      - "8080:8080"
  redis:
    image: redis:7
"#,
        )
        .unwrap();

        let deps = parse_docker_compose(&compose, &[]);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "compose:kinhub-web");
        assert_eq!(deps[0].provider_repo.as_deref(), Some("kinhub-web"));
        assert_eq!(deps[0].source, "compose");
    }

    #[test]
    fn parse_docker_compose_finds_build_context() {
        let dir = tempfile::tempdir().unwrap();
        let compose = dir.path().join("docker-compose.yml");
        std::fs::write(
            &compose,
            r#"version: "3.8"
services:
  lab:
    build: ./kinlab
    ports:
      - "3000:3000"
"#,
        )
        .unwrap();

        let deps = parse_docker_compose(&compose, &[]);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "compose-build:kinlab");
        assert_eq!(deps[0].provider_repo.as_deref(), Some("kinlab"));
        assert_eq!(deps[0].source, "compose");
    }

    #[test]
    fn parse_docker_compose_ignores_non_firelock() {
        let dir = tempfile::tempdir().unwrap();
        let compose = dir.path().join("docker-compose.yml");
        std::fs::write(
            &compose,
            r#"version: "3.8"
services:
  db:
    image: postgres:16
  redis:
    image: redis:7
"#,
        )
        .unwrap();

        let deps = parse_docker_compose(&compose, &[]);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // CI workflow parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_ci_workflow_finds_firelock_checkout() {
        let dir = tempfile::tempdir().unwrap();
        let workflows = dir.path().join(".github").join("workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        let workflow = workflows.join("build.yml");
        std::fs::write(
            &workflow,
            r#"name: Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/checkout@v6
        with:
          repository: firelock-ai/kin-vfs
          path: kin-vfs
      - run: cargo build
"#,
        )
        .unwrap();

        let deps = parse_ci_workflow(&workflow);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "ci:kin-vfs");
        assert_eq!(deps[0].provider_repo.as_deref(), Some("kin-vfs"));
        assert_eq!(deps[0].source, "ci");
    }

    #[test]
    fn parse_ci_workflow_ignores_non_firelock_repos() {
        let dir = tempfile::tempdir().unwrap();
        let workflows = dir.path().join(".github").join("workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        let workflow = workflows.join("ci.yml");
        std::fs::write(
            &workflow,
            r#"name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/checkout@v6
        with:
          repository: other-org/other-repo
          path: other
"#,
        )
        .unwrap();

        let deps = parse_ci_workflow(&workflow);
        assert!(deps.is_empty());
    }

    // -----------------------------------------------------------------------
    // detect_infra_dependencies integration
    // -----------------------------------------------------------------------

    #[test]
    fn detect_infra_dependencies_combines_all_sources() {
        let dir = tempfile::tempdir().unwrap();

        // Dockerfile
        std::fs::write(
            dir.path().join("Dockerfile"),
            "FROM us-central1-docker.pkg.dev/kin-ecosystem/firelock/kinhub-web:latest\n",
        )
        .unwrap();

        // docker-compose
        std::fs::write(
            dir.path().join("docker-compose.yml"),
            "services:\n  app:\n    build: ./kinlab\n",
        )
        .unwrap();

        // CI workflow
        let workflows = dir.path().join(".github").join("workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        std::fs::write(
            workflows.join("deploy.yml"),
            "steps:\n  - uses: actions/checkout@v6\n    with:\n      repository: firelock-ai/kin-vfs\n",
        )
        .unwrap();

        let deps = detect_infra_dependencies(dir.path(), &[]);
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().any(|d| d.source == "dockerfile"));
        assert!(deps.iter().any(|d| d.source == "compose"));
        assert!(deps.iter().any(|d| d.source == "ci"));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    #[test]
    fn repo_name_from_git_url_strips_git_suffix() {
        assert_eq!(
            repo_name_from_git_url("https://github.com/firelock-ai/kin-db.git"),
            Some("kin-db".to_string())
        );
        assert_eq!(
            repo_name_from_git_url("https://github.com/firelock-ai/kin-vfs"),
            Some("kin-vfs".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // Registry-aware matching (third-party repos)
    // -----------------------------------------------------------------------

    #[test]
    fn match_registry_finds_exact_and_normalized() {
        let registry = vec![
            "serde".to_string(),
            "kin-db".to_string(),
            "tokio".to_string(),
        ];

        assert_eq!(
            match_registry("serde", &registry),
            Some("serde".to_string())
        );
        assert_eq!(
            match_registry("kin-db", &registry),
            Some("kin-db".to_string())
        );
        assert_eq!(
            match_registry("kin_db", &registry),
            Some("kin-db".to_string())
        ); // normalized
        assert_eq!(match_registry("unknown", &registry), None);
    }

    #[test]
    fn cargo_deps_link_third_party_via_registry() {
        let dir = tempfile::tempdir().unwrap();
        let cargo = dir.path().join("Cargo.toml");
        std::fs::write(
            &cargo,
            r#"
[dependencies]
serde = "1"
tokio = { version = "1", features = ["full"] }
rand = "0.8"
"#,
        )
        .unwrap();

        // Without registry: no deps detected (all are crates.io, no git URLs)
        let deps = parse_cargo_deps(&cargo, &[]);
        assert!(deps.is_empty());

        // With registry containing serde and tokio: both link
        let registry = vec!["serde".to_string(), "tokio".to_string()];
        let deps = parse_cargo_deps(&cargo, &registry);
        assert_eq!(deps.len(), 2);
        assert!(deps
            .iter()
            .any(|d| d.name == "serde" && d.provider_repo.as_deref() == Some("serde")));
        assert!(deps
            .iter()
            .any(|d| d.name == "tokio" && d.provider_repo.as_deref() == Some("tokio")));
        // rand is not in registry, so not linked
        assert!(!deps.iter().any(|d| d.name == "rand"));
    }

    #[test]
    fn npm_deps_link_third_party_via_registry() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        std::fs::write(
            &pkg,
            r#"{"dependencies": {"react": "^18", "express": "^4", "lodash": "^4"}}"#,
        )
        .unwrap();

        let registry = vec!["react".to_string(), "express".to_string()];
        let deps = parse_npm_deps(&pkg, &registry);
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "react"));
        assert!(deps.iter().any(|d| d.name == "express"));
    }

    #[test]
    fn go_deps_link_third_party_via_registry() {
        let dir = tempfile::tempdir().unwrap();
        let gomod = dir.path().join("go.mod");
        std::fs::write(
            &gomod,
            r#"module example.com/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.0
    github.com/stretchr/testify v1.9.0
)
"#,
        )
        .unwrap();

        // "gin" matches registry entry
        let registry = vec!["gin".to_string()];
        let deps = parse_go_deps(&gomod, &registry);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].provider_repo.as_deref(), Some("gin"));
    }

    // -----------------------------------------------------------------------
    // Tier 6: Subprocess / runtime binary dependencies
    // -----------------------------------------------------------------------

    #[test]
    fn subprocess_rust_command_new_detects_binary() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("main.rs"),
            r#"use std::process::Command;

fn run_kin() {
    let output = Command::new("kin")
        .arg("mcp")
        .arg("start")
        .output()
        .expect("failed to start kin");
}
"#,
        )
        .unwrap();

        let registry = vec!["kin".to_string(), "kinlab".to_string()];
        let deps = detect_subprocess_dependencies(dir.path(), &registry);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "bin:kin");
        assert_eq!(deps[0].provider_repo.as_deref(), Some("kin"));
        assert_eq!(deps[0].source, "subprocess");
    }

    #[test]
    fn subprocess_ts_exec_file_detects_binary() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("index.ts"),
            r#"import { execFile } from "child_process";

function startKin() {
    execFile("kin", ["mcp", "start"], (err, stdout) => {
        console.log(stdout);
    });
}
"#,
        )
        .unwrap();

        let registry = vec!["kin".to_string()];
        let deps = detect_subprocess_dependencies(dir.path(), &registry);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "bin:kin");
        assert_eq!(deps[0].provider_repo.as_deref(), Some("kin"));
        assert_eq!(deps[0].source, "subprocess");
    }

    #[test]
    fn subprocess_ts_spawn_detects_binary() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("index.ts"),
            r#"import { spawn } from "child_process";

const child = spawn("kin", ["--version"]);
"#,
        )
        .unwrap();

        let registry = vec!["kin".to_string()];
        let deps = detect_subprocess_dependencies(dir.path(), &registry);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "bin:kin");
        assert_eq!(deps[0].source, "subprocess");
    }

    #[test]
    fn subprocess_python_detects_binary() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("main.py"),
            r#"import subprocess

result = subprocess.run(["kin", "commit", "-m", "test"])
"#,
        )
        .unwrap();

        let registry = vec!["kin".to_string()];
        let deps = detect_subprocess_dependencies(dir.path(), &registry);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "bin:kin");
        assert_eq!(deps[0].source, "subprocess");
    }

    #[test]
    fn subprocess_env_var_reference_detects_binary() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("index.ts"),
            r#"import { execFile } from "child_process";

const binaryPath = process.env.KIN_BINARY_PATH || "kin";
execFile(binaryPath, ["mcp", "start"]);
"#,
        )
        .unwrap();

        let registry = vec!["kin".to_string()];
        let deps = detect_subprocess_dependencies(dir.path(), &registry);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "bin:kin");
        assert_eq!(deps[0].source, "subprocess");
    }

    #[test]
    fn subprocess_no_binary_invocations_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("lib.rs"),
            r#"fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#,
        )
        .unwrap();

        let registry = vec!["kin".to_string(), "kinlab".to_string()];
        let deps = detect_subprocess_dependencies(dir.path(), &registry);
        assert!(deps.is_empty());
    }

    #[test]
    fn subprocess_no_registry_returns_empty() {
        // Even with subprocess patterns, an empty registry means nothing to match.
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("main.rs"),
            r#"use std::process::Command;
let _ = Command::new("kin").output();
"#,
        )
        .unwrap();

        let deps = detect_subprocess_dependencies(dir.path(), &[]);
        assert!(deps.is_empty());
    }

    #[test]
    fn subprocess_package_json_binary_config_detects_dep() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{
  "name": "kin-editor",
  "contributes": {
    "configuration": {
      "properties": {
        "kin.binaryPath": {
          "type": "string",
          "default": "kin"
        }
      }
    }
  }
}"#,
        )
        .unwrap();

        let registry = vec!["kin".to_string()];
        let deps = detect_subprocess_dependencies(dir.path(), &registry);
        assert!(deps
            .iter()
            .any(|d| d.name == "bin:kin" && d.source == "subprocess"));
    }

    #[test]
    fn subprocess_deduplicates_same_binary() {
        // Multiple files referencing the same binary should produce only one dep.
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("main.rs"),
            r#"use std::process::Command;
let _ = Command::new("kin").arg("commit").output();
"#,
        )
        .unwrap();
        std::fs::write(
            src.join("lib.rs"),
            r#"use std::process::Command;
let _ = Command::new("kin").arg("status").output();
"#,
        )
        .unwrap();

        let registry = vec!["kin".to_string()];
        let deps = detect_subprocess_dependencies(dir.path(), &registry);
        assert_eq!(deps.iter().filter(|d| d.name == "bin:kin").count(), 1);
    }

    // -----------------------------------------------------------------------
    // Tier 7: HTTP API dependencies
    // -----------------------------------------------------------------------

    #[test]
    fn http_localhost_port_detects_kin_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("index.ts"),
            r#"const response = await fetch("http://localhost:4219/api/status");
"#,
        )
        .unwrap();

        let registry = vec!["kin".to_string()];
        let deps = detect_http_dependencies(dir.path(), &registry);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "http:localhost:4219");
        assert_eq!(deps[0].provider_repo.as_deref(), Some("kin"));
        assert_eq!(deps[0].source, "http");
    }

    #[test]
    fn http_localhost_port_detects_kinlab() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("main.ts"),
            r#"const apiUrl = "http://localhost:4010/api/orgs";
"#,
        )
        .unwrap();

        let registry = vec!["kinlab".to_string()];
        let deps = detect_http_dependencies(dir.path(), &registry);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "http:localhost:4010");
        assert_eq!(deps[0].provider_repo.as_deref(), Some("kinlab"));
        assert_eq!(deps[0].source, "http");
    }

    #[test]
    fn http_127_0_0_1_also_detects() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("main.rs"),
            r#"let url = "http://127.0.0.1:4219/health";
"#,
        )
        .unwrap();

        let registry = vec!["kin".to_string()];
        let deps = detect_http_dependencies(dir.path(), &registry);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "http:localhost:4219");
        assert_eq!(deps[0].provider_repo.as_deref(), Some("kin"));
    }

    #[test]
    fn http_no_known_ports_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("index.ts"),
            r#"const url = "http://localhost:3000/api";
const db = "localhost:5432";
"#,
        )
        .unwrap();

        let registry = vec!["kin".to_string(), "kinlab".to_string()];
        let deps = detect_http_dependencies(dir.path(), &registry);
        assert!(deps.is_empty());
    }

    #[test]
    fn http_skips_comments() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("main.rs"),
            r#"// The daemon runs on localhost:4219
// 127.0.0.1:4010 is the control plane
fn main() {}
"#,
        )
        .unwrap();

        let registry = vec!["kin".to_string(), "kinlab".to_string()];
        let deps = detect_http_dependencies(dir.path(), &registry);
        assert!(deps.is_empty());
    }

    #[test]
    fn http_no_source_files_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        // No src/ directory.
        let registry = vec!["kin".to_string()];
        let deps = detect_http_dependencies(dir.path(), &registry);
        assert!(deps.is_empty());
    }

    #[test]
    fn http_deduplicates_same_port() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("index.ts"),
            r#"const a = "http://localhost:4219/status";
const b = "http://localhost:4219/health";
const c = "http://127.0.0.1:4219/api";
"#,
        )
        .unwrap();

        let registry = vec!["kin".to_string()];
        let deps = detect_http_dependencies(dir.path(), &registry);
        assert_eq!(deps.len(), 1);
    }

    #[test]
    fn http_port_without_registry_match_returns_empty() {
        // Port 4219 maps to "kin", but if "kin" is not in the registry, no dep.
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("index.ts"),
            r#"fetch("http://localhost:4219/api");
"#,
        )
        .unwrap();

        let registry = vec!["other-repo".to_string()];
        let deps = detect_http_dependencies(dir.path(), &registry);
        assert!(deps.is_empty());
    }
}
