// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_core::registry::KinRegistry;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

/// Show cross-repo dependencies across all registered Kin repositories.
pub async fn run() -> Result<()> {
    let registry = KinRegistry::load()
        .map_err(|e| anyhow::anyhow!("failed to load registry: {}", e))?;

    if registry.repos.is_empty() {
        println!("No registered repositories.");
        println!("hint: run `kin init` in a directory to register it");
        return Ok(());
    }

    // Build a set of known repo IDs for matching
    let known_ids: HashSet<String> = registry.repos.iter().map(|r| r.id.clone()).collect();

    // Detect typed deps for each repo
    let mut repo_deps: BTreeMap<String, Vec<(String, DepType)>> = BTreeMap::new();
    for repo in &registry.repos {
        let deps = detect_dependencies_for_repo(&repo.path, &known_ids);
        repo_deps.insert(repo.id.clone(), deps);
    }

    println!("Cross-repo dependencies:\n");
    for (id, deps) in &repo_deps {
        println!("  {}", id);
        if deps.is_empty() {
            println!("    (no cross-repo dependencies)");
        } else {
            for (name, dep_type) in deps {
                println!("    -> {} ({})", name, dep_type);
            }
        }
        println!();
    }

    Ok(())
}

/// Detect deps for a single repo path returning (dep_name, dep_type) pairs.
pub fn detect_dependencies_for_repo(
    repo_path: &Path,
    known_ids: &HashSet<String>,
) -> Vec<(String, DepType)> {
    let mut deps = Vec::new();

    // Cargo git deps
    let cargo_deps = detect_cargo_git_deps(repo_path);
    for dep_name in cargo_deps {
        if let Some(matched) = match_to_known_repo(&dep_name, known_ids) {
            if !deps.iter().any(|(n, _)| n == &matched) {
                deps.push((matched, DepType::CargoGit));
            }
        }
    }

    // npm workspace deps
    let npm_deps = detect_npm_workspace_deps(repo_path);
    for dep_name in &npm_deps {
        if let Some(matched) = match_to_known_repo(dep_name, known_ids) {
            if !deps.iter().any(|(n, _)| n == &matched) {
                deps.push((matched, DepType::NpmWorkspace));
            }
            continue;
        }
        // Try scoped npm packages like @kinlab/contracts
        if let Some(_matched) = match_scoped_npm_to_repo(dep_name, known_ids) {
            if !deps.iter().any(|(n, _)| n == dep_name) {
                deps.push((dep_name.clone(), DepType::NpmWorkspace));
            }
        }
    }

    deps.sort_by(|a, b| a.0.cmp(&b.0));
    deps.dedup_by(|a, b| a.0 == b.0);
    deps
}

/// Format deps as a short suffix string for registry display, e.g. "-> kin-db, kin-vfs-core"
pub fn format_deps_short(deps: &[(String, DepType)]) -> String {
    if deps.is_empty() {
        "(no deps)".to_string()
    } else {
        let names: Vec<&str> = deps.iter().map(|(n, _)| n.as_str()).collect();
        format!("-> {}", names.join(", "))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DepType {
    CargoGit,
    NpmWorkspace,
}

impl std::fmt::Display for DepType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DepType::CargoGit => write!(f, "cargo: git dep"),
            DepType::NpmWorkspace => write!(f, "npm: workspace"),
        }
    }
}

/// Parse Cargo.toml files in the repo and find dependencies with `git = "..."`.
fn detect_cargo_git_deps(repo_path: &Path) -> Vec<String> {
    let mut deps = Vec::new();

    // Check root Cargo.toml
    let cargo_path = repo_path.join("Cargo.toml");
    if let Ok(content) = std::fs::read_to_string(&cargo_path) {
        collect_cargo_external_deps(&content, &mut deps);
    }

    // Check workspace member Cargo.toml files
    let crates_dir = repo_path.join("crates");
    if crates_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&crates_dir) {
            for entry in entries.flatten() {
                let member_cargo = entry.path().join("Cargo.toml");
                if member_cargo.is_file() {
                    if let Ok(content) = std::fs::read_to_string(&member_cargo) {
                        collect_cargo_external_deps(&content, &mut deps);
                    }
                }
            }
        }
    }

    deps.sort();
    deps.dedup();
    deps
}

/// Extract dependency names that use `git = "..."` (cross-repo deps).
fn collect_cargo_external_deps(content: &str, deps: &mut Vec<String>) {
    let mut in_deps_section = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // Track section headers
        if trimmed.starts_with('[') {
            in_deps_section = trimmed.starts_with("[dependencies")
                || trimmed.starts_with("[dev-dependencies")
                || trimmed.starts_with("[build-dependencies")
                || trimmed.starts_with("[workspace.dependencies");
            continue;
        }

        if !in_deps_section {
            continue;
        }

        // Check for inline git deps: `name = { git = "..." }`
        if trimmed.contains("git =") || trimmed.contains("git=") {
            if let Some(dep_name) = trimmed.split('=').next() {
                let name = dep_name.trim().trim_matches('"');
                if !name.is_empty() && !name.contains(' ') {
                    deps.push(name.to_string());
                }
            }
        }
    }
}

/// Detect npm workspace / linked dependencies from package.json.
fn detect_npm_workspace_deps(repo_path: &Path) -> Vec<String> {
    let mut deps = Vec::new();

    let pkg_path = repo_path.join("package.json");
    if !pkg_path.is_file() {
        return deps;
    }

    let content = match std::fs::read_to_string(&pkg_path) {
        Ok(c) => c,
        Err(_) => return deps,
    };

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return deps,
    };

    // Check dependencies, devDependencies for workspace: references
    for section in ["dependencies", "devDependencies"] {
        if let Some(obj) = json.get(section).and_then(|v| v.as_object()) {
            for (name, version) in obj {
                let ver_str = version.as_str().unwrap_or("");
                if ver_str.starts_with("workspace:")
                    || ver_str.starts_with("link:")
                    || ver_str.starts_with("file:")
                {
                    deps.push(name.clone());
                }
            }
        }
    }

    deps
}

/// Try to match a dependency name to a known registered repo ID.
fn match_to_known_repo(dep_name: &str, known_ids: &HashSet<String>) -> Option<String> {
    // Exact match
    if known_ids.contains(dep_name) {
        return Some(dep_name.to_string());
    }

    // Try matching crate name to repo (e.g., "kin-vfs-core" crate from "kin-vfs" repo)
    for id in known_ids {
        if dep_name.starts_with(id.as_str()) {
            let rest = &dep_name[id.len()..];
            if rest.is_empty() || rest.starts_with('-') {
                return Some(id.clone());
            }
        }
    }

    None
}

/// Try to match a scoped npm package like `@kinlab/contracts` to a known repo.
fn match_scoped_npm_to_repo(dep_name: &str, known_ids: &HashSet<String>) -> Option<String> {
    if let Some(scoped) = dep_name.strip_prefix('@') {
        if let Some(scope) = scoped.split('/').next() {
            if known_ids.contains(scope) {
                return Some(scope.to_string());
            }
        }
    }
    None
}
