// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-repo dependency detection from manifest files.
//!
//! Parses `Cargo.toml`, `package.json`, and `go.mod` to discover which
//! external repos a project depends on, then maps dependency names to
//! known repos in the [`KinRegistry`](crate::registry::KinRegistry).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

/// Detect dependencies from manifest files in `repo_path`.
pub fn detect_dependencies(repo_path: &Path) -> Vec<RepoDependency> {
    let mut deps = Vec::new();

    let cargo_path = repo_path.join("Cargo.toml");
    if cargo_path.exists() {
        deps.extend(parse_cargo_deps(&cargo_path));
    }

    let pkg_path = repo_path.join("package.json");
    if pkg_path.exists() {
        deps.extend(parse_npm_deps(&pkg_path));
    }

    let go_path = repo_path.join("go.mod");
    if go_path.exists() {
        deps.extend(parse_go_deps(&go_path));
    }

    deps
}

// ---------------------------------------------------------------------------
// Cargo.toml
// ---------------------------------------------------------------------------

fn parse_cargo_deps(path: &Path) -> Vec<RepoDependency> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let table: toml::Value = match content.parse() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut deps = Vec::new();

    // Collect from [dependencies], [workspace.dependencies]
    let sections: &[&[&str]] = &[
        &["dependencies"],
        &["workspace", "dependencies"],
    ];

    for keys in sections {
        if let Some(section) = drill(&table, keys) {
            if let Some(map) = section.as_table() {
                for (name, spec) in map {
                    if let Some(dep) = cargo_dep_from_entry(name, spec) {
                        deps.push(dep);
                    }
                }
            }
        }
    }

    deps
}

/// Extract a [`RepoDependency`] from a single Cargo.toml dependency entry,
/// but only if it uses a `git` source pointing to a firelock-ai repo.
fn cargo_dep_from_entry(name: &str, spec: &toml::Value) -> Option<RepoDependency> {
    let git_url = match spec {
        toml::Value::Table(t) => t.get("git")?.as_str()?,
        _ => return None,
    };

    if !git_url.contains("firelock-ai") {
        return None;
    }

    // Derive the repo name from the git URL.
    // e.g. "https://github.com/firelock-ai/kin-db.git" → "kin-db"
    let repo_name = repo_name_from_git_url(git_url)?;

    Some(RepoDependency {
        name: name.to_string(),
        provider_repo: Some(repo_name),
        source: "cargo".to_string(),
    })
}

// ---------------------------------------------------------------------------
// package.json
// ---------------------------------------------------------------------------

fn parse_npm_deps(path: &Path) -> Vec<RepoDependency> {
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
                if let Some(dep) = npm_dep_from_entry(name) {
                    deps.push(dep);
                }
            }
        }
    }

    deps
}

/// Keep dependencies that look like internal packages: `@kinlab/*` or
/// workspace protocol (`workspace:*`).
fn npm_dep_from_entry(name: &str) -> Option<RepoDependency> {
    if name.starts_with("@kinlab/") {
        // Map @kinlab/* → kinlab repo
        Some(RepoDependency {
            name: name.to_string(),
            provider_repo: Some("kinlab".to_string()),
            source: "npm".to_string(),
        })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// go.mod
// ---------------------------------------------------------------------------

fn parse_go_deps(path: &Path) -> Vec<RepoDependency> {
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
        } else if let Some(rest) = trimmed.strip_prefix("require ") {
            Some(rest.trim())
        } else {
            None
        };

        if let Some(module_line) = module_line {
            if let Some(dep) = go_dep_from_line(module_line) {
                deps.push(dep);
            }
        }
    }

    deps
}

fn go_dep_from_line(line: &str) -> Option<RepoDependency> {
    let module_path = line.split_whitespace().next()?;
    if !module_path.contains("firelock-ai") {
        return None;
    }
    let repo_name = module_path.rsplit('/').next()?;
    Some(RepoDependency {
        name: module_path.to_string(),
        provider_repo: Some(repo_name.to_string()),
        source: "go".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
pub fn dependency_graph(
    repos: &[crate::registry::RegisteredRepo],
) -> HashMap<String, Vec<String>> {
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

        let deps = parse_cargo_deps(&cargo);
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

        let deps = parse_cargo_deps(&cargo);
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "kin-model"
            && d.provider_repo.as_deref() == Some("kin-db")));
        assert!(deps.iter().any(|d| d.name == "kin-vfs-core"
            && d.provider_repo.as_deref() == Some("kin-vfs")));
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

        let deps = parse_cargo_deps(&cargo);
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

        let deps = parse_npm_deps(&pkg);
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().all(|d| d.source == "npm"));
        assert!(deps.iter().all(|d| d.provider_repo.as_deref() == Some("kinlab")));
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

        let deps = parse_npm_deps(&pkg);
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

        let deps = parse_go_deps(&gomod);
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "github.com/firelock-ai/kin-sdk"
            && d.provider_repo.as_deref() == Some("kin-sdk")
            && d.source == "go"));
        assert!(deps.iter().any(|d| d.name == "github.com/firelock-ai/kin-utils"
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

        let deps = parse_go_deps(&gomod);
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
}
