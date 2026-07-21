// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_core::registry::{KinRegistry, RegisteredRepo};
use std::collections::{BTreeMap, HashSet};

/// Show cross-repo dependencies across all registered Kin repositories.
///
/// The answer is projected from the dependency records ingestion wrote for each
/// repo, not re-derived by parsing manifests at query time. A repo that carries
/// no records reports that gap rather than having it filled in from whatever
/// manifests happen to be on disk.
pub async fn run() -> Result<()> {
    let registry =
        KinRegistry::load().map_err(|e| anyhow::anyhow!("failed to load registry: {}", e))?;

    if registry.repos.is_empty() {
        println!("No registered repositories.");
        println!("hint: run `kin init` in a directory to register it");
        return Ok(());
    }

    let known_ids: HashSet<String> = registry.repos.iter().map(|r| r.id.clone()).collect();

    let mut repo_deps: BTreeMap<String, Vec<(String, DepType)>> = BTreeMap::new();
    for repo in &registry.repos {
        repo_deps.insert(repo.id.clone(), dependencies_for_repo(repo, &known_ids));
    }

    println!("Cross-repo dependencies:\n");
    let mut unrecorded = Vec::new();
    for (id, deps) in &repo_deps {
        println!("  {}", id);
        if deps.is_empty() {
            println!("    (no cross-repo dependencies recorded)");
            unrecorded.push(id.clone());
        } else {
            for (name, dep_type) in deps {
                println!("    -> {} ({})", name, dep_type);
            }
        }
        println!();
    }

    if !unrecorded.is_empty() {
        println!(
            "note: dependencies are recorded when a repo is registered or re-indexed. If a repo above should have dependencies, re-run `kin init` in it to refresh its records: {}",
            unrecorded.join(", ")
        );
    }

    Ok(())
}

/// Project a registered repo's recorded cross-repo dependencies.
///
/// [`RegisteredRepo::dependencies`] is written by the registry at ingestion, so
/// this is a read of recorded truth. Only dependencies that ingestion resolved
/// to a repo still present in `known_ids` are reported, so the listing never
/// names a provider the registry no longer knows.
pub fn dependencies_for_repo(
    repo: &RegisteredRepo,
    known_ids: &HashSet<String>,
) -> Vec<(String, DepType)> {
    let mut deps: Vec<(String, DepType)> = repo
        .dependencies
        .iter()
        .filter_map(|dep| {
            let provider = dep.provider_repo.as_ref()?;
            known_ids
                .contains(provider)
                .then(|| (provider.clone(), DepType::from_source(&dep.source)))
        })
        .collect();

    deps.sort();
    deps.dedup();
    deps
}

/// Recorded dependencies for the repo registered at `repo_path`.
///
/// Kept for callers that hold a path rather than the registry record; prefer
/// [`dependencies_for_repo`] when the record is already in hand, since this
/// re-reads the registry to find it.
pub fn detect_dependencies_for_repo(
    repo_path: &std::path::Path,
    known_ids: &HashSet<String>,
) -> Vec<(String, DepType)> {
    let registry = match KinRegistry::load() {
        Ok(registry) => registry,
        Err(error) => {
            tracing::warn!(
                path = %repo_path.display(),
                error = %error.to_string(),
                "registry unreadable; reporting no recorded dependencies"
            );
            return Vec::new();
        }
    };
    registry
        .repos
        .iter()
        .find(|repo| repo.path.as_path() == repo_path)
        .map(|repo| dependencies_for_repo(repo, known_ids))
        .unwrap_or_default()
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

/// Where ingestion observed a dependency.
///
/// Carries the recorded source verbatim so the projection reports what was
/// actually captured rather than collapsing every dependency into one of a
/// couple of guessed manifest kinds.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DepType(String);

impl DepType {
    fn from_source(source: &str) -> Self {
        Self(source.to_string())
    }
}

impl std::fmt::Display for DepType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self.0.as_str() {
            "cargo" => "cargo manifest",
            "npm" => "npm manifest",
            "go" => "go module",
            "protocol" => "protocol import",
            "dockerfile" => "dockerfile",
            "compose" => "docker compose",
            "ci" => "ci workflow",
            "subprocess" => "runtime subprocess",
            "http" => "http api",
            other => other,
        };
        write!(f, "{label}")
    }
}

#[cfg(test)]
mod tests {
    use super::{dependencies_for_repo, DepType};
    use kin_core::dependencies::RepoDependency;
    use kin_core::registry::RegisteredRepo;
    use std::collections::HashSet;

    fn repo(path: std::path::PathBuf, dependencies: Vec<RepoDependency>) -> RegisteredRepo {
        RegisteredRepo {
            id: "kin".to_string(),
            path,
            entities: 0,
            last_commit: "2026-01-01T00:00:00Z".to_string(),
            dependencies,
        }
    }

    fn dep(name: &str, provider: &str, source: &str) -> RepoDependency {
        RepoDependency {
            name: name.to_string(),
            provider_repo: Some(provider.to_string()),
            source: source.to_string(),
        }
    }

    /// `kin deps` answers from the dependency records ingestion wrote, so a
    /// manifest sitting in the working tree cannot steer the answer. The
    /// manifest here contradicts the records on purpose: anything that re-derives
    /// the answer by parsing it reports kin-vfs and fails.
    #[test]
    fn deps_project_recorded_truth_not_the_manifest_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[dependencies]\nkin-vfs = { git = \"git@example.invalid:kin-vfs.git\" }\n",
        )
        .unwrap();

        let repo = repo(
            dir.path().to_path_buf(),
            vec![dep("kin-db", "kin-db", "cargo")],
        );
        let known: HashSet<String> = ["kin-db", "kin-vfs"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        assert_eq!(
            dependencies_for_repo(&repo, &known),
            vec![("kin-db".to_string(), DepType("cargo".to_string()))],
        );
    }

    /// A repo with no recorded dependencies reports none — the gap is surfaced
    /// rather than filled in from the manifests lying next to it.
    #[test]
    fn deps_report_the_gap_rather_than_scraping_manifests() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[dependencies]\nkin-db = { git = \"git@example.invalid:kin-db.git\" }\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            "{\"dependencies\":{\"@kinlab/contracts\":\"workspace:*\"}}",
        )
        .unwrap();

        let repo = repo(dir.path().to_path_buf(), Vec::new());
        let known: HashSet<String> = ["kin-db", "kinlab"].iter().map(|s| s.to_string()).collect();

        assert!(dependencies_for_repo(&repo, &known).is_empty());
    }

    /// A recorded provider the registry no longer knows is dropped rather than
    /// listed as a live cross-repo edge.
    #[test]
    fn deps_drop_providers_the_registry_no_longer_knows() {
        let dir = tempfile::tempdir().unwrap();
        let repo = repo(
            dir.path().to_path_buf(),
            vec![
                dep("kin-db", "kin-db", "cargo"),
                dep("retired-crate", "retired-repo", "cargo"),
            ],
        );
        let known: HashSet<String> = ["kin-db"].iter().map(|s| s.to_string()).collect();

        assert_eq!(
            dependencies_for_repo(&repo, &known),
            vec![("kin-db".to_string(), DepType("cargo".to_string()))],
        );
    }

    /// Every recorded source family renders with a label, including ones the
    /// retired two-variant enum could not express.
    #[test]
    fn dep_type_labels_every_recorded_source() {
        for (source, label) in [
            ("cargo", "cargo manifest"),
            ("npm", "npm manifest"),
            ("go", "go module"),
            ("protocol", "protocol import"),
            ("dockerfile", "dockerfile"),
            ("compose", "docker compose"),
            ("ci", "ci workflow"),
            ("subprocess", "runtime subprocess"),
            ("http", "http api"),
        ] {
            assert_eq!(DepType::from_source(source).to_string(), label);
        }
        assert_eq!(DepType::from_source("future").to_string(), "future");
    }
}
