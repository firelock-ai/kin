// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_core::registry::{KinRegistry, RegisteredRepo};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};

pub const DEPS_SCHEMA: &str = "kin.deps.v1";

/// One direction of one repository's recorded cross-repo edges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyEdge {
    pub repo_id: String,
    pub source: String,
}

/// The cross-repo neighbourhood of one registered repository.
///
/// `depends_on` is what this repository's own records name as providers.
/// `consumers` is the inverse: every registered repository whose records name
/// this one as a provider. Both come from records ingestion wrote, so the
/// inverse direction is recorded truth rather than a re-derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RepoDependencyView {
    pub schema: String,
    pub repo_id: String,
    pub depends_on: Vec<DependencyEdge>,
    pub consumers: Vec<DependencyEdge>,
}

/// Show the cross-repo dependencies of the repository the caller is in.
///
/// The answer is projected from the dependency records ingestion wrote, not
/// re-derived by parsing manifests at query time. A repo that carries no
/// records reports that gap rather than having it filled in from whatever
/// manifests happen to be on disk.
///
/// The default scope is one repository because that is the question a caller
/// standing in a repository is asking. `--all` keeps the fleet-wide listing,
/// which on a host with many registered repositories is thousands of lines and
/// buries the caller's own repository in them.
pub async fn run(all: bool, json: bool) -> Result<()> {
    let registry =
        KinRegistry::load().map_err(|e| anyhow::anyhow!("failed to load registry: {}", e))?;

    if all {
        return report_every_registered_repo(&registry, json);
    }

    let layout = crate::commands::require_repository_layout()?;
    let repo_id = registered_id_for_path(&registry, layout.working_dir())?;
    let view = repo_dependency_view(&registry, repo_id)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&view)?);
        return Ok(());
    }
    for line in render_repo_view_lines(&view) {
        println!("{line}");
    }
    Ok(())
}

/// Resolve the registry entry for the repository the caller is standing in.
///
/// Registration names an entry after the repository's directory, not after the
/// manifest's repository id, and one host routinely carries several checkouts
/// sharing a directory name. The recorded path is the only field that
/// identifies an entry unambiguously, so that is what this matches on. A miss
/// refuses and says which path it looked for rather than falling back to a
/// same-named entry that describes some other checkout.
pub fn registered_id_for_path<'a>(
    registry: &'a KinRegistry,
    working_dir: &std::path::Path,
) -> Result<&'a str> {
    let matches: Vec<&RegisteredRepo> = registry
        .repos
        .iter()
        .filter(|repo| repo.path == working_dir)
        .collect();

    match matches.as_slice() {
        [only] => Ok(only.id.as_str()),
        [] => {
            let same_name = working_dir
                .file_name()
                .map(|name| {
                    registry
                        .repos
                        .iter()
                        .filter(|repo| repo.path.file_name() == Some(name))
                        .count()
                })
                .unwrap_or(0);
            let named = if same_name > 0 {
                format!(
                    " The registry holds {same_name} entry(s) with the same directory name \
                     recorded at other paths, which describe other checkouts and not this one."
                )
            } else {
                String::new()
            };
            anyhow::bail!(
                "no registry entry records the repository at {};{named} `kin init` registers a \
                 repository when it runs, so this one either predates that registration or was \
                 never initialized with `kin init` here; `kin registry` only lists and cleans \
                 rather than adding an entry after the fact. Use `kin deps --all` to list the \
                 repositories that are registered",
                working_dir.display()
            )
        }
        several => anyhow::bail!(
            "{} registry entries record the repository at {} ({}); refusing to pick one, run \
             `kin registry clean` and re-register it",
            several.len(),
            working_dir.display(),
            several
                .iter()
                .map(|repo| repo.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Build the recorded cross-repo neighbourhood of `repo_id`.
///
/// Refuses rather than reporting an empty neighbourhood when the registry has
/// no record for `repo_id`: an unregistered repository has no recorded edges at
/// all, and printing "no dependencies" for it would read as a proved absence.
pub fn repo_dependency_view(registry: &KinRegistry, repo_id: &str) -> Result<RepoDependencyView> {
    let known_ids: HashSet<String> = registry.repos.iter().map(|r| r.id.clone()).collect();
    let selected = registry
        .repos
        .iter()
        .find(|repo| repo.id == repo_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository '{repo_id}' is not in the Kin registry, so no cross-repo dependency \
                 records exist for it. `kin init` registers a repository when it runs; this one \
                 either predates that registration or was never initialized with `kin init` \
                 here, and `kin registry` only lists and cleans rather than adding an entry \
                 after the fact. Use `kin deps --all` to list the repositories that are \
                 registered"
            )
        })?;

    let depends_on = dependencies_for_repo(selected, &known_ids)
        .into_iter()
        .map(|(repo_id, dep_type)| DependencyEdge {
            repo_id,
            source: dep_type.0,
        })
        .collect();

    let mut consumers: Vec<DependencyEdge> = registry
        .repos
        .iter()
        .filter(|candidate| candidate.id != repo_id)
        .flat_map(|candidate| {
            candidate.dependencies.iter().filter_map(move |dep| {
                (dep.provider_repo.as_deref() == Some(repo_id)).then(|| DependencyEdge {
                    repo_id: candidate.id.clone(),
                    source: dep.source.clone(),
                })
            })
        })
        .collect();
    consumers.sort_by(|a, b| (&a.repo_id, &a.source).cmp(&(&b.repo_id, &b.source)));
    consumers.dedup();

    Ok(RepoDependencyView {
        schema: DEPS_SCHEMA.to_string(),
        repo_id: repo_id.to_string(),
        depends_on,
        consumers,
    })
}

/// Render one repository's neighbourhood, saying plainly that an empty
/// direction may be unrecorded rather than letting it read as a proved absence.
pub fn render_repo_view_lines(view: &RepoDependencyView) -> Vec<String> {
    let mut lines = vec![
        format!("Cross-repo dependencies for {}:", view.repo_id),
        String::new(),
    ];

    lines.push(format!("  depends on ({}):", view.depends_on.len()));
    if view.depends_on.is_empty() {
        lines.push("    (no cross-repo dependencies recorded)".to_string());
    } else {
        for edge in &view.depends_on {
            lines.push(format!(
                "    -> {} ({})",
                edge.repo_id,
                DepType::from_source(&edge.source)
            ));
        }
    }
    lines.push(String::new());

    lines.push(format!("  consumed by ({}):", view.consumers.len()));
    if view.consumers.is_empty() {
        lines.push("    (no registered repository records this one as a provider)".to_string());
    } else {
        for edge in &view.consumers {
            lines.push(format!(
                "    <- {} ({})",
                edge.repo_id,
                DepType::from_source(&edge.source)
            ));
        }
    }

    if view.depends_on.is_empty() || view.consumers.is_empty() {
        lines.push(String::new());
        lines.push(
            "note: dependency records are written when `kin init` registers a repository, so \
             empty directions here may mean this repository predates that registration rather \
             than that none exist."
                .to_string(),
        );
    }
    lines.push("Use `kin deps --all` for every registered repository.".to_string());
    lines
}

fn report_every_registered_repo(registry: &KinRegistry, json: bool) -> Result<()> {
    if registry.repos.is_empty() {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema": DEPS_SCHEMA,
                    "repositories": [],
                }))?
            );
        } else {
            println!("No registered repositories.");
            println!(
                "hint: `kin init` registers a repository when it runs; a repository \
                 initialized before this build predates that and has no entry"
            );
        }
        return Ok(());
    }

    let known_ids: HashSet<String> = registry.repos.iter().map(|r| r.id.clone()).collect();

    let mut repo_deps: BTreeMap<String, Vec<(String, DepType)>> = BTreeMap::new();
    for repo in &registry.repos {
        repo_deps.insert(repo.id.clone(), dependencies_for_repo(repo, &known_ids));
    }

    if json {
        let repositories: Vec<serde_json::Value> = repo_deps
            .iter()
            .map(|(id, deps)| {
                serde_json::json!({
                    "repo_id": id,
                    "depends_on": deps
                        .iter()
                        .map(|(repo_id, dep_type)| serde_json::json!({
                            "repo_id": repo_id,
                            "source": dep_type.0,
                        }))
                        .collect::<Vec<_>>(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": DEPS_SCHEMA,
                "repositories": repositories,
            }))?
        );
        return Ok(());
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
            "note: dependency records are written when `kin init` registers a repository, so a \
             repository initialized before this build may show no records rather than no \
             dependencies: {}",
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
    use super::{
        dependencies_for_repo, registered_id_for_path, render_repo_view_lines,
        repo_dependency_view, DepType, DEPS_SCHEMA,
    };
    use kin_core::dependencies::RepoDependency;
    use kin_core::registry::{KinRegistry, RegisteredRepo};
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

    fn named_repo(id: &str, dependencies: Vec<RepoDependency>) -> RegisteredRepo {
        RegisteredRepo {
            id: id.to_string(),
            path: std::path::PathBuf::from(format!("/registered/{id}")),
            entities: 0,
            last_commit: "2026-01-01T00:00:00Z".to_string(),
            dependencies,
        }
    }

    /// A registry carrying the selected repository plus noise: the transient
    /// entries a test host accumulates are exactly what makes the fleet-wide
    /// listing unreadable, so the scoped answer must not contain them.
    fn registry_with_noise() -> KinRegistry {
        let mut registry = KinRegistry::default();
        registry.repos = vec![
            named_repo("kin", vec![dep("kin-db", "kin-db", "cargo")]),
            named_repo("kin-db", Vec::new()),
            named_repo("kin-vfs", vec![dep("kin", "kin", "cargo")]),
            named_repo("kin-bench", vec![dep("kin", "kin", "subprocess")]),
            named_repo(".tmp00M8wK", vec![dep("kin", "kin", "cargo")]),
        ];
        registry
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

    /// The scoped answer names only the caller's own recorded edges. The four
    /// unrelated registry entries, including the transient one, are absent: a
    /// caller standing in `kin` asked about `kin`.
    #[test]
    fn scoped_view_reports_one_repository_in_both_directions() {
        let view = repo_dependency_view(&registry_with_noise(), "kin").unwrap();

        assert_eq!(view.schema, DEPS_SCHEMA);
        assert_eq!(view.repo_id, "kin");
        assert_eq!(
            view.depends_on
                .iter()
                .map(|edge| edge.repo_id.as_str())
                .collect::<Vec<_>>(),
            vec!["kin-db"]
        );
        assert_eq!(
            view.consumers
                .iter()
                .map(|edge| (edge.repo_id.as_str(), edge.source.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (".tmp00M8wK", "cargo"),
                ("kin-bench", "subprocess"),
                ("kin-vfs", "cargo"),
            ],
            "consumers are the registered repositories recording this one as a provider"
        );

        let rendered = render_repo_view_lines(&view).join("\n");
        assert!(rendered.contains("Cross-repo dependencies for kin:"));
        assert!(rendered.contains("kin deps --all"));
        assert!(
            !rendered.contains("kin-db\n  "),
            "the fleet listing's per-repo headings must not appear in a scoped answer"
        );
    }

    /// Falsification: were the scope wired to the registry rather than to the
    /// caller, this would return `kin`'s neighbourhood for `kin-db`.
    #[test]
    fn scoped_view_follows_the_named_repository_not_the_registry_order() {
        let view = repo_dependency_view(&registry_with_noise(), "kin-db").unwrap();

        assert!(
            view.depends_on.is_empty(),
            "kin-db records no providers: {:?}",
            view.depends_on
        );
        assert_eq!(
            view.consumers
                .iter()
                .map(|edge| edge.repo_id.as_str())
                .collect::<Vec<_>>(),
            vec!["kin"]
        );
    }

    /// An unregistered repository has no records at all. Reporting an empty
    /// neighbourhood would read as a proved absence, so it refuses and states
    /// the true state: nothing ships that would register it.
    #[test]
    fn an_unregistered_repository_refuses_rather_than_reporting_no_dependencies() {
        let error = repo_dependency_view(&registry_with_noise(), "not-registered")
            .expect_err("an unregistered repository must not report an empty neighbourhood");
        let message = error.to_string();

        assert!(message.contains("not in the Kin registry"), "{message}");
        assert!(
            message.contains("kin init") && message.contains("registers a repository"),
            "the refusal must explain that registration comes from `kin init`: {message}"
        );
        assert!(
            message.contains("kin registry") && message.contains("only lists and cleans"),
            "the refusal must still say `kin registry` cannot add an entry after the fact: {message}"
        );
        assert!(message.contains("kin deps --all"), "{message}");
    }

    /// Registration names an entry after the repository's directory, so the
    /// path is what identifies it. Falsification: the entry chosen here is not
    /// the one whose directory name matches, which is what a name-keyed lookup
    /// would have returned.
    #[test]
    fn the_caller_resolves_to_the_entry_recording_its_own_path() {
        let mut registry = KinRegistry::default();
        registry.repos = vec![
            named_repo("kin", Vec::new()),
            RegisteredRepo {
                id: "kin-checkout-two".to_string(),
                path: std::path::PathBuf::from("/elsewhere/kin"),
                entities: 0,
                last_commit: "2026-01-01T00:00:00Z".to_string(),
                dependencies: Vec::new(),
            },
        ];

        assert_eq!(
            registered_id_for_path(&registry, std::path::Path::new("/elsewhere/kin")).unwrap(),
            "kin-checkout-two"
        );
        assert_eq!(
            registered_id_for_path(&registry, std::path::Path::new("/registered/kin")).unwrap(),
            "kin"
        );
    }

    /// An unregistered checkout that shares a name with a registered one must
    /// refuse rather than answer about the other checkout, and must say the
    /// same-named entries exist so the miss is not mistaken for a typo.
    #[test]
    fn a_same_named_checkout_elsewhere_never_answers_for_this_one() {
        let mut registry = KinRegistry::default();
        registry.repos = vec![named_repo("kin", vec![dep("kin-db", "kin-db", "cargo")])];

        let error = registered_id_for_path(&registry, std::path::Path::new("/other/place/kin"))
            .expect_err("an unregistered checkout must not borrow another's records");
        let message = error.to_string();

        assert!(message.contains("/other/place/kin"), "{message}");
        assert!(message.contains("same directory name"), "{message}");
        assert!(
            message.contains("kin init") && message.contains("registers a repository"),
            "the refusal must explain that registration comes from `kin init`: {message}"
        );
        assert!(
            message.contains("kin registry") && message.contains("only lists and cleans"),
            "the refusal must still say `kin registry` cannot add an entry after the fact: {message}"
        );
        assert!(message.contains("kin deps --all"), "{message}");
    }

    /// Two entries recording one path is a corrupted registry, not a choice to
    /// make silently.
    #[test]
    fn duplicate_entries_for_one_path_are_refused() {
        let mut registry = KinRegistry::default();
        registry.repos = vec![named_repo("kin", Vec::new()), named_repo("kin", Vec::new())];
        registry.repos[1].id = "kin-duplicate".to_string();

        let error = registered_id_for_path(&registry, std::path::Path::new("/registered/kin"))
            .expect_err("a duplicated path must be refused");

        assert!(
            error.to_string().contains("refusing to pick one"),
            "{error}"
        );
        assert!(error.to_string().contains("kin registry clean"), "{error}");
    }

    /// Both empty directions still say why they are empty, so "no edges" is
    /// never mistaken for "records exist and prove there are none".
    #[test]
    fn empty_directions_read_as_possibly_unrecorded_not_proved_absent() {
        let mut registry = KinRegistry::default();
        registry.repos = vec![named_repo("solo", Vec::new())];

        let view = repo_dependency_view(&registry, "solo").unwrap();
        let rendered = render_repo_view_lines(&view).join("\n");

        assert!(rendered.contains("no cross-repo dependencies recorded"));
        assert!(rendered.contains("no registered repository records this one as a provider"));
        assert!(rendered.contains("kin init") && rendered.contains("registers a repository"));
    }
}
