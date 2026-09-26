// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! rust-analyzer LSP adapter.
//!
//! rust-analyzer loads the Cargo projects it is told about and, when told about
//! none, only those it finds at the root and one level below. A repository with
//! more than one Cargo workspace loses every workspace it does not find: axum
//! keeps its examples in a `[workspace]` of their own, and none of their calls
//! had an answer. So every Cargo workspace root, and every package that belongs
//! to no workspace, is passed as `linkedProjects`.
//!
//! Code behind a non-default feature is also code rust-analyzer never loads, so
//! the workspace is loaded with every feature enabled. When that load fails
//! because of a feature, the server is started again with the default features.
//!
//! Build scripts and procedural macros stay off. Both run code from the
//! repository, and turning them on needs a sandbox decision this adapter does
//! not make.
//!
//! The environment follows the contract: the user's Cargo home when it holds
//! every crate `Cargo.lock` pins, else Kin's analysis environment, the same
//! crates fetched and verified against the lock (see
//! [`crate::analysis_env::rust`]), else none, when rust-analyzer loads the
//! workspace without its dependencies (`cargo.noDeps`) rather than letting
//! Cargo fetch them. Whichever serves, rust-analyzer runs with
//! `CARGO_NET_OFFLINE=true` and `RUSTUP_AUTO_INSTALL=0`: Cargo never fetches
//! and rustup never installs a toolchain.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use kin_model::LanguageId;

use super::contract::{
    self, DependencySource, Environment, EnvironmentBasis, ProjectModel, ProjectPackage, Provider,
    ProvisionReport, Selection, Toolchain,
};
use super::repo_scan;
use super::{LoadCheck, LspAdapter, ServerLaunch};
use crate::analysis_env::{self, rust as analysis};

pub struct RustAnalyzerAdapter;

/// The most projects linked at once. A tree with more Cargo workspaces than
/// this keeps the shallowest; rust-analyzer loads each one in full.
const MAX_LINKED_PROJECTS: usize = 64;

/// Directory names under which a manifest is a test input rather than a
/// project: a fixture crate for a test to build, not code the repository runs.
const FIXTURE_DIRS: &[&str] = &[
    "tests",
    "test",
    "testdata",
    "test-data",
    "test_data",
    "fixtures",
    "fixture",
    "test-fixtures",
];

/// The Cargo projects of one repository, as rust-analyzer should load them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CargoLayout {
    /// Every workspace root, and every package in no workspace, as the
    /// manifest paths rust-analyzer takes in `linkedProjects`. The repository
    /// root's own manifest, when there is one, comes first.
    pub linked_projects: Vec<PathBuf>,
    /// Files a trybuild test compiles one at a time. No Cargo target compiles
    /// them, so no rust-analyzer configuration loads them.
    pub trybuild_inputs: Vec<PathBuf>,
    /// Every package the linked projects hold, fixtures and vendored crates
    /// aside.
    pub packages: Vec<ProjectPackage>,
    /// Each package's name, mapped to its library root, or its binary root
    /// when it has no library.
    pub workspace_map: std::collections::BTreeMap<String, PathBuf>,
}

/// One parsed `Cargo.toml`.
struct Manifest {
    path: PathBuf,
    dir: PathBuf,
    workspace: Option<WorkspaceTable>,
    is_package: bool,
    /// `package.name`.
    package_name: Option<String>,
    /// `lib.path`, relative to the manifest's directory.
    lib_path: Option<String>,
    /// `package.workspace` names its root explicitly.
    names_its_workspace: bool,
    uses_trybuild: bool,
}

struct WorkspaceTable {
    members: Vec<String>,
    exclude: Vec<String>,
}

impl WorkspaceTable {
    /// Cargo's own test (`WorkspaceRootConfig::is_excluded`): a path under an
    /// `exclude` entry is outside the workspace unless a `members` entry names
    /// it, both compared as literal path prefixes.
    fn excludes(&self, root_dir: &Path, manifest_dir: &Path) -> bool {
        let under = |entries: &[String]| {
            entries
                .iter()
                .any(|entry| manifest_dir.starts_with(root_dir.join(entry)))
        };
        under(&self.exclude) && !under(&self.members)
    }
}

fn string_list(table: &toml::Table, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn read_manifest(path: &Path) -> Option<Manifest> {
    let text = std::fs::read_to_string(path).ok()?;
    let table: toml::Table = toml::from_str(&text).ok()?;
    let workspace = table
        .get("workspace")
        .and_then(toml::Value::as_table)
        .map(|workspace| WorkspaceTable {
            members: string_list(workspace, "members"),
            exclude: string_list(workspace, "exclude"),
        });
    let package = table.get("package").and_then(toml::Value::as_table);
    let depends_on_trybuild = ["dependencies", "dev-dependencies"].iter().any(|section| {
        table
            .get(*section)
            .and_then(toml::Value::as_table)
            .is_some_and(|deps| deps.contains_key("trybuild"))
    });
    Some(Manifest {
        path: path.to_path_buf(),
        dir: path.parent()?.to_path_buf(),
        workspace,
        is_package: package.is_some(),
        package_name: package
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
            .map(str::to_string),
        lib_path: table
            .get("lib")
            .and_then(|lib| lib.get("path"))
            .and_then(toml::Value::as_str)
            .map(str::to_string),
        names_its_workspace: package.is_some_and(|package| package.contains_key("workspace")),
        uses_trybuild: depends_on_trybuild,
    })
}

/// Whether a manifest sits inside a test-input directory below `root`. The
/// manifest's own directory does not count: a crate named `tests` is a crate.
fn is_fixture(root: &Path, manifest_dir: &Path) -> bool {
    let Ok(relative) = manifest_dir.strip_prefix(root) else {
        return false;
    };
    let components: Vec<_> = relative.components().collect();
    components
        .iter()
        .take(components.len().saturating_sub(1))
        .any(|component| {
            component
                .as_os_str()
                .to_str()
                .is_some_and(|name| FIXTURE_DIRS.contains(&name))
        })
}

/// Read the repository's Cargo projects: which to link and which files no
/// build compiles.
pub fn cargo_layout(root: &Path) -> CargoLayout {
    let mut manifests = Vec::new();
    let mut rust_projects = Vec::new();
    repo_scan::walk_files(root, &|_, _| true, &mut |path, name| match name {
        "Cargo.toml" => manifests.push(path.to_path_buf()),
        "rust-project.json" => rust_projects.push(path.to_path_buf()),
        _ => {}
    });
    let manifests: Vec<Manifest> = manifests
        .iter()
        .filter_map(|path| read_manifest(path))
        // A vendored dependency carries Cargo's checksum file; it is a
        // dependency's source, loaded as a dependency, never a project.
        .filter(|manifest| !manifest.dir.join(".cargo-checksum.json").is_file())
        .collect();

    let workspace_roots: Vec<&Manifest> = manifests
        .iter()
        .filter(|manifest| manifest.workspace.is_some())
        .collect();
    let claimed = |manifest: &Manifest| {
        manifest.names_its_workspace
            || workspace_roots.iter().any(|root_manifest| {
                manifest.dir.starts_with(&root_manifest.dir)
                    && manifest.dir != root_manifest.dir
                    && !root_manifest
                        .workspace
                        .as_ref()
                        .is_some_and(|table| table.excludes(&root_manifest.dir, &manifest.dir))
            })
    };

    let mut linked: Vec<PathBuf> = manifests
        .iter()
        .filter(|manifest| !is_fixture(root, &manifest.dir))
        .filter(|manifest| {
            manifest.workspace.is_some() || (manifest.is_package && !claimed(manifest))
        })
        .map(|manifest| manifest.path.clone())
        .chain(
            rust_projects
                .into_iter()
                .filter(|path| path.parent().is_some_and(|dir| !is_fixture(root, dir))),
        )
        .collect();
    // Shallowest first, so the root's own manifest leads and a cap keeps the
    // projects nearest the root.
    linked.sort_by_key(|path| (path.components().count(), path.clone()));
    linked.truncate(MAX_LINKED_PROJECTS);

    let trybuild_inputs = manifests
        .iter()
        .filter(|manifest| manifest.uses_trybuild)
        .flat_map(|manifest| trybuild_inputs(&manifest.dir.join("tests")))
        .collect();

    let mut packages = Vec::new();
    let mut workspace_map = std::collections::BTreeMap::new();
    for manifest in manifests
        .iter()
        .filter(|manifest| manifest.is_package && !is_fixture(root, &manifest.dir))
    {
        let Some(name) = &manifest.package_name else {
            continue;
        };
        let src = manifest.dir.join("src");
        let entry = manifest
            .lib_path
            .as_ref()
            .map(|path| manifest.dir.join(path))
            .or_else(|| {
                ["src/lib.rs", "src/main.rs"]
                    .iter()
                    .map(|file| manifest.dir.join(file))
                    .find(|file| file.is_file())
            });
        if let Some(entry) = entry {
            workspace_map.entry(name.clone()).or_insert(entry);
        }
        packages.push(ProjectPackage {
            name: name.clone(),
            dir: manifest.dir.clone(),
            source_roots: vec![if src.is_dir() {
                src
            } else {
                manifest.dir.clone()
            }],
            config: None,
        });
    }

    CargoLayout {
        linked_projects: linked,
        trybuild_inputs,
        packages,
        workspace_map,
    }
}

/// The project model of a Cargo layout: the linked projects are its roots,
/// every feature is loaded, and trybuild cases are in no build.
pub fn project_model_for(layout: CargoLayout) -> ProjectModel {
    ProjectModel {
        roots: layout.linked_projects,
        packages: layout.packages,
        variants: contract::BuildVariants {
            features: Selection::All,
            ..Default::default()
        },
        workspace_map: layout.workspace_map,
        not_in_any_build: layout.trybuild_inputs,
        ..ProjectModel::default()
    }
}

/// What environment discovery reads from the host: its variables, the home
/// directory, Kin's cache, whether analysis environments are on, and the
/// target triple. Injected so every branch is testable.
#[derive(Debug, Clone)]
pub struct RustHost {
    pub vars: HashMap<String, String>,
    pub home: Option<PathBuf>,
    /// Kin's cache directory, `$KIN_HOME/cache`.
    pub cache: PathBuf,
    pub analysis_environments: bool,
    pub triple: Option<&'static str>,
}

impl RustHost {
    /// This process's host.
    pub fn current() -> Self {
        let vars: HashMap<String, String> = std::env::vars().collect();
        let home = vars.get("HOME").map(PathBuf::from);
        Self {
            vars,
            home,
            cache: analysis_env::kin_cache_dir(),
            analysis_environments: analysis_env::enabled(),
            triple: analysis::toolchain::host_triple(),
        }
    }

    fn analysis_host(&self) -> analysis::Host<'_> {
        analysis::Host {
            vars: &self.vars,
            home: self.home.as_deref(),
            cache: &self.cache,
            analysis_environments: self.analysis_environments,
            triple: self.triple,
        }
    }
}

/// The Cargo manifests a model links, which the locks sit beside.
fn manifests_of(model: &ProjectModel) -> Vec<PathBuf> {
    model
        .roots
        .iter()
        .filter(|root| root.file_name().is_some_and(|name| name == "Cargo.toml"))
        .cloned()
        .collect()
}

/// Every package manifest a model holds.
fn members_of(model: &ProjectModel) -> Vec<PathBuf> {
    model
        .packages
        .iter()
        .map(|package| package.dir.join("Cargo.toml"))
        .collect()
}

/// The environment rust-analyzer analyses the repository at `root` against,
/// from the first provider that has one. Nothing here touches the network;
/// what only a download can supply is left in [`Environment::pending`].
pub fn environment_with(root: &Path, model: &ProjectModel, host: &RustHost) -> Environment {
    let assessment = analysis::assess(
        root,
        &manifests_of(model),
        &members_of(model),
        &host.analysis_host(),
    );
    let locked = assessment.locked.registry.len();
    let lock = assessment.locked.files.first().cloned();
    let (toolchain, kin_std, std_pending) = match &assessment.std {
        analysis::StdSource::Installed { toolchain, library } => (
            Some(Toolchain {
                name: "rust".to_string(),
                version: toolchain.clone(),
                pinned_by: format!("{}; installed with rust-src", assessment.pinned_by),
                location: Some(library.clone()),
                substitute: None,
            }),
            false,
            None,
        ),
        analysis::StdSource::Kin {
            src,
            channel,
            library,
            substitute,
        } => (
            Some(Toolchain {
                name: "rust".to_string(),
                version: src
                    .as_ref()
                    .map_or_else(|| channel.clone(), |src| src.release.clone()),
                pinned_by: format!("{}; rust-src from Kin's store", assessment.pinned_by),
                location: library.clone(),
                substitute: substitute.clone(),
            }),
            true,
            library
                .is_none()
                .then(|| format!("fetch rust-src for {channel} from static.rust-lang.org")),
        ),
        analysis::StdSource::Discover => (
            Some(Toolchain {
                name: "rust".to_string(),
                version: "discovered".to_string(),
                pinned_by: assessment.pinned_by.clone(),
                location: None,
                substitute: None,
            }),
            false,
            None,
        ),
        analysis::StdSource::Missing(_) => (None, false, None),
    };
    let passed_over = assessment
        .passed_over
        .as_deref()
        .map(|reason| format!("; the user's Cargo home was passed over: {reason}"))
        .unwrap_or_default();
    let (dependency, provider, crates_pending) = match &assessment.dependencies {
        analysis::Dependencies::None => (
            None,
            if kin_std {
                Provider::KinAnalysisEnvironment {
                    description: "no locked dependencies; the pinned release's rust-src"
                        .to_string(),
                    basis: EnvironmentBasis::Lockfile {
                        path: lock.clone().unwrap_or_default(),
                    },
                }
            } else {
                Provider::UserEnvironment {
                    description: "the installed toolchain; no locked dependencies".to_string(),
                    checked_against: lock.clone(),
                }
            },
            None,
        ),
        analysis::Dependencies::Vendored(how) => (
            None,
            Provider::UserEnvironment {
                description: format!(
                    "crates vendored by the repository's Cargo configuration: {how}"
                ),
                checked_against: lock.clone(),
            },
            None,
        ),
        analysis::Dependencies::UserHome(dir) => (
            Some(DependencySource {
                description: format!("{locked} locked crate(s) in the user's Cargo home"),
                location: Some(dir.clone()),
                lock: lock.clone(),
            }),
            if kin_std {
                Provider::KinAnalysisEnvironment {
                    description: format!(
                        "the pinned release's rust-src with {locked} locked crate(s) from the \
                         user's Cargo home"
                    ),
                    basis: EnvironmentBasis::Lockfile {
                        path: lock.clone().unwrap_or_default(),
                    },
                }
            } else {
                Provider::UserEnvironment {
                    description: format!("the Cargo home at {}", dir.display()),
                    checked_against: lock.clone(),
                }
            },
            None,
        ),
        analysis::Dependencies::KinHome { dir, ready } => (
            Some(DependencySource {
                description: format!("{locked} locked crate(s) in Kin's Cargo home"),
                location: Some(dir.clone()),
                lock: lock.clone(),
            }),
            Provider::KinAnalysisEnvironment {
                description: format!(
                    "{locked} locked crate(s), {} git dependenc(ies) stubbed{passed_over}",
                    assessment.locked.git.len()
                ),
                basis: EnvironmentBasis::Lockfile {
                    path: lock.clone().unwrap_or_default(),
                },
            },
            (!ready).then(|| format!("fetch {locked} locked crate(s)")),
        ),
        analysis::Dependencies::Missing(reason) => (
            None,
            Provider::Missing {
                reason: reason.clone(),
            },
            None,
        ),
    };
    let provider = match (&assessment.std, provider) {
        (analysis::StdSource::Missing(reason), Provider::Missing { reason: deps }) => {
            Provider::Missing {
                reason: format!("{deps}; and {reason}"),
            }
        }
        (analysis::StdSource::Missing(reason), _) => Provider::Missing {
            reason: reason.clone(),
        },
        (_, provider) => provider,
    };
    let pending = match (std_pending, crates_pending) {
        (None, None) => None,
        (Some(one), None) | (None, Some(one)) => Some(one),
        (Some(std), Some(crates)) => Some(format!("{std}, then {crates}")),
    };
    Environment {
        toolchain,
        dependencies: dependency.into_iter().collect(),
        provider,
        identity: assessment.identity,
        pending,
    }
}

/// What rust-analyzer is told beside its options for an environment: the
/// Cargo home to read, never fetching, never installing a toolchain, and the
/// standard library's source when Kin provides it.
fn environment_settings(environment: &Environment) -> (Vec<(String, String)>, EnvironmentOptions) {
    let mut env = vec![
        ("CARGO_NET_OFFLINE".to_string(), "true".to_string()),
        ("RUSTUP_AUTO_INSTALL".to_string(), "0".to_string()),
    ];
    let home = environment
        .dependencies
        .iter()
        .find_map(|source| source.location.clone());
    let deps_ready = home
        .as_ref()
        .is_some_and(|home| environment.pending.is_none() || home.join(".complete").is_file());
    if let (Some(home), true) = (&home, deps_ready) {
        env.push(("CARGO_HOME".to_string(), home.display().to_string()));
    }
    let toolchain = environment.toolchain.as_ref();
    if let Some(substitute) = toolchain.and_then(|toolchain| toolchain.substitute.as_ref()) {
        env.push(("RUSTUP_TOOLCHAIN".to_string(), substitute.clone()));
    }
    let kin_std = matches!(
        environment.provider,
        Provider::KinAnalysisEnvironment { .. }
    ) && toolchain
        .is_some_and(|toolchain| toolchain.pinned_by.contains("Kin's store"));
    let sysroot_src = toolchain
        .filter(|_| kin_std)
        .and_then(|toolchain| toolchain.location.clone());
    // Dependencies that are missing, or not fetched yet, are left out of the
    // load rather than fetched by Cargo.
    let no_deps = match &environment.provider {
        Provider::Missing { .. } => true,
        _ => home.is_some() && !deps_ready,
    };
    (
        env,
        EnvironmentOptions {
            sysroot_src,
            no_deps,
        },
    )
}

/// The options an environment adds to rust-analyzer's own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct EnvironmentOptions {
    sysroot_src: Option<PathBuf>,
    no_deps: bool,
}

/// Fetch what the repository's environment has pending, with the host it
/// runs on. `None` when nothing is pending.
pub fn provision_with(
    root: &Path,
    host: &RustHost,
    fetcher_for: &dyn Fn(
        &analysis::registry::CargoConfig,
        Option<(&str, &str)>,
    ) -> Result<Box<dyn analysis_env::fetch::Fetcher>, String>,
) -> Option<ProvisionReport> {
    let model = project_model_for(cargo_layout(root));
    let environment = environment_with(root, &model, host);
    environment.pending.as_ref()?;
    Some(analysis::provision(
        root,
        &manifests_of(&model),
        &members_of(&model),
        &host.analysis_host(),
        fetcher_for,
    ))
}

/// The Cargo layout a project model was read from, for the translation.
fn layout_of(model: &ProjectModel) -> CargoLayout {
    CargoLayout {
        linked_projects: model.roots.clone(),
        trybuild_inputs: model.not_in_any_build.clone(),
        ..CargoLayout::default()
    }
}

/// The trybuild cases under one package's `tests` directory: programs with a
/// `main` of their own, one directory or more below `tests`, where Cargo's
/// integration-test targets (`tests/*.rs`, `tests/*/main.rs`) never reach.
fn trybuild_inputs(tests: &Path) -> Vec<PathBuf> {
    let mut inputs = Vec::new();
    repo_scan::walk_files(tests, &|_, _| true, &mut |path, name| {
        let Some(parent) = path.parent() else {
            return;
        };
        let integration_target =
            parent == tests || (name == "main.rs" && parent.parent() == Some(tests));
        if name.ends_with(".rs")
            && name != "mod.rs"
            && !integration_target
            && std::fs::read_to_string(path).is_ok_and(|text| text.contains("fn main"))
        {
            inputs.push(path.to_path_buf());
        }
    });
    inputs
}

/// The initialization options for a set of linked projects.
fn options(linked_projects: &[PathBuf], all_features: bool) -> serde_json::Value {
    options_with(
        linked_projects,
        all_features,
        &EnvironmentOptions::default(),
    )
}

fn options_with(
    linked_projects: &[PathBuf],
    all_features: bool,
    environment: &EnvironmentOptions,
) -> serde_json::Value {
    let mut cargo = serde_json::json!({
        "buildScripts": { "enable": false },
        "sysroot": "discover",
    });
    if all_features {
        cargo["features"] = serde_json::json!("all");
    }
    if let Some(src) = &environment.sysroot_src {
        cargo["sysrootSrc"] = serde_json::json!(src.display().to_string());
    }
    if environment.no_deps {
        cargo["noDeps"] = serde_json::json!(true);
    }
    let mut options = serde_json::json!({
        "cargo": cargo,
        "procMacro": { "enable": false },
        "checkOnSave": false,
        "diagnostics": { "enable": false },
    });
    if !linked_projects.is_empty() {
        options["linkedProjects"] = serde_json::json!(linked_projects
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>());
    }
    options
}

/// The launch for a repository whose Cargo layout is `layout`: every feature,
/// falling back to the default features when a feature breaks the load.
pub fn launch_for(layout: CargoLayout) -> ServerLaunch {
    launch_with_environment(layout, Vec::new(), &EnvironmentOptions::default(), "")
}

/// rust-analyzer's configuration for a model and an environment.
pub fn configure(model: &ProjectModel, environment: &Environment) -> ServerLaunch {
    let (env, options) = environment_settings(environment);
    let crates = match &environment.provider {
        Provider::Missing { .. } => "; dependencies not loaded (environment missing)".to_string(),
        _ if options.no_deps => "; dependencies not loaded until Kin fetches them".to_string(),
        Provider::KinAnalysisEnvironment { .. } => format!(
            "; Kin's analysis environment {}",
            &environment.identity.hex()[..12]
        ),
        Provider::UserEnvironment { .. } => "; the user's environment".to_string(),
    };
    launch_with_environment(layout_of(model), env, &options, &crates)
}

fn launch_with_environment(
    layout: CargoLayout,
    env: Vec<(String, String)>,
    environment: &EnvironmentOptions,
    suffix: &str,
) -> ServerLaunch {
    let fallback = ServerLaunch {
        initialization_options: Some(options_with(&layout.linked_projects, false, environment)),
        env: env.clone(),
        label: format!("rust-analyzer with default Cargo features{suffix}"),
        load_check: Some(LoadCheck::ServerStatus),
        ..ServerLaunch::default()
    };
    ServerLaunch {
        initialization_options: Some(options_with(&layout.linked_projects, true, environment)),
        env,
        label: format!(
            "rust-analyzer with all Cargo features, {} linked project(s){suffix}",
            layout.linked_projects.len()
        ),
        load_check: Some(LoadCheck::ServerStatus),
        fallback: Some(Box::new(fallback)),
        // Only a load that failed over a feature is this configuration's
        // fault. Cargo names the feature in every such error.
        fallback_trigger: Some("feature".to_string()),
        ..ServerLaunch::default()
    }
}

impl LspAdapter for RustAnalyzerAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Rust
    }

    fn server_command(&self) -> &str {
        "rust-analyzer"
    }

    fn file_extensions(&self) -> &[&str] {
        &["rs"]
    }

    fn initialization_options(&self, workspace_root: &Path) -> Option<serde_json::Value> {
        Some(options(&cargo_layout(workspace_root).linked_projects, true))
    }

    fn project_model(&self, workspace_root: &Path) -> ProjectModel {
        project_model_for(cargo_layout(workspace_root))
    }

    fn environment(&self, workspace_root: &Path, model: &ProjectModel) -> Environment {
        environment_with(workspace_root, model, &RustHost::current())
    }

    fn configure(
        &self,
        _workspace_root: &Path,
        model: &ProjectModel,
        environment: &Environment,
    ) -> ServerLaunch {
        configure(model, environment)
    }

    fn provision(&self, workspace_root: &Path) -> Option<ProvisionReport> {
        let host = RustHost::current();
        if !host.analysis_environments {
            return None;
        }
        let fetcher_for = |config: &analysis::registry::CargoConfig,
                           token: Option<(&str, &str)>|
         -> Result<Box<dyn analysis_env::fetch::Fetcher>, String> {
            let mut fetcher = analysis_env::fetch::HttpFetcher::new(&config.network())?;
            if let Some((index, token)) = token {
                fetcher = fetcher.with_authorization(index.to_string(), token.to_string());
            }
            Ok(Box::new(fetcher))
        };
        provision_with(workspace_root, &host, &fetcher_for)
    }

    fn requires_workspace_indexing(&self) -> bool {
        true // rust-analyzer needs to load cargo metadata
    }

    fn estimated_index_time_secs(&self) -> u32 {
        30 // typical for medium Rust projects
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::repo_scan::Fixture;

    fn relative(fixture: &Fixture, paths: &[PathBuf]) -> Vec<String> {
        paths
            .iter()
            .map(|path| {
                path.strip_prefix(&fixture.root)
                    .unwrap()
                    .display()
                    .to_string()
            })
            .collect()
    }

    const PACKAGE: &str = "[package]\nname = \"p\"\nversion = \"0.1.0\"\n";

    /// axum's shape: a root workspace whose members are the crates, and an
    /// `examples` directory that is a workspace of its own. Both are linked;
    /// the members are not linked again.
    #[test]
    fn every_workspace_root_is_linked_and_members_are_not() {
        let fixture = Fixture::new("cargo-layout");
        fixture.write(
            "Cargo.toml",
            "[workspace]\nmembers = [\"axum\", \"axum-*\"]\n",
        );
        fixture.write("axum/Cargo.toml", PACKAGE);
        fixture.write("axum-core/Cargo.toml", PACKAGE);
        fixture.write(
            "examples/Cargo.toml",
            "[workspace]\nmembers = [\"*\"]\nexclude = [\"target\"]\n",
        );
        fixture.write("examples/hello/Cargo.toml", PACKAGE);
        fixture.write("target/CACHEDIR.TAG", "");
        fixture.write("target/package/x/Cargo.toml", PACKAGE);

        let layout = cargo_layout(&fixture.root);
        assert_eq!(
            relative(&fixture, &layout.linked_projects),
            vec!["Cargo.toml", "examples/Cargo.toml"]
        );
    }

    /// A package under a workspace root that excludes it, and a package with
    /// no workspace above it, are each a project of their own. Fixture crates
    /// under `tests` are test inputs, and a vendored crate is a dependency.
    #[test]
    fn excluded_and_standalone_packages_are_linked_and_fixtures_are_not() {
        let fixture = Fixture::new("cargo-layout-excluded");
        fixture.write(
            "Cargo.toml",
            "[workspace]\nmembers = [\"core\"]\nexclude = [\"tools/gen\"]\n",
        );
        fixture.write("core/Cargo.toml", PACKAGE);
        fixture.write("tools/gen/Cargo.toml", PACKAGE);
        fixture.write("core/tests/fixtures/broken/Cargo.toml", PACKAGE);
        fixture.write("vendor/dep/Cargo.toml", PACKAGE);
        fixture.write("vendor/dep/.cargo-checksum.json", "{}");
        fixture.write("tests/Cargo.toml", "[workspace]\n");
        fixture.write("bad/Cargo.toml", "this is not toml [");

        let standalone = Fixture::new("cargo-layout-standalone");
        standalone.write("crate-a/Cargo.toml", PACKAGE);
        standalone.write("crate-b/Cargo.toml", PACKAGE);

        assert_eq!(
            relative(&fixture, &cargo_layout(&fixture.root).linked_projects),
            vec!["Cargo.toml", "tests/Cargo.toml", "tools/gen/Cargo.toml"]
        );
        assert_eq!(
            relative(&standalone, &cargo_layout(&standalone.root).linked_projects),
            vec!["crate-a/Cargo.toml", "crate-b/Cargo.toml"]
        );
    }

    /// trybuild cases are programs one directory or more below `tests`, in a
    /// package that depends on trybuild. Integration-test targets and their
    /// modules are not cases.
    #[test]
    fn trybuild_cases_are_reported_as_in_no_build() {
        let fixture = Fixture::new("cargo-trybuild");
        fixture.write(
            "macros/Cargo.toml",
            "[package]\nname = \"m\"\nversion = \"0.1.0\"\n[dev-dependencies]\ntrybuild = \"1\"\n",
        );
        fixture.write("macros/tests/ui.rs", "fn main() {}\n#[test] fn ui() {}\n");
        fixture.write("macros/tests/big/main.rs", "fn main() {}\n");
        fixture.write("macros/tests/common/mod.rs", "pub fn helper() {}\n");
        fixture.write("macros/tests/common/util.rs", "pub fn util() {}\n");
        fixture.write("macros/tests/debug/fail/bad.rs", "fn main() { x }\n");
        fixture.write("macros/tests/debug/pass/good.rs", "fn main() {}\n");
        fixture.write("plain/Cargo.toml", PACKAGE);
        fixture.write("plain/tests/cases/fail/x.rs", "fn main() {}\n");

        let layout = cargo_layout(&fixture.root);
        assert_eq!(
            relative(&fixture, &layout.trybuild_inputs),
            vec![
                "macros/tests/debug/fail/bad.rs",
                "macros/tests/debug/pass/good.rs"
            ]
        );
    }

    /// The first configuration loads every feature and every linked project;
    /// its fallback is the same load with the default features. Build scripts
    /// and procedural macros stay off in both, since they run repository code.
    #[test]
    fn the_launch_loads_all_features_and_falls_back_to_the_defaults() {
        let layout = CargoLayout {
            linked_projects: vec![
                PathBuf::from("/repo/Cargo.toml"),
                PathBuf::from("/repo/examples/Cargo.toml"),
            ],
            trybuild_inputs: vec![PathBuf::from("/repo/m/tests/fail/x.rs")],
            ..CargoLayout::default()
        };
        let launch = launch_for(layout);
        let options = launch.initialization_options.as_ref().unwrap();
        assert_eq!(options["cargo"]["features"], "all");
        assert_eq!(
            options["linkedProjects"],
            serde_json::json!(["/repo/Cargo.toml", "/repo/examples/Cargo.toml"])
        );
        assert_eq!(launch.load_check, Some(LoadCheck::ServerStatus));
        assert_eq!(launch.fallback_trigger.as_deref(), Some("feature"));

        let fallback = launch.fallback.as_deref().expect("a fallback");
        let fallback_options = fallback.initialization_options.as_ref().unwrap();
        assert!(fallback_options["cargo"].get("features").is_none());
        assert_eq!(
            fallback_options["linkedProjects"],
            options["linkedProjects"]
        );
        assert!(fallback.fallback.is_none());

        for options in [options, fallback_options] {
            assert_eq!(options["cargo"]["buildScripts"]["enable"], false);
            assert_eq!(options["procMacro"]["enable"], false);
        }
    }

    /// Discovery reads the packages, their library roots and the pinned
    /// toolchain from manifests alone, and the launch reports the trybuild
    /// cases as in no build.
    #[test]
    fn discovery_reads_packages_toolchain_and_files_in_no_build() {
        let fixture = Fixture::new("cargo-discovery");
        fixture.write(
            "Cargo.toml",
            "[workspace]\nmembers = [\"core\", \"macros\"]\n",
        );
        fixture.write(
            "core/Cargo.toml",
            "[package]\nname = \"core-lib\"\nversion = \"0.1.0\"\n",
        );
        fixture.write("core/src/lib.rs", "pub fn f() {}\n");
        fixture.write(
            "macros/Cargo.toml",
            "[package]\nname = \"m\"\nversion = \"0.1.0\"\n[lib]\npath = \"lib.rs\"\n[dev-dependencies]\ntrybuild = \"1\"\n",
        );
        fixture.write("macros/tests/ui/fail/bad.rs", "fn main() {}\n");
        fixture.write("Cargo.lock", "version = 4\n");
        fixture.write("rust-toolchain.toml", "[toolchain]\nchannel = \"1.96.0\"\n");

        let model = RustAnalyzerAdapter.project_model(&fixture.root);
        let names: Vec<&str> = model.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["core-lib", "m"]);
        assert_eq!(
            model.workspace_map["core-lib"],
            fixture.root.join("core/src/lib.rs")
        );
        assert_eq!(model.workspace_map["m"], fixture.root.join("macros/lib.rs"));
        assert_eq!(model.variants.features, Selection::All);

        let host = host(&fixture);
        let environment = environment_with(&fixture.root, &model, &host);
        let toolchain = environment.toolchain.as_ref().unwrap();
        assert_eq!(
            (toolchain.version.as_str(), toolchain.pinned_by.as_str()),
            (
                "1.96.0",
                "rust-toolchain.toml pins 1.96.0; installed with rust-src"
            )
        );
        assert!(matches!(
            environment.provider,
            Provider::UserEnvironment { .. }
        ));

        let resolution = launch_with_host(&fixture.root, &host).resolution.unwrap();
        assert_eq!(
            resolution.not_in_any_build,
            vec![fixture.root.join("macros/tests/ui/fail/bad.rs")]
        );
        assert!(resolution.status_lines()[2].starts_with("not in any build: 1 file(s)"));
    }

    /// A host whose rustup has the 1.96.0 toolchain with rust-src as its
    /// default, and whose Cargo home is empty.
    fn host(fixture: &Fixture) -> RustHost {
        fixture.write(
            ".host/rustup/toolchains/1.96.0-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/lib.rs",
            "",
        );
        fixture.write(
            ".host/rustup/settings.toml",
            "default_toolchain = \"1.96.0-aarch64-apple-darwin\"\n",
        );
        for tool in ["cargo", "rustc"] {
            fixture.write(
                &format!(".host/rustup/toolchains/1.96.0-aarch64-apple-darwin/bin/{tool}"),
                "",
            );
        }
        let mut vars = HashMap::new();
        vars.insert(
            "RUSTUP_HOME".to_string(),
            fixture.root.join(".host/rustup").display().to_string(),
        );
        vars.insert(
            "CARGO_HOME".to_string(),
            fixture.root.join(".host/cargo").display().to_string(),
        );
        RustHost {
            vars,
            home: None,
            cache: fixture.root.join(".host/kin-cache"),
            analysis_environments: true,
            triple: Some("aarch64-apple-darwin"),
        }
    }

    fn launch_with_host(root: &Path, host: &RustHost) -> ServerLaunch {
        let model = RustAnalyzerAdapter.project_model(root);
        let environment = environment_with(root, &model, host);
        let mut launch = configure(&model, &environment);
        launch.resolution = Some(super::super::Resolution::new(&model, environment));
        launch
    }

    /// The configuration the contract's launch produces is the one this
    /// adapter produced before the contract existed, pinned field by field,
    /// with the environment's guarantees beside it: Cargo never fetches and
    /// rustup never installs.
    #[test]
    fn the_contract_launch_is_the_configuration_the_adapter_always_sent() {
        let fixture = Fixture::new("cargo-pinned-launch");
        fixture.write("Cargo.toml", "[workspace]\nmembers = [\"a\"]\n");
        fixture.write("a/Cargo.toml", PACKAGE);
        let launch = launch_with_host(&fixture.root, &host(&fixture));
        let manifest = fixture.root.join("Cargo.toml").display().to_string();
        assert_eq!(
            launch.initialization_options,
            Some(serde_json::json!({
                "cargo": {"buildScripts": {"enable": false}, "sysroot": "discover", "features": "all"},
                "procMacro": {"enable": false},
                "checkOnSave": false,
                "diagnostics": {"enable": false},
                "linkedProjects": [manifest],
            }))
        );
        assert_eq!(launch.settings, None);
        assert_eq!(
            launch.env,
            vec![
                ("CARGO_NET_OFFLINE".to_string(), "true".to_string()),
                ("RUSTUP_AUTO_INSTALL".to_string(), "0".to_string()),
            ]
        );
        assert_eq!(
            launch.label,
            "rust-analyzer with all Cargo features, 1 linked project(s); the user's environment"
        );
        let fallback = launch.fallback.unwrap();
        assert_eq!(
            fallback.label,
            "rust-analyzer with default Cargo features; the user's environment"
        );
        assert_eq!(
            fallback.env, launch.env,
            "the fallback keeps the guarantees"
        );
        assert!(fallback.resolution.is_none());
    }

    /// Dependencies the user's Cargo home lacks, with analysis environments
    /// off, are left out of the load (`noDeps`) rather than fetched by
    /// Cargo; with them on, the launch waits on Kin's Cargo home.
    #[test]
    fn missing_dependencies_are_left_out_never_fetched_by_cargo() {
        let fixture = Fixture::new("cargo-missing");
        fixture.write(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1\"\n",
        );
        fixture.write(
            "Cargo.lock",
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"ab\"\n",
        );
        let mut host = host(&fixture);
        host.analysis_environments = false;
        let launch = launch_with_host(&fixture.root, &host);
        let options = launch.initialization_options.as_ref().unwrap();
        assert_eq!(options["cargo"]["noDeps"], true);
        assert!(launch
            .resolution
            .as_ref()
            .unwrap()
            .environment
            .missing_reason()
            .is_some_and(|reason| reason.contains("analysis environments are off")));
        let fetcher_for = |_: &analysis::registry::CargoConfig,
                           _: Option<(&str, &str)>|
         -> Result<Box<dyn analysis_env::fetch::Fetcher>, String> {
            panic!("no fetch is attempted with analysis environments off")
        };
        assert!(provision_with(&fixture.root, &host, &fetcher_for).is_none());

        host.analysis_environments = true;
        let launch = launch_with_host(&fixture.root, &host);
        let environment = &launch.resolution.as_ref().unwrap().environment;
        assert_eq!(
            environment.pending.as_deref(),
            Some("fetch 1 locked crate(s)")
        );
        assert_eq!(
            launch.initialization_options.unwrap()["cargo"]["noDeps"],
            true,
            "until Kin's Cargo home is complete"
        );
        assert!(!launch.env.iter().any(|(name, _)| name == "CARGO_HOME"));
    }

    /// A tree with no Cargo manifest links nothing, which leaves rust-analyzer
    /// its own discovery.
    #[test]
    fn a_tree_without_manifests_links_nothing() {
        let options = RustAnalyzerAdapter
            .initialization_options(Path::new("/nonexistent-kin-workspace"))
            .unwrap();
        assert!(options.get("linkedProjects").is_none(), "{options}");
        assert_eq!(options["cargo"]["features"], "all");
    }
}
