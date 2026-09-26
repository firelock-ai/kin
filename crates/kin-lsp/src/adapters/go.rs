// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Go LSP adapter (gopls).
//!
//! gopls loads the files the default build selects. A file behind a build tag
//! (`//go:build integration`) is outside that build, so gopls answers nothing
//! in it and nothing it calls is known to be called from it. This adapter
//! passes the repository's own build tags as `buildFlags`, only those that add
//! files: a tag some file excludes itself with (`!purego`) would hide as much
//! as it shows, and is left off.
//!
//! A `go.work` at the root names the modules that build together, and gopls
//! finds it through `GOWORK`. The variable is set to that file, so the
//! workspace does not depend on the environment Kin inherited (a `GOWORK=off`
//! from a shell turns the workspace off). A `go.work` below the root, and a
//! module without one, are found by gopls itself for the files it opens.
//!
//! The environment follows the contract: the user's module cache when it
//! holds every module `go.sum` locks, else Kin's analysis environment, the
//! same modules fetched from `GOPROXY` and verified against `go.sum` (see
//! [`crate::analysis_env::go`]), else none, reported missing. Whichever
//! serves, gopls runs with `GOPROXY=off`, `GOTOOLCHAIN=local` and
//! `CGO_ENABLED=0`: it never fetches, never swaps its `go` command, and never
//! invokes a C compiler to load a package.

use std::collections::{BTreeSet, HashMap};
use std::io::BufRead;
use std::path::{Path, PathBuf};

use kin_model::LanguageId;

use super::contract::{
    self, DependencySource, Environment, EnvironmentBasis, ProjectModel, ProjectPackage, Provider,
    ProvisionReport, Toolchain,
};
use super::repo_scan;
use super::{LspAdapter, ServerLaunch};
use crate::analysis_env::{self, go as analysis};

pub struct GoplsAdapter;

/// Operating systems a build constraint can name.
const KNOWN_OS: &[&str] = &[
    "aix",
    "android",
    "darwin",
    "dragonfly",
    "freebsd",
    "hurd",
    "illumos",
    "ios",
    "js",
    "linux",
    "nacl",
    "netbsd",
    "openbsd",
    "plan9",
    "solaris",
    "wasip1",
    "windows",
    "zos",
];

/// Architectures a build constraint can name.
const KNOWN_ARCH: &[&str] = &[
    "386",
    "amd64",
    "amd64p32",
    "arm",
    "armbe",
    "arm64",
    "arm64be",
    "loong64",
    "mips",
    "mipsle",
    "mips64",
    "mips64le",
    "mips64p32",
    "mips64p32le",
    "ppc",
    "ppc64",
    "ppc64le",
    "riscv",
    "riscv64",
    "s390",
    "s390x",
    "sparc",
    "sparc64",
    "wasm",
];

/// Tags the toolchain sets itself, or that by convention mark a file no build
/// should include (`ignore` for generators, `tools` for tool imports).
const NOT_USER_TAGS: &[&str] = &["cgo", "gc", "gccgo", "unix", "ignore", "tools"];

fn is_user_tag(tag: &str) -> bool {
    !(KNOWN_OS.contains(&tag)
        || KNOWN_ARCH.contains(&tag)
        || NOT_USER_TAGS.contains(&tag)
        || tag.starts_with("go1")
        || tag.starts_with("goexperiment."))
}

/// The tags one `//go:build` expression names, split into those it requires
/// and those it negates.
fn constraint_tags(
    expression: &str,
    required: &mut BTreeSet<String>,
    negated: &mut BTreeSet<String>,
) {
    let mut negate = false;
    let mut chars = expression.char_indices().peekable();
    while let Some((start, c)) = chars.next() {
        if c == '!' {
            negate = true;
        } else if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
            let mut end = start + c.len_utf8();
            while let Some(&(index, next)) = chars.peek() {
                if next.is_ascii_alphanumeric() || next == '_' || next == '.' {
                    end = index + next.len_utf8();
                    chars.next();
                } else {
                    break;
                }
            }
            let tag = expression[start..end].to_string();
            if negate {
                negated.insert(tag);
            } else {
                required.insert(tag);
            }
            negate = false;
        } else if !c.is_whitespace() {
            negate = false;
        }
    }
}

/// The Go modules and build tags of one repository, read in one walk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoLayout {
    /// Every `go.mod` outside vendored and `testdata` code.
    pub modules: Vec<PathBuf>,
    /// The build tags that only add files; see [`build_tags`].
    pub tags: Vec<String>,
}

/// The build tags the repository's own Go files use that only add files: named
/// by some file's `//go:build` line and negated by none. Vendored and
/// `testdata` code is not the repository's build and is not read.
pub fn build_tags(root: &Path) -> Vec<String> {
    go_layout(root).tags
}

/// Read the repository's Go modules and build tags.
pub fn go_layout(root: &Path) -> GoLayout {
    let mut required = BTreeSet::new();
    let mut negated = BTreeSet::new();
    let mut modules = Vec::new();
    repo_scan::walk_files(
        root,
        &|_, name| name != "vendor" && name != "testdata",
        &mut |path, name| {
            if name == "go.mod" {
                modules.push(path.to_path_buf());
                return;
            }
            if !name.ends_with(".go") {
                return;
            }
            let Ok(file) = std::fs::File::open(path) else {
                return;
            };
            // Constraints precede the package clause; nothing after it counts.
            for line in std::io::BufReader::new(file).lines() {
                let Ok(line) = line else {
                    break;
                };
                let line = line.trim();
                if let Some(expression) = line
                    .strip_prefix("//go:build")
                    .filter(|rest| rest.starts_with(char::is_whitespace))
                {
                    constraint_tags(expression, &mut required, &mut negated);
                } else if line.starts_with("package ") {
                    break;
                }
            }
        },
    );
    GoLayout {
        modules,
        tags: required
            .into_iter()
            .filter(|tag| is_user_tag(tag) && !negated.contains(tag))
            .collect(),
    }
}

/// The value of the first `<directive> <value>` line of a `go.mod`.
fn go_mod_directive(text: &str, directive: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let rest = line.trim().strip_prefix(directive)?;
        rest.starts_with(char::is_whitespace)
            .then(|| rest.split("//").next().unwrap_or("").trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

/// The project model of a Go repository: its modules, each mapped from its
/// module path to its directory, and the build tags that add files. A root
/// `go.work` leads the roots, since it names the modules that build together.
pub fn project_model_for(root: &Path, layout: GoLayout) -> ProjectModel {
    let mut roots: Vec<PathBuf> = root_go_work(root).into_iter().collect();
    let mut packages = Vec::new();
    let mut workspace_map = std::collections::BTreeMap::new();
    for module in &layout.modules {
        let Some(dir) = module.parent() else {
            continue;
        };
        roots.push(module.clone());
        let Some(path) = std::fs::read_to_string(module)
            .ok()
            .and_then(|text| go_mod_directive(&text, "module"))
        else {
            continue;
        };
        workspace_map
            .entry(path.clone())
            .or_insert_with(|| dir.to_path_buf());
        packages.push(ProjectPackage {
            name: path,
            dir: dir.to_path_buf(),
            source_roots: vec![dir.to_path_buf()],
            config: None,
        });
    }
    ProjectModel {
        roots,
        packages,
        variants: contract::BuildVariants {
            tags: layout.tags,
            ..Default::default()
        },
        workspace_map,
        ..ProjectModel::default()
    }
}

/// What environment discovery reads from the host: its variables, the home
/// directory, Kin's cache, whether analysis environments are on, and the Go
/// on `PATH`. Injected so every branch is testable without the host's Go or
/// the network.
#[derive(Debug, Clone)]
pub struct GoHost {
    pub vars: HashMap<String, String>,
    pub home: Option<PathBuf>,
    /// Kin's cache directory, `$KIN_HOME/cache`.
    pub cache: PathBuf,
    pub analysis_environments: bool,
    /// The Go installation behind `go` on `PATH`, read from its files.
    pub installed: Option<analysis::toolchain::InstalledGo>,
}

impl GoHost {
    /// This process's host.
    pub fn current() -> Self {
        let vars: HashMap<String, String> = std::env::vars().collect();
        let home = vars.get("HOME").map(PathBuf::from);
        Self {
            installed: which::which("go")
                .ok()
                .and_then(|go| analysis::toolchain::installation_of(&go)),
            vars,
            home,
            cache: analysis_env::kin_cache_dir(),
            analysis_environments: analysis_env::enabled(),
        }
    }

    fn env(&self) -> analysis::GoEnv {
        analysis::GoEnv::read(&self.vars, self.home.as_deref())
    }
}

/// The modules of a project model, as the analysis environment reads them.
fn workspace_of(root: &Path, model: &ProjectModel) -> analysis::Workspace {
    let mod_files: Vec<PathBuf> = model
        .packages
        .iter()
        .map(|package| package.dir.join("go.mod"))
        .collect();
    analysis::Workspace::read(root, &mod_files)
}

/// The environment gopls analyses the repository at `root` against, from the
/// first provider that has one. Nothing here touches the network; what only a
/// download can supply is left in [`Environment::pending`].
pub fn environment_with(root: &Path, model: &ProjectModel, host: &GoHost) -> Environment {
    let workspace = workspace_of(root, model);
    let env = host.env();
    let analysis_host = analysis::Host {
        env: &env,
        cache: &host.cache,
        installed: host.installed.as_ref(),
        analysis_environments: host.analysis_environments,
    };
    let assessment = analysis::assess(&workspace, &analysis_host);
    let store = analysis_host.store();
    let pinned_by = assessment.requirement.as_ref().map_or_else(
        || "no go.mod names a version; the installed Go".to_string(),
        |requirement| requirement.pinned_by.clone(),
    );
    let (toolchain, kin_toolchain, toolchain_pending) = match &assessment.toolchain {
        analysis::ToolchainChoice::Installed(go) => (
            Some(Toolchain {
                name: "go".to_string(),
                version: go.version.to_string(),
                pinned_by: format!("{pinned_by}; the installed Go satisfies it"),
                location: Some(go.root.clone()),
                substitute: None,
            }),
            false,
            None,
        ),
        analysis::ToolchainChoice::Stored(go) => (
            Some(Toolchain {
                name: "go".to_string(),
                version: go.version.to_string(),
                pinned_by: format!("{pinned_by}; fetched from go.dev by Kin"),
                location: Some(go.root.clone()),
                substitute: None,
            }),
            true,
            None,
        ),
        analysis::ToolchainChoice::Fetch(release) => (
            Some(Toolchain {
                name: "go".to_string(),
                version: release.to_string(),
                pinned_by: format!("{pinned_by}; not fetched yet"),
                location: None,
                substitute: None,
            }),
            true,
            Some(format!("fetch Go {release} from go.dev")),
        ),
        analysis::ToolchainChoice::Missing(_) => (None, false, None),
    };
    let lock = assessment.sums.files.first().cloned();
    let locked = assessment.sums.zips.len();
    let passed_over = assessment
        .passed_over
        .as_deref()
        .map(|reason| format!("; the user's module cache was passed over: {reason}"))
        .unwrap_or_default();
    let (dependency, provider, modules_pending) = match &assessment.dependencies {
        analysis::Dependencies::None => (
            None,
            if kin_toolchain {
                Provider::KinAnalysisEnvironment {
                    description: "no module dependencies".to_string(),
                    basis: EnvironmentBasis::Lockfile {
                        path: workspace.mod_files.first().cloned().unwrap_or_default(),
                    },
                }
            } else {
                Provider::UserEnvironment {
                    description: "the installed Go; no module dependencies".to_string(),
                    checked_against: None,
                }
            },
            None,
        ),
        analysis::Dependencies::Vendored => (
            Some(DependencySource {
                description: "modules vendored in the repository".to_string(),
                location: None,
                lock: workspace
                    .vendored
                    .first()
                    .map(|dir| dir.join("vendor/modules.txt")),
            }),
            Provider::UserEnvironment {
                description: "the repository's vendor directories".to_string(),
                checked_against: workspace
                    .vendored
                    .first()
                    .map(|dir| dir.join("vendor/modules.txt")),
            },
            None,
        ),
        analysis::Dependencies::UserCache(dir) => (
            Some(DependencySource {
                description: format!("{locked} locked module(s) in the user's module cache"),
                location: Some(dir.clone()),
                lock: lock.clone(),
            }),
            if kin_toolchain {
                Provider::KinAnalysisEnvironment {
                    description: format!(
                        "the pinned Go with {locked} locked module(s) from the user's module cache"
                    ),
                    basis: EnvironmentBasis::Lockfile {
                        path: lock.clone().unwrap_or_default(),
                    },
                }
            } else {
                Provider::UserEnvironment {
                    description: format!("the Go module cache at {}", dir.display()),
                    checked_against: lock.clone(),
                }
            },
            None,
        ),
        analysis::Dependencies::KinCache { ready } => (
            Some(DependencySource {
                description: format!("{locked} locked module(s) in Kin's module cache"),
                location: Some(analysis::modcache_dir(&store)),
                lock: lock.clone(),
            }),
            Provider::KinAnalysisEnvironment {
                description: format!("{locked} locked module(s){passed_over}"),
                basis: EnvironmentBasis::Lockfile {
                    path: lock.clone().unwrap_or_default(),
                },
            },
            (!ready).then(|| {
                format!(
                    "fetch {} module(s) and {} go.mod file(s) from GOPROXY",
                    assessment.sums.zips.len(),
                    assessment.sums.mods.len()
                )
            }),
        ),
        analysis::Dependencies::Missing(reason) => (
            None,
            Provider::Missing {
                reason: reason.clone(),
            },
            None,
        ),
    };
    let provider = match &assessment.toolchain {
        analysis::ToolchainChoice::Missing(reason) => Provider::Missing {
            reason: reason.clone(),
        },
        _ => provider,
    };
    let pending = match (toolchain_pending, modules_pending) {
        (None, None) => None,
        (Some(one), None) | (None, Some(one)) => Some(one),
        (Some(toolchain), Some(modules)) => Some(format!("{toolchain}, then {modules}")),
    };
    // A repository of several modules without a go.work gets Kin's own, so
    // each module resolves the others from their source; one Kin wrote for
    // modules the checksum database proved is kept too.
    let go_work = if workspace.go_work.is_some() {
        None
    } else if workspace.wants_kin_go_work() {
        analysis::write_kin_go_work(
            &store,
            &workspace,
            assessment.requirement.as_ref().map(|r| &r.minimum),
            None,
        )
        .inspect_err(|reason| tracing::warn!(%reason, "could not write Kin's go.work"))
        .ok()
    } else {
        Some(analysis::kin_go_work(&store, root)).filter(|file| file.is_file())
    };
    let go_work = go_work.map(|file| DependencySource {
        description: "Kin's go.work: the repository's modules, each resolved from its source"
            .to_string(),
        lock: Some(file.with_file_name("go.work.sum")).filter(|sum| sum.is_file()),
        location: Some(file),
    });
    Environment {
        toolchain,
        dependencies: dependency.into_iter().chain(go_work).collect(),
        provider,
        identity: assessment.identity,
        pending,
    }
}

/// Whether a dependency source is a `go.work` file rather than a module cache.
fn is_go_work(location: &Path) -> bool {
    location.file_name().is_some_and(|name| name == "go.work")
}

/// The environment variables gopls runs with for an environment: never
/// fetching, never swapping its `go` command, never invoking a C compiler,
/// and reading the modules and toolchain the environment names.
pub fn environment_variables(root: &Path, environment: &Environment) -> Vec<(String, String)> {
    let kin_go_work = environment
        .dependencies
        .iter()
        .filter_map(|source| source.location.as_ref())
        .find(|location| is_go_work(location))
        .cloned();
    let mut env: Vec<(String, String)> = root_go_work(root)
        .or(kin_go_work)
        .map(|file| vec![("GOWORK".to_string(), file.display().to_string())])
        .unwrap_or_default();
    env.extend(
        [
            ("GOPROXY", "off"),
            ("GOTOOLCHAIN", "local"),
            ("CGO_ENABLED", "0"),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string())),
    );
    if let Some(location) = environment
        .dependencies
        .iter()
        .filter_map(|source| source.location.as_ref())
        .find(|location| !is_go_work(location))
    {
        env.push(("GOMODCACHE".to_string(), location.display().to_string()));
    }
    // The chosen toolchain, the installed one or one Kin fetched, leads
    // PATH, where gopls looks for its `go` command.
    if let Some(location) = environment
        .toolchain
        .as_ref()
        .and_then(|toolchain| toolchain.location.as_ref())
    {
        let bin = location.join("bin");
        let path = std::env::var_os("PATH").unwrap_or_default();
        let joined = std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(&path)))
            .map(|joined| joined.to_string_lossy().into_owned())
            .unwrap_or_default();
        env.push(("PATH".to_string(), joined));
    }
    env
}

/// Fetch what the repository's environment has pending, with the host it
/// runs on. `None` when nothing is pending.
pub fn provision_with(
    root: &Path,
    host: &GoHost,
    fetcher: &dyn analysis_env::fetch::Fetcher,
) -> Option<ProvisionReport> {
    let model = project_model_for(root, go_layout(root));
    let environment = environment_with(root, &model, host);
    environment.pending.as_ref()?;
    let env = host.env();
    let analysis_host = analysis::Host {
        env: &env,
        cache: &host.cache,
        installed: host.installed.as_ref(),
        analysis_environments: host.analysis_environments,
    };
    Some(analysis::provision(
        &workspace_of(root, &model),
        &analysis_host,
        fetcher,
    ))
}

/// The workspace file at the root, when there is one.
pub fn root_go_work(root: &Path) -> Option<PathBuf> {
    let file = root.join("go.work");
    file.is_file().then_some(file)
}

/// gopls's settings for a set of build tags.
pub fn settings_for(tags: &[String]) -> serde_json::Value {
    let mut settings = serde_json::json!({
        "analyses": { "unusedparams": false, "shadow": false },
        "diagnosticsDelay": "500ms",
    });
    if !tags.is_empty() {
        settings["buildFlags"] = serde_json::json!([format!("-tags={}", tags.join(","))]);
    }
    settings
}

/// gopls's configuration for a model and an environment.
pub fn configure(root: &Path, model: &ProjectModel, environment: &Environment) -> ServerLaunch {
    let tags = &model.variants.tags;
    let settings = settings_for(tags);
    let build = if tags.is_empty() {
        "the default build".to_string()
    } else {
        format!("build tags {}", tags.join(","))
    };
    let modules = match &environment.provider {
        Provider::KinAnalysisEnvironment { .. } if environment.pending.is_some() => {
            "Kin's module cache, not fetched yet".to_string()
        }
        Provider::KinAnalysisEnvironment { .. } => format!(
            "Kin's analysis environment {}",
            &environment.identity.hex()[..12]
        ),
        Provider::UserEnvironment { description, .. } => description.clone(),
        Provider::Missing { .. } => "no module environment (environment missing)".to_string(),
    };
    ServerLaunch {
        initialization_options: Some(settings.clone()),
        settings: Some(serde_json::json!({ "gopls": settings })),
        env: environment_variables(root, environment),
        label: format!("gopls with {build}; {modules}"),
        ..ServerLaunch::default()
    }
}

impl LspAdapter for GoplsAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Go
    }

    fn server_command(&self) -> &str {
        "gopls"
    }

    fn server_args(&self) -> Vec<String> {
        vec!["serve".to_string()]
    }

    fn file_extensions(&self) -> &[&str] {
        &["go"]
    }

    fn initialization_options(&self, workspace_root: &Path) -> Option<serde_json::Value> {
        Some(settings_for(&build_tags(workspace_root)))
    }

    /// The same settings, for the `gopls` section gopls asks for once it
    /// sees the client answers `workspace/configuration`.
    fn workspace_settings(&self, workspace_root: &Path) -> Option<serde_json::Value> {
        Some(serde_json::json!({ "gopls": settings_for(&build_tags(workspace_root)) }))
    }

    fn server_env(&self, workspace_root: &Path) -> Vec<(String, String)> {
        self.launch(workspace_root).env
    }

    fn project_model(&self, workspace_root: &Path) -> ProjectModel {
        project_model_for(workspace_root, go_layout(workspace_root))
    }

    fn environment(&self, workspace_root: &Path, model: &ProjectModel) -> Environment {
        environment_with(workspace_root, model, &GoHost::current())
    }

    fn configure(
        &self,
        workspace_root: &Path,
        model: &ProjectModel,
        environment: &Environment,
    ) -> ServerLaunch {
        configure(workspace_root, model, environment)
    }

    fn provision(&self, workspace_root: &Path) -> Option<ProvisionReport> {
        let host = GoHost::current();
        if !host.analysis_environments {
            return None;
        }
        let fetcher = match analysis_env::fetch::HttpFetcher::new(
            &analysis_env::fetch::NetworkConfig::default(),
        ) {
            Ok(fetcher) => fetcher,
            Err(reason) => {
                return Some(ProvisionReport {
                    failure: Some(reason),
                    ..ProvisionReport::default()
                });
            }
        };
        provision_with(workspace_root, &host, &fetcher)
    }

    fn requires_workspace_indexing(&self) -> bool {
        true
    }

    fn estimated_index_time_secs(&self) -> u32 {
        15
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::repo_scan::Fixture;

    #[test]
    fn constraint_expressions_split_into_required_and_negated_tags() {
        let (mut required, mut negated) = (BTreeSet::new(), BTreeSet::new());
        constraint_tags(
            " integration && (linux || darwin) && !purego && go1.21",
            &mut required,
            &mut negated,
        );
        assert_eq!(
            required.into_iter().collect::<Vec<_>>(),
            vec!["darwin", "go1.21", "integration", "linux"]
        );
        assert_eq!(negated.into_iter().collect::<Vec<_>>(), vec!["purego"]);
    }

    /// Only tags that add files are passed: `integration` and `e2e` guard test
    /// files, `purego` switches implementations and is negated elsewhere, and
    /// platform, toolchain, `ignore` and vendored tags are never the
    /// repository's own.
    #[test]
    fn build_tags_are_the_repositorys_own_tags_that_only_add_files() {
        let repo = Fixture::new("go-tags");
        repo.write("go.mod", "module example.com/x\n");
        repo.write(
            "db/db_integration_test.go",
            "//go:build integration\n\npackage db\n//go:build notaconstraint\n",
        );
        repo.write(
            "e2e/main_test.go",
            "// Copyright\n\n//go:build e2e && linux\n\npackage e2e\n",
        );
        repo.write("hash/asm.go", "//go:build !purego\n\npackage hash\n");
        repo.write("hash/generic.go", "//go:build purego\n\npackage hash\n");
        repo.write("gen/gen.go", "//go:build ignore\n\npackage main\n");
        repo.write("tools.go", "//go:build tools\n\npackage x\n");
        repo.write("vendor/dep/dep.go", "//go:build vendored\n\npackage dep\n");
        repo.write("testdata/case.go", "//go:build fixture\n\npackage case\n");
        assert_eq!(build_tags(&repo.root), vec!["e2e", "integration"]);
    }

    /// A host with no Go installed, no module cache of its own, and Kin's
    /// cache under `cache`.
    fn host(cache: &Path) -> GoHost {
        let mut vars = HashMap::new();
        vars.insert("GOENV".to_string(), "off".to_string());
        vars.insert(
            "GOMODCACHE".to_string(),
            cache.join("user-modcache").display().to_string(),
        );
        GoHost {
            vars,
            home: None,
            cache: cache.to_path_buf(),
            analysis_environments: true,
            installed: None,
        }
    }

    fn launch_with(root: &Path, host: &GoHost) -> ServerLaunch {
        let model = GoplsAdapter.project_model(root);
        let environment = environment_with(root, &model, host);
        let mut launch = configure(root, &model, &environment);
        launch.resolution = Some(super::super::Resolution::new(&model, environment));
        launch
    }

    /// Discovery reads every module's path, the workspace file and the
    /// toolchain `go.mod` pins, and skips vendored modules.
    #[test]
    fn discovery_reads_modules_the_workspace_and_the_toolchain() {
        let repo = Fixture::new("go-discovery");
        let cache = Fixture::new("go-discovery-cache");
        repo.write("go.work", "go 1.22\n\nuse (\n\t./a\n\t.\n)\n");
        repo.write(
            "go.mod",
            "module example.com/root // the root\n\ngo 1.22\n\ntoolchain go1.22.4\n\n\
             require example.com/dep v1.0.0\n",
        );
        repo.write("go.sum", "example.com/dep v1.0.0 h1:zip=\n");
        repo.write("a/go.mod", "module example.com/a\n\ngo 1.21\n");
        repo.write("vendor/example.com/v/go.mod", "module example.com/v\n");
        let model = GoplsAdapter.project_model(&repo.root);
        assert_eq!(model.roots[0], repo.root.join("go.work"));
        let names: Vec<&str> = model.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["example.com/a", "example.com/root"]);
        assert_eq!(model.workspace_map["example.com/a"], repo.root.join("a"));
        let environment = environment_with(&repo.root, &model, &host(&cache.root));
        let toolchain = environment.toolchain.clone().unwrap();
        assert_eq!(toolchain.version, "1.22.4");
        assert!(
            toolchain.pinned_by.contains("toolchain go1.22.4"),
            "{}",
            toolchain.pinned_by
        );
        assert_eq!(environment.dependencies.len(), 1, "one go.sum");
        assert_eq!(
            environment.pending.as_deref(),
            Some(
                "fetch Go 1.22.4 from go.dev, then fetch 1 module(s) and 0 go.mod file(s) from \
                 GOPROXY"
            )
        );
        assert!(matches!(
            environment.provider,
            Provider::KinAnalysisEnvironment { .. }
        ));
    }

    /// With the switch off and no Go that suits the module, the environment
    /// is missing and says why; nothing is pending.
    #[test]
    fn switched_off_the_environment_is_missing() {
        let repo = Fixture::new("go-off");
        let cache = Fixture::new("go-off-cache");
        repo.write(
            "go.mod",
            "module x\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n",
        );
        repo.write("go.sum", "example.com/dep v1.0.0 h1:zip=\n");
        let mut host = host(&cache.root);
        host.analysis_environments = false;
        let model = GoplsAdapter.project_model(&repo.root);
        let environment = environment_with(&repo.root, &model, &host);
        assert!(environment.pending.is_none());
        assert!(
            environment
                .missing_reason()
                .is_some_and(|reason| reason.contains("analysis environments are off")),
            "{:?}",
            environment.provider
        );
        let fetcher = crate::analysis_env::fetch::testing::FixedFetcher::default();
        assert!(provision_with(&repo.root, &host, &fetcher).is_none());
        assert!(fetcher.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn tags_travel_as_build_flags_and_a_root_go_work_as_gowork() {
        let repo = Fixture::new("go-launch");
        let cache = Fixture::new("go-launch-cache");
        repo.write("go.work", "go 1.22\n\nuse ./a\n");
        repo.write("a/go.mod", "module example.com/a\n");
        repo.write("a/x_test.go", "//go:build integration\n\npackage a\n");
        let launch = launch_with(&repo.root, &host(&cache.root));
        let options = launch.initialization_options.as_ref().unwrap();
        assert_eq!(
            options["buildFlags"],
            serde_json::json!(["-tags=integration"])
        );
        assert_eq!(launch.settings.as_ref().unwrap()["gopls"], *options);
        // Pinned field by field: the configuration gopls always received.
        assert_eq!(
            *options,
            serde_json::json!({
                "analyses": {"unusedparams": false, "shadow": false},
                "diagnosticsDelay": "500ms",
                "buildFlags": ["-tags=integration"],
            })
        );
        assert!(
            launch
                .label
                .starts_with("gopls with build tags integration; "),
            "{}",
            launch.label
        );
        let env: HashMap<&str, &str> = launch
            .env
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let go_work = repo.root.join("go.work").display().to_string();
        assert_eq!(env["GOWORK"], go_work);
        assert_eq!(env["GOPROXY"], "off", "gopls never fetches for itself");
        assert_eq!(env["GOTOOLCHAIN"], "local");
        assert_eq!(
            env["CGO_ENABLED"], "0",
            "loading never invokes a C compiler"
        );

        let plain = Fixture::new("go-plain");
        plain.write("go.mod", "module example.com/p\n");
        let launch = launch_with(&plain.root, &host(&cache.root));
        assert!(!launch.env.iter().any(|(name, _)| name == "GOWORK"));
        assert!(launch
            .initialization_options
            .unwrap()
            .get("buildFlags")
            .is_none());
    }

    /// Several modules and no go.work: Kin writes one outside the repository
    /// naming each module, so each resolves the others from source; a
    /// module under `testdata` or an ignored directory is left out.
    #[test]
    fn several_modules_without_a_go_work_get_kins() {
        let repo = Fixture::new("go-multi");
        let cache = Fixture::new("go-multi-cache");
        repo.write("go.mod", "module example.com/root\n\ngo 1.21\n");
        repo.write(
            "examples/go.mod",
            "module example.com/examples\n\ngo 1.22\n\nrequire example.com/root v1.0.0\n",
        );
        repo.write("_old/go.mod", "module example.com/old\n");
        let launch = launch_with(&repo.root, &host(&cache.root));
        let go_work = launch
            .env
            .iter()
            .find(|(name, _)| name == "GOWORK")
            .map(|(_, value)| PathBuf::from(value))
            .unwrap();
        assert!(go_work.starts_with(&cache.root), "outside the repository");
        let text = std::fs::read_to_string(&go_work).unwrap();
        assert!(text.contains("go 1.22"), "{text}");
        assert!(text.contains(&repo.root.join("examples").display().to_string()));
        assert!(text.contains(&format!("\t{}\n", repo.root.display())));
        assert!(!text.contains("_old"), "{text}");
        let mut in_repo = Vec::new();
        repo_scan::walk_files(&repo.root, &|_, _| true, &mut |path, _| {
            in_repo.push(path.to_path_buf())
        });
        assert_eq!(
            in_repo.len(),
            3,
            "nothing written into the repository: {in_repo:?}"
        );
    }

    /// Kin's module cache, once filled, is what gopls reads, and a Go Kin
    /// fetched leads its PATH.
    #[test]
    fn a_provisioned_environment_points_gopls_at_kins_cache_and_toolchain() {
        let repo = Fixture::new("go-kin-env");
        let cache = Fixture::new("go-kin-env-cache");
        repo.write("go.mod", "module x\n\ngo 1.23.2\n");
        let host = host(&cache.root);
        let store = analysis::store_dir(&cache.root);
        let release = analysis::toolchain::GoVersion::parse("1.23.2").unwrap();
        let root = analysis::toolchain::toolchain_dir(&store, &release).join("go");
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("VERSION"), "go1.23.2\n").unwrap();
        std::fs::write(root.join("bin/go"), "").unwrap();
        let launch = launch_with(&repo.root, &host);
        let resolution = launch.resolution.as_ref().unwrap();
        assert!(resolution.environment.pending.is_none());
        let path = launch
            .env
            .iter()
            .find(|(name, _)| name == "PATH")
            .map(|(_, value)| value.clone())
            .unwrap();
        assert!(
            path.starts_with(&root.join("bin").display().to_string()),
            "{path}"
        );
    }
}
