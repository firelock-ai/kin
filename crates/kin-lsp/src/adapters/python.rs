// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! pyright LSP adapter for Python.
//!
//! pyright takes its settings only through `workspace/configuration`, as the
//! `python` and `python.analysis` sections an editor would hold. It reads one
//! flag from `initializationOptions` and nothing else, so a `pythonPath` sent
//! there is never seen. This adapter answers those sections:
//!
//! - `python.pythonPath` names the environment pyright analyses against, from
//!   the first provider that has one (see [`environment_with`]): the user's
//!   own environment when it matches the repository's lock, else Kin's
//!   analysis environment built from that lock, else none, reported missing.
//!   pyright types third-party code, such as a test client's methods, only
//!   from an environment that has it installed.
//! - `python.pythonPath` is always sent. Without it pyright runs whatever
//!   `python` is on its `PATH` and reads that interpreter's packages, an
//!   environment the repository never chose.
//! - `python.analysis.extraPaths` names every `src` directory of a src-layout
//!   project, so the repository's own package is resolved from the workspace
//!   rather than from a copy installed in that environment.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use kin_model::LanguageId;

use super::contract::{
    DependencySource, Environment, EnvironmentBasis, EnvironmentIdentity, ProjectModel,
    ProjectPackage, Provider, ProvisionReport, Selection, Toolchain,
};
use super::{LspAdapter, ServerLaunch};
use crate::analysis_env::{self, python as analysis};

pub struct PyrightAdapter;

/// Where the Python environment handed to pyright came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentSource {
    /// A virtual environment inside the repository (`.venv`, `venv`), which is
    /// where uv, Poetry's in-project setting, PDM and Hatch put one.
    ProjectVenv,
    /// uv's project environment moved by `UV_PROJECT_ENVIRONMENT`.
    UvProjectEnvironment,
    /// The virtual environment active where Kin was started (`VIRTUAL_ENV`).
    ActiveVirtualEnv,
    /// Poetry's environment for this project in its shared cache.
    Poetry,
    /// The conda environment `environment.yml` names.
    Conda,
    /// The pyenv version the repository's `.python-version` names.
    PyenvLocal,
}

impl EnvironmentSource {
    /// Whether the environment was made for this project, found by its path
    /// or named by its manifests, rather than one the host happened to have
    /// active or installed. Only such an environment is used without a lock
    /// to check it against.
    pub fn is_project_bound(self) -> bool {
        matches!(
            self,
            EnvironmentSource::ProjectVenv
                | EnvironmentSource::UvProjectEnvironment
                | EnvironmentSource::Poetry
                | EnvironmentSource::Conda
        )
    }
}

/// A Python interpreter for pyright to take its search paths from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonEnvironment {
    pub interpreter: PathBuf,
    pub source: EnvironmentSource,
}

/// What environment discovery reads from the host: its variables, the home
/// directory, Kin's cache, whether
/// analysis environments are on, uv, and the platform. Injected so every
/// branch can be tested without the host's own Python or the network.
#[derive(Debug, Clone)]
pub struct PythonHost {
    pub vars: HashMap<String, String>,
    pub home: Option<PathBuf>,
    /// Kin's cache directory, `$KIN_HOME/cache`.
    pub cache: PathBuf,
    /// Whether Kin may build analysis environments
    /// ([`analysis_env::SWITCH_ENV`]).
    pub analysis_environments: bool,
    /// uv, for resolving a project that locks nothing.
    pub uv: Option<PathBuf>,
    pub platform: analysis::tags::Platform,
}

impl PythonHost {
    /// This process's host.
    pub fn current() -> Self {
        let vars: HashMap<String, String> = std::env::vars().collect();
        let home = vars.get("HOME").map(PathBuf::from);
        Self {
            vars,
            home,
            cache: analysis_env::kin_cache_dir(),
            analysis_environments: analysis_env::enabled(),
            uv: which::which("uv").ok(),
            platform: analysis::tags::Platform::host(),
        }
    }

    /// The part of the host the analysis environment reads.
    pub fn analysis_host(&self) -> analysis::Host<'_> {
        analysis::Host {
            vars: &self.vars,
            home: self.home.as_deref(),
            cache: &self.cache,
            uv: self.uv.as_deref(),
            platform: self.platform,
        }
    }

    fn var(&self, name: &str) -> Option<&str> {
        self.vars
            .get(name)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }
}

/// The interpreter of a virtual environment directory, when it is one.
fn venv_interpreter(dir: &Path) -> Option<PathBuf> {
    if !dir.join("pyvenv.cfg").is_file() && !dir.join("conda-meta").is_dir() {
        return None;
    }
    interpreter_in(dir)
}

/// The interpreter of an installation or environment prefix.
fn interpreter_in(prefix: &Path) -> Option<PathBuf> {
    [
        "bin/python3",
        "bin/python",
        "Scripts/python.exe",
        "python.exe",
    ]
    .iter()
    .map(|relative| prefix.join(relative))
    .find(|path| path.is_file())
}

fn read_toml(path: &Path) -> Option<toml::Table> {
    toml::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// The project name Poetry hashes into its environment's name.
fn poetry_project(root: &Path) -> Option<String> {
    let pyproject = read_toml(&root.join("pyproject.toml"))?;
    let poetry = pyproject
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(toml::Value::as_table);
    if poetry.is_none() && !root.join("poetry.lock").is_file() {
        return None;
    }
    poetry
        .and_then(|poetry| poetry.get("name"))
        .or_else(|| {
            pyproject
                .get("project")
                .and_then(|project| project.get("name"))
        })
        .and_then(toml::Value::as_str)
        .map(str::to_string)
}

/// Poetry's environment name for a project, `<name>-<hash>`, as
/// `EnvManager.generate_env_name` spells it: the name lowercased with shell
/// metacharacters replaced and cut at 42 characters, then the first eight
/// characters of the URL-safe base64 SHA-256 of the project's real path.
pub fn poetry_env_prefix(name: &str, project_dir: &Path) -> String {
    use sha2::Digest;
    let sanitized: String = name
        .to_lowercase()
        .chars()
        .map(|c| {
            if " $`!*@\"\\\r\n\t".contains(c) {
                '_'
            } else {
                c
            }
        })
        .take(42)
        .collect();
    let digest = sha2::Sha256::digest(project_dir.to_string_lossy().as_bytes());
    format!("{sanitized}-{}", urlsafe_base64_prefix(&digest[..6]))
}

/// URL-safe base64 of six bytes: exactly eight characters, no padding.
fn urlsafe_base64_prefix(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    bytes
        .chunks(3)
        .flat_map(|chunk| {
            let n = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            [18, 12, 6, 0].map(|shift| ALPHABET[((n >> shift) & 63) as usize] as char)
        })
        .collect()
}

fn poetry_cache(host: &PythonHost) -> Option<PathBuf> {
    if let Some(path) = host.var("POETRY_VIRTUALENVS_PATH") {
        return Some(PathBuf::from(path));
    }
    if let Some(cache) = host.var("POETRY_CACHE_DIR") {
        return Some(Path::new(cache).join("virtualenvs"));
    }
    let home = host.home.as_ref()?;
    if cfg!(target_os = "macos") {
        return Some(home.join("Library/Caches/pypoetry/virtualenvs"));
    }
    if cfg!(windows) {
        return host
            .var("LOCALAPPDATA")
            .map(|local| Path::new(local).join("pypoetry/Cache/virtualenvs"));
    }
    Some(
        host.var("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".cache"))
            .join("pypoetry/virtualenvs"),
    )
}

fn poetry_environment(root: &Path, host: &PythonHost) -> Option<PathBuf> {
    let name = poetry_project(root)?;
    let prefix = format!("{}-py", poetry_env_prefix(&name, root));
    let cache = poetry_cache(host)?;
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(&cache)
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .map(|entry| entry.path())
        .collect();
    candidates.sort();
    candidates
        .iter()
        .rev()
        .find_map(|dir| venv_interpreter(dir))
}

/// The environment name `environment.yml` gives, if any.
fn conda_env_name(root: &Path) -> Option<String> {
    ["environment.yml", "environment.yaml"]
        .iter()
        .find_map(|file| std::fs::read_to_string(root.join(file)).ok())?
        .lines()
        .find_map(|line| line.strip_prefix("name:"))
        .map(|name| {
            name.trim()
                .trim_matches(|c| c == '"' || c == '\'')
                .to_string()
        })
        .filter(|name| !name.is_empty())
}

fn conda_environment(root: &Path, host: &PythonHost) -> Option<PathBuf> {
    let name = conda_env_name(root)?;
    let mut env_dirs: Vec<PathBuf> = Vec::new();
    if let Some(paths) = host.var("CONDA_ENVS_PATH") {
        env_dirs.extend(std::env::split_paths(paths));
    }
    // The installation that CONDA_PREFIX or CONDA_EXE belong to.
    for prefix in [host.var("CONDA_PREFIX"), host.var("CONDA_EXE")]
        .into_iter()
        .flatten()
    {
        let prefix = Path::new(prefix);
        if prefix.file_name().is_some_and(|last| last == name.as_str()) {
            env_dirs.push(prefix.parent().map(Path::to_path_buf).unwrap_or_default());
        }
        for base in prefix.ancestors().take(4) {
            if base.join("conda-meta").is_dir() {
                env_dirs.push(base.join("envs"));
            }
        }
    }
    if let Some(home) = &host.home {
        for install in [
            ".conda",
            "miniconda3",
            "anaconda3",
            "miniforge3",
            "mambaforge",
        ] {
            env_dirs.push(home.join(install).join("envs"));
        }
    }
    env_dirs.extend(
        [
            "/opt/conda/envs",
            "/opt/homebrew/Caskroom/miniconda/base/envs",
            "/opt/homebrew/Caskroom/miniforge/base/envs",
        ]
        .map(PathBuf::from),
    );
    env_dirs
        .iter()
        .find_map(|dir| venv_interpreter(&dir.join(&name)))
}

fn pyenv_root(host: &PythonHost) -> Option<PathBuf> {
    host.var("PYENV_ROOT")
        .map(PathBuf::from)
        .or_else(|| host.home.as_ref().map(|home| home.join(".pyenv")))
        .filter(|root| root.join("versions").is_dir())
}

/// The installed pyenv version a version file's line names: the directory of
/// that name, or the newest installed version it is a prefix of (`3.12`
/// selects `3.12.4` over `3.12.1`), as pyenv resolves a prefix.
fn pyenv_version(pyenv: &Path, wanted: &str) -> Option<PathBuf> {
    let versions = pyenv.join("versions");
    if let Some(interpreter) = interpreter_in(&versions.join(wanted)) {
        return Some(interpreter);
    }
    let numeric = |name: &str| -> Vec<u64> {
        name.split(|c: char| !c.is_ascii_digit())
            .filter_map(|part| part.parse().ok())
            .collect()
    };
    let mut matching: Vec<String> = std::fs::read_dir(&versions)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .filter(|name| name.starts_with(&format!("{wanted}.")))
        .collect();
    matching.sort_by_key(|name| numeric(name));
    matching
        .iter()
        .rev()
        .find_map(|name| interpreter_in(&versions.join(name)))
}

/// The versions a pyenv version file lists, in order, without `system`.
fn version_file_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#') && *line != "system")
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The pyenv version the repository's `.python-version` names, when pyenv
/// has it installed. pyenv's global version is never used: the repository did
/// not choose it.
fn pyenv_environment(root: &Path, host: &PythonHost) -> Option<PythonEnvironment> {
    let local = root
        .ancestors()
        .map(|dir| dir.join(".python-version"))
        .find(|file| file.is_file())?;
    let pyenv = pyenv_root(host)?;
    version_file_lines(&local)
        .iter()
        .find_map(|version| pyenv_version(&pyenv, version))
        .map(|interpreter| PythonEnvironment {
            interpreter,
            source: EnvironmentSource::PyenvLocal,
        })
}

/// Every environment of the user's that could serve the repository at
/// `root`, in the order a developer's own tools would pick one:
///
/// 1. uv's project environment when `UV_PROJECT_ENVIRONMENT` moves it;
/// 2. a virtual environment inside the repository (`.venv`, `venv`, `env`);
/// 3. the virtual environment active where Kin was started;
/// 4. Poetry's environment for the project in Poetry's cache;
/// 5. the conda environment `environment.yml` names;
/// 6. the pyenv version `.python-version` names.
pub fn find_environments(root: &Path, host: &PythonHost) -> Vec<PythonEnvironment> {
    let mut found = Vec::new();
    let mut push = |interpreter: Option<PathBuf>, source| {
        if let Some(interpreter) = interpreter {
            found.push(PythonEnvironment {
                interpreter,
                source,
            });
        }
    };
    if root.join("uv.lock").is_file() {
        if let Some(dir) = host.var("UV_PROJECT_ENVIRONMENT") {
            push(
                venv_interpreter(&root.join(dir)),
                EnvironmentSource::UvProjectEnvironment,
            );
        }
    }
    push(
        [".venv", "venv", "env", ".env"]
            .iter()
            .find_map(|dir| venv_interpreter(&root.join(dir))),
        EnvironmentSource::ProjectVenv,
    );
    push(
        host.var("VIRTUAL_ENV")
            .and_then(|dir| venv_interpreter(Path::new(dir))),
        EnvironmentSource::ActiveVirtualEnv,
    );
    push(poetry_environment(root, host), EnvironmentSource::Poetry);
    push(conda_environment(root, host), EnvironmentSource::Conda);
    if let Some(pyenv) = pyenv_environment(root, host) {
        found.push(pyenv);
    }
    found
}

/// The first environment of the user's that could serve the repository.
pub fn find_environment(root: &Path, host: &PythonHost) -> Option<PythonEnvironment> {
    find_environments(root, host).into_iter().next()
}

/// The Python version of an environment, read from its `pyvenv.cfg` or its
/// site-packages directory's name, without running it.
fn environment_python(prefix: &Path) -> Option<(u32, String)> {
    if let Ok(text) = std::fs::read_to_string(prefix.join("pyvenv.cfg")) {
        for key in ["version_info", "version"] {
            let value = text.lines().find_map(|line| {
                let (name, value) = line.split_once('=')?;
                (name.trim() == key).then(|| value.trim().to_string())
            });
            if let Some(value) = value {
                let release: Vec<&str> = value.split('.').take(3).collect();
                if let Some(minor) = release.get(1).and_then(|m| m.parse().ok()) {
                    return Some((minor, release.join(".")));
                }
            }
        }
    }
    let site = analysis::store::site_packages_under(prefix)
        .into_iter()
        .next()?;
    let name = site.parent()?.file_name()?.to_str()?.to_string();
    let minor: u32 = name.strip_prefix("python3.")?.parse().ok()?;
    Some((minor, format!("3.{minor}.0")))
}

/// Whether a user environment holds every package the lock names for it, at
/// the locked version. The error says what differs.
fn matches_lock(
    environment: &PythonEnvironment,
    lock: &analysis::lockfile::Lock,
    root: &Path,
    platform: analysis::tags::Platform,
) -> Result<(), String> {
    let prefix = environment
        .interpreter
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "has no installation prefix".to_string())?;
    let (minor, full_version) = environment_python(prefix)
        .ok_or_else(|| "its Python version could not be read".to_string())?;
    let target = analysis::plan::Target {
        full_version,
        minor,
        platform,
    };
    let plan = analysis::plan::plan(lock, root, &target);
    let installed: HashMap<String, String> = analysis::store::site_packages_under(prefix)
        .iter()
        .flat_map(|site| analysis::store::installed_distributions(site))
        .collect();
    let mut missing = Vec::new();
    let mut different = Vec::new();
    for package in &plan.packages {
        match installed.get(&analysis::lockfile::normalize_name(&package.name)) {
            None => missing.push(package.pin()),
            Some(version) if !analysis::markers::same_version(version, &package.version) => {
                different.push(format!(
                    "has {} {version} where the lock pins {}",
                    package.name, package.version
                ));
            }
            Some(_) => {}
        }
    }
    if missing.is_empty() && different.is_empty() {
        return Ok(());
    }
    let mut reasons = different;
    if !missing.is_empty() {
        reasons.push(format!(
            "lacks {} locked package(s), such as {}",
            missing.len(),
            missing
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Err(reasons.join("; "))
}

/// One Python project the repository holds: a directory with a project
/// manifest beside its code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonProject {
    /// The directory holding the manifest.
    pub dir: PathBuf,
    /// The distribution name the manifest declares, when it declares one
    /// statically (`[project] name`, `[tool.poetry] name`, `setup.cfg`'s
    /// `[metadata] name`). A `setup.py` is never run to learn it.
    pub name: Option<String>,
    /// Its `src` directory, for a src-layout project.
    pub src: Option<PathBuf>,
}

/// The distribution name a project's manifests declare without running
/// anything.
fn declared_name(dir: &Path) -> Option<String> {
    if let Some(pyproject) = read_toml(&dir.join("pyproject.toml")) {
        let name = pyproject
            .get("project")
            .and_then(|project| project.get("name"))
            .or_else(|| {
                pyproject
                    .get("tool")
                    .and_then(|tool| tool.get("poetry"))
                    .and_then(|poetry| poetry.get("name"))
            })
            .and_then(toml::Value::as_str);
        if let Some(name) = name {
            return Some(name.to_string());
        }
    }
    let setup_cfg = std::fs::read_to_string(dir.join("setup.cfg")).ok()?;
    let mut in_metadata = false;
    for line in setup_cfg.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_metadata = line == "[metadata]";
        } else if in_metadata {
            if let Some((key, value)) = line.split_once('=') {
                if key.trim() == "name" && !value.trim().is_empty() {
                    return Some(value.trim().to_string());
                }
            }
        }
    }
    None
}

/// Every Python project at the root and one or two directories below it,
/// shallowest first.
pub fn python_projects(root: &Path) -> Vec<PythonProject> {
    let children = |dir: &Path| -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut dirs: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| !super::repo_scan::is_generated_dir(&entry.path(), name))
            })
            .map(|entry| entry.path())
            .collect();
        dirs.sort();
        dirs
    };
    let mut projects = vec![root.to_path_buf()];
    for child in children(root) {
        projects.extend(children(&child));
        projects.push(child);
    }
    projects.sort_by_key(|dir| (dir.components().count(), dir.clone()));
    projects
        .into_iter()
        .filter(|project| {
            ["pyproject.toml", "setup.py", "setup.cfg"]
                .iter()
                .any(|manifest| project.join(manifest).is_file())
        })
        .map(|dir| {
            let src = dir.join("src");
            PythonProject {
                name: declared_name(&dir),
                src: (src.is_dir() && !src.join("__init__.py").is_file()).then_some(src),
                dir,
            }
        })
        .collect()
}

/// Every `src` directory of a src-layout project: the root's own and those of
/// projects one or two directories below it. A `src` is one when a project
/// manifest sits beside it and it is not itself a package.
pub fn source_roots(root: &Path) -> Vec<PathBuf> {
    python_projects(root)
        .into_iter()
        .filter_map(|project| project.src)
        .collect()
}

/// The project model of a Python repository: its projects, each mapped from
/// its distribution name to the directory its packages are imported from.
pub fn project_model(root: &Path) -> ProjectModel {
    let projects = python_projects(root);
    let mut model = ProjectModel {
        roots: vec![root.to_path_buf()],
        ..ProjectModel::default()
    };
    for project in projects {
        let source = project.src.clone().unwrap_or_else(|| project.dir.clone());
        let name = project.name.clone().unwrap_or_else(|| {
            project
                .dir
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default()
        });
        model
            .workspace_map
            .entry(name.clone())
            .or_insert_with(|| source.clone());
        model.packages.push(ProjectPackage {
            name,
            dir: project.dir,
            source_roots: vec![source],
            config: None,
        });
    }
    model
}

/// The source roots a model's src-layout projects hand pyright as
/// `extraPaths`, so the repository's own packages resolve from the workspace
/// rather than from a copy installed in an environment.
fn extra_paths(model: &ProjectModel) -> Vec<PathBuf> {
    model
        .packages
        .iter()
        .flat_map(|package| {
            package
                .source_roots
                .iter()
                .filter(|source| **source != package.dir)
        })
        .cloned()
        .collect()
}

/// The settings pyright asks for, for a repository whose environment runs
/// `interpreter` and whose own packages are under these source roots.
pub fn settings_for(interpreter: Option<&Path>, source_roots: &[PathBuf]) -> serde_json::Value {
    let mut analysis = serde_json::json!({
        // Sent explicitly: pyright turns it off whenever the section exists
        // and does not set it.
        "autoSearchPaths": true,
        "useLibraryCodeForTypes": true,
        "diagnosticMode": "openFilesOnly",
    });
    if !source_roots.is_empty() {
        analysis["extraPaths"] = serde_json::json!(source_roots
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>());
    }
    let mut python = serde_json::json!({ "analysis": analysis });
    if let Some(interpreter) = interpreter {
        python["pythonPath"] = serde_json::json!(interpreter.display().to_string());
    }
    serde_json::json!({ "python": python })
}

/// The interpreter pyright is pointed at when no environment the repository
/// chose has one yet. It does not exist: pyright finds nothing there, so it
/// reads no packages at all, where without a `pythonPath` it would run the
/// `python` on its `PATH` and read that interpreter's.
pub fn no_interpreter(host: &PythonHost) -> PathBuf {
    analysis::store_dir(&host.cache).join("no-interpreter/bin/python3")
}

/// The normalized names of the repository's own packages.
fn own_packages(model: &ProjectModel) -> BTreeSet<String> {
    model
        .workspace_map
        .keys()
        .map(|name| analysis::lockfile::normalize_name(name))
        .collect()
}

fn user_environment(
    environment: &PythonEnvironment,
    checked_against: Option<PathBuf>,
) -> Environment {
    let description = format!(
        "{} ({:?})",
        environment.interpreter.display(),
        environment.source
    );
    let prefix = environment
        .interpreter
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf);
    let version = prefix
        .as_deref()
        .and_then(environment_python)
        .map_or_else(|| "unknown".to_string(), |(_, full)| full);
    let identity_lock = checked_against
        .as_deref()
        .and_then(super::contract::file_digest)
        .unwrap_or_default();
    Environment {
        identity: EnvironmentIdentity::of(&["python", "user", &description, &identity_lock]),
        toolchain: Some(Toolchain {
            name: "python".to_string(),
            version,
            pinned_by: format!("the user's environment ({:?})", environment.source),
            location: Some(environment.interpreter.clone()),
            substitute: None,
        }),
        dependencies: vec![DependencySource {
            description: format!("the site-packages of {}", environment.interpreter.display()),
            location: prefix,
            lock: checked_against.clone(),
        }],
        provider: Provider::UserEnvironment {
            description,
            checked_against,
        },
        pending: None,
    }
}

/// The environment pyright analyses the repository at `root` against, from
/// the first provider that has one:
///
/// 1. the user's own environment, when it holds every package the lock
///    names at the locked version, or, for a repository with no lock, when it
///    belongs to the project;
/// 2. Kin's analysis environment, from the lock, or from Kin's resolution of
///    the declared requirements when there is no lock;
/// 3. none, with the reason.
///
/// Nothing here touches the network. An analysis environment not yet in the
/// store is returned with [`Environment::pending`] set, for
/// [`provision_with`] to fetch.
pub fn environment_with(root: &Path, model: &ProjectModel, host: &PythonHost) -> Environment {
    let search = analysis::lockfile::find_lock(root);
    let lock = match &search {
        analysis::lockfile::LockSearch::Found(lock) => Some(lock),
        _ => None,
    };
    let lock_path = lock.and_then(|lock| lock.files.first().cloned());
    let mut passed_over = Vec::new();
    for candidate in find_environments(root, host) {
        let name = format!(
            "{} ({:?})",
            candidate.interpreter.display(),
            candidate.source
        );
        match lock {
            Some(lock) => match matches_lock(&candidate, lock, root, host.platform) {
                Ok(()) => return user_environment(&candidate, lock_path),
                Err(reason) => passed_over.push(format!("{name} {reason}")),
            },
            None if candidate.source.is_project_bound() => {
                return user_environment(&candidate, None);
            }
            None => passed_over.push(format!(
                "{name} is not the project's own, and there is no lock to check it against"
            )),
        }
    }
    let passed_over = if passed_over.is_empty() {
        String::new()
    } else {
        format!(
            "; the user's environment was passed over: {}",
            passed_over.join("; ")
        )
    };
    let sentinel = no_interpreter(host);
    let missing = |reason: String, identity: EnvironmentIdentity| Environment {
        toolchain: Some(Toolchain {
            name: "python".to_string(),
            version: "none".to_string(),
            pinned_by: "no environment the repository chose has an interpreter".to_string(),
            location: Some(sentinel.clone()),
            substitute: None,
        }),
        dependencies: Vec::new(),
        provider: Provider::Missing { reason },
        identity,
        pending: None,
    };
    if !host.analysis_environments {
        return missing(
            format!(
                "analysis environments are off ({}){passed_over}",
                analysis_env::SWITCH_ENV
            ),
            EnvironmentIdentity::of(&["python", "missing", "analysis environments off"]),
        );
    }
    let Some(assessment) =
        analysis::assess(root, &own_packages(model), &host.analysis_host(), &search)
    else {
        return missing(
            format!(
                "Kin pins no CPython build for this platform ({}){passed_over}",
                host.platform.id()
            ),
            EnvironmentIdentity::of(&["python", "missing", "unsupported platform"]),
        );
    };
    let interpreter = if assessment.ready {
        assessment.interpreter()
    } else {
        sentinel.clone()
    };
    let site = analysis::store::site_packages(&assessment.dir, assessment.pin.target.minor);
    let packages = assessment
        .plan
        .as_ref()
        .map_or(0, |plan| plan.packages.len());
    let (provider, lock_file) = match &assessment.dependencies {
        analysis::Dependencies::Locked(lock) => {
            let path = lock.files.first().cloned().unwrap_or_default();
            (
                Provider::KinAnalysisEnvironment {
                    description: format!(
                        "{packages} locked package(s) for CPython {}",
                        assessment.pin.build.version
                    ),
                    basis: EnvironmentBasis::Lockfile { path: path.clone() },
                },
                Some(path),
            )
        }
        analysis::Dependencies::Resolved(lock) => (
            Provider::KinAnalysisEnvironment {
                description: format!(
                    "{packages} package(s) resolved from the declared requirements for CPython {}",
                    assessment.pin.build.version
                ),
                basis: EnvironmentBasis::ResolvedNotLocked {
                    resolver: "uv --no-build".to_string(),
                },
            },
            lock.files.first().cloned(),
        ),
        analysis::Dependencies::Unresolved(declared) => (
            Provider::KinAnalysisEnvironment {
                description: format!(
                    "{} declared requirement(s), not resolved yet",
                    declared.requirements.len()
                ),
                basis: EnvironmentBasis::ResolvedNotLocked {
                    resolver: "uv --no-build".to_string(),
                },
            },
            None,
        ),
        analysis::Dependencies::Missing(reason) => (
            Provider::Missing {
                reason: format!("{reason}{passed_over}"),
            },
            None,
        ),
    };
    // Nothing to fetch for a repository that has no dependencies Kin can
    // provide and states no Python version: an interpreter of Kin's choosing
    // would tell pyright nothing its own default does not.
    let nothing_to_fetch = matches!(assessment.dependencies, analysis::Dependencies::Missing(_))
        && !assessment.pin.stated;
    let pending =
        (!assessment.ready && !nothing_to_fetch).then(|| match &assessment.dependencies {
            analysis::Dependencies::Unresolved(_) => format!(
                "resolve the declared requirements with uv without building, then fetch them and \
             CPython {}",
                assessment.pin.build.version
            ),
            analysis::Dependencies::Missing(_) => {
                format!("fetch CPython {}", assessment.pin.build.version)
            }
            _ => format!(
                "fetch {packages} locked package(s) and CPython {}",
                assessment.pin.build.version
            ),
        });
    Environment {
        toolchain: Some(Toolchain {
            name: "python".to_string(),
            version: assessment.pin.build.version.to_string(),
            pinned_by: assessment.pin.pinned_by.clone(),
            location: Some(interpreter),
            substitute: None,
        }),
        dependencies: vec![DependencySource {
            description: match &provider {
                Provider::Missing { .. } => "no dependencies".to_string(),
                _ => format!("{packages} package(s) in Kin's analysis environment"),
            },
            location: Some(site),
            lock: lock_file,
        }],
        provider,
        identity: assessment.identity,
        pending,
    }
}

/// pyright's configuration for a model and an environment.
pub fn configure(model: &ProjectModel, environment: &Environment) -> ServerLaunch {
    let interpreter = environment
        .toolchain
        .as_ref()
        .and_then(|toolchain| toolchain.location.clone());
    let has_interpreter = interpreter.as_deref().is_some_and(Path::exists);
    let label = match &environment.provider {
        Provider::UserEnvironment { description, .. } => format!("pyright with {description}"),
        Provider::KinAnalysisEnvironment { description, .. } if has_interpreter => format!(
            "pyright with Kin's analysis environment {} ({description})",
            &environment.identity.hex()[..12]
        ),
        Provider::KinAnalysisEnvironment { .. } => {
            "pyright with no environment until Kin's analysis environment is fetched".to_string()
        }
        Provider::Missing { .. } if has_interpreter => format!(
            "pyright with CPython {} and no dependencies (environment missing)",
            environment
                .toolchain
                .as_ref()
                .map_or("", |toolchain| toolchain.version.as_str())
        ),
        Provider::Missing { .. } => "pyright with no environment (environment missing)".to_string(),
    };
    ServerLaunch {
        settings: Some(settings_for(interpreter.as_deref(), &extra_paths(model))),
        label,
        ..ServerLaunch::default()
    }
}

/// The project model, with every extra and group loaded, as the analysis
/// environment loads them.
fn model_with_all_extras(root: &Path) -> ProjectModel {
    let mut model = project_model(root);
    model.variants.extras = Selection::All;
    model
}

/// The launch for a repository, with the host it runs on.
pub fn launch_with(root: &Path, host: &PythonHost) -> ServerLaunch {
    let model = model_with_all_extras(root);
    let environment = environment_with(root, &model, host);
    let mut launch = configure(&model, &environment);
    launch.resolution = Some(super::Resolution::new(&model, environment));
    launch
}

/// Fetch and build what the repository's environment has pending, with the
/// host it runs on. `None` when nothing is pending: the user's environment
/// serves, the analysis environment is already built, or none is allowed.
pub fn provision_with(
    root: &Path,
    host: &PythonHost,
    fetcher: &dyn analysis_env::fetch::Fetcher,
) -> Option<ProvisionReport> {
    let model = model_with_all_extras(root);
    let environment = environment_with(root, &model, host);
    environment.pending.as_ref()?;
    Some(analysis::provision(
        root,
        &own_packages(&model),
        &host.analysis_host(),
        fetcher,
    ))
}

impl LspAdapter for PyrightAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Python
    }

    fn server_command(&self) -> &str {
        "pyright-langserver"
    }

    fn server_args(&self) -> Vec<String> {
        vec!["--stdio".to_string()]
    }

    fn file_extensions(&self) -> &[&str] {
        &["py", "pyi"]
    }

    fn workspace_settings(&self, workspace_root: &Path) -> Option<serde_json::Value> {
        self.launch(workspace_root).settings
    }

    fn project_model(&self, workspace_root: &Path) -> ProjectModel {
        model_with_all_extras(workspace_root)
    }

    fn environment(&self, workspace_root: &Path, model: &ProjectModel) -> Environment {
        environment_with(workspace_root, model, &PythonHost::current())
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
        let host = PythonHost::current();
        if !host.analysis_environments {
            return None;
        }
        let network = host.analysis_host().index().network;
        let fetcher = match analysis_env::fetch::HttpFetcher::new(&network) {
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

    fn venv(fixture: &Fixture, dir: &str) -> PathBuf {
        fixture.write(&format!("{dir}/pyvenv.cfg"), "home = /usr/bin\n");
        fixture.write(&format!("{dir}/bin/python3"), "")
    }

    fn host(home: &Path) -> PythonHost {
        PythonHost {
            vars: HashMap::new(),
            home: Some(home.to_path_buf()),
            cache: home.join("kin-cache"),
            analysis_environments: true,
            uv: None,
            platform: analysis::tags::Platform {
                os: analysis::tags::Os::Mac(Some((15, 0))),
                arch: "aarch64",
            },
        }
    }

    #[test]
    fn a_project_venv_wins_over_every_outside_environment() {
        let repo = Fixture::new("py-venv");
        let home = Fixture::new("py-home");
        let interpreter = venv(&repo, ".venv");
        venv(&home, "active");
        let mut host = host(&home.root);
        host.vars.insert(
            "VIRTUAL_ENV".into(),
            home.root.join("active").display().to_string(),
        );
        assert_eq!(
            find_environment(&repo.root, &host),
            Some(PythonEnvironment {
                interpreter,
                source: EnvironmentSource::ProjectVenv
            })
        );
    }

    #[test]
    fn a_directory_without_pyvenv_cfg_is_not_an_environment() {
        let repo = Fixture::new("py-not-venv");
        let home = Fixture::new("py-home-empty");
        repo.write("venv/bin/python3", "");
        assert_eq!(find_environment(&repo.root, &host(&home.root)), None);
    }

    #[test]
    fn uv_project_environment_moves_the_venv() {
        let repo = Fixture::new("py-uv");
        let home = Fixture::new("py-home-uv");
        repo.write("uv.lock", "");
        venv(&repo, ".venv");
        let moved = venv(&repo, "envs/dev");
        let mut host = host(&home.root);
        host.vars
            .insert("UV_PROJECT_ENVIRONMENT".into(), "envs/dev".into());
        assert_eq!(
            find_environment(&repo.root, &host),
            Some(PythonEnvironment {
                interpreter: moved,
                source: EnvironmentSource::UvProjectEnvironment
            })
        );
    }

    /// Poetry names its environment `<name>-<hash>-py<version>`; the hash is
    /// pinned against the value Poetry itself computes for this path.
    #[test]
    fn poetry_environment_is_found_by_its_hashed_name() {
        assert_eq!(
            poetry_env_prefix("My App", Path::new("/home/me/my-app")),
            "my_app-zDamOCZz"
        );
        let repo = Fixture::new("py-poetry");
        let cache = Fixture::new("py-poetry-cache");
        repo.write(
            "pyproject.toml",
            "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        );
        let dir = format!("{}-py3.12", poetry_env_prefix("demo", &repo.root));
        let interpreter = venv(&cache, &dir);
        venv(&cache, "demo-XXXXXXXX-py3.12");
        let mut host = host(&cache.root);
        host.vars.insert(
            "POETRY_VIRTUALENVS_PATH".into(),
            cache.root.display().to_string(),
        );
        assert_eq!(
            find_environment(&repo.root, &host),
            Some(PythonEnvironment {
                interpreter,
                source: EnvironmentSource::Poetry
            })
        );
    }

    #[test]
    fn conda_environment_is_found_by_the_name_environment_yml_gives() {
        let repo = Fixture::new("py-conda");
        let home = Fixture::new("py-home-conda");
        repo.write(
            "environment.yml",
            "name: science\ndependencies:\n  - numpy\n",
        );
        home.write("miniconda3/envs/science/conda-meta/history", "");
        let interpreter = home.write("miniconda3/envs/science/bin/python3", "");
        assert_eq!(
            find_environment(&repo.root, &host(&home.root)),
            Some(PythonEnvironment {
                interpreter,
                source: EnvironmentSource::Conda
            })
        );
    }

    /// fastapi's shape: `.python-version` names 3.11, which pyenv does not
    /// have. The local version serves when it is installed, as a prefix of
    /// the newest match; pyenv's global version never does.
    #[test]
    fn pyenv_serves_only_the_version_the_repository_names() {
        let repo = Fixture::new("py-pyenv");
        let home = Fixture::new("py-home-pyenv");
        repo.write(".python-version", "3.11\n");
        home.write(".pyenv/version", "3.12.4\n");
        home.write(".pyenv/versions/3.12.4/bin/python3", "");
        let host = host(&home.root);
        assert_eq!(find_environment(&repo.root, &host), None);

        home.write(".pyenv/versions/3.11.2/bin/python3", "");
        let newest = home.write(".pyenv/versions/3.11.10/bin/python3", "");
        assert_eq!(
            find_environment(&repo.root, &host),
            Some(PythonEnvironment {
                interpreter: newest,
                source: EnvironmentSource::PyenvLocal
            })
        );
    }

    /// Without a version file, pyenv's versions are not the repository's
    /// business, even when pyenv's shims are on `PATH`.
    #[test]
    fn pyenv_global_is_never_the_repositorys_environment() {
        let repo = Fixture::new("py-no-pyenv");
        let home = Fixture::new("py-home-no-pyenv");
        home.write(".pyenv/version", "3.12.4\n");
        home.write(".pyenv/versions/3.12.4/bin/python3", "");
        let mut host = host(&home.root);
        host.vars.insert("PYENV_VERSION".into(), "3.12.4".into());
        assert_eq!(find_environment(&repo.root, &host), None);
        let launch = launch_with(&repo.root, &host);
        let settings = launch.settings.unwrap();
        assert!(
            !settings["python"]["pythonPath"]
                .as_str()
                .unwrap()
                .contains(".pyenv"),
            "{settings}"
        );
    }

    /// A lock with one package at one version, and a user environment
    /// holding `installed` of it.
    fn locked_repo(tag: &str, installed: Option<&str>) -> (Fixture, Fixture) {
        let repo = Fixture::new(tag);
        let home = Fixture::new(&format!("{tag}-home"));
        repo.write(
            "pyproject.toml",
            "[project]\nname = \"app\"\ndependencies = [\"idna\"]\n",
        );
        repo.write(".python-version", "3.12\n");
        repo.write(
            "uv.lock",
            &format!(
                "version = 1\nrevision = 3\nrequires-python = \">=3.10\"\n\n\
                 [[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = {{ editable = \".\" }}\n\
                 dependencies = [{{ name = \"idna\" }}]\n\n\
                 [[package]]\nname = \"idna\"\nversion = \"3.10\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\n\
                 wheels = [{{ url = \"https://files.pythonhosted.org/idna-3.10-py3-none-any.whl\", hash = \"sha256:{}\" }}]\n",
                "a".repeat(64)
            ),
        );
        if let Some(version) = installed {
            repo.write(
                ".venv/pyvenv.cfg",
                "home = /usr/bin\nversion_info = 3.12.4.final.0\n",
            );
            repo.write(".venv/bin/python3", "");
            repo.write(
                &format!(".venv/lib/python3.12/site-packages/idna-{version}.dist-info/METADATA"),
                "Name: idna\n",
            );
        }
        (repo, home)
    }

    /// The user's environment serves when it holds the locked versions, and
    /// is passed over, with the reason kept, when it does not.
    #[test]
    fn the_users_environment_serves_only_when_it_matches_the_lock() {
        let (repo, home) = locked_repo("py-match", Some("3.10"));
        let environment = launch_with(&repo.root, &host(&home.root))
            .resolution
            .unwrap()
            .environment;
        assert!(
            matches!(
                &environment.provider,
                Provider::UserEnvironment { checked_against: Some(lock), .. }
                    if lock.ends_with("uv.lock")
            ),
            "{:?}",
            environment.provider
        );

        let (repo, home) = locked_repo("py-mismatch", Some("3.7"));
        let launch = launch_with(&repo.root, &host(&home.root));
        let environment = launch.resolution.unwrap().environment;
        assert!(
            matches!(
                &environment.provider,
                Provider::KinAnalysisEnvironment { .. }
            ),
            "{:?}",
            environment.provider
        );
        assert!(environment
            .pending
            .as_deref()
            .is_some_and(|p| p.contains("1 locked package")));
        // Until the analysis environment is fetched, pyright gets no
        // interpreter at all rather than the mismatched one or PATH's.
        let settings = launch.settings.unwrap();
        let python_path = settings["python"]["pythonPath"].as_str().unwrap();
        assert!(python_path.contains("no-interpreter"), "{python_path}");
        assert!(launch
            .label
            .contains("until Kin's analysis environment is fetched"));
    }

    /// A built analysis environment in the store serves: its interpreter is
    /// the pythonPath, and the repository's own package is not in it.
    #[test]
    fn a_built_analysis_environment_is_the_pythonpath() {
        let (repo, home) = locked_repo("py-kin-env", None);
        let host = host(&home.root);
        let model = model_with_all_extras(&repo.root);
        let search = analysis::lockfile::find_lock(&repo.root);
        let assessment = analysis::assess(
            &repo.root,
            &own_packages(&model),
            &host.analysis_host(),
            &search,
        )
        .unwrap();
        let plan = assessment.plan.as_ref().unwrap();
        assert_eq!(plan.in_repo[0].0, "app");
        assert_eq!(plan.packages.len(), 1);
        std::fs::create_dir_all(assessment.dir.join("bin")).unwrap();
        std::fs::write(assessment.interpreter(), "").unwrap();

        let launch = launch_with(&repo.root, &host);
        let resolution = launch.resolution.unwrap();
        assert_eq!(resolution.environment.pending, None);
        assert!(matches!(
            &resolution.environment.provider,
            Provider::KinAnalysisEnvironment {
                basis: EnvironmentBasis::Lockfile { .. },
                ..
            }
        ));
        let toolchain = resolution.environment.toolchain.unwrap();
        assert_eq!(toolchain.version, "3.12.14");
        assert_eq!(toolchain.pinned_by, ".python-version names 3.12");
        assert_eq!(
            launch.settings.unwrap()["python"]["pythonPath"],
            assessment.interpreter().display().to_string()
        );
        assert!(launch
            .label
            .starts_with("pyright with Kin's analysis environment"));
    }

    /// With analysis environments off and no matching environment of the
    /// user's, the environment is missing and says why.
    #[test]
    fn switched_off_the_environment_is_missing() {
        let (repo, home) = locked_repo("py-off", Some("3.7"));
        let mut host = host(&home.root);
        host.analysis_environments = false;
        let resolution = launch_with(&repo.root, &host).resolution.unwrap();
        let reason = resolution.environment.missing_reason().unwrap();
        assert!(reason.contains("analysis environments are off"), "{reason}");
        assert!(
            reason.contains("has idna 3.7 where the lock pins 3.10"),
            "{reason}"
        );
        assert!(resolution.status_lines()[1].starts_with("environment missing: "));
    }

    /// A repository with no dependencies Kin can provide and no Python
    /// version stated has nothing to fetch: its environment is missing, and
    /// pyright is pointed at no interpreter rather than one of Kin's choosing.
    #[test]
    fn nothing_is_fetched_for_a_repository_that_pins_nothing() {
        let repo = Fixture::new("py-nothing");
        let home = Fixture::new("py-nothing-home");
        repo.write("scripts/tool.py", "print(1)\n");
        let resolution = launch_with(&repo.root, &host(&home.root))
            .resolution
            .unwrap();
        assert_eq!(resolution.environment.pending, None);
        assert!(resolution.environment.missing_reason().is_some());

        repo.write(".python-version", "3.12\n");
        let resolution = launch_with(&repo.root, &host(&home.root))
            .resolution
            .unwrap();
        assert_eq!(
            resolution.environment.pending.as_deref(),
            Some("fetch CPython 3.12.14")
        );
    }

    /// An active virtual environment is used only when it matches a lock:
    /// with no lock, it is not the project's to use.
    #[test]
    fn an_active_environment_without_a_lock_is_passed_over() {
        let repo = Fixture::new("py-active");
        let home = Fixture::new("py-active-home");
        venv(&home, "active");
        let mut host = host(&home.root);
        host.vars.insert(
            "VIRTUAL_ENV".into(),
            home.root.join("active").display().to_string(),
        );
        let environment = launch_with(&repo.root, &host)
            .resolution
            .unwrap()
            .environment;
        let reason = environment.missing_reason().unwrap();
        assert!(reason.contains("not the project's own"), "{reason}");
    }

    /// requests' shape: `src/requests` beside `pyproject.toml`. A monorepo's
    /// nested projects add their own `src`; a `src` that is a package is not
    /// a source root.
    #[test]
    fn src_layouts_become_extra_paths() {
        let repo = Fixture::new("py-src");
        repo.write("pyproject.toml", "[project]\nname = \"requests\"\n");
        repo.write("src/requests/__init__.py", "");
        repo.write("packages/tool/setup.py", "");
        repo.write("packages/tool/src/tool/__init__.py", "");
        repo.write("legacy/setup.cfg", "");
        repo.write("legacy/src/__init__.py", "");
        repo.write("docs/src/readme.txt", "");
        assert_eq!(
            source_roots(&repo.root),
            vec![repo.root.join("src"), repo.root.join("packages/tool/src")]
        );
    }

    /// Discovery reads each project's distribution name from its manifests,
    /// never from running `setup.py`, and maps it to where its packages are
    /// imported from.
    #[test]
    fn discovery_names_projects_from_their_manifests() {
        let repo = Fixture::new("py-discovery");
        repo.write("pyproject.toml", "[project]\nname = \"requests\"\n");
        repo.write("src/requests/__init__.py", "");
        repo.write("plugins/tool/setup.cfg", "[metadata]\nname = tool-plugin\n");
        repo.write("plugins/tool/tool/__init__.py", "");
        repo.write("legacy/setup.py", "raise SystemExit('never run')\n");
        let model = project_model(&repo.root);
        let names: Vec<&str> = model.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["requests", "legacy", "tool-plugin"]);
        assert_eq!(model.workspace_map["requests"], repo.root.join("src"));
        assert_eq!(
            model.workspace_map["tool-plugin"],
            repo.root.join("plugins/tool")
        );
        assert_eq!(extra_paths(&model), vec![repo.root.join("src")]);
    }

    /// The settings pyright asks for: `python.pythonPath` when an environment
    /// was found, and `python.analysis` with the search paths kept on.
    #[test]
    fn settings_carry_the_interpreter_and_the_source_roots() {
        let settings = settings_for(
            Some(Path::new("/repo/.venv/bin/python3")),
            &[PathBuf::from("/repo/src")],
        );
        assert_eq!(settings["python"]["pythonPath"], "/repo/.venv/bin/python3");
        assert_eq!(settings["python"]["analysis"]["autoSearchPaths"], true);
        assert_eq!(
            settings["python"]["analysis"]["extraPaths"],
            serde_json::json!(["/repo/src"])
        );
        let bare = settings_for(None, &[]);
        assert!(bare["python"].get("pythonPath").is_none(), "{bare}");
        assert!(bare["python"]["analysis"].get("extraPaths").is_none());
    }

    /// Nothing reaches pyright through `initializationOptions`: it would not
    /// read it. Everything is in the settings it asks for.
    #[test]
    fn the_launch_sends_settings_and_no_initialization_options() {
        let repo = Fixture::new("py-launch");
        let home = Fixture::new("py-home-launch");
        venv(&repo, ".venv");
        let launch = launch_with(&repo.root, &host(&home.root));
        assert_eq!(launch.initialization_options, None);
        let settings = launch.settings.expect("settings");
        assert!(settings["python"]["pythonPath"]
            .as_str()
            .unwrap()
            .ends_with(".venv/bin/python3"));
        assert!(launch.label.contains("ProjectVenv"), "{}", launch.label);
    }
}
