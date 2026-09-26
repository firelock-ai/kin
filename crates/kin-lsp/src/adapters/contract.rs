// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The one contract every language adapter follows to load a repository's code
//! and find its dependencies.
//!
//! An adapter answers three questions, always in this order, and only the way
//! each question is answered differs between languages:
//!
//! 1. **Project model.** Which code the repository holds, read from its
//!    manifests alone and never by running a build: the workspace roots, the
//!    packages and their source roots, the build variants (Cargo features, Go
//!    build tags, TypeScript export conditions, Python extras), a map from each
//!    workspace package's name to its source, and the files no build owns.
//! 2. **Environment.** The toolchain the repository pins and the dependencies
//!    its lockfile names, from exactly one [`Provider`], tried in this order:
//!    the user's own environment when it matches the lock, Kin's analysis
//!    environment (fetched, hash-verified and shared under `KIN_HOME`), or
//!    [`Provider::Missing`] with the reason. Nothing is answered from an
//!    environment the repository did not choose.
//! 3. **Server configuration.** The adapter translates the model and the
//!    environment into its server's own settings, a
//!    [`ServerLaunch`](super::ServerLaunch). Workspace packages always resolve
//!    to their source, even where build output exists.
//!
//! No step runs repository or dependency code: no build script, procedural
//! macro, `setup.py`, package build, install script, Gradle build or CMake
//! configure. A step that would need one reports what is missing instead.
//!
//! [`Resolution`] carries the answers to the first two questions beside the
//! configuration, so every language reports "environment missing", "not in any
//! build" and "project model missing" in the same words.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::Digest;

/// What a repository's manifests say about its code.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProjectModel {
    /// Whether a model could be read at all.
    pub state: ModelState,
    /// The workspace roots the server is pointed at, as the manifest paths or
    /// directories that language's tooling names them by.
    pub roots: Vec<PathBuf>,
    /// Every package the manifests declare.
    pub packages: Vec<ProjectPackage>,
    /// The build variants the model loads.
    pub variants: BuildVariants,
    /// Each workspace package's name, mapped to the source it resolves to. A
    /// workspace package always resolves here, never to build output or to a
    /// copy of it in an environment.
    pub workspace_map: BTreeMap<String, PathBuf>,
    /// Source files that no build of the repository compiles, so no server
    /// configuration answers for them. Reported, never sent to a server.
    pub not_in_any_build: Vec<PathBuf>,
}

impl ProjectModel {
    /// A model that could not be read, with the reason.
    pub fn missing(reason: impl Into<String>) -> Self {
        Self {
            state: ModelState::Missing {
                reason: reason.into(),
            },
            ..Self::default()
        }
    }
}

/// Whether a project model could be read from the repository's manifests.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ModelState {
    /// The manifests were read.
    #[default]
    Found,
    /// No model could be read without running something, or the files it
    /// comes from are absent. The server gets no project configuration.
    Missing { reason: String },
}

/// One package a repository's manifests declare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectPackage {
    /// The name other code refers to it by: a crate, Go module, npm package
    /// or Python distribution name.
    pub name: String,
    /// The directory holding its manifest.
    pub dir: PathBuf,
    /// Where its source lives.
    pub source_roots: Vec<PathBuf>,
    /// Its own compiler configuration, when it has one (a `tsconfig.json`).
    pub config: Option<PathBuf>,
}

/// Which variants of the build a model loads.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BuildVariants {
    /// Cargo features.
    pub features: Selection,
    /// Go build tags.
    pub tags: Vec<String>,
    /// Package export conditions.
    pub conditions: Vec<String>,
    /// Python extras and dependency groups.
    pub extras: Selection,
}

/// A choice among named variants.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Selection {
    /// What the tooling selects by default.
    #[default]
    Default,
    /// Every variant the manifests declare.
    All,
    /// These variants.
    Named(Vec<String>),
}

/// The toolchain and dependencies a server analyses the repository against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Environment {
    /// The toolchain version the repository pins, or the one used because it
    /// pins none.
    pub toolchain: Option<Toolchain>,
    /// Where the dependencies come from.
    pub dependencies: Vec<DependencySource>,
    /// Which of the three providers serves this environment.
    pub provider: Provider,
    /// A digest of everything above that decides answers, for the proof of
    /// which environment answered.
    pub identity: EnvironmentIdentity,
    /// Work the provider's network step still has to do before this
    /// environment is complete, in a few words. `None` when there is none.
    pub pending: Option<String>,
}

impl Environment {
    /// An environment from `provider` with nothing else known, its identity
    /// derived from `identity_parts`.
    pub fn from_provider(provider: Provider, identity_parts: &[&str]) -> Self {
        Self {
            toolchain: None,
            dependencies: Vec::new(),
            provider,
            identity: EnvironmentIdentity::of(identity_parts),
            pending: None,
        }
    }

    /// This environment reported missing because its pending network step
    /// could not finish: calls into dependencies then get no answer, never
    /// one from an environment the repository did not choose.
    pub fn unprovisioned(mut self, reason: impl Into<String>) -> Self {
        if self.pending.is_some() {
            self.provider = Provider::Missing {
                reason: reason.into(),
            };
        }
        self
    }

    /// The reason the environment is missing, when it is.
    pub fn missing_reason(&self) -> Option<&str> {
        match &self.provider {
            Provider::Missing { reason } => Some(reason),
            _ => None,
        }
    }
}

/// A toolchain version, and what chose it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Toolchain {
    /// `python`, `rust`, `go`, `typescript`.
    pub name: String,
    /// The version, as precise as it is known.
    pub version: String,
    /// What pinned it: the file that names it, or why none did.
    pub pinned_by: String,
    /// Where the toolchain is on disk, when Kin provides it or found it.
    pub location: Option<PathBuf>,
    /// Another installed toolchain that runs in its place, by the name its
    /// toolchain manager knows it, when the pinned one is not installed and
    /// only its library is read (Kin fetched the pinned Rust release's
    /// `rust-src`; the installed default runs Cargo).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub substitute: Option<String>,
}

/// One place dependencies are read from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencySource {
    /// What it is, in a few words.
    pub description: String,
    /// The directory the server reads them from, when there is one.
    pub location: Option<PathBuf>,
    /// The lockfile that names their versions, when one does.
    pub lock: Option<PathBuf>,
}

/// Who provides an environment. Tried in declaration order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum Provider {
    /// The user's own environment. `checked_against` names the lock it was
    /// found to match, and is `None` where no check was possible or made.
    UserEnvironment {
        description: String,
        checked_against: Option<PathBuf>,
    },
    /// Kin's analysis environment: the lock's own versions, fetched without
    /// running anything, verified against the lock's hashes and kept in a
    /// content-addressed store under `KIN_HOME` that repositories share.
    KinAnalysisEnvironment {
        description: String,
        basis: EnvironmentBasis,
    },
    /// No environment the repository chose is available. Calls into
    /// dependencies get no answer rather than one from somewhere else.
    Missing { reason: String },
}

impl Provider {
    /// The provider's name, as logs and proofs spell it.
    pub fn kind(&self) -> &'static str {
        match self {
            Provider::UserEnvironment { .. } => "user environment",
            Provider::KinAnalysisEnvironment { .. } => "Kin analysis environment",
            Provider::Missing { .. } => "environment missing",
        }
    }

    /// The provider in one line: its name and what it is or why it is missing.
    pub fn describe(&self) -> String {
        match self {
            Provider::UserEnvironment {
                description,
                checked_against,
            } => match checked_against {
                Some(lock) => format!(
                    "{}: {description}, matching {}",
                    self.kind(),
                    lock.display()
                ),
                None => format!("{}: {description}", self.kind()),
            },
            Provider::KinAnalysisEnvironment { description, basis } => {
                format!("{}: {description} ({})", self.kind(), basis.describe())
            }
            Provider::Missing { reason } => format!("{}: {reason}", self.kind()),
        }
    }
}

/// What an analysis environment's versions come from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "basis", rename_all = "snake_case")]
pub enum EnvironmentBasis {
    /// The versions the repository's lockfile pins.
    Lockfile { path: PathBuf },
    /// Versions Kin resolved from the repository's declared requirements,
    /// without building anything, because the repository locks none. The
    /// repository did not choose these exact versions.
    ResolvedNotLocked { resolver: String },
}

impl EnvironmentBasis {
    fn describe(&self) -> String {
        match self {
            EnvironmentBasis::Lockfile { path } => format!("locked by {}", path.display()),
            EnvironmentBasis::ResolvedNotLocked { resolver } => {
                format!("resolved by Kin with {resolver}, not locked")
            }
        }
    }
}

/// A digest that names one environment: equal digests mean the same
/// toolchain and the same dependency versions.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct EnvironmentIdentity(pub String);

impl EnvironmentIdentity {
    /// The identity of an environment described by `parts`, in order.
    pub fn of(parts: &[&str]) -> Self {
        let mut hasher = sha2::Sha256::new();
        for part in parts {
            hasher.update((part.len() as u64).to_le_bytes());
            hasher.update(part.as_bytes());
        }
        Self(format!("sha256:{}", hex(&hasher.finalize())))
    }

    /// The hex digest without its `sha256:` prefix, for naming a directory.
    pub fn hex(&self) -> &str {
        self.0.strip_prefix("sha256:").unwrap_or(&self.0)
    }
}

impl std::fmt::Display for EnvironmentIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 15)] as char);
    }
    out
}

/// The sha256 of a file's bytes as lowercase hex, `None` when it cannot be
/// read. For naming what a lockfile said in an environment's identity.
pub fn file_digest(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(hex(&sha2::Sha256::digest(&bytes)))
}

/// What one run of an environment's network step did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProvisionReport {
    /// Artifacts downloaded and verified against the lock in this run.
    pub fetched: usize,
    /// Their bytes, as downloaded.
    pub fetched_bytes: u64,
    /// Artifacts already in the shared store, used without a download.
    pub reused: usize,
    /// Locked packages left out, each as `name==version: reason`.
    pub skipped: Vec<String>,
    /// Artifacts refused because their bytes did not match the lock, each as
    /// `name==version: reason`. Nothing refused is unpacked.
    pub refused: Vec<String>,
    /// Every process this run started, as its command line. Fetching and
    /// unpacking start none; only resolving an unlocked project does.
    pub processes: Vec<String>,
    /// The environment directory the run built or found complete.
    pub environment: Option<PathBuf>,
    /// Why no environment could be built, when none was.
    pub failure: Option<String>,
    /// Wall time of the run.
    pub elapsed_ms: u128,
}

impl ProvisionReport {
    /// The run in one line, for the daemon's log.
    pub fn summary(&self) -> String {
        let mut summary = match (&self.environment, &self.failure) {
            (_, Some(failure)) => format!("no environment: {failure}"),
            (Some(dir), None) => format!("environment at {}", dir.display()),
            (None, None) => "nothing to provision".to_string(),
        };
        summary.push_str(&format!(
            "; fetched {} artifact(s), {} bytes; reused {}; skipped {}; refused {}; {} process(es) started; {} ms",
            self.fetched,
            self.fetched_bytes,
            self.reused,
            self.skipped.len(),
            self.refused.len(),
            self.processes.len(),
            self.elapsed_ms
        ));
        summary
    }
}

/// The project model and environment one launch was chosen from, reported the
/// same way for every language.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Resolution {
    /// Whether a project model was read.
    pub project_model: ModelState,
    /// How many packages the model holds.
    pub packages: usize,
    /// The environment the launch analyses against.
    pub environment: Environment,
    /// Files outside every build, as [`ProjectModel::not_in_any_build`].
    pub not_in_any_build: Vec<PathBuf>,
}

impl Resolution {
    /// The resolution of a launch chosen from `model` and `environment`.
    pub fn new(model: &ProjectModel, environment: Environment) -> Self {
        Self {
            project_model: model.state.clone(),
            packages: model.packages.len(),
            environment,
            not_in_any_build: model.not_in_any_build.clone(),
        }
    }

    /// The reason the project model is missing, when it is.
    pub fn project_model_missing(&self) -> Option<&str> {
        match &self.project_model {
            ModelState::Missing { reason } => Some(reason),
            ModelState::Found => None,
        }
    }

    /// The status lines every language reports, in the same words: the
    /// project model, the environment, and the files in no build.
    pub fn status_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        match &self.project_model {
            ModelState::Found => lines.push(format!(
                "project model: {} package(s) from the manifests",
                self.packages
            )),
            ModelState::Missing { reason } => {
                lines.push(format!("project model missing: {reason}"));
            }
        }
        let mut environment = self.environment.provider.describe();
        if let Some(toolchain) = &self.environment.toolchain {
            environment.push_str(&format!(
                "; {} {} ({})",
                toolchain.name, toolchain.version, toolchain.pinned_by
            ));
        }
        environment.push_str(&format!("; identity {}", self.environment.identity));
        lines.push(environment);
        if let Some(pending) = &self.environment.pending {
            lines.push(format!("environment pending: {pending}"));
        }
        if !self.not_in_any_build.is_empty() {
            lines.push(format!(
                "not in any build: {} file(s), first {}",
                self.not_in_any_build.len(),
                self.not_in_any_build[0].display()
            ));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_are_stable_and_separate_their_parts() {
        let a = EnvironmentIdentity::of(&["python", "3.11"]);
        assert_eq!(a, EnvironmentIdentity::of(&["python", "3.11"]));
        assert_ne!(a, EnvironmentIdentity::of(&["python3", ".11"]));
        assert!(a.0.starts_with("sha256:") && a.hex().len() == 64, "{a}");
    }

    /// Every language reports a missing environment, a missing model and the
    /// files in no build in the same words.
    #[test]
    fn status_lines_use_one_vocabulary() {
        let mut model = ProjectModel::missing("no compile_commands.json");
        model.not_in_any_build = vec![PathBuf::from("/repo/tests/ui/fail.rs")];
        let environment = Environment::from_provider(
            Provider::Missing {
                reason: "no lockfile".to_string(),
            },
            &["x"],
        );
        let resolution = Resolution::new(&model, environment);
        let lines = resolution.status_lines();
        assert_eq!(lines[0], "project model missing: no compile_commands.json");
        assert!(
            lines[1].starts_with("environment missing: no lockfile; identity sha256:"),
            "{lines:?}"
        );
        assert_eq!(
            lines[2],
            "not in any build: 1 file(s), first /repo/tests/ui/fail.rs"
        );
        assert_eq!(
            resolution.project_model_missing(),
            Some("no compile_commands.json")
        );
        assert_eq!(resolution.environment.missing_reason(), Some("no lockfile"));
    }
}
