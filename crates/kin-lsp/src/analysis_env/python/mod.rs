// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Python analysis environments.
//!
//! The environment for a repository is assessed without the network (which
//! Python it pins, which packages its lock names, whether that environment
//! is already in the store) and provisioned with it: the pinned CPython and
//! every locked package fetched, verified and linked into one environment.
//! A repository that locks nothing has its declared requirements resolved
//! once by uv without building anything, and the result is marked as
//! resolved by Kin rather than locked.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::adapters::contract::{EnvironmentIdentity, ProvisionReport};

use super::fetch::Fetcher;

pub mod index;
pub mod interpreter;
pub mod lockfile;
pub mod markers;
pub mod plan;
pub mod provision;
pub mod store;
pub mod tags;
pub mod unlocked;

use interpreter::PinnedPython;
use lockfile::{Lock, LockSearch};
use plan::{Plan, Target};
use tags::Platform;
use unlocked::Declared;

/// The Python store under Kin's cache.
pub fn store_dir(cache: &Path) -> PathBuf {
    super::store_root(cache).join("python")
}

/// The Python a repository is analysed as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub target: Target,
    pub build: &'static PinnedPython,
    /// What chose the version, in a few words.
    pub pinned_by: String,
    /// Whether the repository states a version or a range at all. When it
    /// states neither, the version is Kin's choice, and fetching a CPython
    /// for it tells pyright nothing its own default does not.
    pub stated: bool,
}

/// The version a `.python-version` line names, as a minor version of Python 3.
fn minor_of(text: &str) -> Option<u32> {
    let text = text.trim();
    let text = text
        .strip_prefix("cpython-")
        .or_else(|| text.strip_prefix("cpython"))
        .or_else(|| text.strip_prefix("python"))
        .unwrap_or(text);
    let mut parts = text.split(['.', '-']);
    if parts.next()? != "3" {
        return None;
    }
    let minor: String = parts
        .next()?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    minor.parse().ok()
}

/// The `requires-python` a project declares, from `pyproject.toml` or the
/// lock.
fn requires_python(root: &Path, lock: Option<&Lock>) -> Option<(String, String)> {
    std::fs::read_to_string(root.join("pyproject.toml"))
        .ok()
        .and_then(|text| toml::from_str::<toml::Table>(&text).ok())
        .and_then(|table| {
            table
                .get("project")?
                .get("requires-python")?
                .as_str()
                .map(|value| {
                    (
                        value.to_string(),
                        "pyproject.toml requires-python".to_string(),
                    )
                })
        })
        .or_else(|| {
            let lock = lock?;
            lock.requires_python
                .clone()
                .map(|value| (value, format!("{} requires-python", lock.format.describe())))
        })
}

/// The Python a repository pins, in the order the tools that read it do:
/// `.python-version`, the lock's own pin, then the newest pinned build its
/// `requires-python` admits, then the newest pinned build. `None` on a
/// platform Kin pins no CPython build for.
pub fn pin_python(root: &Path, lock: Option<&Lock>, platform: Platform) -> Option<Pin> {
    let triple = platform.triple()?;
    let finish = |minor: u32, pinned_by: String, stated: bool| -> Option<Pin> {
        let (build, substitution) = interpreter::pinned_for(minor, triple)?;
        let pinned_by = match substitution {
            Some(note) => format!("{pinned_by}; {note}"),
            None => pinned_by,
        };
        Some(Pin {
            target: Target {
                full_version: build.version.to_string(),
                minor: build.minor,
                platform,
            },
            build,
            pinned_by,
            stated,
        })
    };
    if let Some((minor, line)) = std::fs::read_to_string(root.join(".python-version"))
        .ok()
        .and_then(|text| {
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .find_map(|line| minor_of(line).map(|minor| (minor, line.to_string())))
        })
    {
        return finish(minor, format!(".python-version names {line}"), true);
    }
    if let Some(pin) = lock.and_then(|lock| lock.python_pin.clone()) {
        if let Some(minor) = minor_of(&pin) {
            return finish(
                minor,
                format!(
                    "{} pins {pin}",
                    lock.map_or("the lock", |l| l.format.describe())
                ),
                true,
            );
        }
    }
    if let Some((range, source)) = requires_python(root, lock) {
        if let Some(set) = markers::SpecifierSet::parse(&range) {
            if let Some(build) =
                interpreter::newest_accepted(triple, &|version| set.contains(version))
            {
                return finish(
                    build.minor,
                    format!("{source} {range}, newest pinned build it admits"),
                    true,
                );
            }
        }
    }
    let newest = interpreter::newest_accepted(triple, &|_| true)?;
    finish(
        newest.minor,
        "no pin or range, newest pinned build".to_string(),
        false,
    )
}

/// What the environment step reads from the host.
#[derive(Debug, Clone)]
pub struct Host<'a> {
    pub vars: &'a HashMap<String, String>,
    pub home: Option<&'a Path>,
    /// Kin's cache directory, `$KIN_HOME/cache`.
    pub cache: &'a Path,
    /// uv, when it is installed, for resolving an unlocked project.
    pub uv: Option<&'a Path>,
    pub platform: Platform,
}

impl Host<'_> {
    pub fn store(&self) -> PathBuf {
        store_dir(self.cache)
    }

    pub fn index(&self) -> index::IndexConfig {
        index::index_config(self.vars, self.home)
    }
}

/// Where an environment's dependency versions come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dependencies {
    /// The repository's lockfile.
    Locked(Lock),
    /// Kin's earlier resolution of an unlocked project's declarations.
    Resolved(Lock),
    /// An unlocked project whose declarations uv has not resolved yet.
    Unresolved(Declared),
    /// None that the repository chose can be had.
    Missing(String),
}

/// What is known about a repository's analysis environment without the
/// network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub pin: Pin,
    pub dependencies: Dependencies,
    pub plan: Option<Plan>,
    pub identity: EnvironmentIdentity,
    /// Where the environment is, or will be once provisioned.
    pub dir: PathBuf,
    /// Whether it is there, complete with its interpreter.
    pub ready: bool,
}

impl Assessment {
    /// The interpreter the environment runs, inside it.
    pub fn interpreter(&self) -> PathBuf {
        self.dir.join("bin/python3")
    }
}

/// Assess the environment of the repository at `root`, whose own packages
/// are `own` (normalized names), from what its lock search found.
pub fn assess(
    root: &Path,
    own: &BTreeSet<String>,
    host: &Host<'_>,
    search: &LockSearch,
) -> Option<Assessment> {
    let lock = match search {
        LockSearch::Found(lock) => Some(lock),
        _ => None,
    };
    let pin = pin_python(root, lock, host.platform)?;
    let store = host.store();
    let dependencies = match search {
        LockSearch::Found(lock) => Dependencies::Locked(lock.clone()),
        other => {
            let unusable = match other {
                LockSearch::Unusable { reasons } => format!(" ({})", reasons.join("; ")),
                _ => String::new(),
            };
            let declared = unlocked::declared_requirements(root, own);
            if declared.requirements.is_empty() {
                Dependencies::Missing(format!(
                    "no usable lockfile{unusable}, and no dependencies declared where Kin can \
                     read them without running anything"
                ))
            } else {
                let key = unlocked::resolution_key(&declared, &pin.target, &host.index());
                let path = unlocked::resolution_path(&store, &key);
                let cached = path.is_file().then(|| {
                    lockfile::parse_requirements(std::slice::from_ref(&path), &|file| {
                        std::fs::read_to_string(file).ok()
                    })
                });
                match cached {
                    Some(Ok(lock)) => Dependencies::Resolved(lock),
                    _ if host.uv.is_some() => Dependencies::Unresolved(declared),
                    _ => Dependencies::Missing(format!(
                        "no usable lockfile{unusable}, and uv is not installed to resolve the \
                         declared requirements without building"
                    )),
                }
            }
        }
    };
    let plan = match &dependencies {
        Dependencies::Locked(lock) | Dependencies::Resolved(lock) => {
            Some(plan::plan(lock, root, &pin.target))
        }
        _ => None,
    };
    let identity = plan.as_ref().map_or_else(
        || plan::bare_identity(&pin.target),
        |plan| plan.identity.clone(),
    );
    let dir = store.join("envs").join(identity.hex());
    // A complete environment's interpreter link leads to an interpreter.
    let ready = dir.join("bin/python3").is_file();
    Some(Assessment {
        pin,
        dependencies,
        plan,
        identity,
        dir,
        ready,
    })
}

/// Fetch and build the analysis environment of the repository at `root`.
pub fn provision(
    root: &Path,
    own: &BTreeSet<String>,
    host: &Host<'_>,
    fetcher: &dyn Fetcher,
) -> ProvisionReport {
    let started = Instant::now();
    let mut report = ProvisionReport::default();
    let search = lockfile::find_lock(root);
    let Some(mut assessment) = assess(root, own, host, &search) else {
        report.failure = Some(format!(
            "Kin pins no CPython build for this platform ({})",
            host.platform.id()
        ));
        return report;
    };
    let store = host.store();
    let index = host.index();
    // The interpreter first: uv resolves against it, and pyright reads its
    // version and standard library.
    let interpreter = match interpreter::ensure(fetcher, &store, assessment.pin.build) {
        Ok((interpreter, bytes)) => {
            if bytes > 0 {
                report.fetched += 1;
                report.fetched_bytes += bytes;
            } else {
                report.reused += 1;
            }
            interpreter
        }
        Err(reason) => {
            report.failure = Some(format!(
                "could not fetch CPython {}: {reason}",
                assessment.pin.build.version
            ));
            report.elapsed_ms = started.elapsed().as_millis();
            return report;
        }
    };
    if let Dependencies::Unresolved(declared) = &assessment.dependencies {
        let (Some(uv), Some(triple)) = (host.uv, host.platform.triple()) else {
            report.failure = Some("uv is not installed".to_string());
            return report;
        };
        let (command, outcome) = unlocked::resolve_with_uv(
            uv,
            &interpreter,
            &store,
            declared,
            &assessment.pin.target,
            &index,
            triple,
        );
        report.processes.push(command);
        if let Err(reason) = outcome {
            report.failure = Some(reason);
            report.elapsed_ms = started.elapsed().as_millis();
            return report;
        }
        match assess(root, own, host, &search) {
            Some(again) => assessment = again,
            None => return report,
        }
    }
    let artifacts = match &assessment.plan {
        Some(plan) => {
            report.skipped.extend(plan.skipped.iter().cloned());
            provision::fetch_plan(
                fetcher,
                &store,
                &index,
                &assessment.pin.target,
                plan,
                &mut report,
            )
        }
        None => Vec::new(),
    };
    match store::build_env(
        &store,
        assessment.identity.hex(),
        &interpreter,
        assessment.pin.target.minor,
        assessment.pin.build.version,
        &artifacts,
    ) {
        Ok(dir) => report.environment = Some(dir),
        Err(reason) => report.failure = Some(reason),
    }
    report.elapsed_ms = started.elapsed().as_millis();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::repo_scan::Fixture;
    use tags::Os;

    fn mac() -> Platform {
        Platform {
            os: Os::Mac(Some((15, 0))),
            arch: "aarch64",
        }
    }

    /// `.python-version` wins; without it a `requires-python` range selects
    /// the newest pinned build it admits; a version Kin pins no build for
    /// takes the nearest and says so.
    #[test]
    fn the_python_version_comes_from_what_the_repository_pins() {
        let repo = Fixture::new("pin-python");
        repo.write(
            "pyproject.toml",
            "[project]\nname = \"x\"\nrequires-python = \">=3.10,<3.13\"\n",
        );
        let pin = pin_python(&repo.root, None, mac()).unwrap();
        assert_eq!(pin.target.minor, 12);
        assert!(
            pin.pinned_by.contains("requires-python"),
            "{}",
            pin.pinned_by
        );

        repo.write(".python-version", "3.11\n");
        let pin = pin_python(&repo.root, None, mac()).unwrap();
        assert_eq!(pin.target.full_version, "3.11.16");
        assert_eq!(pin.pinned_by, ".python-version names 3.11");

        repo.write(".python-version", "# comment\n3.9.18\n");
        let pin = pin_python(&repo.root, None, mac()).unwrap();
        assert_eq!(pin.target.minor, 10);
        assert!(
            pin.pinned_by.contains("no CPython 3.9 build"),
            "{}",
            pin.pinned_by
        );

        let bare = Fixture::new("pin-python-bare");
        let chosen = pin_python(&bare.root, None, mac()).unwrap();
        assert_eq!(chosen.target.minor, 14);
        assert!(!chosen.stated);
        assert!(pin_python(&repo.root, None, mac()).unwrap().stated);
        let unsupported = Platform {
            os: Os::Windows,
            arch: "x86_64",
        };
        assert!(pin_python(&bare.root, None, unsupported).is_none());
    }

    /// Without a lock, without declared requirements and without uv, the
    /// dependencies are missing and say why; with uv they wait for a
    /// resolution; a cached resolution is used as a lock.
    #[test]
    fn an_unlocked_project_resolves_with_uv_or_reports_its_environment_missing() {
        let repo = Fixture::new("assess-unlocked");
        let cache = Fixture::new("assess-unlocked-cache");
        let vars = HashMap::new();
        let mut host = Host {
            vars: &vars,
            home: Some(&cache.root),
            cache: &cache.root,
            uv: None,
            platform: mac(),
        };
        let own = BTreeSet::new();
        let empty = assess(&repo.root, &own, &host, &LockSearch::NotFound).unwrap();
        assert!(
            matches!(&empty.dependencies, Dependencies::Missing(reason) if reason.contains("no dependencies declared")),
            "{:?}",
            empty.dependencies
        );
        repo.write(
            "pyproject.toml",
            "[project]\nname = \"x\"\ndependencies = [\"idna>=3\"]\n",
        );
        let missing = assess(&repo.root, &own, &host, &LockSearch::NotFound).unwrap();
        assert!(
            matches!(&missing.dependencies, Dependencies::Missing(reason) if reason.contains("uv is not installed")),
            "{:?}",
            missing.dependencies
        );
        let uv = PathBuf::from("/usr/bin/uv");
        host.uv = Some(&uv);
        let pending = assess(&repo.root, &own, &host, &LockSearch::NotFound).unwrap();
        let Dependencies::Unresolved(declared) = &pending.dependencies else {
            panic!("{:?}", pending.dependencies);
        };
        assert!(!pending.ready);

        let key = unlocked::resolution_key(declared, &pending.pin.target, &host.index());
        let resolution = unlocked::resolution_path(&host.store(), &key);
        std::fs::create_dir_all(resolution.parent().unwrap()).unwrap();
        std::fs::write(
            &resolution,
            format!("idna==3.10 \\\n    --hash=sha256:{}\n", "a".repeat(64)),
        )
        .unwrap();
        let resolved = assess(&repo.root, &own, &host, &LockSearch::NotFound).unwrap();
        assert!(matches!(resolved.dependencies, Dependencies::Resolved(_)));
        assert_eq!(resolved.plan.unwrap().packages[0].pin(), "idna==3.10");
    }
}
