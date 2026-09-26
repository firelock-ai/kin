// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Which locked packages an analysis environment holds, decided from the lock
//! alone.
//!
//! The environment loads all of a project's code, so it requests every extra
//! and every dependency group of the repository's own packages, and follows
//! what those need for the pinned Python on this platform. A package the
//! repository holds is never fetched: it resolves to the repository's source.
//! A package the lock does not pin to a hashed index file (a VCS checkout, a
//! directory outside the repository, an unhashed URL) is left out and named.
//!
//! The plan, and so the environment's identity, depends only on the lock's
//! contents, the Python minor version and the platform, never on the network,
//! so it is known before anything is fetched and two repositories that lock
//! the same packages share one environment.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use crate::adapters::contract::EnvironmentIdentity;

use super::lockfile::{
    normalize_name, DependencyKind, Lock, LockFormat, LockedFile, LockedPackage, PackageSource,
};
use super::markers::{evaluate, MarkerEnvironment, SpecifierSet};
use super::tags::Platform;

/// The Python an environment is analysed as, on the platform it is built for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The full version of the pinned build, `3.11.16`.
    pub full_version: String,
    /// Its minor version of Python 3.
    pub minor: u32,
    pub platform: Platform,
}

impl Target {
    /// The marker values of this target, with every extra requested.
    pub fn markers(&self) -> MarkerEnvironment {
        let os = match self.platform.os {
            super::tags::Os::Mac(_) => "macos",
            super::tags::Os::Linux { .. } => "linux",
            super::tags::Os::Windows => "windows",
        };
        MarkerEnvironment::cpython(&self.full_version, os, self.platform.arch)
    }
}

/// One locked package the environment holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedPackage {
    /// The name as the lock writes it.
    pub name: String,
    pub version: String,
    /// The artifacts the lock lists, when it lists them.
    pub files: Vec<LockedFile>,
    /// Every digest the lock accepts for this package, lowercase hex.
    pub hashes: BTreeSet<String>,
    /// The index the lock names for it, when it names one.
    pub index: Option<String>,
}

impl PlannedPackage {
    /// `name==version`, for reports.
    pub fn pin(&self) -> String {
        format!("{}=={}", self.name, self.version)
    }
}

/// The packages one environment holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub format: LockFormat,
    /// The lockfile the plan was read from.
    pub lock: PathBuf,
    pub packages: Vec<PlannedPackage>,
    /// The repository's own packages, by name, with the directory their
    /// source is in. They resolve to that source and are never fetched.
    pub in_repo: Vec<(String, PathBuf)>,
    /// Locked packages left out, as `name==version: reason`.
    pub skipped: Vec<String>,
    pub identity: EnvironmentIdentity,
}

/// Whether a marker holds for the target. A marker that cannot be read
/// includes its package: an extra package in an analysis environment costs a
/// download, and a missing one costs every call into it.
fn holds(marker: Option<&str>, environment: &MarkerEnvironment) -> bool {
    marker.is_none_or(|marker| evaluate(marker, environment).unwrap_or(true))
}

fn python_accepted(requires: Option<&str>, target: &Target) -> bool {
    requires
        .and_then(SpecifierSet::parse)
        .is_none_or(|set| set.contains(&target.full_version))
}

/// Where a directory source is, when it is inside the repository.
fn in_repository(lock_dir: &Path, root: &Path, path: &str) -> Option<PathBuf> {
    let joined = lock_dir.join(path);
    let resolved = joined.canonicalize().unwrap_or(joined);
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    resolved.starts_with(&root).then_some(resolved)
}

/// The plan for `lock`, the lock of the repository at `root`, for `target`.
pub fn plan(lock: &Lock, root: &Path, target: &Target) -> Plan {
    let lock_path = lock.files.first().cloned().unwrap_or_default();
    let lock_dir = lock_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.to_path_buf());
    let environment = target.markers();
    let chosen: Vec<usize> = if lock.format == LockFormat::UvLock {
        walk_uv(lock, &lock_dir, root, &environment)
    } else {
        lock.packages
            .iter()
            .enumerate()
            .filter(|(_, package)| {
                holds(package.marker.as_deref(), &environment)
                    && python_accepted(package.requires_python.as_deref(), target)
            })
            .map(|(index, _)| index)
            .collect()
    };

    let mut packages: BTreeMap<String, PlannedPackage> = BTreeMap::new();
    let mut in_repo = Vec::new();
    let mut skipped = Vec::new();
    for index in chosen {
        let package = &lock.packages[index];
        let normalized = normalize_name(&package.name);
        let pin = format!(
            "{}=={}",
            package.name,
            package.version.as_deref().unwrap_or("?")
        );
        match &package.source {
            PackageSource::Directory { path, .. } => {
                match in_repository(&lock_dir, root, path) {
                    Some(dir) => in_repo.push((package.name.clone(), dir)),
                    None => skipped.push(format!(
                        "{pin}: a directory outside the repository, which the lock does not \
                         pin to a hashed file"
                    )),
                }
                continue;
            }
            PackageSource::Vcs { url } => {
                skipped.push(format!(
                    "{pin}: a VCS checkout ({}), which Kin does not fetch; only hashed index \
                     files are",
                    super::super::fetch::redact(url)
                ));
                continue;
            }
            PackageSource::Archive { location } => {
                skipped.push(format!(
                    "{pin}: a direct archive ({}), which Kin does not fetch yet",
                    super::super::fetch::redact(location)
                ));
                continue;
            }
            PackageSource::Registry { .. } => {}
        }
        if packages.contains_key(&normalized) {
            continue;
        }
        let Some(version) = package.version.clone() else {
            skipped.push(format!("{pin}: the lock pins no version"));
            continue;
        };
        let mut hashes: BTreeSet<String> = package
            .files
            .iter()
            .filter_map(|file| file.sha256.clone())
            .chain(package.hashes.iter().cloned())
            .map(|hash| hash.to_ascii_lowercase())
            .collect();
        hashes.retain(|hash| hash.len() == 64);
        if hashes.is_empty() {
            skipped.push(format!(
                "{pin}: the lock gives no sha256 to verify a download against"
            ));
            continue;
        }
        let index = match &package.source {
            PackageSource::Registry { index } => index.clone(),
            _ => None,
        };
        packages.insert(
            normalized,
            PlannedPackage {
                name: package.name.clone(),
                version,
                files: package.files.clone(),
                hashes,
                index,
            },
        );
    }
    // The repository's own packages resolve to source even when the lock also
    // pins a registry copy of the same name.
    let own: BTreeSet<String> = in_repo
        .iter()
        .map(|(name, _)| normalize_name(name))
        .collect();
    packages.retain(|normalized, _| !own.contains(normalized));

    let mut identity: Vec<String> = vec![
        "kin-python-analysis-environment/1".to_string(),
        format!("3.{}", target.minor),
        target.platform.id(),
    ];
    for (normalized, package) in &packages {
        identity.push(format!(
            "{normalized}=={} {}",
            package.version,
            package.hashes.iter().cloned().collect::<Vec<_>>().join(",")
        ));
    }
    let identity: Vec<&str> = identity.iter().map(String::as_str).collect();
    Plan {
        format: lock.format,
        lock: lock_path,
        packages: packages.into_values().collect(),
        in_repo,
        skipped,
        identity: EnvironmentIdentity::of(&identity),
    }
}

/// The identity of an environment with no dependencies, for a repository
/// whose dependencies are missing: the interpreter alone.
pub fn bare_identity(target: &Target) -> EnvironmentIdentity {
    EnvironmentIdentity::of(&[
        "kin-python-analysis-environment/1",
        &format!("3.{}", target.minor),
        &target.platform.id(),
        "no dependencies",
    ])
}

/// uv.lock's selection: from the repository's own packages, with every extra
/// and group, through each dependency whose marker holds, taking only the
/// extras each edge requests of a third-party package.
fn walk_uv(
    lock: &Lock,
    lock_dir: &Path,
    root: &Path,
    environment: &MarkerEnvironment,
) -> Vec<usize> {
    let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
    for (index, package) in lock.packages.iter().enumerate() {
        by_name
            .entry(normalize_name(&package.name))
            .or_default()
            .push(index);
    }
    let is_own = |package: &LockedPackage| match &package.source {
        PackageSource::Directory { path, .. } => in_repository(lock_dir, root, path).is_some(),
        _ => false,
    };
    let members: BTreeSet<String> = lock.members.iter().map(|m| normalize_name(m)).collect();
    let resolve = |name: &str, version: Option<&str>| -> Option<usize> {
        let candidates = by_name.get(&normalize_name(name))?;
        let mut matching: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|&index| {
                version.is_none_or(|version| {
                    lock.packages[index]
                        .version
                        .as_deref()
                        .is_some_and(|own| super::markers::same_version(own, version))
                })
            })
            .collect();
        if matching.len() > 1 {
            let forked: Vec<usize> = matching
                .iter()
                .copied()
                .filter(|&index| {
                    let markers = &lock.packages[index].resolution_markers;
                    markers.is_empty()
                        || markers
                            .iter()
                            .any(|marker| holds(Some(marker), environment))
                })
                .collect();
            if !forked.is_empty() {
                matching = forked;
            }
        }
        matching.first().copied()
    };

    /// What has been walked from one package so far.
    #[derive(Default)]
    struct Visit {
        required: bool,
        all: bool,
        extras: BTreeSet<String>,
    }
    let mut visits: HashMap<usize, Visit> = HashMap::new();
    // (package, extras an edge requests of it, whether to take every extra
    // and group because the repository owns it)
    let mut queue: Vec<(usize, Vec<String>, bool)> = lock
        .packages
        .iter()
        .enumerate()
        .filter(|(_, package)| is_own(package) || members.contains(&normalize_name(&package.name)))
        .map(|(index, _)| (index, Vec::new(), true))
        .collect();
    let mut order = Vec::new();
    while let Some((index, extras, all)) = queue.pop() {
        let visit = visits.entry(index).or_insert_with(|| {
            order.push(index);
            Visit::default()
        });
        let take_required = !visit.required;
        visit.required = true;
        let take_all = all && !visit.all;
        visit.all |= all;
        let new_extras: Vec<String> = extras
            .iter()
            .map(|extra| normalize_name(extra))
            .filter(|extra| visit.extras.insert(extra.clone()))
            .collect();
        if !take_required && !take_all && new_extras.is_empty() {
            continue;
        }
        for dependency in &lock.packages[index].dependencies {
            let wanted = match &dependency.kind {
                DependencyKind::Required => take_required,
                DependencyKind::Extra(extra) => {
                    take_all || new_extras.contains(&normalize_name(extra))
                }
                DependencyKind::Group(_) => take_all,
            };
            if !wanted || !holds(dependency.marker.as_deref(), environment) {
                continue;
            }
            if let Some(next) = resolve(&dependency.name, dependency.version.as_deref()) {
                let own = is_own(&lock.packages[next]);
                queue.push((next, dependency.extras.clone(), own));
            }
        }
    }
    order
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::repo_scan::Fixture;
    use crate::analysis_env::python::lockfile::{parse_uv_lock, FileKind, LockedDependency};
    use crate::analysis_env::python::tags::Os;

    fn target(full: &str, minor: u32) -> Target {
        Target {
            full_version: full.to_string(),
            minor,
            platform: Platform {
                os: Os::Mac(Some((15, 0))),
                arch: "aarch64",
            },
        }
    }

    const H: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn hash(n: u8) -> String {
        format!("{n:02x}{}", &H[2..])
    }

    /// fastapi's shape: the project is editable at the root, the lock forks
    /// by Python version, a dependency is guarded by a marker, a dev group
    /// and an extra add packages, and a third-party extra is taken only when
    /// an edge asks for it.
    #[test]
    fn uv_selection_walks_from_the_project_with_every_extra_and_group() {
        let repo = Fixture::new("plan-uv");
        let text = format!(
            r#"
version = 1
revision = 3
requires-python = ">=3.10"

[[package]]
name = "app"
version = "0.1.0"
source = {{ editable = "." }}
dependencies = [
    {{ name = "starlette" }},
    {{ name = "typing-extensions", marker = "python_full_version < '3.11'" }},
]

[package.optional-dependencies]
all = [{{ name = "httpx", extra = ["http2"] }}]

[package.dev-dependencies]
dev = [{{ name = "pytest" }}]

[[package]]
name = "starlette"
version = "0.47.2"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [{{ url = "https://files.example/starlette-0.47.2-py3-none-any.whl", hash = "sha256:{h1}" }}]

[[package]]
name = "typing-extensions"
version = "4.12.2"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [{{ url = "https://files.example/typing_extensions-4.12.2-py3-none-any.whl", hash = "sha256:{h2}" }}]

[[package]]
name = "httpx"
version = "0.28.1"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [{{ url = "https://files.example/httpx-0.28.1-py3-none-any.whl", hash = "sha256:{h3}" }}]

[package.optional-dependencies]
http2 = [{{ name = "h2" }}]
brotli = [{{ name = "brotli" }}]

[[package]]
name = "h2"
version = "4.1.0"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [{{ url = "https://files.example/h2-4.1.0-py3-none-any.whl", hash = "sha256:{h4}" }}]

[[package]]
name = "brotli"
version = "1.1.0"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [{{ url = "https://files.example/Brotli-1.1.0-cp311-cp311-macosx_10_9_universal2.whl", hash = "sha256:{h5}" }}]

[[package]]
name = "pytest"
version = "8.3.0"
source = {{ registry = "https://pypi.org/simple" }}
resolution-markers = ["python_full_version >= '3.14'"]
wheels = [{{ url = "https://files.example/pytest-8.3.0-py3-none-any.whl", hash = "sha256:{h6}" }}]

[[package]]
name = "pytest"
version = "8.2.0"
source = {{ registry = "https://pypi.org/simple" }}
resolution-markers = ["python_full_version < '3.14'"]
wheels = [{{ url = "https://files.example/pytest-8.2.0-py3-none-any.whl", hash = "sha256:{h7}" }}]

[[package]]
name = "unrelated"
version = "1.0"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [{{ url = "https://files.example/unrelated-1.0-py3-none-any.whl", hash = "sha256:{h8}" }}]
"#,
            h1 = hash(1),
            h2 = hash(2),
            h3 = hash(3),
            h4 = hash(4),
            h5 = hash(5),
            h6 = hash(6),
            h7 = hash(7),
            h8 = hash(8),
        );
        let lock_path = repo.write("uv.lock", &text);
        let lock = parse_uv_lock(&text, &lock_path).unwrap();
        let pins = |plan: &Plan| -> Vec<String> {
            plan.packages.iter().map(PlannedPackage::pin).collect()
        };

        let on_311 = plan(&lock, &repo.root, &target("3.11.16", 11));
        assert_eq!(
            pins(&on_311),
            vec![
                "h2==4.1.0",
                "httpx==0.28.1",
                "pytest==8.2.0",
                "starlette==0.47.2"
            ]
        );
        assert_eq!(on_311.in_repo.len(), 1);
        assert_eq!(on_311.in_repo[0].0, "app");

        let on_310 = plan(&lock, &repo.root, &target("3.10.21", 10));
        assert!(pins(&on_310).contains(&"typing-extensions==4.12.2".to_string()));
        let on_314 = plan(&lock, &repo.root, &target("3.14.7", 14));
        assert!(pins(&on_314).contains(&"pytest==8.3.0".to_string()));
        assert_ne!(on_311.identity, on_314.identity);
        assert_eq!(
            on_311.identity,
            plan(&lock, &repo.root, &target("3.11.9", 11)).identity,
            "the identity follows the minor version and the locked files"
        );
    }

    fn registry(
        name: &str,
        version: &str,
        marker: Option<&str>,
        hashes: &[String],
    ) -> LockedPackage {
        LockedPackage {
            name: name.to_string(),
            version: Some(version.to_string()),
            source: PackageSource::Registry { index: None },
            marker: marker.map(str::to_string),
            requires_python: None,
            files: Vec::new(),
            hashes: hashes.to_vec(),
            dependencies: Vec::<LockedDependency>::new(),
            resolution_markers: Vec::new(),
        }
    }

    /// Every other format is selected by each package's own marker. A VCS
    /// package, an unhashed one and one outside the repository are named, and
    /// the repository's own package resolves to its source.
    #[test]
    fn flat_locks_select_by_marker_and_name_what_they_leave_out() {
        let repo = Fixture::new("plan-flat");
        repo.write("pkg/__init__.py", "");
        let lock = Lock {
            format: LockFormat::PipfileLock,
            files: vec![repo.root.join("Pipfile.lock")],
            packages: vec![
                registry("requests", "2.32.3", None, &[hash(1)]),
                registry(
                    "pywin32",
                    "306",
                    Some("sys_platform == 'win32'"),
                    &[hash(2)],
                ),
                registry(
                    "tomli",
                    "2.0.1",
                    Some("python_version < '3.11'"),
                    &[hash(3)],
                ),
                registry("nohash", "1.0", None, &[]),
                LockedPackage {
                    source: PackageSource::Vcs {
                        url: "https://user:token@git.example/x.git".to_string(),
                    },
                    ..registry("gitdep", "0.1", None, &[])
                },
                LockedPackage {
                    source: PackageSource::Directory {
                        path: ".".to_string(),
                        editable: true,
                    },
                    ..registry("mine", "0.0.0", None, &[])
                },
                LockedPackage {
                    source: PackageSource::Directory {
                        path: "/elsewhere".to_string(),
                        editable: false,
                    },
                    ..registry("theirs", "1.0", None, &[])
                },
            ],
            requires_python: None,
            python_pin: None,
            members: Vec::new(),
            index_urls: Vec::new(),
        };
        let plan = plan(&lock, &repo.root, &target("3.12.14", 12));
        let pins: Vec<String> = plan.packages.iter().map(PlannedPackage::pin).collect();
        assert_eq!(pins, vec!["requests==2.32.3"]);
        assert_eq!(plan.in_repo[0].0, "mine");
        assert_eq!(plan.skipped.len(), 3, "{:?}", plan.skipped);
        assert!(plan.skipped.iter().all(|reason| !reason.contains("token")));
        let _ = FileKind::Wheel;
    }
}
