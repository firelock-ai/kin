// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Fetching a plan's packages into the store and building its environment.
//!
//! For each planned package the file to fetch is the one an installer would
//! take for the pinned CPython on this platform, among the files whose digest
//! the lock names: the lock's own URL when the index in force is the one the
//! lock was made against, and otherwise the same file, by digest, from the
//! configured index. Only when no wheel suits is a source distribution
//! considered, and then only to extract pure-Python source for reading; one
//! that compiles anything is left out. Nothing fetched is run, and no process
//! is started.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::adapters::contract::ProvisionReport;

use super::super::fetch::{redact, FetchError, Fetcher};
use super::index::{project_files, IndexConfig};
use super::lockfile::normalize_name;
use super::plan::{Plan, PlannedPackage, Target};
use super::store::{self, ArtifactError, ArtifactKind};
use super::tags::{parse_wheel_filename, sdist_version, WheelTarget};

/// The most bytes one artifact may be.
const MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// How many artifacts are fetched at once.
const PARALLEL_FETCHES: usize = 8;

/// A file that could be fetched for one package.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    filename: String,
    url: String,
    sha256: String,
}

/// The file to fetch among `candidates`: the best-ranked wheel for the
/// target, else a source distribution.
fn choose(candidates: &[Candidate], target: &WheelTarget) -> Option<(Candidate, ArtifactKind)> {
    candidates
        .iter()
        .filter_map(|candidate| {
            let wheel = parse_wheel_filename(&candidate.filename)?;
            Some((target.wheel_rank(&wheel)?, candidate))
        })
        .min_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.filename.cmp(&b.1.filename)))
        .map(|(_, candidate)| (candidate.clone(), ArtifactKind::Wheel))
        .or_else(|| {
            candidates
                .iter()
                .find(|candidate| {
                    candidate.filename.ends_with(".tar.gz") || candidate.filename.ends_with(".zip")
                })
                .map(|candidate| (candidate.clone(), ArtifactKind::Sdist))
        })
}

/// Whether a URL points at PyPI's own file host.
fn on_pypi(url: &str) -> bool {
    url.starts_with("https://files.pythonhosted.org/") || url.starts_with("https://pypi.org/")
}

/// The files a package can be fetched as, with the digest each must match.
fn candidates(
    fetcher: &dyn Fetcher,
    package: &PlannedPackage,
    index: &IndexConfig,
) -> Result<Vec<Candidate>, String> {
    let from_lock: Vec<Candidate> = package
        .files
        .iter()
        .filter_map(|file| {
            Some(Candidate {
                filename: file.filename.clone(),
                url: file.url.clone()?,
                sha256: file.sha256.clone()?.to_ascii_lowercase(),
            })
        })
        .filter(|candidate| package.hashes.contains(&candidate.sha256))
        .collect();
    // The lock's own URLs serve unless the user points their tools at another
    // index than the one they came from, as a mirror or a proxy does.
    let lock_urls_serve = !from_lock.is_empty()
        && (index.is_pypi() || !from_lock.iter().all(|candidate| on_pypi(&candidate.url)));
    if lock_urls_serve {
        return Ok(from_lock);
    }
    let normalized = normalize_name(&package.name);
    let mut indexes: Vec<&str> = package.index.iter().map(String::as_str).collect();
    indexes.extend(index.all());
    let mut failures = Vec::new();
    for url in indexes {
        match project_files(fetcher, url, &package.name) {
            Ok(files) => {
                let found: Vec<Candidate> = files
                    .into_iter()
                    .filter(|file| !file.yanked || package.hashes.len() == 1)
                    .filter_map(|file| {
                        let sha256 = file.sha256?;
                        let version = parse_wheel_filename(&file.filename)
                            .map(|wheel| wheel.version)
                            .or_else(|| sdist_version(&file.filename, &normalized))?;
                        (package.hashes.contains(&sha256)
                            && super::markers::same_version(&version, &package.version))
                        .then_some(Candidate {
                            filename: file.filename,
                            url: file.url,
                            sha256,
                        })
                    })
                    .collect();
                if !found.is_empty() {
                    return Ok(found);
                }
                failures.push(format!(
                    "{} lists no file with a digest the lock names",
                    redact(url)
                ));
            }
            Err(error) => failures.push(error.to_string()),
        }
    }
    if !from_lock.is_empty() {
        // The configured index lacks it; the lock's own URL is the last try.
        return Ok(from_lock);
    }
    Err(failures.join("; "))
}

/// What happened to one package.
enum Outcome {
    Ready { dir: PathBuf, bytes: u64 },
    Skipped(String),
    Refused(String),
}

fn fetch_one(
    fetcher: &dyn Fetcher,
    store: &Path,
    index: &IndexConfig,
    wheel_target: &WheelTarget,
    package: &PlannedPackage,
) -> Outcome {
    // When the lock names its files, the file an installer would take is
    // known without the network, and one already in the store is used as it
    // is. A lock that names only digests has its file chosen from the
    // index's listing, unless the store already holds one of them.
    let offline: Vec<Candidate> = package
        .files
        .iter()
        .filter_map(|file| {
            Some(Candidate {
                filename: file.filename.clone(),
                url: file.url.clone().unwrap_or_default(),
                sha256: file.sha256.clone()?.to_ascii_lowercase(),
            })
        })
        .filter(|candidate| package.hashes.contains(&candidate.sha256))
        .collect();
    let chosen_offline = choose(&offline, wheel_target);
    let stored = match &chosen_offline {
        Some((candidate, _)) => Some(store::artifact_dir(store, &candidate.sha256)),
        // Another environment may have stored a wheel of this version for
        // another Python; only one whose own tags suit this target serves.
        None if offline.is_empty() => package
            .hashes
            .iter()
            .map(|hash| store::artifact_dir(store, hash))
            .find(|dir| {
                dir.is_dir()
                    && store::artifact_tags(dir).is_none_or(|tags| {
                        wheel_target
                            .wheel_rank(&super::tags::WheelName {
                                name: String::new(),
                                version: String::new(),
                                tags,
                            })
                            .is_some()
                    })
            }),
        None => None,
    };
    if let Some(dir) = stored.filter(|dir| dir.is_dir()) {
        return Outcome::Ready { dir, bytes: 0 };
    }
    let found = match candidates(fetcher, package, index) {
        Ok(found) => found,
        Err(reason) => return Outcome::Skipped(format!("{}: {reason}", package.pin())),
    };
    let chosen = match &chosen_offline {
        // The same file, from wherever the configured index serves it.
        Some((wanted, kind)) => found
            .iter()
            .find(|candidate| candidate.sha256 == wanted.sha256)
            .map(|candidate| (candidate.clone(), *kind)),
        None => choose(&found, wheel_target),
    };
    let Some((candidate, kind)) = chosen else {
        return Outcome::Skipped(format!(
            "{}: no wheel suits CPython 3.{} on {}, and the lock names no source distribution",
            package.pin(),
            wheel_target.minor,
            wheel_target.platform.id()
        ));
    };
    match store::ensure_artifact(
        fetcher,
        store,
        &candidate.url,
        &candidate.filename,
        &candidate.sha256,
        kind,
        &package.name,
        &package.version,
        MAX_ARTIFACT_BYTES,
    ) {
        Ok((dir, bytes)) => Outcome::Ready { dir, bytes },
        Err(ArtifactError::Fetch(FetchError::Mismatch {
            url,
            expected,
            actual,
        })) => Outcome::Refused(format!(
            "{}: {url} served sha256 {actual}, and the lock pins {expected}",
            package.pin()
        )),
        Err(error) => Outcome::Skipped(format!("{}: {error}", package.pin())),
    }
}

/// Fetch every package of `plan` into the store, in parallel, and return the
/// artifact directories in the plan's order, adding what happened to
/// `report`.
pub fn fetch_plan(
    fetcher: &dyn Fetcher,
    store: &Path,
    index: &IndexConfig,
    target: &Target,
    plan: &Plan,
    report: &mut ProvisionReport,
) -> Vec<PathBuf> {
    let wheel_target = WheelTarget {
        minor: target.minor,
        platform: target.platform,
    };
    let next = AtomicUsize::new(0);
    let outcomes: Mutex<Vec<Option<Outcome>>> =
        Mutex::new((0..plan.packages.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..PARALLEL_FETCHES.min(plan.packages.len().max(1)) {
            scope.spawn(|| loop {
                let at = next.fetch_add(1, Ordering::Relaxed);
                let Some(package) = plan.packages.get(at) else {
                    break;
                };
                let outcome = fetch_one(fetcher, store, index, &wheel_target, package);
                outcomes.lock().unwrap_or_else(|e| e.into_inner())[at] = Some(outcome);
            });
        }
    });
    let mut dirs = Vec::new();
    for outcome in outcomes
        .into_inner()
        .unwrap_or_else(|e| e.into_inner())
        .into_iter()
        .flatten()
    {
        match outcome {
            Outcome::Ready { dir, bytes } => {
                if bytes > 0 {
                    report.fetched += 1;
                    report.fetched_bytes += bytes;
                } else {
                    report.reused += 1;
                }
                dirs.push(dir);
            }
            Outcome::Skipped(reason) => report.skipped.push(reason),
            Outcome::Refused(reason) => report.refused.push(reason),
        }
    }
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::contract::hex;
    use crate::adapters::repo_scan::Fixture;
    use crate::analysis_env::fetch::testing::FixedFetcher;
    use crate::analysis_env::fetch::NetworkConfig;
    use crate::analysis_env::python::lockfile::{FileKind, LockedFile};
    use crate::analysis_env::python::tags::{Os, Platform};
    use crate::analysis_env::unpack::testing::{write_tar_gz, write_zip};
    use sha2::Digest;
    use std::collections::BTreeSet;

    fn target() -> Target {
        Target {
            full_version: "3.12.14".to_string(),
            minor: 12,
            platform: Platform {
                os: Os::Linux {
                    glibc: Some((2, 35)),
                    musl: None,
                },
                arch: "x86_64",
            },
        }
    }

    fn pypi() -> IndexConfig {
        IndexConfig {
            index_url: super::super::index::PYPI.to_string(),
            extra_index_urls: Vec::new(),
            source: "test".to_string(),
            network: NetworkConfig::default(),
        }
    }

    fn bytes_of(path: &Path) -> Vec<u8> {
        std::fs::read(path).unwrap()
    }

    fn digest(bytes: &[u8]) -> String {
        hex(&sha2::Sha256::digest(bytes))
    }

    fn package(name: &str, files: Vec<LockedFile>) -> PlannedPackage {
        PlannedPackage {
            name: name.to_string(),
            version: "1.0".to_string(),
            hashes: files.iter().filter_map(|f| f.sha256.clone()).collect(),
            files,
            index: None,
        }
    }

    fn file(filename: &str, url: &str, sha256: &str, kind: FileKind) -> LockedFile {
        LockedFile {
            kind,
            filename: filename.to_string(),
            url: Some(url.to_string()),
            sha256: Some(sha256.to_string()),
            size: None,
        }
    }

    /// The best wheel for the target is fetched, verified and unpacked; a
    /// second run finds it in the store and downloads nothing.
    #[test]
    fn the_chosen_wheel_is_fetched_once_and_shared() {
        let dir = Fixture::new("provision-wheel");
        let wheel = dir.root.join("w.whl");
        write_zip(&wheel, &[("pkg/__init__.py", b"def f(): pass\n")]);
        let wheel_bytes = bytes_of(&wheel);
        let sha = digest(&wheel_bytes);
        let mut fetcher = FixedFetcher::default();
        let url = "https://files.pythonhosted.org/pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.whl";
        fetcher.files.insert(url.to_string(), wheel_bytes);
        let plan_package = package(
            "pkg",
            vec![
                file(
                    "pkg-1.0-cp312-cp312-win_amd64.whl",
                    "https://x/win",
                    &digest(b"w"),
                    FileKind::Wheel,
                ),
                file(
                    "pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.whl",
                    url,
                    &sha,
                    FileKind::Wheel,
                ),
            ],
        );
        let plan = Plan {
            format: super::super::lockfile::LockFormat::UvLock,
            lock: PathBuf::from("uv.lock"),
            packages: vec![plan_package],
            in_repo: Vec::new(),
            skipped: Vec::new(),
            identity: Default::default(),
        };
        let store = dir.root.join("store");
        let mut report = ProvisionReport::default();
        let dirs = fetch_plan(&fetcher, &store, &pypi(), &target(), &plan, &mut report);
        assert_eq!(report.fetched, 1, "{report:?}");
        assert!(dirs[0].join("pkg/__init__.py").is_file());
        assert_eq!(fetcher.requests.lock().unwrap().as_slice(), [url]);

        let mut again = ProvisionReport::default();
        fetch_plan(&fetcher, &store, &pypi(), &target(), &plan, &mut again);
        assert_eq!((again.fetched, again.reused), (0, 1));
        assert_eq!(
            fetcher.requests.lock().unwrap().len(),
            1,
            "no second download"
        );
    }

    /// Bytes that do not match the lock are refused and nothing is stored.
    #[test]
    fn a_hash_mismatch_is_refused() {
        let dir = Fixture::new("provision-mismatch");
        let mut fetcher = FixedFetcher::default();
        let url = "https://files.pythonhosted.org/pkg-1.0-py3-none-any.whl";
        fetcher
            .files
            .insert(url.to_string(), b"not what was locked".to_vec());
        let locked = digest(b"what was locked");
        let plan = Plan {
            format: super::super::lockfile::LockFormat::UvLock,
            lock: PathBuf::from("uv.lock"),
            packages: vec![package(
                "pkg",
                vec![file(
                    "pkg-1.0-py3-none-any.whl",
                    url,
                    &locked,
                    FileKind::Wheel,
                )],
            )],
            in_repo: Vec::new(),
            skipped: Vec::new(),
            identity: Default::default(),
        };
        let store = dir.root.join("store");
        let mut report = ProvisionReport::default();
        let dirs = fetch_plan(&fetcher, &store, &pypi(), &target(), &plan, &mut report);
        assert!(dirs.is_empty());
        assert_eq!(report.refused.len(), 1);
        assert!(report.refused[0].contains(&locked), "{:?}", report.refused);
        assert!(!store::artifact_dir(&store, &locked).exists());
    }

    /// A package locked only as an sdist that compiles native code is left
    /// out and never built: its `setup.py`, which would write a file if it
    /// ran, never runs. A pure-Python one has its source extracted.
    #[test]
    fn an_sdist_is_read_never_built() {
        let dir = Fixture::new("provision-sdist");
        let marker = dir.root.join("setup-py-ran");
        let setup = format!(
            "open({:?}, 'w').write('ran')\nfrom setuptools import setup, Extension\nsetup(ext_modules=[Extension('n', ['n.c'])])\n",
            marker.display().to_string()
        );
        let native = dir.root.join("native.tar.gz");
        write_tar_gz(
            &native,
            &[
                ("native-1.0/setup.py", setup.as_bytes()),
                ("native-1.0/n.c", b"int main(void) { return 0; }\n"),
                ("native-1.0/native/__init__.py", b""),
            ],
        );
        let pure = dir.root.join("pure.tar.gz");
        write_tar_gz(
            &pure,
            &[
                (
                    "pure-1.0/setup.py",
                    setup
                        .replace("ext_modules=[Extension('n', ['n.c'])]", "")
                        .as_bytes(),
                ),
                ("pure-1.0/src/pure/__init__.py", b"def hello(): pass\n"),
                ("pure-1.0/tests/test_pure.py", b""),
            ],
        );
        let mut fetcher = FixedFetcher::default();
        let (native_bytes, pure_bytes) = (bytes_of(&native), bytes_of(&pure));
        let (native_sha, pure_sha) = (digest(&native_bytes), digest(&pure_bytes));
        fetcher
            .files
            .insert("https://x/native-1.0.tar.gz".to_string(), native_bytes);
        fetcher
            .files
            .insert("https://x/pure-1.0.tar.gz".to_string(), pure_bytes);
        let plan = Plan {
            format: super::super::lockfile::LockFormat::UvLock,
            lock: PathBuf::from("uv.lock"),
            packages: vec![
                package(
                    "native",
                    vec![file(
                        "native-1.0.tar.gz",
                        "https://x/native-1.0.tar.gz",
                        &native_sha,
                        FileKind::Sdist,
                    )],
                ),
                package(
                    "pure",
                    vec![file(
                        "pure-1.0.tar.gz",
                        "https://x/pure-1.0.tar.gz",
                        &pure_sha,
                        FileKind::Sdist,
                    )],
                ),
            ],
            in_repo: Vec::new(),
            skipped: Vec::new(),
            identity: Default::default(),
        };
        let store = dir.root.join("store");
        let mut report = ProvisionReport::default();
        let dirs = fetch_plan(&fetcher, &store, &pypi(), &target(), &plan, &mut report);
        assert_eq!(report.skipped.len(), 1, "{:?}", report.skipped);
        assert!(
            report.skipped[0].contains("compiles native code"),
            "{:?}",
            report.skipped
        );
        assert_eq!(dirs.len(), 1);
        assert!(dirs[0].join("pure/__init__.py").is_file());
        assert!(!dirs[0].join("tests").exists());
        assert!(dirs[0].join("pure-1.0.dist-info/METADATA").is_file());
        assert!(!marker.exists(), "setup.py never ran");
        assert!(report.processes.is_empty());
    }

    /// A digest-only lock reuses a stored wheel only when the wheel's own
    /// tags suit the target: one stored for another Python is fetched anew.
    #[test]
    fn a_stored_wheel_for_another_python_is_not_reused() {
        let dir = Fixture::new("provision-reuse-tags");
        let store = dir.root.join("store");
        let other = digest(b"cp311 wheel");
        dir.write(
            &format!("store/artifacts/{other}/pkg-1.0.dist-info/WHEEL"),
            "Wheel-Version: 1.0\nTag: cp311-cp311-manylinux_2_17_x86_64\n",
        );
        let wheel = dir.root.join("w.whl");
        write_zip(
            &wheel,
            &[
                ("pkg/__init__.py", b""),
                (
                    "pkg-1.0.dist-info/WHEEL",
                    b"Tag: cp312-cp312-manylinux_2_17_x86_64\n",
                ),
            ],
        );
        let wheel_bytes = bytes_of(&wheel);
        let own = digest(&wheel_bytes);
        let mut fetcher = FixedFetcher::default();
        fetcher.documents.insert(
            "https://pypi.org/simple/pkg/".to_string(),
            (
                "application/vnd.pypi.simple.v1+json".to_string(),
                format!(r#"{{"files": [{{"filename": "pkg-1.0-cp311-cp311-manylinux_2_17_x86_64.whl", "url": "https://x/311", "hashes": {{"sha256": "{other}"}}}}, {{"filename": "pkg-1.0-cp312-cp312-manylinux_2_17_x86_64.whl", "url": "https://x/312", "hashes": {{"sha256": "{own}"}}}}]}}"#).into_bytes(),
            ),
        );
        fetcher
            .files
            .insert("https://x/312".to_string(), wheel_bytes);
        let mut planned = package("pkg", Vec::new());
        planned.hashes = BTreeSet::from([other.clone(), own.clone()]);
        let plan = Plan {
            format: super::super::lockfile::LockFormat::Requirements,
            lock: PathBuf::from("requirements.txt"),
            packages: vec![planned],
            in_repo: Vec::new(),
            skipped: Vec::new(),
            identity: Default::default(),
        };
        let mut report = ProvisionReport::default();
        let dirs = fetch_plan(&fetcher, &store, &pypi(), &target(), &plan, &mut report);
        assert_eq!(report.fetched, 1, "{report:?}");
        assert_eq!(dirs[0], store::artifact_dir(&store, &own));
    }

    /// A lock that names digests without files is matched against the
    /// configured index's listing, and a mirror the user configured is used
    /// even when the lock names PyPI's URLs.
    #[test]
    fn a_digest_only_lock_is_matched_on_the_configured_index() {
        let dir = Fixture::new("provision-index");
        let wheel = dir.root.join("w.whl");
        write_zip(&wheel, &[("idna/__init__.py", b"")]);
        let wheel_bytes = bytes_of(&wheel);
        let sha = digest(&wheel_bytes);
        let mut fetcher = FixedFetcher::default();
        fetcher.documents.insert(
            "https://mirror.example/simple/idna/".to_string(),
            (
                "application/vnd.pypi.simple.v1+json".to_string(),
                format!(r#"{{"files": [{{"filename": "idna-1.0-py3-none-any.whl", "url": "/files/idna-1.0-py3-none-any.whl", "hashes": {{"sha256": "{sha}"}}}}]}}"#).into_bytes(),
            ),
        );
        fetcher.files.insert(
            "https://mirror.example/files/idna-1.0-py3-none-any.whl".to_string(),
            wheel_bytes,
        );
        let mut planned = package("idna", Vec::new());
        planned.hashes = BTreeSet::from([sha.clone()]);
        let plan = Plan {
            format: super::super::lockfile::LockFormat::Requirements,
            lock: PathBuf::from("requirements.txt"),
            packages: vec![planned],
            in_repo: Vec::new(),
            skipped: Vec::new(),
            identity: Default::default(),
        };
        let mirror = IndexConfig {
            index_url: "https://mirror.example/simple".to_string(),
            ..pypi()
        };
        let store = dir.root.join("store");
        let mut report = ProvisionReport::default();
        let dirs = fetch_plan(&fetcher, &store, &mirror, &target(), &plan, &mut report);
        assert_eq!(report.fetched, 1, "{report:?}");
        assert!(dirs[0].join("idna/__init__.py").is_file());
    }
}
