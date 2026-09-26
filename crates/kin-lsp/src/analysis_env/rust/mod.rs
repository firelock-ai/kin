// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Rust analysis environments.
//!
//! A Cargo workspace locks its dependencies in `Cargo.lock`, each registry
//! crate with the sha256 of its `.crate` file. Kin downloads exactly those
//! files from the registry the user's Cargo configuration names, checks each
//! against the lock before unpacking it, and keeps the unpacked crates in a
//! store under `KIN_HOME` that every repository shares, named by digest.
//!
//! rust-analyzer then runs with a Kin-owned `CARGO_HOME` whose configuration
//! replaces each registry with a Cargo directory source over those crates,
//! and with `CARGO_NET_OFFLINE=true`, so `cargo metadata` resolves the lock
//! without the network and without running anything. Build scripts and
//! procedural macros stay off in rust-analyzer's own configuration. A git
//! dependency is not fetched: it gets a stub crate that declares the lock's
//! edges and nothing else, so the workspace still loads, and calls into it
//! get no answer.
//!
//! The standard library comes from the pinned toolchain's `rust-src`, which
//! Kin fetches only when that toolchain lacks it (see [`toolchain`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::adapters::contract::{EnvironmentIdentity, ProvisionReport};

use super::fetch::Fetcher;
use super::write_atomically;

pub mod lockfile;
pub mod registry;
pub mod toolchain;

use lockfile::{CargoLock, CrateSource, LockedCrate, CRATES_IO};
use registry::{CargoConfig, Origin};
use toolchain::RustSrc;

/// The Rust store under Kin's cache.
pub fn store_dir(cache: &Path) -> PathBuf {
    super::store_root(cache).join("rust")
}

/// What the environment step reads from the host.
#[derive(Debug, Clone)]
pub struct Host<'a> {
    pub vars: &'a HashMap<String, String>,
    pub home: Option<&'a Path>,
    /// Kin's cache directory, `$KIN_HOME/cache`.
    pub cache: &'a Path,
    pub analysis_environments: bool,
    /// The host's target triple.
    pub triple: Option<&'a str>,
}

impl Host<'_> {
    pub fn store(&self) -> PathBuf {
        store_dir(self.cache)
    }
}

/// Every crate the workspace's locks pin, merged across locks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Locked {
    /// Registry crates, each with the checksum the lock names.
    pub registry: Vec<LockedCrate>,
    /// Git dependencies, which are stubbed rather than fetched.
    pub git: Vec<LockedCrate>,
    /// Every package, for the edges a stub declares.
    pub all: Vec<LockedCrate>,
    /// The lockfiles read.
    pub files: Vec<PathBuf>,
    /// Lockfiles that could not be read, and locked entries left out.
    pub problems: Vec<String>,
}

impl Locked {
    pub fn from_locks(locks: &[CargoLock], problems: Vec<String>) -> Self {
        let mut registry = BTreeMap::new();
        let mut git = BTreeMap::new();
        let mut all = BTreeSet::new();
        let mut problems = problems;
        for lock in locks {
            for package in &lock.packages {
                all.insert(package.clone());
                let key = (
                    package.name.clone(),
                    package.version.clone(),
                    package.source.id(),
                );
                match &package.source {
                    CrateSource::Registry(_) if package.checksum.is_some() => {
                        registry.entry(key).or_insert_with(|| package.clone());
                    }
                    CrateSource::Registry(_) => problems.push(format!(
                        "{}: {} names no checksum, so it cannot be verified",
                        package.pin(),
                        lock.path.display()
                    )),
                    CrateSource::Git { .. } => {
                        git.entry(key).or_insert_with(|| package.clone());
                    }
                    CrateSource::Path => {}
                    CrateSource::Other(source) => problems.push(format!(
                        "{}: its source {source} is not one Kin fetches from",
                        package.pin()
                    )),
                }
            }
        }
        Self {
            registry: registry.into_values().collect(),
            git: git.into_values().collect(),
            all: all.into_iter().collect(),
            files: locks.iter().map(|lock| lock.path.clone()).collect(),
            problems,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.registry.is_empty() && self.git.is_empty()
    }
}

/// Why the user's Cargo home cannot serve the lock offline, or `Ok` when it
/// holds every locked registry crate unpacked, with its index entry, and
/// every git dependency checked out.
pub fn check_cargo_home(cargo_home: &Path, locked: &Locked) -> Result<(), String> {
    let dirs = |sub: &str| -> Vec<PathBuf> {
        std::fs::read_dir(cargo_home.join(sub))
            .map(|entries| entries.filter_map(Result::ok).map(|e| e.path()).collect())
            .unwrap_or_default()
    };
    let sources = dirs("registry/src");
    let indexes = dirs("registry/index");
    let checkouts = dirs("git/checkouts");
    let missing_crates = locked
        .registry
        .iter()
        .filter(|package| {
            let dir = format!("{}-{}", package.name, package.version);
            let unpacked = sources
                .iter()
                .any(|source| source.join(&dir).join(".cargo-ok").is_file());
            let prefix = registry::index_prefix(&package.name.to_ascii_lowercase());
            let indexed = indexes.iter().any(|index| {
                index
                    .join(".cache")
                    .join(&prefix)
                    .join(package.name.to_ascii_lowercase())
                    .is_file()
            });
            !(unpacked && indexed)
        })
        .count();
    let missing_git = locked
        .git
        .iter()
        .filter(|package| {
            let CrateSource::Git { commit, .. } = &package.source else {
                return false;
            };
            let short: String = commit.chars().take(7).collect();
            !checkouts
                .iter()
                .any(|checkout| checkout.join(&short).is_dir())
        })
        .count();
    if missing_crates == 0 && missing_git == 0 {
        return Ok(());
    }
    Err(format!(
        "{} lacks {missing_crates} of {} locked crate(s) with their index entries, and \
         {missing_git} of {} git checkout(s)",
        cargo_home.display(),
        locked.registry.len(),
        locked.git.len()
    ))
}

/// Where the standard library's source comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdSource {
    /// The pinned (or default) installed toolchain has `rust-src`.
    Installed { toolchain: String, library: PathBuf },
    /// Kin's store has it, or will: the release, and the installed
    /// toolchain that runs Cargo when the pinned one is not installed.
    Kin {
        src: Option<RustSrc>,
        channel: String,
        library: Option<PathBuf>,
        substitute: Option<String>,
    },
    /// No rustup on this host: rust-analyzer discovers the sysroot from the
    /// `rustc` it finds, which no pin checks.
    Discover,
    /// No toolchain to run Cargo with, or no way to get the library.
    Missing(String),
}

impl StdSource {
    /// The standard library's source directory, when it is on disk.
    pub fn library(&self) -> Option<&Path> {
        match self {
            StdSource::Installed { library, .. } => Some(library),
            StdSource::Kin { library, .. } => library.as_deref(),
            _ => None,
        }
    }
}

/// The record of which `rust-src` a channel resolved to, so a later
/// assessment finds it without the network.
fn channel_record(store: &Path, channel: &str) -> PathBuf {
    store
        .join("rust-src/channels")
        .join(format!("{}.json", channel.replace(['/', '\\'], "_")))
}

fn read_channel_record(store: &Path, channel: &str) -> Option<RustSrc> {
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(channel_record(store, channel)).ok()?).ok()?;
    Some(RustSrc {
        release: value.get("release")?.as_str()?.to_string(),
        url: value.get("url")?.as_str()?.to_string(),
        sha256: value.get("sha256")?.as_str()?.to_string(),
    })
}

/// Choose where `std` is read from for the repository at `root`.
pub fn choose_std(root: &Path, host: &Host<'_>) -> (StdSource, String) {
    let pinned = toolchain::pinned_channel(root);
    let rustup = toolchain::rustup_home(host.vars, host.home);
    let (Some(rustup), Some(triple)) = (rustup, host.triple) else {
        return (
            StdSource::Discover,
            "no rustup installation; the rustc on PATH".to_string(),
        );
    };
    let default = toolchain::default_toolchain(&rustup);
    let (channel, pinned_by) = match &pinned {
        Some((channel, file)) => (channel.clone(), format!("{file} pins {channel}")),
        None => match &default {
            Some(default) => (
                toolchain::channel_name(default, triple),
                format!("no pin; rustup's default {default}"),
            ),
            None => {
                return (
                    StdSource::Missing("no pin and no rustup default toolchain".to_string()),
                    "no pin".to_string(),
                )
            }
        },
    };
    let installed = toolchain::installed(&rustup, &channel, triple);
    if let Some(dir) = &installed {
        if let Some(library) = toolchain::library_of(dir) {
            return (
                StdSource::Installed {
                    toolchain: channel,
                    library,
                },
                pinned_by,
            );
        }
    }
    let substitute = if installed.is_some() {
        None
    } else {
        match default.as_deref() {
            Some(default) if toolchain::installed(&rustup, default, triple).is_some() => {
                Some(toolchain::channel_name(default, triple))
            }
            _ => {
                return (
                    StdSource::Missing(format!(
                        "{channel} is not installed and no installed toolchain can run Cargo in \
                         its place"
                    )),
                    pinned_by,
                )
            }
        }
    };
    // An installed toolchain's own manifest names its exact rust-src.
    let src = installed
        .as_ref()
        .and_then(|dir| {
            std::fs::read_to_string(dir.join("lib/rustlib/multirust-channel-manifest.toml")).ok()
        })
        .and_then(|text| toolchain::rust_src_in_manifest(&text).ok())
        .or_else(|| read_channel_record(&host.store(), &channel));
    let library = src
        .as_ref()
        .and_then(|src| toolchain::stored_library(&host.store(), src));
    if library.is_none() && !host.analysis_environments {
        return (
            StdSource::Missing(format!(
                "{channel} has no rust-src installed, and analysis environments are off ({})",
                super::SWITCH_ENV
            )),
            pinned_by,
        );
    }
    (
        StdSource::Kin {
            src,
            channel,
            library,
            substitute,
        },
        pinned_by,
    )
}

/// Where a workspace's crates come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dependencies {
    /// No lock pins any registry or git crate.
    None,
    /// The repository's own Cargo configuration vendors them.
    Vendored(String),
    /// The user's Cargo home holds everything the lock pins.
    UserHome(PathBuf),
    /// Kin's Cargo home for this identity, complete or not.
    KinHome { dir: PathBuf, ready: bool },
    /// None that the repository chose can be had.
    Missing(String),
}

/// What is known about a workspace's environment without the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub locked: Locked,
    pub std: StdSource,
    pub pinned_by: String,
    pub dependencies: Dependencies,
    pub identity: EnvironmentIdentity,
    pub passed_over: Option<String>,
}

/// The identity of an environment: the standard library's release and every
/// locked crate.
pub fn identity(std: &StdSource, locked: &Locked) -> EnvironmentIdentity {
    let release = match std {
        StdSource::Installed { toolchain, .. } => format!("installed {toolchain}"),
        StdSource::Kin { src: Some(src), .. } => src.release.clone(),
        StdSource::Kin { channel, .. } => format!("channel {channel}"),
        StdSource::Discover => "discovered".to_string(),
        StdSource::Missing(_) => "none".to_string(),
    };
    let mut parts = vec!["rust".to_string(), release];
    for package in locked.registry.iter().chain(&locked.git) {
        parts.push(format!(
            "{} {} {} {}",
            package.name,
            package.version,
            package.source.id(),
            package.checksum.as_deref().unwrap_or("")
        ));
    }
    let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
    EnvironmentIdentity::of(&parts)
}

/// Kin's Cargo home for an identity.
pub fn home_dir(store: &Path, identity: &EnvironmentIdentity) -> PathBuf {
    store.join("homes").join(identity.hex())
}

/// Whether any of these manifests declares a dependency, in any table.
pub fn declares_dependencies(manifests: &[PathBuf]) -> bool {
    fn has_dependencies(table: &toml::Table) -> bool {
        ["dependencies", "dev-dependencies", "build-dependencies"]
            .iter()
            .any(|key| {
                table
                    .get(*key)
                    .and_then(toml::Value::as_table)
                    .is_some_and(|deps| !deps.is_empty())
            })
            || table
                .get("target")
                .and_then(toml::Value::as_table)
                .is_some_and(|targets| {
                    targets
                        .values()
                        .filter_map(toml::Value::as_table)
                        .any(has_dependencies)
                })
            || table
                .get("workspace")
                .and_then(|workspace| workspace.get("dependencies"))
                .and_then(toml::Value::as_table)
                .is_some_and(|deps| !deps.is_empty())
    }
    manifests.iter().any(|manifest| {
        std::fs::read_to_string(manifest)
            .ok()
            .and_then(|text| toml::from_str::<toml::Table>(&text).ok())
            .is_some_and(|table| has_dependencies(&table))
    })
}

/// Assess the environment of the workspace at `root`, whose linked projects
/// are `manifests` and whose packages' manifests are `members`.
pub fn assess(
    root: &Path,
    manifests: &[PathBuf],
    members: &[PathBuf],
    host: &Host<'_>,
) -> Assessment {
    let (locks, problems) = lockfile::read_locks(manifests);
    let (std, pinned_by) = choose_std(root, host);
    // rust-analyzer loads the standard library as a Cargo workspace of its
    // own, whose lock pins crates.io crates too: they are part of the
    // environment, fetched and verified like the repository's.
    let mut all_locks = locks.clone();
    if let Some(library) = std.library() {
        let (library_locks, _) = lockfile::read_locks(&[library.join("Cargo.toml")]);
        all_locks.extend(library_locks);
    }
    let locked = Locked::from_locks(&all_locks, problems);
    let identity = identity(&std, &locked);
    let config = CargoConfig::read(root, host.vars, host.home);
    let mut passed_over = None;
    let vendored = locked
        .registry
        .iter()
        .find_map(|package| match &package.source {
            CrateSource::Registry(source) => match config.origin(source) {
                Origin::Vendored { name, dir } => Some(format!(
                    "the Cargo source `{name}` vendors them in {}",
                    dir.display()
                )),
                _ => None,
            },
            _ => None,
        });
    let dependencies = if locks.is_empty() && declares_dependencies(&[manifests, members].concat())
    {
        Dependencies::Missing(
            "no Cargo.lock pins the dependencies, so nothing can be verified".to_string(),
        )
    } else if locked.is_empty() {
        Dependencies::None
    } else if let Some(vendored) = vendored {
        Dependencies::Vendored(vendored)
    } else {
        let user = config.cargo_home.clone();
        match user.as_deref().map(|home| check_cargo_home(home, &locked)) {
            Some(Ok(())) => Dependencies::UserHome(user.unwrap_or_default()),
            other => {
                passed_over = Some(match other {
                    Some(Err(reason)) => reason,
                    _ => "no Cargo home is configured".to_string(),
                });
                if host.analysis_environments {
                    let dir = home_dir(&host.store(), &identity);
                    Dependencies::KinHome {
                        ready: dir.join(".complete").is_file()
                            && !super::failed_long_ago(&host.store(), &identity),
                        dir,
                    }
                } else {
                    Dependencies::Missing(format!(
                        "analysis environments are off ({}), and {}",
                        super::SWITCH_ENV,
                        passed_over.as_deref().unwrap_or_default()
                    ))
                }
            }
        }
    };
    Assessment {
        locked,
        std,
        pinned_by,
        dependencies,
        identity,
        passed_over,
    }
}

/// A dependency spec for one lock edge, for a stub's manifest.
fn stub_dependency(entry: &str, all: &[LockedCrate]) -> Option<(String, String)> {
    let mut words = entry.split_whitespace();
    let name = words.next()?;
    let version = words.next();
    let source = words
        .next()
        .map(|source| source.trim_start_matches('(').trim_end_matches(')'));
    let target = all.iter().find(|package| {
        package.name == name
            && version.is_none_or(|v| package.version == v)
            && source.is_none_or(|s| package.source.id() == s)
    })?;
    let key = format!("{}-{}", target.name, target.version).replace('.', "_");
    let spec = match &target.source {
        CrateSource::Path => return None,
        CrateSource::Registry(source) if source == CRATES_IO => {
            format!(
                "{{ package = \"{}\", version = \"={}\" }}",
                target.name, target.version
            )
        }
        CrateSource::Registry(source) => format!(
            "{{ package = \"{}\", version = \"={}\", registry-index = \"{}\" }}",
            target.name,
            target.version,
            source.strip_prefix("registry+").unwrap_or(source)
        ),
        CrateSource::Git { url, reference, .. } => match reference {
            Some((kind, value)) => format!(
                "{{ package = \"{}\", git = \"{url}\", {kind} = \"{value}\" }}",
                target.name
            ),
            None => format!("{{ package = \"{}\", git = \"{url}\" }}", target.name),
        },
        CrateSource::Other(_) => return None,
    };
    Some((key, spec))
}

/// The manifest of a stub for a git dependency: its name and version, and
/// the lock's edges from it, so the lock resolves exactly as it is.
fn stub_manifest(package: &LockedCrate, all: &[LockedCrate]) -> String {
    let mut manifest = format!(
        "[package]\nname = \"{}\"\nversion = \"{}\"\nedition = \"2021\"\n\
         description = \"Kin stand-in: this git dependency is not fetched, so nothing in it resolves\"\n\n\
         [lib]\npath = \"lib.rs\"\n\n[dependencies]\n",
        package.name, package.version
    );
    for entry in &package.dependencies {
        if let Some((key, spec)) = stub_dependency(entry, all) {
            manifest.push_str(&format!("{key} = {spec}\n"));
        }
    }
    manifest
}

#[cfg(unix)]
fn link(target: &Path, path: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, path)
}

#[cfg(not(unix))]
fn link(_target: &Path, _path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "analysis environments link their crates, which needs a unix host",
    ))
}

/// Build Kin's Cargo home for an identity: a `config.toml` replacing every
/// locked registry with a directory source over the stored crates, and each
/// git dependency with its stub, then mark it complete.
fn build_home(
    dir: &Path,
    config: &CargoConfig,
    fetched: &BTreeMap<String, Vec<(LockedCrate, PathBuf)>>,
    locked: &Locked,
) -> Result<(), String> {
    let staging = dir.with_file_name(format!(
        ".{}.{}.tmp",
        dir.file_name().unwrap_or_default().to_string_lossy(),
        super::python::store::unique_suffix()
    ));
    let built = (|| -> Result<(), String> {
        let mut text = String::from(
            "# Written by Kin for rust-analyzer: every locked crate from a directory source, \
             never the network.\n[net]\noffline = true\n\n",
        );
        for (index, (source, crates)) in fetched.iter().enumerate() {
            let vendor = format!("vendor/registry-{index}");
            for (package, crate_dir) in crates {
                let entry = staging
                    .join(&vendor)
                    .join(format!("{}-{}", package.name, package.version));
                std::fs::create_dir_all(entry.parent().unwrap_or(&staging))
                    .map_err(|error| error.to_string())?;
                link(crate_dir, &entry).map_err(|error| format!("{}: {error}", entry.display()))?;
            }
            let replaced = format!("kin-registry-{index}");
            if source == CRATES_IO {
                text.push_str(&format!(
                    "[source.crates-io]\nreplace-with = \"{replaced}\"\n\n"
                ));
                // A mirror the user's configuration puts in front of
                // crates.io is replaced in turn.
                if let Some(mirror) = config_replacement(config) {
                    text.push_str(&format!(
                        "[source.{mirror}]\nreplace-with = \"{replaced}\"\n\n"
                    ));
                }
            } else {
                text.push_str(&format!(
                    "[source.kin-original-{index}]\nregistry = \"{}\"\nreplace-with = \"{replaced}\"\n\n",
                    source.strip_prefix("registry+").unwrap_or(source)
                ));
            }
            text.push_str(&format!(
                "[source.{replaced}]\ndirectory = \"{}\"\n\n",
                dir.join(&vendor).display()
            ));
        }
        if !locked.git.is_empty() {
            let stubs = staging.join("vendor/git-stubs");
            for (index, package) in locked.git.iter().enumerate() {
                let CrateSource::Git { url, reference, .. } = &package.source else {
                    continue;
                };
                let stub = stubs.join(format!("{}-{}", package.name, package.version));
                write_atomically(
                    &stub.join("Cargo.toml"),
                    stub_manifest(package, &locked.all).as_bytes(),
                )?;
                write_atomically(&stub.join("lib.rs"), b"")?;
                write_atomically(
                    &stub.join(".cargo-checksum.json"),
                    br#"{"files":{},"package":null}"#,
                )?;
                text.push_str(&format!("[source.kin-git-{index}]\ngit = \"{url}\"\n"));
                if let Some((kind, value)) = reference {
                    text.push_str(&format!("{kind} = \"{value}\"\n"));
                }
                text.push_str("replace-with = \"kin-git-stubs\"\n\n");
            }
            text.push_str(&format!(
                "[source.kin-git-stubs]\ndirectory = \"{}\"\n",
                dir.join("vendor/git-stubs").display()
            ));
        }
        write_atomically(&staging.join("config.toml"), text.as_bytes())?;
        write_atomically(&staging.join(".complete"), b"")
    })();
    if let Err(reason) = built {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(reason);
    }
    if dir.exists() {
        let retired = dir.with_extension(format!("{}.old", super::python::store::unique_suffix()));
        let _ = std::fs::rename(dir, &retired);
        let _ = std::fs::remove_dir_all(&retired);
    }
    super::python::store::publish_dir(&staging, dir)
}

/// The name of the source the user's configuration replaces crates.io with,
/// when it names one.
fn config_replacement(config: &CargoConfig) -> Option<String> {
    match config.origin(CRATES_IO) {
        Origin::Sparse { .. } => config.crates_io_replacement(),
        _ => None,
    }
}

/// Fetch what the assessment left pending: the pinned release's `rust-src`
/// and every locked crate not yet in the store, then build Kin's Cargo home.
pub fn provision(
    root: &Path,
    manifests: &[PathBuf],
    members: &[PathBuf],
    host: &Host<'_>,
    fetcher_for: &dyn Fn(&CargoConfig, Option<(&str, &str)>) -> Result<Box<dyn Fetcher>, String>,
) -> ProvisionReport {
    let started = Instant::now();
    let mut report = ProvisionReport::default();
    let assessment = assess(root, manifests, members, host);
    let store = host.store();
    let config = CargoConfig::read(root, host.vars, host.home);
    report
        .skipped
        .extend(assessment.locked.problems.iter().cloned());
    let fetcher = match fetcher_for(&config, None) {
        Ok(fetcher) => fetcher,
        Err(reason) => {
            report.failure = Some(reason);
            return report;
        }
    };
    if let StdSource::Kin {
        src,
        channel,
        library: None,
        ..
    } = &assessment.std
    {
        let src = match src {
            Some(src) => Ok(src.clone()),
            None => toolchain::fetch_manifest(fetcher.as_ref(), channel).inspect(|src| {
                let _ = write_atomically(
                    &channel_record(&store, channel),
                    serde_json::json!({
                        "release": src.release, "url": src.url, "sha256": src.sha256,
                    })
                    .to_string()
                    .as_bytes(),
                );
            }),
        };
        match src.and_then(|src| toolchain::ensure(fetcher.as_ref(), &store, &src)) {
            Ok((_, bytes)) => {
                report.fetched += 1;
                report.fetched_bytes += bytes;
            }
            Err(reason) => report
                .skipped
                .push(format!("rust-src for {channel}: {reason}")),
        }
    }
    // The fetched library's own lock joins the crates to fetch.
    let assessment = assess(root, manifests, members, host);
    let Dependencies::KinHome { dir, ready: false } = &assessment.dependencies else {
        report.elapsed_ms = started.elapsed().as_millis();
        return report;
    };
    // Group the locked crates by registry, and learn each registry's
    // download URL once.
    let mut by_source: BTreeMap<String, Vec<&LockedCrate>> = BTreeMap::new();
    for package in &assessment.locked.registry {
        if let CrateSource::Registry(source) = &package.source {
            by_source.entry(source.clone()).or_default().push(package);
        }
    }
    let mut fetched: BTreeMap<String, Vec<(LockedCrate, PathBuf)>> = BTreeMap::new();
    for (source, packages) in by_source {
        let (downloads, registry_fetcher) = match config.origin(&source) {
            Origin::CratesIo => (Ok(registry::Downloads::crates_io()), None),
            Origin::Sparse { index, token } => {
                let index_fetcher = match token.as_deref() {
                    Some(token) => fetcher_for(&config, Some((&index, token))).ok(),
                    None => None,
                };
                let downloads = registry::Downloads::fetch(
                    index_fetcher.as_deref().unwrap_or(fetcher.as_ref()),
                    &index,
                );
                // A registry that requires authentication gets its token on
                // downloads too, sent only under its download URL.
                let download_fetcher = match (&downloads, token.as_deref()) {
                    (Ok(downloads), Some(token)) if downloads.auth_required => {
                        let base = downloads.dl.split('{').next().unwrap_or(&downloads.dl);
                        fetcher_for(&config, Some((base, token))).ok()
                    }
                    _ => None,
                };
                (downloads, download_fetcher)
            }
            Origin::Vendored { .. } => continue,
            Origin::Unsupported(reason) => (Err(reason), None),
        };
        let downloads = match downloads {
            Ok(downloads) => downloads,
            Err(reason) => {
                for package in &packages {
                    report.skipped.push(format!("{}: {reason}", package.pin()));
                }
                continue;
            }
        };
        let used = registry_fetcher.as_deref().unwrap_or(fetcher.as_ref());
        let outcomes = super::parallel_map(&packages, super::PARALLEL_FETCHES, |package| {
            let checksum = package.checksum.clone().unwrap_or_default();
            let url = downloads.url(&package.name, &package.version, &checksum);
            registry::ensure_crate(
                used,
                &store,
                &url,
                &package.name,
                &package.version,
                &checksum,
            )
            .map_err(|error| {
                let refused = matches!(error, super::fetch::FetchError::Mismatch { .. });
                (refused, format!("{}: {error}", package.pin()))
            })
        });
        for (package, outcome) in packages.iter().zip(outcomes) {
            match outcome {
                Ok((crate_dir, bytes)) => {
                    if bytes > 0 {
                        report.fetched += 1;
                        report.fetched_bytes += bytes;
                    } else {
                        report.reused += 1;
                    }
                    fetched
                        .entry(source.clone())
                        .or_default()
                        .push(((*package).clone(), crate_dir));
                }
                Err((true, reason)) => report.refused.push(reason),
                Err((false, reason)) => report.skipped.push(reason),
            }
        }
    }
    let failures = report.skipped.len() + report.refused.len();
    super::record_attempt(&store, &assessment.identity, failures);
    for package in &assessment.locked.git {
        report.skipped.push(format!(
            "{} ({}): a git dependency, not fetched; a stub stands in so the workspace loads",
            package.pin(),
            package.source.id()
        ));
    }
    match build_home(dir, &config, &fetched, &assessment.locked) {
        Ok(()) => report.environment = Some(dir.clone()),
        Err(reason) => report.failure = Some(reason),
    }
    report.elapsed_ms = started.elapsed().as_millis();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::contract::hex;
    use crate::adapters::repo_scan::Fixture;
    use crate::analysis_env::fetch::testing::FixedFetcher;
    use crate::analysis_env::unpack::testing::write_tar_gz;
    use sha2::Digest;

    fn host<'a>(vars: &'a HashMap<String, String>, cache: &'a Path) -> Host<'a> {
        Host {
            vars,
            home: None,
            cache,
            analysis_environments: true,
            triple: Some("aarch64-apple-darwin"),
        }
    }

    fn rustup(fixture: &Fixture) {
        fixture.write(
            "rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/lib.rs",
            "",
        );
        for tool in ["cargo", "rustc"] {
            fixture.write(
                &format!("rustup/toolchains/stable-aarch64-apple-darwin/bin/{tool}"),
                "",
            );
            fixture.write(
                &format!("rustup/toolchains/1.91.0-aarch64-apple-darwin/bin/{tool}"),
                "",
            );
        }
        fixture.write(
            "rustup/settings.toml",
            "default_toolchain = \"stable-aarch64-apple-darwin\"\n",
        );
    }

    /// Locked crates are fetched, verified, stored by digest and served
    /// through a directory source; a git dependency gets a stub declaring the
    /// lock's edges; nothing runs.
    #[cfg(unix)]
    #[test]
    fn a_locked_workspace_gets_a_cargo_home_of_verified_crates() {
        let repo = Fixture::new("rust-env");
        let cache = Fixture::new("rust-env-cache");
        rustup(&cache);
        let archive = cache.root.join("demo.crate");
        write_tar_gz(
            &archive,
            &[
                (
                    "demo-0.1.0/Cargo.toml",
                    b"[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
                ),
                (
                    "demo-0.1.0/build.rs",
                    b"fn main() { std::fs::write(\"/tmp/x\", \"\").unwrap(); }\n",
                ),
                ("demo-0.1.0/src/lib.rs", b"pub fn f() {}\n"),
            ],
        );
        let bytes = std::fs::read(&archive).unwrap();
        let sha = hex(&sha2::Sha256::digest(&bytes));
        let manifest = repo.write(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        );
        repo.write(
            "Cargo.lock",
            &format!(
                "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"demo\", \"patched\"]\n\n\
                 [[package]]\nname = \"demo\"\nversion = \"0.1.0\"\nsource = \"{CRATES_IO}\"\nchecksum = \"{sha}\"\n\n\
                 [[package]]\nname = \"patched\"\nversion = \"0.2.0\"\n\
                 source = \"git+https://git.example/patched?branch=main#0123456789abcdef\"\ndependencies = [\"demo\"]\n"
            ),
        );
        let mut vars = HashMap::new();
        vars.insert(
            "CARGO_HOME".to_string(),
            cache.root.join("user-cargo").display().to_string(),
        );
        vars.insert(
            "RUSTUP_HOME".to_string(),
            cache.root.join("rustup").display().to_string(),
        );
        let host = host(&vars, &cache.root);
        let before = assess(&repo.root, std::slice::from_ref(&manifest), &[], &host);
        let Dependencies::KinHome { dir, ready: false } = &before.dependencies else {
            panic!("{:?}", before.dependencies);
        };
        assert!(matches!(before.std, StdSource::Installed { .. }));

        let mut fetcher = FixedFetcher::default();
        fetcher.files.insert(
            "https://static.crates.io/crates/demo/0.1.0/download".to_string(),
            bytes,
        );
        let shared = std::sync::Arc::new(fetcher);
        let fetcher_for =
            |_: &CargoConfig, _: Option<(&str, &str)>| -> Result<Box<dyn Fetcher>, String> {
                Ok(Box::new(SharedFetcher(shared.clone())))
            };
        let report = provision(
            &repo.root,
            std::slice::from_ref(&manifest),
            &[],
            &host,
            &fetcher_for,
        );
        assert_eq!(report.fetched, 1, "{report:?}");
        assert!(
            report.refused.is_empty() && report.processes.is_empty(),
            "{report:?}"
        );
        assert!(report
            .skipped
            .iter()
            .any(|reason| reason.contains("git dependency")));
        let after = assess(&repo.root, &[manifest], &[], &host);
        assert_eq!(
            after.dependencies,
            Dependencies::KinHome {
                dir: dir.clone(),
                ready: true
            }
        );
        let config = std::fs::read_to_string(dir.join("config.toml")).unwrap();
        assert!(
            config.contains("[source.crates-io]\nreplace-with = \"kin-registry-0\""),
            "{config}"
        );
        assert!(config.contains("branch = \"main\""), "{config}");
        let vendored = dir.join("vendor/registry-0/demo-0.1.0");
        assert!(vendored.join("src/lib.rs").is_file());
        let build_script = vendored.join("build.rs");
        assert!(build_script.is_file(), "a build script is kept as data");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&build_script)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0, "and is never executable");
        }
        let stub =
            std::fs::read_to_string(dir.join("vendor/git-stubs/patched-0.2.0/Cargo.toml")).unwrap();
        assert!(
            stub.contains("demo-0_1_0 = { package = \"demo\", version = \"=0.1.0\" }"),
            "{stub}"
        );
    }

    struct SharedFetcher(std::sync::Arc<FixedFetcher>);

    impl Fetcher for SharedFetcher {
        fn document(
            &self,
            url: &str,
            accept: &str,
        ) -> Result<(String, Vec<u8>), crate::analysis_env::fetch::FetchError> {
            self.0.document(url, accept)
        }
        fn download(
            &self,
            url: &str,
            destination: &Path,
            max_bytes: u64,
        ) -> Result<crate::analysis_env::fetch::Downloaded, crate::analysis_env::fetch::FetchError>
        {
            self.0.download(url, destination, max_bytes)
        }
    }

    /// The providers in order: the user's Cargo home when it holds every
    /// locked crate unpacked with its index entry; else Kin's; with the
    /// switch off, missing, and saying why.
    #[test]
    fn the_users_cargo_home_serves_only_when_it_holds_the_lock() {
        let repo = Fixture::new("rust-provider-order");
        let cache = Fixture::new("rust-provider-order-cache");
        rustup(&cache);
        let manifest = repo.write(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1\"\n",
        );
        repo.write(
            "Cargo.lock",
            &format!(
                "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n\
                 source = \"{CRATES_IO}\"\nchecksum = \"{}\"\n",
                "a".repeat(64)
            ),
        );
        let user = cache.root.join("user-cargo");
        let mut vars = HashMap::new();
        vars.insert("CARGO_HOME".to_string(), user.display().to_string());
        vars.insert(
            "RUSTUP_HOME".to_string(),
            cache.root.join("rustup").display().to_string(),
        );
        let mut host = host(&vars, &cache.root);
        let manifests = std::slice::from_ref(&manifest);
        assert!(matches!(
            assess(&repo.root, manifests, &[], &host).dependencies,
            Dependencies::KinHome { ready: false, .. }
        ));
        cache.write(
            "user-cargo/registry/src/index.crates.io-x/serde-1.0.200/.cargo-ok",
            "",
        );
        assert!(
            matches!(
                assess(&repo.root, manifests, &[], &host).dependencies,
                Dependencies::KinHome { .. }
            ),
            "unpacked but not indexed, so Cargo could not resolve it offline"
        );
        cache.write(
            "user-cargo/registry/index/index.crates.io-x/.cache/se/rd/serde",
            "",
        );
        assert_eq!(
            assess(&repo.root, manifests, &[], &host).dependencies,
            Dependencies::UserHome(user.clone())
        );
        std::fs::remove_dir_all(&user).unwrap();
        host.analysis_environments = false;
        assert!(matches!(
            assess(&repo.root, manifests, &[], &host).dependencies,
            Dependencies::Missing(reason) if reason.contains("analysis environments are off")
        ));
    }

    /// The standard library is a workspace with a lock of its own, and its
    /// crates are part of the environment, so rust-analyzer can load `std`
    /// offline.
    #[test]
    fn the_standard_librarys_locked_crates_join_the_environment() {
        let repo = Fixture::new("rust-std-lock");
        let cache = Fixture::new("rust-std-lock-cache");
        rustup(&cache);
        cache.write(
            "rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/Cargo.toml",
            "[workspace]\nmembers = [\"std\"]\n",
        );
        cache.write(
            "rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/Cargo.lock",
            &format!(
                "version = 4\n\n[[package]]\nname = \"rustc-demangle\"\nversion = \"0.1.24\"\n\
                 source = \"{CRATES_IO}\"\nchecksum = \"ab\"\n"
            ),
        );
        let manifest = repo.write(
            "Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
        );
        repo.write("Cargo.lock", "version = 4\n");
        let mut vars = HashMap::new();
        vars.insert(
            "CARGO_HOME".to_string(),
            cache.root.join("user-cargo").display().to_string(),
        );
        vars.insert(
            "RUSTUP_HOME".to_string(),
            cache.root.join("rustup").display().to_string(),
        );
        let host = host(&vars, &cache.root);
        let assessment = assess(&repo.root, std::slice::from_ref(&manifest), &[], &host);
        let names: Vec<&str> = assessment
            .locked
            .registry
            .iter()
            .map(|package| package.name.as_str())
            .collect();
        assert_eq!(names, vec!["rustc-demangle"]);
        assert!(matches!(
            assessment.dependencies,
            Dependencies::KinHome { ready: false, .. }
        ));
    }

    /// A pinned toolchain without rust-src is served by Kin's copy of the
    /// component; switched off, it is missing and says why.
    #[test]
    fn a_pinned_toolchain_without_rust_src_takes_kins() {
        let repo = Fixture::new("rust-std");
        let cache = Fixture::new("rust-std-cache");
        rustup(&cache);
        cache.write("rustup/toolchains/1.91.0-aarch64-apple-darwin/lib/rustlib/multirust-channel-manifest.toml",
            "date = \"2025-10-30\"\n[pkg.rustc]\nversion = \"1.91.0 (x 2025-10-30)\"\n\
             [pkg.rust-src.target.\"*\"]\nurl = \"https://dist.example/rust-src.tar.gz\"\nhash = \"ab\"\n");
        repo.write("rust-toolchain.toml", "[toolchain]\nchannel = \"1.91.0\"\n");
        let mut vars = HashMap::new();
        vars.insert(
            "RUSTUP_HOME".to_string(),
            cache.root.join("rustup").display().to_string(),
        );
        let mut host = host(&vars, &cache.root);
        let (std, pinned_by) = choose_std(&repo.root, &host);
        assert_eq!(pinned_by, "rust-toolchain.toml pins 1.91.0");
        let StdSource::Kin {
            src: Some(src),
            substitute: None,
            library: None,
            ..
        } = std
        else {
            panic!("{std:?}");
        };
        assert_eq!(src.release, "1.91.0-2025-10-30");

        repo.write("rust-toolchain.toml", "[toolchain]\nchannel = \"1.78.0\"\n");
        let (std, _) = choose_std(&repo.root, &host);
        assert!(
            matches!(&std, StdSource::Kin { src: None, substitute: Some(s), .. } if s == "stable"),
            "{std:?}"
        );
        host.analysis_environments = false;
        assert!(matches!(
            choose_std(&repo.root, &host).0,
            StdSource::Missing(_)
        ));
    }
}
