// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! JavaScript and TypeScript analysis environments.
//!
//! A JavaScript repository locks its dependencies in `package-lock.json`,
//! `pnpm-lock.yaml` or `yarn.lock`, each package with the integrity hash of
//! its tarball ([`lockfile`] reads all of them into one graph). Kin downloads
//! exactly those tarballs from the registry the user's `.npmrc` or `.yarnrc`
//! names, checks each against the lock's hash before unpacking it as data,
//! and keeps the unpacked packages in a store under `KIN_HOME` named by
//! digest, which repositories share.
//!
//! The packages are then laid out as a `node_modules` tree of Kin's own,
//! outside the repository ([`layout`]): every importer's directory mirrored
//! with its direct dependencies, and every package in a directory of its own
//! beside exactly the dependencies the lock resolved for it, the way pnpm
//! lays them out. Nothing is installed: no lifecycle script runs, no binary
//! is linked, and nothing is written into the repository. tsserver is pointed
//! at the layout through Kin's workspace plugin.
//!
//! Yarn Berry's lock records only the checksum of Yarn's own cache archive,
//! which cannot verify an npm tarball, so for a package with no npm digest
//! in its lock the digest the registry publishes for that version is used,
//! and the report counts those packages apart.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::adapters::contract::{EnvironmentIdentity, ProvisionReport};

use super::fetch::{FetchError, Fetcher, HashAlgorithm, NetworkConfig};

pub mod layout;
pub mod lockfile;
pub mod yaml;

use lockfile::{Dep, JsLock, LockSearch, LockedPackage, Source};

/// The JavaScript store under Kin's cache.
pub fn store_dir(cache: &Path) -> PathBuf {
    super::store_root(cache).join("js")
}

/// npm's public registry.
pub const NPM_REGISTRY: &str = "https://registry.npmjs.org";

/// The largest tarball fetched.
pub const MAX_TARBALL_BYTES: u64 = 1024 * 1024 * 1024;

/// The registry configuration in force: npm's `.npmrc`, pnpm's (the same
/// file), Yarn Classic's `.yarnrc` and Yarn Berry's `.yarnrc.yml`, from the
/// repository and the user's home, with `npm_config_*` variables over them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registries {
    /// The registry for unscoped packages.
    pub default: String,
    /// Registries by scope, `@scope` to URL.
    pub scopes: BTreeMap<String, String>,
    /// `Authorization` values by URL prefix, from `_authToken`, `_auth` and
    /// Yarn's `npmAuthToken`.
    pub auth: Vec<(String, String)>,
    pub network: NetworkConfig,
    /// Where the configuration came from, for the report.
    pub source: String,
}

/// Replace `${NAME}` in an `.npmrc` value with the variable's value.
fn expand(value: &str, vars: &HashMap<String, String>) -> String {
    let mut out = String::new();
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        match rest[start + 2..].find('}') {
            Some(end) => {
                let name = &rest[start + 2..start + 2 + end];
                out.push_str(vars.get(name).map(String::as_str).unwrap_or(""));
                rest = &rest[start + 3 + end..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn unquote(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(value)
}

/// `https://host/path/` as the `//host/path/` key npm scopes credentials by.
fn credential_key(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    format!("//{}/", rest.trim_end_matches('/'))
}

impl Registries {
    /// Read the configuration of the repository at `root`.
    pub fn read(root: &Path, vars: &HashMap<String, String>, home: Option<&Path>) -> Self {
        let mut registries = Registries {
            default: NPM_REGISTRY.to_string(),
            source: "npm's public registry, since no configuration names one".to_string(),
            ..Registries::default()
        };
        let mut values: Vec<(String, String, String)> = Vec::new();
        // Lowest precedence first.
        let mut npmrcs: Vec<PathBuf> = Vec::new();
        if let Some(file) = vars
            .get("NPM_CONFIG_USERCONFIG")
            .or_else(|| vars.get("npm_config_userconfig"))
        {
            npmrcs.push(PathBuf::from(file));
        } else if let Some(home) = home {
            npmrcs.push(home.join(".npmrc"));
        }
        npmrcs.push(root.join(".npmrc"));
        for file in &npmrcs {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with(['#', ';']) {
                    continue;
                }
                if let Some((key, value)) = line.split_once('=') {
                    values.push((
                        key.trim().to_string(),
                        expand(unquote(value), vars),
                        file.display().to_string(),
                    ));
                }
            }
        }
        for (key, value) in vars {
            let lower = key.to_ascii_lowercase();
            if let Some(name) = lower.strip_prefix("npm_config_") {
                values.push((name.replace('_', "-"), value.clone(), key.clone()));
            }
        }
        for (key, value, source) in values {
            match key.as_str() {
                "registry" => {
                    registries.default = value.trim_end_matches('/').to_string();
                    registries.source = source;
                }
                "https-proxy" | "proxy" if !value.is_empty() => {
                    if key == "https-proxy" || registries.network.proxy.is_none() {
                        registries.network.proxy = Some(value);
                    }
                }
                "cafile" if !value.is_empty() => {
                    registries.network.ca_bundles = vec![PathBuf::from(value)];
                }
                _ => {
                    if let Some(scope) = key.strip_suffix(":registry") {
                        registries
                            .scopes
                            .insert(scope.to_string(), value.trim_end_matches('/').to_string());
                    } else if let Some(prefix) = key.strip_suffix(":_authToken") {
                        registries
                            .auth
                            .push((prefix.to_string(), format!("Bearer {value}")));
                    } else if let Some(prefix) = key.strip_suffix(":_auth") {
                        registries
                            .auth
                            .push((prefix.to_string(), format!("Basic {value}")));
                    }
                }
            }
        }
        registries.read_yarnrc(root, home, vars);
        registries
    }

    /// Yarn's settings: Classic's `registry` line in `.yarnrc`, and Berry's
    /// `npmRegistryServer`, `npmScopes` and `npmAuthToken` in `.yarnrc.yml`.
    fn read_yarnrc(&mut self, root: &Path, home: Option<&Path>, vars: &HashMap<String, String>) {
        for dir in home.into_iter().chain(std::iter::once(root)) {
            if let Ok(text) = std::fs::read_to_string(dir.join(".yarnrc")) {
                for line in text.lines() {
                    if let Some(value) = line.trim().strip_prefix("registry ") {
                        self.default = unquote(value).trim_end_matches('/').to_string();
                        self.source = dir.join(".yarnrc").display().to_string();
                    }
                }
            }
            let file = dir.join(".yarnrc.yml");
            let Some(document) = std::fs::read_to_string(&file)
                .ok()
                .and_then(|text| yaml::parse(&text).ok())
                .and_then(|documents| documents.into_iter().next())
            else {
                continue;
            };
            let text = |node: &yaml::Yaml, key: &str| {
                node.get(key)
                    .and_then(|value| value.as_str())
                    .map(|value| expand(value, vars))
            };
            if let Some(server) = text(&document, "npmRegistryServer") {
                self.default = server.trim_end_matches('/').to_string();
                self.source = file.display().to_string();
            }
            if let Some(token) = text(&document, "npmAuthToken") {
                self.auth
                    .push((credential_key(&self.default), format!("Bearer {token}")));
            }
            if let Some(scopes) = document.get("npmScopes") {
                for (scope, settings) in scopes.entries() {
                    let server =
                        text(settings, "npmRegistryServer").unwrap_or_else(|| self.default.clone());
                    let server = server.trim_end_matches('/').to_string();
                    if let Some(token) = text(settings, "npmAuthToken") {
                        self.auth
                            .push((credential_key(&server), format!("Bearer {token}")));
                    }
                    self.scopes.insert(format!("@{scope}"), server);
                }
            }
            for (key, setting) in [("httpsProxy", true), ("httpProxy", false)] {
                if let Some(proxy) = text(&document, key) {
                    if setting || self.network.proxy.is_none() {
                        self.network.proxy = Some(proxy);
                    }
                }
            }
            if let Some(cafile) = text(&document, "caFilePath") {
                self.network.ca_bundles = vec![PathBuf::from(cafile)];
            }
        }
    }

    /// The registry a package is fetched from: its scope's, else the default.
    pub fn registry_for(&self, name: &str) -> &str {
        name.split_once('/')
            .filter(|(scope, _)| scope.starts_with('@'))
            .and_then(|(scope, _)| self.scopes.get(scope))
            .map(String::as_str)
            .unwrap_or(&self.default)
    }

    /// The URL a locked registry package's tarball is fetched from. A URL on
    /// npm's or Yarn's public registry is moved to the configured registry,
    /// as npm's default `replace-registry-host` does, so a mirror serves it.
    pub fn tarball_url(&self, package: &LockedPackage, tarball: Option<&str>) -> String {
        let registry = self.registry_for(&package.name);
        match tarball {
            Some(url) => {
                for public in [NPM_REGISTRY, "https://registry.yarnpkg.com"] {
                    if let Some(rest) = url.strip_prefix(public) {
                        if registry != NPM_REGISTRY && registry != "https://registry.yarnpkg.com" {
                            return format!("{registry}{rest}");
                        }
                    }
                }
                url.to_string()
            }
            None => lockfile::registry_tarball_url(registry, &package.name, &package.version),
        }
    }

    /// `Authorization` headers by the URL prefixes they apply to.
    pub fn authorizations(&self) -> Vec<(String, String)> {
        self.auth
            .iter()
            .map(|(key, value)| {
                let prefix = key.trim_start_matches('/');
                (format!("https://{prefix}"), value.clone())
            })
            .collect()
    }
}

/// Node's name for this host's operating system and processor.
pub fn host_platform() -> (&'static str, &'static str) {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    };
    let cpu = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        "x86" => "ia32",
        other => other,
    };
    (os, cpu)
}

/// Whether a package's `os` and `cpu` restrictions admit this host, with
/// npm's negation rules (`!win32`).
pub fn admits(restrictions: &[String], value: &str) -> bool {
    if restrictions.is_empty() {
        return true;
    }
    let (negated, listed): (Vec<&String>, Vec<&String>) = restrictions
        .iter()
        .partition(|entry| entry.starts_with('!'));
    if negated.iter().any(|entry| &entry[1..] == value) {
        return false;
    }
    listed.is_empty() || listed.iter().any(|entry| entry.as_str() == value)
}

/// The fetch's own digest algorithm for a lock's.
fn algorithm(algorithm: lockfile::Algorithm) -> HashAlgorithm {
    match algorithm {
        lockfile::Algorithm::Sha512 => HashAlgorithm::Sha512,
        lockfile::Algorithm::Sha384 => HashAlgorithm::Sha384,
        lockfile::Algorithm::Sha256 => HashAlgorithm::Sha256,
        lockfile::Algorithm::Sha1 => HashAlgorithm::Sha1,
    }
}

/// The store directory of a package verified against `digests`, named by the
/// strongest of them.
pub fn package_dir(store: &Path, digests: &[(HashAlgorithm, Vec<u8>)]) -> Option<PathBuf> {
    let (algorithm, digest) = digests
        .iter()
        .max_by_key(|(algorithm, _)| *algorithm as u8)?;
    Some(store.join("packages").join(format!(
        "{}-{}",
        algorithm.name(),
        crate::adapters::contract::hex(digest)
    )))
}

/// Put one package in the store: its tarball fetched, checked against
/// `digests` before anything is unpacked, and unpacked as data, with no
/// executable bit and no link. Returns the directory and the bytes
/// downloaded, zero when the store held it.
pub fn ensure_package(
    fetcher: &dyn Fetcher,
    store: &Path,
    url: &str,
    digests: &[(HashAlgorithm, Vec<u8>)],
) -> Result<(PathBuf, u64), FetchError> {
    let destination = package_dir(store, digests)
        .ok_or_else(|| FetchError::Io(format!("{url} has no digest to check it against")))?;
    if destination.join("package.json").is_file() {
        return Ok((destination, 0));
    }
    let unique = super::python::store::unique_suffix();
    let archive = store.join("downloads").join(format!("{unique}.tgz"));
    let downloaded =
        super::fetch::download_verified_any(fetcher, url, &archive, digests, MAX_TARBALL_BYTES)?;
    let staging = store.join("packages").join(format!(".{unique}.tmp"));
    let outcome = (|| -> Result<(), String> {
        super::unpack::untar_gz(&archive, &staging, super::unpack::TarLayout::DATA)?;
        // A tarball holds one top-level directory, `package` by convention.
        let top = std::fs::read_dir(&staging)
            .map_err(|error| error.to_string())?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.join("package.json").is_file())
            .ok_or("the tarball holds no package.json")?;
        super::python::store::publish_dir(&top, &destination)
    })();
    let _ = std::fs::remove_file(&archive);
    let _ = std::fs::remove_dir_all(&staging);
    outcome.map_err(FetchError::Io)?;
    Ok((destination, downloaded.bytes))
}

/// The digest a registry publishes for one version, for a package whose
/// lock names none: `dist.integrity`, else the sha1 `dist.shasum`.
pub fn published_digests(
    fetcher: &dyn Fetcher,
    registry: &str,
    name: &str,
    version: &str,
) -> Result<Vec<(HashAlgorithm, Vec<u8>)>, String> {
    let url = format!(
        "{}/{}",
        registry.trim_end_matches('/'),
        name.replace('/', "%2f")
    );
    let (_, bytes) = fetcher
        .document(&url, "application/vnd.npm.install-v1+json")
        .map_err(|error| error.to_string())?;
    let document: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| format!("{url} is not JSON: {error}"))?;
    let dist = document
        .get("versions")
        .and_then(|versions| versions.get(version))
        .and_then(|entry| entry.get("dist"))
        .ok_or_else(|| format!("{url} lists no {version}"))?;
    let mut digests: Vec<(HashAlgorithm, Vec<u8>)> = dist
        .get("integrity")
        .and_then(|value| value.as_str())
        .map(lockfile::parse_sri)
        .unwrap_or_default()
        .into_iter()
        .map(|integrity| (algorithm(integrity.algorithm), integrity.digest))
        .collect();
    if digests.is_empty() {
        if let Some(shasum) = dist.get("shasum").and_then(|value| value.as_str()) {
            let bytes: Option<Vec<u8>> = (0..shasum.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(shasum.get(at..at + 2)?, 16).ok())
                .collect();
            if let Some(bytes) = bytes.filter(|bytes| bytes.len() == 20) {
                digests.push((HashAlgorithm::Sha1, bytes));
            }
        }
    }
    if digests.is_empty() {
        return Err(format!("{url} publishes no digest for {version}"));
    }
    Ok(digests)
}

/// Where a repository's JavaScript dependencies come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dependencies {
    /// The lock pins no package.
    None,
    /// The repository's own `node_modules`, installed at the locked versions.
    UserNodeModules,
    /// Kin's layout for this identity, complete or not.
    KinLayout { dir: PathBuf, ready: bool },
    /// None that the repository chose can be had.
    Missing(String),
}

/// What is known about a repository's environment without the network.
#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    pub lock: Option<JsLock>,
    /// The keys of the packages this host needs: every package the importers
    /// reach, less those whose `os` or `cpu` rules out this host.
    pub selected: Vec<String>,
    /// Packages left out for another platform.
    pub other_platform: usize,
    pub dependencies: Dependencies,
    pub identity: EnvironmentIdentity,
    /// Why the user's `node_modules` was passed over, when it was.
    pub passed_over: Option<String>,
    /// The importer whose `typescript` dependency pins the compiler, and
    /// that package's key.
    pub typescript: Option<(String, String)>,
}

/// The packages reachable from the lock's importers that suit this host.
fn select(lock: &JsLock, platform: (&str, &str)) -> (Vec<String>, usize) {
    let mut seen = BTreeSet::new();
    let mut other_platform = BTreeSet::new();
    let mut stack: Vec<&str> = lock
        .importers
        .values()
        .flat_map(|importer| importer.dependencies.values())
        .filter_map(|dep| match dep {
            Dep::Package(key) => Some(key.as_str()),
            _ => None,
        })
        .collect();
    while let Some(key) = stack.pop() {
        if seen.contains(key) || other_platform.contains(key) {
            continue;
        }
        let Some(package) = lock.packages.get(key) else {
            continue;
        };
        if !admits(&package.os, platform.0) || !admits(&package.cpu, platform.1) {
            other_platform.insert(key.to_string());
            continue;
        }
        seen.insert(key.to_string());
        stack.extend(package.dependencies.values().filter_map(|dep| match dep {
            Dep::Package(key) => Some(key.as_str()),
            _ => None,
        }));
    }
    (seen.into_iter().collect(), other_platform.len())
}

/// Why the repository's own `node_modules` does not match the lock, or `Ok`
/// when every importer's direct dependencies are installed at the locked
/// versions.
pub fn check_node_modules(
    root: &Path,
    lock: &JsLock,
    selected: &BTreeSet<&str>,
) -> Result<(), String> {
    let base = lock.file.parent().unwrap_or(root);
    let mut missing = Vec::new();
    let mut other = Vec::new();
    let mut total = 0;
    for (dir, importer) in &lock.importers {
        for (alias, dep) in &importer.dependencies {
            let Dep::Package(key) = dep else {
                continue;
            };
            if !selected.contains(key.as_str()) {
                continue;
            }
            let Some(package) = lock.packages.get(key) else {
                continue;
            };
            total += 1;
            let at = base.join(dir).join("node_modules").join(alias);
            let installed = std::fs::read_to_string(at.join("package.json"))
                .ok()
                .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
                .and_then(|json| json.get("version")?.as_str().map(str::to_string));
            let place = if dir.is_empty() {
                alias.clone()
            } else {
                format!("{dir}: {alias}")
            };
            match installed {
                None => missing.push(place),
                // npm reads a manifest's version loosely (`v1.2.3` is 1.2.3).
                Some(version)
                    if version.trim().trim_start_matches(['v', '=']) != package.version =>
                {
                    other.push(format!("{place} {version}, locked {}", package.version))
                }
                Some(_) => {}
            }
        }
    }
    if missing.is_empty() && other.is_empty() {
        return Ok(());
    }
    let first = |list: &[String]| list.iter().take(3).cloned().collect::<Vec<_>>().join("; ");
    Err(format!(
        "{} of {total} direct dependencies are not installed{} and {} are at other versions \
         than the lock pins{}",
        missing.len(),
        if missing.is_empty() {
            String::new()
        } else {
            format!(" ({})", first(&missing))
        },
        other.len(),
        if other.is_empty() {
            String::new()
        } else {
            format!(" ({})", first(&other))
        }
    ))
}

/// The identity of an environment: the lock's packages this host needs.
pub fn identity(lock: &JsLock, selected: &[String], platform: (&str, &str)) -> EnvironmentIdentity {
    let mut parts = vec![
        "javascript".to_string(),
        format!("{}-{}", platform.0, platform.1),
        lock.format.describe(),
    ];
    for key in selected {
        if let Some(package) = lock.packages.get(key) {
            let digest = match &package.source {
                Source::Registry { integrity, .. } | Source::RemoteTarball { integrity, .. } => {
                    integrity
                        .iter()
                        .map(|i| {
                            format!(
                                "{}-{}",
                                i.algorithm.name(),
                                crate::adapters::contract::hex(&i.digest)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                }
                other => format!("{other:?}"),
            };
            let deps: Vec<String> = package
                .dependencies
                .iter()
                .map(|(alias, dep)| format!("{alias}={dep:?}"))
                .collect();
            parts.push(format!(
                "{key} {} {digest} [{}]",
                package.version,
                deps.join(",")
            ));
        }
    }
    for (dir, importer) in &lock.importers {
        let deps: Vec<String> = importer
            .dependencies
            .iter()
            .map(|(alias, dep)| format!("{alias}={dep:?}"))
            .collect();
        parts.push(format!("importer {dir} [{}]", deps.join(",")));
    }
    let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
    EnvironmentIdentity::of(&parts)
}

/// Kin's layout for an identity.
pub fn layout_dir(store: &Path, identity: &EnvironmentIdentity) -> PathBuf {
    store.join("layouts").join(&identity.hex()[..32])
}

/// What the environment step reads from the host.
#[derive(Debug, Clone)]
pub struct Host<'a> {
    pub vars: &'a HashMap<String, String>,
    pub home: Option<&'a Path>,
    pub cache: &'a Path,
    pub analysis_environments: bool,
    pub platform: (&'a str, &'a str),
}

impl Host<'_> {
    pub fn store(&self) -> PathBuf {
        store_dir(self.cache)
    }
}

/// Assess the environment of the repository at `root`, whose workspace
/// packages are `workspaces` (name, directory).
pub fn assess(root: &Path, workspaces: &[(String, PathBuf)], host: &Host<'_>) -> Assessment {
    let lock = match lockfile::find_lock(root, workspaces) {
        LockSearch::Found(lock) => lock,
        LockSearch::NotFound => {
            let manifest = std::fs::read_to_string(root.join("package.json")).unwrap_or_default();
            let declares = serde_json::from_str::<serde_json::Value>(&manifest)
                .ok()
                .is_some_and(|json| {
                    ["dependencies", "devDependencies", "optionalDependencies"]
                        .iter()
                        .any(|key| {
                            json.get(key)
                                .and_then(|v| v.as_object())
                                .is_some_and(|m| !m.is_empty())
                        })
                });
            // A repository that locks nothing but has installed its own
            // node_modules has an environment of its own choosing.
            let dependencies = if declares && root.join("node_modules").is_dir() {
                Dependencies::UserNodeModules
            } else if declares {
                Dependencies::Missing(
                    "package.json declares dependencies and no lockfile pins them, so nothing can \
                     be verified"
                        .to_string(),
                )
            } else {
                Dependencies::None
            };
            return Assessment {
                lock: None,
                selected: Vec::new(),
                other_platform: 0,
                dependencies,
                identity: EnvironmentIdentity::of(&["javascript", "no lock"]),
                passed_over: None,
                typescript: None,
            };
        }
        LockSearch::Unusable { reasons } => {
            return Assessment {
                lock: None,
                selected: Vec::new(),
                other_platform: 0,
                dependencies: Dependencies::Missing(format!(
                    "no usable lockfile: {}",
                    reasons.join("; ")
                )),
                identity: EnvironmentIdentity::of(&["javascript", "unusable lock"]),
                passed_over: None,
                typescript: None,
            };
        }
    };
    let (selected, other_platform) = select(&lock, host.platform);
    let identity = identity(&lock, &selected, host.platform);
    let typescript = std::iter::once("")
        .chain(lock.importers.keys().map(String::as_str))
        .find_map(
            |dir| match lock.importers.get(dir)?.dependencies.get("typescript")? {
                Dep::Package(key) => Some((dir.to_string(), key.clone())),
                _ => None,
            },
        );
    let mut passed_over = None;
    let dependencies = if selected.is_empty() {
        Dependencies::None
    } else {
        let wanted: BTreeSet<&str> = selected.iter().map(String::as_str).collect();
        match check_node_modules(root, &lock, &wanted) {
            Ok(()) => Dependencies::UserNodeModules,
            Err(reason) => {
                passed_over = Some(reason);
                if host.analysis_environments {
                    let dir = layout_dir(&host.store(), &identity);
                    Dependencies::KinLayout {
                        ready: dir.join(".complete").is_file()
                            && !super::failed_long_ago(&host.store(), &identity),
                        dir,
                    }
                } else {
                    Dependencies::Missing(format!(
                        "analysis environments are off ({}), and the repository's node_modules \
                         does not match the lock: {}",
                        super::SWITCH_ENV,
                        passed_over.as_deref().unwrap_or_default()
                    ))
                }
            }
        }
    };
    Assessment {
        lock: Some(lock),
        selected,
        other_platform,
        dependencies,
        identity,
        passed_over,
        typescript,
    }
}

/// How one package was obtained.
enum Fetched {
    Stored {
        dir: PathBuf,
        bytes: u64,
        registry_digest: bool,
    },
    /// Left out by design: another source kind, or no digest to verify.
    Skipped(String),
    /// Left out because the fetch failed, and worth trying again later.
    Failed(String),
    Refused(String),
}

/// Fetch every selected package not yet in the store, then lay them out.
pub fn provision(
    root: &Path,
    workspaces: &[(String, PathBuf)],
    host: &Host<'_>,
    fetcher: &dyn Fetcher,
) -> ProvisionReport {
    let started = Instant::now();
    let mut report = ProvisionReport::default();
    let assessment = assess(root, workspaces, host);
    let (Some(lock), Dependencies::KinLayout { dir, ready: false }) =
        (&assessment.lock, &assessment.dependencies)
    else {
        report.elapsed_ms = started.elapsed().as_millis();
        return report;
    };
    report.skipped.extend(lock.warnings.iter().cloned());
    let store = host.store();
    let registries = Registries::read(root, host.vars, host.home);
    let outcomes = super::parallel_map(&assessment.selected, super::PARALLEL_FETCHES, |key| {
        let Some(package) = lock.packages.get(key) else {
            return Fetched::Skipped(format!("{key}: not in the lock"));
        };
        let pin = format!("{}@{}", package.name, package.version);
        let (url, digests) = match &package.source {
            Source::Registry {
                tarball, integrity, ..
            } => (
                registries.tarball_url(package, tarball.as_deref()),
                integrity
                    .iter()
                    .map(|i| (algorithm(i.algorithm), i.digest.clone()))
                    .collect::<Vec<_>>(),
            ),
            Source::RemoteTarball { url, integrity } => (
                url.clone(),
                integrity
                    .iter()
                    .map(|i| (algorithm(i.algorithm), i.digest.clone()))
                    .collect(),
            ),
            Source::Git { repository, .. } => {
                return Fetched::Skipped(format!(
                    "{pin}: a git dependency ({repository}), not fetched"
                ))
            }
            Source::Local { path } => {
                return Fetched::Skipped(format!("{pin}: a local directory ({path}), not read"))
            }
            Source::Unsupported { reason } => return Fetched::Skipped(format!("{pin}: {reason}")),
        };
        let (digests, registry_digest) = if digests.is_empty() {
            if !matches!(package.source, Source::Registry { .. }) {
                return Fetched::Skipped(format!("{pin}: the lock names no digest to verify it"));
            }
            match published_digests(
                fetcher,
                registries.registry_for(&package.name),
                &package.name,
                &package.version,
            ) {
                Ok(digests) => (digests, true),
                Err(reason) => {
                    return Fetched::Failed(format!(
                        "{pin}: the lock names no npm digest, and the registry's could not be \
                         read: {reason}"
                    ))
                }
            }
        } else {
            (digests, false)
        };
        match ensure_package(fetcher, &store, &url, &digests) {
            Ok((dir, bytes)) => Fetched::Stored {
                dir,
                bytes,
                registry_digest,
            },
            Err(error @ FetchError::Mismatch { .. }) => Fetched::Refused(format!("{pin}: {error}")),
            Err(error) => Fetched::Failed(format!("{pin}: {error}")),
        }
    });
    let mut stored = BTreeMap::new();
    let mut registry_digests = 0;
    let mut failures = 0;
    for (key, outcome) in assessment.selected.iter().zip(outcomes) {
        if matches!(&outcome, Fetched::Refused(_) | Fetched::Failed(_)) {
            failures += 1;
        }
        match outcome {
            Fetched::Stored {
                dir,
                bytes,
                registry_digest,
            } => {
                if bytes > 0 {
                    report.fetched += 1;
                    report.fetched_bytes += bytes;
                } else {
                    report.reused += 1;
                }
                registry_digests += usize::from(registry_digest);
                stored.insert(key.clone(), dir);
            }
            Fetched::Skipped(reason) | Fetched::Failed(reason) => report.skipped.push(reason),
            Fetched::Refused(reason) => report.refused.push(reason),
        }
    }
    super::record_attempt(&store, &assessment.identity, failures);
    if registry_digests > 0 {
        report.skipped.push(format!(
            "{registry_digests} package(s) verified against the digest their registry publishes, \
             since {} records no npm digest for them",
            lock.format.describe()
        ));
    }
    if assessment.other_platform > 0 {
        report.skipped.push(format!(
            "{} package(s) for another platform left out",
            assessment.other_platform
        ));
    }
    match layout::build(dir, root, lock, &stored) {
        Ok(()) => report.environment = Some(dir.clone()),
        Err(reason) => report.failure = Some(reason),
    }
    report.elapsed_ms = started.elapsed().as_millis();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::repo_scan::Fixture;
    use crate::analysis_env::fetch::testing::FixedFetcher;
    use sha2::Digest;

    /// A gzip-compressed npm tarball holding `files` under `package/`.
    fn tarball(files: &[(&str, &str)]) -> Vec<u8> {
        let dir = Fixture::new("npm-tarball");
        let path = dir.root.join("x.tgz");
        let named: Vec<(String, &[u8])> = files
            .iter()
            .map(|(name, text)| (format!("package/{name}"), text.as_bytes()))
            .collect();
        let borrowed: Vec<(&str, &[u8])> = named
            .iter()
            .map(|(name, bytes)| (name.as_str(), *bytes))
            .collect();
        crate::analysis_env::unpack::testing::write_tar_gz(&path, &borrowed);
        std::fs::read(&path).unwrap()
    }

    fn sri(bytes: &[u8]) -> String {
        format!(
            "sha512-{}",
            crate::analysis_env::base64_encode(&sha2::Sha512::digest(bytes))
        )
    }

    fn host<'a>(vars: &'a HashMap<String, String>, cache: &'a Path) -> Host<'a> {
        Host {
            vars,
            home: None,
            cache,
            analysis_environments: true,
            platform: ("darwin", "arm64"),
        }
    }

    #[test]
    fn restrictions_follow_npms_negation_rules() {
        assert!(admits(&[], "darwin"));
        assert!(admits(&["darwin".to_string()], "darwin"));
        assert!(!admits(&["linux".to_string()], "darwin"));
        assert!(!admits(&["!darwin".to_string()], "darwin"));
        assert!(admits(&["!win32".to_string()], "darwin"));
    }

    #[test]
    fn registries_come_from_npmrc_yarnrc_and_the_environment() {
        let repo = Fixture::new("npmrc");
        repo.write(
            ".npmrc",
            "registry=https://mirror.example/npm/\n@corp:registry=https://corp.example/\n\
             //corp.example/:_authToken=${CORP_TOKEN}\n",
        );
        let mut vars = HashMap::new();
        vars.insert("CORP_TOKEN".to_string(), "secret".to_string());
        let registries = Registries::read(&repo.root, &vars, None);
        assert_eq!(
            registries.registry_for("left-pad"),
            "https://mirror.example/npm"
        );
        assert_eq!(registries.registry_for("@corp/lib"), "https://corp.example");
        assert_eq!(
            registries.authorizations(),
            vec![(
                "https://corp.example/".to_string(),
                "Bearer secret".to_string()
            )]
        );
        let package = LockedPackage {
            name: "left-pad".to_string(),
            version: "1.3.0".to_string(),
            source: Source::Unsupported {
                reason: String::new(),
            },
            dependencies: BTreeMap::new(),
            optional: false,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
        };
        assert_eq!(
            registries.tarball_url(
                &package,
                Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
            ),
            "https://mirror.example/npm/left-pad/-/left-pad-1.3.0.tgz",
            "the public registry's URL moves to the configured mirror"
        );
        repo.write(
            ".yarnrc.yml",
            "npmRegistryServer: \"https://yarn-mirror.example\"\nnpmScopes:\n  corp:\n    npmRegistryServer: \"https://corp-yarn.example\"\n",
        );
        let registries = Registries::read(&repo.root, &vars, None);
        assert_eq!(
            registries.registry_for("left-pad"),
            "https://yarn-mirror.example"
        );
        assert_eq!(
            registries.registry_for("@corp/lib"),
            "https://corp-yarn.example"
        );
    }

    /// A repository whose lock pins a package with install scripts: the
    /// package is fetched, verified and laid out, and none of its scripts
    /// runs; no process starts at all.
    #[cfg(unix)]
    #[test]
    fn a_packages_postinstall_never_runs() {
        let repo = Fixture::new("npm-postinstall");
        let cache = Fixture::new("npm-postinstall-cache");
        let marker = repo.root.join("POSTINSTALL_RAN");
        let script = format!(
            "require('fs').writeFileSync({:?}, 'ran')",
            marker.display().to_string()
        );
        let manifest = serde_json::json!({
            "name": "evil",
            "version": "1.0.0",
            "types": "index.d.ts",
            "bin": { "evil": "cli.js" },
            "scripts": {
                "preinstall": format!("node -e \"{script}\""),
                "install": format!("node -e \"{script}\""),
                "postinstall": format!("node -e \"{script}\""),
                "prepare": format!("node -e \"{script}\""),
            },
        });
        let bytes = tarball(&[
            ("package.json", &manifest.to_string()),
            ("index.d.ts", "export declare function f(): void;\n"),
            (
                "cli.js",
                "#!/usr/bin/env node\nrequire('fs').writeFileSync('x', 'y')\n",
            ),
        ]);
        repo.write(
            "package.json",
            "{\"name\": \"app\", \"dependencies\": {\"evil\": \"1.0.0\"}}",
        );
        repo.write(
            "package-lock.json",
            &serde_json::json!({
                "name": "app",
                "lockfileVersion": 3,
                "packages": {
                    "": { "name": "app", "dependencies": { "evil": "1.0.0" } },
                    "node_modules/evil": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",
                        "integrity": sri(&bytes),
                        "hasInstallScript": true,
                        "bin": { "evil": "cli.js" },
                    },
                },
            })
            .to_string(),
        );
        let vars = HashMap::new();
        let host = host(&vars, &cache.root);
        let mut fetcher = FixedFetcher::default();
        fetcher.files.insert(
            "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz".to_string(),
            bytes,
        );
        let report = provision(&repo.root, &[], &host, &fetcher);
        assert_eq!(report.fetched, 1, "{report:?}");
        assert!(
            report.processes.is_empty(),
            "nothing is started: {report:?}"
        );
        assert!(
            report.refused.is_empty() && report.failure.is_none(),
            "{report:?}"
        );
        assert!(!marker.exists(), "no install script ran");
        let layout = report.environment.unwrap();
        let installed = layout.join("node_modules/evil");
        assert!(installed.join("index.d.ts").is_file());
        assert!(
            !layout.join("node_modules/.bin").exists(),
            "no binary is linked"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(installed.join("cli.js"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0, "nothing unpacked is executable");
        }
        // Nothing was written into the repository.
        let mut in_repo = Vec::new();
        crate::adapters::repo_scan::walk_files(&repo.root, &|_, _| true, &mut |path, _| {
            in_repo.push(path.to_path_buf())
        });
        assert_eq!(in_repo.len(), 2, "{in_repo:?}");
        assert!(matches!(
            assess(&repo.root, &[], &host).dependencies,
            Dependencies::KinLayout { ready: true, .. }
        ));
    }

    /// Without a lock, the repository's own node_modules serves; without
    /// either, the environment is missing and says why.
    #[test]
    fn an_unlocked_repository_uses_its_own_node_modules_or_none() {
        let repo = Fixture::new("npm-unlocked");
        let cache = Fixture::new("npm-unlocked-cache");
        repo.write(
            "package.json",
            "{\"name\": \"app\", \"dependencies\": {\"a\": \"^1\"}}",
        );
        let vars = HashMap::new();
        let host = host(&vars, &cache.root);
        assert!(matches!(
            assess(&repo.root, &[], &host).dependencies,
            Dependencies::Missing(reason) if reason.contains("no lockfile")
        ));
        repo.write(
            "node_modules/a/package.json",
            "{\"name\": \"a\", \"version\": \"1.0.0\"}",
        );
        assert_eq!(
            assess(&repo.root, &[], &host).dependencies,
            Dependencies::UserNodeModules
        );
    }

    /// A tarball whose bytes do not match the lock's integrity is refused and
    /// nothing of it lands in the store.
    #[test]
    fn a_tarball_that_does_not_match_the_lock_is_refused() {
        let repo = Fixture::new("npm-mismatch");
        let cache = Fixture::new("npm-mismatch-cache");
        let bytes = tarball(&[("package.json", "{\"name\": \"a\", \"version\": \"1.0.0\"}")]);
        repo.write(
            "package.json",
            "{\"name\": \"app\", \"dependencies\": {\"a\": \"1.0.0\"}}",
        );
        repo.write(
            "package-lock.json",
            &serde_json::json!({
                "lockfileVersion": 3,
                "packages": {
                    "": { "dependencies": { "a": "1.0.0" } },
                    "node_modules/a": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                        "integrity": sri(b"something else"),
                    },
                },
            })
            .to_string(),
        );
        let vars = HashMap::new();
        let host = host(&vars, &cache.root);
        let mut fetcher = FixedFetcher::default();
        fetcher.files.insert(
            "https://registry.npmjs.org/a/-/a-1.0.0.tgz".to_string(),
            bytes,
        );
        let report = provision(&repo.root, &[], &host, &fetcher);
        assert_eq!(report.refused.len(), 1, "{report:?}");
        assert!(
            report.refused[0].contains("nothing was unpacked"),
            "{report:?}"
        );
        let packages = store_dir(&cache.root).join("packages");
        let stored: Vec<_> = std::fs::read_dir(&packages)
            .map(|entries| entries.filter_map(Result::ok).collect())
            .unwrap_or_default();
        assert!(stored.is_empty(), "{stored:?}");
    }

    /// pnpm's layout: the importer sees its direct dependencies, a package
    /// sees its own resolved dependency beside it, a workspace link points at
    /// the workspace package's source even when the lock names its build
    /// output, and a package for another platform is left out.
    #[cfg(unix)]
    #[test]
    fn the_layout_gives_each_importer_and_package_its_own_dependencies() {
        let repo = Fixture::new("pnpm-layout");
        let cache = Fixture::new("pnpm-layout-cache");
        let lib = tarball(&[(
            "package.json",
            "{\"name\": \"lib\", \"version\": \"2.0.0\"}",
        )]);
        let old = tarball(&[(
            "package.json",
            "{\"name\": \"lib\", \"version\": \"1.0.0\"}",
        )]);
        let user = tarball(&[(
            "package.json",
            "{\"name\": \"user\", \"version\": \"1.0.0\"}",
        )]);
        repo.write("pnpm-workspace.yaml", "packages:\n  - app\n  - core\n");
        repo.write("package.json", "{\"name\": \"root\"}");
        repo.write("core/package.json", "{\"name\": \"core\"}");
        repo.write("app/package.json", "{\"name\": \"app\"}");
        repo.write(
            "pnpm-lock.yaml",
            &format!(
                "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lib:\n        specifier: ^2\n        version: 2.0.0\n\n\
                 \x20 app:\n    dependencies:\n      core:\n        specifier: workspace:./core/dist\n        version: link:../core/dist\n      user:\n        specifier: ^1\n        version: 1.0.0\n      native:\n        specifier: ^1\n        version: 1.0.0\n\n\
                 \x20 core: {{}}\n\npackages:\n\n  lib@1.0.0:\n    resolution: {{integrity: {}}}\n\n  lib@2.0.0:\n    resolution: {{integrity: {}}}\n\n\
                 \x20 user@1.0.0:\n    resolution: {{integrity: {}}}\n\n  native@1.0.0:\n    resolution: {{integrity: {}}}\n    cpu: [x64]\n    os: [linux]\n\n\
                 snapshots:\n\n  lib@1.0.0: {{}}\n\n  lib@2.0.0: {{}}\n\n  user@1.0.0:\n    dependencies:\n      lib: 1.0.0\n\n  native@1.0.0: {{}}\n",
                sri(&old),
                sri(&lib),
                sri(&user),
                sri(b"never fetched"),
            ),
        );
        let vars = HashMap::new();
        let host = host(&vars, &cache.root);
        let workspaces = vec![
            ("core".to_string(), repo.root.join("core")),
            ("app".to_string(), repo.root.join("app")),
        ];
        let mut fetcher = FixedFetcher::default();
        for (name, version, bytes) in [
            ("lib", "2.0.0", &lib),
            ("lib", "1.0.0", &old),
            ("user", "1.0.0", &user),
        ] {
            fetcher.files.insert(
                format!("https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"),
                bytes.clone(),
            );
        }
        let report = provision(&repo.root, &workspaces, &host, &fetcher);
        assert_eq!(report.fetched, 3, "{report:?}");
        assert!(
            report
                .skipped
                .iter()
                .any(|reason| reason.contains("another platform")),
            "{report:?}"
        );
        let layout = report.environment.unwrap();
        let version = |path: &Path| -> String {
            let json: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(path.join("package.json")).unwrap())
                    .unwrap();
            json["version"].as_str().unwrap().to_string()
        };
        assert_eq!(version(&layout.join("node_modules/lib")), "2.0.0");
        let user_dir = std::fs::canonicalize(layout.join("app/node_modules/user")).unwrap();
        assert_eq!(
            version(&user_dir.parent().unwrap().join("lib")),
            "1.0.0",
            "user sees the lib the lock resolved for it"
        );
        assert_eq!(
            std::fs::canonicalize(layout.join("app/node_modules/core")).unwrap(),
            std::fs::canonicalize(repo.root.join("core")).unwrap(),
            "a workspace link reads the package's source, not its unbuilt output"
        );
        assert!(!layout.join("app/node_modules/native").exists());
    }
}
