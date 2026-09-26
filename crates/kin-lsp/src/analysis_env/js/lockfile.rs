// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! JavaScript lockfiles, read into one dependency graph.
//!
//! A JavaScript repository pins its dependencies in the lockfile of its package manager: npm's
//! `package-lock.json` (or `npm-shrinkwrap.json`), pnpm's `pnpm-lock.yaml`, or a `yarn.lock` from
//! Yarn Classic or Yarn Berry. Each reader here turns one of them into the same [`JsLock`]: the
//! importers (the root project and each workspace package), the packages the lock pins, where
//! each package comes from and which digests it must match, and the dependency edges between
//! them, each already resolved to the exact package or directory it reaches.
//!
//! The readers only read text. They never run a package manager, a lifecycle script or any other
//! process, and never touch the network. Laying the packages out and fetching them is left to the
//! caller.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

use serde_json::{Map as JsonMap, Value as JsonValue};

use super::yaml::{self, Yaml};

/// Which lockfile format a lock came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockFormat {
    /// `package-lock.json` version 1 (npm 5 and 6): a nested `dependencies` tree.
    NpmV1,
    /// `package-lock.json` version 2 (npm 7 and 8): a flat `packages` map, kept beside the
    /// version 1 tree.
    NpmV2,
    /// `package-lock.json` version 3 (npm 9 onward): the flat `packages` map alone.
    NpmV3,
    /// `pnpm-lock.yaml`, with its `lockfileVersion` as written ("5.4", "6.0", "9.0").
    Pnpm { version: String },
    /// A `yarn.lock` written by Yarn 1.
    YarnClassic,
    /// A `yarn.lock` written by Yarn 2 or later, with its `__metadata.version` as written.
    YarnBerry { version: String },
}

impl LockFormat {
    /// The format's file name and version, for messages ("pnpm-lock.yaml v9.0").
    pub fn describe(&self) -> String {
        match self {
            LockFormat::NpmV1 => "package-lock.json v1".into(),
            LockFormat::NpmV2 => "package-lock.json v2".into(),
            LockFormat::NpmV3 => "package-lock.json v3".into(),
            LockFormat::Pnpm { version } => format!("pnpm-lock.yaml v{version}"),
            LockFormat::YarnClassic => "yarn.lock v1 (Yarn Classic)".into(),
            LockFormat::YarnBerry { version } => format!("yarn.lock v{version} (Yarn Berry)"),
        }
    }
}

/// The outcome of looking for a lock at a repository root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockSearch {
    /// No lockfile of a JavaScript package manager.
    NotFound,
    /// A lock that was read.
    Found(JsLock),
    /// Lockfiles exist but none could be read; one reason per file, naming the file.
    Unusable { reasons: Vec<String> },
}

/// A lockfile read into one dependency graph, whatever its format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsLock {
    /// The format the lock was read from.
    pub format: LockFormat,
    /// The absolute path of the lockfile that was read.
    pub file: PathBuf,
    /// The projects that install dependencies, keyed by their directory relative to the lock's
    /// directory, "/"-separated, with "" for the lock's own directory. The root is always
    /// present. npm and Yarn Berry also count a linked local directory (npm `file:`, Yarn
    /// `portal:`) as an importer, since the lock resolves its dependencies the same way.
    pub importers: BTreeMap<String, Importer>,
    /// The locked packages, keyed by a key unique within the lock. npm keys a package by its
    /// install path ("node_modules/a/node_modules/b"); pnpm by its package or snapshot key without
    /// a leading `/` ("name@1.2.3(peer@1.0.0)"); Yarn Classic by "name@version"; Yarn Berry by
    /// the entry's `resolution` ("lodash@npm:4.17.21").
    pub packages: BTreeMap<String, LockedPackage>,
    /// What the reader left out or changed while reading, each with its reason: entries it could
    /// not read, patches it does not apply, manifests it could not open, and other lockfiles it
    /// did not read.
    pub warnings: Vec<String>,
}

/// One project of the repository and what it depends on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Importer {
    /// Each declared dependency, by the name the project imports it under (an alias for an npm
    /// alias), resolved: `dependencies`, `devDependencies` and `optionalDependencies`, plus peer
    /// dependencies where the lock resolves them.
    pub dependencies: BTreeMap<String, Dep>,
}

/// Where one dependency edge leads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dep {
    /// A locked package, by its key in [`JsLock::packages`].
    Package(String),
    /// A directory linked in place: a workspace package or another local directory, relative to
    /// the lock's directory.
    Link(String),
    /// An edge the lock declares but does not resolve, with the reason.
    Missing(String),
}

/// One package pinned by a lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedPackage {
    /// The package's real name, never the alias it is installed under.
    pub name: String,
    /// The version the lock pins, as written.
    pub version: String,
    /// Where the package comes from.
    pub source: Source,
    /// The package's resolved edges: `dependencies`, `optionalDependencies`, and the peer
    /// dependencies the lock resolved. An optional or peer dependency the lock does not resolve
    /// is left out.
    pub dependencies: BTreeMap<String, Dep>,
    /// Whether the package is needed only through optional dependencies. npm and pnpm record
    /// this per package; for Yarn it is computed from which edges the lock marks optional.
    pub optional: bool,
    /// The operating systems the lock restricts the package to, as recorded, with negations such
    /// as "!win32" kept verbatim.
    pub os: Vec<String>,
    /// The CPU architectures the lock restricts the package to, as recorded.
    pub cpu: Vec<String>,
    /// The C libraries the lock restricts the package to, as recorded.
    pub libc: Vec<String>,
}

/// Where a locked package comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A package registry. `tarball` is the URL exactly as the lock names it, or `None` when the
    /// lock names none (pnpm usually, Yarn Berry always), in which case the caller derives it
    /// with [`registry_tarball_url`]. `archive_checksum` is Yarn Berry's `checksum`, which hashes
    /// Yarn's own cache archive rather than the npm tarball, so it cannot verify a download.
    Registry {
        tarball: Option<String>,
        integrity: Vec<Integrity>,
        archive_checksum: Option<String>,
    },
    /// A tarball at a URL that is not a registry's.
    RemoteTarball {
        url: String,
        integrity: Vec<Integrity>,
    },
    /// A git repository, by its URL as the lock writes it (without the `#` fragment), and the
    /// commit the lock pins when it names one.
    Git {
        repository: String,
        commit: Option<String>,
    },
    /// A local directory that is not a workspace package, relative to the lock's directory.
    Local { path: String },
    /// A source this reader does not support, with the reason.
    Unsupported { reason: String },
}

/// One digest from a Subresource Integrity string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integrity {
    pub algorithm: Algorithm,
    /// The raw digest bytes, of the length the algorithm produces.
    pub digest: Vec<u8>,
}

/// A digest algorithm a lockfile names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Sha512,
    Sha384,
    Sha256,
    Sha1,
}

impl Algorithm {
    /// The algorithm's name as SRI writes it ("sha512").
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Sha512 => "sha512",
            Algorithm::Sha384 => "sha384",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha1 => "sha1",
        }
    }

    /// The length of the algorithm's digest in bytes.
    pub fn digest_len(self) -> usize {
        match self {
            Algorithm::Sha512 => 64,
            Algorithm::Sha384 => 48,
            Algorithm::Sha256 => 32,
            Algorithm::Sha1 => 20,
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "sha512" => Some(Algorithm::Sha512),
            "sha384" => Some(Algorithm::Sha384),
            "sha256" => Some(Algorithm::Sha256),
            "sha1" => Some(Algorithm::Sha1),
            _ => None,
        }
    }
}

/// Parses a space-separated SRI list ("sha512-... sha1-..."). Options after `?` are dropped, and
/// so is any entry whose algorithm is unknown or whose digest is not valid base64 of the
/// algorithm's length.
pub fn parse_sri(text: &str) -> Vec<Integrity> {
    text.split_whitespace()
        .filter_map(|token| {
            let token = token.split('?').next().unwrap_or(token);
            let (name, encoded) = token.split_once('-')?;
            let algorithm = Algorithm::from_name(name)?;
            let digest = base64_decode(encoded)?;
            (digest.len() == algorithm.digest_len()).then_some(Integrity { algorithm, digest })
        })
        .collect()
}

/// The registry's tarball URL for `name` at `version`:
/// "<registry>/<name>/-/<unscoped name>-<version>.tgz". A scoped name keeps "@scope/name" in the
/// path, so "@babel/core" 7.0.0 is "<registry>/@babel/core/-/core-7.0.0.tgz".
pub fn registry_tarball_url(registry: &str, name: &str, version: &str) -> String {
    let registry = registry.trim_end_matches('/');
    let unscoped = name.rsplit('/').next().unwrap_or(name);
    format!("{registry}/{name}/-/{unscoped}-{version}.tgz")
}

/// Lockfiles by name, each with the package manager that writes it, in the order they are tried
/// when the root `package.json` names no package manager. npm reads `npm-shrinkwrap.json` in
/// preference to `package-lock.json`, so it comes first.
const LOCKFILES: [(&str, &str); 6] = [
    ("pnpm-lock.yaml", "pnpm"),
    ("yarn.lock", "yarn"),
    ("npm-shrinkwrap.json", "npm"),
    ("package-lock.json", "npm"),
    ("bun.lock", "bun"),
    ("bun.lockb", "bun"),
];

/// Looks for a lock at `root` and reads the first that parses. When the root `package.json`
/// names its package manager (`"packageManager": "pnpm@9.1.0"`), that manager's lockfiles are
/// tried first; otherwise the order is `pnpm-lock.yaml`, `yarn.lock`, `npm-shrinkwrap.json`,
/// `package-lock.json`. Bun's lockfiles are never read and count as unusable. The lock that is
/// read carries a warning for every other lockfile present, naming why it was not used.
///
/// `workspaces` is every workspace package the repository declares, as (package name, absolute
/// directory). Yarn Classic locks do not list importers, so their importers come from these
/// directories' `package.json` files, and a dependency on one of these names links to its
/// directory. The other formats list their importers themselves.
pub fn find_lock(root: &Path, workspaces: &[(String, PathBuf)]) -> LockSearch {
    let read = |path: &Path| std::fs::read_to_string(path).ok();
    let mut present: Vec<(&str, &str)> = LOCKFILES
        .iter()
        .copied()
        .filter(|(name, _)| root.join(name).is_file())
        .collect();
    if present.is_empty() {
        return LockSearch::NotFound;
    }
    if let Some(manager) = declared_manager(root, &read) {
        present.sort_by_key(|(_, owner)| *owner != manager.as_str());
    }
    let mut reasons = Vec::new();
    for (index, (name, _)) in present.iter().enumerate() {
        match read_lock_with(&root.join(name), workspaces, &read) {
            Ok(mut lock) => {
                let mut warnings = std::mem::take(&mut reasons);
                for (other, _) in &present[index + 1..] {
                    warnings.push(format!(
                        "{other}: is also present and was not read, since {name} comes first"
                    ));
                }
                warnings.append(&mut lock.warnings);
                lock.warnings = warnings;
                return LockSearch::Found(lock);
            }
            Err(reason) => reasons.push(reason),
        }
    }
    LockSearch::Unusable { reasons }
}

/// Reads one lockfile, choosing the reader by its file name and, for `yarn.lock`, by its
/// content. Errors name the file. `workspaces` is as for [`find_lock`].
pub fn read_lock(file: &Path, workspaces: &[(String, PathBuf)]) -> Result<JsLock, String> {
    read_lock_with(file, workspaces, &|path: &Path| {
        std::fs::read_to_string(path).ok()
    })
}

/// The package manager the root `package.json` names in its `packageManager` field.
fn declared_manager(root: &Path, read: &dyn Fn(&Path) -> Option<String>) -> Option<String> {
    let text = read(&root.join("package.json"))?;
    let manifest: JsonValue = serde_json::from_str(&text).ok()?;
    let field = manifest.get("packageManager")?.as_str()?;
    let name = field.split('@').next()?.trim();
    (!name.is_empty()).then(|| name.to_owned())
}

/// What a reader needs besides the lock's text: where the lock is, the declared workspaces, and
/// a way to read a manifest beside it.
struct Context<'a> {
    lock_dir: &'a Path,
    workspaces: &'a [(String, PathBuf)],
    read: &'a dyn Fn(&Path) -> Option<String>,
}

/// The parts of a [`JsLock`] a reader builds.
#[derive(Default)]
struct Graph {
    importers: BTreeMap<String, Importer>,
    packages: BTreeMap<String, LockedPackage>,
    warnings: Vec<String>,
}

fn read_lock_with(
    file: &Path,
    workspaces: &[(String, PathBuf)],
    read: &dyn Fn(&Path) -> Option<String>,
) -> Result<JsLock, String> {
    let name = file
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let fail = |why: String| format!("{name}: {why}");
    if matches!(name, "bun.lock" | "bun.lockb") {
        return Err(fail("is Bun's lockfile, which is not supported".into()));
    }
    let text = read(file).ok_or_else(|| fail("cannot be read".into()))?;
    let context = Context {
        lock_dir: file.parent().unwrap_or_else(|| Path::new("")),
        workspaces,
        read,
    };
    let (format, mut graph) = match name {
        "pnpm-lock.yaml" => read_pnpm(&text),
        "yarn.lock" if is_berry(&text) => read_berry(&text, &context),
        "yarn.lock" => read_classic(&text, &context).map(|graph| (LockFormat::YarnClassic, graph)),
        "package-lock.json" | "npm-shrinkwrap.json" => read_npm(&text, &context),
        _ => Err("is not a lockfile this reader knows".into()),
    }
    .map_err(fail)?;
    graph.importers.entry(String::new()).or_default();
    Ok(JsLock {
        format,
        file: file.to_path_buf(),
        importers: graph.importers,
        packages: graph.packages,
        warnings: graph.warnings,
    })
}

// package-lock.json and npm-shrinkwrap.json

/// Which declared dependencies an edge comes from, which decides what becomes of an edge the lock
/// does not resolve: a required one is [`Dep::Missing`], an optional or peer one is left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Edge {
    Required,
    Optional,
    Peer,
}

/// The dependency fields of an importer's manifest entry, in the order a name is taken from.
const IMPORTER_FIELDS: [(&str, Edge); 4] = [
    ("dependencies", Edge::Required),
    ("devDependencies", Edge::Required),
    ("optionalDependencies", Edge::Optional),
    ("peerDependencies", Edge::Peer),
];

type JsonObject = JsonMap<String, JsonValue>;

fn read_npm(text: &str, context: &Context) -> Result<(LockFormat, Graph), String> {
    let doc: JsonValue =
        serde_json::from_str(text).map_err(|err| format!("is not valid JSON: {err}"))?;
    let root = doc.as_object().ok_or("is not a JSON object")?;
    match root.get("lockfileVersion").and_then(JsonValue::as_u64) {
        Some(1) => Ok((LockFormat::NpmV1, npm_tree(root, context))),
        Some(2) => Ok((LockFormat::NpmV2, npm_packages(root)?)),
        Some(3) => Ok((LockFormat::NpmV3, npm_packages(root)?)),
        Some(other) => Err(format!(
            "has lockfileVersion {other}, which is not supported"
        )),
        None => Err("has no numeric `lockfileVersion`".into()),
    }
}

/// Reads the flat `packages` map of a version 2 or 3 lock. A key under `node_modules` is an
/// installed package; any other key ("" and "packages/a") is an importer. A `link` entry is a
/// symlink to its `resolved` directory, so an edge that reaches it becomes [`Dep::Link`]. An
/// `inBundle` entry ships inside its parent's tarball, so it is left out of the packages and an
/// edge that reaches it is left out too: unpacking the parent provides it.
fn npm_packages(root: &JsonObject) -> Result<Graph, String> {
    let entries = root
        .get("packages")
        .and_then(JsonValue::as_object)
        .ok_or("has no `packages` object")?;
    let installed: HashMap<&str, &JsonObject> = entries
        .iter()
        .filter_map(|(key, value)| Some((key.as_str(), value.as_object()?)))
        .collect();
    let mut graph = Graph::default();
    for (key, value) in entries {
        let Some(entry) = value.as_object() else {
            graph.warnings.push(format!(
                "packages[{key:?}] is not an object and is left out"
            ));
            continue;
        };
        if !is_install_path(key) {
            let mut dependencies = BTreeMap::new();
            for (field, edge) in IMPORTER_FIELDS {
                npm_edges(key, entry.get(field), edge, &installed, &mut dependencies);
            }
            graph
                .importers
                .insert(key.clone(), Importer { dependencies });
            continue;
        }
        if flag(entry, "link") || flag(entry, "inBundle") {
            continue;
        }
        let name = json_str(entry, "name")
            .unwrap_or_else(|| install_name(key))
            .to_owned();
        let version = json_str(entry, "version").unwrap_or_default().to_owned();
        let integrity = json_str(entry, "integrity")
            .map(parse_sri)
            .unwrap_or_default();
        let source = match json_str(entry, "resolved") {
            Some(resolved) => resolved_source(resolved, &name, &version, integrity),
            None => Source::Registry {
                tarball: None,
                integrity,
                archive_checksum: None,
            },
        };
        let mut dependencies = BTreeMap::new();
        for (field, edge) in [
            ("dependencies", Edge::Required),
            ("optionalDependencies", Edge::Optional),
            ("peerDependencies", Edge::Peer),
        ] {
            npm_edges(key, entry.get(field), edge, &installed, &mut dependencies);
        }
        graph.packages.insert(
            key.clone(),
            LockedPackage {
                name,
                version,
                source,
                dependencies,
                optional: flag(entry, "optional"),
                os: json_strings(entry.get("os")),
                cpu: json_strings(entry.get("cpu")),
                libc: json_strings(entry.get("libc")),
            },
        );
    }
    Ok(graph)
}

/// Resolves the names declared in `declared` from `location` and adds each to `out`, keeping a
/// name already there.
fn npm_edges(
    location: &str,
    declared: Option<&JsonValue>,
    edge: Edge,
    installed: &HashMap<&str, &JsonObject>,
    out: &mut BTreeMap<String, Dep>,
) {
    let Some(declared) = declared.and_then(JsonValue::as_object) else {
        return;
    };
    for name in declared.keys() {
        if out.contains_key(name) {
            continue;
        }
        let dep = match npm_resolve(location, name, installed) {
            Some(found) => {
                let entry = installed[found];
                if flag(entry, "inBundle") {
                    continue;
                }
                if flag(entry, "link") {
                    match json_str(entry, "resolved") {
                        Some(target) => Dep::Link(join_relative(
                            "",
                            target.strip_prefix("file:").unwrap_or(target),
                        )),
                        None => Dep::Missing(format!("{found} is a link with no `resolved`")),
                    }
                } else {
                    Dep::Package(found.to_owned())
                }
            }
            None if edge == Edge::Required => Dep::Missing(format!(
                "no node_modules/{name} is reachable from {}",
                shown_dir(location)
            )),
            None => continue,
        };
        out.insert(name.clone(), dep);
    }
}

/// Finds the install path Node would load `name` from when required at `location`: the nearest
/// `<dir>/node_modules/<name>` walking up from `location` to the lock's directory.
fn npm_resolve<'k>(
    location: &str,
    name: &str,
    installed: &HashMap<&'k str, &JsonObject>,
) -> Option<&'k str> {
    let mut dir = location;
    loop {
        if dir.rsplit('/').next() != Some("node_modules") {
            let candidate = if dir.is_empty() {
                format!("node_modules/{name}")
            } else {
                format!("{dir}/node_modules/{name}")
            };
            if let Some((key, _)) = installed.get_key_value(candidate.as_str()) {
                return Some(key);
            }
        }
        if dir.is_empty() {
            return None;
        }
        dir = dir.rfind('/').map_or("", |at| &dir[..at]);
    }
}

fn is_install_path(key: &str) -> bool {
    key.split('/').any(|segment| segment == "node_modules")
}

/// The name a package is installed under: the part of its install path after the last
/// `node_modules/`.
fn install_name(key: &str) -> &str {
    key.rsplit_once("node_modules/")
        .map_or(key, |(_, name)| name)
}

/// Reads a version 1 lock's nested `dependencies` tree. Each entry's install path is its place in
/// the tree, and its `requires` resolve the way Node resolves them, walking up from that place.
/// An entry whose version is `file:` to a directory is a symlink, so an edge to it becomes
/// [`Dep::Link`]; a `bundled` entry ships inside its parent and is left out as in version 2.
/// Version 1 does not record the root's own dependencies, so they come from the `package.json`
/// beside the lock.
fn npm_tree(root: &JsonObject, context: &Context) -> Graph {
    let mut graph = Graph::default();
    let mut entries: Vec<(String, &JsonObject)> = Vec::new();
    npm_tree_entries(
        root.get("dependencies"),
        "",
        &mut entries,
        &mut graph.warnings,
    );
    let installed: HashMap<&str, &JsonObject> = entries
        .iter()
        .map(|(key, entry)| (key.as_str(), *entry))
        .collect();

    for (key, entry) in &entries {
        if flag(entry, "bundled") {
            continue;
        }
        let written = json_str(entry, "version").unwrap_or_default();
        if written
            .strip_prefix("file:")
            .is_some_and(|path| !is_archive(path))
        {
            continue;
        }
        let (name, version) = match written.strip_prefix("npm:").and_then(split_name_ref) {
            Some((real, version)) => (real, version),
            None => (install_name(key), written),
        };
        let integrity = json_str(entry, "integrity")
            .map(parse_sri)
            .unwrap_or_default();
        let source = match json_str(entry, "resolved") {
            Some(resolved) => resolved_source(resolved, name, version, integrity),
            None if looks_like_git(written) => git_source(written),
            None if is_url(written) => Source::RemoteTarball {
                url: written.to_owned(),
                integrity,
            },
            None => match written.strip_prefix("file:") {
                Some(path) => local_source("", path),
                None => Source::Registry {
                    tarball: None,
                    integrity,
                    archive_checksum: None,
                },
            },
        };
        let mut dependencies = BTreeMap::new();
        for dep_name in entry
            .get("requires")
            .and_then(JsonValue::as_object)
            .into_iter()
            .flat_map(|requires| requires.keys())
        {
            if let Some(dep) = npm_tree_dep(key, dep_name, &installed) {
                dependencies.insert(dep_name.clone(), dep);
            }
        }
        graph.packages.insert(
            key.clone(),
            LockedPackage {
                name: name.to_owned(),
                version: version.to_owned(),
                source,
                dependencies,
                optional: flag(entry, "optional"),
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
            },
        );
    }

    let manifest = (context.read)(&context.lock_dir.join("package.json"))
        .and_then(|text| serde_json::from_str::<JsonValue>(&text).ok());
    let mut dependencies = BTreeMap::new();
    match manifest.as_ref().and_then(JsonValue::as_object) {
        Some(manifest) => {
            for (field, edge) in &IMPORTER_FIELDS[..3] {
                for name in manifest
                    .get(*field)
                    .and_then(JsonValue::as_object)
                    .into_iter()
                    .flat_map(|declared| declared.keys())
                {
                    if dependencies.contains_key(name) {
                        continue;
                    }
                    match npm_tree_dep("", name, &installed) {
                        Some(Dep::Missing(_)) if *edge == Edge::Optional => {}
                        Some(dep) => {
                            dependencies.insert(name.clone(), dep);
                        }
                        None => {}
                    }
                }
            }
        }
        None => {
            graph.warnings.push(
                "package.json beside the lock cannot be read, so every top-level entry of the \
                 lock counts as a dependency of the root"
                    .into(),
            );
            for (key, _) in &entries {
                let Some(name) = key.strip_prefix("node_modules/") else {
                    continue;
                };
                if name.contains("node_modules/") {
                    continue;
                }
                if let Some(dep) = npm_tree_dep("", name, &installed) {
                    dependencies.insert(name.to_owned(), dep);
                }
            }
        }
    }
    graph
        .importers
        .insert(String::new(), Importer { dependencies });
    graph
}

/// Flattens a version 1 `dependencies` tree into (install path, entry) pairs.
fn npm_tree_entries<'a>(
    dependencies: Option<&'a JsonValue>,
    prefix: &str,
    out: &mut Vec<(String, &'a JsonObject)>,
    warnings: &mut Vec<String>,
) {
    let Some(dependencies) = dependencies.and_then(JsonValue::as_object) else {
        return;
    };
    for (name, value) in dependencies {
        let key = if prefix.is_empty() {
            format!("node_modules/{name}")
        } else {
            format!("{prefix}/node_modules/{name}")
        };
        let Some(entry) = value.as_object() else {
            warnings.push(format!("{key} is not an object and is left out"));
            continue;
        };
        npm_tree_entries(entry.get("dependencies"), &key, out, warnings);
        out.push((key, entry));
    }
}

/// Resolves a version 1 edge. `None` means the edge is left out, because it reaches a bundled
/// entry that the parent's tarball provides.
fn npm_tree_dep(location: &str, name: &str, installed: &HashMap<&str, &JsonObject>) -> Option<Dep> {
    let Some(found) = npm_resolve(location, name, installed) else {
        return Some(Dep::Missing(format!(
            "no node_modules/{name} is reachable from {}",
            shown_dir(location)
        )));
    };
    let entry = installed[found];
    if flag(entry, "bundled") {
        return None;
    }
    let written = json_str(entry, "version").unwrap_or_default();
    Some(match written.strip_prefix("file:") {
        Some(path) if !is_archive(path) => Dep::Link(join_relative("", path)),
        _ => Dep::Package(found.to_owned()),
    })
}

// pnpm-lock.yaml

/// The shapes of pnpm lockfile this reader knows. Version 5 keys packages
/// `/name/1.2.3_peer@1.0.0` and keeps importer specifiers apart from versions; version 6 keys them
/// `/name@1.2.3(peer@1.0.0)`; version 9 splits metadata (`packages`, keyed `name@1.2.3`) from
/// edges (`snapshots`, keyed `name@1.2.3(peer@1.0.0)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PnpmStyle {
    V5,
    V6,
    V9,
}

/// One package of a pnpm lock before its edges are resolved.
struct PnpmEntry<'d> {
    key: String,
    /// Where the package's metadata lives: `resolution`, `name`, `version`, `os`.
    meta: &'d Yaml,
    /// Where its resolved edges live: `dependencies`, `optionalDependencies`, `optional`.
    edges: &'d Yaml,
    /// Whether the key names a registry version, rather than a URL, git remote or path.
    registry_keyed: bool,
}

static NO_EDGES: Yaml = Yaml::Null;

fn read_pnpm(text: &str) -> Result<(LockFormat, Graph), String> {
    let documents = yaml::parse(text)?;
    let doc = pnpm_document(&documents).ok_or("has no `lockfileVersion`")?;
    let version = doc
        .str_at("lockfileVersion")
        .ok_or("has a `lockfileVersion` that is not a scalar")?
        .to_owned();
    let style = match version.split('.').next() {
        Some("5") => PnpmStyle::V5,
        Some("6") => PnpmStyle::V6,
        Some("9") => PnpmStyle::V9,
        _ => {
            return Err(format!(
                "has lockfileVersion {version}, which is not supported"
            ))
        }
    };
    let mut graph = Graph::default();
    let entries = pnpm_entries(doc, style, &mut graph.warnings);
    let resolver = PnpmResolver::new(&entries, style);

    for entry in &entries {
        let (key_name, key_version) = match pnpm_name_version(&entry.key, style) {
            Some((name, version)) => (Some(name), Some(version)),
            None => (None, None),
        };
        let name = entry
            .meta
            .str_at("name")
            .or(key_name)
            .unwrap_or(&entry.key)
            .to_owned();
        let version = entry
            .meta
            .str_at("version")
            .or(key_version)
            .unwrap_or_default()
            .to_owned();
        let mut dependencies = BTreeMap::new();
        for field in ["dependencies", "optionalDependencies"] {
            for (alias, value) in entry.edges.get(field).map_or(&[][..], Yaml::entries) {
                let dep = match value.as_str() {
                    Some(value) => resolver.dep(alias, value, ""),
                    None => Dep::Missing(format!("{alias} has no version")),
                };
                dependencies.entry(alias.clone()).or_insert(dep);
            }
        }
        if entry.key.contains("patch_hash=") || is_true(entry.meta.get("patched")) {
            graph.warnings.push(format!(
                "{}: the lock patches this package (patchedDependencies); the patch is not \
                 applied and the package is read unpatched",
                entry.key
            ));
        }
        graph.packages.insert(
            entry.key.clone(),
            LockedPackage {
                name,
                version,
                source: pnpm_source(entry.meta.get("resolution"), entry.registry_keyed),
                dependencies,
                optional: is_true(entry.edges.get("optional"))
                    || is_true(entry.meta.get("optional")),
                os: yaml_strings(entry.meta.get("os")),
                cpu: yaml_strings(entry.meta.get("cpu")),
                libc: yaml_strings(entry.meta.get("libc")),
            },
        );
    }

    // A lock of a single project without workspaces (versions 5 and 6) keeps the root's
    // dependencies at the top level instead of under `importers`.
    let importers: Vec<(&str, &Yaml)> = match doc.get("importers") {
        Some(importers) => importers
            .entries()
            .iter()
            .map(|(dir, entry)| (dir.as_str(), entry))
            .collect(),
        None => vec![(".", doc)],
    };
    for (dir, entry) in importers {
        let dir = join_relative("", dir);
        let mut dependencies = BTreeMap::new();
        for field in ["dependencies", "devDependencies", "optionalDependencies"] {
            for (alias, spec) in entry.get(field).map_or(&[][..], Yaml::entries) {
                let dep = match spec.as_str().or_else(|| spec.str_at("version")) {
                    Some(value) => resolver.dep(alias, value, &dir),
                    None => Dep::Missing(format!("{alias} has no resolved version")),
                };
                dependencies.entry(alias.clone()).or_insert(dep);
            }
        }
        graph.importers.insert(dir, Importer { dependencies });
    }
    Ok((LockFormat::Pnpm { version }, graph))
}

/// The document of a pnpm lock that describes the project. Recent pnpm writes a leading document
/// that locks only its own configuration dependencies and package manager; the project's lock is
/// the document after it.
fn pnpm_document(documents: &[Yaml]) -> Option<&Yaml> {
    let locks: Vec<&Yaml> = documents
        .iter()
        .filter(|doc| doc.get("lockfileVersion").is_some())
        .collect();
    locks
        .iter()
        .rev()
        .find(|doc| !is_pnpm_env_document(doc))
        .or(locks.last())
        .copied()
}

fn is_pnpm_env_document(doc: &Yaml) -> bool {
    let importers = doc.get("importers").map_or(&[][..], Yaml::entries);
    !importers.is_empty()
        && importers.iter().all(|(dir, entry)| {
            dir == "."
                && entry.entries().iter().all(|(field, _)| {
                    field == "configDependencies" || field == "packageManagerDependencies"
                })
        })
}

fn pnpm_entries<'d>(
    doc: &'d Yaml,
    style: PnpmStyle,
    warnings: &mut Vec<String>,
) -> Vec<PnpmEntry<'d>> {
    let packages = doc.get("packages").map_or(&[][..], Yaml::entries);
    if style != PnpmStyle::V9 {
        return packages
            .iter()
            .map(|(raw, entry)| PnpmEntry {
                key: pnpm_key(raw, style),
                meta: entry,
                edges: entry,
                registry_keyed: raw.starts_with('/'),
            })
            .collect();
    }
    let metadata: HashMap<&str, &Yaml> = packages
        .iter()
        .map(|(key, meta)| (key.as_str(), meta))
        .collect();
    let mut described: HashSet<&str> = HashSet::new();
    let mut out = Vec::new();
    for (key, snapshot) in doc.get("snapshots").map_or(&[][..], Yaml::entries) {
        let base = without_peers(key);
        let Some(meta) = metadata.get(base) else {
            warnings.push(format!(
                "snapshot {key} has no entry under `packages` and is left out"
            ));
            continue;
        };
        described.insert(base);
        out.push(PnpmEntry {
            key: key.clone(),
            meta,
            edges: snapshot,
            registry_keyed: v9_registry_keyed(base),
        });
    }
    for (key, meta) in packages {
        if !described.contains(key.as_str()) {
            out.push(PnpmEntry {
                key: key.clone(),
                meta,
                edges: &NO_EDGES,
                registry_keyed: v9_registry_keyed(key),
            });
        }
    }
    out
}

/// Normalizes a pnpm package key: the leading `/` goes, and a version 5 key `/name/1.2.3_x`
/// becomes `name@1.2.3_x` so that every registry key reads `name@version...`. A key without a
/// leading `/` (a git host path or `file:` in versions 5 and 6) stays as written.
fn pnpm_key(raw: &str, style: PnpmStyle) -> String {
    let Some(path) = raw.strip_prefix('/') else {
        return raw.to_owned();
    };
    if style != PnpmStyle::V5 {
        return path.to_owned();
    }
    let name_segments = if path.starts_with('@') { 2 } else { 1 };
    let mut parts = path.splitn(name_segments + 1, '/');
    let name: Vec<&str> = parts.by_ref().take(name_segments).collect();
    match parts.next() {
        Some(version) if name.len() == name_segments => {
            format!("{}@{version}", name.join("/"))
        }
        _ => path.to_owned(),
    }
}

/// The name and version a normalized pnpm key spells, without its peer suffix.
fn pnpm_name_version(key: &str, style: PnpmStyle) -> Option<(&str, &str)> {
    let (name, reference) = split_name_ref(key)?;
    let end = match style {
        PnpmStyle::V5 => reference.find('_'),
        PnpmStyle::V6 | PnpmStyle::V9 => reference.find('('),
    };
    Some((name, &reference[..end.unwrap_or(reference.len())]))
}

/// A version 9 snapshot key without its peer suffix, which is the key of its metadata:
/// `a@1.0.0(b@2.0.0)(c@3.0.0)` gives `a@1.0.0`.
fn without_peers(key: &str) -> &str {
    let from = split_name_ref(key).map_or(0, |(name, _)| name.len() + 1);
    match key[from..].find('(') {
        Some(at) => &key[..from + at],
        None => key,
    }
}

fn v9_registry_keyed(key: &str) -> bool {
    split_name_ref(key).is_some_and(|(_, reference)| !reference.contains(':'))
}

/// Resolves the version a pnpm lock writes for a dependency to a package key.
struct PnpmResolver<'e> {
    style: PnpmStyle,
    keys: HashSet<&'e str>,
    /// Keys by the reference after `name@`, for a dependency on a URL, path or git source
    /// installed under an alias that differs from the package's name.
    by_reference: HashMap<&'e str, Vec<&'e str>>,
}

impl<'e> PnpmResolver<'e> {
    fn new(entries: &'e [PnpmEntry], style: PnpmStyle) -> Self {
        let mut by_reference: HashMap<&str, Vec<&str>> = HashMap::new();
        for entry in entries {
            if let Some((_, reference)) = split_name_ref(&entry.key) {
                by_reference
                    .entry(reference)
                    .or_default()
                    .push(entry.key.as_str());
            }
        }
        PnpmResolver {
            style,
            keys: entries.iter().map(|entry| entry.key.as_str()).collect(),
            by_reference,
        }
    }

    /// Resolves the dependency `alias` written as `value`. `base` is the importer's directory,
    /// which a `link:` path is relative to; for a package it is "".
    fn dep(&self, alias: &str, value: &str, base: &str) -> Dep {
        if let Some(path) = value.strip_prefix("link:") {
            return Dep::Link(join_relative(base, path));
        }
        let mut candidates = Vec::with_capacity(3);
        if value.starts_with('/') {
            // An alias in versions 5 and 6 names the whole key: `/string-width@4.2.3`.
            candidates.push(pnpm_key(value, self.style));
        } else {
            // `1.2.3(peer@1.0.0)` is the version of `alias`; an alias in version 9 names the
            // whole key (`string-width@4.2.3`), and so does a git host path in versions 5 and 6.
            candidates.push(format!("{alias}@{value}"));
            candidates.push(value.to_owned());
            if let Some(spec) = value.strip_prefix("npm:") {
                candidates.push(spec.to_owned());
            }
        }
        for candidate in &candidates {
            if let Some(key) = self.keys.get(candidate.as_str()) {
                return Dep::Package((*key).to_owned());
            }
        }
        if value.contains(':') {
            if let Some([only]) = self.by_reference.get(value).map(Vec::as_slice) {
                return Dep::Package((*only).to_owned());
            }
        }
        Dep::Missing(format!("no package of the lock matches {alias} {value}"))
    }
}

/// Reads a pnpm `resolution`. A tarball on a key that names a registry version is a registry
/// package from a registry that pnpm records the URL of; a tarball on any other key is a remote
/// tarball.
fn pnpm_source(resolution: Option<&Yaml>, registry_keyed: bool) -> Source {
    let Some(resolution) = resolution.filter(|resolution| resolution.as_map().is_some()) else {
        return Source::Unsupported {
            reason: "has no `resolution`".into(),
        };
    };
    let integrity = resolution
        .str_at("integrity")
        .map(parse_sri)
        .unwrap_or_default();
    match resolution.str_at("type") {
        Some("git") => match resolution.str_at("repo") {
            Some(repo) => Source::Git {
                repository: repo.to_owned(),
                commit: resolution.str_at("commit").map(str::to_owned),
            },
            None => Source::Unsupported {
                reason: "has a git resolution with no `repo`".into(),
            },
        },
        Some("directory") => match resolution.str_at("directory") {
            Some(directory) => Source::Local {
                path: join_relative("", directory),
            },
            None => Source::Unsupported {
                reason: "has a directory resolution with no `directory`".into(),
            },
        },
        Some(other) => Source::Unsupported {
            reason: format!("has a resolution of type `{other}`"),
        },
        None => match resolution.str_at("tarball") {
            Some(tarball) => {
                if let Some(path) = tarball.strip_prefix("file:") {
                    local_source("", path)
                } else if registry_keyed {
                    Source::Registry {
                        tarball: Some(tarball.to_owned()),
                        integrity,
                        archive_checksum: None,
                    }
                } else {
                    Source::RemoteTarball {
                        url: tarball.to_owned(),
                        integrity,
                    }
                }
            }
            None if resolution.get("integrity").is_some() => Source::Registry {
                tarball: None,
                integrity,
                archive_checksum: None,
            },
            None => Source::Unsupported {
                reason: "has a resolution with neither `integrity` nor `tarball`".into(),
            },
        },
    }
}

// yarn.lock written by Yarn Classic

/// One node of Yarn Classic's own lockfile format: a `key value` line, or a `key1, key2:` line
/// with the more deeply indented lines under it.
struct ClassicNode {
    keys: Vec<String>,
    value: ClassicValue,
    line: usize,
}

enum ClassicValue {
    Text(String),
    Block(Vec<ClassicNode>),
}

enum ClassicLine {
    Header(Vec<String>),
    Field(String, String),
}

/// One entry of a Yarn Classic lock before its edges are resolved.
struct ClassicEntry<'n> {
    key: String,
    name: String,
    version: &'n str,
    /// The range of the entry's first descriptor, with an npm alias's `npm:name@` removed.
    range: &'n str,
    fields: &'n [ClassicNode],
}

/// Reads a Yarn Classic lock. Each entry is keyed `name@version` by its real name; the rare second
/// entry of the same name and version (a fork from git beside the registry release) is keyed by
/// its `resolved` URL instead. An edge `name range` resolves through the descriptor `name@range`.
/// The lock lists no importers, so they come from the `package.json` of the root and of each
/// declared workspace, and a dependency the lock does not hold but a workspace package is named
/// by links to that package's directory. A dependency whose descriptor the lock lacks is looked
/// up again through the root manifest's `resolutions`. A `resolved` URL's `#` fragment, which is
/// the tarball's sha1, becomes a sha1 [`Integrity`] when the entry has no `integrity`, and is
/// removed from the tarball URL.
fn read_classic(text: &str, context: &Context) -> Result<Graph, String> {
    let nodes = classic_parse(text)?;
    let mut graph = Graph::default();
    let mut entries: Vec<ClassicEntry> = Vec::new();
    let mut by_descriptor: HashMap<&str, usize> = HashMap::new();
    let mut taken: HashSet<String> = HashSet::new();
    for node in &nodes {
        let ClassicValue::Block(fields) = &node.value else {
            graph.warnings.push(format!(
                "line {}: `{}` is not an entry and is left out",
                node.line,
                node.keys.join(", ")
            ));
            continue;
        };
        let first = node.keys.first().map(String::as_str).unwrap_or_default();
        let Some((alias, range)) = split_name_ref(first) else {
            graph.warnings.push(format!(
                "line {}: `{first}` names no package and is left out",
                node.line
            ));
            continue;
        };
        let Some(version) = classic_text(fields, "version") else {
            graph
                .warnings
                .push(format!("{first}: has no version and is left out"));
            continue;
        };
        let name = aliased_name(alias, range);
        let range = range
            .strip_prefix("npm:")
            .and_then(split_name_ref)
            .map_or(range, |(_, real_range)| real_range);
        let mut key = format!("{name}@{version}");
        if taken.contains(&key) {
            let origin = classic_text(fields, "resolved").unwrap_or(range);
            key = format!("{name}@{origin}");
        }
        if !taken.insert(key.clone()) {
            graph.warnings.push(format!(
                "{first}: resolves to {key}, which another entry already holds, and is left out"
            ));
            continue;
        }
        for descriptor in &node.keys {
            by_descriptor.insert(descriptor.as_str(), entries.len());
        }
        entries.push(ClassicEntry {
            key,
            name: name.to_owned(),
            version,
            range,
            fields,
        });
    }

    let mut workspace_dirs: HashMap<&str, String> = HashMap::new();
    let mut manifests = vec![(String::new(), context.lock_dir.join("package.json"))];
    for (name, dir) in context.workspaces {
        match relative_dir(context.lock_dir, dir) {
            Some(relative) => {
                workspace_dirs.insert(name, relative.clone());
                if !relative.is_empty() {
                    manifests.push((relative, dir.join("package.json")));
                }
            }
            None => graph.warnings.push(format!(
                "workspace {name} at {} is outside the lock's directory and is left out",
                dir.display()
            )),
        }
    }
    let resolutions = read_resolutions(context);
    let resolve = |from: &str, alias: &str, range: &str, base: &str| -> Dep {
        if let Some(path) = range.strip_prefix("link:") {
            return Dep::Link(join_relative(base, path));
        }
        if !range.starts_with("workspace:") {
            let forced = forced_range(&resolutions, from, alias, range);
            for range in std::iter::once(range).chain(forced) {
                let descriptor = format!("{alias}@{range}");
                if let Some(&index) = by_descriptor.get(descriptor.as_str()) {
                    return Dep::Package(entries[index].key.clone());
                }
            }
        }
        if let Some(dir) = workspace_dirs.get(alias) {
            return Dep::Link(dir.clone());
        }
        Dep::Missing(format!("no entry of the lock matches {alias}@{range}"))
    };

    let mut optional_edges = OptionalEdges::new();
    for entry in &entries {
        let mut dependencies = BTreeMap::new();
        for (field, optional) in [("dependencies", false), ("optionalDependencies", true)] {
            for node in classic_block(entry.fields, field) {
                let (Some(alias), ClassicValue::Text(range)) = (node.keys.first(), &node.value)
                else {
                    continue;
                };
                if dependencies.contains_key(alias) {
                    continue;
                }
                let dep = resolve(&entry.name, alias, range, "");
                if optional {
                    if matches!(dep, Dep::Missing(_)) {
                        continue;
                    }
                    optional_edges.insert((false, entry.key.clone(), alias.clone()));
                }
                dependencies.insert(alias.clone(), dep);
            }
        }
        graph.packages.insert(
            entry.key.clone(),
            LockedPackage {
                name: entry.name.clone(),
                version: entry.version.to_owned(),
                source: classic_source(entry),
                dependencies,
                optional: false,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
            },
        );
    }

    for (dir, path) in &manifests {
        let Some(manifest) = read_manifest(context, path) else {
            let shown = if dir.is_empty() {
                "package.json".to_owned()
            } else {
                format!("{dir}/package.json")
            };
            graph.warnings.push(format!(
                "{shown}: cannot be read, so the importer at {} has no dependencies",
                shown_dir(dir)
            ));
            graph.importers.insert(dir.clone(), Importer::default());
            continue;
        };
        let from = json_str(&manifest, "name").unwrap_or_default();
        let mut dependencies = BTreeMap::new();
        for (field, edge) in &IMPORTER_FIELDS[..3] {
            for (alias, range) in manifest
                .get(*field)
                .and_then(JsonValue::as_object)
                .into_iter()
                .flatten()
            {
                let Some(range) = range.as_str() else {
                    continue;
                };
                if dependencies.contains_key(alias) {
                    continue;
                }
                let dep = resolve(from, alias, range, dir);
                if *edge == Edge::Optional {
                    if matches!(dep, Dep::Missing(_)) {
                        continue;
                    }
                    optional_edges.insert((true, dir.clone(), alias.clone()));
                }
                dependencies.insert(alias.clone(), dep);
            }
        }
        graph
            .importers
            .insert(dir.clone(), Importer { dependencies });
    }
    mark_optional(&mut graph, &optional_edges);
    Ok(graph)
}

fn classic_source(entry: &ClassicEntry) -> Source {
    let integrity_field = classic_text(entry.fields, "integrity");
    let mut integrity = integrity_field.map(parse_sri).unwrap_or_default();
    let Some(resolved) = classic_text(entry.fields, "resolved") else {
        if let Some(path) = entry.range.strip_prefix("file:") {
            return local_source("", path);
        }
        return Source::Registry {
            tarball: None,
            integrity,
            archive_checksum: None,
        };
    };
    if looks_like_git(resolved) {
        return git_source(resolved);
    }
    let (url, fragment) = split_fragment(resolved);
    if integrity_field.is_none() {
        if let Some(digest) = fragment
            .filter(|fragment| fragment.len() == 40)
            .and_then(hex_decode)
        {
            integrity.push(Integrity {
                algorithm: Algorithm::Sha1,
                digest,
            });
        }
    }
    resolved_source(url, &entry.name, entry.version, integrity)
}

/// The text of the `key value` field named `key`.
fn classic_text<'n>(nodes: &'n [ClassicNode], key: &str) -> Option<&'n str> {
    nodes.iter().find_map(|node| match &node.value {
        ClassicValue::Text(text) if node.keys.first().map(String::as_str) == Some(key) => {
            Some(text.as_str())
        }
        _ => None,
    })
}

/// The nodes under the `key:` block named `key`.
fn classic_block<'n>(nodes: &'n [ClassicNode], key: &str) -> &'n [ClassicNode] {
    nodes
        .iter()
        .find_map(|node| match &node.value {
            ClassicValue::Block(children) if node.keys.first().map(String::as_str) == Some(key) => {
                Some(children.as_slice())
            }
            _ => None,
        })
        .unwrap_or(&[])
}

/// Parses Yarn Classic's lockfile format, which is its own and not YAML: `key value` lines and
/// `key1, key2:` lines that open an indented block, with keys and values bare or in double quotes.
fn classic_parse(text: &str) -> Result<Vec<ClassicNode>, String> {
    let mut lines = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let content = raw.trim_end();
        let body = content.trim_start_matches(' ');
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        if ["<<<<<<<", "=======", ">>>>>>>"]
            .iter()
            .any(|marker| body.starts_with(marker))
        {
            return Err(format!("line {number}: has a merge conflict marker"));
        }
        let indent = content.len() - body.len();
        let line = classic_line(body).map_err(|why| format!("line {number}: {why}"))?;
        lines.push((indent, line, number));
    }
    let mut pos = 0;
    classic_nodes(&lines, &mut pos, 0)
}

fn classic_nodes(
    lines: &[(usize, ClassicLine, usize)],
    pos: &mut usize,
    indent: usize,
) -> Result<Vec<ClassicNode>, String> {
    let mut nodes = Vec::new();
    while let Some((line_indent, line, number)) = lines.get(*pos) {
        if *line_indent < indent {
            break;
        }
        if *line_indent > indent {
            return Err(format!(
                "line {number}: is indented more than the lines around it"
            ));
        }
        *pos += 1;
        match line {
            ClassicLine::Field(key, value) => nodes.push(ClassicNode {
                keys: vec![key.clone()],
                value: ClassicValue::Text(value.clone()),
                line: *number,
            }),
            ClassicLine::Header(keys) => {
                let children = match lines.get(*pos) {
                    Some((next, _, _)) if *next > indent => classic_nodes(lines, pos, *next)?,
                    _ => Vec::new(),
                };
                nodes.push(ClassicNode {
                    keys: keys.clone(),
                    value: ClassicValue::Block(children),
                    line: *number,
                });
            }
        }
    }
    Ok(nodes)
}

fn classic_line(body: &str) -> Result<ClassicLine, String> {
    let bytes = body.as_bytes();
    let mut words: Vec<String> = Vec::new();
    let mut commas = 0;
    let mut colon = false;
    let mut index = 0;
    let ends_word = |at: usize| {
        let byte = bytes[at];
        matches!(byte, b' ' | b'\t' | b',')
            || (byte == b':' && matches!(bytes.get(at + 1), None | Some(b' ' | b'\t')))
    };
    while index < bytes.len() {
        match bytes[index] {
            b' ' | b'\t' => index += 1,
            b'#' if index > 0 && matches!(bytes[index - 1], b' ' | b'\t') => break,
            _ if colon => return Err("has text after the `:` that ends a key".into()),
            b',' => {
                commas += 1;
                index += 1;
            }
            b':' if ends_word(index) => {
                colon = true;
                index += 1;
            }
            b'"' => {
                let (word, end) =
                    yaml::quoted(body, index).ok_or("has a quoted string that is not closed")?;
                words.push(word);
                index = end;
            }
            _ => {
                let start = index;
                while index < bytes.len() && !ends_word(index) {
                    index += 1;
                }
                words.push(body[start..index].to_owned());
            }
        }
    }
    if colon {
        if words.is_empty() || commas + 1 != words.len() {
            return Err("has a malformed list of keys".into());
        }
        return Ok(ClassicLine::Header(words));
    }
    match <[String; 2]>::try_from(words) {
        Ok([key, value]) if commas == 0 => Ok(ClassicLine::Field(key, value)),
        _ => Err("is neither `key value` nor `key:`".into()),
    }
}

/// The real package name of the descriptor `alias@range`. An npm alias
/// (`string-width-cjs@npm:string-width@^4.2.0`) names another package.
fn aliased_name<'a>(alias: &'a str, range: &'a str) -> &'a str {
    range
        .strip_prefix("npm:")
        .and_then(split_name_ref)
        .map_or(alias, |(real, _)| real)
}

// yarn.lock written by Yarn Berry

/// What a Yarn Berry descriptor resolves to.
#[derive(Debug, Clone)]
enum BerryTarget {
    Package(String),
    Link(String),
}

/// One package of a Yarn Berry lock before its edges are resolved.
struct BerryPackage<'d> {
    key: String,
    name: &'d str,
    reference: String,
    entry: &'d Yaml,
    /// Whether the entry is a patched package standing in for an original the lock lacks, whose
    /// `checksum` covers the patched archive and not the original.
    patched: bool,
}

fn is_berry(text: &str) -> bool {
    text.lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .take(3)
        .any(|line| line == "__metadata:")
}

/// Reads a Yarn Berry lock. Each entry is keyed by its `resolution`. A `workspace:` resolution is
/// an importer, and so is a `portal:` one, whose dependencies Yarn resolves; edges to either, and
/// to a `link:` directory, are [`Dep::Link`]. A `patch:` resolution maps to the package it
/// patches, with a warning naming the patch, since the patch is not applied. An edge `name range`
/// resolves through the descriptor `name@range`, and a bare range from an older lock is also
/// tried as `name@npm:range`; a descriptor the lock lacks is looked up again through the root
/// manifest's `resolutions`. Peer dependencies are left out, because the lock does not resolve
/// them. Yarn marks optional edges in `dependenciesMeta`, from which [`LockedPackage::optional`]
/// is computed, and restricts platform packages with `conditions` such as
/// `os=darwin & cpu=arm64`, which become the package's `os`, `cpu` and `libc`.
fn read_berry(text: &str, context: &Context) -> Result<(LockFormat, Graph), String> {
    let documents = yaml::parse(text)?;
    let doc = documents
        .iter()
        .find(|doc| doc.get("__metadata").is_some())
        .ok_or("has no `__metadata`")?;
    let version = doc
        .get("__metadata")
        .and_then(|metadata| metadata.str_at("version"))
        .unwrap_or_default()
        .to_owned();
    let mut graph = Graph::default();
    let mut index = BerryIndex {
        targets: HashMap::new(),
        resolutions: read_resolutions(context),
    };
    let mut packages: Vec<BerryPackage> = Vec::new();
    let mut importers: Vec<(String, &str, &Yaml)> = Vec::new();
    let mut patches: Vec<(&str, String, String, &str, &Yaml)> = Vec::new();

    for (header, entry) in doc.entries() {
        if header == "__metadata" {
            continue;
        }
        let Some(resolution) = entry.str_at("resolution") else {
            graph
                .warnings
                .push(format!("{header}: has no resolution and is left out"));
            continue;
        };
        let Some((name, reference)) = split_name_ref(resolution) else {
            graph.warnings.push(format!(
                "{header}: has resolution `{resolution}`, which names no package, and is left out"
            ));
            continue;
        };
        let target = if let Some(dir) = reference.strip_prefix("workspace:") {
            let dir = join_relative("", dir);
            importers.push((dir.clone(), name, entry));
            BerryTarget::Link(dir)
        } else if let Some(rest) = reference.strip_prefix("portal:") {
            let dir = berry_path(rest);
            importers.push((dir.clone(), name, entry));
            BerryTarget::Link(dir)
        } else if let Some(rest) = reference.strip_prefix("link:") {
            BerryTarget::Link(berry_path(rest))
        } else if reference.starts_with("patch:") {
            let (original, patch) = berry_unpatch(reference);
            patches.push((resolution, original.clone(), patch, name, entry));
            BerryTarget::Package(original)
        } else {
            packages.push(BerryPackage {
                key: resolution.to_owned(),
                name,
                reference: reference.to_owned(),
                entry,
                patched: false,
            });
            BerryTarget::Package(resolution.to_owned())
        };
        for descriptor in header
            .split(',')
            .map(str::trim)
            .filter(|descriptor| !descriptor.is_empty())
        {
            index.targets.insert(descriptor, target.clone());
        }
    }

    let mut known: HashSet<String> = packages.iter().map(|package| package.key.clone()).collect();
    for (resolution, original, patch, name, entry) in patches {
        graph.warnings.push(format!(
            "{resolution}: the patch {patch} is not applied; {original} is read unpatched"
        ));
        if !known.insert(original.clone()) {
            continue;
        }
        // The lock holds the patched package without its original, so the patched entry stands
        // in for the original.
        let reference = split_name_ref(&original)
            .map(|(_, reference)| reference.to_owned())
            .unwrap_or_default();
        packages.push(BerryPackage {
            key: original,
            name,
            reference,
            entry,
            patched: true,
        });
    }

    let mut optional_edges = OptionalEdges::new();
    for package in &packages {
        let dependencies = index.edges(
            package.entry,
            package.name,
            (false, &package.key),
            &mut optional_edges,
        );
        let checksum = package
            .entry
            .str_at("checksum")
            .filter(|_| !package.patched)
            .map(str::to_owned);
        let (os, cpu, libc) = berry_conditions(package.entry.str_at("conditions").unwrap_or(""));
        graph.packages.insert(
            package.key.clone(),
            LockedPackage {
                name: package.name.to_owned(),
                version: package
                    .entry
                    .str_at("version")
                    .unwrap_or_default()
                    .to_owned(),
                source: berry_source(&package.reference, checksum),
                dependencies,
                optional: false,
                os,
                cpu,
                libc,
            },
        );
    }
    for (dir, name, entry) in importers {
        let dependencies = index.edges(entry, name, (true, &dir), &mut optional_edges);
        graph.importers.insert(dir, Importer { dependencies });
    }
    mark_optional(&mut graph, &optional_edges);
    Ok((LockFormat::YarnBerry { version }, graph))
}

/// The descriptors of a Yarn Berry lock and the root manifest's `resolutions`, which together
/// resolve an edge.
struct BerryIndex<'d> {
    targets: HashMap<&'d str, BerryTarget>,
    resolutions: Vec<Resolution>,
}

impl BerryIndex<'_> {
    /// Resolves an entry's `dependencies`, recording in `optional_edges` those `dependenciesMeta`
    /// marks optional. `name` is the entry's package name, which a `parent/name` resolution
    /// matches. `from` names the entry as an importer (`true`, its directory) or a package
    /// (`false`, its key).
    fn edges(
        &self,
        entry: &Yaml,
        name: &str,
        from: (bool, &str),
        optional_edges: &mut OptionalEdges,
    ) -> BTreeMap<String, Dep> {
        let optional: HashSet<&str> = entry
            .get("dependenciesMeta")
            .map_or(&[][..], Yaml::entries)
            .iter()
            .filter(|(_, meta)| meta.str_at("optional") == Some("true"))
            .map(|(key, _)| split_name_ref(key).map_or(key.as_str(), |(name, _)| name))
            .collect();
        let mut out = BTreeMap::new();
        for (alias, range) in entry.get("dependencies").map_or(&[][..], Yaml::entries) {
            let Some(range) = range.as_str() else {
                continue;
            };
            let dep = self.dep(name, alias, range);
            if optional.contains(alias.as_str()) {
                if matches!(dep, Dep::Missing(_)) {
                    continue;
                }
                optional_edges.insert((from.0, from.1.to_owned(), alias.clone()));
            }
            out.insert(alias.clone(), dep);
        }
        out
    }

    fn dep(&self, from: &str, alias: &str, range: &str) -> Dep {
        let found = self.lookup(alias, range).or_else(|| {
            forced_range(&self.resolutions, from, alias, range)
                .and_then(|forced| self.lookup(alias, forced))
        });
        match found {
            Some(BerryTarget::Package(key)) => Dep::Package(key.clone()),
            Some(BerryTarget::Link(dir)) => Dep::Link(dir.clone()),
            None => Dep::Missing(format!("no entry of the lock matches {alias}@{range}")),
        }
    }

    /// The target of the descriptor `alias@range`, trying a bare range from an older lock as
    /// `alias@npm:range` too.
    fn lookup(&self, alias: &str, range: &str) -> Option<&BerryTarget> {
        self.targets
            .get(format!("{alias}@{range}").as_str())
            .or_else(|| {
                if has_protocol(range) {
                    None
                } else {
                    self.targets.get(format!("{alias}@npm:{range}").as_str())
                }
            })
    }
}

/// Whether a range starts with a protocol such as `npm:`, `workspace:` or `git+ssh:`.
fn has_protocol(range: &str) -> bool {
    range.find(':').is_some_and(|at| {
        at > 0
            && range[..at]
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'+' || byte == b'-')
    })
}

/// Splits a `patch:` reference into the locator of the package it patches and the patch it
/// applies. `patch:typescript@npm%3A5.4.5#optional!builtin<compat/typescript>::version=5.4.5`
/// gives `typescript@npm:5.4.5` and `optional!builtin<compat/typescript>`. A patch of a patch
/// unwraps to the innermost original.
fn berry_unpatch(reference: &str) -> (String, String) {
    let mut rest = reference
        .strip_prefix("patch:")
        .unwrap_or(reference)
        .to_owned();
    let mut patches = Vec::new();
    loop {
        let (source, patch) = rest.split_once('#').unwrap_or((rest.as_str(), ""));
        patches.push(patch.split("::").next().unwrap_or(patch).to_owned());
        let original = percent_decode(source);
        match split_name_ref(&original).and_then(|(_, reference)| reference.strip_prefix("patch:"))
        {
            Some(inner) => rest = inner.to_owned(),
            None => return (original, patches.join(", ")),
        }
    }
}

/// The directory a `file:`, `link:` or `portal:` reference names, relative to the lock's
/// directory. Yarn writes the path relative to the workspace that declared it, which a
/// `::locator=` parameter names, and a `file:` resolution repeats the path after a `#`.
fn berry_path(rest: &str) -> String {
    let (path, params) = rest.split_once("::").unwrap_or((rest, ""));
    let path = path.split('#').next().unwrap_or(path);
    let base = params
        .split('&')
        .find_map(|param| param.strip_prefix("locator="))
        .map(percent_decode)
        .and_then(|locator| {
            split_name_ref(&locator).and_then(|(_, reference)| {
                reference
                    .strip_prefix("workspace:")
                    .map(|dir| join_relative("", dir))
            })
        })
        .unwrap_or_default();
    join_relative(&base, path)
}

fn berry_source(reference: &str, checksum: Option<String>) -> Source {
    if reference.starts_with("npm:") {
        return Source::Registry {
            tarball: None,
            integrity: Vec::new(),
            archive_checksum: checksum,
        };
    }
    if looks_like_git(reference) || reference.contains("#commit=") {
        return git_source(reference);
    }
    if is_url(reference) {
        return Source::RemoteTarball {
            url: reference.to_owned(),
            integrity: Vec::new(),
        };
    }
    if let Some(rest) = reference.strip_prefix("file:") {
        let path = berry_path(rest);
        return if is_archive(&path) {
            unsupported_archive(&path)
        } else {
            Source::Local { path }
        };
    }
    let protocol = reference.split(':').next().unwrap_or(reference);
    Source::Unsupported {
        reason: format!("comes from the `{protocol}:` protocol, which is not supported"),
    }
}

/// Reads `conditions` such as `(os=darwin | os=linux) & cpu=arm64` into the listed operating
/// systems, CPUs and C libraries.
fn berry_conditions(conditions: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let (mut os, mut cpu, mut libc) = (Vec::new(), Vec::new(), Vec::new());
    for atom in conditions.split(|c: char| matches!(c, '&' | '|' | '(' | ')') || c.is_whitespace())
    {
        let Some((field, value)) = atom.split_once('=') else {
            continue;
        };
        let list: &mut Vec<String> = match field {
            "os" => &mut os,
            "cpu" => &mut cpu,
            "libc" => &mut libc,
            _ => continue,
        };
        if !list.iter().any(|listed| listed == value) {
            list.push(value.to_owned());
        }
    }
    (os, cpu, libc)
}

// Shared helpers

/// A `resolutions` entry of the root `package.json`. Yarn forces every matching dependency to its
/// range when it installs, and its lock then records only the forced descriptor, so a dependency
/// whose own descriptor the lock lacks is looked up again through the resolution that matches it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Resolution {
    /// The name of the package whose dependency it applies to (`parent/name`), or `None` for any.
    parent: Option<String>,
    name: String,
    /// The range it applies to (`name@range`), or `None` for any range.
    range: Option<String>,
    /// The range it forces.
    value: String,
}

fn read_resolutions(context: &Context) -> Vec<Resolution> {
    let Some(manifest) = read_manifest(context, &context.lock_dir.join("package.json")) else {
        return Vec::new();
    };
    manifest
        .get("resolutions")
        .and_then(JsonValue::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| Some(parse_resolution(key, value.as_str()?)))
        .collect()
}

/// Reads a `resolutions` key: `name`, `name@range`, `parent/name` or `**/name`, where `parent`
/// and `name` may be scoped.
fn parse_resolution(key: &str, value: &str) -> Resolution {
    let key = key.strip_prefix("**/").unwrap_or(key);
    let first = key.find('/');
    let parent_end = if key.starts_with('@') {
        first.and_then(|at| key[at + 1..].find('/').map(|next| at + 1 + next))
    } else {
        first
    };
    let (parent, target) = match parent_end {
        Some(at) if !key[..at].contains(':') => (Some(&key[..at]), &key[at + 1..]),
        _ => (None, key),
    };
    let (name, range) = match split_name_ref(target) {
        Some((name, range)) => (name, Some(range)),
        None => (target, None),
    };
    Resolution {
        parent: parent.map(|parent| {
            split_name_ref(parent)
                .map_or(parent, |(name, _)| name)
                .to_owned()
        }),
        name: name.to_owned(),
        range: range.map(str::to_owned),
        value: value.to_owned(),
    }
}

/// The range the most specific matching resolution forces on `from`'s dependency `alias@range`.
fn forced_range<'r>(
    resolutions: &'r [Resolution],
    from: &str,
    alias: &str,
    range: &str,
) -> Option<&'r str> {
    let bare = |range: &str| range.strip_prefix("npm:").unwrap_or(range).to_owned();
    resolutions
        .iter()
        .filter(|resolution| {
            resolution.name == alias
                && resolution
                    .parent
                    .as_deref()
                    .is_none_or(|parent| parent == from)
                && resolution
                    .range
                    .as_deref()
                    .is_none_or(|wanted| bare(wanted) == bare(range))
        })
        .max_by_key(|resolution| (resolution.parent.is_some(), resolution.range.is_some()))
        .map(|resolution| resolution.value.as_str())
}

fn read_manifest(context: &Context, path: &Path) -> Option<JsonObject> {
    match serde_json::from_str::<JsonValue>(&(context.read)(path)?).ok()? {
        JsonValue::Object(manifest) => Some(manifest),
        _ => None,
    }
}

/// Optional edges, for the formats that mark edges rather than packages optional:
/// (from an importer, the importer's directory or the package's key, the alias).
type OptionalEdges = HashSet<(bool, String, String)>;

/// Marks as optional each package the importers reach only through optional edges, which is what
/// npm and pnpm record per package.
fn mark_optional(graph: &mut Graph, optional_edges: &OptionalEdges) {
    let required = reachable(graph, |from_importer, from, alias| {
        !optional_edges.contains(&(from_importer, from.to_owned(), alias.to_owned()))
    });
    let any = reachable(graph, |_, _, _| true);
    for (key, package) in graph.packages.iter_mut() {
        package.optional = any.contains(key) && !required.contains(key);
    }
}

/// The package keys the importers reach through the edges `follow` accepts.
fn reachable(graph: &Graph, follow: impl Fn(bool, &str, &str) -> bool) -> HashSet<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut stack: Vec<&str> = Vec::new();
    for (dir, importer) in &graph.importers {
        for (alias, dep) in &importer.dependencies {
            if let Dep::Package(key) = dep {
                if follow(true, dir, alias) {
                    stack.push(key);
                }
            }
        }
    }
    while let Some(key) = stack.pop() {
        if !seen.insert(key.to_owned()) {
            continue;
        }
        let Some(package) = graph.packages.get(key) else {
            continue;
        };
        for (alias, dep) in &package.dependencies {
            if let Dep::Package(next) = dep {
                if !seen.contains(next.as_str()) && follow(false, key, alias) {
                    stack.push(next);
                }
            }
        }
    }
    seen
}

/// Classifies a location npm or Yarn Classic resolved a package to: a git remote, a local path,
/// a tarball URL of a registry's shape, or any other tarball URL.
fn resolved_source(resolved: &str, name: &str, version: &str, integrity: Vec<Integrity>) -> Source {
    if looks_like_git(resolved) {
        return git_source(resolved);
    }
    if let Some(path) = resolved.strip_prefix("file:") {
        return local_source("", path);
    }
    if is_url(resolved) {
        return if is_registry_tarball(resolved, name, version) {
            Source::Registry {
                tarball: Some(resolved.to_owned()),
                integrity,
                archive_checksum: None,
            }
        } else {
            Source::RemoteTarball {
                url: resolved.to_owned(),
                integrity,
            }
        };
    }
    Source::Unsupported {
        reason: format!("is resolved to `{resolved}`, which is not a URL, git remote or path"),
    }
}

/// Whether `url` has the shape of a registry's tarball of `name` at `version`, as
/// [`registry_tarball_url`] builds it, with the scope's slash written plainly or escaped.
fn is_registry_tarball(url: &str, name: &str, version: &str) -> bool {
    let unscoped = name.rsplit('/').next().unwrap_or(name);
    let Some(head) = url.strip_suffix(format!("/-/{unscoped}-{version}.tgz").as_str()) else {
        return false;
    };
    [
        name.to_owned(),
        name.replacen('/', "%2f", 1),
        name.replacen('/', "%2F", 1),
    ]
    .iter()
    .any(|written| head.ends_with(format!("/{written}").as_str()))
}

fn is_url(spec: &str) -> bool {
    spec.starts_with("https://") || spec.starts_with("http://")
}

/// Whether a resolved location or version names a git repository.
fn looks_like_git(spec: &str) -> bool {
    [
        "git+",
        "git:",
        "git@",
        "ssh:",
        "github:",
        "gitlab:",
        "bitbucket:",
    ]
    .iter()
    .any(|prefix| spec.starts_with(prefix))
        || split_fragment(spec).0.ends_with(".git")
}

/// A git source from `repository#fragment`, where the fragment is a commit or, for Yarn Berry,
/// `commit=<sha>` among other parameters.
fn git_source(spec: &str) -> Source {
    let (repository, fragment) = split_fragment(spec);
    let commit = fragment.and_then(|fragment| {
        fragment
            .split('&')
            .find_map(|part| part.strip_prefix("commit="))
            .or_else(|| {
                fragment
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                    .then_some(fragment)
            })
    });
    Source::Git {
        repository: repository.to_owned(),
        commit: commit.map(str::to_owned),
    }
}

fn split_fragment(spec: &str) -> (&str, Option<&str>) {
    match spec.split_once('#') {
        Some((head, fragment)) => (head, Some(fragment).filter(|f| !f.is_empty())),
        None => (spec, None),
    }
}

fn is_archive(path: &str) -> bool {
    [".tgz", ".tar.gz", ".tar"]
        .iter()
        .any(|suffix| path.ends_with(suffix))
}

/// A `file:` source relative to the lock-relative directory `base`: a local directory, or a
/// local tarball, which is not supported.
fn local_source(base: &str, path: &str) -> Source {
    let path = join_relative(base, path);
    if is_archive(&path) {
        unsupported_archive(&path)
    } else {
        Source::Local { path }
    }
}

fn unsupported_archive(path: &str) -> Source {
    Source::Unsupported {
        reason: format!("is a local tarball ({path}), which is not supported"),
    }
}

/// Joins `path` onto the lock-relative directory `base` and normalizes the result to a
/// "/"-separated path relative to the lock's directory: "" for the directory itself, with `..`
/// only where the path leaves it. An absolute `path` is returned as written.
fn join_relative(base: &str, path: &str) -> String {
    if path.starts_with('/') {
        return path.to_owned();
    }
    let mut parts: Vec<&str> = Vec::new();
    for segment in base.split('/').chain(path.split('/')) {
        match segment {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

/// `dir` relative to `base`, "/"-separated, or `None` when it is not inside `base`.
fn relative_dir(base: &Path, dir: &Path) -> Option<String> {
    let relative = dir.strip_prefix(base).ok()?;
    let parts: Vec<String> = relative
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    Some(join_relative("", &parts.join("/")))
}

fn shown_dir(dir: &str) -> &str {
    if dir.is_empty() {
        "the lock's directory"
    } else {
        dir
    }
}

/// Splits `name@rest` at the `@` that ends the package name, which for a scoped name is the
/// second one: "@types/node@20.1.0" gives "@types/node" and "20.1.0".
fn split_name_ref(text: &str) -> Option<(&str, &str)> {
    let from = usize::from(text.starts_with('@'));
    let at = text[from..].find('@')? + from;
    (at > 0).then(|| (&text[..at], &text[at + 1..]))
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if let Some(byte) = text
                .get(index + 1..index + 3)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Decodes standard or URL-safe base64, with or without padding.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

fn json_str<'a>(entry: &'a JsonObject, key: &str) -> Option<&'a str> {
    entry.get(key).and_then(JsonValue::as_str)
}

fn flag(entry: &JsonObject, key: &str) -> bool {
    entry.get(key).and_then(JsonValue::as_bool).unwrap_or(false)
}

fn json_strings(value: Option<&JsonValue>) -> Vec<String> {
    match value {
        Some(JsonValue::Array(items)) => items
            .iter()
            .filter_map(JsonValue::as_str)
            .map(str::to_owned)
            .collect(),
        Some(JsonValue::String(text)) => vec![text.clone()],
        _ => Vec::new(),
    }
}

fn yaml_strings(value: Option<&Yaml>) -> Vec<String> {
    match value {
        Some(Yaml::Seq(items)) => items
            .iter()
            .filter_map(Yaml::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Yaml::Scalar(text)) => vec![text.clone()],
        _ => Vec::new(),
    }
}

fn is_true(value: Option<&Yaml>) -> bool {
    value.and_then(Yaml::as_str) == Some("true")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::repo_scan::Fixture;
    use sha2::{Digest, Sha256, Sha512};

    const SHA512_A: &str = "sha512-H0D8ktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ==";
    const SHA512_B: &str = "sha512-Umd2iCLuYk1I/OFexcp5y9YCy39MIVelFlVpkfIu+Me173sY0f9BxZNw77CFhlHUSpNsEbexRMSP4E3zxqPo2g==";
    const SHA256_A: &str = "sha256-ypeBEsobvcr6wjGzmiPcTaeG7/gUfE5yuYB3ha/uSLs=";
    const SHA1_A: &str = "sha1-hvfkN/qlp/zhXR3cuerq6jd2Z7g=";
    const SHA1_A_HEX: &str = "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8";
    const SHA1_B_HEX: &str = "e9d71f5ee7c92d6dc9e92ffdad17b8bd49418f98";
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn fill(text: &str) -> String {
        text.replace("{A}", SHA512_A)
            .replace("{B}", SHA512_B)
            .replace("{S256}", SHA256_A)
            .replace("{S1}", SHA1_A)
            .replace("{H1}", SHA1_A_HEX)
            .replace("{H2}", SHA1_B_HEX)
            .replace("{C}", COMMIT)
    }

    fn found(fixture: &Fixture, workspaces: &[(&str, &str)]) -> JsLock {
        let workspaces: Vec<(String, PathBuf)> = workspaces
            .iter()
            .map(|(name, dir)| ((*name).to_owned(), fixture.root.join(dir)))
            .collect();
        match find_lock(&fixture.root, &workspaces) {
            LockSearch::Found(lock) => lock,
            other => panic!("expected a lock, got {other:?}"),
        }
    }

    fn package(key: &str) -> Dep {
        Dep::Package(key.to_owned())
    }

    fn link(dir: &str) -> Dep {
        Dep::Link(dir.to_owned())
    }

    fn edges<'a>(lock: &'a JsLock, importer: &str) -> &'a BTreeMap<String, Dep> {
        &lock
            .importers
            .get(importer)
            .unwrap_or_else(|| panic!("no importer {importer:?}"))
            .dependencies
    }

    fn locked<'a>(lock: &'a JsLock, key: &str) -> &'a LockedPackage {
        lock.packages
            .get(key)
            .unwrap_or_else(|| panic!("no package {key:?} in {:?}", lock.packages.keys()))
    }

    fn sha1(hex: &str) -> Integrity {
        Integrity {
            algorithm: Algorithm::Sha1,
            digest: hex_decode(hex).unwrap(),
        }
    }

    fn sha512(input: &[u8]) -> Integrity {
        Integrity {
            algorithm: Algorithm::Sha512,
            digest: Sha512::digest(input).to_vec(),
        }
    }

    fn registry(tarball: Option<&str>, integrity: Vec<Integrity>) -> Source {
        Source::Registry {
            tarball: tarball.map(str::to_owned),
            integrity,
            archive_checksum: None,
        }
    }

    fn missing_count(lock: &JsLock) -> usize {
        lock.importers
            .values()
            .flat_map(|importer| importer.dependencies.values())
            .chain(
                lock.packages
                    .values()
                    .flat_map(|package| package.dependencies.values()),
            )
            .filter(|dep| matches!(dep, Dep::Missing(_)))
            .count()
    }

    #[test]
    fn sri_lists_keep_known_algorithms_and_drop_options_and_the_rest() {
        let parsed = parse_sri(&format!(
            "{SHA512_A}?opt=1 md5-abc {SHA256_A}  {SHA1_A} sha512-tooShort== sha384-!!!"
        ));
        assert_eq!(
            parsed,
            vec![
                sha512(b"a"),
                Integrity {
                    algorithm: Algorithm::Sha256,
                    digest: Sha256::digest(b"a").to_vec(),
                },
                sha1(SHA1_A_HEX),
            ]
        );
        assert!(parse_sri("").is_empty());
        let unpadded = SHA512_A.trim_end_matches('=');
        assert_eq!(parse_sri(unpadded), vec![sha512(b"a")]);
    }

    #[test]
    fn registry_tarball_urls_keep_the_scope_in_the_path() {
        assert_eq!(
            registry_tarball_url("https://registry.npmjs.org/", "lodash", "4.17.21"),
            "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
        );
        assert_eq!(
            registry_tarball_url("https://registry.npmjs.org", "@babel/core", "7.0.0"),
            "https://registry.npmjs.org/@babel/core/-/core-7.0.0.tgz"
        );
        assert!(is_registry_tarball(
            "https://registry.yarnpkg.com/@babel/core/-/core-7.0.0.tgz",
            "@babel/core",
            "7.0.0"
        ));
        assert!(!is_registry_tarball(
            "https://example.com/core.tgz",
            "@babel/core",
            "7.0.0"
        ));
    }

    const NPM_V3: &str = r#"{
  "name": "root",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "root",
      "workspaces": ["packages/*"],
      "dependencies": { "a": "^1.0.0", "@x/ws": "*", "sw-cjs": "npm:string-width@^4", "bund": "1.0.0",
                        "g": "github:x/g", "m": "1.0.0", "p": "1.0.0" },
      "devDependencies": { "t": "https://example.com/t.tgz", "c": "1.0.0" },
      "optionalDependencies": { "plat": "1.0.0", "gone": "1.0.0" }
    },
    "packages/ws": { "name": "@x/ws", "version": "0.1.0", "dependencies": { "a": "^2.0.0", "c": "1.0.0" } },
    "packages/ws/node_modules/a": {
      "version": "2.0.0", "resolved": "https://registry.npmjs.org/a/-/a-2.0.0.tgz", "integrity": "{B}"
    },
    "node_modules/@x/ws": { "resolved": "packages/ws", "link": true },
    "node_modules/a": {
      "version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": "{A} {S1}",
      "dependencies": { "b": "^2.0.0" }
    },
    "node_modules/a/node_modules/b": {
      "version": "2.0.0", "resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz", "integrity": "{B}"
    },
    "node_modules/b": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz", "integrity": "{A}" },
    "node_modules/c": {
      "version": "1.0.0", "dev": true, "resolved": "https://registry.npmjs.org/c/-/c-1.0.0.tgz",
      "dependencies": { "b": "^1.0.0" }
    },
    "node_modules/bund": {
      "version": "1.0.0", "resolved": "https://registry.npmjs.org/bund/-/bund-1.0.0.tgz",
      "bundleDependencies": ["inner"], "dependencies": { "inner": "1.0.0" }
    },
    "node_modules/bund/node_modules/inner": { "version": "1.0.0", "inBundle": true },
    "node_modules/g": { "version": "3.0.0", "resolved": "git+ssh://git@github.com/x/g.git#{C}" },
    "node_modules/t": { "version": "0.0.1", "resolved": "https://example.com/t.tgz", "integrity": "{S256}", "dev": true },
    "node_modules/sw-cjs": {
      "name": "string-width", "version": "4.2.3",
      "resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz"
    },
    "node_modules/plat": {
      "version": "1.0.0", "resolved": "https://registry.npmjs.org/plat/-/plat-1.0.0.tgz", "optional": true,
      "os": ["darwin", "!win32"], "cpu": ["arm64"], "libc": ["glibc"]
    },
    "node_modules/p": {
      "version": "1.0.0", "resolved": "https://registry.npmjs.org/p/-/p-1.0.0.tgz",
      "peerDependencies": { "a": "*", "absent": "*" },
      "peerDependenciesMeta": { "absent": { "optional": true } }
    },
    "node_modules/m": {
      "version": "1.0.0", "resolved": "https://registry.npmjs.org/m/-/m-1.0.0.tgz",
      "dependencies": { "nothere": "1" }
    }
  }
}"#;

    #[test]
    fn npm_v3_resolves_nested_copies_before_hoisted_ones_and_links_workspaces() {
        let fixture = Fixture::new("js-npm-v3");
        fixture.write("package-lock.json", &fill(NPM_V3));
        let lock = found(&fixture, &[]);
        assert_eq!(lock.format, LockFormat::NpmV3);
        assert_eq!(lock.format.describe(), "package-lock.json v3");
        assert_eq!(lock.file, fixture.root.join("package-lock.json"));
        assert_eq!(
            lock.importers.keys().collect::<Vec<_>>(),
            vec!["", "packages/ws"]
        );

        let root = edges(&lock, "");
        assert_eq!(root["a"], package("node_modules/a"));
        assert_eq!(root["@x/ws"], link("packages/ws"));
        assert_eq!(root["sw-cjs"], package("node_modules/sw-cjs"));
        assert_eq!(root["t"], package("node_modules/t"));
        assert_eq!(root["plat"], package("node_modules/plat"));
        assert!(!root.contains_key("gone"), "an optional miss is left out");

        // The workspace sees its own nested copy of `a`, and the hoisted `c`.
        let workspace = edges(&lock, "packages/ws");
        assert_eq!(workspace["a"], package("packages/ws/node_modules/a"));
        assert_eq!(workspace["c"], package("node_modules/c"));

        // `a` reaches its nested `b` 2.0.0, while `c` reaches the hoisted `b` 1.0.0.
        assert_eq!(
            locked(&lock, "node_modules/a").dependencies["b"],
            package("node_modules/a/node_modules/b")
        );
        assert_eq!(
            locked(&lock, "node_modules/c").dependencies["b"],
            package("node_modules/b")
        );

        // A bundled dependency ships in its parent's tarball.
        assert!(locked(&lock, "node_modules/bund").dependencies.is_empty());
        assert!(!lock
            .packages
            .contains_key("node_modules/bund/node_modules/inner"));
        assert!(!lock.packages.contains_key("node_modules/@x/ws"));

        // A resolved peer is an edge; an optional peer the lock did not install is not.
        let peers = &locked(&lock, "node_modules/p").dependencies;
        assert_eq!(peers.get("a"), Some(&package("node_modules/a")));
        assert!(!peers.contains_key("absent"));
        assert!(matches!(
            locked(&lock, "node_modules/m").dependencies["nothere"],
            Dep::Missing(_)
        ));
        assert_eq!(missing_count(&lock), 1);

        let a = locked(&lock, "node_modules/a");
        assert_eq!(
            a.source,
            registry(
                Some("https://registry.npmjs.org/a/-/a-1.0.0.tgz"),
                vec![sha512(b"a"), sha1(SHA1_A_HEX)]
            )
        );
        let alias = locked(&lock, "node_modules/sw-cjs");
        assert_eq!(alias.name, "string-width");
        assert_eq!(alias.version, "4.2.3");
        assert!(matches!(
            alias.source,
            Source::Registry {
                tarball: Some(_),
                ..
            }
        ));
        assert_eq!(
            locked(&lock, "node_modules/g").source,
            Source::Git {
                repository: "git+ssh://git@github.com/x/g.git".into(),
                commit: Some(COMMIT.into()),
            }
        );
        assert!(matches!(
            &locked(&lock, "node_modules/t").source,
            Source::RemoteTarball { url, integrity }
                if url == "https://example.com/t.tgz" && integrity[0].algorithm == Algorithm::Sha256
        ));
        let plat = locked(&lock, "node_modules/plat");
        assert!(plat.optional);
        assert_eq!(plat.os, vec!["darwin", "!win32"]);
        assert_eq!(plat.cpu, vec!["arm64"]);
        assert_eq!(plat.libc, vec!["glibc"]);
        assert!(!a.optional);
    }

    #[test]
    fn npm_shrinkwrap_wins_over_package_lock() {
        let fixture = Fixture::new("js-shrinkwrap");
        fixture.write(
            "package-lock.json",
            r#"{"lockfileVersion": 3, "packages": {"": {}}}"#,
        );
        fixture.write(
            "npm-shrinkwrap.json",
            r#"{"lockfileVersion": 2, "packages": {"": {}}}"#,
        );
        let lock = found(&fixture, &[]);
        assert_eq!(lock.format, LockFormat::NpmV2);
        assert_eq!(lock.file, fixture.root.join("npm-shrinkwrap.json"));
        assert_eq!(
            lock.warnings,
            vec![
                "package-lock.json: is also present and was not read, since npm-shrinkwrap.json \
                 comes first"
            ]
        );
    }

    #[test]
    fn npm_v1_walks_the_nested_tree_and_reads_the_root_from_package_json() {
        let fixture = Fixture::new("js-npm-v1");
        fixture.write(
            "package.json",
            r#"{"dependencies": {"a": "^1", "sw": "npm:string-width@^4", "g": "x/g", "local": "file:libs/local",
                "bund": "1"}, "devDependencies": {"b": "^1"}, "optionalDependencies": {"gone": "1"}}"#,
        );
        fixture.write(
            "package-lock.json",
            &fill(
                r#"{
  "name": "old", "version": "1.0.0", "lockfileVersion": 1, "requires": true,
  "dependencies": {
    "a": {
      "version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": "{A}",
      "requires": { "b": "^2.0.0", "c": "^1.0.0" },
      "dependencies": {
        "b": { "version": "2.0.0", "resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz", "integrity": "{B}" }
      }
    },
    "b": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz", "dev": true },
    "c": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/c/-/c-1.0.0.tgz", "requires": { "absent": "1" } },
    "sw": { "version": "npm:string-width@4.2.3", "resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz" },
    "g": { "version": "git+https://github.com/x/g.git#{C}", "from": "git+https://github.com/x/g.git" },
    "local": { "version": "file:libs/local" },
    "bund": {
      "version": "1.0.0", "resolved": "https://registry.npmjs.org/bund/-/bund-1.0.0.tgz", "requires": { "inner": "1" },
      "dependencies": { "inner": { "version": "1.0.0", "bundled": true } }
    }
  }
}"#,
            ),
        );
        let lock = found(&fixture, &[]);
        assert_eq!(lock.format, LockFormat::NpmV1);
        let a = locked(&lock, "node_modules/a");
        assert_eq!(
            a.dependencies["b"],
            package("node_modules/a/node_modules/b")
        );
        assert_eq!(a.dependencies["c"], package("node_modules/c"));
        assert!(matches!(
            locked(&lock, "node_modules/c").dependencies["absent"],
            Dep::Missing(_)
        ));
        let sw = locked(&lock, "node_modules/sw");
        assert_eq!(
            (sw.name.as_str(), sw.version.as_str()),
            ("string-width", "4.2.3")
        );
        assert_eq!(
            locked(&lock, "node_modules/g").source,
            Source::Git {
                repository: "git+https://github.com/x/g.git".into(),
                commit: Some(COMMIT.into()),
            }
        );
        assert!(!lock.packages.contains_key("node_modules/local"));
        assert!(!lock
            .packages
            .contains_key("node_modules/bund/node_modules/inner"));
        assert!(locked(&lock, "node_modules/bund").dependencies.is_empty());

        let root = edges(&lock, "");
        assert_eq!(root["local"], link("libs/local"));
        assert_eq!(root["b"], package("node_modules/b"));
        assert_eq!(root["sw"], package("node_modules/sw"));
        assert!(!root.contains_key("gone"));
        assert_eq!(root.len(), 6);
    }

    const PNPM_V9: &str = "---
lockfileVersion: '9.0'

importers:

  .:
    configDependencies: {}
    packageManagerDependencies:
      pnpm:
        specifier: 12.4.2
        version: 12.4.2

packages:

  pnpm@12.4.2:
    resolution: {integrity: {A}}

snapshots:

  pnpm@12.4.2: {}

---
lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      a:
        specifier: ^1.0.0
        version: 1.0.0(peer@2.0.0)
      string-width-cjs:
        specifier: npm:string-width@^4.2.0
        version: string-width@4.2.3
      '@x/b':
        specifier: workspace:*
        version: link:packages/b
      local-dir:
        specifier: file:vendor/local-dir
        version: file:vendor/local-dir
    devDependencies:
      g:
        specifier: github:x/g
        version: https://codeload.github.com/x/g/tar.gz/{C}
      gitdep:
        specifier: git+https://github.com/x/gitdep.git
        version: git+https://github.com/x/gitdep.git#{C}
    optionalDependencies:
      plat:
        specifier: 1.0.0
        version: 1.0.0

  packages/b:
    dependencies:
      a:
        specifier: ^1.0.0
        version: 1.0.0(peer@2.0.0)
      sibling:
        specifier: link:../c
        version: link:../c

packages:

  a@1.0.0:
    resolution: {integrity: {A}}
    peerDependencies:
      peer: '*'

  peer@2.0.0:
    resolution: {integrity: {B}, tarball: https://custom.example/peer/-/peer-2.0.0.tgz}

  string-width@4.2.3:
    resolution: {integrity: {A}}
    engines: {node: '>=8'}

  local-dir@file:vendor/local-dir:
    resolution: {directory: vendor/local-dir, type: directory}

  g@https://codeload.github.com/x/g/tar.gz/{C}:
    resolution: {tarball: https://codeload.github.com/x/g/tar.gz/{C}}
    version: 3.0.0

  gitdep@git+https://github.com/x/gitdep.git#{C}:
    resolution: {commit: {C}, repo: https://github.com/x/gitdep.git, type: git}
    version: 0.5.0

  plat@1.0.0:
    resolution: {integrity: {B}}
    cpu: [arm64]
    os: [darwin]
    libc: [musl]

snapshots:

  a@1.0.0(peer@2.0.0):
    dependencies:
      peer: 2.0.0
      sw: string-width@4.2.3

  peer@2.0.0: {}

  string-width@4.2.3: {}

  local-dir@file:vendor/local-dir:
    dependencies:
      a: 1.0.0(peer@2.0.0)

  g@https://codeload.github.com/x/g/tar.gz/{C}: {}

  gitdep@git+https://github.com/x/gitdep.git#{C}: {}

  plat@1.0.0:
    optional: true
";

    #[test]
    fn pnpm_v9_reads_the_project_document_with_aliases_peers_links_and_sources() {
        let fixture = Fixture::new("js-pnpm-v9");
        fixture.write("pnpm-lock.yaml", &fill(PNPM_V9));
        let lock = found(&fixture, &[]);
        assert_eq!(
            lock.format,
            LockFormat::Pnpm {
                version: "9.0".into()
            }
        );
        assert_eq!(lock.format.describe(), "pnpm-lock.yaml v9.0");
        assert!(!lock.packages.contains_key("pnpm@12.4.2"));
        assert_eq!(
            lock.importers.keys().collect::<Vec<_>>(),
            vec!["", "packages/b"]
        );

        let root = edges(&lock, "");
        let peered = "a@1.0.0(peer@2.0.0)";
        assert_eq!(root["a"], package(peered));
        assert_eq!(root["string-width-cjs"], package("string-width@4.2.3"));
        assert_eq!(root["@x/b"], link("packages/b"));
        assert_eq!(
            root["local-dir"],
            package("local-dir@file:vendor/local-dir")
        );
        assert_eq!(
            root["g"],
            package(&fill("g@https://codeload.github.com/x/g/tar.gz/{C}"))
        );
        assert_eq!(root["plat"], package("plat@1.0.0"));
        assert_eq!(edges(&lock, "packages/b")["sibling"], link("packages/c"));
        assert_eq!(missing_count(&lock), 0);

        let a = locked(&lock, peered);
        assert_eq!((a.name.as_str(), a.version.as_str()), ("a", "1.0.0"));
        assert_eq!(a.dependencies["peer"], package("peer@2.0.0"));
        assert_eq!(a.dependencies["sw"], package("string-width@4.2.3"));
        assert_eq!(a.source, registry(None, vec![sha512(b"a")]));
        assert_eq!(
            locked(&lock, "peer@2.0.0").source,
            registry(
                Some("https://custom.example/peer/-/peer-2.0.0.tgz"),
                vec![sha512(b"b")]
            )
        );
        let local = locked(&lock, "local-dir@file:vendor/local-dir");
        assert_eq!(local.name, "local-dir");
        assert_eq!(
            local.source,
            Source::Local {
                path: "vendor/local-dir".into()
            }
        );
        let tarball = locked(&lock, &fill("g@https://codeload.github.com/x/g/tar.gz/{C}"));
        assert_eq!(tarball.version, "3.0.0");
        assert_eq!(
            tarball.source,
            Source::RemoteTarball {
                url: fill("https://codeload.github.com/x/g/tar.gz/{C}"),
                integrity: vec![],
            }
        );
        assert_eq!(
            locked(
                &lock,
                &fill("gitdep@git+https://github.com/x/gitdep.git#{C}")
            )
            .source,
            Source::Git {
                repository: "https://github.com/x/gitdep.git".into(),
                commit: Some(COMMIT.into()),
            }
        );
        let plat = locked(&lock, "plat@1.0.0");
        assert!(plat.optional);
        assert_eq!(
            (&plat.os, &plat.cpu, &plat.libc),
            (
                &vec!["darwin".to_owned()],
                &vec!["arm64".to_owned()],
                &vec!["musl".to_owned()]
            )
        );
        assert!(!a.optional);
    }

    #[test]
    fn pnpm_v6_keys_carry_a_slash_and_peer_parentheses() {
        let fixture = Fixture::new("js-pnpm-v6");
        fixture.write(
            "pnpm-lock.yaml",
            &fill(
                "lockfileVersion: '6.0'

dependencies:
  a:
    specifier: ^1.0.0
    version: 1.0.0(peer@2.0.0)
  sw:
    specifier: npm:string-width@^4
    version: /string-width@4.2.3

devDependencies:
  g:
    specifier: github:x/g
    version: github.com/x/g/{C}

packages:

  /a@1.0.0(peer@2.0.0):
    resolution: {integrity: {A}}
    peerDependencies:
      peer: '*'
    dependencies:
      peer: 2.0.0
    dev: false

  /peer@2.0.0:
    resolution: {integrity: {A}}
    dev: false

  /string-width@4.2.3:
    resolution: {integrity: {A}}
    dev: false

  /chokidar@3.6.0(patch_hash=abc):
    resolution: {integrity: {A}}
    patched: true
    dev: true

  github.com/x/g/{C}:
    resolution: {tarball: https://codeload.github.com/x/g/tar.gz/{C}}
    name: g
    version: 3.0.0
    dev: true
",
            ),
        );
        let lock = found(&fixture, &[]);
        let root = edges(&lock, "");
        assert_eq!(root["a"], package("a@1.0.0(peer@2.0.0)"));
        assert_eq!(root["sw"], package("string-width@4.2.3"));
        assert_eq!(root["g"], package(&fill("github.com/x/g/{C}")));
        assert_eq!(
            locked(&lock, "a@1.0.0(peer@2.0.0)").dependencies["peer"],
            package("peer@2.0.0")
        );
        let g = locked(&lock, &fill("github.com/x/g/{C}"));
        assert_eq!((g.name.as_str(), g.version.as_str()), ("g", "3.0.0"));
        assert!(matches!(g.source, Source::RemoteTarball { .. }));
        assert_eq!(
            locked(&lock, "chokidar@3.6.0(patch_hash=abc)").version,
            "3.6.0"
        );
        assert!(lock
            .warnings
            .iter()
            .any(|warning| warning.contains("chokidar@3.6.0(patch_hash=abc)")));
        assert_eq!(missing_count(&lock), 0);
    }

    #[test]
    fn pnpm_v5_keys_split_name_and_version_with_slashes_and_peers_with_underscores() {
        let fixture = Fixture::new("js-pnpm-v5");
        fixture.write(
            "pnpm-lock.yaml",
            &fill(
                "lockfileVersion: 5.4

importers:

  .:
    specifiers:
      a: ^1.0.0
      '@s/b': ^1.0.0
      w: workspace:*
    dependencies:
      a: 1.0.0_peer@2.0.0
      '@s/b': 1.0.0
      w: link:packages/w
      sw: /string-width/4.2.3

  packages/w:
    specifiers:
      a: ^1.0.0
    dependencies:
      a: 1.0.0_peer@2.0.0

packages:

  /a/1.0.0_peer@2.0.0:
    resolution: {integrity: {A}}
    dependencies:
      peer: 2.0.0
    dev: false

  /peer/2.0.0:
    resolution: {integrity: {A}}
    dev: false

  /@s/b/1.0.0:
    resolution: {integrity: {A}}
    dependencies:
      sw: /string-width/4.2.3
    dev: false
    optional: true
    os: [linux]

  /string-width/4.2.3:
    resolution: {integrity: {A}}
",
            ),
        );
        let lock = found(&fixture, &[]);
        assert_eq!(lock.format.describe(), "pnpm-lock.yaml v5.4");
        let root = edges(&lock, "");
        assert_eq!(root["a"], package("a@1.0.0_peer@2.0.0"));
        assert_eq!(root["@s/b"], package("@s/b@1.0.0"));
        assert_eq!(root["w"], link("packages/w"));
        assert_eq!(root["sw"], package("string-width@4.2.3"));
        assert_eq!(
            edges(&lock, "packages/w")["a"],
            package("a@1.0.0_peer@2.0.0")
        );
        let a = locked(&lock, "a@1.0.0_peer@2.0.0");
        assert_eq!((a.name.as_str(), a.version.as_str()), ("a", "1.0.0"));
        assert_eq!(a.dependencies["peer"], package("peer@2.0.0"));
        let b = locked(&lock, "@s/b@1.0.0");
        assert_eq!((b.name.as_str(), b.version.as_str()), ("@s/b", "1.0.0"));
        assert_eq!(b.dependencies["sw"], package("string-width@4.2.3"));
        assert!(b.optional);
        assert_eq!(b.os, vec!["linux"]);
        assert_eq!(missing_count(&lock), 0);
    }

    const YARN_CLASSIC: &str = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/x@^7.0.0", "@babel/x@^7.1.0":
  version "7.2.0"
  resolved "https://registry.yarnpkg.com/@babel/x/-/x-7.2.0.tgz#{H1}"
  dependencies:
    js-tokens "^4.0.0"
  optionalDependencies:
    fsevents "~2.3.2"

js-tokens@^4.0.0:
  version "4.0.0"
  resolved "https://registry.yarnpkg.com/js-tokens/-/js-tokens-4.0.0.tgz#{H2}"
  integrity {A}

fsevents@~2.3.2:
  version "2.3.3"
  resolved "https://registry.yarnpkg.com/fsevents/-/fsevents-2.3.3.tgz#{H2}"

"string-width-cjs@npm:string-width@^4.2.0", string-width@^4.2.0:
  version "4.2.3"
  resolved "https://registry.yarnpkg.com/string-width/-/string-width-4.2.3.tgz#{H1}"
  dependencies:
    "@x/lib" "*"

"g@git+https://github.com/x/g.git#main":
  version "3.0.0"
  resolved "git+https://github.com/x/g.git#{C}"

"t@https://example.com/t-1.0.0.tgz":
  version "1.0.0"
  resolved "https://example.com/t-1.0.0.tgz#{H2}"
"#;

    #[test]
    fn yarn_classic_resolves_descriptors_and_takes_importers_from_manifests() {
        let fixture = Fixture::new("js-yarn-classic");
        fixture.write("yarn.lock", &fill(YARN_CLASSIC));
        fixture.write(
            "package.json",
            r#"{"name": "root", "workspaces": ["packages/*"],
                "dependencies": {"@babel/x": "^7.0.0", "string-width-cjs": "npm:string-width@^4.2.0",
                  "g": "git+https://github.com/x/g.git#main", "@x/lib": "^1.0.0", "l": "link:./vendor/l"},
                "devDependencies": {"t": "https://example.com/t-1.0.0.tgz"},
                "optionalDependencies": {"nope": "1.0.0"}}"#,
        );
        fixture.write(
            "packages/lib/package.json",
            r#"{"name": "@x/lib", "dependencies": {"js-tokens": "^4.0.0", "string-width": "^4.2.0"}}"#,
        );
        let lock = found(&fixture, &[("@x/lib", "packages/lib")]);
        assert_eq!(lock.format, LockFormat::YarnClassic);
        assert_eq!(lock.format.describe(), "yarn.lock v1 (Yarn Classic)");
        assert_eq!(
            lock.packages.keys().collect::<Vec<_>>(),
            vec![
                "@babel/x@7.2.0",
                "fsevents@2.3.3",
                "g@3.0.0",
                "js-tokens@4.0.0",
                "string-width@4.2.3",
                "t@1.0.0",
            ]
        );

        let root = edges(&lock, "");
        assert_eq!(root["@babel/x"], package("@babel/x@7.2.0"));
        assert_eq!(root["string-width-cjs"], package("string-width@4.2.3"));
        assert_eq!(root["g"], package("g@3.0.0"));
        assert_eq!(root["@x/lib"], link("packages/lib"));
        assert_eq!(root["l"], link("vendor/l"));
        assert_eq!(root["t"], package("t@1.0.0"));
        assert!(!root.contains_key("nope"));
        let lib = edges(&lock, "packages/lib");
        assert_eq!(lib["js-tokens"], package("js-tokens@4.0.0"));
        assert_eq!(lib["string-width"], package("string-width@4.2.3"));
        assert_eq!(missing_count(&lock), 0);

        let babel = locked(&lock, "@babel/x@7.2.0");
        assert_eq!(
            babel.source,
            registry(
                Some("https://registry.yarnpkg.com/@babel/x/-/x-7.2.0.tgz"),
                vec![sha1(SHA1_A_HEX)]
            )
        );
        assert_eq!(babel.dependencies["js-tokens"], package("js-tokens@4.0.0"));
        assert_eq!(babel.dependencies["fsevents"], package("fsevents@2.3.3"));
        assert!(!babel.optional);
        assert!(locked(&lock, "fsevents@2.3.3").optional);
        assert_eq!(
            locked(&lock, "js-tokens@4.0.0").source,
            registry(
                Some("https://registry.yarnpkg.com/js-tokens/-/js-tokens-4.0.0.tgz"),
                vec![sha512(b"a")]
            )
        );
        let alias = locked(&lock, "string-width@4.2.3");
        assert_eq!(alias.name, "string-width");
        assert_eq!(alias.dependencies["@x/lib"], link("packages/lib"));
        assert_eq!(
            locked(&lock, "g@3.0.0").source,
            Source::Git {
                repository: "git+https://github.com/x/g.git".into(),
                commit: Some(COMMIT.into()),
            }
        );
        assert_eq!(
            locked(&lock, "t@1.0.0").source,
            Source::RemoteTarball {
                url: "https://example.com/t-1.0.0.tgz".into(),
                integrity: vec![sha1(SHA1_B_HEX)],
            }
        );
    }

    #[test]
    fn yarn_classic_warns_about_a_workspace_manifest_it_cannot_read() {
        let fixture = Fixture::new("js-yarn-classic-missing");
        fixture.write("yarn.lock", "# yarn lockfile v1\n\n");
        fixture.write("package.json", "{}");
        let lock = found(&fixture, &[("@x/gone", "packages/gone")]);
        assert!(edges(&lock, "packages/gone").is_empty());
        assert_eq!(
            lock.warnings,
            vec![
                "packages/gone/package.json: cannot be read, so the importer at packages/gone \
                 has no dependencies"
            ]
        );
    }

    const YARN_BERRY: &str = r#"# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"@native/darwin@npm:1.0.0":
  version: 1.0.0
  resolution: "@native/darwin@npm:1.0.0"
  conditions: (os=darwin | os=linux) & (cpu=arm64 | cpu=x64) & libc=glibc
  languageName: node
  linkType: hard

"@x/lib@workspace:*, @x/lib@workspace:packages/lib":
  version: 0.0.0-use.local
  resolution: "@x/lib@workspace:packages/lib"
  dependencies:
    lodash: "npm:^4.17.21"
    portal-dep: "portal:../../vendor/portal::locator=%40x%2Flib%40workspace%3Apackages%2Flib"
  languageName: unknown
  linkType: soft

"fsevents@npm:~2.3.3":
  version: 2.3.3
  resolution: "fsevents@npm:2.3.3"
  checksum: 10c0/a1
  conditions: os=darwin
  languageName: node
  linkType: hard

"fsevents@patch:fsevents@npm%3A~2.3.3#optional!builtin<compat/fsevents>":
  version: 2.3.3
  resolution: "fsevents@patch:fsevents@npm%3A2.3.3#optional!builtin<compat/fsevents>::version=2.3.3&hash=df0bf1"
  conditions: os=darwin
  languageName: node
  linkType: hard

"g@https://github.com/x/g.git#main":
  version: 3.0.0
  resolution: "g@https://github.com/x/g.git#commit={C}"
  languageName: node
  linkType: hard

"left-pad@patch:left-pad@npm%3A1.3.0#./patches/left-pad.patch::locator=root%40workspace%3A.":
  version: 1.3.0
  resolution: "left-pad@patch:left-pad@npm%3A1.3.0#./patches/left-pad.patch::version=1.3.0&hash=abc&locator=root%40workspace%3A."
  checksum: 10c0/patched
  languageName: node
  linkType: hard

"loc@file:./vendor/loc::locator=root%40workspace%3A.":
  version: 0.1.0
  resolution: "loc@file:./vendor/loc#./vendor/loc::hash=123&locator=root%40workspace%3A."
  languageName: node
  linkType: hard

"lodash@npm:^4.17.21, lodash@npm:^4.17.4":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 10c0/d8
  languageName: node
  linkType: hard

"portal-dep@portal:../../vendor/portal::locator=%40x%2Flib%40workspace%3Apackages%2Flib":
  version: 0.0.0-use.local
  resolution: "portal-dep@portal:../../vendor/portal::locator=%40x%2Flib%40workspace%3Apackages%2Flib"
  dependencies:
    lodash: "npm:^4.17.4"
  languageName: node
  linkType: soft

"root@workspace:.":
  version: 0.0.0-use.local
  resolution: "root@workspace:."
  dependencies:
    "@native/darwin": "npm:1.0.0"
    "@x/lib": "workspace:*"
    fsevents: "patch:fsevents@npm%3A~2.3.3#optional!builtin<compat/fsevents>"
    g: "https://github.com/x/g.git#main"
    left-pad: "patch:left-pad@npm%3A1.3.0#./patches/left-pad.patch::locator=root%40workspace%3A."
    loc: "file:./vendor/loc::locator=root%40workspace%3A."
    string-width-cjs: "npm:string-width@^4.2.0"
    tb: "https://example.com/tb-1.0.0.tgz"
    uses-bare: "npm:1.0.0"
  dependenciesMeta:
    "@native/darwin@1.0.0":
      optional: true
    fsevents:
      optional: true
  languageName: unknown
  linkType: soft

"string-width-cjs@npm:string-width@^4.2.0":
  version: 4.2.3
  resolution: "string-width@npm:4.2.3"
  checksum: 10c0/sw
  languageName: node
  linkType: hard

"tb@https://example.com/tb-1.0.0.tgz":
  version: 1.0.0
  resolution: "tb@https://example.com/tb-1.0.0.tgz"
  languageName: node
  linkType: hard

"uses-bare@npm:1.0.0":
  version: 1.0.0
  resolution: "uses-bare@npm:1.0.0"
  dependencies:
    lodash: ^4.17.4
  languageName: node
  linkType: hard
"#;

    #[test]
    fn yarn_berry_resolves_descriptors_workspaces_patches_and_conditions() {
        let fixture = Fixture::new("js-yarn-berry");
        fixture.write("yarn.lock", &fill(YARN_BERRY));
        let lock = found(&fixture, &[]);
        assert_eq!(
            lock.format,
            LockFormat::YarnBerry {
                version: "8".into()
            }
        );
        assert_eq!(lock.format.describe(), "yarn.lock v8 (Yarn Berry)");
        assert_eq!(
            lock.importers.keys().collect::<Vec<_>>(),
            vec!["", "packages/lib", "vendor/portal"]
        );
        assert!(lock.packages.keys().all(|key| !key.contains("patch:")));

        let root = edges(&lock, "");
        assert_eq!(root["@x/lib"], link("packages/lib"));
        assert_eq!(root["fsevents"], package("fsevents@npm:2.3.3"));
        assert_eq!(
            root["g"],
            package(&fill("g@https://github.com/x/g.git#commit={C}"))
        );
        assert_eq!(root["left-pad"], package("left-pad@npm:1.3.0"));
        assert_eq!(
            root["loc"],
            package("loc@file:./vendor/loc#./vendor/loc::hash=123&locator=root%40workspace%3A.")
        );
        assert_eq!(root["string-width-cjs"], package("string-width@npm:4.2.3"));
        assert_eq!(root["tb"], package("tb@https://example.com/tb-1.0.0.tgz"));
        let lib = edges(&lock, "packages/lib");
        assert_eq!(lib["lodash"], package("lodash@npm:4.17.21"));
        assert_eq!(lib["portal-dep"], link("vendor/portal"));
        assert_eq!(
            edges(&lock, "vendor/portal")["lodash"],
            package("lodash@npm:4.17.21")
        );
        assert_eq!(
            locked(&lock, "uses-bare@npm:1.0.0").dependencies["lodash"],
            package("lodash@npm:4.17.21")
        );
        assert_eq!(missing_count(&lock), 0);

        let fsevents = locked(&lock, "fsevents@npm:2.3.3");
        assert_eq!(
            fsevents.source,
            Source::Registry {
                tarball: None,
                integrity: vec![],
                archive_checksum: Some("10c0/a1".into()),
            }
        );
        assert!(fsevents.optional);
        assert_eq!(fsevents.os, vec!["darwin"]);
        let native = locked(&lock, "@native/darwin@npm:1.0.0");
        assert!(native.optional);
        assert_eq!(native.os, vec!["darwin", "linux"]);
        assert_eq!(native.cpu, vec!["arm64", "x64"]);
        assert_eq!(native.libc, vec!["glibc"]);
        assert!(!locked(&lock, "lodash@npm:4.17.21").optional);
        assert_eq!(locked(&lock, "string-width@npm:4.2.3").name, "string-width");

        // A patched package without its original stands in for it, without the patched checksum.
        let left_pad = locked(&lock, "left-pad@npm:1.3.0");
        assert_eq!(
            (left_pad.name.as_str(), left_pad.version.as_str()),
            ("left-pad", "1.3.0")
        );
        assert_eq!(left_pad.source, registry(None, vec![]));
        assert!(lock
            .warnings
            .iter()
            .any(|warning| warning.contains("optional!builtin<compat/fsevents>")));
        assert!(lock
            .warnings
            .iter()
            .any(|warning| warning.contains("./patches/left-pad.patch")));

        assert_eq!(
            locked(&lock, &fill("g@https://github.com/x/g.git#commit={C}")).source,
            Source::Git {
                repository: "https://github.com/x/g.git".into(),
                commit: Some(COMMIT.into()),
            }
        );
        assert_eq!(
            locked(&lock, "tb@https://example.com/tb-1.0.0.tgz").source,
            Source::RemoteTarball {
                url: "https://example.com/tb-1.0.0.tgz".into(),
                integrity: vec![],
            }
        );
        assert_eq!(
            locked(
                &lock,
                "loc@file:./vendor/loc#./vendor/loc::hash=123&locator=root%40workspace%3A."
            )
            .source,
            Source::Local {
                path: "vendor/loc".into()
            }
        );
    }

    #[test]
    fn yarn_root_resolutions_resolve_descriptors_the_lock_lacks() {
        let berry = Fixture::new("js-berry-resolutions");
        berry.write(
            "package.json",
            r#"{"name": "root", "resolutions": {"js-yaml": "4.3.2", "cosmic/tar": "npm:7.5.22"}}"#,
        );
        berry.write(
            "yarn.lock",
            r#"__metadata:
  version: 10
  cacheKey: 10c0

"cosmic@npm:1.0.0":
  version: 1.0.0
  resolution: "cosmic@npm:1.0.0"
  dependencies:
    js-yaml: "npm:^4.1.0"
    tar: "npm:^7.0.0"

"js-yaml@npm:4.3.2":
  version: 4.3.2
  resolution: "js-yaml@npm:4.3.2"

"other@npm:1.0.0":
  version: 1.0.0
  resolution: "other@npm:1.0.0"
  dependencies:
    tar: "npm:^7.0.0"

"root@workspace:.":
  version: 0.0.0-use.local
  resolution: "root@workspace:."
  dependencies:
    cosmic: "npm:1.0.0"
    other: "npm:1.0.0"

"tar@npm:7.5.22":
  version: 7.5.22
  resolution: "tar@npm:7.5.22"
"#,
        );
        let lock = found(&berry, &[]);
        let cosmic = &locked(&lock, "cosmic@npm:1.0.0").dependencies;
        assert_eq!(cosmic["js-yaml"], package("js-yaml@npm:4.3.2"));
        assert_eq!(cosmic["tar"], package("tar@npm:7.5.22"));
        // `cosmic/tar` applies only below `cosmic`.
        assert!(matches!(
            locked(&lock, "other@npm:1.0.0").dependencies["tar"],
            Dep::Missing(_)
        ));

        let classic = Fixture::new("js-classic-resolutions");
        classic.write(
            "package.json",
            r#"{"name": "root", "dependencies": {"cosmic": "1.0.0"}, "resolutions": {"**/js-yaml": "4.3.2"}}"#,
        );
        classic.write(
            "yarn.lock",
            "# yarn lockfile v1\n\ncosmic@1.0.0:\n  version \"1.0.0\"\n  dependencies:\n    js-yaml \"^4.1.0\"\n\njs-yaml@4.3.2:\n  version \"4.3.2\"\n",
        );
        let lock = found(&classic, &[]);
        assert_eq!(
            locked(&lock, "cosmic@1.0.0").dependencies["js-yaml"],
            package("js-yaml@4.3.2")
        );
        assert_eq!(edges(&lock, "")["cosmic"], package("cosmic@1.0.0"));

        assert_eq!(
            parse_resolution("@s/p@1.0.0/@t/n", "1"),
            Resolution {
                parent: Some("@s/p".into()),
                name: "@t/n".into(),
                range: None,
                value: "1".into(),
            }
        );
        assert_eq!(
            parse_resolution("js-yaml@^4.1.0", "4.3.2").range.as_deref(),
            Some("^4.1.0")
        );
        assert_eq!(parse_resolution("@scope/name", "1").parent, None);
    }

    #[test]
    fn bun_and_broken_locks_are_unusable_and_no_lock_is_not_found() {
        let empty = Fixture::new("js-none");
        assert_eq!(find_lock(&empty.root, &[]), LockSearch::NotFound);

        let bun = Fixture::new("js-bun");
        bun.write("bun.lockb", "\u{0}binary");
        assert_eq!(
            find_lock(&bun.root, &[]),
            LockSearch::Unusable {
                reasons: vec!["bun.lockb: is Bun's lockfile, which is not supported".into()]
            }
        );

        let broken = Fixture::new("js-broken");
        broken.write(
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\nimporters: {a: 1\n",
        );
        broken.write("package-lock.json", "{ not json");
        let LockSearch::Unusable { reasons } = find_lock(&broken.root, &[]) else {
            panic!("expected unusable");
        };
        assert_eq!(reasons.len(), 2);
        assert!(
            reasons[0].starts_with("pnpm-lock.yaml: line 2:"),
            "{reasons:?}"
        );
        assert!(
            reasons[1].starts_with("package-lock.json: is not valid JSON"),
            "{reasons:?}"
        );

        let old = Fixture::new("js-old-pnpm");
        old.write("pnpm-lock.yaml", "lockfileVersion: 4.0\n");
        let LockSearch::Unusable { reasons } = find_lock(&old.root, &[]) else {
            panic!("expected unusable");
        };
        assert_eq!(
            reasons,
            vec!["pnpm-lock.yaml: has lockfileVersion 4.0, which is not supported"]
        );
    }

    #[test]
    fn a_broken_lock_falls_through_to_the_next_with_a_warning() {
        let fixture = Fixture::new("js-fallthrough");
        fixture.write(
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\nimporters: {a: 1\n",
        );
        fixture.write(
            "package-lock.json",
            r#"{"lockfileVersion": 3, "packages": {}}"#,
        );
        let lock = found(&fixture, &[]);
        assert_eq!(lock.format, LockFormat::NpmV3);
        assert!(lock.warnings[0].starts_with("pnpm-lock.yaml: line 2:"));
    }

    #[test]
    fn the_declared_package_manager_picks_among_several_locks() {
        let fixture = Fixture::new("js-manager");
        fixture.write("yarn.lock", "# yarn lockfile v1\n");
        fixture.write(
            "package-lock.json",
            r#"{"lockfileVersion": 3, "packages": {}}"#,
        );
        fixture.write("package.json", r#"{"packageManager": "npm@10.8.0"}"#);
        let lock = found(&fixture, &[]);
        assert_eq!(lock.format, LockFormat::NpmV3);
        assert_eq!(
            lock.warnings,
            vec![
                "yarn.lock: is also present and was not read, since package-lock.json comes first"
            ]
        );

        fixture.write("package.json", "{}");
        assert_eq!(found(&fixture, &[]).format, LockFormat::YarnClassic);
    }

    #[test]
    fn paths_join_and_normalize_relative_to_the_lock() {
        assert_eq!(join_relative("", "."), "");
        assert_eq!(join_relative("packages/a", "../b"), "packages/b");
        assert_eq!(
            join_relative("packages/a", "./vendor/./x/"),
            "packages/a/vendor/x"
        );
        assert_eq!(join_relative("", "../outside"), "../outside");
        assert_eq!(join_relative("a", "../../b"), "../b");
        assert_eq!(
            split_name_ref("@types/node@20.1.0"),
            Some(("@types/node", "20.1.0"))
        );
        assert_eq!(
            split_name_ref("lodash@npm:4.17.21"),
            Some(("lodash", "npm:4.17.21"))
        );
        assert_eq!(split_name_ref("@scope/name"), None);
        assert_eq!(
            without_peers("a@1.0.0(b@2.0.0(c@1.0.0))(d@1.0.0)"),
            "a@1.0.0"
        );
        assert_eq!(
            berry_unpatch("patch:typescript@npm%3A5.4.5#optional!builtin<compat/typescript>::version=5.4.5&hash=5adc0c"),
            ("typescript@npm:5.4.5".to_owned(), "optional!builtin<compat/typescript>".to_owned())
        );
    }
}
