// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Go analysis environments.
//!
//! A Go repository locks its dependencies in `go.sum`: an `h1:` hash for the
//! zip of every module that provides packages, and one for the `go.mod` of
//! every module in the graph. Kin fetches exactly those from the module proxy
//! the user's configuration names (`GOPROXY`, walked the way the `go` command
//! walks it, with `GOPRIVATE` and `GONOPROXY` modules never sent to a public
//! proxy), checks each against its hash before unpacking it, and keeps them in
//! a module cache under `KIN_HOME` that every repository shares, since a
//! module version is the same bytes in every `go.sum` that names it.
//!
//! gopls then runs with that cache as `GOMODCACHE`, `GOPROXY=off` so it never
//! fetches for itself, `GOTOOLCHAIN=local` so the `go` command never swaps
//! itself for a downloaded one, and `CGO_ENABLED=0` so loading a package never
//! invokes a C compiler. Nothing from the repository or a module runs.
//!
//! The environment is assessed without the network ([`assess`]) and fetched
//! with it ([`provision`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::adapters::contract::{EnvironmentIdentity, ProvisionReport};

use super::fetch::Fetcher;
use super::write_atomically;

pub mod modcache;
pub mod sumdb;
pub mod toolchain;

use toolchain::{GoVersion, InstalledGo, Requirement};

/// The Go store under Kin's cache.
pub fn store_dir(cache: &Path) -> PathBuf {
    super::store_root(cache).join("go")
}

/// The module cache in the store, shared by every repository.
pub fn modcache_dir(store: &Path) -> PathBuf {
    store.join("modcache")
}

/// The Go settings in force: the process environment over the `go env -w`
/// file, as the `go` command reads them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoEnv {
    values: HashMap<String, String>,
}

impl GoEnv {
    /// Read the settings of a host with these variables and this home.
    pub fn read(vars: &HashMap<String, String>, home: Option<&Path>) -> Self {
        let mut values = HashMap::new();
        if let Some(file) = env_file(vars, home) {
            if let Ok(text) = std::fs::read_to_string(file) {
                for line in text.lines() {
                    if let Some((key, value)) = line.split_once('=') {
                        let key = key.trim();
                        if !key.is_empty() && !key.starts_with('#') {
                            values.insert(key.to_string(), value.trim().to_string());
                        }
                    }
                }
            }
        }
        for (key, value) in vars {
            if key.starts_with("GO") || key == "CGO_ENABLED" {
                values.insert(key.clone(), value.clone());
            }
        }
        if let Some(home) = home {
            values
                .entry("HOME".to_string())
                .or_insert_with(|| home.display().to_string());
        }
        Self { values }
    }

    /// One setting, when set to something.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.trim().is_empty())
    }

    /// `GOPROXY`, with the `go` command's default.
    pub fn goproxy(&self) -> String {
        self.get("GOPROXY")
            .unwrap_or("https://proxy.golang.org,direct")
            .to_string()
    }

    /// The patterns of modules never fetched through a proxy.
    pub fn noproxy(&self) -> String {
        self.get("GONOPROXY")
            .or_else(|| self.get("GOPRIVATE"))
            .unwrap_or("")
            .to_string()
    }

    /// The patterns of modules never checked against the checksum database.
    pub fn nosumdb(&self) -> String {
        self.get("GONOSUMDB")
            .or_else(|| self.get("GOPRIVATE"))
            .unwrap_or("")
            .to_string()
    }

    /// `GOSUMDB`, with the `go` command's default. `GOFLAGS=-insecure` and
    /// `GONOSUMCHECK=1` turn it off, as they do for the `go` command.
    pub fn gosumdb(&self) -> String {
        if self.get("GONOSUMCHECK") == Some("1")
            || self
                .get("GOFLAGS")
                .is_some_and(|flags| flags.split_whitespace().any(|f| f == "-insecure"))
        {
            return "off".to_string();
        }
        self.get("GOSUMDB").unwrap_or("sum.golang.org").to_string()
    }

    /// `GOTOOLCHAIN`, with the `go` command's default.
    pub fn gotoolchain(&self) -> String {
        self.get("GOTOOLCHAIN").unwrap_or("auto").to_string()
    }

    /// The user's module cache: `GOMODCACHE`, else the first `GOPATH`
    /// entry's `pkg/mod`, else `~/go/pkg/mod`.
    pub fn modcache(&self) -> Option<PathBuf> {
        if let Some(dir) = self.get("GOMODCACHE") {
            return Some(PathBuf::from(dir));
        }
        let gopath = match self.get("GOPATH") {
            Some(list) => std::env::split_paths(list).next()?,
            None => PathBuf::from(self.get("HOME")?).join("go"),
        };
        Some(gopath.join("pkg/mod"))
    }
}

/// The file `go env -w` writes: `GOENV`, else the user configuration
/// directory's `go/env`.
fn env_file(vars: &HashMap<String, String>, home: Option<&Path>) -> Option<PathBuf> {
    match vars.get("GOENV").map(String::as_str) {
        Some("off") => return None,
        Some(file) if !file.is_empty() => return Some(PathBuf::from(file)),
        _ => {}
    }
    let home = home?;
    if cfg!(target_os = "macos") {
        return Some(home.join("Library/Application Support/go/env"));
    }
    if cfg!(windows) {
        return vars
            .get("AppData")
            .map(|dir| PathBuf::from(dir).join("go/env"));
    }
    let config = vars
        .get("XDG_CONFIG_HOME")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    Some(config.join("go/env"))
}

/// Whether a module path matches a comma-separated list of path globs, the
/// way `GOPRIVATE` is matched: a glob with N slashes matches the path's first
/// N+1 elements.
pub fn matches_prefix_patterns(globs: &str, target: &str) -> bool {
    globs.split(',').any(|glob| {
        let glob = glob.trim().trim_end_matches('/');
        if glob.is_empty() {
            return false;
        }
        let slashes = glob.matches('/').count();
        let elements: Vec<&str> = target.split('/').collect();
        if elements.len() <= slashes {
            return false;
        }
        let prefix = elements[..=slashes].join("/");
        glob_match(glob.as_bytes(), prefix.as_bytes())
    })
}

/// `path.Match`: `*` is any run of characters but `/`, `?` one of them.
fn glob_match(pattern: &[u8], name: &[u8]) -> bool {
    match (pattern.first(), name.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            glob_match(&pattern[1..], name)
                || (name.first().is_some_and(|c| *c != b'/') && glob_match(pattern, &name[1..]))
        }
        (Some(b'?'), Some(c)) if *c != b'/' => glob_match(&pattern[1..], &name[1..]),
        (Some(p), Some(n)) if p == n => glob_match(&pattern[1..], &name[1..]),
        _ => false,
    }
}

/// One hash `go.sum` records.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SumEntry {
    pub module: String,
    pub version: String,
    pub hash: String,
}

/// What a workspace's `go.sum` files lock, with the workspace's own modules
/// left out, since those resolve to the repository's source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sums {
    /// Modules whose zip is locked and that a build loads packages from.
    pub zips: Vec<SumEntry>,
    /// Modules whose zip is locked for what no build of the workspace loads,
    /// such as the tests of a dependency. Not fetched.
    pub unneeded_zips: usize,
    /// Needed modules no `go.sum` locks, which are never fetched.
    pub unlocked: Vec<String>,
    /// Modules whose `go.mod` is locked.
    pub mods: Vec<SumEntry>,
    /// Lines two files disagree on, each named; neither side is fetched.
    pub conflicts: Vec<String>,
    /// The files read.
    pub files: Vec<PathBuf>,
}

impl Sums {
    /// Read `files`, leaving out every module in `own`.
    pub fn read(files: &[PathBuf], own: &BTreeSet<String>) -> Self {
        type Map = BTreeMap<(String, String), Result<String, ()>>;
        let mut zips: Map = BTreeMap::new();
        let mut mods: Map = BTreeMap::new();
        let mut conflicts = Vec::new();
        let mut read = Vec::new();
        for file in files {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            read.push(file.clone());
            for line in text.lines() {
                let mut words = line.split_whitespace();
                let (Some(module), Some(version), Some(hash), None) =
                    (words.next(), words.next(), words.next(), words.next())
                else {
                    continue;
                };
                if !hash.starts_with("h1:") || own.contains(module) {
                    continue;
                }
                let (map, version, what) = match version.strip_suffix("/go.mod") {
                    Some(version) => (&mut mods, version, "/go.mod"),
                    None => (&mut zips, version, ""),
                };
                let key = (module.to_string(), version.to_string());
                match map.get(&key) {
                    Some(Ok(existing)) if existing != hash => {
                        conflicts.push(format!(
                            "{module} {version}{what}: go.sum files disagree ({existing} and \
                             {hash}), so neither is fetched"
                        ));
                        map.insert(key, Err(()));
                    }
                    Some(_) => {}
                    None => {
                        map.insert(key, Ok(hash.to_string()));
                    }
                }
            }
        }
        let entries = |map: Map| -> Vec<SumEntry> {
            map.into_iter()
                .filter_map(|((module, version), hash)| {
                    Some(SumEntry {
                        module,
                        version,
                        hash: hash.ok()?,
                    })
                })
                .collect()
        };
        Self {
            zips: entries(zips),
            unneeded_zips: 0,
            unlocked: Vec::new(),
            mods: entries(mods),
            conflicts,
            files: read,
        }
    }

    /// Keep only the zips in `needed`, and name the needed modules no
    /// `go.sum` locks.
    pub fn restrict(mut self, needed: Option<&BTreeSet<(String, String)>>) -> Self {
        let Some(needed) = needed else {
            return self;
        };
        let before = self.zips.len();
        self.zips
            .retain(|entry| needed.contains(&(entry.module.clone(), entry.version.clone())));
        self.unneeded_zips = before - self.zips.len();
        let locked: BTreeSet<(&str, &str)> = self
            .zips
            .iter()
            .map(|entry| (entry.module.as_str(), entry.version.as_str()))
            .collect();
        let conflicted: BTreeSet<&str> = self
            .conflicts
            .iter()
            .filter_map(|line| line.split_whitespace().next())
            .collect();
        self.unlocked = needed
            .iter()
            .filter(|(module, version)| {
                !locked.contains(&(module.as_str(), version.as_str()))
                    && !conflicted.contains(module.as_str())
            })
            .map(|(module, version)| {
                format!("{module} {version}: required, and no go.sum locks its zip")
            })
            .collect();
        self
    }

    pub fn is_empty(&self) -> bool {
        self.zips.is_empty() && self.mods.is_empty()
    }
}

/// What one `go.mod` declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoMod {
    pub module: Option<String>,
    pub go: Option<GoVersion>,
    /// Every `require`, as module path and version.
    pub requires: Vec<(String, String)>,
    /// Every `replace`: the module (and version, when one is named) replaced,
    /// and what replaces it: a module and version, or a directory.
    pub replaces: Vec<Replace>,
}

/// One `replace` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replace {
    pub module: String,
    pub version: Option<String>,
    pub with: Replacement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Replacement {
    Module { module: String, version: String },
    Directory(String),
}

impl GoMod {
    /// Read a `go.mod`'s `module`, `go`, `require` and `replace` lines, in
    /// their single-line and block forms.
    pub fn parse(text: &str) -> Self {
        let mut parsed = GoMod::default();
        let mut block: Option<&str> = None;
        for raw in text.lines() {
            let line = raw.split("//").next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if block.is_some() && line == ")" {
                block = None;
                continue;
            }
            let (verb, rest) = match block {
                Some(verb) => (verb, line),
                None => {
                    let (verb, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
                    let rest = rest.trim();
                    if rest == "(" {
                        block = Some(match verb {
                            "require" => "require",
                            "replace" => "replace",
                            _ => "other",
                        });
                        continue;
                    }
                    (verb, rest)
                }
            };
            let words: Vec<String> = rest
                .split_whitespace()
                .map(|word| word.trim_matches('"').to_string())
                .collect();
            match verb {
                "module" => parsed.module = words.first().cloned(),
                "go" => parsed.go = words.first().and_then(|v| GoVersion::parse(v)),
                "require" if words.len() >= 2 => {
                    parsed.requires.push((words[0].clone(), words[1].clone()));
                }
                "replace" => {
                    let Some(arrow) = words.iter().position(|word| word == "=>") else {
                        continue;
                    };
                    let (left, right) = words.split_at(arrow);
                    let right = &right[1..];
                    let (Some(module), Some(target)) = (left.first(), right.first()) else {
                        continue;
                    };
                    let with = match right.get(1) {
                        Some(version) => Replacement::Module {
                            module: target.clone(),
                            version: version.clone(),
                        },
                        None => Replacement::Directory(target.clone()),
                    };
                    parsed.replaces.push(Replace {
                        module: module.clone(),
                        version: left.get(1).cloned(),
                        with,
                    });
                }
                _ => {}
            }
        }
        parsed
    }

    /// What `require module version` resolves to after this file's replaces.
    fn resolve(&self, module: &str, version: &str) -> Option<Replacement> {
        self.replaces
            .iter()
            .filter(|replace| replace.module == module)
            .find(|replace| replace.version.as_deref().is_none_or(|v| v == version))
            .map(|replace| replace.with.clone())
    }
}

/// A repository's Go workspace, as its module files describe it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Workspace {
    /// The repository root.
    pub root: PathBuf,
    /// Every module's `go.mod`.
    pub mod_files: Vec<PathBuf>,
    /// Every module's path.
    pub own: BTreeSet<String>,
    /// The root `go.work`, when there is one.
    pub go_work: Option<PathBuf>,
    /// Modules whose dependencies are vendored in the repository.
    pub vendored: Vec<PathBuf>,
    /// Modules that require other modules.
    pub requires_anything: bool,
    /// The module versions a build of the workspace loads packages from, as
    /// `go mod download` counts them: every module a Go 1.17 or later
    /// `go.mod` requires, after its replaces. `None` when a module predates
    /// Go 1.17 and lists only its direct requirements, so every zip `go.sum`
    /// locks is needed.
    pub needed: Option<BTreeSet<(String, String)>>,
    /// Requirements replaced by a directory outside the repository, which no
    /// lock describes and Kin does not read.
    pub outside: Vec<String>,
}

impl Workspace {
    /// The workspace of modules `mod_files` under `root`.
    pub fn read(root: &Path, mod_files: &[PathBuf]) -> Self {
        let mut own = BTreeSet::new();
        let mut vendored = Vec::new();
        let mut parsed = Vec::new();
        for file in mod_files {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            let go_mod = GoMod::parse(&text);
            if let Some(path) = &go_mod.module {
                own.insert(path.clone());
            }
            if let Some(dir) = file.parent() {
                if dir.join("vendor/modules.txt").is_file() {
                    vendored.push(dir.to_path_buf());
                }
                parsed.push((dir.to_path_buf(), go_mod));
            }
        }
        let pruned = GoVersion::parse("1.17").unwrap_or_else(|| unreachable!());
        let mut needed = Some(BTreeSet::new());
        let mut outside = Vec::new();
        let mut requires_anything = false;
        for (dir, go_mod) in &parsed {
            requires_anything |= !go_mod.requires.is_empty();
            if go_mod.go.as_ref().is_none_or(|go| *go < pruned) && !go_mod.requires.is_empty() {
                needed = None;
            }
            for (module, version) in &go_mod.requires {
                if own.contains(module) {
                    continue;
                }
                match go_mod.resolve(module, version) {
                    None => {
                        if let Some(needed) = needed.as_mut() {
                            needed.insert((module.clone(), version.clone()));
                        }
                    }
                    Some(Replacement::Module { module, version }) => {
                        if let Some(needed) = needed.as_mut() {
                            needed.insert((module, version));
                        }
                    }
                    Some(Replacement::Directory(path)) => {
                        let target = dir.join(&path);
                        let inside = std::fs::canonicalize(&target)
                            .ok()
                            .zip(std::fs::canonicalize(root).ok())
                            .is_some_and(|(target, root)| target.starts_with(root));
                        if !inside {
                            outside.push(format!(
                                "{module} {version}: replaced by {path}, outside the repository"
                            ));
                        }
                    }
                }
            }
        }
        let go_work = Some(root.join("go.work")).filter(|file| file.is_file());
        Self {
            root: root.to_path_buf(),
            mod_files: mod_files.to_vec(),
            own,
            go_work,
            vendored,
            requires_anything,
            needed,
            outside,
        }
    }

    /// Whether Kin keeps a `go.work` of its own for this workspace: the
    /// repository has none, vendors nothing, and holds more than one module,
    /// so without one a module that requires another by version would read
    /// that one from the module cache rather than from the repository.
    pub fn wants_kin_go_work(&self) -> bool {
        self.go_work.is_none() && self.vendored.is_empty() && self.mod_files.len() > 1
    }

    /// The `go.sum` files the workspace locks with: each module's, and the
    /// workspace's own `go.work.sum`.
    pub fn sum_files(&self) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = self
            .mod_files
            .iter()
            .filter_map(|file| file.parent().map(|dir| dir.join("go.sum")))
            .collect();
        if let Some(work) = &self.go_work {
            files.push(work.with_file_name("go.work.sum"));
        }
        files.retain(|file| file.is_file());
        files
    }
}

/// Where Kin keeps the `go.work` it writes for the repository at `root`.
pub fn kin_go_work(store: &Path, root: &Path) -> PathBuf {
    let digest = sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(
        root.to_string_lossy().as_bytes(),
    ));
    store
        .join("workspaces")
        .join(&crate::adapters::contract::hex(&digest)[..16])
        .join("go.work")
}

/// Write Kin's `go.work` for `workspace`, outside the repository: every
/// module the repository holds, outside `testdata` and directories the go
/// command ignores, at the newest `go` line among them. `sums` are `go.sum`
/// lines the checksum database proved for required modules no `go.sum`
/// locks; they go in the `go.work.sum` beside it, which the go command reads
/// in workspace mode. The file is rewritten only when it changes.
pub fn write_kin_go_work(
    store: &Path,
    workspace: &Workspace,
    minimum: Option<&GoVersion>,
    sums: Option<&[String]>,
) -> Result<PathBuf, String> {
    let file = kin_go_work(store, &workspace.root);
    let mut text =
        String::from("// Written by Kin: the repository's modules, resolved from its source.\n");
    if let Some(minimum) = minimum {
        text.push_str(&format!("go {minimum}\n"));
    }
    text.push_str("\nuse (\n");
    for module in &workspace.mod_files {
        let Some(dir) = module.parent() else {
            continue;
        };
        let ignored = dir
            .strip_prefix(&workspace.root)
            .map(|relative| {
                relative.components().any(|part| {
                    let part = part.as_os_str().to_string_lossy();
                    part.starts_with(['_', '.']) || part == "testdata"
                })
            })
            .unwrap_or(true);
        if !ignored {
            text.push_str(&format!("\t{}\n", dir.display()));
        }
    }
    text.push_str(")\n");
    if std::fs::read_to_string(&file).ok().as_deref() != Some(text.as_str()) {
        write_atomically(&file, text.as_bytes())?;
    }
    if let Some(sums) = sums {
        let mut lines = sums.to_vec();
        lines.sort();
        lines.dedup();
        let body = lines.join("\n") + if lines.is_empty() { "" } else { "\n" };
        write_atomically(&file.with_file_name("go.work.sum"), body.as_bytes())?;
    }
    Ok(file)
}

/// The toolchain an environment loads packages with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolchainChoice {
    /// The installed Go, which is at least the `go` line.
    Installed(InstalledGo),
    /// The release the repository pins, already in Kin's store.
    Stored(InstalledGo),
    /// The release the repository pins, to be fetched.
    Fetch(GoVersion),
    /// None can serve, with the reason.
    Missing(String),
}

impl ToolchainChoice {
    pub fn installation(&self) -> Option<&InstalledGo> {
        match self {
            ToolchainChoice::Installed(go) | ToolchainChoice::Stored(go) => Some(go),
            _ => None,
        }
    }
}

/// What the environment step reads from the host.
#[derive(Debug, Clone)]
pub struct Host<'a> {
    pub env: &'a GoEnv,
    /// Kin's cache directory, `$KIN_HOME/cache`.
    pub cache: &'a Path,
    /// The Go installation on `PATH`, when there is one.
    pub installed: Option<&'a InstalledGo>,
    /// Whether Kin may fetch a toolchain or modules.
    pub analysis_environments: bool,
}

impl Host<'_> {
    pub fn store(&self) -> PathBuf {
        store_dir(self.cache)
    }
}

/// Choose the toolchain for `requirement`: the installed Go when it is new
/// enough, else the pinned release from Kin's store or go.dev.
pub fn choose_toolchain(requirement: Option<&Requirement>, host: &Host<'_>) -> ToolchainChoice {
    let Some(requirement) = requirement else {
        return match host.installed {
            Some(go) => ToolchainChoice::Installed(go.clone()),
            None => ToolchainChoice::Missing(
                "no Go is installed and no go.mod names a version".to_string(),
            ),
        };
    };
    if let Some(go) = host
        .installed
        .filter(|go| go.version >= requirement.minimum)
    {
        return ToolchainChoice::Installed(go.clone());
    }
    let release = requirement.release();
    if let Some(go) = toolchain::stored(&host.store(), &release) {
        return ToolchainChoice::Stored(go);
    }
    let installed = host.installed.map_or_else(
        || "no Go is installed".to_string(),
        |go| format!("the installed Go is {}", go.version),
    );
    if host.env.gotoolchain() == "local" {
        return ToolchainChoice::Missing(format!(
            "{} needs Go {}, {installed}, and GOTOOLCHAIN=local keeps it",
            requirement.pinned_by, requirement.minimum
        ));
    }
    if !host.analysis_environments {
        return ToolchainChoice::Missing(format!(
            "{} needs Go {}, {installed}, and analysis environments are off",
            requirement.pinned_by, requirement.minimum
        ));
    }
    ToolchainChoice::Fetch(release)
}

/// Why the user's module cache cannot serve the lock, or `Ok` when it holds
/// every locked module and `go.mod`.
pub fn check_modcache(modcache: &Path, sums: &Sums) -> Result<(), String> {
    let missing_zip = sums
        .zips
        .iter()
        .filter(|entry| !modcache::has_module(modcache, &entry.module, &entry.version, &entry.hash))
        .count();
    // A build reads the go.mod of every module it loads packages from; the
    // other go.mod files go.sum locks are read only by `go mod tidy`.
    let loaded: BTreeSet<(&str, &str)> = sums
        .zips
        .iter()
        .map(|entry| (entry.module.as_str(), entry.version.as_str()))
        .collect();
    let mods: Vec<&SumEntry> = sums
        .mods
        .iter()
        .filter(|entry| loaded.contains(&(entry.module.as_str(), entry.version.as_str())))
        .collect();
    let missing_mod = mods
        .iter()
        .filter(|entry| !modcache::has_go_mod(modcache, &entry.module, &entry.version, &entry.hash))
        .count();
    if missing_zip == 0 && missing_mod == 0 {
        return Ok(());
    }
    Err(format!(
        "{} lacks {missing_zip} of {} locked module(s) and {missing_mod} of their {} go.mod \
         file(s)",
        modcache.display(),
        sums.zips.len(),
        mods.len()
    ))
}

/// The identity of an environment: the toolchain release and every locked
/// hash.
pub fn identity(toolchain: &str, sums: &Sums) -> EnvironmentIdentity {
    let mut parts = vec!["go".to_string(), toolchain.to_string()];
    for entry in &sums.zips {
        parts.push(format!("{} {} {}", entry.module, entry.version, entry.hash));
    }
    for entry in &sums.mods {
        parts.push(format!(
            "{} {}/go.mod {}",
            entry.module, entry.version, entry.hash
        ));
    }
    let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
    EnvironmentIdentity::of(&parts)
}

/// Where a workspace's dependencies come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dependencies {
    /// No module requires anything.
    None,
    /// Every module vendors its dependencies in the repository.
    Vendored,
    /// The user's module cache holds everything `go.sum` locks.
    UserCache(PathBuf),
    /// Kin's module cache, complete or not.
    KinCache { ready: bool },
    /// None that the repository chose can be had.
    Missing(String),
}

/// What is known about a workspace's environment without the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub requirement: Option<Requirement>,
    pub toolchain: ToolchainChoice,
    pub sums: Sums,
    pub dependencies: Dependencies,
    pub identity: EnvironmentIdentity,
    /// Why the user's module cache was passed over, when it was.
    pub passed_over: Option<String>,
}

/// Assess the environment of `workspace` on `host`.
pub fn assess(workspace: &Workspace, host: &Host<'_>) -> Assessment {
    let requirement = toolchain::requirement(&workspace.mod_files, workspace.go_work.as_deref());
    let toolchain = choose_toolchain(requirement.as_ref(), host);
    let sums =
        Sums::read(&workspace.sum_files(), &workspace.own).restrict(workspace.needed.as_ref());
    let release = match &toolchain {
        ToolchainChoice::Installed(go) | ToolchainChoice::Stored(go) => go.version.to_string(),
        ToolchainChoice::Fetch(release) => release.to_string(),
        ToolchainChoice::Missing(_) => "none".to_string(),
    };
    let mut passed_over = None;
    let dependencies = if !workspace.requires_anything && sums.is_empty() {
        Dependencies::None
    } else if !workspace.vendored.is_empty()
        && workspace.vendored.len() == workspace.mod_files.len()
    {
        Dependencies::Vendored
    } else if sums.is_empty() {
        Dependencies::Missing(
            "go.mod requires modules and no go.sum locks them, so nothing can be verified"
                .to_string(),
        )
    } else {
        let user = host.env.modcache();
        match user.as_deref().map(|cache| check_modcache(cache, &sums)) {
            Some(Ok(())) => Dependencies::UserCache(user.unwrap_or_default()),
            other => {
                passed_over = Some(match other {
                    Some(Err(reason)) => reason,
                    _ => "no module cache is configured".to_string(),
                });
                if host.analysis_environments {
                    // Complete when every locked module is in Kin's cache and
                    // every module the checksum database may prove is in
                    // Kin's go.work.sum.
                    let proved = proved_sums(&host.store(), &workspace.root);
                    let complete = check_modcache(&modcache_dir(&host.store()), &sums).is_ok()
                        && provable(workspace, &sums, host.env)
                            .iter()
                            .all(|pin| proved.contains(pin));
                    let ready = complete
                        || super::recently_failed(&host.store(), &identity(&release, &sums));
                    Dependencies::KinCache { ready }
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
        identity: identity(&release, &sums),
        requirement,
        toolchain,
        sums,
        dependencies,
        passed_over,
    }
}

/// Fetch what the assessment of `workspace` left pending: the pinned Go
/// release and every locked module and `go.mod` not yet in Kin's cache.
pub fn provision(workspace: &Workspace, host: &Host<'_>, fetcher: &dyn Fetcher) -> ProvisionReport {
    let started = Instant::now();
    let mut report = ProvisionReport::default();
    let assessment = assess(workspace, host);
    let store = host.store();
    if let ToolchainChoice::Fetch(release) = &assessment.toolchain {
        match toolchain::ensure(fetcher, &store, release) {
            Ok((_, bytes)) => {
                report.fetched += 1;
                report.fetched_bytes += bytes;
            }
            Err(reason) => {
                report.failure = Some(format!("could not fetch Go {release}: {reason}"));
            }
        }
    }
    report
        .skipped
        .extend(assessment.sums.conflicts.iter().cloned());
    report.skipped.extend(workspace.outside.iter().cloned());
    if matches!(assessment.dependencies, Dependencies::KinCache { .. }) {
        let modcache = modcache_dir(&store);
        let proxies = modcache::parse_goproxy(&host.env.goproxy());
        let noproxy = host.env.noproxy();
        #[derive(Clone, Copy)]
        enum Kind {
            Zip,
            Mod,
        }
        let work: Vec<(Kind, &SumEntry)> = assessment
            .sums
            .zips
            .iter()
            .map(|entry| (Kind::Zip, entry))
            .chain(assessment.sums.mods.iter().map(|entry| (Kind::Mod, entry)))
            .collect();
        let outcomes = super::parallel_map(&work, super::PARALLEL_FETCHES, |(kind, entry)| {
            let private = !noproxy.is_empty() && matches_prefix_patterns(&noproxy, &entry.module);
            if private {
                return Err((
                    false,
                    format!(
                        "{} {}: GOPRIVATE or GONOPROXY keeps it off public proxies, and Kin does \
                         not fetch from version control",
                        entry.module, entry.version
                    ),
                ));
            }
            let outcome = match kind {
                Kind::Zip => modcache::ensure_module(
                    fetcher,
                    &proxies,
                    &modcache,
                    &entry.module,
                    &entry.version,
                    &entry.hash,
                ),
                Kind::Mod => modcache::ensure_go_mod(
                    fetcher,
                    &proxies,
                    &modcache,
                    &entry.module,
                    &entry.version,
                    &entry.hash,
                ),
            };
            outcome.map_err(|reason| {
                let refused = reason.contains("nothing was unpacked");
                let what = match kind {
                    Kind::Zip => "",
                    Kind::Mod => "/go.mod",
                };
                (
                    refused,
                    format!("{} {}{what}: {reason}", entry.module, entry.version),
                )
            })
        });
        let mut failures = 0;
        for outcome in outcomes {
            if matches!(&outcome, Err((refused, reason)) if *refused || !reason.contains("GOPRIVATE"))
            {
                failures += 1;
            }
            match outcome {
                Ok(0) => report.reused += 1,
                Ok(bytes) => {
                    report.fetched += 1;
                    report.fetched_bytes += bytes;
                }
                Err((true, reason)) => report.refused.push(reason),
                Err((false, reason)) => report.skipped.push(reason),
            }
        }
        super::record_attempt(&store, &assessment.identity, failures);
        let proved = prove_unlocked(
            workspace,
            &assessment,
            host,
            fetcher,
            &modcache,
            &proxies,
            &mut report,
        );
        if !proved.is_empty() || workspace.wants_kin_go_work() {
            if let Err(reason) = write_kin_go_work(
                &store,
                workspace,
                assessment.requirement.as_ref().map(|r| &r.minimum),
                Some(&proved),
            ) {
                report.skipped.push(format!("Kin's go.work: {reason}"));
            }
        }
        if report.failure.is_none() {
            report.environment = Some(modcache);
        }
    } else {
        report
            .skipped
            .extend(assessment.sums.unlocked.iter().cloned());
    }
    report.elapsed_ms = started.elapsed().as_millis();
    report
}

/// The module versions Kin's `go.work.sum` for the repository at `root`
/// holds proved zip hashes for.
pub fn proved_sums(store: &Path, root: &Path) -> BTreeSet<(String, String)> {
    std::fs::read_to_string(kin_go_work(store, root).with_file_name("go.work.sum"))
        .map(|text| {
            text.lines()
                .filter_map(|line| {
                    let mut words = line.split_whitespace();
                    let (module, version) = (words.next()?, words.next()?);
                    (!version.ends_with("/go.mod"))
                        .then(|| (module.to_string(), version.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The modules a build needs that no `go.sum` locks and the checksum
/// database may prove: the configuration allows it for them, and Kin can
/// hand gopls the proved hashes in a `go.work.sum` of its own.
pub fn provable(workspace: &Workspace, sums: &Sums, env: &GoEnv) -> Vec<(String, String)> {
    if workspace.go_work.is_some() || !workspace.vendored.is_empty() || env.gosumdb() == "off" {
        return Vec::new();
    }
    let nosumdb = env.nosumdb();
    let noproxy = env.noproxy();
    workspace
        .needed
        .iter()
        .flatten()
        .filter(|(module, version)| {
            !sums
                .zips
                .iter()
                .any(|entry| entry.module == *module && entry.version == *version)
                && !sums
                    .conflicts
                    .iter()
                    .any(|line| line.split_whitespace().next() == Some(module.as_str()))
                && (nosumdb.is_empty() || !matches_prefix_patterns(&nosumdb, module))
                && (noproxy.is_empty() || !matches_prefix_patterns(&noproxy, module))
        })
        .cloned()
        .collect()
}

/// For each module a build needs that no `go.sum` locks, ask the checksum
/// database, when the user's configuration allows it, and fetch the module
/// against the hashes it proves. Returns the proved `go.sum` lines, for
/// Kin's `go.work.sum`; a module that cannot be proved is skipped and named.
fn prove_unlocked(
    workspace: &Workspace,
    assessment: &Assessment,
    host: &Host<'_>,
    fetcher: &dyn Fetcher,
    modcache: &Path,
    proxies: &[modcache::ProxyEntry],
    report: &mut ProvisionReport,
) -> Vec<String> {
    let unlocked: Vec<(String, String)> = workspace
        .needed
        .iter()
        .flatten()
        .filter(|(module, version)| {
            !assessment
                .sums
                .zips
                .iter()
                .any(|entry| entry.module == *module && entry.version == *version)
        })
        .filter(|(module, _)| {
            !assessment
                .sums
                .conflicts
                .iter()
                .any(|line| line.split_whitespace().next() == Some(module.as_str()))
        })
        .cloned()
        .collect();
    if unlocked.is_empty() {
        return Vec::new();
    }
    let refuse = |why: &str, report: &mut ProvisionReport| {
        for (module, version) in &unlocked {
            report.skipped.push(format!(
                "{module} {version}: required, no go.sum locks its zip, and {why}"
            ));
        }
    };
    if workspace.go_work.is_some() {
        refuse(
            "a proved hash could go only in the repository's own go.work.sum, which Kin does not \
             write",
            report,
        );
        return Vec::new();
    }
    if !workspace.vendored.is_empty() {
        refuse("the workspace vendors its modules", report);
        return Vec::new();
    }
    let db = match sumdb::from_gosumdb(&host.env.gosumdb()) {
        Ok(Some(db)) => db,
        Ok(None) => {
            refuse(
                "GOSUMDB is off, so the checksum database cannot prove it",
                report,
            );
            return Vec::new();
        }
        Err(reason) => {
            refuse(&format!("GOSUMDB is unusable: {reason}"), report);
            return Vec::new();
        }
    };
    let nosumdb = host.env.nosumdb();
    let noproxy = host.env.noproxy();
    let mut proved = Vec::new();
    for (module, version) in unlocked {
        if !nosumdb.is_empty() && matches_prefix_patterns(&nosumdb, &module) {
            report.skipped.push(format!(
                "{module} {version}: required, no go.sum locks its zip, and GONOSUMDB or \
                 GOPRIVATE keeps it from the checksum database"
            ));
            continue;
        }
        if !noproxy.is_empty() && matches_prefix_patterns(&noproxy, &module) {
            report.skipped.push(format!(
                "{module} {version}: GOPRIVATE or GONOPROXY keeps it off public proxies"
            ));
            continue;
        }
        let lines = match sumdb::lookup(fetcher, &db, &module, &version) {
            Ok(lines) => lines,
            Err(reason) => {
                report.skipped.push(format!(
                    "{module} {version}: required, no go.sum locks its zip, and the checksum \
                     database did not prove it: {reason}"
                ));
                continue;
            }
        };
        let hash_of = |suffix: &str| {
            lines
                .iter()
                .find(|line| line.version == format!("{version}{suffix}"))
                .map(|line| line.hash.clone())
        };
        let (Some(zip), Some(go_mod)) = (hash_of(""), hash_of("/go.mod")) else {
            continue;
        };
        let fetched = modcache::ensure_module(fetcher, proxies, modcache, &module, &version, &zip)
            .and_then(|zip_bytes| {
                modcache::ensure_go_mod(fetcher, proxies, modcache, &module, &version, &go_mod)
                    .map(|mod_bytes| zip_bytes + mod_bytes)
            });
        match fetched {
            Ok(bytes) => {
                if bytes > 0 {
                    report.fetched += 1;
                    report.fetched_bytes += bytes;
                } else {
                    report.reused += 1;
                }
                proved.extend(lines.iter().map(ToString::to_string));
            }
            Err(reason) if reason.contains("nothing was unpacked") => {
                report.refused.push(format!("{module} {version}: {reason}"));
            }
            Err(reason) => report.skipped.push(format!("{module} {version}: {reason}")),
        }
    }
    proved
}

#[cfg(test)]
mod tests {
    use super::modcache::testing::module_zip;
    use super::*;
    use crate::adapters::repo_scan::Fixture;
    use crate::analysis_env::fetch::testing::FixedFetcher;

    #[test]
    fn private_patterns_match_path_prefixes() {
        assert!(matches_prefix_patterns(
            "*.corp.example.com,rsc.io/private",
            "git.corp.example.com/team/x"
        ));
        assert!(matches_prefix_patterns(
            "rsc.io/private",
            "rsc.io/private/sub"
        ));
        assert!(!matches_prefix_patterns("rsc.io/private", "rsc.io/public"));
        assert!(!matches_prefix_patterns(
            "github.com/org/*",
            "github.com/org"
        ));
        assert!(matches_prefix_patterns(
            "github.com/org/*",
            "github.com/org/repo/pkg"
        ));
        assert!(!matches_prefix_patterns("", "anything"));
    }

    /// The env file names what the process does not; the process wins.
    #[test]
    fn settings_come_from_the_process_over_the_env_file() {
        let home = Fixture::new("go-env");
        let file = home.write(
            "goenv",
            "GOPROXY=https://corp.example/proxy\nGOPRIVATE=corp.example\n",
        );
        let mut vars = HashMap::new();
        vars.insert("GOENV".to_string(), file.display().to_string());
        let env = GoEnv::read(&vars, Some(&home.root));
        assert_eq!(env.goproxy(), "https://corp.example/proxy");
        assert_eq!(env.noproxy(), "corp.example");
        assert_eq!(env.nosumdb(), "corp.example");
        assert_eq!(env.modcache(), Some(home.root.join("go/pkg/mod")));
        vars.insert("GOPROXY".to_string(), "off".to_string());
        vars.insert("GOFLAGS".to_string(), "-insecure".to_string());
        let env = GoEnv::read(&vars, Some(&home.root));
        assert_eq!(env.goproxy(), "off");
        assert_eq!(env.gosumdb(), "off");
    }

    #[test]
    fn go_sum_lines_are_read_and_the_workspace_left_out() {
        let repo = Fixture::new("go-sums");
        let a = repo.write(
            "go.sum",
            "example.com/dep v1.0.0 h1:zip=\nexample.com/dep v1.0.0/go.mod h1:mod=\n\
             example.com/root v0.1.0/go.mod h1:own=\nmalformed line\n",
        );
        let b = repo.write(
            "b/go.sum",
            "example.com/dep v1.0.0 h1:other=\nexample.com/more v2.0.0/go.mod h1:more=\n",
        );
        let own: BTreeSet<String> = ["example.com/root".to_string()].into();
        let sums = Sums::read(&[a, b], &own);
        assert!(
            sums.zips.is_empty(),
            "the disputed zip is fetched from neither"
        );
        assert_eq!(sums.conflicts.len(), 1, "{:?}", sums.conflicts);
        let mods: Vec<&str> = sums.mods.iter().map(|m| m.module.as_str()).collect();
        assert_eq!(mods, vec!["example.com/dep", "example.com/more"]);
    }

    fn installed(dir: &Fixture, version: &str) -> InstalledGo {
        dir.write("go/VERSION", &format!("go{version}\n"));
        dir.write("go/bin/go", "");
        toolchain::installation_at(&dir.root.join("go")).unwrap()
    }

    /// The installed Go serves when it is at least the `go` line; otherwise
    /// the pinned release is fetched, unless GOTOOLCHAIN=local or the switch
    /// forbids it.
    #[test]
    fn the_toolchain_is_the_installed_one_when_new_enough() {
        let repo = Fixture::new("go-toolchain");
        let cache = Fixture::new("go-toolchain-cache");
        let tools = Fixture::new("go-toolchain-installed");
        let go = installed(&tools, "1.22.4");
        let file = repo.write("go.mod", "module x\n\ngo 1.23\n\ntoolchain go1.23.2\n");
        let requirement = toolchain::requirement(&[file], None);
        let env = GoEnv::default();
        let mut host = Host {
            env: &env,
            cache: &cache.root,
            installed: Some(&go),
            analysis_environments: true,
        };
        let choice = choose_toolchain(requirement.as_ref(), &host);
        assert_eq!(
            choice,
            ToolchainChoice::Fetch(GoVersion::parse("1.23.2").unwrap())
        );
        host.analysis_environments = false;
        assert!(matches!(
            choose_toolchain(requirement.as_ref(), &host),
            ToolchainChoice::Missing(reason) if reason.contains("analysis environments are off")
        ));
        let newer = installed(&tools, "1.25.7");
        host.installed = Some(&newer);
        assert!(matches!(
            choose_toolchain(requirement.as_ref(), &host),
            ToolchainChoice::Installed(_)
        ));
    }

    /// A lock the user's cache holds is served from it; one it does not is
    /// fetched into Kin's cache, verified, after which the assessment finds
    /// Kin's cache complete.
    #[test]
    fn the_users_cache_serves_when_complete_and_kins_is_filled_otherwise() {
        let repo = Fixture::new("go-assess");
        let cache = Fixture::new("go-assess-cache");
        let home = Fixture::new("go-assess-home");
        let zip = module_zip("example.com/dep", "v1.0.0", &[("dep.go", "package dep\n")]);
        let zip_path = cache.root.join("probe.zip");
        std::fs::write(&zip_path, &zip).unwrap();
        let zip_hash = modcache::hash_zip(&zip_path).unwrap();
        let go_mod = b"module example.com/dep\n".to_vec();
        let mod_hash = modcache::hash_go_mod(&go_mod);
        let file = repo.write(
            "go.mod",
            "module example.com/root\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n",
        );
        repo.write(
            "go.sum",
            &format!(
                "example.com/dep v1.0.0 {zip_hash}\nexample.com/dep v1.0.0/go.mod {mod_hash}\n"
            ),
        );
        let workspace = Workspace::read(&repo.root, &[file]);
        let mut vars = HashMap::new();
        vars.insert(
            "GOMODCACHE".to_string(),
            home.root.join("modcache").display().to_string(),
        );
        vars.insert("GOPROXY".to_string(), "https://proxy.example".to_string());
        let env = GoEnv::read(&vars, Some(&home.root));
        let host = Host {
            env: &env,
            cache: &cache.root,
            installed: None,
            analysis_environments: true,
        };
        let before = assess(&workspace, &host);
        assert_eq!(before.dependencies, Dependencies::KinCache { ready: false });
        assert!(before.passed_over.unwrap().contains("lacks 1 of 1"));

        let mut fetcher = FixedFetcher::default();
        fetcher.files.insert(
            "https://proxy.example/example.com/dep/@v/v1.0.0.zip".to_string(),
            zip,
        );
        fetcher.documents.insert(
            "https://proxy.example/example.com/dep/@v/v1.0.0.mod".to_string(),
            ("text/plain".to_string(), go_mod),
        );
        let report = provision(&workspace, &host, &fetcher);
        assert_eq!(report.fetched, 2, "{report:?}");
        assert!(report.processes.is_empty());
        assert!(
            report.refused.is_empty() && report.skipped.is_empty(),
            "{report:?}"
        );
        let after = assess(&workspace, &host);
        assert_eq!(after.dependencies, Dependencies::KinCache { ready: true });
        assert_eq!(after.identity, before.identity);

        // The same modules in the user's own cache: it serves, unchecked by
        // nothing but go.sum.
        let user = home.root.join("modcache");
        std::fs::create_dir_all(&user).unwrap();
        fn copy(from: &Path, to: &Path) {
            if from.is_dir() {
                std::fs::create_dir_all(to).unwrap();
                for entry in std::fs::read_dir(from).unwrap().filter_map(Result::ok) {
                    copy(&entry.path(), &to.join(entry.file_name()));
                }
            } else {
                std::fs::copy(from, to).unwrap();
            }
        }
        copy(&modcache_dir(&host.store()), &user);
        assert_eq!(
            assess(&workspace, &host).dependencies,
            Dependencies::UserCache(user)
        );
    }

    /// A module GOPRIVATE names is never sent to a public proxy.
    #[test]
    fn private_modules_are_skipped_and_named() {
        let repo = Fixture::new("go-private");
        let cache = Fixture::new("go-private-cache");
        let file = repo.write(
            "go.mod",
            "module x\n\ngo 1.21\n\nrequire corp.example/lib v1.0.0\n",
        );
        repo.write("go.sum", "corp.example/lib v1.0.0 h1:zip=\n");
        let workspace = Workspace::read(&repo.root, &[file]);
        let mut vars = HashMap::new();
        vars.insert("GOPRIVATE".to_string(), "corp.example".to_string());
        vars.insert(
            "GOMODCACHE".to_string(),
            cache.root.join("user").display().to_string(),
        );
        let env = GoEnv::read(&vars, None);
        let tools = Fixture::new("go-private-tools");
        let go = installed(&tools, "1.25.7");
        let host = Host {
            env: &env,
            cache: &cache.root,
            installed: Some(&go),
            analysis_environments: true,
        };
        let fetcher = FixedFetcher::default();
        let report = provision(&workspace, &host, &fetcher);
        assert!(fetcher.requests.lock().unwrap().is_empty());
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].contains("GOPRIVATE"), "{report:?}");
    }

    #[test]
    fn go_mod_requires_and_replaces_are_read_in_both_forms() {
        let go_mod = GoMod::parse(
            "module example.com/x // comment\n\ngo 1.22\n\nrequire example.com/a v1.0.0\n\
             require (\n\texample.com/b v1.1.0 // indirect\n\t\"example.com/c\" v0.2.0\n)\n\
             replace example.com/a => example.com/fork v1.0.1\n\
             replace (\n\texample.com/b v1.1.0 => ../b\n)\n",
        );
        assert_eq!(go_mod.module.as_deref(), Some("example.com/x"));
        assert_eq!(go_mod.go, GoVersion::parse("1.22"));
        assert_eq!(go_mod.requires.len(), 3);
        assert_eq!(
            go_mod.resolve("example.com/a", "v1.0.0"),
            Some(Replacement::Module {
                module: "example.com/fork".to_string(),
                version: "v1.0.1".to_string()
            })
        );
        assert_eq!(
            go_mod.resolve("example.com/b", "v1.1.0"),
            Some(Replacement::Directory("../b".to_string()))
        );
        assert_eq!(go_mod.resolve("example.com/c", "v0.2.0"), None);
    }

    /// From Go 1.17 a build loads packages only from the modules go.mod
    /// requires, so a dependency's test-only modules in go.sum are not
    /// fetched; before 1.17 every locked zip is.
    #[test]
    fn only_required_modules_are_needed_from_go_1_17() {
        let repo = Fixture::new("go-needed");
        let file = repo.write(
            "go.mod",
            "module x\n\ngo 1.21\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/r v1.0.0\n)\n\
             replace example.com/r => example.com/fork v2.0.0\n",
        );
        repo.write(
            "go.sum",
            "example.com/a v1.0.0 h1:a=\nexample.com/fork v2.0.0 h1:f=\n\
             example.com/testonly v0.1.0 h1:t=\n",
        );
        let workspace = Workspace::read(&repo.root, &[file]);
        let sums =
            Sums::read(&workspace.sum_files(), &workspace.own).restrict(workspace.needed.as_ref());
        let zips: Vec<&str> = sums.zips.iter().map(|z| z.module.as_str()).collect();
        assert_eq!(zips, vec!["example.com/a", "example.com/fork"]);
        assert_eq!(sums.unneeded_zips, 1);

        repo.write(
            "go.mod",
            "module x\n\ngo 1.16\n\nrequire example.com/a v1.0.0\n",
        );
        let workspace = Workspace::read(&repo.root, &[repo.root.join("go.mod")]);
        assert!(workspace.needed.is_none());
        let sums =
            Sums::read(&workspace.sum_files(), &workspace.own).restrict(workspace.needed.as_ref());
        assert_eq!(sums.zips.len(), 3);
    }

    /// A required module no go.sum locks goes to the checksum database only
    /// where the configuration allows it; each refusal names why, and asks
    /// nothing of the network.
    #[test]
    fn unlocked_modules_are_proved_only_where_the_configuration_allows() {
        let repo = Fixture::new("go-unlocked");
        let cache = Fixture::new("go-unlocked-cache");
        let tools = Fixture::new("go-unlocked-tools");
        let go = installed(&tools, "1.25.7");
        let file = repo.write(
            "go.mod",
            "module x\n\ngo 1.21\n\nrequire (\n\texample.com/locked v1.0.0\n\tcorp.example/lib v1.0.0\n\texample.com/untidy v1.0.0\n)\n",
        );
        let zip = module_zip("example.com/locked", "v1.0.0", &[("l.go", "package l\n")]);
        let zip_path = cache.root.join("probe.zip");
        std::fs::write(&zip_path, &zip).unwrap();
        let hash = modcache::hash_zip(&zip_path).unwrap();
        repo.write("go.sum", &format!("example.com/locked v1.0.0 {hash}\n"));
        let workspace = Workspace::read(&repo.root, &[file]);
        let run = |vars: HashMap<String, String>| {
            let env = GoEnv::read(&vars, None);
            let host = Host {
                env: &env,
                cache: &cache.root,
                installed: Some(&go),
                analysis_environments: true,
            };
            let mut fetcher = FixedFetcher::default();
            fetcher.files.insert(
                "https://proxy.example/example.com/locked/@v/v1.0.0.zip".to_string(),
                zip.clone(),
            );
            let report = provision(&workspace, &host, &fetcher);
            let requests = fetcher.requests.lock().unwrap().clone();
            (report, requests)
        };
        let base = || {
            let mut vars = HashMap::new();
            vars.insert("GOENV".to_string(), "off".to_string());
            vars.insert("GOPROXY".to_string(), "https://proxy.example".to_string());
            vars.insert(
                "GOMODCACHE".to_string(),
                cache.root.join("user").display().to_string(),
            );
            vars
        };
        let mut off = base();
        off.insert("GOSUMDB".to_string(), "off".to_string());
        let (report, requests) = run(off);
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.contains("example.com/untidy") && s.contains("GOSUMDB is off")),
            "{report:?}"
        );
        assert!(
            requests.iter().all(|url| !url.contains("sum.golang.org")),
            "{requests:?}"
        );

        let mut private = base();
        private.insert("GOPRIVATE".to_string(), "corp.example".to_string());
        private.insert("GOSUMDB".to_string(), "off".to_string());
        let (report, _) = run(private);
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.contains("corp.example/lib")),
            "{report:?}"
        );

        repo.write("go.work", "go 1.21\n\nuse .\n");
        let workspace_with_work = Workspace::read(&repo.root, &[repo.root.join("go.mod")]);
        let env = GoEnv::read(&base(), None);
        let host = Host {
            env: &env,
            cache: &cache.root,
            installed: Some(&go),
            analysis_environments: true,
        };
        let fetcher = FixedFetcher::default();
        let report = provision(&workspace_with_work, &host, &fetcher);
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.contains("repository's own go.work.sum")),
            "{report:?}"
        );
        assert!(fetcher
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|url| !url.contains("sum.golang.org")));
    }

    #[test]
    fn a_module_without_dependencies_needs_no_environment() {
        let repo = Fixture::new("go-bare");
        let file = repo.write("go.mod", "module x\n\ngo 1.21\n");
        let workspace = Workspace::read(&repo.root, &[file]);
        let env = GoEnv::default();
        let host = Host {
            env: &env,
            cache: &repo.root,
            installed: None,
            analysis_environments: true,
        };
        assert_eq!(assess(&workspace, &host).dependencies, Dependencies::None);
    }
}
