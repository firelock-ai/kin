// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Static readers for Python lockfiles.
//!
//! A Python project pins its dependencies in one of several lockfile formats: `uv.lock`,
//! `pylock.toml` (PEP 751), `poetry.lock`, `pdm.lock`, `Pipfile.lock`, or requirements files that
//! pin every package with `==` and a `--hash`. Each reader here turns one format into the same
//! [`Lock`] model: the pinned packages, where each one comes from, the artifacts and digests the
//! lock accepts for it, and the dependency edges the lock records.
//!
//! The readers only read text. They never run Python, an installer, a build backend or any other
//! process, and never touch the network, so no code from the repository or from its dependencies
//! runs while a lock is read. Markers and version specifiers are carried as written and are never
//! evaluated here.

use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

use serde_json::{Map as JsonMap, Value as JsonValue};
use toml::{Table, Value};

/// Which lockfile format a lock came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockFormat {
    /// uv's `uv.lock`.
    UvLock,
    /// A PEP 751 lock, `pylock.toml` or `pylock.<name>.toml`.
    Pylock,
    /// Poetry's `poetry.lock`.
    PoetryLock,
    /// PDM's `pdm.lock`.
    PdmLock,
    /// Pipenv's `Pipfile.lock`.
    PipfileLock,
    /// One or more pip requirements files that pin and hash every package.
    Requirements,
}

impl LockFormat {
    /// The conventional file name of the format, for messages.
    pub fn describe(self) -> &'static str {
        match self {
            LockFormat::UvLock => "uv.lock",
            LockFormat::Pylock => "pylock.toml",
            LockFormat::PoetryLock => "poetry.lock",
            LockFormat::PdmLock => "pdm.lock",
            LockFormat::PipfileLock => "Pipfile.lock",
            LockFormat::Requirements => "requirements file",
        }
    }
}

/// A lockfile read into one model, whatever its format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lock {
    /// The format the lock was read from.
    pub format: LockFormat,
    /// Every file this lock was read from, the main one first (requirements may be several).
    pub files: Vec<PathBuf>,
    /// The locked packages, in the order the lock lists them.
    pub packages: Vec<LockedPackage>,
    /// The Python versions the lock supports, as a PEP 440 specifier set (">=3.10"), when it says.
    pub requires_python: Option<String>,
    /// An exact Python version the lock pins (Pipfile.lock `_meta.requires.python_full_version`,
    /// else `python_version`), when it pins one.
    pub python_pin: Option<String>,
    /// Workspace members the lock names (uv.lock `[manifest] members`), as written.
    pub members: Vec<String>,
    /// Index URLs the lock itself names, in order: requirements `--index-url` and
    /// `--extra-index-url`, Pipfile `_meta.sources`, and poetry `[package.source]` legacy URLs.
    /// uv.lock and pylock.toml name a registry per package instead, in [`PackageSource::Registry`].
    pub index_urls: Vec<String>,
}

/// One package pinned by a lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedPackage {
    /// The name as written in the lock.
    pub name: String,
    /// The pinned version. `None` only for a package with no version (a uv virtual member, an
    /// in-repo directory, a VCS checkout the lock pins by commit).
    pub version: Option<String>,
    /// Where the package comes from.
    pub source: PackageSource,
    /// The package-level environment marker, unevaluated: pylock `marker`, Pipfile `markers`,
    /// requirements `; marker`, pdm `marker`, and poetry `markers` when it is a string. A poetry
    /// table of per-group markers becomes the group markers joined with " or ", each wrapped in
    /// parentheses when there is more than one; when some group of the package has no marker the
    /// package is unconditional and this is `None`.
    pub marker: Option<String>,
    /// The Python versions this package supports as a PEP 440 specifier set (poetry
    /// `python-versions`, pdm `requires_python`, pylock `requires-python`), `None` when
    /// unconstrained or not representable.
    pub requires_python: Option<String>,
    /// The artifacts the lock lists for this package, each with its own digest.
    pub files: Vec<LockedFile>,
    /// Digests accepted for this package when the lock lists hashes without files (Pipfile.lock,
    /// requirements): lowercase sha256 hex.
    pub hashes: Vec<String>,
    /// What this package depends on, when the lock records it (uv.lock always; poetry
    /// `[package.dependencies]`; pdm `dependencies`; pylock `dependencies`).
    pub dependencies: Vec<LockedDependency>,
    /// uv.lock `resolution-markers` of this package: the forks it belongs to. Empty elsewhere.
    pub resolution_markers: Vec<String>,
}

/// Where a locked package comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageSource {
    /// From a package index; `index` is the index URL the lock names for it, if any.
    Registry { index: Option<String> },
    /// A local directory, as a path relative to the lock's directory when the lock wrote it
    /// relative. uv `editable`/`virtual`/`directory`, pylock `[packages.directory]`, poetry
    /// `type = "directory"`, pdm `path`, Pipfile `path`, requirements `-e <path>` or a bare local
    /// path.
    Directory { path: String, editable: bool },
    /// A direct archive URL or local archive file (uv `url`/`path` to an archive, pylock
    /// `[packages.archive]`, poetry `type = "url"`/`"file"`, requirements `name @ https://...`).
    Archive { location: String },
    /// A VCS checkout (uv `git`, pylock `[packages.vcs]`, poetry `type = "git"`, pdm `git`,
    /// Pipfile `git`), as the lock writes its URL.
    Vcs { url: String },
}

/// Whether an artifact is a built wheel or a source distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// A `.whl` file.
    Wheel,
    /// A source distribution, or any artifact that is not a wheel.
    Sdist,
}

/// One artifact a lock lists for a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedFile {
    /// Wheel or source distribution. The lock's own section decides when it has one (uv and
    /// pylock `sdist` and `wheels`); otherwise a `.whl` name is a wheel and anything else a
    /// source distribution.
    pub kind: FileKind,
    /// The file name ("starlette-0.47.2-py3-none-any.whl"), from the lock's `file`/`name` field
    /// or the URL's last path segment, percent-decoded (`%2B` is `+`).
    pub filename: String,
    /// Where the artifact is downloaded from, when the lock gives a URL.
    pub url: Option<String>,
    /// Lowercase sha256 hex, `None` when the lock gives no sha256 for it (other algorithms are
    /// ignored).
    pub sha256: Option<String>,
    /// The artifact's size in bytes, when the lock records it.
    pub size: Option<u64>,
}

/// One dependency edge a lock records for a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedDependency {
    /// The dependency's name as written.
    pub name: String,
    /// uv.lock names the version (and source) when the lock holds more than one version of that
    /// name.
    pub version: Option<String>,
    /// The environment marker that guards the edge, unevaluated.
    pub marker: Option<String>,
    /// Extras of the dependency that are requested (uv `extra = [..]`, poetry `extras = [..]`, a
    /// `name[a,b]` requirement).
    pub extras: Vec<String>,
    /// Whether the edge is unconditional, or belongs to an extra or a dependency group.
    pub kind: DependencyKind,
}

/// When a dependency edge applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyKind {
    /// Always, subject only to the edge's marker.
    Required,
    /// Only with this extra of the depending package (uv `[package.optional-dependencies]` key,
    /// poetry dep marked optional, listed under `[package.extras]`).
    Extra(String),
    /// Only in this dependency group (uv `[package.dev-dependencies]` key).
    Group(String),
}

/// The outcome of looking for a lock at a project root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockSearch {
    /// A lock that parsed.
    Found(Lock),
    /// Lock-like files exist but none is usable; one reason per file, naming the file.
    Unusable { reasons: Vec<String> },
    /// No lockfile of any supported format.
    NotFound,
}

/// Parse a `uv.lock`. `path` is where the text came from; errors name it and it becomes
/// [`Lock::files`].
pub fn parse_uv_lock(text: &str, path: &Path) -> Result<Lock, String> {
    read_uv_lock(text, path, &path.display().to_string())
}

/// Parse a PEP 751 `pylock.toml` or `pylock.<name>.toml`.
pub fn parse_pylock(text: &str, path: &Path) -> Result<Lock, String> {
    read_pylock(text, path, &path.display().to_string())
}

/// Parse a `poetry.lock`, lock-version 1.x (files under `[metadata.files]`) or 2.x (files per
/// package).
pub fn parse_poetry_lock(text: &str, path: &Path) -> Result<Lock, String> {
    read_poetry_lock(text, path, &path.display().to_string())
}

/// Parse a `pdm.lock`.
pub fn parse_pdm_lock(text: &str, path: &Path) -> Result<Lock, String> {
    read_pdm_lock(text, path, &path.display().to_string())
}

/// Parse a `Pipfile.lock`, both its `default` and `develop` sections. A name in both keeps the
/// `default` entry.
pub fn parse_pipfile_lock(text: &str, path: &Path) -> Result<Lock, String> {
    read_pipfile_lock(text, path, &path.display().to_string())
}

/// Parse requirements files as a lock. `read` returns a file's text, for following `-r`/`-c`
/// includes relative to the including file, and for reading a local project's `pyproject.toml`
/// or `setup.cfg` to learn the name of an in-repo path requirement. Every requirement that is not
/// an in-repo path or editable must be pinned with `==` to an exact version (no wildcard) and
/// carry at least one `--hash=sha256:`; otherwise Err naming the first offending line and why
/// ("requirements-dev.txt: `pytest>=2.8.0,<10` is not pinned with `==`").
///
/// A direct archive URL needs a digest but no `==`, since the URL names one artifact. A VCS
/// requirement, editable or not, must name a full commit, since no digest can cover a checkout.
/// An absolute path is refused because it names no file inside the repository.
pub fn parse_requirements(
    paths: &[PathBuf],
    read: &dyn Fn(&Path) -> Option<String>,
) -> Result<Lock, String> {
    read_requirements(paths, read, None)
}

/// Look for a lock at `root` in this order and return the first that parses: `uv.lock`;
/// `pylock.toml`, then `pylock.*.toml` sorted by name; `poetry.lock`; `pdm.lock`;
/// `Pipfile.lock`; requirements files (root `requirements*.txt` with `requirements.txt` first
/// and the rest sorted, plus `*.txt` directly in a root `requirements/` directory, sorted) taken
/// together, keeping only files that qualify on their own and returning Found when at least one
/// does. A qualifying requirements file that conflicts with the ones before it is left out. A
/// file that exists and fails adds its reason; when nothing is Found, return Unusable with every
/// reason if any file existed, else NotFound. Reasons name files relative to `root`.
pub fn find_lock(root: &Path) -> LockSearch {
    type Reader = fn(&str, &Path, &str) -> Result<Lock, String>;

    let mut reasons = Vec::new();
    let mut candidates: Vec<(PathBuf, Reader)> = vec![
        (root.join("uv.lock"), read_uv_lock),
        (root.join("pylock.toml"), read_pylock),
    ];
    for path in named_pylocks(root) {
        candidates.push((path, read_pylock));
    }
    candidates.push((root.join("poetry.lock"), read_poetry_lock));
    candidates.push((root.join("pdm.lock"), read_pdm_lock));
    candidates.push((root.join("Pipfile.lock"), read_pipfile_lock));

    for (path, reader) in candidates {
        if !path.is_file() {
            continue;
        }
        let label = shown_path(&path, Some(root));
        match std::fs::read_to_string(&path) {
            Ok(text) => match reader(&text, &path, &label) {
                Ok(lock) => return LockSearch::Found(lock),
                Err(reason) => reasons.push(reason),
            },
            Err(err) => reasons.push(format!("{label}: cannot be read: {err}")),
        }
    }

    let read = |path: &Path| std::fs::read_to_string(path).ok();
    let mut qualifying = Vec::new();
    for path in requirements_files(root) {
        match read_requirements(std::slice::from_ref(&path), &read, Some(root)) {
            Ok(_) => qualifying.push(path),
            Err(reason) => reasons.push(reason),
        }
    }
    let mut chosen: Vec<PathBuf> = Vec::new();
    let mut found = None;
    for path in qualifying {
        chosen.push(path);
        match read_requirements(&chosen, &read, Some(root)) {
            Ok(lock) => found = Some(lock),
            Err(reason) => {
                reasons.push(reason);
                chosen.pop();
            }
        }
    }

    match found {
        Some(lock) => LockSearch::Found(lock),
        None if reasons.is_empty() => LockSearch::NotFound,
        None => LockSearch::Unusable { reasons },
    }
}

/// PEP 503 normalization: lowercase, every run of `-`, `_`, `.` becomes one `-`.
pub fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut in_separator_run = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !in_separator_run {
                out.push('-');
                in_separator_run = true;
            }
        } else {
            out.extend(c.to_lowercase());
            in_separator_run = false;
        }
    }
    out
}

// uv.lock

fn read_uv_lock(text: &str, path: &Path, label: &str) -> Result<Lock, String> {
    let doc = parse_toml(text, label)?;
    match doc.get("version") {
        Some(Value::Integer(1)) => {}
        Some(Value::Integer(other)) => {
            return Err(format!("{label}: uv.lock version {other} is not supported"));
        }
        _ => {
            return Err(format!(
                "{label}: has no integer `version`, so it is not a uv.lock"
            ))
        }
    }
    let members = match doc.get("manifest") {
        Some(Value::Table(manifest)) => strings(manifest.get("members")),
        _ => Vec::new(),
    };
    let packages = array_of_tables(&doc, "package")
        .map_err(|why| format!("{label}: {why}"))?
        .into_iter()
        .enumerate()
        .map(|(index, table)| uv_package(table, index).map_err(|why| format!("{label}: {why}")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Lock {
        format: LockFormat::UvLock,
        files: vec![path.to_path_buf()],
        packages,
        requires_python: text_field(&doc, "requires-python"),
        python_pin: None,
        members,
        index_urls: Vec::new(),
    })
}

fn uv_package(pkg: &Table, index: usize) -> Result<LockedPackage, String> {
    let name = package_name(pkg, index)?;
    let fail = |why: String| format!("package `{name}` {why}");
    let source = match pkg.get("source") {
        Some(Value::Table(table)) => {
            uv_source(table).ok_or_else(|| fail("has a `source` of no known kind".into()))?
        }
        _ => return Err(fail("has no `source` table".into())),
    };
    let archive_location = match &source {
        PackageSource::Archive { location } => Some(location.as_str()),
        _ => None,
    };

    let mut files = Vec::new();
    if let Some(sdist) = sub_table(pkg, "sdist").map_err(&fail)? {
        files.push(uv_file(sdist, FileKind::Sdist, archive_location).map_err(&fail)?);
    }
    for wheel in array_of_tables(pkg, "wheels").map_err(&fail)? {
        files.push(uv_file(wheel, FileKind::Wheel, archive_location).map_err(&fail)?);
    }

    let mut dependencies =
        uv_dependencies(pkg.get("dependencies"), &DependencyKind::Required).map_err(&fail)?;
    uv_dependency_tables(
        pkg,
        "optional-dependencies",
        DependencyKind::Extra,
        &mut dependencies,
    )
    .map_err(&fail)?;
    uv_dependency_tables(
        pkg,
        "dev-dependencies",
        DependencyKind::Group,
        &mut dependencies,
    )
    .map_err(&fail)?;

    let version = text_field(pkg, "version");
    let resolution_markers = strings(pkg.get("resolution-markers"));
    Ok(LockedPackage {
        name,
        version,
        source,
        marker: None,
        requires_python: None,
        files,
        hashes: Vec::new(),
        dependencies,
        resolution_markers,
    })
}

fn uv_source(table: &Table) -> Option<PackageSource> {
    if let Some(index) = text_field(table, "registry") {
        return Some(PackageSource::Registry { index: Some(index) });
    }
    if let Some(path) = text_field(table, "editable") {
        return Some(PackageSource::Directory {
            path,
            editable: true,
        });
    }
    if let Some(path) = text_field(table, "virtual").or_else(|| text_field(table, "directory")) {
        return Some(PackageSource::Directory {
            path,
            editable: false,
        });
    }
    if let Some(path) = text_field(table, "path") {
        return Some(if is_archive_name(&path) {
            PackageSource::Archive { location: path }
        } else {
            PackageSource::Directory {
                path,
                editable: false,
            }
        });
    }
    if let Some(location) = text_field(table, "url") {
        return Some(PackageSource::Archive { location });
    }
    text_field(table, "git").map(|url| PackageSource::Vcs { url })
}

/// Reads one `sdist` or `wheels` entry. An entry of a package whose source is itself an archive
/// may carry only a digest; its name and URL then come from the source.
fn uv_file(
    table: &Table,
    kind: FileKind,
    archive_location: Option<&str>,
) -> Result<LockedFile, String> {
    let own_url = text_field(table, "url");
    let own_path = text_field(table, "path");
    let url = match (&own_url, &own_path) {
        (Some(url), _) => Some(url.clone()),
        (None, None) => archive_location
            .filter(|location| has_url_scheme(location))
            .map(str::to_owned),
        (None, Some(_)) => None,
    };
    let filename = text_field(table, "filename")
        .or_else(|| own_url.as_deref().and_then(url_file_name))
        .or_else(|| own_path.as_deref().and_then(path_file_name))
        .or_else(|| {
            archive_location.and_then(|location| {
                if has_url_scheme(location) {
                    url_file_name(location)
                } else {
                    path_file_name(location)
                }
            })
        })
        .ok_or_else(|| "lists an artifact with no file name".to_string())?;
    let sha256 = match text_field(table, "hash") {
        Some(hash) => prefixed_sha256(&hash)?,
        None => None,
    };
    Ok(LockedFile {
        kind,
        filename,
        url,
        sha256,
        size: size_field(table),
    })
}

fn uv_dependency_tables(
    pkg: &Table,
    key: &str,
    kind: fn(String) -> DependencyKind,
    out: &mut Vec<LockedDependency>,
) -> Result<(), String> {
    let Some(groups) = sub_table(pkg, key)? else {
        return Ok(());
    };
    for group in sorted_keys(groups) {
        out.extend(uv_dependencies(groups.get(group), &kind(group.clone()))?);
    }
    Ok(())
}

fn uv_dependencies(
    value: Option<&Value>,
    kind: &DependencyKind,
) -> Result<Vec<LockedDependency>, String> {
    let items = match value {
        None => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return Err("has a dependency list that is not an array".into()),
    };
    items
        .iter()
        .map(|item| {
            let table = item
                .as_table()
                .ok_or("has a dependency that is not a table")?;
            let name = text_field(table, "name").ok_or("has a dependency with no `name`")?;
            Ok(LockedDependency {
                name,
                version: text_field(table, "version"),
                marker: text_field(table, "marker"),
                extras: strings(table.get("extra")),
                kind: kind.clone(),
            })
        })
        .collect()
}

// pylock.toml (PEP 751)

fn read_pylock(text: &str, path: &Path, label: &str) -> Result<Lock, String> {
    let doc = parse_toml(text, label)?;
    let lock_version = text_field(&doc, "lock-version")
        .ok_or_else(|| format!("{label}: has no `lock-version`, so it is not a pylock.toml"))?;
    if lock_version.split('.').next() != Some("1") {
        return Err(format!(
            "{label}: lock-version {lock_version} is not supported"
        ));
    }
    let packages = array_of_tables(&doc, "packages")
        .map_err(|why| format!("{label}: {why}"))?
        .into_iter()
        .enumerate()
        .map(|(index, table)| pylock_package(table, index).map_err(|why| format!("{label}: {why}")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Lock {
        format: LockFormat::Pylock,
        files: vec![path.to_path_buf()],
        packages,
        requires_python: text_field(&doc, "requires-python"),
        python_pin: None,
        members: Vec::new(),
        index_urls: Vec::new(),
    })
}

fn pylock_package(pkg: &Table, index: usize) -> Result<LockedPackage, String> {
    let name = package_name(pkg, index)?;
    let fail = |why: String| format!("package `{name}` {why}");
    let vcs = sub_table(pkg, "vcs").map_err(&fail)?;
    let directory = sub_table(pkg, "directory").map_err(&fail)?;
    let archive = sub_table(pkg, "archive").map_err(&fail)?;
    let sdist = sub_table(pkg, "sdist").map_err(&fail)?;
    let wheels = array_of_tables(pkg, "wheels").map_err(&fail)?;
    let distributions = sdist.is_some() || !wheels.is_empty();
    let kinds = [
        vcs.is_some(),
        directory.is_some(),
        archive.is_some(),
        distributions,
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if kinds == 0 {
        return Err(fail(
            "names no source (vcs, directory, archive, sdist or wheels)".into(),
        ));
    }
    if kinds > 1 {
        return Err(fail("names more than one kind of source".into()));
    }

    let mut files = Vec::new();
    let source = if let Some(vcs) = vcs {
        let url = text_field(vcs, "url")
            .or_else(|| text_field(vcs, "path"))
            .ok_or_else(|| fail("has a `vcs` source with no `url` or `path`".into()))?;
        PackageSource::Vcs { url }
    } else if let Some(directory) = directory {
        let path = text_field(directory, "path")
            .ok_or_else(|| fail("has a `directory` source with no `path`".into()))?;
        let editable = directory
            .get("editable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        PackageSource::Directory { path, editable }
    } else if let Some(archive) = archive {
        let location = text_field(archive, "url")
            .or_else(|| text_field(archive, "path"))
            .ok_or_else(|| fail("has an `archive` source with no `url` or `path`".into()))?;
        files.push(pylock_file(archive, None).map_err(&fail)?);
        PackageSource::Archive { location }
    } else {
        if let Some(sdist) = sdist {
            files.push(pylock_file(sdist, Some(FileKind::Sdist)).map_err(&fail)?);
        }
        for wheel in wheels {
            files.push(pylock_file(wheel, Some(FileKind::Wheel)).map_err(&fail)?);
        }
        PackageSource::Registry {
            index: text_field(pkg, "index"),
        }
    };

    let dependencies = array_of_tables(pkg, "dependencies")
        .map_err(&fail)?
        .into_iter()
        .map(|dep| {
            let dep_name = text_field(dep, "name")
                .ok_or_else(|| fail("has a dependency with no `name`".into()))?;
            Ok(LockedDependency {
                name: dep_name,
                version: text_field(dep, "version"),
                marker: text_field(dep, "marker"),
                extras: Vec::new(),
                kind: DependencyKind::Required,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(LockedPackage {
        version: text_field(pkg, "version"),
        marker: text_field(pkg, "marker"),
        requires_python: text_field(pkg, "requires-python"),
        source,
        files,
        hashes: Vec::new(),
        dependencies,
        resolution_markers: Vec::new(),
        name,
    })
}

/// Reads a pylock `sdist`, `wheels` or `archive` entry. `kind` is `None` for an archive, whose
/// kind follows from its file name.
fn pylock_file(table: &Table, kind: Option<FileKind>) -> Result<LockedFile, String> {
    let url = text_field(table, "url");
    let filename = text_field(table, "name")
        .or_else(|| url.as_deref().and_then(url_file_name))
        .or_else(|| {
            text_field(table, "path")
                .as_deref()
                .and_then(path_file_name)
        })
        .ok_or_else(|| "lists an artifact with no file name".to_string())?;
    let kind = kind.unwrap_or_else(|| kind_of_file(&filename));
    let sha256 = match table.get("hashes") {
        None => None,
        Some(Value::Table(hashes)) => match hashes.get("sha256") {
            None => None,
            Some(Value::String(hex)) => Some(sha256_hex(hex)?),
            Some(_) => return Err("has a sha256 hash that is not a string".into()),
        },
        Some(_) => return Err("has `hashes` that is not a table".into()),
    };
    Ok(LockedFile {
        kind,
        filename,
        url,
        sha256,
        size: size_field(table),
    })
}

// poetry.lock

fn read_poetry_lock(text: &str, path: &Path, label: &str) -> Result<Lock, String> {
    let doc = parse_toml(text, label)?;
    let Some(Value::Table(metadata)) = doc.get("metadata") else {
        return Err(format!(
            "{label}: has no [metadata] table, so it is not a poetry.lock"
        ));
    };
    let legacy_files = match metadata.get("files") {
        Some(Value::Table(files)) => Some(files),
        _ => None,
    };
    let mut packages = Vec::new();
    let mut index_urls = Vec::new();
    for (index, table) in array_of_tables(&doc, "package")
        .map_err(|why| format!("{label}: {why}"))?
        .into_iter()
        .enumerate()
    {
        let package =
            poetry_package(table, index, legacy_files).map_err(|why| format!("{label}: {why}"))?;
        if let PackageSource::Registry { index: Some(url) } = &package.source {
            push_unique(&mut index_urls, url);
        }
        packages.push(package);
    }
    Ok(Lock {
        format: LockFormat::PoetryLock,
        files: vec![path.to_path_buf()],
        packages,
        requires_python: text_field(metadata, "python-versions")
            .and_then(|constraint| poetry_constraint_to_pep440(&constraint)),
        python_pin: None,
        members: Vec::new(),
        index_urls,
    })
}

fn poetry_package(
    pkg: &Table,
    index: usize,
    legacy_files: Option<&Table>,
) -> Result<LockedPackage, String> {
    let name = package_name(pkg, index)?;
    let fail = |why: String| format!("package `{name}` {why}");
    let develop = pkg.get("develop").and_then(Value::as_bool).unwrap_or(false);
    let source = match sub_table(pkg, "source").map_err(&fail)? {
        None => PackageSource::Registry { index: None },
        Some(source) => poetry_source(source, develop).map_err(&fail)?,
    };
    let file_list = match pkg.get("files") {
        Some(files) => Some(files),
        None => legacy_files.and_then(|files| {
            files.get(&name).or_else(|| {
                let key = normalize_name(&name);
                files
                    .iter()
                    .find(|(listed, _)| normalize_name(listed) == key)
                    .map(|(_, value)| value)
            })
        }),
    };
    let files = poetry_files(file_list).map_err(&fail)?;
    let dependencies = poetry_dependencies(pkg).map_err(&fail)?;
    Ok(LockedPackage {
        version: text_field(pkg, "version"),
        marker: poetry_package_marker(pkg),
        requires_python: text_field(pkg, "python-versions")
            .and_then(|constraint| poetry_constraint_to_pep440(&constraint)),
        source,
        files,
        hashes: Vec::new(),
        dependencies,
        resolution_markers: Vec::new(),
        name,
    })
}

fn poetry_source(source: &Table, develop: bool) -> Result<PackageSource, String> {
    let url = text_field(source, "url");
    let need_url = |kind: &str| {
        url.clone()
            .ok_or_else(|| format!("has a `{kind}` source with no `url`"))
    };
    match text_field(source, "type").as_deref() {
        Some("legacy") => Ok(PackageSource::Registry { index: url.clone() }),
        Some("git") => Ok(PackageSource::Vcs {
            url: need_url("git")?,
        }),
        Some("directory") => Ok(PackageSource::Directory {
            path: need_url("directory")?,
            editable: develop
                || source
                    .get("develop")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
        }),
        Some(kind @ ("file" | "url")) => Ok(PackageSource::Archive {
            location: need_url(kind)?,
        }),
        Some(other) => Err(format!("has a source of unknown type `{other}`")),
        None => Err("has a `source` with no `type`".into()),
    }
}

fn poetry_files(value: Option<&Value>) -> Result<Vec<LockedFile>, String> {
    let items = match value {
        None => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return Err("has `files` that is not an array".into()),
    };
    items
        .iter()
        .map(|item| {
            let table = item
                .as_table()
                .ok_or("has a file entry that is not a table")?;
            let url = text_field(table, "url");
            let filename = text_field(table, "file")
                .or_else(|| url.as_deref().and_then(url_file_name))
                .ok_or("lists a file with no `file` name")?;
            let sha256 = match text_field(table, "hash") {
                Some(hash) => prefixed_sha256(&hash)?,
                None => None,
            };
            Ok(LockedFile {
                kind: kind_of_file(&filename),
                filename,
                url,
                sha256,
                size: size_field(table),
            })
        })
        .collect()
}

/// The package-level marker of a poetry package. Poetry 2 writes a table from dependency group to
/// marker; a group of the package with no entry there takes the package unconditionally.
fn poetry_package_marker(pkg: &Table) -> Option<String> {
    let table = match pkg.get("markers")? {
        Value::String(marker) => return non_empty(marker),
        Value::Table(table) => table,
        _ => return None,
    };
    let groups = strings(pkg.get("groups"));
    let mut markers: Vec<String> = Vec::new();
    if groups.is_empty() {
        for group in sorted_keys(table) {
            if let Some(marker) = table.get(group).and_then(Value::as_str).and_then(non_empty) {
                push_unique(&mut markers, &marker);
            }
        }
    } else {
        for group in &groups {
            let marker = table
                .get(group)
                .and_then(Value::as_str)
                .and_then(non_empty)?;
            push_unique(&mut markers, &marker);
        }
    }
    match markers.len() {
        0 => None,
        1 => markers.pop(),
        _ => Some(
            markers
                .iter()
                .map(|marker| format!("({marker})"))
                .collect::<Vec<_>>()
                .join(" or "),
        ),
    }
}

fn poetry_dependencies(pkg: &Table) -> Result<Vec<LockedDependency>, String> {
    let Some(deps) = sub_table(pkg, "dependencies")? else {
        return Ok(Vec::new());
    };
    let extras_naming = poetry_extras(pkg)?;
    let mut out = Vec::new();
    for name in sorted_keys(deps) {
        let constraints: Vec<&Value> = match &deps[name] {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        for constraint in constraints {
            let (marker, optional, extras) = match constraint {
                Value::String(_) => (None, false, Vec::new()),
                Value::Table(table) => (
                    both_markers(
                        text_field(table, "markers"),
                        text_field(table, "python").and_then(|python| poetry_python_marker(&python)),
                    ),
                    table.get("optional").and_then(Value::as_bool).unwrap_or(false),
                    strings(table.get("extras")),
                ),
                _ => {
                    return Err(format!(
                        "has dependency `{name}` with a constraint that is neither a string nor a table"
                    ))
                }
            };
            let dependency = |kind| LockedDependency {
                name: name.clone(),
                version: None,
                marker: marker.clone(),
                extras: extras.clone(),
                kind,
            };
            if optional {
                // An optional dependency is installed only through the extras that name it; one
                // that no extra names is never installed and records no edge.
                for extra in extras_naming
                    .get(&normalize_name(name))
                    .into_iter()
                    .flatten()
                {
                    out.push(dependency(DependencyKind::Extra(extra.clone())));
                }
            } else {
                out.push(dependency(DependencyKind::Required));
            }
        }
    }
    Ok(out)
}

/// Maps each normalized dependency name to the extras of `[package.extras]` that name it.
fn poetry_extras(pkg: &Table) -> Result<HashMap<String, Vec<String>>, String> {
    let mut naming: HashMap<String, Vec<String>> = HashMap::new();
    let Some(extras) = sub_table(pkg, "extras")? else {
        return Ok(naming);
    };
    for extra in sorted_keys(extras) {
        for requirement in strings(extras.get(extra)) {
            if let Some(name) = leading_name(&requirement) {
                let listed = naming.entry(normalize_name(name)).or_default();
                if !listed.contains(extra) {
                    listed.push(extra.clone());
                }
            }
        }
    }
    Ok(naming)
}

/// Converts a poetry version constraint to a PEP 440 specifier set. Caret and tilde become
/// ranges (`^3.10` is `>=3.10,<4.0`, `~3.10` is `>=3.10,<3.11`), a bare version or `=` becomes
/// `==`, and clauses separated by commas or spaces are joined with commas. `*`, an empty
/// constraint, a `||` union and anything unparsable give `None`.
fn poetry_constraint_to_pep440(constraint: &str) -> Option<String> {
    let constraint = constraint.trim();
    if constraint.contains('|') {
        return None;
    }
    let mut clauses = Vec::new();
    for part in constraint.split(',') {
        for clause in poetry_and_clauses(part) {
            clauses.extend(poetry_clause(&clause)?);
        }
    }
    if clauses.is_empty() {
        None
    } else {
        Some(clauses.join(","))
    }
}

/// Splits one comma-separated part of a poetry constraint on whitespace, keeping an operator
/// written apart from its version (`>= 3.8`) attached to it.
fn poetry_and_clauses(part: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut operator = String::new();
    for token in part.split_whitespace() {
        if token.chars().all(|c| "<>=!~^".contains(c)) {
            operator.push_str(token);
            continue;
        }
        out.push(format!("{operator}{token}"));
        operator.clear();
    }
    if !operator.is_empty() {
        out.push(operator);
    }
    out
}

/// Converts one poetry clause. `Some(vec![])` means the clause is unconstrained (`*`).
fn poetry_clause(clause: &str) -> Option<Vec<String>> {
    if clause == "*" {
        return Some(Vec::new());
    }
    if let Some(version) = clause.strip_prefix('^') {
        let parts = release_parts(version);
        let position = match parts.as_slice() {
            [] => return None,
            [major, ..] if *major > 0 => 0,
            [_] => 0,
            [_, minor, ..] if *minor > 0 => 1,
            [_, _] => 1,
            _ => 2,
        };
        let upper = bump_release(&parts, position)?;
        return is_version(version).then(|| vec![format!(">={version}"), format!("<{upper}")]);
    }
    if let Some(version) = clause.strip_prefix("~=") {
        return is_version(version).then(|| vec![format!("~={version}")]);
    }
    if let Some(version) = clause.strip_prefix('~') {
        let parts = release_parts(version);
        let position = if parts.len() == 1 { 0 } else { 1 };
        let upper = bump_release(&parts, position)?;
        return is_version(version).then(|| vec![format!(">={version}"), format!("<{upper}")]);
    }
    for operator in ["===", "==", "!=", ">=", "<=", ">", "<"] {
        if let Some(version) = clause.strip_prefix(operator) {
            return is_version(version).then(|| vec![format!("{operator}{version}")]);
        }
    }
    let version = clause.strip_prefix('=').unwrap_or(clause);
    is_version(version).then(|| vec![format!("=={version}")])
}

/// Turns a poetry `python` constraint on a dependency into a PEP 508 marker. A `||` union
/// becomes an `or` of its branches. `None` when unconstrained or not representable.
fn poetry_python_marker(constraint: &str) -> Option<String> {
    let mut branches: Vec<Vec<String>> = Vec::new();
    for branch in constraint
        .split('|')
        .map(str::trim)
        .filter(|b| !b.is_empty())
    {
        let specifiers = poetry_constraint_to_pep440(branch)?;
        let clauses = specifiers
            .split(',')
            .map(python_clause_marker)
            .collect::<Option<Vec<_>>>()?;
        branches.push(clauses);
    }
    match branches.len() {
        0 => None,
        1 => Some(branches[0].join(" and ")),
        _ => Some(
            branches
                .iter()
                .map(|clauses| {
                    if clauses.len() > 1 {
                        format!("({})", clauses.join(" and "))
                    } else {
                        clauses.join(" and ")
                    }
                })
                .collect::<Vec<_>>()
                .join(" or "),
        ),
    }
}

/// Renders one PEP 440 clause (`>=3.8`) as a marker comparison on the Python version. A version
/// with more than two release segments compares against `python_full_version`.
fn python_clause_marker(clause: &str) -> Option<String> {
    let at = clause.find(|c: char| c.is_ascii_digit())?;
    let (operator, version) = clause.split_at(at);
    if operator.is_empty() {
        return None;
    }
    let field = if release_parts(version).len() > 2 {
        "python_full_version"
    } else {
        "python_version"
    };
    Some(format!("{field} {operator} \"{version}\""))
}

// pdm.lock

fn read_pdm_lock(text: &str, path: &Path, label: &str) -> Result<Lock, String> {
    let doc = parse_toml(text, label)?;
    let Some(Value::Table(metadata)) = doc.get("metadata") else {
        return Err(format!(
            "{label}: has no [metadata] table, so it is not a pdm.lock"
        ));
    };
    let requires_python = match metadata.get("targets") {
        Some(Value::Array(targets)) => targets
            .first()
            .and_then(Value::as_table)
            .and_then(|target| text_field(target, "requires_python")),
        _ => None,
    }
    .or_else(|| text_field(metadata, "requires_python"));

    let mut packages: Vec<LockedPackage> = Vec::new();
    let mut extra_entries: Vec<(Vec<String>, LockedPackage)> = Vec::new();
    for (index, table) in array_of_tables(&doc, "package")
        .map_err(|why| format!("{label}: {why}"))?
        .into_iter()
        .enumerate()
    {
        let package = pdm_package(table, index).map_err(|why| format!("{label}: {why}"))?;
        let extras = strings(table.get("extras"));
        if extras.is_empty() {
            packages.push(package);
        } else {
            extra_entries.push((extras, package));
        }
    }
    // PDM records a package's requested extras as a second entry of the same name and version
    // with `extras = [..]`. Its dependencies become the base package's edges for those extras.
    for (extras, entry) in extra_entries {
        let key = normalize_name(&entry.name);
        let Some(base) = packages
            .iter_mut()
            .find(|p| normalize_name(&p.name) == key && p.version == entry.version)
        else {
            packages.push(entry);
            continue;
        };
        for dep in entry.dependencies {
            let dep_key = normalize_name(&dep.name);
            let already_required = base.dependencies.iter().any(|existing| {
                existing.kind == DependencyKind::Required
                    && normalize_name(&existing.name) == dep_key
                    && existing.marker == dep.marker
            });
            if dep_key == key || already_required {
                continue;
            }
            for extra in &extras {
                let edge = LockedDependency {
                    kind: DependencyKind::Extra(extra.clone()),
                    ..dep.clone()
                };
                if !base.dependencies.contains(&edge) {
                    base.dependencies.push(edge);
                }
            }
        }
    }
    Ok(Lock {
        format: LockFormat::PdmLock,
        files: vec![path.to_path_buf()],
        packages,
        requires_python,
        python_pin: None,
        members: Vec::new(),
        index_urls: Vec::new(),
    })
}

fn pdm_package(pkg: &Table, index: usize) -> Result<LockedPackage, String> {
    let name = package_name(pkg, index)?;
    let fail = |why: String| format!("package `{name}` {why}");
    let source = if let Some(url) = text_field(pkg, "git") {
        PackageSource::Vcs { url }
    } else if let Some(path) = text_field(pkg, "path") {
        if is_archive_name(&path) {
            PackageSource::Archive { location: path }
        } else {
            let editable = pkg
                .get("editable")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            PackageSource::Directory { path, editable }
        }
    } else if let Some(location) = text_field(pkg, "url") {
        PackageSource::Archive { location }
    } else {
        PackageSource::Registry { index: None }
    };

    let files = array_of_tables(pkg, "files")
        .map_err(&fail)?
        .into_iter()
        .map(|entry| {
            let url = text_field(entry, "url");
            let filename = text_field(entry, "file")
                .or_else(|| url.as_deref().and_then(url_file_name))
                .ok_or_else(|| fail("lists a file with no `file` or `url`".into()))?;
            let sha256 = match text_field(entry, "hash") {
                Some(hash) => prefixed_sha256(&hash).map_err(&fail)?,
                None => None,
            };
            Ok(LockedFile {
                kind: kind_of_file(&filename),
                filename,
                url,
                sha256,
                size: size_field(entry),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let dependencies = match pkg.get("dependencies") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                let text = item
                    .as_str()
                    .ok_or_else(|| fail("has a dependency that is not a string".into()))?;
                let parsed = parse_pep508(text)
                    .map_err(|why| fail(format!("has dependency `{text}`, which {why}")))?;
                Ok(LockedDependency {
                    name: parsed.name,
                    version: None,
                    marker: parsed.marker,
                    extras: parsed.extras,
                    kind: DependencyKind::Required,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        Some(_) => return Err(fail("has `dependencies` that is not an array".into())),
    };

    Ok(LockedPackage {
        version: text_field(pkg, "version"),
        marker: text_field(pkg, "marker"),
        requires_python: text_field(pkg, "requires_python"),
        source,
        files,
        hashes: Vec::new(),
        dependencies,
        resolution_markers: Vec::new(),
        name,
    })
}

// Pipfile.lock

fn read_pipfile_lock(text: &str, path: &Path, label: &str) -> Result<Lock, String> {
    let doc: JsonValue =
        serde_json::from_str(text).map_err(|err| format!("{label}: invalid JSON: {err}"))?;
    let Some(root) = doc.as_object() else {
        return Err(format!(
            "{label}: is not a JSON object, so it is not a Pipfile.lock"
        ));
    };
    let Some(meta) = root.get("_meta").and_then(JsonValue::as_object) else {
        return Err(format!(
            "{label}: has no `_meta` object, so it is not a Pipfile.lock"
        ));
    };
    let python_pin = meta
        .get("requires")
        .and_then(JsonValue::as_object)
        .and_then(|requires| {
            json_text(requires, "python_full_version")
                .or_else(|| json_text(requires, "python_version"))
        });

    let mut sources: Vec<(String, String)> = Vec::new();
    let mut index_urls = Vec::new();
    for source in meta
        .get("sources")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_object)
    {
        if let Some(url) = json_text(source, "url") {
            push_unique(&mut index_urls, &url);
            if let Some(name) = json_text(source, "name") {
                sources.push((name, url));
            }
        }
    }

    let mut packages = Vec::new();
    let mut seen = HashSet::new();
    for section in ["default", "develop"] {
        let entries = match root.get(section) {
            None => continue,
            Some(JsonValue::Object(entries)) => entries,
            Some(_) => return Err(format!("{label}: `{section}` is not an object")),
        };
        let mut names: Vec<&String> = entries.keys().collect();
        names.sort();
        for name in names {
            if !seen.insert(normalize_name(name)) {
                continue;
            }
            let package = pipfile_package(name, &entries[name.as_str()], &sources)
                .map_err(|why| format!("{label}: {why}"))?;
            packages.push(package);
        }
    }

    Ok(Lock {
        format: LockFormat::PipfileLock,
        files: vec![path.to_path_buf()],
        packages,
        requires_python: None,
        python_pin,
        members: Vec::new(),
        index_urls,
    })
}

fn pipfile_package(
    name: &str,
    entry: &JsonValue,
    sources: &[(String, String)],
) -> Result<LockedPackage, String> {
    let fail = |why: String| format!("package `{name}` {why}");
    let Some(entry) = entry.as_object() else {
        return Err(fail("is not an object".into()));
    };
    let version = match json_text(entry, "version") {
        None => None,
        Some(written) => Some(
            exact_pin(&written)
                .map_err(|why| fail(format!("has version `{written}`, which {why}")))?,
        ),
    };
    let source = if let Some(path) = json_text(entry, "path") {
        if is_archive_name(&path) {
            PackageSource::Archive { location: path }
        } else {
            let editable = entry
                .get("editable")
                .and_then(JsonValue::as_bool)
                .unwrap_or(false);
            PackageSource::Directory { path, editable }
        }
    } else if let Some(url) = json_text(entry, "git") {
        PackageSource::Vcs { url }
    } else if let Some(location) = json_text(entry, "file") {
        PackageSource::Archive { location }
    } else {
        if version.is_none() {
            return Err(fail("has no pinned `version`".into()));
        }
        let index = json_text(entry, "index").and_then(|wanted| {
            sources
                .iter()
                .find(|(source_name, _)| *source_name == wanted)
                .map(|(_, url)| url.clone())
        });
        PackageSource::Registry { index }
    };
    let mut hashes = Vec::new();
    for hash in entry
        .get("hashes")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
    {
        if let Some(hex) = prefixed_sha256(hash).map_err(&fail)? {
            push_unique(&mut hashes, &hex);
        }
    }
    Ok(LockedPackage {
        name: name.to_owned(),
        version,
        source,
        marker: json_text(entry, "markers"),
        requires_python: None,
        files: Vec::new(),
        hashes,
        dependencies: Vec::new(),
        resolution_markers: Vec::new(),
    })
}

// Requirements files

fn read_requirements(
    paths: &[PathBuf],
    read: &dyn Fn(&Path) -> Option<String>,
    base: Option<&Path>,
) -> Result<Lock, String> {
    let Some(first) = paths.first() else {
        return Err("no requirements file was given".into());
    };
    let mut walk = RequirementsWalk {
        read,
        base,
        visited: HashSet::new(),
        files: Vec::new(),
        lines: Vec::new(),
        index_urls: Vec::new(),
    };
    for path in paths {
        walk.visit(path, Role::Requirement, None)?;
    }
    let RequirementsWalk {
        files,
        lines,
        index_urls,
        ..
    } = walk;
    let packages = settle_requirements(lines)?;
    if packages.is_empty() {
        return Err(format!(
            "{}: names no requirements",
            shown_path(&lexical_normal(first), base)
        ));
    }
    Ok(Lock {
        format: LockFormat::Requirements,
        files,
        packages,
        requires_python: None,
        python_pin: None,
        members: Vec::new(),
        index_urls,
    })
}

/// Whether a file was reached as requirements or as constraints (`-c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Role {
    Requirement,
    Constraint,
}

/// How a requirement line pins what it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pin {
    /// An exact `==` version; it still needs a digest.
    Exact,
    /// A version constraint that is not an exact pin, with the reason.
    Loose(&'static str),
    /// A relative local path or an editable local project: it needs no pin or digest.
    Local,
    /// A direct archive URL: the URL names one artifact, which still needs a digest.
    Archive,
    /// A VCS URL; `true` when it names a full commit.
    Vcs(bool),
    /// An absolute path or `file:` URL, which names nothing inside the repository.
    Outside,
}

/// One requirement or constraint line, before constraints apply and duplicates merge.
#[derive(Debug, Clone)]
struct RequirementLine {
    /// The file that holds the line, as messages name it.
    file: String,
    /// The requirement as written, without its options.
    text: String,
    name: String,
    version: Option<String>,
    source: PackageSource,
    pin: Pin,
    marker: Option<String>,
    hashes: Vec<String>,
}

impl RequirementLine {
    fn into_package(self) -> LockedPackage {
        LockedPackage {
            name: self.name,
            version: self.version,
            source: self.source,
            marker: self.marker,
            requires_python: None,
            files: Vec::new(),
            hashes: self.hashes,
            dependencies: Vec::new(),
            resolution_markers: Vec::new(),
        }
    }
}

/// What a requirement names, before the line's file, text and hashes are attached.
struct Named {
    name: String,
    version: Option<String>,
    source: PackageSource,
    pin: Pin,
    marker: Option<String>,
    /// Digests carried inside a direct URL (`#sha256=`).
    url_hashes: Vec<String>,
}

struct RequirementsWalk<'a> {
    read: &'a dyn Fn(&Path) -> Option<String>,
    /// The directory messages name paths relative to, and a second place to look for an in-repo
    /// project's metadata.
    base: Option<&'a Path>,
    visited: HashSet<(PathBuf, Role)>,
    files: Vec<PathBuf>,
    lines: Vec<(Role, RequirementLine)>,
    index_urls: Vec<String>,
}

impl RequirementsWalk<'_> {
    /// Reads one file and every file it includes. `via` names the including file and line.
    fn visit(&mut self, path: &Path, role: Role, via: Option<(&str, &str)>) -> Result<(), String> {
        let path = lexical_normal(path);
        if !self.visited.insert((path.clone(), role)) {
            return Ok(());
        }
        let file = shown_path(&path, self.base);
        let Some(text) = (self.read)(&path) else {
            return Err(match via {
                Some((from, line)) => format!("{from}: `{line}` names a file that cannot be read"),
                None => format!("{file}: cannot be read"),
            });
        };
        if !self.files.contains(&path) {
            self.files.push(path.clone());
        }
        for line in logical_lines(&text) {
            self.line(&line, &path, &file, role)?;
        }
        Ok(())
    }

    fn line(&mut self, line: &str, path: &Path, file: &str, role: Role) -> Result<(), String> {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.first().is_some_and(|token| token.starts_with('-')) {
            return self.options(&tokens, line, path, file, role);
        }
        let split = tokens
            .iter()
            .position(|token| token.starts_with('-'))
            .unwrap_or(tokens.len());
        let text = tokens[..split].join(" ");
        let mut hashes =
            line_hashes(&tokens[split..]).map_err(|why| format!("{file}: `{text}` {why}"))?;
        let named = self
            .requirement(&text, path)
            .map_err(|why| format!("{file}: `{text}` {why}"))?;
        extend_unique(&mut hashes, named.url_hashes);
        self.lines.push((
            role,
            RequirementLine {
                file: file.to_owned(),
                text,
                name: named.name,
                version: named.version,
                source: named.source,
                pin: named.pin,
                marker: named.marker,
                hashes,
            },
        ));
        Ok(())
    }

    /// Handles a line of options. Only includes, index URLs and editables matter to a lock;
    /// every other option is skipped with any values that follow it.
    fn options(
        &mut self,
        tokens: &[&str],
        line: &str,
        path: &Path,
        file: &str,
        role: Role,
    ) -> Result<(), String> {
        let mut i = 0;
        while i < tokens.len() {
            let (option, inline) = split_option(tokens[i]);
            i += 1;
            let known = matches!(
                option,
                "-r" | "--requirement"
                    | "-c"
                    | "--constraint"
                    | "-i"
                    | "--index-url"
                    | "--extra-index-url"
                    | "-e"
                    | "--editable"
            );
            if !known {
                while i < tokens.len() && !tokens[i].starts_with('-') {
                    i += 1;
                }
                continue;
            }
            let value = match inline {
                Some(value) => value,
                None => {
                    let Some(value) = tokens.get(i) else {
                        return Err(format!("{file}: `{line}` gives `{option}` no value"));
                    };
                    i += 1;
                    value
                }
            };
            match option {
                "-r" | "--requirement" => self.include(value, line, path, file, role)?,
                "-c" | "--constraint" => self.include(value, line, path, file, Role::Constraint)?,
                "-i" | "--index-url" | "--extra-index-url" => {
                    push_unique(&mut self.index_urls, value)
                }
                _ => {
                    let text = format!("-e {value}");
                    let named = self
                        .editable(value, path)
                        .map_err(|why| format!("{file}: `{text}` {why}"))?;
                    self.lines.push((
                        role,
                        RequirementLine {
                            file: file.to_owned(),
                            text,
                            name: named.name,
                            version: named.version,
                            source: named.source,
                            pin: named.pin,
                            marker: named.marker,
                            hashes: named.url_hashes,
                        },
                    ));
                }
            }
        }
        Ok(())
    }

    fn include(
        &mut self,
        target: &str,
        line: &str,
        path: &Path,
        file: &str,
        role: Role,
    ) -> Result<(), String> {
        if has_url_scheme(target) {
            return Err(format!(
                "{file}: `{line}` includes a remote file, which is never fetched"
            ));
        }
        let included = parent_dir(path).join(target);
        self.visit(&included, role, Some((file, line)))
    }

    /// Classifies the requirement part of a line: a bare URL, a local path, `name @ url`, or a
    /// name with a version specifier.
    fn requirement(&self, text: &str, including: &Path) -> Result<Named, String> {
        let first_token = text
            .split(|c: char| c.is_whitespace() || c == ';')
            .next()
            .unwrap_or("");
        if has_url_scheme(text) {
            let (url, marker) = split_url_marker(text);
            let name = egg_name(&url)
                .or_else(|| url_file_name(&url).and_then(|file| name_from_filename(&file)))
                .ok_or("names no package")?;
            return Ok(direct_reference(name, &url, marker));
        }
        if looks_like_path(first_token) {
            let (path_text, marker) = split_url_marker(text);
            return Ok(self.local(&path_text, false, including, None, marker));
        }
        let parsed = parse_pep508(text)?;
        match parsed.url {
            Some(url) if has_url_scheme(&url) => {
                Ok(direct_reference(parsed.name, &url, parsed.marker))
            }
            Some(path_text) => Ok(self.local(
                &path_text,
                false,
                including,
                Some(parsed.name),
                parsed.marker,
            )),
            None => {
                let (pin, version) = match exact_pin(&parsed.specifier) {
                    Ok(version) => (Pin::Exact, Some(version)),
                    Err(why) => (Pin::Loose(why), None),
                };
                Ok(Named {
                    name: parsed.name,
                    version,
                    source: PackageSource::Registry { index: None },
                    pin,
                    marker: parsed.marker,
                    url_hashes: Vec::new(),
                })
            }
        }
    }

    fn editable(&self, value: &str, including: &Path) -> Result<Named, String> {
        if is_vcs_url(value) {
            let name = egg_name(value).ok_or("names no package (it has no `#egg=`)")?;
            return Ok(Named {
                name,
                version: None,
                source: PackageSource::Vcs {
                    url: value.to_owned(),
                },
                pin: Pin::Vcs(names_commit(value)),
                marker: None,
                url_hashes: Vec::new(),
            });
        }
        if has_url_scheme(value) {
            if !value.to_ascii_lowercase().starts_with("file:") {
                return Err("is an editable URL that is not a VCS checkout".into());
            }
            let name = egg_name(value).unwrap_or_else(|| value.to_owned());
            return Ok(Named {
                name,
                version: None,
                source: PackageSource::Directory {
                    path: value.to_owned(),
                    editable: true,
                },
                pin: Pin::Outside,
                marker: None,
                url_hashes: Vec::new(),
            });
        }
        Ok(self.local(value, true, including, None, None))
    }

    /// A local path requirement. The name is the one written (`name @ ./pkg`), else the local
    /// project's own metadata, else the path as written.
    fn local(
        &self,
        written: &str,
        editable: bool,
        including: &Path,
        name: Option<String>,
        marker: Option<String>,
    ) -> Named {
        let path = strip_extras(written);
        let pin = if is_absolute_like(path) {
            Pin::Outside
        } else {
            Pin::Local
        };
        if !editable && is_archive_name(path) {
            let filename = path_file_name(path).unwrap_or_else(|| path.to_owned());
            return Named {
                name: name
                    .or_else(|| name_from_filename(&filename))
                    .unwrap_or_else(|| path.to_owned()),
                version: version_from_filename(&filename),
                source: PackageSource::Archive {
                    location: path.to_owned(),
                },
                pin,
                marker,
                url_hashes: Vec::new(),
            };
        }
        let name = name
            .or_else(|| self.project_name(including, path))
            .unwrap_or_else(|| path.to_owned());
        Named {
            name,
            version: None,
            source: PackageSource::Directory {
                path: path.to_owned(),
                editable,
            },
            pin,
            marker,
            url_hashes: Vec::new(),
        }
    }

    /// Reads a local project's name from its `pyproject.toml` or `setup.cfg`, looking relative to
    /// the including file first and then relative to the base directory. It reads those files as
    /// text and never runs a build backend or `setup.py`.
    fn project_name(&self, including: &Path, dir: &str) -> Option<String> {
        let mut roots = vec![parent_dir(including).to_path_buf()];
        if let Some(base) = self.base {
            roots.push(base.to_path_buf());
        }
        roots.into_iter().find_map(|root| {
            let project = lexical_normal(&root.join(dir));
            (self.read)(&project.join("pyproject.toml"))
                .and_then(|text| pyproject_name(&text))
                .or_else(|| {
                    (self.read)(&project.join("setup.cfg")).and_then(|text| setup_cfg_name(&text))
                })
        })
    }
}

/// Applies constraints, checks that every requirement is locked, and merges duplicates. Lines are
/// handled in the order they were read, so the first offending line is the one reported.
fn settle_requirements(lines: Vec<(Role, RequirementLine)>) -> Result<Vec<LockedPackage>, String> {
    let mut constraints = Vec::new();
    let mut requirements = Vec::new();
    for (role, line) in lines {
        match role {
            Role::Constraint => constraints.push(line),
            Role::Requirement => requirements.push(line),
        }
    }
    let mut packages: Vec<LockedPackage> = Vec::new();
    let mut written: Vec<(String, String)> = Vec::new();
    for mut line in requirements {
        apply_constraint(&mut line, &constraints)?;
        check_locked(&line)?;
        let key = normalize_name(&line.name);
        let existing = packages.iter().position(|package| {
            normalize_name(&package.name) == key && package.marker == line.marker
        });
        match existing {
            Some(i) => {
                let package = &mut packages[i];
                if package.version != line.version || package.source != line.source {
                    let (file, text) = &written[i];
                    return Err(format!(
                        "{}: `{}` conflicts with `{text}` in {file}",
                        line.file, line.text
                    ));
                }
                extend_unique(&mut package.hashes, line.hashes);
            }
            None => {
                written.push((line.file.clone(), line.text.clone()));
                packages.push(line.into_package());
            }
        }
    }
    Ok(packages)
}

/// Lets an exact pin from a constraint file stand in for a registry requirement that has none,
/// and adds the constraint's digests.
fn apply_constraint(
    line: &mut RequirementLine,
    constraints: &[RequirementLine],
) -> Result<(), String> {
    if !matches!(line.source, PackageSource::Registry { .. }) {
        return Ok(());
    }
    let key = normalize_name(&line.name);
    let Some(constraint) = constraints.iter().find(|constraint| {
        constraint.pin == Pin::Exact
            && normalize_name(&constraint.name) == key
            && (constraint.marker.is_none() || constraint.marker == line.marker)
    }) else {
        return Ok(());
    };
    if line.pin == Pin::Exact && line.version != constraint.version {
        return Err(format!(
            "{}: `{}` conflicts with the constraint `{}` in {}",
            line.file, line.text, constraint.text, constraint.file
        ));
    }
    line.pin = Pin::Exact;
    line.version.clone_from(&constraint.version);
    extend_unique(&mut line.hashes, constraint.hashes.clone());
    Ok(())
}

fn check_locked(line: &RequirementLine) -> Result<(), String> {
    let why = match line.pin {
        Pin::Local | Pin::Vcs(true) => return Ok(()),
        Pin::Exact | Pin::Archive if !line.hashes.is_empty() => return Ok(()),
        Pin::Exact | Pin::Archive => "has no `--hash=sha256:` digest",
        Pin::Loose(why) => why,
        Pin::Vcs(false) => "does not pin a full VCS commit",
        Pin::Outside => "names an absolute path, not an in-repo path",
    };
    Err(format!("{}: `{}` {why}", line.file, line.text))
}

/// A direct URL requirement: a VCS checkout, a `file:` URL, or a remote archive.
fn direct_reference(name: String, url: &str, marker: Option<String>) -> Named {
    if is_vcs_url(url) {
        return Named {
            name,
            version: None,
            source: PackageSource::Vcs {
                url: url.to_owned(),
            },
            pin: Pin::Vcs(names_commit(url)),
            marker,
            url_hashes: Vec::new(),
        };
    }
    let filename = url_file_name(url);
    let version = filename.as_deref().and_then(version_from_filename);
    if url.to_ascii_lowercase().starts_with("file:") {
        let source = if is_archive_name(url) {
            PackageSource::Archive {
                location: url.to_owned(),
            }
        } else {
            PackageSource::Directory {
                path: url.to_owned(),
                editable: false,
            }
        };
        return Named {
            name,
            version,
            source,
            pin: Pin::Outside,
            marker,
            url_hashes: Vec::new(),
        };
    }
    Named {
        name,
        version,
        source: PackageSource::Archive {
            location: url.to_owned(),
        },
        pin: Pin::Archive,
        marker,
        url_hashes: fragment_sha256(url).into_iter().collect(),
    }
}

/// Joins continuation lines and strips comments the way pip does: a line ending in `\` continues
/// onto the next unless it holds a comment, and `#` starts a comment only at the start of a line
/// or after whitespace, so `#sha256=` and `#egg=` inside a URL survive.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut pending: Option<String> = None;
    for raw in text.lines() {
        let has_comment = comment_start(raw).is_some();
        if raw.ends_with('\\') && !has_comment {
            pending
                .get_or_insert_with(String::new)
                .push_str(&raw[..raw.len() - 1]);
            continue;
        }
        let full = match pending.take() {
            Some(mut joined) => {
                if has_comment {
                    joined.push(' ');
                }
                joined.push_str(raw);
                joined
            }
            None => raw.to_owned(),
        };
        push_logical(&mut out, &full);
    }
    if let Some(joined) = pending {
        push_logical(&mut out, &joined);
    }
    out
}

fn push_logical(out: &mut Vec<String>, line: &str) {
    let content = match comment_start(line) {
        Some(at) => &line[..at],
        None => line,
    };
    let content = content.trim();
    if !content.is_empty() {
        out.push(content.to_owned());
    }
}

/// The byte offset of the first `#` that starts a comment: at the start of the line or after
/// whitespace.
fn comment_start(line: &str) -> Option<usize> {
    let mut previous_is_space = true;
    for (at, c) in line.char_indices() {
        if c == '#' && previous_is_space {
            return Some(at);
        }
        previous_is_space = c.is_whitespace();
    }
    None
}

/// Splits `--name=value` into the option and its inline value, and `-rfile` into `-r` and
/// `file`.
fn split_option(token: &str) -> (&str, Option<&str>) {
    if token.starts_with("--") {
        return match token.split_once('=') {
            Some((option, value)) => (option, Some(value)),
            None => (token, None),
        };
    }
    if token.len() > 2 && token.is_char_boundary(2) {
        return (&token[..2], Some(&token[2..]));
    }
    (token, None)
}

/// The sha256 digests among the options that follow a requirement.
fn line_hashes(options: &[&str]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < options.len() {
        let token = options[i];
        i += 1;
        let value = if let Some(value) = token.strip_prefix("--hash=") {
            value
        } else if token == "--hash" {
            let Some(value) = options.get(i) else {
                return Err("gives `--hash` no value".into());
            };
            i += 1;
            value
        } else {
            continue;
        };
        if let Some(hex) = prefixed_sha256(value)? {
            push_unique(&mut out, &hex);
        }
    }
    Ok(out)
}

/// The version an exact `==` (or `===`) pin names, or why the specifier set is not one.
fn exact_pin(specifier: &str) -> Result<String, &'static str> {
    const NOT_PINNED: &str = "is not pinned with `==`";
    let specifier: String = specifier.chars().filter(|c| !c.is_whitespace()).collect();
    if specifier.contains(',') {
        return Err(NOT_PINNED);
    }
    let version = specifier
        .strip_prefix("===")
        .or_else(|| specifier.strip_prefix("=="))
        .filter(|version| !version.is_empty())
        .ok_or(NOT_PINNED)?;
    if version.contains('*') {
        return Err("pins a wildcard, not an exact version");
    }
    Ok(version.to_owned())
}

/// A PEP 508 requirement, split into its parts.
struct Pep508 {
    name: String,
    extras: Vec<String>,
    /// The version specifier set without whitespace or enclosing parentheses; empty when none.
    specifier: String,
    url: Option<String>,
    marker: Option<String>,
}

fn parse_pep508(text: &str) -> Result<Pep508, String> {
    let text = text.trim();
    let name_len = text
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(text.len());
    let name = &text[..name_len];
    if !is_valid_name(name) {
        return Err("does not start with a package name".into());
    }
    let mut rest = text[name_len..].trim_start();
    let mut extras = Vec::new();
    if let Some(after) = rest.strip_prefix('[') {
        let close = after.find(']').ok_or("has an unclosed `[`")?;
        extras = after[..close]
            .split(',')
            .map(str::trim)
            .filter(|extra| !extra.is_empty())
            .map(str::to_owned)
            .collect();
        rest = after[close + 1..].trim_start();
    }
    if let Some(after) = rest.strip_prefix('@') {
        let (url, marker) = split_url_marker(after.trim_start());
        if url.is_empty() {
            return Err("has `@` with no URL".into());
        }
        return Ok(Pep508 {
            name: name.to_owned(),
            extras,
            specifier: String::new(),
            url: Some(url),
            marker,
        });
    }
    let (specifier, marker) = match rest.split_once(';') {
        Some((specifier, marker)) => (specifier, non_empty(marker)),
        None => (rest, None),
    };
    let mut specifier: String = specifier.chars().filter(|c| !c.is_whitespace()).collect();
    if specifier.starts_with('(') && specifier.ends_with(')') {
        specifier = specifier[1..specifier.len() - 1].to_owned();
    }
    if !specifier.is_empty() && !specifier.starts_with(['<', '>', '=', '!', '~']) {
        return Err(format!(
            "has `{specifier}` where a version specifier belongs"
        ));
    }
    Ok(Pep508 {
        name: name.to_owned(),
        extras,
        specifier,
        url: None,
        marker,
    })
}

/// Splits a URL or path from a trailing marker. PEP 508 needs whitespace before the `;` here,
/// since a URL may itself hold a `;`.
fn split_url_marker(text: &str) -> (String, Option<String>) {
    let mut previous_is_space = false;
    for (at, c) in text.char_indices() {
        if c == ';' && previous_is_space {
            return (text[..at].trim().to_owned(), non_empty(&text[at + 1..]));
        }
        previous_is_space = c.is_whitespace();
    }
    (text.trim().to_owned(), None)
}

/// The name at the start of a requirement string such as `PySocks (>=1.5.6,!=1.5.7)`.
fn leading_name(requirement: &str) -> Option<&str> {
    let trimmed = requirement.trim_start();
    let end = trimmed
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(trimmed.len());
    let name = &trimmed[..end];
    is_valid_name(name).then_some(name)
}

/// Whether `name` is a valid PEP 508 distribution name.
fn is_valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    match (bytes.first(), bytes.last()) {
        (Some(first), Some(last)) => {
            first.is_ascii_alphanumeric()
                && last.is_ascii_alphanumeric()
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        }
        _ => false,
    }
}

/// Whether the first token of a requirement is a local path rather than a name.
fn looks_like_path(token: &str) -> bool {
    if let Some((before, _)) = token.split_once('@') {
        if is_valid_name(strip_extras(before.trim())) {
            return false;
        }
    }
    token.starts_with(['.', '/', '~', '\\'])
        || token.contains(['/', '\\'])
        || is_absolute_like(token)
        || is_archive_name(strip_extras(token))
}

/// Strips a trailing `[extras]` from a path such as `.[socks]`.
fn strip_extras(text: &str) -> &str {
    if text.ends_with(']') {
        if let Some(open) = text.rfind('[') {
            return &text[..open];
        }
    }
    text
}

fn is_absolute_like(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with(['/', '~', '\\'])
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
}

/// Whether `text` starts with a URL scheme (`https://`, `git+ssh://`, `file:`). A Windows drive
/// letter is not a scheme.
fn has_url_scheme(text: &str) -> bool {
    let Some((scheme, rest)) = text.split_once(':') else {
        return false;
    };
    scheme.len() > 1
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && (rest.starts_with("//") || scheme.eq_ignore_ascii_case("file"))
}

fn is_vcs_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    ["git+", "hg+", "svn+", "bzr+"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// Whether a VCS URL names a full commit id after `@` in its path.
fn names_commit(url: &str) -> bool {
    let without_fragment = url.split('#').next().unwrap_or(url);
    let after_scheme = without_fragment
        .split_once("://")
        .map_or(without_fragment, |(_, rest)| rest);
    let path = after_scheme.find('/').map_or("", |at| &after_scheme[at..]);
    match path.rsplit_once('@') {
        Some((_, revision)) => {
            matches!(revision.len(), 40 | 64) && revision.bytes().all(|b| b.is_ascii_hexdigit())
        }
        None => false,
    }
}

/// The project name in a URL's `#egg=` fragment.
fn egg_name(url: &str) -> Option<String> {
    let (_, fragment) = url.split_once('#')?;
    fragment
        .split('&')
        .find_map(|part| part.strip_prefix("egg="))
        .and_then(leading_name)
        .map(str::to_owned)
}

/// The lowercase sha256 hex in a URL's `#sha256=` fragment.
fn fragment_sha256(url: &str) -> Option<String> {
    let (_, fragment) = url.split_once('#')?;
    fragment
        .split('&')
        .find_map(|part| part.strip_prefix("sha256="))
        .and_then(|hex| sha256_hex(hex).ok())
}

/// The distribution name at the front of a wheel or sdist file name.
fn name_from_filename(filename: &str) -> Option<String> {
    if filename.to_ascii_lowercase().ends_with(".whl") {
        return filename
            .split('-')
            .next()
            .filter(|name| is_valid_name(name))
            .map(str::to_owned);
    }
    let stem = archive_stem(filename)?;
    match stem.rsplit_once('-') {
        Some((name, version)) if version.starts_with(|c: char| c.is_ascii_digit()) => {
            is_valid_name(name).then(|| name.to_owned())
        }
        _ => is_valid_name(stem).then(|| stem.to_owned()),
    }
}

/// The version in a wheel or sdist file name.
fn version_from_filename(filename: &str) -> Option<String> {
    if filename.to_ascii_lowercase().ends_with(".whl") {
        return filename
            .split('-')
            .nth(1)
            .filter(|version| version.starts_with(|c: char| c.is_ascii_digit()))
            .map(str::to_owned);
    }
    let (_, version) = archive_stem(filename)?.rsplit_once('-')?;
    version
        .starts_with(|c: char| c.is_ascii_digit())
        .then(|| version.to_owned())
}

fn archive_stem(filename: &str) -> Option<&str> {
    let lower = filename.to_ascii_lowercase();
    ARCHIVE_SUFFIXES
        .iter()
        .find(|suffix| lower.ends_with(*suffix))
        .map(|suffix| &filename[..filename.len() - suffix.len()])
}

fn pyproject_name(text: &str) -> Option<String> {
    let doc = text.parse::<Table>().ok()?;
    let project = doc.get("project").and_then(Value::as_table);
    let poetry = doc
        .get("tool")
        .and_then(Value::as_table)
        .and_then(|tool| tool.get("poetry"))
        .and_then(Value::as_table);
    project
        .and_then(|table| text_field(table, "name"))
        .or_else(|| poetry.and_then(|table| text_field(table, "name")))
}

fn setup_cfg_name(text: &str) -> Option<String> {
    let mut in_metadata = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_metadata = line == "[metadata]";
            continue;
        }
        if !in_metadata {
            continue;
        }
        if let Some((key, value)) = line.split_once(['=', ':']) {
            if key.trim() == "name" {
                return non_empty(value);
            }
        }
    }
    None
}

// find_lock helpers

/// `pylock.<name>.toml` files directly in `root`, sorted by name.
fn named_pylocks(root: &Path) -> Vec<PathBuf> {
    let mut names: Vec<String> = file_names_in(root)
        .into_iter()
        .filter(|name| {
            name.len() > "pylock..toml".len()
                && name.starts_with("pylock.")
                && name.ends_with(".toml")
        })
        .collect();
    names.sort();
    names.into_iter().map(|name| root.join(name)).collect()
}

/// Root `requirements*.txt` with `requirements.txt` first and the rest sorted, then `*.txt`
/// directly in a root `requirements/` directory, sorted.
fn requirements_files(root: &Path) -> Vec<PathBuf> {
    let mut top: Vec<String> = file_names_in(root)
        .into_iter()
        .filter(|name| name.starts_with("requirements") && name.ends_with(".txt"))
        .collect();
    top.sort_by(|a, b| {
        (a != "requirements.txt")
            .cmp(&(b != "requirements.txt"))
            .then_with(|| a.cmp(b))
    });
    let directory = root.join("requirements");
    let mut nested: Vec<String> = file_names_in(&directory)
        .into_iter()
        .filter(|name| name.ends_with(".txt"))
        .collect();
    nested.sort();
    top.into_iter()
        .map(|name| root.join(name))
        .chain(nested.into_iter().map(|name| directory.join(name)))
        .collect()
}

/// Names of the regular files directly in `dir`; empty when it cannot be listed.
fn file_names_in(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect()
}

// Shared helpers

const ARCHIVE_SUFFIXES: &[&str] = &[
    ".whl", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar.xz", ".txz", ".tar", ".zip",
];

/// Names `path` relative to `base` for messages, or as given when it is not under `base`.
fn shown_path(path: &Path, base: Option<&Path>) -> String {
    base.and_then(|base| path.strip_prefix(base).ok())
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or(path)
        .display()
        .to_string()
}

/// Resolves `.` and `..` components without touching the filesystem.
fn lexical_normal(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                } else {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn parent_dir(path: &Path) -> &Path {
    path.parent().unwrap_or_else(|| Path::new(""))
}

fn parse_toml(text: &str, label: &str) -> Result<Table, String> {
    text.parse::<Table>().map_err(|err| {
        let message = err.message().trim().to_owned();
        match err.span() {
            Some(span) => {
                let line = text[..span.start.min(text.len())].matches('\n').count() + 1;
                format!("{label}: invalid TOML at line {line}: {message}")
            }
            None => format!("{label}: invalid TOML: {message}"),
        }
    })
}

fn package_name(table: &Table, index: usize) -> Result<String, String> {
    text_field(table, "name").ok_or_else(|| format!("package {} has no `name`", index + 1))
}

/// A string field, trimmed, or `None` when absent, not a string, or empty.
fn text_field(table: &Table, key: &str) -> Option<String> {
    table.get(key).and_then(Value::as_str).and_then(non_empty)
}

fn json_text(object: &JsonMap<String, JsonValue>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(JsonValue::as_str)
        .and_then(non_empty)
}

fn non_empty(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// The strings of an array value; other items are skipped.
fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(non_empty)
        .collect()
}

fn sub_table<'a>(table: &'a Table, key: &str) -> Result<Option<&'a Table>, String> {
    match table.get(key) {
        None => Ok(None),
        Some(Value::Table(inner)) => Ok(Some(inner)),
        Some(_) => Err(format!("has a `{key}` that is not a table")),
    }
}

fn array_of_tables<'a>(table: &'a Table, key: &str) -> Result<Vec<&'a Table>, String> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_table()
                    .ok_or_else(|| format!("has a `{key}` entry that is not a table"))
            })
            .collect(),
        Some(_) => Err(format!("has a `{key}` that is not an array of tables")),
    }
}

/// A table's keys in sorted order, so output does not depend on how the TOML map is ordered.
fn sorted_keys(table: &Table) -> Vec<&String> {
    let mut keys: Vec<&String> = table.keys().collect();
    keys.sort();
    keys
}

fn size_field(table: &Table) -> Option<u64> {
    table
        .get("size")
        .and_then(Value::as_integer)
        .and_then(|size| u64::try_from(size).ok())
}

/// Reads an `algorithm:digest` (or `algorithm=digest`) hash. `Ok(None)` for an algorithm other
/// than sha256; Err for a malformed sha256 digest.
fn prefixed_sha256(hash: &str) -> Result<Option<String>, String> {
    let (algorithm, digest) = hash
        .split_once([':', '='])
        .ok_or_else(|| format!("has a hash `{hash}` with no algorithm"))?;
    if !algorithm.trim().eq_ignore_ascii_case("sha256") {
        return Ok(None);
    }
    sha256_hex(digest.trim()).map(Some)
}

fn sha256_hex(hex: &str) -> Result<String, String> {
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(hex.to_ascii_lowercase())
    } else {
        Err(format!("has a malformed sha256 digest `{hex}`"))
    }
}

fn kind_of_file(filename: &str) -> FileKind {
    if filename.to_ascii_lowercase().ends_with(".whl") {
        FileKind::Wheel
    } else {
        FileKind::Sdist
    }
}

/// Whether a path or URL names an archive file rather than a directory.
fn is_archive_name(location: &str) -> bool {
    let bare = location.split(['?', '#']).next().unwrap_or(location);
    let lower = bare.to_ascii_lowercase();
    ARCHIVE_SUFFIXES
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

/// The last path segment of a URL, without query or fragment, percent-decoded.
fn url_file_name(url: &str) -> Option<String> {
    let bare = url.split(['?', '#']).next().unwrap_or(url);
    let segment = bare.trim_end_matches('/').rsplit('/').next()?;
    (!segment.is_empty() && !segment.contains(':')).then(|| percent_decode(segment))
}

/// The last segment of a local path.
fn path_file_name(path: &str) -> Option<String> {
    let segment = path
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()?;
    (!segment.is_empty() && segment != "." && segment != "..").then(|| segment.to_owned())
}

fn percent_decode(text: &str) -> String {
    fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2])) {
                out.push(high * 16 + low);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_owned())
}

/// The numeric release segments at the front of a version: `3.10.*` gives `[3, 10]`, `1.2.3b1`
/// gives `[1, 2, 3]`.
fn release_parts(version: &str) -> Vec<u64> {
    let mut parts = Vec::new();
    for segment in version.trim().split('.') {
        let digits: String = segment.chars().take_while(char::is_ascii_digit).collect();
        let Ok(value) = digits.parse::<u64>() else {
            break;
        };
        parts.push(value);
        if digits.len() != segment.len() {
            break;
        }
    }
    parts
}

/// Increments the release segment at `position` and zeroes the ones after it, keeping the
/// number of segments written.
fn bump_release(parts: &[u64], position: usize) -> Option<String> {
    if position >= parts.len() {
        return None;
    }
    let mut upper = parts.to_vec();
    upper[position] += 1;
    for part in &mut upper[position + 1..] {
        *part = 0;
    }
    Some(
        upper
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// Whether `text` is shaped like a PEP 440 version, wildcards included.
fn is_version(text: &str) -> bool {
    !text.is_empty()
        && text.starts_with(|c: char| c.is_ascii_digit())
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '*' | '+' | '!' | '-' | '_'))
}

fn both_markers(first: Option<String>, second: Option<String>) -> Option<String> {
    match (first, second) {
        (Some(first), Some(second)) => Some(format!("({first}) and ({second})")),
        (first, second) => first.or(second),
    }
}

fn push_unique(list: &mut Vec<String>, item: &str) {
    if !list.iter().any(|existing| existing == item) {
        list.push(item.to_owned());
    }
}

fn extend_unique(list: &mut Vec<String>, items: Vec<String>) {
    for item in items {
        if !list.contains(&item) {
            list.push(item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const DIGESTS: [&str; 16] = [
        "042896dc1966b8a6214e5383aba5b8b931cfa049d17aafa37eb8a77c859b95da",
        "dba0082ec68e72d47fa926dcc91fb9b00961ceb4342554a0c2aa567144a5a6d3",
        "dfd5922f5aa9441e95d21ed58bb9f2209a004912a1232e89f75f725bd37f3d4a",
        "8c09b37123eb0d9dcec63788149e576b1614ed481ad002512d0a47a09cbf59fc",
        "c1db13ab836db24060490c83b83c089adb1ce9e6e1899d81e02d398cec22e6b1",
        "01dc6054f16adcd6557fd9261016d679b2b3ad2b4b1da6d19449e8ebe02697bf",
        "bf7be128c7d4dc05da04c62f93c864bf00620d58d53613b228ba8085440cf858",
        "f3bc822097333cae6697b15854e917ef62e98a4a6a6be0ca0cc616912f3dea9a",
        "4dc776a81b9ac9c85a9364a5050815faf826211393fae0b7fbce9b93f45a4cdf",
        "4e90553f9801bdb5a4ffd95a5bb57ae6da23a144e8849221bbde00d9dba4fad3",
        "8d26d2f8b050c0dab9a4626ab6353de65d4993860566f846fde81edf0e7250a0",
        "b6b3be77081f89dc5aee6cb88a482a41ccd0afc3f73c4c3e69ee67dc996753b7",
        "959b91529855d314ebd7551ab08b54e3f5947e0abc7a6161edcd53cf7f074c94",
        "877b597a012475756e14027c83ba9ade7ecc1c7d125a6569d99901cb33ffeff8",
        "083bc8089ae2d7c506faef53b53fe99665890f65bba67cc6990c16df3d51a6b8",
        "cb51c275c76049a1148449c960c8394ad6ac78489ea76e23aa9cff53e3d0c035",
    ];

    fn d(n: usize) -> String {
        DIGESTS[n - 1].to_owned()
    }

    /// Replaces `{dN}` with digest N and `{DN}` with its uppercase form.
    fn fill(text: &str) -> String {
        let mut out = text.to_owned();
        for (i, digest) in DIGESTS.iter().enumerate() {
            out = out.replace(&format!("{{d{}}}", i + 1), digest);
            out = out.replace(&format!("{{D{}}}", i + 1), &digest.to_ascii_uppercase());
        }
        out
    }

    fn package<'a>(lock: &'a Lock, name: &str) -> &'a LockedPackage {
        lock.packages
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("no package `{name}` in {:?}", lock.packages))
    }

    fn deps<'a>(package: &'a LockedPackage, name: &str) -> Vec<&'a LockedDependency> {
        package
            .dependencies
            .iter()
            .filter(|dep| dep.name == name)
            .collect()
    }

    fn registry(index: &str) -> PackageSource {
        PackageSource::Registry {
            index: Some(index.to_owned()),
        }
    }

    fn reader(files: &[(&str, &str)]) -> impl Fn(&Path) -> Option<String> {
        let map: HashMap<PathBuf, String> = files
            .iter()
            .map(|(path, text)| (PathBuf::from(path), fill(text)))
            .collect();
        move |path: &Path| map.get(path).cloned()
    }

    fn requirements(files: &[(&str, &str)], roots: &[&str]) -> Result<Lock, String> {
        let read = reader(files);
        let paths: Vec<PathBuf> = roots.iter().map(PathBuf::from).collect();
        parse_requirements(&paths, &read)
    }

    /// A scratch directory under the system temp dir, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "lockfile-test-{}-{tag}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn write(&self, relative: &str, text: &str) {
            let path = self.0.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, fill(text)).unwrap();
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const UV_WORKSPACE: &str = r#"version = 1
revision = 3
requires-python = ">=3.10"
resolution-markers = [
    "python_full_version >= '3.12'",
    "python_full_version < '3.12'",
]

[manifest]
members = [
    "demo",
    "demo-lib",
]

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "demo-lib" },
    { name = "numpy", version = "1.26.4", source = { registry = "https://pypi.org/simple" }, marker = "python_full_version < '3.12'" },
    { name = "numpy", version = "2.1.0", source = { registry = "https://pypi.org/simple" }, marker = "python_full_version >= '3.12'" },
]

[package.optional-dependencies]
cuda = [
    { name = "torch", extra = ["cuda"] },
]
socks = [
    { name = "pysocks" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
]
lint = [
    { name = "ruff", marker = "sys_platform != 'win32'" },
]

[package.metadata]
requires-dist = [
    { name = "numpy", specifier = ">=1.26" },
    { name = "pysocks", marker = "extra == 'socks'" },
]

[package.metadata.requires-dev]
dev = [{ name = "pytest", specifier = ">=8" }]

[[package]]
name = "demo-lib"
source = { virtual = "packages/demo-lib" }

[[package]]
name = "numpy"
version = "1.26.4"
source = { registry = "https://pypi.org/simple" }
resolution-markers = [
    "python_full_version < '3.12'",
]
sdist = { url = "https://files.pythonhosted.org/packages/65/6e/09db70a523a96d25e115e71cc56a6f9031e7b8cd166c1ac8438307c14058/numpy-1.26.4.tar.gz", hash = "sha256:{D1}", size = 15786129, upload-time = "2024-02-06T00:26:44.495Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/1a/2e/151484f49fd03944c4a3ad9c418ed193cfd02724e138ac8a9505d056c582/numpy-1.26.4-cp311-cp311-macosx_11_0_arm64.whl", hash = "sha256:{d2}", size = 14421177, upload-time = "2024-02-05T23:51:50.149Z" },
]

[[package]]
name = "numpy"
version = "2.1.0"
source = { registry = "https://pypi.org/simple" }
resolution-markers = [
    "python_full_version >= '3.12'",
]
sdist = { url = "https://files.pythonhosted.org/packages/54/a4/f8188c4f3e07f7737683588210c073478abcb542048cf4ab6fedad0b458a/numpy-2.1.0.tar.gz", hash = "sha256:{d3}", size = 18868922, upload-time = "2024-08-18T21:47:40.017Z" }

[[package]]
name = "torch"
version = "2.4.0+cpu"
source = { registry = "https://download.pytorch.org/whl/cpu" }
wheels = [
    { url = "https://download.pytorch.org/whl/cpu/torch-2.4.0%2Bcpu-cp311-cp311-linux_x86_64.whl", hash = "sha256:{d4}" },
]
"#;

    #[test]
    fn uv_lock_reads_forks_extras_groups_and_editable_root() {
        let lock = parse_uv_lock(&fill(UV_WORKSPACE), Path::new("uv.lock")).unwrap();
        assert_eq!(lock.format, LockFormat::UvLock);
        assert_eq!(lock.files, vec![PathBuf::from("uv.lock")]);
        assert_eq!(lock.requires_python.as_deref(), Some(">=3.10"));
        assert_eq!(lock.members, vec!["demo", "demo-lib"]);
        assert!(lock.index_urls.is_empty());
        assert_eq!(lock.packages.len(), 5);

        let demo = package(&lock, "demo");
        assert_eq!(demo.version.as_deref(), Some("0.1.0"));
        assert_eq!(
            demo.source,
            PackageSource::Directory {
                path: ".".into(),
                editable: true
            }
        );
        let numpy_edges = deps(demo, "numpy");
        assert_eq!(numpy_edges.len(), 2);
        assert_eq!(numpy_edges[0].version.as_deref(), Some("1.26.4"));
        assert_eq!(
            numpy_edges[0].marker.as_deref(),
            Some("python_full_version < '3.12'")
        );
        assert_eq!(numpy_edges[1].version.as_deref(), Some("2.1.0"));
        assert_eq!(deps(demo, "demo-lib")[0].kind, DependencyKind::Required);
        let torch = deps(demo, "torch");
        assert_eq!(torch[0].kind, DependencyKind::Extra("cuda".into()));
        assert_eq!(torch[0].extras, vec!["cuda"]);
        assert_eq!(
            deps(demo, "pysocks")[0].kind,
            DependencyKind::Extra("socks".into())
        );
        assert_eq!(
            deps(demo, "pytest")[0].kind,
            DependencyKind::Group("dev".into())
        );
        let ruff = deps(demo, "ruff");
        assert_eq!(ruff[0].kind, DependencyKind::Group("lint".into()));
        assert_eq!(ruff[0].marker.as_deref(), Some("sys_platform != 'win32'"));
        // `[package.metadata]` is the project's own input, not the lock's resolution.
        assert_eq!(demo.dependencies.len(), 7);

        let lib = package(&lock, "demo-lib");
        assert_eq!(lib.version, None);
        assert_eq!(
            lib.source,
            PackageSource::Directory {
                path: "packages/demo-lib".into(),
                editable: false
            }
        );

        let forks: Vec<&LockedPackage> =
            lock.packages.iter().filter(|p| p.name == "numpy").collect();
        assert_eq!(forks.len(), 2);
        assert_eq!(forks[0].version.as_deref(), Some("1.26.4"));
        assert_eq!(
            forks[0].resolution_markers,
            vec!["python_full_version < '3.12'"]
        );
        assert_eq!(forks[1].version.as_deref(), Some("2.1.0"));
        assert_eq!(
            forks[1].resolution_markers,
            vec!["python_full_version >= '3.12'"]
        );
        assert_eq!(forks[0].source, registry("https://pypi.org/simple"));
        assert_eq!(forks[0].files.len(), 2);
        let sdist = &forks[0].files[0];
        assert_eq!(sdist.kind, FileKind::Sdist);
        assert_eq!(sdist.filename, "numpy-1.26.4.tar.gz");
        assert_eq!(sdist.sha256, Some(d(1)), "digests are lowercased");
        assert_eq!(sdist.size, Some(15786129));
        let wheel = &forks[0].files[1];
        assert_eq!(wheel.kind, FileKind::Wheel);
        assert_eq!(
            wheel.filename,
            "numpy-1.26.4-cp311-cp311-macosx_11_0_arm64.whl"
        );
        assert!(wheel
            .url
            .as_deref()
            .unwrap()
            .starts_with("https://files.pythonhosted.org/"));

        let torch = package(&lock, "torch");
        assert_eq!(
            torch.source,
            registry("https://download.pytorch.org/whl/cpu")
        );
        assert_eq!(
            torch.files[0].filename,
            "torch-2.4.0+cpu-cp311-cp311-linux_x86_64.whl"
        );
        assert_eq!(torch.files[0].size, None);
    }

    #[test]
    fn uv_lock_reads_git_url_path_and_directory_sources() {
        let text = fill(
            r#"version = 1
revision = 2
requires-python = ">=3.9"

[[package]]
name = "app"
version = "0.2.0"
source = { virtual = "." }
dependencies = [
    { name = "httpx" },
    { name = "local-wheel" },
    { name = "remote-sdist" },
    { name = "shared" },
]

[[package]]
name = "httpx"
version = "0.28.1"
source = { git = "https://github.com/encode/httpx?rev=master#0123456789abcdef0123456789abcdef01234567" }

[[package]]
name = "local-wheel"
version = "1.0.0"
source = { path = "wheels/local_wheel-1.0.0-py3-none-any.whl" }
wheels = [
    { filename = "local_wheel-1.0.0-py3-none-any.whl", hash = "sha256:{d5}" },
]

[[package]]
name = "remote-sdist"
version = "2.0.0"
source = { url = "https://example.com/dist/remote_sdist-2.0.0.tar.gz" }
sdist = { hash = "sha256:{d6}" }

[[package]]
name = "shared"
version = "0.1.0"
source = { directory = "../shared" }
"#,
        );
        let lock = parse_uv_lock(&text, Path::new("uv.lock")).unwrap();
        assert!(lock.members.is_empty());
        assert_eq!(
            package(&lock, "app").source,
            PackageSource::Directory {
                path: ".".into(),
                editable: false
            }
        );
        assert_eq!(
            package(&lock, "httpx").source,
            PackageSource::Vcs {
                url: "https://github.com/encode/httpx?rev=master#0123456789abcdef0123456789abcdef01234567".into()
            }
        );
        let local = package(&lock, "local-wheel");
        assert_eq!(
            local.source,
            PackageSource::Archive {
                location: "wheels/local_wheel-1.0.0-py3-none-any.whl".into()
            }
        );
        assert_eq!(
            local.files,
            vec![LockedFile {
                kind: FileKind::Wheel,
                filename: "local_wheel-1.0.0-py3-none-any.whl".into(),
                url: None,
                sha256: Some(d(5)),
                size: None,
            }]
        );
        let remote = package(&lock, "remote-sdist");
        assert_eq!(
            remote.files,
            vec![LockedFile {
                kind: FileKind::Sdist,
                filename: "remote_sdist-2.0.0.tar.gz".into(),
                url: Some("https://example.com/dist/remote_sdist-2.0.0.tar.gz".into()),
                sha256: Some(d(6)),
                size: None,
            }]
        );
        assert_eq!(
            package(&lock, "shared").source,
            PackageSource::Directory {
                path: "../shared".into(),
                editable: false
            }
        );
    }

    #[test]
    fn uv_lock_refuses_other_versions_and_malformed_packages() {
        let path = Path::new("uv.lock");
        let err = parse_uv_lock("version = 2\nrevision = 1\n", path).unwrap_err();
        assert_eq!(err, "uv.lock: uv.lock version 2 is not supported");
        let err = parse_uv_lock("requires-python = \">=3.9\"\n", path).unwrap_err();
        assert!(err.contains("not a uv.lock"), "{err}");
        let err = parse_uv_lock(
            "version = 1\n[[package]]\nname = \"x\"\nversion = \"1\"\n",
            path,
        )
        .unwrap_err();
        assert_eq!(err, "uv.lock: package `x` has no `source` table");
        let err = parse_uv_lock("version = 1\n[[package]\nname = 1\n", path).unwrap_err();
        assert!(err.starts_with("uv.lock: invalid TOML at line 2"), "{err}");
        let err = parse_uv_lock(
            "version = 1\n[[package]]\nname = \"x\"\nversion = \"1\"\nsource = { registry = \"https://pypi.org/simple\" }\nsdist = { url = \"https://h/x-1.tar.gz\", hash = \"sha256:abc\" }\n",
            path,
        )
        .unwrap_err();
        assert_eq!(
            err,
            "uv.lock: package `x` has a malformed sha256 digest `abc`"
        );
    }

    /// Parses a real uv.lock from the FastAPI repository when `KIN_TEST_UV_LOCK` points at one.
    /// The file is large and not vendored here, so the test does nothing when the variable is
    /// unset or the file is missing.
    #[test]
    fn uv_lock_parses_a_real_fastapi_lock_when_given() {
        let Some(path) = std::env::var_os("KIN_TEST_UV_LOCK").map(PathBuf::from) else {
            return;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            return;
        };
        let lock = parse_uv_lock(&text, &path).unwrap();
        assert!(lock.requires_python.as_deref().unwrap().starts_with(">="));
        assert!(lock.packages.len() > 100, "{}", lock.packages.len());

        let fastapi = package(&lock, "fastapi");
        assert_eq!(
            fastapi.source,
            PackageSource::Directory {
                path: ".".into(),
                editable: true
            }
        );
        assert!(deps(fastapi, "starlette")
            .iter()
            .any(|dep| dep.kind == DependencyKind::Required));
        assert!(deps(fastapi, "uvicorn").iter().any(|dep| {
            dep.kind == DependencyKind::Extra("all".into()) && dep.extras == vec!["standard"]
        }));
        assert!(fastapi
            .dependencies
            .iter()
            .any(|dep| dep.kind == DependencyKind::Group("dev".into())));

        let starlette = package(&lock, "starlette");
        assert_eq!(starlette.source, registry("https://pypi.org/simple"));
        for pkg in &lock.packages {
            if !matches!(pkg.source, PackageSource::Registry { .. }) {
                continue;
            }
            assert!(!pkg.files.is_empty(), "{} lists no artifacts", pkg.name);
            for file in &pkg.files {
                assert_eq!(file.sha256.as_ref().map(String::len), Some(64), "{file:?}");
                assert_eq!(
                    file.kind == FileKind::Wheel,
                    file.filename.ends_with(".whl")
                );
                assert!(!file.filename.contains('%'), "{file:?}");
            }
        }
    }

    const PYLOCK: &str = r#"lock-version = "1.0"
requires-python = ">=3.9"
environments = ["sys_platform == 'linux'", "sys_platform == 'darwin'"]
extras = []
dependency-groups = ["dev"]
default-groups = ["dev"]
created-by = "pip"

[[packages]]
name = "attrs"
version = "25.1.0"
requires-python = ">=3.8"
index = "https://pypi.org/simple"

[[packages.wheels]]
name = "attrs-25.1.0-py3-none-any.whl"
upload-time = 2025-01-25T11:30:10.164985+00:00
url = "https://files.pythonhosted.org/packages/fc/30/d4bf8ee0f0d4e6ff0cb3f1f8dc9e7ef9e1b8c9a3c6c2d6c1b1b3b0b0a1e2/attrs-25.1.0-py3-none-any.whl"
size = 63152
hashes = { sha256 = "{d7}" }

[packages.sdist]
upload-time = 2025-01-25T11:30:12.508000+00:00
url = "https://files.pythonhosted.org/packages/49/7c/fdf464bcc51d23881d110abd74b512a42b3d5d376a55a831b44c603ae17f/attrs-25.1.0.tar.gz"
size = 810562
hashes = { sha256 = "{D8}", blake2b = "0123" }

[[packages]]
name = "cattrs"
version = "24.1.2"
marker = "python_version >= '3.10'"
index = "https://pypi.org/simple"
dependencies = [
    { name = "attrs" },
    { name = "exceptiongroup", version = "1.2.2" },
]

[[packages.wheels]]
url = "https://files.pythonhosted.org/packages/c8/d5/867e75361fc45f6de75fe277dd085627a9db5ebb511a87f27dc1396b5351/cattrs-24.1.2-py3-none-any.whl"
hashes = { sha256 = "{d9}" }

[[packages.wheels]]
url = "https://files.pythonhosted.org/packages/64/65/af6d57da2cb32c076c839/cattrs-24.1.2-py3-none-win_amd64.whl"
hashes = { sha512 = "abcd" }

[[packages]]
name = "my-app"

[packages.directory]
path = "."
editable = true

[[packages]]
name = "tomli"
version = "2.2.1"

[packages.vcs]
type = "git"
url = "https://github.com/hukkin/tomli.git"
requested-revision = "2.2.1"
commit-id = "73c3d102eb81fe0d2b87f905df4f740f8878d8da"

[[packages]]
name = "six"
version = "1.17.0"

[packages.archive]
url = "https://example.com/archives/six-1.17.0-py2.py3-none-any.whl"
size = 11050
hashes = { sha256 = "{d10}" }
"#;

    #[test]
    fn pylock_reads_wheels_sdist_directory_vcs_and_archive() {
        let lock = parse_pylock(&fill(PYLOCK), Path::new("pylock.toml")).unwrap();
        assert_eq!(lock.format, LockFormat::Pylock);
        assert_eq!(lock.requires_python.as_deref(), Some(">=3.9"));
        assert_eq!(lock.packages.len(), 5);

        let attrs = package(&lock, "attrs");
        assert_eq!(attrs.source, registry("https://pypi.org/simple"));
        assert_eq!(attrs.requires_python.as_deref(), Some(">=3.8"));
        assert_eq!(attrs.files.len(), 2);
        assert_eq!(attrs.files[0].kind, FileKind::Sdist);
        assert_eq!(attrs.files[0].filename, "attrs-25.1.0.tar.gz");
        assert_eq!(attrs.files[0].sha256, Some(d(8)));
        assert_eq!(attrs.files[0].size, Some(810562));
        assert_eq!(attrs.files[1].kind, FileKind::Wheel);
        assert_eq!(attrs.files[1].filename, "attrs-25.1.0-py3-none-any.whl");
        assert_eq!(attrs.files[1].sha256, Some(d(7)));

        let cattrs = package(&lock, "cattrs");
        assert_eq!(cattrs.marker.as_deref(), Some("python_version >= '3.10'"));
        assert_eq!(cattrs.files.len(), 2);
        assert_eq!(cattrs.files[1].sha256, None, "only sha256 is kept");
        assert_eq!(cattrs.dependencies.len(), 2);
        assert_eq!(cattrs.dependencies[1].name, "exceptiongroup");
        assert_eq!(cattrs.dependencies[1].version.as_deref(), Some("1.2.2"));

        let app = package(&lock, "my-app");
        assert_eq!(app.version, None);
        assert_eq!(
            app.source,
            PackageSource::Directory {
                path: ".".into(),
                editable: true
            }
        );
        assert!(app.files.is_empty());
        assert_eq!(
            package(&lock, "tomli").source,
            PackageSource::Vcs {
                url: "https://github.com/hukkin/tomli.git".into()
            }
        );
        let six = package(&lock, "six");
        assert_eq!(
            six.source,
            PackageSource::Archive {
                location: "https://example.com/archives/six-1.17.0-py2.py3-none-any.whl".into()
            }
        );
        assert_eq!(six.files[0].kind, FileKind::Wheel);
        assert_eq!(six.files[0].sha256, Some(d(10)));
        assert_eq!(six.files[0].size, Some(11050));
    }

    #[test]
    fn pylock_refuses_ambiguous_missing_and_unknown_versions() {
        let path = Path::new("pylock.toml");
        let err = parse_pylock(
            "lock-version = \"1.0\"\n[[packages]]\nname = \"a\"\n[packages.directory]\npath = \".\"\n[[packages.wheels]]\nurl = \"https://h/a-1-py3-none-any.whl\"\n",
            path,
        )
        .unwrap_err();
        assert_eq!(
            err,
            "pylock.toml: package `a` names more than one kind of source"
        );
        let err = parse_pylock(
            "lock-version = \"1.0\"\n[[packages]]\nname = \"a\"\nversion = \"1\"\n",
            path,
        )
        .unwrap_err();
        assert!(err.contains("package `a` names no source"), "{err}");
        let err = parse_pylock("[[packages]]\nname = \"a\"\n", path).unwrap_err();
        assert!(err.contains("not a pylock.toml"), "{err}");
        let err = parse_pylock("lock-version = \"2.0\"\n", path).unwrap_err();
        assert_eq!(err, "pylock.toml: lock-version 2.0 is not supported");
    }

    const POETRY_1: &str = r#"[[package]]
name = "certifi"
version = "2024.2.2"
description = "Python package for providing Mozilla's CA Bundle."
category = "main"
optional = false
python-versions = ">=3.6"

[[package]]
name = "mylib"
version = "0.1.0"
description = ""
category = "main"
optional = false
python-versions = "^3.8"
develop = true

[package.source]
type = "directory"
url = "libs/mylib"

[[package]]
name = "private-pkg"
version = "1.0.0"
description = ""
category = "main"
optional = false
python-versions = "~3.10"

[package.source]
type = "legacy"
url = "https://pypi.example.com/simple"
reference = "private"

[[package]]
name = "pysocks"
version = "1.7.1"
description = "A Python SOCKS client module."
category = "main"
optional = true
python-versions = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*"

[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
category = "main"
optional = false
python-versions = ">=3.7"

[package.dependencies]
certifi = ">=2017.4.17"
charset-normalizer = ">=2,<4"
idna = ">=2.5,<4"
PySocks = {version = ">=1.5.6, !=1.5.7", optional = true}
urllib3 = ">=1.21.1,<3"

[package.extras]
socks = ["PySocks (>=1.5.6,!=1.5.7)"]
use-chardet-on-py3 = ["chardet (>=3.0.2,<6)"]

[[package]]
name = "tomli"
version = "2.0.1"
description = "A lil' TOML parser"
category = "dev"
optional = false
python-versions = ">=3.7"
develop = false

[package.source]
type = "git"
url = "https://github.com/hukkin/tomli.git"
reference = "master"
resolved_reference = "73c3d102eb81fe0d2b87f905df4f740f8878d8da"

[metadata]
lock-version = "1.1"
python-versions = "^3.10"
content-hash = "{d9}"

[metadata.files]
certifi = [
    {file = "certifi-2024.2.2-py3-none-any.whl", hash = "sha256:{d11}"},
    {file = "certifi-2024.2.2.tar.gz", hash = "sha256:{d12}"},
]
mylib = []
private-pkg = [
    {file = "private_pkg-1.0.0.tar.gz", hash = "md5:5d41402abc4b2a76b9719d911017c592"},
]
PySocks = [
    {file = "PySocks-1.7.1-py3-none-any.whl", hash = "sha256:{d13}"},
]
requests = [
    {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:{d14}"},
]
tomli = []
"#;

    #[test]
    fn poetry_1x_reads_metadata_files_sources_and_optional_extras() {
        let lock = parse_poetry_lock(&fill(POETRY_1), Path::new("poetry.lock")).unwrap();
        assert_eq!(lock.format, LockFormat::PoetryLock);
        assert_eq!(lock.requires_python.as_deref(), Some(">=3.10,<4.0"));
        assert_eq!(lock.index_urls, vec!["https://pypi.example.com/simple"]);
        assert_eq!(lock.packages.len(), 6);

        let certifi = package(&lock, "certifi");
        assert_eq!(certifi.source, PackageSource::Registry { index: None });
        assert_eq!(certifi.files.len(), 2);
        assert_eq!(certifi.files[0].kind, FileKind::Wheel);
        assert_eq!(certifi.files[1].kind, FileKind::Sdist);
        assert_eq!(certifi.files[1].sha256, Some(d(12)));
        assert_eq!(certifi.files[1].url, None);

        let private = package(&lock, "private-pkg");
        assert_eq!(private.source, registry("https://pypi.example.com/simple"));
        assert_eq!(private.requires_python.as_deref(), Some(">=3.10,<3.11"));
        assert_eq!(private.files[0].sha256, None, "an md5 hash is not a sha256");

        let pysocks = package(&lock, "pysocks");
        assert_eq!(pysocks.files[0].filename, "PySocks-1.7.1-py3-none-any.whl");
        assert_eq!(
            pysocks.requires_python.as_deref(),
            Some(">=2.7,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*")
        );

        let requests = package(&lock, "requests");
        assert_eq!(requests.dependencies.len(), 5);
        assert_eq!(deps(requests, "certifi")[0].kind, DependencyKind::Required);
        let socks = deps(requests, "PySocks");
        assert_eq!(socks.len(), 1);
        assert_eq!(socks[0].kind, DependencyKind::Extra("socks".into()));

        let mylib = package(&lock, "mylib");
        assert_eq!(
            mylib.source,
            PackageSource::Directory {
                path: "libs/mylib".into(),
                editable: true
            }
        );
        assert_eq!(mylib.requires_python.as_deref(), Some(">=3.8,<4.0"));
        assert!(mylib.files.is_empty());
        assert_eq!(
            package(&lock, "tomli").source,
            PackageSource::Vcs {
                url: "https://github.com/hukkin/tomli.git".into()
            }
        );
    }

    const POETRY_2: &str = r#"# This file is automatically @generated by Poetry 2.1.1 and should not be changed by hand.

[[package]]
name = "click"
version = "8.1.8"
description = "Composable command line interface toolkit"
optional = false
python-versions = ">=3.7"
groups = ["main", "dev"]
markers = {dev = "sys_platform == \"win32\""}
files = [
    {file = "click-8.1.8-py3-none-any.whl", hash = "sha256:{d15}"},
    {file = "click-8.1.8.tar.gz", hash = "sha256:{d16}"},
]

[package.dependencies]
colorama = {version = "*", markers = "platform_system == \"Windows\""}

[[package]]
name = "colorama"
version = "0.4.6"
description = "Cross-platform colored terminal text."
optional = false
python-versions = "!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*,!=3.5.*,!=3.6.*,>=2.7"
groups = ["main", "dev"]
markers = {main = "platform_system == \"Windows\"", dev = "sys_platform == \"win32\""}
files = [
    {file = "colorama-0.4.6-py2.py3-none-any.whl", hash = "sha256:{d1}"},
]

[[package]]
name = "exceptiongroup"
version = "1.2.2"
description = "Backport of PEP 654 (exception groups)"
optional = false
python-versions = ">=3.7"
groups = ["dev"]
markers = "python_version < \"3.11\""
files = [
    {file = "exceptiongroup-1.2.2-py3-none-any.whl", hash = "sha256:{d2}"},
]

[package.extras]
test = ["pytest (>=6)"]

[[package]]
name = "pandas"
version = "2.2.3"
description = "Powerful data structures for data analysis, time series, and statistics"
optional = false
python-versions = ">=3.9"
groups = ["main"]
files = [
    {file = "pandas-2.2.3.tar.gz", hash = "sha256:{d3}"},
]

[package.dependencies]
numpy = [
    {version = ">=1.22.4", markers = "python_version < \"3.11\""},
    {version = ">=1.23.2", markers = "python_version == \"3.11\""},
]
pyarrow = {version = ">=10.0.1", optional = true, extras = ["pandas"]}
tzdata = {version = ">=2022.7", python = "^3.10"}

[package.extras]
feather = ["pyarrow (>=10.0.1)"]
parquet = ["pyarrow (>=10.0.1)"]

[metadata]
lock-version = "2.1"
python-versions = ">=3.10,<4.0"
content-hash = "{d4}"
"#;

    #[test]
    fn poetry_2x_reads_package_files_marker_tables_and_multiple_constraints() {
        let lock = parse_poetry_lock(&fill(POETRY_2), Path::new("poetry.lock")).unwrap();
        assert_eq!(lock.requires_python.as_deref(), Some(">=3.10,<4.0"));
        assert!(lock.index_urls.is_empty());

        let click = package(&lock, "click");
        assert_eq!(
            click.marker, None,
            "`main` has no marker, so click is unconditional"
        );
        assert_eq!(click.files.len(), 2);
        assert_eq!(click.files[0].sha256, Some(d(15)));
        assert_eq!(click.files[1].kind, FileKind::Sdist);
        assert_eq!(
            deps(click, "colorama")[0].marker.as_deref(),
            Some("platform_system == \"Windows\"")
        );

        let colorama = package(&lock, "colorama");
        assert_eq!(
            colorama.marker.as_deref(),
            Some("(platform_system == \"Windows\") or (sys_platform == \"win32\")")
        );
        assert_eq!(
            colorama.requires_python.as_deref(),
            Some("!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*,!=3.5.*,!=3.6.*,>=2.7")
        );
        assert_eq!(
            package(&lock, "exceptiongroup").marker.as_deref(),
            Some("python_version < \"3.11\"")
        );

        let pandas = package(&lock, "pandas");
        let numpy = deps(pandas, "numpy");
        assert_eq!(numpy.len(), 2);
        assert_eq!(
            numpy[0].marker.as_deref(),
            Some("python_version < \"3.11\"")
        );
        assert_eq!(
            numpy[1].marker.as_deref(),
            Some("python_version == \"3.11\"")
        );
        assert!(numpy.iter().all(|dep| dep.kind == DependencyKind::Required));
        let pyarrow = deps(pandas, "pyarrow");
        assert_eq!(
            pyarrow
                .iter()
                .map(|dep| dep.kind.clone())
                .collect::<Vec<_>>(),
            vec![
                DependencyKind::Extra("feather".into()),
                DependencyKind::Extra("parquet".into())
            ]
        );
        assert_eq!(pyarrow[0].extras, vec!["pandas"]);
        assert_eq!(
            deps(pandas, "tzdata")[0].marker.as_deref(),
            Some("python_version >= \"3.10\" and python_version < \"4.0\"")
        );
    }

    #[test]
    fn poetry_constraints_convert_to_pep440() {
        let cases = [
            ("^3.10", Some(">=3.10,<4.0")),
            ("^0.3", Some(">=0.3,<0.4")),
            ("^0.0.3", Some(">=0.0.3,<0.0.4")),
            ("^1.2.3", Some(">=1.2.3,<2.0.0")),
            ("^0", Some(">=0,<1")),
            ("~3.10", Some(">=3.10,<3.11")),
            ("~1.2.3", Some(">=1.2.3,<1.3.0")),
            ("~1", Some(">=1,<2")),
            ("~=3.10", Some("~=3.10")),
            (">=3.8", Some(">=3.8")),
            (">=3.8,<4.0", Some(">=3.8,<4.0")),
            (">=3.8 <4.0", Some(">=3.8,<4.0")),
            (">= 3.8, < 4.0", Some(">=3.8,<4.0")),
            (">=2.7, !=3.0.*", Some(">=2.7,!=3.0.*")),
            ("3.10.*", Some("==3.10.*")),
            ("3.11", Some("==3.11")),
            ("=3.11", Some("==3.11")),
            ("*", None),
            ("", None),
            (">=2.7,<2.8 || >=3.6", None),
            ("~2.7 | ^3.6", None),
            ("latest", None),
        ];
        for (poetry, pep440) in cases {
            assert_eq!(
                poetry_constraint_to_pep440(poetry).as_deref(),
                pep440,
                "{poetry}"
            );
        }
    }

    #[test]
    fn poetry_python_constraints_become_markers() {
        assert_eq!(
            poetry_python_marker("^3.10").as_deref(),
            Some("python_version >= \"3.10\" and python_version < \"4.0\"")
        );
        assert_eq!(
            poetry_python_marker("~2.7 || >=3.6").as_deref(),
            Some("(python_version >= \"2.7\" and python_version < \"2.8\") or python_version >= \"3.6\"")
        );
        assert_eq!(
            poetry_python_marker(">=3.8.1").as_deref(),
            Some("python_full_version >= \"3.8.1\"")
        );
        assert_eq!(poetry_python_marker("*"), None);
    }

    const PDM_LOCK: &str = r#"# This file is @generated by PDM.
# It is not intended for manual editing.

[metadata]
groups = ["default", "dev"]
strategy = ["inherit_metadata"]
lock_version = "4.5.0"
content_hash = "sha256:{d4}"

[[metadata.targets]]
requires_python = ">=3.9"

[[package]]
name = "anyio"
version = "4.8.0"
requires_python = ">=3.9"
summary = "High level compatibility layer for multiple asynchronous event loop implementations"
groups = ["default"]
dependencies = [
    "exceptiongroup>=1.0.2; python_version < \"3.11\"",
    "idna>=2.8",
    "sniffio>=1.1",
    "typing-extensions>=4.5; python_version < \"3.13\"",
]
files = [
    {file = "anyio-4.8.0-py3-none-any.whl", hash = "sha256:{d5}"},
    {file = "anyio-4.8.0.tar.gz", hash = "sha256:{d6}"},
]

[[package]]
name = "exceptiongroup"
version = "1.2.2"
requires_python = ">=3.7"
summary = "Backport of PEP 654 (exception groups)"
groups = ["default"]
marker = "python_version < \"3.11\""
files = [
    {url = "https://files.pythonhosted.org/packages/02/cc/b7e31358aac6ed1ef2bb790a9746ac2c69bcb3c8588b41616914eb2a1ecc/exceptiongroup-1.2.2-py3-none-any.whl", hash = "sha256:{d7}"},
]

[[package]]
name = "requests"
version = "2.32.3"
requires_python = ">=3.8"
summary = "Python HTTP for Humans."
groups = ["default"]
dependencies = [
    "PySocks (!=1.5.7,>=1.5.6)",
    "urllib3[socks]<3,>=1.21.1",
]
files = [
    {file = "requests-2.32.3-py3-none-any.whl", hash = "sha256:{d9}"},
]

[[package]]
name = "uvicorn"
version = "0.30.1"
requires_python = ">=3.8"
summary = "The lightning-fast ASGI server."
groups = ["default"]
dependencies = [
    "click>=7.0",
    "h11>=0.8",
]
files = [
    {file = "uvicorn-0.30.1-py3-none-any.whl", hash = "sha256:{d8}"},
]

[[package]]
name = "uvicorn"
version = "0.30.1"
extras = ["standard"]
requires_python = ">=3.8"
summary = "The lightning-fast ASGI server."
groups = ["default"]
dependencies = [
    "click>=7.0",
    "colorama>=0.4; sys_platform == \"win32\"",
    "httptools>=0.5.0",
    "uvicorn==0.30.1",
    "uvloop!=0.15.0,!=0.15.1,>=0.14.0; (sys_platform != \"cygwin\" and sys_platform != \"win32\") and platform_python_implementation != \"PyPy\"",
]
files = [
    {file = "uvicorn-0.30.1-py3-none-any.whl", hash = "sha256:{d8}"},
]

[[package]]
name = "mylib"
version = "0.1.0"
requires_python = ">=3.9"
path = "./libs/mylib"
editable = true
summary = ""
groups = ["default"]

[[package]]
name = "tomli"
version = "2.0.1"
git = "https://github.com/hukkin/tomli.git"
ref = "master"
revision = "73c3d102eb81fe0d2b87f905df4f740f8878d8da"
summary = "A lil' TOML parser"
groups = ["dev"]
"#;

    #[test]
    fn pdm_lock_reads_dependency_strings_extras_entries_and_local_packages() {
        let lock = parse_pdm_lock(&fill(PDM_LOCK), Path::new("pdm.lock")).unwrap();
        assert_eq!(lock.format, LockFormat::PdmLock);
        assert_eq!(lock.requires_python.as_deref(), Some(">=3.9"));
        assert_eq!(
            lock.packages.len(),
            6,
            "the uvicorn[standard] entry merges into uvicorn"
        );

        let anyio = package(&lock, "anyio");
        assert_eq!(anyio.requires_python.as_deref(), Some(">=3.9"));
        assert_eq!(anyio.source, PackageSource::Registry { index: None });
        assert_eq!(anyio.files.len(), 2);
        assert_eq!(anyio.files[1].sha256, Some(d(6)));
        let group = deps(anyio, "exceptiongroup");
        assert_eq!(
            group[0].marker.as_deref(),
            Some("python_version < \"3.11\"")
        );
        assert_eq!(deps(anyio, "idna")[0].marker, None);

        let exceptiongroup = package(&lock, "exceptiongroup");
        assert_eq!(
            exceptiongroup.marker.as_deref(),
            Some("python_version < \"3.11\"")
        );
        assert_eq!(
            exceptiongroup.files[0].filename,
            "exceptiongroup-1.2.2-py3-none-any.whl"
        );
        assert!(exceptiongroup.files[0].url.is_some());

        let requests = package(&lock, "requests");
        assert_eq!(requests.dependencies[0].name, "PySocks");
        assert_eq!(requests.dependencies[1].name, "urllib3");
        assert_eq!(requests.dependencies[1].extras, vec!["socks"]);

        let uvicorn = package(&lock, "uvicorn");
        assert_eq!(uvicorn.files.len(), 1);
        assert_eq!(
            deps(uvicorn, "click").len(),
            1,
            "click stays one required edge"
        );
        assert!(
            deps(uvicorn, "uvicorn").is_empty(),
            "the self pin is not an edge"
        );
        let colorama = deps(uvicorn, "colorama");
        assert_eq!(colorama[0].kind, DependencyKind::Extra("standard".into()));
        assert_eq!(
            colorama[0].marker.as_deref(),
            Some("sys_platform == \"win32\"")
        );
        let uvloop = deps(uvicorn, "uvloop");
        assert_eq!(uvloop[0].kind, DependencyKind::Extra("standard".into()));
        assert!(uvloop[0]
            .marker
            .as_deref()
            .unwrap()
            .starts_with("(sys_platform"));

        assert_eq!(
            package(&lock, "mylib").source,
            PackageSource::Directory {
                path: "./libs/mylib".into(),
                editable: true
            }
        );
        assert_eq!(
            package(&lock, "tomli").source,
            PackageSource::Vcs {
                url: "https://github.com/hukkin/tomli.git".into()
            }
        );
        let err = parse_pdm_lock("[[package]]\nname = \"a\"\n", Path::new("pdm.lock")).unwrap_err();
        assert!(err.contains("not a pdm.lock"), "{err}");
    }

    const PIPFILE_LOCK: &str = r#"{
    "_meta": {
        "hash": {
            "sha256": "{d9}"
        },
        "pipfile-spec": 6,
        "requires": {
            "python_full_version": "3.11.4",
            "python_version": "3.11"
        },
        "sources": [
            {
                "name": "pypi",
                "url": "https://pypi.org/simple",
                "verify_ssl": true
            },
            {
                "name": "internal",
                "url": "https://pypi.internal.example/simple",
                "verify_ssl": true
            }
        ]
    },
    "default": {
        "certifi": {
            "hashes": [
                "sha256:{d1}",
                "sha256:{d2}"
            ],
            "index": "pypi",
            "markers": "python_version >= '3.6'",
            "version": "==2024.2.2"
        },
        "internal-lib": {
            "hashes": [
                "sha256:{D3}",
                "md5:5d41402abc4b2a76b9719d911017c592"
            ],
            "index": "internal",
            "version": "==0.3.0"
        },
        "myapp": {
            "editable": true,
            "path": "."
        },
        "requests": {
            "extras": [
                "socks"
            ],
            "hashes": [
                "sha256:{d4}"
            ],
            "index": "pypi",
            "version": "==2.31.0"
        },
        "tomli": {
            "git": "https://github.com/hukkin/tomli.git",
            "ref": "73c3d102eb81fe0d2b87f905df4f740f8878d8da"
        },
        "vendored": {
            "file": "https://example.com/vendored-1.0.tar.gz"
        }
    },
    "develop": {
        "certifi": {
            "hashes": [
                "sha256:{d1}"
            ],
            "index": "pypi",
            "version": "==2024.2.2"
        },
        "pytest": {
            "hashes": [
                "sha256:{d5}"
            ],
            "index": "pypi",
            "markers": "python_version >= '3.8'",
            "version": "==8.0.0"
        }
    }
}
"#;

    #[test]
    fn pipfile_lock_resolves_index_names_and_python_pin() {
        let lock = parse_pipfile_lock(&fill(PIPFILE_LOCK), Path::new("Pipfile.lock")).unwrap();
        assert_eq!(lock.format, LockFormat::PipfileLock);
        assert_eq!(lock.python_pin.as_deref(), Some("3.11.4"));
        assert_eq!(lock.requires_python, None);
        assert_eq!(
            lock.index_urls,
            vec![
                "https://pypi.org/simple",
                "https://pypi.internal.example/simple"
            ]
        );
        assert_eq!(
            lock.packages.len(),
            7,
            "the develop duplicate of certifi is dropped"
        );

        let certifi = package(&lock, "certifi");
        assert_eq!(certifi.version.as_deref(), Some("2024.2.2"));
        assert_eq!(certifi.source, registry("https://pypi.org/simple"));
        assert_eq!(certifi.hashes, vec![d(1), d(2)]);
        assert_eq!(certifi.marker.as_deref(), Some("python_version >= '3.6'"));

        let internal = package(&lock, "internal-lib");
        assert_eq!(
            internal.source,
            registry("https://pypi.internal.example/simple")
        );
        assert_eq!(internal.hashes, vec![d(3)]);

        assert_eq!(
            package(&lock, "myapp").source,
            PackageSource::Directory {
                path: ".".into(),
                editable: true
            }
        );
        let tomli = package(&lock, "tomli");
        assert_eq!(tomli.version, None);
        assert_eq!(
            tomli.source,
            PackageSource::Vcs {
                url: "https://github.com/hukkin/tomli.git".into()
            }
        );
        assert_eq!(
            package(&lock, "vendored").source,
            PackageSource::Archive {
                location: "https://example.com/vendored-1.0.tar.gz".into()
            }
        );
        assert_eq!(package(&lock, "pytest").version.as_deref(), Some("8.0.0"));
    }

    #[test]
    fn pipfile_lock_pins_python_version_and_refuses_loose_versions() {
        let text = r#"{"_meta": {"requires": {"python_version": "3.12"}, "sources": []},
            "default": {"six": {"hashes": [], "version": "==1.17.0"}}, "develop": {}}"#;
        let lock = parse_pipfile_lock(text, Path::new("Pipfile.lock")).unwrap();
        assert_eq!(lock.python_pin.as_deref(), Some("3.12"));
        assert_eq!(
            lock.packages[0].source,
            PackageSource::Registry { index: None }
        );

        let loose = r#"{"_meta": {}, "default": {"six": {"version": ">=1.0"}}}"#;
        let err = parse_pipfile_lock(loose, Path::new("Pipfile.lock")).unwrap_err();
        assert_eq!(
            err,
            "Pipfile.lock: package `six` has version `>=1.0`, which is not pinned with `==`"
        );
        let err = parse_pipfile_lock("{\"default\": {}}", Path::new("Pipfile.lock")).unwrap_err();
        assert!(err.contains("not a Pipfile.lock"), "{err}");
    }

    const REQUIREMENTS_MAIN: &str = r#"#
# This file is autogenerated by pip-compile with Python 3.11
# by the following command:
#
#    pip-compile --generate-hashes --output-file=requirements.txt requirements.in
#
--index-url https://pypi.org/simple
--extra-index-url https://download.pytorch.org/whl/cpu
--trusted-host download.pytorch.org
--no-binary :none:

-e .[socks]
    # via -r requirements.in
-r requirements-base.txt
certifi==2024.2.2 \
    --hash=sha256:{d1} \
    --hash=sha256:{D2}
    # via requests
requests[socks]==2.31.0 ; python_version >= "3.7" \
    --hash=sha256:{d3}
    # via -r requirements.in
torch==2.4.0+cpu --hash sha256:{d4} --hash=sha512:abcd
pip-tools @ https://files.pythonhosted.org/packages/0d/dc/38f4ce065e92c66f058ea7a368a9c5de4e702272b479c0992059f7693941/pip_tools-7.4.1-py3-none-any.whl#sha256={d5} \
    --hash=sha256:{d5}
./vendor/tiny_pkg-0.1.0-py3-none-any.whl
"#;

    const REQUIREMENTS_BASE: &str = "-r requirements.txt\nidna==3.6 \\\n    --hash=sha256:{d6} \\\n    --hash=sha256:{d7}\ncertifi==2024.2.2 --hash=sha256:{d8}  # also pinned here\n";

    const PYPROJECT: &str = "[project]\nname = \"demo-app\"\nversion = \"0.1.0\"\n";

    #[test]
    fn requirements_read_pins_hashes_includes_and_an_in_repo_editable() {
        let lock = requirements(
            &[
                ("requirements.txt", REQUIREMENTS_MAIN),
                ("requirements-base.txt", REQUIREMENTS_BASE),
                ("pyproject.toml", PYPROJECT),
            ],
            &["requirements.txt"],
        )
        .unwrap();
        assert_eq!(lock.format, LockFormat::Requirements);
        assert_eq!(
            lock.files,
            vec![
                PathBuf::from("requirements.txt"),
                PathBuf::from("requirements-base.txt")
            ]
        );
        assert_eq!(
            lock.index_urls,
            vec![
                "https://pypi.org/simple",
                "https://download.pytorch.org/whl/cpu"
            ]
        );
        let names: Vec<&str> = lock.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "demo-app",
                "idna",
                "certifi",
                "requests",
                "torch",
                "pip-tools",
                "tiny_pkg"
            ]
        );

        let app = package(&lock, "demo-app");
        assert_eq!(app.version, None);
        assert_eq!(
            app.source,
            PackageSource::Directory {
                path: ".".into(),
                editable: true
            }
        );
        assert_eq!(package(&lock, "idna").hashes, vec![d(6), d(7)]);
        let certifi = package(&lock, "certifi");
        assert_eq!(certifi.version.as_deref(), Some("2024.2.2"));
        assert_eq!(
            certifi.hashes,
            vec![d(8), d(1), d(2)],
            "both files' digests merge"
        );
        let requests = package(&lock, "requests");
        assert_eq!(
            requests.marker.as_deref(),
            Some("python_version >= \"3.7\"")
        );
        assert_eq!(requests.hashes, vec![d(3)]);
        assert_eq!(requests.source, PackageSource::Registry { index: None });
        let torch = package(&lock, "torch");
        assert_eq!(torch.version.as_deref(), Some("2.4.0+cpu"));
        assert_eq!(torch.hashes, vec![d(4)]);
        let pip_tools = package(&lock, "pip-tools");
        assert_eq!(pip_tools.version.as_deref(), Some("7.4.1"));
        assert_eq!(pip_tools.hashes, vec![d(5)]);
        assert!(matches!(
            &pip_tools.source,
            PackageSource::Archive { location } if location.contains(&format!("#sha256={}", d(5)))
        ));
        let tiny = package(&lock, "tiny_pkg");
        assert_eq!(tiny.version.as_deref(), Some("0.1.0"));
        assert_eq!(
            tiny.source,
            PackageSource::Archive {
                location: "./vendor/tiny_pkg-0.1.0-py3-none-any.whl".into()
            }
        );
    }

    #[test]
    fn requirements_refuse_lines_that_are_not_locked() {
        let refuse = |line: &str| {
            requirements(&[("requirements-dev.txt", line)], &["requirements-dev.txt"]).unwrap_err()
        };
        assert_eq!(
            refuse("pytest>=2.8.0,<10\n"),
            "requirements-dev.txt: `pytest>=2.8.0,<10` is not pinned with `==`"
        );
        assert_eq!(
            refuse("pytest\n"),
            "requirements-dev.txt: `pytest` is not pinned with `==`"
        );
        assert_eq!(
            refuse("pytest~=8.3 --hash=sha256:{d1}\n"),
            "requirements-dev.txt: `pytest~=8.3` is not pinned with `==`"
        );
        assert_eq!(
            refuse("pytest==8.*  --hash=sha256:{d1}\n"),
            "requirements-dev.txt: `pytest==8.*` pins a wildcard, not an exact version"
        );
        assert_eq!(
            refuse("pytest==8.3.4\n"),
            "requirements-dev.txt: `pytest==8.3.4` has no `--hash=sha256:` digest"
        );
        assert_eq!(
            refuse("pytest==8.3.4 --hash=sha512:abcd\n"),
            "requirements-dev.txt: `pytest==8.3.4` has no `--hash=sha256:` digest"
        );
        assert_eq!(
            refuse("pytest==8.3.4 --hash=sha256:zz\n"),
            "requirements-dev.txt: `pytest==8.3.4` has a malformed sha256 digest `zz`"
        );
        assert_eq!(
            refuse("mylib @ git+https://github.com/org/mylib@main\n"),
            "requirements-dev.txt: `mylib @ git+https://github.com/org/mylib@main` does not pin a full VCS commit"
        );
        assert_eq!(
            refuse("/opt/wheels/foo-1.0-py3-none-any.whl\n"),
            "requirements-dev.txt: `/opt/wheels/foo-1.0-py3-none-any.whl` names an absolute path, not an in-repo path"
        );
        assert_eq!(
            refuse("-r missing.txt\n"),
            "requirements-dev.txt: `-r missing.txt` names a file that cannot be read"
        );
        assert_eq!(
            refuse("-r https://example.com/reqs.txt\n"),
            "requirements-dev.txt: `-r https://example.com/reqs.txt` includes a remote file, which is never fetched"
        );
        assert_eq!(
            refuse("# nothing pinned yet\n\n"),
            "requirements-dev.txt: names no requirements"
        );
        assert_eq!(
            requirements(&[], &["requirements.txt"]).unwrap_err(),
            "requirements.txt: cannot be read"
        );

        // The first offending line is reported, including one reached through an include.
        let err = requirements(
            &[(
                "requirements.txt",
                "six==1.17.0 --hash=sha256:{d1}\nflask\nclick\n",
            )],
            &["requirements.txt"],
        )
        .unwrap_err();
        assert_eq!(err, "requirements.txt: `flask` is not pinned with `==`");
        let err = requirements(
            &[
                (
                    "requirements/dev.txt",
                    "-r base.txt\npytest==8.3.4 --hash=sha256:{d1}\n",
                ),
                ("requirements/base.txt", "django>=4\n"),
            ],
            &["requirements/dev.txt"],
        )
        .unwrap_err();
        assert_eq!(
            err,
            "requirements/base.txt: `django>=4` is not pinned with `==`"
        );
    }

    #[test]
    fn requirements_accept_commits_urls_and_editable_checkouts() {
        let commit = "73c3d102eb81fe0d2b87f905df4f740f8878d8da";
        let text = format!(
            "mylib @ git+https://github.com/org/mylib@{commit}\n\
             -e git+https://github.com/org/tool.git@{commit}#egg=tool\n\
             -e ./packages/core\n\
             https://example.com/dist/extra_pkg-2.0.tar.gz --hash=sha256:{{d2}}\n"
        );
        let lock = requirements(
            &[
                ("requirements.txt", &text),
                (
                    "packages/core/setup.cfg",
                    "[metadata]\nname = core-lib\nversion = 1.0\n",
                ),
            ],
            &["requirements.txt"],
        )
        .unwrap();
        assert_eq!(
            package(&lock, "mylib").source,
            PackageSource::Vcs {
                url: format!("git+https://github.com/org/mylib@{commit}")
            }
        );
        assert_eq!(
            package(&lock, "tool").source,
            PackageSource::Vcs {
                url: format!("git+https://github.com/org/tool.git@{commit}#egg=tool")
            }
        );
        assert_eq!(
            package(&lock, "core-lib").source,
            PackageSource::Directory {
                path: "./packages/core".into(),
                editable: true
            }
        );
        let extra = package(&lock, "extra_pkg");
        assert_eq!(extra.version.as_deref(), Some("2.0"));
        assert_eq!(extra.hashes, vec![d(2)]);
    }

    #[test]
    fn requirements_constraints_pin_only_required_names() {
        let lock = requirements(
            &[
                ("requirements.txt", "-c constraints.txt\nrequests\nsix==1.17.0 --hash=sha256:{d3}\n"),
                (
                    "constraints.txt",
                    "requests==2.31.0 --hash=sha256:{d1}\nunused==1.0 --hash=sha256:{d2}\nloose>=1\n",
                ),
            ],
            &["requirements.txt"],
        )
        .unwrap();
        assert_eq!(
            lock.files,
            vec![
                PathBuf::from("requirements.txt"),
                PathBuf::from("constraints.txt")
            ]
        );
        assert_eq!(lock.packages.len(), 2);
        let requests = package(&lock, "requests");
        assert_eq!(requests.version.as_deref(), Some("2.31.0"));
        assert_eq!(requests.hashes, vec![d(1)]);
        assert!(lock.packages.iter().all(|p| p.name != "unused"));

        let err = requirements(
            &[
                (
                    "requirements.txt",
                    "-c constraints.txt\nrequests==2.32.0 --hash=sha256:{d1}\n",
                ),
                ("constraints.txt", "requests==2.31.0\n"),
            ],
            &["requirements.txt"],
        )
        .unwrap_err();
        assert_eq!(
            err,
            "requirements.txt: `requests==2.32.0` conflicts with the constraint `requests==2.31.0` in constraints.txt"
        );
    }

    #[test]
    fn requirements_keep_forks_by_marker_and_refuse_conflicting_pins() {
        let lock = requirements(
            &[(
                "requirements.txt",
                "numpy==1.26.4 ; python_version < \"3.12\" --hash=sha256:{d1}\n\
                 numpy==2.1.0 ; python_version >= \"3.12\" --hash=sha256:{d2}\n",
            )],
            &["requirements.txt"],
        )
        .unwrap();
        assert_eq!(lock.packages.len(), 2);
        assert_eq!(
            lock.packages[1].marker.as_deref(),
            Some("python_version >= \"3.12\"")
        );

        let err = requirements(
            &[
                ("a.txt", "six==1.16.0 --hash=sha256:{d1}\n"),
                ("b.txt", "six==1.17.0 --hash=sha256:{d2}\n"),
            ],
            &["a.txt", "b.txt"],
        )
        .unwrap_err();
        assert_eq!(
            err,
            "b.txt: `six==1.17.0` conflicts with `six==1.16.0` in a.txt"
        );
    }

    #[test]
    fn requirements_logical_lines_join_continuations_and_keep_url_fragments() {
        let text = "a==1 \\\n  --hash=sha256:x \\\n  --hash=sha256:y\n# comment\n\
                    b @ https://h/b-1.tar.gz#sha256=abc # trailing\n\
                    c==1 # note \\\nd==2\n\
                    e==1 \\\n# via x\n";
        assert_eq!(
            logical_lines(text),
            vec![
                "a==1   --hash=sha256:x   --hash=sha256:y",
                "b @ https://h/b-1.tar.gz#sha256=abc",
                "c==1",
                "d==2",
                "e==1",
            ]
        );
    }

    fn minimal_uv() -> &'static str {
        "version = 1\nrevision = 3\nrequires-python = \">=3.12\"\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\n"
    }

    fn minimal_poetry() -> &'static str {
        "[[package]]\nname = \"six\"\nversion = \"1.17.0\"\noptional = false\npython-versions = \"*\"\nfiles = []\n\n[metadata]\nlock-version = \"2.1\"\npython-versions = \"^3.12\"\ncontent-hash = \"0\"\n"
    }

    fn minimal_pylock() -> &'static str {
        "lock-version = \"1.0\"\n[[packages]]\nname = \"app\"\n[packages.directory]\npath = \".\"\n"
    }

    #[test]
    fn find_lock_prefers_uv_lock_over_poetry_lock() {
        let root = Scratch::new("uv-first");
        root.write("uv.lock", minimal_uv());
        root.write("poetry.lock", minimal_poetry());
        let LockSearch::Found(lock) = find_lock(&root.0) else {
            panic!("expected a lock");
        };
        assert_eq!(lock.format, LockFormat::UvLock);
        assert_eq!(lock.files, vec![root.0.join("uv.lock")]);
    }

    #[test]
    fn find_lock_falls_through_an_unparsable_uv_lock() {
        let root = Scratch::new("uv-broken");
        root.write("uv.lock", "version = 1\n[[package]\nname = \"x\"\n");
        root.write("poetry.lock", minimal_poetry());
        let LockSearch::Found(lock) = find_lock(&root.0) else {
            panic!("expected poetry.lock");
        };
        assert_eq!(lock.format, LockFormat::PoetryLock);

        std::fs::remove_file(root.0.join("poetry.lock")).unwrap();
        let LockSearch::Unusable { reasons } = find_lock(&root.0) else {
            panic!("expected Unusable");
        };
        assert_eq!(reasons.len(), 1);
        assert!(
            reasons[0].starts_with("uv.lock: invalid TOML at line 2"),
            "{reasons:?}"
        );

        root.write("requirements.txt", "flask\n");
        let LockSearch::Unusable { reasons } = find_lock(&root.0) else {
            panic!("expected Unusable");
        };
        assert_eq!(reasons.len(), 2);
        assert_eq!(
            reasons[1],
            "requirements.txt: `flask` is not pinned with `==`"
        );
    }

    #[test]
    fn find_lock_reports_not_found_for_a_bare_project() {
        let root = Scratch::new("bare");
        root.write("pyproject.toml", PYPROJECT);
        root.write("requirements.in", "flask\n");
        assert_eq!(find_lock(&root.0), LockSearch::NotFound);
    }

    #[test]
    fn find_lock_orders_named_pylocks_and_prefers_them_to_poetry() {
        let root = Scratch::new("pylock");
        root.write("pylock.toml", "lock-version = 1\n");
        root.write("pylock.prod.toml", minimal_pylock());
        root.write("pylock.dev.toml", minimal_pylock());
        root.write("poetry.lock", minimal_poetry());
        let LockSearch::Found(lock) = find_lock(&root.0) else {
            panic!("expected a pylock");
        };
        assert_eq!(lock.format, LockFormat::Pylock);
        assert_eq!(lock.files, vec![root.0.join("pylock.dev.toml")]);
    }

    #[test]
    fn find_lock_combines_the_requirements_files_that_qualify() {
        let root = Scratch::new("requirements");
        root.write("requirements.txt", "six==1.17.0 --hash=sha256:{d1}\n");
        root.write(
            "requirements-dev.txt",
            "-r requirements.txt\npytest==8.3.4 --hash=sha256:{d2}\n",
        );
        root.write("requirements-docs.txt", "sphinx\n");
        root.write("requirements-py38.txt", "six==1.16.0 --hash=sha256:{d3}\n");
        root.write("requirements/ci.txt", "tox==4.23.2 --hash=sha256:{d4}\n");
        root.write("requirements/README.md", "not a requirements file\n");
        let LockSearch::Found(lock) = find_lock(&root.0) else {
            panic!("expected requirements");
        };
        assert_eq!(lock.format, LockFormat::Requirements);
        assert_eq!(
            lock.files,
            vec![
                root.0.join("requirements.txt"),
                root.0.join("requirements-dev.txt"),
                root.0.join("requirements/ci.txt"),
            ]
        );
        let names: Vec<&str> = lock.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["six", "pytest", "tox"]);
    }

    #[test]
    fn normalize_name_follows_pep503() {
        assert_eq!(normalize_name("Foo.Bar__baz--Qux"), "foo-bar-baz-qux");
        assert_eq!(normalize_name("typing_extensions"), "typing-extensions");
        assert_eq!(normalize_name("PySocks"), "pysocks");
        assert_eq!(normalize_name("a-_.b"), "a-b");
        assert_eq!(normalize_name("zope.interface"), "zope-interface");
    }

    #[test]
    fn lock_formats_describe_their_file_names() {
        assert_eq!(LockFormat::UvLock.describe(), "uv.lock");
        assert_eq!(LockFormat::Pylock.describe(), "pylock.toml");
        assert_eq!(LockFormat::PoetryLock.describe(), "poetry.lock");
        assert_eq!(LockFormat::PdmLock.describe(), "pdm.lock");
        assert_eq!(LockFormat::PipfileLock.describe(), "Pipfile.lock");
        assert_eq!(LockFormat::Requirements.describe(), "requirements file");
    }
}
