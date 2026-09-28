// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The content-addressed store analysis environments are built from.
//!
//! ```text
//! <KIN_HOME>/cache/analysis-environments/python/
//!   artifacts/<sha256>/     one verified wheel, unpacked; or one pure-Python
//!                           sdist's importable source, extracted, never built
//!   interpreters/<build>/   one pinned CPython build, unpacked
//!   envs/<identity>/        one environment: a venv whose site-packages
//!                           links to the artifacts it holds
//!   resolutions/<key>.txt   a resolution Kin made for an unlocked project
//!   downloads/              archives in flight, removed once unpacked
//! ```
//!
//! An artifact is named by the digest of the archive it came from, so two
//! repositories that pin the same file share one copy, and a directory that
//! exists is complete: everything is staged under a temporary name and
//! renamed into place. The store is a cache: any of it can be deleted and is
//! fetched again.
//!
//! An environment's site-packages holds nothing that runs when an interpreter
//! starts. A wheel's `.pth` files are rewritten to their path lines alone,
//! since `import` lines in them are executed by `site`, and `sitecustomize`
//! and `usercustomize` modules are left out.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::super::fetch::{download_verified, Fetcher};
use super::super::unpack;

/// A suffix unique to this process and call, for staging names.
pub fn unique_suffix() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}.{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// An exclusively created attempt directory. A suffix is only a candidate:
/// create_dir decides ownership even across reused PIDs or PID namespaces.
/// Only the directory this attempt claimed is removed on drop.
pub(crate) struct OwnedAttempt(pub(crate) PathBuf);

impl OwnedAttempt {
    pub(crate) fn new(parent: &Path) -> Result<Self, String> {
        Self::claim(parent, unique_suffix)
    }

    fn claim(parent: &Path, mut suffix: impl FnMut() -> String) -> Result<Self, String> {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("{}: {error}", parent.display()))?;
        for _ in 0..128 {
            let path = parent.join(format!(".attempt-{}", suffix()));
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;

                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700);
                builder
            };
            #[cfg(not(unix))]
            let builder = std::fs::DirBuilder::new();
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(format!("{}: {error}", path.display())),
            }
        }
        Err(format!(
            "{}: could not claim an exclusive archive attempt",
            parent.display()
        ))
    }
}

impl Drop for OwnedAttempt {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Move a staged directory to its final name. When another writer published
/// the same content first, theirs is kept and the staged copy removed.
pub fn publish_dir(staging: &Path, destination: &Path) -> Result<(), String> {
    if let Some(dir) = destination.parent() {
        std::fs::create_dir_all(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    }
    match std::fs::rename(staging, destination) {
        Ok(()) => Ok(()),
        Err(_) if destination.is_dir() => {
            let _ = std::fs::remove_dir_all(staging);
            Ok(())
        }
        Err(error) => {
            let _ = std::fs::remove_dir_all(staging);
            Err(format!("{}: {error}", destination.display()))
        }
    }
}

/// The directory an artifact with this digest unpacks to.
pub fn artifact_dir(store: &Path, sha256: &str) -> PathBuf {
    store.join("artifacts").join(sha256.to_ascii_lowercase())
}

/// The compatibility tags a stored wheel was built for, from its
/// `*.dist-info/WHEEL` file. `None` for extracted source, which suits any
/// Python.
pub fn artifact_tags(dir: &Path) -> Option<Vec<(String, String, String)>> {
    let dist_info = std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.extension().is_some_and(|ext| ext == "dist-info") && path.join("WHEEL").is_file()
        })?;
    let text = std::fs::read_to_string(dist_info.join("WHEEL")).ok()?;
    let tags: Vec<(String, String, String)> = text
        .lines()
        .filter_map(|line| line.strip_prefix("Tag:"))
        .filter_map(|tag| {
            let mut parts = tag.trim().splitn(3, '-');
            Some((
                parts.next()?.to_ascii_lowercase(),
                parts.next()?.to_ascii_lowercase(),
                parts.next()?.to_ascii_lowercase(),
            ))
        })
        .collect();
    (!tags.is_empty()).then_some(tags)
}

/// What one artifact is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    Wheel,
    /// A source distribution whose importable source is extracted for
    /// reading; `name` and `version` label its metadata.
    Sdist,
}

/// Why an artifact could not be put in the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    /// The download failed or its digest did not match; nothing was kept.
    Fetch(super::super::fetch::FetchError),
    /// The archive could not be read, or held something refused.
    Unpack(String),
    /// A source distribution that needs a build before it can be imported.
    NeedsBuild(String),
}

impl std::fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactError::Fetch(error) => write!(f, "{error}"),
            ArtifactError::Unpack(reason) | ArtifactError::NeedsBuild(reason) => {
                f.write_str(reason)
            }
        }
    }
}

/// Put one artifact in the store: the unpacked directory, and the bytes
/// downloaded (zero when the store already held it).
#[allow(clippy::too_many_arguments)]
pub fn ensure_artifact(
    fetcher: &dyn Fetcher,
    store: &Path,
    url: &str,
    filename: &str,
    sha256: &str,
    kind: ArtifactKind,
    name: &str,
    version: &str,
    max_bytes: u64,
) -> Result<(PathBuf, u64), ArtifactError> {
    let destination = artifact_dir(store, sha256);
    if destination.is_dir() {
        return Ok((destination, 0));
    }
    let unique = unique_suffix();
    let archive = store
        .join("downloads")
        .join(format!("{}.{unique}.part", sha256.to_ascii_lowercase()));
    let downloaded = download_verified(fetcher, url, &archive, sha256, max_bytes)
        .map_err(ArtifactError::Fetch)?;
    let staging = store
        .join("artifacts")
        .join(format!(".{}.{unique}.tmp", sha256.to_ascii_lowercase()));
    let result = match kind {
        ArtifactKind::Wheel => unpack::unzip(&archive, &staging)
            .map_err(ArtifactError::Unpack)
            .and_then(|_| merge_wheel_data(&staging).map_err(ArtifactError::Unpack)),
        ArtifactKind::Sdist => extract_sdist(&archive, filename, &staging, name, version),
    };
    let _ = std::fs::remove_file(&archive);
    if let Err(error) = result {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(error);
    }
    publish_dir(&staging, &destination).map_err(ArtifactError::Unpack)?;
    Ok((destination, downloaded.bytes))
}

/// Move a wheel's `<name>.data/purelib` and `platlib` contents to its root,
/// where an installer puts them. Scripts, headers and data stay where they
/// are, unread.
fn merge_wheel_data(root: &Path) -> Result<(), String> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Ok(());
    };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".data") {
            continue;
        }
        for scheme in ["purelib", "platlib"] {
            let dir = entry.path().join(scheme);
            let Ok(children) = std::fs::read_dir(&dir) else {
                continue;
            };
            for child in children.filter_map(Result::ok) {
                let target = root.join(child.file_name());
                if !target.exists() {
                    std::fs::rename(child.path(), &target)
                        .map_err(|error| format!("{}: {error}", target.display()))?;
                }
            }
        }
    }
    Ok(())
}

/// File extensions whose presence in a source distribution means it compiles
/// something before it can be imported.
const NATIVE_SOURCES: &[&str] = &[
    "c", "cc", "cpp", "cxx", "pyx", "pxd", "rs", "f", "f90", "cu", "m", "mm",
];

/// Words in a `setup.py` or `pyproject.toml` that mean a native extension.
const NATIVE_MARKERS: &[&str] = &[
    "ext_modules",
    "Extension(",
    "cythonize",
    "setuptools_rust",
    "setuptools-rust",
    "maturin",
    "scikit-build",
    "scikit_build",
    "mesonpy",
    "meson-python",
    "cmake",
];

/// Extract a pure-Python sdist's importable source into `staging`: its
/// packages and top-level modules, from `src/` in a src layout. The sdist is
/// read as data, never built, and one that needs a build is refused.
fn extract_sdist(
    archive: &Path,
    filename: &str,
    staging: &Path,
    name: &str,
    version: &str,
) -> Result<(), ArtifactError> {
    let raw = staging.with_extension("raw");
    let unpacked = if filename.ends_with(".zip") {
        unpack::unzip(archive, &raw)
    } else {
        unpack::untar_gz(archive, &raw, unpack::TarLayout::DATA)
    };
    let result = unpacked
        .map_err(ArtifactError::Unpack)
        .and_then(|_| copy_importable_source(&raw, staging, name, version));
    let _ = std::fs::remove_dir_all(&raw);
    result
}

fn copy_importable_source(
    raw: &Path,
    staging: &Path,
    name: &str,
    version: &str,
) -> Result<(), ArtifactError> {
    // An sdist holds one top-level directory, `<name>-<version>`.
    let top = std::fs::read_dir(raw)
        .map_err(|error| ArtifactError::Unpack(error.to_string()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .ok_or_else(|| ArtifactError::Unpack("the sdist holds no source directory".to_string()))?;
    let mut native = None;
    crate::adapters::repo_scan::walk_files(&top, &|_, _| true, &mut |path, file| {
        let extension = file.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("");
        if native.is_none() && NATIVE_SOURCES.contains(&extension) {
            native = Some(
                path.strip_prefix(&top)
                    .unwrap_or(path)
                    .display()
                    .to_string(),
            );
        }
    });
    for manifest in ["setup.py", "pyproject.toml", "setup.cfg"] {
        if let Ok(text) = std::fs::read_to_string(top.join(manifest)) {
            if let Some(marker) = NATIVE_MARKERS.iter().find(|marker| text.contains(**marker)) {
                native.get_or_insert_with(|| format!("{manifest} mentions {marker}"));
            }
        }
    }
    if let Some(evidence) = native {
        return Err(ArtifactError::NeedsBuild(format!(
            "only a source distribution is locked, and it compiles native code ({evidence}); \
             building it runs its code, which Kin never does"
        )));
    }
    let src = top.join("src");
    let import_root = if src.is_dir()
        && std::fs::read_dir(&src)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .any(|e| is_importable(&e.path()))
            })
            .unwrap_or(false)
    {
        src
    } else {
        top.clone()
    };
    std::fs::create_dir_all(staging).map_err(|error| ArtifactError::Unpack(error.to_string()))?;
    let mut copied = 0;
    for entry in std::fs::read_dir(&import_root)
        .map_err(|error| ArtifactError::Unpack(error.to_string()))?
        .filter_map(Result::ok)
    {
        let path = entry.path();
        let file = entry.file_name().to_string_lossy().into_owned();
        let skipped = matches!(
            file.as_str(),
            "setup.py"
                | "conftest.py"
                | "noxfile.py"
                | "tasks.py"
                | "fabfile.py"
                | "tests"
                | "test"
                | "testing"
                | "docs"
                | "examples"
                | "benchmarks"
        );
        if skipped || !is_importable(&path) {
            continue;
        }
        copy_tree(&path, &staging.join(&file))
            .map_err(|error| ArtifactError::Unpack(error.to_string()))?;
        copied += 1;
    }
    if copied == 0 {
        return Err(ArtifactError::Unpack(
            "the sdist holds no importable package or module".to_string(),
        ));
    }
    let dist_info = staging.join(format!("{}-{}.dist-info", name.replace('-', "_"), version));
    std::fs::create_dir_all(&dist_info)
        .map_err(|error| ArtifactError::Unpack(error.to_string()))?;
    std::fs::write(
        dist_info.join("METADATA"),
        format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"),
    )
    .and_then(|()| {
        std::fs::write(
            dist_info.join("INSTALLER"),
            "kin: source extracted from the sdist for reading, not built\n",
        )
    })
    .map_err(|error| ArtifactError::Unpack(error.to_string()))
}

/// Whether a path is a package (a directory with `__init__.py` or `.pyi`
/// stubs) or a module.
fn is_importable(path: &Path) -> bool {
    if path.is_dir() {
        return path.join("__init__.py").is_file() || path.join("__init__.pyi").is_file();
    }
    path.extension()
        .is_some_and(|extension| extension == "py" || extension == "pyi")
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    let kind = std::fs::symlink_metadata(from)?.file_type();
    if kind.is_dir() {
        std::fs::create_dir_all(to)?;
        for entry in std::fs::read_dir(from)?.filter_map(Result::ok) {
            copy_tree(&entry.path(), &to.join(entry.file_name()))?;
        }
    } else if kind.is_file() {
        std::fs::copy(from, to)?;
    }
    Ok(())
}

/// The file names in site-packages that run code when an interpreter
/// starts, and are never linked into an environment.
const STARTUP_HOOKS: &[&str] = &["sitecustomize.py", "usercustomize.py"];

/// The path lines of a `.pth` file: every line `site` would add to
/// `sys.path`, and none of the `import` lines it would execute.
pub fn pth_path_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with('#')
                && !line.starts_with("import ")
                && !line.starts_with("import\t")
        })
        .map(str::to_string)
        .collect()
}

#[cfg(unix)]
fn link(target: &Path, path: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, path)
}

#[cfg(not(unix))]
fn link(_target: &Path, _path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "analysis environments link their packages, which needs a unix host",
    ))
}

/// Link `source`'s entries into `site`, merging directories two artifacts
/// share (a namespace package spread over several wheels).
fn merge_into(source: &Path, site: &Path, top_level: bool) -> std::io::Result<()> {
    for entry in std::fs::read_dir(source)?.filter_map(Result::ok) {
        let file = entry.file_name();
        let name = file.to_string_lossy();
        let from = entry.path();
        let to = site.join(&file);
        if top_level && STARTUP_HOOKS.contains(&name.as_ref()) {
            continue;
        }
        if top_level && name.ends_with(".pth") {
            let lines = pth_path_lines(&std::fs::read_to_string(&from).unwrap_or_default());
            if !lines.is_empty() && !to.exists() {
                std::fs::write(&to, lines.join("\n") + "\n")?;
            }
            continue;
        }
        if top_level && name.ends_with(".data") {
            continue;
        }
        match std::fs::symlink_metadata(&to) {
            Err(_) => link(&from, &to)?,
            Ok(existing) => {
                // Both sides directories: make the existing one real and
                // merge into it.
                if !from.is_dir() || !to.is_dir() {
                    continue;
                }
                if existing.file_type().is_symlink() {
                    let previous = std::fs::read_link(&to)?;
                    std::fs::remove_file(&to)?;
                    std::fs::create_dir(&to)?;
                    merge_into(&previous, &to, false)?;
                }
                merge_into(&from, &to, false)?;
            }
        }
    }
    Ok(())
}

/// The site-packages directory of an environment for Python 3.`minor`.
pub fn site_packages(env: &Path, minor: u32) -> PathBuf {
    env.join("lib")
        .join(format!("python3.{minor}"))
        .join("site-packages")
}

/// Build the environment `envs/<identity>`: a venv on `interpreter` whose
/// site-packages links every artifact in `artifacts`. When a complete
/// environment of that identity exists it is replaced, so a rebuild after a
/// failed fetch picks up what now succeeds.
pub fn build_env(
    store: &Path,
    identity: &str,
    interpreter: &Path,
    minor: u32,
    version: &str,
    artifacts: &[PathBuf],
) -> Result<PathBuf, String> {
    let envs = store.join("envs");
    let destination = envs.join(identity);
    let staging = envs.join(format!(".{identity}.{}.tmp", unique_suffix()));
    let built = (|| -> std::io::Result<()> {
        let site = site_packages(&staging, minor);
        std::fs::create_dir_all(&site)?;
        std::fs::create_dir_all(staging.join("bin"))?;
        let home = interpreter.parent().unwrap_or(interpreter);
        std::fs::write(
            staging.join("pyvenv.cfg"),
            format!(
                "home = {}\ninclude-system-site-packages = false\nversion = {version}\n\
                 executable = {}\n",
                home.display(),
                interpreter.display()
            ),
        )?;
        link(interpreter, &staging.join("bin/python3"))?;
        link(Path::new("python3"), &staging.join("bin/python"))?;
        for artifact in artifacts {
            merge_into(artifact, &site, true)?;
        }
        Ok(())
    })();
    if let Err(error) = built {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(format!(
            "could not build {}: {error}",
            destination.display()
        ));
    }
    if destination.exists() {
        let retired = envs.join(format!(".{identity}.{}.old", unique_suffix()));
        let _ = std::fs::rename(&destination, &retired);
        let _ = std::fs::remove_dir_all(&retired);
    }
    publish_dir(&staging, &destination)?;
    Ok(destination)
}

/// The distributions installed in a site-packages directory, by normalized
/// name, with their versions, read from `*.dist-info` and `*.egg-info` names.
pub fn installed_distributions(site: &Path) -> Vec<(String, String)> {
    let Ok(entries) = std::fs::read_dir(site) else {
        return Vec::new();
    };
    let mut found: Vec<(String, String)> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let stem = name
                .strip_suffix(".dist-info")
                .or_else(|| name.strip_suffix(".egg-info"))?;
            let (distribution, rest) = stem.split_once('-')?;
            let version = rest.split('-').next()?;
            Some((
                super::lockfile::normalize_name(distribution),
                version.to_string(),
            ))
        })
        .collect();
    found.sort();
    found
}

/// Every site-packages under an installation or environment prefix.
pub fn site_packages_under(prefix: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for lib in ["lib", "lib64"] {
        let Ok(entries) = std::fs::read_dir(prefix.join(lib)) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            if entry.file_name().to_string_lossy().starts_with("python3") {
                let site = entry.path().join("site-packages");
                if site.is_dir() {
                    found.push(site);
                }
            }
        }
    }
    let windows = prefix.join("Lib/site-packages");
    if windows.is_dir() {
        found.push(windows);
    }
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::repo_scan::Fixture;

    #[test]
    fn pth_files_keep_their_paths_and_lose_their_imports() {
        let lines = pth_path_lines(
            "# comment\nimport os; os.environ['X'] = '1'\n./vendored\n\nimport\tsys\n/abs/path\n",
        );
        assert_eq!(lines, vec!["./vendored", "/abs/path"]);
    }

    #[cfg(unix)]
    #[test]
    fn an_environment_links_its_artifacts_and_holds_no_startup_hook() {
        let store = Fixture::new("store-env");
        let a = store.write("artifacts/aaa/ns/one/__init__.py", "");
        store.write("artifacts/aaa/one-1.0.dist-info/METADATA", "Name: one\n");
        store.write(
            "artifacts/aaa/evil.pth",
            "import os; os.system('x')\nextra\n",
        );
        store.write("artifacts/aaa/sitecustomize.py", "raise SystemExit\n");
        store.write("artifacts/bbb/ns/two/__init__.py", "");
        store.write("artifacts/bbb/two-2.0.dist-info/METADATA", "Name: two\n");
        let interpreter = store.write("interpreters/x/python/bin/python3.12", "");
        let env = build_env(
            &store.root,
            "abc",
            &interpreter,
            12,
            "3.12.14",
            &[
                store.root.join("artifacts/aaa"),
                store.root.join("artifacts/bbb"),
            ],
        )
        .unwrap();
        let site = site_packages(&env, 12);
        assert!(
            site.join("ns/one/__init__.py").is_file(),
            "namespace merged"
        );
        assert!(
            site.join("ns/two/__init__.py").is_file(),
            "namespace merged"
        );
        assert_eq!(
            std::fs::read_to_string(site.join("evil.pth")).unwrap(),
            "extra\n"
        );
        assert!(!site.join("sitecustomize.py").exists());
        assert_eq!(
            std::fs::read_link(env.join("bin/python3")).unwrap(),
            interpreter
        );
        assert!(std::fs::read_to_string(env.join("pyvenv.cfg"))
            .unwrap()
            .contains("include-system-site-packages = false"));
        assert_eq!(
            installed_distributions(&site),
            vec![
                ("one".to_string(), "1.0".to_string()),
                ("two".to_string(), "2.0".to_string())
            ]
        );
        assert!(a.is_file(), "the store itself is untouched");
    }
}

#[cfg(test)]
mod attempt_tests {
    use super::*;

    #[test]
    fn a_reused_process_suffix_cannot_reuse_another_attempt() {
        let fixture = crate::adapters::repo_scan::Fixture::new("archive-attempt");
        let other = fixture.root.join(".attempt-reused");
        std::fs::create_dir(&other).unwrap();
        std::fs::write(other.join("sentinel"), b"owned elsewhere").unwrap();
        let mut candidates = ["reused", "fresh"].into_iter();
        let attempt =
            OwnedAttempt::claim(&fixture.root, || candidates.next().unwrap().into()).unwrap();
        let owned = attempt.0.clone();
        assert_ne!(owned, other);
        drop(attempt);
        assert!(!owned.exists());
        assert_eq!(
            std::fs::read(other.join("sentinel")).unwrap(),
            b"owned elsewhere"
        );
    }
}
