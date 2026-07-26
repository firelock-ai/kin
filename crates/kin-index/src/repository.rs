// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact repository membership discovery.
//!
//! Repository membership is independent of parser support. This scanner admits
//! every regular file and symbolic link, including configuration, generated
//! output, vendored trees, binaries, and files in unsupported languages. Only
//! Kin/Git control metadata is inherently excluded.
//!
//! Explicit `.kinignore` rules apply only to paths that are not already tracked.
//! A tracked path remains observable after a rule begins matching it, so ignore
//! configuration can never silently turn graph-owned truth into a deletion.
//!
//! A caller receives [`CompleteRepositoryScan`] only after every representable
//! directory entry, metadata lookup, file read, and symbolic-link read
//! succeeds. Unsupported untracked special leaves are diagnosed and skipped;
//! an unsupported tracked path fails closed. Removal inference should accept
//! the complete result type rather than a partial path collection.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use kin_model::RepoPath;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Exact materialization kind observed at a host filesystem boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannedEntryKind {
    Regular { executable: bool },
    Symlink,
}

/// One completely read repository leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedRepositoryEntry {
    pub repo_path: RepoPath,
    pub host_path: PathBuf,
    pub content_hash: [u8; 32],
    pub kind: ScannedEntryKind,
}

/// Evidence accumulated before a repository scan completed or failed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RepositoryScanDiagnostics {
    pub directories_visited: usize,
    pub entries_inspected: usize,
    pub admitted_entries: usize,
    pub ignored_untracked_entries: usize,
    /// Host leaves outside Kin's regular-file/symlink tree that were skipped.
    ///
    /// A tracked path with one of these types fails the scan instead.
    pub unsupported_untracked_entries: usize,
    /// Imported graph-only members preserved without inferring identity from
    /// their host materialization.
    pub graph_only_entries_preserved: usize,
    pub content_bytes_read: u64,
}

/// A repository scan that did not observe the complete host tree.
#[derive(Debug, Error)]
#[error(
    "repository scan incomplete during {operation} at {path}: {reason}; \
     diagnostics: {diagnostics:?}"
)]
pub struct IncompleteRepositoryScan {
    pub path: PathBuf,
    pub operation: &'static str,
    pub reason: String,
    pub diagnostics: RepositoryScanDiagnostics,
}

impl IncompleteRepositoryScan {
    fn io(
        path: impl Into<PathBuf>,
        operation: &'static str,
        error: impl std::fmt::Display,
        diagnostics: RepositoryScanDiagnostics,
    ) -> Self {
        Self {
            path: path.into(),
            operation,
            reason: error.to_string(),
            diagnostics,
        }
    }
}

/// Proof that every repository entry was observed successfully.
///
/// The private field prevents callers from fabricating completion after a
/// partial or failed walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompleteScanToken {
    _private: (),
}

/// A byte-exact, fully successful repository scan.
#[derive(Debug)]
pub struct CompleteRepositoryScan {
    entries: BTreeMap<RepoPath, ScannedRepositoryEntry>,
    graph_only_paths: BTreeSet<RepoPath>,
    diagnostics: RepositoryScanDiagnostics,
    completion: CompleteScanToken,
}

impl CompleteRepositoryScan {
    pub fn entries(
        &self,
    ) -> impl ExactSizeIterator<Item = &ScannedRepositoryEntry> + DoubleEndedIterator {
        self.entries.values()
    }

    pub fn entry(&self, path: &RepoPath) -> Option<&ScannedRepositoryEntry> {
        self.entries.get(path)
    }

    pub fn paths(&self) -> impl ExactSizeIterator<Item = &RepoPath> + DoubleEndedIterator {
        self.entries.keys()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub const fn diagnostics(&self) -> RepositoryScanDiagnostics {
        self.diagnostics
    }

    pub const fn completion(&self) -> CompleteScanToken {
        self.completion
    }

    /// Paths known to graph truth that are absent from this complete scan.
    ///
    /// This method deliberately lives on the complete result so no partial
    /// collection can authorize inferred removal.
    pub fn missing_tracked_paths<'a>(
        &'a self,
        tracked: impl IntoIterator<Item = &'a RepoPath>,
    ) -> Vec<RepoPath> {
        tracked
            .into_iter()
            .filter(|path| {
                !self.entries.contains_key(*path) && !self.graph_only_paths.contains(*path)
            })
            .cloned()
            .collect()
    }
}

/// Literal, repo-scoped admission rules loaded from `.kinignore`.
///
/// A pattern without `/` matches a component at any depth. A pattern with `/`
/// matches one repository path or its descendants. Glob interpretation is
/// intentionally absent.
#[derive(Debug, Clone, Default)]
pub struct RepositoryIgnore {
    names: BTreeSet<Vec<u8>>,
    prefixes: Vec<RepoPath>,
}

impl RepositoryIgnore {
    pub fn load(root: &Path) -> Result<Self, IncompleteRepositoryScan> {
        let path = root.join(".kinignore");
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => {
                return Err(IncompleteRepositoryScan::io(
                    path,
                    "read ignore rules",
                    error,
                    RepositoryScanDiagnostics::default(),
                ));
            }
        };
        let content = std::str::from_utf8(&bytes).map_err(|error| {
            IncompleteRepositoryScan::io(
                &path,
                "decode ignore rules",
                error,
                RepositoryScanDiagnostics::default(),
            )
        })?;

        let mut rules = Self::default();
        for (line_index, raw) in content.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let pattern = line.trim_end_matches('/');
            let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
            if pattern.is_empty() {
                continue;
            }
            if pattern.contains('/') {
                let prefix = RepoPath::from_utf8(pattern).map_err(|error| {
                    IncompleteRepositoryScan::io(
                        &path,
                        "parse ignore rules",
                        format!("line {}: {error}", line_index + 1),
                        RepositoryScanDiagnostics::default(),
                    )
                })?;
                rules.prefixes.push(prefix);
            } else {
                rules.names.insert(pattern.as_bytes().to_vec());
            }
        }
        rules.prefixes.sort();
        rules.prefixes.dedup();
        Ok(rules)
    }

    pub fn matches(&self, path: &RepoPath) -> bool {
        let bytes = path.as_bytes();
        if bytes
            .split(|byte| *byte == b'/')
            .any(|component| self.names.contains(component))
        {
            return true;
        }
        self.prefixes.iter().any(|prefix| {
            bytes == prefix.as_bytes()
                || bytes
                    .strip_prefix(prefix.as_bytes())
                    .is_some_and(|suffix| suffix.starts_with(b"/"))
        })
    }
}

/// Convert a host-relative path to Kin's byte-exact repository path.
pub fn repo_path_from_host_relative(path: &Path) -> io::Result<RepoPath> {
    let mut bytes = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => {
                if !bytes.is_empty() {
                    bytes.push(b'/');
                }
                #[cfg(unix)]
                {
                    use std::os::unix::ffi::OsStrExt;
                    bytes.extend_from_slice(name.as_bytes());
                }
                #[cfg(not(unix))]
                {
                    let name = name.to_str().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "host path cannot be represented exactly on this platform",
                        )
                    })?;
                    bytes.extend_from_slice(name.as_bytes());
                }
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("repository path must be relative: {}", path.display()),
                ));
            }
        }
    }
    RepoPath::from_bytes(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

/// Materialize a byte-exact repository path beneath one host root.
///
/// Platforms that cannot represent the path exactly fail loudly here.
pub fn host_path_from_repo_path(root: &Path, path: &RepoPath) -> io::Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(root.join(std::ffi::OsString::from_vec(path.as_bytes().to_vec())))
    }
    #[cfg(not(unix))]
    {
        let path = path.as_utf8().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "repository path cannot be projected exactly on this platform",
            )
        })?;
        Ok(root.join(path.replace('/', std::path::MAIN_SEPARATOR_STR)))
    }
}

fn is_control_component(component: &[u8]) -> bool {
    component == b".kin"
        || component == b".git"
        || component == b".git-export"
        || component == b".kin-session"
        || component == b".kin-session.json"
        || component == b".kin-shadow"
        || component.starts_with(b".kin-reconcile-")
        || component.starts_with(b".kin-checkout-")
}

/// Whether a repository path names Kin/Git control metadata.
pub fn is_repository_control_path(path: &RepoPath) -> bool {
    path.as_bytes()
        .split(|byte| *byte == b'/')
        .any(is_control_component)
}

/// Whether a host-relative path can participate in repository truth.
///
/// Failure to represent a path exactly returns `false` here for legacy
/// predicate callers. Exact scan callers use [`scan_repository`] and receive a
/// loud error with diagnostics instead.
pub fn should_track_host_relative_path(path: &Path) -> bool {
    repo_path_from_host_relative(path)
        .map(|path| !is_repository_control_path(&path))
        .unwrap_or(false)
}

/// Scan every admitted leaf under `root`.
///
/// `tracked_paths` is graph-owned identity state. Ignore rules never hide
/// those paths, including paths below an ignored directory.
pub fn scan_repository<'a>(
    root: &Path,
    ignore: &RepositoryIgnore,
    tracked_paths: impl IntoIterator<Item = &'a RepoPath>,
) -> Result<CompleteRepositoryScan, IncompleteRepositoryScan> {
    scan_repository_preserving_graph_only(
        root,
        ignore,
        tracked_paths,
        std::iter::empty::<&'a RepoPath>(),
    )
}

/// Scan host-representable leaves while preserving graph-only membership.
///
/// `graph_only_paths` currently carries imported Gitlinks. Their identity is
/// owned by graph/import truth; a host directory is neither evidence for a
/// Gitlink nor permission to expand its checkout into sibling Kin artifacts.
pub fn scan_repository_preserving_graph_only<'a>(
    root: &Path,
    ignore: &RepositoryIgnore,
    tracked_paths: impl IntoIterator<Item = &'a RepoPath>,
    graph_only_paths: impl IntoIterator<Item = &'a RepoPath>,
) -> Result<CompleteRepositoryScan, IncompleteRepositoryScan> {
    let tracked_paths = tracked_paths.into_iter().cloned().collect::<BTreeSet<_>>();
    let graph_only_paths = graph_only_paths
        .into_iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if !graph_only_paths.is_subset(&tracked_paths) {
        return Err(IncompleteRepositoryScan::io(
            root,
            "validate graph-only scan baseline",
            "every graph-only path must also be tracked",
            RepositoryScanDiagnostics::default(),
        ));
    }
    let mut scanner = Scanner {
        root,
        ignore,
        tracked_paths,
        graph_only_paths,
        entries: BTreeMap::new(),
        diagnostics: RepositoryScanDiagnostics::default(),
    };
    scanner.walk(root)?;
    scanner.diagnostics.admitted_entries = scanner.entries.len();
    scanner.diagnostics.graph_only_entries_preserved = scanner.graph_only_paths.len();
    Ok(CompleteRepositoryScan {
        entries: scanner.entries,
        graph_only_paths: scanner.graph_only_paths,
        diagnostics: scanner.diagnostics,
        completion: CompleteScanToken { _private: () },
    })
}

struct Scanner<'a> {
    root: &'a Path,
    ignore: &'a RepositoryIgnore,
    tracked_paths: BTreeSet<RepoPath>,
    graph_only_paths: BTreeSet<RepoPath>,
    entries: BTreeMap<RepoPath, ScannedRepositoryEntry>,
    diagnostics: RepositoryScanDiagnostics,
}

impl Scanner<'_> {
    fn fail(
        &self,
        path: impl Into<PathBuf>,
        operation: &'static str,
        error: impl std::fmt::Display,
    ) -> IncompleteRepositoryScan {
        IncompleteRepositoryScan::io(path, operation, error, self.diagnostics)
    }

    fn is_tracked_or_contains_tracked(&self, path: &RepoPath) -> bool {
        self.tracked_paths.iter().any(|tracked| {
            tracked == path
                || tracked
                    .as_bytes()
                    .strip_prefix(path.as_bytes())
                    .is_some_and(|suffix| suffix.starts_with(b"/"))
        })
    }

    fn walk(&mut self, directory: &Path) -> Result<(), IncompleteRepositoryScan> {
        self.diagnostics.directories_visited += 1;
        let entries = fs::read_dir(directory)
            .map_err(|error| self.fail(directory, "read directory", error))?;

        for entry in entries {
            let entry =
                entry.map_err(|error| self.fail(directory, "read directory entry", error))?;
            self.diagnostics.entries_inspected += 1;
            let host_path = entry.path();
            let relative = host_path
                .strip_prefix(self.root)
                .map_err(|error| self.fail(&host_path, "resolve repository path", error))?;
            let repo_path = repo_path_from_host_relative(relative)
                .map_err(|error| self.fail(&host_path, "encode repository path", error))?;

            if is_repository_control_path(&repo_path) {
                continue;
            }

            let file_type = entry
                .file_type()
                .map_err(|error| self.fail(&host_path, "read entry type", error))?;
            if self.graph_only_paths.contains(&repo_path) {
                // Imported Gitlink identity cannot be reconstructed from a
                // materialized submodule directory. Preserve graph truth and
                // never reinterpret its checkout as ordinary child artifacts.
                continue;
            }
            let ignored = self.ignore.matches(&repo_path);

            if file_type.is_dir() {
                if ignored && !self.is_tracked_or_contains_tracked(&repo_path) {
                    self.diagnostics.ignored_untracked_entries += 1;
                    continue;
                }
                self.walk(&host_path)?;
                continue;
            }

            if ignored && !self.tracked_paths.contains(&repo_path) {
                self.diagnostics.ignored_untracked_entries += 1;
                continue;
            }

            let (content_hash, content_len, kind) = if file_type.is_file() {
                let (hash, bytes, executable) = self.hash_regular_file(&host_path)?;
                (hash, bytes, ScannedEntryKind::Regular { executable })
            } else if file_type.is_symlink() {
                let before = fs::symlink_metadata(&host_path)
                    .map_err(|error| self.fail(&host_path, "read symbolic-link metadata", error))?;
                if !before.file_type().is_symlink() {
                    return Err(self.fail(
                        &host_path,
                        "verify symbolic-link type",
                        "entry changed type during scan",
                    ));
                }
                let target = fs::read_link(&host_path)
                    .map_err(|error| self.fail(&host_path, "read symbolic link", error))?;
                let target_bytes = symlink_target_bytes(&target)
                    .map_err(|error| self.fail(&host_path, "encode symbolic-link target", error))?;
                let observed_again = fs::read_link(&host_path)
                    .map_err(|error| self.fail(&host_path, "re-read symbolic link", error))?;
                let observed_again = symlink_target_bytes(&observed_again).map_err(|error| {
                    self.fail(&host_path, "re-encode symbolic-link target", error)
                })?;
                let after = fs::symlink_metadata(&host_path).map_err(|error| {
                    self.fail(&host_path, "re-read symbolic-link metadata", error)
                })?;
                if target_bytes != observed_again || !same_file_observation(&before, &after) {
                    return Err(self.fail(
                        &host_path,
                        "verify symbolic link",
                        "symbolic-link identity or target changed during scan",
                    ));
                }
                (
                    sha256_bytes(&target_bytes),
                    target_bytes.len() as u64,
                    ScannedEntryKind::Symlink,
                )
            } else {
                if self.is_tracked_or_contains_tracked(&repo_path) {
                    return Err(self.fail(
                        &host_path,
                        "inspect tracked repository entry",
                        "tracked path changed to an unsupported special filesystem entry",
                    ));
                }
                self.diagnostics.unsupported_untracked_entries += 1;
                continue;
            };
            self.diagnostics.content_bytes_read = self
                .diagnostics
                .content_bytes_read
                .saturating_add(content_len);
            self.entries.insert(
                repo_path.clone(),
                ScannedRepositoryEntry {
                    repo_path,
                    host_path,
                    content_hash,
                    kind,
                },
            );
        }
        Ok(())
    }

    fn hash_regular_file(
        &self,
        path: &Path,
    ) -> Result<([u8; 32], u64, bool), IncompleteRepositoryScan> {
        self.hash_regular_file_after_open(path, || {})
    }

    fn hash_regular_file_after_open(
        &self,
        path: &Path,
        after_open: impl FnOnce(),
    ) -> Result<([u8; 32], u64, bool), IncompleteRepositoryScan> {
        // Hash the object reached by a no-follow handle. The before/after
        // samples below are fstat observations of that handle, not independent
        // path metadata reads.
        let mut file = open_regular_file_nofollow(path)
            .map_err(|error| self.fail(path, "open file content without following links", error))?;
        let before = file
            .metadata()
            .map_err(|error| self.fail(path, "read opened file metadata", error))?;
        if !before.is_file() {
            return Err(self.fail(path, "verify file type", "entry changed type during scan"));
        }
        let executable = regular_file_is_executable(&before);
        after_open();
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut bytes_read = 0_u64;
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|error| self.fail(path, "read file content", error))?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            bytes_read = bytes_read.saturating_add(count as u64);
        }
        let after = file
            .metadata()
            .map_err(|error| self.fail(path, "re-read opened file metadata", error))?;
        if !same_file_observation(&before, &after) || bytes_read != after.len() {
            return Err(self.fail(path, "verify file content", "file changed during scan"));
        }

        // A stable descriptor can outlive a rename. Ensure the repository path
        // still names the exact object just hashed before publishing its
        // path-to-blob identity.
        let path_after = fs::symlink_metadata(path)
            .map_err(|error| self.fail(path, "verify hashed file path", error))?;
        if !same_file_observation(&after, &path_after) {
            return Err(self.fail(
                path,
                "verify hashed file path",
                "repository path changed identity during scan",
            ));
        }
        let digest = hasher.finalize();
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&digest);
        Ok((hash, bytes_read, executable))
    }
}

/// Re-read one scanned leaf without following a regular-file symlink swap and
/// verify that its exact bytes and materialization kind still match the scan.
///
/// Callers that persist blobs after walking (commit, init snapshot) must use
/// this instead of reopening `host_path` with a path-following read.
pub fn read_verified_scanned_entry(entry: &ScannedRepositoryEntry) -> io::Result<Vec<u8>> {
    let changed = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "repository entry changed after complete scan: {}",
                entry.repo_path
            ),
        )
    };

    let bytes = match entry.kind {
        ScannedEntryKind::Regular { executable } => {
            let mut file = open_regular_file_nofollow(&entry.host_path)?;
            let before = file.metadata()?;
            if !before.is_file() || regular_file_is_executable(&before) != executable {
                return Err(changed());
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            let after = file.metadata()?;
            let path_after = fs::symlink_metadata(&entry.host_path)?;
            if !same_file_observation(&before, &after)
                || !same_file_observation(&after, &path_after)
                || bytes.len() as u64 != after.len()
            {
                return Err(changed());
            }
            bytes
        }
        ScannedEntryKind::Symlink => {
            let before = fs::symlink_metadata(&entry.host_path)?;
            if !before.file_type().is_symlink() {
                return Err(changed());
            }
            let target = fs::read_link(&entry.host_path)?;
            let bytes = symlink_target_bytes(&target)?;
            let target_again = fs::read_link(&entry.host_path)?;
            let bytes_again = symlink_target_bytes(&target_again)?;
            let after = fs::symlink_metadata(&entry.host_path)?;
            if bytes != bytes_again || !same_file_observation(&before, &after) {
                return Err(changed());
            }
            bytes
        }
    };

    if sha256_bytes(&bytes) != entry.content_hash {
        return Err(changed());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_regular_file_nofollow(path: &Path) -> io::Result<fs::File> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(io::Error::from)?;
    Ok(fs::File::from(fd))
}

#[cfg(not(unix))]
fn open_regular_file_nofollow(path: &Path) -> io::Result<fs::File> {
    // The handle/path verification below remains fail-closed for observable
    // races. A native no-follow open is still required before non-Unix scans
    // can be used as citable release proof.
    fs::OpenOptions::new().read(true).open(path)
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

#[cfg(unix)]
fn regular_file_is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn regular_file_is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn same_file_observation(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.file_type() == after.file_type()
        && before.len() == after.len()
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_observation(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.file_type() == after.file_type()
        && before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
}

#[cfg(unix)]
fn symlink_target_bytes(target: &Path) -> io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    Ok(target.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
fn symlink_target_bytes(target: &Path) -> io::Result<Vec<u8>> {
    target
        .to_str()
        .map(|target| target.as_bytes().to_vec())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "symbolic-link target cannot be represented exactly on this platform",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> RepoPath {
        RepoPath::from_utf8(value).unwrap()
    }

    fn scan(root: &Path) -> CompleteRepositoryScan {
        let ignore = RepositoryIgnore::load(root).unwrap();
        scan_repository(root, &ignore, std::iter::empty()).unwrap()
    }

    #[test]
    fn scan_admits_every_non_control_repository_surface() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let files: &[(&str, &[u8])] = &[
            ("Dockerfile", b"FROM alpine"),
            ("compose.yaml", b"services: {}"),
            ("Cargo.lock", b"version = 4"),
            ("package-lock.json", b"{}"),
            ("src/main.rs", b"fn main() {}"),
            ("src/tool.py", b"print('hi')"),
            ("notes/brain.brainfuck", b"+++[>+++<-]"),
            ("assets/logo.bin", b"\x00\xff\x10"),
            ("unrelated/receipt.pdf", b"%PDF-not-really"),
            ("node_modules/pkg/index.js", b"export default 1"),
            ("target/generated.rs", b"pub const GENERATED: bool = true;"),
            ("vendor/lib/source.c", b"int vendored(void) { return 1; }"),
            ("dist/app.js", b"console.log('dist')"),
            ("build/report.txt", b"build output"),
            ("out/data", b"output"),
            ("__pycache__/state.bin", b"cache"),
            (".next/server/app.js", b"next"),
            (".env.example", b"NAME=value"),
            (".kinignore", b""),
        ];
        for (relative, content) in files {
            let host = root.join(relative);
            fs::create_dir_all(host.parent().unwrap()).unwrap();
            fs::write(host, content).unwrap();
        }
        fs::create_dir_all(root.join(".git/objects")).unwrap();
        fs::write(root.join(".git/config"), b"control").unwrap();
        fs::create_dir_all(root.join(".kin/objects")).unwrap();
        fs::write(root.join(".kin/config.toml"), b"control").unwrap();
        fs::create_dir_all(root.join(".kin-session")).unwrap();
        fs::write(root.join(".kin-session/base.json"), b"control").unwrap();
        fs::create_dir_all(root.join(".kin-reconcile-test")).unwrap();
        fs::write(root.join(".kin-reconcile-test/leak"), b"control").unwrap();
        fs::create_dir_all(root.join(".kin-release")).unwrap();
        fs::write(root.join(".kin-release/downstreams.json"), b"{}").unwrap();

        let scan = scan(root);
        let paths = scan.paths().cloned().collect::<BTreeSet<_>>();
        for (relative, _) in files {
            assert!(paths.contains(&path(relative)), "missing {relative}");
        }
        assert!(paths.contains(&path(".kin-release/downstreams.json")));
        assert!(!paths.iter().any(is_repository_control_path));
        assert_eq!(scan.len(), files.len() + 1);
        assert_eq!(scan.diagnostics().admitted_entries, files.len() + 1);
    }

    #[cfg(unix)]
    #[test]
    fn scan_preserves_executable_and_symlink_identity() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let executable = root.join("tool");
        fs::write(&executable, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        symlink(Path::new("tool"), root.join("current")).unwrap();

        let scan = scan(root);
        assert_eq!(
            scan.entry(&path("tool")).unwrap().kind,
            ScannedEntryKind::Regular { executable: true }
        );
        assert_eq!(
            scan.entry(&path("current")).unwrap().kind,
            ScannedEntryKind::Symlink
        );
    }

    #[cfg(unix)]
    #[test]
    fn repo_path_codec_preserves_non_utf8_identity() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let raw = vec![b'n', b'o', b'n', 0xff];
        let host_relative = PathBuf::from(std::ffi::OsString::from_vec(raw.clone()));
        let repo_path = repo_path_from_host_relative(&host_relative).unwrap();
        assert_eq!(repo_path.as_bytes(), raw);
        let projected = host_path_from_repo_path(Path::new("/projection"), &repo_path).unwrap();
        assert_eq!(projected.file_name().unwrap().as_bytes(), raw);
    }

    // APFS rejects illegal UTF-8 byte sequences before the scanner can observe
    // them. Unix hosts whose filesystems permit arbitrary filename bytes also
    // exercise the complete scan path.
    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn scan_preserves_non_utf8_path_identity() {
        use std::os::unix::ffi::OsStringExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let non_utf8_name = std::ffi::OsString::from_vec(vec![b'n', b'o', b'n', 0xff]);
        fs::write(root.join(&non_utf8_name), b"bytes").unwrap();

        let scan = scan(root);
        let non_utf8 = RepoPath::from_bytes(vec![b'n', b'o', b'n', 0xff]).unwrap();
        assert!(scan.entry(&non_utf8).is_some());
    }

    #[test]
    fn explicit_ignore_applies_only_before_tracking() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("target/nested")).unwrap();
        fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        fs::write(root.join("target/nested/new.bin"), b"new").unwrap();
        fs::write(root.join("target/retained.bin"), b"retained").unwrap();
        fs::write(root.join("node_modules/pkg/index.js"), b"generated").unwrap();
        fs::write(root.join(".env"), b"SECRET=never-admit-untracked").unwrap();
        fs::write(root.join(".kinignore"), b"target/\nnode_modules/\n.env\n").unwrap();
        let ignore = RepositoryIgnore::load(root).unwrap();

        let initial = scan_repository(root, &ignore, std::iter::empty()).unwrap();
        assert!(initial.entry(&path("target/nested/new.bin")).is_none());
        assert!(initial.entry(&path("target/retained.bin")).is_none());
        assert!(initial.entry(&path("node_modules/pkg/index.js")).is_none());
        assert!(initial.entry(&path(".env")).is_none());

        let retained = path("target/retained.bin");
        fs::write(root.join("target/retained.bin"), b"updated tracked bytes").unwrap();
        let tracked = scan_repository(root, &ignore, [&retained]).unwrap();
        assert!(tracked.entry(&retained).is_some());
        assert_eq!(
            tracked.entry(&retained).unwrap().content_hash,
            sha256_bytes(b"updated tracked bytes")
        );
        assert!(tracked.entry(&path("target/nested/new.bin")).is_none());
        assert!(tracked.entry(&path("node_modules/pkg/index.js")).is_none());
        assert!(tracked.entry(&path(".env")).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn unsupported_untracked_special_entry_is_diagnosed_and_skipped() {
        use std::os::unix::net::UnixListener;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::write(root.join("tracked.txt"), b"tracked").unwrap();
        let _listener = UnixListener::bind(root.join("untracked.sock")).unwrap();

        let tracked = path("tracked.txt");
        let complete = scan_repository(root, &RepositoryIgnore::default(), [&tracked]).unwrap();
        assert!(complete.entry(&tracked).is_some());
        assert!(complete.entry(&path("untracked.sock")).is_none());
        assert_eq!(complete.diagnostics().unsupported_untracked_entries, 1);
        assert!(complete.missing_tracked_paths([&tracked]).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn tracked_special_entry_makes_scan_incomplete() {
        use std::os::unix::net::UnixListener;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let tracked = path("tracked.sock");
        let _listener = UnixListener::bind(root.join("tracked.sock")).unwrap();

        let incomplete = scan_repository(root, &RepositoryIgnore::default(), [&tracked])
            .expect_err("tracked special entry must fail the complete scan");
        assert_eq!(incomplete.operation, "inspect tracked repository entry");
        assert!(incomplete.reason.contains("tracked path changed"));
    }

    #[cfg(unix)]
    #[test]
    fn incomplete_scan_never_produces_a_removal_authority_token() {
        use std::os::unix::net::UnixListener;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::write(root.join("tracked.txt"), b"tracked").unwrap();
        let tracked = path("tracked.txt");
        let complete = scan_repository(root, &RepositoryIgnore::default(), [&tracked]).unwrap();
        assert!(complete.missing_tracked_paths([&tracked]).is_empty());
        let _token = complete.completion();

        let tracked_special = path("injected-scan-failure.sock");
        let _listener = UnixListener::bind(root.join("injected-scan-failure.sock")).unwrap();
        fs::remove_file(root.join("tracked.txt")).unwrap();
        let incomplete = scan_repository(
            root,
            &RepositoryIgnore::default(),
            [&tracked, &tracked_special],
        )
        .expect_err("tracked special entry must make the scan incomplete");
        assert_eq!(incomplete.operation, "inspect tracked repository entry");
        assert!(incomplete.diagnostics.entries_inspected > 0);
    }

    #[cfg(unix)]
    #[test]
    fn rename_and_symlink_swap_during_hash_fails_closed() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let live = root.join("live");
        let moved = root.join("moved");
        fs::write(&live, b"original bytes").unwrap();
        fs::write(root.join("replacement"), b"replacement").unwrap();
        let ignore = RepositoryIgnore::default();
        let scanner = Scanner {
            root,
            ignore: &ignore,
            tracked_paths: BTreeSet::new(),
            graph_only_paths: BTreeSet::new(),
            entries: BTreeMap::new(),
            diagnostics: RepositoryScanDiagnostics::default(),
        };

        let error = scanner
            .hash_regular_file_after_open(&live, || {
                fs::rename(&live, &moved).unwrap();
                symlink(Path::new("replacement"), &live).unwrap();
            })
            .expect_err("a stable old descriptor must not mask a path identity swap");
        assert!(
            matches!(
                error.operation,
                "verify file content" | "verify hashed file path"
            ),
            "unexpected fail-closed stage: {error:?}"
        );
    }

    #[test]
    fn graph_only_gitlink_is_preserved_without_expanding_host_checkout() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("submodule/src")).unwrap();
        fs::write(root.join("submodule/src/lib.rs"), b"submodule checkout").unwrap();
        fs::write(root.join("ordinary.txt"), b"ordinary").unwrap();
        let gitlink = path("submodule");

        let scan = scan_repository_preserving_graph_only(
            root,
            &RepositoryIgnore::default(),
            [&gitlink],
            [&gitlink],
        )
        .unwrap();
        assert!(scan.entry(&gitlink).is_none());
        assert!(scan.entry(&path("submodule/src/lib.rs")).is_none());
        assert!(scan.entry(&path("ordinary.txt")).is_some());
        assert!(scan.missing_tracked_paths([&gitlink]).is_empty());
        assert_eq!(scan.diagnostics().graph_only_entries_preserved, 1);

        fs::remove_dir_all(root.join("submodule")).unwrap();
        let deinitialized = scan_repository_preserving_graph_only(
            root,
            &RepositoryIgnore::default(),
            [&gitlink],
            [&gitlink],
        )
        .unwrap();
        assert!(
            deinitialized.missing_tracked_paths([&gitlink]).is_empty(),
            "host absence cannot infer removal of graph-owned Gitlink identity"
        );
    }

    #[test]
    fn missing_root_is_an_incomplete_scan_with_diagnostics() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        let error = scan_repository(&missing, &RepositoryIgnore::default(), std::iter::empty())
            .unwrap_err();
        assert_eq!(error.operation, "read directory");
        assert_eq!(error.diagnostics.directories_visited, 1);
    }
}
