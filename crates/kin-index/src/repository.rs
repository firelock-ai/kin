// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact repository membership discovery.
//!
//! Repository membership is independent of parser support. This scanner admits
//! every regular file and symbolic link, including configuration, vendored
//! trees, binaries, and files in unsupported languages. Kin/Git control
//! metadata is inherently excluded, and the compiler/packager output named by
//! [`DEFAULT_IGNORED_NAMES`] is excluded by default because the graph is the
//! system of record for source truth, not for derived bytes that any build
//! reproduces. A Python virtual environment is excluded by the same default on
//! different evidence: it is recognized by [`PYTHON_VIRTUALENV_MARKER`] rather
//! than by its directory name, which no rule could predict.
//!
//! An ignore rule is a statement about IO, not only about membership. Nothing
//! the effective rules exclude is opened, read, hashed, or verified here, and
//! an excluded directory is not descended into at all. A tracked path the rules
//! exclude is recorded as unverified instead: the walk reports that it declined
//! to observe the path rather than reporting it absent, so an ignored subtree
//! can neither cost content reads nor turn its own churn into a failure of the
//! tree around it.
//!
//! The scanner therefore never turns graph-owned identity into a deletion on
//! its own. Deciding that an already-admitted path should go is the caller's,
//! and it is made against graph truth rather than against the walk:
//! [`tracked_paths_retracted_by_ignore`] names exactly which tracked paths the
//! current rules retract, and a caller withholds those from the tracked set it
//! passes here. Admission and retraction therefore read one compiled rule set
//! through one predicate, [`RepositoryIgnore::matches`].
//!
//! Imported graph-only members are never in that set. Their identity comes from
//! import truth and no host walk could rebuild it, so a rule matching their path
//! does not retire them.
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

use crate::admission::ResolvedAdmissionMatcher;

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
    /// Tracked paths the effective rules exclude, observed as unverified.
    ///
    /// None of them was opened or read, so every one of them contributes zero
    /// to `content_bytes_read` and none can fail the scan by changing.
    pub ignored_tracked_entries_unverified: usize,
    /// Host leaves outside Kin's regular-file/symlink tree that were skipped.
    ///
    /// A tracked path with one of these types fails the scan instead.
    pub unsupported_untracked_entries: usize,
    /// Imported graph-only members preserved without inferring identity from
    /// their host materialization.
    pub graph_only_entries_preserved: usize,
    /// Untracked entries the graph-owned admission policy excludes.
    ///
    /// Counted apart from `ignored_untracked_entries` because the two rule sets
    /// are different objects: that one is this repository's `.kinignore` and the
    /// built-in defaults, and this one is the durable policy compiled from every
    /// `.gitignore`/`.kinignore` blob in the tree plus the frozen local overlay.
    /// A path only the second excludes used to be proposed by the walk and
    /// refused at the authority boundary, which failed the whole admission.
    pub policy_excluded_untracked_entries: usize,
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
    unverified_ignored_paths: BTreeSet<RepoPath>,
    policy_excluded_sample: Vec<RepoPath>,
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

    /// A bounded sample of the untracked paths the graph-owned admission
    /// policy excluded from this walk.
    ///
    /// Bounded because an excluded directory is skipped whole and its leaves
    /// are never counted individually, but a policy that names many separate
    /// files still could. The count in the diagnostics is complete; this names
    /// enough of it for an operator to recognize which rule is at work.
    pub fn policy_excluded_paths_sample(&self) -> &[RepoPath] {
        &self.policy_excluded_sample
    }

    /// Tracked paths the effective ignore rules excluded from observation.
    ///
    /// The walk declined to open, read, or descend into them, so it holds no
    /// evidence about their content and none about whether they still exist. A
    /// caller keeps its graph truth for these paths, or retracts them outright
    /// through [`tracked_paths_retracted_by_ignore`].
    pub fn unverified_ignored_paths(
        &self,
    ) -> impl ExactSizeIterator<Item = &RepoPath> + DoubleEndedIterator {
        self.unverified_ignored_paths.iter()
    }

    /// Paths known to graph truth that are absent from this complete scan.
    ///
    /// This method deliberately lives on the complete result so no partial
    /// collection can authorize inferred removal. An unverified ignored path is
    /// unobserved rather than absent, so it is never reported here: inferring
    /// its removal would let a rule delete graph-owned truth silently, which is
    /// the job of an announced retraction and of nothing else.
    pub fn missing_tracked_paths<'a>(
        &'a self,
        tracked: impl IntoIterator<Item = &'a RepoPath>,
    ) -> Vec<RepoPath> {
        tracked
            .into_iter()
            .filter(|path| {
                !self.entries.contains_key(*path)
                    && !self.graph_only_paths.contains(*path)
                    && !self.unverified_ignored_paths.contains(*path)
            })
            .cloned()
            .collect()
    }
}

/// Names excluded from repository membership before any `.kinignore` is read.
///
/// Every entry is compiler, packager, or tool output that a build reproduces
/// from source already under graph truth. Admitting them costs content-address
/// storage and retrieval quality while adding no semantic truth.
///
/// Ambiguous names are deliberately absent. `build`, `out`, `bin`, `vendor`,
/// and `coverage` routinely hold hand-written source or vendored dependency
/// source, so they stay admitted and a repository that wants them excluded says
/// so in its `.kinignore`. The rule for adding an entry here is that the name
/// must be unambiguously derived output across the ecosystems that use it.
///
/// `venv` and `env` are the same problem and get a different answer:
/// [`PYTHON_VIRTUALENV_MARKER`] recognizes a virtual environment by the file
/// PEP 405 requires it to carry, so an environment is excluded whatever it was
/// named while an ordinary directory sharing the name stays admitted.
///
/// A `!` rule re-admits anything here, and re-admission is scoped: it cancels
/// only the rules matching at or above its own boundary, so `!target` does not
/// also re-admit `target/node_modules`.
pub const DEFAULT_IGNORED_NAMES: &[&str] = &[
    // Rust, Maven, and sbt build output. This is the name that dominates
    // derived-byte volume in a polyglot workspace.
    "target",
    // Package-manager dependency trees.
    "node_modules",
    "bower_components",
    "__pypackages__",
    // JavaScript and Python packaging output.
    "dist",
    // Python bytecode and environment/tool caches.
    "__pycache__",
    ".venv",
    ".tox",
    ".nox",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".ipynb_checkpoints",
    ".eggs",
    // JavaScript framework and bundler caches.
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".parcel-cache",
    ".nyc_output",
    // Build-tool and provider caches.
    ".gradle",
    ".terraform",
    // Kin fleet lane-coordination state.
    ".kin-coord",
    // Finder metadata.
    ".DS_Store",
];

/// The file PEP 405 requires at the root of every Python virtual environment.
///
/// A name list cannot answer this one. `python3 -m venv <name>` takes the name
/// from its caller, `.venv` and `venv` and `env` are all in common use, and two
/// of those three routinely name ordinary source directories, so excluding them
/// by name would either miss real environments or delete real code from the
/// graph. The marker is the interpreter's own declaration that a directory is a
/// materialized environment rather than authored source, and `python3 -m venv`
/// writes it before it installs anything, so a fresh environment is recognized
/// on the first walk that sees it and never races the live watcher for the
/// semantic graph.
///
/// The check is scoped to untracked directories a walk is about to descend
/// into, so it can only decline to admit something new. It never retracts
/// graph-owned truth, which is why the host-blind retraction predicate in
/// [`tracked_paths_retracted_by_ignore`] does not consult it and cannot drift
/// from it: for a tracked path this rule is inert by construction.
pub const PYTHON_VIRTUALENV_MARKER: &str = "pyvenv.cfg";

/// Roots already warned about a missing `.kinignore` in this process.
static WARNED_ROOTS: std::sync::OnceLock<std::sync::Mutex<BTreeSet<PathBuf>>> =
    std::sync::OnceLock::new();

/// Whether this process should emit the missing-`.kinignore` warning for `root`.
///
/// Returns true exactly once per root. A poisoned lock warns rather than
/// swallowing the condition, because an unheard warning is the failure here.
fn warn_once_for_root(root: &Path) -> bool {
    let warned = WARNED_ROOTS.get_or_init(|| std::sync::Mutex::new(BTreeSet::new()));
    match warned.lock() {
        Ok(mut warned) => warned.insert(root.to_path_buf()),
        Err(_) => true,
    }
}

/// Literal, repo-scoped admission rules: [`DEFAULT_IGNORED_NAMES`] plus the
/// contents of `.kinignore`.
///
/// A pattern without `/` matches a component at any depth. A pattern with `/`
/// matches one repository path or its descendants. Glob interpretation is
/// intentionally absent.
///
/// A `!` prefix re-admits a path that another rule excludes, which is the only
/// way to override a built-in default. Re-admission wins regardless of rule
/// order, so `!target` restores an ordinary `target` directory and
/// `!target/keep.rs` restores one path beneath an otherwise-excluded tree.
#[derive(Debug, Clone)]
pub struct RepositoryIgnore {
    names: BTreeSet<Vec<u8>>,
    prefixes: Vec<RepoPath>,
    readmitted_names: BTreeSet<Vec<u8>>,
    readmitted_prefixes: Vec<RepoPath>,
    configured: bool,
}

impl Default for RepositoryIgnore {
    /// The built-in defaults, as though a repository carried no `.kinignore`.
    ///
    /// An empty rule set is [`RepositoryIgnore::admit_everything`]. Defaulting
    /// to no rules is what let derived output reach graph truth unbounded, so
    /// the safe construction is the one callers get implicitly.
    fn default() -> Self {
        let mut rules = Self::admit_everything();
        for name in DEFAULT_IGNORED_NAMES {
            rules.names.insert(name.as_bytes().to_vec());
        }
        rules
    }
}

impl RepositoryIgnore {
    /// Rules that exclude nothing, not even build output.
    ///
    /// Reserved for callers that must observe a complete host tree, such as
    /// import and projection fixtures. Runtime scan paths use
    /// [`RepositoryIgnore::load`].
    pub fn admit_everything() -> Self {
        Self {
            names: BTreeSet::new(),
            prefixes: Vec::new(),
            readmitted_names: BTreeSet::new(),
            readmitted_prefixes: Vec::new(),
            configured: false,
        }
    }

    pub fn load(root: &Path) -> Result<Self, IncompleteRepositoryScan> {
        let path = root.join(".kinignore");
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let rules = Self::default();
                // Latched per root. `load` runs once per watch-loop event batch
                // against a ~100ms poll, so an unlatched warning would repeat
                // several hundred characters per second on every repository in
                // the fleet and bury the warnings that need reading.
                if warn_once_for_root(root) {
                    if let Some(warning) = rules.missing_configuration_warning() {
                        tracing::warn!(
                            repository = %root.display(),
                            defaults = DEFAULT_IGNORED_NAMES.len(),
                            "{warning}"
                        );
                    }
                }
                return Ok(rules);
            }
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
        rules.configured = true;
        for (line_index, raw) in content.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (pattern, readmit) = match line.strip_prefix('!') {
                Some(rest) => (rest.trim(), true),
                None => (line, false),
            };
            let pattern = pattern.trim_end_matches('/');
            let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
            if pattern.is_empty() {
                continue;
            }
            let (names, prefixes) = if readmit {
                (&mut rules.readmitted_names, &mut rules.readmitted_prefixes)
            } else {
                (&mut rules.names, &mut rules.prefixes)
            };
            if pattern.contains('/') {
                let prefix = RepoPath::from_utf8(pattern).map_err(|error| {
                    IncompleteRepositoryScan::io(
                        &path,
                        "parse ignore rules",
                        format!("line {}: {error}", line_index + 1),
                        RepositoryScanDiagnostics::default(),
                    )
                })?;
                prefixes.push(prefix);
            } else {
                names.insert(pattern.as_bytes().to_vec());
            }
        }
        rules.prefixes.sort();
        rules.prefixes.dedup();
        rules.readmitted_prefixes.sort();
        rules.readmitted_prefixes.dedup();
        Ok(rules)
    }

    /// Whether this repository states its own admission rules in `.kinignore`.
    pub const fn is_configured(&self) -> bool {
        self.configured
    }

    /// Operator-facing warning for a repository with no `.kinignore`.
    ///
    /// Returned rather than only logged so callers can surface it on their own
    /// channel and tests can assert its content.
    pub fn missing_configuration_warning(&self) -> Option<String> {
        if self.configured {
            return None;
        }
        Some(format!(
            "no .kinignore: admission is running on {} built-in default excludes \
             ({}), plus any directory carrying a {PYTHON_VIRTUALENV_MARKER}. \
             Derived output outside those names will be ingested as repository \
             truth. Write a .kinignore to state this repository's rules, and use \
             `!name` to re-admit a default.",
            DEFAULT_IGNORED_NAMES.len(),
            DEFAULT_IGNORED_NAMES.join(", ")
        ))
    }

    /// Whether any rule matches at or below byte offset `floor` in `bytes`.
    ///
    /// `floor` is the end of a re-admitted ancestor. Passing `0` tests the whole
    /// path, which is the ordinary unqualified match.
    fn rules_match_below(
        names: &BTreeSet<Vec<u8>>,
        prefixes: &[RepoPath],
        bytes: &[u8],
        floor: usize,
    ) -> bool {
        let mut start = 0;
        for component in bytes.split(|byte| *byte == b'/') {
            if start >= floor && names.contains(component) {
                return true;
            }
            start += component.len() + 1;
        }
        prefixes.iter().any(|prefix| {
            let prefix = prefix.as_bytes();
            prefix.len() > floor
                && (bytes == prefix
                    || bytes
                        .strip_prefix(prefix)
                        .is_some_and(|suffix| suffix.starts_with(b"/")))
        })
    }

    /// End offset of the deepest re-admitted ancestor-or-self of `bytes`.
    fn readmit_floor(&self, bytes: &[u8]) -> Option<usize> {
        let mut floor = None;
        let mut start = 0;
        for component in bytes.split(|byte| *byte == b'/') {
            if self.readmitted_names.contains(component) {
                floor = Some(start + component.len());
            }
            start += component.len() + 1;
        }
        for prefix in &self.readmitted_prefixes {
            let prefix = prefix.as_bytes();
            if bytes == prefix
                || bytes
                    .strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.starts_with(b"/"))
            {
                floor = Some(floor.map_or(prefix.len(), |floor: usize| floor.max(prefix.len())));
            }
        }
        floor
    }

    /// Whether ignore rules exclude `path`.
    ///
    /// A re-admission cancels only the rules matching at or above its own
    /// boundary. Rules that match strictly deeper still apply, so `!target`
    /// restores a `target` tree without dragging `target/node_modules` back in
    /// with it. Without that scoping the escape hatch would reintroduce exactly
    /// the unbounded derived output it exists to let an operator recover from.
    pub fn matches(&self, path: &RepoPath) -> bool {
        let bytes = path.as_bytes();
        let floor = self.readmit_floor(bytes).unwrap_or(0);
        Self::rules_match_below(&self.names, &self.prefixes, bytes, floor)
    }

    /// Whether a `!` rule re-admits `path` itself or an ancestor of it.
    ///
    /// This is how a repository overrides an exclusion that no pattern could
    /// have named, such as the virtual-environment marker: `!venv` in
    /// `.kinignore` re-admits that environment whole. A rule pointing strictly
    /// deeper is not an override of the boundary above it, so it does not
    /// count here.
    pub fn readmits(&self, path: &RepoPath) -> bool {
        self.readmit_floor(path.as_bytes()).is_some()
    }

    /// Whether the walk must descend into an otherwise-excluded `directory`
    /// because a re-admission could name something beneath it.
    ///
    /// A bare-name rule such as `!keep.rs` names no directory, so its depth
    /// cannot be known without looking. Descending is the conservative answer:
    /// it costs directory reads, and the file branch still applies
    /// `ignored && !tracked`, so a re-admission never admits its siblings.
    fn readmits_below(&self, directory: &RepoPath) -> bool {
        if !self.readmitted_names.is_empty() {
            return true;
        }
        let prefix = directory.as_bytes();
        self.readmitted_prefixes.iter().any(|readmitted| {
            readmitted
                .as_bytes()
                .strip_prefix(prefix)
                .is_some_and(|suffix| suffix.starts_with(b"/"))
        })
    }
}

/// Tracked paths that current ignore rules would exclude if they arrived today.
///
/// Ignore rules never hide tracked paths, so a repository that admitted derived
/// output before a rule existed keeps carrying it. This is the evidence a purge
/// reports before it acts and the exact set it removes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IgnoredTrackedPaths {
    paths: Vec<RepoPath>,
    tracked_total: usize,
}

impl IgnoredTrackedPaths {
    /// The tracked paths covered by ignore rules, in repository path order.
    pub fn paths(&self) -> &[RepoPath] {
        &self.paths
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// How many paths the repository tracks in total.
    pub const fn tracked_total(&self) -> usize {
        self.tracked_total
    }

    /// Tracked paths that would remain after a purge.
    pub const fn retained_total(&self) -> usize {
        self.tracked_total.saturating_sub(self.paths.len())
    }
}

/// Name the tracked paths that `ignore` covers.
///
/// This reads graph-owned tracked identity, never the host filesystem: a purge
/// decides what to untrack from repository truth, so an absent or stale working
/// directory cannot change the answer.
pub fn tracked_paths_covered_by_ignore<'a>(
    ignore: &RepositoryIgnore,
    tracked: impl IntoIterator<Item = &'a RepoPath>,
) -> IgnoredTrackedPaths {
    let mut tracked_total = 0;
    let mut paths = Vec::new();
    for path in tracked {
        tracked_total += 1;
        if ignore.matches(path) {
            paths.push(path.clone());
        }
    }
    paths.sort();
    paths.dedup();
    IgnoredTrackedPaths {
        paths,
        tracked_total,
    }
}

/// Name the tracked paths that `ignore` retracts.
///
/// This is the one source every retraction reads, so what a rule excludes at
/// admission and what it removes afterwards are decided by the same compiled
/// rules and can never drift apart. [`RepositoryIgnore::matches`] is the single
/// predicate underneath: the scanner applies it to decide whether an untracked
/// leaf is admitted, and this applies it to decide whether an already-tracked
/// path stays.
///
/// `graph_only` members are withheld. Their identity comes from import truth
/// rather than from a host walk, so nothing could reconstruct them if a rule
/// happened to match their path, and dropping them would also break the
/// scanner's graph-only-is-a-subset-of-tracked precondition.
pub fn tracked_paths_retracted_by_ignore<'a>(
    ignore: &RepositoryIgnore,
    tracked: impl IntoIterator<Item = &'a RepoPath>,
    graph_only: impl IntoIterator<Item = &'a RepoPath>,
) -> IgnoredTrackedPaths {
    let graph_only = graph_only.into_iter().collect::<BTreeSet<_>>();
    let mut covered = tracked_paths_covered_by_ignore(ignore, tracked);
    covered.paths.retain(|path| !graph_only.contains(path));
    covered
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
        // Init's own staging directories. Both are created beside the
        // repository being admitted, which is inside the enclosing repository
        // whenever one is nested under another, so an interrupted init in a
        // sibling checkout would otherwise offer its entire captured object
        // closure to this repository as content on the next whole-tree pass.
        || component.starts_with(b".kin-git-capture-")
        || component.starts_with(b".kin.init-")
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
        None,
        tracked_paths,
        std::iter::empty::<&'a RepoPath>(),
    )
}

/// Scan host-representable leaves while preserving graph-only membership.
///
/// `graph_only_paths` currently carries imported Gitlinks. Their identity is
/// owned by graph/import truth; a host directory is neither evidence for a
/// Gitlink nor permission to expand its checkout into sibling Kin artifacts.
///
/// `policy` is the repository's compiled graph-owned admission policy, and a
/// caller that is about to publish what this walk proposes must pass it. The
/// two rule sets are genuinely different: `ignore` is this repository's
/// `.kinignore` plus the built-in defaults, read from the working copy with
/// literal component matching, while the policy is compiled at the durable
/// authority boundary from every `.gitignore` and `.kinignore` blob in the
/// tree plus the frozen local overlay, with gitwildmatch semantics. Proposing
/// an untracked path the policy excludes is not a survivable disagreement:
/// authority refuses that one artifact and the refusal fails the entire
/// exact-tree admission, so the walk that proposed it admits nothing at all
/// (FIR-2346). Passing `None` keeps the legacy behavior for callers that do not
/// publish, such as coverage reports and purge previews.
///
/// Only untracked paths are judged against it, which is exactly the boundary
/// authority itself applies: an artifact the repository already tracks is
/// admitted regardless of what the policy says today, and retracting it is a
/// separate, announced decision made against graph truth rather than here.
pub fn scan_repository_preserving_graph_only<'a>(
    root: &Path,
    ignore: &RepositoryIgnore,
    policy: Option<&ResolvedAdmissionMatcher>,
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
    // Excluded before the walk starts, so no ignored path can reach the host
    // at all. Leaving them in the tracked set is what let one ignored VM image
    // pull its whole subtree into the walk and read it on every pass. Imported
    // graph-only members stay tracked: their identity is preserved by the walk
    // rather than by a rule, and the graph-only-is-a-subset-of-tracked
    // precondition is theirs to keep.
    let (unverified_ignored_paths, tracked_paths): (BTreeSet<_>, BTreeSet<_>) = tracked_paths
        .into_iter()
        .partition(|path| ignore.matches(path) && !graph_only_paths.contains(path));
    let mut scanner = Scanner {
        root,
        ignore,
        policy,
        tracked_paths,
        graph_only_paths,
        unverified_ignored_paths,
        policy_excluded_sample: Vec::new(),
        entries: BTreeMap::new(),
        diagnostics: RepositoryScanDiagnostics::default(),
    };
    scanner.walk(root, false)?;
    scanner.diagnostics.admitted_entries = scanner.entries.len();
    scanner.diagnostics.graph_only_entries_preserved = scanner.graph_only_paths.len();
    scanner.diagnostics.ignored_tracked_entries_unverified = scanner.unverified_ignored_paths.len();
    Ok(CompleteRepositoryScan {
        entries: scanner.entries,
        graph_only_paths: scanner.graph_only_paths,
        unverified_ignored_paths: scanner.unverified_ignored_paths,
        policy_excluded_sample: scanner.policy_excluded_sample,
        diagnostics: scanner.diagnostics,
        completion: CompleteScanToken { _private: () },
    })
}

/// How many policy-excluded paths one walk names outright. See
/// [`CompleteRepositoryScan::policy_excluded_paths_sample`].
const POLICY_EXCLUDED_SAMPLE_LIMIT: usize = 8;

struct Scanner<'a> {
    root: &'a Path,
    ignore: &'a RepositoryIgnore,
    policy: Option<&'a ResolvedAdmissionMatcher>,
    tracked_paths: BTreeSet<RepoPath>,
    graph_only_paths: BTreeSet<RepoPath>,
    unverified_ignored_paths: BTreeSet<RepoPath>,
    policy_excluded_sample: Vec<RepoPath>,
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

    /// Whether graph truth tracks `path` itself or anything beneath it.
    ///
    /// Answered over the ordered range that starts at `path`, because this runs
    /// once per directory entry and a repository with a large tracked set was
    /// paying a full pass over that set for every entry it inspected. Repository
    /// paths order by their bytes, so every descendant of `path` sorts after it
    /// and before the first path that does not begin with those bytes.
    /// Whether the graph-owned admission policy excludes an untracked `path`.
    ///
    /// Records a bounded sample as it goes, so the pass that skipped a path can
    /// name it once rather than leaving an operator to guess which rule fired.
    /// `true` is only ever returned for a path this walk is about to skip, so
    /// the sample and the count describe the same set.
    fn policy_excludes_untracked(&mut self, path: &RepoPath, is_dir: bool) -> bool {
        let Some(policy) = self.policy else {
            return false;
        };
        if !policy.decide(path, is_dir, false).is_ignored() {
            return false;
        }
        self.diagnostics.policy_excluded_untracked_entries += 1;
        if self.policy_excluded_sample.len() < POLICY_EXCLUDED_SAMPLE_LIMIT {
            self.policy_excluded_sample.push(path.clone());
        }
        true
    }

    /// Whether `directory` is a Python virtual environment this walk declines
    /// to admit.
    ///
    /// The re-admission test comes first so an operator override costs no host
    /// IO, and so the answer for a directory the repository re-admitted is the
    /// same whether or not the marker happens to be there.
    fn excludes_python_virtualenv(&self, repo_path: &RepoPath, host_path: &Path) -> bool {
        !self.ignore.readmits(repo_path) && host_path.join(PYTHON_VIRTUALENV_MARKER).is_file()
    }

    fn is_tracked_or_contains_tracked(&self, path: &RepoPath) -> bool {
        let prefix = path.as_bytes();
        self.tracked_paths
            .range(path.clone()..)
            .take_while(|tracked| tracked.as_bytes().starts_with(prefix))
            .any(|tracked| tracked == path || tracked.as_bytes()[prefix.len()..].starts_with(b"/"))
    }

    /// `within_excluded_environment` marks a descent that only happened because
    /// graph truth tracks something below an excluded Python environment. The
    /// walk reaches those tracked paths and admits nothing else on the way, so
    /// one file committed into an environment before this rule existed cannot
    /// re-open the whole site-packages tree behind it.
    fn walk(
        &mut self,
        directory: &Path,
        within_excluded_environment: bool,
    ) -> Result<(), IncompleteRepositoryScan> {
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
                let holds_tracked = self.is_tracked_or_contains_tracked(&repo_path);
                if ignored && !holds_tracked && !self.ignore.readmits_below(&repo_path) {
                    self.diagnostics.ignored_untracked_entries += 1;
                    continue;
                }
                // A directory the durable policy excludes is skipped whole, and
                // gitwildmatch semantics are why that is exact rather than
                // merely convenient: a rule beneath an excluded ancestor cannot
                // re-admit anything under it, so nothing down there could ever
                // be admitted and descending would only cost the reads. Graph
                // truth still outranks the rules, so a directory holding a
                // tracked path is walked and only its untracked leaves are
                // skipped below.
                if !holds_tracked && self.policy_excludes_untracked(&repo_path, true) {
                    continue;
                }
                // A materialized Python environment, recognized by the marker
                // its interpreter writes rather than by a name anyone chose.
                // Skipped whole for the same reason a policy-excluded directory
                // is: nothing beneath an excluded environment is authored
                // source, so descending would only cost the reads. Re-admitting
                // the environment directory itself (`!venv`) is the override,
                // and it is checked before the host is touched at all.
                let excluded_environment = self.excludes_python_virtualenv(&repo_path, &host_path);
                if (excluded_environment || within_excluded_environment) && !holds_tracked {
                    self.diagnostics.ignored_untracked_entries += 1;
                    continue;
                }
                self.walk(
                    &host_path,
                    within_excluded_environment || excluded_environment,
                )?;
                continue;
            }

            // A leaf inside an excluded environment, reached only because graph
            // truth tracks something down here. Tracked identity is observed as
            // it always is; everything else stays out, so the descent admits
            // exactly what it came for. Checked before `ignored` handling so a
            // tracked path can never fall into the counter for an untracked one.
            if within_excluded_environment
                && !self.tracked_paths.contains(&repo_path)
                && !self.ignore.readmits(&repo_path)
            {
                self.diagnostics.ignored_untracked_entries += 1;
                continue;
            }

            if ignored {
                // An excluded leaf the walk met anyway, either inside an
                // admitted directory or under one a re-admission forced it to
                // descend into. Nothing excluded is opened, so tracking decides
                // which counter this bumps and nothing else: a covered tracked
                // path left the tracked set before the walk began.
                if !self.unverified_ignored_paths.contains(&repo_path) {
                    self.diagnostics.ignored_untracked_entries += 1;
                }
                continue;
            }

            // An untracked leaf the durable policy excludes. Nothing opens it,
            // for the same reason nothing opens an ignored one: proposing it
            // would be refused at the authority boundary, and that refusal is
            // not survivable, it fails the whole tree admission.
            if !self.tracked_paths.contains(&repo_path)
                && self.policy_excludes_untracked(&repo_path, false)
            {
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

    /// Compile one graph-owned policy from rule bytes, as the durable authority
    /// boundary compiles the repository's own.
    fn graph_owned_policy(rules: &str) -> ResolvedAdmissionMatcher {
        ResolvedAdmissionMatcher::compile(
            crate::admission::AdmissionCase::Sensitive,
            vec![crate::admission::ResolvedAdmissionRuleSet::from_bytes(
                crate::admission::AdmissionRuleSource::Shared {
                    source_path: path(".gitignore"),
                },
                0,
                None,
                rules.as_bytes().to_vec(),
            )],
        )
        .unwrap()
    }

    /// The walk skips what the graph-owned policy excludes, and does not read
    /// it on the way.
    ///
    /// Proposing one of these paths is refused at the authority boundary, and
    /// the refusal fails the whole exact-tree admission rather than that one
    /// artifact (FIR-2346). Skipping it is therefore not an optimization. The
    /// byte counter is asserted because an excluded subtree that is walked and
    /// hashed anyway still costs the machine everything the skip exists to
    /// save, which is what a churning agent worktree under an excluded
    /// directory does on every pass.
    #[test]
    fn the_graph_owned_policy_prunes_untracked_paths_before_they_are_read() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join(".claude/worktrees/lane-a/src")).unwrap();
        fs::write(root.join(".claude/scheduled_tasks.lock"), b"held").unwrap();
        fs::write(
            root.join(".claude/worktrees/lane-a/src/dirty.rs"),
            vec![b'x'; 4096],
        )
        .unwrap();
        fs::write(root.join("keep.rs"), b"fn keep() {}").unwrap();
        let ignore = RepositoryIgnore::default();
        let policy = graph_owned_policy(".claude/\n");

        let scan = scan_repository_preserving_graph_only(
            root,
            &ignore,
            Some(&policy),
            std::iter::empty(),
            std::iter::empty(),
        )
        .unwrap();

        assert!(scan.entry(&path("keep.rs")).is_some());
        assert!(scan.entry(&path(".claude/scheduled_tasks.lock")).is_none());
        assert!(scan
            .entry(&path(".claude/worktrees/lane-a/src/dirty.rs"))
            .is_none());
        assert_eq!(scan.diagnostics().policy_excluded_untracked_entries, 1);
        assert_eq!(
            scan.policy_excluded_paths_sample(),
            [path(".claude")],
            "the excluded directory is named once rather than every leaf beneath it"
        );
        assert!(
            scan.diagnostics().content_bytes_read < 4096,
            "the excluded subtree was read: {} bytes",
            scan.diagnostics().content_bytes_read
        );

        // Two-sided. Without the policy the same walk really does reach and
        // read all of it, so the assertions above describe the policy rather
        // than a fixture that was never walkable.
        let everything = scan_repository_preserving_graph_only(
            root,
            &ignore,
            None,
            std::iter::empty(),
            std::iter::empty(),
        )
        .unwrap();
        assert!(everything
            .entry(&path(".claude/worktrees/lane-a/src/dirty.rs"))
            .is_some());
        assert_eq!(
            everything.diagnostics().policy_excluded_untracked_entries,
            0
        );
        assert!(everything.diagnostics().content_bytes_read > 4096);
    }

    /// Graph truth outranks the policy for a path the repository already
    /// tracks, exactly as the authority boundary ranks them.
    ///
    /// Authority admits a tracked artifact whatever the rules say today, so a
    /// walk that dropped it would report it absent and infer a removal from
    /// that. Untracking such a path is a separate announced decision.
    #[test]
    fn a_tracked_path_survives_a_policy_that_would_exclude_it_today() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("vendor/lib")).unwrap();
        fs::write(root.join("vendor/lib/tracked.rs"), b"fn tracked() {}").unwrap();
        fs::write(root.join("vendor/lib/fresh.rs"), b"fn fresh() {}").unwrap();
        let tracked = path("vendor/lib/tracked.rs");
        let ignore = RepositoryIgnore::default();
        let policy = graph_owned_policy("vendor/\n");

        let scan = scan_repository_preserving_graph_only(
            root,
            &ignore,
            Some(&policy),
            [&tracked],
            std::iter::empty(),
        )
        .unwrap();

        assert!(
            scan.entry(&tracked).is_some(),
            "a tracked artifact was dropped by a rule that only governs admission"
        );
        assert!(scan.missing_tracked_paths([&tracked]).is_empty());
        assert!(
            scan.entry(&path("vendor/lib/fresh.rs")).is_none(),
            "an untracked path under the excluded directory was admitted"
        );
    }

    /// Membership stays independent of parser support, hidden names, and
    /// vendoring. Only control metadata and derived output are excluded, and
    /// `build`/`out`/`vendor` stay admitted because those names are ambiguous.
    #[test]
    fn scan_admits_every_non_control_repository_surface() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let admitted: &[(&str, &[u8])] = &[
            ("Dockerfile", b"FROM alpine"),
            ("compose.yaml", b"services: {}"),
            ("Cargo.lock", b"version = 4"),
            ("package-lock.json", b"{}"),
            ("src/main.rs", b"fn main() {}"),
            ("src/tool.py", b"print('hi')"),
            ("notes/brain.brainfuck", b"+++[>+++<-]"),
            ("assets/logo.bin", b"\x00\xff\x10"),
            ("unrelated/receipt.pdf", b"%PDF-not-really"),
            ("vendor/lib/source.c", b"int vendored(void) { return 1; }"),
            ("build/report.txt", b"build output"),
            ("out/data", b"output"),
            (".env.example", b"NAME=value"),
            (".kinignore", b""),
        ];
        let excluded_by_default: &[(&str, &[u8])] = &[
            ("node_modules/pkg/index.js", b"export default 1"),
            ("target/generated.rs", b"pub const GENERATED: bool = true;"),
            ("dist/app.js", b"console.log('dist')"),
            ("__pycache__/state.bin", b"cache"),
            (".next/server/app.js", b"next"),
        ];
        for (relative, content) in admitted.iter().chain(excluded_by_default) {
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
        for (relative, _) in admitted {
            assert!(paths.contains(&path(relative)), "missing {relative}");
        }
        for (relative, _) in excluded_by_default {
            assert!(
                !paths.contains(&path(relative)),
                "derived output admitted: {relative}"
            );
        }
        assert!(paths.contains(&path(".kin-release/downstreams.json")));
        assert!(!paths.iter().any(is_repository_control_path));
        assert_eq!(scan.len(), admitted.len() + 1);
        assert_eq!(scan.diagnostics().admitted_entries, admitted.len() + 1);
    }

    /// Init's own staging directories never become repository content.
    ///
    /// A repository nested under another sees its sibling's init staging as
    /// ordinary untracked directories, and a capture directory an interrupted
    /// init left behind carries the whole object closure of whatever it was
    /// admitting. Admitting that as content would offer another repository's
    /// history to this one as files.
    #[test]
    fn init_staging_directories_are_control_paths() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::write(root.join("kept.rs"), b"fn main() {}").unwrap();
        for staging in [".kin-git-capture-IuJspS", ".kin.init-not-a-uuid"] {
            fs::create_dir_all(root.join(staging).join("objects")).unwrap();
            fs::write(root.join(staging).join("objects/body"), b"closure").unwrap();
        }

        let scan = scan(root);
        let paths = scan.paths().cloned().collect::<BTreeSet<_>>();
        assert!(paths.contains(&path("kept.rs")));
        assert_eq!(scan.len(), 1, "{paths:?}");
        for staging in [".kin-git-capture-IuJspS", ".kin.init-not-a-uuid"] {
            assert!(is_repository_control_path(&path(&format!(
                "{staging}/objects/body"
            ))));
        }
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

    /// Uses names absent from [`DEFAULT_IGNORED_NAMES`] on purpose. Asserting
    /// this against `target` would pass on the built-in defaults alone and
    /// prove nothing about `.kinignore` parsing.
    ///
    /// A rule covers the walk whether or not the path is tracked. Tracking used
    /// to exempt a path from the rules and keep it in the hasher, which is how
    /// one ignored VM image admitted before its rule existed went on costing
    /// 120GB of reads per pass and failing every admission when it churned.
    #[test]
    fn explicit_ignore_withholds_a_covered_path_from_the_walk() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("build/nested")).unwrap();
        fs::create_dir_all(root.join("vendor/pkg")).unwrap();
        fs::write(root.join("build/nested/new.bin"), b"new").unwrap();
        fs::write(root.join("build/retained.bin"), b"retained").unwrap();
        fs::write(root.join("vendor/pkg/index.js"), b"generated").unwrap();
        fs::write(root.join(".env"), b"SECRET=never-admit-untracked").unwrap();
        fs::write(root.join(".kinignore"), b"build/\nvendor/\n.env\n").unwrap();
        let ignore = RepositoryIgnore::load(root).unwrap();
        assert!(ignore.is_configured());

        let initial = scan_repository(root, &ignore, std::iter::empty()).unwrap();
        assert!(initial.entry(&path("build/nested/new.bin")).is_none());
        assert!(initial.entry(&path("build/retained.bin")).is_none());
        assert!(initial.entry(&path("vendor/pkg/index.js")).is_none());
        assert!(initial.entry(&path(".env")).is_none());

        let retained = path("build/retained.bin");
        fs::write(root.join("build/retained.bin"), b"updated tracked bytes").unwrap();
        let tracked = scan_repository(root, &ignore, [&retained]).unwrap();
        assert!(
            tracked.entry(&retained).is_none(),
            "a covered path stays out of the hasher once a rule names it"
        );
        assert_eq!(
            tracked.unverified_ignored_paths().collect::<Vec<_>>(),
            [&retained]
        );
        assert!(
            tracked.missing_tracked_paths([&retained]).is_empty(),
            "declining to observe a path is not evidence that it is gone"
        );
        assert!(tracked.entry(&path("build/nested/new.bin")).is_none());
        assert!(tracked.entry(&path("vendor/pkg/index.js")).is_none());
        assert!(tracked.entry(&path(".env")).is_none());
    }

    #[test]
    fn missing_kinignore_warns_and_still_applies_defaults() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::write(root.join("main.rs"), b"fn main() {}").unwrap();

        let unconfigured = RepositoryIgnore::load(root).unwrap();
        assert!(!unconfigured.is_configured());
        let warning = unconfigured
            .missing_configuration_warning()
            .expect("absent .kinignore must warn");
        assert!(warning.contains(".kinignore"), "{warning}");
        assert!(warning.contains("target"), "{warning}");
        assert!(warning.contains("built-in default excludes"), "{warning}");
        assert!(unconfigured.matches(&path("target/debug/app")));

        // Falsification: the same call against a repository that states its
        // rules must go quiet, so the assertions above cannot pass vacuously.
        fs::write(root.join(".kinignore"), b"# stated\n").unwrap();
        let configured = RepositoryIgnore::load(root).unwrap();
        assert!(configured.is_configured());
        assert_eq!(configured.missing_configuration_warning(), None);
        assert!(configured.matches(&path("target/debug/app")));
    }

    #[test]
    fn default_excludes_reject_untracked_derived_output() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let derived = [
            "target/debug/app.o",
            "node_modules/pkg/index.js",
            "dist/bundle.js",
            "__pycache__/mod.pyc",
            ".venv/bin/python",
            ".pytest_cache/v/lastfailed",
            ".next/server/page.js",
            ".turbo/cache.log",
            ".gradle/state.bin",
            ".terraform/provider",
            ".kin-coord/worktrees/lane/file",
        ];
        for relative in derived {
            let host = root.join(relative);
            fs::create_dir_all(host.parent().unwrap()).unwrap();
            fs::write(host, b"derived").unwrap();
        }
        fs::write(root.join("lib.rs"), b"pub fn kept() {}").unwrap();

        let scan = scan(root);
        for relative in derived {
            assert!(
                scan.entry(&path(relative)).is_none(),
                "derived output admitted: {relative}"
            );
        }
        assert!(scan.entry(&path("lib.rs")).is_some());
        assert_eq!(scan.len(), 1);
        assert!(scan.diagnostics().ignored_untracked_entries > 0);

        // Falsification: the fixture really does contain those trees, so an
        // empty rule set must admit every one of them.
        let everything = scan_repository(
            root,
            &RepositoryIgnore::admit_everything(),
            std::iter::empty(),
        )
        .unwrap();
        for relative in derived {
            assert!(
                everything.entry(&path(relative)).is_some(),
                "fixture never created {relative}"
            );
        }
        assert_eq!(everything.len(), derived.len() + 1);
    }

    /// Materialize the directory `python3 -m venv <name>` produces, down to the
    /// marker file PEP 405 requires and a plausible site-packages leaf.
    fn create_virtualenv(root: &Path, name: &str) {
        let env = root.join(name);
        fs::create_dir_all(env.join("lib/python3.11/site-packages/pytest")).unwrap();
        fs::create_dir_all(env.join("bin")).unwrap();
        fs::write(
            env.join(PYTHON_VIRTUALENV_MARKER),
            b"home = /usr/bin\nversion = 3.11.2\n",
        )
        .unwrap();
        fs::write(env.join("bin/activate"), b"# activate").unwrap();
        fs::write(
            env.join("lib/python3.11/site-packages/pytest/__init__.py"),
            b"__version__ = '9.1.1'",
        )
        .unwrap();
    }

    /// A fresh repository with no user action of any kind must keep a virtual
    /// environment out of the graph, whichever of the three common names its
    /// author used. `.venv` is covered by name; `venv` and `env` are names that
    /// also occur as ordinary source directories, so only the marker can tell
    /// the two apart.
    #[test]
    fn a_freshly_created_virtualenv_is_excluded_without_any_user_action() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        for name in [".venv", "venv", "env"] {
            create_virtualenv(root, name);
        }
        fs::write(root.join("app.py"), b"print('hi')").unwrap();

        // No .kinignore, no .gitignore: exactly what `kin init` leaves behind.
        let admitted = scan(root);
        assert!(admitted.entry(&path("app.py")).is_some());
        for name in [".venv", "venv", "env"] {
            assert!(
                admitted
                    .entry(&path(&format!("{name}/bin/activate")))
                    .is_none(),
                "{name} leaked into the graph"
            );
            assert!(
                admitted
                    .entry(&path(&format!(
                        "{name}/lib/python3.11/site-packages/pytest/__init__.py"
                    )))
                    .is_none(),
                "{name} site-packages leaked into the graph"
            );
        }
        assert_eq!(
            admitted.len(),
            1,
            "only the authored file belongs in the graph: {:?}",
            admitted.paths().collect::<Vec<_>>()
        );

        // Two-sided: the same names WITHOUT the marker are ordinary source and
        // stay admitted, so the assertions above describe the marker rather
        // than a name list that would have deleted real code.
        let sources = tempfile::tempdir().unwrap();
        let sources = sources.path();
        for name in ["venv", "env"] {
            fs::create_dir_all(sources.join(name)).unwrap();
            fs::write(sources.join(name).join("__init__.py"), b"# real source").unwrap();
        }
        let admitted = scan(sources);
        assert!(admitted.entry(&path("venv/__init__.py")).is_some());
        assert!(admitted.entry(&path("env/__init__.py")).is_some());
    }

    /// The escape hatch has to reach an exclusion no pattern named, or a
    /// repository that deliberately tracks a checked-in environment has no way
    /// back. `!venv` in `.kinignore` re-admits the environment whole.
    #[test]
    fn a_readmit_rule_overrides_the_virtualenv_marker() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        create_virtualenv(root, "venv");
        create_virtualenv(root, "tools/env");

        fs::write(root.join(".kinignore"), b"!venv\n").unwrap();
        let ignore = RepositoryIgnore::load(root).unwrap();
        let scan = scan_repository(root, &ignore, std::iter::empty()).unwrap();
        assert!(
            scan.entry(&path("venv/bin/activate")).is_some(),
            "!venv did not re-admit the environment it names"
        );
        assert!(
            scan.entry(&path("tools/env/bin/activate")).is_none(),
            "re-admitting one environment must not re-admit the others"
        );

        // Falsification: drop the rule and the same fixture loses the tree.
        fs::write(root.join(".kinignore"), b"# nothing re-admitted\n").unwrap();
        let none = RepositoryIgnore::load(root).unwrap();
        let scan = scan_repository(root, &none, std::iter::empty()).unwrap();
        assert!(scan.entry(&path("venv/bin/activate")).is_none());
    }

    /// Graph truth outranks the marker exactly as it outranks every other
    /// admission rule: a repository that already tracks a path inside an
    /// environment keeps observing it, so the rule can never turn into a silent
    /// retraction of what the graph already owns.
    #[test]
    fn the_virtualenv_marker_never_retracts_already_tracked_paths() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        create_virtualenv(root, "venv");
        let tracked = path("venv/bin/activate");

        let ignore = RepositoryIgnore::default();
        let scan = scan_repository(root, &ignore, [&tracked]).unwrap();
        assert!(
            scan.entry(&tracked).is_some(),
            "a tracked path was dropped by a rule that only governs admission"
        );
        assert!(scan.missing_tracked_paths([&tracked]).is_empty());
        assert!(
            tracked_paths_retracted_by_ignore(&ignore, [&tracked], std::iter::empty()).is_empty(),
            "the marker must not appear in the retraction predicate"
        );

        // Reaching the tracked path must not re-open the environment around it.
        // One file committed into a venv before this rule existed would
        // otherwise drag all of site-packages back in on every pass.
        assert_eq!(
            scan.paths().collect::<Vec<_>>(),
            [&tracked],
            "the descent admitted more than the tracked path it came for"
        );
    }

    #[test]
    fn readmit_rule_overrides_a_built_in_default() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("target/deep")).unwrap();
        fs::create_dir_all(root.join("dist")).unwrap();
        fs::write(root.join("target/keep.rs"), b"pub fn keep() {}").unwrap();
        fs::write(root.join("target/deep/drop.o"), b"object").unwrap();
        fs::write(root.join("dist/app.js"), b"bundle").unwrap();

        // A whole-name re-admission restores the tree.
        fs::write(root.join(".kinignore"), b"!target\n").unwrap();
        let whole = RepositoryIgnore::load(root).unwrap();
        let scan = scan_repository(root, &whole, std::iter::empty()).unwrap();
        assert!(scan.entry(&path("target/keep.rs")).is_some());
        assert!(scan.entry(&path("target/deep/drop.o")).is_some());
        assert!(scan.entry(&path("dist/app.js")).is_none());

        // A path re-admission descends into an otherwise-pruned directory and
        // restores exactly one member.
        fs::write(root.join(".kinignore"), b"!target/keep.rs\n").unwrap();
        let single = RepositoryIgnore::load(root).unwrap();
        let scan = scan_repository(root, &single, std::iter::empty()).unwrap();
        assert!(scan.entry(&path("target/keep.rs")).is_some());
        assert!(scan.entry(&path("target/deep/drop.o")).is_none());

        // Falsification: drop the re-admission and the same fixture loses it.
        fs::write(root.join(".kinignore"), b"# nothing re-admitted\n").unwrap();
        let none = RepositoryIgnore::load(root).unwrap();
        let scan = scan_repository(root, &none, std::iter::empty()).unwrap();
        assert!(scan.entry(&path("target/keep.rs")).is_none());
    }

    /// A bare-name re-admission has no directory to descend from, so the walker
    /// must descend anyway or the documented escape hatch is a silent no-op.
    #[test]
    fn bare_name_readmission_reaches_inside_a_pruned_directory() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("dist")).unwrap();
        fs::write(root.join("dist/keep.rs"), b"pub fn keep() {}").unwrap();
        fs::write(root.join("dist/bundle.js"), b"derived").unwrap();
        fs::write(root.join(".kinignore"), b"!keep.rs\n").unwrap();

        let ignore = RepositoryIgnore::load(root).unwrap();
        assert!(!ignore.matches(&path("dist/keep.rs")));
        let scan = scan_repository(root, &ignore, std::iter::empty()).unwrap();
        assert!(
            scan.entry(&path("dist/keep.rs")).is_some(),
            "the predicate admitted the path but the walker never reached it"
        );
        // Descending must not admit the siblings it walked past.
        assert!(scan.entry(&path("dist/bundle.js")).is_none());

        // Falsification: without the rule the same fixture keeps the file out.
        fs::write(root.join(".kinignore"), b"# nothing re-admitted\n").unwrap();
        let none = RepositoryIgnore::load(root).unwrap();
        let scan = scan_repository(root, &none, std::iter::empty()).unwrap();
        assert!(scan.entry(&path("dist/keep.rs")).is_none());
    }

    /// Re-admission must cancel only the rule it overrides. If it blanket-won,
    /// rescuing one tree would drag every nested default back in, which is the
    /// volume problem this whole change exists to fix.
    #[test]
    fn readmission_does_not_defeat_defaults_nested_below_it() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::write(root.join(".kinignore"), b"!target\n").unwrap();
        let ignore = RepositoryIgnore::load(root).unwrap();

        assert!(!ignore.matches(&path("target/keep.rs")));
        assert!(!ignore.matches(&path("target/deep/keep.rs")));
        assert!(
            ignore.matches(&path("target/node_modules/pkg/index.js")),
            "a nested default was defeated by an ancestor re-admission"
        );
        assert!(ignore.matches(&path("target/sub/.DS_Store")));
        assert!(ignore.matches(&path("target/a/dist/bundle.js")));

        // A prefix re-admission scopes the same way.
        fs::write(root.join(".kinignore"), b"!target/keep\n").unwrap();
        let prefixed = RepositoryIgnore::load(root).unwrap();
        assert!(!prefixed.matches(&path("target/keep/src/lib.rs")));
        assert!(prefixed.matches(&path("target/keep/node_modules/pkg/index.js")));
        assert!(prefixed.matches(&path("target/other.o")));
    }

    /// The trap: a default exclude alone retires nothing. The walk stops
    /// observing the path, and stopping short of observing it is exactly why it
    /// cannot report the path gone. Retirement stays an announced retraction
    /// the caller performs against graph truth.
    #[test]
    fn default_excludes_never_retire_an_already_tracked_path() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("target/debug")).unwrap();
        fs::write(root.join("target/debug/tracked.o"), b"admitted earlier").unwrap();
        fs::write(root.join("target/debug/fresh.o"), b"arrived later").unwrap();

        let tracked = path("target/debug/tracked.o");
        let ignore = RepositoryIgnore::load(root).unwrap();
        let scan = scan_repository(root, &ignore, [&tracked]).unwrap();

        assert!(
            scan.missing_tracked_paths([&tracked]).is_empty(),
            "a default exclude must not silently delete graph-owned truth"
        );
        assert_eq!(
            scan.unverified_ignored_paths().collect::<Vec<_>>(),
            [&tracked]
        );
        assert!(scan.entry(&tracked).is_none());
        assert!(scan.entry(&path("target/debug/fresh.o")).is_none());
        assert_eq!(scan.diagnostics().content_bytes_read, 0);

        // Falsification: the retraction the caller would perform instead names
        // this exact path, so the walk is declining to observe something a rule
        // really does cover rather than something it merely failed to reach.
        let retracted = tracked_paths_retracted_by_ignore(&ignore, [&tracked], std::iter::empty());
        assert_eq!(retracted.paths(), [tracked]);
    }

    #[test]
    fn tracked_paths_covered_by_ignore_names_the_purge_set() {
        let ignore = RepositoryIgnore::default();
        let tracked = [
            path("src/main.rs"),
            path("target/debug/app.o"),
            path("target/debug/deps/lib.rlib"),
            path("node_modules/pkg/index.js"),
            path("vendor/lib/source.c"),
        ];

        let covered = tracked_paths_covered_by_ignore(&ignore, tracked.iter());
        assert_eq!(
            covered.paths(),
            [
                path("node_modules/pkg/index.js"),
                path("target/debug/app.o"),
                path("target/debug/deps/lib.rlib"),
            ]
        );
        assert_eq!(covered.len(), 3);
        assert_eq!(covered.tracked_total(), 5);
        assert_eq!(covered.retained_total(), 2);
        assert!(!covered.is_empty());

        // Falsification: the same tracked set under empty rules purges nothing.
        let none =
            tracked_paths_covered_by_ignore(&RepositoryIgnore::admit_everything(), tracked.iter());
        assert!(none.is_empty());
        assert_eq!(none.tracked_total(), 5);
        assert_eq!(none.retained_total(), 5);
    }

    /// The retraction set is the covered set less graph-only membership, and it
    /// answers with the same predicate the scanner admits by, so a rule cannot
    /// exclude a path at admission while a retraction disagrees about it.
    #[test]
    fn retraction_matches_admission_and_withholds_graph_only_members() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::write(root.join(".kinignore"), b"investor\n").unwrap();
        let ignore = RepositoryIgnore::load(root).unwrap();

        let gitlink = path("investor/vendored");
        let tracked = [
            path("src/main.rs"),
            path("investor/deck/build_deck.py"),
            gitlink.clone(),
        ];

        let retracted =
            tracked_paths_retracted_by_ignore(&ignore, tracked.iter(), std::iter::once(&gitlink));
        assert_eq!(retracted.paths(), [path("investor/deck/build_deck.py")]);
        assert_eq!(retracted.tracked_total(), 3);
        assert_eq!(retracted.retained_total(), 2);

        // Every retracted path is one the scanner would also refuse to admit.
        for retracted in retracted.paths() {
            assert!(ignore.matches(retracted), "{retracted}");
        }
        // Falsification: without the graph-only exemption the Gitlink is covered
        // too, so the assertion above is testing the exemption and not the rule.
        let covered = tracked_paths_covered_by_ignore(&ignore, tracked.iter());
        assert!(covered.paths().contains(&gitlink));
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
            policy: None,
            tracked_paths: BTreeSet::new(),
            graph_only_paths: BTreeSet::new(),
            unverified_ignored_paths: BTreeSet::new(),
            policy_excluded_sample: Vec::new(),
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
            None,
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
            None,
            [&gitlink],
            [&gitlink],
        )
        .unwrap();
        assert!(
            deinitialized.missing_tracked_paths([&gitlink]).is_empty(),
            "host absence cannot infer removal of graph-owned Gitlink identity"
        );
    }

    /// An ignore rule is a statement about IO, not only about membership. A
    /// tracked path the rules exclude is observed as unverified and never
    /// opened, so no byte of an ignored subtree reaches the hasher.
    #[test]
    fn an_ignored_subtree_costs_no_content_reads_even_when_tracked() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("vm/nested")).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        let rules = b"vm\n";
        let source = b"fn main() {}";
        fs::write(root.join(".kinignore"), rules).unwrap();
        fs::write(root.join("src/main.rs"), source).unwrap();
        fs::write(root.join("vm/disk.img"), vec![0x5a_u8; 128 * 1024]).unwrap();
        fs::write(root.join("vm/nested/state.bin"), vec![0x11_u8; 4 * 1024]).unwrap();

        // Admitted before the rule existed, which is the only way graph truth
        // can hold a path its own rules now exclude.
        let tracked = path("vm/disk.img");
        let ignore = RepositoryIgnore::load(root).unwrap();
        let scan = scan_repository(root, &ignore, [&tracked]).unwrap();

        assert!(scan.entry(&path("src/main.rs")).is_some());
        assert!(scan.entry(&tracked).is_none());
        assert_eq!(
            scan.diagnostics().content_bytes_read,
            (rules.len() + source.len()) as u64,
            "an ignored subtree must cost zero content bytes"
        );
        assert_eq!(scan.diagnostics().ignored_tracked_entries_unverified, 1);
        assert_eq!(
            scan.unverified_ignored_paths().collect::<Vec<_>>(),
            [&tracked]
        );
        assert!(
            scan.missing_tracked_paths([&tracked]).is_empty(),
            "an unobserved ignored path must never authorize inferred removal"
        );

        // Falsification: the same fixture under empty rules reads every one of
        // those bytes, so the accounting above cannot pass vacuously.
        let everything =
            scan_repository(root, &RepositoryIgnore::admit_everything(), [&tracked]).unwrap();
        assert!(everything.entry(&tracked).is_some());
        assert_eq!(
            everything.diagnostics().content_bytes_read,
            (rules.len() + source.len() + 132 * 1024) as u64
        );
        assert_eq!(
            everything.diagnostics().ignored_tracked_entries_unverified,
            0
        );
    }

    /// The live shape: a 120GB VM image inside an ignored subtree rewrote
    /// itself while the walk hashed it, and the churn failed every whole-tree
    /// admission for two days. Nothing in an ignored subtree is read now, so
    /// its churn cannot reach the rest of the tree.
    #[test]
    fn churn_beneath_an_ignored_subtree_admits_the_rest_of_the_tree() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        fs::create_dir_all(root.join("vm")).unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        let rules = b"vm\n";
        let source = b"fn main() {}";
        fs::write(root.join(".kinignore"), rules).unwrap();
        fs::write(root.join("src/main.rs"), source).unwrap();
        fs::write(root.join("vm/disk.img"), vec![0x5a_u8; 256 * 1024]).unwrap();

        let tracked = path("vm/disk.img");
        let stop = Arc::new(AtomicBool::new(false));
        let churn = {
            let root = root.clone();
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut large = false;
                while !stop.load(Ordering::Relaxed) {
                    large = !large;
                    let len = if large { 384 * 1024 } else { 256 * 1024 };
                    let _ = fs::write(root.join("vm/disk.img"), vec![0xa5_u8; len]);
                }
            })
        };

        let expected_bytes = (rules.len() + source.len()) as u64;
        let mut source_hash = None;
        for pass in 0..25 {
            let ignore = RepositoryIgnore::load(&root).unwrap();
            let scan = scan_repository(&root, &ignore, [&tracked])
                .unwrap_or_else(|error| panic!("pass {pass} must admit the tree: {error}"));
            let admitted = scan.entry(&path("src/main.rs")).unwrap();
            assert_eq!(*source_hash.get_or_insert(admitted.content_hash), {
                admitted.content_hash
            });
            assert_eq!(scan.diagnostics().content_bytes_read, expected_bytes);
            assert_eq!(scan.diagnostics().ignored_tracked_entries_unverified, 1);
            assert!(scan.missing_tracked_paths([&tracked]).is_empty());
        }

        stop.store(true, Ordering::Relaxed);
        churn.join().unwrap();

        // Positive control: with the churn stopped and no rules at all, the
        // walk really does reach and read that file, so the passes above were
        // scanning a fixture that could have failed them.
        let everything =
            scan_repository(&root, &RepositoryIgnore::admit_everything(), [&tracked]).unwrap();
        assert!(everything.entry(&tracked).is_some());
        assert!(everything.diagnostics().content_bytes_read > 256 * 1024);
    }

    /// Two-sided: quieting an ignored subtree must not quiet the tree Kin does
    /// admit. Content that changes under an admitted file still fails closed.
    #[test]
    fn churn_in_an_admitted_file_still_fails_the_scan_loudly() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let live = root.join("live.rs");
        fs::write(&live, b"fn live() {}").unwrap();
        let ignore = RepositoryIgnore::default();
        let scanner = Scanner {
            root,
            ignore: &ignore,
            policy: None,
            tracked_paths: BTreeSet::new(),
            graph_only_paths: BTreeSet::new(),
            unverified_ignored_paths: BTreeSet::new(),
            policy_excluded_sample: Vec::new(),
            entries: BTreeMap::new(),
            diagnostics: RepositoryScanDiagnostics::default(),
        };

        let error = scanner
            .hash_regular_file_after_open(&live, || {
                fs::write(&live, b"fn live() { rewritten }").unwrap();
            })
            .expect_err("content churn under an admitted file must fail closed");
        assert_eq!(error.operation, "verify file content");
        assert!(error.reason.contains("file changed during scan"));

        // Falsification: the identical call against an untouched file succeeds,
        // so the failure above is the churn and not the fixture.
        let (_, bytes_read, _) = scanner.hash_regular_file(&live).unwrap();
        assert_eq!(bytes_read, b"fn live() { rewritten }".len() as u64);
    }

    /// An ignored tracked path is unobservable, not absent. Reporting it
    /// missing would let a rule delete graph-owned truth through inference,
    /// which is what retraction exists to do explicitly and announce.
    #[test]
    fn an_unverified_ignored_path_is_never_inferred_as_removed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("vm")).unwrap();
        fs::write(root.join(".kinignore"), b"vm\n").unwrap();
        fs::write(root.join("kept.rs"), b"pub fn kept() {}").unwrap();

        // Tracked, ignored, and no longer materialized. Absence inside a
        // subtree the walk never entered proves nothing about the member.
        let tracked = path("vm/disk.img");
        let ignore = RepositoryIgnore::load(root).unwrap();
        let scan = scan_repository(root, &ignore, [&tracked]).unwrap();
        assert!(scan.missing_tracked_paths([&tracked]).is_empty());
        assert_eq!(scan.diagnostics().ignored_tracked_entries_unverified, 1);

        // Falsification: an admitted tracked path that really is gone is still
        // reported missing, so the exemption is scoped to ignored paths.
        let admitted = path("gone.rs");
        let scan = scan_repository(root, &ignore, [&tracked, &admitted]).unwrap();
        assert_eq!(
            scan.missing_tracked_paths([&admitted]),
            std::slice::from_ref(&admitted)
        );
        assert!(scan.missing_tracked_paths([&tracked]).is_empty());
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
