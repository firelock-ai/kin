// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Complete, source-only admission blocker report for one Git repository.
//!
//! Exact admission proves a whole repository, which takes minutes on a real
//! history. Every refusal it can reach before publication, though, is decided
//! by source state a reader can observe in about a second: registered
//! worktrees, the hook surface Git would really run, checkout filters,
//! repository-local transport configuration, the index against HEAD, and
//! untracked worktree paths.
//!
//! This boundary reads exactly those, reports all of them at once with the
//! path or key that caused each and the one action that clears it, and admits
//! nothing: a clean report only means the expensive proof is worth starting.
//! Admission policy is unchanged, so anything reported here is something the
//! authority proof would have refused anyway, only later and one at a time.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use gix::bstr::ByteSlice;
use kin_model::RepoPath;

use crate::error::{
    GitAdmissionBlocker, GitError, LocalGitHookFact, RegisteredGitWorktreeKind, Result,
};
use crate::lossless::open_repo;
use crate::preflight::{
    checkout_filter_facts, exact_directory_names, frozen_ignore_stack, hook_executability,
    hook_kind, local_ignore_inputs, open_repo_with_user_ignore_config, other_registered_worktrees,
    preflight_error, reject_in_progress_operations, remote_mapping_facts, stable_path,
};

/// Paths of one class printed before the rest are counted rather than listed.
const REPORTED_PATHS: usize = 10;

/// Untracked paths gathered before the walk stops looking for more.
///
/// A worktree carrying an unignored build directory holds hundreds of
/// thousands of them, and every one past the first few hundred changes neither
/// the verdict nor what the reader has to do about it.
const UNTRACKED_SCAN_CAP: usize = 512;

/// Everything one Git source repository would be refused for, in one report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GitAdmissionReport {
    pub blockers: Vec<GitAdmissionBlocker>,
    pub notes: Vec<String>,
}

impl GitAdmissionReport {
    pub fn is_clear(&self) -> bool {
        self.blockers.is_empty()
    }
}

/// Refuse a Git source that cannot be admitted, naming every reason at once.
///
/// The source repository is only read. A clear result is not an admission
/// proof: it establishes that the far more expensive exact proof is worth
/// running, and that proof still decides.
pub fn check_git_admission_blockers(repo_path: &Path) -> Result<()> {
    let report = collect_git_admission_blockers(repo_path)?;
    if report.is_clear() {
        return Ok(());
    }
    Err(GitError::AdmissionBlocked {
        blockers: report.blockers,
        notes: report.notes,
    })
}

/// The report behind [`check_git_admission_blockers`].
pub fn collect_git_admission_blockers(repo_path: &Path) -> Result<GitAdmissionReport> {
    let source = fs::canonicalize(repo_path).map_err(|error| GitError::io(repo_path, error))?;
    let repo = open_repo(&source)?;
    // A shallow source is deliberately not checked here. Capture refuses it a
    // moment later with a message that names the exact command that fixes it,
    // and leaving it there keeps this boundary about local state alone.
    let ambient = open_repo_with_user_ignore_config(&source)?;
    if stable_path(ambient.git_dir()) != stable_path(repo.git_dir())
        || stable_path(ambient.common_dir()) != stable_path(repo.common_dir())
    {
        return Err(preflight_error(
            "resolved user Git configuration opened a different Git repository",
        ));
    }

    let mut report = GitAdmissionReport::default();
    match reject_in_progress_operations(&repo) {
        Ok(()) => {}
        Err(GitError::MigrationPreflight(reason)) => report.blockers.push(GitAdmissionBlocker::new(
            reason,
            "finish or abort the Git operation, then run kin init again",
        )),
        Err(error) => return Err(error),
    }

    for worktree in other_registered_worktrees(&repo, &source)? {
        let kind = match worktree.kind {
            RegisteredGitWorktreeKind::Main => "main",
            RegisteredGitWorktreeKind::Linked => "linked",
        };
        report.blockers.push(GitAdmissionBlocker::new(
            format!(
                "another {kind} Git worktree {} shares this object database",
                worktree.path.display()
            ),
            "remove it with 'git worktree remove', or run kin init from the workspace that keeps it",
        ));
    }

    let hooks = effective_hook_surface(&repo, &ambient)?;
    for hook in &hooks.hooks {
        report.blockers.push(GitAdmissionBlocker::new(
            format!("Git hook {} runs for this repository", hook.path.display()),
            "move it aside; Kin admits repository content, and never imports or runs a hook",
        ));
    }
    report.notes.extend(hooks.notes());

    for filter in checkout_filter_facts(&repo) {
        report.blockers.push(GitAdmissionBlocker::new(
            format!(
                "checkout filter [filter \"{}\"] rewrites worktree content",
                String::from_utf8_lossy(&filter.name)
            ),
            "unset it in this repository's Git config, because Kin admits committed bytes exactly",
        ));
    }

    if let Err(GitError::MigrationPreflight(reason)) = remote_mapping_facts(&repo) {
        report.blockers.push(GitAdmissionBlocker::new(
            reason,
            "unset that key in .git/config, or clone without it",
        ));
    }

    let index = read_index(&repo)?;
    report.blockers.extend(staged_blockers(&repo, &index)?);
    report
        .blockers
        .extend(untracked_blockers(&ambient, &index, &source)?);
    Ok(report)
}

/// The hook directory Git resolves for one repository, and what is in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectiveHookSurface {
    /// Directory Git runs hooks from, after any `core.hooksPath`.
    pub(crate) directory: PathBuf,
    /// The configured override, when one exists.
    pub(crate) configured: Option<ConfiguredHooksPath>,
    /// Entries Git would run, Kin's own legacy links already removed.
    pub(crate) hooks: Vec<LocalGitHookFact>,
    /// Legacy links an older Kin left under the resolved hook directory.
    pub(crate) kin_legacy: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfiguredHooksPath {
    pub(crate) value: PathBuf,
    /// Whether the repository itself set it, rather than the host.
    pub(crate) repository_scoped: bool,
    pub(crate) scope: &'static str,
}

impl EffectiveHookSurface {
    /// Whether the repository's own config redirects its hook surface.
    pub(crate) fn repository_scoped_hooks_path(&self) -> bool {
        self.configured
            .as_ref()
            .is_some_and(|configured| configured.repository_scoped)
    }

    fn notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if let Some(configured) = &self.configured {
            if !configured.repository_scoped {
                notes.push(format!(
                    "{} core.hooksPath is {}, so Git ignores anything under .git/hooks here and \
                     Kin counts neither",
                    configured.scope,
                    configured.value.display()
                ));
            }
        }
        if !self.kin_legacy.is_empty() {
            notes.push(format!(
                "{} hook link(s) an older Kin installed are not counted and are safe to delete: {}",
                self.kin_legacy.len(),
                render_paths(
                    self.kin_legacy
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect()
                )
            ));
        }
        notes
    }
}

/// Resolve the hook surface the way Git does, then read it.
///
/// `.git/hooks` is what Git runs only when nothing overrides it, so an entry
/// sitting there under a `core.hooksPath` override is inert, and counting it
/// refuses a repository over a file that can never execute.
///
/// Which directory is then read depends on who redirected it. A repository that
/// points its own hooks somewhere carries that surface to its next reader, and
/// Kin refuses it. A host-wide `core.hooksPath` is the operator's environment
/// instead, shared by every repository on the machine, so reading it would
/// refuse all of them for something no repository carries. That one is reported
/// as the reason `.git/hooks` went uncounted and blocks nothing.
pub(crate) fn effective_hook_surface(
    repo: &gix::Repository,
    ambient: &gix::Repository,
) -> Result<EffectiveHookSurface> {
    let configured = configured_hooks_path(ambient, repo)?;
    let directory = match &configured {
        Some(configured) => configured.value.clone(),
        None => repo.common_dir().join("hooks"),
    };
    if configured
        .as_ref()
        .is_some_and(|configured| !configured.repository_scoped)
    {
        return Ok(EffectiveHookSurface {
            directory,
            configured,
            hooks: Vec::new(),
            kin_legacy: Vec::new(),
        });
    }
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(EffectiveHookSurface {
                directory,
                configured,
                hooks: Vec::new(),
                kin_legacy: Vec::new(),
            });
        }
        Err(error) => return Err(GitError::io(&directory, error)),
    };
    let entries = entries
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| GitError::io(&directory, error))?;
    let entries = exact_directory_names(&directory, entries)?;

    let mut hooks = Vec::new();
    let mut kin_legacy = Vec::new();
    for (name, entry) in entries {
        if name.ends_with(b".sample") {
            continue;
        }
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| GitError::io(entry.path(), error))?;
        if is_legacy_kin_hook_link(&directory, &path, &metadata)? {
            kin_legacy.push(path);
            continue;
        }
        hooks.push(LocalGitHookFact {
            name,
            path,
            kind: hook_kind(&metadata),
            executable: hook_executability(&metadata)?,
            byte_len: metadata.len(),
        });
    }
    hooks.sort_by(|left, right| left.name.cmp(&right.name));
    kin_legacy.sort();
    Ok(EffectiveHookSurface {
        directory,
        configured,
        hooks,
        kin_legacy,
    })
}

/// Read `core.hooksPath` from the scope Git would honour, if any.
fn configured_hooks_path(
    ambient: &gix::Repository,
    repo: &gix::Repository,
) -> Result<Option<ConfiguredHooksPath>> {
    let snapshot = ambient.config_snapshot();
    let Some(value) = snapshot.trusted_path("core.hooksPath") else {
        return Ok(None);
    };
    let value = value
        .map_err(|error| preflight_error(format!("resolve configured Git hooks path: {error}")))?;
    if value.as_os_str().is_empty() {
        return Ok(None);
    }
    let (repository_scoped, scope) = hooks_path_scope(&snapshot);
    // Git reads a relative hooks path from the top of the working tree, so
    // resolving it against the process working directory would name a
    // different directory than the one that runs.
    let root = repo.workdir().unwrap_or_else(|| repo.common_dir());
    let value = if value.is_absolute() {
        value.into_owned()
    } else {
        root.join(value)
    };
    Ok(Some(ConfiguredHooksPath {
        value,
        repository_scoped,
        scope,
    }))
}

/// Which configuration scope set the `core.hooksPath` Git ends up using.
///
/// Sections are merged in precedence order, so the last one carrying the value
/// is the one that wins.
fn hooks_path_scope(snapshot: &gix::config::Snapshot<'_>) -> (bool, &'static str) {
    let mut winner = None;
    if let Some(sections) = snapshot.plumbing().sections_by_name("core") {
        for section in sections {
            if section.contains_value_name("hooksPath") {
                winner = Some(section.meta().source);
            }
        }
    }
    match winner {
        Some(gix::config::Source::Local) => (true, "this repository's"),
        Some(gix::config::Source::Worktree) => (true, "this worktree's"),
        Some(gix::config::Source::User) => (false, "your global"),
        Some(gix::config::Source::System) => (false, "the system"),
        Some(gix::config::Source::Env) => (false, "the environment's"),
        Some(gix::config::Source::Cli) => (false, "the command line's"),
        _ => (false, "an ambient"),
    }
}

/// Whether one hook entry is a link an older Kin installed.
///
/// Those links point at `<somewhere>/.kin/hooks/<name>`, which is Kin's own
/// installed hook directory rather than anything the repository carries.
/// Counting them makes Kin refuse a repository over its own leftovers, and it
/// is exactly the repositories Kin has already touched that hit it.
fn is_legacy_kin_hook_link(
    hooks_dir: &Path,
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<bool> {
    if !metadata.file_type().is_symlink() {
        return Ok(false);
    }
    let target = fs::read_link(path).map_err(|error| GitError::io(path, error))?;
    let target = if target.is_absolute() {
        target
    } else {
        hooks_dir.join(target)
    };
    let Some(parent) = target.parent() else {
        return Ok(false);
    };
    Ok(parent.file_name().is_some_and(|name| name == "hooks")
        && parent
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == ".kin"))
}

fn read_index(repo: &gix::Repository) -> Result<gix::index::File> {
    gix::index::File::at_or_default(
        repo.index_path(),
        repo.object_hash(),
        false,
        gix::index::decode::Options::default(),
    )
    .map_err(|error| preflight_error(format!("open Git index: {error}")))
}

/// Index entries that do not equal the committed tree they came from.
fn staged_blockers(
    repo: &gix::Repository,
    index: &gix::index::File,
) -> Result<Vec<GitAdmissionBlocker>> {
    let committed = committed_tree_entries(repo)?;
    let mut staged = Vec::new();
    let mut removed = committed.clone();
    for entry in index.entries() {
        let path = entry.path(index).to_vec();
        match removed.remove(&path) {
            Some(committed) if committed == (entry.mode.bits(), entry.id) => {}
            Some(_) | None => staged.push(display_path(&path)),
        }
    }
    let mut blockers = Vec::new();
    if !staged.is_empty() {
        blockers.push(GitAdmissionBlocker::new(
            format!(
                "index contains {} staged or otherwise uncommitted path(s): {}",
                staged.len(),
                render_paths(staged)
            ),
            "commit them or run 'git restore --staged' on each, because Kin admits committed \
             history exactly",
        ));
    }
    let mut deleted = removed
        .into_keys()
        .map(|path| display_path(&path))
        .collect::<Vec<_>>();
    if !deleted.is_empty() {
        deleted.sort();
        blockers.push(GitAdmissionBlocker::new(
            format!(
                "index no longer carries {} committed path(s): {}",
                deleted.len(),
                render_paths(deleted)
            ),
            "commit the removal or run 'git restore --staged' on each",
        ));
    }
    Ok(blockers)
}

/// Every blob, symlink, and gitlink the current HEAD commit records.
///
/// An unborn HEAD commits nothing, so every index entry there is staged.
fn committed_tree_entries(
    repo: &gix::Repository,
) -> Result<BTreeMap<Vec<u8>, (u32, gix::ObjectId)>> {
    let Ok(head) = repo.head_commit() else {
        return Ok(BTreeMap::new());
    };
    let tree = head
        .tree()
        .map_err(|error| preflight_error(format!("read committed Git tree: {error}")))?;
    let mut entries = BTreeMap::new();
    collect_tree_entries(repo, &tree, &[], &mut entries)?;
    Ok(entries)
}

fn collect_tree_entries(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
    prefix: &[u8],
    entries: &mut BTreeMap<Vec<u8>, (u32, gix::ObjectId)>,
) -> Result<()> {
    for entry in tree.iter() {
        let entry =
            entry.map_err(|error| preflight_error(format!("read committed Git tree: {error}")))?;
        let mut path = prefix.to_vec();
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(entry.filename().as_bytes());
        let mode = entry.mode();
        let oid = entry.oid().to_owned();
        if mode.is_tree() {
            let subtree = repo
                .find_object(oid)
                .map_err(|error| preflight_error(format!("read committed Git tree: {error}")))?
                .into_tree();
            collect_tree_entries(repo, &subtree, &path, entries)?;
            continue;
        }
        entries.insert(path, (u32::from(mode.value()), oid));
    }
    Ok(())
}

/// Worktree paths that are neither tracked nor ignored.
fn untracked_blockers(
    ambient: &gix::Repository,
    index: &gix::index::File,
    workdir: &Path,
) -> Result<Vec<GitAdmissionBlocker>> {
    let inputs = local_ignore_inputs(ambient)?;
    let (mut excludes, _) = frozen_ignore_stack(ambient, index, &inputs)?;
    let tracked = index
        .entries()
        .iter()
        .map(|entry| entry.path(index).to_vec())
        .collect::<std::collections::BTreeSet<_>>();
    let mut scan = UntrackedScan {
        tracked,
        found: Vec::new(),
        capped: false,
    };
    scan_untracked(workdir, &[], true, &mut excludes, &mut scan)?;
    if scan.found.is_empty() {
        return Ok(Vec::new());
    }
    let counted = if scan.capped {
        format!("at least {}", scan.found.len())
    } else {
        scan.found.len().to_string()
    };
    Ok(vec![GitAdmissionBlocker::new(
        format!(
            "worktree contains {counted} untracked non-ignored path(s): {}",
            render_paths(scan.found.iter().map(RepoPath::to_string).collect())
        ),
        "commit them, delete them, or add them to .gitignore",
    )])
}

struct UntrackedScan {
    tracked: std::collections::BTreeSet<Vec<u8>>,
    found: Vec<RepoPath>,
    capped: bool,
}

/// Walk the worktree the way the authority proof does, collecting instead of
/// refusing at the first entry.
///
/// The ignore decision itself is the same call over the same frozen inputs, so
/// a path listed here is a path the proof would have refused.
fn scan_untracked(
    absolute: &Path,
    relative: &[u8],
    root: bool,
    excludes: &mut gix::AttributeStack<'_>,
    scan: &mut UntrackedScan,
) -> Result<()> {
    let entries = fs::read_dir(absolute)
        .map_err(|error| GitError::io(absolute, error))?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| GitError::io(absolute, error))?;
    let entries = exact_directory_names(absolute, entries)?;

    for (name, directory_entry) in entries {
        if scan.capped {
            return Ok(());
        }
        if root && name == b".git" {
            continue;
        }
        let path_bytes = if relative.is_empty() {
            name
        } else {
            let mut joined = Vec::with_capacity(relative.len() + 1 + name.len());
            joined.extend_from_slice(relative);
            joined.push(b'/');
            joined.extend_from_slice(&name);
            joined
        };
        if scan.tracked.contains(&path_bytes) {
            continue;
        }
        let absolute_path = directory_entry.path();
        let metadata = fs::symlink_metadata(&absolute_path)
            .map_err(|error| GitError::io(&absolute_path, error))?;
        let mode = if metadata.is_dir() {
            Some(gix::index::entry::Mode::DIR)
        } else if metadata.file_type().is_symlink() {
            Some(gix::index::entry::Mode::SYMLINK)
        } else {
            Some(gix::index::entry::Mode::FILE)
        };
        let ignored = excludes
            .at_entry(path_bytes.as_bstr(), mode)
            .map_err(|error| {
                preflight_error(format!(
                    "evaluate ignore rules for {}: {error}",
                    display_path(&path_bytes)
                ))
            })?
            .is_excluded();
        if ignored {
            continue;
        }
        if metadata.is_dir() {
            scan_untracked(&absolute_path, &path_bytes, false, excludes, scan)?;
            continue;
        }
        let path = RepoPath::from_bytes(path_bytes)
            .map_err(|error| preflight_error(format!("invalid worktree path: {error}")))?;
        scan.found.push(path);
        if scan.found.len() >= UNTRACKED_SCAN_CAP {
            scan.capped = true;
            return Ok(());
        }
    }
    Ok(())
}

/// Print the first few of a list and count the rest.
fn render_paths(mut paths: Vec<String>) -> String {
    let total = paths.len();
    paths.truncate(REPORTED_PATHS);
    let listed = paths.join(", ");
    if total > REPORTED_PATHS {
        return format!("{listed}, and {} more", total - REPORTED_PATHS);
    }
    listed
}

fn display_path(path: &[u8]) -> String {
    String::from_utf8_lossy(path).into_owned()
}


#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;
    use crate::test_support::fixture_git;

    struct Fixture {
        temp: TempDir,
        repo: PathBuf,
    }

    impl Fixture {
        /// One committed repository with nothing else going on.
        fn clean() -> Self {
            let temp = tempfile::tempdir().expect("tempdir");
            let repo = temp.path().join("source");
            fs::create_dir(&repo).expect("source directory");
            git(&repo, &["init", "--initial-branch=main"]);
            git(&repo, &["config", "user.name", "Kin Test"]);
            git(&repo, &["config", "user.email", "kin@example.invalid"]);
            git(&repo, &["config", "commit.gpgSign", "false"]);
            fs::write(repo.join("README.md"), b"seed\n").expect("readme");
            git(&repo, &["add", "README.md"]);
            git(&repo, &["commit", "-m", "seed", "--no-gpg-sign"]);
            Self { temp, repo }
        }

        /// Bind the hook surface to a directory this case owns.
        ///
        /// Hook resolution reads merged Git configuration, so a developer host
        /// carrying a global `core.hooksPath` redirects a fixture too. Every
        /// case here that decides about hooks pins the surface, or it proves
        /// one thing on a plain host and nothing at all on that one.
        fn pin_hook_surface(&self, directory: &Path) {
            fs::create_dir_all(directory).expect("hook directory");
            git(
                &self.repo,
                &[
                    "config",
                    "core.hooksPath",
                    directory.to_str().expect("utf8 test path"),
                ],
            );
        }

        fn report(&self) -> GitAdmissionReport {
            collect_git_admission_blockers(&self.repo).expect("collect admission blockers")
        }

        fn refusal(&self) -> String {
            check_git_admission_blockers(&self.repo)
                .expect_err("blocked admission")
                .to_string()
        }
    }

    fn git(repo: &Path, args: &[&str]) {
        let output = fixture_git()
            .current_dir(repo)
            .args(args)
            .output()
            .expect("run fixture git");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn write_executable(path: &Path, body: &[u8]) {
        fs::write(path, body).expect("write executable");
        let mut permissions = fs::metadata(path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("chmod");
    }

    #[test]
    fn a_repository_with_nothing_wrong_clears() {
        let fixture = Fixture::clean();
        let report = fixture.report();
        assert!(report.is_clear(), "unexpected blockers: {report:?}");
        check_git_admission_blockers(&fixture.repo).expect("clean repository clears");
    }

    #[test]
    fn every_blocker_class_is_reported_in_one_refusal() {
        let fixture = Fixture::clean();
        let hooks = fixture.temp.path().join("hooks");
        fixture.pin_hook_surface(&hooks);
        write_executable(&hooks.join("pre-commit"), b"#!/bin/sh\nexit 0\n");
        git(
            &fixture.repo,
            &["config", "filter.demo.clean", "external-clean"],
        );
        git(&fixture.repo, &["config", "remote.origin.tagOpt", "--tags"]);
        fs::write(fixture.repo.join("init.log"), b"log\n").expect("untracked");
        fs::write(fixture.repo.join("staged.txt"), b"staged\n").expect("staged");
        git(&fixture.repo, &["add", "staged.txt"]);

        let refusal = fixture.refusal();
        for expected in [
            "pre-commit",
            "filter \"demo\"",
            "remote.origin.tagOpt",
            "init.log",
            "staged.txt",
        ] {
            assert!(
                refusal.contains(expected),
                "expected {expected:?} in refusal:\n{refusal}"
            );
        }
        let report = fixture.report();
        assert!(
            report.blockers.len() >= 5,
            "one refusal must carry every class: {report:?}"
        );
        for blocker in &report.blockers {
            assert!(
                !blocker.remedy.is_empty(),
                "every blocker names its way out: {blocker:?}"
            );
        }
    }

    #[test]
    fn a_git_hooks_entry_under_a_hooks_path_override_is_inert_and_uncounted() {
        let fixture = Fixture::clean();
        let redirected = fixture.temp.path().join("redirected-hooks");
        fixture.pin_hook_surface(&redirected);
        write_executable(
            &fixture.repo.join(".git/hooks/pre-commit"),
            b"#!/bin/sh\nexit 1\n",
        );

        let report = fixture.report();
        assert!(
            report.is_clear(),
            "an overridden .git/hooks entry can never run: {report:?}"
        );
    }

    #[test]
    fn a_hook_in_the_overriding_directory_still_blocks() {
        let fixture = Fixture::clean();
        let redirected = fixture.temp.path().join("redirected-hooks");
        fixture.pin_hook_surface(&redirected);
        let hook = redirected.join("pre-push");
        write_executable(&hook, b"#!/bin/sh\nexit 0\n");

        let refusal = fixture.refusal();
        assert!(
            refusal.contains(&hook.display().to_string()),
            "the refusal names the hook that runs:\n{refusal}"
        );
    }

    #[test]
    fn a_legacy_kin_hook_link_is_uncounted_and_named_as_removable() {
        let fixture = Fixture::clean();
        let hooks = fixture.temp.path().join("hooks");
        fixture.pin_hook_surface(&hooks);
        let installed = fixture.temp.path().join(".kin/hooks");
        fs::create_dir_all(&installed).expect("installed kin hooks");
        write_executable(&installed.join("pre-commit"), b"#!/bin/sh\nexit 0\n");
        symlink(installed.join("pre-commit"), hooks.join("pre-commit")).expect("legacy link");

        let report = fixture.report();
        assert!(
            report.is_clear(),
            "Kin's own leftovers must not block Kin: {report:?}"
        );
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("older Kin") && note.contains("pre-commit")),
            "the leftover is named as safe to delete: {report:?}"
        );
    }

    #[test]
    fn a_host_scoped_hooks_path_explains_itself_without_blocking() {
        let surface = EffectiveHookSurface {
            directory: PathBuf::from("/home/dev/.config/git/hooks"),
            configured: Some(ConfiguredHooksPath {
                value: PathBuf::from("/home/dev/.config/git/hooks"),
                repository_scoped: false,
                scope: "your global",
            }),
            hooks: Vec::new(),
            kin_legacy: Vec::new(),
        };
        assert!(!surface.repository_scoped_hooks_path());
        let notes = surface.notes();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("your global core.hooksPath"), "{notes:?}");
        assert!(notes[0].contains(".git/hooks"), "{notes:?}");
    }

    #[test]
    fn untracked_paths_are_listed_and_the_rest_counted() {
        let fixture = Fixture::clean();
        for index in 0..12 {
            fs::write(
                fixture.repo.join(format!("untracked-{index:02}.log")),
                b"noise\n",
            )
            .expect("untracked file");
        }

        let refusal = fixture.refusal();
        assert!(refusal.contains("12 untracked non-ignored path(s)"), "{refusal}");
        assert!(refusal.contains("untracked-00.log"), "{refusal}");
        assert!(refusal.contains("untracked-09.log"), "{refusal}");
        assert!(refusal.contains("and 2 more"), "{refusal}");
        assert!(
            refusal.contains(".gitignore"),
            "the remedy names the way out:\n{refusal}"
        );
    }

    #[test]
    fn an_ignored_path_is_not_a_blocker() {
        let fixture = Fixture::clean();
        fs::write(fixture.repo.join(".gitignore"), b"build/\n").expect("gitignore");
        git(&fixture.repo, &["add", ".gitignore"]);
        git(&fixture.repo, &["commit", "-m", "ignore", "--no-gpg-sign"]);
        fs::create_dir(fixture.repo.join("build")).expect("build directory");
        fs::write(fixture.repo.join("build/output.bin"), b"artifact\n").expect("artifact");

        let report = fixture.report();
        assert!(report.is_clear(), "ignored content is admissible: {report:?}");
    }

    #[test]
    fn a_staged_deletion_is_reported_as_an_uncommitted_path() {
        let fixture = Fixture::clean();
        git(&fixture.repo, &["rm", "--cached", "README.md"]);

        let refusal = fixture.refusal();
        assert!(refusal.contains("README.md"), "{refusal}");
        assert!(
            refusal.contains("committed path(s)"),
            "a staged removal is named as one:\n{refusal}"
        );
    }

    #[test]
    fn a_second_registered_worktree_is_reported_with_its_path() {
        let fixture = Fixture::clean();
        let other = fixture.temp.path().join("other-worktree");
        git(
            &fixture.repo,
            &[
                "worktree",
                "add",
                "-b",
                "other",
                other.to_str().expect("utf8 test path"),
            ],
        );

        let refusal = fixture.refusal();
        assert!(refusal.contains("other-worktree"), "{refusal}");
        assert!(refusal.contains("git worktree remove"), "{refusal}");
    }

    #[test]
    fn a_blocked_repository_is_refused_without_a_snapshot_or_a_plan() {
        let fixture = Fixture::clean();
        fs::write(fixture.repo.join("init.log"), b"log\n").expect("untracked");
        // The whole argument list is one path. Nothing here can consult a
        // lossless snapshot, an import plan, or a blob store, because it is
        // never given one, which is what makes the check cheap enough to run
        // before any of them exist.
        let refusal = check_git_admission_blockers(&fixture.repo).expect_err("blocked admission");
        assert!(refusal.to_string().contains("init.log"), "{refusal}");
    }
}
