// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Complete, source-only admission blocker report for one Git repository.
//!
//! Exact admission proves a whole repository, which takes minutes on a real
//! history. Every refusal it can reach before publication, though, is decided
//! by source state a reader can observe in about a second: registered
//! worktrees, the hook surface Git would really run, checkout filters,
//! repository-local transport configuration, and a sparse checkout.
//!
//! This boundary reads exactly those, reports all of them at once with the
//! path or key that caused each and the one action that clears it, and admits
//! nothing: a clean report only means the expensive proof is worth starting.
//! Admission policy is unchanged, so anything reported here is something the
//! authority proof would have refused anyway, only later and one at a time.
//!
//! A worktree that has been worked in is not among them. Uncommitted state is
//! not repository authority and never enters it, so the proof observes the
//! delta and reports it rather than refusing; see [`crate::preflight`].
//!
//! Nor is a sibling worktree, by itself. What the capture needs from one is
//! that it anchors no commit the shared reference store leaves unnamed, and
//! that nothing is running against the object database. Both are decided per
//! worktree by [`crate::preflight::classify_other_worktrees`], and the ones
//! that pass are disclosed as a note rather than refused.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{
    GitAdmissionBlocker, GitError, LocalGitHookFact, RegisteredGitWorktreeKind, Result,
};
use crate::lossless::open_repo;
use crate::preflight::{
    checkout_filter_facts, classify_other_worktrees, exact_directory_names, hook_executability,
    hook_kind, open_repo_with_user_ignore_config, other_registered_worktrees, preflight_error,
    reject_in_progress_operations, scan_remote_mapping, stable_path,
};

/// Paths of one class printed before the rest are counted rather than listed.
const REPORTED_PATHS: usize = 10;

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
        Err(GitError::MigrationPreflight(reason)) => {
            report.blockers.push(GitAdmissionBlocker::new(
                reason,
                "finish or abort the Git operation, then run kin init again",
            ))
        }
        Err(error) => return Err(error),
    }

    let (tolerated, untolerable) =
        classify_other_worktrees(&repo, other_registered_worktrees(&repo, &source)?)?;
    for entry in untolerable {
        let kind = match entry.worktree.kind {
            RegisteredGitWorktreeKind::Main => "main",
            RegisteredGitWorktreeKind::Linked => "linked",
        };
        report.blockers.push(GitAdmissionBlocker::new(
            format!(
                "another {kind} Git worktree {} {}",
                entry.worktree.path.display(),
                entry.reason
            ),
            entry.remedy,
        ));
    }
    if !tolerated.is_empty() {
        report.notes.push(format!(
            "{} other registered Git worktree(s) share this object database and are not admitted \
             as Kin workspaces: {}. Each is idle on a branch this capture carries, so their \
             commits are admitted; any uncommitted work in them is neither admitted nor reported.",
            tolerated.len(),
            render_paths(
                tolerated
                    .iter()
                    .map(|worktree| worktree.path.display().to_string())
                    .collect()
            )
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

    // Every offending key, not the first. A repository outside the safe subset
    // usually holds several, and one name per run is what turns a config edit
    // into a sequence of them.
    for reason in scan_remote_mapping(&repo)?.refusals {
        report.blockers.push(GitAdmissionBlocker::new(
            reason,
            "unset that key in .git/config, or clone without it",
        ));
    }

    if let Some(sparse) = sparse_checkout_blocker(&repo)? {
        report.blockers.push(sparse);
    }
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
    /// Entries under the resolved hook directory whose names Git never runs.
    pub(crate) not_hooks: Vec<PathBuf>,
}

/// The hook names Git runs, from githooks(5).
///
/// Git looks a hook up by exactly these names under the hook directory, and
/// any other entry there is inert however it is named or moded. gitoxide's
/// init template writes `docs.url` beside the samples, and `kin eject` builds
/// its replacement Git with gitoxide, so a count blind to names refused every
/// repository Kin had just ejected and called a 34-byte URL a hook that runs
/// (FIR-2664).
const GIT_HOOK_NAMES: &[&[u8]] = &[
    b"applypatch-msg",
    b"pre-applypatch",
    b"post-applypatch",
    b"pre-commit",
    b"pre-merge-commit",
    b"prepare-commit-msg",
    b"commit-msg",
    b"post-commit",
    b"pre-rebase",
    b"post-checkout",
    b"post-merge",
    b"pre-push",
    b"pre-receive",
    b"update",
    b"proc-receive",
    b"post-receive",
    b"post-update",
    b"reference-transaction",
    b"push-to-checkout",
    b"pre-auto-gc",
    b"post-rewrite",
    b"sendemail-validate",
    b"fsmonitor-watchman",
    b"p4-changelist",
    b"p4-prepare-changelist",
    b"p4-post-changelist",
    b"p4-pre-submit",
    b"post-index-change",
];

/// Whether Git would ever look for a hook under this name.
fn is_git_hook_name(name: &[u8]) -> bool {
    GIT_HOOK_NAMES.contains(&name)
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
            let read = if configured.repository_scoped {
                "that directory is what Kin read"
            } else {
                "Kin did not count what is in it, because a hooks path the host sets applies to \
                 every repository on this machine rather than to this one"
            };
            notes.push(format!(
                "{} core.hooksPath is {}, so Git runs hooks from there and ignores anything under \
                 .git/hooks; {read}",
                configured.scope,
                configured.value.display()
            ));
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
        if !self.not_hooks.is_empty() {
            notes.push(format!(
                "{} file(s) under {} carry no name Git runs as a hook and were not counted: {}",
                self.not_hooks.len(),
                self.directory.display(),
                render_paths(
                    self.not_hooks
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect()
                )
            ));
        }
        notes
    }
}

/// Resolve the hook surface the way Git does, then read what the repository
/// owns.
///
/// `.git/hooks` is what Git runs only when nothing overrides it, so an entry
/// sitting there under a `core.hooksPath` override is inert, and counting it
/// refuses a repository over a file that can never execute. The configured
/// directory is what Git would run instead.
///
/// Whether that directory is read depends on who named it, and the reason is
/// worth stating because it is the one place this boundary decides rather than
/// reports. A repository that redirects its own hooks carries that surface to
/// whoever clones it, and Kin refuses it. A `core.hooksPath` the host sets
/// applies to every repository on the machine, including ones Kin already
/// manages, so refusing on it would mean Kin can never be adopted on that
/// machine at all. That one is reported with its path and its scope, and left
/// alone. Nothing about it is hidden; the refusal says which directory Git runs
/// and that Kin did not count it.
pub(crate) fn effective_hook_surface(
    repo: &gix::Repository,
    ambient: &gix::Repository,
) -> Result<EffectiveHookSurface> {
    let configured = configured_hooks_path(ambient, repo)?;
    let directory = match &configured {
        Some(configured) => configured.value.clone(),
        None => repo.common_dir().join("hooks"),
    };
    if !surface_is_repository_owned(configured.as_ref()) {
        return Ok(EffectiveHookSurface {
            directory,
            configured,
            hooks: Vec::new(),
            kin_legacy: Vec::new(),
            not_hooks: Vec::new(),
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
                not_hooks: Vec::new(),
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
    let mut not_hooks = Vec::new();
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
        if !is_git_hook_name(&name) {
            not_hooks.push(path);
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
    not_hooks.sort();
    Ok(EffectiveHookSurface {
        directory,
        configured,
        hooks,
        kin_legacy,
        not_hooks,
    })
}

/// Whether the resolved hook directory is the repository's own surface.
///
/// The default `.git/hooks` and a repository-scoped override both are. A host
/// scope is not, and is reported rather than counted.
fn surface_is_repository_owned(configured: Option<&ConfiguredHooksPath>) -> bool {
    configured.is_none_or(|configured| configured.repository_scoped)
}

/// Read `core.hooksPath` from the scope Git would honour, if any.
fn configured_hooks_path(
    ambient: &gix::Repository,
    repo: &gix::Repository,
) -> Result<Option<ConfiguredHooksPath>> {
    let snapshot = ambient.config_snapshot();
    // An empty value is how a repository cancels a host-wide override, and it
    // reaches interpolation as a missing path rather than an empty one, so it
    // has to be recognised before asking for the resolved form.
    if snapshot
        .string("core.hooksPath")
        .is_none_or(|value| value.is_empty())
    {
        return Ok(None);
    }
    let Some(value) = snapshot.trusted_path("core.hooksPath") else {
        return Ok(None);
    };
    let value = value
        .map_err(|error| preflight_error(format!("resolve configured Git hooks path: {error}")))?;
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
fn is_legacy_kin_hook_link(hooks_dir: &Path, path: &Path, metadata: &fs::Metadata) -> Result<bool> {
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
    if target.file_name() != path.file_name() {
        return Ok(false);
    }
    Ok(parent.file_name().is_some_and(|name| name == "hooks")
        && parent
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == ".kin"))
}

fn sparse_checkout_blocker(repo: &gix::Repository) -> Result<Option<GitAdmissionBlocker>> {
    let configured = repo.config_snapshot().boolean("core.sparseCheckout") == Some(true)
        || repo.git_dir().join("info/sparse-checkout").exists();
    if !configured && !read_index(repo)?.is_sparse() {
        return Ok(None);
    }
    Ok(Some(GitAdmissionBlocker::new(
        "sparse checkout configuration is ambiguous for exact migration",
        "run 'git sparse-checkout disable' so the worktree carries the whole committed tree",
    )))
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
            let fixture = Self { temp, repo };
            fixture.pin_ambient_configuration();
            fs::write(fixture.repo.join("README.md"), b"seed\n").expect("readme");
            git(&fixture.repo, &["add", "README.md"]);
            git(&fixture.repo, &["commit", "-m", "seed", "--no-gpg-sign"]);
            fixture
        }

        /// Take the developer's own Git configuration out of the answer.
        ///
        /// Hook and ignore resolution both read merged configuration, and this
        /// process is not the isolated Git child the fixture launches. A host
        /// carrying a global `core.hooksPath` or `core.excludesFile` would
        /// otherwise redirect or silence a case, which is how a suite passes on
        /// one machine while proving nothing on another. Repository scope
        /// outranks the host, so pinning both here settles it.
        fn pin_ambient_configuration(&self) {
            self.pin_hook_surface(&self.temp.path().join("empty-hooks"));
            let excludes = self.temp.path().join("global-ignore");
            fs::write(&excludes, b"").expect("empty global excludes");
            git(
                &self.repo,
                &[
                    "config",
                    "core.excludesFile",
                    excludes.to_str().expect("utf8 test path"),
                ],
            );
        }

        /// Bind the hook surface to a directory this case owns.
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

    fn surface_for(fixture: &Fixture) -> EffectiveHookSurface {
        let source = fs::canonicalize(&fixture.repo).expect("canonical source");
        let repo = open_repo(&source).expect("open repository");
        let ambient = open_repo_with_user_ignore_config(&source).expect("open ambient repository");
        effective_hook_surface(&repo, &ambient).expect("resolve hook surface")
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
        git(&fixture.repo, &["config", "core.sshCommand", "ssh -v"]);

        let refusal = fixture.refusal();
        for expected in [
            "pre-commit",
            "filter \"demo\"",
            "remote.origin.tagOpt",
            "core.sshCommand",
        ] {
            assert!(
                refusal.contains(expected),
                "expected {expected:?} in refusal:\n{refusal}"
            );
        }
        let report = fixture.report();
        assert!(
            report.blockers.len() >= 4,
            "one refusal must carry every class: {report:?}"
        );
        for blocker in &report.blockers {
            assert!(
                !blocker.remedy.is_empty(),
                "every blocker names its way out: {blocker:?}"
            );
        }
    }

    /// Every offending transport key at once, not the first one found.
    ///
    /// Clearing them one refusal per attempt is the whole cost this reports
    /// away, and it only shows up on a repository carrying more than one, which
    /// an ordinary editor-configured checkout does.
    #[test]
    fn every_unsupported_transport_key_is_named_in_one_refusal() {
        let fixture = Fixture::clean();
        git(&fixture.repo, &["config", "remote.origin.tagOpt", "--tags"]);
        git(
            &fixture.repo,
            &["config", "branch.main.pushRemoteRef", "refs/heads/main"],
        );
        git(&fixture.repo, &["config", "core.askPass", "/bin/true"]);

        let refusal = fixture.refusal();
        for expected in [
            "remote.origin.tagOpt",
            "branch.main.pushRemoteRef",
            "core.askPass",
        ] {
            assert!(
                refusal.contains(expected),
                "expected {expected:?} in refusal:\n{refusal}"
            );
        }
    }

    /// The configuration an ordinary editor-configured checkout carries admits.
    ///
    /// Each of these was refused before it was classified, and every developer
    /// using VS Code or `git config push.autoSetupRemote true` had at least one
    /// of them. None can change which refs move or what bytes they carry.
    #[test]
    fn classified_admissible_developer_configuration_clears() {
        let fixture = Fixture::clean();
        git(
            &fixture.repo,
            &["config", "branch.main.vscode-merge-base", "origin/main"],
        );
        git(&fixture.repo, &["config", "branch.main.rebase", "true"]);
        git(
            &fixture.repo,
            &["config", "branch.main.description", "the trunk"],
        );
        git(&fixture.repo, &["config", "push.autoSetupRemote", "true"]);
        git(
            &fixture.repo,
            &["config", "lfs.repositoryFormatVersion", "0"],
        );
        git(
            &fixture.repo,
            &[
                "config",
                "lfs.https://example.invalid/r.git/info/lfs.access",
                "basic",
            ],
        );

        let report = fixture.report();
        assert!(
            report.is_clear(),
            "classified-admissible configuration must not block: {report:?}"
        );
    }

    /// A branch section carrying an admissible key still yields its facts.
    ///
    /// A refusal anywhere in a section makes the scan discard that section, so
    /// classifying the editor key is also what lets the branch's real tracking
    /// configuration be read at all.
    #[test]
    fn a_branch_section_with_an_editor_key_still_maps_its_tracking() {
        let fixture = Fixture::clean();
        git(
            &fixture.repo,
            &[
                "config",
                "remote.origin.url",
                "https://example.invalid/r.git",
            ],
        );
        git(&fixture.repo, &["config", "branch.main.remote", "origin"]);
        git(
            &fixture.repo,
            &["config", "branch.main.merge", "refs/heads/main"],
        );
        git(
            &fixture.repo,
            &["config", "branch.main.vscode-merge-base", "origin/main"],
        );

        let source = fs::canonicalize(&fixture.repo).expect("canonical source");
        let repo = open_repo(&source).expect("open repository");
        let scan = scan_remote_mapping(&repo).expect("scan transport configuration");
        assert!(scan.refusals.is_empty(), "{:?}", scan.refusals);
        assert_eq!(scan.facts.branch_tracking.len(), 1);
        assert_eq!(
            scan.facts.branch_tracking[0].remote.as_deref(),
            Some(&b"origin"[..])
        );
        assert_eq!(
            scan.facts.branch_tracking[0].merge_refs,
            vec![b"refs/heads/main".to_vec()]
        );
    }

    /// `push.autoSetupRemote` is modelled, not merely tolerated.
    #[test]
    fn push_auto_setup_remote_is_admitted_as_a_fact() {
        let fixture = Fixture::clean();
        git(&fixture.repo, &["config", "push.autoSetupRemote", "true"]);

        let source = fs::canonicalize(&fixture.repo).expect("canonical source");
        let repo = open_repo(&source).expect("open repository");
        let scan = scan_remote_mapping(&repo).expect("scan transport configuration");
        assert!(scan.refusals.is_empty(), "{:?}", scan.refusals);
        assert_eq!(
            scan.facts.push_auto_setup_remote.as_deref(),
            Some(&b"true"[..])
        );
    }

    /// The `[lfs]` narrowing does not admit a repository LFS actually rewrites.
    ///
    /// The filter is the surface that changes bytes, and it keeps refusing at
    /// any configuration scope, which is what makes admitting the section safe.
    #[test]
    fn an_lfs_repository_still_blocks_on_its_filter() {
        let fixture = Fixture::clean();
        git(
            &fixture.repo,
            &["config", "lfs.repositoryFormatVersion", "0"],
        );
        git(
            &fixture.repo,
            &["config", "filter.lfs.smudge", "git-lfs smudge -- %f"],
        );

        let report = fixture.report();
        assert_eq!(
            report.blockers.len(),
            1,
            "the filter is the only refusal an LFS repository earns: {report:?}"
        );
        assert!(
            report.blockers[0].subject.contains("filter \"lfs\""),
            "{report:?}"
        );
    }

    /// An `[lfs]` key naming an endpoint Kin cannot restore keeps refusing.
    #[test]
    fn an_lfs_endpoint_key_still_refuses() {
        let fixture = Fixture::clean();
        git(
            &fixture.repo,
            &[
                "config",
                "lfs.url",
                "https://example.invalid/r.git/info/lfs",
            ],
        );

        let refusal = fixture.refusal();
        assert!(refusal.contains("lfs.url"), "{refusal}");
    }

    /// An unclassified key under an `[lfs "<endpoint>"]` subsection refuses,
    /// and the refusal does not print the endpoint.
    ///
    /// An LFS subsection name is a URL, which is the same shape that can carry
    /// `user:password@`, so naming the key is the whole disclosure.
    #[test]
    fn an_unclassified_lfs_subsection_key_refuses_without_printing_the_endpoint() {
        let fixture = Fixture::clean();
        git(
            &fixture.repo,
            &[
                "config",
                "lfs.https://token:secret@example.invalid/r.git/info/lfs.locksverify",
                "true",
            ],
        );

        let refusal = fixture.refusal();
        assert!(refusal.contains("lfs.locksverify"), "{refusal}");
        assert!(
            !refusal.contains("secret") && !refusal.contains("example.invalid"),
            "an endpoint subsection must never reach a refusal:\n{refusal}"
        );
    }

    /// Two offending keys inside one section are both named.
    #[test]
    fn a_section_carrying_two_unsupported_keys_names_both() {
        let fixture = Fixture::clean();
        git(&fixture.repo, &["config", "remote.origin.tagOpt", "--tags"]);
        git(&fixture.repo, &["config", "remote.origin.prune", "true"]);

        let refusal = fixture.refusal();
        assert!(refusal.contains("remote.origin.tagOpt"), "{refusal}");
        assert!(refusal.contains("remote.origin.prune"), "{refusal}");
    }

    /// A worked-in repository is admissible.
    ///
    /// Untracked, staged, and staged-removed paths are all worktree state
    /// rather than repository authority, so none of them is a blocker. The
    /// disclosure of what they are lives in the migration proof, which reads
    /// content this boundary deliberately never opens.
    #[test]
    fn a_worked_in_worktree_is_not_a_blocker() {
        let fixture = Fixture::clean();
        fs::write(fixture.repo.join("init.log"), b"log\n").expect("untracked");
        fs::write(fixture.repo.join("staged.txt"), b"staged\n").expect("staged");
        git(&fixture.repo, &["add", "staged.txt"]);
        git(&fixture.repo, &["rm", "--cached", "README.md"]);

        let report = fixture.report();
        assert!(
            report.is_clear(),
            "uncommitted state is not an admission blocker: {report:?}"
        );
        check_git_admission_blockers(&fixture.repo).expect("a worked-in repository clears");
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
    fn a_hooks_path_says_which_scope_redirected_it() {
        let surface = EffectiveHookSurface {
            directory: PathBuf::from("/home/dev/.config/git/hooks"),
            configured: Some(ConfiguredHooksPath {
                value: PathBuf::from("/home/dev/.config/git/hooks"),
                repository_scoped: false,
                scope: "your global",
            }),
            hooks: Vec::new(),
            kin_legacy: Vec::new(),
            not_hooks: Vec::new(),
        };
        assert!(!surface.repository_scoped_hooks_path());
        let notes = surface.notes();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("your global core.hooksPath"), "{notes:?}");
        assert!(notes[0].contains(".git/hooks"), "{notes:?}");
        assert!(
            notes[0].contains("did not count"),
            "a surface Kin left alone says so: {notes:?}"
        );
    }

    /// Which hook surfaces the repository owns, and which it does not.
    ///
    /// The host-scoped arm has no hermetic end-to-end case, because a test
    /// cannot give this process a global Git configuration without racing every
    /// other test in it. Pinning the decision itself is what is available.
    #[test]
    fn only_the_repositorys_own_hook_surface_is_counted() {
        assert!(surface_is_repository_owned(None));
        for (repository_scoped, expected) in [(true, true), (false, false)] {
            let configured = ConfiguredHooksPath {
                value: PathBuf::from("/somewhere/hooks"),
                repository_scoped,
                scope: "scope",
            };
            assert_eq!(
                surface_is_repository_owned(Some(&configured)),
                expected,
                "repository_scoped={repository_scoped}"
            );
        }
    }

    /// A hook the repository itself redirected Git to is counted.
    #[test]
    fn a_repository_scoped_hooks_path_blocks_on_what_it_holds() {
        let fixture = Fixture::clean();
        let hooks = fixture.temp.path().join("empty-hooks");
        let hook = hooks.join("pre-commit");
        write_executable(&hook, b"#!/bin/sh\nexit 0\n");
        let surface = surface_for(&fixture);

        assert_eq!(surface.hooks.len(), 1);
        assert_eq!(surface.hooks[0].path, hook);
    }

    /// With nothing overriding it, `.git/hooks` is the surface.
    ///
    /// An empty `core.hooksPath` is how a repository says "no override" over a
    /// host that sets one, so this reaches the default branch on any machine.
    #[test]
    fn the_default_surface_is_read_when_no_hooks_path_overrides_it() {
        let fixture = Fixture::clean();
        git(&fixture.repo, &["config", "core.hooksPath", ""]);
        let hook = fixture.repo.join(".git/hooks/pre-commit");
        write_executable(&hook, b"#!/bin/sh\nexit 0\n");

        let surface = surface_for(&fixture);
        assert!(surface.configured.is_none(), "{surface:?}");
        assert_eq!(surface.hooks.len(), 1, "{surface:?}");
        assert_eq!(surface.hooks[0].name, b"pre-commit");
        let refusal = fixture.refusal();
        assert!(refusal.contains("pre-commit"), "{refusal}");
    }

    /// The sample hooks `git init` writes are not hooks.
    #[test]
    fn the_sample_hooks_git_init_writes_are_not_blockers() {
        let fixture = Fixture::clean();
        git(&fixture.repo, &["config", "core.hooksPath", ""]);
        assert!(
            fixture.repo.join(".git/hooks/pre-commit.sample").exists(),
            "the fixture must carry the samples this case is about"
        );

        let report = fixture.report();
        assert!(report.is_clear(), "{report:?}");
    }

    /// `kin eject` builds its replacement Git with gitoxide, whose init
    /// template writes `hooks/docs.url` beside the samples: a 34-byte URL, not
    /// executable, and not a name Git ever runs. Counting it refused `kin init`
    /// on every repository Kin had just ejected, and the refusal called it a
    /// hook that runs (FIR-2664).
    #[test]
    fn a_docs_url_beside_the_samples_is_not_a_hook_and_is_named_as_uncounted() {
        let fixture = Fixture::clean();
        git(&fixture.repo, &["config", "core.hooksPath", ""]);
        fs::write(
            fixture.repo.join(".git/hooks/docs.url"),
            b"https://git-scm.com/docs/githooks\n",
        )
        .expect("docs.url");

        let report = fixture.report();
        assert!(report.is_clear(), "{report:?}");
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("docs.url") && note.contains("not counted")),
            "the uncounted entry is named rather than hidden: {report:?}"
        );
        let surface = surface_for(&fixture);
        assert!(surface.hooks.is_empty(), "{surface:?}");
        assert_eq!(surface.not_hooks.len(), 1, "{surface:?}");
        assert!(surface.not_hooks[0].ends_with("docs.url"), "{surface:?}");
    }

    /// The name is the rule, not the mode: an executable Git would never look
    /// for is still not a hook, and a hook-named file still blocks.
    #[test]
    fn only_names_git_runs_count_as_hooks() {
        let fixture = Fixture::clean();
        git(&fixture.repo, &["config", "core.hooksPath", ""]);
        write_executable(
            &fixture.repo.join(".git/hooks/README"),
            b"#!/bin/sh\nexit 0\n",
        );
        let report = fixture.report();
        assert!(report.is_clear(), "{report:?}");

        let hook = fixture.repo.join(".git/hooks/pre-commit");
        write_executable(&hook, b"#!/bin/sh\nexit 0\n");
        // The refusal prints the canonical path, which on macOS differs from
        // the fixture's `/var` spelling.
        let hook = fs::canonicalize(&hook).expect("canonical hook path");
        let refusal = fixture.refusal();
        assert!(
            refusal.contains(&format!("{} runs for this repository", hook.display())),
            "the hook Git runs is named as one: {refusal}"
        );
        assert!(
            !refusal.contains("README runs for this repository"),
            "the executable Git never looks for is not called a hook: {refusal}"
        );
        assert!(
            refusal.contains("README") && refusal.contains("not counted"),
            "and it is named as uncounted rather than hidden: {refusal}"
        );
    }

    /// Only a link that keeps its own name under `.kin/hooks` is Kin's.
    #[test]
    fn a_link_that_merely_lands_in_a_kin_hooks_directory_still_blocks() {
        let fixture = Fixture::clean();
        let hooks = fixture.temp.path().join("empty-hooks");
        let installed = fixture.temp.path().join(".kin/hooks");
        fs::create_dir_all(&installed).expect("installed kin hooks");
        write_executable(&installed.join("something-else"), b"#!/bin/sh\nexit 0\n");
        symlink(installed.join("something-else"), hooks.join("pre-commit")).expect("link");

        let surface = surface_for(&fixture);
        assert_eq!(surface.hooks.len(), 1, "{surface:?}");
        assert!(surface.kin_legacy.is_empty(), "{surface:?}");
    }

    #[test]
    fn a_sparse_checkout_keeps_its_own_refusal() {
        let fixture = Fixture::clean();
        git(&fixture.repo, &["config", "core.sparseCheckout", "true"]);

        let refusal = fixture.refusal();
        assert!(refusal.contains("sparse checkout"), "{refusal}");
        assert!(refusal.contains("sparse-checkout disable"), "{refusal}");
        assert!(
            !refusal.contains("staged or otherwise uncommitted"),
            "a sparse index must not be reported path by path:\n{refusal}"
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
        assert!(
            report.is_clear(),
            "ignored content is admissible: {report:?}"
        );
    }

    /// An idle sibling on a shared branch admits, and says it is there.
    ///
    /// This is what `git worktree add -b` leaves behind, which is the shape
    /// every worktree user has and the one this fleet's own lane checkouts
    /// create. Refusing it made kin init unavailable to all of them.
    #[test]
    fn an_idle_linked_worktree_is_admitted_and_disclosed() {
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

        let report = fixture.report();
        assert!(
            report.is_clear(),
            "an idle sibling worktree is admissible: {report:?}"
        );
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("other-worktree") && note.contains("not admitted")),
            "the sibling is disclosed rather than hidden: {report:?}"
        );
    }

    /// A sibling at a detached HEAD is reported with its path and the reason.
    #[test]
    fn a_detached_linked_worktree_is_reported_with_its_path() {
        let fixture = Fixture::clean();
        let other = fixture.temp.path().join("detached-worktree");
        git(
            &fixture.repo,
            &[
                "worktree",
                "add",
                "--detach",
                other.to_str().expect("utf8 test path"),
            ],
        );

        let refusal = fixture.refusal();
        assert!(refusal.contains("detached-worktree"), "{refusal}");
        assert!(refusal.contains("detached HEAD"), "{refusal}");
        assert!(refusal.contains("git worktree remove"), "{refusal}");
    }

    /// A sibling mid-rebase is reported, and nothing else can see it.
    ///
    /// Its `rebase-merge` directory is under `.git/worktrees/<id>`, which the
    /// source's own in-progress scan never reaches, so narrowing the worktree
    /// rule without this check would have admitted a repository being rewritten
    /// underneath the proof.
    #[test]
    fn a_linked_worktree_mid_operation_is_reported() {
        let fixture = Fixture::clean();
        let other = fixture.temp.path().join("busy-worktree");
        git(
            &fixture.repo,
            &[
                "worktree",
                "add",
                "-b",
                "busy",
                other.to_str().expect("utf8 test path"),
            ],
        );
        let admin = fixture.repo.join(".git/worktrees/busy-worktree");
        fs::create_dir(admin.join("rebase-merge")).expect("in-progress rebase state");

        let refusal = fixture.refusal();
        assert!(refusal.contains("busy-worktree"), "{refusal}");
        assert!(refusal.contains("rebase-merge"), "{refusal}");
    }

    /// A sibling holding its own refs is reported, naming the ref.
    #[test]
    fn a_linked_worktree_holding_private_refs_is_reported() {
        let fixture = Fixture::clean();
        let other = fixture.temp.path().join("bisect-worktree");
        git(
            &fixture.repo,
            &[
                "worktree",
                "add",
                "-b",
                "bisecting",
                other.to_str().expect("utf8 test path"),
            ],
        );
        let private = fixture
            .repo
            .join(".git/worktrees/bisect-worktree/refs/bisect");
        fs::create_dir_all(&private).expect("private ref directory");
        fs::write(private.join("bad"), b"0\n").expect("private ref");

        let refusal = fixture.refusal();
        assert!(refusal.contains("bisect-worktree"), "{refusal}");
        assert!(refusal.contains("bad"), "{refusal}");
    }

    #[test]
    fn a_blocked_repository_is_refused_without_a_snapshot_or_a_plan() {
        let fixture = Fixture::clean();
        let hooks = fixture.temp.path().join("hooks");
        fixture.pin_hook_surface(&hooks);
        write_executable(&hooks.join("pre-commit"), b"#!/bin/sh\nexit 0\n");
        // The whole argument list is one path. Nothing here can consult a
        // lossless snapshot, an import plan, or a blob store, because it is
        // never given one, which is what makes the check cheap enough to run
        // before any of them exist.
        let refusal = check_git_admission_blockers(&fixture.repo).expect_err("blocked admission");
        assert!(refusal.to_string().contains("pre-commit"), "{refusal}");
    }
}
