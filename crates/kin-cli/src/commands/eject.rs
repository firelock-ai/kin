// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Leave Kin through one exact repository-v6 to Git projection.
//!
//! Eject never restores an initialization snapshot and never treats working
//! files or an ambient `.git/` directory as repository authority. It captures
//! one repository-v6 generation, proves the graph-owned workspace projection
//! against repository source CAS, builds and verifies a complete replacement
//! Git repository off to the side, stops graph projection, reopens the same
//! authority roots, proves the workspace again, and only then detaches `.kin/`.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufRead as _, Read as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use kin_model::{ResolvedTree, TreeEntry};

use super::git::{
    capture_export_snapshot, capture_export_snapshot_from_state, AuthorityExportSnapshot,
    RepositorySource,
};
use super::repository_authority::ActiveRepositoryAuthority;

const EJECT_GIT_METADATA_TIMEOUT: Duration = Duration::from_secs(60);
const EJECT_GIT_FSCK_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const EJECT_GIT_CAPTURE_LIMIT: u64 = 8 * 1024 * 1024;

/// Verify graph truth, install its exact Git projection, and detach Kin.
pub async fn run(yes: bool) -> Result<()> {
    ensure_eject_platform()?;
    let cwd = std::env::current_dir()?;
    let layout = crate::commands::require_repository_layout_at(&cwd)?;
    ensure_real_directory(layout.root(), "Kin metadata")?;
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)?;
    refuse_live_vfs(&layout)?;

    let authority = ActiveRepositoryAuthority::open(&binding)?;
    let captured = capture_export_snapshot(&authority)?;
    let proof = WorkspaceProjectionProof::build(&authority, &captured.workspace.tree)?;
    {
        let initial_projection_freeze =
            kin_core::ExactProjectionFreeze::acquire_existing(layout.working_dir())
                .context("freeze the existing working projection before eject preparation")?;
        proof.verify(&initial_projection_freeze, &captured.workspace.tree)?;
    }

    let staged_git = StagedGitRepository::build(&layout, &authority, &captured)?;

    if !yes
        && !confirm_eject(
            &captured,
            staged_git.imported_commits,
            staged_git.native_commits,
        )?
    {
        println!("Aborted.");
        return Ok(());
    }

    // The daemon is the only long-lived writer allowed to observe this
    // workspace. Stop it before the final root comparison and namespace swap.
    crate::commands::daemon::stop(false, false)
        .await
        .context("stop repository daemon before eject")?;
    drop(authority);

    // Lock order is projection then repository authority everywhere that needs
    // both. The projection guard is existing-only and cannot recreate a
    // detached control namespace.
    let final_projection_freeze =
        kin_core::ExactProjectionFreeze::acquire_existing(layout.working_dir())
            .context("freeze the existing working projection for eject handoff")?;
    let reopened = ActiveRepositoryAuthority::open(&binding)
        .context("reopen repository-v6 authority after daemon shutdown")?;
    let authority_freeze = reopened
        .manager()
        .freeze_current_authority(&captured.roots)
        .context("freeze the expected repository-v6 authority generation for eject handoff")?;
    let final_capture = capture_export_snapshot_from_state(
        &reopened.repository_id,
        &reopened.workspace_id,
        authority_freeze.authority(),
    )?;
    require_unchanged_authority(&captured, &final_capture)?;
    let final_projection_verification =
        proof.verify(&final_projection_freeze, &final_capture.workspace.tree)?;
    let config_proof = GitCoexistenceConfigProof::load(&layout.config_path())?;
    staged_git.install_coexistence_config(&config_proof)?;
    config_proof.revalidate(&layout.config_path())?;

    let staged_git_capability = kin_core::ExactProjectionGitStage::open_existing(
        staged_git.git_dir(),
        staged_git.export_proof(),
        &final_capture.workspace.tree,
    )
    .context("retain and re-verify the fully prepared replacement Git directory")?;
    let (archive, archive_target) = create_eject_archive(&layout)?;
    config_proof.revalidate(&layout.config_path())?;
    // This consumes the projection freeze and owns every namespace mutation:
    // previous `.git` -> retained archive, exact staged `.git` -> retained
    // working root, and `.kin` -> retained archive. On any reported failure it
    // rolls those moves back through the same retained capabilities.
    let eject_outcome = final_projection_freeze
        .replace_git_and_detach_verified_to_from_blobs(
            &final_projection_verification,
            &final_capture.workspace.tree,
            &proof.blobs,
            staged_git_capability,
            &archive_target,
            OsStr::new("kin"),
            OsStr::new("previous-git"),
        )
        .context("replace Git and detach Kin through the frozen namespace transaction")?;
    // Keep the authority writer lock alive until the exact projection guard
    // has revalidated, installed Git, and moved the whole `.kin` namespace.
    drop(authority_freeze);
    drop(reopened);
    println!(
        "Kin ejected at authority generation {}. The working directory is now an ordinary \
         Git repository.",
        captured.roots.generation
    );
    println!("Recoverable eject archive: {}", archive.display());
    if eject_outcome.had_previous_git {
        println!(
            "The archive contains `kin/` and `previous-git/`; keep it until the ordinary Git \
             repository has been independently backed up."
        );
    } else {
        println!(
            "The archive contains `kin/`; keep it until the ordinary Git repository has been \
             independently backed up."
        );
    }
    Ok(())
}

fn ensure_eject_platform() -> Result<()> {
    #[cfg(unix)]
    {
        Ok(())
    }
    #[cfg(not(unix))]
    {
        bail!(
            "capability-anchored exact eject is currently supported only on Unix; no repository \
             namespace was changed"
        )
    }
}

fn require_unchanged_authority(
    before: &AuthorityExportSnapshot,
    after: &AuthorityExportSnapshot,
) -> Result<()> {
    if before.roots != after.roots
        || before.workspace != after.workspace
        || before.plan.repository_id != after.plan.repository_id
    {
        bail!(
            "repository-v6 authority changed while eject was preparing (generation {} -> {}); \
             working files and Kin metadata remain attached",
            before.roots.generation,
            after.roots.generation
        );
    }
    Ok(())
}

struct WorkspaceProjectionProof {
    _directory: tempfile::TempDir,
    blobs: kin_blobs::BlobStore,
}

impl WorkspaceProjectionProof {
    fn build(authority: &ActiveRepositoryAuthority, tree: &ResolvedTree) -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("kin-eject-source-proof.")
            .tempdir()
            .context("create bounded eject source proof store")?;
        let blobs = kin_blobs::BlobStore::new(directory.path().to_path_buf())
            .context("open bounded eject source proof store")?;
        for artifact in tree.artifacts_by_path() {
            let digest = match artifact.entry {
                TreeEntry::Blob { hash, .. } => hash,
                TreeEntry::Symlink { target_blob } => target_blob,
                TreeEntry::Gitlink { .. } => {
                    // Gitlinks are exact graph-owned commit pointers rather
                    // than repository-owned source bodies. The staged Git
                    // export binds their target OID, while the frozen
                    // workspace proof accepts only an absent path or the same
                    // retained real directory.
                    continue;
                }
            };
            let body = authority.load_source_blob(digest).with_context(|| {
                format!(
                    "load repository source body {digest} for graph-owned path {}",
                    artifact.path
                )
            })?;
            let written = blobs.write(&body).with_context(|| {
                format!(
                    "stage source proof body for graph-owned path {}",
                    artifact.path
                )
            })?;
            if written.as_bytes() != digest.as_bytes() {
                bail!(
                    "repository source body for {} did not reproduce its authority identity {}",
                    artifact.path,
                    digest
                );
            }
        }
        Ok(Self {
            _directory: directory,
            blobs,
        })
    }

    fn verify(
        &self,
        freeze: &kin_core::ExactProjectionFreeze,
        tree: &ResolvedTree,
    ) -> Result<kin_core::ExactProjectionVerification> {
        freeze
            .verify_resolved_tree_from_blobs(tree, &self.blobs)
            .map_err(|error| {
                anyhow::anyhow!(
                    "working files are not an exact projection of repository-v6 workspace truth: \
                     {error}. Commit or reconcile the workspace and retry; Kin metadata was not \
                     removed"
                )
            })
    }
}

struct StagedGitRepository {
    _directory: tempfile::TempDir,
    git_dir: PathBuf,
    export_proof: kin_git::RepositoryGitExportProof,
    imported_commits: usize,
    native_commits: usize,
}

impl StagedGitRepository {
    fn build(
        layout: &kin_core::KinLayout,
        authority: &ActiveRepositoryAuthority,
        captured: &AuthorityExportSnapshot,
    ) -> Result<Self> {
        let repository_root = layout.working_dir();
        let parent = repository_root
            .parent()
            .ok_or_else(|| anyhow::anyhow!("repository root has no parent"))?;
        let directory = tempfile::Builder::new()
            .prefix(".kin-eject-git-stage.")
            .tempdir_in(parent)
            .context("create same-filesystem Git eject stage")?;
        let worktree = directory.path().join("worktree");
        fs::create_dir(&worktree)
            .with_context(|| format!("create staged worktree {}", worktree.display()))?;
        let git_dir = worktree.join(".git");
        let mut source = RepositorySource::new(authority);
        let result = kin_git::export_repository_to_git(&captured.plan, &mut source, &git_dir)
            .context("build exact Git eject projection")?;

        run_git(
            &worktree,
            Some(&git_dir),
            &["config", "--local", "core.bare", "false"],
        )
        .context("mark staged Git projection as an ordinary working repository")?;
        run_git(
            &worktree,
            Some(&git_dir),
            &["config", "--local", "core.logAllRefUpdates", "true"],
        )
        .context("enable ordinary Git reflogs in staged projection")?;
        let head = run_git_output(
            &worktree,
            Some(&git_dir),
            &["rev-parse", "--verify", "HEAD^{commit}"],
        )?;
        if head.status.success() {
            run_git(
                &worktree,
                Some(&git_dir),
                &["reset", "--mixed", "--quiet", "HEAD"],
            )
            .context("build ordinary Git index from graph-projected HEAD")?;
            run_git(
                &worktree,
                Some(&git_dir),
                &["diff-index", "--cached", "--quiet", "HEAD", "--"],
            )
            .context("verify staged ordinary Git index against graph-projected HEAD")?;
        }
        // A genuinely unborn Git repository canonically has no index. Creating
        // one with `read-tree --empty` would require adding an unreachable
        // empty-tree object that is absent from exact repository authority.
        run_git(&worktree, Some(&git_dir), &["fsck", "--strict"])
            .context("verify staged ordinary Git object closure")?;
        // Do not ask Git's file-first status heuristic to re-authorize the
        // workspace here. The retained Kin projection proof verifies every
        // host-materializable entry from graph CAS and applies typed graph-only
        // policy to Gitlinks and host-unrepresentable byte paths. The export
        // proof plus the index-vs-HEAD check above bind the replacement Git
        // repository without falsely treating those graph-only entries as
        // worktree deletions.
        kin_git::sync_git_repository_for_authority_handoff(&git_dir)
            .context("make the replacement Git repository durable before eject")?;

        Ok(Self {
            _directory: directory,
            git_dir,
            export_proof: result.proof,
            imported_commits: result.imported_commits_reused,
            native_commits: result.native_commits_written,
        })
    }

    fn git_dir(&self) -> &Path {
        &self.git_dir
    }

    fn export_proof(&self) -> &kin_git::RepositoryGitExportProof {
        &self.export_proof
    }

    fn install_coexistence_config(&self, proof: &GitCoexistenceConfigProof) -> Result<()> {
        let worktree = self
            .git_dir
            .parent()
            .ok_or_else(|| anyhow::anyhow!("staged Git directory has no worktree parent"))?;
        install_git_coexistence_config(worktree, &self.git_dir, &proof.config.git)?;
        kin_git::sync_git_repository_for_authority_handoff(&self.git_dir)
            .context("make restored Git interoperability config durable before eject")
    }
}

struct GitCoexistenceConfigProof {
    bytes: Vec<u8>,
    config: kin_core::KinConfig,
}

impl GitCoexistenceConfigProof {
    fn load(path: &Path) -> Result<Self> {
        let bytes = read_real_file(path, "Kin repository config")?;
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("repository config is not UTF-8: {}", path.display()))?;
        let config: kin_core::KinConfig = toml::from_str(text)
            .with_context(|| format!("parse repository config {}", path.display()))?;
        config
            .validate()
            .context("validate sealed Git coexistence configuration")?;
        Ok(Self { bytes, config })
    }

    fn revalidate(&self, path: &Path) -> Result<()> {
        let current = read_real_file(path, "Kin repository config")?;
        if current != self.bytes {
            bail!(
                "Kin repository config changed while eject was preparing; replacement Git and \
                 Kin metadata remain attached"
            );
        }
        Ok(())
    }
}

fn install_git_coexistence_config(
    worktree: &Path,
    git_dir: &Path,
    config: &kin_core::GitCoexistenceConfig,
) -> Result<()> {
    config
        .validate()
        .context("validate sealed Git coexistence configuration")?;
    for remote in &config.remotes {
        let prefix = format!("remote.{}", remote.name);
        for value in &remote.fetch_urls {
            add_local_git_config(worktree, git_dir, &format!("{prefix}.url"), value)?;
        }
        for value in &remote.push_urls {
            add_local_git_config(worktree, git_dir, &format!("{prefix}.pushurl"), value)?;
        }
        for value in &remote.fetch_refspecs {
            add_local_git_config(worktree, git_dir, &format!("{prefix}.fetch"), value)?;
        }
        for value in &remote.push_refspecs {
            add_local_git_config(worktree, git_dir, &format!("{prefix}.push"), value)?;
        }
    }
    for branch in &config.branches {
        let prefix = format!("branch.{}", branch.branch);
        if let Some(remote) = &branch.remote {
            add_local_git_config(worktree, git_dir, &format!("{prefix}.remote"), remote)?;
        }
        for merge_ref in &branch.merge_refs {
            add_local_git_config(worktree, git_dir, &format!("{prefix}.merge"), merge_ref)?;
        }
        if let Some(remote) = &branch.push_remote {
            add_local_git_config(worktree, git_dir, &format!("{prefix}.pushRemote"), remote)?;
        }
    }
    if let Some(remote) = &config.remote_push_default {
        add_local_git_config(worktree, git_dir, "remote.pushDefault", remote)?;
    }
    if let Some(push_default) = config.push_default {
        add_local_git_config(worktree, git_dir, "push.default", push_default.as_str())?;
    }
    if let Some(auto_setup_remote) = config.push_auto_setup_remote {
        add_local_git_config(
            worktree,
            git_dir,
            "push.autoSetupRemote",
            if auto_setup_remote { "true" } else { "false" },
        )?;
    }
    Ok(())
}

fn add_local_git_config(worktree: &Path, git_dir: &Path, key: &str, value: &str) -> Result<()> {
    run_git(
        worktree,
        Some(git_dir),
        &["config", "--local", "--add", key, value],
    )
    .with_context(|| format!("restore sealed Git interoperability key {key}"))
}

fn create_eject_archive(
    layout: &kin_core::KinLayout,
) -> Result<(PathBuf, kin_core::ExactProjectionDetachTarget)> {
    let repository_root = layout.working_dir();
    let parent = repository_root
        .parent()
        .ok_or_else(|| anyhow::anyhow!("repository root has no parent"))?;
    let archive = parent.join(format!(
        ".kin-ejected-{}-{}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        uuid::Uuid::new_v4().simple()
    ));
    create_private_directory(&archive)?;
    let target = kin_core::ExactProjectionDetachTarget::open_existing(&archive)
        .context("retain the private eject archive as an exact detach target")?;
    Ok((archive, target))
}

fn ensure_real_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if !metadata.file_type().is_dir() {
        bail!("{label} at {} is not a real directory", path.display());
    }
    Ok(())
}

fn read_real_file(path: &Path, label: &str) -> Result<Vec<u8>> {
    let named_before = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if named_before.file_type().is_symlink() || !named_before.is_file() {
        bail!("{label} at {} is not a real file", path.display());
    }

    #[cfg(unix)]
    let mut file = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(fs::File::from)
    .map_err(std::io::Error::from)
    .with_context(|| format!("open {label} {}", path.display()))?;
    #[cfg(not(unix))]
    let mut file =
        fs::File::open(path).with_context(|| format!("open {label} {}", path.display()))?;

    let opened = file
        .metadata()
        .with_context(|| format!("inspect opened {label} {}", path.display()))?;
    if !opened.is_file() {
        bail!("opened {label} at {} is not a real file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if opened.dev() != named_before.dev() || opened.ino() != named_before.ino() {
            bail!("{label} changed identity while opening {}", path.display());
        }
    }

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("read {label} {}", path.display()))?;
    let named_after = fs::symlink_metadata(path)
        .with_context(|| format!("reinspect {label} {}", path.display()))?;
    if named_after.file_type().is_symlink() || !named_after.is_file() {
        bail!("{label} changed kind while reading {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if opened.dev() != named_after.dev() || opened.ino() != named_after.ino() {
            bail!("{label} changed identity while reading {}", path.display());
        }
    }
    Ok(bytes)
}

fn create_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;

        let mut builder = fs::DirBuilder::new();
        builder
            .mode(0o700)
            .create(path)
            .with_context(|| format!("create private eject archive {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path).with_context(|| format!("create eject archive {}", path.display()))?;
    }
    sync_directory(
        path.parent()
            .ok_or_else(|| anyhow::anyhow!("eject archive has no parent"))?,
    )
}

fn confirm_eject(
    captured: &AuthorityExportSnapshot,
    imported_commits: usize,
    native_commits: usize,
) -> Result<bool> {
    eprintln!();
    eprintln!("Eject Kin repository");
    eprintln!("  Repository: {}", captured.plan.repository_id);
    eprintln!("  Authority generation: {}", captured.roots.generation);
    eprintln!(
        "  Graph-owned workspace artifacts verified: {}",
        captured.workspace.tree.len()
    );
    eprintln!(
        "  Git history projection: {imported_commits} imported, {native_commits} native commits"
    );
    eprintln!("  Sealed credential-free Git remote and tracking config will be restored.");
    eprintln!("  Working files will not become repository authority.");
    eprintln!("  Detached metadata will remain in a recoverable sibling archive.");
    eprintln!();
    eprint!("Type \"eject\" to continue, or press Enter to abort: ");

    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim() == "eject")
}

fn refuse_live_vfs(layout: &kin_core::KinLayout) -> Result<()> {
    let pid_path = layout.root().join("vfs.pid");
    let Ok(raw_pid) = fs::read_to_string(&pid_path) else {
        return Ok(());
    };
    let pid = raw_pid.trim().parse::<u32>().with_context(|| {
        format!(
            "invalid VFS PID metadata at {}; stop Kin VFS manually before eject",
            pid_path.display()
        )
    })?;
    if crate::daemon_client::is_process_alive(pid) {
        bail!(
            "Kin VFS process {pid} is still active. Stop it before eject so no process retains \
             repository authority or recreates projection metadata"
        );
    }
    Ok(())
}

fn run_git(root: &Path, git_dir: Option<&Path>, args: &[&str]) -> Result<()> {
    let output = run_git_output(root, git_dir, args)?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "git {:?} failed (status {}): stdout={} stderr={}",
        args,
        output
            .status
            .code()
            .map_or_else(|| "signal".to_string(), |code| code.to_string()),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_git_output(root: &Path, git_dir: Option<&Path>, args: &[&str]) -> Result<Output> {
    let resolution_cwd =
        std::env::current_dir().context("capture host Git resolution directory for eject")?;
    let host_path =
        absolute_eject_host_search_path(kin_core::shims::unshimmed_path(), &resolution_cwd)?;
    let git = which::which_in("git", Some(&host_path), &resolution_cwd)
        .context("locate host Git executable for interoperability proof")?;
    let git = if git.is_absolute() {
        git
    } else {
        resolution_cwd.join(git)
    };
    let mut command = Command::new(git);
    command.current_dir(root);
    command.arg("--no-replace-objects");
    if let Some(git_dir) = git_dir {
        command
            .arg("--git-dir")
            .arg(git_dir)
            .arg("--work-tree")
            .arg(root);
    }
    command.args(args.iter().map(OsStr::new));
    finalize_eject_git_process(&mut command, &host_path);
    crate::daemon_client::probe_process::output_finalized_with_timeout_and_limit(
        command,
        &format!("Git interoperability proof {args:?}"),
        eject_git_timeout(args),
        EJECT_GIT_CAPTURE_LIMIT,
    )
    .with_context(|| format!("run Git interoperability proof {:?}", args))
}

fn eject_git_timeout(args: &[&str]) -> Duration {
    if args.first() == Some(&"fsck") {
        EJECT_GIT_FSCK_TIMEOUT
    } else {
        EJECT_GIT_METADATA_TIMEOUT
    }
}

fn absolute_eject_host_search_path(
    host_path: impl AsRef<OsStr>,
    resolution_cwd: &Path,
) -> Result<OsString> {
    let entries = std::env::split_paths(host_path.as_ref())
        .map(|entry| {
            if entry.is_absolute() {
                entry
            } else {
                resolution_cwd.join(entry)
            }
        })
        .collect::<Vec<_>>();
    std::env::join_paths(entries).with_context(|| {
        format!(
            "normalize host Git PATH against {} for eject",
            resolution_cwd.display()
        )
    })
}

/// Eject verifies a graph-derived Git projection against an explicit root.
/// Ambient repository selectors, Kin/VFS projection state, or loader injection
/// must not be able to redirect that proof to a shim or another repository.
fn isolate_eject_git_process(command: &mut Command, host_path: &OsStr) {
    let explicit_authority = command
        .get_envs()
        .map(|(key, _)| key.to_os_string())
        .filter(|key| is_eject_git_process_authority(key))
        .collect::<Vec<_>>();
    for key in std::env::vars_os()
        .map(|(key, _)| key)
        .filter(|key| is_eject_git_process_authority(key))
        .chain(explicit_authority)
    {
        command.env_remove(key);
    }
    command.env("PATH", host_path).env("KIN_VFS_DISABLE", "1");
}

/// Apply the complete authority boundary immediately before bounded spawn.
fn finalize_eject_git_process(command: &mut Command, host_path: &OsStr) {
    isolate_eject_git_process(command, host_path);
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config());
}

fn is_eject_git_process_authority(key: &std::ffi::OsStr) -> bool {
    let label = key.to_string_lossy();
    eject_env_name_starts_with(&label, "GIT_")
        || eject_env_name_starts_with(&label, "KIN_")
        || eject_env_name_starts_with(&label, "_KIN_")
        || eject_env_name_starts_with(&label, "DYLD_")
        || eject_env_name_starts_with(&label, "LD_")
}

#[cfg(windows)]
fn eject_env_name_starts_with(actual: &str, expected: &str) -> bool {
    actual
        .get(..expected.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(expected))
}

#[cfg(not(windows))]
fn eject_env_name_starts_with(actual: &str, expected: &str) -> bool {
    actual.starts_with(expected)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map(fs::File::from)
    .map_err(std::io::Error::from)
    .with_context(|| format!("open directory {}", path.display()))?
    .sync_all()
    .with_context(|| format!("sync directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod git_process_boundary_tests {
    use super::*;

    /// `kin eject` shells out to Git through this boundary, so the global
    /// config it binds has to be a path Git can actually open. Binding the
    /// reserved Windows device name `NUL` made Git fail with
    /// `fatal: unable to access 'NUL': Invalid argument` on a real Windows
    /// host, which failed the eject proof rather than isolating it.
    #[test]
    fn eject_git_boundary_binds_an_openable_empty_global_config() {
        let mut command = Command::new("git");
        finalize_eject_git_process(&mut command, OsStr::new("/host/bin"));

        let bound = command
            .get_envs()
            .find(|(key, _)| *key == OsStr::new("GIT_CONFIG_GLOBAL"))
            .and_then(|(_, value)| value)
            .expect("the eject Git boundary bound a global config");
        assert_eq!(
            bound,
            kin_git::empty_global_git_config(),
            "the eject Git boundary stopped routing through the shared helper"
        );
        assert!(
            Path::new(bound).is_absolute(),
            "bound global Git config {bound:?} is a bare name, not an absolute path"
        );
    }

    #[test]
    fn eject_git_boundary_scrubs_repository_vfs_and_loader_authority() {
        let mut command = Command::new("git");
        for (key, value) in [
            ("GIT_DIR", "/hostile/repository"),
            ("GIT_CONFIG_COUNT", "1"),
            ("KIN_VFS_WORKSPACE", "/hostile/projection"),
            ("_KIN_VFS_LAST_DIR", "/hostile/projection/src"),
            ("DYLD_INSERT_LIBRARIES", "/hostile/interpose.dylib"),
            ("LD_PRELOAD", "/hostile/interpose.so"),
        ] {
            command.env(key, value);
        }
        finalize_eject_git_process(&mut command, OsStr::new("/host/bin"));

        let envs = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        for removed in [
            "GIT_DIR",
            "GIT_CONFIG_COUNT",
            "KIN_VFS_WORKSPACE",
            "_KIN_VFS_LAST_DIR",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
        ] {
            assert_eq!(
                envs.get(removed),
                Some(&None),
                "{removed} retained eject Git authority"
            );
        }
        assert_eq!(envs.get("KIN_VFS_DISABLE"), Some(&Some("1".to_string())));
        assert_eq!(envs.get("PATH"), Some(&Some("/host/bin".to_string())));
        assert_eq!(
            envs.get("GIT_CONFIG_NOSYSTEM"),
            Some(&Some("1".to_string()))
        );
        assert_eq!(envs.get("GIT_OPTIONAL_LOCKS"), Some(&Some("0".to_string())));
    }

    #[cfg(unix)]
    #[test]
    fn relative_host_path_is_bound_absolutely_before_eject_changes_child_cwd() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let resolution_cwd = root.path().join("resolution");
        let child_cwd = root.path().join("child");
        let host_bin = resolution_cwd.join("bin");
        let hostile_bin = child_cwd.join("bin");
        std::fs::create_dir_all(&host_bin).unwrap();
        std::fs::create_dir_all(&hostile_bin).unwrap();
        let trusted = host_bin.join("git");
        let hostile = hostile_bin.join("git");
        std::fs::write(&trusted, "#!/bin/sh\nprintf trusted\n").unwrap();
        std::fs::write(&hostile, "#!/bin/sh\nprintf hostile\n").unwrap();
        for executable in [&trusted, &hostile] {
            let mut permissions = std::fs::metadata(executable).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(executable, permissions).unwrap();
        }

        let host_path = absolute_eject_host_search_path("bin", &resolution_cwd).unwrap();
        let git = which::which_in("git", Some(&host_path), &resolution_cwd).unwrap();
        assert!(git.is_absolute(), "host Git binding remained relative");
        // `sh` reads the binding as a script operand instead of `exec` taking
        // it as a program. That is the command line `exec` was already
        // building: the fixture carries a `#!/bin/sh` line, so the kernel ran
        // `/bin/sh <binding>` in the child's directory and passed the path
        // exactly as given. A binding that stayed relative therefore still
        // reaches the hostile copy below and still fails, because `sh`
        // resolves a relative operand against its own working directory just
        // as `exec` resolves a relative program path.
        //
        // What the spelling drops is a false failure. `exec` refuses with
        // `ETXTBSY` while any process holds the target inode open for
        // writing, and a sibling test thread's in-flight spawn
        // transiently owns a duplicate of the descriptor the `write` above
        // opened. Nothing here can close that window. The kernel counts
        // writers per inode, so materializing under a temporary name and
        // renaming into place carries the same count across; and the offending
        // descriptor lives in a child process this test never names. Ceasing
        // to be an `exec` target is what removes the exposure.
        let output = Command::new("/bin/sh")
            .arg(&git)
            .current_dir(&child_cwd)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"trusted");
    }

    #[test]
    fn repository_wide_fsck_has_a_separate_finite_budget() {
        assert!(EJECT_GIT_FSCK_TIMEOUT > EJECT_GIT_METADATA_TIMEOUT);
        assert_eq!(
            eject_git_timeout(&["fsck", "--strict"]),
            EJECT_GIT_FSCK_TIMEOUT
        );
        assert_eq!(
            eject_git_timeout(&["rev-parse", "--verify", "HEAD"]),
            EJECT_GIT_METADATA_TIMEOUT
        );
    }

    #[cfg(windows)]
    #[test]
    fn eject_git_boundary_is_case_insensitive_on_windows() {
        for hostile in [
            "git_dir",
            "Kin_Vfs_Workspace",
            "_kin_vfs_last_dir",
            "Dyld_Insert_Libraries",
            "ld_preload",
        ] {
            assert!(
                is_eject_git_process_authority(std::ffi::OsStr::new(hostile)),
                "{hostile} bypassed Windows eject Git isolation"
            );
        }
    }
}
