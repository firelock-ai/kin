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

use std::ffi::OsStr;
use std::fs;
use std::io::{BufRead as _, Read as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};
use kin_model::{ResolvedTree, TreeEntry};

use super::git::{
    capture_export_snapshot, capture_export_snapshot_from_state, AuthorityExportSnapshot,
    RepositorySource,
};
use super::repository_authority::ActiveRepositoryAuthority;

/// Verify graph truth, install its exact Git projection, and detach Kin.
pub async fn run(yes: bool) -> Result<()> {
    ensure_eject_platform()?;
    let cwd = std::env::current_dir()?;
    let layout = kin_core::KinLayout::discover(&cwd)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository"))?;
    ensure_real_directory(layout.root(), "Kin metadata")?;
    refuse_live_vfs(&layout)?;

    let authority = ActiveRepositoryAuthority::open(&layout)?;
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
    let reopened = ActiveRepositoryAuthority::open(&layout)
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
            let digest = artifact.entry.blob_identity().ok_or_else(|| {
                anyhow::anyhow!(
                    "workspace contains gitlink {} at {}; eject cannot produce a complete \
                     materialized ordinary working tree for submodules",
                    artifact.path,
                    match artifact.entry {
                        TreeEntry::Gitlink { target } => target.to_string(),
                        _ => "unknown".to_string(),
                    }
                )
            })?;
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
        }
        // A genuinely unborn Git repository canonically has no index. Creating
        // one with `read-tree --empty` would require adding an unreachable
        // empty-tree object that is absent from exact repository authority.
        run_git(&worktree, Some(&git_dir), &["fsck", "--strict"])
            .context("verify staged ordinary Git object closure")?;
        let status = run_git_output(
            repository_root,
            Some(&git_dir),
            &["status", "--porcelain=v1", "-z", "--untracked-files=no"],
        )?;
        if !status.status.success() {
            bail!(
                "staged ordinary Git could not read the exact working projection: stdout={} \
                 stderr={}",
                String::from_utf8_lossy(&status.stdout),
                String::from_utf8_lossy(&status.stderr)
            );
        }
        if !status.stdout.is_empty() {
            bail!(
                "staged ordinary Git index does not exactly match the graph-owned working \
                 projection"
            );
        }
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
    let git = which::which("git").context("locate Git executable for interoperability proof")?;
    let mut command = Command::new(git);
    command.current_dir(root);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .arg("--no-replace-objects");
    #[cfg(unix)]
    command.env("GIT_CONFIG_GLOBAL", "/dev/null");
    #[cfg(windows)]
    command.env("GIT_CONFIG_GLOBAL", "NUL");
    if let Some(git_dir) = git_dir {
        command
            .arg("--git-dir")
            .arg(git_dir)
            .arg("--work-tree")
            .arg(root);
    }
    command.args(args.iter().map(OsStr::new));
    command
        .output()
        .with_context(|| format!("run Git interoperability proof {:?}", args))
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
