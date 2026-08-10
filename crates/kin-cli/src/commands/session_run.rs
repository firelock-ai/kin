// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Run a process inside an exact graph-derived session workspace.
//!
//! `exec`, `shell`, `open`, and `with` are one surface with four front doors:
//! the daemon materializes repository-authority CAS bodies into a disposable
//! `.kin/runs/session-<id>` projection, a process runs with its working
//! directory inside that projection, and the delta it leaves is either admitted
//! through the repository reconcile boundary or discarded. Nothing here reads
//! or ranks raw repository files: the projection comes from graph-owned truth
//! through the daemon, and the delta goes back the same way.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::commands::reconcile::ReconcileRequest;
use crate::commands::session_workspace::SessionWorkspaceRequest;
use crate::daemon_client::DaemonClient;

/// What to do with the session projection once the process exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCloseout {
    /// Admit the observed delta through repository authority, then remove the
    /// projection.
    Reconcile,
    /// Leave the projection in place for a later `kin reconcile`.
    Keep,
    /// Remove the projection without admitting anything.
    Discard,
}

/// A live session projection plus the daemon binding that produced it.
pub struct SessionProjection {
    client: DaemonClient,
    /// The `session-<uuid>` directory name, which is also the `kin reconcile`
    /// argument.
    name: String,
    dir: PathBuf,
    root: PathBuf,
    /// Set when the caller registered a capability-scoped daemon session for
    /// the process it is about to run.
    session_lease: Option<String>,
}

impl SessionProjection {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The `kin reconcile` argument that admits this projection later.
    pub fn reconcile_hint(&self) -> &str {
        self.name
            .strip_prefix("session-")
            .unwrap_or(self.name.as_str())
    }
}

/// Directory-name prefix for a launch profile under `.kin/runs/`.
///
/// Deliberately not `session-`: every reader of `.kin/runs/` selects
/// projections by that prefix — `resolve_session_directory` when picking the
/// latest session, `validate_session_leaf` when accepting a named one, and
/// [`discard`] when removing one — so a profile directory can never be
/// mistaken for a session to reconcile, resolve, or delete.
const LAUNCH_PROFILE_PREFIX: &str = "launch-profile-";

/// The generated launch profile for one `kin with --semantic-only` process.
///
/// The profile is a sibling of the session projection under `.kin/runs/`, and
/// both halves of that placement carry weight:
///
/// * The reconcile scanner walks the projection directory and nothing else, so
///   a profile file can never be observed as a working-tree change and admitted
///   into repository authority. A launch profile describes the launch, not the
///   work, and committing an assistant's permission settings on every clean
///   exit would be the opposite of what the flag is for.
/// * The launched process's working directory is the projection, so the profile
///   is not an entry of the tree the subject agent is working in.
///
/// A profile lives for exactly one child process. Its directory is removed on
/// every path out of [`with`], including the failure paths, which is why the
/// guard is armed by [`LaunchProfile::write`] before the first byte is written.
pub struct LaunchProfile {
    dir: PathBuf,
    extra_args: Vec<OsString>,
    disclosure: String,
}

impl LaunchProfile {
    /// Build and write one assistant's semantic-only profile.
    ///
    /// Called before the projection is materialized and before any daemon
    /// lease is registered: every step here is fallible, and a failure between
    /// `register_lease` and `close` would abandon both the projection directory
    /// and a live daemon session.
    pub fn write(
        runs_dir: &Path,
        adapter: &dyn super::assistant_adapter::AssistantAdapter,
        windows: bool,
    ) -> Result<Self> {
        let dir = runs_dir.join(format!("{LAUNCH_PROFILE_PREFIX}{}", uuid::Uuid::new_v4()));
        let profile = adapter.semantic_only(&dir, windows)?;
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create the launch profile directory {}", dir.display()))?;
        let written = Self {
            dir,
            extra_args: profile.extra_args,
            disclosure: profile.disclosure,
        };
        for file in &profile.files {
            let path = written.dir.join(&file.relative_path);
            std::fs::write(&path, &file.contents)
                .with_context(|| format!("write the launch profile file {}", path.display()))?;
        }
        Ok(written)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Flags the launched CLI needs to load this profile.
    pub fn extra_args(&self) -> &[OsString] {
        &self.extra_args
    }

    /// The one line printed at launch describing what the profile holds.
    pub fn disclosure(&self) -> &str {
        &self.disclosure
    }
}

impl Drop for LaunchProfile {
    fn drop(&mut self) {
        if let Err(error) = remove_launch_profile(&self.dir) {
            eprintln!(
                "Kin: failed to remove the launch profile {}: {error:#}",
                self.dir.display()
            );
        }
    }
}

/// Remove a launch profile directory.
///
/// Re-checked here for the same reason [`discard`] re-checks a session path: a
/// removal reached from a `Drop` must not be walkable into an arbitrary tree by
/// a caller that constructed the value with a different path.
fn remove_launch_profile(profile_dir: &Path) -> Result<()> {
    let name = profile_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if !name.starts_with(LAUNCH_PROFILE_PREFIX) || name.len() == LAUNCH_PROFILE_PREFIX.len() {
        bail!(
            "refusing to remove {}: not a launch profile",
            profile_dir.display()
        );
    }
    if profile_dir.is_symlink() {
        bail!(
            "refusing to remove {}: launch profile path is a symlink",
            profile_dir.display()
        );
    }
    match std::fs::remove_dir_all(profile_dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("remove the launch profile {}", profile_dir.display())),
    }
}

/// Materialize one disposable session projection through the daemon.
///
/// The daemon owns repository authority, so it is the only process allowed to
/// read CAS bodies and take the projection freeze. A CLI that materialized
/// locally would be a second writer against the same repository epoch.
pub async fn materialize(
    layout: kin_core::KinLayout,
    strategy: Option<String>,
    scope: Option<String>,
) -> Result<SessionProjection> {
    let base_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| {
            crate::daemon_client::daemon_required_error(
                "session workspace materialization",
                &layout,
            )
        })?;
    let client = DaemonClient::from_base_url_for_layout(base_url, &layout)?;

    let name = format!("session-{}", uuid::Uuid::new_v4());
    let dir = layout.runs_dir().join(&name);
    let response = client
        .session_workspace(&SessionWorkspaceRequest {
            session_dir: dir.display().to_string(),
            strategy,
            scope,
        })
        .await?;

    Ok(SessionProjection {
        client,
        name,
        dir,
        root: PathBuf::from(response.root),
        session_lease: None,
    })
}

/// Register a capability-scoped daemon session bound to this projection.
///
/// The returned session id is exported to the child as `KIN_SESSION_ID`, which
/// is what the MCP shim turns into the `X-Kin-Session` header, so an assistant
/// launched into the projection is coordinating under a declared capability set
/// rather than an anonymous one.
pub async fn register_lease(
    projection: &mut SessionProjection,
    vendor: &str,
    client_name: &str,
    capabilities: kin_model::session::SessionCapabilities,
) -> Result<String> {
    let session_id = projection
        .client
        .start_session(
            vendor,
            client_name,
            &projection.root,
            std::process::id(),
            capabilities,
        )
        .await?;
    projection.session_lease = Some(session_id.clone());
    Ok(session_id)
}

/// Environment every session child receives.
///
/// Kin-owned variables are set explicitly rather than inherited so a child
/// cannot pick up a stale session binding from the parent shell and reconcile
/// into the wrong projection.
fn session_env(projection: &SessionProjection) -> BTreeMap<&'static str, OsString> {
    let mut env = BTreeMap::new();
    env.insert("KIN_SESSION", OsString::from("1"));
    env.insert("KIN_SESSION_DIR", OsString::from(&projection.root));
    env.insert(
        "KIN_WORKSPACE_ROOT",
        OsString::from(projection.root.as_os_str()),
    );
    match projection.session_lease.as_deref() {
        Some(session_id) => {
            env.insert("KIN_SESSION_ID", OsString::from(session_id));
        }
        // An unleased session must not leave the parent's session id visible:
        // the child would bind daemon calls to a session it does not own.
        None => {
            env.insert("KIN_SESSION_ID", OsString::new());
        }
    }
    env
}

/// How a session child finished.
#[derive(Debug, Clone, Copy)]
pub struct SessionExit {
    pub code: i32,
}

/// Run `command` with its working directory inside the projection.
///
/// stdio is inherited so the child owns the terminal, which is the point of
/// every one of these surfaces.
pub fn run_in_session(
    projection: &SessionProjection,
    mut command: std::process::Command,
) -> Result<SessionExit> {
    command.current_dir(&projection.root);
    for (key, value) in session_env(projection) {
        if value.is_empty() {
            command.env_remove(key);
        } else {
            command.env(key, value);
        }
    }
    let status = command
        .stdin(if cfg!(test) {
            // A test has no terminal to hand over, so an inherited stdin would
            // block on a descriptor nobody writes to instead of failing.
            std::process::Stdio::null()
        } else {
            std::process::Stdio::inherit()
        })
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("run process in the exact session workspace")?;
    Ok(SessionExit {
        code: status.code().unwrap_or(1),
    })
}

/// Close out a session projection.
///
/// A non-zero child exit always preserves the projection: a failed run must
/// never be silently admitted into repository authority, and it must never be
/// silently deleted either.
pub async fn close(
    projection: &SessionProjection,
    exit: SessionExit,
    closeout: SessionCloseout,
) -> Result<()> {
    if let Some(session_id) = projection.session_lease.as_deref() {
        if let Err(error) = projection.client.end_session(session_id).await {
            eprintln!("Kin: failed to end the session lease {session_id}: {error}");
        }
    }

    if closeout == SessionCloseout::Discard {
        discard(&projection.dir)?;
        eprintln!("Discarded session workspace.");
        return Ok(());
    }

    if exit.code != 0 {
        eprintln!(
            "Process exited {}; session workspace kept at: {}",
            exit.code,
            projection.dir.display()
        );
        eprintln!(
            "  admit its changes anyway: kin reconcile {}",
            projection.reconcile_hint()
        );
        eprintln!("  discard it: rm -rf {}", projection.dir.display());
        return Ok(());
    }

    if closeout == SessionCloseout::Keep {
        eprintln!("Session workspace kept at: {}", projection.dir.display());
        eprintln!(
            "  admit its changes: kin reconcile {}",
            projection.reconcile_hint()
        );
        return Ok(());
    }

    let summary = projection
        .client
        .reconcile(&ReconcileRequest {
            session_dir: projection.dir.clone(),
            confirm_mass_deletion: false,
        })
        .await
        .with_context(|| {
            format!(
                "admit the session observation; the workspace is kept at {} and can be retried \
                 with `kin reconcile {}`",
                projection.dir.display(),
                projection.reconcile_hint()
            )
        })?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    discard(&projection.dir)?;
    Ok(())
}

/// Remove a session projection directory.
///
/// Only ever called with a path the daemon just materialized under
/// `.kin/runs/`, and re-checked here so a caller cannot walk this into an
/// arbitrary removal. This is the one removal path for a projection, whether
/// the surface closes its own session or `kin reconcile` collects it later.
pub(crate) fn discard(session_dir: &Path) -> Result<()> {
    let name = session_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if !name.starts_with("session-") || name.len() == "session-".len() {
        bail!(
            "refusing to remove {}: not a session projection",
            session_dir.display()
        );
    }
    if session_dir.is_symlink() {
        bail!(
            "refusing to remove {}: session projection path is a symlink",
            session_dir.display()
        );
    }
    std::fs::remove_dir_all(session_dir)
        .with_context(|| format!("remove session workspace {}", session_dir.display()))
}

/// Discover the repository layout for a session surface.
pub fn discover_layout() -> Result<kin_core::KinLayout> {
    let cwd = std::env::current_dir().context("resolve current directory")?;
    crate::commands::require_repository_layout_at(&cwd)
}

/// How `kin exec` interprets its trailing arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecInvocation {
    /// argv boundaries preserved exactly as given.
    Direct { program: String, args: Vec<String> },
    /// One script handed to the platform shell.
    Shell(String),
}

impl ExecInvocation {
    pub fn parse(parts: Vec<String>, shell: bool) -> Result<Self> {
        if parts.is_empty() || parts.iter().all(String::is_empty) {
            bail!("no command provided: kin exec [--keep|--discard] -- <command...>");
        }
        if shell {
            if parts.len() != 1 {
                bail!(
                    "`--shell` takes exactly one script argument; quote the whole script, for \
                     example: kin exec --shell -- 'printf \"%s\\n\" \"$KIN_SESSION_DIR\"'"
                );
            }
            let script = parts
                .into_iter()
                .next()
                .unwrap_or_default()
                .trim()
                .to_string();
            if script.is_empty() {
                bail!("shell script cannot be empty");
            }
            return Ok(Self::Shell(script));
        }
        let mut parts = parts.into_iter();
        let program = parts.next().unwrap_or_default();
        if program.is_empty() {
            bail!("command program cannot be empty");
        }
        Ok(Self::Direct {
            program,
            args: parts.collect(),
        })
    }

    pub fn command(&self) -> std::process::Command {
        match self {
            Self::Direct { program, args } => {
                let mut command = std::process::Command::new(program);
                command.args(args);
                command
            }
            Self::Shell(script) if cfg!(target_os = "windows") => {
                let mut command = std::process::Command::new("cmd");
                command.args(["/C", script]);
                command
            }
            Self::Shell(script) => {
                let mut command = std::process::Command::new("sh");
                command.args(["-c", script]);
                command
            }
        }
    }
}

/// Pick the closeout the caller asked for.
pub fn closeout_for(keep: bool, discard: bool) -> SessionCloseout {
    match (keep, discard) {
        (_, true) => SessionCloseout::Discard,
        (true, _) => SessionCloseout::Keep,
        _ => SessionCloseout::Reconcile,
    }
}

/// `kin exec [--shell] [--keep|--discard] -- <command...>`.
pub async fn exec(
    command_parts: Vec<String>,
    shell: bool,
    keep: bool,
    discard: bool,
    strategy: Option<String>,
    scope: Option<String>,
) -> Result<()> {
    let invocation = ExecInvocation::parse(command_parts, shell)?;
    let layout = discover_layout()?;
    let projection = materialize(layout, strategy, scope).await?;
    eprintln!("Session workspace: {}", projection.root().display());

    let exit = run_in_session(&projection, invocation.command())?;
    close(&projection, exit, closeout_for(keep, discard)).await?;
    if exit.code != 0 {
        std::process::exit(exit.code);
    }
    Ok(())
}

/// `kin shell`.
pub async fn shell(strategy: Option<String>) -> Result<()> {
    let layout = discover_layout()?;
    let projection = materialize(layout, strategy, None).await?;
    eprintln!("Session workspace: {}", projection.root().display());
    eprintln!("Exit the shell to admit its changes through repository authority.");

    let exit = run_in_session(&projection, interactive_shell_command())?;
    close(&projection, exit, SessionCloseout::Reconcile).await?;
    if exit.code != 0 {
        std::process::exit(exit.code);
    }
    Ok(())
}

fn interactive_shell_command() -> std::process::Command {
    if cfg!(target_os = "windows") {
        return std::process::Command::new(
            std::env::var_os("COMSPEC").unwrap_or_else(|| OsString::from("cmd")),
        );
    }
    let shell = std::env::var_os("SHELL").unwrap_or_else(|| OsString::from("/bin/sh"));
    std::process::Command::new(shell)
}

/// Editors `kin open` knows how to launch.
///
/// The allowlist is the point: an arbitrary program name here would make
/// `kin open` a second `kin exec` with none of its argument discipline.
pub fn editor_program(editor: &str) -> Result<&'static str> {
    match editor.trim().to_ascii_lowercase().as_str() {
        "code" | "vscode" => Ok("code"),
        "cursor" => Ok("cursor"),
        other => bail!("unknown editor '{other}'; kin open supports: code, cursor"),
    }
}

/// `kin open <editor>`.
///
/// The editor is launched over the projection and the projection is retained:
/// editors detach from the launching process, so there is no exit to key an
/// automatic admission on. `kin reconcile <session>` is both the admission and
/// the collector: it removes the projection once the daemon has taken its
/// delta, so a retained projection lives exactly until its changes land.
pub async fn open(
    editor: String,
    restrict_discovery: bool,
    restrict_filesystem: bool,
) -> Result<()> {
    if restrict_discovery || restrict_filesystem {
        bail!(
            "--restrict-discovery and --restrict-filesystem belonged to the discontinued native \
             editor fork and are fail-closed; the session projection is the boundary now"
        );
    }
    let program = editor_program(&editor)?;
    let layout = discover_layout()?;
    let projection = materialize(layout, None, None).await?;

    let mut command = std::process::Command::new(program);
    command.arg(projection.root());
    let exit = run_in_session(&projection, command)?;
    if exit.code != 0 {
        eprintln!(
            "{program} exited {}; session workspace kept at: {}",
            exit.code,
            projection.root().display()
        );
        std::process::exit(exit.code);
    }
    println!("Session workspace: {}", projection.root().display());
    println!(
        "Admit its changes when you are done: kin reconcile {}",
        projection.reconcile_hint()
    );
    Ok(())
}

/// Assistants `kin with` knows how to launch.
///
/// Resolution lives in the adapter registry so the launcher and `kin setup`'s
/// registration writers can never disagree about which assistants exist.
pub fn assistant_program(assistant: &str) -> Result<&'static str> {
    Ok(super::assistant_adapter::adapter_for(assistant)?.program())
}

/// `kin with <assistant> [-- <task...>]`.
pub async fn with(
    assistant: String,
    session: bool,
    passive_guidance: bool,
    restrict_discovery: bool,
    restrict_filesystem: bool,
    semantic_only: bool,
    task: Vec<String>,
) -> Result<()> {
    if restrict_discovery || restrict_filesystem {
        bail!(
            "--restrict-discovery and --restrict-filesystem belonged to the discontinued native \
             editor fork and are fail-closed; the session projection is the boundary now"
        );
    }
    if passive_guidance {
        bail!(
            "--passive-guidance is fail-closed: prompt-guidance injection was removed with the \
             legacy assistant path, so there is no guidance to suppress"
        );
    }
    if session {
        bail!(
            "--session is fail-closed: it was the opt-in when an unprojected assistant launch \
             existed, and every launch is now a session projection, so the flag can only mean \
             something it no longer selects"
        );
    }

    let adapter = super::assistant_adapter::adapter_for(&assistant)?;
    let program = adapter.program();

    let layout = discover_layout()?;
    // Write the profile before materializing. Every step of it is fallible —
    // an unsupported assistant, a full disk, a read-only mount — and a failure
    // after the projection exists would abandon the projection directory, and
    // after `register_lease` a live daemon session with it.
    let profile = semantic_only
        .then(|| LaunchProfile::write(&layout.runs_dir(), adapter, cfg!(windows)))
        .transpose()?;

    let mut projection = materialize(layout, None, None).await?;
    let session_id = register_lease(
        &mut projection,
        program,
        "kin with",
        kin_model::session::SessionCapabilities {
            can_read: true,
            can_write: true,
            can_execute: true,
            can_branch: false,
            can_commit: true,
            max_concurrent_intents: 8,
        },
    )
    .await?;
    eprintln!("Session workspace: {}", projection.root().display());
    eprintln!("Session: {session_id}");

    let mut command = std::process::Command::new(program);
    if let Some(profile) = &profile {
        command.args(profile.extra_args());
        eprintln!("{}", profile.disclosure());
    }
    if !task.is_empty() {
        command.args(&task);
    }
    let exit = run_in_session(&projection, command)?;
    close(&projection, exit, SessionCloseout::Reconcile).await?;
    // `std::process::exit` runs no destructors, so the profile is removed here
    // rather than left to drop on the way out of a non-zero exit.
    drop(profile);
    if exit.code != 0 {
        std::process::exit(exit.code);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_preserves_argv_boundaries_and_shell_mode_takes_one_script() {
        let direct = ExecInvocation::parse(
            vec![
                "printf".to_string(),
                "value with spaces".to_string(),
                "literal;semicolon".to_string(),
            ],
            false,
        )
        .unwrap();
        assert_eq!(
            direct,
            ExecInvocation::Direct {
                program: "printf".to_string(),
                args: vec![
                    "value with spaces".to_string(),
                    "literal;semicolon".to_string()
                ],
            }
        );

        let shell =
            ExecInvocation::parse(vec!["printf '%s' \"$KIN_SESSION_DIR\"".to_string()], true)
                .unwrap();
        assert_eq!(
            shell,
            ExecInvocation::Shell("printf '%s' \"$KIN_SESSION_DIR\"".to_string())
        );

        assert!(ExecInvocation::parse(vec!["a".to_string(), "b".to_string()], true).is_err());
        assert!(ExecInvocation::parse(Vec::new(), false).is_err());
        assert!(ExecInvocation::parse(vec![String::new()], true).is_err());
    }

    #[test]
    fn discard_refuses_paths_that_are_not_session_projections() {
        let temp = tempfile::tempdir().unwrap();
        let not_a_session = temp.path().join("runs");
        std::fs::create_dir_all(&not_a_session).unwrap();
        let error = discard(&not_a_session).unwrap_err().to_string();
        assert!(error.contains("not a session projection"), "{error}");
        assert!(not_a_session.exists());

        let bare_prefix = temp.path().join("session-");
        std::fs::create_dir_all(&bare_prefix).unwrap();
        assert!(discard(&bare_prefix).is_err());

        let real = temp.path().join("session-abc");
        std::fs::create_dir_all(real.join("nested")).unwrap();
        discard(&real).unwrap();
        assert!(!real.exists());
    }

    #[cfg(unix)]
    #[test]
    fn discard_refuses_a_symlinked_session_path() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("real-tree");
        std::fs::create_dir_all(&target).unwrap();
        let link = temp.path().join("session-linked");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let error = discard(&link).unwrap_err().to_string();
        assert!(error.contains("symlink"), "{error}");
        assert!(target.exists());
    }

    #[test]
    fn closeout_precedence_puts_discard_first() {
        assert_eq!(closeout_for(false, false), SessionCloseout::Reconcile);
        assert_eq!(closeout_for(true, false), SessionCloseout::Keep);
        assert_eq!(closeout_for(false, true), SessionCloseout::Discard);
        assert_eq!(closeout_for(true, true), SessionCloseout::Discard);
    }

    #[test]
    fn launcher_allowlists_reject_arbitrary_programs() {
        assert_eq!(editor_program("code").unwrap(), "code");
        assert_eq!(editor_program("Cursor").unwrap(), "cursor");
        assert!(editor_program("rm").is_err());

        assert_eq!(assistant_program("claude-code").unwrap(), "claude");
        assert_eq!(assistant_program("gemini").unwrap(), "gemini");
        assert!(assistant_program("sh").is_err());
    }
}
