// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The launcher half of `kin_session_exec`: run one toolchain command for an
//! agent session and hand back only what its policy admits.
//!
//! [`kin_mcp::session_exec`] owns the words and the command policy and touches
//! no filesystem. This module is the execution boundary it hands off to, the
//! same one `kin exec` uses:
//!
//! 1. The session named must be open on the repository's daemon and must have
//!    declared `can_execute`.
//! 2. The daemon materializes a session workspace from the current graph head,
//!    which carries every change the session already committed.
//! 3. The project's languages are read from the names in that workspace, never
//!    from file contents, and the command is admitted against their entry
//!    points and the repository's `[execution.agent]` configuration. A refused
//!    command never runs, and its workspace is removed.
//! 4. The command runs directly, with no shell, in its own process group, with
//!    its output bounded as it arrives and a timeout that stops the whole
//!    group.
//! 5. A command that succeeded has its workspace reconciled under
//!    [`SessionWriteBack::ToolchainManifests`], so only toolchain manifests and
//!    lockfiles are admitted, and the admission is recorded as one change
//!    attributed to the session. Anything else it wrote is reported and
//!    dropped with the workspace.
//!
//! Nothing here answers a question about the code. The only reads are the
//! workspace's top-level names, to tell which toolchain a project uses, the
//! repository's own configuration, and for a Go target the checks in
//! [`agent_exec_go`]: its go.mod and go.work, where the target resolves, and
//! a `go run` file's package clause, none of which reaches the agent.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use kin_mcp::session_exec::{
    BoundedCapture, CapturedStream, CommandPolicy, CommandRefusal, ExecOutcome, ExecReport,
    ExecRequest, Language, PathChange, RanOn, SessionExecutor, WithheldPath, WriteBackReport,
    WriteBackState,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::commands::agent_exec_go;
use crate::commands::reconcile::{
    ReconcileChangeKind, ReconcilePath, ReconcileRequest, SessionWriteBack, Toolchain,
};
use crate::commands::session_run::{self, SessionProjection};
use crate::commands::session_workspace::SessionWorkspaceBase;
use crate::daemon_client::DaemonClient;

/// How many withheld changes an answer lists by path. The rest are counted.
const WITHHELD_LISTED: usize = 50;

/// How long the output readers get to drain once the command's process group
/// is gone.
const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// What `/commands/exec-commit` takes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecCommitRequest {
    pub operation_id: kin_model::OperationId,
    pub timestamp: kin_model::Timestamp,
    pub session_id: String,
    pub message: String,
    pub authored_paths: Vec<String>,
    /// The workspace generation and tree the run's reconcile published, which
    /// the change must record exactly.
    pub expected_workspace_generation: u64,
    pub expected_tree_hash: kin_model::Hash256,
}

/// What `/commands/exec-commit` answers.
#[derive(Debug, Clone, Deserialize)]
pub struct ExecCommitResponse {
    pub change_id: String,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub carried_pending_files: Vec<String>,
    /// The tree of the head the change left.
    pub tree_hash: kin_model::Hash256,
    pub workspace_generation: u64,
}

/// The executor `kin mcp start` and `kin call` hand the MCP server.
pub fn executor() -> SessionExecutor {
    Arc::new(|request: ExecRequest| Box::pin(run(request)))
}

/// Run one call. Every failure to get as far as running the command comes back
/// as [`ExecOutcome::Failed`] in its own words.
pub async fn run(request: ExecRequest) -> ExecOutcome {
    match run_checked(&request).await {
        Ok(outcome) => outcome,
        Err(error) => ExecOutcome::Failed(format!("{error:#}")),
    }
}

async fn run_checked(request: &ExecRequest) -> Result<ExecOutcome> {
    if uuid::Uuid::parse_str(&request.session_id).is_err() {
        return Ok(ExecOutcome::SessionRefused(format!(
            "{:?} is not a session id. Open a session with kin_session_start declaring \
             can_execute, and pass the session_id it returns.",
            request.session_id
        )));
    }
    let (layout, url) = bind().await?;
    let client = DaemonClient::from_base_url_with_explicit_authority(
        url,
        crate::daemon_client::resolve_daemon_auth_token_for_layout(&layout),
        Some(&request.session_id),
    )?;
    let Some(session) = client.refresh_session(&request.session_id).await? else {
        return Ok(ExecOutcome::SessionRefused(format!(
            "Session {} is not open on this repository's daemon: it ended or expired after its \
             idle timeout. Open one with kin_session_start declaring can_execute, and run the \
             command again with its session_id.",
            request.session_id
        )));
    };
    if !session.capabilities.can_execute {
        return Ok(ExecOutcome::SessionRefused(format!(
            "Session {} did not declare can_execute, and a session's capabilities are fixed when \
             it starts. Open one with kin_session_start declaring can_execute, with can_write and \
             can_commit to keep the manifests a command writes.",
            request.session_id
        )));
    }
    let may_write = session.capabilities.can_write && session.capabilities.can_commit;
    let configured = kin_core::KinConfig::load_or_default(&layout.config_path())
        .with_context(|| format!("read {}", layout.config_path().display()))?
        .execution
        .agent;

    let projection = session_run::materialize(layout, None, None)
        .await
        .context("materialize the session workspace from the current graph head")?;
    // Read before anything runs, from the base record the daemon wrote with
    // the workspace, so it names the state the command really ran on.
    let ran_on = ran_on(projection.root());
    let (policy, admitted) = admission(
        &request.argv,
        projection.root(),
        &configured,
        &agent_exec_go::GoEnvironment::inherited(),
    );
    if let Err(refusal) = admitted {
        drop_workspace(&projection);
        return Ok(ExecOutcome::Refused { refusal, policy });
    }

    let ran = match run_command(request, projection.root()).await {
        Ok(ran) => ran,
        Err(error) => {
            drop_workspace(&projection);
            return Err(error);
        }
    };
    let succeeded = !ran.timed_out && ran.exit_code == Some(0);
    let write_back = if !succeeded {
        drop_workspace(&projection);
        WriteBackReport::with_state(
            WriteBackState::NotAttempted,
            match ran.exit_code {
                _ if ran.timed_out => {
                    "The command was stopped at its timeout, so nothing it wrote was kept."
                        .to_string()
                }
                Some(code) => format!("The command exited {code}, so nothing it wrote was kept."),
                None => {
                    "The command was stopped by a signal, so nothing it wrote was kept.".to_string()
                }
            },
        )
    } else if !may_write {
        drop_workspace(&projection);
        WriteBackReport::with_state(
            WriteBackState::NotPermitted,
            format!(
                "Session {} did not declare can_write and can_commit, so nothing the command \
                 wrote was kept.",
                request.session_id
            ),
        )
    } else {
        hand_back(&client, &projection, request).await
    };
    Ok(ExecOutcome::Ran(ExecReport {
        languages: policy.languages,
        ran_on,
        exit_code: ran.exit_code,
        timed_out: ran.timed_out,
        elapsed: ran.elapsed,
        stdout: ran.stdout,
        stderr: ran.stderr,
        write_back,
    }))
}

/// The policy a command runs under in the workspace at `root`, and whether
/// it is admitted there: against the project's languages and the
/// repository's `[execution.agent]` configuration, and for a Go build, run,
/// test or vet, against the repository's modules where its targets resolve
/// and the Go settings the command inherits.
fn admission(
    argv: &[String],
    root: &Path,
    configured: &kin_core::AgentExecConfig,
    go_environment: &agent_exec_go::GoEnvironment,
) -> (CommandPolicy, Result<(), CommandRefusal>) {
    let project = detect_project(root);
    let policy = CommandPolicy {
        languages: match &configured.languages {
            Some(names) => names
                .iter()
                .filter_map(|name| Language::parse(name))
                .collect(),
            None if project.languages.is_empty() => Language::ALL.to_vec(),
            None => project.languages.iter().copied().collect(),
        },
        extra: configured
            .allow
            .iter()
            .map(|entry| {
                entry
                    .split_whitespace()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .filter(|words| !words.is_empty())
            .collect(),
        python_modules: project.python_modules.iter().cloned().collect(),
        go: agent_exec_go::go_modules(root, go_environment),
    };
    let admitted = kin_mcp::session_exec::admit(argv, &policy).and_then(|()| {
        // A Go target is checked where it resolves, and under the Go
        // settings the command inherits, before anything runs.
        match kin_mcp::session_exec::go_targets(argv) {
            Some(targets) => go_environment
                .refusal()
                .map_or(Ok(()), Err)
                .and_then(|()| agent_exec_go::check_targets_on_disk(&targets, root, &policy.go)),
            None => Ok(()),
        }
    });
    (policy, admitted)
}

/// The repository this server is bound to and its daemon's endpoint: the
/// daemon `KIN_DAEMON_URL` names, which the MCP binding sets, and the
/// repository it says it serves; otherwise the repository around the working
/// directory.
async fn bind() -> Result<(kin_core::KinLayout, String)> {
    let override_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|url| !url.trim().is_empty());
    if let Some(url) = override_url {
        let health = DaemonClient::from_base_url(url.clone())?
            .health()
            .await
            .context("reach the repository's daemon")?;
        let root = match health.repo_root {
            Some(root) => PathBuf::from(root),
            None => std::env::current_dir().context("resolve the working directory")?,
        };
        let layout = crate::commands::require_repository_layout_at(&root)?;
        return Ok((layout, url));
    }
    let cwd = std::env::current_dir().context("resolve the working directory")?;
    let layout = crate::commands::require_repository_layout_at(&cwd)?;
    let url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| crate::daemon_client::daemon_required_error("kin_session_exec", &layout))?;
    Ok((layout, url))
}

/// Remove a session workspace this run is done with.
fn drop_workspace(projection: &SessionProjection) {
    if let Err(error) = session_run::discard(projection.dir()) {
        tracing::warn!(
            workspace = %projection.dir().display(),
            error = %format!("{error:#}"),
            "kin_session_exec could not remove its session workspace"
        );
    }
}

/// What the command did.
struct Ran {
    exit_code: Option<i32>,
    timed_out: bool,
    elapsed: Duration,
    stdout: CapturedStream,
    stderr: CapturedStream,
}

/// Run `request`'s argv in the workspace at `root`, with no shell, bounded
/// output and a timeout that stops every process the command started. The
/// call's application variables are set exactly as given, never expanded;
/// the server refused any that change how a program is found or loaded.
async fn run_command(request: &ExecRequest, root: &Path) -> Result<Ran> {
    let mut command = tokio::process::Command::new(&request.argv[0]);
    command.args(&request.argv[1..]).current_dir(root);
    for (name, value) in &request.env {
        command.env(name, value);
    }
    // A go command builds the repository's own go.work or none, whatever a
    // go.work above the workspace or the server's environment says, so the
    // modules the target was checked against are the ones it builds.
    if kin_mcp::session_exec::language_of(&request.argv[0]) == Some(Language::Go) {
        command.env("GOWORK", agent_exec_go::pinned_gowork(root));
    }
    command
        .env("KIN_SESSION", "1")
        .env("KIN_SESSION_DIR", root)
        .env("KIN_WORKSPACE_ROOT", root)
        .env("KIN_SESSION_ID", &request.session_id)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Its own process group, so a timeout stops what the command started,
    // `go run`'s compiled program included, and nothing outlives the call.
    #[cfg(unix)]
    command.process_group(0);
    let started = Instant::now();
    let mut child = command.spawn().with_context(|| {
        format!(
            "start {}: is its toolchain installed and on the PATH this Kin server runs with?",
            request.argv[0]
        )
    })?;
    let stdout = child.stdout.take().context("take the command's stdout")?;
    let stderr = child.stderr.take().context("take the command's stderr")?;
    let bound = request.max_output_bytes;
    let stdout = tokio::spawn(capture(stdout, bound));
    let stderr = tokio::spawn(capture(stderr, bound));
    let group = child.id();
    let (status, timed_out) = match tokio::time::timeout(request.timeout, child.wait()).await {
        Ok(status) => (status.ok(), false),
        Err(_) => {
            stop_group(group);
            let _ = child.start_kill();
            (child.wait().await.ok(), true)
        }
    };
    let elapsed = started.elapsed();
    // Anything the command left running in its group goes with it, which also
    // closes the pipes the readers are draining.
    stop_group(group);
    Ok(Ran {
        exit_code: if timed_out {
            None
        } else {
            status.and_then(|status| status.code())
        },
        timed_out,
        elapsed,
        stdout: drained(stdout).await,
        stderr: drained(stderr).await,
    })
}

async fn capture(mut stream: impl AsyncRead + Unpin, bound: usize) -> CapturedStream {
    let mut captured = BoundedCapture::new(bound);
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => captured.push(&buffer[..read]),
        }
    }
    captured.finish()
}

async fn drained(reader: tokio::task::JoinHandle<CapturedStream>) -> CapturedStream {
    match tokio::time::timeout(DRAIN_GRACE, reader).await {
        Ok(Ok(captured)) => captured,
        _ => CapturedStream {
            text: "[Kin stopped reading this stream: a process outside the command's group held \
                   it open]"
                .to_string(),
            ..CapturedStream::default()
        },
    }
}

/// Stop every process in the command's group.
fn stop_group(group: Option<u32>) {
    #[cfg(unix)]
    if let Some(group) = group.and_then(|id| i32::try_from(id).ok()) {
        // SAFETY: killpg only sends a signal. The group is the one this run
        // created with `process_group(0)`, led by the child it spawned.
        unsafe {
            libc::killpg(group, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    let _ = group;
}

/// Hand a successful run's writes back under the agent policy, record what was
/// admitted as a change, and remove the workspace.
async fn hand_back(
    client: &DaemonClient,
    projection: &SessionProjection,
    request: &ExecRequest,
) -> WriteBackReport {
    // A toolchain hands back its own manifests only. A command the repository
    // configured belongs to no one toolchain, so it may hand back any.
    let write_back = match kin_mcp::session_exec::language_of(&request.argv[0]) {
        Some(language) => SessionWriteBack::ManifestsOf(toolchain_of(language)),
        None => SessionWriteBack::ToolchainManifests,
    };
    let summary = match client
        .reconcile(&ReconcileRequest {
            session_dir: projection.dir().to_path_buf(),
            confirm_mass_deletion: false,
            write_back,
        })
        .await
    {
        Ok(summary) => summary,
        Err(error) => {
            // Kept, because a reconcile whose outcome is unknown may have a
            // publication in flight that recovery reads this workspace for.
            return WriteBackReport::with_state(
                WriteBackState::Failed,
                format!(
                    "Kin could not hand the command's writes to the repository, so nothing was \
                     admitted: {error:#}. The session workspace is kept for the operator at {}, \
                     where `kin doctor` lists it.",
                    projection.dir().display()
                ),
            );
        }
    };
    drop_workspace(projection);

    let admitted: Vec<PathChange> = summary
        .changes
        .iter()
        .filter_map(|change| {
            let path = change.new_path.as_ref().or(change.old_path.as_ref())?;
            Some(PathChange {
                path: path_text(path),
                change: change_kind(change.kind).to_string(),
            })
        })
        .collect();
    let withheld_total = summary.withheld.len();
    let withheld: Vec<WithheldPath> = summary
        .withheld
        .iter()
        .take(WITHHELD_LISTED)
        .map(|withheld| WithheldPath {
            path: path_text(&withheld.path),
            change: change_kind(withheld.kind).to_string(),
            reason: serde_json::to_value(withheld.reason)
                .ok()
                .and_then(|value| value.as_str().map(str::to_string))
                .unwrap_or_default(),
            why: withheld.reason.sentence().to_string(),
        })
        .collect();
    let mut report = WriteBackReport {
        state: WriteBackState::Unchanged,
        admitted,
        withheld,
        withheld_total,
        change_id: None,
        tree_hash: None,
        carried_pending_files: Vec::new(),
        note: String::new(),
    };
    if !summary.changed || report.admitted.is_empty() {
        report.note = if withheld_total == 0 {
            "The command changed no file.".to_string()
        } else {
            "The command wrote nothing a toolchain run hands back; the withheld changes were not \
             kept."
                .to_string()
        };
        return report;
    }

    let paths: Vec<String> = report
        .admitted
        .iter()
        .map(|change| change.path.clone())
        .collect();
    let message = request
        .summary
        .clone()
        .unwrap_or_else(|| default_message(&request.argv, &paths));
    match client
        .exec_commit(&ExecCommitRequest {
            operation_id: kin_model::OperationId::new(),
            timestamp: kin_model::Timestamp::now(),
            session_id: request.session_id.clone(),
            message,
            authored_paths: paths.clone(),
            expected_workspace_generation: summary.workspace_generation,
            expected_tree_hash: summary.desired_tree_hash,
        })
        .await
    {
        Ok(committed) => {
            report.state = WriteBackState::Committed;
            report.note = format!(
                "{} admitted and recorded as change {} by this session.",
                paths.join(", "),
                committed.change_id
            );
            report.change_id = Some(committed.change_id);
            report.tree_hash = Some(committed.tree_hash.to_string());
            report.carried_pending_files = committed.carried_pending_files;
        }
        Err(error) => {
            report.state = WriteBackState::AdmittedNotCommitted;
            report.note = format!(
                "{} admitted into the workspace, and recording them as a change failed: \
                 {error:#}. The next kin_mutate commit publishes them and names them as carried.",
                paths.join(", ")
            );
        }
    }
    report
}

/// The change subject a run records when the call named none: the command and
/// the files it kept.
fn default_message(argv: &[String], paths: &[String]) -> String {
    let mut command = argv.join(" ");
    if command.chars().count() > 120 {
        command = command.chars().take(117).collect::<String>() + "...";
    }
    let mut named = paths.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
    if paths.len() > 5 {
        named.push_str(&format!(", and {} more", paths.len() - 5));
    }
    format!("{command}: update {named}")
}

/// The state a workspace was materialized from, read from the base record
/// the daemon installed beside it: the committed head, the exact tree and the
/// workspace generation. `None` when the record cannot be read, which the
/// answer reports as unknown rather than guessing.
fn ran_on(root: &Path) -> Option<RanOn> {
    let bytes = std::fs::read(root.join(".kin-session").join("base.json")).ok()?;
    let base: SessionWorkspaceBase = serde_json::from_slice(&bytes).ok()?;
    ran_on_from(&base)
}

fn ran_on_from(base: &SessionWorkspaceBase) -> Option<RanOn> {
    let workspace = &base.source_workspace;
    let change_id = match &workspace.base_target {
        None => None,
        Some(kin_model::RefTarget::Change { change_id }) => Some(change_id.to_string()),
        // A head on an imported object or a symbolic chain is not a change
        // this answer can name, and saying nothing beats naming the wrong one.
        Some(_) => return None,
    };
    let change_tree_hash = workspace.base_tree_hash.map(|hash| hash.to_string());
    Some(RanOn {
        change_id,
        tree_hash: workspace.tree_hash.to_string(),
        workspace_generation: workspace.generation,
        uncommitted: match workspace.base_tree_hash {
            Some(base) => base != workspace.tree_hash,
            None => workspace.tree.len() > 0,
        },
        change_tree_hash,
    })
}

fn toolchain_of(language: Language) -> Toolchain {
    match language {
        Language::Go => Toolchain::Go,
        Language::Node => Toolchain::Node,
        Language::Python => Toolchain::Python,
        Language::Rust => Toolchain::Rust,
    }
}

fn path_text(path: &ReconcilePath) -> String {
    match path {
        ReconcilePath::Utf8(path) => path.clone(),
        ReconcilePath::Hex(hex) => format!("hex:{hex}"),
    }
}

fn change_kind(kind: ReconcileChangeKind) -> &'static str {
    match kind {
        ReconcileChangeKind::Added => "added",
        ReconcileChangeKind::Modified => "modified",
        ReconcileChangeKind::Removed => "removed",
    }
}

/// What the workspace's names say about the project.
#[derive(Debug, Default, PartialEq, Eq)]
struct Project {
    languages: BTreeSet<Language>,
    python_modules: BTreeSet<String>,
}

/// The most directory entries [`detect_project`] reads.
const DETECT_ENTRY_BUDGET: usize = 4_096;

/// Tell which toolchains a workspace uses from its names alone: manifests and
/// source extensions at the top and one directory down, and the project's own
/// top-level Python modules. No file is opened.
fn detect_project(root: &Path) -> Project {
    let mut project = Project::default();
    let mut budget = DETECT_ENTRY_BUDGET;
    let top = listed(root, &mut budget);
    for (name, is_dir) in &top {
        if *is_dir {
            if skipped_directory(name) {
                continue;
            }
            let child = root.join(name);
            let entries = listed(&child, &mut budget);
            if name == "src" {
                note_python_modules(&child, &entries, &mut project);
            }
            if entries
                .iter()
                .any(|(entry, _)| entry == "__init__.py" || entry == "__main__.py")
                && is_identifier(name)
            {
                project.python_modules.insert(name.clone());
            }
            for (entry, entry_is_dir) in &entries {
                if !entry_is_dir {
                    note_language(entry, &mut project);
                }
            }
        } else {
            note_language(name, &mut project);
            if let Some(stem) = name.strip_suffix(".py").filter(|stem| is_identifier(stem)) {
                project.python_modules.insert(stem.to_string());
            }
        }
    }
    project
}

/// Python packages and modules directly under a `src` layout's directory.
fn note_python_modules(dir: &Path, entries: &[(String, bool)], project: &mut Project) {
    for (name, is_dir) in entries {
        if !is_identifier(name.trim_end_matches(".py")) {
            continue;
        }
        if !is_dir {
            if let Some(stem) = name.strip_suffix(".py") {
                project.python_modules.insert(stem.to_string());
            }
            continue;
        }
        let package = dir.join(name);
        if ["__init__.py", "__main__.py"]
            .iter()
            .any(|marker| package.join(marker).is_file())
        {
            project.python_modules.insert(name.clone());
        }
    }
}

fn note_language(name: &str, project: &mut Project) {
    let extension = name.rsplit_once('.').map(|(_, extension)| extension);
    let language = match (name, extension) {
        ("go.mod" | "go.work", _) | (_, Some("go")) => Language::Go,
        ("package.json", _) | (_, Some("js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx")) => {
            Language::Node
        }
        ("Cargo.toml", _) | (_, Some("rs")) => Language::Rust,
        ("pyproject.toml" | "setup.py" | "setup.cfg" | "requirements.txt" | "Pipfile", _)
        | (_, Some("py")) => Language::Python,
        _ => return,
    };
    project.languages.insert(language);
}

/// Hidden directories and generated ones say nothing about the project.
fn skipped_directory(name: &str) -> bool {
    name.starts_with('.') || crate::commands::write_back::is_generated_name(name.as_bytes())
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// A directory's entries as (name, is a directory), UTF-8 names only, sorted,
/// at most `budget` of them across every call.
fn listed(dir: &Path, budget: &mut usize) -> Vec<(String, bool)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut listed = Vec::new();
    for entry in entries.flatten() {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let is_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
        listed.push((name, is_dir));
    }
    listed.sort();
    listed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_project_is_read_from_its_names() {
        let root = tempfile::tempdir().unwrap();
        let empty = detect_project(root.path());
        assert!(empty.languages.is_empty());

        std::fs::write(root.path().join("main.go"), b"package main\n").unwrap();
        assert_eq!(
            detect_project(root.path()).languages,
            BTreeSet::from([Language::Go])
        );

        std::fs::write(root.path().join("package.json"), b"{}").unwrap();
        std::fs::create_dir_all(root.path().join("src/app")).unwrap();
        std::fs::write(root.path().join("src/app/__init__.py"), b"").unwrap();
        std::fs::create_dir_all(root.path().join("tools")).unwrap();
        std::fs::write(root.path().join("tools/build.rs"), b"fn main() {}\n").unwrap();
        std::fs::write(root.path().join("cli.py"), b"").unwrap();
        // A dependency tree says nothing about the project.
        std::fs::create_dir_all(root.path().join("node_modules/x")).unwrap();
        std::fs::write(root.path().join("node_modules/x/setup.py"), b"").unwrap();
        let project = detect_project(root.path());
        assert_eq!(
            project.languages,
            BTreeSet::from([
                Language::Go,
                Language::Node,
                Language::Python,
                Language::Rust
            ])
        );
        assert_eq!(
            project.python_modules,
            BTreeSet::from(["app".to_string(), "cli".to_string()])
        );
    }

    fn request(
        argv: &[&str],
        env: &[(&str, &str)],
        timeout: Duration,
        bound: usize,
    ) -> ExecRequest {
        ExecRequest {
            session_id: uuid::Uuid::new_v4().to_string(),
            argv: argv.iter().map(|word| word.to_string()).collect(),
            env: env
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
            timeout,
            max_output_bytes: bound,
            summary: None,
        }
    }

    /// A routed `exec` call with an application variable reaches the program
    /// exactly as sent, unexpanded, and the program's answer comes back.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_routed_exec_call_runs_a_program_with_its_environment() {
        let mut params: kin_mcp::ToolCallParams = serde_json::from_value(serde_json::json!({
            "name": kin_mcp::routed::TOOL_NAME,
            "arguments": {"command": "exec", "args": {
                "session_id": uuid::Uuid::new_v4().to_string(),
                "argv": ["printenv", "TASKS_FILE"],
                "env": {"TASKS_FILE": "$HOME/tasks.json"}
            }}
        }))
        .unwrap();
        let routed = kin_mcp::routed::route(
            &mut params,
            Some(kin_mcp::routed::RoutedSurface::WITH_WRITES),
        );
        assert!(
            matches!(routed, kin_mcp::routed::Routing::Dispatch),
            "{routed:?}"
        );
        assert_eq!(params.name, kin_mcp::session_exec::TOOL_NAME);
        let parsed = kin_mcp::session_exec::parse_request(&params.arguments).unwrap();
        let root = tempfile::tempdir().unwrap();
        let ran = run_command(&parsed, root.path()).await.unwrap();
        assert_eq!(ran.exit_code, Some(0));
        assert_eq!(ran.stdout.text, "$HOME/tasks.json\n");
        assert!(!ran.timed_out);
    }

    /// The timeout stops the command and everything it started, and the
    /// answer says it was stopped rather than reporting an exit code.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_command_past_its_timeout_is_stopped_with_its_whole_group() {
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("survived");
        let script = format!("(sleep 3; touch {}) & sleep 60", marker.display());
        let started = Instant::now();
        let ran = run_command(
            &request(
                &["sh", "-c", &script],
                &[],
                Duration::from_millis(500),
                1024,
            ),
            root.path(),
        )
        .await
        .unwrap();
        assert!(ran.timed_out);
        assert_eq!(ran.exit_code, None);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(
            !marker.exists(),
            "a process the command started outlived its timeout"
        );
    }

    /// Output past the bound keeps both ends and says how much was cut.
    #[cfg(unix)]
    #[tokio::test]
    async fn output_past_the_bound_is_cut_and_disclosed() {
        let root = tempfile::tempdir().unwrap();
        let ran = run_command(
            &request(
                &["sh", "-c", "i=0; while [ $i -lt 2000 ]; do echo line-$i; i=$((i+1)); done; echo tail-end >&2"],
                &[],
                Duration::from_secs(20),
                256,
            ),
            root.path(),
        )
        .await
        .unwrap();
        assert_eq!(ran.exit_code, Some(0));
        assert!(ran.stdout.omitted_bytes > 0);
        assert!(ran.stdout.total_bytes > 10_000);
        assert!(ran.stdout.text.starts_with("line-0\n"));
        assert!(
            ran.stdout.text.ends_with("line-1999\n"),
            "{}",
            ran.stdout.text
        );
        assert!(ran.stdout.text.contains("bytes omitted by Kin"));
        assert_eq!(ran.stderr.text, "tail-end\n");
    }

    /// `go version` and a read-only `go env` are admitted in a Go project and
    /// run there, and neither writes a byte into the workspace, so a run of
    /// either has nothing for write-back to hand back. Needs a Go toolchain
    /// on PATH, and says so when there is none.
    #[cfg(unix)]
    #[tokio::test]
    async fn go_version_and_go_env_run_and_write_nothing_into_the_workspace() {
        if std::process::Command::new("go")
            .arg("version")
            .output()
            .is_err()
        {
            eprintln!("skipped: no go toolchain on PATH");
            return;
        }
        fn contents(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
            let mut found = Vec::new();
            let mut pending = vec![root.to_path_buf()];
            while let Some(dir) = pending.pop() {
                for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        pending.push(path);
                    } else {
                        let bytes = std::fs::read(&path).unwrap();
                        found.push((path.strip_prefix(root).unwrap().to_path_buf(), bytes));
                    }
                }
            }
            found.sort();
            found
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("main.go"),
            b"package main\n\nfunc main() {}\n",
        )
        .unwrap();
        let policy = CommandPolicy {
            languages: detect_project(root.path()).languages.into_iter().collect(),
            ..CommandPolicy::default()
        };
        assert_eq!(policy.languages, vec![Language::Go]);
        let before = contents(root.path());
        for argv in [
            &["go", "version"][..],
            &["go", "env"],
            &["go", "env", "GOPATH", "GOFLAGS"],
            &["go", "env", "-json", "GOVERSION"],
        ] {
            let request = request(argv, &[], Duration::from_secs(60), 16_000);
            kin_mcp::session_exec::admit(&request.argv, &policy)
                .unwrap_or_else(|refusal| panic!("{argv:?}: {}", refusal.reason));
            let ran = run_command(&request, root.path()).await.unwrap();
            assert_eq!(ran.exit_code, Some(0), "{argv:?}: {}", ran.stderr.text);
            match argv {
                ["go", "version"] => {
                    assert!(
                        ran.stdout.text.starts_with("go version go"),
                        "{}",
                        ran.stdout.text
                    )
                }
                ["go", "env", "-json", ..] => {
                    let values: serde_json::Value = serde_json::from_str(&ran.stdout.text).unwrap();
                    assert!(values["GOVERSION"].is_string(), "{values}");
                }
                ["go", "env", "GOPATH", "GOFLAGS"] => {
                    assert_eq!(ran.stdout.text.lines().count(), 2, "{}", ran.stdout.text)
                }
                _ => assert!(
                    ran.stdout.text.contains("GOVERSION="),
                    "{}",
                    ran.stdout.text
                ),
            }
        }
        assert_eq!(contents(root.path()), before);
        for argv in [&["go", "env", "-w", "X=1"][..], &["go", "env", "-u", "X"]] {
            let words: Vec<String> = argv.iter().map(|word| word.to_string()).collect();
            let refusal = kin_mcp::session_exec::admit(&words, &policy).unwrap_err();
            assert_eq!(
                refusal.kind,
                kin_mcp::session_exec::RefusalKind::RefusedFlag,
                "{argv:?}"
            );
        }
    }

    /// A small Go module the way an agent leaves one: a committed go.mod, a
    /// main package of two files and an internal package.
    #[cfg(unix)]
    fn go_module_workspace() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let write = |path: &str, text: &str| {
            let path = root.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write("go.mod", "module example.com/app\n\ngo 1.21\n");
        write(
            "main.go",
            "package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n\nfunc main() {\n\tfmt.Println(\"app ran with\", os.Args[1:], helper())\n}\n",
        );
        write(
            "helper.go",
            "package main\n\nfunc helper() int { return 42 }\n",
        );
        write(
            "internal/store/store.go",
            "package store\n\n// Secret is committed source an agent reads by entity.\nconst Secret = \"store-source-text\"\n",
        );
        write(
            "cmd/tool/main.go",
            "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"tool ran\") }\n",
        );
        root
    }

    #[cfg(unix)]
    fn have_go() -> bool {
        std::process::Command::new("go")
            .arg("version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    /// Admit `argv` in the workspace at `root` the way a call is admitted,
    /// with `allow` as the repository's configured prefixes.
    fn admit_in(
        root: &Path,
        argv: &[&str],
        allow: &[&str],
        env: &agent_exec_go::GoEnvironment,
    ) -> Result<(), CommandRefusal> {
        let configured = kin_core::AgentExecConfig {
            allow: allow.iter().map(|prefix| prefix.to_string()).collect(),
            ..kin_core::AgentExecConfig::default()
        };
        let argv: Vec<String> = argv.iter().map(|word| word.to_string()).collect();
        admission(&argv, root, &configured, env).1
    }

    /// Every prefix a repository could configure to reach a Go target.
    const GO_PREFIXES: &[&str] = &["go", "go run", "go test", "go build", "go vet"];

    /// The observed whole-file read, `go run cmd/gofmt main.go
    /// internal/store/store.go`, is refused before anything runs in a Go
    /// module, as are the other routes to a program outside the repository,
    /// whatever prefix the repository configures, and no refusal carries the
    /// files' text. Needs a Go toolchain on PATH, and says so when there is
    /// none.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_go_target_outside_the_repository_is_refused_in_a_real_module() {
        if !have_go() {
            eprintln!("skipped: no go toolchain on PATH");
            return;
        }
        let root = go_module_workspace();
        let env = agent_exec_go::GoEnvironment::default();
        let mut leaked = Vec::new();
        for argv in [
            &[
                "go",
                "run",
                "cmd/gofmt",
                "main.go",
                "internal/store/store.go",
            ][..],
            &["go", "run", "cmd/gofmt", "-l", "-d", "."],
            &["go", "run", "--", "cmd/gofmt", "internal/store/store.go"],
            &[
                "go",
                "run",
                "-tags",
                "x",
                "cmd/gofmt",
                "internal/store/store.go",
            ],
            &["go", "-C", "internal", "run", "cmd/gofmt", "store/store.go"],
            &["go", "run", "internal/store/store.go"],
            &["go", "run", "main.go", "/etc/passwd"],
            &["go", "run", "golang.org/x/tools/cmd/stringer@latest"],
            &["go", "test", "cmd/gofmt"],
            &["go", "vet", "std"],
            &["go", "build", "cmd/..."],
            &["go", "build", "golang.org/x/..."],
        ] {
            for allow in [&[][..], GO_PREFIXES] {
                let refusal = match admit_in(root.path(), argv, allow, &env) {
                    Err(refusal) => refusal,
                    Ok(()) => {
                        let request = request(argv, &[], Duration::from_secs(120), 16_000);
                        let ran = run_command(&request, root.path()).await.unwrap();
                        leaked.push(format!(
                            "{argv:?} admitted; exit {:?}, {} stdout bytes, store source in \
                             stdout: {}",
                            ran.exit_code,
                            ran.stdout.total_bytes,
                            ran.stdout.text.contains("store-source-text")
                        ));
                        continue;
                    }
                };
                assert!(!refusal.kind.configurable(), "{argv:?}");
                assert!(
                    !refusal.reason.contains("store-source-text")
                        && !refusal.reason.contains("package store"),
                    "{argv:?}: {}",
                    refusal.reason
                );
            }
        }
        assert!(leaked.is_empty(), "{leaked:#?}");
    }

    /// The repository's own applications still run: by directory, by the
    /// module's import path, by the files of its main package, and through a
    /// pattern that matches one main package, with the program's own words
    /// after the target; and its packages build, test and vet. A go command
    /// runs with GOWORK pinned to the repository's go.work or off.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_repository_s_own_go_packages_still_run() {
        if !have_go() {
            eprintln!("skipped: no go toolchain on PATH");
            return;
        }
        let root = go_module_workspace();
        let env = agent_exec_go::GoEnvironment::default();
        for (argv, stdout) in [
            (
                &["go", "run", ".", "add", "milk"][..],
                "app ran with [add milk] 42",
            ),
            (
                &["go", "run", ".", "-exec", "user-arg"],
                "app ran with [-exec user-arg] 42",
            ),
            (
                &["go", "run", "main.go", "helper.go", "list"],
                "app ran with [list] 42",
            ),
            (&["go", "run", "./cmd/tool"], "tool ran"),
            (&["go", "run", "./cmd/..."], "tool ran"),
            (&["go", "run", "example.com/app/cmd/tool"], "tool ran"),
            (&["go", "-C", "cmd", "run", "./tool"], "tool ran"),
            (&["go", "test", "./..."], ""),
            (&["go", "vet", "./..."], ""),
            (&["go", "build", "./..."], ""),
            (&["go", "build", "example.com/app/..."], ""),
            (&["go", "env", "GOWORK"], "off"),
        ] {
            for allow in [&[][..], GO_PREFIXES] {
                admit_in(root.path(), argv, allow, &env)
                    .unwrap_or_else(|refusal| panic!("{argv:?}: {}", refusal.reason));
            }
            let request = request(argv, &[], Duration::from_secs(120), 16_000);
            let ran = run_command(&request, root.path()).await.unwrap();
            assert_eq!(ran.exit_code, Some(0), "{argv:?}: {}", ran.stderr.text);
            assert!(
                ran.stdout.text.contains(stdout),
                "{argv:?}: {}",
                ran.stdout.text
            );
        }
        std::fs::write(root.path().join("go.work"), "go 1.21\n\nuse .\n").unwrap();
        let ran = run_command(
            &request(
                &["go", "env", "GOWORK"],
                &[],
                Duration::from_secs(60),
                4_000,
            ),
            root.path(),
        )
        .await
        .unwrap();
        assert_eq!(
            ran.stdout.text.trim(),
            root.path().join("go.work").display().to_string()
        );
        admit_in(
            root.path(),
            &["go", "run", "example.com/app/cmd/tool"],
            &[],
            &env,
        )
        .unwrap();
        std::fs::remove_file(root.path().join("go.work")).unwrap();

        // A pattern that matches two main packages names them, and runs
        // neither.
        std::fs::create_dir_all(root.path().join("cmd/other")).unwrap();
        std::fs::write(
            root.path().join("cmd/other/main.go"),
            "package main\n\nfunc main() {}\n",
        )
        .unwrap();
        let refusal = admit_in(root.path(), &["go", "run", "./cmd/..."], &[], &env).unwrap_err();
        assert!(
            refusal.reason.contains("./cmd/other") && refusal.reason.contains("./cmd/tool"),
            "{}",
            refusal.reason
        );
    }

    /// A module named for the toolchain's own tree is never read as the
    /// toolchain's: its import path is refused, and by path Go runs only the
    /// repository's code or refuses the ambiguity itself.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_module_named_like_a_toolchain_path_never_reaches_the_toolchain() {
        if !have_go() {
            eprintln!("skipped: no go toolchain on PATH");
            return;
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("go.mod"), "module cmd\n\ngo 1.21\n").unwrap();
        std::fs::create_dir_all(root.path().join("gofmt")).unwrap();
        std::fs::write(
            root.path().join("gofmt/main.go"),
            "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"mine\") }\n",
        )
        .unwrap();
        std::fs::write(root.path().join("secret.go"), "package secret\n").unwrap();
        let env = agent_exec_go::GoEnvironment::default();
        let refusal = admit_in(
            root.path(),
            &["go", "run", "cmd/gofmt", "-l", "."],
            &[],
            &env,
        )
        .unwrap_err();
        assert_eq!(
            refusal.kind,
            kin_mcp::session_exec::RefusalKind::PackageOutsideRepository
        );
        let argv = ["go", "run", "./gofmt", "-d", "secret.go"];
        admit_in(root.path(), &argv, &[], &env).unwrap();
        let ran = run_command(
            &request(&argv, &[], Duration::from_secs(120), 16_000),
            root.path(),
        )
        .await
        .unwrap();
        assert!(
            !ran.stdout.text.contains("package secret"),
            "{}",
            ran.stdout.text
        );
    }

    /// What decides who owns a target is read from the workspace and the
    /// inherited Go settings, statically: an inherited GOFLAGS that swaps the
    /// go.mod or overlays files, modules turned off, a go.work that uses a
    /// directory outside the workspace, a replaced or required module under
    /// the main module's path, a nested module, a symbolic link out of the
    /// workspace, and a workspace with no go.mod.
    /// The Go environment file is read the way cmd/go reads it: whole,
    /// through symbolic links, the last line for a key winning, keys and
    /// values untrimmed. A file larger than exec reads is refused, not cut.
    #[cfg(unix)]
    #[test]
    fn the_go_environment_file_is_read_the_way_go_reads_it() {
        use kin_mcp::session_exec::RefusalKind;
        let root = go_module_workspace();
        let settings = tempfile::tempdir().unwrap();
        let env_from = |path: &Path| {
            let path = path.display().to_string();
            agent_exec_go::GoEnvironment::read(move |name| (name == "GOENV").then(|| path.clone()))
        };
        let verdict = |env: &agent_exec_go::GoEnvironment| {
            admit_in(root.path(), &["go", "build", "./..."], &[], env)
                .map_err(|refusal| refusal.kind)
        };
        let dangerous = "GOFLAGS=-toolexec=/bin/cat\n";

        // A symbolic link to the file is followed, as os.ReadFile follows it.
        let real = settings.path().join("real-env");
        std::fs::write(&real, dangerous).unwrap();
        let link = settings.path().join("linked-env");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(
            verdict(&env_from(&link)),
            Err(RefusalKind::RefusedEnvironment)
        );

        // The last line for a key wins.
        let file = settings.path().join("env");
        std::fs::write(&file, format!("GOFLAGS=-mod=mod\n{dangerous}")).unwrap();
        assert_eq!(
            verdict(&env_from(&file)),
            Err(RefusalKind::RefusedEnvironment)
        );
        std::fs::write(&file, format!("{dangerous}GOFLAGS=-mod=mod\n")).unwrap();
        assert_eq!(verdict(&env_from(&file)), Ok(()));
        // An empty last value sets nothing.
        std::fs::write(&file, format!("{dangerous}GOFLAGS=\n")).unwrap();
        assert_eq!(verdict(&env_from(&file)), Ok(()));
        // Keys are exact: a leading space or a space before '=' is not GOFLAGS.
        std::fs::write(
            &file,
            " GOFLAGS=-toolexec=/bin/cat\nGOFLAGS =-toolexec=/bin/cat\n",
        )
        .unwrap();
        assert_eq!(verdict(&env_from(&file)), Ok(()));

        // A setting past what exec reads is never cut off and missed.
        let mut big = "# padding\n".repeat(120_000);
        big.push_str(dangerous);
        std::fs::write(&file, big).unwrap();
        let refusal = admit_in(
            root.path(),
            &["go", "build", "./..."],
            &[],
            &env_from(&file),
        )
        .unwrap_err();
        assert_eq!(refusal.kind, RefusalKind::RefusedEnvironment);
        assert!(refusal.reason.contains("bytes"), "{}", refusal.reason);

        // A file Go cannot read, such as a directory, is ignored as Go ignores it.
        assert_eq!(verdict(&env_from(settings.path())), Ok(()));
    }

    /// An import-path target must name a package the repository's module
    /// holds: a missing or package-less directory under the module's path
    /// could be resolved by Go from another module.
    #[cfg(unix)]
    #[test]
    fn an_import_path_target_needs_a_package_in_the_repository() {
        use kin_mcp::session_exec::RefusalKind;
        let root = go_module_workspace();
        let plain = agent_exec_go::GoEnvironment::default();
        std::fs::create_dir_all(root.path().join("empty")).unwrap();
        for argv in [
            &["go", "run", "-mod=mod", "example.com/app/missing"][..],
            &["go", "run", "example.com/app/missing"],
            &["go", "build", "example.com/app/missing"],
            &["go", "test", "example.com/app/empty"],
            &["go", "vet", "-mod=mod", "example.com/app/missing"],
        ] {
            assert_eq!(
                admit_in(root.path(), argv, &[], &plain).map_err(|refusal| refusal.kind),
                Err(RefusalKind::PackageOutsideRepository),
                "{argv:?}"
            );
        }
        for argv in [
            &["go", "run", "example.com/app/cmd/tool"][..],
            &["go", "build", "example.com/app/internal/store"],
            &["go", "test", "example.com/app/..."],
            &["go", "run", "./missing"],
        ] {
            admit_in(root.path(), argv, &[], &plain)
                .unwrap_or_else(|refusal| panic!("{argv:?} was refused: {}", refusal.reason));
        }
    }

    #[cfg(unix)]
    #[test]
    fn go_target_ownership_is_read_from_the_workspace_and_inherited_settings() {
        use kin_mcp::session_exec::RefusalKind;
        let refused = |root: &Path, argv: &[&str], env: &agent_exec_go::GoEnvironment| {
            admit_in(root, argv, &[], env)
                .map(|()| panic!("{argv:?} was admitted"))
                .unwrap_err()
                .kind
        };
        let plain = agent_exec_go::GoEnvironment::default();

        // Inherited GOFLAGS, from the environment or the Go environment file.
        let root = go_module_workspace();
        let from_env = agent_exec_go::GoEnvironment::read(|name| {
            (name == "GOFLAGS").then(|| "-mod=mod -modfile=/elsewhere/go.mod".to_string())
        });
        for argv in [&["go", "run", "."][..], &["go", "build", "./..."]] {
            assert_eq!(
                refused(root.path(), argv, &from_env),
                RefusalKind::RefusedEnvironment
            );
        }
        admit_in(root.path(), &["go", "mod", "tidy"], &[], &from_env).unwrap();
        let settings = tempfile::tempdir().unwrap();
        let file = settings.path().join("env");
        std::fs::write(&file, "GOFLAGS=-overlay=/tmp/overlay.json\n").unwrap();
        let path = file.display().to_string();
        let from_file =
            agent_exec_go::GoEnvironment::read(|name| (name == "GOENV").then(|| path.clone()));
        let refusal = admit_in(root.path(), &["go", "test", "./..."], &[], &from_file).unwrap_err();
        assert_eq!(refusal.kind, RefusalKind::RefusedEnvironment);
        assert!(
            refusal.reason.contains("Go environment file"),
            "{}",
            refusal.reason
        );
        // The environment wins over the file, as it does for Go.
        let both = agent_exec_go::GoEnvironment::read(|name| match name {
            "GOENV" => Some(path.clone()),
            "GOFLAGS" => Some("-mod=mod".to_string()),
            _ => None,
        });
        admit_in(root.path(), &["go", "test", "./..."], &[], &both).unwrap();
        std::fs::write(&file, "GO111MODULE=off\n").unwrap();
        let modules_off =
            agent_exec_go::GoEnvironment::read(|name| (name == "GOENV").then(|| path.clone()));
        assert_eq!(
            refused(
                root.path(),
                &["go", "run", "example.com/app/cmd/tool"],
                &modules_off
            ),
            RefusalKind::PackageOutsideRepository
        );
        admit_in(root.path(), &["go", "run", "./cmd/tool"], &[], &modules_off).unwrap();

        // A go.work that uses a directory outside the workspace.
        std::fs::write(
            root.path().join("go.work"),
            "go 1.21\n\nuse (\n\t.\n\t../outside\n)\n",
        )
        .unwrap();
        assert_eq!(
            refused(
                root.path(),
                &["go", "run", "example.com/app/cmd/tool"],
                &plain
            ),
            RefusalKind::PackageOutsideRepository
        );
        admit_in(root.path(), &["go", "run", "./cmd/tool"], &[], &plain).unwrap();
        std::fs::remove_file(root.path().join("go.work")).unwrap();

        // A module required and replaced from outside, under the main
        // module's own path.
        std::fs::write(
            root.path().join("go.mod"),
            "module example.com/app\n\ngo 1.21\n\nrequire example.com/app/tools v0.0.0\n\nreplace example.com/app/tools => ../tools\n",
        )
        .unwrap();
        for argv in [
            &["go", "run", "example.com/app/tools/cmd/gen"][..],
            &["go", "build", "example.com/app/..."],
        ] {
            assert_eq!(
                refused(root.path(), argv, &plain),
                RefusalKind::PackageOutsideRepository,
                "{argv:?}"
            );
        }
        admit_in(
            root.path(),
            &["go", "run", "example.com/app/cmd/tool"],
            &[],
            &plain,
        )
        .unwrap();

        // A nested module of its own.
        std::fs::create_dir_all(root.path().join("nested")).unwrap();
        std::fs::write(
            root.path().join("nested/go.mod"),
            "module example.com/nested\n\ngo 1.21\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("nested/main.go"),
            "package main\n\nfunc main() {}\n",
        )
        .unwrap();
        for argv in [
            &["go", "run", "./nested"][..],
            &["go", "run", "nested/main.go"],
            &["go", "build", "./nested/..."],
            &["go", "-C", "nested", "run", "."],
        ] {
            assert_eq!(
                refused(root.path(), argv, &plain),
                RefusalKind::PackageOutsideRepository,
                "{argv:?}"
            );
        }
        // And `./...` never descends into it, as Go's does not.
        admit_in(root.path(), &["go", "run", "./cmd/..."], &[], &plain).unwrap();

        // A symbolic link out of the workspace.
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join("main.go"),
            "package main\n\nfunc main() {}\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("main.go"), root.path().join("evil.go"))
            .unwrap();
        for argv in [
            &["go", "run", "./link"][..],
            &["go", "run", "evil.go"],
            &["go", "build", "./link/..."],
            &["go", "run", "-C", "link", "."],
            &["go", "-C", "link", "build"],
            &["go", "run", "example.com/app/link"],
        ] {
            assert_eq!(
                refused(root.path(), argv, &plain),
                RefusalKind::PathOutsideWorkspace,
                "{argv:?}"
            );
        }

        // A workspace with no go.mod has no module to run.
        let bare = tempfile::tempdir().unwrap();
        std::fs::write(
            bare.path().join("main.go"),
            "package main\n\nfunc main() {}\n",
        )
        .unwrap();
        let refusal = admit_in(bare.path(), &["go", "run", "main.go"], &[], &plain).unwrap_err();
        assert!(refusal.reason.contains("go mod init"), "{}", refusal.reason);
    }

    /// `ran_on` is read from the base record the materialization installed,
    /// so it names exactly the authority state the workspace came from: on a
    /// fresh repository, no change yet and the workspace's own tree and
    /// generation.
    #[cfg(unix)]
    #[test]
    fn ran_on_names_the_state_the_workspace_was_materialized_from() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout).unwrap();
        let session = layout.runs_dir().join("session-ran-on");
        crate::commands::session_workspace::materialize_session_workspace(
            &layout,
            &binding,
            &crate::commands::session_workspace::SessionWorkspaceRequest {
                session_dir: session.display().to_string(),
                strategy: None,
                scope: None,
            },
        )
        .unwrap();
        let base: SessionWorkspaceBase =
            serde_json::from_slice(&std::fs::read(session.join(".kin-session/base.json")).unwrap())
                .unwrap();
        let ran_on = ran_on(&session).expect("a readable base record");
        assert_eq!(ran_on, ran_on_from(&base).unwrap());
        assert_eq!(
            ran_on.change_id, None,
            "a fresh repository has no change yet"
        );
        assert_eq!(
            ran_on.tree_hash,
            base.source_workspace.tree_hash.to_string()
        );
        assert_eq!(
            ran_on.workspace_generation,
            base.source_workspace.generation
        );
        // A command that rewrites the record after it starts cannot change
        // what the answer already read.
        std::fs::write(session.join(".kin-session/base.json"), b"{}").unwrap();
        assert!(ran_on_from(&base).is_some());
        assert!(super::ran_on(&session).is_none());
    }

    #[test]
    fn the_default_change_message_names_the_command_and_its_files() {
        let words =
            |text: &str| -> Vec<String> { text.split_whitespace().map(str::to_string).collect() };
        assert_eq!(
            default_message(&words("go mod tidy"), &words("go.mod go.sum")),
            "go mod tidy: update go.mod, go.sum"
        );
        let many = (0..7).map(|index| format!("f{index}")).collect::<Vec<_>>();
        assert!(default_message(&words("npm install"), &many).ends_with("f4, and 2 more"));
    }
}
