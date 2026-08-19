// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Machine-readable first-run health engine.
//!
//! [`run_health_checks`] probes the real filesystem, daemon, and agent
//! configuration and returns a [`HealthReport`]. It is the single source of
//! truth behind `kin setup status [--json]` and `kin doctor [--fix]`.

use std::env;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::commands::auth::default_base_url_for_health;
use crate::commands::setup::{
    check_binary_in_path, configured_mcp_launcher, detect_shell, detected_ai_client_names,
    home_dir, hook_filename, kin_dir, shell_rc, shim_filename, CANONICAL_NPM_MCP_COMMAND,
    CANONICAL_NPM_MCP_PACKAGE,
};
use crate::daemon_client::{InstalledStartupProtocol, SupervisorStartupSentinel};

/// Outcome of a single probed health check.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Missing,
    Stale,
    Misconfigured,
    /// Expected first-run work a correct install is still doing. It counts as
    /// needing attention, because the surface is not answering at full strength
    /// yet, but it never blocks readiness: nothing is wrong and nothing is lost.
    Pending,
    Unsupported,
}

/// A single probed health check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthCheck {
    pub id: String,
    pub label: String,
    pub status: HealthStatus,
    pub detail: String,
    pub platform_note: Option<String>,
    pub fixable: bool,
    pub manual_fix: Option<String>,
}

/// Aggregated report across every health check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthReport {
    pub platform: String,
    pub checks: Vec<HealthCheck>,
    pub healthy: bool,
}

impl HealthCheck {
    fn new(id: &str, label: &str, status: HealthStatus, detail: impl Into<String>) -> Self {
        Self {
            id: id.to_string(),
            label: label.to_string(),
            status,
            detail: detail.into(),
            platform_note: None,
            fixable: false,
            manual_fix: None,
        }
    }

    fn with_platform_note(mut self, note: impl Into<String>) -> Self {
        self.platform_note = Some(note.into());
        self
    }

    fn fixable(mut self) -> Self {
        self.fixable = true;
        self
    }

    fn with_manual_fix(mut self, fix: impl Into<String>) -> Self {
        self.manual_fix = Some(fix.into());
        self
    }
}

fn is_failing(status: &HealthStatus) -> bool {
    matches!(status, HealthStatus::Missing | HealthStatus::Misconfigured)
}

/// Whether a check prevents the aggregate report from claiming readiness.
///
/// Most `Stale` checks describe recoverable local drift and remain advisory,
/// but semantic readiness is an authority gate: if daemon graph coverage is
/// stale or cannot be read, the report cannot honestly claim the semantic
/// query surface is ready.
///
/// `Pending` sits deliberately outside that gate. It names work a correct
/// install is expected to be doing on its way to ready, not ground a ready
/// install lost, and a gate that cannot tell those apart fails every fresh
/// install for succeeding.
fn blocks_readiness(check: &HealthCheck) -> bool {
    is_failing(&check.status)
        || (check.id == "semantic_query_readiness" && matches!(check.status, HealthStatus::Stale))
}

fn assemble_health_report(platform: String, checks: Vec<HealthCheck>) -> HealthReport {
    let healthy = !checks.iter().any(blocks_readiness);
    HealthReport {
        platform,
        checks,
        healthy,
    }
}

/// A pass/attention/skip tally over a set of checks, used for the one-line
/// readiness summary printed by `kin doctor` and `kin setup status`.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct HealthSummary {
    /// Checks that are Healthy.
    pub passed: usize,
    /// Checks that need attention (Missing, Misconfigured, or Stale).
    pub attention: usize,
    /// Checks that do not apply on this platform / context (Unsupported).
    pub skipped: usize,
}

impl HealthReport {
    /// Tally checks into pass / needs-attention / not-applicable buckets.
    pub fn summary(&self) -> HealthSummary {
        let mut summary = HealthSummary {
            passed: 0,
            attention: 0,
            skipped: 0,
        };
        for check in &self.checks {
            match check.status {
                HealthStatus::Healthy => summary.passed += 1,
                HealthStatus::Unsupported => summary.skipped += 1,
                HealthStatus::Missing
                | HealthStatus::Misconfigured
                | HealthStatus::Stale
                | HealthStatus::Pending => summary.attention += 1,
            }
        }
        summary
    }
}

/// Run every health check and assemble the report.
///
/// This is the single source of truth consumed by the CLI, editor, and
/// hosted UI. Every check reflects real probed state — nothing is assumed
/// healthy.
pub async fn run_health_checks() -> HealthReport {
    let mut checks = vec![
        check_kin_binary(),
        check_kin_daemon_binary(),
        check_supervisor_startup_protocol(),
        check_daemon_running().await,
        check_vfs_projection(),
        check_projection_mode(),
        check_repo_init(),
        check_session_runtime(),
        check_shell_path(),
        check_registry_authority(),
    ];
    checks.extend(check_mcp_clients());
    checks.push(check_setup_ledger());
    checks.push(check_editor());
    checks.push(check_kinlab_connect());
    checks.push(check_semantic_query_readiness().await);
    checks.push(check_reference_edge_coverage().await);
    checks.push(check_background_work().await);
    checks.push(check_embedding_model().await);
    checks.push(check_retrieval_profile());
    checks.push(check_update_policy());
    checks.push(check_binary_assessment_load());

    assemble_health_report(env::consts::OS.to_string(), checks)
}

/// Report the active update policy and where it came from.
///
/// Always healthy: every policy is a legitimate preference, and the check
/// exists so the doctor surface states which one governs this machine now
/// that the default installs unattended (FIR-2342). The inherited default and
/// a recorded choice are named apart, because only the first moves when the
/// shipped default changes.
fn check_update_policy() -> HealthCheck {
    let (policy, recorded) = crate::commands::update::active_update_policy_for_doctor();
    let name = crate::commands::update::policy_name(policy);
    let source = if recorded {
        "recorded in ~/.kin/update.toml"
    } else {
        "the default; no recorded choice"
    };
    HealthCheck::new(
        "update_policy",
        "Update policy",
        HealthStatus::Healthy,
        format!(
            "{name} ({source}); auto installs unattended through the gated executor. Change with \
             `kin update --set-policy auto|prompt|manual`."
        ),
    )
}

/// macOS assesses each never-before-seen binary on first launch. Cold cargo
/// builds mint thousands of fresh binaries, and concurrent cold builds can
/// saturate the assessment daemon; while it is wedged, every new process
/// launch on the machine stalls. Surface that state and the sanctioned
/// exemption instead of leaving the operator to debug random tool hangs.
#[cfg(target_os = "macos")]
fn check_binary_assessment_load() -> HealthCheck {
    match syspolicyd_cpu_percent() {
        None => HealthCheck::new(
            "binary_assessment_load",
            "Host binary assessment",
            HealthStatus::Healthy,
            "assessment daemon not observable; no saturation signal",
        ),
        Some(load) if load < 50.0 => HealthCheck::new(
            "binary_assessment_load",
            "Host binary assessment",
            HealthStatus::Healthy,
            format!("syspolicyd at {load:.0}% CPU"),
        ),
        Some(load) => HealthCheck::new(
            "binary_assessment_load",
            "Host binary assessment",
            HealthStatus::Stale,
            format!(
                "syspolicyd is at {load:.0}% CPU; launches of freshly built binaries will stall machine-wide until it drains"
            ),
        )
        .with_manual_fix(
            "pause concurrent cold builds, then enable your terminal and editor under System Settings, Privacy and Security, Developer Tools (sudo spctl developer-mode enable-terminal opens the pane) so locally built binaries skip assessment",
        ),
    }
}

#[cfg(not(target_os = "macos"))]
fn check_binary_assessment_load() -> HealthCheck {
    HealthCheck::new(
        "binary_assessment_load",
        "Host binary assessment",
        HealthStatus::Unsupported,
        "binary assessment saturation is a macOS behavior",
    )
}

#[cfg(target_os = "macos")]
fn syspolicyd_cpu_percent() -> Option<f32> {
    let pgrep = std::process::Command::new("/usr/bin/pgrep")
        .args(["-x", "syspolicyd"])
        .output()
        .ok()?;
    let pid = String::from_utf8_lossy(&pgrep.stdout)
        .lines()
        .next()?
        .trim()
        .to_string();
    if pid.is_empty() {
        return None;
    }
    let ps = std::process::Command::new("/bin/ps")
        .args(["-o", "pcpu=", "-p", &pid])
        .output()
        .ok()?;
    String::from_utf8_lossy(&ps.stdout)
        .trim()
        .parse::<f32>()
        .ok()
}

fn check_registry_authority() -> HealthCheck {
    use kin_core::registry::RegistryAuthorityState;

    let report = kin_core::registry::inspect_registry_authority();
    if report
        .checks
        .iter()
        .all(|check| check.state == RegistryAuthorityState::Unsupported)
    {
        return HealthCheck::new(
            "registry_authority",
            "Registry authority",
            HealthStatus::Unsupported,
            "Unix ownership and mode checks do not apply on this platform",
        );
    }
    if report.is_secure() {
        let secure = report
            .checks
            .iter()
            .filter(|check| check.state == RegistryAuthorityState::Secure)
            .count();
        let absent = report
            .checks
            .iter()
            .filter(|check| check.state == RegistryAuthorityState::Absent)
            .count();
        return HealthCheck::new(
            "registry_authority",
            "Registry authority",
            HealthStatus::Healthy,
            format!(
                "{secure} private authority file(s); {absent} not created yet; no contents read"
            ),
        );
    }

    let detail = report.failure_summary();
    if report.has_unsafe_object() {
        HealthCheck::new(
            "registry_authority",
            "Registry authority",
            HealthStatus::Misconfigured,
            detail,
        )
        .with_manual_fix(
            "inspect and move the unsafe object aside; Kin will not follow, overwrite, or auto-repair it",
        )
    } else {
        HealthCheck::new(
            "registry_authority",
            "Registry authority",
            HealthStatus::Misconfigured,
            detail,
        )
        .fixable()
        .with_manual_fix("run `kin doctor --fix` to authorize a permission-only 0600 repair")
    }
}

fn check_kin_binary() -> HealthCheck {
    let version = env!("CARGO_PKG_VERSION");
    match env::current_exe() {
        Ok(exe) => HealthCheck::new(
            "kin_binary",
            "kin binary",
            HealthStatus::Healthy,
            format!("v{version} ({})", exe.display()),
        ),
        Err(e) => HealthCheck::new(
            "kin_binary",
            "kin binary",
            HealthStatus::Missing,
            format!("could not resolve current executable: {e}"),
        ),
    }
}

/// Resolve the `kin-daemon` binary using the same search order as
/// `daemon_client::find_daemon_binary`: sibling of the current exe, the
/// cargo target dir (when running from `deps/`), then PATH.
fn resolve_daemon_binary() -> Option<PathBuf> {
    if let Ok(exe) = env::current_exe() {
        let sibling = exe.with_file_name("kin-daemon");
        if sibling.exists() {
            return Some(sibling);
        }
        if exe
            .parent()
            .and_then(|path| path.file_name())
            .is_some_and(|name| name == "deps")
        {
            if let Some(target_dir) = exe.parent().and_then(|path| path.parent()) {
                let target_sibling = target_dir.join("kin-daemon");
                if target_sibling.exists() {
                    return Some(target_sibling);
                }
            }
        }
    }
    check_binary_in_path("kin-daemon")
}

fn check_kin_daemon_binary() -> HealthCheck {
    match resolve_daemon_binary() {
        Some(path) => HealthCheck::new(
            "kin_daemon_binary",
            "kin-daemon binary",
            HealthStatus::Healthy,
            format!("found ({})", path.display()),
        ),
        None => HealthCheck::new(
            "kin_daemon_binary",
            "kin-daemon binary",
            HealthStatus::Missing,
            "not found beside the kin binary or on PATH",
        )
        .with_manual_fix("reinstall Kin so kin-daemon is installed alongside kin"),
    }
}

/// One installed kin other than the running binary, with its probed verdict on
/// the supervisor startup protocol.
#[derive(Debug, Clone)]
struct InstalledKin {
    path: PathBuf,
    protocol: InstalledStartupProtocol,
}

/// Report an installed kin that cannot start a supervisor against the on-disk
/// startup sentinel because it predates the current startup protocol.
///
/// This is the diagnosis a stuck operator never gets from the stuck binary
/// itself: a pre-v2 kin meeting the v2 sentinel sleeps to its startup deadline
/// and then blames lock contention. The running binary can see both halves, the
/// sentinel on disk and the other install's own protocol answer, so it is the
/// surface that can name binary age as the cause.
///
/// Severity follows one rule: a state blocks readiness exactly when it stops
/// the binary running this check from starting a supervisor. A pre-v2 *other*
/// install is `Stale`, because another install's age does not stop this one. The
/// two sentinel shapes `ensure_supervisor_startup_namespace` refuses on are
/// `Misconfigured`: a legacy marker file, and a symlink or reparse point the
/// protocol will not follow. Metadata that simply cannot be read proves nothing
/// either way and stays advisory.
fn supervisor_startup_protocol_check(
    sentinel: SupervisorStartupSentinel,
    sentinel_path: &Path,
    installed: &[InstalledKin],
) -> HealthCheck {
    let protocol = crate::daemon_client::supervisor_startup_protocol();
    let update = format!("update kin: {}", crate::daemon_client::KIN_INSTALL_COMMAND);
    let sentinel_path = sentinel_path.display();

    match sentinel {
        SupervisorStartupSentinel::LegacyMarker => HealthCheck::new(
            "supervisor_startup_protocol",
            "Supervisor protocol",
            HealthStatus::Misconfigured,
            format!(
                "{sentinel_path} is a protocol-v1 marker file, which only a kin older than \
                 startup protocol v{protocol} creates; this binary refuses to start a supervisor \
                 against it"
            ),
        )
        .with_manual_fix(update),
        SupervisorStartupSentinel::RefusedLink => HealthCheck::new(
            "supervisor_startup_protocol",
            "Supervisor protocol",
            HealthStatus::Misconfigured,
            format!(
                "{sentinel_path} is a symlink rather than a directory; startup protocol \
                 v{protocol} refuses to follow one, so this binary cannot start a supervisor at \
                 all while it is there"
            ),
        )
        .with_manual_fix(
            "remove the link at the supervisor startup sentinel path; kin recreates it as an \
             ordinary directory",
        ),
        SupervisorStartupSentinel::Unreadable => HealthCheck::new(
            "supervisor_startup_protocol",
            "Supervisor protocol",
            HealthStatus::Stale,
            format!("{sentinel_path} exists but its metadata could not be read"),
        )
        .with_manual_fix(
            "inspect the supervisor startup sentinel; it must be an ordinary directory",
        ),
        SupervisorStartupSentinel::Absent => HealthCheck::new(
            "supervisor_startup_protocol",
            "Supervisor protocol",
            HealthStatus::Healthy,
            format!("startup protocol v{protocol}; no sentinel written yet"),
        ),
        SupervisorStartupSentinel::ProtocolDirectory => {
            let outdated: Vec<String> = installed
                .iter()
                .filter_map(|kin| match &kin.protocol {
                    InstalledStartupProtocol::Predates(reason) => {
                        Some(format!("{} ({reason})", kin.path.display()))
                    }
                    InstalledStartupProtocol::Current
                    | InstalledStartupProtocol::Undetermined(_) => None,
                })
                .collect();
            if outdated.is_empty() {
                return HealthCheck::new(
                    "supervisor_startup_protocol",
                    "Supervisor protocol",
                    HealthStatus::Healthy,
                    format!("startup protocol v{protocol}; {sentinel_path} matches it"),
                );
            }
            let detail = outdated.join(", ");
            HealthCheck::new(
                "supervisor_startup_protocol",
                "Supervisor protocol",
                HealthStatus::Stale,
                format!(
                    "your installed kin predates the current supervisor protocol: {detail}. \
                     While {sentinel_path} exists, that binary cannot start a supervisor and \
                     waits out its full startup deadline in silence before reporting a lock \
                     timeout that names contention it is not hitting"
                ),
            )
            .with_manual_fix(update)
        }
    }
}

fn check_supervisor_startup_protocol() -> HealthCheck {
    let sentinel = crate::daemon_client::supervisor_startup_sentinel();
    let sentinel_path = crate::daemon_client::supervisor_startup_sentinel_path();
    // Enumerating and probing installs is boundary IO and belongs to
    // daemon_client. The probe is requested only in the state whose answer can
    // change the verdict, but that state is the steady one for every current
    // user, so this runs on essentially every invocation rather than rarely.
    // What keeps it acceptable is its bound, not its frequency: at most two
    // deduped candidates, each capped by the daemon probe timeout.
    //
    // Never under test. This runs inside the unit suite through
    // `run_health_checks`, where spawning the host's installed kin-daemon would
    // make a unit test depend on whatever is installed on the machine and add
    // subprocesses to a thousand-test parallel run. The verdict logic is
    // exercised directly against constructed inputs instead.
    let probe_installs =
        matches!(sentinel, SupervisorStartupSentinel::ProtocolDirectory) && !cfg!(test);
    let installed: Vec<InstalledKin> = if probe_installs {
        crate::daemon_client::installed_kin_startup_protocols()
            .into_iter()
            .map(|(path, protocol)| InstalledKin { path, protocol })
            .collect()
    } else {
        Vec::new()
    };
    supervisor_startup_protocol_check(sentinel, &sentinel_path, &installed)
}

/// Probe whether the daemon is actually *running* (reachable) for the current
/// repository — distinct from [`check_kin_daemon_binary`], which only confirms
/// the binary is installed.
///
/// Outside a Kin repository there is no repo-scoped daemon to probe, so this is
/// reported as Unsupported rather than a failure. Inside a repo, severity turns
/// on whether a daemon was ever published for it, which the endpoint record
/// answers: no record is the resting state every repository starts in and stays
/// in until a command needs a daemon, so it is skipped rather than flagged; a
/// record left behind by a daemon that is no longer reachable is a real
/// leftover and stays advisory.
async fn check_daemon_running() -> HealthCheck {
    let cwd = env::current_dir().unwrap_or_default();
    let layout = match kin_core::KinLayout::discover(&cwd) {
        Some(l) => l,
        None => {
            return HealthCheck::new(
                "daemon_running",
                "kin-daemon running",
                HealthStatus::Unsupported,
                "n/a — not in a Kin repository (the daemon is repo-scoped)",
            )
            .with_manual_fix(
                "cd into a Kin repository, then run any `kin` command to start its daemon",
            );
        }
    };

    let repo = layout.working_dir().display().to_string();
    match crate::daemon_client::resolve_daemon_url_if_running_async(&layout).await {
        Some(url) => HealthCheck::new(
            "daemon_running",
            "kin-daemon running",
            HealthStatus::Healthy,
            format!("daemon reachable for {repo} ({url})"),
        ),
        None => daemon_not_running_check_for(
            &repo,
            &crate::daemon_client::repo_daemon_pid_path(layout.root()),
        ),
    }
}

/// Build the `daemon_running` check for a repository with no reachable daemon.
///
/// The endpoint record is the discriminator, and it is written when a daemon
/// publishes itself and removed when one shuts down cleanly. Its absence means
/// no daemon was ever started here, which is what a repository looks like the
/// moment `kin init` finishes; reporting that as needing attention makes a
/// correct install read as a broken one. Its presence beside an unreachable
/// endpoint means a daemon did start and did not clean up after itself.
fn daemon_not_running_check_for(repo: &str, endpoint_record: &Path) -> HealthCheck {
    if endpoint_record.exists() {
        HealthCheck::new(
            "daemon_running",
            "kin-daemon running",
            HealthStatus::Stale,
            format!(
                "a daemon was started for {repo} but is no longer reachable; its endpoint record {} is still on disk",
                endpoint_record.display()
            ),
        )
        .fixable()
        .with_manual_fix("run any `kin` command in the repo to start a fresh daemon")
    } else {
        HealthCheck::new(
            "daemon_running",
            "kin-daemon running",
            HealthStatus::Unsupported,
            format!("no daemon started for {repo} yet — one starts on first use"),
        )
        .fixable()
        .with_manual_fix("run any `kin` command in the repo to auto-start the daemon")
    }
}

fn check_vfs_projection() -> HealthCheck {
    if cfg!(target_os = "windows") {
        return HealthCheck::new(
            "vfs_projection",
            "VFS projection",
            HealthStatus::Unsupported,
            "Windows projects through ProjFS rather than an injected shim; see the \
             Projection in force row",
        )
        .with_platform_note(
            "This row is about the shim, which Windows has no equivalent of: there is no \
             library the shell hook can inject. Windows projection is the Windows Projected \
             File System, and whether it is enabled and running here is reported by the \
             Projection in force row rather than guessed at by this one.",
        )
        .with_manual_fix(crate::commands::projection::PROJFS_ENABLE_COMMAND);
    }

    let kin_home = match kin_dir() {
        Ok(dir) => dir,
        Err(e) => {
            return HealthCheck::new(
                "vfs_projection",
                "VFS projection",
                HealthStatus::Missing,
                format!("could not resolve ~/.kin: {e}"),
            );
        }
    };
    let lib_path = kin_home.join("lib").join(shim_filename());
    let driver = resolve_vfs_driver(&vfs_driver_candidates(
        pinned_vfs_driver().as_deref(),
        &kin_home,
        env::current_exe().ok().as_deref(),
    ));

    vfs_projection_check_for_recorded(
        &lib_path,
        &driver,
        crate::commands::projection::recorded_mode(&kin_home),
    )
}

/// The install check, plus the one thing it cannot know on its own: whether
/// anyone asked for a projection here.
///
/// [`vfs_projection_check_for`] answers "is projection installed", and its
/// sanctioned outcome on a host that ships without it is a green n/a reading
/// "nothing is missing". That sentence is true only while nobody has chosen a
/// projection mode. Once a mode is recorded, the same machine state is a
/// configured projection that is not installed, and reporting it as nothing
/// missing is the same class of confident negative FIR-2394 removed from the
/// row above it.
fn vfs_projection_check_for_recorded(
    lib_path: &Path,
    driver: &VfsDriverState,
    recorded: Option<crate::commands::projection::ProjectionMode>,
) -> HealthCheck {
    let check = vfs_projection_check_for(lib_path, driver);
    let Some(mode) = recorded else {
        return check;
    };
    if !matches!(check.status, HealthStatus::Unsupported) {
        return check;
    }
    HealthCheck::new(
        "vfs_projection",
        "VFS projection",
        HealthStatus::Missing,
        format!(
            "projection mode {mode} is recorded in ~/.kin/config/setup.toml, but no kin-vfs \
             driver was found beside the kin binary, in ~/.kin/bin, or on PATH, and no shim is \
             installed at {}",
            lib_path.display()
        ),
    )
    .with_manual_fix(
        "reinstall kin to restore projection: curl -fsSL https://get.kinlab.dev/install | sh, or \
         run `kin vfs status` to see what this host can actually run",
    )
}

/// Name of the projection driver binary the installer places beside `kin`.
fn vfs_binary_filename() -> &'static str {
    if cfg!(target_os = "windows") {
        "kin-vfs.exe"
    } else {
        "kin-vfs"
    }
}

/// The environment variable that pins the projection driver.
///
/// It answers a step the docs otherwise have to ask for: a contributor who has
/// just built `kin-vfs` with a mount feature should be able to point Kin at
/// that binary without reordering PATH ahead of the installed one.
pub(crate) const VFS_DRIVER_ENV: &str = "KIN_VFS_BIN";

/// The pinned driver, when one is named. An empty value is not a pin.
pub(crate) fn pinned_vfs_driver() -> Option<PathBuf> {
    env::var_os(VFS_DRIVER_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// Every place the projection driver can be, in resolution order.
///
/// The installer ships `kin-vfs` beside the `kin` binary it installs, and that
/// is `~/.kin/bin` only for the managed layout. An archive or Homebrew install
/// puts both somewhere else, so looking in `~/.kin/bin` alone read a driver
/// sitting next to the running binary as absent, and the check then phrased
/// that guess as a confident "neither is present here".
pub(crate) fn vfs_driver_candidates(
    pinned: Option<&Path>,
    kin_home: &Path,
    exe: Option<&Path>,
) -> Vec<PathBuf> {
    // A pinned driver is the only candidate. Falling back past it would defeat
    // the point of pinning: an operator who names a driver and gets a different
    // one has been told nothing, and a pin that silently resolves elsewhere is
    // how "I tested my build" becomes "I tested the one already installed".
    if let Some(pinned) = pinned {
        return vec![pinned.to_path_buf()];
    }

    fn push_unique(into: &mut Vec<PathBuf>, path: PathBuf) {
        if !into.contains(&path) {
            into.push(path);
        }
    }

    let name = vfs_binary_filename();
    let mut candidates = Vec::new();
    if let Some(dir) = exe.and_then(Path::parent) {
        push_unique(&mut candidates, dir.join(name));
    }
    push_unique(&mut candidates, kin_home.join("bin").join(name));
    if let Some(found) = check_binary_in_path("kin-vfs") {
        push_unique(&mut candidates, found);
    }
    candidates
}

/// What a projection driver on disk actually does when it is run.
///
/// The installer removes `kin-vfs` and its shim together where projection
/// cannot run, so an absent driver is a sanctioned outcome rather than a broken
/// install. A driver that is present and refuses to load is neither: it is a
/// real defect, and reporting it as absence tells a user nothing is missing on
/// a machine where projection is installed and dead.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum VfsDriverState {
    /// No `kin-vfs` beside the running binary, in `~/.kin/bin`, or on PATH.
    Absent,
    /// A driver that runs: probing it reached the driver's own code.
    Loadable(PathBuf),
    /// A driver on disk the loader refuses, carrying its literal complaint.
    Unloadable { path: PathBuf, message: String },
}

/// Probe one driver path by running it.
///
/// Existence is not loadability. The linux-aarch64 archive has shipped a
/// `kin-vfs` needing a newer glibc than the host carries, and on disk that
/// driver is an ordinary file: only executing it produces the loader's refusal.
/// Stdin is closed so a candidate that is not Kin's driver cannot stall the
/// check by reading from the terminal.
fn probe_vfs_driver(path: &Path) -> VfsDriverState {
    use std::process::{Command, Stdio};

    match Command::new(path)
        .arg("--help")
        .stdin(Stdio::null())
        .output()
    {
        Ok(output) if driver_ran(&output.status) => VfsDriverState::Loadable(path.to_path_buf()),
        Ok(output) => VfsDriverState::Unloadable {
            path: path.to_path_buf(),
            message: loader_failure_message(&output.stderr, &output.status),
        },
        Err(error) => VfsDriverState::Unloadable {
            path: path.to_path_buf(),
            message: error.to_string(),
        },
    }
}

/// Whether the probed process actually reached its own code.
///
/// Loading is not the same as exiting zero. `kin-vfs` takes a subcommand and
/// carries no `--version`, so `kin-vfs --version` exits 2 with a clap usage
/// error on a perfectly healthy install; judging on `success()` would have
/// reported every installed driver as broken, which is the same shape of wrong
/// answer this check exists to remove. What a refusal to load looks like is a
/// process that never reaches main: `ld.so` prints its complaint and exits 127,
/// dyld kills the process outright, and a wrong-architecture or unreadable file
/// fails at spawn.
fn driver_ran(status: &std::process::ExitStatus) -> bool {
    match status.code() {
        Some(127) => false,
        Some(_) => true,
        None => false,
    }
}

/// The loader's own words, or the exit status when it said nothing.
fn loader_failure_message(stderr: &[u8], status: &std::process::ExitStatus) -> String {
    String::from_utf8_lossy(stderr)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("it exited with {status} and printed nothing"))
}

/// Resolve the projection driver by running the candidates in order.
///
/// A driver that runs wins over one that does not, so a stale copy in one
/// location cannot hide a working install in another. A candidate that exists
/// and refuses to run is reported only when nothing else runs.
pub(crate) fn resolve_vfs_driver(candidates: &[PathBuf]) -> VfsDriverState {
    let mut refused: Option<VfsDriverState> = None;
    for candidate in candidates {
        if !candidate.is_file() {
            continue;
        }
        match probe_vfs_driver(candidate) {
            VfsDriverState::Loadable(path) => return VfsDriverState::Loadable(path),
            state => {
                if refused.is_none() {
                    refused = Some(state);
                }
            }
        }
    }
    refused.unwrap_or(VfsDriverState::Absent)
}

/// The durable step that repairs a missing or corrupt shim when `kin doctor
/// --fix` cannot source one locally. It must NEVER name `kin doctor --fix`
/// itself: this text is reprinted in the post-`--fix` "still needs manual steps"
/// list, where pointing back at the command that just ran is a dead loop.
const SHIM_REINSTALL_HINT: &str =
    "reinstall kin to restore the shim: curl -fsSL https://get.kinlab.dev/install | sh";

/// The durable step for a projection driver the loader refuses. It must not
/// promise that a reinstall clears it: the loader's message can name a system
/// library this host is too old to carry, and no build of the driver runs on
/// such a host. Saying so is the difference between a remediation and a loop.
const BROKEN_DRIVER_HINT: &str =
    "reinstall kin for this platform: curl -fsSL https://get.kinlab.dev/install | sh. If the \
     message names a system library version this host does not have, projection cannot run \
     here, and the CLI and daemon are fully functional without it.";

/// On-disk state of the VFS shim. Existence alone is not health: a 0-byte file
/// crashes every process the shim is injected into, and a non-object blob is a
/// truncated or partially-written artifact the dynamic linker will reject.
#[derive(Debug, PartialEq, Eq)]
enum ShimState {
    /// No file at the path.
    Missing,
    /// The file exists but is empty — the crash hazard doctor warns about.
    Empty,
    /// The file is non-empty but is not a valid platform object file.
    Invalid,
    /// A usable shim of the given size.
    Valid(u64),
}

/// Classify the shim at `lib_path`. Path is explicit so this is unit-testable
/// without a real `$HOME`, mirroring [`session_runtime_check_for`].
fn classify_shim(lib_path: &Path) -> ShimState {
    let meta = match std::fs::metadata(lib_path) {
        Ok(meta) if meta.is_file() => meta,
        _ => return ShimState::Missing,
    };
    if meta.len() == 0 {
        return ShimState::Empty;
    }
    match read_prefix(lib_path, 4) {
        Ok(header) if shim_magic_ok(&header) => ShimState::Valid(meta.len()),
        _ => ShimState::Invalid,
    }
}

/// Read up to `n` leading bytes of `path`, tolerating short reads.
fn read_prefix(path: &Path, n: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; n];
    let mut filled = 0;
    while filled < n {
        match file.read(&mut buf[filled..])? {
            0 => break,
            read => filled += read,
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Whether `header` carries the object-file magic Kin's shim must have on this
/// platform: Mach-O on macOS, ELF on Linux. Platforms that don't inject through
/// this shim accept any non-empty content.
fn shim_magic_ok(header: &[u8]) -> bool {
    if cfg!(target_os = "macos") {
        is_macho_magic(header)
    } else if cfg!(target_os = "linux") {
        header.starts_with(b"\x7fELF")
    } else {
        !header.is_empty()
    }
}

/// Mach-O magic numbers as the first four bytes appear on disk — thin objects
/// (32/64-bit, both byte orders) and universal ("fat") archives. A real
/// `libkin_vfs_shim.dylib` on arm64/x86_64 begins `CF FA ED FE` (MH_MAGIC_64).
fn is_macho_magic(header: &[u8]) -> bool {
    const MAGICS: [[u8; 4]; 6] = [
        [0xFE, 0xED, 0xFA, 0xCE], // MH_MAGIC (32-bit)
        [0xCE, 0xFA, 0xED, 0xFE], // MH_CIGAM (32-bit, byte-swapped)
        [0xFE, 0xED, 0xFA, 0xCF], // MH_MAGIC_64
        [0xCF, 0xFA, 0xED, 0xFE], // MH_CIGAM_64 (typical dylib on disk)
        [0xCA, 0xFE, 0xBA, 0xBE], // FAT_MAGIC (universal)
        [0xCA, 0xFE, 0xBA, 0xBF], // FAT_MAGIC_64 (universal)
    ];
    header.len() >= 4 && MAGICS.iter().any(|magic| header[..4] == *magic)
}

/// Human name for the platform's shared-object format, for the corrupt-shim message.
fn shim_object_kind() -> &'static str {
    if cfg!(target_os = "macos") {
        "Mach-O library"
    } else if cfg!(target_os = "linux") {
        "ELF library"
    } else {
        "shared library"
    }
}

/// Build the `vfs_projection` check from a resolved shim path and the probed
/// state of the projection driver. Split out from [`check_vfs_projection`] so
/// the size/magic classification and the three driver states are testable.
///
/// The driver decides the headline. A driver that will not load is a defect
/// whatever the shim looks like, and it is the one state the old check could
/// not express: it inferred absence from `~/.kin/bin` alone and reported it as
/// "neither is present here", which is a confident negative built from a place
/// it never looked.
fn vfs_projection_check_for(lib_path: &Path, driver: &VfsDriverState) -> HealthCheck {
    if let VfsDriverState::Unloadable { path, message } = driver {
        return HealthCheck::new(
            "vfs_projection",
            "VFS projection",
            HealthStatus::Misconfigured,
            format!(
                "the kin-vfs driver at {} is installed but will not run: {message}",
                path.display()
            ),
        )
        .with_manual_fix(BROKEN_DRIVER_HINT);
    }

    let driver_note = match driver {
        VfsDriverState::Loadable(path) => format!("; kin-vfs driver at {} runs", path.display()),
        _ => String::new(),
    };

    match classify_shim(lib_path) {
        ShimState::Missing if matches!(driver, VfsDriverState::Absent) => HealthCheck::new(
            "vfs_projection",
            "VFS projection",
            HealthStatus::Unsupported,
            "filesystem projection is not installed on this system; the CLI and daemon \
             are fully functional without it",
        )
        .with_platform_note(
            "The installer ships projection only where it can run, and removes the kin-vfs \
             driver and its shim together when it cannot. No kin-vfs was found beside the kin \
             binary, in ~/.kin/bin, or on PATH, and no shim is installed, so nothing is missing.",
        ),
        ShimState::Valid(size) => HealthCheck::new(
            "vfs_projection",
            "VFS projection",
            HealthStatus::Healthy,
            format!(
                "shim installed ({size} bytes, {}){driver_note}",
                lib_path.display()
            ),
        ),
        ShimState::Empty => HealthCheck::new(
            "vfs_projection",
            "VFS projection",
            HealthStatus::Misconfigured,
            format!(
                "shim is 0 bytes ({}) — a 0-byte injected library crashes processes",
                lib_path.display()
            ),
        )
        .fixable()
        .with_manual_fix(SHIM_REINSTALL_HINT),
        ShimState::Invalid => HealthCheck::new(
            "vfs_projection",
            "VFS projection",
            HealthStatus::Misconfigured,
            format!(
                "shim at {} is not a valid {} — it is truncated or corrupt",
                lib_path.display(),
                shim_object_kind()
            ),
        )
        .fixable()
        .with_manual_fix(SHIM_REINSTALL_HINT),
        ShimState::Missing => HealthCheck::new(
            "vfs_projection",
            "VFS projection",
            HealthStatus::Missing,
            format!("shim not installed at {}{driver_note}", lib_path.display()),
        )
        .fixable()
        .with_manual_fix(SHIM_REINSTALL_HINT),
    }
}

/// Report which projection is in force and whether it is actually working.
///
/// The row above answers whether projection is installed. This one answers the
/// question a user standing in a repository is actually asking: is the file I
/// just edited going through the graph. They are different questions, and a
/// machine can pass the first and fail the second, which is exactly what a
/// container does when the loader strips the injected shim: the library is on
/// disk, the install is intact, and every process is reading raw disk.
fn check_projection_mode() -> HealthCheck {
    let kin_home = match kin_dir() {
        Ok(dir) => dir,
        Err(e) => {
            return HealthCheck::new(
                "projection_mode",
                "Projection in force",
                HealthStatus::Missing,
                format!("could not resolve ~/.kin: {e}"),
            );
        }
    };
    let cwd = env::current_dir().unwrap_or_default();
    let repo_root = kin_core::KinLayout::discover(&cwd)
        .map(|layout| layout.root().to_path_buf())
        .unwrap_or(cwd);
    let report = crate::commands::projection::report_for(
        &kin_home,
        env::current_exe().ok().as_deref(),
        &repo_root,
        None,
    );
    projection_mode_check_for(&report, env::consts::OS)
}

/// Build the projection row from an already-probed report. Split out so all
/// three fixtures (everything present, no shim, a mount that is not mounted)
/// are testable without a real `$HOME` or a real mount.
/// `os` is an argument rather than read from `env::consts::OS` for the reason
/// [`crate::commands::setup::resolve_home_dir`] gives for the same choice: read
/// ambiently, the Windows branch below could only ever be exercised on the one
/// platform this fleet has no host for, and a test written on macOS would take
/// the macOS branch and prove nothing about Windows while looking like it did.
fn projection_mode_check_for(
    report: &crate::commands::projection::ProjectionReport,
    os: &str,
) -> HealthCheck {
    use crate::commands::projection::ProjectionMode;

    let live = &report.live;
    let row = live.row();
    let evidence = live.evidence.join("; ");
    let detail = format!("{row}; {evidence}");
    let any_available = report.modes.iter().any(|probe| probe.available);

    // Nothing chosen and nothing installed is the installer's sanctioned
    // outcome, not a defect: the CLI and daemon answer from the graph without
    // any projection at all. It stops being sanctioned the moment someone
    // records a mode, and it was never sanctioned on a machine that HAS a
    // driver or a shim. Both extra conditions matter: with only "no mode is
    // available" as the test, a container whose loader refuses the driver
    // produces no available modes and would have read as this same green n/a,
    // which is the exact overclaim this row exists to remove.
    let nothing_installed = report.driver.path.is_none() && !report.shim.installed;
    // And the absence is only sanctioned where the platform's floor is something
    // Kin ships and can decline to ship. Windows' floor is ProjFS, an operating
    // system feature present on every SKU that only needs enabling, so a Windows
    // machine with no projection is always a machine someone can fix and must
    // never be told that nothing is missing.
    let floor_is_kin_shipped = crate::commands::projection::floor_mode(os) == ProjectionMode::Shim;
    if report.recorded.is_none() && !any_available && nothing_installed && floor_is_kin_shipped {
        return HealthCheck::new(
            "projection_mode",
            "Projection in force",
            HealthStatus::Unsupported,
            format!(
                "no projection is available on this host and none is configured; the CLI and \
                 daemon are fully functional without one; {evidence}"
            ),
        )
        .with_platform_note(
            "Run `kin vfs status` for what each of shim, NFS and FUSE would need here.",
        );
    }

    if !live.degraded {
        return HealthCheck::new(
            "projection_mode",
            "Projection in force",
            HealthStatus::Healthy,
            detail,
        );
    }

    // A recorded mode that is not the one running, or one that is running and
    // failing its own probe, is a configured projection that does not work. It
    // has to fail: this is the row that must never read "nothing is missing"
    // for a mode somebody chose.
    let configured_and_broken = report.recorded.is_some_and(|recorded| {
        recorded != live.mode || live.readable != crate::commands::projection::Tri::Yes
    });
    if configured_and_broken {
        let remedy = report
            .modes
            .iter()
            .find(|probe| Some(probe.mode) == report.recorded)
            .and_then(|probe| probe.remedy.clone())
            .unwrap_or_else(|| "run `kin vfs status` for what this host can run".to_string());
        return HealthCheck::new(
            "projection_mode",
            "Projection in force",
            HealthStatus::Misconfigured,
            format!(
                "{} is recorded but is not what is running; {detail}",
                report
                    .recorded
                    .map(|mode| mode.to_string())
                    .unwrap_or_default()
            ),
        )
        .with_manual_fix(remedy);
    }

    // An installed projection that is simply not engaged in this process is
    // ordinary: the shell hook injects the shim into new shells, and `kin` run
    // from an editor terminal or a script without the hook is not under it.
    // Advisory rather than failing, and named so the user can see it, because a
    // silent green here is what lets someone edit raw disk believing otherwise.
    // Advisory means "installed and working, just not injected into this
    // process", which is what running `kin` from a shell without the hook looks
    // like. A shim mode that failed its own probe is not that, so a refused
    // driver or a corrupt library cannot borrow the softer status.
    let shim_usable = report
        .modes
        .iter()
        .any(|probe| probe.mode == ProjectionMode::Shim && probe.available);
    let advisory = live.mode == ProjectionMode::Shim
        && shim_usable
        && live.readable == crate::commands::projection::Tri::Yes;
    let status = if advisory {
        HealthStatus::Stale
    } else {
        HealthStatus::Misconfigured
    };
    HealthCheck::new("projection_mode", "Projection in force", status, detail).with_manual_fix(
        if advisory {
            "start a new shell, or run `exec $SHELL -l`, so the hook injects the shim"
        } else {
            "run `kin vfs on` to engage a projection, or `kin vfs status` to see why none is \
             available here"
        },
    )
}

fn check_repo_init() -> HealthCheck {
    let cwd = env::current_dir().unwrap_or_default();
    let layout = kin_core::KinLayout::discover(&cwd);
    repo_init_check_for(&cwd, layout.as_ref(), kin_dir().ok().as_deref())
}

/// Report whether the working directory is inside a Kin repository.
///
/// Not being in one is the state every install finishes in and the literal next
/// step of the quickstart, so it is skipped rather than failed: nothing is
/// broken, `kin init` has simply not been run here yet. What stays a failure is
/// a directory carrying a `.kin` that the layout refuses — a partial or corrupt
/// repository, where something that should work does not. The managed toolchain
/// directory is excluded from that test: `~/.kin` is where the CLI installs
/// itself, not a repository anyone failed to initialize.
fn repo_init_check_for(
    cwd: &Path,
    layout: Option<&kin_core::KinLayout>,
    managed_kin_dir: Option<&Path>,
) -> HealthCheck {
    if let Some(layout) = layout {
        return HealthCheck::new(
            "repo_init",
            "Repository",
            HealthStatus::Healthy,
            format!("Kin repository at {}", layout.root().display()),
        );
    }

    let local_kin = cwd.join(".kin");
    let is_managed_toolchain =
        managed_kin_dir.is_some_and(|managed| same_path(managed, &local_kin));
    if local_kin.exists() && !is_managed_toolchain {
        return HealthCheck::new(
            "repo_init",
            "Repository",
            HealthStatus::Missing,
            format!(
                "{} exists but is not a usable Kin repository",
                local_kin.display()
            ),
        )
        .with_manual_fix(
            "re-run `kin init .`; if it keeps refusing, remove the partial `.kin` directory first",
        );
    }

    HealthCheck::new(
        "repo_init",
        "Repository",
        HealthStatus::Unsupported,
        "not inside a Kin repository yet",
    )
    .with_manual_fix("run `kin init .` to initialize a repository here")
}

/// Compare two paths by their resolved form when both resolve, and literally
/// otherwise. A path that cannot be canonicalized has not been proven different.
fn same_path(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

/// Teach the session runtime path and surface leftover session workspaces.
///
/// Ordinary project tools run through graph-backed session workspaces
/// (`kin exec`, `kin shell`, `kin with`); a workspace left under `.kin/runs/`
/// is either an active session or a run waiting for `kin reconcile`, which
/// admits it and then removes it.
fn check_session_runtime() -> HealthCheck {
    let cwd = env::current_dir().unwrap_or_default();
    session_runtime_check_for(kin_core::KinLayout::discover(&cwd).as_ref())
}

fn session_runtime_check_for(layout: Option<&kin_core::KinLayout>) -> HealthCheck {
    let Some(layout) = layout else {
        return HealthCheck::new(
            "session_runtime",
            "Session runtime",
            HealthStatus::Unsupported,
            "not inside a Kin repository — from a Kin repo, run project tools with `kin exec -- <cmd>`",
        );
    };

    let runs_dir = layout.root().join("runs");
    let pending: Vec<String> = std::fs::read_dir(&runs_dir)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_str().map(ToOwned::to_owned))
        .filter(|name| name.starts_with("session-") || name.starts_with("exec-"))
        .collect();

    if pending.is_empty() {
        HealthCheck::new(
            "session_runtime",
            "Session runtime",
            HealthStatus::Healthy,
            "run project tools with `kin exec -- <cmd>`, \
             open an interactive env with `kin shell`, \
             launch agents with `kin with <assistant>`",
        )
    } else {
        HealthCheck::new(
            "session_runtime",
            "Session runtime",
            HealthStatus::Stale,
            format!(
                "{} session workspace(s) under {} (active session, or a finished run waiting for reconcile)",
                pending.len(),
                runs_dir.display()
            ),
        )
        .with_manual_fix(
            "reconcile a finished session with `kin reconcile <session-id>`, which admits it and \
             then removes it; a workspace you do not want to admit has no exposed discard yet",
        )
    }
}

fn check_shell_path() -> HealthCheck {
    let shell = detect_shell();

    let kin_home = match kin_dir() {
        Ok(dir) => dir,
        Err(e) => {
            return HealthCheck::new(
                "shell_path",
                "Shell integration",
                HealthStatus::Missing,
                format!("could not resolve ~/.kin: {e}"),
            )
            .fixable();
        }
    };

    let bin_dir = kin_home.join("bin");
    let on_path = env::var_os("PATH")
        .map(|paths| env::split_paths(&paths).any(|p| p == bin_dir))
        .unwrap_or(false);

    let hook_path = kin_home.join("shell").join(hook_filename(shell));
    let hook_installed = hook_path.exists();

    let rc_path = shell_rc(shell).ok();
    let rc_content = rc_path
        .as_ref()
        .and_then(|rc| std::fs::read_to_string(rc).ok())
        .unwrap_or_default();
    let rc_sources = rc_content.contains("kin-vfs");
    let bin_display = bin_dir.to_string_lossy();
    let rc_sets_path = rc_content.contains(bin_display.as_ref())
        || rc_content.contains(".kin/bin")
        || rc_content.contains("kin/bin");

    let rc_display = rc_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<unknown>".to_string());

    shell_path_check_from(ShellIntegrationState {
        shell,
        hook_path: &hook_path,
        rc_display: &rc_display,
        bin_dir: &bin_dir,
        bin_dir_present: bin_dir.is_dir(),
        hook_installed,
        rc_sources,
        on_path,
        rc_sets_path,
        recorded_by_setup: shell_integration_recorded_by_setup(),
    })
}

/// Whether `kin setup` recorded installing any part of the shell integration.
///
/// A hook Kin never claimed to install is not Kin's failure. The install ledger
/// is the record of having claimed it, and it is what separates the two meanings
/// of "no hook here": a machine where setup has not run, where nothing of Kin's
/// is broken, from one where setup wrote a hook that has since been removed or
/// unsourced, which is a real regression.
///
/// An unreadable or absent ledger yields false, which is the conservative
/// direction: it can only report an unconfigured shell as unconfigured.
fn shell_integration_recorded_by_setup() -> bool {
    use crate::commands::setup_ledger::{ledger_path, ArtifactKind, SetupLedger};

    let Ok(path) = ledger_path() else {
        return false;
    };
    let Ok(ledger) = SetupLedger::load(&path) else {
        return false;
    };
    ledger.entries.iter().any(|entry| {
        matches!(
            entry.kind,
            ArtifactKind::ShellHook | ArtifactKind::ShellRcLine | ArtifactKind::ShellPathLine
        )
    })
}

/// Probed shell-integration facts, separated from the environment that produced
/// them so both directions of the verdict are testable without a real `$HOME`.
struct ShellIntegrationState<'a> {
    shell: &'a str,
    hook_path: &'a Path,
    rc_display: &'a str,
    bin_dir: &'a Path,
    /// Whether `~/.kin/bin` exists at all. Only the launcher-provisioned layout
    /// populates it, so an archive or Homebrew install has no such directory and
    /// nothing that belongs on PATH through it.
    bin_dir_present: bool,
    hook_installed: bool,
    rc_sources: bool,
    on_path: bool,
    rc_sets_path: bool,
    recorded_by_setup: bool,
}

/// Build the shell integration check from probed state.
///
/// `recorded_by_setup` decides the severity of an ABSENT hook, and only that.
/// The installer publishes `KIN_NO_SETUP=1` on its own install page and then
/// says to run `kin setup` when ready, so a machine that took that path has no
/// hook by instruction. Scoring it a failure told every such user their healthy
/// install was broken. A hook setup did write and that is now gone stays a
/// failure, because that is Kin's own artifact missing.
///
/// A hook file that is present but unsourced is never reclassified, whatever the
/// ledger says. Kin's artifact is on disk, so "setup has not installed a shell
/// hook yet" would be a false statement about a state the user can see, and a
/// diagnostic that lies in the reassuring direction is worse than the noisy
/// report this replaces. That case reaches the failing arm through
/// `!hook_installed` below, which is why the reclassification tests both.
fn shell_path_check_from(state: ShellIntegrationState<'_>) -> HealthCheck {
    let ShellIntegrationState {
        shell,
        hook_path,
        rc_display,
        bin_dir,
        bin_dir_present,
        hook_installed,
        rc_sources,
        on_path,
        rc_sets_path,
        recorded_by_setup,
    } = state;

    if hook_installed && rc_sources && (on_path || rc_sets_path || !bin_dir_present) {
        let detail = match (bin_dir_present, on_path, rc_sets_path) {
            (true, true, _) => {
                format!(
                    "{shell} hook installed and sourced from {rc_display}; {} on PATH",
                    bin_dir.display()
                )
            }
            (true, false, true) => {
                format!(
                    "{shell} hook installed and sourced from {rc_display}; {} will be on PATH after shell restart",
                    bin_dir.display()
                )
            }
            (false, _, true) => {
                format!(
                    "{shell} hook installed and sourced from {rc_display}; that rc adds {} to PATH, a directory this install did not create",
                    bin_dir.display()
                )
            }
            (false, _, false) => {
                format!(
                    "{shell} hook installed and sourced from {rc_display}; no PATH line was added because {} does not exist on this host",
                    bin_dir.display()
                )
            }
            (true, false, false) => unreachable!(),
        };
        HealthCheck::new(
            "shell_path",
            "Shell integration",
            HealthStatus::Healthy,
            detail,
        )
        .fixable()
    } else if !recorded_by_setup && !hook_installed {
        HealthCheck::new(
            "shell_path",
            "Shell integration",
            HealthStatus::Unsupported,
            format!("{shell}: kin setup has not installed a shell hook yet"),
        )
        .fixable()
        .with_manual_fix("run `kin setup` (or `kin doctor --fix`) to install the shell hook")
    } else {
        let mut missing = Vec::new();
        if !hook_installed {
            missing.push(format!("hook missing at {}", hook_path.display()));
        }
        if !rc_sources {
            missing.push(format!("{rc_display} does not source the kin-vfs hook"));
        }
        if bin_dir_present && !on_path && !rc_sets_path {
            missing.push(format!(
                "{rc_display} does not add {} to PATH",
                bin_dir.display()
            ));
        }
        HealthCheck::new(
            "shell_path",
            "Shell integration",
            HealthStatus::Misconfigured,
            format!("{shell}: {}", missing.join("; ")),
        )
        .fixable()
        .with_manual_fix("run `kin setup` (or `kin doctor --fix`) to reinstall the shell hook")
    }
}

/// Path + detection metadata for one AI client's MCP config file.
struct McpClient {
    id: &'static str,
    label: &'static str,
    path: PathBuf,
}

pub(crate) fn mcp_client_config_paths() -> Vec<(&'static str, &'static str, PathBuf)> {
    // Shares `setup::home_dir` deliberately. An unresolvable home here is not an
    // error any caller sees — it is an empty client list, so setup would report
    // success having configured nothing. Resolving the home by a stricter rule
    // than the rest of setup uses is how that silence gets triggered.
    let home = match home_dir() {
        Ok(home) => home,
        Err(_) => return Vec::new(),
    };
    let mut paths = vec![
        (
            "claude",
            "Claude Code",
            // Prefer ~/.claude.json, falling back to ~/.claude/config.json.
            {
                let primary = home.join(".claude.json");
                let alt = home.join(".claude").join("config.json");
                if alt.exists() && !primary.exists() {
                    alt
                } else {
                    primary
                }
            },
        ),
        ("cursor", "Cursor", home.join(".cursor").join("mcp.json")),
        (
            "codex",
            "Codex CLI",
            // Codex reads MCP servers from config.toml, not an mcp.json.
            home.join(".codex").join("config.toml"),
        ),
        (
            "gemini",
            "Gemini CLI",
            home.join(".gemini").join("settings.json"),
        ),
        (
            "windsurf",
            "Windsurf",
            home.join(".codeium")
                .join("windsurf")
                .join("mcp_config.json"),
        ),
        (
            "antigravity",
            "Google Antigravity",
            home.join(".gemini").join("config").join("mcp_config.json"),
        ),
    ];
    if let Some(repo_root) = current_health_repo() {
        paths.push((
            "antigravity_workspace",
            "Google Antigravity workspace",
            repo_root.join(".agents").join("mcp_config.json"),
        ));
    }
    paths
}

/// Repository root the health surface names when it checks an MCP binding.
///
/// `kin setup` records the *canonicalized* repository path in every config it
/// writes. Repository discovery instead inherits the form of the process
/// working directory, which on Windows carries no `\\?\` verbatim prefix and on
/// Unix leaves symlinked ancestors unresolved. Comparing those two forms as
/// strings rejects setup's own write as misconfigured, so both sides derive the
/// repository the same way here rather than at each comparison site.
fn current_health_repo() -> Option<PathBuf> {
    crate::commands::managed_config_scope::discover_repo_root().map(canonical_health_repo)
}

/// Normalize a discovered repository root to the form the config writers record.
///
/// A root that cannot be canonicalized is returned unchanged: discovery already
/// succeeded, so dropping it here would silently retire a health check instead
/// of reporting a binding it can no longer confirm.
fn canonical_health_repo(root: PathBuf) -> PathBuf {
    root.canonicalize().unwrap_or(root)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum McpLauncherTopology {
    Native,
    CanonicalNpm,
}

fn mcp_launcher_topology(
    entry: &Value,
    expected_native_command: &str,
) -> Option<McpLauncherTopology> {
    match entry.get("command").and_then(Value::as_str) {
        Some(command) if command == expected_native_command => Some(McpLauncherTopology::Native),
        Some(CANONICAL_NPM_MCP_COMMAND) => Some(McpLauncherTopology::CanonicalNpm),
        _ => None,
    }
}

fn values_match_strings(values: &[Value], expected: &[&str]) -> bool {
    values.len() == expected.len()
        && values
            .iter()
            .zip(expected)
            .all(|(value, expected)| value.as_str() == Some(*expected))
}

fn mcp_argument_vector_matches(
    entry: &Value,
    client_id: &str,
    topology: McpLauncherTopology,
) -> bool {
    let Some(args) = entry.get("args").and_then(Value::as_array) else {
        return false;
    };
    let prefix: &[&str] = match topology {
        McpLauncherTopology::Native => &["mcp", "start"],
        McpLauncherTopology::CanonicalNpm => &["-y", CANONICAL_NPM_MCP_PACKAGE, "mcp", "start"],
    };
    if matches!(client_id, "codex" | "antigravity" | "antigravity_workspace") {
        args.len() == prefix.len() + 2
            && values_match_strings(&args[..prefix.len()], prefix)
            && args[prefix.len()].as_str() == Some("--repo")
            && args[prefix.len() + 1]
                .as_str()
                .is_some_and(|repo| Path::new(repo).is_absolute())
    } else {
        values_match_strings(args, prefix)
    }
}

fn mcp_repo_argument(entry: &Value, topology: McpLauncherTopology) -> Option<&str> {
    let args = entry.get("args")?.as_array()?;
    let repo_index = match topology {
        McpLauncherTopology::Native => 3,
        McpLauncherTopology::CanonicalNpm => 5,
    };
    args.get(repo_index)?.as_str()
}

/// Inspect a single MCP config file for a `kin` server entry carrying the
/// agent-default tool profile.
///
/// Handles both JSON configs (`mcpServers.kin`) and TOML configs such as
/// Codex's `~/.codex/config.toml` (`mcp_servers.kin`); TOML is normalized to
/// JSON so the same checks apply.
fn evaluate_mcp_client_against(
    path: &PathBuf,
    client_id: &str,
    expected_command: &str,
) -> (HealthStatus, String) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            return (
                HealthStatus::Missing,
                format!("no config file at {}", path.display()),
            )
        }
    };
    let is_toml = path.extension().and_then(|e| e.to_str()) == Some("toml");
    let (root, servers_key): (Value, &str) = if is_toml {
        match toml::from_str::<toml::Value>(&content)
            .ok()
            .and_then(|v| serde_json::to_value(v).ok())
        {
            Some(v) => (v, "mcp_servers"),
            None => {
                return (
                    HealthStatus::Misconfigured,
                    format!("{} is not valid TOML", path.display()),
                )
            }
        }
    } else {
        match serde_json::from_str(&content) {
            Ok(v) => (v, "mcpServers"),
            Err(e) => {
                return (
                    HealthStatus::Misconfigured,
                    format!("{} is not valid JSON: {e}", path.display()),
                )
            }
        }
    };
    let kin_entry = root.get(servers_key).and_then(|s| s.get("kin"));
    match kin_entry {
        None => (
            HealthStatus::Missing,
            format!("no {servers_key}.kin entry in {}", path.display()),
        ),
        Some(entry) => {
            // Entries written by older releases pass `--global`, which the MCP
            // server refuses at startup — the agent sees a dead kin server.
            let has_retired_global_flag = entry
                .get("args")
                .and_then(|args| args.as_array())
                .is_some_and(|args| args.iter().any(|arg| arg.as_str() == Some("--global")));
            if has_retired_global_flag {
                return (
                    HealthStatus::Misconfigured,
                    format!(
                        "{servers_key}.kin uses the retired `--global` mode and cannot start in {}",
                        path.display()
                    ),
                );
            }
            let command = entry.get("command").and_then(Value::as_str);
            let Some(topology) = mcp_launcher_topology(entry, expected_command) else {
                return (
                    HealthStatus::Misconfigured,
                    format!(
                        "{servers_key}.kin command is {} (expected the exact Kin launcher for this installation {} or the canonical `{CANONICAL_NPM_MCP_COMMAND} -y {CANONICAL_NPM_MCP_PACKAGE} ...` wrapper) in {}",
                        command.unwrap_or("unset"),
                        expected_command,
                        path.display()
                    ),
                );
            };
            if !mcp_argument_vector_matches(entry, client_id, topology) {
                return (
                    HealthStatus::Misconfigured,
                    format!(
                        "{servers_key}.kin does not use the exact supported MCP argument vector for {client_id} in {}",
                        path.display()
                    ),
                );
            }
            let profile = entry
                .get("env")
                .and_then(|e| e.get("KIN_MCP_TOOL_PROFILE"))
                .and_then(|p| p.as_str());
            match profile {
                Some("agent-default") => (
                    HealthStatus::Healthy,
                    format!(
                        "{servers_key}.kin present with agent-default profile ({})",
                        path.display()
                    ),
                ),
                // An entry that names no profile is served the curated
                // agent-default surface by `kin mcp start` itself, so it is
                // correctly wired even though `kin setup` would have stated it.
                // Calling this misconfigured would report the supported default
                // as a fault.
                None => (
                    HealthStatus::Healthy,
                    format!(
                        "{servers_key}.kin present, no KIN_MCP_TOOL_PROFILE set; the server \
                         defaults to the agent-default profile ({})",
                        path.display()
                    ),
                ),
                Some(other) => (
                    HealthStatus::Misconfigured,
                    format!(
                        "{servers_key}.kin present but KIN_MCP_TOOL_PROFILE is {other} (expected agent-default, or unset to take it as the default) in {}",
                        path.display()
                    ),
                ),
            }
        }
    }
}

pub(crate) fn evaluate_mcp_client(path: &PathBuf, client_id: &str) -> (HealthStatus, String) {
    let expected_command = match configured_mcp_launcher() {
        Ok(command) => command,
        Err(error) => {
            return (
                HealthStatus::Misconfigured,
                format!(
                "cannot validate MCP client {} without the exact Kin launcher for this installation: {error:#}",
                path.display()
            ),
            )
        }
    };
    evaluate_mcp_client_against(path, client_id, &expected_command)
}

/// The repository binding `kin setup` recorded for this client config, when the
/// entry on disk is still exactly the one setup wrote.
///
/// `kin setup` binds `--repo` to the repository it resolved from the directory
/// it ran in, and this checker resolves its own from the directory it runs in.
/// Those are two independent derivations of one fact, so a setup run from one
/// directory and a check run from another disagreed about a binding neither had
/// touched, and a fresh successful setup read as drift on the next check. The
/// ledger already holds the fact itself, as a fingerprint of the exact entry
/// setup wrote. When the entry still matches that fingerprint, the repository it
/// names IS the repository setup bound, and re-deriving an expectation from the
/// checker's own directory can only invent a disagreement.
///
/// An edited entry gets none of this. Its fingerprint no longer matches, so the
/// caller falls back to comparing against the discovered repository and a
/// hand-edited binding is still caught. Neither does a binding whose repository
/// has since gone away: that is a real fault, not a disagreement about where
/// anyone stood.
fn setup_recorded_binding_repo(path: &Path) -> Option<PathBuf> {
    use crate::commands::setup_ledger::{
        fingerprint_mcp_entry, ledger_path, ArtifactKind, SetupLedger,
    };

    let ledger = SetupLedger::load(&ledger_path().ok()?).ok()?;
    let recorded = ledger
        .entries
        .iter()
        .find(|entry| entry.kind == ArtifactKind::McpConfig && same_path(&entry.path, path))?;
    let bytes = std::fs::read(path).ok()?;
    let entry = super::setup::read_kin_mcp_entry_from_bytes(path, &bytes)?;
    if fingerprint_mcp_entry(&entry) != recorded.fingerprint {
        return None;
    }
    let repo = super::setup::mcp_entry_repo_argument(&entry)?;
    repo.is_dir().then_some(repo)
}

pub(crate) fn evaluate_antigravity_binding(
    path: &Path,
    workspace: bool,
) -> Option<(HealthStatus, String)> {
    // A workspace binding lives inside the repository it names, so it derives
    // its own expectation and never depended on the checker's directory.
    let repo_root = if workspace {
        path.parent()?.parent()?.canonicalize().ok()?
    } else {
        setup_recorded_binding_repo(path).or_else(current_health_repo)?
    };
    evaluate_antigravity_binding_for(path, workspace, &repo_root)
}

fn evaluate_antigravity_binding_for(
    path: &Path,
    workspace: bool,
    repo_root: &Path,
) -> Option<(HealthStatus, String)> {
    let root: Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    let entry = root.get("mcpServers")?.get("kin")?;
    let expected_command = configured_mcp_launcher().ok()?;
    let client_id = if workspace {
        "antigravity_workspace"
    } else {
        "antigravity"
    };
    let expected_repo = repo_root.to_string_lossy();
    let topology = mcp_launcher_topology(entry, &expected_command);
    let launcher_and_args_match = topology.is_some_and(|topology| {
        mcp_argument_vector_matches(entry, client_id, topology)
            && mcp_repo_argument(entry, topology) == Some(expected_repo.as_ref())
    });
    let cwd_matches =
        !workspace || entry.get("cwd").and_then(Value::as_str) == Some(expected_repo.as_ref());
    if launcher_and_args_match && cwd_matches {
        None
    } else {
        Some((
            HealthStatus::Misconfigured,
            format!(
                "Antigravity Kin binding at {} does not use an exact supported launcher, repository arguments, or workspace cwd",
                path.display()
            ),
        ))
    }
}

fn evaluate_codex_binding_for(path: &Path, expected_repo: &Path) -> Option<(HealthStatus, String)> {
    let content = match std::fs::read(path) {
        Ok(content) => content,
        Err(error) => {
            return Some((
                HealthStatus::Misconfigured,
                format!(
                    "could not read Codex MCP config {}: {error}",
                    path.display()
                ),
            ));
        }
    };
    match super::setup::codex_entry_has_exact_repo_binding(&content, expected_repo) {
        Ok(true) => None,
        Ok(false) => Some((
            HealthStatus::Misconfigured,
            format!(
                "Codex Kin binding at {} does not use the exact `mcp start --repo <current-repository>` arguments for {}",
                path.display(),
                expected_repo.display()
            ),
        )),
        Err(error) => Some((
            HealthStatus::Misconfigured,
            format!(
                "Codex Kin binding at {} is invalid: {error:#}",
                path.display()
            ),
        )),
    }
}

fn evaluate_codex_binding(path: &Path) -> Option<(HealthStatus, String)> {
    let expected_repo = setup_recorded_binding_repo(path).or_else(current_health_repo)?;
    evaluate_codex_binding_for(path, &expected_repo)
}

/// Config files `kin setup` recorded merging a kin MCP server entry into.
///
/// An AI client's config is not Kin's artifact. Kin merges one `kin` key into a
/// file the client owns and leaves every sibling alone, and the install ledger
/// is the record of having done it. That record is what separates the two
/// meanings of "no kin entry here": a client Kin has never been registered with,
/// where nothing of Kin's is broken, from a client Kin did register and whose
/// entry has since been removed, which is a real regression.
///
/// An unreadable or absent ledger yields no paths, which is the conservative
/// direction: it can only make this report a third-party config as untouched.
fn mcp_paths_recorded_by_setup() -> Vec<PathBuf> {
    use crate::commands::setup_ledger::{ledger_path, ArtifactKind, SetupLedger};

    let Ok(path) = ledger_path() else {
        return Vec::new();
    };
    let Ok(ledger) = SetupLedger::load(&path) else {
        return Vec::new();
    };
    ledger
        .entries
        .into_iter()
        .filter(|entry| entry.kind == ArtifactKind::McpConfig)
        .map(|entry| entry.path)
        .collect()
}

/// Build one `mcp_client_*` check from an evaluated client config.
///
/// `recorded_by_setup` decides the severity of an absent kin entry, and only
/// that. A kin entry that is present but wrong stays a failure whoever wrote the
/// surrounding file: it is Kin's own binding, and an agent pointed at it gets a
/// dead server.
fn mcp_client_check_from(
    client_id: &str,
    label: &str,
    path: &Path,
    status: HealthStatus,
    detail: String,
    recorded_by_setup: bool,
) -> HealthCheck {
    let id = format!("mcp_client_{client_id}");
    let label = format!("MCP: {label}");
    let unregistered = matches!(status, HealthStatus::Missing) && !recorded_by_setup;
    if unregistered {
        HealthCheck::new(
            &id,
            &label,
            HealthStatus::Unsupported,
            format!(
                "kin is not registered in this client — {} is a config Kin has not written to",
                path.display()
            ),
        )
        .fixable()
        .with_manual_fix(
            "run `kin setup` (or `kin doctor --fix`) to merge the kin MCP server entry into this client",
        )
    } else {
        let check = HealthCheck::new(&id, &label, status, detail);
        if is_failing(&check.status) {
            check.fixable().with_manual_fix(
                "run `kin setup` (or `kin doctor --fix`) to re-merge the kin MCP server entry",
            )
        } else {
            check
        }
    }
}

/// Build the row for a machine carrying no AI client config file at all.
///
/// A config file is evidence a client was configured, not evidence one is
/// installed. Reading only config files, this row told the user there was
/// nothing to configure in the same minute `kin setup` detected Claude Code and
/// wrote both its MCP config and a global instruction file. Both surfaces now
/// read setup's detection, so they cannot disagree about what is on the machine.
fn no_mcp_client_config_check(detected: &[&str]) -> HealthCheck {
    if detected.is_empty() {
        return HealthCheck::new(
            "mcp_clients",
            "AI client MCP config",
            HealthStatus::Healthy,
            "no AI client detected and no client config files present, so there is nothing \
             to configure",
        );
    }

    HealthCheck::new(
        "mcp_clients",
        "AI client MCP config",
        HealthStatus::Unsupported,
        format!(
            "{} detected with no client config file yet; `kin setup` writes the kin MCP server \
             entry for it",
            detected.join(", ")
        ),
    )
    .with_manual_fix("run `kin setup` to register the kin MCP server with the detected client(s)")
}

fn check_mcp_clients() -> Vec<HealthCheck> {
    let clients: Vec<McpClient> = mcp_client_config_paths()
        .into_iter()
        .map(|(id, label, path)| McpClient { id, label, path })
        .filter(|c| c.path.exists())
        .collect();

    if clients.is_empty() {
        return vec![no_mcp_client_config_check(&detected_ai_client_names())];
    }

    let recorded = mcp_paths_recorded_by_setup();

    clients
        .into_iter()
        .map(|client| {
            let (mut status, mut detail) = evaluate_mcp_client(&client.path, client.id);
            if matches!(status, HealthStatus::Healthy)
                && (client.id == "antigravity" || client.id == "antigravity_workspace")
            {
                if let Some((binding_status, binding_detail)) =
                    evaluate_antigravity_binding(&client.path, client.id == "antigravity_workspace")
                {
                    status = binding_status;
                    detail = binding_detail;
                }
            }
            if matches!(status, HealthStatus::Healthy) && client.id == "codex" {
                if let Some((binding_status, binding_detail)) = evaluate_codex_binding(&client.path)
                {
                    status = binding_status;
                    detail = binding_detail;
                }
            }
            let recorded_by_setup = recorded.iter().any(|path| same_path(path, &client.path));
            mcp_client_check_from(
                client.id,
                client.label,
                &client.path,
                status,
                detail,
                recorded_by_setup,
            )
        })
        .collect()
}

/// Verify the install ledger against current disk state: are the artifacts
/// `kin setup` recorded still present and unmodified?
///
/// This is informational and recoverable by construction — it never reports
/// Missing/Misconfigured, so a drifted ledger does not flip first-run readiness
/// to broken. No ledger yet (setup not run) is Unsupported; drift (removed or
/// user-modified artifacts) is Stale with a remediation hint.
fn check_setup_ledger() -> HealthCheck {
    use crate::commands::setup_ledger::{ledger_path, verify_ledger, EntryState};

    let path = match ledger_path() {
        Ok(p) => p,
        Err(e) => {
            return HealthCheck::new(
                "setup_ledger",
                "Install ledger",
                HealthStatus::Unsupported,
                format!("could not resolve ledger path: {e}"),
            );
        }
    };

    let verifications = match verify_ledger(&path) {
        Ok(v) => v,
        Err(_) => {
            return HealthCheck::new(
                "setup_ledger",
                "Install ledger",
                HealthStatus::Stale,
                format!(
                    "install ledger at {} is unreadable or corrupt",
                    path.display()
                ),
            )
            .with_manual_fix("remove the ledger file and re-run `kin setup` to rebuild it");
        }
    };

    if verifications.is_empty() {
        return HealthCheck::new(
            "setup_ledger",
            "Install ledger",
            HealthStatus::Unsupported,
            "no install ledger yet — run `kin setup` to record what gets installed",
        );
    }

    let total = verifications.len();
    let modified = verifications
        .iter()
        .filter(|v| matches!(v.state, EntryState::Modified))
        .count();
    let removed = verifications
        .iter()
        .filter(|v| matches!(v.state, EntryState::Removed))
        .count();

    if modified == 0 && removed == 0 {
        HealthCheck::new(
            "setup_ledger",
            "Install ledger",
            HealthStatus::Healthy,
            format!("{total} artifact(s) tracked, all present and unmodified"),
        )
    } else {
        HealthCheck::new(
            "setup_ledger",
            "Install ledger",
            HealthStatus::Stale,
            format!("{total} tracked: {removed} removed, {modified} modified since install"),
        )
        .with_manual_fix(
            "`kin setup ledger` for detail; `kin setup` re-applies removed artifacts; `kin setup uninstall` removes tracked ones",
        )
    }
}

fn check_editor() -> HealthCheck {
    let home = home_dir().ok();
    let extensions_glob = home.as_ref().map(|h| h.join(".vscode").join("extensions"));

    let detected = extensions_glob
        .as_ref()
        .and_then(|dir| std::fs::read_dir(dir).ok())
        .map(|entries| {
            entries.filter_map(|e| e.ok()).any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .to_lowercase()
                    .contains("kin-editor")
            })
        })
        .unwrap_or(false);

    if detected {
        HealthCheck::new(
            "editor",
            "Editor extension",
            HealthStatus::Healthy,
            "kin-editor extension found in ~/.vscode/extensions",
        )
    } else {
        HealthCheck::new(
            "editor",
            "Editor extension",
            HealthStatus::Unsupported,
            "kin-editor extension not detected in ~/.vscode/extensions (cannot be \
             determined from the CLI for non-VS Code editors)",
        )
        .with_manual_fix("install the kin-editor VS Code extension (see the kin-editor README)")
    }
}

fn check_kinlab_connect() -> HealthCheck {
    let base_url = default_base_url_for_health();
    if crate::commands::auth::has_stored_credential(&base_url) {
        HealthCheck::new(
            "kinlab_connect",
            "KinLab connection",
            HealthStatus::Healthy,
            format!("stored credential present for {base_url}"),
        )
    } else {
        HealthCheck::new(
            "kinlab_connect",
            "KinLab connection",
            HealthStatus::Unsupported,
            format!("no stored credential for {base_url}"),
        )
        .with_manual_fix(format!(
            "run `kin auth login` to connect this machine to {base_url}, or `kin auth login --base-url <url>` for another workspace"
        ))
    }
}

#[cfg(not(feature = "vector"))]
async fn check_semantic_query_readiness() -> HealthCheck {
    HealthCheck::new(
        "semantic_query_readiness",
        "Semantic query readiness",
        HealthStatus::Unsupported,
        "semantic vector ranking is not included in this build; lexical and graph queries remain available",
    )
    .with_platform_note("this platform ships the supported vector-free Kin runtime")
}

/// Render the daemon's background-work disclosure as a health check.
///
/// Split from its fetch so the reporting rule is testable without a daemon.
/// Healthy is the answer whenever nothing was stopped, including while passes
/// are working hard: this check reports faults, and the ordinary account of what
/// the daemon is spending lives in `kin resources`.
///
/// Deliberately not gated on `vector`: background work is every pass the daemon
/// runs, and a build without the vector feature still runs a reconcile loop that
/// can wedge.
pub fn background_work_health_from_state(
    work: &crate::commands::resources::DaemonWorkState,
) -> HealthCheck {
    let stopped: Vec<&crate::commands::resources::BackgroundPassReport> = work
        .passes
        .iter()
        .filter(|pass| pass.stopped_reason.is_some())
        .collect();
    let cpu = match work.daemon_cpu_seconds {
        Some(seconds) => format!("daemon has used {seconds:.0}s of CPU"),
        None => "daemon CPU not sampled yet".to_string(),
    };
    // A pass that is still running is not thereby working. The supervisor stops
    // a pass that holds the CPU without advancing, but a reconcile loop that
    // wakes, fails its admission, and sleeps again advances its own clock
    // perfectly well while admitting nothing, so it is never stopped and this
    // check called it healthy for as long as that lasted. The loop's own
    // account of what it admitted is therefore read beside the stop flags
    // rather than trusted to be implied by them.
    let mut reasons: Vec<String> = stopped
        .iter()
        .filter_map(|pass| pass.stopped_reason.as_deref())
        .map(str::to_string)
        .collect();
    reasons.extend(work.reconcile.degraded_reasons());
    // Carried on the detail of whichever verdict follows, never into `reasons`.
    // A working copy holding untracked files is the normal state of one being
    // edited, so it must not move this check off `Healthy`; it still has to be
    // said, because the paths it names are precisely the ones whose entities a
    // reader will go looking for and not find.
    let notices = work.reconcile.notices();
    let notice_detail = if notices.is_empty() {
        String::new()
    } else {
        format!("; {}", notices.join("; "))
    };
    if reasons.is_empty() {
        let working = work
            .passes
            .iter()
            .filter(|pass| pass.state == "working")
            .count();
        return HealthCheck::new(
            "background_work",
            "Background work",
            HealthStatus::Healthy,
            format!(
                "{cpu}; {} background pass(es), {working} working, none stopped; reconcile \
                 admitting normally{notice_detail}",
                work.passes.len()
            ),
        );
    }
    HealthCheck::new(
        "background_work",
        "Background work",
        HealthStatus::Stale,
        format!("{cpu}; {}{notice_detail}", reasons.join("; ")),
    )
    .with_manual_fix(
        "restart the daemon (`kin daemon restart`) to retry the stopped pass, and report the \
         reason above if it stops again",
    )
}

async fn check_background_work() -> HealthCheck {
    let cwd = env::current_dir().unwrap_or_default();
    let Some(layout) = kin_core::KinLayout::discover(&cwd) else {
        return HealthCheck::new(
            "background_work",
            "Background work",
            HealthStatus::Unsupported,
            "n/a — not in a Kin repository",
        );
    };
    let Some(daemon_url) = crate::daemon_client::resolve_daemon_url_if_running_async(&layout).await
    else {
        return HealthCheck::new(
            "background_work",
            "Background work",
            HealthStatus::Unsupported,
            "n/a — no daemon running for this repository, so there is no background work to \
             account for; a daemon starts on first use",
        );
    };
    let client = match crate::daemon_client::DaemonClient::from_base_url_for_layout(
        daemon_url.clone(),
        &layout,
    ) {
        Ok(client) => client,
        Err(error) => {
            return HealthCheck::new(
                "background_work",
                "Background work",
                HealthStatus::Stale,
                format!("daemon reachable ({daemon_url}), but its URL is invalid: {error}"),
            )
            .with_manual_fix("run `kin status --json` and resolve the reported daemon error");
        }
    };
    match client
        .command_resources(&crate::commands::resources::CommandResourcesRequest::default())
        .await
    {
        Ok(response) => background_work_health_from_state(&response.daemon_work),
        Err(error) => HealthCheck::new(
            "background_work",
            "Background work",
            HealthStatus::Stale,
            format!(
                "daemon reachable ({daemon_url}), but its background-work state is unavailable: \
                 {error}"
            ),
        )
        .with_manual_fix("run `kin status --json` and resolve the reported daemon error"),
    }
}

/// Report whether the relation graph can answer a question about absence.
///
/// Five shipped surfaces (`find_references`, `trace_data_flow`, impact, xref,
/// dead-code) answer from reference edges, and until this row existed no doctor
/// surface said how many of those edges the graph holds: `graph validate` passed
/// on a graph missing 16 imports and roughly 40 cross-file call edges, and
/// `kin languages` listed the language as fully extracted, so every readiness
/// signal pointed away from the gap.
async fn check_reference_edge_coverage() -> HealthCheck {
    const ID: &str = "reference_edge_coverage";
    const LABEL: &str = "Reference edge coverage";

    // Probed first, because it needs no daemon. Every branch below that cannot
    // read the graph still reports this half, so a repository whose daemon is
    // down does not silently lose the language-server signal that used to have
    // its own row.
    let missing_servers =
        missing_language_servers(&crate::commands::graph::installed_language_servers());

    let cwd = env::current_dir().unwrap_or_default();
    let Some(layout) = kin_core::KinLayout::discover(&cwd) else {
        return HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Unsupported,
            "n/a — not in a Kin repository",
        );
    };
    let Some(daemon_url) = crate::daemon_client::resolve_daemon_url_if_running_async(&layout).await
    else {
        return coverage_unreadable(
            HealthStatus::Unsupported,
            "no daemon running for this repository, so relation-graph completeness cannot be \
             read; a daemon starts on first use",
            "run any `kin` command in the repo to auto-start the daemon",
            &missing_servers,
        );
    };
    let client = match crate::daemon_client::DaemonClient::from_base_url_for_layout(
        daemon_url.clone(),
        &layout,
    ) {
        Ok(client) => client,
        Err(error) => {
            return coverage_unreadable(
                HealthStatus::Stale,
                format!("daemon reachable ({daemon_url}), but its URL is invalid: {error}"),
                "check the daemon URL recorded for this repository",
                &missing_servers,
            );
        }
    };
    let response = match client
        .graph_command(&crate::commands::graph::GraphCommandRequest::Status)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return coverage_unreadable(
                HealthStatus::Stale,
                format!(
                    "daemon reachable ({daemon_url}), but relation-graph completeness is \
                     unavailable: {error}"
                ),
                "run `kin graph status` and resolve the reported daemon error",
                &missing_servers,
            );
        }
    };
    let Some(coverage) = response.reference_edge_coverage else {
        return coverage_unreadable(
            HealthStatus::Stale,
            "the daemon serving this repository does not report relation-graph completeness; it \
             predates the measurement",
            "restart the daemon with `kin daemon restart` to pick up this build",
            &missing_servers,
        );
    };
    reference_edge_coverage_health(&coverage)
}

/// The row for every state where the graph itself could not be read.
///
/// It still reports the host probe, because that needed no daemon. Reporting
/// only "completeness unavailable" would drop a fact this process holds, and
/// this row is the only one that carries it now.
fn coverage_unreadable(
    status: HealthStatus,
    detail: impl Into<String>,
    manual_fix: &str,
    missing_servers: &[String],
) -> HealthCheck {
    const ID: &str = "reference_edge_coverage";
    const LABEL: &str = "Reference edge coverage";

    let detail = detail.into();
    if missing_servers.is_empty() {
        return HealthCheck::new(ID, LABEL, status, format!("n/a — {detail}"))
            .with_manual_fix(manual_fix);
    }
    // A missing server is a measured host fact even when the graph is not
    // readable, so it decides the status rather than deferring to the unread
    // half. Stale, not Missing: the graph still answers from the edges it holds.
    HealthCheck::new(
        ID,
        LABEL,
        HealthStatus::Stale,
        format!(
            "{}; graph completeness not read: {detail}",
            language_server_gap_detail(missing_servers)
        ),
    )
    .with_manual_fix(LANGUAGE_SERVER_FIX)
}

/// Turn the measurement into a verdict, split from its fetch so the rule is
/// testable without a daemon.
pub(crate) fn reference_edge_coverage_health(
    coverage: &kin_core::reference_coverage::ReferenceEdgeCoverage,
) -> HealthCheck {
    const ID: &str = "reference_edge_coverage";
    const LABEL: &str = "Reference edge coverage";

    if coverage.languages.is_empty() {
        return HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Healthy,
            "no language entities in the graph yet, so there are no reference edges to resolve",
        );
    }

    let summary = coverage
        .languages
        .iter()
        .map(|language| {
            format!(
                "{} {}/{} calls resolved, {} cross-file",
                language.language,
                language.resolved_call_edges,
                language
                    .parsed_call_sites
                    .map(|parsed| parsed.to_string())
                    .unwrap_or_else(|| "?".to_string()),
                language.cross_file_reference_edges
            )
        })
        .collect::<Vec<_>>()
        .join("; ");

    // The language-server state arrives measured, per language this repository
    // actually holds, rather than probed against every wired language. This row
    // used to have a sibling that probed the host, and that sibling warned about
    // rust-analyzer on a Python-only repository, which is exactly the row a
    // reader learns to skip.
    let missing_servers = coverage.languages_missing_a_language_server();
    let mut gaps = coverage.unsupportable_absence_reasons();
    if !missing_servers.is_empty() {
        gaps.push(format!(
            "cross-file reference and override edges unavailable for {}: no language server \
             found. Import and call edges are still resolved from source",
            missing_servers.join(", ")
        ));
    }
    if gaps.is_empty() {
        return HealthCheck::new(ID, LABEL, HealthStatus::Healthy, summary);
    }

    // Pending rather than Missing: the graph is answering, and every reference
    // query it answers is still true about the edges it holds. What it cannot do
    // is support a claim that something is unused, so this needs attention
    // without failing readiness.
    HealthCheck::new(
        ID,
        LABEL,
        HealthStatus::Pending,
        format!("{}; {}", gaps.join("; "), summary),
    )
    .with_manual_fix(
        "re-admit the repository so relation extraction runs again (`kin reconcile --admit`), and \
         treat any \"unused\" answer as unverified until cross-file edges resolve",
    )
}

/// Semantic readiness when no daemon is running to ask.
///
/// This is where every repository sits until its first command needs a daemon,
/// so it is an unread state rather than a failed one, and reporting it as a
/// failure is what makes an install that did everything right end on a red
/// summary. The authority gate is unchanged for every state that *can* be read:
/// a reachable daemon whose graph coverage is incomplete or unreadable is still
/// Stale, and Stale on this check still blocks readiness.
#[cfg(feature = "vector")]
fn semantic_query_readiness_without_a_daemon() -> HealthCheck {
    HealthCheck::new(
        "semantic_query_readiness",
        "Semantic query readiness",
        HealthStatus::Unsupported,
        "n/a — no daemon running for this repository, so graph embedding coverage cannot \
         be read; a daemon starts on first use",
    )
    .with_manual_fix("run any `kin` command in the repo to auto-start the daemon")
}

#[cfg(feature = "vector")]
fn semantic_query_health_from_runtime(
    daemon_url: &str,
    runtime: &crate::commands::resources::EmbedRuntimeState,
) -> HealthCheck {
    let indexed = runtime.embeddings_indexed;
    let total = runtime.embeddings_total;
    let pending = runtime.embeddings_pending;
    let detail = format!(
        "daemon graph at {daemon_url} reports {indexed}/{total} embeddings indexed, {pending} pending"
    );

    if runtime.embed_worker_failed {
        return HealthCheck::new(
            "semantic_query_readiness",
            "Semantic query readiness",
            HealthStatus::Missing,
            format!("{detail}; embedding worker failed"),
        )
        .with_manual_fix(
            "inspect the daemon logs, resolve the embedding failure, and restart the daemon",
        );
    }

    if total == 0 || (indexed == total && pending == 0) {
        // Coverage is whole. A discard earlier in this daemon's life has been
        // paid off and leaves nothing to act on, and a check that stays yellow
        // after its cause is gone is a check nobody reads.
        return HealthCheck::new(
            "semantic_query_readiness",
            "Semantic query readiness",
            HealthStatus::Healthy,
            detail,
        );
    }

    // A backlog is only work in progress if something is going to consume it.
    // On a store whose graph authority is a remote storage backend there is no
    // durable local vector-sidecar contract, the embedding worker never starts
    // and `/embed` refuses, so this coverage is not filling and never will be.
    // Reporting that as pending promises an outcome the host cannot deliver.
    if runtime.embed_persistence_unavailable {
        return HealthCheck::new(
            "semantic_query_readiness",
            "Semantic query readiness",
            HealthStatus::Unsupported,
            format!(
                "{detail}; this store's graph authority is a remote storage backend, which \
                 carries no durable local vector-sidecar contract, so nothing will embed here"
            ),
        );
    }

    // Incomplete coverage reads identically whether this is a first run or a
    // repository whose finished index was thrown away at open. Only one of them
    // means work already paid for is being paid for again, so when the daemon
    // knows which it is, say so instead of leaving it to be inferred.
    let Some(reason) = &runtime.vector_index_discarded else {
        // Nothing was discarded, so the remaining question is whether this
        // store has ever finished a fill. Before it has, partial coverage is a
        // correct fresh install doing exactly what it should in its first
        // minutes, and gating readiness on it fails every new user for
        // succeeding.
        //
        // After it has, this is a top-up rather than lost ground. A working
        // copy admits new files as they are written and an edit invalidates
        // the embeddings it touched, so on any repository somebody is actually
        // working in, coverage goes partial again constantly and comes back on
        // its own. The surface is serving off a fill that completed, so it is
        // ready; the backlog is named here rather than held against it. The
        // states that do mean lost ground keep their own arms above, keyed on
        // the cause: a discarded index is Stale and a failed worker is Missing,
        // and neither is inferred from counters that grew.
        let (status, detail) = if runtime.embedding_coverage_ever_complete {
            (
                HealthStatus::Healthy,
                format!("{detail}; coverage completed earlier and this backlog is filling"),
            )
        } else {
            (
                HealthStatus::Pending,
                format!("{detail}; first embedding pass still filling"),
            )
        };
        return HealthCheck::new(
            "semantic_query_readiness",
            "Semantic query readiness",
            status,
            detail,
        )
        .with_manual_fix("allow daemon embedding to finish or run `kin embed`");
    };

    HealthCheck::new(
        "semantic_query_readiness",
        "Semantic query readiness",
        HealthStatus::Stale,
        // Not "rebuilt from scratch". The daemon's recovery pass answers
        // unchanged texts from the embedder's persistent cache and forwards
        // only misses, so promising a full rebuild overstates the cost and
        // sends operators to run an embed pass nobody needed. The open-time
        // daemon log makes the same statement in the same words, and two
        // surfaces disagreeing about one fact invites a reader to trust the
        // wrong one.
        format!("{detail}; {reason}, so the daemon is restoring coverage in the background"),
    )
    .with_manual_fix(
        "allow daemon embedding to finish, or run `kin embed` to force it now; the restore \
         reuses prior vectors where they still apply",
    )
}

#[cfg(feature = "vector")]
async fn check_semantic_query_readiness() -> HealthCheck {
    let cwd = env::current_dir().unwrap_or_default();
    let layout = match kin_core::KinLayout::discover(&cwd) {
        Some(l) => l,
        None => {
            return HealthCheck::new(
                "semantic_query_readiness",
                "Semantic query readiness",
                HealthStatus::Unsupported,
                "n/a — not in a Kin repository",
            );
        }
    };

    let daemon_url = crate::daemon_client::resolve_daemon_url_if_running_async(&layout).await;
    let Some(daemon_url) = daemon_url else {
        return semantic_query_readiness_without_a_daemon();
    };

    let client = match crate::daemon_client::DaemonClient::from_base_url_for_layout(
        daemon_url.clone(),
        &layout,
    ) {
        Ok(client) => client,
        Err(error) => {
            return HealthCheck::new(
                "semantic_query_readiness",
                "Semantic query readiness",
                HealthStatus::Stale,
                format!("daemon reachable ({daemon_url}), but its URL is invalid: {error}"),
            )
            .with_manual_fix("run `kin status --json` and resolve the reported daemon error");
        }
    };
    let response = match client
        .command_resources(&crate::commands::resources::CommandResourcesRequest::default())
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return HealthCheck::new(
                "semantic_query_readiness",
                "Semantic query readiness",
                HealthStatus::Stale,
                format!(
                    "daemon reachable ({daemon_url}), but graph embedding status is unavailable: {error}"
                ),
            )
            .with_manual_fix("run `kin status --json` and resolve the reported daemon error");
        }
    };

    semantic_query_health_from_runtime(&daemon_url, &response.embed_runtime)
}

/// Which wired languages have no language server on this host.
///
/// Reference and override edges are not derivable from a single-file parse:
/// they need a resolved program, which Kin gets from an external language
/// server. On a host with none installed the graph simply never gains that edge
/// class, and the only trace used to be a relation count a reader had to
/// already know the expected value of.
///
/// This probes the host and needs no daemon, so it is what the completeness row
/// falls back to when the graph itself cannot be read. When the graph IS
/// readable the same fact arrives measured, per language the repository
/// actually holds, and [`reference_edge_coverage_health`] reads it from there
/// instead: warning about rust-analyzer on a Python-only repository is a row a
/// reader learns to skip.
fn missing_language_servers(
    installed: &std::collections::HashSet<kin_model::LanguageId>,
) -> Vec<String> {
    crate::commands::graph::LANGUAGE_SERVER_BINARIES
        .iter()
        .filter(|(language, _)| !installed.contains(language))
        .map(|(language, binaries)| format!("{language} ({})", binaries.join(" or ")))
        .collect()
}

/// The sentence that names what a missing server costs, and what still works.
///
/// A row that reports only the loss reads as "the graph knows nothing across
/// files", and import-bound calls are resolved from source with no language
/// server involved at all.
fn language_server_gap_detail(missing: &[String]) -> String {
    format!(
        "cross-file reference and override edges unavailable: no language server found for {}; \
         import and call edges are still resolved from source. Languages outside {} gain no \
         reference edges in this build either",
        missing.join(", "),
        crate::commands::graph::LANGUAGE_SERVER_BINARIES
            .iter()
            .map(|(language, _)| language.to_string())
            .collect::<Vec<_>>()
            .join("/")
    )
}

/// How long the model host is given to answer before the probe gives up.
///
/// Bounds `kin doctor` on a host with a black-hole resolver, where a name
/// lookup can otherwise sit for the resolver's own timeout. The budget is
/// stated in the failing detail, because "did not answer within 3s" is what
/// this probe actually establishes and "is unreachable" is not.
const MODEL_HOST_PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);

/// Whether the embedding model this build fetches at runtime is already here,
/// and what a machine that does not have it owes to get it.
///
/// The weights are not shipped with any install. Until this check existed the
/// first embed pass on a fresh machine spent several hundred megabytes of
/// egress with no surface naming the download, the size, the destination, or
/// the host it needs to reach, and an air-gapped host produced exactly the same
/// output as a healthy one that was simply still working.
async fn check_embedding_model() -> HealthCheck {
    // `false`: this is a one-shot CLI process with no embed pass of its own, so
    // the download-in-flight phase is not a state doctor can be in. Doctor
    // answers whether the model is here, not whether some other process is
    // fetching it this second.
    let fetch = crate::embed_model::EmbedModelFetch::probe(false);
    // Probed only where the answer changes the verdict. A machine that already
    // holds the model owes no egress, and asking anyway would put a network
    // call in the path of a check that has nothing to learn from it.
    let reachable = if fetch.present || fetch.no_fetch_reason.is_some() {
        None
    } else {
        Some(model_host_reachable(crate::embed_model::endpoint_host()).await)
    };
    embedding_model_check_from(&fetch, reachable)
}

/// Whether a TCP connection to the model host's HTTPS port completes inside the
/// budget.
///
/// Deliberately not an HTTP request. The question is whether this host has any
/// route to the place the weights come from, and a name that resolves plus a
/// socket that connects answers it without depending on the endpoint's own
/// availability or on a proxy honouring a method. Every way of not answering
/// inside the budget, including a name that never resolves, is reported the
/// same way, which is why the detail names the budget rather than claiming the
/// host is down.
async fn model_host_reachable(host: String) -> bool {
    let target = format!("{host}:443");
    let probe = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        let Ok(mut addrs) = target.to_socket_addrs() else {
            return false;
        };
        let Some(addr) = addrs.next() else {
            return false;
        };
        std::net::TcpStream::connect_timeout(&addr, MODEL_HOST_PROBE_BUDGET).is_ok()
    });
    matches!(
        tokio::time::timeout(MODEL_HOST_PROBE_BUDGET, probe).await,
        Ok(Ok(true))
    )
}

/// The check above, with both probes taken as arguments.
///
/// `reachable` is `None` where the question was never asked, which is not the
/// same fact as a host that answered no, and the two render differently.
fn embedding_model_check_from(
    fetch: &crate::embed_model::EmbedModelFetch,
    reachable: Option<bool>,
) -> HealthCheck {
    let host = crate::embed_model::endpoint_host();
    let model = &fetch.model_id;
    let location = match fetch.cache_dir.as_deref() {
        Some(dir) => format!(" at {dir}"),
        None => String::new(),
    };
    let download = fetch.expected_download();
    let (status, mut detail) = match (fetch.no_fetch_reason.as_deref(), fetch.present, reachable) {
        (Some(reason), _, _) => (HealthStatus::Healthy, format!("{model}: {reason}")),
        (None, true, _) => (
            HealthStatus::Healthy,
            format!("{model} is in the Hugging Face cache{location}, so no download is owed"),
        ),
        (None, false, Some(false)) => (
            HealthStatus::Missing,
            format!(
                "{model} is not in the cache{location} and this host did not reach {host}:443 \
                 within {}s; the first embed pass fetches {download} from {host}, and until \
                 that lands nothing embeds",
                MODEL_HOST_PROBE_BUDGET.as_secs()
            ),
        ),
        (None, false, _) => (
            HealthStatus::Pending,
            format!(
                "{model} is not in the cache{location}; the first embed pass fetches {download} \
                 from {host} before it records anything"
            ),
        ),
    };
    if let Some(hf_home) = fetch.relocated_hf_home.as_deref() {
        detail.push_str(&format!(
            ". HF_HOME is set to {hf_home}, which the embedding loader does not read, so a model \
             seeded there is fetched again into the cache named above"
        ));
    }
    let check = HealthCheck::new("embedding_model", "Embedding model", status, detail);
    if fetch.present || fetch.no_fetch_reason.is_some() {
        return check;
    }
    check.with_manual_fix(format!(
        "allow egress to {host} for the first embed pass, or pre-seed the model by copying an \
         existing Hugging Face hub cache into the directory named above, or point \
         KIN_EMBED_MODEL_ID at a local model directory"
    ))
}

const LANGUAGE_SERVER_FIX: &str =
    "install a language server for the named language (for example `npm i -g pyright` or \
     `rustup component add rust-analyzer`), then restart the daemon";

/// Report the active retrieval quality profile and the effective lever set,
/// so an operator can see at a glance whether they are getting full
/// retrieval capability — and why not, when a lever is off.
fn check_retrieval_profile() -> HealthCheck {
    let profile = crate::retrieval_profile::RetrievalProfile::from_env();
    let ce_model = env::var("KIN_LOCATE_CROSS_ENCODER_MODEL")
        .unwrap_or_else(|_| "BAAI/bge-reranker-base".to_string());
    let ce_revision =
        env::var("KIN_LOCATE_CROSS_ENCODER_REVISION").unwrap_or_else(|_| "main".to_string());
    let ce_cached = crate::retrieval_profile::cross_encoder_model_cached(&ce_model, &ce_revision);
    // Report the daemon-serving default (the state queries actually run
    // under), not this one-shot CLI process's own gate. The accessor answers
    // exactly that question, so this check cannot drift from the profile's
    // own definition.
    let ce_active = env::var("KIN_LOCATE_CROSS_ENCODER_ENABLED")
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
        .unwrap_or_else(|_| profile.cross_encoder_daemon_default(ce_cached));
    // Every lever is read back from the profile rather than assumed from its
    // name, so a profile whose defaults change cannot leave this check
    // asserting a lever set the serving path no longer uses.
    //
    // Two levers are deliberately not counted. `declaration_cutoff_default`
    // is dark for EVERY profile pending its A/B graduation gate. The
    // cross-encoder rerank is off by deliberate default: the do-not-flip
    // verdict on it stands, so serving without it is the shipped
    // configuration, not a degradation. Counting either would make the
    // default profile report degraded forever, and a check that can never be
    // green is a check nobody reads. Both still show in the detail line.
    let levers_off: Vec<&str> = [
        (!profile.semantic_locate_fused()).then_some("fused semantic_locate routing"),
        (!profile.entity_fusion_default()).then_some("entity fusion"),
        (!profile.lexical_floor_readmit_default()).then_some("lexical parity floor"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let detail =
        format!(
        "{}profile {} — semantic_locate routing: {}; entity fusion: {}; lexical parity floor: {}; \
         cross-encoder rerank: {} (model {} {})",
        if levers_off.is_empty() {
            ""
        } else {
            "degraded: "
        },
        profile.name(),
        if profile.semantic_locate_fused() {
            "fused locate pipeline"
        } else {
            "cosine-only (compat)"
        },
        if profile.entity_fusion_default() { "on" } else { "off" },
        if profile.lexical_floor_readmit_default() { "on" } else { "off" },
        if ce_active { "on (budget-gated)" } else { "off" },
        ce_model,
        if ce_cached { "cached" } else { "not cached" },
    );
    // A profile serving with levers off is answering worse than this build
    // can, and reporting that as a passing check tells an operator their
    // weakest retrieval configuration is the healthy one. Stale is this
    // report's advisory tier: it renders as a yellow warning and counts as
    // needing attention, without blocking readiness the way
    // Missing/Misconfigured do, because a degraded profile still serves.
    // Every counted lever is on under the shipped default, so a lever-off
    // state can only be a profile someone chose, never a fresh install.
    let status = if levers_off.is_empty() {
        HealthStatus::Healthy
    } else {
        HealthStatus::Stale
    };
    let check = HealthCheck::new(
        "retrieval_profile",
        "Retrieval quality profile",
        status,
        detail,
    );
    if levers_off.is_empty() {
        return check;
    }
    // Name what is off, and name the way back from the default profile's own
    // identifier so this string cannot drift from the enum. The reranker is
    // deliberately absent from this advice: the shipped default keeps it off,
    // and doctor must not argue with the shipped default.
    let default_profile = crate::retrieval_profile::RetrievalProfile::default();
    let mut fix = format!("off: {}", levers_off.join(", "));
    if profile != default_profile {
        fix.push_str(&format!(
            "; unset KIN_PROFILE or set KIN_PROFILE={} for the shipped measured-accuracy defaults",
            default_profile.name()
        ));
    }
    check.with_manual_fix(fix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_core::test_env::EnvVarGuard;
    use serial_test::serial;

    /// A host with no language server must be told which language lost which
    /// edge class, and told it in words rather than as a low relation count.
    /// The graph is unreadable here, which is exactly the state that used to
    /// carry its own row; folding the two rows must not lose the probe.
    #[test]
    fn doctor_names_the_language_whose_missing_server_costs_cross_file_edges() {
        let missing = missing_language_servers(&std::collections::HashSet::new());
        let check = coverage_unreadable(
            HealthStatus::Unsupported,
            "no daemon running for this repository",
            "start the daemon",
            &missing,
        );

        assert!(matches!(check.status, HealthStatus::Stale));
        assert!(
            check.detail.contains("no language server found for"),
            "{}",
            check.detail
        );
        assert!(check.detail.contains("python"), "{}", check.detail);
        assert!(
            check.detail.contains("pyright-langserver"),
            "{}",
            check.detail
        );
        assert!(
            check
                .detail
                .contains("import and call edges are still resolved from source"),
            "the row must not read as a total loss: {}",
            check.detail
        );
        assert!(
            check.detail.contains("no daemon running"),
            "the unread half is reported beside the probed one, in one row: {}",
            check.detail
        );
        assert!(check.manual_fix.is_some());
    }

    /// The counterpart, so the row above cannot be an unconditional warning:
    /// with every wired language's server installed there is no gap to report.
    #[test]
    fn doctor_reports_no_gap_once_every_wired_language_server_is_installed() {
        let installed: std::collections::HashSet<kin_model::LanguageId> =
            crate::commands::graph::LANGUAGE_SERVER_BINARIES
                .iter()
                .map(|(language, _)| *language)
                .collect();
        let missing = missing_language_servers(&installed);
        assert!(missing.is_empty(), "{missing:?}");

        let check = coverage_unreadable(
            HealthStatus::Unsupported,
            "no daemon running for this repository",
            "start the daemon",
            &missing,
        );
        assert!(matches!(check.status, HealthStatus::Unsupported));
        assert!(!check.detail.contains("unavailable"), "{}", check.detail);
    }

    /// A `Stale` row needs attention without failing readiness. A missing
    /// language server degrades a working install; calling it a failure would
    /// turn `kin doctor` red on every host that never installed one.
    #[test]
    fn a_missing_language_server_needs_attention_without_blocking_readiness() {
        let missing = missing_language_servers(&std::collections::HashSet::new());
        let check = coverage_unreadable(
            HealthStatus::Unsupported,
            "no daemon running for this repository",
            "start the daemon",
            &missing,
        );
        assert!(!blocks_readiness(&check));
        let report = assemble_health_report("test".to_string(), vec![check]);
        assert!(report.healthy);
        assert_eq!(report.summary().attention, 1);
    }

    /// FIR-2370. Two rows about one graph teach an operator to skip both, so the
    /// measured completeness and the language-server state are ONE row. This
    /// pins that: when the graph is readable, the single row carries both facts,
    /// and the language-server half is read per language the repository
    /// actually holds rather than probed against every wired language.
    #[test]
    fn one_doctor_row_carries_both_completeness_facts() {
        use kin_core::reference_coverage::{
            LanguageReferenceCoverage, ReferenceEdgeCoverage, ReferenceEnrichment,
            ReferenceResolution,
        };

        let coverage = ReferenceEdgeCoverage {
            languages: vec![LanguageReferenceCoverage {
                language: "python".to_string(),
                files: 12,
                files_measured: 12,
                entities: 46,
                parsed_call_sites: Some(78),
                parsed_import_statements: Some(16),
                resolved_call_edges: 16,
                resolved_import_edges: 0,
                external_module_imports: None,
                cross_file_reference_edges: 0,
                intra_file_reference_edges: 16,
                external_reference_edges: 0,
                resolution: ReferenceResolution::PartiallyResolved,
                reference_enrichment: ReferenceEnrichment::NoLanguageServer,
            }],
            totals: None,
        };

        let check = reference_edge_coverage_health(&coverage);
        assert_eq!(check.id, "reference_edge_coverage");
        assert!(
            check.detail.contains("no cross-file reference edge"),
            "the measured gap: {}",
            check.detail
        );
        assert!(
            check.detail.contains("no language server found"),
            "and the host gap, in the same row: {}",
            check.detail
        );

        // A language the repository holds no source in produces no row at all,
        // so no gap is reported for it. The old second row probed every wired
        // language and warned about rust-analyzer on a Python-only repository.
        assert!(
            !check.detail.contains("rust"),
            "a language this repository holds nothing in is not a gap: {}",
            check.detail
        );
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        use std::io::Write;
        std::fs::File::create(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    fn pass_report(
        name: &str,
        state: &str,
        stopped_reason: Option<&str>,
    ) -> crate::commands::resources::BackgroundPassReport {
        crate::commands::resources::BackgroundPassReport {
            name: name.to_string(),
            state: state.to_string(),
            progress: 128,
            progress_age_seconds: Some(4),
            working_seconds: Some(9),
            deferred_seconds: None,
            stopped_reason: stopped_reason.map(str::to_string),
        }
    }

    #[test]
    fn background_work_is_healthy_while_passes_are_merely_busy() {
        let check =
            background_work_health_from_state(&crate::commands::resources::DaemonWorkState {
                daemon_cpu_seconds: Some(41.6),
                authority_loads: None,
                passes: vec![
                    pass_report("embed", "working", None),
                    pass_report("reconcile", "idle", None),
                ],
                reconcile: Default::default(),
            });
        assert!(matches!(check.status, HealthStatus::Healthy));
        assert!(
            check.detail.contains("42s of CPU"),
            "the check must disclose cumulative CPU: {}",
            check.detail
        );
        assert!(
            check.detail.contains("none stopped"),
            "a busy daemon is not a faulty one: {}",
            check.detail
        );
    }

    /// The failing-admission shape at the `kin health` surface. No pass is
    /// stopped — the reconcile loop is waking, failing, and sleeping on
    /// schedule, which is exactly why the supervisor never stopped it — and the
    /// check still must not answer healthy.
    #[test]
    fn background_work_degrades_when_reconcile_admits_nothing_though_no_pass_is_stopped() {
        let check =
            background_work_health_from_state(&crate::commands::resources::DaemonWorkState {
                daemon_cpu_seconds: Some(9_000.0),
                authority_loads: None,
                passes: vec![
                    pass_report("embed", "idle", None),
                    pass_report("reconcile", "working", None),
                ],
                reconcile: crate::commands::resources::ReconcileHealth {
                    admission_failure_streak: 412,
                    admission_failures: 412,
                    last_admission_error: Some("scan exceeded its budget".to_string()),
                    last_admission_success_age_seconds: Some(172_800),
                    ..Default::default()
                },
            });
        assert!(
            !matches!(check.status, HealthStatus::Healthy),
            "a daemon that has admitted nothing for two days is not healthy: {:?}",
            check.status
        );
        assert!(
            check.detail.contains("412"),
            "the check must name the streak: {}",
            check.detail
        );
        assert!(
            check.detail.contains("scan exceeded its budget"),
            "the daemon's own error must survive to the surface: {}",
            check.detail
        );
    }

    /// The falsification. Identical passes, identical CPU, and a reconcile loop
    /// that is admitting normally. If this reported anything but healthy the
    /// check above would be measuring the passes rather than the admissions.
    #[test]
    fn background_work_stays_healthy_when_reconcile_is_admitting_normally() {
        let check =
            background_work_health_from_state(&crate::commands::resources::DaemonWorkState {
                daemon_cpu_seconds: Some(9_000.0),
                authority_loads: None,
                passes: vec![
                    pass_report("embed", "idle", None),
                    pass_report("reconcile", "working", None),
                ],
                reconcile: crate::commands::resources::ReconcileHealth {
                    admission_failures: 2,
                    last_admission_success_age_seconds: Some(3),
                    ..Default::default()
                },
            });
        assert!(matches!(check.status, HealthStatus::Healthy));
        assert!(
            check.detail.contains("reconcile admitting normally"),
            "a healthy verdict must say what it checked, or its silence is \
             indistinguishable from never having looked: {}",
            check.detail
        );
    }

    /// The falsification: the same shape with a stopped pass must NOT read
    /// healthy, and must carry the daemon's own reason rather than a summary
    /// invented here.
    #[test]
    fn background_work_reports_a_stopped_pass_and_repeats_its_reason() {
        let check =
            background_work_health_from_state(&crate::commands::resources::DaemonWorkState {
                daemon_cpu_seconds: Some(48_180.0),
                authority_loads: None,
                passes: vec![
                    pass_report(
                        "embed",
                        "stopped",
                        Some("the embed pass held the CPU for 601s"),
                    ),
                    pass_report("reconcile", "idle", None),
                ],
                reconcile: Default::default(),
            });
        assert!(matches!(check.status, HealthStatus::Stale));
        assert!(check
            .detail
            .contains("the embed pass held the CPU for 601s"));
        assert!(check.manual_fix.is_some());
    }

    #[test]
    fn background_work_says_so_when_cpu_has_not_been_sampled() {
        let check = background_work_health_from_state(
            &crate::commands::resources::DaemonWorkState::default(),
        );
        assert!(matches!(check.status, HealthStatus::Healthy));
        assert!(
            check.detail.contains("not sampled yet"),
            "an unsampled total must not be reported as zero CPU: {}",
            check.detail
        );
    }

    /// The magic bytes a valid shim carries on the current platform.
    fn platform_object_magic() -> &'static [u8] {
        if cfg!(target_os = "macos") {
            &[0xCF, 0xFA, 0xED, 0xFE] // MH_MAGIC_64 as it lands on disk
        } else if cfg!(target_os = "linux") {
            b"\x7fELF"
        } else {
            &[0x00, 0x01, 0x02, 0x03]
        }
    }

    #[test]
    fn classify_shim_flags_missing_empty_and_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("libkin_vfs_shim");

        assert_eq!(classify_shim(&path), ShimState::Missing);

        write_file(&path, b"");
        assert_eq!(classify_shim(&path), ShimState::Empty);

        // A non-empty blob without object-file magic is a truncated/corrupt
        // artifact on the platforms that enforce a magic.
        write_file(&path, b"this is not a shared library");
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            assert_eq!(classify_shim(&path), ShimState::Invalid);
        }
    }

    #[test]
    fn classify_shim_accepts_a_real_object_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("libkin_vfs_shim");
        let mut bytes = platform_object_magic().to_vec();
        bytes.extend_from_slice(&[0u8; 128]);
        write_file(&path, &bytes);
        assert!(matches!(classify_shim(&path), ShimState::Valid(_)));
    }

    // ---- Projection in force -------------------------------------------

    use crate::commands::projection::{
        DriverProbe, LiveProjection, ModeProbe, ProjectionMode, ProjectionReport, ShimPresence, Tri,
    };

    /// The row as a macOS host reads it. Every fixture below is about a
    /// macOS/Linux machine, and naming the platform once keeps them from
    /// silently changing meaning on whichever host runs the suite.
    fn projection_mode_check_for_macos(
        report: &crate::commands::projection::ProjectionReport,
    ) -> HealthCheck {
        projection_mode_check_for(report, "macos")
    }

    fn mode_probe(mode: ProjectionMode, available: bool) -> ModeProbe {
        ModeProbe {
            mode,
            available,
            evidence: format!("{mode} fixture probe"),
            remedy: (!available).then(|| format!("fixture remedy for {mode}")),
        }
    }

    fn report(
        recorded: Option<ProjectionMode>,
        available: &[ProjectionMode],
        live: LiveProjection,
    ) -> ProjectionReport {
        ProjectionReport {
            recorded,
            modes: [
                ProjectionMode::Nfs,
                ProjectionMode::Fuse,
                ProjectionMode::Shim,
            ]
            .into_iter()
            .map(|mode| mode_probe(mode, available.contains(&mode)))
            .collect(),
            driver: DriverProbe {
                path: None,
                refusal: None,
                subcommands: None,
            },
            shim: ShimPresence {
                path: PathBuf::from("/home/u/.kin/lib/libkin_vfs_shim.so"),
                installed: available.contains(&ProjectionMode::Shim),
                engaged: false,
            },
            live,
        }
    }

    fn live(
        intent: ProjectionMode,
        mode: ProjectionMode,
        mounted: Tri,
        readable: Tri,
        degraded: bool,
    ) -> LiveProjection {
        LiveProjection {
            intent,
            mode,
            at: PathBuf::from("/w/repo"),
            mounted,
            readable,
            writable: Tri::NotApplicable,
            degraded,
            evidence: vec!["fixture evidence".to_string()],
        }
    }

    /// The three fixtures the row exists to tell apart: everything present, no
    /// shim anywhere, and a configured mount that is not mounted. Each has to
    /// produce a different status and a different detail, or the row is
    /// decorative.
    #[test]
    fn the_projection_row_changes_across_the_three_fixtures() {
        let working = projection_mode_check_for_macos(&report(
            Some(ProjectionMode::Shim),
            &[ProjectionMode::Shim],
            live(
                ProjectionMode::Shim,
                ProjectionMode::Shim,
                Tri::NotApplicable,
                Tri::Yes,
                false,
            ),
        ));
        assert!(
            matches!(working.status, HealthStatus::Healthy),
            "a working projection is healthy, got {:?}",
            working.status
        );

        let nothing = projection_mode_check_for_macos(&report(
            None,
            &[],
            live(
                ProjectionMode::Shim,
                ProjectionMode::Shim,
                Tri::NotApplicable,
                Tri::No,
                true,
            ),
        ));
        assert!(
            matches!(nothing.status, HealthStatus::Unsupported),
            "an install that ships without projection and configures none stays skipped, got {:?}",
            nothing.status
        );
        assert!(!is_failing(&nothing.status));

        let unmounted = projection_mode_check_for_macos(&report(
            Some(ProjectionMode::Nfs),
            &[ProjectionMode::Shim],
            live(
                ProjectionMode::Nfs,
                ProjectionMode::Shim,
                Tri::No,
                Tri::No,
                true,
            ),
        ));
        assert!(
            matches!(unmounted.status, HealthStatus::Misconfigured),
            "a configured mount that is not running must fail, got {:?}",
            unmounted.status
        );
        assert!(is_failing(&unmounted.status));
        assert!(
            unmounted.detail.contains("nfs is recorded"),
            "the row must name the mode that was configured: {}",
            unmounted.detail
        );
        assert_eq!(
            unmounted.manual_fix.as_deref(),
            Some("fixture remedy for nfs"),
            "the configured mode's own remedy must reach the row"
        );

        let details = [&working.detail, &nothing.detail, &unmounted.detail];
        for (i, a) in details.iter().enumerate() {
            for b in details.iter().skip(i + 1) {
                assert_ne!(a, b, "each fixture must read differently");
            }
        }
    }

    /// A shim installed and not injected is the container case. It must be
    /// visible and must not be healthy, and it must not fail readiness either:
    /// running `kin` from an editor terminal without the shell hook is ordinary
    /// and would otherwise fail every install that works.
    #[test]
    fn an_installed_but_unengaged_shim_is_visible_without_failing_readiness() {
        let check = projection_mode_check_for_macos(&report(
            None,
            &[ProjectionMode::Shim],
            live(
                ProjectionMode::Shim,
                ProjectionMode::Shim,
                Tri::NotApplicable,
                Tri::Yes,
                true,
            ),
        ));
        assert!(
            matches!(check.status, HealthStatus::Stale),
            "an unengaged shim is advisory, got {:?}",
            check.status
        );
        assert!(!matches!(check.status, HealthStatus::Healthy));
        assert!(!is_failing(&check.status));
        assert!(check
            .manual_fix
            .as_deref()
            .is_some_and(|fix| fix.contains("new shell")));
    }

    /// The container case, at the row level. A driver the loader refuses
    /// leaves no mode available, which is the same shape as a machine that
    /// shipped without projection, and the two must not produce the same row:
    /// one is fine and the other is every process on the box reading raw disk.
    #[test]
    fn a_refused_driver_is_not_a_sanctioned_absence() {
        let mut refused = report(
            None,
            &[],
            live(
                ProjectionMode::Shim,
                ProjectionMode::Shim,
                Tri::NotApplicable,
                Tri::Yes,
                true,
            ),
        );
        refused.driver = DriverProbe {
            path: Some(PathBuf::from("/opt/kin/kin-vfs")),
            refusal: Some("GLIBC_2.39 not found".to_string()),
            subcommands: None,
        };
        refused.shim.installed = true;

        let check = projection_mode_check_for_macos(&refused);
        assert!(
            is_failing(&check.status),
            "a projection installed and dead must fail, got {:?}",
            check.status
        );

        // Falsification: the same shape with genuinely nothing installed stays
        // the sanctioned green n/a, so the failure above is about the refusal
        // and not about there being no available mode.
        let bare = report(
            None,
            &[],
            live(
                ProjectionMode::Shim,
                ProjectionMode::Shim,
                Tri::NotApplicable,
                Tri::Yes,
                true,
            ),
        );
        assert!(
            matches!(
                projection_mode_check_for_macos(&bare).status,
                HealthStatus::Unsupported
            ),
            "an install that ships without projection stays skipped"
        );
    }

    /// Windows has no sanctioned absence. ProjFS ships on every SKU and only
    /// needs enabling, so a Windows machine with no projection running is
    /// always one someone can fix, and the row that tells a macOS user nothing
    /// is missing would be a lie there.
    #[test]
    fn windows_never_reports_that_nothing_is_missing() {
        // The floor decides it, and the floor is the platform's, not a constant.
        assert_eq!(
            crate::commands::projection::floor_mode("windows"),
            ProjectionMode::ProjFs
        );
        assert_eq!(
            crate::commands::projection::floor_mode("macos"),
            ProjectionMode::Shim
        );

        // ProjFS off, with the exact remedy a user pastes.
        let off = crate::commands::projection::projfs_mode_probe(
            &crate::commands::projection::ProjFsState::FeatureOff,
        );
        assert!(!off.available);
        assert!(off.remedy.as_deref().is_some_and(|remedy| remedy
            .contains("Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS")));

        // One machine shape, nothing available and nothing recorded, judged as
        // each platform. macOS keeps the sanctioned skip because the installer
        // is allowed to ship without projection there. Windows must not have
        // it, and asserting both from one host is the whole reason the platform
        // is an argument rather than something this function reads.
        let bare = report(
            None,
            &[],
            live(
                ProjectionMode::Shim,
                ProjectionMode::Shim,
                Tri::NotApplicable,
                Tri::Yes,
                true,
            ),
        );

        for os in ["macos", "linux"] {
            let check = projection_mode_check_for(&bare, os);
            assert!(
                matches!(check.status, HealthStatus::Unsupported),
                "{os} keeps the sanctioned skip, got {:?}",
                check.status
            );
            assert!(!is_failing(&check.status));
        }

        let windows = projection_mode_check_for(&bare, "windows");
        assert!(
            !matches!(windows.status, HealthStatus::Unsupported),
            "Windows has no sanctioned skip, got {:?}",
            windows.status
        );
        assert!(
            !windows.detail.contains("none is configured")
                && windows
                    .platform_note
                    .as_deref()
                    .is_none_or(|note| !note.contains("would need")),
            "Windows must not be told that nothing is missing: {windows:?}"
        );
    }

    /// The green n/a on the install row is true only while nobody chose a
    /// projection. Once a mode is recorded the same machine state is a
    /// configured projection that is not installed, and "nothing is missing" is
    /// the confident negative this row keeps producing when nothing checks.
    #[test]
    fn a_recorded_mode_turns_the_sanctioned_absence_into_a_defect() {
        let dir = tempfile::tempdir().unwrap();
        let missing_shim = dir.path().join("no-shim");

        let unconfigured =
            vfs_projection_check_for_recorded(&missing_shim, &VfsDriverState::Absent, None);
        assert!(
            matches!(unconfigured.status, HealthStatus::Unsupported),
            "with nothing configured the absence stays sanctioned, got {:?}",
            unconfigured.status
        );
        assert!(
            unconfigured
                .platform_note
                .as_deref()
                .is_some_and(|note| note.contains("nothing is missing")),
            "the sanctioned row is the one that says nothing is missing"
        );

        let configured = vfs_projection_check_for_recorded(
            &missing_shim,
            &VfsDriverState::Absent,
            Some(ProjectionMode::Nfs),
        );
        assert!(
            is_failing(&configured.status),
            "a recorded mode with nothing installed must fail, got {:?}",
            configured.status
        );
        assert!(
            configured.detail.contains("nfs is recorded"),
            "the row must name what was configured: {}",
            configured.detail
        );
        assert!(
            !configured.detail.contains("nothing is missing") && configured.platform_note.is_none(),
            "the sanctioned wording must not survive a recorded mode: {configured:?}"
        );

        // A recorded mode does not rewrite a row that already had something to
        // say: a broken driver stays a broken driver, with the loader's words.
        let broken = vfs_projection_check_for_recorded(
            &missing_shim,
            &VfsDriverState::Unloadable {
                path: PathBuf::from("/opt/kin/kin-vfs"),
                message: "GLIBC_2.39 not found".to_string(),
            },
            Some(ProjectionMode::Shim),
        );
        assert!(broken.detail.contains("GLIBC_2.39"), "{}", broken.detail);
    }

    #[test]
    fn macho_magic_matches_the_shipped_dylib_header() {
        // The v0.2.x macOS shim begins CF FA ED FE (MH_MAGIC_64 little-endian).
        assert!(is_macho_magic(&[0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00]));
        assert!(!is_macho_magic(b"junk"));
        assert!(!is_macho_magic(&[0xCF, 0xFA])); // too short
    }

    #[test]
    fn vfs_remediation_never_points_back_at_the_failed_fix() {
        // The repair text for a broken shim must name a real working
        // step, never `kin doctor --fix` (the command that just failed).
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let empty = dir.path().join("empty");
        write_file(&empty, b"");
        let corrupt = dir.path().join("corrupt");
        write_file(&corrupt, b"not an object file");

        let driver = VfsDriverState::Loadable(dir.path().join(vfs_binary_filename()));
        for path in [&missing, &empty, &corrupt] {
            let check = vfs_projection_check_for(path, &driver);
            assert!(check.fixable, "{}: should be fixable", path.display());
            let fix = check.manual_fix.clone().unwrap_or_default();
            assert!(!fix.is_empty(), "{}: missing manual fix", path.display());
            assert!(
                !fix.contains("doctor --fix"),
                "{}: circular fix text: {fix}",
                path.display()
            );
        }
    }

    /// A shim absent on a machine that never installed projection is the
    /// installer's own sanctioned outcome, and must not be scored as a defect
    /// or answered with a reinstall the installer already declined to perform.
    /// The same absent shim on a machine that *does* carry the projection
    /// driver is a real missing artifact and stays a failure.
    #[test]
    fn absent_shim_is_a_failure_only_where_projection_was_installed() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("libkin_vfs_shim");

        let uninstalled = vfs_projection_check_for(&missing, &VfsDriverState::Absent);
        assert!(
            matches!(uninstalled.status, HealthStatus::Unsupported),
            "no projection on this machine must be skipped, got {:?}",
            uninstalled.status
        );
        assert!(!is_failing(&uninstalled.status));
        assert!(
            !uninstalled.fixable,
            "a machine with no projection must not be offered a shim repair"
        );
        assert!(
            uninstalled.manual_fix.is_none(),
            "must not send a user to reinstall for something the installer removed on purpose"
        );
        assert!(uninstalled.platform_note.is_some());

        // Falsification: flip only the driver state, keep the same path.
        let installed = vfs_projection_check_for(
            &missing,
            &VfsDriverState::Loadable(dir.path().join(vfs_binary_filename())),
        );
        assert!(
            matches!(installed.status, HealthStatus::Missing),
            "a shim missing where projection is installed must stay a failure, got {:?}",
            installed.status
        );
        assert!(is_failing(&installed.status));
        assert!(installed.fixable);
        assert_eq!(installed.manual_fix.as_deref(), Some(SHIM_REINSTALL_HINT));
    }

    /// A corrupt shim is a failure whether or not the driver is present: the
    /// bytes on disk are the proof, and a 0-byte injected library crashes every
    /// process it is loaded into.
    #[test]
    fn a_corrupt_shim_stays_a_failure_even_with_no_projection_driver() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        write_file(&empty, b"");
        let corrupt = dir.path().join("corrupt");
        write_file(&corrupt, b"not an object file");

        for path in [&empty, &corrupt] {
            let check = vfs_projection_check_for(path, &VfsDriverState::Absent);
            if cfg!(any(target_os = "macos", target_os = "linux")) || path == &empty {
                assert!(
                    is_failing(&check.status),
                    "{}: corrupt shim must stay a failure, got {:?}",
                    path.display(),
                    check.status
                );
            }
        }
    }

    /// The driver the user just ran `kin` from is the one to judge. An archive
    /// or Homebrew install puts `kin-vfs` beside the `kin` binary rather than in
    /// `~/.kin/bin`, and looking only in `~/.kin/bin` reported that driver as
    /// absent.
    #[test]
    fn the_driver_beside_the_running_binary_is_a_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("opt/kin");
        std::fs::create_dir_all(&install).unwrap();
        let exe = install.join("kin");
        write_file(&exe, b"kin");

        let candidates = vfs_driver_candidates(None, &dir.path().join("kin-home"), Some(&exe));
        assert!(
            candidates.contains(&install.join(vfs_binary_filename())),
            "a driver beside the running binary must be probed: {candidates:?}"
        );
        assert!(
            candidates.contains(
                &dir.path()
                    .join("kin-home")
                    .join("bin")
                    .join(vfs_binary_filename())
            ),
            "the managed location must still be probed: {candidates:?}"
        );
    }

    /// A pinned driver replaces the search rather than joining it. A pin that
    /// resolved to some other driver when the named one is missing would report
    /// on a binary the operator did not name, which is the failure a pin exists
    /// to prevent.
    #[test]
    fn a_pinned_driver_is_the_only_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("opt/kin/kin");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        write_file(&exe, b"kin");
        let pinned = dir.path().join("built/kin-vfs");

        let candidates =
            vfs_driver_candidates(Some(&pinned), &dir.path().join("kin-home"), Some(&exe));
        assert_eq!(candidates, vec![pinned.clone()]);

        // Falsification: without the pin the same call searches every location.
        let searched = vfs_driver_candidates(None, &dir.path().join("kin-home"), Some(&exe));
        assert!(
            searched.len() > 1 && !searched.contains(&pinned),
            "an unpinned search must look in the ordinary places: {searched:?}"
        );

        // A pin naming a file that is not there is an absent driver, not a
        // fallback to whatever else the host happens to carry.
        assert_eq!(
            resolve_vfs_driver(&candidates),
            VfsDriverState::Absent,
            "a pin to a missing file reports absence"
        );
    }

    /// Write an executable stand-in for the projection driver.
    #[cfg(unix)]
    fn write_driver(path: &Path, script: &str) {
        use std::os::unix::fs::PermissionsExt;
        write_file(path, script.as_bytes());
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A driver the loader refuses is not an absent driver. The linux-aarch64
    /// archive shipped a `kin-vfs` requiring a newer glibc than the host had,
    /// and the check reported "neither is present here" with both files sitting
    /// beside the `kin` binary it had just resolved by full path.
    #[test]
    #[cfg(unix)]
    fn a_driver_that_will_not_load_is_reported_as_broken_rather_than_absent() {
        let dir = tempfile::tempdir().unwrap();
        let driver = dir.path().join(vfs_binary_filename());
        write_driver(
            &driver,
            "#!/bin/sh\necho \"kin-vfs: /lib/libc.so.6: version GLIBC_2.39 not found\" >&2\nexit 127\n",
        );

        let state = resolve_vfs_driver(std::slice::from_ref(&driver));
        let VfsDriverState::Unloadable { path, message } = &state else {
            panic!("a driver that refuses to run must be Unloadable, got {state:?}");
        };
        assert_eq!(path, &driver);
        assert!(
            message.contains("GLIBC_2.39"),
            "the loader's own words must reach the report: {message}"
        );

        let check = vfs_projection_check_for(&dir.path().join("no-shim"), &state);
        assert!(
            is_failing(&check.status),
            "a driver that cannot run must need attention, got {:?}",
            check.status
        );
        assert!(
            check.detail.contains("GLIBC_2.39")
                && check.detail.contains(&driver.display().to_string()),
            "the row must name the driver and quote the loader: {}",
            check.detail
        );
        let fix = check.manual_fix.clone().unwrap_or_default();
        assert!(!fix.is_empty(), "a broken driver must carry a remediation");
        assert!(!fix.contains("doctor --fix"), "circular fix text: {fix}");

        // Falsification: the same missing shim with no driver anywhere is the
        // installer's sanctioned outcome and stays a green n/a.
        let absent = vfs_projection_check_for(&dir.path().join("no-shim"), &VfsDriverState::Absent);
        assert!(
            matches!(absent.status, HealthStatus::Unsupported),
            "an absent driver must stay skipped, got {:?}",
            absent.status
        );
        assert!(!is_failing(&absent.status));
    }

    /// The probe may not require a successful exit. The shipped `kin-vfs` takes
    /// a subcommand and carries no `--version`, so it answers an unknown flag
    /// with a clap usage error and exit 2 on a healthy install. Scoring that as
    /// a driver that will not load fails every install that works.
    #[test]
    #[cfg(unix)]
    fn a_driver_answering_with_a_usage_error_still_counts_as_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let driver = dir.path().join(vfs_binary_filename());
        write_driver(
            &driver,
            "#!/bin/sh\necho \"error: unexpected argument found\" >&2\nexit 2\n",
        );

        assert_eq!(
            resolve_vfs_driver(std::slice::from_ref(&driver)),
            VfsDriverState::Loadable(driver.clone()),
            "a driver that ran and complained about arguments is installed and loadable"
        );

        // Falsification: the loader's own refusal exits 127 and stays broken.
        let refused = dir.path().join("refused").join(vfs_binary_filename());
        std::fs::create_dir_all(refused.parent().unwrap()).unwrap();
        write_driver(
            &refused,
            "#!/bin/sh\necho 'libc.so.6: version not found' >&2\nexit 127\n",
        );
        assert!(
            matches!(
                resolve_vfs_driver(std::slice::from_ref(&refused)),
                VfsDriverState::Unloadable { .. }
            ),
            "a loader refusal must still be caught"
        );
    }

    /// Absent, present and loadable, present and unloadable must be three
    /// different rows. They were two: the first two were the same green n/a,
    /// and the third had no way to be said at all.
    #[test]
    #[cfg(unix)]
    fn the_three_driver_states_are_three_different_rows() {
        let dir = tempfile::tempdir().unwrap();
        let missing_shim = dir.path().join("no-shim");

        let working = dir.path().join("works").join(vfs_binary_filename());
        std::fs::create_dir_all(working.parent().unwrap()).unwrap();
        write_driver(&working, "#!/bin/sh\necho 'kin-vfs 0.0.0-test'\n");
        let loadable = resolve_vfs_driver(std::slice::from_ref(&working));
        assert_eq!(loadable, VfsDriverState::Loadable(working.clone()));

        let broken = dir.path().join("broken").join(vfs_binary_filename());
        std::fs::create_dir_all(broken.parent().unwrap()).unwrap();
        write_driver(&broken, "#!/bin/sh\nexit 127\n");

        let absent = vfs_projection_check_for(&missing_shim, &VfsDriverState::Absent);
        let installed = vfs_projection_check_for(&missing_shim, &loadable);
        let unloadable = vfs_projection_check_for(
            &missing_shim,
            &resolve_vfs_driver(std::slice::from_ref(&broken)),
        );

        assert!(matches!(absent.status, HealthStatus::Unsupported));
        assert!(matches!(installed.status, HealthStatus::Missing));
        assert!(matches!(unloadable.status, HealthStatus::Misconfigured));
        assert!(
            installed.detail.contains(&working.display().to_string()),
            "a driver that runs must be named as running: {}",
            installed.detail
        );
        let details = [&absent.detail, &installed.detail, &unloadable.detail];
        for (i, left) in details.iter().enumerate() {
            for right in details.iter().skip(i + 1) {
                assert_ne!(left, right, "two states must never print the same row");
            }
        }
    }

    /// A repository that has never started a daemon is the resting state every
    /// `kin init` finishes in, so it is skipped. An endpoint record left behind
    /// by a daemon that is no longer reachable is a real leftover and stays
    /// flagged.
    #[test]
    fn daemon_not_running_is_skipped_until_one_has_actually_been_started() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join("daemon.pid");

        let never_started = daemon_not_running_check_for("/repo", &record);
        assert!(
            matches!(never_started.status, HealthStatus::Unsupported),
            "a repo with no daemon record must be skipped, got {:?}",
            never_started.status
        );
        assert!(never_started.detail.contains("/repo"));
        assert!(never_started.manual_fix.is_some());

        // Falsification: publish the record, change nothing else.
        write_file(&record, b"4242");
        let left_behind = daemon_not_running_check_for("/repo", &record);
        assert!(
            matches!(left_behind.status, HealthStatus::Stale),
            "an unreachable daemon that left its endpoint record must stay flagged, got {:?}",
            left_behind.status
        );
        assert!(left_behind.detail.contains("daemon.pid"));
        assert!(left_behind.manual_fix.is_some());
        // Neither arm may hard-fail: the daemon is started on demand.
        assert!(!is_failing(&never_started.status));
        assert!(!is_failing(&left_behind.status));
    }

    /// Not being in a repository is the next step of the quickstart, not a
    /// broken install. A directory carrying a `.kin` the layout refuses is a
    /// partial repository and stays a failure — except the managed toolchain
    /// directory, which is where the CLI installs itself.
    #[test]
    fn outside_a_repository_is_skipped_but_a_refused_dot_kin_is_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        std::fs::create_dir_all(&plain).unwrap();

        let outside = repo_init_check_for(&plain, None, None);
        assert!(
            matches!(outside.status, HealthStatus::Unsupported),
            "a directory that is simply not a repo must be skipped, got {:?}",
            outside.status
        );
        assert!(!is_failing(&outside.status));
        assert!(outside.manual_fix.unwrap().contains("kin init"));

        // Falsification: add the `.kin` a partial init leaves behind, keep the
        // same refused layout.
        let partial = dir.path().join("partial");
        std::fs::create_dir_all(partial.join(".kin")).unwrap();
        let refused = repo_init_check_for(&partial, None, None);
        assert!(
            matches!(refused.status, HealthStatus::Missing),
            "a `.kin` the layout refuses must stay a failure, got {:?}",
            refused.status
        );
        assert!(is_failing(&refused.status));

        // The managed toolchain directory is not a failed repository.
        let home = dir.path().join("home");
        let toolchain = home.join(".kin");
        std::fs::create_dir_all(&toolchain).unwrap();
        let toolchain_home = repo_init_check_for(&home, None, Some(&toolchain));
        assert!(
            matches!(toolchain_home.status, HealthStatus::Unsupported),
            "~/.kin is the toolchain dir, not a failed repository, got {:?}",
            toolchain_home.status
        );
    }

    /// Kin owns one key inside an AI client's config, never the file. A config
    /// with no kin entry that Kin never wrote to is a client Kin is simply not
    /// registered with; the same absence in a config the install ledger records
    /// means Kin's own entry was removed, which is a real regression.
    #[test]
    fn a_config_kin_never_wrote_does_not_fail_kin() {
        let path = Path::new("/tmp/third-party/mcp_config.json");

        let untouched = mcp_client_check_from(
            "cursor",
            "Cursor",
            path,
            HealthStatus::Missing,
            "no mcpServers.kin entry".to_string(),
            false,
        );
        assert_eq!(untouched.id, "mcp_client_cursor");
        assert!(
            matches!(untouched.status, HealthStatus::Unsupported),
            "a third-party config Kin never wrote must not fail Kin, got {:?}",
            untouched.status
        );
        assert!(!is_failing(&untouched.status));
        assert!(
            untouched.fixable && untouched.manual_fix.is_some(),
            "the offer to register must survive the reclassification"
        );

        // Falsification: flip only the ledger record.
        let removed = mcp_client_check_from(
            "cursor",
            "Cursor",
            path,
            HealthStatus::Missing,
            "no mcpServers.kin entry".to_string(),
            true,
        );
        assert!(
            matches!(removed.status, HealthStatus::Missing),
            "an entry Kin recorded writing and that is now gone must stay a failure, got {:?}",
            removed.status
        );
        assert!(is_failing(&removed.status));

        // A kin entry that exists and is wrong is Kin's own broken binding, and
        // stays a failure whoever owns the surrounding file.
        let broken = mcp_client_check_from(
            "cursor",
            "Cursor",
            path,
            HealthStatus::Misconfigured,
            "mcpServers.kin uses the retired `--global` mode".to_string(),
            false,
        );
        assert!(
            matches!(broken.status, HealthStatus::Misconfigured),
            "a present-but-broken kin entry must stay a failure, got {:?}",
            broken.status
        );
        assert!(is_failing(&broken.status));
        assert!(broken.detail.contains("--global"));
    }

    fn shell_state(
        hook_installed: bool,
        recorded_by_setup: bool,
    ) -> ShellIntegrationState<'static> {
        ShellIntegrationState {
            shell: "zsh",
            hook_path: Path::new("/home/u/.kin/shell/kin-vfs.zsh"),
            rc_display: "/home/u/.zshrc",
            bin_dir: Path::new("/home/u/.kin/bin"),
            bin_dir_present: true,
            hook_installed,
            rc_sources: hook_installed,
            on_path: hook_installed,
            rc_sets_path: hook_installed,
            recorded_by_setup,
        }
    }

    /// The install page publishes `KIN_NO_SETUP=1`, the installer honors it and
    /// says to run `kin setup` when ready, and this check then scored that exact
    /// state a failure. A hook Kin never claimed to install is not Kin's
    /// failure; one it did claim and that is now gone is.
    #[test]
    fn a_shell_hook_setup_never_installed_does_not_fail_kin() {
        let unconfigured = shell_path_check_from(shell_state(false, false));
        assert_eq!(unconfigured.id, "shell_path");
        assert!(
            matches!(unconfigured.status, HealthStatus::Unsupported),
            "a shell setup never touched must not fail Kin, got {:?}",
            unconfigured.status
        );
        assert!(!is_failing(&unconfigured.status));
        assert!(
            unconfigured.fixable && unconfigured.manual_fix.is_some(),
            "the offer to install the hook must survive the reclassification"
        );
        assert!(
            unconfigured
                .manual_fix
                .as_deref()
                .is_some_and(|fix| fix.contains("kin setup")),
            "the remedy must name the command that installs the hook"
        );

        // Falsification: flip only the ledger record.
        let removed = shell_path_check_from(shell_state(false, true));
        assert!(
            matches!(removed.status, HealthStatus::Misconfigured),
            "a hook setup recorded installing and that is now gone must stay a \
             failure, got {:?}",
            removed.status
        );
        assert!(is_failing(&removed.status));
        assert!(removed.detail.contains("hook missing at"));

        // A working integration is healthy whether or not a ledger records it:
        // an older install predates the ledger and is not broken by its absence.
        for recorded in [false, true] {
            let healthy = shell_path_check_from(shell_state(true, recorded));
            assert!(
                matches!(healthy.status, HealthStatus::Healthy),
                "an installed and sourced hook is healthy, got {:?}",
                healthy.status
            );
        }

        // A hook on disk that nothing sources is a real misconfiguration even
        // with no ledger behind it. Kin's artifact is right there, so the
        // not-configured-yet wording would be a false statement about a state
        // the user can see, and reclassifying it would be the half-corrected
        // surface this class of fix is supposed to avoid.
        let mut present_but_unsourced = shell_state(false, false);
        present_but_unsourced.hook_installed = true;
        let stranded = shell_path_check_from(present_but_unsourced);
        assert!(
            matches!(stranded.status, HealthStatus::Misconfigured),
            "an installed but unsourced hook must stay a failure, got {:?}",
            stranded.status
        );
        assert!(is_failing(&stranded.status));
        assert!(
            !stranded.detail.contains("has not installed"),
            "the detail must not claim no hook exists when one does: {}",
            stranded.detail
        );
    }

    /// The sixth check of this class. A machine healthy except for never having
    /// run setup must tally no failures, or the footer still closes red on a
    /// perfectly good install.
    #[test]
    fn a_never_configured_shell_leaves_the_summary_without_failures() {
        let report = assemble_health_report(
            "test".to_string(),
            vec![
                check_with("kin_binary", HealthStatus::Healthy),
                check_with("kin_daemon_binary", HealthStatus::Healthy),
                shell_path_check_from(shell_state(false, false)),
            ],
        );
        let summary = report.summary();
        assert_eq!(
            summary.attention, 0,
            "a healthy install that has not run setup must report nothing needing attention"
        );
        assert_eq!(summary.passed, 2);
        assert_eq!(summary.skipped, 1);
        assert!(
            report.healthy,
            "the footer must close green on an install whose only unconfigured surface is one setup was told not to touch"
        );

        // Falsification: the same machine with a hook setup recorded and now
        // gone must still close red.
        let regressed = assemble_health_report(
            "test".to_string(),
            vec![
                check_with("kin_binary", HealthStatus::Healthy),
                check_with("kin_daemon_binary", HealthStatus::Healthy),
                shell_path_check_from(shell_state(false, true)),
            ],
        );
        assert_eq!(regressed.summary().attention, 1);
        assert!(!regressed.healthy);
    }

    #[cfg(feature = "vector")]
    #[test]
    fn semantic_readiness_is_unread_not_failed_when_no_daemon_is_running() {
        let check = semantic_query_readiness_without_a_daemon();
        assert!(
            matches!(check.status, HealthStatus::Unsupported),
            "an unstarted daemon is an unread state, got {:?}",
            check.status
        );
        assert!(!is_failing(&check.status));
        assert!(check.manual_fix.is_some());
        assert!(!blocks_readiness(&check));

        // Falsification: the states that CAN be read still gate readiness.
        let unreadable = HealthCheck::new(
            "semantic_query_readiness",
            "Semantic query readiness",
            HealthStatus::Stale,
            "daemon reachable, but graph embedding status is unavailable",
        );
        assert!(blocks_readiness(&unreadable));
    }

    /// FIR-2358. A graph whose reference edges did not resolve must say so on
    /// the doctor surface, because every other readiness signal points away from
    /// the gap: `kin languages` lists the language as fully extracted and
    /// `graph validate` passes on its integrity.
    #[test]
    fn reference_edge_coverage_needs_attention_when_absence_is_unanswerable() {
        use kin_core::reference_coverage::{
            LanguageReferenceCoverage, ReferenceEdgeCoverage, ReferenceEnrichment,
            ReferenceResolution,
        };

        fn python(cross_file: u64, resolved_calls: u64) -> ReferenceEdgeCoverage {
            ReferenceEdgeCoverage {
                languages: vec![LanguageReferenceCoverage {
                    language: "python".to_string(),
                    files: 12,
                    files_measured: 12,
                    entities: 46,
                    parsed_call_sites: Some(78),
                    parsed_import_statements: Some(16),
                    resolved_call_edges: resolved_calls,
                    resolved_import_edges: 0,
                    external_module_imports: None,
                    cross_file_reference_edges: cross_file,
                    intra_file_reference_edges: 16,
                    external_reference_edges: 0,
                    resolution: ReferenceResolution::PartiallyResolved,
                    reference_enrichment: ReferenceEnrichment::Available,
                }],
                totals: None,
            }
        }

        let gap = reference_edge_coverage_health(&python(0, 16));
        assert!(
            matches!(gap.status, HealthStatus::Pending),
            "{:?}: {}",
            gap.status,
            gap.detail
        );
        assert!(
            gap.detail.contains("no cross-file reference edge"),
            "the row names the measured gap: {}",
            gap.detail
        );
        assert!(
            !blocks_readiness(&gap),
            "the graph still answers about the edges it holds, so this needs attention without \
             failing readiness"
        );

        let resolved = reference_edge_coverage_health(&python(41, 57));
        assert!(
            matches!(resolved.status, HealthStatus::Healthy),
            "{:?}: {}",
            resolved.status,
            resolved.detail
        );
        assert!(
            resolved.detail.contains("41 cross-file"),
            "the healthy row still reports the numbers it passed on: {}",
            resolved.detail
        );

        let empty = reference_edge_coverage_health(&ReferenceEdgeCoverage::default());
        assert!(
            matches!(empty.status, HealthStatus::Healthy),
            "{:?}: {}",
            empty.status,
            empty.detail
        );
    }

    /// The headline: a fresh install that did everything right ends green.
    /// Every state below is what a correct install actually produces, and the
    /// old classification made four of them flip the summary to a red X.
    #[test]
    fn a_correct_fresh_install_reports_ready() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();

        let checks = vec![
            check_with("kin_binary", HealthStatus::Healthy),
            check_with("kin_daemon_binary", HealthStatus::Healthy),
            vfs_projection_check_for(&dir.path().join("no-shim"), &VfsDriverState::Absent),
            repo_init_check_for(&repo, None, None),
            daemon_not_running_check_for("/repo", &dir.path().join("daemon.pid")),
            mcp_client_check_from(
                "claude",
                "Claude Code",
                Path::new("/tmp/third-party/.claude.json"),
                HealthStatus::Missing,
                "no mcpServers.kin entry".to_string(),
                false,
            ),
        ];
        let report = assemble_health_report("test".to_string(), checks);
        let summary = report.summary();

        assert!(
            report.healthy,
            "a correct fresh install must not report as broken: {:?}",
            report
                .checks
                .iter()
                .filter(|check| blocks_readiness(check))
                .map(|check| (check.id.clone(), check.detail.clone()))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            summary.attention, 0,
            "nothing on a correct fresh install needs attention"
        );
        assert_eq!(summary.passed, 2);
        assert_eq!(summary.skipped, 4);
    }

    #[tokio::test]
    async fn report_is_non_empty_and_serializes_with_ids() {
        // Health inspects the managed MCP client configs, which are addressed
        // from the home directory, so an unscoped run reads the developer's
        // live configuration and reports on whatever it happens to contain.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let kin_home = tmp.path().join("kin-home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&kin_home).unwrap();
        let _env = EnvVarGuard::set("HOME", &home).with("KIN_HOME", &kin_home);

        let report = run_health_checks().await;
        assert!(!report.checks.is_empty());
        let json = serde_json::to_string(&report).expect("report serializes");
        assert!(json.contains("\"kin_binary\""));
        assert!(json.contains("\"kin_daemon_binary\""));
        assert!(json.contains("\"daemon_running\""));
        assert!(json.contains("\"vfs_projection\""));
        assert!(json.contains("\"shell_path\""));
        assert!(json.contains("\"registry_authority\""));
        assert!(json.contains("\"setup_ledger\""));
        assert!(json.contains("\"platform\""));
        assert!(json.contains("\"healthy\""));
        assert!(json.contains("\"retrieval_profile\""));
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn registry_authority_health_is_read_only_and_explicitly_fixable() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let registry = tmp.path().join("registry.toml");
        let lock = tmp.path().join("registry.lock");
        std::fs::write(&registry, "repos = []\n").unwrap();
        std::fs::write(&lock, b"").unwrap();
        for path in [&registry, &lock] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let _registry_path = EnvVarGuard::set("KIN_REGISTRY_PATH", &registry);

        let check = check_registry_authority();
        assert!(matches!(check.status, HealthStatus::Misconfigured));
        assert!(check.fixable);
        assert!(check.detail.contains("expected 0600"));
        assert_eq!(
            std::fs::metadata(&registry).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(
            std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
            0o644
        );

        kin_core::registry::repair_registry_authority_permissions().unwrap();
        let check = check_registry_authority();
        assert!(matches!(check.status, HealthStatus::Healthy));
    }

    /// The row that reported `~/.kin/bin will be on PATH after shell restart`
    /// on a host where that directory did not exist. Which of the two cases the
    /// install is in has to be in the row, since the PATH line is written only
    /// in one of them.
    #[test]
    fn the_shell_row_says_whether_a_path_line_was_wanted() {
        let mut archive = shell_state(true, true);
        archive.bin_dir_present = false;
        archive.on_path = false;
        archive.rc_sets_path = false;
        let check = shell_path_check_from(archive);
        assert!(
            matches!(check.status, HealthStatus::Healthy),
            "a hook installed by an archive install is not broken: {:?}",
            check.status
        );
        assert!(
            check.detail.contains("does not exist"),
            "the row must say why no PATH line was written: {}",
            check.detail
        );

        // Falsification: the same rc on the layout that does provision the
        // directory is a real missing PATH line and stays a failure.
        let mut managed = shell_state(true, true);
        managed.on_path = false;
        managed.rc_sets_path = false;
        let check = shell_path_check_from(managed);
        assert!(
            matches!(check.status, HealthStatus::Misconfigured),
            "a provisioned bin directory missing from PATH stays a failure: {:?}",
            check.status
        );
        assert!(
            check.detail.contains("does not add"),
            "the failing row still names the missing PATH line: {}",
            check.detail
        );
    }

    #[test]
    #[serial]
    fn shell_path_is_healthy_when_rc_declares_path_for_next_shell() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let kin_home = tmp.path().join("kin-home");
        let hook_dir = kin_home.join("shell");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&hook_dir).unwrap();

        std::fs::create_dir_all(kin_home.join("bin")).unwrap();

        let hook = hook_dir.join(hook_filename("zsh"));
        std::fs::write(&hook, "# kin-vfs test hook\n").unwrap();
        std::fs::write(
            home.join(".zshrc"),
            format!(
                "source \"{}\"\nexport PATH=\"{}:$PATH\"\n",
                hook.display(),
                kin_home.join("bin").display()
            ),
        )
        .unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _kin_dir = EnvVarGuard::unset("KIN_DIR");
        let _shell = EnvVarGuard::set("SHELL", "/bin/zsh");
        let _ps_module_path = EnvVarGuard::unset("PSModulePath");
        let _ps_version_table = EnvVarGuard::unset("PSVersionTable");
        let _profile = EnvVarGuard::unset("PROFILE");
        let _path = EnvVarGuard::set("PATH", "/usr/bin");

        let check = check_shell_path();
        assert_eq!(check.id, "shell_path");
        assert!(
            matches!(check.status, HealthStatus::Healthy),
            "rc-declared Kin PATH should be healthy after install; got {:?}: {}",
            check.status,
            check.detail
        );
        assert!(
            check.detail.contains("after shell restart"),
            "detail should explain why the current process PATH can lag: {}",
            check.detail
        );
    }

    /// A host that merely ships PowerShell exports `PSModulePath` into every
    /// process, including the bash one the operator is actually using. The
    /// installed bash integration is the one to judge; reading the PowerShell
    /// marker first reported a working bash install as misconfigured and
    /// pointed the operator at a `.ps1` profile their shell never loads.
    #[test]
    #[serial]
    #[cfg(not(target_os = "windows"))]
    fn shell_path_judges_the_named_shell_when_powershell_is_merely_installed() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let kin_home = tmp.path().join("kin-home");
        let hook_dir = kin_home.join("shell");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&hook_dir).unwrap();

        let hook = hook_dir.join(hook_filename("bash"));
        std::fs::write(&hook, "# kin-vfs test hook\n").unwrap();
        std::fs::write(
            home.join(".bashrc"),
            format!(
                "source \"{}\"\nexport PATH=\"{}:$PATH\"\n",
                hook.display(),
                kin_home.join("bin").display()
            ),
        )
        .unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _kin_dir = EnvVarGuard::unset("KIN_DIR");
        let _shell = EnvVarGuard::set("SHELL", "/bin/bash");
        let _ps_module_path =
            EnvVarGuard::set("PSModulePath", "/opt/microsoft/powershell/7/Modules");
        let _ps_version_table = EnvVarGuard::unset("PSVersionTable");
        let _profile = EnvVarGuard::unset("PROFILE");
        let _path = EnvVarGuard::set("PATH", "/usr/bin");

        let check = check_shell_path();
        assert_eq!(check.id, "shell_path");
        assert!(
            matches!(check.status, HealthStatus::Healthy),
            "installed bash integration should be healthy while pwsh is merely present; \
             got {:?}: {}",
            check.status,
            check.detail
        );
        assert!(
            check.detail.starts_with("bash "),
            "detail should describe the bash integration: {}",
            check.detail
        );
    }

    fn check_with(id: &str, status: HealthStatus) -> HealthCheck {
        HealthCheck::new(id, id, status, "")
    }

    /// Doctor said "no AI client config files detected, nothing to configure"
    /// and `kin setup` configured Claude Code seconds later on the same host.
    /// The row now reports what setup's own detection sees, so the two surfaces
    /// cannot contradict each other.
    #[test]
    fn the_no_client_row_reports_detection_rather_than_config_files() {
        let nothing = no_mcp_client_config_check(&[]);
        assert!(matches!(nothing.status, HealthStatus::Healthy));
        assert!(
            nothing.detail.contains("nothing to configure"),
            "a host with no client keeps the settled answer: {}",
            nothing.detail
        );

        // Falsification: one detected client and the same absent config files.
        let detected = no_mcp_client_config_check(&["Claude Code"]);
        assert!(
            detected.detail.contains("Claude Code"),
            "a detected client must be named: {}",
            detected.detail
        );
        assert!(
            !detected.detail.contains("nothing to configure"),
            "setup has work to do here, so the row may not say otherwise: {}",
            detected.detail
        );
        assert!(
            detected.manual_fix.is_some(),
            "the row must point at the command that does the work"
        );
        assert!(
            !is_failing(&detected.status),
            "an unconfigured client is first-run work, not a broken install: {:?}",
            detected.status
        );
    }

    /// The same question asked of the real check, with a real home that has no
    /// client config and a PATH that does or does not carry a client binary.
    #[test]
    #[serial]
    #[cfg(unix)]
    fn a_detected_client_reaches_the_row_that_used_to_say_nothing_to_configure() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let empty_bin = tmp.path().join("empty-bin");
        let client_bin = tmp.path().join("client-bin");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&empty_bin).unwrap();
        std::fs::create_dir_all(&client_bin).unwrap();

        let _home = EnvVarGuard::set("HOME", &home);

        let without = {
            let _path = EnvVarGuard::set("PATH", &empty_bin);
            check_mcp_clients()
        };
        assert_eq!(without.len(), 1, "no config files means one rollup row");
        assert!(
            !without[0].detail.contains("Claude Code"),
            "no client on PATH and none in this home: {}",
            without[0].detail
        );

        let claude = client_bin.join("claude");
        write_file(&claude, b"#!/bin/sh\nexit 0\n");
        std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();

        let with = {
            let _path = EnvVarGuard::set("PATH", &client_bin);
            check_mcp_clients()
        };
        assert_eq!(with.len(), 1, "still no config files, still one rollup row");
        assert!(
            with[0].detail.contains("Claude Code"),
            "an installed client must reach the row: {}",
            with[0].detail
        );
        assert!(
            !with[0].detail.contains("nothing to configure"),
            "setup will configure it, so the row may not say there is nothing to do: {}",
            with[0].detail
        );
    }

    #[test]
    fn binary_assessment_check_always_reports() {
        let check = check_binary_assessment_load();
        assert_eq!(check.id, "binary_assessment_load");
        assert!(!check.detail.is_empty());
        // Advisory by design: a wedged assessment daemon must warn without
        // failing overall readiness.
        assert!(!matches!(
            check.status,
            HealthStatus::Missing | HealthStatus::Misconfigured
        ));
    }

    #[test]
    fn summary_tallies_pass_attention_skip_buckets() {
        let report = HealthReport {
            platform: "test".to_string(),
            checks: vec![
                check_with("a", HealthStatus::Healthy),
                check_with("b", HealthStatus::Healthy),
                check_with("c", HealthStatus::Missing),
                check_with("d", HealthStatus::Misconfigured),
                check_with("e", HealthStatus::Stale),
                check_with("f", HealthStatus::Unsupported),
            ],
            healthy: false,
        };
        let summary = report.summary();
        assert_eq!(summary.passed, 2, "two Healthy checks pass");
        assert_eq!(
            summary.attention, 3,
            "Missing + Misconfigured + Stale need attention"
        );
        assert_eq!(summary.skipped, 1, "Unsupported is not applicable");
    }

    #[test]
    fn summary_buckets_sum_to_total_checks() {
        let report = HealthReport {
            platform: "test".to_string(),
            checks: vec![
                check_with("a", HealthStatus::Healthy),
                check_with("b", HealthStatus::Stale),
                check_with("c", HealthStatus::Unsupported),
            ],
            healthy: false,
        };
        let summary = report.summary();
        assert_eq!(
            summary.passed + summary.attention + summary.skipped,
            report.checks.len(),
            "every check lands in exactly one bucket"
        );
    }

    #[test]
    fn unavailable_semantic_authority_blocks_readiness_without_losing_diagnostics() {
        let detail = "daemon reachable, but graph embedding status is unavailable";
        let report = assemble_health_report(
            "test".to_string(),
            vec![
                check_with("kin_binary", HealthStatus::Healthy),
                HealthCheck::new(
                    "semantic_query_readiness",
                    "Semantic query readiness",
                    HealthStatus::Stale,
                    detail,
                )
                .with_manual_fix("resolve the daemon graph authority error"),
            ],
        );

        assert!(
            !report.healthy,
            "unknown graph authority must fail aggregate semantic readiness"
        );
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["healthy"], false);
        assert_eq!(value["checks"][1]["status"], "stale");
        assert_eq!(value["checks"][1]["detail"], detail);
        assert_eq!(
            value["checks"][1]["manual_fix"],
            "resolve the daemon graph authority error"
        );
    }

    #[tokio::test]
    async fn daemon_running_check_is_present_and_never_hard_fails() {
        // The daemon-running probe is recoverable by construction: Healthy when
        // reachable, Stale when not started (auto-starts on use), Unsupported
        // outside a repo. It must never report Missing/Misconfigured, which
        // would make first-run readiness look broken when it is merely idle.
        // This holds regardless of the test's working directory, so no global
        // cwd mutation (which would race other tests) is needed.
        let daemon = check_daemon_running().await;
        assert_eq!(daemon.id, "daemon_running");
        assert!(
            !is_failing(&daemon.status),
            "daemon-running must not hard-fail; got {:?}",
            daemon.status
        );
        // When the daemon is not Healthy (Stale/Unsupported), there is always a
        // remediation hint so the user knows what to do.
        if !matches!(daemon.status, HealthStatus::Healthy) {
            assert!(
                daemon.manual_fix.is_some(),
                "non-healthy daemon-running must offer a remediation hint"
            );
        }
    }

    #[cfg(not(feature = "vector"))]
    #[tokio::test]
    async fn vector_free_build_reports_semantic_query_as_unsupported() {
        let semantic = check_semantic_query_readiness().await;
        assert_eq!(semantic.id, "semantic_query_readiness");
        assert!(matches!(semantic.status, HealthStatus::Unsupported));
        assert!(!semantic.detail.contains("kin embed"));
        assert!(semantic.manual_fix.is_none());
    }

    #[cfg(feature = "vector")]
    #[test]
    fn semantic_query_readiness_accepts_complete_daemon_graph_coverage() {
        let runtime = crate::commands::resources::EmbedRuntimeState {
            embeddings_indexed: 41,
            embeddings_total: 41,
            embeddings_pending: 0,
            ..Default::default()
        };

        let semantic = semantic_query_health_from_runtime("http://daemon", &runtime);

        assert!(matches!(semantic.status, HealthStatus::Healthy));
        assert!(semantic.detail.contains("41/41 embeddings indexed"));
        assert!(!semantic.detail.contains("graph.kvec"));
        assert!(semantic.manual_fix.is_none());
    }

    #[cfg(feature = "vector")]
    #[test]
    fn semantic_query_readiness_reports_daemon_graph_backlog_and_failure() {
        // A store that has finished a fill before, now carrying a backlog. On
        // a working copy that is being written to this is the ordinary state,
        // not lost ground: files are admitted as they are written and an edit
        // invalidates the embeddings it touched. The surface is serving off a
        // fill that completed, so it is ready and the backlog is named rather
        // than held against it. Lost ground keeps its own arms below, keyed on
        // the cause instead of on counters that grew.
        let topping_up = crate::commands::resources::EmbedRuntimeState {
            embeddings_indexed: 40,
            embeddings_total: 41,
            embeddings_pending: 1,
            embedding_coverage_ever_complete: true,
            ..Default::default()
        };
        let filling = semantic_query_health_from_runtime("http://daemon", &topping_up);
        assert!(
            matches!(filling.status, HealthStatus::Healthy),
            "a top-up on a store whose fill completed is not lost ground: {:?}",
            filling.status
        );
        assert!(filling
            .detail
            .contains("40/41 embeddings indexed, 1 pending"));
        assert!(
            filling.detail.contains("coverage completed earlier"),
            "the backlog must still be named, not hidden by the healthy verdict: {}",
            filling.detail
        );

        // Falsification. The identical counters must go straight back to
        // blocking the moment the runtime names a cause that means ground was
        // actually lost, or the healthy verdict above is not a judgement.
        let discarded = crate::commands::resources::EmbedRuntimeState {
            vector_index_discarded: Some("the persisted vector index was not loaded".to_string()),
            ..topping_up.clone()
        };
        let stale = semantic_query_health_from_runtime("http://daemon", &discarded);
        assert!(matches!(stale.status, HealthStatus::Stale));
        assert!(stale.manual_fix.is_some());
        assert!(
            !assemble_health_report("test".to_string(), vec![stale]).healthy,
            "a discarded index still has to fail the aggregate"
        );

        let failed = crate::commands::resources::EmbedRuntimeState {
            embed_worker_failed: true,
            ..topping_up
        };
        let missing = semantic_query_health_from_runtime("http://daemon", &failed);
        assert!(matches!(missing.status, HealthStatus::Missing));
        assert!(missing.detail.contains("embedding worker failed"));
        assert!(missing.manual_fix.is_some());
    }

    /// The v0.5.18 release gate, held still. Its Public Install Proof ran
    /// `kin embed` to completion, read complete observed coverage out of
    /// `kin status`, and then had readiness call the same store `pending`
    /// because three files the proof itself had just written were admitted in
    /// between. Two defects compounded there, and this covers the classifier
    /// half: a store whose fill completed reports ready even while a backlog
    /// that arrived afterwards is filling.
    #[cfg(feature = "vector")]
    #[test]
    fn work_arriving_after_a_completed_fill_does_not_un_ready_the_surface() {
        let after_the_proof_wrote_its_own_output = crate::commands::resources::EmbedRuntimeState {
            embeddings_indexed: 14,
            embeddings_total: 17,
            embeddings_pending: 3,
            embedding_coverage_ever_complete: true,
            ..Default::default()
        };

        let semantic = semantic_query_health_from_runtime(
            "http://daemon",
            &after_the_proof_wrote_its_own_output,
        );
        assert!(
            matches!(semantic.status, HealthStatus::Healthy),
            "the install proof asserts readiness is healthy after a completed embed: {:?}",
            semantic.status
        );

        let report = assemble_health_report("test".to_string(), vec![semantic]);
        assert!(
            report.healthy,
            "a corpus that grew after its fill completed must not report the install unhealthy"
        );

        // Falsification. The same counters on a store that has never finished a
        // fill are a genuine first pass and must still say so, or this check
        // has stopped distinguishing anything.
        let first_fill = crate::commands::resources::EmbedRuntimeState {
            embedding_coverage_ever_complete: false,
            ..after_the_proof_wrote_its_own_output
        };
        assert!(matches!(
            semantic_query_health_from_runtime("http://daemon", &first_fill).status,
            HealthStatus::Pending
        ));
    }

    /// Pending promises that coverage is on its way. On a store whose graph
    /// authority is a remote storage backend there is no durable local
    /// vector-sidecar contract, the worker never starts and `/embed` refuses,
    /// so the queue is not draining and no amount of waiting changes that.
    /// Naming the host's limit is honest; reporting progress is not.
    #[cfg(feature = "vector")]
    #[test]
    fn a_backlog_nothing_will_drain_is_reported_unsupported_rather_than_pending() {
        let no_local_sidecar = crate::commands::resources::EmbedRuntimeState {
            embeddings_indexed: 0,
            embeddings_total: 41,
            embeddings_pending: 41,
            embed_persistence_unavailable: true,
            ..Default::default()
        };

        let semantic = semantic_query_health_from_runtime("http://daemon", &no_local_sidecar);
        assert!(
            matches!(semantic.status, HealthStatus::Unsupported),
            "a queue nothing will consume is not work in progress: {:?}",
            semantic.status
        );
        assert!(
            semantic.detail.contains("remote storage backend")
                && semantic.detail.contains("nothing will embed here"),
            "the cause has to be named where the check is read: {}",
            semantic.detail
        );

        // Unsupported is a statement about the host, not a way to stay quiet:
        // it must not block the aggregate, and the same store must report
        // pending again the moment local persistence is available.
        assert!(assemble_health_report("test".to_string(), vec![semantic]).healthy);
        let local = crate::commands::resources::EmbedRuntimeState {
            embed_persistence_unavailable: false,
            ..no_local_sidecar
        };
        assert!(matches!(
            semantic_query_health_from_runtime("http://daemon", &local).status,
            HealthStatus::Pending
        ));
    }

    /// A repository whose finished index was thrown away at open looks exactly
    /// like a first run if only the coverage counters are reported: partial
    /// coverage, work in progress, nothing wrong. Naming the discard is the
    /// difference between "Kin is indexing" and "Kin is indexing this again".
    #[cfg(feature = "vector")]
    #[test]
    fn semantic_query_readiness_names_a_discarded_vector_index() {
        let discarded = crate::commands::resources::EmbedRuntimeState {
            embeddings_indexed: 0,
            embeddings_total: 41,
            embeddings_pending: 41,
            vector_index_discarded: Some(
                "the persisted vector index at .kin/kindb/graph.kvec could not be read".to_string(),
            ),
            ..Default::default()
        };

        let semantic = semantic_query_health_from_runtime("http://daemon", &discarded);

        assert!(matches!(semantic.status, HealthStatus::Stale));
        assert!(
            semantic.detail.contains("graph.kvec")
                && semantic
                    .detail
                    .contains("restoring coverage in the background"),
            "a discarded index must be named, not left to be inferred from coverage: {}",
            semantic.detail
        );
        // The recovery serves unchanged texts from the embedding cache, so no
        // surface may promise a full re-embed. The open-time daemon log used to
        // say this too and no longer does; this check keeps the two from
        // drifting apart again.
        assert!(
            !semantic.detail.contains("from scratch"),
            "a recovery that reuses prior vectors must not be announced as a full rebuild: {}",
            semantic.detail
        );
        assert!(semantic.manual_fix.is_some());

        // Once the rebuild lands there is nothing left to act on, and a check
        // that stays yellow after its cause is gone is a check nobody reads.
        let rebuilt = crate::commands::resources::EmbedRuntimeState {
            embeddings_indexed: 41,
            embeddings_pending: 0,
            ..discarded
        };
        let settled = semantic_query_health_from_runtime("http://daemon", &rebuilt);
        assert!(
            matches!(settled.status, HealthStatus::Healthy),
            "a paid-off discard must not hold the check yellow forever: {:?}",
            settled.status
        );
        assert!(!settled.detail.contains("graph.kvec"));
    }

    /// The scenario that refused v0.5.7's promotion on all five platforms: a
    /// correct fresh install whose daemon is part-way through its first
    /// embedding pass when health runs. Nothing is wrong with it, and the whole
    /// install reported unhealthy.
    ///
    /// The falsification is the point of the second half. Pending only means
    /// something if the identical call, on the identical fixture, goes back to
    /// blocking the moment the runtime says coverage was lost rather than never
    /// yet earned.
    #[cfg(feature = "vector")]
    #[test]
    fn a_first_fill_in_progress_does_not_block_readiness() {
        let mid_first_fill = crate::commands::resources::EmbedRuntimeState {
            embeddings_indexed: 12,
            embeddings_total: 41,
            embeddings_pending: 29,
            ..Default::default()
        };

        let semantic = semantic_query_health_from_runtime("http://daemon", &mid_first_fill);
        assert!(
            matches!(semantic.status, HealthStatus::Pending),
            "a first fill in progress is expected first-run work, not a failure: {:?}",
            semantic.status
        );
        assert!(
            semantic
                .detail
                .contains("12/41 embeddings indexed, 29 pending")
                && semantic
                    .detail
                    .contains("first embedding pass still filling"),
            "the pending state must show its progress and name itself: {}",
            semantic.detail
        );
        assert!(semantic.manual_fix.is_some());

        let report = assemble_health_report("test".to_string(), vec![semantic]);
        assert!(
            report.healthy,
            "a fresh install mid-first-fill must not report the whole install unhealthy"
        );
        assert_eq!(
            report.summary().attention,
            1,
            "the fill is still work in progress, so it is attention rather than not-applicable"
        );
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["healthy"], true);
        assert_eq!(json["checks"][0]["status"], "pending");

        // Falsification: same call, same fixture, discard reason set. If this
        // does not flip to blocking, the pending state is separating nothing.
        let discarded = crate::commands::resources::EmbedRuntimeState {
            vector_index_discarded: Some(
                "the persisted vector index at .kin/kindb/graph.kvec could not be read".to_string(),
            ),
            ..mid_first_fill.clone()
        };
        let after_discard = semantic_query_health_from_runtime("http://daemon", &discarded);
        assert!(
            matches!(after_discard.status, HealthStatus::Stale),
            "a discarded index is still the announced blocking state: {:?}",
            after_discard.status
        );
        assert!(
            !assemble_health_report("test".to_string(), vec![after_discard]).healthy,
            "a rebuild after a discard must still block readiness"
        );

        // The same counters on a store that has finished a fill are the other
        // side of what this check separates, and they are not a blocking state.
        // Nothing was discarded and no worker failed, so this is a corpus that
        // grew or an edit that invalidated what it touched, which is what every
        // repository somebody is working in does all day. The blocking states
        // above keep their own arms, keyed on the cause rather than inferred
        // from counters, and `work_arriving_after_a_completed_fill_does_not_
        // un_ready_the_surface` holds the release-gate case this came from.
        let topping_up = crate::commands::resources::EmbedRuntimeState {
            embedding_coverage_ever_complete: true,
            ..mid_first_fill.clone()
        };
        let after_top_up = semantic_query_health_from_runtime("http://daemon", &topping_up);
        assert!(
            matches!(after_top_up.status, HealthStatus::Healthy),
            "a backlog on a store whose fill completed is not lost ground: {:?}",
            after_top_up.status
        );
        assert!(assemble_health_report("test".to_string(), vec![after_top_up]).healthy);

        // A wedged worker fails outright whether or not the fill ever finished.
        let wedged = crate::commands::resources::EmbedRuntimeState {
            embed_worker_failed: true,
            ..mid_first_fill
        };
        let after_wedge = semantic_query_health_from_runtime("http://daemon", &wedged);
        assert!(
            matches!(after_wedge.status, HealthStatus::Missing),
            "a failed embedding worker is a failure at any point in a store's life: {:?}",
            after_wedge.status
        );
        assert!(!assemble_health_report("test".to_string(), vec![after_wedge]).healthy);
    }

    #[test]
    fn health_status_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&HealthStatus::Healthy).unwrap(),
            "\"healthy\""
        );
        assert_eq!(
            serde_json::to_string(&HealthStatus::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&HealthStatus::Missing).unwrap(),
            "\"missing\""
        );
        assert_eq!(
            serde_json::to_string(&HealthStatus::Stale).unwrap(),
            "\"stale\""
        );
        assert_eq!(
            serde_json::to_string(&HealthStatus::Misconfigured).unwrap(),
            "\"misconfigured\""
        );
        assert_eq!(
            serde_json::to_string(&HealthStatus::Unsupported).unwrap(),
            "\"unsupported\""
        );
    }

    /// An entry that states no profile is served the curated agent-default
    /// surface by `kin mcp start` itself, so it is correctly wired. Reporting
    /// the supported default as a fault would send every hand-wired client to
    /// fix something that is not broken.
    #[test]
    fn mcp_config_with_no_profile_is_healthy_on_the_served_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "kin": {
                        "command": "kin",
                        "args": ["mcp", "start"],
                        "env": {}
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let (status, detail) = evaluate_mcp_client_against(&path, "claude", "kin");
        assert!(matches!(status, HealthStatus::Healthy), "detail: {detail}");
        assert!(
            detail.contains("defaults to the agent-default profile"),
            "the reader must be told which surface an unset profile resolves to: {detail}"
        );
    }

    /// A profile that names a different surface is still a deliberate departure
    /// from what `kin setup` writes, and doctor still says so. Without this the
    /// relaxation above would have turned the check into one that cannot fail.
    #[test]
    fn mcp_config_naming_another_profile_is_still_misconfigured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "kin": {
                        "command": "kin",
                        "args": ["mcp", "start"],
                        "env": { "KIN_MCP_TOOL_PROFILE": "full" }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let (status, detail) = evaluate_mcp_client_against(&path, "claude", "kin");
        assert!(
            matches!(status, HealthStatus::Misconfigured),
            "detail: {detail}"
        );
        assert!(detail.contains("full"), "detail: {detail}");
    }

    #[test]
    fn mcp_config_with_agent_default_profile_is_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "kin": {
                        "command": "kin",
                        "args": ["mcp", "start"],
                        "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let (status, _detail) = evaluate_mcp_client_against(&path, "claude", "kin");
        assert!(matches!(status, HealthStatus::Healthy));
    }

    #[test]
    fn mcp_config_with_canonical_npm_wrapper_is_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "kin": {
                        "command": "npx",
                        "args": ["-y", "@kinlab/kin", "mcp", "start"],
                        "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let (status, detail) = evaluate_mcp_client_against(&path, "claude", "/managed/kin");
        assert!(matches!(status, HealthStatus::Healthy), "got: {detail}");
    }

    #[test]
    fn mcp_config_rejects_nearby_npm_wrapper_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        for args in [
            serde_json::json!(["@kinlab/kin", "mcp", "start"]),
            serde_json::json!(["-y", "@kinlab/not-kin", "mcp", "start"]),
            serde_json::json!(["-y", "@kinlab/kin", "mcp", "start", "extra"]),
        ] {
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&serde_json::json!({
                    "mcpServers": {
                        "kin": {
                            "command": "npx",
                            "args": args,
                            "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
                        }
                    }
                }))
                .unwrap(),
            )
            .unwrap();

            let (status, detail) = evaluate_mcp_client_against(&path, "claude", "/managed/kin");
            assert!(
                matches!(status, HealthStatus::Misconfigured),
                "nearby npm shape was accepted: {detail}"
            );
        }
    }

    #[test]
    fn mcp_config_rejects_bare_kin_when_the_installation_has_an_exact_launcher() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "kin": {
                        "command": "kin",
                        "args": ["mcp", "start"],
                        "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let (status, detail) = evaluate_mcp_client_against(&path, "claude", "/managed/kin");
        assert!(matches!(status, HealthStatus::Misconfigured));
        assert!(detail.contains("expected the exact Kin launcher"));
    }

    #[test]
    fn mcp_config_missing_exact_managed_command_is_misconfigured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "kin": {
                        "args": ["mcp", "start"],
                        "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let (status, detail) = evaluate_mcp_client_against(&path, "claude", "/managed/kin");
        assert!(matches!(status, HealthStatus::Misconfigured));
        assert!(detail.contains("command is unset"));
    }

    #[test]
    fn mcp_config_wrong_managed_command_is_misconfigured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "kin": {
                        "command": "/stale/kin",
                        "args": ["mcp", "start"],
                        "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let (status, detail) = evaluate_mcp_client_against(&path, "claude", "/managed/kin");
        assert!(matches!(status, HealthStatus::Misconfigured));
        assert!(detail.contains("expected the exact Kin launcher"));
    }

    #[test]
    fn ordinary_mcp_config_with_repository_arguments_is_misconfigured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "kin": {
                        "command": "/managed/kin",
                        "args": ["mcp", "start", "--repo", "/other"],
                        "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let (status, detail) = evaluate_mcp_client_against(&path, "claude", "/managed/kin");
        assert!(matches!(status, HealthStatus::Misconfigured));
        assert!(detail.contains("exact supported MCP argument vector"));
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn mcp_health_binds_to_the_exact_managed_launcher() {
        let dir = tempfile::tempdir().unwrap();
        let kin_home = dir.path().join("kin-home");
        let managed = kin_home.join("bin/kin");
        std::fs::create_dir_all(managed.parent().unwrap()).unwrap();
        std::fs::copy(std::env::current_exe().unwrap(), &managed).unwrap();
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let path = dir.path().join("claude.json");
        let config = |command: &Path| {
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "kin": {
                        "command": command,
                        "args": ["mcp", "start"],
                        "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
                    }
                }
            }))
            .unwrap()
        };
        std::fs::write(&path, config(&managed)).unwrap();

        let (status, detail) = evaluate_mcp_client(&path, "claude");
        assert!(matches!(status, HealthStatus::Healthy), "got: {detail}");

        std::fs::write(&path, config(Path::new("/wrong/kin"))).unwrap();
        let (status, detail) = evaluate_mcp_client(&path, "claude");
        assert!(matches!(status, HealthStatus::Misconfigured));
        assert!(detail.contains("exact Kin launcher"));
    }

    #[test]
    fn mcp_config_with_retired_global_flag_is_misconfigured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "kin": {
                        "command": "kin",
                        "args": ["mcp", "start", "--global"],
                        "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let (status, detail) = evaluate_mcp_client_against(&path, "claude", "kin");
        assert!(matches!(status, HealthStatus::Misconfigured));
        assert!(detail.contains("--global"));
    }

    #[test]
    fn mcp_config_missing_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let (status, _detail) = evaluate_mcp_client_against(&path, "claude", "kin");
        assert!(matches!(status, HealthStatus::Missing));
    }

    #[test]
    fn mcp_config_toml_with_agent_default_profile_is_healthy() {
        // Codex registers MCP servers in ~/.codex/config.toml, not mcp.json.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[mcp_servers.kin]\ncommand = \"kin\"\nargs = [\"mcp\", \"start\", \"--repo\", \"/repo\"]\nenv = { KIN_MCP_TOOL_PROFILE = \"agent-default\" }\n",
        )
        .unwrap();

        let (status, detail) = evaluate_mcp_client_against(&path, "codex", "kin");
        assert!(matches!(status, HealthStatus::Healthy), "got: {detail}");
        assert!(detail.contains("mcp_servers.kin"));
    }

    #[test]
    fn repo_bound_mcp_config_with_canonical_npm_wrapper_is_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[mcp_servers.kin]\ncommand = \"npx\"\nargs = [\"-y\", \"@kinlab/kin\", \"mcp\", \"start\", \"--repo\", \"/repo\"]\nenv = { KIN_MCP_TOOL_PROFILE = \"agent-default\" }\n",
        )
        .unwrap();

        let (status, detail) = evaluate_mcp_client_against(&path, "codex", "/managed/kin");
        assert!(matches!(status, HealthStatus::Healthy), "got: {detail}");
    }

    #[test]
    fn mcp_config_toml_without_kin_entry_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "model = \"o3\"\n").unwrap();

        let (status, detail) = evaluate_mcp_client_against(&path, "codex", "kin");
        assert!(matches!(status, HealthStatus::Missing), "got: {detail}");
        assert!(detail.contains("mcp_servers.kin"));
    }

    #[test]
    fn codex_health_binding_uses_the_product_toml_parser() {
        let dir = tempfile::tempdir().unwrap();
        let expected = dir.path().join("expected");
        let other = dir.path().join("other");
        std::fs::create_dir_all(expected.join(".kin")).unwrap();
        std::fs::create_dir_all(other.join(".kin")).unwrap();
        let expected = expected.canonicalize().unwrap();
        let other = other.canonicalize().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            format!(
                "[mcp_servers.kin]\ncommand = 'kin'\nargs = ['mcp', 'start', '--repo', '{}']\nenv = {{ KIN_MCP_TOOL_PROFILE = 'agent-default' }}\n",
                expected.display()
            ),
        )
        .unwrap();

        assert!(evaluate_codex_binding_for(&path, &expected).is_none());
        let (status, detail) = evaluate_codex_binding_for(&path, &other).unwrap();
        assert!(matches!(status, HealthStatus::Misconfigured));
        assert!(detail.contains("does not use the exact"));

        std::fs::write(
            &path,
            format!(
                "[mcp_servers.kin]\nargs = ['not-mcp', 'start', '--repo', '{}']\nenv = {{ KIN_MCP_TOOL_PROFILE = 'agent-default' }}\n",
                expected.display()
            ),
        )
        .unwrap();
        assert!(evaluate_codex_binding_for(&path, &expected).is_some());

        std::fs::write(
            &path,
            format!(
                "[mcp_servers.kin]\ncommand = 'npx'\nargs = ['-y', '@kinlab/kin', 'mcp', 'start', '--repo', '{}']\nenv = {{ KIN_MCP_TOOL_PROFILE = 'agent-default' }}\n",
                expected.display()
            ),
        )
        .unwrap();
        assert!(
            evaluate_codex_binding_for(&path, &expected).is_none(),
            "canonical npm wrapper must preserve Codex's exact repository binding"
        );
        assert!(evaluate_codex_binding_for(&path, &other).is_some());
    }

    #[test]
    fn antigravity_workspace_accepts_canonical_npm_repo_binding() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let config = repo.join(".agents/mcp_config.json");
        std::fs::create_dir_all(repo.join(".kin")).unwrap();
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        let repo = repo.canonicalize().unwrap();
        let repo_text = repo.to_string_lossy().into_owned();
        let write_config = |bound_repo: &Path| {
            std::fs::write(
                &config,
                serde_json::to_vec_pretty(&serde_json::json!({
                    "mcpServers": {
                        "kin": {
                            "command": "npx",
                            "args": ["-y", "@kinlab/kin", "mcp", "start", "--repo", bound_repo.to_string_lossy()],
                            "cwd": repo_text,
                            "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
                        }
                    }
                }))
                .unwrap(),
            )
            .unwrap();
        };
        write_config(&repo);

        let (status, detail) =
            evaluate_mcp_client_against(&config, "antigravity_workspace", "/managed/kin");
        assert!(matches!(status, HealthStatus::Healthy), "got: {detail}");
        assert!(evaluate_antigravity_binding(&config, true).is_none());

        let other = dir.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        write_config(&other);
        assert!(evaluate_antigravity_binding(&config, true).is_some());
    }

    /// Write the global Antigravity binding exactly as `kin setup` does: with
    /// the canonicalized repository root, through the canonical npm wrapper so
    /// the assertion does not depend on this machine's installed launcher.
    fn write_global_antigravity_binding(config: &Path, bound_repo: &Path) {
        std::fs::write(
            config,
            serde_json::to_vec_pretty(&serde_json::json!({
                "mcpServers": {
                    "kin": {
                        "command": CANONICAL_NPM_MCP_COMMAND,
                        "args": ["-y", CANONICAL_NPM_MCP_PACKAGE, "mcp", "start", "--repo", bound_repo.to_string_lossy()],
                        "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
    }

    /// The two sides of an MCP binding check name the repository differently:
    /// the writers canonicalize, discovery inherits the working directory's raw
    /// form. Normalizing at the source is what lets the exact-string comparison
    /// stay exact.
    #[test]
    fn health_repo_is_normalized_to_the_form_the_config_writers_record() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".kin")).unwrap();
        let canonical = repo.canonicalize().unwrap();

        // Stands in for what discovery hands back in production: the same
        // repository named through a path `canonicalize` would not produce.
        let raw = canonical.join("..").join(canonical.file_name().unwrap());
        assert_ne!(raw, canonical);

        assert_eq!(canonical_health_repo(raw), canonical);
        assert_eq!(
            canonical_health_repo(canonical.clone()),
            canonical,
            "normalizing an already-canonical root must not disturb it"
        );

        // Discovery succeeded, so a root that cannot be canonicalized is still
        // reported rather than dropped — a dropped root retires the check.
        let vanished = dir.path().join("gone");
        assert_eq!(canonical_health_repo(vanished.clone()), vanished);
    }

    /// Regression: on Windows the first `kin setup` wrote the global
    /// Antigravity binding with the canonicalized (`\\?\` verbatim) repository
    /// root, then `kin setup status --json` reported it misconfigured, because
    /// the global arm compared it against a non-canonicalized root by exact
    /// string. Whichever equivalent form discovery yields, the binding setup
    /// itself just wrote must read healthy.
    #[test]
    fn antigravity_global_binding_accepts_the_repository_setup_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".kin")).unwrap();
        let canonical = repo.canonicalize().unwrap();
        let config = dir.path().join("mcp_config.json");
        write_global_antigravity_binding(&config, &canonical);

        // On Windows the canonicalized form carries the `\\?\` verbatim
        // prefix and PathBuf::join resolves `..` against verbatim bases, so a
        // dot-dot detour collapses back into `canonical` before the premise
        // is ever checked. Derive the equivalent-but-unequal path from the
        // plain form there, which is also the shape discovery produces.
        #[cfg(windows)]
        let discovered = std::path::PathBuf::from(
            canonical
                .to_str()
                .and_then(|s| s.strip_prefix(r"\\?\"))
                .expect("canonicalized temp paths carry the verbatim prefix on Windows"),
        );
        #[cfg(not(windows))]
        let discovered = canonical.join("..").join(canonical.file_name().unwrap());
        assert_ne!(discovered, canonical);

        assert!(
            evaluate_antigravity_binding_for(&config, false, &canonical_health_repo(discovered))
                .is_none(),
            "a binding written with the canonicalized repository root must be accepted when \
             discovery names that same repository through an equivalent path"
        );

        // The check still has to reject a binding pointed at another
        // repository, or normalizing would have made it vacuous.
        let other = dir.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        let other = other.canonicalize().unwrap();
        write_global_antigravity_binding(&config, &other);
        assert!(
            evaluate_antigravity_binding_for(&config, false, &canonical_health_repo(canonical))
                .is_some(),
            "a binding pointed at a different repository must still be misconfigured"
        );
    }

    /// The same defect in the exact path forms Windows produces: `canonicalize`
    /// returns a `\\?\` verbatim path, `env::current_dir` never does, and
    /// repository discovery walks up from the working directory without
    /// changing its form.
    ///
    /// The name must keep its `windows_` prefix. CI's native Windows leg
    /// selects kin-cli tests by the substring filter `windows`, so a
    /// Windows-only regression test named without it compiles on that leg and
    /// never runs, which is worse than having no test at all.
    #[cfg(windows)]
    #[test]
    fn windows_antigravity_global_binding_accepts_a_verbatim_root_from_a_plain_working_directory() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(repo.join(".kin")).unwrap();
        let canonical = repo.canonicalize().unwrap();
        let verbatim = canonical.to_string_lossy().into_owned();
        let plain = verbatim
            .strip_prefix(r"\\?\")
            .expect("canonicalize yields a verbatim path on Windows");
        assert_ne!(plain, verbatim.as_str());

        let config = dir.path().join("mcp_config.json");
        write_global_antigravity_binding(&config, &canonical);

        assert!(
            evaluate_antigravity_binding_for(
                &config,
                false,
                &canonical_health_repo(PathBuf::from(plain)),
            )
            .is_none(),
            "the drive-letter root a working directory yields must accept the verbatim root \
             setup recorded"
        );

        // Without this, the assertion above could pass for the wrong reason.
        // `evaluate_antigravity_binding_for` returns None both when the binding
        // is correct and when it cannot resolve this installation's launcher at
        // all, and this is the first test to reach that code on a Windows
        // runner. A binding pointed elsewhere must still be rejected, so a
        // launcher that failed to resolve fails the test instead of passing it.
        let other = dir.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        let other = other.canonicalize().unwrap();
        write_global_antigravity_binding(&config, &other);
        assert!(
            evaluate_antigravity_binding_for(
                &config,
                false,
                &canonical_health_repo(PathBuf::from(plain)),
            )
            .is_some(),
            "a binding pointed at a different repository must still be misconfigured"
        );
    }

    fn installed_kin(path: &str, protocol: InstalledStartupProtocol) -> InstalledKin {
        InstalledKin {
            path: PathBuf::from(path),
            protocol,
        }
    }

    /// The doctor is the surface that can name binary age, because the stuck
    /// binary blames lock contention instead. It must say so only when an
    /// install actually answers that it predates the protocol.
    #[test]
    fn doctor_names_binary_age_when_an_install_predates_the_startup_protocol() {
        let sentinel = PathBuf::from("/home/dev/.kin/supervisor.start.lock");
        let outdated = installed_kin(
            "/usr/local/bin/kin",
            InstalledStartupProtocol::Predates(
                "it reports compat schema kin.daemon.compat.v1 and no supervisor startup protocol \
                 at all"
                    .to_string(),
            ),
        );

        let check = supervisor_startup_protocol_check(
            SupervisorStartupSentinel::ProtocolDirectory,
            &sentinel,
            std::slice::from_ref(&outdated),
        );
        assert_eq!(check.id, "supervisor_startup_protocol");
        assert!(matches!(check.status, HealthStatus::Stale), "{check:?}");
        assert!(
            check
                .detail
                .contains("your installed kin predates the current supervisor protocol")
                && check.detail.contains("/usr/local/bin/kin")
                && check.detail.contains("kin.daemon.compat.v1"),
            "the diagnosis must name the binary and the evidence: {}",
            check.detail
        );
        assert!(
            check
                .manual_fix
                .as_deref()
                .is_some_and(|fix| fix.contains(crate::daemon_client::KIN_INSTALL_COMMAND)),
            "the remedy must be the exact install command: {:?}",
            check.manual_fix
        );
        assert!(
            !blocks_readiness(&check),
            "another install's age does not stop this binary from working, so it must not flip \
             the report's readiness"
        );
    }

    #[test]
    fn doctor_stays_quiet_when_no_install_answers_that_it_predates_the_protocol() {
        let sentinel = PathBuf::from("/home/dev/.kin/supervisor.start.lock");
        for installed in [
            vec![],
            vec![installed_kin(
                "/usr/local/bin/kin",
                InstalledStartupProtocol::Current,
            )],
            vec![installed_kin(
                "/usr/local/bin/kin",
                InstalledStartupProtocol::Undetermined("no kin-daemon beside it".to_string()),
            )],
        ] {
            let check = supervisor_startup_protocol_check(
                SupervisorStartupSentinel::ProtocolDirectory,
                &sentinel,
                &installed,
            );
            assert!(
                matches!(check.status, HealthStatus::Healthy),
                "an unanswered probe is not evidence of age: {check:?}"
            );
        }

        let absent = supervisor_startup_protocol_check(
            SupervisorStartupSentinel::Absent,
            &sentinel,
            &[installed_kin(
                "/usr/local/bin/kin",
                InstalledStartupProtocol::Predates("older".to_string()),
            )],
        );
        assert!(
            matches!(absent.status, HealthStatus::Healthy),
            "with no sentinel written there is nothing for an older binary to stall on: {absent:?}"
        );
    }

    /// A legacy marker file is different in kind: the running binary refuses to
    /// start a supervisor at all against one, so it blocks readiness.
    #[test]
    fn doctor_treats_a_legacy_marker_as_blocking_and_names_the_update() {
        let sentinel = PathBuf::from("/home/dev/.kin/supervisor.start.lock");
        let check = supervisor_startup_protocol_check(
            SupervisorStartupSentinel::LegacyMarker,
            &sentinel,
            &[],
        );
        assert!(
            matches!(check.status, HealthStatus::Misconfigured),
            "{check:?}"
        );
        assert!(blocks_readiness(&check));
        assert!(check.detail.contains("protocol-v1 marker file"));
        assert!(check
            .manual_fix
            .as_deref()
            .is_some_and(|fix| fix.contains(crate::daemon_client::KIN_INSTALL_COMMAND)));
    }

    /// A link at the sentinel path is a hard block in fact: startup refuses to
    /// follow one, so a report that stayed healthy would print "first-run
    /// ready" on a host where no supervisor can start. The two contrasts are
    /// the point of the severity rule, so they are asserted beside it:
    /// unreadable metadata proves nothing, and a pre-v2 sibling install does
    /// not stop the binary running the check.
    #[test]
    fn doctor_blocks_on_a_refused_link_but_not_on_states_that_do_not_stop_this_binary() {
        let sentinel = PathBuf::from("/home/dev/.kin/supervisor.start.lock");

        let linked = supervisor_startup_protocol_check(
            SupervisorStartupSentinel::RefusedLink,
            &sentinel,
            &[],
        );
        assert!(
            matches!(linked.status, HealthStatus::Misconfigured),
            "a sentinel startup refuses to follow blocks readiness in fact: {linked:?}"
        );
        assert!(
            blocks_readiness(&linked),
            "doctor must not report readiness on a host where no supervisor can start"
        );
        assert!(
            linked.detail.contains("symlink")
                && linked.detail.contains("cannot start a supervisor"),
            "the detail must name the actual refusal, not just an odd file type: {}",
            linked.detail
        );
        assert!(linked.manual_fix.is_some(), "{linked:?}");

        let unreadable = supervisor_startup_protocol_check(
            SupervisorStartupSentinel::Unreadable,
            &sentinel,
            &[],
        );
        assert!(
            !blocks_readiness(&unreadable),
            "metadata that cannot be read proves nothing either way: {unreadable:?}"
        );

        let sibling = supervisor_startup_protocol_check(
            SupervisorStartupSentinel::ProtocolDirectory,
            &sentinel,
            &[installed_kin(
                "/usr/local/bin/kin",
                InstalledStartupProtocol::Predates(
                    "no supervisor startup protocol at all".to_string(),
                ),
            )],
        );
        assert!(
            !blocks_readiness(&sibling),
            "another install's age does not stop this binary, so it must not share the blocking \
             severity: {sibling:?}"
        );
    }

    #[test]
    fn session_runtime_outside_repo_is_skipped_with_hint() {
        let check = session_runtime_check_for(None);
        assert_eq!(check.id, "session_runtime");
        assert!(matches!(check.status, HealthStatus::Unsupported));
        assert!(check.detail.contains("kin exec"));
    }

    #[test]
    fn session_runtime_in_clean_repo_teaches_the_commands() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        let check = session_runtime_check_for(Some(&layout));
        assert!(matches!(check.status, HealthStatus::Healthy));
        assert!(check.detail.contains("kin exec"));
        assert!(check.detail.contains("kin shell"));
        assert!(check.detail.contains("kin with <assistant>"));
        assert!(
            !check.detail.contains("--session"),
            "doctor must not teach a flag the session surface refuses: {}",
            check.detail
        );
    }

    #[test]
    fn session_runtime_reports_pending_session_workspaces() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("runs/session-leftover")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        let check = session_runtime_check_for(Some(&layout));
        assert!(matches!(check.status, HealthStatus::Stale));
        assert!(check.detail.contains("1 session workspace(s)"));
        assert!(check
            .manual_fix
            .as_deref()
            .is_some_and(|fix| fix.contains("kin reconcile")));
    }

    /// A lever-off profile someone chose must not report as a passing check,
    /// and its remediation must point back at the shipped default rather than
    /// at a profile or a download the default deliberately does not carry.
    #[test]
    #[serial]
    fn doctor_warns_on_a_profile_serving_with_levers_off() {
        let _profile = EnvVarGuard::set("KIN_PROFILE", "compat-v0");
        let _ce = EnvVarGuard::unset("KIN_LOCATE_CROSS_ENCODER_ENABLED");

        let check = check_retrieval_profile();

        assert!(
            matches!(check.status, HealthStatus::Stale),
            "a profile with levers off must not report Healthy, got {:?}",
            check.status
        );
        assert!(
            check.detail.contains("degraded"),
            "detail must say so plainly: {}",
            check.detail
        );
        let fix = check
            .manual_fix
            .as_deref()
            .expect("a degraded profile must carry remediation");
        assert!(
            fix.contains("entity fusion") && fix.contains("lexical parity floor"),
            "remediation must name what is off: {fix}"
        );
        assert!(
            fix.contains("accuracy-v2"),
            "remediation must name the shipped default profile: {fix}"
        );
        // Doctor must not argue with the shipped default: no advice to select
        // the reranker profile, no prompt to prefetch its model.
        assert!(
            !fix.contains("accuracy-v1") && !fix.contains("prefetch"),
            "remediation must not recommend the reranker path: {fix}"
        );
    }

    /// The falsifying half. Without this the check above would pass just as
    /// well against a gate hardcoded to warn, which would prove nothing.
    #[test]
    #[serial]
    fn doctor_stays_green_when_every_lever_the_profile_governs_is_on() {
        let _profile = EnvVarGuard::set("KIN_PROFILE", "accuracy-v1");
        // The explicit override wins over the cached-model + resident-daemon
        // default, so this exercises the all-levers-on state from a test
        // binary, which is never a serving daemon.
        let _ce = EnvVarGuard::set("KIN_LOCATE_CROSS_ENCODER_ENABLED", "1");

        let check = check_retrieval_profile();

        assert!(
            matches!(check.status, HealthStatus::Healthy),
            "the best available profile must be able to report Healthy, got {:?} ({})",
            check.status,
            check.detail
        );
        assert!(
            !check.detail.contains("degraded"),
            "a fully-levered profile must not be labelled degraded: {}",
            check.detail
        );
        assert!(
            check.manual_fix.is_none(),
            "nothing to remediate when nothing is off: {:?}",
            check.manual_fix
        );
    }

    /// Doctor agrees with the shipped default: a fresh install with nothing
    /// configured reports Healthy with no remediation, the deliberately-off
    /// reranker included. A doctor that advises changing a stock install is a
    /// doctor arguing with the product's own default.
    ///
    /// The falsifying halves are the point. A cached reranker model must NOT
    /// change the verdict (the default keeps the reranker off even where the
    /// model is already on disk), while a lever-off profile someone chose is
    /// the state the degraded warning exists for and still reports Stale.
    #[test]
    #[serial]
    fn doctor_agrees_with_the_shipped_default_and_keeps_the_reranker_off() {
        let cache = tempfile::tempdir().unwrap();
        let _hf = EnvVarGuard::set("HF_HOME", cache.path());
        let _model = EnvVarGuard::set("KIN_LOCATE_CROSS_ENCODER_MODEL", "BAAI/bge-reranker-base");
        let _ce = EnvVarGuard::unset("KIN_LOCATE_CROSS_ENCODER_ENABLED");
        let mut profile = EnvVarGuard::unset("KIN_PROFILE");

        let check = check_retrieval_profile();

        assert!(
            matches!(check.status, HealthStatus::Healthy),
            "the shipped default must report Healthy: {:?} ({})",
            check.status,
            check.detail
        );
        assert!(
            check.detail.contains("accuracy-v2")
                && check.detail.contains("cross-encoder rerank: off"),
            "the detail names the default profile and the deliberate reranker state: {}",
            check.detail
        );
        assert!(
            !check.detail.contains("degraded"),
            "the default is not a degradation: {}",
            check.detail
        );
        assert!(
            check.manual_fix.is_none(),
            "no advice may contradict the shipped default: {:?}",
            check.manual_fix
        );

        let report = assemble_health_report("test".to_string(), vec![check]);
        assert!(report.healthy);
        let summary = report.summary();
        assert_eq!(
            (summary.attention, summary.skipped),
            (0, 0),
            "a correct fresh install must close on zero checks needing attention"
        );

        // Falsification one: the reranker model is fully cached, the state
        // earlier doctor advice created on real installs. The default must
        // not silently start serving the reranker, and doctor must not start
        // advising it.
        std::fs::create_dir_all(
            cache
                .path()
                .join("hub")
                .join("models--BAAI--bge-reranker-base")
                .join("snapshots")
                .join("0123456789abcdef"),
        )
        .unwrap();
        let with_cached_model = check_retrieval_profile();
        assert!(
            matches!(with_cached_model.status, HealthStatus::Healthy),
            "a cached model must not change the default verdict: {:?} ({})",
            with_cached_model.status,
            with_cached_model.detail
        );
        assert!(
            with_cached_model
                .detail
                .contains("cross-encoder rerank: off"),
            "the default keeps the reranker off even with the model cached: {}",
            with_cached_model.detail
        );
        assert!(with_cached_model.manual_fix.is_none());

        // Falsification two: a lever-off profile someone chose. The degraded
        // warning still exists and still fires.
        profile.apply("KIN_PROFILE", Some("compat-v0"));
        assert!(
            matches!(check_retrieval_profile().status, HealthStatus::Stale),
            "a profile someone chose is a serving decision they can be told about"
        );
    }

    fn absent_model() -> crate::embed_model::EmbedModelFetch {
        crate::embed_model::EmbedModelFetch {
            model_id: crate::embed_model::DEFAULT_EMBED_MODEL_ID.to_string(),
            cache_dir: Some(
                "/home/dev/.cache/huggingface/hub/models--nomic-ai--nomic-embed-text-v1.5"
                    .to_string(),
            ),
            present: false,
            fetched_bytes: 0,
            expected_bytes: Some(crate::embed_model::DEFAULT_EMBED_MODEL_BYTES),
            fetching: false,
            no_fetch_reason: None,
            relocated_hf_home: None,
        }
    }

    /// A machine that already holds the weights owes nothing, and the check
    /// says where they are rather than only that they exist.
    #[test]
    #[serial]
    fn a_cached_embedding_model_is_healthy_and_names_where_it_sits() {
        let _endpoint = EnvVarGuard::unset("HF_ENDPOINT");
        let cached = crate::embed_model::EmbedModelFetch {
            present: true,
            ..absent_model()
        };
        let check = embedding_model_check_from(&cached, None);
        assert!(matches!(check.status, HealthStatus::Healthy));
        assert!(
            check
                .detail
                .contains("models--nomic-ai--nomic-embed-text-v1.5"),
            "the cache location is named: {}",
            check.detail
        );
        assert!(
            !check.detail.contains("fetches about"),
            "no download may be announced for a model that is here: {}",
            check.detail
        );
        assert!(check.manual_fix.is_none());
    }

    /// A machine without the weights that can reach the host is doing expected
    /// first-run work: it needs attention, states the cost and the source, and
    /// does not block readiness.
    #[test]
    #[serial]
    fn a_missing_embedding_model_states_the_fetch_it_will_do() {
        let _endpoint = EnvVarGuard::unset("HF_ENDPOINT");
        let check = embedding_model_check_from(&absent_model(), Some(true));
        assert!(
            matches!(check.status, HealthStatus::Pending),
            "a reachable first fetch is expected work, not a fault: {:?}",
            check.status
        );
        assert!(
            check.detail.contains("about 523 MB") && check.detail.contains("huggingface.co"),
            "the size and the source are both named: {}",
            check.detail
        );
        assert!(
            check
                .manual_fix
                .as_deref()
                .is_some_and(|fix| fix.contains("pre-seed") && fix.contains("KIN_EMBED_MODEL_ID")),
            "the way to avoid the download is named: {:?}",
            check.manual_fix
        );
        assert!(!blocks_readiness(&check));
    }

    /// A machine without the weights that cannot reach the host fails loud and
    /// blocks readiness, naming the egress the fetch requires.
    #[test]
    #[serial]
    fn an_unreachable_model_host_fails_loud_with_its_egress_requirement() {
        let _endpoint = EnvVarGuard::unset("HF_ENDPOINT");
        let check = embedding_model_check_from(&absent_model(), Some(false));
        assert!(
            matches!(check.status, HealthStatus::Missing),
            "a host that cannot fetch the model can never embed: {:?}",
            check.status
        );
        assert!(blocks_readiness(&check), "the failure has to be loud");
        assert!(
            check
                .detail
                .contains("did not reach huggingface.co:443 within 3s"),
            "the probe reports what it established: {}",
            check.detail
        );
        assert!(
            check.detail.contains("until that lands nothing embeds"),
            "the consequence is named: {}",
            check.detail
        );
    }

    /// A configuration that fetches nothing is healthy and says why, so an
    /// operator running against an endpoint is never told to expect a download.
    #[test]
    #[serial]
    fn a_configuration_that_needs_no_model_is_healthy_and_says_why() {
        let _endpoint = EnvVarGuard::unset("HF_ENDPOINT");
        let remote = crate::embed_model::EmbedModelFetch {
            model_id: "text-embedding-3-small".to_string(),
            no_fetch_reason: Some(
                "the openai provider embeds over HTTP, so no model is fetched to this machine"
                    .to_string(),
            ),
            ..Default::default()
        };
        let check = embedding_model_check_from(&remote, None);
        assert!(matches!(check.status, HealthStatus::Healthy));
        assert!(
            check.detail.contains("embeds over HTTP"),
            "{}",
            check.detail
        );
        assert!(check.manual_fix.is_none());
    }

    /// A relocated `HF_HOME` is reported wherever the cache is, because seeding
    /// the model there does not stop the loader fetching it again.
    #[test]
    #[serial]
    fn a_relocated_hf_home_is_reported_beside_the_cache_the_loader_reads() {
        let _endpoint = EnvVarGuard::unset("HF_ENDPOINT");
        let relocated = crate::embed_model::EmbedModelFetch {
            relocated_hf_home: Some("/mnt/models/hf".to_string()),
            ..absent_model()
        };
        let check = embedding_model_check_from(&relocated, Some(true));
        assert!(
            check.detail.contains("HF_HOME is set to /mnt/models/hf")
                && check.detail.contains("does not read"),
            "the disagreement between the two roots is reported: {}",
            check.detail
        );
    }

    /// A model this build has never measured gets no size attributed to it.
    ///
    /// The default figure is the default model's. Printing it for an overridden
    /// `KIN_EMBED_MODEL_ID` would put a number nobody measured in front of an
    /// operator, which is worse than printing none.
    #[test]
    #[serial]
    fn an_overridden_model_is_never_given_the_default_models_size() {
        let _endpoint = EnvVarGuard::unset("HF_ENDPOINT");
        let custom = crate::embed_model::EmbedModelFetch {
            model_id: "acme/private-embed".to_string(),
            expected_bytes: None,
            ..absent_model()
        };
        let check = embedding_model_check_from(&custom, Some(true));
        assert!(
            !check.detail.contains("523"),
            "no measured size may be attributed to an unmeasured model: {}",
            check.detail
        );
        assert!(
            check
                .detail
                .contains("fetches the model from huggingface.co"),
            "the fetch is still named without a size: {}",
            check.detail
        );
    }
}
