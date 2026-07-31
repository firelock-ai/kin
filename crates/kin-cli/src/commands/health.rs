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
    check_binary_in_path, detect_shell, hook_filename, kin_dir, shell_rc, shim_filename,
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
                HealthStatus::Missing | HealthStatus::Misconfigured | HealthStatus::Stale => {
                    summary.attention += 1
                }
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
    checks.push(check_retrieval_profile());
    checks.push(check_binary_assessment_load());

    assemble_health_report(env::consts::OS.to_string(), checks)
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
/// A pre-v2 install is `Stale`, not `Misconfigured`: it does not block the
/// binary running this check, so it must not flip the report's readiness. A
/// legacy marker file is `Misconfigured`, because the current binary refuses to
/// start a supervisor at all while one exists.
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
        SupervisorStartupSentinel::Unreadable => HealthCheck::new(
            "supervisor_startup_protocol",
            "Supervisor protocol",
            HealthStatus::Stale,
            format!("{sentinel_path} exists but is neither a directory nor a regular file"),
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
    // daemon_client. Probing costs a subprocess per install, so it is requested
    // only in the state whose answer can change the verdict.
    let installed: Vec<InstalledKin> =
        if matches!(sentinel, SupervisorStartupSentinel::ProtocolDirectory) {
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
/// reported as Unsupported rather than a failure. Inside a repo, a daemon that
/// is not reachable is reported as Stale (recoverable): any `kin` command in the
/// repo auto-starts it, so it is not a hard first-run blocker.
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
        None => HealthCheck::new(
            "daemon_running",
            "kin-daemon running",
            HealthStatus::Stale,
            format!("no daemon reachable for {repo} — it auto-starts on first use"),
        )
        .fixable()
        .with_manual_fix("run any `kin` command in the repo to auto-start the daemon"),
    }
}

fn check_vfs_projection() -> HealthCheck {
    if cfg!(target_os = "windows") {
        return HealthCheck::new(
            "vfs_projection",
            "VFS projection",
            HealthStatus::Unsupported,
            "Windows uses ProjFS, which is not shell-auto-injected",
        )
        .with_platform_note(
            "Windows projection uses ProjFS (planned), enabled via the optional \
             feature and started by an explicit daemon init — it is not injected \
             by the shell hook like the macOS/Linux shim.",
        )
        .with_manual_fix(
            "Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart",
        );
    }

    let lib_path = match kin_dir() {
        Ok(dir) => dir.join("lib").join(shim_filename()),
        Err(e) => {
            return HealthCheck::new(
                "vfs_projection",
                "VFS projection",
                HealthStatus::Missing,
                format!("could not resolve ~/.kin: {e}"),
            );
        }
    };

    vfs_projection_check_for(&lib_path)
}

/// The durable step that repairs a missing or corrupt shim when `kin doctor
/// --fix` cannot source one locally. It must NEVER name `kin doctor --fix`
/// itself: this text is reprinted in the post-`--fix` "still needs manual steps"
/// list, where pointing back at the command that just ran is a dead loop.
const SHIM_REINSTALL_HINT: &str =
    "reinstall kin to restore the shim: curl -fsSL https://get.kinlab.dev/install | sh";

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

/// Build the `vfs_projection` check from a resolved shim path. Split out from
/// [`check_vfs_projection`] so the size/magic classification is testable.
fn vfs_projection_check_for(lib_path: &Path) -> HealthCheck {
    match classify_shim(lib_path) {
        ShimState::Valid(size) => HealthCheck::new(
            "vfs_projection",
            "VFS projection",
            HealthStatus::Healthy,
            format!("shim installed ({size} bytes, {})", lib_path.display()),
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
            format!("shim not installed at {}", lib_path.display()),
        )
        .fixable()
        .with_manual_fix(SHIM_REINSTALL_HINT),
    }
}

fn check_repo_init() -> HealthCheck {
    let cwd = env::current_dir().unwrap_or_default();
    match kin_core::KinLayout::discover(&cwd) {
        Some(layout) => HealthCheck::new(
            "repo_init",
            "Repository",
            HealthStatus::Healthy,
            format!("Kin repository at {}", layout.root().display()),
        ),
        None => HealthCheck::new(
            "repo_init",
            "Repository",
            HealthStatus::Missing,
            "current directory is not inside a Kin repository",
        )
        .with_manual_fix("run `kin init .` to initialize a repository here"),
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

    if hook_installed && rc_sources && (on_path || rc_sets_path) {
        let detail = match (on_path, rc_sets_path) {
            (true, _) => {
                format!(
                    "{shell} hook installed and sourced from {rc_display}; {} on PATH",
                    bin_dir.display()
                )
            }
            (false, true) => {
                format!(
                    "{shell} hook installed and sourced from {rc_display}; {} will be on PATH after shell restart",
                    bin_dir.display()
                )
            }
            (false, false) => unreachable!(),
        };
        HealthCheck::new(
            "shell_path",
            "Shell integration",
            HealthStatus::Healthy,
            detail,
        )
        .fixable()
    } else {
        let mut missing = Vec::new();
        if !hook_installed {
            missing.push(format!("hook missing at {}", hook_path.display()));
        }
        if !rc_sources {
            missing.push(format!("{rc_display} does not source the kin-vfs hook"));
        }
        if !on_path && !rc_sets_path {
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
    let home = directories::BaseDirs::new().map(|d| d.home_dir().to_path_buf());
    let home = match home {
        Some(h) => h,
        None => return Vec::new(),
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

fn current_health_repo() -> Option<PathBuf> {
    crate::commands::managed_config_scope::discover_repo_root()
}

/// Inspect a single MCP config file for a `kin` server entry carrying the
/// agent-default tool profile.
///
/// Handles both JSON configs (`mcpServers.kin`) and TOML configs such as
/// Codex's `~/.codex/config.toml` (`mcp_servers.kin`); TOML is normalized to
/// JSON so the same checks apply.
pub(crate) fn evaluate_mcp_client(path: &PathBuf) -> (HealthStatus, String) {
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
            let profile = entry
                .get("env")
                .and_then(|e| e.get("KIN_MCP_TOOL_PROFILE"))
                .and_then(|p| p.as_str());
            if profile == Some("agent-default") {
                (
                    HealthStatus::Healthy,
                    format!(
                        "{servers_key}.kin present with agent-default profile ({})",
                        path.display()
                    ),
                )
            } else {
                (
                    HealthStatus::Misconfigured,
                    format!(
                        "{servers_key}.kin present but KIN_MCP_TOOL_PROFILE is {} (expected agent-default) in {}",
                        profile.unwrap_or("unset"),
                        path.display()
                    ),
                )
            }
        }
    }
}

fn evaluate_antigravity_binding(path: &Path, workspace: bool) -> Option<(HealthStatus, String)> {
    let repo_root = if workspace {
        path.parent()?.parent()?.canonicalize().ok()?
    } else {
        current_health_repo()?
    };
    let root: Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    let entry = root.get("mcpServers")?.get("kin")?;
    let expected_command =
        kin_dir()
            .ok()?
            .join("bin")
            .join(if cfg!(windows) { "kin.exe" } else { "kin" });
    let command_matches = entry.get("command").and_then(Value::as_str)
        == Some(expected_command.to_string_lossy().as_ref());
    let expected_args = serde_json::json!(["mcp", "start", "--repo", repo_root.to_string_lossy()]);
    let args_match = entry.get("args") == Some(&expected_args);
    let cwd_matches = !workspace
        || entry.get("cwd").and_then(Value::as_str) == Some(repo_root.to_string_lossy().as_ref());
    if command_matches && args_match && cwd_matches {
        None
    } else {
        Some((
            HealthStatus::Misconfigured,
            format!(
                "Antigravity Kin binding at {} does not use the exact managed binary, repository arguments, or workspace cwd",
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
    let expected_repo = current_health_repo()?;
    evaluate_codex_binding_for(path, &expected_repo)
}

fn check_mcp_clients() -> Vec<HealthCheck> {
    let clients: Vec<McpClient> = mcp_client_config_paths()
        .into_iter()
        .map(|(id, label, path)| McpClient { id, label, path })
        .filter(|c| c.path.exists())
        .collect();

    if clients.is_empty() {
        return vec![HealthCheck::new(
            "mcp_clients",
            "AI client MCP config",
            HealthStatus::Healthy,
            "no AI client config files detected — nothing to configure",
        )];
    }

    clients
        .into_iter()
        .map(|client| {
            let (mut status, mut detail) = evaluate_mcp_client(&client.path);
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
            let mut check = HealthCheck::new(
                &format!("mcp_client_{}", client.id),
                &format!("MCP: {}", client.label),
                status,
                detail,
            );
            if is_failing(&check.status) {
                check = check.fixable().with_manual_fix(
                    "run `kin setup` (or `kin doctor --fix`) to re-merge the kin MCP server entry",
                );
            }
            check
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
    let home = directories::BaseDirs::new().map(|d| d.home_dir().to_path_buf());
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
        .with_platform_note("hosted connect is not yet a first-run flow")
        .with_manual_fix("run `kin auth login` once hosted connect is available")
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
        HealthCheck::new(
            "semantic_query_readiness",
            "Semantic query readiness",
            HealthStatus::Healthy,
            detail,
        )
    } else {
        HealthCheck::new(
            "semantic_query_readiness",
            "Semantic query readiness",
            HealthStatus::Stale,
            detail,
        )
        .with_manual_fix("allow daemon embedding to finish or run `kin embed`")
    }
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
        return HealthCheck::new(
            "semantic_query_readiness",
            "Semantic query readiness",
            HealthStatus::Missing,
            "daemon not reachable for this repository",
        )
        .with_manual_fix("run any `kin` command in the repo to auto-start the daemon");
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

/// Report the active retrieval quality profile and the effective lever set,
/// so an operator can see at a glance whether they are getting full
/// retrieval capability — and why not, when a lever is off.
fn check_retrieval_profile() -> HealthCheck {
    let profile = crate::retrieval_profile::RetrievalProfile::from_env();
    let ce_model = env::var("KIN_LOCATE_CROSS_ENCODER_MODEL")
        .unwrap_or_else(|_| "BAAI/bge-reranker-base".to_string());
    let ce_cached = crate::retrieval_profile::cross_encoder_model_cached(&ce_model);
    // Report the daemon-serving default (the state queries actually run
    // under), not this one-shot CLI process's own gate.
    let ce_active = env::var("KIN_LOCATE_CROSS_ENCODER_ENABLED")
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
        .unwrap_or(
            matches!(
                profile,
                crate::retrieval_profile::RetrievalProfile::AccuracyV1
            ) && ce_cached,
        );
    let detail =
        format!(
        "profile {} — semantic_locate routing: {}; entity fusion: {}; lexical parity floor: {}; \
         cross-encoder rerank: {} (model {} {})",
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
    let check = HealthCheck::new(
        "retrieval_profile",
        "Retrieval quality profile",
        HealthStatus::Healthy,
        detail,
    );
    if !ce_cached {
        check.with_manual_fix(
            "to enable the reranker, prefetch its model once with \
             KIN_LOCATE_CROSS_ENCODER_ENABLED=1 (downloads on first use)",
        )
    } else {
        check
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::ffi::{OsStr, OsString};

    struct EnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
            let previous = env::var_os(key);
            env::set_var(key, value.as_ref());
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = env::var_os(key);
            env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => env::set_var(self.key, value),
                None => env::remove_var(self.key),
            }
        }
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        use std::io::Write;
        std::fs::File::create(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
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

        for path in [&missing, &empty, &corrupt] {
            let check = vfs_projection_check_for(path);
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

    #[tokio::test]
    async fn report_is_non_empty_and_serializes_with_ids() {
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
        let _registry_path = EnvGuard::set("KIN_REGISTRY_PATH", &registry);

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

    #[test]
    #[serial]
    fn shell_path_is_healthy_when_rc_declares_path_for_next_shell() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let kin_home = tmp.path().join("kin-home");
        let hook_dir = kin_home.join("shell");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&hook_dir).unwrap();

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

        let _home = EnvGuard::set("HOME", &home);
        let _kin_home = EnvGuard::set("KIN_HOME", &kin_home);
        let _kin_dir = EnvGuard::remove("KIN_DIR");
        let _shell = EnvGuard::set("SHELL", "/bin/zsh");
        let _ps_module_path = EnvGuard::remove("PSModulePath");
        let _ps_version_table = EnvGuard::remove("PSVersionTable");
        let _profile = EnvGuard::remove("PROFILE");
        let _path = EnvGuard::set("PATH", "/usr/bin");

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

    fn check_with(id: &str, status: HealthStatus) -> HealthCheck {
        HealthCheck::new(id, id, status, "")
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
        let pending = crate::commands::resources::EmbedRuntimeState {
            embeddings_indexed: 40,
            embeddings_total: 41,
            embeddings_pending: 1,
            ..Default::default()
        };
        let stale = semantic_query_health_from_runtime("http://daemon", &pending);
        assert!(matches!(stale.status, HealthStatus::Stale));
        assert!(stale.detail.contains("40/41 embeddings indexed, 1 pending"));
        assert!(stale.manual_fix.is_some());

        let failed = crate::commands::resources::EmbedRuntimeState {
            embed_worker_failed: true,
            ..pending
        };
        let missing = semantic_query_health_from_runtime("http://daemon", &failed);
        assert!(matches!(missing.status, HealthStatus::Missing));
        assert!(missing.detail.contains("embedding worker failed"));
        assert!(missing.manual_fix.is_some());
    }

    #[test]
    fn health_status_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&HealthStatus::Healthy).unwrap(),
            "\"healthy\""
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

    #[test]
    fn mcp_config_without_agent_default_profile_is_misconfigured() {
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

        let (status, _detail) = evaluate_mcp_client(&path);
        assert!(matches!(status, HealthStatus::Misconfigured));
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

        let (status, _detail) = evaluate_mcp_client(&path);
        assert!(matches!(status, HealthStatus::Healthy));
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

        let (status, detail) = evaluate_mcp_client(&path);
        assert!(matches!(status, HealthStatus::Misconfigured));
        assert!(detail.contains("--global"));
    }

    #[test]
    fn mcp_config_missing_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let (status, _detail) = evaluate_mcp_client(&path);
        assert!(matches!(status, HealthStatus::Missing));
    }

    #[test]
    fn mcp_config_toml_with_agent_default_profile_is_healthy() {
        // Codex registers MCP servers in ~/.codex/config.toml, not mcp.json.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[mcp_servers.kin]\ncommand = \"kin\"\nargs = [\"mcp\", \"start\"]\nenv = { KIN_MCP_TOOL_PROFILE = \"agent-default\" }\n",
        )
        .unwrap();

        let (status, detail) = evaluate_mcp_client(&path);
        assert!(matches!(status, HealthStatus::Healthy), "got: {detail}");
        assert!(detail.contains("mcp_servers.kin"));
    }

    #[test]
    fn mcp_config_toml_without_kin_entry_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "model = \"o3\"\n").unwrap();

        let (status, detail) = evaluate_mcp_client(&path);
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
}
