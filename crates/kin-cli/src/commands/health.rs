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
    check_binary_in_path, configured_mcp_launcher, detect_shell, home_dir, hook_filename, kin_dir,
    shell_rc, shim_filename, CANONICAL_NPM_MCP_COMMAND, CANONICAL_NPM_MCP_PACKAGE,
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
    checks.push(check_background_work().await);
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

    vfs_projection_check_for(&lib_path, projection_installed_under(&kin_home))
}

/// Name of the projection driver binary the installer places beside `kin`.
fn vfs_binary_filename() -> &'static str {
    if cfg!(target_os = "windows") {
        "kin-vfs.exe"
    } else {
        "kin-vfs"
    }
}

/// Whether filesystem projection was actually installed under `kin_home`.
///
/// The installer ships projection only where it can run. When the archive
/// carries no projection, or the host loader cannot execute the one it carries,
/// the installer deletes `kin-vfs` and the shim together and says so out loud:
/// "Filesystem projection is unavailable on this platform; core CLI and daemon
/// are fully functional without it." So a shim absent beside an absent
/// `kin-vfs` is that sanctioned outcome, not a broken install — and telling
/// such a user to reinstall contradicts what the installer just told them and
/// sends them somewhere that cannot help. A shim absent while `kin-vfs` is
/// installed is the opposite case: projection is on this machine and the half
/// that gets injected into processes is gone.
fn projection_installed_under(kin_home: &Path) -> bool {
    kin_home.join("bin").join(vfs_binary_filename()).exists()
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

/// Build the `vfs_projection` check from a resolved shim path and whether
/// projection is installed on this machine at all. Split out from
/// [`check_vfs_projection`] so the size/magic classification is testable.
fn vfs_projection_check_for(lib_path: &Path, projection_installed: bool) -> HealthCheck {
    match classify_shim(lib_path) {
        ShimState::Missing if !projection_installed => HealthCheck::new(
            "vfs_projection",
            "VFS projection",
            HealthStatus::Unsupported,
            "filesystem projection is not installed on this system; the CLI and daemon \
             are fully functional without it",
        )
        .with_platform_note(
            "The installer ships projection only where it can run, and removes the kin-vfs \
             driver and its shim together when it cannot. Neither is present here, so nothing \
             is missing.",
        ),
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

fn evaluate_antigravity_binding(path: &Path, workspace: bool) -> Option<(HealthStatus, String)> {
    let repo_root = if workspace {
        path.parent()?.parent()?.canonicalize().ok()?
    } else {
        current_health_repo()?
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
    let expected_repo = current_health_repo()?;
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

/// Semantic readiness when no daemon is running to ask.
///
/// This is where every repository sits until its first command needs a daemon,
/// so it is an unread state rather than a failed one, and reporting it as a
/// failure is what makes an install that did everything right end on a red
/// summary. The authority gate is unchanged for every state that *can* be read:
/// a reachable daemon whose graph coverage is incomplete or unreadable is still
/// Stale, and Stale on this check still blocks readiness.
#[cfg(feature = "vector")]
/// Render the daemon's background-work disclosure as a health check.
///
/// Split from its fetch so the reporting rule is testable without a daemon.
/// Healthy is the answer whenever nothing was stopped, including while passes
/// are working hard: this check reports faults, and the ordinary account of what
/// the daemon is spending lives in `kin resources`.
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
    if stopped.is_empty() {
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
                "{cpu}; {} background pass(es), {working} working, none stopped",
                work.passes.len()
            ),
        );
    }
    let reasons = stopped
        .iter()
        .filter_map(|pass| pass.stopped_reason.as_deref())
        .collect::<Vec<_>>()
        .join("; ");
    HealthCheck::new(
        "background_work",
        "Background work",
        HealthStatus::Stale,
        format!("{cpu}; {reasons}"),
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

    // Incomplete coverage reads identically whether this is a first run or a
    // repository whose finished index was thrown away at open. Only one of them
    // means work already paid for is being paid for again, so when the daemon
    // knows which it is, say so instead of leaving it to be inferred.
    let Some(reason) = &runtime.vector_index_discarded else {
        return HealthCheck::new(
            "semantic_query_readiness",
            "Semantic query readiness",
            HealthStatus::Stale,
            detail,
        )
        .with_manual_fix("allow daemon embedding to finish or run `kin embed`");
    };

    HealthCheck::new(
        "semantic_query_readiness",
        "Semantic query readiness",
        HealthStatus::Stale,
        format!("{detail}; {reason}, so it is being rebuilt from scratch"),
    )
    .with_manual_fix(
        "allow daemon embedding to finish or run `kin embed`; the rebuild is not lost work \
         repeating itself once it completes",
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
    // Every lever is read back from the profile rather than assumed from its
    // name, so a profile whose defaults change cannot leave this check
    // asserting a lever set the serving path no longer uses.
    //
    // `declaration_cutoff_default` is deliberately excluded: it is dark for
    // EVERY profile pending its A/B graduation gate, so counting it would make
    // the best available profile report degraded forever, and a check that can
    // never be green is a check nobody reads.
    let levers_off: Vec<&str> = [
        (!profile.semantic_locate_fused()).then_some("fused semantic_locate routing"),
        (!profile.entity_fusion_default()).then_some("entity fusion"),
        (!profile.lexical_floor_readmit_default()).then_some("lexical parity floor"),
        (!ce_active).then_some("cross-encoder rerank"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let detail =
        format!(
        "{}profile {} — semantic_locate routing: {}; entity fusion: {}; lexical parity floor: {}; \
         cross-encoder rerank: {} (model {} {})",
        if levers_off.is_empty() { "" } else { "degraded: " },
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
    // A profile serving with levers off is answering worse than this build can,
    // and reporting that as a passing check tells a first-run user their weakest
    // retrieval configuration is the healthy one. Stale is this report's
    // advisory tier: it renders as a yellow warning and counts as needing
    // attention, without blocking readiness the way Missing/Misconfigured do,
    // because a degraded profile still serves.
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
    // The remediation was previously attached only when the reranker model was
    // uncached, and the Healthy status meant the renderer never printed it. Name
    // what is off, and name the better profile from its own identifier so this
    // string cannot drift from the enum.
    let best = crate::retrieval_profile::RetrievalProfile::AccuracyV1;
    let mut fix = format!("off: {}", levers_off.join(", "));
    if profile != best {
        fix.push_str(&format!(
            "; set KIN_PROFILE={} for the measured-accuracy defaults",
            best.name()
        ));
    }
    if !ce_cached {
        fix.push_str(
            "; prefetch the reranker model once with \
             KIN_LOCATE_CROSS_ENCODER_ENABLED=1 (downloads on first use)",
        );
    }
    check.with_manual_fix(fix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_core::test_env::EnvVarGuard;
    use serial_test::serial;

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
            stopped_reason: stopped_reason.map(str::to_string),
        }
    }

    #[test]
    fn background_work_is_healthy_while_passes_are_merely_busy() {
        let check =
            background_work_health_from_state(&crate::commands::resources::DaemonWorkState {
                daemon_cpu_seconds: Some(41.6),
                passes: vec![
                    pass_report("embed", "working", None),
                    pass_report("reconcile", "idle", None),
                ],
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

    /// The falsification: the same shape with a stopped pass must NOT read
    /// healthy, and must carry the daemon's own reason rather than a summary
    /// invented here.
    #[test]
    fn background_work_reports_a_stopped_pass_and_repeats_its_reason() {
        let check =
            background_work_health_from_state(&crate::commands::resources::DaemonWorkState {
                daemon_cpu_seconds: Some(48_180.0),
                passes: vec![
                    pass_report(
                        "embed",
                        "stopped",
                        Some("the embed pass held the CPU for 601s"),
                    ),
                    pass_report("reconcile", "idle", None),
                ],
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
            let check = vfs_projection_check_for(path, true);
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

        let uninstalled = vfs_projection_check_for(&missing, false);
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

        // Falsification: flip only the installed flag, keep the same path.
        let installed = vfs_projection_check_for(&missing, true);
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
            let check = vfs_projection_check_for(path, false);
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

    #[test]
    fn projection_is_detected_from_the_driver_beside_the_managed_binaries() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!projection_installed_under(dir.path()));

        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        write_file(&bin.join(vfs_binary_filename()), b"driver");
        assert!(projection_installed_under(dir.path()));
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
            vfs_projection_check_for(&dir.path().join("no-shim"), false),
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
                && semantic.detail.contains("rebuilt from scratch"),
            "a discarded index must be named, not left to be inferred from coverage: {}",
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

    /// Regression, FIR-1911: on Windows the first `kin setup` wrote the global
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

    /// The degraded default must not report as a passing check. A first-run
    /// user otherwise measures this build's weakest retrieval configuration
    /// and is told it is the healthy one.
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
            fix.contains("cross-encoder rerank"),
            "remediation must name what is off: {fix}"
        );
        assert!(
            fix.contains("accuracy-v1"),
            "remediation must name the better profile: {fix}"
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
}
