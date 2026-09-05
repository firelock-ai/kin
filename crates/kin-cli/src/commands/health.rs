// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Machine-readable first-run health engine.
//!
//! [`run_health_checks`] probes the real filesystem, daemon, and agent
//! configuration and returns a [`HealthReport`]. It is the single source of
//! truth behind `kin setup status [--json]` and `kin doctor [--fix]`.

use std::env;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use serde_json::Value;

use crate::commands::auth::default_base_url_for_health;
use crate::commands::setup::{
    check_binary_in_path, configured_mcp_launcher, detect_shell, detected_ai_client_names,
    home_dir, hook_filename, kin_dir, shell_path_rcs, shell_rc, shim_filename,
    CANONICAL_NPM_MCP_COMMAND, CANONICAL_NPM_MCP_PACKAGE,
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
    /// Expected first-run work a correct install is still doing. Nothing is
    /// wrong and nothing is lost, so it never makes the verdict
    /// [`HealthVerdict::Failing`]. It does keep the report out of
    /// [`HealthVerdict::Ready`], because the surface is not answering at full
    /// strength yet and a roll-up that said otherwise would claim more than
    /// this row supports.
    Pending,
    /// A real shortfall in the machine or container Kin was asked to run on,
    /// rather than in the install. Nothing about the install is wrong, so it
    /// never makes the verdict [`HealthVerdict::Failing`]: a host below a
    /// measured cost is a fact about the host. It does keep the report out of
    /// [`HealthVerdict::Ready`], for the same reason `Pending` does.
    Degraded,
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

/// The overall verdict a [`HealthReport`] carries, as one word.
///
/// The boolean beside it answers "is everything answering at full strength",
/// which is the only question a boolean can carry honestly. This says which of
/// the two ways a report can fall short of that it is in, so a reader can tell
/// an install that is still warming up on a small host from one that is broken
/// without re-deriving it from the rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthVerdict {
    /// Every check in scope is [`HealthStatus::Healthy`].
    Ready,
    /// Nothing about the install is wrong, and something is not answering at
    /// full strength yet: work still in flight, or ground the host never had.
    NeedsAttention,
    /// Something about the install itself is wrong, or the semantic authority
    /// cannot be read. See [`blocks_readiness`].
    Failing,
}

/// Aggregated report across every health check.
///
/// `healthy` and `verdict` are derived from `checks` by [`join_over_checks`]
/// and are private for that reason: the aggregate is not an independent
/// opinion, and every place that could write one by hand is a place the
/// roll-up can start claiming more than its components support. Build one with
/// [`HealthReport::from_checks`], read the aggregate with [`HealthReport::healthy`]
/// and [`HealthReport::verdict`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthReport {
    pub platform: String,
    pub checks: Vec<HealthCheck>,
    healthy: bool,
    verdict: HealthVerdict,
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

/// Whether a check names something wrong with the INSTALL.
///
/// Most `Stale` checks describe recoverable local drift and remain advisory,
/// but semantic readiness is an authority gate: if daemon graph coverage is
/// stale or cannot be read, the report cannot honestly claim the semantic
/// query surface is ready.
///
/// `Pending` sits deliberately outside this predicate. It names work a correct
/// install is expected to be doing on its way to ready, not ground a ready
/// install lost, and a gate that cannot tell those apart fails every fresh
/// install for succeeding.
///
/// `Degraded` sits outside it too, for the opposite reason. It names ground the
/// host never had rather than ground a correct install lost, and a gate that
/// failed on one would fail every correct install on a small machine.
///
/// This is not the same question as whether the report may claim readiness.
/// That is [`needs_attention`], and conflating the two is what FIR-2919
/// records.
fn blocks_readiness(check: &HealthCheck) -> bool {
    is_failing(&check.status)
        || (check.id == "semantic_query_readiness" && matches!(check.status, HealthStatus::Stale))
}

/// Whether a check keeps the report out of [`HealthVerdict::Ready`].
///
/// The one rule the whole roll-up is built from, and the reason it is one line:
/// a check is out of scope only when the platform or the context puts it out of
/// scope, which is exactly `Unsupported`. Every other status is a component
/// that is not answering at full strength, so a report claiming readiness over
/// one claims more than its components support.
///
/// FIR-2919 is what that costs when it is spelt twice. The roll-up gated on
/// `blocks_readiness` while the printed readiness line gated on this, so a
/// fresh Windows install emitted 19 `unsupported` rows, `embedding_model`
/// `pending` and `memory_floor` `degraded` under `"healthy": true` while its
/// own last printed line read "2 checks need attention". The release's install
/// proof threw on the contradiction and fenced v0.6.1.
///
/// `pub(crate)` so the printed readiness line in `setup.rs` can call it. It
/// held a verbatim copy of this predicate to derive its own count, which is the
/// same shape as the defect one layer up: two surfaces of one report, each
/// correct on its own, deriving the same rule twice.
pub(crate) fn needs_attention(check: &HealthCheck) -> bool {
    !matches!(
        check.status,
        HealthStatus::Healthy | HealthStatus::Unsupported
    )
}

/// The whole roll-up, as one function of the checks.
///
/// Nothing else in Kin may compute an overall health verdict. Callers that
/// need one build a [`HealthReport`] and read it back.
fn join_over_checks(checks: &[HealthCheck]) -> HealthVerdict {
    if checks.iter().any(blocks_readiness) {
        HealthVerdict::Failing
    } else if checks.iter().any(needs_attention) {
        HealthVerdict::NeedsAttention
    } else {
        HealthVerdict::Ready
    }
}

fn assemble_health_report(platform: String, checks: Vec<HealthCheck>) -> HealthReport {
    HealthReport::from_checks(platform, checks)
}

/// A pass/attention/skip tally over a set of checks, used for the one-line
/// readiness summary printed by `kin doctor` and `kin setup status`.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct HealthSummary {
    /// Checks that are Healthy.
    pub passed: usize,
    /// Checks that need attention, which is every check [`needs_attention`]
    /// answers true for: Missing, Misconfigured, Stale, Pending or Degraded.
    /// The list was already this long when the doc said three; the tally and
    /// the roll-up read one predicate now, so they cannot drift again.
    pub attention: usize,
    /// Checks that do not apply on this platform / context (Unsupported).
    pub skipped: usize,
}

impl HealthReport {
    /// Build a report and derive its aggregate from the checks it carries.
    ///
    /// The only way to make one. `healthy` and `verdict` are computed here by
    /// [`join_over_checks`] and are private, so no caller and no test can hand
    /// the report an aggregate its own rows do not support.
    pub fn from_checks(platform: String, checks: Vec<HealthCheck>) -> Self {
        let verdict = join_over_checks(&checks);
        Self {
            platform,
            checks,
            healthy: verdict == HealthVerdict::Ready,
            verdict,
        }
    }

    /// Whether every check in scope is answering at full strength.
    ///
    /// True exactly when [`HealthReport::verdict`] is [`HealthVerdict::Ready`].
    /// A reader that needs to tell a warming install from a broken one reads
    /// the verdict; this boolean cannot carry that difference and must not be
    /// asked to.
    pub fn healthy(&self) -> bool {
        self.healthy
    }

    /// The overall verdict, derived from the checks by [`join_over_checks`].
    pub fn verdict(&self) -> HealthVerdict {
        self.verdict
    }

    /// Tally checks into pass / needs-attention / not-applicable buckets.
    ///
    /// The attention bucket is [`needs_attention`] rather than its own list of
    /// statuses, so the tally and the roll-up cannot disagree about what needs
    /// attention. They did: the printed tally counted `pending` and `degraded`
    /// while the aggregate did not (FIR-2919).
    pub fn summary(&self) -> HealthSummary {
        let mut summary = HealthSummary {
            passed: 0,
            attention: 0,
            skipped: 0,
        };
        for check in &self.checks {
            if needs_attention(check) {
                summary.attention += 1;
            } else if matches!(check.status, HealthStatus::Unsupported) {
                summary.skipped += 1;
            } else {
                summary.passed += 1;
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
        check_daemon_idle_window(),
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
    // Keep the exact coverage state beside the check that interpreted it. The
    // host-pressure row below reads the same fact: an old embed refusal cannot
    // describe work only after the selected graph is wholly indexed. `None`
    // remains an unread observation and must never be treated as complete.
    let semantic_readiness = check_semantic_query_readiness().await;
    let embedding_coverage = semantic_readiness.embedding_coverage;
    checks.push(semantic_readiness.check);
    // One `graph status` for the whole run, handed to every row that reads graph
    // truth. `kin graph status` is the slowest surface Kin has on a real store,
    // and it was fetched per row, so each row answering from graph truth added a
    // whole one to the wall time of a doctor run on exactly the stores where an
    // operator is most likely to be running doctor because something is wrong.
    let graph_status = RunGraphStatus::for_run();
    checks.push(check_reference_edge_coverage(&graph_status).await);
    checks.push(check_relation_census(&graph_status).await);
    checks.push(check_hydration_semantics());
    checks.push(check_parse_coverage(&graph_status).await);
    checks.push(check_graph_section(&graph_status).await);
    checks.push(check_background_work().await);
    checks.push(check_embedding_model().await);
    checks.push(check_memory_floor());
    checks.push(check_commit_memory_headroom());
    checks.push(check_daemon_kill_record());
    checks.push(check_interrupted_init());
    checks.push(check_stranded_init_stage());
    checks.push(check_suspended_sweep());
    checks.extend(check_memory_pressure_rows(embedding_coverage));
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

/// Report the idle window the next CLI-spawned daemon for this repository will
/// take, and what decided it.
///
/// Always advisory: every window here is a correct one. The check exists
/// because the window used to be a compiled 60 seconds for every store, which
/// was shorter than a converted repository's own cold start, so each command
/// paid a fresh open and nothing on any surface said why. A number an operator
/// cannot see is a number nobody can question.
fn check_daemon_idle_window() -> HealthCheck {
    let cwd = env::current_dir().unwrap_or_default();
    let Some(layout) = kin_core::KinLayout::discover(&cwd) else {
        return HealthCheck::new(
            "daemon_idle_window",
            "Daemon idle window",
            HealthStatus::Unsupported,
            "not in a Kin repository, so there is no per-store window to report",
        );
    };
    if let Ok(user_value) = env::var("KIN_DAEMON_IDLE_TIMEOUT_SECS") {
        return HealthCheck::new(
            "daemon_idle_window",
            "Daemon idle window",
            HealthStatus::Healthy,
            format!(
                "{}s, from KIN_DAEMON_IDLE_TIMEOUT_SECS in this environment, which overrides \
                 the measured rule",
                user_value.trim()
            ),
        );
    }
    let window = kin_daemon_spawn::cli_idle_window_for_store(layout.root());
    HealthCheck::new(
        "daemon_idle_window",
        "Daemon idle window",
        HealthStatus::Healthy,
        window.describe(),
    )
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
    let local_shim = crate::commands::setup::find_shim();
    let check = vfs_projection_check_for(lib_path, driver, local_shim.as_deref());
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

/// The repair to offer for a missing or corrupt shim, preferring a copy that is
/// already on this host.
///
/// Both arms of the v0.5.40 stranger run were told to `curl` the network
/// installer over the release candidate they had just extracted, while the shim
/// being asked for sat beside the binary printing the message: the archive is
/// four files and one of them is the shim. Following that hint replaces the
/// build under test, which for a release verification, an airgapped install, or
/// anyone pinned to a version destroys the thing they were working on.
///
/// The network installer stays, as the fallback it always should have been, for
/// the standalone binary that genuinely has no local copy. Each arm says which
/// it is, because "reinstall" and "copy the file next door" are different
/// enough that a reader must not have to guess which one they were handed.
fn shim_repair_hint(lib_path: &Path, local_source: Option<&Path>) -> String {
    match local_source {
        Some(source) => format!(
            "copy the shim from this install: cp {} {}",
            source.display(),
            lib_path.display()
        ),
        None => format!("no local shim was found beside this binary, in ~/.kin/lib, or on PATH, so {SHIM_REINSTALL_HINT}"),
    }
}

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
fn vfs_projection_check_for(
    lib_path: &Path,
    driver: &VfsDriverState,
    local_source: Option<&Path>,
) -> HealthCheck {
    let repair = shim_repair_hint(lib_path, local_source);
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
        .with_manual_fix(repair.clone()),
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
        .with_manual_fix(repair.clone()),
        ShimState::Missing => HealthCheck::new(
            "vfs_projection",
            "VFS projection",
            HealthStatus::Missing,
            format!("shim not installed at {}{driver_note}", lib_path.display()),
        )
        .fixable()
        .with_manual_fix(repair.clone()),
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
    let layout = kin_core::KinLayout::discover(&cwd);
    let inside_repository = layout.is_some();
    let repo_root = layout
        .map(|layout| layout.root().to_path_buf())
        .unwrap_or(cwd);
    let report = crate::commands::projection::report_for(
        &kin_home,
        env::current_exe().ok().as_deref(),
        &repo_root,
        None,
    );
    let outside = probe_outside_repo(home_dir().ok().as_deref(), report.shim.engaged);
    let hook = probe_shell_hook(&kin_home, detect_shell(), &report.shim.path);
    projection_mode_check_for_context(&report, env::consts::OS, &outside, &hook, inside_repository)
}

/// Whether Kin's own shell hook is live in the shell that started this process.
///
/// This exists because the projection row was asking the one question the hook
/// guarantees a "no" to. The hook wraps the control plane as
/// `kin() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin "$@"; }`, which is
/// correct, since injecting the shim into the binary that serves it is
/// circular. The row then measured whether the shim was preloaded into `kin
/// doctor` and told a correctly installed user to start a new shell so the hook
/// would inject it. It never would (FIR-2501). The question worth asking is
/// about the OTHER processes in this shell, and it is answerable, because the
/// two variables the `kin` wrapper does not clear pass straight through.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ShellHook {
    /// Live: this shell runs Kin's hook, so the non-`kin` processes it starts
    /// are launched under the shim, and this process is unshimmed on purpose.
    Live(String),
    /// Not live, and this is why. The container with no hook, the editor
    /// terminal that never sourced one, and the shell where the kill switch is
    /// set all land here.
    Withheld(String),
}

impl ShellHook {
    fn is_live(&self) -> bool {
        matches!(self, Self::Live(_))
    }

    /// The hook's own words, whatever the verdict, so a row can name the
    /// evidence it rests on rather than asserting a result.
    fn evidence(&self) -> &str {
        match self {
            Self::Live(text) | Self::Withheld(text) => text,
        }
    }
}

/// Probed facts about the shell hook, separated from the environment that
/// produced them so both directions of the verdict are testable without a real
/// `$HOME`, a real shell, or a real shim.
struct ShellHookFacts<'a> {
    shell: &'a str,
    hook_path: &'a Path,
    /// Whether the hook file is there at all.
    installed: bool,
    /// Whether its bytes are the ones this build writes. Existence alone is not
    /// currency: a hook from an older install is a file that exists and a
    /// behavior nobody here has read.
    current: bool,
    /// Whether the shell's startup file sources it.
    sourced: bool,
    /// The shim as classified on disk. The hook exports the preload only when
    /// the library is present and non-empty (`-f` and `-s` in its own words), so
    /// a missing or 0-byte shim means the hook injects nothing however well it
    /// is installed. [`classify_shim`] is strictly stronger, since it also
    /// rejects a blob the loader would refuse.
    shim: ShimState,
    /// `KIN_VFS_DISABLE` as this process sees it. The hook reads the same
    /// variable as its kill switch and the `kin` wrapper does not clear it, so a
    /// switched-on value is positive proof the hook injected nothing.
    disable: Option<String>,
    /// `KIN_VFS_WORKSPACE` as this process sees it.
    ///
    /// Positive proof, and only positive proof. All three POSIX hooks export
    /// this variable and the preload from the same branch and clear both from
    /// the other one, so a bound root in `kin`'s environment means the preload
    /// was exported for everything else this shell starts. Its ABSENCE proves
    /// nothing: outside a repository the hook deactivates by design, and a shell
    /// that has simply not entered one yet is not a broken install.
    bound_root: Option<String>,
}

/// Read the shell hook's state from this process's environment and `~/.kin`.
fn probe_shell_hook(kin_home: &Path, shell: &str, shim_path: &Path) -> ShellHook {
    let hook_path = hook_path_for(kin_home, shell);
    let installed = hook_path.is_file();
    let current = std::fs::read(&hook_path)
        .is_ok_and(|bytes| bytes == crate::commands::setup::hook_content(shell).as_bytes());
    let rc_content = shell_rc(shell)
        .ok()
        .and_then(|rc| std::fs::read_to_string(rc).ok())
        .unwrap_or_default();
    let non_empty = |name: &str| env::var(name).ok().filter(|value| !value.trim().is_empty());
    shell_hook_from(ShellHookFacts {
        shell,
        hook_path: &hook_path,
        installed,
        current,
        sourced: rc_sources_hook(&rc_content),
        shim: classify_shim(shim_path),
        disable: non_empty("KIN_VFS_DISABLE"),
        bound_root: non_empty("KIN_VFS_WORKSPACE"),
    })
}

/// Whether a `KIN_VFS_DISABLE` value switches the hook off.
///
/// The literal spellings all three hooks accept (`1`, `true`, `yes`, `on`,
/// case-insensitively), rather than the shim's narrower "the literal 1": the
/// question here is what the HOOK did, and a shell where the hook stood down is
/// a shell where nothing was injected whatever the shim would have made of the
/// same value.
fn vfs_disabled_by(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Decide whether the hook is live, from probed facts alone.
fn shell_hook_from(facts: ShellHookFacts<'_>) -> ShellHook {
    let ShellHookFacts {
        shell,
        hook_path,
        installed,
        current,
        sourced,
        shim,
        disable,
        bound_root,
    } = facts;
    let where_it_is = hook_path.display();

    if let Some(value) = disable.as_deref().filter(|value| vfs_disabled_by(value)) {
        return ShellHook::Withheld(format!(
            "KIN_VFS_DISABLE={value} is set in this shell, which is the hook's own kill switch, so \
             nothing here is injected with the shim"
        ));
    }
    if !installed {
        return ShellHook::Withheld(format!(
            "no {shell} hook is installed at {where_it_is}, so no process this shell starts is \
             injected with the shim"
        ));
    }
    // The shim's own state decides this before the hook's, because the hook
    // tests the library before exporting anything and clears the preload when
    // the test fails. A hook installed over a 0-byte or truncated shim injects
    // nothing, and saying otherwise would be the reassuring lie this row exists
    // to remove.
    let shim_size = match shim {
        ShimState::Valid(size) => size,
        ShimState::Missing => {
            return ShellHook::Withheld(format!(
                "the {shell} hook at {where_it_is} exports the preload only when the shim library \
                 is there, and it is not"
            ));
        }
        ShimState::Empty | ShimState::Invalid => {
            return ShellHook::Withheld(format!(
                "the {shell} hook at {where_it_is} exports the preload only when the shim library \
                 is a usable {}, and this one is not",
                shim_object_kind()
            ));
        }
    };

    // Two ways to answer, and the measured one wins. A bound root is the hook's
    // activate path having run in THIS shell: every POSIX hook exports
    // KIN_VFS_WORKSPACE and the preload together, and clears both together, so
    // the variable `kin`'s own wrapper forgets to strip is a witness to the
    // preload that wrapper just stripped. Where there is no witness, and
    // outside a repository the hook stands down by design, the evidence is the
    // file and the rc line. Currency is required there because nobody has read
    // this hook's behavior and an older one is a file whose contents are a
    // guess.
    match bound_root {
        Some(root) => ShellHook::Live(format!(
            "Kin's {shell} hook is live in this shell: it bound {root} as the projection root and \
             exports the {} shim ({shim_size} bytes) into every process this shell starts except \
             the kin control plane, which it strips on purpose",
            shim_object_kind()
        )),
        None if current && sourced => ShellHook::Live(format!(
            "Kin's {shell} hook is installed at {where_it_is}, is the one this build writes, and \
             is sourced by this shell's startup file, so it injects the shim into the processes \
             this shell starts and strips it from the kin control plane on purpose"
        )),
        None if !current => ShellHook::Withheld(format!(
            "the {shell} hook at {where_it_is} is not the one this build installs, and no \
             projection root is bound here to show what it did; run `kin setup` to refresh it"
        )),
        None => ShellHook::Withheld(format!(
            "the {shell} hook at {where_it_is} is installed but this shell's startup file does not \
             source it, and no projection root is bound here"
        )),
    }
}

/// Where this shell's projection hook lives.
///
/// Shared by the shell-integration row and the projection row, which must not
/// disagree about the same file.
fn hook_path_for(kin_home: &Path, shell: &str) -> PathBuf {
    kin_home.join("shell").join(hook_filename(shell))
}

/// Whether a shell startup file sources the projection hook.
fn rc_sources_hook(rc_content: &str) -> bool {
    rc_content.contains("kin-vfs")
}

/// What a real syscall through the shim says about a path outside the
/// repository.
///
/// The rest of this row measures the repository, which is the one place an
/// engaged shim is certain to serve, and that is why it can be green in a shell
/// where the user's version control does not run. Git reads
/// `$HOME/.config/git/config` on every single command, so a shim that answers
/// an error for paths under the home directory breaks `git status`, `git init`
/// and `git config` in any directory at all while this row reports the
/// projection healthy and doctor reports nothing needing attention. A health
/// check that is green in the configuration where git is broken sends the
/// user's suspicion somewhere else, which is worse than having no check.
///
/// So the answer is measured rather than assumed, and it is measured where the
/// assumption breaks: outside the repository, with a real `read_dir` and a real
/// `stat`, through whatever the loader has injected into this process.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OutsideRepoProbe {
    /// A syscall on a path under the home directory succeeded.
    Served(String),
    /// A syscall on a path under the home directory failed, and this is what it
    /// said. The projection cannot be called healthy on this evidence.
    Broken(String),
    /// No syscall was taken, and this is why. Neutral by construction: an
    /// unengaged shim, an unresolvable home, or a home with nothing in it says
    /// nothing about the projection either way, and must not be allowed to turn
    /// a healthy row red or a broken one green.
    NotTaken(String),
}

impl OutsideRepoProbe {
    /// The probe's own words, whatever the verdict, so any row can name the
    /// evidence it rests on rather than asserting a result.
    fn evidence(&self) -> &str {
        match self {
            Self::Served(text) | Self::Broken(text) | Self::NotTaken(text) => text,
        }
    }
}

/// Whether one entry's failed `lstat` is the projection answering.
///
/// A path that is simply not there is a race with whatever else is running on
/// the machine rather than a projection failure, so it is not held against the
/// shim. Every other error is the projection answering, and the EIO the
/// container in FIR-2554 returned for everything under the home directory is
/// one of them.
///
/// Pure over the kind because the racing case cannot be staged on a real
/// filesystem: without this, that branch would be one nobody had ever executed.
fn stat_failure_blames_the_projection(kind: std::io::ErrorKind) -> bool {
    kind != std::io::ErrorKind::NotFound
}

/// How many entries of the home directory the probe will try before giving up.
///
/// One is enough on any healthy machine, and the budget exists only so a run of
/// dangling symlinks at the front of the listing cannot end the probe early. It
/// is small because a home directory that answers for none of its first few
/// entries has told us what we needed either way.
const PROBE_ENTRY_BUDGET: usize = 8;

/// Take the probe. `home` is `None` when this process cannot resolve a home
/// directory at all, which is a reason not to probe rather than a defect.
///
/// Pure over its two inputs so both the serving and the failing case are
/// testable without a shim, a container, or a real `$HOME`.
fn probe_outside_repo(home: Option<&Path>, shim_engaged: bool) -> OutsideRepoProbe {
    if !shim_engaged {
        return OutsideRepoProbe::NotTaken(
            "the shim is not injected into this process, so there is nothing outside the \
             repository to read through it"
                .to_string(),
        );
    }
    let Some(home) = home else {
        return OutsideRepoProbe::NotTaken(
            "no home directory could be resolved, so no path outside the repository was read"
                .to_string(),
        );
    };
    let entries = match std::fs::read_dir(home) {
        Ok(entries) => entries,
        Err(error) => {
            return OutsideRepoProbe::Broken(format!(
                "reading {} through the shim failed: {error}",
                home.display()
            ));
        }
    };
    // Several entries rather than the first one, because which entry `read_dir`
    // hands back first is arbitrary and one of them can be a dangling symlink or
    // a file that vanished between the listing and the stat. Either would make
    // one entry answer for the whole home directory, and a false red here is the
    // exact trade FIR-2554 forbids: a row that is permanently pessimistic has
    // replaced one wrong answer with another.
    let mut absent = 0usize;
    let mut listed = 0usize;
    for entry in entries.take(PROBE_ENTRY_BUDGET) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                return OutsideRepoProbe::Broken(format!(
                    "listing {} through the shim failed: {error}",
                    home.display()
                ));
            }
        };
        listed += 1;
        let path = entry.path();
        // `symlink_metadata`, not `metadata`: the question is whether the shim
        // serves this path, and following a link would fold the link target's
        // absence into the answer.
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                return OutsideRepoProbe::Served(format!(
                    "read {} and stat of {} through the shim succeeded",
                    home.display(),
                    path.display()
                ));
            }
            Err(error) if !stat_failure_blames_the_projection(error.kind()) => absent += 1,
            Err(error) => {
                return OutsideRepoProbe::Broken(format!(
                    "stat of {} through the shim failed: {error}",
                    path.display()
                ));
            }
        }
    }
    // Nothing listed, or everything listed had gone by the time it was stat'd.
    // Neither is a passing probe. Reporting either as Served would make this
    // check unable to fail on exactly the machine it was written for.
    if listed == 0 {
        OutsideRepoProbe::NotTaken(format!(
            "{} is empty, so there was nothing under it to read through the shim",
            home.display()
        ))
    } else {
        OutsideRepoProbe::NotTaken(format!(
            "every one of the {absent} entries read from {} had gone by the time it was stat'd, \
             so nothing outside the repository was measured",
            home.display()
        ))
    }
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
    outside: &OutsideRepoProbe,
    hook: &ShellHook,
) -> HealthCheck {
    use crate::commands::projection::ProjectionMode;

    let live = &report.live;
    let row = live.row();
    let evidence = live.evidence.join("; ");
    let detail = format!("{row}; {evidence}");
    let any_available = report.modes.iter().any(|probe| probe.available);

    // Before anything else, because a failing syscall outside the repository
    // outranks every other reading this row can take. The repository probes can
    // all be green while the shim answers errors for the home directory, and
    // that combination is the one where `git status` exits 128 in any directory
    // and doctor says nothing needs attention.
    if let OutsideRepoProbe::Broken(evidence_outside) = outside {
        return HealthCheck::new(
            "projection_mode",
            "Projection in force",
            HealthStatus::Misconfigured,
            format!(
                "the projection is engaged but does not serve paths outside the repository, so \
                 tools that read configuration from the home directory are broken in this shell; \
                 git reads $HOME/.config/git/config on every command; {evidence_outside}; {detail}"
            ),
        )
        .with_manual_fix(
            "run `kin vfs off` to disengage the projection, or start a shell without the hook, \
             and check that `git status` works before trusting this row again",
        );
    }

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
        // A green row names the probe it rests on, so a reader can tell a
        // projection that was measured outside the repository from one that was
        // only measured inside it.
        let detail = format!("{detail}; {}", outside.evidence());
        let check = HealthCheck::new(
            "projection_mode",
            "Projection in force",
            HealthStatus::Healthy,
            detail,
        );
        // A working mode can still have a limit, and this is the row where a
        // silent green would hide it. The shim interposes libc, so a binary
        // that never calls libc reads the working copy while everything else
        // reads graph truth; that stays true of a shim mode passing every
        // probe. Carrying it as a platform note rather than a status keeps the
        // row green, because the limit is a property of the mode rather than a
        // defect in the install, and puts it in front of a reader who ran
        // `kin doctor` and would otherwise have to know to run `kin vfs status`
        // (FIR-2572).
        return match live.mode.raw_syscall_note() {
            Some(note) => check.with_platform_note(note),
            None => check,
        };
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

    // Nothing recorded and nothing in force is not a misconfiguration. It is
    // an ordinary host where nobody has engaged a projection yet, and the
    // recorded-mode branch above has already returned for every host where
    // somebody did, so reaching here with nothing recorded means the mode in
    // `detail` is one the chooser named rather than one a person picked.
    // Calling that `misconfigured` reports a defect against a choice nobody
    // made: every fresh native Windows install read exactly that in `kin
    // doctor`, one line under `kin setup` printing that projfs was available
    // and needed `kin vfs on` to engage, and the two surfaces contradicted
    // each other about the same probe. Reserving `misconfigured` for a
    // RECORDED mode that is not running is what keeps this row diagnostic on
    // the day it fires.
    //
    // The row still names what is engageable rather than reporting an absence,
    // because a host that can run a projection and is not running one has
    // something a reader can act on. The advisory shim case keeps its own
    // status ahead of this one: an installed shim that is simply not injected
    // into this process is the more specific answer, and it is the more useful
    // thing to tell that user.
    //
    // A projection that is installed and DEAD is not an unconfigured host,
    // even with nothing recorded. Somebody put it there and the loader will
    // not run it, which is the container case one branch up: every process on
    // the box reads raw disk while the install looks intact. That keys on the
    // evidence of breakage, the loader's refusal or an installed shim no probe
    // can use, rather than on a driver merely being present, because a driver
    // sitting on disk for a mount mode nobody engaged is the ordinary state
    // this branch is about.
    let installed_and_dead =
        report.driver.refusal.is_some() || (report.shim.installed && !shim_usable);

    // FIR-2501. The advisory arm above is right about a shell with no hook and
    // wrong about a shell with one, and until now it could not tell them apart
    // because it read the one signal Kin's own hook is built to blank. The hook
    // wraps the control plane so `kin` never runs under the shim, which is
    // correct and permanent, and this row then measured `kin doctor`'s own
    // preload, called a correct install STALE, and printed a fix that could not
    // work. Since FIR-2547 tightened the readiness line to require zero
    // attention rows, that denied "First-run ready" on every correctly
    // hook-installed machine.
    //
    // So the arm splits on the question the ticket asks: not whether THIS
    // process is injected, but whether the hook is live for the processes that
    // are not `kin`. Three conditions, and all three are load-bearing:
    //
    // - `advisory` keeps FIR-2394 intact. It requires a usable shim, so a
    //   refused driver or a library no probe can open never reaches here, and
    //   `!installed_and_dead` says the same thing a second time on purpose:
    //   an installed projection the loader will not run must never borrow a
    //   softer status, let alone a green one.
    // - `unengaged_here_only` is the projection's own verdict with the
    //   engagement question answered yes. Without it this branch would report
    //   the FIR-2552 machine, a root bound that nothing serves or one that does
    //   not contain this directory, as healthy, which is the state where
    //   every path under that root returns EIO for every process the shim IS
    //   injected into.
    // - `hook.is_live()` is the hook evidence itself.
    //
    // Only the ROW's status moves. `LiveProjection::degraded` stays exactly what
    // it was, because it answers for the process asking, and `kin vfs status`
    // reporting "in force" from a `kin` process that is reading raw disk would
    // be the same false green in a different surface. That is why the machine
    // row below still reads `degraded=yes` under a green status, and why the
    // detail explains the difference in words rather than hiding it.
    if advisory && !installed_and_dead && live.unengaged_here_only && hook.is_live() {
        return HealthCheck::new(
            "projection_mode",
            "Projection in force",
            HealthStatus::Healthy,
            format!(
                "{detail}; the shim is installed and IS injected into the processes this shell \
                 starts, and is correctly NOT injected into `kin` itself, which is why the row \
                 above reads degraded=yes: that field is about this process, and Kin's hook wraps \
                 the control plane so the binary serving the projection never runs under it; \
                 {}; {}",
                hook.evidence(),
                outside.evidence()
            ),
        );
    }

    if report.recorded.is_none() && !advisory && !installed_and_dead {
        let engageable = report
            .modes
            .iter()
            .find(|probe| probe.available)
            .map(|probe| probe.mode);
        let route = match engageable {
            Some(mode) => format!(
                "{mode} is available here, and `kin vfs on --mode {mode}` engages it and records \
                 it once it is running"
            ),
            // Not "nothing is missing". Where no mode can be engaged yet there
            // is still usually something the reader can do, and on Windows
            // there always is: ProjFS ships on every SKU and only needs
            // enabling. So the row names the first remedy a probe produced
            // rather than reporting a bare absence, and `kin vfs status`,
            // named in the fix below, carries the rest.
            None => report
                .modes
                .iter()
                .find_map(|probe| {
                    probe.remedy.clone().map(|remedy| {
                        format!("nothing is engageable yet: {} needs {remedy}", probe.mode)
                    })
                })
                .unwrap_or_else(|| {
                    "nothing is engageable here, and no probe named a remedy".to_string()
                }),
        };
        return HealthCheck::new(
            "projection_mode",
            "Projection in force",
            HealthStatus::Unsupported,
            format!(
                "no projection is configured and none is in force; the CLI and daemon answer \
                 from the graph without one; {route}; {evidence}"
            ),
        )
        .with_manual_fix(
            "run `kin vfs on` to engage a projection and record it, or `kin vfs status` for what \
             each mode would need here",
        );
    }

    let status = if advisory {
        HealthStatus::Stale
    } else {
        HealthStatus::Misconfigured
    };
    // The advisory arm is the one whose subject is the shell, so it carries the
    // hook's own words. A reader who lands here is being told something is not
    // injected, and what the hook did is the first thing they need in order to
    // know whether that is their shell or their projection.
    let detail = if advisory {
        format!("{detail}; {}", hook.evidence())
    } else {
        detail
    };
    HealthCheck::new("projection_mode", "Projection in force", status, detail).with_manual_fix(
        if advisory && hook.is_live() {
            // The hook is already doing its job, so the old line would send a
            // reader to open shell after shell against a row that can never
            // move: what is missing here is the projection, not the shell. It
            // names `kin vfs status` and not `kin doctor --fix`, which has no
            // repair for this row and would only loop (FIR-2435).
            "Kin's shell hook is already live here and runs `kin` without the shim on purpose, so \
             a new shell will not change this row: run `kin vfs status` for the root this shell \
             bound, whether it contains this directory, and whether anything is serving it"
        } else if advisory {
            // Not `exec $SHELL -l`. A stock Debian `~/.bashrc` guards itself on
            // interactivity (`case $- in *i*) ;; *) return;; esac`), not on
            // login, so a login shell does not engage the hook there and the
            // old advice named the wrong lever for that shell. And the shell
            // this line asks the user to create is one no probe has been taken
            // in, so it asks for the probe rather than promising the result.
            "start a new interactive shell so the hook injects the shim, then run `kin doctor` \
             again there: a login shell does not engage the hook where the shell's startup file \
             only runs when interactive, and this row cannot speak for a shell it has not run in"
        } else {
            "run `kin vfs on` to engage a projection, or `kin vfs status` to see why none is \
             available here"
        },
    )
}

/// Qualify the projection row by whether this doctor run has a repository to
/// project. Kept as a separate seam so first-contact context can be tested
/// without asking a fixture to discover the process working directory.
fn projection_mode_check_for_context(
    report: &crate::commands::projection::ProjectionReport,
    os: &str,
    outside: &OutsideRepoProbe,
    hook: &ShellHook,
    inside_repository: bool,
) -> HealthCheck {
    let check = projection_mode_check_for(report, os, outside, hook);
    if !inside_repository && hook.is_live() && matches!(check.status, HealthStatus::Stale) {
        return HealthCheck::new(
            "projection_mode",
            "Projection in force",
            HealthStatus::Unsupported,
            format!(
                "this command is not inside a Kin repository, so there is no repository root for \
                 the live shell hook to project; the hook itself is live; underlying probe: {}",
                check.detail
            ),
        )
        .with_platform_note(
            "Run `kin doctor` from inside the Kin repository whose projection you want to check.",
        );
    }
    check
}

/// Report staging an interrupted `kin init` left on disk, and where it stopped.
///
/// A conversion the kernel kills for memory runs no destructor: the shell gets
/// exit 137, `.kin` never appears, and hundreds of megabytes of staging sit
/// beside the repository with nothing pointing at them. The rc0550 stranger met
/// that and deleted it by hand after guessing what it was. This row is the
/// answer to the question that operator had no way to ask.
///
/// Reports, never reaps. An operator asking what is on their disk has not asked
/// Kin to delete anything, and the reclaim already happens on the next `kin
/// init` in that repository, which the fix line names.
fn check_interrupted_init() -> HealthCheck {
    let cwd = env::current_dir().unwrap_or_default();
    interrupted_init_check_for(&interrupted_init_scan_roots(&cwd))
}

/// Where a doctor run looks for interrupted-conversion staging.
///
/// The choice of directories, and the filesystem access it takes to resolve
/// them, belong to the init boundary in kin-core rather than to a CLI health
/// row: doctor asks that boundary where to look and reports what it answers.
fn interrupted_init_scan_roots(cwd: &Path) -> Vec<PathBuf> {
    kin_core::init_attempt::staging_scan_roots(cwd)
}

fn interrupted_init_check_for(roots: &[PathBuf]) -> HealthCheck {
    let mut attempts = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for root in roots {
        for attempt in kin_core::init_attempt::abandoned_init_attempts(root).unwrap_or_default() {
            if seen.insert(attempt.capture_path.clone()) {
                attempts.push(attempt);
            }
        }
    }
    match kin_core::init_attempt::doctor_row(&attempts) {
        Some((detail, fix)) => HealthCheck::new(
            "interrupted_init",
            "Interrupted conversion",
            HealthStatus::Degraded,
            detail,
        )
        .with_manual_fix(fix),
        None => HealthCheck::new(
            "interrupted_init",
            "Interrupted conversion",
            HealthStatus::Healthy,
            "no `kin init` staging is waiting to be reclaimed here",
        ),
    }
}

/// Reports, never reaps, exactly like the interrupted-conversion row above it.
///
/// Separate from that row rather than folded into it, because the two find
/// different things. `abandoned_init_attempts` scans `.kin-git-capture-*`
/// directories and learns about a repository stage only by reading a surviving
/// capture record, which the native `kin init` path never writes at all. This
/// row scans the `.kin.init-<uuid>.owner` records themselves, which is the same
/// evidence `recover_orphaned_repository_stages` reaps by, so a stage whose
/// capture directory is already gone is still named here. FIR-3146.
fn check_stranded_init_stage() -> HealthCheck {
    let cwd = env::current_dir().unwrap_or_default();
    stranded_init_stage_check_for(&interrupted_init_scan_roots(&cwd))
}

fn stranded_init_stage_check_for(roots: &[PathBuf]) -> HealthCheck {
    let survey = survey_stranded_stages(roots);
    match kin_core::init::stranded_stage_doctor_row(&survey) {
        Some((detail, fix)) => HealthCheck::new(
            "stranded_init_stage",
            "Stranded init staging",
            HealthStatus::Degraded,
            detail,
        )
        .with_manual_fix(fix),
        None => HealthCheck::new(
            "stranded_init_stage",
            "Stranded init staging",
            HealthStatus::Healthy,
            "no crashed `kin init` left a staged store beside this directory",
        ),
    }
}

/// Survey every scan root once, keeping each stage the first time it is seen.
///
/// Deduplicated on the owner record's path, which is unique per stage. The
/// roots are a directory and its parent, so they hold disjoint entries today
/// and the dedupe is insurance against a caller that passes overlapping roots
/// rather than against the pair `staging_scan_roots` returns.
///
/// A root that could not be read is recorded, not dropped. Reporting a parent
/// as clean because `read_dir` refused it would be the false negative this row
/// exists to end, and it is the parent, one level up from where an operator
/// stands, that these stages strand in.
pub(crate) fn survey_stranded_stages(roots: &[PathBuf]) -> kin_core::StrandedStageSurvey {
    let mut survey = kin_core::StrandedStageSurvey::default();
    let mut seen = std::collections::BTreeSet::new();
    for root in roots {
        let found = match kin_core::survey_orphaned_repository_stages(root) {
            Ok(found) => found,
            Err(error) => {
                survey
                    .unreadable
                    .push(format!("{}: {error}", root.display()));
                continue;
            }
        };
        survey.live += found.live;
        for stage in found.stages {
            if seen.insert(stage.owner_path.clone()) {
                survey.stages.push(stage);
            }
        }
    }
    survey
}

/// Where a reclaim looks, which is exactly where the row that reported it
/// looked.
///
/// Shared rather than re-derived: a reclaim that scanned a different set of
/// directories than the row an operator just read would take back something
/// they were never shown, or nothing at all.
pub fn stranded_stage_scan_roots() -> Vec<PathBuf> {
    let cwd = env::current_dir().unwrap_or_default();
    interrupted_init_scan_roots(&cwd)
}

/// Take back every stranded stage the `stranded_init_stage` row just named.
///
/// The row is the dry run. `kin doctor` names every stage this would remove
/// with its size and leaves the disk untouched, so an operator sees the list
/// before anything is deleted and there is no second `--dry-run` flag to teach
/// them. `kin cache gc` needs one because its default is destructive; this
/// command's default surface is a diagnostic.
///
/// Removes only what `kin_core::reclaim_orphaned_repository_stages` proves
/// abandoned, which is the same proof the reaper inside `kin init` uses: a free
/// owner lock, a private owner record and stage directory owned by this user,
/// the exact recorded stage path, and a matching device and inode. A stage a
/// live `kin init` holds is never touched.
///
/// That owner lock is host-local, so the proof holds on local storage and not
/// on a shared mount, where a stage another machine is still writing can read
/// as abandoned. FIR-3155 carries the fix, a host identifier on the owner
/// record.
///
/// Refuses rather than returning zero when no root could be examined at all. A
/// caller reading only the exit status would otherwise take "I could not look"
/// for "there was nothing there".
pub fn reclaim_stranded_stages(json: bool) -> anyhow::Result<()> {
    reclaim_stranded_stages_in(&stranded_stage_scan_roots(), json)
}

/// [`reclaim_stranded_stages`] against explicit roots.
///
/// Split out so the refusal below is reachable from a test. Resolving the roots
/// from `env::current_dir` is process-global state, and a test that changed the
/// working directory to drive this would reach every other test running beside
/// it in the same binary.
pub(crate) fn reclaim_stranded_stages_in(roots: &[PathBuf], json: bool) -> anyhow::Result<()> {
    let mut recovered = 0usize;
    let mut bytes = 0u64;
    let mut retained = 0usize;
    let mut live = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for root in roots {
        match kin_core::reclaim_orphaned_repository_stages(root) {
            Ok(outcome) => {
                recovered += outcome.recovered;
                bytes = bytes.saturating_add(outcome.bytes_recovered);
                retained += outcome.retained;
                live += outcome.live;
            }
            // Named, not swallowed. A root that could not be scanned is the one
            // thing an operator must not read as "nothing was stranded there".
            Err(error) => failures.push(format!("{}: {error}", root.display())),
        }
    }
    // Fail loud. `recovered == 0` beside a failure for every root is not a clean
    // parent, and the summary sentence below says "nothing to reclaim here",
    // which is the one thing this must not tell a script that reads only the
    // exit status.
    if failures.len() == roots.len() && !roots.is_empty() {
        anyhow::bail!(
            "kin doctor --reclaim-staging: no directory could be examined, so this run says \
             nothing about what is stranded here: {}",
            failures.join("; ")
        );
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": STRANDED_STAGE_RECLAIM_SCHEMA,
                "roots": roots.iter().map(|root| root.display().to_string()).collect::<Vec<_>>(),
                "recovered": recovered,
                "bytes_recovered": bytes,
                "retained": retained,
                "live": live,
                "unreadable_roots": failures,
            }))?
        );
    } else if recovered == 0 {
        println!("kin doctor --reclaim-staging: nothing to reclaim here.");
    } else {
        let noun = if recovered == 1 { "stage" } else { "stages" };
        println!(
            "kin doctor --reclaim-staging: reclaimed {} from {recovered} stranded init {noun}.",
            kin_core::init_attempt::human_bytes(bytes)
        );
    }
    if !json {
        if retained > 0 {
            let (noun, pronoun) = if retained == 1 {
                ("store", "it")
            } else {
                ("stores", "them")
            };
            println!(
                "  {retained} further staged {noun} left alone, because this run could not prove \
                 {pronoun} unused."
            );
        }
        if live > 0 {
            let (noun, verb) = if live == 1 {
                ("store", "is")
            } else {
                ("stores", "are")
            };
            println!("  {live} staged {noun} {verb} owned by a `kin init` running right now.");
        }
        for failure in &failures {
            println!("  could not be examined, {failure}");
        }
    }
    Ok(())
}

/// Schema of the `--reclaim-staging --json` payload.
pub const STRANDED_STAGE_RECLAIM_SCHEMA: &str = "kin.stranded-stage-reclaim.v1";

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

    let hook_path = hook_path_for(&kin_home, shell);
    let hook_installed = hook_path.exists();

    let rc_path = shell_rc(shell).ok();
    let rc_content = rc_path
        .as_ref()
        .and_then(|rc| std::fs::read_to_string(rc).ok())
        .unwrap_or_default();
    let rc_sources = rc_sources_hook(&rc_content);

    // The PATH line does not always live beside the hook. zsh's belongs in
    // `.zshenv`, which is the file a non-interactive shell reads, and bash's
    // lives in the login file as well as `.bashrc`, so reading only the hook's
    // file would report a correctly installed host as missing its PATH. Every
    // file the PATH line is written to is read and any of them satisfies the
    // check, which also keeps an install that predates either split reading
    // healthy.
    let path_rc_content = shell_path_rcs(shell)
        .unwrap_or_default()
        .into_iter()
        .filter(|path| Some(path) != rc_path.as_ref())
        .filter_map(|rc| std::fs::read_to_string(rc).ok())
        .collect::<Vec<_>>()
        .join("\n");

    let bin_display = bin_dir.to_string_lossy();
    let declares_bin = |content: &str| {
        content.contains(bin_display.as_ref())
            || content.contains(".kin/bin")
            || content.contains("kin/bin")
    };
    let rc_sets_path = declares_bin(&rc_content) || declares_bin(&path_rc_content);

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
                // `kin setup` writes `agent-default`, and an operator who
                // narrowed the entry to the query half of that same belt
                // made a supported choice rather than a mistake. Reporting it
                // as misconfigured would tell someone who deliberately dropped
                // the transaction contracts from every prompt to put them back.
                Some("agent-query") => (
                    HealthStatus::Healthy,
                    format!(
                        "{servers_key}.kin present with the query-only agent-query profile ({})",
                        path.display()
                    ),
                ),
                // Same reasoning one step further: an operator who narrowed the
                // entry to the measured always-on set chose a supported surface,
                // and every other tool is still reachable from it through
                // `kin_tool_search`.
                Some("agent-search") => (
                    HealthStatus::Healthy,
                    format!(
                        "{servers_key}.kin present with the always-on agent-search profile ({})",
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
                        "{servers_key}.kin present but KIN_MCP_TOOL_PROFILE is {other} (expected agent-default, agent-query, agent-search, or unset to take agent-default as the default) in {}",
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

pub(crate) fn editor_extension_detected() -> bool {
    home_dir()
        .ok()
        .map(|home| editor_extension_detected_in(&home.join(".vscode").join("extensions")))
        .unwrap_or(false)
}

/// Whether the default VS Code extension directory carries a current official
/// Kin extension.
///
/// A directory name is only a candidate. VS Code can leave partial, obsolete,
/// or unrelated directories under `extensions`, so only a parsed manifest with
/// the official publisher and package name is allowed to suppress setup's
/// install guidance.
fn editor_extension_detected_in(extensions_dir: &Path) -> bool {
    let obsolete_path = extensions_dir.join(".obsolete");
    let obsolete = match std::fs::read(&obsolete_path) {
        Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(value) if value.is_object() => value,
            _ => Value::Object(serde_json::Map::new()),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Value::Object(serde_json::Map::new())
        }
        Err(_) => Value::Object(serde_json::Map::new()),
    };

    let Ok(entries) = std::fs::read_dir(extensions_dir) else {
        return false;
    };

    entries.filter_map(Result::ok).any(|entry| {
        let folder = entry.file_name().to_string_lossy().into_owned();
        let normalized = folder.to_ascii_lowercase();
        let official_candidate =
            normalized == "firelock.kin-editor" || normalized.starts_with("firelock.kin-editor-");
        if !official_candidate
            || obsolete.as_object().is_some_and(|entries| {
                entries.iter().any(|(name, removed)| {
                    name.eq_ignore_ascii_case(&folder) && removed.as_bool() == Some(true)
                })
            })
        {
            return false;
        }

        let Ok(metadata) = std::fs::metadata(entry.path()) else {
            return false;
        };
        if !metadata.is_dir() {
            return false;
        }

        let Ok(bytes) = std::fs::read(entry.path().join("package.json")) else {
            return false;
        };
        let Ok(manifest) = serde_json::from_slice::<Value>(&bytes) else {
            return false;
        };
        manifest
            .get("publisher")
            .and_then(Value::as_str)
            .is_some_and(|publisher| publisher.eq_ignore_ascii_case("firelock"))
            && manifest
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.eq_ignore_ascii_case("kin-editor"))
    })
}

fn check_editor() -> HealthCheck {
    if editor_extension_detected() {
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
            kinlab_connect_detail(
                &base_url,
                crate::commands::auth::stored_credential_provider(&base_url).as_deref(),
            ),
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

/// What the KinLab row says about a credential this machine holds.
///
/// The provider is named only when the credential records one, and worded as
/// what the login asked for rather than as what the browser did, because the
/// exchange response carries no provider and that is the whole distance
/// between the two claims. A credential written before `--provider` existed,
/// or one held in the keyring or behind a passphrase, names none, and this
/// says nothing rather than defaulting the reader to Google.
fn kinlab_connect_detail(base_url: &str, provider: Option<&str>) -> String {
    match provider {
        Some(provider) => format!(
            "stored credential present for {base_url} (login asked for the {provider} provider)"
        ),
        None => format!("stored credential present for {base_url}"),
    }
}

/// The semantic-readiness row and the exact embedding observation it read.
///
/// The count stays optional because a build without vectors, a missing daemon,
/// or a failed resources request observed no backlog at all. That state must
/// preserve a durable refusal rather than laundering "unknown" into zero.
struct SemanticQueryReadinessSample {
    check: HealthCheck,
    embedding_coverage: Option<kin_core::memory_pressure::EmbeddingCoverage>,
}

impl From<HealthCheck> for SemanticQueryReadinessSample {
    fn from(check: HealthCheck) -> Self {
        Self {
            check,
            embedding_coverage: None,
        }
    }
}

#[cfg(not(feature = "vector"))]
async fn check_semantic_query_readiness() -> SemanticQueryReadinessSample {
    HealthCheck::new(
        "semantic_query_readiness",
        "Semantic query readiness",
        HealthStatus::Unsupported,
        "semantic vector ranking is not included in this build; lexical and graph queries remain available",
    )
    .with_platform_note("this platform ships the supported vector-free Kin runtime")
    .into()
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
        "stop the daemon (`kin daemon stop`) so the next kin command starts one that retries \
         the stopped pass, and report the reason above if it stops again",
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
async fn check_reference_edge_coverage(graph_status: &RunGraphStatus) -> HealthCheck {
    // Probed first, because it needs no daemon. Every branch below that cannot
    // read the graph still reports this half, so a repository whose daemon is
    // down does not silently lose the language-server signal that used to have
    // its own row.
    let cwd = env::current_dir().unwrap_or_default();
    // Probed, not looked up on PATH. A binary that resolves and cannot start
    // serves no language, and a row that reports it as served sends an operator
    // looking for a problem somewhere else entirely.
    let readiness = crate::commands::language_servers::probe_language_server_readiness(&cwd).await;
    let missing_servers = missing_language_servers(&readiness);
    // The run's one fetch. Every unreadable state is phrased by this row in its
    // own words rather than reported once by the fetch, because a row that reads
    // graph truth must never render the same whether the graph was healthy or
    // unreadable.
    let response = match coverage_row_for_unread_graph(graph_status.get().await, &missing_servers) {
        Ok(response) => response,
        Err(row) => return row,
    };
    let Some(coverage) = response.reference_edge_coverage.as_ref() else {
        return coverage_unreadable(
            HealthStatus::Stale,
            "the daemon serving this repository does not report relation-graph completeness; it \
             predates the measurement",
            "stop the daemon (`kin daemon stop`) so the next kin command starts one on this build",
            &missing_servers,
        );
    };
    reference_edge_coverage_health(coverage)
}

/// This row's words for a graph status the run could not read, or the response
/// when it could.
///
/// Split from the fetch and from the verdict so every cause has a rendering that
/// is testable without a daemon, and so the property FIR-2560 must not lose stays
/// checkable: a shared fetch carries its failure to each consumer rather than
/// reporting it once, and no unreadable state renders as a healthy graph.
fn coverage_row_for_unread_graph<'a>(
    status: &'a GraphStatusForRun,
    missing_servers: &[String],
) -> Result<&'a crate::commands::graph::GraphCommandResponse, HealthCheck> {
    const ID: &str = "reference_edge_coverage";
    const LABEL: &str = "Reference edge coverage";

    match status {
        GraphStatusForRun::Answered(response) => Ok(response),
        GraphStatusForRun::NotInRepository => Err(HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Unsupported,
            "n/a — not in a Kin repository",
        )),
        GraphStatusForRun::NoDaemon => Err(coverage_unreadable(
            HealthStatus::Unsupported,
            "no daemon running for this repository, so relation-graph completeness cannot be \
             read; a daemon starts on first use",
            "run any `kin` command in the repo to auto-start the daemon",
            missing_servers,
        )),
        GraphStatusForRun::DaemonUrlInvalid { daemon_url, error } => Err(coverage_unreadable(
            HealthStatus::Stale,
            format!("daemon reachable ({daemon_url}), but its URL is invalid: {error}"),
            "check the daemon URL recorded for this repository",
            missing_servers,
        )),
        GraphStatusForRun::Unavailable { daemon_url, error } => Err(coverage_unreadable(
            HealthStatus::Stale,
            format!(
                "daemon reachable ({daemon_url}), but relation-graph completeness is unavailable: \
                 {error}"
            ),
            "run `kin graph status` and resolve the reported daemon error",
            missing_servers,
        )),
    }
}

/// What a doctor run's single `graph status` fetch produced.
///
/// The failure arms carry the cause rather than a rendered row. A shared fetch
/// that reported its own failure once would leave every other row silent about a
/// graph it could not read, and a row that goes quiet when the graph is
/// unreadable is indistinguishable from one reporting a healthy graph. So each
/// consumer phrases the same cause in the words its own row needs.
#[derive(Debug)]
pub(crate) enum GraphStatusForRun {
    /// The daemon answered.
    Answered(Box<crate::commands::graph::GraphCommandResponse>),
    /// This process is not standing in a Kin repository, so nothing was fetched.
    NotInRepository,
    /// No daemon is running for this repository, so nothing was fetched.
    NoDaemon,
    /// A daemon is running and the URL recorded for it will not parse.
    DaemonUrlInvalid { daemon_url: String, error: String },
    /// The daemon was asked and did not answer.
    Unavailable { daemon_url: String, error: String },
}

/// A future producing the run's graph status, boxed so the fetch can be
/// substituted in tests.
type GraphStatusFuture = Pin<Box<dyn Future<Output = GraphStatusForRun> + Send>>;

/// The `graph status` a doctor run reads, fetched at most once however many rows
/// consult it.
///
/// FIR-2416 measured `kin graph status` at 31.812 s on the rc0545c psf/requests
/// store against 0.091 s on express. A second fetch therefore does not cost a
/// little more, it roughly doubles the wall time of a doctor run, and the shape
/// did not stop at two: every future row answering from graph truth added
/// another whole fetch. Holding the answer here makes a new consumer free.
///
/// Lazy rather than eager so a run whose rows all short-circuit before reading
/// graph truth still pays nothing, and so the fetch keeps its position in the
/// run relative to the probes a row takes first.
pub(crate) struct RunGraphStatus {
    fetch: Box<dyn Fn() -> GraphStatusFuture + Send + Sync>,
    once: tokio::sync::OnceCell<GraphStatusForRun>,
}

impl RunGraphStatus {
    /// The real fetch, against the daemon serving the current directory.
    pub(crate) fn for_run() -> Self {
        Self::with_fetch(|| Box::pin(fetch_graph_status()))
    }

    fn with_fetch(fetch: impl Fn() -> GraphStatusFuture + Send + Sync + 'static) -> Self {
        Self {
            fetch: Box::new(fetch),
            once: tokio::sync::OnceCell::new(),
        }
    }

    /// The run's graph status, fetching it on the first call and returning that
    /// same answer to every later one.
    pub(crate) async fn get(&self) -> &GraphStatusForRun {
        self.once.get_or_init(|| (self.fetch)()).await
    }
}

/// Take the run's one `graph status` round trip.
///
/// Every way this can fail to produce a response is a named variant rather than
/// a message, so a consumer renders the cause in its own row's terms and no
/// caller has to parse prose to tell "no daemon" from "the daemon refused".
async fn fetch_graph_status() -> GraphStatusForRun {
    let cwd = env::current_dir().unwrap_or_default();
    let Some(layout) = kin_core::KinLayout::discover(&cwd) else {
        return GraphStatusForRun::NotInRepository;
    };
    let Some(daemon_url) = crate::daemon_client::resolve_daemon_url_if_running_async(&layout).await
    else {
        return GraphStatusForRun::NoDaemon;
    };
    let client = match crate::daemon_client::DaemonClient::from_base_url_for_layout(
        daemon_url.clone(),
        &layout,
    ) {
        Ok(client) => client,
        Err(error) => {
            return GraphStatusForRun::DaemonUrlInvalid {
                daemon_url,
                error: error.to_string(),
            };
        }
    };
    match client
        .graph_command(&crate::commands::graph::GraphCommandRequest::Status)
        .await
    {
        Ok(response) => GraphStatusForRun::Answered(Box::new(response)),
        Err(error) => GraphStatusForRun::Unavailable {
            daemon_url,
            error: error.to_string(),
        },
    }
}

/// Report whether this store has lost relation coverage it once held.
///
/// The relation-kind histogram `kin graph status` prints is a census, and until
/// this row existed nothing compared it to anything. On the rc0545c stranger
/// run a store went from 1985 entity-to-entity relations to 1807 and lost the
/// `UsesType` kind entirely, from 94 edges to none, and the health line
/// underneath the numbers that proved it read `✓ No issues detected.` Every
/// counter needed to notice was on the screen. Nothing on the screen noticed.
///
/// The comparison is read structurally off the graph command rather than parsed
/// out of its rendered lines, exactly as the reference-edge coverage above it
/// is, so a wording change on one surface cannot silently break the other.
async fn check_relation_census(graph_status: &RunGraphStatus) -> HealthCheck {
    let response = match relation_census_row_for_unread_graph(graph_status.get().await) {
        Ok(response) => response,
        Err(row) => return row,
    };
    let Some(comparison) = response.relation_census.as_ref() else {
        return HealthCheck::new(
            "relation_census",
            "Relation census",
            HealthStatus::Stale,
            "the daemon serving this repository does not report a relation census; it predates \
             the measurement",
        )
        .with_manual_fix(
            "stop the daemon (`kin daemon stop`) so the next kin command starts one on this build",
        );
    };
    relation_census_health(comparison)
}

/// This row's words for a graph status the run could not read, or the response
/// when it could.
fn relation_census_row_for_unread_graph(
    status: &GraphStatusForRun,
) -> Result<&crate::commands::graph::GraphCommandResponse, HealthCheck> {
    const ID: &str = "relation_census";
    const LABEL: &str = "Relation census";

    match status {
        GraphStatusForRun::Answered(response) => Ok(response),
        GraphStatusForRun::NotInRepository => Err(HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Unsupported,
            "n/a — not in a Kin repository",
        )),
        GraphStatusForRun::NoDaemon => Err(HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Unsupported,
            "n/a — no daemon running for this repository, so the relation census cannot be \
             read; a daemon starts on first use",
        )
        .with_manual_fix("run any `kin` command in the repo to auto-start the daemon")),
        GraphStatusForRun::DaemonUrlInvalid { daemon_url, error } => Err(HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Stale,
            format!("daemon reachable ({daemon_url}), but its URL is invalid: {error}"),
        )
        .with_manual_fix("check the daemon URL recorded for this repository")),
        GraphStatusForRun::Unavailable { daemon_url, error } => Err(HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Stale,
            format!(
                "daemon reachable ({daemon_url}), but the relation census is unavailable: \
                 {error}"
            ),
        )
        .with_manual_fix("run `kin graph status` and resolve the reported daemon error")),
    }
}

/// Turn the comparison into a verdict, split from its fetch so the rule is
/// testable without a daemon.
///
/// A lost kind reads `Stale` rather than `Missing`: the store held those edges
/// and no longer does, which is drift rather than a broken install, and a row
/// that blocked readiness on it would refuse every repository whose enrichment
/// is legitimately narrower than its last pass. It still counts as attention,
/// so the doctor summary can no longer report a whole-kind loss as a pass.
pub(crate) fn relation_census_health(
    comparison: &kin_core::relation_census::RelationCensusComparison,
) -> HealthCheck {
    const ID: &str = "relation_census";
    const LABEL: &str = "Relation census";

    if let Some(unavailable) = &comparison.unavailable {
        // Pending, not healthy. A store with no baseline is not a store that
        // kept its coverage; it is one nothing can answer the question about
        // yet, and those must not render the same.
        return HealthCheck::new(ID, LABEL, HealthStatus::Pending, unavailable.clone())
            .with_manual_fix(
                "run `kin commit`, or let the enrichment sweep finish, to record the first census",
            );
    }
    let losses = comparison.loss_lines();
    if losses.is_empty() {
        return HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Healthy,
            format!(
                "no relation kind has lost ground since the last recorded census ({} kind(s) \
                 compared)",
                comparison.changes.len()
            ),
        );
    }
    HealthCheck::new(ID, LABEL, HealthStatus::Stale, losses.join("; ")).with_manual_fix(
        "compare `kin graph status` against the named cause, then re-run enrichment with it \
         cleared",
    )
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
    .with_manual_fix(language_server_fix())
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
    let check = HealthCheck::new(
        ID,
        LABEL,
        HealthStatus::Pending,
        format!("{}; {}", gaps.join("; "), summary),
    );
    // A missing server is the one gap on this row an operator can actually
    // close, so it is the only case that carries a fix, and the fix names the
    // command for the languages THIS repository holds rather than for every
    // language the build wires. `unsupportable_absence_reasons` covers gaps a
    // host cannot install its way out of; offering an install for those would
    // be a fix that changes nothing.
    if missing_servers.is_empty() {
        check
    } else {
        check.with_manual_fix(crate::commands::language_servers::install_fix_line(
            &missing_servers,
        ))
    }
    .with_manual_fix(
        "install the servers, then stop this daemon (`kin daemon stop`) because a daemon \
         discovers language servers once at startup and the next command starts one that finds \
         them, then ask it to enrich (`kin daemon sweep`), and treat any \"unused\" answer as \
         unverified until cross-file edges resolve",
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
    // Checked before the discard arm's `else`, because a salvage is the case
    // neither arm below can describe. It attaches an index, so no discard is
    // recorded and the first arm falls through; and it leaves a real shortfall
    // against a fill that finished, so the "backlog is filling" arm would call
    // a coverage loss healthy. Stale is the honest verdict: the surface is
    // serving off less than it was.
    if let Some(salvage) = runtime.vector_index_salvage {
        return HealthCheck::new(
            "semantic_query_readiness",
            "Semantic query readiness",
            HealthStatus::Stale,
            format!(
                "{detail}; the persisted vector index no longer matched this repository's graph \
                 authority when the daemon opened, so it was salvaged per key: {} vectors were \
                 kept and {} were retired. The daemon re-embeds the retired keys in the \
                 background",
                salvage.kept, salvage.dropped
            ),
        )
        .with_manual_fix(
            "allow daemon embedding to finish, or run `kin embed` to force it now; only the \
             retired keys are re-derived",
        );
    }

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
async fn check_semantic_query_readiness() -> SemanticQueryReadinessSample {
    let cwd = env::current_dir().unwrap_or_default();
    let layout = match kin_core::KinLayout::discover(&cwd) {
        Some(l) => l,
        None => {
            return HealthCheck::new(
                "semantic_query_readiness",
                "Semantic query readiness",
                HealthStatus::Unsupported,
                "n/a — not in a Kin repository",
            )
            .into();
        }
    };

    let daemon_url = crate::daemon_client::resolve_daemon_url_if_running_async(&layout).await;
    let Some(daemon_url) = daemon_url else {
        return semantic_query_readiness_without_a_daemon().into();
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
            .with_manual_fix("run `kin status --json` and resolve the reported daemon error")
            .into();
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
            .with_manual_fix("run `kin status --json` and resolve the reported daemon error")
            .into();
        }
    };

    semantic_query_readiness_sample_from_runtime(&daemon_url, &response.embed_runtime)
}

/// Build the response row and retain the exact counter that response used.
/// Kept pure so the cross-row plumbing can be graded without a live daemon.
#[cfg(feature = "vector")]
fn semantic_query_readiness_sample_from_runtime(
    daemon_url: &str,
    runtime: &crate::commands::resources::EmbedRuntimeState,
) -> SemanticQueryReadinessSample {
    SemanticQueryReadinessSample {
        check: semantic_query_health_from_runtime(daemon_url, runtime),
        embedding_coverage: Some(kin_core::memory_pressure::EmbeddingCoverage {
            pending: runtime.embeddings_pending,
            indexed: runtime.embeddings_indexed,
            total: runtime.embeddings_total,
        }),
    }
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
    readiness: &kin_core::reference_coverage::LanguageServerReadinessMap,
) -> Vec<String> {
    use kin_core::reference_coverage::LanguageServerReadiness;
    crate::commands::language_servers::language_server_binaries()
        .into_iter()
        .filter_map(|(language, binaries)| match readiness.get(&language) {
            Some(LanguageServerReadiness::Usable) => None,
            // A server that is installed and cannot start is NOT reported here.
            // Telling an operator to install what they already have sends them
            // to the wrong repair, which is the whole reason the two states are
            // kept apart.
            Some(LanguageServerReadiness::Unusable { reason }) => Some(format!(
                "{language} (installed but it did not start: {reason})"
            )),
            Some(LanguageServerReadiness::Absent) | None => {
                Some(format!("{language} ({})", binaries.join(" or ")))
            }
        })
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
        crate::commands::language_servers::language_server_binaries()
            .into_iter()
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
///
/// The detail names `kin init` as what starts that pass. It is the command a
/// reader has usually just run when they reach doctor, and the earlier wording
/// pointed at a later `kin embed` that was never going to be the one paying
/// (FIR-2555).
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
                 within {}s; `kin init` starts the first embed pass, which fetches {download} \
                 from {host}, and until that lands nothing embeds",
                MODEL_HOST_PROBE_BUDGET.as_secs()
            ),
        ),
        (None, false, _) => (
            HealthStatus::Pending,
            format!(
                "{model} is not in the cache{location}; `kin init` starts the first embed \
                 pass, which fetches {download} from {host}, and it reports whether that \
                 pass ran or left the fetch for `kin embed`"
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

/// The fix for the fallback row, which probes every wired language because it
/// could not read the graph to learn which ones this repository holds.
///
/// Built rather than written out, so the commands here and the ones the
/// measured row prints come from one table. A hand-written example command is
/// how `npm i -g pyright` ended up beside a probe for `pyright-langserver`
/// without anything checking that the package provides the binary.
fn language_server_fix() -> String {
    let every: Vec<String> = crate::commands::language_servers::language_server_binaries()
        .into_iter()
        .map(|(language, _)| language.to_string())
        .collect();
    let names: Vec<&str> = every.iter().map(String::as_str).collect();
    crate::commands::language_servers::install_fix_line(&names)
}

/// Report the active retrieval quality profile and the effective lever set,
/// so an operator can see at a glance whether they are getting full
/// retrieval capability — and why not, when a lever is off.
/// One commit observation from a real converted repository.
///
/// `peak_bytes` is a WHOLE-MACHINE total taken while the commit ran, not the
/// commit's own demand: everything else resident at the time is inside it. That
/// distinction is FIR-2643. Keying these totals to store size and reading the
/// result as what a commit costs put this row roughly an order of magnitude out,
/// because the one measurement that separated the terms found a docstring-only
/// edit on a 500 MiB store costing about 0.9 GB over a resident baseline of
/// 8.16 GB, while the store-size reading implied a 10.6 GiB floor.
///
/// `observed_ceiling_bytes` is the size of the machine the total was taken
/// inside, and it travels with the total because a total means nothing without
/// it. 12283 MiB is comfortable in 24 GiB and is the last reading before a kill
/// in 12288 MiB, and it was the second.
struct MeasuredCommitPeak {
    repository: &'static str,
    store_bytes: u64,
    peak_bytes: u64,
    observed_ceiling_bytes: u64,
}

const MIB: u64 = 1024 * 1024;

/// Commit observations from converted repositories, smallest store first.
///
/// Every row is one whole-machine total taken while a commit ran, never a fitted
/// curve and never a commit's own demand, and the check below never interpolates
/// or extrapolates between them. It quotes the largest row whose store is no
/// larger than the store in front of it, so what a reader is told is always a
/// machine that was actually measured rather than a prediction about theirs.
/// Below the smallest row nothing is claimed at all.
///
/// The two rows are the table's own argument against a curve. `expressjs/express`
/// holds a store 47% the size of `psf/requests` and its total lands within 12% of
/// it. A quantity that barely moves when the store nearly halves is not a
/// quantity the store predicts, which is why this check compares one ceiling
/// against one observation and stops there.
///
/// Both were taken in the same 5 CPU / 12 GiB container on `kin 0.5.40`, before
/// the workspace-graph scoping in `plan_native_commit_inner` cut what a commit
/// holds at its peak. A build that peaks lower than a row makes this check
/// conservative rather than wrong, which is the safe direction for a warning:
/// it can advise headroom nobody needs, and it cannot stay quiet about a
/// ceiling somebody does.
const MEASURED_COMMIT_PEAKS: &[MeasuredCommitPeak] = &[
    MeasuredCommitPeak {
        repository: "expressjs/express",
        store_bytes: 437 * MIB,
        peak_bytes: 10809 * MIB,
        observed_ceiling_bytes: 12288 * MIB,
    },
    MeasuredCommitPeak {
        repository: "psf/requests",
        store_bytes: 922 * MIB,
        peak_bytes: 12283 * MIB,
        observed_ceiling_bytes: 12288 * MIB,
    },
];

/// How far above the quoted total a ceiling has to sit, as a percentage of that
/// total, before this check calls it ok.
///
/// This is a repeatability figure, not a scaling claim. Two commits observed in
/// the SAME 12 GiB container produced totals 13.6% apart, so a total is not
/// reproducible closer than that even with the machine held fixed. A ceiling
/// merely level with a quoted total therefore has no room in it, and calling
/// that ok is what told an isolated stranger run its 12288 MiB container was
/// fine six hours before a commit was killed at 12283 MiB.
///
/// FIR-2643: the margin used to be justified by "a larger store peaks higher",
/// which the table's own two rows do not support and which put this row's
/// forecast roughly an order of magnitude out. The band it opens is unchanged,
/// because the kill it caught is unchanged. Only the reason it exists is stated
/// correctly now.
///
/// The number rounds the observed spread up, because the safe direction for a
/// warning is to advise headroom nobody needs rather than to stay quiet about a
/// ceiling somebody does. `the_comfort_margin_covers_the_spread_the_table_shows`
/// holds it to the table, so a row measured later that spreads wider fails a
/// test instead of quietly narrowing the band this exists to open.
const COMMIT_PEAK_COMFORT_MARGIN_PERCENT: u64 = 14;

/// Report how this machine's memory ceiling compares with the totals commits on
/// stores this size have already been observed reaching.
///
/// A commit that runs out of memory is reported to the person running it as a
/// closed socket, and by then the write is gone. The comparison this row makes
/// needs no commit to have been attempted, so it is published where a user looks
/// before they are surprised rather than after.
///
/// What it does not do, since FIR-2643, is predict what a commit here would
/// cost. The observations it quotes are whole-machine totals, the commit's own
/// share of them is not modelled, and the version of this row that derived one
/// from store size ran roughly an order of magnitude high. It compares a ceiling
/// against an observation, and it says that is what it is doing.
///
/// It reports three bands. A ceiling clear of the quoted total is healthy, one
/// merely level with it is `Stale`, and one below it is `Degraded`. The middle
/// band exists because a total is not reproducible closer than the spread the
/// table itself shows, so parity with one is the edge rather than headroom.
///
/// It is advisory by construction and never blocks readiness, whichever band it
/// lands in. A ceiling below an observed total is a fact about a machine, not a
/// broken install, and a check that failed readiness on it would fail every
/// correct install on a small host.
fn check_commit_memory_headroom() -> HealthCheck {
    let cwd = env::current_dir().unwrap_or_default();
    let Some(layout) = kin_core::KinLayout::discover(&cwd) else {
        return HealthCheck::new(
            "commit_memory_headroom",
            "Commit memory headroom",
            HealthStatus::Unsupported,
            "not in a Kin repository, so there is no store to measure a commit against",
        );
    };
    let footprint = crate::commands::store_footprint::StoreFootprint::measure(&layout);
    commit_memory_headroom_check_for(&footprint, &crate::capability::memory_evidence())
}

/// What this machine affords Kin, stated before a conversion starts rather than
/// after one has already cost something.
///
/// Every other memory row on this page needs a store to talk about, so on a
/// fresh box, before `kin init`, all of them read n/a and the page says nothing
/// at all about whether Kin fits here. FIR-2787 is what that costs: four
/// separate disclosures reached one reader, each of them true, each on a
/// different surface, and each after the work it described had been paid for.
/// This row needs no repository, so it is the one that arrives first.
///
/// It states three things a reader can act on before an import runs for eleven
/// minutes: the ceiling this process actually runs under, what one repository
/// daemon will be allowed to hold inside it, and whether this machine is over
/// the line where locate runs its full multihop budget. It forecasts nothing
/// about a particular store, which is the neighbouring row's job and needs one
/// to exist.
///
/// Advisory by construction, like every memory row here. `Degraded` never
/// blocks readiness, because a machine smaller than Kin wants is a fact about
/// the machine, and a check that failed on it would fail every correct install
/// on a small host.
fn check_memory_floor() -> HealthCheck {
    memory_floor_check_for(
        &crate::capability::memory_evidence(),
        &crate::capability::CapabilityDetection::detect(),
    )
}

/// Core of [`check_memory_floor`] with both readings as inputs, so every branch
/// is testable on any host, including the small container no developer here
/// runs on.
fn memory_floor_check_for(
    evidence: &crate::capability::MemoryEvidence,
    detection: &crate::capability::CapabilityDetection,
) -> HealthCheck {
    const ID: &str = "memory_floor";
    const LABEL: &str = "Memory floor";

    let available = format_health_bytes(evidence.limit_bytes);
    let ceiling_source = evidence.limit_source.describe();
    // Resolved rather than derived, so an operator who named a budget is told
    // their own number. `kin doctor` runs before the conversion, so the daemon
    // this row is describing is one this shell has not started yet and will
    // start with this environment.
    let budget = kin_core::memory_pressure::FootprintBudget::resolve(Some(evidence.limit_bytes))
        .unwrap_or(kin_core::memory_pressure::FootprintBudget {
            bytes: kin_core::memory_pressure::FootprintBudget::derived_from(evidence.limit_bytes),
            source: kin_core::memory_pressure::BudgetSource::Derived,
        });
    let daemon_clause = format!(
        "one repository daemon is allowed {} of that, {}, and its background embedding is the \
         first work held back once that is spent; a second repository gets its own daemon and \
         its own {}, so two of them are allowed {} here",
        format_health_bytes(budget.bytes),
        describe_daemon_budget(&budget, evidence.limit_bytes),
        format_health_bytes(budget.bytes),
        format_health_bytes(budget.bytes.saturating_mul(2)),
    );

    let (tier_clause, tier_is_full) = memory_floor_tier_clause(detection);

    // The cheapest commit anybody has measured, so a ceiling under it is under
    // every row in the table. A reader with no store cannot pick a row by store
    // size the way `Commit memory headroom` does, so this quotes the floor of
    // the table and names the repository it came from.
    let cheapest = MEASURED_COMMIT_PEAKS
        .iter()
        .min_by_key(|point| point.peak_bytes);
    let (commit_clause, ceiling_clears) = match cheapest {
        None => (None, true),
        Some(point) => {
            let comfortable = point.peak_bytes.saturating_add(
                point
                    .peak_bytes
                    .saturating_mul(COMMIT_PEAK_COMFORT_MARGIN_PERCENT)
                    / 100,
            );
            let clears = evidence.limit_bytes >= comfortable;
            let clause = if clears {
                format!(
                    "The cheapest commit Kin has measured drove a {} machine to {} in total on \
                     {} ({} store), and this ceiling clears that by at least {}%",
                    format_health_bytes(point.observed_ceiling_bytes),
                    format_health_bytes(point.peak_bytes),
                    point.repository,
                    format_health_bytes(point.store_bytes),
                    COMMIT_PEAK_COMFORT_MARGIN_PERCENT,
                )
            } else {
                format!(
                    "The cheapest commit Kin has measured drove a {} machine to {} in total on \
                     {} ({} store), and {available} is not {}% clear of that, so a commit here \
                     has no measured room. That total is a whole-machine reading with everything \
                     else resident inside it rather than a commit's own demand, so this compares \
                     a ceiling against an observation and forecasts nothing about a write here",
                    format_health_bytes(point.observed_ceiling_bytes),
                    format_health_bytes(point.peak_bytes),
                    point.repository,
                    format_health_bytes(point.store_bytes),
                    COMMIT_PEAK_COMFORT_MARGIN_PERCENT,
                )
            };
            (Some(clause), clears)
        }
    };

    let mut detail =
        format!("{available} of memory here ({ceiling_source}); {daemon_clause}. {tier_clause}");
    if let Some(commit_clause) = commit_clause {
        detail.push_str(". ");
        detail.push_str(&commit_clause);
    }
    detail.push('.');

    if ceiling_clears && tier_is_full {
        return HealthCheck::new(ID, LABEL, HealthStatus::Healthy, detail);
    }

    // One fix line, carrying only the moves that apply. A fix that listed a
    // larger machine under a shortfall the machine does not have is the kind of
    // advice that sends a reader to buy hardware they already own, which is the
    // defect `disabled_signals` was corrected for.
    let mut moves: Vec<String> = Vec::new();
    if !ceiling_clears {
        moves.push(
            "convert one repository at a time here, and run `kin daemon stop` in a repository you \
             are not working in"
                .to_string(),
        );
        moves.push(format!(
            "raise this ceiling above {}",
            format_health_bytes(
                cheapest
                    .map(|point| point.peak_bytes.saturating_add(
                        point
                            .peak_bytes
                            .saturating_mul(COMMIT_PEAK_COMFORT_MARGIN_PERCENT)
                            / 100,
                    ))
                    .unwrap_or(evidence.limit_bytes)
            )
        ));
    }
    if !tier_is_full {
        moves.push(format!(
            "run locate work on a machine with {} cores and {:.0} GB to get the full multihop \
             budget",
            crate::capability::PERFORMANCE_TIER_MIN_CORES,
            crate::capability::PERFORMANCE_TIER_MIN_RAM_GB,
        ));
    }
    HealthCheck::new(ID, LABEL, HealthStatus::Degraded, detail).with_manual_fix(format!(
        "Before converting a repository here: {}.",
        moves.join(", or ")
    ))
}

/// Where a daemon's budget came from, in the four shapes it can take.
///
/// "Half the ceiling" is true of a 12 GiB container and false of a 128 GiB
/// workstation, where half is 64 and the derived budget is capped at 8. The row
/// printed the half sentence over both, which is a claim eight times the size of
/// the fact on the second machine, and a reader who trusted it would size their
/// host for a daemon Kin will never let grow that large.
fn describe_daemon_budget(
    budget: &kin_core::memory_pressure::FootprintBudget,
    ceiling_bytes: u64,
) -> String {
    if budget.source == kin_core::memory_pressure::BudgetSource::Operator {
        return format!(
            "the figure {} names rather than anything derived from this ceiling",
            kin_core::memory_pressure::FOOTPRINT_BUDGET_ENV
        );
    }
    let half = ceiling_bytes / 2;
    if budget.bytes >= kin_core::memory_pressure::DERIVED_BUDGET_CEILING_BYTES
        && half > budget.bytes
    {
        return format!(
            "the most a derived budget ever allows one daemon rather than half of {}, because a \
             repository daemon holding more than that is pathological whatever the host has spare",
            format_health_bytes(ceiling_bytes)
        );
    }
    if budget.bytes <= kin_core::memory_pressure::DERIVED_BUDGET_FLOOR_BYTES && half < budget.bytes
    {
        return "the least a derived budget ever allows, because a smaller one would back off \
                before it could do anything useful"
            .to_string();
    }
    "half the ceiling".to_string()
}

/// The tier half of the row, and whether this machine is over the line.
///
/// Split out because it has four shapes and the row has two, and because the
/// case that matters most is the one nobody can reach on a developer host: a
/// tier scored against a stand-in after the memory probe failed. That tier must
/// never be reported as a reading, since "run on a bigger host" is actively
/// wrong advice for a host that was never read.
fn memory_floor_tier_clause(detection: &crate::capability::CapabilityDetection) -> (String, bool) {
    let full = detection.profile == crate::capability::LocateProfile::Performance;
    let line = format!(
        "the {} core / {:.0} GB line",
        crate::capability::PERFORMANCE_TIER_MIN_CORES,
        crate::capability::PERFORMANCE_TIER_MIN_RAM_GB,
    );
    let narrowing = format!(
        "multihop depth {} of {}, frontier {} of {}, timeout {}ms of {}ms",
        detection.profile.multihop_max_depth(),
        crate::capability::LocateProfile::Performance.multihop_max_depth(),
        detection.profile.multihop_frontier_limit(),
        crate::capability::LocateProfile::Performance.multihop_frontier_limit(),
        detection.profile.multihop_timeout_ms(),
        crate::capability::LocateProfile::Performance.multihop_timeout_ms(),
    );

    if detection.forced_by_env {
        let clause = if full {
            format!(
                "KIN_LOCATE_PROFILE pins locate to the {} tier, so no reading of this host decided \
                 it and it runs the full multihop budget",
                detection.profile.name()
            )
        } else {
            format!(
                "KIN_LOCATE_PROFILE pins locate to the {} tier, so no reading of this host decided \
                 it: {narrowing}",
                detection.profile.name()
            )
        };
        return (clause, full);
    }

    // A probe that could not answer is scored against a stand-in, and the
    // stand-in is 4 GB, so this arm is always below the line. Saying which
    // numbers were read is the whole point: the remediation differs.
    if let Some(reason) = detection.misread_host() {
        return (
            format!(
                "this host's memory could not be read ({reason}), so locate was scored against a \
                 stand-in rather than a measurement and sits on the {} tier: {narrowing}",
                detection.profile.name()
            ),
            false,
        );
    }

    let cores = detection.cores.unwrap_or(0);
    let ram = detection
        .memory
        .as_ref()
        .map(|memory| memory.gb_or_stand_in())
        .unwrap_or(0.0);
    let clause = if full {
        format!(
            "{cores} cores and {ram:.1} GB put this machine at or over {line}, so locate runs its \
             full multihop budget"
        )
    } else {
        format!(
            "{cores} cores and {ram:.1} GB put locate on the {} tier, under {line}: {narrowing}",
            detection.profile.name()
        )
    };
    (clause, full)
}

/// Whether a daemon serving this store was killed, and what killed it.
///
/// Every other row on this page describes a daemon that is running or one that
/// is absent. A daemon that was killed leaves both readings intact: the store
/// is fine, a replacement is serving, and the kills that got it there appear in
/// no count anywhere on this page. The store's own record is the only thing
/// that remembers them, and this is the row that reads it.
///
/// Advisory by construction: `Degraded` does not block readiness, because a
/// machine too small for this repository is a fact about the machine and not a
/// broken install.
fn check_daemon_kill_record() -> HealthCheck {
    const ID: &str = "daemon_kill_record";
    const LABEL: &str = "Daemon kills";
    let cwd = env::current_dir().unwrap_or_default();
    let Some(layout) = kin_core::KinLayout::discover(&cwd) else {
        return HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Unsupported,
            "not in a Kin repository, so there is no store whose daemons could have been killed",
        );
    };
    // The store's tally OR a death it has not settled yet. The tally alone
    // leaves a window this row exists to close: a daemon killed with nothing
    // watching is settled by the NEXT daemon start, and a reader who runs
    // `kin doctor` before starting one is exactly the reader who just watched a
    // command die. This row would have told them no daemon serving this store
    // has ever been killed.
    daemon_kill_record_check_for(crate::daemon_death::recorded_for_store(layout.root()).as_ref())
}

/// Core of [`check_daemon_kill_record`] with the record as its input, so both
/// branches are testable on any host and without a killed daemon.
fn daemon_kill_record_check_for(
    record: Option<&kin_daemon_spawn::DaemonKillRecord>,
) -> HealthCheck {
    const ID: &str = "daemon_kill_record";
    const LABEL: &str = "Daemon kills";
    let Some(record) = record else {
        return HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Healthy,
            "no daemon serving this store has been killed",
        );
    };
    HealthCheck::new(ID, LABEL, HealthStatus::Degraded, record.cause_sentence())
        .with_manual_fix(record.remediation())
}

/// Whether this store's language-server enrichment has been switched off.
///
/// The daemon opens that circuit after three consecutive sweeps end early
/// having enriched nothing, and until now it said so in its own log and nowhere
/// else. Every counter a reader can see keeps reporting unenriched files as
/// pending work, which is the one reading that is wrong: nothing is going to
/// pick them up until a sweep is asked for.
///
/// Advisory rather than blocking, for the reason the kill row is: a store whose
/// sweeps keep dying is telling you about the machine, and the install is fine.
fn check_suspended_sweep() -> HealthCheck {
    const ID: &str = "suspended_sweep";
    const LABEL: &str = "Enrichment sweeps";
    let cwd = env::current_dir().unwrap_or_default();
    let Some(layout) = kin_core::KinLayout::discover(&cwd) else {
        return HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Unsupported,
            "not in a Kin repository, so there is no store whose sweeps could be suspended",
        );
    };
    suspended_sweep_check_for(kin_daemon_spawn::SuspendedSweep::read(layout.root()).as_ref())
}

/// Core of [`check_suspended_sweep`] with the reading as its input, so both
/// branches are testable without a store that has lost three sweeps.
fn suspended_sweep_check_for(suspended: Option<&kin_daemon_spawn::SuspendedSweep>) -> HealthCheck {
    const ID: &str = "suspended_sweep";
    const LABEL: &str = "Enrichment sweeps";
    let Some(suspended) = suspended else {
        return HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Healthy,
            "language-server enrichment is not suspended for this store",
        );
    };
    HealthCheck::new(
        ID,
        LABEL,
        HealthStatus::Degraded,
        suspended.cause_sentence(),
    )
    .with_manual_fix(suspended.remediation())
}

/// Whether this store's daemon has declined heavy work because the machine had
/// no room for it.
///
/// The refusal itself is the product working as intended: Kin measured the
/// pressure and backed off instead of pushing on until the kernel decided. What
/// would not be working is a refusal nobody can see. Every counter on every
/// other surface keeps reporting the work as pending, which reads exactly like
/// a store that is converging, and the daemon that decided is a process nobody
/// is watching.
///
/// Advisory rather than blocking, for the same reason the kill row and the
/// suspended-sweep row are: this is the host talking, not the install, and a
/// `kin doctor` that failed over a busy machine would be reporting the wrong
/// defect. `Degraded` never blocks readiness.
fn check_host_memory_pressure(
    embedding_coverage: Option<kin_core::memory_pressure::EmbeddingCoverage>,
) -> HealthCheck {
    const ID: &str = "host_memory_pressure";
    const LABEL: &str = "Host memory pressure";
    let cwd = env::current_dir().unwrap_or_default();
    let Some(layout) = kin_core::KinLayout::discover(&cwd) else {
        return HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Unsupported,
            "not in a Kin repository, so there is no store whose work could have been held back",
        );
    };
    let refusals = kin_core::memory_pressure::PressureRefusal::read_all(layout.root());
    host_memory_pressure_check_for(
        &refusals,
        kin_core::memory_pressure::DaemonFootprint::read(layout.root()).as_ref(),
        embedding_coverage,
    )
}

/// Every row the memory-pressure reading is worth, one measurement each.
///
/// Split from [`check_host_memory_pressure`] so the row set is one function
/// rather than a branch at the call site.
fn check_memory_pressure_rows(
    embedding_coverage: Option<kin_core::memory_pressure::EmbeddingCoverage>,
) -> Vec<HealthCheck> {
    let cwd = env::current_dir().unwrap_or_default();
    let refusal_row = check_host_memory_pressure(embedding_coverage);
    let Some(layout) = kin_core::KinLayout::discover(&cwd) else {
        return vec![refusal_row];
    };
    let mut rows = vec![refusal_row];
    if let Some(footprint) = kin_core::memory_pressure::DaemonFootprint::read(layout.root()) {
        rows.push(daemon_memory_standing_check_for(&footprint, unix_now()));
    }
    rows
}

/// Unix seconds now, or zero when the clock is before the epoch.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// What this store's daemon last published about what it is holding.
///
/// Its own row rather than a clause appended to the refusal row. A refusal is a
/// reading taken at the moment work was declined; this is the reading taken
/// when the daemon last published one. Joined into one row with "Also:" they
/// read as one self-contradicting claim, and the walkthrough that found it
/// quoted both halves back: 3.7 GiB and 7.0 GiB of the same 4.0 GiB allowance,
/// eleven child processes and ten. Two moments, two rows, each stamped.
fn daemon_memory_standing_check_for(
    footprint: &kin_core::memory_pressure::DaemonFootprint,
    now_unix: u64,
) -> HealthCheck {
    const ID: &str = "daemon_memory_standing";
    const LABEL: &str = "Daemon memory standing";
    let status = if footprint.standing().is_over_allowance() {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    };
    HealthCheck::new(ID, LABEL, status, footprint.row_sentence(now_unix))
}

/// Whether this store's creation-time replay version matches the one this
/// binary carries.
///
/// Advisory in phase one. A gap is real and deserves a red row, but it does not
/// mean the install or daemon is broken, so [`HealthStatus::Stale`] discloses it
/// without making the aggregate readiness result fail.
fn check_hydration_semantics() -> HealthCheck {
    const ID: &str = "hydration_semantics";
    const LABEL: &str = "Hydration semantics";
    let cwd = env::current_dir().unwrap_or_default();
    let Some(layout) = kin_core::KinLayout::discover(&cwd) else {
        return HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Unsupported,
            "not in a Kin repository, so there is no store whose replay semantics can be compared",
        );
    };
    hydration_semantics_check_for(&kin_core::hydration_semantics::standing(&layout))
}

/// Core of [`check_hydration_semantics`] with the standing as input, so every
/// comparison branch is testable without creating a repository.
fn hydration_semantics_check_for(
    standing: &kin_core::hydration_semantics::HydrationStanding,
) -> HealthCheck {
    const ID: &str = "hydration_semantics";
    const LABEL: &str = "Hydration semantics";
    let status = if standing.is_gap() {
        HealthStatus::Stale
    } else {
        HealthStatus::Healthy
    };
    let check = HealthCheck::new(ID, LABEL, status, standing.sentence());
    match standing.remedy() {
        Some(remedy) => check.with_manual_fix(remedy),
        None => check,
    }
}

/// Core of [`check_host_memory_pressure`] with both records and the exact
/// coverage observation as its inputs, so every branch is testable without a
/// machine that has actually run out of memory.
///
/// The healthy branch reports the standing rather than only the absence of a
/// refusal. "No work has been held back" is true and unusable: a reader whose
/// daemon is backing off wants to know how close it is, and a reader on a
/// machine Kin grades wrongly has nothing to look at and no way to know a
/// threshold needs moving. The numbers are already published, so printing them
/// costs nothing and turns the row from a bell into a gauge.
fn host_memory_pressure_check_for(
    refusals: &[kin_core::memory_pressure::PressureRefusal],
    footprint: Option<&kin_core::memory_pressure::DaemonFootprint>,
    embedding_coverage: Option<kin_core::memory_pressure::EmbeddingCoverage>,
) -> HealthCheck {
    const ID: &str = "host_memory_pressure";
    const LABEL: &str = "Host memory pressure";
    // Only an exact embedding observation can retire an old embed refusal.
    // The core predicate deliberately preserves LSP and unknown future work,
    // while `None` here preserves every refusal because nothing was measured.
    let refusal = refusals.iter().rev().find(|refusal| {
        embedding_coverage
            .map(|coverage| refusal.describes_outstanding_work(coverage))
            .unwrap_or(true)
    });
    let Some(refusal) = refusal else {
        // The gauge is not appended here. It is a live reading with its own
        // moment and it gets its own row, so this one carries exactly what the
        // refusal ledger says and nothing else.
        let detail = match footprint {
            Some(_) => "no work has been held back on this store for want of memory; the \
                        Daemon memory standing row reports how close it is"
                .to_string(),
            None => "no work has been held back on this store for want of memory".to_string(),
        };
        return HealthCheck::new(ID, LABEL, HealthStatus::Healthy, detail);
    };
    // One measurement, stamped. The live standing used to be appended here
    // behind "Also:", which put a reading from the moment work was declined
    // beside a reading from minutes later and let the row disagree with itself.
    // It has its own row now; see [`daemon_memory_standing_check_for`].
    // The synthetic record that means "I could not read the ledger" stamps
    // `at_unix` with the moment of the READ, and its own reason says Kin could
    // not read one complete record. So there may have been no declining at all,
    // and the ordinary clause would put a clock time on one that never
    // happened. That is the same fault as the row this check exists to fix,
    // which is why this record is stamped with what it is instead.
    let detail = if refusal.is_unreadable_record() {
        format!(
            "{}; Kin read that at {}, which is a read time and not a moment work was declined",
            refusal.cause_sentence(),
            kin_daemon_spawn::hhmm_utc(refusal.at_unix)
        )
    } else {
        format!(
            "{}; that reading was taken at {}, when the work was declined",
            refusal.cause_sentence(),
            kin_daemon_spawn::hhmm_utc(refusal.at_unix)
        )
    };
    HealthCheck::new(ID, LABEL, HealthStatus::Degraded, detail)
        .with_manual_fix(refusal.remediation())
}

/// How much of what this repository admits a language adapter actually parsed.
///
/// The row exists because the page reads healthy while a language's main files
/// hold no entity at all. `kin graph status` prints "Supported inputs" (what an
/// adapter could parse) beside "Files" (what produced an entity) and never
/// subtracts one from the other, so an express checkout where `lib/express.js`
/// was never parsed printed both numbers and then an all-clear, and `kin
/// doctor` agreed with it.
///
/// Reads the run's one `graph status` rather than taking its own, for the
/// reason every graph-truth row here does.
async fn check_parse_coverage(graph_status: &RunGraphStatus) -> HealthCheck {
    const ID: &str = "parse_coverage";
    const LABEL: &str = "Parse coverage";

    let response = match parse_coverage_row_for_unread_graph(graph_status.get().await) {
        Ok(response) => response,
        Err(row) => return row,
    };
    let Some(census) = response
        .reference_edge_coverage
        .as_ref()
        .and_then(|coverage| coverage.parse.as_ref())
    else {
        return HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Stale,
            "the daemon serving this repository does not report parse coverage; it predates the \
             measurement",
        )
        .with_manual_fix(
            "stop the daemon (`kin daemon stop`) so the next kin command starts one on this build",
        );
    };
    parse_coverage_health(census)
}

/// This row's words for a graph status the run could not read.
///
/// Phrased here rather than shared with the other graph-truth rows because a
/// row that reads graph truth must never render the same whether the graph was
/// healthy or unreadable.
fn parse_coverage_row_for_unread_graph(
    status: &GraphStatusForRun,
) -> Result<&crate::commands::graph::GraphCommandResponse, HealthCheck> {
    const ID: &str = "parse_coverage";
    const LABEL: &str = "Parse coverage";

    match status {
        GraphStatusForRun::Answered(response) => Ok(response),
        GraphStatusForRun::NotInRepository => Err(HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Unsupported,
            "not in a Kin repository, so there is no admitted file set to measure coverage over",
        )),
        GraphStatusForRun::NoDaemon => Err(HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Unsupported,
            "no daemon is serving this repository, so its parse coverage was not read",
        )
        .with_manual_fix("run any `kin` command in the repo to auto-start the daemon")),
        GraphStatusForRun::DaemonUrlInvalid { daemon_url, error } => Err(HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Stale,
            format!("daemon reachable ({daemon_url}), but its URL is invalid: {error}"),
        )
        .with_manual_fix("check the daemon URL recorded for this repository")),
        GraphStatusForRun::Unavailable { daemon_url, error } => Err(HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Stale,
            format!("daemon reachable ({daemon_url}), but parse coverage is unavailable: {error}"),
        )
        .with_manual_fix("run `kin graph status` and resolve the reported daemon error")),
    }
}

/// Turn the census into a row, split from its fetch so it is testable without a
/// daemon.
///
/// Healthy on a count alone, and that is a deliberate retreat rather than an
/// oversight. A verdict needs a signal that separates a language the extractor
/// failed on from a file that legitimately declares nothing: a side-effect
/// script, a re-export and a comment-only file each produce no entity and are
/// each perfectly correct. Measured on a five-file JavaScript repository holding
/// one real module beside one of each of those, the ratio reads 1/5, which is
/// worse than the express checkout this census was built for. So a silent file
/// is reported with its path and the reading is left to a person who can open
/// it.
///
/// One arm now reaches a verdict, because one signal now exists. The daemon's
/// reconcile seams record which paths did not parse from their CURRENT bytes,
/// and a file in that set is not one of the three correct silences: it is on
/// disk, it does not parse, and the entities the graph still serves for it came
/// from bytes it no longer has. That row goes to attention with the paths named
/// and a next step, and the `with_entities` numerator beside it already excludes
/// them.
pub(crate) fn parse_coverage_health(
    census: &kin_core::reference_coverage::ParseCoverageCensus,
) -> HealthCheck {
    const ID: &str = "parse_coverage";
    const LABEL: &str = "Parse coverage";

    if census.languages.is_empty() {
        return HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Healthy,
            "the repository tree admits no file a full language adapter parses",
        );
    }

    // The same numerator the census section prints, which excludes a file whose
    // current bytes did not parse. A row reading `python 2/2` above a sentence
    // naming one of those two would be two readings of one store on one line.
    let summary = census
        .languages
        .iter()
        .map(|language| {
            format!(
                "{} {}/{}",
                language.language, language.with_entities, language.tracked
            )
        })
        .collect::<Vec<String>>()
        .join("; ");

    // The one arm of this row that reaches a verdict, and the reason it can is
    // the signal the paragraph above says did not exist. A file the graph is
    // answering about from an earlier parse is not one of the three correct
    // silences: its bytes are on disk, they do not parse, and every span,
    // reference and enumeration over it describes bytes it no longer has. The
    // daemon's reconcile seams record exactly that set, so this row can now
    // separate the case worth acting on from the population it sits in.
    //
    // `Pending` rather than `Missing`: the graph is answering and every answer
    // it gives about every other file is still true, so this needs attention
    // without failing readiness, exactly as the reference-edge row beside it
    // does for a gap a person can close.
    // Both populations reach the detail, and only one reaches the verdict. An
    // early return on the retained arm dropped the silent sample from any store
    // holding both, which is the store most worth reading: a reader told about
    // one broken file would never learn that seventy-five others declare
    // nothing. The severity and the fix stay gated on the retained set alone,
    // because a silent file is not evidence that anything failed.
    let mut detail = vec![summary];
    detail.extend(census.retained_file_lines());
    detail.extend(census.silent_file_lines());
    let detail = detail.join("; ");

    if !census.any_retained() {
        return HealthCheck::new(ID, LABEL, HealthStatus::Healthy, detail);
    }
    HealthCheck::new(ID, LABEL, HealthStatus::Pending, detail).with_manual_fix(format!(
        "fix the syntax in {} and run `kin admit`, which re-derives them; until then Kin answers \
         about those paths from an earlier parse where it has one, and not at all where it does \
         not",
        census.retained_paths().join(", ")
    ))
}

/// Whether this store serves its graph from the persisted section or folds its
/// history at every open.
async fn check_graph_section(graph_status: &RunGraphStatus) -> HealthCheck {
    const ID: &str = "graph_section";
    const LABEL: &str = "Graph section";

    let response = match graph_section_row_for_unread_graph(graph_status.get().await) {
        Ok(response) => response,
        Err(row) => return row,
    };
    let Some(state) = response.graph_section.as_ref() else {
        return HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Stale,
            "the daemon serving this repository does not report whether it folds this store's \
             history at every open; it predates the measurement",
        )
        .with_manual_fix(
            "stop the daemon (`kin daemon stop`) so the next kin command starts one on this build",
        );
    };
    graph_section_health(state)
}

/// This row's words for a graph status the run could not read.
///
/// Phrased here rather than shared with the other graph-truth rows because a
/// row that reads graph truth must never render the same whether the graph was
/// healthy or unreadable.
fn graph_section_row_for_unread_graph(
    status: &GraphStatusForRun,
) -> Result<&crate::commands::graph::GraphCommandResponse, HealthCheck> {
    const ID: &str = "graph_section";
    const LABEL: &str = "Graph section";

    match status {
        GraphStatusForRun::Answered(response) => Ok(response),
        GraphStatusForRun::NotInRepository => Err(HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Unsupported,
            "not in a Kin repository, so there is no store whose open cost could be read",
        )),
        GraphStatusForRun::NoDaemon => Err(HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Unsupported,
            "no daemon is serving this repository, so whether its opens fold history was not read",
        )
        .with_manual_fix("run any `kin` command in the repo to auto-start the daemon")),
        GraphStatusForRun::DaemonUrlInvalid { daemon_url, error } => Err(HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Stale,
            format!("daemon reachable ({daemon_url}), but its URL is invalid: {error}"),
        )
        .with_manual_fix("check the daemon URL recorded for this repository")),
        GraphStatusForRun::Unavailable { daemon_url, error } => Err(HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Stale,
            format!(
                "daemon reachable ({daemon_url}), but the graph section state is unavailable: \
                 {error}"
            ),
        )
        .with_manual_fix("run `kin graph status` and resolve the reported daemon error")),
    }
}

/// Turn the section state into a row, split from its fetch so every branch is
/// testable without a daemon.
///
/// `Stale` for a folding store, and the severity is chosen rather than
/// inherited. A store that folds is completely correct; it is only paying a full
/// history replay at every open, which on the kin store was 47 seconds of a 95
/// second one. `Missing` and `Misconfigured` fail the whole report, and a store
/// that answers every question correctly must not do that. What is wanted is a
/// status that costs the all-clear and nothing else.
///
/// Two statuses do exactly that, and the row carried the wrong one. `Degraded`
/// is documented on the enum as "a real shortfall in the machine or container
/// Kin was asked to run on", and `setup.rs` reads it at its word: its closing
/// line prints "Degraded rows are host limits: Graph section." So a first
/// `kin commit` in a fresh repository told its owner that a memoization nobody
/// had written yet was a property of their machine, over a store holding one
/// change, with an internal repair command beside it (journey GAP-4). `Stale`
/// carries the same roll-up behaviour for this row, keeping it out of `Ready`
/// through `needs_attention` and out of `Failing` through `blocks_readiness`,
/// and it says the true thing: this store's acceleration is not current. The
/// row still names the one command that changes it.
///
/// A refused section is reported with kin-db's own refusal word because that is
/// the word its own log carries, so an operator comparing this row against
/// `.kin/daemon.log` is matching a term rather than guessing at a paraphrase.
pub(crate) fn graph_section_health(
    state: &kin_core::graph_section::GraphSectionState,
) -> HealthCheck {
    const ID: &str = "graph_section";
    const LABEL: &str = "Graph section";

    let status = match state.standing {
        kin_core::graph_section::GraphSectionStanding::Serving
        | kin_core::graph_section::GraphSectionStanding::Unborn => HealthStatus::Healthy,
        kin_core::graph_section::GraphSectionStanding::Folding => HealthStatus::Stale,
        // Never healthy. A state that could not be read is not a state that is
        // fine, and rendering it as one is the invisibility this row replaces.
        // It shares `Stale` with a folding store, and the two stay separate
        // where `kin_core::graph_section` keeps them separate, in the sentence:
        // one says the store folds and how big the fold is, the other says the
        // state could not be read and why. What the module refuses is rendering
        // either as a clean bill, and neither is one.
        kin_core::graph_section::GraphSectionStanding::Unknown => HealthStatus::Stale,
    };
    let check = HealthCheck::new(ID, LABEL, status, state.doctor_detail());
    if state.folds() {
        return check.with_manual_fix(
            "run `kin graph materialize` to persist this workspace's base graph, so later opens \
             read it instead of folding the history again",
        );
    }
    check
}

/// Core of [`check_commit_memory_headroom`] with both readings as inputs, so
/// every branch is testable on any host.
fn commit_memory_headroom_check_for(
    footprint: &crate::commands::store_footprint::StoreFootprint,
    evidence: &crate::capability::MemoryEvidence,
) -> HealthCheck {
    const ID: &str = "commit_memory_headroom";
    const LABEL: &str = "Commit memory headroom";
    let Some(store) = footprint.store.as_ref() else {
        return HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Unsupported,
            "the store could not be measured, so nothing here can be compared against it",
        );
    };
    let available = format_health_bytes(evidence.limit_bytes);
    let ceiling_source = evidence.limit_source.describe();
    let measured = MEASURED_COMMIT_PEAKS
        .iter()
        .rev()
        .find(|point| store.bytes >= point.store_bytes);
    let Some(measured) = measured else {
        return HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Healthy,
            format!(
                "{} of memory here ({ceiling_source}); this {} store is smaller than any store a \
                 commit has been observed on, so no headroom claim is made about it",
                available,
                format_health_bytes(store.bytes)
            ),
        );
    };
    let needed = format_health_bytes(measured.peak_bytes);
    let measured_store = format_health_bytes(measured.store_bytes);
    let measured_machine = format_health_bytes(measured.observed_ceiling_bytes);
    let room = format_observation_room(measured.peak_bytes, measured.observed_ceiling_bytes);
    let store_size = format_health_bytes(store.bytes);
    let ratio = format_store_ratio(store.bytes, measured.store_bytes);
    let comfortable = measured.peak_bytes.saturating_add(
        measured
            .peak_bytes
            .saturating_mul(COMMIT_PEAK_COMFORT_MARGIN_PERCENT)
            / 100,
    );
    if evidence.limit_bytes >= comfortable {
        return HealthCheck::new(
            ID,
            LABEL,
            HealthStatus::Healthy,
            format!(
                "{available} of memory here ({ceiling_source}); a commit on {} ({measured_store} \
                 store) was observed driving a {measured_machine} machine to {needed} in total, \
                 and this ceiling clears that peak by at least {}%. This {store_size} store is \
                 {ratio} the measured one",
                measured.repository, COMMIT_PEAK_COMFORT_MARGIN_PERCENT
            ),
        );
    }
    let (status, opening) = if evidence.limit_bytes >= measured.peak_bytes {
        (
            HealthStatus::Stale,
            format!(
                "{available} of memory here ({ceiling_source}) is parity with the {needed} a \
                 commit on {} ({measured_store} store) was observed reaching inside a \
                 {measured_machine} machine, {room}, not headroom over it",
                measured.repository
            ),
        )
    } else {
        (
            HealthStatus::Degraded,
            format!(
                "only {available} of memory here ({ceiling_source}), under the {needed} a commit \
                 on {} ({measured_store} store) was already observed reaching inside a \
                 {measured_machine} machine, {room}",
                measured.repository
            ),
        )
    };
    // What the row is allowed to say, and what it is not. The band above is an
    // observation compared against this machine's own ceiling, so it is stated.
    // What a commit HERE would cost is not modelled, so it is not stated, and
    // the store ratio is offered as distance from the measured case rather than
    // as a multiplier on the total. FIR-2643 is what the multiplier reading
    // cost: a 10.6 GiB floor quoted over a commit that took about 0.9 GB.
    HealthCheck::new(
        ID,
        LABEL,
        status,
        format!(
            "{opening}. That figure is a whole-machine total with everything else that was \
             resident inside it rather than a commit's own demand, so this row compares a ceiling \
             against an observation and forecasts nothing about this write. This {store_size} \
             store is {ratio} the measured one, which says how far it sits from the machine that \
             was measured, not what a commit on it would cost. Do this write on a smaller \
             repository or a larger machine. {}",
            crate::commands::commit_progress::COMMIT_MEMORY_REMEDY,
        ),
    )
    .with_manual_fix(
        "Run the commit on a machine or container with more memory, raise this container's memory \
         limit, or do this write on a smaller repository.",
    )
}

/// What the machine an observation was taken in still had when the total peaked.
///
/// A total is unreadable without its machine: 12283 MiB is comfortable in 24 GiB
/// and is the last reading before a kill in 12288 MiB. This is the phrase that
/// carries that difference into the row, and it is why the table stores the
/// machine beside the total.
fn format_observation_room(peak_bytes: u64, observed_ceiling_bytes: u64) -> String {
    let Some(room) = observed_ceiling_bytes
        .checked_sub(peak_bytes)
        .filter(|room| *room > 0)
    else {
        return "with nothing left in that machine".to_string();
    };
    format!(
        "{} short of that machine's own ceiling",
        format_health_bytes(room)
    )
}

/// How many times the measured store this store is.
///
/// The ratio says how far this store sits from the repository that was actually
/// observed, so a reader can judge whether the observation is close enough to
/// their case to act on. It is not a multiplier on the total. FIR-2643 is what
/// happens when a ratio is read that way, and the table's own rows are the
/// counter-example: a store 47% the size of the other lands within 12% of its
/// total.
fn format_store_ratio(store_bytes: u64, measured_bytes: u64) -> String {
    if measured_bytes == 0 {
        return "an unknown multiple of".to_string();
    }
    format!("{:.1}x", store_bytes as f64 / measured_bytes as f64)
}

fn format_health_bytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{} MiB", bytes / MIB)
    }
}

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

    fn write_editor_manifest(
        extensions_dir: &Path,
        folder: &str,
        publisher: &str,
        name: &str,
    ) -> PathBuf {
        let extension = extensions_dir.join(folder);
        std::fs::create_dir_all(&extension).expect("create editor extension fixture");
        std::fs::write(
            extension.join("package.json"),
            serde_json::json!({
                "publisher": publisher,
                "name": name,
                "version": "0.0.0-test",
            })
            .to_string(),
        )
        .expect("write editor extension manifest");
        extension
    }

    #[test]
    fn editor_detection_accepts_an_official_current_manifest() {
        let root = tempfile::tempdir().expect("extension root");
        write_editor_manifest(
            root.path(),
            "firelock.kin-editor-test",
            "firelock",
            "kin-editor",
        );

        assert!(editor_extension_detected_in(root.path()));
    }

    #[test]
    fn editor_detection_rejects_empty_candidates() {
        let root = tempfile::tempdir().expect("extension root");
        std::fs::create_dir(root.path().join("firelock.kin-editor-empty"))
            .expect("create empty candidate directory");
        std::fs::write(root.path().join("firelock.kin-editor-file"), b"")
            .expect("create matching regular file");

        assert!(!editor_extension_detected_in(root.path()));
    }

    #[test]
    fn editor_detection_rejects_a_malformed_manifest() {
        let root = tempfile::tempdir().expect("extension root");
        let extension = root.path().join("firelock.kin-editor-malformed");
        std::fs::create_dir(&extension).expect("create malformed candidate");
        std::fs::write(extension.join("package.json"), b"{not-json")
            .expect("write malformed manifest");

        assert!(!editor_extension_detected_in(root.path()));
    }

    #[test]
    fn editor_detection_rejects_wrong_manifest_identity() {
        let root = tempfile::tempdir().expect("extension root");
        write_editor_manifest(
            root.path(),
            "firelock.kin-editor-wrong-publisher",
            "someone-else",
            "kin-editor",
        );
        write_editor_manifest(
            root.path(),
            "firelock.kin-editor-wrong-name",
            "firelock",
            "something-else",
        );

        assert!(!editor_extension_detected_in(root.path()));
    }

    #[test]
    fn editor_detection_rejects_an_obsolete_official_version() {
        let root = tempfile::tempdir().expect("extension root");
        let folder = "firelock.kin-editor-obsolete";
        write_editor_manifest(root.path(), folder, "firelock", "kin-editor");
        std::fs::write(
            root.path().join(".obsolete"),
            serde_json::to_string(&std::collections::BTreeMap::from([(folder, true)]))
                .expect("serialize obsolete map"),
        )
        .expect("mark extension version obsolete");

        assert!(!editor_extension_detected_in(root.path()));
    }

    #[test]
    fn editor_detection_ignores_invalid_obsolete_state() {
        let root = tempfile::tempdir().expect("extension root");
        write_editor_manifest(
            root.path(),
            "firelock.kin-editor-current",
            "firelock",
            "kin-editor",
        );

        for invalid in [b"{not-json".as_slice(), b"[]".as_slice()] {
            std::fs::write(root.path().join(".obsolete"), invalid)
                .expect("write invalid obsolete state");
            assert!(
                editor_extension_detected_in(root.path()),
                "invalid .obsolete state must not hide a current extension"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn editor_detection_accepts_an_official_symlinked_directory() {
        let root = tempfile::tempdir().expect("extension root");
        let target_root = tempfile::tempdir().expect("extension target root");
        let target = write_editor_manifest(
            target_root.path(),
            "kin-editor-target",
            "firelock",
            "kin-editor",
        );
        std::os::unix::fs::symlink(target, root.path().join("firelock.kin-editor-symlinked"))
            .expect("link official editor extension");

        assert!(editor_extension_detected_in(root.path()));
    }

    fn footprint(store_bytes: u64) -> crate::commands::store_footprint::StoreFootprint {
        crate::commands::store_footprint::StoreFootprint {
            store: Some(crate::commands::store_footprint::TreeBytes {
                bytes: store_bytes,
                unreadable_entries: 0,
            }),
            git_objects: None,
            unmeasured_reason: None,
        }
    }

    fn memory(limit_bytes: u64) -> crate::capability::MemoryEvidence {
        crate::capability::MemoryEvidence {
            limit_bytes,
            limit_source: crate::capability::MemoryLimitSource::HostRam,
            cgroup_oom_kills: None,
            cgroup_ceiling_hits: None,
        }
    }

    /// The same ceiling, read off a container cap instead of the host figure.
    fn capped_memory(limit_bytes: u64) -> crate::capability::MemoryEvidence {
        crate::capability::MemoryEvidence {
            limit_bytes,
            limit_source: crate::capability::MemoryLimitSource::ContainerLimit,
            cgroup_oom_kills: None,
            cgroup_ceiling_hits: None,
        }
    }

    /// Build a detection the way the host probe would have, so a row's numbers
    /// come from a shape the real reader produces rather than from a literal.
    fn detected(
        profile: crate::capability::LocateProfile,
        cores: usize,
        ram_gb: f64,
    ) -> crate::capability::CapabilityDetection {
        crate::capability::CapabilityDetection {
            profile,
            forced_by_env: false,
            cores: Some(cores),
            memory: Some(crate::capability::HostMemory::Detected(ram_gb)),
        }
    }

    /// "Half the ceiling" is true of a small container and false of a big host.
    ///
    /// The first draft of this row said it over both. On the 128 GiB machine it
    /// was written on, half is 64 GiB and the budget a daemon actually gets is
    /// 8, so the sentence was eight times the size of the fact and pointed a
    /// reader at a host they would never need. Caught by printing the row rather
    /// than by reading it, which is why this arm exists.
    ///
    /// Falsify by restoring the unconditional "half the ceiling": the clamped
    /// arm goes red and the container arm stays green, which is exactly how the
    /// defect read.
    #[test]
    #[serial]
    fn the_budget_clause_says_half_only_where_the_budget_really_is_half() {
        let container = memory_floor_check_for(
            &capped_memory(12288 * MIB),
            &detected(crate::capability::LocateProfile::Standard, 5, 12.0),
        );
        assert!(
            container
                .detail
                .contains("6.0 GiB of that, half the ceiling"),
            "on a 12 GiB box the derived budget really is half of it: {}",
            container.detail
        );

        let workstation = memory_floor_check_for(
            &memory(128 * 1024 * MIB),
            &detected(crate::capability::LocateProfile::Performance, 18, 128.0),
        );
        assert!(
            !workstation.detail.contains("half the ceiling"),
            "half of 128 GiB is 64 and the cap holds a daemon to 8, so this machine is not \
             getting half of anything: {}",
            workstation.detail
        );
        assert!(
            workstation.detail.contains("8.0 GiB of that")
                && workstation
                    .detail
                    .contains("the most a derived budget ever allows"),
            "and the row names the cap that decided it: {}",
            workstation.detail
        );
    }

    /// A budget an operator named is theirs, not a number this row derived.
    ///
    /// Doctor runs before the conversion, so the daemon being described is one
    /// this shell has not started and will start with this environment. Quoting
    /// a derived figure over an operator's own would misreport the machine they
    /// configured.
    #[test]
    #[serial]
    fn a_budget_an_operator_named_is_reported_as_theirs() {
        let _guard = EnvVarGuard::set(
            kin_core::memory_pressure::FOOTPRINT_BUDGET_ENV,
            (3 * 1024 * MIB).to_string(),
        );
        let check = memory_floor_check_for(
            &memory(128 * 1024 * MIB),
            &detected(crate::capability::LocateProfile::Performance, 18, 128.0),
        );
        assert!(
            check.detail.contains("3.0 GiB of that")
                && check
                    .detail
                    .contains(kin_core::memory_pressure::FOOTPRINT_BUDGET_ENV),
            "the row quotes the operator's number and names where it came from: {}",
            check.detail
        );
        assert!(
            !check.detail.contains("half the ceiling"),
            "and never calls it a fraction of anything: {}",
            check.detail
        );
    }

    /// The stranger's own box, and the reading nobody was given until after an
    /// eleven-minute conversion had spent itself.
    ///
    /// Five schedulable CPUs and a 12 GiB container cap. Every memory row on
    /// this page reads n/a there before `kin init`, because every one of them
    /// needs a store, so the page said nothing at all about a machine two
    /// converted repositories would not fit on.
    ///
    /// Falsify by returning `Healthy` unconditionally, or by deleting the
    /// registration: the constrained arm goes quiet, which is the state this
    /// row exists to end.
    #[test]
    #[serial]
    fn the_memory_floor_row_reads_a_constrained_container_before_any_repository_exists() {
        let check = memory_floor_check_for(
            &capped_memory(12288 * MIB),
            &detected(crate::capability::LocateProfile::Standard, 5, 12.0),
        );

        assert!(
            matches!(check.status, HealthStatus::Degraded),
            "a container two daemons do not fit in is not a quiet row: {}",
            check.detail
        );
        assert!(
            check.detail.contains("12.0 GiB") && check.detail.contains("container"),
            "the ceiling and which reading it came from are the whole point: {}",
            check.detail
        );
        assert!(
            check.detail.contains("6.0 GiB"),
            "the per-daemon budget is what the reader is about to spend: {}",
            check.detail
        );
        assert!(
            check.manual_fix.is_some(),
            "every non-green row on this page carries the fix it needs: {check:?}"
        );
    }

    /// The arithmetic that makes a 12 GiB box a bad place for two repositories,
    /// stated before the second conversion rather than after it.
    ///
    /// One daemon per repository, each deriving half the ceiling. Two of them
    /// are allowed the whole machine, which is the sentence the stranger
    /// assembled for themselves out of four surfaces over several hours.
    #[test]
    #[serial]
    fn the_row_states_what_two_repository_daemons_come_to_against_this_ceiling() {
        let check = memory_floor_check_for(
            &capped_memory(12288 * MIB),
            &detected(crate::capability::LocateProfile::Standard, 5, 12.0),
        );
        assert!(
            check.detail.contains("two of them are allowed 12.0 GiB"),
            "one daemon at 6.0 GiB is unremarkable and two are the whole box; the row has to do \
             that multiplication for the reader: {}",
            check.detail
        );
    }

    /// The control, and the reason the row is worth having at all.
    ///
    /// A warning that fires on every machine is wallpaper by the second run.
    /// This is a developer host clear of both lines, and it has to be silent.
    #[test]
    #[serial]
    fn a_machine_over_both_lines_keeps_a_quiet_row_and_offers_no_repair() {
        let check = memory_floor_check_for(
            &memory(64 * 1024 * MIB),
            &detected(crate::capability::LocateProfile::Performance, 10, 64.0),
        );
        assert!(
            matches!(check.status, HealthStatus::Healthy),
            "{}",
            check.detail
        );
        assert!(
            check.manual_fix.is_none(),
            "there is nothing to repair on a machine that clears both lines: {check:?}"
        );
        assert!(
            check.detail.contains("full multihop budget"),
            "and it says so, because a reader deciding where to convert wants the positive \
             answer too: {}",
            check.detail
        );
    }

    /// A fix line names only the moves this machine needs.
    ///
    /// A 32 GiB box with four cores clears every measured commit and is still
    /// under the tier line. Telling that reader to raise a memory limit is the
    /// shape of advice that sent an earlier operator off to buy hardware they
    /// were already running, which is what `disabled_signals` was corrected
    /// for. The two arms are asserted against each other so neither can quietly
    /// become the other's text.
    #[test]
    #[serial]
    fn the_fix_line_names_the_shortfall_this_machine_has_and_not_the_other_one() {
        let tier_only = memory_floor_check_for(
            &memory(32 * 1024 * MIB),
            &detected(crate::capability::LocateProfile::Standard, 4, 32.0),
        );
        assert!(
            matches!(tier_only.status, HealthStatus::Degraded),
            "{}",
            tier_only.detail
        );
        let fix = tier_only
            .manual_fix
            .clone()
            .expect("a row needing attention carries its fix");
        assert!(
            fix.contains("multihop"),
            "the shortfall this machine has is the tier: {fix}"
        );
        assert!(
            !fix.contains("raise this ceiling"),
            "and a machine with memory to spare must not be told to buy more: {fix}"
        );

        let ceiling_only = memory_floor_check_for(
            &capped_memory(8 * 1024 * MIB),
            &detected(crate::capability::LocateProfile::Performance, 16, 8.0),
        );
        let fix = ceiling_only
            .manual_fix
            .clone()
            .expect("a ceiling under every measured commit carries its fix");
        assert!(
            fix.contains("raise this ceiling"),
            "the shortfall here is the ceiling: {fix}"
        );
        assert!(
            !fix.contains("multihop"),
            "and locate is already running at full budget on it: {fix}"
        );
    }

    /// The line a reader is told is the line that is scored.
    ///
    /// Two constants, read by the tier scorer and by this row, so the sentence
    /// cannot drift from the threshold. Asserting a literal "8 core / 16 GB"
    /// here would write the number twice and let the row keep quoting a line
    /// the scorer had moved off.
    ///
    /// Falsify by hardcoding the pair in `memory_floor_tier_clause` and then
    /// changing either constant: this goes red and nothing else does.
    #[test]
    #[serial]
    fn the_tier_line_the_row_quotes_is_the_one_the_scorer_uses() {
        let check = memory_floor_check_for(
            &memory(64 * 1024 * MIB),
            &detected(crate::capability::LocateProfile::Performance, 10, 64.0),
        );
        let line = format!(
            "{} core / {:.0} GB",
            crate::capability::PERFORMANCE_TIER_MIN_CORES,
            crate::capability::PERFORMANCE_TIER_MIN_RAM_GB,
        );
        assert!(
            check.detail.contains(&line),
            "the row has to quote the scorer's own threshold: wanted {line} in {}",
            check.detail
        );
    }

    /// A tier scored from a probe that failed is never reported as a reading.
    ///
    /// The stand-in is 4 GB, so this arm always lands below the line, and "run
    /// on a bigger host" is actively wrong advice for a host nothing read. The
    /// forced arm is the same rule from the other side: an operator who named
    /// the tier was not measured either.
    #[test]
    #[serial]
    fn a_tier_from_an_unread_host_or_an_operator_says_so_instead_of_quoting_numbers() {
        let misread = memory_floor_check_for(
            &memory(64 * 1024 * MIB),
            &crate::capability::CapabilityDetection {
                profile: crate::capability::LocateProfile::Minimal,
                forced_by_env: false,
                cores: Some(10),
                memory: Some(crate::capability::HostMemory::Undetected(
                    "sysctl hw.memsize refused".to_string(),
                )),
            },
        );
        assert!(
            misread.detail.contains("could not be read")
                && misread.detail.contains("sysctl hw.memsize refused"),
            "the row says the host was not read, and quotes the probe's own reason: {}",
            misread.detail
        );
        assert!(
            matches!(misread.status, HealthStatus::Degraded),
            "an unmeasured host is not a machine this row has cleared: {}",
            misread.detail
        );

        let forced = memory_floor_check_for(
            &memory(64 * 1024 * MIB),
            &crate::capability::CapabilityDetection {
                profile: crate::capability::LocateProfile::Performance,
                forced_by_env: true,
                cores: None,
                memory: None,
            },
        );
        assert!(
            forced.detail.contains("KIN_LOCATE_PROFILE"),
            "a tier an operator named says who named it: {}",
            forced.detail
        );
        assert!(
            matches!(forced.status, HealthStatus::Healthy),
            "a forced performance tier runs the full budget, whoever chose it: {}",
            forced.detail
        );
    }

    /// The stranded-stage row scans where an operator stands, and reaps
    /// nothing.
    ///
    /// A repository stage sits beside the repository that was never created,
    /// not inside it, so the row that finds it has to look at the parent as
    /// well as the working directory. Scanned here from one level down, which
    /// is the standpoint the reported case had: a real `redis-full` clone with
    /// the crashed init's 1.5 GB stage sitting next to it.
    ///
    /// The clean parent beside it is the control. Without it a row that
    /// reported every directory as degraded would pass this test.
    #[cfg(unix)]
    #[test]
    fn the_stranded_stage_row_scans_the_working_directory_and_its_parent() {
        let directory = tempfile::tempdir().unwrap();
        let parent = directory.path().canonicalize().unwrap();
        let corpus = parent.join("redis-full");
        std::fs::create_dir(&corpus).unwrap();
        let (stage, owner) =
            kin_core::init::strand_repository_stage(&parent, &corpus.join(".kin")).unwrap();

        let check =
            stranded_init_stage_check_for(&kin_core::init_attempt::staging_scan_roots(&corpus));
        assert!(matches!(check.status, HealthStatus::Degraded), "{check:?}");
        assert!(
            check.detail.contains(&stage.display().to_string()),
            "{}",
            check.detail
        );
        assert!(
            check
                .manual_fix
                .as_deref()
                .unwrap_or_default()
                .contains("kin doctor --reclaim-staging"),
            "{check:?}"
        );
        assert!(
            stage.is_dir(),
            "doctor reports and must never reap what it reports"
        );
        assert!(owner.is_file());

        let clean = tempfile::tempdir().unwrap();
        let quiet = stranded_init_stage_check_for(&[clean.path().to_path_buf()]);
        assert!(matches!(quiet.status, HealthStatus::Healthy), "{quiet:?}");
        assert!(quiet.manual_fix.is_none(), "{quiet:?}");
    }

    /// A scan root the process cannot read is reported, not reported as clean.
    ///
    /// The row used to drop the error and fall through to Healthy, printing
    /// "no crashed `kin init` left a staged store beside this directory" about
    /// a directory it had never managed to open. The reclaim beside it already
    /// refused to do that, so the two surfaces disagreed on the same machine.
    ///
    /// The clean tempdir above is the control for the Healthy arm; this one is
    /// the control for the other direction, so neither reading is an accident.
    #[cfg(unix)]
    #[test]
    fn a_scan_root_that_cannot_be_read_is_reported_rather_than_read_as_clean() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let sealed = directory.path().join("sealed");
        std::fs::create_dir(&sealed).unwrap();
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();

        let check = stranded_init_stage_check_for(std::slice::from_ref(&sealed));
        // Restored before any assertion, so a failing assertion still leaves a
        // directory the tempdir can remove.
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(check.status, HealthStatus::Degraded), "{check:?}");
        assert!(
            check.detail.contains(&sealed.display().to_string()),
            "{}",
            check.detail
        );
        assert!(
            check
                .detail
                .contains("does not say whether anything is stranded"),
            "{}",
            check.detail
        );
    }

    /// A reclaim that could examine nothing refuses, rather than exiting clean.
    ///
    /// `main` exits non-zero only on `Err`, so returning `Ok(())` after every
    /// root failed would tell a script that reads the exit status that the disk
    /// was examined and found clean. The human summary in that case even prints
    /// "nothing to reclaim here", which is the one sentence this must never say
    /// about a directory it could not open.
    ///
    /// The readable tempdir is the control: a genuinely clean parent still
    /// succeeds, so this is not a refusal that fires on everything.
    #[cfg(unix)]
    #[test]
    fn a_reclaim_that_could_examine_nothing_refuses_rather_than_reporting_clean() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let sealed = directory.path().join("sealed");
        std::fs::create_dir(&sealed).unwrap();
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();

        let refused = reclaim_stranded_stages_in(std::slice::from_ref(&sealed), false);
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700)).unwrap();

        let error = refused.expect_err("a root that could not be examined is not a clean parent");
        let message = error.to_string();
        assert!(message.contains(&sealed.display().to_string()), "{message}");
        assert!(
            message.contains("no directory could be examined"),
            "{message}"
        );

        let clean = tempfile::tempdir().unwrap();
        assert!(
            reclaim_stranded_stages_in(&[clean.path().to_path_buf()], false).is_ok(),
            "a readable empty parent still succeeds"
        );
    }

    /// The reading a user needed BEFORE the commit that killed their daemon.
    ///
    /// A ceiling under a peak already measured for a store no larger than this
    /// one is the band that reads red: nothing about the install is wrong, and
    /// the write is still going to die.
    ///
    /// Falsify by comparing against `store.bytes` instead of the measured peak,
    /// or by returning `Healthy` unconditionally: the constrained arm then
    /// passes silently, which is the state this check exists to end.
    /// The row has to find staging whether doctor is run from the repository
    /// being converted or from the directory that holds it, because init stages
    /// beside the repository and an operator stands in either place.
    #[test]
    fn the_interrupted_conversion_row_scans_the_working_directory_and_its_parent() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let repo = root.join("requests");
        std::fs::create_dir(&repo).unwrap();

        let clean = interrupted_init_check_for(&interrupted_init_scan_roots(&repo));
        assert!(
            matches!(clean.status, HealthStatus::Healthy),
            "a disk with no staging on it must not raise a row: {clean:?}"
        );
        assert!(clean.manual_fix.is_none());

        // The shape a killed init leaves: a leased capture directory carrying a
        // phase record, beside the repository rather than inside it.
        let capture = root.join(".kin-git-capture-abdd7a1c");
        std::fs::create_dir(&capture).unwrap();
        std::fs::write(capture.join("capture.lease"), b"").unwrap();
        std::fs::write(capture.join("body"), vec![0_u8; 4096]).unwrap();
        let record = serde_json::json!({
            "version": 1,
            "source": repo.display().to_string(),
            "destination": repo.join(".kin").display().to_string(),
            "pid": 41,
            "started_unix": 1000,
            "phase_index": 13,
            "phase_total": 17,
            "phase_label": "commit bootstrap transaction",
            "phase_started_unix": 1707,
            "memory_limit_bytes": 12884901888_u64,
            "memory_source": "container",
            "stage_path": serde_json::Value::Null,
        });
        std::fs::write(
            capture.join("init-attempt.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();

        for (where_from, cwd) in [("inside the repository", &repo), ("beside it", &root)] {
            let found = interrupted_init_check_for(&interrupted_init_scan_roots(cwd));
            assert!(
                matches!(found.status, HealthStatus::Degraded),
                "run {where_from}, the row must raise: {found:?}"
            );
            assert!(
                found
                    .detail
                    .contains("phase 13 of 17, commit bootstrap transaction"),
                "run {where_from}, the row must name the phase: {}",
                found.detail
            );
            assert!(
                found.detail.contains(" KB of staging"),
                "run {where_from}, the row must name the size in bytes it measured: {}",
                found.detail
            );
            let fix = found
                .manual_fix
                .as_deref()
                .unwrap_or_else(|| panic!("run {where_from}, the row must carry a fix line"));
            assert!(
                fix.contains(&capture.display().to_string()),
                "run {where_from}, the fix must name the path to delete: {fix}"
            );
        }

        // One directory, reachable from two scan roots, is one finding.
        let both = interrupted_init_check_for(&interrupted_init_scan_roots(&repo));
        assert!(
            both.detail.contains("from 1 interrupted"),
            "a capture found through both roots must be counted once: {}",
            both.detail
        );
        assert!(
            capture.exists(),
            "doctor reports and must never reap what it reports"
        );
    }

    /// A working directory with no parent is the filesystem root, and asking
    /// for one must not produce a duplicate scan of the same directory.
    #[test]
    fn the_scan_roots_never_repeat_a_directory() {
        let root = interrupted_init_scan_roots(Path::new("/"));
        assert_eq!(root, vec![PathBuf::from("/")], "the root has no parent");
        let nested = interrupted_init_scan_roots(Path::new("/tmp"));
        assert_eq!(
            nested.len(),
            2,
            "an ordinary directory scans itself and its parent: {nested:?}"
        );
        assert_ne!(nested[0], nested[1]);
    }

    #[test]
    fn doctor_reads_a_ceiling_below_a_measured_commit_peak_as_degraded() {
        let check =
            commit_memory_headroom_check_for(&footprint(1844 * MIB), &memory(8 * 1024 * MIB));
        assert!(
            matches!(check.status, HealthStatus::Degraded),
            "a ceiling under a measured peak is over parity, not at it: {:?}",
            check.status
        );
        assert!(
            check.detail.contains("psf/requests") && check.detail.contains("12.0 GiB"),
            "the warning must quote the repository and peak it was measured on: {}",
            check.detail
        );
        assert!(
            check.detail.contains("2.0x the measured one"),
            "the reader cannot judge a floor without the store ratio: {}",
            check.detail
        );
        assert!(
            check.manual_fix.is_some(),
            "a warning a reader cannot act on is noise"
        );
    }

    /// Parity with an observed total is the edge, and it used to round up to ok.
    ///
    /// A one-file commit on a 922 MiB store peaked at 12283 MiB against a
    /// 12288 MiB ceiling. `kin doctor` had both numbers and called it ok six
    /// hours before the commit was killed, because it compared with `>=` and
    /// 12288 clears 12283. Amber is the whole finding: it costs a reader
    /// nothing to move the write to a smaller repository, and it costs them the
    /// write not to.
    ///
    /// FIR-2643 changed what this test requires of the WORDS and deliberately
    /// left what it requires of the BAND alone. It used to demand the row call
    /// the quoted total "a floor here rather than a bound", which is the
    /// store-size extrapolation that ran roughly an order of magnitude high;
    /// that clause is gone, and continuing to assert it would have pinned the
    /// defect in place. What replaces it is the claim that survives its own
    /// evidence: the quoted number is a whole-machine total, and the row has to
    /// say so. The band is untouched, so a commit that would exceed this ceiling
    /// still cannot be reported as safe, which is the kill this test was bought
    /// by.
    ///
    /// Falsify by restoring the `>=` comparison against the bare peak: both
    /// arms below go `Healthy` again and the assertions name the status.
    #[test]
    fn doctor_reads_a_ceiling_at_a_measured_commit_peak_as_parity_rather_than_ok() {
        let exactly_at = commit_memory_headroom_check_for(
            &footprint(1844 * MIB),
            &memory(MEASURED_COMMIT_PEAKS[1].peak_bytes),
        );
        assert!(
            matches!(exactly_at.status, HealthStatus::Stale),
            "a ceiling exactly at the measured peak is parity, not headroom: {:?}",
            exactly_at.status
        );

        // The container the isolated stranger run actually had: 5 MiB of margin
        // on a 12 GiB budget, which is arithmetic rather than headroom.
        let stranger =
            commit_memory_headroom_check_for(&footprint(1844 * MIB), &memory(12288 * MIB));
        assert!(
            matches!(stranger.status, HealthStatus::Stale),
            "12288 MiB over a 12283 MiB peak is parity: {:?}",
            stranger.status
        );
        assert!(
            stranger.detail.contains("parity"),
            "the row has to say what band it is in: {}",
            stranger.detail
        );
        assert!(
            stranger.detail.contains("psf/requests") && stranger.detail.contains("12.0 GiB"),
            "parity must quote the peak it is at parity with: {}",
            stranger.detail
        );
        assert!(
            stranger.detail.contains("2.0x the measured one"),
            "the reader cannot judge how far the observation sits from their case without the \
             store ratio: {}",
            stranger.detail
        );
        assert!(
            stranger.detail.contains("whole-machine total"),
            "the quoted number includes everything else that was resident, and a reader who \
             takes it for a commit's own demand is reading the defect: {}",
            stranger.detail
        );
        assert!(
            stranger
                .detail
                .contains("5 MiB short of that machine's own ceiling"),
            "12283 MiB inside 12288 MiB is the whole finding, and the row that omits the gap \
             leaves a reader nothing to weigh: {}",
            stranger.detail
        );
        assert!(
            !matches!(stranger.status, HealthStatus::Healthy),
            "a ceiling with no room over an observed total must never be reported as safe: {:?}",
            stranger.status
        );
        assert!(
            stranger.detail.contains("smaller repository"),
            "the row exists to redirect the write before the kill: {}",
            stranger.detail
        );
        assert!(
            stranger.manual_fix.is_some(),
            "a warning a reader cannot act on is noise"
        );
    }

    /// The row states what it does not know instead of forecasting a kill from
    /// a model that measures the wrong thing.
    ///
    /// The rc0550 stranger watched this row warn that a commit could be killed
    /// mid-transaction, quoting a 10.6 GiB floor, before a docstring-only commit
    /// on a 500 MiB requests store. That commit's attributable cost was about
    /// 0.9 GB over an 8.16 GB resident baseline. The forecast was roughly an
    /// order of magnitude out because it read whole-machine totals as commit
    /// demand and then scaled them by store size, and a warning that far off is
    /// ignored by the third time a reader watches the write succeed anyway.
    ///
    /// Both warning bands are swept, because the row is one shared tail joined
    /// to a band-specific opening and a correction applied to one is not a
    /// correction. The positive controls are the point of the test: an emptied
    /// row satisfies every negative assertion here, so the row must still name
    /// the repository, the total, the store ratio and a fix a reader can act on.
    ///
    /// Falsify by restoring either removed claim. The kill forecast fails the
    /// first assertion in each band; the store-size floor fails the second.
    #[test]
    fn the_headroom_row_states_its_uncertainty_instead_of_forecasting_a_kill() {
        let bands = [
            (
                "degraded",
                commit_memory_headroom_check_for(&footprint(1844 * MIB), &memory(8 * 1024 * MIB)),
            ),
            (
                "parity",
                commit_memory_headroom_check_for(&footprint(1844 * MIB), &memory(12288 * MIB)),
            ),
        ];
        for (band, check) in bands {
            assert!(
                !check.detail.contains("can be killed"),
                "{band}: the row forecasts a kill from a cost it does not model: {}",
                check.detail
            );
            assert!(
                !check.detail.contains("floor here rather than a bound")
                    && !check.detail.contains("larger store peaks higher"),
                "{band}: the row is extrapolating an observed total by store size again: {}",
                check.detail
            );
            assert!(
                check
                    .detail
                    .contains("not yet modelled well enough to predict from the store alone"),
                "{band}: a row that drops the forecast owes the reader what it does not know: {}",
                check.detail
            );
            assert!(
                check.detail.contains("whole-machine total"),
                "{band}: the quoted number carries everything else that was resident, and \
                 leaving that out is what let it be read as commit demand: {}",
                check.detail
            );
            // Positive controls. Every assertion above passes on an empty row.
            assert!(
                check.detail.contains("psf/requests") && check.detail.contains("12.0 GiB"),
                "{band}: the row still owes the reader the repository and the total: {}",
                check.detail
            );
            assert!(
                check.detail.contains("2.0x the measured one"),
                "{band}: the row still owes the reader how far its store sits from that one: {}",
                check.detail
            );
            assert!(
                check.detail.contains("smaller repository"),
                "{band}: the row exists to redirect the write before it is spent: {}",
                check.detail
            );
            assert!(
                check.manual_fix.is_some(),
                "{band}: a warning a reader cannot act on is noise"
            );
        }
    }

    /// Dropping the forecast is not permission to go quiet.
    ///
    /// The band is the half of this row grounded in an observation rather than a
    /// model, and it is the half that caught the 12283 MiB commit inside the
    /// 12288 MiB container. This sweeps the whole table instead of one fixture,
    /// so a row measured later inherits the guarantee rather than needing its own
    /// test, and it covers exact parity, one MiB under, and half the total.
    ///
    /// Falsify by comparing with `>` instead of `>=`, or by returning `Healthy`
    /// from any band: the exact-parity arm fails first and names the total it
    /// was judged against.
    #[test]
    fn the_headroom_row_never_reports_a_ceiling_at_or_under_an_observed_total_as_ok() {
        for point in MEASURED_COMMIT_PEAKS {
            for ceiling in [
                point.peak_bytes,
                point.peak_bytes.saturating_sub(MIB),
                point.peak_bytes / 2,
            ] {
                let check = commit_memory_headroom_check_for(
                    &footprint(point.store_bytes),
                    &memory(ceiling),
                );
                assert!(
                    !matches!(check.status, HealthStatus::Healthy),
                    "{} at a {} ceiling against an observed total of {}: a ceiling with no room \
                     over an observation must not read ok, which is what called a 12288 MiB \
                     container fine six hours before a commit was killed at 12283 MiB",
                    point.repository,
                    format_health_bytes(ceiling),
                    format_health_bytes(point.peak_bytes)
                );
                assert!(
                    check.detail.contains(point.repository),
                    "the row has to name the observation it is judging against: {}",
                    check.detail
                );
                assert!(
                    check.manual_fix.is_some(),
                    "every warning band carries a fix the reader can act on"
                );
            }
        }
    }

    /// The row says which reading its ceiling came from.
    ///
    /// FIR-2638 shipped a probe that answered with the host figure for a process
    /// capped at twelve gigabytes and stayed silent through the kill. A row that
    /// prints a byte count without its source cannot be checked by the person it
    /// is warning, and raising a container limit is a different action from
    /// moving to a bigger host. Every band quotes the ceiling, so every band owes
    /// the provenance, not only the red one.
    ///
    /// Falsify by dropping the source from the format strings, which fails all
    /// three arms, or by hard-coding one source, which fails the other.
    #[test]
    fn the_headroom_row_names_the_reading_its_ceiling_came_from() {
        let capped = commit_memory_headroom_check_for(
            &footprint(1844 * MIB),
            &capped_memory(8 * 1024 * MIB),
        );
        assert!(
            capped.detail.contains("this container's memory cap"),
            "a capped process is owed the fact that the cap is the wall it hit: {}",
            capped.detail
        );
        let bare =
            commit_memory_headroom_check_for(&footprint(1844 * MIB), &memory(8 * 1024 * MIB));
        assert!(
            bare.detail.contains("this host's RAM"),
            "an uncapped process must not be sent to raise a limit it does not have: {}",
            bare.detail
        );
        let healthy = commit_memory_headroom_check_for(
            &footprint(922 * MIB),
            &capped_memory(64 * 1024 * MIB),
        );
        assert!(
            matches!(healthy.status, HealthStatus::Healthy),
            "the fixture must exercise the ok band: {:?}",
            healthy.status
        );
        assert!(
            healthy.detail.contains("this container's memory cap"),
            "the ok band quotes the same ceiling and owes the same provenance: {}",
            healthy.detail
        );
    }

    /// Neither warning band may report the install as broken.
    ///
    /// A headroom band names ground the host never had. It keeps the report out
    /// of `Ready`, because the row is real and the reader is entitled to see it
    /// in the roll-up, and it must never reach `Failing`, which is the verdict
    /// that says something about the install itself is wrong. Both bands are
    /// asserted here rather than trusted to the enum, because `blocks_readiness`
    /// is where that would go wrong.
    ///
    /// This used to assert `report.healthy` was true over a `Degraded` row,
    /// which is the overclaim FIR-2919 records: the aggregate said ready while
    /// the row said the machine had no measured room. The property the test was
    /// written for survives as the `Failing` assertion; the overclaim does not.
    #[test]
    fn no_commit_headroom_band_reports_the_install_as_broken() {
        for limit in [
            MEASURED_COMMIT_PEAKS[1].peak_bytes,
            12288 * MIB,
            8 * 1024 * MIB,
        ] {
            let check = commit_memory_headroom_check_for(&footprint(1844 * MIB), &memory(limit));
            assert!(
                !matches!(check.status, HealthStatus::Healthy),
                "the fixture must exercise a warning band: {:?}",
                check.status
            );
            assert!(
                !blocks_readiness(&check),
                "a small machine is not a broken install: {:?}",
                check.status
            );
            let report = assemble_health_report("test".to_string(), vec![check]);
            assert_eq!(
                report.verdict(),
                HealthVerdict::NeedsAttention,
                "a small machine needs attention and is not a broken install: {:?}",
                check_status_of(&report, "commit_memory_headroom")
            );
            assert!(
                !report.healthy(),
                "the roll-up may not claim readiness over a row that says the host has no \
                 measured room"
            );
        }
    }

    /// The status a report carries for one id, for an assertion message.
    fn check_status_of(report: &HealthReport, id: &str) -> String {
        report
            .checks
            .iter()
            .find(|check| check.id == id)
            .map(|check| format!("{:?}", check.status))
            .unwrap_or_else(|| format!("{id} absent"))
    }

    /// A machine with the headroom is told so, quoting the same measurement.
    #[test]
    fn doctor_reports_headroom_as_healthy_against_the_same_measured_peak() {
        let check =
            commit_memory_headroom_check_for(&footprint(922 * MIB), &memory(64 * 1024 * MIB));
        assert!(
            matches!(check.status, HealthStatus::Healthy),
            "64 GiB clears every measured peak: {:?}",
            check.status
        );
        assert!(check.detail.contains("psf/requests"), "{}", check.detail);
        assert!(
            check.detail.contains("clears that peak by at least"),
            "ok has to say what it cleared, or it is the rounding again: {}",
            check.detail
        );
        assert!(
            check.detail.contains("1.0x the measured one"),
            "the store ratio belongs in every band: {}",
            check.detail
        );
    }

    /// The comfort margin is read off the table, so it cannot fall behind it.
    ///
    /// The margin is the spread the table itself measures between two totals
    /// observed in the SAME machine, which is what makes it a repeatability
    /// figure and not the store-size claim FIR-2643 removed. This docstring said
    /// "a larger store peaks higher" until that sweep found it, three hundred
    /// lines from the constant whose own docstring had already been corrected,
    /// which is the shape a wrong model leaves behind: the sentence that
    /// justifies a number outlives the number's own explanation.
    ///
    /// A row measured later that spreads wider than the constant would silently
    /// shrink the amber band back toward the rounding this replaced, so the
    /// constant is held to the table rather than to a number somebody
    /// remembered.
    #[test]
    fn the_comfort_margin_covers_the_spread_the_table_shows() {
        let widest = MEASURED_COMMIT_PEAKS
            .windows(2)
            .map(|pair| {
                let (lower, higher) = (pair[0].peak_bytes, pair[1].peak_bytes);
                if higher <= lower {
                    0
                } else {
                    ((higher - lower) * 100).div_ceil(lower)
                }
            })
            .max()
            .unwrap_or(0);
        assert!(
            COMMIT_PEAK_COMFORT_MARGIN_PERCENT >= widest,
            "the table measures a {widest}% spread between adjacent peaks and the comfort margin \
             is {COMMIT_PEAK_COMFORT_MARGIN_PERCENT}%, so a store past the quoted row can peak \
             above a ceiling this check calls ok"
        );
    }

    /// The table has to be ordered and real for the lookup to mean anything.
    ///
    /// The check walks it in reverse to find the largest row a store reaches. A
    /// row inserted out of order would quote the wrong measurement without
    /// failing anything, and a zero store would divide the ratio by nothing.
    #[test]
    fn the_measured_table_is_ordered_and_carries_no_empty_rows() {
        for point in MEASURED_COMMIT_PEAKS {
            assert!(
                point.store_bytes > 0 && point.peak_bytes > 0,
                "{} carries an empty measurement",
                point.repository
            );
        }
        for pair in MEASURED_COMMIT_PEAKS.windows(2) {
            assert!(
                pair[1].store_bytes > pair[0].store_bytes,
                "the table must be smallest store first: {} is not above {}",
                pair[1].repository,
                pair[0].repository
            );
        }
    }

    /// Below the smallest measured store nothing is claimed at all.
    ///
    /// The two measured points do not scale with each other, so there is no
    /// curve to run down. A check that invented one would warn every small
    /// repository on a small machine about a cost nobody has measured there.
    #[test]
    fn doctor_makes_no_headroom_claim_about_a_store_smaller_than_any_measurement() {
        let check = commit_memory_headroom_check_for(&footprint(64 * MIB), &memory(2 * 1024 * MIB));
        assert!(
            matches!(check.status, HealthStatus::Healthy),
            "an unmeasured size is not a warning: {:?}",
            check.status
        );
        assert!(
            check.detail.contains("no headroom claim is made"),
            "silence must be stated rather than implied: {}",
            check.detail
        );
        assert!(
            !check.detail.contains("psf/requests"),
            "a measurement that does not apply must not be quoted: {}",
            check.detail
        );
    }

    /// The middle band quotes the smaller measurement, not the larger one.
    #[test]
    fn doctor_quotes_the_largest_measurement_the_store_actually_reaches() {
        let check =
            commit_memory_headroom_check_for(&footprint(500 * MIB), &memory(8 * 1024 * MIB));
        assert!(
            check.detail.contains("expressjs/express"),
            "a 500 MiB store has passed the express point and not the requests one: {}",
            check.detail
        );
        assert!(!check.detail.contains("psf/requests"), "{}", check.detail);
    }

    /// A store that could not be measured produces no verdict about it.
    #[test]
    fn doctor_reports_an_unmeasurable_store_as_unsupported_rather_than_as_healthy() {
        let unmeasured = crate::commands::store_footprint::StoreFootprint {
            store: None,
            git_objects: None,
            unmeasured_reason: Some("permission denied".to_string()),
        };
        let check = commit_memory_headroom_check_for(&unmeasured, &memory(1024 * MIB));
        assert!(
            matches!(check.status, HealthStatus::Unsupported),
            "an unread store is not a passed check: {:?}",
            check.status
        );
    }

    /// A host with no language server must be told which language lost which
    /// edge class, and told it in words rather than as a low relation count.
    /// The graph is unreadable here, which is exactly the state that used to
    /// carry its own row; folding the two rows must not lose the probe.
    #[test]
    fn doctor_names_the_language_whose_missing_server_costs_cross_file_edges() {
        let missing = missing_language_servers(
            &kin_core::reference_coverage::LanguageServerReadinessMap::new(),
        );
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

    fn census_pair(
        previous: &[(&str, u64)],
        current: &[(&str, u64)],
        causes: Vec<String>,
    ) -> kin_core::relation_census::RelationCensusComparison {
        let recorded = kin_core::relation_census::RelationCensus::new(
            chrono::Utc::now(),
            kin_core::relation_census::CensusSource::Sweep,
            previous
                .iter()
                .map(|(kind, count)| ((*kind).to_string(), *count))
                .collect(),
            Vec::new(),
        );
        kin_core::relation_census::RelationCensusComparison::build(
            &kin_core::relation_census::RelationCensusRead::Recorded(recorded),
            &current
                .iter()
                .map(|(kind, count)| ((*kind).to_string(), *count))
                .collect(),
            causes,
        )
    }

    /// The rc0545c shape, at the doctor row. A store that lost a whole relation
    /// kind must not be tallied as a pass.
    #[test]
    fn doctor_reports_a_relation_kind_that_vanished_since_the_recorded_census() {
        let check = relation_census_health(&census_pair(
            &[("Calls", 951), ("UsesType", 94)],
            &[("Calls", 940)],
            vec!["KIN_DAEMON_DISABLE_LSP set to non-default value \"1\"".to_string()],
        ));
        assert!(
            matches!(check.status, HealthStatus::Stale),
            "a lost kind needs attention: {:?}",
            check.status
        );
        assert!(
            check.detail.contains("UsesType went 94 to 0"),
            "{}",
            check.detail
        );
        assert!(
            check.detail.contains("KIN_DAEMON_DISABLE_LSP"),
            "the row carries the cause: {}",
            check.detail
        );
    }

    /// The counterpart, so the row above cannot be an unconditional warning.
    #[test]
    fn doctor_stays_green_when_no_relation_kind_lost_ground() {
        let check = relation_census_health(&census_pair(
            &[("Calls", 940), ("UsesType", 94)],
            &[("Calls", 951), ("UsesType", 94)],
            Vec::new(),
        ));
        assert!(
            matches!(check.status, HealthStatus::Healthy),
            "growth is not a loss: {:?} {}",
            check.status,
            check.detail
        );
    }

    /// The same pair as `census_pair`, with an entity count on both sides so
    /// the row can tell a store that lost edges from one that lost code.
    fn census_pair_with_entities(
        previous: &[(&str, u64)],
        previous_entities: u64,
        current: &[(&str, u64)],
        current_entities: u64,
    ) -> kin_core::relation_census::RelationCensusComparison {
        let recorded = kin_core::relation_census::RelationCensus::new(
            chrono::Utc::now(),
            kin_core::relation_census::CensusSource::Sweep,
            previous
                .iter()
                .map(|(kind, count)| ((*kind).to_string(), *count))
                .collect(),
            Vec::new(),
        )
        .with_entities(previous_entities);
        kin_core::relation_census::RelationCensusComparison::build(
            &kin_core::relation_census::RelationCensusRead::Recorded(recorded),
            &current
                .iter()
                .map(|(kind, count)| ((*kind).to_string(), *count))
                .collect(),
            Vec::new(),
        )
        .with_current_entities(current_entities)
    }

    /// The rc0547b shape, at the doctor row. Eleven call edges and one override
    /// edge gone from `psf/requests` after a docstring commit, over 783
    /// entities both times, and the row read `✓ Relation census ok`.
    #[test]
    fn doctor_reports_edges_lost_over_an_unchanged_entity_count() {
        let check = relation_census_health(&census_pair_with_entities(
            &[("Calls", 1279), ("Overrides", 11)],
            783,
            &[("Calls", 1268), ("Overrides", 10)],
            783,
        ));
        assert!(
            matches!(check.status, HealthStatus::Stale),
            "edges gone with no code removed needs attention: {:?} {}",
            check.status,
            check.detail
        );
        assert!(
            check.detail.contains("Calls slipped 1279 to 1268"),
            "the kind and both counts are named: {}",
            check.detail
        );
        assert!(
            check.detail.contains("Overrides slipped 11 to 10"),
            "and the second kind: {}",
            check.detail
        );
        assert!(
            check.detail.contains("the entity count held at 783"),
            "the row says why this is a regression rather than a deletion: {}",
            check.detail
        );
    }

    /// The counterpart, so the row above cannot be an unconditional warning on
    /// any downward movement. The same drop over a store that shrank is a
    /// store that shrank.
    #[test]
    fn doctor_stays_green_when_the_edges_left_with_their_entities() {
        let check = relation_census_health(&census_pair_with_entities(
            &[("Calls", 1279), ("Overrides", 11)],
            783,
            &[("Calls", 1268), ("Overrides", 10)],
            770,
        ));
        assert!(
            matches!(check.status, HealthStatus::Healthy),
            "a smaller store is not a regression: {:?} {}",
            check.status,
            check.detail
        );
    }

    /// A store with no baseline cannot answer the question, and must not read
    /// the same as one that kept its coverage.
    #[test]
    fn doctor_separates_a_store_with_no_recorded_census_from_a_healthy_one() {
        let check =
            relation_census_health(&kin_core::relation_census::RelationCensusComparison::build(
                &kin_core::relation_census::RelationCensusRead::Absent,
                &std::collections::BTreeMap::from([("Calls".to_string(), 940)]),
                Vec::new(),
            ));
        assert!(
            matches!(check.status, HealthStatus::Pending),
            "an unrecorded census is pending, never healthy: {:?}",
            check.status
        );
        assert!(
            check
                .detail
                .contains("no previous relation census is recorded"),
            "{}",
            check.detail
        );
    }

    /// The counterpart, so the row above cannot be an unconditional warning:
    /// with every wired language's server installed there is no gap to report.
    #[test]
    fn doctor_reports_no_gap_once_every_wired_language_server_is_installed() {
        let installed: kin_core::reference_coverage::LanguageServerReadinessMap =
            crate::commands::language_servers::language_server_binaries()
                .into_iter()
                .map(|(language, _)| {
                    (
                        language,
                        kin_core::reference_coverage::LanguageServerReadiness::Usable,
                    )
                })
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

    /// An installed server that cannot start must not be reported as a missing
    /// install, and must not be reported as fine either.
    ///
    /// This is the state a PATH lookup could not see and the reason the doctor
    /// row now probes. The dev host produced it on 2026-08-20: a
    /// typescript-language-server installed beside TypeScript 7, resolving
    /// perfectly and failing every start. Telling that operator to install what
    /// they already have sends them to the wrong repair.
    #[test]
    fn doctor_separates_a_broken_install_from_a_missing_one() {
        use kin_core::reference_coverage::{LanguageServerReadiness, LanguageServerReadinessMap};
        let mut readiness = LanguageServerReadinessMap::new();
        for (language, _) in crate::commands::language_servers::language_server_binaries() {
            readiness.insert(language, LanguageServerReadiness::Usable);
        }
        readiness.insert(
            kin_model::LanguageId::JavaScript,
            LanguageServerReadiness::Unusable {
                reason: "Could not find a valid TypeScript installation".to_string(),
            },
        );

        let missing = missing_language_servers(&readiness);
        let javascript: Vec<&String> = missing
            .iter()
            .filter(|row| row.starts_with("javascript"))
            .collect();
        assert_eq!(
            missing.len(),
            1,
            "only the broken language is reported: {missing:?}"
        );
        assert!(
            javascript[0].contains("installed but it did not start"),
            "the row must say the install is broken rather than absent: {}",
            javascript[0]
        );
        assert!(
            javascript[0].contains("Could not find a valid TypeScript installation"),
            "the row must carry the server's own reason, which names the repair: {}",
            javascript[0]
        );
    }

    /// A `Stale` row needs attention without reporting a broken install. A
    /// missing language server degrades a working install; calling it a failure
    /// would turn `kin doctor` red on every host that never installed one.
    #[test]
    fn a_missing_language_server_needs_attention_without_blocking_readiness() {
        let missing = missing_language_servers(
            &kin_core::reference_coverage::LanguageServerReadinessMap::new(),
        );
        let check = coverage_unreadable(
            HealthStatus::Unsupported,
            "no daemon running for this repository",
            "start the daemon",
            &missing,
        );
        assert!(!blocks_readiness(&check));
        let report = assemble_health_report("test".to_string(), vec![check]);
        assert_eq!(
            report.verdict(),
            HealthVerdict::NeedsAttention,
            "a host with no language server is not a broken install: {:?}",
            report.checks[0].status
        );
        assert_eq!(report.summary().attention, 1);
        assert!(
            !report.healthy(),
            "the tally says one row needs attention, so the aggregate may not say ready"
        );
    }

    /// A healthy response for the fetch tests to hand back.
    fn answered_graph_status() -> GraphStatusForRun {
        GraphStatusForRun::Answered(Box::new(crate::commands::graph::GraphCommandResponse {
            lines: vec!["graph status".to_string()],
            error: None,
            source: None,
            reference_edge_coverage: Some(
                kin_core::reference_coverage::ReferenceEdgeCoverage::default(),
            ),
            relation_census: Some(census_pair(&[], &[], Vec::new())),
            graph_section: Some(serving_section_state()),
        }))
    }

    /// A store whose persisted section answers for its base.
    fn serving_section_state() -> kin_core::graph_section::GraphSectionState {
        kin_core::graph_section::GraphSectionState {
            schema: kin_core::graph_section::GRAPH_SECTION_STATE_SCHEMA.to_string(),
            standing: kin_core::graph_section::GraphSectionStanding::Serving,
            section_present: true,
            refusal: None,
            unreadable: None,
            base_target: Some("2b".repeat(32)),
            section_resolved_at: Some("2b".repeat(32)),
            changes_in_store: 3005,
            fold: kin_core::graph_section::FoldSize::Nothing,
            prepared_may_preempt: false,
        }
    }

    /// The same store with no section, which is every store written before v14.
    fn folding_section_state() -> kin_core::graph_section::GraphSectionState {
        kin_core::graph_section::GraphSectionState {
            schema: kin_core::graph_section::GRAPH_SECTION_STATE_SCHEMA.to_string(),
            standing: kin_core::graph_section::GraphSectionStanding::Folding,
            section_present: false,
            refusal: Some("absent".to_string()),
            unreadable: None,
            base_target: Some("2b".repeat(32)),
            section_resolved_at: None,
            changes_in_store: 3005,
            fold: kin_core::graph_section::FoldSize::Exact(3005),
            prepared_may_preempt: false,
        }
    }

    /// FIR-2560. One `graph status` per doctor run, however many rows read it.
    ///
    /// `kin graph status` is the slowest surface Kin has on a real store, and it
    /// was fetched per row: FIR-2416 measured 31.812 s on the rc0545c
    /// psf/requests store against 0.091 s on express, so a second fetch does not
    /// cost a little more, it roughly doubles the wall time of a doctor run on
    /// exactly the stores where an operator is most likely to be running doctor.
    /// Three consumers here rather than the two the tree holds today, because the
    /// cost this pins is the one a fourth row would add.
    #[tokio::test]
    async fn one_doctor_run_fetches_graph_status_once_however_many_rows_read_it() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let fetches = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&fetches);
        let status = RunGraphStatus::with_fetch(move || {
            let counted = Arc::clone(&counted);
            Box::pin(async move {
                counted.fetch_add(1, Ordering::SeqCst);
                answered_graph_status()
            })
        });

        assert_eq!(
            fetches.load(Ordering::SeqCst),
            0,
            "the fetch is lazy, so a run whose rows never read graph truth pays nothing"
        );

        let mut seen = Vec::new();
        for _ in 0..3 {
            seen.push(format!("{:?}", status.get().await));
        }

        assert_eq!(
            fetches.load(Ordering::SeqCst),
            1,
            "three rows reading graph status must cost one daemon round trip, not three"
        );
        assert_eq!(
            seen.iter().collect::<std::collections::BTreeSet<_>>().len(),
            1,
            "and every row must see the same answer: {seen:?}"
        );
    }

    /// The property the shared fetch must not cost. A graph the run could not
    /// read reaches the row as its own unreadable state, rather than being
    /// reported once by the fetch and leaving the row silent.
    ///
    /// A row that goes quiet when the graph is unreadable is indistinguishable
    /// from one reporting a healthy graph, which is the failure the row exists to
    /// end. So each cause is checked for a status that is not healthy and for
    /// words naming what happened.
    #[test]
    fn an_unreadable_graph_reaches_the_row_rather_than_being_reported_once() {
        let no_servers: Vec<String> = Vec::new();

        let unreadable = [
            (
                GraphStatusForRun::NotInRepository,
                "not in a Kin repository",
            ),
            (
                GraphStatusForRun::NoDaemon,
                "no daemon running for this repository",
            ),
            (
                GraphStatusForRun::DaemonUrlInvalid {
                    daemon_url: "http://127.0.0.1:0".to_string(),
                    error: "invalid port".to_string(),
                },
                "its URL is invalid",
            ),
            (
                GraphStatusForRun::Unavailable {
                    daemon_url: "http://127.0.0.1:4242".to_string(),
                    error: "connection refused".to_string(),
                },
                "unavailable",
            ),
        ];
        for (status, expected) in unreadable {
            let coverage_row = coverage_row_for_unread_graph(&status, &no_servers)
                .expect_err("an unread graph must produce a row rather than a response");
            let census_row = relation_census_row_for_unread_graph(&status)
                .expect_err("an unread graph must reach the census row too");
            for row in [coverage_row, census_row] {
                assert!(
                    !matches!(row.status, HealthStatus::Healthy),
                    "an unread graph must never render as healthy: {status:?} gave {:?}",
                    row.status
                );
                assert!(
                    row.detail.contains(expected),
                    "the row must name what happened: {status:?} gave {}",
                    row.detail
                );
            }
        }

        // And the readable case still yields the response, or the four arms
        // above would be the only outcome and the row could never report a
        // measurement.
        assert!(
            coverage_row_for_unread_graph(&answered_graph_status(), &no_servers).is_ok(),
            "a graph the run did read must hand its response to the coverage row"
        );
        assert!(
            relation_census_row_for_unread_graph(&answered_graph_status()).is_ok(),
            "a graph the run did read must hand its response to the census row"
        );
    }

    /// A store that folds its whole history at every open is completely correct
    /// and materially slower than it needs to be, and doctor has to say the
    /// second without claiming the first. `Degraded` costs the report its
    /// all-clear and nothing else; `Missing` or `Misconfigured` would fail a
    /// report about a store answering every question correctly.
    #[test]
    fn a_folding_store_loses_the_all_clear_without_failing_the_report() {
        let row = graph_section_health(&folding_section_state());
        assert!(
            matches!(row.status, HealthStatus::Stale),
            "a folding store's acceleration is out of date, not broken, and not a host limit: \
             {:?}",
            row.status
        );
        assert!(
            !matches!(row.status, HealthStatus::Degraded),
            "`Degraded` is the host-shortfall status, and `setup.rs` prints `Degraded rows are \
             host limits`; a store that one `kin graph materialize` fixes is not a host limit"
        );
        assert!(
            !blocks_readiness(&row),
            "a correct store must never fail the readiness verdict: {:?}",
            row.status
        );
        assert!(
            needs_attention(&row),
            "a 47 second fold at every open must withhold the all-clear"
        );
        assert!(
            row.detail.contains("folds"),
            "the row must say what the store does: {}",
            row.detail
        );
        assert!(
            row.detail.contains("3005"),
            "the row must name the size of the fold: {}",
            row.detail
        );
        assert!(
            row.manual_fix
                .as_deref()
                .is_some_and(|fix| fix.contains("kin graph materialize")),
            "a reported cost with no named fix is a nag: {:?}",
            row.manual_fix
        );
    }

    /// The control for the row above. A store whose section answers is healthy
    /// and offers no repair, or the row would report every store as needing one
    /// and could never distinguish the two.
    #[test]
    fn a_store_whose_section_answers_reads_healthy_with_nothing_to_fix() {
        let row = graph_section_health(&serving_section_state());
        assert!(
            matches!(row.status, HealthStatus::Healthy),
            "a served base is healthy: {:?}",
            row.status
        );
        assert!(!needs_attention(&row));
        assert_eq!(row.manual_fix, None, "there is nothing to repair");
        assert!(
            row.detail.contains("folds nothing"),
            "the row must say the fold did not run: {}",
            row.detail
        );
    }

    /// A state doctor could not read is not a state that is fine. Rendering it
    /// as healthy is the invisibility this row replaces, restated one layer up.
    #[test]
    fn a_section_state_that_could_not_be_read_is_never_healthy() {
        let mut state = folding_section_state();
        state.standing = kin_core::graph_section::GraphSectionStanding::Unknown;
        state.unreadable = Some("this authority holds no workspace 0".to_string());
        let row = graph_section_health(&state);
        assert!(
            !matches!(row.status, HealthStatus::Healthy),
            "an unread state must never render as healthy: {:?}",
            row.status
        );
        assert!(row.detail.contains("could not be read"), "{}", row.detail);
    }

    /// This row's own four unreadable arms. Shared wording would let one row go
    /// quiet about a graph another row could not read, and a row that goes quiet
    /// is indistinguishable from one reporting a healthy store.
    #[test]
    fn an_unread_graph_reaches_the_graph_section_row_in_its_own_words() {
        let unreadable = [
            (
                GraphStatusForRun::NotInRepository,
                "not in a Kin repository",
            ),
            (GraphStatusForRun::NoDaemon, "no daemon is serving"),
            (
                GraphStatusForRun::DaemonUrlInvalid {
                    daemon_url: "http://127.0.0.1:0".to_string(),
                    error: "invalid port".to_string(),
                },
                "its URL is invalid",
            ),
            (
                GraphStatusForRun::Unavailable {
                    daemon_url: "http://127.0.0.1:4242".to_string(),
                    error: "connection refused".to_string(),
                },
                "unavailable",
            ),
        ];
        for (status, expected) in unreadable {
            let row = graph_section_row_for_unread_graph(&status)
                .expect_err("an unread graph must produce a row rather than a response");
            assert!(
                !matches!(row.status, HealthStatus::Healthy),
                "an unread graph must never render as healthy: {status:?} gave {:?}",
                row.status
            );
            assert!(
                row.detail.contains(expected),
                "the row must name what happened: {status:?} gave {}",
                row.detail
            );
        }
        assert!(
            graph_section_row_for_unread_graph(&answered_graph_status()).is_ok(),
            "a graph the run did read must hand its response to this row"
        );
    }

    /// A daemon built before this measurement existed sends no section state,
    /// and the absence must read as a stale daemon rather than as a store with
    /// nothing to report.
    #[tokio::test]
    async fn a_daemon_that_reports_no_section_state_reads_stale_rather_than_healthy() {
        let older = RunGraphStatus::with_fetch(|| {
            Box::pin(async {
                GraphStatusForRun::Answered(Box::new(
                    crate::commands::graph::GraphCommandResponse {
                        lines: vec!["graph status".to_string()],
                        error: None,
                        source: None,
                        reference_edge_coverage: None,
                        relation_census: None,
                        graph_section: None,
                    },
                ))
            })
        });
        let row = check_graph_section(&older).await;
        assert!(
            matches!(row.status, HealthStatus::Stale),
            "an older daemon is stale, not healthy: {:?}",
            row.status
        );
        assert!(
            row.manual_fix
                .as_deref()
                .is_some_and(|fix| fix.contains("kin daemon stop")),
            "the row must name how to get a daemon that reports it: {:?}",
            row.manual_fix
        );

        // The control: a daemon that DOES report it reaches the measurement,
        // or the arm above would be the only outcome this row can produce.
        let current = RunGraphStatus::with_fetch(|| Box::pin(async { answered_graph_status() }));
        let row = check_graph_section(&current).await;
        assert!(
            matches!(row.status, HealthStatus::Healthy),
            "a reported serving section reads healthy: {:?}",
            row.status
        );
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
            parse: None,
            languages: vec![LanguageReferenceCoverage {
                language: "python".to_string(),
                files: 12,
                files_measured: 12,
                entities: 46,
                parsed_call_sites: Some(78),
                call_sites_measured_files: 12,
                parsed_import_statements: Some(16),
                resolved_call_edges: 16,
                resolved_import_statements: Some(0),
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

    /// The failing-admission shape at the `kin doctor` surface. No pass is
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
        projection_mode_check_for(report, "macos", &not_probed(), &no_hook())
    }

    /// The neutral probe: no shim injected into this process, so nothing
    /// outside the repository was read. Every fixture that predates the probe
    /// uses it, which keeps their meaning exactly what it was.
    fn not_probed() -> OutsideRepoProbe {
        OutsideRepoProbe::NotTaken("fixture: no probe taken".to_string())
    }

    /// No shell hook in this shell. Every fixture that predates FIR-2501 uses
    /// it, which keeps their meaning exactly what it was: a container or an
    /// editor terminal, where nothing is injected into anything.
    fn no_hook() -> ShellHook {
        ShellHook::Withheld("fixture: no hook is live in this shell".to_string())
    }

    /// Kin's own shell hook, live in this shell: every process it starts except
    /// the `kin` control plane is launched under the shim.
    fn hook_live() -> ShellHook {
        ShellHook::Live("fixture: the hook is live in this shell".to_string())
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

    /// The same fixture shaped like a real Windows host: the probes are the
    /// two modes `fallback_order("windows")` returns, so there is a projfs row
    /// carrying the `Enable-WindowsOptionalFeature` remedy and no shim row at
    /// all. `report` above builds the Unix three, and a Windows assertion made
    /// against those probes would be asserting about a machine that cannot
    /// exist.
    fn windows_report(
        recorded: Option<ProjectionMode>,
        available: &[ProjectionMode],
        live: LiveProjection,
    ) -> ProjectionReport {
        ProjectionReport {
            recorded,
            modes: [ProjectionMode::ProjFs, ProjectionMode::Nfs]
                .into_iter()
                .map(|mode| mode_probe(mode, available.contains(&mode)))
                .collect(),
            driver: DriverProbe {
                path: None,
                refusal: None,
                subcommands: None,
            },
            shim: ShimPresence {
                path: PathBuf::from("C:/Users/u/.kin/lib/kin_vfs_shim.dll"),
                installed: false,
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
            unengaged_here_only: false,
            evidence: vec!["fixture evidence".to_string()],
        }
    }

    /// FIR-2572. A green projection row still names what its mode cannot do.
    ///
    /// The shim interposes libc, so a binary that never calls libc reads the
    /// working copy while everything else reads graph truth, and that stays
    /// true of a shim passing every probe this row takes. `kin vfs status`
    /// said so and `kin doctor` did not, so a reader who ran doctor, saw a
    /// green projection and stopped had no way to learn the limit existed.
    ///
    /// The note rides `platform_note`, so it must not move the status: a limit
    /// that belongs to the mode is not a defect in the install, and a row that
    /// went red over one would fail every correct shim install.
    #[test]
    fn a_green_shim_row_names_the_limit_and_a_green_mount_row_has_none() {
        let shim = projection_mode_check_for_macos(&report(
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
            matches!(shim.status, HealthStatus::Healthy),
            "naming the limit must not move the status, got {:?}",
            shim.status
        );
        assert!(
            !blocks_readiness(&shim),
            "a mode's limit must never block readiness"
        );
        let note = shim
            .platform_note
            .as_deref()
            .expect("a green shim row carries the shim's limit");
        assert!(
            note.contains("libc") && note.contains("Go"),
            "the limit must name what it is about: {note}"
        );
        assert!(
            !note.contains("Node is not projected"),
            "Node is projected under the shim since FIR-2572: {note}"
        );

        // The control. A mount is served by the kernel and has no such limit,
        // so an unconditional note would be a false warning on every mount
        // host and this assertion is what keeps the note attached to the mode
        // rather than to the row.
        let mount = projection_mode_check_for_macos(&report(
            Some(ProjectionMode::Nfs),
            &[ProjectionMode::Nfs],
            live(
                ProjectionMode::Nfs,
                ProjectionMode::Nfs,
                Tri::Yes,
                Tri::Yes,
                false,
            ),
        ));
        assert!(
            matches!(mount.status, HealthStatus::Healthy),
            "the mount fixture must be green for this control to mean anything, got {:?}",
            mount.status
        );
        assert_eq!(
            mount.platform_note, None,
            "a mount projects every process on the host and must carry no such limit"
        );
    }

    /// The machine FIR-2501 is about: a shim installed and working, in a shell
    /// running Kin's own hook, so every probe passed except the one asking
    /// whether THIS process is injected, which is the one the hook's `kin`
    /// wrapper guarantees a no to, on purpose and permanently.
    fn correctly_hooked_report() -> ProjectionReport {
        let mut report = report(
            Some(ProjectionMode::Shim),
            &[ProjectionMode::Shim],
            live(
                ProjectionMode::Shim,
                ProjectionMode::Shim,
                Tri::NotApplicable,
                Tri::Yes,
                true,
            ),
        );
        report.live.unengaged_here_only = true;
        report
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

    /// A shim installed and not injected, in a shell with NO hook, is the
    /// container case. It must be visible and must not be healthy, and it must
    /// not fail readiness either: running `kin` from an editor terminal without
    /// the shell hook is ordinary and would otherwise fail every install that
    /// works.
    ///
    /// This test used to make the same assertion with no hook input at all,
    /// which is what let FIR-2501 through: it pinned STALE to "this process is
    /// not injected" and so pinned it to the one state Kin's own hook creates on
    /// purpose. The container is still real and still STALE; the hook fact is
    /// now stated rather than assumed, and its opposite is asserted in
    /// [`a_live_shell_hook_makes_the_projection_row_green`].
    #[test]
    fn an_installed_but_unengaged_shim_is_visible_without_failing_readiness() {
        let container = report(
            None,
            &[ProjectionMode::Shim],
            live(
                ProjectionMode::Shim,
                ProjectionMode::Shim,
                Tri::NotApplicable,
                Tri::Yes,
                true,
            ),
        );
        let check = projection_mode_check_for(&container, "macos", &not_probed(), &no_hook());
        assert!(
            matches!(check.status, HealthStatus::Stale),
            "an unengaged shim in a shell with no hook is advisory, got {:?}",
            check.status
        );
        assert!(!matches!(check.status, HealthStatus::Healthy));
        assert!(!is_failing(&check.status));
        assert!(
            check
                .manual_fix
                .as_deref()
                .is_some_and(|fix| fix.contains("new interactive shell")),
            "the fix must still point at a new shell, and say which kind: {check:?}"
        );
        assert!(
            check.detail.contains("no hook is live in this shell"),
            "the row must name what the hook did, which is what tells this apart from a machine \
             whose hook is working: {}",
            check.detail
        );
    }

    /// FIR-2501, in both directions, over one fixture with one fact flipped.
    ///
    /// The defect was a row that measured whether the shim was preloaded into
    /// `kin doctor`, the one process Kin's hook exists to keep unshimmed, then
    /// called a correct install STALE and printed a fix that could not work. A
    /// STALE row denies "First-run ready" since FIR-2547, so this was every
    /// correctly hook-installed machine.
    #[test]
    fn a_live_shell_hook_makes_the_projection_row_green() {
        let hooked = correctly_hooked_report();

        let green = projection_mode_check_for(&hooked, "macos", &not_probed(), &hook_live());
        assert!(
            matches!(green.status, HealthStatus::Healthy),
            "a shim installed, working, and injected by a live hook into everything but `kin` \
             itself is a healthy projection, got {:?}: {}",
            green.status,
            green.detail
        );
        assert!(
            green.manual_fix.is_none(),
            "a green row must not ask for a repair: {green:?}"
        );
        assert!(
            !green.fixable,
            "there is no --fix repair for this row, and claiming one loops (FIR-1880)"
        );

        // The detail must not claim the doctor process is shimmed. It must say
        // the opposite, and say that it is correct.
        assert!(
            green
                .detail
                .contains("IS injected into the processes this shell starts")
                && green
                    .detail
                    .contains("correctly NOT injected into `kin` itself"),
            "the green detail must say plainly which processes are injected and which are not: {}",
            green.detail
        );
        // And it must keep the machine row intact, degraded and all, because
        // `LiveProjection::degraded` is deliberately unchanged: it answers for
        // the process asking, and `kin vfs status` is right to keep saying so.
        assert!(
            green.detail.contains("mode=shim") && green.detail.contains("degraded=yes"),
            "the row shape must survive the new status: {}",
            green.detail
        );

        // The other direction, same fixture, one fact flipped: no hook, so
        // nothing in this shell is injected and the row is advisory again.
        let stale = projection_mode_check_for(&hooked, "macos", &not_probed(), &no_hook());
        assert!(
            matches!(stale.status, HealthStatus::Stale),
            "without a hook the same machine is not projecting anything, got {:?}",
            stale.status
        );
        assert_ne!(
            green.detail, stale.detail,
            "the two readings must not print the same sentence"
        );
        assert!(
            stale
                .manual_fix
                .as_deref()
                .is_some_and(|fix| fix.contains("new interactive shell")),
            "the no-hook fix is still the shell, and it is still the right one: {stale:?}"
        );
    }

    /// Outside a Kin repository there is no graph-backed root for a live hook
    /// to project. That is expected context, not a stale install.
    #[test]
    fn a_live_hook_outside_a_repository_is_not_an_attention_row() {
        let mut unbound = correctly_hooked_report();
        unbound.live.unengaged_here_only = false;

        let outside = projection_mode_check_for_context(
            &unbound,
            "macos",
            &not_probed(),
            &hook_live(),
            false,
        );
        assert!(
            matches!(outside.status, HealthStatus::Unsupported),
            "outside a repository no projection can be in force, got {:?}: {}",
            outside.status,
            outside.detail
        );
        assert!(!needs_attention(&outside));
        assert!(outside.detail.contains("not inside a Kin repository"));

        // The falsification control: the same probe from inside a repository
        // is still stale because its bound root is not serving this process.
        let inside =
            projection_mode_check_for_context(&unbound, "macos", &not_probed(), &hook_live(), true);
        assert!(matches!(inside.status, HealthStatus::Stale));
        assert!(needs_attention(&inside));
    }

    /// The negative controls for the green above. Each one removes a single
    /// condition from a machine that would otherwise read healthy, and each must
    /// take the row off green: a hook switched off, a projection that is broken
    /// for the processes the shim IS injected into (FIR-2552), and a shim the
    /// loader cannot use (FIR-2394).
    #[test]
    fn the_green_hook_row_is_withheld_the_moment_any_condition_fails() {
        let hooked = correctly_hooked_report();
        assert!(matches!(
            projection_mode_check_for(&hooked, "macos", &not_probed(), &hook_live()).status,
            HealthStatus::Healthy
        ));

        // The kill switch, as the hook itself reads it. This is what
        // `KIN_VFS_DISABLE=1` produces, and it must never read green.
        let disabled = shell_hook_from(ShellHookFacts {
            shell: "zsh",
            hook_path: Path::new("/home/u/.kin/shell/kin-vfs.zsh"),
            installed: true,
            current: true,
            sourced: true,
            shim: ShimState::Valid(4096),
            disable: Some("1".to_string()),
            bound_root: Some("/w/repo".to_string()),
        });
        assert!(
            !disabled.is_live(),
            "KIN_VFS_DISABLE is the hook's own kill switch: {disabled:?}"
        );
        let killed = projection_mode_check_for(&hooked, "macos", &not_probed(), &disabled);
        assert!(
            !matches!(killed.status, HealthStatus::Healthy),
            "a shell with the projection switched off has no projection in force, got {:?}",
            killed.status
        );

        // FIR-2552, at this row: a live hook over a projection that is broken
        // for every process the shim IS injected into. `unengaged_here_only` is
        // the projection's own verdict with the engagement question answered
        // yes, and a false one means the failure is not about this process.
        let mut unserved = correctly_hooked_report();
        unserved.live.unengaged_here_only = false;
        let check = projection_mode_check_for(&unserved, "macos", &not_probed(), &hook_live());
        assert!(
            !matches!(check.status, HealthStatus::Healthy),
            "a bound root nothing serves is not a healthy projection however good the hook is, \
             got {:?}",
            check.status
        );
        assert!(
            check
                .manual_fix
                .as_deref()
                .is_some_and(|fix| fix.contains("kin vfs status") && !fix.contains("kin doctor")),
            "with the hook already live, the fix must name the projection and not another shell, \
             and must never name `kin doctor --fix` (FIR-2435): {check:?}"
        );

        // FIR-2394: an installed shim no probe can use must not borrow the
        // softer status, and must not borrow the green one either.
        let mut dead = correctly_hooked_report();
        dead.modes = dead
            .modes
            .iter()
            .map(|probe| ModeProbe {
                available: probe.mode != ProjectionMode::Shim && probe.available,
                ..probe.clone()
            })
            .collect();
        assert!(dead.shim.installed);
        let check = projection_mode_check_for(&dead, "macos", &not_probed(), &hook_live());
        assert!(
            is_failing(&check.status),
            "an installed shim the loader will not run must still fail, got {:?}",
            check.status
        );
    }

    /// The hook verdict itself, over probed facts alone, in every direction it
    /// can be decided.
    #[test]
    fn the_shell_hook_verdict_reads_the_facts_the_kin_wrapper_cannot_strip() {
        let facts = |installed, current, sourced, shim, bound_root: Option<&str>| ShellHookFacts {
            shell: "bash",
            hook_path: Path::new("/home/u/.kin/shell/kin-vfs.bash"),
            installed,
            current,
            sourced,
            shim,
            disable: None,
            bound_root: bound_root.map(ToOwned::to_owned),
        };

        // A bound root is the measurement: the hook's activate path exports
        // KIN_VFS_WORKSPACE and the preload from the same branch, and the `kin`
        // wrapper clears only the preload. So the variable that survives is a
        // witness to the one that did not, and currency is not needed for it.
        let measured = shell_hook_from(facts(
            true,
            false,
            false,
            ShimState::Valid(4096),
            Some("/w/repo"),
        ));
        assert!(
            measured.is_live(),
            "a bound projection root proves the hook ran in this shell: {measured:?}"
        );
        assert!(
            measured.evidence().contains("/w/repo"),
            "the verdict must name the root it read: {measured:?}"
        );

        // With no witness, the file and the rc line are the evidence, and both
        // are required. Outside a repository the hook stands down by design, so
        // this arm must not go red on a machine that is simply not in a repo.
        assert!(shell_hook_from(facts(true, true, true, ShimState::Valid(4096), None)).is_live());
        assert!(!shell_hook_from(facts(true, true, false, ShimState::Valid(4096), None)).is_live());
        assert!(!shell_hook_from(facts(true, false, true, ShimState::Valid(4096), None)).is_live());
        assert!(!shell_hook_from(facts(false, true, true, ShimState::Valid(4096), None)).is_live());

        // The shim decides before the hook does, because the hook tests the
        // library before exporting anything and clears the preload when the test
        // fails. A witness cannot rescue a shim that is not there.
        for shim in [ShimState::Missing, ShimState::Empty, ShimState::Invalid] {
            let verdict = shell_hook_from(facts(true, true, true, shim, Some("/w/repo")));
            assert!(
                !verdict.is_live(),
                "the hook injects nothing over an unusable shim: {verdict:?}"
            );
        }

        // The kill switch, in every spelling all three hooks accept, and the
        // controls that must NOT switch it off.
        for on in ["1", "true", "TRUE", "Yes", "on", " on "] {
            assert!(vfs_disabled_by(on), "{on:?} switches the hook off");
        }
        for off in ["", "0", "false", "no", "off", "2", "onward"] {
            assert!(
                !vfs_disabled_by(off),
                "{off:?} does not switch the hook off"
            );
        }
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
            let check = projection_mode_check_for(&bare, os, &not_probed(), &no_hook());
            assert!(
                matches!(check.status, HealthStatus::Unsupported),
                "{os} keeps the sanctioned skip, got {:?}",
                check.status
            );
            assert!(!is_failing(&check.status));
        }

        // Windows keeps no sanctioned absence, and what proves it moved. It
        // used to be the status: the row read `misconfigured` there, which
        // FIR-2460 removed, because a status is the wrong place to carry "you
        // could enable something" and reporting a defect against a mode nobody
        // chose is what made every fresh native Windows install read a fault
        // in `kin doctor`. What the row must never do is tell a Windows user
        // that nothing is missing, and that obligation now lives where it
        // always belonged, in the text. So the assertion is that the row names
        // the ProjFS remedy a user can paste, on the real Windows probes
        // rather than on the Unix three.
        let windows_off = windows_report(
            None,
            &[],
            live(
                ProjectionMode::ProjFs,
                ProjectionMode::ProjFs,
                Tri::No,
                Tri::No,
                true,
            ),
        );
        let windows = projection_mode_check_for(&windows_off, "windows", &not_probed(), &no_hook());
        assert!(
            !is_failing(&windows.status),
            "a mode nobody chose is not a defect, got {:?}",
            windows.status
        );
        assert!(
            windows.detail.contains("nothing is engageable yet")
                && windows.detail.contains("fixture remedy for projfs"),
            "Windows must be told what it can still enable: {}",
            windows.detail
        );
        // Falsification for the line above: strip every remedy the probes
        // carry and the row can no longer name one, so the assertion is about
        // the remedy reaching the text and not about the phrasing around it.
        let mut remedyless = windows_off.clone();
        for probe in &mut remedyless.modes {
            probe.remedy = None;
        }
        let bare_windows =
            projection_mode_check_for(&remedyless, "windows", &not_probed(), &no_hook());
        assert!(
            !bare_windows.detail.contains("fixture remedy for projfs"),
            "the remedy must come from the probes: {}",
            bare_windows.detail
        );
    }

    /// FIR-2460, taken from the release run the Windows install-proof leg
    /// failed on. Nothing is recorded, because setup records only a mode that
    /// is in force by installation alone and Windows has no shim to install.
    /// Nothing is mounted, because nobody ran `kin vfs on`. The chooser still
    /// names projfs, since it is what this host could run, and the row used to
    /// report that guess as `misconfigured`. A fault the reader did not cause
    /// and cannot act on is not a diagnosis, and `kin setup` printed the
    /// opposite about the same probe one screen earlier.
    #[test]
    fn nothing_recorded_and_nothing_in_force_is_not_a_misconfiguration() {
        let fresh = windows_report(
            None,
            &[ProjectionMode::ProjFs],
            live(
                ProjectionMode::ProjFs,
                ProjectionMode::ProjFs,
                Tri::No,
                Tri::No,
                true,
            ),
        );
        let check = projection_mode_check_for(&fresh, "windows", &not_probed(), &no_hook());
        assert!(
            matches!(check.status, HealthStatus::Unsupported),
            "an unconfigured host has no projection in force to report on, got {:?}",
            check.status
        );
        assert!(!is_failing(&check.status));
        assert!(
            check.detail.contains("projfs is available here")
                && check.detail.contains("kin vfs on --mode projfs"),
            "the row must name the mode and the command that engages it: {}",
            check.detail
        );

        // The control that keeps this row worth reading. Record the same mode
        // and change nothing else: it is now a projection somebody configured
        // that is not running, which is the one state this row exists to
        // report, and it must still fail.
        let mut recorded = fresh.clone();
        recorded.recorded = Some(ProjectionMode::ProjFs);
        let configured = projection_mode_check_for(&recorded, "windows", &not_probed(), &no_hook());
        assert!(
            matches!(configured.status, HealthStatus::Misconfigured),
            "a recorded mode that is not running must still fail, got {:?}",
            configured.status
        );
        assert!(
            configured
                .detail
                .contains("is recorded but is not what is running"),
            "the failing row must say what it is failing about: {}",
            configured.detail
        );

        // Not a Windows special case. macOS reaches the same state whenever the
        // chooser prefers a mount mode and no shim was installed to record
        // instead, which is the combination that failed the v0.5.41 release
        // install proof on all three non-Linux legs.
        let mac_fresh = report(
            None,
            &[ProjectionMode::Nfs],
            live(
                ProjectionMode::Nfs,
                ProjectionMode::Nfs,
                Tri::No,
                Tri::No,
                true,
            ),
        );
        let mac = projection_mode_check_for(&mac_fresh, "macos", &not_probed(), &no_hook());
        assert!(
            !is_failing(&mac.status),
            "the same unconfigured state is not a defect on macOS either, got {:?}",
            mac.status
        );
        assert!(
            mac.detail.contains("nfs is available here"),
            "the macOS row names its own mode: {}",
            mac.detail
        );
    }

    /// FIR-2554, stated as the stranger found it. Every probe the row takes
    /// inside the repository is green, the shim is engaged, nothing reads
    /// degraded, and in that same shell `git status` exits 128 because the shim
    /// answers an error for `$HOME/.config/git/config`. The row must not be
    /// healthy on evidence it never gathered.
    #[test]
    fn a_shim_that_fails_outside_the_repository_cannot_read_healthy() {
        let mut healthy = report(
            Some(ProjectionMode::Shim),
            &[ProjectionMode::Shim],
            live(
                ProjectionMode::Shim,
                ProjectionMode::Shim,
                Tri::NotApplicable,
                Tri::Yes,
                false,
            ),
        );
        healthy.shim.engaged = true;

        // The control first: with the same report and no failing probe, this
        // row is green. That is what makes the assertion below about the probe
        // rather than about the fixture.
        let green = projection_mode_check_for(&healthy, "macos", &not_probed(), &no_hook());
        assert!(
            matches!(green.status, HealthStatus::Healthy),
            "the fixture must be green without a failing probe, got {:?}",
            green.status
        );

        let broken = OutsideRepoProbe::Broken(
            "stat of /home/dev/.bashrc through the shim failed: Input/output error (os error 5)"
                .to_string(),
        );
        let check = projection_mode_check_for(&healthy, "macos", &broken, &no_hook());
        assert!(
            is_failing(&check.status),
            "a shim that cannot serve paths outside the repository must fail this row, got {:?}",
            check.status
        );
        assert!(
            check.detail.contains("Input/output error"),
            "the row must carry the cause the probe reported: {}",
            check.detail
        );
        assert!(
            check.detail.contains("$HOME/.config/git/config"),
            "the row must name why this breaks git: {}",
            check.detail
        );
        assert!(
            check
                .manual_fix
                .as_deref()
                .is_some_and(|fix| fix.contains("kin vfs off")),
            "the row must offer a way out: {check:?}"
        );
    }

    /// The other direction, which the ticket names as its positive control: a
    /// working shim on a working host still reaches green. A fix that made this
    /// row permanently pessimistic would have traded a false green for a false
    /// red, and this is the test that would not let it.
    #[test]
    fn a_shim_that_serves_outside_the_repository_still_reads_healthy() {
        let mut healthy = report(
            Some(ProjectionMode::Shim),
            &[ProjectionMode::Shim],
            live(
                ProjectionMode::Shim,
                ProjectionMode::Shim,
                Tri::NotApplicable,
                Tri::Yes,
                false,
            ),
        );
        healthy.shim.engaged = true;
        let served = OutsideRepoProbe::Served(
            "read /home/dev and stat of /home/dev/.bashrc through the \
                                     shim succeeded"
                .to_string(),
        );
        let check = projection_mode_check_for(&healthy, "macos", &served, &no_hook());
        assert!(
            matches!(check.status, HealthStatus::Healthy),
            "a shim that serves outside the repository is healthy, got {:?}",
            check.status
        );
        assert!(
            check.detail.contains("through the shim succeeded"),
            "a green row names the probe it rests on: {}",
            check.detail
        );
    }

    /// The probe itself, driven through every branch it has. A verdict set
    /// nobody has proven reachable is a set of branches rather than a set of
    /// verdicts, so each one is produced here from a real directory.
    #[test]
    fn the_outside_repository_probe_reaches_every_verdict() {
        let dir = tempfile::tempdir().unwrap();

        // Not engaged: nothing is taken, whatever the home holds.
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join(".bashrc"), "").unwrap();
        assert!(matches!(
            probe_outside_repo(Some(&home), false),
            OutsideRepoProbe::NotTaken(_)
        ));

        // Engaged over a home with something in it: a real read and a real stat.
        match probe_outside_repo(Some(&home), true) {
            OutsideRepoProbe::Served(evidence) => {
                assert!(evidence.contains(".bashrc"), "{evidence}");
            }
            other => panic!("a readable home must serve: {other:?}"),
        }

        // Engaged over a home that cannot be read at all: the failing verdict,
        // which is the one the whole check exists for.
        let gone = dir.path().join("no-such-home");
        match probe_outside_repo(Some(&gone), true) {
            OutsideRepoProbe::Broken(evidence) => {
                assert!(evidence.contains("no-such-home"), "{evidence}");
            }
            other => panic!("an unreadable home must be broken: {other:?}"),
        }

        // Engaged over an empty home: nothing was read, so nothing is claimed.
        // Reporting this as Served would make the check unable to fail on a
        // machine whose home directory happens to be empty.
        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(matches!(
            probe_outside_repo(Some(&empty), true),
            OutsideRepoProbe::NotTaken(_)
        ));

        // Engaged over a home whose only entries are dangling symlinks. This is
        // the false-red case: `metadata` follows the link, finds nothing, and
        // would report a perfectly healthy machine as a broken projection. The
        // probe stats the link itself, so the home still serves.
        #[cfg(unix)]
        {
            let dangling = dir.path().join("dangling-home");
            std::fs::create_dir_all(&dangling).unwrap();
            std::os::unix::fs::symlink(
                dir.path().join("target-that-is-not-there"),
                dangling.join(".broken-link"),
            )
            .unwrap();
            match probe_outside_repo(Some(&dangling), true) {
                OutsideRepoProbe::Served(evidence) => {
                    assert!(evidence.contains(".broken-link"), "{evidence}");
                }
                other => panic!("a dangling symlink is not a broken projection: {other:?}"),
            }
        }

        // The racing entry, which no fixture can stage: an entry that read_dir
        // returned and lstat then could not find. It must not be blamed on the
        // projection, while every other error must be.
        assert!(!stat_failure_blames_the_projection(
            std::io::ErrorKind::NotFound
        ));
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::Other,
            std::io::ErrorKind::InvalidInput,
        ] {
            assert!(
                stat_failure_blames_the_projection(kind),
                "{kind:?} is the projection answering and must fail the row"
            );
        }

        // No home resolvable: a reason not to probe, not a defect.
        assert!(matches!(
            probe_outside_repo(None, true),
            OutsideRepoProbe::NotTaken(_)
        ));
    }

    /// The STALE fix line is the delivery mechanism FIR-2554 describes: it is
    /// what walks a user into the shell where git does not run. It must not
    /// name a login shell, which does not engage the hook on a stock Debian
    /// `~/.bashrc`, and it must ask for the check rather than promise the
    /// result.
    ///
    /// It is asserted against a shell with NO hook, which is the only shell that
    /// line is true of. It used to be asserted with no hook input at all, which
    /// is how it came to be printed at users whose hook was already live and for
    /// whom no new shell could ever move the row (FIR-2501). The second half of
    /// this test is that case, and it must get a different line.
    #[test]
    fn the_stale_fix_line_names_interactivity_and_asks_for_a_recheck() {
        let mut installed_not_engaged = report(
            Some(ProjectionMode::Shim),
            &[ProjectionMode::Shim],
            live(
                ProjectionMode::Shim,
                ProjectionMode::Shim,
                Tri::NotApplicable,
                Tri::Yes,
                true,
            ),
        );
        installed_not_engaged.shim.engaged = false;
        let check =
            projection_mode_check_for(&installed_not_engaged, "macos", &not_probed(), &no_hook());
        assert!(
            matches!(check.status, HealthStatus::Stale),
            "an installed shim that is not engaged, in a shell with no hook, is the advisory \
             case, got {:?}",
            check.status
        );
        let fix = check.manual_fix.as_deref().unwrap_or_default();
        assert!(
            !fix.contains("exec $SHELL -l"),
            "the fix must not name a login shell, which does not engage the hook on a stock \
             Debian ~/.bashrc: {fix}"
        );
        assert!(
            fix.contains("interactive"),
            "the fix must name the condition the hook actually needs: {fix}"
        );
        assert!(
            fix.contains("kin doctor"),
            "the fix must ask for the check in the shell it creates: {fix}"
        );

        // The same machine in a shell whose hook is already live. A new shell
        // cannot move this row, so the line that asks for one is the wrong
        // instruction and must not be printed here.
        let hooked =
            projection_mode_check_for(&installed_not_engaged, "macos", &not_probed(), &hook_live());
        let hooked_fix = hooked.manual_fix.as_deref().unwrap_or_default();
        assert_ne!(
            hooked_fix, fix,
            "a shell that already runs the hook must not be told to start another one"
        );
        assert!(
            !hooked_fix.contains("interactive shell") && hooked_fix.contains("kin vfs status"),
            "with the hook live the fix must name the projection instead: {hooked_fix}"
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
            let check = vfs_projection_check_for(path, &driver, None);
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

        let uninstalled = vfs_projection_check_for(&missing, &VfsDriverState::Absent, None);
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
            None,
        );
        assert!(
            matches!(installed.status, HealthStatus::Missing),
            "a shim missing where projection is installed must stay a failure, got {:?}",
            installed.status
        );
        assert!(is_failing(&installed.status));
        assert!(installed.fixable);
        let fix = installed.manual_fix.as_deref().expect("a manual fix");
        assert!(
            fix.contains(SHIM_REINSTALL_HINT),
            "with no local copy the installer is the remaining route: {fix}"
        );
        assert!(
            fix.starts_with("no local shim was found"),
            "the reader has to know which of the two arms they got: {fix}"
        );
    }

    /// Both arms of the v0.5.40 stranger run were told to curl the network
    /// installer over the release candidate they had just extracted, while the
    /// shim it wanted was one of the four files in that archive. A local copy
    /// is the repair; the installer is the fallback.
    #[test]
    fn a_local_shim_is_offered_before_the_network_installer() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir
            .path()
            .join(".kin/lib")
            .join(crate::commands::setup::shim_filename());
        let source = dir
            .path()
            .join("archive")
            .join(crate::commands::setup::shim_filename());

        let local = vfs_projection_check_for(
            &dest,
            &VfsDriverState::Loadable(dir.path().join(vfs_binary_filename())),
            Some(&source),
        );
        let fix = local.manual_fix.as_deref().expect("a manual fix");
        assert!(
            fix.contains(&format!("cp {} {}", source.display(), dest.display())),
            "the fix must name the copy that is already on this host: {fix}"
        );
        assert!(
            !fix.contains("get.kinlab.dev"),
            "an install that carries the shim must not be told to download over itself: {fix}"
        );
        // The invariant this text has always had: it is reprinted in the
        // post-`--fix` "still needs manual steps" list, so naming the command
        // that just ran would be a dead loop.
        assert!(
            !fix.contains("doctor --fix"),
            "the durable step must not point back at the command that printed it: {fix}"
        );
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
            let check = vfs_projection_check_for(path, &VfsDriverState::Absent, None);
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

    /// How long a fixture waits for a file it just wrote to become executable.
    ///
    /// Generous against a loaded runner and far short of any real failure: the
    /// only handle that can still be open is a copy this process forked, and
    /// that copy is closed by the child's own exec microseconds later. A bound
    /// this wide expiring means something holds the file open indefinitely,
    /// which no fixture here does.
    #[cfg(unix)]
    const EXEC_READY_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

    /// Write an executable stand-in for the projection driver, and do not
    /// return until the host will actually run it.
    ///
    /// `write_file` closes its own handle before this returns, and that is not
    /// enough. A fork raised by another test thread between the open and the
    /// close inherits a copy of the write descriptor, and the kernel refuses to
    /// exec a file any process still holds open for writing: ETXTBSY, spelled
    /// "Text file busy". The inherited copy dies at that child's own exec, so
    /// the window is short and belongs entirely to the fixture, but it is wide
    /// enough under load to have ejected two green pull requests from the merge
    /// queue (FIR-2488, FIR-2457).
    ///
    /// Waiting for one successful exec is what closes the window rather than
    /// widening a sleep. Nothing else writes these files, so once the kernel
    /// has let the file run, no writer can appear again.
    #[cfg(unix)]
    fn write_driver(path: &Path, script: &str) {
        use std::os::unix::fs::PermissionsExt;
        write_file(path, script.as_bytes());
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        wait_until_executable(path);
    }

    /// Block until the host executes `path`, or fail naming what still refuses.
    ///
    /// Only ETXTBSY is waited out. Every other spawn error, and every exit
    /// status, means the file ran or is broken for a reason no wait repairs,
    /// so both return immediately.
    #[cfg(unix)]
    fn wait_until_executable(path: &Path) {
        wait_until_executable_within(path, EXEC_READY_BOUND);
    }

    /// [`wait_until_executable`] with the bound named, so the guard below can
    /// prove the wait expires without spending the real one.
    #[cfg(unix)]
    fn wait_until_executable_within(path: &Path, bound: std::time::Duration) {
        let deadline = std::time::Instant::now() + bound;
        let mut attempts = 0_u32;
        loop {
            let error = match std::process::Command::new(path)
                .arg("--kin-fixture-exec-probe")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
            {
                Ok(_) => return,
                Err(error) => error,
            };
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::ExecutableFileBusy,
                "{} could not be executed: {error}",
                path.display()
            );
            attempts += 1;
            assert!(
                std::time::Instant::now() < deadline,
                "{} stayed text-busy across {attempts} exec attempts in {bound:?}",
                path.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// The exec-readiness wait has to be able to see the condition it waits
    /// for, or it is a sleep that always returns.
    ///
    /// The condition is a file some process still holds open for writing, which
    /// is what a fork raised mid-write leaves behind. Linux refuses to exec such
    /// a file with ETXTBSY and macOS does not refuse at all, measured on both:
    /// `ubuntu:24.04` answers "Text file busy" and exit 126 while a descriptor
    /// is held and exit 0 once it closes, and this workstation runs the file in
    /// both states. So the refusing half of this guard asserts only where the
    /// kernel produces the refusal, decided by asking rather than by target
    /// name, and the returning half is asserted everywhere. That platform split
    /// is also why the flake this wait removes never reproduced on a local
    /// macOS gate and only ever ejected pull requests from Linux runs
    /// (FIR-2488, FIR-2457).
    #[test]
    #[cfg(unix)]
    fn the_exec_readiness_wait_sees_a_busy_file_and_stops_waiting_when_it_clears() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("stand-in");
        write_file(&script, b"#!/bin/sh\nexit 0\n");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let handle = std::fs::OpenOptions::new()
            .write(true)
            .open(&script)
            .unwrap();
        let refused_while_held = std::process::Command::new(&script)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .err()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::ExecutableFileBusy);

        if refused_while_held {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let expired = std::panic::catch_unwind(|| {
                wait_until_executable_within(&script, std::time::Duration::from_millis(200));
            });
            std::panic::set_hook(previous);
            let payload = expired
                .expect_err("a file this kernel refuses to exec must make the bounded wait expire");
            let message = payload
                .downcast_ref::<String>()
                .cloned()
                .unwrap_or_default();
            assert!(
                message.contains("stayed text-busy"),
                "the expiry must name what it was waiting on, got {message:?}"
            );
        }

        // Text-busy is the only failure worth waiting out. A wait that sat out
        // its bound on every error would turn a fixture typo into a timeout
        // instead of naming the missing file, so the discrimination is asserted
        // rather than assumed.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let started = std::time::Instant::now();
        let missing = std::panic::catch_unwind(|| {
            wait_until_executable_within(
                &dir.path().join("no-such-stand-in"),
                std::time::Duration::from_secs(30),
            );
        });
        std::panic::set_hook(previous);
        let payload = missing.expect_err("a path that is not there cannot become executable");
        assert!(
            payload
                .downcast_ref::<String>()
                .is_some_and(|message| message.contains("could not be executed")),
            "an absent file must be reported, not waited out: {payload:?}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "an error that is not text-busy must fail at once, took {:?}",
            started.elapsed()
        );

        drop(handle);
        // Both worlds: with no writer left the wait returns rather than
        // spending its bound, which is the half that keeps every fixture in
        // this module cheap.
        let cleared = std::time::Instant::now();
        wait_until_executable_within(&script, EXEC_READY_BOUND);
        assert!(
            cleared.elapsed() < std::time::Duration::from_secs(5),
            "a file nothing holds open must be executable at once, took {:?}",
            cleared.elapsed()
        );
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

        let check = vfs_projection_check_for(&dir.path().join("no-shim"), &state, None);
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
        let absent =
            vfs_projection_check_for(&dir.path().join("no-shim"), &VfsDriverState::Absent, None);
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

        let absent = vfs_projection_check_for(&missing_shim, &VfsDriverState::Absent, None);
        let installed = vfs_projection_check_for(&missing_shim, &loadable, None);
        let unloadable = vfs_projection_check_for(
            &missing_shim,
            &resolve_vfs_driver(std::slice::from_ref(&broken)),
            None,
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
            report.healthy(),
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
        assert!(!regressed.healthy());
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
                parse: None,
                languages: vec![LanguageReferenceCoverage {
                    language: "python".to_string(),
                    files: 12,
                    files_measured: 12,
                    entities: 46,
                    parsed_call_sites: Some(78),
                    call_sites_measured_files: 12,
                    parsed_import_statements: Some(16),
                    resolved_call_edges: resolved_calls,
                    resolved_import_statements: Some(0),
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
            vfs_projection_check_for(&dir.path().join("no-shim"), &VfsDriverState::Absent, None),
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
            report.healthy(),
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
        assert!(json.contains("\"daemon_idle_window\""));
        assert!(json.contains("\"vfs_projection\""));
        assert!(json.contains("\"shell_path\""));
        assert!(json.contains("\"registry_authority\""));
        assert!(json.contains("\"setup_ledger\""));
        assert!(json.contains("\"platform\""));
        assert!(json.contains("\"healthy\""));
        assert!(json.contains("\"retrieval_profile\""));
        // The row FIR-2787 is about answers with no repository in sight, so a
        // run outside one is exactly where it has to appear. Every unit test
        // above calls its core directly and would stay green if nobody ever
        // registered it, which is the shape of a check that cannot fail.
        assert!(json.contains("\"memory_floor\""));

        // Assert against the real assembled doctor report so cross-file/LSP
        // guidance cannot silently move behind embedding availability.
        let position = |id: &str| {
            report
                .checks
                .iter()
                .position(|check| check.id == id)
                .unwrap_or_else(|| panic!("doctor report omitted {id}"))
        };
        assert!(
            position("reference_edge_coverage") < position("embedding_model"),
            "doctor must explain cross-file/LSP coverage before embedding availability"
        );
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

    /// zsh's PATH line lives in `.zshenv`, which is the file a non-interactive
    /// shell reads, and setup no longer writes it to `.zshrc`. Doctor has to
    /// read that file or it reports a correctly installed host as missing its
    /// PATH, which is the shape of check that can never pass.
    #[test]
    #[serial]
    fn shell_path_reads_the_file_a_non_interactive_zsh_actually_reads() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let kin_home = tmp.path().join("kin-home");
        let hook_dir = kin_home.join("shell");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&hook_dir).unwrap();
        std::fs::create_dir_all(kin_home.join("bin")).unwrap();

        let hook = hook_dir.join(hook_filename("zsh"));
        std::fs::write(&hook, "# kin-vfs test hook\n").unwrap();

        // Exactly what setup writes now: the hook in the interactive file, the
        // PATH line in the file every zsh reads, and neither in the other.
        std::fs::write(
            home.join(".zshrc"),
            format!("source \"{}\"\n", hook.display()),
        )
        .unwrap();
        std::fs::write(
            home.join(".zshenv"),
            format!("export PATH=\"{}:$PATH\"\n", kin_home.join("bin").display()),
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
            "doctor read only the interactive rc, so an install that put the PATH \
             line where a script can see it reads as broken; got {:?}: {}",
            check.status,
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

    // ------------------------------------------------------------------ join
    //
    // FIR-2919. The roll-up is one function of the rows, and these pin it. Each
    // case is built through `HealthReport::from_checks`, which is the only
    // constructor, so no fixture can describe an aggregate the product cannot
    // produce.

    fn joined(statuses: &[(&str, HealthStatus)]) -> HealthReport {
        HealthReport::from_checks(
            "test".to_string(),
            statuses
                .iter()
                .map(|(id, status)| HealthCheck::new(id, id, status.clone(), "fixture"))
                .collect(),
        )
    }

    /// Every check healthy is the only shape that may claim readiness.
    #[test]
    fn the_join_reports_ready_over_all_healthy_checks() {
        let report = joined(&[
            ("kin_binary", HealthStatus::Healthy),
            ("shell_path", HealthStatus::Healthy),
        ]);
        assert_eq!(report.verdict(), HealthVerdict::Ready);
        assert!(report.healthy());
        assert_eq!(report.summary().attention, 0);
    }

    /// `Unsupported` is out of scope, not a shortfall, so it does not
    /// disqualify a ready verdict. This is the half of the rule that must NOT
    /// change: 19 of the 33 rows a fresh Windows install emits are unsupported,
    /// and a join that counted them would report every correct Windows install
    /// as needing attention.
    #[test]
    fn the_join_reports_ready_over_healthy_plus_unsupported_checks() {
        let report = joined(&[
            ("kin_binary", HealthStatus::Healthy),
            ("vfs_projection", HealthStatus::Unsupported),
            ("registry_authority", HealthStatus::Unsupported),
        ]);
        assert_eq!(report.verdict(), HealthVerdict::Ready);
        assert!(report.healthy());
        assert_eq!(report.summary().skipped, 2);
    }

    /// One `Pending` row is enough. The install is not broken, so the verdict
    /// is `NeedsAttention` and not `Failing`, and it is not ready either.
    #[test]
    fn the_join_refuses_ready_over_any_pending_check() {
        let report = joined(&[
            ("kin_binary", HealthStatus::Healthy),
            ("vfs_projection", HealthStatus::Unsupported),
            ("embedding_model", HealthStatus::Pending),
        ]);
        assert!(
            !report.healthy(),
            "a pending row is a component not answering at full strength"
        );
        assert_eq!(report.verdict(), HealthVerdict::NeedsAttention);
        assert_eq!(serde_json::to_value(&report).unwrap()["healthy"], false);
    }

    /// One `Degraded` row is enough, for the same reason and not the same
    /// cause: pending is work in flight, degraded is ground the host never had.
    /// Both keep the report out of ready; neither makes it failing.
    #[test]
    fn the_join_refuses_ready_over_any_degraded_check() {
        let report = joined(&[
            ("kin_binary", HealthStatus::Healthy),
            ("vfs_projection", HealthStatus::Unsupported),
            ("memory_floor", HealthStatus::Degraded),
        ]);
        assert!(!report.healthy());
        assert_eq!(report.verdict(), HealthVerdict::NeedsAttention);
        assert_eq!(serde_json::to_value(&report).unwrap()["healthy"], false);
    }

    /// A broken install is a third answer, not the same one louder. Without
    /// this, `healthy: false` would mean two different things and no consumer
    /// could tell a warming install from one that cannot work.
    #[test]
    fn the_join_reports_failing_over_a_missing_check() {
        let report = joined(&[
            ("kin_binary", HealthStatus::Healthy),
            ("embedding_model", HealthStatus::Pending),
            ("shell_path", HealthStatus::Missing),
        ]);
        assert!(!report.healthy());
        assert_eq!(
            report.verdict(),
            HealthVerdict::Failing,
            "a missing component outranks work in flight"
        );
        assert_eq!(serde_json::to_value(&report).unwrap()["verdict"], "failing");
    }

    /// `Stale` on the semantic authority is the one stale that fails, and it
    /// must still fail now that stale rows elsewhere merely need attention.
    #[test]
    fn the_join_separates_authority_stale_from_ordinary_stale() {
        let authority = joined(&[
            ("kin_binary", HealthStatus::Healthy),
            ("semantic_query_readiness", HealthStatus::Stale),
        ]);
        assert_eq!(authority.verdict(), HealthVerdict::Failing);

        let ordinary = joined(&[
            ("kin_binary", HealthStatus::Healthy),
            ("projection_mode", HealthStatus::Stale),
        ]);
        assert_eq!(
            ordinary.verdict(),
            HealthVerdict::NeedsAttention,
            "an ordinary stale row is drift, not a broken install"
        );
        assert!(!ordinary.healthy());
    }

    /// The exact row set a fresh Windows install emitted on the v0.6.1 release
    /// run, lifted from the `install-proof-windows-latest-33235776577`
    /// artifact's `kin-windows-health.json` rather than composed here.
    ///
    /// This host cannot run Windows. What is portable is the rule, and the rule
    /// is what the fixture exercises: 12 healthy rows, 19 unsupported, one
    /// pending and one degraded, under `"healthy": true` on the shipped bytes.
    /// That contradiction is what the release's install proof threw on, and it
    /// is what this asserts is gone.
    const WINDOWS_V061_ROWS: &[(&str, HealthStatus)] = &[
        ("kin_binary", HealthStatus::Healthy),
        ("kin_daemon_binary", HealthStatus::Healthy),
        ("supervisor_startup_protocol", HealthStatus::Healthy),
        ("daemon_running", HealthStatus::Unsupported),
        ("daemon_idle_window", HealthStatus::Unsupported),
        ("vfs_projection", HealthStatus::Unsupported),
        ("projection_mode", HealthStatus::Unsupported),
        ("repo_init", HealthStatus::Unsupported),
        ("session_runtime", HealthStatus::Unsupported),
        ("shell_path", HealthStatus::Healthy),
        ("registry_authority", HealthStatus::Unsupported),
        ("mcp_client_claude", HealthStatus::Healthy),
        ("mcp_client_cursor", HealthStatus::Healthy),
        ("mcp_client_gemini", HealthStatus::Healthy),
        ("mcp_client_windsurf", HealthStatus::Healthy),
        ("setup_ledger", HealthStatus::Healthy),
        ("editor", HealthStatus::Unsupported),
        ("kinlab_connect", HealthStatus::Unsupported),
        ("semantic_query_readiness", HealthStatus::Unsupported),
        ("reference_edge_coverage", HealthStatus::Unsupported),
        ("relation_census", HealthStatus::Unsupported),
        ("parse_coverage", HealthStatus::Unsupported),
        ("background_work", HealthStatus::Unsupported),
        ("embedding_model", HealthStatus::Pending),
        ("memory_floor", HealthStatus::Degraded),
        ("commit_memory_headroom", HealthStatus::Unsupported),
        ("daemon_kill_record", HealthStatus::Unsupported),
        ("interrupted_init", HealthStatus::Healthy),
        ("suspended_sweep", HealthStatus::Unsupported),
        ("host_memory_pressure", HealthStatus::Unsupported),
        ("retrieval_profile", HealthStatus::Healthy),
        ("update_policy", HealthStatus::Healthy),
        ("binary_assessment_load", HealthStatus::Unsupported),
    ];

    #[test]
    fn the_windows_first_install_row_set_no_longer_claims_ready() {
        let report = joined(WINDOWS_V061_ROWS);
        assert_eq!(report.checks.len(), 33, "the shipped row set is 33 rows");
        let summary = report.summary();
        assert_eq!(summary.passed, 12);
        assert_eq!(summary.skipped, 19);
        assert_eq!(
            summary.attention, 2,
            "embedding_model pending and memory_floor degraded"
        );
        assert!(
            !report.healthy(),
            "the shipped report emitted healthy=true over these exact rows"
        );
        assert_eq!(
            report.verdict(),
            HealthVerdict::NeedsAttention,
            "nothing about that install was broken; it had not fetched the model \
             and the host was small"
        );

        // The control that makes the assertion above mean something. Drop the
        // two rows that need attention and the same 31 rows must read ready, or
        // this is a fixture that fails for having any rows at all.
        let in_scope_only: Vec<(&str, HealthStatus)> = WINDOWS_V061_ROWS
            .iter()
            .filter(|(id, _)| *id != "embedding_model" && *id != "memory_floor")
            .map(|(id, status)| (*id, status.clone()))
            .collect();
        let control = joined(&in_scope_only);
        assert_eq!(control.checks.len(), 31);
        assert_eq!(
            control.verdict(),
            HealthVerdict::Ready,
            "19 unsupported rows must not be what refuses readiness"
        );
        assert!(control.healthy());
    }

    #[test]
    fn summary_tallies_pass_attention_skip_buckets() {
        // Every status the enum carries, so the tally is graded over the whole
        // vocabulary rather than the four an author happens to think of.
        let report = HealthReport::from_checks(
            "test".to_string(),
            vec![
                check_with("a", HealthStatus::Healthy),
                check_with("b", HealthStatus::Healthy),
                check_with("c", HealthStatus::Missing),
                check_with("d", HealthStatus::Misconfigured),
                check_with("e", HealthStatus::Stale),
                check_with("f", HealthStatus::Unsupported),
                check_with("g", HealthStatus::Pending),
                check_with("h", HealthStatus::Degraded),
            ],
        );
        let summary = report.summary();
        assert_eq!(summary.passed, 2, "two Healthy checks pass");
        assert_eq!(
            summary.attention, 5,
            "Missing + Misconfigured + Stale + Pending + Degraded need attention"
        );
        assert_eq!(summary.skipped, 1, "Unsupported is not applicable");
    }

    #[test]
    fn summary_buckets_sum_to_total_checks() {
        let report = HealthReport::from_checks(
            "test".to_string(),
            vec![
                check_with("a", HealthStatus::Healthy),
                check_with("b", HealthStatus::Stale),
                check_with("c", HealthStatus::Unsupported),
                check_with("d", HealthStatus::Pending),
                check_with("e", HealthStatus::Degraded),
            ],
        );
        let summary = report.summary();
        assert_eq!(
            summary.passed + summary.attention + summary.skipped,
            report.checks.len(),
            "every check lands in exactly one bucket"
        );
    }

    /// FIR-2426. The idle window is a per-store number now, so a surface has to
    /// say what it is. It is always advisory: every window the rule produces is
    /// a correct one, and a check that could fail readiness over a legitimate
    /// preference would make `kin doctor` cry wolf on a healthy install.
    #[test]
    fn the_idle_window_check_reports_the_window_and_never_fails_readiness() {
        let check = check_daemon_idle_window();
        assert_eq!(check.id, "daemon_idle_window");
        assert!(
            matches!(
                check.status,
                HealthStatus::Healthy | HealthStatus::Unsupported
            ),
            "the idle window is a report, not a verdict: {:?}",
            check.status
        );
        assert!(
            !blocks_readiness(&check),
            "a legitimate window must never block readiness"
        );
        assert!(
            !check.detail.trim().is_empty(),
            "the check owes a reason, not just a status"
        );
    }

    /// Whatever the window is, the reason names what decided it, because a
    /// number with no cause behind it cannot be questioned.
    #[test]
    fn the_idle_window_detail_names_what_decided_it() {
        let detail = check_daemon_idle_window().detail;
        assert!(
            detail.contains("not in a Kin repository")
                || detail.contains("no local daemon")
                || detail.contains("the floor")
                || detail.contains("the ceiling")
                || detail.contains("times the last open")
                || detail.contains("KIN_DAEMON_IDLE_TIMEOUT_SECS"),
            "the detail must name a cause: {detail}"
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
            !report.healthy(),
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
        assert_eq!(semantic.check.id, "semantic_query_readiness");
        assert!(matches!(semantic.check.status, HealthStatus::Unsupported));
        assert!(!semantic.check.detail.contains("kin embed"));
        assert!(semantic.check.manual_fix.is_none());
        assert_eq!(semantic.embedding_coverage, None);
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

        let sample = semantic_query_readiness_sample_from_runtime("http://daemon", &runtime);
        assert_eq!(
            sample.embedding_coverage,
            Some(kin_core::memory_pressure::EmbeddingCoverage {
                pending: 0,
                indexed: 41,
                total: 41,
            })
        );
        let semantic = sample.check;

        assert!(matches!(semantic.status, HealthStatus::Healthy));
        assert!(semantic.detail.contains("41/41 embeddings indexed"));
        assert!(!semantic.detail.contains("graph.kvec"));
        assert!(semantic.manual_fix.is_none());
    }

    /// A salvage is lost ground, and the arm that would otherwise catch it
    /// calls the identical counters healthy.
    ///
    /// A per-key salvage attaches an index, so no discard is recorded, and it
    /// happens on stores that HAVE finished a fill, so `ever_complete` holds.
    /// Both of those steer the same counters to the Healthy top-up arm, which
    /// is the correct verdict for a working copy admitting new files and the
    /// wrong one for a store that just had coverage retired. The counts kin-db
    /// now returns are what let this path tell them apart (FIR-2562).
    #[cfg(feature = "vector")]
    #[test]
    fn semantic_query_readiness_calls_a_retired_coverage_stale_not_filling() {
        // Identical to the top-up fixture below in every field that the
        // healthy arm reads, so the verdict can only turn on the salvage.
        let topping_up = crate::commands::resources::EmbedRuntimeState {
            embeddings_indexed: 40,
            embeddings_total: 41,
            embeddings_pending: 1,
            embedding_coverage_ever_complete: true,
            ..Default::default()
        };
        let healthy = semantic_query_health_from_runtime("http://daemon", &topping_up);
        assert!(
            matches!(healthy.status, HealthStatus::Healthy),
            "the control: these counters alone are a healthy top-up: {:?}",
            healthy.status
        );

        let salvaged = crate::commands::resources::EmbedRuntimeState {
            vector_index_salvage: Some(crate::commands::resources::VectorSalvage {
                kept: 1770,
                dropped: 342,
            }),
            ..topping_up.clone()
        };
        let stale = semantic_query_health_from_runtime("http://daemon", &salvaged);
        assert!(
            matches!(stale.status, HealthStatus::Stale),
            "coverage retired at open is not a backlog filling: {:?}, {}",
            stale.status,
            stale.detail
        );
        assert!(
            stale.detail.contains("1770") && stale.detail.contains("342"),
            "both counts have to reach the reader: {}",
            stale.detail
        );
        assert!(
            !stale
                .detail
                .contains("coverage completed earlier and this backlog is filling"),
            "the filling sentence must not survive beside a retirement: {}",
            stale.detail
        );
        assert!(stale.manual_fix.is_some());
        assert!(
            !assemble_health_report("test".to_string(), vec![stale]).healthy(),
            "a retired coverage has to fail the aggregate, as a discard does"
        );
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
            !assemble_health_report("test".to_string(), vec![stale]).healthy(),
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
            report.healthy(),
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
        assert!(assemble_health_report("test".to_string(), vec![semantic]).healthy());
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
        assert_eq!(
            report.verdict(),
            HealthVerdict::NeedsAttention,
            "a fresh install mid-first-fill is warming up, not broken: {:?}",
            report.checks[0].status
        );
        assert_eq!(
            report.summary().attention,
            1,
            "the fill is still work in progress, so it is attention rather than not-applicable"
        );
        // The emitted pair, read off the serialized report rather than the
        // struct, because the JSON is what the install proof and every other
        // consumer actually reads. `healthy` false with `verdict`
        // `needs_attention` is the whole difference FIR-2919 bought: the old
        // shape emitted `true` here, over this exact row.
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["healthy"], false);
        assert_eq!(json["verdict"], "needs_attention");
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
            !assemble_health_report("test".to_string(), vec![after_discard]).healthy(),
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
        assert!(assemble_health_report("test".to_string(), vec![after_top_up]).healthy());

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
        assert!(!assemble_health_report("test".to_string(), vec![after_wedge]).healthy());
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

    /// The query-only surface is a supported choice, not a fault.
    ///
    /// `kin setup` writes `agent-default`, and an operator who narrowed the
    /// entry to the same belt without its session and transaction tools stopped
    /// paying for contracts a query-only client never calls (FIR-3107). Doctor
    /// telling them to put those back would be doctor arguing with a product
    /// decision.
    #[test]
    fn mcp_config_on_the_query_profile_is_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "kin": {
                        "command": "kin",
                        "args": ["mcp", "start"],
                        "env": { "KIN_MCP_TOOL_PROFILE": "agent-query" }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let (status, detail) = evaluate_mcp_client_against(&path, "claude", "kin");
        assert!(matches!(status, HealthStatus::Healthy), "detail: {detail}");
        assert!(
            detail.contains("agent-query"),
            "the reader must be told which surface is wired: {detail}"
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
        assert!(report.healthy());
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
        // FIR-2555: the command that starts the pass, not a later one the
        // reader has no reason to run.
        assert!(
            check
                .detail
                .contains("`kin init` starts the first embed pass"),
            "the detail names what starts the fetch: {}",
            check.detail
        );
        // FIR-2957: naming `kin init` is right and promising the fetch lands
        // inside it is not. `kin init` records first and may leave the fetch
        // for `kin embed`, and its own notice says which happened, so this row
        // may not tell the reader to expect the download before init returns.
        assert!(
            !check.detail.contains("before it records anything"),
            "the row must not promise the fetch completes inside init: {}",
            check.detail
        );
        assert!(
            !check.detail.contains("a later embed pass fetches"),
            "the check must be able to fail: {}",
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

    /// The two commands that describe one fetch must not describe it
    /// differently.
    ///
    /// This is a join, not two endpoint checks. `kin doctor` and `kin init`
    /// each own a sentence about the same embedding-model state, they were
    /// written at different times, and on the v0.6.2 candidate they disagreed:
    /// init had been corrected to say it records without fetching, and
    /// doctor still told the reader the fetch happens before init records
    /// anything. Two tests asserting two hardcoded strings could not have seen
    /// that, because each was right about its own half. So this one reads what
    /// init actually produces for a state and requires doctor's row for the
    /// same state to be consistent with it, and the one literal both sides are
    /// checked against is written here once.
    #[test]
    #[serial]
    fn doctor_and_init_agree_about_the_model_fetch() {
        let _endpoint = EnvVarGuard::unset("HF_ENDPOINT");
        let absent = absent_model();

        // The state under test: absent when the command opened and absent when
        // it closed, which is what a cold container with no egress budget gets.
        let init_line = crate::commands::init::embedding_model_notice(&absent, &absent, None);
        let doctor = embedding_model_check_from(&absent, Some(true));

        assert!(
            init_line.contains("did not fetch it"),
            "the fixture must be the state where init records without fetching, \
             or this test is grading the wrong pair: {init_line}"
        );

        // Read the fallback out of init's own sentence rather than trusting a
        // second copy of it, then require doctor to name the same one.
        const FALLBACK: &str = "`kin embed`";
        assert!(
            init_line.contains(FALLBACK),
            "init names the command that does the fetch: {init_line}"
        );
        assert!(
            doctor.detail.contains(FALLBACK),
            "doctor names the same fallback init does, so a reader who follows \
             either command lands in the same place: {}",
            doctor.detail
        );

        // And doctor may not contradict init about when the download happens.
        assert!(
            !doctor.detail.contains("before it records anything"),
            "doctor promises a fetch init's own line says may not have happened: {}",
            doctor.detail
        );
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

    /// One row, one measurement, one moment.
    ///
    /// `kin doctor` used to join a refusal's captured standing and the daemon's
    /// live one into a single row behind "Also:", and a cold-user walk quoted
    /// the pair back: the same row said the daemon held 3.7 GiB and 7.0 GiB of
    /// the same 4.0 GiB allowance, with eleven child processes and ten. Both
    /// readings were true. The row never said they were minutes apart, and the
    /// second one, being larger than the allowance, read as arithmetically
    /// impossible.
    #[test]
    fn memory_pressure_rows_carry_one_measurement_each_with_its_moment() {
        let gib = 1024 * 1024 * 1024;
        let over = kin_core::memory_pressure::DaemonFootprint {
            footprint: kin_core::memory_pressure::TreeFootprint {
                own_bytes: 4 * gib,
                children_bytes: 3 * gib,
                child_count: 10,
                kernel_capped: false,
            },
            budget_bytes: 4 * gib,
            budget_is_derived: true,
            level: "critical".to_string(),
            pid: 4103,
            at_unix: 76_440, // 21:14Z
        };
        let refusal = kin_core::memory_pressure::PressureRefusal {
            work: kin_core::memory_pressure::HeavyWork::LspSweep
                .id()
                .to_string(),
            level: "critical".to_string(),
            reason: "this repository's daemon and the 11 process(es) it started hold 3.7 GiB \
                     of the 4.0 GiB it is allowed"
                .to_string(),
            at_unix: 76_440, // 21:14Z
        };

        let row = host_memory_pressure_check_for(std::slice::from_ref(&refusal), Some(&over), None);
        assert!(
            !row.detail.contains("Also:"),
            "the two readings are no longer joined into one row: {}",
            row.detail
        );
        assert!(
            row.detail.contains("21:14Z") && row.detail.contains("when the work was declined"),
            "the refusal row says when its reading was taken: {}",
            row.detail
        );
        assert!(
            !row.detail.contains("7.0 GiB"),
            "and carries only its own measurement: {}",
            row.detail
        );

        // The synthetic record that means "I could not read the ledger" is a
        // different claim and must not be stamped as a declining. Its
        // `at_unix` is the moment of the read, and `describes_outstanding_work`
        // returns true for every work id that is not `EmbedBatch`, so nothing
        // filters it out before the clause.
        let unreadable = kin_core::memory_pressure::PressureRefusal {
            work: kin_core::memory_pressure::PRESSURE_RECORD_UNREADABLE_WORK_ID.to_string(),
            level: "unknown".to_string(),
            reason: "Kin found an existing memory-pressure publication but could not read one \
                     complete record from it"
                .to_string(),
            at_unix: 76_440, // 21:14Z
        };
        let unreadable_row =
            host_memory_pressure_check_for(std::slice::from_ref(&unreadable), None, None);
        assert!(
            !unreadable_row.detail.contains("when the work was declined"),
            "an unreadable ledger records no declining, so the row must not claim one: {}",
            unreadable_row.detail
        );
        assert!(
            unreadable_row.detail.contains("21:14Z")
                && unreadable_row.detail.contains("a read time"),
            "and the moment it does carry is named as the read it was: {}",
            unreadable_row.detail
        );

        // The control that keeps the fix narrow: a refusal a producer actually
        // wrote still says when the work was declined, so the clause was told
        // apart rather than dropped for everything.
        let declined_row =
            host_memory_pressure_check_for(std::slice::from_ref(&refusal), None, None);
        assert!(
            declined_row.detail.contains("when the work was declined"),
            "a real refusal keeps the clause: {}",
            declined_row.detail
        );

        let standing = daemon_memory_standing_check_for(&over, 76_440 + 42);
        assert!(
            standing.detail.contains("7.0 GiB") && standing.detail.contains("10 process(es)"),
            "the live standing is a row of its own: {}",
            standing.detail
        );
        assert!(
            standing.detail.contains("measured at 21:14Z")
                && standing.detail.contains("42s ago")
                && standing.detail.contains("pid 4103"),
            "stamped unconditionally, not only once it has gone stale: {}",
            standing.detail
        );
        assert!(
            matches!(standing.status, HealthStatus::Degraded),
            "a tree past its allowance is not a healthy row"
        );
        assert!(
            !blocks_readiness(&standing),
            "and it still must not fail a correct install on a small machine"
        );

        // The impossible-looking figure now says what it means. Without this
        // clause "hold 7.0 GiB of the 4.0 GiB it is allowed" is a sentence a
        // reader cannot resolve, and an unresolvable row stops being read.
        assert!(
            standing.detail.contains("3.0 GiB past the allowance")
                && standing
                    .detail
                    .contains("rather than one the kernel imposes"),
            "the overrun is named and explained: {}",
            standing.detail
        );

        let under = kin_core::memory_pressure::DaemonFootprint {
            footprint: kin_core::memory_pressure::TreeFootprint {
                own_bytes: gib,
                children_bytes: gib,
                child_count: 2,
                kernel_capped: false,
            },
            ..over.clone()
        };
        let inside = daemon_memory_standing_check_for(&under, 76_440);
        assert!(
            matches!(inside.status, HealthStatus::Healthy),
            "a tree inside its allowance is healthy"
        );
        assert!(
            !inside.detail.contains("past the allowance"),
            "and says nothing about an overrun it does not have: {}",
            inside.detail
        );
    }

    /// A refusal remains visible exactly while its own work is outstanding or
    /// the count is unknown, and it never changes the verdict of the page.
    ///
    /// The second half is the half that could break a release. `kin doctor`'s
    /// aggregate is what the install proof asserts on, so a row that flipped a
    /// healthy store to unhealthy on a busy machine would fail the gate over
    /// the host rather than over the install.
    #[test]
    fn the_memory_pressure_row_uses_exact_pending_without_muting_other_work() {
        let quiet = host_memory_pressure_check_for(&[], None, None);
        assert!(matches!(quiet.status, HealthStatus::Healthy));
        assert!(quiet.manual_fix.is_none());
        assert!(!blocks_readiness(&quiet));

        // With a standing published, the healthy row is a gauge rather than a
        // bell: it says how close the daemon is, so a reader on a machine Kin
        // grades wrongly has something to look at.
        let published = kin_core::memory_pressure::DaemonFootprint {
            footprint: kin_core::memory_pressure::TreeFootprint {
                own_bytes: 2 * 1024 * 1024 * 1024,
                children_bytes: 512 * 1024 * 1024,
                child_count: 1,
                kernel_capped: false,
            },
            budget_bytes: 8 * 1024 * 1024 * 1024,
            budget_is_derived: true,
            level: "nominal".to_string(),
            pid: 4103,
            at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or_default(),
        };
        let gauge = host_memory_pressure_check_for(&[], Some(&published), None);
        assert!(matches!(gauge.status, HealthStatus::Healthy));
        assert!(!blocks_readiness(&gauge));
        // The gauge moved to its own row, so this one points at it rather than
        // carrying a second measurement of its own. See
        // `memory_pressure_rows_carry_one_measurement_each_with_its_moment`.
        assert!(
            gauge.detail.contains("Daemon memory standing"),
            "the refusal row points at the row that holds the standing: {}",
            gauge.detail
        );
        let standing_row = daemon_memory_standing_check_for(&published, published.at_unix + 3);
        assert!(matches!(standing_row.status, HealthStatus::Healthy));
        assert!(!blocks_readiness(&standing_row));
        assert!(
            standing_row.detail.contains("it is allowed")
                && standing_row.detail.contains("child processes"),
            "the standing row reports the standing and names the children: {}",
            standing_row.detail
        );

        let refusal = |work: &str| kin_core::memory_pressure::PressureRefusal {
            work: work.to_string(),
            level: "critical".to_string(),
            reason: format!("host memory pressure held back {work}"),
            at_unix: 4_800,
        };
        let coverage = |pending, indexed, total| kin_core::memory_pressure::EmbeddingCoverage {
            pending,
            indexed,
            total,
        };

        let embed = refusal(kin_core::memory_pressure::HeavyWork::EmbedBatch.id());
        let completed = host_memory_pressure_check_for(
            std::slice::from_ref(&embed),
            Some(&published),
            Some(coverage(0, 9, 9)),
        );
        assert!(matches!(completed.status, HealthStatus::Healthy));
        assert!(completed.manual_fix.is_none());
        assert!(!completed.detail.contains(&embed.reason));
        assert!(
            completed.detail.contains("Daemon memory standing"),
            "retiring an old embed refusal still points at the footprint gauge: {}",
            completed.detail
        );

        let live_embed = host_memory_pressure_check_for(
            std::slice::from_ref(&embed),
            None,
            Some(coverage(1, 9, 9)),
        );
        let queue_empty_but_short = host_memory_pressure_check_for(
            std::slice::from_ref(&embed),
            None,
            Some(coverage(0, 8, 9)),
        );
        let unobserved_embed =
            host_memory_pressure_check_for(std::slice::from_ref(&embed), None, None);
        let lsp = refusal(kin_core::memory_pressure::HeavyWork::LspSweep.id());
        let live_lsp = host_memory_pressure_check_for(
            std::slice::from_ref(&lsp),
            None,
            Some(coverage(0, 9, 9)),
        );
        let unknown = refusal("future-heavy-work");
        let live_unknown = host_memory_pressure_check_for(
            std::slice::from_ref(&unknown),
            None,
            Some(coverage(0, 9, 9)),
        );

        for reported in [
            &live_embed,
            &queue_empty_but_short,
            &unobserved_embed,
            &live_lsp,
            &live_unknown,
        ] {
            assert!(matches!(reported.status, HealthStatus::Degraded));
            assert!(reported
                .manual_fix
                .as_deref()
                .is_some_and(|fix| fix.contains("more memory")));
            assert!(
                !blocks_readiness(reported),
                "a busy machine is not a broken install, and this row must never fail the proof"
            );
        }
        // The row now stamps the refusal with the moment it was taken, so it
        // opens with the reason rather than equalling it. Which refusal is
        // being reported is still what these arms are asking.
        for (reported, expected) in [
            (&live_embed, &embed.reason),
            (&queue_empty_but_short, &embed.reason),
            (&unobserved_embed, &embed.reason),
            (&live_lsp, &lsp.reason),
            (&live_unknown, &unknown.reason),
        ] {
            assert!(
                reported.detail.starts_with(expected.as_str()),
                "the row reports this refusal: {} against {expected}",
                reported.detail
            );
            assert!(
                reported.detail.contains("when the work was declined"),
                "stamped with the moment it was taken: {}",
                reported.detail
            );
        }

        for independent in [&lsp, &unknown] {
            for refusals in [
                vec![(*independent).clone(), embed.clone()],
                vec![embed.clone(), (*independent).clone()],
            ] {
                let reported =
                    host_memory_pressure_check_for(&refusals, None, Some(coverage(0, 9, 9)));
                assert!(matches!(reported.status, HealthStatus::Degraded));
                assert!(
                    reported.detail.starts_with(independent.reason.as_str()),
                    "a completed embed entry cannot mask {} in either publication order: {}",
                    independent.work,
                    reported.detail
                );
                assert!(!blocks_readiness(&reported));
            }
        }
    }

    /// The hydration row is advisory but never vague: agreement is healthy,
    /// every other standing is stale, and each gap keeps its direction-specific
    /// remedy. `Stale` stays outside the aggregate readiness gate in phase one.
    #[test]
    fn the_hydration_semantics_row_separates_agreement_from_every_gap() {
        use kin_core::hydration_semantics::HydrationStanding;

        let current = hydration_semantics_check_for(&HydrationStanding::Current { version: 10 });
        assert!(matches!(current.status, HealthStatus::Healthy));
        assert!(current.manual_fix.is_none());
        assert!(!blocks_readiness(&current));

        let standing = HydrationStanding::Behind {
            created_under: 9,
            derives: 10,
        };
        let row = hydration_semantics_check_for(&standing);
        assert!(matches!(row.status, HealthStatus::Stale), "{row:?}");
        assert!(
            row.manual_fix
                .as_deref()
                .is_some_and(|fix| fix.contains("re-ingest")),
            "a store this build can repair needs the re-ingest remedy: {row:?}"
        );
        assert!(
            !blocks_readiness(&row),
            "phase-one disclosure must not turn a legacy store into a broken install"
        );

        for standing in [
            HydrationStanding::Unstamped { derives: 10 },
            HydrationStanding::Unreadable {
                reason: "future schema".to_string(),
                derives: 10,
            },
        ] {
            let unknown = hydration_semantics_check_for(&standing);
            assert!(matches!(unknown.status, HealthStatus::Stale));
            let fix = unknown.manual_fix.as_deref().unwrap_or_default();
            assert!(
                fix.starts_with("upgrade Kin to the newest build"),
                "unknown provenance must not trigger destructive advice: {unknown:?}"
            );
            // The doctor row a native store reads after a sync it could not
            // match. It may not name re-ingest as a step that keeps this
            // store's history, because a native store has no source to
            // re-ingest from.
            assert!(
                !fix.contains("re-ingest the repository into a separate fresh store"),
                "unknown provenance must not presume a source outside the store: {fix}"
            );
            assert!(fix.contains("keeps serving its history"));
            assert!(!blocks_readiness(&unknown));
        }

        let ahead = hydration_semantics_check_for(&HydrationStanding::Ahead {
            created_under: 11,
            derives: 10,
        });
        assert!(matches!(ahead.status, HealthStatus::Stale));
        let fix = ahead.manual_fix.as_deref().unwrap_or_default();
        assert!(fix.contains("upgrade this Kin build"), "{ahead:?}");
        assert!(
            !fix.contains("re-ingest the repository"),
            "an older binary must not replace a store recorded under newer replay semantics: {ahead:?}"
        );
        assert!(!blocks_readiness(&ahead));
    }

    /// The row exists because every other row on the page reads healthy after a
    /// kill: the store is fine and a replacement is serving. The record is the
    /// only thing that remembers, and a store that has lost none must not grow
    /// a row saying so ambiguously.
    #[test]
    fn the_daemon_kill_row_reports_a_record_and_stays_quiet_without_one() {
        let quiet = daemon_kill_record_check_for(None);
        assert!(matches!(quiet.status, HealthStatus::Healthy));
        assert!(quiet.manual_fix.is_none());

        let record = kin_daemon_spawn::DaemonKillRecord {
            kills: 4,
            memory_kills: 4,
            first_unix: 4_320,
            last_unix: 4_800,
            last_pid: Some(41),
            last_cause: kin_daemon_spawn::DaemonKillCause::MemoryLimit {
                kernel_oom_kills: 1,
            },
            limit_bytes: Some(12 * 1024 * 1024 * 1024),
            last_rss_bytes: None,
        };
        let reported = daemon_kill_record_check_for(Some(&record));
        assert!(matches!(reported.status, HealthStatus::Degraded));
        assert!(
            reported
                .detail
                .contains("killed by the memory limit 4 time(s) since 01:12Z"),
            "{}",
            reported.detail
        );
        assert!(
            reported
                .manual_fix
                .as_deref()
                .is_some_and(|fix| fix.contains("KIN_DAEMON_DISABLE_LSP=1 kin graph status")),
            "the fix line must name something the reader can do: {:?}",
            reported.manual_fix
        );
        assert!(
            !blocks_readiness(&reported),
            "a machine too small for this repository is not a broken install"
        );
    }

    /// The sweep row exists because the page reads healthy while enrichment is
    /// off: unenriched files are counted as pending everywhere else, and
    /// pending is the one thing they are not. A store whose sweeps are running
    /// must not grow a row that reads like a complaint.
    #[test]
    fn the_sweep_row_reports_a_suspension_and_stays_quiet_without_one() {
        let quiet = suspended_sweep_check_for(None);
        assert!(matches!(quiet.status, HealthStatus::Healthy));
        assert!(quiet.manual_fix.is_none());
        assert!(
            !quiet.detail.contains("kin daemon sweep"),
            "a store that is sweeping normally is not told to ask for a sweep: {}",
            quiet.detail
        );

        let suspended = kin_daemon_spawn::SuspendedSweep { interruptions: 3 };
        let reported = suspended_sweep_check_for(Some(&suspended));
        assert!(matches!(reported.status, HealthStatus::Degraded));
        assert!(
            reported.detail.contains('3') && reported.detail.contains("suspended"),
            "{}",
            reported.detail
        );
        assert!(
            reported
                .manual_fix
                .as_deref()
                .is_some_and(|fix| fix.contains("kin daemon sweep")),
            "the fix line must name something the reader can do: {:?}",
            reported.manual_fix
        );
        assert!(
            !blocks_readiness(&reported),
            "a store whose sweeps keep dying is telling you about the machine, not the install"
        );
    }

    /// One census row, so the row is testable without a daemon or a store.
    fn parse_census_row(
        language: &str,
        tracked: usize,
        silent: usize,
    ) -> kin_core::reference_coverage::LanguageParseCoverage {
        kin_core::reference_coverage::LanguageParseCoverage {
            language: language.to_string(),
            tracked,
            with_entities: tracked.saturating_sub(silent),
            silent,
            retained: 0,
            sample: if silent > 0 {
                vec!["lib/express.js".to_string()]
            } else {
                Vec::new()
            },
            retained_sample: Vec::new(),
        }
    }

    /// One census row for a language holding a file the graph is answering
    /// about from an earlier parse, so this row's own verdict is testable
    /// without a daemon or a store.
    fn retained_census_row(
        language: &str,
        tracked: usize,
        retained: usize,
    ) -> kin_core::reference_coverage::LanguageParseCoverage {
        kin_core::reference_coverage::LanguageParseCoverage {
            language: language.to_string(),
            tracked,
            with_entities: tracked.saturating_sub(retained),
            silent: 0,
            retained,
            sample: Vec::new(),
            retained_sample: vec!["search.py (4 parse errors)".to_string()],
        }
    }

    /// The row reports and never judges. Healthy in both states, because no
    /// graph-owned signal separates a file an adapter could not read from one
    /// that correctly declares nothing, and a doctor row that went red on the
    /// second would go red on most JavaScript repositories. It still has to
    /// carry the numbers and the paths, or it is a row nobody can act on.
    #[test]
    fn the_parse_row_reports_its_numbers_and_never_fails_a_store() {
        let clean = parse_coverage_health(&kin_core::reference_coverage::ParseCoverageCensus {
            languages: vec![parse_census_row("rust", 200, 0)],
        });
        assert!(matches!(clean.status, HealthStatus::Healthy));
        assert!(clean.manual_fix.is_none());
        assert!(clean.detail.contains("rust 200/200"), "{}", clean.detail);

        let silent = parse_coverage_health(&kin_core::reference_coverage::ParseCoverageCensus {
            languages: vec![parse_census_row("javascript", 141, 75)],
        });
        assert!(
            matches!(silent.status, HealthStatus::Healthy),
            "a count is not a defect: {:?}",
            silent.status
        );
        for expected in ["75", "141", "lib/express.js"] {
            assert!(
                silent.detail.contains(expected),
                "the row must carry {expected}: {}",
                silent.detail
            );
        }
        assert!(
            silent.manual_fix.is_none(),
            "a fix line would promise a repair for something not shown to be broken: {:?}",
            silent.manual_fix
        );
        assert!(!blocks_readiness(&silent));
    }

    /// The one arm of this row that judges, and the control that keeps it from
    /// judging everything.
    ///
    /// A file the graph is answering about from an earlier parse is the case
    /// this row's own doc comment said it could not see: not a side-effect
    /// script, not a re-export, not a comment-only file, but source on disk that
    /// does not parse, whose every span and reference describes bytes that are
    /// gone. It goes to attention with the path named and a next step. A silent
    /// file, in the same run, still does not.
    #[test]
    fn a_file_retained_from_an_earlier_parse_needs_attention_and_names_its_next_step() {
        let retained = parse_coverage_health(&kin_core::reference_coverage::ParseCoverageCensus {
            languages: vec![retained_census_row("python", 2, 1)],
        });
        assert!(
            needs_attention(&retained),
            "a file answering from bytes it no longer has is a gap, not a count: {:?}",
            retained.status
        );
        assert!(
            !blocks_readiness(&retained),
            "the graph is still answering, so this must not fail readiness: {:?}",
            retained.status
        );
        assert!(
            retained.detail.contains("python 1/2"),
            "the numerator excludes the retained file: {}",
            retained.detail
        );
        assert!(
            retained.detail.contains("search.py (4 parse errors)"),
            "the row names the path and the reconciler's own count: {}",
            retained.detail
        );
        let fix = retained
            .manual_fix
            .as_deref()
            .expect("a gap a person can close carries the step that closes it");
        assert!(
            fix.contains("search.py") && fix.contains("kin admit"),
            "{fix}"
        );

        // The control, and it is the half that matters: a silent file is not
        // this case. A row that went to attention on every census would say
        // nothing, and the paragraph above it explains at length why.
        let silent = parse_coverage_health(&kin_core::reference_coverage::ParseCoverageCensus {
            languages: vec![parse_census_row("javascript", 141, 75)],
        });
        assert!(
            !needs_attention(&silent),
            "75 files that declare nothing is not 75 defects: {:?}",
            silent.status
        );
        assert!(silent.manual_fix.is_none());
    }

    /// A store holding both populations reports both.
    ///
    /// The retained arm used to return before the silent one ran, so exactly the
    /// store worth reading, one broken file among seventy-five that declare
    /// nothing, lost the larger half of its own row. The verdict still comes
    /// from the retained set alone.
    #[test]
    fn a_store_holding_both_a_retained_file_and_silent_ones_reports_both() {
        let row = parse_coverage_health(&kin_core::reference_coverage::ParseCoverageCensus {
            languages: vec![
                retained_census_row("python", 2, 1),
                parse_census_row("javascript", 141, 75),
            ],
        });
        assert!(needs_attention(&row), "{:?}", row.status);
        for expected in [
            "search.py (4 parse errors)",
            "lib/express.js",
            "python 1/2",
            "javascript 66/141",
        ] {
            assert!(
                row.detail.contains(expected),
                "the row must carry {expected}: {}",
                row.detail
            );
        }
        assert!(
            row.manual_fix
                .as_deref()
                .is_some_and(|fix| fix.contains("search.py") && !fix.contains("express.js")),
            "the fix names only what a person can fix: {:?}",
            row.manual_fix
        );
    }

    /// A daemon that never measured parse coverage and a store whose files are
    /// all parsed must not render the same. The first is unread and the second
    /// is a verdict, and collapsing them is how an all-clear gets printed about
    /// a store nobody looked at.
    #[test]
    fn a_store_admitting_no_parsable_file_is_not_the_same_row_as_one_nobody_measured() {
        let empty = parse_coverage_health(&kin_core::reference_coverage::ParseCoverageCensus {
            languages: Vec::new(),
        });
        assert!(matches!(empty.status, HealthStatus::Healthy));
        assert!(
            empty.detail.contains("admits no file"),
            "an empty census says why it is empty: {}",
            empty.detail
        );

        let unread = parse_coverage_row_for_unread_graph(&GraphStatusForRun::NoDaemon)
            .expect_err("no daemon is not an answered status");
        assert!(matches!(unread.status, HealthStatus::Unsupported));
        assert!(
            !unread.detail.contains("admits no file"),
            "an unread graph must not borrow the words of a measured one: {}",
            unread.detail
        );
    }

    /// FIR-2938. The row names the provider only when the credential records
    /// one, and words it as what the login asked for, because the exchange
    /// response carries none and "signed in with github" would be a claim the
    /// client cannot make. The absent arm is the one that matters: an older
    /// credential must not read as Google.
    #[test]
    fn the_kinlab_row_names_a_recorded_provider_and_invents_none() {
        let named = kinlab_connect_detail("https://kinlab.ai", Some("github"));
        assert!(named.contains("https://kinlab.ai"), "{named}");
        assert!(named.contains("github"), "{named}");
        assert!(
            named.contains("asked for"),
            "the row must not claim more than the client knows: {named}"
        );

        let unnamed = kinlab_connect_detail("https://kinlab.ai", None);
        assert!(unnamed.contains("https://kinlab.ai"), "{unnamed}");
        for provider in ["google", "github"] {
            assert!(
                !unnamed.contains(provider),
                "a credential naming no provider must name none: {unnamed}"
            );
        }
    }
}
