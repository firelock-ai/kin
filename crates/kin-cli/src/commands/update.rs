// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use fs2::FileExt;
use semver::Version;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
#[cfg(unix)]
use std::ffi::CString;
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::Command;
use std::time::Duration;
use sysinfo::{Pid, System};

#[cfg(windows)]
#[path = "update_windows.rs"]
pub(crate) mod windows_update;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_RELEASES_LATEST_URL: &str =
    "https://api.github.com/repos/firelock-ai/kin/releases/latest";
const GITHUB_RELEASES_LIST_URL: &str =
    "https://api.github.com/repos/firelock-ai/kin/releases?per_page=30";
const GITHUB_GIT_REF_TAGS_URL: &str = "https://api.github.com/repos/firelock-ai/kin/git/ref/tags/";
const GITHUB_GIT_TAGS_URL: &str = "https://api.github.com/repos/firelock-ai/kin/git/tags/";
const MAX_ANNOTATED_TAG_DEPTH: usize = 8;
const UPDATE_CHECK_SCHEMA: &str = "kin.update-check.v1";
const UPDATE_HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const UPDATE_HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_RELEASE_METADATA_BYTES: usize = 4 * 1024 * 1024;
const MAX_GIT_OBJECT_BYTES: usize = 256 * 1024;
const MAX_CHECKSUMS_BYTES: usize = 256 * 1024;
const MAX_PROVENANCE_BYTES: usize = 1024 * 1024;
const MAX_RELEASE_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;
const MAX_ARCHIVE_ENTRY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ARCHIVE_EXPANDED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 256;
const MAX_TAR_FORMAT_OVERHEAD_BYTES: u64 = 2 * 1024 * 1024;

const _: () = {
    assert!(MAX_GIT_OBJECT_BYTES < MAX_RELEASE_METADATA_BYTES);
    assert!(MAX_CHECKSUMS_BYTES < MAX_RELEASE_METADATA_BYTES);
    assert!(MAX_PROVENANCE_BYTES <= MAX_RELEASE_METADATA_BYTES);
    assert!(MAX_RELEASE_METADATA_BYTES < MAX_RELEASE_ARCHIVE_BYTES);
    assert!(MAX_ARCHIVE_ENTRY_BYTES <= MAX_ARCHIVE_EXPANDED_BYTES);
};

#[derive(Clone, Copy)]
struct ArchiveSizeLimits {
    compressed_bytes: usize,
    entry_bytes: u64,
    expanded_bytes: u64,
}

const RELEASE_ARCHIVE_LIMITS: ArchiveSizeLimits = ArchiveSizeLimits {
    compressed_bytes: MAX_RELEASE_ARCHIVE_BYTES,
    entry_bytes: MAX_ARCHIVE_ENTRY_BYTES,
    expanded_bytes: MAX_ARCHIVE_EXPANDED_BYTES,
};

/// Expected checksums-manifest asset name published with every release.
/// Releases do not publish a detached signature, so integrity verification
/// is checksum-only — see `verify_sha256`/`verify_archive_checksum` below.
const CHECKSUMS_ASSET: &str = "checksums-sha256.txt";
const TRANSACTION_PREFIX: &str = ".update-backup-";
const STAGING_PREFIX: &str = ".update-stage-";
const TRANSACTION_JOURNAL: &str = "journal.json";
const RESTART_ACK_REQUIRED_FILE: &str = "update-restart-ack-required.json";
const RESTART_MARKER_SCHEMA_VERSION: u32 = 3;
const RESTART_FENCE_REASON: &str = "all managed daemon, supervisor, MCP, VFS, and NFS serving executables were proven quiescent before remote preflight and again before the durable update commit; acknowledgement confirms the persisted process fence and installed byte identities, not version text";
const MCP_REPAIR_PENDING_FILE: &str = "update-mcp-repair-pending.json";
const MCP_REPAIR_MARKER_SCHEMA_VERSION: u32 = 3;
const PRIVATE_TEMP_CONTAINER: &str = ".kin-update-private";
const PREFLIGHT_TEMP_PREFIX: &str = ".kin-update-preflight-";
const PRIVATE_TEMP_RECLAIM_PREFIX: &str = ".kin-update-reclaim-";
const TEMP_LEASE_FILE: &str = ".kin-update-lease.json";
const TEMP_LEASE_SCHEMA_VERSION: u32 = 1;
const MAX_TEMP_LEASE_BYTES: u64 = 16 * 1024;
const MAX_TEMP_LEASE_SCAN_ENTRIES: usize = 1024;
const UNLEASED_TEMP_GRACE: Duration = Duration::from_secs(5 * 60);

fn is_canonical_random_uuid_suffix(name: &str, prefix: &str) -> bool {
    let Some(id) = name.strip_prefix(prefix) else {
        return false;
    };
    uuid::Uuid::parse_str(id).is_ok_and(|parsed| {
        parsed.get_version() == Some(uuid::Version::Random) && parsed.hyphenated().to_string() == id
    })
}

#[cfg(unix)]
fn is_updater_journal_temp_name(name: &str) -> bool {
    is_canonical_random_uuid_suffix(name, ".journal.json.tmp-")
}

#[cfg(unix)]
fn is_updater_journal_quarantine_name(name: &str) -> bool {
    is_canonical_random_uuid_suffix(name, ".journal.json.quarantine-")
}

#[cfg(unix)]
fn is_updater_journal_scratch_name(name: &str) -> bool {
    is_updater_journal_temp_name(name) || is_updater_journal_quarantine_name(name)
}

#[derive(serde::Deserialize)]
struct GithubRelease {
    tag_name: String,
    /// GitHub marks any tag containing `-` (e.g. `-alpha`/`-beta`/`-rc`) as a
    /// pre-release. Used to select builds for the alpha channel.
    #[serde(default)]
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct GithubGitObject {
    sha: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Debug, serde::Deserialize)]
struct GithubGitObjectEnvelope {
    object: GithubGitObject,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReleaseExpectation {
    version: Version,
    commit_sha: String,
    archive_sha256: String,
}

impl ReleaseExpectation {
    fn from_options(
        version: Option<Version>,
        commit_sha: Option<String>,
        archive_sha256: Option<String>,
    ) -> Result<Option<Self>> {
        match (version, commit_sha, archive_sha256) {
            (None, None, None) => Ok(None),
            (Some(version), Some(commit_sha), Some(archive_sha256)) => Ok(Some(Self {
                version,
                commit_sha: parse_expected_commit_sha(&commit_sha).map_err(anyhow::Error::msg)?,
                archive_sha256: parse_expected_archive_sha256(&archive_sha256)
                    .map_err(anyhow::Error::msg)?,
            })),
            _ => anyhow::bail!(
                "--expect-version, --expect-sha, and --expect-archive-sha256 must be provided together"
            ),
        }
    }

    fn validate_selected_release(
        &self,
        selected_version: &Version,
        selected_commit_sha: &str,
    ) -> Result<()> {
        if selected_version != &self.version {
            anyhow::bail!(
                "selected release v{selected_version} does not match pinned version v{}",
                self.version
            );
        }
        if selected_commit_sha != self.commit_sha {
            anyhow::bail!(
                "selected release commit {selected_commit_sha} does not match pinned commit {}",
                self.commit_sha
            );
        }
        Ok(())
    }

    fn validate_archive_bytes(&self, archive_bytes: &[u8]) -> Result<()> {
        let actual = hex::encode(Sha256::digest(archive_bytes));
        if actual != self.archive_sha256 {
            anyhow::bail!(
                "downloaded platform archive SHA-256 does not match the externally attestation-derived expected archive SHA-256.\n\
                 Expected: {}\n\
                 Got:      {actual}\n\
                 The version and tag-commit pins select a release but do not authenticate archive bytes. Aborting before install authority.",
                self.archive_sha256
            );
        }
        Ok(())
    }

    fn validate_selected_archive_sha256(&self, selected_archive_sha256: &str) -> Result<()> {
        if selected_archive_sha256 != self.archive_sha256 {
            anyhow::bail!(
                "selected platform archive checksum {selected_archive_sha256} does not match the externally attestation-derived expected archive SHA-256 {}",
                self.archive_sha256
            );
        }
        Ok(())
    }
}

/// Parse and normalize the exact Git commit accepted by updater automation.
/// Kept public so clap and direct callers share one fail-closed contract.
pub fn parse_expected_commit_sha(value: &str) -> std::result::Result<String, String> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("expected a 40-character hexadecimal Git commit SHA".to_string());
    }
    Ok(value.to_ascii_lowercase())
}

/// Parse and normalize the external byte-authority platform-archive digest
/// accepted by updater automation. Kept public so clap and direct callers share
/// one fail-closed contract.
pub fn parse_expected_archive_sha256(value: &str) -> std::result::Result<String, String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("expected a 64-character hexadecimal SHA-256 archive digest".to_string());
    }
    Ok(value.to_ascii_lowercase())
}

/// Release channel selected for `kin update`.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    /// Stable releases only. The default.
    #[default]
    Stable,
    /// Latest pre-release (alpha/beta/rc) build. Unstable — not for production.
    Alpha,
}

fn channel_name(channel: Channel) -> &'static str {
    match channel {
        Channel::Stable => "stable",
        Channel::Alpha => "alpha",
    }
}

/// How an available update is allowed to reach this machine.
///
/// Updating is not a background detail here. Kin's binaries sit under live
/// agent sessions, daemons part-way through embedding, MCP servers bound into
/// running CLIs, and VFS shims mapped into other processes. Swapping bytes out
/// from under all of that without being asked is the mechanism that produces
/// the stale-runtime drift the watchdog then reports, so the default is to ask.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum UpdatePolicy {
    /// Install unattended, but only when the machine is provably idle. The
    /// default is not this: a silent swap under live sessions is exactly the
    /// failure this policy exists to bound.
    Auto,
    /// Notify with the remedy attached and install when the person says so.
    #[default]
    Prompt,
    /// Never notify about an available update. Checks still run.
    Manual,
}

fn policy_name(policy: UpdatePolicy) -> &'static str {
    match policy {
        UpdatePolicy::Auto => "auto",
        UpdatePolicy::Prompt => "prompt",
        UpdatePolicy::Manual => "manual",
    }
}

/// What the machine is doing, as far as the updater could actually tell.
///
/// `readable` is the field that matters. Every other flag is only meaningful
/// once the probe that produced it is known to have run, and a probe that could
/// not answer is not evidence of an idle machine. Collapsing an unreadable
/// signal into `false` is how an unattended install lands mid-session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MachineActivity {
    /// A managed daemon, MCP server, or VFS process is alive.
    pub managed_runtimes_active: bool,
    /// An agent or user session is open against the daemon.
    pub external_sessions: bool,
    /// A store holds work part-way done, such as pending embeddings.
    pub work_in_flight: bool,
    /// Whether the probes above actually answered.
    pub readable: bool,
}

/// What an unattended check decided to do about an available update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AutoDecision {
    /// Install now, unattended.
    Proceed,
    /// Do not install unattended; notify and let the person choose.
    Prompt(&'static str),
    /// Say nothing. The person asked not to be told.
    Silent(&'static str),
}

impl AutoDecision {
    /// The reason a machine was not updated unattended, for the log and the
    /// notification body. `Proceed` has no reason to give.
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            Self::Proceed => None,
            Self::Prompt(reason) | Self::Silent(reason) => Some(reason),
        }
    }
}

/// Decide how an available update reaches the machine. Pure, so the rule can be
/// tested without a daemon, a network, or an install root.
///
/// Auto never proceeds on a machine it could not read. That asymmetry is the
/// whole point: refusing to install when the answer is unknown costs a person
/// one button press, and installing on an unknown answer costs whatever the
/// running session was doing.
pub fn decide_auto_update(policy: UpdatePolicy, activity: MachineActivity) -> AutoDecision {
    match policy {
        UpdatePolicy::Manual => AutoDecision::Silent("update policy is manual"),
        UpdatePolicy::Prompt => AutoDecision::Prompt("update policy is prompt"),
        UpdatePolicy::Auto => {
            if !activity.readable {
                AutoDecision::Prompt("could not read whether this machine was busy")
            } else if activity.external_sessions {
                AutoDecision::Prompt("an agent or user session is open")
            } else if activity.managed_runtimes_active {
                AutoDecision::Prompt("a managed Kin process is still running")
            } else if activity.work_in_flight {
                AutoDecision::Prompt("a store is part-way through indexing")
            } else {
                AutoDecision::Proceed
            }
        }
    }
}

/// One step of the chain that brings a drifted machine current.
///
/// The chain exists because the drift a person is shown is not the work. Seven
/// reported rows routinely reduce to these steps, and asking someone to run
/// three commands in the right order, from the right binary, is how a machine
/// stays half-updated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainStep {
    /// Download, verify, and install the release.
    Install,
    /// Acknowledge the restart fence. This one cannot run in the process that
    /// started the chain: the fence validates the acknowledging binary's own
    /// version and build sha against the marker, so the old binary can never
    /// satisfy it. The chain re-invokes the freshly installed `kin` for it.
    AcknowledgeRestart,
    /// Repair agent MCP configs and the rest of `kin setup doctor --fix`.
    RepairConfigs,
}

impl ChainStep {
    /// The full chain, in the only order that works.
    pub const ORDER: [Self; 3] = [Self::Install, Self::AcknowledgeRestart, Self::RepairConfigs];

    /// What this step will do, for `--dry-run` and for the report afterwards.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Install => "install the release",
            Self::AcknowledgeRestart => "acknowledge the restart fence",
            Self::RepairConfigs => "repair agent configs",
        }
    }

    /// The command a person would otherwise have typed. Printed by `--dry-run`
    /// so the gesture is never a black box, and so the chain stays auditable
    /// against what it claims to be a shortcut for.
    pub fn command(self) -> &'static str {
        match self {
            Self::Install => "kin update",
            Self::AcknowledgeRestart => "kin update --ack-restart",
            Self::RepairConfigs => "kin setup doctor --fix",
        }
    }

    /// Whether the step must run from the newly installed binary rather than
    /// from the process that began the chain.
    pub fn needs_installed_binary(self) -> bool {
        matches!(self, Self::AcknowledgeRestart | Self::RepairConfigs)
    }
}

/// The chain a machine actually needs, given what the check found.
///
/// A machine with no available update and no pending fence still has a chain
/// when its configs drifted, and running the install step there would download
/// a release it already has. Selecting the steps from the observed state is
/// what keeps one gesture honest across all of those cases.
pub fn chain_plan(
    update_available: bool,
    restart_ack_required: bool,
    configs_drifted: bool,
) -> Vec<ChainStep> {
    let mut plan = Vec::new();
    if update_available {
        plan.push(ChainStep::Install);
    }
    // An install writes the fence, so the acknowledgement belongs to the plan
    // whenever the install is in it, not only when a fence is already pending.
    if update_available || restart_ack_required {
        plan.push(ChainStep::AcknowledgeRestart);
    }
    if update_available || configs_drifted {
        plan.push(ChainStep::RepairConfigs);
    }
    plan
}

/// Persisted update preferences, stored at `~/.kin/update.toml`.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct UpdateConfig {
    #[serde(default)]
    channel: Channel,
    #[serde(default)]
    policy: UpdatePolicy,
}

impl UpdateConfig {
    #[cfg(test)]
    fn path() -> Result<PathBuf> {
        Ok(crate::commands::setup::kin_dir()?.join("update.toml"))
    }

    /// Load stored preferences, falling back to defaults on any missing file or
    /// parse error (the preference is advisory, never a hard failure).
    fn load_from(kin_home: &Path) -> Self {
        std::fs::read_to_string(kin_home.join("update.toml"))
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save_to(&self, _kin_home: &Path, _lock: Option<&InstallRootLock>) -> Result<()> {
        let contents = toml::to_string_pretty(self).context("failed to serialize update config")?;
        #[cfg(unix)]
        {
            let install = _lock
                .context("update config mutation requires the held install lock")?
                .install()?;
            install
                .root
                .atomic_write_checked("update.toml", contents.as_bytes(), 0o600, || {
                    install.ensure_bound()
                })
                .context("failed to persist anchored update config")?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let path = _kin_home.join("update.toml");
            write_file_atomically(&path, contents.as_bytes(), 0o600)
                .with_context(|| format!("failed to write {}", path.display()))?;
            Ok(())
        }
    }
}

/// Resolve the effective channel: an explicit `--channel` flag wins and, for a
/// mutating update, is saved as the new default. Check-only calls pass
/// `persist = false` so their filesystem contract remains read-only.
#[cfg(test)]
fn resolve_channel(kin_home: &Path, flag: Option<Channel>, quiet: bool, persist: bool) -> Channel {
    resolve_channel_locked(kin_home, flag, quiet, persist, None)
}

fn resolve_channel_locked(
    kin_home: &Path,
    flag: Option<Channel>,
    quiet: bool,
    persist: bool,
    lock: Option<&InstallRootLock>,
) -> Channel {
    let config = UpdateConfig::load_from(kin_home);
    let stored = config.channel;
    if let Some(requested) = flag {
        if persist && requested != stored {
            // The whole file is rewritten, so every field it already carried is
            // read back and passed through. Constructing a fresh config here
            // would silently reset the update policy every time a channel
            // changed, which is the one preference that must never move on its
            // own.
            let updated = UpdateConfig {
                channel: requested,
                policy: config.policy,
            };
            // Persisting is best-effort: a write failure must not block the update.
            match updated.save_to(kin_home, lock) {
                Ok(()) if !quiet => {
                    println!("Saved default update channel: {}", channel_name(requested))
                }
                Ok(()) => {}
                Err(e) if !quiet => {
                    eprintln!("Note: could not persist update channel preference: {e}")
                }
                Err(_) => {}
            }
        }
    }
    effective_channel(flag, stored)
}

/// Pure channel-precedence rule (flag over stored default), split out for tests.
fn effective_channel(flag: Option<Channel>, stored: Channel) -> Channel {
    flag.unwrap_or(stored)
}

/// Persist how updates are allowed to reach this machine.
///
/// This is the one preference that decides whether bytes move without being
/// asked, so it is only ever set by an explicit request. Nothing else in the
/// updater writes it, and the channel path reads it back and passes it through
/// rather than reconstructing the file.
fn set_update_policy(policy: UpdatePolicy) -> Result<()> {
    let requested_home = crate::commands::setup::kin_dir()?;
    let lock = InstallRootLock::acquire_existing(&requested_home)?;
    let stored = UpdateConfig::load_from(lock.root());
    if stored.policy == policy {
        println!("Update policy is already {}.", policy_name(policy));
        return Ok(());
    }
    UpdateConfig {
        channel: stored.channel,
        policy,
    }
    .save_to(lock.root(), Some(&lock))
    .context("failed to persist the update policy")?;
    println!(
        "Update policy: {} (was {}).",
        policy_name(policy),
        policy_name(stored.policy)
    );
    if policy == UpdatePolicy::Auto {
        println!(
            "Unattended installs run only when no agent session, managed Kin process, or \
             part-way indexing job is detected. When that cannot be determined, Kin asks instead."
        );
    }
    Ok(())
}

/// Print the ordered chain without running any of it.
///
/// The gesture a person triggers from a notification has to be inspectable
/// before they trigger it, and afterwards has to be checkable against what it
/// claimed it would do.
fn print_chain_plan(plan: &[ChainStep]) {
    if plan.is_empty() {
        println!("Nothing to apply: this machine is already current.");
        return;
    }
    println!("kin update --apply would run {} step(s):", plan.len());
    for (index, step) in plan.iter().enumerate() {
        println!(
            "  {}. {} ({})",
            index + 1,
            step.describe(),
            step.command()
        );
    }
    println!(
        "Steps after the install run from the newly installed binary, because the restart fence \
         validates the acknowledging binary's own identity."
    );
}

fn ensure_pinned_channel_unchanged(preflight: Channel, locked: Channel) -> Result<()> {
    if preflight != locked {
        anyhow::bail!(
            "update channel changed during pinned remote preflight ({} -> {}); refusing to install the preflighted release",
            channel_name(preflight),
            channel_name(locked)
        );
    }
    Ok(())
}

#[derive(Clone, Debug, serde::Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

struct PreparedPinnedRelease {
    release: GithubRelease,
    version: Version,
    commit_sha: String,
    archive_name: String,
    archive_bytes: Vec<u8>,
    provenance: ArtifactProvenance,
    provenance_identities: VerifiedStagedIdentities,
}

impl PreparedPinnedRelease {
    fn asset(&self) -> Result<&GithubAsset> {
        find_release_asset(&self.release, &self.archive_name)
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct ArtifactProvenance {
    schema_version: u32,
    release_tag: String,
    artifact: String,
    target: String,
    vfs_target: String,
    kin: KinProvenance,
    kin_vfs: VfsProvenance,
    archive: ProvenanceArchive,
    archive_contents: Vec<ProvenanceFile>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct KinProvenance {
    commit: String,
    cargo_lock_sha256: String,
    embedded_dependency_provenance: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct VfsProvenance {
    commit: String,
    dirty: bool,
    cargo_lock_sha256: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct ProvenanceArchive {
    name: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct ProvenanceFile {
    name: String,
    sha256: String,
    size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    build_identity: Option<StaticBuildIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct StaticBuildIdentity {
    schema: String,
    version: String,
    commit: String,
    clean: bool,
    source_known: bool,
    dependency_provenance: String,
    graph_snapshot_version: u32,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RestartPending {
    schema_version: u32,
    installed_version: String,
    kin_commit: String,
    dependency_provenance: String,
    kin_vfs_commit: String,
    recorded_at: String,
    recorded_at_unix_seconds: u64,
    /// Exact managed runtime path, byte, and filesystem-object identities
    /// captured only after the transaction crossed its durable commit point
    /// and a fresh process scan proved every managed server was quiescent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit_runtime_fence: Option<Vec<RuntimeCommitIdentity>>,
    reason: String,
    runtime_obligations: Vec<RuntimeRestartObligation>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeCommitIdentity {
    kind: RuntimeKind,
    component: String,
    path: PathBuf,
    identity: FileIdentity,
    object: PlatformObjectIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeKind {
    Daemon,
    Mcp,
    Vfs,
}

impl RuntimeKind {
    fn label(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Mcp => "mcp",
            Self::Vfs => "vfs",
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRestartObligation {
    kind: RuntimeKind,
    component: String,
    expected_identity: FileIdentity,
    prior_sessions: Vec<RuntimeSessionAtUpdate>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeSessionAtUpdate {
    pid: u32,
    start_time: u64,
    executable: PathBuf,
    executable_identity: FileIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<PathBuf>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct McpRepairPending {
    schema_version: u32,
    installed_version: String,
    recorded_at: String,
    repair_required: bool,
    targets: Vec<crate::commands::setup::McpRepairTarget>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RuntimeSessionEvidence {
    kind: RuntimeKind,
    pid: u32,
}

#[derive(Debug, serde::Serialize)]
struct UpdateCheck<'a> {
    schema: &'static str,
    current_version: &'a str,
    latest_version: &'a str,
    release_tag: &'a str,
    release_commit_sha: &'a str,
    channel: &'a str,
    /// How an available update is allowed to reach this machine. The watchdog
    /// reads it here rather than parsing `update.toml`, so the policy has one
    /// definition and one reader instead of two encodings that drift.
    update_policy: &'a str,
    update_available: bool,
    platform_asset: &'a str,
    platform_archive_sha256: &'a str,
    restart_ack_required: bool,
    mcp_repair_pending: bool,
}

/// `kin update`, plus the two gestures built on top of it: setting the policy,
/// and applying the whole remedy chain at once.
///
/// The chain's later steps deliberately run as fresh processes rather than as
/// more code in this one. The restart fence validates the acknowledging
/// binary's own version and build sha against the marker the install wrote, so
/// the process that performed the install can never satisfy it. Re-invoking the
/// installed binary is not a convenience here, it is the only ordering the
/// fence accepts.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    skip_verify: bool,
    channel_flag: Option<Channel>,
    expect_version: Option<Version>,
    expect_sha: Option<String>,
    expect_archive_sha256: Option<String>,
    check_only: bool,
    json: bool,
    ack_restart: bool,
    runtime_sessions: Vec<String>,
    set_policy: Option<UpdatePolicy>,
    apply: bool,
    dry_run: bool,
) -> Result<()> {
    // Setting the policy is a preference write and nothing else. It runs before
    // any expectation parsing, network client, or install-root inspection so
    // that changing how updates arrive never depends on one being available.
    if let Some(policy) = set_policy {
        return set_update_policy(policy);
    }
    if dry_run && !apply {
        anyhow::bail!("--dry-run describes what --apply would do; pass both or neither");
    }

    run_update_flow(
        skip_verify,
        channel_flag,
        expect_version,
        expect_sha,
        expect_archive_sha256,
        check_only,
        json,
        ack_restart,
        runtime_sessions,
        apply,
        dry_run,
    )
    .await?;

    if apply && !dry_run {
        return run_chain_tail();
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_update_flow(
    skip_verify: bool,
    channel_flag: Option<Channel>,
    expect_version: Option<Version>,
    expect_sha: Option<String>,
    expect_archive_sha256: Option<String>,
    check_only: bool,
    json: bool,
    ack_restart: bool,
    runtime_sessions: Vec<String>,
    apply: bool,
    dry_run: bool,
) -> Result<()> {
    // A dry run of the chain is a read. Forcing the check-only path is what
    // makes that a property of the code rather than a promise in the help text:
    // every mutation below is already gated on `!check_only`.
    let plan_only = apply && dry_run;
    let check_only = check_only || plan_only;

    let expectation =
        ReleaseExpectation::from_options(expect_version, expect_sha, expect_archive_sha256)?;
    if ack_restart && expectation.is_some() {
        anyhow::bail!("release pins cannot be used with --ack-restart");
    }
    if skip_verify && expectation.is_some() {
        anyhow::bail!(
            "release pins require checksum and provenance verification; remove --skip-verify"
        );
    }
    ensure_mutating_update_supported(std::env::consts::OS, check_only)?;
    registry_authority_preflight()?;
    if ack_restart {
        return acknowledge_runtime_restart(&parse_runtime_session_evidence(&runtime_sessions)?);
    }

    // Check-only must remain byte-for-byte read-only. It inspects a stale
    // transaction and fails with a recovery instruction. An interactive
    // mutation keeps its existing lock-before-network behavior. A pinned
    // unattended mutation performs only a no-follow, read-only restart-marker
    // existence fence before network preflight, then acquires and revalidates
    // the install authority before any managed mutation.
    let requested_home = crate::commands::setup::kin_dir()?;
    let inspected_home = validate_existing_install_root(&requested_home)?;
    let spec = platform_bundle_spec(std::env::consts::OS)?;
    let stale = transaction_dirs(&inspected_home)?;
    let pinned_mutation = !check_only && expectation.is_some();
    if check_only && !stale.is_empty() {
        anyhow::bail!(
            "an interrupted Kin update requires recovery at {}. Run `kin update` without \
             --check-only; this check did not modify any file",
            stale[0].display()
        );
    }
    if pinned_mutation && !stale.is_empty() {
        anyhow::bail!(
            "an interrupted Kin update requires local recovery at {} before pinned remote preflight. Run `kin update` once without release pins, then retry the pinned update",
            stale[0].display()
        );
    }
    if pinned_mutation {
        // This fence must not create or harden update.lock, chmod KIN_HOME, or
        // create bin/lib on a pin mismatch or remote failure. The locked check
        // after authenticated preflight closes the race before mutation.
        refuse_restart_marker_before_remote_preflight(&inspected_home)?;
    }
    if !check_only {
        ensure_no_active_managed_runtimes(&inspected_home, spec).context(
            "initial update preflight requires every managed serving executable to be stopped; no recovery, cleanup, repair, preference mutation, or release download was attempted",
        )?;
    }

    // Capture the exact full installed generation and a durable handle to the
    // process' mapped executable before constructing an HTTP client or making
    // any network request. A stale interactive install is recovered under its
    // lock first, then captured before that flow reaches the network.
    let mut start_authority = if stale.is_empty() {
        Some(UpdaterStartAuthority::capture(&inspected_home, spec)?)
    } else {
        None
    };
    let mut held_lock = None;
    let kin_home = if check_only || pinned_mutation {
        inspected_home
    } else {
        let lock = InstallRootLock::acquire_existing(&requested_home)?;
        refuse_new_update_while_restart_marker_exists(&lock)?;
        if let Some(authority) = start_authority.as_ref() {
            authority.verify_locked(&lock, spec)?;
        }
        recover_stale_transactions(&lock, spec)?;
        refuse_new_update_while_restart_marker_exists(&lock)?;
        cleanup_stale_staging_dirs(&lock)?;
        if start_authority.is_none() {
            start_authority = Some(UpdaterStartAuthority::capture(lock.root(), spec)?);
        }
        start_authority
            .as_ref()
            .context("updater lost its startup authority")?
            .verify_locked(&lock, spec)?;
        attempt_pending_mcp_repair(&lock)?;
        let root = lock.root().to_path_buf();
        held_lock = Some(lock);
        root
    };
    let channel = resolve_channel_locked(
        &kin_home,
        channel_flag,
        json,
        !check_only && !pinned_mutation,
        held_lock.as_ref(),
    );

    if !json {
        println!("Current version: v{CURRENT_VERSION}");
        match channel {
            Channel::Stable => println!("Update channel: stable"),
            Channel::Alpha => {
                println!("Update channel: alpha (pre-release)");
                eprintln!(
                    "WARNING: alpha builds are pre-releases. They are unstable, may change \
                     or break without notice, and are not recommended for production use. \
                     Switch back with `kin update --channel stable`."
                );
            }
        }
        println!("Checking for updates...");
    }

    let client = build_update_http_client()?;

    if pinned_mutation {
        let expectation = expectation
            .as_ref()
            .context("pinned update lost its release expectation")?;
        let preflight =
            prepare_pinned_release(&client, channel, expectation, &requested_home, spec).await;
        let (lock, prepared) =
            enter_pinned_install_phase(&requested_home, spec, start_authority.as_ref(), preflight)?;
        let kin_home = lock.root().to_path_buf();
        let persisted_channel =
            resolve_channel_locked(&kin_home, channel_flag, json, true, Some(&lock));
        ensure_pinned_channel_unchanged(channel, persisted_channel)?;

        let latest = prepared.version.to_string();
        let current_version = parse_release_version(CURRENT_VERSION)?;
        let update_available = prepared.version > current_version;
        let restart_ack_required = restart_pending_path(&kin_home).exists();
        if !update_available {
            println!("Already up to date (v{CURRENT_VERSION}).");
            if restart_ack_required {
                println!(
                    "Runtime restart acknowledgement remains required: {}",
                    restart_pending_path(&kin_home).display()
                );
            }
            if mcp_repair_pending_path(&kin_home).exists() {
                println!(
                    "MCP launcher repair remains pending: {}",
                    mcp_repair_pending_path(&kin_home).display()
                );
            }
            return Ok(());
        }

        println!("New version available: v{latest}");
        println!(
            "Using preflight-verified {} after matching its external byte-authority digest (release commit {}).",
            prepared.archive_name, prepared.commit_sha
        );
        let asset = prepared.asset()?;
        let staging = StagingDir::create(&lock)?;
        stage_archive_locked(&lock, &staging, &prepared.archive_bytes, &asset.name, spec)?;
        validate_staged_artifact_provenance(
            staging.path(),
            spec,
            &prepared.provenance_identities,
            true,
        )?;
        validate_staged_static_build_identity(staging.path(), spec, &latest, &prepared.provenance)?;
        start_authority
            .as_ref()
            .context("pinned updater lost its startup authority")?
            .verify_locked(&lock, spec)?;
        let pending_record = restart_pending_record(
            &kin_home,
            &latest,
            &prepared.provenance,
            &prepared.provenance_identities,
            spec,
        )?;
        let outcome = install_staged_bundle_locked(
            &lock,
            &staging,
            spec,
            &prepared.provenance_identities,
            &latest,
            &pending_record,
        )?;
        report_successful_install(&lock, &kin_home, &latest, outcome)?;
        return Ok(());
    }

    let release = resolve_release(&client, channel).await?;

    let latest_version = parse_release_version(&release.tag_name)?;
    let archive_name = current_platform_asset_name()?;
    let asset = find_release_asset(&release, &archive_name)?;
    let release_commit_sha = resolve_release_commit(&client, &release.tag_name).await?;
    if let Some(expectation) = &expectation {
        // Check-only validates release selection without downloading the
        // platform archive. It does not authenticate archive bytes; mutating
        // pinned updates enforce the external byte-authority digest in the
        // stronger prepare_pinned_release path above.
        expectation.validate_selected_release(&latest_version, &release_commit_sha)?;
    }
    let check_archive_sha256 = if check_only {
        let digest = fetch_archive_checksum(&client, &release, &asset.name).await?;
        if let Some(expectation) = &expectation {
            // Check-only deliberately never downloads the release archive. It
            // can still prove that the selected release tuple publishes the
            // externally supplied byte digest; only a mutating pinned update
            // authenticates the actual downloaded archive bytes against it.
            expectation.validate_selected_archive_sha256(&digest)?;
        }
        Some(digest)
    } else {
        None
    };
    let latest = latest_version.to_string();
    let current_version = parse_release_version(CURRENT_VERSION)?;
    let update_available = latest_version > current_version;
    let restart_ack_required = restart_pending_path(&kin_home).exists();
    let mcp_repair_pending = mcp_repair_pending_path(&kin_home).exists();

    if plan_only {
        print_chain_plan(&chain_plan(
            update_available,
            restart_ack_required,
            mcp_repair_pending,
        ));
        return Ok(());
    }

    if check_only {
        let check = UpdateCheck {
            schema: UPDATE_CHECK_SCHEMA,
            current_version: CURRENT_VERSION,
            latest_version: &latest,
            release_tag: &release.tag_name,
            release_commit_sha: &release_commit_sha,
            channel: channel_name(channel),
            update_policy: policy_name(UpdateConfig::load_from(&kin_home).policy),
            update_available,
            platform_asset: &asset.name,
            platform_archive_sha256: check_archive_sha256
                .as_deref()
                .context("check-only lost its selected platform archive checksum")?,
            restart_ack_required,
            mcp_repair_pending,
        };
        if json {
            println!("{}", serde_json::to_string_pretty(&check)?);
        } else if update_available {
            println!("Update available: v{CURRENT_VERSION} -> v{latest}");
        } else {
            println!("Already up to date (v{CURRENT_VERSION}).");
        }
        if restart_ack_required && !json {
            println!(
                "Runtime restart acknowledgement remains required: {}",
                restart_pending_path(&kin_home).display()
            );
        }
        if mcp_repair_pending && !json {
            println!(
                "MCP launcher repair remains pending: {}",
                mcp_repair_pending_path(&kin_home).display()
            );
        }
        return Ok(());
    }

    if !update_available {
        println!("Already up to date (v{CURRENT_VERSION}).");
        if restart_ack_required {
            println!(
                "Runtime restart acknowledgement remains required: {}",
                restart_pending_path(&kin_home).display()
            );
        }
        if mcp_repair_pending_path(&kin_home).exists() {
            println!(
                "MCP launcher repair remains pending: {}",
                mcp_repair_pending_path(&kin_home).display()
            );
        }
        return Ok(());
    }

    println!("New version available: v{latest}");

    ensure_no_active_managed_runtimes(&kin_home, spec).context(
        "update preflight requires every managed serving executable to be stopped; no release archive was downloaded or staged",
    )?;

    println!("Downloading {}...", asset.name);

    let archive_response = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("failed to download release archive")?;
    let archive_bytes = read_bounded_response(
        archive_response,
        MAX_RELEASE_ARCHIVE_BYTES,
        "release archive",
    )
    .await?;

    // --- Integrity verification ---
    if skip_verify {
        eprintln!(
            "WARNING: --skip-verify is set. Skipping checksum verification. \
             This release bundle has NOT been authenticated."
        );
    } else {
        println!("Verifying checksum...");
        verify_archive_checksum(&client, &release, &asset.name, &archive_bytes).await?;
        println!("  SHA-256 checksum verified.");
    }

    let lock = held_lock
        .as_ref()
        .context("mutating update lost its held install lock")?;
    start_authority
        .as_ref()
        .context("mutating updater lost its startup authority")?
        .verify_locked(lock, spec)?;
    let staging = StagingDir::create(lock)?;
    stage_archive_locked(lock, &staging, &archive_bytes, &asset.name, spec)?;
    let provenance = fetch_artifact_provenance(&client, &release, asset).await?;
    let verified_staged_identities = validate_artifact_provenance(
        &provenance,
        &release,
        &release_commit_sha,
        asset,
        &archive_bytes,
        staging.path(),
        spec,
        !skip_verify,
    )?;
    validate_staged_static_build_identity(staging.path(), spec, &latest, &provenance)?;
    start_authority
        .as_ref()
        .context("mutating updater lost its startup authority")?
        .verify_locked(lock, spec)?;
    let pending_record = restart_pending_record(
        &kin_home,
        &latest,
        &provenance,
        &verified_staged_identities,
        spec,
    )?;
    let outcome = install_staged_bundle_locked(
        lock,
        &staging,
        spec,
        &verified_staged_identities,
        &latest,
        &pending_record,
    )?;
    report_successful_install(lock, &kin_home, &latest, outcome)
}

/// The managed `kin` the chain re-invokes. Deliberately the installed path
/// rather than `current_exe`: after an install those are different bytes, and
/// the whole reason the tail exists is to run as the new ones.
fn installed_kin_binary(kin_home: &Path) -> PathBuf {
    let name = if cfg!(windows) { "kin.exe" } else { "kin" };
    kin_home.join("bin").join(name)
}

fn run_chain_step(binary: &Path, step: ChainStep, args: &[&str]) -> Result<()> {
    println!("Applying: {} ({}).", step.describe(), step.command());
    let status = std::process::Command::new(binary)
        .args(args)
        .status()
        .with_context(|| format!("failed to run `{}`", step.command()))?;
    if !status.success() {
        anyhow::bail!(
            "`{}` exited with {}. The chain stopped here, and the steps after it did not run",
            step.command(),
            status
        );
    }
    Ok(())
}

/// Finish the chain after the install, as the newly installed binary.
///
/// Only the acknowledgement is conditional, because the fence refuses outright
/// when no marker is pending, and that refusal would otherwise read as a failed
/// chain rather than as a step with nothing to do. The config repair is
/// idempotent and always runs, so `--apply` converges a machine whose bytes
/// were already current but whose agent configs had drifted.
fn run_chain_tail() -> Result<()> {
    let kin_home = crate::commands::setup::kin_dir()?;
    let binary = installed_kin_binary(&kin_home);
    if !binary.is_file() {
        anyhow::bail!(
            "the update chain cannot continue: no installed kin at {}",
            binary.display()
        );
    }

    if restart_pending_path(&kin_home).exists() {
        run_chain_step(
            &binary,
            ChainStep::AcknowledgeRestart,
            &["update", "--ack-restart"],
        )?;
    } else {
        println!("No restart fence is pending, so there is nothing to acknowledge.");
    }

    run_chain_step(
        &binary,
        ChainStep::RepairConfigs,
        &["setup", "doctor", "--fix"],
    )?;
    Ok(())
}

fn registry_authority_preflight() -> Result<()> {
    kin_core::registry::require_registry_authority_secure().map_err(|error| {
        anyhow::anyhow!(
            "update preflight refused unsafe local registry authority; no release bytes were downloaded: {error}"
        )
    })
}

fn report_successful_install(
    lock: &InstallRootLock,
    kin_home: &Path,
    latest: &str,
    outcome: InstallOutcome,
) -> Result<()> {
    if let Some(backup) = outcome.retained_backup {
        eprintln!(
            "WARNING: update succeeded, but the old-version backup could not be removed: {}",
            backup.display()
        );
    }

    // The transaction replaces the notification bundle by rename, so its path
    // is unchanged while the inode, the code signature, and the `Info.plist`
    // behind it are not. LaunchServices still holds the record it built for the
    // tree that was moved away, and the notification daemon refuses a posting
    // bundle it cannot validate through that record, so the updater owes the
    // same registration `scripts/install.sh` and the npm launcher perform for
    // the copies they write. Only the managed root is registered, because that
    // is the only copy this transaction maintains; an install with no bundle
    // resolves nothing and registers nothing.
    if let Err(error) =
        kin_notify::Notifier::with_home(kin_home.to_path_buf()).register_with_launch_services()
    {
        eprintln!(
            "WARNING: the update installed the notification bundle but could not register it with \
             LaunchServices, so notifications may post as Script Editor until `kin setup` runs \
             again: {error:#}"
        );
    }

    attempt_pending_mcp_repair(lock)?;
    let pending = restart_pending_path(kin_home);
    println!("Installed v{latest} on disk.");
    println!(
        "Restart acknowledgement required: {}. The updater proved that no managed daemon, \
         supervisor, MCP server, VFS server, or NFS server crossed the transaction and recorded \
         the exact installed binary identities. Run `kin update --ack-restart`; no \
         `--runtime-session` arguments are required for this fenced update. This does not attest \
         arbitrary long-lived processes that may have loaded the VFS interposition shim.",
        pending.display()
    );
    Ok(())
}

fn build_update_http_client() -> Result<reqwest::Client> {
    build_update_http_client_with_timeouts(UPDATE_HTTP_CONNECT_TIMEOUT, UPDATE_HTTP_REQUEST_TIMEOUT)
}

fn build_update_http_client_with_timeouts(
    connect_timeout: Duration,
    request_timeout: Duration,
) -> Result<reqwest::Client> {
    if connect_timeout.is_zero() || request_timeout.is_zero() {
        anyhow::bail!("updater HTTP timeouts must be non-zero");
    }
    if connect_timeout > request_timeout {
        anyhow::bail!("updater connect timeout cannot exceed its total request timeout");
    }
    reqwest::Client::builder()
        .user_agent("kin-cli")
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .build()
        .context("failed to build bounded updater HTTP client")
}

fn append_bounded_response_chunk(
    body: &mut Vec<u8>,
    chunk: &[u8],
    max_bytes: usize,
    label: &str,
) -> Result<()> {
    let next_len = body
        .len()
        .checked_add(chunk.len())
        .context("updater response length overflow")?;
    if next_len > max_bytes {
        anyhow::bail!("{label} exceeded the maximum response size of {max_bytes} bytes");
    }
    body.extend_from_slice(chunk);
    Ok(())
}

async fn read_bounded_response(
    response: reqwest::Response,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    let mut response = response
        .error_for_status()
        .with_context(|| format!("{label} returned an HTTP error"))?;
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        anyhow::bail!("{label} declared a response larger than the {max_bytes}-byte limit");
    }
    let capacity = response
        .content_length()
        .unwrap_or_default()
        .min(max_bytes as u64) as usize;
    let mut body = Vec::with_capacity(capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("failed while reading {label}"))?
    {
        append_bounded_response_chunk(&mut body, &chunk, max_bytes, label)?;
    }
    Ok(body)
}

/// Resolve and authenticate every remote input used by a pinned unattended
/// update before the install lock is opened. The selected release, peeled
/// commit, archive bytes, and provenance stay owned by this value across the
/// local lock/recovery boundary, so the mutable channel endpoint is never
/// consulted a second time.
async fn prepare_pinned_release(
    client: &reqwest::Client,
    channel: Channel,
    expectation: &ReleaseExpectation,
    requested_home: &Path,
    spec: &[ComponentSpec],
) -> Result<PreparedPinnedRelease> {
    let release = resolve_release(client, channel).await?;
    let version = parse_release_version(&release.tag_name)?;
    let archive_name = current_platform_asset_name()?;
    let asset = find_release_asset(&release, &archive_name)?.clone();
    let commit_sha = resolve_release_commit(client, &release.tag_name).await?;
    expectation.validate_selected_release(&version, &commit_sha)?;

    println!("Downloading {} for pinned preflight...", asset.name);
    let archive_response = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("failed to download pinned release archive")?;
    let archive_bytes = read_bounded_response(
        archive_response,
        MAX_RELEASE_ARCHIVE_BYTES,
        "pinned release archive",
    )
    .await?;

    println!("Verifying pinned archive against its external byte-authority digest...");
    expectation.validate_archive_bytes(&archive_bytes)?;
    println!("Verifying co-published release checksum and provenance...");
    verify_archive_checksum(client, &release, &asset.name, &archive_bytes).await?;
    let provenance = fetch_artifact_provenance(client, &release, &asset).await?;
    let provenance_identities = validate_artifact_provenance_metadata(
        &provenance,
        &release,
        &commit_sha,
        &asset,
        &archive_bytes,
        spec,
        true,
    )?;
    let provenance_identities = validate_archive_payload_provenance_and_static_identity(
        &archive_bytes,
        &asset.name,
        spec,
        &provenance_identities,
        &provenance,
    )?;
    validate_pinned_preflight_build_identity(
        requested_home,
        &archive_bytes,
        &asset.name,
        spec,
        &version.to_string(),
        &provenance,
        &provenance_identities,
    )?;

    Ok(PreparedPinnedRelease {
        release,
        version,
        commit_sha,
        archive_name,
        archive_bytes,
        provenance,
        provenance_identities,
    })
}

/// Prove the staged release binaries before acquiring install authority. The
/// temporary extraction is a private sibling of KIN_HOME, never a child, and
/// is deleted before this function returns. Only the already-authenticated
/// archive bytes and verified identities cross into the locked install phase.
fn validate_pinned_preflight_build_identity(
    requested_home: &Path,
    archive_bytes: &[u8],
    archive_name: &str,
    spec: &[ComponentSpec],
    expected_version: &str,
    provenance: &ArtifactProvenance,
    provenance_identities: &VerifiedStagedIdentities,
) -> Result<()> {
    if !requested_home.is_absolute() {
        anyhow::bail!(
            "Kin install root must be absolute, got {}",
            requested_home.display()
        );
    }
    let requested_parent = requested_home
        .parent()
        .context("Kin install root has no parent")?;
    let canonical_parent = requested_parent.canonicalize().with_context(|| {
        format!(
            "parent of Kin install root does not exist or is inaccessible: {}",
            requested_parent.display()
        )
    })?;
    let root_name = requested_home
        .file_name()
        .context("Kin install root has no final path component")?;
    let canonical_home = canonical_parent.join(root_name);
    let mut staging =
        PrivateUpdaterTempDir::create(&canonical_parent, PREFLIGHT_TEMP_PREFIX, "created")
            .context("failed to create private pinned-update preflight directory")?;
    if staging.path().starts_with(&canonical_home) {
        anyhow::bail!("pinned-update preflight directory must be outside KIN_HOME");
    }
    staging.persist_status("extracting authenticated release")?;
    staging.validate_root_binding()?;
    stage_archive(archive_bytes, archive_name, staging.path(), spec)?;
    staging.validate_root_binding()?;
    #[cfg(windows)]
    {
        let staging_path = staging.path().to_path_buf();
        staging.seal_staged_bundle(&staging_path, spec)?;
    }
    staging.persist_status("validating staged provenance")?;
    validate_staged_artifact_provenance(staging.path(), spec, provenance_identities, true)?;
    #[cfg(windows)]
    staging.validate_windows()?;
    staging.persist_status("validating staged static build identity")?;
    let result =
        validate_staged_static_build_identity(staging.path(), spec, expected_version, provenance);
    #[cfg(windows)]
    staging.validate_windows()?;
    result
}

/// Convert a successful remote preflight into local mutation authority. The
/// `Result` is deliberately consumed before the install-phase lock is
/// reacquired, so every mismatch, timeout, download error, and provenance
/// failure exits without changing managed install bytes or transaction state.
/// The earlier restart fence was strictly read-only. This phase first creates
/// or opens the persistent update-lock sidecar and revalidates all authority
/// after the unlocked network/temp-staging interval.
fn enter_pinned_install_phase<T>(
    requested_home: &Path,
    spec: &[ComponentSpec],
    start_authority: Option<&UpdaterStartAuthority>,
    preflight: Result<T>,
) -> Result<(InstallRootLock, T)> {
    let prepared = preflight?;
    let start_authority = start_authority.context("pinned updater lost its startup authority")?;
    let lock = InstallRootLock::acquire_existing(requested_home)?;
    refuse_new_update_while_restart_marker_exists(&lock)?;
    // This comparison is the downgrade gate: an updater that spent its remote
    // preflight interval behind a newer concurrent install cannot use its old
    // embedded CURRENT_VERSION to overwrite the new full bundle generation.
    start_authority.verify_locked(&lock, spec)?;
    recover_stale_transactions(&lock, spec)?;
    refuse_new_update_while_restart_marker_exists(&lock)?;
    cleanup_stale_staging_dirs(&lock)?;
    start_authority.verify_locked(&lock, spec)?;
    ensure_no_active_managed_runtimes(lock.root(), spec).context(
        "pinned update install phase requires every managed serving executable to remain stopped",
    )?;
    attempt_pending_mcp_repair(&lock)?;
    Ok((lock, prepared))
}

fn validate_mcp_repair_record(record: &McpRepairPending) -> Result<()> {
    if record.schema_version != MCP_REPAIR_MARKER_SCHEMA_VERSION {
        anyhow::bail!(
            "unsupported MCP repair marker schema {} (only schema {} carries complete exact-target authority)",
            record.schema_version,
            MCP_REPAIR_MARKER_SCHEMA_VERSION,
        );
    }
    parse_release_version(&record.installed_version)?;
    chrono::DateTime::parse_from_rfc3339(&record.recorded_at).with_context(|| {
        format!(
            "MCP repair record has an invalid recorded_at timestamp: {}",
            record.recorded_at
        )
    })?;
    if !record.repair_required {
        if !record.targets.is_empty() {
            anyhow::bail!("no-op MCP repair journal payload unexpectedly contains targets");
        }
        return Ok(());
    }
    if record.targets.is_empty() {
        anyhow::bail!("MCP repair obligation has an empty target manifest");
    }
    let normalized = crate::commands::setup::normalize_mcp_repair_targets(record.targets.clone())?;
    if normalized != record.targets {
        anyhow::bail!(
            "MCP repair obligation targets are not canonical, sorted, unique, and conflict-free"
        );
    }
    Ok(())
}

fn validate_retained_mcp_repair_record(record: &McpRepairPending) -> Result<()> {
    validate_mcp_repair_record(record)?;
    if !record.repair_required || record.targets.is_empty() {
        anyhow::bail!(
            "retained MCP repair marker is not an active nonempty repair obligation; marker retained for evidence-preserving recovery"
        );
    }
    Ok(())
}

fn validate_mcp_repair_targets_not_reserved(
    record: &McpRepairPending,
    kin_home: &Path,
) -> Result<()> {
    let marker = crate::commands::setup::ConfigLock::normalized_path_with_existing_parent(
        &mcp_repair_pending_path(kin_home),
    )?;
    if record.targets.iter().any(|target| target.path == marker) {
        anyhow::bail!(
            "MCP repair target manifest names its own durable marker {}; refusing recursive marker authority",
            marker.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
struct LockedPrivateMarker {
    path: PathBuf,
    bytes: Vec<u8>,
    #[cfg(windows)]
    file: File,
    _lock: crate::commands::setup::ConfigLock,
}

#[cfg(windows)]
fn open_windows_private_marker(path: &Path, label: &str) -> Result<Option<(File, Vec<u8>)>> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::FromRawHandle as _;
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GENERIC_READ, GENERIC_WRITE,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, OPEN_EXISTING,
    };

    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        anyhow::bail!("{label} path contains an interior NUL");
    }
    wide.push(0);
    // The retained handle denies both write and delete sharing. Every type,
    // reparse, link-count, owner, ACL, and byte check below is handle-derived;
    // the pathname is never trusted again for validation or deletion.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | DELETE,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            std::ptr::null_mut(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(code)
                if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32
        ) {
            return Ok(None);
        }
        return Err(error)
            .with_context(|| format!("failed to retain exact {label} {}", path.display()));
    }
    let file = unsafe { File::from_raw_handle(raw) };
    windows_update::validate_current_user_private_file(&file)
        .with_context(|| format!("invalid {label} handle {}", path.display()))?;
    let mut bytes = Vec::new();
    (&file)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read exact {label} handle {}", path.display()))?;
    Ok(Some((file, bytes)))
}

#[cfg(not(unix))]
impl LockedPrivateMarker {
    fn open(path: &Path, label: &str) -> Result<Option<Self>> {
        let lock = crate::commands::setup::ConfigLock::acquire_nofollow(path)
            .with_context(|| format!("failed to lock {label} {}", path.display()))?;
        let Some(locked_bytes) = lock
            .original_bytes(path)
            .with_context(|| format!("failed to read locked {label} {}", path.display()))?
        else {
            return Ok(None);
        };
        #[cfg(windows)]
        let Some((file, bytes)) = open_windows_private_marker(path, label)?
        else {
            anyhow::bail!("locked {label} disappeared before its exact handle was retained");
        };
        #[cfg(windows)]
        if locked_bytes != bytes {
            anyhow::bail!("{label} bytes disagree with its retained exact handle");
        }
        #[cfg(all(not(unix), not(windows)))]
        let bytes = locked_bytes;
        Ok(Some(Self {
            path: path.to_path_buf(),
            bytes,
            #[cfg(windows)]
            file,
            _lock: lock,
        }))
    }

    fn remove_unchanged(self, label: &str) -> Result<()> {
        #[cfg(windows)]
        {
            windows_update::validate_current_user_private_file(&self.file).with_context(|| {
                format!(
                    "{label} exact handle lost object authority at {}",
                    self.path.display()
                )
            })?;
            let mut observed = Vec::new();
            let mut reader = &self.file;
            reader.seek(io::SeekFrom::Start(0))?;
            reader.read_to_end(&mut observed)?;
            if observed != self.bytes {
                anyhow::bail!("{label} exact object bytes changed; marker retained");
            }
            windows_update::dispose_private_file_handle_exact(&self.file, &self.path, label)?;
            let sync = self
                .file
                .sync_all()
                .with_context(|| format!("failed to flush disposed exact {label}"));
            let path = self.path.clone();
            drop(self.file);
            sync?;
            return match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Ok(_) => anyhow::bail!(
                    "disposed exact {label} is still visible at {}; clear not acknowledged",
                    path.display()
                ),
                Err(error) => Err(error)
                    .with_context(|| format!("failed to verify exact {label} disposition")),
            };
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            self._lock
                .remove_guarded(&self.path, Some(&self.bytes))
                .with_context(|| format!("{label} changed before marker clear; marker retained"))
        }
    }
}

fn attempt_pending_mcp_repair(lock: &InstallRootLock) -> Result<bool> {
    let kin_home = lock.root();
    #[cfg(unix)]
    let install = lock.install()?;
    #[cfg(unix)]
    let marker_present = install.root.stat_entry(MCP_REPAIR_PENDING_FILE)?.is_some();
    #[cfg(not(unix))]
    let marker_present = match fs::symlink_metadata(mcp_repair_pending_path(kin_home)) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("failed to inspect MCP repair pending marker"),
    };
    if !marker_present {
        return Ok(false);
    }
    // Global writer order: install authority -> MCP topology -> marker
    // ConfigLock -> retained marker target handle -> sorted config targets.
    let topology = crate::commands::setup::McpTopologyLock::acquire()?;
    #[cfg(unix)]
    let (marker_identity, record) = {
        let marker = install
            .root
            .read_regular(MCP_REPAIR_PENDING_FILE, "MCP repair pending marker")?;
        let marker_identity = bytes_identity(&marker);
        if install
            .root
            .identity(MCP_REPAIR_PENDING_FILE, "MCP repair pending marker")?
            .as_ref()
            != Some(&marker_identity)
        {
            anyhow::bail!("MCP repair pending state changed while it was read; marker retained");
        }
        let record: McpRepairPending = serde_json::from_slice(&marker)
            .context("malformed or unsupported MCP repair pending state; marker retained")?;
        validate_retained_mcp_repair_record(&record)
            .context("unsupported MCP repair pending state; marker retained")?;
        (marker_identity, record)
    };
    #[cfg(not(unix))]
    let marker_path = mcp_repair_pending_path(kin_home);
    #[cfg(not(unix))]
    let marker = match LockedPrivateMarker::open(&marker_path, "MCP repair pending marker")? {
        Some(marker) => marker,
        None => anyhow::bail!(
            "MCP repair pending marker disappeared while exact authority was acquired; marker state retained"
        ),
    };
    #[cfg(not(unix))]
    let record: McpRepairPending = serde_json::from_slice(&marker.bytes)
        .context("malformed or unsupported MCP repair pending state; marker retained")?;
    #[cfg(not(unix))]
    validate_retained_mcp_repair_record(&record)
        .context("unsupported MCP repair pending state; marker retained")?;
    validate_mcp_repair_targets_not_reserved(&record, kin_home)
        .context("invalid MCP repair target lifecycle; marker retained")?;
    #[cfg(not(unix))]
    for target in &record.targets {
        if marker._lock.protects_alias(&target.path).with_context(|| {
            format!(
                "failed to compare MCP repair target {} with reserved marker authority",
                target.path.display()
            )
        })? {
            anyhow::bail!(
                "MCP repair target {} aliases its own durable marker sidecar; marker retained",
                target.path.display()
            );
        }
    }

    let repaired = crate::commands::setup::remerge_mcp_targets_exact_with_topology_and_finalizer(
        &record.targets,
        &topology,
        || {
            #[cfg(unix)]
            {
                install.ensure_bound()?;
                if install
                    .root
                    .identity(MCP_REPAIR_PENDING_FILE, "MCP repair pending marker")?
                    .as_ref()
                    != Some(&marker_identity)
                {
                    anyhow::bail!("MCP repair pending state changed before marker clear");
                }
                install.ensure_bound()?;
                install.root.unlink_file(MCP_REPAIR_PENDING_FILE)?;
            }
            #[cfg(not(unix))]
            marker.remove_unchanged("MCP repair pending marker")?;
            Ok(())
        },
    )
    .with_context(|| {
        format!(
            "MCP repair remains pending at {}",
            mcp_repair_pending_path(kin_home).display()
        )
    })?;
    for path in repaired {
        eprintln!("Refreshed Kin MCP launcher: {}", path.display());
    }
    Ok(true)
}

#[cfg(all(test, unix))]
pub(crate) fn enqueue_mcp_repair_targets(
    targets: &[crate::commands::setup::McpRepairTarget],
) -> Result<bool> {
    let targets = crate::commands::setup::normalize_mcp_repair_targets(targets.iter().cloned())?;
    if targets.is_empty() {
        return Ok(false);
    }
    let kin_home = crate::commands::setup::kin_dir()?;
    let lock = InstallRootLock::acquire_existing(&kin_home)?;
    let existing = read_existing_mcp_repair_record(&lock)?;

    let mut combined = existing
        .map(|record| {
            validate_retained_mcp_repair_record(&record)?;
            Ok::<_, anyhow::Error>(record.targets)
        })
        .transpose()?
        .unwrap_or_default();
    combined.extend(targets);
    let combined = crate::commands::setup::normalize_mcp_repair_targets(combined)?;
    let record = McpRepairPending {
        schema_version: MCP_REPAIR_MARKER_SCHEMA_VERSION,
        installed_version: CURRENT_VERSION.to_string(),
        recorded_at: chrono::Utc::now().to_rfc3339(),
        repair_required: true,
        targets: combined,
    };
    validate_mcp_repair_targets_not_reserved(&record, &kin_home)?;
    #[cfg(unix)]
    persist_mcp_repair_record_at(lock.install()?, &record)?;
    #[cfg(not(unix))]
    persist_mcp_repair_record(lock.root(), &record)?;
    Ok(true)
}

fn retry_pending_mcp_repair_with_start_authority(
    requested_home: &Path,
    spec: &[ComponentSpec],
    start_authority: &UpdaterStartAuthority,
) -> Result<bool> {
    let lock = InstallRootLock::acquire_existing_waiting(requested_home)?;
    start_authority.verify_locked(&lock, spec).context(
        "managed Kin bundle changed while ordinary-command MCP repair waited for install authority; marker retained",
    )?;
    attempt_pending_mcp_repair(&lock)
}

/// Retry a durable MCP repair from an ordinary command without splitting
/// authorization into a check-then-act boolean. The exact executing image and
/// complete managed bundle are captured before waiting for the install lock,
/// then reverified while that lock is held before any config can change.
pub fn retry_pending_mcp_repair_from_managed_process() -> Result<bool> {
    let requested_home = crate::commands::setup::kin_dir()?;
    match fs::symlink_metadata(mcp_repair_pending_path(&requested_home)) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("failed to inspect MCP repair pending marker"),
    }
    let spec = platform_bundle_spec(std::env::consts::OS)?;
    // UpdaterStartAuthority retains the live process image (`/proc/self/exe`
    // on Linux, the Mach text vnode on macOS, and an image handle on Windows).
    // A copied checkout binary therefore cannot mutate a real user's configs.
    let start_authority = UpdaterStartAuthority::capture(&requested_home, spec).context(
        "automatic MCP repair requires the exact managed Kin launcher and full installed generation; marker retained",
    )?;
    retry_pending_mcp_repair_with_start_authority(&requested_home, spec, &start_authority)
}

fn ensure_mutating_update_supported(os: &str, check_only: bool) -> Result<()> {
    if os == "windows" && !check_only {
        anyhow::bail!(
            "in-process self-update is disabled on Windows because the running kin.exe cannot be \
             replaced safely. No update state was changed; use the signed Windows installer"
        );
    }
    Ok(())
}

/// OS-level lock held by every writer of a managed Kin install component.
///
/// Unix keeps a persistent in-root flock file; deleting it while held would
/// create a second inode that another process could lock concurrently. Windows
/// uses a persistent current-user-only sibling lock because an open descendant
/// handle prevents atomic install-root retirement there.
pub(crate) struct InstallRootLock {
    file: File,
    root: PathBuf,
    #[cfg(unix)]
    install: InstallLayout,
}

/// Shared admission lease held from immediately before a managed supervisor or
/// worker spawn until that child has published readiness. Full uninstall takes
/// the same install authority exclusively, so a spawn is either wholly before
/// the uninstall stop sweep or wholly after retirement (where path
/// revalidation fails because the managed binary no longer exists). Unix uses
/// `update.lock`; Windows uses the current-user-only sibling authority file
/// because Windows cannot rename a directory while an open lock remains inside
/// it.
pub(crate) struct InstallSpawnFence {
    _file: File,
}

impl InstallSpawnFence {
    pub(crate) fn acquire_for_daemon_binary(binary: &Path) -> Result<Option<Self>> {
        let configured_root = crate::commands::setup::kin_dir()?;
        Self::acquire_for_daemon_binary_at(binary, &configured_root)
    }

    fn acquire_for_daemon_binary_at(binary: &Path, configured_root: &Path) -> Result<Option<Self>> {
        let Some(bin_dir) = binary.parent() else {
            return Ok(None);
        };
        if bin_dir.file_name().and_then(|name| name.to_str()) != Some("bin") {
            return Ok(None);
        }
        let Some(candidate_root) = bin_dir.parent() else {
            return Ok(None);
        };
        let candidate_root = candidate_root.canonicalize().with_context(|| {
            format!(
                "failed to resolve managed daemon install root {}",
                candidate_root.display()
            )
        })?;
        let candidate_root_name = candidate_root
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let retired_token = candidate_root_name
            .strip_prefix(".kin-uninstall-retired-")
            .or_else(|| candidate_root_name.strip_prefix(".kin-uninstall-delete-"));
        if retired_token.is_some_and(|token| uuid::Uuid::parse_str(token).is_ok()) {
            anyhow::bail!(
                "refusing to spawn a managed daemon from retired uninstall state: {}",
                binary.display()
            );
        }
        let configured_root = match configured_root.canonicalize() {
            Ok(root) => root,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to resolve configured Kin install root {}",
                        configured_root.display()
                    )
                })
            }
        };
        if candidate_root != configured_root {
            return Ok(None);
        }
        let expected_binary = configured_root.join("bin").join(
            binary
                .file_name()
                .context("managed daemon binary has no file name")?,
        );
        let binary_metadata = fs::symlink_metadata(binary).with_context(|| {
            format!(
                "failed to inspect managed daemon binary {}",
                binary.display()
            )
        })?;
        if binary_metadata.file_type().is_symlink() || !binary_metadata.is_file() {
            anyhow::bail!(
                "managed daemon binary is not a real non-symlink file: {}",
                binary.display()
            );
        }
        let resolved_binary = binary.canonicalize().with_context(|| {
            format!(
                "failed to resolve managed daemon binary {}",
                binary.display()
            )
        })?;
        if resolved_binary
            != expected_binary.canonicalize().with_context(|| {
                format!(
                    "failed to resolve expected managed daemon binary {}",
                    expected_binary.display()
                )
            })?
        {
            anyhow::bail!(
                "managed daemon binary changed while acquiring spawn admission: {}",
                binary.display()
            );
        }

        #[cfg(unix)]
        {
            let parent_path = configured_root
                .parent()
                .context("Kin install root has no parent")?;
            let root_name = configured_root
                .file_name()
                .and_then(|name| name.to_str())
                .context("Kin install root name is not UTF-8")?;
            let parent = AnchoredDir::open_ambient(parent_path)?;
            let root = parent.open_child(root_name)?;
            parent.ensure_child_binding(root_name, &root)?;
            let (mut file, created) = open_lock_file_at(&root)?;
            if created {
                file.write_all(b"kin-update-lock-v1\n")?;
                file.sync_all()?;
                root.sync()?;
            }
            FileExt::lock_shared(&file).context("failed to acquire managed daemon spawn lease")?;
            let lock = rustix::fs::fstat(&file)?;
            ensure_root_lock_binding(
                &parent,
                root_name,
                &root,
                lock.st_dev as u64,
                lock.st_ino as u64,
            )?;
            if binary.canonicalize().ok().as_deref() != Some(resolved_binary.as_path()) {
                anyhow::bail!(
                    "managed daemon binary changed after spawn admission: {}",
                    binary.display()
                );
            }
            return Ok(Some(Self { _file: file }));
        }

        #[cfg(windows)]
        {
            let authority_path = windows_install_authority_path(&configured_root)?;
            let (file, _) =
                windows_update::open_or_create_current_user_private_lock_file(&authority_path)?;
            FileExt::lock_shared(&file).context("failed to acquire managed daemon spawn lease")?;
            ensure_no_incomplete_windows_uninstall(&configured_root)?;
            if configured_root.canonicalize()? != candidate_root
                || binary.canonicalize().ok().as_deref() != Some(resolved_binary.as_path())
            {
                anyhow::bail!("managed daemon install changed after spawn admission");
            }
            Ok(Some(Self { _file: file }))
        }
    }
}

/// An install root detached from its public pathname while the exact directory
/// incarnation remains pinned by open descriptors. Cleanup is descriptor-
/// relative; callers never reopen the retired tree by pathname.
#[cfg(unix)]
pub(crate) struct RetiredInstallRoot {
    parent: AnchoredDir,
    root: AnchoredDir,
    name: String,
    incomplete_marker: String,
    path: PathBuf,
}

#[cfg(unix)]
impl RetiredInstallRoot {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Remove only the directory incarnation pinned at retirement. If any
    /// binding changes, preserve the replacement and fail closed.
    pub(crate) fn remove(self) -> Result<()> {
        self.root.remove_contents_recursive()?;
        self.root.ensure_empty()?;
        self.parent
            .ensure_child_binding(&self.name, &self.root)
            .context("retired Kin install root binding changed before final removal")?;
        self.parent.remove_child_dir(&self.name)?;
        self.parent.quarantine_verified_regular(
            &self.incomplete_marker,
            "Kin uninstall incomplete marker",
            || Ok(()),
        )
    }
}

impl InstallRootLock {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn acquire(kin_home: &Path) -> Result<Self> {
        Self::acquire_inner(kin_home, true, false)
    }

    fn acquire_existing(kin_home: &Path) -> Result<Self> {
        Self::acquire_inner(kin_home, false, false)
    }

    pub(crate) fn acquire_existing_waiting(kin_home: &Path) -> Result<Self> {
        Self::acquire_inner(kin_home, false, true)
    }

    fn acquire_inner(kin_home: &Path, create: bool, wait: bool) -> Result<Self> {
        #[cfg(windows)]
        let authority_root = windows_install_authority_root(kin_home)?;
        #[cfg(windows)]
        let authority_path = windows_install_authority_path(&authority_root)?;
        #[cfg(windows)]
        let (mut file, created) =
            windows_update::open_or_create_current_user_private_lock_file(&authority_path)?;
        #[cfg(windows)]
        if wait {
            FileExt::lock_exclusive(&file).with_context(|| {
                format!(
                    "failed while waiting for Kin install authority {}",
                    authority_path.display()
                )
            })?;
        } else {
            match FileExt::try_lock_exclusive(&file) {
                Ok(()) => {}
                Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
                    anyhow::bail!(
                        "another Kin install mutation is already active for {} (lock: {})",
                        kin_home.display(),
                        authority_path.display()
                    );
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to acquire Windows Kin install authority {}",
                            authority_path.display()
                        )
                    });
                }
            }
        }
        #[cfg(windows)]
        if created {
            file.write_all(b"kin-update-lock-v2\n").with_context(|| {
                format!(
                    "failed to initialize Windows Kin install authority {}",
                    authority_path.display()
                )
            })?;
            file.sync_all().with_context(|| {
                format!(
                    "failed to sync Windows Kin install authority {}",
                    authority_path.display()
                )
            })?;
        }
        #[cfg(windows)]
        ensure_no_incomplete_windows_uninstall(&authority_root)?;
        let root = validate_install_root(kin_home, create)?;
        #[cfg(unix)]
        let path = root.join("update.lock");
        #[cfg(unix)]
        let parent_path = root.parent().context("Kin install root has no parent")?;
        #[cfg(unix)]
        let root_name = root
            .file_name()
            .and_then(|name| name.to_str())
            .context("Kin install root name is not UTF-8")?
            .to_string();
        #[cfg(unix)]
        let parent_anchor = AnchoredDir::open_ambient(parent_path)?;
        #[cfg(unix)]
        let root_anchor = parent_anchor.open_child(&root_name)?;
        #[cfg(unix)]
        parent_anchor.ensure_child_binding(&root_name, &root_anchor)?;
        #[cfg(unix)]
        let (mut file, created) = open_lock_file_at(&root_anchor)?;

        #[cfg(unix)]
        if wait {
            FileExt::lock_exclusive(&file).with_context(|| {
                format!(
                    "failed while waiting for Kin install authority {}",
                    path.display()
                )
            })?;
        } else {
            match FileExt::try_lock_exclusive(&file) {
                Ok(()) => {}
                Err(err) if err.kind() == fs2::lock_contended_error().kind() => {
                    anyhow::bail!(
                        "another Kin install mutation is already active for {} (lock: {})",
                        root.display(),
                        path.display()
                    );
                }
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to acquire update lock {}", path.display())
                    });
                }
            }
        }

        #[cfg(unix)]
        let lock_stat =
            rustix::fs::fstat(&file).context("failed to inspect held anchored update lock")?;
        #[cfg(unix)]
        ensure_root_lock_binding(
            &parent_anchor,
            &root_name,
            &root_anchor,
            lock_stat.st_dev as u64,
            lock_stat.st_ino as u64,
        )?;
        #[cfg(unix)]
        root_anchor.set_mode(0o700, "managed Kin install root")?;

        #[cfg(unix)]
        if created {
            file.write_all(b"kin-update-lock-v1\n")
                .with_context(|| format!("failed to initialize update lock {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("failed to sync update lock {}", path.display()))?;
            root_anchor.sync()?;
        }
        #[cfg(unix)]
        {
            ensure_root_lock_binding(
                &parent_anchor,
                &root_name,
                &root_anchor,
                lock_stat.st_dev as u64,
                lock_stat.st_ino as u64,
            )?;
            let install = InstallLayout::from_locked_root(
                parent_anchor,
                root_name,
                root_anchor,
                lock_stat.st_dev as u64,
                lock_stat.st_ino as u64,
            )?;
            return Ok(Self {
                file,
                root,
                install,
            });
        }
        #[cfg(windows)]
        {
            // Managed directories are created only after exclusive lock
            // acquisition, so a contended writer is byte-for-byte read-only.
            ensure_managed_dirs(&root, true)?;
            Ok(Self { file, root })
        }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Atomically detach the exact locked install root from its public name so
    /// recursive cleanup can never follow a replacement placed at that name.
    /// The returned sibling path names the same anchored directory incarnation
    /// this lock was acquired against.
    #[cfg(unix)]
    pub(crate) fn retire_for_uninstall(&self) -> Result<RetiredInstallRoot> {
        let install = self.install()?;
        let token = uuid::Uuid::new_v4();
        let retired_name = format!(".kin-uninstall-retired-{token}");
        let incomplete_marker = format!(".kin-uninstall-incomplete-{token}");
        if install.parent.stat_entry(&retired_name)?.is_some() {
            anyhow::bail!(
                "refusing to replace an existing uninstall retirement path {}/{}",
                install.parent.display.display(),
                retired_name
            );
        }
        if install.parent.stat_entry(&incomplete_marker)?.is_some() {
            anyhow::bail!(
                "refusing to replace an existing uninstall incomplete marker {}/{}",
                install.parent.display.display(),
                incomplete_marker
            );
        }
        install.ensure_bound()?;
        install.parent.create_exclusive_file(
            &incomplete_marker,
            b"kin-uninstall-incomplete-v1\n",
            0o600,
        )?;
        let rename = rustix::fs::renameat_with(
            &install.parent.file,
            install.root_name.as_str(),
            &install.parent.file,
            retired_name.as_str(),
            rustix::fs::RenameFlags::NOREPLACE,
        );
        if let Err(error) = rename {
            let _ = install.parent.unlink_file(&incomplete_marker);
            return Err(error).with_context(|| {
                format!(
                    "failed to atomically retire locked Kin install root {}",
                    self.root.display()
                )
            });
        }
        install.parent.sync()?;
        let retired = install
            .parent
            .stat_entry(&retired_name)?
            .context("retired Kin install root disappeared after atomic rename")?;
        if rustix::fs::FileType::from_raw_mode(retired.st_mode) != rustix::fs::FileType::Directory
            || retired.st_dev as u64 != install.root.dev
            || retired.st_ino as u64 != install.root.ino
        {
            anyhow::bail!(
                "retired Kin install root identity changed after atomic rename; preserving {}",
                install.parent.display.join(&retired_name).display()
            );
        }
        let path = install.parent.display.join(&retired_name);
        Ok(RetiredInstallRoot {
            parent: install.parent.try_clone()?,
            root: install.root.try_clone()?,
            name: retired_name,
            incomplete_marker,
            path,
        })
    }

    #[cfg(unix)]
    fn install(&self) -> Result<&InstallLayout> {
        let held = rustix::fs::fstat(&self.file)
            .context("failed to inspect held update lock before install mutation")?;
        if held.st_dev as u64 != self.install.lock_dev
            || held.st_ino as u64 != self.install.lock_ino
        {
            anyhow::bail!("held update lock identity changed");
        }
        self.install.ensure_bound()?;
        Ok(&self.install)
    }
}

impl Drop for InstallRootLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

#[cfg(windows)]
fn windows_install_authority_root(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        anyhow::bail!(
            "Kin install root must be absolute, got {}. Set KIN_HOME to an absolute path",
            path.display()
        );
    }
    match path.canonicalize() {
        Ok(root) => return Ok(root),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to resolve existing Kin install root for authority {}",
                    path.display()
                )
            });
        }
    }
    let parent = path.parent().context("Kin install root has no parent")?;
    let name = path
        .file_name()
        .context("Kin install root has no final path component")?;
    let parent = parent.canonicalize().with_context(|| {
        format!(
            "parent of Kin install root does not exist or is inaccessible: {}",
            parent.display()
        )
    })?;
    Ok(parent.join(name))
}

#[cfg(windows)]
pub(crate) fn windows_install_authority_path(root: &Path) -> Result<PathBuf> {
    let root = windows_install_authority_root(root)?;
    let normalized = root.to_string_lossy().to_lowercase();
    let digest = hex::encode(Sha256::digest(normalized.as_bytes()));
    Ok(root
        .parent()
        .context("Kin install root has no parent")?
        .join(format!(".kin-install-authority-{digest}.lock")))
}

#[cfg(windows)]
fn ensure_no_incomplete_windows_uninstall(root: &Path) -> Result<()> {
    let parent = root.parent().context("Kin install root has no parent")?;
    let mut artifacts = Vec::new();
    for entry in fs::read_dir(parent).with_context(|| {
        format!(
            "failed to inspect {} for incomplete Kin uninstall state",
            parent.display()
        )
    })? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let token = name
            .strip_prefix(".kin-uninstall-retired-")
            .or_else(|| name.strip_prefix(".kin-uninstall-delete-"))
            .or_else(|| name.strip_prefix(".kin-uninstall-incomplete-"));
        let Some(token) = token else {
            continue;
        };
        if uuid::Uuid::parse_str(token).is_ok_and(|id| {
            id.get_version() == Some(uuid::Version::Random) && id.hyphenated().to_string() == token
        }) {
            artifacts.push(entry.path());
        }
    }
    if !artifacts.is_empty() {
        artifacts.sort();
        anyhow::bail!(
            "a prior Windows Kin uninstall is still completing or requires recovery: {}; refusing install mutation until that identity-bound cleanup finishes",
            artifacts
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

fn validate_existing_install_root(path: &Path) -> Result<PathBuf> {
    let root = validate_install_root(path, false)?;
    ensure_managed_dirs(&root, false)?;
    Ok(root)
}

fn validate_install_root(path: &Path, create: bool) -> Result<PathBuf> {
    if !path.is_absolute() {
        anyhow::bail!(
            "Kin install root must be absolute, got {}. Set KIN_HOME to an absolute path",
            path.display()
        );
    }

    #[cfg(unix)]
    {
        let parent_path = path.parent().context("Kin install root has no parent")?;
        let root_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("Kin install root name is not UTF-8")?;
        let canonical_parent = parent_path.canonicalize().with_context(|| {
            format!(
                "parent of Kin install root does not exist or is inaccessible: {}",
                parent_path.display()
            )
        })?;
        let parent = AnchoredDir::open_ambient(&canonical_parent)?;
        let root = match parent.stat_entry(root_name)? {
            Some(stat)
                if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                    == rustix::fs::FileType::Directory =>
            {
                parent.open_child(root_name)?
            }
            Some(_) => anyhow::bail!(
                "Kin install root is not a real non-symlink directory: {}",
                path.display()
            ),
            None if create => parent.create_child(root_name, 0o700)?,
            None => anyhow::bail!(
                "managed Kin install root does not exist: {}. Use the platform installer first",
                path.display()
            ),
        };
        parent.ensure_child_binding(root_name, &root)?;
        return Ok(canonical_parent.join(root_name));
    }

    #[cfg(not(unix))]
    {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    anyhow::bail!("refusing symlink Kin install root {}", path.display());
                }
                if !metadata.is_dir() {
                    anyhow::bail!("Kin install root is not a directory: {}", path.display());
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && create => {
                let parent = path.parent().context("Kin install root has no parent")?;
                let parent = parent.canonicalize().with_context(|| {
                    format!(
                        "parent of Kin install root does not exist or is inaccessible: {}",
                        parent.display()
                    )
                })?;
                fs::create_dir(path)
                    .with_context(|| format!("failed to create Kin home {}", path.display()))?;
                sync_dir(&parent)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                anyhow::bail!(
                    "managed Kin install root does not exist: {}. Use the platform installer first",
                    path.display()
                );
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to inspect Kin home {}", path.display()));
            }
        }

        path.canonicalize()
            .with_context(|| format!("failed to canonicalize Kin home {}", path.display()))
    }
}

fn ensure_managed_dirs(root: &Path, create: bool) -> Result<()> {
    #[cfg(unix)]
    {
        let root = AnchoredDir::open_ambient(root)?;
        for name in ["bin", "lib"] {
            match root.stat_entry(name)? {
                Some(stat)
                    if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                        == rustix::fs::FileType::Directory =>
                {
                    let child = root.open_child(name)?;
                    root.ensure_child_binding(name, &child)?;
                }
                Some(_) => anyhow::bail!(
                    "managed path is not a real non-symlink directory: {}/{}",
                    root.display.display(),
                    name
                ),
                None if create => {
                    root.create_child(name, 0o700)?;
                }
                None => {}
            }
        }
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        let canonical_root = root.canonicalize().with_context(|| {
            format!("failed to canonicalize Kin install root {}", root.display())
        })?;
        for name in ["bin", "lib"] {
            let path = root.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() {
                        anyhow::bail!("refusing symlink managed directory {}", path.display());
                    }
                    if !metadata.is_dir() {
                        anyhow::bail!("managed path is not a directory: {}", path.display());
                    }
                    let canonical = path.canonicalize().with_context(|| {
                        format!(
                            "failed to canonicalize managed directory {}",
                            path.display()
                        )
                    })?;
                    if !canonical.starts_with(&canonical_root) {
                        anyhow::bail!(
                            "managed directory escapes Kin install root: {}",
                            path.display()
                        );
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound && create => {
                    fs::create_dir(&path).with_context(|| {
                        format!("failed to create managed directory {}", path.display())
                    })?;
                    sync_dir(root)?;
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to inspect managed path {}", path.display())
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn open_lock_file_at(root: &AnchoredDir) -> Result<(File, bool)> {
    let flags = rustix::fs::OFlags::RDWR
        | rustix::fs::OFlags::CREATE
        | rustix::fs::OFlags::EXCL
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC;
    match rustix::fs::openat(
        &root.file,
        "update.lock",
        flags,
        rustix::fs::Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => {
            let file = File::from(fd);
            set_and_verify_file_mode(&file, 0o600, "anchored update lock")?;
            file.sync_all()?;
            root.sync()?;
            return Ok((file, true));
        }
        Err(rustix::io::Errno::EXIST) => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to create anchored update lock {}/update.lock",
                    root.display.display()
                )
            });
        }
    }

    let before = root
        .stat_entry("update.lock")?
        .context("anchored update lock disappeared")?;
    if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile {
        anyhow::bail!(
            "refusing non-regular or symlink update lock {}/update.lock",
            root.display.display()
        );
    }
    let fd = rustix::fs::openat(
        &root.file,
        "update.lock",
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .context("failed to open anchored update lock")?;
    let file = File::from(fd);
    let opened = rustix::fs::fstat(&file).context("failed to inspect anchored update lock")?;
    if rustix::fs::FileType::from_raw_mode(opened.st_mode) != rustix::fs::FileType::RegularFile
        || opened.st_dev != before.st_dev
        || opened.st_ino != before.st_ino
    {
        anyhow::bail!("anchored update lock changed while it was being opened");
    }
    set_and_verify_file_mode(&file, 0o600, "anchored update lock")?;
    file.sync_all()?;
    Ok((file, false))
}

#[cfg(unix)]
fn set_and_verify_file_mode(file: &File, mode: u32, context: &str) -> Result<()> {
    rustix::fs::fchmod(file, rustix::fs::Mode::from_raw_mode(mode as _))
        .with_context(|| format!("failed to set private mode on {context}"))?;
    let stat = rustix::fs::fstat(file).with_context(|| format!("failed to inspect {context}"))?;
    if stat.st_mode as u32 & 0o777 != mode {
        anyhow::bail!(
            "{context} mode verification failed: expected {mode:o}, found {:o}",
            stat.st_mode as u32 & 0o777
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(path: &Path) -> Result<()> {
    let _ = path;
    Ok(())
}

#[cfg(unix)]
#[derive(Debug)]
struct AnchoredDir {
    file: File,
    display: PathBuf,
    dev: u64,
    ino: u64,
}

#[cfg(unix)]
struct PendingAnchoredChild<'a> {
    parent: &'a AnchoredDir,
    name: String,
    identity: Option<(u64, u64)>,
    armed: bool,
}

#[cfg(unix)]
impl PendingAnchoredChild<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(unix)]
impl Drop for PendingAnchoredChild<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Some((dev, ino)) = self.identity else {
            return;
        };
        let removable = self
            .parent
            .stat_entry(&self.name)
            .ok()
            .flatten()
            .is_some_and(|stat| {
                rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Directory
                    && stat.st_dev as u64 == dev
                    && stat.st_ino as u64 == ino
            });
        if removable {
            let _ = self.parent.remove_child_dir(&self.name);
        }
    }
}

#[cfg(unix)]
impl AnchoredDir {
    fn from_file(file: File, display: PathBuf) -> Result<Self> {
        let stat = rustix::fs::fstat(&file)
            .with_context(|| format!("failed to inspect directory handle {}", display.display()))?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
            anyhow::bail!("anchored path is not a directory: {}", display.display());
        }
        Ok(Self {
            file,
            display,
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
        })
    }

    fn open_ambient(path: &Path) -> Result<Self> {
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .with_context(|| format!("failed to anchor directory {}", path.display()))?;
        Self::from_file(File::from(fd), path.to_path_buf())
    }

    fn try_clone(&self) -> Result<Self> {
        Self::from_file(
            self.file.try_clone().with_context(|| {
                format!(
                    "failed to duplicate anchored directory {}",
                    self.display.display()
                )
            })?,
            self.display.clone(),
        )
    }

    fn open_child(&self, name: &str) -> Result<Self> {
        let before = self.stat_entry(name)?.with_context(|| {
            format!(
                "missing anchored directory {}/{}",
                self.display.display(),
                name
            )
        })?;
        if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::Directory {
            anyhow::bail!(
                "anchored child is not a real directory: {}/{}",
                self.display.display(),
                name
            );
        }
        let fd = rustix::fs::openat(
            &self.file,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .with_context(|| {
            format!(
                "failed to open anchored directory {}/{}",
                self.display.display(),
                name
            )
        })?;
        let child = Self::from_file(File::from(fd), self.display.join(name))?;
        if child.dev != before.st_dev as u64 || child.ino != before.st_ino as u64 {
            anyhow::bail!(
                "directory changed while it was being anchored: {}",
                child.display.display()
            );
        }
        Ok(child)
    }

    fn create_child(&self, name: &str, mode: u32) -> Result<Self> {
        rustix::fs::mkdirat(&self.file, name, rustix::fs::Mode::from_raw_mode(mode as _))
            .with_context(|| {
                format!(
                    "failed to create anchored directory {}/{}",
                    self.display.display(),
                    name
                )
            })?;
        let mut pending = PendingAnchoredChild {
            parent: self,
            name: name.to_string(),
            identity: None,
            armed: true,
        };
        let created = self.stat_entry(name)?.with_context(|| {
            format!(
                "newly created anchored directory disappeared: {}/{}",
                self.display.display(),
                name
            )
        })?;
        pending.identity = Some((created.st_dev as u64, created.st_ino as u64));
        if rustix::fs::FileType::from_raw_mode(created.st_mode) != rustix::fs::FileType::Directory {
            anyhow::bail!(
                "newly created anchored child is not a directory: {}/{}",
                self.display.display(),
                name
            );
        }
        // mkdir honors umask, so explicitly restore the requested mode before
        // opening the directory and verify it again on the descriptor.
        match rustix::fs::chmodat(
            &self.file,
            name,
            rustix::fs::Mode::from_raw_mode(mode as _),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(()) => {}
            Err(rustix::io::Errno::OPNOTSUPP) => rustix::fs::chmodat(
                &self.file,
                name,
                rustix::fs::Mode::from_raw_mode(mode as _),
                rustix::fs::AtFlags::empty(),
            )?,
            Err(error) => return Err(error.into()),
        }
        self.sync()?;
        let child = self.open_child(name)?;
        let stat = rustix::fs::fstat(&child.file)?;
        if stat.st_mode as u32 & 0o777 != mode {
            anyhow::bail!(
                "anchored directory mode verification failed at {}: expected {mode:o}, found {:o}",
                child.display.display(),
                stat.st_mode as u32 & 0o777
            );
        }
        pending.disarm();
        Ok(child)
    }

    fn set_mode(&self, mode: u32, context: &str) -> Result<()> {
        rustix::fs::fchmod(&self.file, rustix::fs::Mode::from_raw_mode(mode as _)).with_context(
            || format!("failed to set {context} mode at {}", self.display.display()),
        )?;
        let stat = rustix::fs::fstat(&self.file)?;
        if stat.st_mode as u32 & 0o777 != mode {
            anyhow::bail!(
                "{context} mode verification failed at {}: expected {mode:o}, found {:o}",
                self.display.display(),
                stat.st_mode as u32 & 0o777
            );
        }
        self.sync()
    }

    fn stat_entry(&self, name: &str) -> Result<Option<rustix::fs::Stat>> {
        match rustix::fs::statat(&self.file, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(stat)),
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "failed to inspect anchored path {}/{}",
                    self.display.display(),
                    name
                )
            }),
        }
    }

    fn ensure_child_binding(&self, name: &str, child: &Self) -> Result<()> {
        let current = self.stat_entry(name)?.with_context(|| {
            format!(
                "anchored directory binding disappeared: {}/{}",
                self.display.display(),
                name
            )
        })?;
        if rustix::fs::FileType::from_raw_mode(current.st_mode) != rustix::fs::FileType::Directory
            || current.st_dev as u64 != child.dev
            || current.st_ino as u64 != child.ino
        {
            anyhow::bail!(
                "anchored directory binding changed: {}/{}",
                self.display.display(),
                name
            );
        }
        Ok(())
    }

    fn ensure_regular_binding(&self, name: &str, dev: u64, ino: u64) -> Result<()> {
        let current = self.stat_entry(name)?.with_context(|| {
            format!(
                "anchored regular-file binding disappeared: {}/{}",
                self.display.display(),
                name
            )
        })?;
        if rustix::fs::FileType::from_raw_mode(current.st_mode) != rustix::fs::FileType::RegularFile
            || current.st_dev as u64 != dev
            || current.st_ino as u64 != ino
        {
            anyhow::bail!(
                "anchored regular-file binding changed: {}/{}",
                self.display.display(),
                name
            );
        }
        Ok(())
    }

    fn open_regular(&self, name: &str, context: &str) -> Result<Option<(File, rustix::fs::Stat)>> {
        let Some(before) = self.stat_entry(name)? else {
            return Ok(None);
        };
        if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile
        {
            anyhow::bail!(
                "{context} is not a regular non-symlink file: {}/{}",
                self.display.display(),
                name
            );
        }
        let fd = rustix::fs::openat(
            &self.file,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .with_context(|| {
            format!(
                "failed to open {context} {}/{}",
                self.display.display(),
                name
            )
        })?;
        let file = File::from(fd);
        let opened = rustix::fs::fstat(&file).with_context(|| {
            format!(
                "failed to inspect opened {context} {}/{}",
                self.display.display(),
                name
            )
        })?;
        if rustix::fs::FileType::from_raw_mode(opened.st_mode) != rustix::fs::FileType::RegularFile
            || opened.st_dev != before.st_dev
            || opened.st_ino != before.st_ino
        {
            anyhow::bail!(
                "{context} changed while it was being opened: {}/{}",
                self.display.display(),
                name
            );
        }
        Ok(Some((file, opened)))
    }

    fn identity(&self, name: &str, context: &str) -> Result<Option<FileIdentity>> {
        Ok(self
            .generation_identity(name, context)?
            .map(|generation| generation.identity))
    }

    fn generation_identity(
        &self,
        name: &str,
        context: &str,
    ) -> Result<Option<ManagedComponentGeneration>> {
        let Some((mut file, stat)) = self.open_regular(name, context)? else {
            return Ok(None);
        };
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer).with_context(|| {
                format!(
                    "failed to hash {context} {}/{}",
                    self.display.display(),
                    name
                )
            })?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        self.ensure_regular_binding(name, stat.st_dev as u64, stat.st_ino as u64)?;
        Ok(Some(ManagedComponentGeneration {
            identity: FileIdentity {
                sha256: hex::encode(hasher.finalize()),
                size_bytes: stat.st_size as u64,
            },
            binding: PlatformObjectIdentity {
                namespace: stat.st_dev as u64,
                file: stat.st_ino as u64,
            },
        }))
    }

    fn read_regular(&self, name: &str, context: &str) -> Result<Vec<u8>> {
        let Some((mut file, _)) = self.open_regular(name, context)? else {
            anyhow::bail!("missing {context} {}/{}", self.display.display(), name);
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).with_context(|| {
            format!(
                "failed to read {context} {}/{}",
                self.display.display(),
                name
            )
        })?;
        Ok(bytes)
    }

    fn atomic_write_checked<C>(
        &self,
        name: &str,
        bytes: &[u8],
        mode: u32,
        check_binding: C,
    ) -> Result<()>
    where
        C: FnMut() -> Result<()>,
    {
        self.atomic_write_with_hooks(name, bytes, mode, || Ok(()), check_binding)
    }

    fn create_private_file_absent_or_identical_with_hook<B, C>(
        &self,
        name: &str,
        bytes: &[u8],
        label: &str,
        before_create: B,
        after_noreplace_conflict: C,
    ) -> Result<()>
    where
        B: FnOnce() -> Result<()>,
        C: FnOnce() -> Result<()>,
    {
        let verify_existing = || -> Result<bool> {
            let Some((mut file, stat)) = self.open_regular(name, label)? else {
                return Ok(false);
            };
            let mut existing = Vec::new();
            file.read_to_end(&mut existing)?;
            self.ensure_regular_binding(name, stat.st_dev as u64, stat.st_ino as u64)?;
            if existing != bytes {
                anyhow::bail!(
                    "{label} already exists with different bytes; existing object retained without replacement"
                );
            }
            Ok(true)
        };
        if verify_existing()? {
            return Ok(());
        }
        let temp = format!(".{name}.create-{}", uuid::Uuid::new_v4());
        let fd = rustix::fs::openat(
            &self.file,
            temp.as_str(),
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .with_context(|| {
            format!(
                "failed to create private {label} staging file {}/{}",
                self.display.display(),
                temp
            )
        })?;
        let mut file = File::from(fd);
        let created = rustix::fs::fstat(&file)?;
        let mut committed = false;
        let result = (|| -> Result<()> {
            set_and_verify_file_mode(&file, 0o600, label)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            self.ensure_regular_binding(&temp, created.st_dev as u64, created.st_ino as u64)?;
            before_create()?;
            self.ensure_regular_binding(&temp, created.st_dev as u64, created.st_ino as u64)?;
            match rustix::fs::renameat_with(
                &self.file,
                temp.as_str(),
                &self.file,
                name,
                rustix::fs::RenameFlags::NOREPLACE,
            ) {
                Ok(()) => {
                    committed = true;
                    self.sync()
                }
                Err(rustix::io::Errno::EXIST) => {
                    after_noreplace_conflict()?;
                    if !verify_existing()? {
                        anyhow::bail!(
                            "{label} disappeared after the no-replace conflict; durable marker creation was not proven"
                        );
                    }
                    Ok(())
                }
                Err(error) => Err(error).with_context(|| {
                    format!(
                        "failed to commit {label} without replacement at {}/{}",
                        self.display.display(),
                        name
                    )
                }),
            }
        })();
        if !committed
            && self
                .ensure_regular_binding(&temp, created.st_dev as u64, created.st_ino as u64)
                .is_ok()
        {
            let _ = self.unlink_file(&temp);
        }
        result
    }

    fn atomic_write_with_hooks<B, C>(
        &self,
        name: &str,
        bytes: &[u8],
        mode: u32,
        before_rename: B,
        check_binding: C,
    ) -> Result<()>
    where
        B: FnOnce() -> Result<()>,
        C: FnMut() -> Result<()>,
    {
        let mut check_binding = check_binding;
        check_binding()?;
        let temp = format!(".{name}.tmp-{}", uuid::Uuid::new_v4());
        let fd = rustix::fs::openat(
            &self.file,
            temp.as_str(),
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(mode as _),
        )
        .with_context(|| {
            format!(
                "failed to create anchored temporary file {}/{}",
                self.display.display(),
                temp
            )
        })?;
        let result = (|| -> Result<()> {
            let mut file = File::from(fd);
            set_and_verify_file_mode(&file, mode, "anchored temporary file")?;
            file.write_all(bytes).with_context(|| {
                format!(
                    "failed to write anchored temporary file {}/{}",
                    self.display.display(),
                    temp
                )
            })?;
            file.sync_all().with_context(|| {
                format!(
                    "failed to sync anchored temporary file {}/{}",
                    self.display.display(),
                    temp
                )
            })?;
            drop(file);
            before_rename()?;
            check_binding()?;
            rustix::fs::renameat(&self.file, temp.as_str(), &self.file, name).with_context(
                || {
                    format!(
                        "failed to atomically replace anchored file {}/{}",
                        self.display.display(),
                        name
                    )
                },
            )?;
            self.sync()
        })();
        if result.is_err() {
            // If authority changed, fail closed and leave the staged inode for
            // the next anchored recovery instead of mutating a detached tree.
            if check_binding().is_ok() {
                let _ = self.unlink_file(&temp);
            }
        }
        result
    }

    fn rename_to(&self, source: &str, destination_dir: &Self, destination: &str) -> Result<()> {
        rustix::fs::renameat(&self.file, source, &destination_dir.file, destination).with_context(
            || {
                format!(
                    "failed to rename {}/{} to {}/{}",
                    self.display.display(),
                    source,
                    destination_dir.display.display(),
                    destination
                )
            },
        )?;
        self.sync()?;
        if self.dev != destination_dir.dev || self.ino != destination_dir.ino {
            destination_dir.sync()?;
        }
        Ok(())
    }

    fn unlink_file(&self, name: &str) -> Result<()> {
        match rustix::fs::unlinkat(&self.file, name, rustix::fs::AtFlags::empty()) {
            Ok(()) => self.sync(),
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "failed to remove anchored file {}/{}",
                    self.display.display(),
                    name
                )
            }),
        }
    }

    fn create_exclusive_file(&self, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
        let fd = rustix::fs::openat(
            &self.file,
            name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(mode as _),
        )
        .with_context(|| {
            format!(
                "failed to create exclusive anchored file {}/{}",
                self.display.display(),
                name
            )
        })?;
        let result = (|| -> Result<()> {
            let mut file = File::from(fd);
            set_and_verify_file_mode(&file, mode, "exclusive anchored file")?;
            file.write_all(bytes)?;
            file.sync_all()?;
            self.sync()
        })();
        if result.is_err() {
            let _ = self.unlink_file(name);
        }
        result
    }

    fn quarantine_verified_regular<C>(
        &self,
        name: &str,
        context: &str,
        check_binding: C,
    ) -> Result<()>
    where
        C: FnMut() -> Result<()>,
    {
        self.quarantine_verified_regular_with_hooks(
            name,
            context,
            |_| Ok(()),
            |_| Ok(()),
            check_binding,
        )
    }

    fn quarantine_verified_regular_with_hooks<B, U, C>(
        &self,
        name: &str,
        context: &str,
        mut before_quarantine: B,
        mut before_unlink: U,
        mut check_binding: C,
    ) -> Result<()>
    where
        B: FnMut(&str) -> Result<()>,
        U: FnMut(&str) -> Result<()>,
        C: FnMut() -> Result<()>,
    {
        check_binding()?;
        let Some((file, opened)) = self.open_regular(name, context)? else {
            return Ok(());
        };
        self.ensure_regular_binding(name, opened.st_dev as u64, opened.st_ino as u64)
            .with_context(|| format!("{context} changed before quarantine"))?;

        let quarantine = format!(".journal.json.quarantine-{}", uuid::Uuid::new_v4());
        check_binding()?;
        self.ensure_regular_binding(name, opened.st_dev as u64, opened.st_ino as u64)
            .with_context(|| format!("{context} changed before quarantine"))?;
        before_quarantine(&quarantine)?;
        rustix::fs::renameat_with(
            &self.file,
            name,
            &self.file,
            quarantine.as_str(),
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .with_context(|| {
            format!(
                "failed to quarantine {context} {}/{} as {}",
                self.display.display(),
                name,
                quarantine
            )
        })?;
        self.sync()?;

        // A raced replacement may have occupied `name` in the narrow window
        // between the last identity check and rename. Never unlink until the
        // unpredictable quarantine pathname is proven to hold the originally
        // opened inode.
        check_binding()?;
        let (_, quarantined) = self
            .open_regular(&quarantine, context)?
            .with_context(|| format!("quarantined {context} disappeared before cleanup"))?;
        if quarantined.st_dev != opened.st_dev || quarantined.st_ino != opened.st_ino {
            anyhow::bail!(
                "{context} changed while being quarantined; retained at {}/{}",
                self.display.display(),
                quarantine
            );
        }

        before_unlink(&quarantine)?;
        check_binding()?;
        self.ensure_regular_binding(&quarantine, opened.st_dev as u64, opened.st_ino as u64)
            .with_context(|| format!("quarantined {context} changed before unlink"))?;
        let result = self.unlink_file(&quarantine);
        drop(file);
        result
    }

    fn remove_child_dir(&self, name: &str) -> Result<()> {
        match rustix::fs::unlinkat(&self.file, name, rustix::fs::AtFlags::REMOVEDIR) {
            Ok(()) => self.sync(),
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "failed to remove anchored directory {}/{}",
                    self.display.display(),
                    name
                )
            }),
        }
    }

    /// Empty this exact open directory without following a pathname back to
    /// it. Every child is first moved to an unpredictable quarantine name and
    /// its inode is revalidated there. Concurrent additions or substitutions
    /// therefore make cleanup fail closed instead of deleting the newcomer.
    fn remove_contents_recursive(&self) -> Result<()> {
        let mut directory = rustix::fs::Dir::read_from(&self.file).with_context(|| {
            format!(
                "failed to enumerate anchored directory {}",
                self.display.display()
            )
        })?;
        let mut names = Vec::<CString>::new();
        for entry in &mut directory {
            let entry = entry.with_context(|| {
                format!(
                    "failed to enumerate anchored directory {}",
                    self.display.display()
                )
            })?;
            let name = entry.file_name();
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                names.push(name.to_owned());
            }
        }
        drop(directory);

        for name in names {
            let before = match rustix::fs::statat(
                &self.file,
                name.as_c_str(),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT) => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to inspect anchored uninstall entry {}/{}",
                            self.display.display(),
                            name.to_string_lossy()
                        )
                    })
                }
            };
            let quarantine = CString::new(format!(".kin-uninstall-entry-{}", uuid::Uuid::new_v4()))
                .expect("generated uninstall quarantine name contains no NUL");
            rustix::fs::renameat_with(
                &self.file,
                name.as_c_str(),
                &self.file,
                quarantine.as_c_str(),
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .with_context(|| {
                format!(
                    "failed to quarantine anchored uninstall entry {}/{}",
                    self.display.display(),
                    name.to_string_lossy()
                )
            })?;
            let quarantined = rustix::fs::statat(
                &self.file,
                quarantine.as_c_str(),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .context("quarantined uninstall entry disappeared")?;
            if quarantined.st_dev != before.st_dev
                || quarantined.st_ino != before.st_ino
                || quarantined.st_mode != before.st_mode
            {
                anyhow::bail!(
                    "uninstall entry changed while being quarantined; preserving {}/{}",
                    self.display.display(),
                    quarantine.to_string_lossy()
                );
            }

            let is_directory = rustix::fs::FileType::from_raw_mode(quarantined.st_mode)
                == rustix::fs::FileType::Directory;
            if is_directory {
                let fd = rustix::fs::openat(
                    &self.file,
                    quarantine.as_c_str(),
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .context("failed to pin quarantined uninstall directory")?;
                let child = Self::from_file(
                    File::from(fd),
                    self.display.join(quarantine.to_string_lossy().as_ref()),
                )?;
                if child.dev != quarantined.st_dev as u64 || child.ino != quarantined.st_ino as u64
                {
                    anyhow::bail!(
                        "quarantined uninstall directory changed while being opened; preserving {}/{}",
                        self.display.display(),
                        quarantine.to_string_lossy()
                    );
                }
                child.remove_contents_recursive()?;
                child.ensure_empty()?;
                let current = rustix::fs::statat(
                    &self.file,
                    quarantine.as_c_str(),
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
                .context("quarantined uninstall directory disappeared before removal")?;
                if current.st_dev as u64 != child.dev || current.st_ino as u64 != child.ino {
                    anyhow::bail!(
                        "quarantined uninstall directory binding changed; preserving {}/{}",
                        self.display.display(),
                        quarantine.to_string_lossy()
                    );
                }
                rustix::fs::unlinkat(
                    &self.file,
                    quarantine.as_c_str(),
                    rustix::fs::AtFlags::REMOVEDIR,
                )
                .context("failed to remove quarantined uninstall directory")?;
            } else {
                let current = rustix::fs::statat(
                    &self.file,
                    quarantine.as_c_str(),
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
                .context("quarantined uninstall entry disappeared before removal")?;
                if current.st_dev != quarantined.st_dev || current.st_ino != quarantined.st_ino {
                    anyhow::bail!(
                        "quarantined uninstall entry binding changed; preserving {}/{}",
                        self.display.display(),
                        quarantine.to_string_lossy()
                    );
                }
                rustix::fs::unlinkat(
                    &self.file,
                    quarantine.as_c_str(),
                    rustix::fs::AtFlags::empty(),
                )
                .context("failed to remove quarantined uninstall entry")?;
            }
        }
        self.sync()?;
        self.ensure_empty()
    }

    fn ensure_empty(&self) -> Result<()> {
        let mut entries = rustix::fs::Dir::read_from(&self.file).with_context(|| {
            format!(
                "failed to read anchored directory {}",
                self.display.display()
            )
        })?;
        for entry in &mut entries {
            let entry = entry.with_context(|| {
                format!(
                    "failed to enumerate anchored directory {}",
                    self.display.display()
                )
            })?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                anyhow::bail!(
                    "anchored directory contains an unexpected entry: {}/{}",
                    self.display.display(),
                    String::from_utf8_lossy(name)
                );
            }
        }
        Ok(())
    }

    fn entry_names(&self) -> Result<Vec<String>> {
        let mut entries = rustix::fs::Dir::read_from(&self.file).with_context(|| {
            format!(
                "failed to read anchored directory {}",
                self.display.display()
            )
        })?;
        let mut names = Vec::new();
        for entry in &mut entries {
            let entry = entry.with_context(|| {
                format!(
                    "failed to enumerate anchored directory {}",
                    self.display.display()
                )
            })?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            names.push(
                std::str::from_utf8(bytes)
                    .context("anchored directory contains a non-UTF-8 entry")?
                    .to_string(),
            );
        }
        Ok(names)
    }

    fn sync(&self) -> Result<()> {
        rustix::fs::fsync(&self.file).with_context(|| {
            format!(
                "failed to sync anchored directory {}",
                self.display.display()
            )
        })
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct InstallLayout {
    parent: AnchoredDir,
    root_name: String,
    root: AnchoredDir,
    bin: AnchoredDir,
    lib: AnchoredDir,
    lock_dev: u64,
    lock_ino: u64,
}

#[cfg(unix)]
impl InstallLayout {
    fn from_locked_root(
        parent: AnchoredDir,
        root_name: String,
        root_dir: AnchoredDir,
        lock_dev: u64,
        lock_ino: u64,
    ) -> Result<Self> {
        ensure_root_lock_binding(&parent, &root_name, &root_dir, lock_dev, lock_ino)?;
        let bin =
            open_or_create_managed_dir(&parent, &root_name, &root_dir, lock_dev, lock_ino, "bin")?;
        let lib =
            open_or_create_managed_dir(&parent, &root_name, &root_dir, lock_dev, lock_ino, "lib")?;
        let layout = Self {
            parent,
            root_name,
            root: root_dir,
            bin,
            lib,
            lock_dev,
            lock_ino,
        };
        layout.ensure_bound()?;
        Ok(layout)
    }

    fn ensure_bound(&self) -> Result<()> {
        self.parent
            .ensure_child_binding(&self.root_name, &self.root)?;
        self.root
            .ensure_regular_binding("update.lock", self.lock_dev, self.lock_ino)?;
        self.root.ensure_child_binding("bin", &self.bin)?;
        self.root.ensure_child_binding("lib", &self.lib)
    }

    fn component_dir(&self, component: ComponentSpec) -> &AnchoredDir {
        match component.location {
            ComponentLocation::Bin => &self.bin,
            ComponentLocation::Lib => &self.lib,
        }
    }
}

#[cfg(unix)]
fn ensure_root_lock_binding(
    parent: &AnchoredDir,
    root_name: &str,
    root: &AnchoredDir,
    lock_dev: u64,
    lock_ino: u64,
) -> Result<()> {
    parent.ensure_child_binding(root_name, root)?;
    root.ensure_regular_binding("update.lock", lock_dev, lock_ino)
}

#[cfg(unix)]
fn open_or_create_managed_dir(
    parent: &AnchoredDir,
    root_name: &str,
    root: &AnchoredDir,
    lock_dev: u64,
    lock_ino: u64,
    name: &str,
) -> Result<AnchoredDir> {
    ensure_root_lock_binding(parent, root_name, root, lock_dev, lock_ino)?;
    match root.stat_entry(name)? {
        Some(stat)
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                == rustix::fs::FileType::Directory =>
        {
            let child = root.open_child(name)?;
            ensure_root_lock_binding(parent, root_name, root, lock_dev, lock_ino)?;
            root.ensure_child_binding(name, &child)?;
            child.set_mode(0o700, "managed Kin component directory")?;
            Ok(child)
        }
        Some(_) => anyhow::bail!(
            "managed path is not a real non-symlink directory: {}/{}",
            root.display.display(),
            name
        ),
        None => {
            ensure_root_lock_binding(parent, root_name, root, lock_dev, lock_ino)?;
            let child = root.create_child(name, 0o700)?;
            ensure_root_lock_binding(parent, root_name, root, lock_dev, lock_ino)?;
            root.ensure_child_binding(name, &child)?;
            Ok(child)
        }
    }
}

#[cfg(unix)]
#[derive(Debug)]
enum UnjournaledRootKind {
    Transaction,
    Staging,
}

#[cfg(unix)]
struct PendingUnjournaledRoot<'a> {
    install: &'a InstallLayout,
    name: String,
    root: Option<AnchoredDir>,
    kind: UnjournaledRootKind,
}

#[cfg(unix)]
impl<'a> PendingUnjournaledRoot<'a> {
    fn new(
        install: &'a InstallLayout,
        name: String,
        root: AnchoredDir,
        kind: UnjournaledRootKind,
    ) -> Self {
        Self {
            install,
            name,
            root: Some(root),
            kind,
        }
    }

    fn root(&self) -> &AnchoredDir {
        self.root
            .as_ref()
            .expect("pending updater root must remain armed")
    }

    fn disarm(mut self) -> AnchoredDir {
        self.root
            .take()
            .expect("pending updater root must remain armed")
    }
}

#[cfg(unix)]
impl Drop for PendingUnjournaledRoot<'_> {
    fn drop(&mut self) {
        let Some(root) = self.root.as_ref() else {
            return;
        };
        let _ = match self.kind {
            UnjournaledRootKind::Transaction => {
                cleanup_journalless_transaction_at(self.install, &self.name, root)
            }
            UnjournaledRootKind::Staging => cleanup_staging_tree_at(self.install, &self.name, root),
        };
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct TransactionLayout {
    name: String,
    root: AnchoredDir,
    old: AnchoredDir,
    old_bin: AnchoredDir,
    old_lib: AnchoredDir,
}

#[cfg(unix)]
impl TransactionLayout {
    fn create(install: &InstallLayout) -> Result<Self> {
        Self::create_with_hook(install, |_| Ok(()))
    }

    fn create_with_hook<F>(install: &InstallLayout, mut after_step: F) -> Result<Self>
    where
        F: FnMut(&str) -> Result<()>,
    {
        install.ensure_bound()?;
        let name = format!("{TRANSACTION_PREFIX}{}", uuid::Uuid::new_v4());
        let root = install.root.create_child(&name, 0o700)?;
        let pending = PendingUnjournaledRoot::new(
            install,
            name.clone(),
            root,
            UnjournaledRootKind::Transaction,
        );
        after_step("transaction-root")?;
        install.ensure_bound()?;
        install.root.ensure_child_binding(&name, pending.root())?;
        let old = pending.root().create_child("old", 0o700)?;
        after_step("transaction-old")?;
        install.ensure_bound()?;
        install.root.ensure_child_binding(&name, pending.root())?;
        pending.root().ensure_child_binding("old", &old)?;
        let old_bin = old.create_child("bin", 0o700)?;
        after_step("transaction-old-bin")?;
        install.ensure_bound()?;
        install.root.ensure_child_binding(&name, pending.root())?;
        pending.root().ensure_child_binding("old", &old)?;
        old.ensure_child_binding("bin", &old_bin)?;
        let old_lib = old.create_child("lib", 0o700)?;
        after_step("transaction-old-lib")?;
        install.ensure_bound()?;
        install.root.ensure_child_binding(&name, pending.root())?;
        pending.root().ensure_child_binding("old", &old)?;
        old.ensure_child_binding("bin", &old_bin)?;
        old.ensure_child_binding("lib", &old_lib)?;
        after_step("transaction-validated")?;
        let root = pending.disarm();
        Ok(Self {
            name,
            root,
            old,
            old_bin,
            old_lib,
        })
    }

    fn open(install: &InstallLayout, transaction_root: &Path) -> Result<Self> {
        install.ensure_bound()?;
        let name = transaction_root
            .file_name()
            .and_then(|name| name.to_str())
            .context("transaction root name is not UTF-8")?
            .to_string();
        let root = install.root.open_child(&name)?;
        let old = root.open_child("old")?;
        let old_bin = old.open_child("bin")?;
        let old_lib = old.open_child("lib")?;
        let layout = Self {
            name,
            root,
            old,
            old_bin,
            old_lib,
        };
        layout.ensure_bound(install)?;
        Ok(layout)
    }

    fn ensure_bound(&self, install: &InstallLayout) -> Result<()> {
        install.ensure_bound()?;
        install.root.ensure_child_binding(&self.name, &self.root)?;
        self.root.ensure_child_binding("old", &self.old)?;
        self.old.ensure_child_binding("bin", &self.old_bin)?;
        self.old.ensure_child_binding("lib", &self.old_lib)
    }

    fn component_dir(&self, component: ComponentSpec) -> &AnchoredDir {
        match component.location {
            ComponentLocation::Bin => &self.old_bin,
            ComponentLocation::Lib => &self.old_lib,
        }
    }
}

#[cfg(unix)]
#[derive(Debug)]
struct StagingLayout {
    parent: AnchoredDir,
    root_name: String,
    root: AnchoredDir,
    bin: AnchoredDir,
    lib: AnchoredDir,
}

#[cfg(unix)]
impl StagingLayout {
    fn open(stage_root: &Path) -> Result<Self> {
        let parent_path = stage_root.parent().context("staging root has no parent")?;
        let root_name = stage_root
            .file_name()
            .and_then(|name| name.to_str())
            .context("staging root name is not UTF-8")?
            .to_string();
        let parent = AnchoredDir::open_ambient(parent_path)?;
        let root = parent.open_child(&root_name)?;
        let bin = root.open_child("bin")?;
        let lib = root.open_child("lib")?;
        let layout = Self {
            parent,
            root_name,
            root,
            bin,
            lib,
        };
        layout.ensure_bound()?;
        Ok(layout)
    }

    fn ensure_bound(&self) -> Result<()> {
        self.parent
            .ensure_child_binding(&self.root_name, &self.root)?;
        self.root.ensure_child_binding("bin", &self.bin)?;
        self.root.ensure_child_binding("lib", &self.lib)
    }

    fn component_dir(&self, component: ComponentSpec) -> &AnchoredDir {
        match component.location {
            ComponentLocation::Bin => &self.bin,
            ComponentLocation::Lib => &self.lib,
        }
    }
}

#[cfg(unix)]
fn cleanup_staging_tree_at(install: &InstallLayout, name: &str, root: &AnchoredDir) -> Result<()> {
    install.ensure_bound()?;
    install.root.ensure_child_binding(name, root)?;
    let mut root_entries = root.entry_names()?;
    root_entries.sort();
    if root_entries
        .iter()
        .any(|entry| entry != "bin" && entry != "lib")
    {
        anyhow::bail!(
            "staging directory contains an unexpected entry: {}",
            root.display.display()
        );
    }
    for directory_name in ["bin", "lib"] {
        let Some(stat) = root.stat_entry(directory_name)? else {
            continue;
        };
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
            anyhow::bail!(
                "staging path is not a real directory: {}/{}",
                root.display.display(),
                directory_name
            );
        }
        let directory = root.open_child(directory_name)?;
        for entry in directory.entry_names()? {
            let stat = directory
                .stat_entry(&entry)?
                .context("staging entry disappeared during cleanup")?;
            // The staged notification bundle is the one directory the staging
            // tree may hold. It is removed as a tree; every other non-file entry
            // is still refused rather than walked.
            if entry == NOTIFIER_BUNDLE_DIR
                && directory_name == "lib"
                && rustix::fs::FileType::from_raw_mode(stat.st_mode)
                    == rustix::fs::FileType::Directory
            {
                install.ensure_bound()?;
                install.root.ensure_child_binding(name, root)?;
                root.ensure_child_binding(directory_name, &directory)?;
                remove_bundle_tree(&directory, &entry)?;
                continue;
            }
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                != rustix::fs::FileType::RegularFile
            {
                anyhow::bail!(
                    "refusing unexpected staging entry type: {}/{}",
                    directory.display.display(),
                    entry
                );
            }
            install.ensure_bound()?;
            install.root.ensure_child_binding(name, root)?;
            root.ensure_child_binding(directory_name, &directory)?;
            directory.unlink_file(&entry)?;
        }
        directory.ensure_empty()?;
        install.ensure_bound()?;
        install.root.ensure_child_binding(name, root)?;
        root.ensure_child_binding(directory_name, &directory)?;
        root.remove_child_dir(directory_name)?;
    }
    root.ensure_empty()?;
    install.ensure_bound()?;
    install.root.ensure_child_binding(name, root)?;
    install.root.remove_child_dir(name)
}

/// Open a bundle subdirectory, creating it when it is not there yet.
///
/// Bundle members arrive one at a time and in archive order, so the directories
/// they need are created on demand. Every step re-proves the binding it just
/// used, the same way the component paths do, so a swapped directory cannot
/// redirect a later write.
#[cfg(unix)]
fn open_or_create_bundle_dir(parent: &AnchoredDir, name: &str) -> Result<AnchoredDir> {
    match parent.stat_entry(name)? {
        Some(stat)
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                == rustix::fs::FileType::Directory =>
        {
            let child = parent.open_child(name)?;
            parent.ensure_child_binding(name, &child)?;
            Ok(child)
        }
        Some(_) => anyhow::bail!(
            "notification bundle path is not a real non-symlink directory: {}/{}",
            parent.display.display(),
            name
        ),
        None => {
            // The install root remains private, while the app tree itself uses
            // the same conventional directory mode as the script and npm
            // installers. Keeping all delivery channels byte-and-mode
            // equivalent avoids an update silently changing bundle shape.
            let child = parent.create_child(name, 0o755)?;
            parent.ensure_child_binding(name, &child)?;
            Ok(child)
        }
    }
}

/// Materialize one bundle member beneath `bundle_root`.
#[cfg(unix)]
fn write_bundle_member(
    bundle_root: &AnchoredDir,
    member: &BundleMember,
    contents: &[u8],
    check_binding: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    check_binding()?;
    let segments: Vec<&str> = member.path.split('/').collect();
    let (leaf, directories) = if member.directory {
        (None, segments.as_slice())
    } else {
        let (leaf, rest) = segments
            .split_last()
            .context("notification bundle member has no name")?;
        (Some(*leaf), rest)
    };
    let mut current = bundle_root.try_clone()?;
    for directory in directories {
        current = open_or_create_bundle_dir(&current, directory)?;
    }
    let Some(leaf) = leaf else {
        return Ok(());
    };
    let mode = if member.executable { 0o755 } else { 0o644 };
    current.atomic_write_checked(leaf, contents, mode, || check_binding())
}

/// Read back the identity of an installed or staged bundle tree.
///
/// This is the read side of the same fold the archive walk computes, so a
/// bundle staged from an archive and the bundle later found on disk produce the
/// same `tree_sha256` when they hold the same thing.
#[cfg(unix)]
fn read_bundle_members(root: &AnchoredDir) -> Result<Vec<BundleMember>> {
    let mut members = Vec::new();
    let mut total_bytes = 0_u64;
    let mut pending = vec![(root.try_clone()?, String::new(), 0_usize)];
    while let Some((directory, prefix, depth)) = pending.pop() {
        if depth > MAX_NOTIFIER_BUNDLE_DEPTH {
            anyhow::bail!(
                "notification bundle is nested deeper than {MAX_NOTIFIER_BUNDLE_DEPTH} levels"
            );
        }
        let mut names = directory.entry_names()?;
        names.sort();
        for name in names {
            if members.len() >= MAX_NOTIFIER_BUNDLE_MEMBERS {
                anyhow::bail!(
                    "notification bundle exceeds its member limit of {MAX_NOTIFIER_BUNDLE_MEMBERS}"
                );
            }
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let stat = directory
                .stat_entry(&name)?
                .context("notification bundle entry disappeared while it was read")?;
            match rustix::fs::FileType::from_raw_mode(stat.st_mode) {
                rustix::fs::FileType::Directory => {
                    let child = directory.open_child(&name)?;
                    directory.ensure_child_binding(&name, &child)?;
                    members.push(BundleMember {
                        path: path.clone(),
                        directory: true,
                        executable: false,
                        size_bytes: 0,
                        sha256: String::new(),
                    });
                    pending.push((child, path, depth + 1));
                }
                rustix::fs::FileType::RegularFile => {
                    let identity = directory
                        .identity(&name, "notification bundle member")?
                        .context("notification bundle member disappeared while it was hashed")?;
                    total_bytes = total_bytes
                        .checked_add(identity.size_bytes)
                        .context("notification bundle size overflow")?;
                    if total_bytes > MAX_NOTIFIER_BUNDLE_BYTES {
                        anyhow::bail!(
                            "notification bundle exceeds its expanded-size limit of {MAX_NOTIFIER_BUNDLE_BYTES} bytes"
                        );
                    }
                    members.push(BundleMember {
                        path,
                        directory: false,
                        executable: stat.st_mode as u32 & 0o111 != 0,
                        size_bytes: identity.size_bytes,
                        sha256: identity.sha256,
                    });
                }
                _ => anyhow::bail!(
                    "notification bundle contains an entry that is neither a directory nor a regular file: {}/{}",
                    directory.display.display(),
                    name
                ),
            }
        }
    }
    Ok(members)
}

/// Identity of the bundle named `name` under `parent`, or `None` when there is
/// none. A non-directory sitting at that name is an error rather than an
/// absence: something else owns the path and must not be silently replaced.
#[cfg(unix)]
fn bundle_identity_at(parent: &AnchoredDir, name: &str) -> Result<Option<BundleIdentity>> {
    let Some(stat) = parent.stat_entry(name)? else {
        return Ok(None);
    };
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
        anyhow::bail!(
            "managed notification bundle path is not a real non-symlink directory: {}/{}",
            parent.display.display(),
            name
        );
    }
    let root = parent.open_child(name)?;
    parent.ensure_child_binding(name, &root)?;
    let mut members = read_bundle_members(&root)?;
    Ok(Some(bundle_identity_from_members(&mut members)?))
}

/// Identity of a bundle that must also be able to do its job.
///
/// Used for the staged bundle and for the bundle immediately after it is
/// installed. The live bundle being replaced is read with `bundle_identity_at`
/// instead: a previously broken bundle is a reason to update, not a reason to
/// refuse one.
#[cfg(unix)]
fn staged_bundle_identity_at(parent: &AnchoredDir, name: &str) -> Result<Option<BundleIdentity>> {
    let Some(stat) = parent.stat_entry(name)? else {
        return Ok(None);
    };
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
        anyhow::bail!(
            "staged notification bundle path is not a real non-symlink directory: {}/{}",
            parent.display.display(),
            name
        );
    }
    let root = parent.open_child(name)?;
    parent.ensure_child_binding(name, &root)?;
    let mut members = read_bundle_members(&root)?;
    validate_notifier_bundle_shape(&members)?;
    Ok(Some(bundle_identity_from_members(&mut members)?))
}

/// Remove a bundle tree, refusing anything the tree should not contain.
///
/// Written against anchored handles rather than `remove_dir_all` so a symlink
/// or a device node swapped into the tree stops the removal instead of
/// redirecting it somewhere outside the managed root.
#[cfg(unix)]
fn remove_bundle_tree(parent: &AnchoredDir, name: &str) -> Result<()> {
    let Some(stat) = parent.stat_entry(name)? else {
        return Ok(());
    };
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
        anyhow::bail!(
            "refusing to remove a notification bundle path that is not a directory: {}/{}",
            parent.display.display(),
            name
        );
    }
    let root = parent.open_child(name)?;
    parent.ensure_child_binding(name, &root)?;
    remove_bundle_contents(&root, 0)?;
    root.ensure_empty()?;
    parent.ensure_child_binding(name, &root)?;
    parent.remove_child_dir(name)
}

#[cfg(unix)]
fn remove_bundle_contents(directory: &AnchoredDir, depth: usize) -> Result<()> {
    if depth > MAX_NOTIFIER_BUNDLE_DEPTH {
        anyhow::bail!(
            "notification bundle is nested deeper than {MAX_NOTIFIER_BUNDLE_DEPTH} levels"
        );
    }
    for name in directory.entry_names()? {
        let stat = directory
            .stat_entry(&name)?
            .context("notification bundle entry disappeared during removal")?;
        match rustix::fs::FileType::from_raw_mode(stat.st_mode) {
            rustix::fs::FileType::Directory => {
                let child = directory.open_child(&name)?;
                directory.ensure_child_binding(&name, &child)?;
                remove_bundle_contents(&child, depth + 1)?;
                child.ensure_empty()?;
                directory.ensure_child_binding(&name, &child)?;
                directory.remove_child_dir(&name)?;
            }
            rustix::fs::FileType::RegularFile => directory.unlink_file(&name)?,
            _ => anyhow::bail!(
                "refusing to remove an unexpected notification bundle entry: {}/{}",
                directory.display.display(),
                name
            ),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_file_atomically(path: &Path, bytes: &[u8], unix_mode: u32) -> Result<()> {
    #[cfg(not(unix))]
    let _ = unix_mode;
    let parent = path
        .parent()
        .with_context(|| format!("path has no parent: {}", path.display()))?;
    let temp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("update"),
        uuid::Uuid::new_v4()
    ));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(unix_mode);
        }
        let mut file = options
            .open(&temp)
            .with_context(|| format!("failed to create temporary file {}", temp.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("failed to write temporary file {}", temp.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync temporary file {}", temp.display()))?;
        drop(file);
        fs::rename(&temp, path).with_context(|| {
            format!(
                "failed to atomically replace {} with {}",
                path.display(),
                temp.display()
            )
        })?;
        sync_dir(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(not(unix))]
fn durable_rename(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination).with_context(|| {
        format!(
            "failed to rename {} to {}",
            source.display(),
            destination.display()
        )
    })?;
    if let Some(parent) = source.parent() {
        sync_dir(parent)?;
    }
    if destination.parent() != source.parent() {
        if let Some(parent) = destination.parent() {
            sync_dir(parent)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn durable_remove_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sync_dir(parent)?;
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", path.display())),
    }
}

#[cfg(not(unix))]
fn durable_remove_dir_all(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sync_dir(parent)?;
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {} for hashing", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn file_identity_from_open_file(file: &File, context: &str) -> Result<FileIdentity> {
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect open {context}"))?;
    if !metadata.is_file() {
        anyhow::bail!("open {context} is not a regular file");
    }
    let mut reader = file
        .try_clone()
        .with_context(|| format!("failed to duplicate open {context}"))?;
    reader
        .rewind()
        .with_context(|| format!("failed to rewind open {context}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("failed to hash open {context}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(FileIdentity {
        sha256: hex::encode(hasher.finalize()),
        size_bytes: metadata.len(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct FileIdentity {
    sha256: String,
    size_bytes: u64,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct WindowsFileId([u8; 16]);

#[cfg(windows)]
impl WindowsFileId {
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub(crate) fn zero() -> Self {
        Self([0; 16])
    }

    fn from_legacy_u64(value: u64) -> Self {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        Self(bytes)
    }

    fn is_zero(self) -> bool {
        self.0 == [0; 16]
    }
}

#[cfg(windows)]
impl std::fmt::Display for WindowsFileId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

#[cfg(windows)]
impl PartialEq<u64> for WindowsFileId {
    fn eq(&self, other: &u64) -> bool {
        if *other == 0 {
            self.is_zero()
        } else {
            *self == Self::from_legacy_u64(*other)
        }
    }
}

#[cfg(windows)]
impl serde::Serialize for WindowsFileId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

#[cfg(windows)]
impl<'de> serde::Deserialize<'de> for WindowsFileId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = WindowsFileId;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a 32-character lowercase file-id hex string or legacy u64")
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(WindowsFileId::from_legacy_u64(value))
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() != 32
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(E::custom(
                        "Windows file identity must be exactly 32 lowercase hexadecimal characters",
                    ));
                }
                let mut bytes = [0_u8; 16];
                hex::decode_to_slice(value, &mut bytes).map_err(E::custom)?;
                Ok(WindowsFileId(bytes))
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PlatformObjectIdentity {
    namespace: u64,
    #[cfg(not(windows))]
    file: u64,
    #[cfg(windows)]
    file: WindowsFileId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ManagedComponentGeneration {
    identity: FileIdentity,
    binding: PlatformObjectIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ManagedBundleGeneration {
    root: PathBuf,
    root_binding: PlatformObjectIdentity,
    components: HashMap<String, Option<ManagedComponentGeneration>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EmbeddedBuildIdentity {
    version: String,
    commit: String,
    dirty: bool,
    source_known: bool,
    dependency_provenance: String,
}

impl EmbeddedBuildIdentity {
    fn current() -> Result<Self> {
        let reported_version = kin_buildinfo::version()
            .split_once(' ')
            .map_or(kin_buildinfo::version(), |(version, _)| version);
        if reported_version != CURRENT_VERSION {
            anyhow::bail!(
                "executing Kin build reports version {reported_version}, but the updater was compiled as {CURRENT_VERSION}"
            );
        }
        let build = kin_buildinfo::get();
        Ok(Self {
            version: CURRENT_VERSION.to_string(),
            commit: build.sha.to_string(),
            dirty: build.dirty,
            source_known: build.source_known,
            dependency_provenance: build.dependency_provenance.to_string(),
        })
    }

    fn require_published_release_identity(&self) -> Result<()> {
        if self.dirty
            || !self.source_known
            || self.commit.len() != 40
            || !self.commit.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            anyhow::bail!(
                "VFS shim auto-repair requires a clean published Kin build with a full embedded commit; executing build is version {} commit {} (dirty={}, source_known={})",
                self.version,
                self.commit,
                self.dirty,
                self.source_known
            );
        }
        Ok(())
    }
}

struct ExecutingProcessAuthority {
    path: PathBuf,
    generation: ManagedComponentGeneration,
    build: EmbeddedBuildIdentity,
    #[cfg(unix)]
    file: File,
    #[cfg(windows)]
    file: windows_update::ExecutingFileAuthority,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn capture_executing_unix_file() -> Result<(PathBuf, File, PlatformObjectIdentity)> {
    use std::os::unix::fs::MetadataExt as _;

    // `/proc/self/exe` resolves the process' live executable object, not the
    // possibly replaced pathname returned by `current_exe`. Keeping this file
    // open preserves authority over that inode across an updater rename.
    let file = File::open("/proc/self/exe")
        .context("failed to open the live /proc/self/exe process image")?;
    let metadata = file
        .metadata()
        .context("failed to inspect the live /proc/self/exe process image")?;
    if !metadata.is_file() {
        anyhow::bail!("the live /proc/self/exe process image is not a regular file");
    }
    let path = std::env::current_exe().context("failed to locate the running Kin executable")?;
    Ok((
        path,
        file,
        PlatformObjectIdentity {
            namespace: metadata.dev(),
            file: metadata.ino(),
        },
    ))
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct DarwinProcRegionInfo {
    protection: u32,
    max_protection: u32,
    inheritance: u32,
    flags: u32,
    offset: u64,
    behavior: u32,
    user_wired_count: u32,
    user_tag: u32,
    pages_resident: u32,
    pages_shared_now_private: u32,
    pages_swapped_out: u32,
    pages_dirtied: u32,
    ref_count: u32,
    shadow_depth: u32,
    share_mode: u32,
    private_pages_resident: u32,
    shared_pages_resident: u32,
    object_id: u32,
    depth: u32,
    address: u64,
    size: u64,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct DarwinProcRegionWithPathInfo {
    region: DarwinProcRegionInfo,
    vnode: libc::vnode_info_path,
}

#[cfg(target_os = "macos")]
#[inline(never)]
extern "C" fn updater_executable_text_marker() -> u8 {
    0x4b
}

#[cfg(target_os = "macos")]
fn capture_executing_unix_file() -> Result<(PathBuf, File, PlatformObjectIdentity)> {
    use std::mem::{size_of, zeroed};
    use std::os::unix::fs::MetadataExt as _;

    const PROC_PIDREGIONPATHINFO: i32 = 8;
    // SAFETY: the structure is an integer/C-layout output buffer. The marker
    // address lies in this executable's text mapping, and proc_pidinfo writes
    // at most the exact supplied structure size.
    let mut region: DarwinProcRegionWithPathInfo = unsafe { zeroed() };
    let result = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            PROC_PIDREGIONPATHINFO,
            updater_executable_text_marker as *const () as usize as u64,
            (&mut region as *mut DarwinProcRegionWithPathInfo).cast(),
            size_of::<DarwinProcRegionWithPathInfo>() as i32,
        )
    };
    if result != size_of::<DarwinProcRegionWithPathInfo>() as i32 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect the running Mach-O vnode mapping");
    }
    let mapped = &region.vnode.vip_vi.vi_stat;
    let path = std::env::current_exe().context("failed to locate the running Kin executable")?;
    let file = File::open(&path).with_context(|| {
        format!(
            "failed to retain an open handle to running executable {}",
            path.display()
        )
    })?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "failed to inspect retained running executable {}",
            path.display()
        )
    })?;
    let binding = PlatformObjectIdentity {
        namespace: metadata.dev(),
        file: metadata.ino(),
    };
    let mapped_binding = PlatformObjectIdentity {
        namespace: u64::from(mapped.vst_dev),
        file: mapped.vst_ino,
    };
    if binding != mapped_binding {
        anyhow::bail!(
            "running executable path was replaced before updater authority capture: mapped object {}:{}, opened object {}:{}",
            mapped_binding.namespace,
            mapped_binding.file,
            binding.namespace,
            binding.file
        );
    }
    Ok((path, file, binding))
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_os = "macos"))
))]
fn capture_executing_unix_file() -> Result<(PathBuf, File, PlatformObjectIdentity)> {
    anyhow::bail!("durable executing-process identity is unsupported on this Unix platform")
}

impl ExecutingProcessAuthority {
    fn capture() -> Result<Self> {
        let build = EmbeddedBuildIdentity::current()?;
        #[cfg(unix)]
        {
            let (path, file, binding) = capture_executing_unix_file()?;
            let identity = file_identity_from_open_file(&file, "executing Kin image")?;
            return Ok(Self {
                path,
                generation: ManagedComponentGeneration { identity, binding },
                build,
                file,
            });
        }
        #[cfg(windows)]
        {
            let file = windows_update::ExecutingFileAuthority::capture()?;
            let path = file.path().to_path_buf();
            let identity = file_identity_from_open_file(file.file(), "executing Kin image")?;
            let binding = file.binding().clone();
            return Ok(Self {
                path,
                generation: ManagedComponentGeneration { identity, binding },
                build,
                file,
            });
        }
        #[cfg(not(any(unix, windows)))]
        anyhow::bail!("durable executing-process identity is unsupported on this platform")
    }

    #[cfg(all(test, unix))]
    fn capture_test_file(path: &Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt as _;
        let file = File::open(path)
            .with_context(|| format!("failed to open test executable {}", path.display()))?;
        let metadata = file.metadata()?;
        let identity = file_identity_from_open_file(&file, "test executing Kin image")?;
        Ok(Self {
            path: path.to_path_buf(),
            generation: ManagedComponentGeneration {
                identity,
                binding: PlatformObjectIdentity {
                    namespace: metadata.dev(),
                    file: metadata.ino(),
                },
            },
            build: EmbeddedBuildIdentity::current()?,
            file,
        })
    }

    fn verify_durable_identity(&self) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let metadata = self
                .file
                .metadata()
                .context("failed to inspect durable executing Kin image handle")?;
            let binding = PlatformObjectIdentity {
                namespace: metadata.dev(),
                file: metadata.ino(),
            };
            let identity = file_identity_from_open_file(&self.file, "executing Kin image")?;
            if binding != self.generation.binding || identity != self.generation.identity {
                anyhow::bail!(
                    "durable executing Kin image identity changed during update preflight"
                );
            }
        }
        #[cfg(windows)]
        {
            self.file.validate()?;
            let identity = file_identity_from_open_file(self.file.file(), "executing Kin image")?;
            if identity != self.generation.identity {
                anyhow::bail!(
                    "durable executing Kin image identity changed during update preflight"
                );
            }
        }
        Ok(())
    }
}

struct UpdaterStartAuthority {
    bundle: ManagedBundleGeneration,
    executing: ExecutingProcessAuthority,
}

impl UpdaterStartAuthority {
    fn capture(requested_home: &Path, spec: &[ComponentSpec]) -> Result<Self> {
        let executing = ExecutingProcessAuthority::capture()?;
        let bundle = snapshot_managed_bundle_generation(requested_home, spec)?;
        let authority = Self { bundle, executing };
        authority.validate_managed_cli_binding()?;

        // An unlocked snapshot spans several component opens. A second exact
        // snapshot proves there was one stable full generation at startup;
        // the retained executing-image handle then survives path replacement.
        let confirmed = snapshot_managed_bundle_generation(requested_home, spec)?;
        if confirmed != authority.bundle {
            anyhow::bail!("managed Kin bundle changed while startup authority was captured");
        }
        Ok(Self {
            bundle: confirmed,
            executing: authority.executing,
        })
    }

    #[cfg(all(test, unix))]
    fn capture_test_file(
        requested_home: &Path,
        spec: &[ComponentSpec],
        executing_path: &Path,
    ) -> Result<Self> {
        let authority = Self {
            bundle: snapshot_managed_bundle_generation(requested_home, spec)?,
            executing: ExecutingProcessAuthority::capture_test_file(executing_path)?,
        };
        authority.validate_managed_cli_binding()?;
        Ok(authority)
    }

    fn validate_managed_cli_binding(&self) -> Result<()> {
        let cli_name = if cfg!(windows) { "kin.exe" } else { "kin" };
        let managed = self
            .bundle
            .components
            .get(cli_name)
            .and_then(Option::as_ref)
            .with_context(|| {
                format!(
                    "managed Kin executable is missing from {}",
                    self.bundle.root.join("bin").display()
                )
            })?;
        if managed != &self.executing.generation {
            anyhow::bail!(
                "refusing to update a different or replaced Kin installation. Executing image: {} ({} bytes, SHA-256 {}, object {}:{}). Managed target: {} ({} bytes, SHA-256 {}, object {}:{}). Invoke the exact managed target directly or use the package manager that owns the running executable",
                self.executing.path.display(),
                self.executing.generation.identity.size_bytes,
                self.executing.generation.identity.sha256,
                self.executing.generation.binding.namespace,
                self.executing.generation.binding.file,
                self.bundle.root.join("bin").join(cli_name).display(),
                managed.identity.size_bytes,
                managed.identity.sha256,
                managed.binding.namespace,
                managed.binding.file
            );
        }
        Ok(())
    }

    fn verify_locked(&self, lock: &InstallRootLock, spec: &[ComponentSpec]) -> Result<()> {
        self.executing.verify_durable_identity()?;
        verify_managed_bundle_generation_locked(lock, spec, &self.bundle)?;
        self.validate_managed_cli_binding()
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct PrivateTempLeaseRecord {
    schema_version: u32,
    kind: String,
    directory_id: String,
    pid: u32,
    process_start_time: u64,
    created_at_unix_seconds: u64,
    root_binding: PlatformObjectIdentity,
    nonce: String,
    status: String,
}

struct PrivateUpdaterTempDir {
    path: PathBuf,
    lease: Option<File>,
    record: PrivateTempLeaseRecord,
    #[cfg(windows)]
    windows_root: Option<windows_update::WindowsPrivateTempDir>,
}

#[cfg(not(windows))]
struct PendingPrivateTempRoot {
    path: PathBuf,
    armed: bool,
}

#[cfg(not(windows))]
impl PendingPrivateTempRoot {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(not(windows))]
impl Drop for PendingPrivateTempRoot {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
            if let Some(parent) = self.path.parent() {
                let _ = sync_private_temp_parent(parent);
            }
        }
    }
}

fn ensure_private_updater_temp_container(parent: &Path) -> Result<PathBuf> {
    let path = parent.join(PRIVATE_TEMP_CONTAINER);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;

        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => {
                #[cfg(test)]
                observe_atomic_private_temp_mode(&path)?;
                sync_private_temp_parent(parent)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to create private updater container {}",
                        path.display()
                    )
                });
            }
        }
        private_temp_root_identity(&path)?;
    }
    #[cfg(windows)]
    {
        windows_update::ensure_private_temp_container(parent, PRIVATE_TEMP_CONTAINER)?;
        private_temp_root_identity(&path)?;
    }
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("private updater temp containers are unsupported on this platform");
    Ok(path)
}

#[cfg(all(test, unix))]
fn observe_atomic_private_temp_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let Ok(marker) = std::env::var("KIN_UPDATE_TEST_PRIVATE_CREATE_OBSERVE") else {
        return Ok(());
    };
    let metadata = fs::symlink_metadata(path)?;
    fs::write(
        marker,
        format!("{:o}", metadata.permissions().mode() & 0o777),
    )?;
    Ok(())
}

impl PrivateUpdaterTempDir {
    fn create(parent: &Path, prefix: &str, initial_status: &str) -> Result<Self> {
        if prefix != PREFLIGHT_TEMP_PREFIX {
            anyhow::bail!("unsupported private updater temp prefix '{prefix}'");
        }
        let container = ensure_private_updater_temp_container(parent)?;
        cleanup_stale_private_temp_dirs_in_container(&container, prefix)?;

        #[cfg(not(windows))]
        let path = {
            let mut selected = None;
            for _ in 0..128 {
                let candidate = container.join(format!("{prefix}{}", uuid::Uuid::new_v4()));
                #[cfg(unix)]
                let create_result = {
                    use std::os::unix::fs::DirBuilderExt as _;
                    let mut builder = fs::DirBuilder::new();
                    builder.mode(0o700);
                    builder.create(&candidate)
                };
                #[cfg(not(unix))]
                let create_result = fs::create_dir(&candidate);
                match create_result {
                    Ok(()) => {
                        #[cfg(all(test, unix))]
                        observe_atomic_private_temp_mode(&candidate)?;
                        selected = Some(candidate);
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!(
                                "failed to create private updater directory under {}",
                                container.display()
                            )
                        });
                    }
                }
            }
            selected.with_context(|| {
                format!(
                    "failed to allocate a unique private updater directory under {}",
                    container.display()
                )
            })?
        };
        #[cfg(windows)]
        let mut windows_root = windows_update::WindowsPrivateTempDir::create(&container, prefix)?;
        #[cfg(windows)]
        let path = windows_root.path().to_path_buf();
        #[cfg(not(windows))]
        let mut pending_root = PendingPrivateTempRoot::new(path.clone());

        let root_binding = private_temp_root_identity(&path)?;
        let directory_id = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(prefix))
            .context("private updater directory did not retain its canonical prefix")?
            .to_string();
        if !is_canonical_random_uuid_suffix(
            path.file_name()
                .and_then(|name| name.to_str())
                .context("private updater directory name is not UTF-8")?,
            prefix,
        ) {
            anyhow::bail!("private updater directory lacks a canonical random UUID");
        }
        let (pid, process_start_time) = current_process_lease_identity()?;
        let record = PrivateTempLeaseRecord {
            schema_version: TEMP_LEASE_SCHEMA_VERSION,
            kind: prefix.to_string(),
            directory_id,
            pid,
            process_start_time,
            created_at_unix_seconds: unix_time_seconds()?,
            root_binding,
            nonce: uuid::Uuid::new_v4().to_string(),
            status: initial_status.to_string(),
        };
        let lease_path = path.join(TEMP_LEASE_FILE);
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let lease = options.open(&lease_path).with_context(|| {
            format!(
                "failed to create updater temp lease {}",
                lease_path.display()
            )
        })?;
        lease
            .lock_exclusive()
            .context("failed to lock updater temp lease")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&lease_path, fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(windows)]
        windows_root.seal_file(&lease_path)?;

        let mut result = Self {
            path,
            lease: Some(lease),
            record,
            #[cfg(windows)]
            windows_root: Some(windows_root),
        };
        result.persist_status(initial_status)?;
        #[cfg(windows)]
        result.validate_windows()?;
        #[cfg(not(windows))]
        pending_root.disarm();
        Ok(result)
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn validate_root_binding(&self) -> Result<()> {
        let current = private_temp_root_identity(&self.path)?;
        if current != self.record.root_binding {
            anyhow::bail!(
                "private updater temp root binding changed: {}",
                self.path.display()
            );
        }
        #[cfg(windows)]
        self.validate_windows()?;
        Ok(())
    }

    fn persist_status(&mut self, status: &str) -> Result<()> {
        if status.is_empty() || status.len() > 128 || status.bytes().any(|byte| byte < b' ') {
            anyhow::bail!("invalid updater temp lease status");
        }
        self.record.status = status.to_string();
        let bytes = serde_json::to_vec_pretty(&self.record)
            .context("failed to serialize updater temp lease")?;
        if bytes.len() as u64 > MAX_TEMP_LEASE_BYTES {
            anyhow::bail!("updater temp lease exceeds its size bound");
        }
        self.validate_root_binding()?;
        let lease = self
            .lease
            .as_mut()
            .context("updater temp lease was already released")?;
        lease.set_len(0)?;
        lease.rewind()?;
        lease.write_all(&bytes)?;
        lease.sync_all()?;
        self.validate_root_binding()?;
        Ok(())
    }

    #[cfg(windows)]
    fn seal_staged_bundle(&mut self, stage_root: &Path, spec: &[ComponentSpec]) -> Result<()> {
        self.windows_root
            .as_mut()
            .context("private Windows updater root was released")?
            .seal_staged_bundle(stage_root, spec)
    }

    #[cfg(windows)]
    fn validate_windows(&self) -> Result<()> {
        self.windows_root
            .as_ref()
            .context("private Windows updater root was released")?
            .validate()
    }
}

impl Drop for PrivateUpdaterTempDir {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            let _ = fs2::FileExt::unlock(&lease);
            drop(lease);
        }
        #[cfg(windows)]
        {
            drop(self.windows_root.take());
        }
        #[cfg(not(windows))]
        {
            let _ = fs::remove_dir_all(&self.path);
            if let Some(parent) = self.path.parent() {
                let _ = sync_private_temp_parent(parent);
            }
        }
    }
}

fn unix_time_seconds() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")
        .map(|duration| duration.as_secs())
}

fn current_process_lease_identity() -> Result<(u32, u64)> {
    let pid = sysinfo::get_current_pid().map_err(anyhow::Error::msg)?;
    let system = System::new_all();
    let process = system
        .process(pid)
        .context("failed to inspect updater process start time")?;
    Ok((pid.as_u32(), process.start_time()))
}

fn lease_process_is_live(pid: u32, process_start_time: u64) -> bool {
    let system = System::new_all();
    system
        .process(Pid::from_u32(pid))
        .is_some_and(|process| process.start_time() == process_start_time)
}

fn sync_private_temp_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)
            .with_context(|| format!("failed to open temp parent {} for sync", path.display()))?
            .sync_all()
            .with_context(|| format!("failed to sync temp parent {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn private_temp_root_identity(path: &Path) -> Result<PlatformObjectIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect private temp root {}", path.display()))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o777 != 0o700
            // SAFETY: geteuid has no preconditions.
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            anyhow::bail!(
                "private updater temp root is not an owner-only real directory: {}",
                path.display()
            );
        }
        return Ok(PlatformObjectIdentity {
            namespace: metadata.dev(),
            file: metadata.ino(),
        });
    }
    #[cfg(windows)]
    {
        return windows_update::private_directory_identity(path);
    }
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("private updater directory identity is unsupported on this platform")
}

fn private_temp_directory_age(path: &Path) -> Result<Duration> {
    let modified = fs::symlink_metadata(path)?
        .modified()
        .context("private updater temp root has no modification time")?;
    Ok(std::time::SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default())
}

fn open_temp_lease_for_cleanup(path: &Path) -> Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .with_context(|| format!("failed to open updater temp lease {}", path.display()))
}

#[cfg(unix)]
fn remove_anchored_private_temp_contents(root: &AnchoredDir) -> Result<()> {
    let mut removed_any = false;
    for name in root.entry_names()? {
        let stat = root
            .stat_entry(&name)?
            .with_context(|| format!("private temp entry disappeared: {name}"))?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::Directory {
            let child = root.open_child(&name)?;
            remove_anchored_private_temp_contents(&child)?;
            root.ensure_child_binding(&name, &child)?;
            child.ensure_empty()?;
            root.remove_child_dir(&name)?;
        } else {
            root.unlink_file(&name)?;
        }
        if !removed_any {
            removed_any = true;
            maybe_crash_private_temp_cleanup("mid-delete");
        }
    }
    root.ensure_empty()
}

#[cfg(test)]
fn maybe_crash_private_temp_cleanup(point: &str) {
    if std::env::var("KIN_UPDATE_TEST_TEMP_CLEANUP_CRASH_POINT").as_deref() == Ok(point) {
        std::process::exit(87);
    }
}

#[cfg(not(test))]
fn maybe_crash_private_temp_cleanup(_point: &str) {}

fn remove_quarantined_private_temp_root(
    _parent: &Path,
    quarantine: &Path,
    expected: &PlatformObjectIdentity,
) -> Result<()> {
    #[cfg(unix)]
    {
        let parent_dir = AnchoredDir::open_ambient(_parent)?;
        let name = quarantine
            .file_name()
            .and_then(|name| name.to_str())
            .context("quarantined private temp name is not UTF-8")?;
        let root = parent_dir.open_child(name)?;
        let binding = PlatformObjectIdentity {
            namespace: root.dev,
            file: root.ino,
        };
        if &binding != expected {
            anyhow::bail!("quarantined private temp root changed before anchored removal");
        }
        remove_anchored_private_temp_contents(&root)?;
        parent_dir.ensure_child_binding(name, &root)?;
        parent_dir.remove_child_dir(name)?;
        return Ok(());
    }
    #[cfg(windows)]
    {
        if &private_temp_root_identity(quarantine)? != expected {
            anyhow::bail!("quarantined private temp root changed before removal");
        }
        return fs::remove_dir_all(quarantine).with_context(|| {
            format!(
                "failed to remove quarantined updater temp root {}",
                quarantine.display()
            )
        });
    }
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("private temp root removal is unsupported on this platform")
}

#[cfg(test)]
fn cleanup_stale_private_temp_dirs(parent: &Path, prefix: &str) -> Result<usize> {
    let container = ensure_private_updater_temp_container(parent)?;
    cleanup_stale_private_temp_dirs_in_container(&container, prefix)
}

fn cleanup_stale_private_temp_dirs_in_container(container: &Path, prefix: &str) -> Result<usize> {
    if prefix != PREFLIGHT_TEMP_PREFIX {
        anyhow::bail!("unsupported private updater temp prefix '{prefix}'");
    }
    private_temp_root_identity(container)?;
    let mut candidates = Vec::new();
    for entry in fs::read_dir(container).with_context(|| {
        format!(
            "failed to scan private updater temp container {}",
            container.display()
        )
    })? {
        if candidates.len() >= MAX_TEMP_LEASE_SCAN_ENTRIES {
            anyhow::bail!(
                "private updater temp container exceeds the inspection bound of {MAX_TEMP_LEASE_SCAN_ENTRIES} entries"
            );
        }
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .context("private updater temp container contains a non-UTF-8 entry")?
            .to_string();
        let active = is_canonical_random_uuid_suffix(&name, prefix);
        let reclaim = is_canonical_random_uuid_suffix(&name, PRIVATE_TEMP_RECLAIM_PREFIX);
        if !active && !reclaim {
            anyhow::bail!(
                "private updater temp container contains unexpected entry '{}'",
                entry.path().display()
            );
        }
        candidates.push((name, entry.path(), active));
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0));

    let mut reclaimed = 0_usize;
    for (name, path, active) in candidates {
        let root_binding = private_temp_root_identity(&path).with_context(|| {
            format!(
                "private updater temp container entry failed closed validation: {}",
                path.display()
            )
        })?;
        let lease_path = path.join(TEMP_LEASE_FILE);
        let mut stale_status = "unleased".to_string();
        let mut locked_lease = None;
        match fs::symlink_metadata(&lease_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.len() > MAX_TEMP_LEASE_BYTES
                {
                    if active && private_temp_directory_age(&path)? < UNLEASED_TEMP_GRACE {
                        continue;
                    }
                    stale_status = "invalid-old-lease".to_string();
                } else {
                    let mut lease = open_temp_lease_for_cleanup(&lease_path)?;
                    match lease.try_lock_exclusive() {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(error) => {
                            return Err(error).context("failed to inspect updater temp lease lock")
                        }
                    }
                    let mut bytes = Vec::with_capacity(metadata.len() as usize);
                    lease.read_to_end(&mut bytes)?;
                    let record = serde_json::from_slice::<PrivateTempLeaseRecord>(&bytes).ok();
                    if let Some(record) = record.as_ref() {
                        let active_id = active.then(|| name.strip_prefix(prefix).unwrap());
                        if record.schema_version != TEMP_LEASE_SCHEMA_VERSION
                            || record.kind != prefix
                            || uuid::Uuid::parse_str(&record.directory_id).is_err()
                            || active_id.is_some_and(|id| record.directory_id != id)
                            || record.root_binding != root_binding
                            || uuid::Uuid::parse_str(&record.nonce).is_err()
                        {
                            if active && private_temp_directory_age(&path)? < UNLEASED_TEMP_GRACE {
                                let _ = fs2::FileExt::unlock(&lease);
                                continue;
                            }
                            stale_status = "invalid-old-lease".to_string();
                        } else if lease_process_is_live(record.pid, record.process_start_time) {
                            let _ = fs2::FileExt::unlock(&lease);
                            continue;
                        } else {
                            stale_status = record.status.clone();
                        }
                    } else if active && private_temp_directory_age(&path)? < UNLEASED_TEMP_GRACE {
                        let _ = fs2::FileExt::unlock(&lease);
                        continue;
                    } else {
                        stale_status = "unparseable-old-lease".to_string();
                    }
                    locked_lease = Some(lease);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if active && private_temp_directory_age(&path)? < UNLEASED_TEMP_GRACE {
                    continue;
                }
            }
            Err(error) => return Err(error.into()),
        }

        let quarantine = if active {
            let quarantine = container.join(format!(
                "{PRIVATE_TEMP_RECLAIM_PREFIX}{}",
                uuid::Uuid::new_v4()
            ));
            fs::rename(&path, &quarantine).with_context(|| {
                format!(
                    "failed to quarantine stale updater temp root {}",
                    path.display()
                )
            })?;
            match private_temp_root_identity(&quarantine) {
                Ok(identity) if identity == root_binding => {}
                Ok(_) | Err(_) => {
                    let _ = fs::rename(&quarantine, &path);
                    anyhow::bail!(
                        "stale updater temp root identity changed during quarantine: {}",
                        path.display()
                    );
                }
            }
            sync_private_temp_parent(container)?;
            maybe_crash_private_temp_cleanup("after-rename");
            quarantine
        } else {
            path
        };
        remove_quarantined_private_temp_root(container, &quarantine, &root_binding)?;
        if let Some(lease) = locked_lease.take() {
            let _ = fs2::FileExt::unlock(&lease);
        }
        sync_private_temp_parent(container)?;
        reclaimed += 1;
        eprintln!("Updater temp cleanup reclaimed {name} (last lease status: {stale_status})");
    }
    Ok(reclaimed)
}

type VerifiedStagedIdentities = HashMap<String, FileIdentity>;

#[cfg(test)]
fn staged_identities_for_test(
    stage_root: &Path,
    spec: &[ComponentSpec],
) -> Result<VerifiedStagedIdentities> {
    #[cfg(unix)]
    {
        let staging = StagingLayout::open(stage_root)?;
        let mut identities = VerifiedStagedIdentities::new();
        for component in spec {
            if let Some(identity) = staging
                .component_dir(*component)
                .identity(component.name, "test staged component")?
            {
                identities.insert(component.name.to_string(), identity);
            }
        }
        return Ok(identities);
    }
    #[cfg(not(unix))]
    {
        let mut identities = VerifiedStagedIdentities::new();
        for component in spec {
            let path = component_path(stage_root, *component);
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    identities.insert(component.name.to_string(), file_identity(&path)?);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(identities)
    }
}

#[cfg(any(not(windows), test))]
fn bytes_identity(bytes: &[u8]) -> FileIdentity {
    FileIdentity {
        sha256: hex::encode(Sha256::digest(bytes)),
        size_bytes: bytes.len() as u64,
    }
}

fn file_identity(path: &Path) -> Result<FileIdentity> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {} for identity", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "identity input is not a regular non-symlink file: {}",
            path.display()
        );
    }
    Ok(FileIdentity {
        sha256: sha256_file(path)?,
        size_bytes: metadata.len(),
    })
}

fn verify_file_identity(path: &Path, expected: &FileIdentity, context: &str) -> Result<()> {
    let actual = file_identity(path)?;
    if &actual != expected {
        anyhow::bail!(
            "{context} identity mismatch at {}: expected {} bytes SHA-256 {}, got {} bytes SHA-256 {}",
            path.display(),
            expected.size_bytes,
            expected.sha256,
            actual.size_bytes,
            actual.sha256
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum ComponentLocation {
    Bin,
    Lib,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ComponentSpec {
    name: &'static str,
    location: ComponentLocation,
    required: bool,
}

/// Directory name of the macOS notification bundle, both inside a release
/// archive and under the managed `lib` directory once installed.
///
/// The bundle travels as a directory rather than as a component file because
/// replacing only its executable would break the seal `codesign` places over
/// the whole bundle, and an unsealed bundle is refused by the notification
/// system. It is therefore deliberately NOT a `ComponentSpec`: those are swapped
/// by inode identity over a single regular file, which a directory cannot
/// supply. It is instead a whole-tree participant with its own identity, staged,
/// backed up, swapped, and rolled back alongside the components.
const NOTIFIER_BUNDLE_DIR: &str = "KinNotifier.app";

/// Bundle members whose absence leaves nothing to launch or nothing to credit
/// the notification to. The same two the release archive shape check requires.
const NOTIFIER_BUNDLE_EXECUTABLE: &[&str] = &["Contents", "MacOS", "KinNotifier"];
const NOTIFIER_BUNDLE_PLIST: &[&str] = &["Contents", "Info.plist"];

/// A bundle is a fixed, small shape, so its walk is bounded rather than
/// unbounded over attacker-chosen structure. These match the caps the release
/// workflow's archive shape check applies on the publishing side.
const MAX_NOTIFIER_BUNDLE_MEMBERS: usize = 64;
const MAX_NOTIFIER_BUNDLE_DEPTH: usize = 6;
const MAX_NOTIFIER_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;

/// Whether this platform's release archive carries the notification bundle.
///
/// Keyed on the component contract rather than on the host, so a test that
/// drives the Linux or Windows contract from a macOS host still gets that
/// platform's rules.
fn spec_carries_notifier_bundle(spec: &[ComponentSpec]) -> bool {
    spec == MACOS_COMPONENTS
}

/// Whether an archive entry belongs to the notification bundle.
///
/// Matching on a whole path component (rather than a prefix) cannot be widened
/// by a crafted name like `KinNotifier.appx`, and the archive walker has already
/// rejected `..`, absolute paths, and link records before this is consulted.
fn is_notifier_bundle_entry(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == NOTIFIER_BUNDLE_DIR)
}

/// Whether this archive record names the bundle directory itself rather than
/// a member below it. Release tarballs contain this structural record because
/// the packaging workflow archives the whole artifact directory.
fn is_notifier_bundle_root_entry(path: &Path) -> bool {
    let mut components = path
        .components()
        .skip_while(|component| component.as_os_str() != std::ffi::OsStr::new(NOTIFIER_BUNDLE_DIR));
    components.next().is_some() && components.next().is_none()
}

/// The part of an archive member path that lies inside the bundle.
///
/// Returns the path relative to `KinNotifier.app` itself, which is what gets
/// recreated under the staging tree. Rejects the shapes that would let a member
/// land outside the bundle root or name something the bundle cannot contain.
fn notifier_bundle_member_path(path: &Path) -> Result<PathBuf> {
    let mut components = path
        .components()
        .skip_while(|component| component.as_os_str() != std::ffi::OsStr::new(NOTIFIER_BUNDLE_DIR));
    components
        .next()
        .context("archive entry is not inside the notification bundle")?;
    let mut relative = PathBuf::new();
    let mut depth = 0_usize;
    for component in components {
        let std::path::Component::Normal(name) = component else {
            anyhow::bail!(
                "notification bundle entry '{}' has an unsupported path component",
                path.display()
            );
        };
        let Some(name) = name.to_str() else {
            anyhow::bail!("notification bundle entry has a non-UTF-8 name");
        };
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            anyhow::bail!("notification bundle entry '{}' is not a plain name", name);
        }
        depth += 1;
        if depth > MAX_NOTIFIER_BUNDLE_DEPTH {
            anyhow::bail!(
                "notification bundle entry '{}' is nested deeper than {MAX_NOTIFIER_BUNDLE_DEPTH} levels",
                path.display()
            );
        }
        relative.push(name);
    }
    if relative.as_os_str().is_empty() {
        anyhow::bail!("notification bundle entry names the bundle root itself");
    }
    Ok(relative)
}

/// Identity of a whole notification bundle.
///
/// The transaction proves a component is the intended one by hashing its bytes.
/// A bundle has no single stream of bytes, so its identity is the fold of every
/// member in sorted order: relative path, whether it is a directory, its
/// executable bit, its size, and its content digest. Adding, removing, moving,
/// truncating, or de-executabling any member changes `tree_sha256`, which is
/// what makes it usable as a journal identity.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct BundleIdentity {
    tree_sha256: String,
    file_count: u64,
    total_bytes: u64,
}

/// One member of a bundle being assembled or measured.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct BundleMember {
    /// Path relative to the bundle root, as `/`-joined segments. Stored in this
    /// canonical form so an identity computed on one platform's separator
    /// conventions matches one computed on another's.
    path: String,
    directory: bool,
    executable: bool,
    size_bytes: u64,
    sha256: String,
}

/// Fold a sorted member list into a bundle identity.
///
/// Sorting first is what makes the digest independent of archive order and of
/// directory-read order, so the identity recorded when the bundle was staged is
/// the identity recomputed after it was installed.
fn bundle_identity_from_members(members: &mut Vec<BundleMember>) -> Result<BundleIdentity> {
    members.sort();
    members.dedup();
    let mut seen = HashSet::new();
    let mut hasher = Sha256::new();
    let mut file_count = 0_u64;
    let mut total_bytes = 0_u64;
    for member in members.iter() {
        if !seen.insert(member.path.as_str()) {
            anyhow::bail!(
                "notification bundle contains conflicting entries for '{}'",
                member.path
            );
        }
        hasher.update(member.path.as_bytes());
        hasher.update([0]);
        hasher.update([u8::from(member.directory), u8::from(member.executable)]);
        hasher.update(member.size_bytes.to_le_bytes());
        hasher.update(member.sha256.as_bytes());
        hasher.update([0]);
        if !member.directory {
            file_count += 1;
            total_bytes = total_bytes
                .checked_add(member.size_bytes)
                .context("notification bundle size overflow")?;
        }
    }
    // A tree with no files still gets an identity rather than an error. Identity
    // is a pure description of what is there; whether what is there can post a
    // notification is `validate_notifier_bundle_shape`'s question. Keeping them
    // separate is what lets a rollback recognize a half-removed tree instead of
    // failing to describe it, and the journal separately refuses to record an
    // empty identity as anything's original or staged bundle.
    Ok(BundleIdentity {
        tree_sha256: hex::encode(hasher.finalize()),
        file_count,
        total_bytes,
    })
}

/// Collects the notification bundle out of an archive walk.
///
/// The bundle carries its own budget because it is deliberately absent from the
/// release manifest's per-file inventory: the manifest covers swappable
/// components, and the bundle's bytes are authenticated by the archive digest
/// that was verified before any of this ran. Counting bundle members against
/// the inventory-derived expanded-size bound would therefore fail every macOS
/// archive, and counting them against nothing would leave them unbounded.
struct NotifierBundleCollector<'a> {
    members: Vec<BundleMember>,
    total_bytes: u64,
    root_entry_seen: bool,
    sink: &'a mut dyn FnMut(&BundleMember, &[u8]) -> Result<()>,
}

impl<'a> NotifierBundleCollector<'a> {
    fn new(sink: &'a mut dyn FnMut(&BundleMember, &[u8]) -> Result<()>) -> Self {
        Self {
            members: Vec::new(),
            total_bytes: 0,
            root_entry_seen: false,
            sink,
        }
    }

    fn record(&mut self, member: BundleMember, contents: &[u8]) -> Result<()> {
        if self.members.len() >= MAX_NOTIFIER_BUNDLE_MEMBERS {
            anyhow::bail!(
                "notification bundle exceeds its member limit of {MAX_NOTIFIER_BUNDLE_MEMBERS}"
            );
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(member.size_bytes)
            .context("notification bundle size overflow")?;
        if self.total_bytes > MAX_NOTIFIER_BUNDLE_BYTES {
            anyhow::bail!(
                "notification bundle exceeds its expanded-size limit of {MAX_NOTIFIER_BUNDLE_BYTES} bytes"
            );
        }
        (self.sink)(&member, contents)?;
        self.members.push(member);
        Ok(())
    }

    /// Take one archive entry that lives inside the bundle.
    ///
    /// Every ancestor directory is recorded alongside the file so that the
    /// identity covers the tree's shape and not merely its leaf contents, and
    /// so an archive that omits directory entries still produces the same
    /// identity as one that includes them.
    fn accept(&mut self, entry: &SimpleTarEntry) -> Result<()> {
        if is_notifier_bundle_root_entry(&entry.path) {
            if entry.kind != SimpleTarEntryKind::Directory {
                anyhow::bail!(
                    "notification bundle root '{}' must be a directory record",
                    entry.path.display()
                );
            }
            if entry.declared_size != 0 {
                anyhow::bail!(
                    "notification bundle root '{}' must have zero expanded size",
                    entry.path.display()
                );
            }
            if std::mem::replace(&mut self.root_entry_seen, true) {
                anyhow::bail!(
                    "notification bundle contains duplicate root entry '{}'",
                    entry.path.display()
                );
            }
            // The root is archive structure, not a member of the signed app
            // tree. It still consumed the archive walker's global entry budget,
            // but must not consume the bundle member budget or change identity.
            return Ok(());
        }
        let relative = notifier_bundle_member_path(&entry.path)?;
        let mut ancestor = PathBuf::new();
        let segments: Vec<_> = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy().into_owned())
            .collect();
        let leaf_is_directory = entry.kind == SimpleTarEntryKind::Directory;
        let directory_depth = if leaf_is_directory {
            segments.len()
        } else {
            segments.len().saturating_sub(1)
        };
        for segment in segments.iter().take(directory_depth) {
            ancestor.push(segment);
            let path = ancestor.to_string_lossy().replace('\\', "/");
            if self.members.iter().any(|member| member.path == path) {
                continue;
            }
            self.record(
                BundleMember {
                    path,
                    directory: true,
                    executable: false,
                    size_bytes: 0,
                    sha256: String::new(),
                },
                &[],
            )?;
        }
        if leaf_is_directory {
            return Ok(());
        }
        let path = relative.to_string_lossy().replace('\\', "/");
        if self.members.iter().any(|member| member.path == path) {
            anyhow::bail!("notification bundle contains duplicate member '{path}'");
        }
        self.record(
            BundleMember {
                path,
                directory: false,
                executable: entry.mode & 0o111 != 0,
                size_bytes: entry.declared_size,
                sha256: hex::encode(Sha256::digest(&entry.contents)),
            },
            &entry.contents,
        )
    }

    /// Nothing at all was seen, which is what a Linux or Windows archive looks
    /// like and what a macOS archive must never look like.
    fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    fn finish(mut self) -> Result<BundleIdentity> {
        validate_notifier_bundle_shape(&self.members)?;
        bundle_identity_from_members(&mut self.members)
    }
}

/// Reject a bundle that could not do its job once installed.
///
/// A bundle missing its executable has nothing to launch, and one missing its
/// `Info.plist` has no identity for macOS to credit the notification to. Both
/// failures are invisible at install time and show up only as a wrong sender
/// name, so they are refused here instead.
fn validate_notifier_bundle_shape(members: &[BundleMember]) -> Result<()> {
    for required in [NOTIFIER_BUNDLE_EXECUTABLE, NOTIFIER_BUNDLE_PLIST] {
        let path = required.join("/");
        let member = members
            .iter()
            .find(|member| member.path == path && !member.directory)
            .with_context(|| format!("notification bundle is missing '{path}'"))?;
        if member.size_bytes == 0 {
            anyhow::bail!("notification bundle member '{path}' is empty");
        }
    }
    let executable = NOTIFIER_BUNDLE_EXECUTABLE.join("/");
    if !members
        .iter()
        .any(|member| member.path == executable && member.executable)
    {
        anyhow::bail!("notification bundle member '{executable}' is not executable");
    }
    Ok(())
}

const MACOS_COMPONENTS: &[ComponentSpec] = &[
    // Keep the currently running executable last in the swap order. If a
    // platform refuses to rename it, every earlier swap is rolled back.
    ComponentSpec {
        name: "kin-daemon",
        location: ComponentLocation::Bin,
        required: true,
    },
    ComponentSpec {
        name: "kin-vfs",
        location: ComponentLocation::Bin,
        required: true,
    },
    // The MCP server is now `kin mcp start`; remove a stale pre-bundling
    // standalone binary instead of leaving a mixed-version command on PATH.
    ComponentSpec {
        name: "kin-mcp",
        location: ComponentLocation::Bin,
        required: false,
    },
    ComponentSpec {
        name: "libkin_vfs_shim.dylib",
        location: ComponentLocation::Lib,
        required: true,
    },
    ComponentSpec {
        name: "kin",
        location: ComponentLocation::Bin,
        required: true,
    },
];

const LINUX_COMPONENTS: &[ComponentSpec] = &[
    ComponentSpec {
        name: "kin-daemon",
        location: ComponentLocation::Bin,
        required: true,
    },
    ComponentSpec {
        name: "kin-vfs",
        location: ComponentLocation::Bin,
        required: true,
    },
    ComponentSpec {
        name: "kin-mcp",
        location: ComponentLocation::Bin,
        required: false,
    },
    ComponentSpec {
        name: "libkin_vfs_shim.so",
        location: ComponentLocation::Lib,
        required: true,
    },
    ComponentSpec {
        name: "kin",
        location: ComponentLocation::Bin,
        required: true,
    },
];

const WINDOWS_COMPONENTS: &[ComponentSpec] = &[
    ComponentSpec {
        name: "kin-daemon.exe",
        location: ComponentLocation::Bin,
        required: true,
    },
    // Native Windows projection is not a release requirement today. These are
    // still managed so a future archive installs them and an archive without
    // them removes stale copies from an older release.
    ComponentSpec {
        name: "kin-vfs.exe",
        location: ComponentLocation::Bin,
        required: false,
    },
    ComponentSpec {
        name: "kin-mcp.exe",
        location: ComponentLocation::Bin,
        required: false,
    },
    ComponentSpec {
        name: "kin_vfs_shim.dll",
        location: ComponentLocation::Lib,
        required: false,
    },
    ComponentSpec {
        name: "kin.exe",
        location: ComponentLocation::Bin,
        required: true,
    },
];

fn platform_bundle_spec(os: &str) -> Result<&'static [ComponentSpec]> {
    match os {
        "macos" => Ok(MACOS_COMPONENTS),
        "linux" => Ok(LINUX_COMPONENTS),
        "windows" => Ok(WINDOWS_COMPONENTS),
        _ => anyhow::bail!("unsupported OS for release bundle: {os}"),
    }
}

fn component_path(root: &Path, component: ComponentSpec) -> PathBuf {
    match component.location {
        ComponentLocation::Bin => root.join("bin").join(component.name),
        ComponentLocation::Lib => root.join("lib").join(component.name),
    }
}

fn snapshot_managed_bundle_generation(
    requested_home: &Path,
    spec: &[ComponentSpec],
) -> Result<ManagedBundleGeneration> {
    let root = validate_existing_install_root(requested_home)?;
    #[cfg(unix)]
    {
        let root_dir = AnchoredDir::open_ambient(&root)?;
        let bin = root_dir.open_child("bin")?;
        let lib = root_dir.open_child("lib")?;
        root_dir.ensure_child_binding("bin", &bin)?;
        root_dir.ensure_child_binding("lib", &lib)?;
        let mut components = HashMap::new();
        for component in spec {
            let directory = match component.location {
                ComponentLocation::Bin => &bin,
                ComponentLocation::Lib => &lib,
            };
            components.insert(
                component.name.to_string(),
                directory
                    .generation_identity(component.name, "managed bundle generation component")?,
            );
        }
        root_dir.ensure_child_binding("bin", &bin)?;
        root_dir.ensure_child_binding("lib", &lib)?;
        return Ok(ManagedBundleGeneration {
            root,
            root_binding: PlatformObjectIdentity {
                namespace: root_dir.dev,
                file: root_dir.ino,
            },
            components,
        });
    }
    #[cfg(windows)]
    {
        return windows_update::snapshot_managed_bundle_generation(root, spec);
    }
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("managed bundle generation snapshots are unsupported on this platform")
}

fn verify_managed_bundle_generation_locked(
    lock: &InstallRootLock,
    spec: &[ComponentSpec],
    expected: &ManagedBundleGeneration,
) -> Result<()> {
    if lock.root() != expected.root {
        anyhow::bail!("managed Kin install root changed during updater preflight");
    }
    #[cfg(unix)]
    {
        let install = lock.install()?;
        let root_binding = PlatformObjectIdentity {
            namespace: install.root.dev,
            file: install.root.ino,
        };
        if root_binding != expected.root_binding {
            anyhow::bail!("managed Kin install root generation changed during updater preflight");
        }
        let mut current = HashMap::new();
        for component in spec {
            current.insert(
                component.name.to_string(),
                install.component_dir(*component).generation_identity(
                    component.name,
                    "locked managed bundle generation component",
                )?,
            );
        }
        install.ensure_bound()?;
        if current != expected.components {
            anyhow::bail!("managed Kin bundle generation changed during updater preflight");
        }
        return Ok(());
    }
    #[cfg(windows)]
    {
        return windows_update::verify_managed_bundle_generation_locked(lock, spec, expected);
    }
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("managed bundle generation verification is unsupported on this platform")
}

#[cfg(not(windows))]
fn component_is_recovery_cli(component: ComponentSpec) -> bool {
    matches!(component.name, "kin" | "kin.exe")
}

#[cfg(not(unix))]
struct PendingUpdateRoot {
    path: PathBuf,
    armed: bool,
}

#[cfg(not(unix))]
impl PendingUpdateRoot {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(not(unix))]
impl Drop for PendingUpdateRoot {
    fn drop(&mut self) {
        if self.armed {
            let _ = durable_remove_dir_all(&self.path);
        }
    }
}

struct StagingDir<'a> {
    path: PathBuf,
    lock: &'a InstallRootLock,
    #[cfg(unix)]
    layout: StagingLayout,
}

impl<'a> StagingDir<'a> {
    fn create(lock: &'a InstallRootLock) -> Result<Self> {
        Self::create_with_hook(lock, |_| Ok(()))
    }

    fn create_with_hook<F>(lock: &'a InstallRootLock, mut after_step: F) -> Result<Self>
    where
        F: FnMut(&str) -> Result<()>,
    {
        let kin_home = lock.root();
        let name = format!(".update-stage-{}", uuid::Uuid::new_v4());
        let path = kin_home.join(&name);
        #[cfg(unix)]
        {
            let install = lock.install()?;
            install.ensure_bound()?;
            let root = install.root.create_child(&name, 0o700)?;
            let pending = PendingUnjournaledRoot::new(
                install,
                name.clone(),
                root,
                UnjournaledRootKind::Staging,
            );
            after_step("staging-root")?;
            install.ensure_bound()?;
            install.root.ensure_child_binding(&name, pending.root())?;
            let bin = pending.root().create_child("bin", 0o700)?;
            after_step("staging-bin")?;
            install.ensure_bound()?;
            install.root.ensure_child_binding(&name, pending.root())?;
            pending.root().ensure_child_binding("bin", &bin)?;
            let lib = pending.root().create_child("lib", 0o700)?;
            after_step("staging-lib")?;
            install.ensure_bound()?;
            install.root.ensure_child_binding(&name, pending.root())?;
            pending.root().ensure_child_binding("bin", &bin)?;
            pending.root().ensure_child_binding("lib", &lib)?;
            let parent = install.root.try_clone()?;
            after_step("staging-validated")?;
            let root = pending.disarm();
            let layout = StagingLayout {
                parent,
                root_name: name,
                root,
                bin,
                lib,
            };
            return Ok(Self { path, lock, layout });
        }
        #[cfg(not(unix))]
        {
            fs::create_dir(&path).with_context(|| {
                format!("failed to create update staging dir {}", path.display())
            })?;
            let mut pending = PendingUpdateRoot::new(path.clone());
            after_step("staging-root")?;
            sync_dir(kin_home)?;
            after_step("staging-validated")?;
            let staging = Self { path, lock };
            pending.disarm();
            Ok(staging)
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(unix)]
    fn layout(&self) -> &StagingLayout {
        &self.layout
    }
}

impl Drop for StagingDir<'_> {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let cleanup = self.lock.install().and_then(|install| {
                cleanup_staging_tree_at(install, &self.layout.root_name, &self.layout.root)
            });
            let _ = cleanup;
            return;
        }
        #[cfg(not(unix))]
        {
            let _ = fs::remove_dir_all(&self.path);
            if let Some(parent) = self.path.parent() {
                let _ = sync_dir(parent);
            }
        }
    }
}

fn stage_archive_locked(
    lock: &InstallRootLock,
    staging: &StagingDir<'_>,
    bytes: &[u8],
    archive_name: &str,
    spec: &[ComponentSpec],
) -> Result<()> {
    if !std::ptr::eq(lock, staging.lock) {
        anyhow::bail!("staging authority does not match the held install lock");
    }
    #[cfg(unix)]
    {
        let install = lock.install()?;
        let layout = staging.layout();
        install.ensure_bound()?;
        layout.ensure_bound()?;
        let mut seen = HashSet::new();
        let mut writer = |component, contents: &[u8], seen: &mut HashSet<&'static str>| {
            write_staged_component_locked(install, layout, component, contents, seen)
        };
        let mut bundle_sink = |member: &BundleMember, contents: &[u8]| -> Result<()> {
            let bundle_root = open_or_create_bundle_dir(&layout.lib, NOTIFIER_BUNDLE_DIR)?;
            write_bundle_member(&bundle_root, member, contents, &mut || {
                install.ensure_bound()?;
                layout.ensure_bound()
            })
        };
        let mut bundle = NotifierBundleCollector::new(&mut bundle_sink);
        stage_archive_payload(
            bytes,
            archive_name,
            spec,
            &mut seen,
            &mut writer,
            &mut bundle,
        )?;
        if spec_carries_notifier_bundle(spec) {
            bundle.finish()?;
        } else if !bundle.is_empty() {
            anyhow::bail!("release archive carries a notification bundle this platform cannot use");
        }
        validate_staged_bundle_locked(install, layout, spec)
    }

    #[cfg(not(unix))]
    {
        let _ = lock;
        stage_archive(bytes, archive_name, staging.path(), spec)
    }
}

fn stage_archive(
    bytes: &[u8],
    archive_name: &str,
    stage_root: &Path,
    spec: &[ComponentSpec],
) -> Result<()> {
    match fs::symlink_metadata(stage_root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            anyhow::bail!(
                "staging root is not a regular directory: {}",
                stage_root.display()
            );
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                let parent_path = stage_root.parent().context("staging root has no parent")?;
                let name = stage_root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .context("staging root name is not UTF-8")?;
                let parent = AnchoredDir::open_ambient(parent_path)?;
                parent.create_child(name, 0o700)?;
            }
            #[cfg(not(unix))]
            {
                fs::create_dir(stage_root).with_context(|| {
                    format!("failed to create staging root {}", stage_root.display())
                })?;
                if let Some(parent) = stage_root.parent() {
                    sync_dir(parent)?;
                }
            }
        }
        Err(err) => return Err(err).context("failed to inspect staging root"),
    }
    #[cfg(unix)]
    let stage_anchor = {
        let parent =
            AnchoredDir::open_ambient(stage_root.parent().context("staging root has no parent")?)?;
        parent.open_child(
            stage_root
                .file_name()
                .and_then(|name| name.to_str())
                .context("staging root name is not UTF-8")?,
        )?
    };
    for name in ["bin", "lib"] {
        #[cfg(unix)]
        {
            match stage_anchor.stat_entry(name)? {
                Some(stat)
                    if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                        == rustix::fs::FileType::Directory => {}
                Some(_) => anyhow::bail!(
                    "staging path is not a real directory: {}/{}",
                    stage_root.display(),
                    name
                ),
                None => {
                    stage_anchor.create_child(name, 0o700)?;
                }
            }
            continue;
        }
        #[cfg(not(unix))]
        {
            let dir = stage_root.join(name);
            match fs::symlink_metadata(&dir) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                    anyhow::bail!("staging path is not a real directory: {}", dir.display());
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&dir).with_context(|| {
                        format!("failed to create staging directory {}", dir.display())
                    })?;
                    sync_dir(stage_root)?;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to inspect staging directory {}", dir.display())
                    });
                }
            }
        }
    }

    let mut seen = HashSet::new();
    let mut writer = |component, contents: &[u8], seen: &mut HashSet<&'static str>| {
        write_staged_component(stage_root, component, contents, seen)
    };
    let mut bundle_sink = |member: &BundleMember, contents: &[u8]| -> Result<()> {
        #[cfg(unix)]
        {
            let lib = stage_anchor.open_child("lib")?;
            let bundle_root = open_or_create_bundle_dir(&lib, NOTIFIER_BUNDLE_DIR)?;
            return write_bundle_member(&bundle_root, member, contents, &mut || Ok(()));
        }
        #[cfg(not(unix))]
        {
            let _ = (member, contents);
            anyhow::bail!("this platform's release archive carries no notification bundle")
        }
    };
    let mut bundle = NotifierBundleCollector::new(&mut bundle_sink);
    stage_archive_payload(
        bytes,
        archive_name,
        spec,
        &mut seen,
        &mut writer,
        &mut bundle,
    )?;
    if spec_carries_notifier_bundle(spec) {
        bundle.finish()?;
    } else if !bundle.is_empty() {
        anyhow::bail!("release archive carries a notification bundle this platform cannot use");
    }
    validate_staged_bundle(stage_root, spec)
}

fn stage_archive_payload<W>(
    bytes: &[u8],
    archive_name: &str,
    spec: &[ComponentSpec],
    seen: &mut HashSet<&'static str>,
    writer: &mut W,
    bundle: &mut NotifierBundleCollector<'_>,
) -> Result<()>
where
    W: FnMut(ComponentSpec, &[u8], &mut HashSet<&'static str>) -> Result<()>,
{
    stage_archive_payload_with_limits(
        bytes,
        archive_name,
        spec,
        None,
        RELEASE_ARCHIVE_LIMITS,
        seen,
        writer,
        bundle,
    )
}

#[allow(clippy::too_many_arguments)]
fn stage_archive_payload_with_limits<W>(
    bytes: &[u8],
    archive_name: &str,
    spec: &[ComponentSpec],
    expected: Option<&VerifiedStagedIdentities>,
    limits: ArchiveSizeLimits,
    seen: &mut HashSet<&'static str>,
    writer: &mut W,
    bundle: &mut NotifierBundleCollector<'_>,
) -> Result<()>
where
    W: FnMut(ComponentSpec, &[u8], &mut HashSet<&'static str>) -> Result<()>,
{
    if bytes.len() > limits.compressed_bytes {
        anyhow::bail!(
            "release archive exceeds the compressed-size limit of {} bytes",
            limits.compressed_bytes
        );
    }
    let expected_expanded_bytes = expected
        .map(|inventory| validate_archive_inventory_limits(inventory, limits))
        .transpose()?;
    let mut expanded_bytes = 0_u64;
    let mut entry_count = 0_usize;
    if archive_name.ends_with(".tar.gz") || archive_name.ends_with(".tgz") {
        stage_tar_gz(
            bytes,
            spec,
            expected,
            expected_expanded_bytes,
            limits,
            &mut expanded_bytes,
            &mut entry_count,
            seen,
            writer,
            bundle,
        )
    } else if archive_name.ends_with(".zip") {
        stage_zip(
            bytes,
            spec,
            expected,
            expected_expanded_bytes,
            limits,
            &mut expanded_bytes,
            &mut entry_count,
            seen,
            writer,
        )
    } else {
        anyhow::bail!("unknown archive format: {archive_name}")
    }
}

fn validate_archive_inventory_limits(
    inventory: &VerifiedStagedIdentities,
    limits: ArchiveSizeLimits,
) -> Result<u64> {
    let mut total = 0_u64;
    for (name, identity) in inventory {
        if identity.size_bytes > limits.entry_bytes {
            anyhow::bail!(
                "release component '{name}' exceeds the per-entry expanded-size limit of {} bytes",
                limits.entry_bytes
            );
        }
        total = total
            .checked_add(identity.size_bytes)
            .context("release component inventory size overflow")?;
        if total > limits.expanded_bytes {
            anyhow::bail!(
                "release component inventory exceeds the aggregate expanded-size limit of {} bytes",
                limits.expanded_bytes
            );
        }
    }
    Ok(total)
}

fn account_archive_entry(
    component: ComponentSpec,
    declared_size: u64,
    expected: Option<&VerifiedStagedIdentities>,
    expected_expanded_bytes: Option<u64>,
    limits: ArchiveSizeLimits,
    expanded_bytes: &mut u64,
) -> Result<()> {
    if declared_size > limits.entry_bytes {
        anyhow::bail!(
            "release component '{}' exceeds the per-entry expanded-size limit of {} bytes",
            component.name,
            limits.entry_bytes
        );
    }
    if let Some(expected) = expected {
        let identity = expected.get(component.name).with_context(|| {
            format!(
                "artifact provenance is missing archive component '{}'",
                component.name
            )
        })?;
        if declared_size != identity.size_bytes {
            anyhow::bail!(
                "release archive declared size for component '{}' does not match artifact provenance",
                component.name
            );
        }
    }
    *expanded_bytes = expanded_bytes
        .checked_add(declared_size)
        .context("release archive expanded-size overflow")?;
    let aggregate_limit = expected_expanded_bytes.unwrap_or(limits.expanded_bytes);
    if *expanded_bytes > aggregate_limit {
        anyhow::bail!(
            "release archive exceeds the aggregate expanded-size limit of {aggregate_limit} bytes"
        );
    }
    Ok(())
}

fn account_archive_entry_count(entry_count: &mut usize) -> Result<()> {
    *entry_count = entry_count
        .checked_add(1)
        .context("release archive entry-count overflow")?;
    if *entry_count > MAX_ARCHIVE_ENTRIES {
        anyhow::bail!("release archive exceeds the maximum entry count of {MAX_ARCHIVE_ENTRIES}");
    }
    Ok(())
}

fn read_bounded_archive_entry<R: Read>(
    reader: &mut R,
    declared_size: u64,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>> {
    if declared_size > max_bytes {
        anyhow::bail!("{label} exceeds the expanded-size limit of {max_bytes} bytes");
    }
    let read_limit = declared_size
        .checked_add(1)
        .context("archive entry read limit overflow")?;
    let mut contents = Vec::new();
    reader
        .take(read_limit)
        .read_to_end(&mut contents)
        .with_context(|| format!("failed to read {label} from archive"))?;
    if contents.len() as u64 != declared_size {
        anyhow::bail!("{label} expanded size does not match its declared size");
    }
    Ok(contents)
}

/// Parse and authenticate the complete release payload in memory. This shares
/// archive path and entry parsing with staging, but its writer only hashes
/// bytes. Pinned automation therefore rejects unsafe paths, unexpected or
/// duplicate files, missing required components, empty files, and every
/// size/hash mismatch before local install authority is acquired.
fn validate_archive_payload_provenance(
    archive_bytes: &[u8],
    archive_name: &str,
    spec: &[ComponentSpec],
    provenance_identities: &VerifiedStagedIdentities,
) -> Result<VerifiedStagedIdentities> {
    validate_archive_payload_provenance_with_limits(
        archive_bytes,
        archive_name,
        spec,
        provenance_identities,
        RELEASE_ARCHIVE_LIMITS,
    )
}

/// Authenticate the exact CLI and daemon bytes carried by the release
/// archive against the hash-bound static identities in provenance. This is a
/// pure parser: candidate programs are never loaded or executed.
fn validate_archive_payload_provenance_and_static_identity(
    archive_bytes: &[u8],
    archive_name: &str,
    spec: &[ComponentSpec],
    provenance_identities: &VerifiedStagedIdentities,
    provenance: &ArtifactProvenance,
) -> Result<VerifiedStagedIdentities> {
    let verified = validate_archive_payload_provenance(
        archive_bytes,
        archive_name,
        spec,
        provenance_identities,
    )?;
    let (cli_name, daemon_name) = static_identity_component_names(spec)?;
    let release_version = parse_release_version(&provenance.release_tag)?;
    let mut seen = HashSet::new();
    let mut graph_version = None;
    let mut verifier =
        |component: ComponentSpec, contents: &[u8], seen: &mut HashSet<&'static str>| {
            if !seen.insert(component.name) {
                anyhow::bail!(
                    "release archive contains duplicate component '{}'",
                    component.name
                );
            }
            if component.name != cli_name && component.name != daemon_name {
                return Ok(());
            }
            let record = provenance
                .archive_contents
                .iter()
                .find(|record| record.name == component.name)
                .with_context(|| {
                    format!("artifact provenance has no '{}' component", component.name)
                })?;
            let expected = record.build_identity.as_ref().with_context(|| {
                format!(
                    "artifact provenance has no static identity for '{}'",
                    component.name
                )
            })?;
            let actual = parse_static_build_identity(contents)?;
            if &actual != expected {
                anyhow::bail!(
                    "archive component '{}' static identity does not match provenance",
                    component.name
                );
            }
            validate_static_build_identity_claim(
                &actual,
                &release_version,
                &provenance.kin,
                component.name,
            )?;
            if let Some(expected_graph) = graph_version {
                if expected_graph != actual.graph_snapshot_version {
                    anyhow::bail!("archive CLI and daemon graph snapshot identities disagree");
                }
            } else {
                graph_version = Some(actual.graph_snapshot_version);
            }
            Ok(())
        };
    // The notification bundle is authenticated by the archive digest rather than
    // by the per-file inventory, so nothing here reads its bytes. Its shape is
    // still judged, because a macOS archive whose bundle cannot launch or cannot
    // be attributed should fail before an install, not after one.
    let mut inspect_only = |_: &BundleMember, _: &[u8]| Ok(());
    let mut bundle = NotifierBundleCollector::new(&mut inspect_only);
    stage_archive_payload_with_limits(
        archive_bytes,
        archive_name,
        spec,
        Some(provenance_identities),
        RELEASE_ARCHIVE_LIMITS,
        &mut seen,
        &mut verifier,
        &mut bundle,
    )?;
    if spec_carries_notifier_bundle(spec) {
        bundle.finish()?;
    }
    if !seen.contains(cli_name) || !seen.contains(daemon_name) {
        anyhow::bail!("release archive lacks the CLI or daemon static build identity");
    }
    Ok(verified)
}

fn validate_archive_payload_provenance_with_limits(
    archive_bytes: &[u8],
    archive_name: &str,
    spec: &[ComponentSpec],
    provenance_identities: &VerifiedStagedIdentities,
    limits: ArchiveSizeLimits,
) -> Result<VerifiedStagedIdentities> {
    let mut seen = HashSet::new();
    let mut verified = VerifiedStagedIdentities::new();
    let mut verifier =
        |component: ComponentSpec, contents: &[u8], seen: &mut HashSet<&'static str>| {
            if !seen.insert(component.name) {
                anyhow::bail!(
                    "release archive contains duplicate component '{}'",
                    component.name
                );
            }
            if contents.is_empty() {
                anyhow::bail!("release component '{}' is empty", component.name);
            }
            let expected = provenance_identities.get(component.name).with_context(|| {
                format!(
                    "artifact provenance is missing archive component '{}'",
                    component.name
                )
            })?;
            let actual = FileIdentity {
                sha256: hex::encode(Sha256::digest(contents)),
                size_bytes: contents.len() as u64,
            };
            if &actual != expected {
                anyhow::bail!(
                    "release archive component '{}' does not match artifact provenance",
                    component.name
                );
            }
            verified.insert(component.name.to_string(), actual);
            Ok(())
        };
    let mut inspect_only = |_: &BundleMember, _: &[u8]| Ok(());
    let mut bundle = NotifierBundleCollector::new(&mut inspect_only);
    stage_archive_payload_with_limits(
        archive_bytes,
        archive_name,
        spec,
        Some(provenance_identities),
        limits,
        &mut seen,
        &mut verifier,
        &mut bundle,
    )?;
    if spec_carries_notifier_bundle(spec) {
        bundle.finish()?;
    }

    for component in spec.iter().filter(|component| component.required) {
        if !verified.contains_key(component.name) {
            anyhow::bail!(
                "release archive is incomplete: required component '{}' is missing",
                component.name
            );
        }
    }
    if verified.len() != provenance_identities.len() {
        anyhow::bail!(
            "artifact provenance inventory does not exactly match the in-memory release archive"
        );
    }
    Ok(verified)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SimpleTarEntryKind {
    File,
    Directory,
}

#[derive(Debug)]
struct SimpleTarEntry {
    path: PathBuf,
    kind: SimpleTarEntryKind,
    declared_size: u64,
    /// Permission bits as recorded by the archive. Components are written with
    /// the mode their location dictates and ignore this; the notification
    /// bundle carries its own executable bit and needs it preserved, because a
    /// bundle whose executable lost `+x` cannot be launched to post anything.
    mode: u32,
    contents: Vec<u8>,
}

fn parse_tar_octal(field: &[u8], label: &str) -> Result<u64> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        anyhow::bail!("tar {label} uses unsupported base-256 encoding");
    }
    let start = field
        .iter()
        .position(|byte| !matches!(*byte, 0 | b' '))
        .unwrap_or(field.len());
    let end = field
        .iter()
        .rposition(|byte| !matches!(*byte, 0 | b' '))
        .map(|index| index + 1)
        .unwrap_or(start);
    if start == end {
        return Ok(0);
    }
    let digits = &field[start..end];
    if !digits.iter().all(|byte| matches!(*byte, b'0'..=b'7')) {
        anyhow::bail!("tar {label} is not strict octal");
    }
    digits.iter().try_fold(0_u64, |value, digit| {
        value
            .checked_mul(8)
            .and_then(|value| value.checked_add(u64::from(*digit - b'0')))
            .context("tar numeric field overflow")
    })
}

fn parse_tar_text(field: &[u8], label: &str) -> Result<String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        anyhow::bail!("tar {label} contains bytes after its NUL terminator");
    }
    let value =
        std::str::from_utf8(&field[..end]).with_context(|| format!("tar {label} is not UTF-8"))?;
    if value.is_empty() {
        anyhow::bail!("tar {label} is empty");
    }
    Ok(value.to_string())
}

fn validate_tar_header_checksum(header: &[u8; 512]) -> Result<()> {
    let recorded = parse_tar_octal(&header[148..156], "header checksum")?;
    let actual = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum::<u64>();
    if recorded != actual {
        anyhow::bail!("tar header checksum mismatch: recorded {recorded}, computed {actual}");
    }
    Ok(())
}

fn read_counted_tar_exact<R: Read>(
    reader: &mut R,
    bytes: &mut [u8],
    raw_bytes: &mut u64,
    raw_limit: u64,
    label: &str,
) -> Result<()> {
    let next = raw_bytes
        .checked_add(bytes.len() as u64)
        .context("tar decompressed-byte counter overflow")?;
    if next > raw_limit {
        anyhow::bail!("tar decompressed stream exceeds the global limit of {raw_limit} bytes");
    }
    reader
        .read_exact(bytes)
        .with_context(|| format!("truncated tar {label}"))?;
    *raw_bytes = next;
    Ok(())
}

fn read_counted_tar_block<R: Read>(
    reader: &mut R,
    raw_bytes: &mut u64,
    raw_limit: u64,
) -> Result<Option<[u8; 512]>> {
    let mut block = [0_u8; 512];
    let mut filled = 0_usize;
    while filled < block.len() {
        let remaining = raw_limit.saturating_sub(*raw_bytes);
        let requested = usize::try_from(
            remaining
                .saturating_add(1)
                .min((block.len() - filled) as u64),
        )
        .unwrap_or(block.len() - filled);
        let read = reader
            .read(&mut block[filled..filled + requested])
            .context("failed to decompress tar header")?;
        if read == 0 {
            if filled == 0 {
                return Ok(None);
            }
            anyhow::bail!("truncated tar header block");
        }
        let next = raw_bytes
            .checked_add(read as u64)
            .context("tar decompressed-byte counter overflow")?;
        if next > raw_limit {
            anyhow::bail!("tar decompressed stream exceeds the global limit of {raw_limit} bytes");
        }
        *raw_bytes = next;
        filled += read;
    }
    Ok(Some(block))
}

fn walk_simple_tar_gz<F>(bytes: &[u8], limits: ArchiveSizeLimits, mut visitor: F) -> Result<()>
where
    F: FnMut(SimpleTarEntry) -> Result<()>,
{
    if bytes.len() > limits.compressed_bytes {
        anyhow::bail!(
            "release archive exceeds the compressed-size limit of {} bytes",
            limits.compressed_bytes
        );
    }
    let raw_limit = limits
        .expanded_bytes
        .checked_add(MAX_TAR_FORMAT_OVERHEAD_BYTES)
        .context("tar global decompressed-size limit overflow")?;
    let mut decoder = flate2::read::MultiGzDecoder::new(bytes);
    let mut raw_bytes = 0_u64;
    let mut payload_bytes = 0_u64;
    let mut entry_count = 0_usize;
    let mut zero_blocks = 0_u8;

    while let Some(header) = read_counted_tar_block(&mut decoder, &mut raw_bytes, raw_limit)? {
        if header.iter().all(|byte| *byte == 0) {
            zero_blocks = zero_blocks.saturating_add(1);
            if zero_blocks < 2 {
                continue;
            }
            let mut trailing = [0_u8; 8 * 1024];
            loop {
                let remaining = raw_limit.saturating_sub(raw_bytes);
                let requested =
                    usize::try_from(remaining.saturating_add(1).min(trailing.len() as u64))
                        .unwrap_or(trailing.len());
                let read = decoder
                    .read(&mut trailing[..requested])
                    .context("failed to read tar trailer")?;
                if read == 0 {
                    return Ok(());
                }
                let next = raw_bytes
                    .checked_add(read as u64)
                    .context("tar decompressed-byte counter overflow")?;
                if next > raw_limit {
                    anyhow::bail!(
                        "tar decompressed stream exceeds the global limit of {raw_limit} bytes"
                    );
                }
                raw_bytes = next;
                if trailing[..read].iter().any(|byte| *byte != 0) {
                    anyhow::bail!("tar contains nonzero data after its end markers");
                }
            }
        }
        if zero_blocks != 0 {
            anyhow::bail!("tar contains a single zero block before another entry");
        }
        validate_tar_header_checksum(&header)?;
        account_archive_entry_count(&mut entry_count)?;

        let magic = &header[257..263];
        let version = &header[263..265];
        let supported_header = (magic == b"ustar\0" && version == b"00")
            || (magic == b"ustar " && version == b" \0")
            || (magic.iter().all(|byte| *byte == 0) && version.iter().all(|byte| *byte == 0));
        if !supported_header {
            anyhow::bail!("tar uses an unsupported header format");
        }
        let kind = match header[156] {
            0 | b'0' => SimpleTarEntryKind::File,
            b'5' => SimpleTarEntryKind::Directory,
            kind => anyhow::bail!(
                "tar contains unsupported extension, sparse, or special record type 0x{kind:02x}"
            ),
        };
        if header[345..500].iter().any(|byte| *byte != 0) {
            anyhow::bail!("tar uses an unsupported prefix field");
        }
        if header[157..257].iter().any(|byte| *byte != 0) {
            anyhow::bail!("tar ordinary entry carries unsupported link metadata");
        }

        let path = PathBuf::from(parse_tar_text(&header[..100], "entry path")?);
        if path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        }) {
            anyhow::bail!("release archive contains unsafe path '{}'", path.display());
        }
        let declared_size = parse_tar_octal(&header[124..136], "entry size")?;
        if kind == SimpleTarEntryKind::Directory && declared_size != 0 {
            anyhow::bail!(
                "release archive directory '{}' has nonzero expanded size",
                path.display()
            );
        }
        if declared_size > limits.entry_bytes {
            anyhow::bail!(
                "release archive entry '{}' exceeds the per-entry expanded-size limit of {} bytes",
                path.display(),
                limits.entry_bytes
            );
        }
        payload_bytes = payload_bytes
            .checked_add(declared_size)
            .context("release archive expanded-size overflow")?;
        if payload_bytes > limits.expanded_bytes {
            anyhow::bail!(
                "release archive exceeds the aggregate expanded-size limit of {} bytes",
                limits.expanded_bytes
            );
        }
        let declared_len = usize::try_from(declared_size)
            .context("tar entry size does not fit in memory on this platform")?;
        let mut contents = vec![0_u8; declared_len];
        read_counted_tar_exact(
            &mut decoder,
            &mut contents,
            &mut raw_bytes,
            raw_limit,
            "entry payload",
        )?;
        let padding = (512 - declared_len % 512) % 512;
        let mut padding_bytes = [0_u8; 511];
        read_counted_tar_exact(
            &mut decoder,
            &mut padding_bytes[..padding],
            &mut raw_bytes,
            raw_limit,
            "entry padding",
        )?;
        if padding_bytes[..padding].iter().any(|byte| *byte != 0) {
            anyhow::bail!("tar entry '{}' has nonzero padding", path.display());
        }
        let mode = u32::try_from(parse_tar_octal(&header[100..108], "entry mode")?)
            .context("tar entry mode does not fit in a permission word")?
            & 0o7777;
        visitor(SimpleTarEntry {
            path,
            kind,
            declared_size,
            mode,
            contents,
        })?;
    }
    anyhow::bail!("tar ended without two zero end-of-archive blocks")
}

#[allow(clippy::too_many_arguments)]
fn stage_tar_gz<W>(
    bytes: &[u8],
    spec: &[ComponentSpec],
    expected: Option<&VerifiedStagedIdentities>,
    expected_expanded_bytes: Option<u64>,
    limits: ArchiveSizeLimits,
    expanded_bytes: &mut u64,
    entry_count: &mut usize,
    seen: &mut HashSet<&'static str>,
    writer: &mut W,
    bundle: &mut NotifierBundleCollector<'_>,
) -> Result<()>
where
    W: FnMut(ComponentSpec, &[u8], &mut HashSet<&'static str>) -> Result<()>,
{
    let carries_bundle = spec_carries_notifier_bundle(spec);
    walk_simple_tar_gz(bytes, limits, |entry| {
        *entry_count = entry_count
            .checked_add(1)
            .context("release archive entry-count overflow")?;
        // The notification bundle is a whole-tree participant rather than a
        // swappable component, so it is collected here under its own budget and
        // installed by the transaction as one directory. On a platform whose
        // archive has no bundle, a member of one is simply an unexpected entry.
        if is_notifier_bundle_entry(&entry.path) {
            if !carries_bundle {
                anyhow::bail!(
                    "release archive contains unexpected file '{}'",
                    entry.path.display()
                );
            }
            return bundle.accept(&entry);
        }
        if entry.kind == SimpleTarEntryKind::Directory {
            return Ok(());
        }
        let path = entry.path;
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            anyhow::bail!("release archive contains a non-UTF-8 file name");
        };
        let Some(component) = spec.iter().copied().find(|item| item.name == name) else {
            anyhow::bail!(
                "release archive contains unexpected file '{}'",
                path.display()
            );
        };
        account_archive_entry(
            component,
            entry.declared_size,
            expected,
            expected_expanded_bytes,
            limits,
            expanded_bytes,
        )?;
        writer(component, &entry.contents, seen)
    })
}

fn stage_zip<W>(
    bytes: &[u8],
    spec: &[ComponentSpec],
    expected: Option<&VerifiedStagedIdentities>,
    expected_expanded_bytes: Option<u64>,
    limits: ArchiveSizeLimits,
    expanded_bytes: &mut u64,
    entry_count: &mut usize,
    seen: &mut HashSet<&'static str>,
    writer: &mut W,
) -> Result<()>
where
    W: FnMut(ComponentSpec, &[u8], &mut HashSet<&'static str>) -> Result<()>,
{
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("failed to open zip archive")?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        anyhow::bail!("release archive exceeds the maximum entry count of {MAX_ARCHIVE_ENTRIES}");
    }
    for index in 0..archive.len() {
        account_archive_entry_count(entry_count)?;
        let mut entry = archive.by_index(index).context("corrupt zip entry")?;
        let Some(enclosed_path) = entry.enclosed_name() else {
            anyhow::bail!("release zip contains an unsafe or invalid file path");
        };
        if entry.is_dir() {
            if entry.size() != 0 {
                anyhow::bail!(
                    "release archive directory '{}' has nonzero expanded size",
                    enclosed_path.display()
                );
            }
            continue;
        }
        if !entry.is_file() {
            anyhow::bail!(
                "release archive contains non-regular entry '{}'",
                enclosed_path.display()
            );
        }
        // Only macOS carries the notification bundle and only its tar archives
        // do. Rejecting the shape here also stops a zip from smuggling a
        // component past the flat-name lookup below by nesting it in a
        // bundle-shaped directory.
        if is_notifier_bundle_entry(&enclosed_path) {
            anyhow::bail!(
                "release zip contains a notification bundle entry '{}'",
                enclosed_path.display()
            );
        }
        let Some(file_name) = enclosed_path.file_name().map(|name| name.to_owned()) else {
            anyhow::bail!("release zip contains an invalid file path");
        };
        let Some(name) = file_name.to_str() else {
            anyhow::bail!("release zip contains a non-UTF-8 file name");
        };
        let Some(component) = spec.iter().copied().find(|item| item.name == name) else {
            anyhow::bail!("release archive contains unexpected file '{name}'");
        };
        let declared_size = entry.size();
        account_archive_entry(
            component,
            declared_size,
            expected,
            expected_expanded_bytes,
            limits,
            expanded_bytes,
        )?;
        let contents = read_bounded_archive_entry(
            &mut entry,
            declared_size,
            limits.entry_bytes,
            &format!("release component '{}'", component.name),
        )?;
        writer(component, &contents, seen)?;
    }
    Ok(())
}

fn write_staged_component(
    stage_root: &Path,
    component: ComponentSpec,
    contents: &[u8],
    seen: &mut HashSet<&'static str>,
) -> Result<()> {
    if !seen.insert(component.name) {
        anyhow::bail!(
            "release archive contains duplicate component '{}'",
            component.name
        );
    }
    if contents.is_empty() {
        anyhow::bail!("release component '{}' is empty", component.name);
    }

    #[cfg(unix)]
    {
        let staging = StagingLayout::open(stage_root)?;
        staging.ensure_bound()?;
        let mode = if component.location == ComponentLocation::Bin {
            0o755
        } else {
            0o644
        };
        staging
            .component_dir(component)
            .atomic_write_checked(component.name, contents, mode, || staging.ensure_bound())
            .with_context(|| format!("failed to stage release component {}", component.name))?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let path = component_path(stage_root, component);
        let mut file = File::create(&path)
            .with_context(|| format!("failed to stage release component {}", path.display()))?;
        file.write_all(contents)
            .with_context(|| format!("failed to write staged component {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync staged component {}", path.display()))?;
        drop(file);
        sync_dir(path.parent().expect("component paths always have a parent"))?;
        Ok(())
    }
}

#[cfg(unix)]
fn write_staged_component_locked(
    install: &InstallLayout,
    staging: &StagingLayout,
    component: ComponentSpec,
    contents: &[u8],
    seen: &mut HashSet<&'static str>,
) -> Result<()> {
    if !seen.insert(component.name) {
        anyhow::bail!(
            "release archive contains duplicate component '{}'",
            component.name
        );
    }
    if contents.is_empty() {
        anyhow::bail!("release component '{}' is empty", component.name);
    }
    let mode = if component.location == ComponentLocation::Bin {
        0o755
    } else {
        0o644
    };
    install.ensure_bound()?;
    staging.ensure_bound()?;
    staging
        .component_dir(component)
        .atomic_write_checked(component.name, contents, mode, || {
            install.ensure_bound()?;
            staging.ensure_bound()
        })
        .with_context(|| format!("failed to stage release component {}", component.name))
}

#[cfg(unix)]
fn validate_staged_bundle_locked(
    install: &InstallLayout,
    staging: &StagingLayout,
    spec: &[ComponentSpec],
) -> Result<()> {
    install.ensure_bound()?;
    staging.ensure_bound()?;
    for component in spec {
        let identity = staging
            .component_dir(*component)
            .identity(component.name, "staged release component")?;
        match identity {
            Some(identity) if identity.size_bytes > 0 => {}
            Some(_) => anyhow::bail!(
                "release archive is invalid: component '{}' is empty",
                component.name
            ),
            None if component.required => anyhow::bail!(
                "release archive is incomplete: required component '{}' is missing",
                component.name
            ),
            None => {}
        }
    }
    if spec_carries_notifier_bundle(spec)
        && staged_bundle_identity_at(&staging.lib, NOTIFIER_BUNDLE_DIR)?.is_none()
    {
        anyhow::bail!("release archive is incomplete: the notification bundle is missing");
    }
    Ok(())
}

/// Prove the staged tree holds a usable notification bundle.
#[cfg(unix)]
fn validate_staged_notifier_bundle(stage_root: &Path) -> Result<()> {
    let lib = AnchoredDir::open_ambient(&stage_root.join("lib"))?;
    staged_bundle_identity_at(&lib, NOTIFIER_BUNDLE_DIR)?
        .context("release archive is incomplete: the notification bundle is missing")?;
    Ok(())
}

#[cfg(not(unix))]
fn validate_staged_notifier_bundle(_stage_root: &Path) -> Result<()> {
    anyhow::bail!("this platform cannot stage a notification bundle")
}

fn validate_staged_bundle(stage_root: &Path, spec: &[ComponentSpec]) -> Result<()> {
    for component in spec {
        let path = component_path(stage_root, *component);
        if !path.exists() {
            if component.required {
                anyhow::bail!(
                    "release archive is incomplete: required component '{}' is missing",
                    component.name
                );
            }
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect staged component {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            anyhow::bail!(
                "release archive is invalid: component '{}' is not a non-empty file",
                component.name
            );
        }
    }
    if spec_carries_notifier_bundle(spec) {
        validate_staged_notifier_bundle(stage_root)?;
    }
    Ok(())
}

#[derive(Debug)]
struct InstallOutcome {
    retained_backup: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransactionPhase {
    Prepared,
    BackingUp,
    Installing,
    Committed,
    RolledBack,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct JournalComponent {
    name: String,
    location: ComponentLocation,
    required: bool,
    had_original: bool,
    install_new: bool,
    original_identity: Option<FileIdentity>,
    staged_identity: Option<FileIdentity>,
}

/// The notification bundle's place in a transaction.
///
/// Both fields are absent on a platform whose archive carries no bundle, and
/// `original_identity` is absent on the first install that brings one. A
/// default-empty record is what a journal written before the bundle joined the
/// transaction deserializes to, which is exactly what it means: that
/// transaction did not touch a bundle.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct JournalBundle {
    original_identity: Option<BundleIdentity>,
    staged_identity: Option<BundleIdentity>,
}

impl JournalBundle {
    fn is_empty(&self) -> bool {
        self.original_identity.is_none() && self.staged_identity.is_none()
    }
}

/// Journal schema written by this build.
///
/// Schema 2 is still accepted on read: a crash during an update leaves the
/// journal written by the older CLI that started it, and the newer CLI that
/// becomes live afterwards has to be able to finish or reverse that work. A
/// schema-2 journal never touched a notification bundle, so recovering one is
/// exactly the component-only behavior it recorded.
const TRANSACTION_JOURNAL_SCHEMA: u32 = 3;
const TRANSACTION_JOURNAL_SCHEMA_WITHOUT_BUNDLE: u32 = 2;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct TransactionJournal {
    schema_version: u32,
    target_version: String,
    phase: TransactionPhase,
    components: Vec<JournalComponent>,
    #[serde(default)]
    notifier_bundle: JournalBundle,
    restart_pending: RestartPending,
    mcp_repair_pending: McpRepairPending,
}

#[cfg(test)]
fn install_staged_bundle(
    kin_home: &Path,
    stage_root: &Path,
    spec: &[ComponentSpec],
    target_version: &str,
    restart_pending: &RestartPending,
) -> Result<InstallOutcome> {
    let lock = InstallRootLock::acquire_existing(kin_home)?;
    let verified_staged_identities = staged_identities_for_test(stage_root, spec)?;
    install_staged_bundle_locked_with_hook(
        &lock,
        stage_root,
        spec,
        &verified_staged_identities,
        target_version,
        restart_pending,
        |_, _| Ok(()),
    )
}

fn install_staged_bundle_locked(
    lock: &InstallRootLock,
    staging: &StagingDir<'_>,
    spec: &[ComponentSpec],
    verified_staged_identities: &VerifiedStagedIdentities,
    target_version: &str,
    restart_pending: &RestartPending,
) -> Result<InstallOutcome> {
    if !std::ptr::eq(lock, staging.lock) {
        anyhow::bail!("staging authority does not match the held install lock");
    }
    refuse_new_update_while_restart_marker_exists(lock)?;
    #[cfg(unix)]
    {
        return install_staged_bundle_unix(
            lock,
            staging.layout(),
            spec,
            verified_staged_identities,
            target_version,
            restart_pending,
            |_, _| Ok(()),
        );
    }
    #[cfg(not(unix))]
    {
        install_staged_bundle_locked_with_hook(
            lock,
            staging.path(),
            spec,
            verified_staged_identities,
            target_version,
            restart_pending,
            |_, _| Ok(()),
        )
    }
}

#[cfg(test)]
fn install_staged_bundle_with_hook<F>(
    kin_home: &Path,
    stage_root: &Path,
    spec: &[ComponentSpec],
    target_version: &str,
    restart_pending: &RestartPending,
    before_install: F,
) -> Result<InstallOutcome>
where
    F: FnMut(usize, &Path) -> Result<()>,
{
    let lock = InstallRootLock::acquire_existing(kin_home)?;
    let verified_staged_identities = staged_identities_for_test(stage_root, spec)?;
    install_staged_bundle_locked_with_hook(
        &lock,
        stage_root,
        spec,
        &verified_staged_identities,
        target_version,
        restart_pending,
        before_install,
    )
}

#[cfg(any(test, not(unix)))]
fn install_staged_bundle_locked_with_hook<F>(
    lock: &InstallRootLock,
    stage_root: &Path,
    spec: &[ComponentSpec],
    verified_staged_identities: &VerifiedStagedIdentities,
    target_version: &str,
    restart_pending: &RestartPending,
    before_install: F,
) -> Result<InstallOutcome>
where
    F: FnMut(usize, &Path) -> Result<()>,
{
    refuse_new_update_while_restart_marker_exists(lock)?;
    #[cfg(unix)]
    {
        let staging = StagingLayout::open(stage_root)?;
        return install_staged_bundle_unix(
            lock,
            &staging,
            spec,
            verified_staged_identities,
            target_version,
            restart_pending,
            before_install,
        );
    }

    #[cfg(not(unix))]
    {
        let kin_home = lock.root();
        let mut before_install = before_install;
        validate_staged_bundle(stage_root, spec)?;
        ensure_managed_dirs(kin_home, true)?;

        // Every path is checked before the durable journal is created, and symlink
        // destinations are rejected rather than followed or preserved.
        let mut components = Vec::with_capacity(spec.len());
        for component in spec {
            let dest = component_path(kin_home, *component);
            let had_original = match fs::symlink_metadata(&dest) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        anyhow::bail!(
                            "refusing non-regular or symlink update destination {}",
                            dest.display()
                        );
                    }
                    true
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to inspect destination {}", dest.display())
                    });
                }
            };
            let original_identity = if had_original {
                Some(file_identity(&dest)?)
            } else {
                None
            };
            let staged = component_path(stage_root, *component);
            let actual_staged_identity = match fs::symlink_metadata(&staged) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        anyhow::bail!(
                            "staged component is not a regular file: {}",
                            staged.display()
                        );
                    }
                    Some(file_identity(&staged)?)
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to inspect staged component {}", staged.display())
                    });
                }
            };
            let staged_identity = verified_staged_identities.get(component.name).cloned();
            if actual_staged_identity != staged_identity {
                anyhow::bail!(
                    "staged component '{}' does not match its verified release provenance identity",
                    component.name
                );
            }
            let install_new = staged_identity.is_some();
            if component.required && !install_new {
                anyhow::bail!("required component '{}' was not staged", component.name);
            }
            components.push(JournalComponent {
                name: component.name.to_string(),
                location: component.location,
                required: component.required,
                had_original,
                install_new,
                original_identity,
                staged_identity,
            });
        }
        if verified_staged_identities.len()
            != components
                .iter()
                .filter(|component| component.install_new)
                .count()
        {
            anyhow::bail!(
                "verified staged identity inventory contains files outside the managed platform bundle"
            );
        }

        // Capture and union every durable MCP obligation before creating any
        // transaction directory. A malformed/unsupported marker or an
        // unbound managed client therefore fails without journalless residue.
        let mcp_repair_pending = mcp_repair_pending_record(lock, target_version)?;
        let transaction_root = create_transaction_root(kin_home)?;
        let backup_root = transaction_root.join("old");
        // The schema is what this build writes, not what this platform happens
        // to fill in. The bundle record stays empty because no archive for a
        // platform without `spec_carries_notifier_bundle` carries one, and
        // pinning the literal here is how the constant and the journal drift
        // apart at the next schema bump.
        let mut journal = TransactionJournal {
            schema_version: TRANSACTION_JOURNAL_SCHEMA,
            target_version: target_version.to_string(),
            phase: TransactionPhase::Prepared,
            components,
            notifier_bundle: JournalBundle::default(),
            restart_pending: restart_pending.clone(),
            mcp_repair_pending,
        };
        if let Err(err) = persist_journal(&transaction_root, &journal) {
            let _ = durable_remove_dir_all(&transaction_root);
            return Err(err);
        }

        journal.phase = TransactionPhase::BackingUp;
        if let Err(err) = persist_journal(&transaction_root, &journal) {
            let _ = durable_remove_dir_all(&transaction_root);
            return Err(err);
        }

        for (index, component) in spec.iter().enumerate() {
            let record = journal_component(&journal, component.name)?;
            if !record.had_original {
                continue;
            }
            let dest = component_path(kin_home, *component);
            let backup = component_path(&backup_root, *component);
            if let Err(err) = durable_rename(&dest, &backup) {
                return rollback_after_failure(
                    err,
                    &mut journal,
                    &transaction_root,
                    kin_home,
                    spec,
                );
            }
            maybe_crash_at(&format!("after-backup-{index}"));
        }

        journal.phase = TransactionPhase::Installing;
        if let Err(err) = persist_journal(&transaction_root, &journal) {
            return rollback_after_failure(err, &mut journal, &transaction_root, kin_home, spec);
        }

        let mut install_index = 0;
        for component in spec {
            let record = journal_component(&journal, component.name)?;
            let Some(expected) = record.staged_identity.clone() else {
                continue;
            };
            let staged = component_path(stage_root, *component);
            let dest = component_path(kin_home, *component);
            if let Err(err) = before_install(install_index, &dest) {
                return rollback_after_failure(
                    err,
                    &mut journal,
                    &transaction_root,
                    kin_home,
                    spec,
                );
            }
            if let Err(err) = verify_file_identity(
                &staged,
                &expected,
                &format!(
                    "staged component '{}' immediately before install",
                    component.name
                ),
            ) {
                return rollback_after_failure(
                    err,
                    &mut journal,
                    &transaction_root,
                    kin_home,
                    spec,
                );
            }
            if let Err(err) = durable_rename(&staged, &dest) {
                return rollback_after_failure(
                    err,
                    &mut journal,
                    &transaction_root,
                    kin_home,
                    spec,
                );
            }
            if let Err(err) = verify_file_identity(
                &dest,
                &expected,
                &format!(
                    "installed component '{}' immediately after install",
                    component.name
                ),
            ) {
                return rollback_after_failure(
                    err,
                    &mut journal,
                    &transaction_root,
                    kin_home,
                    spec,
                );
            }
            maybe_crash_at(&format!("after-install-{install_index}"));
            install_index += 1;
        }

        if let Err(err) = validate_installed_bundle(kin_home, &journal, spec) {
            return rollback_after_failure(err, &mut journal, &transaction_root, kin_home, spec);
        }

        if let Err(err) = ensure_no_active_managed_runtimes(kin_home, spec) {
            return rollback_after_failure(
                err.context(
                    "a managed serving executable appeared before the durable commit point; the uncommitted update will be rolled back",
                ),
                &mut journal,
                &transaction_root,
                kin_home,
                spec,
            );
        }

        // This durable transition is the transaction's commit point. Recovery
        // rolls back every earlier phase and finishes cleanup for this phase.
        journal.phase = TransactionPhase::Committed;
        if let Err(err) = persist_journal(&transaction_root, &journal) {
            return rollback_after_failure(err, &mut journal, &transaction_root, kin_home, spec);
        }
        maybe_crash_at("after-commit-journal-before-process-fence");
        mark_restart_record_committed(&mut journal.restart_pending, kin_home, spec).with_context(
            || {
                format!(
                    "update committed on disk, but its runtime identity fence could not be captured; durable recovery remains at {}",
                    transaction_root.display()
                )
            },
        )?;
        persist_journal(&transaction_root, &journal).with_context(|| {
            format!(
                "update committed on disk, but its runtime identity fence could not be persisted; durable recovery remains at {}",
                transaction_root.display()
            )
        })?;
        maybe_crash_at("after-commit");

        persist_restart_record(kin_home, &journal.restart_pending).with_context(|| {
            format!(
            "update committed on disk, but restart-pending state could not be persisted; durable \
             recovery remains at {}",
            transaction_root.display()
        )
        })?;
        maybe_crash_at("after-restart-marker");
        persist_mcp_repair_record(kin_home, &journal.mcp_repair_pending).with_context(|| {
            format!(
                "update committed on disk, but MCP repair state could not be persisted; durable \
             recovery remains at {}",
                transaction_root.display()
            )
        })?;
        maybe_crash_at("after-mcp-marker");

        let retained_backup = match cleanup_transaction_root(&transaction_root) {
            Ok(()) => None,
            Err(_) => Some(transaction_root),
        };
        maybe_crash_at("after-cleanup");
        Ok(InstallOutcome { retained_backup })
    }
}

#[cfg(unix)]
fn persist_journal_at(
    install: &InstallLayout,
    transaction: &TransactionLayout,
    journal: &TransactionJournal,
) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(journal).context("failed to serialize update journal")?;
    let crash_point = match journal.phase {
        TransactionPhase::Prepared => Some("before-journal-rename-prepared"),
        TransactionPhase::Installing => Some("before-journal-rename-installing"),
        _ => None,
    };
    transaction
        .root
        .atomic_write_with_hooks(
            TRANSACTION_JOURNAL,
            &bytes,
            0o600,
            || {
                if let Some(point) = crash_point {
                    maybe_crash_at(point);
                }
                Ok(())
            },
            || transaction.ensure_bound(install),
        )
        .context("failed to persist anchored update journal")
}

#[cfg(unix)]
fn persist_restart_record_at(install: &InstallLayout, record: &RestartPending) -> Result<()> {
    validate_restart_record_ready(record)?;
    install.ensure_bound()?;
    let bytes = serde_json::to_vec_pretty(record).context("failed to serialize restart state")?;
    install
        .root
        .create_private_file_absent_or_identical_with_hook(
            RESTART_ACK_REQUIRED_FILE,
            &bytes,
            "restart acknowledgement marker",
            || install.ensure_bound(),
            || Ok(()),
        )
        .context("failed to persist anchored restart acknowledgement state")
}

#[cfg(unix)]
fn persist_mcp_repair_record_at(install: &InstallLayout, record: &McpRepairPending) -> Result<()> {
    persist_mcp_repair_record_at_with_hook(install, record, || Ok(()))
}

#[cfg(unix)]
fn persist_mcp_repair_record_at_with_hook<B>(
    install: &InstallLayout,
    record: &McpRepairPending,
    before_create: B,
) -> Result<()>
where
    B: FnOnce() -> Result<()>,
{
    validate_mcp_repair_record(record)?;
    if !record.repair_required {
        return Ok(());
    }
    install.ensure_bound()?;
    let bytes =
        serde_json::to_vec_pretty(record).context("failed to serialize MCP repair state")?;
    install
        .root
        .create_private_file_absent_or_identical_with_hook(
            MCP_REPAIR_PENDING_FILE,
            &bytes,
            "MCP repair pending marker",
            || {
                before_create()?;
                install.ensure_bound()
            },
            || Ok(()),
        )
        .context("failed to persist anchored MCP repair state")
}

#[cfg(unix)]
fn validate_installed_bundle_at(
    install: &InstallLayout,
    journal: &TransactionJournal,
    spec: &[ComponentSpec],
) -> Result<()> {
    install.ensure_bound()?;
    for component in spec {
        let record = journal_component(journal, component.name)?;
        let actual = install
            .component_dir(*component)
            .identity(component.name, "installed component")?;
        match (&record.staged_identity, actual) {
            (Some(expected), Some(actual)) if expected == &actual => {}
            (Some(_), Some(_)) => anyhow::bail!(
                "installed component '{}' does not match its recorded staged identity",
                component.name
            ),
            (Some(_), None) => {
                anyhow::bail!("installed component '{}' is missing", component.name)
            }
            (None, Some(_)) => anyhow::bail!(
                "stale optional component '{}' remained after update",
                component.name
            ),
            (None, None) if component.required => {
                anyhow::bail!("required component '{}' was not installed", component.name)
            }
            (None, None) => {}
        }
    }
    let installed = if journal.notifier_bundle.staged_identity.is_some() {
        staged_bundle_identity_at(&install.lib, NOTIFIER_BUNDLE_DIR)?
    } else {
        bundle_identity_at(&install.lib, NOTIFIER_BUNDLE_DIR)?
    };
    match (&journal.notifier_bundle.staged_identity, installed) {
        (Some(expected), Some(actual)) if expected == &actual => {}
        (Some(_), Some(_)) => anyhow::bail!(
            "the installed notification bundle does not match its recorded staged identity"
        ),
        (Some(_), None) => anyhow::bail!("the notification bundle is missing after the update"),
        // Nothing was staged, so whatever is there predates this transaction
        // and is none of its business.
        (None, _) => {}
    }
    Ok(())
}

#[cfg(unix)]
fn validate_backup_tree_at(
    install: &InstallLayout,
    transaction: &TransactionLayout,
    journal: &TransactionJournal,
    spec: &[ComponentSpec],
) -> Result<()> {
    transaction.ensure_bound(install)?;
    ensure_exact_directory_entries(&transaction.root, &[TRANSACTION_JOURNAL, "old"])?;
    ensure_exact_directory_entries(&transaction.old, &["bin", "lib"])?;
    ensure_allowed_directory_entries(
        &transaction.old_bin,
        spec.iter()
            .filter(|component| component.location == ComponentLocation::Bin)
            .map(|component| component.name),
    )?;
    ensure_allowed_directory_entries(
        &transaction.old_lib,
        spec.iter()
            .filter(|component| component.location == ComponentLocation::Lib)
            .map(|component| component.name)
            .chain(spec_carries_notifier_bundle(spec).then_some(NOTIFIER_BUNDLE_DIR)),
    )?;
    match (
        &journal.notifier_bundle.original_identity,
        bundle_identity_at(&transaction.old_lib, NOTIFIER_BUNDLE_DIR)?,
    ) {
        (Some(expected), Some(actual)) if expected == &actual => {}
        (Some(_), Some(_)) => {
            anyhow::bail!("the notification bundle backup identity changed")
        }
        (None, Some(_)) => {
            anyhow::bail!(
                "unexpected notification bundle backup for a transaction that recorded none"
            )
        }
        (_, None) => {}
    }
    for component in spec {
        let record = journal_component(journal, component.name)?;
        let actual = transaction
            .component_dir(*component)
            .identity(component.name, "transaction backup")?;
        match (&record.original_identity, actual) {
            (Some(expected), Some(actual)) if expected == &actual => {}
            (Some(_), Some(_)) => anyhow::bail!(
                "transaction backup identity mismatch for '{}'",
                component.name
            ),
            (None, Some(_)) => anyhow::bail!(
                "unexpected transaction backup for component '{}'",
                component.name
            ),
            (_, None) => {}
        }
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_exact_directory_entries(directory: &AnchoredDir, expected: &[&str]) -> Result<()> {
    let mut actual = directory.entry_names()?;
    actual.sort();
    let mut expected = expected
        .iter()
        .map(|entry| (*entry).to_string())
        .collect::<Vec<_>>();
    expected.sort();
    if actual != expected {
        anyhow::bail!(
            "anchored directory inventory mismatch at {}: expected {:?}, found {:?}",
            directory.display.display(),
            expected,
            actual
        );
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_allowed_directory_entries<'a>(
    directory: &AnchoredDir,
    allowed: impl Iterator<Item = &'a str>,
) -> Result<()> {
    let allowed = allowed.collect::<HashSet<_>>();
    for actual in directory.entry_names()? {
        if !allowed.contains(actual.as_str()) {
            anyhow::bail!(
                "unexpected anchored directory entry at {}/{}",
                directory.display.display(),
                actual
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn install_staged_bundle_unix<F>(
    lock: &InstallRootLock,
    staging: &StagingLayout,
    spec: &[ComponentSpec],
    verified_staged_identities: &VerifiedStagedIdentities,
    target_version: &str,
    restart_pending: &RestartPending,
    before_install: F,
) -> Result<InstallOutcome>
where
    F: FnMut(usize, &Path) -> Result<()>,
{
    install_staged_bundle_unix_with_hooks(
        lock,
        staging,
        spec,
        verified_staged_identities,
        target_version,
        restart_pending,
        |_, _| Ok(()),
        before_install,
        |_| Ok(()),
    )
}

#[cfg(unix)]
fn install_staged_bundle_unix_with_hooks<B, F, P>(
    lock: &InstallRootLock,
    staging: &StagingLayout,
    spec: &[ComponentSpec],
    verified_staged_identities: &VerifiedStagedIdentities,
    target_version: &str,
    restart_pending: &RestartPending,
    mut before_backup: B,
    mut before_install: F,
    mut after_precommit_mutation: P,
) -> Result<InstallOutcome>
where
    B: FnMut(usize, &Path) -> Result<()>,
    F: FnMut(usize, &Path) -> Result<()>,
    P: FnMut(&str) -> Result<()>,
{
    let kin_home = lock.root();
    let install = lock.install()?;
    validate_staged_bundle_locked(install, staging, spec)?;
    install.ensure_bound()?;
    staging.ensure_bound()?;

    let mut components = Vec::with_capacity(spec.len());
    for component in spec {
        let original_identity = install
            .component_dir(*component)
            .identity(component.name, "live update destination")?;
        let actual_staged_identity = staging
            .component_dir(*component)
            .identity(component.name, "staged component")?;
        let staged_identity = verified_staged_identities.get(component.name).cloned();
        if actual_staged_identity != staged_identity {
            anyhow::bail!(
                "staged component '{}' does not match its verified release provenance identity",
                component.name
            );
        }
        if component.required && staged_identity.is_none() {
            anyhow::bail!("required component '{}' was not staged", component.name);
        }
        components.push(JournalComponent {
            name: component.name.to_string(),
            location: component.location,
            required: component.required,
            had_original: original_identity.is_some(),
            install_new: staged_identity.is_some(),
            original_identity,
            staged_identity,
        });
    }
    if verified_staged_identities.len()
        != components
            .iter()
            .filter(|component| component.install_new)
            .count()
    {
        anyhow::bail!(
            "verified staged identity inventory contains files outside the managed platform bundle"
        );
    }

    // The notification bundle is read before the transaction exists for the
    // same reason the components are: a fallible read must not strand a
    // half-created transaction directory.
    let notifier_bundle = if spec_carries_notifier_bundle(spec) {
        let staged_identity = staged_bundle_identity_at(&staging.lib, NOTIFIER_BUNDLE_DIR)?;
        if staged_identity.is_none() {
            anyhow::bail!("the staged release is missing its notification bundle");
        }
        JournalBundle {
            original_identity: bundle_identity_at(&install.lib, NOTIFIER_BUNDLE_DIR)?,
            staged_identity,
        }
    } else {
        JournalBundle::default()
    };

    // Resolve the durable repair manifest before transaction creation so a
    // fallible config/ledger read cannot strand an unjournaled directory.
    let mcp_repair_pending = mcp_repair_pending_record(lock, target_version)?;
    let transaction = TransactionLayout::create(install)?;
    let transaction_root = kin_home.join(&transaction.name);
    let mut journal = TransactionJournal {
        schema_version: TRANSACTION_JOURNAL_SCHEMA,
        target_version: target_version.to_string(),
        phase: TransactionPhase::Prepared,
        components,
        notifier_bundle,
        restart_pending: restart_pending.clone(),
        mcp_repair_pending,
    };
    if let Err(error) = persist_journal_at(install, &transaction, &journal) {
        let _ = cleanup_transaction_at(install, &transaction, &journal, spec);
        return Err(error);
    }
    let precommit = (|| -> Result<()> {
        journal.phase = TransactionPhase::BackingUp;
        persist_journal_at(install, &transaction, &journal)?;

        // The bundle moves first in both phases. It is the only participant
        // made of many files, so doing it while nothing else has been disturbed
        // keeps the window in which a failure has work to undo as small as the
        // component swaps allow, and it leaves the running CLI's swap last.
        if let Some(expected) = journal.notifier_bundle.original_identity.clone() {
            install.ensure_bound()?;
            staging.ensure_bound()?;
            transaction.ensure_bound(install)?;
            if bundle_identity_at(&install.lib, NOTIFIER_BUNDLE_DIR)?.as_ref() != Some(&expected) {
                anyhow::bail!(
                    "the live notification bundle changed after its journal identity was recorded"
                );
            }
            if transaction
                .old_lib
                .stat_entry(NOTIFIER_BUNDLE_DIR)?
                .is_some()
            {
                anyhow::bail!("a transaction backup of the notification bundle already exists");
            }
            transaction.ensure_bound(install)?;
            install.lib.rename_to(
                NOTIFIER_BUNDLE_DIR,
                &transaction.old_lib,
                NOTIFIER_BUNDLE_DIR,
            )?;
            after_precommit_mutation("after-backup-mutation-notifier-bundle")?;
            transaction.ensure_bound(install)?;
            if bundle_identity_at(&transaction.old_lib, NOTIFIER_BUNDLE_DIR)?.as_ref()
                != Some(&expected)
            {
                anyhow::bail!(
                    "the notification bundle backup does not match the recorded original identity"
                );
            }
            maybe_crash_at("after-backup-notifier-bundle");
        }

        for (index, component) in spec.iter().enumerate() {
            let record = journal_component(&journal, component.name)?;
            let Some(expected) = &record.original_identity else {
                continue;
            };
            let destination_path = component_path(kin_home, *component);
            before_backup(index, &destination_path)?;
            install.ensure_bound()?;
            staging.ensure_bound()?;
            transaction.ensure_bound(install)?;
            let live_dir = install.component_dir(*component);
            let backup_dir = transaction.component_dir(*component);
            if live_dir
                .identity(component.name, "live component before backup")?
                .as_ref()
                != Some(expected)
            {
                anyhow::bail!(
                    "live component '{}' changed after its journal identity was recorded",
                    component.name
                );
            }
            if backup_dir
                .identity(component.name, "preexisting transaction backup")?
                .is_some()
            {
                anyhow::bail!("transaction backup '{}' already exists", component.name);
            }
            transaction.ensure_bound(install)?;
            if component_is_recovery_cli(*component) {
                // Keep the canonical recovery launcher executable throughout the
                // transaction. The backup is an exact durable copy; install later
                // atomically renames the staged CLI over the still-live original.
                let bytes = live_dir.read_regular(component.name, "live recovery CLI")?;
                if bytes_identity(&bytes) != *expected {
                    anyhow::bail!("live recovery CLI changed while its backup was copied");
                }
                backup_dir.atomic_write_checked(component.name, &bytes, 0o755, || {
                    transaction.ensure_bound(install)
                })?;
            } else {
                live_dir.rename_to(component.name, backup_dir, component.name)?;
            }
            after_precommit_mutation(&format!("after-backup-mutation-{index}"))?;
            transaction.ensure_bound(install)?;
            if backup_dir
                .identity(component.name, "new transaction backup")?
                .as_ref()
                != Some(expected)
            {
                anyhow::bail!(
                    "transaction backup '{}' does not match the recorded original identity",
                    component.name
                );
            }
            maybe_crash_at(&format!("after-backup-{index}"));
        }

        journal.phase = TransactionPhase::Installing;
        persist_journal_at(install, &transaction, &journal)?;
        if let Some(expected) = journal.notifier_bundle.staged_identity.clone() {
            install.ensure_bound()?;
            staging.ensure_bound()?;
            transaction.ensure_bound(install)?;
            if staged_bundle_identity_at(&staging.lib, NOTIFIER_BUNDLE_DIR)?.as_ref()
                != Some(&expected)
            {
                anyhow::bail!(
                    "the staged notification bundle changed after its journal identity was recorded"
                );
            }
            if install.lib.stat_entry(NOTIFIER_BUNDLE_DIR)?.is_some() {
                anyhow::bail!(
                    "the live notification bundle path is not in its expected pre-install state"
                );
            }
            install.ensure_bound()?;
            staging.ensure_bound()?;
            transaction.ensure_bound(install)?;
            staging
                .lib
                .rename_to(NOTIFIER_BUNDLE_DIR, &install.lib, NOTIFIER_BUNDLE_DIR)?;
            after_precommit_mutation("after-install-mutation-notifier-bundle")?;
            install.ensure_bound()?;
            if staged_bundle_identity_at(&install.lib, NOTIFIER_BUNDLE_DIR)?.as_ref()
                != Some(&expected)
            {
                anyhow::bail!(
                    "the installed notification bundle does not match its staged identity"
                );
            }
            maybe_crash_at("after-install-notifier-bundle");
        }
        let mut install_index = 0;
        for component in spec {
            let record = journal_component(&journal, component.name)?;
            let Some(expected) = &record.staged_identity else {
                continue;
            };
            let destination_path = component_path(kin_home, *component);
            before_install(install_index, &destination_path)?;
            install.ensure_bound()?;
            staging.ensure_bound()?;
            transaction.ensure_bound(install)?;
            let stage_dir = staging.component_dir(*component);
            let live_dir = install.component_dir(*component);
            if stage_dir
                .identity(component.name, "staged component before install")?
                .as_ref()
                != Some(expected)
            {
                anyhow::bail!(
                    "staged component '{}' changed after its journal identity was recorded",
                    component.name
                );
            }
            let live_before_install =
                live_dir.identity(component.name, "live destination before install")?;
            let destination_ready = if component_is_recovery_cli(*component) {
                live_before_install.as_ref() == record.original_identity.as_ref()
            } else {
                live_before_install.is_none()
            };
            if !destination_ready {
                anyhow::bail!(
                    "live destination '{}' is not in its expected pre-install state",
                    component.name
                );
            }
            install.ensure_bound()?;
            staging.ensure_bound()?;
            transaction.ensure_bound(install)?;
            stage_dir.rename_to(component.name, live_dir, component.name)?;
            after_precommit_mutation(&format!("after-install-mutation-{install_index}"))?;
            install.ensure_bound()?;
            if live_dir
                .identity(component.name, "installed component")?
                .as_ref()
                != Some(expected)
            {
                anyhow::bail!(
                    "installed component '{}' does not match its staged identity",
                    component.name
                );
            }
            maybe_crash_at(&format!("after-install-{install_index}"));
            install_index += 1;
        }

        validate_installed_bundle_at(install, &journal, spec)?;
        validate_backup_tree_at(install, &transaction, &journal, spec)?;
        install.ensure_bound()?;
        staging.ensure_bound()?;
        transaction.ensure_bound(install)?;
        ensure_no_active_managed_runtimes(kin_home, spec).context(
            "a managed serving executable appeared before the durable commit point; the uncommitted update will be rolled back",
        )?;
        after_precommit_mutation("precommit-validated")?;
        Ok(())
    })();
    if let Err(error) = precommit {
        return rollback_after_failure_at(
            error,
            &mut journal,
            install,
            &transaction,
            &transaction_root,
            spec,
        );
    }

    journal.phase = TransactionPhase::Committed;
    if let Err(error) = persist_journal_at(install, &transaction, &journal) {
        // A failed commit write is ambiguous: rename may have installed the
        // committed journal even if its directory fsync failed. Rolling back
        // here could therefore contradict the durable recovery decision.
        // Retain both exact bundles and let the next locked recovery inspect
        // the journal that is actually present.
        return Err(error.context(format!(
            "update commit transition was not durably confirmed; no rollback was attempted and recovery state is retained at {}",
            transaction_root.display()
        )));
    }
    maybe_crash_at("after-commit-journal-before-process-fence");
    mark_restart_record_committed(&mut journal.restart_pending, kin_home, spec).with_context(|| {
        format!(
            "update committed on disk, but its runtime identity fence could not be captured; durable recovery remains at {}",
            transaction_root.display()
        )
    })?;
    persist_journal_at(install, &transaction, &journal).with_context(|| {
        format!(
            "update committed on disk, but its runtime identity fence could not be persisted; durable recovery remains at {}",
            transaction_root.display()
        )
    })?;
    maybe_crash_at("after-commit");

    persist_restart_record_at(install, &journal.restart_pending).with_context(|| {
        format!(
            "update committed on disk, but restart acknowledgement state could not be persisted; durable recovery remains at {}",
            transaction_root.display()
        )
    })?;
    maybe_crash_at("after-restart-marker");
    persist_mcp_repair_record_at(install, &journal.mcp_repair_pending).with_context(|| {
        format!(
            "update committed on disk, but MCP repair state could not be persisted; durable recovery remains at {}",
            transaction_root.display()
        )
    })?;
    maybe_crash_at("after-mcp-marker");

    let retained_backup = match cleanup_transaction_at(install, &transaction, &journal, spec) {
        Ok(()) => None,
        Err(_) => Some(transaction_root),
    };
    maybe_crash_at("after-cleanup");
    Ok(InstallOutcome { retained_backup })
}

#[cfg(unix)]
fn rollback_plan_at(
    install: &InstallLayout,
    transaction: &TransactionLayout,
    journal: &TransactionJournal,
    spec: &[ComponentSpec],
) -> Result<Vec<(ComponentSpec, RollbackAction)>> {
    validate_journal(journal, spec)?;
    validate_backup_tree_at(install, transaction, journal, spec)?;
    let mut actions = Vec::with_capacity(spec.len());
    for component in spec.iter().rev() {
        let record = journal_component(journal, component.name)?;
        let backup_identity = transaction
            .component_dir(*component)
            .identity(component.name, "transaction backup")?;
        let live_identity = install
            .component_dir(*component)
            .identity(component.name, "live rollback destination")?;
        let action = match (
            &record.original_identity,
            &record.staged_identity,
            backup_identity,
            live_identity,
        ) {
            (Some(original), staged, Some(backup), live) => {
                if &backup != original {
                    anyhow::bail!(
                        "transaction backup identity changed for '{}'",
                        component.name
                    );
                }
                match live {
                    None => RollbackAction::RestoreOriginal {
                        remove_installed: false,
                    },
                    Some(actual) if &actual == original && component_is_recovery_cli(*component) => {
                        RollbackAction::None
                    }
                    Some(actual) if staged.as_ref() == Some(&actual) => {
                        RollbackAction::RestoreOriginal {
                            remove_installed: true,
                        }
                    }
                    Some(_) => anyhow::bail!(
                        "refusing ambiguous rollback for '{}': backup exists but live bytes are not the recorded staged identity",
                        component.name
                    ),
                }
            }
            (Some(original), _, None, Some(actual)) if &actual == original => RollbackAction::None,
            (Some(_), _, None, Some(_)) => anyhow::bail!(
                "refusing ambiguous rollback for '{}': backup is missing and live bytes are not the recorded original identity",
                component.name
            ),
            (Some(_), _, None, None) => anyhow::bail!(
                "original component '{}' is absent from both live and backup paths",
                component.name
            ),
            (None, Some(staged), None, Some(actual)) if &actual == staged => {
                RollbackAction::RemoveInstalled
            }
            (None, Some(_), None, Some(_)) => anyhow::bail!(
                "refusing ambiguous rollback for '{}': live bytes are not the recorded staged identity",
                component.name
            ),
            (None, _, None, None) => RollbackAction::None,
            (None, _, Some(_), _) => anyhow::bail!(
                "unexpected backup exists for component '{}' that had no original",
                component.name
            ),
            (None, None, None, Some(_)) => anyhow::bail!(
                "unexpected live bytes exist for optional component '{}'",
                component.name
            ),
        };
        actions.push((*component, action));
    }
    Ok(actions)
}

#[cfg(unix)]
fn rollback_transaction_at(
    journal: &mut TransactionJournal,
    install: &InstallLayout,
    transaction: &TransactionLayout,
    spec: &[ComponentSpec],
) -> Result<()> {
    let actions = rollback_plan_at(install, transaction, journal, spec)?;
    for (component, action) in actions {
        transaction.ensure_bound(install)?;
        let live_dir = install.component_dir(component);
        let backup_dir = transaction.component_dir(component);
        match action {
            RollbackAction::None => {}
            RollbackAction::RemoveInstalled => {
                let staged = journal_component(journal, component.name)?
                    .staged_identity
                    .as_ref()
                    .context("rollback remove is missing staged identity")?;
                if live_dir
                    .identity(component.name, "rollback live component")?
                    .as_ref()
                    != Some(staged)
                {
                    anyhow::bail!(
                        "live component '{}' changed immediately before rollback removal",
                        component.name
                    );
                }
                transaction.ensure_bound(install)?;
                live_dir.unlink_file(component.name)?;
                maybe_crash_at(&format!("after-rollback-remove-{}", component.name));
            }
            RollbackAction::RestoreOriginal { remove_installed } => {
                let record = journal_component(journal, component.name)?;
                let original = record
                    .original_identity
                    .as_ref()
                    .context("rollback restore is missing original identity")?;
                if backup_dir
                    .identity(component.name, "rollback backup immediately before restore")?
                    .as_ref()
                    != Some(original)
                {
                    anyhow::bail!(
                        "backup component '{}' changed immediately before restore",
                        component.name
                    );
                }
                if remove_installed && !component_is_recovery_cli(component) {
                    let staged = record
                        .staged_identity
                        .as_ref()
                        .context("rollback replacement is missing staged identity")?;
                    if live_dir
                        .identity(component.name, "rollback live component")?
                        .as_ref()
                        != Some(staged)
                    {
                        anyhow::bail!(
                            "live component '{}' changed immediately before rollback removal",
                            component.name
                        );
                    }
                    transaction.ensure_bound(install)?;
                    live_dir.unlink_file(component.name)?;
                    maybe_crash_at(&format!("after-rollback-remove-{}", component.name));
                }
                // Recheck after the live unlink: a concurrent backup swap must
                // never be renamed into the managed install.
                if backup_dir
                    .identity(component.name, "rollback backup immediately before rename")?
                    .as_ref()
                    != Some(original)
                {
                    anyhow::bail!(
                        "backup component '{}' changed before rollback rename",
                        component.name
                    );
                }
                transaction.ensure_bound(install)?;
                backup_dir.rename_to(component.name, live_dir, component.name)?;
                if remove_installed && component_is_recovery_cli(component) {
                    // Preserve the historical crash hook while proving the
                    // canonical launcher is already restored atomically.
                    maybe_crash_at(&format!("after-rollback-remove-{}", component.name));
                }
                if live_dir
                    .identity(component.name, "restored rollback component")?
                    .as_ref()
                    != Some(original)
                {
                    anyhow::bail!(
                        "restored component '{}' does not match its original identity",
                        component.name
                    );
                }
                maybe_crash_at(&format!("after-rollback-restore-{}", component.name));
            }
        }
    }
    rollback_notifier_bundle_at(install, transaction, journal)?;
    journal.phase = TransactionPhase::RolledBack;
    persist_journal_at(install, transaction, journal)?;
    cleanup_transaction_at(install, transaction, journal, spec)
}

/// Reverse the bundle swap, last, because it moved first.
///
/// The decision is made from what is actually on disk rather than from how far
/// the transaction believed it had got, so a crash between any two steps
/// resolves the same way a clean failure does.
///
/// A component is one file swapped by one atomic rename, so it is only ever the
/// old bytes or the new bytes, and anything else is refused as ambiguous. A
/// bundle is a tree removed file by file, so an interrupted rollback genuinely
/// can leave a partial tree that is neither. Refusing that outright would wedge
/// every later update behind a state only manual deletion could clear. So the
/// rule is narrower than the components': a live tree that matches neither is
/// discarded only while the recorded original is proven present in the backup,
/// which is precisely when discarding it loses nothing. With no backup to
/// restore, removal would be irreversible, so the tree is left alone and the
/// gap is reported instead.
#[cfg(unix)]
fn rollback_notifier_bundle_at(
    install: &InstallLayout,
    transaction: &TransactionLayout,
    journal: &TransactionJournal,
) -> Result<()> {
    let record = &journal.notifier_bundle;
    if record.is_empty() {
        return Ok(());
    }
    transaction.ensure_bound(install)?;
    let live = bundle_identity_at(&install.lib, NOTIFIER_BUNDLE_DIR)?;
    let backup = bundle_identity_at(&transaction.old_lib, NOTIFIER_BUNDLE_DIR)?;
    let backup_holds_original = record
        .original_identity
        .as_ref()
        .is_some_and(|original| backup.as_ref() == Some(original));

    let remove_live = match (&live, &record.original_identity, &record.staged_identity) {
        (None, _, _) => false,
        // Already the bundle to end on: either the original was never moved, or
        // it has been restored by an earlier attempt at this rollback.
        (Some(actual), Some(original), _) if actual == original => return Ok(()),
        (Some(actual), _, Some(staged)) if actual == staged => true,
        // Neither, but the original is proven recoverable: an interrupted
        // rollback's partial tree, about to be replaced by bytes we hold.
        (Some(_), Some(_), _) if backup_holds_original => true,
        (Some(_), _, _) => anyhow::bail!(
            "refusing an ambiguous notification bundle rollback: the bundle at {}/{} is neither the recorded original nor the recorded staged bundle, and no verified backup is held to replace it. Remove it to let the next update reinstall one.",
            install.lib.display.display(),
            NOTIFIER_BUNDLE_DIR
        ),
    };

    let Some(original) = &record.original_identity else {
        // Nothing to restore: this transaction brought the first bundle, so
        // undoing it means leaving the install without one, exactly as before.
        if remove_live {
            transaction.ensure_bound(install)?;
            remove_bundle_tree(&install.lib, NOTIFIER_BUNDLE_DIR)?;
            maybe_crash_at("after-rollback-remove-notifier-bundle");
        }
        return Ok(());
    };
    if !backup_holds_original {
        anyhow::bail!("the notification bundle backup changed immediately before it was restored");
    }
    if remove_live {
        transaction.ensure_bound(install)?;
        remove_bundle_tree(&install.lib, NOTIFIER_BUNDLE_DIR)?;
        maybe_crash_at("after-rollback-remove-notifier-bundle");
    }
    // Recheck after the live removal: a concurrent swap of the backup must never
    // be renamed into the managed install.
    if bundle_identity_at(&transaction.old_lib, NOTIFIER_BUNDLE_DIR)?.as_ref() != Some(original) {
        anyhow::bail!("the notification bundle backup changed before the rollback rename");
    }
    transaction.ensure_bound(install)?;
    transaction
        .old_lib
        .rename_to(NOTIFIER_BUNDLE_DIR, &install.lib, NOTIFIER_BUNDLE_DIR)?;
    install.ensure_bound()?;
    if bundle_identity_at(&install.lib, NOTIFIER_BUNDLE_DIR)?.as_ref() != Some(original) {
        anyhow::bail!("the restored notification bundle does not match its original identity");
    }
    maybe_crash_at("after-rollback-restore-notifier-bundle");
    Ok(())
}

#[cfg(unix)]
fn rollback_after_failure_at(
    primary: anyhow::Error,
    journal: &mut TransactionJournal,
    install: &InstallLayout,
    transaction: &TransactionLayout,
    transaction_root: &Path,
    spec: &[ComponentSpec],
) -> Result<InstallOutcome> {
    match rollback_transaction_at(journal, install, transaction, spec) {
        Ok(()) => Err(primary.context("update transaction failed; previous bundle was restored")),
        Err(rollback_error) => Err(primary.context(format!(
            "update transaction failed AND rollback was incomplete: {rollback_error:#}. Recovery backup retained at {}",
            transaction_root.display()
        ))),
    }
}

#[cfg(unix)]
fn cleanup_transaction_at(
    install: &InstallLayout,
    transaction: &TransactionLayout,
    journal: &TransactionJournal,
    spec: &[ComponentSpec],
) -> Result<()> {
    transaction.ensure_bound(install)?;
    validate_backup_tree_at(install, transaction, journal, spec)?;
    for component in spec {
        let backup_dir = transaction.component_dir(*component);
        if let Some(actual) = backup_dir.identity(component.name, "cleanup transaction backup")? {
            let expected = journal_component(journal, component.name)?
                .original_identity
                .as_ref()
                .context("unexpected cleanup backup without original identity")?;
            if &actual != expected {
                anyhow::bail!(
                    "transaction backup '{}' changed before cleanup",
                    component.name
                );
            }
            transaction.ensure_bound(install)?;
            backup_dir.unlink_file(component.name)?;
        }
    }
    if let Some(actual) = bundle_identity_at(&transaction.old_lib, NOTIFIER_BUNDLE_DIR)? {
        let expected = journal
            .notifier_bundle
            .original_identity
            .as_ref()
            .context("unexpected notification bundle backup without a recorded original")?;
        if &actual != expected {
            anyhow::bail!("the notification bundle backup changed before cleanup");
        }
        transaction.ensure_bound(install)?;
        remove_bundle_tree(&transaction.old_lib, NOTIFIER_BUNDLE_DIR)?;
    }
    transaction.old_bin.ensure_empty()?;
    transaction.old_lib.ensure_empty()?;

    // Keep the journal until all backup bytes are gone and both backup leaf
    // directories have been proven empty. Once the journal is removed, only
    // empty structural directories remain and no recovery decision is needed.
    transaction.ensure_bound(install)?;
    transaction.root.unlink_file(TRANSACTION_JOURNAL)?;
    transaction
        .root
        .ensure_child_binding("old", &transaction.old)?;
    transaction
        .old
        .ensure_child_binding("bin", &transaction.old_bin)?;
    transaction.ensure_bound(install)?;
    transaction.old.remove_child_dir("bin")?;
    transaction
        .old
        .ensure_child_binding("lib", &transaction.old_lib)?;
    install.ensure_bound()?;
    install
        .root
        .ensure_child_binding(&transaction.name, &transaction.root)?;
    transaction
        .root
        .ensure_child_binding("old", &transaction.old)?;
    transaction
        .old
        .ensure_child_binding("lib", &transaction.old_lib)?;
    transaction.old.remove_child_dir("lib")?;
    transaction.old.ensure_empty()?;
    transaction
        .root
        .ensure_child_binding("old", &transaction.old)?;
    install.ensure_bound()?;
    install
        .root
        .ensure_child_binding(&transaction.name, &transaction.root)?;
    transaction
        .root
        .ensure_child_binding("old", &transaction.old)?;
    transaction.root.remove_child_dir("old")?;
    transaction.root.ensure_empty()?;
    install.ensure_bound()?;
    install
        .root
        .ensure_child_binding(&transaction.name, &transaction.root)?;
    install.root.remove_child_dir(&transaction.name)
}

#[cfg(not(unix))]
fn create_transaction_root(kin_home: &Path) -> Result<PathBuf> {
    create_transaction_root_with_hook(kin_home, |_| Ok(()))
}

#[cfg(not(unix))]
fn create_transaction_root_with_hook<F>(kin_home: &Path, mut after_step: F) -> Result<PathBuf>
where
    F: FnMut(&str) -> Result<()>,
{
    let transaction_root = kin_home.join(format!("{TRANSACTION_PREFIX}{}", uuid::Uuid::new_v4()));
    fs::create_dir(&transaction_root).with_context(|| {
        format!(
            "failed to create update transaction directory {}",
            transaction_root.display()
        )
    })?;
    let mut pending = PendingUpdateRoot::new(transaction_root.clone());
    after_step("transaction-root")?;
    sync_dir(kin_home)?;
    let old = transaction_root.join("old");
    fs::create_dir(&old)?;
    after_step("transaction-old")?;
    sync_dir(&transaction_root)?;
    for name in ["bin", "lib"] {
        fs::create_dir(old.join(name))?;
        after_step(match name {
            "bin" => "transaction-old-bin",
            "lib" => "transaction-old-lib",
            _ => unreachable!("fixed transaction directory inventory"),
        })?;
        sync_dir(&old)?;
    }
    after_step("transaction-validated")?;
    pending.disarm();
    Ok(transaction_root)
}

#[cfg(not(unix))]
fn persist_journal(transaction_root: &Path, journal: &TransactionJournal) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(journal).context("failed to serialize update journal")?;
    write_file_atomically(&transaction_root.join(TRANSACTION_JOURNAL), &bytes, 0o600)
        .context("failed to persist update journal")
}

#[cfg(not(unix))]
fn read_journal(transaction_root: &Path) -> Result<TransactionJournal> {
    let path = transaction_root.join(TRANSACTION_JOURNAL);
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("missing transaction journal {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "transaction journal is not a regular file: {}",
            path.display()
        );
    }
    let bytes = fs::read(&path)
        .with_context(|| format!("failed to read transaction journal {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid transaction journal {}", path.display()))
}

fn journal_component<'a>(
    journal: &'a TransactionJournal,
    name: &str,
) -> Result<&'a JournalComponent> {
    journal
        .components
        .iter()
        .find(|component| component.name == name)
        .with_context(|| format!("transaction journal is missing component '{name}'"))
}

fn validate_journal(journal: &TransactionJournal, spec: &[ComponentSpec]) -> Result<()> {
    match journal.schema_version {
        TRANSACTION_JOURNAL_SCHEMA => {}
        TRANSACTION_JOURNAL_SCHEMA_WITHOUT_BUNDLE => {
            if !journal.notifier_bundle.is_empty() {
                anyhow::bail!(
                    "update journal schema {TRANSACTION_JOURNAL_SCHEMA_WITHOUT_BUNDLE} carries a notification bundle record it cannot describe"
                );
            }
        }
        other => anyhow::bail!("unsupported update journal schema {other}"),
    }
    if !spec_carries_notifier_bundle(spec) && !journal.notifier_bundle.is_empty() {
        anyhow::bail!("update journal records a notification bundle this platform does not carry");
    }
    // Only the digest is checked. A bundle identity describes whatever tree was
    // there, including a husk left by an interrupted removal, and refusing to
    // describe that state is what would strand a rollback that has to reverse
    // it. That the bundle being installed is a usable one is proven separately,
    // by the shape check that runs when it is staged and again once it is live.
    for identity in [
        journal.notifier_bundle.original_identity.as_ref(),
        journal.notifier_bundle.staged_identity.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_hex(
            &identity.tree_sha256,
            64,
            "journal notification bundle SHA-256",
        )?;
    }
    if journal.components.len() != spec.len() {
        anyhow::bail!("update journal component inventory does not match this platform");
    }
    if journal.mcp_repair_pending.schema_version != MCP_REPAIR_MARKER_SCHEMA_VERSION
        || parse_release_version(&journal.target_version)?
            != parse_release_version(&journal.restart_pending.installed_version)?
        || parse_release_version(&journal.target_version)?
            != parse_release_version(&journal.mcp_repair_pending.installed_version)?
    {
        anyhow::bail!("update journal restart identity does not match its target version");
    }
    validate_restart_record_schema(&journal.restart_pending)?;
    validate_mcp_repair_record(&journal.mcp_repair_pending)?;
    let runtime_kinds = journal
        .restart_pending
        .runtime_obligations
        .iter()
        .map(|obligation| obligation.kind)
        .collect::<HashSet<_>>();
    if spec != WINDOWS_COMPONENTS
        && (runtime_kinds
            != HashSet::from([RuntimeKind::Daemon, RuntimeKind::Mcp, RuntimeKind::Vfs])
            || journal.restart_pending.runtime_obligations.len() != 3)
    {
        anyhow::bail!("restart marker does not contain the exact managed runtime obligations");
    }
    if spec != WINDOWS_COMPONENTS {
        let mut prior_processes = HashSet::new();
        for obligation in &journal.restart_pending.runtime_obligations {
            if journal_component(journal, &obligation.component)?
                .staged_identity
                .as_ref()
                != Some(&obligation.expected_identity)
            {
                anyhow::bail!(
                    "managed {} runtime identity does not match the staged transaction component",
                    obligation.kind.label()
                );
            }
            for session in &obligation.prior_sessions {
                if session.pid == 0
                    || session.start_time == 0
                    || !session.executable.is_absolute()
                    || session
                        .binding
                        .as_ref()
                        .is_some_and(|path| !path.is_absolute())
                    || !prior_processes.insert((session.pid, session.start_time))
                {
                    anyhow::bail!(
                        "journal has an invalid pre-update {} runtime session",
                        obligation.kind.label()
                    );
                }
                validate_hex(
                    &session.executable_identity.sha256,
                    64,
                    "journal pre-update runtime SHA-256",
                )?;
                if session.executable_identity.size_bytes == 0 {
                    anyhow::bail!("journal has an empty pre-update runtime identity");
                }
            }
        }
    }
    validate_hex(
        &journal.restart_pending.kin_commit,
        40,
        "journal Kin commit",
    )?;
    validate_hex(
        &journal.restart_pending.dependency_provenance,
        64,
        "journal dependency provenance",
    )?;
    validate_hex(
        &journal.restart_pending.kin_vfs_commit,
        40,
        "journal kin-vfs commit",
    )?;
    let mut seen = HashSet::new();
    for expected in spec {
        let component = journal_component(journal, expected.name)?;
        if !seen.insert(component.name.as_str())
            || component.location != expected.location
            || component.required != expected.required
            || component.had_original != component.original_identity.is_some()
            || component.install_new != component.staged_identity.is_some()
        {
            anyhow::bail!(
                "update journal component '{}' does not match the platform contract",
                expected.name
            );
        }
        if let Some(identity) = &component.original_identity {
            validate_hex(&identity.sha256, 64, "journal original SHA-256")?;
        }
        if let Some(identity) = &component.staged_identity {
            validate_hex(&identity.sha256, 64, "journal staged SHA-256")?;
            if identity.size_bytes == 0 {
                anyhow::bail!(
                    "update journal staged component '{}' has an empty identity",
                    component.name
                );
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_installed_bundle(
    kin_home: &Path,
    journal: &TransactionJournal,
    spec: &[ComponentSpec],
) -> Result<()> {
    for component in spec {
        let record = journal_component(journal, component.name)?;
        let was_staged = record.install_new;
        let dest = component_path(kin_home, *component);
        if !was_staged {
            if component.required {
                anyhow::bail!("required component '{}' was not installed", component.name);
            }
            if fs::symlink_metadata(&dest).is_ok() {
                anyhow::bail!(
                    "stale optional component '{}' remained after update",
                    component.name
                );
            }
            continue;
        }
        let metadata = fs::symlink_metadata(&dest)
            .with_context(|| format!("installed component {} is missing", dest.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            anyhow::bail!(
                "installed component '{}' is not a non-empty file",
                component.name
            );
        }
        verify_file_identity(
            &dest,
            record
                .staged_identity
                .as_ref()
                .context("installed component is missing its staged identity")?,
            "installed component",
        )?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn optional_file_identity(path: &Path, context: &str) -> Result<Option<FileIdentity>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                anyhow::bail!(
                    "{context} is not a regular non-symlink file: {}",
                    path.display()
                );
            }
            Ok(Some(file_identity(path)?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {context} {}", path.display()))
        }
    }
}

#[cfg(not(unix))]
fn validate_real_directory(path: &Path, context: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("missing {context} {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "{context} is not a real non-symlink directory: {}",
            path.display()
        );
    }
    Ok(())
}

/// Validate every expected backup object before rollback is allowed to remove
/// any live byte. Missing component backups are permitted because a crash may
/// have happened before backup or after an idempotent restore. A present backup
/// must be the exact original regular file recorded before the first rename.
#[cfg(not(unix))]
fn validate_backup_tree(
    transaction_root: &Path,
    journal: &TransactionJournal,
    spec: &[ComponentSpec],
    allow_missing_tree: bool,
) -> Result<()> {
    validate_real_directory(transaction_root, "transaction root")?;
    let old = transaction_root.join("old");
    if allow_missing_tree && fs::symlink_metadata(&old).is_err() {
        return Ok(());
    }
    validate_real_directory(&old, "transaction backup root")?;
    validate_real_directory(&old.join("bin"), "transaction bin backup directory")?;
    validate_real_directory(&old.join("lib"), "transaction lib backup directory")?;
    for component in spec {
        let record = journal_component(journal, component.name)?;
        let backup = component_path(&old, *component);
        let actual = optional_file_identity(&backup, "transaction backup")?;
        match (&record.original_identity, actual) {
            (Some(expected), Some(actual)) if &actual == expected => {}
            (Some(_), Some(_)) => anyhow::bail!(
                "transaction backup identity mismatch for '{}' at {}",
                component.name,
                backup.display()
            ),
            (None, Some(_)) => anyhow::bail!(
                "unexpected transaction backup for component '{}' at {}",
                component.name,
                backup.display()
            ),
            (_, None) => {}
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RollbackAction {
    None,
    RemoveInstalled,
    RestoreOriginal { remove_installed: bool },
}

#[cfg(not(unix))]
fn rollback_transaction(
    journal: &mut TransactionJournal,
    transaction_root: &Path,
    kin_home: &Path,
    spec: &[ComponentSpec],
) -> Result<()> {
    validate_journal(journal, spec)?;
    let backup_root = transaction_root.join("old");
    validate_backup_tree(transaction_root, journal, spec, false)?;

    // Preflight the entire recovery plan before mutating any live component.
    // This guarantees a malicious/unknown backup or destination cannot cause a
    // half-rollback before the updater notices the ambiguity.
    let mut actions = Vec::with_capacity(spec.len());
    for component in spec.iter().rev() {
        let record = journal_component(journal, component.name)?;
        let dest = component_path(kin_home, *component);
        let backup = component_path(&backup_root, *component);
        let backup_identity = optional_file_identity(&backup, "transaction backup")?;
        let dest_identity = optional_file_identity(&dest, "live rollback destination")?;
        let action = match (&record.original_identity, &record.staged_identity, backup_identity, dest_identity) {
            (Some(original), staged, Some(backup_actual), dest_actual) => {
                if &backup_actual != original {
                    anyhow::bail!("transaction backup identity changed for '{}'", component.name);
                }
                match dest_actual {
                    None => RollbackAction::RestoreOriginal { remove_installed: false },
                    Some(actual) if staged.as_ref() == Some(&actual) => {
                        RollbackAction::RestoreOriginal { remove_installed: true }
                    }
                    Some(_) => anyhow::bail!(
                        "refusing ambiguous rollback for '{}': backup exists but live bytes are not the recorded staged identity",
                        component.name
                    ),
                }
            }
            (Some(original), _, None, Some(actual)) if &actual == original => RollbackAction::None,
            (Some(_), _, None, Some(_)) => anyhow::bail!(
                "refusing ambiguous rollback for '{}': backup is missing and live bytes are not the recorded original identity",
                component.name
            ),
            (Some(_), _, None, None) => anyhow::bail!(
                "original component '{}' is absent from both live and backup paths",
                component.name
            ),
            (None, Some(staged), None, Some(actual)) if &actual == staged => {
                RollbackAction::RemoveInstalled
            }
            (None, Some(_), None, Some(_)) => anyhow::bail!(
                "refusing ambiguous rollback for '{}': live bytes are not the recorded staged identity",
                component.name
            ),
            (None, _, None, None) => RollbackAction::None,
            (None, _, Some(_), _) => anyhow::bail!(
                "unexpected backup exists for component '{}' that had no original",
                component.name
            ),
            (None, None, None, Some(_)) => anyhow::bail!(
                "unexpected live bytes exist for optional component '{}'",
                component.name
            ),
        };
        actions.push((*component, action));
    }

    for (component, action) in actions {
        let dest = component_path(kin_home, component);
        let backup = component_path(&backup_root, component);
        match action {
            RollbackAction::None => {}
            RollbackAction::RemoveInstalled => {
                durable_remove_file(&dest)?;
                maybe_crash_at(&format!("after-rollback-remove-{}", component.name));
            }
            RollbackAction::RestoreOriginal { remove_installed } => {
                if remove_installed {
                    durable_remove_file(&dest)?;
                    maybe_crash_at(&format!("after-rollback-remove-{}", component.name));
                }
                durable_rename(&backup, &dest)?;
                maybe_crash_at(&format!("after-rollback-restore-{}", component.name));
            }
        }
    }
    journal.phase = TransactionPhase::RolledBack;
    persist_journal(transaction_root, journal)?;
    cleanup_transaction_root(transaction_root)
}

#[cfg(not(unix))]
fn rollback_after_failure(
    primary: anyhow::Error,
    journal: &mut TransactionJournal,
    transaction_root: &Path,
    kin_home: &Path,
    spec: &[ComponentSpec],
) -> Result<InstallOutcome> {
    let rollback = rollback_transaction(journal, transaction_root, kin_home, spec);
    match rollback {
        Ok(()) => Err(primary.context("update transaction failed; previous bundle was restored")),
        Err(rollback_err) => Err(primary.context(format!(
            "update transaction failed AND rollback was incomplete: {rollback_err:#}. \
             Recovery backup retained at {}",
            transaction_root.display()
        ))),
    }
}

#[cfg(not(unix))]
fn cleanup_transaction_root(transaction_root: &Path) -> Result<()> {
    // Keep the committed journal until every backup byte has been removed. A
    // crash during cleanup can therefore be resumed without ambiguity.
    durable_remove_dir_all(&transaction_root.join("old"))?;
    durable_remove_file(&transaction_root.join(TRANSACTION_JOURNAL))?;
    durable_remove_dir_all(transaction_root)
}

fn transaction_dirs(kin_home: &Path) -> Result<Vec<PathBuf>> {
    let mut transactions = Vec::new();
    for entry in fs::read_dir(kin_home)
        .with_context(|| format!("failed to inspect Kin home {}", kin_home.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(id) = name.strip_prefix(TRANSACTION_PREFIX) else {
            continue;
        };
        if uuid::Uuid::parse_str(id).is_err() {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            anyhow::bail!(
                "refusing non-directory update transaction path {}",
                entry.path().display()
            );
        }
        transactions.push(entry.path());
    }
    transactions.sort();
    Ok(transactions)
}

fn recover_stale_transactions(lock: &InstallRootLock, spec: &[ComponentSpec]) -> Result<()> {
    #[cfg(unix)]
    {
        return recover_stale_transactions_unix(lock, spec);
    }

    #[cfg(not(unix))]
    {
        let kin_home = lock.root();
        for transaction_root in transaction_dirs(kin_home)? {
            let journal_path = transaction_root.join(TRANSACTION_JOURNAL);
            if !journal_path.exists() {
                let old = transaction_root.join("old");
                if directory_tree_has_entries(&old)? {
                    anyhow::bail!(
                    "interrupted update at {} contains backups but no durable journal; refusing \
                     automatic recovery",
                    transaction_root.display()
                );
                }
                durable_remove_dir_all(&transaction_root)?;
                continue;
            }

            let mut journal = read_journal(&transaction_root)?;
            validate_journal(&journal, spec)?;
            if journal.phase == TransactionPhase::Committed {
                validate_backup_tree(&transaction_root, &journal, spec, true).with_context(
                    || {
                        format!(
                            "committed interrupted update at {} has an invalid backup tree",
                            transaction_root.display()
                        )
                    },
                )?;
                validate_installed_bundle(kin_home, &journal, spec).with_context(|| {
                    format!(
                        "committed interrupted update at {} has an invalid live bundle",
                        transaction_root.display()
                    )
                })?;
                if journal.restart_pending.schema_version == RESTART_MARKER_SCHEMA_VERSION {
                    if journal.restart_pending.commit_runtime_fence.is_none() {
                        mark_restart_record_committed(
                            &mut journal.restart_pending,
                            kin_home,
                            spec,
                        )?;
                        persist_journal(&transaction_root, &journal)?;
                    } else {
                        validate_runtime_commit_fence(&journal.restart_pending, kin_home, spec)?;
                    }
                }
                persist_restart_record(kin_home, &journal.restart_pending)?;
                persist_mcp_repair_record(kin_home, &journal.mcp_repair_pending)?;
                cleanup_transaction_root(&transaction_root)?;
            } else {
                rollback_transaction(&mut journal, &transaction_root, kin_home, spec)
                    .with_context(|| {
                        format!(
                            "failed to recover interrupted update at {}",
                            transaction_root.display()
                        )
                    })?;
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn read_journal_at(transaction: &TransactionLayout) -> Result<TransactionJournal> {
    let bytes = transaction
        .root
        .read_regular(TRANSACTION_JOURNAL, "transaction journal")?;
    serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "invalid transaction journal {}/{}",
            transaction.root.display.display(),
            TRANSACTION_JOURNAL
        )
    })
}

#[cfg(unix)]
fn recover_stale_transactions_unix(lock: &InstallRootLock, spec: &[ComponentSpec]) -> Result<()> {
    let install = lock.install()?;
    let kin_home = lock.root();
    for name in transaction_names_at(install)? {
        install.ensure_bound()?;
        let transaction_root = kin_home.join(&name);
        let root = install.root.open_child(&name)?;
        cleanup_journal_temps_at(install, &name, &root)?;
        if root.stat_entry(TRANSACTION_JOURNAL)?.is_none() {
            cleanup_journalless_transaction_at(install, &name, &root)?;
            continue;
        }

        // Opening the full hierarchy is intentionally deferred until a journal
        // is known to exist. A crash after journal removal may leave only a
        // prefix of the now-empty structural directories, which is safe to
        // finish via cleanup_journalless_transaction_at above.
        let transaction = TransactionLayout::open(install, &transaction_root)?;
        let mut journal = read_journal_at(&transaction)?;
        validate_journal(&journal, spec)?;
        if journal.phase == TransactionPhase::Committed {
            validate_backup_tree_at(install, &transaction, &journal, spec).with_context(|| {
                format!(
                    "committed interrupted update at {} has an invalid backup tree",
                    transaction_root.display()
                )
            })?;
            validate_installed_bundle_at(install, &journal, spec).with_context(|| {
                format!(
                    "committed interrupted update at {} has an invalid live bundle",
                    transaction_root.display()
                )
            })?;
            if journal.restart_pending.schema_version == RESTART_MARKER_SCHEMA_VERSION {
                if journal.restart_pending.commit_runtime_fence.is_none() {
                    mark_restart_record_committed(&mut journal.restart_pending, kin_home, spec)?;
                    persist_journal_at(install, &transaction, &journal)?;
                } else {
                    validate_runtime_commit_fence(&journal.restart_pending, kin_home, spec)?;
                }
            }
            persist_restart_record_at(install, &journal.restart_pending)?;
            persist_mcp_repair_record_at(install, &journal.mcp_repair_pending)?;
            cleanup_transaction_at(install, &transaction, &journal, spec)?;
        } else {
            rollback_transaction_at(&mut journal, install, &transaction, spec).with_context(
                || {
                    format!(
                        "failed to recover interrupted update at {}",
                        transaction_root.display()
                    )
                },
            )?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn transaction_names_at(install: &InstallLayout) -> Result<Vec<String>> {
    install.ensure_bound()?;
    let mut transactions = Vec::new();
    for name in install.root.entry_names()? {
        let Some(id) = name.strip_prefix(TRANSACTION_PREFIX) else {
            continue;
        };
        if uuid::Uuid::parse_str(id).is_err() {
            continue;
        }
        let stat = install
            .root
            .stat_entry(&name)?
            .context("transaction directory disappeared during discovery")?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
            anyhow::bail!(
                "refusing non-directory update transaction path {}/{}",
                install.root.display.display(),
                name
            );
        }
        transactions.push(name);
    }
    transactions.sort();
    Ok(transactions)
}

#[cfg(unix)]
fn cleanup_journal_temps_at(
    install: &InstallLayout,
    transaction_name: &str,
    root: &AnchoredDir,
) -> Result<()> {
    install.ensure_bound()?;
    install.root.ensure_child_binding(transaction_name, root)?;
    for name in root.entry_names()? {
        if !is_updater_journal_scratch_name(&name) {
            continue;
        }
        // An updater journal scratch file is disposable only when the exact
        // strict updater-owned name resolves to one stable regular non-symlink
        // inode. Quarantine it under a fresh unpredictable name before unlink
        // so a raced pathname replacement is retained rather than deleted.
        install.ensure_bound()?;
        install.root.ensure_child_binding(transaction_name, root)?;
        root.quarantine_verified_regular(&name, "update journal scratch file", || {
            install.ensure_bound()?;
            install.root.ensure_child_binding(transaction_name, root)
        })?;
    }
    Ok(())
}

#[cfg(unix)]
fn cleanup_journalless_transaction_at(
    install: &InstallLayout,
    name: &str,
    root: &AnchoredDir,
) -> Result<()> {
    install.ensure_bound()?;
    install.root.ensure_child_binding(name, root)?;
    let entries = root.entry_names()?;
    if entries.iter().any(|entry| entry != "old") {
        anyhow::bail!(
            "journal-free transaction contains an unexpected entry at {}",
            root.display.display()
        );
    }
    if root.stat_entry("old")?.is_some() {
        let old = root.open_child("old")?;
        let old_entries = old.entry_names()?;
        if old_entries
            .iter()
            .any(|entry| entry != "bin" && entry != "lib")
        {
            anyhow::bail!(
                "journal-free transaction backup tree contains an unexpected entry at {}",
                old.display.display()
            );
        }
        for leaf_name in ["bin", "lib"] {
            if old.stat_entry(leaf_name)?.is_none() {
                continue;
            }
            let leaf = old.open_child(leaf_name)?;
            leaf.ensure_empty().with_context(|| {
                format!(
                    "journal-free transaction contains backup bytes at {}",
                    leaf.display.display()
                )
            })?;
            install.ensure_bound()?;
            install.root.ensure_child_binding(name, root)?;
            root.ensure_child_binding("old", &old)?;
            old.ensure_child_binding(leaf_name, &leaf)?;
            old.remove_child_dir(leaf_name)?;
        }
        old.ensure_empty()?;
        install.ensure_bound()?;
        install.root.ensure_child_binding(name, root)?;
        root.ensure_child_binding("old", &old)?;
        root.remove_child_dir("old")?;
    }
    root.ensure_empty()?;
    install.ensure_bound()?;
    install.root.ensure_child_binding(name, root)?;
    install.root.remove_child_dir(name)
}

#[cfg(not(unix))]
fn directory_tree_has_entries(path: &Path) -> Result<bool> {
    match fs::read_dir(path) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                let metadata = fs::symlink_metadata(entry.path())?;
                if metadata.is_dir() {
                    if directory_tree_has_entries(&entry.path())? {
                        return Ok(true);
                    }
                } else {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn cleanup_stale_staging_dirs(lock: &InstallRootLock) -> Result<()> {
    #[cfg(unix)]
    {
        let install = lock.install()?;
        for name in install.root.entry_names()? {
            let Some(id) = name.strip_prefix(STAGING_PREFIX) else {
                continue;
            };
            if uuid::Uuid::parse_str(id).is_err() {
                continue;
            }
            let stat = install
                .root
                .stat_entry(&name)?
                .context("staging directory disappeared during cleanup")?;
            if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory
            {
                anyhow::bail!(
                    "refusing unsafe staging path {}/{}",
                    install.root.display.display(),
                    name
                );
            }
            let root = install.root.open_child(&name)?;
            cleanup_staging_tree_at(install, &name, &root)?;
        }
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        let kin_home = lock.root();
        for entry in fs::read_dir(kin_home)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(id) = name.strip_prefix(STAGING_PREFIX) else {
                continue;
            };
            if uuid::Uuid::parse_str(id).is_err() {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                anyhow::bail!("refusing unsafe staging path {}", entry.path().display());
            }
            durable_remove_dir_all(&entry.path())?;
        }
        Ok(())
    }
}

#[cfg(test)]
fn maybe_crash_at(point: &str) {
    if std::env::var("KIN_UPDATE_TEST_CRASH_POINT").as_deref() == Ok(point) {
        std::process::exit(86);
    }
}

#[cfg(not(test))]
fn maybe_crash_at(_point: &str) {}

/// Fetch the release to install for the requested channel.
///
/// Stable uses the GitHub `releases/latest` endpoint (which never returns a
/// pre-release). Alpha lists releases and picks the newest pre-release.
async fn resolve_release(client: &reqwest::Client, channel: Channel) -> Result<GithubRelease> {
    match channel {
        Channel::Stable => {
            let response = client
                .get(GITHUB_RELEASES_LATEST_URL)
                .send()
                .await
                .context("failed to reach GitHub releases API")?;
            let bytes = read_bounded_response(
                response,
                MAX_RELEASE_METADATA_BYTES,
                "GitHub release metadata",
            )
            .await?;
            let release = serde_json::from_slice(&bytes).context("failed to parse release JSON")?;
            Ok(release)
        }
        Channel::Alpha => {
            let response = client
                .get(GITHUB_RELEASES_LIST_URL)
                .send()
                .await
                .context("failed to reach GitHub releases API")?;
            let bytes = read_bounded_response(
                response,
                MAX_RELEASE_METADATA_BYTES,
                "GitHub releases metadata",
            )
            .await?;
            let releases: Vec<GithubRelease> =
                serde_json::from_slice(&bytes).context("failed to parse releases JSON")?;
            select_alpha(releases)?.context(
                "no pre-release build is available on the alpha channel yet. \
                 See https://github.com/firelock-ai/kin/releases",
            )
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum GitObjectStep {
    ResolvedCommit(String),
    FetchAnnotatedTag(String),
}

fn inspect_git_object(
    object: GithubGitObject,
    seen: &mut HashSet<String>,
    depth: usize,
) -> Result<GitObjectStep> {
    let sha = parse_expected_commit_sha(&object.sha).map_err(anyhow::Error::msg)?;
    if !seen.insert(sha.clone()) {
        anyhow::bail!("release tag object chain contains a cycle at {sha}");
    }
    match object.kind.as_str() {
        "commit" => Ok(GitObjectStep::ResolvedCommit(sha)),
        "tag" if depth < MAX_ANNOTATED_TAG_DEPTH => Ok(GitObjectStep::FetchAnnotatedTag(sha)),
        "tag" => anyhow::bail!(
            "release tag exceeds the maximum annotated-tag depth of {MAX_ANNOTATED_TAG_DEPTH}"
        ),
        other => anyhow::bail!(
            "release tag resolves to unsupported Git object type '{other}', expected tag or commit"
        ),
    }
}

async fn fetch_git_object(
    client: &reqwest::Client,
    url: String,
    label: &str,
) -> Result<GithubGitObject> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to resolve {label}"))?;
    let bytes = read_bounded_response(response, MAX_GIT_OBJECT_BYTES, label).await?;
    let envelope: GithubGitObjectEnvelope = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {label} Git object"))?;
    Ok(envelope.object)
}

/// Resolve a lightweight or annotated release tag to its final commit. The
/// release API's `target_commitish` is not authoritative for annotated tags,
/// so updater automation always peels the Git object chain itself.
async fn resolve_release_commit(client: &reqwest::Client, release_tag: &str) -> Result<String> {
    let version = parse_release_version(release_tag)?;
    let canonical_tag = format!("v{version}");
    if release_tag != canonical_tag {
        anyhow::bail!(
            "release tag '{release_tag}' is not the canonical version tag '{canonical_tag}'"
        );
    }

    let mut object = fetch_git_object(
        client,
        format!("{GITHUB_GIT_REF_TAGS_URL}{release_tag}"),
        &format!("release tag {release_tag}"),
    )
    .await?;
    let mut seen = HashSet::new();
    for depth in 0..=MAX_ANNOTATED_TAG_DEPTH {
        match inspect_git_object(object, &mut seen, depth)? {
            GitObjectStep::ResolvedCommit(sha) => return Ok(sha),
            GitObjectStep::FetchAnnotatedTag(tag_object_sha) => {
                object = fetch_git_object(
                    client,
                    format!("{GITHUB_GIT_TAGS_URL}{tag_object_sha}"),
                    &format!("annotated tag object {tag_object_sha}"),
                )
                .await?;
            }
        }
    }
    unreachable!("annotated-tag depth is bounded by inspect_git_object")
}

/// Select the newest pre-release from a list of releases (highest version wins).
fn select_alpha(releases: Vec<GithubRelease>) -> Result<Option<GithubRelease>> {
    let mut selected: Option<(Version, GithubRelease)> = None;
    for release in releases
        .into_iter()
        .filter(|release| release.prerelease || release.tag_name.contains('-'))
    {
        let version = parse_release_version(&release.tag_name).with_context(|| {
            format!("pre-release tag '{}' is not valid SemVer", release.tag_name)
        })?;
        if selected
            .as_ref()
            .map(|(current, _)| version > *current)
            .unwrap_or(true)
        {
            selected = Some((version, release));
        }
    }
    Ok(selected.map(|(_, release)| release))
}

// ---------------------------------------------------------------------------
// Release asset resolution + checksum verification
//
// Shared by the self-update flow (`run`, above) and the VFS shim repair used
// by `kin doctor --fix` (`download_shim_for_current_version`, below). Every
// published release names archives `kin-{macos|linux|windows}-{aarch64|x86_64}`
// with a `.tar.gz` extension (`.zip` for Windows) and ships a
// `checksums-sha256.txt` manifest — no detached signature — so both flows
// resolve the asset name and verify the download the same way.
// ---------------------------------------------------------------------------

/// Release archive asset name for a given OS/arch pair, e.g.
/// `kin-macos-aarch64.tar.gz` or `kin-windows-x86_64.zip`.
///
/// `os`/`arch` use Rust's own `std::env::consts::OS`/`ARCH` spelling
/// (`"macos"`/`"linux"`/`"windows"`, `"x86_64"`/`"aarch64"`), which already
/// matches the tokens the release pipeline names assets with — no separate
/// translation table needed. Pure and host-independent, so the full platform
/// matrix is directly testable regardless of which platform the test runs on.
fn platform_asset_name(os: &str, arch: &str) -> Result<String> {
    if !matches!(os, "macos" | "linux" | "windows") {
        anyhow::bail!("unsupported OS for release download: {os}");
    }
    if !matches!(arch, "x86_64" | "aarch64") {
        anyhow::bail!("unsupported architecture for release download: {arch}");
    }
    // release.yml packages Windows with PowerShell's Compress-Archive (.zip);
    // every other target ships a .tar.gz.
    let ext = if os == "windows" { "zip" } else { "tar.gz" };
    Ok(format!("kin-{os}-{arch}.{ext}"))
}

/// Exact compiler-target identities emitted by the release matrix. The archive
/// name is the public platform contract; provenance must match both target legs
/// byte-for-byte instead of merely providing non-empty strings.
fn release_target_mapping(artifact: &str) -> Result<(&'static str, &'static str)> {
    match artifact {
        "kin-linux-x86_64" => Ok(("x86_64-unknown-linux-musl", "x86_64-unknown-linux-gnu")),
        "kin-linux-aarch64" => Ok(("aarch64-unknown-linux-musl", "aarch64-unknown-linux-gnu")),
        "kin-macos-x86_64" => Ok(("x86_64-apple-darwin", "x86_64-apple-darwin")),
        "kin-macos-aarch64" => Ok(("aarch64-apple-darwin", "aarch64-apple-darwin")),
        "kin-windows-x86_64" => Ok(("x86_64-pc-windows-msvc", "x86_64-pc-windows-msvc")),
        _ => anyhow::bail!("unsupported release artifact identity '{artifact}'"),
    }
}

fn validate_provenance_target_identity(
    provenance: &ArtifactProvenance,
    expected_artifact: &str,
) -> Result<()> {
    let (expected_target, expected_vfs_target) = release_target_mapping(expected_artifact)?;
    if provenance.artifact != expected_artifact
        || provenance.target != expected_target
        || provenance.vfs_target != expected_vfs_target
    {
        anyhow::bail!(
            "artifact provenance compiler targets do not match release matrix identity '{}'",
            expected_artifact
        );
    }
    Ok(())
}

/// Release archive asset name for the platform this binary is actually
/// running on.
fn current_platform_asset_name() -> Result<String> {
    platform_asset_name(std::env::consts::OS, std::env::consts::ARCH)
}

/// Find the release asset whose name exactly matches `archive_name`.
///
/// Errors name the exact archive that was looked for and list every asset
/// the release actually published, so a platform/naming mismatch is always
/// an honest, actionable failure — never a silent no-match. Matching is
/// exact rather than a substring search: every archive also has an adjacent
/// `<archive>.sha256` asset whose name contains the archive name, which a
/// substring match could resolve instead of the archive itself.
fn find_release_asset<'a>(
    release: &'a GithubRelease,
    archive_name: &str,
) -> Result<&'a GithubAsset> {
    release
        .assets
        .iter()
        .find(|a| a.name == archive_name)
        .with_context(|| {
            let published = release
                .assets
                .iter()
                .map(|a| a.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "no release asset named '{archive_name}' in release '{}'. Published assets: [{published}]",
                release.tag_name
            )
        })
}

/// Download the checksums manifest from the release and verify the archive's
/// SHA-256 against the entry recorded for `archive_name`.
///
/// Checksum-only: no release currently publishes a detached signature, so
/// this is the sole integrity gate for both `kin update` and shim repair. An
/// update must never install unverified bytes.
async fn verify_archive_checksum(
    client: &reqwest::Client,
    release: &GithubRelease,
    archive_name: &str,
    archive_bytes: &[u8],
) -> Result<()> {
    let expected = fetch_archive_checksum(client, release, archive_name).await?;
    verify_sha256(archive_bytes, &expected)
}

/// Resolve the bounded co-published checksum metadata for one exact platform
/// asset without downloading that asset. This is the archive identity exposed
/// by read-only update checks; mutating updates additionally hash owned bytes.
async fn fetch_archive_checksum(
    client: &reqwest::Client,
    release: &GithubRelease,
    archive_name: &str,
) -> Result<String> {
    let checksums_asset = release
        .assets
        .iter()
        .find(|a| a.name == CHECKSUMS_ASSET)
        .with_context(|| {
            format!("release is missing '{CHECKSUMS_ASSET}' — cannot verify the download")
        })?;

    let response = client
        .get(&checksums_asset.browser_download_url)
        .send()
        .await
        .context("failed to download checksums file")?;
    let checksums_bytes =
        read_bounded_response(response, MAX_CHECKSUMS_BYTES, "release checksums").await?;

    let checksums_text =
        std::str::from_utf8(&checksums_bytes).context("checksums file is not valid UTF-8")?;
    let expected = parse_checksum(checksums_text, archive_name)
        .with_context(|| format!("'{archive_name}' not found in the checksums file"))?;
    parse_expected_archive_sha256(&expected).map_err(anyhow::Error::msg)
}

/// Compare the SHA-256 of `archive_bytes` against an `expected_hash_hex`
/// already looked up from a checksums file.
///
/// Pure and network-free so the checksum-mismatch failure mode is directly
/// testable without a mock server.
fn verify_sha256(archive_bytes: &[u8], expected_hash_hex: &str) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(archive_bytes);
    let actual = hex::encode(hasher.finalize());
    let expected = expected_hash_hex.to_lowercase();

    if actual != expected {
        anyhow::bail!(
            "SHA-256 MISMATCH.\n\
             Expected: {expected}\n\
             Got:      {actual}\n\
             The downloaded archive does not match the published checksum.\n\
             This could indicate a corrupted download or tampered release. Aborting."
        );
    }
    Ok(())
}

/// Parse a `sha256sum`-style checksums file and return the hash for `filename`.
///
/// Format: `<hex-hash>  <filename>` (two spaces, matching coreutils sha256sum output).
fn parse_checksum(checksums_text: &str, filename: &str) -> Option<String> {
    for line in checksums_text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Support both "hash  filename" (two spaces) and "hash filename" (one space).
        if let Some((hash, name)) = line.split_once(char::is_whitespace) {
            let name = name.trim();
            if name == filename {
                return Some(hash.to_lowercase());
            }
        }
    }
    None
}

fn artifact_name_from_archive(archive_name: &str) -> Result<&str> {
    archive_name
        .strip_suffix(".tar.gz")
        .or_else(|| archive_name.strip_suffix(".zip"))
        .with_context(|| format!("unsupported release archive name '{archive_name}'"))
}

async fn fetch_artifact_provenance(
    client: &reqwest::Client,
    release: &GithubRelease,
    archive: &GithubAsset,
) -> Result<ArtifactProvenance> {
    let artifact = artifact_name_from_archive(&archive.name)?;
    let provenance_name = format!("{artifact}.provenance.json");
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == provenance_name)
        .with_context(|| {
            format!(
                "release '{}' is missing required provenance asset '{provenance_name}'",
                release.tag_name
            )
        })?;
    let response = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("failed to download artifact provenance")?;
    let bytes =
        read_bounded_response(response, MAX_PROVENANCE_BYTES, "artifact provenance").await?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("'{provenance_name}' is not valid provenance JSON"))
}

fn validate_artifact_provenance(
    provenance: &ArtifactProvenance,
    release: &GithubRelease,
    release_commit_sha: &str,
    archive: &GithubAsset,
    archive_bytes: &[u8],
    stage_root: &Path,
    spec: &[ComponentSpec],
    verify_hashes: bool,
) -> Result<VerifiedStagedIdentities> {
    let verified_identities = validate_artifact_provenance_metadata(
        provenance,
        release,
        release_commit_sha,
        archive,
        archive_bytes,
        spec,
        verify_hashes,
    )?;
    validate_archive_payload_provenance_and_static_identity(
        archive_bytes,
        &archive.name,
        spec,
        &verified_identities,
        provenance,
    )?;
    validate_staged_artifact_provenance(stage_root, spec, &verified_identities, verify_hashes)?;
    Ok(verified_identities)
}

/// Validate every provenance claim that does not depend on extracted files.
/// This is intentionally usable before KIN_HOME is locked or staged so pinned
/// automation can authenticate the remote release without local side effects.
fn validate_artifact_provenance_metadata(
    provenance: &ArtifactProvenance,
    release: &GithubRelease,
    release_commit_sha: &str,
    archive: &GithubAsset,
    archive_bytes: &[u8],
    spec: &[ComponentSpec],
    verify_hashes: bool,
) -> Result<VerifiedStagedIdentities> {
    if provenance.schema_version != 2 {
        anyhow::bail!(
            "unsupported artifact provenance schema {}",
            provenance.schema_version
        );
    }
    let release_version = parse_release_version(&release.tag_name)?;
    let manifest_version = parse_release_version(&provenance.release_tag)?;
    if release_version != manifest_version {
        anyhow::bail!(
            "artifact provenance release '{}' does not match selected release '{}'",
            provenance.release_tag,
            release.tag_name
        );
    }
    let expected_artifact = artifact_name_from_archive(&archive.name)?;
    if provenance.archive.name != archive.name {
        anyhow::bail!(
            "artifact provenance identity does not match '{}'",
            archive.name
        );
    }
    validate_provenance_target_identity(provenance, expected_artifact)?;
    if archive_bytes.len() > RELEASE_ARCHIVE_LIMITS.compressed_bytes {
        anyhow::bail!(
            "artifact provenance archive exceeds the compressed-size limit of {} bytes",
            RELEASE_ARCHIVE_LIMITS.compressed_bytes
        );
    }
    if provenance.archive.size_bytes != archive_bytes.len() as u64 {
        anyhow::bail!("artifact provenance archive size does not match downloaded bytes");
    }
    validate_hex(&provenance.archive.sha256, 64, "archive SHA-256")?;
    if verify_hashes {
        verify_sha256(archive_bytes, &provenance.archive.sha256)
            .context("artifact provenance archive hash mismatch")?;
    }

    validate_hex(&provenance.kin.commit, 40, "Kin commit")?;
    if provenance.kin.commit != release_commit_sha {
        anyhow::bail!(
            "artifact provenance Kin commit {} does not match release tag commit {release_commit_sha}",
            provenance.kin.commit
        );
    }
    validate_hex(
        &provenance.kin.cargo_lock_sha256,
        64,
        "Kin Cargo.lock SHA-256",
    )?;
    validate_hex(
        &provenance.kin.embedded_dependency_provenance,
        64,
        "embedded dependency provenance",
    )?;
    if provenance.kin.cargo_lock_sha256 != provenance.kin.embedded_dependency_provenance {
        anyhow::bail!("artifact provenance dependency identity is internally inconsistent");
    }
    validate_hex(&provenance.kin_vfs.commit, 40, "kin-vfs commit")?;
    validate_hex(
        &provenance.kin_vfs.cargo_lock_sha256,
        64,
        "kin-vfs Cargo.lock SHA-256",
    )?;
    if provenance.kin_vfs.dirty {
        anyhow::bail!("artifact provenance identifies a dirty kin-vfs build");
    }

    let (cli_name, daemon_name) = static_identity_component_names(spec)?;

    let mut verified_identities = VerifiedStagedIdentities::new();
    let mut static_graph_version = None;
    for record in &provenance.archive_contents {
        validate_hex(
            &record.sha256,
            64,
            &format!("component '{}' SHA-256", record.name),
        )?;
        if !spec
            .iter()
            .any(|component| component.name == record.name.as_str())
        {
            anyhow::bail!(
                "artifact provenance inventory contains file '{}' outside the managed platform bundle",
                record.name
            );
        }
        if verified_identities
            .insert(
                record.name.clone(),
                FileIdentity {
                    sha256: record.sha256.to_lowercase(),
                    size_bytes: record.size_bytes,
                },
            )
            .is_some()
        {
            anyhow::bail!(
                "artifact provenance contains duplicate component '{}'",
                record.name
            );
        }
        let requires_build_identity = record.name == cli_name || record.name == daemon_name;
        match (&record.build_identity, requires_build_identity) {
            (Some(identity), true) => {
                validate_static_build_identity_claim(
                    identity,
                    &release_version,
                    &provenance.kin,
                    &record.name,
                )?;
                if let Some(expected) = static_graph_version {
                    if expected != identity.graph_snapshot_version {
                        anyhow::bail!(
                            "CLI and daemon static build identities disagree on graph snapshot version"
                        );
                    }
                } else {
                    static_graph_version = Some(identity.graph_snapshot_version);
                }
            }
            (None, true) => anyhow::bail!(
                "artifact provenance is missing static build identity for '{}'",
                record.name
            ),
            (Some(_), false) => anyhow::bail!(
                "artifact provenance carries a static build identity for non-authority component '{}'",
                record.name
            ),
            (None, false) => {}
        }
    }
    for component in spec.iter().filter(|component| component.required) {
        if !verified_identities.contains_key(component.name) {
            anyhow::bail!(
                "artifact provenance is missing required component '{}'",
                component.name
            );
        }
    }
    validate_archive_inventory_limits(&verified_identities, RELEASE_ARCHIVE_LIMITS)?;
    Ok(verified_identities)
}

fn validate_staged_artifact_provenance(
    stage_root: &Path,
    spec: &[ComponentSpec],
    provenance_identities: &VerifiedStagedIdentities,
    verify_hashes: bool,
) -> Result<()> {
    let mut staged_components = HashSet::new();
    for component in spec {
        let path = component_path(stage_root, *component);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    anyhow::bail!(
                        "staged provenance input is not a regular non-symlink file: {}",
                        path.display()
                    );
                }
                let identity = provenance_identities.get(component.name).with_context(|| {
                    format!(
                        "artifact provenance is missing staged component '{}'",
                        component.name
                    )
                })?;
                if identity.size_bytes != metadata.len() {
                    anyhow::bail!(
                        "artifact provenance size mismatch for component '{}'",
                        component.name
                    );
                }
                if verify_hashes && sha256_file(&path)? != identity.sha256 {
                    anyhow::bail!(
                        "artifact provenance hash mismatch for component '{}'",
                        component.name
                    );
                }
                staged_components.insert(component.name);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err).context("failed to inspect staged provenance input"),
        }
    }
    if provenance_identities.len() != staged_components.len() {
        anyhow::bail!(
            "artifact provenance inventory does not exactly match the staged platform bundle"
        );
    }
    Ok(())
}

fn validate_hex(value: &str, length: usize, label: &str) -> Result<()> {
    if value.len() != length || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("{label} is not a {length}-character hexadecimal identity");
    }
    Ok(())
}

const STATIC_BUILD_IDENTITY_SCHEMA: &str = "kin.update-build.v1";
const STATIC_BUILD_IDENTITY_SENTINEL_BYTES: usize = 198;

fn static_identity_component_names(spec: &[ComponentSpec]) -> Result<(&'static str, &'static str)> {
    fn exactly_one(
        spec: &[ComponentSpec],
        candidates: &[&str],
        label: &str,
    ) -> Result<&'static str> {
        let mut matches = spec
            .iter()
            .filter(|component| candidates.contains(&component.name))
            .map(|component| component.name);
        let name = matches
            .next()
            .with_context(|| format!("platform bundle contract is missing the {label}"))?;
        if matches.next().is_some() {
            anyhow::bail!("platform bundle contract contains multiple {label} components");
        }
        Ok(name)
    }

    Ok((
        exactly_one(spec, &["kin", "kin.exe"], "CLI build identity")?,
        exactly_one(
            spec,
            &["kin-daemon", "kin-daemon.exe"],
            "daemon build identity",
        )?,
    ))
}

fn decode_static_build_identity_magic(encoded: [u8; 16]) -> [u8; 16] {
    // `black_box` prevents the updater parser's marker from being folded into
    // a second literal copy inside the Kin CLI binary that it must scan.
    let mask = std::hint::black_box(0xa5_u8);
    let mut decoded = [0_u8; 16];
    for (output, input) in decoded.iter_mut().zip(encoded) {
        *output = input ^ mask;
    }
    decoded
}

fn parse_static_identity_ascii(field: &[u8], label: &str) -> Result<String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if end == 0 {
        anyhow::bail!("static build identity {label} is empty");
    }
    if field[end..].iter().any(|byte| *byte != 0) {
        anyhow::bail!("static build identity {label} has nonzero padding");
    }
    if field[..end].iter().any(|byte| !byte.is_ascii_graphic()) {
        anyhow::bail!("static build identity {label} is not canonical ASCII");
    }
    Ok(std::str::from_utf8(&field[..end])
        .with_context(|| format!("static build identity {label} is not UTF-8"))?
        .to_string())
}

fn parse_static_build_identity(bytes: &[u8]) -> Result<StaticBuildIdentity> {
    if bytes.len() as u64 > MAX_ARCHIVE_ENTRY_BYTES {
        anyhow::bail!(
            "candidate component exceeds the {MAX_ARCHIVE_ENTRY_BYTES}-byte static scan limit"
        );
    }
    let start = decode_static_build_identity_magic([
        165, 44, 238, 236, 235, 240, 245, 225, 228, 241, 224, 164, 168, 175, 191, 175,
    ]);
    let end = decode_static_build_identity_magic([
        165, 44, 238, 236, 235, 224, 235, 225, 243, 148, 90, 164, 168, 175, 191, 175,
    ]);
    let mut found = None;
    let mut count = 0_usize;
    for (offset, window) in bytes.windows(start.len()).enumerate() {
        if window == start {
            count += 1;
            found.get_or_insert(offset);
            if count > 1 {
                break;
            }
        }
    }
    if count != 1 {
        anyhow::bail!(
            "candidate component contains {count} static build identity sentinels; expected exactly one"
        );
    }
    let offset = found.context("static build identity offset disappeared")?;
    let sentinel = bytes
        .get(offset..offset + STATIC_BUILD_IDENTITY_SENTINEL_BYTES)
        .context("candidate component contains a truncated static build identity sentinel")?;
    if sentinel[182..198] != end {
        anyhow::bail!("candidate component static build identity end marker is invalid");
    }
    let schema = parse_static_identity_ascii(&sentinel[16..40], "schema")?;
    let version = parse_static_identity_ascii(&sentinel[40..72], "version")?;
    parse_release_version(&version).context("invalid static build identity version")?;
    let commit = parse_static_identity_ascii(&sentinel[72..112], "commit")?.to_lowercase();
    validate_hex(&commit, 40, "static build identity commit")?;
    let clean = match sentinel[112] {
        0 => false,
        1 => true,
        _ => anyhow::bail!("static build identity clean flag is not canonical"),
    };
    let source_known = match sentinel[113] {
        0 => false,
        1 => true,
        _ => anyhow::bail!("static build identity source-known flag is not canonical"),
    };
    let dependency_provenance =
        parse_static_identity_ascii(&sentinel[114..178], "dependency provenance")?.to_lowercase();
    validate_hex(
        &dependency_provenance,
        64,
        "static build identity dependency provenance",
    )?;
    let graph_snapshot_version =
        u32::from_le_bytes(sentinel[178..182].try_into().expect("fixed static field"));
    if graph_snapshot_version == 0 {
        anyhow::bail!("static build identity graph snapshot version must be nonzero");
    }
    if schema != STATIC_BUILD_IDENTITY_SCHEMA {
        anyhow::bail!("unsupported static build identity schema '{schema}'");
    }
    Ok(StaticBuildIdentity {
        schema,
        version,
        commit,
        clean,
        source_known,
        dependency_provenance,
        graph_snapshot_version,
    })
}

fn validate_static_build_identity_claim(
    identity: &StaticBuildIdentity,
    expected_version: &Version,
    provenance: &KinProvenance,
    component: &str,
) -> Result<()> {
    if identity.schema != STATIC_BUILD_IDENTITY_SCHEMA {
        anyhow::bail!("component '{component}' has an unsupported static build identity schema");
    }
    if parse_release_version(&identity.version)? != *expected_version {
        anyhow::bail!("component '{component}' static build version does not match the release");
    }
    if identity.commit.to_lowercase() != provenance.commit.to_lowercase() {
        anyhow::bail!("component '{component}' static build commit does not match provenance");
    }
    if !identity.clean || !identity.source_known {
        anyhow::bail!("component '{component}' does not carry a clean known static build identity");
    }
    if identity.dependency_provenance.to_lowercase()
        != provenance.embedded_dependency_provenance.to_lowercase()
    {
        anyhow::bail!(
            "component '{component}' static dependency provenance does not match release provenance"
        );
    }
    if identity.graph_snapshot_version == 0 {
        anyhow::bail!("component '{component}' has no graph snapshot compatibility identity");
    }
    Ok(())
}

fn validate_staged_static_build_identity(
    stage_root: &Path,
    spec: &[ComponentSpec],
    expected_version: &str,
    provenance: &ArtifactProvenance,
) -> Result<()> {
    let (cli_name, daemon_name) = static_identity_component_names(spec)?;
    let expected_version = parse_release_version(expected_version)?;
    let mut graph_version = None;
    for name in [cli_name, daemon_name] {
        let component = spec
            .iter()
            .copied()
            .find(|component| component.name == name)
            .with_context(|| format!("platform bundle contract has no '{name}' component"))?;
        let record = provenance
            .archive_contents
            .iter()
            .find(|record| record.name == name)
            .with_context(|| format!("artifact provenance has no '{name}' component"))?;
        let expected_identity = record
            .build_identity
            .as_ref()
            .with_context(|| format!("artifact provenance has no static identity for '{name}'"))?;
        let path = component_path(stage_root, component);
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_ARCHIVE_ENTRY_BYTES
        {
            anyhow::bail!(
                "staged static identity input is not a bounded regular file: {}",
                path.display()
            );
        }
        let mut file = File::open(&path)?;
        let bytes = read_bounded_archive_entry(
            &mut file,
            metadata.len(),
            MAX_ARCHIVE_ENTRY_BYTES,
            &format!("staged component '{name}'"),
        )?;
        let actual_file = FileIdentity {
            sha256: hex::encode(Sha256::digest(&bytes)),
            size_bytes: bytes.len() as u64,
        };
        if actual_file.sha256 != record.sha256.to_lowercase()
            || actual_file.size_bytes != record.size_bytes
        {
            anyhow::bail!("staged component '{name}' changed before static identity validation");
        }
        let actual_identity = parse_static_build_identity(&bytes)?;
        if &actual_identity != expected_identity {
            anyhow::bail!("staged component '{name}' static identity does not match provenance");
        }
        validate_static_build_identity_claim(
            &actual_identity,
            &expected_version,
            &provenance.kin,
            name,
        )?;
        if let Some(expected) = graph_version {
            if expected != actual_identity.graph_snapshot_version {
                anyhow::bail!("staged CLI and daemon graph snapshot identities disagree");
            }
        } else {
            graph_version = Some(actual_identity.graph_snapshot_version);
        }
    }
    Ok(())
}
fn runtime_component_matches(kind: RuntimeKind, name: &str) -> bool {
    match kind {
        RuntimeKind::Daemon => matches!(name, "kin-daemon" | "kin-daemon.exe"),
        RuntimeKind::Mcp => matches!(name, "kin" | "kin.exe" | "kin-mcp" | "kin-mcp.exe"),
        RuntimeKind::Vfs => matches!(name, "kin-vfs" | "kin-vfs.exe"),
    }
}

fn canonical_runtime_component(spec: &[ComponentSpec], kind: RuntimeKind) -> Result<&'static str> {
    let wanted = match kind {
        RuntimeKind::Daemon => ["kin-daemon", "kin-daemon.exe"].as_slice(),
        RuntimeKind::Mcp => ["kin", "kin.exe"].as_slice(),
        RuntimeKind::Vfs => ["kin-vfs", "kin-vfs.exe"].as_slice(),
    };
    spec.iter()
        .find(|component| wanted.contains(&component.name))
        .map(|component| component.name)
        .with_context(|| format!("release bundle has no managed {} runtime", kind.label()))
}

fn normalized_process_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    let path = PathBuf::from(text.strip_suffix(" (deleted)").unwrap_or(&text));
    path.canonicalize().unwrap_or(path)
}

fn transaction_component_path_matches(
    executable: &Path,
    kin_home: &Path,
    component: ComponentSpec,
) -> bool {
    let executable = normalized_process_path(executable);
    let kin_home = normalized_process_path(kin_home);
    let Ok(relative) = executable.strip_prefix(&kin_home) else {
        return false;
    };
    let parts = relative
        .components()
        .map(|part| part.as_os_str())
        .collect::<Vec<_>>();
    let location = match component.location {
        ComponentLocation::Bin => "bin",
        ComponentLocation::Lib => "lib",
    };
    parts.len() == 4
        && parts[0].to_str().is_some_and(|name| {
            name.strip_prefix(TRANSACTION_PREFIX)
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
        })
        && parts[1] == "old"
        && parts[2] == location
        && parts[3] == component.name
}

fn process_path_matches_component(
    _pid: u32,
    executable: &Path,
    managed: &Path,
    kin_home: &Path,
    component: ComponentSpec,
) -> bool {
    if normalized_process_path(executable) == normalized_process_path(managed)
        || transaction_component_path_matches(executable, kin_home, component)
    {
        return true;
    }
    #[cfg(target_os = "linux")]
    if let Ok(mapped) = fs::read_link(format!("/proc/{_pid}/exe")) {
        return normalized_process_path(&mapped) == normalized_process_path(managed)
            || transaction_component_path_matches(&mapped, kin_home, component);
    }
    false
}

fn argv0_matches_component(
    command: &[String],
    cwd: Option<&Path>,
    managed: &Path,
    kin_home: &Path,
    component: ComponentSpec,
) -> bool {
    let Some(argv0) = command.first().map(PathBuf::from) else {
        return false;
    };
    let candidate = if argv0.is_absolute() {
        argv0
    } else if let Some(cwd) = cwd {
        cwd.join(argv0)
    } else {
        return false;
    };
    normalized_process_path(&candidate) == normalized_process_path(managed)
        || transaction_component_path_matches(&candidate, kin_home, component)
}

fn command_requests_help_or_version(command: &[String]) -> bool {
    command
        .iter()
        .skip(1)
        .any(|argument| matches!(argument.as_str(), "-h" | "--help" | "-V" | "--version"))
}

fn is_managed_serving_process(kind: RuntimeKind, component_name: &str, command: &[String]) -> bool {
    if command_requests_help_or_version(command) {
        return false;
    }
    match kind {
        RuntimeKind::Daemon => true,
        RuntimeKind::Mcp => {
            matches!(component_name, "kin-mcp" | "kin-mcp.exe")
                || command_has_adjacent(command, "mcp", "start")
        }
        RuntimeKind::Vfs => true,
    }
}

struct RuntimeExecutableDiagnostic {
    path: PathBuf,
    identity: FileIdentity,
    object: PlatformObjectIdentity,
    scope: &'static str,
}

fn runtime_executable_diagnostic_scope() -> &'static str {
    if cfg!(target_os = "linux") {
        "mapped executable object"
    } else if cfg!(target_os = "macos") {
        "current object at the reported executable pathname; the process-mapped Mach vnode is not inferred from that pathname"
    } else {
        "current object at the reported executable pathname"
    }
}

fn runtime_executable_diagnostic(
    pid: u32,
    executable: &Path,
) -> Result<RuntimeExecutableDiagnostic> {
    #[cfg(target_os = "linux")]
    let identity_path = PathBuf::from(format!("/proc/{pid}/exe"));
    #[cfg(not(target_os = "linux"))]
    let identity_path = executable.to_path_buf();
    let file = File::open(&identity_path).with_context(|| {
        format!(
            "failed to open mapped executable for runtime PID {pid} at {}",
            identity_path.display()
        )
    })?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "failed to inspect mapped executable for runtime PID {pid} at {}",
            identity_path.display()
        )
    })?;
    if !metadata.is_file() {
        anyhow::bail!("runtime PID {pid} mapped executable is not a regular file");
    }
    #[cfg(unix)]
    let object = {
        use std::os::unix::fs::MetadataExt as _;
        PlatformObjectIdentity {
            namespace: metadata.dev(),
            file: metadata.ino(),
        }
    };
    #[cfg(not(unix))]
    let object = PlatformObjectIdentity {
        namespace: 0,
        #[cfg(windows)]
        file: WindowsFileId::zero(),
        #[cfg(not(windows))]
        file: 0,
    };
    Ok(RuntimeExecutableDiagnostic {
        path: fs::read_link(&identity_path).unwrap_or_else(|_| executable.to_path_buf()),
        identity: file_identity_from_open_file(
            &file,
            "managed runtime executable diagnostic object",
        )?,
        object,
        scope: runtime_executable_diagnostic_scope(),
    })
}

fn reject_active_managed_runtime(
    system: &System,
    kin_home: &Path,
    spec: &[ComponentSpec],
    kind: RuntimeKind,
    component_name: &str,
) -> Result<()> {
    let component = spec
        .iter()
        .find(|component| component.name == component_name)
        .with_context(|| format!("managed {} runtime component is missing", kind.label()))?;
    let managed_path = component_path(kin_home, *component);
    let managed = managed_path.canonicalize().unwrap_or(managed_path);
    for (pid, process) in system.processes() {
        let pid = pid.as_u32();
        let command = process_command(process);
        let matched =
            process.exe().is_some_and(|executable| {
                process_path_matches_component(pid, executable, &managed, kin_home, *component)
            }) || argv0_matches_component(&command, process.cwd(), &managed, kin_home, *component);
        if !matched || !is_managed_serving_process(kind, component_name, &command) {
            continue;
        }
        let executable = process.exe().with_context(|| {
            format!(
                "active managed {} PID {pid} has no observable mapped executable path",
                kind.label()
            )
        })?;
        let evidence = runtime_executable_diagnostic(pid, executable).with_context(|| {
            format!(
                "cannot capture fail-closed executable diagnostics for active managed {} PID {pid}",
                kind.label()
            )
        })?;
        anyhow::bail!(
            "active managed {} PID {pid} reports executable {} ({}: {}, object {}:{}, {} bytes, SHA-256 {}); stop it before self-update. This diagnostic never authorizes runtime convergence",
            kind.label(),
            managed.display(),
            evidence.scope,
            evidence.path.display(),
            evidence.object.namespace,
            evidence.object.file,
            evidence.identity.size_bytes,
            evidence.identity.sha256
        );
    }
    Ok(())
}

fn ensure_no_active_managed_runtimes(kin_home: &Path, spec: &[ComponentSpec]) -> Result<()> {
    for pass in 0..3 {
        let mut system = System::new_all();
        system.refresh_all();
        for kind in [RuntimeKind::Daemon, RuntimeKind::Mcp, RuntimeKind::Vfs] {
            for component in spec
                .iter()
                .filter(|component| runtime_component_matches(kind, component.name))
            {
                reject_active_managed_runtime(&system, kin_home, spec, kind, component.name)?;
            }
        }
        if pass != 2 {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    Ok(())
}

fn restart_pending_record(
    kin_home: &Path,
    version: &str,
    provenance: &ArtifactProvenance,
    staged: &VerifiedStagedIdentities,
    spec: &[ComponentSpec],
) -> Result<RestartPending> {
    ensure_no_active_managed_runtimes(kin_home, spec).context(
        "a managed serving executable appeared before update commit; staged bytes remain uninstalled",
    )?;
    let mut runtime_obligations = Vec::new();
    for kind in [RuntimeKind::Daemon, RuntimeKind::Mcp, RuntimeKind::Vfs] {
        let component = canonical_runtime_component(spec, kind)?;
        let expected_identity = staged.get(component).cloned().with_context(|| {
            format!(
                "release bundle has no staged identity for managed {} runtime component {component}",
                kind.label()
            )
        })?;
        runtime_obligations.push(RuntimeRestartObligation {
            kind,
            component: component.to_string(),
            expected_identity,
            prior_sessions: Vec::new(),
        });
    }
    let now = chrono::Utc::now();
    Ok(RestartPending {
        schema_version: RESTART_MARKER_SCHEMA_VERSION,
        installed_version: version.to_string(),
        kin_commit: provenance.kin.commit.clone(),
        dependency_provenance: provenance.kin.embedded_dependency_provenance.clone(),
        kin_vfs_commit: provenance.kin_vfs.commit.clone(),
        recorded_at: now.to_rfc3339(),
        recorded_at_unix_seconds: now.timestamp().max(0) as u64,
        commit_runtime_fence: None,
        reason: RESTART_FENCE_REASON.to_string(),
        runtime_obligations,
    })
}

fn capture_runtime_commit_fence(
    record: &RestartPending,
    kin_home: &Path,
    spec: &[ComponentSpec],
) -> Result<Vec<RuntimeCommitIdentity>> {
    ensure_no_active_managed_runtimes(kin_home, spec).context(
        "update is already durably committed, but a managed serving executable appeared in the commit-time race window; stop it and rerun `kin update` so retained recovery can finish",
    )?;
    let first = snapshot_managed_bundle_generation(kin_home, spec)?;
    let confirmed = snapshot_managed_bundle_generation(kin_home, spec)?;
    if first != confirmed {
        anyhow::bail!(
            "managed Kin bundle changed while the post-commit runtime identity fence was captured"
        );
    }

    let mut identities = Vec::with_capacity(record.runtime_obligations.len());
    for obligation in &record.runtime_obligations {
        let component = spec
            .iter()
            .find(|component| component.name == obligation.component)
            .with_context(|| {
                format!(
                    "{} runtime component '{}' is not managed on this platform",
                    obligation.kind.label(),
                    obligation.component
                )
            })?;
        let generation = confirmed
            .components
            .get(&obligation.component)
            .and_then(Option::as_ref)
            .with_context(|| {
                format!(
                    "managed {} runtime component '{}' is missing after commit",
                    obligation.kind.label(),
                    obligation.component
                )
            })?;
        if generation.identity != obligation.expected_identity {
            anyhow::bail!(
                "managed {} runtime bytes do not match the committed release identity",
                obligation.kind.label()
            );
        }
        identities.push(RuntimeCommitIdentity {
            kind: obligation.kind,
            component: obligation.component.clone(),
            path: component_path(&confirmed.root, *component),
            identity: generation.identity.clone(),
            object: generation.binding.clone(),
        });
    }
    identities.sort_by_key(|identity| identity.kind.label());
    Ok(identities)
}

fn mark_restart_record_committed(
    record: &mut RestartPending,
    kin_home: &Path,
    spec: &[ComponentSpec],
) -> Result<()> {
    validate_restart_record_schema(record)?;
    if record.schema_version == RESTART_MARKER_SCHEMA_VERSION {
        record.commit_runtime_fence = Some(capture_runtime_commit_fence(record, kin_home, spec)?);
    }
    let now = chrono::Utc::now();
    record.recorded_at = now.to_rfc3339();
    record.recorded_at_unix_seconds = now.timestamp().max(0) as u64;
    Ok(())
}

fn restart_pending_path(kin_home: &Path) -> PathBuf {
    kin_home.join(RESTART_ACK_REQUIRED_FILE)
}

fn refuse_restart_marker_before_remote_preflight(kin_home: &Path) -> Result<()> {
    let path = restart_pending_path(kin_home);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => anyhow::bail!(
            "a runtime restart acknowledgement path already exists at {}; refusing pinned remote preflight before any install lock or managed-directory mutation",
            path.display()
        ),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect runtime restart acknowledgement path {} without following links; refusing pinned remote preflight before local mutation",
                path.display()
            )
        }),
    }
}

fn refuse_new_update_while_restart_marker_exists(lock: &InstallRootLock) -> Result<()> {
    #[cfg(unix)]
    let present = lock
        .install()?
        .root
        .stat_entry(RESTART_ACK_REQUIRED_FILE)?
        .is_some();
    #[cfg(windows)]
    let present = {
        let path = restart_pending_path(lock.root());
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error)
                    .context("failed to inspect restart acknowledgement marker path")
            }
            Ok(_) => match LockedPrivateMarker::open(
                &path,
                "runtime restart acknowledgement marker",
            ) {
                Ok(Some(_marker)) => {
                    anyhow::bail!(
                        "a runtime restart acknowledgement marker already exists at {}; refusing a newer update before recovery, cleanup, MCP repair, channel persistence, staging, or live-bundle mutation. Acknowledge it with `kin update --ack-restart` first; malformed, unsupported, and non-regular markers are retained exactly",
                        path.display()
                    )
                }
                Ok(None) => {
                    anyhow::bail!(
                        "restart acknowledgement marker changed while exact authority was acquired; refusing update"
                    )
                }
                Err(error) => {
                    return Err(error).context(
                        "a restart acknowledgement path exists or is inaccessible, malformed, unsupported, or unsafe; refusing update before local mutation and retaining it exactly",
                    )
                }
            },
        }
    };
    #[cfg(all(not(unix), not(windows)))]
    let present = match fs::symlink_metadata(restart_pending_path(lock.root())) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error).context("failed to inspect restart acknowledgement marker")
        }
    };
    if present {
        anyhow::bail!(
            "a runtime restart acknowledgement marker already exists at {}; refusing a newer update before recovery, cleanup, MCP repair, channel persistence, staging, or live-bundle mutation. Acknowledge it with `kin update --ack-restart` first; malformed, unsupported, and non-regular markers are retained exactly",
            restart_pending_path(lock.root()).display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_marker_absent_or_identical(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    let lock = crate::commands::setup::ConfigLock::acquire_nofollow(path)?;
    let original = lock.original_bytes(path)?;
    if let Some(original) = original {
        #[cfg(windows)]
        {
            let existing_label = format!("existing {label}");
            let (file, exact) = open_windows_private_marker(path, &existing_label)?
                .with_context(|| format!("existing {label} disappeared"))?;
            if exact != original {
                anyhow::bail!("existing {label} disagrees with its retained handle");
            }
            if exact != bytes {
                anyhow::bail!(
                    "{label} already exists with different bytes; existing object retained without replacement"
                );
            }
            drop(file);
            return Ok(());
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            if original != bytes {
                anyhow::bail!(
                    "{label} already exists with different bytes; existing object retained without replacement"
                );
            }
            return Ok(());
        }
    }

    #[cfg(windows)]
    {
        match windows_update::create_current_user_private_file_for_exact_commit(path) {
            Ok(mut file) => {
                let write_result = (|| -> Result<()> {
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    sync_dir(
                        path.parent()
                            .with_context(|| format!("{label} has no parent"))?,
                    )
                })();
                if let Err(error) = write_result {
                    let partial_label = format!("partial {label}");
                    let cleanup = windows_update::dispose_private_file_handle_exact(
                        &file,
                        path,
                        &partial_label,
                    );
                    return match cleanup {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(error.context(format!(
                            "exact partial-marker cleanup also failed: {cleanup:#}"
                        ))),
                    };
                }
                return Ok(());
            }
            Err(create_error) => {
                let concurrent_label = format!("concurrent {label}");
                if let Some((file, exact)) = open_windows_private_marker(path, &concurrent_label)? {
                    if exact == bytes {
                        drop(file);
                        return Ok(());
                    }
                    anyhow::bail!(
                        "{label} appeared at the create boundary with different bytes; existing object retained without replacement"
                    );
                }
                return Err(create_error)
                    .with_context(|| format!("failed to create {label} exclusively"));
            }
        }
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options.open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        sync_dir(
            path.parent()
                .with_context(|| format!("{label} has no parent"))?,
        )
    }
}

#[cfg(not(unix))]
fn persist_restart_record(kin_home: &Path, record: &RestartPending) -> Result<PathBuf> {
    let path = restart_pending_path(kin_home);
    validate_restart_record_ready(record)?;
    let bytes = serde_json::to_vec_pretty(record).context("failed to serialize restart state")?;
    create_private_marker_absent_or_identical(&path, &bytes, "restart acknowledgement marker")
        .with_context(|| format!("failed to persist restart state {}", path.display()))?;
    Ok(path)
}

fn mcp_repair_pending_path(kin_home: &Path) -> PathBuf {
    kin_home.join(MCP_REPAIR_PENDING_FILE)
}

fn read_existing_mcp_repair_record(lock: &InstallRootLock) -> Result<Option<McpRepairPending>> {
    #[cfg(unix)]
    {
        let install = lock.install()?;
        let Some(_) = install.root.stat_entry(MCP_REPAIR_PENDING_FILE)? else {
            return Ok(None);
        };
        let bytes = install
            .root
            .read_regular(MCP_REPAIR_PENDING_FILE, "MCP repair pending marker")?;
        let identity = bytes_identity(&bytes);
        if install
            .root
            .identity(MCP_REPAIR_PENDING_FILE, "MCP repair pending marker")?
            .as_ref()
            != Some(&identity)
        {
            anyhow::bail!("MCP repair pending marker changed while it was read");
        }
        let record: McpRepairPending = serde_json::from_slice(&bytes)
            .context("invalid or unsupported MCP repair pending marker")?;
        validate_retained_mcp_repair_record(&record)
            .context("unsupported MCP repair pending marker; marker retained")?;
        return Ok(Some(record));
    }
    #[cfg(not(unix))]
    {
        let path = mcp_repair_pending_path(lock.root());
        let Some(marker) = LockedPrivateMarker::open(&path, "MCP repair pending marker")? else {
            return Ok(None);
        };
        let record: McpRepairPending = serde_json::from_slice(&marker.bytes)
            .context("invalid or unsupported MCP repair pending marker")?;
        validate_retained_mcp_repair_record(&record)
            .context("unsupported MCP repair pending marker; marker retained")?;
        Ok(Some(record))
    }
}

fn mcp_repair_pending_record(lock: &InstallRootLock, version: &str) -> Result<McpRepairPending> {
    let mut targets = if let Some(existing) = read_existing_mcp_repair_record(lock)? {
        validate_mcp_repair_record(&existing)?;
        existing.targets
    } else {
        Vec::new()
    };
    targets.extend(crate::commands::setup::current_mcp_repair_targets()?);
    let targets = crate::commands::setup::normalize_mcp_repair_targets(targets)?;
    Ok(McpRepairPending {
        schema_version: MCP_REPAIR_MARKER_SCHEMA_VERSION,
        installed_version: version.to_string(),
        recorded_at: chrono::Utc::now().to_rfc3339(),
        repair_required: !targets.is_empty(),
        targets,
    })
}

#[cfg(not(unix))]
fn persist_mcp_repair_record(kin_home: &Path, record: &McpRepairPending) -> Result<PathBuf> {
    let path = mcp_repair_pending_path(kin_home);
    validate_mcp_repair_record(record)?;
    if !record.repair_required {
        return Ok(path);
    }
    let bytes =
        serde_json::to_vec_pretty(record).context("failed to serialize MCP repair state")?;
    create_private_marker_absent_or_identical(&path, &bytes, "MCP repair pending marker")
        .with_context(|| format!("failed to persist MCP repair state {}", path.display()))?;
    Ok(path)
}

#[cfg(not(unix))]
fn read_restart_record_locked(kin_home: &Path) -> Result<(RestartPending, LockedPrivateMarker)> {
    let path = restart_pending_path(kin_home);
    let marker = LockedPrivateMarker::open(&path, "runtime restart acknowledgement marker")?
        .with_context(|| {
            format!(
                "no runtime restart acknowledgement is pending at {}",
                path.display()
            )
        })?;
    let record = serde_json::from_slice(&marker.bytes)
        .with_context(|| format!("invalid restart acknowledgement marker {}", path.display()))?;
    Ok((record, marker))
}

fn validate_restart_ack_identity(
    record: &RestartPending,
    running_version: &str,
    running_commit: &str,
    dependency_provenance: &str,
) -> Result<()> {
    validate_restart_record_schema(record)?;
    if parse_release_version(&record.installed_version)? != parse_release_version(running_version)?
        || record.kin_commit != running_commit
        || record.dependency_provenance != dependency_provenance
    {
        anyhow::bail!(
            "running Kin identity does not match the release awaiting restart acknowledgement"
        );
    }
    Ok(())
}

fn validate_restart_record_schema(record: &RestartPending) -> Result<()> {
    match record.schema_version {
        2 => {
            if record.commit_runtime_fence.is_some() {
                anyhow::bail!("legacy restart acknowledgement marker has an unknown commit fence");
            }
            Ok(())
        }
        RESTART_MARKER_SCHEMA_VERSION => {
            if record.reason != RESTART_FENCE_REASON {
                anyhow::bail!("restart acknowledgement marker has an invalid process-fence reason");
            }
            if record
                .runtime_obligations
                .iter()
                .any(|obligation| !obligation.prior_sessions.is_empty())
            {
                anyhow::bail!(
                    "restart acknowledgement marker contradicts its stop-before-update process fence"
                );
            }
            if let Some(fence) = &record.commit_runtime_fence {
                let mut kinds = HashSet::new();
                let mut components = HashSet::new();
                for identity in fence {
                    if !identity.path.is_absolute()
                        || !kinds.insert(identity.kind)
                        || !components.insert(identity.component.as_str())
                    {
                        anyhow::bail!(
                            "restart acknowledgement marker has an invalid commit runtime fence"
                        );
                    }
                    validate_hex(
                        &identity.identity.sha256,
                        64,
                        "commit runtime SHA-256",
                    )?;
                    if identity.identity.size_bytes == 0 {
                        anyhow::bail!(
                            "restart acknowledgement marker has an empty commit runtime identity"
                        );
                    }
                    #[cfg(unix)]
                    if identity.object.namespace == 0 || identity.object.file == 0 {
                        anyhow::bail!(
                            "restart acknowledgement marker has an invalid commit runtime object identity"
                        );
                    }
                    #[cfg(windows)]
                    if identity.object.namespace == 0 || identity.object.file.is_zero() {
                        anyhow::bail!(
                            "restart acknowledgement marker has an invalid full Windows commit runtime object identity"
                        );
                    }
                }
            }
            Ok(())
        }
        schema => anyhow::bail!(
            "unsupported restart acknowledgement schema {schema}; the marker was retained. Use the Kin build that created this marker or an evidence-preserving recovery build; do not delete it to bypass pending proof"
        ),
    }
}

fn validate_restart_record_ready(record: &RestartPending) -> Result<()> {
    validate_restart_record_schema(record)?;
    if record.schema_version == RESTART_MARKER_SCHEMA_VERSION
        && record.commit_runtime_fence.is_none()
    {
        anyhow::bail!(
            "restart acknowledgement marker cannot be persisted before its post-commit runtime fence"
        );
    }
    Ok(())
}

fn validate_runtime_commit_fence(
    record: &RestartPending,
    kin_home: &Path,
    spec: &[ComponentSpec],
) -> Result<()> {
    if record.schema_version != RESTART_MARKER_SCHEMA_VERSION {
        return Ok(());
    }
    let fence = record
        .commit_runtime_fence
        .as_ref()
        .context("restart acknowledgement marker has no durable commit runtime fence")?;
    if fence.len() != record.runtime_obligations.len() {
        anyhow::bail!("restart acknowledgement marker has an incomplete commit runtime fence");
    }

    let first = snapshot_managed_bundle_generation(kin_home, spec)?;
    let current = snapshot_managed_bundle_generation(kin_home, spec)?;
    if first != current {
        anyhow::bail!("managed Kin bundle changed while its commit runtime fence was verified");
    }
    for obligation in &record.runtime_obligations {
        let component = spec
            .iter()
            .find(|component| component.name == obligation.component)
            .with_context(|| {
                format!(
                    "{} runtime component '{}' is not managed on this platform",
                    obligation.kind.label(),
                    obligation.component
                )
            })?;
        let expected_path = component_path(&current.root, *component);
        let generation = current
            .components
            .get(&obligation.component)
            .and_then(Option::as_ref)
            .context("managed runtime component is missing while verifying its commit fence")?;
        let captured = fence
            .iter()
            .find(|identity| {
                identity.kind == obligation.kind && identity.component == obligation.component
            })
            .with_context(|| {
                format!(
                    "restart acknowledgement marker has no {} commit identity",
                    obligation.kind.label()
                )
            })?;
        if normalized_process_path(&captured.path) != normalized_process_path(&expected_path)
            || captured.identity != obligation.expected_identity
            || captured.identity != generation.identity
            || captured.object != generation.binding
        {
            anyhow::bail!(
                "managed {} runtime path, inode, or SHA-256 no longer matches the durable commit fence",
                obligation.kind.label()
            );
        }
    }
    Ok(())
}

fn parse_runtime_session_evidence(values: &[String]) -> Result<Vec<RuntimeSessionEvidence>> {
    let mut seen_pids = HashSet::new();
    let mut evidence = Vec::new();
    for value in values {
        let (kind, pid) = value
            .split_once('=')
            .with_context(|| format!("invalid runtime session '{value}'; expected KIND=PID"))?;
        let kind = match kind {
            "daemon" => RuntimeKind::Daemon,
            "mcp" => RuntimeKind::Mcp,
            "vfs" => RuntimeKind::Vfs,
            _ => anyhow::bail!("invalid runtime kind '{kind}'; expected daemon, mcp, or vfs"),
        };
        let pid = pid
            .parse::<u32>()
            .with_context(|| format!("invalid PID in runtime session '{value}'"))?;
        if pid == 0 {
            anyhow::bail!("runtime session PID must be non-zero");
        }
        if !seen_pids.insert(pid) {
            anyhow::bail!("duplicate runtime session PID {pid}");
        }
        evidence.push(RuntimeSessionEvidence { kind, pid });
    }
    Ok(evidence)
}

#[derive(Clone, Debug)]
struct ObservedRuntimeProcess {
    pid: u32,
    start_time: u64,
    executable: Option<PathBuf>,
    executable_identity: Option<FileIdentity>,
    command: Vec<String>,
    binding: Option<PathBuf>,
}

fn process_command(process: &sysinfo::Process) -> Vec<String> {
    process
        .cmd()
        .iter()
        .map(|part| part.to_string_lossy().into_owned())
        .collect()
}

fn command_has_adjacent(command: &[String], first: &str, second: &str) -> bool {
    command
        .windows(2)
        .any(|parts| parts[0] == first && parts[1] == second)
}

fn command_argument<'a>(command: &'a [String], flag: &str) -> Option<&'a str> {
    command
        .windows(2)
        .find(|parts| parts[0] == flag)
        .map(|parts| parts[1].as_str())
}

fn normalize_runtime_binding(value: Option<&str>, cwd: Option<&Path>) -> Option<PathBuf> {
    let path = match value {
        Some(value) => {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                path
            } else {
                cwd?.join(path)
            }
        }
        None => cwd?.to_path_buf(),
    };
    if !path.is_absolute() {
        return None;
    }
    Some(path.canonicalize().unwrap_or(path))
}

fn runtime_binding(kind: RuntimeKind, command: &[String], cwd: Option<&Path>) -> Option<PathBuf> {
    match kind {
        RuntimeKind::Daemon => {
            if command.iter().any(|part| part == "--supervisor")
                && command_argument(command, "--repo").is_none()
            {
                None
            } else {
                normalize_runtime_binding(command_argument(command, "--repo"), cwd)
            }
        }
        RuntimeKind::Mcp => normalize_runtime_binding(command_argument(command, "--repo"), cwd),
        RuntimeKind::Vfs => {
            normalize_runtime_binding(command_argument(command, "--workspace"), cwd)
        }
    }
}

#[cfg(target_os = "linux")]
fn executable_identity_for_process(pid: u32, executable: &Path) -> Result<FileIdentity> {
    let identity_path = PathBuf::from(format!("/proc/{pid}/exe"));
    let _ = executable;

    let metadata = fs::metadata(&identity_path).with_context(|| {
        format!(
            "failed to inspect executable identity for runtime PID {pid} at {}",
            identity_path.display()
        )
    })?;
    if !metadata.is_file() {
        anyhow::bail!(
            "runtime PID {pid} executable is not a regular file: {}",
            identity_path.display()
        );
    }
    Ok(FileIdentity {
        sha256: sha256_file(&identity_path)?,
        size_bytes: metadata.len(),
    })
}

#[cfg(not(target_os = "linux"))]
fn executable_identity_for_process(pid: u32, executable: &Path) -> Result<FileIdentity> {
    let _ = executable;
    anyhow::bail!(
        "runtime PID {pid} mapped executable identity is unavailable on this platform; pathname bytes are not process-image authority"
    )
}

fn runtime_process_serves_kind(kind: RuntimeKind, command: &[String]) -> bool {
    match kind {
        RuntimeKind::Mcp => command_has_adjacent(command, "mcp", "start"),
        RuntimeKind::Daemon => !command.iter().any(|argument| {
            matches!(
                argument.as_str(),
                "--compat-json" | "--help" | "-h" | "--version" | "-V"
            )
        }),
        RuntimeKind::Vfs => command
            .iter()
            .any(|argument| matches!(argument.as_str(), "start" | "mount" | "nfs-start")),
    }
}

fn observe_runtime_sessions(
    record: &RestartPending,
    evidence: &[RuntimeSessionEvidence],
) -> Result<HashMap<u32, ObservedRuntimeProcess>> {
    let mut system = System::new_all();
    system.refresh_all();
    let mut kinds_by_pid = HashMap::new();
    for session in evidence {
        kinds_by_pid.insert(session.pid, session.kind);
    }
    let wanted_pids = record
        .runtime_obligations
        .iter()
        .flat_map(|obligation| obligation.prior_sessions.iter().map(|session| session.pid))
        .chain(evidence.iter().map(|session| session.pid))
        .collect::<HashSet<_>>();
    let mut observed = HashMap::new();
    for pid in wanted_pids {
        let Some(process) = system.process(Pid::from_u32(pid)) else {
            continue;
        };
        let command = process_command(process);
        let kind = kinds_by_pid.get(&pid).copied();
        let executable = process.exe().map(Path::to_path_buf);
        let executable_identity = executable
            .as_deref()
            .and_then(|path| executable_identity_for_process(pid, path).ok());
        observed.insert(
            pid,
            ObservedRuntimeProcess {
                pid,
                start_time: process.start_time(),
                executable,
                executable_identity,
                binding: kind.and_then(|kind| runtime_binding(kind, &command, process.cwd())),
                command,
            },
        );
    }
    Ok(observed)
}

fn validate_runtime_convergence(
    record: &RestartPending,
    kin_home: &Path,
    spec: &[ComponentSpec],
    evidence: &[RuntimeSessionEvidence],
    observed: &HashMap<u32, ObservedRuntimeProcess>,
) -> Result<()> {
    validate_restart_record_schema(record)?;
    #[cfg(not(target_os = "linux"))]
    if record.schema_version == 2 {
        anyhow::bail!(
            "legacy restart acknowledgement schema 2 cannot be acknowledged on this platform because PID-mapped executable identity is unavailable; marker retained"
        );
    }
    validate_runtime_commit_fence(record, kin_home, spec)?;
    if record.schema_version == RESTART_MARKER_SCHEMA_VERSION
        && (!evidence.is_empty() || !observed.is_empty())
    {
        anyhow::bail!(
            "a stop-before-update restart marker accepts no runtime-session evidence; acknowledgement is bound to the persisted process fence and installed binary identities"
        );
    }
    let required_kinds = record
        .runtime_obligations
        .iter()
        .map(|item| item.kind)
        .collect::<HashSet<_>>();
    if record.runtime_obligations.len() != 3
        || required_kinds
            != HashSet::from([RuntimeKind::Daemon, RuntimeKind::Mcp, RuntimeKind::Vfs])
    {
        anyhow::bail!("restart marker has an incomplete managed-runtime obligation manifest");
    }
    if record.recorded_at_unix_seconds == 0 {
        anyhow::bail!("restart marker has no durable commit timestamp");
    }
    let distinct_pids = evidence.iter().map(|item| item.pid).collect::<HashSet<_>>();
    if distinct_pids.len() != evidence.len() {
        anyhow::bail!("runtime replacement evidence contains a duplicate PID");
    }

    let mut required_groups = HashSet::new();
    let mut prior_processes = HashSet::new();
    for obligation in &record.runtime_obligations {
        validate_hex(
            &obligation.expected_identity.sha256,
            64,
            &format!("expected {} runtime SHA-256", obligation.kind.label()),
        )?;
        let component = spec
            .iter()
            .find(|component| component.name == obligation.component)
            .with_context(|| {
                format!(
                    "{} runtime component '{}' is not managed on this platform",
                    obligation.kind.label(),
                    obligation.component
                )
            })?;
        let expected_path = component_path(kin_home, *component);
        verify_file_identity(
            &expected_path,
            &obligation.expected_identity,
            &format!("managed {} runtime binary", obligation.kind.label()),
        )?;

        for prior in &obligation.prior_sessions {
            if prior.pid == 0 || prior.start_time == 0 || !prior.executable.is_absolute() {
                anyhow::bail!(
                    "restart marker has invalid pre-update {} process identity",
                    obligation.kind.label()
                );
            }
            if prior
                .binding
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            {
                anyhow::bail!(
                    "restart marker has a non-absolute pre-update {} binding",
                    obligation.kind.label()
                );
            }
            validate_hex(
                &prior.executable_identity.sha256,
                64,
                &format!("pre-update {} runtime SHA-256", obligation.kind.label()),
            )?;
            if !prior_processes.insert((prior.pid, prior.start_time)) {
                anyhow::bail!("restart marker repeats one pre-update runtime process");
            }
            required_groups.insert((obligation.kind, prior.binding.clone()));
            if observed
                .get(&prior.pid)
                .is_some_and(|process| process.start_time == prior.start_time)
            {
                anyhow::bail!(
                    "pre-update {} runtime PID {} (start {}) is still live",
                    obligation.kind.label(),
                    prior.pid,
                    prior.start_time
                );
            }
        }
    }

    let mut replacement_groups = HashSet::new();
    for session in evidence {
        let obligation = record
            .runtime_obligations
            .iter()
            .find(|obligation| obligation.kind == session.kind)
            .with_context(|| {
                format!(
                    "restart marker has no {} runtime obligation",
                    session.kind.label()
                )
            })?;
        let process = observed.get(&session.pid).with_context(|| {
            format!(
                "{} replacement runtime PID {} is not live",
                session.kind.label(),
                session.pid
            )
        })?;
        if process.start_time <= record.recorded_at_unix_seconds {
            anyhow::bail!(
                "{} replacement runtime PID {} did not start after the committed update",
                session.kind.label(),
                process.pid
            );
        }
        let component = spec
            .iter()
            .find(|component| component.name == obligation.component)
            .with_context(|| {
                format!(
                    "{} runtime component '{}' is not managed on this platform",
                    obligation.kind.label(),
                    obligation.component
                )
            })?;
        let expected_path = component_path(kin_home, *component);
        let observed_executable = process.executable.as_deref().with_context(|| {
            format!(
                "cannot verify executable path for {} runtime PID {}",
                obligation.kind.label(),
                process.pid
            )
        })?;
        let expected_canonical = expected_path
            .canonicalize()
            .with_context(|| format!("failed to canonicalize {}", expected_path.display()))?;
        let observed_canonical = observed_executable.canonicalize().with_context(|| {
            format!(
                "failed to canonicalize executable for {} runtime PID {}",
                obligation.kind.label(),
                process.pid
            )
        })?;
        if observed_canonical != expected_canonical {
            anyhow::bail!(
                "{} runtime PID {} is not executing the managed component {}",
                obligation.kind.label(),
                process.pid,
                expected_path.display()
            );
        }
        if process.executable_identity.as_ref() != Some(&obligation.expected_identity) {
            anyhow::bail!(
                "{} runtime PID {} is not executing the expected post-update binary identity",
                obligation.kind.label(),
                process.pid
            );
        }
        if !runtime_process_serves_kind(obligation.kind, &process.command) {
            anyhow::bail!(
                "{} runtime PID {} is not serving the expected managed role",
                obligation.kind.label(),
                process.pid,
            );
        }
        let group = (session.kind, process.binding.clone());
        if !required_groups.contains(&group) {
            anyhow::bail!(
                "{} runtime PID {} does not replace a recorded pre-update binding ({})",
                session.kind.label(),
                process.pid,
                process
                    .binding
                    .as_deref()
                    .map_or_else(|| "unbound".to_string(), |path| path.display().to_string())
            );
        }
        if !replacement_groups.insert(group) {
            anyhow::bail!(
                "duplicate replacement evidence for one {} runtime binding",
                session.kind.label()
            );
        }
    }

    if replacement_groups != required_groups {
        anyhow::bail!(
            "restart acknowledgement requires one post-commit replacement for each distinct runtime binding recorded at update time (expected {}, got {})",
            required_groups.len(),
            replacement_groups.len()
        );
    }
    Ok(())
}

fn restart_acknowledgement_output(installed_version: &str) -> String {
    format!(
        "Verified the persisted process fence and installed byte identities for Kin v{installed_version}; live runtime convergence was not inferred."
    )
}

fn acknowledge_runtime_restart(evidence: &[RuntimeSessionEvidence]) -> Result<()> {
    let requested_home = crate::commands::setup::kin_dir()?;
    let lock = InstallRootLock::acquire_existing(&requested_home)?;
    let spec = platform_bundle_spec(std::env::consts::OS)?;
    // Restart persistence is create-only-or-identical, so committed recovery
    // can finish idempotently without ever superseding this exact marker.
    recover_stale_transactions(&lock, spec)?;
    let start_authority = UpdaterStartAuthority::capture(lock.root(), spec)?;
    start_authority.verify_locked(&lock, spec)?;
    attempt_pending_mcp_repair(&lock)?;

    #[cfg(unix)]
    let install = lock.install()?;
    #[cfg(unix)]
    let marker_bytes = install
        .root
        .read_regular(RESTART_ACK_REQUIRED_FILE, "restart acknowledgement marker")?;
    #[cfg(unix)]
    let marker_identity = bytes_identity(&marker_bytes);
    #[cfg(unix)]
    if install
        .root
        .identity(RESTART_ACK_REQUIRED_FILE, "restart acknowledgement marker")?
        .as_ref()
        != Some(&marker_identity)
    {
        anyhow::bail!("restart acknowledgement marker changed while it was read");
    }
    #[cfg(unix)]
    let record: RestartPending =
        serde_json::from_slice(&marker_bytes).context("invalid restart acknowledgement marker")?;
    #[cfg(not(unix))]
    let (record, marker) = read_restart_record_locked(lock.root())?;
    let build = kin_buildinfo::get();
    validate_restart_ack_identity(
        &record,
        CURRENT_VERSION,
        build.sha,
        build.dependency_provenance,
    )?;
    let observed = observe_runtime_sessions(&record, evidence)?;
    validate_runtime_convergence(&record, lock.root(), spec, evidence, &observed)?;
    #[cfg(unix)]
    {
        install.ensure_bound()?;
        if install
            .root
            .identity(RESTART_ACK_REQUIRED_FILE, "restart acknowledgement marker")?
            .as_ref()
            != Some(&marker_identity)
        {
            anyhow::bail!("restart acknowledgement marker changed before acknowledgement");
        }
        install.ensure_bound()?;
        install.root.unlink_file(RESTART_ACK_REQUIRED_FILE)?;
    }
    #[cfg(not(unix))]
    marker.remove_unchanged("runtime restart acknowledgement marker")?;
    println!(
        "{}",
        restart_acknowledgement_output(&record.installed_version)
    );
    Ok(())
}

/// The `firelock-ai/kin` release for an exact tag. Suffix `v{VERSION}`.
const GITHUB_RELEASES_TAG_URL: &str =
    "https://api.github.com/repos/firelock-ai/kin/releases/tags/v";

/// Download the VFS shim from the GitHub release matching the running version
/// and install it atomically at `dest`.
///
/// Verifies the downloaded archive's SHA-256 against the release's
/// `checksums-sha256.txt`, requires the extracted shim to be non-empty, and
/// writes via a temp file + atomic rename so a partial download can never land
/// as the 0-byte shim this repairs. Returns `Err` — honestly — when offline,
/// when the release or asset is absent, or when verification fails, so the
/// caller can print a manual reinstall step instead of looping.
pub(crate) async fn download_shim_for_current_version() -> Result<PathBuf> {
    let requested_home = crate::commands::setup::kin_dir()?;
    let spec = platform_bundle_spec(std::env::consts::OS)?;
    // Bind the repair to the exact mapped CLI inode/handle, embedded
    // version+commit, and complete installed generation before any network.
    // Holding the install lock through the fetch prevents a newer updater from
    // winning between this check and the final shim write.
    let start_authority = UpdaterStartAuthority::capture(&requested_home, spec)?;
    validate_shim_repair_start_authority(&start_authority)?;
    let install_lock = InstallRootLock::acquire_existing(&requested_home)?;
    start_authority.verify_locked(&install_lock, spec)?;
    if let Some(stale) = transaction_dirs(install_lock.root())?.first() {
        anyhow::bail!(
            "VFS shim auto-repair refuses an interrupted update at {}; recover it with `kin update` first",
            stale.display()
        );
    }
    let shim_name = crate::commands::setup::shim_filename();
    let archive_name = current_platform_asset_name()?;

    let client = build_update_http_client()?;

    let tag_url = format!("{GITHUB_RELEASES_TAG_URL}{CURRENT_VERSION}");
    let response = client
        .get(&tag_url)
        .send()
        .await
        .context("failed to reach the GitHub releases API (offline?)")?;
    let release_bytes = read_bounded_response(
        response,
        MAX_RELEASE_METADATA_BYTES,
        "GitHub release metadata for VFS shim repair",
    )
    .await
    .with_context(|| format!("no usable published release found for v{CURRENT_VERSION}"))?;
    let release: GithubRelease =
        serde_json::from_slice(&release_bytes).context("failed to parse release JSON")?;
    let release_version = parse_release_version(&release.tag_name)?;
    if release_version != parse_release_version(&start_authority.executing.build.version)? {
        anyhow::bail!(
            "VFS shim release {} does not match executing Kin version {}",
            release.tag_name,
            start_authority.executing.build.version
        );
    }
    let release_commit = resolve_release_commit(&client, &release.tag_name).await?;
    if release_commit != start_authority.executing.build.commit.to_ascii_lowercase() {
        anyhow::bail!(
            "VFS shim release commit {release_commit} does not match executing Kin build commit {}",
            start_authority.executing.build.commit
        );
    }

    let asset = find_release_asset(&release, &archive_name)?;

    let response = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("failed to download release archive")?;
    let archive_bytes = read_bounded_response(
        response,
        MAX_RELEASE_ARCHIVE_BYTES,
        "VFS shim release archive",
    )
    .await?;

    if archive_bytes.is_empty() {
        anyhow::bail!("downloaded archive '{archive_name}' was empty");
    }

    verify_archive_checksum(&client, &release, &asset.name, &archive_bytes).await?;

    let shim_bytes = extract_named_file_from_tar_gz(&archive_bytes, shim_name)
        .with_context(|| format!("archive '{archive_name}' did not contain '{shim_name}'"))?;
    if shim_bytes.is_empty() {
        anyhow::bail!("the shim '{shim_name}' extracted from '{archive_name}' was empty");
    }

    start_authority.verify_locked(&install_lock, spec)?;
    install_preflighted_shim_locked_if_generation_matches(
        &install_lock,
        shim_name,
        &shim_bytes,
        spec,
        &start_authority.bundle,
    )
}

fn validate_shim_repair_start_authority(authority: &UpdaterStartAuthority) -> Result<()> {
    // Keep this ordering explicit: a stale old doctor facing a newly installed
    // managed CLI must fail on the local inode/hash binding before any remote
    // release work is eligible to begin.
    authority.validate_managed_cli_binding()?;
    authority
        .executing
        .build
        .require_published_release_identity()
}

#[cfg(all(test, unix))]
fn install_preflighted_shim_if_generation_matches(
    requested_home: &Path,
    shim_name: &str,
    shim_bytes: &[u8],
    spec: &[ComponentSpec],
    generation: &ManagedBundleGeneration,
) -> Result<PathBuf> {
    // Remote and archive preflight is complete. Acquire local mutation
    // authority only for an exact-generation compare and final atomic write.
    let install_lock = InstallRootLock::acquire_existing(requested_home)?;
    install_preflighted_shim_locked_if_generation_matches(
        &install_lock,
        shim_name,
        shim_bytes,
        spec,
        generation,
    )
}

fn install_preflighted_shim_locked_if_generation_matches(
    install_lock: &InstallRootLock,
    shim_name: &str,
    shim_bytes: &[u8],
    spec: &[ComponentSpec],
    generation: &ManagedBundleGeneration,
) -> Result<PathBuf> {
    #[cfg(windows)]
    let _windows_install_binding = windows_update::guard_managed_directories(install_lock.root())?;
    verify_managed_bundle_generation_locked(install_lock, spec, generation)?;
    let dest = install_lock.root().join("lib").join(shim_name);
    write_managed_component_atomically(install_lock, &dest, shim_bytes)
        .with_context(|| format!("failed to install the shim at {}", dest.display()))?;
    Ok(dest)
}

/// Extract the bytes of the archive entry whose file name is exactly `target`.
fn extract_named_file_from_tar_gz(bytes: &[u8], target: &str) -> Result<Vec<u8>> {
    extract_named_file_from_tar_gz_with_limits(bytes, target, RELEASE_ARCHIVE_LIMITS)
}

fn extract_named_file_from_tar_gz_with_limits(
    bytes: &[u8],
    target: &str,
    limits: ArchiveSizeLimits,
) -> Result<Vec<u8>> {
    let mut selected = None;
    walk_simple_tar_gz(bytes, limits, |entry| {
        if entry.kind == SimpleTarEntryKind::File
            && entry.path.file_name().and_then(|name| name.to_str()) == Some(target)
        {
            if selected.is_some() {
                anyhow::bail!("release archive contains duplicate shim entry '{target}'");
            }
            selected = Some(entry.contents);
        }
        Ok(())
    })?;
    selected.with_context(|| format!("'{target}' not found in archive"))
}

/// Write `bytes` to `dest` via a sibling temp file + rename, so a crash or
/// partial write never leaves a truncated file at `dest`.
pub(crate) fn write_managed_component_atomically(
    lock: &InstallRootLock,
    dest: &Path,
    bytes: &[u8],
) -> Result<()> {
    #[cfg(unix)]
    {
        return write_managed_component_atomically_unix_with_hook(lock, dest, bytes, || Ok(()));
    }

    #[cfg(not(unix))]
    {
        let parent = dest
            .parent()
            .context("destination path has no parent directory")?;
        let canonical_parent = parent
            .canonicalize()
            .with_context(|| format!("failed to canonicalize {}", parent.display()))?;
        let expected_parent = lock.root().join("lib");
        if canonical_parent != expected_parent {
            anyhow::bail!(
                "refusing managed component write outside {}: {}",
                expected_parent.display(),
                dest.display()
            );
        }
        if let Ok(metadata) = fs::symlink_metadata(dest) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                anyhow::bail!(
                    "refusing non-regular managed destination {}",
                    dest.display()
                );
            }
        }
        write_file_atomically(dest, bytes, 0o644)
    }
}

#[cfg(unix)]
fn write_managed_component_atomically_unix_with_hook<B>(
    lock: &InstallRootLock,
    dest: &Path,
    bytes: &[u8],
    before_rename: B,
) -> Result<()>
where
    B: FnOnce() -> Result<()>,
{
    let install = lock.install()?;
    install.ensure_bound()?;
    let parent = dest
        .parent()
        .context("destination path has no parent directory")?;
    let supplied_parent = AnchoredDir::open_ambient(parent)?;
    if supplied_parent.dev != install.lib.dev || supplied_parent.ino != install.lib.ino {
        anyhow::bail!(
            "refusing managed component write outside {}: {}",
            lock.root().join("lib").display(),
            dest.display()
        );
    }
    let name = dest
        .file_name()
        .and_then(|name| name.to_str())
        .context("managed component file name is not UTF-8")?;
    if install.lib.stat_entry(name)?.is_some() {
        let _ = install
            .lib
            .identity(name, "existing managed component destination")?;
    }
    install.ensure_bound()?;
    install
        .lib
        .atomic_write_with_hooks(name, bytes, 0o644, before_rename, || install.ensure_bound())
}

fn parse_release_version(value: &str) -> Result<Version> {
    let value = value.strip_prefix('v').unwrap_or(value);
    Version::parse(value).with_context(|| format!("'{value}' is not valid semantic version syntax"))
}

#[cfg(test)]
fn is_newer(latest: &str, current: &str) -> Result<bool> {
    Ok(parse_release_version(latest)? > parse_release_version(current)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_subprocess::{output_with_timeout, DEFAULT_TEST_SUBPROCESS_TIMEOUT};
    use kin_core::test_env::EnvVarGuard;
    use serial_test::serial;

    #[cfg(windows)]
    const WINDOWS_INSTALL_AUTHORITY_CHILD_MODE: &str =
        "KIN_INTERNAL_TEST_INSTALL_AUTHORITY_CHILD_MODE";
    #[cfg(windows)]
    const WINDOWS_INSTALL_AUTHORITY_CHILD_ROOT: &str =
        "KIN_INTERNAL_TEST_INSTALL_AUTHORITY_CHILD_ROOT";
    #[cfg(windows)]
    const WINDOWS_INSTALL_AUTHORITY_CHILD_MARKER: &str =
        "KIN_INTERNAL_TEST_INSTALL_AUTHORITY_CHILD_MARKER";

    fn test_subprocess_output(command: Command, label: &str) -> Result<std::process::Output> {
        output_with_timeout(command, label, DEFAULT_TEST_SUBPROCESS_TIMEOUT)
    }

    /// Keep update fixtures from deriving MCP repair authority from the
    /// developer's real client configuration.
    ///
    /// `install_staged_bundle*` captures every configured MCP target before it
    /// creates the transaction. These tests used to inherit `HOME`, which made
    /// nextest exercise a developer's live `.claude.json` while `cargo test`
    /// could see a temporary home installed by another in-process fixture. The two
    /// runners were therefore testing different transactions. Bind every home
    /// spelling used by the supported hosts, and clear the legacy Kin aliases,
    /// so both runners prove only the fixture assembled by the test.
    fn isolated_update_environment(root: &Path, kin_home: &Path) -> EnvVarGuard {
        let home = root.join("home");
        fs::create_dir_all(home.join(".config")).unwrap();
        EnvVarGuard::set("HOME", &home)
            .with("USERPROFILE", &home)
            .with("XDG_CONFIG_HOME", home.join(".config"))
            .with("KIN_HOME", kin_home)
            .without("KIN_DIR")
            .without("KIN_MCP_REPO")
    }

    #[cfg(windows)]
    #[test]
    fn windows_marker_guard_denies_path_replacement_and_disposes_exact_handle() {
        let tmp = tempfile::tempdir().unwrap();
        let marker_path = tmp.path().join("restart-marker.json");
        let bytes = b"exact retained marker";
        let config_lock =
            crate::commands::setup::ConfigLock::acquire_nofollow(&marker_path).unwrap();
        config_lock
            .write_private_guarded(&marker_path, bytes, None)
            .unwrap();
        drop(config_lock);

        let marker = LockedPrivateMarker::open(&marker_path, "test marker")
            .unwrap()
            .unwrap();
        assert_eq!(marker.bytes, bytes);
        assert!(
            fs::remove_file(&marker_path).is_err(),
            "held marker handle must deny external pathname deletion"
        );
        let replacement = tmp.path().join("replacement.json");
        fs::write(&replacement, b"hostile replacement").unwrap();
        assert!(
            fs::rename(&replacement, &marker_path).is_err(),
            "held marker handle must deny external pathname replacement"
        );
        marker.remove_unchanged("test marker").unwrap();

        assert!(!marker_path.exists());
        assert_eq!(fs::read(replacement).unwrap(), b"hostile replacement");
    }

    #[cfg(unix)]
    struct ConfigDirectorySyncFailureGuard;

    #[cfg(unix)]
    impl ConfigDirectorySyncFailureGuard {
        fn enable(root: &Path) -> Self {
            crate::commands::setup::inject_config_directory_sync_failure_under(Some(root));
            Self
        }
    }

    #[cfg(unix)]
    impl Drop for ConfigDirectorySyncFailureGuard {
        fn drop(&mut self) {
            crate::commands::setup::inject_config_directory_sync_failure_under(None);
        }
    }

    struct CwdGuard(PathBuf);

    impl CwdGuard {
        fn set(path: &Path) -> Self {
            let previous = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            Self(previous)
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.0).unwrap();
        }
    }

    /// Build an in-memory `.tar.gz` with the given (name, bytes) entries.
    fn make_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let with_modes: Vec<_> = entries
            .iter()
            .map(|(name, data)| (*name, *data, 0o644_u32))
            .collect();
        make_tar_gz_with_modes(&with_modes)
    }

    /// Build an archive that carries per-entry permissions. A name ending in
    /// `/` describes an explicit zero-sized directory record, matching the
    /// release tarballs produced by the macOS packaging workflow. The
    /// notification bundle's executable is refused unless it is actually
    /// executable, so a fixture standing in for a real macOS archive has to say
    /// so as well.
    fn make_tar_gz_with_modes(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        {
            let mut builder = tar::Builder::new(&mut gz);
            for (name, data, mode) in entries {
                let mut header = tar::Header::new_gnu();
                if name.ends_with('/') {
                    assert!(data.is_empty(), "directory fixture must be empty: {name}");
                    header.set_entry_type(tar::EntryType::Directory);
                }
                header.set_size(data.len() as u64);
                header.set_mode(*mode);
                header.set_cksum();
                builder.append_data(&mut header, name, *data).unwrap();
            }
            builder.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    fn make_tar_gz_with_nonempty_directory(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        {
            let mut builder = tar::Builder::new(&mut gz);
            let mut directory = tar::Header::new_gnu();
            directory.set_entry_type(tar::EntryType::Directory);
            directory.set_size(1);
            directory.set_mode(0o755);
            directory.set_cksum();
            builder
                .append_data(&mut directory, "nonempty/", b"x".as_slice())
                .unwrap();
            for (name, data) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, name, *data).unwrap();
            }
            builder.finish().unwrap();
        }
        gz.finish().unwrap()
    }

    fn write_test_tar_octal(field: &mut [u8], value: u64) {
        let digits = format!("{value:0width$o}", width = field.len() - 1);
        assert_eq!(digits.len(), field.len() - 1);
        field[..digits.len()].copy_from_slice(digits.as_bytes());
        field[digits.len()] = 0;
    }

    fn refresh_test_tar_checksum(header: &mut [u8; 512]) {
        header[148..156].fill(b' ');
        let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        let encoded = format!("{checksum:06o}\0 ");
        assert_eq!(encoded.len(), 8);
        header[148..156].copy_from_slice(encoded.as_bytes());
    }

    fn make_test_tar_header(name: &str, declared_size: u64, record_type: u8) -> [u8; 512] {
        assert!(!name.is_empty() && name.len() <= 100);
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        write_test_tar_octal(&mut header[100..108], 0o644);
        write_test_tar_octal(&mut header[108..116], 0);
        write_test_tar_octal(&mut header[116..124], 0);
        write_test_tar_octal(&mut header[124..136], declared_size);
        write_test_tar_octal(&mut header[136..148], 0);
        header[156] = record_type;
        refresh_test_tar_checksum(&mut header);
        header
    }

    fn gzip_test_tar(raw: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write as _;

        let mut gz = GzEncoder::new(Vec::new(), Compression::best());
        gz.write_all(raw).unwrap();
        gz.finish().unwrap()
    }

    fn make_raw_test_tar(header: [u8; 512], payload: &[u8]) -> Vec<u8> {
        let mut raw = Vec::from(header);
        raw.extend_from_slice(payload);
        raw.resize(raw.len().next_multiple_of(512), 0);
        raw.extend_from_slice(&[0_u8; 1024]);
        gzip_test_tar(&raw)
    }

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::{Cursor, Write as _};

        let cursor = Cursor::new(Vec::new());
        let mut archive = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            archive.start_file(*name, options).unwrap();
            archive.write_all(data).unwrap();
        }
        archive.finish().unwrap().into_inner()
    }

    fn test_static_build_identity() -> StaticBuildIdentity {
        StaticBuildIdentity {
            schema: STATIC_BUILD_IDENTITY_SCHEMA.to_string(),
            version: "0.2.22".to_string(),
            commit: "a".repeat(40),
            clean: true,
            source_known: true,
            dependency_provenance: "b".repeat(64),
            graph_snapshot_version: 1,
        }
    }

    fn bytes_with_static_build_identity(prefix: &[u8], identity: &StaticBuildIdentity) -> Vec<u8> {
        fn put_ascii(target: &mut [u8], value: &str) {
            assert!(value.len() <= target.len());
            target[..value.len()].copy_from_slice(value.as_bytes());
        }

        let mut bytes = prefix.to_vec();
        let mut sentinel = [0_u8; STATIC_BUILD_IDENTITY_SENTINEL_BYTES];
        sentinel[..16].copy_from_slice(&[
            0x00, 0x89, b'K', b'I', b'N', b'U', b'P', b'D', b'A', b'T', b'E', 1, 0x0d, 0x0a, 0x1a,
            0x0a,
        ]);
        put_ascii(&mut sentinel[16..40], &identity.schema);
        put_ascii(&mut sentinel[40..72], &identity.version);
        put_ascii(&mut sentinel[72..112], &identity.commit);
        sentinel[112] = u8::from(identity.clean);
        sentinel[113] = u8::from(identity.source_known);
        put_ascii(&mut sentinel[114..178], &identity.dependency_provenance);
        sentinel[178..182].copy_from_slice(&identity.graph_snapshot_version.to_le_bytes());
        sentinel[182..].copy_from_slice(&[
            0x00, 0x89, b'K', b'I', b'N', b'E', b'N', b'D', b'V', b'1', 0xff, 1, 0x0d, 0x0a, 0x1a,
            0x0a,
        ]);
        bytes.extend_from_slice(&sentinel);
        bytes
    }

    fn static_identity_release_fixture(
        spec: &[ComponentSpec],
        artifact: &str,
        archive_name: &str,
        target: &str,
        vfs_target: &str,
    ) -> (Vec<u8>, ArtifactProvenance, VerifiedStagedIdentities) {
        let identity = test_static_build_identity();
        let (cli_name, daemon_name) = static_identity_component_names(spec).unwrap();
        let entries = spec
            .iter()
            .filter(|component| component.required)
            .map(|component| {
                let bytes = if matches!(component.name, name if name == cli_name || name == daemon_name)
                {
                    bytes_with_static_build_identity(component.name.as_bytes(), &identity)
                } else {
                    format!("fixture-{}", component.name).into_bytes()
                };
                (component.name.to_string(), bytes)
            })
            .collect::<Vec<_>>();
        let archive_entries = entries
            .iter()
            .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
            .collect::<Vec<_>>();
        let archive = if archive_name.ends_with(".zip") {
            make_zip(&archive_entries)
        } else {
            // A real macOS release archive carries the notification bundle, and
            // the stager requires it, so this fixture carries one too. It stays
            // out of `entries`: the bundle is deliberately absent from the
            // manifest's per-file inventory, and adding it there would make the
            // fixture describe an archive the release workflow never produces.
            let mut with_modes = archive_entries
                .iter()
                .map(|(name, bytes)| (*name, *bytes, 0o755_u32))
                .collect::<Vec<_>>();
            if spec_carries_notifier_bundle(spec) {
                with_modes.push((
                    "KinNotifier.app/Contents/Info.plist",
                    b"<plist/>".as_slice(),
                    0o644,
                ));
                with_modes.push((
                    "KinNotifier.app/Contents/MacOS/KinNotifier",
                    b"fixture-notifier".as_slice(),
                    0o755,
                ));
            }
            make_tar_gz_with_modes(&with_modes)
        };
        let identities = entries
            .iter()
            .map(|(name, bytes)| (name.clone(), bytes_identity(bytes)))
            .collect::<VerifiedStagedIdentities>();
        let provenance = ArtifactProvenance {
            schema_version: 2,
            release_tag: "v0.2.22".to_string(),
            artifact: artifact.to_string(),
            target: target.to_string(),
            vfs_target: vfs_target.to_string(),
            kin: KinProvenance {
                commit: "a".repeat(40),
                cargo_lock_sha256: "b".repeat(64),
                embedded_dependency_provenance: "b".repeat(64),
            },
            kin_vfs: VfsProvenance {
                commit: "c".repeat(40),
                dirty: false,
                cargo_lock_sha256: "d".repeat(64),
            },
            archive: ProvenanceArchive {
                name: archive_name.to_string(),
                sha256: hex::encode(Sha256::digest(&archive)),
                size_bytes: archive.len() as u64,
            },
            archive_contents: entries
                .iter()
                .map(|(name, bytes)| ProvenanceFile {
                    name: name.clone(),
                    sha256: hex::encode(Sha256::digest(bytes)),
                    size_bytes: bytes.len() as u64,
                    build_identity: matches!(name.as_str(), candidate if candidate == cli_name || candidate == daemon_name)
                        .then(|| identity.clone()),
                })
                .collect(),
        };
        (archive, provenance, identities)
    }

    fn assert_static_identity_release_fixture(
        spec: &[ComponentSpec],
        artifact: &str,
        archive_name: &str,
        target: &str,
        vfs_target: &str,
    ) {
        let (archive, provenance, expected_identities) =
            static_identity_release_fixture(spec, artifact, archive_name, target, vfs_target);
        let release = GithubRelease {
            tag_name: "v0.2.22".to_string(),
            prerelease: false,
            assets: vec![GithubAsset {
                name: archive_name.to_string(),
                browser_download_url: format!("https://example.invalid/{archive_name}"),
            }],
        };
        let asset = &release.assets[0];
        let metadata_identities = validate_artifact_provenance_metadata(
            &provenance,
            &release,
            &"a".repeat(40),
            asset,
            &archive,
            spec,
            true,
        )
        .unwrap();
        assert_eq!(metadata_identities, expected_identities);
        assert_eq!(
            validate_archive_payload_provenance_and_static_identity(
                &archive,
                archive_name,
                spec,
                &metadata_identities,
                &provenance,
            )
            .unwrap(),
            expected_identities
        );

        let stage = tempfile::tempdir().unwrap();
        stage_archive(&archive, archive_name, stage.path(), spec).unwrap();
        validate_staged_static_build_identity(stage.path(), spec, "0.2.22", &provenance).unwrap();
    }

    fn full_linux_static_archive(prefix: &str) -> Vec<u8> {
        let identity = test_static_build_identity();
        let cli = bytes_with_static_build_identity(b"new-kin", &identity);
        let daemon = bytes_with_static_build_identity(b"new-daemon", &identity);
        make_tar_gz(&[
            (&format!("{prefix}/kin"), &cli),
            (&format!("{prefix}/kin-daemon"), &daemon),
            (&format!("{prefix}/kin-vfs"), b"new-vfs"),
            (&format!("{prefix}/libkin_vfs_shim.so"), b"new-shim"),
        ])
    }

    fn full_linux_archive(prefix: &str) -> Vec<u8> {
        make_tar_gz(&[
            (&format!("{prefix}/kin"), b"new-kin"),
            (&format!("{prefix}/kin-daemon"), b"new-daemon"),
            (&format!("{prefix}/kin-vfs"), b"new-vfs"),
            (&format!("{prefix}/libkin_vfs_shim.so"), b"new-shim"),
        ])
    }

    /// A complete macOS archive: the same component bytes as the Linux fixture
    /// so the shared restart-obligation fixture applies, plus the notification
    /// bundle that only this platform's archive carries.
    #[cfg(unix)]
    fn full_macos_archive(prefix: &str) -> Vec<u8> {
        macos_archive_with_notifier(prefix, b"new-notifier")
    }

    #[cfg(unix)]
    fn macos_archive_with_notifier(prefix: &str, notifier: &[u8]) -> Vec<u8> {
        make_tar_gz_with_modes(&[
            (&format!("{prefix}/"), b"", 0o755),
            (&format!("{prefix}/kin"), b"new-kin", 0o755),
            (&format!("{prefix}/kin-daemon"), b"new-daemon", 0o755),
            (&format!("{prefix}/kin-vfs"), b"new-vfs", 0o755),
            (
                &format!("{prefix}/libkin_vfs_shim.dylib"),
                b"new-shim",
                0o644,
            ),
            (&format!("{prefix}/KinNotifier.app/"), b"", 0o755),
            (&format!("{prefix}/KinNotifier.app/Contents/"), b"", 0o755),
            (
                &format!("{prefix}/KinNotifier.app/Contents/MacOS/"),
                b"",
                0o755,
            ),
            (
                &format!("{prefix}/KinNotifier.app/Contents/Resources/"),
                b"",
                0o755,
            ),
            (
                &format!("{prefix}/KinNotifier.app/Contents/Info.plist"),
                b"<plist>new</plist>",
                0o644,
            ),
            (
                &format!("{prefix}/KinNotifier.app/Contents/MacOS/KinNotifier"),
                notifier,
                0o755,
            ),
            (
                &format!("{prefix}/KinNotifier.app/Contents/Resources/Kin.icns"),
                b"new-icns",
                0o644,
            ),
        ])
    }

    /// Write a KinNotifier.app under `root/lib` whose files all carry `prefix`.
    #[cfg(unix)]
    fn write_notifier_bundle(root: &Path, marker: &[u8]) {
        let bundle = root.join("lib").join(NOTIFIER_BUNDLE_DIR);
        fs::create_dir_all(bundle.join("Contents").join("MacOS")).unwrap();
        fs::create_dir_all(bundle.join("Contents").join("Resources")).unwrap();
        fs::write(bundle.join("Contents").join("Info.plist"), marker).unwrap();
        fs::write(
            bundle.join("Contents").join("MacOS").join("KinNotifier"),
            marker,
        )
        .unwrap();
        fs::write(
            bundle.join("Contents").join("Resources").join("Kin.icns"),
            marker,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                bundle.join("Contents").join("MacOS").join("KinNotifier"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
    }

    #[cfg(unix)]
    fn notifier_executable_bytes(root: &Path) -> Vec<u8> {
        fs::read(
            root.join("lib")
                .join(NOTIFIER_BUNDLE_DIR)
                .join("Contents")
                .join("MacOS")
                .join("KinNotifier"),
        )
        .unwrap()
    }

    #[cfg(unix)]
    fn pinned_probe_fixture(
        cli: Vec<u8>,
        daemon: Vec<u8>,
    ) -> (Vec<u8>, ArtifactProvenance, VerifiedStagedIdentities) {
        let vfs = b"preflight-vfs".to_vec();
        let shim = b"preflight-shim".to_vec();
        let entries = [
            ("kin", cli.as_slice()),
            ("kin-daemon", daemon.as_slice()),
            ("kin-vfs", vfs.as_slice()),
            ("libkin_vfs_shim.so", shim.as_slice()),
        ];
        let archive = make_tar_gz(&entries);
        let identities = entries
            .iter()
            .map(|(name, bytes)| ((*name).to_string(), bytes_identity(bytes)))
            .collect::<VerifiedStagedIdentities>();
        let provenance = ArtifactProvenance {
            schema_version: 2,
            release_tag: "v0.2.22".to_string(),
            artifact: "kin-linux-x86_64".to_string(),
            target: "x86_64-unknown-linux-musl".to_string(),
            vfs_target: "x86_64-unknown-linux-gnu".to_string(),
            kin: KinProvenance {
                commit: "a".repeat(40),
                cargo_lock_sha256: "b".repeat(64),
                embedded_dependency_provenance: "b".repeat(64),
            },
            kin_vfs: VfsProvenance {
                commit: "c".repeat(40),
                dirty: false,
                cargo_lock_sha256: "d".repeat(64),
            },
            archive: ProvenanceArchive {
                name: "kin-linux-x86_64.tar.gz".to_string(),
                sha256: hex::encode(Sha256::digest(&archive)),
                size_bytes: archive.len() as u64,
            },
            archive_contents: entries
                .iter()
                .map(|(name, bytes)| ProvenanceFile {
                    name: (*name).to_string(),
                    sha256: hex::encode(Sha256::digest(bytes)),
                    size_bytes: bytes.len() as u64,
                    build_identity: matches!(*name, "kin" | "kin-daemon")
                        .then(test_static_build_identity),
                })
                .collect(),
        };
        (archive, provenance, identities)
    }

    /// Point ambient home resolution at the fixture for a test's lifetime.
    ///
    /// An update records the MCP repair obligation it will owe after the swap,
    /// and the client configs that obligation covers are addressed from the
    /// home directory rather than from the install root the test passes in. A
    /// test that leaves `HOME` alone therefore resolves, and can write, the
    /// developer's live configuration.
    fn fixture_home(tmp: &tempfile::TempDir, kin_home: &Path) -> EnvVarGuard {
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        EnvVarGuard::set("HOME", &home).with("KIN_HOME", kin_home)
    }

    fn write_bundle(root: &Path, spec: &[ComponentSpec], prefix: &[u8]) {
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("lib")).unwrap();
        for component in spec {
            let mut bytes = prefix.to_vec();
            bytes.extend_from_slice(component.name.as_bytes());
            let path = component_path(root, *component);
            fs::write(&path, bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = if component.location == ComponentLocation::Bin {
                    0o755
                } else {
                    0o644
                };
                fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
            }
        }
    }

    fn test_restart_pending(version: &str) -> RestartPending {
        RestartPending {
            schema_version: 2,
            installed_version: version.to_string(),
            kin_commit: "a".repeat(40),
            dependency_provenance: "b".repeat(64),
            kin_vfs_commit: "c".repeat(40),
            recorded_at: "2026-07-13T00:00:00Z".to_string(),
            recorded_at_unix_seconds: 1_752_364_800,
            commit_runtime_fence: None,
            reason: "test restart pending".to_string(),
            runtime_obligations: [
                (RuntimeKind::Daemon, "kin-daemon", b"new-daemon".as_slice()),
                (RuntimeKind::Mcp, "kin", b"new-kin".as_slice()),
                (RuntimeKind::Vfs, "kin-vfs", b"new-vfs".as_slice()),
            ]
            .into_iter()
            .map(|(kind, component, bytes)| RuntimeRestartObligation {
                kind,
                component: component.to_string(),
                expected_identity: bytes_identity(bytes),
                prior_sessions: Vec::new(),
            })
            .collect(),
        }
    }

    fn test_provenance(
        stage_root: &Path,
        spec: &[ComponentSpec],
        archive_name: &str,
        archive_bytes: &[u8],
    ) -> ArtifactProvenance {
        let archive_contents = spec
            .iter()
            .filter_map(|component| {
                let path = component_path(stage_root, *component);
                let metadata = fs::metadata(&path).ok()?;
                Some(ProvenanceFile {
                    name: component.name.to_string(),
                    sha256: sha256_file(&path).unwrap(),
                    size_bytes: metadata.len(),
                    build_identity: matches!(component.name, "kin" | "kin-daemon")
                        .then(|| parse_static_build_identity(&fs::read(&path).unwrap()).unwrap()),
                })
            })
            .collect();
        ArtifactProvenance {
            schema_version: 2,
            release_tag: "v0.2.22".to_string(),
            artifact: artifact_name_from_archive(archive_name)
                .unwrap()
                .to_string(),
            target: "x86_64-unknown-linux-musl".to_string(),
            vfs_target: "x86_64-unknown-linux-gnu".to_string(),
            kin: KinProvenance {
                commit: "a".repeat(40),
                cargo_lock_sha256: "b".repeat(64),
                embedded_dependency_provenance: "b".repeat(64),
            },
            kin_vfs: VfsProvenance {
                commit: "c".repeat(40),
                dirty: false,
                cargo_lock_sha256: "d".repeat(64),
            },
            archive: ProvenanceArchive {
                name: archive_name.to_string(),
                sha256: hex::encode(Sha256::digest(archive_bytes)),
                size_bytes: archive_bytes.len() as u64,
            },
            archive_contents,
        }
    }

    fn bundle_snapshot(root: &Path, spec: &[ComponentSpec]) -> HashMap<String, Option<Vec<u8>>> {
        spec.iter()
            .map(|component| {
                (
                    component.name.to_string(),
                    fs::read(component_path(root, *component)).ok(),
                )
            })
            .collect()
    }

    #[cfg(unix)]
    #[derive(Debug, PartialEq, Eq)]
    struct InstallTreeEntrySnapshot {
        relative_path: PathBuf,
        file_type: u32,
        permissions: u32,
        device: u64,
        inode: u64,
        bytes: Option<Vec<u8>>,
    }

    #[cfg(unix)]
    fn install_tree_snapshot(root: &Path) -> Vec<InstallTreeEntrySnapshot> {
        fn visit(root: &Path, path: &Path, entries: &mut Vec<InstallTreeEntrySnapshot>) {
            use std::os::unix::fs::MetadataExt;

            let metadata = fs::symlink_metadata(path).unwrap();
            entries.push(InstallTreeEntrySnapshot {
                relative_path: path.strip_prefix(root).unwrap().to_path_buf(),
                file_type: metadata.mode() & libc::S_IFMT as u32,
                permissions: metadata.mode() & 0o7777,
                device: metadata.dev(),
                inode: metadata.ino(),
                bytes: metadata.is_file().then(|| fs::read(path).unwrap()),
            });
            if metadata.is_dir() {
                let mut children = fs::read_dir(path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .collect::<Vec<_>>();
                children.sort();
                for child in children {
                    visit(root, &child, entries);
                }
            }
        }

        let mut entries = Vec::new();
        visit(root, root, &mut entries);
        entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        entries
    }

    fn assert_bundle_matches(
        root: &Path,
        spec: &[ComponentSpec],
        expected: &HashMap<String, Option<Vec<u8>>>,
    ) {
        for component in spec {
            assert_eq!(
                fs::read(component_path(root, *component)).ok(),
                expected[component.name],
                "{}",
                component.name
            );
        }
    }

    /// Which component contract a crash worker runs under, chosen by the parent
    /// so one worker can drive both the bundle-free and bundle-carrying paths.
    fn worker_spec() -> &'static [ComponentSpec] {
        match std::env::var("KIN_UPDATE_TEST_WORKER_SPEC").as_deref() {
            Ok("macos") => MACOS_COMPONENTS,
            _ => LINUX_COMPONENTS,
        }
    }

    fn run_crash_recovery_case(point: &str, committed: bool) {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let old = bundle_snapshot(&kin_home, LINUX_COMPONENTS);
        let archive = full_linux_archive("kin-linux-x86_64");
        stage_archive(
            &archive,
            "kin-linux-x86_64.tar.gz",
            &stage,
            LINUX_COMPONENTS,
        )
        .unwrap();

        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "commands::update::tests::crash_recovery_worker",
                "--nocapture",
            ])
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("KIN_HOME", &kin_home)
            .env_remove("KIN_DIR")
            .env_remove("KIN_MCP_REPO")
            .env("KIN_UPDATE_TEST_WORKER_HOME", &kin_home)
            .env("KIN_UPDATE_TEST_WORKER_STAGE", &stage)
            .env("KIN_UPDATE_TEST_CRASH_POINT", point);
        let output =
            test_subprocess_output(command, &format!("crash recovery worker at {point}")).unwrap();
        assert_eq!(
            output.status.code(),
            Some(86),
            "worker output: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!transaction_dirs(&kin_home).unwrap().is_empty());
        #[cfg(unix)]
        if point == "after-backup-4" {
            use std::os::unix::fs::PermissionsExt;
            let launcher = kin_home.join("bin/kin");
            assert!(launcher.is_file());
            assert_ne!(
                fs::metadata(&launcher).unwrap().permissions().mode() & 0o111,
                0,
                "the canonical launcher must remain executable after its final backup"
            );
        }

        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        recover_stale_transactions(&lock, LINUX_COMPONENTS).unwrap();
        if committed {
            assert_eq!(fs::read(kin_home.join("bin/kin")).unwrap(), b"new-kin");
            assert_eq!(
                fs::read(kin_home.join("bin/kin-daemon")).unwrap(),
                b"new-daemon"
            );
            assert_eq!(fs::read(kin_home.join("bin/kin-vfs")).unwrap(), b"new-vfs");
            assert_eq!(
                fs::read(kin_home.join("lib/libkin_vfs_shim.so")).unwrap(),
                b"new-shim"
            );
            assert!(!kin_home.join("bin/kin-mcp").exists());
            assert!(restart_pending_path(lock.root()).is_file());
        } else {
            assert_bundle_matches(&kin_home, LINUX_COMPONENTS, &old);
            assert!(!restart_pending_path(lock.root()).exists());
        }
        assert!(transaction_dirs(lock.root()).unwrap().is_empty());
    }

    /// Kill a real update process between two bundle steps and let a later
    /// recovery reverse it.
    ///
    /// A clean failure through the swap hook unwinds inside the process that
    /// created the transaction, so it proves only the rollback the failing
    /// process itself performs. A durable recovery has to reach the same state
    /// from the journal alone, with no live process and no memory of how far it
    /// got, which is the case a power loss actually produces.
    #[cfg(unix)]
    fn run_bundle_crash_recovery_case(point: &str) {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        write_bundle(&kin_home, MACOS_COMPONENTS, b"old-");
        write_notifier_bundle(&kin_home, b"old-notifier");
        let old = bundle_snapshot(&kin_home, MACOS_COMPONENTS);
        stage_archive(
            &full_macos_archive("kin-macos-aarch64"),
            "kin-macos-aarch64.tar.gz",
            &stage,
            MACOS_COMPONENTS,
        )
        .unwrap();

        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "commands::update::tests::crash_recovery_worker",
                "--nocapture",
            ])
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("KIN_HOME", &kin_home)
            .env_remove("KIN_DIR")
            .env_remove("KIN_MCP_REPO")
            .env("KIN_UPDATE_TEST_WORKER_HOME", &kin_home)
            .env("KIN_UPDATE_TEST_WORKER_STAGE", &stage)
            .env("KIN_UPDATE_TEST_WORKER_SPEC", "macos")
            .env("KIN_UPDATE_TEST_CRASH_POINT", point);
        let output =
            test_subprocess_output(command, &format!("bundle crash worker at {point}")).unwrap();
        // Reaching the kill point is itself the evidence that the bundle's
        // fault-injection labels are live: a worker that never reached one
        // would exit having completed the update instead.
        assert_eq!(
            output.status.code(),
            Some(86),
            "worker output: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!transaction_dirs(&kin_home).unwrap().is_empty());

        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        recover_stale_transactions(&lock, MACOS_COMPONENTS).unwrap();
        assert_eq!(
            notifier_executable_bytes(&kin_home),
            b"old-notifier",
            "recovery after a crash at {point} must restore the previous bundle"
        );
        assert!(
            kin_home
                .join("lib")
                .join(NOTIFIER_BUNDLE_DIR)
                .join("Contents/Resources/Kin.icns")
                .exists(),
            "the restored bundle must be the whole original tree"
        );
        assert_bundle_matches(&kin_home, MACOS_COMPONENTS, &old);
        assert!(!restart_pending_path(lock.root()).exists());
        assert!(transaction_dirs(lock.root()).unwrap().is_empty());
    }

    /// Both bundle steps happen before the commit fence, so a crash at either
    /// one has to leave the install on the version it started from.
    #[cfg(unix)]
    #[test]
    #[serial]
    fn subprocess_crashes_around_the_bundle_swap_recover_the_old_bundle() {
        for point in [
            "after-backup-notifier-bundle",
            "after-install-notifier-bundle",
        ] {
            run_bundle_crash_recovery_case(point);
        }
    }

    /// A restart during rollback must be idempotent at both bundle mutations:
    /// after the staged tree is removed and after the original is restored.
    /// The first-install case has no backup to restore, so its remove point is
    /// exercised separately from the refresh case.
    #[cfg(unix)]
    fn run_bundle_rollback_crash_case(point: &str, had_original: bool) {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        write_bundle(&kin_home, MACOS_COMPONENTS, b"old-");
        if had_original {
            write_notifier_bundle(&kin_home, b"old-notifier");
        }
        let old = bundle_snapshot(&kin_home, MACOS_COMPONENTS);
        stage_archive(
            &full_macos_archive("kin-macos-aarch64"),
            "kin-macos-aarch64.tar.gz",
            &stage,
            MACOS_COMPONENTS,
        )
        .unwrap();

        let worker = |crash_point: &str, recover: bool| {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "commands::update::tests::crash_recovery_worker",
                    "--nocapture",
                ])
                .env("HOME", &home)
                .env("USERPROFILE", &home)
                .env("XDG_CONFIG_HOME", home.join(".config"))
                .env("KIN_HOME", &kin_home)
                .env_remove("KIN_DIR")
                .env_remove("KIN_MCP_REPO")
                .env("KIN_UPDATE_TEST_WORKER_HOME", &kin_home)
                .env("KIN_UPDATE_TEST_WORKER_STAGE", &stage)
                .env("KIN_UPDATE_TEST_WORKER_SPEC", "macos")
                .env("KIN_UPDATE_TEST_CRASH_POINT", crash_point);
            if recover {
                command.env("KIN_UPDATE_TEST_WORKER_RECOVER", "1");
            }
            let output = test_subprocess_output(
                command,
                &format!("bundle rollback worker at {crash_point}"),
            )
            .unwrap();
            assert_eq!(
                output.status.code(),
                Some(86),
                "worker output: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        };

        // Leave a pre-commit transaction with the staged bundle live and the
        // original, when present, held in the journaled backup.
        worker("after-install-notifier-bundle", false);
        worker(point, true);

        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        recover_stale_transactions(&lock, MACOS_COMPONENTS).unwrap();
        assert_bundle_matches(&kin_home, MACOS_COMPONENTS, &old);
        if had_original {
            assert_eq!(notifier_executable_bytes(&kin_home), b"old-notifier");
        } else {
            assert!(
                !kin_home.join("lib").join(NOTIFIER_BUNDLE_DIR).exists(),
                "recovery of a first bundle install must end without a bundle"
            );
        }
        assert!(transaction_dirs(lock.root()).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn subprocess_crashes_during_bundle_rollback_recover_idempotently() {
        run_bundle_rollback_crash_case("after-rollback-remove-notifier-bundle", true);
        run_bundle_rollback_crash_case("after-rollback-restore-notifier-bundle", true);
        run_bundle_rollback_crash_case("after-rollback-remove-notifier-bundle", false);
    }

    /// The non-crash failure hooks immediately after each bundle mutation are
    /// also live, and each one unwinds the whole transaction before returning.
    #[cfg(unix)]
    #[test]
    #[serial]
    fn bundle_post_mutation_failures_restore_the_old_install_immediately() {
        for failure_point in [
            "after-backup-mutation-notifier-bundle",
            "after-install-mutation-notifier-bundle",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let kin_home = tmp.path().join("kin-home");
            let stage = tmp.path().join("stage");
            let _environment = isolated_update_environment(tmp.path(), &kin_home);
            write_bundle(&kin_home, MACOS_COMPONENTS, b"old-");
            write_notifier_bundle(&kin_home, b"old-notifier");
            let old = bundle_snapshot(&kin_home, MACOS_COMPONENTS);
            stage_archive(
                &full_macos_archive("kin-macos-aarch64"),
                "kin-macos-aarch64.tar.gz",
                &stage,
                MACOS_COMPONENTS,
            )
            .unwrap();
            let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
            let staged_identities = staged_identities_for_test(&stage, MACOS_COMPONENTS).unwrap();

            let error = install_staged_bundle_unix_with_hooks(
                &lock,
                &StagingLayout::open(&stage).unwrap(),
                MACOS_COMPONENTS,
                &staged_identities,
                "0.2.22",
                &test_restart_pending("0.2.22"),
                |_, _| Ok(()),
                |_, _| Ok(()),
                |point| {
                    if point == failure_point {
                        anyhow::bail!("injected bundle mutation failure at {point}");
                    }
                    Ok(())
                },
            )
            .expect_err("the bundle mutation failure must abort the transaction");
            let message = format!("{error:#}");
            assert!(message.contains(failure_point), "{message}");
            assert!(
                message.contains("previous bundle was restored"),
                "{message}"
            );
            assert_bundle_matches(&kin_home, MACOS_COMPONENTS, &old);
            assert_eq!(notifier_executable_bytes(&kin_home), b"old-notifier");
            assert!(transaction_dirs(&kin_home).unwrap().is_empty());
        }
    }

    #[cfg(unix)]
    struct CrashedUpdate {
        _tmp: tempfile::TempDir,
        kin_home: PathBuf,
        old: HashMap<String, Option<Vec<u8>>>,
        mcp_home: Option<PathBuf>,
        mcp_config: Option<PathBuf>,
        mcp_repo: Option<PathBuf>,
    }

    #[cfg(unix)]
    fn crash_update(point: &str, fail_install_index: Option<usize>) -> CrashedUpdate {
        crash_update_inner(point, fail_install_index, false, None)
    }

    #[cfg(unix)]
    fn crash_update_with_mcp(point: &str, fail_install_index: Option<usize>) -> CrashedUpdate {
        crash_update_inner(point, fail_install_index, true, None)
    }

    #[cfg(unix)]
    fn crash_update_with_umask(point: &str, umask: &str) -> CrashedUpdate {
        crash_update_inner(point, None, false, Some(umask))
    }

    #[cfg(unix)]
    fn crash_update_inner(
        point: &str,
        fail_install_index: Option<usize>,
        configure_mcp: bool,
        umask: Option<&str>,
    ) -> CrashedUpdate {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        let home = tmp.path().join("home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let old = bundle_snapshot(&kin_home, LINUX_COMPONENTS);
        stage_archive(
            &full_linux_archive("kin-linux-x86_64"),
            "kin-linux-x86_64.tar.gz",
            &stage,
            LINUX_COMPONENTS,
        )
        .unwrap();
        let (mcp_config, mcp_repo) = if configure_mcp {
            let config = home.join(".codex/config.toml");
            let repo = tmp.path().join("mcp-repo");
            fs::create_dir_all(config.parent().unwrap()).unwrap();
            fs::create_dir_all(repo.join(".kin")).unwrap();
            let repo = repo.canonicalize().unwrap();
            fs::write(
                &config,
                format!(
                    r#"[mcp_servers.kin]
command = "/old/Cellar/kin/0.2.21/bin/kin"
args = ["mcp", "start", "--repo", {:?}]
cwd = {:?}
"#,
                    repo.to_string_lossy(),
                    repo.to_string_lossy()
                ),
            )
            .unwrap();
            (Some(config), Some(repo))
        } else {
            fs::create_dir_all(&home).unwrap();
            (None, None)
        };
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "commands::update::tests::crash_recovery_worker",
                "--nocapture",
            ])
            .env("HOME", &home)
            .env("KIN_HOME", &kin_home)
            .env("KIN_UPDATE_TEST_WORKER_HOME", &kin_home)
            .env("KIN_UPDATE_TEST_WORKER_STAGE", &stage)
            .env("KIN_UPDATE_TEST_CRASH_POINT", point);
        if let Some(index) = fail_install_index {
            command.env("KIN_UPDATE_TEST_FAIL_INSTALL_INDEX", index.to_string());
        }
        if let Some(umask) = umask {
            command.env("KIN_UPDATE_TEST_UMASK", umask);
        }
        let output =
            test_subprocess_output(command, &format!("crash update worker at {point}")).unwrap();
        assert_eq!(
            output.status.code(),
            Some(86),
            "worker output: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        CrashedUpdate {
            _tmp: tmp,
            kin_home,
            old,
            mcp_home: configure_mcp.then_some(home),
            mcp_config,
            mcp_repo,
        }
    }

    #[test]
    fn incomplete_archive_is_rejected_before_install() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = make_tar_gz(&[
            ("kin-linux-x86_64/kin", b"kin"),
            ("kin-linux-x86_64/kin-daemon", b"daemon"),
        ]);

        let err = stage_archive(
            &archive,
            "kin-linux-x86_64.tar.gz",
            tmp.path(),
            LINUX_COMPONENTS,
        )
        .expect_err("missing VFS files must reject the archive");
        let message = format!("{err:#}");
        assert!(message.contains("kin-vfs"), "message: {message}");
    }

    /// A macOS release archive carries KinNotifier.app as a directory. The
    /// stager materializes it under the staging tree's `lib`, preserving the
    /// executable bit its executable needs to be launchable at all.
    ///
    /// Unix-only, and not because of the host this runs on: the primitives that
    /// materialize a bundle tree are `#[cfg(unix)]`, so on Windows the staging
    /// sink refuses a bundle outright. Every test below that stages or installs
    /// a bundle-carrying contract is gated for that reason. The rest of the
    /// bundle rules key on the component contract rather than the host and so
    /// hold everywhere, including a bundle offered to a contract that carries
    /// none.
    #[cfg(unix)]
    #[test]
    fn macos_archive_carrying_the_notifier_bundle_stages() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = full_macos_archive("kin-macos-aarch64");
        stage_archive(
            &archive,
            "kin-macos-aarch64.tar.gz",
            tmp.path(),
            MACOS_COMPONENTS,
        )
        .expect("an archive carrying the notification bundle must stage");

        let staged = tmp.path().join("lib").join(NOTIFIER_BUNDLE_DIR);
        assert_eq!(
            fs::read(staged.join("Contents/MacOS/KinNotifier")).unwrap(),
            b"new-notifier"
        );
        assert_eq!(
            fs::read(staged.join("Contents/Info.plist")).unwrap(),
            b"<plist>new</plist>"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for relative in ["", "Contents", "Contents/MacOS", "Contents/Resources"] {
                let mode = fs::metadata(staged.join(relative))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(
                    mode,
                    0o755,
                    "bundle directory {} must match every other install channel",
                    staged.join(relative).display()
                );
            }
            let mode = fs::metadata(staged.join("Contents/MacOS/KinNotifier"))
                .unwrap()
                .permissions()
                .mode();
            assert!(
                mode & 0o111 != 0,
                "a staged notifier that lost +x cannot be launched, mode {mode:o}"
            );
        }
    }

    /// The bundle belongs to the macOS archive alone. A Linux archive carrying
    /// one is not quietly skipped: skipping is how a member could smuggle
    /// itself past the component inventory unexamined.
    #[test]
    fn a_notifier_bundle_in_a_linux_archive_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = make_tar_gz(&[
            ("kin-linux-x86_64/kin", b"new-kin"),
            ("kin-linux-x86_64/kin-daemon", b"new-daemon"),
            ("kin-linux-x86_64/kin-vfs", b"new-vfs"),
            ("kin-linux-x86_64/libkin_vfs_shim.so", b"new-shim"),
            (
                "kin-linux-x86_64/KinNotifier.app/Contents/MacOS/KinNotifier",
                b"notifier",
            ),
        ]);
        let error = stage_archive(
            &archive,
            "kin-linux-x86_64.tar.gz",
            tmp.path(),
            LINUX_COMPONENTS,
        )
        .expect_err("a platform with no bundle must refuse one");
        assert!(format!("{error:#}").contains("unexpected file"));
    }

    /// A macOS archive whose bundle cannot post as Kin is refused at staging
    /// rather than installed and discovered later as a wrong sender name.
    #[cfg(unix)]
    #[test]
    fn a_macos_archive_missing_the_bundle_identity_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = make_tar_gz_with_modes(&[
            ("kin-macos-aarch64/kin", b"new-kin", 0o755),
            ("kin-macos-aarch64/kin-daemon", b"new-daemon", 0o755),
            ("kin-macos-aarch64/kin-vfs", b"new-vfs", 0o755),
            (
                "kin-macos-aarch64/libkin_vfs_shim.dylib",
                b"new-shim",
                0o644,
            ),
            (
                "kin-macos-aarch64/KinNotifier.app/Contents/MacOS/KinNotifier",
                b"notifier",
                0o755,
            ),
        ]);
        let error = stage_archive(
            &archive,
            "kin-macos-aarch64.tar.gz",
            tmp.path(),
            MACOS_COMPONENTS,
        )
        .expect_err("a bundle with no Info.plist has no identity to post under");
        assert!(format!("{error:#}").contains("Info.plist"), "{error:#}");
    }

    /// A macOS archive with no bundle at all is incomplete, not merely thinner:
    /// installing it would silently downgrade every notification to Script
    /// Editor for as long as that release stayed installed.
    #[test]
    fn a_macos_archive_without_a_bundle_is_incomplete() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = make_tar_gz(&[
            ("kin-macos-aarch64/kin", b"new-kin"),
            ("kin-macos-aarch64/kin-daemon", b"new-daemon"),
            ("kin-macos-aarch64/kin-vfs", b"new-vfs"),
            ("kin-macos-aarch64/libkin_vfs_shim.dylib", b"new-shim"),
        ]);
        let error = stage_archive(
            &archive,
            "kin-macos-aarch64.tar.gz",
            tmp.path(),
            MACOS_COMPONENTS,
        )
        .expect_err("a macOS archive must carry the notification bundle");
        assert!(
            format!("{error:#}").contains("notification bundle is missing"),
            "{error:#}"
        );
    }

    /// The identity is a fold over the whole tree, so it has to notice a change
    /// that leaves every path and size alone.
    #[test]
    fn bundle_identity_distinguishes_content_and_shape() {
        let member = |path: &str, executable: bool, sha: &str| BundleMember {
            path: path.to_string(),
            directory: false,
            executable,
            size_bytes: 4,
            sha256: sha.to_string(),
        };
        let base = vec![
            member("Contents/Info.plist", false, "aa"),
            member("Contents/MacOS/KinNotifier", true, "bb"),
        ];

        let identity = bundle_identity_from_members(&mut base.clone()).unwrap();
        // Reordering is not a change: the fold sorts first.
        let mut reversed = base.clone();
        reversed.reverse();
        assert_eq!(
            bundle_identity_from_members(&mut reversed).unwrap(),
            identity
        );

        // Content, the executable bit, and tree shape each move the digest.
        let mut edited = base.clone();
        edited[1].sha256 = "cc".to_string();
        assert_ne!(bundle_identity_from_members(&mut edited).unwrap(), identity);

        let mut unexecutable = base.clone();
        unexecutable[1].executable = false;
        assert_ne!(
            bundle_identity_from_members(&mut unexecutable).unwrap(),
            identity
        );

        let mut extra = base.clone();
        extra.push(member("Contents/Resources/Kin.icns", false, "dd"));
        assert_ne!(bundle_identity_from_members(&mut extra).unwrap(), identity);
    }

    #[test]
    fn bundle_member_paths_cannot_escape_the_bundle() {
        assert_eq!(
            notifier_bundle_member_path(Path::new(
                "kin-macos-aarch64/KinNotifier.app/Contents/MacOS/KinNotifier"
            ))
            .unwrap(),
            PathBuf::from("Contents/MacOS/KinNotifier")
        );
        // The bundle root itself carries no member.
        assert!(notifier_bundle_member_path(Path::new("KinNotifier.app")).is_err());
        assert!(notifier_bundle_member_path(Path::new("kin-macos-aarch64/kin")).is_err());
        let deep = format!(
            "KinNotifier.app/{}",
            ["a"; MAX_NOTIFIER_BUNDLE_DEPTH + 1].join("/")
        );
        assert!(notifier_bundle_member_path(Path::new(&deep)).is_err());
    }

    #[test]
    fn notifier_bundle_root_acceptance_is_structural_and_fail_closed() {
        let regular_root =
            make_tar_gz_with_modes(&[("kin-macos-aarch64/KinNotifier.app", b"", 0o755)]);
        let regular_error = stage_archive(
            &regular_root,
            "kin-macos-aarch64.tar.gz",
            tempfile::tempdir().unwrap().path(),
            MACOS_COMPONENTS,
        )
        .expect_err("a regular file cannot stand in for the bundle root");
        assert!(
            format!("{regular_error:#}").contains("must be a directory record"),
            "{regular_error:#}"
        );

        let nonempty_header = make_test_tar_header("kin-macos-aarch64/KinNotifier.app/", 1, b'5');
        let nonempty_root = make_raw_test_tar(nonempty_header, b"x");
        let nonempty_error = stage_archive(
            &nonempty_root,
            "kin-macos-aarch64.tar.gz",
            tempfile::tempdir().unwrap().path(),
            MACOS_COMPONENTS,
        )
        .expect_err("a directory root carrying payload bytes must be rejected");
        assert!(
            format!("{nonempty_error:#}").contains("has nonzero expanded size"),
            "{nonempty_error:#}"
        );

        let duplicate_root = make_tar_gz_with_modes(&[
            ("kin-macos-aarch64/KinNotifier.app/", b"", 0o755),
            ("kin-macos-aarch64/KinNotifier.app/", b"", 0o755),
        ]);
        let duplicate_error = stage_archive(
            &duplicate_root,
            "kin-macos-aarch64.tar.gz",
            tempfile::tempdir().unwrap().path(),
            MACOS_COMPONENTS,
        )
        .expect_err("duplicate structural roots must not be normalized away");
        assert!(
            format!("{duplicate_error:#}").contains("duplicate root entry"),
            "{duplicate_error:#}"
        );
    }

    /// An update must leave the installed notification bundle holding the bytes
    /// the new archive carries. A bundle that survives an update unchanged is a
    /// silent version skew: the CLI reports the new version while the sender
    /// identity, icon, and any notifier fix stay on the old release.
    #[cfg(unix)]
    #[test]
    #[serial]
    fn update_refreshes_the_installed_notifier_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        let _environment = isolated_update_environment(tmp.path(), &kin_home);
        write_bundle(&kin_home, MACOS_COMPONENTS, b"old-");
        write_notifier_bundle(&kin_home, b"old-notifier");
        assert_eq!(notifier_executable_bytes(&kin_home), b"old-notifier");

        let archive = full_macos_archive("kin-macos-aarch64");
        stage_archive(
            &archive,
            "kin-macos-aarch64.tar.gz",
            &stage,
            MACOS_COMPONENTS,
        )
        .unwrap();
        install_staged_bundle(
            &kin_home,
            &stage,
            MACOS_COMPONENTS,
            "0.2.22",
            &test_restart_pending("0.2.22"),
        )
        .unwrap();

        assert_eq!(fs::read(kin_home.join("bin/kin")).unwrap(), b"new-kin");
        assert_eq!(
            notifier_executable_bytes(&kin_home),
            b"new-notifier",
            "the update left the previous notification bundle in place"
        );
    }

    /// A failed update must leave the bundle as it found it. The bundle is
    /// swapped before the components, so by the time a component swap fails the
    /// new bundle is already live and the rollback has real work to undo.
    #[cfg(unix)]
    #[test]
    #[serial]
    fn a_failed_update_restores_the_previous_notifier_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        let _environment = isolated_update_environment(tmp.path(), &kin_home);
        write_bundle(&kin_home, MACOS_COMPONENTS, b"old-");
        write_notifier_bundle(&kin_home, b"old-notifier");

        let archive = full_macos_archive("kin-macos-aarch64");
        stage_archive(
            &archive,
            "kin-macos-aarch64.tar.gz",
            &stage,
            MACOS_COMPONENTS,
        )
        .unwrap();
        let error = install_staged_bundle_with_hook(
            &kin_home,
            &stage,
            MACOS_COMPONENTS,
            "0.2.22",
            &test_restart_pending("0.2.22"),
            |index, _| {
                if index == 2 {
                    anyhow::bail!("injected swap failure");
                }
                Ok(())
            },
        )
        .expect_err("the injected failure must fail the update");
        assert!(
            format!("{error:#}").contains("previous bundle was restored"),
            "{error:#}"
        );

        assert_eq!(
            notifier_executable_bytes(&kin_home),
            b"old-notifier",
            "a rolled-back update must not leave the new bundle installed"
        );
        assert_eq!(fs::read(kin_home.join("bin/kin")).unwrap(), b"old-kin");
        // The rollback also removes its own backup: a bundle left behind under a
        // transaction directory would be reported as an unexpected entry by the
        // next recovery.
        let leftovers: Vec<_> = fs::read_dir(&kin_home)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(TRANSACTION_PREFIX))
            .collect();
        assert!(leftovers.is_empty(), "retained transaction: {leftovers:?}");
    }

    /// A bundle is removed file by file, so unlike a component it can be caught
    /// half-way. A rollback that finds such a tree must still finish, because
    /// refusing it would leave every later update blocked behind a state only
    /// manual deletion could clear.
    #[cfg(unix)]
    #[test]
    #[serial]
    fn a_rollback_restores_the_bundle_over_a_partially_removed_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        let _environment = isolated_update_environment(tmp.path(), &kin_home);
        write_bundle(&kin_home, MACOS_COMPONENTS, b"old-");
        write_notifier_bundle(&kin_home, b"old-notifier");

        let archive = full_macos_archive("kin-macos-aarch64");
        stage_archive(
            &archive,
            "kin-macos-aarch64.tar.gz",
            &stage,
            MACOS_COMPONENTS,
        )
        .unwrap();
        let live_bundle = kin_home.join("lib").join(NOTIFIER_BUNDLE_DIR);
        install_staged_bundle_with_hook(
            &kin_home,
            &stage,
            MACOS_COMPONENTS,
            "0.2.22",
            &test_restart_pending("0.2.22"),
            |index, _| {
                // The bundle is installed before any component, so by the first
                // component swap the new bundle is live. Tear a file out of it
                // to stand in for a rollback interrupted mid-removal, then fail.
                if index == 0 {
                    fs::remove_file(live_bundle.join("Contents/Resources/Kin.icns")).unwrap();
                    anyhow::bail!("injected swap failure");
                }
                Ok(())
            },
        )
        .expect_err("the injected failure must fail the update");

        assert_eq!(
            notifier_executable_bytes(&kin_home),
            b"old-notifier",
            "a partial tree must not stop the original bundle being restored"
        );
        assert!(
            kin_home
                .join("lib")
                .join(NOTIFIER_BUNDLE_DIR)
                .join("Contents/Resources/Kin.icns")
                .exists(),
            "the restored bundle must be the whole original, not a repaired remnant"
        );
    }

    /// Rolling back the update that brought the very first bundle means leaving
    /// the install without one, not leaving the new one behind.
    #[cfg(unix)]
    #[test]
    #[serial]
    fn a_failed_first_bundle_install_removes_what_it_installed() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        let _environment = isolated_update_environment(tmp.path(), &kin_home);
        write_bundle(&kin_home, MACOS_COMPONENTS, b"old-");

        let archive = full_macos_archive("kin-macos-aarch64");
        stage_archive(
            &archive,
            "kin-macos-aarch64.tar.gz",
            &stage,
            MACOS_COMPONENTS,
        )
        .unwrap();
        install_staged_bundle_with_hook(
            &kin_home,
            &stage,
            MACOS_COMPONENTS,
            "0.2.22",
            &test_restart_pending("0.2.22"),
            |index, _| {
                if index == 2 {
                    anyhow::bail!("injected swap failure");
                }
                Ok(())
            },
        )
        .expect_err("the injected failure must fail the update");

        assert!(
            !kin_home.join("lib").join(NOTIFIER_BUNDLE_DIR).exists(),
            "a rolled-back first install must not leave its bundle behind"
        );
        assert_eq!(fs::read(kin_home.join("bin/kin")).unwrap(), b"old-kin");
    }

    /// A journal written before the bundle joined the transaction still has to
    /// be recoverable: the CLI that finishes a crashed update is often a newer
    /// one than the CLI that started it.
    #[test]
    fn a_journal_without_a_bundle_record_is_still_accepted() {
        let mut journal = TransactionJournal {
            schema_version: TRANSACTION_JOURNAL_SCHEMA_WITHOUT_BUNDLE,
            target_version: "0.2.22".to_string(),
            phase: TransactionPhase::Prepared,
            components: LINUX_COMPONENTS
                .iter()
                .map(|component| JournalComponent {
                    name: component.name.to_string(),
                    location: component.location,
                    required: component.required,
                    had_original: false,
                    install_new: true,
                    original_identity: None,
                    staged_identity: Some(bytes_identity(
                        format!("new-{}", component.name).as_bytes(),
                    )),
                })
                .collect(),
            notifier_bundle: JournalBundle::default(),
            restart_pending: test_restart_pending("0.2.22"),
            mcp_repair_pending: McpRepairPending {
                schema_version: MCP_REPAIR_MARKER_SCHEMA_VERSION,
                installed_version: "0.2.22".to_string(),
                recorded_at: "2026-07-16T00:00:00Z".to_string(),
                repair_required: false,
                targets: Vec::new(),
            },
        };
        // Fix the staged identities the restart obligations pin.
        for (name, bytes) in [
            ("kin", b"new-kin".as_slice()),
            ("kin-daemon", b"new-daemon".as_slice()),
            ("kin-vfs", b"new-vfs".as_slice()),
        ] {
            let component = journal
                .components
                .iter_mut()
                .find(|component| component.name == name)
                .unwrap();
            component.staged_identity = Some(bytes_identity(bytes));
        }
        validate_journal(&journal, LINUX_COMPONENTS)
            .expect("a schema 2 journal predates the bundle and must still recover");

        // The same schema claiming a bundle record it cannot describe is not a
        // journal this build wrote, so it is refused rather than guessed at.
        journal.notifier_bundle.staged_identity = Some(BundleIdentity {
            tree_sha256: "d".repeat(64),
            file_count: 3,
            total_bytes: 9,
        });
        let error = validate_journal(&journal, LINUX_COMPONENTS)
            .expect_err("a schema 2 journal cannot carry a bundle record");
        assert!(
            format!("{error:#}").contains("cannot describe"),
            "{error:#}"
        );
    }

    /// The skip must key on a whole path component. A file merely prefixed with
    /// the bundle name is still an unexpected archive entry.
    #[test]
    fn a_name_resembling_the_notifier_bundle_is_still_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = make_tar_gz(&[
            ("kin-macos-aarch64/kin", b"new-kin"),
            ("kin-macos-aarch64/kin-daemon", b"new-daemon"),
            ("kin-macos-aarch64/kin-vfs", b"new-vfs"),
            ("kin-macos-aarch64/libkin_vfs_shim.dylib", b"new-shim"),
            ("kin-macos-aarch64/KinNotifier.appx/payload", b"smuggled"),
        ]);
        let error = stage_archive(
            &archive,
            "kin-macos-aarch64.tar.gz",
            tmp.path(),
            MACOS_COMPONENTS,
        )
        .expect_err("a lookalike directory must not inherit the bundle exemption");
        assert!(format!("{error:#}").contains("unexpected file"));
    }

    #[test]
    fn notifier_bundle_entries_are_recognized_by_whole_component() {
        assert!(is_notifier_bundle_entry(Path::new(
            "kin-macos-aarch64/KinNotifier.app/Contents/MacOS/KinNotifier"
        )));
        assert!(is_notifier_bundle_entry(Path::new("KinNotifier.app")));
        // Prefix and suffix lookalikes must not match.
        assert!(!is_notifier_bundle_entry(Path::new(
            "kin-macos-aarch64/KinNotifier.appx/payload"
        )));
        assert!(!is_notifier_bundle_entry(Path::new(
            "kin-macos-aarch64/NotKinNotifier.app/payload"
        )));
        assert!(!is_notifier_bundle_entry(Path::new(
            "kin-macos-aarch64/kin"
        )));
    }

    #[test]
    fn in_memory_preflight_authenticates_complete_archive_shape_and_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = full_linux_archive("kin-linux-x86_64");
        stage_archive(
            &archive,
            "kin-linux-x86_64.tar.gz",
            tmp.path(),
            LINUX_COMPONENTS,
        )
        .unwrap();
        let identities = staged_identities_for_test(tmp.path(), LINUX_COMPONENTS).unwrap();
        let verified = validate_archive_payload_provenance(
            &archive,
            "kin-linux-x86_64.tar.gz",
            LINUX_COMPONENTS,
            &identities,
        )
        .unwrap();
        assert_eq!(verified, identities);

        let mut wrong_hash = identities.clone();
        wrong_hash.get_mut("kin").unwrap().sha256 = "0".repeat(64);
        assert!(format!(
            "{:#}",
            validate_archive_payload_provenance(
                &archive,
                "kin-linux-x86_64.tar.gz",
                LINUX_COMPONENTS,
                &wrong_hash,
            )
            .unwrap_err()
        )
        .contains("does not match artifact provenance"));

        let duplicate = make_tar_gz(&[
            ("kin-linux-x86_64/kin", b"new-kin"),
            ("kin-linux-x86_64/kin", b"new-kin"),
            ("kin-linux-x86_64/kin-daemon", b"new-daemon"),
            ("kin-linux-x86_64/kin-vfs", b"new-vfs"),
            ("kin-linux-x86_64/libkin_vfs_shim.so", b"new-shim"),
        ]);
        assert!(format!(
            "{:#}",
            validate_archive_payload_provenance(
                &duplicate,
                "kin-linux-x86_64.tar.gz",
                LINUX_COMPONENTS,
                &identities,
            )
            .unwrap_err()
        )
        .contains("duplicate component"));

        let unexpected = make_tar_gz(&[
            ("kin-linux-x86_64/README", b"unexpected"),
            ("kin-linux-x86_64/kin", b"new-kin"),
            ("kin-linux-x86_64/kin-daemon", b"new-daemon"),
            ("kin-linux-x86_64/kin-vfs", b"new-vfs"),
            ("kin-linux-x86_64/libkin_vfs_shim.so", b"new-shim"),
        ]);
        assert!(format!(
            "{:#}",
            validate_archive_payload_provenance(
                &unexpected,
                "kin-linux-x86_64.tar.gz",
                LINUX_COMPONENTS,
                &identities,
            )
            .unwrap_err()
        )
        .contains("unexpected file"));

        let unsafe_path = make_zip(&[
            ("../kin", b"new-kin"),
            ("kin-daemon", b"new-daemon"),
            ("kin-vfs", b"new-vfs"),
            ("libkin_vfs_shim.so", b"new-shim"),
        ]);
        assert!(format!(
            "{:#}",
            validate_archive_payload_provenance(
                &unsafe_path,
                "kin-linux-x86_64.zip",
                LINUX_COMPONENTS,
                &identities,
            )
            .unwrap_err()
        )
        .contains("unsafe or invalid file path"));

        let missing = make_tar_gz(&[
            ("kin-linux-x86_64/kin", b"new-kin"),
            ("kin-linux-x86_64/kin-daemon", b"new-daemon"),
        ]);
        assert!(format!(
            "{:#}",
            validate_archive_payload_provenance(
                &missing,
                "kin-linux-x86_64.tar.gz",
                LINUX_COMPONENTS,
                &identities,
            )
            .unwrap_err()
        )
        .contains("required component 'kin-vfs' is missing"));
    }

    #[test]
    fn archive_preflight_enforces_compressed_entry_and_aggregate_size_limits() {
        let temp = tempfile::tempdir().unwrap();
        let archive = full_linux_archive("kin-linux-x86_64");
        stage_archive(
            &archive,
            "kin-linux-x86_64.tar.gz",
            temp.path(),
            LINUX_COMPONENTS,
        )
        .unwrap();
        let identities = staged_identities_for_test(temp.path(), LINUX_COMPONENTS).unwrap();
        let limits = |compressed_bytes, entry_bytes, expanded_bytes| ArchiveSizeLimits {
            compressed_bytes,
            entry_bytes,
            expanded_bytes,
        };

        let compressed = validate_archive_payload_provenance_with_limits(
            &archive,
            "kin-linux-x86_64.tar.gz",
            LINUX_COMPONENTS,
            &identities,
            limits(archive.len() - 1, 1024, 4096),
        )
        .unwrap_err();
        assert!(format!("{compressed:#}").contains("compressed-size limit"));

        let per_entry = validate_archive_payload_provenance_with_limits(
            &archive,
            "kin-linux-x86_64.tar.gz",
            LINUX_COMPONENTS,
            &identities,
            limits(archive.len(), 7, 4096),
        )
        .unwrap_err();
        assert!(format!("{per_entry:#}").contains("per-entry expanded-size limit"));

        let aggregate = validate_archive_payload_provenance_with_limits(
            &archive,
            "kin-linux-x86_64.tar.gz",
            LINUX_COMPONENTS,
            &identities,
            limits(archive.len(), 1024, 20),
        )
        .unwrap_err();
        assert!(format!("{aggregate:#}").contains("aggregate expanded-size limit"));

        let mut wrong_declared_size = identities.clone();
        wrong_declared_size.get_mut("kin").unwrap().size_bytes += 1;
        let mismatch = validate_archive_payload_provenance_with_limits(
            &archive,
            "kin-linux-x86_64.tar.gz",
            LINUX_COMPONENTS,
            &wrong_declared_size,
            limits(archive.len(), 1024, 4096),
        )
        .unwrap_err();
        assert!(format!("{mismatch:#}").contains("declared size"));
    }

    #[test]
    fn tar_and_zip_reject_nonempty_directory_entries_before_payload_reads() {
        let entries = [
            ("kin", b"new-kin".as_slice()),
            ("kin-daemon", b"new-daemon".as_slice()),
            ("kin-vfs", b"new-vfs".as_slice()),
            ("libkin_vfs_shim.so", b"new-shim".as_slice()),
        ];
        let identities = entries
            .iter()
            .map(|(name, bytes)| ((*name).to_string(), bytes_identity(bytes)))
            .collect::<VerifiedStagedIdentities>();
        let tar = make_tar_gz_with_nonempty_directory(&entries);
        let tar_error = validate_archive_payload_provenance(
            &tar,
            "kin-linux-x86_64.tar.gz",
            LINUX_COMPONENTS,
            &identities,
        )
        .unwrap_err();
        assert!(format!("{tar_error:#}").contains("directory 'nonempty/' has nonzero"));

        let zip = make_zip(&[
            ("nonempty/", b"x"),
            ("kin", b"new-kin"),
            ("kin-daemon", b"new-daemon"),
            ("kin-vfs", b"new-vfs"),
            ("libkin_vfs_shim.so", b"new-shim"),
        ]);
        let zip_error = validate_archive_payload_provenance(
            &zip,
            "kin-linux-x86_64.zip",
            LINUX_COMPONENTS,
            &identities,
        )
        .unwrap_err();
        let zip_message = format!("{zip_error:#}");
        assert!(
            zip_message.contains("directory 'nonempty' has nonzero"),
            "unexpected ZIP validation error: {zip_message}"
        );
    }

    #[test]
    fn raw_tar_preflight_rejects_extension_sparse_and_link_records_before_allocation() {
        let limits = ArchiveSizeLimits {
            compressed_bytes: 64 * 1024,
            entry_bytes: 1,
            expanded_bytes: 1,
        };
        for (record_type, label) in [
            (b'L', "GNU longname"),
            (b'K', "GNU longlink"),
            (b'x', "PAX local"),
            (b'g', "PAX global"),
            (b'S', "GNU sparse"),
        ] {
            let header = make_test_tar_header("metadata", 8_589_934_591, record_type);
            let archive = make_raw_test_tar(header, &[]);
            let error = extract_named_file_from_tar_gz_with_limits(&archive, "kin", limits)
                .expect_err("extension records must be rejected before their payload is read");
            let message = format!("{error:#}");
            assert!(
                message.contains("unsupported extension, sparse, or special record type"),
                "{label} produced the wrong error: {message}"
            );
            assert!(
                !message.contains("per-entry expanded-size limit"),
                "{label} was size-accounted before its type was rejected: {message}"
            );
        }
    }

    #[test]
    fn raw_tar_preflight_validates_checksum_size_payload_and_padding() {
        let limits = ArchiveSizeLimits {
            compressed_bytes: 64 * 1024,
            entry_bytes: 1024,
            expanded_bytes: 1024,
        };

        let mut bad_checksum = make_test_tar_header("kin", 1, b'0');
        bad_checksum[0] ^= 1;
        let error = extract_named_file_from_tar_gz_with_limits(
            &make_raw_test_tar(bad_checksum, b"x"),
            "kin",
            limits,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("header checksum mismatch"));

        let mut base_256_size = make_test_tar_header("kin", 1, b'0');
        base_256_size[124] = 0x80;
        refresh_test_tar_checksum(&mut base_256_size);
        let error = extract_named_file_from_tar_gz_with_limits(
            &make_raw_test_tar(base_256_size, b"x"),
            "kin",
            limits,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("unsupported base-256 encoding"));

        let truncated_header = make_test_tar_header("kin", 10, b'0');
        let mut truncated = Vec::from(truncated_header);
        truncated.extend_from_slice(b"abc");
        let error =
            extract_named_file_from_tar_gz_with_limits(&gzip_test_tar(&truncated), "kin", limits)
                .unwrap_err();
        assert!(format!("{error:#}").contains("truncated tar entry payload"));

        let header = make_test_tar_header("kin", 1, b'0');
        let mut nonzero_padding = Vec::from(header);
        nonzero_padding.push(b'x');
        nonzero_padding.push(1);
        nonzero_padding.resize(1024, 0);
        nonzero_padding.extend_from_slice(&[0_u8; 1024]);
        let error = extract_named_file_from_tar_gz_with_limits(
            &gzip_test_tar(&nonzero_padding),
            "kin",
            limits,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("nonzero padding"));
    }

    #[test]
    fn raw_tar_preflight_globally_bounds_a_small_gzip_bomb() {
        let raw = vec![0_u8; MAX_TAR_FORMAT_OVERHEAD_BYTES as usize + 1025];
        let archive = gzip_test_tar(&raw);
        assert!(
            archive.len() < 16 * 1024,
            "fixture must remain a small compressed bomb, got {} bytes",
            archive.len()
        );
        let error = extract_named_file_from_tar_gz_with_limits(
            &archive,
            "kin",
            ArchiveSizeLimits {
                compressed_bytes: archive.len(),
                entry_bytes: 0,
                expanded_bytes: 0,
            },
        )
        .expect_err("every decompressed trailer byte must count toward the global bound");
        assert!(format!("{error:#}").contains("global limit"));
    }

    #[test]
    #[serial]
    fn full_bundle_install_includes_vfs_and_shim_under_custom_root() {
        let tmp = tempfile::tempdir().unwrap();
        let custom_home = tmp.path().join("custom-kin-home");
        let stage = tmp.path().join("stage");
        let _environment = isolated_update_environment(tmp.path(), &custom_home);
        let _cwd = CwdGuard::set(tmp.path());
        write_bundle(&custom_home, LINUX_COMPONENTS, b"old-");

        let archive = full_linux_archive("kin-linux-x86_64");
        stage_archive(
            &archive,
            "kin-linux-x86_64.tar.gz",
            &stage,
            LINUX_COMPONENTS,
        )
        .unwrap();
        let outcome = install_staged_bundle(
            &custom_home,
            &stage,
            LINUX_COMPONENTS,
            "0.2.22",
            &test_restart_pending("0.2.22"),
        )
        .unwrap();

        assert!(outcome.retained_backup.is_none());
        assert_eq!(fs::read(custom_home.join("bin/kin")).unwrap(), b"new-kin");
        assert_eq!(
            fs::read(custom_home.join("bin/kin-daemon")).unwrap(),
            b"new-daemon"
        );
        assert_eq!(
            fs::read(custom_home.join("bin/kin-vfs")).unwrap(),
            b"new-vfs"
        );
        assert_eq!(
            fs::read(custom_home.join("lib/libkin_vfs_shim.so")).unwrap(),
            b"new-shim"
        );
        assert!(
            !custom_home.join("bin/kin-mcp").exists(),
            "obsolete standalone MCP binary must not survive the bundle update"
        );
    }

    #[test]
    #[serial]
    fn install_failure_rolls_back_every_component() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        let _environment = isolated_update_environment(tmp.path(), &kin_home);
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let _env = fixture_home(&tmp, &kin_home);
        let expected: Vec<_> = LINUX_COMPONENTS
            .iter()
            .map(|component| {
                (
                    component_path(&kin_home, *component),
                    fs::read(component_path(&kin_home, *component)).unwrap(),
                )
            })
            .collect();

        let archive = full_linux_archive("kin-linux-x86_64");
        stage_archive(
            &archive,
            "kin-linux-x86_64.tar.gz",
            &stage,
            LINUX_COMPONENTS,
        )
        .unwrap();

        let err = install_staged_bundle_with_hook(
            &kin_home,
            &stage,
            LINUX_COMPONENTS,
            "0.2.22",
            &test_restart_pending("0.2.22"),
            |index, _| {
                if index == 2 {
                    anyhow::bail!("injected swap failure");
                }
                Ok(())
            },
        )
        .expect_err("the injected failure must abort the transaction");
        assert!(
            format!("{err:#}").contains("previous bundle was restored"),
            "unexpected rollback failure: {err:#}"
        );
        for (path, bytes) in expected {
            assert_eq!(fs::read(&path).unwrap(), bytes, "{}", path.display());
        }
        let leftovers: Vec<_> = fs::read_dir(&kin_home)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".update-backup-")
            })
            .collect();
        assert!(leftovers.is_empty(), "rollback backup should be cleaned");
    }

    #[test]
    fn staging_constructor_failures_remove_the_owned_root() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        #[cfg(unix)]
        let failure_points = [
            "staging-root",
            "staging-bin",
            "staging-lib",
            "staging-validated",
        ];
        #[cfg(not(unix))]
        let failure_points = ["staging-root", "staging-validated"];

        for failure_point in failure_points {
            let error = StagingDir::create_with_hook(&lock, |point| {
                if point == failure_point {
                    anyhow::bail!("injected staging constructor failure at {point}");
                }
                Ok(())
            })
            .err()
            .expect("the constructor failure must be injected");
            assert!(format!("{error:#}").contains(failure_point));
            let leftovers = fs::read_dir(&kin_home)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(STAGING_PREFIX)
                })
                .collect::<Vec<_>>();
            assert!(
                leftovers.is_empty(),
                "staging root leaked after {failure_point}: {leftovers:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_transaction_constructor_failures_remove_the_owned_root() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        let install = lock.install().unwrap();

        for failure_point in [
            "transaction-root",
            "transaction-old",
            "transaction-old-bin",
            "transaction-old-lib",
            "transaction-validated",
        ] {
            let error = TransactionLayout::create_with_hook(install, |point| {
                if point == failure_point {
                    anyhow::bail!("injected transaction constructor failure at {point}");
                }
                Ok(())
            })
            .expect_err("the constructor failure must be injected");
            assert!(format!("{error:#}").contains(failure_point));
            assert!(
                transaction_dirs(&kin_home).unwrap().is_empty(),
                "transaction root leaked after {failure_point}"
            );
        }
    }

    #[cfg(not(unix))]
    #[test]
    fn non_unix_transaction_constructor_failures_remove_the_owned_root() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        fs::create_dir(&kin_home).unwrap();

        for failure_point in [
            "transaction-root",
            "transaction-old",
            "transaction-old-bin",
            "transaction-old-lib",
            "transaction-validated",
        ] {
            let error = create_transaction_root_with_hook(&kin_home, |point| {
                if point == failure_point {
                    anyhow::bail!("injected transaction constructor failure at {point}");
                }
                Ok(())
            })
            .expect_err("the constructor failure must be injected");
            assert!(format!("{error:#}").contains(failure_point));
            assert!(
                transaction_dirs(&kin_home).unwrap().is_empty(),
                "transaction root leaked after {failure_point}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn every_post_mutation_precommit_error_restores_the_old_bundle_immediately() {
        for failure_point in [
            "after-backup-mutation-0",
            "after-install-mutation-0",
            "precommit-validated",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let kin_home = tmp.path().join("kin-home");
            let stage = tmp.path().join("stage");
            let home = tmp.path().join("home");
            fs::create_dir(&home).unwrap();
            let _home = EnvVarGuard::set("HOME", &home);
            let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
            write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
            let expected = bundle_snapshot(&kin_home, LINUX_COMPONENTS);
            stage_archive(
                &full_linux_archive("kin-linux-x86_64"),
                "kin-linux-x86_64.tar.gz",
                &stage,
                LINUX_COMPONENTS,
            )
            .unwrap();
            let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
            let verified_staged_identities =
                staged_identities_for_test(&stage, LINUX_COMPONENTS).unwrap();

            let error = install_staged_bundle_unix_with_hooks(
                &lock,
                &StagingLayout::open(&stage).unwrap(),
                LINUX_COMPONENTS,
                &verified_staged_identities,
                "0.2.22",
                &test_restart_pending("0.2.22"),
                |_, _| Ok(()),
                |_, _| Ok(()),
                |point| {
                    if point == failure_point {
                        anyhow::bail!("injected precommit failure at {point}");
                    }
                    Ok(())
                },
            )
            .expect_err("the precommit failure must abort the transaction");
            let message = format!("{error:#}");
            assert!(message.contains(failure_point), "{message}");
            assert!(
                message.contains("previous bundle was restored"),
                "{message}"
            );
            assert_bundle_matches(&kin_home, LINUX_COMPONENTS, &expected);
            assert!(
                transaction_dirs(&kin_home).unwrap().is_empty(),
                "rollback must clean the transaction after {failure_point}"
            );
        }
    }

    #[test]
    fn crash_recovery_worker() {
        let Some(kin_home) = std::env::var_os("KIN_UPDATE_TEST_WORKER_HOME") else {
            return;
        };
        #[cfg(unix)]
        if let Ok(value) = std::env::var("KIN_UPDATE_TEST_UMASK") {
            let mode = u32::from_str_radix(&value, 8).expect("test umask must be octal");
            unsafe {
                libc::umask(mode as libc::mode_t);
            }
        }
        // The contract under test is a parameter, not a constant: the
        // notification bundle's transaction steps exist only on a spec that
        // carries one, so a worker hardcoded to the Linux contract can never
        // reach their fault-injection points.
        let spec = worker_spec();
        if std::env::var_os("KIN_UPDATE_TEST_WORKER_RECOVER").is_some() {
            let lock = InstallRootLock::acquire_existing(Path::new(&kin_home)).unwrap();
            recover_stale_transactions(&lock, spec)
                .expect("crash worker must reach its configured recovery kill point");
            return;
        }
        let stage = std::env::var_os("KIN_UPDATE_TEST_WORKER_STAGE")
            .expect("crash worker stage must be provided");
        let fail_index = std::env::var("KIN_UPDATE_TEST_FAIL_INSTALL_INDEX")
            .ok()
            .and_then(|value| value.parse::<usize>().ok());
        install_staged_bundle_with_hook(
            Path::new(&kin_home),
            Path::new(&stage),
            spec,
            "0.2.22",
            &test_restart_pending("0.2.22"),
            |index, _| {
                if fail_index == Some(index) {
                    anyhow::bail!("injected crash-worker install failure");
                }
                Ok(())
            },
        )
        .expect("crash worker must reach its configured kill point");
    }

    #[test]
    fn subprocess_crashes_before_commit_recover_the_old_bundle() {
        for point in ["after-backup-1", "after-backup-4", "after-install-1"] {
            run_crash_recovery_case(point, false);
        }
    }

    #[cfg(unix)]
    #[test]
    fn canonical_launcher_survives_atomic_rollback_crash_and_recovery() {
        use std::os::unix::fs::PermissionsExt;

        let state = crash_update("after-install-3", None);
        let home = state._tmp.path().join("rollback-home");
        fs::create_dir_all(&home).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "commands::update::tests::crash_recovery_worker",
                "--nocapture",
            ])
            .env("HOME", &home)
            .env("KIN_HOME", &state.kin_home)
            .env("KIN_UPDATE_TEST_WORKER_HOME", &state.kin_home)
            .env("KIN_UPDATE_TEST_WORKER_RECOVER", "1")
            .env("KIN_UPDATE_TEST_CRASH_POINT", "after-rollback-remove-kin");
        let output = test_subprocess_output(
            command,
            "crash recovery worker at after-rollback-remove-kin",
        )
        .unwrap();
        assert_eq!(
            output.status.code(),
            Some(86),
            "worker output: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let launcher = state.kin_home.join("bin/kin");
        assert_eq!(
            fs::read(&launcher).unwrap().as_slice(),
            state.old["kin"].as_deref().unwrap()
        );
        assert_ne!(
            fs::metadata(&launcher).unwrap().permissions().mode() & 0o111,
            0,
            "the canonical launcher must remain executable at the rollback crash point"
        );

        let lock = InstallRootLock::acquire_existing(&state.kin_home).unwrap();
        recover_stale_transactions(&lock, LINUX_COMPONENTS).unwrap();
        assert_bundle_matches(&state.kin_home, LINUX_COMPONENTS, &state.old);
        assert!(transaction_dirs(lock.root()).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn restrictive_umask_keeps_updater_state_private_and_recoverable() {
        use std::os::unix::fs::PermissionsExt;

        fn assert_mode(path: &Path, expected: u32) {
            let actual = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(actual, expected, "unexpected mode at {}", path.display());
        }

        let state = crash_update_with_umask("after-commit", "0777");
        let transaction = only_transaction(&state.kin_home);
        assert_mode(&state.kin_home, 0o700);
        assert_mode(&state.kin_home.join("bin"), 0o700);
        assert_mode(&state.kin_home.join("lib"), 0o700);
        assert_mode(&state.kin_home.join("update.lock"), 0o600);
        assert_mode(&transaction, 0o700);
        assert_mode(&transaction.join("old"), 0o700);
        assert_mode(&transaction.join("old/bin"), 0o700);
        assert_mode(&transaction.join("old/lib"), 0o700);
        assert_mode(&transaction.join(TRANSACTION_JOURNAL), 0o600);
        for component in LINUX_COMPONENTS {
            let live = component_path(&state.kin_home, *component);
            if live.exists() {
                assert_mode(
                    &live,
                    if component.location == ComponentLocation::Bin {
                        0o755
                    } else {
                        0o644
                    },
                );
            }
            let backup = component_path(&transaction.join("old"), *component);
            if backup.exists() {
                assert_mode(
                    &backup,
                    if component.location == ComponentLocation::Bin {
                        0o755
                    } else {
                        0o644
                    },
                );
            }
        }

        let lock = InstallRootLock::acquire_existing(&state.kin_home).unwrap();
        recover_stale_transactions(&lock, LINUX_COMPONENTS).unwrap();
        assert!(transaction_dirs(lock.root()).unwrap().is_empty());
        assert_mode(&restart_pending_path(lock.root()), 0o600);
        assert_mode(&lock.root().join("bin/kin"), 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn crash_created_journal_temps_are_cleaned_before_recovery_inventory() {
        for point in [
            "before-journal-rename-prepared",
            "before-journal-rename-installing",
        ] {
            let state = crash_update(point, None);
            let transaction = only_transaction(&state.kin_home);
            let temp_names: Vec<_> = fs::read_dir(&transaction)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|name| is_updater_journal_temp_name(name))
                .collect();
            assert_eq!(temp_names.len(), 1, "{point}");
            assert_eq!(
                transaction.join(TRANSACTION_JOURNAL).is_file(),
                point == "before-journal-rename-installing",
                "{point}"
            );

            let lock = InstallRootLock::acquire_existing(&state.kin_home).unwrap();
            recover_stale_transactions(&lock, LINUX_COMPONENTS).unwrap();
            assert_bundle_matches(&state.kin_home, LINUX_COMPONENTS, &state.old);
            assert!(transaction_dirs(lock.root()).unwrap().is_empty(), "{point}");

            let exact_after_first = bundle_snapshot(&state.kin_home, LINUX_COMPONENTS);
            recover_stale_transactions(&lock, LINUX_COMPONENTS).unwrap();
            assert_bundle_matches(&state.kin_home, LINUX_COMPONENTS, &exact_after_first);
            assert!(transaction_dirs(lock.root()).unwrap().is_empty(), "{point}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn journal_scratch_replacement_during_quarantine_is_retained() {
        let tmp = tempfile::tempdir().unwrap();
        let name = format!(".journal.json.tmp-{}", uuid::Uuid::new_v4());
        let original = tmp.path().join(&name);
        let held_original = tmp.path().join("held-original");
        let victim = tmp.path().join("victim");
        fs::write(&original, b"verified-scratch").unwrap();
        fs::write(&victim, b"must-survive").unwrap();
        let root = AnchoredDir::open_ambient(tmp.path()).unwrap();

        let error = root
            .quarantine_verified_regular_with_hooks(
                &name,
                "update journal scratch file",
                |_| {
                    fs::rename(&original, &held_original)?;
                    fs::rename(&victim, &original)?;
                    Ok(())
                },
                |_| Ok(()),
                || Ok(()),
            )
            .expect_err("a replacement moved into quarantine must not be unlinked");

        assert!(format!("{error:#}").contains("changed while being quarantined"));
        assert_eq!(fs::read(&held_original).unwrap(), b"verified-scratch");
        let quarantined = fs::read_dir(tmp.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(is_updater_journal_quarantine_name)
            })
            .expect("the raced replacement must remain quarantined");
        assert_eq!(fs::read(quarantined).unwrap(), b"must-survive");
    }

    #[cfg(unix)]
    #[test]
    fn journal_quarantine_replacement_before_unlink_is_retained() {
        let tmp = tempfile::tempdir().unwrap();
        let name = format!(".journal.json.tmp-{}", uuid::Uuid::new_v4());
        fs::write(tmp.path().join(&name), b"verified-scratch").unwrap();
        fs::write(tmp.path().join("victim"), b"must-survive").unwrap();
        let root = AnchoredDir::open_ambient(tmp.path()).unwrap();
        let held_original = tmp.path().join("held-original");

        let error = root
            .quarantine_verified_regular_with_hooks(
                &name,
                "update journal scratch file",
                |_| Ok(()),
                |quarantine| {
                    fs::rename(tmp.path().join(quarantine), &held_original)?;
                    fs::rename(tmp.path().join("victim"), tmp.path().join(quarantine))?;
                    Ok(())
                },
                || Ok(()),
            )
            .expect_err("a replacement at the quarantine path must not be unlinked");

        assert!(format!("{error:#}").contains("changed before unlink"));
        assert_eq!(fs::read(&held_original).unwrap(), b"verified-scratch");
        let quarantined = fs::read_dir(tmp.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(is_updater_journal_quarantine_name)
            })
            .expect("the raced replacement must remain at the quarantine path");
        assert_eq!(fs::read(quarantined).unwrap(), b"must-survive");
    }

    #[cfg(unix)]
    fn assert_journal_temp_impostor_rejected(mutate: impl FnOnce(&Path, &Path)) {
        let state = crash_update("before-journal-rename-prepared", None);
        let transaction = only_transaction(&state.kin_home);
        let temp = fs::read_dir(&transaction)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(is_updater_journal_temp_name)
            })
            .unwrap();
        fs::remove_file(&temp).unwrap();
        let victim = state._tmp.path().join("journal-temp-victim");
        fs::write(&victim, b"must-survive").unwrap();
        mutate(&temp, &victim);
        let before = bundle_snapshot(&state.kin_home, LINUX_COMPONENTS);

        let lock = InstallRootLock::acquire_existing(&state.kin_home).unwrap();
        let error = recover_stale_transactions(&lock, LINUX_COMPONENTS)
            .expect_err("journal temp impostor must fail closed");
        assert!(
            format!("{error:#}").contains("not a regular non-symlink file"),
            "{error:#}"
        );
        assert_bundle_matches(&state.kin_home, LINUX_COMPONENTS, &before);
        assert_eq!(fs::read(&victim).unwrap(), b"must-survive");
        assert!(temp.exists());
        assert!(transaction.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_journal_temp_impostor_is_retained() {
        use std::os::unix::fs::symlink;
        assert_journal_temp_impostor_rejected(|temp, victim| symlink(victim, temp).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn directory_journal_temp_impostor_is_retained() {
        assert_journal_temp_impostor_rejected(|temp, _| fs::create_dir(temp).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn fifo_journal_temp_impostor_is_retained_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        assert_journal_temp_impostor_rejected(|temp, _| {
            let path = CString::new(temp.as_os_str().as_bytes()).unwrap();
            // SAFETY: `path` is a valid NUL-terminated pathname for this call.
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        });
    }

    #[test]
    fn subprocess_crashes_after_commit_recover_the_new_bundle_and_marker() {
        for point in ["after-commit", "after-restart-marker"] {
            run_crash_recovery_case(point, true);
        }
    }

    #[cfg(unix)]
    fn only_transaction(kin_home: &Path) -> PathBuf {
        let transactions = transaction_dirs(kin_home).unwrap();
        assert_eq!(transactions.len(), 1);
        transactions.into_iter().next().unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn rollback_missing_backup_accepts_exact_original() {
        let state = crash_update("after-install-1", None);
        let transaction = only_transaction(&state.kin_home);
        let component = LINUX_COMPONENTS[0];
        let live = component_path(&state.kin_home, component);
        let backup = component_path(&transaction.join("old"), component);
        fs::remove_file(&live).unwrap();
        fs::rename(&backup, &live).unwrap();

        let lock = InstallRootLock::acquire_existing(&state.kin_home).unwrap();
        recover_stale_transactions(&lock, LINUX_COMPONENTS).unwrap();
        assert_bundle_matches(&state.kin_home, LINUX_COMPONENTS, &state.old);
        assert!(transaction_dirs(lock.root()).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn rollback_missing_backup_rejects_staged_and_retains_transaction() {
        let state = crash_update("after-install-1", None);
        let transaction = only_transaction(&state.kin_home);
        let component = LINUX_COMPONENTS[0];
        let backup = component_path(&transaction.join("old"), component);
        fs::remove_file(backup).unwrap();
        let before = bundle_snapshot(&state.kin_home, LINUX_COMPONENTS);

        let lock = InstallRootLock::acquire_existing(&state.kin_home).unwrap();
        let error = recover_stale_transactions(&lock, LINUX_COMPONENTS)
            .expect_err("staged live bytes without their backup are ambiguous");
        assert!(format!("{error:#}").contains("backup is missing"));
        assert_bundle_matches(&state.kin_home, LINUX_COMPONENTS, &before);
        assert_eq!(transaction_dirs(lock.root()).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn rollback_missing_backup_rejects_unknown_and_retains_transaction() {
        let state = crash_update("after-install-1", None);
        let transaction = only_transaction(&state.kin_home);
        let component = LINUX_COMPONENTS[0];
        fs::remove_file(component_path(&transaction.join("old"), component)).unwrap();
        fs::write(
            component_path(&state.kin_home, component),
            b"attacker-bytes",
        )
        .unwrap();
        let before = bundle_snapshot(&state.kin_home, LINUX_COMPONENTS);

        let lock = InstallRootLock::acquire_existing(&state.kin_home).unwrap();
        let error = recover_stale_transactions(&lock, LINUX_COMPONENTS)
            .expect_err("unknown live bytes without their backup are ambiguous");
        assert!(format!("{error:#}").contains("backup is missing"));
        assert_bundle_matches(&state.kin_home, LINUX_COMPONENTS, &before);
        assert_eq!(transaction_dirs(lock.root()).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn committed_recovery_rejects_staged_hash_mismatch_and_retains_backup() {
        let state = crash_update("after-commit", None);
        let transaction = only_transaction(&state.kin_home);
        fs::write(state.kin_home.join("bin/kin-daemon"), b"tampered-new").unwrap();
        let before = bundle_snapshot(&state.kin_home, LINUX_COMPONENTS);

        let lock = InstallRootLock::acquire_existing(&state.kin_home).unwrap();
        let error = recover_stale_transactions(&lock, LINUX_COMPONENTS)
            .expect_err("committed live bytes must match staged journal identities");
        assert!(format!("{error:#}").contains("recorded staged identity"));
        assert_bundle_matches(&state.kin_home, LINUX_COMPONENTS, &before);
        assert!(transaction.is_dir());
        assert_eq!(transaction_dirs(lock.root()).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn rollback_crashes_after_each_remove_or_restore_recover_idempotently() {
        let points = [
            "after-rollback-restore-libkin_vfs_shim.so",
            "after-rollback-restore-kin-mcp",
            "after-rollback-remove-kin-vfs",
            "after-rollback-restore-kin-vfs",
            "after-rollback-remove-kin-daemon",
            "after-rollback-restore-kin-daemon",
        ];
        for point in points {
            let state = crash_update(point, Some(2));
            assert_eq!(
                transaction_dirs(&state.kin_home).unwrap().len(),
                1,
                "{point}"
            );
            let lock = InstallRootLock::acquire_existing(&state.kin_home).unwrap();
            recover_stale_transactions(&lock, LINUX_COMPONENTS).unwrap();
            assert_bundle_matches(&state.kin_home, LINUX_COMPONENTS, &state.old);
            assert!(transaction_dirs(lock.root()).unwrap().is_empty());
            let after_first = bundle_snapshot(&state.kin_home, LINUX_COMPONENTS);
            recover_stale_transactions(&lock, LINUX_COMPONENTS).unwrap();
            assert_bundle_matches(&state.kin_home, LINUX_COMPONENTS, &after_first);
        }
    }

    #[cfg(unix)]
    fn assert_malicious_backup_rejected(mutate: impl FnOnce(&Path, &Path, &Path)) {
        let state = crash_update("after-install-1", None);
        let transaction = only_transaction(&state.kin_home);
        let victim = state._tmp.path().join("outside-victim");
        fs::write(&victim, b"must-survive").unwrap();
        mutate(&transaction, &state.kin_home, &victim);
        let before = bundle_snapshot(&state.kin_home, LINUX_COMPONENTS);

        let lock = InstallRootLock::acquire_existing(&state.kin_home).unwrap();
        recover_stale_transactions(&lock, LINUX_COMPONENTS)
            .expect_err("malformed backup authority must fail closed");
        assert_bundle_matches(&state.kin_home, LINUX_COMPONENTS, &before);
        assert_eq!(fs::read(&victim).unwrap(), b"must-survive");
        assert!(transaction.is_dir());
        assert_eq!(transaction_dirs(lock.root()).unwrap().len(), 1);
        assert!(!restart_pending_path(lock.root()).exists());
        assert!(!mcp_repair_pending_path(lock.root()).exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_backup_to_outside_victim_is_rejected_without_live_mutation() {
        use std::os::unix::fs::symlink;
        assert_malicious_backup_rejected(|transaction, _, victim| {
            let backup = transaction.join("old/bin/kin-daemon");
            fs::remove_file(&backup).unwrap();
            symlink(victim, backup).unwrap();
        });
    }

    #[cfg(unix)]
    #[test]
    fn directory_backup_is_rejected_without_live_mutation() {
        assert_malicious_backup_rejected(|transaction, _, _| {
            let backup = transaction.join("old/bin/kin-daemon");
            fs::remove_file(&backup).unwrap();
            fs::create_dir(backup).unwrap();
        });
    }

    #[cfg(unix)]
    #[test]
    fn fifo_backup_is_rejected_without_blocking_or_live_mutation() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        assert_malicious_backup_rejected(|transaction, _, _| {
            let backup = transaction.join("old/bin/kin-daemon");
            fs::remove_file(&backup).unwrap();
            let path = CString::new(backup.as_os_str().as_bytes()).unwrap();
            // SAFETY: `path` is a valid NUL-terminated pathname owned for the
            // duration of the call; mode contains only permission bits.
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_old_bin_directory_is_rejected_without_live_mutation() {
        use std::os::unix::fs::symlink;
        assert_malicious_backup_rejected(|transaction, _, victim| {
            let outside = victim.parent().unwrap().join("outside-bin");
            fs::create_dir(&outside).unwrap();
            fs::rename(
                transaction.join("old/bin"),
                transaction.join("old/bin-held"),
            )
            .unwrap();
            symlink(&outside, transaction.join("old/bin")).unwrap();
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_old_lib_directory_is_rejected_without_live_mutation() {
        use std::os::unix::fs::symlink;
        assert_malicious_backup_rejected(|transaction, _, victim| {
            let outside = victim.parent().unwrap().join("outside-lib");
            fs::create_dir(&outside).unwrap();
            fs::rename(
                transaction.join("old/lib"),
                transaction.join("old/lib-held"),
            )
            .unwrap();
            symlink(&outside, transaction.join("old/lib")).unwrap();
        });
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn replacing_bin_before_first_backup_cannot_redirect_mutation() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        let _environment = isolated_update_environment(tmp.path(), &kin_home);
        let outside = tmp.path().join("outside-bin");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let _env = fixture_home(&tmp, &kin_home);
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("kin-daemon"), b"outside-victim").unwrap();
        stage_archive(
            &full_linux_archive("kin-linux-x86_64"),
            "kin-linux-x86_64.tar.gz",
            &stage,
            LINUX_COMPONENTS,
        )
        .unwrap();
        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        let verified_staged_identities =
            staged_identities_for_test(&stage, LINUX_COMPONENTS).unwrap();

        let error = install_staged_bundle_unix_with_hooks(
            &lock,
            &StagingLayout::open(&stage).unwrap(),
            LINUX_COMPONENTS,
            &verified_staged_identities,
            "0.2.22",
            &test_restart_pending("0.2.22"),
            |index, _| {
                if index == 0 {
                    fs::rename(kin_home.join("bin"), kin_home.join("bin-original"))?;
                    symlink(&outside, kin_home.join("bin"))?;
                }
                Ok(())
            },
            |_, _| Ok(()),
            |_| Ok(()),
        )
        .expect_err("replaced bin binding must abort before backup");
        assert!(format!("{error:#}").contains("binding changed"));
        assert_eq!(
            fs::read(outside.join("kin-daemon")).unwrap(),
            b"outside-victim"
        );
        assert!(!outside.join("kin").exists());
        assert_eq!(
            fs::read(kin_home.join("bin-original/kin-daemon")).unwrap(),
            b"old-kin-daemon"
        );
        assert_eq!(transaction_dirs(&kin_home).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn replacing_lib_before_shim_install_cannot_redirect_mutation() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        let outside = tmp.path().join("outside-lib");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let _env = fixture_home(&tmp, &kin_home);
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("libkin_vfs_shim.so"), b"outside-victim").unwrap();
        stage_archive(
            &full_linux_archive("kin-linux-x86_64"),
            "kin-linux-x86_64.tar.gz",
            &stage,
            LINUX_COMPONENTS,
        )
        .unwrap();

        let error = install_staged_bundle_with_hook(
            &kin_home,
            &stage,
            LINUX_COMPONENTS,
            "0.2.22",
            &test_restart_pending("0.2.22"),
            |index, _| {
                if index == 2 {
                    fs::rename(kin_home.join("lib"), kin_home.join("lib-original"))?;
                    symlink(&outside, kin_home.join("lib"))?;
                }
                Ok(())
            },
        )
        .expect_err("replaced lib binding must abort before shim install");
        assert!(format!("{error:#}").contains("binding changed"));
        assert_eq!(
            fs::read(outside.join("libkin_vfs_shim.so")).unwrap(),
            b"outside-victim"
        );
        let transaction = only_transaction(&kin_home);
        assert_eq!(
            fs::read(transaction.join("old/lib/libkin_vfs_shim.so")).unwrap(),
            b"old-libkin_vfs_shim.so"
        );
    }

    #[cfg(unix)]
    #[test]
    fn replacing_lib_during_atomic_shim_rename_cannot_touch_outside_bytes() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let outside = tmp.path().join("outside-lib");
        let held_lib = kin_home.join("lib-original");
        fs::create_dir_all(kin_home.join("bin")).unwrap();
        fs::create_dir(kin_home.join("lib")).unwrap();
        fs::create_dir(&outside).unwrap();
        let shim = kin_home.join("lib/libkin_vfs_shim.so");
        fs::write(&shim, b"old-shim").unwrap();
        fs::write(outside.join("libkin_vfs_shim.so"), b"outside-victim").unwrap();
        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();

        let error =
            write_managed_component_atomically_unix_with_hook(&lock, &shim, b"new-shim", || {
                fs::rename(kin_home.join("lib"), &held_lib)?;
                symlink(&outside, kin_home.join("lib"))?;
                Ok(())
            })
            .expect_err("atomic shim rename must recheck the lib binding");

        assert!(format!("{error:#}").contains("binding changed"));
        assert_eq!(
            fs::read(outside.join("libkin_vfs_shim.so")).unwrap(),
            b"outside-victim"
        );
        assert_eq!(
            fs::read(held_lib.join("libkin_vfs_shim.so")).unwrap(),
            b"old-shim"
        );
        let detached_temps = fs::read_dir(&held_lib)
            .unwrap()
            .filter_map(|entry| {
                let entry = entry.unwrap();
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".libkin_vfs_shim.so.tmp-")
                    .then_some(entry.path())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            detached_temps.len(),
            1,
            "failed binding validation must retain the detached temp rather than mutate a no-longer-authoritative tree"
        );
        assert_eq!(fs::read(&detached_temps[0]).unwrap(), b"new-shim");
    }

    #[test]
    fn provenance_mismatch_is_rejected_before_live_bytes_move() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let old = bundle_snapshot(&kin_home, LINUX_COMPONENTS);
        let archive = full_linux_static_archive("kin-linux-x86_64");
        stage_archive(
            &archive,
            "kin-linux-x86_64.tar.gz",
            &stage,
            LINUX_COMPONENTS,
        )
        .unwrap();
        let mut provenance = test_provenance(
            &stage,
            LINUX_COMPONENTS,
            "kin-linux-x86_64.tar.gz",
            &archive,
        );
        let release = GithubRelease {
            tag_name: "v0.2.22".to_string(),
            prerelease: false,
            assets: Vec::new(),
        };
        let asset = GithubAsset {
            name: "kin-linux-x86_64.tar.gz".to_string(),
            browser_download_url: "https://example.invalid/archive".to_string(),
        };
        let wrong_release_commit = validate_artifact_provenance(
            &provenance,
            &release,
            &"e".repeat(40),
            &asset,
            &archive,
            &stage,
            LINUX_COMPONENTS,
            true,
        )
        .expect_err("provenance from a different commit must fail before install");
        assert!(format!("{wrong_release_commit:#}").contains("release tag commit"));
        assert_bundle_matches(&kin_home, LINUX_COMPONENTS, &old);
        assert!(transaction_dirs(&kin_home).unwrap().is_empty());

        validate_artifact_provenance(
            &provenance,
            &release,
            &"a".repeat(40),
            &asset,
            &archive,
            &stage,
            LINUX_COMPONENTS,
            true,
        )
        .unwrap();

        provenance.archive_contents[0].sha256 = "0".repeat(64);
        let err = validate_artifact_provenance(
            &provenance,
            &release,
            &"a".repeat(40),
            &asset,
            &archive,
            &stage,
            LINUX_COMPONENTS,
            true,
        )
        .expect_err("component hash mismatch must fail preflight");
        assert!(format!("{err:#}").contains("does not match artifact provenance"));
        assert_bundle_matches(&kin_home, LINUX_COMPONENTS, &old);
        assert!(transaction_dirs(&kin_home).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn staged_replacement_after_provenance_validation_is_rejected_before_transaction() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let old = bundle_snapshot(&kin_home, LINUX_COMPONENTS);
        let archive = full_linux_static_archive("kin-linux-x86_64");
        stage_archive(
            &archive,
            "kin-linux-x86_64.tar.gz",
            &stage,
            LINUX_COMPONENTS,
        )
        .unwrap();
        let provenance = test_provenance(
            &stage,
            LINUX_COMPONENTS,
            "kin-linux-x86_64.tar.gz",
            &archive,
        );
        let release = GithubRelease {
            tag_name: "v0.2.22".to_string(),
            prerelease: false,
            assets: Vec::new(),
        };
        let asset = GithubAsset {
            name: "kin-linux-x86_64.tar.gz".to_string(),
            browser_download_url: "https://example.invalid/archive".to_string(),
        };
        let verified_staged_identities = validate_artifact_provenance(
            &provenance,
            &release,
            &"a".repeat(40),
            &asset,
            &archive,
            &stage,
            LINUX_COMPONENTS,
            true,
        )
        .unwrap();

        fs::write(
            component_path(&stage, LINUX_COMPONENTS[0]),
            b"post-validation replacement",
        )
        .unwrap();
        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        let error = install_staged_bundle_unix(
            &lock,
            &StagingLayout::open(&stage).unwrap(),
            LINUX_COMPONENTS,
            &verified_staged_identities,
            "0.2.22",
            &test_restart_pending("0.2.22"),
            |_, _| Ok(()),
        )
        .expect_err("post-validation staged replacement must fail closed");

        assert!(
            format!("{error:#}").contains("verified release provenance identity"),
            "{error:#}"
        );
        assert_bundle_matches(&kin_home, LINUX_COMPONENTS, &old);
        assert!(transaction_dirs(&kin_home).unwrap().is_empty());
    }

    #[test]
    fn provenance_requires_exact_target_and_vfs_target_for_every_release_artifact() {
        let matrix = [
            (
                "kin-linux-x86_64",
                "x86_64-unknown-linux-musl",
                "x86_64-unknown-linux-gnu",
            ),
            (
                "kin-linux-aarch64",
                "aarch64-unknown-linux-musl",
                "aarch64-unknown-linux-gnu",
            ),
            (
                "kin-macos-x86_64",
                "x86_64-apple-darwin",
                "x86_64-apple-darwin",
            ),
            (
                "kin-macos-aarch64",
                "aarch64-apple-darwin",
                "aarch64-apple-darwin",
            ),
            (
                "kin-windows-x86_64",
                "x86_64-pc-windows-msvc",
                "x86_64-pc-windows-msvc",
            ),
        ];

        for (artifact, target, vfs_target) in matrix {
            let base = ArtifactProvenance {
                schema_version: 1,
                release_tag: "v0.2.22".to_string(),
                artifact: artifact.to_string(),
                target: target.to_string(),
                vfs_target: vfs_target.to_string(),
                kin: KinProvenance {
                    commit: "a".repeat(40),
                    cargo_lock_sha256: "b".repeat(64),
                    embedded_dependency_provenance: "b".repeat(64),
                },
                kin_vfs: VfsProvenance {
                    commit: "c".repeat(40),
                    dirty: false,
                    cargo_lock_sha256: "d".repeat(64),
                },
                archive: ProvenanceArchive {
                    name: format!("{artifact}.tar.gz"),
                    sha256: "e".repeat(64),
                    size_bytes: 1,
                },
                archive_contents: Vec::new(),
            };
            validate_provenance_target_identity(&base, artifact).unwrap();

            let mut wrong_target = base.clone();
            wrong_target.target.push_str("-wrong");
            assert!(
                validate_provenance_target_identity(&wrong_target, artifact).is_err(),
                "{artifact} accepted a mutated primary target"
            );

            let mut wrong_vfs_target = base;
            wrong_vfs_target.vfs_target.push_str("-wrong");
            assert!(
                validate_provenance_target_identity(&wrong_vfs_target, artifact).is_err(),
                "{artifact} accepted a mutated VFS target"
            );
        }
    }

    #[test]
    fn static_build_identity_requires_exact_clean_provenance() {
        let provenance = KinProvenance {
            commit: "a".repeat(40),
            cargo_lock_sha256: "b".repeat(64),
            embedded_dependency_provenance: "b".repeat(64),
        };
        let identity = test_static_build_identity();
        let bytes = bytes_with_static_build_identity(b"inert candidate", &identity);
        assert_eq!(parse_static_build_identity(&bytes).unwrap(), identity);
        validate_static_build_identity_claim(
            &identity,
            &Version::parse("0.2.22").unwrap(),
            &provenance,
            "kin",
        )
        .unwrap();

        let mut dirty = identity.clone();
        dirty.clean = false;
        assert!(validate_static_build_identity_claim(
            &dirty,
            &Version::parse("0.2.22").unwrap(),
            &provenance,
            "kin-daemon",
        )
        .is_err());
        let mut wrong_commit = identity;
        wrong_commit.commit = "f".repeat(40);
        assert!(validate_static_build_identity_claim(
            &wrong_commit,
            &Version::parse("0.2.22").unwrap(),
            &provenance,
            "kin-daemon",
        )
        .is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_release_archive_static_identities_validate_without_execution() {
        assert_static_identity_release_fixture(
            MACOS_COMPONENTS,
            "kin-macos-aarch64",
            "kin-macos-aarch64.tar.gz",
            "aarch64-apple-darwin",
            "aarch64-apple-darwin",
        );
    }

    #[test]
    fn windows_release_archive_static_identities_are_host_independent() {
        assert_static_identity_release_fixture(
            WINDOWS_COMPONENTS,
            "kin-windows-x86_64",
            "kin-windows-x86_64.zip",
            "x86_64-pc-windows-msvc",
            "x86_64-pc-windows-msvc",
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_file_id_json_round_trips_all_128_bits_in_lowercase_hex() {
        let id = WindowsFileId::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"00112233445566778899aabbccddeeff\"");
        assert_eq!(serde_json::from_str::<WindowsFileId>(&json).unwrap(), id);
        assert!(
            serde_json::from_str::<WindowsFileId>("\"00112233445566778899AABBCCDDEEFF\"").is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_legacy_u64_file_id_maps_to_low_little_endian_bytes() {
        let id = serde_json::from_str::<WindowsFileId>("72623859790382856").unwrap();
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            "\"08070605040302010000000000000000\""
        );
    }

    #[test]
    fn windows_mutating_update_fails_before_any_state_change() {
        assert!(ensure_mutating_update_supported("windows", false).is_err());
        assert!(ensure_mutating_update_supported("windows", true).is_ok());
        assert!(ensure_mutating_update_supported("macos", false).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn install_root_and_lock_symlinks_are_rejected_without_touching_targets() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let actual = tmp.path().join("actual");
        fs::create_dir(&actual).unwrap();
        let linked = tmp.path().join("linked");
        symlink(&actual, &linked).unwrap();
        assert!(InstallRootLock::acquire(&linked).is_err());

        let root = tmp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        fs::create_dir(root.join("lib")).unwrap();
        let victim = tmp.path().join("victim");
        fs::write(&victim, b"must-survive").unwrap();
        symlink(&victim, root.join("update.lock")).unwrap();
        assert!(InstallRootLock::acquire(&root).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"must-survive");

        let unsafe_root = tmp.path().join("unsafe-root");
        let outside_bin = tmp.path().join("outside-bin");
        fs::create_dir(&unsafe_root).unwrap();
        fs::create_dir(&outside_bin).unwrap();
        symlink(&outside_bin, unsafe_root.join("bin")).unwrap();
        assert!(InstallRootLock::acquire(&unsafe_root).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn component_destination_symlink_is_rejected_before_transaction() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let victim = tmp.path().join("victim");
        fs::write(&victim, b"must-survive").unwrap();
        fs::remove_file(kin_home.join("bin/kin-daemon")).unwrap();
        symlink(&victim, kin_home.join("bin/kin-daemon")).unwrap();
        let archive = full_linux_archive("kin-linux-x86_64");
        stage_archive(
            &archive,
            "kin-linux-x86_64.tar.gz",
            &stage,
            LINUX_COMPONENTS,
        )
        .unwrap();

        let err = install_staged_bundle(
            &kin_home,
            &stage,
            LINUX_COMPONENTS,
            "0.2.22",
            &test_restart_pending("0.2.22"),
        )
        .expect_err("symlink destination must fail before backup");
        assert!(format!("{err:#}").contains("symlink"));
        assert_eq!(fs::read(&victim).unwrap(), b"must-survive");
        assert!(transaction_dirs(&kin_home).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn startup_authority_requires_the_exact_executing_object_and_rechecks_its_bytes() {
        use std::io::Write as _;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("kin-home");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir(root.join("lib")).unwrap();
        let target = root.join("bin/kin");
        fs::copy(std::env::current_exe().unwrap(), &target).unwrap();
        let error = UpdaterStartAuthority::capture(&root, LINUX_COMPONENTS)
            .err()
            .expect("an identical copy is not the exact executing process object");
        assert!(format!("{error:#}").contains("different or replaced Kin installation"));

        let authority =
            UpdaterStartAuthority::capture_test_file(&root, LINUX_COMPONENTS, &target).unwrap();

        fs::OpenOptions::new()
            .append(true)
            .open(&target)
            .unwrap()
            .write_all(b"different")
            .unwrap();
        let lock = InstallRootLock::acquire_existing(&root).unwrap();
        let error = authority
            .verify_locked(&lock, LINUX_COMPONENTS)
            .expect_err("durable image bytes and the full generation must be rechecked");
        assert!(format!("{error:#}").contains("identity changed"));
    }

    #[test]
    fn update_lock_rejects_a_concurrent_updater() {
        let tmp = tempfile::tempdir().unwrap();
        let first = InstallRootLock::acquire(tmp.path()).unwrap();
        let err = InstallRootLock::acquire(tmp.path())
            .err()
            .expect("a second updater must not acquire the same install lock");
        assert!(format!("{err:#}").contains("already active"));
        drop(first);
        InstallRootLock::acquire(tmp.path()).expect("lock must be reusable after release");
    }

    #[cfg(windows)]
    #[test]
    fn native_install_authority_contends_across_aliases_and_recovers_after_crash() -> Result<()> {
        if std::env::var_os(WINDOWS_INSTALL_AUTHORITY_CHILD_MODE).is_some() {
            let root = PathBuf::from(
                std::env::var_os(WINDOWS_INSTALL_AUTHORITY_CHILD_ROOT)
                    .context("Windows authority child root is missing")?,
            );
            let marker = PathBuf::from(
                std::env::var_os(WINDOWS_INSTALL_AUTHORITY_CHILD_MARKER)
                    .context("Windows authority child marker is missing")?,
            );
            let _lock = InstallRootLock::acquire_existing_waiting(&root)?;
            fs::write(marker, b"authority-held\n")?;
            std::process::abort();
        }

        let fixture = tempfile::tempdir()?;
        let parent = fixture.path().join("home");
        let root = parent.join(".kin");
        fs::create_dir_all(root.join("bin"))?;
        fs::create_dir(root.join("lib"))?;
        let alias = parent.join("alias-parent").join("..").join(".kin");
        fs::create_dir(parent.join("alias-parent"))?;
        let case_alias = parent.join(".KIN");

        let first = InstallRootLock::acquire_existing(&root)?;
        let alias_error = InstallRootLock::acquire_existing(&alias)
            .err()
            .context("an alias spelling must contend on the same authority")?;
        anyhow::ensure!(
            format!("{alias_error:#}").contains("already active"),
            "alias contention produced an unexpected error: {alias_error:#}"
        );
        let case_error = InstallRootLock::acquire_existing(&case_alias)
            .err()
            .context("a case-equivalent spelling must contend on the same authority")?;
        anyhow::ensure!(
            format!("{case_error:#}").contains("already active"),
            "case-equivalent contention produced an unexpected error: {case_error:#}"
        );
        drop(first);

        let crash_marker = fixture.path().join("crash-authority-held");
        let test_name = "commands::update::tests::native_install_authority_contends_across_aliases_and_recovers_after_crash";
        let mut child = Command::new(std::env::current_exe()?)
            .args([test_name, "--exact", "--nocapture"])
            .env(WINDOWS_INSTALL_AUTHORITY_CHILD_MODE, "crash")
            .env(WINDOWS_INSTALL_AUTHORITY_CHILD_ROOT, &root)
            .env(WINDOWS_INSTALL_AUTHORITY_CHILD_MARKER, &crash_marker)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !crash_marker.exists() && child.try_wait()?.is_none() {
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "crash child did not publish held-authority evidence"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        anyhow::ensure!(
            crash_marker.is_file(),
            "crash child exited before acquiring install authority"
        );
        let status = child.wait()?;
        anyhow::ensure!(!status.success(), "authority crash child did not crash");

        let recovered = InstallRootLock::acquire_existing(&case_alias)
            .context("kernel did not release Windows install authority after holder crash")?;
        drop(recovered);
        Ok(())
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn managed_daemon_spawn_lease_blocks_uninstall_authority_until_readiness() {
        use std::sync::mpsc;
        use std::time::Duration;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("kin-home");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir(root.join("lib")).unwrap();
        let daemon = root.join("bin/kin-daemon");
        fs::write(&daemon, b"managed daemon fixture").unwrap();

        let spawn_lease = InstallSpawnFence::acquire_for_daemon_binary_at(&daemon, &root)
            .unwrap()
            .expect("a daemon under the configured install root must take a spawn lease");
        let waiting_root = root.clone();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let uninstall_authority =
                InstallRootLock::acquire_existing_waiting(&waiting_root).unwrap();
            acquired_tx.send(()).unwrap();
            uninstall_authority
        });

        assert!(
            acquired_rx
                .recv_timeout(Duration::from_millis(200))
                .is_err(),
            "exclusive uninstall authority must wait while a managed child is being spawned"
        );
        drop(spawn_lease);
        acquired_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("uninstall authority must proceed once child readiness releases admission");
        drop(waiter.join().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn retired_managed_root_cannot_obtain_spawn_admission() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join(".kin");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir(root.join("lib")).unwrap();
        fs::write(root.join("bin/kin-daemon"), b"managed daemon fixture").unwrap();
        let retired = tmp
            .path()
            .join(format!(".kin-uninstall-retired-{}", uuid::Uuid::new_v4()));
        fs::rename(&root, &retired).unwrap();

        let error = InstallSpawnFence::acquire_for_daemon_binary_at(
            &retired.join("bin/kin-daemon"),
            &root,
        )
        .err()
        .expect("retirement must revoke spawn admission even when the CLI resolves its new path");
        assert!(format!("{error:#}").contains("retired uninstall state"));
    }

    #[cfg(unix)]
    #[test]
    fn contended_lock_does_not_create_missing_managed_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("kin-home");
        fs::create_dir(&root).unwrap();
        let lock_path = root.join("update.lock");
        fs::write(&lock_path, b"preexisting-lock-bytes\n").unwrap();
        let held = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        FileExt::try_lock_exclusive(&held).unwrap();
        let before = fs::read(&lock_path).unwrap();

        let error = InstallRootLock::acquire(&root)
            .err()
            .expect("contended acquisition must fail");

        assert!(format!("{error:#}").contains("already active"));
        assert!(!root.join("bin").exists());
        assert!(!root.join("lib").exists());
        assert_eq!(fs::read(&lock_path).unwrap(), before);
        FileExt::unlock(&held).unwrap();
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn replacing_install_root_aborts_before_component_mutation() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let detached = tmp.path().join("kin-home-detached");
        let stage = tmp.path().join("stage");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let _env = fixture_home(&tmp, &kin_home);
        let expected = bundle_snapshot(&kin_home, LINUX_COMPONENTS);
        stage_archive(
            &full_linux_archive("kin-linux-x86_64"),
            "kin-linux-x86_64.tar.gz",
            &stage,
            LINUX_COMPONENTS,
        )
        .unwrap();
        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        let verified_staged_identities =
            staged_identities_for_test(&stage, LINUX_COMPONENTS).unwrap();

        let error = install_staged_bundle_unix_with_hooks(
            &lock,
            &StagingLayout::open(&stage).unwrap(),
            LINUX_COMPONENTS,
            &verified_staged_identities,
            "0.2.22",
            &test_restart_pending("0.2.22"),
            |index, _| {
                if index == 0 {
                    fs::rename(&kin_home, &detached)?;
                    fs::create_dir(&kin_home)?;
                    fs::create_dir(kin_home.join("bin"))?;
                    fs::create_dir(kin_home.join("lib"))?;
                    fs::write(kin_home.join("update.lock"), b"replacement-lock\n")?;
                    fs::write(kin_home.join("bin/victim"), b"replacement-root-victim")?;
                }
                Ok(())
            },
            |_, _| Ok(()),
            |_| Ok(()),
        )
        .expect_err("replaced install root must invalidate the held authority");

        assert!(format!("{error:#}").contains("binding changed"));
        assert_bundle_matches(&detached, LINUX_COMPONENTS, &expected);
        assert_eq!(
            fs::read(kin_home.join("bin/victim")).unwrap(),
            b"replacement-root-victim"
        );
        assert_eq!(
            fs::read(kin_home.join("update.lock")).unwrap(),
            b"replacement-lock\n"
        );
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn replacing_update_lock_aborts_before_component_mutation() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let _env = fixture_home(&tmp, &kin_home);
        let expected = bundle_snapshot(&kin_home, LINUX_COMPONENTS);
        stage_archive(
            &full_linux_archive("kin-linux-x86_64"),
            "kin-linux-x86_64.tar.gz",
            &stage,
            LINUX_COMPONENTS,
        )
        .unwrap();
        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        let verified_staged_identities =
            staged_identities_for_test(&stage, LINUX_COMPONENTS).unwrap();

        let error = install_staged_bundle_unix_with_hooks(
            &lock,
            &StagingLayout::open(&stage).unwrap(),
            LINUX_COMPONENTS,
            &verified_staged_identities,
            "0.2.22",
            &test_restart_pending("0.2.22"),
            |index, _| {
                if index == 0 {
                    fs::remove_file(kin_home.join("update.lock"))?;
                    fs::write(kin_home.join("update.lock"), b"replacement-lock\n")?;
                }
                Ok(())
            },
            |_, _| Ok(()),
            |_| Ok(()),
        )
        .expect_err("replaced lock inode must invalidate the held authority");

        assert!(format!("{error:#}").contains("binding changed"));
        assert_bundle_matches(&kin_home, LINUX_COMPONENTS, &expected);
        assert_eq!(
            fs::read(kin_home.join("update.lock")).unwrap(),
            b"replacement-lock\n"
        );
    }

    #[test]
    #[serial]
    fn windows_bundle_uses_exe_names_and_removes_stale_projection_files() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&kin_home).unwrap();
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _home = EnvVarGuard::set("HOME", &home);
        let stage = tmp.path().join("stage");
        write_bundle(&kin_home, WINDOWS_COMPONENTS, b"old-");
        let archive = make_zip(&[("kin.exe", b"new-kin"), ("kin-daemon.exe", b"new-daemon")]);

        stage_archive(
            &archive,
            "kin-windows-x86_64.zip",
            &stage,
            WINDOWS_COMPONENTS,
        )
        .unwrap();
        install_staged_bundle(
            &kin_home,
            &stage,
            WINDOWS_COMPONENTS,
            "0.2.22",
            &test_restart_pending("0.2.22"),
        )
        .unwrap();

        assert_eq!(fs::read(kin_home.join("bin/kin.exe")).unwrap(), b"new-kin");
        assert_eq!(
            fs::read(kin_home.join("bin/kin-daemon.exe")).unwrap(),
            b"new-daemon"
        );
        assert!(!kin_home.join("bin/kin").exists());
        assert!(!kin_home.join("bin/kin-vfs.exe").exists());
        assert!(!kin_home.join("bin/kin-mcp.exe").exists());
        assert!(!kin_home.join("lib/kin_vfs_shim.dll").exists());
    }

    #[tokio::test]
    #[serial]
    async fn check_only_reports_stale_transaction_without_writing_any_state() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("custom-kin-home");
        let registry = tmp.path().join("registry.toml");
        fs::create_dir_all(kin_home.join("bin")).unwrap();
        fs::create_dir(kin_home.join("lib")).unwrap();
        let transaction = kin_home.join(format!(".update-backup-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&transaction).unwrap();
        let sentinel = transaction.join("sentinel");
        fs::write(&sentinel, b"must remain byte-for-byte unchanged").unwrap();
        let mut before: Vec<_> = fs::read_dir(&kin_home)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        before.sort();
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _registry = EnvVarGuard::set("KIN_REGISTRY_PATH", &registry);

        let error = run(
            false,
            None,
            None,
            None,
            None,
            true,
            true,
            false,
            Vec::new(),
            None,
            false,
            false,
        )
        .await
        .expect_err("check-only must report, not recover, a stale transaction");
        assert!(format!("{error:#}").contains("did not modify any file"));
        assert_eq!(
            fs::read(&sentinel).unwrap(),
            b"must remain byte-for-byte unchanged"
        );
        assert!(!kin_home.join("update.lock").exists());
        assert!(!kin_home.join("update.toml").exists());
        assert!(!restart_pending_path(&kin_home).exists());
        let mut after: Vec<_> = fs::read_dir(&kin_home)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        after.sort();
        assert_eq!(after, before);
        assert!(!registry.exists());
        assert!(!registry.with_extension("lock").exists());
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn update_preflight_refuses_unsafe_registry_without_repairing_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let registry = tmp.path().join("registry.toml");
        let lock = registry.with_extension("lock");
        fs::write(&registry, b"repos = []\n").unwrap();
        fs::write(&lock, b"").unwrap();
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
        let before_registry = fs::read(&registry).unwrap();
        let before_lock = fs::read(&lock).unwrap();
        let _registry = EnvVarGuard::set("KIN_REGISTRY_PATH", &registry);

        let error = registry_authority_preflight()
            .expect_err("updater must refuse unsafe registry authority");

        assert!(format!("{error:#}").contains("refused unsafe local registry authority"));
        assert_eq!(fs::read(&registry).unwrap(), before_registry);
        assert_eq!(fs::read(&lock).unwrap(), before_lock);
        assert_eq!(
            fs::metadata(&registry).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(
            fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    #[serial]
    fn post_update_mcp_refresh_uses_custom_managed_launcher_and_preserves_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let kin_home = tmp.path().join("custom-kin-home");
        let executable_name = if cfg!(windows) { "kin.exe" } else { "kin" };
        fs::create_dir_all(home.join(".codex")).unwrap();
        fs::create_dir_all(kin_home.join("bin")).unwrap();
        fs::copy(
            std::env::current_exe().unwrap(),
            kin_home.join("bin").join(executable_name),
        )
        .unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        let repo = repo.canonicalize().unwrap();
        let config = home.join(".codex/config.toml");
        fs::write(
            &config,
            format!(
                r#"[mcp_servers.kin]
command = "/old/Cellar/kin/0.2.21/bin/kin"
args = ["mcp", "start"]
cwd = {:?}
"#,
                repo.to_string_lossy()
            ),
        )
        .unwrap();
        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _kin_dir = EnvVarGuard::set("KIN_DIR", tmp.path().join("wrong-install"));

        let repaired = crate::commands::setup::remerge_existing_mcp_configs();
        let normalized_config = crate::commands::setup::ConfigLock::normalized_path(&config)
            .expect("test MCP config path must normalize");
        assert!(repaired.contains(&normalized_config));
        let root: toml::Value = toml::from_str(&fs::read_to_string(config).unwrap()).unwrap();
        let entry = &root["mcp_servers"]["kin"];
        let expected_launcher = kin_home
            .join("bin")
            .join(executable_name)
            .to_string_lossy()
            .into_owned();
        assert_eq!(entry["command"].as_str(), Some(expected_launcher.as_str()));
        assert_eq!(entry["cwd"].as_str(), repo.to_str());
        assert_eq!(entry["args"][2].as_str(), Some("--repo"));
        assert_eq!(entry["args"][3].as_str(), repo.to_str());
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn postcommit_crashes_durably_repair_mcp_before_marker_clear() {
        for point in ["after-commit", "after-restart-marker", "after-cleanup"] {
            let state = crash_update_with_mcp(point, None);
            match point {
                "after-commit" => {
                    assert!(!restart_pending_path(&state.kin_home).exists());
                    assert!(!mcp_repair_pending_path(&state.kin_home).exists());
                }
                "after-restart-marker" => {
                    assert!(restart_pending_path(&state.kin_home).is_file());
                    assert!(
                        !mcp_repair_pending_path(&state.kin_home).exists(),
                        "the crash point must precede MCP marker persistence"
                    );
                }
                "after-cleanup" => {
                    assert!(transaction_dirs(&state.kin_home).unwrap().is_empty());
                    assert!(restart_pending_path(&state.kin_home).is_file());
                    assert!(mcp_repair_pending_path(&state.kin_home).is_file());
                }
                _ => unreachable!(),
            }
            let home = state.mcp_home.as_ref().unwrap();
            let repo = state.mcp_repo.as_ref().unwrap();
            let config = state.mcp_config.as_ref().unwrap();
            let _home = EnvVarGuard::set("HOME", home);
            let _kin_home = EnvVarGuard::set("KIN_HOME", &state.kin_home);
            let _kin_dir = EnvVarGuard::set("KIN_DIR", state._tmp.path().join("wrong-install"));
            let _cwd = CwdGuard::set(&home);

            let lock = InstallRootLock::acquire_existing(&state.kin_home).unwrap();
            if !transaction_dirs(&state.kin_home).unwrap().is_empty() {
                recover_stale_transactions(&lock, LINUX_COMPONENTS).unwrap();
            }
            assert!(
                mcp_repair_pending_path(&state.kin_home).is_file(),
                "{point} must converge to durable MCP repair state"
            );

            attempt_pending_mcp_repair(&lock).unwrap();
            let root: toml::Value = toml::from_str(&fs::read_to_string(config).unwrap()).unwrap();
            let expected = state
                .kin_home
                .join("bin/kin")
                .to_string_lossy()
                .into_owned();
            assert_eq!(
                root["mcp_servers"]["kin"]["command"].as_str(),
                Some(expected.as_str()),
                "{point}"
            );
            assert_eq!(root["mcp_servers"]["kin"]["cwd"].as_str(), repo.to_str());
            assert_eq!(
                root["mcp_servers"]["kin"]["args"][2].as_str(),
                Some("--repo")
            );
            assert_eq!(
                root["mcp_servers"]["kin"]["args"][3].as_str(),
                repo.to_str()
            );
            assert!(
                !mcp_repair_pending_path(&state.kin_home).exists(),
                "{point} marker must clear only after the intended config is repaired"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn malformed_mcp_config_is_byte_preserved_and_repair_stays_pending() {
        let state = crash_update("after-cleanup", None);
        let home = state._tmp.path().join("home-malformed");
        let repo = state._tmp.path().join("repo-malformed");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        let repo = repo.canonicalize().unwrap();
        let config = home.join(".codex/config.toml");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        let malformed = b"\xff\xfe[mcp_servers.kin\ncommand =";
        fs::write(&config, malformed).unwrap();
        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &state.kin_home);
        let _cwd = CwdGuard::set(&home);
        enqueue_mcp_repair_targets(&[crate::commands::setup::McpRepairTarget {
            id: "codex".to_string(),
            path: config.clone(),
            repo_root: Some(repo),
            captured_config_sha256: crate::commands::setup_ledger::sha256_hex(malformed),
        }])
        .unwrap();
        let marker = mcp_repair_pending_path(&state.kin_home);
        let marker_before = fs::read(&marker).unwrap();

        let lock = InstallRootLock::acquire_existing(&state.kin_home).unwrap();
        assert!(attempt_pending_mcp_repair(&lock).is_err());

        assert_eq!(fs::read(&config).unwrap(), malformed);
        assert_eq!(fs::read(&marker).unwrap(), marker_before);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn exact_mcp_manifest_repairs_its_recorded_target_independent_of_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"installed-");
        let home = tmp.path().join("home");
        let config = home.join(".codex/config.toml");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        let intended_repo = tmp.path().join("intended-repo");
        let unrelated_repo = tmp.path().join("unrelated-repo");
        fs::create_dir_all(intended_repo.join(".kin")).unwrap();
        fs::create_dir_all(unrelated_repo.join(".kin")).unwrap();
        let intended_repo = intended_repo.canonicalize().unwrap();
        fs::write(
            &config,
            "[mcp_servers.kin]\ncommand = \"/stale/kin\"\nargs = [\"mcp\", \"start\"]\n",
        )
        .unwrap();
        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        enqueue_mcp_repair_targets(&[crate::commands::setup::McpRepairTarget {
            id: "codex".to_string(),
            path: config.clone(),
            repo_root: Some(intended_repo.clone()),
            captured_config_sha256: crate::commands::setup_ledger::sha256_hex(
                &fs::read(&config).unwrap(),
            ),
        }])
        .unwrap();
        let _cwd = CwdGuard::set(&unrelated_repo);

        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        assert!(attempt_pending_mcp_repair(&lock).unwrap());

        let root: toml::Value = toml::from_str(&fs::read_to_string(&config).unwrap()).unwrap();
        assert_eq!(
            root["mcp_servers"]["kin"]["args"][3].as_str(),
            intended_repo.to_str()
        );
        assert!(!mcp_repair_pending_path(&kin_home).exists());
        assert!(
            crate::commands::setup::mcp_repair_targets_ledger_verified(&[
                crate::commands::setup::McpRepairTarget {
                    id: "codex".to_string(),
                    captured_config_sha256: crate::commands::setup_ledger::sha256_hex(
                        &fs::read(&config).unwrap(),
                    ),
                    path: config,
                    repo_root: Some(intended_repo),
                }
            ])
            .unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn legacy_empty_and_malformed_mcp_manifests_fail_closed() {
        let cases = [
            serde_json::json!({
                "schema_version": 1,
                "installed_version": "0.2.21",
                "recorded_at": "2026-07-13T00:00:00Z"
            }),
            serde_json::json!({
                "schema_version": 2,
                "installed_version": "0.2.21",
                "recorded_at": "2026-07-13T00:00:00Z",
                "repair_required": true,
                "targets": []
            }),
            serde_json::json!({
                "schema_version": 2,
                "installed_version": "0.2.21",
                "recorded_at": "2026-07-13T00:00:00Z",
                "repair_required": true,
                "targets": [{
                    "id": "codex",
                    "path": "relative/config.toml"
                }]
            }),
        ];
        for marker_json in cases {
            let tmp = tempfile::tempdir().unwrap();
            let kin_home = tmp.path().join("kin-home");
            write_bundle(&kin_home, LINUX_COMPONENTS, b"installed-");
            let marker = mcp_repair_pending_path(&kin_home);
            let bytes = serde_json::to_vec_pretty(&marker_json).unwrap();
            fs::write(&marker, &bytes).unwrap();
            let home = tmp.path().join("home");
            fs::create_dir_all(&home).unwrap();
            let _home = EnvVarGuard::set("HOME", &home);
            let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);

            let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
            assert!(attempt_pending_mcp_repair(&lock).is_err());
            assert_eq!(fs::read(&marker).unwrap(), bytes);
        }
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn unknown_mcp_lifecycle_fields_preserve_marker_and_config_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"installed-");
        let home = tmp.path().join("home");
        let repo = tmp.path().join("repo");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        let repo = repo.canonicalize().unwrap();
        let config = home.join(".codex/config.toml");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        let config_bytes = format!(
            "[mcp_servers.kin]\ncommand = \"/stale/kin\"\nargs = [\"mcp\", \"start\", \"--repo\", {:?}]\n",
            repo.to_string_lossy()
        )
        .into_bytes();
        fs::write(&config, &config_bytes).unwrap();
        let marker = mcp_repair_pending_path(&kin_home);
        let captured_config_sha256 = crate::commands::setup_ledger::sha256_hex(&config_bytes);
        let marker_bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": MCP_REPAIR_MARKER_SCHEMA_VERSION,
            "installed_version": "0.2.21",
            "recorded_at": "2026-07-16T13:44:00-04:00",
            "repair_required": true,
            "configuration_repaired": true,
            "client_restart_pending": true,
            "acknowledged": false,
            "targets": [{
                "id": "codex",
                "path": config,
                "repo_root": repo,
                "captured_config_sha256": captured_config_sha256,
            }]
        }))
        .unwrap();
        fs::write(&marker, &marker_bytes).unwrap();
        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);

        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        let error = attempt_pending_mcp_repair(&lock)
            .expect_err("unknown lifecycle fields must fail closed");
        assert!(format!("{error:#}").contains("unknown field"));
        assert_eq!(fs::read(&marker).unwrap(), marker_bytes);
        assert_eq!(fs::read(&config).unwrap(), config_bytes);
        drop(lock);

        let nested_marker_bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": MCP_REPAIR_MARKER_SCHEMA_VERSION,
            "installed_version": "0.2.21",
            "recorded_at": "2026-07-16T13:44:00-04:00",
            "repair_required": true,
            "targets": [{
                "id": "codex",
                "path": config,
                "repo_root": repo,
                "captured_config_sha256": captured_config_sha256,
                "acknowledged": false,
            }]
        }))
        .unwrap();
        fs::write(&marker, &nested_marker_bytes).unwrap();
        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        let error = attempt_pending_mcp_repair(&lock)
            .expect_err("unknown target lifecycle fields must fail closed");
        assert!(format!("{error:#}").contains("unknown field"));
        assert_eq!(fs::read(&marker).unwrap(), nested_marker_bytes);
        assert_eq!(fs::read(&config).unwrap(), config_bytes);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn mcp_marker_self_target_fails_without_recursive_target_locking() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"installed-");
        let marker = mcp_repair_pending_path(&kin_home);
        let marker_bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": MCP_REPAIR_MARKER_SCHEMA_VERSION,
            "installed_version": "0.2.21",
            "recorded_at": "2026-07-16T20:00:00Z",
            "repair_required": true,
            "targets": [{
                "id": "cursor",
                "path": marker,
                "captured_config_sha256": "0".repeat(64),
            }]
        }))
        .unwrap();
        fs::write(&marker, &marker_bytes).unwrap();
        let _home = EnvVarGuard::set("HOME", tmp.path().join("home"));
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);

        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        let error = attempt_pending_mcp_repair(&lock)
            .expect_err("a marker must never become its own config target");
        let message = format!("{error:#}");
        assert!(
            message.contains("own durable marker") || message.contains("arbitrary path authority"),
            "unexpected self-target rejection: {message}"
        );
        assert_eq!(fs::read(&marker).unwrap(), marker_bytes);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn retained_mcp_marker_rejects_arbitrary_id_path_authority_without_writes() {
        for victim_kind in ["arbitrary_json", "restart_marker", "setup_ledger"] {
            let tmp = tempfile::tempdir().unwrap();
            let kin_home = tmp.path().join("kin-home");
            write_bundle(&kin_home, LINUX_COMPONENTS, b"installed-");
            let home = tmp.path().join("home");
            fs::create_dir_all(home.join(".cursor")).unwrap();
            let _home = EnvVarGuard::set("HOME", &home);
            let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
            let victim = match victim_kind {
                "arbitrary_json" => home.join("victim.json"),
                "restart_marker" => restart_pending_path(&kin_home),
                "setup_ledger" => crate::commands::setup_ledger::ledger_path().unwrap(),
                _ => unreachable!(),
            };
            fs::create_dir_all(victim.parent().unwrap()).unwrap();
            let victim_bytes = format!("protected victim: {victim_kind}").into_bytes();
            fs::write(&victim, &victim_bytes).unwrap();
            let marker = mcp_repair_pending_path(&kin_home);
            let marker_bytes = serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": MCP_REPAIR_MARKER_SCHEMA_VERSION,
                "installed_version": "0.2.21",
                "recorded_at": "2026-07-16T20:00:00Z",
                "repair_required": true,
                "targets": [{
                    "id": "cursor",
                    "path": victim,
                    "captured_config_sha256": crate::commands::setup_ledger::sha256_hex(&victim_bytes),
                }]
            }))
            .unwrap();
            fs::write(&marker, &marker_bytes).unwrap();

            let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
            let error = attempt_pending_mcp_repair(&lock)
                .expect_err("strict markers cannot grant arbitrary client path authority");
            assert!(format!("{error:#}").contains("arbitrary path authority"));
            assert_eq!(fs::read(&marker).unwrap(), marker_bytes);
            assert_eq!(fs::read(&victim).unwrap(), victim_bytes);
        }
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn unsupported_mcp_marker_fails_before_transaction_directory_creation() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        stage_archive(
            &full_linux_archive("kin-linux-x86_64"),
            "kin-linux-x86_64.tar.gz",
            &stage,
            LINUX_COMPONENTS,
        )
        .unwrap();
        let marker = mcp_repair_pending_path(&kin_home);
        let marker_bytes = br#"{"schema_version":99,"installed_version":"0.2.21","recorded_at":"2026-07-16T00:00:00Z","repair_required":true,"targets":[]}"#;
        fs::write(&marker, marker_bytes).unwrap();
        let _home = EnvVarGuard::set("HOME", tmp.path().join("home"));
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);

        let error = install_staged_bundle(
            &kin_home,
            &stage,
            LINUX_COMPONENTS,
            "0.2.22",
            &test_restart_pending("0.2.22"),
        )
        .expect_err("unsupported repair state must fail before transaction creation");
        assert!(format!("{error:#}").contains("unsupported MCP repair marker schema"));
        assert!(transaction_dirs(&kin_home).unwrap().is_empty());
        assert_eq!(fs::read(marker).unwrap(), marker_bytes);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn any_restart_marker_blocks_new_install_before_transaction_or_live_mutation() {
        for marker_bytes in [
            b"{malformed restart marker".as_slice(),
            br#"{"schema_version":99,"unknown_lifecycle":true}"#.as_slice(),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let kin_home = tmp.path().join("kin-home");
            let stage = tmp.path().join("stage");
            write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
            stage_archive(
                &full_linux_archive("kin-linux-x86_64"),
                "kin-linux-x86_64.tar.gz",
                &stage,
                LINUX_COMPONENTS,
            )
            .unwrap();
            let before = bundle_snapshot(&kin_home, LINUX_COMPONENTS);
            let marker = restart_pending_path(&kin_home);
            fs::write(&marker, marker_bytes).unwrap();

            let error = install_staged_bundle(
                &kin_home,
                &stage,
                LINUX_COMPONENTS,
                "0.2.22",
                &test_restart_pending("0.2.22"),
            )
            .expect_err("an existing restart path must supersede a newer install");
            assert!(format!("{error:#}").contains("restart acknowledgement marker"));
            assert_eq!(fs::read(&marker).unwrap(), marker_bytes);
            assert!(transaction_dirs(&kin_home).unwrap().is_empty());
            assert_bundle_matches(&kin_home, LINUX_COMPONENTS, &before);
        }
    }

    #[cfg(unix)]
    #[test]
    fn restart_persistence_retains_marker_appearing_after_precheck() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"committed-");
        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        refuse_new_update_while_restart_marker_exists(&lock).unwrap();
        let mut record = test_restart_pending("0.2.22");
        record.schema_version = RESTART_MARKER_SCHEMA_VERSION;
        record.reason = RESTART_FENCE_REASON.to_string();
        for obligation in &mut record.runtime_obligations {
            obligation.expected_identity =
                file_identity(&kin_home.join("bin").join(&obligation.component)).unwrap();
        }
        mark_restart_record_committed(&mut record, &kin_home, LINUX_COMPONENTS).unwrap();

        let marker = restart_pending_path(&kin_home);
        let hostile = b"external marker after updater precheck";
        let bytes = serde_json::to_vec_pretty(&record).unwrap();
        let install = lock.install().unwrap();
        let error = install
            .root
            .create_private_file_absent_or_identical_with_hook(
                RESTART_ACK_REQUIRED_FILE,
                &bytes,
                "restart acknowledgement marker",
                || {
                    fs::write(&marker, hostile)?;
                    Ok(())
                },
                || Ok(()),
            )
            .expect_err("restart persistence must never supersede a late marker");
        assert!(format!("{error:#}").contains("different bytes"));
        assert_eq!(fs::read(marker).unwrap(), hostile);
    }

    #[cfg(unix)]
    #[test]
    fn private_marker_create_fails_if_conflict_disappears_before_verification() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"committed-");
        let marker = restart_pending_path(&kin_home);
        let bytes = b"identical late marker";
        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        let install = lock.install().unwrap();

        let error = install
            .root
            .create_private_file_absent_or_identical_with_hook(
                RESTART_ACK_REQUIRED_FILE,
                bytes,
                "restart acknowledgement marker",
                || {
                    fs::write(&marker, bytes)?;
                    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))?;
                    Ok(())
                },
                || {
                    fs::remove_file(&marker)?;
                    Ok(())
                },
            )
            .expect_err("a vanished conflict cannot prove durable marker creation");

        assert!(format!("{error:#}").contains("durable marker creation was not proven"));
        assert!(!marker.exists());
        assert!(fs::read_dir(&kin_home).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".create-")));
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn mcp_persistence_retains_different_marker_appearing_at_create_boundary() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"committed-");
        let home = tmp.path().join("home");
        let config = home.join(".cursor/mcp.json");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        let config_bytes =
            br#"{"mcpServers":{"kin":{"command":"/stale/kin","args":["mcp","start"]}}}"#;
        fs::write(&config, config_bytes).unwrap();
        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let target = crate::commands::setup::McpRepairTarget {
            id: "cursor".to_string(),
            path: config,
            repo_root: None,
            captured_config_sha256: crate::commands::setup_ledger::sha256_hex(config_bytes),
        };
        let target = crate::commands::setup::normalize_mcp_repair_targets([target])
            .unwrap()
            .remove(0);
        let desired = McpRepairPending {
            schema_version: MCP_REPAIR_MARKER_SCHEMA_VERSION,
            installed_version: "0.2.22".to_string(),
            recorded_at: "2026-07-16T00:00:00Z".to_string(),
            repair_required: true,
            targets: vec![target],
        };
        let mut hostile = desired.clone();
        hostile.installed_version = "0.2.23".to_string();
        hostile.recorded_at = "2026-07-16T00:00:01Z".to_string();
        validate_mcp_repair_record(&desired).unwrap();
        validate_mcp_repair_record(&hostile).unwrap();
        let hostile_bytes = serde_json::to_vec_pretty(&hostile).unwrap();
        let marker = mcp_repair_pending_path(&kin_home);
        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        let error =
            persist_mcp_repair_record_at_with_hook(lock.install().unwrap(), &desired, || {
                fs::write(&marker, &hostile_bytes)?;
                fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))?;
                Ok(())
            })
            .expect_err("MCP persistence must never supersede a late valid obligation");

        assert!(format!("{error:#}").contains("different bytes"));
        assert_eq!(fs::read(marker).unwrap(), hostile_bytes);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn transaction_manifest_preserves_existing_mcp_repair_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let home = home.canonicalize().unwrap();
        let existing_path = home.join(".cursor/mcp.json");
        fs::create_dir_all(existing_path.parent().unwrap()).unwrap();
        fs::write(
            &existing_path,
            r#"{"mcpServers":{"kin":{"command":"/stale/kin","args":["mcp","start"]}}}"#,
        )
        .unwrap();
        let existing_target = crate::commands::setup::McpRepairTarget {
            id: "cursor".to_string(),
            captured_config_sha256: crate::commands::setup_ledger::sha256_hex(
                &fs::read(&existing_path).unwrap(),
            ),
            path: existing_path,
            repo_root: None,
        };
        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        persist_mcp_repair_record_at(
            lock.install().unwrap(),
            &McpRepairPending {
                schema_version: MCP_REPAIR_MARKER_SCHEMA_VERSION,
                installed_version: "0.2.21".to_string(),
                recorded_at: "2026-07-16T00:00:00Z".to_string(),
                repair_required: true,
                targets: vec![existing_target.clone()],
            },
        )
        .unwrap();

        let record = mcp_repair_pending_record(&lock, "0.2.22").unwrap();
        assert!(record.repair_required);
        assert_eq!(record.targets, vec![existing_target]);
        assert_eq!(record.installed_version, "0.2.22");
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn automatic_mcp_repair_rejects_identical_bytes_on_replaced_inode() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"installed-");
        let managed = kin_home.join("bin/kin");
        fs::remove_file(&managed).unwrap();
        fs::hard_link(std::env::current_exe().unwrap(), &managed).unwrap();
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o755)).unwrap();
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _home = EnvVarGuard::set("HOME", tmp.path().join("home"));

        assert!(UpdaterStartAuthority::capture(&kin_home, LINUX_COMPONENTS).is_ok());
        let replacement = kin_home.join("bin/.kin-identical-replacement");
        fs::copy(std::env::current_exe().unwrap(), &replacement).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755)).unwrap();
        fs::rename(&replacement, &managed).unwrap();
        assert!(UpdaterStartAuthority::capture(&kin_home, LINUX_COMPONENTS).is_err());
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn ordinary_mcp_repair_reverifies_start_authority_after_install_lock_wait() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::mpsc;

        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let managed = kin_home.join("bin/kin");
        fs::remove_file(&managed).unwrap();
        fs::hard_link(std::env::current_exe().unwrap(), &managed).unwrap();
        fs::set_permissions(&managed, fs::Permissions::from_mode(0o755)).unwrap();

        let home = tmp.path().join("home");
        let repo = tmp.path().join("repo");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        let repo = repo.canonicalize().unwrap();
        let config = home.join(".codex/config.toml");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        let config_bytes = format!(
            "[mcp_servers.kin]\ncommand = \"/stale/kin\"\nargs = [\"mcp\", \"start\", \"--repo\", {:?}]\n",
            repo.to_string_lossy()
        )
        .into_bytes();
        fs::write(&config, &config_bytes).unwrap();
        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        enqueue_mcp_repair_targets(&[crate::commands::setup::McpRepairTarget {
            id: "codex".to_string(),
            path: config.clone(),
            repo_root: Some(repo),
            captured_config_sha256: crate::commands::setup_ledger::sha256_hex(&config_bytes),
        }])
        .unwrap();
        let marker = mcp_repair_pending_path(&kin_home);
        let old_marker = fs::read(&marker).unwrap();
        let authority =
            UpdaterStartAuthority::capture_test_file(&kin_home, LINUX_COMPONENTS, &managed)
                .unwrap();

        let blocking_lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let thread_home = kin_home.clone();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            retry_pending_mcp_repair_with_start_authority(
                &thread_home,
                LINUX_COMPONENTS,
                &authority,
            )
        });
        started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !worker.is_finished(),
            "ordinary repair must wait for the existing install authority"
        );

        // Model a newer updater replacing every managed pathname and its
        // repair marker while the old process retains its original executable
        // inode and waits for the install lock.
        for component in LINUX_COMPONENTS {
            let destination = component_path(&kin_home, *component);
            let replacement = destination.with_extension("newer-generation");
            fs::write(&replacement, format!("newer-{}", component.name)).unwrap();
            fs::set_permissions(
                &replacement,
                fs::Permissions::from_mode(if component.location == ComponentLocation::Bin {
                    0o755
                } else {
                    0o644
                }),
            )
            .unwrap();
            fs::rename(&replacement, &destination).unwrap();
        }
        let mut replacement_marker: serde_json::Value =
            serde_json::from_slice(&old_marker).unwrap();
        replacement_marker["recorded_at"] =
            serde_json::Value::String("2026-07-16T20:00:00Z".to_string());
        let replacement_marker = serde_json::to_vec_pretty(&replacement_marker).unwrap();
        let replacement_path = marker.with_extension("newer-marker");
        fs::write(&replacement_path, &replacement_marker).unwrap();
        fs::set_permissions(&replacement_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement_path, &marker).unwrap();
        drop(blocking_lock);

        let error = worker
            .join()
            .unwrap()
            .expect_err("old process must refuse the newer generation and marker");
        assert!(format!("{error:#}").contains("bundle generation changed"));
        assert_eq!(fs::read(&marker).unwrap(), replacement_marker);
        assert_eq!(fs::read(&config).unwrap(), config_bytes);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn mcp_destination_directory_sync_failure_reports_error_and_retains_marker() {
        let state = crash_update("after-cleanup", None);
        let home = state._tmp.path().join("home-dir-sync-failure");
        let config = home.join(".codex/config.toml");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        let repo = state._tmp.path().join("repo-dir-sync-failure");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        let repo = repo.canonicalize().unwrap();
        fs::write(
            &config,
            format!(
                r#"[mcp_servers.kin]
command = "/old/Cellar/kin/0.2.21/bin/kin"
args = ["mcp", "start"]
cwd = {:?}
"#,
                repo.to_string_lossy()
            ),
        )
        .unwrap();
        let marker = mcp_repair_pending_path(&state.kin_home);
        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &state.kin_home);
        let _cwd = CwdGuard::set(&home);
        enqueue_mcp_repair_targets(&[crate::commands::setup::McpRepairTarget {
            id: "codex".to_string(),
            path: config.clone(),
            repo_root: Some(repo),
            captured_config_sha256: crate::commands::setup_ledger::sha256_hex(
                &fs::read(&config).unwrap(),
            ),
        }])
        .unwrap();
        let marker_before = fs::read(&marker).unwrap();
        let _failure = ConfigDirectorySyncFailureGuard::enable(&home);

        let outcome = crate::commands::setup::remerge_existing_mcp_configs_detailed();
        assert!(outcome.repaired.is_empty());
        assert!(!outcome.errors.is_empty());
        assert!(
            outcome
                .errors
                .iter()
                .all(|error| error.contains("directory sync failure")),
            "{:?}",
            outcome.errors
        );

        let lock = InstallRootLock::acquire_existing(&state.kin_home).unwrap();
        assert!(attempt_pending_mcp_repair(&lock).is_err());

        assert_eq!(fs::read(&marker).unwrap(), marker_before);
    }

    #[test]
    fn restart_acknowledgement_output_preserves_proof_boundary() {
        let output = restart_acknowledgement_output("0.2.23");
        assert!(output.contains("persisted process fence"));
        assert!(output.contains("installed byte identities"));
        assert!(output.contains("live runtime convergence was not inferred"));
        assert!(!output.contains("Verified post-update runtime convergence"));
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn explicit_restart_ack_clears_only_a_matching_release_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let lock = InstallRootLock::acquire(&kin_home).unwrap();
        fs::hard_link(std::env::current_exe().unwrap(), kin_home.join("bin/kin")).unwrap();
        fs::write(kin_home.join("bin/kin-daemon"), b"new-daemon").unwrap();
        fs::write(kin_home.join("bin/kin-vfs"), b"new-vfs").unwrap();
        let build = kin_buildinfo::get();
        let mut record = test_restart_pending(CURRENT_VERSION);
        record.kin_commit = build.sha.to_string();
        record.dependency_provenance = build.dependency_provenance.to_string();
        for obligation in &mut record.runtime_obligations {
            obligation.expected_identity =
                file_identity(&kin_home.join("bin").join(&obligation.component)).unwrap();
        }
        record.schema_version = RESTART_MARKER_SCHEMA_VERSION;
        record.reason = RESTART_FENCE_REASON.to_string();
        mark_restart_record_committed(&mut record, &kin_home, LINUX_COMPONENTS).unwrap();
        persist_restart_record_at(lock.install().unwrap(), &record).unwrap();
        drop(lock);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _home = EnvVarGuard::set("HOME", tmp.path().join("home"));

        acknowledge_runtime_restart(&[]).unwrap();

        assert!(!restart_pending_path(&kin_home).exists());
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn unknown_restart_lifecycle_fields_retain_exact_marker_bytes() {
        use std::os::unix::fs::PermissionsExt;

        for location in ["marker", "obligation", "session", "commit_identity"] {
            let tmp = tempfile::tempdir().unwrap();
            let kin_home = tmp.path().join("kin-home");
            let lock = InstallRootLock::acquire(&kin_home).unwrap();
            fs::hard_link(std::env::current_exe().unwrap(), kin_home.join("bin/kin")).unwrap();
            fs::write(kin_home.join("bin/kin-daemon"), b"new-daemon").unwrap();
            fs::write(kin_home.join("bin/kin-vfs"), b"new-vfs").unwrap();
            let build = kin_buildinfo::get();
            let mut record = test_restart_pending(CURRENT_VERSION);
            record.kin_commit = build.sha.to_string();
            record.dependency_provenance = build.dependency_provenance.to_string();
            for obligation in &mut record.runtime_obligations {
                obligation.expected_identity =
                    file_identity(&kin_home.join("bin").join(&obligation.component)).unwrap();
            }
            record.schema_version = RESTART_MARKER_SCHEMA_VERSION;
            record.reason = RESTART_FENCE_REASON.to_string();
            mark_restart_record_committed(&mut record, &kin_home, LINUX_COMPONENTS).unwrap();
            let mut value = serde_json::to_value(&record).unwrap();
            match location {
                "marker" => {
                    value
                        .as_object_mut()
                        .unwrap()
                        .insert("acknowledged".to_string(), serde_json::json!(false));
                }
                "obligation" => {
                    value["runtime_obligations"][0]
                        .as_object_mut()
                        .unwrap()
                        .insert("restarted".to_string(), serde_json::json!(true));
                }
                "session" => {
                    let executable = std::env::current_exe().unwrap();
                    let mut session = serde_json::to_value(RuntimeSessionAtUpdate {
                        pid: 1,
                        start_time: 1,
                        executable: executable.clone(),
                        executable_identity: file_identity(&executable).unwrap(),
                        binding: None,
                    })
                    .unwrap();
                    session
                        .as_object_mut()
                        .unwrap()
                        .insert("acknowledged".to_string(), serde_json::json!(false));
                    value["runtime_obligations"][0]["prior_sessions"]
                        .as_array_mut()
                        .unwrap()
                        .push(session);
                }
                "commit_identity" => {
                    value["commit_runtime_fence"][0]
                        .as_object_mut()
                        .unwrap()
                        .insert("reopened".to_string(), serde_json::json!(true));
                }
                _ => unreachable!(),
            }
            let marker_bytes = serde_json::to_vec_pretty(&value).unwrap();
            let marker = restart_pending_path(&kin_home);
            fs::write(&marker, &marker_bytes).unwrap();
            fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
            drop(lock);
            let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
            let _home = EnvVarGuard::set("HOME", tmp.path().join("home"));

            let error = acknowledge_runtime_restart(&[])
                .expect_err("unknown restart lifecycle fields must fail closed");
            assert!(format!("{error:#}").contains("unknown field"), "{location}");
            assert_eq!(fs::read(&marker).unwrap(), marker_bytes, "{location}");
        }
    }

    #[cfg(target_os = "linux")]
    fn runtime_convergence_fixture() -> (tempfile::TempDir, PathBuf, RestartPending) {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        fs::create_dir_all(kin_home.join("bin")).unwrap();
        fs::write(kin_home.join("bin/kin-daemon"), b"new-daemon").unwrap();
        fs::write(kin_home.join("bin/kin"), b"new-kin").unwrap();
        fs::write(kin_home.join("bin/kin-vfs"), b"new-vfs").unwrap();
        (tmp, kin_home, test_restart_pending("0.2.22"))
    }

    #[cfg(unix)]
    fn fenced_runtime_convergence_fixture() -> (tempfile::TempDir, PathBuf, RestartPending) {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"committed-");
        let mut record = test_restart_pending("0.2.22");
        record.schema_version = RESTART_MARKER_SCHEMA_VERSION;
        record.reason = RESTART_FENCE_REASON.to_string();
        for obligation in &mut record.runtime_obligations {
            obligation.expected_identity =
                file_identity(&kin_home.join("bin").join(&obligation.component)).unwrap();
        }
        mark_restart_record_committed(&mut record, &kin_home, LINUX_COMPONENTS).unwrap();
        (tmp, kin_home, record)
    }

    #[cfg(target_os = "linux")]
    fn prior_runtime_session(
        pid: u32,
        start_time: u64,
        executable: PathBuf,
        binding: Option<PathBuf>,
    ) -> RuntimeSessionAtUpdate {
        RuntimeSessionAtUpdate {
            pid,
            start_time,
            executable,
            executable_identity: bytes_identity(b"old-runtime"),
            binding,
        }
    }

    #[cfg(target_os = "linux")]
    fn replacement_runtime_process(
        pid: u32,
        start_time: u64,
        executable: PathBuf,
        identity: FileIdentity,
        command: Vec<String>,
        binding: Option<PathBuf>,
    ) -> ObservedRuntimeProcess {
        ObservedRuntimeProcess {
            pid,
            start_time,
            executable: Some(executable),
            executable_identity: Some(identity),
            command,
            binding,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restart_convergence_accepts_explicitly_inactive_runtimes_without_replacements() {
        let (_tmp, kin_home, record) = runtime_convergence_fixture();
        validate_runtime_convergence(&record, &kin_home, LINUX_COMPONENTS, &[], &HashMap::new())
            .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn stop_before_update_marker_persists_path_inode_and_hash_convergence() {
        let (_tmp, kin_home, record) = fenced_runtime_convergence_fixture();
        let fence = record
            .commit_runtime_fence
            .as_ref()
            .expect("post-commit fence must be durable");
        assert_eq!(fence.len(), 3);
        assert!(fence.iter().all(|identity| {
            identity.path.is_absolute()
                && identity.object.namespace != 0
                && identity.object.file != 0
                && identity.identity.size_bytes != 0
        }));
        validate_runtime_convergence(&record, &kin_home, LINUX_COMPONENTS, &[], &HashMap::new())
            .unwrap();

        let daemon = kin_home.join("bin/kin-daemon");
        let replacement = kin_home.join("bin/.kin-daemon-identical-replacement");
        fs::write(&replacement, fs::read(&daemon).unwrap()).unwrap();
        fs::rename(&replacement, &daemon).unwrap();
        let error = validate_runtime_convergence(
            &record,
            &kin_home,
            LINUX_COMPONENTS,
            &[],
            &HashMap::new(),
        )
        .expect_err("an identical-byte inode replacement must not satisfy runtime convergence");
        assert!(format!("{error:#}").contains("path, inode, or SHA-256"));
    }

    #[cfg(unix)]
    #[test]
    fn stop_before_update_marker_rejects_runtime_session_evidence() {
        let (_tmp, kin_home, record) = fenced_runtime_convergence_fixture();
        let evidence = [RuntimeSessionEvidence {
            kind: RuntimeKind::Daemon,
            pid: 4242,
        }];
        let error = validate_runtime_convergence(
            &record,
            &kin_home,
            LINUX_COMPONENTS,
            &evidence,
            &HashMap::new(),
        )
        .expect_err("new fenced markers must not accept legacy session assertions");
        assert!(format!("{error:#}").contains("accepts no runtime-session evidence"));
    }

    #[test]
    fn managed_server_classification_does_not_treat_version_text_as_runtime_evidence() {
        assert!(is_managed_serving_process(
            RuntimeKind::Mcp,
            "kin",
            &["kin".into(), "mcp".into(), "start".into()]
        ));
        assert!(!is_managed_serving_process(
            RuntimeKind::Mcp,
            "kin",
            &["kin".into(), "update".into()]
        ));
        assert!(!is_managed_serving_process(
            RuntimeKind::Daemon,
            "kin-daemon",
            &["kin-daemon".into(), "--version".into()]
        ));
        assert!(is_managed_serving_process(
            RuntimeKind::Daemon,
            "kin-daemon",
            &["kin-daemon".into(), "--supervisor".into()]
        ));
    }

    #[test]
    fn runtime_replacement_roles_reject_non_serving_commands() {
        assert!(runtime_process_serves_kind(
            RuntimeKind::Daemon,
            &["kin-daemon".into(), "--supervisor".into()]
        ));
        assert!(!runtime_process_serves_kind(
            RuntimeKind::Daemon,
            &["kin-daemon".into(), "--compat-json".into()]
        ));
        assert!(runtime_process_serves_kind(
            RuntimeKind::Mcp,
            &["kin".into(), "mcp".into(), "start".into()]
        ));
        assert!(!runtime_process_serves_kind(
            RuntimeKind::Mcp,
            &["kin".into(), "mcp".into(), "status".into()]
        ));
        assert!(runtime_process_serves_kind(
            RuntimeKind::Vfs,
            &["kin-vfs".into(), "nfs-start".into()]
        ));
        assert!(!runtime_process_serves_kind(
            RuntimeKind::Vfs,
            &["kin-vfs".into(), "status".into()]
        ));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn legacy_restart_ack_fails_without_pid_mapped_identity_authority() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        fs::create_dir_all(kin_home.join("bin")).unwrap();
        fs::write(kin_home.join("bin/kin-daemon"), b"new-daemon").unwrap();
        fs::write(kin_home.join("bin/kin"), b"new-kin").unwrap();
        fs::write(kin_home.join("bin/kin-vfs"), b"new-vfs").unwrap();
        let record = test_restart_pending("0.2.22");
        let error = validate_runtime_convergence(
            &record,
            &kin_home,
            LINUX_COMPONENTS,
            &[],
            &HashMap::new(),
        )
        .expect_err("legacy restart evidence must fail closed off Linux");
        assert!(format!("{error:#}").contains("PID-mapped executable identity"));
    }

    #[test]
    fn runtime_diagnostic_claims_mapped_inode_only_where_proc_exe_is_authoritative() {
        let scope = runtime_executable_diagnostic_scope();
        if cfg!(target_os = "linux") {
            assert_eq!(scope, "mapped executable object");
        } else {
            assert!(!scope.starts_with("mapped executable object"));
        }
        if cfg!(target_os = "macos") {
            assert!(scope.contains("process-mapped Mach vnode is not inferred"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restart_convergence_rejects_a_preupdate_pid_start_pair_still_live() {
        let (tmp, kin_home, mut record) = runtime_convergence_fixture();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let repo = repo.canonicalize().unwrap();
        let old_executable = kin_home.join("bin/kin-daemon");
        record.runtime_obligations[0]
            .prior_sessions
            .push(prior_runtime_session(
                4101,
                101,
                old_executable.clone(),
                Some(repo),
            ));
        let observed = HashMap::from([(
            4101,
            replacement_runtime_process(
                4101,
                101,
                old_executable,
                bytes_identity(b"new-daemon"),
                vec!["kin-daemon".to_string()],
                None,
            ),
        )]);

        let error =
            validate_runtime_convergence(&record, &kin_home, LINUX_COMPONENTS, &[], &observed)
                .expect_err("the exact pre-update process must be gone");
        assert!(format!("{error:#}").contains("still live"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restart_convergence_collapses_duplicate_mcp_sessions_by_binding() {
        let (tmp, kin_home, mut record) = runtime_convergence_fixture();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let repo = repo.canonicalize().unwrap();
        let mcp = record
            .runtime_obligations
            .iter_mut()
            .find(|obligation| obligation.kind == RuntimeKind::Mcp)
            .unwrap();
        for pid in [4201, 4202] {
            mcp.prior_sessions.push(prior_runtime_session(
                pid,
                100 + u64::from(pid),
                kin_home.join("bin/kin"),
                Some(repo.clone()),
            ));
        }
        let replacement_pid = 4203;
        let replacement = replacement_runtime_process(
            replacement_pid,
            record.recorded_at_unix_seconds + 1,
            kin_home.join("bin/kin").canonicalize().unwrap(),
            bytes_identity(b"new-kin"),
            vec![
                "kin".to_string(),
                "mcp".to_string(),
                "start".to_string(),
                "--repo".to_string(),
                repo.display().to_string(),
            ],
            Some(repo),
        );
        let evidence = [RuntimeSessionEvidence {
            kind: RuntimeKind::Mcp,
            pid: replacement_pid,
        }];

        validate_runtime_convergence(
            &record,
            &kin_home,
            LINUX_COMPONENTS,
            &evidence,
            &HashMap::from([(replacement_pid, replacement)]),
        )
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restart_convergence_does_not_require_vfs_when_vfs_was_inactive() {
        let (tmp, kin_home, mut record) = runtime_convergence_fixture();
        let repo = tmp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let repo = repo.canonicalize().unwrap();
        let daemon = record
            .runtime_obligations
            .iter_mut()
            .find(|obligation| obligation.kind == RuntimeKind::Daemon)
            .unwrap();
        daemon.prior_sessions.push(prior_runtime_session(
            4301,
            100,
            kin_home.join("bin/kin-daemon"),
            Some(repo.clone()),
        ));
        let replacement_pid = 4302;
        let replacement = replacement_runtime_process(
            replacement_pid,
            record.recorded_at_unix_seconds + 1,
            kin_home.join("bin/kin-daemon").canonicalize().unwrap(),
            bytes_identity(b"new-daemon"),
            vec![
                "kin-daemon".to_string(),
                "--repo".to_string(),
                repo.display().to_string(),
            ],
            Some(repo),
        );
        let evidence = [RuntimeSessionEvidence {
            kind: RuntimeKind::Daemon,
            pid: replacement_pid,
        }];

        validate_runtime_convergence(
            &record,
            &kin_home,
            LINUX_COMPONENTS,
            &evidence,
            &HashMap::from([(replacement_pid, replacement)]),
        )
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restart_convergence_rejects_wrong_binding_and_runtime_hash() {
        let (tmp, kin_home, mut record) = runtime_convergence_fixture();
        let repo = tmp.path().join("repo");
        let other = tmp.path().join("other");
        fs::create_dir(&repo).unwrap();
        fs::create_dir(&other).unwrap();
        let repo = repo.canonicalize().unwrap();
        let other = other.canonicalize().unwrap();
        let daemon = record
            .runtime_obligations
            .iter_mut()
            .find(|obligation| obligation.kind == RuntimeKind::Daemon)
            .unwrap();
        daemon.prior_sessions.push(prior_runtime_session(
            4401,
            100,
            kin_home.join("bin/kin-daemon"),
            Some(repo),
        ));
        let replacement_pid = 4402;
        let mut replacement = replacement_runtime_process(
            replacement_pid,
            record.recorded_at_unix_seconds + 1,
            kin_home.join("bin/kin-daemon").canonicalize().unwrap(),
            bytes_identity(b"wrong-daemon"),
            vec!["kin-daemon".to_string()],
            Some(other),
        );
        let evidence = [RuntimeSessionEvidence {
            kind: RuntimeKind::Daemon,
            pid: replacement_pid,
        }];
        let error = validate_runtime_convergence(
            &record,
            &kin_home,
            LINUX_COMPONENTS,
            &evidence,
            &HashMap::from([(replacement_pid, replacement.clone())]),
        )
        .expect_err("wrong executable identity must fail before binding acceptance");
        assert!(format!("{error:#}").contains("binary identity"));

        replacement.executable_identity = Some(bytes_identity(b"new-daemon"));
        let error = validate_runtime_convergence(
            &record,
            &kin_home,
            LINUX_COMPONENTS,
            &evidence,
            &HashMap::from([(replacement_pid, replacement)]),
        )
        .expect_err("a different repo binding must remain pending");
        assert!(format!("{error:#}").contains("does not replace"));
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn restart_ack_rejects_identity_mismatch_and_retains_obligation() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let lock = InstallRootLock::acquire(&kin_home).unwrap();
        fs::hard_link(std::env::current_exe().unwrap(), kin_home.join("bin/kin")).unwrap();
        let build = kin_buildinfo::get();
        let mut record = test_restart_pending(CURRENT_VERSION);
        record.kin_commit = "0".repeat(40);
        record.dependency_provenance = build.dependency_provenance.to_string();
        persist_restart_record_at(lock.install().unwrap(), &record).unwrap();
        drop(lock);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _home = EnvVarGuard::set("HOME", tmp.path().join("home"));

        let error = acknowledge_runtime_restart(&[])
            .expect_err("a different running build cannot acknowledge the marker");

        assert!(format!("{error:#}").contains("does not match"));
        assert!(restart_pending_path(&kin_home).is_file());
    }

    #[test]
    #[serial]
    fn update_config_path_honors_kin_home_over_kin_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let fallback = tmp.path().join("fallback");
        let preferred = tmp.path().join("preferred");
        let _kin_dir = EnvVarGuard::set("KIN_DIR", &fallback);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &preferred);

        assert_eq!(UpdateConfig::path().unwrap(), preferred.join("update.toml"));
    }

    #[test]
    #[serial]
    fn check_only_channel_override_does_not_persist_state() {
        let tmp = tempfile::tempdir().unwrap();
        let _kin_home = EnvVarGuard::set("KIN_HOME", tmp.path());

        assert_eq!(
            resolve_channel(tmp.path(), Some(Channel::Alpha), true, false),
            Channel::Alpha
        );
        assert!(
            !tmp.path().join("update.toml").exists(),
            "check-only channel resolution must stay read-only"
        );
    }

    #[test]
    fn update_check_json_contract_is_stable_and_machine_readable() {
        let check = UpdateCheck {
            schema: UPDATE_CHECK_SCHEMA,
            current_version: "0.2.21",
            latest_version: "0.2.22",
            release_tag: "v0.2.22",
            release_commit_sha: "0123456789abcdef0123456789abcdef01234567",
            channel: "stable",
            update_policy: "prompt",
            update_available: true,
            platform_asset: "kin-macos-aarch64.tar.gz",
            platform_archive_sha256:
                "a7f58f3c51f6e6bc7c3c2f1de979b67f506e9c3826d38e08752d28daf2f11731",
            restart_ack_required: false,
            mcp_repair_pending: false,
        };
        let value = serde_json::to_value(check).unwrap();

        assert_eq!(value["schema"], "kin.update-check.v1");
        assert_eq!(value["current_version"], "0.2.21");
        assert_eq!(value["latest_version"], "0.2.22");
        assert_eq!(value["release_tag"], "v0.2.22");
        assert_eq!(
            value["release_commit_sha"],
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(value["channel"], "stable");
        assert_eq!(value["update_available"], true);
        assert_eq!(value["platform_asset"], "kin-macos-aarch64.tar.gz");
        assert_eq!(
            value["platform_archive_sha256"],
            "a7f58f3c51f6e6bc7c3c2f1de979b67f506e9c3826d38e08752d28daf2f11731"
        );
        assert_eq!(value["restart_ack_required"], false);
        assert_eq!(value["mcp_repair_pending"], false);
        // The watchdog reads the policy here rather than parsing update.toml,
        // so it is part of the contract and not an incidental field.
        assert_eq!(value["update_policy"], "prompt");
        // The schema stays v1 because this addition is purely additive: no
        // field was removed and none changed meaning, so every existing reader
        // keeps working. The count is what makes that claim checkable, and it
        // is why adding a field has to be a deliberate edit here.
        assert_eq!(value.as_object().unwrap().len(), 12);
    }

    #[test]
    fn release_expectation_is_complete_and_rejects_a_latest_release_race() {
        let expected_version = Version::parse("0.2.22").unwrap();
        let expected_sha = "a".repeat(40);
        let expected_archive_sha256 = "b".repeat(64);
        let partial_expectations = [
            (Some(expected_version.clone()), None, None),
            (None, Some(expected_sha.clone()), None),
            (None, None, Some(expected_archive_sha256.clone())),
            (
                Some(expected_version.clone()),
                Some(expected_sha.clone()),
                None,
            ),
            (
                Some(expected_version.clone()),
                None,
                Some(expected_archive_sha256.clone()),
            ),
            (
                None,
                Some(expected_sha.clone()),
                Some(expected_archive_sha256.clone()),
            ),
        ];
        for (version, commit_sha, archive_sha256) in partial_expectations {
            assert!(ReleaseExpectation::from_options(version, commit_sha, archive_sha256).is_err());
        }
        assert!(ReleaseExpectation::from_options(None, None, None)
            .unwrap()
            .is_none());

        let expectation = ReleaseExpectation::from_options(
            Some(expected_version.clone()),
            Some(expected_sha.clone()),
            Some(expected_archive_sha256.clone()),
        )
        .unwrap()
        .unwrap();
        expectation
            .validate_selected_release(&expected_version, &expected_sha)
            .unwrap();
        expectation
            .validate_selected_archive_sha256(&expected_archive_sha256)
            .unwrap();
        assert!(expectation
            .validate_selected_archive_sha256(&"c".repeat(64))
            .is_err());

        let version_race = expectation
            .validate_selected_release(&Version::parse("0.2.23").unwrap(), &"b".repeat(40))
            .expect_err("a newly promoted Latest release must not cross the automation pin");
        assert!(format!("{version_race:#}").contains("pinned version"));

        let moved_tag = expectation
            .validate_selected_release(&expected_version, &"b".repeat(40))
            .expect_err("a moved release tag must not cross the automation pin");
        assert!(format!("{moved_tag:#}").contains("pinned commit"));
    }

    #[test]
    fn release_expectation_authenticates_exact_owned_archive_bytes() {
        let archive = b"exact external byte-authority platform archive";
        let expected_digest = hex::encode(Sha256::digest(archive));
        let expectation = ReleaseExpectation::from_options(
            Some(Version::parse("0.2.22").unwrap()),
            Some("a".repeat(40)),
            Some(expected_digest),
        )
        .unwrap()
        .unwrap();

        expectation.validate_archive_bytes(archive).unwrap();
        let error = expectation
            .validate_archive_bytes(b"replacement archive")
            .expect_err("asset replacement must not cross the independently supplied digest");
        let message = format!("{error:#}");
        assert!(message.contains("externally attestation-derived expected archive SHA-256"));
        assert!(message.contains("do not authenticate archive bytes"));
        assert!(message.contains("before install authority"));
    }

    #[cfg(unix)]
    #[test]
    fn pinned_install_phase_refuses_to_downgrade_a_concurrently_newer_generation() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let kin_home = temp.path().join("kin-home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let managed_cli = kin_home.join("bin/kin");
        fs::copy(std::env::current_exe().unwrap(), &managed_cli).unwrap();
        fs::set_permissions(&managed_cli, fs::Permissions::from_mode(0o755)).unwrap();
        let authority =
            UpdaterStartAuthority::capture_test_file(&kin_home, LINUX_COMPONENTS, &managed_cli)
                .unwrap();

        // Model a complete newer install winning while the old process is in
        // remote preflight. Atomic replacement preserves the old executing
        // inode through `authority` while every managed pathname moves ahead.
        for component in LINUX_COMPONENTS {
            let destination = component_path(&kin_home, *component);
            let replacement = destination.with_extension("newer-install");
            fs::write(&replacement, format!("newer-{}", component.name)).unwrap();
            fs::set_permissions(
                &replacement,
                fs::Permissions::from_mode(if component.location == ComponentLocation::Bin {
                    0o755
                } else {
                    0o644
                }),
            )
            .unwrap();
            fs::rename(&replacement, &destination).unwrap();
        }
        let newer = bundle_snapshot(&kin_home, LINUX_COMPONENTS);

        let error =
            enter_pinned_install_phase(&kin_home, LINUX_COMPONENTS, Some(&authority), Ok(()))
                .err()
                .expect(
                    "an old preflight must not obtain downgrade authority after a newer install",
                );
        assert!(format!("{error:#}").contains("bundle generation changed"));
        assert_bundle_matches(&kin_home, LINUX_COMPONENTS, &newer);
        assert!(transaction_dirs(&kin_home).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_remote_preflight_restart_fence_is_read_only() {
        use std::os::unix::fs::PermissionsExt as _;

        for marker_kind in ["absent", "malformed-directory"] {
            let temp = tempfile::tempdir().unwrap();
            let kin_home = temp.path().join("kin-home");
            fs::create_dir(&kin_home).unwrap();
            fs::set_permissions(&kin_home, fs::Permissions::from_mode(0o751)).unwrap();
            if marker_kind == "malformed-directory" {
                fs::create_dir(restart_pending_path(&kin_home)).unwrap();
            }
            let before = install_tree_snapshot(&kin_home);
            let before_mode = fs::symlink_metadata(&kin_home)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777;

            let result = refuse_restart_marker_before_remote_preflight(&kin_home);
            if marker_kind == "absent" {
                result.unwrap();
            } else {
                let error = result.expect_err("any restart-marker path must fence preflight");
                assert!(format!("{error:#}").contains("before any install lock"));
            }

            assert_eq!(install_tree_snapshot(&kin_home), before);
            assert_eq!(
                fs::symlink_metadata(&kin_home)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                before_mode
            );
            assert!(!kin_home.join("update.lock").exists());
            assert!(!kin_home.join("bin").exists());
            assert!(!kin_home.join("lib").exists());
        }

        let temp = tempfile::tempdir().unwrap();
        let absent_home = temp.path().join("absent-kin-home");
        let before = install_tree_snapshot(temp.path());
        refuse_restart_marker_before_remote_preflight(&absent_home).unwrap();
        assert_eq!(install_tree_snapshot(temp.path()), before);
        assert!(!absent_home.exists());
    }

    #[cfg(unix)]
    #[test]
    fn failed_pinned_preflight_is_byte_entry_inode_and_mode_read_only() {
        use std::os::unix::fs::PermissionsExt;

        for failure in ["pin-mismatch", "remote-timeout"] {
            let temp = tempfile::tempdir().unwrap();
            let kin_home = temp.path().join("kin-home");
            fs::create_dir(&kin_home).unwrap();
            fs::set_permissions(&kin_home, fs::Permissions::from_mode(0o751)).unwrap();
            let state = kin_home.join("state");
            fs::create_dir(&state).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(0o711)).unwrap();
            let sentinel = state.join("sentinel");
            fs::write(&sentinel, b"existing-install-state").unwrap();
            fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o640)).unwrap();

            let before = install_tree_snapshot(&kin_home);
            let before_mode = fs::symlink_metadata(&kin_home)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777;
            validate_existing_install_root(&kin_home).unwrap();
            refuse_restart_marker_before_remote_preflight(&kin_home).unwrap();
            let expectation = ReleaseExpectation {
                version: Version::parse("0.2.22").unwrap(),
                commit_sha: "a".repeat(40),
                archive_sha256: "b".repeat(64),
            };
            let preflight: Result<()> = match failure {
                "pin-mismatch" => expectation
                    .validate_selected_release(&Version::parse("0.2.23").unwrap(), &"b".repeat(40)),
                "remote-timeout" => Err(anyhow::anyhow!(
                    "simulated bounded remote preflight timeout"
                )),
                _ => unreachable!(),
            };

            let error = enter_pinned_install_phase(&kin_home, LINUX_COMPONENTS, None, preflight)
                .err()
                .expect("a failed preflight must never open the install lock");
            assert!(format!("{error:#}").contains(if failure == "pin-mismatch" {
                "pinned version"
            } else {
                "remote preflight timeout"
            }));
            assert_eq!(
                install_tree_snapshot(&kin_home),
                before,
                "{failure} changed KIN_HOME entries, bytes, inodes, or modes"
            );
            assert_eq!(
                fs::symlink_metadata(&kin_home)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                before_mode,
                "{failure} chmodded KIN_HOME before install authority"
            );
            assert!(!kin_home.join("update.lock").exists());
            assert!(!kin_home.join("bin").exists());
            assert!(!kin_home.join("lib").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_pinned_preflight_does_not_create_an_absent_install_root() {
        let temp = tempfile::tempdir().unwrap();
        let absent_home = temp.path().join("absent-kin-home");
        let before = install_tree_snapshot(temp.path());
        let preflight: Result<()> = Err(anyhow::anyhow!(
            "simulated remote failure before install authority"
        ));

        let error = enter_pinned_install_phase(&absent_home, LINUX_COMPONENTS, None, preflight)
            .err()
            .expect("failed preflight must return its original error");
        assert!(format!("{error:#}").contains("simulated remote failure"));
        assert_eq!(install_tree_snapshot(temp.path()), before);
        assert!(!absent_home.exists());
        assert!(!absent_home.join("update.lock").exists());
        assert!(!absent_home.join("bin").exists());
        assert!(!absent_home.join("lib").exists());
    }

    #[cfg(unix)]
    #[test]
    fn malformed_static_candidate_identities_are_read_only_before_the_install_lock() {
        let identity = test_static_build_identity();
        let valid = bytes_with_static_build_identity(b"valid", &identity);
        let mut duplicate = valid.clone();
        duplicate.extend_from_slice(&valid);
        let truncated = valid[..valid.len() - 8].to_vec();
        let mut wrong = identity.clone();
        wrong.version = "0.2.23".to_string();
        let cases = [
            ("missing", b"no sentinel".to_vec(), "contains 0 static"),
            ("duplicate", duplicate, "contains 2 static"),
            ("truncated", truncated, "truncated static"),
            (
                "provenance-mismatch",
                bytes_with_static_build_identity(b"wrong", &wrong),
                "does not match provenance",
            ),
        ];

        for (case, cli, expected_error) in cases {
            let temp = tempfile::tempdir().unwrap();
            let kin_home = temp.path().join("kin-home");
            fs::create_dir(&kin_home).unwrap();
            fs::create_dir(kin_home.join("state")).unwrap();
            fs::write(kin_home.join("state/sentinel"), b"real-install-state").unwrap();
            let before = install_tree_snapshot(&kin_home);
            let (archive, provenance, identities) = pinned_probe_fixture(cli, valid.clone());

            let error = validate_pinned_preflight_build_identity(
                &kin_home,
                &archive,
                "kin-linux-x86_64.tar.gz",
                LINUX_COMPONENTS,
                "0.2.22",
                &provenance,
                &identities,
            )
            .expect_err("an unproved static identity must fail before install authority");

            assert!(
                format!("{error:#}").contains(expected_error),
                "{case}: {error:#}"
            );
            assert_eq!(
                install_tree_snapshot(&kin_home),
                before,
                "{case} changed real KIN_HOME"
            );
            assert!(!kin_home.join("update.lock").exists());
            assert!(!kin_home.join("bin").exists());
            assert!(!kin_home.join("lib").exists());
            let container = temp.path().join(PRIVATE_TEMP_CONTAINER);
            assert!(container.is_dir());
            assert_eq!(fs::read_dir(container).unwrap().count(), 0);
        }
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn forged_cohosted_evidence_cannot_cross_the_independent_archive_digest() {
        let temp = tempfile::tempdir().unwrap();
        let kin_home = temp.path().join("kin-home");
        fs::create_dir(&kin_home).unwrap();
        fs::create_dir(kin_home.join("state")).unwrap();
        fs::write(kin_home.join("state/sentinel"), b"real-install-state").unwrap();
        let before = install_tree_snapshot(&kin_home);
        let marker = temp.path().join("forged-candidate-executed");
        let script = format!("#!/bin/sh\nprintf forged > {}\nexit 99\n", marker.display());
        let identity = test_static_build_identity();
        let (archive, provenance, fixture_identities) = pinned_probe_fixture(
            bytes_with_static_build_identity(script.as_bytes(), &identity),
            bytes_with_static_build_identity(b"forged daemon", &identity),
        );
        let archive_name = "kin-linux-x86_64.tar.gz";

        // Model a fully compromised mutable release surface: the attacker also
        // supplies a matching checksum, provenance, per-file identities, and
        // embedded static sentinels.
        let forged_checksum = hex::encode(Sha256::digest(&archive));
        let wrong_external_digest = format!(
            "{}{}",
            if forged_checksum.starts_with('0') {
                '1'
            } else {
                '0'
            },
            &forged_checksum[1..]
        );
        let release = GithubRelease {
            tag_name: "v0.2.22".to_string(),
            prerelease: false,
            assets: vec![GithubAsset {
                name: archive_name.to_string(),
                browser_download_url: format!("https://example.invalid/{archive_name}"),
            }],
        };

        let expectation = ReleaseExpectation::from_options(
            Some(Version::parse("0.2.22").unwrap()),
            Some("a".repeat(40)),
            Some(wrong_external_digest),
        )
        .unwrap()
        .unwrap();
        expectation
            .validate_selected_release(&Version::parse("0.2.22").unwrap(), &"a".repeat(40))
            .unwrap();
        let preflight = expectation.validate_archive_bytes(&archive);
        let error = enter_pinned_install_phase(&kin_home, LINUX_COMPONENTS, None, preflight)
            .err()
            .expect("a forged mutable release must fail before install authority");

        assert!(format!("{error:#}")
            .contains("externally attestation-derived expected archive SHA-256"));
        assert_eq!(install_tree_snapshot(&kin_home), before);
        assert!(!kin_home.join("update.lock").exists());

        // Counterfactual only: after the real preflight has already failed
        // read-only on the external digest, prove that every attacker-controlled
        // defense-in-depth input was internally consistent and would pass.
        verify_sha256(&archive, &forged_checksum).unwrap();
        let metadata_identities = validate_artifact_provenance_metadata(
            &provenance,
            &release,
            &"a".repeat(40),
            &release.assets[0],
            &archive,
            LINUX_COMPONENTS,
            true,
        )
        .unwrap();
        assert_eq!(metadata_identities, fixture_identities);
        let payload_identities = validate_archive_payload_provenance_and_static_identity(
            &archive,
            archive_name,
            LINUX_COMPONENTS,
            &metadata_identities,
            &provenance,
        )
        .unwrap();
        validate_pinned_preflight_build_identity(
            &kin_home,
            &archive,
            archive_name,
            LINUX_COMPONENTS,
            "0.2.22",
            &provenance,
            &payload_identities,
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(!marker.exists(), "forged candidate bytes were executed");
        assert_eq!(install_tree_snapshot(&kin_home), before);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn executable_looking_candidate_is_statically_validated_and_never_executed() {
        let temp = tempfile::tempdir().unwrap();
        let kin_home = temp.path().join("kin-home");
        fs::create_dir(&kin_home).unwrap();
        fs::create_dir(kin_home.join("state")).unwrap();
        fs::write(kin_home.join("state/sentinel"), b"real-install-state").unwrap();
        let before = install_tree_snapshot(&kin_home);
        let marker = temp.path().join("candidate-executed");
        let script = format!(
            "#!/bin/sh\nsetsid /bin/sh -c 'printf escaped > {}' &\nprintf executed > {}\nexit 99\n",
            marker.display(),
            marker.display()
        );
        let identity = test_static_build_identity();
        let (archive, provenance, identities) = pinned_probe_fixture(
            bytes_with_static_build_identity(script.as_bytes(), &identity),
            bytes_with_static_build_identity(b"daemon that must remain inert", &identity),
        );

        validate_pinned_preflight_build_identity(
            &kin_home,
            &archive,
            "kin-linux-x86_64.tar.gz",
            LINUX_COMPONENTS,
            "0.2.22",
            &provenance,
            &identities,
        )
        .unwrap();

        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !marker.exists(),
            "candidate bytes were unexpectedly executed"
        );
        assert_eq!(install_tree_snapshot(&kin_home), before);
        assert!(!kin_home.join("update.lock").exists());
    }

    #[test]
    fn private_temp_lease_is_watchdog_visible_and_protects_a_live_sibling() {
        let temp = tempfile::tempdir().unwrap();
        let mut root = PrivateUpdaterTempDir::create(
            temp.path(),
            PREFLIGHT_TEMP_PREFIX,
            "extracting authenticated release",
        )
        .unwrap();
        let path = root.path().to_path_buf();
        let record: PrivateTempLeaseRecord =
            serde_json::from_slice(&fs::read(path.join(TEMP_LEASE_FILE)).unwrap()).unwrap();
        let (pid, start_time) = current_process_lease_identity().unwrap();
        assert_eq!(record.schema_version, TEMP_LEASE_SCHEMA_VERSION);
        assert_eq!(record.pid, pid);
        assert_eq!(record.process_start_time, start_time);
        assert_eq!(record.status, "extracting authenticated release");
        assert_eq!(
            record.root_binding,
            private_temp_root_identity(&path).unwrap()
        );

        assert_eq!(
            cleanup_stale_private_temp_dirs(temp.path(), PREFLIGHT_TEMP_PREFIX).unwrap(),
            0,
            "a locked live sibling lease must never be reaped"
        );
        assert!(path.is_dir());
        root.persist_status("validating staged static build identity")
            .unwrap();
        let updated: PrivateTempLeaseRecord =
            serde_json::from_slice(&fs::read(path.join(TEMP_LEASE_FILE)).unwrap()).unwrap();
        assert_eq!(updated.status, "validating staged static build identity");
        drop(root);
        assert!(!path.exists());
    }

    #[test]
    fn private_temp_lease_crash_worker() {
        let Ok(parent) = std::env::var("KIN_UPDATE_TEMP_LEASE_CRASH_PARENT") else {
            return;
        };
        let marker = std::env::var("KIN_UPDATE_TEMP_LEASE_CRASH_MARKER").unwrap();
        let mut root = PrivateUpdaterTempDir::create(
            Path::new(&parent),
            PREFLIGHT_TEMP_PREFIX,
            "crash-test-created",
        )
        .unwrap();
        root.persist_status("crash-test-orphaned").unwrap();
        fs::write(marker, root.path().to_string_lossy().as_bytes()).unwrap();
        std::process::exit(86);
    }

    #[test]
    fn private_temp_cleanup_crash_worker() {
        let Ok(parent) = std::env::var("KIN_UPDATE_TEMP_CLEANUP_CRASH_PARENT") else {
            return;
        };
        cleanup_stale_private_temp_dirs(Path::new(&parent), PREFLIGHT_TEMP_PREFIX).unwrap();
    }

    fn spawn_private_temp_orphan(parent: &Path) -> PathBuf {
        let marker = parent.join(format!("marker-{}", uuid::Uuid::new_v4()));
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "commands::update::tests::private_temp_lease_crash_worker",
                "--nocapture",
            ])
            .env("KIN_UPDATE_TEMP_LEASE_CRASH_PARENT", parent)
            .env("KIN_UPDATE_TEMP_LEASE_CRASH_MARKER", &marker);
        let output = test_subprocess_output(command, "private temp lease crash worker").unwrap();
        assert_eq!(
            output.status.code(),
            Some(86),
            "crash worker output: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        PathBuf::from(String::from_utf8(fs::read(marker).unwrap()).unwrap())
    }

    #[test]
    #[serial]
    fn subprocess_crash_leftover_is_reclaimed_from_private_container() {
        let temp = tempfile::tempdir().unwrap();
        let orphan = spawn_private_temp_orphan(temp.path());
        assert!(orphan.is_dir());
        let lease: PrivateTempLeaseRecord =
            serde_json::from_slice(&fs::read(orphan.join(TEMP_LEASE_FILE)).unwrap()).unwrap();
        assert_eq!(lease.status, "crash-test-orphaned");
        assert_eq!(
            cleanup_stale_private_temp_dirs(temp.path(), PREFLIGHT_TEMP_PREFIX).unwrap(),
            1
        );
        assert!(!orphan.exists());
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn cleanup_resumes_quarantine_after_rename_and_mid_delete_crashes() {
        for point in ["after-rename", "mid-delete"] {
            let temp = tempfile::tempdir().unwrap();
            let orphan = spawn_private_temp_orphan(temp.path());
            fs::write(orphan.join("payload"), b"owned payload").unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "commands::update::tests::private_temp_cleanup_crash_worker",
                    "--nocapture",
                ])
                .env("KIN_UPDATE_TEMP_CLEANUP_CRASH_PARENT", temp.path())
                .env("KIN_UPDATE_TEST_TEMP_CLEANUP_CRASH_POINT", point);
            let output = test_subprocess_output(
                command,
                &format!("private temp cleanup crash worker at {point}"),
            )
            .unwrap();
            assert_eq!(
                output.status.code(),
                Some(87),
                "cleanup crash worker at {point}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let container = temp.path().join(PRIVATE_TEMP_CONTAINER);
            let names = fs::read_dir(&container)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert_eq!(names.len(), 1, "{point}: {names:?}");
            assert!(names[0].starts_with(PRIVATE_TEMP_RECLAIM_PREFIX));
            assert_eq!(
                cleanup_stale_private_temp_dirs(temp.path(), PREFLIGHT_TEMP_PREFIX).unwrap(),
                1
            );
            assert_eq!(fs::read_dir(container).unwrap().count(), 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn unrelated_parent_entries_do_not_consume_the_private_container_scan_bound() {
        let temp = tempfile::tempdir().unwrap();
        for index in 0..(MAX_TEMP_LEASE_SCAN_ENTRIES + 64) {
            fs::write(temp.path().join(format!("unrelated-{index}")), b"x").unwrap();
        }
        let root = PrivateUpdaterTempDir::create(
            temp.path(),
            PREFLIGHT_TEMP_PREFIX,
            "bounded-parent-scan",
        )
        .unwrap();
        assert!(root
            .path()
            .starts_with(temp.path().join(PRIVATE_TEMP_CONTAINER)));
    }

    #[cfg(unix)]
    #[test]
    fn private_container_fails_closed_on_unexpected_or_over_bound_state() {
        use std::os::unix::fs::DirBuilderExt as _;

        let temp = tempfile::tempdir().unwrap();
        let container = ensure_private_updater_temp_container(temp.path()).unwrap();
        fs::write(container.join("unexpected"), b"x").unwrap();
        let error = cleanup_stale_private_temp_dirs(temp.path(), PREFLIGHT_TEMP_PREFIX)
            .expect_err("unexpected owned-container state must fail closed");
        assert!(format!("{error:#}").contains("unexpected entry"));
        fs::remove_file(container.join("unexpected")).unwrap();
        for _ in 0..=MAX_TEMP_LEASE_SCAN_ENTRIES {
            let path = container.join(format!(
                "{PRIVATE_TEMP_RECLAIM_PREFIX}{}",
                uuid::Uuid::new_v4()
            ));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).create(path).unwrap();
        }
        let error = cleanup_stale_private_temp_dirs(temp.path(), PREFLIGHT_TEMP_PREFIX)
            .expect_err("owned-container scan truncation must fail closed");
        assert!(format!("{error:#}").contains("inspection bound"));
    }

    /// A permissive umask must not widen the private updater root.
    ///
    /// The observation runs in a worker process because the file-creation mask
    /// is process-global, exactly like the environment table: every directory
    /// any concurrently running test creates while this one holds `umask(0)`
    /// comes out world-writable, and Kin's own namespace-safety checks then
    /// refuse those directories. The failures land on whatever test happened to
    /// be creating a temporary directory in that window, which is why the set
    /// moved run to run. `#[serial]` cannot prevent it: it orders a test only
    /// against other serial tests, not against the thousand running beside it.
    /// The restrictive-umask tests in `setup.rs` already take this shape.
    #[cfg(unix)]
    #[test]
    fn private_root_is_atomically_0700_even_with_umask_zero() {
        use std::os::unix::fs::PermissionsExt as _;

        const WORKER_ROOT: &str = "KIN_UPDATE_TEST_PRIVATE_ROOT_UMASK_ROOT";

        if let Some(root) = std::env::var_os(WORKER_ROOT) {
            let root = PathBuf::from(root);
            // SAFETY: umask accepts every mode value and has no pointer
            // arguments. This process exists only to hold the permissive mask.
            unsafe { libc::umask(0) };
            let private =
                PrivateUpdaterTempDir::create(&root, PREFLIGHT_TEMP_PREFIX, "atomic-mode-test")
                    .unwrap();
            assert_eq!(
                fs::symlink_metadata(private.path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("observed-mode");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "commands::update::tests::private_root_is_atomically_0700_even_with_umask_zero",
                "--nocapture",
            ])
            .env(WORKER_ROOT, temp.path())
            .env("KIN_UPDATE_TEST_PRIVATE_CREATE_OBSERVE", &marker);
        let output = test_subprocess_output(command, "private updater root under umask 0").unwrap();
        assert!(
            output.status.success(),
            "worker output: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(&marker).unwrap(),
            "700",
            "creation must request 0700 atomically rather than widen and repair"
        );
    }

    #[test]
    fn updater_http_client_has_bounded_unattended_timeouts() {
        assert!(!UPDATE_HTTP_CONNECT_TIMEOUT.is_zero());
        assert!(UPDATE_HTTP_CONNECT_TIMEOUT < UPDATE_HTTP_REQUEST_TIMEOUT);
        assert!(UPDATE_HTTP_REQUEST_TIMEOUT <= Duration::from_secs(300));
        build_update_http_client().unwrap();
        assert!(
            build_update_http_client_with_timeouts(Duration::ZERO, Duration::from_secs(1)).is_err()
        );
        assert!(build_update_http_client_with_timeouts(
            Duration::from_secs(2),
            Duration::from_secs(1)
        )
        .is_err());
    }

    #[test]
    fn bounded_http_body_accumulation_accepts_the_limit_and_rejects_one_byte_more() {
        let mut body = Vec::new();
        append_bounded_response_chunk(&mut body, b"abcd", 4, "test response").unwrap();
        assert_eq!(body, b"abcd");
        let error = append_bounded_response_chunk(&mut body, b"e", 4, "test response")
            .expect_err("a streamed body must not grow beyond its cap");
        assert!(format!("{error:#}").contains("maximum response size"));
        assert_eq!(body, b"abcd", "rejected bytes must not be retained");
    }

    #[test]
    fn expected_commit_parser_normalizes_hex_and_rejects_non_commits() {
        assert_eq!(
            parse_expected_commit_sha(&"A".repeat(40)).unwrap(),
            "a".repeat(40)
        );
        assert!(parse_expected_commit_sha(&"a".repeat(39)).is_err());
        assert!(parse_expected_commit_sha(&format!("{}g", "a".repeat(39))).is_err());
    }

    #[test]
    fn expected_archive_digest_parser_normalizes_hex_and_rejects_malformed_digests() {
        assert_eq!(
            parse_expected_archive_sha256(&"A".repeat(64)).unwrap(),
            "a".repeat(64)
        );
        assert!(parse_expected_archive_sha256(&"a".repeat(63)).is_err());
        assert!(parse_expected_archive_sha256(&"a".repeat(65)).is_err());
        assert!(parse_expected_archive_sha256(&format!("{}g", "a".repeat(63))).is_err());
    }

    #[test]
    fn annotated_release_tags_peel_to_one_exact_commit() {
        let mut seen = HashSet::new();
        assert_eq!(
            inspect_git_object(
                GithubGitObject {
                    sha: "a".repeat(40),
                    kind: "tag".to_string(),
                },
                &mut seen,
                0,
            )
            .unwrap(),
            GitObjectStep::FetchAnnotatedTag("a".repeat(40))
        );
        assert_eq!(
            inspect_git_object(
                GithubGitObject {
                    sha: "b".repeat(40),
                    kind: "commit".to_string(),
                },
                &mut seen,
                1,
            )
            .unwrap(),
            GitObjectStep::ResolvedCommit("b".repeat(40))
        );
    }

    #[test]
    fn annotated_release_tag_cycles_and_unbounded_chains_fail_closed() {
        let mut seen = HashSet::new();
        let tag = GithubGitObject {
            sha: "a".repeat(40),
            kind: "tag".to_string(),
        };
        inspect_git_object(tag.clone(), &mut seen, 0).unwrap();
        assert!(inspect_git_object(tag, &mut seen, 1).is_err());

        let mut seen = HashSet::new();
        let too_deep = inspect_git_object(
            GithubGitObject {
                sha: "c".repeat(40),
                kind: "tag".to_string(),
            },
            &mut seen,
            MAX_ANNOTATED_TAG_DEPTH,
        )
        .expect_err("an unbounded annotated-tag chain must fail closed");
        assert!(format!("{too_deep:#}").contains("maximum annotated-tag depth"));
    }

    /// Real asset names published for a stable release, pinned via:
    /// `gh release view v0.2.12 --repo firelock-ai/kin --json assets --jq '.assets[].name'`
    fn mock_v0_2_12_release() -> GithubRelease {
        let names = [
            "checksums-sha256.txt",
            "kin-linux-aarch64.tar.gz",
            "kin-linux-aarch64.tar.gz.sha256",
            "kin-linux-x86_64.tar.gz",
            "kin-linux-x86_64.tar.gz.sha256",
            "kin-macos-aarch64.tar.gz",
            "kin-macos-aarch64.tar.gz.sha256",
            "kin-macos-x86_64.tar.gz",
            "kin-macos-x86_64.tar.gz.sha256",
            "kin-windows-x86_64.zip",
            "kin-windows-x86_64.zip.sha256",
        ];
        GithubRelease {
            tag_name: "v0.2.12".to_string(),
            prerelease: false,
            assets: names
                .iter()
                .map(|name| GithubAsset {
                    name: name.to_string(),
                    browser_download_url: format!(
                        "https://github.com/firelock-ai/kin/releases/download/v0.2.12/{name}"
                    ),
                })
                .collect(),
        }
    }

    #[test]
    fn platform_asset_name_matches_real_release_naming() {
        // Matrix covering the acceptance-required platforms plus every other
        // real asset firelock-ai/kin v0.2.12 publishes.
        assert_eq!(
            platform_asset_name("macos", "aarch64").unwrap(),
            "kin-macos-aarch64.tar.gz"
        );
        assert_eq!(
            platform_asset_name("linux", "x86_64").unwrap(),
            "kin-linux-x86_64.tar.gz"
        );
        assert_eq!(
            platform_asset_name("linux", "aarch64").unwrap(),
            "kin-linux-aarch64.tar.gz"
        );
        assert_eq!(
            platform_asset_name("macos", "x86_64").unwrap(),
            "kin-macos-x86_64.tar.gz"
        );
        // Windows is packaged as a zip (release.yml's Compress-Archive step),
        // not a tar.gz.
        assert_eq!(
            platform_asset_name("windows", "x86_64").unwrap(),
            "kin-windows-x86_64.zip"
        );
    }

    #[test]
    fn platform_asset_name_rejects_unsupported_platforms() {
        assert!(platform_asset_name("freebsd", "x86_64").is_err());
        assert!(platform_asset_name("linux", "riscv64").is_err());
    }

    #[test]
    fn current_platform_asset_name_resolves_on_this_test_host() {
        // Sanity check that the env::consts-based wrapper produces a name
        // `platform_asset_name` accepts on whatever host actually runs the
        // test suite.
        let name = current_platform_asset_name().unwrap();
        assert!(name.starts_with("kin-"), "unexpected asset name: {name}");
        assert!(
            name.ends_with(".tar.gz") || name.ends_with(".zip"),
            "unexpected extension: {name}"
        );
    }

    #[test]
    fn find_release_asset_matches_macos_aarch64() {
        let release = mock_v0_2_12_release();
        let asset = find_release_asset(&release, "kin-macos-aarch64.tar.gz").unwrap();
        assert_eq!(asset.name, "kin-macos-aarch64.tar.gz");
        assert!(asset
            .browser_download_url
            .ends_with("kin-macos-aarch64.tar.gz"));
    }

    #[test]
    fn find_release_asset_matches_linux_x86_64() {
        let release = mock_v0_2_12_release();
        let asset = find_release_asset(&release, "kin-linux-x86_64.tar.gz").unwrap();
        assert_eq!(asset.name, "kin-linux-x86_64.tar.gz");
        assert!(asset
            .browser_download_url
            .ends_with("kin-linux-x86_64.tar.gz"));
    }

    #[test]
    fn find_release_asset_matches_the_archive_not_its_sha256_sibling() {
        // Every real archive has an adjacent "<name>.sha256" asset whose name
        // contains the archive name as a substring (e.g.
        // "kin-macos-aarch64.tar.gz.sha256"). Exact-name matching must
        // resolve the archive itself, never the checksum sidecar.
        let release = mock_v0_2_12_release();
        let asset = find_release_asset(&release, "kin-macos-aarch64.tar.gz").unwrap();
        assert_eq!(asset.name, "kin-macos-aarch64.tar.gz");
    }

    #[test]
    fn find_release_asset_reports_an_honest_actionable_error_on_no_match() {
        let release = mock_v0_2_12_release();
        let err = find_release_asset(&release, "kin-freebsd-riscv64.tar.gz")
            .expect_err("freebsd is not a published platform");
        let message = format!("{err:#}");
        // Names exactly what was looked for...
        assert!(
            message.contains("kin-freebsd-riscv64.tar.gz"),
            "error should name the asset that was looked for: {message}"
        );
        // ...and is actionable: it lists what actually got published, rather
        // than failing silently with an empty/generic "not found".
        assert!(
            message.contains("kin-macos-aarch64.tar.gz"),
            "error should list the assets that were actually published: {message}"
        );
    }

    #[test]
    fn verify_sha256_accepts_a_matching_hash() {
        let bytes = b"hello release archive";
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let hash = hex::encode(hasher.finalize());

        assert!(verify_sha256(bytes, &hash).is_ok());
        // Case-insensitive, matching real sha256sum/shasum output conventions.
        assert!(verify_sha256(bytes, &hash.to_uppercase()).is_ok());
    }

    #[test]
    fn verify_sha256_refuses_install_on_mismatch() {
        let bytes = b"hello release archive";
        let wrong_hash = "0".repeat(64);

        let err = verify_sha256(bytes, &wrong_hash).expect_err("hash must not match");
        let message = format!("{err}");
        assert!(message.contains("MISMATCH"), "message: {message}");
        assert!(message.contains(&wrong_hash), "message: {message}");
    }

    #[test]
    fn extract_named_file_pulls_the_shim_out_of_the_archive() {
        let archive = make_tar_gz(&[
            ("kin-macos-aarch64/kin", b"binary-bytes"),
            (
                "kin-macos-aarch64/libkin_vfs_shim.dylib",
                b"\xCF\xFA\xED\xFEshim-body",
            ),
        ]);
        let shim = extract_named_file_from_tar_gz(&archive, "libkin_vfs_shim.dylib").unwrap();
        assert_eq!(shim, b"\xCF\xFA\xED\xFEshim-body");
    }

    #[test]
    fn extract_named_file_errors_when_absent() {
        let archive = make_tar_gz(&[("kin-macos-aarch64/kin", b"binary-bytes")]);
        assert!(extract_named_file_from_tar_gz(&archive, "libkin_vfs_shim.dylib").is_err());
    }

    #[test]
    fn shim_extraction_bounds_the_target_and_the_complete_archive_walk() {
        let archive = make_tar_gz(&[
            ("libkin_vfs_shim.dylib", b"shim"),
            ("later-component", b"01234567890123456789"),
        ]);
        let limits = |compressed_bytes, entry_bytes, expanded_bytes| ArchiveSizeLimits {
            compressed_bytes,
            entry_bytes,
            expanded_bytes,
        };

        let compressed = extract_named_file_from_tar_gz_with_limits(
            &archive,
            "libkin_vfs_shim.dylib",
            limits(archive.len() - 1, 64, 64),
        )
        .unwrap_err();
        assert!(format!("{compressed:#}").contains("compressed-size limit"));

        let target = extract_named_file_from_tar_gz_with_limits(
            &archive,
            "libkin_vfs_shim.dylib",
            limits(archive.len(), 3, 64),
        )
        .unwrap_err();
        assert!(format!("{target:#}").contains("per-entry expanded-size limit"));

        let full_walk = extract_named_file_from_tar_gz_with_limits(
            &archive,
            "libkin_vfs_shim.dylib",
            limits(archive.len(), 64, 10),
        )
        .unwrap_err();
        assert!(format!("{full_walk:#}").contains("aggregate expanded-size limit"));
    }

    #[cfg(unix)]
    #[test]
    fn stale_doctor_after_a_newer_install_fails_before_download_or_write() {
        use std::cell::Cell;
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let kin_home = temp.path().join("kin-home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let managed_cli = kin_home.join("bin/kin");
        fs::copy(std::env::current_exe().unwrap(), &managed_cli).unwrap();
        fs::set_permissions(&managed_cli, fs::Permissions::from_mode(0o755)).unwrap();
        let stale_executing = ExecutingProcessAuthority::capture_test_file(&managed_cli).unwrap();

        for component in LINUX_COMPONENTS {
            let destination = component_path(&kin_home, *component);
            let replacement = destination.with_extension("newer-doctor-test");
            fs::write(&replacement, format!("newer-{}", component.name)).unwrap();
            fs::set_permissions(
                &replacement,
                fs::Permissions::from_mode(if component.location == ComponentLocation::Bin {
                    0o755
                } else {
                    0o644
                }),
            )
            .unwrap();
            fs::rename(&replacement, &destination).unwrap();
        }
        let shim = kin_home.join("lib/libkin_vfs_shim.so");
        let newer_shim = fs::read(&shim).unwrap();
        let stale_doctor = UpdaterStartAuthority {
            bundle: snapshot_managed_bundle_generation(&kin_home, LINUX_COMPONENTS).unwrap(),
            executing: stale_executing,
        };
        let download_attempted = Cell::new(false);

        let error = validate_shim_repair_start_authority(&stale_doctor)
            .map(|()| {
                download_attempted.set(true);
            })
            .expect_err("an old doctor must not fetch or write into a newer generation");
        assert!(format!("{error:#}").contains("different or replaced Kin installation"));
        assert!(!download_attempted.get());
        assert_eq!(fs::read(&shim).unwrap(), newer_shim);
    }

    #[cfg(unix)]
    #[test]
    fn shim_repair_refuses_to_overwrite_a_newer_managed_bundle_generation() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let kin_home = temp.path().join("kin-home");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        drop(InstallRootLock::acquire_existing(&kin_home).unwrap());
        let generation = snapshot_managed_bundle_generation(&kin_home, LINUX_COMPONENTS).unwrap();
        let shim = kin_home.join("lib/libkin_vfs_shim.so");
        let replacement = kin_home.join("lib/newer-shim");
        fs::write(&replacement, b"newer-release-shim").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o644)).unwrap();
        fs::rename(&replacement, &shim).unwrap();
        let newer_identity = file_identity(&shim).unwrap();

        let error = install_preflighted_shim_if_generation_matches(
            &kin_home,
            "libkin_vfs_shim.so",
            b"stale-doctor-shim",
            LINUX_COMPONENTS,
            &generation,
        )
        .expect_err("a stale doctor must not overwrite a concurrently installed generation");

        assert!(format!("{error:#}").contains("bundle generation changed"));
        assert_eq!(fs::read(&shim).unwrap(), b"newer-release-shim");
        assert_eq!(file_identity(&shim).unwrap(), newer_identity);
    }

    #[test]
    fn write_atomically_installs_bytes_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let lock = InstallRootLock::acquire(dir.path()).unwrap();
        let dest = dir.path().join("lib").join("libkin_vfs_shim.dylib");
        write_managed_component_atomically(&lock, &dest, b"\xCF\xFA\xED\xFEbody").unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"\xCF\xFA\xED\xFEbody");
        let leftovers: Vec<_> = std::fs::read_dir(dest.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp download file was not cleaned up"
        );
    }

    #[test]
    fn version_comparison() {
        assert!(is_newer("0.2.0", "0.1.0").unwrap());
        assert!(is_newer("1.0.0", "0.9.9").unwrap());
        assert!(!is_newer("0.1.0", "0.1.0").unwrap());
        assert!(!is_newer("0.1.0", "0.2.0").unwrap());
        assert!(is_newer("0.2.22+build.1", "0.2.21").unwrap());
        assert!(is_newer("not-semver", "0.2.21").is_err());
    }

    #[test]
    fn version_comparison_understands_prereleases() {
        // A pre-release of a higher core beats a lower stable release.
        assert!(is_newer("0.2.7-alpha.1", "0.2.6").unwrap());
        // A newer alpha beats an older alpha of the same core.
        assert!(is_newer("0.2.7-alpha.2", "0.2.7-alpha.1").unwrap());
        // A stable release outranks its own pre-release.
        assert!(is_newer("0.2.7", "0.2.7-alpha.9").unwrap());
        // A pre-release never outranks its released version (no downgrade).
        assert!(!is_newer("0.2.7-alpha.1", "0.2.7").unwrap());
        // Equal pre-releases are not newer.
        assert!(!is_newer("0.2.7-alpha.1", "0.2.7-alpha.1").unwrap());
        // Alphanumeric identifiers rank above numeric; 'beta' > 'alpha' lexically.
        assert!(is_newer("0.2.7-beta", "0.2.7-alpha.1").unwrap());
        // Leading 'v' is tolerated on either side.
        assert!(is_newer("v0.2.7", "v0.2.6").unwrap());
    }

    #[test]
    fn effective_channel_precedence() {
        // An explicit flag wins over the stored default.
        assert_eq!(
            effective_channel(Some(Channel::Alpha), Channel::Stable),
            Channel::Alpha
        );
        assert_eq!(
            effective_channel(Some(Channel::Stable), Channel::Alpha),
            Channel::Stable
        );
        // No flag falls back to the stored default.
        assert_eq!(effective_channel(None, Channel::Alpha), Channel::Alpha);
        assert_eq!(effective_channel(None, Channel::Stable), Channel::Stable);
        // The out-of-the-box default is stable.
        assert_eq!(Channel::default(), Channel::Stable);
    }

    #[test]
    fn pinned_channel_drift_is_a_runtime_error() {
        ensure_pinned_channel_unchanged(Channel::Stable, Channel::Stable).unwrap();
        let error = ensure_pinned_channel_unchanged(Channel::Stable, Channel::Alpha)
            .expect_err("release builds must reject channel drift across remote preflight");
        let message = format!("{error:#}");
        assert!(message.contains("changed during pinned remote preflight"));
        assert!(message.contains("stable -> alpha"));
    }

    /// A machine with nothing running and every probe answering.
    fn idle_machine() -> MachineActivity {
        MachineActivity {
            managed_runtimes_active: false,
            external_sessions: false,
            work_in_flight: false,
            readable: true,
        }
    }

    #[test]
    fn the_default_policy_asks_before_swapping_bytes() {
        // The default decides what happens on every install that never sets a
        // policy, which is all of them. Kin's binaries sit under live agent
        // sessions and mapped VFS shims, so the default has to be the one that
        // does not move them without being asked.
        assert_eq!(UpdatePolicy::default(), UpdatePolicy::Prompt);
        assert_eq!(
            decide_auto_update(UpdatePolicy::default(), idle_machine()),
            AutoDecision::Prompt("update policy is prompt"),
            "an idle machine on the default policy must still ask"
        );
    }

    #[test]
    fn auto_installs_only_on_a_provably_idle_machine() {
        assert_eq!(
            decide_auto_update(UpdatePolicy::Auto, idle_machine()),
            AutoDecision::Proceed
        );

        for (activity, expected) in [
            (
                MachineActivity {
                    external_sessions: true,
                    ..idle_machine()
                },
                "an agent or user session is open",
            ),
            (
                MachineActivity {
                    managed_runtimes_active: true,
                    ..idle_machine()
                },
                "a managed Kin process is still running",
            ),
            (
                MachineActivity {
                    work_in_flight: true,
                    ..idle_machine()
                },
                "a store is part-way through indexing",
            ),
        ] {
            assert_eq!(
                decide_auto_update(UpdatePolicy::Auto, activity),
                AutoDecision::Prompt(expected),
                "a busy machine must fall back to asking"
            );
        }
    }

    #[test]
    fn an_unreadable_machine_is_never_treated_as_an_idle_one() {
        // The failure this exists to prevent: a probe that could not answer
        // being folded into "nothing is running" and an install landing
        // mid-session. Unknown and idle are different answers, and only one of
        // them may proceed.
        let unknown = MachineActivity {
            readable: false,
            ..idle_machine()
        };
        assert_eq!(
            decide_auto_update(UpdatePolicy::Auto, unknown),
            AutoDecision::Prompt("could not read whether this machine was busy")
        );
        // The control: the same struct with the probe answering does proceed,
        // so this test can distinguish the two rather than passing either way.
        assert_eq!(
            decide_auto_update(UpdatePolicy::Auto, idle_machine()),
            AutoDecision::Proceed
        );
    }

    #[test]
    fn manual_stays_quiet_and_prompt_speaks_up() {
        assert_eq!(
            decide_auto_update(UpdatePolicy::Manual, idle_machine()),
            AutoDecision::Silent("update policy is manual")
        );
        assert_eq!(
            decide_auto_update(UpdatePolicy::Prompt, idle_machine()),
            AutoDecision::Prompt("update policy is prompt")
        );
        // Every non-proceeding decision carries a reason a notification or log
        // can print. A refusal nobody can attribute is the unreadable alarm
        // this whole surface was built to stop shipping.
        assert!(AutoDecision::Proceed.reason().is_none());
        for policy in [UpdatePolicy::Manual, UpdatePolicy::Prompt] {
            assert!(
                decide_auto_update(policy, idle_machine()).reason().is_some(),
                "{policy:?} must say why it did not install"
            );
        }
        assert!(
            decide_auto_update(
                UpdatePolicy::Auto,
                MachineActivity {
                    readable: false,
                    ..idle_machine()
                }
            )
            .reason()
            .is_some()
        );
    }

    #[test]
    fn the_chain_runs_the_install_before_anything_that_depends_on_it() {
        assert_eq!(
            chain_plan(true, false, false),
            vec![
                ChainStep::Install,
                ChainStep::AcknowledgeRestart,
                ChainStep::RepairConfigs
            ],
            "an install writes the fence, so its acknowledgement belongs to the same plan"
        );
        assert_eq!(
            chain_plan(false, true, false),
            vec![ChainStep::AcknowledgeRestart],
            "a pending fence is its own chain; nothing needs downloading"
        );
        assert_eq!(
            chain_plan(false, false, true),
            vec![ChainStep::RepairConfigs],
            "drifted configs on a current machine must not trigger a download"
        );
        assert!(
            chain_plan(false, false, false).is_empty(),
            "a current machine has no chain to run"
        );
        assert_eq!(ChainStep::ORDER.len(), 3);
    }

    #[test]
    fn the_steps_after_the_install_run_as_the_installed_binary() {
        // The restart fence validates the acknowledging binary's own version
        // and build sha against the marker the install wrote, so the process
        // that performed the install can never satisfy it. This is an ordering
        // constraint, not a preference.
        assert!(!ChainStep::Install.needs_installed_binary());
        assert!(ChainStep::AcknowledgeRestart.needs_installed_binary());
        assert!(ChainStep::RepairConfigs.needs_installed_binary());
        assert_eq!(ChainStep::AcknowledgeRestart.command(), "kin update --ack-restart");
        assert_eq!(ChainStep::RepairConfigs.command(), "kin setup doctor --fix");
    }

    #[test]
    fn update_config_toml_roundtrip() {
        let text = toml::to_string_pretty(&UpdateConfig {
            channel: Channel::Alpha,
            policy: UpdatePolicy::Auto,
        })
        .unwrap();
        assert!(text.contains("channel = \"alpha\""));
        assert!(text.contains("policy = \"auto\""));

        let parsed: UpdateConfig = toml::from_str(&text).unwrap();
        assert_eq!(parsed.channel, Channel::Alpha);

        // A missing/empty config deserializes to the stable default.
        let empty: UpdateConfig = toml::from_str("").unwrap();
        assert_eq!(empty.channel, Channel::Stable);
        // Every install that predates the policy has a config carrying only a
        // channel, and each one must read as prompt rather than as auto.
        let channel_only: UpdateConfig = toml::from_str("channel = \"alpha\"").unwrap();
        assert_eq!(channel_only.policy, UpdatePolicy::Prompt);
    }

    #[test]
    fn select_alpha_picks_newest_prerelease() {
        let mk = |tag: &str, prerelease: bool| GithubRelease {
            tag_name: tag.to_string(),
            prerelease,
            assets: vec![],
        };

        let picked = select_alpha(vec![
            mk("v0.2.6", false), // stable, must be ignored
            mk("v0.2.7-alpha.1", true),
            mk("v0.2.7-alpha.3", true), // newest pre-release
            mk("v0.2.7-alpha.2", true),
        ])
        .unwrap()
        .expect("a pre-release should be selected");
        assert_eq!(picked.tag_name, "v0.2.7-alpha.3");

        // No pre-releases available → nothing to select.
        assert!(select_alpha(vec![mk("v0.2.6", false)]).unwrap().is_none());
    }

    #[test]
    fn parse_checksum_finds_entry() {
        let checksums = "\
            abc123def456  kin-darwin-arm64.tar.gz\n\
            789abc012def  kin-linux-amd64.tar.gz\n";
        assert_eq!(
            parse_checksum(checksums, "kin-darwin-arm64.tar.gz"),
            Some("abc123def456".to_string())
        );
        assert_eq!(
            parse_checksum(checksums, "kin-linux-amd64.tar.gz"),
            Some("789abc012def".to_string())
        );
        assert_eq!(parse_checksum(checksums, "kin-windows-amd64.zip"), None);
    }

    #[test]
    fn parse_checksum_handles_comments_and_blanks() {
        let checksums = "\
            # SHA-256 checksums for kin v0.2.0\n\
            \n\
            abc123  kin-darwin-arm64.tar.gz\n";
        assert_eq!(
            parse_checksum(checksums, "kin-darwin-arm64.tar.gz"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn parse_checksum_normalizes_case() {
        let checksums = "ABCDEF123456  kin-linux-amd64.tar.gz\n";
        assert_eq!(
            parse_checksum(checksums, "kin-linux-amd64.tar.gz"),
            Some("abcdef123456".to_string())
        );
    }
}
