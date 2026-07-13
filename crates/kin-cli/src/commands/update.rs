// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use fs2::FileExt;
use semver::Version;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_RELEASES_LATEST_URL: &str =
    "https://api.github.com/repos/firelock-ai/kin/releases/latest";
const GITHUB_RELEASES_LIST_URL: &str =
    "https://api.github.com/repos/firelock-ai/kin/releases?per_page=30";

/// Expected checksums-manifest asset name published with every release.
/// Releases do not publish a detached signature, so integrity verification
/// is checksum-only — see `verify_sha256`/`verify_archive_checksum` below.
const CHECKSUMS_ASSET: &str = "checksums-sha256.txt";
const TRANSACTION_PREFIX: &str = ".update-backup-";
const STAGING_PREFIX: &str = ".update-stage-";
const TRANSACTION_JOURNAL: &str = "journal.json";
const RESTART_ACK_REQUIRED_FILE: &str = "update-restart-ack-required.json";
const MCP_REPAIR_PENDING_FILE: &str = "update-mcp-repair-pending.json";

#[derive(serde::Deserialize)]
struct GithubRelease {
    tag_name: String,
    /// GitHub marks any tag containing `-` (e.g. `-alpha`/`-beta`/`-rc`) as a
    /// pre-release. Used to select builds for the alpha channel.
    #[serde(default)]
    prerelease: bool,
    assets: Vec<GithubAsset>,
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

/// Persisted update preferences, stored at `~/.kin/update.toml`.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct UpdateConfig {
    #[serde(default)]
    channel: Channel,
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

    fn save_to(&self, kin_home: &Path) -> Result<()> {
        let contents = toml::to_string_pretty(self).context("failed to serialize update config")?;
        #[cfg(unix)]
        {
            let install = InstallLayout::open(kin_home)?;
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
            let path = kin_home.join("update.toml");
            write_file_atomically(&path, contents.as_bytes(), 0o600)
                .with_context(|| format!("failed to write {}", path.display()))?;
            Ok(())
        }
    }
}

/// Resolve the effective channel: an explicit `--channel` flag wins and, for a
/// mutating update, is saved as the new default. Check-only calls pass
/// `persist = false` so their filesystem contract remains read-only.
fn resolve_channel(kin_home: &Path, flag: Option<Channel>, quiet: bool, persist: bool) -> Channel {
    let stored = UpdateConfig::load_from(kin_home).channel;
    if let Some(requested) = flag {
        if persist && requested != stored {
            // Persisting is best-effort: a write failure must not block the update.
            match (UpdateConfig { channel: requested }).save_to(kin_home) {
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

#[derive(Debug, serde::Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
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
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct RestartPending {
    schema_version: u32,
    installed_version: String,
    kin_commit: String,
    dependency_provenance: String,
    kin_vfs_commit: String,
    recorded_at: String,
    reason: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct McpRepairPending {
    schema_version: u32,
    installed_version: String,
    recorded_at: String,
}

#[derive(Debug, serde::Serialize)]
struct UpdateCheck<'a> {
    current_version: &'a str,
    latest_version: &'a str,
    channel: &'a str,
    update_available: bool,
    platform_asset: &'a str,
    restart_ack_required: bool,
    mcp_repair_pending: bool,
}

pub async fn run(
    skip_verify: bool,
    channel_flag: Option<Channel>,
    check_only: bool,
    json: bool,
    ack_restart: bool,
) -> Result<()> {
    ensure_mutating_update_supported(std::env::consts::OS, check_only)?;
    if ack_restart {
        return acknowledge_runtime_restart();
    }

    // Check-only must remain byte-for-byte read-only. It inspects a stale
    // transaction and fails with a recovery instruction, while a mutating
    // update takes the install lock and recovers before doing any network I/O.
    let requested_home = crate::commands::setup::kin_dir()?;
    let inspected_home = validate_existing_install_root(&requested_home)?;
    let spec = platform_bundle_spec(std::env::consts::OS)?;
    let stale = transaction_dirs(&inspected_home)?;
    if check_only && !stale.is_empty() {
        anyhow::bail!(
            "an interrupted Kin update requires recovery at {}. Run `kin update` without \
             --check-only; this check did not modify any file",
            stale[0].display()
        );
    }

    if stale.is_empty() {
        verify_target_binding(&inspected_home)?;
    }

    let mut held_lock = None;
    let kin_home = if check_only {
        inspected_home
    } else {
        let lock = InstallRootLock::acquire_existing(&requested_home)?;
        recover_stale_transactions(lock.root(), spec)?;
        cleanup_stale_staging_dirs(lock.root())?;
        verify_target_binding(lock.root())?;
        attempt_pending_mcp_repair(lock.root());
        let root = lock.root().to_path_buf();
        held_lock = Some(lock);
        root
    };
    let _held_lock = held_lock;
    let channel = resolve_channel(&kin_home, channel_flag, json, !check_only);

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

    let client = reqwest::Client::builder().user_agent("kin-cli").build()?;

    let release = resolve_release(&client, channel).await?;

    let latest_version = parse_release_version(&release.tag_name)?;
    let latest = latest_version.to_string();
    let archive_name = current_platform_asset_name()?;
    let asset = find_release_asset(&release, &archive_name)?;
    let current_version = parse_release_version(CURRENT_VERSION)?;
    let update_available = latest_version > current_version;
    let restart_ack_required = restart_pending_path(&kin_home).exists();
    let mcp_repair_pending = mcp_repair_pending_path(&kin_home).exists();

    if check_only {
        let check = UpdateCheck {
            current_version: CURRENT_VERSION,
            latest_version: &latest,
            channel: channel_name(channel),
            update_available,
            platform_asset: &asset.name,
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

    println!("Downloading {}...", asset.name);

    let archive_bytes = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("failed to download release archive")?
        .error_for_status()
        .context("download returned an error")?
        .bytes()
        .await
        .context("failed to read archive bytes")?;

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

    let staging = StagingDir::create(&kin_home)?;
    stage_archive(&archive_bytes, &asset.name, staging.path(), spec)?;
    let provenance = fetch_artifact_provenance(&client, &release, asset).await?;
    validate_artifact_provenance(
        &provenance,
        &release,
        asset,
        &archive_bytes,
        staging.path(),
        spec,
        !skip_verify,
    )?;
    validate_staged_build_identity(staging.path(), spec, &latest, &provenance)?;
    let pending_record = restart_pending_record(&latest, &provenance);
    let outcome = install_staged_bundle(&kin_home, staging.path(), spec, &latest, &pending_record)?;
    if let Some(backup) = outcome.retained_backup {
        eprintln!(
            "WARNING: update succeeded, but the old-version backup could not be removed: {}",
            backup.display()
        );
    }

    attempt_pending_mcp_repair(&kin_home);

    let pending = restart_pending_path(&kin_home);
    println!("Installed v{latest} on disk.");
    println!(
        "Runtime restart acknowledgement required: {}. Restart daemon, MCP, and VFS sessions, \
         then run `kin update --ack-restart`. The marker is an explicit acknowledgement \
         obligation, not an automated convergence claim.",
        pending.display()
    );
    Ok(())
}

fn attempt_pending_mcp_repair(kin_home: &Path) {
    #[cfg(unix)]
    let anchored = match InstallLayout::open(kin_home) {
        Ok(layout) => Some(layout),
        Err(error) => {
            eprintln!("WARNING: could not anchor MCP repair state: {error:#}");
            return;
        }
    };
    #[cfg(unix)]
    let marker_identity = {
        let install = anchored.as_ref().expect("anchored layout was constructed");
        match install.root.stat_entry(MCP_REPAIR_PENDING_FILE) {
            Ok(None) => return,
            Ok(Some(_)) => {}
            Err(error) => {
                eprintln!("WARNING: could not inspect MCP repair pending state: {error:#}");
                return;
            }
        }
        let marker = match install
            .root
            .read_regular(MCP_REPAIR_PENDING_FILE, "MCP repair pending marker")
        {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("WARNING: invalid MCP repair pending state retained: {error:#}");
                return;
            }
        };
        let marker_identity = bytes_identity(&marker);
        match install
            .root
            .identity(MCP_REPAIR_PENDING_FILE, "MCP repair pending marker")
        {
            Ok(Some(current)) if current == marker_identity => {}
            Ok(_) => {
                eprintln!("WARNING: MCP repair pending state changed while it was read; retained");
                return;
            }
            Err(error) => {
                eprintln!("WARNING: MCP repair pending state could not be revalidated: {error:#}");
                return;
            }
        }
        let record: McpRepairPending = match serde_json::from_slice(&marker) {
            Ok(record) => record,
            Err(error) => {
                eprintln!("WARNING: malformed MCP repair pending state retained: {error}");
                return;
            }
        };
        if record.schema_version != 1 || parse_release_version(&record.installed_version).is_err() {
            eprintln!("WARNING: unsupported MCP repair pending state retained");
            return;
        }
        marker_identity
    };
    #[cfg(not(unix))]
    if !mcp_repair_pending_path(kin_home).exists() {
        return;
    }
    let outcome = crate::commands::setup::remerge_existing_mcp_configs_detailed();
    for path in &outcome.repaired {
        println!("Refreshed Kin MCP launcher: {}", path.display());
    }
    if outcome.errors.is_empty() {
        #[cfg(unix)]
        let clear = (|| -> Result<()> {
            let install = anchored.as_ref().expect("anchored layout was constructed");
            install.ensure_bound()?;
            if install
                .root
                .identity(MCP_REPAIR_PENDING_FILE, "MCP repair pending marker")?
                .as_ref()
                != Some(&marker_identity)
            {
                anyhow::bail!("MCP repair pending state changed before marker clear");
            }
            install.root.unlink_file(MCP_REPAIR_PENDING_FILE)
        })();
        #[cfg(not(unix))]
        let clear = durable_remove_file(&mcp_repair_pending_path(kin_home));
        if let Err(error) = clear {
            eprintln!(
                "WARNING: MCP launchers were repaired, but the durable pending marker could not \
                 be cleared: {error:#}"
            );
        }
    } else {
        for error in &outcome.errors {
            eprintln!("WARNING: Kin MCP launcher repair remains pending: {error}");
        }
        eprintln!(
            "MCP repair state retained at {}",
            mcp_repair_pending_path(kin_home).display()
        );
    }
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
/// The lock file is deliberately persistent. Deleting a flock file while it is
/// held creates a second inode that another process can lock concurrently.
pub(crate) struct InstallRootLock {
    file: File,
    root: PathBuf,
}

impl InstallRootLock {
    pub(crate) fn acquire(kin_home: &Path) -> Result<Self> {
        Self::acquire_inner(kin_home, true)
    }

    fn acquire_existing(kin_home: &Path) -> Result<Self> {
        Self::acquire_inner(kin_home, false)
    }

    fn acquire_inner(kin_home: &Path, create: bool) -> Result<Self> {
        let root = validate_install_root(kin_home, create)?;
        ensure_managed_dirs(&root, true)?;
        let path = root.join("update.lock");
        #[cfg(unix)]
        let root_anchor = AnchoredDir::open_ambient(&root)?;
        #[cfg(unix)]
        let (mut file, created) = open_lock_file_at(&root_anchor)?;
        #[cfg(not(unix))]
        let (mut file, created) = open_lock_file(&path)?;

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
                return Err(err)
                    .with_context(|| format!("failed to acquire update lock {}", path.display()));
            }
        }

        if created {
            file.write_all(b"kin-update-lock-v1\n")
                .with_context(|| format!("failed to initialize update lock {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("failed to sync update lock {}", path.display()))?;
            #[cfg(unix)]
            root_anchor.sync()?;
            #[cfg(not(unix))]
            sync_dir(&root)?;
        }
        Ok(Self { file, root })
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for InstallRootLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
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

#[cfg(not(unix))]
fn open_lock_file(path: &Path) -> Result<(File, bool)> {
    let mut create = OpenOptions::new();
    create.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }

    match create.open(path) {
        Ok(file) => return Ok((file, true)),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to create update lock {}", path.display()));
        }
    }

    let before = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect update lock {}", path.display()))?;
    if before.file_type().is_symlink() || !before.is_file() {
        anyhow::bail!(
            "refusing non-regular or symlink update lock {}",
            path.display()
        );
    }

    let mut existing = OpenOptions::new();
    existing.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        existing.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = existing
        .open(path)
        .with_context(|| format!("failed to open update lock {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("failed to inspect opened update lock {}", path.display()))?;
    if !opened.is_file() {
        anyhow::bail!(
            "opened update lock is not a regular file: {}",
            path.display()
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            anyhow::bail!(
                "update lock changed while it was being opened: {}",
                path.display()
            );
        }
    }
    Ok((file, false))
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
        Ok(fd) => return Ok((File::from(fd), true)),
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
    Ok((file, false))
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
        self.sync()?;
        self.open_child(name)
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
        Ok(Some(FileIdentity {
            sha256: hex::encode(hasher.finalize()),
            size_bytes: stat.st_size as u64,
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
        C: FnOnce() -> Result<()>,
    {
        self.atomic_write_with_hooks(name, bytes, mode, || Ok(()), check_binding)
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
        C: FnOnce() -> Result<()>,
    {
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
            let _ = rustix::fs::unlinkat(&self.file, temp.as_str(), rustix::fs::AtFlags::empty());
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
}

#[cfg(unix)]
impl InstallLayout {
    fn open(root: &Path) -> Result<Self> {
        let parent_path = root.parent().context("Kin install root has no parent")?;
        let root_name = root
            .file_name()
            .and_then(|name| name.to_str())
            .context("Kin install root name is not UTF-8")?
            .to_string();
        let parent = AnchoredDir::open_ambient(parent_path)?;
        let root_dir = parent.open_child(&root_name)?;
        let bin = root_dir.open_child("bin")?;
        let lib = root_dir.open_child("lib")?;
        let layout = Self {
            parent,
            root_name,
            root: root_dir,
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
        install.ensure_bound()?;
        let name = format!("{TRANSACTION_PREFIX}{}", uuid::Uuid::new_v4());
        let root = install.root.create_child(&name, 0o700)?;
        let old = root.create_child("old", 0o700)?;
        let old_bin = old.create_child("bin", 0o700)?;
        let old_lib = old.create_child("lib", 0o700)?;
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
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                != rustix::fs::FileType::RegularFile
            {
                anyhow::bail!(
                    "refusing unexpected staging entry type: {}/{}",
                    directory.display.display(),
                    entry
                );
            }
            directory.unlink_file(&entry)?;
        }
        directory.ensure_empty()?;
        root.remove_child_dir(directory_name)?;
    }
    root.ensure_empty()?;
    install.ensure_bound()?;
    install.root.ensure_child_binding(name, root)?;
    install.root.remove_child_dir(name)
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

fn verify_target_binding(kin_home: &Path) -> Result<()> {
    let executable_name = if cfg!(windows) { "kin.exe" } else { "kin" };
    let target = kin_home.join("bin").join(executable_name);
    let metadata = fs::symlink_metadata(&target)
        .with_context(|| format!("managed Kin executable is missing: {}", target.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "managed Kin executable must be a regular non-symlink file: {}",
            target.display()
        );
    }

    let running = std::env::current_exe().context("failed to locate the running Kin executable")?;
    let running = running.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize running executable {}",
            running.display()
        )
    })?;
    let target = target.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize managed executable {}",
            target.display()
        )
    })?;
    let running_sha = sha256_file(&running)?;
    let target_sha = sha256_file(&target)?;
    if running == target || running_sha == target_sha {
        return Ok(());
    }

    anyhow::bail!(
        "refusing to update a different Kin installation. Running executable: {}. Managed target: \
         {} (SHA-256 {target_sha}). Invoke the managed target directly or use the package manager that \
         owns the running executable",
        running.display(),
        target.display()
    )
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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct FileIdentity {
    sha256: String,
    size_bytes: u64,
}

#[cfg(unix)]
fn bytes_identity(bytes: &[u8]) -> FileIdentity {
    FileIdentity {
        sha256: hex::encode(Sha256::digest(bytes)),
        size_bytes: bytes.len() as u64,
    }
}

#[cfg(not(unix))]
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

#[cfg(not(unix))]
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

struct StagingDir {
    path: PathBuf,
    #[cfg(unix)]
    install: InstallLayout,
    #[cfg(unix)]
    root: AnchoredDir,
    #[cfg(unix)]
    name: String,
}

impl StagingDir {
    fn create(kin_home: &Path) -> Result<Self> {
        let name = format!(".update-stage-{}", uuid::Uuid::new_v4());
        let path = kin_home.join(&name);
        #[cfg(unix)]
        {
            let install = InstallLayout::open(kin_home)?;
            let root = install.root.create_child(&name, 0o700)?;
            root.create_child("bin", 0o700)?;
            root.create_child("lib", 0o700)?;
            return Ok(Self {
                path,
                install,
                root,
                name,
            });
        }
        #[cfg(not(unix))]
        {
            fs::create_dir(&path).with_context(|| {
                format!("failed to create update staging dir {}", path.display())
            })?;
            sync_dir(kin_home)?;
            Ok(Self { path })
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let cleanup = cleanup_staging_tree_at(&self.install, &self.name, &self.root);
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
    if archive_name.ends_with(".tar.gz") || archive_name.ends_with(".tgz") {
        stage_tar_gz(bytes, stage_root, spec, &mut seen)?;
    } else if archive_name.ends_with(".zip") {
        stage_zip(bytes, stage_root, spec, &mut seen)?;
    } else {
        anyhow::bail!("unknown archive format: {archive_name}");
    }
    validate_staged_bundle(stage_root, spec)
}

fn stage_tar_gz(
    bytes: &[u8],
    stage_root: &Path,
    spec: &[ComponentSpec],
    seen: &mut HashSet<&'static str>,
) -> Result<()> {
    use std::io::Read;

    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries().context("failed to read tar entries")? {
        let mut entry = entry.context("corrupt tar entry")?;
        let path = entry.path().context("invalid entry path")?.into_owned();
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
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            if entry.header().entry_type().is_dir() {
                continue;
            }
            anyhow::bail!("release archive contains a non-UTF-8 file name");
        };
        if !entry.header().entry_type().is_file() {
            if entry.header().entry_type().is_dir() {
                continue;
            }
            anyhow::bail!(
                "release archive contains non-regular entry '{}'",
                path.display()
            );
        }
        let Some(component) = spec.iter().copied().find(|item| item.name == name) else {
            anyhow::bail!(
                "release archive contains unexpected file '{}'",
                path.display()
            );
        };
        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .with_context(|| format!("failed to read '{}' from archive", component.name))?;
        write_staged_component(stage_root, component, &contents, seen)?;
    }
    Ok(())
}

fn stage_zip(
    bytes: &[u8],
    stage_root: &Path,
    spec: &[ComponentSpec],
    seen: &mut HashSet<&'static str>,
) -> Result<()> {
    use std::io::Read;

    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("failed to open zip archive")?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).context("corrupt zip entry")?;
        if entry.is_dir() {
            continue;
        }
        let Some(file_name) = entry
            .enclosed_name()
            .and_then(|path| path.file_name().map(|name| name.to_owned()))
        else {
            anyhow::bail!("release zip contains an unsafe or invalid file path");
        };
        let Some(name) = file_name.to_str() else {
            anyhow::bail!("release zip contains a non-UTF-8 file name");
        };
        let Some(component) = spec.iter().copied().find(|item| item.name == name) else {
            anyhow::bail!("release archive contains unexpected file '{name}'");
        };
        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .with_context(|| format!("failed to read '{}' from archive", component.name))?;
        write_staged_component(stage_root, component, &contents, seen)?;
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

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct TransactionJournal {
    schema_version: u32,
    target_version: String,
    phase: TransactionPhase,
    components: Vec<JournalComponent>,
    restart_pending: RestartPending,
    mcp_repair_pending: McpRepairPending,
}

fn install_staged_bundle(
    kin_home: &Path,
    stage_root: &Path,
    spec: &[ComponentSpec],
    target_version: &str,
    restart_pending: &RestartPending,
) -> Result<InstallOutcome> {
    install_staged_bundle_with_hook(
        kin_home,
        stage_root,
        spec,
        target_version,
        restart_pending,
        |_, _| Ok(()),
    )
}

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
    #[cfg(unix)]
    {
        return install_staged_bundle_unix(
            kin_home,
            stage_root,
            spec,
            target_version,
            restart_pending,
            before_install,
        );
    }

    #[cfg(not(unix))]
    {
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
            let install_new = match fs::symlink_metadata(&staged) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        anyhow::bail!(
                            "staged component is not a regular file: {}",
                            staged.display()
                        );
                    }
                    true
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to inspect staged component {}", staged.display())
                    });
                }
            };
            let staged_identity = if install_new {
                Some(file_identity(&staged)?)
            } else {
                None
            };
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

        let transaction_root = create_transaction_root(kin_home)?;
        let backup_root = transaction_root.join("old");
        let mut journal = TransactionJournal {
            schema_version: 2,
            target_version: target_version.to_string(),
            phase: TransactionPhase::Prepared,
            components,
            restart_pending: restart_pending.clone(),
            mcp_repair_pending: mcp_repair_pending_record(target_version),
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
            if !record.install_new {
                continue;
            }
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
            if let Err(err) = durable_rename(&staged, &dest) {
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

        // This durable transition is the transaction's commit point. Recovery
        // rolls back every earlier phase and finishes cleanup for this phase.
        journal.phase = TransactionPhase::Committed;
        if let Err(err) = persist_journal(&transaction_root, &journal) {
            return rollback_after_failure(err, &mut journal, &transaction_root, kin_home, spec);
        }
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
    transaction
        .root
        .atomic_write_checked(TRANSACTION_JOURNAL, &bytes, 0o600, || {
            transaction.ensure_bound(install)
        })
        .context("failed to persist anchored update journal")
}

#[cfg(unix)]
fn persist_restart_record_at(install: &InstallLayout, record: &RestartPending) -> Result<()> {
    install.ensure_bound()?;
    let bytes = serde_json::to_vec_pretty(record).context("failed to serialize restart state")?;
    install
        .root
        .atomic_write_checked(RESTART_ACK_REQUIRED_FILE, &bytes, 0o600, || {
            install.ensure_bound()
        })
        .context("failed to persist anchored restart acknowledgement state")
}

#[cfg(unix)]
fn persist_mcp_repair_record_at(install: &InstallLayout, record: &McpRepairPending) -> Result<()> {
    install.ensure_bound()?;
    let bytes =
        serde_json::to_vec_pretty(record).context("failed to serialize MCP repair state")?;
    install
        .root
        .atomic_write_checked(MCP_REPAIR_PENDING_FILE, &bytes, 0o600, || {
            install.ensure_bound()
        })
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
            .map(|component| component.name),
    )?;
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
    install_staged_bundle_unix_with_hooks(
        kin_home,
        stage_root,
        spec,
        target_version,
        restart_pending,
        |_, _| Ok(()),
        before_install,
    )
}

#[cfg(unix)]
fn install_staged_bundle_unix_with_hooks<B, F>(
    kin_home: &Path,
    stage_root: &Path,
    spec: &[ComponentSpec],
    target_version: &str,
    restart_pending: &RestartPending,
    mut before_backup: B,
    mut before_install: F,
) -> Result<InstallOutcome>
where
    B: FnMut(usize, &Path) -> Result<()>,
    F: FnMut(usize, &Path) -> Result<()>,
{
    validate_staged_bundle(stage_root, spec)?;
    ensure_managed_dirs(kin_home, true)?;
    let install = InstallLayout::open(kin_home)?;
    let staging = StagingLayout::open(stage_root)?;
    install.ensure_bound()?;
    staging.ensure_bound()?;

    let mut components = Vec::with_capacity(spec.len());
    for component in spec {
        let original_identity = install
            .component_dir(*component)
            .identity(component.name, "live update destination")?;
        let staged_identity = staging
            .component_dir(*component)
            .identity(component.name, "staged component")?;
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

    let transaction = TransactionLayout::create(&install)?;
    let transaction_root = kin_home.join(&transaction.name);
    let mut journal = TransactionJournal {
        schema_version: 2,
        target_version: target_version.to_string(),
        phase: TransactionPhase::Prepared,
        components,
        restart_pending: restart_pending.clone(),
        mcp_repair_pending: mcp_repair_pending_record(target_version),
    };
    if let Err(error) = persist_journal_at(&install, &transaction, &journal) {
        let _ = cleanup_transaction_at(&install, &transaction, &journal, spec);
        return Err(error);
    }
    journal.phase = TransactionPhase::BackingUp;
    persist_journal_at(&install, &transaction, &journal)?;

    for (index, component) in spec.iter().enumerate() {
        let record = journal_component(&journal, component.name)?;
        let Some(expected) = &record.original_identity else {
            continue;
        };
        let destination_path = component_path(kin_home, *component);
        if let Err(error) = before_backup(index, &destination_path) {
            return rollback_after_failure_at(
                error,
                &mut journal,
                &install,
                &transaction,
                &transaction_root,
                spec,
            );
        }
        install.ensure_bound()?;
        staging.ensure_bound()?;
        transaction.ensure_bound(&install)?;
        let live_dir = install.component_dir(*component);
        let backup_dir = transaction.component_dir(*component);
        if live_dir
            .identity(component.name, "live component before backup")?
            .as_ref()
            != Some(expected)
        {
            return rollback_after_failure_at(
                anyhow::anyhow!(
                    "live component '{}' changed after its journal identity was recorded",
                    component.name
                ),
                &mut journal,
                &install,
                &transaction,
                &transaction_root,
                spec,
            );
        }
        if backup_dir
            .identity(component.name, "preexisting transaction backup")?
            .is_some()
        {
            return rollback_after_failure_at(
                anyhow::anyhow!("transaction backup '{}' already exists", component.name),
                &mut journal,
                &install,
                &transaction,
                &transaction_root,
                spec,
            );
        }
        live_dir.rename_to(component.name, backup_dir, component.name)?;
        transaction.ensure_bound(&install)?;
        if backup_dir
            .identity(component.name, "new transaction backup")?
            .as_ref()
            != Some(expected)
        {
            return rollback_after_failure_at(
                anyhow::anyhow!(
                    "transaction backup '{}' does not match the recorded original identity",
                    component.name
                ),
                &mut journal,
                &install,
                &transaction,
                &transaction_root,
                spec,
            );
        }
        maybe_crash_at(&format!("after-backup-{index}"));
    }

    journal.phase = TransactionPhase::Installing;
    persist_journal_at(&install, &transaction, &journal)?;
    let mut install_index = 0;
    for component in spec {
        let record = journal_component(&journal, component.name)?;
        let Some(expected) = &record.staged_identity else {
            continue;
        };
        let destination_path = component_path(kin_home, *component);
        if let Err(error) = before_install(install_index, &destination_path) {
            return rollback_after_failure_at(
                error,
                &mut journal,
                &install,
                &transaction,
                &transaction_root,
                spec,
            );
        }
        if let Err(error) = install.ensure_bound() {
            return rollback_after_failure_at(
                error,
                &mut journal,
                &install,
                &transaction,
                &transaction_root,
                spec,
            );
        }
        staging.ensure_bound()?;
        transaction.ensure_bound(&install)?;
        let stage_dir = staging.component_dir(*component);
        let live_dir = install.component_dir(*component);
        if stage_dir
            .identity(component.name, "staged component before install")?
            .as_ref()
            != Some(expected)
        {
            return rollback_after_failure_at(
                anyhow::anyhow!(
                    "staged component '{}' changed after its journal identity was recorded",
                    component.name
                ),
                &mut journal,
                &install,
                &transaction,
                &transaction_root,
                spec,
            );
        }
        if live_dir
            .identity(component.name, "live destination before install")?
            .is_some()
        {
            return rollback_after_failure_at(
                anyhow::anyhow!(
                    "live destination '{}' unexpectedly exists before install",
                    component.name
                ),
                &mut journal,
                &install,
                &transaction,
                &transaction_root,
                spec,
            );
        }
        stage_dir.rename_to(component.name, live_dir, component.name)?;
        install.ensure_bound()?;
        if live_dir
            .identity(component.name, "installed component")?
            .as_ref()
            != Some(expected)
        {
            return rollback_after_failure_at(
                anyhow::anyhow!(
                    "installed component '{}' does not match its staged identity",
                    component.name
                ),
                &mut journal,
                &install,
                &transaction,
                &transaction_root,
                spec,
            );
        }
        maybe_crash_at(&format!("after-install-{install_index}"));
        install_index += 1;
    }

    if let Err(error) = validate_installed_bundle_at(&install, &journal, spec) {
        return rollback_after_failure_at(
            error,
            &mut journal,
            &install,
            &transaction,
            &transaction_root,
            spec,
        );
    }
    validate_backup_tree_at(&install, &transaction, &journal, spec)?;
    install.ensure_bound()?;
    staging.ensure_bound()?;
    transaction.ensure_bound(&install)?;

    journal.phase = TransactionPhase::Committed;
    if let Err(error) = persist_journal_at(&install, &transaction, &journal) {
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
    maybe_crash_at("after-commit");

    persist_restart_record_at(&install, &journal.restart_pending).with_context(|| {
        format!(
            "update committed on disk, but restart acknowledgement state could not be persisted; durable recovery remains at {}",
            transaction_root.display()
        )
    })?;
    maybe_crash_at("after-restart-marker");
    persist_mcp_repair_record_at(&install, &journal.mcp_repair_pending).with_context(|| {
        format!(
            "update committed on disk, but MCP repair state could not be persisted; durable recovery remains at {}",
            transaction_root.display()
        )
    })?;
    maybe_crash_at("after-mcp-marker");

    let retained_backup = match cleanup_transaction_at(&install, &transaction, &journal, spec) {
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
                if remove_installed {
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
                backup_dir.rename_to(component.name, live_dir, component.name)?;
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
    journal.phase = TransactionPhase::RolledBack;
    persist_journal_at(install, transaction, journal)?;
    cleanup_transaction_at(install, transaction, journal, spec)
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
            backup_dir.unlink_file(component.name)?;
        }
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
    transaction.old.remove_child_dir("bin")?;
    transaction
        .old
        .ensure_child_binding("lib", &transaction.old_lib)?;
    transaction.old.remove_child_dir("lib")?;
    transaction.old.ensure_empty()?;
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
    let transaction_root = kin_home.join(format!("{TRANSACTION_PREFIX}{}", uuid::Uuid::new_v4()));
    fs::create_dir(&transaction_root).with_context(|| {
        format!(
            "failed to create update transaction directory {}",
            transaction_root.display()
        )
    })?;
    sync_dir(kin_home)?;
    let old = transaction_root.join("old");
    fs::create_dir(&old)?;
    sync_dir(&transaction_root)?;
    for name in ["bin", "lib"] {
        fs::create_dir(old.join(name))?;
        sync_dir(&old)?;
    }
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
    if journal.schema_version != 2 {
        anyhow::bail!(
            "unsupported update journal schema {}",
            journal.schema_version
        );
    }
    if journal.components.len() != spec.len() {
        anyhow::bail!("update journal component inventory does not match this platform");
    }
    if journal.restart_pending.schema_version != 1
        || journal.mcp_repair_pending.schema_version != 1
        || parse_release_version(&journal.target_version)?
            != parse_release_version(&journal.restart_pending.installed_version)?
        || parse_release_version(&journal.target_version)?
            != parse_release_version(&journal.mcp_repair_pending.installed_version)?
    {
        anyhow::bail!("update journal restart identity does not match its target version");
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

fn recover_stale_transactions(kin_home: &Path, spec: &[ComponentSpec]) -> Result<()> {
    #[cfg(unix)]
    {
        return recover_stale_transactions_unix(kin_home, spec);
    }

    #[cfg(not(unix))]
    {
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
fn recover_stale_transactions_unix(kin_home: &Path, spec: &[ComponentSpec]) -> Result<()> {
    let install = InstallLayout::open(kin_home)?;
    for transaction_root in transaction_dirs(kin_home)? {
        install.ensure_bound()?;
        let name = transaction_root
            .file_name()
            .and_then(|name| name.to_str())
            .context("transaction root name is not UTF-8")?;
        let root = install.root.open_child(name)?;
        if root.stat_entry(TRANSACTION_JOURNAL)?.is_none() {
            cleanup_journalless_transaction_at(&install, name, &root)?;
            continue;
        }

        // Opening the full hierarchy is intentionally deferred until a journal
        // is known to exist. A crash after journal removal may leave only a
        // prefix of the now-empty structural directories, which is safe to
        // finish via cleanup_journalless_transaction_at above.
        let transaction = TransactionLayout::open(&install, &transaction_root)?;
        let mut journal = read_journal_at(&transaction)?;
        validate_journal(&journal, spec)?;
        if journal.phase == TransactionPhase::Committed {
            validate_backup_tree_at(&install, &transaction, &journal, spec).with_context(|| {
                format!(
                    "committed interrupted update at {} has an invalid backup tree",
                    transaction_root.display()
                )
            })?;
            validate_installed_bundle_at(&install, &journal, spec).with_context(|| {
                format!(
                    "committed interrupted update at {} has an invalid live bundle",
                    transaction_root.display()
                )
            })?;
            persist_restart_record_at(&install, &journal.restart_pending)?;
            persist_mcp_repair_record_at(&install, &journal.mcp_repair_pending)?;
            cleanup_transaction_at(&install, &transaction, &journal, spec)?;
        } else {
            rollback_transaction_at(&mut journal, &install, &transaction, spec).with_context(
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
            old.ensure_child_binding(leaf_name, &leaf)?;
            old.remove_child_dir(leaf_name)?;
        }
        old.ensure_empty()?;
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

fn cleanup_stale_staging_dirs(kin_home: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let install = InstallLayout::open(kin_home)?;
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
            cleanup_staging_tree_at(&install, &name, &root)?;
        }
        return Ok(());
    }

    #[cfg(not(unix))]
    {
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
            let release: GithubRelease = client
                .get(GITHUB_RELEASES_LATEST_URL)
                .send()
                .await
                .context("failed to reach GitHub releases API")?
                .error_for_status()
                .context("GitHub API returned an error")?
                .json()
                .await
                .context("failed to parse release JSON")?;
            Ok(release)
        }
        Channel::Alpha => {
            let releases: Vec<GithubRelease> = client
                .get(GITHUB_RELEASES_LIST_URL)
                .send()
                .await
                .context("failed to reach GitHub releases API")?
                .error_for_status()
                .context("GitHub API returned an error")?
                .json()
                .await
                .context("failed to parse releases JSON")?;
            select_alpha(releases)?.context(
                "no pre-release build is available on the alpha channel yet. \
                 See https://github.com/firelock-ai/kin/releases",
            )
        }
    }
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
    let checksums_asset = release
        .assets
        .iter()
        .find(|a| a.name == CHECKSUMS_ASSET)
        .with_context(|| {
            format!("release is missing '{CHECKSUMS_ASSET}' — cannot verify the download")
        })?;

    let checksums_bytes = client
        .get(&checksums_asset.browser_download_url)
        .send()
        .await
        .context("failed to download checksums file")?
        .error_for_status()?
        .bytes()
        .await
        .context("failed to read checksums bytes")?;

    let checksums_text =
        std::str::from_utf8(&checksums_bytes).context("checksums file is not valid UTF-8")?;
    let expected = parse_checksum(checksums_text, archive_name)
        .with_context(|| format!("'{archive_name}' not found in the checksums file"))?;

    verify_sha256(archive_bytes, &expected)
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
    let bytes = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("failed to download artifact provenance")?
        .error_for_status()
        .context("artifact provenance download returned an error")?
        .bytes()
        .await
        .context("failed to read artifact provenance")?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("'{provenance_name}' is not valid provenance JSON"))
}

fn validate_artifact_provenance(
    provenance: &ArtifactProvenance,
    release: &GithubRelease,
    archive: &GithubAsset,
    archive_bytes: &[u8],
    stage_root: &Path,
    spec: &[ComponentSpec],
    verify_hashes: bool,
) -> Result<()> {
    if provenance.schema_version != 1 {
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
    if provenance.archive.size_bytes != archive_bytes.len() as u64 {
        anyhow::bail!("artifact provenance archive size does not match downloaded bytes");
    }
    validate_hex(&provenance.archive.sha256, 64, "archive SHA-256")?;
    if verify_hashes {
        verify_sha256(archive_bytes, &provenance.archive.sha256)
            .context("artifact provenance archive hash mismatch")?;
    }

    validate_hex(&provenance.kin.commit, 40, "Kin commit")?;
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

    let mut records = HashMap::new();
    for record in &provenance.archive_contents {
        validate_hex(
            &record.sha256,
            64,
            &format!("component '{}' SHA-256", record.name),
        )?;
        if records.insert(record.name.as_str(), record).is_some() {
            anyhow::bail!(
                "artifact provenance contains duplicate component '{}'",
                record.name
            );
        }
    }

    let mut staged_count = 0;
    for component in spec {
        let path = component_path(stage_root, *component);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                staged_count += 1;
                let record = records.get(component.name).with_context(|| {
                    format!(
                        "artifact provenance is missing staged component '{}'",
                        component.name
                    )
                })?;
                if record.size_bytes != metadata.len() {
                    anyhow::bail!(
                        "artifact provenance size mismatch for component '{}'",
                        component.name
                    );
                }
                if verify_hashes && sha256_file(&path)? != record.sha256.to_lowercase() {
                    anyhow::bail!(
                        "artifact provenance hash mismatch for component '{}'",
                        component.name
                    );
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err).context("failed to inspect staged provenance input"),
        }
    }
    if records.len() != staged_count {
        anyhow::bail!(
            "artifact provenance inventory contains files outside the managed platform bundle"
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

#[derive(Clone, Debug, serde::Deserialize)]
struct StagedCliMeta {
    schema: String,
    kin_version: String,
    graph_snapshot_version: u32,
    kin_commit: String,
    kin_dirty: bool,
    kin_source_known: bool,
    dependency_provenance: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct StagedDaemonMeta {
    schema: String,
    version: String,
    graph_snapshot_version: u32,
    build: StagedDaemonBuild,
}

#[derive(Clone, Debug, serde::Deserialize)]
struct StagedDaemonBuild {
    sha: String,
    dirty: bool,
    source_known: bool,
    dependency_provenance: String,
}

fn validate_staged_build_identity(
    stage_root: &Path,
    spec: &[ComponentSpec],
    expected_version: &str,
    provenance: &ArtifactProvenance,
) -> Result<()> {
    let cli_name = if cfg!(windows) { "kin.exe" } else { "kin" };
    let daemon_name = if cfg!(windows) {
        "kin-daemon.exe"
    } else {
        "kin-daemon"
    };
    let cli_spec = spec
        .iter()
        .copied()
        .find(|component| component.name == cli_name)
        .context("platform bundle contract has no Kin CLI")?;
    let daemon_spec = spec
        .iter()
        .copied()
        .find(|component| component.name == daemon_name)
        .context("platform bundle contract has no Kin daemon")?;
    let cli: StagedCliMeta = run_json_probe(
        &component_path(stage_root, cli_spec),
        &["bench-meta", "--json"],
    )?;
    let daemon: StagedDaemonMeta =
        run_json_probe(&component_path(stage_root, daemon_spec), &["--compat-json"])?;
    validate_build_identity(&cli, &daemon, expected_version, provenance)
}

fn run_json_probe<T: serde::de::DeserializeOwned>(path: &Path, args: &[&str]) -> Result<T> {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let mut child = Command::new(path)
        .args(args)
        .env_remove("DYLD_INSERT_LIBRARIES")
        .env_remove("LD_PRELOAD")
        .env("KIN_NO_VFS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to execute staged probe {}", path.display()))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("staged metadata probe timed out: {}", path.display());
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        pipe.read_to_end(&mut stdout)?;
    }
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_end(&mut stderr)?;
    }
    if !status.success() {
        anyhow::bail!(
            "staged metadata probe {} failed with {status}: {}",
            path.display(),
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    serde_json::from_slice(&stdout).with_context(|| {
        format!(
            "staged metadata probe was not valid JSON: {}",
            path.display()
        )
    })
}

fn validate_build_identity(
    cli: &StagedCliMeta,
    daemon: &StagedDaemonMeta,
    expected_version: &str,
    provenance: &ArtifactProvenance,
) -> Result<()> {
    if cli.schema != "kin.bench-meta.v1" || daemon.schema != "kin.daemon.compat.v1" {
        anyhow::bail!("staged CLI or daemon emitted an unsupported metadata schema");
    }
    let expected = parse_release_version(expected_version)?;
    if parse_release_version(&cli.kin_version)? != expected
        || parse_release_version(&daemon.version)? != expected
    {
        anyhow::bail!("staged CLI or daemon version does not match release v{expected}");
    }
    if cli.kin_dirty || !cli.kin_source_known || daemon.build.dirty || !daemon.build.source_known {
        anyhow::bail!("staged CLI or daemon does not prove a clean, known source build");
    }
    if cli.kin_commit != daemon.build.sha || cli.kin_commit != provenance.kin.commit {
        anyhow::bail!("staged CLI and daemon commit identity does not match release provenance");
    }
    if cli.dependency_provenance != daemon.build.dependency_provenance
        || cli.dependency_provenance != provenance.kin.embedded_dependency_provenance
    {
        anyhow::bail!(
            "staged CLI and daemon dependency provenance does not match release provenance"
        );
    }
    if cli.graph_snapshot_version != daemon.graph_snapshot_version {
        anyhow::bail!("staged CLI and daemon graph snapshot versions are incompatible");
    }
    Ok(())
}

fn restart_pending_record(version: &str, provenance: &ArtifactProvenance) -> RestartPending {
    RestartPending {
        schema_version: 1,
        installed_version: version.to_string(),
        kin_commit: provenance.kin.commit.clone(),
        dependency_provenance: provenance.kin.embedded_dependency_provenance.clone(),
        kin_vfs_commit: provenance.kin_vfs.commit.clone(),
        recorded_at: chrono::Utc::now().to_rfc3339(),
        reason: "user acknowledgement is required after restarting daemon, MCP, and VFS sessions"
            .to_string(),
    }
}

fn restart_pending_path(kin_home: &Path) -> PathBuf {
    kin_home.join(RESTART_ACK_REQUIRED_FILE)
}

#[cfg(not(unix))]
fn persist_restart_record(kin_home: &Path, record: &RestartPending) -> Result<PathBuf> {
    let path = restart_pending_path(kin_home);
    let bytes = serde_json::to_vec_pretty(record).context("failed to serialize restart state")?;
    write_file_atomically(&path, &bytes, 0o600)
        .with_context(|| format!("failed to persist restart state {}", path.display()))?;
    Ok(path)
}

fn mcp_repair_pending_path(kin_home: &Path) -> PathBuf {
    kin_home.join(MCP_REPAIR_PENDING_FILE)
}

fn mcp_repair_pending_record(version: &str) -> McpRepairPending {
    McpRepairPending {
        schema_version: 1,
        installed_version: version.to_string(),
        recorded_at: chrono::Utc::now().to_rfc3339(),
    }
}

#[cfg(not(unix))]
fn persist_mcp_repair_record(kin_home: &Path, record: &McpRepairPending) -> Result<PathBuf> {
    let path = mcp_repair_pending_path(kin_home);
    let bytes =
        serde_json::to_vec_pretty(record).context("failed to serialize MCP repair state")?;
    write_file_atomically(&path, &bytes, 0o600)
        .with_context(|| format!("failed to persist MCP repair state {}", path.display()))?;
    Ok(path)
}

#[cfg(not(unix))]
fn read_restart_record(kin_home: &Path) -> Result<RestartPending> {
    let path = restart_pending_path(kin_home);
    let metadata = fs::symlink_metadata(&path).with_context(|| {
        format!(
            "no runtime restart acknowledgement is pending at {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "runtime restart acknowledgement marker is not a regular non-symlink file: {}",
            path.display()
        );
    }
    let bytes = fs::read(&path).with_context(|| {
        format!(
            "failed to read restart acknowledgement marker {}",
            path.display()
        )
    })?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid restart acknowledgement marker {}", path.display()))
}

fn validate_restart_ack_identity(
    record: &RestartPending,
    running_version: &str,
    running_commit: &str,
    dependency_provenance: &str,
) -> Result<()> {
    if record.schema_version != 1 {
        anyhow::bail!(
            "unsupported restart acknowledgement schema {}",
            record.schema_version
        );
    }
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

fn acknowledge_runtime_restart() -> Result<()> {
    let requested_home = crate::commands::setup::kin_dir()?;
    let lock = InstallRootLock::acquire_existing(&requested_home)?;
    let spec = platform_bundle_spec(std::env::consts::OS)?;
    recover_stale_transactions(lock.root(), spec)?;
    verify_target_binding(lock.root())?;
    attempt_pending_mcp_repair(lock.root());

    #[cfg(unix)]
    let install = InstallLayout::open(lock.root())?;
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
    let record = read_restart_record(lock.root())?;
    let build = kin_buildinfo::get();
    validate_restart_ack_identity(
        &record,
        CURRENT_VERSION,
        build.sha,
        build.dependency_provenance,
    )?;
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
        install.root.unlink_file(RESTART_ACK_REQUIRED_FILE)?;
    }
    #[cfg(not(unix))]
    durable_remove_file(&restart_pending_path(lock.root()))?;
    println!(
        "Acknowledged restarted daemon, MCP, and VFS sessions for Kin v{}.",
        record.installed_version
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
    let install_lock = InstallRootLock::acquire(&requested_home)?;
    let shim_name = crate::commands::setup::shim_filename();
    let dest = install_lock.root().join("lib").join(shim_name);
    let archive_name = current_platform_asset_name()?;

    let client = reqwest::Client::builder()
        .user_agent("kin-cli")
        .build()
        .context("failed to build HTTP client")?;

    let tag_url = format!("{GITHUB_RELEASES_TAG_URL}{CURRENT_VERSION}");
    let release: GithubRelease = client
        .get(&tag_url)
        .send()
        .await
        .context("failed to reach the GitHub releases API (offline?)")?
        .error_for_status()
        .with_context(|| format!("no published release found for v{CURRENT_VERSION}"))?
        .json()
        .await
        .context("failed to parse release JSON")?;

    let asset = find_release_asset(&release, &archive_name)?;

    let archive_bytes = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("failed to download release archive")?
        .error_for_status()
        .context("archive download returned an error")?
        .bytes()
        .await
        .context("failed to read archive bytes")?;

    if archive_bytes.is_empty() {
        anyhow::bail!("downloaded archive '{archive_name}' was empty");
    }

    verify_archive_checksum(&client, &release, &asset.name, &archive_bytes).await?;

    let shim_bytes = extract_named_file_from_tar_gz(&archive_bytes, shim_name)
        .with_context(|| format!("archive '{archive_name}' did not contain '{shim_name}'"))?;
    if shim_bytes.is_empty() {
        anyhow::bail!("the shim '{shim_name}' extracted from '{archive_name}' was empty");
    }

    write_managed_component_atomically(&install_lock, &dest, &shim_bytes)
        .with_context(|| format!("failed to install the shim at {}", dest.display()))?;
    Ok(dest)
}

/// Extract the bytes of the archive entry whose file name is exactly `target`.
fn extract_named_file_from_tar_gz(bytes: &[u8], target: &str) -> Result<Vec<u8>> {
    use std::io::Read;
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries().context("failed to read tar entries")? {
        let mut entry = entry.context("corrupt tar entry")?;
        let path = entry.path().context("invalid entry path")?.into_owned();
        if path.file_name().and_then(|n| n.to_str()) == Some(target) {
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .context("failed to read shim bytes from archive")?;
            return Ok(buf);
        }
    }
    anyhow::bail!("'{target}' not found in archive")
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
    let install = InstallLayout::open(lock.root())?;
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
    use serial_test::serial;
    use std::ffi::{OsStr, OsString};

    struct EnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value.as_ref());
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
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
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        {
            let mut builder = tar::Builder::new(&mut gz);
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

    fn full_linux_archive(prefix: &str) -> Vec<u8> {
        make_tar_gz(&[
            (&format!("{prefix}/kin"), b"new-kin"),
            (&format!("{prefix}/kin-daemon"), b"new-daemon"),
            (&format!("{prefix}/kin-vfs"), b"new-vfs"),
            (&format!("{prefix}/libkin_vfs_shim.so"), b"new-shim"),
        ])
    }

    fn write_bundle(root: &Path, spec: &[ComponentSpec], prefix: &[u8]) {
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("lib")).unwrap();
        for component in spec {
            let mut bytes = prefix.to_vec();
            bytes.extend_from_slice(component.name.as_bytes());
            fs::write(component_path(root, *component), bytes).unwrap();
        }
    }

    fn test_restart_pending(version: &str) -> RestartPending {
        RestartPending {
            schema_version: 1,
            installed_version: version.to_string(),
            kin_commit: "a".repeat(40),
            dependency_provenance: "b".repeat(64),
            kin_vfs_commit: "c".repeat(40),
            recorded_at: "2026-07-13T00:00:00Z".to_string(),
            reason: "test restart pending".to_string(),
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
                })
            })
            .collect();
        ArtifactProvenance {
            schema_version: 1,
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

    fn run_crash_recovery_case(point: &str, committed: bool) {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
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

        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::update::tests::crash_recovery_worker",
                "--nocapture",
            ])
            .env("KIN_UPDATE_TEST_WORKER_HOME", &kin_home)
            .env("KIN_UPDATE_TEST_WORKER_STAGE", &stage)
            .env("KIN_UPDATE_TEST_CRASH_POINT", point)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(86),
            "worker output: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!transaction_dirs(&kin_home).unwrap().is_empty());

        let lock = InstallRootLock::acquire_existing(&kin_home).unwrap();
        recover_stale_transactions(lock.root(), LINUX_COMPONENTS).unwrap();
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

    struct CrashedUpdate {
        _tmp: tempfile::TempDir,
        kin_home: PathBuf,
        old: HashMap<String, Option<Vec<u8>>>,
    }

    fn crash_update(point: &str, fail_install_index: Option<usize>) -> CrashedUpdate {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        let old = bundle_snapshot(&kin_home, LINUX_COMPONENTS);
        stage_archive(
            &full_linux_archive("kin-linux-x86_64"),
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
            .env("KIN_UPDATE_TEST_WORKER_HOME", &kin_home)
            .env("KIN_UPDATE_TEST_WORKER_STAGE", &stage)
            .env("KIN_UPDATE_TEST_CRASH_POINT", point);
        if let Some(index) = fail_install_index {
            command.env("KIN_UPDATE_TEST_FAIL_INSTALL_INDEX", index.to_string());
        }
        let output = command.output().unwrap();
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

    #[test]
    fn full_bundle_install_includes_vfs_and_shim_under_custom_root() {
        let tmp = tempfile::tempdir().unwrap();
        let custom_home = tmp.path().join("custom-kin-home");
        let stage = tmp.path().join("stage");
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
    fn install_failure_rolls_back_every_component() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
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
        assert!(format!("{err:#}").contains("previous bundle was restored"));
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
    fn crash_recovery_worker() {
        let Some(kin_home) = std::env::var_os("KIN_UPDATE_TEST_WORKER_HOME") else {
            return;
        };
        let stage = std::env::var_os("KIN_UPDATE_TEST_WORKER_STAGE")
            .expect("crash worker stage must be provided");
        let fail_index = std::env::var("KIN_UPDATE_TEST_FAIL_INSTALL_INDEX")
            .ok()
            .and_then(|value| value.parse::<usize>().ok());
        install_staged_bundle_with_hook(
            Path::new(&kin_home),
            Path::new(&stage),
            LINUX_COMPONENTS,
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
        for point in ["after-backup-1", "after-install-1"] {
            run_crash_recovery_case(point, false);
        }
    }

    #[test]
    fn subprocess_crashes_after_commit_recover_the_new_bundle_and_marker() {
        for point in ["after-commit", "after-restart-marker"] {
            run_crash_recovery_case(point, true);
        }
    }

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
        recover_stale_transactions(lock.root(), LINUX_COMPONENTS).unwrap();
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
        let error = recover_stale_transactions(lock.root(), LINUX_COMPONENTS)
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
        let error = recover_stale_transactions(lock.root(), LINUX_COMPONENTS)
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
        let error = recover_stale_transactions(lock.root(), LINUX_COMPONENTS)
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
            "after-rollback-restore-kin",
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
            recover_stale_transactions(lock.root(), LINUX_COMPONENTS).unwrap();
            assert_bundle_matches(&state.kin_home, LINUX_COMPONENTS, &state.old);
            assert!(transaction_dirs(lock.root()).unwrap().is_empty());
            let after_first = bundle_snapshot(&state.kin_home, LINUX_COMPONENTS);
            recover_stale_transactions(lock.root(), LINUX_COMPONENTS).unwrap();
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
        recover_stale_transactions(lock.root(), LINUX_COMPONENTS)
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
    fn replacing_bin_before_first_backup_cannot_redirect_mutation() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        let outside = tmp.path().join("outside-bin");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("kin-daemon"), b"outside-victim").unwrap();
        stage_archive(
            &full_linux_archive("kin-linux-x86_64"),
            "kin-linux-x86_64.tar.gz",
            &stage,
            LINUX_COMPONENTS,
        )
        .unwrap();

        let error = install_staged_bundle_unix_with_hooks(
            &kin_home,
            &stage,
            LINUX_COMPONENTS,
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
    fn replacing_lib_before_shim_install_cannot_redirect_mutation() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
        let outside = tmp.path().join("outside-lib");
        write_bundle(&kin_home, LINUX_COMPONENTS, b"old-");
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
        assert!(
            fs::read_dir(&held_lib).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp-")),
            "failed atomic write must remove its detached temp file"
        );
    }

    #[test]
    fn provenance_mismatch_is_rejected_before_live_bytes_move() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let stage = tmp.path().join("stage");
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
        validate_artifact_provenance(
            &provenance,
            &release,
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
            &asset,
            &archive,
            &stage,
            LINUX_COMPONENTS,
            true,
        )
        .expect_err("component hash mismatch must fail preflight");
        assert!(format!("{err:#}").contains("hash mismatch"));
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
    fn staged_build_identity_requires_exact_clean_provenance() {
        let provenance = ArtifactProvenance {
            schema_version: 1,
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
                sha256: "e".repeat(64),
                size_bytes: 1,
            },
            archive_contents: Vec::new(),
        };
        let cli = StagedCliMeta {
            schema: "kin.bench-meta.v1".to_string(),
            kin_version: "0.2.22".to_string(),
            graph_snapshot_version: 7,
            kin_commit: "a".repeat(40),
            kin_dirty: false,
            kin_source_known: true,
            dependency_provenance: "b".repeat(64),
        };
        let daemon = StagedDaemonMeta {
            schema: "kin.daemon.compat.v1".to_string(),
            version: "0.2.22".to_string(),
            graph_snapshot_version: 7,
            build: StagedDaemonBuild {
                sha: "a".repeat(40),
                dirty: false,
                source_known: true,
                dependency_provenance: "b".repeat(64),
            },
        };
        validate_build_identity(&cli, &daemon, "0.2.22", &provenance).unwrap();

        let mut dirty = daemon.clone();
        dirty.build.dirty = true;
        assert!(validate_build_identity(&cli, &dirty, "0.2.22", &provenance).is_err());
        let mut wrong_commit = daemon;
        wrong_commit.build.sha = "f".repeat(40);
        assert!(validate_build_identity(&cli, &wrong_commit, "0.2.22", &provenance).is_err());
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
    fn target_binding_accepts_identical_bytes_and_rejects_a_different_binary() {
        use std::io::Write as _;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("kin-home");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir(root.join("lib")).unwrap();
        let target = root.join("bin/kin");
        fs::copy(std::env::current_exe().unwrap(), &target).unwrap();
        verify_target_binding(&root).unwrap();

        fs::OpenOptions::new()
            .append(true)
            .open(&target)
            .unwrap()
            .write_all(b"different")
            .unwrap();
        let err = verify_target_binding(&root).expect_err("different target bytes must fail");
        assert!(format!("{err:#}").contains("different Kin installation"));
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

    #[test]
    fn windows_bundle_uses_exe_names_and_removes_stale_projection_files() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
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
        let _kin_home = EnvGuard::set("KIN_HOME", &kin_home);

        let error = run(false, None, true, true, false)
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
        let config = home.join(".codex/config.toml");
        fs::write(
            &config,
            r#"[mcp_servers.kin]
command = "/old/Cellar/kin/0.2.21/bin/kin"
args = ["mcp", "start"]
cwd = "/user/repo"
"#,
        )
        .unwrap();
        let _home = EnvGuard::set("HOME", &home);
        let _kin_home = EnvGuard::set("KIN_HOME", &kin_home);
        let _kin_dir = EnvGuard::set("KIN_DIR", tmp.path().join("wrong-install"));

        let repaired = crate::commands::setup::remerge_existing_mcp_configs();
        assert!(repaired.contains(&config));
        let root: toml::Value = toml::from_str(&fs::read_to_string(config).unwrap()).unwrap();
        let entry = &root["mcp_servers"]["kin"];
        let expected_launcher = kin_home
            .join("bin")
            .join(executable_name)
            .to_string_lossy()
            .into_owned();
        assert_eq!(entry["command"].as_str(), Some(expected_launcher.as_str()));
        assert_eq!(entry["cwd"].as_str(), Some("/user/repo"));
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn postcommit_crashes_durably_repair_mcp_before_marker_clear() {
        for point in ["after-commit", "after-restart-marker", "after-cleanup"] {
            let state = crash_update(point, None);
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
            let home = state._tmp.path().join(format!("home-{point}"));
            let config = home.join(".codex/config.toml");
            fs::create_dir_all(config.parent().unwrap()).unwrap();
            fs::write(
                &config,
                r#"[mcp_servers.kin]
command = "/old/Cellar/kin/0.2.21/bin/kin"
args = ["mcp", "start"]
cwd = "/user/repo"
"#,
            )
            .unwrap();
            let _home = EnvGuard::set("HOME", &home);
            let _kin_home = EnvGuard::set("KIN_HOME", &state.kin_home);
            let _kin_dir = EnvGuard::set("KIN_DIR", state._tmp.path().join("wrong-install"));
            let _cwd = CwdGuard::set(&home);

            if !transaction_dirs(&state.kin_home).unwrap().is_empty() {
                let lock = InstallRootLock::acquire_existing(&state.kin_home).unwrap();
                recover_stale_transactions(lock.root(), LINUX_COMPONENTS).unwrap();
            }
            assert!(
                mcp_repair_pending_path(&state.kin_home).is_file(),
                "{point} must converge to durable MCP repair state"
            );

            attempt_pending_mcp_repair(&state.kin_home);
            let root: toml::Value = toml::from_str(&fs::read_to_string(&config).unwrap()).unwrap();
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
            assert_eq!(
                root["mcp_servers"]["kin"]["cwd"].as_str(),
                Some("/user/repo")
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
        let config = home.join(".codex/config.toml");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        let malformed = b"\xff\xfe[mcp_servers.kin\ncommand =";
        fs::write(&config, malformed).unwrap();
        let marker = mcp_repair_pending_path(&state.kin_home);
        let marker_before = fs::read(&marker).unwrap();
        let _home = EnvGuard::set("HOME", &home);
        let _kin_home = EnvGuard::set("KIN_HOME", &state.kin_home);
        let _cwd = CwdGuard::set(&home);

        attempt_pending_mcp_repair(&state.kin_home);

        assert_eq!(fs::read(&config).unwrap(), malformed);
        assert_eq!(fs::read(&marker).unwrap(), marker_before);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn explicit_restart_ack_clears_only_a_matching_release_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let lock = InstallRootLock::acquire(&kin_home).unwrap();
        fs::copy(std::env::current_exe().unwrap(), kin_home.join("bin/kin")).unwrap();
        let build = kin_buildinfo::get();
        let mut record = test_restart_pending(CURRENT_VERSION);
        record.kin_commit = build.sha.to_string();
        record.dependency_provenance = build.dependency_provenance.to_string();
        let install = InstallLayout::open(lock.root()).unwrap();
        persist_restart_record_at(&install, &record).unwrap();
        drop(lock);
        let _kin_home = EnvGuard::set("KIN_HOME", &kin_home);
        let _home = EnvGuard::set("HOME", tmp.path().join("home"));

        acknowledge_runtime_restart().unwrap();

        assert!(!restart_pending_path(&kin_home).exists());
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn restart_ack_rejects_identity_mismatch_and_retains_obligation() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let lock = InstallRootLock::acquire(&kin_home).unwrap();
        fs::copy(std::env::current_exe().unwrap(), kin_home.join("bin/kin")).unwrap();
        let build = kin_buildinfo::get();
        let mut record = test_restart_pending(CURRENT_VERSION);
        record.kin_commit = "0".repeat(40);
        record.dependency_provenance = build.dependency_provenance.to_string();
        let install = InstallLayout::open(lock.root()).unwrap();
        persist_restart_record_at(&install, &record).unwrap();
        drop(lock);
        let _kin_home = EnvGuard::set("KIN_HOME", &kin_home);
        let _home = EnvGuard::set("HOME", tmp.path().join("home"));

        let error = acknowledge_runtime_restart()
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
        let _kin_dir = EnvGuard::set("KIN_DIR", &fallback);
        let _kin_home = EnvGuard::set("KIN_HOME", &preferred);

        assert_eq!(UpdateConfig::path().unwrap(), preferred.join("update.toml"));
    }

    #[test]
    #[serial]
    fn check_only_channel_override_does_not_persist_state() {
        let tmp = tempfile::tempdir().unwrap();
        let _kin_home = EnvGuard::set("KIN_HOME", tmp.path());

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
            current_version: "0.2.21",
            latest_version: "0.2.22",
            channel: "stable",
            update_available: true,
            platform_asset: "kin-macos-aarch64.tar.gz",
            restart_ack_required: false,
            mcp_repair_pending: false,
        };
        let value = serde_json::to_value(check).unwrap();

        assert_eq!(value["current_version"], "0.2.21");
        assert_eq!(value["latest_version"], "0.2.22");
        assert_eq!(value["channel"], "stable");
        assert_eq!(value["update_available"], true);
        assert_eq!(value["platform_asset"], "kin-macos-aarch64.tar.gz");
        assert_eq!(value["restart_ack_required"], false);
        assert_eq!(value["mcp_repair_pending"], false);
        assert_eq!(value.as_object().unwrap().len(), 7);
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
    fn update_config_toml_roundtrip() {
        let text = toml::to_string_pretty(&UpdateConfig {
            channel: Channel::Alpha,
        })
        .unwrap();
        assert!(text.contains("channel = \"alpha\""));

        let parsed: UpdateConfig = toml::from_str(&text).unwrap();
        assert_eq!(parsed.channel, Channel::Alpha);

        // A missing/empty config deserializes to the stable default.
        let empty: UpdateConfig = toml::from_str("").unwrap();
        assert_eq!(empty.channel, Channel::Stable);
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
