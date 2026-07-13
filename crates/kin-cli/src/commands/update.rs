// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use fs2::FileExt;
use semver::Version;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
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
const RESTART_PENDING_FILE: &str = "update-restart-pending.json";

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
        let path = kin_home.join("update.toml");
        let contents = toml::to_string_pretty(self).context("failed to serialize update config")?;
        write_file_atomically(&path, contents.as_bytes(), 0o600)
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
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

#[derive(Debug, serde::Serialize)]
struct UpdateCheck<'a> {
    current_version: &'a str,
    latest_version: &'a str,
    channel: &'a str,
    update_available: bool,
    platform_asset: &'a str,
    restart_pending: bool,
}

pub async fn run(
    skip_verify: bool,
    channel_flag: Option<Channel>,
    check_only: bool,
    json: bool,
) -> Result<()> {
    ensure_mutating_update_supported(std::env::consts::OS, check_only)?;

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
    let restart_pending = restart_pending_path(&kin_home).exists();

    if check_only {
        let check = UpdateCheck {
            current_version: CURRENT_VERSION,
            latest_version: &latest,
            channel: channel_name(channel),
            update_available,
            platform_asset: &asset.name,
            restart_pending,
        };
        if json {
            println!("{}", serde_json::to_string_pretty(&check)?);
        } else if update_available {
            println!("Update available: v{CURRENT_VERSION} -> v{latest}");
        } else {
            println!("Already up to date (v{CURRENT_VERSION}).");
        }
        if restart_pending && !json {
            println!(
                "Runtime restart remains pending: {}",
                restart_pending_path(&kin_home).display()
            );
        }
        return Ok(());
    }

    if !update_available {
        println!("Already up to date (v{CURRENT_VERSION}).");
        if restart_pending {
            println!(
                "Runtime restart remains pending: {}",
                restart_pending_path(&kin_home).display()
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

    // Long-lived MCP client configs must point at the stable managed launcher,
    // not a versioned Cellar path or a Cargo target binary. This repair is
    // deliberately post-commit and best-effort: a malformed client config must
    // never roll back a verified binary bundle, and the setup merge warns while
    // preserving user-authored policy such as `cwd`.
    for path in refresh_mcp_launchers_after_update() {
        println!("Refreshed Kin MCP launcher: {}", path.display());
    }

    let pending = restart_pending_path(&kin_home);
    println!("Installed v{latest} on disk.");
    println!(
        "Runtime restart pending: {}. Existing daemon, MCP, and VFS processes may still be \
         running the previous build; restart those sessions before treating the runtime as converged.",
        pending.display()
    );
    Ok(())
}

fn refresh_mcp_launchers_after_update() -> Vec<PathBuf> {
    crate::commands::setup::remerge_existing_mcp_configs()
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

fn ensure_managed_dirs(root: &Path, create: bool) -> Result<()> {
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize Kin install root {}", root.display()))?;
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
                return Err(err)
                    .with_context(|| format!("failed to inspect managed path {}", path.display()));
            }
        }
    }
    Ok(())
}

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

fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)
            .with_context(|| format!("failed to open directory for sync {}", path.display()))?
            .sync_all()
            .with_context(|| format!("failed to sync directory {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

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
}

impl StagingDir {
    fn create(kin_home: &Path) -> Result<Self> {
        let path = kin_home.join(format!(".update-stage-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)
            .with_context(|| format!("failed to create update staging dir {}", path.display()))?;
        sync_dir(kin_home)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
        if let Some(parent) = self.path.parent() {
            let _ = sync_dir(parent);
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
            fs::create_dir(stage_root).with_context(|| {
                format!("failed to create staging root {}", stage_root.display())
            })?;
            if let Some(parent) = stage_root.parent() {
                sync_dir(parent)?;
            }
        }
        Err(err) => return Err(err).context("failed to inspect staging root"),
    }
    for name in ["bin", "lib"] {
        let dir = stage_root.join(name);
        fs::create_dir(&dir)
            .with_context(|| format!("failed to create staging directory {}", dir.display()))?;
        sync_dir(stage_root)?;
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

    let path = component_path(stage_root, component);
    let mut file = File::create(&path)
        .with_context(|| format!("failed to stage release component {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("failed to write staged component {}", path.display()))?;
    #[cfg(unix)]
    if component.location == ComponentLocation::Bin {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    }
    file.sync_all()
        .with_context(|| format!("failed to sync staged component {}", path.display()))?;
    drop(file);
    sync_dir(path.parent().expect("component paths always have a parent"))?;
    Ok(())
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
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct TransactionJournal {
    schema_version: u32,
    target_version: String,
    phase: TransactionPhase,
    components: Vec<JournalComponent>,
    restart_pending: RestartPending,
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
    mut before_install: F,
) -> Result<InstallOutcome>
where
    F: FnMut(usize, &Path) -> Result<()>,
{
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
                return Err(err)
                    .with_context(|| format!("failed to inspect destination {}", dest.display()));
            }
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
        if component.required && !install_new {
            anyhow::bail!("required component '{}' was not staged", component.name);
        }
        components.push(JournalComponent {
            name: component.name.to_string(),
            location: component.location,
            required: component.required,
            had_original,
            install_new,
        });
    }

    let transaction_root = create_transaction_root(kin_home)?;
    let backup_root = transaction_root.join("old");
    let mut journal = TransactionJournal {
        schema_version: 1,
        target_version: target_version.to_string(),
        phase: TransactionPhase::Prepared,
        components,
        restart_pending: restart_pending.clone(),
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
            return rollback_after_failure(err, &mut journal, &transaction_root, kin_home, spec);
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
            return rollback_after_failure(err, &mut journal, &transaction_root, kin_home, spec);
        }
        if let Err(err) = durable_rename(&staged, &dest) {
            return rollback_after_failure(err, &mut journal, &transaction_root, kin_home, spec);
        }
        maybe_crash_at(&format!("after-install-{install_index}"));
        install_index += 1;
    }

    let staged_components: HashSet<&str> = journal
        .components
        .iter()
        .filter(|component| component.install_new)
        .map(|component| component.name.as_str())
        .collect();
    if let Err(err) = validate_installed_bundle(kin_home, &staged_components, spec) {
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

    let retained_backup = match cleanup_transaction_root(&transaction_root) {
        Ok(()) => None,
        Err(_) => Some(transaction_root),
    };
    Ok(InstallOutcome { retained_backup })
}

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

fn persist_journal(transaction_root: &Path, journal: &TransactionJournal) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(journal).context("failed to serialize update journal")?;
    write_file_atomically(&transaction_root.join(TRANSACTION_JOURNAL), &bytes, 0o600)
        .context("failed to persist update journal")
}

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
    if journal.schema_version != 1 {
        anyhow::bail!(
            "unsupported update journal schema {}",
            journal.schema_version
        );
    }
    if journal.components.len() != spec.len() {
        anyhow::bail!("update journal component inventory does not match this platform");
    }
    if journal.restart_pending.schema_version != 1
        || parse_release_version(&journal.target_version)?
            != parse_release_version(&journal.restart_pending.installed_version)?
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
        {
            anyhow::bail!(
                "update journal component '{}' does not match the platform contract",
                expected.name
            );
        }
    }
    Ok(())
}

fn validate_installed_bundle(
    kin_home: &Path,
    staged_components: &HashSet<&str>,
    spec: &[ComponentSpec],
) -> Result<()> {
    for component in spec {
        let was_staged = staged_components.contains(component.name);
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
    }
    Ok(())
}

fn rollback_transaction(
    journal: &mut TransactionJournal,
    transaction_root: &Path,
    kin_home: &Path,
    spec: &[ComponentSpec],
) -> Result<()> {
    validate_journal(journal, spec)?;
    let backup_root = transaction_root.join("old");
    let mut failures = Vec::new();
    for component in spec.iter().rev() {
        let record = journal_component(journal, component.name)?;
        let dest = component_path(kin_home, *component);
        let backup = component_path(&backup_root, *component);
        let backup_exists = fs::symlink_metadata(&backup).is_ok();
        let dest_exists = fs::symlink_metadata(&dest).is_ok();

        if record.had_original && backup_exists {
            if dest_exists {
                if let Err(err) = durable_remove_file(&dest) {
                    failures.push(format!("remove new {}: {err:#}", dest.display()));
                    continue;
                }
            }
            if let Err(err) = durable_rename(&backup, &dest) {
                failures.push(format!(
                    "restore {} from {}: {err:#}",
                    dest.display(),
                    backup.display()
                ));
            }
        } else if record.had_original && !dest_exists {
            failures.push(format!(
                "original component '{}' is absent from both live and backup paths",
                component.name
            ));
        } else if !record.had_original && record.install_new && dest_exists {
            if let Err(err) = durable_remove_file(&dest) {
                failures.push(format!("remove new {}: {err:#}", dest.display()));
            }
        }
    }
    if failures.is_empty() {
        journal.phase = TransactionPhase::RolledBack;
        persist_journal(transaction_root, journal)?;
        cleanup_transaction_root(transaction_root)
    } else {
        anyhow::bail!("rollback encountered errors: {}", failures.join("; "));
    }
}

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
            let installed: HashSet<&str> = journal
                .components
                .iter()
                .filter(|component| component.install_new)
                .map(|component| component.name.as_str())
                .collect();
            validate_installed_bundle(kin_home, &installed, spec).with_context(|| {
                format!(
                    "committed interrupted update at {} has an invalid live bundle",
                    transaction_root.display()
                )
            })?;
            persist_restart_record(kin_home, &journal.restart_pending)?;
            cleanup_transaction_root(&transaction_root)?;
        } else {
            rollback_transaction(&mut journal, &transaction_root, kin_home, spec).with_context(
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
    if provenance.artifact != expected_artifact
        || provenance.archive.name != archive.name
        || provenance.target.is_empty()
        || provenance.vfs_target.is_empty()
    {
        anyhow::bail!(
            "artifact provenance identity does not match '{}'",
            archive.name
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
        reason: "existing daemon, MCP, or VFS processes may still be executing the previous build"
            .to_string(),
    }
}

fn restart_pending_path(kin_home: &Path) -> PathBuf {
    kin_home.join(RESTART_PENDING_FILE)
}

fn persist_restart_record(kin_home: &Path, record: &RestartPending) -> Result<PathBuf> {
    let path = restart_pending_path(kin_home);
    let bytes = serde_json::to_vec_pretty(record).context("failed to serialize restart state")?;
    write_file_atomically(&path, &bytes, 0o600)
        .with_context(|| format!("failed to persist restart state {}", path.display()))?;
    Ok(path)
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
        install_staged_bundle(
            Path::new(&kin_home),
            Path::new(&stage),
            LINUX_COMPONENTS,
            "0.2.22",
            &test_restart_pending("0.2.22"),
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

        OpenOptions::new()
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

        let error = run(false, None, true, true)
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

        let repaired = refresh_mcp_launchers_after_update();
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
            restart_pending: false,
        };
        let value = serde_json::to_value(check).unwrap();

        assert_eq!(value["current_version"], "0.2.21");
        assert_eq!(value["latest_version"], "0.2.22");
        assert_eq!(value["channel"], "stable");
        assert_eq!(value["update_available"], true);
        assert_eq!(value["platform_asset"], "kin-macos-aarch64.tar.gz");
        assert_eq!(value["restart_pending"], false);
        assert_eq!(value.as_object().unwrap().len(), 6);
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
