// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Checked filesystem carrier for a frozen local repository generation.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path};

use anyhow::{bail, Context, Result};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SCHEMA: &str = "kin.recovery.v1";
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;

pub(super) fn ensure_platform() -> Result<()> {
    if !cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    )) {
        bail!("atomic native recovery is not supported on this platform; preserve the source and use a supported Linux or macOS system");
    }
    Ok(())
}

fn ensure_directory_identity(expected: &File, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let actual = open_directory(path)?.into_std_file().metadata()?;
        let expected = expected.metadata()?;
        if (actual.dev(), actual.ino()) != (expected.dev(), expected.ino()) {
            bail!(
                "recovery directory moved or was replaced: {}",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    let _ = (expected, path);
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub size: u64,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub schema: String,
    pub source_root: std::path::PathBuf,
    pub repository_id: String,
    pub workspace_id: String,
    pub layout_version: u32,
    pub roots: kin_model::RootBundle,
    pub files: BTreeMap<String, Entry>,
}

fn open_directory(path: &Path) -> Result<Dir> {
    let absolute = std::path::absolute(path)?;
    let mut directory = Dir::open_ambient_dir("/", cap_std::ambient_authority())?;
    for component in absolute.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => directory = directory.open_dir_nofollow(name)?,
            _ => bail!("unsupported recovery directory path"),
        }
    }
    Ok(directory)
}

fn open_regular(path: &Path) -> Result<File> {
    let parent = open_directory(path.parent().context("file parent missing")?)?;
    open_regular_at(
        &parent,
        Path::new(path.file_name().context("file name missing")?),
    )
}

fn open_sync_directory(path: &Path) -> Result<File> {
    let directory = open_directory(path)?;
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY);
    }
    // Directory traversal capabilities may use O_PATH, which cannot be synced.
    Ok(directory.open_with(".", &options)?.into_std())
}

fn open_regular_at(parent: &Dir, name: &Path) -> Result<File> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = parent.open_with(name, &options)?;
    if !file.metadata()?.is_file() {
        bail!("recovery requires a regular file: {}", name.display());
    }
    Ok(file.into_std())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    open_regular(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("recovery input exceeds size limit: {}", path.display());
    }
    Ok(bytes)
}

fn digest_file(path: &Path) -> Result<Entry> {
    digest_open_file(open_regular(path)?)
}

fn digest_open_file(mut input: File) -> Result<Entry> {
    let metadata = input.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("recovery requires a regular file");
    }
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        size = size
            .checked_add(count as u64)
            .context("recovery size overflow")?;
    }
    if size != metadata.len() {
        bail!("file changed while reading recovery input");
    }
    Ok(Entry {
        size,
        sha256: hex::encode(hash.finalize()),
    })
}

fn safe_relative(name: &str) -> Result<&Path> {
    let path = Path::new(name);
    if name.is_empty()
        || name.contains('\\')
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        bail!("unsafe recovery payload path {name:?}");
    }
    Ok(path)
}

fn inventory(root: &Path) -> Result<BTreeMap<String, Entry>> {
    let mut result = BTreeMap::new();
    let mut pending = vec![(open_directory(root)?, std::path::PathBuf::new())];
    while let Some((dir, prefix)) = pending.pop() {
        for entry in dir.entries()? {
            let entry = entry?;
            let filename = entry.file_name();
            let path = prefix.join(&filename);
            let kind = entry.file_type()?;
            if kind.is_symlink() || (!kind.is_file() && !kind.is_dir()) {
                bail!("unsupported recovery input: {}", path.display());
            }
            if kind.is_dir() {
                pending.push((dir.open_dir_nofollow(&filename)?, path));
                continue;
            }
            if result.len() >= MAX_ENTRIES {
                bail!("recovery carrier exceeds {MAX_ENTRIES} files");
            }
            let name = path
                .to_str()
                .context("non-UTF-8 recovery path")?
                .replace(std::path::MAIN_SEPARATOR, "/");
            safe_relative(&name)?;
            result.insert(
                name,
                digest_open_file(open_regular_at(&dir, Path::new(&filename))?)?,
            );
        }
    }
    Ok(result)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn publish_absent(
    source: &Path,
    destination: &Path,
    source_parent: &File,
    destination_parent: &File,
) -> Result<()> {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    ))]
    {
        rustix::fs::renameat_with(
            source_parent,
            source.file_name().context("source name missing")?,
            destination_parent,
            destination
                .file_name()
                .context("destination name missing")?,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        Ok(())
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "redox"
    )))]
    {
        let _ = (source, destination, source_parent, destination_parent);
        bail!("atomic recovery publication is unsupported on this platform");
    }
}

fn copy_checked(source: &Path, target: &Path, files: &BTreeMap<String, Entry>) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(target)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(target)?;
    for (name, expected) in files {
        let relative = safe_relative(name)?;
        let from = source.join(relative);
        let to = target.join(relative);
        let parent = to.parent().context("payload parent missing")?;
        fs::create_dir_all(parent)?;
        let mut input = open_regular(&from)?;
        let mut output = OpenOptions::new().write(true).create_new(true).open(&to)?;
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        if &digest_file(&to)? != expected {
            bail!("recovery input changed: {name}");
        }
    }
    let mut directories = vec![target.to_path_buf()];
    for name in files.keys() {
        let mut parent = target
            .join(safe_relative(name)?)
            .parent()
            .unwrap()
            .to_path_buf();
        while parent != target {
            directories.push(parent.clone());
            parent.pop();
        }
    }
    directories.sort();
    directories.dedup();
    for directory in directories.into_iter().rev() {
        sync_directory(&directory)?;
    }
    Ok(())
}

/// The caller retains its authority freeze throughout this operation.
pub(super) fn publish(source: &Path, target: &Path, mut manifest: Manifest) -> Result<()> {
    ensure_platform()?;
    refuse_path_bound_recovery(source)?;
    let absolute_target = std::path::absolute(target)?;
    let target = absolute_target.as_path();
    if fs::symlink_metadata(target).is_ok() {
        bail!("backup destination already exists: {}", target.display());
    }
    let parent = target
        .parent()
        .context("backup destination needs a parent")?
        .canonicalize()?;
    if parent.starts_with(source.canonicalize()?) {
        bail!("backup must be outside the source .kin directory");
    }
    let parent_handle = open_sync_directory(&parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".kin-backup-incomplete-")
        .tempdir_in(&parent)?;
    ensure_directory_identity(&parent_handle, &parent)?;
    let staging_handle = open_directory(staging.path())?.into_std_file();
    manifest.schema = SCHEMA.into();
    manifest.source_root = source.canonicalize()?;
    manifest.files = inventory(source)?;
    copy_checked(source, &staging.path().join("payload"), &manifest.files)?;
    refuse_path_bound_recovery(source)?;
    refuse_path_bound_recovery(&staging.path().join("payload"))?;
    if inventory(source)? != manifest.files {
        bail!("source changed during backup; retry after stopping writers");
    }
    let _staged_freeze = verify_staged_authority(&staging.path().join("payload"), &manifest)
        .context("validate copied native authority before completing backup")?;
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        bail!("recovery manifest exceeds size limit");
    }
    write_new(&staging.path().join("manifest.json"), &bytes)?;
    write_new(
        &staging.path().join("COMPLETE"),
        hex::encode(Sha256::digest(&bytes)).as_bytes(),
    )?;
    validate(staging.path())?;
    sync_directory(staging.path())?;
    ensure_directory_identity(&parent_handle, &parent)?;
    ensure_directory_identity(&staging_handle, staging.path())?;
    publish_absent(staging.path(), target, &parent_handle, &parent_handle)
        .context("publish completed backup")?;
    parent_handle.sync_all().context("backup was published, but parent durability is unconfirmed; preserve and inspect the destination")?;
    Ok(())
}

pub(super) fn validate(carrier: &Path) -> Result<Manifest> {
    ensure_platform()?;
    let path = carrier.join("manifest.json");
    let bytes = read_bounded(&path, MAX_MANIFEST_BYTES)?;
    let complete = carrier.join("COMPLETE");
    let marker = read_bounded(&complete, 64)?;
    if marker.len() != 64 {
        bail!("backup completion marker is invalid");
    }
    if marker != hex::encode(Sha256::digest(&bytes)).as_bytes() {
        bail!("backup manifest checksum mismatch");
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    if manifest.schema != SCHEMA {
        bail!("unsupported recovery carrier schema {}", manifest.schema);
    }
    if !manifest.source_root.is_absolute() {
        bail!("recovery carrier source location must be absolute");
    }
    if manifest.files.len() > MAX_ENTRIES {
        bail!("recovery carrier exceeds file limit");
    }
    for name in manifest.files.keys() {
        safe_relative(name)?;
    }
    if inventory(&carrier.join("payload"))? != manifest.files {
        bail!("backup payload is incomplete or corrupt");
    }
    let layout = kin_core::KinLayout::new(carrier.join("payload"));
    let identity = kin_core::KinManifest::load(&layout.manifest_path())?;
    if identity.repo_id != manifest.repository_id || identity.workspace_id != manifest.workspace_id
    {
        bail!("backup repository or workspace identity mismatch");
    }
    if layout.read_version()? != manifest.layout_version {
        bail!("backup layout version mismatch");
    }
    Ok(manifest)
}

pub(super) fn inspect(carrier: &Path) -> Result<Manifest> {
    let manifest = validate(carrier)?;
    refuse_path_bound_recovery(&carrier.join("payload"))?;
    let _freeze = verify_staged_authority(&carrier.join("payload"), &manifest)?;
    Ok(manifest)
}

/// Retain the validated native generation until its staged files are published.
fn verify_staged_authority(
    path: &Path,
    manifest: &Manifest,
) -> Result<kin_db::LocalRepositoryAuthorityFreeze> {
    let layout = kin_core::KinLayout::new(path.to_path_buf());
    let identity = kin_core::KinManifest::load(&layout.manifest_path())?;
    if identity.repo_id != manifest.repository_id || identity.workspace_id != manifest.workspace_id
    {
        bail!("staged repository or workspace identity mismatch");
    }
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)?;
    let backend = kin_db::LocalFileBackend::new(layout.kindb_dir());
    let frozen = kin_db::LocalRepositoryAuthorityFreeze::open_existing_read_only(
        binding.repository_id().clone(),
        &backend,
    )?;
    if frozen.roots() != &manifest.roots {
        bail!("staged native authority roots do not match the carrier");
    }
    if !frozen
        .authority()
        .metadata()
        .workspaces
        .iter()
        .any(|workspace| workspace.workspace_id == binding.workspace_id())
    {
        bail!("staged authority does not contain its manifest workspace");
    }
    Ok(frozen)
}

const RUNTIME_FILES: &[&str] = &[
    "daemon.pid",
    "daemon.port",
    "daemon.owner",
    "daemon.pid.tmp",
    "daemon.port.tmp",
    "daemon.owner.tmp",
    "daemon.token",
    "daemon.lock",
    "daemon.lifecycle",
    "daemon.start.lock",
];

fn refuse_path_bound_recovery(root: &Path) -> Result<()> {
    let directory = open_directory(root)?;
    match directory.symlink_metadata("reconciliation") {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let control = open_directory(&root.join("reconciliation"))?;
    for entry in control.entries()? {
        let name = entry?.file_name();
        if name.to_string_lossy().starts_with("tx-")
            || name
                .to_string_lossy()
                .eq_ignore_ascii_case("exact-eject-journal.json")
        {
            bail!("path-bound reconciliation recovery remains; preserve the original repository and recover it with its matching Kin binary before creating or restoring a carrier");
        }
    }
    Ok(())
}

pub(super) fn restore(
    carrier: &Path,
    destination: &Path,
    verify: impl FnOnce(&Path, &Manifest) -> Result<()>,
) -> Result<()> {
    ensure_platform()?;
    let absolute_destination = std::path::absolute(destination)?;
    let destination = absolute_destination.as_path();
    let manifest = validate(carrier)?;
    refuse_path_bound_recovery(&carrier.join("payload"))?;
    let restore_files: BTreeMap<_, _> = manifest
        .files
        .iter()
        .filter(|(name, _)| {
            !RUNTIME_FILES
                .iter()
                .any(|runtime| name.eq_ignore_ascii_case(runtime))
        })
        .map(|(name, entry)| (name.clone(), entry.clone()))
        .collect();
    if fs::symlink_metadata(destination).is_ok() {
        bail!(
            "restore destination already exists: {}",
            destination.display()
        );
    }
    let parent = destination
        .parent()
        .context("restore destination needs a parent")?
        .canonicalize()?;
    if parent.starts_with(carrier.canonicalize()?) {
        bail!("restore destination must be outside the carrier");
    }
    let resolved_destination = parent.join(
        destination
            .file_name()
            .context("restore target needs a name")?,
    );
    let same_source = resolved_destination == manifest.source_root;
    #[cfg(target_vendor = "apple")]
    let same_source = same_source
        || resolved_destination
            .to_string_lossy()
            .eq_ignore_ascii_case(&manifest.source_root.to_string_lossy());
    if same_source {
        bail!("restore requires a different working-directory path from the original repository; preserve the carrier and choose a fresh location");
    }
    let parent_handle = open_sync_directory(&parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".kin-restore-incomplete-")
        .tempdir_in(&parent)?;
    ensure_directory_identity(&parent_handle, &parent)?;
    let staging_handle = open_directory(staging.path())?.into_std_file();
    let payload = staging.path().join("payload");
    copy_checked(&carrier.join("payload"), &payload, &restore_files)?;
    let payload_handle = open_directory(&payload)?.into_std_file();
    verify(&payload, &manifest)?;
    refuse_path_bound_recovery(&payload)?;
    let _staged_freeze = verify_staged_authority(&payload, &manifest)
        .context("validate restored native authority")?;
    if inventory(&payload)? != restore_files {
        bail!("staged recovery payload changed before publication");
    }
    sync_directory(&payload)?;
    ensure_directory_identity(&parent_handle, &parent)?;
    ensure_directory_identity(&staging_handle, staging.path())?;
    ensure_directory_identity(&payload_handle, &payload)?;
    refuse_path_bound_recovery(&payload)?;
    publish_absent(&payload, destination, &staging_handle, &parent_handle)
        .context("publish restored repository")?;
    parent_handle.sync_all().context("restore was published, but parent durability is unconfirmed; preserve and inspect the destination")?;
    Ok(())
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "redox"
))]
#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
    }

    #[test]
    fn publication_parent_handle_can_sync_and_retains_directory_identity() {
        let temp = scratch();
        let parent = temp.path().join("parent");
        let moved = temp.path().join("moved");
        fs::create_dir(&parent).unwrap();
        let handle = open_sync_directory(&parent).unwrap();
        handle.sync_all().unwrap();
        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        handle.sync_all().unwrap();
        ensure_directory_identity(&handle, &moved).unwrap();
        assert!(ensure_directory_identity(&handle, &parent).is_err());
    }

    fn retain_installed_authority_marker(source: &Path) -> std::path::PathBuf {
        let identity = kin_core::KinManifest::load(&source.join("manifest.json")).unwrap();
        let namespace = source.join("kindb").join(identity.repo_id);
        let bytes = fs::read(namespace.join("authority.json")).unwrap();
        let sha256: [u8; 32] = Sha256::digest(&bytes).into();
        let marker = namespace.join("authority.json.tmp.meta");
        write_new(
            &marker,
            &serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "byte_len": bytes.len(),
                "sha256": sha256,
            }))
            .unwrap(),
        )
        .unwrap();
        marker
    }

    fn fixture(root: &Path) -> (std::path::PathBuf, Manifest) {
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        let initialized = kin_core::init(&source).unwrap();
        let mut config =
            kin_core::config::KinConfig::load(&initialized.layout.config_path()).unwrap();
        config.remote.default = Some("origin".into());
        config.remote.refs.push(kin_core::config::RemoteRefConfig {
            name: "origin".into(),
            host: kin_core::config::RemoteHostKind::Peer,
            transport: kin_core::config::RemoteTransportKind::NativeKin,
            url: Some("https://recovery.example.invalid/native".into()),
            publish_review_state: true,
            publish_proofs: false,
        });
        config.save(&initialized.layout.config_path()).unwrap();
        let identity = kin_core::KinManifest::load(&initialized.layout.manifest_path()).unwrap();
        let binding =
            kin_core::LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();
        let manager = binding.open_manager().unwrap();
        let manifest = Manifest {
            schema: SCHEMA.into(),
            source_root: source.clone(),
            repository_id: identity.repo_id,
            workspace_id: identity.workspace_id,
            layout_version: 2,
            roots: manager.read_authority().roots().clone(),
            files: BTreeMap::new(),
        };
        fs::create_dir_all(initialized.layout.root().join("specs")).unwrap();
        fs::write(
            initialized.layout.root().join("specs/intent.json"),
            serde_json::to_vec(&kin_model::Spec {
                id: kin_model::SpecId(uuid::Uuid::new_v4()),
                intent: "preserve native intent".into(),
                scope: vec![],
                constraints: vec![],
                acceptance_criteria: vec!["identity and history survive".into()],
                affected_systems: vec![],
                validation_requirements: vec![],
            })
            .unwrap(),
        )
        .unwrap();
        (initialized.layout.root().to_path_buf(), manifest)
    }

    #[test]
    fn carrier_round_trip_preserves_every_file_and_identity() {
        let scratch = scratch();
        let (source, manifest) = fixture(scratch.path());
        let expected = inventory(&source).unwrap();
        let backup = scratch.path().join("backup");
        publish(&source, &backup, manifest).unwrap();
        assert_eq!(inventory(&source).unwrap(), expected);
        let destination = scratch.path().join("restored");
        restore(&backup, &destination, |path, manifest| {
            let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(
                &kin_core::KinLayout::new(path.to_path_buf()),
            )?;
            let manager = binding.open_manager()?;
            let frozen = manager.freeze_current_authority(&manifest.roots)?;
            assert_eq!(frozen.roots(), &manifest.roots);
            Ok(())
        })
        .unwrap();
        assert_eq!(inventory(&destination).unwrap(), expected);
        assert_eq!(validate(&backup).unwrap().files, expected);
    }

    #[test]
    fn restore_discards_runtime_endpoints_but_preserves_recovery_keys() {
        let scratch = scratch();
        let (source, manifest) = fixture(scratch.path());
        for name in RUNTIME_FILES {
            fs::write(source.join(name), b"original process").unwrap();
        }
        fs::rename(source.join("daemon.pid"), source.join("DAEMON.PID")).unwrap();
        fs::create_dir_all(source.join("reconciliation")).unwrap();
        fs::write(
            source.join("reconciliation/authority.key"),
            b"native authority key",
        )
        .unwrap();
        let carrier = scratch.path().join("carrier");
        publish(&source, &carrier, manifest).unwrap();
        let restored = scratch.path().join("restored");
        restore(&carrier, &restored, |_, _| Ok(())).unwrap();
        for name in RUNTIME_FILES {
            if *name != "daemon.pid" {
                assert!(carrier.join("payload").join(name).is_file());
            }
            assert!(!restored.join(name).exists());
        }
        assert!(carrier.join("payload/DAEMON.PID").is_file());
        assert!(!restored.join("DAEMON.PID").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&restored).unwrap().permissions().mode() & 0o077,
                0
            );
        }
        assert_eq!(
            fs::read(restored.join("reconciliation/authority.key")).unwrap(),
            b"native authority key"
        );
    }

    #[test]
    fn pending_path_bound_recovery_is_preserved_and_refused() {
        for name in [
            "tx-empty",
            "exact-eject-journal.json",
            "EXACT-EJECT-JOURNAL.JSON",
        ] {
            let scratch = scratch();
            let (source, manifest) = fixture(scratch.path());
            fs::create_dir_all(source.join("reconciliation")).unwrap();
            let pending = source.join("reconciliation").join(name);
            if name.starts_with("tx-") {
                fs::create_dir(&pending).unwrap();
            } else {
                fs::write(&pending, b"pending journal").unwrap();
            }
            let before = inventory(&source).unwrap();
            let carrier = scratch.path().join("carrier");
            assert!(publish(&source, &carrier, manifest)
                .unwrap_err()
                .to_string()
                .contains("path-bound"));
            assert!(pending.exists());
            assert_eq!(inventory(&source).unwrap(), before);
            assert!(!carrier.exists());
        }
    }

    #[test]
    fn late_empty_reconciliation_transaction_cannot_publish() {
        let scratch = scratch();
        let (source, manifest) = fixture(scratch.path());
        let carrier = scratch.path().join("carrier");
        publish(&source, &carrier, manifest).unwrap();
        let restored = scratch.path().join("restored");
        let error = restore(&carrier, &restored, |payload, _| {
            fs::create_dir_all(payload.join("reconciliation/tx-late"))?;
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("path-bound"));
        assert!(!restored.exists());
        inspect(&carrier).unwrap();
        fs::create_dir_all(carrier.join("payload/reconciliation/tx-pending")).unwrap();
        assert!(inspect(&carrier)
            .unwrap_err()
            .to_string()
            .contains("path-bound"));
        assert!(restore(&carrier, &restored, |_, _| Ok(()))
            .unwrap_err()
            .to_string()
            .contains("path-bound"));
        assert!(!restored.exists());
    }

    #[test]
    fn lost_original_path_cannot_reuse_an_existing_supervisor_route() {
        let scratch = scratch();
        let (source, manifest) = fixture(scratch.path());
        let carrier = scratch.path().join("carrier");
        publish(&source, &carrier, manifest).unwrap();
        fs::rename(&source, scratch.path().join("preserved-original")).unwrap();
        let error = restore(&carrier, &source, |_, _| Ok(())).unwrap_err();
        assert!(error
            .to_string()
            .contains("different working-directory path"));
        assert!(!source.exists());
        inspect(&carrier).unwrap();
    }

    #[test]
    fn supported_v13_authority_survives_current_carrier_restore() {
        use kin_db::StorageBackend;
        let scratch = scratch();
        let (source, _) = fixture(scratch.path());
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(
            &kin_core::KinLayout::new(source.clone()),
        )
        .unwrap();
        let manager = binding.open_manager().unwrap();
        let mut snapshot = manager.read_authority().snapshot().clone();
        drop(manager);
        let metadata = snapshot.repository_authority.as_mut().unwrap();
        let operations: BTreeMap<_, _> = metadata
            .operation_log
            .iter()
            .map(|operation| (operation.operation_id, operation.clone()))
            .collect();
        assert!(metadata
            .receipts
            .iter()
            .all(|receipt| receipt.operation.is_none()));
        for receipt in &mut metadata.receipts {
            receipt.operation = Some(operations[&receipt.operation_id].clone());
        }
        metadata.schema_version =
            kin_db::storage::repository::MIN_REPOSITORY_AUTHORITY_SCHEMA_VERSION;
        snapshot.materialized_graph = None;
        snapshot.version = snapshot.wire_version();
        assert_eq!(snapshot.version, 13);
        let aged = scratch.path().join("aged");
        let metadata_files = inventory(&source)
            .unwrap()
            .into_iter()
            .filter(|(name, _)| !name.starts_with("kindb/"))
            .collect();
        copy_checked(&source, &aged, &metadata_files).unwrap();
        fs::create_dir(aged.join("kindb")).unwrap();
        let backend = kin_db::LocalFileBackend::new(aged.join("kindb"));
        backend
            .save_snapshot(
                &binding.repository_id().to_string(),
                &snapshot.to_bytes().unwrap(),
                0,
            )
            .unwrap();
        let carrier = scratch.path().join("carrier");
        super::super::backup::create_carrier_at(&kin_core::KinLayout::new(aged.clone()), &carrier)
            .unwrap();
        let before = inventory(&aged).unwrap();
        let restored = scratch.path().join("restored");
        restore(&carrier, &restored, |_, _| Ok(())).unwrap();
        let frozen = kin_db::LocalRepositoryAuthorityFreeze::open_existing_read_only(
            binding.repository_id().clone(),
            &kin_db::LocalFileBackend::new(restored.join("kindb")),
        )
        .unwrap();
        assert_eq!(frozen.authority().snapshot().version, 13);
        assert_eq!(
            frozen.authority().snapshot().repository_authority,
            snapshot.repository_authority
        );
        assert_eq!(inventory(&aged).unwrap(), before);
    }

    #[tokio::test]
    async fn command_restores_only_into_an_absent_kin_directory() {
        let cwd = std::env::current_dir().unwrap();
        let scratch = tempfile::Builder::new()
            .prefix(".recovery-cli-test-")
            .tempdir_in(&cwd)
            .unwrap();
        let (source, _) = fixture(scratch.path());
        let marker = retain_installed_authority_marker(&source);
        let before = inventory(&source).unwrap();
        let backup = scratch.path().join("backup");
        super::super::backup::create_carrier_at(
            &kin_core::KinLayout::new(source.clone()),
            backup.strip_prefix(&cwd).unwrap(),
        )
        .unwrap();
        assert_eq!(inventory(&source).unwrap(), before);
        assert!(marker.exists());
        let working = scratch.path().join("working");
        fs::create_dir(&working).unwrap();
        let destination = working.join(".kin");
        super::super::backup::restore_carrier(
            backup.strip_prefix(&cwd).unwrap().to_path_buf(),
            destination.strip_prefix(&cwd).unwrap().to_path_buf(),
        )
        .await
        .unwrap();
        assert_eq!(
            inventory(&source).unwrap(),
            inventory(&destination).unwrap()
        );
        assert!(
            super::super::backup::restore_carrier(backup.clone(), destination.clone())
                .await
                .is_err()
        );
        assert!(
            super::super::backup::restore_carrier(backup, working.join("not-kin"))
                .await
                .is_err()
        );
    }

    #[test]
    fn failed_backup_preserves_corrupt_source_and_publishes_nothing() {
        let scratch = scratch();
        let (source, manifest) = fixture(scratch.path());
        fs::write(
            kin_core::kindb_namespace_in(&source.join("kindb"), &manifest.repository_id)
                .join("authority.json"),
            b"truncated",
        )
        .unwrap();
        let before = inventory(&source).unwrap();
        let backup = scratch.path().join("backup");
        assert!(super::super::backup::create_carrier_at(
            &kin_core::KinLayout::new(source.clone()),
            &backup
        )
        .is_err());
        assert_eq!(inventory(&source).unwrap(), before);
        assert!(!backup.exists());
    }

    #[test]
    fn unsupported_layouts_remain_intact_without_a_partial_backup() {
        for version in [1, 99] {
            let scratch = scratch();
            let (source, _) = fixture(scratch.path());
            fs::write(source.join("version"), version.to_string()).unwrap();
            let before = inventory(&source).unwrap();
            let backup = scratch.path().join("backup");
            assert!(super::super::backup::create_carrier_at(
                &kin_core::KinLayout::new(source.clone()),
                &backup
            )
            .is_err());
            assert_eq!(inventory(&source).unwrap(), before);
            assert!(!backup.exists());
        }
    }

    #[test]
    fn corrupt_and_incomplete_carriers_leave_destination_absent() {
        for victim in ["COMPLETE", "manifest.json", "payload/specs/intent.json"] {
            let scratch = scratch();
            let (source, manifest) = fixture(scratch.path());
            let before = inventory(&source).unwrap();
            let backup = scratch.path().join("backup");
            publish(&source, &backup, manifest).unwrap();
            validate(&backup).unwrap();
            fs::write(backup.join(victim), b"truncated").unwrap();
            let destination = scratch.path().join("restored");
            assert!(restore(&backup, &destination, |_, _| Ok(())).is_err());
            assert!(!destination.exists());
            assert_eq!(inventory(&source).unwrap(), before);
        }
    }

    #[test]
    fn failed_validation_and_destination_race_preserve_existing_state() {
        let scratch = scratch();
        let (source, manifest) = fixture(scratch.path());
        let backup = scratch.path().join("backup");
        publish(&source, &backup, manifest).unwrap();
        let destination = scratch.path().join("restored");
        assert!(restore(&backup, &destination, |_, _| bail!(
            "invalid native authority"
        ))
        .is_err());
        assert!(!destination.exists());
        assert!(restore(&backup, &destination, |_, _| {
            fs::create_dir(&destination)?;
            fs::write(destination.join("sentinel"), b"keep")?;
            Ok(())
        })
        .is_err());
        assert_eq!(fs::read(destination.join("sentinel")).unwrap(), b"keep");
    }

    #[test]
    fn displaced_parent_or_payload_cannot_publish_unverified_state() {
        for replace_parent in [false, true] {
            let scratch = scratch();
            let (source, manifest) = fixture(scratch.path());
            let backup = scratch.path().join("backup");
            publish(&source, &backup, manifest).unwrap();
            let working = scratch.path().join("working");
            fs::create_dir(&working).unwrap();
            let destination = working.join(".kin");
            let moved = scratch.path().join("moved-working");
            assert!(restore(&backup, &destination, |payload, _| {
                if replace_parent {
                    fs::rename(&working, &moved)?;
                    fs::create_dir(&working)?;
                } else {
                    fs::rename(payload, payload.with_file_name("displaced"))?;
                    fs::create_dir(payload)?;
                    fs::write(payload.join("unverified"), b"must not publish")?;
                }
                Ok(())
            })
            .is_err());
            assert!(!destination.exists());
            assert!(!moved.join(".kin").exists());
            validate(&backup).unwrap();
        }
    }

    #[test]
    fn in_place_metadata_changes_cannot_escape_final_validation() {
        let scratch = scratch();
        let (source, manifest) = fixture(scratch.path());
        let backup = scratch.path().join("backup");
        publish(&source, &backup, manifest).unwrap();
        let destination = scratch.path().join("restored");
        let error = restore(&backup, &destination, |payload, _| {
            fs::write(payload.join("specs/intent.json"), b"truncated")?;
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("payload changed"));
        assert!(!destination.exists());
        validate(&backup).unwrap();
    }

    #[test]
    fn backup_cannot_complete_with_roots_from_another_generation() {
        let scratch = scratch();
        let (source, mut manifest) = fixture(scratch.path());
        let before = inventory(&source).unwrap();
        manifest.roots.generation += 1;
        let backup = scratch.path().join("backup");
        assert!(publish(&source, &backup, manifest).is_err());
        assert!(!backup.exists());
        assert_eq!(inventory(&source).unwrap(), before);
    }

    #[test]
    fn rehashed_manifest_cannot_change_repository_identity() {
        let scratch = scratch();
        let (source, manifest) = fixture(scratch.path());
        let backup = scratch.path().join("backup");
        publish(&source, &backup, manifest).unwrap();
        let mut manifest = validate(&backup).unwrap();
        manifest.repository_id = "another-repository".into();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(backup.join("manifest.json"), &bytes).unwrap();
        fs::write(backup.join("COMPLETE"), hex::encode(Sha256::digest(&bytes))).unwrap();
        assert!(validate(&backup)
            .unwrap_err()
            .to_string()
            .contains("identity mismatch"));
    }

    #[test]
    fn rehashed_wrong_roots_cannot_publish_a_restore() {
        let scratch = scratch();
        let (source, manifest) = fixture(scratch.path());
        let backup = scratch.path().join("backup");
        publish(&source, &backup, manifest).unwrap();
        let mut manifest = validate(&backup).unwrap();
        manifest.roots.generation += 1;
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(backup.join("manifest.json"), &bytes).unwrap();
        fs::write(backup.join("COMPLETE"), hex::encode(Sha256::digest(&bytes))).unwrap();
        validate(&backup).unwrap();
        assert!(inspect(&backup).is_err());
        let before = inventory(&backup).unwrap();
        let destination = scratch.path().join("restored");
        let error = restore(&backup, &destination, |_, _| Ok(())).unwrap_err();
        assert!(error
            .to_string()
            .contains("validate restored native authority"));
        assert!(!destination.exists());
        assert_eq!(inventory(&backup).unwrap(), before);
    }

    #[test]
    fn payload_omission_and_addition_are_both_rejected() {
        let scratch = scratch();
        let (source, manifest) = fixture(scratch.path());
        let backup = scratch.path().join("backup");
        publish(&source, &backup, manifest).unwrap();
        let victim = backup.join("payload/specs/intent.json");
        let bytes = fs::read(&victim).unwrap();
        fs::remove_file(&victim).unwrap();
        assert!(validate(&backup).is_err());
        fs::write(&victim, bytes).unwrap();
        validate(&backup).unwrap();
        fs::write(backup.join("payload/unexpected"), b"extra").unwrap();
        assert!(validate(&backup).is_err());
    }

    #[test]
    fn native_history_refs_reviews_and_audit_survive_restore() {
        use kin_model::*;
        let scratch = scratch();
        let (source, mut manifest) = fixture(scratch.path());
        let layout = kin_core::KinLayout::new(source.clone());
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout).unwrap();
        let manager = binding.open_manager().unwrap();
        let body = b"native bytes absent from Git";
        let digest = kin_blobs::digest(body);
        manager.save_source_blob(digest, body).unwrap();
        let make_change = |parents: Vec<SemanticChangeId>, message: &str| {
            let root = parents.is_empty();
            let mut change = SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
                origin: ChangeOrigin::Native,
                parents,
                timestamp: Timestamp::now(),
                author: AuthorId::new("Recovery Test <recovery@example.invalid>"),
                message: message.into(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas: vec![],
                admission_policy_delta: root
                    .then(|| AdmissionPolicyDelta::initialize(SharedAdmissionPolicy::empty(0))),
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                external_reference_deltas: vec![],
            };
            change.id = kin_core::compute_semantic_change_id(&change).unwrap();
            change
        };
        let first = make_change(vec![], "first native change");
        let mut second = make_change(vec![first.id], "second native change");
        second.tree_deltas.push(TreeDelta::Added {
            artifact_id: ArtifactId::new(),
            new: LocatedEntry::new(
                RepoPath::from_utf8("native.txt").unwrap(),
                TreeEntry::blob(digest, false),
            ),
        });
        second.id = kin_core::compute_semantic_change_id(&second).unwrap();
        let review = Review {
            review_id: ReviewId(uuid::Uuid::new_v4()),
            title: "preserve native review".into(),
            base_ref: "main".into(),
            head_ref: "native".into(),
            state: ReviewDecisionState::Pending,
            completion: ReviewCompletionState::InReview,
            created_by: IdentityRef::human("recovery-test"),
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
            scopes: vec![],
        };
        let roots = manager.read_authority().roots().clone();
        let workspace = manager.read_authority().metadata().workspaces[0].clone();
        let next_tree = workspace.tree.apply(&second.tree_deltas).unwrap();
        let next_tree_hash = compute_resolved_tree_hash(&next_tree).unwrap();
        let actor = Actor {
            actor_id: ActorId::new(),
            kind: ActorKind::Human,
            display_name: "Recovery Test".into(),
            external_refs: vec![],
        };
        let audit = AuditEvent {
            event_id: AuditEventId::new(),
            actor_id: actor.actor_id,
            action: "review.create".into(),
            target_scope: None,
            timestamp: Timestamp::now(),
            details: Some("native recovery fixture".into()),
        };
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: binding.repository_id().clone(),
            expected_generation: roots.generation,
            expected_roots: roots,
            actor: second.author.clone(),
            reason: "record native recovery fixture".into(),
            external_objects: vec![],
            git_authority_delta: None,
            changes: vec![first.clone(), second.clone()],
            aliases: vec![],
            ref_mutations: vec![RefMutation {
                name: RefName::branch(b"native").unwrap(),
                expected: RefExpectation::MustNotExist,
                new_target: Some(RefTarget::change(second.id)),
                policy: RefUpdatePolicy::FastForwardOnly,
            }],
            default_ref_mutation: None,
            workspace_mutation: Some(WorkspaceMutation {
                workspace_id: workspace.workspace_id,
                expected: WorkspaceExpectation::MustEqual {
                    generation: workspace.generation,
                    head: workspace.head.clone(),
                    base_target: workspace.base_target.clone(),
                    base_tree_hash: workspace.base_tree_hash,
                    tree_hash: workspace.tree_hash,
                    semantic_overlay_hash: workspace.semantic_overlay_hash,
                    admission_policy: workspace.admission_policy.clone(),
                },
                new_generation: workspace.generation + 1,
                new_head: WorkspaceHead::Symbolic {
                    target: RefName::branch(b"native").unwrap(),
                },
                new_base_target: Some(RefTarget::change(second.id)),
                new_base_tree_hash: Some(next_tree_hash),
                tree_deltas: second.tree_deltas.clone(),
                new_tree_hash: next_tree_hash,
                semantic_delta: WorkspaceSemanticDelta::default(),
                new_shared_admission_policy: workspace.shared_admission_policy.clone(),
                new_admission_policy: workspace.admission_policy.clone(),
            }),
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
            collaboration_delta: Some(CollaborationDelta {
                reviews: vec![Keyed::new(review.review_id, review.clone())],
                actors: vec![Keyed::new(actor.actor_id, actor)],
                audit_events: vec![audit],
                ..Default::default()
            }),
        };
        manager.commit_repository_transaction(transaction).unwrap();
        manifest.roots = manager.read_authority().roots().clone();
        let frozen = manager.freeze_current_authority(&manifest.roots).unwrap();
        let expected = frozen.authority().snapshot().clone();
        let backup = scratch.path().join("backup");
        publish(&source, &backup, manifest).unwrap();
        drop(frozen);
        let destination = scratch.path().join("restored");
        restore(&backup, &destination, |path, manifest| {
            let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(
                &kin_core::KinLayout::new(path.to_path_buf()),
            )?;
            let manager = binding.open_manager()?;
            let frozen = manager.freeze_current_authority(&manifest.roots)?;
            let snapshot = frozen.authority().snapshot();
            assert_eq!(
                snapshot.changes.get(&second.id).unwrap().parents,
                vec![first.id]
            );
            assert_eq!(snapshot.changes.len(), expected.changes.len());
            for (id, change) in expected.changes.iter() {
                assert_eq!(snapshot.changes.get(id), Some(change));
            }
            assert_eq!(snapshot.repository_authority, expected.repository_authority);
            assert_eq!(snapshot.reviews, expected.reviews);
            assert_eq!(snapshot.actors, expected.actors);
            assert_eq!(snapshot.audit_events, expected.audit_events);
            assert_eq!(frozen.roots(), &manifest.roots);
            assert_eq!(
                frozen
                    .authority()
                    .resolve_ref_target(&RefName::branch(b"native")?)?,
                Some(RefTarget::change(second.id))
            );
            let restored_workspace = &frozen.authority().metadata().workspaces[0];
            assert_eq!(restored_workspace.workspace_id, workspace.workspace_id);
            assert_eq!(restored_workspace.generation, workspace.generation + 1);
            assert_eq!(restored_workspace.tree_hash, next_tree_hash);
            drop(frozen);
            assert_eq!(manager.load_source_blob(digest)?, Some(body.to_vec()));
            Ok(())
        })
        .unwrap();
        let blob_path = inventory(&source)
            .unwrap()
            .keys()
            .find(|name| name.contains("/source-blobs/"))
            .expect("referenced content is present")
            .clone();
        fs::write(source.join(blob_path), b"corrupt native content").unwrap();
        let marker = retain_installed_authority_marker(&source);
        let corrupt_source = inventory(&source).unwrap();
        let refused = scratch.path().join("refused-backup");
        assert!(super::super::backup::create_carrier_at(&layout, &refused).is_err());
        assert_eq!(inventory(&source).unwrap(), corrupt_source);
        assert!(marker.exists());
        assert!(!refused.exists());
    }

    #[cfg(unix)]
    #[test]
    fn substituted_directory_cannot_escape_the_source() {
        let scratch = scratch();
        let source = scratch.path().join("source");
        let outside = scratch.path().join("outside");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret"), b"outside").unwrap();
        std::os::unix::fs::symlink(&outside, source.join("subdir")).unwrap();
        assert!(open_regular(&source.join("subdir/secret")).is_err());
        assert!(inventory(&source).is_err());
        assert_eq!(fs::read(outside.join("secret")).unwrap(), b"outside");
    }

    #[test]
    fn bounded_inputs_and_nested_restore_are_rejected() {
        let scratch = scratch();
        let oversized = scratch.path().join("oversized");
        fs::write(&oversized, [0u8; 66]).unwrap();
        assert!(read_bounded(&oversized, 64).is_err());
        assert_eq!(read_bounded(&oversized, 66).unwrap().len(), 66);
        let (source, manifest) = fixture(scratch.path());
        let backup = scratch.path().join("backup");
        publish(&source, &backup, manifest).unwrap();
        let before = inventory(&backup).unwrap();
        let nested = backup.join("restored");
        assert!(restore(&backup, &nested, |_, _| Ok(())).is_err());
        assert!(!nested.exists());
        assert_eq!(inventory(&backup).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn payload_symlinks_are_rejected_without_reading_the_target() {
        let scratch = scratch();
        let (source, manifest) = fixture(scratch.path());
        let outside = scratch.path().join("outside");
        fs::write(&outside, b"untouched").unwrap();
        std::os::unix::fs::symlink(&outside, source.join("link")).unwrap();
        let backup = scratch.path().join("backup");
        assert!(publish(&source, &backup, manifest).is_err());
        assert!(!backup.exists());
        assert_eq!(fs::read(&outside).unwrap(), b"untouched");
    }
}
