// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-repo Kin registry at `<managed Kin home>/registry.toml`.
//!
//! Lets MCP servers and cross-repo queries discover all Kin repositories on
//! disk regardless of where they live. The file is store state, so `KIN_HOME`
//! bounds it like the rest of the store: see [`registry_path`].

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
#[cfg(not(unix))]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
#[derive(Default)]
struct RegistryProcessGates {
    active: std::collections::HashSet<RegistryProcessKey>,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RegistryProcessKey {
    parent: FileIdentity,
    lock_authority_name: Vec<u8>,
}

#[cfg(unix)]
static REGISTRY_PROCESS_GATES: std::sync::OnceLock<(
    std::sync::Mutex<RegistryProcessGates>,
    std::sync::Condvar,
)> = std::sync::OnceLock::new();

#[cfg(unix)]
struct RegistryProcessGuard {
    key: RegistryProcessKey,
}

#[cfg(unix)]
impl Drop for RegistryProcessGuard {
    fn drop(&mut self) {
        let (state, changed) = REGISTRY_PROCESS_GATES
            .get()
            .expect("registry process gate was initialized before guard creation");
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active.remove(&self.key);
        changed.notify_all();
    }
}

/// `flock` semantics for separately-opened descriptors differ across Unix
/// kernels when contenders are threads in one process. Keep a path-keyed local
/// gate around the preflight + OS-lock transaction so an atomic rename cannot
/// unlink a sibling thread's just-opened registry descriptor (`st_nlink == 0`).
/// Different registry authorities remain independent; the durable lock file
/// remains the cross-process authority. Keying on the opened parent identity
/// plus the collision-normalized lock name collapses both prefix aliases such
/// as `/tmp` and `/private/tmp` and case aliases on default macOS filesystems.
#[cfg(unix)]
fn lock_registry_process(path: &Path) -> std::io::Result<RegistryProcessGuard> {
    let anchor = prepare_anchor(path).map_err(|error| {
        std::io::Error::other(format!("failed to anchor registry process lock: {error}"))
    })?;
    let parent_stat = stat_file(&anchor.parent)?;
    let key = RegistryProcessKey {
        parent: FileIdentity {
            device: parent_stat.st_dev as u64,
            inode: parent_stat.st_ino as u64,
        },
        lock_authority_name: collision_normalized_authority_name(&anchor.lock_name),
    };
    let (state, changed) = REGISTRY_PROCESS_GATES.get_or_init(|| {
        (
            std::sync::Mutex::new(RegistryProcessGates::default()),
            std::sync::Condvar::new(),
        )
    });
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while state.active.contains(&key) {
        state = changed
            .wait(state)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    state.active.insert(key.clone());
    Ok(RegistryProcessGuard { key })
}

/// Read-only classification of one local registry-authority path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryAuthorityState {
    /// A regular, single-link, current-user-owned file with mode 0600.
    Secure,
    /// The path does not exist yet. Kin will create it privately when needed.
    Absent,
    /// The object is structurally safe, but its mode is not exactly 0600.
    RepairablePermissions,
    /// The object or its parent cannot be trusted or repaired automatically.
    Unsafe,
    /// Unix ownership and mode checks do not apply on this platform.
    Unsupported,
}

/// One content-free registry-authority check.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RegistryAuthorityCheck {
    pub label: String,
    pub path: PathBuf,
    pub state: RegistryAuthorityState,
    pub detail: String,
}

/// Content-free authority report shared by doctor, setup/install, and update.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RegistryAuthorityReport {
    pub checks: Vec<RegistryAuthorityCheck>,
}

impl RegistryAuthorityReport {
    /// Missing authority files are safe: Kin creates them at 0600 on first use.
    pub fn is_secure(&self) -> bool {
        self.checks.iter().all(|check| {
            matches!(
                check.state,
                RegistryAuthorityState::Secure
                    | RegistryAuthorityState::Absent
                    | RegistryAuthorityState::Unsupported
            )
        })
    }

    pub fn has_repairable_permissions(&self) -> bool {
        self.checks
            .iter()
            .any(|check| check.state == RegistryAuthorityState::RepairablePermissions)
    }

    pub fn has_unsafe_object(&self) -> bool {
        self.checks
            .iter()
            .any(|check| check.state == RegistryAuthorityState::Unsafe)
    }

    pub fn failure_summary(&self) -> String {
        self.checks
            .iter()
            .filter(|check| {
                matches!(
                    check.state,
                    RegistryAuthorityState::RepairablePermissions | RegistryAuthorityState::Unsafe
                )
            })
            .map(|check| format!("{}: {}", check.path.display(), check.detail))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct KinRegistry {
    pub repos: Vec<RegisteredRepo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredRepo {
    pub id: String,
    pub path: PathBuf,
    pub entities: usize,
    pub last_commit: String, // ISO 8601
    #[serde(default)]
    pub dependencies: Vec<crate::dependencies::RepoDependency>,
}

impl KinRegistry {
    /// Load from [`registry_path`], or return empty if it doesn't exist.
    ///
    /// Acquires a shared (read) lock to prevent reading a partially-written file.
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        Self::load_from(&registry_path())
    }

    /// Load from a specific path (for testing).
    ///
    /// Acquires a shared (read) lock on the corresponding `.lock` file.
    pub fn load_from(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(unix)]
        {
            load_from_unix(path)
        }
        #[cfg(not(unix))]
        {
            if !path.exists() {
                return Ok(Self::default());
            }
            let lock_path = path.with_extension("lock");
            let lock_file = open_private_lock_file(&lock_path)?;
            lock_file.lock_shared()?;
            let content = std::fs::read_to_string(path)?;
            Ok(toml::from_str(&content)?)
        }
    }

    /// Save to [`registry_path`].
    ///
    /// Acquires an exclusive lock, writes atomically (tmp → rename).
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.save_to(&registry_path())
    }

    /// Save to a specific path (for testing).
    ///
    /// Acquires an exclusive lock, writes atomically (tmp → rename)
    /// so concurrent readers never see a partial file.
    pub fn save_to(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(unix)]
        {
            save_to_unix(self, path)
        }
        #[cfg(not(unix))]
        {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent)?;
            }
            let lock_path = path.with_extension("lock");
            let lock_file = open_private_lock_file(&lock_path)?;
            lock_file.lock_exclusive()?;
            let contents = toml::to_string_pretty(self)?;
            write_registry_atomically(path, contents.as_bytes())?;
            Ok(())
        }
    }

    /// Update [`registry_path`] under one exclusive read-modify-write lock.
    ///
    /// Registry writers must use this API instead of a separate `load` followed
    /// by `save`; keeping the lock across the caller's mutation prevents one
    /// concurrent writer from silently replacing another writer's update.
    pub fn update<T>(mutate: impl FnOnce(&mut Self) -> T) -> Result<T, Box<dyn std::error::Error>> {
        Self::update_at(&registry_path(), mutate)
    }

    /// Update a specific registry path under one exclusive read-modify-write lock.
    pub fn update_at<T>(
        path: &Path,
        mutate: impl FnOnce(&mut Self) -> T,
    ) -> Result<T, Box<dyn std::error::Error>> {
        #[cfg(unix)]
        {
            update_at_unix(path, mutate)
        }
        #[cfg(not(unix))]
        {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent)?;
            }
            let lock_path = path.with_extension("lock");
            let lock_file = open_private_lock_file(&lock_path)?;
            lock_file.lock_exclusive()?;
            let mut registry = if path.exists() {
                toml::from_str(&std::fs::read_to_string(path)?)?
            } else {
                Self::default()
            };
            let result = mutate(&mut registry);
            let contents = toml::to_string_pretty(&registry)?;
            write_registry_atomically(path, contents.as_bytes())?;
            Ok(result)
        }
    }

    /// Register or update a repo entry.
    ///
    /// Automatically detects cross-repo dependencies from manifest files
    /// (`Cargo.toml`, `package.json`, `go.mod`) located at `path`.
    ///
    /// If `remote_repo_ids` is provided, dependency detection also matches
    /// against repos known to the remote spine (KinLab). This enables
    /// detecting dependencies on repos the user doesn't have locally.
    pub fn upsert(&mut self, id: String, path: PathBuf, entities: usize) {
        self.upsert_with_remote(id, path, entities, &[]);
    }

    /// Register or update, with additional remote repo IDs for dependency matching.
    pub fn upsert_with_remote(
        &mut self,
        id: String,
        path: PathBuf,
        entities: usize,
        remote_repo_ids: &[String],
    ) {
        let now = chrono::Utc::now().to_rfc3339();
        // Combine local + remote repo IDs for dependency detection.
        let mut all_ids: Vec<String> = self.repos.iter().map(|r| r.id.clone()).collect();
        for remote_id in remote_repo_ids {
            if !all_ids.contains(remote_id) {
                all_ids.push(remote_id.clone());
            }
        }
        let deps = crate::dependencies::detect_dependencies_with_registry(&path, &all_ids);
        if let Some(existing) = self.repos.iter_mut().find(|r| r.id == id) {
            existing.path = path;
            existing.entities = entities;
            existing.last_commit = now;
            existing.dependencies = deps;
        } else {
            self.repos.push(RegisteredRepo {
                id,
                path,
                entities,
                last_commit: now,
                dependencies: deps,
            });
        }
    }

    /// Resolve the remote spine URL from config, if any.
    ///
    /// Checks (in order):
    /// 1. `KIN_REMOTE_URL` env var
    /// 2. `~/.kin/remote.toml` `url = "..."` field
    ///
    /// Returns None if no remote is configured.
    pub fn remote_url() -> Option<String> {
        if let Ok(url) = std::env::var("KIN_REMOTE_URL") {
            if !url.is_empty() {
                return Some(url);
            }
        }
        let config_path = Self::kin_dir().join("remote.toml");
        let content = std::fs::read_to_string(&config_path).ok()?;
        let parsed: toml::Table = content.parse().ok()?;
        parsed
            .get("url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Parse a JSON response body into a list of repo IDs.
    /// Accepts either `[{"id": "repo-a"}, ...]` or `["repo-a", ...]`.
    pub fn parse_repo_catalog(body: &str) -> Vec<String> {
        // Try array of objects with "id" field first.
        if let Ok(repos) = serde_json::from_str::<Vec<serde_json::Value>>(body) {
            let ids: Vec<String> = repos
                .iter()
                .filter_map(|r| r.get("id").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
                .collect();
            if !ids.is_empty() {
                return ids;
            }
        }
        // Fallback: simple string array.
        serde_json::from_str::<Vec<String>>(body).unwrap_or_default()
    }

    fn kin_dir() -> PathBuf {
        directories::BaseDirs::new()
            .map(|b| b.home_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".kin")
    }

    /// Build the cross-repo dependency graph: repo ID → [provider repo IDs].
    pub fn dependency_graph(&self) -> HashMap<String, Vec<String>> {
        crate::dependencies::dependency_graph(&self.repos)
    }

    /// Remove entries whose paths no longer contain a `.kin/` directory.
    pub fn clean(&mut self) -> usize {
        let before = self.repos.len();
        self.repos.retain(|r| r.path.join(".kin").exists());
        before - self.repos.len()
    }

    /// Get all registered repo paths.
    pub fn repo_paths(&self) -> Vec<&Path> {
        self.repos.iter().map(|r| r.path.as_path()).collect()
    }
}

/// Inspect the default local registry authority without reading file contents.
pub fn inspect_registry_authority() -> RegistryAuthorityReport {
    inspect_registry_authority_at(&registry_path())
}

/// Inspect a registry authority path without following links or reading contents.
pub fn inspect_registry_authority_at(path: &Path) -> RegistryAuthorityReport {
    #[cfg(unix)]
    {
        inspect_registry_authority_at_unix(path)
    }
    #[cfg(not(unix))]
    {
        RegistryAuthorityReport {
            checks: vec![RegistryAuthorityCheck {
                label: "registry authority".to_string(),
                path: path.to_path_buf(),
                state: RegistryAuthorityState::Unsupported,
                detail: "Unix ownership and mode checks do not apply on this platform".to_string(),
            }],
        }
    }
}

/// Refuse an operation when existing registry authority is not trustworthy.
pub fn require_registry_authority_secure() -> Result<(), Box<dyn std::error::Error>> {
    require_registry_authority_secure_at(&registry_path())
}

pub fn require_registry_authority_secure_at(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut report = inspect_registry_authority_at(path);
    // A newly-created lock is requested at 0600 but the process umask can make
    // its public mode temporarily differ before the creator's descriptor-
    // anchored fchmod. A sibling initializer can likewise observe a new parent
    // before its descriptor-anchored chmod. Never repair or trust either state:
    // only wait briefly and re-inspect for convergence.
    for _ in 0..50 {
        if report.is_secure() {
            return Ok(());
        }
        if !report.is_lock_creation_window_candidate()
            && !report.is_parent_creation_window_candidate(path)
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
        report = inspect_registry_authority_at(path);
    }
    if report.is_secure() {
        return Ok(());
    }
    let remediation = if report.has_unsafe_object() {
        "Refusing to trust or replace it. Move the unsafe object aside after inspecting it, then retry."
    } else {
        "Run `kin doctor --fix` to authorize a local permission-only repair, then retry."
    };
    Err(Box::new(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "unsafe local registry authority: {} {remediation}",
            report.failure_summary()
        ),
    )))
}

impl RegistryAuthorityReport {
    #[cfg(unix)]
    fn is_lock_creation_window_candidate(&self) -> bool {
        let mut saw_lock = false;
        self.checks.iter().all(|check| match check.state {
            RegistryAuthorityState::Secure | RegistryAuthorityState::Absent => true,
            RegistryAuthorityState::RepairablePermissions if check.label == "registry lock" => {
                saw_lock = true;
                true
            }
            _ => false,
        }) && saw_lock
    }

    #[cfg(not(unix))]
    fn is_lock_creation_window_candidate(&self) -> bool {
        false
    }

    #[cfg(unix)]
    fn is_parent_creation_window_candidate(&self, path: &Path) -> bool {
        if self.checks.len() != 1
            || self.checks[0].label != "registry authority"
            || self.checks[0].state != RegistryAuthorityState::Unsafe
        {
            return false;
        }
        match RegistryAnchor::open(path) {
            Ok(_) => true,
            Err(err) => matches!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
            ),
        }
    }

    #[cfg(not(unix))]
    fn is_parent_creation_window_candidate(&self, _path: &Path) -> bool {
        false
    }
}

/// Explicitly repair mode bits on structurally safe registry-authority files.
///
/// This never reads or replaces contents and refuses symlinks, non-regular
/// files, wrong ownership, hard links, unsafe parents, and path collisions.
pub fn repair_registry_authority_permissions() -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    repair_registry_authority_permissions_at(&registry_path())
}

pub fn repair_registry_authority_permissions_at(
    path: &Path,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        repair_registry_authority_permissions_at_unix(path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "registry permission repair is only supported on Unix",
        )))
    }
}

/// Create missing Unix registry authority files without replacing existing data.
///
/// This is intended for fresh/upgrade installers. Existing authority must
/// already be secure (or explicitly repaired first); existing registry bytes
/// are never rewritten merely to create a missing companion file.
pub fn initialize_registry_authority() -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    initialize_registry_authority_at(&registry_path())
}

pub fn initialize_registry_authority_at(
    path: &Path,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        initialize_registry_authority_at_unix(path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(Vec::new())
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
struct RegistryAnchor {
    parent: File,
    registry_name: std::ffi::OsString,
    lock_name: std::ffi::OsString,
    legacy_tmp_name: std::ffi::OsString,
}

#[cfg(unix)]
impl RegistryAnchor {
    fn open(path: &Path) -> std::io::Result<Self> {
        use std::os::fd::FromRawFd;
        use std::os::unix::ffi::OsStrExt;

        let parent_path = normalized_parent(path);
        let parent_c =
            std::ffi::CString::new(parent_path.as_os_str().as_bytes()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "registry parent path contains a NUL byte",
                )
            })?;
        // SAFETY: `parent_c` is NUL-terminated and remains alive for the call.
        let fd = unsafe {
            libc::open(
                parent_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` was returned by `open` and ownership transfers to `File`.
        let parent = unsafe { File::from_raw_fd(fd) };
        Self::from_parent(path, parent)
    }

    fn from_parent(path: &Path, parent: File) -> std::io::Result<Self> {
        let registry_name = path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "registry path has no filename",
                )
            })?
            .to_os_string();
        let lock_name = path
            .with_extension("lock")
            .file_name()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "registry lock path has no filename",
                )
            })?
            .to_os_string();
        let legacy_tmp_name = path
            .with_extension("tmp")
            .file_name()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "legacy registry temp path has no filename",
                )
            })?
            .to_os_string();

        validate_authority_filename(&registry_name)?;

        if authority_names_collide(&registry_name, &lock_name)
            || authority_names_collide(&registry_name, &legacy_tmp_name)
            || authority_names_collide(&lock_name, &legacy_tmp_name)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "registry path collides with its reserved .lock or .tmp authority path",
            ));
        }
        validate_parent(&parent)?;

        Ok(Self {
            parent,
            registry_name,
            lock_name,
            legacy_tmp_name,
        })
    }
}

#[cfg(unix)]
fn authority_names_collide(a: &std::ffi::OsStr, b: &std::ffi::OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;

    // Conservatively reject ASCII case variants on every Unix platform so a
    // case-insensitive filesystem cannot alias registry data with lock/temp.
    a.as_bytes().eq_ignore_ascii_case(b.as_bytes())
}

#[cfg(unix)]
fn validate_authority_filename(name: &std::ffi::OsStr) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    // Filesystems such as default macOS APFS apply Unicode normalization and
    // case folding that cannot be reproduced from raw OsStr bytes. In
    // particular, `registry.locK` aliases `registry.lock`, despite the two
    // names being neither byte-equal nor ASCII-case-equal. Restrict only the
    // authority filename (parent paths remain fully Unicode-capable) so the
    // data, lock, and reserved temp names can never alias unexpectedly.
    if !name.as_bytes().is_ascii() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "registry authority filename must be ASCII to avoid filesystem case-fold aliases",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn collision_normalized_authority_name(name: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;

    name.as_bytes().iter().map(u8::to_ascii_lowercase).collect()
}

#[cfg(unix)]
fn normalized_parent(path: &Path) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

#[cfg(unix)]
const REGISTRY_CREATE_RACE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[cfg(unix)]
fn is_transient_traversal_refusal(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::EACCES)
}

#[cfg(unix)]
fn prepare_anchor(path: &Path) -> Result<RegistryAnchor, Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + REGISTRY_CREATE_RACE_TIMEOUT;
    loop {
        let refusal = match RegistryAnchor::open(path) {
            Ok(anchor) => return Ok(anchor),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                match create_private_dir_all(&normalized_parent(path)) {
                    Ok(parent) => return Ok(RegistryAnchor::from_parent(path, parent)?),
                    Err(err) if is_transient_traversal_refusal(&err) => err,
                    Err(err) => return Err(Box::new(err)),
                }
            }
            Err(err) if is_transient_traversal_refusal(&err) => err,
            Err(err) => return Err(Box::new(err)),
        };
        if std::time::Instant::now() >= deadline {
            return Err(Box::new(refusal));
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

#[cfg(unix)]
fn create_private_dir_all(path: &Path) -> std::io::Result<File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    // Always resolve the final requested component through the retained
    // ancestor fd. If another process creates it after our caller observed
    // ENOENT, this avoids re-resolving the mutable path or following a link.
    let mut ancestor = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let mut missing = vec![path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "registry parent has no creatable directory component",
            )
        })?
        .to_os_string()];
    loop {
        match std::fs::symlink_metadata(&ancestor) {
            Ok(_) => break,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let name = ancestor.file_name().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "registry parent has no creatable directory component",
                    )
                })?;
                missing.push(name.to_os_string());
                ancestor = ancestor
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf();
            }
            Err(err) => return Err(err),
        }
    }

    let canonical_ancestor = ancestor.canonicalize()?;
    let mut current = File::open(&canonical_ancestor)?;
    validate_parent(&current).map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!(
                "refusing to create registry directories below {}: {err}",
                canonical_ancestor.display()
            ),
        )
    })?;

    for name in missing.into_iter().rev() {
        let name_c = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "registry directory component contains a NUL byte",
            )
        })?;
        // SAFETY: the retained parent fd and NUL-terminated component are valid.
        let created = if unsafe { libc::mkdirat(current.as_raw_fd(), name_c.as_ptr(), 0o700) } == 0
        {
            true
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                false
            } else {
                return Err(err);
            }
        };

        if created {
            // The retained parent is current-user-owned and not writable by
            // other users. AT_SYMLINK_NOFOLLOW keeps the chmod anchored to the
            // directory entry this operation created even under umask 0777.
            // SAFETY: the dirfd/name are valid and mode has no invalid bits.
            if unsafe {
                libc::fchmodat(
                    current.as_raw_fd(),
                    name_c.as_ptr(),
                    0o700,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }

        let next = open_directory_after_create_race(&current, &name_c)?;
        validate_parent(&next)?;
        if created && stat_file(&next)?.st_mode & 0o7777 != 0o700 {
            return Err(registry_security_error(
                "new registry directory did not reach mode 0700",
            ));
        }
        current = next;
    }
    Ok(current)
}

#[cfg(unix)]
fn open_directory_after_create_race(parent: &File, name: &std::ffi::CStr) -> std::io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let deadline = std::time::Instant::now() + REGISTRY_CREATE_RACE_TIMEOUT;
    loop {
        // SAFETY: the retained parent fd and NUL-terminated name are valid.
        // O_NOFOLLOW prevents a raced symlink from becoming a creation anchor.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd >= 0 {
            // SAFETY: fd was returned by openat and ownership transfers to File.
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let err = std::io::Error::last_os_error();
        if !matches!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
        ) || std::time::Instant::now() >= deadline
        {
            return Err(err);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

#[cfg(unix)]
fn absent_authority_report(path: &Path) -> RegistryAuthorityReport {
    RegistryAuthorityReport {
        checks: vec![
            authority_check(
                "registry file",
                path.to_path_buf(),
                RegistryAuthorityState::Absent,
                "not created yet; Kin will create it with mode 0600",
            ),
            authority_check(
                "registry lock",
                path.with_extension("lock"),
                RegistryAuthorityState::Absent,
                "not created yet; Kin will create it with mode 0600",
            ),
        ],
    }
}

#[cfg(unix)]
fn authority_check(
    label: &str,
    path: PathBuf,
    state: RegistryAuthorityState,
    detail: impl Into<String>,
) -> RegistryAuthorityCheck {
    RegistryAuthorityCheck {
        label: label.to_string(),
        path,
        state,
        detail: detail.into(),
    }
}

#[cfg(unix)]
fn inspect_registry_authority_at_unix(path: &Path) -> RegistryAuthorityReport {
    let anchor = match RegistryAnchor::open(path) {
        Ok(anchor) => anchor,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return absent_authority_report(path);
        }
        Err(err) => {
            return RegistryAuthorityReport {
                checks: vec![authority_check(
                    "registry authority",
                    path.to_path_buf(),
                    RegistryAuthorityState::Unsafe,
                    err.to_string(),
                )],
            };
        }
    };

    let mut checks = vec![
        inspect_named_authority(
            &anchor,
            &anchor.registry_name,
            "registry file",
            path.to_path_buf(),
        ),
        inspect_named_authority(
            &anchor,
            &anchor.lock_name,
            "registry lock",
            path.with_extension("lock"),
        ),
    ];
    let legacy_tmp = inspect_named_authority(
        &anchor,
        &anchor.legacy_tmp_name,
        "legacy registry temp file",
        path.with_extension("tmp"),
    );
    if legacy_tmp.state != RegistryAuthorityState::Absent {
        checks.push(legacy_tmp);
    }
    RegistryAuthorityReport { checks }
}

#[cfg(unix)]
fn inspect_named_authority(
    anchor: &RegistryAnchor,
    name: &std::ffi::OsStr,
    label: &str,
    path: PathBuf,
) -> RegistryAuthorityCheck {
    let stat = match stat_at(anchor, name) {
        Ok(stat) => stat,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return authority_check(
                label,
                path,
                RegistryAuthorityState::Absent,
                "not created yet; Kin will create it with mode 0600",
            );
        }
        Err(err) => {
            return authority_check(
                label,
                path,
                RegistryAuthorityState::Unsafe,
                format!("could not inspect without following links: {err}"),
            );
        }
    };
    if let Err(err) = validate_regular_stat(&stat, label) {
        return authority_check(label, path, RegistryAuthorityState::Unsafe, err.to_string());
    }
    let mode = stat.st_mode & 0o7777;
    if mode != 0o600 {
        return authority_check(
            label,
            path,
            RegistryAuthorityState::RepairablePermissions,
            format!(
                "mode {mode:04o}; expected 0600. Contents were not read. Run `kin doctor --fix` to authorize repair"
            ),
        );
    }
    authority_check(
        label,
        path,
        RegistryAuthorityState::Secure,
        "regular, single-link, current-user-owned, mode 0600",
    )
}

#[cfg(unix)]
fn repair_registry_authority_permissions_at_unix(
    path: &Path,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let _process_guard = lock_registry_process(path)?;
    let anchor = match RegistryAnchor::open(path) {
        Ok(anchor) => anchor,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(Box::new(err)),
    };
    let report = inspect_registry_authority_at_unix(path);
    if report.has_unsafe_object() {
        return Err(Box::new(registry_security_error(format!(
            "permission repair refused: {}",
            report.failure_summary()
        ))));
    }

    let candidates = [
        (&anchor.registry_name, "registry file", path.to_path_buf()),
        (
            &anchor.lock_name,
            "registry lock",
            path.with_extension("lock"),
        ),
        (
            &anchor.legacy_tmp_name,
            "legacy registry temp file",
            path.with_extension("tmp"),
        ),
    ];
    let mut opened = Vec::new();
    for (name, label, candidate_path) in candidates {
        let file = match open_at(&anchor, name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(Box::new(err)),
        };
        let identity = validate_regular_file(&file, label)?;
        verify_named_structural_identity(&anchor, name, identity, label)?;
        opened.push((name.to_os_string(), label, candidate_path, file, identity));
    }

    let mut repaired = Vec::new();
    for (name, label, candidate_path, file, identity) in opened {
        if stat_file(&file)?.st_mode & 0o7777 != 0o600 {
            set_private_mode(&file)?;
            verify_named_identity(&anchor, &name, identity, label)?;
            repaired.push(candidate_path);
        }
    }
    Ok(repaired)
}

#[cfg(unix)]
fn initialize_registry_authority_at_unix(
    path: &Path,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let _process_guard = lock_registry_process(path)?;
    // This preflight is deliberately before directory or lock creation: an
    // unsafe existing registry must not cause any companion-path mutation.
    require_registry_authority_secure_at(path)?;
    let anchor = prepare_anchor(path)?;
    let lock_was_absent = match stat_at(&anchor, &anchor.lock_name) {
        Ok(_) => false,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
        Err(err) => return Err(Box::new(err)),
    };
    let lock_file = open_private_lock_at(&anchor)?;
    lock_file.lock_exclusive()?;
    verify_named_file(&anchor, &anchor.lock_name, &lock_file, "registry lock")?;
    validate_legacy_tmp_at(&anchor)?;

    let mut initialized = Vec::new();
    if lock_was_absent {
        initialized.push(path.with_extension("lock"));
    }
    if open_existing_regular_at(&anchor, &anchor.registry_name, "registry file")?.is_none() {
        let contents = toml::to_string_pretty(&KinRegistry::default())?;
        write_registry_atomically_at(&anchor, contents.as_bytes())?;
        initialized.push(path.to_path_buf());
    }
    Ok(initialized)
}

#[cfg(unix)]
fn load_from_unix(path: &Path) -> Result<KinRegistry, Box<dyn std::error::Error>> {
    let _process_guard = lock_registry_process(path)?;
    // Reject the complete authority snapshot before a missing lock can be
    // created. Descriptor-anchored checks below then revalidate under lock.
    require_registry_authority_secure_at(path)?;
    let anchor = match RegistryAnchor::open(path) {
        Ok(anchor) => anchor,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(KinRegistry::default());
        }
        Err(err) => return Err(Box::new(err)),
    };
    let lock_file = open_private_lock_at(&anchor)?;
    lock_file.lock_shared()?;
    verify_named_file(&anchor, &anchor.lock_name, &lock_file, "registry lock")?;
    validate_legacy_tmp_at(&anchor)?;
    read_registry_at(&anchor)
}

#[cfg(unix)]
fn save_to_unix(registry: &KinRegistry, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let _process_guard = lock_registry_process(path)?;
    require_registry_authority_secure_at(path)?;
    let contents = toml::to_string_pretty(registry)?;
    let anchor = prepare_anchor(path)?;
    let lock_file = open_private_lock_at(&anchor)?;
    lock_file.lock_exclusive()?;
    verify_named_file(&anchor, &anchor.lock_name, &lock_file, "registry lock")?;
    save_registry_at(&anchor, contents.as_bytes())
}

#[cfg(unix)]
fn update_at_unix<T>(
    path: &Path,
    mutate: impl FnOnce(&mut KinRegistry) -> T,
) -> Result<T, Box<dyn std::error::Error>> {
    let _process_guard = lock_registry_process(path)?;
    require_registry_authority_secure_at(path)?;
    let anchor = prepare_anchor(path)?;
    let lock_file = open_private_lock_at(&anchor).map_err(|err| {
        std::io::Error::new(err.kind(), format!("failed to open registry lock: {err}"))
    })?;
    lock_file.lock_exclusive().map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("failed to acquire registry lock: {err}"),
        )
    })?;
    verify_named_file(&anchor, &anchor.lock_name, &lock_file, "registry lock").map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("failed to revalidate locked registry lock: {err}"),
        )
    })?;
    validate_legacy_tmp_at(&anchor).map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("failed to validate legacy registry temp: {err}"),
        )
    })?;
    let mut registry = read_registry_at(&anchor)
        .map_err(|err| std::io::Error::other(format!("failed to read locked registry: {err}")))?;
    let result = mutate(&mut registry);
    let contents = toml::to_string_pretty(&registry)?;
    save_registry_at(&anchor, contents.as_bytes())
        .map_err(|err| std::io::Error::other(format!("failed to save locked registry: {err}")))?;
    Ok(result)
}

#[cfg(unix)]
fn read_registry_at(anchor: &RegistryAnchor) -> Result<KinRegistry, Box<dyn std::error::Error>> {
    let Some(mut file) = open_existing_regular_at(anchor, &anchor.registry_name, "registry file")?
    else {
        return Ok(KinRegistry::default());
    };
    let identity = validate_regular_file(&file, "registry file")?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    verify_named_identity(anchor, &anchor.registry_name, identity, "registry file")?;
    Ok(toml::from_str(&content)?)
}

#[cfg(unix)]
fn save_registry_at(
    anchor: &RegistryAnchor,
    contents: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    validate_legacy_tmp_at(anchor)?;
    let _ = open_existing_regular_at(anchor, &anchor.registry_name, "registry file")?;
    write_registry_atomically_at(anchor, contents)
}

#[cfg(unix)]
fn open_private_lock_at(anchor: &RegistryAnchor) -> std::io::Result<File> {
    let (file, created) = match open_at(
        anchor,
        &anchor.lock_name,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    ) {
        Ok(file) => Ok((file, true)),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            open_lock_after_create_race(anchor).map(|file| (file, false))
        }
        Err(err) => Err(err),
    }
    .map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("openat registry lock {:?} failed: {err}", anchor.lock_name),
        )
    })?;
    validate_regular_file(&file, "registry lock").map_err(|err| {
        std::io::Error::new(err.kind(), format!("registry lock fd invalid: {err}"))
    })?;
    if created {
        set_private_mode(&file).map_err(|err| {
            std::io::Error::new(err.kind(), format!("registry lock fchmod failed: {err}"))
        })?;
    } else {
        validate_private_file(&file, "registry lock")?;
    }
    verify_named_file(anchor, &anchor.lock_name, &file, "registry lock").map_err(|err| {
        std::io::Error::new(err.kind(), format!("registry lock pathname invalid: {err}"))
    })?;
    Ok(file)
}

#[cfg(unix)]
fn open_lock_after_create_race(anchor: &RegistryAnchor) -> std::io::Result<File> {
    let deadline = std::time::Instant::now() + REGISTRY_CREATE_RACE_TIMEOUT;
    loop {
        match open_at(
            anchor,
            &anchor.lock_name,
            libc::O_RDWR | libc::O_NONBLOCK,
            0,
        ) {
            Ok(file) => return Ok(file),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
                ) =>
            {
                if std::time::Instant::now() >= deadline {
                    return Err(err);
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(unix)]
fn open_existing_regular_at(
    anchor: &RegistryAnchor,
    name: &std::ffi::OsStr,
    label: &str,
) -> std::io::Result<Option<File>> {
    let file = match open_at(anchor, name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    validate_private_file(&file, label)?;
    verify_named_file(anchor, name, &file, label)?;
    Ok(Some(file))
}

#[cfg(unix)]
fn validate_legacy_tmp_at(anchor: &RegistryAnchor) -> std::io::Result<()> {
    let _ = open_existing_regular_at(anchor, &anchor.legacy_tmp_name, "legacy registry temp file")?;
    Ok(())
}

#[cfg(unix)]
fn open_at(
    anchor: &RegistryAnchor,
    name: &std::ffi::OsStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let name_c = name_cstring(name)?;
    // SAFETY: both descriptors/strings are valid for the duration of the call.
    let fd = unsafe {
        libc::openat(
            anchor.parent.as_raw_fd(),
            name_c.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            libc::c_uint::from(mode),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was returned by `openat` and ownership transfers to `File`.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn name_cstring(name: &std::ffi::OsStr) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;

    std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "registry filename contains a NUL byte",
        )
    })
}

#[cfg(unix)]
fn validate_parent(parent: &File) -> std::io::Result<()> {
    let stat = stat_file(parent)?;
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(registry_security_error(
            "registry parent must be a directory",
        ));
    }
    // SAFETY: `geteuid` has no preconditions.
    if stat.st_uid != unsafe { libc::geteuid() } {
        return Err(registry_security_error(
            "registry parent must be owned by the current user",
        ));
    }
    if stat.st_mode & 0o022 != 0 {
        return Err(registry_security_error(format!(
            "registry parent must not be group/world writable (found mode {:04o})",
            stat.st_mode & 0o7777
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_regular_file(file: &File, label: &str) -> std::io::Result<FileIdentity> {
    validate_regular_stat(&stat_file(file)?, label)
}

#[cfg(unix)]
fn validate_private_file(file: &File, label: &str) -> std::io::Result<FileIdentity> {
    validate_private_stat(&stat_file(file)?, label)
}

#[cfg(unix)]
fn validate_regular_stat(stat: &libc::stat, label: &str) -> std::io::Result<FileIdentity> {
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(registry_security_error(format!(
            "{label} must be a regular file"
        )));
    }
    // SAFETY: `geteuid` has no preconditions.
    if stat.st_uid != unsafe { libc::geteuid() } {
        return Err(registry_security_error(format!(
            "{label} must be owned by the current user"
        )));
    }
    if stat.st_nlink != 1 {
        return Err(registry_security_error(format!(
            "{label} must have exactly one hard link (found {})",
            stat.st_nlink
        )));
    }
    Ok(FileIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino,
    })
}

#[cfg(unix)]
fn validate_private_stat(stat: &libc::stat, label: &str) -> std::io::Result<FileIdentity> {
    let identity = validate_regular_stat(stat, label)?;
    let mode = stat.st_mode & 0o7777;
    if mode != 0o600 {
        return Err(registry_security_error(format!(
            "{label} has mode {mode:04o}; expected 0600. Refusing to trust or replace it. Run `kin doctor --fix` to authorize a permission-only repair"
        )));
    }
    Ok(identity)
}

#[cfg(unix)]
fn stat_file(file: &File) -> std::io::Result<libc::stat> {
    use std::os::fd::AsRawFd;

    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` points to writable storage and the file descriptor is valid.
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful `fstat` initialized the entire structure.
    Ok(unsafe { stat.assume_init() })
}

#[cfg(unix)]
fn stat_at(anchor: &RegistryAnchor, name: &std::ffi::OsStr) -> std::io::Result<libc::stat> {
    use std::os::fd::AsRawFd;

    let name_c = name_cstring(name)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the dirfd/name are valid and `stat` points to writable storage.
    if unsafe {
        libc::fstatat(
            anchor.parent.as_raw_fd(),
            name_c.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful `fstatat` initialized the entire structure.
    Ok(unsafe { stat.assume_init() })
}

#[cfg(unix)]
fn set_private_mode(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    // Call `fchmod` unconditionally: newly-created files must end at exactly
    // 0600 even when the process umask removed every requested mode bit.
    // SAFETY: the file descriptor is valid and the mode has no invalid bits.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stat = stat_file(file)?;
    if stat.st_mode & 0o7777 != 0o600 {
        return Err(registry_security_error(
            "registry authority file did not reach mode 0600",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_named_file(
    anchor: &RegistryAnchor,
    name: &std::ffi::OsStr,
    file: &File,
    label: &str,
) -> std::io::Result<()> {
    let identity = validate_private_file(file, label)?;
    verify_named_identity(anchor, name, identity, label)
}

#[cfg(unix)]
fn verify_named_identity(
    anchor: &RegistryAnchor,
    name: &std::ffi::OsStr,
    expected: FileIdentity,
    label: &str,
) -> std::io::Result<()> {
    let actual = validate_private_stat(&stat_at(anchor, name)?, label)?;
    if actual != expected {
        return Err(registry_security_error(format!(
            "{label} changed identity during the registry operation"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_named_structural_identity(
    anchor: &RegistryAnchor,
    name: &std::ffi::OsStr,
    expected: FileIdentity,
    label: &str,
) -> std::io::Result<()> {
    let actual = validate_regular_stat(&stat_at(anchor, name)?, label)?;
    if actual != expected {
        return Err(registry_security_error(format!(
            "{label} changed identity during the registry operation"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn write_registry_atomically_at(
    anchor: &RegistryAnchor,
    contents: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::fd::AsRawFd;

    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(&anchor.registry_name);
    tmp_name.push(format!(".tmp-{}", uuid::Uuid::new_v4()));

    let mut created_identity = None;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut file = open_at(
            anchor,
            &tmp_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        set_private_mode(&file)?;
        let identity = validate_regular_file(&file, "registry transaction temp file")?;
        created_identity = Some(identity);
        verify_named_identity(
            anchor,
            &tmp_name,
            identity,
            "registry transaction temp file",
        )?;
        file.write_all(contents)?;
        file.sync_all()?;

        #[cfg(test)]
        if std::env::var_os("REGISTRY_TEST_FAIL_AFTER_TEMP_SYNC").is_some() {
            return Err(Box::new(std::io::Error::other(
                "injected registry failure after temp sync",
            )));
        }

        verify_named_identity(
            anchor,
            &tmp_name,
            identity,
            "registry transaction temp file",
        )?;
        let tmp_c = name_cstring(&tmp_name)?;
        let registry_c = name_cstring(&anchor.registry_name)?;
        // SAFETY: both names are relative to the retained valid directory fd.
        if unsafe {
            libc::renameat(
                anchor.parent.as_raw_fd(),
                tmp_c.as_ptr(),
                anchor.parent.as_raw_fd(),
                registry_c.as_ptr(),
            )
        } != 0
        {
            return Err(Box::new(std::io::Error::last_os_error()));
        }
        verify_named_identity(anchor, &anchor.registry_name, identity, "registry file")?;
        anchor.parent.sync_all()?;
        Ok(())
    })();

    if let Some(identity) = created_identity {
        if result.is_err() {
            let _ = cleanup_temp_if_same(anchor, &tmp_name, identity);
        }
    }
    result
}

#[cfg(unix)]
fn cleanup_temp_if_same(
    anchor: &RegistryAnchor,
    name: &std::ffi::OsStr,
    expected: FileIdentity,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let stat = match stat_at(anchor, name) {
        Ok(stat) => stat,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    let actual = match validate_regular_stat(&stat, "registry transaction temp file") {
        Ok(identity) => identity,
        Err(_) => return Ok(()),
    };
    if actual != expected {
        return Ok(());
    }
    let name_c = name_cstring(name)?;
    // SAFETY: the retained dirfd and relative name are valid. The containing
    // directory is owned by the current user and is not group/world writable;
    // same-UID pathname replacement is outside this file-permission boundary
    // because that actor can already modify the 0600 authority files. The
    // identity check still prevents unlinking an observed replacement.
    if unsafe { libc::unlinkat(anchor.parent.as_raw_fd(), name_c.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn registry_security_error(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message.into())
}

#[cfg(not(unix))]
fn open_private_lock_file(path: &Path) -> Result<File, Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(false);
    let file = options.open(path)?;
    Ok(file)
}

#[cfg(not(unix))]
fn write_registry_atomically(
    path: &Path,
    contents: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// The cross-repo registry this process is bounded by: `KIN_REGISTRY_PATH`, or
/// `registry.toml` inside the managed Kin home.
///
/// The registry is store state, so it honors `KIN_HOME` exactly as the rest of
/// the store does. A process pinned to a scratch home discovers only the
/// repositories that home registered, and the operator's real registry is
/// reachable only from the real home. Without that, a fixture daemon under a
/// scratch home pinned sibling authority for every repository on the box, so
/// tests observed machine state and could be perturbed by it.
///
/// The supervisor directory is deliberately *not* this path's parent. It is a
/// machine-level singleton and comes from [`supervisor_root`]; see
/// [`managed_kin_home`] for the boundary each variable actually draws.
pub fn registry_path() -> PathBuf {
    resolve_registry_path(|key| std::env::var_os(key), managed_kin_home)
}

/// The policy behind [`registry_path`], with the environment and the managed
/// home taken as arguments.
///
/// Taking both by argument is what lets the split between this and
/// [`resolve_supervisor_root`] be proven from one fixed environment, rather than
/// by mutating a process-global table that every other test also reads.
pub(crate) fn resolve_registry_path(
    var_os: impl Fn(&str) -> Option<std::ffi::OsString>,
    managed_home: impl FnOnce() -> PathBuf,
) -> PathBuf {
    if let Some(path) = var_os("KIN_REGISTRY_PATH") {
        return PathBuf::from(path);
    }

    managed_home().join("registry.toml")
}

/// Directory of the machine-level daemon supervisor.
///
/// Keyed on the real home, or on the parent of an explicit `KIN_REGISTRY_PATH`,
/// deliberately *not* on `KIN_HOME`. One supervisor holds daemons launched under
/// several managed homes, so every daemon records [`managed_kin_home`] and the
/// census partitions on it. Moving the supervisor with `KIN_HOME` would hide
/// from a pinned session the daemons it shares the box with, which is the
/// opposite of what that variable is for.
pub fn supervisor_root() -> PathBuf {
    resolve_supervisor_root(
        |key| std::env::var_os(key),
        || directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf()),
    )
}

/// The policy behind [`supervisor_root`], with the environment and the OS home
/// lookup taken as arguments.
///
/// This reproduces, case for case, what the supervisor directory was before the
/// registry moved into the managed home: the parent of an explicit
/// `KIN_REGISTRY_PATH`, or `<real home>/.kin`.
pub(crate) fn resolve_supervisor_root(
    var_os: impl Fn(&str) -> Option<std::ffi::OsString>,
    base_dirs_home: impl FnOnce() -> Option<PathBuf>,
) -> PathBuf {
    if let Some(path) = var_os("KIN_REGISTRY_PATH") {
        return PathBuf::from(path)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".kin"));
    }

    base_dirs_home()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".kin")
}

/// The managed Kin install root this process resolves: `KIN_HOME`, then the
/// `KIN_DIR` compatibility alias, then `<home>/.kin`.
///
/// This is the boundary `KIN_HOME` genuinely draws. It bounds store and install
/// state, the cross-repo [`registry_path`] included; it does not move the
/// supervisor, whose directory comes from [`supervisor_root`] and therefore
/// from the real home. One supervisor can
/// consequently hold daemons launched under several managed homes, so every
/// daemon records the value this returns and the census partitions on it.
///
/// Both the CLI and the daemon call this same function, so two processes that
/// resolve independently agree by construction.
pub fn managed_kin_home() -> PathBuf {
    resolve_managed_kin_home(
        cfg!(windows),
        |key| std::env::var_os(key),
        || directories::UserDirs::new().map(|dirs| dirs.home_dir().to_path_buf()),
        || directories::BaseDirs::new().map(|dirs| dirs.home_dir().to_path_buf()),
    )
}

/// The policy behind [`managed_kin_home`], with the platform, the environment,
/// and both OS home lookups taken as arguments.
///
/// The Windows arm is a runtime branch rather than a `#[cfg]` block so it is
/// compiled and tested on every host, including the ones this fleet actually
/// builds on.
pub(crate) fn resolve_managed_kin_home(
    windows: bool,
    var_os: impl Fn(&str) -> Option<std::ffi::OsString>,
    known_profile_root: impl FnOnce() -> Option<PathBuf>,
    base_dirs_home: impl FnOnce() -> Option<PathBuf>,
) -> PathBuf {
    for key in ["KIN_HOME", "KIN_DIR"] {
        if let Some(value) = var_os(key).filter(|value| !value.is_empty()) {
            return PathBuf::from(value);
        }
    }

    let home = if windows {
        var_os("USERPROFILE")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(known_profile_root)
            .or_else(base_dirs_home)
    } else {
        base_dirs_home()
    };

    home.unwrap_or_else(|| PathBuf::from(".")).join(".kin")
}

/// Stable string identity for a managed home, for comparison between processes
/// that resolved it independently.
///
/// A home that does not exist yet cannot be canonicalized; its literal path is
/// used instead. Two processes that disagree about whether it existed therefore
/// compare as *different* homes, which is the safe direction: an unrecognized
/// home is skipped and named rather than silently swept up.
pub fn managed_kin_home_id(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn round_trip_load_save() {
        let dir = tempfile::tempdir().unwrap();
        let reg_path = dir.path().join("registry.toml");

        let mut reg = KinRegistry::default();
        reg.upsert("my-repo".to_string(), PathBuf::from("/tmp/my-repo"), 42);

        reg.save_to(&reg_path).unwrap();
        let loaded = KinRegistry::load_from(&reg_path).unwrap();

        assert_eq!(loaded.repos.len(), 1);
        assert_eq!(loaded.repos[0].id, "my-repo");
        assert_eq!(loaded.repos[0].path, PathBuf::from("/tmp/my-repo"));
        assert_eq!(loaded.repos[0].entities, 42);
        assert!(!loaded.repos[0].last_commit.is_empty());
        #[cfg(unix)]
        {
            assert_eq!(mode(&reg_path), 0o600);
            assert_eq!(mode(&reg_path.with_extension("lock")), 0o600);
        }
    }

    #[cfg(unix)]
    #[test]
    fn unicode_case_fold_cannot_alias_registry_and_lock_authorities() {
        let dir = tempfile::tempdir().unwrap();
        let reg_path = dir.path().join("registry.locK");

        let error = KinRegistry::default().save_to(&reg_path).unwrap_err();

        assert!(error.to_string().contains("filename must be ASCII"));
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_permissions_are_rejected_without_mutation_until_explicit_repair() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let reg_path = dir.path().join("registry.toml");
        let lock_path = reg_path.with_extension("lock");
        std::fs::write(&reg_path, "repos = []\n").unwrap();
        std::fs::write(&lock_path, b"").unwrap();
        std::fs::set_permissions(&reg_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let registry_before = std::fs::read(&reg_path).unwrap();
        let lock_before = std::fs::read(&lock_path).unwrap();

        let error = KinRegistry::default().save_to(&reg_path).unwrap_err();
        assert!(error.to_string().contains("expected 0600"));
        assert_eq!(std::fs::read(&reg_path).unwrap(), registry_before);
        assert_eq!(std::fs::read(&lock_path).unwrap(), lock_before);
        assert_eq!(mode(&reg_path), 0o644);
        assert_eq!(mode(&lock_path), 0o644);

        let report = inspect_registry_authority_at(&reg_path);
        assert!(report.has_repairable_permissions());
        assert!(!report.has_unsafe_object());
        assert!(require_registry_authority_secure_at(&reg_path).is_err());

        let repaired = repair_registry_authority_permissions_at(&reg_path).unwrap();
        assert_eq!(repaired.len(), 2);

        assert_eq!(mode(&reg_path), 0o600);
        assert_eq!(mode(&lock_path), 0o600);
        KinRegistry::default().save_to(&reg_path).unwrap();
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")));
    }

    #[cfg(unix)]
    #[test]
    fn loading_never_tightens_existing_permissions_implicitly() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let reg_path = dir.path().join("registry.toml");
        let lock_path = reg_path.with_extension("lock");
        std::fs::write(&reg_path, "repos = []\n").unwrap();
        std::fs::write(&lock_path, b"").unwrap();
        std::fs::set_permissions(&reg_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let error = KinRegistry::load_from(&reg_path).unwrap_err();
        assert!(error.to_string().contains("expected 0600"));

        assert_eq!(mode(&reg_path), 0o644);
        assert_eq!(mode(&lock_path), 0o644);
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_registry_never_creates_a_missing_companion_lock() {
        use std::os::unix::fs::PermissionsExt;

        for operation in ["load", "save", "update"] {
            let dir = tempfile::tempdir().unwrap();
            let reg_path = dir.path().join("registry.toml");
            let lock_path = reg_path.with_extension("lock");
            std::fs::write(&reg_path, "repos = []\n").unwrap();
            std::fs::set_permissions(&reg_path, std::fs::Permissions::from_mode(0o644)).unwrap();

            let result = match operation {
                "load" => KinRegistry::load_from(&reg_path).map(|_| ()),
                "save" => KinRegistry::default().save_to(&reg_path),
                "update" => KinRegistry::update_at(&reg_path, |_| {}),
                _ => unreachable!(),
            };
            assert!(result.is_err(), "{operation} unexpectedly trusted 0644");
            assert!(!lock_path.exists(), "{operation} created a companion lock");
            assert_eq!(mode(&reg_path), 0o644);
        }
    }

    #[cfg(unix)]
    #[test]
    fn genuine_non_private_lock_modes_are_refused_without_implicit_repair() {
        use std::os::unix::fs::PermissionsExt;

        for unsafe_mode in [0o000, 0o200, 0o400, 0o644] {
            let dir = tempfile::tempdir().unwrap();
            let reg_path = dir.path().join("registry.toml");
            let lock_path = reg_path.with_extension("lock");
            std::fs::write(&reg_path, "repos = []\n").unwrap();
            std::fs::write(&lock_path, b"").unwrap();
            std::fs::set_permissions(&reg_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(unsafe_mode))
                .unwrap();

            let error = KinRegistry::load_from(&reg_path).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("mode {unsafe_mode:04o}")),
                "{error}"
            );
            assert_eq!(mode(&lock_path), unsafe_mode);
            assert_eq!(std::fs::read(&reg_path).unwrap(), b"repos = []\n");
        }
    }

    #[cfg(unix)]
    #[test]
    fn installer_initialization_creates_missing_authority_without_rewriting_existing_bytes() {
        let fresh = tempfile::tempdir().unwrap();
        let fresh_path = fresh.path().join("registry.toml");
        let initialized = initialize_registry_authority_at(&fresh_path).unwrap();
        assert_eq!(initialized.len(), 2);
        assert_eq!(mode(&fresh_path), 0o600);
        assert_eq!(mode(&fresh_path.with_extension("lock")), 0o600);
        assert!(KinRegistry::load_from(&fresh_path).is_ok());

        let upgrade = tempfile::tempdir().unwrap();
        let upgrade_path = upgrade.path().join("registry.toml");
        let existing = b"# retained comment\nrepos = []\n";
        std::fs::write(&upgrade_path, existing).unwrap();
        set_private_mode(&File::open(&upgrade_path).unwrap()).unwrap();
        let initialized = initialize_registry_authority_at(&upgrade_path).unwrap();
        assert_eq!(initialized, vec![upgrade_path.with_extension("lock")]);
        assert_eq!(std::fs::read(&upgrade_path).unwrap(), existing);
        assert_eq!(mode(&upgrade_path), 0o600);
        assert_eq!(mode(&upgrade_path.with_extension("lock")), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn process_gate_keeps_same_registry_rename_outside_open_descriptor_window() {
        let dir = tempfile::tempdir().unwrap();
        let registry = dir.path().join("registry.toml");
        let replacement = dir.path().join("replacement.toml");
        let unrelated = dir.path().join("other-registry.toml");
        std::fs::write(&registry, b"repos = []\n").unwrap();
        std::fs::write(&replacement, b"repos = []\n").unwrap();

        let guard = lock_registry_process(&registry).unwrap();
        let opened_before_rename = File::open(&registry).unwrap();
        assert_eq!(stat_file(&opened_before_rename).unwrap().st_nlink, 1);

        // The key is path-scoped: an unrelated authority remains available.
        drop(lock_registry_process(&unrelated).unwrap());

        let (attempted_tx, attempted_rx) = std::sync::mpsc::channel();
        let (renamed_tx, renamed_rx) = std::sync::mpsc::channel();
        let registry_for_thread = registry.clone();
        let replacement_for_thread = replacement.clone();
        let writer = std::thread::spawn(move || {
            attempted_tx.send(()).unwrap();
            let _guard = lock_registry_process(&registry_for_thread).unwrap();
            std::fs::rename(replacement_for_thread, registry_for_thread).unwrap();
            renamed_tx.send(()).unwrap();
        });

        attempted_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(matches!(
            renamed_rx.recv_timeout(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        assert_eq!(stat_file(&opened_before_rename).unwrap().st_nlink, 1);

        drop(guard);
        renamed_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        writer.join().unwrap();
        assert_eq!(stat_file(&opened_before_rename).unwrap().st_nlink, 0);
    }

    #[cfg(unix)]
    #[test]
    fn process_gate_collapses_symlinked_prefix_aliases_by_parent_identity() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let real_root = root.path().join("real");
        let nested = real_root.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        let alias_root = root.path().join("alias");
        symlink(&real_root, &alias_root).unwrap();
        let real_registry = nested.join("registry.toml");
        let aliased_registry = alias_root.join("nested").join("registry.toml");

        let first = lock_registry_process(&real_registry).unwrap();
        let (attempted_tx, attempted_rx) = std::sync::mpsc::channel();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let contender = std::thread::spawn(move || {
            attempted_tx.send(()).unwrap();
            let _guard = lock_registry_process(&aliased_registry).unwrap();
            acquired_tx.send(()).unwrap();
        });

        attempted_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(matches!(
            acquired_rx.recv_timeout(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        drop(first);
        acquired_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        contender.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn process_gate_collapses_case_aliases_of_the_named_lock_authority() {
        let root = tempfile::tempdir().unwrap();
        let lowercase = root.path().join("registry.toml");
        let uppercase = root.path().join("REGISTRY.TOML");

        let first = lock_registry_process(&lowercase).unwrap();
        let (attempted_tx, attempted_rx) = std::sync::mpsc::channel();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let contender = std::thread::spawn(move || {
            attempted_tx.send(()).unwrap();
            let _guard = lock_registry_process(&uppercase).unwrap();
            acquired_tx.send(()).unwrap();
        });

        attempted_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert!(matches!(
            acquired_rx.recv_timeout(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        drop(first);
        acquired_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        contender.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn case_alias_updates_preserve_both_writers_on_case_insensitive_filesystems() {
        use std::sync::{Arc, Barrier};

        let root = tempfile::tempdir().unwrap();
        let lowercase = root.path().join("registry.toml");
        let uppercase = root.path().join("REGISTRY.TOML");
        KinRegistry::default().save_to(&lowercase).unwrap();
        let Ok(lower_file) = File::open(&lowercase) else {
            return;
        };
        let Ok(upper_file) = File::open(&uppercase) else {
            return;
        };
        let lower_stat = stat_file(&lower_file).unwrap();
        let upper_stat = stat_file(&upper_file).unwrap();
        if lower_stat.st_dev != upper_stat.st_dev || lower_stat.st_ino != upper_stat.st_ino {
            return;
        }

        let barrier = Arc::new(Barrier::new(2));
        let writers = [(lowercase.clone(), "lower"), (uppercase, "upper")]
            .into_iter()
            .map(|(path, id)| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    KinRegistry::update_at(&path, |registry| {
                        registry.repos.push(RegisteredRepo {
                            id: id.to_string(),
                            path: PathBuf::from(format!("/{id}")),
                            entities: 1,
                            last_commit: "now".to_string(),
                            dependencies: Vec::new(),
                        });
                    })
                    .unwrap();
                })
            })
            .collect::<Vec<_>>();
        for writer in writers {
            writer.join().unwrap();
        }

        let registry = KinRegistry::load_from(&lowercase).unwrap();
        let ids = registry
            .repos
            .iter()
            .map(|repo| repo.id.as_str())
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids, std::collections::HashSet::from(["lower", "upper"]));
    }

    #[test]
    fn locked_updates_preserve_concurrent_writers() {
        use std::sync::{Arc, Barrier};

        const WRITERS: usize = 24;
        let dir = Arc::new(tempfile::tempdir().unwrap());
        let reg_path = Arc::new(dir.path().join("registry.toml"));
        let barrier = Arc::new(Barrier::new(WRITERS));
        let mut handles = Vec::new();

        for index in 0..WRITERS {
            let path = Arc::clone(&reg_path);
            let barrier = Arc::clone(&barrier);
            let dir_guard = Arc::clone(&dir);
            handles.push(std::thread::spawn(move || {
                let _dir_guard = dir_guard;
                barrier.wait();
                KinRegistry::update_at(&path, |registry| {
                    registry.repos.push(RegisteredRepo {
                        id: format!("repo-{index}"),
                        path: PathBuf::from(format!("/repo-{index}")),
                        entities: index,
                        last_commit: "2026-07-13T00:00:00Z".to_string(),
                        dependencies: Vec::new(),
                    });
                })
                .map_err(|err| err.to_string())
            }));
        }
        let errors: Vec<_> = handles
            .into_iter()
            .filter_map(|handle| handle.join().unwrap().err())
            .collect();
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert!(
            errors.is_empty(),
            "errors: {errors:?}; entries: {entries:?}"
        );

        let loaded = KinRegistry::load_from(&reg_path).unwrap();
        let ids: std::collections::HashSet<_> =
            loaded.repos.iter().map(|repo| repo.id.as_str()).collect();
        assert_eq!(loaded.repos.len(), WRITERS);
        assert_eq!(ids.len(), WRITERS);
    }

    #[cfg(unix)]
    #[test]
    fn identity_safe_cleanup_does_not_unlink_a_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let reg_path = dir.path().join("registry.toml");
        let anchor = prepare_anchor(&reg_path).unwrap();
        let tmp_name = std::ffi::OsStr::new("candidate.tmp");
        let original = open_at(
            &anchor,
            tmp_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
        .unwrap();
        set_private_mode(&original).unwrap();
        let original_identity =
            validate_regular_file(&original, "registry transaction temp file").unwrap();
        drop(original);

        std::fs::rename(
            dir.path().join("candidate.tmp"),
            dir.path().join("original.tmp"),
        )
        .unwrap();
        std::fs::write(dir.path().join("candidate.tmp"), b"replacement").unwrap();

        cleanup_temp_if_same(&anchor, tmp_name, original_identity).unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("candidate.tmp")).unwrap(),
            b"replacement"
        );
    }

    #[cfg(unix)]
    fn run_registry_security_subprocess(case: &str) {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let kin_home = root.path().join("kin-home");
        let tmp = root.path().join("tmp");
        let work = root.path().join("work");
        for directory in [&home, &kin_home, &tmp, &work] {
            std::fs::create_dir_all(directory).unwrap();
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("registry_security_subprocess")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env("REGISTRY_SECURITY_TEST_CASE", case)
            .env("REGISTRY_SECURITY_TEST_ROOT", root.path())
            .env("HOME", &home)
            .env("KIN_HOME", &kin_home)
            .env("KIN_REGISTRY_PATH", kin_home.join("registry.toml"))
            .env("TMPDIR", &tmp)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "registry security subprocess {case} exceeded 5 seconds\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "registry security subprocess {case} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    #[test]
    fn restrictive_umask_and_relative_path_are_isolated() {
        run_registry_security_subprocess("restrictive-umask-relative");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_victims_are_isolated() {
        run_registry_security_subprocess("symlink-victims");
    }

    #[cfg(unix)]
    #[test]
    fn first_load_and_legacy_temp_migrations_are_isolated() {
        run_registry_security_subprocess("legacy-migrations");
    }

    #[cfg(unix)]
    #[test]
    fn failure_cleanup_is_isolated() {
        run_registry_security_subprocess("failure-cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn authority_identity_checks_are_isolated() {
        run_registry_security_subprocess("identity-checks");
    }

    #[cfg(unix)]
    #[test]
    fn fifo_authority_paths_fail_within_a_bounded_time() {
        run_registry_security_subprocess("fifo-paths");
    }

    #[cfg(unix)]
    #[test]
    fn writable_registry_parent_is_rejected() {
        run_registry_security_subprocess("writable-parent");
    }

    #[cfg(unix)]
    #[test]
    fn reserved_registry_path_collisions_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        for filename in [
            "registry.lock",
            "registry.tmp",
            "registry.LOCK",
            "registry.TMP",
        ] {
            let path = dir.path().join(filename);
            let error = KinRegistry::default().save_to(&path).unwrap_err();
            assert!(error.to_string().contains("collides"), "{error}");
            let report = inspect_registry_authority_at(&path);
            assert!(report.has_unsafe_object());
        }
    }

    #[cfg(unix)]
    #[test]
    fn registry_security_subprocess() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let Some(case) = std::env::var_os("REGISTRY_SECURITY_TEST_CASE") else {
            return;
        };
        let root = PathBuf::from(std::env::var_os("REGISTRY_SECURITY_TEST_ROOT").unwrap());
        let work = root.join("work");
        let registry_path = work.join("registry.toml");
        let lock_path = work.join("registry.lock");
        let legacy_tmp_path = work.join("registry.tmp");

        match case.to_str().unwrap() {
            "restrictive-umask-relative" => {
                std::env::set_current_dir(&work).unwrap();
                // SAFETY: this isolated subprocess sets the umask before spawning
                // workers and restores it after every worker has joined.
                let previous = unsafe { libc::umask(0o777) };
                let fresh_path = work.join("new-parent/nested/registry.toml");
                let initialized = initialize_registry_authority_at(&fresh_path).unwrap();

                let concurrent_path =
                    std::sync::Arc::new(work.join("concurrent-parent/nested/registry.toml"));
                let concurrent_barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
                let mut concurrent_handles = Vec::new();
                for index in 0..8 {
                    let path = std::sync::Arc::clone(&concurrent_path);
                    let barrier = std::sync::Arc::clone(&concurrent_barrier);
                    let repo_path = work.clone();
                    concurrent_handles.push(std::thread::spawn(move || {
                        barrier.wait();
                        KinRegistry::update_at(&path, |registry| {
                            registry.repos.push(RegisteredRepo {
                                id: format!("concurrent-parent-{index}"),
                                path: repo_path,
                                entities: index,
                                last_commit: "2026-07-13T00:00:00Z".to_string(),
                                dependencies: Vec::new(),
                            });
                        })
                        .unwrap();
                    }));
                }
                for handle in concurrent_handles {
                    handle.join().unwrap();
                }

                let mut handles = Vec::new();
                for index in 0..8 {
                    let repo_path = work.clone();
                    handles.push(std::thread::spawn(move || {
                        KinRegistry::update_at(Path::new("registry.toml"), |registry| {
                            registry.repos.push(RegisteredRepo {
                                id: format!("relative-{index}"),
                                path: repo_path,
                                entities: index,
                                last_commit: "2026-07-13T00:00:00Z".to_string(),
                                dependencies: Vec::new(),
                            });
                        })
                        .unwrap();
                    }));
                }
                for handle in handles {
                    handle.join().unwrap();
                }
                // SAFETY: restore the process umask before any assertion can panic.
                unsafe { libc::umask(previous) };
                assert_eq!(initialized.len(), 2);
                assert_eq!(mode(&work.join("new-parent")), 0o700);
                assert_eq!(mode(&work.join("new-parent/nested")), 0o700);
                assert_eq!(mode(&fresh_path), 0o600);
                assert_eq!(mode(&fresh_path.with_extension("lock")), 0o600);
                assert_eq!(mode(&work.join("concurrent-parent")), 0o700);
                assert_eq!(mode(&work.join("concurrent-parent/nested")), 0o700);
                assert_eq!(mode(&concurrent_path), 0o600);
                assert_eq!(mode(&concurrent_path.with_extension("lock")), 0o600);
                assert_eq!(
                    KinRegistry::load_from(&concurrent_path)
                        .unwrap()
                        .repos
                        .len(),
                    8
                );
                assert_eq!(mode(Path::new("registry.toml")), 0o600);
                assert_eq!(mode(Path::new("registry.lock")), 0o600);
                assert_eq!(
                    KinRegistry::load_from(Path::new("registry.toml"))
                        .unwrap()
                        .repos
                        .len(),
                    8
                );
            }
            "symlink-victims" => {
                let victim = work.join("victim");
                std::fs::write(&victim, b"do not touch").unwrap();
                std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o640)).unwrap();
                let victim_mode = mode(&victim);

                symlink(&victim, &registry_path).unwrap();
                assert!(KinRegistry::load_from(&registry_path).is_err());
                assert!(KinRegistry::default().save_to(&registry_path).is_err());
                assert_eq!(std::fs::read(&victim).unwrap(), b"do not touch");
                assert_eq!(mode(&victim), victim_mode);
                std::fs::remove_file(&registry_path).unwrap();
                assert!(!lock_path.exists());

                std::fs::write(&registry_path, "repos = []\n").unwrap();
                std::fs::set_permissions(&registry_path, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
                symlink(&victim, &lock_path).unwrap();
                assert!(KinRegistry::load_from(&registry_path).is_err());
                assert!(KinRegistry::default().save_to(&registry_path).is_err());
                assert_eq!(std::fs::read(&victim).unwrap(), b"do not touch");
                assert_eq!(mode(&victim), victim_mode);
                std::fs::remove_file(&lock_path).unwrap();

                symlink(&victim, &legacy_tmp_path).unwrap();
                assert!(KinRegistry::default().save_to(&registry_path).is_err());
                assert_eq!(std::fs::read(&victim).unwrap(), b"do not touch");
                assert_eq!(mode(&victim), victim_mode);
            }
            "legacy-migrations" => {
                std::fs::write(&registry_path, "repos = []\n").unwrap();
                std::fs::write(&lock_path, b"").unwrap();
                std::fs::write(&legacy_tmp_path, b"legacy").unwrap();
                for path in [&registry_path, &lock_path, &legacy_tmp_path] {
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
                }
                assert!(KinRegistry::load_from(&registry_path).is_err());
                assert_eq!(mode(&registry_path), 0o644);
                assert_eq!(mode(&lock_path), 0o644);
                assert_eq!(mode(&legacy_tmp_path), 0o644);
                let repaired = repair_registry_authority_permissions_at(&registry_path).unwrap();
                assert_eq!(repaired.len(), 3);
                KinRegistry::load_from(&registry_path).unwrap();
                assert_eq!(mode(&registry_path), 0o600);
                assert_eq!(mode(&lock_path), 0o600);
                assert_eq!(mode(&legacy_tmp_path), 0o600);
                assert_eq!(std::fs::read(&legacy_tmp_path).unwrap(), b"legacy");
            }
            "fifo-paths" => {
                let make_fifo = |path: &Path| {
                    let path = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
                        path.as_os_str(),
                    ))
                    .unwrap();
                    // SAFETY: path is a valid NUL-terminated string and mode is valid.
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                };

                make_fifo(&registry_path);
                let started = std::time::Instant::now();
                let error = KinRegistry::load_from(&registry_path).unwrap_err();
                assert!(started.elapsed() < std::time::Duration::from_secs(1));
                assert!(error.to_string().contains("regular file"), "{error}");
                std::fs::remove_file(&registry_path).unwrap();
                assert!(!lock_path.exists());

                std::fs::write(&registry_path, "repos = []\n").unwrap();
                std::fs::set_permissions(&registry_path, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
                make_fifo(&lock_path);
                let started = std::time::Instant::now();
                let error = KinRegistry::load_from(&registry_path).unwrap_err();
                assert!(started.elapsed() < std::time::Duration::from_secs(1));
                assert!(error.to_string().contains("regular file"), "{error}");
                std::fs::remove_file(&lock_path).unwrap();

                std::fs::write(&lock_path, b"").unwrap();
                std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
                make_fifo(&legacy_tmp_path);
                let started = std::time::Instant::now();
                let error = KinRegistry::load_from(&registry_path).unwrap_err();
                assert!(started.elapsed() < std::time::Duration::from_secs(1));
                assert!(error.to_string().contains("regular file"), "{error}");
            }
            "writable-parent" => {
                std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o777)).unwrap();
                let error = KinRegistry::default().save_to(&registry_path).unwrap_err();
                assert!(
                    error.to_string().contains("group/world writable"),
                    "{error}"
                );
                assert!(!registry_path.exists());
                assert!(!lock_path.exists());
                let nested_registry = work.join("nested/private/registry.toml");
                let error = initialize_registry_authority_at(&nested_registry).unwrap_err();
                assert!(
                    error.to_string().contains("group/world writable"),
                    "{error}"
                );
                assert!(!work.join("nested").exists());
                std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            "failure-cleanup" => {
                KinRegistry::default().save_to(&registry_path).unwrap();
                let before = std::fs::read(&registry_path).unwrap();
                let mut fail_after_temp_sync =
                    crate::test_env::EnvVarGuard::set("REGISTRY_TEST_FAIL_AFTER_TEMP_SYNC", "1");
                let mut changed = KinRegistry::default();
                changed.repos.push(RegisteredRepo {
                    id: "must-not-land".to_string(),
                    path: work.clone(),
                    entities: 1,
                    last_commit: "2026-07-13T00:00:00Z".to_string(),
                    dependencies: Vec::new(),
                });
                assert!(changed.save_to(&registry_path).is_err());
                fail_after_temp_sync.apply::<_, &str>("REGISTRY_TEST_FAIL_AFTER_TEMP_SYNC", None);
                assert_eq!(std::fs::read(&registry_path).unwrap(), before);
                assert!(std::fs::read_dir(&work).unwrap().all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp-")));
            }
            "identity-checks" => {
                std::fs::write(&registry_path, "repos = []\n").unwrap();
                std::fs::set_permissions(&registry_path, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
                let registry_link = work.join("registry-hardlink");
                std::fs::hard_link(&registry_path, &registry_link).unwrap();
                assert!(KinRegistry::load_from(&registry_path).is_err());
                std::fs::remove_file(&registry_link).unwrap();

                std::fs::write(&lock_path, b"").unwrap();
                std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
                let lock_link = work.join("lock-hardlink");
                std::fs::hard_link(&lock_path, &lock_link).unwrap();
                assert!(KinRegistry::load_from(&registry_path).is_err());
                std::fs::remove_file(&lock_link).unwrap();

                std::fs::remove_file(&lock_path).unwrap();
                std::fs::remove_file(&registry_path).unwrap();
                std::fs::create_dir(&registry_path).unwrap();
                assert!(KinRegistry::load_from(&registry_path).is_err());
                std::fs::remove_dir(&registry_path).unwrap();
                assert!(!lock_path.exists());

                std::fs::create_dir(&lock_path).unwrap();
                assert!(KinRegistry::default().save_to(&registry_path).is_err());
                std::fs::remove_dir(&lock_path).unwrap();

                let real_parent = root.join("real-parent");
                let linked_parent = root.join("linked-parent");
                std::fs::create_dir(&real_parent).unwrap();
                symlink(&real_parent, &linked_parent).unwrap();
                assert!(KinRegistry::default()
                    .save_to(&linked_parent.join("registry.toml"))
                    .is_err());

                // Wrong-owner coverage is possible only for a privileged test runner.
                // SAFETY: `geteuid` and `chown` have no Rust aliasing requirements.
                if unsafe { libc::geteuid() } == 0 {
                    std::fs::write(&registry_path, "repos = []\n").unwrap();
                    let path_c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
                        registry_path.as_os_str(),
                    ))
                    .unwrap();
                    // SAFETY: `path_c` is valid and the test is running as root.
                    assert_eq!(unsafe { libc::chown(path_c.as_ptr(), 1, u32::MAX) }, 0);
                    assert!(KinRegistry::load_from(&registry_path).is_err());
                    // SAFETY: restore ownership before testing the lock authority.
                    assert_eq!(unsafe { libc::chown(path_c.as_ptr(), 0, u32::MAX) }, 0);
                    let lock_c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
                        lock_path.as_os_str(),
                    ))
                    .unwrap();
                    // SAFETY: `lock_c` is valid and the test is running as root.
                    assert_eq!(unsafe { libc::chown(lock_c.as_ptr(), 1, u32::MAX) }, 0);
                    assert!(KinRegistry::load_from(&registry_path).is_err());
                }
            }
            unknown => panic!("unknown registry security subprocess case: {unknown}"),
        }
    }

    #[test]
    fn upsert_updates_existing_entry() {
        let mut reg = KinRegistry::default();
        reg.upsert("repo".to_string(), PathBuf::from("/a"), 10);
        reg.upsert("repo".to_string(), PathBuf::from("/b"), 20);

        assert_eq!(reg.repos.len(), 1);
        assert_eq!(reg.repos[0].path, PathBuf::from("/b"));
        assert_eq!(reg.repos[0].entities, 20);
    }

    #[test]
    fn upsert_adds_distinct_repos() {
        let mut reg = KinRegistry::default();
        reg.upsert("repo-a".to_string(), PathBuf::from("/a"), 1);
        reg.upsert("repo-b".to_string(), PathBuf::from("/b"), 2);

        assert_eq!(reg.repos.len(), 2);
    }

    #[test]
    fn clean_removes_stale_paths() {
        let dir = tempfile::tempdir().unwrap();
        let valid_repo = dir.path().join("valid");
        std::fs::create_dir_all(valid_repo.join(".kin")).unwrap();

        let mut reg = KinRegistry::default();
        reg.upsert("valid".to_string(), valid_repo.clone(), 10);
        reg.upsert("stale".to_string(), PathBuf::from("/nonexistent/path"), 5);

        let removed = reg.clean();
        assert_eq!(removed, 1);
        assert_eq!(reg.repos.len(), 1);
        assert_eq!(reg.repos[0].id, "valid");
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let reg_path = dir.path().join("does-not-exist.toml");
        let reg = KinRegistry::load_from(&reg_path).unwrap();
        assert!(reg.repos.is_empty());
    }

    #[test]
    fn repo_paths_returns_all_paths() {
        let mut reg = KinRegistry::default();
        reg.upsert("a".to_string(), PathBuf::from("/a"), 1);
        reg.upsert("b".to_string(), PathBuf::from("/b"), 2);

        let paths = reg.repo_paths();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&Path::new("/a")));
        assert!(paths.contains(&Path::new("/b")));
    }

    /// Resolve against a stated environment, so no test reads ambient state.
    fn managed_home_with(windows: bool, env: &[(&str, &str)]) -> PathBuf {
        let owned: Vec<(String, String)> = env
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        resolve_managed_kin_home(
            windows,
            |key| {
                owned
                    .iter()
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| std::ffi::OsString::from(value))
            },
            || Some(PathBuf::from("/profile-root")),
            || Some(PathBuf::from("/base-home")),
        )
    }

    #[test]
    fn kin_home_wins_over_kin_dir_and_the_home_fallback() {
        assert_eq!(
            managed_home_with(false, &[("KIN_HOME", "/pinned"), ("KIN_DIR", "/alias")]),
            PathBuf::from("/pinned")
        );
    }

    #[test]
    fn kin_dir_is_the_compatibility_alias() {
        assert_eq!(
            managed_home_with(false, &[("KIN_DIR", "/alias")]),
            PathBuf::from("/alias")
        );
    }

    #[test]
    fn an_empty_pin_is_not_a_home() {
        assert_eq!(
            managed_home_with(false, &[("KIN_HOME", ""), ("KIN_DIR", "")]),
            PathBuf::from("/base-home/.kin")
        );
    }

    #[test]
    fn unpinned_falls_back_to_the_real_home() {
        assert_eq!(
            managed_home_with(false, &[]),
            PathBuf::from("/base-home/.kin")
        );
    }

    #[test]
    fn windows_prefers_the_user_profile_for_the_fallback_home() {
        assert_eq!(
            managed_home_with(true, &[("USERPROFILE", "/users/kin")]),
            PathBuf::from("/users/kin/.kin")
        );
        assert_eq!(
            managed_home_with(true, &[]),
            PathBuf::from("/profile-root/.kin")
        );
    }

    /// A fake environment, so the split below is proven without writing to the
    /// process-global table every other test in this binary also reads.
    fn fake_env(env: &[(&str, &str)]) -> impl Fn(&str) -> Option<std::ffi::OsString> {
        let owned: Vec<(String, String)> = env
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |key| {
            owned
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| std::ffi::OsString::from(value))
        }
    }

    /// The split this seam exists to draw, read from one fixed environment: a
    /// pinned `KIN_HOME` moves the registry with the rest of the store, and does
    /// not move the machine-level supervisor.
    ///
    /// FIR-2467. Before this, both hung off the real home, so a daemon under a
    /// scratch home pinned sibling authority for every repository on the box.
    #[test]
    fn pinning_kin_home_moves_the_registry_and_not_the_supervisor() {
        let env = [("KIN_HOME", "/scratch/home")];
        let managed = managed_home_with(false, &env);
        assert_eq!(managed, PathBuf::from("/scratch/home"));

        let registry = resolve_registry_path(fake_env(&env), || managed.clone());
        assert_eq!(registry, PathBuf::from("/scratch/home/registry.toml"));

        let supervisor =
            resolve_supervisor_root(fake_env(&env), || Some(PathBuf::from("/base-home")));
        assert_eq!(supervisor, PathBuf::from("/base-home/.kin"));
        assert!(!supervisor.starts_with("/scratch/home"));
    }

    /// With no `KIN_HOME`, the two land where they always did: side by side in
    /// the real home. The default install is the case this fix must not move.
    #[test]
    fn an_unpinned_home_keeps_the_registry_beside_the_supervisor() {
        let managed = managed_home_with(false, &[]);
        assert_eq!(managed, PathBuf::from("/base-home/.kin"));

        let registry = resolve_registry_path(fake_env(&[]), || managed.clone());
        let supervisor =
            resolve_supervisor_root(fake_env(&[]), || Some(PathBuf::from("/base-home")));

        assert_eq!(registry, PathBuf::from("/base-home/.kin/registry.toml"));
        assert_eq!(supervisor, PathBuf::from("/base-home/.kin"));
        assert_eq!(registry.parent(), Some(supervisor.as_path()));
    }

    /// `KIN_REGISTRY_PATH` still names the file outright and still carries the
    /// supervisor to its parent, which is how every isolated harness in this
    /// fleet pins both today.
    #[test]
    fn an_explicit_registry_path_still_carries_the_supervisor() {
        let env = [
            ("KIN_REGISTRY_PATH", "/pinned/dir/registry.toml"),
            ("KIN_HOME", "/scratch/home"),
        ];
        assert_eq!(
            resolve_registry_path(fake_env(&env), || PathBuf::from("/scratch/home")),
            PathBuf::from("/pinned/dir/registry.toml")
        );
        assert_eq!(
            resolve_supervisor_root(fake_env(&env), || Some(PathBuf::from("/base-home"))),
            PathBuf::from("/pinned/dir")
        );
    }

    /// The edge answers the previous `registry_path().parent()` derivation
    /// produced, kept exactly rather than tidied.
    ///
    /// A bare filename's parent is the empty path, not `.kin`: only an empty
    /// `KIN_REGISTRY_PATH`, whose parent is `None`, ever reached that fallback.
    /// Both are odd, and both are what shipped, so both are asserted here. This
    /// test is the reason to believe the supervisor did not move: it failed on
    /// the first run, against an expectation that had guessed rather than read.
    #[test]
    fn the_supervisor_keeps_its_old_answers_at_the_edges() {
        assert_eq!(
            resolve_supervisor_root(fake_env(&[("KIN_REGISTRY_PATH", "registry.toml")]), || {
                Some(PathBuf::from("/base-home"))
            }),
            PathBuf::from("")
        );
        assert_eq!(
            resolve_supervisor_root(fake_env(&[("KIN_REGISTRY_PATH", "")]), || Some(
                PathBuf::from("/base-home")
            )),
            PathBuf::from(".kin")
        );
        assert_eq!(
            resolve_supervisor_root(fake_env(&[]), || None),
            PathBuf::from("./.kin")
        );
    }

    #[test]
    fn a_missing_home_keeps_its_literal_identity() {
        let missing = PathBuf::from("/definitely/not/present/.kin");
        assert_eq!(managed_kin_home_id(&missing), missing.display().to_string());
    }

    #[test]
    fn identity_is_stable_for_a_home_that_exists() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            managed_kin_home_id(dir.path()),
            managed_kin_home_id(dir.path())
        );
    }
}
