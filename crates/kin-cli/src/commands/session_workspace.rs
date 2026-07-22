// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
#[cfg(any(unix, windows))]
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use anyhow::Result;
#[cfg(any(unix, windows))]
use cap_fs_ext::DirExt;
use kin_model::ChangeStore;
use kin_runtime::workspace::{
    MaterializationSourceKind, MaterializeStrategy, MaterializedWorkspace,
};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionWorkspaceRequest {
    pub session_dir: String,
    #[serde(default)]
    pub strategy: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionWorkspaceResponse {
    pub root: String,
    pub strategy: String,
    pub source_kind: String,
}

pub(crate) async fn create_session_workspace(
    layout: &kin_core::KinLayout,
    session_dir: &std::path::Path,
    strategy: Option<MaterializeStrategy>,
    scope: Option<&str>,
) -> Result<MaterializedWorkspace> {
    let base_url = match std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        Some(base_url) => base_url,
        None => crate::daemon_client::resolve_daemon_url(layout)
            .await?
            .ok_or_else(|| anyhow::anyhow!("kin daemon is required"))?,
    };
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    let response = client
        .session_workspace(&SessionWorkspaceRequest {
            session_dir: session_dir.display().to_string(),
            strategy: strategy.map(|value| value.to_string()),
            scope: scope.map(str::to_string),
        })
        .await?;
    let strategy = response
        .strategy
        .parse::<MaterializeStrategy>()
        .map_err(|error| anyhow::anyhow!("{}", error))?;
    let source_kind = match response.source_kind.as_str() {
        "blob-tree" => MaterializationSourceKind::BlobTree,
        "filesystem" => MaterializationSourceKind::Filesystem,
        other => anyhow::bail!("daemon returned unknown materialization source: {other}"),
    };

    Ok(MaterializedWorkspace::from_existing(
        std::path::PathBuf::from(response.root),
        strategy,
        source_kind,
    ))
}

pub fn create_session_workspace_from_graph(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    session_dir: &Path,
    strategy: Option<MaterializeStrategy>,
    scope: Option<&str>,
) -> Result<MaterializedWorkspace> {
    create_session_workspace_from_graph_with_hooks(
        layout,
        graph,
        session_dir,
        strategy,
        scope,
        |_| Ok(()),
        |_| Ok(()),
    )
}

#[cfg(test)]
fn create_session_workspace_from_graph_with_hook(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    session_dir: &Path,
    strategy: Option<MaterializeStrategy>,
    scope: Option<&str>,
    after_root_created: impl FnOnce(&Path) -> Result<()>,
) -> Result<MaterializedWorkspace> {
    create_session_workspace_from_graph_with_hooks(
        layout,
        graph,
        session_dir,
        strategy,
        scope,
        |_| Ok(()),
        after_root_created,
    )
}

#[cfg(test)]
fn create_session_workspace_from_graph_with_child_hook(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    session_dir: &Path,
    strategy: Option<MaterializeStrategy>,
    scope: Option<&str>,
    after_child_created: impl FnOnce(&Path) -> Result<()>,
) -> Result<MaterializedWorkspace> {
    create_session_workspace_from_graph_with_hooks(
        layout,
        graph,
        session_dir,
        strategy,
        scope,
        after_child_created,
        |_| Ok(()),
    )
}

fn create_session_workspace_from_graph_with_hooks(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    session_dir: &Path,
    strategy: Option<MaterializeStrategy>,
    scope: Option<&str>,
    after_child_created: impl FnOnce(&Path) -> Result<()>,
    after_root_created: impl FnOnce(&Path) -> Result<()>,
) -> Result<MaterializedWorkspace> {
    if let Some(strategy) = strategy {
        if strategy != MaterializeStrategy::Copy {
            return Err(anyhow::anyhow!(
                "native graph-backed session materialization only supports `copy`; requested `{}`",
                strategy
            ));
        }
    }

    let session_name = validate_session_dir(layout, session_dir)?;

    let branch_name = kin_core::read_current_branch(layout)?;
    let branch = graph.get_branch(&branch_name)?.ok_or_else(|| {
        anyhow::anyhow!(
            "current branch '{}' is missing from the daemon graph",
            branch_name
        )
    })?;
    let genesis = kin_core::build_genesis_change();
    let tree = kin_core::build_file_tree(graph, &genesis.id, &branch.head)?;
    let scope_filter = validated_scope_filter(scope)?;
    let entries = preflight_blob_tree(&tree, scope_filter.as_deref())?;
    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    #[cfg(any(unix, windows))]
    {
        materialize_preflighted_blob_tree(
            layout,
            session_dir,
            session_name,
            &blob_store,
            &entries,
            branch.head.to_string(),
            after_child_created,
            after_root_created,
        )
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (
            session_name,
            blob_store,
            entries,
            branch,
            after_child_created,
            after_root_created,
        );
        anyhow::bail!("secure graph-backed session materialization is unsupported on this platform")
    }
}

#[derive(Debug)]
struct PreflightedBlob {
    file_id: String,
    relative_path: PathBuf,
    hash: kin_model::Hash256,
}

fn preflight_blob_tree(
    tree: &HashMap<kin_model::FilePathId, kin_model::Hash256>,
    scope_filter: Option<&Path>,
) -> Result<Vec<PreflightedBlob>> {
    let mut entries = Vec::with_capacity(tree.len());
    let mut portable_paths = BTreeMap::new();

    for (file_id, hash) in tree {
        let relative_path = validate_portable_relative_path(&file_id.0, "graph FilePathId")?;
        let collision_key = portable_path_collision_key(&relative_path)?;
        if let Some(existing) = portable_paths.insert(collision_key, relative_path.clone()) {
            anyhow::bail!(
                "graph FilePathId '{}' collides portably with materialized path '{}'",
                file_id.0,
                existing.display()
            );
        }
        entries.push(PreflightedBlob {
            file_id: file_id.0.clone(),
            relative_path,
            hash: *hash,
        });
    }

    for (path_key, path) in &portable_paths {
        let mut parent_key = path_key.clone();
        parent_key.pop();
        while !parent_key.is_empty() {
            if let Some(candidate) = portable_paths.get(&parent_key) {
                anyhow::bail!(
                    "graph FilePathId '{}' conflicts portably with file-valued parent '{}'",
                    path.display(),
                    candidate.display()
                );
            }
            parent_key.pop();
        }
    }

    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    if let Some(scope_filter) = scope_filter {
        entries.retain(|entry| entry.relative_path == scope_filter);
    }
    Ok(entries)
}

fn portable_path_collision_key(path: &Path) -> Result<Vec<String>> {
    path.components()
        .map(|component| match component {
            Component::Normal(component) => {
                let component = component.to_str().ok_or_else(|| {
                    anyhow::anyhow!("portable path component must be valid UTF-8")
                })?;
                let normalized: String = component.nfkc().collect();
                Ok(normalized
                    .chars()
                    .flat_map(char::to_uppercase)
                    .flat_map(char::to_lowercase)
                    .nfkc()
                    .collect())
            }
            _ => Err(anyhow::anyhow!(
                "portable collision key requires only normal relative components"
            )),
        })
        .collect()
}

fn validated_scope_filter(scope: Option<&str>) -> Result<Option<PathBuf>> {
    let Some(scope) = scope else {
        return Ok(None);
    };
    if scope.starts_with("entity:") {
        anyhow::bail!("entity scope must be resolved against graph truth before materialization");
    }
    let raw = scope.strip_prefix("file:").unwrap_or(scope);
    validate_portable_relative_path(raw, "materialization scope").map(Some)
}

fn validate_portable_relative_path(raw: &str, subject: &str) -> Result<PathBuf> {
    if raw.is_empty() {
        anyhow::bail!("{subject} must not be empty");
    }
    if raw.starts_with('/') || Path::new(raw).is_absolute() {
        anyhow::bail!("{subject} '{raw}' must be relative, not rooted or absolute");
    }
    if raw.contains('\\') {
        anyhow::bail!("{subject} '{raw}' contains an ambiguous platform path separator");
    }

    let mut relative_path = PathBuf::new();
    for component in raw.split('/') {
        if component.is_empty() {
            anyhow::bail!(
                "{subject} '{raw}' contains an ambiguous repeated or trailing path separator"
            );
        }
        match component {
            "." => anyhow::bail!("{subject} '{raw}' contains an ambiguous current component"),
            ".." => anyhow::bail!("{subject} '{raw}' contains parent traversal"),
            _ => validate_portable_component(component, subject, raw)?,
        }
        relative_path.push(component);
    }

    if Path::new(raw)
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        anyhow::bail!("{subject} '{raw}' contains a prefix, root, or non-relative component");
    }
    Ok(relative_path)
}

fn validate_portable_component(component: &str, subject: &str, full_path: &str) -> Result<()> {
    if component.encode_utf16().count() > 255 {
        anyhow::bail!(
            "{subject} '{full_path}' contains a component longer than 255 UTF-16 code units"
        );
    }
    if component.len() > 255 {
        anyhow::bail!("{subject} '{full_path}' contains a component longer than 255 UTF-8 bytes");
    }
    if component.ends_with('.') || component.ends_with(' ') {
        anyhow::bail!(
            "{subject} '{full_path}' contains a component with platform-ambiguous trailing characters"
        );
    }
    if component.chars().any(|character| {
        character <= '\u{1f}'
            || matches!(
                character,
                '<' | '>' | ':' | '"' | '|' | '?' | '*' | '/' | '\\'
            )
    }) {
        anyhow::bail!(
            "{subject} '{full_path}' contains a platform-invalid or prefix-ambiguous component"
        );
    }

    let portable_case = component.to_ascii_lowercase();
    if matches!(portable_case.as_str(), ".kin-session" | ".kin" | ".git") {
        anyhow::bail!(
            "{subject} '{full_path}' contains reserved control-plane component '{component}'"
        );
    }

    // Keep this in parity with cap-primitives' Windows `file_prefix` check so
    // graph preflight cannot accept a name that capability-rooted creation
    // rejects after the session workspace has already been prepared.
    let device_stem = component
        .char_indices()
        .skip(1)
        .find_map(|(index, character)| (character == '.').then_some(&component[..index]))
        .unwrap_or(component)
        .trim_end()
        .to_uppercase();
    let reserved = matches!(
        device_stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "CLOCK$"
            | "COM0"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "COM¹"
            | "COM²"
            | "COM³"
            | "LPT0"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
            | "LPT¹"
            | "LPT²"
            | "LPT³"
    );
    if reserved {
        anyhow::bail!("{subject} '{full_path}' contains a reserved platform path component");
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn absolute_path_from_filesystem_root(path: &Path) -> std::io::Result<(PathBuf, PathBuf)> {
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("path must be absolute: {}", path.display()),
        ));
    }
    let filesystem_root = path
        .ancestors()
        .last()
        .filter(|ancestor| ancestor.has_root() && !ancestor.as_os_str().is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("path has no filesystem root: {}", path.display()),
            )
        })?
        .to_path_buf();
    let relative = path
        .strip_prefix(&filesystem_root)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "path is not beneath its filesystem root: {}",
                    path.display()
                ),
            )
        })?
        .to_path_buf();
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "absolute path contains an ambiguous component: {}",
                path.display()
            ),
        ));
    }
    Ok((filesystem_root, relative))
}

#[cfg(target_os = "macos")]
fn rewrite_verified_system_directory_alias(path: &Path) -> std::io::Result<PathBuf> {
    let aliases = [
        (Path::new("/var"), Path::new("/private/var")),
        (Path::new("/tmp"), Path::new("/private/tmp")),
    ];
    let Some((alias, target)) = aliases
        .into_iter()
        .find(|(alias, _)| path.starts_with(alias))
    else {
        return Ok(path.to_path_buf());
    };

    let alias_metadata = std::fs::symlink_metadata(alias)?;
    let target_metadata = std::fs::symlink_metadata(target)?;
    let resolved = std::fs::canonicalize(alias)?;
    if !alias_metadata.file_type().is_symlink()
        || target_metadata.file_type().is_symlink()
        || !target_metadata.is_dir()
        || resolved.as_path() != target
    {
        return Err(std::io::Error::other(format!(
            "system directory alias {} is not the verified {} mapping",
            alias.display(),
            target.display()
        )));
    }
    Ok(target.join(path.strip_prefix(alias).expect("prefix checked above")))
}

#[cfg(any(windows, all(unix, not(target_os = "macos"))))]
fn rewrite_verified_system_directory_alias(path: &Path) -> std::io::Result<PathBuf> {
    Ok(path.to_path_buf())
}

#[cfg(any(unix, windows))]
fn open_absolute_directory_nofollow(
    path: &Path,
) -> std::io::Result<(cap_std::fs::Dir, cap_std::fs::Dir, PathBuf)> {
    let path = rewrite_verified_system_directory_alias(path)?;
    let (filesystem_root_path, relative) = absolute_path_from_filesystem_root(&path)?;
    let filesystem_root =
        cap_std::fs::Dir::open_ambient_dir(&filesystem_root_path, cap_std::ambient_authority())?;
    let directory = open_relative_directory_nofollow(&filesystem_root, &relative)?;
    Ok((filesystem_root, directory, relative))
}

#[cfg(any(unix, windows))]
fn open_absolute_session_directory_nofollow(path: &Path) -> std::io::Result<cap_std::fs::Dir> {
    let path = rewrite_verified_system_directory_alias(path)?;
    let (filesystem_root_path, relative) = absolute_path_from_filesystem_root(&path)?;
    let session_name = relative.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("session path has no final component: {}", path.display()),
        )
    })?;
    let parent_relative = relative.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("session path has no parent: {}", path.display()),
        )
    })?;
    let filesystem_root =
        cap_std::fs::Dir::open_ambient_dir(&filesystem_root_path, cap_std::ambient_authority())?;
    let parent = open_relative_directory_nofollow(&filesystem_root, parent_relative)?;
    let before = parent.symlink_metadata(session_name)?;
    if metadata_is_link_like(&before) || !before.is_dir() {
        return Err(std::io::Error::other(
            "ambient session path is link-like or not a directory",
        ));
    }
    let opened = open_session_directory_for_cleanup(&parent, session_name)?;
    let after = parent.symlink_metadata(session_name)?;
    if metadata_is_link_like(&after)
        || !after.is_dir()
        || !same_directory_metadata(&before, &after)
        || !same_directory_metadata(&opened.dir_metadata()?, &after)
    {
        return Err(std::io::Error::other(
            "ambient session path changed while it was opened",
        ));
    }
    Ok(opened)
}

#[cfg(any(unix, windows))]
fn open_relative_directory_nofollow(
    filesystem_root: &cap_std::fs::Dir,
    relative: &Path,
) -> std::io::Result<cap_std::fs::Dir> {
    let mut directory = filesystem_root.try_clone()?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "capability path contains a non-normal component: {}",
                    relative.display()
                ),
            ));
        };
        let before = directory.symlink_metadata(name)?;
        if metadata_is_link_like(&before) || !before.is_dir() {
            return Err(std::io::Error::other(format!(
                "capability path component is link-like or not a directory: {}",
                name.to_string_lossy()
            )));
        }
        let opened = directory.open_dir_nofollow(name)?;
        let after = directory.symlink_metadata(name)?;
        if metadata_is_link_like(&after)
            || !after.is_dir()
            || !same_directory_metadata(&before, &after)
            || !same_directory_metadata(&opened.dir_metadata()?, &after)
        {
            return Err(std::io::Error::other(format!(
                "capability path component changed while it was opened: {}",
                name.to_string_lossy()
            )));
        }
        directory = opened;
    }
    Ok(directory)
}

#[cfg(any(unix, windows))]
struct SessionCapabilities {
    repo_root: cap_std::fs::Dir,
    kin_root: cap_std::fs::Dir,
    runs_root: cap_std::fs::Dir,
    session_root: Option<cap_std::fs::Dir>,
    ambient_session_path: PathBuf,
    kin_name: OsString,
    session_name: OsString,
}

#[cfg(any(unix, windows))]
impl SessionCapabilities {
    fn create(
        layout: &kin_core::KinLayout,
        session_dir: &Path,
        session_name: OsString,
        after_child_created: impl FnOnce(&Path) -> Result<()>,
    ) -> Result<Self> {
        let kin_name = layout
            .root()
            .file_name()
            .ok_or_else(|| anyhow::anyhow!(".kin capability root must be a direct child"))?
            .to_os_string();
        let expected_kin_root = layout.working_dir().join(&kin_name);
        if kin_name != OsStr::new(".kin")
            || layout.root().as_os_str() != expected_kin_root.as_os_str()
        {
            anyhow::bail!(".kin capability root must be an exact direct child of the repository");
        }

        let (_, repo_root, _) =
            open_absolute_directory_nofollow(layout.working_dir()).map_err(|error| {
                anyhow::anyhow!(
                    "failed to bind repository capability root {} from its filesystem root: {}",
                    layout.working_dir().display(),
                    error
                )
            })?;
        let kin_metadata = repo_root.symlink_metadata(&kin_name).map_err(|error| {
            anyhow::anyhow!(
                "failed to inspect capability-rooted .kin directory: {}",
                error
            )
        })?;
        if metadata_is_link_like(&kin_metadata) || !kin_metadata.is_dir() {
            anyhow::bail!(".kin must be a direct, non-link directory");
        }
        let kin_root = repo_root.open_dir_nofollow(&kin_name).map_err(|error| {
            anyhow::anyhow!("failed to open capability-rooted .kin directory: {}", error)
        })?;
        let reopened_kin_metadata = repo_root.symlink_metadata(&kin_name).map_err(|error| {
            anyhow::anyhow!(
                "failed to re-inspect capability-rooted .kin directory: {}",
                error
            )
        })?;
        if metadata_is_link_like(&reopened_kin_metadata)
            || !reopened_kin_metadata.is_dir()
            || !same_directory_metadata(&kin_metadata, &reopened_kin_metadata)
            || !same_directory_metadata(&kin_root.dir_metadata()?, &reopened_kin_metadata)
        {
            anyhow::bail!(".kin changed while its capability was opened");
        }

        let runs_metadata = match kin_root.symlink_metadata("runs") {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                kin_root.create_dir("runs").map_err(|create_error| {
                    anyhow::anyhow!(
                        "failed to create capability-rooted runs directory: {}",
                        create_error
                    )
                })?;
                kin_root
                    .symlink_metadata("runs")
                    .map_err(|metadata_error| {
                        anyhow::anyhow!(
                            "failed to inspect newly created runs directory: {}",
                            metadata_error
                        )
                    })?
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "failed to inspect capability-rooted runs directory: {}",
                    error
                ))
            }
        };
        if metadata_is_link_like(&runs_metadata) || !runs_metadata.is_dir() {
            anyhow::bail!(".kin/runs must be a direct, non-link directory");
        }
        let runs_root = kin_root.open_dir_nofollow("runs").map_err(|error| {
            anyhow::anyhow!("failed to open capability-rooted runs directory: {}", error)
        })?;
        if !same_directory_metadata(&runs_metadata, &runs_root.dir_metadata()?) {
            anyhow::bail!(".kin/runs changed while its capability was opened");
        }

        runs_root.create_dir(&session_name).map_err(|error| {
            let reason = if error.kind() == std::io::ErrorKind::AlreadyExists {
                "session workspace must be a fresh direct child"
            } else {
                "failed to create fresh capability-rooted session workspace"
            };
            anyhow::anyhow!("{}: {}", reason, error)
        })?;
        let session_root = capture_fresh_empty_session_directory(&runs_root, &session_name)?;

        let capabilities = Self {
            repo_root,
            kin_root,
            runs_root,
            session_root: Some(session_root),
            ambient_session_path: session_dir.to_path_buf(),
            kin_name,
            session_name,
        };
        if let Err(error) = after_child_created(session_dir) {
            return Err(capabilities.cleanup_after_error(error));
        }
        if let Err(error) = capabilities.verify_direct_child_identity() {
            return Err(capabilities.cleanup_after_error(error));
        }
        Ok(capabilities)
    }

    fn session_root(&self) -> &cap_std::fs::Dir {
        self.session_root
            .as_ref()
            .expect("session capability is present until commit or cleanup")
    }

    fn verify_direct_child_identity(&self) -> Result<()> {
        let reopened_kin_metadata =
            self.repo_root
                .symlink_metadata(&self.kin_name)
                .map_err(|error| {
                    anyhow::anyhow!(
                        ".kin changed before session materialization completed: {}",
                        error
                    )
                })?;
        if metadata_is_link_like(&reopened_kin_metadata)
            || !reopened_kin_metadata.is_dir()
            || !same_directory_metadata(&self.kin_root.dir_metadata()?, &reopened_kin_metadata)
        {
            anyhow::bail!(".kin changed before session materialization completed");
        }
        let reopened_kin = self
            .repo_root
            .open_dir_nofollow(&self.kin_name)
            .map_err(|error| {
                anyhow::anyhow!(
                    ".kin changed before session materialization completed: {}",
                    error
                )
            })?;
        if !same_directory(&self.kin_root, &reopened_kin)? {
            anyhow::bail!(".kin changed before session materialization completed");
        }

        let reopened_runs_metadata = self.kin_root.symlink_metadata("runs").map_err(|error| {
            anyhow::anyhow!(
                ".kin/runs changed before session materialization completed: {}",
                error
            )
        })?;
        if metadata_is_link_like(&reopened_runs_metadata)
            || !reopened_runs_metadata.is_dir()
            || !same_directory_metadata(&self.runs_root.dir_metadata()?, &reopened_runs_metadata)
        {
            anyhow::bail!(".kin/runs changed before session materialization completed");
        }
        let reopened_runs = self.kin_root.open_dir_nofollow("runs").map_err(|error| {
            anyhow::anyhow!(
                ".kin/runs changed before session materialization completed: {}",
                error
            )
        })?;
        if !same_directory(&self.runs_root, &reopened_runs)? {
            anyhow::bail!(".kin/runs changed before session materialization completed");
        }

        let reopened_session_metadata = self
            .runs_root
            .symlink_metadata(&self.session_name)
            .map_err(|error| {
                anyhow::anyhow!(
                    "session workspace changed before materialization completed: {}",
                    error
                )
            })?;
        if metadata_is_link_like(&reopened_session_metadata)
            || !reopened_session_metadata.is_dir()
            || !same_directory_metadata(
                &self.session_root().dir_metadata()?,
                &reopened_session_metadata,
            )
        {
            anyhow::bail!("session workspace changed before materialization completed");
        }
        let reopened_session =
            open_session_directory_for_cleanup(&self.runs_root, &self.session_name).map_err(
                |error| {
                    anyhow::anyhow!(
                        "session workspace changed before materialization completed: {}",
                        error
                    )
                },
            )?;
        if !same_directory(self.session_root(), &reopened_session)? {
            anyhow::bail!("session workspace changed before materialization completed");
        }

        let ambient_session = open_absolute_session_directory_nofollow(&self.ambient_session_path)
            .map_err(|error| {
                anyhow::anyhow!(
                    "ambient session workspace changed before materialization completed: {}",
                    error
                )
            })?;
        if !same_directory(self.session_root(), &ambient_session)? {
            anyhow::bail!("ambient session workspace changed before materialization completed");
        }
        Ok(())
    }

    fn commit(mut self) {
        self.session_root.take();
    }

    fn cleanup(mut self) -> std::io::Result<()> {
        match self.session_root.take() {
            Some(session_root) => cleanup_open_session_directory(session_root),
            None => Ok(()),
        }
    }

    fn cleanup_after_error(self, error: anyhow::Error) -> anyhow::Error {
        match self.cleanup() {
            Ok(()) => error,
            Err(cleanup_error) => error.context(format!(
                "capability-rooted retained session cleanup also failed: {}",
                cleanup_error
            )),
        }
    }
}

#[cfg(any(unix, windows))]
fn capture_fresh_empty_session_directory(
    runs_root: &cap_std::fs::Dir,
    session_name: &OsStr,
) -> Result<cap_std::fs::Dir> {
    // Portable mkdir does not return a directory handle. Ownership begins only
    // after the opened object matches both pathname observations and is empty.
    // An empty directory substituted inside this create-to-open window is not
    // distinguishable; nonempty substitutes fail closed and are never recursed.
    let capture = (|| {
        let created_metadata = runs_root.symlink_metadata(session_name).map_err(|error| {
            anyhow::anyhow!(
                "failed to inspect newly created session workspace: {}",
                error
            )
        })?;
        if metadata_is_link_like(&created_metadata) || !created_metadata.is_dir() {
            anyhow::bail!("new session workspace is not a direct, non-link directory");
        }

        let session_root =
            open_session_directory_for_cleanup(runs_root, session_name).map_err(|error| {
                anyhow::anyhow!("failed to open newly created session capability: {}", error)
            })?;
        let reopened_session_metadata =
            runs_root.symlink_metadata(session_name).map_err(|error| {
                anyhow::anyhow!(
                    "failed to re-inspect newly created session workspace: {}",
                    error
                )
            })?;
        let session_handle_metadata = session_root.dir_metadata().map_err(|error| {
            anyhow::anyhow!(
                "failed to inspect newly opened session capability: {}",
                error
            )
        })?;
        if metadata_is_link_like(&reopened_session_metadata)
            || !reopened_session_metadata.is_dir()
            || metadata_is_link_like(&session_handle_metadata)
            || !session_handle_metadata.is_dir()
            || !same_directory_metadata(&created_metadata, &reopened_session_metadata)
            || !same_directory_metadata(&session_handle_metadata, &reopened_session_metadata)
        {
            anyhow::bail!("session workspace changed while its capability was opened");
        }
        if !directory_is_empty(&session_root).map_err(|error| {
            anyhow::anyhow!(
                "failed to inspect fresh session workspace contents: {}",
                error
            )
        })? {
            anyhow::bail!("new session workspace was not empty at ownership capture");
        }
        Ok(session_root)
    })();

    match capture {
        Ok(session_root) => Ok(session_root),
        Err(error) => Err(cleanup_unvalidated_session_child(
            runs_root,
            session_name,
            error,
        )),
    }
}

#[cfg(any(unix, windows))]
fn directory_is_empty(directory: &cap_std::fs::Dir) -> std::io::Result<bool> {
    let mut entries = directory.entries()?;
    match entries.next() {
        None => Ok(true),
        Some(Ok(_)) => Ok(false),
        Some(Err(error)) => Err(error),
    }
}

#[cfg(unix)]
fn open_session_directory_for_cleanup(
    parent: &cap_std::fs::Dir,
    name: &OsStr,
) -> std::io::Result<cap_std::fs::Dir> {
    parent.open_dir_nofollow(name)
}

#[cfg(windows)]
fn open_session_directory_for_cleanup(
    parent: &cap_std::fs::Dir,
    name: &OsStr,
) -> std::io::Result<cap_std::fs::Dir> {
    let file = open_windows_entry_for_deletion(parent, name)?;
    let metadata = file.metadata()?;
    if metadata_is_link_like(&metadata) || !metadata.is_dir() {
        return Err(std::io::Error::other(
            "session cleanup handle is link-like or not a directory",
        ));
    }
    Ok(cap_std::fs::Dir::from_std_file(file.into_std()))
}

#[cfg(unix)]
fn cleanup_open_session_directory(session_root: cap_std::fs::Dir) -> std::io::Result<()> {
    session_root.remove_open_dir_all()
}

#[cfg(windows)]
fn cleanup_open_session_directory(session_root: cap_std::fs::Dir) -> std::io::Result<()> {
    remove_windows_directory_contents(&session_root)?;
    mark_windows_directory_for_deletion(session_root)
}

#[cfg(unix)]
fn cleanup_unvalidated_session_leaf(
    runs_root: &cap_std::fs::Dir,
    session_name: &OsStr,
) -> std::io::Result<()> {
    runs_root.remove_dir(session_name)
}

#[cfg(windows)]
fn cleanup_unvalidated_session_leaf(
    runs_root: &cap_std::fs::Dir,
    session_name: &OsStr,
) -> std::io::Result<()> {
    let entry = open_windows_entry_for_deletion(runs_root, session_name)?;
    let metadata = entry.metadata()?;
    if metadata_is_link_like(&metadata) || !metadata.is_dir() {
        return Err(std::io::Error::other(
            "unvalidated session child is link-like or not a directory",
        ));
    }
    let directory = cap_std::fs::Dir::from_std_file(entry.into_std());
    if !directory_is_empty(&directory)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::DirectoryNotEmpty,
            "unvalidated session child is not empty",
        ));
    }
    mark_windows_directory_for_deletion(directory)
}

#[cfg(windows)]
fn remove_windows_directory_contents(directory: &cap_std::fs::Dir) -> std::io::Result<()> {
    let entries = directory.entries()?;
    for entry in entries {
        let name = entry?.file_name();
        let child = match open_windows_entry_for_deletion(directory, &name) {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let metadata = child.metadata()?;
        if metadata.is_dir() && !metadata_is_link_like(&metadata) {
            let child_directory = cap_std::fs::Dir::from_std_file(child.into_std());
            remove_windows_directory_contents(&child_directory)?;
            mark_windows_directory_for_deletion(child_directory)?;
        } else {
            mark_windows_file_for_deletion(&child)?;
            drop(child);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_entry_for_deletion(
    parent: &cap_std::fs::Dir,
    name: &OsStr,
) -> std::io::Result<cap_std::fs::File> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
    use cap_std::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::GENERIC_READ;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = cap_std::fs::OpenOptions::new();
    // `maybe_dir(true)` deliberately strips FILE_SHARE_DELETE in cap-primitives.
    // This handle must instead stay rename-compatible while retaining exact,
    // no-follow DELETE authority, so request directory semantics directly.
    options
        .access_mode(GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .follow(FollowSymlinks::No);
    parent.open_with(name, &options)
}

#[cfg(windows)]
fn mark_windows_file_for_deletion(file: &cap_std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    mark_windows_handle_for_deletion(file.as_raw_handle().cast())
}

#[cfg(windows)]
fn mark_windows_directory_for_deletion(directory: cap_std::fs::Dir) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    let directory = directory.into_std_file();
    mark_windows_handle_for_deletion(directory.as_raw_handle().cast())?;
    drop(directory);
    Ok(())
}

#[cfg(windows)]
fn mark_windows_handle_for_deletion(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> std::io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let removed = unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if removed == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn cleanup_unvalidated_session_child(
    runs_root: &cap_std::fs::Dir,
    session_name: &OsStr,
    error: anyhow::Error,
) -> anyhow::Error {
    match cleanup_unvalidated_session_leaf(runs_root, session_name) {
        Ok(()) => error,
        Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => error,
        Err(cleanup_error) => error.context(format!(
            "capability-rooted unvalidated session cleanup also failed: {}",
            cleanup_error
        )),
    }
}

#[cfg(any(unix, windows))]
impl Drop for SessionCapabilities {
    fn drop(&mut self) {
        if let Some(session_root) = self.session_root.take() {
            let _ = cleanup_open_session_directory(session_root);
        }
    }
}

#[cfg(any(unix, windows))]
fn materialize_preflighted_blob_tree(
    layout: &kin_core::KinLayout,
    session_dir: &Path,
    session_name: OsString,
    blob_store: &kin_blobs::BlobStore,
    entries: &[PreflightedBlob],
    base_head: String,
    after_child_created: impl FnOnce(&Path) -> Result<()>,
    after_root_created: impl FnOnce(&Path) -> Result<()>,
) -> Result<MaterializedWorkspace> {
    let capabilities =
        SessionCapabilities::create(layout, session_dir, session_name, after_child_created)?;
    let result = (|| {
        after_root_created(session_dir)?;
        for entry in entries {
            let blob_hash = kin_blobs::Hash256(*entry.hash.as_bytes());
            let content = blob_store.read(&blob_hash).map_err(|error| {
                anyhow::anyhow!("failed to read blob for {}: {}", entry.file_id, error)
            })?;
            if let Some(parent) = entry
                .relative_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                capabilities
                    .session_root()
                    .create_dir_all(parent)
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "failed to create capability-rooted parent for '{}': {}",
                            entry.file_id,
                            error
                        )
                    })?;
            }

            let mut options = cap_std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            let mut file = capabilities
                .session_root()
                .open_with(&entry.relative_path, &options)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "failed to create capability-rooted graph file '{}': {}",
                        entry.file_id,
                        error
                    )
                })?;
            file.write_all(&content).map_err(|error| {
                anyhow::anyhow!(
                    "failed to write capability-rooted graph file '{}': {}",
                    entry.file_id,
                    error
                )
            })?;
        }

        super::session_base::record_materialized_base_from_dir(
            capabilities.session_root(),
            Some(base_head),
        )?;
        let workspace = MaterializedWorkspace::from_existing(
            session_dir.to_path_buf(),
            MaterializeStrategy::Copy,
            MaterializationSourceKind::BlobTree,
        );
        capabilities.verify_direct_child_identity()?;
        Ok(workspace)
    })();

    match result {
        Ok(workspace) => {
            capabilities.commit();
            Ok(workspace)
        }
        Err(error) => match capabilities.cleanup() {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(error.context(format!(
                "capability-rooted session cleanup also failed: {}",
                cleanup_error
            ))),
        },
    }
}

#[cfg(unix)]
fn same_directory_metadata(left: &cap_std::fs::Metadata, right: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn same_directory_metadata(left: &cap_std::fs::Metadata, right: &cap_std::fs::Metadata) -> bool {
    use cap_fs_ext::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(any(unix, windows))]
fn same_directory(left: &cap_std::fs::Dir, right: &cap_std::fs::Dir) -> Result<bool> {
    Ok(same_directory_metadata(
        &left.dir_metadata()?,
        &right.dir_metadata()?,
    ))
}

#[cfg(unix)]
fn metadata_is_link_like(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn metadata_is_link_like(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt;
    metadata.file_type().is_symlink()
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
}

pub fn materialize_session_workspace(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &SessionWorkspaceRequest,
) -> Result<SessionWorkspaceResponse> {
    let strategy = request
        .strategy
        .as_deref()
        .map(str::parse::<MaterializeStrategy>)
        .transpose()
        .map_err(|error| anyhow::anyhow!("{}", error))?;
    let session_dir = std::path::PathBuf::from(&request.session_dir);
    // `entity:`/`artifact:` scopes resolve against graph truth here, so every
    // session surface (shell, exec, open) shares one scope vocabulary and an
    // unresolvable scope fails loud instead of silently widening.
    let scope = super::exec::resolve_materialization_scope(graph, request.scope.clone())?;
    let workspace = create_session_workspace_from_graph(
        layout,
        graph,
        &session_dir,
        strategy,
        scope.as_deref(),
    )?;

    Ok(SessionWorkspaceResponse {
        root: workspace.root.display().to_string(),
        strategy: workspace.strategy.to_string(),
        source_kind: match workspace.source_kind() {
            MaterializationSourceKind::BlobTree => "blob-tree".to_string(),
            MaterializationSourceKind::Filesystem => "filesystem".to_string(),
        },
    })
}

fn validate_session_dir(layout: &kin_core::KinLayout, session_dir: &Path) -> Result<OsString> {
    let runs_dir = layout.runs_dir();
    if !session_dir.is_absolute() {
        anyhow::bail!(
            "session workspace must be an absolute path under {}",
            runs_dir.display()
        );
    }

    let relative = session_dir.strip_prefix(&runs_dir).map_err(|_| {
        anyhow::anyhow!(
            "session workspace must be an absolute path under {}",
            runs_dir.display()
        )
    })?;
    let mut components = relative.components();
    let session_name = match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) => name.to_os_string(),
        _ => anyhow::bail!(
            "session workspace must be a direct child directory under {}",
            runs_dir.display()
        ),
    };
    let expected_session_dir = runs_dir.join(&session_name);
    if session_dir.as_os_str() != expected_session_dir.as_os_str() {
        anyhow::bail!(
            "session workspace must use an unambiguous direct child path under {}",
            runs_dir.display()
        );
    }
    let session_name_text = session_name
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("session workspace child name must be valid UTF-8"))?;
    validate_portable_component(session_name_text, "session workspace", session_name_text)?;

    Ok(session_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_core::init as init_repo;
    use kin_model::{
        ArtifactDelta, ArtifactDeltaKind, AuthorId, BranchName, ChangeStore, FilePathId, Hash256,
        SemanticChange, SemanticChangeId,
    };
    use std::fs;

    fn commit_id(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    fn write_native_graph_file(
        layout: &kin_core::KinLayout,
        rel_path: &str,
        content: &[u8],
    ) -> anyhow::Result<()> {
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())?;
        let blob_hash = blob_store.write(content)?;
        let snap = crate::backend::open_kindb_snapshot(layout)?;
        let graph = snap.graph();
        let branch_name = BranchName::new("main");
        let branch = graph.get_branch(&branch_name)?.expect("main branch");
        let change = SemanticChange {
            id: commit_id(9),
            parents: vec![branch.head],
            timestamp: kin_model::Timestamp::now(),
            author: AuthorId::new("test"),
            message: "add artifact".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![ArtifactDelta {
                file_id: FilePathId::new(rel_path),
                kind: ArtifactDeltaKind::Added,
                old_hash: None,
                new_hash: Some(blob_hash),
            }],
            projected_files: vec![FilePathId::new(rel_path)],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: Some(branch_name.clone()),
        };
        graph.create_change(&change)?;
        graph.update_branch_head(&branch_name, &change.id)?;
        snap.save()?;
        Ok(())
    }

    #[test]
    fn native_mode_rejects_non_copy_strategies_before_file_authority_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("source-root")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        // No mode to set — there's one mode: Kin.

        let graph = kin_db::InMemoryGraph::new();
        let err = create_session_workspace_from_graph(
            &layout,
            &graph,
            &dir.path().join("runs/session-1"),
            Some(MaterializeStrategy::Hardlink),
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("only supports `copy`"));
    }

    #[test]
    fn session_workspace_path_validation_rejects_parent_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        let escaped = layout.root().join("runs/session-1/../../outside");

        let err = validate_session_dir(&layout, &escaped)
            .unwrap_err()
            .to_string();

        assert!(err.contains("must be a direct child"));
    }

    #[test]
    fn session_workspace_path_validation_requires_an_unambiguous_direct_child_of_runs() {
        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;

        let root_err = validate_session_dir(&layout, &layout.runs_dir())
            .unwrap_err()
            .to_string();
        assert!(root_err.contains("must be a direct child"));

        let outside_err = validate_session_dir(&layout, &layout.root().join("outside"))
            .unwrap_err()
            .to_string();
        assert!(outside_err.contains("must be an absolute path under"));

        let nested_err = validate_session_dir(&layout, &layout.runs_dir().join("one/two"))
            .unwrap_err()
            .to_string();
        assert!(nested_err.contains("must be a direct child"));

        let repeated_separator = PathBuf::from(format!(
            "{}//session-1",
            layout.runs_dir().to_string_lossy()
        ));
        let separator_err = validate_session_dir(&layout, &repeated_separator)
            .unwrap_err()
            .to_string();
        assert!(separator_err.contains("unambiguous direct child"));

        let child = validate_session_dir(&layout, &layout.runs_dir().join("session-1")).unwrap();
        assert_eq!(child, "session-1");
    }

    #[test]
    fn portable_graph_paths_reject_roots_prefixes_parent_components_and_separator_ambiguity() {
        for invalid in [
            "",
            "/absolute.rs",
            "../outside.rs",
            "src/../outside.rs",
            "./src.rs",
            "src//lib.rs",
            "src/lib.rs/",
            "src\\lib.rs",
            "C:/outside.rs",
            "C:outside.rs",
            "src/file:stream",
            "src/NUL.txt",
            "src/COM0.txt",
            "src/LPT0.txt",
            "src/COM¹.txt",
            "src/COM².txt",
            "src/COM³.txt",
            "src/LPT¹.txt",
            "src/LPT².txt",
            "src/LPT³.txt",
            "src/COM1 .txt",
            "src/lpt9 .txt",
            "src/trailing.",
            ".kin-session/reconcile-base.json",
            "src/.KIN/manifest.json",
            ".GiT/config",
        ] {
            assert!(
                validate_portable_relative_path(invalid, "graph FilePathId").is_err(),
                "path should be rejected on every platform: {invalid:?}"
            );
        }

        assert_eq!(
            validate_portable_relative_path("src/lib.rs", "graph FilePathId").unwrap(),
            PathBuf::from("src/lib.rs")
        );
        assert_eq!(
            validate_portable_relative_path("README.md", "graph FilePathId").unwrap(),
            PathBuf::from("README.md")
        );
    }

    #[test]
    fn portable_graph_preflight_rejects_ascii_case_collisions() {
        let mut tree = HashMap::new();
        tree.insert(
            FilePathId::new("src/Foo.rs"),
            Hash256::from_bytes([0x41; 32]),
        );
        tree.insert(
            FilePathId::new("src/foo.rs"),
            Hash256::from_bytes([0x42; 32]),
        );

        let error = preflight_blob_tree(&tree, None).unwrap_err().to_string();

        assert!(error.contains("collides portably"), "{error}");
    }

    #[test]
    fn portable_graph_preflight_rejects_composed_and_decomposed_unicode_collisions() {
        let mut tree = HashMap::new();
        tree.insert(
            FilePathId::new("src/caf\u{e9}.rs"),
            Hash256::from_bytes([0x51; 32]),
        );
        tree.insert(
            FilePathId::new("src/cafe\u{301}.rs"),
            Hash256::from_bytes([0x52; 32]),
        );

        let error = preflight_blob_tree(&tree, None).unwrap_err().to_string();

        assert!(error.contains("collides portably"), "{error}");
    }

    #[test]
    fn portable_graph_preflight_rejects_non_ascii_casefold_collisions() {
        let mut tree = HashMap::new();
        tree.insert(
            FilePathId::new("src/Stra\u{df}e.rs"),
            Hash256::from_bytes([0x53; 32]),
        );
        tree.insert(
            FilePathId::new("src/STRASSE.rs"),
            Hash256::from_bytes([0x54; 32]),
        );

        let error = preflight_blob_tree(&tree, None).unwrap_err().to_string();

        assert!(error.contains("collides portably"), "{error}");
    }

    #[test]
    fn portable_graph_preflight_rejects_case_folded_file_parent_collisions() {
        let mut tree = HashMap::new();
        tree.insert(FilePathId::new("Foo"), Hash256::from_bytes([0x43; 32]));
        tree.insert(
            FilePathId::new("foo/bar.rs"),
            Hash256::from_bytes([0x44; 32]),
        );

        let error = preflight_blob_tree(&tree, None).unwrap_err().to_string();

        assert!(error.contains("conflicts portably"), "{error}");
    }

    #[test]
    fn graph_path_preflight_rejects_escape_before_creating_session_child() {
        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        write_native_graph_file(&layout, "../outside.txt", b"must not escape\n").unwrap();
        let session_dir = layout.runs_dir().join("session-invalid-graph-path");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();

        let error = create_session_workspace_from_graph(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("graph FilePathId"), "{error}");
        assert!(!session_dir.exists());
        assert!(!layout.runs_dir().join("outside.txt").exists());
        assert!(!layout.root().join("outside.txt").exists());
    }

    #[test]
    fn graph_path_preflight_rejects_windows_device_aliases_before_creating_session_child() {
        for (case, device_alias) in [
            "COM0.txt",
            "LPT0.txt",
            "COM¹.txt",
            "COM².txt",
            "COM³.txt",
            "LPT¹.txt",
            "LPT².txt",
            "LPT³.txt",
            "COM1 .txt",
            "lpt9 .txt",
        ]
        .into_iter()
        .enumerate()
        {
            let dir = tempfile::tempdir().unwrap();
            let layout = init_repo(dir.path()).unwrap().layout;
            let graph_path = format!("src/{device_alias}");
            write_native_graph_file(&layout, &graph_path, b"must not materialize\n").unwrap();
            let session_dir = layout
                .runs_dir()
                .join(format!("session-device-alias-{case}"));
            let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();

            let error = create_session_workspace_from_graph(
                &layout,
                snap.graph().as_ref(),
                &session_dir,
                None,
                None,
            )
            .unwrap_err()
            .to_string();

            assert!(
                error.contains("reserved platform path component"),
                "unexpected error for {device_alias:?}: {error}"
            );
            assert!(
                !session_dir.exists(),
                "preflight created session child for {device_alias:?}"
            );
        }
    }

    #[test]
    fn graph_path_preflight_rejects_overlong_utf16_component_before_creating_session_child() {
        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        let overlong_component = "\u{1f600}".repeat(128);
        let graph_path = format!("{overlong_component}/payload.txt");
        write_native_graph_file(&layout, &graph_path, b"must not materialize\n").unwrap();
        let session_dir = layout.runs_dir().join("session-overlong-graph-path");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();

        let error = create_session_workspace_from_graph(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("255 UTF-16 code units"), "{error}");
        assert!(!session_dir.exists());
    }

    #[test]
    fn graph_path_preflight_rejects_overlong_utf8_component_before_creating_session_child() {
        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        let overlong_component = "\u{e9}".repeat(128);
        assert!(overlong_component.encode_utf16().count() <= 255);
        let graph_path = format!("{overlong_component}/payload.txt");
        write_native_graph_file(&layout, &graph_path, b"must not materialize\n").unwrap();
        let session_dir = layout.runs_dir().join("session-overlong-utf8-graph-path");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();

        let error = create_session_workspace_from_graph(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("255 UTF-8 bytes"), "{error}");
        assert!(!session_dir.exists());
    }

    #[test]
    fn graph_path_preflight_reserves_session_metadata_before_creating_session_child() {
        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        write_native_graph_file(
            &layout,
            ".KIN-SESSION/reconcile-base.json",
            b"must not shadow runtime metadata\n",
        )
        .unwrap();
        let session_dir = layout.runs_dir().join("session-reserved-metadata");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();

        let error = create_session_workspace_from_graph(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("reserved control-plane component"),
            "{error}"
        );
        assert!(!session_dir.exists());
    }

    #[test]
    fn scope_path_preflight_rejects_escape_before_creating_session_child() {
        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        write_native_graph_file(&layout, "src/lib.rs", b"graph truth\n").unwrap();
        let session_dir = layout.runs_dir().join("session-invalid-scope");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();

        let error = create_session_workspace_from_graph(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            Some("file:../outside.txt"),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("materialization scope"), "{error}");
        assert!(!session_dir.exists());
    }

    #[test]
    fn session_workspace_creation_rejects_existing_child_without_removing_it() {
        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        write_native_graph_file(&layout, "src/lib.rs", b"graph truth\n").unwrap();
        let session_dir = layout.runs_dir().join("session-existing");
        fs::create_dir(&session_dir).unwrap();
        fs::write(session_dir.join("owner.txt"), "preserve me\n").unwrap();
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();

        let error = create_session_workspace_from_graph(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("fresh direct child"), "{error}");
        assert_eq!(
            fs::read_to_string(session_dir.join("owner.txt")).unwrap(),
            "preserve me\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_kin_root_is_rejected_before_session_child_creation() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        write_native_graph_file(&layout, "src/lib.rs", b"graph truth\n").unwrap();
        let session_dir = layout.runs_dir().join("session-linked-kin-root");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let kin_root = layout.root().to_path_buf();
        let moved_kin_root = dir.path().join(".kin-before-link");

        fs::rename(&kin_root, &moved_kin_root).unwrap();
        symlink(&moved_kin_root, &kin_root).unwrap();

        let error = create_session_workspace_from_graph(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            None,
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains(".kin must be a direct, non-link directory"),
            "{error}"
        );
        assert!(!moved_kin_root.join("runs/session-linked-kin-root").exists());

        fs::remove_file(&kin_root).unwrap();
        fs::rename(&moved_kin_root, &kin_root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn replaced_session_child_cannot_redirect_validation_or_cleanup() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        let outside = dir.path().join("outside-session-child");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("sentinel.txt"), "outside\n").unwrap();
        write_native_graph_file(&layout, "nested/payload.txt", b"graph payload\n").unwrap();
        let session_dir = layout.runs_dir().join("session-child-swap");
        let moved_session = layout.runs_dir().join("session-child-before-swap");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let attack_moved_session = moved_session.clone();
        let attack_outside = outside.clone();

        let error = create_session_workspace_from_graph_with_child_hook(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            None,
            move |child| {
                fs::rename(child, &attack_moved_session)?;
                symlink(&attack_outside, child)?;
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("session workspace changed"), "{error}");
        assert_eq!(
            fs::read_to_string(outside.join("sentinel.txt")).unwrap(),
            "outside\n"
        );
        assert!(!outside.join("nested/payload.txt").exists());
        assert!(!outside.join(".kin-session").exists());
        assert!(
            fs::symlink_metadata(&session_dir)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the replacement must not be touched after capability capture"
        );
        assert!(
            !moved_session.exists(),
            "only the displaced retained child may be cleaned up"
        );
        fs::remove_file(&session_dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn direct_directory_substitution_after_capture_preserves_the_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        write_native_graph_file(&layout, "nested/payload.txt", b"graph payload\n").unwrap();
        let session_dir = layout.runs_dir().join("session-direct-substitution");
        let moved_session = layout
            .runs_dir()
            .join("session-direct-substitution-retained");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let attack_moved_session = moved_session.clone();

        let error = create_session_workspace_from_graph_with_child_hook(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            None,
            move |child| {
                fs::rename(child, &attack_moved_session)?;
                fs::create_dir(child)?;
                fs::write(child.join("sentinel.txt"), "replacement\n")?;
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("session workspace changed"), "{error}");
        assert_eq!(
            fs::read_to_string(session_dir.join("sentinel.txt")).unwrap(),
            "replacement\n"
        );
        assert!(!session_dir.join("nested/payload.txt").exists());
        assert!(!session_dir.join(".kin-session").exists());
        assert!(
            !moved_session.exists(),
            "only the displaced retained child may be cleaned up"
        );
        fs::remove_dir_all(&session_dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn create_to_open_nonempty_substitution_fails_without_recursive_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let runs = dir.path().join("runs");
        let session = runs.join("session-raced");
        let moved_session = runs.join("session-created");
        fs::create_dir(&runs).unwrap();
        let runs_root =
            cap_std::fs::Dir::open_ambient_dir(&runs, cap_std::ambient_authority()).unwrap();
        runs_root.create_dir("session-raced").unwrap();

        fs::rename(&session, &moved_session).unwrap();
        fs::create_dir(&session).unwrap();
        fs::write(session.join("sentinel.txt"), "replacement\n").unwrap();

        let error = capture_fresh_empty_session_directory(&runs_root, OsStr::new("session-raced"))
            .unwrap_err();
        let error = format!("{error:#}");

        assert!(error.contains("not empty at ownership capture"), "{error}");
        assert_eq!(
            fs::read_to_string(session.join("sentinel.txt")).unwrap(),
            "replacement\n"
        );
        assert!(moved_session.is_dir());
        fs::remove_dir_all(&session).unwrap();
        fs::remove_dir(&moved_session).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn nested_symlink_injected_after_root_creation_cannot_escape_and_is_cleaned_up() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("sentinel.txt"), "outside\n").unwrap();
        write_native_graph_file(&layout, "nested/payload.txt", b"graph payload\n").unwrap();
        let session_dir = layout.runs_dir().join("session-nested-link");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();

        let error = create_session_workspace_from_graph_with_hook(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            None,
            |root| {
                symlink(&outside, root.join("nested"))?;
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("capability-rooted"), "{error}");
        assert_eq!(
            fs::read_to_string(outside.join("sentinel.txt")).unwrap(),
            "outside\n"
        );
        assert!(!outside.join("payload.txt").exists());
        assert!(!outside.join(".kin-session").exists());
        assert!(!session_dir.exists(), "failed session must be cleaned up");
    }

    #[cfg(unix)]
    #[test]
    fn parent_swap_during_materialization_cannot_redirect_writes_or_cleanup() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        let runs_dir = layout.runs_dir();
        let moved_runs = layout.root().join("runs-before-swap");
        let outside = dir.path().join("outside-parent");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("sentinel.txt"), "outside\n").unwrap();
        write_native_graph_file(&layout, "nested/payload.txt", b"graph payload\n").unwrap();
        let session_dir = runs_dir.join("session-parent-swap");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let attack_runs = runs_dir.clone();
        let attack_moved = moved_runs.clone();
        let attack_outside = outside.clone();

        let error = create_session_workspace_from_graph_with_hook(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            None,
            move |_| {
                fs::rename(&attack_runs, &attack_moved)?;
                symlink(&attack_outside, &attack_runs)?;
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains(".kin/runs changed"), "{error}");
        assert_eq!(
            fs::read_to_string(outside.join("sentinel.txt")).unwrap(),
            "outside\n"
        );
        assert!(!outside.join("session-parent-swap").exists());
        assert!(!moved_runs.join("session-parent-swap").exists());

        fs::remove_file(&runs_dir).unwrap();
        fs::rename(&moved_runs, &runs_dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn outer_repo_swap_cannot_rebind_the_returned_ambient_session_path() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let repo = parent.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let layout = init_repo(&repo).unwrap().layout;
        write_native_graph_file(&layout, "nested/payload.txt", b"graph payload\n").unwrap();
        let session_dir = layout.runs_dir().join("session-outer-repo-swap");
        let moved_repo = parent.path().join("repo-before-swap");
        let replacement_session = session_dir.clone();
        let attack_repo = repo.clone();
        let attack_moved_repo = moved_repo.clone();
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();

        let error = create_session_workspace_from_graph_with_hook(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            None,
            move |_| {
                fs::rename(&attack_repo, &attack_moved_repo)?;
                fs::create_dir_all(attack_repo.join(".kin"))?;
                symlink(
                    attack_moved_repo.join(".kin/objects"),
                    attack_repo.join(".kin/objects"),
                )?;
                fs::create_dir_all(&replacement_session)?;
                fs::write(replacement_session.join("sentinel.txt"), "replacement\n")?;
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("ambient session workspace changed"),
            "{error}"
        );
        assert_eq!(
            fs::read_to_string(session_dir.join("sentinel.txt")).unwrap(),
            "replacement\n"
        );
        assert!(!session_dir.join("nested/payload.txt").exists());
        assert!(
            !moved_repo
                .join(".kin/runs/session-outer-repo-swap")
                .exists(),
            "the displaced capability-rooted session must be cleaned up"
        );
    }

    #[cfg(windows)]
    #[test]
    fn nested_junction_injected_after_root_creation_cannot_escape_and_is_cleaned_up() {
        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("sentinel.txt"), "outside\n").unwrap();
        write_native_graph_file(&layout, "nested/payload.txt", b"graph payload\n").unwrap();
        let session_dir = layout.runs_dir().join("session-nested-junction");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();

        let error = create_session_workspace_from_graph_with_hook(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            None,
            |root| {
                let command = format!(
                    "mklink /J \"{}\" \"{}\"",
                    root.join("nested").display(),
                    outside.display()
                );
                let output = std::process::Command::new("cmd")
                    .args(["/C", &command])
                    .output()?;
                anyhow::ensure!(
                    output.status.success(),
                    "failed to create test junction: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("capability-rooted"), "{error}");
        assert_eq!(
            fs::read_to_string(outside.join("sentinel.txt")).unwrap(),
            "outside\n"
        );
        assert!(!outside.join("payload.txt").exists());
        assert!(!outside.join(".kin-session").exists());
        assert!(!session_dir.exists(), "failed session must be cleaned up");
    }

    #[cfg(windows)]
    #[test]
    fn replaced_session_child_junction_cannot_redirect_validation_or_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        let outside = dir.path().join("outside-session-child");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("sentinel.txt"), "outside\n").unwrap();
        write_native_graph_file(&layout, "nested/payload.txt", b"graph payload\n").unwrap();
        let session_dir = layout.runs_dir().join("session-child-swap");
        let moved_session = layout.runs_dir().join("session-child-before-swap");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let attack_moved_session = moved_session.clone();
        let attack_outside = outside.clone();

        let error = create_session_workspace_from_graph_with_child_hook(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            None,
            move |child| {
                fs::rename(child, &attack_moved_session)?;
                let command = format!(
                    "mklink /J \"{}\" \"{}\"",
                    child.display(),
                    attack_outside.display()
                );
                let output = std::process::Command::new("cmd")
                    .args(["/C", &command])
                    .output()?;
                anyhow::ensure!(
                    output.status.success(),
                    "failed to create test junction: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("session workspace changed"), "{error}");
        assert_eq!(
            fs::read_to_string(outside.join("sentinel.txt")).unwrap(),
            "outside\n"
        );
        assert!(!outside.join("nested/payload.txt").exists());
        assert!(!outside.join(".kin-session").exists());
        assert!(
            fs::symlink_metadata(&session_dir).unwrap().is_dir(),
            "the replacement junction must not be touched after capability capture"
        );
        assert!(
            !moved_session.exists(),
            "only the displaced retained child may be cleaned up"
        );
        fs::remove_dir(&session_dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn direct_directory_substitution_after_capture_preserves_the_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        write_native_graph_file(&layout, "nested/payload.txt", b"graph payload\n").unwrap();
        let session_dir = layout.runs_dir().join("session-direct-substitution");
        let moved_session = layout
            .runs_dir()
            .join("session-direct-substitution-retained");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let attack_moved_session = moved_session.clone();
        let replacement_installed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_replacement_installed = std::sync::Arc::clone(&replacement_installed);

        let error = create_session_workspace_from_graph_with_child_hook(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            None,
            move |child| {
                fs::rename(child, &attack_moved_session)?;
                fs::create_dir(child)?;
                fs::write(child.join("sentinel.txt"), "replacement\n")?;
                hook_replacement_installed.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();

        assert!(
            replacement_installed.load(std::sync::atomic::Ordering::SeqCst),
            "the replacement-installing hook must run past the retained-handle rename"
        );
        assert!(error.contains("session workspace changed"), "{error}");
        assert_eq!(
            fs::read_to_string(session_dir.join("sentinel.txt")).unwrap(),
            "replacement\n"
        );
        assert!(!session_dir.join("nested/payload.txt").exists());
        assert!(!session_dir.join(".kin-session").exists());
        assert!(
            !moved_session.exists(),
            "only the displaced retained child may be cleaned up"
        );
        fs::remove_dir_all(&session_dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn create_to_open_nonempty_substitution_fails_without_recursive_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let runs = dir.path().join("runs");
        let session = runs.join("session-raced");
        let moved_session = runs.join("session-created");
        fs::create_dir(&runs).unwrap();
        let runs_root =
            cap_std::fs::Dir::open_ambient_dir(&runs, cap_std::ambient_authority()).unwrap();
        runs_root.create_dir("session-raced").unwrap();

        fs::rename(&session, &moved_session).unwrap();
        fs::create_dir(&session).unwrap();
        fs::write(session.join("sentinel.txt"), "replacement\n").unwrap();

        let error = capture_fresh_empty_session_directory(&runs_root, OsStr::new("session-raced"))
            .unwrap_err();
        let error = format!("{error:#}");

        assert!(error.contains("not empty at ownership capture"), "{error}");
        assert_eq!(
            fs::read_to_string(session.join("sentinel.txt")).unwrap(),
            "replacement\n"
        );
        assert!(moved_session.is_dir());
        fs::remove_dir_all(&session).unwrap();
        fs::remove_dir(&moved_session).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn held_parent_capability_blocks_parent_swap_until_materialization_finishes() {
        let dir = tempfile::tempdir().unwrap();
        let layout = init_repo(dir.path()).unwrap().layout;
        let runs_dir = layout.runs_dir();
        let moved_runs = layout.root().join("runs-before-swap");
        write_native_graph_file(&layout, "nested/payload.txt", b"graph payload\n").unwrap();
        let session_dir = runs_dir.join("session-parent-swap");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let mut swap_error = None;

        let workspace = create_session_workspace_from_graph_with_hook(
            &layout,
            snap.graph().as_ref(),
            &session_dir,
            None,
            None,
            |_| {
                swap_error = Some(fs::rename(&runs_dir, &moved_runs).unwrap_err().kind());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(swap_error, Some(std::io::ErrorKind::PermissionDenied));
        assert_eq!(
            fs::read_to_string(workspace.root.join("nested/payload.txt")).unwrap(),
            "graph payload\n"
        );
    }

    #[cfg(windows)]
    #[test]
    fn retained_windows_cleanup_handle_allows_direct_child_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let runs = dir.path().join("runs");
        let session = runs.join("session-retained");
        let moved_session = runs.join("session-retained-moved");
        fs::create_dir_all(&session).unwrap();
        fs::write(session.join("owned.txt"), "owned\n").unwrap();
        let runs_root =
            cap_std::fs::Dir::open_ambient_dir(&runs, cap_std::ambient_authority()).unwrap();
        let retained =
            open_session_directory_for_cleanup(&runs_root, OsStr::new("session-retained")).unwrap();
        let reopened =
            open_session_directory_for_cleanup(&runs_root, OsStr::new("session-retained")).unwrap();
        let ambient = open_absolute_session_directory_nofollow(&session).unwrap();
        assert!(same_directory(&retained, &reopened).unwrap());
        assert!(same_directory(&retained, &ambient).unwrap());

        fs::rename(&session, &moved_session)
            .expect("all retained identity handles must share delete for child replacement");
        fs::create_dir(&session).unwrap();
        fs::write(session.join("sentinel.txt"), "replacement\n").unwrap();
        drop(reopened);
        drop(ambient);
        cleanup_open_session_directory(retained).unwrap();

        assert!(!moved_session.exists());
        assert_eq!(
            fs::read_to_string(session.join("sentinel.txt")).unwrap(),
            "replacement\n"
        );
        fs::remove_dir_all(&session).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_handle_cleanup_deletes_a_junction_without_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let runs = dir.path().join("runs");
        let session = runs.join("session-cleanup");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&session).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("sentinel.txt"), "outside\n").unwrap();
        fs::write(session.join("payload.txt"), "payload\n").unwrap();
        let junction = session.join("junction");
        let command = format!(
            "mklink /J \"{}\" \"{}\"",
            junction.display(),
            outside.display()
        );
        let output = std::process::Command::new("cmd")
            .args(["/C", &command])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "failed to create test junction: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let runs_root =
            cap_std::fs::Dir::open_ambient_dir(&runs, cap_std::ambient_authority()).unwrap();
        let session_root =
            open_session_directory_for_cleanup(&runs_root, OsStr::new("session-cleanup")).unwrap();

        cleanup_open_session_directory(session_root).unwrap();

        assert!(!session.exists());
        assert_eq!(
            fs::read_to_string(outside.join("sentinel.txt")).unwrap(),
            "outside\n"
        );
    }

    #[test]
    #[serial_test::serial]
    fn native_mode_materializes_graph_truth_through_runtime_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        let init = init_repo(dir.path()).unwrap();
        let layout = init.layout;
        // No mode to set — there's one mode: Kin.
        fs::create_dir_all(kin_core::source_dir(&layout).join("src")).unwrap();
        fs::write(
            kin_core::source_dir(&layout).join("src/lib.rs"),
            "source drift\n",
        )
        .unwrap();
        write_native_graph_file(&layout, "src/lib.rs", b"graph truth\n").unwrap();

        let session_dir = layout.root().join("runs/session-native");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let graph = snap.graph();
        let workspace =
            create_session_workspace_from_graph(&layout, graph.as_ref(), &session_dir, None, None)
                .unwrap();

        assert_eq!(workspace.source_kind(), MaterializationSourceKind::BlobTree);
        assert_eq!(
            fs::read_to_string(workspace.root.join("src/lib.rs")).unwrap(),
            "graph truth\n"
        );
        let base = super::super::session_base::load_base(&workspace.root)
            .unwrap()
            .expect("capability-rooted base manifest");
        assert_eq!(
            base.files.get("src/lib.rs"),
            Some(&kin_blobs::digest(b"graph truth\n").to_string())
        );

        let artifact_dir = std::path::Path::new("/tmp/workstreamC-materialization-dispatch-proof");
        fs::create_dir_all(artifact_dir).unwrap();
        fs::write(
            artifact_dir.join("native.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "source_kind": format!("{:?}", workspace.source_kind()),
                "materialized_content": fs::read_to_string(workspace.root.join("src/lib.rs")).unwrap(),
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    #[serial_test::serial]
    fn default_session_workspace_materializes_graph_snapshot_even_when_source_tree_exists() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/lib.rs"), "compat source\n").unwrap();
        let init = init_repo(dir.path()).unwrap();
        let layout = init.layout;
        write_native_graph_file(&layout, "src/lib.rs", b"compat source\n").unwrap();

        let session_dir = layout.root().join("runs/session-compat");
        let snap = crate::backend::open_kindb_snapshot(&layout).unwrap();
        let graph = snap.graph();
        let workspace =
            create_session_workspace_from_graph(&layout, graph.as_ref(), &session_dir, None, None)
                .unwrap();

        assert_eq!(workspace.source_kind(), MaterializationSourceKind::BlobTree);
        assert_eq!(
            fs::read_to_string(workspace.root.join("src/lib.rs")).unwrap(),
            "compat source\n"
        );

        let artifact_dir = std::path::Path::new("/tmp/workstreamC-materialization-dispatch-proof");
        fs::create_dir_all(artifact_dir).unwrap();
        fs::write(
            artifact_dir.join("compat.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "source_kind": format!("{:?}", workspace.source_kind()),
                "materialized_content": fs::read_to_string(workspace.root.join("src/lib.rs")).unwrap(),
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            artifact_dir.join("summary.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "native_source_kind": "BlobTree",
                "native_materialized_content": "graph truth\\n",
                "compat_source_kind": "BlobTree",
                "compat_materialized_content": "compat source\\n",
            }))
            .unwrap(),
        )
        .unwrap();
    }
}
