// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact repository-artifact MCP surfaces.
//!
//! Semantic entities are an enrichment of repository truth, not its membership
//! boundary. These handlers therefore read the identity-bearing repository tree
//! directly. Configuration, lockfiles, binaries, unsupported languages,
//! symlinks, and gitlinks remain visible even when no parser emits an entity.

use std::collections::HashMap;
use std::path::PathBuf;

use base64::Engine as _;
use kin_model::{
    ArtifactId, GraphStore, RepoPath, ResolvedArtifact, ResolvedTree, SemanticChangeId, TreeEntry,
};
use serde::Serialize;

use crate::error::{McpError, Result};
use crate::types::ToolCallResult;

pub const ARTIFACT_LIST_DESC: &str = "\
List the exact graph-owned repository artifacts at one semantic change. This is the \
repository-membership surface: it includes code and every non-code tracked object such as \
Docker Compose files, Dockerfiles, lockfiles, configuration, binary assets, unsupported \
languages, symlinks, executable files, and gitlinks. Paths are returned as canonical \
lowercase `bytes_hex` objects; `path_label` is presentation-only and \
`path_label_lossy` says whether replacement characters were required. Identity comes from \
`artifact_id`, never from a path. Omit `source_change_id` to read the current branch head.";

pub const ARTIFACT_READ_DESC: &str = "\
Read one exact graph-owned repository artifact by stable `artifact_id` or canonical \
byte-exact `path`. Blob and symlink bytes are returned losslessly as base64 and, only when \
valid UTF-8, as `text_utf8`. Gitlinks return their external object identity and have no \
repository-owned body. The read is bound to the resolved tree entry at \
`source_change_id` (or the current branch head) and fails loudly when the tree, identity, \
or content-addressed blob is missing. It never reads the working directory.";

#[derive(Debug, Serialize)]
struct ArtifactWire {
    artifact_id: ArtifactId,
    path: RepoPath,
    path_label: String,
    path_label_lossy: bool,
    entry: TreeEntry,
}

impl From<&ResolvedArtifact> for ArtifactWire {
    fn from(artifact: &ResolvedArtifact) -> Self {
        let path_label_lossy = artifact.path.as_utf8().is_none();
        let path_label = String::from_utf8_lossy(artifact.path.as_bytes()).into_owned();
        Self {
            artifact_id: artifact.artifact_id,
            path: artifact.path.clone(),
            path_label,
            path_label_lossy,
            entry: artifact.entry,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ExactTreeSelection {
    pub layout: Option<kin_core::KinLayout>,
    pub source_change_id: SemanticChangeId,
    pub tree: ResolvedTree,
}

/// Resolve the configured repository layout without inspecting source files.
///
/// `KIN_SOURCE_ROOT` is the explicit binding installed by MCP/daemon launch.
/// The current directory is only a repository-location fallback. `discover`
/// reads Kin control metadata; it is not a semantic answer authority.
pub(crate) fn active_layout() -> Result<kin_core::KinLayout> {
    let start = std::env::var_os("KIN_SOURCE_ROOT")
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(std::env::current_dir)?;
    kin_core::KinLayout::discover(&start).ok_or_else(|| {
        McpError::Context(format!(
            "graph authority gap: no Kin repository layout is bound at '{}'; \
             set KIN_SOURCE_ROOT or run MCP from the repository",
            start.display()
        ))
    })
}

fn explicit_source_change_id(
    args: &HashMap<String, serde_json::Value>,
) -> Result<Option<SemanticChangeId>> {
    args.get("source_change_id")
        .map(|value| {
            let raw = value.as_str().ok_or_else(|| {
                McpError::InvalidParams("source_change_id must be a lowercase hex string".into())
            })?;
            crate::handlers::common::parse_change_id(raw)
        })
        .transpose()
}

pub(crate) fn active_source_head<G: GraphStore>(
    store: &G,
    layout: &kin_core::KinLayout,
) -> Result<SemanticChangeId> {
    let branch_name = kin_core::read_current_branch(layout).map_err(|error| {
        McpError::Context(format!(
            "graph authority gap: cannot resolve current Kin branch: {error}"
        ))
    })?;
    let branch = store
        .get_branch(&branch_name)
        .map_err(McpError::graph)?
        .ok_or_else(|| {
            McpError::Context(format!(
                "graph authority gap: current branch '{}' is absent from graph truth",
                branch_name
            ))
        })?;
    Ok(branch.head)
}

pub(crate) fn resolve_tree_selection<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    require_layout: bool,
) -> Result<ExactTreeSelection> {
    let explicit = explicit_source_change_id(args)?;
    let layout = if explicit.is_none() || require_layout {
        Some(active_layout()?)
    } else {
        None
    };
    let source_change_id = match explicit {
        Some(id) => id,
        None => active_source_head(
            store,
            layout
                .as_ref()
                .expect("layout is required when the source change is implicit"),
        )?,
    };
    let tree = store.resolve_tree_at(&source_change_id).map_err(|error| {
        McpError::Context(format!(
            "graph authority gap: cannot resolve exact repository tree at \
                 {source_change_id}: {error}"
        ))
    })?;
    Ok(ExactTreeSelection {
        layout,
        source_change_id,
        tree,
    })
}

fn parse_artifact_id(value: &serde_json::Value) -> Result<ArtifactId> {
    serde_json::from_value(value.clone())
        .map_err(|error| McpError::InvalidParams(format!("invalid artifact_id: {error}")))
}

fn parse_repo_path(value: &serde_json::Value) -> Result<RepoPath> {
    serde_json::from_value(value.clone()).map_err(|error| {
        McpError::InvalidParams(format!(
            "invalid byte-exact path; expected {{\"bytes_hex\":\"...\"}}: {error}"
        ))
    })
}

fn select_artifact<'a>(
    args: &HashMap<String, serde_json::Value>,
    tree: &'a ResolvedTree,
) -> Result<&'a ResolvedArtifact> {
    let by_id = args
        .get("artifact_id")
        .map(parse_artifact_id)
        .transpose()?
        .and_then(|id| tree.get(&id));
    let by_path = args
        .get("path")
        .map(parse_repo_path)
        .transpose()?
        .and_then(|path| tree.artifact_at_path(&path));

    match (args.contains_key("artifact_id"), args.contains_key("path")) {
        (false, false) => Err(McpError::InvalidParams(
            "one of artifact_id or path is required".into(),
        )),
        (true, false) => by_id.ok_or_else(|| {
            McpError::Context("graph authority gap: artifact_id is absent from this tree".into())
        }),
        (false, true) => by_path.ok_or_else(|| {
            McpError::Context("graph authority gap: exact path is absent from this tree".into())
        }),
        (true, true) => match (by_id, by_path) {
            (Some(left), Some(right)) if left.artifact_id == right.artifact_id => Ok(left),
            (Some(_), Some(_)) => Err(McpError::InvalidParams(
                "artifact_id and path resolve to different graph artifacts".into(),
            )),
            _ => Err(McpError::Context(
                "graph authority gap: artifact_id and path do not both resolve in this tree".into(),
            )),
        },
    }
}

pub fn handle_artifact_list<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let selection = resolve_tree_selection(args, store, false)?;
    let offset = args
        .get("offset")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as usize;
    let limit = args
        .get("limit")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(200)
        .clamp(1, 1_000) as usize;
    let total = selection.tree.len();
    let artifacts = selection
        .tree
        .artifacts_by_path()
        .skip(offset)
        .take(limit)
        .map(ArtifactWire::from)
        .collect::<Vec<_>>();
    let returned = artifacts.len();
    let result = serde_json::json!({
        "source_change_id": selection.source_change_id,
        "artifact_count": total,
        "offset": offset,
        "returned": returned,
        "truncated": offset.saturating_add(returned) < total,
        "artifacts": artifacts,
    });
    Ok(ToolCallResult::text(
        serde_json::to_string_pretty(&result).map_err(McpError::Json)?,
    ))
}

pub fn handle_artifact_read<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let selection = resolve_tree_selection(args, store, true)?;
    let artifact = select_artifact(args, &selection.tree)?;
    let mut result = serde_json::json!({
        "source_change_id": selection.source_change_id,
        "artifact": ArtifactWire::from(artifact),
    });

    match artifact.entry {
        TreeEntry::Gitlink { target } => {
            result["content_kind"] = serde_json::json!("gitlink_reference");
            result["git_object_id"] = serde_json::to_value(target).map_err(McpError::Json)?;
        }
        TreeEntry::Blob { hash, .. } | TreeEntry::Symlink { target_blob: hash } => {
            let layout = selection
                .layout
                .as_ref()
                .expect("artifact reads always require a bound layout");
            let blobs = kin_blobs::BlobStore::new(layout.objects_dir()).map_err(|error| {
                McpError::Context(format!("cannot open graph blob store: {error}"))
            })?;
            let blob_hash = kin_blobs::Hash256(*hash.as_bytes());
            let bytes = blobs.read(&blob_hash).map_err(|error| {
                McpError::Context(format!(
                    "graph authority gap: blob {} for artifact {:?} at {} is unavailable or \
                     corrupt: {error}",
                    hash, artifact.artifact_id, artifact.path
                ))
            })?;
            result["content_kind"] = serde_json::json!(match artifact.entry {
                TreeEntry::Blob { .. } => "blob",
                TreeEntry::Symlink { .. } => "symlink_target",
                TreeEntry::Gitlink { .. } => unreachable!(),
            });
            result["content_length"] = serde_json::json!(bytes.len());
            result["content_base64"] =
                serde_json::json!(base64::engine::general_purpose::STANDARD.encode(&bytes));
            if let Ok(text) = std::str::from_utf8(&bytes) {
                result["text_utf8"] = serde_json::json!(text);
            }
        }
    }

    Ok(ToolCallResult::text(
        serde_json::to_string_pretty(&result).map_err(McpError::Json)?,
    ))
}
