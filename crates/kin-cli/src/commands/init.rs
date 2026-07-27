// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Clean-slate repository authority initialization.
//!
//! `kin init` has exactly two admission paths:
//!
//! - a fresh Git worktree is captured by [`kin_core::init_from_git`] as exact
//!   reachable history, refs, raw objects, workspace state, and admission policy;
//! - an empty non-Git directory is initialized as an unborn Kin-native repository.
//!
//! This command deliberately does not parse a checkout, synthesize a snapshot
//! change, or rebuild an existing repository from raw filesystem contents.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

/// Invalidates prepared state when the repository bootstrap authority changes.
pub(crate) const GRAPH_BUILD_PIPELINE_EPOCH: &str =
    "graph-build-2026-07-26-repository-v6-authority-v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitBoundary {
    ExactGit,
    NativeUnborn,
}

impl InitBoundary {
    fn source_boundary(self) -> &'static str {
        match self {
            Self::ExactGit => "git-exact-reachable-history",
            Self::NativeUnborn => "native-unborn",
        }
    }

    fn history(self) -> &'static str {
        match self {
            Self::ExactGit => "exact-reachable",
            Self::NativeUnborn => "unborn",
        }
    }
}

#[derive(Debug, Serialize)]
struct InitResultPayload<'a> {
    schema: &'static str,
    authority: &'static str,
    source_boundary: &'static str,
    history: &'static str,
    semantic_enrichment: &'static str,
    repo_root: String,
    kin_dir: String,
    repository_id: &'a kin_model::RepositoryId,
    workspace_id: kin_model::WorkspaceId,
    default_ref: Option<&'a kin_model::RefName>,
    authority_generation: u64,
    workspace_generation: u64,
    workspace_head: &'a kin_model::WorkspaceHead,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_git_head: Option<&'a kin_model::GitRawTarget>,
    base_target: Option<&'a kin_model::RefTarget>,
    base_tree_hash: Option<kin_model::Hash256>,
    workspace_tree_hash: kin_model::Hash256,
    roots: &'a kin_model::RootBundle,
    initial_change_id: Option<&'a kin_model::SemanticChangeId>,
    exact_reachable_git_history: bool,
}

pub async fn run(path: Option<String>, json: bool) -> Result<()> {
    let _span = tracing::info_span!("kin.init").entered();
    let dir = path
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

    ensure_directory(&dir)?;
    reject_existing_repository(&dir)?;

    let boundary = if path_exists(&dir.join(".git"))? {
        InitBoundary::ExactGit
    } else {
        require_empty_native_boundary(&dir)?;
        InitBoundary::NativeUnborn
    };

    let result = match boundary {
        InitBoundary::ExactGit => kin_core::init_from_git(&dir)
            .context("admit exact reachable Git repository authority")?,
        InitBoundary::NativeUnborn => {
            kin_core::init(&dir).context("initialize unborn Kin-native repository authority")?
        }
    };

    if json {
        print_json_result(&result, boundary)?;
    } else {
        print_human_result(&result, boundary)?;
    }
    Ok(())
}

fn ensure_directory(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => anyhow::bail!("repository path is not a directory: {}", dir.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir_all(dir)
            .with_context(|| format!("create repository directory {}", dir.display())),
        Err(error) => {
            Err(error).with_context(|| format!("inspect repository directory {}", dir.display()))
        }
    }
}

fn reject_existing_repository(dir: &Path) -> Result<()> {
    if path_exists(&dir.join(".kin"))? {
        anyhow::bail!(
            "Kin repository already exists at {}; `kin init` never rebuilds graph authority from \
             the working tree",
            dir.display()
        );
    }
    Ok(())
}

fn require_empty_native_boundary(dir: &Path) -> Result<()> {
    let mut entries = std::fs::read_dir(dir)
        .with_context(|| format!("inspect native repository boundary {}", dir.display()))?;
    if entries
        .next()
        .transpose()
        .with_context(|| format!("inspect native repository boundary {}", dir.display()))?
        .is_some()
    {
        anyhow::bail!(
            "non-Git repository admission currently requires an empty directory: {}; Kin will \
             not silently ignore or derive authority from existing filesystem contents. Commit \
             the exact files to Git and retry, or initialize an empty Kin-native repository.",
            dir.display()
        );
    }
    Ok(())
}

fn path_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn print_json_result(result: &kin_core::InitResult, boundary: InitBoundary) -> Result<()> {
    let workspace = &result.authority.workspace;
    let default_ref = initialized_default_ref(result);
    let payload = InitResultPayload {
        schema: "kin.init-result.v4",
        authority: "repository-v6",
        source_boundary: boundary.source_boundary(),
        history: boundary.history(),
        semantic_enrichment: "not-run",
        repo_root: result.layout.working_dir().display().to_string(),
        kin_dir: result.layout.root().display().to_string(),
        repository_id: &result.repository_id,
        workspace_id: result.workspace_id,
        default_ref,
        authority_generation: result.authority.receipt.generation,
        workspace_generation: workspace.workspace_generation,
        workspace_head: &workspace.workspace_head,
        raw_git_head: initialized_raw_git_head(result),
        base_target: workspace.base_target.as_ref(),
        base_tree_hash: workspace.base_tree_hash,
        workspace_tree_hash: workspace.workspace_tree_hash,
        roots: &result.authority.receipt.roots_after,
        initial_change_id: result.authority.initial_change_id.as_ref(),
        exact_reachable_git_history: boundary == InitBoundary::ExactGit,
    };
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

fn print_human_result(result: &kin_core::InitResult, boundary: InitBoundary) -> Result<()> {
    let default_ref = initialized_default_ref(result);
    println!(
        "Initialized Kin repository authority at {}",
        result.layout.root().display()
    );
    println!("  Authority: repository-v6 (graph-owned)");
    println!("  Repository: {}", result.repository_id);
    println!("  Workspace: {}", result.workspace_id);
    match default_ref {
        Some(default_ref) => println!("  Default ref: {default_ref}"),
        None => println!("  Default ref: none (detached workspace)"),
    }
    println!(
        "  Authority generation: {}",
        result.authority.receipt.generation
    );
    println!(
        "  Workspace generation: {}",
        result.authority.workspace.workspace_generation
    );
    println!(
        "  Workspace head: {}",
        serde_json::to_string(&result.authority.workspace.workspace_head)?
    );
    match boundary {
        InitBoundary::ExactGit => {
            println!(
                "  Imported: exact reachable Git history, refs, raw objects, workspace, and admission policy"
            );
            println!("  Semantic enrichment: not run during authority admission");
        }
        InitBoundary::NativeUnborn => {
            println!("  History: unborn (no synthetic commit)");
            println!("  Workspace: empty exact tree");
        }
    }
    Ok(())
}

fn initialized_default_ref(result: &kin_core::InitResult) -> Option<&kin_model::RefName> {
    result
        .authority
        .receipt
        .operation
        .default_ref_mutation
        .as_ref()
        .and_then(|mutation| mutation.new_default.as_ref())
}

fn initialized_raw_git_head(result: &kin_core::InitResult) -> Option<&kin_model::GitRawTarget> {
    result
        .authority
        .receipt
        .operation
        .git_authority_delta
        .as_ref()
        .and_then(|delta| delta.new.as_ref())
        .map(|authority| &authority.raw_head)
}
