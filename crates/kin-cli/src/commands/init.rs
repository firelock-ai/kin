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

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use super::status::{SemanticEnrichmentPresence, SemanticEnrichmentStatus};
use super::store_footprint::{store_size_notice, StoreFootprint};

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
    /// Durable generation-bound enrichment committed by admission. This is
    /// carried from the bootstrap lease, not reopened after publication.
    semantic_enrichment: SemanticEnrichmentStatus,
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
    /// What the store this command just wrote costs on disk, and what the Git
    /// object store it was admitted from costs. Measured after publication, so
    /// it describes the store the caller now has rather than a projection of it.
    store_footprint: StoreFootprint,
    /// Source paths that were not the committed state, and are therefore not in
    /// what was admitted. Absent when the source carried none.
    #[serde(skip_serializing_if = "Option::is_none")]
    uncommitted_worktree: Option<UncommittedWorktreePayload>,
}

/// The uncommitted delta initialization saw and did not admit.
#[derive(Debug, Serialize)]
struct UncommittedWorktreePayload {
    /// Paths observed, including every one this payload does not carry.
    observed_paths: usize,
    /// Observed paths not carried in `paths`.
    unlisted_paths: usize,
    paths: Vec<UncommittedPathPayload>,
}

/// Paths one machine-readable result carries by name.
///
/// Nothing bounds how many paths can differ: a repository whose checkout Git
/// rewrote reports every text file it holds. A count of those is useful on a
/// piped stdout and tens of thousands of path strings are not, so the payload
/// carries a sample and says exactly how many it left out.
const SERIALIZED_PATHS: usize = 200;

#[derive(Debug, Serialize)]
struct UncommittedPathPayload {
    path: String,
    state: &'static str,
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

    if let Err(error) = exclude_store_from_git(result.layout.working_dir()) {
        eprintln!(
            "warning: the Kin store at {} was not added to this repository's local Git excludes, \
             so `git status` will list it as untracked: {error:#}",
            result.layout.root().display()
        );
    }

    let enrichment =
        SemanticEnrichmentStatus::from_durable_summary(&result.authority.semantic_enrichment);
    if json {
        print_json_result(&result, boundary, enrichment)?;
    } else {
        print_human_result(&result, boundary, &enrichment)?;
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
        anyhow::bail!(existing_repository_refusal(dir));
    }
    Ok(())
}

/// The refusal `kin init` raises over a directory that already holds a store.
///
/// The reader who arrives here most often is the one the store wall just sent,
/// after an older store refused to open. That wall names a rebuild, and `kin
/// init` is half of it, so this refusal names the same rebuild instead of
/// stopping at the fact that a store exists.
fn existing_repository_refusal(dir: &Path) -> String {
    format!(
        "Kin repository already exists at {}; `kin init` never rebuilds graph authority from the \
         working tree. If this build cannot open that store, {} again to rebuild it from the \
         repository's Git history.",
        dir.display(),
        super::REBUILD_INCOMPATIBLE_STORE
    )
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
             the exact files to Git and retry, or initialize an empty Kin-native repository.{}",
            dir.display(),
            git_prerequisite_note(which::which("git").is_ok())
        );
    }
    Ok(())
}

/// The suffix naming Git as a prerequisite of the remedy above.
///
/// Kin reads a repository's history through `gix` and never needs the host
/// binary to admit one, so this error is reachable on a host with no Git at
/// all — and the first remedy it offers is a `git commit`. Say that the tool
/// is missing rather than sending the reader to a command they do not have.
fn git_prerequisite_note(git_on_path: bool) -> &'static str {
    if git_on_path {
        ""
    } else {
        " Git is not installed on this host, so committing to Git needs `git` installed first."
    }
}

/// The rule `kin init` adds so the store stays out of `git status`.
///
/// Anchored and directory-scoped so it names the store this command just wrote
/// and nothing else. An unanchored `.kin/` would also hide a nested directory
/// of that name anywhere in the tree, which is not this command's to decide.
const STORE_EXCLUDE_RULE: &str = "/.kin/";

/// Spellings of a rule that already keeps the store out of `git status`.
///
/// A repository converted before this command excluded anything, or one whose
/// author added the rule by hand, is already correct. Re-stating it would leave
/// a duplicate line behind on every re-init.
const STORE_EXCLUDE_EQUIVALENTS: &[&str] = &[".kin", ".kin/", "/.kin", "/.kin/"];

/// Keep the store out of the converted repository's `git status`.
///
/// Admission writes a `.kin` directory that is routinely a gigabyte, and Git
/// has no reason to know it is Kin's. Without a rule it is reported as
/// untracked forever, on every `git status` the author runs, which is a
/// permanent cost paid for a one-time conversion.
///
/// The rule goes in `.git/info/exclude` rather than the repository's tracked
/// `.gitignore`, because whether a peer's checkout carries a Kin store is that
/// peer's business. Excluding it locally costs the author nothing and changing
/// a tracked file would put Kin in their next diff.
///
/// Every refusal here is reported and none of them fail the command: the store
/// is durable before this runs, and an admission that succeeded must not be
/// turned into a failure by a convenience.
fn exclude_store_from_git(working_dir: &Path) -> Result<Option<PathBuf>> {
    let Some(common_dir) = git_common_dir(working_dir)? else {
        return Ok(None);
    };
    if store_already_excluded(working_dir, &common_dir)? {
        return Ok(None);
    }

    let info_dir = common_dir.join("info");
    std::fs::create_dir_all(&info_dir)
        .with_context(|| format!("create Git info directory {}", info_dir.display()))?;
    let exclude = info_dir.join("exclude");
    if let Ok(metadata) = std::fs::symlink_metadata(&exclude) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            anyhow::bail!(
                "Git exclude authority must be a regular non-symlink file: {}",
                exclude.display()
            );
        }
    }

    let mut body = read_optional_text(&exclude)?.unwrap_or_default();
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    body.push_str(STORE_EXCLUDE_RULE);
    body.push('\n');
    std::fs::write(&exclude, body)
        .with_context(|| format!("write Git exclude {}", exclude.display()))?;
    Ok(Some(exclude))
}

/// The directory holding the shared `info/exclude` for this worktree.
///
/// A `.git` directory is its own common directory. A linked worktree or a
/// submodule instead carries a `gitdir:` pointer file, and a linked worktree's
/// excludes live with the repository it was added from, which its `commondir`
/// names. Following the pointer is what makes this work in the worktrees Kin's
/// own fleet runs in.
fn git_common_dir(working_dir: &Path) -> Result<Option<PathBuf>> {
    let dot_git = working_dir.join(".git");
    let metadata = match std::fs::symlink_metadata(&dot_git) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", dot_git.display())),
    };
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "repository Git authority must not be a symlink: {}",
            dot_git.display()
        );
    }
    if metadata.is_dir() {
        return Ok(Some(dot_git));
    }
    if !metadata.is_file() {
        return Ok(None);
    }

    let pointer = std::fs::read_to_string(&dot_git)
        .with_context(|| format!("read Git pointer file {}", dot_git.display()))?;
    let Some(target) = pointer
        .lines()
        .find_map(|line| line.trim().strip_prefix("gitdir:"))
    else {
        anyhow::bail!("Git pointer file names no gitdir: {}", dot_git.display());
    };
    let git_dir = resolve_against(working_dir, target.trim());
    match read_optional_text(&git_dir.join("commondir"))? {
        Some(common) => match common
            .lines()
            .next()
            .map(str::trim)
            .filter(|l| !l.is_empty())
        {
            Some(common) => Ok(Some(resolve_against(&git_dir, common))),
            None => Ok(Some(git_dir)),
        },
        None => Ok(Some(git_dir)),
    }
}

fn resolve_against(base: &Path, target: &str) -> PathBuf {
    let target = Path::new(target);
    if target.is_absolute() {
        target.to_path_buf()
    } else {
        base.join(target)
    }
}

/// Whether some rule Git already reads keeps the store out of `git status`.
///
/// Checked against both places a rule can already live for this repository:
/// the local excludes this command writes, and the tracked `.gitignore` a
/// project may have adopted on its own. Either one makes writing a second rule
/// pure noise.
fn store_already_excluded(working_dir: &Path, common_dir: &Path) -> Result<bool> {
    for candidate in [
        common_dir.join("info").join("exclude"),
        working_dir.join(".gitignore"),
    ] {
        let Some(body) = read_optional_text(&candidate)? else {
            continue;
        };
        if body
            .lines()
            .map(str::trim)
            .any(|line| STORE_EXCLUDE_EQUIVALENTS.contains(&line))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_optional_text(path: &Path) -> Result<Option<String>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            Ok(Some(String::from_utf8(bytes).with_context(|| {
                format!("{} is not UTF-8", path.display())
            })?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn path_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn print_json_result(
    result: &kin_core::InitResult,
    boundary: InitBoundary,
    semantic_enrichment: SemanticEnrichmentStatus,
) -> Result<()> {
    let workspace = &result.authority.workspace;
    let default_ref = initialized_default_ref(result);
    let payload = InitResultPayload {
        schema: "kin.init-result.v6",
        authority: "repository-v6",
        source_boundary: boundary.source_boundary(),
        history: boundary.history(),
        semantic_enrichment,
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
        store_footprint: StoreFootprint::measure(&result.layout),
        uncommitted_worktree: uncommitted_worktree_payload(&result.workspace_divergence),
    };
    emit(&format!("{}\n", serde_json::to_string_pretty(&payload)?))
}

fn uncommitted_worktree_payload(
    divergence: &kin_git::GitWorkspaceDivergenceFacts,
) -> Option<UncommittedWorktreePayload> {
    if divergence.is_empty() {
        return None;
    }
    let paths = divergence
        .entries
        .iter()
        .take(SERIALIZED_PATHS)
        .map(|entry| UncommittedPathPayload {
            path: entry.path.to_string(),
            state: entry.kind.label(),
        })
        .collect::<Vec<_>>();
    Some(UncommittedWorktreePayload {
        observed_paths: divergence.observed_paths(),
        unlisted_paths: divergence.observed_paths() - paths.len(),
        paths,
    })
}

fn print_human_result(
    result: &kin_core::InitResult,
    boundary: InitBoundary,
    semantic_enrichment: &SemanticEnrichmentStatus,
) -> Result<()> {
    emit(&render_human_result(result, boundary, semantic_enrichment)?)
}

/// Hand a finished result to stdout, tolerating a reader that already left.
///
/// The store is durable before a single byte of this is written, so a consumer
/// that closed its pipe must not turn a completed admission into a failure.
/// `println!` panics on a write error, which is exactly what `kin init | head`
/// did. Every write error that is not a departed reader is still reported.
fn emit(rendered: &str) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    match stdout
        .write_all(rendered.as_bytes())
        .and_then(|()| stdout.flush())
    {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error).context("write the kin init result to stdout"),
    }
}

/// The whole human result as one string, so it reaches stdout in one write.
fn render_human_result(
    result: &kin_core::InitResult,
    boundary: InitBoundary,
    semantic_enrichment: &SemanticEnrichmentStatus,
) -> Result<String> {
    let default_ref = initialized_default_ref(result);
    let mut out = String::new();
    writeln!(
        out,
        "Initialized Kin repository authority at {}",
        result.layout.root().display()
    )?;
    writeln!(out, "  Authority: repository-v6 (graph-owned)")?;
    writeln!(out, "  Repository: {}", result.repository_id)?;
    writeln!(out, "  Workspace: {}", result.workspace_id)?;
    match default_ref {
        Some(default_ref) => writeln!(out, "  Default ref: {default_ref}")?,
        None => writeln!(out, "  Default ref: none (detached workspace)")?,
    }
    writeln!(
        out,
        "  Authority generation: {}",
        result.authority.receipt.generation
    )?;
    writeln!(
        out,
        "  Workspace generation: {}",
        result.authority.workspace.workspace_generation
    )?;
    writeln!(
        out,
        "  Workspace head: {}",
        serde_json::to_string(&result.authority.workspace.workspace_head)?
    )?;
    match boundary {
        InitBoundary::ExactGit => {
            writeln!(
                out,
                "  Imported: exact reachable Git history, refs, raw objects, workspace, and admission policy"
            )?;
        }
        InitBoundary::NativeUnborn => {
            writeln!(out, "  History: unborn (no synthetic commit)")?;
            writeln!(out, "  Workspace: empty exact tree")?;
        }
    }
    writeln!(
        out,
        "  Semantic enrichment: {}",
        render_semantic_enrichment(semantic_enrichment)
    )?;
    if let Some(notice) = semantic_absence_notice(semantic_enrichment) {
        writeln!(out, "{notice}")?;
    }
    writeln!(
        out,
        "  Store size: {}",
        StoreFootprint::measure(&result.layout).render()
    )?;
    writeln!(out, "  {}", store_size_notice())?;
    for line in uncommitted_worktree_disclosure(&result.workspace_divergence) {
        writeln!(out, "{line}")?;
    }
    Ok(out)
}

/// Paths listed by name before the rest are counted rather than named.
const DISCLOSED_PATHS: usize = 10;

/// What to say about a source that had been worked in before it was admitted.
///
/// Authority is the committed state, so none of this is in the repository this
/// command published, and none of it was lost either: it is still in the
/// worktree, and the daemon admits it as workspace state the same way it admits
/// every later edit. Both halves have to be said. A list with no disposition
/// reads as damage, and a disposition with no list is a claim the operator
/// cannot check.
///
/// Returns the exact lines to print, so absence is one empty vector rather than
/// a branch at the call site.
fn uncommitted_worktree_disclosure(
    divergence: &kin_git::GitWorkspaceDivergenceFacts,
) -> Vec<String> {
    if divergence.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "  Uncommitted worktree state: {} path(s) differ from the committed state that was admitted",
        divergence.observed_paths()
    )];
    for kind in [
        kin_git::GitWorkspaceDivergenceKind::Staged,
        kin_git::GitWorkspaceDivergenceKind::StagedRemoval,
        kin_git::GitWorkspaceDivergenceKind::Modified,
        kin_git::GitWorkspaceDivergenceKind::Missing,
        kin_git::GitWorkspaceDivergenceKind::Untracked,
    ] {
        let paths = divergence
            .of_kind(kind)
            .map(|entry| entry.path.to_string())
            .collect::<Vec<_>>();
        if paths.is_empty() {
            continue;
        }
        // Paths the walk stopped naming are part of the total this line states
        // and are not among the ones it can list, so they count once in each
        // and never in both.
        let observed = paths.len()
            + if kind == kin_git::GitWorkspaceDivergenceKind::Untracked {
                divergence.untracked_beyond_cap
            } else {
                0
            };
        let mut rendered = paths
            .iter()
            .take(DISCLOSED_PATHS)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let unlisted = observed - paths.len().min(DISCLOSED_PATHS);
        if unlisted > 0 {
            rendered.push_str(&format!(", and {unlisted} more"));
        }
        lines.push(format!("    {} ({observed}): {rendered}", kind.label()));
    }
    lines.push(
        "  None of it entered repository authority, and none of it was touched. It becomes \
         workspace state the first time the daemon runs here."
            .to_string(),
    );
    lines
}

/// What to say when initialization produced no semantic entities at all.
///
/// Absence here was previously reported as a number and nothing else, and a
/// repository whose languages Kin does not parse then answers every later query
/// with an empty list — byte-identical to a query that legitimately found
/// nothing. The two call for opposite next actions and the operator had no way
/// to tell them apart, on any surface, in any output.
///
/// The wording is deliberately CONDITIONAL rather than diagnostic. This function
/// knows that zero entities were extracted; it does NOT know whether that is
/// because no admitted file had an adapter or because something went wrong for a
/// language Kin does support, and asserting the first would be a confident guess
/// dressed as a finding. Naming the possibility and handing over the command
/// that settles it costs one line and cannot be wrong.
fn semantic_absence_notice(enrichment: &SemanticEnrichmentStatus) -> Option<String> {
    if !matches!(enrichment.presence, SemanticEnrichmentPresence::Absent) {
        return None;
    }
    Some(
        "  No semantic entities were extracted. If this repository's languages are not \
         ones Kin parses, that is expected, and `kin languages` lists the ones it does; \
         content and history are still under repository authority either way."
            .to_string(),
    )
}

fn render_semantic_enrichment(enrichment: &SemanticEnrichmentStatus) -> String {
    let presence = match enrichment.presence {
        SemanticEnrichmentPresence::Absent => "absent",
        SemanticEnrichmentPresence::Present => "present",
    };
    format!(
        "{presence} ({} entities, {} relations, {} changes in durable authority generation {}; completion not attested)",
        enrichment.entity_count,
        enrichment.relation_count,
        enrichment.semantic_change_count,
        enrichment.authority_generation
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::status::SemanticEnrichmentView;

    fn enrichment(
        presence: SemanticEnrichmentPresence,
        entities: usize,
    ) -> SemanticEnrichmentStatus {
        SemanticEnrichmentStatus {
            view: SemanticEnrichmentView::DurableRepositoryAuthority,
            authority_generation: 1,
            workspace_generation: 1,
            presence,
            entity_count: entities,
            relation_count: 0,
            semantic_change_count: 0,
            completion_attested: false,
        }
    }

    /// The non-empty-directory refusal offers "commit the exact files to Git"
    /// as its first remedy. Measured on a fresh ubuntu:24.04 curl install, that
    /// host has no git at all, so the remedy names a command the reader does
    /// not have and the error dead-ends.
    #[test]
    fn the_non_git_refusal_names_git_as_a_prerequisite_only_when_it_is_absent() {
        assert_eq!(
            git_prerequisite_note(true),
            "",
            "a host that has git needs no extra instruction"
        );

        let absent = git_prerequisite_note(false);
        assert!(
            absent.contains("not installed") && absent.contains("git"),
            "a host without git must be told before being sent to a git commit: {absent}"
        );
    }

    /// The store wall and this refusal are read in sequence by one reader, so
    /// they have to name one remedy between them.
    ///
    /// They did not. The wall sent the reader to `kin init` in a fresh checkout,
    /// and `kin init` answered that a repository already exists and that it
    /// never rebuilds graph authority, which reads as a flat contradiction and
    /// leaves no next move.
    #[test]
    fn the_store_wall_and_the_existing_repository_refusal_name_one_remedy() {
        let wall = crate::commands::incompatible_store_refusal(
            std::path::Path::new("/repo/.kin"),
            &kin_core::KinError::IncompatibleVersion {
                found: 1,
                supported: 2,
            },
        );
        let refusal = existing_repository_refusal(std::path::Path::new("/repo"));

        assert!(
            wall.contains(crate::commands::REBUILD_INCOMPATIBLE_STORE),
            "the store wall must name the shared remedy: {wall}"
        );
        assert!(
            refusal.contains(crate::commands::REBUILD_INCOMPATIBLE_STORE),
            "the existing-repository refusal must name the same remedy: {refusal}"
        );
        assert!(
            wall.contains("found v1, this binary requires v2"),
            "the wall must lead with the version gap it is about: {wall}"
        );
        assert!(
            !wall.contains("fresh checkout") && !refusal.contains("fresh checkout"),
            "neither text may send the reader to a checkout they do not have"
        );
    }

    /// A repository Kin could not extract anything from must SAY so and name the
    /// command that explains why. Silence here is what made "no parser for my
    /// language" indistinguishable from "my search was bad".
    #[test]
    fn an_empty_semantic_layer_points_at_the_supported_languages() {
        let notice = semantic_absence_notice(&enrichment(SemanticEnrichmentPresence::Absent, 0))
            .expect("absence must be explained, not merely counted");
        assert!(
            notice.contains("kin languages"),
            "the notice must hand over the command that settles it: {notice}"
        );
        // The claim must stay conditional. Asserting the cause outright would be
        // a guess: this code knows the count, not the reason.
        assert!(
            notice.contains("If this repository's languages are not"),
            "the notice must not assert a cause it cannot know: {notice}"
        );
    }

    /// The falsification: a repository that DID get semantics must print
    /// nothing extra, or the notice is noise on every successful init rather
    /// than a signal on the failing ones.
    #[test]
    fn a_repository_with_semantics_gets_no_notice() {
        assert!(
            semantic_absence_notice(&enrichment(SemanticEnrichmentPresence::Present, 19_405))
                .is_none()
        );
    }

    fn divergence(
        entries: Vec<(&str, kin_git::GitWorkspaceDivergenceKind)>,
        beyond_cap: usize,
    ) -> kin_git::GitWorkspaceDivergenceFacts {
        let mut facts = kin_git::GitWorkspaceDivergenceFacts::none();
        facts.entries = entries
            .into_iter()
            .map(|(path, kind)| kin_git::GitWorkspaceDivergence {
                path: kin_model::RepoPath::from_bytes(path.as_bytes().to_vec())
                    .expect("test repo path"),
                kind,
                detail: String::new(),
                observed: None,
            })
            .collect();
        facts.untracked_beyond_cap = beyond_cap;
        facts
    }

    /// The disclosure names the paths and says where they went.
    ///
    /// A list with no disposition reads as damage, so the sentence about what
    /// happens to the delta is asserted alongside the paths themselves.
    #[test]
    fn the_uncommitted_disclosure_names_paths_and_their_disposition() {
        let lines = uncommitted_worktree_disclosure(&divergence(
            vec![
                ("src/main.rs", kin_git::GitWorkspaceDivergenceKind::Modified),
                ("notes.txt", kin_git::GitWorkspaceDivergenceKind::Untracked),
                ("staged.rs", kin_git::GitWorkspaceDivergenceKind::Staged),
            ],
            0,
        ))
        .join("\n");

        assert!(lines.contains("3 path(s) differ"), "{lines}");
        assert!(lines.contains("staged (1): staged.rs"), "{lines}");
        assert!(lines.contains("modified (1): src/main.rs"), "{lines}");
        assert!(lines.contains("untracked (1): notes.txt"), "{lines}");
        assert!(
            lines.contains("None of it entered repository authority"),
            "{lines}"
        );
        assert!(lines.contains("the first time the daemon runs"), "{lines}");
    }

    /// A long list is capped and the rest counted, including what the walk
    /// stopped naming, so the total the header states is never contradicted by
    /// the lines beneath it.
    #[test]
    fn the_uncommitted_disclosure_counts_what_it_does_not_list() {
        let entries = (0..12)
            .map(|index| (index, kin_git::GitWorkspaceDivergenceKind::Untracked))
            .collect::<Vec<_>>();
        let named = entries
            .iter()
            .map(|(index, kind)| (format!("untracked-{index:02}.log"), *kind))
            .collect::<Vec<_>>();
        let lines = uncommitted_worktree_disclosure(&divergence(
            named
                .iter()
                .map(|(path, kind)| (path.as_str(), *kind))
                .collect(),
            7,
        ))
        .join("\n");

        assert!(lines.contains("19 path(s) differ"), "{lines}");
        assert!(lines.contains("untracked (19)"), "{lines}");
        assert!(lines.contains("untracked-00.log"), "{lines}");
        assert!(lines.contains("untracked-09.log"), "{lines}");
        assert!(!lines.contains("untracked-10.log"), "{lines}");
        assert!(lines.contains("and 9 more"), "{lines}");
    }

    /// The machine-readable payload carries a sample and counts the rest.
    ///
    /// A repository whose checkout Git rewrote reports every text file it
    /// holds, so an unbounded array here is tens of thousands of path strings
    /// on a piped stdout. The count stays exact either way, and the two
    /// numbers must always add up to it.
    #[test]
    fn the_uncommitted_payload_bounds_its_path_list_without_losing_the_count() {
        let entries = (0..SERIALIZED_PATHS + 40)
            .map(|index| {
                (
                    format!("src/file-{index:04}.rs"),
                    kin_git::GitWorkspaceDivergenceKind::Modified,
                )
            })
            .collect::<Vec<_>>();
        let payload = uncommitted_worktree_payload(&divergence(
            entries
                .iter()
                .map(|(path, kind)| (path.as_str(), *kind))
                .collect(),
            13,
        ))
        .expect("a divergent source carries a payload");

        assert_eq!(payload.observed_paths, SERIALIZED_PATHS + 53);
        assert_eq!(payload.paths.len(), SERIALIZED_PATHS);
        assert_eq!(payload.unlisted_paths, 53);
        assert_eq!(
            payload.paths.len() + payload.unlisted_paths,
            payload.observed_paths,
            "what is listed plus what is not must be what was observed"
        );
    }

    /// The falsification: a source that matched prints nothing, or the
    /// disclosure is noise on every clean init.
    #[test]
    fn a_source_that_matched_gets_no_disclosure() {
        assert!(
            uncommitted_worktree_disclosure(&kin_git::GitWorkspaceDivergenceFacts::none())
                .is_empty()
        );
        assert!(
            uncommitted_worktree_payload(&kin_git::GitWorkspaceDivergenceFacts::none()).is_none()
        );
    }

    fn git(repository: &Path, args: &[&str]) {
        let output = crate::commands::test_subprocess::fixture_git(repository)
            .args(args)
            .output()
            .expect("run fixture git");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_status(repository: &Path) -> String {
        let output = crate::commands::test_subprocess::fixture_git(repository)
            .args(["status", "--porcelain"])
            .output()
            .expect("run fixture git status");
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn write_store(working_dir: &Path) {
        let store = working_dir.join(".kin");
        std::fs::create_dir_all(store.join("objects")).unwrap();
        std::fs::write(store.join("objects").join("pack"), b"store bytes").unwrap();
    }

    /// The whole point, asked of Git itself rather than of a string.
    ///
    /// A converted repository leaves a store that is routinely a gigabyte, and
    /// before this the author saw it as untracked on every `git status` they
    /// ever ran again. The assertion is on the porcelain, because a rule that
    /// parses correctly and does not actually exclude the store reads exactly
    /// like one that works.
    #[test]
    fn an_excluded_store_is_absent_from_git_status() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        git(repo, &["init", "-q"]);
        write_store(repo);

        let before = git_status(repo);
        assert!(
            before.contains(".kin"),
            "the fixture must start with a visible store, or this test proves nothing: {before:?}"
        );

        exclude_store_from_git(repo).unwrap().expect("a rule");

        let after = git_status(repo);
        assert!(
            !after.contains(".kin"),
            "the store must be absent from git status: {after:?}"
        );
    }

    /// Re-running init must not stack duplicate rules.
    #[test]
    fn excluding_the_store_twice_writes_one_rule() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git").join("info")).unwrap();

        let exclude = exclude_store_from_git(repo).unwrap().expect("a rule");
        assert!(
            exclude_store_from_git(repo).unwrap().is_none(),
            "the second pass must find the rule already present"
        );

        let body = std::fs::read_to_string(&exclude).unwrap();
        assert_eq!(
            body.lines()
                .filter(|line| line.trim() == STORE_EXCLUDE_RULE)
                .count(),
            1,
            "exactly one rule survives a re-init: {body:?}"
        );
    }

    /// A repository whose `.git` carries no `info` directory yet.
    #[test]
    fn a_missing_info_directory_is_created_rather_than_refused() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        assert!(!repo.join(".git").join("info").exists());

        let exclude = exclude_store_from_git(repo).unwrap().expect("a rule");
        assert_eq!(exclude, repo.join(".git").join("info").join("exclude"));
        assert!(std::fs::read_to_string(&exclude)
            .unwrap()
            .contains(STORE_EXCLUDE_RULE));
    }

    /// A rule that already excludes the store, in either place Git reads one.
    #[test]
    fn an_existing_rule_is_left_alone() {
        for (name, seed) in [
            (".git/info/exclude", ".kin\n"),
            (".gitignore", "target\n.kin/\n"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let repo = dir.path();
            std::fs::create_dir_all(repo.join(".git").join("info")).unwrap();
            let seeded = repo.join(name);
            std::fs::write(&seeded, seed).unwrap();

            assert!(
                exclude_store_from_git(repo).unwrap().is_none(),
                "{name} already excludes the store"
            );
            assert_eq!(
                std::fs::read_to_string(&seeded).unwrap(),
                seed,
                "{name} must be untouched"
            );
        }
    }

    /// A directory Git does not own is not this command's to write into.
    #[test]
    fn a_directory_without_git_gets_no_rule() {
        let dir = tempfile::tempdir().unwrap();
        assert!(exclude_store_from_git(dir.path()).unwrap().is_none());
        assert!(!dir.path().join(".git").exists());
    }

    /// A linked worktree's excludes live with the repository it came from.
    ///
    /// Kin's own fleet runs almost entirely in linked worktrees, where `.git`
    /// is a pointer file and `info/exclude` is shared through `commondir`. A
    /// resolver that stopped at the pointer would write a rule into the
    /// worktree's private gitdir, where Git never reads one for excludes.
    #[test]
    fn a_linked_worktree_is_followed_to_its_common_directory() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("main");
        let linked = dir.path().join("linked");
        std::fs::create_dir_all(&main).unwrap();
        git(&main, &["init", "-q"]);
        git(&main, &["config", "user.email", "kin-test@example.invalid"]);
        git(&main, &["config", "user.name", "Kin Test"]);
        std::fs::write(main.join("seed"), b"seed").unwrap();
        git(&main, &["add", "seed"]);
        git(&main, &["commit", "-qm", "seed"]);
        git(
            &main,
            &[
                "worktree",
                "add",
                "-q",
                linked.to_str().unwrap(),
                "-b",
                "linked",
            ],
        );
        write_store(&linked);

        let before = git_status(&linked);
        assert!(
            before.contains(".kin"),
            "fixture must start visible: {before:?}"
        );

        let exclude = exclude_store_from_git(&linked).unwrap().expect("a rule");
        assert_eq!(
            exclude.canonicalize().unwrap(),
            main.join(".git")
                .join("info")
                .join("exclude")
                .canonicalize()
                .unwrap(),
            "a linked worktree writes to the shared exclude, not its private gitdir"
        );

        let after = git_status(&linked);
        assert!(!after.contains(".kin"), "store must be excluded: {after:?}");
    }
}
