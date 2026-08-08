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
    /// Paths observed, including any past the listing cap.
    observed_paths: usize,
    /// Observed paths not carried in `paths`, because the walk stopped listing.
    unlisted_paths: usize,
    paths: Vec<UncommittedPathPayload>,
}

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
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

fn uncommitted_worktree_payload(
    divergence: &kin_git::GitWorkspaceDivergenceFacts,
) -> Option<UncommittedWorktreePayload> {
    if divergence.is_empty() {
        return None;
    }
    Some(UncommittedWorktreePayload {
        observed_paths: divergence.observed_paths(),
        unlisted_paths: divergence.untracked_beyond_cap,
        paths: divergence
            .entries
            .iter()
            .map(|entry| UncommittedPathPayload {
                path: entry.path.to_string(),
                state: entry.kind.label(),
            })
            .collect(),
    })
}

fn print_human_result(
    result: &kin_core::InitResult,
    boundary: InitBoundary,
    semantic_enrichment: &SemanticEnrichmentStatus,
) -> Result<()> {
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
        }
        InitBoundary::NativeUnborn => {
            println!("  History: unborn (no synthetic commit)");
            println!("  Workspace: empty exact tree");
        }
    }
    println!(
        "  Semantic enrichment: {}",
        render_semantic_enrichment(semantic_enrichment)
    );
    if let Some(notice) = semantic_absence_notice(semantic_enrichment) {
        println!("{notice}");
    }
    println!(
        "  Store size: {}",
        StoreFootprint::measure(&result.layout).render()
    );
    println!("  {}", store_size_notice());
    for line in uncommitted_worktree_disclosure(&result.workspace_divergence) {
        println!("{line}");
    }
    Ok(())
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
}
