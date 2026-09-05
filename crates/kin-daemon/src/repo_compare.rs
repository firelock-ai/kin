// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `GET /repos/{repo_id}/compare` — what changed between two refs, from the graph.
//!
//! The daemon could answer for one file's bytes and for one ref's whole tree. It
//! could not answer the question a reader asks before either: what is different
//! between these two refs. A caller that cannot ask it has to decide what an
//! unanswered comparison means, and the shape closest to hand is a comparison of
//! zero files, zero ahead and zero behind, which is indistinguishable from two
//! refs that really are identical.
//!
//! So this route refuses wherever it cannot compute, and the refusals are the
//! design rather than the leftovers. A ref that does not resolve names which
//! side. Two histories with no common ancestor refuse rather than reporting no
//! distance. A history walk past its bound refuses and names the bound. None of
//! them is a comparison of zero files.
//!
//! Identities, not bytes. The changed-file list is a set difference over the two
//! resolved trees, and a path present in both is modified when its tree entry
//! differs, which catches a mode change as well as a content change. Nothing
//! here reads the content-addressed store, because a comparison needs to know
//! which files differ and not what they say; a caller wanting the text asks
//! `/repos/{repo_id}/blob` twice. And nothing here reads a filesystem.
//!
//! Renames are not reported, and that is a claim about evidence rather than a
//! gap. A resolved tree carries a path and an entry per artifact and no rename
//! record, so a rename could only be inferred by similarity. An addition beside
//! a deletion is what the tree proves.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::api::{repository_read_view, RepositoryReadView};
use crate::repo_blob::{resolve_read_point, RepoBlobRefusal};
use crate::state::DaemonState;

/// How many changes either side's ancestor walk records before refusing.
///
/// A bound is needed because two histories with no common ancestor are only
/// discovered by walking both of them to their roots, and this route answers a
/// page. Past it the honest answer is that the distance was not established,
/// which is why the refusal names the bound rather than reporting a distance of
/// zero.
pub const MAX_COMPARE_HISTORY_DEPTH: usize = 10_000;

/// The header every refusal from this route carries, naming which refusal it is.
pub const REPO_COMPARE_REFUSAL_HEADER: &str = "x-kin-compare-refusal";

/// Which refusal, in a closed set a caller can branch on without reading English.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoCompareRefusal {
    /// The request itself could not be understood, so nothing was resolved.
    BadRequest,
    /// This daemon does not serve a repository by that id.
    UnknownRepository,
    /// It serves the id and could not read it as a repository.
    RepositoryUnreadable,
    /// One side named neither a ref this repository carries nor a change id.
    UnknownRef,
    /// One side is a short alias more than one ref answers to.
    AmbiguousRef,
    /// The two histories share no ancestor, so there is no distance to report.
    NoCommonAncestor,
    /// One side's history ran past the walk's bound before an ancestor was found.
    HistoryTooDeep,
    /// Several best common ancestors exist and none descends from another.
    AmbiguousMergeBase,
    /// A changed path's bytes are not UTF-8, so this response cannot name it.
    PathNotRepresentable,
}

impl RepoCompareRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad-request",
            Self::UnknownRepository => "unknown-repository",
            Self::RepositoryUnreadable => "repository-unreadable",
            Self::UnknownRef => "unknown-ref",
            Self::AmbiguousRef => "ambiguous-ref",
            Self::NoCommonAncestor => "no-common-ancestor",
            Self::HistoryTooDeep => "history-too-deep",
            Self::AmbiguousMergeBase => "ambiguous-merge-base",
            Self::PathNotRepresentable => "path-not-representable",
        }
    }
}

/// A refusal from this route: a status, a kind, and a sentence for a person.
#[derive(Debug)]
pub struct RepoCompareError {
    pub status: StatusCode,
    pub kind: RepoCompareRefusal,
    pub message: String,
}

impl RepoCompareError {
    fn new(status: StatusCode, kind: RepoCompareRefusal, message: impl Into<String>) -> Self {
        Self {
            status,
            kind,
            message: message.into(),
        }
    }

    /// Carry a blob-route refusal across under the matching compare kind.
    ///
    /// Both routes resolve a read point by the same rule, so they refuse a ref
    /// for the same reasons. Mapping the kind rather than re-deriving it is what
    /// keeps one rule: the exact-name precedence and the ambiguous-alias refusal
    /// that route already carries apply here without being written twice.
    fn from_read_point(side: &str, error: crate::repo_blob::RepoBlobError) -> Self {
        let kind = match error.kind {
            RepoBlobRefusal::UnknownRef => RepoCompareRefusal::UnknownRef,
            RepoBlobRefusal::AmbiguousRef => RepoCompareRefusal::AmbiguousRef,
            RepoBlobRefusal::UnknownRepository => RepoCompareRefusal::UnknownRepository,
            _ => RepoCompareRefusal::RepositoryUnreadable,
        };
        // Which side failed is the first thing a caller needs and the status
        // cannot carry it, so it leads the sentence.
        Self::new(error.status, kind, format!("{side}: {}", error.message))
    }
}

impl IntoResponse for RepoCompareError {
    fn into_response(self) -> axum::response::Response {
        let mut response = (self.status, self.message).into_response();
        response.headers_mut().insert(
            HeaderName::from_static(REPO_COMPARE_REFUSAL_HEADER),
            HeaderValue::from_static(self.kind.as_str()),
        );
        response
    }
}

#[derive(Debug, Deserialize)]
pub struct RepoCompareQuery {
    /// A ref name or a canonical change id. Required: this route has no default.
    base: String,
    head: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoCompareFileEntry {
    pub path: String,
    /// `added`, `deleted` or `modified`. Never `renamed`; see the module note.
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoCompareResponse {
    pub repo_id: String,
    /// The change each side resolved to, not the string the caller sent.
    pub base_ref: String,
    pub head_ref: String,
    pub merge_base_ref: String,
    pub ahead: usize,
    pub behind: usize,
    pub files: Vec<RepoCompareFileEntry>,
    /// Always empty here. Conflict detection is a merge question, not a
    /// comparison one, and an empty list is the truthful answer rather than a
    /// placeholder: this route establishes no conflicts and claims none.
    pub conflicts: Vec<serde_json::Value>,
}

/// GET /repos/{repo_id}/compare — the changed-file list and the distance.
pub async fn repo_compare(
    Path(repo_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
    // Fallible for the same reason the blob route's is: an axum rejection
    // carries no refusal header, and a caller branching on that header would
    // read a malformed request as a route that forgot to name its refusal.
    query: Result<Query<RepoCompareQuery>, QueryRejection>,
) -> Result<impl IntoResponse, RepoCompareError> {
    let Query(query) = query.map_err(|rejection| {
        RepoCompareError::new(
            rejection.status(),
            RepoCompareRefusal::BadRequest,
            rejection.body_text(),
        )
    })?;

    // Both sides are required and neither may be blank, checked before anything
    // is opened. The shared resolver reads a blank reference as no reference
    // given and answers the repository's default ref, which is correct for a
    // route that has a default and wrong for one that does not: a blank base
    // would quietly become the head's own ref, and the answer would be zero
    // files, zero ahead and zero behind, which is the shape this route exists
    // not to invent. The refusal travels through this route's own error so it
    // carries the refusal header like every other.
    let base = nonblank_ref("base", &query.base)?;
    let head = nonblank_ref("head", &query.head)?;

    // Three views because `resolve_tree_at` consumes one and this needs two
    // trees plus a history walk. On a hosted daemon each is a generation-cache
    // read, which is the path that exists to make repeated reads cheap.
    let walk_view = open_view(&state, &repo_id).await?;
    let base_change = resolve_read_point(&walk_view, Some(base), &repo_id)
        .map_err(|error| RepoCompareError::from_read_point("base", error))?
        .0;
    let head_change = resolve_read_point(&walk_view, Some(head), &repo_id)
        .map_err(|error| RepoCompareError::from_read_point("head", error))?
        .0;

    let distance = measure_distance(&walk_view, &base_change, &head_change)?;

    let base_tree = open_view(&state, &repo_id)
        .await?
        .resolve_tree_at(&state, &base_change)
        .map_err(|parts| {
            RepoCompareError::new(parts.0, RepoCompareRefusal::RepositoryUnreadable, parts.1)
        })?;
    let head_tree = open_view(&state, &repo_id)
        .await?
        .resolve_tree_at(&state, &head_change)
        .map_err(|parts| {
            RepoCompareError::new(parts.0, RepoCompareRefusal::RepositoryUnreadable, parts.1)
        })?;

    Ok(Json(RepoCompareResponse {
        repo_id,
        base_ref: base_change.to_string(),
        head_ref: head_change.to_string(),
        merge_base_ref: distance.merge_base.to_string(),
        ahead: distance.ahead,
        behind: distance.behind,
        files: changed_files(&base_tree, &head_tree)?,
        conflicts: Vec::new(),
    }))
}

/// One side of the comparison, refused when it names nothing.
fn nonblank_ref<'a>(side: &str, value: &'a str) -> Result<&'a str, RepoCompareError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(RepoCompareError::new(
            StatusCode::BAD_REQUEST,
            RepoCompareRefusal::BadRequest,
            format!(
                "{side} must name a ref or a change id, and this request left it blank. This \
                 route compares two read points a caller chose and has no default for either."
            ),
        ));
    }
    Ok(trimmed)
}

async fn open_view(
    state: &DaemonState,
    repo_id: &str,
) -> Result<RepositoryReadView, RepoCompareError> {
    repository_read_view(state, repo_id).await.map_err(|parts| {
        let kind = if parts.0 == StatusCode::NOT_FOUND {
            RepoCompareRefusal::UnknownRepository
        } else {
            RepoCompareRefusal::RepositoryUnreadable
        };
        RepoCompareError::new(parts.0, kind, parts.1)
    })
}

#[derive(Debug)]
pub(crate) struct Distance {
    pub(crate) merge_base: kin_model::SemanticChangeId,
    pub(crate) ahead: usize,
    pub(crate) behind: usize,
}

/// Every ancestor of `tip`, inclusive of it, over ALL parents.
///
/// First-parent only is the wrong walk here and the difference is not academic.
/// A head that merged a side branch reaches those changes through a second
/// parent, so a first-parent walk reports a distance that omits everything the
/// merge brought in, and two tips whose only relationship runs through a merge
/// can look unrelated. Distance is a question about reachability, so the walk
/// has to follow every edge reachability follows.
fn ancestors<P>(
    tip: &kin_model::SemanticChangeId,
    side: &str,
    parents_of: &mut P,
) -> Result<std::collections::HashSet<kin_model::SemanticChangeId>, RepoCompareError>
where
    P: FnMut(
        &kin_model::SemanticChangeId,
    ) -> Result<Vec<kin_model::SemanticChangeId>, RepoCompareError>,
{
    let mut seen = std::collections::HashSet::new();
    let mut queue = vec![*tip];
    while let Some(change_id) = queue.pop() {
        if !seen.insert(change_id) {
            continue;
        }
        if seen.len() > MAX_COMPARE_HISTORY_DEPTH {
            return Err(too_deep(side));
        }
        queue.extend(parents_of(&change_id)?);
    }
    Ok(seen)
}

/// How far apart two changes are, by ancestor-set difference.
///
/// `ahead` is what the head reaches and the base does not, `behind` the reverse,
/// which is the same shape `git rev-list --count base...head` answers and
/// therefore counts changes a merge brought in. The merge base is the
/// descendant-most common ancestor: a common ancestor that no other common
/// ancestor descends from. Several incomparable ones is a real repository shape
/// and this response can carry one, so it refuses rather than picking.
pub(crate) fn measure_distance_with<P>(
    base: &kin_model::SemanticChangeId,
    head: &kin_model::SemanticChangeId,
    parents_of: &mut P,
) -> Result<Distance, RepoCompareError>
where
    P: FnMut(
        &kin_model::SemanticChangeId,
    ) -> Result<Vec<kin_model::SemanticChangeId>, RepoCompareError>,
{
    let base_ancestors = ancestors(base, "base", parents_of)?;
    let head_ancestors = ancestors(head, "head", parents_of)?;
    let common: std::collections::HashSet<_> = base_ancestors
        .intersection(&head_ancestors)
        .copied()
        .collect();
    if common.is_empty() {
        return Err(RepoCompareError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            RepoCompareRefusal::NoCommonAncestor,
            format!(
                "{base} and {head} share no ancestor, so there is no distance between them to \
                 report"
            ),
        ));
    }

    // A common ancestor that another common ancestor descends from is not the
    // best one. Striking everything reachable from a common ancestor's PARENTS
    // leaves exactly the descendant-most, and one walk over the union of those
    // ancestries answers it for every candidate at once: a change already
    // walked has already been struck, so a second visit could add nothing.
    // Starting at parents rather than at the candidates themselves is what
    // keeps a candidate from striking itself.
    let mut superseded = std::collections::HashSet::new();
    let mut walked = std::collections::HashSet::new();
    let mut queue = Vec::new();
    for candidate in &common {
        queue.extend(parents_of(candidate)?);
    }
    while let Some(change_id) = queue.pop() {
        if !walked.insert(change_id) {
            continue;
        }
        if common.contains(&change_id) {
            superseded.insert(change_id);
        }
        queue.extend(parents_of(&change_id)?);
    }
    let mut best: Vec<_> = common.difference(&superseded).copied().collect();
    best.sort_by_key(|change_id| change_id.to_string());
    let merge_base = match best.as_slice() {
        [only] => *only,
        [] => {
            return Err(RepoCompareError::new(
                StatusCode::FAILED_DEPENDENCY,
                RepoCompareRefusal::RepositoryUnreadable,
                format!(
                    "{base} and {head} share ancestors but none is descendant-most, which means \
                     the history reached here contains a cycle"
                ),
            ));
        }
        several => {
            let names: Vec<String> = several.iter().map(ToString::to_string).collect();
            return Err(RepoCompareError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                RepoCompareRefusal::AmbiguousMergeBase,
                format!(
                    "{base} and {head} have {} best common ancestors and none descends from \
                     another: {}. This response carries one merge base, so it will not pick.",
                    several.len(),
                    names.join(", ")
                ),
            ));
        }
    };

    Ok(Distance {
        merge_base,
        ahead: head_ancestors.difference(&base_ancestors).count(),
        behind: base_ancestors.difference(&head_ancestors).count(),
    })
}

fn measure_distance(
    view: &RepositoryReadView,
    base: &kin_model::SemanticChangeId,
    head: &kin_model::SemanticChangeId,
) -> Result<Distance, RepoCompareError> {
    // Parents are read once per change and cached, because the best-common-
    // ancestor pass walks the common set again and a repository read is not
    // free on either arm.
    let mut cache: HashMap<kin_model::SemanticChangeId, Vec<kin_model::SemanticChangeId>> =
        HashMap::new();
    let mut parents_of = |change_id: &kin_model::SemanticChangeId| {
        if let Some(parents) = cache.get(change_id) {
            return Ok(parents.clone());
        }
        let change = view
            .change(change_id)
            .map_err(|parts| {
                RepoCompareError::new(parts.0, RepoCompareRefusal::RepositoryUnreadable, parts.1)
            })?
            .ok_or_else(|| {
                RepoCompareError::new(
                    StatusCode::FAILED_DEPENDENCY,
                    RepoCompareRefusal::RepositoryUnreadable,
                    format!("history references missing change {change_id}"),
                )
            })?;
        let parents = change.parents.clone();
        cache.insert(*change_id, parents.clone());
        Ok(parents)
    };
    measure_distance_with(base, head, &mut parents_of)
}

fn too_deep(side: &str) -> RepoCompareError {
    RepoCompareError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        RepoCompareRefusal::HistoryTooDeep,
        format!(
            "{side} history reached this route's {MAX_COMPARE_HISTORY_DEPTH}-change walk limit \
             before the comparison could be established"
        ),
    )
}

/// The changed-file list, as a set difference over two resolved trees.
///
/// A path in both is modified when its ENTRY differs rather than when its blob
/// digest differs, so a file that changed only its mode is still reported. A
/// path in neither tree cannot appear, and a path in both with an identical
/// entry is not a change and is omitted.
pub(crate) fn changed_files(
    base: &kin_model::ResolvedTree,
    head: &kin_model::ResolvedTree,
) -> Result<Vec<RepoCompareFileEntry>, RepoCompareError> {
    let name = |path: &kin_model::RepoPath| {
        path.as_utf8().map(ToOwned::to_owned).ok_or_else(|| {
            RepoCompareError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                RepoCompareRefusal::PathNotRepresentable,
                format!("this comparison cannot name the changed path {path}, whose bytes are not UTF-8"),
            )
        })
    };
    let base_by_path: HashMap<_, _> = base
        .artifacts()
        .map(|artifact| (artifact.path.clone(), artifact))
        .collect();
    let mut files = Vec::new();
    let mut seen_in_head = std::collections::HashSet::new();
    for artifact in head.artifacts() {
        seen_in_head.insert(artifact.path.clone());
        match base_by_path.get(&artifact.path) {
            None => files.push(RepoCompareFileEntry {
                path: name(&artifact.path)?,
                status: "added".to_string(),
            }),
            Some(before) if before.entry != artifact.entry => files.push(RepoCompareFileEntry {
                path: name(&artifact.path)?,
                status: "modified".to_string(),
            }),
            Some(_) => {}
        }
    }
    for artifact in base.artifacts() {
        if !seen_in_head.contains(&artifact.path) {
            files.push(RepoCompareFileEntry {
                path: name(&artifact.path)?,
                status: "deleted".to_string(),
            });
        }
    }
    // Sorted so two runs over one pair of trees answer identically, which is
    // what lets a caller cache or diff the answer itself.
    files.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.status.cmp(&right.status))
    });
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A change id built from one byte, so a test DAG reads like a diagram.
    fn id(n: u8) -> kin_model::SemanticChangeId {
        kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([n; 32]))
    }

    /// A change id minted from a counter, distinct from every `id(n)` because
    /// its trailing bytes are zero and `id`'s are not.
    fn minted_id(n: u32) -> kin_model::SemanticChangeId {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&n.to_le_bytes());
        kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes(bytes))
    }

    /// A synthetic history: child to parents, newest first in each list.
    ///
    /// The distance question is about the shape of a graph, so the tests give it
    /// a graph directly. A fixture that could only be built by publishing real
    /// changes could not express a diamond in six lines, and the diamond is the
    /// case a first-parent walk gets wrong.
    fn dag(
        edges: &[(u8, &[u8])],
    ) -> impl FnMut(
        &kin_model::SemanticChangeId,
    ) -> Result<Vec<kin_model::SemanticChangeId>, RepoCompareError> {
        let map: HashMap<kin_model::SemanticChangeId, Vec<kin_model::SemanticChangeId>> = edges
            .iter()
            .map(|(child, parents)| (id(*child), parents.iter().map(|p| id(*p)).collect()))
            .collect();
        move |change_id: &kin_model::SemanticChangeId| {
            Ok(map.get(change_id).cloned().unwrap_or_default())
        }
    }

    #[test]
    fn a_merge_is_counted_over_every_parent_and_not_the_first_one_only() {
        // 1 -> 2 and 1 -> 3, then 4 merges both with 2 as its first parent.
        //   base = 2, head = 4.
        // Over all parents: head reaches 4 and 3 that the base does not, so
        // ahead is 2. A first-parent walk from 4 goes 4, 2 and never sees 3, so
        // it would answer ahead 1 and silently omit the change the merge brought
        // in. That difference is the whole reason this walk follows every edge.
        let mut parents = dag(&[(4, &[2, 3]), (3, &[1]), (2, &[1]), (1, &[])]);
        let distance = measure_distance_with(&id(2), &id(4), &mut parents).unwrap();
        assert_eq!(distance.merge_base, id(2));
        assert_eq!(
            distance.ahead, 2,
            "the merged side branch has to be counted"
        );
        assert_eq!(distance.behind, 0);
    }

    #[test]
    fn two_identical_tips_are_zero_apart_and_their_own_merge_base() {
        // Zero and zero is the truthful answer here, and only here. It is the
        // reading a fabricated compare used to give for reads that never
        // happened, so the case that legitimately produces it is pinned.
        let mut parents = dag(&[(2, &[1]), (1, &[])]);
        let distance = measure_distance_with(&id(2), &id(2), &mut parents).unwrap();
        assert_eq!(distance.merge_base, id(2));
        assert_eq!(distance.ahead, 0);
        assert_eq!(distance.behind, 0);
    }

    #[test]
    fn a_base_that_is_an_ancestor_of_the_head_is_the_merge_base() {
        let mut parents = dag(&[(3, &[2]), (2, &[1]), (1, &[])]);
        let distance = measure_distance_with(&id(1), &id(3), &mut parents).unwrap();
        assert_eq!(distance.merge_base, id(1));
        assert_eq!(distance.ahead, 2);
        assert_eq!(distance.behind, 0);

        // And the same pair the other way round, so ahead and behind cannot be
        // swapped without a test noticing.
        let distance = measure_distance_with(&id(3), &id(1), &mut parents).unwrap();
        assert_eq!(distance.ahead, 0);
        assert_eq!(distance.behind, 2);
    }

    #[test]
    fn unrelated_histories_refuse_rather_than_reporting_no_distance() {
        let mut parents = dag(&[(2, &[1]), (1, &[]), (4, &[3]), (3, &[])]);
        let refusal = measure_distance_with(&id(2), &id(4), &mut parents).unwrap_err();
        assert_eq!(refusal.kind, RepoCompareRefusal::NoCommonAncestor);
        assert_eq!(refusal.status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn two_incomparable_best_common_ancestors_refuse_rather_than_picking_one() {
        // Criss-cross: 4 and 5 each merge both 2 and 3, and neither 2 nor 3
        // descends from the other. Picking either silently would report a
        // distance measured from a base the caller never chose.
        let mut parents = dag(&[(5, &[2, 3]), (4, &[2, 3]), (3, &[1]), (2, &[1]), (1, &[])]);
        let refusal = measure_distance_with(&id(4), &id(5), &mut parents).unwrap_err();
        assert_eq!(refusal.kind, RepoCompareRefusal::AmbiguousMergeBase);
        assert!(
            refusal.message.contains("will not pick"),
            "the refusal has to say it is declining rather than failing: {}",
            refusal.message
        );
    }

    #[test]
    fn a_history_past_the_walk_bound_refuses_and_names_the_bound() {
        // A history with no end: every change's parent is one nobody has seen
        // before, so the walk runs out of budget rather than out of history.
        // A cycle would not exercise this at all, because revisiting a change
        // the walk already recorded terminates it correctly.
        let mut minted: u32 = 0;
        let mut parents = |_change_id: &kin_model::SemanticChangeId| {
            minted += 1;
            Ok(vec![minted_id(minted)])
        };
        let refusal = measure_distance_with(&id(1), &id(9), &mut parents).unwrap_err();
        assert_eq!(refusal.kind, RepoCompareRefusal::HistoryTooDeep);
        assert!(
            refusal
                .message
                .contains(&MAX_COMPARE_HISTORY_DEPTH.to_string()),
            "the refusal has to name the bound it hit: {}",
            refusal.message
        );
    }

    fn tree(entries: &[(&str, u8, bool)]) -> kin_model::ResolvedTree {
        kin_model::ResolvedTree::from_artifacts(entries.iter().map(|(path, digest, executable)| {
            kin_model::ResolvedArtifact::new(
                kin_model::ArtifactId::new(),
                kin_model::RepoPath::from_utf8(*path).unwrap(),
                kin_model::TreeEntry::blob(
                    kin_model::Hash256::from_bytes([*digest; 32]),
                    *executable,
                ),
            )
        }))
        .unwrap()
    }

    #[test]
    fn the_changed_file_list_is_the_difference_between_two_trees() {
        let base = tree(&[
            ("src/kept.rs", 1, false),
            ("src/gone.rs", 2, false),
            ("src/edited.rs", 3, false),
        ]);
        let head = tree(&[
            ("src/kept.rs", 1, false),
            ("src/edited.rs", 4, false),
            ("src/new.rs", 5, false),
        ]);
        let files = changed_files(&base, &head).unwrap();
        let rendered: Vec<(String, String)> = files
            .into_iter()
            .map(|entry| (entry.path, entry.status))
            .collect();
        assert_eq!(
            rendered,
            vec![
                ("src/edited.rs".to_string(), "modified".to_string()),
                ("src/gone.rs".to_string(), "deleted".to_string()),
                ("src/new.rs".to_string(), "added".to_string()),
            ],
            "an unchanged path must not appear, and the order must be stable"
        );
    }

    #[test]
    fn a_file_whose_only_change_is_its_mode_is_still_reported() {
        // Comparing blob digests alone would call these identical, and a file
        // that became executable did change.
        let base = tree(&[("scripts/run.sh", 7, false)]);
        let head = tree(&[("scripts/run.sh", 7, true)]);
        let files = changed_files(&base, &head).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].status, "modified");
    }

    /// A tree whose one path is not UTF-8, which a JSON response cannot name.
    fn tree_with_raw_path(bytes: &[u8]) -> kin_model::ResolvedTree {
        kin_model::ResolvedTree::from_artifacts(std::iter::once(kin_model::ResolvedArtifact::new(
            kin_model::ArtifactId::new(),
            kin_model::RepoPath::from_bytes(bytes.to_vec()).unwrap(),
            kin_model::TreeEntry::blob(kin_model::Hash256::from_bytes([9; 32]), false),
        )))
        .unwrap()
    }

    #[test]
    fn a_changed_path_that_is_not_utf8_is_refused_rather_than_mangled() {
        // A repository path is bytes, and JSON strings are not. Answering the
        // lossy rendering would name a path that is not the one that changed,
        // and a caller asking for that path's bytes would be told it does not
        // exist. The refusal is the honest answer.
        let base = tree(&[("src/kept.rs", 1, false)]);
        let head = tree_with_raw_path(b"src/\xff\xfe.rs");
        let refusal = changed_files(&base, &head).unwrap_err();
        assert_eq!(refusal.kind, RepoCompareRefusal::PathNotRepresentable);
        assert_eq!(refusal.status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn two_identical_trees_produce_no_changed_files() {
        // The control for both tests above: a real empty list, from two trees
        // that really are the same, which is what makes a non-empty one mean
        // something.
        let base = tree(&[("src/kept.rs", 1, false), ("src/also.rs", 2, true)]);
        let head = tree(&[("src/kept.rs", 1, false), ("src/also.rs", 2, true)]);
        assert!(changed_files(&base, &head).unwrap().is_empty());
    }

    #[test]
    fn every_refusal_kind_has_a_distinct_stable_spelling() {
        let kinds = [
            RepoCompareRefusal::BadRequest,
            RepoCompareRefusal::UnknownRepository,
            RepoCompareRefusal::RepositoryUnreadable,
            RepoCompareRefusal::UnknownRef,
            RepoCompareRefusal::AmbiguousRef,
            RepoCompareRefusal::NoCommonAncestor,
            RepoCompareRefusal::HistoryTooDeep,
            RepoCompareRefusal::AmbiguousMergeBase,
            RepoCompareRefusal::PathNotRepresentable,
        ];
        let spellings: std::collections::BTreeSet<&str> =
            kinds.iter().map(|kind| kind.as_str()).collect();
        assert_eq!(spellings.len(), kinds.len(), "two kinds share a spelling");
        assert!(
            spellings.iter().all(|s| HeaderValue::from_str(s).is_ok()),
            "every spelling has to survive the header it travels in"
        );
    }
}
