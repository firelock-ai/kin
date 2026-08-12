// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Which repository paths own their host subtree independently of this
//! repository's source projection, decided against a consistent snapshot.
//!
//! A graph-only member (a Gitlink, or a path the host cannot represent)
//! declares that this repository does not own the host subtree beneath it.
//! Admission never traverses one, so host content written under it is not this
//! repository's content and no watcher event naming it carries an observation
//! of this repository's projection.
//!
//! Removing the member does not turn that content into something someone just
//! wrote. Watcher events outlive the transition that removes it, though, so a
//! membership verdict read off the tree as it stands when those events drain
//! reads them as ordinary new files: ambient admission sweeps the nested
//! checkout into the workspace, and the next transition refuses because the
//! workspace is ahead of the base it was just made level with.
//!
//! The retirement below is what makes the verdict independent of arrival time.
//! It is recorded by the transition that drops the member, while both sides of
//! that transition are in hand, rather than sampled from the tree afterwards.
//! Every instant is then covered by exactly one of the two rules: before the
//! transition the member is live and the event is dropped, after it the path is
//! retired and the content is reported untracked instead of admitted. There is
//! no window in between for a stale event to fall through, which is the
//! difference between closing this race and shortening it.

use std::collections::BTreeSet;
use std::sync::Mutex;

use kin_model::{RepoPath, ResolvedTree};

/// The graph-only members of one repository tree.
///
/// A member is any tracked path whose source projection is not materialized:
/// Gitlinks everywhere, plus paths the host cannot name. Both own their host
/// subtree in the sense that matters here, which is that admission does not
/// traverse them.
pub fn members_of(tree: &ResolvedTree) -> kin_core::Result<BTreeSet<RepoPath>> {
    let mut members = BTreeSet::new();
    for artifact in tree.artifacts_by_path() {
        if kin_core::source_projection_disposition(&artifact.path, artifact.entry)?
            != kin_core::SourceProjectionDisposition::Materialized
        {
            members.insert(artifact.path.clone());
        }
    }
    Ok(members)
}

/// Paths that were graph-only repository members until a transition dropped
/// them, and whose host subtrees are therefore pre-existing content rather than
/// content ambient observation may admit.
///
/// A retirement suppresses ambient admission only. The paths stay visible: they
/// are counted and named by the untracked-content surfaces exactly like any
/// other host content the walk declined to take, so an explicit admission seam
/// still sweeps them and reports what it took.
#[derive(Debug, Default)]
pub struct RetiredGraphOnlyMembers {
    paths: Mutex<BTreeSet<RepoPath>>,
}

impl RetiredGraphOnlyMembers {
    /// Record that these paths stopped being graph-only repository members.
    ///
    /// Additive by construction. A transition may only ever widen what is
    /// retired, so ordering this before the graph advances leaves no instant at
    /// which a path is neither a live member nor a retired one.
    pub fn retire<'a>(&self, paths: impl IntoIterator<Item = &'a RepoPath>) {
        let mut retired = match self.paths.lock() {
            Ok(retired) => retired,
            Err(poisoned) => poisoned.into_inner(),
        };
        for path in paths {
            retired.insert(path.clone());
        }
    }

    /// Drop retirements for paths that are graph-only repository members again.
    ///
    /// Called with the live member set, so a path restored by a later
    /// transition is covered by the live rule from then on and does not need a
    /// retirement standing behind it.
    pub fn forget_live_members<'a>(&self, live: impl IntoIterator<Item = &'a RepoPath>) {
        let mut retired = match self.paths.lock() {
            Ok(retired) => retired,
            Err(poisoned) => poisoned.into_inner(),
        };
        for path in live {
            retired.remove(path);
        }
    }

    /// Forget every retirement.
    ///
    /// An explicit admission seam walks the whole working copy and takes what it
    /// finds, including the subtrees a retirement was holding back. Once that
    /// has happened the caller has said outright that this content is theirs, so
    /// ambient observation resumes over it.
    pub fn clear(&self) {
        let mut retired = match self.paths.lock() {
            Ok(retired) => retired,
            Err(poisoned) => poisoned.into_inner(),
        };
        retired.clear();
    }

    /// Whether one repository path is a retired member or lies beneath one.
    pub fn covers(&self, path: &RepoPath) -> bool {
        let retired = match self.paths.lock() {
            Ok(retired) => retired,
            Err(poisoned) => poisoned.into_inner(),
        };
        covered_by(&retired, path)
    }

    /// The retired members, for one pass to read instead of locking per path.
    pub fn snapshot(&self) -> BTreeSet<RepoPath> {
        match self.paths.lock() {
            Ok(retired) => retired.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

/// Whether one repository path is a member of `retired` or lies beneath one.
///
/// The prefix compare is on path segments, so a sibling whose name merely
/// begins with a retired member's name is a different path.
pub fn covered_by(retired: &BTreeSet<RepoPath>, path: &RepoPath) -> bool {
    retired.iter().any(|member| {
        path == member
            || path
                .as_bytes()
                .strip_prefix(member.as_bytes())
                .is_some_and(|suffix| suffix.starts_with(b"/"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> RepoPath {
        RepoPath::from_utf8(value).expect("repository path")
    }

    #[test]
    fn a_retired_member_covers_itself_and_its_descendants() {
        let retired = RetiredGraphOnlyMembers::default();
        retired.retire([&path("vendor/dependency")]);
        assert!(retired.covers(&path("vendor/dependency")));
        assert!(retired.covers(&path("vendor/dependency/nested/owned.txt")));
    }

    /// The prefix compare is on path segments, not bytes. A sibling whose name
    /// merely starts with a retired member's name is a different path and must
    /// keep reconciling.
    #[test]
    fn a_sibling_sharing_a_name_prefix_is_not_covered() {
        let retired = RetiredGraphOnlyMembers::default();
        retired.retire([&path("vendor/dependency")]);
        assert!(!retired.covers(&path("vendor/dependency-notes.md")));
        assert!(!retired.covers(&path("vendor/other/lib.rs")));
        assert!(!retired.covers(&path("vendor")));
    }

    #[test]
    fn a_member_restored_by_a_later_transition_stops_being_retired() {
        let retired = RetiredGraphOnlyMembers::default();
        retired.retire([&path("vendor/dependency")]);
        retired.forget_live_members([&path("vendor/dependency")]);
        assert!(!retired.covers(&path("vendor/dependency/nested/owned.txt")));
        assert!(retired.snapshot().is_empty());
    }

    #[test]
    fn an_explicit_sweep_forgets_every_retirement() {
        let retired = RetiredGraphOnlyMembers::default();
        retired.retire([&path("vendor/dependency"), &path("vendor/other")]);
        retired.clear();
        assert!(!retired.covers(&path("vendor/dependency/nested/owned.txt")));
        assert!(!retired.covers(&path("vendor/other/lib.rs")));
    }
}
