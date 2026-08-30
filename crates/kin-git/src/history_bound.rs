// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! How much Git history one admission takes in, and where it stopped.
//!
//! Git is an ingestion input at this boundary, so a bounded import is a smaller
//! input rather than a different kind of truth: the graph's own history starts
//! at admission either way. What changes under a bound is where "admission"
//! begins, and that edge is recorded here rather than left for a reader to
//! infer from a change that happens to have no parent.
//!
//! Nothing in this module bounds the lossless Git capture. A bounded
//! repository still holds every Git object and every ref the source had, and
//! every exactness proof over that capture is unchanged. Only the derived
//! semantic history is bounded.

use std::num::NonZeroUsize;

use kin_model::GitObjectId;

/// How much Git history one semantic import derives.
///
/// [`Self::Whole`] is the default in the type system as well as in the product,
/// so a caller that says nothing gets every commit. That is deliberate: a
/// default that silently bounded history would be a worse defect than the
/// memory ceiling the bound exists to work around, because a store missing
/// history nobody asked to drop looks exactly like a store that has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HistoryLimit {
    /// Every commit the snapshot holds, which is every commit reachable from
    /// every ref.
    #[default]
    Whole,
    /// The newest `commits` commits of HEAD's first-parent chain.
    ///
    /// First-parent because it is the only window whose size a caller can
    /// predict: `git log --first-parent` is a chain, so asking for N admits N,
    /// while any reachability-closed window admits however much a merge dragged
    /// in. A side branch merged into that chain is therefore an unadmitted
    /// parent, recorded as one.
    FirstParent { commits: NonZeroUsize },
}

impl HistoryLimit {
    /// The bound as a commit count, or `None` for whole history.
    pub fn commits(&self) -> Option<NonZeroUsize> {
        match self {
            Self::Whole => None,
            Self::FirstParent { commits } => Some(*commits),
        }
    }

    /// Whether this admission takes in every commit it can reach.
    pub fn is_whole(&self) -> bool {
        matches!(self, Self::Whole)
    }

    /// Build a limit from a raw count, treating zero as whole history.
    ///
    /// Zero means "no bound" rather than "admit nothing", because the only way
    /// a zero reaches here is a caller threading an unset option through an
    /// integer, and admitting nothing is never what that caller meant.
    pub fn from_count(commits: usize) -> Self {
        match NonZeroUsize::new(commits) {
            Some(commits) => Self::FirstParent { commits },
            None => Self::Whole,
        }
    }
}

/// Where a bounded admission stopped taking history in.
///
/// Present only when a bound actually cut something. A `--history-limit` larger
/// than the repository's own history admits all of it and records no boundary,
/// because there is no edge to report and claiming one would tell a reader
/// their history is incomplete when it is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedHistoryBoundary {
    /// The count the operator asked for.
    pub requested_limit: usize,
    /// Commits actually admitted, which is the length of the first-parent chain
    /// this walk took. Never more than `requested_limit`.
    pub admitted_commits: usize,
    /// The oldest commit this admission took in. Its parents are the edge.
    pub oldest_admitted_commit: GitObjectId,
    /// Commits that are parents of an admitted commit and were not admitted.
    ///
    /// Both kinds live here and a reader can tell them apart by looking: the
    /// first parent of `oldest_admitted_commit` is where the mainline stops,
    /// and every other entry is a merge's side branch this window did not
    /// reach. Sorted, so two runs of the same admission record the same bytes.
    pub unadmitted_parents: Vec<GitObjectId>,
}

impl AdmittedHistoryBoundary {
    /// One sentence a command can print about where admitted history ends.
    ///
    /// Says what was admitted and what was not, and never says the repository
    /// began here, which is the specific untruth this record exists to prevent.
    pub fn summary(&self) -> String {
        format!(
            "admitted history starts at Git commit {}, which is the oldest of the {} commits \
             `--history-limit {}` took in; {} older or side-branch Git commit(s) are in this \
             store as Git objects and are not in the semantic graph",
            self.oldest_admitted_commit,
            self.admitted_commits,
            self.requested_limit,
            self.unadmitted_parents.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_limit_is_whole_history() {
        assert_eq!(HistoryLimit::default(), HistoryLimit::Whole);
        assert!(HistoryLimit::default().is_whole());
        assert_eq!(HistoryLimit::default().commits(), None);
    }

    #[test]
    fn a_zero_count_is_whole_history_rather_than_nothing() {
        assert_eq!(HistoryLimit::from_count(0), HistoryLimit::Whole);
    }

    #[test]
    fn a_positive_count_bounds_the_first_parent_chain() {
        let limit = HistoryLimit::from_count(800);
        assert_eq!(limit.commits().map(NonZeroUsize::get), Some(800));
        assert!(!limit.is_whole());
    }

    #[test]
    fn the_summary_never_claims_the_repository_began_at_the_boundary() {
        let boundary = AdmittedHistoryBoundary {
            requested_limit: 800,
            admitted_commits: 800,
            oldest_admitted_commit: GitObjectId::Sha1([7; 20]),
            unadmitted_parents: vec![GitObjectId::Sha1([9; 20])],
        };
        let summary = boundary.summary();
        assert!(
            summary.contains("admitted history starts at"),
            "the summary names where admission starts: {summary}"
        );
        assert!(
            summary.contains("are not in the semantic graph"),
            "the summary says what was left out rather than implying nothing was: {summary}"
        );
    }
}
