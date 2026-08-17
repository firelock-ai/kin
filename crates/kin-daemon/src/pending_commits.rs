// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Commits that have entered this daemon and have not left it yet.
//!
//! The ambient reconcile tick and `/commands/commit` both admit the working
//! copy, and both publish a repository-authority successor to do it. Preparing
//! that successor and persisting the store are O(store) on every commit, so the
//! two of them running back to back costs one whole publication more than the
//! edit needed: the tick publishes the file, and the commit publishes it again
//! inside its own transaction moments later.
//!
//! This is how the tick learns that the second half of that pair is already on
//! its way. A commit announces itself the moment its handler is entered, before
//! it waits on the coordination gate, and stops announcing when the handler
//! returns. The tick reads that and holds off, because a commit admits the whole
//! working copy itself and carries the tree in the same transaction that
//! publishes its change.
//!
//! The counter is not the gate's waiter count. A `tokio::sync::Mutex` does not
//! expose one, and it would answer a narrower question anyway: a commit that has
//! entered the daemon but has not reached the gate yet is exactly as certain to
//! publish as one already queued on it.

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Notify;

/// Commits currently inside this daemon, and a wakeup for whoever is waiting on
/// one to arrive.
#[derive(Debug, Default)]
pub(crate) struct PendingCommits {
    inside: AtomicUsize,
    arrived: Notify,
}

impl PendingCommits {
    /// Announce one commit for as long as the returned guard is held.
    ///
    /// Take it at the top of the handler, before any lock: the point of the
    /// announcement is to be readable by a tick that has not started publishing
    /// yet, and every microsecond spent before it is announced is a microsecond
    /// in which the tick can commit to a publication this commit makes
    /// redundant.
    pub(crate) fn announce(&self) -> PendingCommit<'_> {
        self.inside.fetch_add(1, Ordering::SeqCst);
        // Wakes whoever is already waiting. A wakeup that finds nobody is
        // dropped rather than stored, which is why a waiter registers its
        // interest before it reads the count rather than after.
        self.arrived.notify_waiters();
        PendingCommit { commits: self }
    }

    /// Whether any commit is inside the daemon right now.
    pub(crate) fn any(&self) -> bool {
        self.inside.load(Ordering::SeqCst) > 0
    }

    /// A future that completes when a commit announces itself.
    ///
    /// Enable it (`Notified::enable`) before reading [`any`](Self::any), so a
    /// commit that arrives between the read and the wait still wakes the
    /// waiter instead of being missed by both.
    pub(crate) fn arrival(&self) -> tokio::sync::futures::Notified<'_> {
        self.arrived.notified()
    }
}

/// One commit's announcement, withdrawn when this is dropped.
#[derive(Debug)]
pub(crate) struct PendingCommit<'a> {
    commits: &'a PendingCommits,
}

impl Drop for PendingCommit<'_> {
    fn drop(&mut self) {
        self.commits.inside.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_commit_is_announced_for_exactly_as_long_as_its_guard_lives() {
        let commits = PendingCommits::default();
        assert!(!commits.any(), "an idle daemon announces no commit");
        {
            let _commit = commits.announce();
            assert!(commits.any(), "an entered commit announces itself");
        }
        assert!(
            !commits.any(),
            "a commit that left the daemon must stop announcing itself, or the tick \
             would hold off forever for a commit that already finished"
        );
    }

    #[test]
    fn concurrent_commits_are_counted_rather_than_flagged() {
        let commits = PendingCommits::default();
        let first = commits.announce();
        let second = commits.announce();
        drop(first);
        assert!(
            commits.any(),
            "the second commit is still inside the daemon; a bare flag would have been \
             cleared by the first one leaving"
        );
        drop(second);
        assert!(!commits.any());
    }

    #[tokio::test]
    async fn a_waiter_that_enabled_its_interest_first_cannot_miss_an_arrival() {
        let commits = PendingCommits::default();
        let arrival = commits.arrival();
        tokio::pin!(arrival);
        arrival.as_mut().enable();
        assert!(!commits.any(), "nothing has arrived yet");

        let _commit = commits.announce();
        tokio::time::timeout(std::time::Duration::from_secs(5), arrival)
            .await
            .expect("an announcement must wake a waiter that registered before reading");
        assert!(commits.any());
    }
}
