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
//!
//! One commit cannot announce itself this way, and it is the one that started
//! the daemon. Its handler is reached only after the store has opened, which on
//! a large store is seconds, and the first reconcile round of the daemon's life
//! has decided whether to publish long before that. So a client also announces
//! on disk, before it does any of its own preparation, and this reads that
//! announcement back. Both channels answer the same question and feed the same
//! predicate; the difference is only whether the commit had a daemon to tell.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Notify;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

/// Commits currently inside this daemon, and a wakeup for whoever is waiting on
/// one to arrive.
#[derive(Debug, Default)]
pub(crate) struct PendingCommits {
    inside: AtomicUsize,
    /// Whether a client has announced a commit that has not arrived yet, as of
    /// the last [`refresh_approaching`](PendingCommits::refresh_approaching).
    ///
    /// Cached rather than read per question on purpose. The predicate is asked
    /// twice per reconcile round and the answer changes only when a client
    /// writes or withdraws a marker, so the loop refreshes at the two points
    /// where it is about to decide something and nothing else pays for the read.
    approaching: AtomicBool,
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

    /// Whether any commit is inside the daemon right now, or is on its way and
    /// has said so.
    pub(crate) fn any(&self) -> bool {
        self.inside.load(Ordering::SeqCst) > 0 || self.approaching.load(Ordering::SeqCst)
    }

    /// Re-read the on-disk announcement for `kin_root` and wake any waiter that
    /// a fresh one has appeared for.
    ///
    /// Called where the loop is about to decide, not on a timer: the answer only
    /// matters at the two points a round consults it, and reading it there keeps
    /// this off every other path.
    pub(crate) fn refresh_approaching(&self, kin_root: &Path) {
        self.refresh_approaching_at(kin_root, unix_now());
    }

    /// [`refresh_approaching`](Self::refresh_approaching) against a supplied
    /// clock, so a test can age an announcement past its window without
    /// sleeping through it.
    pub(crate) fn refresh_approaching_at(&self, kin_root: &Path, now_unix: u64) {
        let approaching = kin_daemon_spawn::read_approaching_commit(kin_root)
            .is_some_and(|announced| announced.is_fresh(now_unix));
        // Only a transition wakes anyone. A refresh that finds the same answer
        // as the last one has nothing to report, and notifying on every round
        // would turn the arrival wakeup into a poll.
        if self.approaching.swap(approaching, Ordering::SeqCst) != approaching && approaching {
            self.arrived.notify_waiters();
        }
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

    fn announce_on_disk(kin_root: &Path, announced_unix: u64) {
        kin_daemon_spawn::write_approaching_commit(
            kin_root,
            &kin_daemon_spawn::ApproachingCommit {
                pid: 4284,
                announced_unix,
            },
        );
    }

    /// The channel a commit that started this daemon has to use.
    ///
    /// Its handler cannot announce until the store is open, so the only thing
    /// readable while the first reconcile round decides is what the client wrote
    /// before it began waiting. Freshness is what bounds it: nothing withdraws
    /// an announcement whose client was killed.
    #[test]
    fn an_announcement_counts_while_it_is_fresh_and_stops_when_it_is_not() {
        let repo = tempfile::tempdir().unwrap();
        let commits = PendingCommits::default();

        commits.refresh_approaching_at(repo.path(), 1_000);
        assert!(
            !commits.any(),
            "no announcement has been written, so there is nothing to stand down for"
        );

        announce_on_disk(repo.path(), 1_000);
        commits.refresh_approaching_at(repo.path(), 1_000);
        assert!(
            commits.any(),
            "a commit that said it was coming counts before it gets here"
        );

        commits.refresh_approaching_at(
            repo.path(),
            1_000 + kin_daemon_spawn::APPROACHING_COMMIT_STALE_AFTER.as_secs() + 1,
        );
        assert!(
            !commits.any(),
            "past its window the announcement is a client that never arrived, and holding \
             admission off for it forever is the failure it exists to avoid"
        );
    }

    /// The two channels are independent, and either one alone is enough.
    #[test]
    fn a_commit_inside_the_daemon_counts_whether_or_not_one_was_announced() {
        let repo = tempfile::tempdir().unwrap();
        let commits = PendingCommits::default();

        let inside = commits.announce();
        commits.refresh_approaching_at(repo.path(), 1_000);
        assert!(
            commits.any(),
            "a commit already inside the daemon needs no announcement on disk"
        );

        drop(inside);
        assert!(
            !commits.any(),
            "and with it gone and nothing announced, the daemon is quiet again"
        );
    }

    /// A round already waiting out its grace must not have to sit through the
    /// rest of it to learn that a commit announced itself in the meantime.
    #[tokio::test]
    async fn a_refresh_that_newly_finds_an_announcement_wakes_a_waiter() {
        let repo = tempfile::tempdir().unwrap();
        let commits = PendingCommits::default();
        let arrival = commits.arrival();
        tokio::pin!(arrival);
        arrival.as_mut().enable();
        assert!(!commits.any(), "nothing has been announced yet");

        announce_on_disk(repo.path(), 1_000);
        commits.refresh_approaching_at(repo.path(), 1_000);
        tokio::time::timeout(std::time::Duration::from_secs(5), arrival)
            .await
            .expect("a refresh that first reads an announcement must wake a waiter");
        assert!(commits.any());
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
