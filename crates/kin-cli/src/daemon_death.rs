// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What a store's own records say about a daemon of its own that died, for the
//! surfaces that have to say it out loud.
//!
//! The measured failure (FIR-2650) is one sentence. On `psf/requests` at full
//! history inside a 12 GiB container, `kin init` finished, exit 0, and the
//! daemon was then OOM-killed inside its post-init enrichment commit. Kin said:
//!
//! > the kin daemon at http://127.0.0.1:39767 stopped answering while the lsp
//! > sweep status request was in flight; it exits after its idle window, so
//! > re-run the command and kin will start a fresh one
//!
//! The cgroup had recorded the kill and `docker inspect` read `OOMKilled=true`,
//! so the truth was on two independent surfaces and Kin used neither. It
//! matters past the wording: an idle exit is a normal event whose advice is to
//! re-run, while an OOM at that repository size recurs on every attempt, so the
//! reader is sent around a loop that cannot terminate.
//!
//! Which record answers, and why it is not the obvious one
//! ------------------------------------------------------
//! The tempting input is [`kin_daemon_spawn::read_daemon_kill_record`], the
//! store's accumulated tally. It is the wrong one for a sentence about a
//! request that just failed: it accumulates, it outlives every daemon that
//! follows it, and a message built from it blames a kill from last week for an
//! idle exit today.
//!
//! The serving record cannot do that. A daemon publishes it at start and
//! retires it as it exits on its own terms, so it is overwritten by each
//! successor and removed by every clean ending. Finding one beside a dead pid
//! therefore says something about THIS store's most recent daemon and nothing
//! about any earlier one: it began serving and never reached the line that
//! would have retired it. That is a kill, and it is this one.
//!
//! Read-only, on purpose. Settling a death is the next daemon start's job, so
//! it is counted once however many surfaces describe it.

use std::path::Path;

use kin_daemon_spawn::DaemonKillRecord;

/// The death this store's most recent daemon suffered, if it suffered one.
///
/// `None` is the ordinary case and is the reading that leaves every message
/// exactly what it was: a daemon that retired after its idle window took its
/// serving record with it, and a store that has never lost one has nothing
/// here.
pub fn most_recent_death(kin_root: &Path) -> Option<DaemonKillRecord> {
    kin_daemon_spawn::peek_unwatched_daemon_death(kin_root)
}

/// The death to quote beside a store's own state, rather than beside a request.
///
/// Two readings, in the order that keeps each claim as strong as its evidence
/// and no stronger. The unsettled death is exact and is about the daemon that
/// was serving a moment ago, so it answers first. Failing that, the store's
/// accumulated record answers, because by the time a reader runs `kin status`
/// a successor daemon has usually started and settled the death into that
/// tally, and dropping the signal at that moment would mean a store forgot a
/// kill the instant it recorded one.
///
/// The wording every caller builds from this is deliberately joint rather than
/// causal: the store's enrichment is unattested AND a daemon serving it was
/// killed. Which of its daemons, and whether that kill is what stopped the
/// enrichment, is not something either record establishes, so no surface here
/// says it.
pub fn recorded_for_store(kin_root: &Path) -> Option<DaemonKillRecord> {
    most_recent_death(kin_root).or_else(|| kin_daemon_spawn::read_daemon_kill_record(kin_root))
}

/// The store root for the working directory, when it is inside a Kin
/// repository.
///
/// Every caller here is best-effort by construction: a surface that could not
/// find a store says what it always said, which is the same outcome as a store
/// that never lost a daemon.
pub fn kin_root_from_cwd() -> Option<std::path::PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    Some(kin_core::KinLayout::discover(&cwd)?.root().to_path_buf())
}

/// The clause that replaces a bare "completion not attested".
///
/// A store whose enrichment nobody attested and whose daemon was killed reads,
/// unchanged, exactly like a store whose enrichment simply has not been
/// certified yet, which is the ordinary and unalarming case. The counts are the
/// same, the presence is the same, and the parenthetical is the same. Naming
/// the kill is the only thing that separates them.
///
/// It stays a clause rather than becoming the whole line because the counts
/// beside it are still true: the entities were extracted and the relations were
/// derived. What is in doubt is whether anything more was coming.
pub fn enrichment_clause(record: Option<&DaemonKillRecord>) -> &'static str {
    match record {
        Some(_) => "completion not attested, and a daemon serving this store was killed",
        None => "completion not attested",
    }
}

/// The sentence a daemon request that went unanswered ends with, when the store
/// can say the daemon died.
///
/// The idle-window sentence it replaces is not merely wrong here, it is
/// actively harmful: its advice is to re-run, and re-running is what cannot
/// terminate. This one leads with the fact that the daemon did not retire, and
/// hands over the record's own remediation, every action in which is one the
/// caller can perform.
pub fn dropped_request_sentence(base_url: &str, leaf: &str, record: &DaemonKillRecord) -> String {
    format!(
        "the kin daemon at {base_url} stopped answering while the {leaf} request was in flight, \
         and it did not exit its idle window: {}",
        record.summary()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_daemon_spawn::DaemonKillCause;

    const TWELVE_GIB: u64 = 12 * 1024 * 1024 * 1024;

    fn memory_kill() -> DaemonKillRecord {
        DaemonKillRecord {
            kills: 1,
            memory_kills: 1,
            first_unix: 1_787_000_000,
            last_unix: 1_787_000_000,
            last_pid: Some(4103),
            last_cause: DaemonKillCause::MemoryLimit {
                kernel_oom_kills: 1,
            },
            limit_bytes: Some(TWELVE_GIB),
            last_rss_bytes: Some(TWELVE_GIB - 5 * 1024 * 1024),
        }
    }

    fn unattributed_kill() -> DaemonKillRecord {
        DaemonKillRecord {
            kills: 1,
            memory_kills: 0,
            first_unix: 1_787_000_000,
            last_unix: 1_787_000_000,
            last_pid: Some(4103),
            last_cause: DaemonKillCause::Unattributed { signal: 0 },
            limit_bytes: None,
            last_rss_bytes: None,
        }
    }

    /// The measured sentence, and the one claim it may never make again.
    ///
    /// "It exits after its idle window, so re-run the command" is the advice
    /// that cannot terminate when the cause is an OOM at this repository's
    /// size, so its absence is asserted rather than left to a reader's eye.
    #[test]
    fn a_dropped_request_over_a_killed_daemon_never_offers_the_idle_window() {
        let sentence =
            dropped_request_sentence("http://127.0.0.1:39767", "lsp sweep status", &memory_kill());
        assert!(
            !sentence.contains("idle window, so re-run"),
            "the advice that cannot terminate was still offered: {sentence}"
        );
        assert!(
            sentence.contains("did not exit its idle window"),
            "{sentence}"
        );
        assert!(sentence.contains("killed"), "{sentence}");
        assert!(sentence.contains("http://127.0.0.1:39767"), "{sentence}");
        assert!(sentence.contains("lsp sweep status"), "{sentence}");
    }

    /// A kill the kernel attributed to memory is named with its ceiling.
    ///
    /// "The daemon died" invites a re-run. "It was killed by the memory limit,
    /// cap 12.0 GiB" does not, and the figure is what makes the difference
    /// actionable, so a mention with no number would not be a fix.
    #[test]
    fn a_memory_kill_is_named_with_its_figure_and_its_remedy() {
        let sentence = dropped_request_sentence("http://127.0.0.1:1", "locate", &memory_kill());
        assert!(sentence.contains("memory limit"), "{sentence}");
        assert!(sentence.contains("12.0 GiB"), "{sentence}");
        assert!(sentence.contains("To recover:"), "{sentence}");
    }

    /// A kill this host cannot attribute is still a kill, and says only that.
    ///
    /// On a host with no cgroup accounting, "not attributed" is the honest
    /// answer and "not memory" is not. What must not survive either way is the
    /// idle window.
    #[test]
    fn an_unattributed_kill_reports_the_death_without_inventing_a_cause() {
        let sentence =
            dropped_request_sentence("http://127.0.0.1:1", "locate", &unattributed_kill());
        assert!(sentence.contains("killed"), "{sentence}");
        assert!(!sentence.contains("idle window, so re-run"), "{sentence}");
        assert!(
            !sentence.contains("memory limit"),
            "a host that publishes no accounting attributed nothing: {sentence}"
        );
    }

    /// The enrichment clause separates the two stores that used to read alike.
    #[test]
    fn the_enrichment_clause_names_a_kill_only_when_there_was_one() {
        assert_eq!(enrichment_clause(None), "completion not attested");
        let killed = enrichment_clause(Some(&memory_kill()));
        assert!(killed.starts_with("completion not attested"), "{killed}");
        assert!(killed.contains("killed"), "{killed}");
    }

    /// A store nothing has happened to says what it always said.
    ///
    /// The control that keeps every message on every healthy host byte for byte
    /// what it was. A reader who has never lost a daemon must not start seeing
    /// daemon deaths discussed.
    #[test]
    fn a_store_with_no_records_reports_no_death() {
        let dir = tempfile::tempdir().unwrap();
        assert!(most_recent_death(dir.path()).is_none());
        assert!(recorded_for_store(dir.path()).is_none());
    }

    /// The unsettled death answers ahead of the accumulated tally.
    ///
    /// Both can be present at once: a store that lost a daemon last week and
    /// lost another one a minute ago. The recent one is what a reader is asking
    /// about, and it is the only one whose recency this code can establish.
    #[test]
    fn an_unsettled_death_answers_ahead_of_the_stores_older_tally() {
        let dir = tempfile::tempdir().unwrap();
        let stale = DaemonKillRecord {
            kills: 9,
            ..unattributed_kill()
        };
        kin_daemon_spawn::write_daemon_kill_record(dir.path(), &stale);
        assert_eq!(
            recorded_for_store(dir.path()).map(|r| r.kills),
            Some(9),
            "with no unsettled death, the store's own tally is what there is"
        );

        std::fs::write(
            kin_daemon_spawn::serving_path(dir.path()),
            serde_json::to_vec(&kin_daemon_spawn::ServingDaemon {
                // A pid that cannot be alive, so this is deterministic rather
                // than a race against whatever holds the number today.
                pid: u32::MAX,
                oom_kills_at_start: Some(0),
                at_unix: 1_000,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            recorded_for_store(dir.path()).map(|r| r.kills),
            Some(1),
            "the death a moment ago is the one a reader is asking about"
        );
    }
}
