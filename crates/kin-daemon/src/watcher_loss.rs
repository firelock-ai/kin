// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Durable record of filesystem-watcher event loss, and the one thing that
//! clears it.
//!
//! A watcher backend can tell Kin that it lost events: inotify on kernel queue
//! overflow, FSEvents on `MUST_SCAN_SUBDIRS`. Both spell it as a pathless
//! `EventKind::Other` carrying notify's `Rescan` flag, so nothing about the
//! signal names a file and no per-path recovery can be derived from it. An
//! unknown region of the working copy changed and nothing will ever report it.
//!
//! Ambient admission cannot recover that. The watch loop admits what it is told
//! about, and it was told nothing, so every later tick succeeds, stamps a fresh
//! last-admission marker, and leaves the graph exactly as far behind as the loss
//! left it. That is the failure this record exists to end: a store that lost a
//! whole subtree while every health surface printed the all-clear.
//!
//! So the state is durable rather than held in daemon memory. The loss outlives
//! the daemon that observed it, and a restart that erased it would turn a
//! recoverable gap into a permanent silent one.
//!
//! Two monotonic counters rather than a flag. `generation` counts every loss
//! signal this store has been told about; `recovered_through` is the highest
//! generation a COMPLETED full admission covered. Recovery is required while the
//! first exceeds the second. That shape is what makes the clearing rule
//! expressible at all: a pass captures the generation standing against the store
//! before it runs and clears only that one, so a loss arriving while the pass
//! ran is still standing when it finishes. A boolean would be cleared by the
//! same pass that never observed the newer loss.
//!
//! Only an explicit full admission clears it. The ambient watch tick shares the
//! admission seam with `kin admit` and records the same success on the same
//! probes, so the clearing call deliberately does NOT live beside
//! [`crate::background_work::record_durable_admission`], which both of them
//! reach. It lives in [`crate::repository_admit`], which is only the explicit
//! path. This is the founder's contract: fail loud, and let a person or an agent
//! decide to admit.
//!
//! Reads are three-way for the same reason [`kin_core::last_admission`] reads
//! are, with the direction reversed: an unreadable record is treated as recovery
//! required. A read error must never be able to present as a healthy store.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Mutex, PoisonError};

/// Schema token carried in the record so a future format change is legible
/// rather than silently misparsed.
pub const WATCHER_LOSS_SCHEMA: &str = "kin.watcher-loss.v1";

/// Serializes every read-modify-write of one store's record within this process.
///
/// The loop's tick records a loss and an explicit admission records a recovery,
/// and both rewrite the whole file. Without this, a lost update could drop the
/// loss, which is the one direction that must not be possible: a dropped
/// recovery merely leaves a healthy store asking for an admission it does not
/// need, while a dropped loss leaves a blind store reporting itself well.
///
/// Process-wide rather than per store, because the writes are rare and short,
/// and a daemon serves one store. Cross-process concurrency is out of scope here
/// exactly as it is for the last-admission marker beside it.
static WRITE_GATE: Mutex<()> = Mutex::new(());

/// What a store has been told it lost, and how much of that a completed full
/// admission has covered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatcherLoss {
    pub schema: String,
    /// Every loss signal this store has ever been told about.
    ///
    /// Durable and monotonic across daemon lives, unlike the watcher's own
    /// in-memory count, which restarts with each backend registration. The loop
    /// advances this by the rise it observes rather than assigning the watcher's
    /// count, so a restart cannot walk the generation backwards past a recovery
    /// that already cleared it.
    pub generation: u64,
    /// The highest generation a completed full admission covered.
    pub recovered_through: u64,
    /// Wall-clock time of the newest loss, so a surface can say when.
    pub at: DateTime<Utc>,
    /// The backend's own hint for the newest loss, when it gave one.
    pub reason: Option<String>,
}

impl WatcherLoss {
    fn new(generation: u64, recovered_through: u64, reason: Option<String>) -> Self {
        Self {
            schema: WATCHER_LOSS_SCHEMA.to_string(),
            generation,
            recovered_through,
            at: Utc::now(),
            reason,
        }
    }

    /// Whether this store still owes a complete exact-tree admission.
    pub fn recovery_required(&self) -> bool {
        self.generation > self.recovered_through
    }
}

/// The outcome of consulting the record.
///
/// Three variants rather than an `Option`, and unreadable is the loud one. A
/// record that exists and will not parse means something wrote or truncated it,
/// and collapsing that into "no loss recorded" would hand a blind store a clean
/// bill of health through the one door this record was built to close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatcherLossRead {
    Recorded(WatcherLoss),
    Absent,
    Unreadable(String),
}

impl WatcherLossRead {
    /// Whether this store still owes a complete exact-tree admission.
    pub fn recovery_required(&self) -> bool {
        match self {
            Self::Recorded(recorded) => recorded.recovery_required(),
            Self::Absent => false,
            Self::Unreadable(_) => true,
        }
    }

    /// One line naming what was lost, when, and what clears it, or nothing when
    /// this store owes no recovery.
    ///
    /// Every state that owes a recovery produces a line, including the
    /// unreadable one. A surface that printed nothing there would be
    /// indistinguishable from one reporting a healthy store.
    pub fn describe(&self, working_dir: &Path) -> Option<String> {
        match self {
            Self::Absent => None,
            Self::Recorded(recorded) if !recorded.recovery_required() => None,
            Self::Recorded(recorded) => {
                let reason = match recorded.reason.as_deref() {
                    Some(reason) => format!(", backend reason: {reason}"),
                    None => ", the backend named no reason".to_string(),
                };
                Some(format!(
                    "the filesystem watcher lost events (loss generation {}, recovered through \
                     {}, most recently {}{reason}); an unknown set of paths under {} changed with \
                     no notification, so ambient admission cannot recover them and this graph may \
                     be behind its working copy. Run `kin admit` to admit the complete exact tree; \
                     ordinary watch ticks do not clear this",
                    recorded.generation,
                    recorded.recovered_through,
                    recorded.at.to_rfc3339(),
                    working_dir.display(),
                ))
            }
            Self::Unreadable(reason) => Some(format!(
                "the watcher-loss record for {} could not be read ({reason}), so whether this \
                 watcher lost events is unknown rather than no. Run `kin admit` to admit the \
                 complete exact tree and rewrite it",
                working_dir.display(),
            )),
        }
    }
}

/// What stood against the store when a full admission began.
///
/// Captured before the pass rather than read after it, because the pass observes
/// the tree at its start. A loss signal that arrives while it runs describes
/// writes the pass may never have seen, so it is not covered by definition, and
/// reading the generation afterwards would clear it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryCapture {
    /// No loss stood against the store when the pass began.
    Clean,
    /// This generation stood against the store when the pass began.
    Through(u64),
    /// The record could not be read when the pass began.
    Unreadable,
}

fn record_path(layout: &kin_core::KinLayout) -> std::path::PathBuf {
    layout.kindb_dir().join("watcher-loss")
}

/// Read the durable record for `layout`.
///
/// Never fails. A missing record is [`WatcherLossRead::Absent`] and anything
/// unparseable is [`WatcherLossRead::Unreadable`], and only the first of those
/// means the store is well.
pub fn read(layout: &kin_core::KinLayout) -> WatcherLossRead {
    let path = record_path(layout);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return WatcherLossRead::Absent
        }
        Err(error) => return WatcherLossRead::Unreadable(error.to_string()),
    };
    match serde_json::from_str::<WatcherLoss>(&raw) {
        Ok(recorded) if recorded.schema == WATCHER_LOSS_SCHEMA => {
            WatcherLossRead::Recorded(recorded)
        }
        Ok(recorded) => WatcherLossRead::Unreadable(format!(
            "schema {} is not {WATCHER_LOSS_SCHEMA}",
            recorded.schema
        )),
        Err(error) => WatcherLossRead::Unreadable(error.to_string()),
    }
}

/// Advance the durable loss generation by `signals`, whatever it held before.
///
/// Advancing rather than assigning is what keeps the generation monotonic across
/// daemon lives. The watcher's own count restarts at zero with every backend
/// registration, so a daemon that assigned it would walk the generation back
/// below a recovery that had already cleared it and turn a standing loss into a
/// healthy store.
///
/// An unreadable record is replaced rather than preserved. Its contents told
/// nobody anything, and the replacement starts at `recovered_through: 0`, so the
/// store keeps owing an admission. That is the safe direction: the only outcome
/// this must never produce is a record that reads as recovered.
///
/// A write failure is logged and swallowed, in the one place where that is the
/// wrong direction and there is no better one: failing the tick would stop the
/// loop admitting, and the in-memory disclosure recorded beside this call still
/// degrades every health surface for the life of this daemon.
pub fn record_loss(layout: &kin_core::KinLayout, signals: u64, reason: Option<&str>) {
    if signals == 0 {
        return;
    }
    let _gate = WRITE_GATE.lock().unwrap_or_else(PoisonError::into_inner);
    let recorded = match read(layout) {
        WatcherLossRead::Recorded(previous) => WatcherLoss::new(
            previous.generation.saturating_add(signals),
            previous.recovered_through,
            reason.map(str::to_string),
        ),
        WatcherLossRead::Absent | WatcherLossRead::Unreadable(_) => {
            WatcherLoss::new(signals, 0, reason.map(str::to_string))
        }
    };
    if let Err(error) = write(layout, &recorded) {
        tracing::error!(
            error = %error,
            generation = recorded.generation,
            "could not persist the watcher-loss record; this daemon still reports the loss on \
             every health surface, but a restart before the next successful write would lose it"
        );
    }
}

/// Read what stands against the store, for a full admission that is about to
/// begin.
pub fn capture(layout: &kin_core::KinLayout) -> RecoveryCapture {
    match read(layout) {
        WatcherLossRead::Recorded(recorded) if recorded.recovery_required() => {
            RecoveryCapture::Through(recorded.generation)
        }
        WatcherLossRead::Recorded(_) | WatcherLossRead::Absent => RecoveryCapture::Clean,
        WatcherLossRead::Unreadable(_) => RecoveryCapture::Unreadable,
    }
}

/// Clear the loss a COMPLETED full admission covered, and nothing else.
///
/// Called only from the explicit admission path, and only after that pass
/// succeeded. Every refusal below is a rule the contract needs:
///
/// - `Clean` writes nothing, so a loss that arrived during a pass that began on
///   a well store is still standing when it ends.
/// - `Through(g)` clears only when the record still reads exactly `g`. A newer
///   loss has moved it past `g`, and that loss describes writes this pass was
///   never told about, so it survives its own recovery.
/// - `Unreadable` rewrites a healthy record only if the record is STILL
///   unreadable. A complete exact-tree admission observes the whole working
///   copy, so it covers whatever the unrecoverable record described; but if the
///   record became readable while the pass ran, a real loss landed and is not
///   covered.
///
/// A write failure is logged and swallowed in the safe direction: an uncleared
/// record leaves the store asking for an admission it has already had, which
/// costs a pass and never a silence.
pub fn record_recovery(layout: &kin_core::KinLayout, captured: RecoveryCapture) {
    let _gate = WRITE_GATE.lock().unwrap_or_else(PoisonError::into_inner);
    let recorded = match (captured, read(layout)) {
        (RecoveryCapture::Clean, _) => return,
        (RecoveryCapture::Through(covered), WatcherLossRead::Recorded(standing))
            if standing.generation == covered =>
        {
            WatcherLoss {
                recovered_through: covered,
                ..standing
            }
        }
        (RecoveryCapture::Unreadable, WatcherLossRead::Unreadable(_)) => {
            WatcherLoss::new(0, 0, None)
        }
        (RecoveryCapture::Through(_) | RecoveryCapture::Unreadable, _) => {
            tracing::warn!(
                "a complete exact-tree admission succeeded, but the watcher loss standing against \
                 this store is not the one it covered; the store keeps owing a recovery"
            );
            return;
        }
    };
    if let Err(error) = write(layout, &recorded) {
        tracing::warn!(
            error = %error,
            "could not clear the watcher-loss record after a complete admission; the store will \
             keep reporting that it owes one until a later pass rewrites it"
        );
    }
}

/// The health-surface view of the durable record, or nothing when this store
/// owes no recovery.
///
/// One producer, so `/health`, `kin graph status` and every other surface that
/// reads the reconcile report state this identically. Two independently written
/// renderings of the same record drift into the exact failure this whole record
/// exists to end, one surface reporting a blind store and another reporting a
/// well one.
pub fn standing(
    layout: &kin_core::KinLayout,
    working_dir: &Path,
) -> Option<kin_cli::commands::resources::WatcherLossState> {
    let read_back = read(layout);
    let disclosure = read_back.describe(working_dir)?;
    // An unreadable record names no generation, and zero is what a healthy store
    // reports. Keep those counters at their floor, and publish the read failure
    // separately so a machine reader cannot mistake them for an all-clear.
    let (generation, recovered_through, at, reason, read_error) = match &read_back {
        WatcherLossRead::Recorded(recorded) => (
            recorded.generation,
            recorded.recovered_through,
            Some(recorded.at.to_rfc3339()),
            recorded.reason.clone(),
            None,
        ),
        WatcherLossRead::Unreadable(error) => (0, 0, None, None, Some(error.clone())),
        WatcherLossRead::Absent => (0, 0, None, None, None),
    };
    Some(kin_cli::commands::resources::WatcherLossState {
        generation,
        recovered_through,
        at,
        reason,
        read_error,
        disclosure,
    })
}

/// Write the durable record for `layout`, atomically.
///
/// Staged beside the target and renamed into place after an fsync, then the
/// directory metadata is synced, so a crash mid-write leaves either the previous
/// record or the new one and never a truncated file. This mirrors how the
/// last-admission marker beside it is published.
pub fn write(layout: &kin_core::KinLayout, recorded: &WatcherLoss) -> std::io::Result<()> {
    use std::io::Write;

    let path = record_path(layout);
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("watcher-loss path has no parent directory"))?;
    std::fs::create_dir_all(parent)?;
    let staged = path.with_extension(format!("tmp-{}", std::process::id()));
    let body = serde_json::to_vec(recorded).map_err(std::io::Error::other)?;
    {
        let mut file = std::fs::File::create(&staged)?;
        file.write_all(&body)?;
        file.sync_all()?;
    }
    if let Err(error) = std::fs::rename(&staged, &path) {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }
    crate::state::sync_directory_metadata(parent)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout_in(dir: &Path) -> kin_core::KinLayout {
        let kin_dir = dir.join(".kin");
        std::fs::create_dir_all(kin_dir.join("kindb")).unwrap();
        kin_core::KinLayout::new(kin_dir)
    }

    /// The negative control for every assertion below. A store nothing has told
    /// about a loss owes no recovery and says nothing, so a later `Some` is
    /// evidence rather than the function's only behaviour.
    #[test]
    fn a_store_with_no_recorded_loss_owes_no_recovery_and_discloses_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());

        assert_eq!(read(&layout), WatcherLossRead::Absent);
        assert!(!read(&layout).recovery_required());
        assert_eq!(read(&layout).describe(dir.path()), None);
        assert_eq!(capture(&layout), RecoveryCapture::Clean);
    }

    /// The whole point of the file: the loss outlives the daemon that saw it.
    /// A fresh read is what a restarted daemon performs.
    #[test]
    fn a_recorded_loss_requires_recovery_and_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());

        record_loss(&layout, 1, Some("rescan: kernel dropped"));

        let read_back = read(&layout);
        assert!(read_back.recovery_required());
        let disclosure = read_back
            .describe(dir.path())
            .expect("a standing loss discloses");
        assert!(
            disclosure.contains("kin admit"),
            "the disclosure names what clears it: {disclosure}"
        );
        assert!(
            disclosure.contains("rescan: kernel dropped"),
            "the disclosure names the backend's reason: {disclosure}"
        );
        assert!(
            disclosure.contains("generation 1"),
            "the disclosure carries the generation: {disclosure}"
        );
        let surface = standing(&layout, dir.path()).expect("a standing loss reaches health");
        assert_eq!(surface.generation, 1);
        assert_eq!(surface.recovered_through, 0);
        assert_eq!(surface.reason.as_deref(), Some("rescan: kernel dropped"));
        assert_eq!(surface.read_error, None);
        assert_eq!(surface.disclosure, disclosure);
    }

    /// The generation advances rather than being assigned, so a watcher whose
    /// own count restarted at one cannot walk a store back to recovered.
    #[test]
    fn the_durable_generation_advances_and_never_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());

        record_loss(&layout, 2, None);
        record_recovery(&layout, RecoveryCapture::Through(2));
        assert!(!read(&layout).recovery_required());

        // A restarted daemon's watcher reports its first signal as generation 1.
        record_loss(&layout, 1, None);

        let recorded = match read(&layout) {
            WatcherLossRead::Recorded(recorded) => recorded,
            other => panic!("expected a record, got {other:?}"),
        };
        assert_eq!(recorded.generation, 3, "the durable generation advanced");
        assert_eq!(recorded.recovered_through, 2);
        assert!(recorded.recovery_required());
    }

    /// Only a full admission clears, and only the generation it captured.
    #[test]
    fn a_full_admission_clears_the_generation_it_captured() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());

        record_loss(&layout, 1, None);
        let captured = capture(&layout);
        assert_eq!(captured, RecoveryCapture::Through(1));

        record_recovery(&layout, captured);

        assert!(!read(&layout).recovery_required());
        assert_eq!(read(&layout).describe(dir.path()), None);
    }

    /// A loss that lands WHILE a pass runs is not covered by it. The pass
    /// observed the tree when it started, so the writes the newer signal stands
    /// for may never have reached it.
    #[test]
    fn a_loss_that_arrives_during_a_pass_survives_that_pass() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());

        record_loss(&layout, 1, None);
        let captured = capture(&layout);

        // The pass is running. The loop's tick records a second signal.
        record_loss(&layout, 1, Some("rescan: user dropped"));

        record_recovery(&layout, captured);

        assert!(
            read(&layout).recovery_required(),
            "a newer loss must survive the recovery of an older one"
        );
        let recorded = match read(&layout) {
            WatcherLossRead::Recorded(recorded) => recorded,
            other => panic!("expected a record, got {other:?}"),
        };
        assert_eq!(recorded.generation, 2);
        assert_eq!(
            recorded.recovered_through, 0,
            "the pass covered neither generation, so it cleared neither"
        );
    }

    /// A pass that began on a well store clears nothing, so a loss that arrives
    /// mid-pass is still standing when it ends.
    #[test]
    fn a_pass_that_began_clean_clears_a_loss_that_arrived_under_it() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());

        let captured = capture(&layout);
        assert_eq!(captured, RecoveryCapture::Clean);

        record_loss(&layout, 1, None);
        record_recovery(&layout, captured);

        assert!(
            read(&layout).recovery_required(),
            "a pass that captured nothing must clear nothing"
        );
    }

    /// An unreadable record is a loud state, not a quiet one, and a completed
    /// admission is what rewrites it.
    #[test]
    fn an_unreadable_record_never_reads_as_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        std::fs::write(record_path(&layout), b"{ truncated").unwrap();

        let read_back = read(&layout);
        let error = match &read_back {
            WatcherLossRead::Unreadable(error) => error.clone(),
            other => panic!("expected an unreadable record, got {other:?}"),
        };
        assert!(read_back.recovery_required());
        assert!(read_back.describe(dir.path()).is_some());
        assert_eq!(capture(&layout), RecoveryCapture::Unreadable);
        let surface = standing(&layout, dir.path()).expect("an unreadable record reaches health");
        assert_eq!(surface.generation, 0);
        assert_eq!(surface.recovered_through, 0);
        assert_eq!(surface.reason, None);
        assert_eq!(surface.read_error.as_deref(), Some(error.as_str()));

        record_recovery(&layout, RecoveryCapture::Unreadable);
        assert!(
            !read(&layout).recovery_required(),
            "a complete exact-tree admission observes the whole working copy, so it covers \
             whatever the unreadable record described"
        );
    }

    /// A real loss landing on top of an unreadable record is not covered by the
    /// pass that captured only the unreadable one.
    #[test]
    fn a_loss_recorded_over_an_unreadable_record_survives_its_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        std::fs::write(record_path(&layout), b"{ truncated").unwrap();
        let captured = capture(&layout);

        record_loss(&layout, 1, None);
        record_recovery(&layout, captured);

        assert!(read(&layout).recovery_required());
    }

    /// A record whose schema token is not this one is unreadable rather than
    /// silently reinterpreted.
    #[test]
    fn a_foreign_schema_is_unreadable_rather_than_misparsed() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        std::fs::write(
            record_path(&layout),
            br#"{"schema":"kin.watcher-loss.v99","generation":4,"recovered_through":4,"at":"2026-09-09T00:00:00Z","reason":null}"#,
        )
        .unwrap();

        assert!(matches!(read(&layout), WatcherLossRead::Unreadable(_)));
        assert!(read(&layout).recovery_required());
    }
}
