// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Durable record of when a complete exact-tree admission last succeeded.
//!
//! The reconcile probes already know this fact and already publish it as
//! `last_admission_success_at`. They hold it in daemon memory, so a restart
//! erases it and every freshness surface then reports that no admission has ever
//! succeeded in this daemon's life. A store last admitted months ago therefore
//! reads exactly like one admitted a second ago, and a quiescent store produces
//! no failures to trip the one age clock that reaches a verdict. That is how a
//! graph can fall arbitrarily far behind its repository while every status
//! surface prints the all-clear.
//!
//! This marker is the durable half. It is deliberately NOT written by the
//! generation-publish path, which also runs on daemon startup: stamping it there
//! would refresh the timestamp on every restart and manufacture the false
//! freshness the marker exists to prevent. It is written only where an admission
//! actually completed.
//!
//! Reads are three-way on purpose. Absent and unreadable are different answers,
//! and neither may be collapsed into "current". A surface that turns an
//! unreadable marker into a zero age, or into silence, reintroduces the defect in
//! a new place.

use crate::layout::KinLayout;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Schema token carried in the marker so a future format change is legible
/// rather than silently misparsed.
pub const LAST_ADMISSION_SCHEMA: &str = "kin.last-admission.v1";

/// When a complete exact-tree admission last succeeded, and how much of the tree
/// it left behind.
///
/// `tracked_artifacts` is recorded beside the timestamp because age alone cannot
/// distinguish a store that is current from one whose admission succeeded while
/// covering a fraction of the repository. A reader comparing this count to what
/// the repository actually holds is how "31 of 125 files" becomes a number
/// instead of a silence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LastAdmission {
    pub schema: String,
    pub at: DateTime<Utc>,
    pub tracked_artifacts: u64,
}

impl LastAdmission {
    pub fn new(at: DateTime<Utc>, tracked_artifacts: u64) -> Self {
        Self {
            schema: LAST_ADMISSION_SCHEMA.to_string(),
            at,
            tracked_artifacts,
        }
    }

    /// Whole seconds between this admission and `now`.
    ///
    /// Saturates at zero rather than going negative. A marker stamped slightly
    /// ahead of the reader's clock is a clock-skew artifact, and reporting a
    /// negative age would make a surface look broken where the honest answer is
    /// "as good as current".
    pub fn age_seconds(&self, now: DateTime<Utc>) -> u64 {
        let seconds = now.signed_duration_since(self.at).num_seconds();
        if seconds <= 0 {
            0
        } else {
            seconds as u64
        }
    }
}

/// The outcome of consulting the marker.
///
/// Three variants rather than an `Option` because the surfaces have three honest
/// things to say. A store with no marker has either never been admitted or was
/// admitted by a build that predates this record, and in both cases the age is
/// unknown rather than zero. A marker that exists but will not parse is a
/// different and louder fact: something wrote or truncated it, and pretending it
/// is merely absent hides that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LastAdmissionRead {
    Recorded(LastAdmission),
    Absent,
    Unreadable(String),
}

impl LastAdmissionRead {
    /// The recorded admission, when there is one.
    pub fn recorded(&self) -> Option<&LastAdmission> {
        match self {
            Self::Recorded(recorded) => Some(recorded),
            Self::Absent | Self::Unreadable(_) => None,
        }
    }

    /// One line naming the freshness of graph truth, for a status surface.
    ///
    /// Every variant produces a line. That is the point: a surface that prints
    /// nothing when the answer is unknown is indistinguishable from one reporting
    /// a healthy store, which is the failure this whole marker exists to end.
    pub fn describe(&self, now: DateTime<Utc>) -> String {
        match self {
            Self::Recorded(recorded) => {
                let age = recorded.age_seconds(now);
                format!(
                    "last complete admission {} ({} ago), covering {} tracked artifact(s)",
                    recorded.at.to_rfc3339(),
                    humanize_age(age),
                    recorded.tracked_artifacts
                )
            }
            Self::Absent => "no complete admission is recorded for this store, so how far graph \
                             truth has fallen behind the repository is unknown; run `kin admit` \
                             to admit the complete exact tree and record one"
                .to_string(),
            Self::Unreadable(reason) => format!(
                "the last-admission record could not be read ({reason}), so freshness is unknown \
                 rather than current; run `kin admit` to rewrite it"
            ),
        }
    }
}

/// Render an age in the largest unit that stays honest.
///
/// Seconds for the first minute, then minutes, hours, days. A reader deciding
/// whether to trust a store cares about the order of magnitude, and "893821s"
/// buries it.
pub fn humanize_age(seconds: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    if seconds < MINUTE {
        format!("{seconds}s")
    } else if seconds < HOUR {
        format!("{}m", seconds / MINUTE)
    } else if seconds < DAY {
        format!("{}h", seconds / HOUR)
    } else {
        format!("{}d", seconds / DAY)
    }
}

/// Read the durable marker for `layout`.
///
/// Never fails: a missing marker is [`LastAdmissionRead::Absent`] and anything
/// unparseable is [`LastAdmissionRead::Unreadable`], both of which the surfaces
/// can state honestly. A read error must not be able to present as freshness.
pub fn read(layout: &KinLayout) -> LastAdmissionRead {
    let path = layout.kindb_last_admission_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return LastAdmissionRead::Absent
        }
        Err(error) => return LastAdmissionRead::Unreadable(error.to_string()),
    };
    match serde_json::from_str::<LastAdmission>(&raw) {
        Ok(recorded) if recorded.schema == LAST_ADMISSION_SCHEMA => {
            LastAdmissionRead::Recorded(recorded)
        }
        Ok(recorded) => LastAdmissionRead::Unreadable(format!(
            "schema {} is not {LAST_ADMISSION_SCHEMA}",
            recorded.schema
        )),
        Err(error) => LastAdmissionRead::Unreadable(error.to_string()),
    }
}

/// Write the durable marker for `layout`, atomically.
///
/// Staged beside the target and renamed into place after an fsync, then the
/// directory metadata is synced, so a crash mid-write leaves either the previous
/// record or the new one and never a truncated file that would read as
/// unreadable forever. This mirrors how the durable authority head marker beside
/// it is published.
pub fn write(layout: &KinLayout, recorded: &LastAdmission) -> std::io::Result<()> {
    use std::io::Write;

    let path = layout.kindb_last_admission_path();
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("last-admission path has no parent directory"))?;
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
    sync_directory_metadata(parent)?;
    Ok(())
}

/// Sync the containing directory so the rename that published the marker is
/// itself durable.
///
/// A rename is only as durable as the directory entry recording it. Syncing the
/// staged file alone leaves a window where a crash loses the publication even
/// though the bytes reached the platter, which is exactly the restart this
/// record exists to survive. This is the step that makes the atomic publish
/// above mirror the authority head marker beside it rather than merely resemble
/// it.
#[cfg(unix)]
fn sync_directory_metadata(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::open(path).and_then(|directory| directory.sync_all())
}

/// Non-unix platforms expose no portable directory handle to sync, so the
/// rename's own ordering guarantees are all there is.
#[cfg(not(unix))]
fn sync_directory_metadata(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn layout_in(dir: &std::path::Path) -> KinLayout {
        let kin_dir = dir.join(".kin");
        std::fs::create_dir_all(kin_dir.join("kindb")).unwrap();
        KinLayout::new(kin_dir)
    }

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    #[test]
    fn a_written_record_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        let recorded = LastAdmission::new(at(1_000_000), 125);
        write(&layout, &recorded).unwrap();
        assert_eq!(read(&layout), LastAdmissionRead::Recorded(recorded));
    }

    /// The durability property this whole marker exists for. A record survives
    /// being read by a process that never wrote it, which is what a daemon
    /// restart looks like from the reader's side.
    #[test]
    fn a_record_survives_a_reader_that_did_not_write_it() {
        let dir = tempfile::tempdir().unwrap();
        {
            let layout = layout_in(dir.path());
            write(&layout, &LastAdmission::new(at(500), 7)).unwrap();
        }
        let reopened = layout_in(dir.path());
        let read_back = read(&reopened);
        assert_eq!(
            read_back.recorded().map(|r| r.tracked_artifacts),
            Some(7),
            "a durable marker must outlive the process that wrote it"
        );
    }

    #[test]
    fn a_missing_marker_is_absent_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        assert_eq!(read(&layout), LastAdmissionRead::Absent);
        let line = read(&layout).describe(at(0));
        assert!(
            line.contains("unknown"),
            "an absent marker must report unknown freshness, not silence: {line}"
        );
    }

    /// Absent and unreadable must not collapse into each other, and neither may
    /// present as a current store.
    #[test]
    fn a_corrupt_marker_is_unreadable_rather_than_absent_or_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        std::fs::write(layout.kindb_last_admission_path(), b"{ truncated").unwrap();
        let read_back = read(&layout);
        assert!(
            matches!(read_back, LastAdmissionRead::Unreadable(_)),
            "a corrupt marker must be unreadable, got {read_back:?}"
        );
        let line = read_back.describe(at(0));
        assert!(
            line.contains("unknown"),
            "an unreadable marker must not read as current: {line}"
        );
    }

    #[test]
    fn a_wrong_schema_is_unreadable_rather_than_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        std::fs::write(
            layout.kindb_last_admission_path(),
            br#"{"schema":"kin.last-admission.v0","at":"2026-08-02T16:10:00Z","tracked_artifacts":31}"#,
        )
        .unwrap();
        assert!(matches!(read(&layout), LastAdmissionRead::Unreadable(_)));
    }

    #[test]
    fn a_rewrite_replaces_the_previous_record() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        write(&layout, &LastAdmission::new(at(100), 1)).unwrap();
        write(&layout, &LastAdmission::new(at(200), 2)).unwrap();
        let read_back = read(&layout);
        assert_eq!(read_back.recorded().map(|r| r.tracked_artifacts), Some(2));
        assert_eq!(read_back.recorded().map(|r| r.at), Some(at(200)));
    }

    #[test]
    fn age_saturates_at_zero_under_clock_skew() {
        let recorded = LastAdmission::new(at(1_000), 3);
        assert_eq!(recorded.age_seconds(at(1_060)), 60);
        assert_eq!(
            recorded.age_seconds(at(900)),
            0,
            "a marker ahead of the reader's clock must not report a negative age"
        );
    }

    #[test]
    fn age_is_rendered_in_the_largest_honest_unit() {
        assert_eq!(humanize_age(45), "45s");
        assert_eq!(humanize_age(600), "10m");
        assert_eq!(humanize_age(7_200), "2h");
        assert_eq!(humanize_age(864_000), "10d");
    }

    /// The months-behind case from the Aug-11 dogfood, stated as a test: the
    /// describe line has to carry an order of magnitude a reader can act on.
    #[test]
    fn a_months_old_record_reports_days_not_seconds() {
        let recorded = LastAdmission::new(at(0), 31);
        let line = LastAdmissionRead::Recorded(recorded).describe(at(86_400 * 70));
        assert!(line.contains("70d"), "expected a day-scale age: {line}");
        assert!(
            line.contains("31 tracked artifact"),
            "expected the coverage count beside the age: {line}"
        );
    }
}
