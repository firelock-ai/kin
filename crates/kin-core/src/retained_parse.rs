// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Durable record of the paths whose current bytes did not parse.
//!
//! The daemon reconciles under `ReconcilePolicy::FallbackToLkg`, so a file whose
//! syntax is broken keeps whatever entities a previous parse produced and derives
//! nothing new. A file created with a typo reaches the same arm and has nothing
//! to keep, which is why nothing here diagnoses one path. That is the right answer: an agent mid-edit produces
//! half-written source constantly, and refusing to record anything until the
//! syntax is fixed would be worse than serving spans one edit old. What was
//! missing is that nobody was told. The reconciler logs `broken AST, retaining
//! LKG state` and returns an outcome every consumer drops, so `kin status`,
//! `kin diff`, `kin commit`, `kin graph status` and `kin doctor` each reported a
//! whole store over a file the graph was answering about at positions its bytes
//! no longer hold.
//!
//! This is the durable half, published beside the last-admission marker and read
//! by all five. Durable rather than in-process because the pass that learns the
//! fact and the command that has to report it are usually different processes,
//! and because a pass with nothing to admit returns before it reconciles
//! anything: recomputing per surface would report a store clean the moment
//! nothing changed.
//!
//! Reads are three-way for the same reason the marker beside it is. Absent and
//! unreadable are different answers and neither may be collapsed into "nothing
//! is retained". A surface that turns an unreadable record into silence
//! reintroduces the defect in a new place.

use crate::layout::KinLayout;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Schema token carried in the record so a future format change is legible
/// rather than silently misparsed.
pub const RETAINED_PARSE_SCHEMA: &str = "kin.retained-parse.v1";

/// The tag every sentence about a retained path opens with, for a caller keying
/// on the class rather than reading the prose.
///
/// `retained_last_good_parse` rather than `parse_failure`, because nothing
/// failed to be recorded: the bytes are durable, the history is right, and where
/// the graph already held a parse of this path it kept it. What the tag names is
/// the population, not a diagnosis of any one member. `FileEvent::Changed`
/// covers "created or modified", so a brand-new file with a typo reaches the
/// same fallback arm with no earlier parse to keep, and no sentence over this
/// set may claim one for it.
pub const RETAINED_OBSERVATION: &str = "retained_last_good_parse";

/// Paths named on a surface line before it stops being readable.
const RETAINED_SAMPLE: usize = 5;

/// One path the graph is answering about from an earlier parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedPath {
    /// Repository path, as the tree spells it.
    pub path: String,
    /// How many parse errors the adapter reported in the current bytes.
    ///
    /// The reconciler's own count, carried rather than recomputed. It is a
    /// property of this edit and this adapter: the same missing bracket produced
    /// three errors in one measured file and four in another, so no surface may
    /// assert a number of its own.
    pub errors: usize,
}

/// Every path this store is currently answering about from an earlier parse.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedParse {
    pub schema: String,
    /// When the pass that wrote this record ran.
    pub at: DateTime<Utc>,
    /// Sorted by path, so the same store always renders the same order.
    pub paths: Vec<RetainedPath>,
}

impl RetainedParse {
    pub fn new(at: DateTime<Utc>, mut paths: Vec<RetainedPath>) -> Self {
        paths.sort_by(|left, right| left.path.cmp(&right.path));
        paths.dedup_by(|left, right| left.path == right.path);
        Self {
            schema: RETAINED_PARSE_SCHEMA.to_string(),
            at,
            paths,
        }
    }

    /// Whether this store is answering about anything from an earlier parse.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

/// The outcome of consulting the record.
///
/// Three variants rather than an `Option`, because the surfaces have three
/// honest things to say. A store with no record has had no pass observe
/// anything since a build that writes one, which is not the same as a pass that
/// looked and found nothing. A record that exists and will not parse is a louder
/// fact than one that is missing: something wrote or truncated it, and rendering
/// that as a clean store hides it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetainedParseRead {
    Recorded(RetainedParse),
    Absent,
    Unreadable(String),
}

impl RetainedParseRead {
    /// The recorded paths, when there are any.
    ///
    /// `Absent` and `Unreadable` both answer with nothing, and that is
    /// deliberate: a counter must not invent a retained path out of a record it
    /// could not read. The `Unreadable` case is not thereby silent, because
    /// [`Self::describe`] renders it as its own line.
    pub fn paths(&self) -> &[RetainedPath] {
        match self {
            Self::Recorded(recorded) => &recorded.paths,
            Self::Absent | Self::Unreadable(_) => &[],
        }
    }

    /// Error count for one repository path, when the record names it.
    pub fn errors_for(&self, path: &str) -> Option<usize> {
        self.paths()
            .iter()
            .find(|retained| retained.path == path)
            .map(|retained| retained.errors)
    }

    /// The one line a surface prints, or nothing when there is nothing to say.
    ///
    /// Silent on a clean store, and that is the whole difference between this
    /// and the freshness line beside it. Freshness has no clean state: a store
    /// is always some age. This has one, because a repository whose every file
    /// parses is the ordinary case, and a line that appeared on every run would
    /// train a reader to skip the line that matters.
    ///
    /// Never silent when there IS something to say, including the case where the
    /// record itself could not be read.
    pub fn describe(&self, now: DateTime<Utc>) -> Option<String> {
        match self {
            Self::Recorded(recorded) if recorded.paths.is_empty() => None,
            Self::Recorded(recorded) => {
                let named = recorded
                    .paths
                    .iter()
                    .take(RETAINED_SAMPLE)
                    .map(|retained| format!("{} ({} parse errors)", retained.path, retained.errors))
                    .collect::<Vec<_>>()
                    .join(", ");
                let more = recorded.paths.len().saturating_sub(RETAINED_SAMPLE);
                let and_more = if more > 0 {
                    format!(" and {more} more")
                } else {
                    String::new()
                };
                let age = crate::last_admission::humanize_age(age_seconds(recorded.at, now));
                // Established half first, conditional half second, and the split
                // is the point. The seam knows which of the two populations a
                // path is in; this record does not, and widening it to carry
                // that is a change to the on-disk shape rather than to a
                // sentence. So the line asserts only what is true of both: the
                // bytes on disk do not parse. What the graph still holds for
                // them is stated as a conditional, because a file created with
                // a typo has no earlier parse to hold.
                Some(format!(
                    "Did not parse as written: {named}{and_more}. The bytes on disk do not parse, \
                     so any entities the graph still holds for these paths came from an earlier \
                     parse of bytes that are gone, and a path the graph never parsed is absent \
                     from it entirely. Fix the syntax and the next admission re-derives them. \
                     Observed {age} ago."
                ))
            }
            Self::Absent => None,
            Self::Unreadable(reason) => Some(format!(
                "Did not parse as written: unknown. The record of which paths failed to parse \
                 could not be read ({reason}), so this report cannot say there are none; run \
                 `kin admit` to rewrite it."
            )),
        }
    }
}

/// Whole seconds between `at` and `now`, saturating at zero.
///
/// A record stamped slightly ahead of the reader's clock is a skew artifact, and
/// a negative age would make a surface look broken where the honest answer is
/// "as good as now".
fn age_seconds(at: DateTime<Utc>, now: DateTime<Utc>) -> u64 {
    let seconds = now.signed_duration_since(at).num_seconds();
    if seconds <= 0 {
        0
    } else {
        seconds as u64
    }
}

/// What one reconcile pass saw about one path.
///
/// `errors` is `Some` when the path's current bytes did not parse and the graph
/// kept an earlier reading, and `None` when the pass read the path and got a
/// clean answer or the path left the tree. Both are observations; the absence of
/// a path from a pass's observations is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedParse {
    pub path: String,
    pub errors: Option<usize>,
}

impl ObservedParse {
    pub fn retained(path: impl Into<String>, errors: usize) -> Self {
        Self {
            path: path.into(),
            errors: Some(errors),
        }
    }

    pub fn settled(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            errors: None,
        }
    }
}

/// Fold one pass's observations into the record.
///
/// The rule is "of the paths this pass observed, these were retained; drop every
/// other observed path; leave unobserved paths alone", and it is one rule rather
/// than two because the two writers see different populations. The complete sync
/// observes every path its exact-tree transition moved, and the ambient tick
/// observes the batch its watcher delivered. Replacing the whole record from
/// either would let a partial tick clear a path it never looked at; merging
/// without dropping would leave a fixed file named forever.
///
/// Pure, and separate from [`record`], so every branch is testable without a
/// store.
pub fn fold(
    previous: &[RetainedPath],
    observed: &[ObservedParse],
    at: DateTime<Utc>,
) -> RetainedParse {
    let mut paths: Vec<RetainedPath> = previous
        .iter()
        .filter(|retained| {
            !observed
                .iter()
                .any(|observation| observation.path == retained.path)
        })
        .cloned()
        .collect();
    for observation in observed {
        if let Some(errors) = observation.errors {
            paths.push(RetainedPath {
                path: observation.path.clone(),
                errors,
            });
        }
    }
    RetainedParse::new(at, paths)
}

/// Read the durable record for `layout`.
///
/// Never fails: a missing record is [`RetainedParseRead::Absent`] and anything
/// unparseable is [`RetainedParseRead::Unreadable`], both of which the surfaces
/// state honestly. A read error must not be able to present as a clean store.
pub fn read(layout: &KinLayout) -> RetainedParseRead {
    let path = layout.kindb_retained_parse_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return RetainedParseRead::Absent
        }
        Err(error) => return RetainedParseRead::Unreadable(error.to_string()),
    };
    match serde_json::from_str::<RetainedParse>(&raw) {
        Ok(recorded) if recorded.schema == RETAINED_PARSE_SCHEMA => {
            RetainedParseRead::Recorded(recorded)
        }
        Ok(recorded) => RetainedParseRead::Unreadable(format!(
            "schema {} is not {RETAINED_PARSE_SCHEMA}",
            recorded.schema
        )),
        Err(error) => RetainedParseRead::Unreadable(error.to_string()),
    }
}

/// The record for a store named by its `.kin` root rather than by a layout.
///
/// The graph surfaces are handed a root and not a layout, and rebuilding the
/// layout at each of them would put the same three lines in three places. A
/// caller with no root at all gets [`RetainedParseRead::Absent`], which is the
/// honest answer: it has no store to consult.
pub fn read_at_root(kin_root: Option<&std::path::Path>) -> RetainedParseRead {
    match kin_root {
        Some(root) => read(&KinLayout::new(root.to_path_buf())),
        None => RetainedParseRead::Absent,
    }
}

/// Fold `observed` into the record for `layout` and publish the result.
///
/// The one writer every reconcile seam goes through, so the five surfaces cannot
/// come to disagree about which paths are retained.
///
/// A write failure is logged and swallowed. A pass that reconciled did
/// reconcile, and turning a record-write failure into a reconcile failure would
/// refuse an admission over a disclosure. The failure direction is the safe one
/// in only one of the two cases and that is worth stating plainly: an unwritten
/// record leaves a path named after it was fixed, which over-reports, and leaves
/// a newly broken path unnamed, which under-reports. Neither changes a query
/// answer, and the next pass that observes the path rewrites it.
pub fn record(layout: &KinLayout, observed: &[ObservedParse]) {
    if observed.is_empty() {
        return;
    }
    let previous = read(layout);
    let folded = fold(previous.paths(), observed, Utc::now());
    if let Err(error) = write(layout, &folded) {
        tracing::warn!(
            error = %error,
            "could not persist the retained-parse record; the status, diff, commit, graph and \
             doctor surfaces will report the previous set until the next pass rewrites it"
        );
    }
}

/// Write the durable record for `layout`, atomically.
///
/// Staged beside the target and renamed into place after an fsync, then the
/// directory metadata is synced, so a crash mid-write leaves either the previous
/// record or the new one and never a truncated file that would read as
/// unreadable forever. This mirrors how the last-admission marker beside it is
/// published.
pub fn write(layout: &KinLayout, recorded: &RetainedParse) -> std::io::Result<()> {
    use std::io::Write;

    let path = layout.kindb_retained_parse_path();
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("retained-parse path has no parent directory"))?;
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

/// Sync the containing directory so the rename that published the record is
/// itself durable, exactly as the last-admission marker beside it does.
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

    fn at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 5, 2, 30, 22).unwrap()
    }

    #[test]
    fn a_store_nothing_has_observed_is_absent_rather_than_clean() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        assert_eq!(read(&layout), RetainedParseRead::Absent);
        assert!(read(&layout).describe(at()).is_none());
    }

    #[test]
    fn a_recorded_path_round_trips_and_names_itself_with_its_error_count() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        record(&layout, &[ObservedParse::retained("search.py", 4)]);

        let read_back = read(&layout);
        assert_eq!(read_back.errors_for("search.py"), Some(4));
        let line = read_back.describe(at()).expect("a retained path speaks");
        assert!(line.contains("search.py (4 parse errors)"), "{line}");
        assert!(
            line.contains("The bytes on disk do not parse"),
            "the established half leads: {line}"
        );
        // The half a brand-new file with a typo makes load-bearing. `FileEvent`
        // has only `Changed` and `Removed`, and `Changed` covers "created", so
        // this set holds paths with no earlier parse at all. A sentence that
        // asserted one would be a false diagnosis on five surfaces.
        assert!(
            line.contains("any entities the graph still holds"),
            "what the graph holds is a conditional, not an assertion: {line}"
        );
        assert!(
            !line.contains("the graph answers about them at the positions"),
            "no sentence over this set may claim an earlier parse for every member: {line}"
        );
    }

    /// The record that will not parse is the loud case, not the quiet one. A
    /// reader given silence here would take a truncated record for a clean
    /// store, which is the defect this whole record exists to end, reached by
    /// the other door.
    #[test]
    fn an_unreadable_record_says_so_rather_than_reading_as_a_clean_store() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        std::fs::write(layout.kindb_retained_parse_path(), b"{ truncated").unwrap();

        let read_back = read(&layout);
        assert!(matches!(read_back, RetainedParseRead::Unreadable(_)));
        assert!(
            read_back.paths().is_empty(),
            "a record nobody could read names no path"
        );
        let line = read_back
            .describe(at())
            .expect("an unreadable record still speaks");
        assert!(line.contains("could not be read"), "{line}");
    }

    #[test]
    fn a_record_carrying_another_schema_is_unreadable_rather_than_empty() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        std::fs::write(
            layout.kindb_retained_parse_path(),
            br#"{"schema":"kin.retained-parse.v99","at":"2026-09-05T02:30:22Z","paths":[]}"#,
        )
        .unwrap();
        assert!(matches!(read(&layout), RetainedParseRead::Unreadable(_)));
    }

    /// The fold's whole rule, in one test. A path this pass observed and found
    /// clean is dropped; a path it observed and found broken is carried; a path
    /// it never looked at is left exactly as it was.
    #[test]
    fn a_pass_settles_what_it_observed_and_leaves_what_it_did_not() {
        let previous = vec![
            RetainedPath {
                path: "fixed.py".to_string(),
                errors: 2,
            },
            RetainedPath {
                path: "still_broken.py".to_string(),
                errors: 4,
            },
            RetainedPath {
                path: "untouched.py".to_string(),
                errors: 1,
            },
        ];
        let observed = [
            ObservedParse::settled("fixed.py"),
            ObservedParse::retained("still_broken.py", 4),
            ObservedParse::retained("newly_broken.ts", 7),
        ];

        let folded = fold(&previous, &observed, at());
        let named: Vec<&str> = folded
            .paths
            .iter()
            .map(|retained| retained.path.as_str())
            .collect();
        assert_eq!(
            named,
            vec!["newly_broken.ts", "still_broken.py", "untouched.py"],
            "a path the pass settled leaves, one it never observed stays: {folded:?}"
        );
    }

    /// A pass that observed nothing rewrites nothing. The complete sync returns
    /// early when its exact-tree transition is empty, and a rewrite there would
    /// clear every retained path on the first command run after an edit was
    /// already admitted.
    #[test]
    fn a_pass_that_observed_nothing_leaves_the_record_standing() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        record(&layout, &[ObservedParse::retained("search.py", 4)]);
        record(&layout, &[]);
        assert_eq!(read(&layout).errors_for("search.py"), Some(4));
    }

    #[test]
    fn a_record_names_a_bounded_sample_and_counts_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        let observed: Vec<ObservedParse> = (0..8)
            .map(|index| ObservedParse::retained(format!("mod{index}.py"), index + 1))
            .collect();
        record(&layout, &observed);

        let line = read(&layout).describe(at()).expect("eight paths speak");
        assert!(line.contains("mod0.py (1 parse errors)"), "{line}");
        assert!(
            !line.contains("mod7.py"),
            "the sample is bounded so a large working copy cannot flood the surface: {line}"
        );
        assert!(line.contains("and 3 more"), "{line}");
    }
}
