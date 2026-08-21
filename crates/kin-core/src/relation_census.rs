// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Durable record of the relation-kind census, and the rule that compares one
//! census to the one before it.
//!
//! `kin graph status` prints the full relation-kind histogram immediately above
//! its health line and compares it to nothing, so a store that lost an entire
//! relation kind reads as healthy. On the rc0545c stranger run a psf/requests
//! store went from 1985 entity-to-entity relations to 1807 in 36 minutes, and
//! `UsesType` went from 94 to zero, under `✓ No issues detected.` Every number
//! needed to notice was on the screen, and nothing on the screen noticed.
//!
//! A census on its own cannot say whether a count is low or falling. Only a
//! previous census can, so one is recorded where the graph's relations were last
//! settled: at the end of a completed enrichment sweep and at the end of a
//! commit. Both are points where the relation set just changed and the process
//! doing the changing knows it finished.
//!
//! Reads are three-way for the same reason [`crate::last_admission`] reads are.
//! Absent and unreadable are different answers and neither may present as
//! "nothing changed": a surface that turns a missing record into a clean bill
//! reintroduces the defect this record exists to close.

use crate::layout::KinLayout;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Schema token carried in the record so a future format change is legible
/// rather than silently misparsed.
pub const RELATION_CENSUS_SCHEMA: &str = "kin.relation-census.v1";

/// How far a kind must fall before the drop is reported as a warning rather
/// than as ordinary movement.
///
/// Stated as a constant and named in the rendered line, because a threshold a
/// reader cannot see is a threshold they cannot calibrate against. A quarter of
/// a kind is far more than re-parsing noise and far less than the whole-kind
/// loss that is reported unconditionally.
pub const SHARP_DROP_FRACTION: f64 = 0.25;

/// What was recorded, and where the recording happened.
///
/// The source is kept because the two writers answer different questions. A
/// census recorded by a sweep describes a graph whose enrichment just finished;
/// one recorded by a commit describes a graph that just took a change. A drop
/// between a sweep census and a commit census is a different event from a drop
/// between two sweep censuses, and a reader who cannot tell them apart cannot
/// act on either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CensusSource {
    /// The end of a completed language-server enrichment sweep.
    Sweep,
    /// The end of a commit that installed its change in the live graph.
    Commit,
}

impl CensusSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Sweep => "enrichment sweep",
            Self::Commit => "commit",
        }
    }
}

/// The relation-kind census of one store at one moment.
///
/// `kinds` is entity-rooted, matching the `Entity-to-entity relation kinds` line
/// `kin graph status` prints, so the recorded census and the compared census are
/// the same measurement rather than two that merely resemble each other.
///
/// `causes` carries the correctness-relevant environment overrides active in the
/// process that recorded it. Those are the conditions the graph was built under,
/// and they are what turns "UsesType went 94 to 0" into an answer instead of a
/// question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationCensus {
    pub schema: String,
    pub at: DateTime<Utc>,
    pub source: CensusSource,
    pub kinds: BTreeMap<String, u64>,
    pub total: u64,
    #[serde(default)]
    pub causes: Vec<String>,
}

impl RelationCensus {
    pub fn new(
        at: DateTime<Utc>,
        source: CensusSource,
        kinds: BTreeMap<String, u64>,
        causes: Vec<String>,
    ) -> Self {
        let total = kinds.values().copied().sum();
        Self {
            schema: RELATION_CENSUS_SCHEMA.to_string(),
            at,
            source,
            kinds,
            total,
            causes,
        }
    }
}

/// The outcome of consulting the record.
///
/// Three variants rather than an `Option`, for the reason
/// [`crate::last_admission::LastAdmissionRead`] has three: a store with no
/// record has nothing to compare against, and a record that will not parse is a
/// louder fact than a missing one. Neither may render as "unchanged".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RelationCensusRead {
    Recorded(RelationCensus),
    #[default]
    Absent,
    Unreadable(String),
}

impl RelationCensusRead {
    pub fn recorded(&self) -> Option<&RelationCensus> {
        match self {
            Self::Recorded(recorded) => Some(recorded),
            Self::Absent | Self::Unreadable(_) => None,
        }
    }
}

/// What one relation kind did between two censuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CensusMovement {
    /// The kind held edges and now holds none. Reported unconditionally: a
    /// whole kind disappearing is not a matter of degree.
    Vanished,
    /// The kind fell by at least [`SHARP_DROP_FRACTION`] without reaching zero.
    Fell,
    /// The kind fell by less than [`SHARP_DROP_FRACTION`]. Carried so a reader
    /// asking for the whole comparison gets it, and never on its own a warning.
    Slipped,
    /// The kind grew.
    Grew,
    /// The kind is present now and was absent from the previous census.
    Appeared,
    /// The count is identical.
    Unchanged,
}

impl CensusMovement {
    /// Whether this movement withholds the all-clear.
    ///
    /// A vanished kind and a sharp fall both do. Growth, a new kind, an
    /// identical count and ordinary slippage do not: reporting those as issues
    /// would make every re-parse of a live repository print a warning, and a
    /// surface that always warns is one nobody reads.
    pub fn is_loss(self) -> bool {
        matches!(self, Self::Vanished | Self::Fell)
    }
}

/// One kind's before and after, with the verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensusChange {
    pub kind: String,
    pub previous: u64,
    pub current: u64,
    pub movement: CensusMovement,
}

impl CensusChange {
    /// The fraction of the previous count that is gone, in `0.0..=1.0`.
    ///
    /// Zero when the kind did not fall, and zero when there was nothing to fall
    /// from: a kind that appears from an absent previous count has no
    /// denominator, and inventing one would report a new kind as a loss.
    pub fn lost_fraction(&self) -> f64 {
        if self.previous == 0 || self.current >= self.previous {
            return 0.0;
        }
        (self.previous - self.current) as f64 / self.previous as f64
    }

    /// One sentence naming what this kind did, for a status or doctor line.
    pub fn describe(&self) -> String {
        match self.movement {
            CensusMovement::Vanished => format!("{} went {} to 0", self.kind, self.previous),
            CensusMovement::Fell => format!(
                "{} fell {} to {} ({:.0}% of its edges)",
                self.kind,
                self.previous,
                self.current,
                self.lost_fraction() * 100.0
            ),
            CensusMovement::Slipped => format!(
                "{} slipped {} to {}",
                self.kind, self.previous, self.current
            ),
            CensusMovement::Grew => {
                format!("{} grew {} to {}", self.kind, self.previous, self.current)
            }
            CensusMovement::Appeared => format!("{} is new at {}", self.kind, self.current),
            CensusMovement::Unchanged => format!("{} held at {}", self.kind, self.current),
        }
    }
}

/// Classify every kind in either census.
///
/// Pure, and over the union of both key sets, so a kind that vanished is
/// classified from the previous census alone. A comparison that iterated only
/// the current census would be structurally unable to see the case this whole
/// record exists for: the vanished kind is precisely the one that is no longer
/// there to iterate.
pub fn compare(
    previous: &BTreeMap<String, u64>,
    current: &BTreeMap<String, u64>,
) -> Vec<CensusChange> {
    let mut kinds: Vec<&String> = previous.keys().chain(current.keys()).collect();
    kinds.sort_unstable();
    kinds.dedup();

    kinds
        .into_iter()
        .map(|kind| {
            let before = previous.get(kind).copied().unwrap_or(0);
            let after = current.get(kind).copied().unwrap_or(0);
            let mut change = CensusChange {
                kind: kind.clone(),
                previous: before,
                current: after,
                movement: CensusMovement::Unchanged,
            };
            change.movement = if before == 0 && after > 0 {
                CensusMovement::Appeared
            } else if after > before {
                CensusMovement::Grew
            } else if after == before {
                CensusMovement::Unchanged
            } else if after == 0 {
                CensusMovement::Vanished
            } else if change.lost_fraction() >= SHARP_DROP_FRACTION {
                CensusMovement::Fell
            } else {
                CensusMovement::Slipped
            };
            change
        })
        .collect()
}

/// A current census set beside the recorded one, and what the pair says.
///
/// Built even when there is no previous record, because every state has a line
/// to print. A comparison that rendered nothing when it had nothing to compare
/// would be indistinguishable from one reporting a healthy store, which is the
/// exact failure mode being closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationCensusComparison {
    /// When the previous census was recorded, and by which writer. Absent when
    /// no previous census could be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_source: Option<CensusSource>,
    /// Why nothing could be compared, when nothing could be.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<String>,
    #[serde(default)]
    pub changes: Vec<CensusChange>,
    /// Conditions known to reduce relation coverage, active now.
    #[serde(default)]
    pub causes: Vec<String>,
}

impl RelationCensusComparison {
    /// Compare `current` against whatever the store recorded.
    pub fn build(
        previous: &RelationCensusRead,
        current: &BTreeMap<String, u64>,
        causes: Vec<String>,
    ) -> Self {
        match previous {
            RelationCensusRead::Recorded(recorded) => Self {
                previous_at: Some(recorded.at),
                previous_source: Some(recorded.source),
                unavailable: None,
                changes: compare(&recorded.kinds, current),
                causes,
            },
            RelationCensusRead::Absent => Self {
                previous_at: None,
                previous_source: None,
                unavailable: Some(
                    "no previous relation census is recorded for this store, so a lost relation \
                     kind cannot be detected yet; one is recorded at the next completed \
                     enrichment sweep or commit"
                        .to_string(),
                ),
                changes: Vec::new(),
                causes,
            },
            RelationCensusRead::Unreadable(reason) => Self {
                previous_at: None,
                previous_source: None,
                unavailable: Some(format!(
                    "the recorded relation census could not be read ({reason}), so a lost \
                     relation kind cannot be detected; the next completed enrichment sweep or \
                     commit rewrites it"
                )),
                changes: Vec::new(),
                causes,
            },
        }
    }

    /// The kinds that disappeared entirely.
    pub fn vanished(&self) -> Vec<&CensusChange> {
        self.changes
            .iter()
            .filter(|change| change.movement == CensusMovement::Vanished)
            .collect()
    }

    /// The kinds that fell beyond [`SHARP_DROP_FRACTION`] without vanishing.
    pub fn sharp_drops(&self) -> Vec<&CensusChange> {
        self.changes
            .iter()
            .filter(|change| change.movement == CensusMovement::Fell)
            .collect()
    }

    /// Whether the pair withholds the all-clear.
    pub fn reports_loss(&self) -> bool {
        self.changes.iter().any(|change| change.movement.is_loss())
    }

    /// The clause naming why coverage fell, when the cause is known.
    ///
    /// Empty when nothing on this host is known to reduce coverage. Silence is
    /// correct there: naming a cause that was not measured would send an
    /// operator after a knob nobody set.
    fn cause_clause(&self) -> String {
        if self.causes.is_empty() {
            return String::new();
        }
        format!("; recorded cause: {}", self.causes.join("; "))
    }

    /// The issue sentences a status surface adds to its warnings, most severe
    /// first.
    ///
    /// One per losing kind rather than one summary, because the operator's next
    /// action depends on which kind went: a lost `UsesType` points at type
    /// resolution and a lost `Calls` points at the parser.
    pub fn loss_lines(&self) -> Vec<String> {
        let recorded = match (self.previous_at, self.previous_source) {
            (Some(at), Some(source)) => {
                format!(
                    " since the census recorded at {} ({})",
                    at.to_rfc3339(),
                    source.label()
                )
            }
            _ => String::new(),
        };
        let cause = self.cause_clause();
        self.vanished()
            .into_iter()
            .map(|change| {
                format!(
                    "relation kind {} lost every edge it held: {}{recorded}{cause}",
                    change.kind,
                    change.describe()
                )
            })
            .chain(self.sharp_drops().into_iter().map(|change| {
                format!(
                    "relation kind {} fell beyond {:.0}% of its edges: {}{recorded}{cause}",
                    change.kind,
                    SHARP_DROP_FRACTION * 100.0,
                    change.describe()
                )
            }))
            .collect()
    }

    /// Previous and current totals across every kind in the comparison.
    pub fn totals(&self) -> (u64, u64) {
        self.changes
            .iter()
            .fold((0, 0), |(previous, current), change| {
                (previous + change.previous, current + change.current)
            })
    }

    /// The clause naming an aggregate fall, when the total fell.
    ///
    /// Carried because a store can lose real ground with no single kind
    /// crossing the warning threshold. On the run this record comes from,
    /// `References` fell 412 to 340, comfortably inside tolerance, while the
    /// total moved 1985 to 1807. A row reporting only per-kind losses would
    /// have named the vanished kind and stayed silent about the rest.
    fn total_clause(&self) -> String {
        let (previous, current) = self.totals();
        if current >= previous {
            return String::new();
        }
        format!("the total fell {previous} to {current}")
    }

    /// The one row a status surface always prints, whatever the verdict.
    pub fn summary_line(&self) -> String {
        if let Some(unavailable) = &self.unavailable {
            return format!("Relation census: {unavailable}");
        }
        let recorded = match (self.previous_at, self.previous_source) {
            (Some(at), Some(source)) => format!("{} ({})", at.to_rfc3339(), source.label()),
            _ => "an unrecorded moment".to_string(),
        };
        let total = self.total_clause();
        let losses = self.loss_summary();
        if losses.is_empty() {
            if total.is_empty() {
                return format!(
                    "Relation census: no relation kind has lost ground since {recorded}, which \
                     is what this row compares the histogram above against"
                );
            }
            return format!(
                "Relation census: no relation kind lost enough to warn about since {recorded}, \
                 though {total}{}",
                self.cause_clause()
            );
        }
        let total = if total.is_empty() {
            String::new()
        } else {
            format!(", and {total}")
        };
        format!(
            "Relation census: {losses}{total} since {recorded}{}",
            self.cause_clause()
        )
    }

    fn loss_summary(&self) -> String {
        let losses: Vec<String> = self
            .changes
            .iter()
            .filter(|change| change.movement.is_loss())
            .map(|change| change.describe())
            .collect();
        losses.join(", ")
    }
}

/// What a status surface needs to compare its own census against the store's.
///
/// Bundled and passed in rather than read inside the renderer, so the rule is
/// driven by real inputs in tests instead of by whatever the test process
/// happens to have on disk and in its environment. `Default` is the honest
/// no-store case: no previous census and no known cause.
#[derive(Debug, Clone, Default)]
pub struct CensusContext {
    pub previous: RelationCensusRead,
    pub causes: Vec<String>,
}

impl CensusContext {
    /// Read the record for `layout` and audit `vars` for conditions known to
    /// reduce relation coverage.
    pub fn for_layout<I>(layout: &KinLayout, vars: I) -> Self
    where
        I: IntoIterator<Item = (String, String)>,
    {
        Self {
            previous: read(layout),
            causes: known_causes(vars),
        }
    }
}

/// Read the durable record for `layout`.
///
/// Never fails. A missing record is [`RelationCensusRead::Absent`] and anything
/// unparseable is [`RelationCensusRead::Unreadable`]; a read error must not be
/// able to present as "nothing changed".
pub fn read(layout: &KinLayout) -> RelationCensusRead {
    let path = layout.kindb_relation_census_path();
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return RelationCensusRead::Absent
        }
        Err(error) => return RelationCensusRead::Unreadable(error.to_string()),
    };
    match serde_json::from_str::<RelationCensus>(&raw) {
        Ok(recorded) if recorded.schema == RELATION_CENSUS_SCHEMA => {
            RelationCensusRead::Recorded(recorded)
        }
        Ok(recorded) => RelationCensusRead::Unreadable(format!(
            "schema {} is not {RELATION_CENSUS_SCHEMA}",
            recorded.schema
        )),
        Err(error) => RelationCensusRead::Unreadable(error.to_string()),
    }
}

/// Write the durable record for `layout`, atomically.
///
/// Staged beside the target and renamed into place after an fsync, then the
/// directory metadata is synced, so a crash mid-write leaves either the previous
/// census or the new one and never a truncated file that would read as
/// unreadable forever. This is the same publication the last-admission marker
/// beside it uses.
pub fn write(layout: &KinLayout, recorded: &RelationCensus) -> std::io::Result<()> {
    use std::io::Write;

    let path = layout.kindb_relation_census_path();
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("relation-census path has no parent directory"))?;
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

/// The conditions in an environment that are known to reduce relation coverage.
///
/// Derived from the same audit that emits `correctness-relevant override
/// active` at startup, so the cause a status row names is the cause the log
/// already warned about, word for word. On the run that produced this record's
/// ticket the warning fired unprompted at commit time and the health line
/// contradicted it three minutes later.
///
/// Pure over an iterator rather than reading the process environment, so the
/// rule is testable and so a daemon reports the environment IT runs under
/// rather than the one a reader's shell happens to carry.
pub fn known_causes<I>(vars: I) -> Vec<String>
where
    I: IntoIterator<Item = (String, String)>,
{
    crate::env_registry::audit_env(vars, false)
        .non_default
        .into_iter()
        .map(|finding| format!("{} {}", finding.var, finding.message))
        .collect()
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

    fn census(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs
            .iter()
            .map(|(kind, count)| ((*kind).to_string(), *count))
            .collect()
    }

    fn movement_of(changes: &[CensusChange], kind: &str) -> CensusMovement {
        changes
            .iter()
            .find(|change| change.kind == kind)
            .unwrap_or_else(|| panic!("no change recorded for {kind}: {changes:?}"))
            .movement
    }

    /// The rc0545c case. `UsesType` held 94 edges and then held none, and no
    /// surface said so.
    #[test]
    fn a_kind_that_vanished_is_reported_as_vanished() {
        let previous = census(&[("Calls", 951), ("UsesType", 94)]);
        let current = census(&[("Calls", 940)]);
        let changes = compare(&previous, &current);
        assert_eq!(movement_of(&changes, "UsesType"), CensusMovement::Vanished);
        let vanished = changes
            .iter()
            .find(|change| change.kind == "UsesType")
            .unwrap();
        assert_eq!(vanished.previous, 94);
        assert_eq!(vanished.current, 0);
        assert_eq!(vanished.describe(), "UsesType went 94 to 0");
    }

    /// Forty percent is past the stated threshold, so it is a loss rather than
    /// movement.
    #[test]
    fn a_kind_that_dropped_forty_percent_is_reported_as_a_sharp_fall() {
        let previous = census(&[("References", 500)]);
        let current = census(&[("References", 300)]);
        let changes = compare(&previous, &current);
        assert_eq!(movement_of(&changes, "References"), CensusMovement::Fell);
        let fell = changes
            .iter()
            .find(|change| change.kind == "References")
            .unwrap();
        assert!(
            (fell.lost_fraction() - 0.4).abs() < 1e-9,
            "40% of 500 is 200: {}",
            fell.lost_fraction()
        );
        assert!(
            fell.describe().contains("References fell 500 to 300"),
            "{}",
            fell.describe()
        );
    }

    /// Just under the threshold. Reported in the comparison, never as a
    /// warning, because a surface that warns on every re-parse is one nobody
    /// reads.
    #[test]
    fn a_kind_that_slipped_within_tolerance_is_not_a_loss() {
        let previous = census(&[("Calls", 100)]);
        let current = census(&[("Calls", 80)]);
        let changes = compare(&previous, &current);
        assert_eq!(movement_of(&changes, "Calls"), CensusMovement::Slipped);
        assert!(!CensusMovement::Slipped.is_loss());
    }

    #[test]
    fn a_kind_that_grew_is_not_a_loss() {
        let previous = census(&[("Calls", 940)]);
        let current = census(&[("Calls", 951)]);
        let changes = compare(&previous, &current);
        assert_eq!(movement_of(&changes, "Calls"), CensusMovement::Grew);
        assert!(!CensusMovement::Grew.is_loss());
    }

    #[test]
    fn a_kind_absent_from_the_previous_census_is_new_rather_than_a_loss() {
        let previous = census(&[("Calls", 940)]);
        let current = census(&[("Calls", 940), ("UsesType", 94)]);
        let changes = compare(&previous, &current);
        assert_eq!(movement_of(&changes, "UsesType"), CensusMovement::Appeared);
        let appeared = changes
            .iter()
            .find(|change| change.kind == "UsesType")
            .unwrap();
        assert_eq!(appeared.previous, 0);
        assert_eq!(
            appeared.lost_fraction(),
            0.0,
            "a new kind has no denominator to lose against"
        );
    }

    #[test]
    fn an_identical_census_reports_every_kind_unchanged_and_no_loss() {
        let both = census(&[("Calls", 940), ("Contains", 483), ("Overrides", 10)]);
        let changes = compare(&both, &both);
        assert_eq!(changes.len(), 3);
        assert!(
            changes
                .iter()
                .all(|change| change.movement == CensusMovement::Unchanged),
            "{changes:?}"
        );
        assert!(!changes.iter().any(|change| change.movement.is_loss()));
    }

    /// The structural property. A kind that vanished is absent from the current
    /// census, so a comparison that walked only the current one could never see
    /// it, whatever its thresholds were.
    #[test]
    fn the_comparison_walks_kinds_the_current_census_no_longer_holds() {
        let previous = census(&[("UsesType", 94)]);
        let current = census(&[]);
        let changes = compare(&previous, &current);
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert_eq!(changes[0].kind, "UsesType");
        assert_eq!(changes[0].movement, CensusMovement::Vanished);
    }

    #[test]
    fn a_comparison_against_a_recorded_census_names_the_loss_and_its_cause() {
        let recorded = RelationCensus::new(
            at(1_000_000),
            CensusSource::Sweep,
            census(&[("Calls", 951), ("UsesType", 94)]),
            Vec::new(),
        );
        let comparison = RelationCensusComparison::build(
            &RelationCensusRead::Recorded(recorded),
            &census(&[("Calls", 940)]),
            vec!["KIN_DAEMON_DISABLE_LSP set to non-default value \"1\"".to_string()],
        );
        assert!(comparison.reports_loss());
        let lines = comparison.loss_lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("UsesType went 94 to 0"),
            "the loss is named: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("KIN_DAEMON_DISABLE_LSP"),
            "the cause is named: {}",
            lines[0]
        );
        assert!(
            comparison.summary_line().contains("UsesType went 94 to 0"),
            "{}",
            comparison.summary_line()
        );
    }

    /// Absent is not "unchanged". The row says what it cannot do.
    #[test]
    fn no_recorded_census_reports_that_nothing_could_be_compared() {
        let comparison = RelationCensusComparison::build(
            &RelationCensusRead::Absent,
            &census(&[("Calls", 940)]),
            Vec::new(),
        );
        assert!(!comparison.reports_loss());
        assert!(comparison.loss_lines().is_empty());
        assert!(
            comparison
                .summary_line()
                .contains("no previous relation census is recorded"),
            "{}",
            comparison.summary_line()
        );
    }

    #[test]
    fn an_unreadable_census_reports_the_reason_rather_than_silence() {
        let comparison = RelationCensusComparison::build(
            &RelationCensusRead::Unreadable("expected value at line 1 column 1".to_string()),
            &census(&[("Calls", 940)]),
            Vec::new(),
        );
        assert!(!comparison.reports_loss());
        assert!(
            comparison
                .summary_line()
                .contains("expected value at line 1 column 1"),
            "{}",
            comparison.summary_line()
        );
    }

    /// The gap a per-kind threshold leaves. Nothing crosses 25%, so nothing
    /// warns, and the row still has to say the store holds fewer edges than it
    /// did or the aggregate move is invisible.
    #[test]
    fn a_total_that_fell_is_named_even_when_no_single_kind_crossed_the_threshold() {
        let recorded = RelationCensus::new(
            at(1_000_000),
            CensusSource::Sweep,
            census(&[("Calls", 951), ("References", 412)]),
            Vec::new(),
        );
        let comparison = RelationCensusComparison::build(
            &RelationCensusRead::Recorded(recorded),
            &census(&[("Calls", 940), ("References", 340)]),
            Vec::new(),
        );
        assert!(
            !comparison.reports_loss(),
            "17% is inside tolerance, so nothing warns: {:?}",
            comparison.changes
        );
        assert_eq!(comparison.totals(), (1363, 1280));
        assert!(
            comparison
                .summary_line()
                .contains("the total fell 1363 to 1280"),
            "{}",
            comparison.summary_line()
        );
    }

    #[test]
    fn a_total_that_grew_adds_no_clause() {
        let recorded = RelationCensus::new(
            at(1),
            CensusSource::Commit,
            census(&[("Calls", 100)]),
            Vec::new(),
        );
        let comparison = RelationCensusComparison::build(
            &RelationCensusRead::Recorded(recorded),
            &census(&[("Calls", 120)]),
            Vec::new(),
        );
        assert!(
            !comparison.summary_line().contains("the total fell"),
            "{}",
            comparison.summary_line()
        );
    }

    #[test]
    fn a_written_census_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        let recorded = RelationCensus::new(
            at(1_000_000),
            CensusSource::Commit,
            census(&[("Calls", 940), ("Contains", 483)]),
            vec!["KIN_DAEMON_DISABLE_LSP set to non-default value \"1\"".to_string()],
        );
        write(&layout, &recorded).unwrap();
        assert_eq!(read(&layout), RelationCensusRead::Recorded(recorded));
    }

    /// The durability property. A census survives being read by a process that
    /// never wrote it, which is what a daemon restart looks like from the
    /// reader's side.
    #[test]
    fn a_census_survives_a_reader_that_did_not_write_it() {
        let dir = tempfile::tempdir().unwrap();
        {
            let layout = layout_in(dir.path());
            write(
                &layout,
                &RelationCensus::new(
                    at(500),
                    CensusSource::Sweep,
                    census(&[("UsesType", 94)]),
                    Vec::new(),
                ),
            )
            .unwrap();
        }
        let reopened = layout_in(dir.path());
        match read(&reopened) {
            RelationCensusRead::Recorded(recorded) => {
                assert_eq!(recorded.kinds.get("UsesType"), Some(&94));
                assert_eq!(recorded.total, 94);
            }
            other => panic!("expected a recorded census, got {other:?}"),
        }
    }

    #[test]
    fn a_record_written_by_a_future_schema_reads_as_unreadable_rather_than_absent() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        let mut recorded = RelationCensus::new(
            at(1),
            CensusSource::Sweep,
            census(&[("Calls", 1)]),
            Vec::new(),
        );
        recorded.schema = "kin.relation-census.v9".to_string();
        std::fs::write(
            layout.kindb_relation_census_path(),
            serde_json::to_vec(&recorded).unwrap(),
        )
        .unwrap();
        match read(&layout) {
            RelationCensusRead::Unreadable(reason) => {
                assert!(reason.contains("kin.relation-census.v9"), "{reason}")
            }
            other => panic!("expected unreadable, got {other:?}"),
        }
    }

    /// The cause a status row names is the cause the startup log already
    /// warned about, from the same audit.
    #[test]
    fn the_knob_that_disables_lsp_enrichment_is_reported_as_a_known_cause() {
        let causes = known_causes([("KIN_DAEMON_DISABLE_LSP".to_string(), "1".to_string())]);
        assert_eq!(causes.len(), 1, "{causes:?}");
        assert!(
            causes[0].starts_with("KIN_DAEMON_DISABLE_LSP"),
            "{}",
            causes[0]
        );
    }

    #[test]
    fn an_environment_with_no_overrides_names_no_cause() {
        assert!(known_causes([("PATH".to_string(), "/usr/bin".to_string())]).is_empty());
    }
}
