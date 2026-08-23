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
//! Recording at those moments is necessary and was not sufficient. The rc0547b
//! stranger run committed 26 lines of docstring to `psf/requests` and the store
//! went from 1279 `Calls` and 11 `Overrides` edges to 1268 and 10, with the
//! entity count unmoved at 783. `kin doctor` reported the census green, because
//! the commit that lost the edges wrote the baseline the next comparison would
//! be judged against, and both recovery sweeps advanced it again. A detector
//! whose comparison point is written by the event it exists to catch cannot
//! catch it.
//!
//! Two rules close that, and they are the same rule read from either end.
//! [`record`] advances the baseline only to a census that did not lose ground
//! against the one it would replace, so a losing pass leaves the last
//! verified-good census in place and no later sweep can bury it. And a kind
//! that slipped while the entity count held or grew is reported rather than
//! tolerated, because edges disappearing with no code removed is a derivation
//! defect at any magnitude, while the same slip beside a fallen entity count is
//! a store that shrank. The entity count is the discriminator, it is already on
//! the screen directly above the histogram, and without it the only honest
//! choice is between missing a twelve-edge regression and warning on every
//! deletion.
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
    /// Entities the graph held when this census was taken.
    ///
    /// The discriminator between a store that lost edges and a store that lost
    /// code. Relation counts alone cannot tell a derivation regression from an
    /// ordinary deletion, so a rule built on them alone must either tolerate the
    /// twelve-edge loss this record exists for or warn every time someone
    /// removes a function.
    ///
    /// `Option` rather than a bare count, and the difference is load-bearing.
    /// A record written before this field existed carries no entity count, and
    /// reading the absence as zero would make every store that upgraded look
    /// like one that had just grown its entire graph from nothing. `None` means
    /// the discriminator is unavailable, and every rule below falls back to the
    /// magnitude thresholds it used before rather than guessing.
    #[serde(default)]
    pub entities: Option<u64>,
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
            entities: None,
        }
    }

    /// Record the entity count the graph held when this census was measured.
    pub fn with_entities(mut self, entities: u64) -> Self {
        self.entities = Some(entities);
        self
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
    /// Entities the previous census recorded, when it recorded any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_entities: Option<u64>,
    /// Entities the graph holds now, when the caller measured them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_entities: Option<u64>,
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
                previous_entities: recorded.entities,
                current_entities: None,
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
                previous_entities: None,
                current_entities: None,
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
                previous_entities: None,
                current_entities: None,
            },
        }
    }

    /// Record the entity count the current census was measured beside.
    ///
    /// Chained rather than taken by [`Self::build`] so a caller that genuinely
    /// does not hold an entity count says so by omission, and so the surfaces
    /// that do hold one all pass the same measurement the histogram above them
    /// was counted from.
    pub fn with_current_entities(mut self, entities: u64) -> Self {
        self.current_entities = Some(entities);
        self
    }

    /// Whether the store holds at least as many entities as it did at the
    /// baseline.
    ///
    /// `false` when either count is unknown. A comparison that cannot see the
    /// entity count must not be able to promote an ordinary slip to a warning,
    /// so the unknown case reads as "the store may have shrunk" and the
    /// magnitude thresholds decide alone.
    pub fn entities_held(&self) -> bool {
        match (self.previous_entities, self.current_entities) {
            (Some(previous), Some(current)) => current >= previous,
            _ => false,
        }
    }

    /// Kinds that lost edges while the entity count held or grew.
    ///
    /// These are the losses [`SHARP_DROP_FRACTION`] was never going to catch.
    /// On the rc0547b run `Calls` fell 1279 to 1268, which is 0.9% of the kind
    /// and nowhere near the threshold, over a graph whose entity count did not
    /// move at all. No code was removed and eleven call edges were, and there
    /// is no magnitude at which that is ordinary.
    pub fn unexplained_slips(&self) -> Vec<&CensusChange> {
        if !self.entities_held() {
            return Vec::new();
        }
        self.changes
            .iter()
            .filter(|change| change.movement == CensusMovement::Slipped)
            .collect()
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
    ///
    /// A vanished kind and a sharp fall do at any entity count. A slip does
    /// only when the entity count held, which is what makes it a regression
    /// rather than a smaller store.
    pub fn reports_loss(&self) -> bool {
        self.changes.iter().any(|change| change.movement.is_loss())
            || !self.unexplained_slips().is_empty()
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
        let entities = match (self.previous_entities, self.current_entities) {
            (Some(previous), Some(current)) if current == previous => {
                format!(", while the entity count held at {current}")
            }
            (Some(previous), Some(current)) => {
                format!(", while the entity count grew {previous} to {current}")
            }
            _ => String::new(),
        };
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
            .chain(self.unexplained_slips().into_iter().map(|change| {
                format!(
                    "relation kind {} lost edges with no entity removed: {}{entities}{recorded}\
                     {cause}",
                    change.kind,
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
        let unexplained: Vec<&String> = self
            .unexplained_slips()
            .into_iter()
            .map(|change| &change.kind)
            .collect();
        let losses: Vec<String> = self
            .changes
            .iter()
            .filter(|change| change.movement.is_loss() || unexplained.contains(&&change.kind))
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

/// What [`record`] did with the census it was handed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CensusRecordOutcome {
    /// The census did not lose ground, so it is the new baseline.
    Advanced,
    /// The census lost ground, so the previous baseline stays and the loss is
    /// named. The recorded comparison point is the one in `held_at`.
    Held {
        held_at: DateTime<Utc>,
        held_source: CensusSource,
        losses: Vec<String>,
    },
    /// The record could not be written. The previous baseline stays, which is
    /// the safe direction: a longer window reports more movement, not less.
    Failed(String),
}

/// File name for the durable record that this store is currently below its own
/// verified-good census.
pub const CENSUS_HOLD_FILE_NAME: &str = "relation-census-hold.json";

/// Where a `.kin` root keeps it, beside the census it qualifies.
pub fn census_hold_path(kin_root: &std::path::Path) -> std::path::PathBuf {
    kin_root.join("kindb").join(CENSUS_HOLD_FILE_NAME)
}

/// What a store records when a pass lost relation ground.
///
/// [`record`] already knew this and only logged it. A warning in a daemon log
/// nobody is tailing is not a disclosure: on the rc0550 run the relation census
/// was the one surface that saw a comment-only commit delete twelve edges,
/// while `find_references` answered from the damaged graph with
/// `degraded_signals: []` and `edge_coverage.calls: "present"` (FIR-2644). The
/// query surfaces cannot recompute a census per response, so the pass that
/// already computed it leaves this behind for them.
///
/// Durable and self-clearing on the same terms as the baseline it qualifies:
/// written whenever `record` refuses a losing census, removed the moment a
/// census advances, so a store that recovers stops reporting a loss without any
/// second event to retract it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CensusHold {
    /// When the baseline the graph is short against was taken.
    pub held_at: DateTime<Utc>,
    /// Which pass took it.
    pub held_source: String,
    /// One line per kind that lost ground, as [`RelationCensusComparison`]
    /// renders them.
    pub losses: Vec<String>,
}

impl CensusHold {
    /// What this store records, or `None` when it records nothing.
    ///
    /// An unreadable record reads as absent, for the reason the memory-pressure
    /// record does: this exists to report a degradation and must never become
    /// one.
    pub fn read(kin_root: &std::path::Path) -> Option<Self> {
        let raw = std::fs::read(census_hold_path(kin_root)).ok()?;
        serde_json::from_slice(&raw).ok()
    }

    /// One sentence a surface can print without parsing the parts.
    pub fn summary(&self) -> String {
        format!(
            "the graph holds fewer relations than the census recorded at {} ({}): {}",
            self.held_at.to_rfc3339(),
            self.held_source,
            self.losses.join("; ")
        )
    }
}

/// Publish the hold for `layout`, or retire it when the graph has recovered.
///
/// A write that fails is dropped. A pass that cannot publish its own disclosure
/// must not fail the work it was disclosing about, and the direction of that
/// failure is the safe one for a retire and the unsafe one for a publish, which
/// is why the publish is attempted before anything depends on it.
fn publish_hold(layout: &KinLayout, hold: Option<&CensusHold>) {
    let path = census_hold_path(layout.root());
    match hold {
        Some(hold) => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(body) = serde_json::to_vec(hold) {
                let _ = std::fs::write(&path, body);
            }
        }
        None => {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Record `census` as the store's baseline, unless it lost ground.
///
/// This is the write half of the rule the module doc states. A baseline is a
/// claim that the graph was last known good at that point, so a census holding
/// fewer edges than the one it would replace is not eligible to become one. A
/// losing pass leaves the previous record untouched and returns [`Held`], and
/// every later `kin graph status` and `kin doctor` keeps comparing the live
/// graph against the last verified-good census until the graph recovers.
///
/// That ordering is the whole point. The rc0547b commit measured its own
/// post-commit census and wrote it, so the next comparison was the losing graph
/// against itself and found nothing; the two recovery sweeps that followed each
/// advanced the baseline again over the same loss. Under this rule the commit's
/// census is refused, the pre-commit sweep census stays the comparison point,
/// and neither sweep can move it while the store is still short.
///
/// It clears itself. Once the graph holds what it held, the next census no
/// longer loses ground against the baseline and becomes the new one, so
/// enrichment jitter that dips and recovers costs one held pass rather than a
/// permanent warning. A store that genuinely shrank advances too, because a
/// slip beside a fallen entity count is not a loss.
///
/// [`Held`]: CensusRecordOutcome::Held
pub fn record(layout: &KinLayout, census: &RelationCensus) -> CensusRecordOutcome {
    let previous = read(layout);
    if let RelationCensusRead::Recorded(recorded) = &previous {
        let mut comparison =
            RelationCensusComparison::build(&previous, &census.kinds, census.causes.clone());
        if let Some(entities) = census.entities {
            comparison = comparison.with_current_entities(entities);
        }
        if comparison.reports_loss() {
            let losses = comparison.loss_lines();
            publish_hold(
                layout,
                Some(&CensusHold {
                    held_at: recorded.at,
                    held_source: recorded.source.label().to_string(),
                    losses: losses.clone(),
                }),
            );
            return CensusRecordOutcome::Held {
                held_at: recorded.at,
                held_source: recorded.source,
                losses,
            };
        }
    }
    match write(layout, census) {
        Ok(()) => {
            // Retired only after the advance landed. A cleared hold beside a
            // baseline that failed to move would report a recovery the store
            // did not make.
            publish_hold(layout, None);
            CensusRecordOutcome::Advanced
        }
        Err(error) => CensusRecordOutcome::Failed(error.to_string()),
    }
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

    /// The rc0547b case, in its own numbers. A 26-line docstring commit on
    /// `psf/requests` took `Calls` 1279 to 1268 and `Overrides` 11 to 10 while
    /// the entity count sat at 783 both times. Neither kind is near
    /// [`SHARP_DROP_FRACTION`], so magnitude alone reports nothing.
    #[test]
    fn a_kind_that_slipped_while_the_entity_count_held_is_reported_as_a_loss() {
        let recorded = RelationCensus::new(
            at(1_000_000),
            CensusSource::Sweep,
            census(&[("Calls", 1279), ("Overrides", 11), ("UsesType", 1829)]),
            Vec::new(),
        )
        .with_entities(783);
        let comparison = RelationCensusComparison::build(
            &RelationCensusRead::Recorded(recorded),
            &census(&[("Calls", 1268), ("Overrides", 10), ("UsesType", 1829)]),
            Vec::new(),
        )
        .with_current_entities(783);

        assert_eq!(
            movement_of(&comparison.changes, "Calls"),
            CensusMovement::Slipped,
            "0.9% is nowhere near the threshold, which is the point"
        );
        assert!(
            comparison.reports_loss(),
            "eleven call edges gone with no entity removed is a loss: {:?}",
            comparison.changes
        );
        let lines = comparison.loss_lines();
        assert_eq!(lines.len(), 2, "{lines:?}");
        let rendered = lines.join("\n");
        assert!(
            rendered.contains("Calls slipped 1279 to 1268"),
            "the kind and both counts are named: {rendered}"
        );
        assert!(
            rendered.contains("Overrides slipped 11 to 10"),
            "the second kind is named too: {rendered}"
        );
        assert!(
            rendered.contains("the entity count held at 783"),
            "the discriminator is named beside the loss: {rendered}"
        );
        let summary = comparison.summary_line();
        assert!(
            summary.contains("Calls slipped 1279 to 1268")
                && summary.contains("Overrides slipped 11 to 10"),
            "the one row status always prints names both kinds: {summary}"
        );
    }

    /// The arm that keeps the rule above from warning on every deletion. Same
    /// eleven edges, over a store that lost entities to hold them.
    #[test]
    fn a_kind_that_slipped_beside_a_fallen_entity_count_is_a_smaller_store() {
        let recorded = RelationCensus::new(
            at(1_000_000),
            CensusSource::Sweep,
            census(&[("Calls", 1279)]),
            Vec::new(),
        )
        .with_entities(783);
        let comparison = RelationCensusComparison::build(
            &RelationCensusRead::Recorded(recorded),
            &census(&[("Calls", 1268)]),
            Vec::new(),
        )
        .with_current_entities(770);

        assert!(!comparison.entities_held());
        assert!(
            !comparison.reports_loss(),
            "removing code removes its edges: {:?}",
            comparison.changes
        );
        assert!(comparison.loss_lines().is_empty());
    }

    /// A record written before the entity count existed cannot answer the
    /// question, and an unknown count must not read as zero. The old magnitude
    /// rule decides alone there.
    #[test]
    fn a_census_with_no_recorded_entity_count_falls_back_to_the_threshold() {
        let recorded = RelationCensus::new(
            at(1_000_000),
            CensusSource::Sweep,
            census(&[("Calls", 1279)]),
            Vec::new(),
        );
        assert_eq!(recorded.entities, None);
        let comparison = RelationCensusComparison::build(
            &RelationCensusRead::Recorded(recorded),
            &census(&[("Calls", 1268)]),
            Vec::new(),
        )
        .with_current_entities(783);

        assert!(!comparison.entities_held(), "one side is unknown");
        assert!(!comparison.reports_loss());
    }

    /// The defect this record's second rule closes. The commit that lost the
    /// edges must not be allowed to become the point the loss is judged
    /// against.
    #[test]
    fn a_losing_census_does_not_become_the_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        let good = RelationCensus::new(
            at(1_000_000),
            CensusSource::Sweep,
            census(&[("Calls", 1279), ("Overrides", 11)]),
            Vec::new(),
        )
        .with_entities(783);
        assert_eq!(record(&layout, &good), CensusRecordOutcome::Advanced);

        let after_commit = RelationCensus::new(
            at(1_000_500),
            CensusSource::Commit,
            census(&[("Calls", 1268), ("Overrides", 10)]),
            Vec::new(),
        )
        .with_entities(783);
        match record(&layout, &after_commit) {
            CensusRecordOutcome::Held {
                held_at,
                held_source,
                losses,
            } => {
                assert_eq!(held_at, at(1_000_000));
                assert_eq!(held_source, CensusSource::Sweep);
                assert!(
                    losses
                        .iter()
                        .any(|line| line.contains("Calls slipped 1279 to 1268")),
                    "the refusal names what it refused: {losses:?}"
                );
            }
            other => panic!("a commit that lost edges must not set the baseline, got {other:?}"),
        }
        match read(&layout) {
            RelationCensusRead::Recorded(recorded) => {
                assert_eq!(recorded.kinds.get("Calls"), Some(&1279));
                assert_eq!(recorded.at, at(1_000_000));
            }
            other => panic!("the verified-good census stays on disk, got {other:?}"),
        }
    }

    /// Every recovery attempt on the rc0547b store advanced the baseline again.
    /// A sweep that reproduces the loss is not evidence of health either.
    #[test]
    fn a_sweep_after_a_losing_commit_cannot_bury_it() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        let good = RelationCensus::new(
            at(1_000_000),
            CensusSource::Sweep,
            census(&[("Calls", 1279)]),
            Vec::new(),
        )
        .with_entities(783);
        record(&layout, &good);
        let losing = |secs: i64, source| {
            RelationCensus::new(at(secs), source, census(&[("Calls", 1268)]), Vec::new())
                .with_entities(783)
        };
        assert!(matches!(
            record(&layout, &losing(1_000_500, CensusSource::Commit)),
            CensusRecordOutcome::Held { .. }
        ));
        assert!(
            matches!(
                record(&layout, &losing(1_000_900, CensusSource::Sweep)),
                CensusRecordOutcome::Held { .. }
            ),
            "the first recovery sweep is refused too"
        );
        assert!(
            matches!(
                record(&layout, &losing(1_001_400, CensusSource::Sweep)),
                CensusRecordOutcome::Held { .. }
            ),
            "and the second"
        );
        match read(&layout) {
            RelationCensusRead::Recorded(recorded) => assert_eq!(recorded.at, at(1_000_000)),
            other => panic!("expected the original baseline, got {other:?}"),
        }
    }

    /// The hold clears itself, so enrichment jitter costs one refused pass
    /// rather than a permanent warning.
    #[test]
    fn a_recovered_census_becomes_the_baseline_again() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        let good = RelationCensus::new(
            at(1_000_000),
            CensusSource::Sweep,
            census(&[("Calls", 1279)]),
            Vec::new(),
        )
        .with_entities(783);
        record(&layout, &good);
        record(
            &layout,
            &RelationCensus::new(
                at(1_000_500),
                CensusSource::Sweep,
                census(&[("Calls", 1268)]),
                Vec::new(),
            )
            .with_entities(783),
        );
        let recovered = RelationCensus::new(
            at(1_001_000),
            CensusSource::Sweep,
            census(&[("Calls", 1279)]),
            Vec::new(),
        )
        .with_entities(783);
        assert_eq!(record(&layout, &recovered), CensusRecordOutcome::Advanced);
        match read(&layout) {
            RelationCensusRead::Recorded(recorded) => assert_eq!(recorded.at, at(1_001_000)),
            other => panic!("expected the recovered census, got {other:?}"),
        }
    }

    /// A store that legitimately shrank keeps moving. Holding here would pin a
    /// repository's baseline at its largest historical size forever.
    #[test]
    fn a_store_that_shrank_advances_the_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        record(
            &layout,
            &RelationCensus::new(
                at(1_000_000),
                CensusSource::Sweep,
                census(&[("Calls", 1279)]),
                Vec::new(),
            )
            .with_entities(783),
        );
        let smaller = RelationCensus::new(
            at(1_000_500),
            CensusSource::Commit,
            census(&[("Calls", 1268)]),
            Vec::new(),
        )
        .with_entities(770);
        assert_eq!(record(&layout, &smaller), CensusRecordOutcome::Advanced);
        match read(&layout) {
            RelationCensusRead::Recorded(recorded) => assert_eq!(recorded.at, at(1_000_500)),
            other => panic!("expected the smaller store's census, got {other:?}"),
        }
    }

    /// A store with nothing recorded has no ground to lose, so the first census
    /// is always taken.
    #[test]
    fn the_first_census_on_a_store_is_always_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        assert_eq!(read(&layout), RelationCensusRead::Absent);
        let first = RelationCensus::new(
            at(1),
            CensusSource::Commit,
            census(&[("Calls", 1)]),
            Vec::new(),
        )
        .with_entities(1);
        assert_eq!(record(&layout, &first), CensusRecordOutcome::Advanced);
    }

    /// A whole kind disappearing is refused whatever the entity count did. A
    /// deletion that removes 2% of a store does not take 100% of a relation
    /// kind with it.
    #[test]
    fn a_vanished_kind_holds_the_baseline_even_over_a_shrinking_store() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        record(
            &layout,
            &RelationCensus::new(
                at(1_000_000),
                CensusSource::Sweep,
                census(&[("Calls", 951), ("UsesType", 94)]),
                Vec::new(),
            )
            .with_entities(783),
        );
        let stripped = RelationCensus::new(
            at(1_000_500),
            CensusSource::Sweep,
            census(&[("Calls", 940)]),
            Vec::new(),
        )
        .with_entities(770);
        assert!(matches!(
            record(&layout, &stripped),
            CensusRecordOutcome::Held { .. }
        ));
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

    /// FIR-2644: the hold is what carries a loss to a surface that cannot
    /// recompute a census.
    ///
    /// `record` already reached this verdict and only logged it, so
    /// `find_references` answered from a graph short of its own baseline with
    /// an empty degraded list. The record is durable because the process that
    /// measures is a daemon nobody is watching and every surface that reports
    /// it runs later.
    #[test]
    fn a_refused_census_leaves_a_hold_the_query_surfaces_can_read() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        assert!(
            CensusHold::read(layout.root()).is_none(),
            "a store nothing has measured records no hold"
        );

        let good = RelationCensus::new(
            at(1_000_000),
            CensusSource::Sweep,
            census(&[("Calls", 1279), ("Overrides", 11)]),
            Vec::new(),
        )
        .with_entities(783);
        assert_eq!(record(&layout, &good), CensusRecordOutcome::Advanced);
        assert!(
            CensusHold::read(layout.root()).is_none(),
            "an advancing census records no hold, or the flag fires on every store"
        );

        let after_commit = RelationCensus::new(
            at(1_000_500),
            CensusSource::Commit,
            census(&[("Calls", 1269), ("Overrides", 10)]),
            Vec::new(),
        )
        .with_entities(783);
        assert!(matches!(
            record(&layout, &after_commit),
            CensusRecordOutcome::Held { .. }
        ));
        let hold = CensusHold::read(layout.root()).expect("the refusal published a hold");
        assert_eq!(hold.held_at, at(1_000_000));
        assert_eq!(hold.held_source, CensusSource::Sweep.label());
        assert!(
            hold.summary().contains("Calls slipped 1279 to 1269"),
            "the hold names the kind and both counts: {}",
            hold.summary()
        );
    }

    /// It clears itself. A store that recovers must stop reporting a loss
    /// without any second event to retract it, or the disclosure becomes a
    /// permanent warning nobody reads.
    #[test]
    fn a_recovered_graph_retires_its_own_hold() {
        let dir = tempfile::tempdir().unwrap();
        let layout = layout_in(dir.path());
        let kinds = census(&[("Calls", 1279), ("Overrides", 11)]);
        record(
            &layout,
            &RelationCensus::new(
                at(1_000_000),
                CensusSource::Sweep,
                kinds.clone(),
                Vec::new(),
            )
            .with_entities(783),
        );
        record(
            &layout,
            &RelationCensus::new(
                at(1_000_500),
                CensusSource::Commit,
                census(&[("Calls", 1269), ("Overrides", 10)]),
                Vec::new(),
            )
            .with_entities(783),
        );
        assert!(CensusHold::read(layout.root()).is_some());

        assert_eq!(
            record(
                &layout,
                &RelationCensus::new(at(1_001_000), CensusSource::Sweep, kinds, Vec::new())
                    .with_entities(783),
            ),
            CensusRecordOutcome::Advanced
        );
        assert!(
            CensusHold::read(layout.root()).is_none(),
            "a graph that holds what it held again reports no loss"
        );
    }
}
