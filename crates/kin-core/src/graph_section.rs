// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Whether a store serves its graph from the persisted section or folds it out
//! of history at every open, and how big that fold is.
//!
//! A converted repository's snapshot IS its history. The entities and relations
//! a daemon serves are absent from the file and folded out of the change map by
//! `ChangeStore::resolve_graph_at` every time the store opens, unless a
//! materialized graph section is present that resolves at the workspace's own
//! base. On the kin store measured on 2026-09-03 that fold was 47 seconds of a
//! 95 second open, over a change map holding 3,005 changes and making up 94.76
//! percent of a 3.49 GB body.
//!
//! Nothing reported it. kin-db logs an absent section at `trace!` and a refused
//! one at `warn!`, the daemon runs at `info`, and no kin surface named the state
//! at all, so a store paying a full history fold at every open was
//! indistinguishable from one that was not. That is what this module exists to
//! end: it reads the state, and `kin graph status`, `kin doctor` and the
//! daemon's own startup log all say it in their own voices.
//!
//! It invents no policy. It writes nothing, refreshes nothing and decides
//! nothing about when a section should exist. `kin graph materialize` remains
//! the only thing that writes one.
//!
//! **The predicate here is kin-db's own.** [`read`] asks
//! `MaterializedGraphSection::validate_for` the same question
//! `resolved_graph_from_section` asks, against the same base change resolved by
//! kin-db's own `resolve_target_change_id`. A second copy of that rule would be
//! wrong only in ways that look like a passing run, so there is no second copy:
//! a store this module calls folding is a store kin-db will fold.

use kin_db::{MaterializedGraphRefusal, RepositoryAuthorityState};
use kin_model::WorkspaceId;
use serde::{Deserialize, Serialize};

/// Schema token carried in the record so a future format change is legible
/// rather than silently misparsed.
pub const GRAPH_SECTION_STATE_SCHEMA: &str = "kin.graph-section-state.v1";

/// Where an open gets this workspace's base graph.
///
/// Absent and unreadable are separate answers, for the reason
/// [`crate::relation_census`] keeps them separate: a surface that renders a
/// state it could not read as a clean bill reintroduces exactly the invisibility
/// this module exists to remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphSectionStanding {
    /// A section is present and resolves at this workspace's base, so the open
    /// substitutes it and folds nothing.
    Serving,
    /// No section answers for this base, so the open folds the base out of the
    /// change map. [`GraphSectionState::refusal`] carries kin-db's own reason.
    Folding,
    /// The workspace names no base target. `resolve_graph_at` is never reached,
    /// there is nothing to fold and nothing worth memoizing.
    Unborn,
    /// The state could not be read. Never rendered as either of the two above.
    Unknown,
}

/// How many changes an open folds.
///
/// Two bounds rather than one number, because the exact count and the cheap
/// count are not available at the same moments. The exact count is the length
/// of the base's first-parent chain, which is what `resolve_graph_at` walks;
/// reading it means following `parents.first()` through the change map, and on
/// a store that has not decoded that map yet, taking it would force the decode
/// this whole surface exists to warn about. So the exact count is taken only
/// where the map is already in memory, and everywhere else the store's own
/// change count is reported as the upper bound it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "bound", content = "changes")]
pub enum FoldSize {
    /// Nothing is folded.
    Nothing,
    /// The base's first-parent chain, walked over an already-decoded change map.
    Exact(u64),
    /// The store holds this many changes and the fold walks the base's
    /// first-parent ancestry within them, which is at most all of them.
    AtMost(u64),
}

impl FoldSize {
    /// The number to print, whichever bound this is.
    pub const fn changes(self) -> u64 {
        match self {
            Self::Nothing => 0,
            Self::Exact(changes) | Self::AtMost(changes) => changes,
        }
    }

    /// Whether the count is the chain length rather than an upper bound.
    pub const fn is_exact(self) -> bool {
        matches!(self, Self::Nothing | Self::Exact(_))
    }

    /// Which bound this is, as one word, for a log field. A count read without
    /// its bound is a measurement a reader cannot calibrate.
    pub const fn bound(self) -> &'static str {
        match self {
            Self::Nothing => "none",
            Self::Exact(_) => "exact",
            Self::AtMost(_) => "at_most",
        }
    }

    /// The count with its bound stated, so no reader takes a ceiling for a
    /// measurement.
    fn phrase(self) -> String {
        match self {
            Self::Nothing => "no changes".to_string(),
            Self::Exact(1) => "1 change".to_string(),
            Self::Exact(changes) => format!("{changes} changes"),
            Self::AtMost(changes) => format!(
                "at most the {changes} changes this store holds, the base's first-parent \
                 ancestry within them"
            ),
        }
    }
}

/// What a cold open must do to produce this workspace's graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphSectionState {
    pub schema: String,
    pub standing: GraphSectionStanding,
    /// Whether the snapshot carries a section at all, regardless of whether it
    /// answers for this base. A present-and-refused section and an absent one
    /// are different operator problems: the first says an acceleration was
    /// written and is going unused, the second says none was ever written.
    pub section_present: bool,
    /// kin-db's own [`MaterializedGraphRefusal`], verbatim, when the standing is
    /// [`GraphSectionStanding::Folding`]. Its vocabulary rather than a
    /// paraphrase, so a reader can match this against the daemon's own warning.
    pub refusal: Option<String>,
    /// Why the state could not be read, when the standing is
    /// [`GraphSectionStanding::Unknown`].
    pub unreadable: Option<String>,
    /// The change this workspace's base resolves to, as hex.
    ///
    /// A string rather than a `SemanticChangeId` because this record is only
    /// ever displayed or logged, never used to address anything. Carrying the
    /// typed id would put a parse on the far side of a wire for no reader.
    pub base_target: Option<String>,
    /// The change the section resolves at, as hex, when one is present.
    /// Different from `base_target` is exactly what a `target` refusal means.
    pub section_resolved_at: Option<String>,
    /// Changes this store holds, read from the change map's header rather than
    /// from its contents, so asking costs no decode.
    pub changes_in_store: u64,
    pub fold: FoldSize,
    /// The workspace carries a semantic overlay, so kin-db may answer this open
    /// from a durable prepared artifact before it reaches the section question
    /// at all (`prepared_workspace_state_pays_for_itself`). Stated rather than
    /// hidden, because a line claiming a fold on an open that never folded is
    /// the same class of wrong this module exists to fix.
    pub prepared_may_preempt: bool,
}

impl GraphSectionState {
    fn new(standing: GraphSectionStanding) -> Self {
        Self {
            schema: GRAPH_SECTION_STATE_SCHEMA.to_string(),
            standing,
            section_present: false,
            refusal: None,
            unreadable: None,
            base_target: None,
            section_resolved_at: None,
            changes_in_store: 0,
            fold: FoldSize::Nothing,
            prepared_may_preempt: false,
        }
    }

    /// Whether an open of this store folds its history.
    pub const fn folds(&self) -> bool {
        matches!(self.standing, GraphSectionStanding::Folding)
    }

    /// The arm an open takes, as one word, for a log field.
    pub const fn arm(&self) -> &'static str {
        match self.standing {
            GraphSectionStanding::Serving => "section",
            GraphSectionStanding::Folding => "fold",
            GraphSectionStanding::Unborn => "unborn",
            GraphSectionStanding::Unknown => "unknown",
        }
    }

    /// The `kin graph status` row.
    ///
    /// Renders in every state including the two where nothing can be measured,
    /// because a row that falls silent when it cannot read the store is
    /// indistinguishable from one reporting a store that is fine.
    pub fn status_line(&self) -> String {
        format!(
            "Graph section: {}{}",
            self.sentence(),
            self.preempt_clause()
        )
    }

    /// The same facts as `kin doctor`'s detail, which prints one line per row
    /// and therefore says it slightly shorter.
    pub fn doctor_detail(&self) -> String {
        let mut detail = self.sentence();
        detail.push_str(&self.preempt_clause());
        detail
    }

    fn sentence(&self) -> String {
        match self.standing {
            GraphSectionStanding::Serving => format!(
                "present and current at {}, so an open serves this workspace's base from it and \
                 folds nothing",
                self.base_target.as_deref().unwrap_or("this base")
            ),
            GraphSectionStanding::Folding => {
                let cause = match self.refusal.as_deref() {
                    Some("absent") | None => "absent".to_string(),
                    Some(refusal) => format!("present but refused ({refusal})"),
                };
                let tail = if self.section_present {
                    ". A section was written and is not being used: a commit moves the workspace \
                     base and no publish refreshes the section, so `kin graph materialize` is what \
                     brings it back"
                } else {
                    ". `kin graph materialize` writes one"
                };
                format!(
                    "{cause}, so every open of this store folds this workspace's base out of \
                     history, {}{tail}",
                    self.fold.phrase()
                )
            }
            GraphSectionStanding::Unborn => "this workspace names no base target, so an open \
                                             resolves an empty graph and there is nothing to fold \
                                             or to memoize"
                .to_string(),
            GraphSectionStanding::Unknown => format!(
                "could not be read ({}), so whether an open of this store folds its history is \
                 unknown rather than fine",
                self.unreadable.as_deref().unwrap_or("no reason recorded")
            ),
        }
    }

    fn preempt_clause(&self) -> String {
        if self.prepared_may_preempt {
            ". This workspace carries a semantic overlay, so a durable prepared artifact may \
             answer an open before the section is consulted"
                .to_string()
        } else {
            String::new()
        }
    }
}

/// Read the section state of one workspace off an already-open authority.
///
/// Costs no decode and no IO. Every field comes from the envelope this open
/// already holds: the section rides at snapshot field 36 and the change count
/// comes from the change map's own header, which `ChangeMap::len` reads without
/// touching the entries.
///
/// The one exception is the exact fold count, and it is gated on the map
/// already being decoded precisely so that asking this question can never be
/// what pays for the answer. On a daemon this is called after the workspace
/// snapshot phase, where a store that folded has decoded the map as a side
/// effect of folding, so the exact count is free exactly where it is wanted.
///
/// Infallible on purpose. This is a reporting surface, and a status command that
/// failed because it could not describe an acceleration would be a worse
/// outcome than the invisibility it replaces. Every failure lands in
/// [`GraphSectionStanding::Unknown`] with its reason.
pub fn read(authority: &RepositoryAuthorityState, workspace_id: &WorkspaceId) -> GraphSectionState {
    let Some(workspace) = authority
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| &workspace.workspace_id == workspace_id)
    else {
        let mut state = GraphSectionState::new(GraphSectionStanding::Unknown);
        state.unreadable = Some(format!("this authority holds no workspace {workspace_id}"));
        return state;
    };

    let snapshot = authority.snapshot();
    let section = snapshot.materialized_graph.as_ref();
    let changes_in_store = snapshot.changes.len() as u64;

    let Some(base_target) = workspace.base_target.as_ref() else {
        let mut state = GraphSectionState::new(GraphSectionStanding::Unborn);
        state.section_present = section.is_some();
        state.section_resolved_at = section.map(|section| section.resolved_at.to_string());
        state.changes_in_store = changes_in_store;
        state.prepared_may_preempt = !workspace.semantic_overlay.is_empty();
        return state;
    };

    // kin-db's own resolution, through kin-db's own two calls, because the
    // section is checked against the change this produces and a base resolved
    // any other way would be checking a different question.
    let resolved = match base_target {
        kin_model::RefTarget::Symbolic { target } => match authority.resolve_ref_target(target) {
            Ok(Some(resolved)) => Ok(resolved),
            Ok(None) => Err(format!("symbolic repository ref '{target}' is absent")),
            Err(error) => Err(error.to_string()),
        },
        target => Ok(target.clone()),
    };
    let base_change = match resolved.and_then(|target| {
        authority
            .resolve_target_change_id(&target)
            .map_err(|error| error.to_string())
    }) {
        Ok(change_id) => change_id,
        Err(reason) => {
            let mut state = GraphSectionState::new(GraphSectionStanding::Unknown);
            state.section_present = section.is_some();
            state.section_resolved_at = section.map(|section| section.resolved_at.to_string());
            state.changes_in_store = changes_in_store;
            state.prepared_may_preempt = !workspace.semantic_overlay.is_empty();
            state.unreadable = Some(format!(
                "this workspace's base target does not resolve to a change: {reason}"
            ));
            return state;
        }
    };

    let refusal = match section {
        Some(section) => section.validate_for(&base_change).err(),
        None => Some(MaterializedGraphRefusal::Absent),
    };

    let mut state = GraphSectionState::new(match refusal {
        Some(_) => GraphSectionStanding::Folding,
        None => GraphSectionStanding::Serving,
    });
    state.section_present = section.is_some();
    state.refusal = refusal.map(|refusal| refusal.to_string());
    state.base_target = Some(base_change.to_string());
    state.section_resolved_at = section.map(|section| section.resolved_at.to_string());
    state.changes_in_store = changes_in_store;
    state.prepared_may_preempt = !workspace.semantic_overlay.is_empty();
    state.fold = match state.standing {
        GraphSectionStanding::Folding => fold_size(snapshot, &base_change, changes_in_store),
        _ => FoldSize::Nothing,
    };
    state
}

/// The size of the fold at `base_change`, exactly when that is free.
///
/// Mirrors `kin_model::graph`'s own `collect_changes_first_parent`, which is
/// what `resolve_graph_at` walks: start at the head and follow `parents.first()`
/// until there is none. That helper is private to kin-model and takes a
/// `ChangeStore` whose `get_change` clones every change it returns, which on a
/// converted store is the whole history copied to count it. This walk reads the
/// same chain by reference and copies nothing.
///
/// Any surprise on the walk (a parent the map does not hold, or a chain longer
/// than the map, which would mean a cycle) reports the upper bound rather than a
/// number. kin-model refuses both cases outright, so a store reaching them
/// cannot open at all, and guessing a count for a store that will not open is
/// not worth a wrong number.
fn fold_size(
    snapshot: &kin_db::GraphSnapshot,
    base_change: &kin_model::SemanticChangeId,
    changes_in_store: u64,
) -> FoldSize {
    if !snapshot.changes.is_decoded() {
        return FoldSize::AtMost(changes_in_store);
    }
    let mut walked = 0u64;
    let mut current = Some(*base_change);
    while let Some(change_id) = current {
        let Some(change) = snapshot.changes.get(&change_id) else {
            return FoldSize::AtMost(changes_in_store);
        };
        walked += 1;
        if walked > changes_in_store {
            return FoldSize::AtMost(changes_in_store);
        }
        current = change.parents.first().copied();
    }
    FoldSize::Exact(walked)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folding(refusal: &str, section_present: bool, fold: FoldSize) -> GraphSectionState {
        let mut state = GraphSectionState::new(GraphSectionStanding::Folding);
        state.section_present = section_present;
        state.refusal = Some(refusal.to_string());
        state.base_target = Some("2b".repeat(32));
        state.changes_in_store = 3005;
        state.fold = fold;
        state
    }

    fn serving() -> GraphSectionState {
        let mut state = GraphSectionState::new(GraphSectionStanding::Serving);
        state.section_present = true;
        state.base_target = Some("2b".repeat(32));
        state.section_resolved_at = Some("2b".repeat(32));
        state.changes_in_store = 3005;
        state
    }

    /// The whole point of the row. Two stores that behave completely differently
    /// on every open rendered identically on every kin surface before this,
    /// which is why a 47 second fold went unnoticed for three weeks.
    #[test]
    fn a_store_that_folds_and_a_store_that_does_not_never_render_the_same() {
        let folds = folding("absent", false, FoldSize::Exact(3005)).status_line();
        let serves = serving().status_line();
        assert_ne!(folds, serves);
        assert!(
            folds.contains("folds"),
            "a folding store must say so: {folds}"
        );
        assert!(
            folds.contains("3005"),
            "a folding store must name its fold size: {folds}"
        );
        assert!(
            !serves.contains("folds this workspace's base out of history"),
            "a served base must not claim a fold: {serves}"
        );
        assert!(
            serves.contains("folds nothing"),
            "a served base must say the fold did not run: {serves}"
        );
    }

    /// An upper bound read as a measurement is a number a reader cannot
    /// calibrate, and the two are one word apart on the screen.
    #[test]
    fn an_upper_bound_never_reads_as_a_count() {
        let bounded = folding("absent", false, FoldSize::AtMost(3005)).status_line();
        let exact = folding("absent", false, FoldSize::Exact(3005)).status_line();
        assert!(
            bounded.contains("at most"),
            "an upper bound must say so: {bounded}"
        );
        assert!(
            !exact.contains("at most"),
            "a walked chain must not be hedged: {exact}"
        );
        assert_eq!(FoldSize::AtMost(3005).bound(), "at_most");
        assert_eq!(FoldSize::Exact(3005).bound(), "exact");
        assert_eq!(FoldSize::Nothing.bound(), "none");
        assert!(!FoldSize::AtMost(3005).is_exact());
        assert!(FoldSize::Exact(3005).is_exact());
    }

    /// A refused section and an absent one are different operator problems, and
    /// the refused one carries kin-db's own word so a reader can match this
    /// against the warning in `.kin/daemon.log` rather than guess at a
    /// paraphrase.
    #[test]
    fn a_refused_section_is_reported_as_written_and_unused() {
        // Taken from kin-db rather than written here. This test used to assert
        // the literal "target", which is the VARIANT's name and not the word
        // kin-db prints: `MaterializedGraphRefusal::Target` displays as
        // "resolved_at". So the assertion held against a fixture nobody in the
        // product produces, and the claim it exists to defend, that this line
        // carries kin-db's own vocabulary, was never checked. Reading the word
        // off the type is what makes it checked, and it goes red if kin-db ever
        // renames it.
        let word = MaterializedGraphRefusal::Target.to_string();
        assert_eq!(
            word, "resolved_at",
            "kin-db renamed its target refusal; this line's vocabulary follows it"
        );
        let refused = folding(&word, true, FoldSize::Exact(3005)).status_line();
        let absent = folding("absent", false, FoldSize::Exact(3005)).status_line();
        assert!(
            refused.contains(&word),
            "the refusal keeps kin-db's own word: {refused}"
        );
        assert!(
            !refused.contains("Target"),
            "the variant's name is not the word kin-db prints: {refused}"
        );
        assert!(
            refused.contains("is not being used"),
            "a written section going unused must say so: {refused}"
        );
        assert!(
            !absent.contains("is not being used"),
            "a store that never had a section has nothing going unused: {absent}"
        );
        assert_ne!(refused, absent);
    }

    /// Absent and unreadable are different answers, and neither may present as
    /// the other. A row that renders an unread store as a fine one reintroduces
    /// exactly the invisibility this module replaces.
    #[test]
    fn a_state_that_could_not_be_read_is_never_rendered_as_a_healthy_one() {
        let mut state = GraphSectionState::new(GraphSectionStanding::Unknown);
        state.unreadable = Some("this authority holds no workspace 0".to_string());
        let line = state.status_line();
        assert!(line.contains("could not be read"), "{line}");
        assert!(line.contains("holds no workspace 0"), "{line}");
        assert!(
            !line.contains("folds nothing"),
            "an unread store must not read as a served one: {line}"
        );
        assert!(!state.folds());
        assert_eq!(state.arm(), "unknown");
    }

    #[test]
    fn an_unborn_workspace_claims_neither_a_fold_nor_a_section() {
        let state = GraphSectionState::new(GraphSectionStanding::Unborn);
        let line = state.status_line();
        assert!(line.contains("no base target"), "{line}");
        assert!(!state.folds());
        assert_eq!(state.arm(), "unborn");
        assert_eq!(state.fold, FoldSize::Nothing);
    }

    /// A prepared serve answers before the section is consulted, so a line
    /// claiming a fold on an open that never folded would be the same class of
    /// wrong this module exists to fix.
    #[test]
    fn a_workspace_with_an_overlay_says_a_prepared_artifact_may_answer_first() {
        let mut state = folding("absent", false, FoldSize::Exact(3005));
        state.prepared_may_preempt = true;
        let line = state.status_line();
        assert!(line.contains("prepared artifact"), "{line}");
        assert!(
            !folding("absent", false, FoldSize::Exact(3005))
                .status_line()
                .contains("prepared artifact"),
            "a clean workspace must not carry the clause"
        );
    }

    #[test]
    fn the_record_round_trips_through_its_own_schema() {
        for state in [
            serving(),
            folding("absent", false, FoldSize::AtMost(3005)),
            folding("target", true, FoldSize::Exact(12)),
            GraphSectionState::new(GraphSectionStanding::Unborn),
            GraphSectionState::new(GraphSectionStanding::Unknown),
        ] {
            let json = serde_json::to_value(&state).unwrap();
            assert_eq!(json["schema"], GRAPH_SECTION_STATE_SCHEMA);
            let round_trip: GraphSectionState = serde_json::from_value(json).unwrap();
            assert_eq!(round_trip, state);
        }
    }

    /// The falsifiable pair, over a real store's own bytes.
    ///
    /// One repository admitted through the exact admission boundary, read twice:
    /// before it has a section and after `materialize_workspace_base_graph_section`
    /// writes one. Nothing else about the store changes between the two reads,
    /// so a detection that answered the same both times, or answered from
    /// anything other than the section, fails here.
    ///
    /// Falsified by inverting the predicate in [`read`]: with `refusal` forced to
    /// `None` this test fails on the first assertion, and with it forced to
    /// `Some` it fails after materialization. Neither arm passes on its own.
    #[test]
    fn a_store_reads_as_folding_until_it_is_materialized_and_as_serving_after() {
        let directory = tempfile::tempdir().unwrap();
        let working = directory.path().join("repo");
        std::fs::create_dir_all(working.join("src")).unwrap();
        let git = |args: &[&str]| {
            let output = kin_git::test_support::fixture_git_in(&working)
                .args(args)
                .output()
                .unwrap();
            assert!(output.status.success(), "git {args:?}: {output:?}");
        };
        git(&["init", "--initial-branch=main"]);
        git(&["config", "user.email", "kin@example.invalid"]);
        git(&["config", "user.name", "Kin"]);
        std::fs::write(
            working.join("src/lib.rs"),
            b"pub fn one() -> u8 {\n    1\n}\n",
        )
        .unwrap();
        git(&["add", "--all"]);
        git(&["commit", "-m", "one function"]);

        let admitted = crate::init_from_git(&working).unwrap();
        let binding =
            crate::LocalRepositoryAuthorityBinding::from_layout(&admitted.layout).unwrap();
        let workspace_id = binding.workspace_id();

        let folding = {
            let manager = binding.open_manager().unwrap();
            let lease = manager.read_authority();
            read(&lease, &workspace_id)
        };
        assert_eq!(
            folding.standing,
            GraphSectionStanding::Folding,
            "admission writes no section, so this store folds: {folding:?}"
        );
        assert!(!folding.section_present, "{folding:?}");
        assert_eq!(folding.refusal.as_deref(), Some("absent"), "{folding:?}");
        assert!(
            folding.base_target.is_some(),
            "a committed workspace has a base target, or this case is the unborn one \
             rather than the folding one: {folding:?}"
        );
        assert!(
            folding.fold.changes() > 0,
            "a fold over a committed history walks at least one change: {folding:?}"
        );
        assert!(folding.folds());

        {
            let manager = binding.open_manager().unwrap();
            manager
                .materialize_workspace_base_graph_section(binding.repository_id(), &workspace_id)
                .unwrap()
                .expect("the workspace exists");
        }

        let serving = {
            let manager = binding.open_manager().unwrap();
            let lease = manager.read_authority();
            read(&lease, &workspace_id)
        };
        assert_eq!(
            serving.standing,
            GraphSectionStanding::Serving,
            "a materialized section answers for this base: {serving:?}"
        );
        assert!(serving.section_present, "{serving:?}");
        assert_eq!(serving.refusal, None, "{serving:?}");
        assert_eq!(serving.fold, FoldSize::Nothing, "{serving:?}");
        assert!(!serving.folds());
        assert_eq!(
            serving.section_resolved_at, serving.base_target,
            "a serving section resolves at exactly this base: {serving:?}"
        );
        assert_eq!(
            serving.changes_in_store, folding.changes_in_store,
            "materialization is a representation rewrite and adds no history"
        );

        // The prepared-preempt flag, against a real `WorkspaceState` rather
        // than a hand-built one. A freshly admitted workspace is clean, so
        // `prepared_workspace_state_pays_for_itself` is false for it and no
        // durable artifact can answer ahead of the section. This is the arm
        // that must not fire; the arm that does fire needs a dirty workspace
        // and a daemon, which is why the daemon OBSERVES that arm through
        // kin-db's own serve counter instead of predicting it.
        for state in [&folding, &serving] {
            assert!(
                !state.prepared_may_preempt,
                "an admitted workspace carries no semantic overlay, so nothing \
                 preempts the section question: {state:?}"
            );
            assert!(
                !state.status_line().contains("prepared artifact"),
                "and the clause must not render for it: {}",
                state.status_line()
            );
        }
    }
}

/// FIR-3064: the decode-versus-fold split of a cold open's largest phase.
///
/// kin-db ships its own open-cost harness behind `KIN_FIR3064_STORE`
/// (`storage/repository.rs`, `fir3064_open_cost::measure_what_an_open_retains`),
/// and it reports the terms an open retains but not this split: it prints
/// `changes.len()`, which `ChangeMap::len` answers from the map's header without
/// decoding, so the decode is still inside its `workspace_graph_snapshot` term
/// rather than beside it. This harness separates the two by forcing the decode
/// first, through kin-db's own public `ChangeMap::decoded`, and then timing the
/// fold over a map already in memory.
///
/// Both modes run so the split can be checked rather than believed. `combined`
/// leaves the map encoded and times the phase exactly as a daemon open does;
/// `split` forces the decode and times the two halves. If `decode + fold` does
/// not reconcile with `combined`, the split is measuring something other than
/// what it names, and the reconciliation is the falsification.
///
/// Ignored by default and gated on an env var naming a store, so the ordinary
/// suite never opens a multi-gigabyte repository.
#[cfg(test)]
mod fir3064_decode_versus_fold {
    /// Resident set of this process in KiB, from `ps`, so the number is the one
    /// an operator reads rather than an allocator's own accounting. Same
    /// instrument kin-db's harness uses, so the two are comparable.
    fn resident_kb() -> i64 {
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .expect("ps runs");
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .expect("ps prints the resident set as a number")
    }

    fn report(label: &str, started: std::time::Instant, previous_kb: i64) -> i64 {
        let now_kb = resident_kb();
        println!(
            "[TERM] {label}_ms={} rss_kb={now_kb} delta_kb={}",
            started.elapsed().as_millis(),
            now_kb - previous_kb
        );
        now_kb
    }

    #[test]
    #[ignore = "needs KIN_FOLD_SPLIT_REPO naming a real repository root"]
    fn measure_the_decode_and_the_fold() {
        let root = std::env::var("KIN_FOLD_SPLIT_REPO")
            .expect("set KIN_FOLD_SPLIT_REPO to a repository root holding a .kin directory");
        let mode = std::env::var("KIN_FOLD_SPLIT_MODE").unwrap_or_else(|_| "split".to_string());
        assert!(
            mode == "split" || mode == "combined",
            "KIN_FOLD_SPLIT_MODE must be split or combined, not {mode}"
        );
        let layout = crate::KinLayout::discover(std::path::Path::new(&root))
            .expect("KIN_FOLD_SPLIT_REPO holds a .kin directory");
        let binding = crate::LocalRepositoryAuthorityBinding::from_layout(&layout)
            .expect("bind repository authority");
        let workspace_id = binding.workspace_id();

        let baseline_kb = resident_kb();
        println!("[TERM] baseline rss_kb={baseline_kb} mode={mode}");

        let started = std::time::Instant::now();
        let manager = binding.open_manager().expect("open repository authority");
        let after_open_kb = report("authority_open", started, baseline_kb);

        let lease = manager.read_authority();
        let snapshot = lease.snapshot();
        println!(
            "[store] changes={} entities={} relations={} entity_revisions={} \
             section_present={} change_map_decoded={}",
            snapshot.changes.len(),
            snapshot.entities.len(),
            snapshot.relations.len(),
            snapshot.entity_revisions.len(),
            snapshot.materialized_graph.is_some(),
            snapshot.changes.is_decoded()
        );

        let after_decode_kb = if mode == "split" {
            let started = std::time::Instant::now();
            let decoded = snapshot.changes.decoded().expect("decode the change map");
            let decoded_len = decoded.len();
            let after = report("change_map_decode", started, after_open_kb);
            println!("[decode] decoded_changes={decoded_len}");
            after
        } else {
            after_open_kb
        };

        let started = std::time::Instant::now();
        let workspace_snapshot = lease
            .workspace_graph_snapshot(&workspace_id)
            .expect("materialize the workspace graph")
            .expect("the workspace exists");
        let label = if mode == "split" {
            "base_fold_only"
        } else {
            "workspace_snapshot_combined"
        };
        let after_workspace_kb = report(label, started, after_decode_kb);
        println!(
            "[workspace] entities={} relations={} entity_revisions={} \
             authority_change_map_decoded={}",
            workspace_snapshot.entities.len(),
            workspace_snapshot.relations.len(),
            workspace_snapshot.entity_revisions.len(),
            snapshot.changes.is_decoded(),
        );

        let state = super::read(&lease, &workspace_id);
        println!(
            "[section] arm={} section_present={} refusal={} fold={} bound={} changes_in_store={}",
            state.arm(),
            state.section_present,
            state.refusal.as_deref().unwrap_or("none"),
            state.fold.changes(),
            state.fold.bound(),
            state.changes_in_store,
        );
        println!("[section] status_line={}", state.status_line());

        let started = std::time::Instant::now();
        drop(workspace_snapshot);
        drop(lease);
        drop(manager);
        report("after_drop", started, after_workspace_kb);
    }
}
