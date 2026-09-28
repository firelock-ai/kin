// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Whether a caller could have arrived at the focal through a call the linker
//! never recorded (FIR-2775).
//!
//! `find_references` answers from the `Calls` edges the graph holds. That is the
//! whole answer only when every call site the parser read in the files that can
//! reach the focal became an edge. Where it did not, the missing edges are
//! invisible to the query, so an empty answer and a genuinely uncalled function
//! produce the identical response, and the envelope stamps the first one
//! `certified` / `safe_to_conclude_absent: true`.
//!
//! That is not hypothetical. On the v0.6.0 stranger run a Python package under
//! `src/` called `storage.note_body(db, note.id)` from a test that reached the
//! module through `from notekeeper import storage`. The parser read the call.
//! The linker declined to bind it, because binding a member whose leaf name the
//! repository already defines would be a guess rather than a resolution. Nothing
//! recorded the decline, so `find_references("note_body")` reported no incoming
//! relations of any kind and certified that absence as authoritative. A
//! dead-code sweep run on the envelope's word would have deleted a live
//! function.
//!
//! ## What this measures, and what it deliberately does not
//!
//! Two numbers per file, both already graph-owned:
//!
//! - how many call sites the parser read there
//!   ([`kin_parser::FILE_PARSED_CALL_SITES_KEY`], stamped on every entity of the
//!   file at extraction). An adapter that censuses its call sites publishes that
//!   census, which counts every site the file holds rather than only the ones
//!   extraction could represent, so the count is present whatever extraction
//!   managed; Python does this since kin#1206. An adapter with no census still
//!   publishes the representable count when extraction was complete and
//!   withholds it otherwise, so an absent count remains possible and remains its
//!   own kind of gap,
//! - how many `Calls` edges the graph holds whose source is one of that file's
//!   entities.
//!
//! A file whose parse side exceeds its edge side holds calls that reached no
//! destination. When this was written the linker minted an unresolved-receiver
//! placeholder for a call it could not settle, which IS a `Calls` edge, so an
//! ordinary call into a third-party package stayed out of the shortfall. That
//! tier was removed in kin#1186, so the shortfall now also carries every call
//! into a package this repository does not hold, and a file that calls its
//! standard library reads as a gap on that alone. Measured on the v0.6.1
//! stranger corpus: `notekeeper/cli.py` parses 57 call sites and the graph
//! holds 12 edges from its entities.
//!
//! So the shortfall is a CEILING on the ambiguity rather than a measure of it,
//! and this reading is deliberately the conservative side of that: it refuses
//! to certify where it cannot separate the two, and it never certifies on a
//! count it did not take. Narrowing it wants a parse-side count that excludes
//! calls through a receiver bound outside the repository, which the extractor
//! cannot produce because externality is a linker fact; that is tracked
//! separately and is not this module's to assume.
//!
//! ## Why it is scoped to a family rather than to the store
//!
//! Flooring every absence on store-wide health is the substitution this module
//! exists to avoid, in the other direction: an envelope that never certifies
//! teaches a caller to ignore it, and the ticket that filed this is explicit
//! that a genuinely uncalled function reached through a resolved shape must
//! still read as an authoritative absence. So the reading is taken over the
//! files that can actually reach the focal: those holding an `Imports` or
//! `Includes` edge into an entity of the focal's own file. A shortfall in an
//! unrelated corner of the repository says nothing about this focal and is not
//! reported as if it did.
//!
//! The family is established from import edges rather than from the focal's own
//! call edges, and that split is the point: import resolution and call
//! resolution are separate tiers, and this gate exists precisely for the case
//! where the second one failed while the first one held. Where the language
//! holds no import edges at all, the family cannot be established and the state
//! is `unmeasured` rather than empty, because "nobody imports this file" and "I
//! cannot see who imports anything" are opposite facts and only the first is
//! evidence about the focal.

use std::collections::HashSet;

use kin_model::graph::{EntityFilter, GraphStore};
use kin_model::{entity::Entity, EntityId, FilePathId, RelationKind};
use serde::Serialize;
use serde_json::json;

/// Key under which `find_references` publishes this reading.
pub const CALLER_ARRIVAL_KEY: &str = "caller_arrival";

/// Limiting-factor id the negative envelope reports when arrival is incomplete.
/// Spelled once so the gate, the advice and any test key on one string.
pub const UNRESOLVED_ARRIVAL_LIMITING_FACTOR: &str = "caller_arrival_unresolved";

/// Limiting-factor id for a family that could not be established at all.
pub const UNMEASURED_ARRIVAL_LIMITING_FACTOR: &str = "caller_arrival_unmeasured";

/// The phrase every spanless-edge refusal carries, and no other refusal does.
///
/// `ArrivalState::Unmeasured` has several producers: a language that links no
/// imports, a family above the cap, an index that could not be read, and this
/// one. A reader keying on the state alone cannot tell them apart, and a reason
/// shared between two causes is the exact join hazard this module tests
/// elsewhere, so the spanless condition owns a string nothing else uses and a
/// test pins that it is unique among the reasons this module can produce.
pub const NO_CALL_SITE_SPAN_REASON: &str =
    "holds call edges the graph records no call-site span for";

/// Importing files examined before the reading declines.
///
/// Each costs one entity query plus one relation read per entity of that file.
/// A hub imported by more files than this gets an honest `unmeasured` rather
/// than a verdict drawn from a truncated set, because truncating and reporting
/// `accounted` is the silent cap this module exists to refuse.
const FAMILY_FILE_CAP: usize = 200;

/// Evidence rows the published block carries, at most.
///
/// The verdict rests on `unaccounted_file_count`, which is never truncated. These
/// rows are what a reader audits it with, and they are capped because this block
/// must not become the reason the answer gets evicted from the response budget.
/// The block says when it truncated, so a short list is never read as a whole one.
const EVIDENCE_ROW_CAP: usize = 10;

/// What this reading counts and what it cannot see, published as the block's
/// `scope` and recited by a verdict that certifies over it.
///
/// Both limits follow from how the reading is built, and an absence certified
/// on it inherits both, so they are stated rather than left for a reader to
/// derive. A call site counts as arrived when the graph holds any `Calls` edge
/// from it, wherever that edge lands, so a call the linker bound to a
/// same-named definition in the caller's own file counts even when the source
/// meant the focal. And the family is the files holding an import edge into the
/// focal's file, so a caller that reaches the focal with no such edge, a
/// same-package caller in a language that needs no import for one, is never
/// read.
pub const ARRIVAL_READING_SCOPE: &str = "this reading counts a call site as arrived when the \
     graph holds any call edge from it, including a call the linker bound to a same-named \
     definition in the caller's own file, and it reads only the files that hold an import edge \
     into the focal's file, so a caller that reaches the focal without one is not read";

/// How completely this reading could account for the ways a caller reaches the
/// focal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrivalState {
    /// Every file that IMPORTS the focal's file had every call site it parsed
    /// become an edge.
    ///
    /// Narrower than "nothing could have called the focal without an edge", and
    /// the difference is load-bearing rather than pedantic. The family is built
    /// from files that name the focal's file from OUTSIDE it, so the focal's own
    /// file is excluded by construction and a call from beside the focal that
    /// the linker dropped is invisible to this arithmetic. A surface whose
    /// answer is a delete list has to account for the focal's own file too, and
    /// that is [`absence_gap`]'s job rather than this state's.
    Accounted,
    /// At least one file that can reach the focal holds call sites that became
    /// no edge, so a caller of the focal may be among them.
    Unaccounted,
    /// The reading could not be taken. Not the same as `Accounted`, and never
    /// collapsed into it.
    Unmeasured,
}

impl ArrivalState {
    pub fn wire(self) -> &'static str {
        match self {
            Self::Accounted => "accounted",
            Self::Unaccounted => "unaccounted",
            Self::Unmeasured => "unmeasured",
        }
    }

    /// Whether this state licenses reading an empty reference list as the whole
    /// truth about the focal. Only a complete accounting does.
    pub fn certifies_absence(self) -> bool {
        matches!(self, Self::Accounted)
    }
}

/// One family file whose call sites did not all become edges.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UnaccountedFile {
    pub file: String,
    /// `None` when the file carries no parse-side count. An adapter that
    /// censuses its call sites always publishes one, which Python does since
    /// kin#1206; one that does not withholds the key on any file whose call
    /// extraction it could not represent. Absent, not zero, and it is its own
    /// kind of gap.
    pub parsed_call_sites: Option<u64>,
    pub resolved_call_edges: u64,
    /// `parsed - resolved`, floored at zero. `None` when the parse side was not
    /// measured.
    pub unaccounted_call_sites: Option<u64>,
    /// Whether the number above is a FLOOR rather than an exact count.
    ///
    /// True when the file holds `Calls` edges the graph records no call site
    /// for, so the resolved side is a range and only its worst case can be
    /// asserted. The distinction is published rather than smoothed over,
    /// because "at least two sites became no edge" and "exactly two did" are
    /// different claims and a reader acting on a delete list is entitled to
    /// know which one this is.
    #[serde(default)]
    pub shortfall_is_floor: bool,
    /// How the row was counted.
    pub count_source: CountSource,
    /// Whether `unaccounted_call_sites` is exact. True only for a row counted
    /// from site ledgers, where it is the sites no resolver settled. A count
    /// from parse against edges is a ceiling on the ambiguity at best, because
    /// a call into a package the repository does not hold becomes no edge too.
    pub count_exact: bool,
    /// For a row counted from site ledgers, its unsettled sites by the state
    /// each reads as.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub unsettled_by_state: std::collections::BTreeMap<&'static str, u64>,
    /// Callers in the file that no current ledger describes, which is why a
    /// row counted from parse against edges was not counted from ledgers.
    pub owed_callers: u64,
    /// For a row counted from site ledgers, the unsettled sites left out
    /// because they cannot be a call to the focal: their callee is another
    /// name and the focal does not escape as a value. They are counted in
    /// `resolved_call_edges` with the settled ones, as sites accounted for.
    #[serde(skip_serializing_if = "is_zero")]
    pub ruled_out_by_name: u64,
}

fn is_zero(count: &u64) -> bool {
    *count == 0
}

/// How a family file's call sites were counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CountSource {
    /// Every caller in the file held a current call-site ledger, so each site
    /// was read as the state its ledger records.
    SiteLedgers,
    /// Some caller held none, so the file's parse-side call count was set
    /// against the call edges its entities hold.
    #[default]
    ParseVersusEdges,
}

/// A caller in the focal's family that no current ledger describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwedCaller {
    /// The caller's entity id.
    pub id: String,
    pub name: String,
    pub file: String,
    /// What stands between the reading and its ledger: `owed_enrichment`,
    /// `owed_derivation` or `proof_context_stale`.
    pub reading: &'static str,
}

/// The reading itself.
#[derive(Debug, Clone)]
pub struct CallerArrival {
    pub state: ArrivalState,
    /// Files holding an import edge into the focal's file.
    pub family_files: usize,
    /// Of those, how many carry a parse-side call count.
    pub family_measured: usize,
    pub unaccounted: Vec<UnaccountedFile>,
    /// Why the state is `unmeasured`, when it is.
    pub unmeasured_reason: Option<String>,
    /// Of the family files, how many were counted from site ledgers.
    pub files_from_site_ledgers: usize,
    /// Callers in the family that no current ledger describes.
    pub owed_callers: Vec<OwedCaller>,
    /// Every caller in the family, read through the one site-state reading,
    /// or `None` when the family could not be established.
    pub call_sites: Option<kin_model::CallSiteTally>,
    /// Owed callers of the focal's language outside the family and the
    /// focal's own file, or `None` when the entity index could not be read.
    /// A caller can reach the focal without importing its file, so these
    /// qualify a settled family: see [`crate::call_sites::owed_outside`].
    pub owed_outside: Option<Vec<crate::call_sites::OwedFile>>,
    /// Of the family's owed callers, how many `call_sites` leaves out because
    /// their whole body never spells the name a call to the focal uses. They
    /// stay in `owed_callers`, and their files keep the parse-against-edge
    /// count, which still holds every call they make to account.
    pub owed_callers_cannot_name_focal: u64,
    /// The store-wide reading of every caller that could call the focal, when
    /// the answer took one. It narrows the family's ledger counts to the sites
    /// that could call the focal, and its block, with a row for each such
    /// site, is the `call_sites` block the answer serves.
    pub scan: Option<std::sync::Arc<crate::call_sites::FocalScan>>,
}

impl CallerArrival {
    fn unmeasured(reason: impl Into<String>) -> Self {
        Self {
            state: ArrivalState::Unmeasured,
            family_files: 0,
            family_measured: 0,
            unaccounted: Vec::new(),
            unmeasured_reason: Some(reason.into()),
            files_from_site_ledgers: 0,
            owed_callers: Vec::new(),
            call_sites: None,
            owed_outside: Some(Vec::new()),
            owed_callers_cannot_name_focal: 0,
            scan: None,
        }
    }

    /// The `call_sites` block `find_references` and `kin refs` both serve.
    ///
    /// With a store-wide reading, it is that reading's block: every caller in
    /// the store that could call the focal, narrowed to the sites that could,
    /// with a row for each unsettled one (see [`crate::call_sites::named_block`]).
    /// Without one, it is the block for the callers in the files that import
    /// the focal's file, qualified by the owed callers outside them, or `None`
    /// when the family could not be established.
    pub fn call_sites_block(&self) -> Option<serde_json::Value> {
        if let Some(scan) = self.scan.as_deref() {
            return Some(crate::call_sites::named_block(scan));
        }
        let tally = self.call_sites.as_ref()?;
        let mut block = crate::call_sites::family_block(tally, self.owed_outside.as_deref());
        if self.owed_callers_cannot_name_focal > 0 {
            block["owed_callers_cannot_name_focal"] = json!(self.owed_callers_cannot_name_focal);
        }
        Some(block)
    }

    /// The block `find_references` publishes, and the one the negative envelope
    /// reads back. Published on every answer, populated or empty, so a reader
    /// never has to tell "checked and fine" from "not reported".
    pub fn to_json(&self) -> serde_json::Value {
        let mut block = self.fields_json();
        block["scope"] = json!(ARRIVAL_READING_SCOPE);
        block
    }

    /// The reading's own fields, without the `scope` every block states once.
    /// An impact answer carries one of these per entity and its scope beside
    /// them, so the sentence is not repeated on every row.
    fn fields_json(&self) -> serde_json::Value {
        let mut block = json!({
            "state": self.state.wire(),
            "family_files": self.family_files,
            "family_measured": self.family_measured,
            // How many family files hold unaccounted calls, beside the rows.
            // The count is the fact the verdict rests on and it is never
            // truncated; the rows below are evidence a reader can audit it with,
            // and those are capped.
            "unaccounted_file_count": self.unaccounted.len(),
            // Capped, and the cap is named rather than silent. The one response
            // shape this module adds must not become the reason the answer gets
            // evicted: a `find_references` returning two rows already carried
            // close to eight kilobytes of envelope on the run that filed this,
            // and a hub with two hundred importers would put two hundred more
            // objects in front of the references a caller asked for.
            "unaccounted_files": self
                .unaccounted
                .iter()
                .take(EVIDENCE_ROW_CAP)
                .collect::<Vec<_>>(),
            "unaccounted_files_truncated": self.unaccounted.len() > EVIDENCE_ROW_CAP,
            "unmeasured_reason": self.unmeasured_reason,
            // Whether every family file was counted from its callers' current
            // site ledgers, which makes `unaccounted_file_count` and every
            // row's `unaccounted_call_sites` exact. A reading that could not
            // be taken is never exact.
            "count_exact": self.state != ArrivalState::Unmeasured
                && self.files_from_site_ledgers == self.family_files,
            "files_counted_from_site_ledgers": self.files_from_site_ledgers,
            // The callers that kept a file on the arithmetic: no current
            // ledger describes them. Counted in full on every answer, and
            // named up to the cap when there are any.
            "owed_caller_count": self.owed_callers.len(),
        });
        if self.owed_callers_cannot_name_focal > 0 {
            block["owed_callers_cannot_name_focal"] = json!(self.owed_callers_cannot_name_focal);
        }
        match &self.owed_outside {
            Some(files) if !files.is_empty() => {
                block["owed_outside_scope"] = json!({
                    "file_count": files.len(),
                    "callers": files.iter().map(|file| file.callers).sum::<u64>(),
                    "files": files.iter().take(EVIDENCE_ROW_CAP).collect::<Vec<_>>(),
                });
            }
            Some(_) => {}
            None => block["owed_outside_scope"] = json!({ "unreadable": true }),
        }
        if !self.owed_callers.is_empty() {
            block["owed_callers"] = json!(self
                .owed_callers
                .iter()
                .take(EVIDENCE_ROW_CAP)
                .collect::<Vec<_>>());
            block["owed_callers_truncated"] = json!(self.owed_callers.len() > EVIDENCE_ROW_CAP);
        }
        block
    }

    /// The one sentence the verdict prints when this reading limits the answer,
    /// or `None` when it does not.
    pub fn limiting_factor(&self) -> Option<String> {
        match self.state {
            ArrivalState::Accounted => None,
            ArrivalState::Unmeasured => Some(format!(
                "{UNMEASURED_ARRIVAL_LIMITING_FACTOR}: this answer could not establish which files \
                 can reach the focal ({}), so an empty reference list is not evidence that nothing \
                 calls it",
                self.unmeasured_reason.as_deref().unwrap_or("no reason recorded")
            )),
            ArrivalState::Unaccounted => {
                let named: Vec<String> = self
                    .unaccounted
                    .iter()
                    .take(5)
                    .map(
                        |file| match (file.unaccounted_call_sites, file.count_exact) {
                            (Some(missing), true) => format!(
                                "{} ({missing} of {} call sites are not settled, an exact count \
                             from site ledgers)",
                                file.file,
                                file.parsed_call_sites.unwrap_or(0)
                            ),
                            (Some(missing), false) => format!(
                                "{} ({missing} of {} parsed call sites became no edge)",
                                file.file,
                                file.parsed_call_sites.unwrap_or(0)
                            ),
                            (None, _) => format!(
                                "{} (the store holds no parse-side call count for this file, so \
                             its call sites could not be accounted for)",
                                file.file
                            ),
                        },
                    )
                    .collect();
                // Joined with ", " and never with "; ", which is
                // `crate::verdict::CLAUSE_SEPARATOR`. The rendered limiting
                // factor is one string that a reader splits back into clauses on
                // that separator, so a clause carrying it arrives as a labelled
                // clause plus a bare fragment with no label at all. Two gap texts
                // shipped that defect before; this one would have been the third,
                // and the guard that asserts the invariant drives one producer by
                // name and cannot see a new one.
                let more = self.unaccounted.len().saturating_sub(named.len());
                let tail = if more > 0 {
                    format!(" and {more} more")
                } else {
                    String::new()
                };
                Some(format!(
                    "{UNRESOLVED_ARRIVAL_LIMITING_FACTOR}: {} of {} file(s) that import the \
                     focal's file hold call sites the linker recorded no edge for, so a caller of \
                     this focal may be among them and this list is a floor rather than the whole \
                     set: {}{tail}",
                    self.unaccounted.len(),
                    self.family_files,
                    named.join(", ")
                ))
            }
        }
    }
}

/// Relation classes that put a file in the focal's family: it named the focal's
/// file in its own source, so a call from it could have reached the focal.
const FAMILY_KINDS: [RelationKind; 2] = [RelationKind::Imports, RelationKind::Includes];

/// The second way a file names another one, and the one this reading was blind
/// to until FIR-2821.
///
/// `from . import linkgraph` binds a MODULE, not any name inside it, so it
/// produces no `Imports` edge into any entity of `linkgraph.py`. What it
/// produces is a `References` edge into that file's `Module` entity, one per
/// referencing entity. The family was built from [`FAMILY_KINDS`] alone, so a
/// file reached only this way had an EMPTY family and took the empty-family
/// branch, which certifies. That is the exact shape of the finding: on the
/// v0.6.1 stranger corpus `notekeeper/linkgraph.py` is named by 35 such edges
/// from `cli.py` and `tests/test_linkgraph.py`, and this reading answered
/// `accounted` with `family_files: 0` over it. A gate that certifies the one
/// shape it was added to catch is a check that cannot fail.
///
/// Narrow on purpose: only a reference whose destination is a `Module` entity
/// of the focal's own file counts. A `References` edge into a function or a
/// type is a mention rather than a module binding, and admitting those would
/// put most of the repository in most families.
const MODULE_BINDING_KIND: RelationKind = RelationKind::References;

/// Read the per-file parse-side call count the extractor stamped on every
/// entity of the file. `None` means unmeasured, never zero.
///
/// Whether the key is present depends on the adapter. One that censuses its
/// call sites publishes the census whatever extraction managed, which is what
/// Python does since kin#1206, so the measured branch is the common one there.
/// One with no census publishes the representable count when extraction was
/// complete and withholds the key rather than reporting a number it cannot
/// stand behind, so the uncounted branch is still reachable and is still a gap
/// rather than a zero.
fn parsed_call_sites(entity: &Entity) -> Option<u64> {
    entity
        .metadata
        .extra
        .get(kin_parser::FILE_PARSED_CALL_SITES_KEY)
        .and_then(serde_json::Value::as_u64)
}

/// Entities examined before the language-wide import witness gives up.
///
/// It stops at the first import edge it sees, so on any graph that links imports
/// this costs a handful of reads. The budget bounds the other case, where the
/// answer is that there are none: a completed scan that found nothing and a scan
/// that ran out of budget both mean the same thing here, which is that the
/// control could not witness import linking, and both decline.
const IMPORT_WITNESS_BUDGET: usize = 500;

/// Whether this graph links imports across files at all, for this language.
///
/// The last-resort control for an empty family, and it is reached only when the
/// focal's own file holds no import edge in EITHER direction, which on a real
/// repository is rare. It answers a question about the LANGUAGE and never about
/// the focal's file: a file nothing imports holds no incoming import edge by
/// construction, and reading the control off that alone would make every such
/// file unmeasurable.
///
/// This is the only path here that reads the whole language, and it declines
/// rather than truncating when the language is larger than the walk: a sample
/// that finds no import edge and a store that holds none are the same answer
/// from this function, and only one of them is evidence.
fn language_links_imports<G: GraphStore>(store: &G, language: kin_model::LanguageId) -> bool {
    let Ok(entities) = store.query_entities(&EntityFilter {
        languages: Some(vec![language]),
        ..EntityFilter::default()
    }) else {
        return false;
    };
    for entity in entities.iter().take(IMPORT_WITNESS_BUDGET) {
        let Ok(relations) = store.get_all_relations_for_entity(&entity.id) else {
            continue;
        };
        if relations
            .iter()
            .any(|relation| FAMILY_KINDS.contains(&relation.kind))
        {
            return true;
        }
    }
    false
}

/// Entities of one file, and the parse-side call count the extractor stamped on
/// every one of them. The count is identical across a file's entities, so the
/// first entity carrying it settles the file, and `None` means unmeasured.
fn file_entities<G: GraphStore>(
    store: &G,
    file: &FilePathId,
) -> Option<(Vec<Entity>, Option<u64>)> {
    let entities = store
        .query_entities(&EntityFilter {
            file_path: Some(file.clone()),
            ..EntityFilter::default()
        })
        .ok()?;
    let parsed = entities.iter().find_map(parsed_call_sites);
    Some((entities, parsed))
}

/// What the current ledgers of one file's callers say about its sites.
#[derive(Debug, Default)]
struct LedgerCount {
    /// Call expressions the ledgers hold.
    census: u64,
    /// Of those, the sites a resolver settled.
    settled: u64,
    /// Of those, the unsettled sites that cannot be a call to the focal.
    ruled_out: u64,
    /// The rest, by the state each reads as.
    unsettled: std::collections::BTreeMap<&'static str, u64>,
}

/// Read every entity of one family file through the one site-state reading,
/// adding each to `tally`.
///
/// `Some` when every entity with source text in the file holds a current
/// ledger and at least one does, which makes the file's unsettled sites an
/// exact count. `None` otherwise, with every caller no current ledger
/// describes pushed onto `owed`. A file with no entity holding text is left to
/// the arithmetic, because a count of nothing from ledgers would certify a file
/// whose calls no entity holds.
///
/// An owed or stale caller whose whole body never spells the name a call to
/// the focal uses (`could_name` false) is left out of `tally` and counted in
/// `cannot_name` instead: it cannot call the focal by name, so settling its
/// sites cannot add a caller of the focal. The file's module entity is one of
/// the callers read here, so an import that binds the focal under another
/// name spells it there and keeps the file's owed callers counted. It is still
/// owed, so it is still pushed onto `owed` and keeps the file on the
/// arithmetic.
#[allow(clippy::too_many_arguments)]
fn ledger_count<F: kin_model::CallSiteFacts + ?Sized>(
    facts: &F,
    file: &FilePathId,
    entities: &[Entity],
    could_name: &dyn Fn(&Entity) -> bool,
    could_call: &dyn Fn(&Entity, &kin_model::CallSite) -> bool,
    tally: &mut kin_model::CallSiteTally,
    owed: &mut Vec<OwedCaller>,
    cannot_name: &mut u64,
) -> Option<LedgerCount> {
    use kin_model::CallerSites;
    let mut count = LedgerCount::default();
    let mut ledgered = 0usize;
    let mut owed_here = false;
    for entity in entities {
        let reading = kin_model::read_caller_sites(facts, entity);
        let unsettled_caller = matches!(
            reading,
            CallerSites::OwedDerivation
                | CallerSites::OwedEnrichment
                | CallerSites::Stale(_)
                | CallerSites::Unverified { .. }
        );
        if unsettled_caller && !could_name(entity) {
            *cannot_name += 1;
        } else if let CallerSites::Current(_) = reading {
            tally.add(&reading.retain_sites(|site| {
                kin_model::SiteStateKind::of(&site.state).is_settled() || could_call(entity, site)
            }));
        } else {
            tally.add(&reading);
        }
        match &reading {
            CallerSites::NoSites => {}
            CallerSites::Current(ledger) => {
                ledgered += 1;
                count.census += u64::from(ledger.census);
                for site in &ledger.sites {
                    let kind = reading.site_kind(site);
                    if kind.is_settled() {
                        count.settled += 1;
                    } else if could_call(entity, site) {
                        *count.unsettled.entry(kind.wire()).or_insert(0) += 1;
                    } else {
                        count.ruled_out += 1;
                    }
                }
            }
            CallerSites::OwedDerivation
            | CallerSites::OwedEnrichment
            | CallerSites::NoResolver { .. }
            | CallerSites::Stale(_)
            | CallerSites::Unverified { .. } => {
                owed_here = true;
                owed.push(OwedCaller {
                    id: entity.id.to_string(),
                    name: entity.name.clone(),
                    file: file.0.clone(),
                    reading: reading.wire(),
                });
            }
        }
    }
    (!owed_here && ledgered > 0).then_some(count)
}

/// What one file's resolved side came to, or why it could not be taken.
enum ResolvedSites {
    /// The `Calls` edges from this file's entities, split by whether each could
    /// be joined to a call site.
    Counted {
        /// Distinct call sites the joinable edges came to.
        sites: u64,
        /// Edges carrying no usable span in this file. Each one stands for
        /// somewhere between a share of one site and a site of its own, which
        /// is the whole reason the shortfall becomes an interval.
        spanless: u64,
    },
    /// The relation index could not be read.
    Unreadable,
}

/// What one file's shortfall can be once the spanless edges are accounted for
/// as a RANGE rather than a number.
///
/// With `P` parsed sites, `S` distinct joined sites and `R` spanless edges, the
/// spanless edges stand for at least one site (they all fan out from one) and at
/// most `R` sites (they are all distinct), so writing `Q` for `P - S` floored at
/// zero, the true shortfall lies in `[Q - R, Q - min(R, 1)]` floored at zero.
/// Three branches follow, and they are not the same claim:
///
/// - the top of the range is zero, so nothing went missing whichever way the
///   spanless edges fall, and an absence here is the whole set;
/// - the bottom of the range is above zero, so at least that many parsed sites
///   became no edge whichever way they fall, which is a floor to disclose with
///   its number rather than a certification;
/// - the range straddles zero, so the spanless edges decide the answer and
///   nothing available here can, which is the only branch that declines.
///
/// The middle branch is what keeps this from withholding every verdict on the
/// nine adapters that record no call site: a file that parses more sites than it
/// holds edges of any kind still reports a real shortfall, and a file that
/// parses at most one site still certifies, because a single site cannot fan out
/// into a hidden second one.
#[derive(Debug, PartialEq, Eq)]
enum FileShortfall {
    /// Every call site the parser read became an edge, whichever way the
    /// spanless edges fall.
    None,
    /// At least this many parsed sites became no edge, whichever way they fall.
    /// A floor, never an exact count when spanless edges are in play.
    AtLeast(u64),
    /// The spanless edges decide the answer and this reading cannot.
    Undecidable,
}

/// The interval above, as a function so it can be tested without a store.
fn file_shortfall(parsed: u64, sites: u64, spanless: u64) -> FileShortfall {
    let remaining = parsed.saturating_sub(sites);
    let upper = remaining.saturating_sub(spanless.min(1));
    let lower = remaining.saturating_sub(spanless);
    if upper == 0 {
        FileShortfall::None
    } else if lower > 0 {
        FileShortfall::AtLeast(lower)
    } else {
        FileShortfall::Undecidable
    }
}

/// How many distinct call SITES the graph holds an edge for, among the entities
/// of one file.
///
/// Not the number of `Calls` relations, and the difference is a hole this
/// reading used to certify over. One source-level call site can fan out to
/// several same-named destinations, and counting relations lets that fan-out pay
/// for a DIFFERENT site that produced no edge at all: two parsed sites, two
/// edges both minted from the first, and the subtraction reads zero missing
/// while the second site is a hidden caller candidate. The parse side counts
/// sites, so the resolved side has to count sites too or the two are not
/// commensurable.
///
/// The join is [`kin_model::relation::RelationEvidence::source_span`], the
/// syntax the parser recorded for each edge, which this crate already reads as a
/// graph fact rather than something a consumer reconstructs
/// (`handlers::common::relation_reference_lines`). An edge carrying no span in
/// this file cannot be joined to a site and keeps its old weight of one rather
/// than being dropped, so this count is never above the relation count it
/// replaces and never below the sites the graph can actually witness. Where no
/// edge carries a span the answer is exactly what it was before, which is why a
/// store that records no spans reads no differently.
///
/// [`kin_model::relation::RelationEvidence::occurrence_count`] is read rather
/// than ignored, and ignoring it would have been this whole ticket in
/// miniature: it says how many equivalent occurrences the extractor COLLAPSED
/// into one record, so a record standing for three of them is three sites
/// wearing one span. The count for a distinct span is the largest any record
/// claims for it, because two edges sharing a span and a collapse count
/// describe one set of occurrences fanned out, not two sets.
///
/// ## Where the join exists, and what happens where it does not
///
/// The join binds only where the adapter that produced the edge recorded a
/// call-site span. Counted over `crates/kin-parser/src/languages/` by reading
/// each `ExtractedRelation` construction whose `kind` is `Calls` and asking
/// whether it sets `site: Some`: `python.rs` spans both of its two emitters and
/// `javascript.rs` spans its one. Nine adapters span none of theirs, and they
/// are `c_lang.rs`, `cpp_lang.rs`, `go.rs`, `java.rs`, `kotlin.rs`, `php.rs`,
/// `rust_lang.rs` (two emitters), `shallow_backed.rs` (two) and `swift.rs`;
/// `typescript.rs` declares no emitter of its own.
///
/// A spanless edge cannot be joined to a site, and giving it a weight of one is
/// not a neutral fallback: that is exactly the relation count this whole
/// function replaces, so a Rust file whose thirteen parsed sites produce ten
/// edges, three of them a fan-out from one site, subtracts to zero and
/// certifies while three sites became nothing. So the spanless edges are
/// COUNTED here and turned into a range by [`file_shortfall`], which certifies
/// where the range's top is zero, discloses a floor where its bottom is above
/// zero, and declines only where the range straddles zero. Refusing outright on
/// any spanless edge was the first shape of this fix and it withheld every
/// dead-code verdict on nine languages, which is failing closed over a question
/// the join does not decide.
///
/// The grain is the RELATION rather than the evidence record, deliberately. The
/// linker attaches a span-free marker record beside a spanned one for a raise
/// target (`kin-index/src/linker.rs`, and its own comment says the record is
/// deliberately span-free so no consumer counts it as a second site), and
/// merging two shape-blind edges pushes a bare default record. Refusing on any
/// span-free RECORD would make every Python file holding a `raise Foo()`
/// unmeasurable on a marker that exists precisely so it counts for nothing.
/// A relation joins when any one of its records carries a usable span.
fn resolved_call_sites<G: GraphStore>(
    store: &G,
    file: &FilePathId,
    entities: &[Entity],
) -> ResolvedSites {
    let mut sites: std::collections::HashMap<(usize, usize), u64> =
        std::collections::HashMap::new();
    let mut spanless = 0u64;
    for entity in entities {
        let entity_id = &entity.id;
        let Ok(relations) = store.get_all_relations_for_entity(entity_id) else {
            return ResolvedSites::Unreadable;
        };
        for relation in relations.iter().filter(|relation| {
            relation.kind == RelationKind::Calls && relation.src.as_entity() == Some(*entity_id)
        }) {
            let mut joined = false;
            for evidence in &relation.evidence {
                let Some(span) = evidence
                    .source_span
                    .as_ref()
                    .filter(|span| &span.file == file)
                else {
                    continue;
                };
                let collapsed = u64::from(evidence.occurrence_count).max(1);
                let site = sites.entry((span.start_byte, span.end_byte)).or_insert(0);
                *site = (*site).max(collapsed);
                joined = true;
            }
            if !joined {
                spanless += 1;
            }
        }
    }
    ResolvedSites::Counted {
        sites: sites.values().sum::<u64>(),
        spanless,
    }
}

/// One file's own call-site accounting, the same arithmetic
/// [`observe_caller_arrival`] runs over a family member.
///
/// `Ok(None)` means every call site the parser read in this file became an edge.
/// `Ok(Some(row))` means it did not, or the store holds no count to check it
/// against, which are two different gaps and both are gaps. `Err(reason)` means
/// the file could not be read at all.
///
/// Exposed because the family a focal belongs to never contains the focal's own
/// file, so this is the only way to ask whether a caller sitting BESIDE the
/// focal could have arrived through a call the linker dropped.
pub fn observe_file_call_sites<G: GraphStore>(
    store: &G,
    file: &FilePathId,
) -> Result<Option<UnaccountedFile>, String> {
    let Some((entities, parsed)) = file_entities(store, file) else {
        return Err("the entity index could not be read for the focal's own file".to_string());
    };
    let (sites, spanless) = match resolved_call_sites(store, file, &entities) {
        ResolvedSites::Counted { sites, spanless } => (sites, spanless),
        ResolvedSites::Unreadable => {
            return Err("the relation index could not be read for the focal's own file".to_string())
        }
    };
    // The same three branches [`file_shortfall`] states, on the focal's own file.
    let missing = match parsed.map(|parsed| file_shortfall(parsed, sites, spanless)) {
        Some(FileShortfall::None) => return Ok(None),
        Some(FileShortfall::AtLeast(floor)) => Some(floor),
        Some(FileShortfall::Undecidable) => {
            return Err(format!(
                "{} {NO_CALL_SITE_SPAN_REASON}, and it parses more call sites than this reading \
                 could join, so whether a call to the row from beside it became no edge depends \
                 on how those edges fan out and nothing here can settle it",
                file.0
            ))
        }
        None => None,
    };
    Ok(Some(UnaccountedFile {
        file: file.0.clone(),
        parsed_call_sites: parsed,
        resolved_call_edges: sites + spanless,
        unaccounted_call_sites: missing,
        shortfall_is_floor: spanless > 0,
        ..UnaccountedFile::default()
    }))
}

/// Whether a caller could reach `focal` through a call this graph does not hold.
///
/// Never fails the request: any error, an oversized family or an unreadable
/// index becomes `Unmeasured`, which declines to certify rather than certifying
/// on a walk that did not finish.
///
/// Every read here is scoped to one file. An earlier version loaded the whole
/// language to build a file index and refused above a cap, which on any real
/// repository is every query: kin's own Rust alone declares more than seven
/// thousand functions, so the gate would have reported `unmeasured` for every
/// focal in the store and put a floor under every absence in it. The cost now
/// scales with the focal's file and its importers, not with the repository.
pub fn observe_caller_arrival<G: GraphStore>(store: &G, focal: &Entity) -> CallerArrival {
    observe_caller_arrival_with(store, focal, None)
}

/// [`observe_caller_arrival`] over `scan`, the store-wide reading of every
/// caller that could call the focal, when the answer took one.
///
/// A family file counted from ledgers then counts only the unsettled sites
/// the scan keeps: an unresolved `json.dumps` cannot be a call to
/// `_make_timedelta`. The scan is store-wide, never the family alone, so a
/// caller that reaches the focal without importing its file is still read,
/// and its block is the `call_sites` block the answer serves. Without a scan
/// every unsettled site in the family counts, as it always has.
pub fn observe_caller_arrival_with<G: GraphStore>(
    store: &G,
    focal: &Entity,
    scan: Option<std::sync::Arc<crate::call_sites::FocalScan>>,
) -> CallerArrival {
    let mut arrival = observe_family(store, focal, scan.as_deref());
    arrival.scan = scan;
    arrival
}

fn observe_family<G: GraphStore>(
    store: &G,
    focal: &Entity,
    scan: Option<&crate::call_sites::FocalScan>,
) -> CallerArrival {
    let names = kin_model::focal_call_names(focal);
    let could_call = |entity: &Entity, site: &kin_model::CallSite| {
        scan.is_none_or(|scan| scan.keeps(entity.id, site))
    };
    let Some(focal_file) = focal.file_origin.clone() else {
        return CallerArrival::unmeasured("the focal entity carries no file of origin");
    };

    let Some((focal_file_entities, _)) = file_entities(store, &focal_file) else {
        return CallerArrival::unmeasured(
            "the entity index could not be read for the focal's file",
        );
    };
    let focal_owned: HashSet<EntityId> =
        focal_file_entities.iter().map(|entity| entity.id).collect();
    // The destinations a module binding may land on. Kept separate from
    // `focal_owned` so the widened edge class cannot admit a bare mention of a
    // function in this file as if it were an import of the file.
    let focal_modules: HashSet<EntityId> = focal_file_entities
        .iter()
        .filter(|entity| entity.kind == kin_model::EntityKind::Module)
        .map(|entity| entity.id)
        .collect();

    // The family: files holding an import edge into an entity of the focal's
    // file. Walked from the focal's file outward, because the focal's file owns
    // few entities and the repository owns many.
    //
    // `focal_file_imports_something` rides along as the cheap half of the
    // empty-family control: if this file's own imports resolved to edges, then
    // import linking demonstrably works here, and no language-wide read is
    // needed to establish it.
    let mut family: HashSet<FilePathId> = HashSet::new();
    let mut focal_file_imports_something = false;
    for entity in &focal_file_entities {
        let Ok(relations) = store.get_all_relations_for_entity(&entity.id) else {
            return CallerArrival::unmeasured(
                "the relation index could not be read for the focal's file",
            );
        };
        for relation in relations {
            let named_by_import = FAMILY_KINDS.contains(&relation.kind);
            let (Some(source), Some(destination)) =
                (relation.src.as_entity(), relation.dst.as_entity())
            else {
                continue;
            };
            // A module binding counts only when it lands on a `Module` entity of
            // the focal's own file, which is what `from . import mod` produces
            // and what a mention of a function in this file does not.
            let named_by_module_binding =
                relation.kind == MODULE_BINDING_KIND && focal_modules.contains(&destination);
            if !named_by_import && !named_by_module_binding {
                continue;
            }
            // The cheap half of the empty-family control stays keyed on import
            // edges alone. It answers "does import linking work in this file",
            // and only an import edge is evidence about import linking.
            if named_by_import && focal_owned.contains(&source) {
                focal_file_imports_something = true;
            }
            // An import edge out of this file says nothing about who can reach
            // it. Only one INTO it puts the importer in the family.
            if !focal_owned.contains(&destination) || focal_owned.contains(&source) {
                continue;
            }
            let Ok(Some(importer)) = store.get_entity(&source) else {
                continue;
            };
            if let Some(importer_file) = importer.file_origin {
                if importer_file != focal_file {
                    family.insert(importer_file);
                }
            }
        }
    }

    if family.is_empty() {
        // Nothing imports this file. Whether that is a fact about the repository
        // or about the graph depends on whether imports link here at all, and
        // only one of those licenses certifying an absence.
        //
        // The control is taken over the LANGUAGE and not over the focal's own
        // incoming edges, and that distinction is load-bearing rather than
        // pedantic: a file nothing imports holds no incoming import edge by
        // definition, so reading the control there would report every such file
        // as unmeasured and put a floor under every absence in the store. Four
        // handler fixtures went inconclusive on exactly that mistake, including
        // the one built to prove a graph linking every class across files still
        // earns its absence.
        if focal_file_imports_something || language_links_imports(store, focal.language) {
            return CallerArrival {
                state: ArrivalState::Accounted,
                family_files: 0,
                family_measured: 0,
                unaccounted: Vec::new(),
                unmeasured_reason: None,
                files_from_site_ledgers: 0,
                owed_callers: Vec::new(),
                call_sites: Some(kin_model::CallSiteTally::default()),
                owed_callers_cannot_name_focal: 0,
                owed_outside: crate::call_sites::owed_outside(
                    store,
                    focal.language,
                    &std::collections::HashSet::from([focal_file.0.clone()]),
                    &names,
                ),
                scan: None,
            };
        }
        return CallerArrival::unmeasured(
            "this language links no imports across files in this graph, so the set of files that \
             can reach the focal could not be established",
        );
    }

    let mut family_files: Vec<FilePathId> = family.into_iter().collect();
    family_files.sort_by(|left, right| left.0.cmp(&right.0));
    // A hub file can be imported by hundreds of others, and reading them all is
    // work nobody asked for. Truncating and reporting `accounted` would be the
    // silent cap this whole module exists to refuse, so an oversized family
    // declines instead: it is the honest word for a set that was not examined.
    if family_files.len() > FAMILY_FILE_CAP {
        return CallerArrival::unmeasured(format!(
            "{} files import the focal's file, above the {FAMILY_FILE_CAP} this reading examines, \
             so their call sites were not accounted for",
            family_files.len()
        ));
    }

    let mut unaccounted = Vec::new();
    let mut family_measured = 0usize;
    // Every caller in the family, read through the one site-state reading the
    // other surfaces share. Where every caller of a file holds a current
    // ledger, the file is counted from them and the count is exact; otherwise
    // the file keeps the arithmetic below and its owed callers are named.
    let facts = crate::call_sites::GraphSiteFacts::new(store);
    let mut tally = kin_model::CallSiteTally::default();
    let mut owed_callers: Vec<OwedCaller> = Vec::new();
    let mut owed_callers_cannot_name_focal = 0u64;
    let could_name = |entity: &Entity| crate::call_sites::could_name_focal(entity, &names);
    let mut files_from_site_ledgers = 0usize;
    for file in &family_files {
        let Some((entities, parsed)) = file_entities(store, file) else {
            return CallerArrival::unmeasured(
                "the entity index could not be read for a file in the focal's family",
            );
        };
        let owed_before = owed_callers.len();
        if let Some(count) = ledger_count(
            &facts,
            file,
            &entities,
            &could_name,
            &could_call,
            &mut tally,
            &mut owed_callers,
            &mut owed_callers_cannot_name_focal,
        ) {
            family_measured += 1;
            files_from_site_ledgers += 1;
            let unsettled: u64 = count.unsettled.values().sum();
            if unsettled > 0 {
                unaccounted.push(UnaccountedFile {
                    file: file.0.clone(),
                    parsed_call_sites: Some(count.census),
                    resolved_call_edges: count.settled + count.ruled_out,
                    unaccounted_call_sites: Some(unsettled),
                    shortfall_is_floor: false,
                    count_source: CountSource::SiteLedgers,
                    count_exact: true,
                    unsettled_by_state: count.unsettled,
                    owed_callers: 0,
                    ruled_out_by_name: count.ruled_out,
                });
            }
            continue;
        }
        let owed_here = (owed_callers.len() - owed_before) as u64;
        if parsed.is_some() {
            family_measured += 1;
        }
        let (sites, spanless) = match resolved_call_sites(store, file, &entities) {
            ResolvedSites::Counted { sites, spanless } => (sites, spanless),
            ResolvedSites::Unreadable => {
                return CallerArrival::unmeasured(
                    "the relation index could not be read for a file in the focal's family",
                )
            }
        };
        // Three branches, and only the third declines. See [`file_shortfall`]:
        // the spanless edges make the shortfall a range, the range's top being
        // zero certifies, its bottom being above zero is a floor to disclose,
        // and a range straddling zero is the only case where the answer depends
        // on something this reading cannot see.
        let shortfall = parsed.map(|parsed| file_shortfall(parsed, sites, spanless));
        if shortfall == Some(FileShortfall::Undecidable) {
            return CallerArrival::unmeasured(format!(
                "{} can reach the focal and {NO_CALL_SITE_SPAN_REASON}, and it parses more call \
                 sites than the sites this reading could join, so whether one of them became no \
                 edge depends on how those edges fan out and nothing here can settle it",
                file.0
            ));
        }
        // Two distinct gaps and both count. A shortfall is call sites that
        // reached no destination, exact when every edge joined and a floor when
        // some did not. An absent count is a file whose call extraction the
        // parser could not represent at all, which it signals by withholding the
        // number rather than by reporting zero.
        let missing = match shortfall {
            Some(FileShortfall::None) => Some(0),
            Some(FileShortfall::AtLeast(floor)) => Some(floor),
            Some(FileShortfall::Undecidable) => unreachable!("returned above"),
            None => None,
        };
        if missing.is_none_or(|missing| missing > 0) {
            unaccounted.push(UnaccountedFile {
                file: file.0.clone(),
                parsed_call_sites: parsed,
                resolved_call_edges: sites + spanless,
                unaccounted_call_sites: missing,
                shortfall_is_floor: spanless > 0,
                owed_callers: owed_here,
                ..UnaccountedFile::default()
            });
        }
    }

    CallerArrival {
        state: if unaccounted.is_empty() {
            ArrivalState::Accounted
        } else {
            ArrivalState::Unaccounted
        },
        family_files: family_files.len(),
        family_measured,
        unaccounted,
        unmeasured_reason: None,
        files_from_site_ledgers,
        owed_callers,
        call_sites: Some(tally),
        owed_callers_cannot_name_focal,
        owed_outside: crate::call_sites::owed_outside(
            store,
            focal.language,
            &family_files
                .iter()
                .map(|file| file.0.clone())
                .chain(std::iter::once(focal_file.0.clone()))
                .collect(),
            &names,
        ),
        scan: None,
    }
}

/// The gate the negative envelope applies, read back off the published block so
/// the verdict and the evidence a reader audits it against are the same object.
///
/// Returns the limiting factor when the answer's own `caller_arrival` block says
/// a caller could have arrived through an edge the graph does not hold, and
/// `None` when it says the arrival paths are accounted for.
pub fn arrival_gap(payload: &serde_json::Value) -> Option<String> {
    let block = payload.get(CALLER_ARRIVAL_KEY)?;
    let state = block.get("state").and_then(serde_json::Value::as_str)?;
    match state {
        "accounted" => None,
        "unaccounted" => {
            let files: Vec<String> = block
                .get("unaccounted_files")
                .and_then(serde_json::Value::as_array)
                .map(|files| {
                    files
                        .iter()
                        .take(5)
                        .filter_map(|file| {
                            let path = file.get("file").and_then(serde_json::Value::as_str)?;
                            let exact =
                                file.get("count_exact").and_then(serde_json::Value::as_bool)
                                    == Some(true);
                            Some(
                                match file
                                    .get("unaccounted_call_sites")
                                    .and_then(serde_json::Value::as_u64)
                                {
                                    Some(missing) if exact => {
                                        format!("{path} ({missing} unsettled, exact)")
                                    }
                                    Some(missing) => format!("{path} ({missing} unaccounted)"),
                                    None => format!("{path} (no parse-side count in store)"),
                                },
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            let family = block
                .get("family_files")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            // The count the verdict rests on is `unaccounted_file_count`, which
            // is never truncated. The rows are capped and five of them are named
            // here, so counting the named ones reported five files where twelve
            // held the gap.
            let unaccounted = block
                .get("unaccounted_file_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(files.len() as u64)
                .max(files.len() as u64);
            let more = unaccounted.saturating_sub(files.len() as u64);
            let tail = if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            };
            Some(format!(
                "{UNRESOLVED_ARRIVAL_LIMITING_FACTOR}: of the {family} file(s) that import the \
                 focal's file, {unaccounted} hold call sites the linker recorded no edge for, so a \
                 caller of this focal may be among them and an empty reference list here is a \
                 floor rather than proof of disuse: {}{tail}",
                files.join(", ")
            ))
        }
        "unmeasured" => {
            let reason = block
                .get("unmeasured_reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("no reason recorded");
            Some(format!(
                "{UNMEASURED_ARRIVAL_LIMITING_FACTOR}: this answer could not establish which files \
                 can reach the focal ({reason}), so an empty reference list is not evidence that \
                 nothing calls it"
            ))
        }
        other => Some(format!(
            "caller_arrival_state_unknown: this answer reported the arrival state as {other:?}, \
             which is not a state that licenses reading an empty reference list as whole"
        )),
    }
}

/// Whether an absence claim about `focal` can be supported at all, and the
/// limiting factor when it cannot.
///
/// This is THE rule for a delete list, spelled once so every dead-code surface
/// reaches the same verdict about the same entity. `kin dead-code`, the MCP
/// `dead_code` tool, and both seeded implementations used to decide on present
/// inbound edges alone; wiring the arrival reading into one of them would have
/// left an agent asking the MCP for removable code and getting the answer the
/// terminal had already refused to stand behind.
///
/// Two things separate it from reading [`ArrivalState`] off
/// [`observe_caller_arrival`] directly, and both are fail-closed.
///
/// First, only [`ArrivalState::Accounted`] licenses an absence, so a family file
/// carrying NO parse-side count gates the row exactly as a measured shortfall
/// does. That case is not a rare one: on the store this ticket came from the
/// reading returned `family_measured: 0` with `parsed_call_sites: null` on every
/// row, and it is the whole reason a delete list must not read a missing
/// measurement as a clean one. The two gaps keep different factor ids, because
/// "some call went nowhere" and "nobody counted" are different news for whoever
/// reads the row, but neither one certifies.
///
/// Second, the focal's own file is accounted here. The family is by construction
/// the files that name the focal's file from outside it, so a call from BESIDE
/// the focal that the linker dropped is outside the reading entirely, and on a
/// delete list that is the caller whose deletion breaks the build. The
/// candidate scan already drops a row whose own file holds an inbound EDGE; this
/// covers the same-file call that produced no edge at all.
///
/// Scoped to this authority rather than folded into [`observe_caller_arrival`]
/// on purpose: `find_references` qualifies a reference list, this qualifies a
/// deletion, and a delete list has always carried the stricter bar.
pub fn absence_gap<G: GraphStore>(store: &G, focal: &Entity) -> Option<(&'static str, String)> {
    let arrival = observe_caller_arrival(store, focal);
    match arrival.state {
        ArrivalState::Unmeasured => {
            return Some((
                UNMEASURED_ARRIVAL_LIMITING_FACTOR,
                format!(
                    "the set of files that can reach it could not be established ({})",
                    arrival
                        .unmeasured_reason
                        .as_deref()
                        .unwrap_or("no reason recorded")
                ),
            ));
        }
        ArrivalState::Unaccounted => {
            // `unaccounted_call_sites` is `Some(n)` only where both sides of the
            // subtraction were read. `None` is a file the store holds no parse
            // count for. Both are gaps; they differ only in what the row can
            // tell its reader, so the measured ones are named first and the
            // absent ones fall back to a factor that says nobody counted.
            let measured: Vec<String> = arrival
                .unaccounted
                .iter()
                .filter_map(|file| {
                    file.unaccounted_call_sites
                        .filter(|missing| *missing > 0)
                        .map(|missing| {
                            if file.count_exact {
                                format!(
                                    "{} ({missing} of {} call sites are not settled, an exact \
                                     count from site ledgers)",
                                    file.file,
                                    file.parsed_call_sites.unwrap_or(0)
                                )
                            } else {
                                format!(
                                    "{} ({missing} of {} parsed call sites became no edge)",
                                    file.file,
                                    file.parsed_call_sites.unwrap_or(0)
                                )
                            }
                        })
                })
                .collect();
            if !measured.is_empty() {
                return Some((
                    UNRESOLVED_ARRIVAL_LIMITING_FACTOR,
                    format!(
                        "{} of the {} file(s) that can reach it hold call sites the linker \
                         recorded no edge for, so a caller may be among them: {}",
                        measured.len(),
                        arrival.family_files,
                        measured.join(", ")
                    ),
                ));
            }
            let uncounted = arrival.unaccounted.len();
            return Some((
                UNMEASURED_ARRIVAL_LIMITING_FACTOR,
                format!(
                    "the store holds no parse-side call count for {uncounted} of the {} file(s) \
                     that can reach it, so the calls made there could not be accounted for",
                    arrival.family_files
                ),
            ));
        }
        ArrivalState::Accounted => {}
    }

    // Every file that names this one from outside accounted for its calls. What
    // remains is the file itself, which is in no family.
    let file = focal.file_origin.as_ref()?;
    match observe_file_call_sites(store, file) {
        Err(reason) => Some((UNMEASURED_ARRIVAL_LIMITING_FACTOR, reason)),
        Ok(None) => None,
        Ok(Some(row)) => match row.unaccounted_call_sites {
            Some(missing) => Some((
                UNRESOLVED_ARRIVAL_LIMITING_FACTOR,
                format!(
                    "{missing} of the {} call sites the parser read in that same file became no \
                     edge, so a caller sitting beside it may be among them",
                    row.parsed_call_sites.unwrap_or(0)
                ),
            )),
            None => Some((
                UNMEASURED_ARRIVAL_LIMITING_FACTOR,
                "the store holds no parse-side call count for that file itself, so a call to it \
                 from beside it could not be accounted for"
                    .to_string(),
            )),
        },
    }
}

/// [`absence_gap`] over a scan that classifies many entities at once.
///
/// The reading consults the focal only through its file of origin and its
/// language, and it walks up to [`FAMILY_FILE_CAP`] importing files per reading,
/// so a scan listing forty rows out of three files takes three readings rather
/// than forty. Every entity of one file shares that file's language, so the memo
/// key is the file and nothing finer.
#[derive(Default)]
pub struct AbsenceGapMemo {
    by_file: std::collections::HashMap<FilePathId, Option<(&'static str, String)>>,
}

impl AbsenceGapMemo {
    pub fn new() -> Self {
        Self::default()
    }

    /// The gap for one entity, computed once per file.
    pub fn gap<G: GraphStore>(
        &mut self,
        store: &G,
        focal: &Entity,
    ) -> Option<(&'static str, String)> {
        let Some(file) = focal.file_origin.clone() else {
            return absence_gap(store, focal);
        };
        self.by_file
            .entry(file)
            .or_insert_with(|| absence_gap(store, focal))
            .clone()
    }

    /// The same gap rendered as the one sentence a JSON surface publishes, and
    /// `None` when the absence is supportable.
    ///
    /// Published on every row rather than only on limited ones, so a reader
    /// never has to tell "checked and fine" from "not reported".
    pub fn limiting_factor<G: GraphStore>(&mut self, store: &G, focal: &Entity) -> Option<String> {
        self.gap(store, focal)
            .map(|(factor, reason)| format!("{factor}: {reason}"))
    }
}

/// What an `impact_analysis` block reports as its state when no row of the
/// answer claims an absence, so there was nothing for the reading to qualify.
pub const IMPACT_ARRIVAL_NOT_APPLICABLE: &str = "not_applicable";

/// The caller-arrival reading an `impact_analysis` answer publishes under
/// [`CALLER_ARRIVAL_KEY`], taken for every changed entity its answer reports
/// with no consumers.
///
/// A `consumer_count: 0` row is the same claim an empty `find_references` is:
/// nothing reaches this entity. It is read off the same `Calls` edges, so it has
/// the same hole, and until this reading existed it was certified over that
/// hole. An export whose caller sits in a file that imports it, where the
/// linker recorded no edge for the call, came back `consumer_count: 0` under a
/// certified verdict while `find_references` refused the same absence on the
/// same graph.
///
/// So each such entity gets [`observe_caller_arrival`], the reading
/// `find_references` publishes, and its entry carries exactly that reading's
/// fields beside the entity's id, name and file. The two surfaces then reach
/// one verdict on one reading. Rows that report consumers claim no absence and
/// are not read, which is the same scope `find_references` gives the gate: a
/// shortfall in the arrival paths bounds what "nothing calls this" can mean and
/// says nothing about the consumers a row did find.
///
/// The counts are never truncated; the verdict rests on them. The entries are
/// evidence a reader audits them with, capped at [`EVIDENCE_ROW_CAP`] with the
/// refusing ones first, and the block says when it truncated.
///
/// Readings are shared only when the focal's file, language and name match.
/// The name decides which owed callers could reach this focal, so two entities
/// in one file can have different readings.
pub fn observe_impact_arrival<G: GraphStore>(
    store: &G,
    entities_without_consumers: &[EntityId],
) -> serde_json::Value {
    let mut by_focal: std::collections::HashMap<
        (FilePathId, kin_model::LanguageId, String),
        CallerArrival,
    > = std::collections::HashMap::new();
    let mut entries: Vec<(EntityId, Option<String>, Option<String>, CallerArrival)> = Vec::new();
    let mut outside_focals: std::collections::HashMap<
        kin_model::LanguageId,
        std::collections::HashMap<String, HashSet<String>>,
    > = std::collections::HashMap::new();
    for id in entities_without_consumers {
        let (name, file, arrival) = match store.get_entity(id) {
            Ok(Some(entity)) => {
                let arrival = match entity.file_origin.clone() {
                    Some(file) => by_focal
                        .entry((file, entity.language, entity.name.clone()))
                        .or_insert_with(|| observe_caller_arrival(store, &entity))
                        .clone(),
                    None => observe_caller_arrival(store, &entity),
                };
                if let Some(files) = &arrival.owed_outside {
                    for file in files {
                        outside_focals
                            .entry(entity.language)
                            .or_default()
                            .entry(file.file.clone())
                            .or_default()
                            .extend(kin_model::focal_call_names(&entity));
                    }
                }
                (
                    Some(entity.name),
                    entity.file_origin.map(|file| file.0),
                    arrival,
                )
            }
            Ok(None) => (
                None,
                None,
                CallerArrival::unmeasured(
                    "the changed entity is not in the graph, so the files that can reach it could \
                     not be established",
                ),
            ),
            Err(_) => (
                None,
                None,
                CallerArrival::unmeasured(
                    "the entity index could not be read for the changed entity",
                ),
            ),
        };
        entries.push((*id, name, file, arrival));
    }

    let count = |state: ArrivalState| {
        entries
            .iter()
            .filter(|(_, _, _, arrival)| arrival.state == state)
            .count()
    };
    let unaccounted = count(ArrivalState::Unaccounted);
    let unmeasured = count(ArrivalState::Unmeasured);
    let state = if entries.is_empty() {
        IMPACT_ARRIVAL_NOT_APPLICABLE
    } else if unaccounted > 0 {
        ArrivalState::Unaccounted.wire()
    } else if unmeasured > 0 {
        ArrivalState::Unmeasured.wire()
    } else {
        ArrivalState::Accounted.wire()
    };

    // Refusing entries lead, so a capped list still names what limits the
    // answer. The sort is stable, which keeps the answer's own row order inside
    // each group.
    entries.sort_by_key(|(_, _, _, arrival)| arrival.state.certifies_absence());
    let rows: Vec<serde_json::Value> = entries
        .iter()
        .take(EVIDENCE_ROW_CAP)
        .map(|(id, name, file, arrival)| {
            let mut row = arrival.fields_json();
            row["entity_id"] = json!(id.to_string());
            row["name"] = json!(name);
            row["file"] = json!(file);
            row
        })
        .collect();

    // Union caller identities before counting by file. Different focal names
    // can select disjoint or overlapping callers in the same outside file:
    // neither the maximum nor the sum of the per-focal counts is their union.
    let mut owed_outside_unreadable = entries
        .iter()
        .any(|(_, _, _, arrival)| arrival.owed_outside.is_none());
    let mut outside_callers = Vec::new();
    let mut seen_callers = HashSet::new();
    if !owed_outside_unreadable {
        for (language, files) in outside_focals {
            let Ok(entities) = store.query_entities(&EntityFilter {
                languages: Some(vec![language]),
                ..EntityFilter::default()
            }) else {
                owed_outside_unreadable = true;
                break;
            };
            outside_callers.extend(entities.into_iter().filter(|entity| {
                entity.span.as_ref().is_some_and(|span| {
                    span.start_byte < span.end_byte
                        && files.get(&span.file.0).is_some_and(|names| {
                            let names: Vec<String> = names.iter().cloned().collect();
                            crate::call_sites::could_name_focal(entity, &names)
                        })
                }) && seen_callers.insert(entity.id)
            }));
        }
    }
    let owed_outside = crate::call_sites::owed_files(store, &outside_callers);

    let mut block = json!({
        "state": state,
        "entities_examined": entries.len(),
        "unaccounted_entity_count": unaccounted,
        "unmeasured_entity_count": unmeasured,
        "entities": rows,
        "entities_truncated": entries.len() > EVIDENCE_ROW_CAP,
        "scope": ARRIVAL_READING_SCOPE,
    });
    if owed_outside_unreadable {
        block["owed_outside_scope"] = json!({ "unreadable": true });
    } else if !owed_outside.is_empty() {
        block["owed_outside_scope"] = json!({
            "file_count": owed_outside.len(),
            "callers": owed_outside.iter().map(|file| file.callers).sum::<u64>(),
            "files": owed_outside.iter().take(EVIDENCE_ROW_CAP).collect::<Vec<_>>(),
        });
    }
    block
}

/// What a certified absence says about this reading when the reading is one of
/// the inputs it certified over, or `None` when the answer holds no reading
/// that certified.
///
/// A certification on this reading inherits its [`ARRIVAL_READING_SCOPE`], so
/// the reason a reader acts on names the reading and recites the scope, rather
/// than leaving the two limits in a block the reason never mentions. Read off
/// the published block, the way [`arrival_gap`] and [`impact_arrival_gaps`]
/// read it, so the certified reason and the gaps cannot come apart.
pub fn arrival_certification_clause(tool: &str, payload: &serde_json::Value) -> Option<String> {
    let block = payload.get(CALLER_ARRIVAL_KEY)?;
    if block.get("state").and_then(serde_json::Value::as_str)
        != Some(ArrivalState::Accounted.wire())
    {
        return None;
    }
    let count = |key: &str| {
        block
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    };
    let read = match tool {
        "find_references" | "get_context_pack" => format!(
            "the {CALLER_ARRIVAL_KEY} reading found every call site accounted for in the {} \
             file(s) that import the focal's file",
            count("family_files")
        ),
        "impact_analysis" => format!(
            "the {CALLER_ARRIVAL_KEY} reading found every call site accounted for in the files \
             that import each of the {} entities reported with no consumers",
            count("entities_examined")
        ),
        _ => return None,
    };
    Some(format!("{read} ({ARRIVAL_READING_SCOPE})"))
}

/// The gaps an `impact_analysis` answer's own caller-arrival block reports, one
/// clause per kind of gap, or none when every entity it read was accounted for.
///
/// The per-entity arithmetic is [`observe_caller_arrival`]'s and the codes are
/// the ones [`arrival_gap`] gives `find_references`. What differs is only that
/// an impact answer can claim several absences at once, so each clause says
/// how many of the entities it read carry that gap and names them, rather than
/// speaking of one focal. Two entities sharing a gap therefore make one clause,
/// which is what the verdict's per-code dedupe would have left anyway, and none
/// of them is dropped from it.
///
/// A payload with no block is not gated here, exactly as [`arrival_gap`] leaves
/// a reference answer with none. The handler publishes one on every answer.
/// The gap a published arrival block states while owed callers outside the
/// family could hold a call to the focal, or `None` when there are none.
///
/// Read off the block, the way [`arrival_gap`] reads it, so the verdict and
/// the evidence a reader audits it against are the same object. The block is
/// either one focal's reading or an impact answer's, which carry the field
/// under the same name.
pub fn owed_outside_gap(payload: &serde_json::Value) -> Option<String> {
    let owed = payload.get(CALLER_ARRIVAL_KEY)?.get("owed_outside_scope")?;
    if owed.get("unreadable").and_then(serde_json::Value::as_bool) == Some(true) {
        return Some(crate::call_sites::owed_outside_unreadable_clause());
    }
    let files = owed.get("file_count").and_then(serde_json::Value::as_u64)?;
    let callers = owed
        .get("callers")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    (files > 0).then(|| crate::call_sites::owed_outside_counts_clause(files, callers))
}

pub fn impact_arrival_gaps(payload: &serde_json::Value) -> Vec<String> {
    let Some(block) = payload.get(CALLER_ARRIVAL_KEY) else {
        return Vec::new();
    };
    let state = block.get("state").and_then(serde_json::Value::as_str);
    let owed_outside = owed_outside_gap(payload);
    if matches!(
        state,
        Some("accounted") | Some(IMPACT_ARRIVAL_NOT_APPLICABLE)
    ) {
        return owed_outside.into_iter().collect();
    }
    let reported = state.map_or_else(|| "absent".to_string(), |state| format!("{state:?}"));
    if !matches!(state, Some("unaccounted") | Some("unmeasured")) {
        return vec![format!(
            "caller_arrival_state_unknown: this answer reported the arrival state of the entities \
             it found no consumers for as {reported}, which is not a state that licenses reading a \
             zero consumer count as whole"
        )];
    }

    let examined = block
        .get("entities_examined")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let count_of = |key: &str| {
        block
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    };
    let entities: &[serde_json::Value] = block
        .get("entities")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let named = |wire: &str, describe: &dyn Fn(&serde_json::Value) -> String| -> Vec<String> {
        entities
            .iter()
            .filter(|entry| entry.get("state").and_then(serde_json::Value::as_str) == Some(wire))
            .take(5)
            .map(|entry| {
                let name = entry
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| entry.get("entity_id").and_then(serde_json::Value::as_str))
                    .unwrap_or("an entity with no recorded name");
                format!("{name} [{}]", describe(entry))
            })
            .collect()
    };
    // The entities a clause names, and how many more it counts than it names.
    // The listed rows are capped and the refusing ones lead, so when one kind of
    // gap fills the cap the other can name none of its entities, and the clause
    // says so rather than ending on an empty list.
    let naming = |listed: &[String], total: u64| {
        let more = total.saturating_sub(listed.len() as u64);
        match (listed.is_empty(), more) {
            (true, _) => format!("{total} not among the listed entities"),
            (false, 0) => listed.join(", "),
            (false, more) => format!("{} and {more} more", listed.join(", ")),
        }
    };
    // Who a clause is about. One entity is named as the one the answer reported,
    // and several are counted against the rows the reading examined.
    let subject = |count: u64| {
        if examined == 1 {
            "the entity this answer reports with no consumers".to_string()
        } else {
            format!("{count} of the {examined} entities this answer reports with no consumers")
        }
    };
    let pronoun = |count: u64| if count == 1 { "it" } else { "them" };

    // Joined with ", " throughout, never with "; ", which is
    // `crate::verdict::CLAUSE_SEPARATOR`: a clause carrying it reaches a reader
    // as a labelled clause and an unlabelled fragment.
    let mut gaps = Vec::new();
    let unaccounted = count_of("unaccounted_entity_count");
    if unaccounted > 0 {
        let listed = named(ArrivalState::Unaccounted.wire(), &|entry| {
            let files: Vec<String> = entry
                .get("unaccounted_files")
                .and_then(serde_json::Value::as_array)
                .map(|files| {
                    files
                        .iter()
                        .take(3)
                        .filter_map(|file| {
                            let path = file.get("file").and_then(serde_json::Value::as_str)?;
                            Some(
                                match file
                                    .get("unaccounted_call_sites")
                                    .and_then(serde_json::Value::as_u64)
                                {
                                    Some(missing) => format!("{path} {missing} unaccounted"),
                                    None => format!("{path} no parse-side count in store"),
                                },
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            // Three files are named per entity, out of a count that is never
            // truncated, so an entity whose gap spans more says how many more
            // rather than reading as a whole list.
            let more = entry
                .get("unaccounted_file_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                .saturating_sub(files.len() as u64);
            if more > 0 {
                format!("{} and {more} more", files.join(", "))
            } else {
                files.join(", ")
            }
        });
        gaps.push(format!(
            "{UNRESOLVED_ARRIVAL_LIMITING_FACTOR}: {} can be reached from files that hold call \
             sites the linker recorded no edge for, so a consumer may be among them and a zero \
             consumer count there is a floor rather than proof of disuse: {}",
            subject(unaccounted),
            naming(&listed, unaccounted),
        ));
    }
    let unmeasured = count_of("unmeasured_entity_count");
    if unmeasured > 0 {
        let listed = named(ArrivalState::Unmeasured.wire(), &|entry| {
            entry
                .get("unmeasured_reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("no reason recorded")
                .to_string()
        });
        gaps.push(format!(
            "{UNMEASURED_ARRIVAL_LIMITING_FACTOR}: for {} the files that can reach {} could not \
             be established, so a zero consumer count there is not evidence that nothing uses {}: \
             {}",
            subject(unmeasured),
            pronoun(unmeasured),
            pronoun(unmeasured),
            naming(&listed, unmeasured),
        ));
    }
    if gaps.is_empty() {
        // The block named a refusing state and counted nothing under it. That
        // is a block this function did not write, and a state that refuses is
        // never read as clearance because its counts are missing.
        gaps.push(format!(
            "caller_arrival_state_unknown: this answer reported the arrival state of the entities \
             it found no consumers for as {reported} and counted no entity under it, so a zero \
             consumer count cannot be read as whole"
        ));
    }
    gaps.extend(owed_outside);
    gaps
}

#[cfg(test)]
mod tests {
    use super::*;

    use kin_db::InMemoryGraph;
    use kin_model::graph::EntityStore;
    use kin_model::relation::RelationEvidence;
    use kin_model::{
        EntityKind, EntityMetadata, FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId,
        Relation, RelationId, RelationOrigin, SemanticFingerprint, SourceSpan, Visibility,
    };

    const FOCAL_FILE: &str = "src/notekeeper/storage.py";
    const CALLER_FILE: &str = "tests/test_storage.py";

    /// One entity in a file, carrying the file-level parse-side call count the
    /// extractor stamps on every entity of the file. `None` reproduces a file
    /// whose call extraction the parser could not represent, which it signals by
    /// withholding the number rather than by reporting zero.
    fn entity_in(name: &str, file: &str, parsed_calls: Option<u64>) -> Entity {
        let mut metadata = EntityMetadata::default();
        if let Some(count) = parsed_calls {
            metadata.extra.insert(
                kin_parser::FILE_PARSED_CALL_SITES_KEY.into(),
                serde_json::Value::from(count),
            );
        }
        Entity {
            id: EntityId::from_content(file, name, "Function", 0),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: Some(SourceSpan {
                file: FilePathId::new(file),
                start_byte: 0,
                end_byte: 10,
                start_line: 1,
                start_col: 0,
                end_line: 2,
                end_col: 0,
            }),
            signature: format!("def {name}()"),
            visibility: Visibility::Public,
            role: kin_model::EntityRole::Source,
            doc_summary: None,
            metadata,
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn edge(kind: RelationKind, src: &Entity, dst: &Entity) -> Relation {
        Relation {
            id: RelationId::from_content(
                &src.id.0.to_string(),
                &dst.id.0.to_string(),
                &format!("{kind:?}"),
            ),
            kind,
            src: GraphNodeId::Entity(src.id),
            dst: GraphNodeId::Entity(dst.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    /// The stranger's shape: a module under `src/`, a test file that imports it
    /// and calls into it, and a linker that bound some of that test's calls and
    /// not others.
    ///
    /// `caller_parsed_calls` is what the parser read in the test file and
    /// `caller_resolved_calls` is how many of them became edges. The gap between
    /// them is the whole subject.
    fn store_with(
        caller_parsed_calls: Option<u64>,
        caller_resolved_calls: usize,
        import_edge: bool,
    ) -> (InMemoryGraph, Entity) {
        let store = InMemoryGraph::new();
        let focal = entity_in("note_body", FOCAL_FILE, Some(2));
        let focal_module = entity_in("storage", FOCAL_FILE, Some(2));
        let find_note = entity_in("find_note", FOCAL_FILE, Some(2));
        let caller_module = entity_in("test_storage", CALLER_FILE, caller_parsed_calls);
        let caller = entity_in("test_bodies_round_trip", CALLER_FILE, caller_parsed_calls);
        for entity in [&focal, &focal_module, &find_note, &caller_module, &caller] {
            store.upsert_entity(entity).unwrap();
        }
        if import_edge {
            store
                .upsert_relation(&edge(RelationKind::Imports, &caller_module, &focal_module))
                .unwrap();
        }
        // Whatever the linker did bind from the test file. `find_note` stands in
        // for the calls that resolved; `note_body` is the one that did not, so
        // the focal has no incoming edge in any arm.
        //
        // Each edge sits at its own call-site span, which is what an adapter
        // that records sites produces and what these arms mean by "resolved
        // calls". Leaving them span-free would make every arm here read
        // `unmeasured` on the join refusal rather than on the shortfall they are
        // about, and that state has its own arm.
        for index in 0..caller_resolved_calls {
            let target = if index == 0 {
                &find_note
            } else {
                &focal_module
            };
            store
                .upsert_relation(&call_edge_at(
                    &caller,
                    target,
                    CALLER_FILE,
                    100 * (index + 1),
                ))
                .unwrap();
        }
        (store, focal)
    }

    /// The same entity, but minted as the `Module` a Python file always carries.
    ///
    /// `entity_in` builds a `Function` for every name, which is what the other
    /// arms want. A module binding lands on a `Module`, and the difference is
    /// the whole of what separates the widened family from a bare mention.
    fn module_entity_in(name: &str, file: &str, parsed_calls: Option<u64>) -> Entity {
        Entity {
            kind: EntityKind::Module,
            id: EntityId::from_content(file, name, "Module", 0),
            ..entity_in(name, file, parsed_calls)
        }
    }

    /// The FIR-2821 shape, built the way the graph actually records it.
    ///
    /// `from . import linkgraph` then `linkgraph.to_dot(conn)` binds the module
    /// and no name inside it, so the caller holds a `References` edge into the
    /// focal file's `Module` entity and NO `Imports` edge into any entity of
    /// that file. `dst_kind` is what the reference lands on, which is the one
    /// thing the two arms below differ by.
    fn store_with_module_binding(
        caller_parsed_calls: Option<u64>,
        caller_resolved_calls: usize,
        reference_lands_on_module: bool,
    ) -> (InMemoryGraph, Entity) {
        let store = InMemoryGraph::new();
        let focal = entity_in("to_dot", FOCAL_FILE, Some(2));
        let focal_module = module_entity_in("linkgraph", FOCAL_FILE, Some(2));
        let neighbour = entity_in("resolve_key", FOCAL_FILE, Some(2));
        let caller = entity_in("_cmd_graph", CALLER_FILE, caller_parsed_calls);
        for entity in [&focal, &focal_module, &neighbour, &caller] {
            store.upsert_entity(entity).unwrap();
        }
        let destination = if reference_lands_on_module {
            &focal_module
        } else {
            &neighbour
        };
        store
            .upsert_relation(&edge(RelationKind::References, &caller, destination))
            .unwrap();
        // One span per resolved call, for the reason `store_with` states.
        for index in 0..caller_resolved_calls {
            store
                .upsert_relation(&call_edge_at(
                    &caller,
                    &neighbour,
                    CALLER_FILE,
                    100 * (index + 1),
                ))
                .unwrap();
        }
        (store, focal)
    }

    #[test]
    fn a_module_binding_puts_its_file_in_the_family() {
        // THE ARM FIR-2821 BOUGHT. Before the module-binding class existed here,
        // this store's family was EMPTY, the empty-family branch certified, and
        // the gate answered `accounted` over the one shape it exists to catch.
        // On the v0.6.1 stranger corpus that is 35 real edges answering
        // `family_files: 0`.
        let (store, focal) = store_with_module_binding(Some(4), 1, true);
        let arrival = observe_caller_arrival(&store, &focal);

        assert_eq!(
            arrival.family_files, 1,
            "a file that named this module in its own source can reach the focal, \
             whether it named it by specifier or by module"
        );
        assert_eq!(
            arrival.state,
            ArrivalState::Unaccounted,
            "three of the caller's four parsed call sites became no edge, and the \
             focal could be among them"
        );
        assert_eq!(arrival.unaccounted.len(), 1);
        assert_eq!(arrival.unaccounted[0].file, CALLER_FILE);
        assert_eq!(arrival.unaccounted[0].unaccounted_call_sites, Some(3));
    }

    #[test]
    fn a_reference_that_is_not_a_module_binding_does_not_build_a_family() {
        // THE CONTROL, and it is what stops the widening from becoming "any
        // References edge". A reference landing on a FUNCTION of the focal's
        // file is a mention, not a binding of the file, and admitting it would
        // put most of a repository in most families and floor every absence.
        // This arm is the one that stays green only while the class is narrow.
        let (store, focal) = store_with_module_binding(Some(4), 1, false);
        let arrival = observe_caller_arrival(&store, &focal);

        assert_eq!(
            arrival.family_files, 0,
            "a mention of a sibling function is not the caller naming this file"
        );
    }

    #[test]
    fn a_module_binding_whose_caller_resolved_every_call_still_certifies() {
        // The other half of the control. The widened class must be able to
        // answer `accounted`, or it is a gate that never certifies, which is the
        // failure this module's own header warns against.
        let (store, focal) = store_with_module_binding(Some(1), 1, true);
        let arrival = observe_caller_arrival(&store, &focal);

        assert_eq!(arrival.family_files, 1);
        assert_eq!(
            arrival.state,
            ArrivalState::Accounted,
            "every call site the caller parsed became an edge, so an absence over \
             these edges is the whole set"
        );
    }

    #[test]
    fn a_call_site_that_became_no_edge_makes_the_absence_unaccounted() {
        // Three call sites read in the test file, two edges recorded. The third
        // is `storage.note_body(db, note.id)`, and it is the focal.
        let (store, focal) = store_with(Some(3), 2, true);
        let arrival = observe_caller_arrival(&store, &focal);

        assert_eq!(arrival.state, ArrivalState::Unaccounted);
        assert_eq!(arrival.family_files, 1);
        assert_eq!(arrival.family_measured, 1);
        assert_eq!(arrival.unaccounted.len(), 1);
        assert_eq!(arrival.unaccounted[0].file, CALLER_FILE);
        assert_eq!(arrival.unaccounted[0].parsed_call_sites, Some(3));
        assert_eq!(arrival.unaccounted[0].resolved_call_edges, 2);
        assert_eq!(arrival.unaccounted[0].unaccounted_call_sites, Some(1));

        let factor = arrival
            .limiting_factor()
            .expect("an unaccounted arrival limits the answer");
        assert!(
            factor.starts_with(UNRESOLVED_ARRIVAL_LIMITING_FACTOR),
            "the limiting factor must lead with its id: {factor}"
        );
        assert!(
            factor.contains(CALLER_FILE),
            "the limiting factor must name the file that holds the unaccounted calls: {factor}"
        );
        // And the published block says the same thing, so the gate a reader sees
        // and the evidence they audit it against cannot disagree.
        let gap = arrival_gap(&json!({ CALLER_ARRIVAL_KEY: arrival.to_json() }))
            .expect("the published block must reproduce the gap");
        assert!(gap.starts_with(UNRESOLVED_ARRIVAL_LIMITING_FACTOR), "{gap}");
        assert!(gap.contains(CALLER_FILE), "{gap}");
    }

    #[test]
    fn every_call_site_accounted_still_certifies_the_absence() {
        // The control the ticket demands. Flooring every absence would destroy
        // the envelope's value in the other direction, so a family whose call
        // sites all became edges must still license an authoritative absence,
        // on a store built the same way as the failing arm.
        let (store, focal) = store_with(Some(2), 2, true);
        let arrival = observe_caller_arrival(&store, &focal);

        assert_eq!(arrival.state, ArrivalState::Accounted);
        assert_eq!(arrival.family_files, 1);
        assert!(arrival.unaccounted.is_empty());
        assert_eq!(arrival.limiting_factor(), None);
        assert_eq!(
            arrival_gap(&json!({ CALLER_ARRIVAL_KEY: arrival.to_json() })),
            None
        );
    }

    #[test]
    fn fan_out_past_the_parsed_count_is_not_a_shortfall() {
        // One call site can bind several same-named destinations, so the edge
        // side can exceed the parse side. Subtracting the other way round would
        // wrap and report a gap on a graph that resolved everything.
        let (store, focal) = store_with(Some(1), 3, true);
        let arrival = observe_caller_arrival(&store, &focal);
        assert_eq!(arrival.state, ArrivalState::Accounted);
    }

    #[test]
    fn a_file_whose_call_extraction_was_incomplete_is_its_own_gap() {
        // The parser withholds the count rather than reporting zero when it
        // could not represent a file's calls. An absent count read as zero would
        // make that file look perfectly resolved, which is the reading this
        // whole module exists to refuse.
        let (store, focal) = store_with(None, 2, true);
        let arrival = observe_caller_arrival(&store, &focal);

        assert_eq!(arrival.state, ArrivalState::Unaccounted);
        assert_eq!(arrival.family_measured, 0);
        assert_eq!(arrival.unaccounted[0].parsed_call_sites, None);
        assert_eq!(arrival.unaccounted[0].unaccounted_call_sites, None);
        let factor = arrival
            .limiting_factor()
            .expect("an unmeasured file limits the answer");
        assert!(
            factor.contains("no parse-side call count"),
            "the reason must say the count is absent rather than zero, and must not name a \
             cause it cannot know: a file reaches this branch both when the parser withheld \
             the count and when the store simply does not hold one, and on a converted store \
             today the second is the common case: {factor}"
        );
    }

    #[test]
    fn no_import_edge_anywhere_is_unmeasured_not_empty() {
        // "Nobody imports this file" and "I cannot see who imports anything" are
        // opposite facts and only the first licenses certifying an absence. With
        // no import edge in the language the family cannot be established, so
        // the state declines rather than reading as an empty family.
        let (store, focal) = store_with(Some(3), 2, false);
        let arrival = observe_caller_arrival(&store, &focal);

        assert_eq!(arrival.state, ArrivalState::Unmeasured);
        assert!(!arrival.state.certifies_absence());
        let factor = arrival
            .limiting_factor()
            .expect("unmeasured limits the answer");
        assert!(
            factor.starts_with(UNMEASURED_ARRIVAL_LIMITING_FACTOR),
            "{factor}"
        );
    }

    #[test]
    fn a_file_nothing_imports_still_certifies_when_the_language_links_imports() {
        // The other half of the control above, and the reason the two cannot be
        // collapsed. Here the graph demonstrably resolves imports and this file
        // simply has none pointing at it, so an empty family is a real reading
        // about the repository rather than a blind spot.
        //
        // The focal's own file is deliberately left with NO incident import edge
        // of any kind. That is what makes this a falsification of the mistake it
        // was written for: taking the control off the focal's file rather than
        // off the language reports every unimported file as unmeasured and puts
        // a floor under every absence in the store. Four handler fixtures went
        // red on it, this one goes red on it, and no arm above can see it.
        let store = InMemoryGraph::new();
        let focal = entity_in("private_helper", "src/notekeeper/internal.py", Some(0));
        let other = entity_in("elsewhere", "src/notekeeper/other.py", Some(1));
        let third = entity_in("third", "src/notekeeper/third.py", Some(1));
        for entity in [&focal, &other, &third] {
            store.upsert_entity(entity).unwrap();
        }
        store
            .upsert_relation(&edge(RelationKind::Imports, &other, &third))
            .unwrap();

        let arrival = observe_caller_arrival(&store, &focal);
        assert_eq!(
            arrival.state,
            ArrivalState::Accounted,
            "a language that links imports elsewhere makes an unimported file a real empty family"
        );
        assert_eq!(arrival.family_files, 0);
        assert_eq!(arrival.limiting_factor(), None);
    }

    #[test]
    fn a_repository_larger_than_any_scan_cap_is_still_measured() {
        // The regression this guards shipped in the first draft of this module
        // and would have been invisible in every arm above: the reading built a
        // file index by loading the whole language and refused above a cap. On
        // any real repository that is every query. Kin's own Rust declares more
        // than seven thousand functions, so the gate would have reported
        // `unmeasured` for every focal in the store and put a floor under every
        // absence in it, which is the exact over-correction the ticket names.
        //
        // Five thousand entities in unrelated files, well past any cap a future
        // edit is likely to reintroduce. The verdict must still be the real one.
        let (store, focal) = store_with(Some(3), 2, true);
        for index in 0..5_000 {
            store
                .upsert_entity(&entity_in(
                    &format!("unrelated{index}"),
                    &format!("src/notekeeper/bulk{}.py", index % 250),
                    Some(1),
                ))
                .unwrap();
        }

        let arrival = observe_caller_arrival(&store, &focal);
        assert_eq!(
            arrival.state,
            ArrivalState::Unaccounted,
            "the reading must scale with the focal's file and its importers, never with the \
             repository; a cap on the language turns this into `unmeasured`"
        );
        assert_eq!(arrival.family_files, 1, "the family is unchanged by bulk");
        assert_eq!(arrival.unaccounted[0].file, CALLER_FILE);
    }

    #[test]
    fn a_family_too_large_to_examine_declines_rather_than_truncating() {
        // A hub imported by more files than the reading examines. Truncating and
        // reporting `accounted` would be the silent cap this module exists to
        // refuse, so the verdict is `unmeasured` and the reason carries the
        // number, which is the one word that does not overstate what was read.
        let store = InMemoryGraph::new();
        let focal = entity_in("note_body", FOCAL_FILE, Some(2));
        let focal_module = entity_in("storage", FOCAL_FILE, Some(2));
        store.upsert_entity(&focal).unwrap();
        store.upsert_entity(&focal_module).unwrap();
        for index in 0..(FAMILY_FILE_CAP + 1) {
            let importer = entity_in(
                &format!("importer{index}"),
                &format!("tests/test_{index}.py"),
                Some(1),
            );
            store.upsert_entity(&importer).unwrap();
            store
                .upsert_relation(&edge(RelationKind::Imports, &importer, &focal_module))
                .unwrap();
        }

        let arrival = observe_caller_arrival(&store, &focal);
        assert_eq!(arrival.state, ArrivalState::Unmeasured);
        let reason = arrival
            .unmeasured_reason
            .as_deref()
            .expect("an oversized family names its own size");
        assert!(
            reason.contains(&(FAMILY_FILE_CAP + 1).to_string()),
            "the reason must say how many files it did not examine: {reason}"
        );

        // The control that keeps the cap from being a blanket refusal: one file
        // under the cap is examined normally.
        let (small, small_focal) = store_with(Some(2), 2, true);
        assert_eq!(
            observe_caller_arrival(&small, &small_focal).state,
            ArrivalState::Accounted
        );
    }

    #[test]
    fn the_published_block_caps_its_evidence_and_says_so() {
        // The count the verdict rests on is never truncated; the rows a reader
        // audits it with are. The stranger's second recommendation was that the
        // envelope is eating the answer, with a two-row `find_references`
        // carrying close to eight kilobytes of it, so the block this module adds
        // must not be the reason the references get evicted. A silent cap would
        // be the same defect wearing this module's name.
        let store = InMemoryGraph::new();
        let focal = entity_in("note_body", FOCAL_FILE, Some(2));
        let focal_module = entity_in("storage", FOCAL_FILE, Some(2));
        store.upsert_entity(&focal).unwrap();
        store.upsert_entity(&focal_module).unwrap();
        let importers = EVIDENCE_ROW_CAP + 5;
        for index in 0..importers {
            // No parse-side count, so every one of them is unaccounted.
            let importer = entity_in(
                &format!("importer{index}"),
                &format!("tests/test_{index:03}.py"),
                None,
            );
            store.upsert_entity(&importer).unwrap();
            store
                .upsert_relation(&edge(RelationKind::Imports, &importer, &focal_module))
                .unwrap();
        }

        let arrival = observe_caller_arrival(&store, &focal);
        assert_eq!(arrival.state, ArrivalState::Unaccounted);
        assert_eq!(arrival.unaccounted.len(), importers);

        let block = arrival.to_json();
        assert_eq!(
            block["unaccounted_file_count"],
            json!(importers),
            "the count the verdict rests on is never truncated"
        );
        assert_eq!(
            block["unaccounted_files"].as_array().unwrap().len(),
            EVIDENCE_ROW_CAP,
            "the evidence rows are capped"
        );
        assert_eq!(
            block["unaccounted_files_truncated"],
            json!(true),
            "a capped list must say so, or a short list reads as a whole one"
        );
        // And the gate still fires off the capped block, because it keys on the
        // state and not on the row count. Its clause counts every file that
        // holds the gap, not the five it names, and says how many it left out.
        let gap = arrival_gap(&json!({ CALLER_ARRIVAL_KEY: block }))
            .expect("an unaccounted block is a gap");
        assert!(gap.starts_with(UNRESOLVED_ARRIVAL_LIMITING_FACTOR), "{gap}");
        assert!(
            gap.contains(&format!(
                "of the {importers} file(s) that import the focal's file, {importers} hold"
            )),
            "the clause counts every unaccounted file: {gap}"
        );
        assert!(
            gap.ends_with(&format!(" and {} more", importers - 5)),
            "five are named and the rest are counted: {gap}"
        );

        // An impact answer names three files per entity out of the same count.
        let impact = observe_impact_arrival(&store, &[focal.id]);
        let gaps = impact_arrival_gaps(&json!({ CALLER_ARRIVAL_KEY: impact }));
        assert!(
            gaps[0].contains(&format!(" and {} more]", importers - 3)),
            "the entity's own list says how many more files it holds: {gaps:?}"
        );

        // The control: a family under the cap publishes every row and says it
        // did not truncate, so the flag cannot become decoration.
        let (small, small_focal) = store_with(Some(3), 2, true);
        let small_block = observe_caller_arrival(&small, &small_focal).to_json();
        assert_eq!(small_block["unaccounted_file_count"], json!(1));
        assert_eq!(
            small_block["unaccounted_files"].as_array().unwrap().len(),
            1
        );
        assert_eq!(small_block["unaccounted_files_truncated"], json!(false));
    }

    #[test]
    fn no_factor_this_module_produces_carries_the_clause_separator() {
        // `crate::verdict` renders the one limiting factor as a single string and
        // a reader splits it back into clauses on "; ". A clause carrying that
        // separator arrives as a labelled clause plus a bare fragment with no
        // label at all, and the reader handed `limiting_factor` gets the
        // fragment. Two gap texts shipped that defect before this module existed.
        //
        // Mine would have been the third: both producers joined their file list
        // with "; ", and the guard that asserts this invariant drives
        // `negative::absence_coverage_clauses` by name, so it could not see a new
        // producer at all. This drives MY producers over the shapes that reach
        // them rather than restating their text, for the same reason that one
        // does: a test that restates the strings is a second copy of them.
        let mut seen = 0;
        for (label, arrival) in arrival_shapes() {
            if let Some(factor) = arrival.limiting_factor() {
                seen += 1;
                assert!(
                    !factor.contains(crate::verdict::CLAUSE_SEPARATOR),
                    "{label}: limiting_factor carries the clause separator, so any reader that \
                     splits the rendered factor cuts it into a labelled clause and an unlabelled \
                     fragment: {factor}"
                );
            }
            if let Some(gap) = arrival_gap(&json!({ CALLER_ARRIVAL_KEY: arrival.to_json() })) {
                seen += 1;
                assert!(
                    !gap.contains(crate::verdict::CLAUSE_SEPARATOR),
                    "{label}: arrival_gap carries the clause separator: {gap}"
                );
            }
        }
        assert!(
            seen > 0,
            "no factor was produced by any shape, so this asserted nothing"
        );
    }

    /// Every shape whose factor a reader can end up splitting, including the
    /// multi-file ones, which are the only ones that join anything at all and so
    /// the only ones that can carry a separator.
    fn arrival_shapes() -> Vec<(&'static str, CallerArrival)> {
        let one = UnaccountedFile {
            file: "tests/test_storage.py".to_string(),
            parsed_call_sites: Some(3),
            resolved_call_edges: 2,
            unaccounted_call_sites: Some(1),
            shortfall_is_floor: false,
            ..UnaccountedFile::default()
        };
        let ledgered = UnaccountedFile {
            file: "tests/test_index.py".to_string(),
            parsed_call_sites: Some(4),
            resolved_call_edges: 2,
            unaccounted_call_sites: Some(2),
            count_source: CountSource::SiteLedgers,
            count_exact: true,
            unsettled_by_state: [("unresolved", 1), ("binding", 1)].into_iter().collect(),
            ..UnaccountedFile::default()
        };
        let withheld = UnaccountedFile {
            file: "tests/test_linkgraph.py".to_string(),
            parsed_call_sites: None,
            resolved_call_edges: 4,
            unaccounted_call_sites: None,
            shortfall_is_floor: false,
            ..UnaccountedFile::default()
        };
        let many: Vec<UnaccountedFile> = (0..8)
            .map(|index| UnaccountedFile {
                file: format!("tests/test_{index}.py"),
                parsed_call_sites: Some(index + 2),
                resolved_call_edges: 1,
                unaccounted_call_sites: Some(index + 1),
                shortfall_is_floor: false,
                ..UnaccountedFile::default()
            })
            .collect();
        let build = |unaccounted: Vec<UnaccountedFile>| CallerArrival {
            state: ArrivalState::Unaccounted,
            family_files: unaccounted.len().max(1),
            family_measured: 0,
            unaccounted,
            unmeasured_reason: None,
            files_from_site_ledgers: 0,
            owed_callers: Vec::new(),
            call_sites: None,
            owed_outside: Some(Vec::new()),
            owed_callers_cannot_name_focal: 0,
            scan: None,
        };
        vec![
            ("one shortfall file", build(vec![one.clone()])),
            ("one withheld-count file", build(vec![withheld.clone()])),
            (
                "both kinds joined",
                build(vec![one.clone(), withheld.clone()]),
            ),
            ("a file counted from ledgers", build(vec![ledgered.clone()])),
            (
                "all three kinds joined",
                build(vec![one, withheld, ledgered]),
            ),
            ("more files than the factor names", build(many)),
            (
                "unmeasured",
                CallerArrival::unmeasured(
                    "this language links no imports across files in this graph",
                ),
            ),
        ]
    }

    /// A `Calls` edge carrying the exact source syntax the linker bound.
    ///
    /// `start_byte` is what separates two edges minted from ONE call site from
    /// two edges minted from two, which is the whole subject of the fan-out arm.
    fn call_edge_at(src: &Entity, dst: &Entity, file: &str, start_byte: usize) -> Relation {
        call_edge_collapsing(src, dst, file, start_byte, 1)
    }

    /// The same edge whose one evidence record stands for `occurrences`
    /// equivalent call sites the extractor folded together.
    ///
    /// Built from [`RelationEvidence::default`] rather than field by field, so a
    /// field added to the evidence record cannot leave this helper pinned to a
    /// stale shape while still compiling.
    fn call_edge_collapsing(
        src: &Entity,
        dst: &Entity,
        file: &str,
        start_byte: usize,
        occurrences: u32,
    ) -> Relation {
        Relation {
            id: RelationId::from_content(
                &src.id.0.to_string(),
                &dst.id.0.to_string(),
                &format!("Calls@{start_byte}x{occurrences}"),
            ),
            evidence: vec![RelationEvidence {
                source_span: Some(SourceSpan {
                    file: FilePathId::new(file),
                    start_byte,
                    end_byte: start_byte + 8,
                    start_line: start_byte as u32,
                    start_col: 0,
                    end_line: start_byte as u32,
                    end_col: 8,
                }),
                occurrence_count: occurrences,
                ..RelationEvidence::default()
            }],
            ..edge(RelationKind::Calls, src, dst)
        }
    }

    /// One caller file whose two parsed call sites became two edges, either from
    /// one site fanning out to two same-named destinations or from two separate
    /// sites.
    ///
    /// The review counterexample this exists for: with `fan_out` the aggregate
    /// relation count is 2 against 2 parsed sites, so a reading that counts
    /// relations subtracts to zero and certifies while one parsed site produced
    /// no edge at all.
    fn store_with_call_sites(fan_out: bool) -> (InMemoryGraph, Entity) {
        let store = InMemoryGraph::new();
        // The focal's own file parses no calls, so its own accounting is clean
        // and this arm reads only the family.
        let focal = entity_in("note_body", FOCAL_FILE, Some(0));
        let focal_module = entity_in("storage", FOCAL_FILE, Some(0));
        let find_note = entity_in("find_note", FOCAL_FILE, Some(0));
        let caller_module = entity_in("test_storage", CALLER_FILE, Some(2));
        let caller = entity_in("test_bodies_round_trip", CALLER_FILE, Some(2));
        for entity in [&focal, &focal_module, &find_note, &caller_module, &caller] {
            store.upsert_entity(entity).unwrap();
        }
        store
            .upsert_relation(&edge(RelationKind::Imports, &caller_module, &focal_module))
            .unwrap();
        store
            .upsert_relation(&call_edge_at(&caller, &find_note, CALLER_FILE, 100))
            .unwrap();
        let second_site = if fan_out { 100 } else { 200 };
        store
            .upsert_relation(&call_edge_at(
                &caller,
                &focal_module,
                CALLER_FILE,
                second_site,
            ))
            .unwrap();
        (store, focal)
    }

    /// FIR-2821 review, third P1, second counterexample. One parsed call site
    /// can fan out to several same-named destinations, and counting relations
    /// lets that fan-out pay for a DIFFERENT site that produced no edge.
    #[test]
    fn two_edges_minted_from_one_call_site_do_not_account_for_two() {
        let (store, focal) = store_with_call_sites(true);
        let arrival = observe_caller_arrival(&store, &focal);
        assert_eq!(
            arrival.state,
            ArrivalState::Unaccounted,
            "two edges from one span account for one site, so one of the two parsed sites \
             became no edge: {:?}",
            arrival.unaccounted
        );
        let row = &arrival.unaccounted[0];
        assert_eq!(row.resolved_call_edges, 1, "{row:?}");
        assert_eq!(row.unaccounted_call_sites, Some(1), "{row:?}");
    }

    /// The control, and it is the half that makes the arm above a measurement
    /// rather than a refusal: the same two edges at two distinct sites account
    /// for both parsed sites and still certify.
    #[test]
    fn two_edges_at_two_call_sites_account_for_both() {
        let (store, focal) = store_with_call_sites(false);
        let arrival = observe_caller_arrival(&store, &focal);
        assert_eq!(
            arrival.state,
            ArrivalState::Accounted,
            "two distinct spans are two accounted sites: {:?}",
            arrival.unaccounted
        );
    }

    /// The decline branch. Two parsed sites against two spanless edges is the
    /// case where the fan-out decides the answer: both edges from one site
    /// leaves a site missing, one from each accounts for both, and nothing here
    /// can tell those apart.
    ///
    /// Giving a spanless edge a weight of one would answer "accounted" for both
    /// readings, which is exactly the relation count the fan-out repair
    /// replaces. The two arms beside this one hold the other branches: one
    /// parsed site certifies, and a file short of edges reports a floor.
    #[test]
    fn a_file_whose_call_edges_carry_no_span_reads_unmeasured() {
        let (store, focal) = store_with_spanless_calls(2, 2);
        let arrival = observe_caller_arrival(&store, &focal);
        assert_eq!(
            arrival.state,
            ArrivalState::Unmeasured,
            "the resolved side could not be counted as sites, and a count that could not be \
             taken is not a clean one: {:?}",
            arrival.unaccounted
        );
        let reason = arrival.unmeasured_reason.unwrap_or_default();
        assert!(
            reason.contains(NO_CALL_SITE_SPAN_REASON),
            "the reason names what is missing rather than a cause it cannot know: {reason}"
        );
    }

    /// The three branches of the interval, stated as a table so each one is a
    /// row a mutation has to move rather than a sentence in a doc comment.
    ///
    /// `P` parsed sites, `S` joined sites, `R` spanless edges. The spanless
    /// edges stand for between one site and `R` sites, so the shortfall is a
    /// range and only its ends decide anything.
    #[test]
    fn the_shortfall_interval_certifies_floors_and_declines_in_the_right_places() {
        use FileShortfall::{AtLeast, None as NoShortfall, Undecidable};
        let cases: [(u64, u64, u64, FileShortfall, &str); 9] = [
            // Every edge joined, so the range collapses to a number.
            (0, 0, 0, NoShortfall, "nothing parsed, nothing to miss"),
            (2, 2, 0, NoShortfall, "two parsed, two joined sites"),
            (
                3,
                1,
                0,
                AtLeast(2),
                "two parsed sites became no edge, exactly",
            ),
            // Spanless edges, and the top of the range is zero.
            (0, 0, 3, NoShortfall, "no parsed site can go missing"),
            (1, 0, 1, NoShortfall, "one parsed site cannot hide a second"),
            (1, 0, 5, NoShortfall, "still one site, whatever the fan-out"),
            // Spanless edges, and the bottom of the range is above zero.
            (
                3,
                0,
                1,
                AtLeast(2),
                "at least two became no edge, whichever way",
            ),
            (
                5,
                1,
                2,
                AtLeast(2),
                "joined sites count first, then the floor",
            ),
            // Spanless edges, and the range straddles zero.
            (
                2,
                0,
                3,
                Undecidable,
                "the fan-out decides and this reading cannot",
            ),
        ];
        for (parsed, sites, spanless, expected, why) in cases {
            assert_eq!(
                file_shortfall(parsed, sites, spanless),
                expected,
                "P={parsed} S={sites} R={spanless}: {why}"
            );
        }
    }

    /// The certify branch, end to end. A file parsing one call site certifies
    /// however its edges fan out, because one site cannot hide a second.
    ///
    /// This is the branch that keeps the rule from withholding every verdict on
    /// the nine adapters that record no call site.
    #[test]
    fn one_parsed_call_site_certifies_even_with_spanless_edges() {
        let (store, focal) = store_with_spanless_calls(1, 3);
        let arrival = observe_caller_arrival(&store, &focal);
        assert_eq!(
            arrival.state,
            ArrivalState::Accounted,
            "one parsed site cannot fan out into a hidden second one: {:?}",
            arrival.unaccounted
        );
    }

    /// The floor branch, end to end. A file parsing more sites than it holds
    /// edges of any kind reports a real shortfall even when nothing joined, and
    /// says on the row that the number is a floor.
    ///
    /// The five and the two are load bearing. They put the interval at `[3, 4]`,
    /// where the floor and the ceiling differ, so the number below witnesses
    /// which end of the range the row reports. A pair that makes the two ends
    /// coincide, three parsed sites against one spanless edge, scores the same
    /// shortfall whichever end is read, and a reading taken off the top would
    /// pass this test unchanged.
    #[test]
    fn a_spanless_file_short_of_edges_reports_a_floor_rather_than_declining() {
        let (store, focal) = store_with_spanless_calls(5, 2);
        let arrival = observe_caller_arrival(&store, &focal);
        assert_eq!(
            arrival.state,
            ArrivalState::Unaccounted,
            "five parsed sites against two edges is short whichever way they fan: {:?}",
            arrival.unaccounted
        );
        let row = &arrival.unaccounted[0];
        assert_eq!(row.unaccounted_call_sites, Some(3), "{row:?}");
        assert!(
            row.shortfall_is_floor,
            "the row says the number is a floor, because a spanless edge leaves the resolved \
             side a range: {row:?}"
        );
    }

    /// And its control: the same shortfall where every edge joined is exact
    /// rather than a floor, so the flag separates the two claims instead of
    /// being set on everything.
    #[test]
    fn a_spanned_shortfall_is_exact_rather_than_a_floor() {
        let (store, focal) = store_with(Some(3), 1, true);
        let arrival = observe_caller_arrival(&store, &focal);
        let row = &arrival.unaccounted[0];
        assert_eq!(row.unaccounted_call_sites, Some(2), "{row:?}");
        assert!(
            !row.shortfall_is_floor,
            "every edge joined, so this count is exact: {row:?}"
        );
    }

    /// The spanless refusal owns its reason, and no other refusal borrows it.
    ///
    /// `Unmeasured` has four producers here, and a reader keying on the state
    /// cannot tell them apart. A reason shared between two causes is the join
    /// hazard this module tests elsewhere: an operator reading "could not be
    /// measured" would have no way to know whether to teach an adapter to emit
    /// spans or to look at an index that failed to read.
    #[test]
    fn only_the_spanless_refusal_carries_the_spanless_reason() {
        let (store, focal) = store_with_spanless_calls(2, 2);
        let reason = observe_caller_arrival(&store, &focal)
            .unmeasured_reason
            .unwrap_or_default();
        assert!(reason.contains(NO_CALL_SITE_SPAN_REASON), "{reason}");

        // The other producers of the same state, DRIVEN rather than quoted. A
        // control assembled from copies of the strings this module emits cannot
        // tell you what the producer actually says, so each of these reaches
        // `Unmeasured` through a real store and each must decline to borrow the
        // spanless phrase.
        let (no_imports_store, no_imports_focal) = store_with(Some(2), 0, false);
        let no_imports = observe_caller_arrival(&no_imports_store, &no_imports_focal);

        let orphan_store = InMemoryGraph::new();
        let mut orphan = entity_in("floating", FOCAL_FILE, Some(0));
        orphan.file_origin = None;
        orphan_store.upsert_entity(&orphan).unwrap();
        let no_file = observe_caller_arrival(&orphan_store, &orphan);

        for other in [&no_imports, &no_file] {
            assert_eq!(
                other.state,
                ArrivalState::Unmeasured,
                "this control is only a control while it reaches the same state: {other:?}"
            );
            let text = other.unmeasured_reason.clone().unwrap_or_default();
            assert!(
                !text.contains(NO_CALL_SITE_SPAN_REASON),
                "another producer of Unmeasured borrowed the spanless reason: {text}"
            );
        }
        // The index-unreadable branch is not driven here: an in-memory store
        // does not fail a read, so nothing in this test can reach it. Said out
        // loud rather than left as a silent hole in the enumeration.
    }

    /// The spanned control's second half: a store whose edges carry spans and
    /// whose parse side genuinely exceeds them reads Unaccounted with a real
    /// shortfall, not Unmeasured.
    ///
    /// Without this arm the clean control alone leaves the spanned path proven
    /// only where nothing is wrong, and a rule that declined every spanned store
    /// with a gap would pass it.
    #[test]
    fn a_spanned_store_with_a_real_shortfall_reads_unaccounted() {
        let (store, focal) = store_with(Some(3), 1, true);
        let arrival = observe_caller_arrival(&store, &focal);
        assert_eq!(
            arrival.state,
            ArrivalState::Unaccounted,
            "three parsed sites against one spanned edge is a measured shortfall: {:?}",
            arrival.unaccounted
        );
        let row = &arrival.unaccounted[0];
        assert_eq!(
            row.unaccounted_call_sites,
            Some(2),
            "and the shortfall is measured rather than absent: {row:?}"
        );
    }

    /// The control, and the half that keeps the arm above from being a refusal
    /// dressed as a measurement: the identical shape whose edges DO carry spans,
    /// which is what `python.rs` and `javascript.rs` produce, still measures and
    /// still certifies.
    #[test]
    fn a_file_whose_call_edges_carry_spans_still_measures() {
        let (store, focal) = store_with(Some(2), 2, true);
        let arrival = observe_caller_arrival(&store, &focal);
        assert_eq!(
            arrival.state,
            ArrivalState::Accounted,
            "two spanned edges at two sites account for two parsed sites: {:?}",
            arrival.unaccounted
        );
    }

    /// A raise-target marker record must not make its file unmeasurable.
    ///
    /// The linker attaches a span-free record beside the spanned one for a raise
    /// target, and its own comment says the record is deliberately span-free so
    /// no consumer counts it as a second site. Refusing on any span-free RECORD
    /// rather than on an unjoinable RELATION would make every Python file
    /// holding a `raise Foo()` unmeasurable on a marker that exists precisely so
    /// it counts for nothing.
    #[test]
    fn a_span_free_marker_beside_a_spanned_record_still_measures() {
        let store = InMemoryGraph::new();
        let focal = entity_in("note_body", FOCAL_FILE, Some(0));
        let focal_module = entity_in("storage", FOCAL_FILE, Some(0));
        let caller_module = entity_in("test_storage", CALLER_FILE, Some(1));
        let caller = entity_in("test_bodies_round_trip", CALLER_FILE, Some(1));
        for entity in [&focal, &focal_module, &caller_module, &caller] {
            store.upsert_entity(entity).unwrap();
        }
        store
            .upsert_relation(&edge(RelationKind::Imports, &caller_module, &focal_module))
            .unwrap();
        let mut call = call_edge_at(&caller, &focal_module, CALLER_FILE, 100);
        call.evidence.push(RelationEvidence {
            parser_rule: Some("python_raise_target_call".to_string()),
            ..RelationEvidence::default()
        });
        store.upsert_relation(&call).unwrap();

        let arrival = observe_caller_arrival(&store, &focal);
        assert_eq!(
            arrival.state,
            ArrivalState::Accounted,
            "the relation joined through its spanned record, so the marker beside it costs \
             nothing: {:?}",
            arrival.unaccounted
        );
    }

    /// The stranger's shape with span-free call edges, which is what the nine
    /// adapters that record no call site produce.
    fn store_with_spanless_calls(
        caller_parsed_calls: u64,
        caller_resolved_calls: usize,
    ) -> (InMemoryGraph, Entity) {
        let store = InMemoryGraph::new();
        let focal = entity_in("note_body", FOCAL_FILE, Some(0));
        let focal_module = entity_in("storage", FOCAL_FILE, Some(0));
        let caller_module = entity_in("test_storage", CALLER_FILE, Some(caller_parsed_calls));
        let caller = entity_in(
            "test_bodies_round_trip",
            CALLER_FILE,
            Some(caller_parsed_calls),
        );
        for entity in [&focal, &focal_module, &caller_module, &caller] {
            store.upsert_entity(entity).unwrap();
        }
        store
            .upsert_relation(&edge(RelationKind::Imports, &caller_module, &focal_module))
            .unwrap();
        for index in 0..caller_resolved_calls {
            store
                .upsert_relation(&Relation {
                    id: RelationId::from_content(
                        &caller.id.0.to_string(),
                        &focal_module.id.0.to_string(),
                        &format!("Calls{index}"),
                    ),
                    ..edge(RelationKind::Calls, &caller, &focal_module)
                })
                .unwrap();
        }
        (store, focal)
    }

    /// A record standing for several folded occurrences is several sites.
    ///
    /// The extractor may fold equivalent call sites into one evidence record and
    /// say how many through `occurrence_count`. A join keyed on the span alone
    /// would read three occurrences as one site and report a shortfall that is
    /// an artifact of the fold rather than a fact about the code.
    #[test]
    fn a_folded_evidence_record_counts_every_occurrence_it_stands_for() {
        let store = InMemoryGraph::new();
        let focal = entity_in("note_body", FOCAL_FILE, Some(0));
        let focal_module = entity_in("storage", FOCAL_FILE, Some(0));
        let find_note = entity_in("find_note", FOCAL_FILE, Some(0));
        let caller_module = entity_in("test_storage", CALLER_FILE, Some(3));
        let caller = entity_in("test_bodies_round_trip", CALLER_FILE, Some(3));
        for entity in [&focal, &focal_module, &find_note, &caller_module, &caller] {
            store.upsert_entity(entity).unwrap();
        }
        store
            .upsert_relation(&edge(RelationKind::Imports, &caller_module, &focal_module))
            .unwrap();
        // Three parsed sites: two folded into one record, and one on its own.
        store
            .upsert_relation(&call_edge_collapsing(
                &caller,
                &find_note,
                CALLER_FILE,
                100,
                2,
            ))
            .unwrap();
        store
            .upsert_relation(&call_edge_at(&caller, &focal_module, CALLER_FILE, 300))
            .unwrap();

        let arrival = observe_caller_arrival(&store, &focal);
        assert_eq!(
            arrival.state,
            ArrivalState::Accounted,
            "two folded occurrences plus one site account for all three parsed sites: {:?}",
            arrival.unaccounted
        );
    }

    /// The delete-list fixture: one family file, counts present on both sides,
    /// and the focal's own file accounted for. `family_parsed` is what the
    /// parser read in the caller and `focal_parsed` what it read beside the
    /// focal, so each arm names which side it moved.
    fn store_for_absence(
        family_parsed: Option<u64>,
        focal_parsed: Option<u64>,
    ) -> (InMemoryGraph, Entity) {
        let store = InMemoryGraph::new();
        let focal = entity_in("note_body", FOCAL_FILE, focal_parsed);
        let focal_module = entity_in("storage", FOCAL_FILE, focal_parsed);
        let caller_module = entity_in("test_storage", CALLER_FILE, family_parsed);
        let caller = entity_in("test_bodies_round_trip", CALLER_FILE, family_parsed);
        for entity in [&focal, &focal_module, &caller_module, &caller] {
            store.upsert_entity(entity).unwrap();
        }
        store
            .upsert_relation(&edge(RelationKind::Imports, &caller_module, &focal_module))
            .unwrap();
        // The caller's one parsed call site, bound. Nothing calls the focal.
        store
            .upsert_relation(&call_edge_at(&caller, &focal_module, CALLER_FILE, 100))
            .unwrap();
        (store, focal)
    }

    /// FIR-2821 review, first P1. A family file the store holds no parse-side
    /// count for is `Unaccounted`, and only `Accounted` licenses an absence, so
    /// a delete list may not read the missing measurement as a clean one. This
    /// is the state a converted store is in for nearly every file today.
    #[test]
    fn a_family_file_with_no_parse_count_does_not_license_a_delete() {
        let (store, focal) = store_for_absence(None, Some(0));
        assert_eq!(
            observe_caller_arrival(&store, &focal).state,
            ArrivalState::Unaccounted,
            "the reading itself refuses; the gate under test is whether the consumer agrees"
        );
        let (factor, reason) = absence_gap(&store, &focal)
            .expect("a family file with no parse count cannot license a delete");
        assert_eq!(factor, UNMEASURED_ARRIVAL_LIMITING_FACTOR);
        assert!(
            reason.contains("no parse-side call count for 1 of the 1 file(s)"),
            "the reason states what is missing rather than naming a cause it cannot know: \
             {reason}"
        );
    }

    /// The control the arm above needs: the identical shape with the count
    /// present and every site accounted for licenses the delete. Without it a
    /// gate that refused everything would pass that arm.
    #[test]
    fn a_fully_accounted_family_licenses_a_delete() {
        let (store, focal) = store_for_absence(Some(1), Some(0));
        assert_eq!(
            observe_caller_arrival(&store, &focal).state,
            ArrivalState::Accounted
        );
        assert_eq!(absence_gap(&store, &focal), None);
    }

    /// FIR-2821 review, third P1, first counterexample. The family is by
    /// construction the files that name the focal's file from OUTSIDE it, so a
    /// call sitting beside the focal that the linker dropped is invisible to the
    /// family arithmetic. A delete list has to account for that file too.
    #[test]
    fn a_dropped_call_beside_the_focal_does_not_license_a_delete() {
        let (store, focal) = store_for_absence(Some(1), Some(2));
        assert_eq!(
            observe_caller_arrival(&store, &focal).state,
            ArrivalState::Accounted,
            "the family accounts for itself, which is exactly why the family alone is not \
             enough"
        );
        let (factor, reason) = absence_gap(&store, &focal).expect(
            "two call sites beside the focal became no edge, and one of them could be a \
                     call to the focal",
        );
        assert_eq!(factor, UNRESOLVED_ARRIVAL_LIMITING_FACTOR);
        assert!(
            reason.contains("2 of the 2 call sites the parser read in that same file"),
            "{reason}"
        );
    }

    /// The other half of the same-file rule: a focal whose own file holds no
    /// parse-side count cannot be certified either, because the call beside it
    /// was not counted rather than counted at zero.
    #[test]
    fn a_focal_file_with_no_parse_count_does_not_license_a_delete() {
        let (store, focal) = store_for_absence(Some(1), None);
        let (factor, reason) =
            absence_gap(&store, &focal).expect("an uncounted focal file cannot license a delete");
        assert_eq!(factor, UNMEASURED_ARRIVAL_LIMITING_FACTOR);
        assert!(
            reason.contains("no parse-side call count for that file itself"),
            "{reason}"
        );
    }

    #[test]
    fn an_unreported_block_is_not_read_as_accounted() {
        // A payload carrying no block at all yields no gap, because there is
        // nothing to read; the tool always publishes one, and this pins that the
        // reader never invents an "accounted" from silence.
        assert_eq!(arrival_gap(&json!({})), None);
        // An unknown state is refused rather than treated as whole.
        let gap = arrival_gap(&json!({ CALLER_ARRIVAL_KEY: { "state": "probably_fine" } }))
            .expect("an unrecognized state cannot license an absence");
        assert!(gap.starts_with("caller_arrival_state_unknown"), "{gap}");
    }

    /// The impact reading is the reference reading, taken per entity. On one
    /// store and one focal both surfaces have to refuse together or certify
    /// together, under the same code, or an agent learns which tool to ask
    /// rather than what is true.
    #[test]
    fn impact_and_references_reach_one_verdict_on_one_reading() {
        for (parsed, resolved, refuses) in [(Some(3), 2, true), (Some(2), 2, false)] {
            let (store, focal) = store_with(parsed, resolved, true);
            let references = json!({
                CALLER_ARRIVAL_KEY: observe_caller_arrival(&store, &focal).to_json(),
            });
            let impact = json!({
                CALLER_ARRIVAL_KEY: observe_impact_arrival(&store, &[focal.id]),
            });
            let from_references = arrival_gap(&references);
            let from_impact = impact_arrival_gaps(&impact);
            assert_eq!(
                from_references.is_some(),
                refuses,
                "the reference reading: {from_references:?}"
            );
            assert_eq!(
                !from_impact.is_empty(),
                refuses,
                "the impact reading disagreed with the reference reading on one store: \
                 {from_impact:?}"
            );
            if refuses {
                assert!(
                    from_impact[0].starts_with(UNRESOLVED_ARRIVAL_LIMITING_FACTOR),
                    "the same code, so the verdict names the same gap: {from_impact:?}"
                );
                assert!(
                    from_impact[0].contains(CALLER_FILE) && from_impact[0].contains("note_body"),
                    "the clause names the entity and the file its caller may be in: \
                     {from_impact:?}"
                );
            }
        }
    }

    #[test]
    fn impact_uses_each_same_file_focals_name_for_owed_family_callers() {
        let (store, focal) = store_with(Some(1), 0, true);
        let sibling = find_note();
        let (mut module, mut caller) = caller_file_entities(Some(1));
        for entity in [&mut module, &mut caller] {
            entity.metadata.extra.insert(
                kin_parser::extract::EMBEDDING_BODY_PREVIEW_KEY.into(),
                json!("note_body()"),
            );
            store.upsert_entity(entity).unwrap();
        }

        for ids in [[focal.id, sibling.id], [sibling.id, focal.id]] {
            let block = observe_impact_arrival(&store, &ids);
            let rows = block["entities"].as_array().unwrap();
            for (entity, cannot_name) in [(&focal, 0), (&sibling, 2)] {
                let mut expected = observe_caller_arrival(&store, entity).fields_json();
                expected["entity_id"] = json!(entity.id.to_string());
                expected["name"] = json!(entity.name);
                expected["file"] = json!(FOCAL_FILE);
                let row = rows
                    .iter()
                    .find(|row| row["entity_id"] == entity.id.to_string())
                    .unwrap();
                assert_eq!(
                    row, &expected,
                    "a preceding focal cannot change this reading"
                );
                assert_eq!(
                    row["owed_callers_cannot_name_focal"].as_u64().unwrap_or(0),
                    cannot_name,
                    "only note_body is named by the owed callers: {block}"
                );
            }
        }
    }

    #[test]
    fn impact_keeps_owed_outside_callers_for_each_same_file_focal_in_either_order() {
        let store = InMemoryGraph::new();
        let focal = entity_in("note_body", FOCAL_FILE, Some(0));
        let sibling = entity_in("find_note", FOCAL_FILE, Some(0));
        let mut other = entity_in("elsewhere", "src/other.py", Some(0));
        other.metadata.extra.insert(
            kin_parser::extract::EMBEDDING_BODY_PREVIEW_KEY.into(),
            json!("pass"),
        );
        let mut caller = entity_in("test_body", CALLER_FILE, Some(1));
        caller.metadata.extra.insert(
            kin_parser::extract::EMBEDDING_BODY_PREVIEW_KEY.into(),
            json!("note_body()"),
        );
        for entity in [&focal, &sibling, &other, &caller] {
            store.upsert_entity(entity).unwrap();
        }
        // Import linking works, but the caller reaches the focal without an
        // import into its file, so only the outside-family reading sees it.
        store
            .upsert_relation(&edge(RelationKind::Imports, &focal, &other))
            .unwrap();

        for ids in [[focal.id, sibling.id], [sibling.id, focal.id]] {
            let block = observe_impact_arrival(&store, &ids);
            let rows = block["entities"].as_array().unwrap();
            let focal_row = rows
                .iter()
                .find(|row| row["entity_id"] == focal.id.to_string())
                .unwrap();
            let sibling_row = rows
                .iter()
                .find(|row| row["entity_id"] == sibling.id.to_string())
                .unwrap();
            assert_eq!(focal_row["owed_outside_scope"]["callers"], 1, "{block}");
            assert!(sibling_row.get("owed_outside_scope").is_none(), "{block}");
            assert_eq!(block["owed_outside_scope"]["callers"], 1, "{block}");
            assert_eq!(block["owed_outside_scope"]["file_count"], 1, "{block}");
            assert_eq!(
                block["owed_outside_scope"]["files"][0]["file"], CALLER_FILE,
                "{block}"
            );
            let gaps = impact_arrival_gaps(&json!({ CALLER_ARRIVAL_KEY: block }));
            assert_eq!(
                gaps.len(),
                1,
                "the owed caller still limits impact: {gaps:?}"
            );
        }
    }

    #[test]
    fn impact_unions_distinct_and_shared_owed_outside_callers() {
        let store = InMemoryGraph::new();
        let focal = entity_in("note_body", FOCAL_FILE, Some(0));
        let sibling = entity_in("find_note", FOCAL_FILE, Some(0));
        let mut other = entity_in("elsewhere", "src/other.py", Some(0));
        other.metadata.extra.insert(
            kin_parser::extract::EMBEDDING_BODY_PREVIEW_KEY.into(),
            json!("pass"),
        );
        for entity in [&focal, &sibling, &other] {
            store.upsert_entity(entity).unwrap();
        }
        store
            .upsert_relation(&edge(RelationKind::Imports, &focal, &other))
            .unwrap();
        for (name, body) in [
            ("body_only", "note_body()"),
            ("find_only", "find_note()"),
            ("shared", "note_body(); find_note()"),
        ] {
            let mut caller = entity_in(name, CALLER_FILE, Some(4));
            caller.metadata.extra.insert(
                kin_parser::extract::EMBEDDING_BODY_PREVIEW_KEY.into(),
                json!(body),
            );
            store.upsert_entity(&caller).unwrap();
        }

        for ids in [
            vec![focal.id, sibling.id],
            vec![sibling.id, focal.id],
            vec![focal.id, sibling.id, focal.id],
        ] {
            let block = observe_impact_arrival(&store, &ids);
            for row in block["entities"].as_array().unwrap() {
                assert_eq!(row["owed_outside_scope"]["callers"], 2, "{block}");
            }
            assert_eq!(block["owed_outside_scope"]["callers"], 3, "{block}");
            assert_eq!(block["owed_outside_scope"]["file_count"], 1, "{block}");
            assert_eq!(
                block["owed_outside_scope"]["files"][0]["callers"], 3,
                "{block}"
            );
            let gap = owed_outside_gap(&json!({ CALLER_ARRIVAL_KEY: block })).unwrap();
            assert!(gap.contains("3 caller(s) in 1 file(s)"), "{gap}");
        }
    }

    /// Several zeros at once, with every kind of gap and a clean one. Each kind
    /// makes one clause naming its entities, the clean entity makes none, and no
    /// clause carries the separator a reader splits the factor on.
    #[test]
    fn an_impact_answer_with_several_zeros_names_each_gap_once() {
        let (store, focal) = store_with(Some(3), 2, true);
        // Shares the focal's file and the same unaccounted call sites.
        let sibling = entity_in("find_note", FOCAL_FILE, Some(2));
        // An id the graph does not hold, which is how a removed entity arrives.
        let removed = EntityId::from_content("src/gone.py", "gone", "Function", 0);

        let block = observe_impact_arrival(&store, &[focal.id, sibling.id, removed]);
        assert_eq!(block["state"], json!("unaccounted"), "{block}");
        assert_eq!(block["entities_examined"], json!(3));
        assert_eq!(block["unaccounted_entity_count"], json!(2));
        assert_eq!(block["unmeasured_entity_count"], json!(1));
        assert_eq!(block["entities"].as_array().map(Vec::len), Some(3));
        assert_eq!(block["entities_truncated"], json!(false));

        let gaps = impact_arrival_gaps(&json!({ CALLER_ARRIVAL_KEY: block }));
        assert_eq!(gaps.len(), 2, "one clause per kind of gap: {gaps:?}");
        assert!(
            gaps[0].starts_with(UNRESOLVED_ARRIVAL_LIMITING_FACTOR),
            "{gaps:?}"
        );
        assert!(gaps[0].contains("2 of the 3 entities"), "{gaps:?}");
        assert!(
            gaps[0].contains("note_body") && gaps[0].contains("find_note"),
            "{gaps:?}"
        );
        assert!(
            gaps[1].starts_with(UNMEASURED_ARRIVAL_LIMITING_FACTOR),
            "{gaps:?}"
        );
        assert!(gaps[1].contains("not in the graph"), "{gaps:?}");
        for gap in &gaps {
            assert!(
                !gap.contains(crate::verdict::CLAUSE_SEPARATOR),
                "a clause carrying the separator reaches a reader as a labelled clause and an \
                 unlabelled fragment: {gap}"
            );
        }
    }

    /// More refusing entities than the block lists. The count still carries
    /// every one, and a kind of gap the capped rows leave out says it names none
    /// of its entities rather than ending on an empty list.
    #[test]
    fn a_gap_the_capped_rows_leave_out_is_still_counted_and_worded() {
        let (store, focal) = store_with(Some(3), 2, true);
        let mut ids = vec![focal.id];
        for index in 0..EVIDENCE_ROW_CAP {
            let sibling = entity_in(&format!("sibling_{index}"), FOCAL_FILE, Some(2));
            store.upsert_entity(&sibling).unwrap();
            ids.push(sibling.id);
        }
        ids.push(EntityId::from_content("src/gone.py", "gone", "Function", 0));

        let block = observe_impact_arrival(&store, &ids);
        assert_eq!(
            block["unaccounted_entity_count"],
            json!(EVIDENCE_ROW_CAP + 1)
        );
        assert_eq!(block["unmeasured_entity_count"], json!(1));
        assert_eq!(block["entities_truncated"], json!(true));

        let gaps = impact_arrival_gaps(&json!({ CALLER_ARRIVAL_KEY: block }));
        assert_eq!(gaps.len(), 2, "{gaps:?}");
        assert!(gaps[0].contains("and 6 more"), "{gaps:?}");
        assert!(
            gaps[1].ends_with("1 not among the listed entities"),
            "{gaps:?}"
        );
    }

    /// Each published block states what the reading counts and what it cannot
    /// read. A reference block carries it beside its fields; an impact block
    /// carries it once beside its rows rather than once per row, because the
    /// rows are capped so the block cannot crowd out the answer.
    #[test]
    fn every_published_block_states_the_reading_s_scope_once() {
        let (store, focal) = store_with(Some(2), 2, true);
        let block = observe_caller_arrival(&store, &focal).to_json();
        assert_eq!(block["scope"], json!(ARRIVAL_READING_SCOPE));

        let (store, focal) = store_with(Some(3), 2, true);
        let impact = observe_impact_arrival(&store, &[focal.id]);
        assert_eq!(impact["scope"], json!(ARRIVAL_READING_SCOPE));
        let rows = impact["entities"].as_array().unwrap();
        assert!(!rows.is_empty());
        assert!(
            rows.iter().all(|row| row.get("scope").is_none()),
            "the rows do not repeat it: {impact}"
        );
        for limit in [
            "a same-named definition in the caller's own file",
            "an import edge into the focal's file",
        ] {
            assert!(ARRIVAL_READING_SCOPE.contains(limit), "{limit}");
        }
    }

    /// A certified absence recites the reading and its scope only where the
    /// reading certified. A refusing or inapplicable block is not a
    /// certification, and a tool that never reads the block has none to recite.
    #[test]
    fn only_a_reading_that_certified_is_recited_as_one() {
        let (store, focal) = store_with(Some(2), 2, true);
        let accounted =
            json!({ CALLER_ARRIVAL_KEY: observe_caller_arrival(&store, &focal).to_json() });
        let clause = arrival_certification_clause("find_references", &accounted)
            .expect("an accounted reading is recited");
        assert!(clause.contains(ARRIVAL_READING_SCOPE), "{clause}");
        assert!(arrival_certification_clause("get_context_pack", &accounted).is_some());
        assert!(arrival_certification_clause("graph_neighborhood", &accounted).is_none());

        let (store, focal) = store_with(Some(3), 2, true);
        let unaccounted =
            json!({ CALLER_ARRIVAL_KEY: observe_caller_arrival(&store, &focal).to_json() });
        assert!(arrival_certification_clause("find_references", &unaccounted).is_none());

        let none = json!({ CALLER_ARRIVAL_KEY: observe_impact_arrival(&store, &[]) });
        assert!(arrival_certification_clause("impact_analysis", &none).is_none());
        assert!(arrival_certification_clause("find_references", &json!({})).is_none());
    }

    /// The controls. An answer that reports no zero has nothing for the reading
    /// to qualify, and one whose zeros are all accounted for certifies, so the
    /// gate cannot pass by refusing everything.
    #[test]
    fn an_impact_answer_with_no_unaccounted_zero_is_not_gated() {
        let (store, focal) = store_with(Some(2), 2, true);

        let none = observe_impact_arrival(&store, &[]);
        assert_eq!(none["state"], json!(IMPACT_ARRIVAL_NOT_APPLICABLE));
        assert!(impact_arrival_gaps(&json!({ CALLER_ARRIVAL_KEY: none })).is_empty());

        let accounted = observe_impact_arrival(&store, &[focal.id]);
        assert_eq!(accounted["state"], json!("accounted"), "{accounted}");
        assert!(impact_arrival_gaps(&json!({ CALLER_ARRIVAL_KEY: accounted })).is_empty());

        // And a block this reader did not write is refused, never read as clear.
        let gaps = impact_arrival_gaps(&json!({ CALLER_ARRIVAL_KEY: { "state": "fine" } }));
        assert_eq!(gaps.len(), 1);
        assert!(
            gaps[0].starts_with("caller_arrival_state_unknown"),
            "{gaps:?}"
        );
    }

    /// The callers of the stranger's test file, as `store_with` minted them.
    fn caller_file_entities(parsed: Option<u64>) -> (Entity, Entity) {
        (
            entity_in("test_storage", CALLER_FILE, parsed),
            entity_in("test_bodies_round_trip", CALLER_FILE, parsed),
        )
    }

    /// Ledgers for the test file's callers under one proof context: the
    /// module's with no call, and the test's with one site per state.
    fn ledgers_for(
        store: &InMemoryGraph,
        module: Option<&Entity>,
        caller: Option<(&Entity, Vec<kin_model::CallSiteState>)>,
    ) {
        use crate::call_sites::fixture::{admit, id_of, ledger, proof_context};
        let context = proof_context(LanguageId::Python, "1.1.400");
        let context_id = id_of(&context);
        let mut records = vec![context];
        if let Some(module) = module {
            records.push(ledger(module, "", context_id, Vec::new()));
        }
        if let Some((caller, states)) = caller {
            let tokens = ["ab", "cd", "ef", "gh"];
            records.push(ledger(
                caller,
                "abcdefghij",
                context_id,
                tokens.into_iter().zip(states).collect(),
            ));
        }
        admit(store, &[], records);
    }

    fn find_note() -> Entity {
        entity_in("find_note", FOCAL_FILE, Some(2))
    }

    #[test]
    fn a_family_file_whose_callers_all_hold_ledgers_is_counted_exactly_from_them() {
        use kin_model::CallSiteState;
        // Three parsed sites and one edge, which the arithmetic reads as two
        // sites that went nowhere. The ledgers say every one of the three was
        // settled: one into the focal's sibling, two outside the repository.
        let (store, focal) = store_with(Some(3), 1, true);
        let (module, caller) = caller_file_entities(Some(3));
        ledgers_for(
            &store,
            Some(&module),
            Some((
                &caller,
                vec![
                    CallSiteState::ProvenTarget {
                        target: find_note().id,
                    },
                    CallSiteState::ProvenOutside,
                    CallSiteState::ProvenOutside,
                ],
            )),
        );
        let arrival = observe_caller_arrival(&store, &focal);
        let block = arrival.to_json();
        assert_eq!(arrival.state, ArrivalState::Accounted, "{block}");
        assert_eq!(block["count_exact"], true, "{block}");
        assert_eq!(block["files_counted_from_site_ledgers"], 1, "{block}");
        assert_eq!(block["owed_caller_count"], 0, "{block}");
        let tally = arrival.call_sites.as_ref().expect("the family is tallied");
        assert_eq!(tally.callers, 2);
        assert_eq!(tally.sites, 3);
        assert!(tally.is_settled());
    }

    #[test]
    fn an_unsettled_site_in_a_ledgered_family_file_is_an_exact_count() {
        use kin_model::CallSiteState;
        let (store, focal) = store_with(Some(3), 1, true);
        let (module, caller) = caller_file_entities(Some(3));
        ledgers_for(
            &store,
            Some(&module),
            Some((
                &caller,
                vec![
                    CallSiteState::ProvenTarget {
                        target: find_note().id,
                    },
                    CallSiteState::Unresolved {
                        reason: kin_model::UnresolvedReason::NoAnswer,
                    },
                    CallSiteState::ProvenOutside,
                ],
            )),
        );
        let arrival = observe_caller_arrival(&store, &focal);
        let block = arrival.to_json();
        assert_eq!(arrival.state, ArrivalState::Unaccounted, "{block}");
        let row = &block["unaccounted_files"][0];
        assert_eq!(row["file"], CALLER_FILE, "{block}");
        assert_eq!(row["count_source"], "site_ledgers", "{block}");
        assert_eq!(row["count_exact"], true, "{block}");
        assert_eq!(row["unaccounted_call_sites"], 1, "{block}");
        assert_eq!(row["parsed_call_sites"], 3, "{block}");
        assert_eq!(row["resolved_call_edges"], 2, "{block}");
        assert_eq!(
            row["unsettled_by_state"],
            json!({"unresolved": 1}),
            "{block}"
        );
        let factor = arrival
            .limiting_factor()
            .expect("an unsettled site limits the answer");
        assert!(
            factor.contains("1 of 3 call sites are not settled, an exact count from site ledgers"),
            "{factor}"
        );
        assert!(!factor.contains("; "), "{factor}");
        let gap = arrival_gap(&json!({ CALLER_ARRIVAL_KEY: block })).expect("the gate reads it");
        assert!(gap.contains("1 unsettled, exact"), "{gap}");
    }

    #[test]
    fn a_family_file_with_an_owed_caller_keeps_the_arithmetic_and_names_the_caller() {
        use kin_model::CallSiteState;
        let (store, focal) = store_with(Some(3), 1, true);
        let (module, caller) = caller_file_entities(Some(3));
        ledgers_for(
            &store,
            None,
            Some((&caller, vec![CallSiteState::ProvenOutside; 3])),
        );
        let arrival = observe_caller_arrival(&store, &focal);
        let block = arrival.to_json();
        assert_eq!(arrival.state, ArrivalState::Unaccounted, "{block}");
        assert_eq!(block["count_exact"], false, "{block}");
        assert_eq!(block["files_counted_from_site_ledgers"], 0, "{block}");
        let row = &block["unaccounted_files"][0];
        assert_eq!(row["count_source"], "parse_versus_edges", "{block}");
        assert_eq!(row["count_exact"], false, "{block}");
        assert_eq!(
            row["unaccounted_call_sites"], 2,
            "the arithmetic stands: {block}"
        );
        assert_eq!(row["owed_callers"], 1, "{block}");
        assert_eq!(block["owed_caller_count"], 1, "{block}");
        assert_eq!(
            block["owed_callers"],
            json!([{
                "id": module.id.to_string(),
                "name": "test_storage",
                "file": CALLER_FILE,
                "reading": "owed_enrichment",
            }]),
            "{block}"
        );
        let tally = arrival.call_sites.as_ref().expect("the family is tallied");
        assert_eq!(tally.callers_owed_enrichment, 1);
        assert!(!tally.is_settled());
    }
}
