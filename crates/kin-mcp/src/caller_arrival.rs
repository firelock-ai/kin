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
//!   file at extraction, and WITHHELD from a file whose call extraction the
//!   parser could not fully represent, which as this is written is nearly every
//!   real Python file; FIR-2828 publishes the count beside a completeness flag
//!   instead, and this paragraph is stale the day that lands),
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
#[derive(Debug, Clone, Serialize)]
pub struct UnaccountedFile {
    pub file: String,
    /// `None` when the file carries no parse-side count, which the parser omits
    /// on any file whose call extraction it could not represent, and which as
    /// this is written is nearly every real Python file until FIR-2828 lands.
    /// Absent, not zero, and it is its own kind of gap.
    pub parsed_call_sites: Option<u64>,
    pub resolved_call_edges: u64,
    /// `parsed - resolved`, floored at zero. `None` when the parse side was not
    /// measured.
    pub unaccounted_call_sites: Option<u64>,
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
}

impl CallerArrival {
    fn unmeasured(reason: impl Into<String>) -> Self {
        Self {
            state: ArrivalState::Unmeasured,
            family_files: 0,
            family_measured: 0,
            unaccounted: Vec::new(),
            unmeasured_reason: Some(reason.into()),
        }
    }

    /// The block `find_references` publishes, and the one the negative envelope
    /// reads back. Published on every answer, populated or empty, so a reader
    /// never has to tell "checked and fine" from "not reported".
    pub fn to_json(&self) -> serde_json::Value {
        json!({
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
        })
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
                    .map(|file| match file.unaccounted_call_sites {
                        Some(missing) => format!(
                            "{} ({missing} of {} parsed call sites became no edge)",
                            file.file,
                            file.parsed_call_sites.unwrap_or(0)
                        ),
                        None => format!(
                            "{} (the store holds no parse-side call count for this file, so \
                             its call sites could not be accounted for)",
                            file.file
                        ),
                    })
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
/// The extractor withholds the key rather than reporting a count it cannot
/// stand behind, and as this is written it withholds it from nearly every real
/// Python file, which is why the uncounted branch below is the common case
/// rather than an edge. FIR-2828 changes that by publishing the count beside a
/// completeness flag; when it lands, "nearly every" stops being true here and
/// the measured branch becomes the common one. Nothing in this function needs
/// to change for that, but this sentence does.
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
) -> Option<(Vec<(EntityId, kin_model::EntityKind)>, Option<u64>)> {
    let entities = store
        .query_entities(&EntityFilter {
            file_path: Some(file.clone()),
            ..EntityFilter::default()
        })
        .ok()?;
    let parsed = entities.iter().find_map(parsed_call_sites);
    Some((
        entities
            .into_iter()
            .map(|entity| (entity.id, entity.kind))
            .collect(),
        parsed,
    ))
}

/// What one file's resolved side came to, or why it could not be taken.
enum ResolvedSites {
    /// Every `Calls` edge from this file's entities joined to a call site, and
    /// this is how many distinct sites they came to.
    Counted(u64),
    /// At least one `Calls` edge records no call-site span in this file, so the
    /// resolved side cannot be compared with a parse side that counts sites.
    /// Not zero, and not a count with that edge dropped.
    Unjoinable,
    /// The relation index could not be read.
    Unreadable,
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
/// certifies while three sites became nothing. So an unjoinable edge makes the
/// file UNMEASURABLE rather than counting as a site, which is the same ruling
/// an absent parse-side count gets and for the same reason: a measurement that
/// could not be taken is not a clean one.
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
    entity_ids: &[(EntityId, kin_model::EntityKind)],
) -> ResolvedSites {
    let mut sites: std::collections::HashMap<(usize, usize), u64> =
        std::collections::HashMap::new();
    for (entity_id, _) in entity_ids {
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
                return ResolvedSites::Unjoinable;
            }
        }
    }
    ResolvedSites::Counted(sites.values().sum::<u64>())
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
    let Some((entity_ids, parsed)) = file_entities(store, file) else {
        return Err("the entity index could not be read for the focal's own file".to_string());
    };
    let resolved = match resolved_call_sites(store, file, &entity_ids) {
        ResolvedSites::Counted(resolved) => resolved,
        ResolvedSites::Unjoinable => {
            return Err(format!(
                "{} {NO_CALL_SITE_SPAN_REASON}, so the calls made there could not be counted as \
                 sites and a fan-out there could hide a call to the row that became no edge",
                file.0
            ))
        }
        ResolvedSites::Unreadable => {
            return Err("the relation index could not be read for the focal's own file".to_string())
        }
    };
    let missing = parsed.map(|parsed| parsed.saturating_sub(resolved));
    if missing.is_some_and(|missing| missing == 0) {
        return Ok(None);
    }
    Ok(Some(UnaccountedFile {
        file: file.0.clone(),
        parsed_call_sites: parsed,
        resolved_call_edges: resolved,
        unaccounted_call_sites: missing,
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
    let Some(focal_file) = focal.file_origin.clone() else {
        return CallerArrival::unmeasured("the focal entity carries no file of origin");
    };

    let Some((focal_file_entities, _)) = file_entities(store, &focal_file) else {
        return CallerArrival::unmeasured(
            "the entity index could not be read for the focal's file",
        );
    };
    let focal_owned: HashSet<EntityId> = focal_file_entities.iter().map(|(id, _)| *id).collect();
    // The destinations a module binding may land on. Kept separate from
    // `focal_owned` so the widened edge class cannot admit a bare mention of a
    // function in this file as if it were an import of the file.
    let focal_modules: HashSet<EntityId> = focal_file_entities
        .iter()
        .filter(|(_, kind)| *kind == kin_model::EntityKind::Module)
        .map(|(id, _)| *id)
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
    for (entity_id, _) in &focal_file_entities {
        let Ok(relations) = store.get_all_relations_for_entity(entity_id) else {
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
    for file in &family_files {
        let Some((entity_ids, parsed)) = file_entities(store, file) else {
            return CallerArrival::unmeasured(
                "the entity index could not be read for a file in the focal's family",
            );
        };
        if parsed.is_some() {
            family_measured += 1;
        }
        let resolved = match resolved_call_sites(store, file, &entity_ids) {
            ResolvedSites::Counted(resolved) => resolved,
            // Fail closed rather than fall back to counting relations, which is
            // the arithmetic the fan-out repair exists to replace. Nine of the
            // eleven adapters that emit `Calls` record no call-site span, so
            // this is the state most non-Python files are in today, and saying
            // so is the honest reading.
            ResolvedSites::Unjoinable => {
                return CallerArrival::unmeasured(format!(
                    "{} can reach the focal and {NO_CALL_SITE_SPAN_REASON}, so its calls could \
                     not be counted as sites and a fan-out there could hide a site that became \
                     no edge",
                    file.0
                ))
            }
            ResolvedSites::Unreadable => {
                return CallerArrival::unmeasured(
                    "the relation index could not be read for a file in the focal's family",
                )
            }
        };
        // A call site can still fan out to several same-named destinations that
        // the graph records without a joinable span, so the resolved side can
        // exceed the parsed side; the shortfall floors at zero rather than
        // wrapping, which is the same cap `call_percent` puts on the ratio for
        // the same reason.
        let missing = parsed.map(|parsed| parsed.saturating_sub(resolved));
        // Two distinct gaps and both count. A positive shortfall is call sites
        // that reached no destination. An absent count is a file whose call
        // extraction the parser could not represent at all, which it signals by
        // withholding the number rather than by reporting zero.
        if missing.is_none_or(|missing| missing > 0) {
            unaccounted.push(UnaccountedFile {
                file: file.0.clone(),
                parsed_call_sites: parsed,
                resolved_call_edges: resolved,
                unaccounted_call_sites: missing,
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
                            Some(
                                match file
                                    .get("unaccounted_call_sites")
                                    .and_then(serde_json::Value::as_u64)
                                {
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
            Some(format!(
                "{UNRESOLVED_ARRIVAL_LIMITING_FACTOR}: of the {family} file(s) that import the \
                 focal's file, {} hold call sites the linker recorded no edge for, so a caller of \
                 this focal may be among them and an empty reference list here is a floor rather \
                 than proof of disuse: {}",
                files.len(),
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
                            format!(
                                "{} ({missing} of {} parsed call sites became no edge)",
                                file.file,
                                file.parsed_call_sites.unwrap_or(0)
                            )
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
        // state and not on the row count.
        assert!(arrival_gap(&json!({ CALLER_ARRIVAL_KEY: block }))
            .is_some_and(|gap| gap.starts_with(UNRESOLVED_ARRIVAL_LIMITING_FACTOR)));

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
        };
        let withheld = UnaccountedFile {
            file: "tests/test_linkgraph.py".to_string(),
            parsed_call_sites: None,
            resolved_call_edges: 4,
            unaccounted_call_sites: None,
        };
        let many: Vec<UnaccountedFile> = (0..8)
            .map(|index| UnaccountedFile {
                file: format!("tests/test_{index}.py"),
                parsed_call_sites: Some(index + 2),
                resolved_call_edges: 1,
                unaccounted_call_sites: Some(index + 1),
            })
            .collect();
        let build = |unaccounted: Vec<UnaccountedFile>| CallerArrival {
            state: ArrivalState::Unaccounted,
            family_files: unaccounted.len().max(1),
            family_measured: 0,
            unaccounted,
            unmeasured_reason: None,
        };
        vec![
            ("one shortfall file", build(vec![one.clone()])),
            ("one withheld-count file", build(vec![withheld.clone()])),
            ("both kinds joined", build(vec![one, withheld])),
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

    /// A file whose call edges record no call-site span cannot be measured, and
    /// giving those edges a weight of one is not a neutral fallback.
    ///
    /// It is exactly the relation count the fan-out repair replaces, so a file
    /// whose two parsed sites produce two edges from ONE site subtracts to zero
    /// and certifies while a site became nothing. Nine of the eleven adapters
    /// that emit `Calls` record no span, so this is the state most non-Python
    /// files are in.
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
}
