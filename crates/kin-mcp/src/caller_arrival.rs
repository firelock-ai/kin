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
//!   file at extraction),
//! - how many `Calls` edges the graph holds whose source is one of that file's
//!   entities.
//!
//! A file whose parse side exceeds its edge side holds calls that reached no
//! destination. That is not by itself a defect: a call into a third-party
//! package cannot resolve to an in-repo entity either. The linker records those
//! as unresolved-receiver placeholders, which ARE `Calls` edges and so are
//! counted here, which is what keeps an ordinary dependency call from reading as
//! a gap. What remains in the shortfall is calls the linker dropped without a
//! placeholder, and that is exactly the ambiguity class the focal could be
//! hiding in.
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

/// Importing files examined before the reading declines.
///
/// Each costs one entity query plus one relation read per entity of that file.
/// A hub imported by more files than this gets an honest `unmeasured` rather
/// than a verdict drawn from a truncated set, because truncating and reporting
/// `accounted` is the silent cap this module exists to refuse.
const FAMILY_FILE_CAP: usize = 200;

/// How completely this reading could account for the ways a caller reaches the
/// focal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrivalState {
    /// Every file that can reach the focal had every call site it parsed become
    /// an edge. An absence answered over these edges is the whole set.
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
    /// on any file whose call extraction it could not represent. Absent, not
    /// zero, and it is its own kind of gap.
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
            "unaccounted_files": self.unaccounted,
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
                            "{} (call extraction was incomplete, so its call sites were never \
                             counted)",
                            file.file
                        ),
                    })
                    .collect();
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
                    named.join("; ")
                ))
            }
        }
    }
}

/// Relation classes that put a file in the focal's family: it named the focal's
/// file in its own source, so a call from it could have reached the focal.
const FAMILY_KINDS: [RelationKind; 2] = [RelationKind::Imports, RelationKind::Includes];

/// Read the per-file parse-side call count the extractor stamped on every
/// entity of the file. `None` means unmeasured, never zero.
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
) -> Option<(Vec<EntityId>, Option<u64>)> {
    let entities = store
        .query_entities(&EntityFilter {
            file_path: Some(file.clone()),
            ..EntityFilter::default()
        })
        .ok()?;
    let parsed = entities.iter().find_map(parsed_call_sites);
    Some((
        entities.into_iter().map(|entity| entity.id).collect(),
        parsed,
    ))
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
    let focal_owned: HashSet<EntityId> = focal_file_entities.iter().copied().collect();

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
    for entity_id in &focal_file_entities {
        let Ok(relations) = store.get_all_relations_for_entity(entity_id) else {
            return CallerArrival::unmeasured(
                "the relation index could not be read for the focal's file",
            );
        };
        for relation in relations {
            if !FAMILY_KINDS.contains(&relation.kind) {
                continue;
            }
            let (Some(source), Some(destination)) =
                (relation.src.as_entity(), relation.dst.as_entity())
            else {
                continue;
            };
            if focal_owned.contains(&source) {
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
        let mut resolved = 0u64;
        for entity_id in &entity_ids {
            let Ok(relations) = store.get_all_relations_for_entity(entity_id) else {
                return CallerArrival::unmeasured(
                    "the relation index could not be read for a file in the focal's family",
                );
            };
            resolved += relations
                .iter()
                .filter(|relation| {
                    relation.kind == RelationKind::Calls
                        && relation.src.as_entity() == Some(*entity_id)
                })
                .count() as u64;
        }
        // A call site can fan out to several same-named destinations, so the
        // resolved side can exceed the parsed side; the shortfall floors at
        // zero rather than wrapping, which is the same cap `call_percent` puts
        // on the ratio for the same reason.
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
                                    None => format!("{path} (call extraction incomplete)"),
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
                files.join("; ")
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

#[cfg(test)]
mod tests {
    use super::*;

    use kin_db::InMemoryGraph;
    use kin_model::graph::EntityStore;
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
        for index in 0..caller_resolved_calls {
            let target = if index == 0 {
                &find_note
            } else {
                &focal_module
            };
            store
                .upsert_relation(&Relation {
                    id: RelationId::from_content(
                        &caller.id.0.to_string(),
                        &target.id.0.to_string(),
                        &format!("Calls{index}"),
                    ),
                    ..edge(RelationKind::Calls, &caller, target)
                })
                .unwrap();
        }
        (store, focal)
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
            factor.contains("call extraction was incomplete"),
            "the reason must say the count is absent rather than zero: {factor}"
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
