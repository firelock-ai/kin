// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! One way to name an entity, for every read command that takes one.
//!
//! A caller addresses an entity three ways: by the id `kin search --json`
//! handed back, by a name, or by a name plus the qualifiers that pin which of
//! several same-named entities it meant. Before this module each command spelled
//! that out for itself, and they disagreed. `kin context` and `kin impact` read
//! an id; `kin trace` and `kin xref` matched the id string as a name pattern and
//! reported the entity absent, while `kin trace --help` advertised "Entity name
//! or ID". Only `kin impact` accepted `--file`, `--kind` and `--signature`, so a
//! caller that knew which twin it meant could say so to one command out of five
//! (FIR-3071).
//!
//! Resolution answers in two stages and keeps them apart. `name_matches` is what
//! the name alone reaches; `matches` is what survives the qualifiers. A command
//! that collapses them reports "not found" about an entity the unqualified
//! lookup had just returned, which is what `kin impact Error --file
//! src/error.rs` used to do.
//!
//! Nothing here reads the filesystem. Every fact is read from the graph's own
//! entity records, and the qualifiers compare against
//! [`kin_review::StableEntityIdentity`], the same normalized identity the note
//! this module prints suggests, so a `--file`/`--kind` pair copied out of that
//! note is the pair the filter compares.

use anyhow::{bail, Result};
use kin_model::{Entity, EntityFilter, EntityId, GraphNodeId, GraphStore, RelationKind};

use crate::entity_ref::EntityRef;

/// The qualifiers that pin one entity when a name reaches several.
#[derive(Debug, Clone, Default)]
pub struct IdentityQualifiers {
    /// Exact repo-relative file path.
    pub file: Option<String>,
    /// Exact entity kind, spelled as `StableEntityIdentity` spells it.
    pub kind: Option<String>,
    /// Whitespace-normalized declaration signature, for overloads.
    pub signature: Option<String>,
}

impl IdentityQualifiers {
    pub fn is_empty(&self) -> bool {
        self.file.is_none() && self.kind.is_none() && self.signature.is_none()
    }

    /// The qualifiers as the caller typed them, for a message that has to name
    /// what excluded everything.
    pub fn labels(&self) -> Vec<String> {
        [
            self.file.as_deref().map(|v| format!("--file {v}")),
            self.kind.as_deref().map(|v| format!("--kind {v}")),
            self.signature
                .as_deref()
                .map(|v| format!("--signature {v}")),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

/// What a query resolved to, at both stages of resolution.
pub struct ResolvedIdentity {
    /// After `--file`, `--kind` and `--signature`.
    pub matches: Vec<Entity>,
    /// Before them: what the name or id alone reaches.
    pub name_matches: Vec<Entity>,
    /// Whether the query is some entity's name exactly, rather than a fragment
    /// of one. A structured caller resolves only on an exact name, so this is
    /// what separates "the graph holds nothing by that name" from "the name you
    /// gave is part of several entities' names".
    pub exact_name: bool,
    /// Whether the query parsed as an entity id. An id names one entity, so a
    /// caller that passed one has already disambiguated and gets no twin note.
    pub addressed_by_id: bool,
}

/// Resolve `query` to the entities it can mean, then narrow by `qualifiers`.
///
/// An id resolves to at most one entity and skips name matching entirely. A
/// name goes through the graph's name index, drops external reference targets,
/// and narrows to exact-name hits when the query is exactly some entity's name.
///
/// An external reference target carries an imported symbol's name while standing
/// for a definition another repository owns. This repository holds no file and
/// no relations for it, so it can never be the subject of a trace or an impact
/// walk; leaving it in inflates the count and turns a repository's own `Error`
/// into an ambiguous query.
pub fn resolve_identity<G: GraphStore>(
    graph: &G,
    query: &str,
    qualifiers: &IdentityQualifiers,
) -> Result<ResolvedIdentity> {
    let trimmed = query.trim();
    let addressed_by_id = uuid::Uuid::parse_str(trimmed).is_ok();

    let mut matches: Vec<Entity> = if let Ok(uuid) = uuid::Uuid::parse_str(trimmed) {
        graph.get_entity(&EntityId(uuid))?.into_iter().collect()
    } else {
        let filter = EntityFilter {
            name_pattern: Some(trimmed.to_string()),
            ..Default::default()
        };
        let mut matches = graph.query_entities(&filter)?;
        matches.retain(|entity| !kin_index::is_external_reference_target(entity));
        // Broad matching is for discovery: "resolve" should still reach
        // resolve_binary. But when the query names an entity exactly, substring
        // cousins force an ambiguity note onto an unambiguous ask, so an
        // exact-name hit narrows the set to the exact matches.
        let exact: Vec<Entity> = matches
            .iter()
            .filter(|entity| entity.name == trimmed)
            .cloned()
            .collect();
        if !exact.is_empty() {
            matches = exact;
        }
        matches
    };

    let exact_name = matches.iter().any(|entity| entity.name == trimmed);
    let name_matches = matches.clone();
    apply_qualifiers(&mut matches, qualifiers);

    Ok(ResolvedIdentity {
        matches,
        name_matches,
        exact_name,
        addressed_by_id,
    })
}

/// Narrow `matches` to the entities the qualifiers admit.
///
/// Split out from [`resolve_identity`] so a command that gathers its candidates
/// its own way still filters them by exactly these rules. `kin trace` is one:
/// its name lookup retries a qualified name against its leaf, so `Router::route`
/// reaches `Router<S>::route`, and that retry has to happen before the
/// qualifiers narrow what it found.
///
/// Compared against [`kin_review::StableEntityIdentity`], the normalized
/// identity, so `--file` takes the repo-relative path the answer prints and
/// `--kind` takes the lowercase kind, not a `Debug` spelling.
pub fn apply_qualifiers(matches: &mut Vec<Entity>, qualifiers: &IdentityQualifiers) {
    if let Some(file) = qualifiers.file.as_deref() {
        matches.retain(|entity| kin_review::StableEntityIdentity::from_entity(entity).file == file);
    }
    if let Some(kind) = qualifiers.kind.as_deref() {
        matches.retain(|entity| kin_review::StableEntityIdentity::from_entity(entity).kind == kind);
    }
    if let Some(signature) = qualifiers.signature.as_deref() {
        let normalized = signature.split_whitespace().collect::<Vec<_>>().join(" ");
        matches.retain(|entity| {
            kin_review::StableEntityIdentity::from_entity(entity).signature == normalized
        });
    }
}

/// The entity to answer about when several share a name and nothing pins one.
///
/// The first entity [`rank_candidates`] puts forward, so `kin context` chooses
/// by the same rule as every other read command. Every term of that rule is read
/// off the graph, so the choice is a property of the candidates and not of the
/// order the store listed them in, which is what made the same question answer
/// two ways across six stores built from one tree (FIR-3071).
pub fn choose_definition<G: GraphStore>(graph: &G, matches: &[Entity]) -> Result<Option<Entity>> {
    let mut ranked = matches.to_vec();
    rank_candidates(graph, &mut ranked)?;
    Ok(ranked.into_iter().next())
}

/// The relation kinds that make an entity something others depend on, for
/// [`rank_candidates`]. The set `kin refs` answers on by default, so "has
/// dependents" means `kin refs` would list someone.
const DEPENDENT_RELATION_KINDS: [RelationKind; 3] = [
    RelationKind::Calls,
    RelationKind::Imports,
    RelationKind::References,
];

/// The rule [`rank_candidates`] orders same-named entities by, as the sentence an
/// answer prints when it had to choose.
pub const RANKING_RULE: &str = "a definition before a declaration, then an entity something \
     calls, imports or references before one nothing does, then by file path and line";

/// Order `candidates` by the one rule every read command chooses with.
///
/// Lower sorts first: a definition before a declaration ([`kin_core::carries_body`]
/// reads the stored signature), then an entity another entity calls, imports or
/// references before one nothing does, then file path, then start line, then id.
/// A re-export, a forward declaration or a fixture sharing a name carries no
/// dependents, and answering for it prints an empty result indistinguishable
/// from a subject nothing depends on, which is why the second term exists.
/// Every term is read off the graph, so `kin refs`, `kin impact`, `kin blame`
/// and the graph commands choose the same entity for the same name.
pub fn rank_candidates<G: GraphStore>(graph: &G, candidates: &mut Vec<Entity>) -> Result<()> {
    rank_candidates_by(candidates, |entity| has_dependents(graph, entity))
}

/// [`rank_candidates`] with the dependents test supplied by the caller, for a
/// candidate set that lives outside a store, such as a state replayed at a
/// historical ref.
pub fn rank_candidates_by(
    candidates: &mut Vec<Entity>,
    mut has_dependents: impl FnMut(&Entity) -> Result<bool>,
) -> Result<()> {
    if candidates.len() < 2 {
        return Ok(());
    }
    let mut keyed = Vec::with_capacity(candidates.len());
    for entity in candidates.drain(..) {
        let dependents = has_dependents(&entity)?;
        let (declaration, path, line, id) = kin_core::definition_identity_key(&entity);
        keyed.push(((declaration, !dependents, path, line, id), entity));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    candidates.extend(keyed.into_iter().map(|(_, entity)| entity));
    Ok(())
}

/// Whether another entity calls, imports or references `entity`.
fn has_dependents<G: GraphStore>(graph: &G, entity: &Entity) -> Result<bool> {
    Ok(graph
        .get_all_relations_for_entity(&entity.id)?
        .iter()
        .any(|relation| depended_on_by(relation) == Some(entity.id)))
}

/// The entity a relation makes something others depend on: the target of a
/// call, import or reference from another entity, or `None`.
///
/// The one test behind [`rank_candidates`], so a ranking over a state replayed
/// at a historical ref reads dependents exactly as a ranking over the live graph
/// does.
pub fn depended_on_by(relation: &kin_model::relation::Relation) -> Option<EntityId> {
    let GraphNodeId::Entity(target) = relation.dst else {
        return None;
    };
    (matches!(relation.src, GraphNodeId::Entity(source) if source != target)
        && DEPENDENT_RELATION_KINDS.contains(&relation.kind))
    .then_some(target)
}

/// How a query met the name of what it resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameMatch {
    /// The query was an entity id, which names one entity.
    Id,
    /// Some entity's name is the query exactly.
    Exact,
    /// Some entity's name is the query once ASCII case is ignored.
    CaseInsensitive,
    /// The query is only part of the names it reached.
    Partial,
}

/// Everything one query resolved to, at every stage, so a command can answer
/// and also say how it chose.
pub struct EntityResolution {
    /// The query with its `#kind@path:line` suffix read out and merged with the
    /// caller's flags.
    pub reference: EntityRef,
    /// What the name or id alone reaches, before any pin.
    pub name_matches: Vec<Entity>,
    /// What survives the pins, ranked by [`rank_candidates`]; the first is the
    /// answer.
    pub candidates: Vec<Entity>,
    pub name_match: NameMatch,
}

impl EntityResolution {
    /// The entity the answer is about.
    pub fn chosen(&self) -> Option<&Entity> {
        self.candidates.first()
    }

    pub fn addressed_by_id(&self) -> bool {
        self.name_match == NameMatch::Id
    }

    pub fn exact_name(&self) -> bool {
        self.name_match == NameMatch::Exact
    }

    /// A partial name that reaches several entities names none of them, so the
    /// caller is asked which it meant instead of being handed a guess.
    pub fn needs_a_pin(&self) -> bool {
        self.name_match == NameMatch::Partial && self.candidates.len() > 1
    }

    /// The name reaches entities and the pins exclude every one of them, which
    /// is a filter miss and never an absent entity.
    pub fn pin_excluded_all(&self) -> bool {
        !self.name_matches.is_empty() && self.candidates.is_empty()
    }
}

/// Resolve `query` the one way every read command resolves a name.
///
/// The query is an entity id, a name, or a name carrying the
/// `Name#kind@path:line` suffix `kin context` already reads; `flags` are the
/// same pins spelled as command-line flags, and a pin given both ways with two
/// values is refused. Names go through the graph's name index with the generics
/// and qualified-leaf retries `kin trace` has always used, drop external
/// reference targets, and narrow to exact, then case-folded, matches when any
/// exist. What survives the pins is ranked by [`rank_candidates`].
pub fn resolve_entity<G: GraphStore>(
    graph: &G,
    query: &str,
    flags: &IdentityQualifiers,
) -> Result<EntityResolution> {
    let trimmed = query.trim();
    let reference = merge_pins(
        split_pins(trimmed, || {
            Ok(graph
                .query_entities(&EntityFilter {
                    name_pattern: Some(trimmed.to_string()),
                    ..Default::default()
                })?
                .iter()
                .any(|entity| entity.name == trimmed))
        })?,
        flags,
    )?;
    let name = reference.name.trim().to_string();
    let (name_matches, name_match) = if let Ok(uuid) = uuid::Uuid::parse_str(&name) {
        (
            graph.get_entity(&EntityId(uuid))?.into_iter().collect(),
            NameMatch::Id,
        )
    } else {
        gather_by_name(graph, &name)?
    };
    finish_resolution(reference, name_matches, name_match, |entity| {
        has_dependents(graph, entity)
    })
}

/// [`resolve_entity`] over entities that live outside a store, such as a state
/// replayed at a historical ref: the same pins, the same narrowing and the same
/// ranking, with the dependents test supplied by the caller.
///
/// A name reaches the entities whose names contain it, ignoring case, or the
/// ones a leading or trailing `*` admits, which is what the store's name index
/// answers with. The generics and qualified-leaf retries `kin trace` adds belong
/// to the live graph's index and are not repeated over a replayed state.
pub fn resolve_entity_among<'a>(
    entities: impl IntoIterator<Item = &'a Entity>,
    query: &str,
    flags: &IdentityQualifiers,
    has_dependents: impl FnMut(&Entity) -> Result<bool>,
) -> Result<EntityResolution> {
    let entities: Vec<&Entity> = entities.into_iter().collect();
    let trimmed = query.trim();
    let reference = merge_pins(
        split_pins(trimmed, || {
            Ok(entities.iter().any(|entity| entity.name == trimmed))
        })?,
        flags,
    )?;
    let name = reference.name.trim().to_string();
    let (name_matches, name_match) = if let Ok(uuid) = uuid::Uuid::parse_str(&name) {
        let id = EntityId(uuid);
        (
            entities
                .iter()
                .filter(|entity| entity.id == id)
                .map(|entity| (*entity).clone())
                .collect(),
            NameMatch::Id,
        )
    } else if name.is_empty() {
        (Vec::new(), NameMatch::Partial)
    } else {
        let folded = name.to_lowercase();
        let glob = name.starts_with('*') || name.ends_with('*');
        let reached = entities
            .iter()
            .filter(|entity| !kin_index::is_external_reference_target(entity))
            .filter(|entity| {
                if glob {
                    glob_matches(&entity.name, &name)
                } else {
                    entity.name.to_lowercase().contains(&folded)
                }
            })
            .map(|entity| (*entity).clone())
            .collect();
        narrow_by_name(reached, &name)
    };
    finish_resolution(reference, name_matches, name_match, has_dependents)
}

/// Pin, then rank, what a name reached: the tail every resolution shares.
fn finish_resolution(
    reference: EntityRef,
    mut name_matches: Vec<Entity>,
    name_match: NameMatch,
    mut has_dependents: impl FnMut(&Entity) -> Result<bool>,
) -> Result<EntityResolution> {
    let mut candidates = name_matches.clone();
    apply_qualifiers(&mut candidates, &reference.qualifiers);
    crate::entity_ref::apply_line(&mut candidates, reference.line);
    rank_candidates_by(&mut candidates, &mut has_dependents)?;
    if candidates.is_empty() {
        // Only a miss lists these, and it lists them in the order the rule would
        // have chosen them.
        rank_candidates_by(&mut name_matches, &mut has_dependents)?;
    }
    Ok(EntityResolution {
        reference,
        name_matches,
        candidates,
        name_match,
    })
}

/// Read the pins out of a query's suffix.
///
/// The raw token is tried as an entity name first, so a name that itself
/// carries `@` or `#` resolves as that name rather than being split into a pin.
/// `raw_is_a_name` is asked only when the token carries one of them.
fn split_pins(trimmed: &str, raw_is_a_name: impl FnOnce() -> Result<bool>) -> Result<EntityRef> {
    let bare = || EntityRef {
        name: trimmed.to_string(),
        ..EntityRef::default()
    };
    if !(trimmed.contains('@') || trimmed.contains('#')) || raw_is_a_name()? {
        return Ok(bare());
    }
    let parsed = crate::entity_ref::parse_entity_ref(trimmed);
    if parsed.name.trim().is_empty() {
        return Ok(bare());
    }
    Ok(parsed)
}

/// Merge the pins a query's suffix carried with the ones its flags carried.
fn merge_pins(mut reference: EntityRef, flags: &IdentityQualifiers) -> Result<EntityRef> {
    let pairs = [
        ("file", &mut reference.qualifiers.file, &flags.file),
        ("kind", &mut reference.qualifiers.kind, &flags.kind),
        (
            "signature",
            &mut reference.qualifiers.signature,
            &flags.signature,
        ),
    ];
    for (label, from_query, from_flag) in pairs {
        match (from_query.as_deref(), from_flag.as_deref()) {
            (Some(spelled), Some(flagged)) if spelled != flagged => bail!(
                "the {label} pin was given twice with two values: '{spelled}' in the entity \
                 name and '{flagged}' as a flag; give it once"
            ),
            (None, Some(flagged)) => *from_query = Some(flagged.to_string()),
            _ => {}
        }
    }
    Ok(reference)
}

/// Every entity a name reaches, narrowed to exact or case-folded matches when
/// the name is some entity's whole name.
fn gather_by_name<G: GraphStore>(graph: &G, name: &str) -> Result<(Vec<Entity>, NameMatch)> {
    if name.is_empty() {
        return Ok((Vec::new(), NameMatch::Partial));
    }
    let mut matches = kin_core::query_trace_matches(graph, name)?;
    matches.retain(|entity| !kin_index::is_external_reference_target(entity));
    if matches.is_empty() && (name.starts_with('*') || name.ends_with('*')) {
        // The name index is a substring test and reads `*` literally, so a glob
        // is answered by a sweep. It stays narrowed to the query: an unfiltered
        // sweep is how `kin history alwaysTrue` once listed four unrelated names
        // as its matches.
        matches = graph
            .list_all_entities()?
            .into_iter()
            .filter(|entity| {
                !kin_index::is_external_reference_target(entity) && glob_matches(&entity.name, name)
            })
            .collect();
    }
    Ok(narrow_by_name(matches, name))
}

/// Narrow what a name reached to its exact matches, then to its case-folded
/// ones, when the name is some entity's whole name.
fn narrow_by_name(matches: Vec<Entity>, name: &str) -> (Vec<Entity>, NameMatch) {
    let exact: Vec<Entity> = matches
        .iter()
        .filter(|entity| entity.name == name)
        .cloned()
        .collect();
    if !exact.is_empty() {
        return (exact, NameMatch::Exact);
    }
    let folded: Vec<Entity> = matches
        .iter()
        .filter(|entity| entity.name.eq_ignore_ascii_case(name))
        .cloned()
        .collect();
    if !folded.is_empty() {
        return (folded, NameMatch::CaseInsensitive);
    }
    (matches, NameMatch::Partial)
}

/// A leading `*` matches a suffix and a trailing one a prefix, ignoring case.
fn glob_matches(name: &str, pattern: &str) -> bool {
    let name = name.to_lowercase();
    let pattern = pattern.to_lowercase();
    if let Some(suffix) = pattern.strip_prefix('*') {
        name.ends_with(suffix.trim_end_matches('*'))
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else {
        name == pattern
    }
}

/// How many candidates a note lists before it points at `kin graph inspect`.
const MAX_LISTED_CANDIDATES: usize = 8;

/// How a command spells its pins, for the line that tells a reader how to reach
/// another candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSpelling {
    /// `--file <path> --kind <kind>`.
    FileKind,
    /// `kin refs`, whose `--kind` already filters relation kinds.
    FileEntityKind,
}

impl PinSpelling {
    fn flags(self, file: &str, kind: &str) -> String {
        match self {
            Self::FileKind => format!("--file {file} --kind {kind}"),
            Self::FileEntityKind => format!("--file {file} --entity-kind {kind}"),
        }
    }
}

/// One row per candidate: its kind, where it is, and its id, which pins it
/// exactly in every command.
pub fn candidate_rows<G: GraphStore>(graph: &G, candidates: &[Entity]) -> Vec<String> {
    candidate_rows_by(candidates, |candidate| entity_location(graph, candidate))
}

/// [`candidate_rows`] with the location supplied by the caller, for candidates
/// read from a replayed state whose tree is not the live graph's.
pub fn candidate_rows_by(candidates: &[Entity], locate: impl Fn(&Entity) -> String) -> Vec<String> {
    let mut rows: Vec<String> = candidates
        .iter()
        .take(MAX_LISTED_CANDIDATES)
        .map(|candidate| {
            format!(
                "  {:<9} {}  {}",
                kin_review::StableEntityIdentity::from_entity(candidate).kind,
                locate(candidate),
                candidate.id
            )
        })
        .collect();
    if candidates.len() > MAX_LISTED_CANDIDATES {
        rows.push(format!(
            "  ... and {} more; `kin graph inspect {}` lists every one",
            candidates.len() - MAX_LISTED_CANDIDATES,
            candidates[0].name
        ));
    }
    rows
}

/// What an answer says when its query reached more than one entity: every
/// candidate, the rule that picked the first, and how to pin another.
///
/// Silent for an id and for a query that reached one entity, because nothing
/// was chosen.
pub fn choice_note<G: GraphStore>(
    graph: &G,
    resolution: &EntityResolution,
    spelling: PinSpelling,
) -> Vec<String> {
    choice_note_by(resolution, spelling, |candidate| {
        entity_location(graph, candidate)
    })
}

/// [`choice_note`] with the location supplied by the caller.
pub fn choice_note_by(
    resolution: &EntityResolution,
    spelling: PinSpelling,
    locate: impl Fn(&Entity) -> String,
) -> Vec<String> {
    if resolution.addressed_by_id() || resolution.candidates.len() < 2 {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "note: '{}' names {} entities in this graph; this answer is about the first one listed.",
        resolution.reference.name,
        resolution.candidates.len()
    )];
    lines.extend(candidate_rows_by(&resolution.candidates, locate));
    lines.push(format!("note: ranked {RANKING_RULE}."));
    let next = kin_review::StableEntityIdentity::from_entity(&resolution.candidates[1]);
    let file = if next.file.is_empty() {
        "<path>"
    } else {
        next.file.as_str()
    };
    lines.push(format!(
        "note: to answer about another, pin it, for example {}, or pass its id.",
        spelling.flags(file, &next.kind)
    ));
    lines
}

/// The answer when a partial name reaches several entities.
pub fn pin_request_lines<G: GraphStore>(graph: &G, resolution: &EntityResolution) -> Vec<String> {
    pin_request_lines_by(resolution, |candidate| entity_location(graph, candidate))
}

/// [`pin_request_lines`] with the location supplied by the caller.
pub fn pin_request_lines_by(
    resolution: &EntityResolution,
    locate: impl Fn(&Entity) -> String,
) -> Vec<String> {
    let mut lines = vec![format!(
        "No entity is named '{}' exactly, and it is part of the names of {} entities, so there \
         is no one entity to answer about:",
        resolution.reference.name,
        resolution.candidates.len()
    )];
    lines.extend(candidate_rows_by(&resolution.candidates, locate));
    lines.push(
        "hint: re-run with one of the names above, or pass its id. Pins narrow a name; they \
         cannot make a partial name exact."
            .to_string(),
    );
    lines
}

/// The answer when the name resolves and the pins exclude every entity it
/// reaches. The entity is in the graph, so saying it is absent would be false.
pub fn pin_miss_lines<G: GraphStore>(graph: &G, resolution: &EntityResolution) -> Vec<String> {
    pin_miss_lines_by(resolution, |candidate| entity_location(graph, candidate))
}

/// [`pin_miss_lines`] with the location supplied by the caller.
pub fn pin_miss_lines_by(
    resolution: &EntityResolution,
    locate: impl Fn(&Entity) -> String,
) -> Vec<String> {
    let name = &resolution.reference.name;
    let mut pins = resolution.reference.qualifiers.labels();
    if let Some(line) = resolution.reference.line {
        pins.push(format!("line {line}"));
    }
    let count = resolution.name_matches.len();
    let mut lines = vec![
        format!("No entity named '{name}' matches {}.", pins.join(" ")),
        format!(
            "'{name}' resolves in this repo's graph to {count} entit{}:",
            if count == 1 { "y" } else { "ies" }
        ),
    ];
    lines.extend(candidate_rows_by(&resolution.name_matches, locate));
    lines.push("hint: pin one of the entities above, or pass its id.".to_string());
    lines
}

/// How many candidates a note lists before it stops.
const MAX_LISTED_TWINS: usize = 4;

/// What the answer has to say when the name reached more than one entity.
///
/// Says which entity was chosen and why, then names the others and the flags
/// that pin them. Without this a caller cannot tell an unambiguous answer from a
/// coin flip the command already made on its behalf, which is how a demo put a
/// header's declaration and a source file's definition into one prompt as though
/// they were the same entity.
///
/// Silent when the caller passed an id or when the name reached one entity,
/// because there was nothing to choose.
pub fn twin_note<G: GraphStore>(
    graph: &G,
    query: &str,
    chosen: &Entity,
    matches: &[Entity],
) -> Vec<String> {
    if matches.len() < 2 {
        return Vec::new();
    }
    let chosen_identity = kin_review::StableEntityIdentity::from_entity(chosen);
    let mut lines = vec![format!(
        "note: '{}' names {} entities in this graph; traced the {} at {}.",
        query,
        matches.len(),
        if kin_core::carries_body(chosen) {
            "definition"
        } else {
            "declaration"
        },
        entity_location(graph, chosen),
    )];
    let others: Vec<&Entity> = matches
        .iter()
        .filter(|candidate| candidate.id != chosen.id)
        .collect();
    for candidate in others.iter().take(MAX_LISTED_TWINS) {
        let identity = kin_review::StableEntityIdentity::from_entity(candidate);
        lines.push(format!(
            "note: also {} ({}).",
            entity_location(graph, candidate),
            identity.kind
        ));
    }
    if others.len() > MAX_LISTED_TWINS {
        lines.push(format!(
            "note: and {} more.",
            others.len() - MAX_LISTED_TWINS
        ));
    }
    lines.push(format!(
        "note: pin one with --file <path> --kind <kind>, for example --file {} --kind {}.",
        if chosen_identity.file.is_empty() {
            "<path>".to_string()
        } else {
            chosen_identity.file.clone()
        },
        chosen_identity.kind
    ));
    lines
}

/// `path:line` for an entity, `path (span stale)` when its span describes an
/// older version of the file than the graph holds, or `unknown` when the graph
/// carries no file for it. Presentation only; resolution is keyed on graph
/// identity, never on paths.
pub fn entity_location<G: GraphStore>(graph: &G, entity: &Entity) -> String {
    entity_pointer(graph, entity).render()
}

/// The mark a location carries when the graph cannot vouch for its line.
pub const STALE_SPAN_MARK: &str = "(span stale)";

/// Where an entity starts, as far as the graph can vouch for it.
///
/// The line comes from the entity's own span, converted to 1-based at the seam
/// every surface converts at. It is withheld, and the pointer marked stale,
/// when the span was measured against different bytes than the graph's tree now
/// holds at that path: the reconciler stamps every entity with the digest of the
/// source its span was derived from, and a digest that disagrees with the tree
/// means the line lands wherever that code used to be. A store that stopped
/// re-deriving entities printed `cache.rs:35` for a function that has sat at
/// line 41 since August, which is the class this names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityPointer {
    pub path: Option<String>,
    /// 1-based start line; `None` without a span, or when the span is stale.
    pub line: Option<u32>,
    pub stale: bool,
}

impl EntityPointer {
    pub fn render(&self) -> String {
        match (&self.path, self.line) {
            (Some(path), _) if self.stale => format!("{path} {STALE_SPAN_MARK}"),
            (Some(path), Some(line)) => format!("{path}:{line}"),
            (Some(path), None) => path.clone(),
            (None, _) => "unknown".to_string(),
        }
    }
}

/// Read an entity's pointer out of the graph. Graph reads only: the check
/// compares two digests the graph already holds and never opens the file.
pub fn entity_pointer<G: GraphStore>(graph: &G, entity: &Entity) -> EntityPointer {
    pointer_against(entity, |file| {
        graph
            .get_tree_entry(file)
            .ok()
            .flatten()
            .and_then(|entry| entry.blob_identity())
    })
}

/// [`entity_pointer`] for an entity read from a state replayed at a historical
/// ref, checked against that state's tree, so a line printed for the ref is
/// vouched for by the bytes the ref holds rather than by today's.
pub fn entity_pointer_in_tree(tree: &kin_model::ResolvedTree, entity: &Entity) -> EntityPointer {
    pointer_against(entity, |file| {
        let path = kin_model::RepoPath::from_utf8(file.0.clone()).ok()?;
        tree.artifact_at_path(&path)
            .and_then(|artifact| artifact.entry.blob_identity())
    })
}

fn pointer_against(
    entity: &Entity,
    blob_at: impl FnOnce(&kin_model::FilePathId) -> Option<kin_model::Hash256>,
) -> EntityPointer {
    let path = entity.file_origin.as_ref().map(|file| file.0.clone());
    let line = kin_mcp::handlers::common::entity_presentation_start_line(entity);
    let stale = line.is_some() && span_is_stale(entity, blob_at);
    EntityPointer {
        path,
        line: if stale { None } else { line },
        stale,
    }
}

/// Whether the entity's recorded span digest provably disagrees with the blob
/// the graph's tree holds at its path.
///
/// Only a provable disagreement counts. An entity that records no digest, a path
/// the tree does not carry, or a tree entry that cannot be read is unverifiable,
/// and an unverifiable line prints as it always did rather than being withheld on
/// a guess. The comparison is kin-mcp's `span_source_coherence`, the rule
/// `get_entity_source` already refuses a stale span by, so the two surfaces
/// cannot disagree about which spans are stale.
fn span_is_stale(
    entity: &Entity,
    blob_at: impl FnOnce(&kin_model::FilePathId) -> Option<kin_model::Hash256>,
) -> bool {
    let Some(file) = entity.file_origin.as_ref() else {
        return false;
    };
    let Some(blob) = blob_at(file) else {
        return false;
    };
    kin_mcp::handlers::common::span_source_coherence(entity, &blob, &file.0).is_err()
}

/// The sentence an answer carries once when any location it printed is stale.
pub fn stale_span_note(lines: &[String]) -> Option<String> {
    lines
        .iter()
        .any(|line| line.contains(STALE_SPAN_MARK))
        .then(|| {
            format!(
                "note: a location marked {STALE_SPAN_MARK} belongs to an entity record measured \
                 against an older version of that file than the graph now holds, so its line is \
                 left out rather than printed wrong; `kin graph status` reports whether \
                 admission is keeping up."
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::{
        EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId, FingerprintAlgorithm,
        Hash256, LanguageId, SemanticFingerprint, SourceSpan, Visibility,
    };

    /// The FIR-3071 fixture in miniature: one name, a declaration in a header
    /// and a definition in a source file, exactly as the C parser writes them.
    /// The declaration keeps its terminator because nothing clamped its
    /// signature; the definition's stops where its body starts.
    fn twin(name: &str, file: &str, line: u32, signature: &str, span_len: usize) -> Entity {
        let file_id = FilePathId::new(file);
        Entity {
            id: EntityId::from_content(&file_id.0, name, "Function", line),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::C,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(file_id.clone()),
            span: Some(SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte: span_len,
                start_line: line,
                start_col: 0,
                end_line: line,
                end_col: 0,
            }),
            signature: signature.to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn declaration() -> Entity {
        twin(
            "buffer_grow",
            "src/buffer.h",
            5,
            "int buffer_grow(buf_t *b, size_t need);",
            39,
        )
    }

    fn definition() -> Entity {
        twin(
            "buffer_grow",
            "src/buffer.c",
            5,
            "int buffer_grow(buf_t *b, size_t need)",
            220,
        )
    }

    /// The property the six preserved stores broke: the choice must be the same
    /// whichever order the store lists the twins in.
    #[test]
    fn choose_definition_ignores_the_order_the_store_listed_the_twins_in() {
        let graph = InMemoryGraph::new();
        let forward = vec![definition(), declaration()];
        let reversed = vec![declaration(), definition()];

        let first = choose_definition(&graph, &forward)
            .unwrap()
            .expect("a candidate");
        let second = choose_definition(&graph, &reversed)
            .unwrap()
            .expect("a candidate");

        assert_eq!(
            first.id, second.id,
            "the choice moved with the listing order"
        );
        assert_eq!(
            first.file_origin.as_ref().map(|f| f.0.as_str()),
            Some("src/buffer.c"),
            "the definition should win over the header's declaration"
        );
    }

    #[test]
    fn twin_note_names_the_choice_and_the_flags_that_pin_the_other() {
        let graph = InMemoryGraph::new();
        let matches = vec![definition(), declaration()];
        let chosen = choose_definition(&graph, &matches)
            .unwrap()
            .expect("a candidate");
        let note = twin_note(&graph, "buffer_grow", &chosen, &matches).join("\n");

        assert!(note.contains("names 2 entities"), "{note}");
        assert!(note.contains("traced the definition"), "{note}");
        assert!(note.contains("src/buffer.h"), "{note}");
        assert!(note.contains("--file src/buffer.c"), "{note}");
    }

    #[test]
    fn twin_note_is_silent_when_the_name_reaches_one_entity() {
        let graph = InMemoryGraph::new();
        let matches = vec![definition()];
        let chosen = choose_definition(&graph, &matches)
            .unwrap()
            .expect("a candidate");
        assert!(twin_note(&graph, "buffer_grow", &chosen, &matches).is_empty());
    }

    #[test]
    fn resolve_identity_reads_an_entity_id_the_way_context_and_impact_do() {
        let graph = InMemoryGraph::new();
        let target = definition();
        graph.upsert_entity(&target).unwrap();
        graph.upsert_entity(&declaration()).unwrap();

        let resolved = resolve_identity(
            &graph,
            &target.id.to_string(),
            &IdentityQualifiers::default(),
        )
        .unwrap();

        assert!(resolved.addressed_by_id);
        assert_eq!(resolved.matches.len(), 1);
        assert_eq!(resolved.matches[0].id, target.id);
    }

    #[test]
    fn resolve_identity_pins_a_twin_by_file_and_kind() {
        let graph = InMemoryGraph::new();
        graph.upsert_entity(&definition()).unwrap();
        graph.upsert_entity(&declaration()).unwrap();

        let resolved = resolve_identity(
            &graph,
            "buffer_grow",
            &IdentityQualifiers {
                file: Some("src/buffer.h".to_string()),
                kind: Some("function".to_string()),
                signature: None,
            },
        )
        .unwrap();

        assert_eq!(resolved.name_matches.len(), 2, "both twins carry the name");
        assert_eq!(resolved.matches.len(), 1, "the file pins one");
        assert_eq!(
            resolved.matches[0]
                .file_origin
                .as_ref()
                .map(|f| f.0.as_str()),
            Some("src/buffer.h"),
            "the qualifier must win over the definition preference"
        );
    }

    /// A qualifier that excludes everything is a filter miss, not an absent
    /// entity, and the two stages have to stay distinguishable for the command
    /// to say so.
    #[test]
    fn resolve_identity_keeps_a_qualifier_miss_apart_from_a_name_miss() {
        let graph = InMemoryGraph::new();
        graph.upsert_entity(&definition()).unwrap();

        let resolved = resolve_identity(
            &graph,
            "buffer_grow",
            &IdentityQualifiers {
                file: Some("src/nowhere.c".to_string()),
                kind: None,
                signature: None,
            },
        )
        .unwrap();

        assert!(resolved.matches.is_empty());
        assert_eq!(resolved.name_matches.len(), 1);
        assert!(resolved.exact_name);
    }

    fn calls(graph: &InMemoryGraph, caller: &Entity, callee: &Entity) {
        use kin_model::relation::{Relation, RelationOrigin};
        graph
            .upsert_relation(&Relation {
                id: kin_model::RelationId::from_content(
                    &caller.id.to_string(),
                    &callee.id.to_string(),
                    "calls",
                ),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(caller.id),
                dst: GraphNodeId::Entity(callee.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();
    }

    /// Among definitions, one something calls outranks one nothing does, even
    /// when the uncalled one sorts first by path.
    #[test]
    fn a_called_definition_outranks_an_uncalled_one() {
        let graph = InMemoryGraph::new();
        let uncalled = twin("grow", "src/a.c", 1, "int grow(void)", 20);
        let called = twin("grow", "src/z.c", 1, "int grow(void)", 20);
        let caller = twin("user", "src/user.c", 1, "int user(void)", 20);
        for entity in [&uncalled, &called, &caller] {
            graph.upsert_entity(entity).unwrap();
        }
        calls(&graph, &caller, &called);

        let resolution = resolve_entity(&graph, "grow", &IdentityQualifiers::default()).unwrap();
        assert_eq!(resolution.chosen().map(|e| e.id), Some(called.id));
    }

    /// A definition outranks a declaration even when only the declaration is
    /// called, because the declaration is not where the code is.
    #[test]
    fn a_definition_outranks_a_called_declaration() {
        let graph = InMemoryGraph::new();
        let caller = twin("user", "src/user.c", 1, "int user(void)", 20);
        for entity in [&definition(), &declaration(), &caller] {
            graph.upsert_entity(entity).unwrap();
        }
        calls(&graph, &caller, &declaration());

        let resolution =
            resolve_entity(&graph, "buffer_grow", &IdentityQualifiers::default()).unwrap();
        assert_eq!(resolution.chosen().map(|e| e.id), Some(definition().id));
    }

    /// The note names every candidate by id, states the rule, and shows the pin
    /// that reaches the next one, in the command's own flag spelling.
    #[test]
    fn the_choice_note_lists_every_candidate_and_how_to_pin_the_next() {
        let graph = InMemoryGraph::new();
        graph.upsert_entity(&definition()).unwrap();
        graph.upsert_entity(&declaration()).unwrap();

        let resolution =
            resolve_entity(&graph, "buffer_grow", &IdentityQualifiers::default()).unwrap();
        let note = choice_note(&graph, &resolution, PinSpelling::FileEntityKind).join("\n");

        assert!(note.contains("names 2 entities"), "{note}");
        assert!(note.contains(&definition().id.to_string()), "{note}");
        assert!(note.contains(&declaration().id.to_string()), "{note}");
        assert!(note.contains(RANKING_RULE), "{note}");
        assert!(
            note.contains("--file src/buffer.h --entity-kind function"),
            "{note}"
        );
    }

    /// An id names one entity, so nothing was chosen and nothing is noted.
    #[test]
    fn an_id_carries_no_choice_note() {
        let graph = InMemoryGraph::new();
        graph.upsert_entity(&definition()).unwrap();
        graph.upsert_entity(&declaration()).unwrap();

        let resolution = resolve_entity(
            &graph,
            &declaration().id.to_string(),
            &IdentityQualifiers::default(),
        )
        .unwrap();
        assert!(resolution.addressed_by_id());
        assert_eq!(resolution.chosen().map(|e| e.id), Some(declaration().id));
        assert!(choice_note(&graph, &resolution, PinSpelling::FileKind).is_empty());
    }

    /// A name that itself carries `@` resolves as that name, not as a pin.
    #[test]
    fn a_name_carrying_an_at_sign_is_not_split_into_a_pin() {
        let graph = InMemoryGraph::new();
        let odd = twin("user@host", "src/odd.c", 3, "int user_at_host(void)", 30);
        graph.upsert_entity(&odd).unwrap();

        let resolution =
            resolve_entity(&graph, "user@host", &IdentityQualifiers::default()).unwrap();
        assert_eq!(resolution.chosen().map(|e| e.id), Some(odd.id));
        assert!(resolution.reference.qualifiers.file.is_none());
    }

    /// A glob reaches by prefix and stays narrowed to the query, and a partial
    /// reach of several names asks for a pin.
    #[test]
    fn a_glob_query_reaches_by_prefix_and_stays_narrowed() {
        let graph = InMemoryGraph::new();
        for name in ["buffer_grow", "buffer_shrink", "grow_buffer"] {
            graph
                .upsert_entity(&twin(name, &format!("src/{name}.c"), 1, "int f(void)", 10))
                .unwrap();
        }

        let resolution =
            resolve_entity(&graph, "buffer_*", &IdentityQualifiers::default()).unwrap();
        let names: Vec<&str> = resolution
            .candidates
            .iter()
            .map(|entity| entity.name.as_str())
            .collect();
        assert_eq!(names, vec!["buffer_grow", "buffer_shrink"]);
        assert!(resolution.needs_a_pin());
    }

    /// Case alone does not make a name partial.
    #[test]
    fn a_name_that_differs_only_in_case_resolves_without_a_pin() {
        let graph = InMemoryGraph::new();
        graph
            .upsert_entity(&twin("BufferGrow", "src/a.c", 1, "int f(void)", 10))
            .unwrap();
        graph
            .upsert_entity(&twin("BufferGrowLater", "src/b.c", 1, "int g(void)", 10))
            .unwrap();

        let resolution =
            resolve_entity(&graph, "buffergrow", &IdentityQualifiers::default()).unwrap();
        assert_eq!(resolution.name_match, NameMatch::CaseInsensitive);
        assert_eq!(resolution.candidates.len(), 1);
        assert!(!resolution.needs_a_pin());
    }

    /// A digest the graph cannot compare against, because its tree carries no
    /// entry for the path, leaves the line in place rather than withholding it
    /// on a guess.
    #[test]
    fn a_path_the_tree_does_not_carry_leaves_the_line_in_place() {
        let graph = InMemoryGraph::new();
        let mut entity = definition();
        entity.metadata.extra.insert(
            "blob_hash".to_string(),
            serde_json::Value::String("aa".repeat(32)),
        );
        graph.upsert_entity(&entity).unwrap();

        let pointer = entity_pointer(&graph, &entity);
        assert!(!pointer.stale);
        assert_eq!(pointer.render(), "src/buffer.c:6");
    }
}
