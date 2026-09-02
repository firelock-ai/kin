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

use anyhow::Result;
use kin_model::{Entity, EntityFilter, EntityId, GraphStore};

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
/// Ordered by [`kin_core::definition_identity_key`]: a body beats a declaration,
/// then the file path, then the start line, then the id. Every term is read off
/// the entity record, so the choice is a property of the candidates and not of
/// the order the store listed them in, which is what made the same question
/// answer two ways across six stores built from one tree (FIR-3071).
pub fn choose_definition(matches: &[Entity]) -> Option<&Entity> {
    matches.iter().min_by(|a, b| {
        kin_core::definition_identity_key(a).cmp(&kin_core::definition_identity_key(b))
    })
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
pub fn twin_note(query: &str, chosen: &Entity, matches: &[Entity]) -> Vec<String> {
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
        entity_location(chosen),
    )];
    let others: Vec<&Entity> = matches
        .iter()
        .filter(|candidate| candidate.id != chosen.id)
        .collect();
    for candidate in others.iter().take(MAX_LISTED_TWINS) {
        let identity = kin_review::StableEntityIdentity::from_entity(candidate);
        lines.push(format!(
            "note: also {} ({}).",
            entity_location(candidate),
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

/// `path:line` for an entity, or `unknown` when the graph carries no file for
/// it. Presentation only; resolution is keyed on graph identity, never on paths.
pub fn entity_location(entity: &Entity) -> String {
    crate::commands::declaration_neighbors::entity_location(entity)
        .unwrap_or_else(|| "unknown".to_string())
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
        let forward = vec![definition(), declaration()];
        let reversed = vec![declaration(), definition()];

        let first = choose_definition(&forward).expect("a candidate");
        let second = choose_definition(&reversed).expect("a candidate");

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
        let matches = vec![definition(), declaration()];
        let chosen = choose_definition(&matches).expect("a candidate");
        let note = twin_note("buffer_grow", chosen, &matches).join("\n");

        assert!(note.contains("names 2 entities"), "{note}");
        assert!(note.contains("traced the definition"), "{note}");
        assert!(note.contains("src/buffer.h"), "{note}");
        assert!(note.contains("--file src/buffer.c"), "{note}");
    }

    #[test]
    fn twin_note_is_silent_when_the_name_reaches_one_entity() {
        let matches = vec![definition()];
        let chosen = choose_definition(&matches).expect("a candidate");
        assert!(twin_note("buffer_grow", chosen, &matches).is_empty());
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
}
