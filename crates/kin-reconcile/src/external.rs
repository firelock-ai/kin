// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Source-owned external imports on the live transaction path.

use std::collections::{HashMap, HashSet};

use kin_blobs::BlobStore;
use kin_index::IndexedFile;
use kin_model::{Entity, GraphStore, ParseState, Relation, RelationId, TreeEntry};

use crate::error::{ReconcileError, Result};

pub(crate) fn claims_external_import(relation: &Relation) -> bool {
    matches!(
        relation.kind,
        kin_model::RelationKind::Calls | kin_model::RelationKind::References
    ) && relation.evidence.iter().any(|evidence| {
        matches!(
            evidence.parser_rule.as_deref(),
            Some(
                kin_index::EXTERNAL_IMPORT_REFERENCE_RULE
                    | kin_index::JS_IMPORTED_GETTER_REFERENCE_RULE
            )
        )
    })
}

pub(crate) fn has_import_pinned_reference(indexed: &IndexedFile) -> bool {
    indexed.extracted_relations.iter().any(|raw| {
        matches!(
            raw.kind,
            kin_model::RelationKind::Calls | kin_model::RelationKind::References
        ) && raw.import_source.is_some()
    })
}

#[derive(Default)]
pub(crate) struct ExternalImports {
    pub targets: Vec<Entity>,
    pub retired: HashSet<RelationId>,
    /// The part of `retired` a startup re-derivation retired on a failed
    /// recount alone: this build's parser, re-reading the exact bytes the edge
    /// was recorded against, derives a different declaration or occurrence
    /// count. Always empty unless `prepare` was asked to retire unprovable
    /// edges.
    pub unreproduced: HashSet<RelationId>,
}

fn invalid(reason: impl std::fmt::Display) -> ReconcileError {
    ReconcileError::InvalidTransaction(format!("external import authority: {reason}"))
}

/// Which occurrences a placeholder's evidence counts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OccurrenceRule {
    /// What this build's linker mints, as
    /// [`kin_index::is_external_import_occurrence`] states it: a receiverless
    /// call or any reference, and the JavaScript imported-getter receiver under
    /// its own rule.
    Current,
    /// What an earlier linker minted before it stopped counting receiver
    /// calls: a call on a receiver whose member name matched an import was
    /// counted as an occurrence of that import too. Only ever a proof that a
    /// stored edge came from those bytes, so that it may be retired.
    ReceiverCallsCounted,
}

/// Source interpretation may change between parser versions. These are the
/// only mismatches a startup migration may replace; structural authority and
/// source I/O failures never become a migration permission.
#[derive(Debug)]
enum SourceProof {
    Proven,
    DeclarationMismatch,
    OccurrenceMismatch(RelationId),
}

impl SourceProof {
    fn require(self) -> Result<()> {
        match self {
            Self::Proven => Ok(()),
            Self::DeclarationMismatch => Err(invalid(
                "source declaration does not match its recorded blob",
            )),
            Self::OccurrenceMismatch(id) => {
                Err(invalid(format!("unverified import occurrences for {id}")))
            }
        }
    }
}

/// Current edges must bind exactly to the parser's immutable input.
fn verify_source(relation: &Relation, source: &Entity, indexed: &IndexedFile) -> Result<()> {
    source_proof_under(relation, source, indexed, OccurrenceRule::Current)?.require()
}

/// Both historical counting rules are exact proofs, not name-only inference.
fn stored_source_proof(
    relation: &Relation,
    source: &Entity,
    indexed: &IndexedFile,
) -> Result<SourceProof> {
    let current = source_proof_under(relation, source, indexed, OccurrenceRule::Current)?;
    if matches!(current, SourceProof::Proven) {
        return Ok(current);
    }
    let earlier = source_proof_under(
        relation,
        source,
        indexed,
        OccurrenceRule::ReceiverCallsCounted,
    )?;
    Ok(if matches!(earlier, SourceProof::Proven) {
        earlier
    } else {
        current
    })
}

fn verify_stored_source(relation: &Relation, source: &Entity, indexed: &IndexedFile) -> Result<()> {
    stored_source_proof(relation, source, indexed)?.require()
}

fn source_proof_under(
    relation: &Relation,
    source: &Entity,
    indexed: &IndexedFile,
    rule: OccurrenceRule,
) -> Result<SourceProof> {
    if !kin_index::is_external_import_placeholder(relation)
        || relation.src.as_entity() != Some(source.id)
        || source.file_origin.as_ref() != Some(&indexed.file_id)
        || !matches!(indexed.parse_state, ParseState::Valid)
    {
        return Err(invalid(format!("invalid source proof for {}", relation.id)));
    }
    let span = source
        .span
        .as_ref()
        .ok_or_else(|| invalid("source has no span"))?;
    let declarations: Vec<_> = indexed
        .entities
        .iter()
        .filter(|entity| {
            entity.name == source.name
                && entity.kind == source.kind
                && entity.span.as_ref() == Some(span)
                && entity.fingerprint == source.fingerprint
        })
        .collect();
    if declarations.len() != 1 {
        return Ok(SourceProof::DeclarationMismatch);
    }
    let source_index = kin_index::RelationSourceIndex::new(&indexed.entities);
    for evidence in &relation.evidence {
        let count = indexed
            .extracted_relations
            .iter()
            .filter(|raw| {
                raw.kind == relation.kind
                    && raw.src_name == source.name
                    && raw.import_source == relation.import_source
                    && Some(raw.dst_name.as_str()) == evidence.token.as_deref()
                    && occurrence_matches_under(
                        raw,
                        evidence,
                        &indexed.file_id,
                        source.language,
                        rule,
                    )
                    && source_index.resolve(raw).is_some_and(|owner| {
                        owner.kind == source.kind
                            && owner.span.as_ref() == Some(span)
                            && owner.fingerprint == source.fingerprint
                    })
                    && raw.site.as_ref().is_some_and(|site| {
                        span.start_byte <= site.start_byte
                            && site.start_byte < site.end_byte
                            && site.end_byte <= span.end_byte
                    })
            })
            .count();
        if count == 0 || count != evidence.occurrence_count as usize {
            return Ok(SourceProof::OccurrenceMismatch(relation.id));
        }
    }

    Ok(SourceProof::Proven)
}

fn occurrence_matches_under(
    raw: &kin_parser::ExtractedRelation,
    evidence: &kin_model::RelationEvidence,
    file: &kin_model::FilePathId,
    language: kin_model::LanguageId,
    rule: OccurrenceRule,
) -> bool {
    match (rule, evidence.parser_rule.as_deref()) {
        (OccurrenceRule::ReceiverCallsCounted, Some(kin_index::EXTERNAL_IMPORT_REFERENCE_RULE)) => {
            kin_index::is_external_import_occurrence(raw, language)
                || (raw.kind == kin_model::RelationKind::Calls
                    && !kin_index::is_js_imported_getter_receiver(raw))
        }
        _ => external_occurrence_matches(raw, evidence, file, language),
    }
}

fn external_occurrence_matches(
    raw: &kin_parser::ExtractedRelation,
    evidence: &kin_model::RelationEvidence,
    file: &kin_model::FilePathId,
    language: kin_model::LanguageId,
) -> bool {
    match evidence.parser_rule.as_deref() {
        Some(kin_index::EXTERNAL_IMPORT_REFERENCE_RULE) => {
            kin_index::is_external_import_occurrence(raw, language)
        }
        Some(kin_index::JS_IMPORTED_GETTER_REFERENCE_RULE) => {
            kin_index::is_js_imported_getter_receiver(raw)
                && raw.site.as_ref().is_some_and(|site| {
                    evidence.source_span.as_ref() == Some(&site.to_source_span(file))
                })
        }
        _ => false,
    }
}

/// Verify an existing target without rewriting shared language or commit
/// provenance. Every identity-bearing field must still match the shared
/// factory, so an occupied ID is never silently enrolled as an external node.
fn verify_target(expected: &Entity, held: &Entity) -> Result<()> {
    let mut comparable = expected.clone();
    comparable.language = held.language;
    comparable.created_in = held.created_in;
    if comparable != *held {
        return Err(invalid(format!(
            "external target identity collision at {}",
            expected.id
        )));
    }
    Ok(())
}

/// Prove a stored external binding against one complete immutable predecessor.
/// Merge planning may select a different body for the same declaration identity;
/// that mixed candidate is not evidence of what the old binding referred to.
pub fn verify_external_import_predecessor(
    predecessor: &kin_model::graph::ResolvedGraphState,
    relation: &Relation,
    blobs: &BlobStore,
) -> Result<()> {
    if predecessor.relations.get(&relation.id) != Some(relation) {
        return Err(invalid("external binding differs from its predecessor"));
    }
    let source = relation
        .src
        .as_entity()
        .and_then(|id| predecessor.entities.get(&id))
        .ok_or_else(|| invalid("predecessor external source is absent"))?;
    let file = source
        .file_origin
        .as_ref()
        .ok_or_else(|| invalid("predecessor external source has no file"))?;
    let path = kin_model::RepoPath::from_utf8(file.0.clone()).map_err(invalid)?;
    let hash = source
        .metadata
        .extra
        .get("blob_hash")
        .and_then(|value| value.as_str())
        .ok_or_else(|| invalid("predecessor external source has no digest"))?;
    let digest = kin_blobs::Hash256::from_hex(hash).map_err(invalid)?;
    if predecessor
        .tree
        .artifact_at_path(&path)
        .and_then(|artifact| artifact.entry.blob_identity())
        != Some(kin_model::Hash256::from_bytes(digest.0))
    {
        return Err(invalid("predecessor external source differs from its tree"));
    }
    let expected = kin_index::placeholder_target_entity(relation, source.language)
        .ok_or_else(|| invalid("predecessor external target proof is invalid"))?;
    let target = predecessor
        .entities
        .get(&expected.id)
        .ok_or_else(|| invalid("predecessor external target is absent"))?;
    verify_target(&expected, target)?;
    let bytes = blobs.read(&digest)?;
    if kin_blobs::digest(&bytes) != digest {
        return Err(invalid("predecessor source blob digest mismatch"));
    }
    let indexed = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(file, &bytes, digest)?
        .indexed_file;
    verify_stored_source(relation, source, &indexed)
}

fn checked_target(
    expected: &Entity,
    allow_new: bool,
    read: impl FnOnce() -> Result<Option<Entity>>,
) -> Result<Option<Entity>> {
    match read()? {
        Some(held) => {
            verify_target(expected, &held)?;
            Ok(None)
        }
        None if allow_new => Ok(Some(expected.clone())),
        None => Err(invalid("stored external target is not admitted")),
    }
}

/// Startup may replace an older parser's declaration or occurrence accounting.
/// It still requires a factory-owned edge, its exact admitted target, and
/// readable, digest-verified old source with a complete parse. Every other
/// provenance or I/O failure refuses the whole preparation. Each edge retired
/// that way is named in [`ExternalImports::unreproduced`], so the start counts
/// and discloses it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare<G: GraphStore>(
    graph: &G,
    indexed: &IndexedFile,
    stable_entities: &[Entity],
    existing: &[Entity],
    current: &[Relation],
    prior: &[Relation],
    blobs: &BlobStore,
    pass_ran: bool,
    retire_unprovable: bool,
) -> Result<ExternalImports> {
    if !pass_ran && has_import_pinned_reference(indexed) {
        return Err(invalid(
            "import-pinned source has no admitted live linker pass",
        ));
    }
    let old: Vec<_> = prior
        .iter()
        .filter(|relation| {
            claims_external_import(relation)
                && existing
                    .iter()
                    .any(|entity| relation.src.as_entity() == Some(entity.id))
        })
        .collect();
    if current.is_empty() && old.is_empty() {
        return Ok(ExternalImports::default());
    }
    if !pass_ran || !matches!(indexed.parse_state, ParseState::Valid) {
        return Err(invalid("a complete current source pass is unavailable"));
    }
    let admitted = graph
        .get_tree_entry(&indexed.file_id)
        .map_err(|error| ReconcileError::Graph(error.to_string()))?;
    if !matches!(admitted, Some(TreeEntry::Blob { hash, .. }) if hash.to_string() == indexed.blob_hash.to_string())
    {
        return Err(invalid(
            "current source bytes are not the admitted file version",
        ));
    }

    let mut result = ExternalImports::default();
    let mut targets = HashSet::new();
    let mut produced = HashSet::new();
    for relation in current {
        let source = stable_entities
            .iter()
            .find(|entity| relation.src.as_entity() == Some(entity.id))
            .ok_or_else(|| invalid("external source is not in this transaction"))?;
        verify_source(relation, source, indexed)?;
        if prior
            .iter()
            .any(|held| held.id == relation.id && !kin_index::is_external_import_placeholder(held))
        {
            return Err(invalid(
                "external relation identity is occupied by other evidence",
            ));
        }
        if !produced.insert(relation.id) {
            return Err(invalid("duplicate external relation identity"));
        }
        let target = kin_index::placeholder_target_entity(relation, source.language)
            .ok_or_else(|| invalid("external target factory refused the proof"))?;
        if stable_entities
            .iter()
            .chain(existing)
            .any(|entity| entity.id == target.id)
        {
            return Err(invalid(
                "external target collides with a source declaration",
            ));
        }
        if targets.insert(target.id) {
            if let Some(new) = checked_target(&target, true, || {
                graph
                    .get_entity(&target.id)
                    .map_err(|error| ReconcileError::Graph(error.to_string()))
            })? {
                result.targets.push(new);
            }
        }
    }

    // Old blobs are CAS inputs, never workspace paths. Cache per immutable
    // version so multiple external calls in one file pay for one parse.
    let mut parsed = HashMap::new();
    for relation in old {
        if !kin_index::is_external_import_placeholder(relation) {
            return Err(invalid(format!(
                "malformed stored external proof {}",
                relation.id
            )));
        }
        let source = existing
            .iter()
            .find(|entity| relation.src.as_entity() == Some(entity.id))
            .expect("old relations were selected by their source");
        let expected = kin_index::placeholder_target_entity(relation, source.language)
            .ok_or_else(|| invalid("stored external target proof is invalid"))?;
        checked_target(&expected, false, || {
            graph
                .get_entity(&expected.id)
                .map_err(|error| ReconcileError::Graph(error.to_string()))
        })?;
        if produced.contains(&relation.id) {
            continue;
        }
        // Removing the declaration already collects all of its incident edges.
        if !stable_entities.iter().any(|entity| entity.id == source.id) {
            continue;
        }
        let proof = prove_stored(relation, source, indexed, blobs, &mut parsed)?;
        if retire_unprovable {
            if !matches!(proof, SourceProof::Proven) {
                tracing::debug!(
                    relation = %relation.id,
                    mismatch = ?proof,
                    "retiring a factory-owned external edge whose source derivation changed"
                );
                result.unreproduced.insert(relation.id);
            }
        } else {
            proof.require()?;
        }
        result.retired.insert(relation.id);
    }
    result.targets.sort_by_key(|entity| entity.id);
    Ok(result)
}

/// The provenance proof a stored external edge must pass before a live edit
/// may retire it, as one fallible step: its shape, its target, and its
/// occurrences re-read from the source bytes its declaration records.
fn prove_stored(
    relation: &Relation,
    source: &Entity,
    indexed: &IndexedFile,
    blobs: &BlobStore,
    parsed: &mut HashMap<String, IndexedFile>,
) -> Result<SourceProof> {
    if !kin_index::is_external_import_placeholder(relation) {
        return Err(invalid(format!(
            "malformed stored external proof {}",
            relation.id
        )));
    }
    kin_index::placeholder_target_entity(relation, source.language)
        .ok_or_else(|| invalid("stored external target proof is invalid"))?;
    let hash = source
        .metadata
        .extra
        .get("blob_hash")
        .and_then(|value| value.as_str())
        .ok_or_else(|| invalid("obsolete external edge has no recorded source blob"))?;
    if let std::collections::hash_map::Entry::Vacant(entry) = parsed.entry(hash.to_owned()) {
        let digest = kin_blobs::Hash256::from_hex(hash).map_err(invalid)?;
        let bytes = blobs.read(&digest)?;
        if kin_blobs::digest(&bytes) != digest {
            return Err(invalid("old source blob digest mismatch"));
        }
        let previous = kin_index::IndexPipeline::new()
            .index_file_content_with_tests(&indexed.file_id, &bytes, digest)?
            .indexed_file;
        entry.insert(previous);
    }
    stored_source_proof(relation, source, &parsed[hash])
}

/// A local destination can arrive after its callers. Re-read only those waiting
/// source files whose new bindings meet old external edges. Their admitted CAS
/// version, rather than the in-memory waiting fragment, authorizes withdrawal.
///
/// With `retire_unprovable`, which only a startup re-derivation sets, a waiting
/// source whose own derivation is stale is left for its own re-derivation in the
/// same pass rather than refusing this one: its declarations cannot anchor a
/// replacement proof until they are re-derived from its bytes.
pub(crate) fn retire_rebound<G: GraphStore>(
    graph: &G,
    current_sources: &[Entity],
    removed_entities: &HashSet<kin_model::EntityId>,
    rebound: &[Relation],
    blobs: &BlobStore,
    retire_unprovable: bool,
    relink: impl Fn(&kin_index::FileParseData) -> Result<Vec<Relation>>,
) -> Result<Vec<Relation>> {
    let mut files = HashSet::new();
    let mut removed = Vec::new();
    for binding in rebound {
        let Some(id) = binding.src.as_entity() else {
            continue;
        };
        if current_sources.iter().any(|entity| entity.id == id) {
            continue;
        }
        let source = graph
            .get_entity(&id)
            .map_err(|error| ReconcileError::Graph(error.to_string()))?
            .ok_or_else(|| invalid("waiting source is no longer admitted"))?;
        let Some(file) = source.file_origin else {
            continue;
        };
        if !files.insert(file.clone()) {
            continue;
        }
        let entities = graph
            .query_entities(&kin_model::EntityFilter {
                file_path: Some(file.clone()),
                ..Default::default()
            })
            .map_err(|error| ReconcileError::Graph(error.to_string()))?;
        let mut old = HashMap::new();
        for entity in &entities {
            for relation in graph
                .get_all_relations_for_entity(&entity.id)
                .map_err(|error| ReconcileError::Graph(error.to_string()))?
            {
                if relation.src.as_entity() == Some(entity.id) && claims_external_import(&relation)
                {
                    old.insert(relation.id, relation);
                }
            }
        }
        if old.is_empty() {
            continue;
        }
        let entry = graph
            .get_tree_entry(&file)
            .map_err(|error| ReconcileError::Graph(error.to_string()))?;
        let Some(TreeEntry::Blob { hash, .. }) = entry else {
            return Err(invalid("waiting source has no admitted blob"));
        };
        let hash_text = hash.to_string();
        if entities.iter().any(|entity| {
            entity
                .metadata
                .extra
                .get("blob_hash")
                .and_then(|value| value.as_str())
                != Some(hash_text.as_str())
        }) {
            if retire_unprovable {
                continue;
            }
            return Err(invalid(
                "waiting source metadata differs from its admitted blob",
            ));
        }
        let digest = kin_blobs::Hash256::from_hex(&hash_text).map_err(invalid)?;
        let bytes = blobs.read(&digest)?;
        if kin_blobs::digest(&bytes) != digest {
            return Err(invalid("waiting source blob digest mismatch"));
        }
        let indexed = kin_index::IndexPipeline::new()
            .index_file_content_with_tests(&file, &bytes, digest)?
            .indexed_file;
        if !matches!(indexed.parse_state, ParseState::Valid) {
            return Err(invalid("waiting source parse is incomplete"));
        }
        if indexed.entities.len() != entities.len() {
            if retire_unprovable {
                continue;
            }
            return Err(invalid("waiting declaration set differs from graph truth"));
        }
        let mut remapped = Vec::new();
        let mut claimed = HashSet::new();
        let mut stale = false;
        for parsed in &indexed.entities {
            let matches: Vec<_> = entities
                .iter()
                .filter(|entity| {
                    entity.name == parsed.name
                        && entity.kind == parsed.kind
                        && entity.span == parsed.span
                        && entity.fingerprint == parsed.fingerprint
                })
                .collect();
            if matches.len() != 1 || !claimed.insert(matches[0].id) {
                if retire_unprovable {
                    stale = true;
                    break;
                }
                return Err(invalid(
                    "waiting declaration identity is ambiguous or stale",
                ));
            }
            remapped.push(matches[0].clone());
        }
        if stale {
            continue;
        }
        let input = kin_index::FileParseData {
            file_path: file.0.clone(),
            entities: remapped,
            relations: indexed.extracted_relations.clone(),
            imports: indexed.imports.clone(),
        };
        let fresh = relink(&input)?;
        // A prior derived transaction may have failed at application, leaving
        // its proposed destinations in the linker's cache. That cache can
        // derive candidates, but cannot authorize destructive graph updates.
        for relation in fresh
            .iter()
            .filter(|relation| !claims_external_import(relation))
        {
            for id in [relation.src, relation.dst]
                .iter()
                .filter_map(|node| node.as_entity())
            {
                if removed_entities.contains(&id) {
                    return Err(invalid(
                        "replacement endpoint is removed in this transaction",
                    ));
                }
                if !current_sources.iter().any(|entity| entity.id == id)
                    && graph
                        .get_entity(&id)
                        .map_err(|error| ReconcileError::Graph(error.to_string()))?
                        .is_none()
                {
                    return Err(invalid(
                        "replacement depends on an unadmitted cached target",
                    ));
                }
            }
        }
        let mut retained = HashSet::new();
        for relation in fresh
            .iter()
            .filter(|relation| claims_external_import(relation))
        {
            let source = entities
                .iter()
                .find(|entity| relation.src.as_entity() == Some(entity.id))
                .ok_or_else(|| invalid("relinked external source is not admitted"))?;
            verify_source(relation, source, &indexed)?;
            retained.insert(relation.id);
        }
        let source_index = kin_index::RelationSourceIndex::new(&indexed.entities);
        for relation in old.into_values() {
            let source = entities
                .iter()
                .find(|entity| relation.src.as_entity() == Some(entity.id))
                .ok_or_else(|| invalid("stored external source is not admitted"))?;
            verify_stored_source(&relation, source, &indexed)?;
            let expected = kin_index::placeholder_target_entity(&relation, source.language)
                .ok_or_else(|| invalid("stored external target proof is invalid"))?;
            checked_target(&expected, false, || {
                graph
                    .get_entity(&expected.id)
                    .map_err(|error| ReconcileError::Graph(error.to_string()))
            })?;
            if !retained.contains(&relation.id) {
                let token = relation.evidence[0].token.as_deref();
                for occurrence in indexed.extracted_relations.iter().filter(|raw| {
                    raw.kind == relation.kind
                        && raw.src_name == source.name
                        && raw.import_source == relation.import_source
                        && Some(raw.dst_name.as_str()) == token
                        && relation.evidence.iter().any(|evidence| {
                            external_occurrence_matches(raw, evidence, &file, source.language)
                        })
                        && source_index.resolve(raw).is_some_and(|owner| {
                            owner.kind == source.kind
                                && owner.span == source.span
                                && owner.fingerprint == source.fingerprint
                        })
                }) {
                    let span = occurrence
                        .site
                        .as_ref()
                        .ok_or_else(|| invalid("replacement occurrence has no exact site"))?
                        .to_source_span(&file);
                    let carries_site = |candidate: &Relation| {
                        candidate
                            .evidence
                            .iter()
                            .any(|evidence| evidence.source_span.as_ref() == Some(&span))
                    };
                    if !fresh.iter().any(|candidate| {
                        candidate.src == relation.src
                            && candidate.kind == relation.kind
                            && !claims_external_import(candidate)
                            && carries_site(candidate)
                            && rebound.iter().any(|proposed| {
                                proposed.id == candidate.id && carries_site(proposed)
                            })
                    }) {
                        return Err(invalid(
                            "obsolete external occurrence has no proposed admissible replacement",
                        ));
                    }
                }
                removed.push(relation);
            }
        }
    }
    removed.sort_by_key(|relation| relation.id);
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Entity {
        let file = kin_model::FilePathId::new("caller.js");
        let bytes = b"const remote = require('external-one'); function run() { return remote(); }";
        let indexed = kin_index::IndexPipeline::new()
            .index_file_content_with_tests(&file, bytes, kin_blobs::digest(bytes))
            .unwrap()
            .indexed_file;
        let artifact = kin_model::ArtifactId::new();
        let source = kin_index::FileParseData {
            file_path: file.0.clone(),
            entities: indexed.entities,
            relations: indexed.extracted_relations,
            imports: indexed.imports,
        };
        let linked =
            kin_index::link_cross_file(&[source], &HashMap::from([(file.0, artifact)])).unwrap();
        let edge = linked
            .iter()
            .find(|relation| kin_index::is_external_import_placeholder(relation))
            .unwrap();
        kin_index::placeholder_target_entity(edge, kin_model::LanguageId::JavaScript).unwrap()
    }

    #[test]
    fn target_read_failure_is_never_treated_as_absence_or_permission_to_add() {
        let expected = target();
        for allow_new in [false, true] {
            let error = checked_target(&expected, allow_new, || {
                Err(ReconcileError::Graph("owned injected read failure".into()))
            })
            .unwrap_err();
            assert!(
                matches!(error, ReconcileError::Graph(message) if message == "owned injected read failure")
            );
        }
        assert!(checked_target(&expected, false, || Ok(None)).is_err());
        assert_eq!(
            checked_target(&expected, true, || Ok(None)).unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn existing_target_keeps_its_other_importers_language_and_commit_provenance() {
        let expected = target();
        let mut held = expected.clone();
        held.language = kin_model::LanguageId::Python;
        held.created_in = Some(kin_model::SemanticChangeId::from_hash(
            kin_model::Hash256::from_bytes([7; 32]),
        ));
        assert!(checked_target(&expected, true, || Ok(Some(held.clone())))
            .unwrap()
            .is_none());
        held.signature = "unrelated definition".into();
        assert!(checked_target(&expected, true, || Ok(Some(held))).is_err());
    }
}
