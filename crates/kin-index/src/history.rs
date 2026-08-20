// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Deterministic semantic enrichment for exact historical trees.
//!
//! This boundary never reads a checkout. It derives supported-language
//! entities and relations solely from graph-owned resolved trees and immutable
//! CAS bodies. Every other artifact remains represented by the exact tree even
//! when it has no language adapter.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use kin_blobs::BlobStore;
use kin_model::{
    ArtifactId, ChangeOrigin, Entity, EntityDelta, EntityId, EntityKind, EntityMetadata,
    EntityRole, FilePathId, FingerprintAlgorithm, Hash256, LanguageId, ParseCompleteness, Relation,
    RelationDelta, RelationId, ResolvedTree, SemanticChange, SemanticChangeId, SemanticFingerprint,
    TreeEntry, Visibility,
};
use sha2::{Digest, Sha256};

use crate::classifier::{FileClassification, FileClassifier};
use crate::error::{IndexError, Result};
use crate::linker::{
    is_external_import_placeholder, is_unresolved_receiver_placeholder,
    link_cross_file_borrowed_with_completeness, split_unresolved_receiver_token,
    unresolved_receiver_display_name, ArtifactIdentityMap, FileParseCompletenessMap, FileParseData,
};
use crate::pipeline::IndexPipeline;

/// Declared version of the replay semantics that author historical deltas.
///
/// Kin's deep history is not a stored fact. It is re-authored here from
/// graph-owned trees and CAS bodies, so editing any of the replay functions
/// pinned by `scripts/hydration-semantics-manifest.json` changes what a
/// repository's past is said to contain the next time that repository is
/// admitted. A digest mismatch in that guard is a decision to make, not a file
/// to regenerate: establish whether replay semantics actually changed, and if
/// they did, bump this constant and the manifest's recorded version together.
/// Never regenerate a digest silently.
///
/// This constant is a declaration, not an enforcement point. Nothing persists
/// it beside a graph and nothing compares it when one is opened, and no path
/// re-derives historical deltas for a repository that was already admitted, so
/// bumping it does not invalidate, migrate, or re-enrich an existing graph. A
/// repository admitted under an earlier version keeps whatever its past was
/// authored to contain until it is admitted again, and reports nothing about
/// which version authored it. Coupling the dial to graph authority so a
/// version gap can be detected and refused is open follow-up work.
pub const HYDRATION_SEMANTICS_VERSION: u32 = 8;

/// Semantic graph delta derived for one pre-enrichment change identity.
///
/// Callers apply these deltas to the matching change and then recompute change
/// identities, parent identities, and external aliases in parent-first order.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoricalSemanticDelta {
    pub change_id: SemanticChangeId,
    pub entity_deltas: Vec<EntityDelta>,
    pub relation_deltas: Vec<RelationDelta>,
}

struct ParsedFile {
    completeness: ParseCompleteness,
    entities: Vec<Entity>,
    relations: Vec<kin_parser::ExtractedRelation>,
    imports: Vec<kin_parser::FileImport>,
}

/// One file's parsed semantics, carried forward across commits by reference.
///
/// A commit that touches one file leaves every other file in the tree
/// byte-identical to its parent's, and the fold reuses those parsed results
/// rather than reparsing. Holding the parsed payload behind [`Arc`] makes that
/// reuse a reference count instead of a deep copy of every entity, relation,
/// and import the file declares, which the fold otherwise paid for every
/// unchanged file on every commit in history.
#[derive(Clone)]
struct SemanticFileState {
    artifact_id: ArtifactId,
    entry: TreeEntry,
    completeness: Arc<ParseCompleteness>,
    parse_data: Arc<FileParseData>,
}

#[derive(Clone, Default)]
struct SemanticTreeState {
    files: BTreeMap<ArtifactId, SemanticFileState>,
    entities: BTreeMap<EntityId, Entity>,
    relations: BTreeMap<RelationId, Relation>,
}

/// Derive semantic deltas for parent-first exact history.
///
/// `trees` is keyed by each input change's current identity. The input changes
/// must not already contain semantic deltas: this is a single, explicit build
/// phase, not a best-effort repair path.
pub fn derive_historical_semantic_deltas(
    changes: &[SemanticChange],
    trees: &BTreeMap<SemanticChangeId, ResolvedTree>,
    blob_store: &BlobStore,
) -> Result<Vec<HistoricalSemanticDelta>> {
    let pipeline = IndexPipeline::new();
    // An external target's fingerprint is a pure function of the import source
    // and symbol its identity is derived from, so it is the same value in every
    // tree that observes the import. The fold relinks the whole tree per change,
    // which would otherwise recompute those digests once per commit for a value
    // that cannot change.
    let mut external_fingerprints = BTreeMap::<EntityId, SemanticFingerprint>::new();
    let mut states = BTreeMap::<SemanticChangeId, SemanticTreeState>::new();
    let mut known_changes = HashSet::with_capacity(changes.len());
    let mut remaining_child_uses = BTreeMap::<SemanticChangeId, usize>::new();
    let mut output = Vec::with_capacity(changes.len());

    for change in changes {
        if !known_changes.insert(change.id) {
            return Err(invalid(format!(
                "history repeats change identity {}",
                change.id
            )));
        }
        for parent in &change.parents {
            *remaining_child_uses.entry(*parent).or_default() += 1;
        }
    }
    if trees.len() != changes.len() {
        return Err(invalid(format!(
            "semantic tree map contains {} entries for {} enriched changes",
            trees.len(),
            changes.len()
        )));
    }

    for change in changes {
        if !matches!(change.origin, ChangeOrigin::GitCommit { .. }) {
            return Err(invalid(format!(
                "historical Git enrichment received native change {}",
                change.id
            )));
        }
        if !change.entity_deltas.is_empty() || !change.relation_deltas.is_empty() {
            return Err(invalid(format!(
                "change {} already carries semantic deltas",
                change.id
            )));
        }
        let parent_states = change
            .parents
            .iter()
            .map(|parent| {
                states.get(parent).ok_or_else(|| {
                    invalid(format!(
                        "parent {} of change {} was not enriched first",
                        parent, change.id
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let empty_parent = SemanticTreeState::default();
        let first_parent = parent_states.first().copied().unwrap_or(&empty_parent);
        let tree = trees.get(&change.id).ok_or_else(|| {
            invalid(format!(
                "change {} has no exact resolved tree for semantic enrichment",
                change.id
            ))
        })?;
        let current = semantic_state_for_tree(
            tree,
            &parent_states,
            blob_store,
            &pipeline,
            &mut external_fingerprints,
        )?;
        let entity_deltas = diff_entities(&first_parent.entities, &current.entities);
        let relation_deltas = diff_relations(&first_parent.relations, &current.relations);

        output.push(HistoricalSemanticDelta {
            change_id: change.id,
            entity_deltas,
            relation_deltas,
        });

        drop(parent_states);
        for parent in &change.parents {
            let remaining = remaining_child_uses.get_mut(parent).ok_or_else(|| {
                invalid(format!(
                    "parent {} of change {} has no child-use accounting",
                    parent, change.id
                ))
            })?;
            *remaining = remaining.checked_sub(1).ok_or_else(|| {
                invalid(format!(
                    "parent {} of change {} has invalid child-use accounting",
                    parent, change.id
                ))
            })?;
            if *remaining == 0 {
                states.remove(parent);
            }
        }
        if remaining_child_uses.get(&change.id).copied().unwrap_or(0) > 0 {
            states.insert(change.id, current);
        }
    }

    if !states.is_empty() {
        return Err(invalid(
            "semantic history retained parent state after every child was enriched",
        ));
    }
    Ok(output)
}

fn semantic_state_for_tree(
    tree: &ResolvedTree,
    parents: &[&SemanticTreeState],
    blob_store: &BlobStore,
    pipeline: &IndexPipeline,
    external_fingerprints: &mut BTreeMap<EntityId, SemanticFingerprint>,
) -> Result<SemanticTreeState> {
    let mut files = BTreeMap::new();

    for artifact in tree.artifacts() {
        let Some(path) = artifact.path.as_utf8() else {
            continue;
        };
        let TreeEntry::Blob { hash, .. } = artifact.entry else {
            continue;
        };
        if !matches!(
            FileClassifier::classify(Path::new(path)),
            FileClassification::EntitySource
        ) {
            continue;
        }

        if let Some(existing) = parents.iter().find_map(|parent| {
            parent
                .files
                .get(&artifact.artifact_id)
                .filter(|file| file.parse_data.file_path == path && file.entry == artifact.entry)
        }) {
            if files
                .insert(artifact.artifact_id, existing.clone())
                .is_some()
            {
                return Err(invalid(format!(
                    "tree assigns artifact {:?} to multiple semantic files",
                    artifact.artifact_id
                )));
            }
            continue;
        }

        let body_hash = kin_blobs::Hash256::from_bytes(*hash.as_bytes());
        let body = blob_store.read(&body_hash)?;
        if kin_blobs::digest_bytes(&body) != *hash.as_bytes() {
            return Err(invalid(format!(
                "CAS body for {path} does not match exact tree identity {hash}"
            )));
        }
        if !matches!(
            FileClassifier::classify_with_content(Path::new(path), &body),
            FileClassification::EntitySource
        ) {
            continue;
        }
        let indexed =
            pipeline.index_file_content_with_tests(&FilePathId::new(path), &body, body_hash)?;
        let indexed = indexed.indexed_file;
        let parsed = ParsedFile {
            completeness: indexed.file_layout.parse_completeness,
            entities: indexed.entities,
            relations: indexed.extracted_relations,
            imports: indexed.imports,
        };
        let old_entities = parents
            .iter()
            .filter_map(|parent| parent.files.get(&artifact.artifact_id))
            .flat_map(|file| file.parse_data.entities.iter())
            .collect::<Vec<_>>();
        let entities =
            stabilize_historical_entities(artifact.artifact_id, old_entities, &parsed.entities);
        let state = SemanticFileState {
            artifact_id: artifact.artifact_id,
            entry: artifact.entry,
            completeness: Arc::new(parsed.completeness),
            parse_data: Arc::new(FileParseData {
                file_path: path.to_string(),
                entities,
                relations: parsed.relations,
                imports: parsed.imports,
            }),
        };
        if files.insert(artifact.artifact_id, state).is_some() {
            return Err(invalid(format!(
                "tree assigns artifact {:?} to multiple semantic files",
                artifact.artifact_id
            )));
        }
    }

    // The linker input borrows each file's parsed result rather than copying it.
    // Every entry here is either freshly parsed above or carried forward from a
    // parent, and this runs once per commit over the whole tree, so materializing
    // it would re-copy every entity, relation, and import in the repository for
    // every commit in history.
    let mut parse_data: Vec<&FileParseData> = Vec::with_capacity(files.len());
    let mut completeness = FileParseCompletenessMap::new();
    let mut artifact_ids = ArtifactIdentityMap::new();
    let mut entities = BTreeMap::new();
    for file in files.values() {
        let path = file.parse_data.file_path.as_str();
        if artifact_ids
            .insert(path.to_string(), file.artifact_id)
            .is_some()
        {
            return Err(invalid(format!(
                "tree contains more than one semantic artifact at {path}"
            )));
        }
        completeness.insert(path.to_string(), (*file.completeness).clone());
        for entity in &file.parse_data.entities {
            if let Some(previous) = entities.insert(entity.id, entity.clone()) {
                return Err(invalid(format!(
                    "semantic entity identity {} is duplicated in one tree: {} {:?} from {:?} and {} {:?} from {}",
                    entity.id,
                    previous.name,
                    previous.kind,
                    previous.file_origin,
                    entity.name,
                    entity.kind,
                    path
                )));
            }
        }
        parse_data.push(&file.parse_data);
    }
    parse_data.sort_by(|left, right| left.file_path.cmp(&right.file_path));

    let linked =
        link_cross_file_borrowed_with_completeness(&parse_data, &artifact_ids, &completeness)?;
    entities.extend(external_reference_targets(
        &linked,
        &entities,
        external_fingerprints,
    ));
    let mut relations = BTreeMap::new();
    for relation in linked {
        if let Some(absent) = absent_local_endpoint(&relation, &entities) {
            // A change carries the entity set of its own tree, so replaying it
            // can only bind an edge whose endpoints that tree defines. Every
            // cross-repo destination now has one, so an absent endpoint here is
            // inconsistent state and fails closed instead of being admitted.
            return Err(invalid(format!(
                "linked relation {} names {} entity {} that the tree does not define",
                relation.id,
                if absent.is_destination {
                    "destination"
                } else {
                    "source"
                },
                absent.entity_id
            )));
        }
        if relations.insert(relation.id, relation).is_some() {
            return Err(invalid(
                "cross-file linker returned a duplicate relation identity",
            ));
        }
    }

    Ok(SemanticTreeState {
        files,
        entities,
        relations,
    })
}

/// An entity endpoint of a linked relation that the tree does not define.
struct AbsentEndpoint {
    entity_id: EntityId,
    is_destination: bool,
}

/// Bind a graph-owned destination for every cross-repo reference the linker
/// produced against `entities`.
///
/// The linker answers an import it cannot resolve locally with a deterministic
/// placeholder destination naming the symbol another repository owns. That is
/// the one endpoint this tree cannot supply from its own files, and a change
/// whose relation names an entity nothing defines does not replay, so the
/// reference used to be discarded: a freshly imported repository held no
/// cross-repo references at all and answered every cross-repo query empty.
///
/// Binding an external target instead makes the reference complete,
/// change-owned truth at the admission boundary. The target keeps the linker's
/// deterministic identity, so every commit that observes the same import binds
/// the same node. It carries no file origin, because this tree does not contain
/// the definition, and no signature, because none was observed. Its uniform
/// [`EntityKind::Module`] says only what this repository can prove, that the
/// symbol is reached through a module it does not own, and keeps external
/// targets from ever matching a local definition by kind.
///
/// Every field is derived from the target itself rather than from whichever
/// importer happened to be walked first, so a commit that only reorders or
/// renames unrelated files cannot restate the target and make history record a
/// modification to a node it never touched.
fn external_reference_targets(
    linked: &[Relation],
    entities: &BTreeMap<EntityId, Entity>,
    fingerprints: &mut BTreeMap<EntityId, SemanticFingerprint>,
) -> BTreeMap<EntityId, Entity> {
    // One target can be imported by several files, and in a polyglot tree those
    // importers do not share a language. The importers are collected first so
    // the language is chosen from all of them by a total order, because the id
    // the linker derives excludes language: picking the first importer in walk
    // order would let an unrelated added or renamed file change which language a
    // target claims.
    let mut importers: BTreeMap<EntityId, (&str, &str, Vec<LanguageId>)> = BTreeMap::new();
    for relation in linked {
        if !is_external_import_placeholder(relation) {
            continue;
        }
        let Some(destination) = relation.dst.as_entity() else {
            continue;
        };
        if entities.contains_key(&destination) {
            continue;
        }
        // The placeholder contract guarantees a local source, a non-empty
        // import source, and exactly one evidence entry carrying the symbol.
        let (Some(source), Some(import_source), Some(symbol)) = (
            relation.src.as_entity().and_then(|id| entities.get(&id)),
            relation.import_source.as_deref(),
            relation
                .evidence
                .first()
                .and_then(|evidence| evidence.token.as_deref()),
        ) else {
            continue;
        };
        importers
            .entry(destination)
            .or_insert((import_source, symbol, Vec::new()))
            .2
            .push(source.language);
    }

    // The second placeholder class: a member call whose receiver resolves to
    // nothing this repository defines. It carries no import source, because
    // there is no module to name, so its identity and its display name come
    // from the member expression the evidence recorded as written.
    let mut receivers: BTreeMap<EntityId, (String, Vec<LanguageId>)> = BTreeMap::new();
    for relation in linked {
        if !is_unresolved_receiver_placeholder(relation) {
            continue;
        }
        let Some(destination) = relation.dst.as_entity() else {
            continue;
        };
        if entities.contains_key(&destination) {
            continue;
        }
        let (Some(source), Some(token)) = (
            relation.src.as_entity().and_then(|id| entities.get(&id)),
            relation
                .evidence
                .first()
                .and_then(|evidence| evidence.token.as_deref()),
        ) else {
            continue;
        };
        let Some((receiver, symbol)) = split_unresolved_receiver_token(token) else {
            continue;
        };
        receivers
            .entry(destination)
            .or_insert_with(|| {
                (
                    unresolved_receiver_display_name(receiver, symbol),
                    Vec::new(),
                )
            })
            .1
            .push(source.language);
    }

    let mut targets = BTreeMap::new();
    for (destination, (display_name, languages)) in receivers {
        let fingerprint = fingerprints
            .entry(destination)
            .or_insert_with(|| external_reference_fingerprint("", &display_name))
            .clone();
        let Some(language) = lowest_language(&languages) else {
            continue;
        };
        targets.insert(
            destination,
            external_reference_entity(destination, &display_name, language, fingerprint),
        );
    }
    for (destination, (import_source, symbol, languages)) in importers {
        let fingerprint = fingerprints
            .entry(destination)
            .or_insert_with(|| external_reference_fingerprint(import_source, symbol))
            .clone();
        let Some(language) = lowest_language(&languages) else {
            continue;
        };
        targets.insert(
            destination,
            external_reference_entity(destination, symbol, language, fingerprint),
        );
    }
    targets
}

/// Choose one language from every language that reached an external target.
///
/// [`LanguageId`] carries no total order of its own, so the languages are
/// ordered by their canonical names. Any total order would do; what matters is
/// that the choice depends on the set of importing languages and on nothing
/// else, so it holds still while that set does.
fn lowest_language(languages: &[LanguageId]) -> Option<LanguageId> {
    languages
        .iter()
        .min_by_key(|language| language.to_string())
        .copied()
}

/// Report whether `entity` is an external reference target rather than
/// something this repository defines.
///
/// Consumers of graph truth need this because such a target answers a different
/// question than every other entity: it names a symbol reached through a module
/// this repository does not own, so it has no file, no span, and no signature to
/// report, and it is never the definition of anything found here.
///
/// The test is deliberately the conjunction of the role and the absent file
/// origin rather than the role alone. [`EntityRole::External`] is also assigned
/// by path classification to real, locally defined entities under `third_party/`
/// and its siblings, and those own their source; only a target with no file
/// origin at all stands for a definition that lives elsewhere.
pub fn is_external_reference_target(entity: &Entity) -> bool {
    entity.role == EntityRole::External && entity.file_origin.is_none()
}

/// The placeholder entity one placeholder relation's destination stands for,
/// or `None` when the relation is not a placeholder.
///
/// Both placeholder classes are handled here so a caller cannot learn one and
/// miss the other. That is not hypothetical: the historical ref view re-links
/// source and inserts the result straight into a snapshot, and admission fails
/// closed on an endpoint no entity backs, so a synthesis that knew only the
/// cross-repo class turned a new class of edge into a hard error the moment one
/// appeared.
///
/// The language comes from the caller because a target defined elsewhere has
/// none of its own; the importing side is the only thing that observed it.
pub fn placeholder_target_entity(relation: &Relation, language: LanguageId) -> Option<Entity> {
    let destination = relation.dst.as_entity()?;
    let token = relation.evidence.first()?.token.as_deref()?;
    if is_external_import_placeholder(relation) {
        let import_source = relation.import_source.as_deref()?;
        let fingerprint = external_reference_fingerprint(import_source, token);
        return Some(external_reference_entity(
            destination,
            token,
            language,
            fingerprint,
        ));
    }
    if is_unresolved_receiver_placeholder(relation) {
        let (receiver, symbol) = split_unresolved_receiver_token(token)?;
        let name = unresolved_receiver_display_name(receiver, symbol);
        let fingerprint = external_reference_fingerprint("", &name);
        return Some(external_reference_entity(
            destination,
            &name,
            language,
            fingerprint,
        ));
    }
    None
}

/// Build the external target a cross-repo reference resolves against.
fn external_reference_entity(
    id: EntityId,
    symbol: &str,
    language: LanguageId,
    fingerprint: SemanticFingerprint,
) -> Entity {
    Entity {
        id,
        kind: EntityKind::Module,
        name: symbol.to_string(),
        language,
        fingerprint,
        file_origin: None,
        span: None,
        signature: String::new(),
        visibility: Visibility::Public,
        role: EntityRole::External,
        doc_summary: None,
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

/// Derive the fingerprint of an external target from the only two facts this
/// repository observed about it.
///
/// The bodies that would produce a real fingerprint live in another repository,
/// so every hash is domain-separated over the import source and symbol instead.
/// That keeps one external target's identity stable across commits while
/// keeping two different targets distinct, and it never coincides with a
/// fingerprint computed over actual source. The stability score is zero because
/// nothing here was measured.
fn external_reference_fingerprint(import_source: &str, symbol: &str) -> SemanticFingerprint {
    let digest = |domain: &str| {
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update((import_source.len() as u64).to_le_bytes());
        hasher.update(import_source.as_bytes());
        hasher.update((symbol.len() as u64).to_le_bytes());
        hasher.update(symbol.as_bytes());
        Hash256::from_bytes(hasher.finalize().into())
    };
    SemanticFingerprint {
        algorithm: FingerprintAlgorithm::V1TreeSitter,
        ast_hash: digest("kin.external-reference.ast.v1"),
        signature_hash: digest("kin.external-reference.signature.v1"),
        behavior_hash: digest("kin.external-reference.behavior.v1"),
        equivalence_hash: digest("kin.external-reference.equivalence.v1"),
        stability_score: 0.0,
    }
}

/// Report the first entity endpoint of `relation` that `entities` does not
/// define, source before destination. Non-entity endpoints are not part of the
/// entity state a change replays, so they are never reported.
fn absent_local_endpoint(
    relation: &Relation,
    entities: &BTreeMap<EntityId, Entity>,
) -> Option<AbsentEndpoint> {
    [(relation.src, false), (relation.dst, true)]
        .into_iter()
        .find_map(|(node, is_destination)| {
            node.as_entity()
                .filter(|entity_id| !entities.contains_key(entity_id))
                .map(|entity_id| AbsentEndpoint {
                    entity_id,
                    is_destination,
                })
        })
}

fn stabilize_historical_entities(
    artifact_id: ArtifactId,
    old_entities: Vec<&Entity>,
    parsed_entities: &[Entity],
) -> Vec<Entity> {
    let mut matched = HashSet::<EntityId>::new();
    let mut in_use = HashSet::<EntityId>::new();
    let mut unmatched = Vec::new();
    let mut current = Vec::with_capacity(parsed_entities.len());

    for parsed in parsed_entities {
        let existing = old_entities
            .iter()
            .filter(|candidate| !matched.contains(&candidate.id))
            .copied()
            .find(|candidate| candidate.name == parsed.name && candidate.kind == parsed.kind)
            .or_else(|| {
                old_entities
                    .iter()
                    .filter(|candidate| !matched.contains(&candidate.id))
                    .copied()
                    .find(|candidate| {
                        candidate.name == parsed.name && candidate.file_origin == parsed.file_origin
                    })
            });
        let mut stabilized = parsed.clone();
        if let Some(old) = existing {
            stabilized.id = old.id;
            stabilized.lineage_parent = old.lineage_parent;
            stabilized.created_in = old.created_in;
            stabilized.superseded_by = old.superseded_by;
            matched.insert(old.id);
            in_use.insert(old.id);
        } else {
            unmatched.push(current.len());
        }
        current.push(stabilized);
    }

    // Deriving an identity from the parser identity alone can land on one this
    // same file already carries. Inheritance deliberately detaches an entity
    // from the position it was first parsed at, so a later definition that
    // takes over that position derives exactly the identity the moved entity
    // still holds: two conditionally compiled definitions of one name are
    // enough. Mint against the identities already in use so distinct
    // definitions can never collapse into one entity.
    for index in unmatched {
        let parser_id = parsed_entities[index].id;
        let mut identity = historical_entity_id(artifact_id, parser_id);
        let mut displacement = 0_u32;
        while !in_use.insert(identity) {
            displacement += 1;
            identity = displaced_historical_entity_id(artifact_id, parser_id, displacement);
        }
        current[index].id = identity;
    }

    current.sort_by_key(|entity| entity.id);
    current
}

fn historical_entity_id(artifact_id: ArtifactId, parser_id: EntityId) -> EntityId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin.historical-entity.v1\0");
    hasher.update(artifact_id.0.as_bytes());
    hasher.update(parser_id.0.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntityId(uuid::Uuid::from_bytes(bytes))
}

/// Derive the identity of a parsed entity whose primary derived identity is
/// already carried by another entity in the same file.
///
/// Kept separate from [`historical_entity_id`] so an identity only ever moves
/// when a collision actually forces it: every entity that can keep its primary
/// derivation keeps exactly the identity it had.
fn displaced_historical_entity_id(
    artifact_id: ArtifactId,
    parser_id: EntityId,
    displacement: u32,
) -> EntityId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin.historical-entity.displaced.v1\0");
    hasher.update(artifact_id.0.as_bytes());
    hasher.update(parser_id.0.as_bytes());
    hasher.update(displacement.to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntityId(uuid::Uuid::from_bytes(bytes))
}

fn diff_entities(
    old: &BTreeMap<EntityId, Entity>,
    new: &BTreeMap<EntityId, Entity>,
) -> Vec<EntityDelta> {
    let mut deltas = Vec::new();
    for (id, old_entity) in old {
        match new.get(id) {
            Some(new_entity) if old_entity == new_entity => {}
            Some(new_entity) => deltas.push(EntityDelta::Modified {
                old: old_entity.clone(),
                new: new_entity.clone(),
            }),
            None => deltas.push(EntityDelta::Removed {
                old: old_entity.clone(),
            }),
        }
    }
    for (id, new_entity) in new {
        if !old.contains_key(id) {
            deltas.push(EntityDelta::Added {
                new: new_entity.clone(),
            });
        }
    }
    deltas.sort_by_key(EntityDelta::target_id);
    deltas
}

fn diff_relations(
    old: &BTreeMap<RelationId, Relation>,
    new: &BTreeMap<RelationId, Relation>,
) -> Vec<RelationDelta> {
    let mut deltas = Vec::new();
    for (id, old_relation) in old {
        match new.get(id) {
            Some(new_relation) if old_relation == new_relation => {}
            Some(new_relation) => deltas.push(RelationDelta::Modified {
                old: old_relation.clone(),
                new: new_relation.clone(),
            }),
            None => deltas.push(RelationDelta::Removed {
                old: old_relation.clone(),
            }),
        }
    }
    for (id, new_relation) in new {
        if !old.contains_key(id) {
            deltas.push(RelationDelta::Added {
                new: new_relation.clone(),
            });
        }
    }
    deltas.sort_by_key(RelationDelta::target_id);
    deltas
}

fn invalid(message: impl Into<String>) -> IndexError {
    IndexError::InvalidHistoricalSemantics(message.into())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use kin_git::{
        admit_semantic_git_import, capture_lossless_git_repository, plan_semantic_git_import,
    };
    use kin_model::{ChangeStore, EntityKind, RepositoryId};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn enriches_supported_languages_from_cas_without_semanticizing_other_artifacts() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);

        write(
            &repository,
            "src/lib.rs",
            b"pub fn helper() -> u8 { 1 }\npub fn answer() -> u8 { helper() }\n",
        );
        write(
            &repository,
            "service/app.py",
            b"def python_value():\n    return 9\n",
        );
        write(
            &repository,
            "compose.yaml",
            b"services:\n  app:\n    build: .\n",
        );
        write(&repository, "Dockerfile", b"FROM scratch\n");
        write(
            &repository,
            "archive/source.unknownlang",
            b"unsupported language remains exact\n",
        );
        write(&repository, "payload.rs", &[0, 255, 0, 128, 42]);
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "mixed exact tree"]);

        write(
            &repository,
            "src/lib.rs",
            b"pub fn helper() -> u8 { 1 }\npub fn answer() -> u8 { helper() + 1 }\n",
        );
        write(
            &repository,
            "compose.yaml",
            b"services:\n  app:\n    build:\n      context: .\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "change code and compose"]);

        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("history-enrichment").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan);

        let first = derive_historical_semantic_deltas(&plan.changes, &trees, &blob_store).unwrap();
        let second = derive_historical_semantic_deltas(&plan.changes, &trees, &blob_store).unwrap();
        assert_eq!(second, first);
        assert_eq!(first.len(), 2);

        let bindings = first
            .iter()
            .map(|delta| {
                (
                    delta.change_id,
                    delta.entity_deltas.clone(),
                    delta.relation_deltas.clone(),
                )
            })
            .collect::<Vec<_>>();
        let enriched = plan
            .clone()
            .with_historical_semantics(&blob_store, &bindings)
            .unwrap();
        enriched.validate(&blob_store).unwrap();
        let admitted = admit_semantic_git_import(&enriched, &blob_store).unwrap();
        admitted.validate(&blob_store).unwrap();
        assert_ne!(enriched.aliases, plan.aliases);
        assert_eq!(
            enriched.changes[1].parents,
            vec![enriched.changes[0].id],
            "semantic binding must reidentify parent edges"
        );
        assert_eq!(
            admitted.changes[0].entity_deltas,
            enriched.changes[0].entity_deltas
        );

        let initial_entities = first[0]
            .entity_deltas
            .iter()
            .filter_map(EntityDelta::new_state)
            .collect::<Vec<_>>();
        assert!(initial_entities
            .iter()
            .any(|entity| entity.kind == EntityKind::Function && entity.name == "answer"));
        assert!(initial_entities
            .iter()
            .any(|entity| entity.kind == EntityKind::Function && entity.name == "python_value"));
        assert!(initial_entities.iter().all(|entity| {
            entity
                .file_origin
                .as_ref()
                .is_some_and(|origin| origin.0 == "src/lib.rs" || origin.0 == "service/app.py")
        }));
        assert!(!first[0].relation_deltas.is_empty());

        let initial_answer = initial_entities
            .iter()
            .find(|entity| entity.name == "answer")
            .unwrap();
        let modified_answer = first[1]
            .entity_deltas
            .iter()
            .find_map(|delta| match delta {
                EntityDelta::Modified { old, new } if new.name == "answer" => Some((old, new)),
                _ => None,
            })
            .unwrap();
        assert_eq!(modified_answer.0.id, initial_answer.id);
        assert_eq!(modified_answer.1.id, initial_answer.id);

        let tip = trees.get(&plan.changes[1].id).unwrap();
        assert!(tip
            .artifact_at_path(&kin_model::RepoPath::from_utf8("compose.yaml").unwrap())
            .is_some());
        assert!(tip
            .artifact_at_path(
                &kin_model::RepoPath::from_utf8("archive/source.unknownlang").unwrap()
            )
            .is_some());
        assert!(tip
            .artifact_at_path(&kin_model::RepoPath::from_utf8("payload.rs").unwrap())
            .is_some());
    }

    #[test]
    fn preserves_secondary_parent_entity_identity_across_a_merge() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);
        write(&repository, "src/lib.rs", b"pub fn root() {}\n");
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "root"]);

        git(&repository, &["checkout", "-b", "feature"]);
        write(&repository, "src/feature.rs", b"pub fn feature_only() {}\n");
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "feature"]);

        git(&repository, &["checkout", "main"]);
        write(&repository, "src/main.rs", b"pub fn main_only() {}\n");
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "main"]);
        git(
            &repository,
            &["merge", "--no-ff", "feature", "-m", "merge feature"],
        );

        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("history-merge").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan);
        let deltas = derive_historical_semantic_deltas(&plan.changes, &trees, &blob_store).unwrap();

        let feature_id = deltas
            .iter()
            .flat_map(|delta| &delta.entity_deltas)
            .filter_map(EntityDelta::new_state)
            .find(|entity| entity.name == "feature_only")
            .unwrap()
            .id;
        let merge_index = plan
            .changes
            .iter()
            .position(|change| change.parents.len() == 2)
            .unwrap();
        let merged_feature = deltas[merge_index]
            .entity_deltas
            .iter()
            .filter_map(EntityDelta::new_state)
            .find(|entity| entity.name == "feature_only")
            .unwrap();
        assert_eq!(merged_feature.id, feature_id);

        let bindings = deltas
            .iter()
            .map(|delta| {
                (
                    delta.change_id,
                    delta.entity_deltas.clone(),
                    delta.relation_deltas.clone(),
                )
            })
            .collect::<Vec<_>>();
        plan.with_historical_semantics(&blob_store, &bindings)
            .unwrap()
            .validate(&blob_store)
            .unwrap();
    }

    /// The shape that blocked every real repository: a commit that starts
    /// calling a symbol imported from another crate. The linker answers with a
    /// cross-repo placeholder destination no local file defines, so enrichment
    /// must bind an external target for it before the change can replay. The
    /// commit, the local call graph around it, and the cross-repo reference
    /// itself must all survive admission.
    ///
    /// Upstream trigger: fd b4a252a3916ab342b289331fbf49aa2db73df579, its 26th
    /// commit, which adds `extern crate isatty` and calls `stdout_isatty` from
    /// `main`. ripgrep reaches the same shape at its 25th,
    /// 5450aed9a891254a3cfe26ce0da3a56fed0d957a, by editing
    /// `start_of_previous_lines` around its existing `memrchr` call: the call
    /// site need not be new, because the change re-derives the enclosing
    /// entity's relations.
    #[test]
    fn calling_an_imported_external_symbol_stays_replayable() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);
        write(
            &repository,
            "src/main.rs",
            b"fn colored() -> bool {\n    true\n}\n\nfn main() {\n    let _ = colored();\n}\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "local call graph only"]);

        write(
            &repository,
            "src/main.rs",
            b"extern crate isatty;\n\nuse isatty::stdout_isatty;\n\nfn colored() -> bool {\n    true\n}\n\nfn main() {\n    let _ = colored() && stdout_isatty();\n}\n",
        );
        git(&repository, &["add", "--all"]);
        git(
            &repository,
            &["commit", "-m", "detect interactive terminal"],
        );

        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("history-external-import").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan);
        let deltas = derive_historical_semantic_deltas(&plan.changes, &trees, &blob_store).unwrap();

        let bindings = deltas
            .iter()
            .map(|delta| {
                (
                    delta.change_id,
                    delta.entity_deltas.clone(),
                    delta.relation_deltas.clone(),
                )
            })
            .collect::<Vec<_>>();
        let enriched = plan
            .with_historical_semantics(&blob_store, &bindings)
            .unwrap();
        enriched.validate(&blob_store).unwrap();
        let admitted = admit_semantic_git_import(&enriched, &blob_store).unwrap();

        let entity_ids = admitted
            .changes
            .iter()
            .flat_map(|change| &change.entity_deltas)
            .filter_map(EntityDelta::new_state)
            .map(|entity| entity.id)
            .collect::<HashSet<_>>();
        let bound_relations = admitted
            .changes
            .iter()
            .flat_map(|change| &change.relation_deltas)
            .filter_map(RelationDelta::new_state)
            .collect::<Vec<_>>();
        assert!(
            bound_relations
                .iter()
                .any(|relation| relation.kind == kin_model::RelationKind::Calls),
            "the local call graph must survive"
        );
        let external = bound_relations
            .iter()
            .find(|relation| is_external_import_placeholder(relation))
            .expect("the cross-repo reference must survive admission as change-owned truth");
        let target = external.dst.as_entity().and_then(|id| {
            admitted
                .changes
                .iter()
                .flat_map(|change| &change.entity_deltas)
                .filter_map(EntityDelta::new_state)
                .find(|entity| entity.id == id)
        });
        let target = target.expect("the external reference must bind a destination entity");
        assert_eq!(target.role, EntityRole::External);
        assert_eq!(target.name, "stdout_isatty");
        assert!(
            target.file_origin.is_none(),
            "an external target has no file in this repository"
        );
        for relation in &bound_relations {
            for node in [relation.src, relation.dst] {
                if let kin_model::GraphNodeId::Entity(entity_id) = node {
                    assert!(
                        entity_ids.contains(&entity_id),
                        "relation {} names entity {entity_id}, which history never defines",
                        relation.id
                    );
                }
            }
        }

        let graph = kin_db::InMemoryGraph::new();
        for change in &admitted.changes {
            graph.create_change(change).unwrap();
        }
        let head = admitted
            .changes
            .iter()
            .map(|change| change.id)
            .find(|candidate| {
                !admitted
                    .changes
                    .iter()
                    .any(|change| change.parents.contains(candidate))
            })
            .unwrap();
        graph
            .resolve_graph_at(&head)
            .expect("admitted history must replay without a dangling relation");
    }

    /// Identity derivation is positional, inheritance is not. A definition that
    /// takes over the position an inherited entity was first parsed at derives
    /// that entity's identity, and two definitions of one name in one file must
    /// never collapse into a single entity because of it.
    ///
    /// Upstream trigger: fd 6c9e743d43ff2daff39aeab0796ae713bb544263, which
    /// renames `print_entry_uncolorized` to `print_entry_uncolorized_base` and
    /// gives the original name a `#[cfg(not(unix))]` / `#[cfg(unix)]` pair in
    /// `src/output.rs`. The names and the path here are that commit's.
    #[test]
    fn a_definition_taking_an_inherited_position_keeps_its_own_identity() {
        let artifact_id = ArtifactId::new();
        let path = "src/output.rs";
        let moved = parsed_function(path, "print_entry_uncolorized", 2);
        let arrived = parsed_function(path, "print_entry_uncolorized", 6);
        let inherited = Entity {
            id: historical_entity_id(artifact_id, arrived.id),
            ..parsed_function(path, "print_entry_uncolorized", 6)
        };

        let stabilized =
            stabilize_historical_entities(artifact_id, vec![&inherited], &[moved, arrived]);

        assert_eq!(stabilized.len(), 2);
        assert_ne!(
            stabilized[0].id, stabilized[1].id,
            "two definitions must not share one identity"
        );
        assert!(
            stabilized.iter().any(|entity| entity.id == inherited.id),
            "the entity that matched must keep the identity it carried"
        );
    }

    /// The whole-history form of the same defect: one conditionally compiled
    /// pair is enough to make a tree claim one entity twice. The two commits
    /// below replay fd 6c9e743d43ff2daff39aeab0796ae713bb544263 in miniature,
    /// down to the symbol name and the file it lives in.
    #[test]
    fn conditionally_compiled_duplicates_of_one_name_enrich() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);
        write(
            &repository,
            "src/output.rs",
            b"fn head() {}\n\nfn tail() {}\n\nfn print_entry_uncolorized() {}\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "one definition"]);

        write(
            &repository,
            "src/output.rs",
            b"fn print_entry_uncolorized_base() {}\n#[cfg(not(unix))]\nfn print_entry_uncolorized() {}\n#[cfg(unix)]\nfn print_entry_uncolorized() {}\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "split by target"]);

        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("history-conditional-duplicates").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan);
        let deltas = derive_historical_semantic_deltas(&plan.changes, &trees, &blob_store).unwrap();

        let tip = deltas
            .last()
            .unwrap()
            .entity_deltas
            .iter()
            .filter_map(EntityDelta::new_state)
            .filter(|entity| entity.name == "print_entry_uncolorized")
            .map(|entity| entity.id)
            .collect::<HashSet<_>>();
        assert_eq!(
            tip.len(),
            2,
            "both definitions must reach history as distinct entities"
        );
    }

    fn parsed_function(path: &str, name: &str, start_line: u32) -> Entity {
        let pipeline = IndexPipeline::new();
        let body = format!("{}fn {name}() {{}}\n", "\n".repeat(start_line as usize - 1));
        let indexed = pipeline
            .index_file_content_with_tests(
                &FilePathId::new(path),
                body.as_bytes(),
                kin_blobs::Hash256::from_bytes(kin_blobs::digest_bytes(body.as_bytes())),
            )
            .unwrap()
            .indexed_file;
        indexed
            .entities
            .into_iter()
            .find(|entity| entity.name == name)
            .unwrap()
    }

    #[test]
    fn fails_closed_when_history_is_not_parent_first() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);
        write(&repository, "src/lib.rs", b"pub fn one() {}\n");
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "one"]);
        write(
            &repository,
            "src/lib.rs",
            b"pub fn one() {}\npub fn two() {}\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "two"]);

        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("history-order").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan);
        let reversed = plan.changes.iter().cloned().rev().collect::<Vec<_>>();

        let error = derive_historical_semantic_deltas(&reversed, &trees, &blob_store).unwrap_err();
        assert!(
            error.to_string().contains("was not enriched first"),
            "{error}"
        );
    }

    fn trees_by_change(
        plan: &kin_git::SemanticGitImportPlan,
    ) -> BTreeMap<SemanticChangeId, ResolvedTree> {
        plan.aliases
            .iter()
            .map(|alias| {
                (
                    alias.change_id,
                    plan.commit_trees.get(&alias.oid).unwrap().clone(),
                )
            })
            .collect()
    }

    fn write(repository: &Path, relative: &str, body: &[u8]) {
        let path = repository.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, body).unwrap();
    }

    fn git(repository: &Path, args: &[&str]) {
        let output = fixture_git(repository).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn fixture_git(repository: &Path) -> kin_git::test_support::FixtureGitCommand {
        kin_git::test_support::fixture_git_in(repository)
    }
}
