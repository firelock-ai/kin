// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Deterministic semantic enrichment for exact historical trees.
//!
//! This boundary never reads a checkout. It derives supported-language
//! entities and relations solely from graph-owned resolved trees and immutable
//! CAS bodies. Every other artifact remains represented by the exact tree even
//! when it has no language adapter.

use std::borrow::Borrow;
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
    is_external_import_placeholder, link_cross_file_borrowed_with_completeness,
    ArtifactIdentityMap, FileParseCompletenessMap, FileParseData,
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
/// This constant is now persisted and compared, and it is still not an
/// enforcement point. `kin_core::hydration_semantics` records its value into
/// every store at creation and compares the record when a store is read, so
/// `kin graph status`, `kin doctor` and the `_kin` envelope all disclose a gap
/// between what a store was created under and what this build derives. Native
/// transfer carries the sending store's creation record. Admission preserves
/// the receiver's record only when that transported authoring version matches;
/// an absent or mismatched version durably discards the local record.
///
/// What bumping the dial does not do by itself: it re-derives nothing. Every
/// store an earlier build admitted then reads behind, and `kin upgrade`
/// re-derives the state such a store serves through [`rederive_tree_semantics`]
/// and records each head's transition as a new change. History recorded
/// before that change is not re-derived, because a change's identity hashes
/// its deltas, and keeps what the build that recorded it authored.
/// Version 19 records that `is_external_import_placeholder` now recognizes an
/// `Overrides` crossing alongside `Calls` and `References`. The predicate
/// decides which inferred imported crossings become persisted external target
/// entities during replay, so a repository re-admitted under this build has
/// external targets authored for base-class crossings its past did not carry.
/// That is a replay-semantics change and it is recorded here rather than
/// regenerated into the manifest in silence.
/// Version 20 records three replay-semantics changes that landed after
/// version 19 without moving this dial. `resolve_one_file` now resolves a Go
/// call through a receiver whose method is promoted from an embedded type, so
/// replay authors call edges it did not. Import edges are anchored on the line
/// that carries the imported name rather than on the statement's first line,
/// so replay authors different evidence positions. And the JavaScript,
/// TypeScript, Go, Java, PHP, Kotlin and Swift adapters mint a file's module
/// surface only when the file produced a declaration or an import, so replay
/// authors no module entity for a file that produced neither a declaration nor an import.
/// Version 21 records that `resolve_one_file`'s same-file tier no longer links
/// a relation that resolved to a definition in its own file to every
/// same-named entity in other files. Only a same-file prototype, or a
/// same-file definition whose known arity rejects the call, still hands the
/// relation on to those entities as name-only candidates, so replay authors
/// fewer edges than it did: calls above all, and also the containment,
/// reference and implements edges the same tier linked by name. No history
/// re-admitted under this build carries the removed ones.
/// Version 22 records that `make_external_reference_relation` no longer mints
/// an external-import edge for a call on a receiver, other than the JavaScript
/// imported-getter receiver. A method whose name matched an import, such as
/// Rust's `cmd.env(..)` beside `use std::env;`, was persisted as a call edge to
/// that import, so a repository re-admitted under this build carries none of
/// those edges its past did. In Rust such a call now gets no edge at all: the
/// adapter still pins it to the import by name, so it never reaches the
/// receiver-method tier. A reference on a receiver is unchanged and still mints
/// one: Python's class-body `session: Session` keeps the attribute in the
/// receiver and names the imported `Session` itself.
/// Version 23 records that the same-file tier no longer settles a relation
/// locally in four shapes where version 21 did. A Kotlin or Swift top-level
/// function is handed on to the same-named functions elsewhere, since another
/// file of its package or module can overload it. A C++ function is handed on
/// when the calling file or a header in its include closure declares another
/// overload the call's argument count admits. A TypeScript ambient declaration,
/// which the adapter now marks `declare`, counts as a declaration and is handed
/// on like a C prototype. And a call that carries an import of the name it
/// calls, from a language other than Rust, links its same-file match as a
/// name-only candidate and goes on to the import tiers, which resolve the
/// imported binding. A same-file definition whose arity rejects the call is
/// now authored as a name-only candidate instead of a parser-certain edge, and
/// a C++ definition reads its default arguments from its same-named
/// declarations before its arity can reject anything. A Go call through an
/// imported package, such as `errors.New` in a file that defines its own
/// `New`, no longer reaches the same-file tier at all and is resolved inside
/// the imported package, so replay stops authoring the edge to the calling
/// file's own function. The tier also never hands a call on to a module entity
/// that shares the called name. Replay therefore authors more name-only edges
/// than version 21 in the hand-on shapes and for imported calls, a different
/// confidence on the local edge in two shapes, and fewer edges for Go package
/// calls.
/// Version 26 binds Rust import edges to the importing file's own module
/// coordinate, not the first module in stored entity order. Re-admission and
/// explicit upgrade therefore author deterministic import owners; existing
/// immutable changes retain the semantics under which they were recorded.
/// Version 29 also excludes macro placeholder names and function declarations
/// from Rust call extraction. Explicit replay uses the corrected parser while
/// existing immutable changes keep their original recorded semantics.
/// Version 30 records independently bound parser occurrence tiers on Calls.
/// A stronger occurrence no longer lends its authority to weaker sites on the
/// same logical edge. Explicit replay authors the new evidence; old immutable
/// changes retain their original records and disclose unqualified site attribution.
/// It also binds Go receiver methods to the unique type in their admitted package,
/// withholding an ambiguous owner instead of selecting a same-named declaration.
/// Version 31 retires Python language-server bindings obtained before initialize
/// named the workspace. The explicit store upgrade keeps parser/history state
/// and re-asks the server under that corrected scope.
pub const HYDRATION_SEMANTICS_VERSION: u32 = 31;

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
///
/// The map is generic over how its trees are held so a caller that already
/// owns every exact tree can lend them rather than copy them. This is the
/// whole-map form of [`HistoricalSemanticFold`], which a conversion no longer
/// uses: it hands the fold each commit's tree as the history derivation
/// resolves it, so no map of every tree is ever built. This form remains for
/// callers that hold a few trees already, and it is the fold underneath.
pub fn derive_historical_semantic_deltas<T: Borrow<ResolvedTree>>(
    changes: &[SemanticChange],
    trees: &BTreeMap<SemanticChangeId, T>,
    blob_store: &BlobStore,
) -> Result<Vec<HistoricalSemanticDelta>> {
    if trees.len() != changes.len() {
        return Err(invalid(format!(
            "semantic tree map contains {} entries for {} enriched changes",
            trees.len(),
            changes.len()
        )));
    }
    let mut fold = HistoricalSemanticFold::new(changes)?;
    let mut output = Vec::with_capacity(changes.len());
    for change in changes {
        let tree = trees.get(&change.id).ok_or_else(|| {
            invalid(format!(
                "change {} has no exact resolved tree for semantic enrichment",
                change.id
            ))
        })?;
        output.push(fold.enrich(change, tree.borrow(), blob_store)?);
    }
    fold.finish()?;
    Ok(output)
}

/// The historical enrichment fold, one commit at a time.
///
/// A fold is opened over the whole parent-first history so it knows how many
/// children still need each commit's semantic state, then fed each change with
/// its exact tree in that same order, and closed once every change has been
/// enriched. It keeps the semantic state of a commit only while a later commit
/// still folds against it, exactly as the whole-map derivation did; what it
/// no longer needs is the whole map. The history derivation in `kin-git` hands
/// it each tree while that tree is live for the same reason, so a conversion's
/// enrichment holds the frontier of history rather than all of it.
pub struct HistoricalSemanticFold {
    pipeline: IndexPipeline,
    /// An external target's fingerprint is a pure function of the import
    /// source and symbol its identity is derived from, so it is the same value
    /// in every tree that observes the import. The fold relinks the whole tree
    /// per change, which would otherwise recompute those digests once per
    /// commit for a value that cannot change.
    external_fingerprints: BTreeMap<EntityId, SemanticFingerprint>,
    states: BTreeMap<SemanticChangeId, SemanticTreeState>,
    remaining_child_uses: BTreeMap<SemanticChangeId, usize>,
    /// Changes opened over and not yet enriched.
    pending: HashSet<SemanticChangeId>,
}

impl HistoricalSemanticFold {
    /// Open a fold over a complete parent-first history.
    ///
    /// Every change is checked here for what enrichment requires of it: a Git
    /// origin, no semantic deltas already bound, and an identity that appears
    /// once. The child-use count that lets a parent's state be dropped is
    /// taken from the whole history, which is why the fold has to see it
    /// before it enriches anything.
    pub fn new(changes: &[SemanticChange]) -> Result<Self> {
        Self::from_change_stream(changes.iter().map(Ok::<_, std::convert::Infallible>))
    }

    /// Inspect complete history one record at a time, retaining only identity
    /// and parent-use metadata needed by the subsequent semantic fold.
    pub fn from_change_stream<C, E>(
        changes: impl IntoIterator<Item = std::result::Result<C, E>>,
    ) -> Result<Self>
    where
        C: std::borrow::Borrow<SemanticChange>,
        E: std::fmt::Display,
    {
        let mut pending = HashSet::new();
        let mut remaining_child_uses = BTreeMap::<SemanticChangeId, usize>::new();
        for change in changes {
            let change =
                change.map_err(|error| invalid(format!("read historical change: {error}")))?;
            let change = change.borrow();
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
            if !pending.insert(change.id) {
                return Err(invalid(format!(
                    "history repeats change identity {}",
                    change.id
                )));
            }
            for parent in &change.parents {
                *remaining_child_uses.entry(*parent).or_default() += 1;
            }
        }
        Ok(Self {
            pipeline: IndexPipeline::new(),
            external_fingerprints: BTreeMap::new(),
            states: BTreeMap::new(),
            remaining_child_uses,
            pending,
        })
    }

    /// Enrich one change against its exact tree.
    ///
    /// The change must be one the fold was opened over, must not have been
    /// enriched yet, and every one of its parents must have been enriched
    /// before it, which parent-first order guarantees. The replay itself is
    /// [`enrich_historical_change`], a free function so the replay-semantics
    /// guard can pin its source the way it pins every other function that
    /// authors persisted history.
    pub fn enrich(
        &mut self,
        change: &SemanticChange,
        tree: &ResolvedTree,
        blob_store: &BlobStore,
    ) -> Result<HistoricalSemanticDelta> {
        enrich_historical_change(self, change, tree, blob_store)
    }

    /// Close the fold, requiring every opened change to have been enriched and
    /// no parent state to have outlived its last child.
    pub fn finish(self) -> Result<()> {
        if !self.pending.is_empty() {
            return Err(invalid(format!(
                "{} changes were opened for enrichment and never enriched",
                self.pending.len()
            )));
        }
        if !self.states.is_empty() {
            return Err(invalid(
                "semantic history retained parent state after every child was enriched",
            ));
        }
        Ok(())
    }
}

/// The entity and relation state one exact tree derives under this build.
///
/// What [`rederive_tree_semantics`] returns: the state a change at this tree
/// would carry had it been replayed by this build, keyed the way a resolved
/// graph keys its domains.
#[derive(Debug, Clone, PartialEq)]
pub struct RederivedTreeSemantics {
    pub entities: BTreeMap<EntityId, Entity>,
    pub relations: BTreeMap<RelationId, Relation>,
    /// Entity-source files the derivation parsed.
    pub source_files: usize,
}

/// A file path no tree can hold, so a held file's parse is never reused.
///
/// Repository paths are UTF-8 and never contain NUL, so the reuse test in
/// [`semantic_state_for_tree`], which requires a parent file's recorded path to
/// equal the artifact's, can never pass for a file carrying this one.
const HELD_IDENTITIES_ONLY: &str = "\0held entity identities";

/// How many times a derivation re-offers its own identities before refusing.
///
/// Identity assignment within a file takes the held entities of one name and
/// kind in identity order. A declaration that is new to this build mints an
/// identity that can sort before one it matched, so the first derivation is
/// not always the one a second derivation over its own output reproduces; the
/// second always is, and the third proves it.
const IDENTITY_PASSES: usize = 3;

/// Derive the complete entity and relation state `tree` holds under this
/// build's replay semantics, carrying entity identities from `held`.
///
/// This is the store upgrade's derivation. A store admitted by an older build
/// holds history its replay authored, and nothing about that history can be
/// re-derived in place without renaming every change, because a change's
/// identity hashes its deltas and parents. What can be brought current is the
/// state a head serves. This returns that state exactly as the replay derives
/// it for one change, by running [`semantic_state_for_tree`] itself: every
/// source file is parsed from the CAS body the tree names and the whole tree
/// is linked once, so the result is what a fresh admission of this tree under
/// this build would serve, rather than a patch of what the older build left.
///
/// `held` is the state the store already serves at this tree. It supplies
/// identity and nothing else. Each held entity is offered to the replay as a
/// parent entity of the artifact the tree places at its file, which is the
/// same way a parent change offers its entities to a child, so a declaration
/// the older build also recognized keeps its identity, lineage and creating
/// change, and an entity it minted that this build does not derive is simply
/// absent from the result. The held files are marked so their parses are never
/// reused: a parse is carried forward only between trees that hold identical
/// bytes under identical semantics, and this call exists because the semantics
/// changed.
///
/// The result is a fixed point: deriving the same tree again with the result as
/// `held` reproduces it exactly. That is what lets a second `kin upgrade` find
/// nothing to do, and what lets a verifier re-derive a committed graph and
/// compare it for equality rather than for resemblance. When a derivation mints
/// an identity, it is repeated over its own output until it reproduces itself,
/// and a tree that never settles is refused rather than returned.
///
/// A held entity with no file origin, or whose file the tree does not hold as
/// a source artifact, supplies nothing. External reference targets are
/// re-derived from the linked relations, whose identity is a function of the
/// import they name.
pub fn rederive_tree_semantics<'held>(
    tree: &ResolvedTree,
    held: impl IntoIterator<Item = &'held Entity>,
    blob_store: &BlobStore,
) -> Result<RederivedTreeSemantics> {
    let mut held: Vec<Entity> = held.into_iter().cloned().collect();
    let mut previous: Option<RederivedTreeSemantics> = None;
    for _ in 0..IDENTITY_PASSES {
        let derived = derive_tree_semantics_once(tree, &held, blob_store)?;
        match &previous {
            Some(previous)
                if previous.entities == derived.entities
                    && previous.relations == derived.relations =>
            {
                return Ok(derived);
            }
            Some(_) => {}
            None => {
                // Every file-owned identity came from `held`, so a derivation
                // over this output offers the same identities in the same order
                // and reproduces it without being asked to.
                let held_ids: HashSet<EntityId> = held.iter().map(|entity| entity.id).collect();
                if derived
                    .entities
                    .values()
                    .all(|entity| entity.file_origin.is_none() || held_ids.contains(&entity.id))
                {
                    return Ok(derived);
                }
            }
        }
        held = derived.entities.values().cloned().collect();
        previous = Some(derived);
    }
    Err(invalid(
        "entity identities did not settle across repeated derivations of one tree",
    ))
}

/// Stage the bodies a derivation of `tree` reads into a scratch store, then
/// derive it with [`rederive_tree_semantics`].
///
/// Only entity sources and Cargo manifests are read by a derivation, so only
/// those are staged. `load_body` is the caller's store, returning the exact
/// bytes a content address names or `None` when it holds none; a missing body
/// is refused, and a body whose digest is not its address is refused, because
/// a derivation is only as exact as the bytes it read. The scratch store lives
/// for this call only.
pub fn rederive_tree_semantics_from<'held>(
    tree: &ResolvedTree,
    held: impl IntoIterator<Item = &'held Entity>,
    load_body: &mut dyn FnMut(kin_model::Hash256) -> std::result::Result<Option<Vec<u8>>, String>,
) -> Result<RederivedTreeSemantics> {
    let scratch = tempfile::Builder::new()
        .prefix("kin-rederive-")
        .tempdir()
        .map_err(|error| invalid(format!("create a scratch source store: {error}")))?;
    let bodies = BlobStore::new_ephemeral(scratch.path().join("cas"))?;
    let mut staged = HashSet::new();
    for artifact in tree.artifacts() {
        let TreeEntry::Blob { hash, .. } = artifact.entry else {
            continue;
        };
        let Some(path) = artifact.path.as_utf8() else {
            continue;
        };
        let source = matches!(
            FileClassifier::classify(Path::new(path)),
            FileClassification::EntitySource
        );
        if !source && path.rsplit('/').next() != Some("Cargo.toml") {
            continue;
        }
        if !staged.insert(hash) {
            continue;
        }
        let body = load_body(hash)
            .map_err(|error| invalid(format!("read the body of {path} ({hash}): {error}")))?
            .ok_or_else(|| {
                invalid(format!(
                    "the store holds no body for {path} ({hash}), and a derivation reads only \
                     bytes the store keeps"
                ))
            })?;
        let written = bodies.write(&body)?;
        if written != hash {
            return Err(invalid(format!(
                "the body read for {path} does not hash to {hash}"
            )));
        }
    }
    rederive_tree_semantics(tree, held, &bodies)
}

/// One derivation of `tree`, offering `held` as the identities to keep.
fn derive_tree_semantics_once(
    tree: &ResolvedTree,
    held: &[Entity],
    blob_store: &BlobStore,
) -> Result<RederivedTreeSemantics> {
    let artifact_at_path = tree
        .artifacts()
        .filter_map(|artifact| {
            let path = artifact.path.as_utf8()?;
            matches!(artifact.entry, TreeEntry::Blob { .. })
                .then(|| (path.to_string(), (artifact.artifact_id, artifact.entry)))
        })
        .collect::<BTreeMap<_, _>>();
    let mut held_by_artifact = BTreeMap::<ArtifactId, (TreeEntry, Vec<Entity>)>::new();
    for entity in held {
        let Some(origin) = entity.file_origin.as_ref() else {
            continue;
        };
        let Some((artifact_id, entry)) = artifact_at_path.get(origin.0.as_str()) else {
            continue;
        };
        held_by_artifact
            .entry(*artifact_id)
            .or_insert_with(|| (*entry, Vec::new()))
            .1
            .push(entity.clone());
    }
    let mut prior = SemanticTreeState::default();
    for (artifact_id, (entry, mut entities)) in held_by_artifact {
        // Offered in identity order, which is the order a replayed parent
        // holds its entities in, so a file whose declarations share a name and
        // kind pairs with them exactly as the replay of a later commit would.
        entities.sort_by_key(|entity| entity.id);
        prior.files.insert(
            artifact_id,
            SemanticFileState {
                artifact_id,
                entry,
                completeness: Arc::new(ParseCompleteness::Full),
                parse_data: Arc::new(FileParseData {
                    file_path: HELD_IDENTITIES_ONLY.to_string(),
                    entities,
                    relations: Vec::new(),
                    imports: Vec::new(),
                }),
            },
        );
    }
    let state = semantic_state_for_tree(
        tree,
        &[&prior],
        blob_store,
        &IndexPipeline::new(),
        &mut BTreeMap::new(),
    )?;
    Ok(RederivedTreeSemantics {
        source_files: state.files.len(),
        entities: state.entities,
        relations: state.relations,
    })
}

/// Enrich one change of a parent-first history against its exact tree.
///
/// This is the per-change replay: it decides the baseline the change is
/// diffed from (its first parent's semantic state, or nothing for a root),
/// derives the tree's state against every parent so carried-forward parses
/// are reused, diffs entities and relations, and then releases each parent
/// state whose last child this was. The whole-map derivation and the streaming
/// fold both run exactly this, once per change, in the same order.
fn enrich_historical_change(
    fold: &mut HistoricalSemanticFold,
    change: &SemanticChange,
    tree: &ResolvedTree,
    blob_store: &BlobStore,
) -> Result<HistoricalSemanticDelta> {
    if !fold.pending.remove(&change.id) {
        return Err(invalid(format!(
            "change {} was not opened for enrichment, or was enriched twice",
            change.id
        )));
    }
    let parent_states = change
        .parents
        .iter()
        .map(|parent| {
            fold.states.get(parent).ok_or_else(|| {
                invalid(format!(
                    "parent {} of change {} was not enriched first",
                    parent, change.id
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let empty_parent = SemanticTreeState::default();
    let first_parent = parent_states.first().copied().unwrap_or(&empty_parent);
    let current = semantic_state_for_tree(
        tree,
        &parent_states,
        blob_store,
        &fold.pipeline,
        &mut fold.external_fingerprints,
    )?;
    let entity_deltas = diff_entities(&first_parent.entities, &current.entities);
    let relation_deltas = diff_relations(&first_parent.relations, &current.relations);
    let delta = HistoricalSemanticDelta {
        change_id: change.id,
        entity_deltas,
        relation_deltas,
    };

    drop(parent_states);
    for parent in &change.parents {
        let remaining = fold.remaining_child_uses.get_mut(parent).ok_or_else(|| {
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
            fold.states.remove(parent);
        }
    }
    if fold
        .remaining_child_uses
        .get(&change.id)
        .copied()
        .unwrap_or(0)
        > 0
    {
        fold.states.insert(change.id, current);
    }
    Ok(delta)
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

    let rust_project = if parse_data
        .iter()
        .any(|file| file.file_path.ends_with(".rs"))
    {
        Some(
            crate::rust_project::RustProjectAuthority::observe_admitted_tree(
                tree,
                crate::rust_project::RustProjectLimits::default(),
                |hash| {
                    blob_store
                        .read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))
                        .map_err(|error| error.to_string())
                },
            )
            .map_err(invalid)?,
        )
    } else {
        None
    };
    let linked = if let Some(authority) = rust_project
        .as_ref()
        .and_then(|observation| observation.authority())
    {
        crate::linker::link_cross_file_with_rust_project(
            &parse_data,
            &entities.values().collect::<Vec<_>>(),
            &artifact_ids,
            &completeness,
            authority,
        )?
    } else {
        link_cross_file_borrowed_with_completeness(&parse_data, &artifact_ids, &completeness)?
    };
    entities.extend(external_reference_targets(
        &linked,
        &entities,
        external_fingerprints,
    ));
    let mut relations = BTreeMap::new();
    for mut relation in linked {
        if let Some(artifact) = match relation.src {
            kin_model::GraphNodeId::Artifact(id) => files.get(&id),
            _ => None,
        } {
            if crate::is_parse_coverage_relation(
                &relation,
                &artifact.parse_data.file_path,
                artifact.artifact_id,
            ) {
                if let TreeEntry::Blob { hash, .. } = artifact.entry {
                    crate::bind_parse_coverage_source(
                        &mut relation,
                        &artifact.parse_data.file_path,
                        hash,
                    );
                }
            }
        }
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

    let mut targets = BTreeMap::new();
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
/// One class reaches here, and it is the one whose destination a resolver can
/// bind: a cross-repo import, which names its module in `import_source` and its
/// symbol in evidence. Admission fails closed on an endpoint no entity backs,
/// so the historical ref view calls this before inserting a re-linked relation
/// into a snapshot, and a placeholder class this does not know is a hard error
/// rather than a silent drop. That is the contract every placeholder class has
/// to satisfy to exist at all, and it is why there is exactly one.
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
        let trees = trees_by_change(&plan, &snapshot, &blob_store);

        let changes = plan
            .changes
            .iter()
            .collect::<kin_git::Result<Vec<_>>>()
            .unwrap();
        let first = derive_historical_semantic_deltas(&changes, &trees, &blob_store).unwrap();
        let second = derive_historical_semantic_deltas(&changes, &trees, &blob_store).unwrap();
        assert_eq!(second, first);
        assert_eq!(first.len(), 2);

        let bindings = first
            .iter()
            .map(|delta| {
                kin_git::HistoricalSemanticBinding::borrowed(
                    delta.change_id,
                    &delta.entity_deltas,
                    &delta.relation_deltas,
                )
            })
            .collect::<Vec<_>>();
        let enriched = plan
            .clone()
            .with_historical_semantics(&blob_store, bindings)
            .unwrap();
        enriched.validate(&blob_store).unwrap();
        let admitted = admit_semantic_git_import(&enriched, &blob_store).unwrap();
        admitted.validate(&blob_store).unwrap();
        assert_ne!(enriched.aliases, plan.aliases);
        assert_eq!(
            enriched.changes.read_at(1).unwrap().unwrap().parents,
            vec![enriched.changes.read_at(0).unwrap().unwrap().id],
            "semantic binding must reidentify parent edges"
        );
        assert_eq!(
            admitted.changes.read_at(0).unwrap().unwrap().entity_deltas,
            enriched.changes.read_at(0).unwrap().unwrap().entity_deltas
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

        let tip = trees.get(&changes[1].id).unwrap();
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
        let trees = trees_by_change(&plan, &snapshot, &blob_store);
        let changes = plan
            .changes
            .iter()
            .collect::<kin_git::Result<Vec<_>>>()
            .unwrap();
        let deltas = derive_historical_semantic_deltas(&changes, &trees, &blob_store).unwrap();

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
            .position(|change| change.unwrap().parents.len() == 2)
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
                kin_git::HistoricalSemanticBinding::borrowed(
                    delta.change_id,
                    &delta.entity_deltas,
                    &delta.relation_deltas,
                )
            })
            .collect::<Vec<_>>();
        plan.with_historical_semantics(&blob_store, bindings)
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
        let trees = trees_by_change(&plan, &snapshot, &blob_store);
        let changes = plan
            .changes
            .iter()
            .collect::<kin_git::Result<Vec<_>>>()
            .unwrap();
        let deltas = derive_historical_semantic_deltas(&changes, &trees, &blob_store).unwrap();

        let bindings = deltas
            .iter()
            .map(|delta| {
                kin_git::HistoricalSemanticBinding::borrowed(
                    delta.change_id,
                    &delta.entity_deltas,
                    &delta.relation_deltas,
                )
            })
            .collect::<Vec<_>>();
        let enriched = plan
            .with_historical_semantics(&blob_store, bindings)
            .unwrap();
        enriched.validate(&blob_store).unwrap();
        let admitted = admit_semantic_git_import(&enriched, &blob_store).unwrap();

        let admitted_changes = admitted
            .changes
            .iter()
            .collect::<kin_git::Result<Vec<_>>>()
            .unwrap();
        let entity_ids = admitted_changes
            .iter()
            .flat_map(|change| &change.entity_deltas)
            .filter_map(EntityDelta::new_state)
            .map(|entity| entity.id)
            .collect::<HashSet<_>>();
        let bound_relations = admitted_changes
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
            admitted_changes
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
        for change in &admitted_changes {
            graph.create_change(change).unwrap();
        }
        let head = admitted_changes
            .iter()
            .map(|change| change.id)
            .find(|candidate| {
                !admitted_changes
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
        let trees = trees_by_change(&plan, &snapshot, &blob_store);
        let changes = plan
            .changes
            .iter()
            .collect::<kin_git::Result<Vec<_>>>()
            .unwrap();
        let deltas = derive_historical_semantic_deltas(&changes, &trees, &blob_store).unwrap();

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
        let trees = trees_by_change(&plan, &snapshot, &blob_store);
        let mut reversed = plan
            .changes
            .iter()
            .collect::<kin_git::Result<Vec<_>>>()
            .unwrap();
        reversed.reverse();

        let error = derive_historical_semantic_deltas(&reversed, &trees, &blob_store).unwrap_err();
        assert!(
            error.to_string().contains("was not enriched first"),
            "{error}"
        );
    }

    #[test]
    fn span_provenance_history_tracks_exact_tree_bytes_and_reuses_unchanged_files() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);
        let initial = b"def merge_setting(value):\n    return value\n";
        write(&repository, "src/sessions.py", initial);
        write(
            &repository,
            "src/unchanged.py",
            b"def unchanged():\n    return 7\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "initial source"]);
        let shifted = b"# leading source comment\ndef merge_setting(value):\n    return value\n";
        write(&repository, "src/sessions.py", shifted);
        git(&repository, &["add", "--all"]);
        git(
            &repository,
            &[
                "commit",
                "-m",
                "move function without changing its behavior",
            ],
        );
        write(&repository, "README.md", b"unrelated artifact change\n");
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "retain source unchanged"]);
        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("span-provenance-history").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan, &snapshot, &blob_store);
        // Enrichment must use the captured graph and CAS, even when a checkout differs.
        write(
            &repository,
            "src/sessions.py",
            b"def unrelated_checkout():\n    pass\n",
        );
        let changes = plan
            .changes
            .iter()
            .collect::<kin_git::Result<Vec<_>>>()
            .unwrap();
        let deltas = derive_historical_semantic_deltas(&changes, &trees, &blob_store).unwrap();
        assert_eq!(deltas.len(), 3);
        let mut entities = BTreeMap::new();
        for delta in &deltas {
            for change in &delta.entity_deltas {
                if let Some(entity) = change.new_state() {
                    entities.insert(entity.id, entity.clone());
                }
            }
            assert_eq!(
                entities
                    .values()
                    .filter(|entity| entity.kind == EntityKind::Function)
                    .count(),
                2,
                "both fixture functions must survive replay"
            );
            let tree = &trees[&delta.change_id];
            for entity in entities.values() {
                let path = entity.file_origin.as_ref().unwrap();
                let artifact = tree
                    .artifact_at_path(&kin_model::RepoPath::from_utf8(&path.0).unwrap())
                    .unwrap();
                let digest = artifact.entry.blob_identity().unwrap();
                assert_eq!(
                    entity
                        .metadata
                        .extra
                        .get("blob_hash")
                        .and_then(|value| value.as_str()),
                    Some(digest.to_string().as_str()),
                    "{} span must bind its exact historical tree body",
                    entity.name
                );
                let body = blob_store
                    .read(&kin_blobs::Hash256::from_bytes(*digest.as_bytes()))
                    .unwrap();
                let span = entity.span.as_ref().unwrap();
                let excerpt = &body[span.start_byte as usize..span.end_byte as usize];
                if entity.kind == EntityKind::Function {
                    assert!(String::from_utf8_lossy(excerpt).contains(&entity.name));
                }
            }
        }
        let moved = deltas[1]
            .entity_deltas
            .iter()
            .find_map(|delta| match delta {
                EntityDelta::Modified { old, new } if new.name == "merge_setting" => {
                    Some((old, new))
                }
                _ => None,
            })
            .expect("span-only edit must persist a modified entity");
        assert_eq!(moved.0.id, moved.1.id);
        assert_eq!(moved.0.fingerprint, moved.1.fingerprint);
        assert_ne!(
            moved.0.metadata.extra["blob_hash"],
            moved.1.metadata.extra["blob_hash"]
        );
        assert!(
            deltas[2].entity_deltas.is_empty(),
            "unchanged source needs no semantic delta"
        );
        let bindings = deltas
            .iter()
            .map(|delta| {
                kin_git::HistoricalSemanticBinding::borrowed(
                    delta.change_id,
                    &delta.entity_deltas,
                    &delta.relation_deltas,
                )
            })
            .collect::<Vec<_>>();
        let enriched = plan
            .with_historical_semantics(&blob_store, bindings)
            .unwrap();
        let admitted = admit_semantic_git_import(&enriched, &blob_store).unwrap();
        admitted.validate(&blob_store).unwrap();
        assert_eq!(
            admitted.changes.read_at(1).unwrap().unwrap().entity_deltas,
            deltas[1].entity_deltas
        );
    }

    #[test]
    fn cargo_manifest_only_history_rebinds_from_each_immutable_tree() {
        let root = tempdir().unwrap();
        let repository = root.path().join("source");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "--initial-branch=main"]);
        git(
            &repository,
            &["config", "user.email", "kin@example.invalid"],
        );
        git(&repository, &["config", "user.name", "Kin Test"]);
        let manifest = b"[package]\nname='fixture'\nedition='2021'\nautolib=false\nautobins=false\n[lib]\npath='app.rs'\n";
        write(&repository, "Cargo.toml", manifest);
        write(&repository, "app.rs", b"pub mod owner; pub mod caller;");
        write(&repository, "owner.rs", b"pub fn work() {}");
        write(
            &repository,
            "caller.rs",
            b"use crate::owner::work; pub fn run() { work(); }",
        );
        write(&repository, "other.rs", b"pub fn unrelated() {}");
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "bound root"]);
        write(
            &repository,
            "Cargo.toml",
            &String::from_utf8(manifest.to_vec())
                .unwrap()
                .replace("app.rs", "other.rs")
                .into_bytes(),
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "manifest-only root change"]);
        write(&repository, "Cargo.toml", manifest);
        git(&repository, &["add", "--all"]);
        git(
            &repository,
            &["commit", "-m", "manifest-only root recovery"],
        );
        let blobs = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("cargo-history").unwrap(),
            &blobs,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blobs).unwrap();
        let trees = trees_by_change(&plan, &snapshot, &blobs);
        let changes = plan
            .changes
            .iter()
            .collect::<kin_git::Result<Vec<_>>>()
            .unwrap();
        fs::remove_dir_all(&repository).unwrap();
        let derived = derive_historical_semantic_deltas(&changes, &trees, &blobs).unwrap();
        assert_eq!(derived.len(), 3);
        let entity = |name: &str| {
            derived[0]
                .entity_deltas
                .iter()
                .filter_map(EntityDelta::new_state)
                .find(|e| e.name == name && e.file_origin.is_some() && e.kind != EntityKind::Module)
                .unwrap()
                .id
        };
        let caller = entity("run");
        let target = entity("work");
        let exact = |relation: &Relation| {
            relation.kind == kin_model::RelationKind::Calls
                && relation.src.as_entity() == Some(caller)
                && relation.dst.as_entity() == Some(target)
        };
        let original = derived[0]
            .relation_deltas
            .iter()
            .find_map(|delta| match delta {
                RelationDelta::Added { new } if exact(new) => Some(new),
                _ => None,
            })
            .expect("Cargo-root call is authored from admitted history");
        assert_eq!(original.confidence, 0.95);
        assert!(derived[1]
            .relation_deltas
            .iter()
            .any(|delta| matches!(delta, RelationDelta::Removed { old } if old == original)));
        assert!(derived[2]
            .relation_deltas
            .iter()
            .any(|delta| matches!(delta, RelationDelta::Added { new } if new == original)));
        assert!(derived[1..].iter().flat_map(|delta| &delta.entity_deltas).all(|delta| !matches!(delta, EntityDelta::Removed { old } if old.id == caller || old.id == target)));
        let bindings: Vec<_> = derived
            .iter()
            .map(|delta| {
                kin_git::HistoricalSemanticBinding::borrowed(
                    delta.change_id,
                    &delta.entity_deltas,
                    &delta.relation_deltas,
                )
            })
            .collect();
        let enriched = plan.with_historical_semantics(&blobs, bindings).unwrap();
        let admitted = admit_semantic_git_import(&enriched, &blobs).unwrap();
        admitted.validate(&blobs).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let admitted_changes = admitted
            .changes
            .iter()
            .collect::<kin_git::Result<Vec<_>>>()
            .unwrap();
        for change in &admitted_changes {
            graph.create_change(change).unwrap();
        }
        for (index, change) in admitted_changes.iter().enumerate() {
            let state = graph.resolve_graph_at(&change.id).unwrap();
            assert_eq!(state.relations.values().any(exact), index != 1);
        }
    }

    /// A two-commit history in four languages, replayed the way admission
    /// replays it, and the state its head serves: the fold of every delta.
    struct ReplayedHead {
        _root: tempfile::TempDir,
        blob_store: BlobStore,
        tree: ResolvedTree,
        entities: BTreeMap<EntityId, Entity>,
        relations: BTreeMap<RelationId, Relation>,
    }

    fn replayed_head() -> ReplayedHead {
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
            b"mod util;\n\npub fn entry(value: u32) -> u32 {\n    util::helper(value) + 1\n}\n",
        );
        write(
            &repository,
            "src/util.rs",
            b"pub fn helper(value: u32) -> u32 {\n    value * 2\n}\n",
        );
        write(&repository, "pkg/__init__.py", b"");
        write(
            &repository,
            "pkg/b.py",
            b"def double(value):\n    return value * 2\n",
        );
        write(
            &repository,
            "web/lib.mjs",
            b"export function triple(value) {\n  return value * 3;\n}\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "start"]);
        write(
            &repository,
            "pkg/a.py",
            b"from pkg.b import double\n\n\ndef run(value):\n    return double(value) + 1\n",
        );
        write(
            &repository,
            "web/index.mjs",
            b"import { triple } from './lib.mjs';\n\nexport function main() {\n  return triple(2);\n}\n",
        );
        git(&repository, &["add", "--all"]);
        git(&repository, &["commit", "-m", "call across files"]);

        let blob_store = BlobStore::new(root.path().join("cas")).unwrap();
        let snapshot = capture_lossless_git_repository(
            &repository,
            RepositoryId::new("history-rederivation").unwrap(),
            &blob_store,
        )
        .unwrap();
        let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
        let trees = trees_by_change(&plan, &snapshot, &blob_store);
        let changes = plan
            .changes
            .iter()
            .collect::<kin_git::Result<Vec<_>>>()
            .unwrap();
        let deltas = derive_historical_semantic_deltas(&changes, &trees, &blob_store).unwrap();
        let mut entities = BTreeMap::new();
        let mut relations = BTreeMap::new();
        for delta in &deltas {
            for entity in &delta.entity_deltas {
                match entity {
                    EntityDelta::Added { new } | EntityDelta::Modified { new, .. } => {
                        entities.insert(new.id, new.clone());
                    }
                    EntityDelta::Removed { old } => {
                        entities.remove(&old.id);
                    }
                }
            }
            for relation in &delta.relation_deltas {
                match relation {
                    RelationDelta::Added { new } | RelationDelta::Modified { new, .. } => {
                        relations.insert(new.id, new.clone());
                    }
                    RelationDelta::Removed { old } => {
                        relations.remove(&old.id);
                    }
                }
            }
        }
        let tree = trees.get(&changes[1].id).unwrap().clone();
        ReplayedHead {
            _root: root,
            blob_store,
            tree,
            entities,
            relations,
        }
    }

    /// The upgrade's derivation of a head is the state the replay itself left
    /// that head serving, identity for identity, when the same build did both.
    #[test]
    fn rederiving_a_replayed_head_reproduces_the_replay_exactly() {
        let head = replayed_head();
        assert!(
            head.entities.len() >= 8 && head.relations.len() >= 4,
            "the fixture replayed too little to prove anything: {} entities, {} relations",
            head.entities.len(),
            head.relations.len()
        );
        let derived =
            rederive_tree_semantics(&head.tree, head.entities.values(), &head.blob_store).unwrap();
        assert_eq!(derived.entities, head.entities);
        assert_eq!(derived.relations, head.relations);
        assert!(derived.source_files >= 6, "{}", derived.source_files);
    }

    /// What the store held that this build does not derive is gone, what this
    /// build derives differently is restated, and every declaration it still
    /// recognizes keeps its identity.
    #[test]
    fn rederiving_retires_held_state_this_build_does_not_derive_and_keeps_identities() {
        let head = replayed_head();
        let mut held = head.entities.clone();
        // A declaration an older build minted for a file that declares nothing
        // like it.
        let stale = {
            let mut stale = head
                .entities
                .values()
                .find(|entity| entity.name == "double")
                .unwrap()
                .clone();
            stale.id = EntityId::new();
            stale.name = "receiver_minted_by_an_older_build".to_string();
            stale
        };
        held.insert(stale.id, stale.clone());
        // A declaration an older build placed differently.
        let moved = held
            .values_mut()
            .find(|entity| entity.name == "helper")
            .unwrap();
        let helper_id = moved.id;
        if let Some(span) = moved.span.as_mut() {
            span.start_line += 40;
            span.end_line += 40;
        }
        let derived = rederive_tree_semantics(&head.tree, held.values(), &head.blob_store).unwrap();
        assert!(!derived.entities.contains_key(&stale.id));
        assert!(
            derived
                .entities
                .values()
                .all(|entity| entity.name != "receiver_minted_by_an_older_build"),
            "a declaration no parse produces survived the re-derivation"
        );
        assert_eq!(
            derived.entities.get(&helper_id),
            head.entities.get(&helper_id),
            "the re-derivation must restate the declaration from its bytes under its own identity"
        );
        assert_eq!(derived.entities, head.entities);
        assert_eq!(derived.relations, head.relations);
    }

    /// Identities a derivation mints settle: re-deriving the result reproduces
    /// it, which is what makes a second upgrade find nothing to do.
    #[test]
    fn a_rederivation_is_a_fixed_point_of_itself() {
        let head = replayed_head();
        let first =
            rederive_tree_semantics(&head.tree, std::iter::empty(), &head.blob_store).unwrap();
        assert_eq!(first.entities.len(), head.entities.len());
        let second =
            rederive_tree_semantics(&head.tree, first.entities.values(), &head.blob_store).unwrap();
        assert_eq!(second.entities, first.entities);
        assert_eq!(second.relations, first.relations);
    }

    /// Bodies come from the caller's store and are checked against the
    /// address that names them: a missing body and a wrong one both refuse.
    #[test]
    fn a_rederivation_refuses_a_missing_or_mismatched_body() {
        let head = replayed_head();
        let mut from_store = |hash: kin_model::Hash256| {
            head.blob_store
                .read(&hash)
                .map(Some)
                .map_err(|error| error.to_string())
        };
        let derived =
            rederive_tree_semantics_from(&head.tree, head.entities.values(), &mut from_store)
                .unwrap();
        assert_eq!(derived.entities, head.entities);

        let mut missing = |_hash: kin_model::Hash256| Ok(None);
        let error = rederive_tree_semantics_from(&head.tree, head.entities.values(), &mut missing)
            .unwrap_err()
            .to_string();
        assert!(error.contains("holds no body"), "{error}");

        let mut wrong = |_hash: kin_model::Hash256| Ok(Some(b"not the body".to_vec()));
        let error = rederive_tree_semantics_from(&head.tree, head.entities.values(), &mut wrong)
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not hash to"), "{error}");
    }

    fn head_graph(head: &ReplayedHead) -> kin_db::GraphSnapshot {
        let mut graph = kin_db::GraphSnapshot::empty();
        graph.entities = head
            .entities
            .iter()
            .map(|(id, entity)| (*id, entity.clone()))
            .collect();
        graph.relations = head
            .relations
            .iter()
            .map(|(id, relation)| (*id, relation.clone()))
            .collect();
        graph.resolved_tree = head.tree.clone();
        graph
    }

    fn verify(
        head: &ReplayedHead,
        graph: &kin_db::GraphSnapshot,
    ) -> std::result::Result<(), String> {
        let mut load = |hash: kin_model::Hash256| {
            head.blob_store
                .read(&hash)
                .map(Some)
                .map_err(|error| error.to_string())
        };
        crate::binding_history::verify_rederived_graph(graph, &mut load)
    }

    /// The re-derivation verifier qualifies exactly a graph a derivation of its
    /// own tree reproduces, and nothing the graph supplies can stand in for the
    /// derivation: a changed payload, a missing or invented derived edge, or a
    /// swapped identity each refuse, while an edge no derivation authors is
    /// neither required nor refused.
    #[test]
    fn the_rederivation_verifier_qualifies_only_an_exact_derivation() {
        let head = replayed_head();
        let exact = head_graph(&head);
        verify(&head, &exact).expect("an exact derivation qualifies");

        let mut moved = exact.clone();
        let entity = moved
            .entities
            .values_mut()
            .find(|entity| entity.name == "helper")
            .unwrap();
        entity.signature.push_str(" /* edited */");
        assert!(
            verify(&head, &moved).is_err(),
            "a changed payload qualified"
        );

        let mut invented = exact.clone();
        let mut extra = exact.entities.values().next().unwrap().clone();
        extra.id = EntityId::new();
        extra.name = "invented".to_string();
        invented.entities.insert(extra.id, extra);
        assert!(
            verify(&head, &invented).is_err(),
            "an invented entity qualified"
        );

        let mut dropped = exact.clone();
        let derived_edge = *dropped
            .relations
            .iter()
            .find(|(_, relation)| crate::binding_history::relation_is_derived(relation))
            .unwrap()
            .0;
        dropped.relations.remove(&derived_edge);
        assert!(
            verify(&head, &dropped).is_err(),
            "a missing derived edge qualified"
        );

        let mut fabricated = exact.clone();
        let mut edge = exact.relations.values().next().unwrap().clone();
        edge.id = RelationId::new();
        edge.origin = kin_model::RelationOrigin::Parsed;
        fabricated.relations.insert(edge.id, edge.clone());
        assert!(
            verify(&head, &fabricated).is_err(),
            "an invented derived edge qualified"
        );

        let mut asserted = exact.clone();
        edge.origin = kin_model::RelationOrigin::Lsp;
        asserted.relations.insert(edge.id, edge);
        verify(&head, &asserted).expect("an edge no derivation authors is not refused");

        // Two called declarations trading identities under edges that still
        // name the old ones: the edges now bind the wrong targets, and the
        // derivation, which binds by what the bytes call, says so.
        let mut swapped = exact.clone();
        let id_of = |name: &str| {
            swapped
                .entities
                .values()
                .find(|entity| entity.name == name)
                .unwrap()
                .id
        };
        let (left, right) = (id_of("helper"), id_of("double"));
        let mut first = swapped.entities.remove(&left).unwrap();
        let mut second = swapped.entities.remove(&right).unwrap();
        std::mem::swap(&mut first.id, &mut second.id);
        swapped.entities.insert(first.id, first);
        swapped.entities.insert(second.id, second);
        assert!(
            verify(&head, &swapped).is_err(),
            "swapped identities qualified"
        );
    }

    /// A graph that owes local binding debt is refused even when every entity
    /// and derived edge is exactly what a derivation produces. Debt is a
    /// binding a later observation still has to settle, so no lineage can
    /// start over it, and the store stays unproven.
    #[test]
    fn the_rederivation_verifier_refuses_a_graph_that_owes_binding_debt() {
        let head = replayed_head();
        let mut owing = head_graph(&head);
        let blob_at = |path: &str| {
            let id = owing
                .resolved_tree
                .artifact_id_at_path(&kin_model::RepoPath::from_utf8(path.to_string()).unwrap())
                .unwrap_or_else(|| panic!("the fixture holds {path}"));
            let TreeEntry::Blob { hash, .. } = owing.resolved_tree.get(&id).unwrap().entry else {
                panic!("{path} is not a blob");
            };
            (id, hash)
        };
        let (source, source_digest) = blob_at("pkg/a.py");
        let (target, _) = blob_at("pkg/b.py");
        let call = owing
            .relations
            .values()
            .find(|relation| {
                relation.kind == kin_model::RelationKind::Calls
                    && relation.evidence.iter().any(|evidence| {
                        evidence
                            .source_span
                            .as_ref()
                            .is_some_and(|span| span.file.0 == "pkg/a.py")
                    })
            })
            .expect("the fixture calls across Python files")
            .clone();
        let debt = crate::binding_debt::build_local_binding_debt(
            source,
            crate::binding_debt::LocalBindingDebt {
                source_file: FilePathId::new("pkg/a.py"),
                observed_source_digest: source_digest,
                obligations: vec![crate::binding_debt::LocalBindingObligation {
                    retired_relation: call,
                    source_name: "run".to_string(),
                    source_digest,
                    prior_source_file: None,
                    target_artifact: target,
                    target_file: FilePathId::new("pkg/b.py"),
                    target_name: "double".to_string(),
                }],
            },
        )
        .unwrap();
        owing.relations.insert(debt.id, debt);
        let error = verify(&head, &owing).unwrap_err();
        assert!(error.contains("binding debt"), "{error}");
    }

    fn trees_by_change(
        plan: &kin_git::SemanticGitImportPlan,
        snapshot: &kin_git::LosslessGitRepository,
        blob_store: &BlobStore,
    ) -> BTreeMap<SemanticChangeId, ResolvedTree> {
        let trees = kin_git::derive_commit_trees(snapshot, blob_store).unwrap();
        plan.aliases
            .iter()
            .map(|alias| (alias.change_id, trees.get(&alias.oid).unwrap().clone()))
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
