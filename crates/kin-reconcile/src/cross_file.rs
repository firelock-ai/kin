// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-file relation resolution on the live reconcile path.
//!
//! Before this existed, a file that reached the graph after `kin init` was
//! resolved only against its own entities. `IndexPipeline::resolve_relations`
//! matches every extracted relation against the parsed file's entity list and
//! pushes the rest onto `IndexedFile::unresolved_relations`, a field nothing on
//! the live path ever read. A repository built one file at a time therefore
//! held `Contains` and same-file `Calls` and nothing else, permanently: no
//! cross-file `Calls`, no artifact `Imports`, `find_references` blind across
//! files, and `trace_data_flow` unable to leave the file it started in.
//!
//! [`LiveCrossFileLinker`] keeps a [`kin_index::IncrementalLinker`] current as
//! files arrive and binds in both directions:
//!
//! * **forward.** The file being reconciled resolves its destinations against
//!   every entity already in the graph, so a file written against modules that
//!   already exist connects on arrival.
//! * **backward.** A reference a file indexed earlier left unbound binds the
//!   moment its destination arrives. This is the half that makes "write module
//!   A, then write module B" connect A to B, and a forward-only fix passes a
//!   naive test while failing a real build.
//!
//! Both directions run through the same resolver the batch linker uses, so an
//! incrementally bound edge carries the same confidence tier as a batch-bound
//! one and a guessed edge is still marked as a guess.
//!
//! # Cost
//!
//! Nothing here walks the repository per write. The entity universe is indexed
//! once per process from graph truth ([`LiveCrossFileLinker::seed_from_graph`],
//! the same one-time shape as `Reconciler::seed_lkg_entities_from_graph`).
//! After that, one write resolves exactly two things: the file being
//! reconciled, and the files holding a still-unbound reference to a name this
//! file defines. The second set is read out of a reverse `name -> files` index
//! rather than found by scanning, and those files are re-resolved from retained
//! parse fragments rather than re-read from disk, so no file is parsed twice.
//! [`CrossFilePass::files_resolved`] reports that count and the tests assert it
//! stays independent of repository size.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use kin_index::{
    bare_entity_name, link_cross_file_incremental_with_completeness, FileParseCompletenessMap,
    FileParseData, IncrementalLinker,
};
use kin_model::{
    ArtifactId, Entity, EntityId, GraphNodeId, GraphStore, ParseCompleteness, Relation,
    RelationKind, RepoPath,
};
use kin_parser::{ExtractedRelation, FileImport};
use tracing::{debug, info, warn};

/// Upper bound on files retained for backward binding.
///
/// A file is retained only while it names a destination no file in the graph
/// defines, and only its unbound relations and import declarations are kept,
/// never its entities or source. A repository whose files reference third-party
/// names the graph will never hold keeps those entries for the process
/// lifetime, so the set is capped rather than left to grow without limit.
/// Reaching the cap is reported once: a silently truncated index would read as
/// "nothing was waiting" and quietly stop binding.
const MAX_PENDING_FILES: usize = 20_000;

/// One file's retained fragment, held only while it waits on a name.
#[derive(Debug, Clone)]
struct PendingFile {
    /// The file's unbound relations plus its import declarations. Entities are
    /// deliberately absent: source entities are looked up through the linker's
    /// own per-file index, so retaining them would duplicate the universe.
    parse: FileParseData,
    completeness: ParseCompleteness,
    /// Destination names this file is still waiting on.
    waiting_on: BTreeSet<String>,
}

/// Destination names freshly parsed source still mentions, per relation kind,
/// with caller-specific evidence for Calls.
///
/// This is the evidence a single-file reconcile actually holds about cross-file
/// edges it did not re-derive: the file's own text. An edge whose destination
/// this file no longer names anywhere is stale by that evidence and may be
/// retired. For calls, the reference must belong to that source entity, not a
/// different caller in the file. A still-named target is preserved even when the
/// incremental pass failed to re-derive it, so an init-time batch-linked edge
/// resolved at a tier the incremental universe cannot reach is never deleted by
/// a pass that merely could not see it.
#[derive(Debug, Default, Clone)]
pub struct ReferencedDestinations {
    by_kind: HashMap<RelationKind, HashSet<String>>,
    /// Complete, unambiguous caller declarations, using the IDs this pass admits.
    calls_by_source: HashMap<EntityId, HashSet<String>>,
    /// A call whose source cannot be certified may belong to any caller here.
    unattributed_calls: HashSet<String>,
    calls_complete: bool,
    file_calls_complete: bool,
    incomplete_sources: HashSet<EntityId>,
    /// False when the parse was not complete, which withdraws all authority:
    /// a recovered tree can omit call sites, so an absent name proves nothing.
    trustworthy: bool,
}

impl ReferencedDestinations {
    fn from_extracted(
        extracted: &[ExtractedRelation],
        completeness: &ParseCompleteness,
        entities: &[Entity],
        imports: &[FileImport],
    ) -> Self {
        let mut declarations: HashMap<&str, Vec<&Entity>> = HashMap::new();
        for entity in entities {
            declarations.entry(&entity.name).or_default().push(entity);
        }
        let mut calls_by_source: HashMap<EntityId, HashSet<String>> = declarations
            .values()
            .filter(|matches| matches.len() == 1 && matches[0].span.is_some())
            .map(|matches| (matches[0].id, HashSet::new()))
            .collect();
        calls_by_source.retain(|id, _| {
            let span = entities
                .iter()
                .find(|entity| entity.id == *id)
                .unwrap()
                .span
                .as_ref()
                .unwrap();
            !entities.iter().any(|other| {
                other.id != *id
                    && other.span.as_ref().is_some_and(|other| {
                        let overlaps =
                            span.start_byte < other.end_byte && other.start_byte < span.end_byte;
                        let nested = (span.start_byte <= other.start_byte
                            && other.end_byte <= span.end_byte)
                            || (other.start_byte <= span.start_byte
                                && span.end_byte <= other.end_byte);
                        overlaps
                            && (!nested
                                || (span.start_byte == other.start_byte
                                    && span.end_byte == other.end_byte))
                    })
            })
        });
        let mut unattributed_calls = HashSet::new();
        let mut calls_complete = true;
        let mut file_calls_complete = true;
        let mut incomplete_sources: HashSet<_> = entities
            .iter()
            .filter(|entity| entity.signature.starts_with('@'))
            .map(|entity| entity.id)
            .collect();
        let mut by_kind: HashMap<RelationKind, HashSet<String>> = HashMap::new();
        let certified_sources: HashSet<_> = calls_by_source.keys().copied().collect();
        let source_of = |relation: &ExtractedRelation| -> Option<EntityId> {
            let matches = declarations.get(relation.src_name.as_str())?;
            if matches.len() != 1 {
                return None;
            }
            let entity = matches[0];
            let span = entity.span.as_ref()?;
            let site = relation.site.as_ref()?;
            if !(span.start_byte <= site.start_byte
                && site.start_byte < site.end_byte
                && site.end_byte <= span.end_byte)
            {
                return None;
            }
            // Modules/classes may enclose a method, but another declaration at
            // the same or narrower span makes this site's owner unproven.
            if entities.iter().any(|other| {
                other.id != entity.id
                    && other.span.as_ref().is_some_and(|other| {
                        other.start_byte <= site.start_byte
                            && site.end_byte <= other.end_byte
                            && other.end_byte - other.start_byte <= span.end_byte - span.start_byte
                    })
            }) {
                return None;
            }
            certified_sources.contains(&entity.id).then_some(entity.id)
        };
        let add_name = |names: &mut HashSet<String>, name: &str| {
            names.insert(name.to_owned());
            names.insert(bare_entity_name(name).to_owned());
            for specifier in imports.iter().flat_map(|import| &import.specifiers) {
                if specifier.local_name == name {
                    if let Some(original) = &specifier.original_name {
                        names.insert(original.clone());
                        names.insert(bare_entity_name(original).to_owned());
                    }
                }
            }
        };
        for relation in extracted {
            if kin_parser::is_call_extraction_incomplete_marker(relation) {
                file_calls_complete = false;
                if kin_parser::is_scoped_call_extraction_incomplete_marker(relation) {
                    if let Some(source) = source_of(relation) {
                        if let Some(name) =
                            relation.receiver.as_deref().filter(|name| !name.is_empty())
                        {
                            add_name(
                                calls_by_source
                                    .get_mut(&source)
                                    .expect("certified declaration"),
                                name,
                            );
                        } else {
                            incomplete_sources.insert(source);
                        }
                        continue;
                    }
                }
                calls_complete = false;
                continue;
            }
            if relation.kind == RelationKind::Calls {
                let names = match source_of(relation) {
                    Some(id) => calls_by_source.get_mut(&id).expect("certified declaration"),
                    None => &mut unattributed_calls,
                };
                add_name(names, &relation.dst_name);
            }
            let names = by_kind.entry(relation.kind).or_default();
            names.insert(relation.dst_name.clone());
            names.insert(bare_entity_name(&relation.dst_name).to_string());
        }
        Self {
            by_kind,
            calls_by_source,
            unattributed_calls,
            calls_complete,
            file_calls_complete,
            incomplete_sources,
            trustworthy: matches!(completeness, ParseCompleteness::Full),
        }
    }

    /// Whether this file still names `entity_name` as the destination of a
    /// `kind` relation, under either its qualified or its bare spelling.
    pub fn mentions(&self, kind: RelationKind, entity_name: &str) -> bool {
        let Some(names) = self.by_kind.get(&kind) else {
            return false;
        };
        names.contains(entity_name) || names.contains(bare_entity_name(entity_name))
    }

    /// Whether an edge this file sources may be retired on this evidence.
    ///
    /// Requires a complete parse: a recovered tree can drop call sites, and an
    /// absent name would then retire a live edge.
    pub fn can_retire(&self, kind: RelationKind, entity_name: &str) -> bool {
        self.trustworthy
            && (kind != RelationKind::Calls || self.file_calls_complete)
            && !self.mentions(kind, entity_name)
    }

    /// Retire a missing call only from the caller that stopped naming its target.
    /// A different caller's reference cannot preserve that edge. Unknown source
    /// ownership, incomplete call extraction and ambiguous declarations withdraw
    /// negative authority; unresolved destinations that remain named are kept.
    pub fn can_retire_from(&self, source: EntityId, kind: RelationKind, entity_name: &str) -> bool {
        if kind != RelationKind::Calls {
            return self.can_retire(kind, entity_name);
        }
        let mentions = |names: &HashSet<String>| {
            names.contains(entity_name) || names.contains(bare_entity_name(entity_name))
        };
        self.trustworthy
            && self.calls_complete
            && !self.incomplete_sources.contains(&source)
            && !mentions(&self.unattributed_calls)
            && self
                .calls_by_source
                .get(&source)
                .is_some_and(|names| !mentions(names))
    }

    /// Whether the parse behind this evidence was complete. A recovered tree
    /// can omit declarations, so nothing may be retired on its silence.
    pub fn is_complete(&self) -> bool {
        self.trustworthy
    }
}

/// Prior lexical evidence is read only from the blob recorded on the old
/// entity. Cache one parse per immutable version, never read its projection.
/// A scoped current-name absence may retire direct/import-alias syntax only;
/// it cannot reinterpret an old receiver/alias binding or an evidence-free edge.
#[derive(Default)]
pub(crate) struct PriorCallSites {
    parsed: HashMap<(kin_model::FilePathId, String), Option<kin_index::IndexedFile>>,
}

impl PriorCallSites {
    pub(crate) fn supports_retirement(
        &mut self,
        relation: &Relation,
        source: &Entity,
        target: &Entity,
        blobs: &kin_blobs::BlobStore,
    ) -> bool {
        let Some(span) = source.span.as_ref() else {
            return false;
        };
        let Some(hash) = source
            .metadata
            .extra
            .get("blob_hash")
            .and_then(|v| v.as_str())
        else {
            return false;
        };
        let indexed = self
            .parsed
            .entry((span.file.clone(), hash.to_owned()))
            .or_insert_with(|| {
                let digest = kin_blobs::Hash256::from_hex(hash).ok()?;
                let bytes = blobs.read(&digest).ok()?;
                if kin_blobs::digest(&bytes) != digest {
                    return None;
                }
                kin_index::IndexPipeline::new()
                    .index_file_content_with_tests(&span.file, &bytes, digest)
                    .ok()
                    .map(|result| result.indexed_file)
            });
        let Some(indexed) = indexed else {
            return false;
        };
        if !matches!(indexed.parse_state, kin_model::ParseState::Valid) {
            return false;
        }
        let mut declarations = indexed.entities.iter().filter(|entity| {
            entity.name == source.name
                && entity.kind == source.kind
                && entity.span.as_ref() == Some(span)
        });
        if declarations.next().is_none() || declarations.next().is_some() {
            return false;
        }
        if source.signature.starts_with('@')
            || indexed.extracted_relations.iter().any(|raw| {
                kin_parser::is_call_extraction_incomplete_marker(raw)
                    && (!kin_parser::is_scoped_call_extraction_incomplete_marker(raw)
                        || (raw.src_name == source.name && raw.receiver.is_none()))
            })
        {
            return false;
        }
        let sites: Vec<_> = relation
            .evidence
            .iter()
            .filter_map(|e| e.source_span.as_ref())
            .collect();
        if sites.is_empty() {
            return false;
        }
        sites.iter().all(|site| {
            if site.file != span.file
                || site.start_byte < span.start_byte
                || site.end_byte > span.end_byte
            {
                return false;
            }
            let mut calls = indexed.extracted_relations.iter().filter(|call| {
                call.kind == RelationKind::Calls
                    && call.src_name == source.name
                    && call
                        .site
                        .as_ref()
                        .is_some_and(|callsite| callsite.to_source_span(&span.file) == **site)
            });
            let Some(call) = calls.next() else {
                return false;
            };
            if calls.next().is_some()
                || call.receiver.is_some()
                || call.dst_name.contains(['.', ':'])
            {
                return false;
            }
            // A same-spelled direct call or a recorded import alias can support
            // this target. Unknown assignments / object.alias provenance cannot.
            call.dst_name == target.name
                || call.dst_name == bare_entity_name(&target.name)
                || indexed
                    .imports
                    .iter()
                    .flat_map(|import| &import.specifiers)
                    .any(|specifier| {
                        specifier.local_name == call.dst_name
                            && specifier.original_name.as_ref().is_some_and(|original| {
                                original == &target.name
                                    || original == bare_entity_name(&target.name)
                            })
                    })
        })
    }
}

/// What one cross-file pass produced.
#[derive(Debug, Default)]
pub struct CrossFilePass {
    /// Cross-file relations, entity-level and artifact-level, that the pass
    /// resolved. Entity-level relations here always cross a file boundary;
    /// same-file relations travel in [`CrossFilePass::same_file`].
    pub resolved: Vec<Relation>,
    /// Entity-level relations the pass resolved whose endpoints are both in a
    /// file it resolved.
    ///
    /// These were discarded, on the ground that the pipeline's own per-file
    /// resolution already carries them. It does not carry all of them.
    /// `Overrides` has exactly one producer, `kin_index::linker`, and its
    /// base-class walk resolves a same-file base first, so a class that
    /// overrides a base declared beside it produces an edge only this linker
    /// derives. Dropping it here left the reconciler holding a parser-derived
    /// edge with both endpoints in the file that this pass had not re-derived,
    /// which is precisely the `parser_authoritative` retire condition, so a
    /// comment-only edit deleted it (FIR-2644).
    ///
    /// Kept separate from `resolved` rather than merged into it because the
    /// caller reconciles the two against different evidence: a cross-file edge
    /// is retired on the source file's own text, while a same-file edge is
    /// governed by the pipeline's per-file authority.
    pub same_file: Vec<Relation>,
    /// Artifact-level import and include edges the current source of every
    /// file in this pass declares. The complete set for those files, so a
    /// caller that can read an artifact node's existing relations can retire
    /// what is missing here.
    pub artifact_imports: Vec<Relation>,
    /// The artifacts this pass re-derived import edges for, and is therefore
    /// authoritative over.
    pub source_artifacts: Vec<ArtifactId>,
    /// Destination names the reconciled file still mentions.
    pub referenced: ReferencedDestinations,
    /// Whether the pass ran at all. False when the file has no admitted
    /// artifact identity yet, which withdraws removal authority rather than
    /// guessing.
    pub ran: bool,
    /// Files whose relations this pass resolved: the reconciled file plus the
    /// files that were waiting on a name it defines. Never the repository.
    pub files_resolved: usize,
}

/// Live cross-file resolver: the incremental linker plus the waiting-name index
/// that makes backward binding bounded.
#[derive(Debug, Default)]
pub struct LiveCrossFileLinker {
    linker: IncrementalLinker,
    /// Artifact identity in both directions. The linker owns the same mapping
    /// privately; these are kept beside it so a resolved relation's endpoints
    /// can be attributed to a file in constant time rather than by searching
    /// the universe, which is what keeps a write's cost off repository size.
    artifact_id_by_file: HashMap<String, ArtifactId>,
    file_by_artifact_id: HashMap<ArtifactId, String>,
    /// Entity identity to the file that declares it, same reason.
    ///
    /// The path is shared rather than copied. One entry exists per entity in the
    /// repository and it is held for the process lifetime, so an owned `String`
    /// here was one heap allocation of the same path per entity: on a tree with
    /// 6,160 files and 264,615 entities that is 264,615 copies of 6,160 distinct
    /// strings. An `Arc<str>` is one allocation per distinct file, and both
    /// readers below want either the path itself or an equality against another
    /// entity's path, which share unchanged.
    file_by_entity: HashMap<EntityId, Arc<str>>,
    /// Files retained because they still name something the graph lacks.
    pending: HashMap<String, PendingFile>,
    /// Reverse index: destination name -> files waiting on it. This is what
    /// keeps backward binding bounded; without it a write would have to ask
    /// every file whether it was waiting.
    waiting_on: HashMap<String, BTreeSet<String>>,
    seeded: bool,
    refreshed: bool,
    capacity_reported: bool,
    /// Files the most recent pass resolved. The cost bound made observable:
    /// this is the number a test can assert stays independent of repository
    /// size, and the number a trace can read when a write looks slow.
    last_files_resolved: usize,
}

impl LiveCrossFileLinker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the entity universe has been indexed from graph truth.
    ///
    /// A pass on an unseeded linker would resolve against an empty universe and
    /// report every destination missing, so callers gate on this.
    pub fn is_seeded(&self) -> bool {
        self.seeded
    }

    /// Number of files currently retained for backward binding.
    pub fn pending_file_count(&self) -> usize {
        self.pending.len()
    }

    /// Files the most recent pass resolved: the edited file plus the files that
    /// were waiting on a name it defines.
    pub fn last_files_resolved(&self) -> usize {
        self.last_files_resolved
    }

    /// Index the entity universe from graph truth.
    ///
    /// One pass over the graph's entities per process, grouped by originating
    /// file. Files without an admitted artifact identity are skipped: the
    /// linker's own precondition is that every file it knows carries one, and
    /// minting a placeholder here would attach real import edges to an identity
    /// the repository never assigned.
    pub fn seed_from_graph<G: GraphStore>(&mut self, graph: &G) {
        let entities = match graph.list_all_entities() {
            Ok(entities) => entities,
            Err(error) => {
                warn!(error = %error, "cross-file linker seed skipped: graph read failed");
                return;
            }
        };

        let mut by_file: HashMap<String, Vec<Entity>> = HashMap::new();
        for entity in entities {
            let Some(file) = entity.file_origin.as_ref() else {
                continue;
            };
            by_file.entry(file.0.clone()).or_default().push(entity);
        }

        let mut indexed = 0usize;
        let mut unadmitted = 0usize;
        for (path, entities) in by_file {
            match admitted_artifact_id(graph, &path) {
                Some(artifact_id) => {
                    self.install_file(&path, artifact_id, &entities);
                    indexed += 1;
                }
                None => unadmitted += 1,
            }
        }

        self.seeded = true;
        info!(
            files = indexed,
            skipped_unadmitted = unadmitted,
            "seeded cross-file linker from graph snapshot"
        );
    }

    /// Whether the universe already holds this file.
    pub fn knows_file(&self, file_path: &str) -> bool {
        self.linker.known_files.contains(file_path)
    }

    /// The path the universe believes this artifact identity names.
    pub fn path_of_artifact(&self, artifact_id: &ArtifactId) -> Option<String> {
        self.file_by_artifact_id.get(artifact_id).cloned()
    }

    /// Whether the universe already holds the file behind this artifact.
    ///
    /// Retiring an import edge requires this: a destination the linker has
    /// never heard of is one module resolution could not have reached, so its
    /// absence from a pass proves nothing about the source declaration.
    pub fn knows_artifact(&self, artifact_id: &ArtifactId) -> bool {
        self.file_by_artifact_id.contains_key(artifact_id)
    }

    /// Re-index the universe once when it is provably behind graph truth.
    ///
    /// A file the graph already holds entities for, that this linker has never
    /// heard of, means the graph gained files through a path that does not run
    /// reconcile, and `kin init` importing an existing git history is the one
    /// that matters. Resolving against that stale universe would silently miss every
    /// destination those files declare. Re-indexing is capped at once per
    /// process so a file the seed legitimately skips, such as one with no
    /// admitted artifact identity, cannot make every write pay for a rescan.
    pub fn refresh_if_behind<G: GraphStore>(&mut self, graph: &G, file_path: &str) {
        if !self.seeded || self.refreshed || self.knows_file(file_path) {
            return;
        }
        self.refreshed = true;
        info!(
            file = %file_path,
            "cross-file linker is behind graph truth; re-indexing the entity universe once"
        );
        self.seed_from_graph(graph);
    }

    /// Drop a file from the universe and from the waiting index.
    pub fn forget_file(&mut self, file_path: &str) {
        self.uninstall_file(file_path);
        self.clear_pending(file_path);
    }

    /// Install a file's entities into the universe, keeping the identity
    /// side-indexes in step. Replaces whatever the file held before.
    fn install_file(&mut self, file_path: &str, artifact_id: ArtifactId, entities: &[Entity]) {
        self.uninstall_file(file_path);
        self.linker.add_file(file_path, artifact_id, entities);
        self.artifact_id_by_file
            .insert(file_path.to_string(), artifact_id);
        self.file_by_artifact_id
            .insert(artifact_id, file_path.to_string());
        // One allocation for the path, shared by every entity this file
        // declares, rather than one per entity.
        let shared_path: Arc<str> = Arc::from(file_path);
        for entity in entities {
            self.file_by_entity
                .insert(entity.id, Arc::clone(&shared_path));
        }
    }

    fn uninstall_file(&mut self, file_path: &str) {
        if let Some(previous) = self.linker.entities_by_file.get(file_path) {
            for (entity_id, _) in previous {
                self.file_by_entity.remove(entity_id);
            }
        }
        if let Some(artifact_id) = self.artifact_id_by_file.remove(file_path) {
            self.file_by_artifact_id.remove(&artifact_id);
        }
        self.linker.remove_file(file_path);
    }

    /// Resolve cross-file relations for a file that just changed, and re-bind
    /// the files that were waiting on the names it defines.
    ///
    /// `entities` must carry the identities the transaction will commit, not
    /// the raw parse identities: a modified entity keeps the id already in the
    /// graph, and resolving against the parse identity would mint edges into
    /// entities the delta is about to discard.
    pub fn resolve_after_edit<G: GraphStore>(
        &mut self,
        graph: &G,
        file_path: &str,
        entities: &[Entity],
        extracted: &[ExtractedRelation],
        imports: &[FileImport],
        completeness: ParseCompleteness,
    ) -> CrossFilePass {
        let referenced =
            ReferencedDestinations::from_extracted(extracted, &completeness, entities, imports);
        self.last_files_resolved = 0;
        if !self.seeded {
            return CrossFilePass {
                referenced,
                ..CrossFilePass::default()
            };
        }

        let Some(artifact_id) = admitted_artifact_id(graph, file_path) else {
            debug!(
                file = %file_path,
                "cross-file resolution skipped: no admitted artifact identity yet"
            );
            return CrossFilePass {
                referenced,
                ..CrossFilePass::default()
            };
        };

        let own = FileParseData {
            file_path: file_path.to_string(),
            entities: entities.to_vec(),
            relations: extracted.to_vec(),
            imports: imports.to_vec(),
        };

        // Install the file's current entities before resolving anything, so
        // both directions see the same universe: forward resolution needs this
        // file's sources, backward resolution needs its destinations.
        self.install_file(file_path, artifact_id, entities);
        let own_slice = std::slice::from_ref(&own);
        self.linker.record_file_includes(own_slice);
        self.linker.record_class_bases(own_slice);

        // Backward direction. A file can only newly bind because a name it was
        // waiting on now exists, so the candidate set is looked up by the names
        // this file defines rather than scanned for.
        let dependents = self.files_waiting_on_names_of(file_path, entities);

        let mut batch: Vec<FileParseData> = Vec::with_capacity(dependents.len() + 1);
        let mut completeness_map: FileParseCompletenessMap = HashMap::new();
        completeness_map.insert(file_path.to_string(), completeness.clone());
        batch.push(own);
        for dependent in &dependents {
            let Some(pending) = self.pending.get(dependent) else {
                continue;
            };
            completeness_map.insert(dependent.clone(), pending.completeness.clone());
            batch.push(pending.parse.clone());
        }

        let files_resolved = batch.len();
        self.last_files_resolved = files_resolved;
        let relations = match link_cross_file_incremental_with_completeness(
            &batch,
            &self.linker,
            &completeness_map,
        ) {
            Ok(relations) => relations,
            Err(error) => {
                warn!(
                    file = %file_path,
                    error = %error,
                    "cross-file resolution failed; keeping intra-file edges only"
                );
                return CrossFilePass {
                    referenced,
                    files_resolved,
                    ..CrossFilePass::default()
                };
            }
        };

        let batched_paths: HashSet<String> = batch.iter().map(|f| f.file_path.clone()).collect();

        let mut resolved = Vec::new();
        let mut same_file: Vec<Relation> = Vec::new();
        let mut artifact_imports: Vec<Relation> = Vec::new();
        for relation in relations {
            match (relation.src, relation.dst) {
                (GraphNodeId::Entity(src), GraphNodeId::Entity(dst)) => {
                    // A module path that resolves to no repository file makes
                    // the linker mint a cross-repo external-reference
                    // placeholder whose destination is a synthetic id. The
                    // batch path turns those into real `ExternalReference`
                    // records in the same transaction; nothing on the live path
                    // does, and admitting the edge alone would name an endpoint
                    // the graph does not hold. Third-party imports therefore
                    // stay unbound here rather than half-bound.
                    if kin_index::is_external_import_placeholder(&relation) {
                        continue;
                    }
                    let Some(src_file) = self.file_by_entity.get(&src) else {
                        continue;
                    };
                    // Only edges sourced by a file this pass resolved.
                    if !batched_paths.contains(&**src_file) {
                        continue;
                    }
                    if self.file_by_entity.get(&dst) == Some(src_file) {
                        same_file.push(relation);
                        continue;
                    }
                    resolved.push(relation);
                }
                (GraphNodeId::Artifact(src), GraphNodeId::Artifact(_)) => {
                    if !matches!(
                        relation.kind,
                        RelationKind::Imports | RelationKind::Includes
                    ) {
                        continue;
                    }
                    let Some(path) = self.file_by_artifact_id.get(&src) else {
                        continue;
                    };
                    if !batched_paths.contains(path) {
                        continue;
                    }
                    artifact_imports.push(relation);
                }
                _ => {}
            }
        }

        // Artifact-level import edges are reconciled against graph truth by the
        // caller, which can read an artifact node's relations; this pass only
        // reports what the current source declares and which artifacts it is
        // authoritative for.
        let mut source_artifacts: Vec<ArtifactId> = batched_paths
            .iter()
            .filter_map(|path| self.artifact_id_by_file.get(path).copied())
            .collect();
        source_artifacts.sort_by_key(|id| format!("{id:?}"));

        self.record_pending(file_path, completeness, extracted, imports);
        for dependent in &dependents {
            self.reduce_pending(dependent);
        }

        CrossFilePass {
            resolved,
            same_file,
            artifact_imports,
            source_artifacts,
            referenced,
            ran: true,
            files_resolved,
        }
    }

    /// The files waiting on a name this file now defines, excluding itself.
    fn files_waiting_on_names_of(&self, file_path: &str, entities: &[Entity]) -> Vec<String> {
        let mut names: BTreeSet<&str> = BTreeSet::new();
        for entity in entities {
            names.insert(entity.name.as_str());
            names.insert(bare_entity_name(&entity.name));
        }

        let mut dependents: BTreeSet<String> = BTreeSet::new();
        for name in names {
            let Some(files) = self.waiting_on.get(name) else {
                continue;
            };
            for file in files {
                if file != file_path {
                    dependents.insert(file.clone());
                }
            }
        }
        dependents.into_iter().collect()
    }

    /// Retain the reconciled file's still-unbound references so a later file
    /// defining one of those names can bind it.
    fn record_pending(
        &mut self,
        file_path: &str,
        completeness: ParseCompleteness,
        extracted: &[ExtractedRelation],
        imports: &[FileImport],
    ) {
        let unbound: Vec<ExtractedRelation> = extracted
            .iter()
            .filter(|relation| !kin_parser::is_call_extraction_incomplete_marker(relation))
            .filter(|relation| !self.linker_knows_name(&relation.dst_name))
            .cloned()
            .collect();

        if unbound.is_empty() {
            self.clear_pending(file_path);
            return;
        }

        if !self.pending.contains_key(file_path) && self.pending.len() >= MAX_PENDING_FILES {
            if !self.capacity_reported {
                self.capacity_reported = true;
                warn!(
                    cap = MAX_PENDING_FILES,
                    file = %file_path,
                    "cross-file waiting index is full; files past the cap will not bind \
                     retroactively until the daemon restarts"
                );
            }
            return;
        }

        let waiting: BTreeSet<String> = unbound
            .iter()
            .map(|relation| relation.dst_name.clone())
            .collect();

        self.clear_pending(file_path);
        for name in &waiting {
            self.waiting_on
                .entry(name.clone())
                .or_default()
                .insert(file_path.to_string());
            let bare = bare_entity_name(name);
            if bare != name {
                self.waiting_on
                    .entry(bare.to_string())
                    .or_default()
                    .insert(file_path.to_string());
            }
        }
        self.pending.insert(
            file_path.to_string(),
            PendingFile {
                parse: FileParseData {
                    file_path: file_path.to_string(),
                    entities: Vec::new(),
                    relations: unbound,
                    imports: imports.to_vec(),
                },
                completeness,
                waiting_on: waiting,
            },
        );
    }

    /// Drop the names a dependent no longer waits on after this pass bound them.
    fn reduce_pending(&mut self, file_path: &str) {
        let Some(pending) = self.pending.get(file_path) else {
            return;
        };
        let still_waiting: Vec<ExtractedRelation> = pending
            .parse
            .relations
            .iter()
            .filter(|relation| !self.linker_knows_name(&relation.dst_name))
            .cloned()
            .collect();
        if still_waiting.is_empty() {
            self.clear_pending(file_path);
            return;
        }
        let waiting: BTreeSet<String> = still_waiting
            .iter()
            .map(|relation| relation.dst_name.clone())
            .collect();
        let imports = pending.parse.imports.clone();
        let completeness = pending.completeness.clone();
        self.clear_pending(file_path);
        for name in &waiting {
            self.waiting_on
                .entry(name.clone())
                .or_default()
                .insert(file_path.to_string());
            let bare = bare_entity_name(name);
            if bare != name {
                self.waiting_on
                    .entry(bare.to_string())
                    .or_default()
                    .insert(file_path.to_string());
            }
        }
        self.pending.insert(
            file_path.to_string(),
            PendingFile {
                parse: FileParseData {
                    file_path: file_path.to_string(),
                    entities: Vec::new(),
                    relations: still_waiting,
                    imports,
                },
                completeness,
                waiting_on: waiting,
            },
        );
    }

    fn clear_pending(&mut self, file_path: &str) {
        let Some(previous) = self.pending.remove(file_path) else {
            return;
        };
        for name in previous.waiting_on {
            let bare = bare_entity_name(&name).to_string();
            for key in [name, bare] {
                if let Some(files) = self.waiting_on.get_mut(&key) {
                    files.remove(file_path);
                    if files.is_empty() {
                        self.waiting_on.remove(&key);
                    }
                }
            }
        }
    }

    fn linker_knows_name(&self, name: &str) -> bool {
        self.linker.entity_by_name.contains_key(name)
            || self.linker.entity_by_bare_name.contains_key(name)
            || self
                .linker
                .entity_by_bare_name
                .contains_key(bare_entity_name(name))
    }
}

fn admitted_artifact_id<G: GraphStore>(graph: &G, path: &str) -> Option<ArtifactId> {
    let repo_path = RepoPath::from_utf8(path.to_string()).ok()?;
    graph.artifact_id_at_path(&repo_path)
}

#[cfg(test)]
mod source_evidence_tests {
    use super::*;
    use kin_index::{IndexPipeline, IndexedFile};
    use kin_model::FilePathId;

    fn parsed(source: &str) -> IndexedFile {
        IndexPipeline::new()
            .index_file_content_with_tests(
                &FilePathId::new("source_fixture.py"),
                source.as_bytes(),
                kin_blobs::digest(source.as_bytes()),
            )
            .unwrap()
            .indexed_file
    }

    fn identity(file: &IndexedFile, name: &str) -> EntityId {
        file.entities.iter().find(|e| e.name == name).unwrap().id
    }

    fn evidence(file: &IndexedFile, completeness: ParseCompleteness) -> ReferencedDestinations {
        ReferencedDestinations::from_extracted(
            &file.extracted_relations,
            &completeness,
            &file.entities,
            &file.imports,
        )
    }

    #[test]
    fn qualified_callers_do_not_share_destination_retention() {
        let file = parsed(
            "from absent_module import target\n\nclass A:\n    def call(self):\n        return 1\n\nclass B:\n    def call(self):\n        return target()\n",
        );
        let observed = evidence(&file, ParseCompleteness::Full);
        assert!(observed.can_retire_from(identity(&file, "A.call"), RelationKind::Calls, "target"));
        assert!(!observed.can_retire_from(
            identity(&file, "B.call"),
            RelationKind::Calls,
            "target"
        ));
        assert!(!observed.can_retire_from(EntityId::new(), RelationKind::Calls, "target"));
    }

    #[test]
    fn unknown_call_site_ownership_preserves_the_named_destination() {
        for mode in ["unknown-name", "missing-site", "outside-declaration"] {
            let mut file = parsed("def a():\n    return 1\n\ndef b():\n    return target()\n");
            let source = identity(&file, "a");
            assert!(evidence(&file, ParseCompleteness::Full).can_retire_from(
                source,
                RelationKind::Calls,
                "target"
            ));
            let relation = file
                .extracted_relations
                .iter_mut()
                .find(|r| r.kind == RelationKind::Calls)
                .unwrap();
            match mode {
                "unknown-name" => relation.src_name = "unbound".into(),
                "missing-site" => relation.site = None,
                _ => relation.src_name = "a".into(),
            }
            let observed = evidence(&file, ParseCompleteness::Full);
            assert!(
                !observed.can_retire_from(source, RelationKind::Calls, "target"),
                "{mode}"
            );
        }
    }

    #[test]
    fn ambiguous_source_declarations_do_not_certify_absence() {
        let mut file = parsed("def caller():\n    return target()\n");
        let original = identity(&file, "caller");
        assert!(evidence(&file, ParseCompleteness::Full).can_retire_from(
            original,
            RelationKind::Calls,
            "unmentioned"
        ));
        let mut duplicate = file
            .entities
            .iter()
            .find(|e| e.id == original)
            .unwrap()
            .clone();
        duplicate.id = EntityId::new();
        let other = duplicate.id;
        file.entities.push(duplicate);
        let observed = evidence(&file, ParseCompleteness::Full);
        for id in [original, other] {
            assert!(!observed.can_retire_from(id, RelationKind::Calls, "target"));
            assert!(!observed.can_retire_from(id, RelationKind::Calls, "unmentioned"));
        }
    }

    #[test]
    fn import_alias_keeps_an_unresolved_target_for_its_own_caller() {
        let mut file = parsed(
            "from absent_module import target as renamed\n\ndef caller():\n    return renamed()\n",
        );
        assert!(evidence(&file, ParseCompleteness::Full).can_retire_from(
            identity(&file, "caller"),
            RelationKind::Calls,
            "unmentioned"
        ));
        // Some adapters leave the local spelling for the linker to bind.
        file.extracted_relations
            .iter_mut()
            .find(|r| r.kind == RelationKind::Calls)
            .unwrap()
            .dst_name = "renamed".into();
        let observed = evidence(&file, ParseCompleteness::Full);
        assert!(!observed.can_retire_from(
            identity(&file, "caller"),
            RelationKind::Calls,
            "target"
        ));
        assert!(!observed.can_retire_from(
            identity(&file, "caller"),
            RelationKind::Calls,
            "module.target"
        ));
    }

    #[test]
    fn partial_or_incomplete_call_extraction_cannot_retire_on_silence() {
        let mut file = parsed("def caller():\n    return 1\n");
        let id = identity(&file, "caller");
        assert!(evidence(&file, ParseCompleteness::Full).can_retire_from(
            id,
            RelationKind::Calls,
            "target"
        ));
        for completeness in [
            ParseCompleteness::Partial("recovered".into()),
            ParseCompleteness::Failed("LKG".into()),
        ] {
            assert!(!evidence(&file, completeness).can_retire_from(
                id,
                RelationKind::Calls,
                "target"
            ));
        }
        file.extracted_relations
            .push(kin_parser::call_extraction_incomplete_marker());
        let observed = evidence(&file, ParseCompleteness::Full);
        assert!(!observed.can_retire_from(id, RelationKind::Calls, "target"));
        assert!(!observed.can_retire(RelationKind::Calls, "target"));
        assert!(
            observed.is_complete(),
            "call coverage does not change artifact import parse authority"
        );
    }
    #[test]
    fn scoped_known_names_and_unknown_calls_have_different_negative_authority() {
        let file = parsed("def caller(headers):\n    return headers.items()\n\ndef unknown(dispatch):\n    return dispatch['dynamic']()\n\nAT_MODULE = object()\n");
        let observed = evidence(&file, ParseCompleteness::Full);
        assert!(observed.can_retire_from(identity(&file, "caller"), RelationKind::Calls, "target"));
        assert!(!observed.can_retire_from(identity(&file, "caller"), RelationKind::Calls, "items"));
        assert!(!observed.can_retire_from(
            identity(&file, "unknown"),
            RelationKind::Calls,
            "target"
        ));
        assert!(
            file.extracted_relations
                .iter()
                .any(kin_parser::is_call_extraction_incomplete_marker),
            "broad linker coverage must remain incomplete"
        );
    }

    #[test]
    fn nested_execution_scopes_and_decorators_withdraw_caller_absence() {
        for source in [
            "def caller():\n    def nested():\n        return target()\n    return 1\n",
            "def caller():\n    return lambda: target()\n",
            "def caller(arg=target()):\n    return 1\n",
            "@decorator\ndef caller():\n    return 1\n",
            "@decorator(target())\ndef caller():\n    return 1\n",
        ] {
            let file = parsed(source);
            assert!(
                !evidence(&file, ParseCompleteness::Full).can_retire_from(
                    identity(&file, "caller"),
                    RelationKind::Calls,
                    "unmentioned"
                ),
                "{source}"
            );
        }
    }

    #[test]
    fn unbound_or_malformed_scoped_gaps_fail_closed_globally() {
        for mode in [
            "unknown-owner",
            "missing-site",
            "outside-owner",
            "unknown-payload",
        ] {
            let mut file = parsed("def caller(headers):\n    return headers.items()\n");
            let id = identity(&file, "caller");
            assert!(evidence(&file, ParseCompleteness::Full).can_retire_from(
                id,
                RelationKind::Calls,
                "target"
            ));
            let gap = file
                .extracted_relations
                .iter_mut()
                .find(|r| kin_parser::is_scoped_call_extraction_incomplete_marker(r))
                .unwrap();
            match mode {
                "unknown-owner" => gap.src_name = "missing".into(),
                "missing-site" => gap.site = None,
                "outside-owner" => gap.site.as_mut().unwrap().end_byte += 1000,
                _ => gap.import_source = Some("invalid".into()),
            }
            assert!(
                !evidence(&file, ParseCompleteness::Full).can_retire_from(
                    id,
                    RelationKind::Calls,
                    "target"
                ),
                "{mode}"
            );
        }
    }

    #[test]
    fn prior_retirement_requires_graph_blob_and_lexical_site_provenance() {
        use kin_model::{RelationEvidence, RelationId, RelationOrigin};
        let temp = tempfile::TempDir::new().unwrap();
        let blobs = kin_blobs::BlobStore::new(temp.path().to_path_buf()).unwrap();
        for (body, allowed) in [
            (
                "from absent import target\ndef caller():\n    return target()\n",
                true,
            ),
            (
                "from absent import target as renamed\ndef caller():\n    return renamed()\n",
                true,
            ),
            ("def caller(object):\n    return object.alias()\n", false),
            (
                "def caller():\n    alias = target\n    return alias()\n",
                false,
            ),
        ] {
            let mut file = parsed(body);
            let hash = blobs.write(body.as_bytes()).unwrap();
            let call = file
                .extracted_relations
                .iter()
                .find(|r| r.kind == RelationKind::Calls)
                .unwrap();
            let source = file
                .entities
                .iter_mut()
                .find(|e| e.name == "caller")
                .unwrap();
            source
                .metadata
                .extra
                .insert("blob_hash".into(), hash.to_string().into());
            let mut target = source.clone();
            target.id = EntityId::new();
            target.name = "target".into();
            let mut relation = Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: source.id.into(),
                dst: target.id.into(),
                confidence: 0.95,
                origin: RelationOrigin::Inferred,
                created_in: None,
                import_source: Some("absent".into()),
                evidence: vec![RelationEvidence {
                    source_span: Some(
                        call.site
                            .as_ref()
                            .unwrap()
                            .to_source_span(&source.span.as_ref().unwrap().file),
                    ),
                    ..Default::default()
                }],
            };
            let mut prior = PriorCallSites::default();
            assert_eq!(
                prior.supports_retirement(&relation, source, &target, &blobs),
                allowed,
                "{body}"
            );
            if allowed {
                relation.evidence[0]
                    .source_span
                    .as_mut()
                    .unwrap()
                    .start_byte += 1;
                assert!(!prior.supports_retirement(&relation, source, &target, &blobs));
                relation.evidence.clear();
                assert!(!prior.supports_retirement(&relation, source, &target, &blobs));
                source.metadata.extra.remove("blob_hash");
                assert!(!prior.supports_retirement(&relation, source, &target, &blobs));
            }
        }
    }
}
