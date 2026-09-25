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
//! The ordinary name index does not walk the repository per write. Rust project
//! authority is currently reconstructed from selected tree/CAS when a checked
//! pass resolves a Rust source; its cost remains a separate scaling gate.
//! The entity universe is indexed
//! once per process from graph truth ([`LiveCrossFileLinker::seed_from_graph`],
//! the same one-time shape as `Reconciler::seed_lkg_entities_from_graph`).
//! Dependency fragments are reconstructed from verified admitted CAS sources
//! once after a seed. Later writes nominate dependent files through a reverse
//! `name -> files` index, including resolved imports that may need rebinding.
//! The checked reconcile route verifies and reparses each nominated source's
//! complete admitted CAS bytes before resolving it; workspace files are never
//! consulted. Names nominate work but do not establish a binding.
//! [`CrossFilePass::files_resolved`] reports that count and the tests assert it
//! stays independent of repository size.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use kin_index::{
    bare_entity_name, link_cross_file_incremental_with_graph, FileParseCompletenessMap,
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
/// Imported files retain relations and import declarations after resolution,
/// so a removed or recreated destination can rebind an unchanged source.
/// Non-importing files retain unresolved relations. Entities and source bytes
/// are not cached here. The checked route refuses capacity overflow before
/// publication rather than silently losing dependent files.
const MAX_PENDING_FILES: usize = 20_000;

/// One file's retained dependency fragment.
#[derive(Debug, Clone)]
struct PendingFile {
    /// The file's relevant relations plus its import declarations. Entities are
    /// deliberately absent: source entities are looked up through the linker's
    /// own per-file index, so retaining them would duplicate the universe.
    parse: FileParseData,
    completeness: ParseCompleteness,
    /// Binds this cached fragment to the complete source version that produced
    /// it. A graph reseed may preserve it only with matching admitted bytes and
    /// declaration identities; absence is never permission to reuse a fragment.
    source_blob_hash: Option<String>,
    /// Destination names that nominate this source for verified rederivation.
    waiting_on: BTreeSet<String>,
    /// Resolver candidate paths nominate imports even when the exported symbol
    /// is anonymous or has a different name from the local import binding.
    waiting_on_paths: BTreeSet<String>,
    /// Go Contains syntax lives with the method, but depends on a receiver
    /// type that may be declared in another file. Keep this after binding.
    go_receiver_owners: BTreeSet<String>,
}

fn go_receiver_owner_names(
    extracted: &[ExtractedRelation],
    entities: &[Entity],
) -> BTreeSet<String> {
    extracted
        .iter()
        .filter(|relation| {
            relation.kind == RelationKind::Contains
                && kin_index::dispatch::split_qualified_method(&relation.dst_name)
                    .is_some_and(|(owner, _)| owner == relation.src_name)
                && entities.iter().any(|entity| {
                    entity.name == relation.dst_name
                        && entity.kind == kin_model::EntityKind::Method
                        && entity.language == kin_model::LanguageId::Go
                })
        })
        .map(|relation| relation.src_name.clone())
        .collect()
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
    /// A failed authority read or link pass cannot authorize replacing an
    /// informed graph edge with an intra-file guess.
    pub failure: Option<String>,
    /// Cross-file relations, entity-level and artifact-level, that the pass
    /// resolved. Entity-level relations here always cross a file boundary;
    /// same-file relations travel in [`CrossFilePass::same_file`].
    pub resolved: Vec<Relation>,
    /// Source-local relations, including candidate-to-generator artifact evidence.
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
    /// Validated external imports sourced by the fully parsed file being edited.
    /// Their targets must be admitted in the same transaction as these edges.
    pub external: Vec<Relation>,
    /// Complete admitted observations for unchanged sources re-derived in this pass.
    pub dependent_sources: Vec<kin_index::IndexedFile>,
    pub dependent_external: Vec<Relation>,
    pub named_import_observations: Vec<kin_index::linker::NamedImportObservation>,
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
    /// Import dependencies survive resolution, so destination replacement or
    /// recreation can re-derive their unchanged source. Unimported unresolved
    /// references retain the previous bounded name-waiting behavior.
    pending: HashMap<String, PendingFile>,
    /// Reverse index: destination name -> files waiting on it. This is what
    /// keeps backward binding bounded; without it a write would have to ask
    /// every file whether it was waiting.
    waiting_on: HashMap<String, BTreeSet<String>>,
    waiting_on_paths: HashMap<String, BTreeSet<String>>,
    seeded: bool,
    refreshed: bool,
    dependencies_restored: bool,
    // Only an owned, unpublished batch may carry a tree ahead of its old
    // declaration anchors. Keep those anchors out of the resolution universe
    // until their ordinary reconcile delta has landed in the private graph.
    withheld: HashMap<ArtifactId, String>,
    // The entire private batch, including its second pass after withholding
    // empties, delegates Rust authority to the one final coherent census.
    defer_rust_project: bool,
    capacity_reported: bool,
    /// Files the most recent pass resolved. The cost bound made observable:
    /// this is the number a test can assert stays independent of repository
    /// size, and the number a trace can read when a write looks slow.
    last_files_resolved: usize,
}

impl LiveCrossFileLinker {
    pub(crate) fn withhold_batch(&mut self, artifacts: HashMap<ArtifactId, String>) {
        self.withheld = artifacts;
        self.defer_rust_project = true;
    }

    pub(crate) fn finish_batch_file(&mut self, artifact: ArtifactId) {
        self.withheld.remove(&artifact);
    }

    fn is_withheld(&self, file: &str) -> bool {
        self.artifact_id_by_file
            .get(file)
            .is_some_and(|artifact| self.withheld.contains_key(artifact))
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn checked_fork(&self) -> crate::error::Result<Self> {
        Ok(Self {
            linker: IncrementalLinker::from_checkpoint_v1(self.linker.to_checkpoint_v1())
                .map_err(crate::error::ReconcileError::Graph)?,
            artifact_id_by_file: self.artifact_id_by_file.clone(),
            file_by_artifact_id: self.file_by_artifact_id.clone(),
            file_by_entity: self.file_by_entity.clone(),
            pending: self.pending.clone(),
            waiting_on: self.waiting_on.clone(),
            waiting_on_paths: self.waiting_on_paths.clone(),
            seeded: self.seeded,
            refreshed: self.refreshed,
            dependencies_restored: self.dependencies_restored,
            withheld: self.withheld.clone(),
            defer_rust_project: self.defer_rust_project,
            capacity_reported: self.capacity_reported,
            last_files_resolved: self.last_files_resolved,
        })
    }

    /// Stage live cache adoption without changing the serving linker. The
    /// fork replaces only affected complete sources; unrelated include, class,
    /// import and partial observations remain exact. Partial nomination fragments
    /// cannot authorize edges without a later complete admitted-source read.
    pub(crate) fn fork_for_admitted_batch<G: GraphStore>(
        &self,
        graph: &G,
        blobs: &kin_blobs::BlobStore,
        sources: &[kin_index::IndexedFile],
    ) -> crate::error::Result<(Self, Vec<kin_model::FilePathId>)> {
        let mut staged = self.checked_fork()?;
        if !staged.withheld.is_empty() {
            return Err(crate::error::ReconcileError::InvalidTransaction(
                "live adoption cannot inherit unpublished withheld declarations".into(),
            ));
        }
        if !staged.seeded {
            // A genuinely empty live cache has no observations to preserve.
            // Refuse to relabel retained but invalidated cache state as fresh.
            if !staged.pending.is_empty() || !staged.artifact_id_by_file.is_empty() {
                return Err(crate::error::ReconcileError::InvalidTransaction(
                    "cannot adopt a batch over an invalidated retained linker".into(),
                ));
            }
            staged.seed_from_graph_checked(graph)?;
            staged.restore_dependencies(graph, blobs, None)?;
        }
        // The successor may have retired sources outside this batch. Carrying
        // their pending fragments forward would nominate a now-absent importer
        // on the next ordinary edit. Read membership before changing the fork;
        // the live cache remains untouched until its checked adoption succeeds.
        let (_, absent) = staged.partition_admitted_sources(
            graph,
            staged.artifact_id_by_file.keys().cloned().collect(),
        )?;
        let mut retired_paths: BTreeSet<_> = absent.into_iter().collect();
        for path in &retired_paths {
            staged.forget_file(path);
        }
        let mut adopted = std::collections::BTreeMap::new();
        for source in sources {
            let path = &source.file_id.0;
            let artifact = admitted_artifact_id(graph, path).ok_or_else(|| {
                crate::error::ReconcileError::InvalidTransaction(
                    "prepared live source has no admitted artifact".into(),
                )
            })?;
            adopted.insert(path.clone(), artifact);
        }
        // Resolve old cache custody from the original fork before any install.
        // Otherwise an old-path replacement can erase a moved artifact's new
        // reverse mapping, or a later cleanup can delete the replacement.
        for (path, artifact) in &adopted {
            let Some(previous) = staged.file_by_artifact_id.get(artifact) else {
                continue;
            };
            if previous == path {
                continue;
            }
            if staged.artifact_id_by_file.get(previous) != Some(artifact) {
                return Err(crate::error::ReconcileError::InvalidTransaction(
                    "moved batch cache has inconsistent artifact custody".into(),
                ));
            }
            if let Some(replacement) = admitted_artifact_id(graph, previous) {
                if adopted.get(previous) != Some(&replacement) {
                    return Err(crate::error::ReconcileError::InvalidTransaction(
                        "reused former batch path requires its checked replacement source".into(),
                    ));
                }
            }
            retired_paths.insert(previous.clone());
        }
        for path in &retired_paths {
            staged.forget_file(path);
        }
        for source in sources {
            let path = &source.file_id.0;
            let artifact = adopted[path];
            if staged.needs_dependency_entry(
                &source.extracted_relations,
                &source.imports,
                &source.entities,
            ) && !staged.pending.contains_key(path)
                && staged.pending.len() >= MAX_PENDING_FILES
            {
                return Err(crate::error::ReconcileError::InvalidTransaction(
                    "admitted dependency cache capacity exceeded".into(),
                ));
            }
            staged.install_observed_file(path, artifact, &source.entities);
            let parse = FileParseData {
                file_path: path.clone(),
                entities: source.entities.clone(),
                relations: source.extracted_relations.clone(),
                imports: source.imports.clone(),
            };
            staged
                .linker
                .record_file_includes(std::slice::from_ref(&parse));
            staged
                .linker
                .record_class_bases(std::slice::from_ref(&parse));
            staged.record_pending(
                path,
                ParseCompleteness::Full,
                &source.extracted_relations,
                &source.imports,
                &source.entities,
            );
        }
        Ok((
            staged,
            retired_paths
                .into_iter()
                .map(kin_model::FilePathId::new)
                .collect(),
        ))
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
        if let Err(error) = self.seed_from_graph_checked(graph) {
            warn!(error = %error, "cross-file linker seed skipped: graph authority unavailable");
        }
    }

    pub(crate) fn seed_from_graph_checked<G: GraphStore>(
        &mut self,
        graph: &G,
    ) -> crate::error::Result<()> {
        self.seed_with(
            || {
                graph
                    .list_all_entities()
                    .map_err(|error| crate::error::ReconcileError::Graph(error.to_string()))
            },
            |path| {
                let repo_path = RepoPath::from_utf8(path.to_string())
                    .map_err(|error| crate::error::ReconcileError::Graph(error.to_string()))?;
                checked_seed_artifact(
                    || {
                        graph
                            .get_tree_entry(&kin_model::FilePathId::new(path))
                            .map_err(|error| crate::error::ReconcileError::Graph(error.to_string()))
                    },
                    || graph.artifact_id_at_path(&repo_path),
                )
            },
        )
    }

    fn seed_with(
        &mut self,
        read_entities: impl FnOnce() -> crate::error::Result<Vec<Entity>>,
        mut read_artifact: impl FnMut(&str) -> crate::error::Result<Option<SeedArtifact>>,
    ) -> crate::error::Result<()> {
        // Stage every read before installing anything. A failed refresh cannot
        // leave a partially read universe marked usable for publication.
        self.seeded = false;
        self.dependencies_restored = false;
        let entities = read_entities()?;

        let mut by_file: std::collections::BTreeMap<String, Vec<Entity>> = Default::default();
        for entity in entities {
            let Some(file) = entity.file_origin.as_ref() else {
                continue;
            };
            by_file.entry(file.0.clone()).or_default().push(entity);
        }

        let mut admitted = Vec::new();
        let mut unadmitted = 0usize;
        for (path, entities) in by_file {
            match read_artifact(&path)? {
                Some(artifact) => admitted.push((path, artifact, entities)),
                None => unadmitted += 1,
            }
        }
        // A newly authored source may have no old declarations at all. Its
        // admitted module still exists while its declarations are withheld;
        // otherwise an early caller could be misclassified as external.
        for (id, path) in &self.withheld {
            if !admitted.iter().any(|(_, artifact, _)| artifact.id == *id) {
                admitted.push((
                    path.clone(),
                    SeedArtifact {
                        id: *id,
                        blob_hash: None,
                    },
                    vec![],
                ));
            }
        }
        let indexed = admitted.len();
        let retained: HashSet<_> = admitted
            .iter()
            .filter_map(|(path, artifact, entities)| {
                let pending = self.pending.get(path)?;
                let hash = pending.source_blob_hash.as_deref()?;
                let previous: HashSet<_> = self
                    .linker
                    .entities_by_file
                    .get(path)?
                    .iter()
                    .map(|(id, _)| *id)
                    .collect();
                let current: HashSet<_> = entities.iter().map(|entity| entity.id).collect();
                (self.artifact_id_by_file.get(path) == Some(&artifact.id)
                    && artifact.blob_hash.as_deref() == Some(hash)
                    && common_source_blob(entities) == Some(hash)
                    && previous == current)
                    .then(|| path.clone())
            })
            .collect();
        for path in self
            .pending
            .keys()
            .filter(|path| !retained.contains(*path))
            .cloned()
            .collect::<Vec<_>>()
        {
            self.clear_pending(&path);
        }
        // A checked seed reclaims authority from the complete staged snapshot.
        // Never retain destinations that only existed in a rejected proposal.
        self.linker = IncrementalLinker::new();
        self.artifact_id_by_file.clear();
        self.file_by_artifact_id.clear();
        self.file_by_entity.clear();
        for (path, artifact, entities) in admitted {
            self.install_file(&path, artifact.id, &entities);
        }

        self.seeded = true;
        info!(
            files = indexed,
            skipped_unadmitted = unadmitted,
            "seeded cross-file linker from graph snapshot"
        );
        Ok(())
    }

    /// Re-derive a complete admitted source against the updated universe.
    /// Used only to verify obsolete external edges of affected waiting files.
    pub(crate) fn relink_complete_source<G: GraphStore>(
        &self,
        graph: &G,
        source: &FileParseData,
    ) -> crate::error::Result<Vec<Relation>> {
        let completeness = HashMap::from([(source.file_path.clone(), ParseCompleteness::Full)]);
        link_cross_file_incremental_with_graph(
            std::slice::from_ref(source),
            &self.linker,
            &completeness,
            graph,
        )
        .map_err(|error| crate::error::ReconcileError::Graph(error.to_string()))
    }

    /// Coverage comes only from this entire fresh parse, never pending fragments.
    pub(crate) fn coverage_for(
        &self,
        indexed: &kin_index::IndexedFile,
        artifact_id: ArtifactId,
    ) -> Relation {
        let mut relation = kin_index::build_incremental_parse_coverage_relation(
            &FileParseData {
                file_path: indexed.file_id.0.clone(),
                entities: indexed.entities.clone(),
                relations: indexed.extracted_relations.clone(),
                imports: indexed.imports.clone(),
            },
            artifact_id,
            &ParseCompleteness::from_parse_state(&indexed.parse_state),
            &self.linker,
        );
        kin_index::bind_parse_coverage_source(
            &mut relation,
            &indexed.file_id.0,
            kin_model::Hash256::from_bytes(*indexed.blob_hash.as_bytes()),
        );
        relation
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

    /// Remove a file and restore receiver ownership that its declarations
    /// made ambiguous. Names only nominate methods; complete admitted CAS
    /// sources and the ordinary package-aware linker authorize the new edges.
    pub(crate) fn forget_file_and_relink_go_receivers<G: GraphStore>(
        &mut self,
        graph: &G,
        blobs: &kin_blobs::BlobStore,
        file_path: &str,
        departing: &[Entity],
    ) -> crate::error::Result<Vec<Relation>> {
        let names: BTreeSet<_> = departing
            .iter()
            .filter(|entity| {
                entity.language == kin_model::LanguageId::Go
                    && matches!(
                        entity.kind,
                        kin_model::EntityKind::Class
                            | kin_model::EntityKind::TypeAlias
                            | kin_model::EntityKind::Interface
                    )
            })
            .map(|entity| entity.name.as_str())
            .collect();
        if names.is_empty() {
            self.forget_file(file_path);
            self.last_files_resolved = 0;
            return Ok(Vec::new());
        }
        let nominees = self
            .files_waiting_on_names_of(file_path, departing)
            .into_iter()
            .filter(|path| {
                self.pending.get(path).is_some_and(|pending| {
                    pending
                        .go_receiver_owners
                        .iter()
                        .any(|name| names.contains(name.as_str()))
                })
            })
            .collect();
        let (paths, absent) = self.partition_admitted_sources(graph, nominees)?;
        let mut batch = Vec::new();
        let mut completeness = HashMap::new();
        for path in paths {
            let Some(source) =
                crate::admitted_source::load(graph, blobs, &kin_model::FilePathId::new(path))?
            else {
                // An incomplete method keeps last-good state and supplies no
                // new ownership authority, even if an ambiguity disappeared.
                continue;
            };
            completeness.insert(source.file_id.0.clone(), ParseCompleteness::Full);
            batch.push(FileParseData {
                file_path: source.file_id.0,
                entities: source.entities,
                relations: source
                    .extracted_relations
                    .into_iter()
                    .filter(|relation| relation.kind == RelationKind::Contains)
                    .collect(),
                imports: Vec::new(),
            });
        }
        // Finish all admitted-source reads before changing the cached universe.
        self.forget_file(file_path);
        for path in absent {
            self.forget_file(&path);
        }
        self.last_files_resolved = batch.len();
        if batch.is_empty() {
            return Ok(Vec::new());
        }
        let relations =
            link_cross_file_incremental_with_graph(&batch, &self.linker, &completeness, graph)
                .map_err(|error| {
                    crate::error::ReconcileError::InvalidTransaction(format!(
                        "Go receiver ownership after file removal: {error}"
                    ))
                })?;
        Ok(relations
            .into_iter()
            .filter(|relation| {
                let (Some(src), Some(dst)) = (relation.src.as_entity(), relation.dst.as_entity())
                else {
                    return false;
                };
                relation.kind == RelationKind::Contains
                    && self.linker.entity_language_by_id.get(&src)
                        == Some(&kin_model::LanguageId::Go)
                    && matches!(
                        self.linker.entity_kind_by_id.get(&src),
                        Some(
                            kin_model::EntityKind::Class
                                | kin_model::EntityKind::TypeAlias
                                | kin_model::EntityKind::Interface
                        )
                    )
                    && self.linker.entity_language_by_id.get(&dst)
                        == Some(&kin_model::LanguageId::Go)
                    && self.linker.entity_kind_by_id.get(&dst)
                        == Some(&kin_model::EntityKind::Method)
            })
            .collect())
    }

    /// Distinguish a retired cached source from unreadable admitted source.
    /// This only nominates cache cleanup: present bytes still undergo the full
    /// admitted-source reader, including identity and CAS validation. Callers
    /// stage all reads before forgetting anything, under their graph authority
    /// boundary. A missing body or inconsistent tree/identity is never absence.
    fn partition_admitted_sources<G: GraphStore>(
        &self,
        graph: &G,
        mut paths: Vec<String>,
    ) -> crate::error::Result<(Vec<String>, Vec<String>)> {
        paths.sort();
        let mut present = Vec::new();
        let mut absent = Vec::new();
        for path in paths {
            let repo_path = RepoPath::from_utf8(path.clone())
                .map_err(|error| crate::error::ReconcileError::Graph(error.to_string()))?;
            let entry = checked_seed_artifact(
                || {
                    graph
                        .get_tree_entry(&kin_model::FilePathId::new(&path))
                        .map_err(|error| crate::error::ReconcileError::Graph(error.to_string()))
                },
                || graph.artifact_id_at_path(&repo_path),
            )?;
            if entry.is_some() {
                present.push(path);
            } else {
                absent.push(path);
            }
        }
        Ok((present, absent))
    }

    /// Install a file's entities into the universe, keeping the identity
    /// side-indexes in step. Replaces whatever the file held before.
    fn install_file(&mut self, file_path: &str, artifact_id: ArtifactId, entities: &[Entity]) {
        let entities = if self.withheld.contains_key(&artifact_id) {
            &[]
        } else {
            entities
        };
        self.install_observed_file(file_path, artifact_id, entities);
    }

    fn install_observed_file(
        &mut self,
        file_path: &str,
        artifact_id: ArtifactId,
        entities: &[Entity],
    ) {
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
        self.resolve_after_edit_inner(
            graph,
            file_path,
            entities,
            extracted,
            imports,
            completeness,
            None,
            None,
        )
    }

    /// Restore dependency nominations from admitted CAS, once per checked seed.
    /// The file currently being edited supplies its fresh observation separately.
    pub(crate) fn restore_dependencies<G: GraphStore>(
        &mut self,
        graph: &G,
        blobs: &kin_blobs::BlobStore,
        editing: Option<&str>,
    ) -> crate::error::Result<()> {
        self.restore_dependencies_inner(graph, blobs, editing, None, None)
            .map(|_| ())
    }

    /// The caller owns this private linker fork. The explicit exact-tree source
    /// census includes valid files with no declarations and forces one checked
    /// observation even if a previous dependency-only restore already ran.
    ///
    /// With `stale` supplied, a source whose graph declarations were not
    /// derived from its bytes is named there instead of failing the census,
    /// every such source is named, and nothing is installed into this fork
    /// when any was found. The caller then discards the fork.
    pub(crate) fn restore_canonical_sources<G: GraphStore>(
        &mut self,
        graph: &G,
        blobs: &kin_blobs::BlobStore,
        paths: Vec<String>,
        stale: Option<&mut Vec<crate::reconciler::StaleCanonicalSource>>,
    ) -> crate::error::Result<Vec<crate::admitted_source::AdmittedSource>> {
        if !self.withheld.is_empty() {
            return Err(crate::error::ReconcileError::InvalidTransaction(
                "canonical restore cannot consume an unpublished withheld batch".into(),
            ));
        }
        self.seed_from_graph_checked(graph)?;
        self.restore_dependencies_inner(graph, blobs, None, Some(paths), stale)
    }

    fn restore_dependencies_inner<G: GraphStore>(
        &mut self,
        graph: &G,
        blobs: &kin_blobs::BlobStore,
        editing: Option<&str>,
        source_paths: Option<Vec<String>>,
        mut stale: Option<&mut Vec<crate::reconciler::StaleCanonicalSource>>,
    ) -> crate::error::Result<Vec<crate::admitted_source::AdmittedSource>> {
        let retain_sources = source_paths.is_some();
        if (self.dependencies_restored && !retain_sources) || !self.seeded {
            return Ok(Vec::new());
        }
        let paths = source_paths.unwrap_or_else(|| {
            self.artifact_id_by_file
                .keys()
                .filter(|path| editing != Some(path.as_str()) && !self.is_withheld(path))
                .cloned()
                .collect()
        });
        let (paths, absent) = self.partition_admitted_sources(graph, paths)?;
        let mut sources = Vec::new();
        let mut observations = Vec::new();
        let mut witnesses = Vec::new();
        let mut witness_count = 0;
        for path in paths {
            let file = kin_model::FilePathId::new(path);
            let reading = crate::admitted_source::inspect_with_content(graph, &file, |hash| {
                blobs
                    .read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))
                    .map_err(Into::into)
            })?;
            let reading = match (reading, stale.as_deref_mut()) {
                (crate::admitted_source::AdmittedSourceReading::Stale(reason), Some(stale)) => {
                    stale.push(crate::reconciler::StaleCanonicalSource { file, reason });
                    continue;
                }
                (reading, _) => reading,
            };
            if let Some(source) = reading.into_complete(&file)? {
                let indexed = &source.indexed;
                witnesses.push((
                    indexed.file_id.0.clone(),
                    kin_index::linker::bind_import_witness(
                        &indexed.file_id.0,
                        &indexed.entities,
                        &indexed.extracted_relations,
                    ),
                ));
                witness_count += usize::from(
                    witnesses
                        .last()
                        .is_some_and(|(_, witness)| witness.is_some()),
                );
                if witness_count > MAX_PENDING_FILES {
                    return Err(crate::error::ReconcileError::InvalidTransaction(
                        "admitted import evidence cache capacity exceeded".into(),
                    ));
                }
                if let Some(fragment) = self.dependency_fragment(
                    &indexed.file_id.0,
                    ParseCompleteness::Full,
                    &indexed.extracted_relations,
                    &indexed.imports,
                    &indexed.entities,
                ) {
                    observations.push((indexed.file_id.0.clone(), fragment));
                    if observations.len() > MAX_PENDING_FILES {
                        return Err(crate::error::ReconcileError::InvalidTransaction(
                            "admitted dependency cache capacity exceeded".into(),
                        ));
                    }
                }
                if retain_sources {
                    sources.push(source);
                }
            }
        }
        // A census that named a stale source installs nothing: the caller
        // re-derives those sources and restores again from the result.
        if stale.is_some_and(|stale| !stale.is_empty()) {
            return Ok(Vec::new());
        }
        // Install only after every read succeeds. Ordinary restoration retains
        // compact fragments; explicit canonical restoration also retains exact
        // bodies for the separately staged projection cache.
        for path in absent {
            self.forget_file(&path);
        }
        // Rebuild full observations only for the explicit canonical restore.
        // Ordinary edit-time dependency restoration retains its compact cache.
        for source in &sources {
            let indexed = &source.indexed;
            let artifact = admitted_artifact_id(graph, &indexed.file_id.0).ok_or_else(|| {
                crate::error::ReconcileError::InvalidTransaction(
                    "canonical source lost admitted artifact identity".into(),
                )
            })?;
            self.install_observed_file(&indexed.file_id.0, artifact, &indexed.entities);
            let parse = FileParseData {
                file_path: indexed.file_id.0.clone(),
                entities: indexed.entities.clone(),
                relations: indexed.extracted_relations.clone(),
                imports: indexed.imports.clone(),
            };
            self.linker
                .record_file_includes(std::slice::from_ref(&parse));
            self.linker.record_class_bases(std::slice::from_ref(&parse));
        }
        for (file, witness) in witnesses {
            self.linker.replace_import_witness(&file, witness);
        }
        for (file, fragment) in observations {
            self.install_pending(&file, fragment);
        }
        self.dependencies_restored = true;
        Ok(sources)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resolve_after_edit_checked<G: GraphStore>(
        &mut self,
        graph: &G,
        blobs: &kin_blobs::BlobStore,
        file_path: &str,
        entities: &[Entity],
        extracted: &[ExtractedRelation],
        imports: &[FileImport],
        completeness: ParseCompleteness,
    ) -> crate::error::Result<CrossFilePass> {
        self.restore_dependencies(graph, blobs, Some(file_path))?;
        if self.needs_dependency_entry(extracted, imports, entities)
            && !self.pending.contains_key(file_path)
            && self.pending.len() >= MAX_PENDING_FILES
        {
            return Err(crate::error::ReconcileError::InvalidTransaction(
                "admitted dependency cache capacity exceeded".into(),
            ));
        }
        let mut sources = Vec::new();
        let (paths, absent) = self.partition_admitted_sources(
            graph,
            self.files_waiting_on_names_of(file_path, entities),
        )?;
        for path in paths {
            if let Some(indexed) =
                crate::admitted_source::load(graph, blobs, &kin_model::FilePathId::new(path))?
            {
                sources.push(indexed);
            }
        }
        for path in absent {
            self.forget_file(&path);
        }
        Ok(self.resolve_after_edit_inner(
            graph,
            file_path,
            entities,
            extracted,
            imports,
            completeness,
            Some(sources),
            Some(blobs),
        ))
    }

    /// Repair cached identity custody for the bounded exact-import footprint.
    /// A replacement remains a known module with no old declarations; changed
    /// bytes on the same artifact still need normal checked readmission.
    fn refresh_named_import_inputs<G: GraphStore>(
        &mut self,
        graph: &G,
        batch: &[FileParseData],
    ) -> crate::error::Result<Vec<kin_index::linker::NamedImportObservation>> {
        self.refresh_named_import_inputs_with(batch, |path| {
            let repo_path = RepoPath::from_utf8(path.to_owned())
                .map_err(|error| crate::error::ReconcileError::Graph(error.to_string()))?;
            checked_seed_artifact(
                || {
                    graph
                        .get_tree_entry(&kin_model::FilePathId::new(path))
                        .map_err(|error| crate::error::ReconcileError::Graph(error.to_string()))
                },
                || graph.artifact_id_at_path(&repo_path),
            )
        })
    }

    fn refresh_named_import_inputs_with(
        &mut self,
        batch: &[FileParseData],
        mut read: impl FnMut(&str) -> crate::error::Result<Option<SeedArtifact>>,
    ) -> crate::error::Result<Vec<kin_index::linker::NamedImportObservation>> {
        let fresh: HashSet<_> = batch.iter().map(|file| file.file_path.as_str()).collect();
        let mut examined = 0usize;
        for _ in 0..64 {
            let observations = kin_index::linker::named_import_observations(batch, &self.linker);
            let paths: BTreeSet<_> = observations
                .iter()
                .flat_map(|observation| {
                    observation
                        .candidate_presence
                        .keys()
                        .chain(observation.source_bindings.keys())
                })
                .filter(|path| {
                    !fresh.contains(path.as_str())
                        && !self.is_withheld(path)
                        && self.artifact_id_by_file.contains_key(*path)
                })
                .collect();
            examined = examined.checked_add(paths.len()).ok_or_else(|| {
                crate::error::ReconcileError::Graph("named-import input inspection overflow".into())
            })?;
            if examined > MAX_PENDING_FILES {
                return Err(crate::error::ReconcileError::Graph(
                    "named-import input inspection budget exceeded".into(),
                ));
            }
            let mut stale = Vec::new();
            // Do not change cache state if any identity/tree read in this round
            // fails. Final source/candidate publication checks remain required.
            for path in paths {
                let current = read(path)?;
                if current.as_ref().map(|entry| entry.id)
                    != self.artifact_id_by_file.get(path).copied()
                {
                    stale.push((path.clone(), current));
                }
            }
            if stale.is_empty() {
                return Ok(observations);
            }
            for (path, current) in stale {
                self.forget_file(&path);
                if let Some(current) = current {
                    self.install_file(&path, current.id, &[]);
                }
            }
            // Removing a stale competing module can expose a package chain.
            // Recompute its footprint only after actual identity progress.
        }
        Err(crate::error::ReconcileError::Graph(
            "named-import input refresh round budget exceeded".into(),
        ))
    }

    fn refresh_rust_project<G: GraphStore>(
        &mut self,
        graph: &G,
        blobs: &kin_blobs::BlobStore,
        batch: &[FileParseData],
    ) -> crate::error::Result<kin_model::Hash256> {
        use crate::error::ReconcileError;
        self.linker.clear_rust_project();
        let tree = graph
            .resolved_tree_snapshot()
            .map_err(|error| ReconcileError::Graph(error.to_string()))?
            .ok_or_else(|| {
                ReconcileError::InvalidTransaction(
                    "Rust live resolution requires a selected tree".into(),
                )
            })?;
        let observation = kin_index::rust_project::RustProjectAuthority::observe_admitted_tree(
            &tree,
            Default::default(),
            |hash| {
                blobs
                    .read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))
                    .map_err(|error| error.to_string())
            },
        )
        .map_err(|error| ReconcileError::InvalidTransaction(error.to_string()))?;
        if let Some(authority) = observation.authority() {
            let mut entities = graph
                .list_all_entities()
                .map_err(|error| ReconcileError::Graph(error.to_string()))?;
            let replaced: HashSet<_> = batch.iter().map(|file| file.file_path.as_str()).collect();
            entities.retain(|entity| {
                !entity
                    .file_origin
                    .as_ref()
                    .is_some_and(|file| replaced.contains(file.0.as_str()))
            });
            entities.extend(batch.iter().flat_map(|file| file.entities.iter().cloned()));
            self.linker
                .install_rust_project(authority.clone(), &entities)
                .map_err(ReconcileError::InvalidTransaction)?;
        }
        Ok(observation.tree_digest())
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_after_edit_inner<G: GraphStore>(
        &mut self,
        graph: &G,
        file_path: &str,
        entities: &[Entity],
        extracted: &[ExtractedRelation],
        imports: &[FileImport],
        completeness: ParseCompleteness,
        fresh_dependents: Option<Vec<kin_index::IndexedFile>>,
        blobs: Option<&kin_blobs::BlobStore>,
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
        let waiting_before_edit = self.files_waiting_on_names_of(file_path, entities);

        // Install the file's current entities before resolving anything, so
        // both directions see the same universe: forward resolution needs this
        // file's sources, backward resolution needs its destinations.
        // These are the fresh parse's stable identities, never the withheld
        // old anchors. The batch owner releases withholding only after apply.
        self.install_observed_file(file_path, artifact_id, entities);
        let own_slice = std::slice::from_ref(&own);
        self.linker.record_file_includes(own_slice);
        self.linker.record_class_bases(own_slice);

        // Backward direction. A file can only newly bind because a name it was
        // waiting on now exists, so the candidate set is looked up by the names
        // this file defines rather than scanned for.
        let checked = fresh_dependents.is_some();
        let dependent_sources = fresh_dependents.unwrap_or_default();
        let dependents = if checked {
            dependent_sources
                .iter()
                .map(|source| source.file_id.0.clone())
                .collect()
        } else {
            waiting_before_edit
        };

        let mut batch: Vec<FileParseData> = Vec::with_capacity(dependents.len() + 1);
        let mut completeness_map: FileParseCompletenessMap = HashMap::new();
        completeness_map.insert(file_path.to_string(), completeness.clone());
        batch.push(own);
        if checked {
            for source in &dependent_sources {
                completeness_map.insert(source.file_id.0.clone(), ParseCompleteness::Full);
                batch.push(FileParseData {
                    file_path: source.file_id.0.clone(),
                    entities: source.entities.clone(),
                    relations: source.extracted_relations.clone(),
                    imports: source.imports.clone(),
                });
            }
        } else {
            for dependent in &dependents {
                let Some(pending) = self.pending.get(dependent) else {
                    continue;
                };
                completeness_map.insert(dependent.clone(), pending.completeness.clone());
                batch.push(pending.parse.clone());
            }
        }

        let files_resolved = batch.len();
        self.last_files_resolved = files_resolved;
        // Exact-tree admission can retire a file without passing a removal
        // event through this reconciler. Repair only the cached inputs this
        // exact resolver consulted, before either linking or publishing facts.
        let checked_named_observations = if checked {
            match self.refresh_named_import_inputs(graph, &batch) {
                Ok(observations) => Some(observations),
                Err(error) => {
                    return CrossFilePass {
                        failure: Some(error.to_string()),
                        referenced,
                        files_resolved,
                        ..CrossFilePass::default()
                    };
                }
            }
        } else {
            None
        };
        // Input refresh may remove/reinstall cache entries, which clears an
        // earlier authority. Rebuild after every such mutation, then recompute
        // observations under this exact selected source generation.
        let rust_tree = match blobs.filter(|_| !self.defer_rust_project) {
            Some(blobs) if batch.iter().any(|file| file.file_path.ends_with(".rs")) => {
                match self.refresh_rust_project(graph, blobs, &batch) {
                    Ok(tree) => Some(tree),
                    Err(error) => {
                        return CrossFilePass {
                            failure: Some(error.to_string()),
                            referenced,
                            files_resolved,
                            ..CrossFilePass::default()
                        };
                    }
                }
            }
            _ => None,
        };
        let relations = match link_cross_file_incremental_with_graph(
            &batch,
            &self.linker,
            &completeness_map,
            graph,
        ) {
            Ok(relations) => relations,
            Err(error) => {
                warn!(
                    file = %file_path,
                    error = %error,
                    "cross-file resolution failed; withdrawing publication authority"
                );
                return CrossFilePass {
                    failure: Some(error.to_string()),
                    referenced,
                    files_resolved,
                    ..CrossFilePass::default()
                };
            }
        };

        let mut named_import_observations = if rust_tree.is_some() {
            kin_index::linker::named_import_observations(&batch, &self.linker)
        } else {
            checked_named_observations.unwrap_or_else(|| {
                kin_index::linker::named_import_observations(&batch, &self.linker)
            })
        };
        if let Some(tree) = rust_tree {
            for observation in &mut named_import_observations {
                // An unresolved result also depends on the selected tree.
                observation.rust_project_tree = Some(tree);
            }
        }
        let batched_paths: HashSet<String> = batch.iter().map(|f| f.file_path.clone()).collect();

        let mut resolved = Vec::new();
        let mut same_file: Vec<Relation> = Vec::new();
        let mut external = Vec::new();
        let mut dependent_external = Vec::new();
        let mut artifact_imports: Vec<Relation> = Vec::new();
        for relation in relations {
            match (relation.src, relation.dst) {
                (GraphNodeId::Entity(src), GraphNodeId::Entity(dst)) => {
                    let Some(src_file) = self.file_by_entity.get(&src) else {
                        continue;
                    };
                    // Only edges sourced by a file this pass resolved.
                    // Receiver ownership is declared by the destination
                    // method's file, not by the source type's file.
                    let go_receiver_declaration = relation.kind == RelationKind::Contains
                        && self.linker.entity_kind_by_id.get(&dst)
                            == Some(&kin_model::EntityKind::Method)
                        && self.linker.entity_language_by_id.get(&dst)
                            == Some(&kin_model::LanguageId::Go)
                        && self
                            .file_by_entity
                            .get(&dst)
                            .is_some_and(|file| batched_paths.contains(&**file));
                    if !batched_paths.contains(&**src_file) && !go_receiver_declaration {
                        continue;
                    }
                    if crate::external::claims_external_import(&relation) {
                        // Waiting fragments are not fresh whole-file authority.
                        // Only the current complete source can publish or retire
                        // its external import evidence.
                        if &**src_file == file_path
                            && matches!(completeness, ParseCompleteness::Full)
                        {
                            external.push(relation);
                        } else if checked
                            && dependent_sources
                                .iter()
                                .any(|source| source.file_id.0 == **src_file)
                        {
                            dependent_external.push(relation);
                        }
                        continue;
                    }
                    if self.file_by_entity.get(&dst) == Some(src_file) {
                        same_file.push(relation);
                        continue;
                    }
                    resolved.push(relation);
                }
                (GraphNodeId::Entity(src), GraphNodeId::Artifact(dst))
                    if relation.kind == RelationKind::DerivedFrom =>
                {
                    let Some(src_file) = self.file_by_entity.get(&src) else {
                        continue;
                    };
                    let entity = batch
                        .iter()
                        .flat_map(|file| file.entities.iter())
                        .find(|entity| entity.id == src);
                    let hash = graph
                        .get_tree_entry(&kin_model::FilePathId::new(&**src_file))
                        .ok()
                        .flatten()
                        .and_then(|entry| match entry {
                            kin_model::TreeEntry::Blob { hash, .. } => Some(hash.to_string()),
                            _ => None,
                        });
                    if batched_paths.contains(&**src_file)
                        && self.artifact_id_by_file.get(&**src_file) == Some(&dst)
                        && entity.zip(hash.as_deref()).is_some_and(|(entity, hash)| {
                            kin_model::derivation::generator_relation_matches(
                                entity, &relation, dst, hash,
                            )
                        })
                    {
                        same_file.push(relation);
                    }
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

        self.record_pending(file_path, completeness, extracted, imports, entities);
        for dependent in &dependents {
            // A proposed local binding may still fail validation or application.
            // Keep its waiting fragment while graph truth retains an external
            // edge, so a retry can derive the same atomic replacement.
            let mut has_external = false;
            if let Some(entities) = self.linker.entity_by_file_name.get(dependent) {
                for id in entities.values() {
                    let held = match graph.get_all_relations_for_entity(id) {
                        Ok(held) => held,
                        Err(error) => {
                            return CrossFilePass {
                                failure: Some(format!(
                                    "waiting-source relation read failed: {error}"
                                )),
                                referenced,
                                files_resolved,
                                ..CrossFilePass::default()
                            }
                        }
                    };
                    has_external |= held.iter().any(|relation| {
                        relation.src.as_entity() == Some(*id)
                            && crate::external::claims_external_import(relation)
                    });
                }
            }
            if !has_external {
                self.reduce_pending(dependent);
            }
        }

        CrossFilePass {
            failure: None,
            resolved,
            same_file,
            external,
            dependent_sources,
            dependent_external,
            named_import_observations,
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
        // A receiver rename withdraws the old name. Nominate unchanged method
        // files before the replacement erases that name from the cache.
        if let Some(previous) = self.linker.entity_by_file_name.get(file_path) {
            for (name, id) in previous {
                if self.linker.entity_language_by_id.get(id) == Some(&kin_model::LanguageId::Go)
                    && matches!(
                        self.linker.entity_kind_by_id.get(id),
                        Some(
                            kin_model::EntityKind::Class
                                | kin_model::EntityKind::TypeAlias
                                | kin_model::EntityKind::Interface
                        )
                    )
                {
                    names.insert(name);
                }
            }
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
        // Follow source-declared importer paths transitively: an intermediate
        // re-export may change without changing any of its symbol names. The
        // pending map is bounded by MAX_PENDING_FILES; each file is visited once.
        // Names nominate only the first wave, never guessed transitive bindings.
        let mut queue = std::collections::VecDeque::from([file_path.to_string()]);
        queue.extend(dependents.iter().cloned());
        let mut visited = HashSet::new();
        while let Some(path) = queue.pop_front() {
            if !visited.insert(path.clone()) {
                continue;
            }
            if let Some(files) = self.waiting_on_paths.get(&path) {
                for file in files {
                    if file != file_path && dependents.insert(file.clone()) {
                        queue.push_back(file.clone());
                    }
                }
            }
        }
        dependents
            .into_iter()
            .filter(|file| !self.is_withheld(file))
            .collect()
    }

    fn needs_dependency_entry(
        &self,
        extracted: &[ExtractedRelation],
        imports: &[FileImport],
        entities: &[Entity],
    ) -> bool {
        !imports.is_empty()
            || !go_receiver_owner_names(extracted, entities).is_empty()
            || extracted.iter().any(|relation| {
                !kin_parser::is_call_extraction_incomplete_marker(relation)
                    && !kin_parser::import_witness::claims_import_witness(relation)
                    && !self.linker_knows_name(&relation.dst_name)
            })
    }

    /// Retain imported references even after resolution. These names nominate
    /// affected sources; only a fresh admitted parse can authorize new edges.
    fn record_pending(
        &mut self,
        file_path: &str,
        completeness: ParseCompleteness,
        extracted: &[ExtractedRelation],
        imports: &[FileImport],
        entities: &[Entity],
    ) {
        let Some(fragment) =
            self.dependency_fragment(file_path, completeness, extracted, imports, entities)
        else {
            self.clear_pending(file_path);
            return;
        };
        if !self.pending.contains_key(file_path) && self.pending.len() >= MAX_PENDING_FILES {
            if !self.capacity_reported {
                self.capacity_reported = true;
                warn!(cap = MAX_PENDING_FILES, file = %file_path,
                    "cross-file waiting index is full; legacy unchecked caller cannot retain another dependency");
            }
            return;
        }
        self.install_pending(file_path, fragment);
    }

    fn dependency_fragment(
        &self,
        file_path: &str,
        completeness: ParseCompleteness,
        extracted: &[ExtractedRelation],
        imports: &[FileImport],
        entities: &[Entity],
    ) -> Option<PendingFile> {
        let go_receiver_owners = go_receiver_owner_names(extracted, entities);
        let relations: Vec<ExtractedRelation> = extracted
            .iter()
            .filter(|relation| !kin_parser::is_call_extraction_incomplete_marker(relation))
            .filter(|relation| !kin_parser::import_witness::claims_import_witness(relation))
            .filter(|relation| {
                !imports.is_empty()
                    || go_receiver_owners.contains(&relation.src_name)
                    || !self.linker_knows_name(&relation.dst_name)
            })
            .cloned()
            .collect();
        if relations.is_empty() && imports.is_empty() {
            return None;
        }
        let waiting_on = relations
            .iter()
            .map(|relation| relation.dst_name.clone())
            .chain(go_receiver_owners.iter().cloned())
            .chain(
                imports
                    .iter()
                    .flat_map(|import| &import.specifiers)
                    .flat_map(|name| {
                        [
                            name.local_name.clone(),
                            name.original_name
                                .clone()
                                .unwrap_or_else(|| name.local_name.clone()),
                        ]
                    }),
            )
            .collect();
        let waiting_on_paths = imports
            .iter()
            .flat_map(|import| {
                kin_index::workspace_package_import_candidate_paths(file_path, &import.module_path)
                    .into_iter()
                    .chain(kin_index::linker::python_import_observation_paths(
                        file_path,
                        &import.module_path,
                    ))
            })
            .collect();
        Some(PendingFile {
            parse: FileParseData {
                file_path: file_path.to_string(),
                entities: Vec::new(),
                relations,
                imports: imports.to_vec(),
            },
            completeness,
            source_blob_hash: common_source_blob(entities).map(str::to_owned),
            waiting_on,
            waiting_on_paths,
            go_receiver_owners,
        })
    }

    fn install_pending(&mut self, file_path: &str, fragment: PendingFile) {
        self.clear_pending(file_path);
        for path in &fragment.waiting_on_paths {
            self.waiting_on_paths
                .entry(path.clone())
                .or_default()
                .insert(file_path.to_string());
        }
        for name in &fragment.waiting_on {
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
        self.pending.insert(file_path.to_string(), fragment);
    }

    /// Drop the names a dependent no longer waits on after this pass bound them.
    fn reduce_pending(&mut self, file_path: &str) {
        let Some(pending) = self.pending.get(file_path) else {
            return;
        };
        if !pending.parse.imports.is_empty() || !pending.go_receiver_owners.is_empty() {
            return;
        }
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
        let source_blob_hash = pending.source_blob_hash.clone();
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
                source_blob_hash,
                waiting_on: waiting,
                waiting_on_paths: BTreeSet::new(),
                go_receiver_owners: BTreeSet::new(),
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
        for path in previous.waiting_on_paths {
            if let Some(files) = self.waiting_on_paths.get_mut(&path) {
                files.remove(file_path);
                if files.is_empty() {
                    self.waiting_on_paths.remove(&path);
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

#[derive(Debug, PartialEq)]
struct SeedArtifact {
    id: ArtifactId,
    blob_hash: Option<String>,
}

fn common_source_blob(entities: &[Entity]) -> Option<&str> {
    let hash = entities
        .first()?
        .metadata
        .extra
        .get("blob_hash")?
        .as_str()?;
    entities
        .iter()
        .all(|entity| {
            entity
                .metadata
                .extra
                .get("blob_hash")
                .and_then(|value| value.as_str())
                == Some(hash)
        })
        .then_some(hash)
}

fn checked_seed_artifact(
    read_entry: impl FnOnce() -> crate::error::Result<Option<kin_model::TreeEntry>>,
    read_id: impl FnOnce() -> Option<ArtifactId>,
) -> crate::error::Result<Option<SeedArtifact>> {
    match (read_entry()?, read_id()) {
        (Some(entry), Some(id)) => Ok(Some(SeedArtifact {
            id,
            blob_hash: match entry {
                kin_model::TreeEntry::Blob { hash, .. } => Some(hash.to_string()),
                _ => None,
            },
        })),
        (None, None) => Ok(None),
        _ => Err(crate::error::ReconcileError::Graph(
            "cross-file seed artifact identity disagrees with admitted tree".into(),
        )),
    }
}

#[cfg(test)]
#[path = "cross_file_cache_tests.rs"]
mod cache_membership_tests;

#[cfg(test)]
mod source_evidence_tests {
    use super::*;
    use kin_index::{IndexPipeline, IndexedFile};
    use kin_model::FilePathId;

    fn named_input_fixture() -> (LiveCrossFileLinker, FileParseData) {
        let mut live = LiveCrossFileLinker::new();
        let mut files = Vec::new();
        for (path, body) in [
            (
                "caller.py",
                "from local import work\ndef run():\n    return work()\n",
            ),
            ("local.py", "def work():\n    return 1\n"),
            ("local.pyi", "def work():\n    return 2\n"),
        ] {
            let indexed = IndexPipeline::new()
                .index_file_content_with_tests(
                    &FilePathId::new(path),
                    body.as_bytes(),
                    kin_blobs::digest(body.as_bytes()),
                )
                .unwrap()
                .indexed_file;
            live.install_file(path, ArtifactId::new(), &indexed.entities);
            files.push(FileParseData {
                file_path: path.into(),
                entities: indexed.entities,
                relations: indexed.extracted_relations,
                imports: indexed.imports,
            });
        }
        live.linker.record_class_bases(&files);
        (live, files.remove(0))
    }

    #[test]
    fn named_input_refresh_stages_all_reads_before_invalidating_a_round() {
        let (mut live, caller) = named_input_fixture();
        let before = serde_json::to_vec(&live.linker.to_checkpoint_v1()).unwrap();
        let mut reads = Vec::new();
        let error = live
            .refresh_named_import_inputs_with(&[caller], |path| {
                reads.push(path.to_owned());
                if path == "local.py" {
                    Ok(None)
                } else {
                    Err(crate::error::ReconcileError::Graph(
                        "injected footprint read failure".into(),
                    ))
                }
            })
            .unwrap_err();
        assert_eq!(reads, vec!["local.py", "local.pyi"]);
        assert!(error
            .to_string()
            .contains("injected footprint read failure"));
        assert_eq!(
            serde_json::to_vec(&live.linker.to_checkpoint_v1()).unwrap(),
            before
        );
        assert!(live.knows_file("local.py"));
    }

    #[test]
    fn named_input_refresh_preserves_fresh_and_withheld_batch_members() {
        let (mut live, caller) = named_input_fixture();
        for path in ["local.py", "local.pyi"] {
            let id = live.artifact_id_by_file[path];
            live.withheld.insert(id, path.to_owned());
            live.install_file(path, id, &[]);
        }
        let before = serde_json::to_vec(&live.linker.to_checkpoint_v1()).unwrap();
        let observations = live
            .refresh_named_import_inputs_with(&[caller], |_| {
                panic!("fresh and explicitly withheld members are owned by the batch")
            })
            .unwrap();
        assert_eq!(observations.len(), 1);
        assert!(observations[0].target.is_none());
        assert_eq!(
            serde_json::to_vec(&live.linker.to_checkpoint_v1()).unwrap(),
            before
        );
    }

    #[test]
    fn checked_seed_refuses_entity_read_failure_without_claiming_authority() {
        let mut linker = LiveCrossFileLinker::new();
        let error = linker
            .seed_with(
                || {
                    Err(crate::error::ReconcileError::Graph(
                        "injected entity read failure".into(),
                    ))
                },
                |_| panic!("artifact reads require a successful entity read"),
            )
            .unwrap_err();
        assert!(error.to_string().contains("injected entity read failure"));
        assert!(!linker.is_seeded());
    }

    #[test]
    fn checked_seed_stages_all_artifact_reads_before_installing_any_file() {
        let mut entities = parsed("def example():\n    return 1\n").entities;
        entities.truncate(1);
        let mut second = entities[0].clone();
        entities[0].file_origin = Some(FilePathId::new("a.py"));
        second.id = EntityId::new();
        second.file_origin = Some(FilePathId::new("b.py"));
        entities.push(second);
        let mut linker = LiveCrossFileLinker::new();
        let error = linker
            .seed_with(
                || Ok(entities.clone()),
                |file| {
                    if file == "a.py" {
                        Ok(Some(SeedArtifact {
                            id: ArtifactId::new(),
                            blob_hash: None,
                        }))
                    } else {
                        Err(crate::error::ReconcileError::Graph(
                            "injected artifact read failure".into(),
                        ))
                    }
                },
            )
            .unwrap_err();
        assert!(error.to_string().contains("injected artifact read failure"));
        assert!(!linker.is_seeded());
        assert!(!linker.knows_file("a.py"));
        assert!(!linker.knows_file("b.py"));
        linker
            .seed_with(
                || Ok(entities),
                |file| {
                    Ok((file == "a.py").then(|| SeedArtifact {
                        id: ArtifactId::new(),
                        blob_hash: None,
                    }))
                },
            )
            .unwrap();
        assert!(linker.is_seeded());
        assert!(linker.knows_file("a.py"));
        assert!(!linker.knows_file("b.py"));
    }

    #[test]
    fn checked_seed_distinguishes_missing_artifact_from_unreadable_or_inconsistent_truth() {
        let id = ArtifactId::new();
        let entry = kin_model::TreeEntry::blob(kin_model::Hash256::from_bytes([3; 32]), false);
        assert_eq!(checked_seed_artifact(|| Ok(None), || None).unwrap(), None);
        assert_eq!(
            checked_seed_artifact(|| Ok(Some(entry.clone())), || Some(id)).unwrap(),
            Some(SeedArtifact {
                id,
                blob_hash: Some(kin_model::Hash256::from_bytes([3; 32]).to_string())
            })
        );
        assert!(checked_seed_artifact(|| Ok(Some(entry)), || None).is_err());
        assert!(checked_seed_artifact(|| Ok(None), || Some(id)).is_err());
        let error = checked_seed_artifact(
            || {
                Err(crate::error::ReconcileError::Graph(
                    "injected tree read failure".into(),
                ))
            },
            || panic!("identity lookup must not mask a failed tree read"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("injected tree read failure"));
    }

    #[test]
    fn checked_reseed_replaces_stale_universe_and_preserves_only_version_bound_waiters() {
        let source = parsed("from remote import invoke\n\ndef caller():\n    return invoke()\n");
        let source_path = source.file_id.0.clone();
        let source_artifact = ArtifactId::new();
        let source_hash = common_source_blob(&source.entities).unwrap().to_owned();
        let old_artifact = ArtifactId::new();
        let mut old = parsed("def old_destination():\n    return 1\n").entities;
        for entity in &mut old {
            entity.id = EntityId::new();
            entity.file_origin = Some(FilePathId::new("old.py"));
        }
        let mut all = source.entities.clone();
        all.extend(old.clone());
        let mut linker = LiveCrossFileLinker::new();
        linker
            .seed_with(
                || Ok(all),
                |file| {
                    Ok(Some(SeedArtifact {
                        id: if file == source_path {
                            source_artifact
                        } else {
                            old_artifact
                        },
                        blob_hash: Some(source_hash.clone()),
                    }))
                },
            )
            .unwrap();
        linker.record_pending(
            &source_path,
            ParseCompleteness::Full,
            &source.extracted_relations,
            &source.imports,
            &source.entities,
        );
        assert_eq!(linker.pending_file_count(), 1);
        assert!(linker.knows_file("old.py"));
        assert!(linker
            .seed_with(
                || Err(crate::error::ReconcileError::Graph(
                    "injected refresh failure".into()
                )),
                |_| unreachable!(),
            )
            .is_err());
        assert!(!linker.is_seeded());
        linker
            .seed_with(
                || Ok(source.entities.clone()),
                |_| {
                    Ok(Some(SeedArtifact {
                        id: source_artifact,
                        blob_hash: Some(source_hash.clone()),
                    }))
                },
            )
            .unwrap();
        assert!(linker.is_seeded());
        assert!(!linker.knows_file("old.py"));
        assert!(!linker.knows_artifact(&old_artifact));
        assert!(old
            .iter()
            .all(|entity| !linker.file_by_entity.contains_key(&entity.id)));
        assert!(!linker.linker_knows_name("old_destination"));
        assert_eq!(linker.pending_file_count(), 1);
        assert_eq!(
            linker.waiting_on.get("invoke").unwrap(),
            &BTreeSet::from([source_path.clone()])
        );

        // A path and declaration identities alone cannot preserve old syntax.
        let changed_hash = kin_blobs::digest(b"different admitted source").to_string();
        let mut changed = source.entities.clone();
        for entity in &mut changed {
            entity
                .metadata
                .extra
                .insert("blob_hash".into(), changed_hash.clone().into());
        }
        linker
            .seed_with(
                || Ok(changed),
                |_| {
                    Ok(Some(SeedArtifact {
                        id: source_artifact,
                        blob_hash: Some(changed_hash.clone()),
                    }))
                },
            )
            .unwrap();
        assert_eq!(linker.pending_file_count(), 0);
        assert!(!linker.waiting_on.contains_key("invoke"));
    }

    #[test]
    fn import_witness_controls_do_not_consume_dependency_capacity_or_keys() {
        let plain = parsed("def plain():\n    return 1\n");
        let mut linker = LiveCrossFileLinker::new();
        linker.install_file(&plain.file_id.0, ArtifactId::new(), &plain.entities);
        assert!(plain
            .extracted_relations
            .iter()
            .any(kin_parser::import_witness::claims_import_witness));
        assert!(!linker.needs_dependency_entry(
            &plain.extracted_relations,
            &plain.imports,
            &plain.entities
        ));
        assert!(linker
            .dependency_fragment(
                &plain.file_id.0,
                ParseCompleteness::Full,
                &plain.extracted_relations,
                &plain.imports,
                &plain.entities
            )
            .is_none());

        let mut malformed = plain.extracted_relations.clone();
        let control = malformed
            .iter_mut()
            .find(|relation| kin_parser::import_witness::claims_import_witness(relation))
            .unwrap();
        control.dst_name = "not valid witness JSON".into();
        assert!(!linker.needs_dependency_entry(&malformed, &plain.imports, &plain.entities));
        assert!(linker
            .dependency_fragment(
                &plain.file_id.0,
                ParseCompleteness::Full,
                &malformed,
                &plain.imports,
                &plain.entities
            )
            .is_none());

        let waiting = parsed("def run():\n    return missing()\n");
        linker.install_file(&waiting.file_id.0, ArtifactId::new(), &waiting.entities);
        assert!(linker.needs_dependency_entry(
            &waiting.extracted_relations,
            &waiting.imports,
            &waiting.entities
        ));
        let fragment = linker
            .dependency_fragment(
                &waiting.file_id.0,
                ParseCompleteness::Full,
                &waiting.extracted_relations,
                &waiting.imports,
                &waiting.entities,
            )
            .unwrap();
        assert!(fragment.waiting_on.contains("missing"));
        assert!(fragment
            .parse
            .relations
            .iter()
            .all(|relation| !kin_parser::import_witness::claims_import_witness(relation)));
        assert_eq!(
            fragment.waiting_on.len(),
            1,
            "only the actual unresolved symbol is a dependency key"
        );
    }

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
