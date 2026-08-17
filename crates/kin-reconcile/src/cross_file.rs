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
//! * **forward** — the file being reconciled resolves its destinations against
//!   every entity already in the graph, so a file written against modules that
//!   already exist connects on arrival;
//! * **backward** — a reference a file indexed earlier left unbound binds the
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

/// Destination names a file's freshly parsed source still mentions, per
/// relation kind.
///
/// This is the evidence a single-file reconcile actually holds about cross-file
/// edges it did not re-derive: the file's own text. An edge whose destination
/// this file no longer names anywhere is stale by that evidence and may be
/// retired; an edge whose destination is still named is preserved even when the
/// incremental pass failed to re-derive it, so an init-time batch-linked edge
/// resolved at a tier the incremental universe cannot reach is never deleted by
/// a pass that merely could not see it.
#[derive(Debug, Default, Clone)]
pub struct ReferencedDestinations {
    by_kind: HashMap<RelationKind, HashSet<String>>,
    /// False when the parse was not complete, which withdraws all authority:
    /// a recovered tree can omit call sites, so an absent name proves nothing.
    trustworthy: bool,
}

impl ReferencedDestinations {
    fn from_extracted(extracted: &[ExtractedRelation], completeness: &ParseCompleteness) -> Self {
        let mut by_kind: HashMap<RelationKind, HashSet<String>> = HashMap::new();
        for relation in extracted {
            if kin_parser::is_call_extraction_incomplete_marker(relation) {
                continue;
            }
            let names = by_kind.entry(relation.kind).or_default();
            names.insert(relation.dst_name.clone());
            names.insert(bare_entity_name(&relation.dst_name).to_string());
        }
        Self {
            by_kind,
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
        self.trustworthy && !self.mentions(kind, entity_name)
    }

    /// Whether the parse behind this evidence was complete. A recovered tree
    /// can omit declarations, so nothing may be retired on its silence.
    pub fn is_complete(&self) -> bool {
        self.trustworthy
    }
}

/// What one cross-file pass produced.
#[derive(Debug, Default)]
pub struct CrossFilePass {
    /// Cross-file relations, entity-level and artifact-level, that the pass
    /// resolved. Entity-level relations here always cross a file boundary;
    /// same-file relations stay the pipeline's business.
    pub resolved: Vec<Relation>,
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
    file_by_entity: HashMap<EntityId, String>,
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
    /// reconcile — `kin init` importing an existing git history is the one that
    /// matters. Resolving against that stale universe would silently miss every
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
        for entity in entities {
            self.file_by_entity.insert(entity.id, file_path.to_string());
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
        let referenced = ReferencedDestinations::from_extracted(extracted, &completeness);
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
        let relations =
            match link_cross_file_incremental_with_completeness(&batch, &self.linker, &completeness_map)
            {
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

        let batched_paths: HashSet<String> =
            batch.iter().map(|f| f.file_path.clone()).collect();

        let mut resolved = Vec::new();
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
                    // Only edges sourced by a file this pass resolved, and only
                    // when they actually leave that file: same-file relations
                    // are already carried by the pipeline's own resolution and
                    // adding them here would duplicate a delta key.
                    if !batched_paths.contains(src_file) {
                        continue;
                    }
                    if self.file_by_entity.get(&dst) == Some(src_file) {
                        continue;
                    }
                    resolved.push(relation);
                }
                (GraphNodeId::Artifact(src), GraphNodeId::Artifact(_)) => {
                    if !matches!(relation.kind, RelationKind::Imports | RelationKind::Includes) {
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
