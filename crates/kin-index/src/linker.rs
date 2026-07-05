// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;
use tracing::debug;

use sha2::{Digest, Sha256};

use kin_model::{
    ArtifactId, Entity, EntityId, EntityKind, GraphNodeId, Relation, RelationEvidence, RelationId,
    RelationKind, RelationOrigin, Visibility,
};
use kin_parser::{ExtractedRelation, FileImport};

/// Result of resolving a single unresolved relation.
#[derive(Debug)]
pub enum LinkingOutcome {
    /// Successfully resolved to an existing entity.
    Resolved { relation: Relation },
    /// Could not find a matching entity (deferred or discarded).
    Unresolved {
        kind: RelationKind,
        src: String,
        dst: String,
    },
}

/// Cross-file relation resolver/linker.
///
/// After all files in a workspace have been indexed, this takes unresolved
/// relations (calls, imports with entity names) and matches them against
/// the full set of parsed files to create actual EntityId-based relations.
pub struct CrossFileLinker;

/// Unresolved relation with string-based references (before entity ID lookup).
#[derive(Debug, Clone)]
pub struct UnresolvedRelation {
    pub kind: RelationKind,
    pub src_entity_id: EntityId,
    pub dst_name: String,
}

/// Data for a single parsed file, used for cross-file linking.
#[derive(Debug)]
pub struct FileParseData {
    /// Relative file path (e.g., "src/app/api/chat/route.ts").
    pub file_path: String,
    /// Entities with IDs already assigned.
    pub entities: Vec<Entity>,
    /// Unresolved name-based relations from this file.
    pub relations: Vec<ExtractedRelation>,
    /// Import declarations from this file.
    pub imports: Vec<FileImport>,
}

/// Parsed file data plus parser-emitted tests.
///
/// This is a plumbing-only carrier for ingestion paths that want to retain
/// parser test metadata while still linking with the existing `FileParseData`
/// projection.
#[derive(Debug, Clone)]
pub struct FileParseDataWithTests {
    pub file_path: String,
    pub entities: Vec<Entity>,
    pub relations: Vec<ExtractedRelation>,
    pub imports: Vec<FileImport>,
    pub tests: Vec<kin_parser::ExtractedTest>,
}

impl FileParseDataWithTests {
    pub fn into_linkable(self) -> FileParseData {
        FileParseData {
            file_path: self.file_path,
            entities: self.entities,
            relations: self.relations,
            imports: self.imports,
        }
    }
}

/// Extensions to try when resolving a bare module path.
const MODULE_EXTENSIONS: &[&str] = &[
    "ts", "tsx", "js", "jsx", "py", "rs", "go", "h", "hh", "hpp", "hxx",
];

/// Index filenames to try when resolving a directory module path.
const INDEX_FILENAMES: &[&str] = &["index.ts", "index.tsx", "index.js", "index.jsx", "mod.rs"];

/// Resolve cross-file relations across all parsed files.
///
/// This function:
/// 1. Builds entity indices (by file+name and by name alone)
/// 2. Builds an import map (local_name -> source module + original name)
/// 3. Resolves module paths to actual file paths
/// 4. Resolves each ExtractedRelation to entity-ID-based Relations
///
/// Returns a deduplicated list of resolved Relations.
pub fn link_cross_file(files: &[FileParseData]) -> Vec<Relation> {
    let _span = tracing::info_span!("kin.index.link_cross_file", files = files.len()).entered();
    let universe_entities: Vec<Entity> = files
        .iter()
        .flat_map(|file| file.entities.iter().cloned())
        .collect();
    link_cross_file_against_entities(files, &universe_entities)
}

/// Resolve cross-file relations while carrying parser-emitted tests alongside the input.
pub fn link_cross_file_with_tests(files: &[FileParseDataWithTests]) -> Vec<Relation> {
    let linkable: Vec<FileParseData> = files
        .iter()
        .map(|file| FileParseData {
            file_path: file.file_path.clone(),
            entities: file.entities.clone(),
            relations: file.relations.clone(),
            imports: file.imports.clone(),
        })
        .collect();
    link_cross_file(&linkable)
}

/// Total order over entities so cross-file linking is order-independent.
fn entity_link_order(a: &Entity, b: &Entity) -> std::cmp::Ordering {
    let file_a = a.file_origin.as_ref().map(|f| f.0.as_str()).unwrap_or("");
    let file_b = b.file_origin.as_ref().map(|f| f.0.as_str()).unwrap_or("");
    let line_a = a.span.as_ref().map(|s| s.start_line).unwrap_or(u32::MAX);
    let line_b = b.span.as_ref().map(|s| s.start_line).unwrap_or(u32::MAX);
    let col_a = a.span.as_ref().map(|s| s.start_col).unwrap_or(u32::MAX);
    let col_b = b.span.as_ref().map(|s| s.start_col).unwrap_or(u32::MAX);
    file_a
        .cmp(file_b)
        .then_with(|| line_a.cmp(&line_b))
        .then_with(|| col_a.cmp(&col_b))
        .then_with(|| a.name.cmp(&b.name))
        .then_with(|| a.id.0.cmp(&b.id.0))
}

/// The bare (unqualified) leaf of an entity name: the part after the final
/// `::` or `.` separator, or the whole name when it carries no qualifier.
///
/// Shared by the batch [`link_cross_file`] entity index and the
/// [`IncrementalLinker`] bare-name index so both derive receiver-method leaf
/// names identically — a divergence here would resolve the same call to
/// different entities across the two linkers.
fn bare_entity_name(name: &str) -> &str {
    match name.rfind("::") {
        Some(idx) => &name[idx + 2..],
        None => match name.rfind('.') {
            Some(idx) => &name[idx + 1..],
            None => name,
        },
    }
}

/// Resolve cross-file relations for `files` against a broader target universe.
///
/// This is used by warm/incremental indexing paths where only a subset of files
/// are reparsed, but those reparsed files still need to reconnect to unchanged
/// entities elsewhere in the graph.
///
/// `universe_entities` must include the entities from `files`.
pub fn link_cross_file_against_entities(
    files: &[FileParseData],
    universe_entities: &[Entity],
) -> Vec<Relation> {
    let _span = tracing::info_span!(
        "kin.index.link_cross_file_against_entities",
        files = files.len(),
        universe_entities = universe_entities.len()
    )
    .entered();

    let ctx = build_link_context(files, universe_entities);

    let total_files = files.len();
    let progress_interval = std::cmp::max(total_files / 50, 1);
    let link_start = std::time::Instant::now();

    // Resolve each file independently: every relation's source entity is owned
    // by its own file, so the (src, dst, kind) triples produced by different
    // files never collide. Per-file resolution carries its own dedup state and
    // is therefore order-independent; results are collected in input-file order
    // (`par_iter().collect()` preserves order) and merged serially below so the
    // materialized relation set and ordering are identical to a serial pass.
    let per_file_relations: Vec<Vec<Relation>> = {
        let _span = tracing::info_span!(
            "kin.index.link_cross_file.resolve_relations",
            files = files.len()
        )
        .entered();
        let completed = AtomicUsize::new(0);
        let found = AtomicUsize::new(0);
        files
            .par_iter()
            .map(|file| {
                let relations = resolve_one_file(file, &ctx);
                if total_files > 50 {
                    let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    let total =
                        found.fetch_add(relations.len(), Ordering::Relaxed) + relations.len();
                    if done % progress_interval == 0 || done == total_files {
                        eprint!(
                            "\r  Linking: [{}/{}] {}% | {} relations | {:.1}s",
                            done,
                            total_files,
                            (done * 100) / total_files,
                            total,
                            link_start.elapsed().as_secs_f64()
                        );
                    }
                }
                relations
            })
            .collect()
    };

    let resolved = merge_resolved(per_file_relations, files, &ctx);

    if total_files > 0 {
        eprintln!(); // newline after \r progress
    }
    debug!(resolved = resolved.len(), "cross-file linking complete");
    resolved
}

/// Read-only indices shared across per-file relation resolution.
struct LinkContext<'a> {
    sorted_universe: Vec<&'a Entity>,
    entity_by_file_name: HashMap<(&'a str, &'a str), EntityId>,
    entity_by_name: HashMap<&'a str, Vec<(&'a str, EntityId)>>,
    entity_by_bare_name: HashMap<&'a str, Vec<(&'a str, EntityId)>>,
    entity_kind_by_id: HashMap<EntityId, EntityKind>,
    entity_count_by_file: HashMap<&'a str, usize>,
    known_files: HashSet<&'a str>,
    import_map: HashMap<&'a str, HashMap<&'a str, (&'a str, &'a str)>>,
    include_graph: HashMap<String, Vec<String>>,
}

fn build_link_context<'a>(
    files: &'a [FileParseData],
    universe_entities: &'a [Entity],
) -> LinkContext<'a> {
    // Sort for deterministic relation materialization.
    let sorted_universe: Vec<&Entity> = {
        let mut sorted: Vec<&Entity> = universe_entities.iter().collect();
        sorted.sort_by(|a, b| entity_link_order(a, b));
        sorted
    };
    // Step 1: Build entity indices
    //   (file_path, entity_name) -> EntityId
    let (
        entity_by_file_name,
        entity_by_name,
        entity_by_bare_name,
        entity_kind_by_id,
        entity_count_by_file,
        known_files,
    ) = {
        let _span = tracing::info_span!(
            "kin.index.link_cross_file.build_entity_indices",
            universe_entities = sorted_universe.len()
        )
        .entered();
        let mut entity_by_file_name: HashMap<(&str, &str), EntityId> = HashMap::new();
        let mut entity_by_name: HashMap<&str, Vec<(&str, EntityId)>> = HashMap::new();
        let mut entity_by_bare_name: HashMap<&str, Vec<(&str, EntityId)>> = HashMap::new();
        let mut entity_kind_by_id: HashMap<EntityId, EntityKind> = HashMap::new();
        let mut entity_count_by_file: HashMap<&str, usize> = HashMap::new();
        let mut known_files: HashSet<&str> = HashSet::new();

        for &entity in &sorted_universe {
            entity_kind_by_id.insert(entity.id, entity.kind);
            let Some(file_path) = entity.file_origin.as_ref().map(|path| path.0.as_str()) else {
                continue;
            };
            known_files.insert(file_path);
            *entity_count_by_file.entry(file_path).or_insert(0) += 1;
            entity_by_file_name.insert((file_path, &entity.name), entity.id);
            entity_by_name
                .entry(&*entity.name)
                .or_default()
                .push((file_path, entity.id));

            let bare_name = bare_entity_name(&entity.name);
            if bare_name != entity.name {
                entity_by_bare_name
                    .entry(bare_name)
                    .or_default()
                    .push((file_path, entity.id));
            }
        }

        for file in files {
            known_files.insert(&file.file_path);
        }

        (
            entity_by_file_name,
            entity_by_name,
            entity_by_bare_name,
            entity_kind_by_id,
            entity_count_by_file,
            known_files,
        )
    };

    // Step 2: Build import map per file
    //   file_path -> { local_name -> (module_path, original_name) }
    let import_map: HashMap<&str, HashMap<&str, (&str, &str)>> = {
        let _span = tracing::info_span!(
            "kin.index.link_cross_file.build_import_map",
            files = files.len()
        )
        .entered();
        let mut import_map: HashMap<&str, HashMap<&str, (&str, &str)>> = HashMap::new();
        for file in files {
            let mut file_imports: HashMap<&str, (&str, &str)> = HashMap::new();
            for imp in &file.imports {
                for spec in &imp.specifiers {
                    let original = spec.original_name.as_deref().unwrap_or(&spec.local_name);
                    file_imports.insert(&spec.local_name, (&imp.module_path, original));
                }
            }
            if !file_imports.is_empty() {
                import_map.insert(&file.file_path, file_imports);
            }
        }
        import_map
    };

    let include_graph = build_include_graph(files, &known_files);

    LinkContext {
        sorted_universe,
        entity_by_file_name,
        entity_by_name,
        entity_by_bare_name,
        entity_kind_by_id,
        entity_count_by_file,
        known_files,
        import_map,
        include_graph,
    }
}

/// Resolve the name-based relations of a single file into entity-ID relations.
///
/// All reads are against the shared read-only [`LinkContext`]; the only mutable
/// state is a file-local dedup set, so this is pure with respect to other files.
fn resolve_one_file(file: &FileParseData, ctx: &LinkContext<'_>) -> Vec<Relation> {
    let mut resolved = Vec::new();
    let mut seen: HashSet<(EntityId, EntityId, RelationKind)> = HashSet::new();
    // Lazily resolved once per file: only ambiguous name buckets need them.
    let mut caller_import_targets: Option<HashSet<String>> = None;
    let mut caller_include_closure: Option<HashMap<String, usize>> = None;

    for rel in &file.relations {
        let src_id = ctx
            .entity_by_file_name
            .get(&(file.file_path.as_str(), rel.src_name.as_str()));
        let dst_same_file = ctx
            .entity_by_file_name
            .get(&(file.file_path.as_str(), rel.dst_name.as_str()));

        let src_id = match src_id {
            Some(id) => *id,
            None => {
                debug!(
                    src = %rel.src_name,
                    dst = %rel.dst_name,
                    file = %file.file_path,
                    "linker: src entity not found, skipping"
                );
                continue;
            }
        };

        if rel.kind == RelationKind::UsesMacro {
            if let Some(&dst_id) = dst_same_file {
                if ctx.entity_kind_by_id.get(&dst_id) == Some(&EntityKind::Macro) {
                    if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                        resolved.push(make_relation(rel.kind, src_id, dst_id, 1.0));
                    }
                    continue;
                }
            }

            if let Some(dst_id) = resolve_reachable_macro_target(
                &file.file_path,
                &rel.dst_name,
                &ctx.include_graph,
                &ctx.entity_by_file_name,
                &ctx.entity_kind_by_id,
            ) {
                if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                    resolved.push(make_relation(rel.kind, src_id, dst_id, 0.95));
                }
                continue;
            }

            debug!(
                src = %rel.src_name,
                dst = %rel.dst_name,
                file = %file.file_path,
                "linker: macro use unresolved through same-file/include closure"
            );
            continue;
        }

        // (a) Same-file resolution
        if let Some(&dst_id) = dst_same_file {
            if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                resolved.push(make_relation(rel.kind, src_id, dst_id, 1.0));
            }
            continue;
        }

        // (b) Import-based cross-file resolution
        if let Some(file_imports) = ctx.import_map.get(file.file_path.as_str()) {
            if let Some(&(module_path, original_name)) = file_imports.get(rel.dst_name.as_str()) {
                if let Some(target_file) =
                    resolve_module_path(&file.file_path, module_path, &ctx.known_files)
                {
                    let direct = ctx
                        .entity_by_file_name
                        .get(&(target_file.as_str(), original_name))
                        .copied();
                    let dst_id = if direct.is_some() {
                        direct
                    } else if original_name == "default" {
                        // Default import: fall back to first entity in target file
                        resolve_default_export(&target_file, &ctx.sorted_universe)
                    } else {
                        None
                    };
                    if let Some(dst_id) = dst_id {
                        if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                            resolved.push(make_relation(rel.kind, src_id, dst_id, 0.95));
                        }
                        continue;
                    }
                }
            }

            // (b2) Namespace/package import member resolution:
            //   JS/TS: `util.finalizeIssue` via `import * as util from "./util"`
            //   Go:    `create.NewCmdCreate` via `import "github.com/.../create"`
            if let Some((import_name, member_name)) = split_member_access(rel.dst_name.as_str()) {
                if let Some(&(module_path, _original_name)) = file_imports.get(import_name) {
                    // Try resolving module path and looking up the member
                    if let Some(target_file) =
                        resolve_module_path(&file.file_path, module_path, &ctx.known_files)
                    {
                        if let Some(&dst_id) = ctx
                            .entity_by_file_name
                            .get(&(target_file.as_str(), member_name))
                        {
                            if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                                resolved.push(make_relation(rel.kind, src_id, dst_id, 0.9));
                            }
                            continue;
                        }
                    }
                }
            }
        }

        let exact_candidates = ctx
            .entity_by_name
            .get(rel.dst_name.as_str())
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        let other_file_candidates: Vec<(&str, EntityId)> = exact_candidates
            .iter()
            .filter(|(fp, _)| *fp != file.file_path.as_str())
            .map(|&(fp, id)| (fp, id))
            .collect();

        // (b3) Parser-pinned import resolution: the relation carries the module
        // its callee was imported from. A pinned callee must resolve inside
        // that module (or its package directory) — never through the global
        // name bucket, whose order is residency-accidental.
        let mut name_fallback_allowed = true;
        match resolve_import_pinned_target(
            rel,
            &file.file_path,
            &ctx.known_files,
            |target_file, name| ctx.entity_by_file_name.get(&(target_file, name)).copied(),
            &other_file_candidates,
        ) {
            ImportPinnedTarget::Resolved(dst_id) => {
                if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                    resolved.push(make_relation(
                        rel.kind,
                        src_id,
                        dst_id,
                        IMPORT_PINNED_CONFIDENCE,
                    ));
                }
                continue;
            }
            ImportPinnedTarget::PinnedMiss => name_fallback_allowed = false,
            ImportPinnedTarget::NoPin => {}
        }

        // (c) Global name-match fallback
        let bare_candidates = if rel.kind == RelationKind::Calls {
            ctx.entity_by_bare_name
                .get(rel.dst_name.as_str())
                .map(|v| v.as_slice())
                .unwrap_or(&[])
        } else {
            &[]
        };

        let mut linked = false;

        if name_fallback_allowed && !other_file_candidates.is_empty() {
            let distinct_ids: HashSet<EntityId> =
                other_file_candidates.iter().map(|&(_, id)| id).collect();
            let (dst_id, confidence) = if distinct_ids.len() == 1 {
                (other_file_candidates[0].1, 0.7)
            } else {
                let targets = caller_import_targets.get_or_insert_with(|| {
                    resolve_caller_import_targets(&file.file_path, &file.imports, &ctx.known_files)
                });
                let closure = caller_include_closure.get_or_insert_with(|| {
                    include_closure_depths(&file.file_path, &ctx.include_graph)
                });
                match disambiguate_same_name_candidates(
                    &file.file_path,
                    targets,
                    closure,
                    &other_file_candidates,
                    |path| ctx.entity_count_by_file.get(path).copied().unwrap_or(0),
                ) {
                    Some(dst_id) => (dst_id, LOCALITY_DISAMBIGUATED_CONFIDENCE),
                    // No locality signal: keep the historical bucket-order
                    // pick so signal-less repos do not lose existing edges.
                    None => (other_file_candidates[0].1, 0.7),
                }
            };
            if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                resolved.push(make_relation(rel.kind, src_id, dst_id, confidence));
                linked = true;
            }
        }

        // (c2) Receiver-method calls (`x.method()`) arrive as the bare method
        // name and never match (b)'s `Type::method` key. Resolve them through
        // the bare-name index only when unambiguous — exactly one method of
        // that name in another file. Ambiguous names (`new`, `run`, `get`) have
        // an unknowable receiver type, so linking every candidate would mint
        // spurious callers; leave those to the inconclusive-absence gate.
        if name_fallback_allowed && !linked && !bare_candidates.is_empty() {
            let mut distinct_targets: HashSet<EntityId> = HashSet::new();
            for &(fp, dst_id) in bare_candidates {
                if fp != file.file_path.as_str() {
                    distinct_targets.insert(dst_id);
                }
            }
            if distinct_targets.len() == 1 {
                let dst_id = *distinct_targets.iter().next().expect("len checked == 1");
                if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                    resolved.push(make_relation(rel.kind, src_id, dst_id, 0.3));
                    linked = true;
                }
            }
        }

        // (c3) Path-qualified calls (`crate::mod::func`, `Type::method`,
        // `alias::Type::method`) arrive with the full lexical path as `dst_name`
        // and no import source, so they miss (a)/(b) and the exact/bare indices
        // in (c)/(c2). Reduce the path to its resolvable suffixes and link only
        // an unambiguous single target in another file — idiomatic qualified
        // Rust would otherwise leave callers uncounted in refs/impact.
        if name_fallback_allowed
            && !linked
            && matches!(rel.kind, RelationKind::Calls | RelationKind::References)
        {
            if let Some(dst_id) =
                resolve_qualified_suffix(rel.dst_name.as_str(), file.file_path.as_str(), ctx)
            {
                if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                    resolved.push(make_relation(
                        rel.kind,
                        src_id,
                        dst_id,
                        QUALIFIED_SUFFIX_CONFIDENCE,
                    ));
                    linked = true;
                }
            }
        }

        if linked {
            continue;
        }

        // (d) Cross-repo external reference: the target is not in this repo's
        // parse universe, but the parser recorded an external module it was
        // imported from. Preserve it as an inferred edge carrying the imported
        // symbol and source so the spine cross-repo resolver can match it
        // against a sibling repo. Drops to the unresolved log below when no
        // external import source/symbol is available.
        if let Some(external) =
            make_external_reference_relation(rel, src_id, &file.file_path, &ctx.known_files)
        {
            if let GraphNodeId::Entity(dst_id) = external.dst {
                if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                    resolved.push(external);
                }
            }
            continue;
        }

        debug!(
            src = %rel.src_name,
            dst = %rel.dst_name,
            file = %file.file_path,
            kind = ?rel.kind,
            "linker: cross-file relation unresolved"
        );
    }

    resolved
}

/// Merge per-file resolved relations in input-file order, deduplicating across
/// files (a no-op when sources are disjoint, but kept so output is identical to
/// a single serial pass), then append artifact-level import/include edges.
fn merge_resolved(
    per_file_relations: Vec<Vec<Relation>>,
    files: &[FileParseData],
    ctx: &LinkContext<'_>,
) -> Vec<Relation> {
    let mut resolved = Vec::new();
    let mut seen: HashSet<(GraphNodeId, GraphNodeId, RelationKind)> = HashSet::new();
    for file_relations in per_file_relations {
        for rel in file_relations {
            if seen.insert((rel.src, rel.dst, rel.kind)) {
                resolved.push(rel);
            }
        }
    }

    // Step 4: Create artifact-level import/include edges from import declarations.
    //
    // Import/include syntax belongs to the file/module surface. Do not anchor it
    // to an arbitrary "first entity" in the file; that makes the graph lie about
    // which symbol owns the dependency and drops files with no parsed entities.
    //
    // Edge construction resolves each import's module path (which can scan the
    // whole `known_files` set), so per-file candidates are built in parallel and
    // collected in input order. The cross-file dedup then runs serially over that
    // ordered set, so the appended edges — and their order — match a serial pass.
    let mut seen_artifact: HashSet<(GraphNodeId, GraphNodeId, RelationKind)> = HashSet::new();
    {
        let _span = tracing::info_span!(
            "kin.index.link_cross_file.build_import_edges",
            files = files.len()
        )
        .entered();
        let per_file_artifact: Vec<Vec<Relation>> = files
            .par_iter()
            .map(|file| {
                file.imports
                    .iter()
                    .filter_map(|imp| {
                        make_artifact_import_relation(&file.file_path, imp, &ctx.known_files)
                    })
                    .collect()
            })
            .collect();
        for file_relations in per_file_artifact {
            for rel in file_relations {
                let key = (rel.src, rel.dst, rel.kind);
                if seen_artifact.insert(key) {
                    resolved.push(rel);
                }
            }
        }
    }

    resolved
}

/// Serial counterpart of [`link_cross_file_against_entities`], retained as the
/// byte-identical reference for the parallel resolution path.
#[cfg(test)]
fn link_cross_file_against_entities_serial(
    files: &[FileParseData],
    universe_entities: &[Entity],
) -> Vec<Relation> {
    let ctx = build_link_context(files, universe_entities);
    let per_file_relations: Vec<Vec<Relation>> = files
        .iter()
        .map(|file| resolve_one_file(file, &ctx))
        .collect();
    merge_resolved(per_file_relations, files, &ctx)
}

/// Serial counterpart of [`build_include_graph`], retained as the byte-identical
/// reference for the parallel include-graph construction.
#[cfg(test)]
fn build_include_graph_serial<S>(
    files: &[FileParseData],
    known_files: &HashSet<S>,
) -> HashMap<String, Vec<String>>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let mut include_graph: HashMap<String, Vec<String>> = HashMap::new();
    for file in files {
        for import in &file.imports {
            let Some(resolved_path) =
                resolve_module_path(&file.file_path, &import.module_path, known_files)
            else {
                continue;
            };
            if is_include_like_path(&import.module_path) || is_include_like_path(&resolved_path) {
                include_graph
                    .entry(file.file_path.clone())
                    .or_default()
                    .push(resolved_path);
            }
        }
    }
    for targets in include_graph.values_mut() {
        targets.sort();
        targets.dedup();
    }
    include_graph
}

/// Serial counterpart of the artifact-edge construction in [`merge_resolved`],
/// retained as the byte-identical reference for the parallel edge pass.
#[cfg(test)]
fn merge_resolved_serial(
    per_file_relations: Vec<Vec<Relation>>,
    files: &[FileParseData],
    ctx: &LinkContext<'_>,
) -> Vec<Relation> {
    let mut resolved = Vec::new();
    let mut seen: HashSet<(GraphNodeId, GraphNodeId, RelationKind)> = HashSet::new();
    for file_relations in per_file_relations {
        for rel in file_relations {
            if seen.insert((rel.src, rel.dst, rel.kind)) {
                resolved.push(rel);
            }
        }
    }
    let mut seen_artifact: HashSet<(GraphNodeId, GraphNodeId, RelationKind)> = HashSet::new();
    for file in files {
        for imp in &file.imports {
            if let Some(rel) = make_artifact_import_relation(&file.file_path, imp, &ctx.known_files)
            {
                let key = (rel.src, rel.dst, rel.kind);
                if seen_artifact.insert(key) {
                    resolved.push(rel);
                }
            }
        }
    }
    resolved
}

/// Resolve the include-like import targets of one file, sorted and deduped.
///
/// Shared by batch include-graph construction and the incremental linker's
/// persistent per-file include state so both record identical edges.
fn resolve_include_targets<S>(
    file_path: &str,
    imports: &[FileImport],
    known_files: &HashSet<S>,
) -> Vec<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let mut targets = Vec::new();
    for import in imports {
        let Some(resolved_path) = resolve_module_path(file_path, &import.module_path, known_files)
        else {
            continue;
        };
        if is_include_like_path(&import.module_path) || is_include_like_path(&resolved_path) {
            targets.push(resolved_path);
        }
    }
    targets.sort();
    targets.dedup();
    targets
}

fn build_include_graph<S>(
    files: &[FileParseData],
    known_files: &HashSet<S>,
) -> HashMap<String, Vec<String>>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq + Sync,
{
    // Each file's include targets are resolved independently, and module-path
    // resolution can scan the entire `known_files` set, so this is the heavy
    // part of include-graph construction. Resolve per file in parallel, collect
    // in input order, then fold into the map serially so the result is identical
    // to a sequential pass (entries are keyed by file path; the final per-target
    // sort/dedup makes within-entry order independent of scheduling anyway).
    let per_file: Vec<(String, Vec<String>)> = files
        .par_iter()
        .filter_map(|file| {
            let targets = resolve_include_targets(&file.file_path, &file.imports, known_files);
            if targets.is_empty() {
                None
            } else {
                Some((file.file_path.clone(), targets))
            }
        })
        .collect();

    let mut include_graph: HashMap<String, Vec<String>> = HashMap::new();
    for (file_path, targets) in per_file {
        include_graph.entry(file_path).or_default().extend(targets);
    }
    for targets in include_graph.values_mut() {
        targets.sort();
        targets.dedup();
    }
    include_graph
}

fn is_include_like_path(path: &str) -> bool {
    is_header_like_module_path(path)
}

fn reachable_include_files(
    importer_file: &str,
    include_graph: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut stack = include_graph
        .get(importer_file)
        .cloned()
        .unwrap_or_default();

    while let Some(path) = stack.pop() {
        if !seen.insert(path.clone()) {
            continue;
        }
        if let Some(next) = include_graph.get(&path) {
            stack.extend(next.iter().cloned());
        }
    }

    let mut reachable = seen.into_iter().collect::<Vec<_>>();
    reachable.sort();
    reachable
}

/// Depth bound for include-closure traversal. Real header trees stay well
/// inside this; the bound keeps closure construction linear on pathological
/// include chains.
const INCLUDE_CLOSURE_MAX_DEPTH: usize = 16;

/// Files reachable through the caller's include edges, keyed by resolved path
/// with the shortest include distance (1 = directly included).
///
/// The walk is level-by-level, so every recorded depth is minimal regardless
/// of visit order within a level, and cycles terminate on the visited check.
fn include_closure_depths(
    caller_file: &str,
    include_graph: &HashMap<String, Vec<String>>,
) -> HashMap<String, usize> {
    let mut depth_by_file: HashMap<String, usize> = HashMap::new();
    let mut frontier: Vec<String> = include_graph.get(caller_file).cloned().unwrap_or_default();
    let mut depth = 1usize;
    while !frontier.is_empty() && depth <= INCLUDE_CLOSURE_MAX_DEPTH {
        let mut next = Vec::new();
        for path in frontier {
            if depth_by_file.contains_key(&path) || path == caller_file {
                continue;
            }
            if let Some(targets) = include_graph.get(&path) {
                next.extend(targets.iter().cloned());
            }
            depth_by_file.insert(path, depth);
        }
        frontier = next;
        depth += 1;
    }
    depth_by_file
}

fn resolve_reachable_macro_target<'a>(
    importer_file: &str,
    macro_name: &str,
    include_graph: &HashMap<String, Vec<String>>,
    entity_by_file_name: &HashMap<(&'a str, &'a str), EntityId>,
    entity_kind_by_id: &HashMap<EntityId, EntityKind>,
) -> Option<EntityId> {
    for include_file in reachable_include_files(importer_file, include_graph) {
        let Some(&candidate_id) = entity_by_file_name.get(&(include_file.as_str(), macro_name))
        else {
            continue;
        };
        if entity_kind_by_id.get(&candidate_id) == Some(&EntityKind::Macro) {
            return Some(candidate_id);
        }
    }
    None
}

fn resolve_reachable_macro_target_incremental(
    importer_file: &str,
    macro_name: &str,
    include_graph: &HashMap<String, Vec<String>>,
    linker: &IncrementalLinker,
) -> Option<EntityId> {
    for include_file in reachable_include_files(importer_file, include_graph) {
        let Some(candidate_id) = linker
            .entity_by_file_name
            .get(&include_file)
            .and_then(|entities| entities.get(macro_name))
            .copied()
        else {
            continue;
        };
        if linker.entity_kind_by_id.get(&candidate_id) == Some(&EntityKind::Macro) {
            return Some(candidate_id);
        }
    }
    None
}

/// Try to insert a (src, dst, kind) triple; returns true if it was new.
fn add_deduped(
    seen: &mut HashSet<(EntityId, EntityId, RelationKind)>,
    src: EntityId,
    dst: EntityId,
    kind: RelationKind,
) -> bool {
    seen.insert((src, dst, kind))
}

/// Split a dotted member access like `util.finalizeIssue` into the import alias (`util`)
/// and the leaf member name (`finalizeIssue`).
fn split_member_access(name: &str) -> Option<(&str, &str)> {
    let prefix = name.split('.').next()?;
    let leaf = name.rsplit('.').next()?;
    if prefix == name || leaf == name || prefix.is_empty() || leaf.is_empty() {
        return None;
    }
    Some((prefix, leaf))
}

/// Confidence for a call/reference edge resolved by reducing a path-qualified
/// callee (`crate::mod::func`, `Type::method`, `alias::Type::method`) to a unique
/// local entity via suffix matching. Inferred: the module/crate prefix is dropped
/// before matching, so it ranks below an import-verified edge (0.95) yet above the
/// ambiguous receiver-method guess (0.3) because the suffix match is required to
/// be unambiguous.
const QUALIFIED_SUFFIX_CONFIDENCE: f32 = 0.6;

/// Whether a `::`-path segment is a plain Rust identifier (`crate`, `self`,
/// `Widget`, `run`). Rejects generic/turbofish fragments (`<T>`, `run::<T>`) and
/// other non-identifier forms so suffix resolution never keys off a mangled
/// segment.
fn is_path_identifier(seg: &str) -> bool {
    let mut chars = seg.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_alphanumeric())
}

/// Collect the distinct target entity ids among `candidates` that live in a file
/// other than `current_file`.
fn distinct_cross_file_targets(
    candidates: Option<&Vec<(&str, EntityId)>>,
    current_file: &str,
    out: &mut HashSet<EntityId>,
) {
    if let Some(candidates) = candidates {
        for &(fp, id) in candidates {
            if fp != current_file {
                out.insert(id);
            }
        }
    }
}

/// Resolve a Rust-style path-qualified call/reference target to a unique local
/// entity by matching the path's resolvable suffixes against the entity indices.
///
/// The Rust adapter preserves the full lexical path written at the call site as
/// `dst_name` (`crate::work::run`, `Widget::make`, `crate::model::Widget::make`),
/// but entities are keyed by their *simple* name (free function `run`) or their
/// *type-qualified* name (method `Widget::make`). This reduces the path to the two
/// suffixes that can name a real entity:
///
///   1. the type-qualified suffix `Type::method` (the last two segments), which
///      pins the receiver type and resolves e.g. `crate::model::Widget::make`; and
///   2. the bare leaf `func`/`method`, which resolves a module-qualified free
///      function (`crate::work::run`) and receiver methods stored bare.
///
/// It links only when exactly one distinct target entity exists in a file other
/// than the caller's. Ambiguous suffixes (more than one distinct target) resolve
/// to `None` and are logged — a missing edge is preferred over a wrong one.
fn resolve_qualified_suffix(
    dst_name: &str,
    current_file: &str,
    ctx: &LinkContext<'_>,
) -> Option<EntityId> {
    let segments: Vec<&str> = dst_name.split("::").collect();
    // Must be a genuine `::` path of identifier-like segments. Rejects bare names
    // (handled by (c)/(c2)), leading/trailing `::`, and turbofish/exotic forms.
    if segments.len() < 2 || !segments.iter().all(|s| is_path_identifier(s)) {
        return None;
    }
    let last = segments[segments.len() - 1];

    // Tier 1: type-qualified suffix `Penult::last` against the full-name index.
    // Resolves a method reached through a module/crate prefix. If this pinned
    // suffix is itself ambiguous, stop — widening to the bare leaf would be less
    // precise, not more.
    let type_qualified = format!("{}::{}", segments[segments.len() - 2], last);
    let mut tq_targets: HashSet<EntityId> = HashSet::new();
    distinct_cross_file_targets(
        ctx.entity_by_name.get(type_qualified.as_str()),
        current_file,
        &mut tq_targets,
    );
    match tq_targets.len() {
        1 => return tq_targets.into_iter().next(),
        n if n > 1 => {
            debug!(
                dst = %dst_name,
                suffix = %type_qualified,
                count = n,
                "linker: ambiguous type-qualified suffix, leaving unresolved"
            );
            return None;
        }
        _ => {}
    }

    // Tier 2: bare leaf. Free functions live in `entity_by_name` under `last`;
    // methods live in `entity_by_bare_name` under `last`. Union both and require
    // a single distinct target.
    let mut leaf_targets: HashSet<EntityId> = HashSet::new();
    distinct_cross_file_targets(
        ctx.entity_by_name.get(last),
        current_file,
        &mut leaf_targets,
    );
    distinct_cross_file_targets(
        ctx.entity_by_bare_name.get(last),
        current_file,
        &mut leaf_targets,
    );
    match leaf_targets.len() {
        1 => leaf_targets.into_iter().next(),
        0 => None,
        n => {
            debug!(
                dst = %dst_name,
                leaf = %last,
                count = n,
                "linker: ambiguous qualified-call leaf, leaving unresolved"
            );
            None
        }
    }
}

/// Incremental-linker counterpart of [`resolve_qualified_suffix`]. The
/// incremental index keys entities by their owned simple name and carries no
/// bare-name index, so only the type-qualified suffix (`Type::method`) and the
/// bare leaf free-function name are matched; ambiguous suffixes stay unresolved.
fn resolve_qualified_suffix_incremental(
    dst_name: &str,
    current_file: &str,
    linker: &IncrementalLinker,
) -> Option<EntityId> {
    let segments: Vec<&str> = dst_name.split("::").collect();
    if segments.len() < 2 || !segments.iter().all(|s| is_path_identifier(s)) {
        return None;
    }
    let last = segments[segments.len() - 1];

    // Tier 1: type-qualified suffix `Penult::last`.
    let type_qualified = format!("{}::{}", segments[segments.len() - 2], last);
    let mut tq_targets: HashSet<EntityId> = HashSet::new();
    if let Some(cands) = linker.entity_by_name.get(type_qualified.as_str()) {
        for (fp, id) in cands {
            if fp != current_file {
                tq_targets.insert(*id);
            }
        }
    }
    match tq_targets.len() {
        1 => return tq_targets.into_iter().next(),
        n if n > 1 => {
            debug!(
                dst = %dst_name,
                suffix = %type_qualified,
                count = n,
                "linker(incremental): ambiguous type-qualified suffix, leaving unresolved"
            );
            return None;
        }
        _ => {}
    }

    // Tier 2: bare leaf (free functions) resolved through `entity_by_name`. A
    // qualified path whose leaf is a receiver method (`Type::method`) is not in
    // `entity_by_name` under the bare leaf; those are resolved by the caller's
    // (c2) bare-name step via `entity_by_bare_name`, not here.
    let mut leaf_targets: HashSet<EntityId> = HashSet::new();
    if let Some(cands) = linker.entity_by_name.get(last) {
        for (fp, id) in cands {
            if fp != current_file {
                leaf_targets.insert(*id);
            }
        }
    }
    match leaf_targets.len() {
        1 => leaf_targets.into_iter().next(),
        0 => None,
        n => {
            debug!(
                dst = %dst_name,
                leaf = %last,
                count = n,
                "linker(incremental): ambiguous qualified-call leaf, leaving unresolved"
            );
            None
        }
    }
}

/// Directory component of a repo-relative path (`""` for top-level files).
fn parent_dir(path: &str) -> &str {
    match path.rfind('/') {
        Some(idx) => &path[..idx],
        None => "",
    }
}

/// Repo-local files reachable through the caller's own import/include
/// declarations, resolved with the same module-path resolution the artifact
/// import edges use. Used to disambiguate same-name candidates: a candidate
/// defined in a file the caller explicitly imports outranks one it never
/// references.
fn resolve_caller_import_targets<S>(
    caller_file: &str,
    imports: &[FileImport],
    known_files: &HashSet<S>,
) -> HashSet<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let mut targets = HashSet::new();
    for import in imports {
        if let Some(resolved) = resolve_module_path(caller_file, &import.module_path, known_files) {
            targets.insert(resolved);
        }
    }
    targets
}

/// Choose one target among same-name candidates that live in other files.
///
/// Tier 1: exactly one distinct target in the caller's own directory — the
/// same Go package, or a C-family sibling header/impl pair. Tier 2: exactly
/// one distinct target among the files the caller itself imports/includes.
/// Tier 3: exactly one distinct target among the files in the caller's
/// include closure — a C-family caller reaching a definition through an
/// umbrella header sees no direct-import signal, but the transitive include
/// walk pins the defining header.
///
/// When several closure candidates remain, the most *specific* defining file
/// wins: the file defining the fewest entities. An amalgamated single-include
/// bundles the whole library and so re-defines the symbol alongside thousands
/// of others, while the focused header that owns it defines a handful —
/// entity count identifies the authoritative definition site structurally,
/// without path heuristics. Nearness (minimal include depth) breaks ties only
/// between equally specific files: an umbrella is *nearer* by construction
/// (the caller includes it, it includes the focused header), so depth alone
/// would systematically prefer the bundle.
///
/// All tiers are count-based over entity-id sets and integer minima, so
/// bucket insertion order can never pick the winner. No unique winner →
/// `None`; the caller decides whether a legacy fallback applies.
fn disambiguate_same_name_candidates(
    caller_file: &str,
    caller_import_targets: &HashSet<String>,
    caller_include_closure: &HashMap<String, usize>,
    candidates: &[(&str, EntityId)],
    defined_entity_count: impl Fn(&str) -> usize,
) -> Option<EntityId> {
    let caller_dir = parent_dir(caller_file);
    let mut same_dir: HashSet<EntityId> = HashSet::new();
    for (candidate_file, candidate_id) in candidates {
        if parent_dir(candidate_file) == caller_dir {
            same_dir.insert(*candidate_id);
        }
    }
    if same_dir.len() == 1 {
        return same_dir.into_iter().next();
    }

    let mut imported: HashSet<EntityId> = HashSet::new();
    for (candidate_file, candidate_id) in candidates {
        if caller_import_targets.contains(*candidate_file) {
            imported.insert(*candidate_id);
        }
    }
    if imported.len() == 1 {
        return imported.into_iter().next();
    }

    // Tier 3: candidates whose defining file the caller (transitively)
    // includes, carried as (id, include depth, defining-file entity count).
    let mut in_closure: Vec<(EntityId, usize, usize)> = Vec::new();
    let mut closure_ids: HashSet<EntityId> = HashSet::new();
    for (candidate_file, candidate_id) in candidates {
        if let Some(&depth) = caller_include_closure.get(*candidate_file) {
            in_closure.push((*candidate_id, depth, defined_entity_count(candidate_file)));
            closure_ids.insert(*candidate_id);
        }
    }
    if closure_ids.len() == 1 {
        return closure_ids.into_iter().next();
    }
    if closure_ids.len() > 1 {
        let min_count = in_closure
            .iter()
            .map(|&(_, _, count)| count)
            .min()
            .expect("closure candidates checked non-empty");
        let specific: Vec<&(EntityId, usize, usize)> = in_closure
            .iter()
            .filter(|&&(_, _, count)| count == min_count)
            .collect();
        let specific_ids: HashSet<EntityId> = specific.iter().map(|&&(id, _, _)| id).collect();
        if specific_ids.len() == 1 {
            return specific_ids.into_iter().next();
        }
        let min_depth = specific
            .iter()
            .map(|&&(_, depth, _)| depth)
            .min()
            .expect("specific candidates checked non-empty");
        let nearest_ids: HashSet<EntityId> = specific
            .iter()
            .filter(|&&&(_, depth, _)| depth == min_depth)
            .map(|&&(id, _, _)| id)
            .collect();
        if nearest_ids.len() == 1 {
            return nearest_ids.into_iter().next();
        }
    }
    None
}

/// Outcome of resolving a relation through its parser-recorded import source.
enum ImportPinnedTarget {
    /// The pinned module resolved and names exactly one local target.
    Resolved(EntityId),
    /// The relation is pinned to a module — external, or local without the
    /// symbol — so name-global fallbacks must not run: binding a pinned callee
    /// to a same-named entity in an unrelated file mints a false consumer.
    PinnedMiss,
    /// The relation carries no import source; name-global tiers may run.
    NoPin,
}

/// Resolve a relation through `rel.import_source` — the module the parser saw
/// the callee imported from (`create.NewCmdCreate` arrives as dst `NewCmdCreate`
/// pinned to `github.com/.../pr/create`). Looks up the symbol in the resolved
/// module file first, then uniquely within that file's directory (a Go package
/// spans multiple files).
fn resolve_import_pinned_target<S>(
    rel: &ExtractedRelation,
    caller_file: &str,
    known_files: &HashSet<S>,
    lookup_in_file: impl Fn(&str, &str) -> Option<EntityId>,
    same_name_candidates: &[(&str, EntityId)],
) -> ImportPinnedTarget
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let Some(import_source) = rel
        .import_source
        .as_deref()
        .map(str::trim)
        .filter(|source| !source.is_empty())
    else {
        return ImportPinnedTarget::NoPin;
    };
    let Some(target_file) = resolve_module_path(caller_file, import_source, known_files) else {
        // Path-shaped module sources (`github.com/...`, `@scope/pkg`) that do
        // not resolve locally are external: the external reference tier owns
        // them, and a local name-match would be fabricated. Bare module names
        // (`helpers`, `django.db`) have ambiguous provenance when unresolved —
        // leave those to the name-global tiers rather than orphaning them.
        return if import_source.contains('/') {
            ImportPinnedTarget::PinnedMiss
        } else {
            ImportPinnedTarget::NoPin
        };
    };
    if let Some(dst_id) = lookup_in_file(&target_file, &rel.dst_name) {
        return ImportPinnedTarget::Resolved(dst_id);
    }
    let target_dir = parent_dir(&target_file);
    let mut in_target_dir: HashSet<EntityId> = HashSet::new();
    for (candidate_file, candidate_id) in same_name_candidates {
        if parent_dir(candidate_file) == target_dir {
            in_target_dir.insert(*candidate_id);
        }
    }
    if in_target_dir.len() == 1 {
        return ImportPinnedTarget::Resolved(
            in_target_dir.into_iter().next().expect("len checked == 1"),
        );
    }
    ImportPinnedTarget::PinnedMiss
}

/// Confidence for a target reached through the relation's own import source.
const IMPORT_PINNED_CONFIDENCE: f32 = 0.9;

/// Confidence for an ambiguous name bucket settled by locality (same
/// directory / caller-imported file) rather than a direct module hit.
const LOCALITY_DISAMBIGUATED_CONFIDENCE: f32 = 0.8;

/// Build a Relation with a deterministic ID derived from (src, dst, kind).
///
/// Using a stable ID ensures the same logical relation (A calls B) gets the
/// same RelationId across commits, preventing duplicate rows when the MERGE
/// query matches on `{rel_id: $rel_id}`.
fn make_relation(kind: RelationKind, src: EntityId, dst: EntityId, confidence: f32) -> Relation {
    let origin = if confidence >= 1.0 {
        RelationOrigin::Parsed
    } else {
        RelationOrigin::Inferred
    };

    // Deterministic RelationId from src+dst+kind
    let id = stable_relation_id(&src, &dst, &kind);

    Relation {
        id,
        kind,
        src: kin_model::GraphNodeId::Entity(src),
        dst: kin_model::GraphNodeId::Entity(dst),
        confidence,
        origin,
        created_in: None,
        import_source: None,
        evidence: Vec::new(),
    }
}

/// Confidence assigned to an unresolved cross-repo reference edge. The target
/// entity lives in another repository and is absent from this repo's parse
/// universe, so the edge is inferred until the spine cross-repo resolver matches
/// it against a registered sibling repo.
const EXTERNAL_REFERENCE_CONFIDENCE: f32 = 0.2;

/// Synthetic tag used to derive a deterministic, repo-stable id for an external
/// (cross-repo) reference target. It is never a real `EntityKind`, so the
/// derived id can never collide with a locally indexed entity.
const EXTERNAL_REFERENCE_KIND_TAG: &str = "ExternalReference";

/// Emit a cross-repo reference edge for a Calls/References relation that could
/// not be resolved to any local entity but carries a parser-provided import
/// source from a module that lives outside this repo.
///
/// The destination is a deterministic placeholder entity derived from the import
/// source and the called/imported symbol. It is intentionally absent from this
/// repo's entity set, which is exactly the signal the spine cross-repo resolver
/// keys on. The relation carries the lexical symbol as `evidence.token` and the
/// module hint as `import_source`, the two facts the resolver needs to match it
/// against a sibling repo. When the parser supplied no import source or no
/// symbol, no edge is emitted — the reference stays honestly unresolved rather
/// than fabricated.
///
/// An import whose module path resolves to a file in this repo is a local
/// import, not a cross-repo reference: a symbol that fails local resolution
/// there (e.g. a moved or deleted local definition) must not be mis-attributed
/// as an external edge. Only module sources that do not resolve locally qualify.
fn make_external_reference_relation<S>(
    rel: &ExtractedRelation,
    src: EntityId,
    importer_file: &str,
    known_files: &HashSet<S>,
) -> Option<Relation>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    if rel.kind != RelationKind::Calls && rel.kind != RelationKind::References {
        return None;
    }
    let import_source = rel
        .import_source
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    let symbol = rel.dst_name.trim();
    if symbol.is_empty() {
        return None;
    }
    if resolve_module_path(importer_file, import_source, known_files).is_some() {
        return None;
    }

    let dst = EntityId::from_content(import_source, symbol, EXTERNAL_REFERENCE_KIND_TAG, 0);
    let id = stable_relation_id(&src, &dst, &rel.kind);

    Some(Relation {
        id,
        kind: rel.kind,
        src: GraphNodeId::Entity(src),
        dst: GraphNodeId::Entity(dst),
        confidence: EXTERNAL_REFERENCE_CONFIDENCE,
        origin: RelationOrigin::Inferred,
        created_in: None,
        import_source: Some(import_source.to_string()),
        evidence: vec![RelationEvidence {
            token: Some(symbol.to_string()),
            parser_rule: Some("external_import_reference".to_string()),
            source_path: Some(import_source.to_string()),
            ..RelationEvidence::default()
        }],
    })
}

// Graph-less caller: the cross-file linker pipeline builds these artifact
// import/include edges purely from parse data (`FileParseData` + `known_files`)
// before any `GraphSnapshot`/`artifact_index` exists — its output is what the
// graph is later constructed from (commit/init/import/migrate/ref_view). There
// is no `artifact_index` to resolve graph-assigned IDs against here, so we keep
// the deterministic path derivation. This matches the canonical kin-db approach
// for index-time, snapshot-less artifact IDs (e.g. `ensure_artifact_id` /
// `build_artifact_indexes_from_paths`), which also stay path-derived.
fn make_artifact_import_relation<S>(
    importer_file: &str,
    import: &FileImport,
    known_files: &HashSet<S>,
) -> Option<Relation>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let resolved_path = resolve_module_path(importer_file, &import.module_path, known_files)?;
    let kind = if is_header_like_module_path(&import.module_path) {
        RelationKind::Includes
    } else {
        RelationKind::Imports
    };
    let src = GraphNodeId::Artifact(ArtifactId::seed_from_path(importer_file));
    let dst = GraphNodeId::Artifact(ArtifactId::seed_from_path(&resolved_path));
    let evidence = RelationEvidence {
        source_path: Some(import.module_path.clone()),
        resolved_path: Some(resolved_path.clone()),
        parser_rule: Some(
            match kind {
                RelationKind::Includes => "include_directive",
                _ => "import_declaration",
            }
            .to_string(),
        ),
        occurrence_count: 1,
        ..RelationEvidence::default()
    };
    Some(Relation {
        id: stable_relation_node_id(&src, &dst, &kind),
        kind,
        src,
        dst,
        confidence: 1.0,
        origin: RelationOrigin::Parsed,
        created_in: None,
        import_source: Some(import.module_path.clone()),
        evidence: vec![evidence],
    })
}

/// Build artifact-level provenance edges for generated projection files.
///
/// Amalgamated headers and generated bundles often retain their source-file
/// boundaries as commented include markers, e.g.
/// `// #include <nlohmann/detail/exceptions.hpp>`. These are not runtime/textual
/// includes, so they should not be modeled as [`RelationKind::Includes`].
/// Instead, they are projection provenance: generated artifact derives from
/// source artifact.
pub fn build_projection_derived_relations_for_file<S, F>(
    file_path: &str,
    source: &[u8],
    known_files: &HashSet<S>,
    artifact_id_for_path: F,
) -> Vec<Relation>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
    F: FnMut(&str) -> Option<ArtifactId>,
{
    let markers = extract_projection_source_markers(file_path, source);
    build_projection_derived_relations_from_markers(
        file_path,
        &markers,
        known_files,
        artifact_id_for_path,
    )
}

pub fn build_projection_derived_relations_from_markers<S, F>(
    file_path: &str,
    markers: &[String],
    known_files: &HashSet<S>,
    mut artifact_id_for_path: F,
) -> Vec<Relation>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
    F: FnMut(&str) -> Option<ArtifactId>,
{
    if markers.is_empty() {
        return Vec::new();
    }

    let Some(src_artifact_id) = artifact_id_for_path(file_path) else {
        return Vec::new();
    };
    let src = GraphNodeId::Artifact(src_artifact_id);

    let mut by_resolved_path: HashMap<String, (String, u32)> = HashMap::new();
    for marker in markers {
        let Some(resolved_path) = resolve_module_path(file_path, marker, known_files) else {
            continue;
        };
        if resolved_path == file_path {
            continue;
        }
        by_resolved_path
            .entry(resolved_path)
            .and_modify(|(_, count)| *count = count.saturating_add(1))
            .or_insert((marker.clone(), 1));
    }

    let mut resolved: Vec<(String, String, u32)> = by_resolved_path
        .into_iter()
        .map(|(resolved_path, (source_path, count))| (resolved_path, source_path, count))
        .collect();
    resolved.sort_by(|left, right| left.0.cmp(&right.0));

    let mut relations = Vec::new();
    for (resolved_path, source_path, occurrence_count) in resolved {
        let Some(dst_artifact_id) = artifact_id_for_path(&resolved_path) else {
            continue;
        };
        let dst = GraphNodeId::Artifact(dst_artifact_id);
        let evidence = RelationEvidence {
            parser_rule: Some("projection_include_marker".to_string()),
            token: Some("#include".to_string()),
            source_path: Some(source_path),
            resolved_path: Some(resolved_path),
            occurrence_count,
            ..RelationEvidence::default()
        };
        relations.push(Relation {
            id: stable_relation_node_id(&src, &dst, &RelationKind::DerivedFrom),
            kind: RelationKind::DerivedFrom,
            src,
            dst,
            confidence: 0.9,
            origin: RelationOrigin::Inferred,
            created_in: None,
            import_source: None,
            evidence: vec![evidence],
        });
    }

    relations
}

pub fn extract_projection_source_markers(file_path: &str, source: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };

    let mut seen = HashSet::new();
    let mut paths = Vec::new();
    for line in text.lines() {
        let Some(path) = commented_include_marker_path(line) else {
            continue;
        };
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    }

    if paths.is_empty() {
        return Vec::new();
    }

    if is_projection_artifact_path(file_path) || paths.len() >= 4 {
        paths
    } else {
        Vec::new()
    }
}

fn commented_include_marker_path(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let comment_body = if let Some(rest) = trimmed.strip_prefix("//") {
        rest.trim_start()
    } else if let Some(rest) = trimmed.strip_prefix("/*") {
        rest.trim_start_matches('*').trim_start()
    } else {
        return None;
    };

    let rest = comment_body.strip_prefix("#include")?.trim_start();
    let path = if let Some(rest) = rest.strip_prefix('<') {
        rest.split_once('>')?.0
    } else if let Some(rest) = rest.strip_prefix('"') {
        rest.split_once('"')?.0
    } else {
        return None;
    };

    let path = path.trim();
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

fn is_projection_artifact_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("single_include/")
        || lower.contains("/single_include/")
        || lower.contains("_amalgamation")
        || lower.contains("/amalgamated/")
        || lower.starts_with("generated/")
        || lower.contains("/generated/")
        || lower.starts_with("__generated__/")
        || lower.contains("/__generated__/")
        || lower.ends_with(".generated.ts")
        || lower.ends_with(".generated.rs")
}

/// Derive a deterministic RelationId from the (src, dst, kind) triple.
fn stable_relation_id(src: &EntityId, dst: &EntityId, kind: &RelationKind) -> RelationId {
    stable_relation_node_id(&GraphNodeId::Entity(*src), &GraphNodeId::Entity(*dst), kind)
}

fn stable_relation_node_id(
    src: &GraphNodeId,
    dst: &GraphNodeId,
    kind: &RelationKind,
) -> RelationId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-rel-v1:");
    hasher.update(src.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(dst.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(format!("{:?}", kind).as_bytes());
    let result = hasher.finalize();
    // Use first 16 bytes as UUID v4-shaped bytes for RelationId
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&result[..16]);
    RelationId::from_bytes(bytes)
}

/// Resolve a module path relative to the importing file's directory.
///
/// For relative paths like `./utils` or `../lib/foo`, tries multiple extensions
/// and index file patterns against the set of known file paths.
///
/// For non-relative (package) imports like `@vue/shared` or `@mui/utils/foo`,
/// uses monorepo heuristics to locate workspace packages under `packages/`.
fn resolve_module_path<S>(
    importer_path: &str,
    module_path: &str,
    known_files: &HashSet<S>,
) -> Option<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    if module_path.starts_with('.') {
        // Relative import resolution
        let importer = Path::new(importer_path);
        let importer_dir = importer.parent().unwrap_or(Path::new(""));

        let resolved = normalize_path(&importer_dir.join(module_path));
        let resolved_str = resolved.to_string_lossy();
        // Try direct match (module path already has extension)
        if known_files.contains(resolved_str.as_ref()) {
            return Some(resolved_str.into_owned());
        }

        // Try adding common extensions
        for ext in MODULE_EXTENSIONS {
            let candidate = format!("{}.{}", resolved_str, ext);
            if known_files.contains(candidate.as_str()) {
                return Some(candidate);
            }
        }

        // Try as directory with index file
        for index in INDEX_FILENAMES {
            let candidate = format!("{}/{}", resolved_str, index);
            if known_files.contains(candidate.as_str()) {
                return Some(candidate);
            }
        }

        None
    } else {
        // Non-relative import. Header includes are often written relative to an
        // include root (e.g. nlohmann/detail/foo.hpp) while known files carry
        // repo paths such as include/nlohmann/detail/foo.hpp.
        resolve_repo_local_header(module_path, known_files)
            // Package import — try monorepo heuristic resolution.
            .or_else(|| resolve_package_import(module_path, known_files))
            // Java package resolution: com.foo.bar.ClassName → src/main/java/com/foo/bar/ClassName.java
            .or_else(|| resolve_java_package_import(module_path, known_files))
            // Go module resolution: github.com/org/repo/v2/pkg/foo → pkg/foo/*.go
            .or_else(|| resolve_go_module_import(module_path, known_files))
    }
}

fn resolve_repo_local_header<S>(module_path: &str, known_files: &HashSet<S>) -> Option<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    if !is_header_like_module_path(module_path) {
        return None;
    }

    if known_files.contains(module_path) {
        return Some(module_path.to_string());
    }

    for prefix in ["include/", "src/", "lib/"] {
        let candidate = format!("{prefix}{module_path}");
        if known_files.contains(candidate.as_str()) {
            return Some(candidate);
        }
    }

    let suffix = format!("/{module_path}");
    // Pick the smallest match for stable resolution across HashSet order.
    let mut best: Option<&str> = None;
    for file in known_files.iter() {
        let file_str = file.borrow();
        if file_str.ends_with(&suffix) && best.is_none_or(|b| file_str < b) {
            best = Some(file_str);
        }
    }

    best.map(|s| s.to_string())
}

fn is_header_like_module_path(module_path: &str) -> bool {
    let lower = module_path.to_ascii_lowercase();
    matches!(lower.rsplit('.').next(), Some("h" | "hh" | "hpp" | "hxx"))
}

/// Resolve a non-relative package import using monorepo heuristics.
///
/// Handles scoped packages like `@vue/shared` and `@mui/utils/foo` by mapping
/// them to workspace directories under `packages/`.
///
/// Conventions tried:
/// - `@scope/pkg` → `packages/pkg/`, `packages/scope-pkg/`
/// - `@scope/pkg/subpath` → `packages/pkg/src/subpath/`, `packages/scope-pkg/src/subpath/`
/// - `pkg` (unscoped) → `packages/pkg/`
fn resolve_package_import<S>(module_path: &str, known_files: &HashSet<S>) -> Option<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let (pkg_name, subpath) = parse_package_import(module_path)?;

    // Generate candidate directory names for the package
    let dir_candidates = package_dir_candidates(&pkg_name);

    for dir_name in &dir_candidates {
        // Build candidate base paths under packages/
        let base_dirs = if subpath.is_empty() {
            // No subpath: try package root
            vec![
                format!("packages/{}/src", dir_name),
                format!("packages/{}", dir_name),
            ]
        } else {
            // Has subpath (e.g., `@mui/utils/generateUtilityClasses`)
            vec![
                format!("packages/{}/src/{}", dir_name, subpath),
                format!("packages/{}/{}", dir_name, subpath),
            ]
        };

        for base in &base_dirs {
            // Try with extensions
            for ext in MODULE_EXTENSIONS {
                let candidate = format!("{}.{}", base, ext);
                if known_files.contains(candidate.as_str()) {
                    return Some(candidate);
                }
            }
            // Try as directory with index file
            for index in INDEX_FILENAMES {
                let candidate = format!("{}/{}", base, index);
                if known_files.contains(candidate.as_str()) {
                    return Some(candidate);
                }
            }
        }
    }

    None
}

/// Resolve a Java fully-qualified package import to a file path.
///
/// Converts dot-separated Java packages to directory paths and tries common
/// Maven/Gradle source roots:
/// - `com.foo.bar.ClassName` → `src/main/java/com/foo/bar/ClassName.java`
/// - Also tries `src/test/java/...` and bare `com/foo/bar/ClassName.java`
fn resolve_java_package_import<S>(module_path: &str, known_files: &HashSet<S>) -> Option<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    // Must look like a Java package (contains dots, no slashes)
    if !module_path.contains('.') || module_path.contains('/') {
        return None;
    }
    // Convert dots to path separators
    let dir_path = module_path.replace('.', "/");

    // Try standard Maven/Gradle source roots
    let prefixes = [
        "src/main/java/",
        "src/test/java/",
        "src/main/groovy/",
        "src/test/groovy/",
        "", // bare path
    ];

    for prefix in &prefixes {
        let candidate = format!("{}{}.java", prefix, dir_path);
        if known_files.contains(candidate.as_str()) {
            return Some(candidate);
        }
        // Also try as Kotlin file
        let kt_candidate = format!("{}{}.kt", prefix, dir_path);
        if known_files.contains(kt_candidate.as_str()) {
            return Some(kt_candidate);
        }
    }

    // For multi-module projects (e.g., jib-core/src/main/java/...),
    // try each known file that ends with the class path
    let suffix = format!("{}.java", dir_path);
    // Pick the smallest match for stable resolution across HashSet order.
    let mut best: Option<&str> = None;
    for file in known_files.iter() {
        let file_str = file.borrow();
        if file_str.ends_with(&suffix) && best.is_none_or(|b| file_str < b) {
            best = Some(file_str);
        }
    }

    best.map(|s| s.to_string())
}

/// Resolve a Go module import to a directory of Go files.
///
/// Go imports are package-level (e.g., `github.com/cli/cli/v2/pkg/cmd/create`).
/// We strip the module prefix and look for the remaining path as a directory
/// relative to the repo root, returning the first Go file found in it.
fn resolve_go_module_import<S>(module_path: &str, known_files: &HashSet<S>) -> Option<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    // Must look like a Go module path (contains slashes, no dots at start)
    if !module_path.contains('/') {
        return None;
    }

    // Try progressively shorter prefixes to find the repo-local portion.
    // e.g., "github.com/cli/cli/v2/pkg/cmd/create" → try:
    //   "pkg/cmd/create", "v2/pkg/cmd/create", "cli/v2/pkg/cmd/create", etc.
    let parts: Vec<&str> = module_path.split('/').collect();
    for skip in 1..parts.len() {
        let local_path = parts[skip..].join("/");
        if local_path.is_empty() {
            continue;
        }
        // Pick the smallest .go file as the package's stable representative.
        let mut best: Option<&str> = None;
        for file in known_files.iter() {
            let file_str = file.borrow();
            if file_str.starts_with(&local_path)
                && file_str.ends_with(".go")
                && file_str[local_path.len()..].starts_with('/')
                && !file_str[local_path.len() + 1..].contains('/')
                && best.is_none_or(|b| file_str < b)
            {
                best = Some(file_str);
            }
        }
        if let Some(best) = best {
            return Some(best.to_string());
        }
    }

    None
}

/// Parse a package import path into (package_name, subpath).
///
/// - `@vue/shared` → (`@vue/shared`, `""`)
/// - `@mui/utils/foo` → (`@mui/utils`, `"foo"`)
/// - `lodash/merge` → (`lodash`, `"merge"`)
/// - `react` → (`react`, `""`)
fn parse_package_import(module_path: &str) -> Option<(String, String)> {
    if module_path.is_empty() {
        return None;
    }

    if module_path.starts_with('@') {
        // Scoped package: @scope/name[/subpath]
        let without_at = &module_path[1..];
        let parts: Vec<&str> = without_at.splitn(3, '/').collect();
        if parts.len() < 2 {
            return None; // Invalid scoped package
        }
        let pkg_name = format!("@{}/{}", parts[0], parts[1]);
        let subpath = if parts.len() > 2 {
            parts[2].to_string()
        } else {
            String::new()
        };
        Some((pkg_name, subpath))
    } else {
        // Unscoped package: name[/subpath]
        let parts: Vec<&str> = module_path.splitn(2, '/').collect();
        let pkg_name = parts[0].to_string();
        let subpath = if parts.len() > 1 {
            parts[1].to_string()
        } else {
            String::new()
        };
        Some((pkg_name, subpath))
    }
}

/// Generate candidate directory names for a package.
///
/// For `@vue/shared` → `["shared", "vue-shared"]`
/// For `@mui/material` → `["material", "mui-material"]`
/// For `lodash` → `["lodash"]`
fn package_dir_candidates(pkg_name: &str) -> Vec<String> {
    if let Some(without_at) = pkg_name.strip_prefix('@') {
        let parts: Vec<&str> = without_at.splitn(2, '/').collect();
        if parts.len() == 2 {
            let scope = parts[0];
            let name = parts[1];
            // Common conventions: packages/name/ and packages/scope-name/
            vec![name.to_string(), format!("{}-{}", scope, name)]
        } else {
            vec![without_at.to_string()]
        }
    } else {
        vec![pkg_name.to_string()]
    }
}

/// Resolve a default export from a target file.
///
/// When `import Foo from './bar'` maps original_name to `"default"`, the target
/// file may not have an entity literally named `"default"`. In JS/TS, the
/// default export is typically the file's primary declaration. We find it by
/// looking for the first entity in the target file that is Public (exported).
/// If none are Public, fall back to the first entity in the file.
fn resolve_default_export(target_file: &str, universe_entities: &[&Entity]) -> Option<EntityId> {
    let mut first_in_file: Option<EntityId> = None;
    for entity in universe_entities {
        let Some(ref file_path) = entity.file_origin else {
            continue;
        };
        if file_path.0.as_str() != target_file {
            continue;
        }
        if first_in_file.is_none() {
            first_in_file = Some(entity.id);
        }
        if entity.visibility == Visibility::Public {
            return Some(entity.id);
        }
    }
    first_in_file
}

/// Incremental cross-file relation linker state.
///
/// Keeps entity indices in-memory to avoid O(N) universe cloning and map rebuilding
/// per commit during history hydration.
pub struct IncrementalLinker {
    /// file_path -> entity_name -> EntityId
    pub entity_by_file_name: HashMap<String, HashMap<String, EntityId>>,
    /// entity_name -> Vec<(file_path, EntityId)>
    pub entity_by_name: HashMap<String, Vec<(String, EntityId)>>,
    /// bare (unqualified) leaf name -> Vec<(file_path, EntityId)>, for entities
    /// whose name carries a `::`/`.` qualifier (e.g. `Widget::work` -> `work`).
    /// Backs the incremental (c2) receiver-method resolution, mirroring the
    /// batch linker's `entity_by_bare_name`.
    pub entity_by_bare_name: HashMap<String, Vec<(String, EntityId)>>,
    /// entity_id -> kind
    pub entity_kind_by_id: HashMap<EntityId, EntityKind>,
    /// Set of all known files
    pub known_files: HashSet<String>,
    /// file_path -> Vec<(EntityId, Visibility)>
    pub entities_by_file: HashMap<String, Vec<(EntityId, Visibility)>>,
    /// file_path -> resolved include targets (sorted, deduped).
    ///
    /// Evolves across steps alongside the entity indexes so include-closure
    /// walks see edges recorded when other files were parsed, not only the
    /// step-local ones.
    pub include_targets_by_file: HashMap<String, Vec<String>>,
}

impl IncrementalLinker {
    pub fn new() -> Self {
        Self {
            entity_by_file_name: HashMap::new(),
            entity_by_name: HashMap::new(),
            entity_by_bare_name: HashMap::new(),
            entity_kind_by_id: HashMap::new(),
            known_files: HashSet::new(),
            entities_by_file: HashMap::new(),
            include_targets_by_file: HashMap::new(),
        }
    }

    /// Remove a file and all its associated entities from the indexes.
    pub fn remove_file(&mut self, file_path: &str) {
        self.known_files.remove(file_path);

        if let Some(file_entities) = self.entity_by_file_name.remove(file_path) {
            for (entity_name, entity_id) in file_entities {
                self.entity_kind_by_id.remove(&entity_id);
                if let Some(candidates) = self.entity_by_name.get_mut(&entity_name) {
                    candidates.retain(|(fp, _)| fp != file_path);
                    if candidates.is_empty() {
                        self.entity_by_name.remove(&entity_name);
                    }
                }
                let bare = bare_entity_name(&entity_name);
                if bare != entity_name {
                    if let Some(candidates) = self.entity_by_bare_name.get_mut(bare) {
                        candidates.retain(|(fp, _)| fp != file_path);
                        if candidates.is_empty() {
                            self.entity_by_bare_name.remove(bare);
                        }
                    }
                }
            }
        }

        self.entities_by_file.remove(file_path);
        self.include_targets_by_file.remove(file_path);
    }

    /// Record the resolved include targets of each file, replacing any prior
    /// entry (a file whose includes all resolved away is cleared).
    ///
    /// Call after the step's entity indexes are up to date so module
    /// resolution sees every file known at this point in history.
    pub fn record_file_includes(&mut self, files: &[FileParseData]) {
        for file in files {
            let targets =
                resolve_include_targets(&file.file_path, &file.imports, &self.known_files);
            if targets.is_empty() {
                self.include_targets_by_file.remove(&file.file_path);
            } else {
                self.include_targets_by_file
                    .insert(file.file_path.clone(), targets);
            }
        }
    }

    /// Add or update a file and its entities in the indexes.
    pub fn add_file(&mut self, file_path: &str, entities: &[Entity]) {
        self.remove_file(file_path);

        self.known_files.insert(file_path.to_string());

        let mut file_entities_map = HashMap::new();
        let mut file_entities_list = Vec::new();

        for entity in entities {
            file_entities_map.insert(entity.name.clone(), entity.id);
            self.entity_kind_by_id.insert(entity.id, entity.kind);

            self.entity_by_name
                .entry(entity.name.clone())
                .or_default()
                .push((file_path.to_string(), entity.id));

            let bare = bare_entity_name(&entity.name);
            if bare != entity.name {
                self.entity_by_bare_name
                    .entry(bare.to_string())
                    .or_default()
                    .push((file_path.to_string(), entity.id));
            }

            file_entities_list.push((entity.id, entity.visibility));
        }

        if !file_entities_map.is_empty() {
            self.entity_by_file_name
                .insert(file_path.to_string(), file_entities_map);
        }
        if !file_entities_list.is_empty() {
            self.entities_by_file
                .insert(file_path.to_string(), file_entities_list);
        }
    }
}

/// Resolve a default export from a target file using the incremental index.
fn resolve_default_export_incremental(
    target_file: &str,
    entities_by_file: &HashMap<String, Vec<(EntityId, Visibility)>>,
) -> Option<EntityId> {
    let entities = entities_by_file.get(target_file)?;
    let mut first_in_file: Option<EntityId> = None;
    for &(id, visibility) in entities {
        if first_in_file.is_none() {
            first_in_file = Some(id);
        }
        if visibility == Visibility::Public {
            return Some(id);
        }
    }
    first_in_file
}

/// Resolve cross-file relations using the incrementally updated linker state.
pub fn link_cross_file_incremental(
    files: &[FileParseData],
    linker: &IncrementalLinker,
) -> Vec<Relation> {
    let _span =
        tracing::info_span!("kin.index.link_cross_file_incremental", files = files.len()).entered();

    // Step 2: Build import map per file
    let import_map: HashMap<&str, HashMap<&str, (&str, &str)>> = {
        let mut import_map: HashMap<&str, HashMap<&str, (&str, &str)>> = HashMap::new();
        for file in files {
            let mut file_imports: HashMap<&str, (&str, &str)> = HashMap::new();
            for imp in &file.imports {
                for spec in &imp.specifiers {
                    let original = spec.original_name.as_deref().unwrap_or(&spec.local_name);
                    file_imports.insert(&spec.local_name, (&imp.module_path, original));
                }
            }
            if !file_imports.is_empty() {
                import_map.insert(&file.file_path, file_imports);
            }
        }
        import_map
    };

    let mut resolved = Vec::new();
    let mut seen: HashSet<(EntityId, EntityId, RelationKind)> = HashSet::new();
    // Step-local include edges overlay the linker's persistent per-file
    // include state: files parsed this step resolve fresh (including files
    // that dropped every include), every other file keeps the edges recorded
    // when it was last parsed. Closure walks therefore cross step boundaries.
    let include_graph = {
        let mut merged = linker.include_targets_by_file.clone();
        for file in files {
            merged.remove(&file.file_path);
        }
        for (file_path, targets) in build_include_graph(files, &linker.known_files) {
            merged.insert(file_path, targets);
        }
        merged
    };

    let total_files = files.len();
    let progress_interval = std::cmp::max(total_files / 50, 1);
    let link_start = std::time::Instant::now();

    for (file_idx, file) in files.iter().enumerate() {
        if total_files > 50 && (file_idx % progress_interval == 0 || file_idx + 1 == total_files) {
            eprint!(
                "\r  Linking: [{}/{}] {}% | {} relations | {:.1}s",
                file_idx + 1,
                total_files,
                ((file_idx + 1) * 100) / total_files,
                resolved.len(),
                link_start.elapsed().as_secs_f64()
            );
        }
        // Lazily resolved once per file: only ambiguous name buckets need them.
        let mut caller_import_targets: Option<HashSet<String>> = None;
        let mut caller_include_closure: Option<HashMap<String, usize>> = None;
        for rel in &file.relations {
            let src_id = linker
                .entity_by_file_name
                .get(&file.file_path)
                .and_then(|m| m.get(&rel.src_name))
                .copied();
            let dst_same_file = linker
                .entity_by_file_name
                .get(&file.file_path)
                .and_then(|m| m.get(&rel.dst_name))
                .copied();

            let src_id = match src_id {
                Some(id) => id,
                None => {
                    debug!(
                        src = %rel.src_name,
                        dst = %rel.dst_name,
                        file = %file.file_path,
                        "linker: src entity not found, skipping"
                    );
                    continue;
                }
            };

            if rel.kind == RelationKind::UsesMacro {
                if let Some(dst_id) = dst_same_file {
                    if linker.entity_kind_by_id.get(&dst_id) == Some(&EntityKind::Macro) {
                        if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                            resolved.push(make_relation(rel.kind, src_id, dst_id, 1.0));
                        }
                        continue;
                    }
                }

                if let Some(dst_id) = resolve_reachable_macro_target_incremental(
                    &file.file_path,
                    &rel.dst_name,
                    &include_graph,
                    linker,
                ) {
                    if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                        resolved.push(make_relation(rel.kind, src_id, dst_id, 0.95));
                    }
                    continue;
                }

                debug!(
                    src = %rel.src_name,
                    dst = %rel.dst_name,
                    file = %file.file_path,
                    "linker: macro use unresolved through same-file/include closure"
                );
                continue;
            }

            // (a) Same-file resolution
            if let Some(dst_id) = dst_same_file {
                if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                    resolved.push(make_relation(rel.kind, src_id, dst_id, 1.0));
                }
                continue;
            }

            // (b) Import-based cross-file resolution
            if let Some(file_imports) = import_map.get(file.file_path.as_str()) {
                if let Some(&(module_path, original_name)) = file_imports.get(rel.dst_name.as_str())
                {
                    if let Some(target_file) =
                        resolve_module_path(&file.file_path, module_path, &linker.known_files)
                    {
                        let direct = linker
                            .entity_by_file_name
                            .get(&target_file)
                            .and_then(|m| m.get(original_name))
                            .copied();
                        let dst_id = if direct.is_some() {
                            direct
                        } else if original_name == "default" {
                            resolve_default_export_incremental(
                                &target_file,
                                &linker.entities_by_file,
                            )
                        } else {
                            None
                        };
                        if let Some(dst_id) = dst_id {
                            if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                                resolved.push(make_relation(rel.kind, src_id, dst_id, 0.95));
                            }
                            continue;
                        }
                    }
                }

                // (b2) Namespace/package import member resolution
                if let Some((import_name, member_name)) = split_member_access(rel.dst_name.as_str())
                {
                    if let Some(&(module_path, _original_name)) = file_imports.get(import_name) {
                        if let Some(target_file) =
                            resolve_module_path(&file.file_path, module_path, &linker.known_files)
                        {
                            if let Some(&dst_id) = linker
                                .entity_by_file_name
                                .get(&target_file)
                                .and_then(|m| m.get(member_name))
                            {
                                if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                                    resolved.push(make_relation(rel.kind, src_id, dst_id, 0.9));
                                }
                                continue;
                            }
                        }
                    }
                }
            }

            let other_file_candidates: Vec<(&str, EntityId)> = linker
                .entity_by_name
                .get(&rel.dst_name)
                .map(|candidates| {
                    candidates
                        .iter()
                        .filter(|(fp, _)| fp != &file.file_path)
                        .map(|(fp, id)| (fp.as_str(), *id))
                        .collect()
                })
                .unwrap_or_default();

            // (b3) Parser-pinned import resolution — mirrors the batch linker:
            // a callee pinned to a module must resolve inside that module (or
            // its package directory), never through the global name bucket.
            let mut name_fallback_allowed = true;
            match resolve_import_pinned_target(
                rel,
                &file.file_path,
                &linker.known_files,
                |target_file, name| {
                    linker
                        .entity_by_file_name
                        .get(target_file)
                        .and_then(|m| m.get(name))
                        .copied()
                },
                &other_file_candidates,
            ) {
                ImportPinnedTarget::Resolved(dst_id) => {
                    if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                        resolved.push(make_relation(
                            rel.kind,
                            src_id,
                            dst_id,
                            IMPORT_PINNED_CONFIDENCE,
                        ));
                    }
                    continue;
                }
                ImportPinnedTarget::PinnedMiss => name_fallback_allowed = false,
                ImportPinnedTarget::NoPin => {}
            }

            // (c) Global name-match fallback
            if name_fallback_allowed && !other_file_candidates.is_empty() {
                let distinct_ids: HashSet<EntityId> =
                    other_file_candidates.iter().map(|&(_, id)| id).collect();
                let (dst_id, confidence) = if distinct_ids.len() == 1 {
                    (other_file_candidates[0].1, 0.7)
                } else {
                    let targets = caller_import_targets.get_or_insert_with(|| {
                        resolve_caller_import_targets(
                            &file.file_path,
                            &file.imports,
                            &linker.known_files,
                        )
                    });
                    let closure = caller_include_closure.get_or_insert_with(|| {
                        include_closure_depths(&file.file_path, &include_graph)
                    });
                    match disambiguate_same_name_candidates(
                        &file.file_path,
                        targets,
                        closure,
                        &other_file_candidates,
                        |path| {
                            linker
                                .entities_by_file
                                .get(path)
                                .map(|entities| entities.len())
                                .unwrap_or(0)
                        },
                    ) {
                        Some(dst_id) => (dst_id, LOCALITY_DISAMBIGUATED_CONFIDENCE),
                        // No locality signal: keep the historical bucket-order
                        // pick so signal-less repos do not lose existing edges.
                        None => (other_file_candidates[0].1, 0.7),
                    }
                };
                if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                    resolved.push(make_relation(rel.kind, src_id, dst_id, confidence));
                }
                continue;
            }

            // (c2) Receiver-method calls (`x.method()`) arrive as the bare method
            // name with no exact cross-file entity of that name, so (c) above
            // never fires. Resolve them through the bare-name index only when
            // unambiguous — exactly one method of that name in another file —
            // mirroring the batch linker's (c2). Ambiguous names have an
            // unknowable receiver type, so linking every candidate would mint
            // spurious callers; leave those unresolved. This is the incremental
            // counterpart the batch resolver already had; without it a receiver
            // method resolved into a full-tree snapshot is dropped the moment an
            // incremental relink of the caller re-derives its edges.
            if name_fallback_allowed && rel.kind == RelationKind::Calls {
                if let Some(bare_candidates) = linker.entity_by_bare_name.get(rel.dst_name.as_str())
                {
                    let distinct_targets: HashSet<EntityId> = bare_candidates
                        .iter()
                        .filter(|(fp, _)| fp != &file.file_path)
                        .map(|(_, id)| *id)
                        .collect();
                    if distinct_targets.len() == 1 {
                        let dst_id = *distinct_targets.iter().next().expect("len checked == 1");
                        if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                            resolved.push(make_relation(rel.kind, src_id, dst_id, 0.3));
                        }
                        continue;
                    }
                }
            }

            // (c3) Path-qualified suffix resolution — the incremental counterpart
            // of the batch linker's (c3). Live edits reach this daemon path, so
            // qualified calls must resolve here too, not only on a full re-index.
            if name_fallback_allowed
                && matches!(rel.kind, RelationKind::Calls | RelationKind::References)
            {
                if let Some(dst_id) =
                    resolve_qualified_suffix_incremental(&rel.dst_name, &file.file_path, linker)
                {
                    if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                        resolved.push(make_relation(
                            rel.kind,
                            src_id,
                            dst_id,
                            QUALIFIED_SUFFIX_CONFIDENCE,
                        ));
                    }
                    continue;
                }
            }

            // (d) Cross-repo external reference: preserve an unresolved
            // reference to an external module as an inferred edge carrying the
            // imported symbol and source, so the spine cross-repo resolver can
            // match it against a sibling repo. See
            // `make_external_reference_relation`.
            if let Some(external) =
                make_external_reference_relation(rel, src_id, &file.file_path, &linker.known_files)
            {
                if let GraphNodeId::Entity(dst_id) = external.dst {
                    if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                        resolved.push(external);
                    }
                }
                continue;
            }
        }
    }

    // Step 4: Create artifact-level import/include edges from import declarations.
    let mut seen_artifact: HashSet<(GraphNodeId, GraphNodeId, RelationKind)> = HashSet::new();
    for file in files {
        for imp in &file.imports {
            if let Some(rel) =
                make_artifact_import_relation(&file.file_path, imp, &linker.known_files)
            {
                let key = (rel.src, rel.dst, rel.kind);
                if seen_artifact.insert(key) {
                    resolved.push(rel);
                }
            }
        }
    }

    resolved
}

/// Normalize a path by resolving `.` and `..` components without touching the filesystem.
fn normalize_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::CurDir => {}
            other => components.push(other),
        }
    }
    components.iter().collect()
}

#[cfg(test)]
// Test fixtures construct artifact endpoints by path because they assert on
// the linker's snapshot-less output (see `make_artifact_import_relation`),
// where graph-assigned IDs are path-derived. Matches kin-model's own test
// module, which also allows the deprecated path constructor.
mod tests {
    use super::*;
    use kin_model::{
        ArtifactId, EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm,
        GraphNodeId, Hash256, LanguageId, SemanticFingerprint, SourceSpan, Visibility,
    };

    fn test_fingerprint() -> SemanticFingerprint {
        let zero = Hash256::from_bytes([0u8; 32]);
        SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: zero,
            signature_hash: zero,
            behavior_hash: zero,
            stability_score: 1.0,
        }
    }

    fn make_entity(name: &str, file_path: &str) -> Entity {
        let file_id = FilePathId::new(file_path);
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::TypeScript,
            fingerprint: test_fingerprint(),
            file_origin: Some(file_id.clone()),
            span: Some(SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte: 10,
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: 10,
            }),
            signature: name.to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn make_macro_entity(name: &str, file_path: &str) -> Entity {
        let mut entity = make_entity(name, file_path);
        entity.kind = EntityKind::Macro;
        entity.language = LanguageId::Cpp;
        entity
    }

    #[test]
    fn same_file_resolution() {
        let e1 = make_entity("foo", "src/a.ts");
        let e2 = make_entity("bar", "src/a.ts");

        let files = vec![FileParseData {
            file_path: "src/a.ts".to_string(),
            entities: vec![e1.clone(), e2.clone()],
            relations: vec![ExtractedRelation {
                kind: RelationKind::Calls,
                src_name: "foo".to_string(),
                dst_name: "bar".to_string(),
                import_source: None,
            }],
            imports: vec![],
        }];

        let result = link_cross_file(&files);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].src, GraphNodeId::Entity(e1.id));
        assert_eq!(result[0].dst, GraphNodeId::Entity(e2.id));
        assert_eq!(result[0].confidence, 1.0);
    }

    #[test]
    fn import_based_cross_file_resolution() {
        let caller = make_entity("handler", "src/routes/api.ts");
        let callee = make_entity("executeTool", "src/utils/tools.ts");

        let files = vec![
            FileParseData {
                file_path: "src/routes/api.ts".to_string(),
                entities: vec![caller.clone()],
                relations: vec![ExtractedRelation {
                    kind: RelationKind::Calls,
                    src_name: "handler".to_string(),
                    dst_name: "executeTool".to_string(),
                    import_source: None,
                }],
                imports: vec![FileImport {
                    module_path: "../utils/tools".to_string(),
                    specifiers: vec![kin_parser::ImportedName {
                        local_name: "executeTool".to_string(),
                        original_name: None,
                        is_default: false,
                    }],
                }],
            },
            FileParseData {
                file_path: "src/utils/tools.ts".to_string(),
                entities: vec![callee.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        // Step 3b produces a Calls edge; Step 4 produces an artifact-level Imports edge
        assert_eq!(result.len(), 2);
        let calls = result
            .iter()
            .find(|r| r.kind == RelationKind::Calls)
            .expect("expected Calls relation");
        assert_eq!(calls.src, GraphNodeId::Entity(caller.id));
        assert_eq!(calls.dst, GraphNodeId::Entity(callee.id));
        assert_eq!(calls.confidence, 0.95);
        let imports = result
            .iter()
            .find(|r| r.kind == RelationKind::Imports)
            .expect("expected Imports relation");
        assert_eq!(
            imports.src,
            GraphNodeId::Artifact(ArtifactId::seed_from_path("src/routes/api.ts"))
        );
        assert_eq!(
            imports.dst,
            GraphNodeId::Artifact(ArtifactId::seed_from_path("src/utils/tools.ts"))
        );
        assert_eq!(imports.import_source.as_deref(), Some("../utils/tools"));
    }

    #[test]
    fn incremental_linker_resolves_reparsed_file_against_unchanged_target() {
        let caller = make_entity("handler", "src/routes/api.ts");
        let callee = make_entity("executeTool", "src/utils/tools.ts");

        let reparsed = vec![FileParseData {
            file_path: "src/routes/api.ts".to_string(),
            entities: vec![caller.clone()],
            relations: vec![ExtractedRelation {
                kind: RelationKind::Calls,
                src_name: "handler".to_string(),
                dst_name: "executeTool".to_string(),
                import_source: None,
            }],
            imports: vec![FileImport {
                module_path: "../utils/tools".to_string(),
                specifiers: vec![kin_parser::ImportedName {
                    local_name: "executeTool".to_string(),
                    original_name: None,
                    is_default: false,
                }],
            }],
        }];

        let universe = vec![caller.clone(), callee.clone()];

        let result = link_cross_file_against_entities(&reparsed, &universe);
        // Step 3b produces a Calls edge; Step 4 produces an artifact-level Imports edge
        assert_eq!(result.len(), 2);
        let calls = result
            .iter()
            .find(|r| r.kind == RelationKind::Calls)
            .expect("expected Calls relation");
        assert_eq!(calls.src, GraphNodeId::Entity(caller.id));
        assert_eq!(calls.dst, GraphNodeId::Entity(callee.id));
        assert_eq!(calls.confidence, 0.95);
        let imports = result
            .iter()
            .find(|r| r.kind == RelationKind::Imports)
            .expect("expected Imports relation");
        assert_eq!(
            imports.src,
            GraphNodeId::Artifact(ArtifactId::seed_from_path("src/routes/api.ts"))
        );
        assert_eq!(
            imports.dst,
            GraphNodeId::Artifact(ArtifactId::seed_from_path("src/utils/tools.ts"))
        );
        assert_eq!(imports.import_source.as_deref(), Some("../utils/tools"));
    }

    #[test]
    fn cross_file_resolution_is_independent_of_universe_entity_order() {
        let caller = make_entity("run", "src/app.ts");
        let earlier_target = make_entity("helper", "src/a/helper.ts");
        let later_target = make_entity("helper", "src/z/helper.ts");

        let reparsed = vec![FileParseData {
            file_path: "src/app.ts".to_string(),
            entities: vec![caller.clone()],
            relations: vec![ExtractedRelation {
                kind: RelationKind::Calls,
                src_name: "run".to_string(),
                dst_name: "helper".to_string(),
                import_source: None,
            }],
            imports: vec![],
        }];

        let forward = vec![caller.clone(), earlier_target.clone(), later_target.clone()];
        let reverse = vec![later_target, earlier_target.clone(), caller.clone()];

        let forward_result = link_cross_file_against_entities(&reparsed, &forward);
        let reverse_result = link_cross_file_against_entities(&reparsed, &reverse);

        let relation_key = |rel: &Relation| (rel.kind, rel.src, rel.dst, rel.confidence.to_bits());
        assert_eq!(
            forward_result.iter().map(relation_key).collect::<Vec<_>>(),
            reverse_result.iter().map(relation_key).collect::<Vec<_>>()
        );
        let calls = forward_result
            .iter()
            .find(|rel| rel.kind == RelationKind::Calls)
            .expect("ambiguous global fallback should still pick one stable target");
        assert_eq!(calls.src, GraphNodeId::Entity(caller.id));
        assert_eq!(calls.dst, GraphNodeId::Entity(earlier_target.id));
    }

    #[test]
    fn parallel_resolution_is_byte_identical_to_serial() {
        let calls = |src: &str, dst: &str| ExtractedRelation {
            kind: RelationKind::Calls,
            src_name: src.to_string(),
            dst_name: dst.to_string(),
            import_source: None,
        };
        let import = |module: &str, name: &str| FileImport {
            module_path: module.to_string(),
            specifiers: vec![kin_parser::ImportedName {
                local_name: name.to_string(),
                original_name: None,
                is_default: false,
            }],
        };

        let mut files = vec![
            // Same-file resolution.
            FileParseData {
                file_path: "src/a.ts".to_string(),
                entities: vec![
                    make_entity("funcA", "src/a.ts"),
                    make_entity("helperA", "src/a.ts"),
                ],
                relations: vec![calls("funcA", "helperA")],
                imports: vec![],
            },
            // Import-based cross-file resolution + artifact import edge.
            FileParseData {
                file_path: "src/b.ts".to_string(),
                entities: vec![make_entity("handler", "src/b.ts")],
                relations: vec![calls("handler", "executeTool")],
                imports: vec![import("./utils/tools", "executeTool")],
            },
            FileParseData {
                file_path: "src/utils/tools.ts".to_string(),
                entities: vec![make_entity("executeTool", "src/utils/tools.ts")],
                relations: vec![],
                imports: vec![],
            },
            // Ambiguous global name fallback across two files.
            FileParseData {
                file_path: "src/c.ts".to_string(),
                entities: vec![make_entity("runner", "src/c.ts")],
                relations: vec![calls("runner", "shared")],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/d/shared.ts".to_string(),
                entities: vec![make_entity("shared", "src/d/shared.ts")],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/z/shared.ts".to_string(),
                entities: vec![make_entity("shared", "src/z/shared.ts")],
                relations: vec![],
                imports: vec![],
            },
        ];

        // Pad with self-contained files so the parallel pass spreads real work
        // and any ordering hazard would surface.
        for i in 0..32 {
            let path = format!("src/pad/m{i}.ts");
            files.push(FileParseData {
                file_path: path.clone(),
                entities: vec![make_entity("a", &path), make_entity("b", &path)],
                relations: vec![calls("a", "b"), calls("b", "missing")],
                imports: vec![],
            });
        }

        let universe: Vec<Entity> = files
            .iter()
            .flat_map(|file| file.entities.iter().cloned())
            .collect();

        let parallel = link_cross_file_against_entities(&files, &universe);
        let serial = link_cross_file_against_entities_serial(&files, &universe);

        assert_eq!(
            format!("{parallel:?}"),
            format!("{serial:?}"),
            "parallel linking must produce byte-identical relations to the serial path"
        );
        // Re-running the parallel path must also be byte-stable.
        let parallel_again = link_cross_file_against_entities(&files, &universe);
        assert_eq!(format!("{parallel:?}"), format!("{parallel_again:?}"));
    }

    #[test]
    fn build_include_graph_parallel_matches_serial() {
        let header = |path: &str| FileParseData {
            file_path: path.to_string(),
            entities: vec![],
            relations: vec![],
            imports: vec![],
        };
        let header_import = |module: &str| FileImport {
            module_path: module.to_string(),
            specifiers: vec![],
        };

        let mut files = vec![
            header("include/json/macros.hpp"),
            header("include/json/extra.hpp"),
            // Resolves to a real file but is not include-like (exercises the
            // "resolved but filtered out" branch).
            header("src/other.ts"),
        ];
        // Many includers so the parallel resolve spreads real work; module-path
        // resolution scans known_files, which is the cost being parallelized.
        for i in 0..24 {
            files.push(FileParseData {
                file_path: format!("src/app{i}.cpp"),
                entities: vec![],
                relations: vec![],
                imports: vec![
                    header_import("json/macros.hpp"),
                    header_import("json/extra.hpp"),
                    header_import("./other"),
                ],
            });
        }

        let known_files: HashSet<&str> = files.iter().map(|f| f.file_path.as_str()).collect();

        let parallel = build_include_graph(&files, &known_files);
        let serial = build_include_graph_serial(&files, &known_files);
        assert_eq!(
            parallel, serial,
            "parallel include graph must equal the serial reference"
        );
        assert!(
            !parallel.is_empty(),
            "expected include edges to be produced"
        );
    }

    #[test]
    fn artifact_import_edges_parallel_match_serial() {
        let import = |module: &str, name: &str| FileImport {
            module_path: module.to_string(),
            specifiers: vec![kin_parser::ImportedName {
                local_name: name.to_string(),
                original_name: None,
                is_default: false,
            }],
        };

        let mut files = vec![
            FileParseData {
                file_path: "src/a.ts".to_string(),
                entities: vec![make_entity("handler", "src/a.ts")],
                relations: vec![],
                imports: vec![import("./b/util", "util")],
            },
            FileParseData {
                file_path: "src/b/util.ts".to_string(),
                entities: vec![make_entity("util", "src/b/util.ts")],
                relations: vec![],
                imports: vec![],
            },
        ];
        // Pad so the parallel artifact-edge pass spreads across files; each edge
        // resolves a module path (the parallelized cost).
        for i in 0..24 {
            let path = format!("src/pad/m{i}.ts");
            let dep = format!("src/pad/dep{i}.ts");
            files.push(FileParseData {
                file_path: path.clone(),
                entities: vec![make_entity("m", &path)],
                relations: vec![],
                imports: vec![import(&format!("./dep{i}"), "d")],
            });
            files.push(FileParseData {
                file_path: dep.clone(),
                entities: vec![make_entity("d", &dep)],
                relations: vec![],
                imports: vec![],
            });
        }

        let universe: Vec<Entity> = files
            .iter()
            .flat_map(|f| f.entities.iter().cloned())
            .collect();
        let ctx = build_link_context(&files, &universe);

        // resolve_one_file is deterministic, so building the per-file relations
        // twice yields identical inputs for the two merge paths.
        let pfr_parallel: Vec<Vec<Relation>> =
            files.iter().map(|f| resolve_one_file(f, &ctx)).collect();
        let pfr_serial: Vec<Vec<Relation>> =
            files.iter().map(|f| resolve_one_file(f, &ctx)).collect();

        let parallel = merge_resolved(pfr_parallel, &files, &ctx);
        let serial = merge_resolved_serial(pfr_serial, &files, &ctx);

        assert_eq!(
            format!("{parallel:?}"),
            format!("{serial:?}"),
            "parallel artifact-edge construction must be byte-identical to serial"
        );
        assert!(
            parallel.iter().any(|r| r.kind == RelationKind::Imports),
            "expected artifact-level import edges"
        );
    }

    #[test]
    fn global_name_fallback() {
        let caller = make_entity("main", "src/app.ts");
        let target = make_entity("helper", "src/lib/helper.ts");

        let files = vec![
            FileParseData {
                file_path: "src/app.ts".to_string(),
                entities: vec![caller.clone()],
                relations: vec![ExtractedRelation {
                    kind: RelationKind::Calls,
                    src_name: "main".to_string(),
                    dst_name: "helper".to_string(),
                    import_source: None,
                }],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/lib/helper.ts".to_string(),
                entities: vec![target.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].src, GraphNodeId::Entity(caller.id));
        assert_eq!(result[0].dst, GraphNodeId::Entity(target.id));
        assert_eq!(result[0].confidence, 0.7);
    }

    #[test]
    fn macro_use_resolves_through_reachable_include() {
        let caller = make_entity("main", "src/app.cpp");
        let macro_def = make_macro_entity("JSON_PRIVATE_UNLESS_TESTED", "include/json/macros.hpp");

        let files = vec![
            FileParseData {
                file_path: "src/app.cpp".to_string(),
                entities: vec![caller.clone()],
                relations: vec![ExtractedRelation {
                    kind: RelationKind::UsesMacro,
                    src_name: "main".to_string(),
                    dst_name: "JSON_PRIVATE_UNLESS_TESTED".to_string(),
                    import_source: None,
                }],
                imports: vec![FileImport {
                    module_path: "json/macros.hpp".to_string(),
                    specifiers: vec![kin_parser::ImportedName {
                        local_name: "macros.hpp".to_string(),
                        original_name: Some("default".to_string()),
                        is_default: true,
                    }],
                }],
            },
            FileParseData {
                file_path: "include/json/macros.hpp".to_string(),
                entities: vec![macro_def.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let uses_macro = result
            .iter()
            .find(|rel| rel.kind == RelationKind::UsesMacro)
            .expect("expected reachable macro use relation");
        assert_eq!(uses_macro.src, GraphNodeId::Entity(caller.id));
        assert_eq!(uses_macro.dst, GraphNodeId::Entity(macro_def.id));
        assert_eq!(uses_macro.confidence, 0.95);
        assert!(
            result.iter().any(|rel| {
                rel.kind == RelationKind::Includes
                    && rel.src == GraphNodeId::Artifact(ArtifactId::seed_from_path("src/app.cpp"))
                    && rel.dst
                        == GraphNodeId::Artifact(ArtifactId::seed_from_path(
                            "include/json/macros.hpp",
                        ))
            }),
            "include directive should be preserved as an artifact edge"
        );
    }

    #[test]
    fn macro_use_does_not_resolve_to_unincluded_global_match() {
        let caller = make_entity("main", "src/app.cpp");
        let macro_def = make_macro_entity("JSON_PRIVATE_UNLESS_TESTED", "include/json/macros.hpp");

        let files = vec![
            FileParseData {
                file_path: "src/app.cpp".to_string(),
                entities: vec![caller],
                relations: vec![ExtractedRelation {
                    kind: RelationKind::UsesMacro,
                    src_name: "main".to_string(),
                    dst_name: "JSON_PRIVATE_UNLESS_TESTED".to_string(),
                    import_source: None,
                }],
                imports: vec![],
            },
            FileParseData {
                file_path: "include/json/macros.hpp".to_string(),
                entities: vec![macro_def],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert!(
            result.iter().all(|rel| rel.kind != RelationKind::UsesMacro),
            "macro uses must not resolve through the generic global fallback"
        );
    }

    #[test]
    fn projection_markers_emit_derived_from_artifact_edges() {
        let known_files = HashSet::from([
            "single_include/nlohmann/json.hpp".to_string(),
            "include/nlohmann/detail/exceptions.hpp".to_string(),
            "include/nlohmann/detail/iterators/internal_iterator.hpp".to_string(),
        ]);
        let source = br#"
// #include <nlohmann/detail/exceptions.hpp>
// #include <nlohmann/detail/iterators/internal_iterator.hpp>
// #include <vector>
"#;

        let relations = build_projection_derived_relations_for_file(
            "single_include/nlohmann/json.hpp",
            source,
            &known_files,
            |path| {
                if known_files.contains(path) {
                    Some(ArtifactId::seed_from_path(path))
                } else {
                    None
                }
            },
        );

        assert_eq!(relations.len(), 2);
        assert!(relations.iter().all(|rel| {
            rel.kind == RelationKind::DerivedFrom
                && rel.src
                    == GraphNodeId::Artifact(ArtifactId::seed_from_path(
                        "single_include/nlohmann/json.hpp",
                    ))
        }));
        let exception_edge = relations
            .iter()
            .find(|rel| {
                rel.dst
                    == GraphNodeId::Artifact(ArtifactId::seed_from_path(
                        "include/nlohmann/detail/exceptions.hpp",
                    ))
            })
            .expect("expected exceptions provenance edge");
        assert_eq!(exception_edge.origin, RelationOrigin::Inferred);
        assert_eq!(exception_edge.confidence, 0.9);
        assert_eq!(
            exception_edge.evidence[0].parser_rule.as_deref(),
            Some("projection_include_marker")
        );
        assert_eq!(
            exception_edge.evidence[0].source_path.as_deref(),
            Some("nlohmann/detail/exceptions.hpp")
        );
        assert_eq!(
            exception_edge.evidence[0].resolved_path.as_deref(),
            Some("include/nlohmann/detail/exceptions.hpp")
        );
    }

    #[test]
    fn projection_markers_require_projection_context_or_density() {
        let sparse_source = br#"
// #include <nlohmann/detail/exceptions.hpp>
void f();
"#;
        assert!(
            extract_projection_source_markers("include/nlohmann/json.hpp", sparse_source)
                .is_empty(),
            "ordinary source comments should not become projection provenance"
        );

        let dense_source = br#"
// #include <a.hpp>
// #include <b.hpp>
// #include <c.hpp>
// #include <d.hpp>
"#;
        assert_eq!(
            extract_projection_source_markers("include/nlohmann/json.hpp", dense_source).len(),
            4,
            "dense source boundary markers are projection evidence even without a generated path"
        );
    }

    #[test]
    fn namespace_import_member_resolution() {
        let caller = make_entity("_safeParse", "src/parse.ts");
        let callee = make_entity("finalizeIssue", "src/util.ts");

        let files = vec![
            FileParseData {
                file_path: "src/parse.ts".to_string(),
                entities: vec![caller.clone()],
                relations: vec![ExtractedRelation {
                    kind: RelationKind::Calls,
                    src_name: "_safeParse".to_string(),
                    dst_name: "util.finalizeIssue".to_string(),
                    import_source: None,
                }],
                imports: vec![FileImport {
                    module_path: "./util".to_string(),
                    specifiers: vec![kin_parser::ImportedName {
                        local_name: "util".to_string(),
                        original_name: Some("*".to_string()),
                        is_default: false,
                    }],
                }],
            },
            FileParseData {
                file_path: "src/util.ts".to_string(),
                entities: vec![callee.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        // 1 Calls edge + 1 artifact-level Imports edge
        assert_eq!(result.len(), 2);
        let calls = result
            .iter()
            .find(|r| r.kind == RelationKind::Calls)
            .expect("expected Calls relation");
        assert_eq!(calls.src, GraphNodeId::Entity(caller.id));
        assert_eq!(calls.dst, GraphNodeId::Entity(callee.id));
        assert_eq!(calls.confidence, 0.9);
    }

    #[test]
    fn deduplicates_relations() {
        let e1 = make_entity("foo", "src/a.ts");
        let e2 = make_entity("bar", "src/a.ts");

        let files = vec![FileParseData {
            file_path: "src/a.ts".to_string(),
            entities: vec![e1.clone(), e2.clone()],
            relations: vec![
                ExtractedRelation {
                    kind: RelationKind::Calls,
                    src_name: "foo".to_string(),
                    dst_name: "bar".to_string(),
                    import_source: None,
                },
                ExtractedRelation {
                    kind: RelationKind::Calls,
                    src_name: "foo".to_string(),
                    dst_name: "bar".to_string(),
                    import_source: None,
                },
            ],
            imports: vec![],
        }];

        let result = link_cross_file(&files);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn unresolved_dst_skipped() {
        let e1 = make_entity("foo", "src/a.ts");

        let files = vec![FileParseData {
            file_path: "src/a.ts".to_string(),
            entities: vec![e1],
            relations: vec![ExtractedRelation {
                kind: RelationKind::Calls,
                src_name: "foo".to_string(),
                dst_name: "nonexistent".to_string(),
                import_source: None,
            }],
            imports: vec![],
        }];

        let result = link_cross_file(&files);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn receiver_method_call_resolves_when_bare_name_unambiguous() {
        // `project_after_mcp_commit` calls `reconciler.project_overlay_to_files(...)`,
        // captured as the bare name `project_overlay_to_files`; exactly one method of
        // that name exists, so the receiver target is unambiguous and must link.
        let caller = make_entity("project_after_mcp_commit", "src/wiring.rs");
        let callee = make_entity("Reconciler::project_overlay_to_files", "src/reconciler.rs");

        let files = vec![
            FileParseData {
                file_path: "src/wiring.rs".to_string(),
                entities: vec![caller.clone()],
                relations: vec![ExtractedRelation {
                    kind: RelationKind::Calls,
                    src_name: "project_after_mcp_commit".to_string(),
                    dst_name: "project_overlay_to_files".to_string(),
                    import_source: None,
                }],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/reconciler.rs".to_string(),
                entities: vec![callee.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let calls = result
            .iter()
            .find(|r| r.kind == RelationKind::Calls)
            .expect("unambiguous receiver-method call should resolve to the single Type::method");
        assert_eq!(calls.src, GraphNodeId::Entity(caller.id));
        assert_eq!(calls.dst, GraphNodeId::Entity(callee.id));
    }

    #[test]
    fn receiver_method_call_skipped_when_bare_name_ambiguous() {
        // A call to bare `new` could target either `Foo::new` or `Bar::new`; the
        // receiver type is unknowable from the name, so linking to either would mint
        // a spurious caller. Leave it unlinked for the inconclusive gate.
        let caller = make_entity("build", "src/caller.rs");
        let foo_new = make_entity("Foo::new", "src/foo.rs");
        let bar_new = make_entity("Bar::new", "src/bar.rs");

        let files = vec![
            FileParseData {
                file_path: "src/caller.rs".to_string(),
                entities: vec![caller.clone()],
                relations: vec![ExtractedRelation {
                    kind: RelationKind::Calls,
                    src_name: "build".to_string(),
                    dst_name: "new".to_string(),
                    import_source: None,
                }],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/foo.rs".to_string(),
                entities: vec![foo_new],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/bar.rs".to_string(),
                entities: vec![bar_new],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let calls = result
            .iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .count();
        assert_eq!(
            calls, 0,
            "ambiguous bare-name receiver call must not link to any candidate, got {calls} edges"
        );
    }

    #[test]
    fn incremental_receiver_method_call_resolves_when_bare_name_unambiguous() {
        // Incremental (c2) parity with `receiver_method_call_resolves_when_bare_name_unambiguous`:
        // a bare receiver-method call resolves to the single `Type::method` through
        // the incremental bare-name index. Before the parity fix the incremental
        // linker had no bare-name index and left this unresolved.
        let caller = make_entity("project_after_mcp_commit", "src/wiring.rs");
        let callee = make_entity("Reconciler::project_overlay_to_files", "src/reconciler.rs");

        let mut linker = IncrementalLinker::new();
        linker.add_file("src/wiring.rs", std::slice::from_ref(&caller));
        linker.add_file("src/reconciler.rs", std::slice::from_ref(&callee));

        let files = vec![FileParseData {
            file_path: "src/wiring.rs".to_string(),
            entities: vec![caller.clone()],
            relations: vec![ExtractedRelation {
                kind: RelationKind::Calls,
                src_name: "project_after_mcp_commit".to_string(),
                dst_name: "project_overlay_to_files".to_string(),
                import_source: None,
            }],
            imports: vec![],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        let calls = result
            .iter()
            .find(|r| r.kind == RelationKind::Calls)
            .expect("incremental unambiguous receiver-method call should resolve to Type::method");
        assert_eq!(calls.src, GraphNodeId::Entity(caller.id));
        assert_eq!(calls.dst, GraphNodeId::Entity(callee.id));
    }

    #[test]
    fn incremental_receiver_method_call_skipped_when_bare_name_ambiguous() {
        // Incremental (c2) parity with `receiver_method_call_skipped_when_bare_name_ambiguous`:
        // bare `new` could be `Foo::new` or `Bar::new`; the receiver type is
        // unknowable, so it must stay unlinked (matching the batch resolver's
        // conservatism — no spurious callers).
        let caller = make_entity("build", "src/caller.rs");
        let foo_new = make_entity("Foo::new", "src/foo.rs");
        let bar_new = make_entity("Bar::new", "src/bar.rs");

        let mut linker = IncrementalLinker::new();
        linker.add_file("src/caller.rs", std::slice::from_ref(&caller));
        linker.add_file("src/foo.rs", std::slice::from_ref(&foo_new));
        linker.add_file("src/bar.rs", std::slice::from_ref(&bar_new));

        let files = vec![FileParseData {
            file_path: "src/caller.rs".to_string(),
            entities: vec![caller.clone()],
            relations: vec![ExtractedRelation {
                kind: RelationKind::Calls,
                src_name: "build".to_string(),
                dst_name: "new".to_string(),
                import_source: None,
            }],
            imports: vec![],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        let calls = result
            .iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .count();
        assert_eq!(
            calls, 0,
            "incremental ambiguous bare-name receiver call must not link, got {calls} edges"
        );
    }

    #[test]
    fn resolve_module_path_with_extension() {
        let known: HashSet<&str> = ["src/utils/tools.ts"].into_iter().collect();
        let result = resolve_module_path("src/routes/api.ts", "../utils/tools", &known);
        assert_eq!(result, Some("src/utils/tools.ts".to_string()));
    }

    #[test]
    fn resolve_module_path_index_file() {
        let known: HashSet<&str> = ["src/utils/index.ts"].into_iter().collect();
        let result = resolve_module_path("src/routes/api.ts", "../utils", &known);
        assert_eq!(result, Some("src/utils/index.ts".to_string()));
    }

    #[test]
    fn resolve_module_path_non_relative_no_workspace_match() {
        // Non-relative imports with no matching workspace package return None
        let known: HashSet<&str> = ["node_modules/lodash/index.js"].into_iter().collect();
        let result = resolve_module_path("src/app.ts", "lodash", &known);
        assert_eq!(result, None);
    }

    #[test]
    fn resolve_scoped_package_import() {
        // @vue/shared → packages/shared/src/index.ts
        let known: HashSet<&str> = [
            "packages/shared/src/index.ts",
            "packages/shared/src/general.ts",
        ]
        .into_iter()
        .collect();
        let result =
            resolve_module_path("packages/reactivity/src/effect.ts", "@vue/shared", &known);
        assert_eq!(result, Some("packages/shared/src/index.ts".to_string()));
    }

    #[test]
    fn resolve_scoped_package_with_scope_prefix_dir() {
        // @mui/utils → packages/mui-utils/src/index.ts
        let known: HashSet<&str> = ["packages/mui-utils/src/index.ts"].into_iter().collect();
        let result = resolve_module_path(
            "packages/mui-material/src/Grid/Grid.tsx",
            "@mui/utils",
            &known,
        );
        assert_eq!(result, Some("packages/mui-utils/src/index.ts".to_string()));
    }

    #[test]
    fn resolve_scoped_package_with_subpath() {
        // @mui/utils/generateUtilityClasses → packages/mui-utils/src/generateUtilityClasses/index.ts
        let known: HashSet<&str> = ["packages/mui-utils/src/generateUtilityClasses/index.ts"]
            .into_iter()
            .collect();
        let result = resolve_module_path(
            "packages/mui-material/src/Grid/gridClasses.ts",
            "@mui/utils/generateUtilityClasses",
            &known,
        );
        assert_eq!(
            result,
            Some("packages/mui-utils/src/generateUtilityClasses/index.ts".to_string())
        );
    }

    #[test]
    fn resolve_repo_local_header_include_path() {
        let known: HashSet<&str> = ["include/nlohmann/detail/input/binary_reader.hpp"]
            .into_iter()
            .collect();

        let result = resolve_module_path(
            "src/main.cpp",
            "nlohmann/detail/input/binary_reader.hpp",
            &known,
        );

        assert_eq!(
            result,
            Some("include/nlohmann/detail/input/binary_reader.hpp".to_string())
        );
    }

    #[test]
    fn go_module_import_resolution_uses_stable_package_representative() {
        let known: HashSet<&str> = [
            "pkg/cmd/create/zz_generated.go",
            "pkg/cmd/create/create.go",
            "pkg/cmd/create/create_test.go",
            "pkg/cmd/create/nested/skip.go",
            "pkg/cmd/delete/delete.go",
        ]
        .into_iter()
        .collect();

        let result = resolve_module_path(
            "cmd/gh/main.go",
            "github.com/cli/cli/v2/pkg/cmd/create",
            &known,
        );

        assert_eq!(result, Some("pkg/cmd/create/create.go".to_string()));
    }

    #[test]
    fn renamed_import_resolution() {
        let caller = make_entity("handler", "src/api.ts");
        let callee = make_entity("doWork", "src/utils.ts");

        let files = vec![
            FileParseData {
                file_path: "src/api.ts".to_string(),
                entities: vec![caller.clone()],
                relations: vec![ExtractedRelation {
                    kind: RelationKind::Calls,
                    src_name: "handler".to_string(),
                    dst_name: "myWork".to_string(),
                    import_source: None,
                }],
                imports: vec![FileImport {
                    module_path: "./utils".to_string(),
                    specifiers: vec![kin_parser::ImportedName {
                        local_name: "myWork".to_string(),
                        original_name: Some("doWork".to_string()),
                        is_default: false,
                    }],
                }],
            },
            FileParseData {
                file_path: "src/utils.ts".to_string(),
                entities: vec![callee.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        // Step 3b produces a Calls edge; Step 4 produces an artifact-level Imports edge
        assert_eq!(result.len(), 2);
        let calls = result
            .iter()
            .find(|r| r.kind == RelationKind::Calls)
            .expect("expected Calls relation");
        assert_eq!(calls.src, GraphNodeId::Entity(caller.id));
        assert_eq!(calls.dst, GraphNodeId::Entity(callee.id));
        assert_eq!(calls.confidence, 0.95);
        let imports = result
            .iter()
            .find(|r| r.kind == RelationKind::Imports)
            .expect("expected Imports relation");
        assert_eq!(
            imports.src,
            GraphNodeId::Artifact(ArtifactId::seed_from_path("src/api.ts"))
        );
        assert_eq!(
            imports.dst,
            GraphNodeId::Artifact(ArtifactId::seed_from_path("src/utils.ts"))
        );
        assert_eq!(imports.import_source.as_deref(), Some("./utils"));
    }

    #[test]
    fn import_creates_imports_relation() {
        let importer = make_entity("handler", "src/routes/api.ts");
        let target = make_entity("executeTool", "src/utils/tools.ts");

        let files = vec![
            FileParseData {
                file_path: "src/routes/api.ts".to_string(),
                entities: vec![importer.clone()],
                relations: vec![],
                imports: vec![FileImport {
                    module_path: "../utils/tools".to_string(),
                    specifiers: vec![kin_parser::ImportedName {
                        local_name: "executeTool".to_string(),
                        original_name: None,
                        is_default: false,
                    }],
                }],
            },
            FileParseData {
                file_path: "src/utils/tools.ts".to_string(),
                entities: vec![target.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].kind, RelationKind::Imports);
        assert_eq!(
            result[0].src,
            GraphNodeId::Artifact(ArtifactId::seed_from_path("src/routes/api.ts"))
        );
        assert_eq!(
            result[0].dst,
            GraphNodeId::Artifact(ArtifactId::seed_from_path("src/utils/tools.ts"))
        );
        assert_eq!(result[0].import_source.as_deref(), Some("../utils/tools"));
    }

    #[test]
    fn header_include_creates_default_import_relation() {
        let _importer = make_entity("main", "src/main.cpp");
        let _target = make_entity(
            "binary_reader",
            "include/nlohmann/detail/input/binary_reader.hpp",
        );

        let files = vec![
            FileParseData {
                file_path: "src/main.cpp".to_string(),
                entities: vec![_importer.clone()],
                relations: vec![],
                imports: vec![FileImport {
                    module_path: "nlohmann/detail/input/binary_reader.hpp".to_string(),
                    specifiers: vec![kin_parser::ImportedName {
                        local_name: "binary_reader.hpp".to_string(),
                        original_name: Some("default".to_string()),
                        is_default: true,
                    }],
                }],
            },
            FileParseData {
                file_path: "include/nlohmann/detail/input/binary_reader.hpp".to_string(),
                entities: vec![_target.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert_eq!(result.len(), 1);
        // Header includes produce Includes edges (artifact-level)
        assert_eq!(result[0].kind, RelationKind::Includes);
        assert_eq!(
            result[0].src,
            GraphNodeId::Artifact(ArtifactId::seed_from_path("src/main.cpp"))
        );
        assert_eq!(
            result[0].dst,
            GraphNodeId::Artifact(ArtifactId::seed_from_path(
                "include/nlohmann/detail/input/binary_reader.hpp"
            ))
        );
        assert_eq!(
            result[0].import_source.as_deref(),
            Some("nlohmann/detail/input/binary_reader.hpp")
        );
    }

    #[test]
    fn import_and_call_both_created() {
        let caller = make_entity("handler", "src/routes/api.ts");
        let callee = make_entity("executeTool", "src/utils/tools.ts");

        let files = vec![
            FileParseData {
                file_path: "src/routes/api.ts".to_string(),
                entities: vec![caller.clone()],
                relations: vec![ExtractedRelation {
                    kind: RelationKind::Calls,
                    src_name: "handler".to_string(),
                    dst_name: "executeTool".to_string(),
                    import_source: None,
                }],
                imports: vec![FileImport {
                    module_path: "../utils/tools".to_string(),
                    specifiers: vec![kin_parser::ImportedName {
                        local_name: "executeTool".to_string(),
                        original_name: None,
                        is_default: false,
                    }],
                }],
            },
            FileParseData {
                file_path: "src/utils/tools.ts".to_string(),
                entities: vec![callee.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert_eq!(result.len(), 2);
        let calls = result.iter().find(|r| r.kind == RelationKind::Calls);
        let imports = result.iter().find(|r| r.kind == RelationKind::Imports);
        assert!(calls.is_some(), "should have a Calls relation");
        assert!(imports.is_some(), "should have an Imports relation");
    }

    #[test]
    fn wildcard_import_creates_artifact_edge() {
        // Wildcard imports now produce artifact-level edges (file imports file)
        // even though no per-specifier entity resolution occurs.
        let importer = make_entity("handler", "src/api.ts");
        let target = make_entity("helper", "src/util.ts");

        let files = vec![
            FileParseData {
                file_path: "src/api.ts".to_string(),
                entities: vec![importer.clone()],
                relations: vec![],
                imports: vec![FileImport {
                    module_path: "./util".to_string(),
                    specifiers: vec![kin_parser::ImportedName {
                        local_name: "util".to_string(),
                        original_name: Some("*".to_string()),
                        is_default: false,
                    }],
                }],
            },
            FileParseData {
                file_path: "src/util.ts".to_string(),
                entities: vec![target.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert_eq!(
            result.len(),
            1,
            "wildcard imports should create an artifact-level edge"
        );
        assert_eq!(result[0].kind, RelationKind::Imports);
        assert_eq!(
            result[0].src,
            GraphNodeId::Artifact(ArtifactId::seed_from_path("src/api.ts"))
        );
        assert_eq!(
            result[0].dst,
            GraphNodeId::Artifact(ArtifactId::seed_from_path("src/util.ts"))
        );
    }

    #[test]
    fn empty_files_returns_empty() {
        let result = link_cross_file(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn linker_name_matching_exact() {
        let e1 = make_entity("caller", "a.ts");
        let e2 = make_entity("callee", "b.ts");

        let files = vec![
            FileParseData {
                file_path: "a.ts".to_string(),
                entities: vec![e1.clone()],
                relations: vec![ExtractedRelation {
                    kind: RelationKind::Calls,
                    src_name: "caller".to_string(),
                    dst_name: "callee".to_string(),
                    import_source: None,
                }],
                imports: vec![],
            },
            FileParseData {
                file_path: "b.ts".to_string(),
                entities: vec![e2.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].kind, RelationKind::Calls);
        assert_eq!(result[0].src, GraphNodeId::Entity(e1.id));
        assert_eq!(result[0].dst, GraphNodeId::Entity(e2.id));
    }

    #[test]
    fn external_reference_carries_symbol_and_import_source() {
        // A call to a symbol that lives in another repo: the target is absent
        // from this repo's parse universe, but the parser recorded the module it
        // was imported from. The linker must preserve it as a cross-repo edge
        // carrying the lexical symbol (evidence.token) and the module hint
        // (import_source) — exactly what the spine resolver keys on.
        let caller = make_entity("run_task", "src/app.rs");

        let files = vec![FileParseData {
            file_path: "src/app.rs".to_string(),
            entities: vec![caller.clone()],
            relations: vec![ExtractedRelation {
                kind: RelationKind::Calls,
                src_name: "run_task".to_string(),
                dst_name: "InMemoryGraph".to_string(),
                import_source: Some("kin_db".to_string()),
            }],
            imports: vec![],
        }];

        let result = link_cross_file(&files);
        assert_eq!(result.len(), 1, "one cross-repo reference edge expected");
        let edge = &result[0];
        assert_eq!(edge.kind, RelationKind::Calls);
        assert_eq!(edge.src, GraphNodeId::Entity(caller.id));
        // The destination is an external placeholder, never a local entity.
        assert_ne!(edge.dst, GraphNodeId::Entity(caller.id));
        assert_eq!(edge.import_source.as_deref(), Some("kin_db"));
        assert_eq!(edge.origin, RelationOrigin::Inferred);
        let token = edge
            .evidence
            .iter()
            .find_map(|ev| ev.token.as_deref())
            .expect("evidence token present");
        assert_eq!(token, "InMemoryGraph");
    }

    #[test]
    fn external_reference_not_emitted_without_import_source() {
        // No import source from the parser means we cannot honestly attribute
        // the reference to any repo — it must stay unresolved, not fabricated.
        let caller = make_entity("run_task", "src/app.rs");

        let files = vec![FileParseData {
            file_path: "src/app.rs".to_string(),
            entities: vec![caller.clone()],
            relations: vec![ExtractedRelation {
                kind: RelationKind::Calls,
                src_name: "run_task".to_string(),
                dst_name: "InMemoryGraph".to_string(),
                import_source: None,
            }],
            imports: vec![],
        }];

        let result = link_cross_file(&files);
        assert!(
            result.is_empty(),
            "no edge should be fabricated without an import source"
        );
    }

    #[test]
    fn external_reference_is_deterministic_and_deduped() {
        // Two call sites to the same external symbol collapse to one stable edge,
        // and the derived target id is identical across independent link runs.
        let caller = make_entity("run_task", "src/app.rs");
        let other = make_entity("run_again", "src/app.rs");

        let build = |entities: Vec<Entity>| FileParseData {
            file_path: "src/app.rs".to_string(),
            entities,
            relations: vec![
                ExtractedRelation {
                    kind: RelationKind::Calls,
                    src_name: "run_task".to_string(),
                    dst_name: "InMemoryGraph".to_string(),
                    import_source: Some("kin_db".to_string()),
                },
                ExtractedRelation {
                    kind: RelationKind::Calls,
                    src_name: "run_again".to_string(),
                    dst_name: "InMemoryGraph".to_string(),
                    import_source: Some("kin_db".to_string()),
                },
            ],
            imports: vec![],
        };

        let first = link_cross_file(&[build(vec![caller.clone(), other.clone()])]);
        // Two distinct sources, same external target → two edges sharing one dst.
        assert_eq!(first.len(), 2);
        let dst_a = first[0].dst;
        let dst_b = first[1].dst;
        assert_eq!(dst_a, dst_b, "same symbol/source → same external target id");

        let second = link_cross_file(&[build(vec![caller, other])]);
        assert_eq!(second.len(), 2);
        assert_eq!(
            first[0].dst, second[0].dst,
            "external target id is stable across link runs"
        );
    }

    #[test]
    fn external_reference_skipped_for_local_module_import() {
        // The import source resolves to a file in this repo, so a symbol that
        // fails local resolution (e.g. a moved or deleted local definition) is a
        // broken local import, not a cross-repo reference. No external edge may
        // be fabricated for it.
        let handler = make_entity("handler", "src/routes/api.ts");
        // tools.ts still exists in the repo but no longer defines `executeTool`.
        let surviving = make_entity("VERSION", "src/utils/tools.ts");

        let files = vec![
            FileParseData {
                file_path: "src/routes/api.ts".to_string(),
                entities: vec![handler.clone()],
                relations: vec![ExtractedRelation {
                    kind: RelationKind::Calls,
                    src_name: "handler".to_string(),
                    dst_name: "executeTool".to_string(),
                    import_source: Some("../utils/tools".to_string()),
                }],
                imports: vec![FileImport {
                    module_path: "../utils/tools".to_string(),
                    specifiers: vec![kin_parser::ImportedName {
                        local_name: "executeTool".to_string(),
                        original_name: None,
                        is_default: false,
                    }],
                }],
            },
            FileParseData {
                file_path: "src/utils/tools.ts".to_string(),
                entities: vec![surviving],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert!(
            result.iter().all(|r| r.kind != RelationKind::Calls),
            "a broken local import must not be emitted as a cross-repo edge"
        );
    }

    // ---- Path-qualified call resolution ----
    //
    // The Rust adapter preserves the full lexical path of a qualified call
    // (`crate::mod::func`, `Type::method`, `alias::Type::method`) as the
    // relation `dst_name`. Before (c3), those names matched no entity index and
    // callers were silently dropped from refs/impact. These tests pin the
    // matrix {path-qualified free fn, module-qualified, Type::method,
    // crate::Type::method, alias::Type::method} x {resolve, ambiguous, absent}
    // for both the batch and incremental linkers.

    fn make_method_entity(name: &str, file_path: &str) -> Entity {
        let mut e = make_entity(name, file_path);
        e.kind = EntityKind::Method;
        e.language = LanguageId::Rust;
        e
    }

    fn rust_fn(name: &str, file_path: &str) -> Entity {
        let mut e = make_entity(name, file_path);
        e.language = LanguageId::Rust;
        e
    }

    fn calls_relation(src: &str, dst: &str) -> ExtractedRelation {
        ExtractedRelation {
            kind: RelationKind::Calls,
            src_name: src.to_string(),
            dst_name: dst.to_string(),
            import_source: None,
        }
    }

    fn find_calls_edge<'a>(
        result: &'a [Relation],
        src: &Entity,
        dst: &Entity,
    ) -> Option<&'a Relation> {
        result.iter().find(|r| {
            r.kind == RelationKind::Calls
                && r.src == GraphNodeId::Entity(src.id)
                && r.dst == GraphNodeId::Entity(dst.id)
        })
    }

    #[test]
    fn qualified_free_fn_call_resolves_cross_file() {
        // `crate::work::run(...)` in caller.rs -> free fn `run` in work.rs.
        let caller = rust_fn("caller", "src/caller.rs");
        let target = rust_fn("run", "src/work.rs");

        let files = vec![
            FileParseData {
                file_path: "src/caller.rs".to_string(),
                entities: vec![caller.clone()],
                relations: vec![calls_relation("caller", "crate::work::run")],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/work.rs".to_string(),
                entities: vec![target.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let edge = find_calls_edge(&result, &caller, &target)
            .expect("qualified free-fn call should resolve to the target fn");
        assert_eq!(edge.confidence, QUALIFIED_SUFFIX_CONFIDENCE);
        assert_eq!(edge.origin, RelationOrigin::Inferred);
    }

    #[test]
    fn module_qualified_free_fn_resolves() {
        // The exact ticket case: `impact::analyze_impact(...)` -> free fn.
        let caller = rust_fn("review_from_diff", "kin-review/src/review.rs");
        let target = rust_fn("analyze_impact", "kin-review/src/impact.rs");

        let files = vec![
            FileParseData {
                file_path: "kin-review/src/review.rs".to_string(),
                entities: vec![caller.clone()],
                relations: vec![calls_relation("review_from_diff", "impact::analyze_impact")],
                imports: vec![],
            },
            FileParseData {
                file_path: "kin-review/src/impact.rs".to_string(),
                entities: vec![target.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert!(
            find_calls_edge(&result, &caller, &target).is_some(),
            "module-qualified call should resolve"
        );
    }

    #[test]
    fn crate_type_method_call_resolves_via_type_qualified_suffix() {
        // `crate::model::Widget::make(...)` -> method entity `Widget::make`.
        let caller = rust_fn("caller", "src/caller.rs");
        let method = make_method_entity("Widget::make", "src/model.rs");

        let files = vec![
            FileParseData {
                file_path: "src/caller.rs".to_string(),
                entities: vec![caller.clone()],
                relations: vec![calls_relation("caller", "crate::model::Widget::make")],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/model.rs".to_string(),
                entities: vec![method.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert!(
            find_calls_edge(&result, &caller, &method).is_some(),
            "crate::Type::method should resolve via the type-qualified suffix"
        );
    }

    #[test]
    fn alias_type_method_call_resolves() {
        // `alias::Widget::make(...)` (renamed-crate prefix) -> `Widget::make`.
        let caller = rust_fn("caller", "src/caller.rs");
        let method = make_method_entity("Widget::make", "vendor/src/model.rs");

        let files = vec![
            FileParseData {
                file_path: "src/caller.rs".to_string(),
                entities: vec![caller.clone()],
                relations: vec![calls_relation("caller", "alias::Widget::make")],
                imports: vec![],
            },
            FileParseData {
                file_path: "vendor/src/model.rs".to_string(),
                entities: vec![method.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert!(
            find_calls_edge(&result, &caller, &method).is_some(),
            "alias::Type::method should resolve via the type-qualified suffix"
        );
    }

    #[test]
    fn two_segment_type_method_still_resolves() {
        // Guard: plain `Widget::make(...)` cross-file already resolves via the
        // exact (c) name match; (c3) must not disturb it.
        let caller = rust_fn("caller", "src/caller.rs");
        let method = make_method_entity("Widget::make", "src/model.rs");

        let files = vec![
            FileParseData {
                file_path: "src/caller.rs".to_string(),
                entities: vec![caller.clone()],
                relations: vec![calls_relation("caller", "Widget::make")],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/model.rs".to_string(),
                entities: vec![method.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert!(
            find_calls_edge(&result, &caller, &method).is_some(),
            "two-segment Type::method should still resolve"
        );
    }

    #[test]
    fn ambiguous_qualified_leaf_leaves_unresolved() {
        // Two distinct free fns named `run` in different files; the qualified
        // call cannot be pinned to one -> conservative miss (no wrong edge).
        let caller = rust_fn("caller", "src/caller.rs");
        let run_a = rust_fn("run", "src/a.rs");
        let run_b = rust_fn("run", "src/b.rs");

        let files = vec![
            FileParseData {
                file_path: "src/caller.rs".to_string(),
                entities: vec![caller.clone()],
                relations: vec![calls_relation("caller", "crate::somewhere::run")],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/a.rs".to_string(),
                entities: vec![run_a.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/b.rs".to_string(),
                entities: vec![run_b.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert!(
            result.iter().all(|r| r.kind != RelationKind::Calls),
            "ambiguous qualified leaf must not mint a Calls edge, got {:?}",
            result
                .iter()
                .filter(|r| r.kind == RelationKind::Calls)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn qualified_call_to_absent_target_is_honest_miss() {
        // Target not in the universe and no import source -> no edge, no fake.
        let caller = rust_fn("caller", "src/caller.rs");

        let files = vec![FileParseData {
            file_path: "src/caller.rs".to_string(),
            entities: vec![caller.clone()],
            relations: vec![calls_relation("caller", "crate::gone::vanished")],
            imports: vec![],
        }];

        let result = link_cross_file(&files);
        assert!(
            result.iter().all(|r| r.kind != RelationKind::Calls),
            "absent qualified target must produce no Calls edge"
        );
    }

    #[test]
    fn qualified_calls_recover_all_three_callers() {
        // Mirrors the ticket acceptance at the linker layer: three qualified
        // call sites across two files all resolve to one target fn, so impact
        // would report three callers instead of one.
        let target = rust_fn("analyze_impact", "kin-review/src/impact.rs");
        let caller_review = rust_fn("review_from_diff", "kin-review/src/review.rs");
        let caller_mcp = rust_fn("handle_review", "kin-mcp/src/handlers/review.rs");

        let files = vec![
            FileParseData {
                file_path: "kin-review/src/impact.rs".to_string(),
                entities: vec![target.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "kin-review/src/review.rs".to_string(),
                entities: vec![caller_review.clone()],
                // same-crate module-qualified, twice (deduped to one edge)
                relations: vec![
                    calls_relation("review_from_diff", "impact::analyze_impact"),
                    calls_relation("review_from_diff", "impact::analyze_impact"),
                ],
                imports: vec![],
            },
            FileParseData {
                file_path: "kin-mcp/src/handlers/review.rs".to_string(),
                entities: vec![caller_mcp.clone()],
                // cross-crate crate-qualified
                relations: vec![calls_relation(
                    "handle_review",
                    "kin_review::analyze_impact",
                )],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let callers: HashSet<GraphNodeId> = result
            .iter()
            .filter(|r| r.kind == RelationKind::Calls && r.dst == GraphNodeId::Entity(target.id))
            .map(|r| r.src)
            .collect();
        assert_eq!(
            callers.len(),
            2,
            "both caller functions should link to analyze_impact, got {:?}",
            callers
        );
        assert!(callers.contains(&GraphNodeId::Entity(caller_review.id)));
        assert!(callers.contains(&GraphNodeId::Entity(caller_mcp.id)));
    }

    #[test]
    fn incremental_linker_resolves_qualified_free_fn() {
        // The daemon's live-edit path uses the incremental linker; qualified
        // calls must resolve there too (the ticket repro was a live edit).
        let caller = rust_fn("caller", "src/caller.rs");
        let target = rust_fn("run", "src/work.rs");

        let mut linker = IncrementalLinker::new();
        linker.add_file("src/caller.rs", std::slice::from_ref(&caller));
        linker.add_file("src/work.rs", std::slice::from_ref(&target));

        let files = vec![FileParseData {
            file_path: "src/caller.rs".to_string(),
            entities: vec![caller.clone()],
            relations: vec![calls_relation("caller", "crate::work::run")],
            imports: vec![],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        let edge = find_calls_edge(&result, &caller, &target)
            .expect("incremental linker should resolve the qualified free-fn call");
        assert_eq!(edge.confidence, QUALIFIED_SUFFIX_CONFIDENCE);
    }

    #[test]
    fn incremental_linker_resolves_crate_type_method() {
        let caller = rust_fn("caller", "src/caller.rs");
        let method = make_method_entity("Widget::make", "src/model.rs");

        let mut linker = IncrementalLinker::new();
        linker.add_file("src/caller.rs", std::slice::from_ref(&caller));
        linker.add_file("src/model.rs", std::slice::from_ref(&method));

        let files = vec![FileParseData {
            file_path: "src/caller.rs".to_string(),
            entities: vec![caller.clone()],
            relations: vec![calls_relation("caller", "crate::model::Widget::make")],
            imports: vec![],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        assert!(
            find_calls_edge(&result, &caller, &method).is_some(),
            "incremental linker should resolve crate::Type::method"
        );
    }

    #[test]
    fn incremental_linker_ambiguous_qualified_leaf_is_miss() {
        let caller = rust_fn("caller", "src/caller.rs");
        let run_a = rust_fn("run", "src/a.rs");
        let run_b = rust_fn("run", "src/b.rs");

        let mut linker = IncrementalLinker::new();
        linker.add_file("src/caller.rs", std::slice::from_ref(&caller));
        linker.add_file("src/a.rs", std::slice::from_ref(&run_a));
        linker.add_file("src/b.rs", std::slice::from_ref(&run_b));

        let files = vec![FileParseData {
            file_path: "src/caller.rs".to_string(),
            entities: vec![caller.clone()],
            relations: vec![calls_relation("caller", "crate::somewhere::run")],
            imports: vec![],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        assert!(
            result.iter().all(|r| r.kind != RelationKind::Calls),
            "incremental ambiguous qualified leaf must not mint a Calls edge"
        );
    }

    #[test]
    fn is_path_identifier_rejects_non_idents() {
        assert!(is_path_identifier("crate"));
        assert!(is_path_identifier("Widget"));
        assert!(is_path_identifier("_private"));
        assert!(is_path_identifier("run2"));
        assert!(!is_path_identifier(""));
        assert!(!is_path_identifier("<T>"));
        assert!(!is_path_identifier("2run"));
        assert!(!is_path_identifier("a-b"));
    }

    fn go_fn(name: &str, file_path: &str) -> Entity {
        let mut e = make_entity(name, file_path);
        e.language = LanguageId::Go;
        e
    }

    fn pinned_calls_relation(src: &str, dst: &str, import_source: &str) -> ExtractedRelation {
        ExtractedRelation {
            kind: RelationKind::Calls,
            src_name: src.to_string(),
            dst_name: dst.to_string(),
            import_source: Some(import_source.to_string()),
        }
    }

    /// Two Go packages define the same function name; the caller's relation is
    /// pinned to one package via its import source. The pinned package must
    /// win even though the other package sits first in the name bucket.
    #[test]
    fn import_pinned_call_resolves_to_pinned_package() {
        let decoy = go_fn("NewCmdCreate", "pkg/cmd/project/create/create.go");
        let target = go_fn("NewCmdCreate", "pkg/cmd/pr/create/create.go");
        let caller = go_fn("NewCmdPR", "pkg/cmd/pr/pr.go");

        let files = vec![
            // Decoy package first: bucket order would pick it without the pin.
            FileParseData {
                file_path: "pkg/cmd/project/create/create.go".to_string(),
                entities: vec![decoy.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "pkg/cmd/pr/create/create.go".to_string(),
                entities: vec![target.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "pkg/cmd/pr/pr.go".to_string(),
                entities: vec![caller.clone()],
                relations: vec![pinned_calls_relation(
                    "NewCmdPR",
                    "NewCmdCreate",
                    "github.com/cli/cli/v2/pkg/cmd/pr/create",
                )],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let edge = find_calls_edge(&result, &caller, &target)
            .expect("pinned call must resolve into the pinned package");
        assert_eq!(edge.confidence, IMPORT_PINNED_CONFIDENCE);
        assert!(
            find_calls_edge(&result, &caller, &decoy).is_none(),
            "pinned call must not bind to the same-named entity in another package"
        );
    }

    /// A bare same-package call (Go test file calling its package's function)
    /// must prefer the same-directory candidate over an earlier bucket entry
    /// from an unrelated package.
    #[test]
    fn same_package_bare_call_prefers_same_directory() {
        let decoy = go_fn("createRun", "pkg/cmd/label/create.go");
        let target = go_fn("createRun", "pkg/cmd/pr/create/create.go");
        let caller = go_fn("TestCreateRun", "pkg/cmd/pr/create/create_test.go");

        let files = vec![
            FileParseData {
                file_path: "pkg/cmd/label/create.go".to_string(),
                entities: vec![decoy.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "pkg/cmd/pr/create/create.go".to_string(),
                entities: vec![target.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "pkg/cmd/pr/create/create_test.go".to_string(),
                entities: vec![caller.clone()],
                relations: vec![calls_relation("TestCreateRun", "createRun")],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let edge = find_calls_edge(&result, &caller, &target)
            .expect("bare same-package call must resolve within its own directory");
        assert_eq!(edge.confidence, LOCALITY_DISAMBIGUATED_CONFIDENCE);
        assert!(find_calls_edge(&result, &caller, &decoy).is_none());
    }

    /// A call pinned to an external module must not bind to a same-named
    /// local entity; it stays an external reference edge.
    #[test]
    fn import_pinned_external_call_never_binds_local_name() {
        let local_decoy = go_fn("Execute", "internal/run/run.go");
        let caller = go_fn("main", "cmd/gh/main.go");

        let files = vec![
            FileParseData {
                file_path: "internal/run/run.go".to_string(),
                entities: vec![local_decoy.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "cmd/gh/main.go".to_string(),
                entities: vec![caller.clone()],
                relations: vec![pinned_calls_relation(
                    "main",
                    "Execute",
                    "github.com/spf13/cobra",
                )],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert!(
            find_calls_edge(&result, &caller, &local_decoy).is_none(),
            "externally pinned call must not mint a local consumer"
        );
        let external = result
            .iter()
            .find(|r| r.kind == RelationKind::Calls && r.src == GraphNodeId::Entity(caller.id))
            .expect("externally pinned call keeps its cross-repo reference edge");
        assert_eq!(external.confidence, EXTERNAL_REFERENCE_CONFIDENCE);
        assert_eq!(
            external.import_source.as_deref(),
            Some("github.com/spf13/cobra")
        );
    }

    /// An ambiguous bucket with no import pin and no locality signal keeps the
    /// historical first-candidate link, so signal-less repos lose no edges.
    #[test]
    fn ambiguous_bucket_without_signal_keeps_first_candidate() {
        let first = go_fn("parse", "src/x/parse.go");
        let second = go_fn("parse", "src/y/parse.go");
        let caller = go_fn("drive", "src/z/drive.go");

        let files = vec![
            FileParseData {
                file_path: "src/x/parse.go".to_string(),
                entities: vec![first.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/y/parse.go".to_string(),
                entities: vec![second.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/z/drive.go".to_string(),
                entities: vec![caller.clone()],
                relations: vec![calls_relation("drive", "parse")],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let edge = find_calls_edge(&result, &caller, &first)
            .expect("signal-less ambiguity keeps the historical first-bucket pick");
        assert_eq!(edge.confidence, 0.7);
    }

    #[test]
    fn incremental_import_pinned_call_resolves_to_pinned_package() {
        let decoy = go_fn("NewCmdCreate", "pkg/cmd/project/create/create.go");
        let target = go_fn("NewCmdCreate", "pkg/cmd/pr/create/create.go");
        let caller = go_fn("NewCmdPR", "pkg/cmd/pr/pr.go");

        let mut linker = IncrementalLinker::new();
        // Decoy first: bucket order would pick it without the pin.
        linker.add_file(
            "pkg/cmd/project/create/create.go",
            std::slice::from_ref(&decoy),
        );
        linker.add_file("pkg/cmd/pr/create/create.go", std::slice::from_ref(&target));
        linker.add_file("pkg/cmd/pr/pr.go", std::slice::from_ref(&caller));

        let files = vec![FileParseData {
            file_path: "pkg/cmd/pr/pr.go".to_string(),
            entities: vec![caller.clone()],
            relations: vec![pinned_calls_relation(
                "NewCmdPR",
                "NewCmdCreate",
                "github.com/cli/cli/v2/pkg/cmd/pr/create",
            )],
            imports: vec![],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        let edge = find_calls_edge(&result, &caller, &target)
            .expect("incremental pinned call must resolve into the pinned package");
        assert_eq!(edge.confidence, IMPORT_PINNED_CONFIDENCE);
        assert!(find_calls_edge(&result, &caller, &decoy).is_none());
    }

    #[test]
    fn incremental_same_package_bare_call_prefers_same_directory() {
        let decoy = go_fn("createRun", "pkg/cmd/label/create.go");
        let target = go_fn("createRun", "pkg/cmd/pr/create/create.go");
        let caller = go_fn("TestCreateRun", "pkg/cmd/pr/create/create_test.go");

        let mut linker = IncrementalLinker::new();
        linker.add_file("pkg/cmd/label/create.go", std::slice::from_ref(&decoy));
        linker.add_file("pkg/cmd/pr/create/create.go", std::slice::from_ref(&target));
        linker.add_file(
            "pkg/cmd/pr/create/create_test.go",
            std::slice::from_ref(&caller),
        );

        let files = vec![FileParseData {
            file_path: "pkg/cmd/pr/create/create_test.go".to_string(),
            entities: vec![caller.clone()],
            relations: vec![calls_relation("TestCreateRun", "createRun")],
            imports: vec![],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        let edge = find_calls_edge(&result, &caller, &target)
            .expect("incremental bare same-package call must resolve within its own directory");
        assert_eq!(edge.confidence, LOCALITY_DISAMBIGUATED_CONFIDENCE);
        assert!(find_calls_edge(&result, &caller, &decoy).is_none());
    }

    /// C-family sibling pair: an impl file calling into its same-directory
    /// header must not bind to a same-named duplicate in a bundled single
    /// include.
    #[test]
    fn cpp_sibling_header_beats_bundled_duplicate() {
        let mut bundled = make_entity("toString", "single_include/catch.hpp");
        bundled.language = LanguageId::Cpp;
        let mut header = make_entity("toString", "include/internal/catch_tostring.h");
        header.language = LanguageId::Cpp;
        let mut caller = make_entity("writeValue", "include/internal/catch_tostring.cpp");
        caller.language = LanguageId::Cpp;

        let files = vec![
            FileParseData {
                file_path: "single_include/catch.hpp".to_string(),
                entities: vec![bundled.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "include/internal/catch_tostring.h".to_string(),
                entities: vec![header.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "include/internal/catch_tostring.cpp".to_string(),
                entities: vec![caller.clone()],
                relations: vec![calls_relation("writeValue", "toString")],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let edge = find_calls_edge(&result, &caller, &header)
            .expect("impl file must resolve into its sibling header");
        assert_eq!(edge.confidence, LOCALITY_DISAMBIGUATED_CONFIDENCE);
        assert!(find_calls_edge(&result, &caller, &bundled).is_none());
    }

    fn cpp_entity(name: &str, file_path: &str) -> Entity {
        let mut e = make_entity(name, file_path);
        e.language = LanguageId::Cpp;
        e
    }

    fn include_import(module_path: &str) -> FileImport {
        FileImport {
            module_path: module_path.to_string(),
            specifiers: vec![],
        }
    }

    /// A caller reaching a definition through an umbrella header has no
    /// direct-import signal for the defining file; the transitive include
    /// closure must pin it over a same-named duplicate elsewhere.
    #[test]
    fn cpp_include_closure_resolves_transitive_header_target() {
        let bundled = cpp_entity("convert", "single_include/catch2/catch.hpp");
        let target = cpp_entity("convert", "include/internal/catch_tostring.h");
        let caller = cpp_entity("TestToString", "projects/SelfTest/ToStringTests.cpp");

        let files = vec![
            // Bundled duplicate first: bucket order would pick it without the
            // closure signal.
            FileParseData {
                file_path: "single_include/catch2/catch.hpp".to_string(),
                entities: vec![bundled.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "include/internal/catch_tostring.h".to_string(),
                entities: vec![target.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "include/catch.hpp".to_string(),
                entities: vec![],
                relations: vec![],
                imports: vec![include_import("internal/catch_tostring.h")],
            },
            FileParseData {
                file_path: "projects/SelfTest/ToStringTests.cpp".to_string(),
                entities: vec![caller.clone()],
                relations: vec![calls_relation("TestToString", "convert")],
                imports: vec![include_import("catch.hpp")],
            },
        ];

        let result = link_cross_file(&files);
        let edge = find_calls_edge(&result, &caller, &target)
            .expect("include closure must resolve the transitively included header");
        assert_eq!(edge.confidence, LOCALITY_DISAMBIGUATED_CONFIDENCE);
        assert!(
            find_calls_edge(&result, &caller, &bundled).is_none(),
            "closure-resolved call must not bind to the bundled duplicate"
        );
    }

    /// When both the amalgamated single include and the focused header sit in
    /// the caller's closure, the focused header (fewer defined entities) wins.
    #[test]
    fn cpp_umbrella_duplicate_loses_to_specific_header_in_closure() {
        let bundled = cpp_entity("Session", "single_include/catch2/catch.hpp");
        let bundled_extra_a = cpp_entity("Approx", "single_include/catch2/catch.hpp");
        let bundled_extra_b = cpp_entity("AutoReg", "single_include/catch2/catch.hpp");
        let target = cpp_entity("Session", "include/internal/catch_session.h");
        let caller = cpp_entity("runMain", "projects/SelfTest/MainTests.cpp");

        let files = vec![
            FileParseData {
                file_path: "single_include/catch2/catch.hpp".to_string(),
                entities: vec![bundled.clone(), bundled_extra_a, bundled_extra_b],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "include/internal/catch_session.h".to_string(),
                entities: vec![target.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "projects/SelfTest/MainTests.cpp".to_string(),
                entities: vec![caller.clone()],
                relations: vec![calls_relation("runMain", "Session")],
                imports: vec![
                    include_import("catch2/catch.hpp"),
                    include_import("internal/catch_session.h"),
                ],
            },
        ];

        let result = link_cross_file(&files);
        let edge = find_calls_edge(&result, &caller, &target)
            .expect("focused header must win over the amalgamated duplicate");
        assert_eq!(edge.confidence, LOCALITY_DISAMBIGUATED_CONFIDENCE);
        assert!(
            find_calls_edge(&result, &caller, &bundled).is_none(),
            "amalgamated single include must lose to the focused header"
        );
    }

    /// Same-named candidates in headers the caller never includes carry no
    /// closure signal; the historical first-bucket pick must survive.
    #[test]
    fn cpp_closure_ambiguity_without_signal_keeps_first_candidate() {
        let first = cpp_entity("format", "alpha/format.hpp");
        let second = cpp_entity("format", "beta/format.hpp");
        let caller = cpp_entity("render", "src/render.cpp");

        let files = vec![
            FileParseData {
                file_path: "alpha/format.hpp".to_string(),
                entities: vec![first.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "beta/format.hpp".to_string(),
                entities: vec![second.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/other.hpp".to_string(),
                entities: vec![],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/render.cpp".to_string(),
                entities: vec![caller.clone()],
                relations: vec![calls_relation("render", "format")],
                imports: vec![include_import("src/other.hpp")],
            },
        ];

        let result = link_cross_file(&files);
        let edge = find_calls_edge(&result, &caller, &first)
            .expect("signal-less closure ambiguity keeps the historical first-bucket pick");
        assert_eq!(edge.confidence, 0.7);
    }

    /// Incremental counterpart of the transitive-closure test: the umbrella's
    /// include edge was recorded in an earlier step, so resolution must walk
    /// the linker's persistent include state, not only the step-local edges.
    #[test]
    fn incremental_include_closure_resolves_transitive_header_target() {
        let bundled = cpp_entity("convert", "single_include/catch2/catch.hpp");
        let target = cpp_entity("convert", "include/internal/catch_tostring.h");
        let caller = cpp_entity("TestToString", "projects/SelfTest/ToStringTests.cpp");

        let mut linker = IncrementalLinker::new();
        // Bundled duplicate first: bucket order would pick it without the
        // closure signal.
        linker.add_file(
            "single_include/catch2/catch.hpp",
            std::slice::from_ref(&bundled),
        );
        linker.add_file(
            "include/internal/catch_tostring.h",
            std::slice::from_ref(&target),
        );
        linker.add_file("include/catch.hpp", &[]);
        linker.add_file(
            "projects/SelfTest/ToStringTests.cpp",
            std::slice::from_ref(&caller),
        );
        // Earlier step: the umbrella header was parsed and its include edge
        // recorded into persistent state.
        linker.record_file_includes(&[FileParseData {
            file_path: "include/catch.hpp".to_string(),
            entities: vec![],
            relations: vec![],
            imports: vec![include_import("internal/catch_tostring.h")],
        }]);

        // Later step: only the caller is (re)parsed.
        let files = vec![FileParseData {
            file_path: "projects/SelfTest/ToStringTests.cpp".to_string(),
            entities: vec![caller.clone()],
            relations: vec![calls_relation("TestToString", "convert")],
            imports: vec![include_import("catch.hpp")],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        let edge = find_calls_edge(&result, &caller, &target)
            .expect("persistent include state must resolve the transitive header");
        assert_eq!(edge.confidence, LOCALITY_DISAMBIGUATED_CONFIDENCE);
        assert!(find_calls_edge(&result, &caller, &bundled).is_none());
    }

    /// Incremental counterpart of the umbrella-specificity test, with the
    /// defining-file entity counts served by the incremental indexes.
    #[test]
    fn incremental_umbrella_duplicate_loses_to_specific_header_in_closure() {
        let bundled = cpp_entity("Session", "single_include/catch2/catch.hpp");
        let bundled_extra_a = cpp_entity("Approx", "single_include/catch2/catch.hpp");
        let bundled_extra_b = cpp_entity("AutoReg", "single_include/catch2/catch.hpp");
        let target = cpp_entity("Session", "include/internal/catch_session.h");
        let caller = cpp_entity("runMain", "projects/SelfTest/MainTests.cpp");

        let mut linker = IncrementalLinker::new();
        linker.add_file(
            "single_include/catch2/catch.hpp",
            &[bundled.clone(), bundled_extra_a, bundled_extra_b],
        );
        linker.add_file(
            "include/internal/catch_session.h",
            std::slice::from_ref(&target),
        );
        linker.add_file(
            "projects/SelfTest/MainTests.cpp",
            std::slice::from_ref(&caller),
        );

        let files = vec![FileParseData {
            file_path: "projects/SelfTest/MainTests.cpp".to_string(),
            entities: vec![caller.clone()],
            relations: vec![calls_relation("runMain", "Session")],
            imports: vec![
                include_import("catch2/catch.hpp"),
                include_import("internal/catch_session.h"),
            ],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        let edge = find_calls_edge(&result, &caller, &target)
            .expect("incremental focused header must win over the amalgamated duplicate");
        assert_eq!(edge.confidence, LOCALITY_DISAMBIGUATED_CONFIDENCE);
        assert!(find_calls_edge(&result, &caller, &bundled).is_none());
    }

    /// Persistent include state must evolve with reparses: when the umbrella
    /// drops its include of the focused header, the closure signal disappears
    /// and the legacy bucket-order pick returns — no edge is lost.
    #[test]
    fn incremental_include_state_evolves_with_reparse() {
        let bundled = cpp_entity("convert", "single_include/catch2/catch.hpp");
        let target = cpp_entity("convert", "include/internal/catch_tostring.h");
        let caller = cpp_entity("TestToString", "projects/SelfTest/ToStringTests.cpp");

        let mut linker = IncrementalLinker::new();
        linker.add_file(
            "single_include/catch2/catch.hpp",
            std::slice::from_ref(&bundled),
        );
        linker.add_file(
            "include/internal/catch_tostring.h",
            std::slice::from_ref(&target),
        );
        linker.add_file("include/catch.hpp", &[]);
        linker.add_file(
            "projects/SelfTest/ToStringTests.cpp",
            std::slice::from_ref(&caller),
        );
        linker.record_file_includes(&[FileParseData {
            file_path: "include/catch.hpp".to_string(),
            entities: vec![],
            relations: vec![],
            imports: vec![include_import("internal/catch_tostring.h")],
        }]);

        let caller_step = vec![FileParseData {
            file_path: "projects/SelfTest/ToStringTests.cpp".to_string(),
            entities: vec![caller.clone()],
            relations: vec![calls_relation("TestToString", "convert")],
            imports: vec![include_import("catch.hpp")],
        }];

        let before = link_cross_file_incremental(&caller_step, &linker);
        assert!(
            find_calls_edge(&before, &caller, &target).is_some(),
            "closure signal must resolve the focused header before the reparse"
        );

        // Later step: the umbrella is reparsed without the include.
        linker.record_file_includes(&[FileParseData {
            file_path: "include/catch.hpp".to_string(),
            entities: vec![],
            relations: vec![],
            imports: vec![],
        }]);

        let after = link_cross_file_incremental(&caller_step, &linker);
        let edge = find_calls_edge(&after, &caller, &bundled)
            .expect("losing the closure signal falls back to the first-bucket pick");
        assert_eq!(edge.confidence, 0.7);
        assert!(find_calls_edge(&after, &caller, &target).is_none());
    }

    /// The closure walk is depth-bounded: a definition past the bound carries
    /// no signal, so the legacy pick survives instead of an unbounded scan.
    #[test]
    fn include_closure_depth_is_bounded() {
        let decoy = cpp_entity("probe", "aux/probe.hpp");
        let chain_len = INCLUDE_CLOSURE_MAX_DEPTH + 1;
        let deep_file = format!("chain/h{:02}.hpp", chain_len - 1);
        let deep = cpp_entity("probe", &deep_file);
        let caller = cpp_entity("drive", "src/drive.cpp");

        let mut files = vec![
            FileParseData {
                file_path: "aux/probe.hpp".to_string(),
                entities: vec![decoy.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/drive.cpp".to_string(),
                entities: vec![caller.clone()],
                relations: vec![calls_relation("drive", "probe")],
                imports: vec![include_import("chain/h00.hpp")],
            },
        ];
        // h00 -> h01 -> ... -> h{chain_len-1}; the caller reaches h00 at depth
        // 1, so the deep definition sits at depth chain_len, past the bound.
        for i in 0..chain_len {
            let file_path = format!("chain/h{i:02}.hpp");
            let entities = if i == chain_len - 1 {
                vec![deep.clone()]
            } else {
                vec![]
            };
            let imports = if i + 1 < chain_len {
                vec![include_import(&format!("chain/h{:02}.hpp", i + 1))]
            } else {
                vec![]
            };
            files.push(FileParseData {
                file_path,
                entities,
                relations: vec![],
                imports,
            });
        }

        let result = link_cross_file(&files);
        let edge = find_calls_edge(&result, &caller, &decoy)
            .expect("definition past the closure bound keeps the historical pick");
        assert_eq!(edge.confidence, 0.7);
        assert!(find_calls_edge(&result, &caller, &deep).is_none());
    }
}
