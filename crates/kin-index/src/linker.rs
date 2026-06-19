// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

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
    // Sort for deterministic relation materialization.
    let sorted_universe: Vec<&Entity> = {
        let mut sorted: Vec<&Entity> = universe_entities.iter().collect();
        sorted.sort_by(|a, b| entity_link_order(a, b));
        sorted
    };
    // Step 1: Build entity indices
    //   (file_path, entity_name) -> EntityId
    let (entity_by_file_name, entity_by_name, entity_by_bare_name, entity_kind_by_id, known_files) = {
        let _span = tracing::info_span!(
            "kin.index.link_cross_file.build_entity_indices",
            universe_entities = sorted_universe.len()
        )
        .entered();
        let mut entity_by_file_name: HashMap<(&str, &str), EntityId> = HashMap::new();
        let mut entity_by_name: HashMap<&str, Vec<(&str, EntityId)>> = HashMap::new();
        let mut entity_by_bare_name: HashMap<&str, Vec<(&str, EntityId)>> = HashMap::new();
        let mut entity_kind_by_id: HashMap<EntityId, EntityKind> = HashMap::new();
        let mut known_files: HashSet<&str> = HashSet::new();

        for &entity in &sorted_universe {
            entity_kind_by_id.insert(entity.id, entity.kind);
            let Some(file_path) = entity.file_origin.as_ref().map(|path| path.0.as_str()) else {
                continue;
            };
            known_files.insert(file_path);
            entity_by_file_name.insert((file_path, &entity.name), entity.id);
            entity_by_name
                .entry(&*entity.name)
                .or_default()
                .push((file_path, entity.id));

            let bare_name = match entity.name.rfind("::") {
                Some(idx) => &entity.name[idx + 2..],
                None => match entity.name.rfind('.') {
                    Some(idx) => &entity.name[idx + 1..],
                    None => &*entity.name,
                },
            };
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

    let mut resolved = Vec::new();
    let mut seen: HashSet<(EntityId, EntityId, RelationKind)> = HashSet::new();
    let mut seen_artifact: HashSet<(GraphNodeId, GraphNodeId, RelationKind)> = HashSet::new();
    let include_graph = build_include_graph(files, &known_files);

    let total_files = files.len();
    let progress_interval = std::cmp::max(total_files / 50, 1);
    let link_start = std::time::Instant::now();

    {
        let _span = tracing::info_span!(
            "kin.index.link_cross_file.resolve_relations",
            files = files.len()
        )
        .entered();
        for (file_idx, file) in files.iter().enumerate() {
            if total_files > 50
                && (file_idx % progress_interval == 0 || file_idx + 1 == total_files)
            {
                eprint!(
                    "\r  Linking: [{}/{}] {}% | {} relations | {:.1}s",
                    file_idx + 1,
                    total_files,
                    ((file_idx + 1) * 100) / total_files,
                    resolved.len(),
                    link_start.elapsed().as_secs_f64()
                );
            }
            for rel in &file.relations {
                let src_id =
                    entity_by_file_name.get(&(file.file_path.as_str(), rel.src_name.as_str()));
                let dst_same_file =
                    entity_by_file_name.get(&(file.file_path.as_str(), rel.dst_name.as_str()));

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
                        if entity_kind_by_id.get(&dst_id) == Some(&EntityKind::Macro) {
                            if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                                resolved.push(make_relation(rel.kind, src_id, dst_id, 1.0));
                            }
                            continue;
                        }
                    }

                    if let Some(dst_id) = resolve_reachable_macro_target(
                        &file.file_path,
                        &rel.dst_name,
                        &include_graph,
                        &entity_by_file_name,
                        &entity_kind_by_id,
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
                if let Some(file_imports) = import_map.get(file.file_path.as_str()) {
                    if let Some(&(module_path, original_name)) =
                        file_imports.get(rel.dst_name.as_str())
                    {
                        if let Some(target_file) =
                            resolve_module_path(&file.file_path, module_path, &known_files)
                        {
                            let direct = entity_by_file_name
                                .get(&(target_file.as_str(), original_name))
                                .copied();
                            let dst_id = if direct.is_some() {
                                direct
                            } else if original_name == "default" {
                                // Default import: fall back to first entity in target file
                                resolve_default_export(&target_file, &sorted_universe)
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
                    if let Some((import_name, member_name)) =
                        split_member_access(rel.dst_name.as_str())
                    {
                        if let Some(&(module_path, _original_name)) = file_imports.get(import_name)
                        {
                            // Try resolving module path and looking up the member
                            if let Some(target_file) =
                                resolve_module_path(&file.file_path, module_path, &known_files)
                            {
                                if let Some(&dst_id) =
                                    entity_by_file_name.get(&(target_file.as_str(), member_name))
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

                // (c) Global name-match fallback
                let exact_candidates = entity_by_name
                    .get(rel.dst_name.as_str())
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);

                let bare_candidates = if rel.kind == RelationKind::Calls {
                    entity_by_bare_name
                        .get(rel.dst_name.as_str())
                        .map(|v| v.as_slice())
                        .unwrap_or(&[])
                } else {
                    &[]
                };

                let mut linked = false;

                // Pick the first exact candidate from a different file
                if let Some(&(_, dst_id)) = exact_candidates
                    .iter()
                    .find(|(fp, _)| *fp != file.file_path.as_str())
                {
                    if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                        resolved.push(make_relation(rel.kind, src_id, dst_id, 0.7));
                        linked = true;
                    }
                }

                // (c2) Receiver-method calls (`x.method()`) arrive as the bare method
                // name and never match (b)'s `Type::method` key. Resolve them through
                // the bare-name index only when unambiguous — exactly one method of
                // that name in another file. Ambiguous names (`new`, `run`, `get`) have
                // an unknowable receiver type, so linking every candidate would mint
                // spurious callers; leave those to the inconclusive-absence gate.
                if !linked && !bare_candidates.is_empty() {
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

                if linked {
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
        }
    }

    // Step 4: Create artifact-level import/include edges from import declarations.
    //
    // Import/include syntax belongs to the file/module surface. Do not anchor it
    // to an arbitrary "first entity" in the file; that makes the graph lie about
    // which symbol owns the dependency and drops files with no parsed entities.
    {
        let _span = tracing::info_span!(
            "kin.index.link_cross_file.build_import_edges",
            files = files.len()
        )
        .entered();
        for file in files {
            for imp in &file.imports {
                if let Some(rel) = make_artifact_import_relation(&file.file_path, imp, &known_files)
                {
                    let key = (rel.src, rel.dst, rel.kind);
                    if seen_artifact.insert(key) {
                        resolved.push(rel);
                    }
                }
            }
        }
    }

    if total_files > 0 {
        eprintln!(); // newline after \r progress
    }
    debug!(resolved = resolved.len(), "cross-file linking complete");
    resolved
}

fn build_include_graph<S>(
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
    /// entity_id -> kind
    pub entity_kind_by_id: HashMap<EntityId, EntityKind>,
    /// Set of all known files
    pub known_files: HashSet<String>,
    /// file_path -> Vec<(EntityId, Visibility)>
    pub entities_by_file: HashMap<String, Vec<(EntityId, Visibility)>>,
}

impl IncrementalLinker {
    pub fn new() -> Self {
        Self {
            entity_by_file_name: HashMap::new(),
            entity_by_name: HashMap::new(),
            entity_kind_by_id: HashMap::new(),
            known_files: HashSet::new(),
            entities_by_file: HashMap::new(),
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
            }
        }

        self.entities_by_file.remove(file_path);
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
    let include_graph = build_include_graph(files, &linker.known_files);

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

            // (c) Global name-match fallback
            if let Some(candidates) = linker.entity_by_name.get(&rel.dst_name) {
                let other_file_match = candidates.iter().find(|(fp, _)| fp != &file.file_path);

                if let Some((_, dst_id)) = other_file_match {
                    if add_deduped(&mut seen, src_id, *dst_id, rel.kind) {
                        resolved.push(make_relation(rel.kind, src_id, *dst_id, 0.7));
                    }
                }
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
}
