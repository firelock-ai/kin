// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::Hash;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::debug;

use sha2::{Digest, Sha256};

use kin_model::{
    ArtifactId, Entity, EntityId, EntityKind, EntityRole, FilePathId, GraphNodeId, LanguageId,
    ParseCompleteness, Relation, RelationEvidence, RelationId, RelationKind, RelationOrigin,
    SourceSpan, Visibility,
};
use kin_parser::{
    is_call_extraction_incomplete_marker, is_python_builtin_name, CallArgShape, ExtractedRelation,
    FileImport, RelationSyntacticRole,
};

use crate::error::{IndexError, Result as IndexResult};
use crate::resolution::RECEIVER_NAME_FANOUT_CONFIDENCE;

/// Graph-assigned artifact identities keyed by repository-relative path.
///
/// Linking never derives identity from a path. Callers must resolve or allocate
/// these IDs through graph authority before asking the linker to create
/// artifact-level relations.
pub type ArtifactIdentityMap = HashMap<String, ArtifactId>;

fn require_artifact_identities<'a>(
    paths: impl IntoIterator<Item = &'a str>,
    artifact_ids: &ArtifactIdentityMap,
) -> IndexResult<()> {
    for path in paths {
        if !artifact_ids.contains_key(path) {
            return Err(IndexError::Graph(format!(
                "missing graph-assigned artifact identity for {path}"
            )));
        }
    }
    Ok(())
}

/// Persisted provenance marker for call-shape evidence produced by a linker
/// that preserves every occurrence on one logical `(src, dst, Calls)` edge.
///
/// v0.2.15 could persist one shaped occurrence while silently dropping later
/// calls from the same caller to the same target. Those legacy records already
/// have `call_shape: Some(_)`, so shape presence alone cannot certify complete
/// evidence after an upgrade. New full-file batch and incremental linking stamp
/// every shaped record with this marker; review requires it before a rename may
/// be neutralized. `parser_rule` is defaultable in storage, making an older
/// record's absent marker a conservative, backward-compatible `unknown`.
pub const CALL_SHAPE_EVIDENCE_AGGREGATION_V1: &str = "call_shape_aggregation_v1";

/// Persisted fail-closed marker for call evidence recovered from a parse that
/// was not fully valid. A recovered tree can omit call sites, so even a shaped
/// occurrence cannot certify that every call on the logical edge was observed.
/// Review treats this explicit unshaped record as unknown/blocking evidence.
pub const CALL_SHAPE_EVIDENCE_INCOMPLETE_PARSE_V1: &str = "call_shape_incomplete_parse_v1";

/// Persisted fail-closed marker for a syntax-valid file whose adapter could not
/// represent every call expression with a statically proven named target. This
/// is deliberately distinct from parse recovery: the source parsed, but call
/// extraction or receiver resolution was not exhaustive, so shaped occurrences
/// cannot certify a parameter rename.
pub const CALL_SHAPE_EVIDENCE_INCOMPLETE_EXTRACTION_V1: &str =
    "call_shape_incomplete_extraction_v1";

/// File-level certificate that the parser observed the complete source file.
/// Ref-scoped review requires this positive evidence because old graph history
/// has no way to distinguish a full parse from a recovered parse that omitted
/// every relevant call.
/// Marks the import half of a file's coverage certificate.
///
/// Carried as its own evidence entry beside the call-coverage one rather than as
/// its own relation, because a per-file certificate is an artifact self-loop and
/// `stable_relation_node_id` hashes `(src, dst, kind)`, so a sibling self-loop of
/// the same kind would collide with it.
///
/// `occurrence_count` holds the import STATEMENTS the parser read, and `token`
/// holds how many of them resolved to a file this repository holds, rendered as
/// a decimal string. Both are in the `FileImport` unit, which is the unit
/// `parsed_import_statements` counts in and the only unit in which the ratio
/// means what its label says.
pub const IMPORT_RESOLUTION_COVERAGE_V1: &str = "import_resolution_coverage_v1";

pub const CALL_SHAPE_PARSE_COVERAGE_FULL_V1: &str = "call_shape_parse_coverage_full_v1";

/// File-level marker that call-site coverage is incomplete or unknown.
pub const CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1: &str = "call_shape_parse_coverage_incomplete_v1";

/// File-level marker that syntax was valid but named-call extraction or
/// receiver resolution was not exhaustive.
pub const CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1: &str =
    "call_shape_extraction_coverage_incomplete_v1";

/// Provenance marker for an `Overrides` edge the linker derived from syntax
/// alone: the class declares a base, that base name resolved to a class entity
/// through the same tiers an inherited-method call resolves through, and both
/// classes define a member of the same leaf name. It records that no language
/// server was involved, which is what separates this edge from an
/// `Overrides` a type hierarchy proved.
pub const OVERRIDE_EVIDENCE_RESOLVED_BASE_V1: &str = "override_resolved_base_v1";

/// Per-file parse completeness supplied by ingestion paths that have parser
/// state available. Kept separate from [`FileParseData`] so adding the safety
/// signal does not break downstream struct literals for the published API.
pub type FileParseCompletenessMap = HashMap<String, ParseCompleteness>;

const FULL_PARSE_COMPLETENESS: ParseCompleteness = ParseCompleteness::Full;

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
#[derive(Debug, Clone)]
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
///
/// The four ECMAScript module extensions sit with the other JavaScript ones
/// because Node resolves `./x` to `x.mjs` or `x.cjs` exactly as it resolves it
/// to `x.js`. Leaving them out made every `.mjs`/`.cjs` module in a repository
/// unreachable through a relative specifier, which is the whole import surface
/// of a modern ESM package.
const MODULE_EXTENSIONS: &[&str] = &[
    "ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts", "py", "rs", "go", "h", "hh", "hpp", "hxx",
];

/// Index filenames to try when resolving a directory module path.
const INDEX_FILENAMES: &[&str] = &[
    "index.ts",
    "index.tsx",
    "index.js",
    "index.jsx",
    "index.mjs",
    "index.cjs",
    "mod.rs",
];

/// Source extensions a specifier's written JavaScript extension can stand for.
///
/// Node ESM requires the extension in the specifier, and a TypeScript package
/// compiled for NodeNext writes `./util.js` in source whose file on disk is
/// `util.ts`. The specifier names the emitted artifact; the repository holds the
/// input. Substituting only within a pair keeps this a rewrite of one known
/// emit convention rather than a search for a same-stemmed file.
const EMITTED_EXTENSION_SOURCES: &[(&str, &[&str])] = &[
    ("js", &["ts", "tsx"]),
    ("jsx", &["tsx"]),
    ("mjs", &["mts"]),
    ("cjs", &["cts"]),
];

/// Resolve cross-file relations across all parsed files.
///
/// This function:
/// 1. Builds entity indices (by file+name and by name alone)
/// 2. Builds an import map (local_name -> source module + original name)
/// 3. Resolves module paths to actual file paths
/// 4. Resolves each ExtractedRelation to entity-ID-based Relations
///
/// Returns a deduplicated list of resolved Relations.
pub fn link_cross_file(
    files: &[FileParseData],
    artifact_ids: &ArtifactIdentityMap,
) -> IndexResult<Vec<Relation>> {
    let files: Vec<&FileParseData> = files.iter().collect();
    link_cross_file_internal(&files, artifact_ids, None)
}

/// Resolve cross-file relations with explicit parser completeness.
///
/// Unlike the compatibility [`link_cross_file`] entry point, this path emits a
/// positive or negative file-level call-coverage certificate even when parser
/// recovery omitted every call relation in that file.
pub fn link_cross_file_with_completeness(
    files: &[FileParseData],
    artifact_ids: &ArtifactIdentityMap,
    completeness: &FileParseCompletenessMap,
) -> IndexResult<Vec<Relation>> {
    let files: Vec<&FileParseData> = files.iter().collect();
    link_cross_file_internal(&files, artifact_ids, Some(completeness))
}

/// Resolve cross-file relations for files the caller already holds by reference.
///
/// Replaying history reuses one parsed result per artifact across every commit
/// that leaves the file untouched, so it holds borrowed files and owns no
/// contiguous slice to hand over. Linking from references lets it link a tree
/// without copying every entity, relation, and import in the repository, which
/// it would otherwise repeat once per commit for the whole of history.
pub fn link_cross_file_borrowed_with_completeness(
    files: &[&FileParseData],
    artifact_ids: &ArtifactIdentityMap,
    completeness: &FileParseCompletenessMap,
) -> IndexResult<Vec<Relation>> {
    link_cross_file_internal(files, artifact_ids, Some(completeness))
}

fn link_cross_file_internal(
    files: &[&FileParseData],
    artifact_ids: &ArtifactIdentityMap,
    completeness: Option<&FileParseCompletenessMap>,
) -> IndexResult<Vec<Relation>> {
    let _span = tracing::info_span!("kin.index.link_cross_file", files = files.len()).entered();
    // The universe is exactly the entities `files` already own, and linking only
    // ever reads it: `build_link_context` reduces it to references before doing
    // anything else. Borrowing them in place rather than copying the whole
    // semantic universe matters because the historical fold links once per
    // commit, so this ran once per commit over every entity in the repository.
    let universe_entities: Vec<&Entity> =
        files.iter().flat_map(|file| file.entities.iter()).collect();
    link_cross_file_against_entity_refs(files, &universe_entities, artifact_ids, completeness)
}

/// Resolve cross-file relations while carrying parser-emitted tests alongside the input.
pub fn link_cross_file_with_tests(
    files: &[FileParseDataWithTests],
    artifact_ids: &ArtifactIdentityMap,
) -> IndexResult<Vec<Relation>> {
    let linkable: Vec<FileParseData> = files
        .iter()
        .map(|file| FileParseData {
            file_path: file.file_path.clone(),
            entities: file.entities.clone(),
            relations: file.relations.clone(),
            imports: file.imports.clone(),
        })
        .collect();
    link_cross_file(&linkable, artifact_ids)
}

/// Resolve cross-file relations while retaining parser tests and explicit
/// parse completeness.
pub fn link_cross_file_with_tests_and_completeness(
    files: &[FileParseDataWithTests],
    artifact_ids: &ArtifactIdentityMap,
    completeness: &FileParseCompletenessMap,
) -> IndexResult<Vec<Relation>> {
    let linkable: Vec<FileParseData> = files
        .iter()
        .map(|file| FileParseData {
            file_path: file.file_path.clone(),
            entities: file.entities.clone(),
            relations: file.relations.clone(),
            imports: file.imports.clone(),
        })
        .collect();
    link_cross_file_with_completeness(&linkable, artifact_ids, completeness)
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
/// Shared by the batch [`link_cross_file`] entity index, the
/// [`IncrementalLinker`] bare-name index, and the live reconcile path's
/// destination-name evidence so all three derive receiver-method leaf names
/// identically. A divergence here would resolve the same call to different
/// entities across the two linkers, or let a reconcile retire an edge whose
/// destination the file still names under its qualified spelling.
pub fn bare_entity_name(name: &str) -> &str {
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
    artifact_ids: &ArtifactIdentityMap,
) -> IndexResult<Vec<Relation>> {
    link_cross_file_against_entities_internal(files, universe_entities, artifact_ids, None)
}

/// Resolve a parsed subset against a broader entity universe while honoring
/// explicit parser completeness.
pub fn link_cross_file_against_entities_with_completeness(
    files: &[FileParseData],
    universe_entities: &[Entity],
    artifact_ids: &ArtifactIdentityMap,
    completeness: &FileParseCompletenessMap,
) -> IndexResult<Vec<Relation>> {
    link_cross_file_against_entities_internal(
        files,
        universe_entities,
        artifact_ids,
        Some(completeness),
    )
}

fn link_cross_file_against_entities_internal(
    files: &[FileParseData],
    universe_entities: &[Entity],
    artifact_ids: &ArtifactIdentityMap,
    completeness: Option<&FileParseCompletenessMap>,
) -> IndexResult<Vec<Relation>> {
    let files: Vec<&FileParseData> = files.iter().collect();
    let universe_entities: Vec<&Entity> = universe_entities.iter().collect();
    link_cross_file_against_entity_refs(&files, &universe_entities, artifact_ids, completeness)
}

/// Resolve cross-file relations against files and a universe the caller holds.
///
/// Every entry point funnels here holding both by reference, so no path copies
/// parsed files or the entity universe to satisfy this signature.
fn link_cross_file_against_entity_refs(
    files: &[&FileParseData],
    universe_entities: &[&Entity],
    artifact_ids: &ArtifactIdentityMap,
    completeness: Option<&FileParseCompletenessMap>,
) -> IndexResult<Vec<Relation>> {
    let _span = tracing::info_span!(
        "kin.index.link_cross_file_against_entities",
        files = files.len(),
        universe_entities = universe_entities.len()
    )
    .entered();

    let ctx = build_link_context(files, universe_entities);
    require_artifact_identities(ctx.known_files.iter().copied(), artifact_ids)?;

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
                let relations = resolve_one_file(file, &ctx, completeness);
                if shows_progress_bar(total_files) {
                    let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    let total =
                        found.fetch_add(relations.len(), Ordering::Relaxed) + relations.len();
                    if done.is_multiple_of(progress_interval) || done == total_files {
                        draw_progress(format_args!(
                            "\r  Linking: [{}/{}] {}% | {} relations | {:.1}s",
                            done,
                            total_files,
                            (done * 100) / total_files,
                            total,
                            link_start.elapsed().as_secs_f64()
                        ));
                    }
                }
                relations
            })
            .collect()
    };

    let resolved = merge_resolved(per_file_relations, files, &ctx, artifact_ids, completeness);

    if shows_progress_bar(total_files) {
        draw_progress(format_args!("\n")); // newline after \r progress
    }
    debug!(resolved = resolved.len(), "cross-file linking complete");
    Ok(resolved)
}

/// Read-only indices shared across per-file relation resolution.
struct LinkContext<'a> {
    sorted_universe: Vec<&'a Entity>,
    entity_by_file_name: HashMap<(&'a str, &'a str), EntityId>,
    entity_by_name: HashMap<&'a str, Vec<(&'a str, EntityId)>>,
    entity_by_bare_name: HashMap<&'a str, Vec<(&'a str, EntityId)>>,
    entity_kind_by_id: HashMap<EntityId, EntityKind>,
    /// Parser-reported language for every entity. Blind name/locality
    /// inference must fail closed when either side is absent and may only
    /// connect equal or explicitly compatible language families.
    entity_language_by_id: HashMap<EntityId, LanguageId>,
    /// C/C++ callee id -> the argument-count bounds parsed from its signature.
    /// Absent for a callee whose language does not carry call arity or whose
    /// parameter list could not be read, so the linker prunes an overloaded
    /// callee's arity-incompatible candidates without ever pruning on missing
    /// evidence.
    entity_arity_by_id: HashMap<EntityId, ArityBounds>,
    /// Project role of every entity. A production call site must not resolve to
    /// a test entity while a production candidate of the same name exists, so
    /// the same-name fan-out tiers need role in hand at resolution time.
    entity_role_by_id: HashMap<EntityId, EntityRole>,
    entity_count_by_file: HashMap<&'a str, usize>,
    known_files: HashSet<&'a str>,
    import_map: HashMap<&'a str, HashMap<&'a str, (&'a str, &'a str)>>,
    include_graph: HashMap<String, Vec<String>>,
    /// (file, class name) -> that class's declared base names, lexicographically
    /// sorted, deduped. Backs inheritance-aware receiver-method resolution;
    /// keyed per file because class names repeat across a repo (django alone
    /// has dozens of `Command` classes).
    class_bases_by_file_class: HashMap<(&'a str, &'a str), Vec<&'a str>>,
    /// (file, class name, attribute) -> the type name that class's body
    /// declares for that attribute.
    ///
    /// This is the repository-wide half of a two-hop receiver. A call written
    /// `r.connection.send(...)` under `r: Response` arrives owner-qualified as
    /// `Response.connection.send`, and the declaration settling `connection`
    /// lives on `Response` in a file the caller may never open. Keyed per file
    /// because class names repeat across a repository, and the caller resolves
    /// its root type to one class before asking.
    declared_attribute_types: HashMap<(&'a str, &'a str, &'a str), &'a str>,
}

/// Whether two parser-reported languages may participate in a relation inferred
/// solely from a name or locality heuristic.
///
/// Cross-language relations need stronger evidence (an import/include/module
/// pin, a parser-qualified path, or an explicit hierarchy edge). Keeping this
/// compatibility list narrow prevents an unrelated same-name symbol in another
/// language from becoming a fabricated dependency.
fn blind_inference_languages_compatible(src: LanguageId, dst: LanguageId) -> bool {
    blind_inference_language_is_known(src)
        && blind_inference_language_is_known(dst)
        && (src == dst
            || matches!(
                (src, dst),
                (LanguageId::C, LanguageId::Cpp)
                    | (LanguageId::Cpp, LanguageId::C)
                    | (LanguageId::JavaScript, LanguageId::TypeScript)
                    | (LanguageId::TypeScript, LanguageId::JavaScript)
                    | (LanguageId::Java, LanguageId::Kotlin)
                    | (LanguageId::Kotlin, LanguageId::Java)
            ))
}

/// Keep a future `Unknown`/opaque language marker out of blind inference even
/// when both endpoints carry that same marker. Unsupported artifacts retain
/// artifact-level membership/search benefits without gaining fabricated
/// entity relations.
#[allow(unreachable_patterns)]
fn blind_inference_language_is_known(language: LanguageId) -> bool {
    matches!(
        language,
        LanguageId::TypeScript
            | LanguageId::JavaScript
            | LanguageId::Python
            | LanguageId::Go
            | LanguageId::Java
            | LanguageId::Rust
            | LanguageId::C
            | LanguageId::Cpp
            | LanguageId::CSharp
            | LanguageId::Ruby
            | LanguageId::Php
            | LanguageId::Swift
            | LanguageId::Kotlin
            | LanguageId::Hcl
    )
}

/// Fail-closed language gate for blind inference. Missing language evidence is
/// not permission to connect two entities.
fn blind_inference_target_allowed(
    src: EntityId,
    dst: EntityId,
    languages: &HashMap<EntityId, LanguageId>,
) -> bool {
    languages
        .get(&src)
        .zip(languages.get(&dst))
        .map(|(&src, &dst)| blind_inference_languages_compatible(src, dst))
        .unwrap_or(false)
}

fn build_link_context<'a>(
    files: &[&'a FileParseData],
    universe_entities: &[&'a Entity],
) -> LinkContext<'a> {
    // Sort for deterministic relation materialization.
    let sorted_universe: Vec<&'a Entity> = {
        let mut sorted: Vec<&'a Entity> = universe_entities.to_vec();
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
        entity_language_by_id,
        entity_arity_by_id,
        entity_role_by_id,
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
        let mut entity_language_by_id: HashMap<EntityId, LanguageId> = HashMap::new();
        let mut entity_arity_by_id: HashMap<EntityId, ArityBounds> = HashMap::new();
        let mut entity_role_by_id: HashMap<EntityId, EntityRole> = HashMap::new();
        let mut entity_count_by_file: HashMap<&str, usize> = HashMap::new();
        let mut known_files: HashSet<&str> = HashSet::new();

        for &entity in &sorted_universe {
            entity_kind_by_id.insert(entity.id, entity.kind);
            entity_language_by_id.insert(entity.id, entity.language);
            entity_role_by_id.insert(entity.id, entity.role);
            let Some(file_path) = entity.file_origin.as_ref().map(|path| path.0.as_str()) else {
                continue;
            };
            known_files.insert(file_path);
            *entity_count_by_file.entry(file_path).or_insert(0) += 1;
            let slot_free = entity_by_file_name
                .get(&(file_path, entity.name.as_str()))
                .and_then(|occupant| entity_kind_by_id.get(occupant))
                .is_none_or(|occupant| file_name_slot_admits(entity.kind, *occupant));
            if slot_free {
                entity_by_file_name.insert((file_path, &entity.name), entity.id);
            }
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

            if let Some(bounds) = callee_arity_bounds(entity) {
                entity_arity_by_id.insert(entity.id, bounds);
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
            entity_language_by_id,
            entity_arity_by_id,
            entity_role_by_id,
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

    // Step 3: class hierarchy from parser-emitted Extends relations, keyed per
    // (file, class). Bases are sorted lexicographically — NOT declaration
    // order — because the reopen path rehydrates this index from committed
    // graph edges, which carry no declaration order; one uniform order keeps
    // cold, incremental, and reopened graphs resolving identically.
    let mut class_bases_by_file_class: HashMap<(&str, &str), Vec<&str>> = HashMap::new();
    for file in files {
        for rel in &file.relations {
            if rel.kind != RelationKind::Extends {
                continue;
            }
            let bases = class_bases_by_file_class
                .entry((file.file_path.as_str(), rel.src_name.as_str()))
                .or_default();
            if !bases.contains(&rel.dst_name.as_str()) {
                bases.push(rel.dst_name.as_str());
            }
        }
    }
    for bases in class_bases_by_file_class.values_mut() {
        bases.sort_unstable();
    }

    // Step 4: the declared type of every class attribute, from the reference
    // edge the annotation already produced. Two declarations of one attribute
    // leave it out entirely rather than picking one, because an ambiguous
    // entry answers a two-hop join with a fabricated edge and the missing edge
    // it replaces is the safer wrong answer.
    let declared_attribute_types = build_declared_attribute_types(files.iter().copied());

    LinkContext {
        sorted_universe,
        entity_by_file_name,
        entity_by_name,
        entity_by_bare_name,
        entity_kind_by_id,
        entity_language_by_id,
        entity_arity_by_id,
        entity_role_by_id,
        entity_count_by_file,
        known_files,
        import_map,
        include_graph,
        class_bases_by_file_class,
        declared_attribute_types,
    }
}

/// (file, class, attribute) -> declared type name, read off the reference edges
/// a class body's own annotations produced.
///
/// The parser stamps the attribute onto that edge, so nothing is re-parsed
/// here and no edge is invented: the table is a second index over relations the
/// graph already holds. An attribute two annotations in one class disagree
/// about is dropped, which is the same fail-closed rule the base-class index
/// applies to an ambiguous name.
fn build_declared_attribute_types<'a, I>(files: I) -> HashMap<(&'a str, &'a str, &'a str), &'a str>
where
    I: IntoIterator<Item = &'a FileParseData>,
{
    let mut declared: HashMap<(&'a str, &'a str, &'a str), &'a str> = HashMap::new();
    let mut ambiguous: HashSet<(&'a str, &'a str, &'a str)> = HashSet::new();
    for file in files {
        for rel in &file.relations {
            if rel.kind != RelationKind::References {
                continue;
            }
            let Some(attribute) = rel.receiver.as_deref().filter(|a| !a.is_empty()) else {
                continue;
            };
            if rel.src_name.is_empty() || rel.dst_name.is_empty() {
                continue;
            }
            let key = (file.file_path.as_str(), rel.src_name.as_str(), attribute);
            match declared.get(&key) {
                Some(seen) if *seen == rel.dst_name.as_str() => {}
                Some(_) => {
                    ambiguous.insert(key);
                }
                None => {
                    declared.insert(key, rel.dst_name.as_str());
                }
            }
        }
    }
    for key in ambiguous {
        declared.remove(&key);
    }
    declared
}

/// The method a two-hop declared receiver dispatches to, or `None` when either
/// declaration is missing.
///
/// Three lookups, each of which must succeed on something the source writes
/// down. The root type resolves to one class through the CALLING file's
/// imports; that class's own body must declare the attribute; and the
/// attribute's type resolves to one class through the DECLARING file's
/// imports, which is where a type-only import of it lives. Nothing is inferred
/// from an assignment anywhere along the way, so a repository that annotates
/// nothing gains no edges and loses none.
fn resolve_two_hop_declared_method(
    calling_file: &str,
    root_type: &str,
    attribute: &str,
    method: &str,
    ctx: &LinkContext<'_>,
) -> Option<EntityId> {
    let (root_file, root_class) = locate_base_class(calling_file, root_type, ctx)?;
    let attribute_type =
        ctx.declared_attribute_types
            .get(&(root_file.as_str(), root_class.as_str(), attribute))?;
    let (owner_file, owner_class) = locate_base_class(&root_file, attribute_type, ctx)?;
    resolve_declared_method(&owner_file, &owner_class, method, ctx)
}

/// Resolve the name-based relations of a single file into entity-ID relations.
///
/// All reads are against the shared read-only [`LinkContext`]; the only mutable
/// state is a file-local relation accumulator, so this is pure with respect to
/// other files.
fn resolve_one_file(
    file: &FileParseData,
    ctx: &LinkContext<'_>,
    completeness: Option<&FileParseCompletenessMap>,
) -> Vec<Relation> {
    let mut resolved = Vec::new();
    let mut relation_indices = HashMap::new();
    let call_extraction_complete = !file
        .relations
        .iter()
        .any(is_call_extraction_incomplete_marker);
    let parse_completeness = completeness
        .and_then(|by_file| by_file.get(&file.file_path))
        .unwrap_or(&FULL_PARSE_COMPLETENESS);
    let caller_file = FilePathId::new(&file.file_path);
    let make_relation = |rel: &ExtractedRelation, src, dst, confidence| {
        make_relation(
            rel,
            src,
            dst,
            confidence,
            &caller_file,
            parse_completeness,
            call_extraction_complete,
        )
    };
    // Lazily resolved once per file: only ambiguous name buckets need them.
    let mut caller_import_targets: Option<HashSet<String>> = None;
    let mut caller_include_closure: Option<HashMap<String, usize>> = None;

    for rel in &file.relations {
        if is_call_extraction_incomplete_marker(rel) {
            continue;
        }
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

        // Positional arity the call's overloads are pruned by, `None` when the
        // shape is absent or splat-widened (fail-open). Resolved once per
        // relation and threaded through every same-name fan-out tier below.
        let call_arity = call_positional_arity(&rel.call_shape);

        if rel.kind == RelationKind::UsesMacro {
            if let Some(&dst_id) = dst_same_file {
                if ctx.entity_kind_by_id.get(&dst_id) == Some(&EntityKind::Macro) {
                    accumulate_relation(
                        &mut resolved,
                        &mut relation_indices,
                        make_relation(rel, src_id, dst_id, 1.0),
                    );
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
                accumulate_relation(
                    &mut resolved,
                    &mut relation_indices,
                    make_relation(rel, src_id, dst_id, 0.95),
                );
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

        // (a0) Receiver-scoped resolution. An attribute call carries its
        // receiver as written; the calling file's imports say whether that
        // receiver is a module or a value, and that decides which entities can
        // possibly be the destination. Narrowest resolution wins: a receiver
        // bound to a repo-local module yields exactly one edge, and a receiver
        // bound to a module outside the repo yields no local edge at all rather
        // than a repo-wide guess.
        let receiver_scope = rel
            .receiver
            .as_deref()
            .filter(|receiver| rel.kind == RelationKind::Calls && !receiver.is_empty())
            .map(|receiver| {
                (
                    receiver,
                    classify_receiver(
                        receiver,
                        &file.file_path,
                        ctx.import_map.get(file.file_path.as_str()),
                        &ctx.known_files,
                    ),
                )
            });
        let mut receiver_is_object = false;
        if let Some((receiver, scope)) = receiver_scope.as_ref() {
            let receiver_root = receiver.split('.').next().unwrap_or(receiver);
            match scope {
                ReceiverScope::Module(target_file) => {
                    if let Some(dst_id) = resolve_receiver_module_target(
                        target_file.as_str(),
                        receiver_root,
                        rel.dst_name.as_str(),
                        ctx.import_map.get(file.file_path.as_str()),
                        &ctx.import_map,
                        &ctx.known_files,
                        |target, name| ctx.entity_by_file_name.get(&(target, name)).copied(),
                    ) {
                        accumulate_relation(
                            &mut resolved,
                            &mut relation_indices,
                            make_relation(rel, src_id, dst_id, RECEIVER_MODULE_CONFIDENCE),
                        );
                        continue;
                    }
                }
                ReceiverScope::ExternalModule => {}
                ReceiverScope::Object => receiver_is_object = true,
            }
            if !receiver_is_object {
                // The receiver names a module, and that module does not define
                // this callee here. Binding the bare leaf to a same-named
                // symbol somewhere else in the repo would mint a consumer the
                // source never had, so stop at the cross-repo placeholder.
                if let Some(external) =
                    make_external_reference_relation(rel, src_id, &file.file_path, &ctx.known_files)
                {
                    accumulate_relation(&mut resolved, &mut relation_indices, external);
                }
                continue;
            }
        }

        // (a) Same-file resolution. A same-file entity still wins and is emitted
        // first at full confidence, but it is frequently a declaration/prototype
        // whose definition lives in another file; when cross-file entities share
        // the exact name, also fan out to them (bounded so the same-file target
        // plus its cross-file twins stay within the cap) so the real definition
        // is linked, not just the local stub. Cross-file twins are name-inferred,
        // so they carry the (c) name-match confidence (0.7), below the
        // parser-certain same-file edge (1.0).
        //
        // A call through an object skips this tier: the leaf name is a member
        // name, and a same-file free function that happens to share it is a
        // decoy, not the destination.
        if let Some(&dst_id) = dst_same_file.filter(|_| !receiver_is_object) {
            accumulate_relation(
                &mut resolved,
                &mut relation_indices,
                make_relation(rel, src_id, dst_id, 1.0),
            );
            let mut cross_file_twins: HashSet<EntityId> = HashSet::new();
            distinct_cross_file_targets(
                ctx.entity_by_name.get(rel.dst_name.as_str()),
                file.file_path.as_str(),
                &mut cross_file_twins,
            );
            cross_file_twins.retain(|dst_id| {
                blind_inference_target_allowed(src_id, *dst_id, &ctx.entity_language_by_id)
            });
            let cross_file_twins =
                prune_ids_by_arity(cross_file_twins, call_arity, &ctx.entity_arity_by_id);
            let cross_file_twins =
                narrow_candidates_by_role(src_id, cross_file_twins, &ctx.entity_role_by_id);
            if !cross_file_twins.is_empty() && cross_file_twins.len() < AMBIGUOUS_CALL_FANOUT_CAP {
                for cross_id in sorted_fanout_targets(cross_file_twins) {
                    accumulate_relation(
                        &mut resolved,
                        &mut relation_indices,
                        make_relation(rel, src_id, cross_id, 0.7),
                    );
                }
            }
            continue;
        }

        // (a1) Python builtin gate. `open(path)`, `len(items)` and the rest of
        // the builtins table are bound by the interpreter, not by this
        // repository, and the same-file tier above has already given a local
        // definition its win. Every tier below answers by matching the name
        // somewhere else in the repo, so without this the one entity in the
        // graph carrying that name captures the call.
        if is_unbound_python_builtin_call(
            rel,
            src_id,
            file,
            dst_same_file.is_some(),
            ctx.import_map.get(file.file_path.as_str()),
            &ctx.entity_language_by_id,
        ) {
            debug!(
                src = %rel.src_name,
                dst = %rel.dst_name,
                file = %file.file_path,
                "linker: bare Python builtin call the file neither defines nor imports, leaving unlinked"
            );
            continue;
        }

        // (a2) Inheritance-aware receiver-method resolution. The Python adapter
        // emits `self.m()` / `cls.m()` class-qualified (`EnclosingClass.m`), so
        // when the owner half names a class in this file — i.e. the parser
        // pinned the dispatch class — and (a) found no local override, walk the
        // class's Extends chain to the defining ancestor. That edge is dispatch
        // evidence and must not fall through to the blind bare-name fan-out.
        // When the walk finds nothing in-graph (builtin/external base, dynamic
        // hierarchy), the call continues through the tiers below as its bare
        // leaf, so recall never drops below the pre-qualification behavior.
        // Dotted callees whose owner is NOT a local class (namespace members
        // like `util.finalize()`) skip this tier untouched.
        let mut dst_lookup: &str = rel.dst_name.as_str();
        // A tier that declines must hand the call back exactly as it arrived.
        // The two-hop owner half is a name the PARSER wrote from declarations
        // (`Response.connection.send`), not a path the source spells, so when
        // no declaration settles it every tier below has to see the bare leaf
        // the call would otherwise have carried. Without this the dotted name
        // reached tier (d), whose cross-repo placeholder refuses a dotted
        // symbol, and four real unresolved-receiver edges in requests
        // disappeared instead of one appearing.
        let mut declined_two_hop: Option<ExtractedRelation> = None;
        if rel.kind == RelationKind::Calls {
            if let Some((owner, method)) = split_owner_method(rel.dst_name.as_str()) {
                let owner_is_class = ctx
                    .entity_by_file_name
                    .get(&(file.file_path.as_str(), owner))
                    .map(|id| is_class_like(ctx.entity_kind_by_id.get(id)))
                    .unwrap_or(false);
                if owner_is_class {
                    // (a2a) The owner half came from the receiver's DECLARED
                    // type and that type names a class right here, so the
                    // method the class declares is the destination the source
                    // wrote down. The inheritance walk below starts at the
                    // bases on the documented assumption that an earlier tier
                    // already gave a same-file own method its win, and for a
                    // receiver-typed call none did: tier (a) passes over the
                    // same-file entity precisely because the receiver is an
                    // object. Without this tier the call reaches nothing able
                    // to look inside its own file — (b), (c) and (c4) are
                    // skipped for an object receiver and (c2) drops same-file
                    // candidates — and `ingest_directory(database: Database)`
                    // calling `database.upsert_note()` in the file that
                    // declares `Database` produced no edge at all.
                    if rel.receiver.is_some() {
                        if let Some(dst_id) =
                            resolve_own_method(&file.file_path, owner, method, ctx)
                        {
                            accumulate_relation(
                                &mut resolved,
                                &mut relation_indices,
                                make_relation(rel, src_id, dst_id, RECEIVER_TYPE_CONFIDENCE),
                            );
                            continue;
                        }
                    }
                    if let Some(dst_id) =
                        resolve_inherited_method(&file.file_path, owner, method, ctx)
                    {
                        accumulate_relation(
                            &mut resolved,
                            &mut relation_indices,
                            make_relation(rel, src_id, dst_id, INHERITED_METHOD_CONFIDENCE),
                        );
                        continue;
                    }
                    dst_lookup = method;
                } else if rel.receiver.is_some() {
                    // (a2b) The owner half came from the receiver's DECLARED
                    // type rather than from a path the caller wrote, so the
                    // class it names is one the file imports or the repository
                    // holds exactly one of, not necessarily one defined here.
                    // `adapter.send(request)` under `adapter: HTTPAdapter`
                    // binds to `HTTPAdapter.send`, which is the call
                    // `find_references` counted as zero while the annotation
                    // proving it sat in the graph.
                    if let Some((owner_file, owner_class)) =
                        locate_base_class(&file.file_path, owner, ctx)
                    {
                        if let Some(dst_id) =
                            resolve_declared_method(&owner_file, &owner_class, method, ctx)
                        {
                            accumulate_relation(
                                &mut resolved,
                                &mut relation_indices,
                                make_relation(rel, src_id, dst_id, RECEIVER_TYPE_CONFIDENCE),
                            );
                            continue;
                        }
                    }
                    // (a2c) The two-hop receiver. The owner half is itself
                    // two-part, `Response.connection`: the declared type of
                    // the receiver's root and the attribute read off it. The
                    // tier above could not settle it because the declaration
                    // that does lives on another class in another file, which
                    // is the whole shape of `r.connection.send(prep)` in
                    // requests' `auth.py`. Runs after (a2b) has failed, so a
                    // path the caller wrote down keeps its answer.
                    if let Some((root_type, attribute)) = split_owner_method(owner) {
                        if let Some(dst_id) = resolve_two_hop_declared_method(
                            &file.file_path,
                            root_type,
                            attribute,
                            method,
                            ctx,
                        ) {
                            accumulate_relation(
                                &mut resolved,
                                &mut relation_indices,
                                make_relation(rel, src_id, dst_id, RECEIVER_TYPE_CONFIDENCE),
                            );
                            continue;
                        }
                    }
                    // The declared type names nothing this repository defines,
                    // or defines no such method. The call keeps the bare leaf
                    // it arrived with before the type was consulted, so the
                    // disclaimed same-name path below runs exactly as it did.
                    if owner.contains('.') {
                        declined_two_hop = Some(ExtractedRelation {
                            dst_name: method.to_string(),
                            ..rel.clone()
                        });
                    }
                    dst_lookup = method;
                }
            }
        }
        let rel = declined_two_hop.as_ref().unwrap_or(rel);

        // (b) Import-based cross-file resolution. Skipped for a call through an
        // object: `dst_name` is then a member name read off a value, not the
        // local binding an import introduced.
        if let Some(file_imports) = ctx
            .import_map
            .get(file.file_path.as_str())
            .filter(|_| !receiver_is_object)
        {
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
                        accumulate_relation(
                            &mut resolved,
                            &mut relation_indices,
                            make_relation(rel, src_id, dst_id, 0.95),
                        );
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
                            accumulate_relation(
                                &mut resolved,
                                &mut relation_indices,
                                make_relation(rel, src_id, dst_id, 0.9),
                            );
                            continue;
                        }
                    }
                }
            }
        }

        let exact_candidates = ctx
            .entity_by_name
            .get(dst_lookup)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        let other_file_candidates: Vec<(&str, EntityId)> = exact_candidates
            .iter()
            .filter(|(fp, _)| *fp != file.file_path.as_str())
            .map(|&(fp, id)| (fp, id))
            .collect();
        let other_file_candidates =
            drop_module_call_targets(rel.kind, other_file_candidates, &ctx.entity_kind_by_id);

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
                accumulate_relation(
                    &mut resolved,
                    &mut relation_indices,
                    make_relation(rel, src_id, dst_id, IMPORT_PINNED_CONFIDENCE),
                );
                continue;
            }
            ImportPinnedTarget::PinnedMiss => name_fallback_allowed = false,
            ImportPinnedTarget::NoPin => {}
        }

        // From this point on, exact-name candidates are blind inference: import
        // and module pins above have already had their chance to resolve with
        // stronger evidence. Only equal/compatible language families may
        // participate in name or locality selection.
        let other_file_candidates: Vec<_> = other_file_candidates
            .into_iter()
            .filter(|(_, dst_id)| {
                blind_inference_target_allowed(src_id, *dst_id, &ctx.entity_language_by_id)
            })
            .collect();

        // (c) Global name-match fallback
        let bare_candidates = if rel.kind == RelationKind::Calls {
            ctx.entity_by_bare_name
                .get(dst_lookup)
                .map(|v| v.as_slice())
                .unwrap_or(&[])
        } else {
            &[]
        };

        let mut linked = false;
        // Set when the exact-name bucket named several cross-file entities and
        // no import, directory, or include signal separated them. The callee's
        // name alone cannot say which definition this call site reaches, so no
        // edge is emitted and the blind name tiers below are suppressed: they
        // key on the same unresolvable name and would re-guess the ambiguity
        // (c) already failed to settle.
        let mut unresolvable_name_ambiguity = false;

        // Arity gate for the exact-name fallbacks below: an overloaded C/C++
        // callee recorded its call-site argument count, so drop the same-name
        // candidates whose parameter count cannot accept it before (c) picks a
        // target or (c2) fans out. Fail-open and a no-op for callees without
        // recorded arity, so non-overloaded and non-C/C++ binding is unchanged.
        let other_file_candidates =
            prune_pairs_by_arity(other_file_candidates, call_arity, &ctx.entity_arity_by_id);
        let other_file_candidates =
            narrow_pairs_by_role(src_id, other_file_candidates, &ctx.entity_role_by_id);

        // A call through an object never reaches a module-level function, and
        // the exact-name bucket holds exactly those: a method is indexed under
        // its owner-qualified name and is reached by (c2) below. Letting an
        // object call settle here is what bound `proxies.get("no_proxy")` to
        // the public `requests.get`.
        if name_fallback_allowed && !receiver_is_object && !other_file_candidates.is_empty() {
            let distinct_ids: HashSet<EntityId> =
                other_file_candidates.iter().map(|&(_, id)| id).collect();
            let settled = if distinct_ids.len() == 1 {
                Some((other_file_candidates[0].1, 0.7))
            } else {
                let targets = caller_import_targets.get_or_insert_with(|| {
                    resolve_caller_import_targets(&file.file_path, &file.imports, &ctx.known_files)
                });
                let closure = caller_include_closure.get_or_insert_with(|| {
                    include_closure_depths(&file.file_path, &ctx.include_graph)
                });
                disambiguate_same_name_candidates(
                    &file.file_path,
                    targets,
                    closure,
                    &other_file_candidates,
                    |path| ctx.entity_count_by_file.get(path).copied().unwrap_or(0),
                )
                .map(|dst_id| (dst_id, LOCALITY_DISAMBIGUATED_CONFIDENCE))
            };
            match settled {
                Some((dst_id, confidence)) => {
                    accumulate_relation(
                        &mut resolved,
                        &mut relation_indices,
                        make_relation(rel, src_id, dst_id, confidence),
                    );
                    linked = true;
                }
                None => {
                    unresolvable_name_ambiguity = true;
                    debug!(
                        src = %rel.src_name,
                        dst = %rel.dst_name,
                        file = %file.file_path,
                        candidates = distinct_ids.len(),
                        "linker: same-name bucket unresolvable without scope signal, leaving unlinked"
                    );
                }
            }
        }

        // (c2) Receiver-method calls (`x.method()`) arrive as the bare method
        // name and never match (b)'s `Type::method` key. Resolve them through
        // the bare-name index. A single distinct cross-file method links as
        // before; when several implementor classes define the name — virtual
        // dispatch has an unknowable receiver type — fan out to all of them up
        // to the cap so every plausible dispatch target is counted rather than
        // dropped. Beyond the cap the name is too ubiquitous to guess, so it
        // stays unlinked for the inconclusive-absence gate.
        if name_fallback_allowed
            && !linked
            && !unresolvable_name_ambiguity
            && !bare_candidates.is_empty()
        {
            let candidates: Vec<(&str, EntityId)> = bare_candidates
                .iter()
                .copied()
                .filter(|&(fp, dst_id)| {
                    fp != file.file_path.as_str()
                        && blind_inference_target_allowed(
                            src_id,
                            dst_id,
                            &ctx.entity_language_by_id,
                        )
                })
                .collect();
            let candidates = prune_pairs_by_arity(candidates, call_arity, &ctx.entity_arity_by_id);
            let candidates = narrow_pairs_by_role(src_id, candidates, &ctx.entity_role_by_id);
            let candidates = if receiver_is_object {
                let owner_bound = owner_bound_targets(
                    dst_lookup,
                    ctx.import_map.get(file.file_path.as_str()),
                    |key, bound| {
                        if let Some(named) = ctx.entity_by_name.get(key) {
                            bound.extend(named.iter().map(|&(_, id)| id));
                        }
                    },
                );
                let settled = settle_receiver_method_owner(candidates, &owner_bound);
                if settled.is_empty() {
                    debug!(
                        src = %rel.src_name,
                        dst = %rel.dst_name,
                        file = %file.file_path,
                        named_owners = owner_bound.values().collect::<HashSet<_>>().len(),
                        "linker: receiver-method call names no single owner this file reaches, leaving unlinked"
                    );
                }
                settled
            } else if is_python_bare_identifier_call(rel, src_id, &ctx.entity_language_by_id) {
                // This tier exists for calls made through a receiver. A bare
                // Python identifier has none, so no method here is a dispatch
                // target for it.
                drop_method_candidates(candidates, &ctx.entity_kind_by_id)
            } else if is_rust_bare_identifier_call(rel, src_id, &ctx.entity_language_by_id)
                && !rust_bare_call_may_reach_owned(
                    rel.dst_name.as_str(),
                    file,
                    ctx.import_map.get(file.file_path.as_str()),
                )
            {
                debug!(
                    src = %rel.src_name,
                    dst = %rel.dst_name,
                    file = %file.file_path,
                    "linker: bare Rust call cannot reach an owner-qualified entity this file does not import, leaving unlinked"
                );
                Vec::new()
            } else {
                candidates
            };
            let distinct_targets: HashSet<EntityId> =
                candidates.into_iter().map(|(_, id)| id).collect();
            if (1..=AMBIGUOUS_CALL_FANOUT_CAP).contains(&distinct_targets.len()) {
                for dst_id in sorted_fanout_targets(distinct_targets) {
                    accumulate_relation(
                        &mut resolved,
                        &mut relation_indices,
                        make_relation(rel, src_id, dst_id, RECEIVER_NAME_FANOUT_CONFIDENCE),
                    );
                    linked = true;
                }
            }
        }

        // (c2a) A bare call to a same-file sibling under the caller's own
        // owner. `void Foo::a() { b(); }` in a file that also defines `Foo::b`
        // reached no tier at all before this one, so the call site existed in
        // the source and in no edge. See `same_owner_sibling_name` for why the
        // sibling is composed rather than searched, and
        // `bare_call_reaches_owner_sibling` for the language allowlist that
        // decides where a bare call carries an implicit receiver.
        //
        // It links only when exactly one distinct candidate survives the same
        // filters (c2) applies. Fanning out here would reopen the decoy problem
        // the (c) comment above describes, in the one place a decoy is most
        // likely: the caller's own file.
        //
        // LOCALITY_DISAMBIGUATED_CONFIDENCE and deliberately not 1.0. Locality
        // plus a unique owner-qualified leaf beats the cross-file fan-out and
        // stays under the parser-certain same-file edge (a) emits, because 1.0
        // would stamp `RelationOrigin::Parsed` and let `find_references` report
        // a name-derived edge as proven.
        if name_fallback_allowed && !linked && !unresolvable_name_ambiguity {
            if let Some((sibling, _leaf)) =
                same_owner_sibling_name(rel, src_id, &ctx.entity_language_by_id).filter(
                    |(_, leaf)| {
                        bare_leaf_names_one_thing(
                            ctx.entity_by_bare_name.get(leaf).map_or(0, |v| v.len()),
                            ctx.entity_by_name.get(leaf).map_or(0, |v| v.len()),
                        )
                    },
                )
            {
                let candidates: Vec<(&str, EntityId)> = ctx
                    .entity_by_name
                    .get(sibling.as_str())
                    .map(|v| v.as_slice())
                    .unwrap_or(&[])
                    .iter()
                    .copied()
                    .filter(|&(fp, dst_id)| {
                        fp == file.file_path.as_str()
                            && dst_id != src_id
                            && blind_inference_target_allowed(
                                src_id,
                                dst_id,
                                &ctx.entity_language_by_id,
                            )
                    })
                    .collect();
                let candidates =
                    prune_pairs_by_arity(candidates, call_arity, &ctx.entity_arity_by_id);
                let candidates = narrow_pairs_by_role(src_id, candidates, &ctx.entity_role_by_id);
                let distinct: HashSet<EntityId> =
                    candidates.into_iter().map(|(_, id)| id).collect();
                if distinct.len() == 1 {
                    for dst_id in sorted_fanout_targets(distinct) {
                        accumulate_relation(
                            &mut resolved,
                            &mut relation_indices,
                            make_relation(rel, src_id, dst_id, LOCALITY_DISAMBIGUATED_CONFIDENCE),
                        );
                        linked = true;
                    }
                }
            }
        }

        // (c4) C++ receiver-scoped inherited method. A `Owner::method` call
        // whose receiver type the parser pinned matched no exact entity above
        // (own method — same-file (a) or cross-file (c)) resolves through the
        // receiver class's Extends chain to the defining ancestor: the C++
        // counterpart of the (a2) `self.m()` walk, keyed on `::` methods.
        // Running before (c3) keeps an inherited call pinned to its true base
        // rather than fanning out to every same-named method the bare leaf
        // would reach. Only a located class owner binds, so a namespace-scoped
        // free function (`Catch::Main`) is left for the tiers below.
        if name_fallback_allowed && !linked && rel.kind == RelationKind::Calls {
            if let Some((owner, method)) = split_scoped_receiver_method(rel.dst_name.as_str()) {
                if let Some((owner_file, owner_class)) =
                    locate_base_class(&file.file_path, owner, ctx)
                {
                    if let Some(dst_id) =
                        resolve_inherited_method(&owner_file, &owner_class, method, ctx)
                    {
                        accumulate_relation(
                            &mut resolved,
                            &mut relation_indices,
                            make_relation(rel, src_id, dst_id, INHERITED_METHOD_CONFIDENCE),
                        );
                        linked = true;
                    }
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
            && !unresolvable_name_ambiguity
            && matches!(rel.kind, RelationKind::Calls | RelationKind::References)
        {
            // Fan out: an ambiguous qualified leaf resolves to every distinct
            // cross-file target (overloads / amalgamated copies), not just one —
            // arity-pruned so an overloaded callee (`Catch::Main`) drops the
            // overloads the call site's argument count cannot reach.
            for dst_id in resolve_qualified_suffix(
                rel.dst_name.as_str(),
                file.file_path.as_str(),
                call_arity,
                ctx,
            ) {
                accumulate_relation(
                    &mut resolved,
                    &mut relation_indices,
                    make_relation(rel, src_id, dst_id, QUALIFIED_SUFFIX_CONFIDENCE),
                );
                linked = true;
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
            accumulate_relation(&mut resolved, &mut relation_indices, external);
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

    // Derived after the parser's own relations: an override is a fact about
    // two declarations plus a resolved base, not about any one extracted
    // relation, so it has no `ExtractedRelation` to be resolved from.
    for relation in derive_override_relations(file, ctx) {
        accumulate_relation(&mut resolved, &mut relation_indices, relation);
    }

    resolved
}

/// Merge per-file resolved relations in input-file order, deduplicating across
/// files (a no-op when sources are disjoint, but kept so output is identical to
/// a single serial pass), then append artifact-level import/include edges.
fn merge_resolved(
    per_file_relations: Vec<Vec<Relation>>,
    files: &[&FileParseData],
    ctx: &LinkContext<'_>,
    artifact_ids: &ArtifactIdentityMap,
    completeness: Option<&FileParseCompletenessMap>,
) -> Vec<Relation> {
    let mut resolved = Vec::new();
    let mut relation_indices = HashMap::new();
    for file_relations in per_file_relations {
        for rel in file_relations {
            accumulate_relation(&mut resolved, &mut relation_indices, rel);
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
        let module_entities = module_entity_by_file(files);
        let per_file_artifact: Vec<Vec<Relation>> = files
            .par_iter()
            .map(|file| {
                let mut out: Vec<Relation> = Vec::new();
                for imp in &file.imports {
                    // Resolved once, and the kind decided once, for both builders.
                    let Some((target, kind)) =
                        resolve_import_target(&file.file_path, imp, &ctx.known_files)
                    else {
                        continue;
                    };
                    if let Some(rel) = make_artifact_import_relation(
                        &file.file_path,
                        imp,
                        &target,
                        kind,
                        artifact_ids,
                    ) {
                        out.push(rel);
                    }
                    out.extend(make_entity_import_relations(
                        &file.file_path,
                        imp,
                        &target,
                        kind,
                        &|path| module_entities.get(path).copied(),
                        &|path, name| ctx.entity_by_file_name.get(&(path, name)).copied(),
                    ));
                }
                out
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

    append_parse_coverage_relations(
        &mut resolved,
        files,
        artifact_ids,
        completeness,
        &ctx.known_files,
    );

    resolved
}

/// Serial counterpart of [`link_cross_file_against_entities`], retained as the
/// byte-identical reference for the parallel resolution path.
#[cfg(test)]
fn link_cross_file_against_entities_serial(
    files: &[FileParseData],
    universe_entities: &[Entity],
    artifact_ids: &ArtifactIdentityMap,
) -> Vec<Relation> {
    let universe_entities: Vec<&Entity> = universe_entities.iter().collect();
    let files: Vec<&FileParseData> = files.iter().collect();
    let ctx = build_link_context(&files, &universe_entities);
    let per_file_relations: Vec<Vec<Relation>> = files
        .iter()
        .map(|file| resolve_one_file(file, &ctx, None))
        .collect();
    merge_resolved(per_file_relations, &files, &ctx, artifact_ids, None)
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
    artifact_ids: &ArtifactIdentityMap,
) -> Vec<Relation> {
    let mut resolved = Vec::new();
    let mut relation_indices = HashMap::new();
    for file_relations in per_file_relations {
        for rel in file_relations {
            accumulate_relation(&mut resolved, &mut relation_indices, rel);
        }
    }
    let mut seen_artifact: HashSet<(GraphNodeId, GraphNodeId, RelationKind)> = HashSet::new();
    let file_refs: Vec<&FileParseData> = files.iter().collect();
    let module_entities = module_entity_by_file(&file_refs);
    for file in files {
        for imp in &file.imports {
            let Some((target, kind)) =
                resolve_import_target(&file.file_path, imp, &ctx.known_files)
            else {
                continue;
            };
            if let Some(rel) =
                make_artifact_import_relation(&file.file_path, imp, &target, kind, artifact_ids)
            {
                let key = (rel.src, rel.dst, rel.kind);
                if seen_artifact.insert(key) {
                    resolved.push(rel);
                }
            }
            for rel in make_entity_import_relations(
                &file.file_path,
                imp,
                &target,
                kind,
                &|path| module_entities.get(path).copied(),
                &|path, name| ctx.entity_by_file_name.get(&(path, name)).copied(),
            ) {
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
    files: &[&FileParseData],
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CallShapeEvidenceKey {
    positional: u32,
    keywords: Vec<String>,
    has_var_positional: bool,
    has_var_keyword: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CallEvidenceKey {
    source_span: Option<(String, usize, usize, u32, u32, u32, u32)>,
    parser_rule: Option<String>,
    token: Option<String>,
    source_path: Option<String>,
    resolved_path: Option<String>,
    call_shape: Option<CallShapeEvidenceKey>,
}

fn canonicalize_call_evidence(evidence: &mut Vec<RelationEvidence>) {
    let mut canonical = BTreeMap::<CallEvidenceKey, RelationEvidence>::new();

    for mut record in evidence.drain(..) {
        if let Some(shape) = &mut record.call_shape {
            shape.keywords.sort();
            shape.keywords.dedup();
        }
        // Exhaustive destructuring makes a future RelationEvidence field fail
        // compilation until the deterministic key explicitly accounts for it.
        let RelationEvidence {
            source_span,
            parser_rule,
            token,
            source_path,
            resolved_path,
            occurrence_count: _,
            call_shape,
        } = &record;
        let key = CallEvidenceKey {
            source_span: source_span.as_ref().map(|span| {
                (
                    span.file.to_string(),
                    span.start_byte,
                    span.end_byte,
                    span.start_line,
                    span.start_col,
                    span.end_line,
                    span.end_col,
                )
            }),
            parser_rule: parser_rule.clone(),
            token: token.clone(),
            source_path: source_path.clone(),
            resolved_path: resolved_path.clone(),
            call_shape: call_shape.as_ref().map(|shape| {
                let kin_model::CallArgShape {
                    positional,
                    keywords,
                    has_var_positional,
                    has_var_keyword,
                } = shape;
                CallShapeEvidenceKey {
                    positional: *positional,
                    keywords: keywords.clone(),
                    has_var_positional: *has_var_positional,
                    has_var_keyword: *has_var_keyword,
                }
            }),
        };
        match canonical.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(record);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let occurrence_count = entry
                    .get()
                    .occurrence_count
                    .saturating_add(record.occurrence_count);
                entry.get_mut().occurrence_count = occurrence_count;
            }
        }
    }

    evidence.extend(canonical.into_values());
}

fn relation_origin_priority(origin: RelationOrigin) -> u8 {
    match origin {
        RelationOrigin::Manual => 4,
        RelationOrigin::Lsp => 3,
        RelationOrigin::Parsed => 2,
        RelationOrigin::Inferred => 1,
    }
}

/// Merge scalar metadata without making the retained relation depend on which
/// source occurrence happened to be linked first. Confidence is the review
/// gate's authority, so the strongest resolution wins and carries its origin.
/// Equal-confidence origins use the same provenance ordering as semantic
/// resolution elsewhere in Kin. Import sources are explanatory rather than a
/// strength signal; retain one deterministically instead of dropping a later
/// source-bearing occurrence.
fn merge_relation_metadata(existing: &mut Relation, incoming: &Relation) {
    let incoming_is_stronger = match incoming.confidence.total_cmp(&existing.confidence) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Equal => {
            relation_origin_priority(incoming.origin) > relation_origin_priority(existing.origin)
        }
        std::cmp::Ordering::Less => false,
    };
    if incoming_is_stronger {
        existing.confidence = incoming.confidence;
        existing.origin = incoming.origin;
    }

    match (&existing.import_source, &incoming.import_source) {
        (None, Some(_)) => existing.import_source.clone_from(&incoming.import_source),
        (Some(current), Some(candidate)) if candidate < current => {
            existing.import_source.clone_from(&incoming.import_source);
        }
        _ => {}
    }
}

/// Insert one logical relation, preserving every call-site shape on repeated
/// `(src, dst, Calls)` edges. Relation IDs intentionally identify the logical
/// caller/callee edge rather than an individual source occurrence, so distinct
/// shapes live as deterministic evidence records and identical shapes collapse
/// through `occurrence_count`. An empty evidence vector is an older or
/// shape-blind call site; when mixed with shaped occurrences it becomes an
/// explicit `call_shape: None` marker so downstream proof fails closed.
pub(crate) fn accumulate_relation(
    resolved: &mut Vec<Relation>,
    relation_indices: &mut HashMap<(GraphNodeId, GraphNodeId, RelationKind), usize>,
    mut relation: Relation,
) {
    let key = (relation.src, relation.dst, relation.kind);
    let Some(&index) = relation_indices.get(&key) else {
        relation_indices.insert(key, resolved.len());
        resolved.push(relation);
        return;
    };

    let existing = &mut resolved[index];
    merge_relation_metadata(existing, &relation);

    if relation.kind != RelationKind::Calls {
        // A non-call edge carries evidence only when the adapter recorded a
        // site for it, and two sites for one edge are two lines to report, so
        // they merge instead of the later one being dropped. None of the
        // call-shape marker synthesis below applies: a non-call edge has no
        // shape, so a spanless occurrence contributes nothing rather than an
        // explicit unshaped marker.
        if !relation.evidence.is_empty() {
            existing.evidence.append(&mut relation.evidence);
            canonicalize_call_evidence(&mut existing.evidence);
        }
        return;
    }

    let existing_missing_shape = existing.evidence.is_empty();
    let incoming_missing_shape = relation.evidence.is_empty();
    if existing_missing_shape {
        existing.evidence.push(RelationEvidence::default());
    }
    if incoming_missing_shape {
        existing.evidence.push(RelationEvidence::default());
    } else {
        existing.evidence.append(&mut relation.evidence);
    }
    canonicalize_call_evidence(&mut existing.evidence);
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
/// callee (`crate::mod::func`, `Type::method`, `alias::Type::method`) to local
/// entities via suffix matching. Inferred: the module/crate prefix is dropped
/// before matching, so it ranks below an import-verified edge (0.95) yet above
/// the ambiguous receiver-method guess (0.3). A single suffix target and a
/// fanned-out set of ambiguous ones share this confidence: every emitted target
/// is a real definition the suffix genuinely names, so the resolution quality is
/// the same whether one target or several survive.
const QUALIFIED_SUFFIX_CONFIDENCE: f32 = 0.6;

/// Confidence for a method call resolved through the receiver class's Extends
/// chain (`self.m()` in `Sub(Base)` linking to `Base.m`). The parser pinned the
/// dispatch class and the class hierarchy pinned the defining ancestor, so this
/// is dispatch evidence, not a name guess — above locality disambiguation (0.8)
/// and well above the review-side strong-consumer floor, below an
/// import-verified edge (0.95) because the base-class link itself may have been
/// name-resolved.
/// Confidence for a call bound through the receiver's declared type.
///
/// The type is written in the source the call sits in, the owner resolved to a
/// class entity, and the method was selected inside that class or an ancestor
/// of it, so nothing here is inferred from a name matching a name. It sits
/// above the inherited-method walk, which infers the dispatch class, and below
/// the same-file parser-certain edge.
const RECEIVER_TYPE_CONFIDENCE: f32 = 0.95;

const INHERITED_METHOD_CONFIDENCE: f32 = 0.85;

/// Split a dotted `Owner.method` dst_name into its owner and method parts at
/// the FINAL dot (`N.Class.Method` → (`N.Class`, `Method`)). Returns `None` for
/// undotted names, `::` paths (those belong to the qualified-suffix resolver),
/// and empty halves, so only receiver-qualified method keys reach the
/// inheritance walk.
fn split_owner_method(name: &str) -> Option<(&str, &str)> {
    if name.contains("::") {
        return None;
    }
    let idx = name.rfind('.')?;
    let (owner, method) = (&name[..idx], &name[idx + 1..]);
    (!owner.is_empty() && !method.is_empty()).then_some((owner, method))
}

/// The two receiver-method entity keys a class + method can form: the Python
/// adapter stores methods as `Class.method`, the C++ adapter as `Class::method`.
/// The inheritance walk tries both so one Extends-chain resolver serves every
/// language's method naming.
fn receiver_method_keys(class: &str, method: &str) -> [String; 2] {
    [format!("{class}.{method}"), format!("{class}::{method}")]
}

/// Split a C++-style receiver-qualified call `Owner::method` (or a longer
/// `A::B::Owner::method`) into its receiver-class leaf and method name. Returns
/// `None` for names without `::`, with non-identifier segments (turbofish,
/// operators), or with an empty half — so only a genuine receiver-scoped method
/// key reaches the Extends-chain walk. The owner is validated as a class at the
/// call site, so a namespace-qualified free function (`Catch::Main`) never binds.
fn split_scoped_receiver_method(name: &str) -> Option<(&str, &str)> {
    let (owner_path, method) = name.rsplit_once("::")?;
    let owner = owner_path.rsplit("::").next()?;
    if owner.is_empty()
        || method.is_empty()
        || !is_path_identifier(owner)
        || !is_path_identifier(method)
    {
        return None;
    }
    Some((owner, method))
}

/// Upper bound on how many classes an inheritance walk may visit before giving
/// up. Real hierarchies are shallow; the cap is cycle/pathology insurance so a
/// malformed `Extends` graph (self-inheritance, giant generated lattices) can
/// never stall linking.
const INHERITANCE_WALK_CAP: usize = 64;

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

/// Upper bound on how many ambiguous same-name targets one call or reference
/// may fan out to.
///
/// A virtual-dispatch method call, a set of overloads, or a
/// declaration/definition split has several equally-plausible definitions.
/// Linking every one keeps the caller visible in refs/impact instead of
/// silently dropping the edge when the target cannot be pinned to exactly one.
/// The cap bounds that over-approximation: a ubiquitous leaf name (`new`,
/// `get`, `run`) can occur in dozens of files, and fanning out to all of them
/// would flood the graph with low-value guesses. At or below the cap every
/// distinct candidate is linked; above it the resolver stays silent rather than
/// emit a wall of edges.
const AMBIGUOUS_CALL_FANOUT_CAP: usize = 8;

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

/// Order a fanned-out target set deterministically before emitting relations.
///
/// Fan-out gathers candidates into a `HashSet`, whose iteration order is not
/// stable across processes. Sorting by [`EntityId`] — content-derived, hence
/// reproducible — fixes the emitted relation order so a re-run is byte-stable
/// and the batch and incremental linkers emit identical edges for identical
/// input.
fn sorted_fanout_targets(targets: HashSet<EntityId>) -> Vec<EntityId> {
    let mut ids: Vec<EntityId> = targets.into_iter().collect();
    ids.sort_unstable();
    ids
}

/// Argument-count bounds a callee accepts, read from its signature: `min`
/// required parameters (those without a default), `max` declared parameters,
/// and whether a trailing C variadic (`...`) or parameter pack lets it accept
/// unboundedly many. A call of `n` positional arguments is arity-compatible
/// with the callee iff `min <= n && (variadic || n <= max)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArityBounds {
    min: usize,
    max: usize,
    variadic: bool,
}

impl ArityBounds {
    fn accepts(&self, args: usize) -> bool {
        args >= self.min && (self.variadic || args <= self.max)
    }
}

/// The argument-count bounds of an entity that can be a call target, or `None`
/// when arity should not be inferred for it. Only C/C++ function and method
/// entities qualify: their call sites are the ones that record arity (so only
/// their candidates are ever pruned), and their signatures share one parameter
/// grammar. Every other language yields `None`, leaving its callees arity-blind
/// exactly as before.
fn callee_arity_bounds(entity: &Entity) -> Option<ArityBounds> {
    if !matches!(entity.language, LanguageId::Cpp | LanguageId::C) {
        return None;
    }
    if !matches!(entity.kind, EntityKind::Function | EntityKind::Method) {
        return None;
    }
    parse_signature_arity(&entity.signature)
}

/// Compute a C/C++ callee's [`ArityBounds`] from its stored signature, or `None`
/// when the parameter list cannot be located (arity then stays unknown and the
/// callee is never pruned). The signature is the declaration text with
/// whitespace normalized (`declaration_signature`): the parameter list is its
/// first top-level `(...)` group (an `operator()` name is skipped), split into
/// parameters on top-level commas so nested templates/parens/braces never
/// miscount. A `void`-only list is zero; a parameter carrying a top-level `=`
/// is optional (counts toward `max`, not `min`); a `...` or parameter-pack
/// parameter sets `variadic`.
fn parse_signature_arity(signature: &str) -> Option<ArityBounds> {
    let (open, close) = param_list_span(signature)?;
    let inner = signature[open + 1..close].trim();
    if inner.is_empty() || inner == "void" {
        return Some(ArityBounds {
            min: 0,
            max: 0,
            variadic: false,
        });
    }
    let mut min = 0usize;
    let mut max = 0usize;
    let mut variadic = false;
    for param in split_top_level_commas(inner) {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }
        // `...` (C varargs) is not a counted parameter; a parameter pack
        // (`Args... args`) accepts zero or more, so it too adds no required
        // argument. Either way the callee accepts unboundedly many.
        if param == "..." || param.contains("...") {
            variadic = true;
            continue;
        }
        max += 1;
        if !param_has_default(param) {
            min += 1;
        }
    }
    Some(ArityBounds { min, max, variadic })
}

/// Byte offsets of the `(` and matching `)` of a signature's parameter list:
/// the first `(` at top level (outside a template `<...>`) whose name is not
/// `operator`. Returns `None` for a signature with no such group.
fn param_list_span(sig: &str) -> Option<(usize, usize)> {
    let bytes = sig.as_bytes();
    let mut angle: usize = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => angle += 1,
            b'>' => angle = angle.saturating_sub(1),
            b'(' if angle == 0 => {
                let close = matching_close_paren(bytes, i)?;
                // `operator()`: the call-operator name, not the parameter list —
                // skip it so the real parameter list after it is found.
                if sig[..i].trim_end().ends_with("operator") {
                    i = close + 1;
                    continue;
                }
                return Some((i, close));
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Byte index of the `)` matching the `(` at `open`, tracking nested parens.
/// `None` when the parentheses are unbalanced.
fn matching_close_paren(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Split a parameter list's inner text on commas at the top nesting level so a
/// comma inside `<...>`, `(...)`, `[...]`, or `{...}` (template arguments,
/// function-pointer parameters, array bounds, brace-init defaults) never splits
/// one parameter into several.
fn split_top_level_commas(inner: &str) -> Vec<&str> {
    let bytes = inner.as_bytes();
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'<' | b'(' | b'[' | b'{' => depth += 1,
            b'>' | b')' | b']' | b'}' => depth = (depth - 1).max(0),
            b',' if depth == 0 => {
                parts.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&inner[start..]);
    parts
}

/// Whether a single parameter carries a default value: a top-level `=` that is
/// the assignment, not a `==`/`<=`/`>=`/`!=` fragment inside a default
/// expression.
fn param_has_default(param: &str) -> bool {
    let bytes = param.as_bytes();
    let mut depth = 0i32;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' | b'(' | b'[' | b'{' => depth += 1,
            b'>' | b')' | b']' | b'}' => depth = (depth - 1).max(0),
            b'=' if depth == 0 => {
                let prev = bytes[..i].last().copied();
                let next = bytes.get(i + 1).copied();
                let is_comparison =
                    matches!(prev, Some(b'<' | b'>' | b'!' | b'=')) || next == Some(b'=');
                if !is_comparison {
                    return true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// Keep only the entity ids a call of `arg_count` positional arguments could
/// bind to. A candidate stays when its arity is unknown (unparsed signature or
/// a non-C/C++ callee — never pruned on missing evidence) or accepts the count;
/// a candidate whose known arity rejects the count is dropped. `None`
/// `arg_count` returns the set unchanged. Fail-open: if every candidate is
/// known-incompatible the original set is returned, so an arity read prunes
/// wrong overloads but never erases the edge outright.
fn prune_ids_by_arity(
    ids: HashSet<EntityId>,
    arg_count: Option<usize>,
    arity_by_id: &HashMap<EntityId, ArityBounds>,
) -> HashSet<EntityId> {
    let Some(args) = arg_count else {
        return ids;
    };
    let kept: HashSet<EntityId> = ids
        .iter()
        .copied()
        .filter(|id| arity_admits(arity_by_id.get(id), args))
        .collect();
    if kept.is_empty() {
        ids
    } else {
        kept
    }
}

/// `(file, id)` counterpart of [`prune_ids_by_arity`] for the exact-name
/// candidate lists, with the same fail-open semantics.
fn prune_pairs_by_arity<'a>(
    pairs: Vec<(&'a str, EntityId)>,
    arg_count: Option<usize>,
    arity_by_id: &HashMap<EntityId, ArityBounds>,
) -> Vec<(&'a str, EntityId)> {
    let Some(args) = arg_count else {
        return pairs;
    };
    let kept: Vec<(&str, EntityId)> = pairs
        .iter()
        .copied()
        .filter(|(_, id)| arity_admits(arity_by_id.get(id), args))
        .collect();
    if kept.is_empty() {
        pairs
    } else {
        kept
    }
}

/// Whether a candidate with the given (possibly unknown) arity admits a call of
/// `args` positional arguments. Unknown arity always admits — the linker never
/// prunes a candidate whose parameter count it could not read.
fn arity_admits(bounds: Option<&ArityBounds>, args: usize) -> bool {
    match bounds {
        Some(bounds) => bounds.accepts(args),
        None => true,
    }
}

/// The exact positional argument count to prune a call's overloads by, or `None`
/// when arity is not pinnable. A recorded [`CallArgShape`] pins arity only when
/// no pack/splat expansion widens it: a `*args`/`args...` positional splat or a
/// `**kwargs` keyword splat makes the positional count a lower bound, so the
/// call is treated as arity-unknown and no overload is pruned. `None` shape
/// (adapter recorded nothing) is likewise unknown — fail-open on both.
fn call_positional_arity(shape: &Option<CallArgShape>) -> Option<usize> {
    match shape {
        Some(shape) if !shape.has_var_positional && !shape.has_var_keyword => {
            Some(shape.positional as usize)
        }
        _ => None,
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
/// Returns every distinct cross-file target the suffix can name, in a
/// deterministic order; an empty vector is an honest miss. The type-qualified
/// suffix is precise, so it resolves a single target and stops (empty) when it
/// is itself ambiguous — widening to the bare leaf would be less precise, not
/// more. The bare leaf is the ambiguous tier: when it names several cross-file
/// targets (overloads, or amalgamated header copies of one symbol) it fans out
/// to all of them, bounded by [`AMBIGUOUS_CALL_FANOUT_CAP`]; beyond the cap it
/// stays silent and is logged — a wall of guesses is worse than a missing edge.
fn resolve_qualified_suffix(
    dst_name: &str,
    current_file: &str,
    arg_count: Option<usize>,
    ctx: &LinkContext<'_>,
) -> Vec<EntityId> {
    let segments: Vec<&str> = dst_name.split("::").collect();
    // Must be a genuine `::` path of identifier-like segments. Rejects bare names
    // (handled by (c)/(c2)), leading/trailing `::`, and turbofish/exotic forms.
    if segments.len() < 2 || !segments.iter().all(|s| is_path_identifier(s)) {
        return Vec::new();
    }
    let last = segments[segments.len() - 1];

    // Tier 1: type-qualified suffix `Penult::last` against the full-name index.
    // Resolves a method reached through a module/crate prefix. If this pinned
    // suffix is itself ambiguous, stop — widening to the bare leaf would be less
    // precise, not more. Arity pruning first can settle that ambiguity when the
    // rival suffix targets are overloads the call's argument count separates.
    let type_qualified = format!("{}::{}", segments[segments.len() - 2], last);
    let mut tq_targets: HashSet<EntityId> = HashSet::new();
    distinct_cross_file_targets(
        ctx.entity_by_name.get(type_qualified.as_str()),
        current_file,
        &mut tq_targets,
    );
    let tq_targets = prune_ids_by_arity(tq_targets, arg_count, &ctx.entity_arity_by_id);
    match tq_targets.len() {
        1 => return tq_targets.into_iter().collect(),
        n if n > 1 => {
            debug!(
                dst = %dst_name,
                suffix = %type_qualified,
                count = n,
                "linker: ambiguous type-qualified suffix, leaving unresolved"
            );
            return Vec::new();
        }
        _ => {}
    }

    // Tier 2: bare leaf. Free functions live in `entity_by_name` under `last`;
    // methods live in `entity_by_bare_name` under `last`. Union both, then fan
    // out to every distinct cross-file target up to the cap so overload sets and
    // amalgamated duplicate definitions all link instead of dropping the edge.
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
    let leaf_targets = prune_ids_by_arity(leaf_targets, arg_count, &ctx.entity_arity_by_id);
    match leaf_targets.len() {
        0 => Vec::new(),
        n if n <= AMBIGUOUS_CALL_FANOUT_CAP => sorted_fanout_targets(leaf_targets),
        n => {
            debug!(
                dst = %dst_name,
                leaf = %last,
                count = n,
                "linker: qualified-call leaf beyond fan-out cap, leaving unresolved"
            );
            Vec::new()
        }
    }
}

/// Incremental-linker counterpart of [`resolve_qualified_suffix`], kept in exact
/// resolution parity with it: the type-qualified suffix (`Type::method`) resolves
/// a single target or stops on ambiguity, and the bare leaf unions the
/// simple-name and bare-name indices, then fans out to every distinct cross-file
/// target up to [`AMBIGUOUS_CALL_FANOUT_CAP`]. Returns the targets in the same
/// deterministic order as the batch resolver; an empty vector is an honest miss.
fn resolve_qualified_suffix_incremental(
    dst_name: &str,
    current_file: &str,
    arg_count: Option<usize>,
    linker: &IncrementalLinker,
) -> Vec<EntityId> {
    let segments: Vec<&str> = dst_name.split("::").collect();
    if segments.len() < 2 || !segments.iter().all(|s| is_path_identifier(s)) {
        return Vec::new();
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
    let tq_targets = prune_ids_by_arity(tq_targets, arg_count, &linker.entity_arity_by_id);
    match tq_targets.len() {
        1 => return tq_targets.into_iter().collect(),
        n if n > 1 => {
            debug!(
                dst = %dst_name,
                suffix = %type_qualified,
                count = n,
                "linker(incremental): ambiguous type-qualified suffix, leaving unresolved"
            );
            return Vec::new();
        }
        _ => {}
    }

    // Tier 2: bare leaf. Free functions live in `entity_by_name` under `last`;
    // methods live in `entity_by_bare_name` under `last`. Union both so the
    // incremental linker resolves the same leaf targets as the batch resolver,
    // then fan out to every distinct cross-file target up to the cap.
    let mut leaf_targets: HashSet<EntityId> = HashSet::new();
    if let Some(cands) = linker.entity_by_name.get(last) {
        for (fp, id) in cands {
            if fp != current_file {
                leaf_targets.insert(*id);
            }
        }
    }
    if let Some(cands) = linker.entity_by_bare_name.get(last) {
        for (fp, id) in cands {
            if fp != current_file {
                leaf_targets.insert(*id);
            }
        }
    }
    let leaf_targets = prune_ids_by_arity(leaf_targets, arg_count, &linker.entity_arity_by_id);
    match leaf_targets.len() {
        0 => Vec::new(),
        n if n <= AMBIGUOUS_CALL_FANOUT_CAP => sorted_fanout_targets(leaf_targets),
        n => {
            debug!(
                dst = %dst_name,
                leaf = %last,
                count = n,
                "linker(incremental): qualified-call leaf beyond fan-out cap, leaving unresolved"
            );
            Vec::new()
        }
    }
}

/// Whether an entity id names a type that can anchor an inheritance walk.
/// Whether an entity may take the `(file, name)` slot another entity holds.
///
/// A Python file's Module entity is named for the file stem, so `nk/search.py`
/// containing `def search(...)` puts a Module and a Function on one
/// `(file, name)` key. Inside a module that name binds to the function: Python
/// binds no name for the module itself in the module's own namespace. Letting
/// the Module take the slot parked every caller of `search` on the module node,
/// left the function holding zero incoming edges, and made `kin dead-code`
/// print the program's primary function as unreferenced.
///
/// So a Module never displaces a non-Module here, and a non-Module always
/// displaces a Module. Two entities of any other kinds keep the prior
/// last-one-wins behaviour.
fn file_name_slot_admits(candidate: EntityKind, occupant: EntityKind) -> bool {
    candidate != EntityKind::Module || occupant == EntityKind::Module
}

fn is_class_like(kind: Option<&EntityKind>) -> bool {
    matches!(
        kind,
        Some(
            EntityKind::Class | EntityKind::EnumDef | EntityKind::Interface | EntityKind::TraitDef
        )
    )
}

/// Collapse a file's Extends relations into per-class base lists, sorted
/// lexicographically (see the batch index comment: committed graph edges carry
/// no declaration order, so one uniform order keeps every linking path
/// bit-identical).
fn collect_class_bases(relations: &[ExtractedRelation]) -> Vec<(String, Vec<String>)> {
    let mut classes: Vec<(String, Vec<String>)> = Vec::new();
    for rel in relations {
        if rel.kind != RelationKind::Extends {
            continue;
        }
        match classes.iter_mut().find(|(class, _)| class == &rel.src_name) {
            Some((_, bases)) => {
                if !bases.contains(&rel.dst_name) {
                    bases.push(rel.dst_name.clone());
                }
            }
            None => classes.push((rel.src_name.clone(), vec![rel.dst_name.clone()])),
        }
    }
    for (_, bases) in &mut classes {
        bases.sort_unstable();
    }
    classes
}

/// Declared base names of `class_name` in `file_path` within a per-file
/// hierarchy map, if recorded.
fn class_bases_in<'m>(
    map: &'m HashMap<String, Vec<(String, Vec<String>)>>,
    file_path: &str,
    class_name: &str,
) -> Option<&'m [String]> {
    map.get(file_path)?
        .iter()
        .find(|(class, _)| class == class_name)
        .map(|(_, bases)| bases.as_slice())
}

/// Locate the class a declared base NAME refers to, from `class_file`'s point
/// of view: a same-file class shadows everything; then the file's own import
/// bindings (`from pkg.base import Base [as B]`, or a `models.Model` member of
/// an imported module); then a repo-globally unique class name (Python's
/// absolute `pkg.mod` imports do not resolve to files — see
/// `resolve_import_pinned_target` — so uniqueness is the honest cross-file
/// evidence tier). Returns the (file, class entity name) to continue the walk
/// from, or `None` when the base is external, builtin, or ambiguous — a walk
/// must never guess a hierarchy.
fn locate_base_class(
    class_file: &str,
    base_raw: &str,
    ctx: &LinkContext<'_>,
) -> Option<(String, String)> {
    let base_leaf = bare_entity_name(base_raw);

    if let Some(id) = ctx.entity_by_file_name.get(&(class_file, base_leaf)) {
        if is_class_like(ctx.entity_kind_by_id.get(id)) {
            return Some((class_file.to_string(), base_leaf.to_string()));
        }
    }

    if let Some(file_imports) = ctx.import_map.get(class_file) {
        let (binding, target_name) = match base_raw.split_once('.') {
            // `models.Model`: the binding is the first segment, the class is
            // the leaf inside the imported module.
            Some((first, _)) => (first, base_leaf),
            // `Base` bound by `from m import Base [as B]`: the target file
            // declares the original name.
            None => (base_raw, ""),
        };
        if let Some(&(module_path, original_name)) = file_imports.get(binding) {
            let target_name = if target_name.is_empty() {
                original_name
            } else {
                target_name
            };
            if let Some(target_file) =
                resolve_module_path(class_file, module_path, &ctx.known_files)
            {
                if let Some(id) = ctx
                    .entity_by_file_name
                    .get(&(target_file.as_str(), target_name))
                {
                    if is_class_like(ctx.entity_kind_by_id.get(id)) {
                        return Some((target_file, target_name.to_string()));
                    }
                }
            }
        }
    }

    let mut unique: Option<(&str, EntityId)> = None;
    if let Some(candidates) = ctx.entity_by_name.get(base_leaf) {
        for &(fp, id) in candidates {
            match unique {
                None => unique = Some((fp, id)),
                Some((_, seen)) if seen == id => {}
                Some(_) => return None,
            }
        }
    }
    if let Some((fp, id)) = unique {
        if is_class_like(ctx.entity_kind_by_id.get(&id)) {
            return Some((fp.to_string(), base_leaf.to_string()));
        }
    }
    None
}

/// Resolve an inherited receiver-method call (`Sub.method` where `Sub` does
/// not define `method`) to the defining ancestor's method entity by walking
/// `Sub`'s Extends chain breadth-first. Level order matches Python's MRO
/// property that nearer ancestors shadow farther ones; among a level's several
/// bases the walk visits lexicographically (a documented approximation of C3's
/// left-to-right rule — declaration order cannot be rehydrated from committed
/// graph edges, and one uniform order keeps cold/incremental/reopened graphs
/// bit-identical). The walk is bounded by [`INHERITANCE_WALK_CAP`] and
/// cycle-guarded, and ends any branch whose base cannot be located
/// ([`locate_base_class`]) — it never guesses. Kept in exact resolution parity
/// with [`resolve_inherited_method_incremental`].
/// The method `owner_class` itself declares, before any ancestor is consulted.
///
/// [`resolve_inherited_method`] deliberately starts at the class's bases: its
/// caller has already given a same-file own method its win. A call bound
/// through the receiver's declared type has had no such tier, because tier (a)
/// passes over the same-file entity whenever the receiver is an object, so it
/// asks for the class's own method first and walks the hierarchy only when the
/// class does not declare it.
fn resolve_declared_method(
    owner_file: &str,
    owner_class: &str,
    method: &str,
    ctx: &LinkContext<'_>,
) -> Option<EntityId> {
    resolve_own_method(owner_file, owner_class, method, ctx)
        .or_else(|| resolve_inherited_method(owner_file, owner_class, method, ctx))
}

/// The method entity `owner_class` declares under its own name in
/// `owner_file`, with no ancestor consulted.
///
/// The lookup is keyed on the class-qualified entity name (`Class.method` or
/// `Class::method`), so a free function in the same file that happens to share
/// the method's leaf name is not a candidate here. That is what lets a
/// receiver-typed call ask a same-file class for its own method without
/// reopening the decoy tier (a) refuses.
fn resolve_own_method(
    owner_file: &str,
    owner_class: &str,
    method: &str,
    ctx: &LinkContext<'_>,
) -> Option<EntityId> {
    receiver_method_keys(owner_class, method)
        .iter()
        .find_map(|key| {
            ctx.entity_by_file_name
                .get(&(owner_file, key.as_str()))
                .copied()
        })
}

/// The incremental mirror of [`resolve_declared_method`].
fn resolve_declared_method_incremental(
    owner_file: &str,
    owner_class: &str,
    method: &str,
    linker: &IncrementalLinker,
    import_map: &HashMap<&str, HashMap<&str, (&str, &str)>>,
    class_bases: &HashMap<String, Vec<(String, Vec<String>)>>,
) -> Option<EntityId> {
    resolve_own_method_incremental(owner_file, owner_class, method, linker).or_else(|| {
        resolve_inherited_method_incremental(
            owner_file,
            owner_class,
            method,
            linker,
            import_map,
            class_bases,
        )
    })
}

/// The incremental mirror of [`resolve_own_method`].
fn resolve_own_method_incremental(
    owner_file: &str,
    owner_class: &str,
    method: &str,
    linker: &IncrementalLinker,
) -> Option<EntityId> {
    receiver_method_keys(owner_class, method)
        .iter()
        .find_map(|key| {
            linker
                .entity_by_file_name
                .get(owner_file)
                .and_then(|by_name| by_name.get(key.as_str()))
                .copied()
        })
}

fn resolve_inherited_method(
    src_file: &str,
    owner: &str,
    method: &str,
    ctx: &LinkContext<'_>,
) -> Option<EntityId> {
    let start = (src_file.to_string(), owner.to_string());
    let mut visited: HashSet<(String, String)> = HashSet::new();
    let mut queue: std::collections::VecDeque<(String, String)> = std::collections::VecDeque::new();
    visited.insert(start.clone());
    queue.push_back(start);

    while let Some((class_file, class_name)) = queue.pop_front() {
        let Some(bases) = ctx
            .class_bases_by_file_class
            .get(&(class_file.as_str(), class_name.as_str()))
        else {
            continue;
        };
        for &base_raw in bases {
            let Some((base_file, base_class)) = locate_base_class(&class_file, base_raw, ctx)
            else {
                continue;
            };
            for method_key in receiver_method_keys(&base_class, method) {
                if let Some(&dst_id) = ctx
                    .entity_by_file_name
                    .get(&(base_file.as_str(), method_key.as_str()))
                {
                    return Some(dst_id);
                }
            }
            if visited.len() >= INHERITANCE_WALK_CAP {
                return None;
            }
            let key = (base_file, base_class);
            if !visited.contains(&key) {
                visited.insert(key.clone());
                queue.push_back(key);
            }
        }
    }
    None
}

/// Whether an entity kind can override an ancestor's member.
///
/// Methods are the whole of it for the languages kin parses, but a parser that
/// records a class member as a plain function is admitted on the same footing
/// so the rule turns on the parser's own `Contains` edge rather than on a
/// naming convention.
fn is_overridable_member(kind: Option<&EntityKind>) -> bool {
    matches!(kind, Some(EntityKind::Method | EntityKind::Function))
}

/// Build the `Overrides` edge for a resolved (child member, base member) pair.
///
/// `Parsed` origin and full confidence, because every input is syntax the
/// parser read: the base declaration, the two member declarations, and the
/// resolution tiers that connected them. Evidence carries the overriding
/// member's own span, so a reader is sent to the declaration that does the
/// overriding rather than to the base it replaces.
fn override_relation(child: EntityId, base: EntityId, span: Option<&SourceSpan>) -> Relation {
    Relation {
        id: stable_relation_id(&child, &base, &RelationKind::Overrides),
        kind: RelationKind::Overrides,
        src: GraphNodeId::Entity(child),
        dst: GraphNodeId::Entity(base),
        confidence: 1.0,
        origin: RelationOrigin::Parsed,
        created_in: None,
        import_source: None,
        evidence: vec![RelationEvidence {
            source_span: span.cloned(),
            parser_rule: Some(OVERRIDE_EVIDENCE_RESOLVED_BASE_V1.to_string()),
            ..RelationEvidence::default()
        }],
    }
}

/// Emit `Overrides(child member -> base member)` for every member a class
/// redeclares from an ancestor it declares and the linker can resolve.
///
/// This is a syntactic fact, not a type-resolved one, and it is deliberately
/// the same fact the inherited-call path already trusts: the walk is
/// [`resolve_inherited_method`], so a class overrides exactly what a call
/// through that class would have reached on its base. Two answers derived from
/// one walk cannot disagree, which matters because a consumer that counts a
/// caller of the base as reaching the override would otherwise double count or
/// miss depending on which of two walks it asked.
///
/// A base that resolves to nothing yields nothing. `locate_base_class` returns
/// `None` for an external, builtin, or ambiguous base name, and the walk ends
/// that branch rather than guessing. A name-only base reference never mints an
/// edge, because it is not evidence that anything was overridden.
///
/// Class membership comes from the parser's `Contains` edges rather than from
/// splitting qualified entity names, so a language whose parser names members
/// bare is covered on the same footing as one that qualifies them. Kept in
/// exact resolution parity with [`derive_override_relations_incremental`].
fn derive_override_relations(file: &FileParseData, ctx: &LinkContext<'_>) -> Vec<Relation> {
    let file_path = file.file_path.as_str();
    // Nothing in this file declares a base, so nothing in it can override.
    if !file
        .relations
        .iter()
        .any(|rel| rel.kind == RelationKind::Extends)
    {
        return Vec::new();
    }

    let span_by_id: HashMap<EntityId, &SourceSpan> = file
        .entities
        .iter()
        .filter_map(|entity| entity.span.as_ref().map(|span| (entity.id, span)))
        .collect();

    let mut overrides = Vec::new();
    for rel in &file.relations {
        if rel.kind != RelationKind::Contains {
            continue;
        }
        // Only a class this file declares a base for can override anything.
        if !ctx
            .class_bases_by_file_class
            .contains_key(&(file_path, rel.src_name.as_str()))
        {
            continue;
        }
        let Some(&child_id) = ctx
            .entity_by_file_name
            .get(&(file_path, rel.dst_name.as_str()))
        else {
            continue;
        };
        if !is_overridable_member(ctx.entity_kind_by_id.get(&child_id)) {
            continue;
        }
        let Some(base_id) = resolve_inherited_method(
            file_path,
            &rel.src_name,
            bare_entity_name(&rel.dst_name),
            ctx,
        ) else {
            continue;
        };
        // A cycle in the declared hierarchy could walk back to the member it
        // started from; a member does not override itself.
        if base_id == child_id {
            continue;
        }
        overrides.push(override_relation(
            child_id,
            base_id,
            span_by_id.get(&child_id).copied(),
        ));
    }
    overrides
}

/// Incremental-linker counterpart of [`locate_base_class`], kept in exact
/// resolution parity: same-file class, then the caller file's import bindings,
/// then a repo-globally unique class name. `import_map` is the step-local
/// import index, so the import tier only sees files parsed this step — files
/// recorded at earlier steps still resolve through the same-file and
/// global-unique tiers.
fn locate_base_class_incremental(
    class_file: &str,
    base_raw: &str,
    linker: &IncrementalLinker,
    import_map: &HashMap<&str, HashMap<&str, (&str, &str)>>,
) -> Option<(String, String)> {
    let base_leaf = bare_entity_name(base_raw);

    if let Some(id) = linker
        .entity_by_file_name
        .get(class_file)
        .and_then(|m| m.get(base_leaf))
    {
        if is_class_like(linker.entity_kind_by_id.get(id)) {
            return Some((class_file.to_string(), base_leaf.to_string()));
        }
    }

    if let Some(file_imports) = import_map.get(class_file) {
        let (binding, target_name) = match base_raw.split_once('.') {
            Some((first, _)) => (first, base_leaf),
            None => (base_raw, ""),
        };
        if let Some(&(module_path, original_name)) = file_imports.get(binding) {
            let target_name = if target_name.is_empty() {
                original_name
            } else {
                target_name
            };
            if let Some(target_file) =
                resolve_module_path(class_file, module_path, &linker.known_files)
            {
                if let Some(id) = linker
                    .entity_by_file_name
                    .get(&target_file)
                    .and_then(|m| m.get(target_name))
                {
                    if is_class_like(linker.entity_kind_by_id.get(id)) {
                        return Some((target_file, target_name.to_string()));
                    }
                }
            }
        }
    }

    let mut unique: Option<(&str, EntityId)> = None;
    if let Some(candidates) = linker.entity_by_name.get(base_leaf) {
        for (fp, id) in candidates {
            match unique {
                None => unique = Some((fp.as_str(), *id)),
                Some((_, seen)) if seen == *id => {}
                Some(_) => return None,
            }
        }
    }
    if let Some((fp, id)) = unique {
        if is_class_like(linker.entity_kind_by_id.get(&id)) {
            return Some((fp.to_string(), base_leaf.to_string()));
        }
    }
    None
}

/// Incremental-linker counterpart of [`resolve_inherited_method`], kept in
/// exact resolution parity: breadth-first over declaration-ordered bases,
/// cycle-guarded, bounded by [`INHERITANCE_WALK_CAP`], never guessing an
/// unlocatable base. Without this twin an inherited-method edge resolved into a
/// full-tree snapshot would drop the moment an incremental relink of the
/// caller re-derives its edges — the exact failure mode the (c2) parity work
/// fixed for bare receiver methods.
fn resolve_inherited_method_incremental(
    src_file: &str,
    owner: &str,
    method: &str,
    linker: &IncrementalLinker,
    import_map: &HashMap<&str, HashMap<&str, (&str, &str)>>,
    class_bases: &HashMap<String, Vec<(String, Vec<String>)>>,
) -> Option<EntityId> {
    let start = (src_file.to_string(), owner.to_string());
    let mut visited: HashSet<(String, String)> = HashSet::new();
    let mut queue: std::collections::VecDeque<(String, String)> = std::collections::VecDeque::new();
    visited.insert(start.clone());
    queue.push_back(start);

    while let Some((class_file, class_name)) = queue.pop_front() {
        let Some(bases) = class_bases_in(class_bases, &class_file, &class_name) else {
            continue;
        };
        for base_raw in bases {
            let Some((base_file, base_class)) =
                locate_base_class_incremental(&class_file, base_raw, linker, import_map)
            else {
                continue;
            };
            for method_key in receiver_method_keys(&base_class, method) {
                if let Some(&dst_id) = linker
                    .entity_by_file_name
                    .get(&base_file)
                    .and_then(|m| m.get(method_key.as_str()))
                {
                    return Some(dst_id);
                }
            }
            if visited.len() >= INHERITANCE_WALK_CAP {
                return None;
            }
            let key = (base_file, base_class);
            if !visited.contains(&key) {
                visited.insert(key.clone());
                queue.push_back(key);
            }
        }
    }
    None
}

/// Incremental-linker counterpart of [`derive_override_relations`], kept in
/// exact resolution parity: the same `Contains`-driven membership, the same
/// overridable-kind rule, and the same walk through
/// [`resolve_inherited_method_incremental`], whose base resolution mirrors
/// [`locate_base_class`] tier for tier. `class_bases` is the step-local
/// hierarchy overlay, so a class whose base was declared in this step resolves
/// exactly as the batch linker would resolve it.
fn derive_override_relations_incremental(
    file: &FileParseData,
    linker: &IncrementalLinker,
    import_map: &HashMap<&str, HashMap<&str, (&str, &str)>>,
    class_bases: &HashMap<String, Vec<(String, Vec<String>)>>,
) -> Vec<Relation> {
    let file_path = file.file_path.as_str();
    if !file
        .relations
        .iter()
        .any(|rel| rel.kind == RelationKind::Extends)
    {
        return Vec::new();
    }

    let span_by_id: HashMap<EntityId, &SourceSpan> = file
        .entities
        .iter()
        .filter_map(|entity| entity.span.as_ref().map(|span| (entity.id, span)))
        .collect();

    let mut overrides = Vec::new();
    for rel in &file.relations {
        if rel.kind != RelationKind::Contains {
            continue;
        }
        if class_bases_in(class_bases, file_path, &rel.src_name).is_none() {
            continue;
        }
        let Some(&child_id) = linker
            .entity_by_file_name
            .get(file_path)
            .and_then(|by_name| by_name.get(rel.dst_name.as_str()))
        else {
            continue;
        };
        if !is_overridable_member(linker.entity_kind_by_id.get(&child_id)) {
            continue;
        }
        let Some(base_id) = resolve_inherited_method_incremental(
            file_path,
            &rel.src_name,
            bare_entity_name(&rel.dst_name),
            linker,
            import_map,
            class_bases,
        ) else {
            continue;
        };
        if base_id == child_id {
            continue;
        }
        overrides.push(override_relation(
            child_id,
            base_id,
            span_by_id.get(&child_id).copied(),
        ));
    }
    overrides
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

/// What the calling file's own declarations say about the receiver of an
/// attribute call (`receiver.method(...)`).
///
/// Python's `x.method()` and `mod.function()` are the same syntax and arrive
/// with the same bare leaf name. Only the file's imports separate them, and the
/// difference decides what the callee can possibly be: a call through an
/// imported module reaches a module-level function in that module, while a call
/// through an object reaches a member of some type and can never reach a
/// module-level function. Collapsing the two is what let
/// `Session.merge_environment_settings`, whose only `.get(` sites are
/// `proxies.get("no_proxy")` and `os.environ.get(...)`, bind to the public
/// `requests.get`.
#[derive(Debug, PartialEq, Eq)]
enum ReceiverScope {
    /// The receiver's root name is bound by an import that resolves to a file
    /// in this repository: the callee is a member of that module.
    Module(String),
    /// The receiver's root name is bound by an import whose module is not part
    /// of this repository (stdlib, a third-party package). No local entity can
    /// be the destination.
    ExternalModule,
    /// The receiver is a value — a parameter, a local, an attribute read, a
    /// call result. Its type is not known here, but it is not a module, so the
    /// destination must be a member of some type.
    Object,
}

/// Package-index filenames a bare module name may resolve through when the
/// language writes a directory module rather than a file. Kept beside the
/// receiver resolver rather than folded into [`INDEX_FILENAMES`], which is the
/// import-path resolver's own list.
const PACKAGE_INDEX_FILENAMES: &[&str] = &["__init__.py", "index.ts", "index.js", "mod.rs"];

/// Locate the repository file a receiver's imported module names, if any.
///
/// Falls back to a bare dotted module name (`mathlib`, `pkg.mathlib`) read as a
/// repo path, tried from the caller's own directory first — a sibling module
/// imported by bare name is the common Python shape and the import-path
/// resolver does not cover it. Returning `None` is the positive finding that no
/// file in this repository can be that module, which is what separates a stdlib
/// receiver from a repo-local one.
fn resolve_receiver_module_file<S>(
    caller_file: &str,
    module_path: &str,
    known_files: &HashSet<S>,
) -> Option<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    if let Some(target_file) = resolve_module_path(caller_file, module_path, known_files) {
        return Some(target_file);
    }
    if module_path.is_empty() || !module_path.split('.').all(is_path_identifier) {
        return None;
    }
    let relative = module_path.replace('.', "/");
    let caller_dir = parent_dir(caller_file);
    let bases = [format!("{caller_dir}/{relative}"), relative.clone()];
    for base in bases.iter().map(|base| base.trim_start_matches('/')) {
        if base.is_empty() {
            continue;
        }
        for ext in MODULE_EXTENSIONS {
            let candidate = format!("{base}.{ext}");
            if known_files.contains(candidate.as_str()) {
                return Some(candidate);
            }
        }
        for index in PACKAGE_INDEX_FILENAMES {
            let candidate = format!("{base}/{index}");
            if known_files.contains(candidate.as_str()) {
                return Some(candidate);
            }
        }
    }
    None
}

/// Classify an attribute call's receiver against the calling file's imports.
///
/// Only the receiver's root segment is consulted: `os.environ.get(...)` is a
/// call through `os`, and whether `os` is a repo module or a stdlib one is
/// exactly the question that decides whether a local `get` may be the target.
fn classify_receiver<S>(
    receiver: &str,
    caller_file: &str,
    file_imports: Option<&HashMap<&str, (&str, &str)>>,
    known_files: &HashSet<S>,
) -> ReceiverScope
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let root = receiver.split('.').next().unwrap_or(receiver).trim();
    if root.is_empty() || !is_path_identifier(root) {
        return ReceiverScope::Object;
    }
    let Some(&(module_path, _)) = file_imports.and_then(|imports| imports.get(root)) else {
        return ReceiverScope::Object;
    };
    match resolve_receiver_module_file(caller_file, module_path, known_files) {
        Some(target_file) => ReceiverScope::Module(target_file),
        None => ReceiverScope::ExternalModule,
    }
}

/// Whether this relation is a Python call written as a bare identifier.
///
/// Python is the only adapter that separates the two call shapes at extraction
/// time: an attribute call carries its receiver as written, a `self`/`cls` call
/// folds its owner into the callee name, and only a bare `name(...)` arrives
/// with neither. Adapters that record no receiver at all cannot tell the shapes
/// apart, so the gates keyed on this predicate stay off their calls rather than
/// reading a missing receiver as proof of a bare call.
fn is_python_bare_identifier_call(
    rel: &ExtractedRelation,
    src_id: EntityId,
    languages: &HashMap<EntityId, LanguageId>,
) -> bool {
    rel.kind == RelationKind::Calls
        && rel.receiver.is_none()
        && !rel.dst_name.contains('.')
        && !rel.dst_name.contains("::")
        && languages.get(&src_id) == Some(&LanguageId::Python)
}

/// Whether a wildcard import could be binding names this file never spells.
///
/// `from constants import *` is recorded as an import with no specifiers,
/// because there is no name to record. Every name that import binds is
/// therefore invisible here, so a file carrying one has no answer to "does this
/// file import that name" and the builtin gate stands down instead of guessing.
fn imports_are_name_complete(imports: &[FileImport]) -> bool {
    imports.iter().all(|import| !import.specifiers.is_empty())
}

/// Whether a bare Python call names a builtin this file cannot have rebound.
///
/// A module-level name is reachable inside a Python module only when that
/// module defines it or imports it. So a bare call to a name in the builtins
/// table, from a file that does neither, is a call into the interpreter, and
/// every remaining linker tier would answer it by matching the name somewhere
/// else in the repository. That is how `open(path)` in a parsing module that
/// imports `os` and `re` acquired a `Calls` edge to `NoteStore.open` in a
/// storage module it never imports, and a `trace_data_flow` subtree underneath
/// it.
///
/// A local definition or an import of the same name is the shadow Python allows,
/// and it wins: this returns false there, leaving the same-file and import tiers
/// to resolve the call exactly as before.
fn is_unbound_python_builtin_call(
    rel: &ExtractedRelation,
    src_id: EntityId,
    file: &FileParseData,
    defined_in_file: bool,
    file_imports: Option<&HashMap<&str, (&str, &str)>>,
    languages: &HashMap<EntityId, LanguageId>,
) -> bool {
    is_python_bare_identifier_call(rel, src_id, languages)
        && is_python_builtin_name(rel.dst_name.as_str())
        && !defined_in_file
        && !file_imports.is_some_and(|imports| imports.contains_key(rel.dst_name.as_str()))
        && imports_are_name_complete(&file.imports)
}

/// Whether this relation is a Rust call written as a plain `name(..)`.
///
/// The Rust adapter records a dispatch through an object with its receiver as
/// written, and folds `self.m()` / `Self::m()` into the `Owner::m` key the
/// method entity is stored under. So a Rust call arriving with neither a
/// receiver nor a path is the one shape that genuinely has no receiver.
fn is_rust_bare_identifier_call(
    rel: &ExtractedRelation,
    src_id: EntityId,
    languages: &HashMap<EntityId, LanguageId>,
) -> bool {
    rel.kind == RelationKind::Calls
        && rel.receiver.is_none()
        && !rel.dst_name.contains('.')
        && !rel.dst_name.contains("::")
        && languages.get(&src_id) == Some(&LanguageId::Rust)
}

/// Whether a bare Rust call may reach the owner-qualified entities the
/// bare-name index holds.
///
/// Every entry in that index is stored under an owner (`Type::method`,
/// `Enum::Variant`), and Rust reaches none of those from a plain `name(..)`.
/// An inherent or trait method needs a receiver or a `Type::` path, and a
/// variant or associated item needs the `use` that binds its short name here.
/// That is how `Ok(self.width())` acquired a `Calls` edge to a repository
/// `ParseResult::Ok` in a module the caller never names: `Ok` is
/// `core::result::Result::Ok`, and the one entity in the graph spelling the
/// same leaf captured the call, carrying a `trace_data_flow` subtree with it.
///
/// A `use` of that exact name is the binding Rust does allow, and it wins. A
/// glob import binds names this parse cannot see, so a file carrying one has no
/// answer to "does this file bind that name" and the gate stands down rather
/// than guessing, exactly as the Python builtin gate does for `import *`.
fn rust_bare_call_may_reach_owned(
    dst_name: &str,
    file: &FileParseData,
    file_imports: Option<&HashMap<&str, (&str, &str)>>,
) -> bool {
    !imports_are_name_complete(&file.imports)
        || file_imports.is_some_and(|imports| imports.contains_key(dst_name))
}

/// The owner path of a qualified entity name, and the separator that joined it.
///
/// Mirrors [`bare_entity_name`]'s precedence exactly, `::` before `.`, so the
/// two can never disagree about where a name splits: this returns the owner of
/// the leaf that one returns. `None` for an unqualified name, which is what
/// keeps a free function out of the sibling tier below.
fn entity_owner_path(name: &str) -> Option<(&str, &str)> {
    match name.rfind("::") {
        Some(idx) if idx > 0 => Some((&name[..idx], "::")),
        Some(_) => None,
        None => match name.rfind('.') {
            Some(idx) if idx > 0 => Some((&name[..idx], ".")),
            _ => None,
        },
    }
}

/// Whether a bare `name(..)` in this language reaches a sibling member of the
/// caller's own owner with no receiver written.
///
/// Measured against the real adapters rather than assumed. Every adapter this
/// indexes emits the identical relation for `b()` inside `Foo.a`: a `Calls`
/// with `dst_name = "b"` and no receiver. The relation cannot tell the
/// languages apart, so only the language can.
///
/// The five here give a member call an implicit receiver, so `b()` inside
/// `Foo.a` is `this.b()` or `self.b()` and the same-owner sibling is the target
/// the source names. Every other language is left out, each for its own reason:
///
///   * Python and Rust need `self.b()` or `Self::b()`. The gates at
///     [`is_python_bare_identifier_call`] and [`rust_bare_call_may_reach_owned`]
///     already say so, and this tier must not step around them.
///   * Go needs `f.b()`; a bare `b()` inside a method names a package-level
///     function.
///   * PHP needs `$this->b()`; a bare `b()` inside a method names a global
///     function.
///   * JavaScript and TypeScript need `this.b()`.
///   * C has no owner-qualified entities, so the lookup could never hit.
///   * Ruby's adapter records no call at all for the bare shape, so a rule for
///     it would be a rule nothing exercises.
///   * HCL has no call syntax.
///
/// An allowlist and not a denylist, on purpose: a language added to
/// [`LanguageId`] tomorrow inherits no binding rule until somebody makes the
/// same judgement for it and writes it here.
fn bare_call_reaches_owner_sibling(
    src_id: EntityId,
    languages: &HashMap<EntityId, LanguageId>,
) -> bool {
    matches!(
        languages.get(&src_id),
        Some(
            LanguageId::Java
                | LanguageId::CSharp
                | LanguageId::Cpp
                | LanguageId::Kotlin
                | LanguageId::Swift
        )
    )
}

/// (c2a) The name of the same-file sibling under the caller's own owner that a
/// bare call reaches, if this call can reach one at all.
///
/// No tier before this one can. Tier (a) keys `entity_by_file_name` on the FULL
/// name and `Foo::b` is not `b`; tier (c) keys `entity_by_name` the same way;
/// tier (c2) does hold `Foo::b` under its bare leaf and drops every candidate
/// in the caller's own file. So `void Foo::a() { b(); }` emitted no relation of
/// any kind, not even a placeholder, and `find_references`, blast radius and
/// every rename built on the graph omitted the site with nothing to say so.
///
/// This composes the sibling's full name from the caller's own owner. Composing
/// rather than searching the bare-leaf index is what keeps the tier safe: that
/// index would also offer `Bar::b` in the same file, which a bare call in none
/// of these languages can reach. The composed name is then looked up by the
/// caller, which applies the same candidate filters (c2) applies before
/// deciding, so the two tiers cannot drift on what an overload or a test-only
/// target admits.
fn same_owner_sibling_name<'r>(
    rel: &'r ExtractedRelation,
    src_id: EntityId,
    languages: &HashMap<EntityId, LanguageId>,
) -> Option<(String, &'r str)> {
    if rel.kind != RelationKind::Calls || rel.receiver.is_some() {
        return None;
    }
    let leaf = rel.dst_name.as_str();
    if leaf.is_empty() || leaf.contains('.') || leaf.contains("::") {
        return None;
    }
    if !bare_call_reaches_owner_sibling(src_id, languages) {
        return None;
    }
    let (owner, separator) = entity_owner_path(rel.src_name.as_str())?;
    Some((format!("{owner}{separator}{leaf}"), leaf))
}

/// Whether the bare leaf of a call can mean anything in this repository other
/// than the sibling [`same_owner_sibling_name`] composed.
///
/// The adapters for every language in [`bare_call_reaches_owner_sibling`] record
/// NO receiver for `h.b()`. That is measured, in
/// `tests/same_owner_bare_call_resolution.rs`, not assumed: Java, C#, Kotlin,
/// Swift and C++ all emit the same relation for `h.b()` as for `b()`, a `Calls`
/// with `dst_name = "b"` and `receiver: None`. Only Python and Rust separate the
/// two shapes at extraction time, and neither is in the allowlist. So this tier
/// cannot ask whether a receiver was written, and something else has to stand in
/// for that question, or an object call would bind to whatever member of the
/// caller's own class shares the leaf. That is the phantom-consumer defect the
/// `proxies.get("no_proxy")` gate above exists to prevent, arriving in the one
/// place a decoy is most likely.
///
/// Uniqueness stands in. When the leaf names exactly one owner-qualified entity
/// in the whole universe and no unqualified one, there is nothing else the call
/// could have meant whatever was written before the dot. That is precisely the
/// shape the ticket describes, a bare call whose ONLY candidate is a same-file
/// qualified-name entity, and it is what keeps `h.b()` off the caller's own
/// `Foo.b` wherever `Helper.b` is in the graph.
///
/// The bound it leaves is stated rather than hidden: a receiver call whose
/// receiver type the graph does not hold at all still binds to the caller's own
/// sibling. Closing that needs the adapters to record receivers for these
/// languages, which is a parser change and not a linker one.
fn bare_leaf_names_one_thing(bare_holders: usize, exact_holders: usize) -> bool {
    bare_holders == 1 && exact_holders == 0
}

/// Drop the method candidates a bare Python call can never dispatch to.
///
/// A method needs a receiver to be reached, and a bare `name(...)` has none, so
/// a same-named method is a decoy however few of them the repository holds. The
/// bare-name index holds only owner-qualified entities, which is exactly where
/// `open` found `NoteStore.open`: a `@classmethod` no bare-name call can invoke.
///
/// Non-method candidates are left to the builtin and import tiers above; this
/// filter only answers the receiver question.
/// Drop the module entities a call can never reach.
///
/// A module is not callable in any language this indexes, and its Python entity
/// is named for the file stem, so `nk/search.py` puts a Module named `search`
/// in the same-name bucket as the function `def search(...)`. Leaving it there
/// made the bucket hold two ids for one callable name, which the exact-name
/// tier reads as an unresolvable ambiguity and the package-directory fallback
/// reads as two candidates, so a caller writing `from nk.search import search`
/// got no edge at all rather than the wrong one.
///
/// A `References` edge is left alone: `import nk.search` then passing
/// `nk.search` as a value genuinely names the module.
fn drop_module_call_targets<'a>(
    kind: RelationKind,
    candidates: Vec<(&'a str, EntityId)>,
    kinds: &HashMap<EntityId, EntityKind>,
) -> Vec<(&'a str, EntityId)> {
    if kind != RelationKind::Calls {
        return candidates;
    }
    candidates
        .into_iter()
        .filter(|(_, id)| kinds.get(id) != Some(&EntityKind::Module))
        .collect()
}

fn drop_method_candidates<'a>(
    candidates: Vec<(&'a str, EntityId)>,
    kinds: &HashMap<EntityId, EntityKind>,
) -> Vec<(&'a str, EntityId)> {
    candidates
        .into_iter()
        .filter(|(_, id)| kinds.get(id) != Some(&EntityKind::Method))
        .collect()
}

/// Keep a production call site from resolving to a test entity while a
/// production entity of the same name is available.
///
/// `RedirectSession` in `tests/test_requests.py` subclasses a redirect mixin
/// and can never be the receiver at `adapter.send(...)` in `sessions.py`, yet a
/// bare-name fan-out over every `send` in the repository reached it. Role is
/// already extracted per entity, so the tiebreak costs nothing. Test callers are
/// left alone: a test legitimately calls its own doubles.
fn narrow_candidates_by_role(
    src_id: EntityId,
    targets: HashSet<EntityId>,
    roles: &HashMap<EntityId, EntityRole>,
) -> HashSet<EntityId> {
    if roles.get(&src_id) != Some(&EntityRole::Source) {
        return targets;
    }
    let has_source_candidate = targets
        .iter()
        .any(|id| roles.get(id) == Some(&EntityRole::Source));
    if !has_source_candidate {
        return targets;
    }
    targets
        .into_iter()
        .filter(|id| roles.get(id) != Some(&EntityRole::Test))
        .collect()
}

/// The `(file, id)` form of [`narrow_candidates_by_role`], for the tiers that
/// still need each candidate's defining file to disambiguate by locality.
fn narrow_pairs_by_role<'a>(
    src_id: EntityId,
    candidates: Vec<(&'a str, EntityId)>,
    roles: &HashMap<EntityId, EntityRole>,
) -> Vec<(&'a str, EntityId)> {
    if roles.get(&src_id) != Some(&EntityRole::Source) {
        return candidates;
    }
    let has_source_candidate = candidates
        .iter()
        .any(|(_, id)| roles.get(id) == Some(&EntityRole::Source));
    if !has_source_candidate {
        return candidates;
    }
    candidates
        .into_iter()
        .filter(|(_, id)| roles.get(id) != Some(&EntityRole::Test))
        .collect()
}

/// The receiver-method candidates whose owning type the calling file binds by
/// name, each mapped back to the local name that bound it.
///
/// A method entity is keyed `Owner.method` or `Owner::method`, so a file's
/// import bindings name candidate owners directly: for each local name an
/// import introduces, the two owner-qualified spellings of the call's leaf
/// select exactly the methods that name's type defines. `named_ids` is the
/// caller's exact-name index, consulted once per import binding rather than
/// once per candidate.
///
/// The owner travels with each id because the number of DISTINCT owners is what
/// decides whether the call has a destination at all: one owner is a
/// destination the file named, several is a choice nothing at the call site
/// makes.
fn owner_bound_targets<'a>(
    leaf: &str,
    file_imports: Option<&HashMap<&'a str, (&'a str, &'a str)>>,
    mut named_ids: impl FnMut(&str, &mut Vec<EntityId>),
) -> HashMap<EntityId, &'a str> {
    let mut bound = HashMap::new();
    let Some(file_imports) = file_imports else {
        return bound;
    };
    for local_name in file_imports.keys() {
        let mut ids = Vec::new();
        for key in receiver_method_keys(local_name, leaf) {
            named_ids(&key, &mut ids);
        }
        for id in ids {
            bound.insert(id, *local_name);
        }
    }
    bound
}

/// Settle a receiver-method call against the owners the calling file names.
///
/// A call through an object dispatches on the receiver's static type, and the
/// only types a file can be holding one of are the ones it names: a class it
/// imports by name, or one it defines. A same-named method on a type this file
/// never sees is not a dispatch target here however many other files reach it.
///
/// So exactly two shapes bind. Exactly one named owner carries the leaf, and
/// its methods are the destination. Anything else binds nothing: no named owner
/// carries it, so the call has no destination this file can reach; or several
/// do, and choosing among them is a guess with nothing at the call site behind
/// it. This is FIR-1552's rule, and it is the one kin#906 applied to bare
/// Python builtins and kin#923 to bare Rust calls, applied to the shape that
/// produced the most edges: `find_references(HTTPAdapter.send)` on psf/requests
/// answered 33 where two lines call it, and every one of the 33 came through
/// this tier.
///
/// The earlier rule fanned out to every candidate when the file's imports
/// accounted for none of them, on the reasoning that a rule which cannot see
/// any candidate should not drop them all. That is the fail-open that minted
/// ten of those 33: a `sock.send(...)` in a test file that imports nothing
/// defining `send` reached the HTTP adapter, the session, and every other
/// `send` in the repository. A rule that cannot see the receiver's type does
/// not thereby know the answer is all of them.
fn settle_receiver_method_owner<'a>(
    candidates: Vec<(&'a str, EntityId)>,
    owner_bound: &HashMap<EntityId, &str>,
) -> Vec<(&'a str, EntityId)> {
    let reached: Vec<(&'a str, EntityId)> = candidates
        .into_iter()
        .filter(|(_, id)| owner_bound.contains_key(id))
        .collect();
    let owners: HashSet<&str> = reached
        .iter()
        .filter_map(|(_, id)| owner_bound.get(id).copied())
        .collect();
    if owners.len() == 1 {
        reached
    } else {
        Vec::new()
    }
}

/// Confidence for a call through a receiver the file's own imports bind to a
/// repo-local module, resolved inside that module. The module is known and the
/// symbol was selected within it, so this is import-scoped: the same band as
/// the parser-pinned and namespace-member tiers.
const RECEIVER_MODULE_CONFIDENCE: f32 = 0.9;

/// The local name a whole-module re-export binds its source module under.
///
/// `extract_assignment_lhs_name` keeps the `module.exports` receiver whole
/// rather than reducing it to the `exports` property, so a file that does
/// nothing but hand its exports on names the real module under this key in its
/// own import map.
const WHOLE_MODULE_REEXPORT_LOCAL_NAME: &str = "module.exports";

/// The sibling module a package-root receiver's own import specifier names.
///
/// `from pkg import mod` records `pkg` as the module path and `mod` as a
/// specifier and never joins the two, so the receiver resolves to
/// `pkg/__init__.py` while the callee is defined in the sibling `pkg/mod.py`.
/// The specifier is already in the calling file's import map, one element over
/// from the module path the receiver was classified through.
///
/// Only a receiver that landed on a package index is eligible, and only the one
/// sibling the import statement actually names is offered. A module file wins
/// over a subpackage of the same name, matching [`python_module_file`]'s order.
fn receiver_package_sibling<S>(
    target_file: &str,
    receiver_root: &str,
    caller_imports: Option<&HashMap<&str, (&str, &str)>>,
    known_files: &HashSet<S>,
) -> Option<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let base_name = target_file
        .rsplit_once('/')
        .map(|(_, name)| name)
        .unwrap_or(target_file);
    if !PACKAGE_INDEX_FILENAMES.contains(&base_name) {
        return None;
    }
    let specifier = caller_imports?.get(receiver_root)?.1.trim();
    if specifier.is_empty() || !is_path_identifier(specifier) {
        return None;
    }
    let dir = parent_dir(target_file);
    let prefix = if dir.is_empty() {
        specifier.to_string()
    } else {
        format!("{dir}/{specifier}")
    };
    for ext in MODULE_EXTENSIONS {
        let candidate = format!("{prefix}.{ext}");
        if known_files.contains(candidate.as_str()) {
            return Some(candidate);
        }
    }
    for index in PACKAGE_INDEX_FILENAMES {
        let candidate = format!("{prefix}/{index}");
        if known_files.contains(candidate.as_str()) {
            return Some(candidate);
        }
    }
    None
}

/// The module a file re-exports wholesale.
///
/// `module.exports = require('./lib/express')` makes the package entry point the
/// receiver's file while every export lives one hop away, which is why
/// `express.static(...)` reached nothing even once `lib/express.js` carried the
/// entity. The re-export is already recorded as an import of this file, so the
/// destination is read rather than guessed. A re-export that resolves back to
/// its own file is refused: a self-loop is not a hop.
fn whole_module_reexport_target<S>(
    target_file: &str,
    import_map: &HashMap<&str, HashMap<&str, (&str, &str)>>,
    known_files: &HashSet<S>,
) -> Option<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let (module_path, _) = import_map
        .get(target_file)?
        .get(WHOLE_MODULE_REEXPORT_LOCAL_NAME)?;
    let resolved = resolve_module_path(target_file, module_path, known_files)?;
    (resolved != target_file).then_some(resolved)
}

/// The single file a receiver's module hands its callee off to, when the
/// receiver's own file does not define it.
///
/// Tier (a0) binds a receiver to the file its import names, and that file is
/// frequently one hop short of where the callee lives. Two shapes produce that
/// gap and each names its own destination in source, so neither needs a guess:
/// a Python package index standing in for a submodule, and a JavaScript entry
/// point that re-exports another module wholesale.
///
/// Exactly one candidate is returned, chosen by a statement the source actually
/// wrote. Handing the call to the name-matching tiers instead would bind the
/// bare leaf to any same-named symbol in the repository, which is the false
/// consumer the caller's `continue` exists to prevent.
fn resolve_receiver_module_hop<S>(
    target_file: &str,
    receiver_root: &str,
    caller_imports: Option<&HashMap<&str, (&str, &str)>>,
    import_map: &HashMap<&str, HashMap<&str, (&str, &str)>>,
    known_files: &HashSet<S>,
) -> Option<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    receiver_package_sibling(target_file, receiver_root, caller_imports, known_files)
        .or_else(|| whole_module_reexport_target(target_file, import_map, known_files))
}

/// Resolve an attribute call whose receiver names a repo-local module. The
/// callee is looked up as a plain member of that module first, then as a member
/// of a type the receiver's own root names (`Session.get` for `Session.get(...)`
/// where `Session` was imported). When neither name is in that file, one
/// re-export hop the source itself names is followed and both lookups are tried
/// again there.
///
/// `lookup` is the caller's own entity index, passed as a closure because the
/// batch and incremental linkers key theirs differently and this tier has to
/// answer identically in both: a cold, incremental and reopened graph resolving
/// one call to different destinations is drift, not a difference.
fn resolve_receiver_module_target<S>(
    target_file: &str,
    receiver_root: &str,
    method: &str,
    caller_imports: Option<&HashMap<&str, (&str, &str)>>,
    import_map: &HashMap<&str, HashMap<&str, (&str, &str)>>,
    known_files: &HashSet<S>,
    lookup: impl Fn(&str, &str) -> Option<EntityId>,
) -> Option<EntityId>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let qualified = format!("{receiver_root}.{method}");
    let in_file = |file: &str| lookup(file, method).or_else(|| lookup(file, qualified.as_str()));
    if let Some(dst_id) = in_file(target_file) {
        return Some(dst_id);
    }
    let hop = resolve_receiver_module_hop(
        target_file,
        receiver_root,
        caller_imports,
        import_map,
        known_files,
    )?;
    in_file(&hop)
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
fn make_relation(
    rel: &ExtractedRelation,
    src: EntityId,
    dst: EntityId,
    confidence: f32,
    caller_file: &FilePathId,
    parse_completeness: &ParseCompleteness,
    call_extraction_complete: bool,
) -> Relation {
    let kind = rel.kind;
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
        evidence: relation_evidence(
            rel,
            caller_file,
            parse_completeness,
            call_extraction_complete,
        ),
    }
}

/// The stored evidence for one resolved relation: its call shape, when the
/// adapter records shapes, carrying the site the syntax was read at, when the
/// adapter records sites.
///
/// The site is the whole point of `reference_lines`. An adapter reports it
/// file-free, because a relation's syntax is always inside the file being
/// parsed; pairing it with `caller_file` here is what makes the span belong to
/// the caller rather than to whichever file a later stage happened to hold.
/// That also means a parser-recorded site can never land under
/// `span_outside_caller_file`.
///
/// A non-call edge previously carried no evidence record at all, so a site on
/// one has nothing to attach to and gets a record of its own. A call edge's
/// record already exists for the shape, and the site goes onto it rather than
/// beside it, so an edge does not report one occurrence twice.
pub(crate) fn relation_evidence(
    rel: &ExtractedRelation,
    caller_file: &FilePathId,
    parse_completeness: &ParseCompleteness,
    call_extraction_complete: bool,
) -> Vec<RelationEvidence> {
    let mut evidence = call_shape_evidence(
        rel.kind,
        rel.call_shape.as_ref(),
        parse_completeness,
        call_extraction_complete,
    );
    let Some(site) = rel.site.as_ref() else {
        return evidence;
    };
    let span = site.to_source_span(caller_file);
    let rule = site.syntactic_role.map(|role| match role {
        RelationSyntacticRole::RaiseTarget => RAISE_TARGET_CALL_RULE.to_string(),
    });
    if evidence.is_empty() {
        let mut only = RelationEvidence {
            source_span: Some(span),
            ..RelationEvidence::default()
        };
        only.parser_rule = rule;
        return vec![only];
    }
    for record in &mut evidence {
        record.source_span = Some(span.clone());
    }
    // The syntactic role the adapter classified, carried onto the persisted
    // evidence so a consumer that never sees the parse can still tell a throw
    // site from a hop it should spend a trace slot on.
    //
    // A record of its own rather than a field on the shape record, because a
    // shaped call already spends `parser_rule` on its aggregation certificate
    // and `rename` matches that string exactly. Deliberately span-free: every
    // consumer that counts occurrences reads spans, so a marker with none adds
    // no occurrence, no reference line and no evidence a reader could mistake
    // for a second call site.
    if let Some(rule) = rule {
        evidence.push(RelationEvidence {
            parser_rule: Some(rule),
            ..RelationEvidence::default()
        });
    }
    evidence
}

/// Convert a parser-side [`CallArgShape`] into stored relation evidence carrying
/// the graph-model shape mirror. Fully parsed shaped calls receive the complete
/// aggregation certificate; recovered calls receive an explicit unshaped
/// marker because the parse may have omitted sibling occurrences. Non-call and
/// fully parsed shape-blind edges stay evidence-free as before.
pub(crate) fn call_shape_evidence(
    kind: RelationKind,
    shape: Option<&CallArgShape>,
    parse_completeness: &ParseCompleteness,
    call_extraction_complete: bool,
) -> Vec<RelationEvidence> {
    if kind != RelationKind::Calls {
        return Vec::new();
    }
    if !call_extraction_complete {
        return vec![RelationEvidence {
            parser_rule: Some(CALL_SHAPE_EVIDENCE_INCOMPLETE_EXTRACTION_V1.to_string()),
            call_shape: None,
            ..RelationEvidence::default()
        }];
    }
    if !matches!(parse_completeness, ParseCompleteness::Full) {
        return vec![RelationEvidence {
            parser_rule: Some(CALL_SHAPE_EVIDENCE_INCOMPLETE_PARSE_V1.to_string()),
            call_shape: None,
            ..RelationEvidence::default()
        }];
    }
    match shape {
        Some(shape) => vec![RelationEvidence {
            parser_rule: Some(CALL_SHAPE_EVIDENCE_AGGREGATION_V1.to_string()),
            call_shape: Some(kin_model::CallArgShape::new(
                shape.positional,
                shape.keywords.clone(),
                shape.has_var_positional,
                shape.has_var_keyword,
            )),
            ..RelationEvidence::default()
        }],
        None => Vec::new(),
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

/// Linker evidence rule that identifies an intentional cross-repo placeholder
/// destination. Consumers may accept a missing destination only when a
/// Calls/References relation also has a non-empty import source and this rule.
pub const EXTERNAL_IMPORT_REFERENCE_RULE: &str = "external_import_reference";

/// Evidence marker for a call the parser read as the operand of a `raise`.
///
/// `raise SSLError(...)` in an `except` block is a call edge like any other and
/// is genuinely evidence, but it is a throw site rather than a hop a value
/// travels along. A trace walking data flow needs to tell the two apart: on a
/// converted `psf/requests`, nine of the twelve depth-1 slots a stranger's
/// trace returned were exception constructors, and they crowded out the hop
/// that governs connection reuse. Carried as a `parser_rule` because that field
/// is already persisted on relation evidence, so no schema in `kin-model` moves.
pub const RAISE_TARGET_CALL_RULE: &str = "raise_target_call";

/// What lies on the other side of a boundary step, or an explicit statement
/// that the graph does not know.
///
/// An external record used to carry identity and nothing else, so `router.handle`
/// arrived as a bare symbol with no way to tell an npm package from a Node
/// builtin from a typo. The graph knows a boundary exists; when it also knows
/// the specifier the importing file named, saying it costs nothing, and when it
/// does not, saying THAT is the answer. Silence is the one option that reads
/// like an in-repo entity.
///
/// Lives here rather than on either surface because `trace_data_flow` has two
/// implementations, the CLI one the daemon route serves and the MCP one the
/// in-process arm serves, and a boundary rule that differs by whether a daemon
/// is up is the divergence class FIR-2507 was filed about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceCrossing {
    /// `named` when the graph holds the specifier, `unknown` when it holds only
    /// the fact of the boundary.
    pub status: String,
    /// The module specifier the importing file named (`router`, `urllib3`),
    /// when an edge into this symbol recorded one. Explicitly null under
    /// `unknown`, because the keys of this object are uniform for the same
    /// reason the step's are.
    #[serde(default)]
    pub specifier: Option<String>,
    /// The receiver the call was written through, when the edge recorded one
    /// and no specifier is available.
    ///
    /// Always `None` since the unresolved-receiver placeholder tier was removed:
    /// the only edge class that ever recorded a receiver here was the one that
    /// minted a destination entity out of the receiver's own spelling, and a
    /// resolver-bound specifier is the only provenance left. The key stays in
    /// the payload because the object's keys are uniform across both statuses,
    /// for the same reason the step's are.
    #[serde(default)]
    pub receiver: Option<String>,
    /// Why the status reads the way it does, in a sentence a caller can act on.
    pub note: String,
}

/// Whether this call edge came from a parse, so its silence about `raise` is
/// evidence rather than ignorance.
///
/// A resolved call reaches the graph twice on a repository with a language
/// server: once from the parser, carrying the syntax it read, and once from the
/// LSP call hierarchy, carrying only that the call exists. Only the parser can
/// see a `raise`, so an LSP edge that does not mark one is not saying the call
/// was ordinary; it is saying nothing at all, and letting it vote made the
/// raise demotion structurally impossible on any repository with a language
/// server installed. Measured on a converted `psf/requests`: every neighbour of
/// `HTTPAdapter.send` arrived on two call edges, one `Parsed` or `Inferred` and
/// one `Lsp`, so "every call edge is a raise" was false for `SSLError` even
/// though the only edge that could classify it said `raise_target_call`.
pub fn is_raise_classifiable_call_edge(rel: &Relation) -> bool {
    rel.kind == RelationKind::Calls && !matches!(rel.origin, RelationOrigin::Lsp)
}

/// Whether this edge is a call the parser read as the operand of a `raise`.
///
/// Reads the marker the linker persisted on the edge's own evidence, so a
/// language whose adapter does not record raise sites reports `false` and its
/// traces rank exactly as they did.
pub fn is_raise_target_edge(rel: &Relation) -> bool {
    rel.kind == RelationKind::Calls
        && rel
            .evidence
            .iter()
            .any(|evidence| evidence.parser_rule.as_deref() == Some(RAISE_TARGET_CALL_RULE))
}

/// The crossing record for a step, built from the edge that reached it.
///
/// Reads only what the graph already persisted: `import_source`, set by the
/// cross-repo tier when the parser pinned the module a symbol came from.
/// Nothing is inferred from a name, so a symbol the graph cannot place reports
/// `unknown` rather than a guess.
pub fn trace_crossing_for(entity: &Entity, reached_by: Option<&Relation>) -> Option<TraceCrossing> {
    if entity.file_origin.is_some() {
        return None;
    }
    let specifier = reached_by
        .and_then(|rel| rel.import_source.as_deref())
        .map(str::trim)
        .filter(|source| !source.is_empty())
        .map(str::to_string);
    if let Some(specifier) = specifier {
        return Some(TraceCrossing {
            note: format!(
                "the importing file named `{specifier}`; the graph holds no entities for what that resolves to"
            ),
            status: "named".to_string(),
            specifier: Some(specifier),
            receiver: None,
        });
    }
    Some(TraceCrossing {
        status: "unknown".to_string(),
        specifier: None,
        receiver: None,
        note: "no edge into this symbol records a module, so this symbol could be a package, a builtin or a typo".to_string(),
    })
}

/// Returns whether a relation exactly matches the linker's external-import
/// placeholder contract. This does not inspect graph membership; callers must
/// separately establish that the destination is absent from the local entity
/// set. `created_in` is deliberately not part of this predicate because commit
/// provenance may stamp it after the linker produces the relation.
pub fn is_external_import_placeholder(relation: &Relation) -> bool {
    if !matches!(
        relation.kind,
        RelationKind::Calls | RelationKind::References
    ) || relation.origin != RelationOrigin::Inferred
        || relation.confidence.to_bits() != EXTERNAL_REFERENCE_CONFIDENCE.to_bits()
    {
        return false;
    }

    let Some(src) = relation.src.as_entity() else {
        return false;
    };
    let Some(dst) = relation.dst.as_entity() else {
        return false;
    };
    let Some(import_source) = relation.import_source.as_deref() else {
        return false;
    };
    if import_source.is_empty() || import_source != import_source.trim() {
        return false;
    }

    let [evidence] = relation.evidence.as_slice() else {
        return false;
    };
    let Some(symbol) = evidence.token.as_deref() else {
        return false;
    };
    if symbol.is_empty() || symbol != symbol.trim() {
        return false;
    }
    if evidence.parser_rule.as_deref() != Some(EXTERNAL_IMPORT_REFERENCE_RULE)
        || evidence.source_path.as_deref() != Some(import_source)
        || evidence.source_span.is_some()
        || evidence.resolved_path.is_some()
        || evidence.call_shape.is_some()
        || evidence.occurrence_count == 0
    {
        return false;
    }

    let expected_dst =
        EntityId::from_content(import_source, symbol, EXTERNAL_REFERENCE_KIND_TAG, 0);
    dst == expected_dst && relation.id == stable_relation_id(&src, &expected_dst, &relation.kind)
}

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
            parser_rule: Some(EXTERNAL_IMPORT_REFERENCE_RULE.to_string()),
            source_path: Some(import_source.to_string()),
            ..RelationEvidence::default()
        }],
    })
}

/// Resolve an import specifier to the repository file it names.
///
/// Both edge builders below need this one answer, and `resolve_module_path`
/// scans the whole `known_files` set and probes extensions and index files, so
/// it is the most expensive step in the import path. Resolving once per import
/// site rather than once per builder is why this exists as its own function.
///
/// `require('.')` from a file that IS its directory's index resolves back to
/// the importer. A module does not import itself, and a self-loop would be
/// counted as a resolved import by every surface that reads these edges, so
/// that rule is applied here, once, for both builders.
///
/// It returns the relation kind alongside the path so the two edge builders
/// cannot disagree about it. A C or C++ `#include` is an `Includes` edge, not
/// an `Imports` one, and having each builder decide that for itself is how one
/// site would come to carry two different kinds.
fn resolve_import_target<S>(
    importer_file: &str,
    import: &FileImport,
    known_files: &HashSet<S>,
) -> Option<(String, RelationKind)>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let resolved = resolve_module_path(importer_file, &import.module_path, known_files)?;
    if resolved == importer_file {
        return None;
    }
    let kind = if is_header_like_module_path(&import.module_path) {
        RelationKind::Includes
    } else {
        RelationKind::Imports
    };
    Some((resolved, kind))
}

fn make_artifact_import_relation(
    importer_file: &str,
    import: &FileImport,
    resolved_path: &str,
    kind: RelationKind,
    artifact_ids: &ArtifactIdentityMap,
) -> Option<Relation> {
    let src = GraphNodeId::Artifact(*artifact_ids.get(importer_file)?);
    let dst = GraphNodeId::Artifact(*artifact_ids.get(resolved_path)?);
    let evidence = RelationEvidence {
        source_path: Some(import.module_path.clone()),
        resolved_path: Some(resolved_path.to_string()),
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

/// How many of a file's import STATEMENTS resolved to a file this repository
/// holds, and how many did not.
///
/// Returned as `(statements, resolved)`. The unit is the `FileImport`, one per
/// import statement, which is exactly the unit `parsed_import_statements`
/// counts in.
///
/// It has to be taken HERE, because it cannot be recovered downstream. Measured
/// with the real adapter: `from storage import Store, open_db` is one
/// `FileImport` with two specifiers, and the same two names on separate lines
/// are two `FileImport`s with one each. Those two shapes produce byte-identical
/// graph content, one artifact edge (the linker dedupes on `(src, dst, kind)`)
/// and two entity edges (one per specifier), while differing here, 1 against 2.
/// So no key derived from edges can tell them apart, and a collector counting
/// edges against a denominator of statements reports a ratio between two
/// different populations.
///
/// The unresolved remainder is also the honest external count for a language
/// whose specifier syntax cannot settle externality on its own. A Python
/// `import re` names a module outside the repository exactly when no file the
/// repository holds answers to it, which is what `known_files` decides here,
/// and which is strictly better evidence than the syntactic bare-specifier
/// proxy JavaScript uses.
fn import_resolution_counts<S>(
    file_path: &str,
    imports: &[FileImport],
    known_files: &HashSet<S>,
) -> ImportResolutionCounts
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let resolved = imports
        .iter()
        .filter(|import| resolve_import_target(file_path, import, known_files).is_some())
        .count();
    ImportResolutionCounts {
        statements: imports.len(),
        resolved,
    }
}

/// A file's import statements and how many of them reached this repository.
///
/// `statements - resolved` is the count that names a module outside the
/// repository, decided against `known_files` rather than by specifier syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ImportResolutionCounts {
    statements: usize,
    resolved: usize,
}

/// Index each file's module entity, the endpoint an entity-level import edge
/// sources from.
///
/// A file carrying no module entity is absent from the map rather than mapped
/// to something else, because there is no second-best answer: anchoring to
/// another entity in the file is exactly the claim [`merge_resolved`]'s call
/// site refuses to make.
fn module_entity_by_file<'a>(files: &[&'a FileParseData]) -> HashMap<&'a str, EntityId> {
    let mut out = HashMap::new();
    for file in files {
        if let Some(entity) = file
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Module)
        {
            // First in parse order wins. The caller's file list is ordered, so
            // a file that somehow carried two module entities still resolves
            // the same way on every run.
            out.entry(file.file_path.as_str()).or_insert(entity.id);
        }
    }
    out
}

/// Entity-level import edges for the names an import actually binds.
///
/// [`make_artifact_import_relation`] answers "which file imports which file".
/// It cannot answer "who imports this export", because the reference walk in
/// the MCP layer skips any relation whose `src` is not an entity, so an
/// artifact-rooted edge is invisible to `find_references` however exactly its
/// specifier resolved. Every named specifier that resolves to an entity the
/// target actually defines therefore gets a second edge here, from the
/// importing file's MODULE entity to that entity.
///
/// The module entity is the importer's file surface, which is what owns a
/// file-level dependency. It is deliberately not "the first entity in the
/// file": anchoring there would claim one particular symbol owns the
/// dependency, which is the shape [`merge_resolved`]'s call site refuses, and
/// that refusal is right. This satisfies it rather than working around it.
///
/// An importer carrying no module entity yields nothing rather than falling
/// back to some other entity. That is a real gap for JavaScript and TypeScript,
/// whose adapters emit a module entity only for index files, and it is left
/// visible as a gap rather than papered over with a guess.
///
/// The artifact edge is unaffected. Both are emitted, they carry different node
/// ids so they cannot collide in the caller's dedup, and every consumer reading
/// artifact import edges today keeps reading exactly what it read before.
/// The two lookups are closures rather than maps because the batch linker and
/// the incremental linker hold their indexes in different shapes. Passing the
/// lookup instead of the container is what lets both paths run this one
/// function, so an incrementally relinked file cannot quietly disagree with a
/// fully relinked one.
fn make_entity_import_relations(
    importer_file: &str,
    import: &FileImport,
    resolved_path: &str,
    kind: RelationKind,
    module_of: &dyn Fn(&str) -> Option<EntityId>,
    entity_of: &dyn Fn(&str, &str) -> Option<EntityId>,
) -> Vec<Relation> {
    let Some(src_id) = module_of(importer_file) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for spec in &import.specifiers {
        // A default specifier binds the module object itself, which is what a
        // CommonJS `require` produces. Its local name is the importer's choice
        // and names no symbol in the target, so scoring it against the target's
        // symbols would report a miss for an import that made no such claim.
        // The entity it reaches is the target's own module entity.
        let dst_id = if spec.is_default {
            module_of(resolved_path)
        } else {
            // Bind the ORIGINAL name wherever the import renamed it, because
            // that is the name the target defines. Binding the local alias
            // would point the edge at a name no file declares.
            let wanted = spec
                .original_name
                .as_deref()
                .unwrap_or(spec.local_name.as_str());
            entity_of(resolved_path, wanted)
        };
        let Some(dst_id) = dst_id else {
            continue;
        };
        if dst_id == src_id {
            continue;
        }
        let src = GraphNodeId::Entity(src_id);
        let dst = GraphNodeId::Entity(dst_id);
        out.push(Relation {
            id: stable_relation_node_id(&src, &dst, &kind),
            kind,
            src,
            dst,
            // The specifier resolved to a file this repository holds and the
            // name matched an entity that file declares. Both halves are exact,
            // so this is as certain as the artifact edge beside it.
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: Some(import.module_path.clone()),
            evidence: vec![RelationEvidence {
                token: Some(spec.local_name.clone()),
                source_path: Some(import.module_path.clone()),
                resolved_path: Some(resolved_path.to_string()),
                parser_rule: Some(IMPORT_SPECIFIER_BINDING_RULE.to_string()),
                occurrence_count: 1,
                // The import statement's own bytes, which is what makes this
                // edge renameable. Without it a rename planner searches the
                // SOURCE ENTITY's span, and this edge is sourced at the
                // importing file's module entity whose span is the whole file,
                // so it finds every mention of the name rather than the import
                // site and refuses on a count it can never satisfy.
                source_span: Some(import.site.to_source_span(&FilePathId::new(importer_file))),
                ..RelationEvidence::default()
            }],
        });
    }
    out
}

/// Parser rule recorded on an entity-level import edge, so a consumer can tell
/// one apart from the artifact edge that shares its import.
const IMPORT_SPECIFIER_BINDING_RULE: &str = "import_specifier_binding";

/// Build the graph-owned file-level call-coverage certificate used by
/// ref-scoped review. Coverage state lives in relation evidence; history paths
/// compare the complete relation payload and replace changed evidence.
fn make_parse_coverage_relation(
    file_path: &str,
    artifact_id: ArtifactId,
    completeness: Option<&ParseCompleteness>,
    call_extraction_complete: bool,
    imports: ImportResolutionCounts,
) -> Relation {
    let is_full = call_extraction_complete && matches!(completeness, Some(ParseCompleteness::Full));
    let (parser_rule, token) = if !call_extraction_complete {
        (
            CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1,
            "call-extraction-incomplete",
        )
    } else if is_full {
        (CALL_SHAPE_PARSE_COVERAGE_FULL_V1, "full")
    } else {
        (
            CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1,
            completeness
                .map(ParseCompleteness::bucket)
                .unwrap_or("missing"),
        )
    };
    // Coverage is evidence about the graph-owned artifact itself. A self-loop
    // avoids fabricating a second path-derived pseudo-artifact; evidence
    // changes still replace the relation when completeness changes.
    let src = GraphNodeId::Artifact(artifact_id);
    let dst = src;
    let kind = RelationKind::DependsOn;
    Relation {
        id: stable_relation_node_id(&src, &dst, &kind),
        kind,
        src,
        dst,
        confidence: 1.0,
        origin: RelationOrigin::Parsed,
        created_in: None,
        import_source: None,
        evidence: vec![
            RelationEvidence {
                token: Some(token.to_string()),
                source_path: Some(file_path.to_string()),
                parser_rule: Some(parser_rule.to_string()),
                occurrence_count: 1,
                ..RelationEvidence::default()
            },
            RelationEvidence {
                token: Some(imports.resolved.to_string()),
                source_path: Some(file_path.to_string()),
                parser_rule: Some(IMPORT_RESOLUTION_COVERAGE_V1.to_string()),
                occurrence_count: imports.statements as u32,
                ..RelationEvidence::default()
            },
        ],
    }
}

/// Emit each file's coverage certificate.
///
/// Emitted only where the caller supplied a completeness map, which is where it
/// has always been emitted.
///
/// Making it unconditional so the import half reached the three callers that
/// link without completeness (`kin-cli` graph, `kin-daemon` api, `kin-index`
/// pipeline) put a certificate on paths that never carried one, and 18 tests
/// counting relations saw the extra edge. Those tests are right: adding a
/// relation to every file on paths that had none is a change to the graph, not
/// a change to a report.
///
/// So the gate stays, and a file with no certificate reports its import counts
/// as UNMEASURED rather than as zero, exactly as the call side already does for
/// a file whose extraction was incomplete. A bucket nobody measured is not a
/// bucket that reads zero, and that rule is what keeps the absence honest.
fn append_parse_coverage_relations<S>(
    resolved: &mut Vec<Relation>,
    files: &[&FileParseData],
    artifact_ids: &ArtifactIdentityMap,
    completeness: Option<&FileParseCompletenessMap>,
    known_files: &HashSet<S>,
) where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let Some(completeness) = completeness else {
        return;
    };
    let mut seen = HashSet::new();
    for file in files {
        if seen.insert(file.file_path.as_str()) {
            let artifact_id = *artifact_ids
                .get(&file.file_path)
                .expect("artifact identities were validated before linking");
            let call_extraction_complete = !file
                .relations
                .iter()
                .any(is_call_extraction_incomplete_marker);
            resolved.push(make_parse_coverage_relation(
                &file.file_path,
                artifact_id,
                completeness.get(&file.file_path),
                call_extraction_complete,
                import_resolution_counts(&file.file_path, &file.imports, known_files),
            ));
        }
    }
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
    // Python module paths are dotted, not path-shaped, in both directions:
    // `app.parsing` names `app/parsing.py` and `.parsing` names a sibling
    // module inside the importer's own package. Neither shape survives the
    // generic branches below — the relative branch would join `.parsing` onto
    // the importer's directory as a literal path segment, and the non-relative
    // branch only knows header, JS package, Java, and Go layouts. So every
    // Python import fell through unresolved, which cost the graph its
    // artifact-level `Imports` edges and left every imported call to the blind
    // name fallback.
    if is_python_source_path(importer_path) {
        return resolve_python_module_import(importer_path, module_path, known_files);
    }

    if module_path.starts_with('.') {
        // Relative import resolution
        let importer = Path::new(importer_path);
        let importer_dir = importer.parent().unwrap_or(Path::new(""));

        // A specifier written with a trailing slash names the directory, which
        // is Node's "resolve to the index file inside it" form. Joining it as
        // written leaves an empty final component that no candidate matches.
        let trimmed = module_path.trim_end_matches('/');
        let joined = if trimmed.is_empty() {
            importer_dir.to_path_buf()
        } else {
            importer_dir.join(trimmed)
        };
        let resolved = normalize_path(&joined);
        let resolved_str = resolved.to_string_lossy();
        // Try direct match (module path already has extension)
        if known_files.contains(resolved_str.as_ref()) {
            return Some(resolved_str.into_owned());
        }

        // The specifier may name the emitted JavaScript of a TypeScript source
        // this repository holds instead.
        if let Some(candidate) = resolve_emitted_extension(&resolved_str, known_files) {
            return Some(candidate);
        }

        // Try adding common extensions. An empty resolved path is the
        // repository root, which names a directory and never a file stem.
        if !resolved_str.is_empty() {
            for ext in MODULE_EXTENSIONS {
                let candidate = format!("{}.{}", resolved_str, ext);
                if known_files.contains(candidate.as_str()) {
                    return Some(candidate);
                }
            }
        }

        // Try as directory with index file. `require('../..')` from a nested
        // example directory names the repository root, and joining an index
        // filename onto an empty prefix produced the absolute-looking
        // `/index.js`, which matches no repo-relative path. That one missing
        // branch was 96 of express's 157 relative specifiers.
        for index in INDEX_FILENAMES {
            let candidate = if resolved_str.is_empty() {
                (*index).to_string()
            } else {
                format!("{}/{}", resolved_str, index)
            };
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

/// Resolve a specifier that names an emitted JavaScript file to the TypeScript
/// source the repository actually holds.
///
/// Returns `None` when the specifier carries no JavaScript extension, so a
/// caller can fall through to plain extension completion.
fn resolve_emitted_extension<S>(resolved_path: &str, known_files: &HashSet<S>) -> Option<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let (stem, written) = resolved_path.rsplit_once('.')?;
    let sources = EMITTED_EXTENSION_SOURCES
        .iter()
        .find_map(|(emitted, sources)| (*emitted == written).then_some(*sources))?;
    sources.iter().find_map(|source| {
        let candidate = format!("{stem}.{source}");
        known_files
            .contains(candidate.as_str())
            .then_some(candidate)
    })
}

/// Source extensions a Python module name can materialize as.
const PYTHON_MODULE_EXTENSIONS: &[&str] = &["py", "pyi"];

/// Source roots an absolute Python import is resolved against, in the order a
/// repository normally puts them on `sys.path`.
///
/// Deliberately short. A repo-wide suffix search would find a same-named module
/// anywhere in the tree and bind the import to it, which is a guess wearing the
/// costume of a resolution; an import that names no module at one of these roots
/// stays unresolved instead.
const PYTHON_SOURCE_ROOTS: &[&str] = &["", "src"];

fn is_python_source_path(path: &str) -> bool {
    matches!(path.rsplit('.').next(), Some("py" | "pyi"))
}

/// Resolve a Python import to the repo-local file that defines it.
///
/// Handles the two shapes the adapter emits: an absolute dotted path
/// (`app.parsing`) resolved against the repository's source roots, and a
/// relative one (`.parsing`, `..util.text`) resolved against the importer's own
/// package, where each leading dot beyond the first climbs one package.
///
/// Both shapes only ever name files the caller already knows about, so an
/// import of a third-party or standard-library module resolves to nothing and
/// is left to the external-reference tier. When more than one source root
/// answers the same module the import is ambiguous and stays unresolved: a
/// fabricated edge is worse than a missing one.
fn resolve_python_module_import<S>(
    importer_path: &str,
    module_path: &str,
    known_files: &HashSet<S>,
) -> Option<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let level = module_path.chars().take_while(|c| *c == '.').count();
    let segments: Vec<&str> = module_path[level..]
        .split('.')
        .filter(|segment| !segment.is_empty())
        .collect();

    if level > 0 {
        let mut base = parent_dir(importer_path).to_string();
        for _ in 1..level {
            if base.is_empty() {
                // More leading dots than there are packages above the importer.
                return None;
            }
            base = parent_dir(&base).to_string();
        }
        return python_module_file(&base, &segments, known_files);
    }

    let mut hit: Option<String> = None;
    for root in PYTHON_SOURCE_ROOTS {
        let Some(candidate) = python_module_file(root, &segments, known_files) else {
            continue;
        };
        match &hit {
            Some(existing) if *existing != candidate => return None,
            Some(_) => {}
            None => hit = Some(candidate),
        }
    }
    hit
}

/// The file a dotted module name resolves to under one source root, preferring
/// a module (`pkg/mod.py`) over a package (`pkg/mod/__init__.py`).
///
/// An empty segment list names the base package itself (`from . import sibling`),
/// which can only be that package's `__init__`.
fn python_module_file<S>(base: &str, segments: &[&str], known_files: &HashSet<S>) -> Option<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let joined = segments.join("/");
    let prefix = match (base.is_empty(), joined.is_empty()) {
        (true, true) => return None,
        (true, false) => joined,
        (false, true) => base.to_string(),
        (false, false) => format!("{base}/{joined}"),
    };

    if !segments.is_empty() {
        for ext in PYTHON_MODULE_EXTENSIONS {
            let candidate = format!("{prefix}.{ext}");
            if known_files.contains(candidate.as_str()) {
                return Some(candidate);
            }
        }
    }
    for ext in PYTHON_MODULE_EXTENSIONS {
        let candidate = format!("{prefix}/__init__.{ext}");
        if known_files.contains(candidate.as_str()) {
            return Some(candidate);
        }
    }
    None
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

    if let Some(without_at) = module_path.strip_prefix('@') {
        // Scoped package: @scope/name[/subpath]
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
#[derive(Debug)]
pub struct IncrementalLinker {
    /// Graph-assigned artifact identity for every known repository path.
    artifact_ids: ArtifactIdentityMap,
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
    /// entity_id -> parser-reported language. Blind name/locality inference is
    /// fail-closed against this map.
    pub entity_language_by_id: HashMap<EntityId, LanguageId>,
    /// C/C++ callee id -> argument-count bounds parsed from its signature. The
    /// incremental mirror of the batch linker's `entity_arity_by_id`; backs
    /// overload arity pruning on the live-edit path.
    pub entity_arity_by_id: HashMap<EntityId, ArityBounds>,
    /// entity_id -> project role. The incremental mirror of the batch linker's
    /// `entity_role_by_id`; backs the production-over-test tiebreak on the
    /// live-edit path.
    pub entity_role_by_id: HashMap<EntityId, EntityRole>,
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
    /// file_path -> that file's classes with their declared base names,
    /// lexicographically sorted, deduped. The incremental mirror of the batch
    /// linker's per-(file, class) hierarchy index; persists across steps like
    /// `include_targets_by_file` so an inheritance walk can cross into files
    /// recorded at earlier steps.
    pub class_bases_by_file: HashMap<String, Vec<(String, Vec<String>)>>,
}

/// Serialization contract for [`IncrementalLinker`] inside history-hydration
/// checkpoints.
///
/// This is intentionally a separate, versioned shape rather than serde on the
/// runtime hash maps. Map and set iteration order is process-randomized, while
/// checkpoint bytes must be reproducible. Every unordered container is stored
/// as a sorted vector; order-sensitive candidate vectors retain their runtime
/// order. There are deliberately no serde defaults. Adding a runtime linker
/// field therefore requires changing both exhaustive conversions below and
/// bumping [`INCREMENTAL_LINKER_CHECKPOINT_VERSION`], or the build fails.
type ClassBasesByFileCheckpointV1 = Vec<(String, Vec<(String, Vec<String>)>)>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncrementalLinkerCheckpointV1 {
    artifact_ids: Vec<(String, ArtifactId)>,
    entity_by_file_name: Vec<(String, Vec<(String, EntityId)>)>,
    entity_by_name: Vec<(String, Vec<(String, EntityId)>)>,
    entity_by_bare_name: Vec<(String, Vec<(String, EntityId)>)>,
    entity_kind_by_id: Vec<(EntityId, EntityKind)>,
    entity_language_by_id: Vec<(EntityId, LanguageId)>,
    entity_arity_by_id: Vec<(EntityId, ArityBounds)>,
    entity_role_by_id: Vec<(EntityId, EntityRole)>,
    known_files: Vec<String>,
    entities_by_file: Vec<(String, Vec<(EntityId, Visibility)>)>,
    include_targets_by_file: Vec<(String, Vec<String>)>,
    class_bases_by_file: ClassBasesByFileCheckpointV1,
}

/// Bump whenever [`IncrementalLinkerCheckpointV1`] or linker semantics change.
pub const INCREMENTAL_LINKER_CHECKPOINT_VERSION: u32 = 6;

/// Build-time kin-index identity included in the composite hydration
/// checkpoint version key.
pub const KIN_INDEX_CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

fn checkpoint_hash_map<K, V>(
    entries: Vec<(K, V)>,
    field: &'static str,
) -> Result<HashMap<K, V>, String>
where
    K: Eq + Hash,
{
    let mut map = HashMap::with_capacity(entries.len());
    for (key, value) in entries {
        if map.insert(key, value).is_some() {
            return Err(format!(
                "incremental-linker checkpoint contains duplicate key in {field}"
            ));
        }
    }
    Ok(map)
}

fn checkpoint_hash_set<T>(values: Vec<T>, field: &'static str) -> Result<HashSet<T>, String>
where
    T: Eq + Hash,
{
    let expected = values.len();
    let set: HashSet<T> = values.into_iter().collect();
    if set.len() != expected {
        return Err(format!(
            "incremental-linker checkpoint contains duplicate value in {field}"
        ));
    }
    Ok(set)
}

impl Default for IncrementalLinker {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalLinker {
    pub fn new() -> Self {
        Self {
            artifact_ids: HashMap::new(),
            entity_by_file_name: HashMap::new(),
            entity_by_name: HashMap::new(),
            entity_by_bare_name: HashMap::new(),
            entity_kind_by_id: HashMap::new(),
            entity_language_by_id: HashMap::new(),
            entity_arity_by_id: HashMap::new(),
            entity_role_by_id: HashMap::new(),
            known_files: HashSet::new(),
            entities_by_file: HashMap::new(),
            include_targets_by_file: HashMap::new(),
            class_bases_by_file: HashMap::new(),
        }
    }

    /// Convert the live linker to its canonical checkpoint representation.
    pub fn to_checkpoint_v1(&self) -> IncrementalLinkerCheckpointV1 {
        let Self {
            artifact_ids,
            entity_by_file_name,
            entity_by_name,
            entity_by_bare_name,
            entity_kind_by_id,
            entity_language_by_id,
            entity_arity_by_id,
            entity_role_by_id,
            known_files,
            entities_by_file,
            include_targets_by_file,
            class_bases_by_file,
        } = self;

        let mut artifact_ids: Vec<_> = artifact_ids
            .iter()
            .map(|(path, id)| (path.clone(), *id))
            .collect();
        artifact_ids.sort_by(|a, b| a.0.cmp(&b.0));

        let mut entity_by_file_name: Vec<_> = entity_by_file_name
            .iter()
            .map(|(file, entities)| {
                let mut entities: Vec<_> = entities
                    .iter()
                    .map(|(name, id)| (name.clone(), *id))
                    .collect();
                entities.sort_by(|a, b| a.0.cmp(&b.0));
                (file.clone(), entities)
            })
            .collect();
        entity_by_file_name.sort_by(|a, b| a.0.cmp(&b.0));

        let mut entity_by_name: Vec<_> = entity_by_name
            .iter()
            .map(|(name, candidates)| (name.clone(), candidates.clone()))
            .collect();
        entity_by_name.sort_by(|a, b| a.0.cmp(&b.0));

        let mut entity_by_bare_name: Vec<_> = entity_by_bare_name
            .iter()
            .map(|(name, candidates)| (name.clone(), candidates.clone()))
            .collect();
        entity_by_bare_name.sort_by(|a, b| a.0.cmp(&b.0));

        let mut entity_kind_by_id: Vec<_> = entity_kind_by_id
            .iter()
            .map(|(id, kind)| (*id, *kind))
            .collect();
        entity_kind_by_id.sort_by_key(|(id, _)| *id);

        let mut entity_language_by_id: Vec<_> = entity_language_by_id
            .iter()
            .map(|(id, language)| (*id, *language))
            .collect();
        entity_language_by_id.sort_by_key(|(id, _)| *id);

        let mut entity_arity_by_id: Vec<_> = entity_arity_by_id
            .iter()
            .map(|(id, bounds)| (*id, *bounds))
            .collect();
        entity_arity_by_id.sort_by_key(|(id, _)| *id);

        let mut entity_role_by_id: Vec<_> = entity_role_by_id
            .iter()
            .map(|(id, role)| (*id, *role))
            .collect();
        entity_role_by_id.sort_by_key(|(id, _)| *id);

        let mut known_files: Vec<_> = known_files.iter().cloned().collect();
        known_files.sort();

        let mut entities_by_file: Vec<_> = entities_by_file
            .iter()
            .map(|(file, entities)| (file.clone(), entities.clone()))
            .collect();
        entities_by_file.sort_by(|a, b| a.0.cmp(&b.0));

        let mut include_targets_by_file: Vec<_> = include_targets_by_file
            .iter()
            .map(|(file, targets)| (file.clone(), targets.clone()))
            .collect();
        include_targets_by_file.sort_by(|a, b| a.0.cmp(&b.0));

        let mut class_bases_by_file: Vec<_> = class_bases_by_file
            .iter()
            .map(|(file, bases)| (file.clone(), bases.clone()))
            .collect();
        class_bases_by_file.sort_by(|a, b| a.0.cmp(&b.0));

        IncrementalLinkerCheckpointV1 {
            artifact_ids,
            entity_by_file_name,
            entity_by_name,
            entity_by_bare_name,
            entity_kind_by_id,
            entity_language_by_id,
            entity_arity_by_id,
            entity_role_by_id,
            known_files,
            entities_by_file,
            include_targets_by_file,
            class_bases_by_file,
        }
    }

    /// Restore a linker checkpoint, refusing duplicate keys or set members.
    pub fn from_checkpoint_v1(checkpoint: IncrementalLinkerCheckpointV1) -> Result<Self, String> {
        let IncrementalLinkerCheckpointV1 {
            artifact_ids,
            entity_by_file_name,
            entity_by_name,
            entity_by_bare_name,
            entity_kind_by_id,
            entity_language_by_id,
            entity_arity_by_id,
            entity_role_by_id,
            known_files,
            entities_by_file,
            include_targets_by_file,
            class_bases_by_file,
        } = checkpoint;

        let entity_by_file_name = checkpoint_hash_map(
            entity_by_file_name
                .into_iter()
                .map(|(file, entities)| {
                    checkpoint_hash_map(entities, "entity_by_file_name.inner")
                        .map(|entities| (file, entities))
                })
                .collect::<Result<Vec<_>, _>>()?,
            "entity_by_file_name",
        )?;

        let artifact_ids = checkpoint_hash_map(artifact_ids, "artifact_ids")?;
        let known_files = checkpoint_hash_set(known_files, "known_files")?;
        let identity_paths = artifact_ids.keys().cloned().collect::<HashSet<_>>();
        if identity_paths != known_files {
            let mut missing = known_files
                .difference(&identity_paths)
                .cloned()
                .collect::<Vec<_>>();
            let mut stale = identity_paths
                .difference(&known_files)
                .cloned()
                .collect::<Vec<_>>();
            missing.sort();
            stale.sort();
            return Err(format!(
                "incremental-linker checkpoint artifact identity mismatch: \
                 missing={missing:?}, stale={stale:?}"
            ));
        }

        let entity_kind_by_id = checkpoint_hash_map(entity_kind_by_id, "entity_kind_by_id")?;
        let entity_language_by_id =
            checkpoint_hash_map(entity_language_by_id, "entity_language_by_id")?;
        let kind_ids = entity_kind_by_id.keys().copied().collect::<HashSet<_>>();
        let language_ids = entity_language_by_id
            .keys()
            .copied()
            .collect::<HashSet<_>>();
        if kind_ids != language_ids {
            return Err(
                "incremental-linker checkpoint entity language coverage does not match entity kind coverage"
                    .to_string(),
            );
        }

        Ok(Self {
            artifact_ids,
            entity_by_file_name,
            entity_by_name: checkpoint_hash_map(entity_by_name, "entity_by_name")?,
            entity_by_bare_name: checkpoint_hash_map(entity_by_bare_name, "entity_by_bare_name")?,
            entity_kind_by_id,
            entity_language_by_id,
            entity_arity_by_id: checkpoint_hash_map(entity_arity_by_id, "entity_arity_by_id")?,
            entity_role_by_id: checkpoint_hash_map(entity_role_by_id, "entity_role_by_id")?,
            known_files,
            entities_by_file: checkpoint_hash_map(entities_by_file, "entities_by_file")?,
            include_targets_by_file: checkpoint_hash_map(
                include_targets_by_file,
                "include_targets_by_file",
            )?,
            class_bases_by_file: checkpoint_hash_map(class_bases_by_file, "class_bases_by_file")?,
        })
    }

    /// Remove a file and all its associated entities from the indexes.
    pub fn remove_file(&mut self, file_path: &str) {
        self.known_files.remove(file_path);
        self.artifact_ids.remove(file_path);

        if let Some(file_entities) = self.entity_by_file_name.remove(file_path) {
            for (entity_name, entity_id) in file_entities {
                self.entity_kind_by_id.remove(&entity_id);
                self.entity_language_by_id.remove(&entity_id);
                self.entity_arity_by_id.remove(&entity_id);
                self.entity_role_by_id.remove(&entity_id);
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
        self.class_bases_by_file.remove(file_path);
    }

    /// Record each file's class hierarchy (Extends declarations), replacing any
    /// prior entry — a file whose classes lost all bases is cleared. The
    /// incremental counterpart of the batch linker's hierarchy index; call
    /// alongside [`IncrementalLinker::record_file_includes`] wherever a step's
    /// parse data is recorded.
    pub fn record_class_bases(&mut self, files: &[FileParseData]) {
        for file in files {
            let classes = collect_class_bases(&file.relations);
            if classes.is_empty() {
                self.class_bases_by_file.remove(&file.file_path);
            } else {
                self.class_bases_by_file
                    .insert(file.file_path.clone(), classes);
            }
        }
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

    /// Add or update one explicitly admitted file and its entities.
    ///
    /// Artifact identity is mandatory and installed atomically with file
    /// membership. A remove followed by path reuse therefore cannot inherit
    /// the removed artifact's identity.
    pub fn add_file(&mut self, file_path: &str, artifact_id: ArtifactId, entities: &[Entity]) {
        self.remove_file(file_path);

        self.known_files.insert(file_path.to_string());
        self.artifact_ids.insert(file_path.to_string(), artifact_id);

        let mut file_entities_map = HashMap::new();
        let mut file_entities_list = Vec::new();

        for entity in entities {
            self.entity_kind_by_id.insert(entity.id, entity.kind);
            let slot_free = file_entities_map
                .get(&entity.name)
                .and_then(|occupant| self.entity_kind_by_id.get(occupant))
                .is_none_or(|occupant| file_name_slot_admits(entity.kind, *occupant));
            if slot_free {
                file_entities_map.insert(entity.name.clone(), entity.id);
            }
            self.entity_language_by_id
                .insert(entity.id, entity.language);
            self.entity_role_by_id.insert(entity.id, entity.role);
            if let Some(bounds) = callee_arity_bounds(entity) {
                self.entity_arity_by_id.insert(entity.id, bounds);
            }

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

/// Files below which the cross-file linker prints no progress bar.
///
/// The bar and the newline that terminates it must be gated on the SAME
/// condition. They were not: the bar was gated on this threshold while its
/// terminator fired on any non-zero file count, so every link pass under the
/// threshold emitted one bare newline and nothing else. The linker runs once per commit
/// during admission, so a 929-commit repository with 37 entity-source files
/// printed 927 blank lines as its entire progress output, measured with `xxd`
/// as 0x0a and nothing more. Routing both decisions through one predicate is
/// what stops the two from drifting apart again.
const PROGRESS_BAR_MIN_FILES: usize = 50;

/// Whether this link pass prints a progress bar, and therefore whether it has a
/// line to terminate.
fn shows_progress_bar(total_files: usize) -> bool {
    progress_bar_is_drawn(total_files, std::io::stderr().is_terminal())
}

/// The bar decision, split from the terminal probe so both halves are testable.
///
/// The terminal half is not cosmetic. The bar redraws in place with a carriage
/// return, which a terminal shows as one line and a pipe records as one frame
/// per update, so a captured run kept every frame instead of the final one. Off
/// a terminal the surrounding phase ladder already reports this phase with a
/// start line and an end line carrying its elapsed time, which is the whole of
/// what a log needs.
fn progress_bar_is_drawn(total_files: usize, stderr_is_terminal: bool) -> bool {
    total_files > PROGRESS_BAR_MIN_FILES && stderr_is_terminal
}

/// Draw one frame of the in-place bar, or the newline that ends it.
///
/// Progress is advisory and the work is not. `eprint!` panics when its write
/// fails, so a consumer that closed the reading end used to take a running
/// admission down with it partway through, leaving no store behind. Failures
/// here are dropped and the link pass carries on.
fn draw_progress(args: std::fmt::Arguments<'_>) {
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_fmt(args);
    let _ = stderr.flush();
}

/// Resolve cross-file relations using the incrementally updated linker state.
pub fn link_cross_file_incremental(
    files: &[FileParseData],
    linker: &IncrementalLinker,
) -> IndexResult<Vec<Relation>> {
    link_cross_file_incremental_internal(files, linker, None)
}

/// Resolve cross-file relations through the incremental indexes while
/// preserving explicit file-level parse coverage.
pub fn link_cross_file_incremental_with_completeness(
    files: &[FileParseData],
    linker: &IncrementalLinker,
    completeness: &FileParseCompletenessMap,
) -> IndexResult<Vec<Relation>> {
    link_cross_file_incremental_internal(files, linker, Some(completeness))
}

fn link_cross_file_incremental_internal(
    files: &[FileParseData],
    linker: &IncrementalLinker,
    completeness: Option<&FileParseCompletenessMap>,
) -> IndexResult<Vec<Relation>> {
    let _span =
        tracing::info_span!("kin.index.link_cross_file_incremental", files = files.len()).entered();
    require_artifact_identities(
        linker.known_files.iter().map(String::as_str),
        &linker.artifact_ids,
    )?;

    // Read-only step-local overlays shared by every per-file resolution. Built
    // once so the parallel per-file pass and its serial reference both resolve
    // against byte-identical context.
    let IncrementalLinkOverlays {
        import_map,
        include_graph,
        class_bases,
        declared_attribute_types,
    } = build_incremental_link_overlays(files, linker);

    // Resolve each file independently: every relation's source entity is owned
    // by its own file, so the (src, dst, kind) triples produced by different
    // files never collide. Per-file resolution carries its own dedup state and
    // is therefore order-independent; results are collected in input-file order
    // (`par_iter().collect()` preserves order) and merged serially below so the
    // materialized relation set and ordering are identical to a serial pass —
    // mirroring the batch `link_cross_file` resolver.
    let total_files = files.len();
    let progress_interval = std::cmp::max(total_files / 50, 1);
    let link_start = std::time::Instant::now();
    let completed = AtomicUsize::new(0);
    let found = AtomicUsize::new(0);
    let per_file_relations: Vec<Vec<Relation>> = files
        .par_iter()
        .map(|file| {
            let relations = resolve_one_file_incremental(
                file,
                linker,
                &import_map,
                &include_graph,
                &class_bases,
                &declared_attribute_types,
                completeness,
            );
            if shows_progress_bar(total_files) {
                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                let total = found.fetch_add(relations.len(), Ordering::Relaxed) + relations.len();
                if done.is_multiple_of(progress_interval) || done == total_files {
                    draw_progress(format_args!(
                        "\r  Linking: [{}/{}] {}% | {} relations | {:.1}s",
                        done,
                        total_files,
                        (done * 100) / total_files,
                        total,
                        link_start.elapsed().as_secs_f64()
                    ));
                }
            }
            relations
        })
        .collect();
    if shows_progress_bar(total_files) {
        draw_progress(format_args!("\n")); // newline after \r progress
    }

    Ok(merge_incremental_resolved(
        per_file_relations,
        files,
        linker,
        completeness,
    ))
}

/// Resolve the name-based relations of a single file into entity-ID relations
/// using the incrementally updated linker state.
///
/// All reads are against the shared read-only `linker` and the step-local
/// overlays (`import_map`, `include_graph`, `class_bases`); the only mutable
/// state is a file-local dedup set, so this is pure with respect to other files
/// and safe to run across files in parallel. Mirrors the batch
/// [`resolve_one_file`].
#[allow(clippy::too_many_arguments)]
fn resolve_one_file_incremental(
    file: &FileParseData,
    linker: &IncrementalLinker,
    import_map: &HashMap<&str, HashMap<&str, (&str, &str)>>,
    include_graph: &HashMap<String, Vec<String>>,
    class_bases: &HashMap<String, Vec<(String, Vec<String>)>>,
    declared_attribute_types: &HashMap<(&str, &str, &str), &str>,
    completeness: Option<&FileParseCompletenessMap>,
) -> Vec<Relation> {
    let mut resolved = Vec::new();
    let mut relation_indices = HashMap::new();
    let call_extraction_complete = !file
        .relations
        .iter()
        .any(is_call_extraction_incomplete_marker);
    let parse_completeness = completeness
        .and_then(|by_file| by_file.get(&file.file_path))
        .unwrap_or(&FULL_PARSE_COMPLETENESS);
    let caller_file = FilePathId::new(&file.file_path);
    let make_relation = |rel: &ExtractedRelation, src, dst, confidence| {
        make_relation(
            rel,
            src,
            dst,
            confidence,
            &caller_file,
            parse_completeness,
            call_extraction_complete,
        )
    };
    // Lazily resolved once per file: only ambiguous name buckets need them.
    let mut caller_import_targets: Option<HashSet<String>> = None;
    let mut caller_include_closure: Option<HashMap<String, usize>> = None;
    for rel in &file.relations {
        if is_call_extraction_incomplete_marker(rel) {
            continue;
        }
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

        // Positional arity the call's overloads are pruned by (fail-open on an
        // absent or splat-widened shape) — the incremental mirror of the batch
        // linker's per-relation derivation.
        let call_arity = call_positional_arity(&rel.call_shape);

        if rel.kind == RelationKind::UsesMacro {
            if let Some(dst_id) = dst_same_file {
                if linker.entity_kind_by_id.get(&dst_id) == Some(&EntityKind::Macro) {
                    accumulate_relation(
                        &mut resolved,
                        &mut relation_indices,
                        make_relation(rel, src_id, dst_id, 1.0),
                    );
                    continue;
                }
            }

            if let Some(dst_id) = resolve_reachable_macro_target_incremental(
                &file.file_path,
                &rel.dst_name,
                include_graph,
                linker,
            ) {
                accumulate_relation(
                    &mut resolved,
                    &mut relation_indices,
                    make_relation(rel, src_id, dst_id, 0.95),
                );
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

        // (a) Same-file resolution. Mirrors the batch linker: the same-file
        // entity wins and is emitted first at full confidence, but when
        // cross-file entities share the exact name (a declaration/prototype
        // whose definition lives elsewhere) also fan out to them, bounded so
        // the same-file target plus its cross-file twins stay within the cap.
        // (a0) Receiver-scoped resolution — mirrors the batch linker: an
        // attribute call's receiver decides which entities can be the
        // destination at all, so a receiver bound to a repo-local module yields
        // exactly one edge and a receiver bound outside the repo yields none.
        let receiver_scope = rel
            .receiver
            .as_deref()
            .filter(|receiver| rel.kind == RelationKind::Calls && !receiver.is_empty())
            .map(|receiver| {
                (
                    receiver,
                    classify_receiver(
                        receiver,
                        &file.file_path,
                        import_map.get(file.file_path.as_str()),
                        &linker.known_files,
                    ),
                )
            });
        let mut receiver_is_object = false;
        if let Some((receiver, scope)) = receiver_scope.as_ref() {
            let receiver_root = receiver.split('.').next().unwrap_or(receiver);
            match scope {
                ReceiverScope::Module(target_file) => {
                    // Shares the batch linker's resolver rather than repeating
                    // its lookup order, so the re-export hop cannot land on one
                    // path and be missing from the other.
                    let dst_id = resolve_receiver_module_target(
                        target_file.as_str(),
                        receiver_root,
                        rel.dst_name.as_str(),
                        import_map.get(file.file_path.as_str()),
                        import_map,
                        &linker.known_files,
                        |target, name| {
                            linker
                                .entity_by_file_name
                                .get(target)
                                .and_then(|names| names.get(name))
                                .copied()
                        },
                    );
                    if let Some(dst_id) = dst_id {
                        accumulate_relation(
                            &mut resolved,
                            &mut relation_indices,
                            make_relation(rel, src_id, dst_id, RECEIVER_MODULE_CONFIDENCE),
                        );
                        continue;
                    }
                }
                ReceiverScope::ExternalModule => {}
                ReceiverScope::Object => receiver_is_object = true,
            }
            if !receiver_is_object {
                if let Some(external) = make_external_reference_relation(
                    rel,
                    src_id,
                    &file.file_path,
                    &linker.known_files,
                ) {
                    accumulate_relation(&mut resolved, &mut relation_indices, external);
                }
                continue;
            }
        }

        // Cross-file twins carry the (c) name-match confidence (0.7). A call
        // through an object skips this tier: a same-file free function sharing
        // the member name is a decoy, not the destination.
        if let Some(dst_id) = dst_same_file.filter(|_| !receiver_is_object) {
            accumulate_relation(
                &mut resolved,
                &mut relation_indices,
                make_relation(rel, src_id, dst_id, 1.0),
            );
            let mut cross_file_twins: HashSet<EntityId> = HashSet::new();
            if let Some(candidates) = linker.entity_by_name.get(&rel.dst_name) {
                for (fp, id) in candidates {
                    if fp != &file.file_path {
                        cross_file_twins.insert(*id);
                    }
                }
            }
            cross_file_twins.retain(|dst_id| {
                blind_inference_target_allowed(src_id, *dst_id, &linker.entity_language_by_id)
            });
            let cross_file_twins =
                prune_ids_by_arity(cross_file_twins, call_arity, &linker.entity_arity_by_id);
            let cross_file_twins =
                narrow_candidates_by_role(src_id, cross_file_twins, &linker.entity_role_by_id);
            if !cross_file_twins.is_empty() && cross_file_twins.len() < AMBIGUOUS_CALL_FANOUT_CAP {
                for cross_id in sorted_fanout_targets(cross_file_twins) {
                    accumulate_relation(
                        &mut resolved,
                        &mut relation_indices,
                        make_relation(rel, src_id, cross_id, 0.7),
                    );
                }
            }
            continue;
        }

        // (a1) Python builtin gate, mirroring the batch linker. A bare call to
        // a name the interpreter binds, from a file that neither defines nor
        // imports it, has no destination in this repository and must not be
        // answered by the name tiers below.
        if is_unbound_python_builtin_call(
            rel,
            src_id,
            file,
            dst_same_file.is_some(),
            import_map.get(file.file_path.as_str()),
            &linker.entity_language_by_id,
        ) {
            debug!(
                src = %rel.src_name,
                dst = %rel.dst_name,
                file = %file.file_path,
                "linker(incremental): bare Python builtin call the file neither defines nor imports, leaving unlinked"
            );
            continue;
        }

        // (a2) Inheritance-aware receiver-method resolution — mirrors the
        // batch linker: a class-qualified `self.m()`/`cls.m()` callee whose
        // owner is a class in this file resolves through the recorded
        // Extends chain to the defining ancestor; an unresolvable hierarchy
        // falls back to the bare leaf for the tiers below.
        let mut dst_lookup: &str = rel.dst_name.as_str();
        // A tier that declines must hand the call back exactly as it arrived.
        // The two-hop owner half is a name the PARSER wrote from declarations
        // (`Response.connection.send`), not a path the source spells, so when
        // no declaration settles it every tier below has to see the bare leaf
        // the call would otherwise have carried. Without this the dotted name
        // reached tier (d), whose cross-repo placeholder refuses a dotted
        // symbol, and four real unresolved-receiver edges in requests
        // disappeared instead of one appearing.
        let mut declined_two_hop: Option<ExtractedRelation> = None;
        if rel.kind == RelationKind::Calls {
            if let Some((owner, method)) = split_owner_method(rel.dst_name.as_str()) {
                let owner_is_class = linker
                    .entity_by_file_name
                    .get(&file.file_path)
                    .and_then(|m| m.get(owner))
                    .map(|id| is_class_like(linker.entity_kind_by_id.get(id)))
                    .unwrap_or(false);
                if owner_is_class {
                    // (a2a) mirrors the batch linker: a receiver whose
                    // declared type names a class in this very file binds to
                    // that class's own method, which the bases-first walk
                    // below never consults and no later tier can reach for an
                    // object receiver. A live edit must resolve this call the
                    // same way a cold index does.
                    if rel.receiver.is_some() {
                        if let Some(dst_id) =
                            resolve_own_method_incremental(&file.file_path, owner, method, linker)
                        {
                            accumulate_relation(
                                &mut resolved,
                                &mut relation_indices,
                                make_relation(rel, src_id, dst_id, RECEIVER_TYPE_CONFIDENCE),
                            );
                            continue;
                        }
                    }
                    if let Some(dst_id) = resolve_inherited_method_incremental(
                        &file.file_path,
                        owner,
                        method,
                        linker,
                        import_map,
                        class_bases,
                    ) {
                        accumulate_relation(
                            &mut resolved,
                            &mut relation_indices,
                            make_relation(rel, src_id, dst_id, INHERITED_METHOD_CONFIDENCE),
                        );
                        continue;
                    }
                    dst_lookup = method;
                } else if rel.receiver.is_some() {
                    // (a2b) mirrors the batch linker: an owner half that came
                    // from the receiver's declared type resolves through the
                    // class that type names, wherever the repository defines
                    // it, and falls back to the bare leaf when it names none.
                    if let Some((owner_file, owner_class)) =
                        locate_base_class_incremental(&file.file_path, owner, linker, import_map)
                    {
                        if let Some(dst_id) = resolve_declared_method_incremental(
                            &owner_file,
                            &owner_class,
                            method,
                            linker,
                            import_map,
                            class_bases,
                        ) {
                            accumulate_relation(
                                &mut resolved,
                                &mut relation_indices,
                                make_relation(rel, src_id, dst_id, RECEIVER_TYPE_CONFIDENCE),
                            );
                            continue;
                        }
                    }
                    // (a2c) mirrors the batch linker's two-hop tier: an owner
                    // half that is itself `Type.attribute` joins the calling
                    // scope's declaration of the root to the class body's
                    // declaration of the attribute, and falls back to the bare
                    // leaf when either is missing.
                    if let Some((root_type, attribute)) = split_owner_method(owner) {
                        if let Some(dst_id) = resolve_two_hop_declared_method_incremental(
                            &file.file_path,
                            root_type,
                            attribute,
                            method,
                            linker,
                            import_map,
                            class_bases,
                            declared_attribute_types,
                        ) {
                            accumulate_relation(
                                &mut resolved,
                                &mut relation_indices,
                                make_relation(rel, src_id, dst_id, RECEIVER_TYPE_CONFIDENCE),
                            );
                            continue;
                        }
                    }
                    if owner.contains('.') {
                        declined_two_hop = Some(ExtractedRelation {
                            dst_name: method.to_string(),
                            ..rel.clone()
                        });
                    }
                    dst_lookup = method;
                }
            }
        }
        let rel = declined_two_hop.as_ref().unwrap_or(rel);

        // (b) Import-based cross-file resolution. Skipped for a call through
        // an object: `dst_name` is then a member name, not an imported binding.
        if let Some(file_imports) = import_map
            .get(file.file_path.as_str())
            .filter(|_| !receiver_is_object)
        {
            if let Some(&(module_path, original_name)) = file_imports.get(rel.dst_name.as_str()) {
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
                        resolve_default_export_incremental(&target_file, &linker.entities_by_file)
                    } else {
                        None
                    };
                    if let Some(dst_id) = dst_id {
                        accumulate_relation(
                            &mut resolved,
                            &mut relation_indices,
                            make_relation(rel, src_id, dst_id, 0.95),
                        );
                        continue;
                    }
                }
            }

            // (b2) Namespace/package import member resolution
            if let Some((import_name, member_name)) = split_member_access(rel.dst_name.as_str()) {
                if let Some(&(module_path, _original_name)) = file_imports.get(import_name) {
                    if let Some(target_file) =
                        resolve_module_path(&file.file_path, module_path, &linker.known_files)
                    {
                        if let Some(&dst_id) = linker
                            .entity_by_file_name
                            .get(&target_file)
                            .and_then(|m| m.get(member_name))
                        {
                            accumulate_relation(
                                &mut resolved,
                                &mut relation_indices,
                                make_relation(rel, src_id, dst_id, 0.9),
                            );
                            continue;
                        }
                    }
                }
            }
        }

        let other_file_candidates: Vec<(&str, EntityId)> = linker
            .entity_by_name
            .get(dst_lookup)
            .map(|candidates| {
                candidates
                    .iter()
                    .filter(|(fp, _)| fp != &file.file_path)
                    .map(|(fp, id)| (fp.as_str(), *id))
                    .collect()
            })
            .unwrap_or_default();
        let other_file_candidates =
            drop_module_call_targets(rel.kind, other_file_candidates, &linker.entity_kind_by_id);

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
                accumulate_relation(
                    &mut resolved,
                    &mut relation_indices,
                    make_relation(rel, src_id, dst_id, IMPORT_PINNED_CONFIDENCE),
                );
                continue;
            }
            ImportPinnedTarget::PinnedMiss => name_fallback_allowed = false,
            ImportPinnedTarget::NoPin => {}
        }

        // Import/module pins above are permitted to cross language boundaries.
        // Everything below is blind name/locality inference and is therefore
        // restricted to equal or explicitly compatible language families.
        let other_file_candidates: Vec<_> = other_file_candidates
            .into_iter()
            .filter(|(_, dst_id)| {
                blind_inference_target_allowed(src_id, *dst_id, &linker.entity_language_by_id)
            })
            .collect();

        // Arity gate mirroring the batch linker: drop the exact-name candidates
        // an overloaded C/C++ callee's recorded call-site argument count cannot
        // reach before (c)/(c2) bind. Fail-open and a no-op without recorded
        // arity, so non-overloaded and non-C/C++ binding is unchanged.
        let other_file_candidates = prune_pairs_by_arity(
            other_file_candidates,
            call_arity,
            &linker.entity_arity_by_id,
        );
        let other_file_candidates =
            narrow_pairs_by_role(src_id, other_file_candidates, &linker.entity_role_by_id);

        // (c) Global name-match fallback. Mirrors the batch linker: a bucket
        // several cross-file entities share, with no signal to separate them,
        // leaves the call unlinked and suppresses the blind name tiers below.
        // A call through an object skips it: the exact-name bucket holds
        // module-level functions, which an object call can never reach.
        let mut unresolvable_name_ambiguity = false;
        if name_fallback_allowed && !receiver_is_object && !other_file_candidates.is_empty() {
            let distinct_ids: HashSet<EntityId> =
                other_file_candidates.iter().map(|&(_, id)| id).collect();
            let settled = if distinct_ids.len() == 1 {
                Some((other_file_candidates[0].1, 0.7))
            } else {
                let targets = caller_import_targets.get_or_insert_with(|| {
                    resolve_caller_import_targets(
                        &file.file_path,
                        &file.imports,
                        &linker.known_files,
                    )
                });
                let closure = caller_include_closure
                    .get_or_insert_with(|| include_closure_depths(&file.file_path, include_graph));
                disambiguate_same_name_candidates(
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
                )
                .map(|dst_id| (dst_id, LOCALITY_DISAMBIGUATED_CONFIDENCE))
            };
            match settled {
                Some((dst_id, confidence)) => {
                    accumulate_relation(
                        &mut resolved,
                        &mut relation_indices,
                        make_relation(rel, src_id, dst_id, confidence),
                    );
                    continue;
                }
                None => {
                    unresolvable_name_ambiguity = true;
                    debug!(
                        src = %rel.src_name,
                        dst = %rel.dst_name,
                        file = %file.file_path,
                        candidates = distinct_ids.len(),
                        "linker(incremental): same-name bucket unresolvable without scope signal, leaving unlinked"
                    );
                }
            }
        }

        // (c2) Receiver-method calls (`x.method()`) arrive as the bare method
        // name with no exact cross-file entity of that name, so (c) above
        // never fires. Resolve them through the bare-name index, mirroring
        // the batch linker's (c2): a single distinct cross-file method links,
        // and several implementor classes fan out to all of them up to the
        // cap (virtual dispatch has an unknowable receiver type). Beyond the
        // cap the name is too ubiquitous to guess and stays unresolved.
        // Without this step a receiver method resolved into a full-tree
        // snapshot is dropped the moment an incremental relink of the caller
        // re-derives its edges.
        if name_fallback_allowed && !unresolvable_name_ambiguity && rel.kind == RelationKind::Calls
        {
            if let Some(bare_candidates) = linker.entity_by_bare_name.get(dst_lookup) {
                let candidates: Vec<(&str, EntityId)> = bare_candidates
                    .iter()
                    .filter(|(fp, dst_id)| {
                        fp != &file.file_path
                            && blind_inference_target_allowed(
                                src_id,
                                *dst_id,
                                &linker.entity_language_by_id,
                            )
                    })
                    .map(|(fp, id)| (fp.as_str(), *id))
                    .collect();
                let candidates =
                    prune_pairs_by_arity(candidates, call_arity, &linker.entity_arity_by_id);
                let candidates =
                    narrow_pairs_by_role(src_id, candidates, &linker.entity_role_by_id);
                let candidates = if receiver_is_object {
                    let owner_bound = owner_bound_targets(
                        dst_lookup,
                        import_map.get(file.file_path.as_str()),
                        |key, bound| {
                            if let Some(named) = linker.entity_by_name.get(key) {
                                bound.extend(named.iter().map(|(_, id)| *id));
                            }
                        },
                    );
                    let settled = settle_receiver_method_owner(candidates, &owner_bound);
                    if settled.is_empty() {
                        debug!(
                            src = %rel.src_name,
                            dst = %rel.dst_name,
                            file = %file.file_path,
                            named_owners = owner_bound.values().collect::<HashSet<_>>().len(),
                            "linker(incremental): receiver-method call names no single owner this file reaches, leaving unlinked"
                        );
                    }
                    settled
                } else if is_python_bare_identifier_call(rel, src_id, &linker.entity_language_by_id)
                {
                    // A bare Python identifier carries no receiver, and this
                    // tier resolves calls that have one.
                    drop_method_candidates(candidates, &linker.entity_kind_by_id)
                } else if is_rust_bare_identifier_call(rel, src_id, &linker.entity_language_by_id)
                    && !rust_bare_call_may_reach_owned(
                        rel.dst_name.as_str(),
                        file,
                        import_map.get(file.file_path.as_str()),
                    )
                {
                    debug!(
                        src = %rel.src_name,
                        dst = %rel.dst_name,
                        file = %file.file_path,
                        "linker: bare Rust call cannot reach an owner-qualified entity this file does not import, leaving unlinked"
                    );
                    Vec::new()
                } else {
                    candidates
                };
                let distinct_targets: HashSet<EntityId> =
                    candidates.into_iter().map(|(_, id)| id).collect();
                if (1..=AMBIGUOUS_CALL_FANOUT_CAP).contains(&distinct_targets.len()) {
                    for dst_id in sorted_fanout_targets(distinct_targets) {
                        accumulate_relation(
                            &mut resolved,
                            &mut relation_indices,
                            make_relation(rel, src_id, dst_id, RECEIVER_NAME_FANOUT_CONFIDENCE),
                        );
                    }
                    continue;
                }
            }
        }

        // (c2a) The incremental counterpart of the batch linker's (c2a): a
        // bare call to a same-file sibling under the caller's own owner.
        // Without this step the edge a full-tree link resolved is dropped the
        // moment an incremental relink of the caller re-derives its edges,
        // which is how a warm store loses edges a cold one has.
        if name_fallback_allowed && !unresolvable_name_ambiguity {
            if let Some((sibling, _leaf)) =
                same_owner_sibling_name(rel, src_id, &linker.entity_language_by_id).filter(
                    |(_, leaf)| {
                        bare_leaf_names_one_thing(
                            linker.entity_by_bare_name.get(*leaf).map_or(0, |v| v.len()),
                            linker.entity_by_name.get(*leaf).map_or(0, |v| v.len()),
                        )
                    },
                )
            {
                let candidates: Vec<(&str, EntityId)> = linker
                    .entity_by_name
                    .get(sibling.as_str())
                    .map(|v| v.as_slice())
                    .unwrap_or(&[])
                    .iter()
                    .filter(|(fp, dst_id)| {
                        fp == &file.file_path
                            && *dst_id != src_id
                            && blind_inference_target_allowed(
                                src_id,
                                *dst_id,
                                &linker.entity_language_by_id,
                            )
                    })
                    .map(|(fp, id)| (fp.as_str(), *id))
                    .collect();
                let candidates =
                    prune_pairs_by_arity(candidates, call_arity, &linker.entity_arity_by_id);
                let candidates =
                    narrow_pairs_by_role(src_id, candidates, &linker.entity_role_by_id);
                let distinct: HashSet<EntityId> =
                    candidates.into_iter().map(|(_, id)| id).collect();
                if distinct.len() == 1 {
                    for dst_id in sorted_fanout_targets(distinct) {
                        accumulate_relation(
                            &mut resolved,
                            &mut relation_indices,
                            make_relation(rel, src_id, dst_id, LOCALITY_DISAMBIGUATED_CONFIDENCE),
                        );
                    }
                    continue;
                }
            }
        }

        // (c4) C++ receiver-scoped inherited method — the incremental
        // counterpart of the batch linker's (c4). A `Owner::method` call with
        // no exact entity above resolves through the receiver class's Extends
        // chain to the defining ancestor, keeping an inherited call pinned to
        // its true base instead of the bare-leaf fan-out (c3) would reach.
        if name_fallback_allowed && rel.kind == RelationKind::Calls {
            if let Some((owner, method)) = split_scoped_receiver_method(rel.dst_name.as_str()) {
                if let Some((owner_file, owner_class)) =
                    locate_base_class_incremental(&file.file_path, owner, linker, import_map)
                {
                    if let Some(dst_id) = resolve_inherited_method_incremental(
                        &owner_file,
                        &owner_class,
                        method,
                        linker,
                        import_map,
                        class_bases,
                    ) {
                        accumulate_relation(
                            &mut resolved,
                            &mut relation_indices,
                            make_relation(rel, src_id, dst_id, INHERITED_METHOD_CONFIDENCE),
                        );
                        continue;
                    }
                }
            }
        }

        // (c3) Path-qualified suffix resolution — the incremental counterpart
        // of the batch linker's (c3). Live edits reach this daemon path, so
        // qualified calls must resolve here too, not only on a full re-index.
        if name_fallback_allowed
            && !unresolvable_name_ambiguity
            && matches!(rel.kind, RelationKind::Calls | RelationKind::References)
        {
            // Fan out: an ambiguous qualified leaf resolves to every distinct
            // cross-file target, arity-pruned, matching the batch resolver.
            let qualified_targets = resolve_qualified_suffix_incremental(
                &rel.dst_name,
                &file.file_path,
                call_arity,
                linker,
            );
            if !qualified_targets.is_empty() {
                for dst_id in qualified_targets {
                    accumulate_relation(
                        &mut resolved,
                        &mut relation_indices,
                        make_relation(rel, src_id, dst_id, QUALIFIED_SUFFIX_CONFIDENCE),
                    );
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
            accumulate_relation(&mut resolved, &mut relation_indices, external);
            continue;
        }
    }

    // See the batch resolver: an override is derived from declarations, not
    // resolved from an extracted relation.
    for relation in derive_override_relations_incremental(file, linker, import_map, class_bases) {
        accumulate_relation(&mut resolved, &mut relation_indices, relation);
    }

    resolved
}

/// Read-only step-local overlays shared by every per-file incremental
/// resolution, built once per link so the parallel per-file pass and its serial
/// reference resolve against byte-identical context.
struct IncrementalLinkOverlays<'a> {
    import_map: HashMap<&'a str, HashMap<&'a str, (&'a str, &'a str)>>,
    include_graph: HashMap<String, Vec<String>>,
    class_bases: HashMap<String, Vec<(String, Vec<String>)>>,
    /// (file, class, attribute) -> declared type name, for the two-hop
    /// receiver tier. Step-local like `import_map` above rather than merged
    /// with persistent state like `class_bases`: both halves of a two-hop join
    /// are read out of relations, and this step's relations are the ones the
    /// linker holds. A step that re-links one file therefore joins only
    /// against declarations that step carries, which is the same bound the
    /// import overlay beside it already has.
    declared_attribute_types: HashMap<(&'a str, &'a str, &'a str), &'a str>,
}

/// The incremental mirror of [`resolve_two_hop_declared_method`]. Same three
/// lookups against the live-edit indexes, so a running daemon answers a
/// two-hop receiver exactly as a cold index does.
#[allow(clippy::too_many_arguments)]
fn resolve_two_hop_declared_method_incremental(
    calling_file: &str,
    root_type: &str,
    attribute: &str,
    method: &str,
    linker: &IncrementalLinker,
    import_map: &HashMap<&str, HashMap<&str, (&str, &str)>>,
    class_bases: &HashMap<String, Vec<(String, Vec<String>)>>,
    declared_attribute_types: &HashMap<(&str, &str, &str), &str>,
) -> Option<EntityId> {
    let (root_file, root_class) =
        locate_base_class_incremental(calling_file, root_type, linker, import_map)?;
    let attribute_type =
        declared_attribute_types.get(&(root_file.as_str(), root_class.as_str(), attribute))?;
    let (owner_file, owner_class) =
        locate_base_class_incremental(&root_file, attribute_type, linker, import_map)?;
    resolve_declared_method_incremental(
        &owner_file,
        &owner_class,
        method,
        linker,
        import_map,
        class_bases,
    )
}

fn build_incremental_link_overlays<'a>(
    files: &'a [FileParseData],
    linker: &IncrementalLinker,
) -> IncrementalLinkOverlays<'a> {
    // Import map per file: local_name -> (module_path, original_name).
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

    // Step-local include edges overlay the linker's persistent per-file include
    // state: files parsed this step resolve fresh (including files that dropped
    // every include), every other file keeps the edges recorded when it was last
    // parsed. Closure walks therefore cross step boundaries.
    let include_graph = {
        let mut merged = linker.include_targets_by_file.clone();
        for file in files {
            merged.remove(&file.file_path);
        }
        let file_refs: Vec<&FileParseData> = files.iter().collect();
        for (file_path, targets) in build_include_graph(&file_refs, &linker.known_files) {
            merged.insert(file_path, targets);
        }
        merged
    };

    // Step-local class hierarchy overlays the linker's persistent per-file state,
    // exactly like the include graph above: files parsed this step resolve from
    // their fresh Extends declarations (including files whose classes lost every
    // base), every other file keeps the hierarchy recorded when it was last
    // parsed or rehydrated. Inheritance walks therefore cross step boundaries
    // without reading committed-stale bases for edited files.
    let class_bases = {
        let mut merged = linker.class_bases_by_file.clone();
        for file in files {
            merged.remove(&file.file_path);
        }
        for file in files {
            let classes = collect_class_bases(&file.relations);
            if !classes.is_empty() {
                merged.insert(file.file_path.clone(), classes);
            }
        }
        merged
    };

    IncrementalLinkOverlays {
        import_map,
        include_graph,
        class_bases,
        declared_attribute_types: build_declared_attribute_types(files.iter()),
    }
}

/// Merge per-file incremental relations in input-file order, then append
/// artifact-level import/include edges. The cross-file dedup is a no-op across
/// files (each relation's source entity is file-local) but is preserved so the
/// emitted set and order match a serial pass exactly. Mirrors the batch
/// [`merge_resolved`].
fn merge_incremental_resolved(
    per_file_relations: Vec<Vec<Relation>>,
    files: &[FileParseData],
    linker: &IncrementalLinker,
    completeness: Option<&FileParseCompletenessMap>,
) -> Vec<Relation> {
    let mut resolved = Vec::new();
    let mut relation_indices = HashMap::new();
    for file_relations in per_file_relations {
        for rel in file_relations {
            accumulate_relation(&mut resolved, &mut relation_indices, rel);
        }
    }

    // Step 4: Create import/include edges from import declarations, at both the
    // artifact level and the entity level.
    //
    // The entity-level lookups read the linker's own repository-wide indexes
    // rather than the changed-file slice, because an incremental relink of one
    // file still imports from files it did not touch. Building them from
    // `files` would silently drop every edge whose target sat outside the
    // change, and a partially relinked graph would disagree with a fully
    // relinked one for as long as nobody rebuilt from scratch.
    let mut seen_artifact: HashSet<(GraphNodeId, GraphNodeId, RelationKind)> = HashSet::new();
    let module_of = |path: &str| -> Option<EntityId> {
        linker
            .entities_by_file
            .get(path)?
            .iter()
            .find(|(id, _)| linker.entity_kind_by_id.get(id) == Some(&EntityKind::Module))
            .map(|(id, _)| *id)
    };
    let entity_of = |path: &str, name: &str| -> Option<EntityId> {
        linker.entity_by_file_name.get(path)?.get(name).copied()
    };
    for file in files {
        for imp in &file.imports {
            let Some((target, kind)) =
                resolve_import_target(&file.file_path, imp, &linker.known_files)
            else {
                continue;
            };
            if let Some(rel) = make_artifact_import_relation(
                &file.file_path,
                imp,
                &target,
                kind,
                &linker.artifact_ids,
            ) {
                let key = (rel.src, rel.dst, rel.kind);
                if seen_artifact.insert(key) {
                    resolved.push(rel);
                }
            }
            for rel in make_entity_import_relations(
                &file.file_path,
                imp,
                &target,
                kind,
                &module_of,
                &entity_of,
            ) {
                let key = (rel.src, rel.dst, rel.kind);
                if seen_artifact.insert(key) {
                    resolved.push(rel);
                }
            }
        }
    }

    let file_refs: Vec<&FileParseData> = files.iter().collect();
    append_parse_coverage_relations(
        &mut resolved,
        &file_refs,
        &linker.artifact_ids,
        completeness,
        &linker.known_files,
    );

    resolved
}

/// Serial counterpart of [`link_cross_file_incremental`], retained as the
/// byte-identical reference for the parallel per-file resolution path.
#[cfg(test)]
fn link_cross_file_incremental_serial(
    files: &[FileParseData],
    linker: &IncrementalLinker,
) -> Vec<Relation> {
    let IncrementalLinkOverlays {
        import_map,
        include_graph,
        class_bases,
        declared_attribute_types,
    } = build_incremental_link_overlays(files, linker);
    let per_file_relations: Vec<Vec<Relation>> = files
        .iter()
        .map(|file| {
            resolve_one_file_incremental(
                file,
                linker,
                &import_map,
                &include_graph,
                &class_bases,
                &declared_attribute_types,
                None,
            )
        })
        .collect();
    merge_incremental_resolved(per_file_relations, files, linker, None)
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
mod tests {
    use super::*;
    use crate::resolution::{RelationResolution, RESOLUTION_TIER_LADDER};
    use kin_model::{
        ArtifactId, EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm,
        GraphNodeId, Hash256, LanguageId, SemanticFingerprint, SourceSpan, Visibility,
    };
    use kin_parser::ImportedName;

    /// A well-formed but synthetic import site, for fixtures whose subject is
    /// not the span.
    ///
    /// These fixtures hand-build `FileImport` to exercise resolution, so they
    /// need the field to be present and shaped correctly and nothing more.
    /// Every test whose subject IS the span parses real source and reads the
    /// parser's own site; see `crates/kin-parser/tests/import_span_coverage.rs`.
    /// Naming this "synthetic" rather than "default" is deliberate: a helper
    /// called `default_site()` reads like something a production path could
    /// reasonably reach for, and nothing in production may invent a span.
    fn synthetic_import_site() -> kin_parser::RelationSite {
        kin_parser::RelationSite {
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            start_col: 0,
            end_line: 1,
            end_col: 1,
            syntactic_role: None,
        }
    }

    use std::sync::{Mutex, OnceLock};

    #[test]
    fn the_progress_gate_excludes_its_own_threshold() {
        assert!(!progress_bar_is_drawn(0, true));
        assert!(!progress_bar_is_drawn(1, true));
        assert!(!progress_bar_is_drawn(PROGRESS_BAR_MIN_FILES, true));
        assert!(progress_bar_is_drawn(PROGRESS_BAR_MIN_FILES + 1, true));
    }

    /// The bar redraws with a carriage return, which only a terminal reads as an
    /// overwrite. A pipe keeps every frame, so a captured admission of a large
    /// repository collected megabytes of `Linking:` lines that a reader had to
    /// scroll past to find the phase summaries underneath.
    ///
    /// The terminal probe is passed in rather than read here on purpose. Reading
    /// the real stderr would make this test pass or fail on whether a human ran
    /// it from a terminal, which is a check that answers a different question
    /// every time it runs.
    #[test]
    fn the_in_place_bar_is_never_drawn_off_a_terminal() {
        assert!(!progress_bar_is_drawn(PROGRESS_BAR_MIN_FILES + 1, false));
        assert!(!progress_bar_is_drawn(100_000, false));
    }

    /// A progress bar and the newline that terminates it must be decided by the
    /// same predicate. When they were two separate comparisons they drifted, and
    /// the terminator fired for link passes that had drawn nothing, so admission
    /// printed one bare newline per commit as its entire progress output.
    ///
    /// A unit test on the predicate cannot catch that, because the defect is a
    /// call site not using it. This reads the module's own source and fails if
    /// any gate is written inline again.
    ///
    /// Only the production half is scanned. The first version of this test read
    /// the whole file and failed immediately on the comparison literals in its
    /// own assertions, which is the mirror of a check that cannot fail: a check
    /// that cannot pass. Cutting the source at the test module keeps the guard
    /// pointed at the code it is guarding.
    #[test]
    fn every_progress_gate_routes_through_one_predicate() {
        let source = include_str!("linker.rs");
        let test_module = source
            .find("#[cfg(test)]\nmod tests {")
            .expect("linker.rs carries its test module");
        let production = &source[..test_module];

        let routed = production
            .matches("shows_progress_bar(total_files)")
            .count();
        assert_eq!(
            routed, 4,
            "expected both link paths to gate their bar and their terminator through \
             shows_progress_bar; found {routed} production call sites"
        );
        for inline in ["total_files > 0", "total_files > 50"] {
            assert!(
                !production.contains(inline),
                "a progress gate is written inline as `{inline}`; route it through \
                 shows_progress_bar so the bar and its terminator cannot disagree"
            );
        }
    }

    /// Test-only admission registry. The first fixture that admits a path gets
    /// a fresh graph-style identity; later assertions resolve that stored ID.
    /// Identity is never derived from path content.
    fn admitted_artifact_id(path: &str) -> ArtifactId {
        static IDS: OnceLock<Mutex<HashMap<String, ArtifactId>>> = OnceLock::new();
        let mut ids = IDS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .expect("test artifact admission lock poisoned");
        *ids.entry(path.to_string()).or_insert_with(ArtifactId::new)
    }

    fn admitted_artifacts<'a>(paths: impl IntoIterator<Item = &'a str>) -> ArtifactIdentityMap {
        paths
            .into_iter()
            .map(|path| (path.to_string(), admitted_artifact_id(path)))
            .collect()
    }

    fn artifact_ids_for(
        files: &[FileParseData],
        universe_entities: &[Entity],
    ) -> ArtifactIdentityMap {
        admitted_artifacts(
            files.iter().map(|file| file.file_path.as_str()).chain(
                universe_entities
                    .iter()
                    .filter_map(|entity| entity.file_origin.as_ref().map(|path| path.0.as_str())),
            ),
        )
    }

    /// Compatibility-shaped test helpers keep the large linker behavior
    /// matrix readable while exercising the production identity-required API.
    #[track_caller]
    fn link_cross_file(files: &[FileParseData]) -> Vec<Relation> {
        let universe = files
            .iter()
            .flat_map(|file| file.entities.iter().cloned())
            .collect::<Vec<_>>();
        let artifact_ids = artifact_ids_for(files, &universe);
        super::link_cross_file(files, &artifact_ids).expect("test paths were explicitly admitted")
    }

    #[track_caller]
    fn link_cross_file_with_completeness(
        files: &[FileParseData],
        completeness: &FileParseCompletenessMap,
    ) -> Vec<Relation> {
        let universe = files
            .iter()
            .flat_map(|file| file.entities.iter().cloned())
            .collect::<Vec<_>>();
        let artifact_ids = artifact_ids_for(files, &universe);
        super::link_cross_file_with_completeness(files, &artifact_ids, completeness)
            .expect("test paths were explicitly admitted")
    }

    #[track_caller]
    fn link_cross_file_against_entities(
        files: &[FileParseData],
        universe_entities: &[Entity],
    ) -> Vec<Relation> {
        let artifact_ids = artifact_ids_for(files, universe_entities);
        super::link_cross_file_against_entities(files, universe_entities, &artifact_ids)
            .expect("test paths were explicitly admitted")
    }

    fn admitted_incremental_linker(linker: &IncrementalLinker) -> IncrementalLinker {
        let mut checkpoint = linker.to_checkpoint_v1();
        let existing = checkpoint
            .artifact_ids
            .iter()
            .map(|(path, _)| path.clone())
            .collect::<HashSet<_>>();
        for path in &checkpoint.known_files {
            if !existing.contains(path) {
                checkpoint
                    .artifact_ids
                    .push((path.clone(), admitted_artifact_id(path)));
            }
        }
        checkpoint
            .artifact_ids
            .sort_by(|left, right| left.0.cmp(&right.0));
        IncrementalLinker::from_checkpoint_v1(checkpoint).expect("clone test linker")
    }

    #[track_caller]
    fn link_cross_file_incremental(
        files: &[FileParseData],
        linker: &IncrementalLinker,
    ) -> Vec<Relation> {
        let linker = admitted_incremental_linker(linker);
        super::link_cross_file_incremental(files, &linker)
            .expect("test paths were explicitly admitted")
    }

    #[track_caller]
    fn link_cross_file_incremental_with_completeness(
        files: &[FileParseData],
        linker: &IncrementalLinker,
        completeness: &FileParseCompletenessMap,
    ) -> Vec<Relation> {
        let linker = admitted_incremental_linker(linker);
        super::link_cross_file_incremental_with_completeness(files, &linker, completeness)
            .expect("test paths were explicitly admitted")
    }

    #[test]
    fn linker_fails_closed_without_graph_assigned_artifact_identity() {
        let files = [FileParseData {
            file_path: "src/lib.rs".to_string(),
            entities: vec![make_entity("run", "src/lib.rs")],
            relations: Vec::new(),
            imports: Vec::new(),
        }];
        let error = super::link_cross_file(&files, &ArtifactIdentityMap::new())
            .expect_err("linking must not fabricate an artifact identity");
        assert!(error
            .to_string()
            .contains("missing graph-assigned artifact identity for src/lib.rs"));
    }

    #[test]
    fn incremental_remove_then_path_reuse_cannot_retain_artifact_identity() {
        let mut linker = IncrementalLinker::new();
        let removed_identity = ArtifactId::new();
        let replacement_identity = ArtifactId::new();

        linker.add_file("assets/data.bin", removed_identity, &[]);
        assert_eq!(
            linker.artifact_ids.get("assets/data.bin"),
            Some(&removed_identity)
        );

        linker.remove_file("assets/data.bin");
        assert!(!linker.known_files.contains("assets/data.bin"));
        assert!(!linker.artifact_ids.contains_key("assets/data.bin"));

        linker.add_file("assets/data.bin", replacement_identity, &[]);
        assert_eq!(
            linker.artifact_ids.get("assets/data.bin"),
            Some(&replacement_identity)
        );
        assert_ne!(removed_identity, replacement_identity);
    }

    #[test]
    fn published_file_parse_carriers_keep_the_pre_completeness_struct_literal_api() {
        let _plain = FileParseData {
            file_path: "src/lib.py".to_string(),
            entities: Vec::new(),
            relations: Vec::new(),
            imports: Vec::new(),
        };
        let _with_tests = FileParseDataWithTests {
            file_path: "src/lib.py".to_string(),
            entities: Vec::new(),
            relations: Vec::new(),
            imports: Vec::new(),
            tests: Vec::new(),
        };
    }

    #[test]
    fn incremental_linker_checkpoint_is_canonical_round_trippable_and_fail_loud() {
        let alpha = EntityId::from_content("src/a.rs", "alpha", "function", 1);
        let beta = EntityId::from_content("src/b.rs", "beta", "function", 1);

        let build = |reverse: bool| {
            let mut linker = IncrementalLinker::new();
            let entries = if reverse {
                vec![("src/b.rs", "beta", beta), ("src/a.rs", "alpha", alpha)]
            } else {
                vec![("src/a.rs", "alpha", alpha), ("src/b.rs", "beta", beta)]
            };
            for (file, name, id) in entries {
                linker
                    .artifact_ids
                    .insert(file.to_string(), admitted_artifact_id(file));
                linker
                    .entity_by_file_name
                    .insert(file.to_string(), HashMap::from([(name.to_string(), id)]));
                linker
                    .entity_by_name
                    .insert(name.to_string(), vec![(file.to_string(), id)]);
                linker.entity_kind_by_id.insert(id, EntityKind::Function);
                linker.entity_language_by_id.insert(id, LanguageId::Rust);
                linker.known_files.insert(file.to_string());
                linker
                    .entities_by_file
                    .insert(file.to_string(), vec![(id, Visibility::Public)]);
                linker
                    .include_targets_by_file
                    .insert(file.to_string(), vec![format!("include/{name}.h")]);
                linker.class_bases_by_file.insert(
                    file.to_string(),
                    vec![(format!("{name}Class"), vec!["Base".to_string()])],
                );
            }
            linker
        };

        let canonical = serde_json::to_vec(&build(false).to_checkpoint_v1()).unwrap();
        let reverse_insertion = serde_json::to_vec(&build(true).to_checkpoint_v1()).unwrap();
        assert_eq!(
            canonical, reverse_insertion,
            "unordered map/set insertion must not change checkpoint bytes"
        );

        let checkpoint: IncrementalLinkerCheckpointV1 = serde_json::from_slice(&canonical).unwrap();
        let restored = IncrementalLinker::from_checkpoint_v1(checkpoint).unwrap();
        assert_eq!(
            canonical,
            serde_json::to_vec(&restored.to_checkpoint_v1()).unwrap(),
            "round-trip must preserve the canonical linker state"
        );

        let mut missing_field: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        missing_field.as_object_mut().unwrap().remove("known_files");
        assert!(
            serde_json::from_value::<IncrementalLinkerCheckpointV1>(missing_field).is_err(),
            "missing newly-required linker state must fail loudly; no serde defaults"
        );
    }

    fn test_fingerprint() -> SemanticFingerprint {
        let zero = Hash256::from_bytes([0u8; 32]);
        SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: zero,
            signature_hash: zero,
            behavior_hash: zero,
            equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
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

    fn arity(min: usize, max: usize, variadic: bool) -> ArityBounds {
        ArityBounds { min, max, variadic }
    }

    #[test]
    fn parse_signature_arity_plain_and_empty_parameter_lists() {
        assert_eq!(
            parse_signature_arity("int Main(int argc, char* const argv[])"),
            Some(arity(2, 2, false))
        );
        assert_eq!(
            parse_signature_arity("void add(int value)"),
            Some(arity(1, 1, false))
        );
        assert_eq!(
            parse_signature_arity("void run()"),
            Some(arity(0, 0, false))
        );
        // A C-style `(void)` list declares zero parameters, not one.
        assert_eq!(
            parse_signature_arity("int shutdown(void)"),
            Some(arity(0, 0, false))
        );
        // No locatable parameter list: arity is unknown, never a false zero.
        assert_eq!(parse_signature_arity("struct Widget"), None);
    }

    #[test]
    fn parse_signature_arity_counts_template_typed_parameters_as_one() {
        // The `<Config>` / `<int, Alloc>` commas sit inside a parameter's type,
        // so depth-aware splitting must not read them as parameter separators.
        assert_eq!(
            parse_signature_arity("Ptr<Config> Main(Ptr<Config> const& config)"),
            Some(arity(1, 1, false))
        );
        assert_eq!(
            parse_signature_arity("void insert(std::map<int, Alloc> m, int key)"),
            Some(arity(2, 2, false))
        );
    }

    #[test]
    fn parse_signature_arity_defaulted_parameters_widen_max_only() {
        // A defaulted parameter is optional: it lifts `max` but not `min`.
        assert_eq!(
            parse_signature_arity("void f(int a, int b = 0)"),
            Some(arity(1, 2, false))
        );
        assert_eq!(
            parse_signature_arity("void g(int a, int b = 0, int c = 1)"),
            Some(arity(1, 3, false))
        );
        // A relational operator inside a default expression is not the default
        // marker and must not be miscounted as an extra parameter.
        assert_eq!(
            parse_signature_arity("void h(int a, bool ok = a >= 0)"),
            Some(arity(1, 2, false))
        );
    }

    #[test]
    fn parse_signature_arity_variadics_accept_unbounded() {
        // C varargs and parameter packs both make the callee accept any count at
        // or above its required parameters.
        let printf = parse_signature_arity("int printf(const char* fmt, ...)").unwrap();
        assert_eq!(printf, arity(1, 1, true));
        assert!(printf.accepts(1) && printf.accepts(5) && !printf.accepts(0));

        let pack = parse_signature_arity("void emit(Args... args)").unwrap();
        assert!(pack.variadic && pack.accepts(0) && pack.accepts(3));
    }

    #[test]
    fn arity_bounds_accepts_matches_overload_selection() {
        let two = arity(2, 2, false);
        assert!(two.accepts(2));
        assert!(!two.accepts(1));
        assert!(!two.accepts(3));
        let optional = arity(1, 2, false);
        assert!(optional.accepts(1) && optional.accepts(2) && !optional.accepts(3));
    }

    #[test]
    fn same_file_resolution() {
        let e1 = make_entity("foo", "src/a.ts");
        let e2 = make_entity("bar", "src/a.ts");

        let files = vec![FileParseData {
            file_path: "src/a.ts".to_string(),
            entities: vec![e1.clone(), e2.clone()],
            relations: vec![ExtractedRelation {
                site: None,
                receiver: None,
                call_shape: None,
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
    fn repeated_call_shapes_are_complete_deterministic_and_batch_incremental_equal() {
        let caller = make_entity("caller", "src/a.py");
        let target = make_entity("target", "src/a.py");
        let positional_two = CallArgShape {
            positional: 2,
            ..CallArgShape::default()
        };
        let keyword = CallArgShape {
            positional: 1,
            keywords: vec!["args".to_string()],
            ..CallArgShape::default()
        };
        let var_positional = CallArgShape {
            has_var_positional: true,
            ..CallArgShape::default()
        };
        let forward_shapes = vec![
            Some(positional_two.clone()),
            Some(keyword.clone()),
            Some(positional_two),
            Some(var_positional),
        ];

        let build = |mut shapes: Vec<Option<CallArgShape>>| FileParseData {
            file_path: "src/a.py".to_string(),
            entities: vec![caller.clone(), target.clone()],
            relations: shapes
                .drain(..)
                .map(|call_shape| ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape,
                    kind: RelationKind::Calls,
                    src_name: "caller".to_string(),
                    dst_name: "target".to_string(),
                    import_source: None,
                })
                .collect(),
            imports: vec![],
        };
        let edge_evidence = |relations: &[Relation]| {
            find_calls_edge(relations, &caller, &target)
                .expect("logical caller-target edge")
                .evidence
                .clone()
        };

        let forward = vec![build(forward_shapes.clone())];
        let mut reversed_shapes = forward_shapes;
        reversed_shapes.reverse();
        let reversed = vec![build(reversed_shapes)];
        let batch_forward = edge_evidence(&link_cross_file(&forward));
        let batch_reversed = edge_evidence(&link_cross_file(&reversed));

        let mut incremental = IncrementalLinker::new();
        incremental.add_file(
            "src/a.py",
            admitted_artifact_id("src/a.py"),
            &[caller.clone(), target.clone()],
        );
        let incremental_forward =
            edge_evidence(&link_cross_file_incremental(&forward, &incremental));
        let incremental_reversed =
            edge_evidence(&link_cross_file_incremental(&reversed, &incremental));

        assert_eq!(batch_forward, batch_reversed);
        assert_eq!(batch_forward, incremental_forward);
        assert_eq!(batch_forward, incremental_reversed);
        assert_eq!(batch_forward.len(), 3, "three distinct call shapes");
        assert_eq!(
            batch_forward
                .iter()
                .map(|evidence| evidence.occurrence_count)
                .sum::<u32>(),
            4,
            "all four call sites survive through occurrence counts"
        );
        assert!(batch_forward.iter().any(|evidence| {
            evidence.occurrence_count == 2
                && evidence
                    .call_shape
                    .as_ref()
                    .is_some_and(|shape| shape.positional == 2)
        }));
        assert!(batch_forward.iter().any(|evidence| {
            evidence
                .call_shape
                .as_ref()
                .is_some_and(|shape| shape.keywords == ["args"])
        }));
        assert!(batch_forward.iter().any(|evidence| {
            evidence
                .call_shape
                .as_ref()
                .is_some_and(|shape| shape.has_var_positional)
        }));
    }

    #[test]
    fn repeated_call_with_any_missing_shape_retains_fail_closed_marker() {
        let caller = make_entity("caller", "src/a.py");
        let target = make_entity("target", "src/a.py");
        let build = |shapes: Vec<Option<CallArgShape>>| FileParseData {
            file_path: "src/a.py".to_string(),
            entities: vec![caller.clone(), target.clone()],
            relations: shapes
                .into_iter()
                .map(|call_shape| ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape,
                    kind: RelationKind::Calls,
                    src_name: "caller".to_string(),
                    dst_name: "target".to_string(),
                    import_source: None,
                })
                .collect(),
            imports: vec![],
        };
        let shaped = Some(CallArgShape {
            positional: 2,
            ..CallArgShape::default()
        });
        let forward = vec![build(vec![shaped.clone(), None])];
        let reversed = vec![build(vec![None, shaped])];
        let evidence = |files: &[FileParseData]| {
            find_calls_edge(&link_cross_file(files), &caller, &target)
                .expect("logical caller-target edge")
                .evidence
                .clone()
        };

        let forward_evidence = evidence(&forward);
        let reversed_evidence = evidence(&reversed);
        assert_eq!(forward_evidence, reversed_evidence);
        assert_eq!(forward_evidence.len(), 2);
        assert!(forward_evidence
            .iter()
            .any(|record| record.call_shape.is_none()));
        assert!(forward_evidence
            .iter()
            .any(|record| record.call_shape.is_some()));
    }

    #[test]
    fn incomplete_parse_call_evidence_is_explicit_and_never_certified() {
        let caller = make_entity("caller", "src/a.py");
        let target = make_entity("target", "src/a.py");
        let files = vec![FileParseData {
            file_path: "src/a.py".to_string(),
            entities: vec![caller.clone(), target.clone()],
            relations: vec![ExtractedRelation {
                site: None,
                receiver: None,
                call_shape: Some(CallArgShape {
                    positional: 2,
                    ..CallArgShape::default()
                }),
                kind: RelationKind::Calls,
                src_name: "caller".to_string(),
                dst_name: "target".to_string(),
                import_source: None,
            }],
            imports: vec![],
        }];
        let completeness = FileParseCompletenessMap::from([(
            "src/a.py".to_string(),
            ParseCompleteness::Partial("tree-sitter recovered from one error range".to_string()),
        )]);
        let evidence = |relations: &[Relation]| {
            find_calls_edge(relations, &caller, &target)
                .expect("recovered call edge")
                .evidence
                .clone()
        };

        let batch_relations = link_cross_file_with_completeness(&files, &completeness);
        let batch = evidence(&batch_relations);
        let mut linker = IncrementalLinker::new();
        linker.add_file(
            "src/a.py",
            admitted_artifact_id("src/a.py"),
            &[caller.clone(), target.clone()],
        );
        let incremental_relations =
            link_cross_file_incremental_with_completeness(&files, &linker, &completeness);
        let incremental = evidence(&incremental_relations);
        assert_eq!(batch, incremental);
        assert_eq!(batch.len(), 1);
        assert_eq!(
            batch[0].parser_rule.as_deref(),
            Some(CALL_SHAPE_EVIDENCE_INCOMPLETE_PARSE_V1)
        );
        assert!(batch[0].call_shape.is_none());
        for relations in [&batch_relations, &incremental_relations] {
            assert!(relations.iter().any(|relation| {
                relation.evidence.iter().any(|evidence| {
                    evidence.parser_rule.as_deref() == Some(CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1)
                })
            }));
        }
    }

    #[test]
    fn incomplete_call_extraction_downgrades_batch_incremental_and_compatibility_paths() {
        let caller = make_entity("caller", "src/a.py");
        let target = make_entity("target", "src/a.py");
        let files = vec![FileParseData {
            file_path: "src/a.py".to_string(),
            entities: vec![caller.clone(), target.clone()],
            relations: vec![
                ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: Some(CallArgShape {
                        positional: 2,
                        ..CallArgShape::default()
                    }),
                    kind: RelationKind::Calls,
                    src_name: "caller".to_string(),
                    dst_name: "target".to_string(),
                    import_source: None,
                },
                kin_parser::call_extraction_incomplete_marker(),
            ],
            imports: vec![],
        }];
        let evidence = |relations: &[Relation]| {
            find_calls_edge(relations, &caller, &target)
                .expect("surviving named call edge")
                .evidence
                .clone()
        };
        let assert_downgraded = |relations: &[Relation]| {
            let evidence = evidence(relations);
            assert_eq!(evidence.len(), 1);
            assert_eq!(
                evidence[0].parser_rule.as_deref(),
                Some(CALL_SHAPE_EVIDENCE_INCOMPLETE_EXTRACTION_V1)
            );
            assert!(evidence[0].call_shape.is_none());
            assert!(relations.iter().all(|relation| {
                relation.evidence.iter().all(|evidence| {
                    evidence.token.as_deref()
                        != Some(kin_parser::CALL_EXTRACTION_INCOMPLETE_MARKER_V1)
                })
            }));
        };

        let mut linker = IncrementalLinker::new();
        linker.add_file(
            "src/a.py",
            admitted_artifact_id("src/a.py"),
            &[caller.clone(), target.clone()],
        );
        let compat_batch = link_cross_file(&files);
        let compat_incremental = link_cross_file_incremental(&files, &linker);
        assert_downgraded(&compat_batch);
        assert_downgraded(&compat_incremental);
        assert_eq!(evidence(&compat_batch), evidence(&compat_incremental));

        let completeness =
            FileParseCompletenessMap::from([("src/a.py".to_string(), ParseCompleteness::Full)]);
        let batch = link_cross_file_with_completeness(&files, &completeness);
        let incremental =
            link_cross_file_incremental_with_completeness(&files, &linker, &completeness);
        assert_downgraded(&batch);
        assert_downgraded(&incremental);
        for relations in [&batch, &incremental] {
            assert!(relations.iter().any(|relation| {
                relation.evidence.iter().any(|evidence| {
                    evidence.parser_rule.as_deref()
                        == Some(CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1)
                        && evidence.token.as_deref() == Some("call-extraction-incomplete")
                })
            }));
            assert!(relations.iter().all(|relation| {
                relation.evidence.iter().all(|evidence| {
                    evidence.parser_rule.as_deref() != Some(CALL_SHAPE_PARSE_COVERAGE_FULL_V1)
                })
            }));
        }
    }

    #[test]
    fn omitted_only_call_file_emits_coverage_gap_in_batch_and_incremental_linking() {
        let target = make_entity("target", "src/defs.py");
        let caller = make_entity("caller", "src/good.py");
        let broken = make_entity("broken", "src/bad.py");
        let files = vec![
            FileParseData {
                file_path: "src/defs.py".to_string(),
                entities: vec![target.clone()],
                relations: Vec::new(),
                imports: Vec::new(),
            },
            FileParseData {
                file_path: "src/good.py".to_string(),
                entities: vec![caller.clone()],
                relations: vec![ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: Some(CallArgShape {
                        positional: 1,
                        ..CallArgShape::default()
                    }),
                    kind: RelationKind::Calls,
                    src_name: "caller".to_string(),
                    dst_name: "target".to_string(),
                    import_source: None,
                }],
                imports: Vec::new(),
            },
            FileParseData {
                file_path: "src/bad.py".to_string(),
                entities: vec![broken.clone()],
                relations: Vec::new(),
                imports: Vec::new(),
            },
        ];
        let completeness = FileParseCompletenessMap::from([
            ("src/defs.py".to_string(), ParseCompleteness::Full),
            ("src/good.py".to_string(), ParseCompleteness::Full),
            (
                "src/bad.py".to_string(),
                ParseCompleteness::Partial("recovered malformed keyword call".to_string()),
            ),
        ]);

        let batch = link_cross_file_with_completeness(&files, &completeness);
        let mut linker = IncrementalLinker::new();
        for file in &files {
            linker.add_file(
                &file.file_path,
                admitted_artifact_id(&file.file_path),
                &file.entities,
            );
        }
        let incremental =
            link_cross_file_incremental_with_completeness(&files, &linker, &completeness);

        for relations in [&batch, &incremental] {
            let inbound = find_calls_edge(relations, &caller, &target)
                .expect("the independent full positional call must link");
            assert!(inbound.evidence.iter().all(|evidence| {
                evidence.parser_rule.as_deref() == Some(CALL_SHAPE_EVIDENCE_AGGREGATION_V1)
                    && evidence.call_shape.is_some()
            }));
            assert!(relations
                .iter()
                .any(|relation| relation.evidence.iter().any(|evidence| {
                    evidence.parser_rule.as_deref() == Some(CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1)
                        && evidence.source_path.as_deref() == Some("src/bad.py")
                })));
        }

        let all_full = FileParseCompletenessMap::from([
            ("src/defs.py".to_string(), ParseCompleteness::Full),
            ("src/good.py".to_string(), ParseCompleteness::Full),
            ("src/bad.py".to_string(), ParseCompleteness::Full),
        ]);
        let restored = link_cross_file_with_completeness(&files, &all_full);
        let marker_id = |relations: &[Relation], parser_rule: &str| {
            relations
                .iter()
                .find(|relation| {
                    relation.evidence.iter().any(|evidence| {
                        evidence.parser_rule.as_deref() == Some(parser_rule)
                            && evidence.source_path.as_deref() == Some("src/bad.py")
                    })
                })
                .expect("bad.py coverage marker")
                .id
        };
        assert_eq!(
            marker_id(&batch, CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1),
            marker_id(&restored, CALL_SHAPE_PARSE_COVERAGE_FULL_V1),
            "coverage changes update one graph-owned artifact relation; they must not \
             fabricate a new relation identity from path or evidence"
        );
    }

    #[test]
    fn repeated_call_metadata_keeps_strongest_resolution_independent_of_source_order() {
        let caller = rust_fn("caller", "src/caller.rs");
        let target = make_method_entity("Widget::make", "src/model.rs");
        let build = |strong_first: bool| {
            let mut relations = vec![
                calls_relation("caller", "Widget::make"),
                calls_relation("caller", "make"),
            ];
            if !strong_first {
                relations.reverse();
            }
            vec![
                FileParseData {
                    // Load-bearing: a bare Rust call reaches the bare-name tier
                    // only from a file whose import list cannot answer whether it
                    // binds that name. With no imports at all the list is
                    // name-complete, and the bare `make` is refused before it can
                    // merge with the qualified one, which is the FIR-1581 gate
                    // doing its job rather than this test's subject.
                    file_path: "src/caller.rs".to_string(),
                    entities: vec![caller.clone()],
                    relations,
                    imports: vec![FileImport {
                        site: synthetic_import_site(),
                        module_path: "crate::model".to_string(),
                        specifiers: vec![],
                    }],
                },
                FileParseData {
                    file_path: "src/model.rs".to_string(),
                    entities: vec![target.clone()],
                    relations: vec![],
                    imports: vec![],
                },
            ]
        };
        let batch_edge = |files: &[FileParseData]| {
            find_calls_edge(&link_cross_file(files), &caller, &target)
                .expect("qualified and bare calls should resolve to one logical edge")
                .clone()
        };
        let incremental_edge = |files: &[FileParseData]| {
            let mut linker = IncrementalLinker::new();
            for file in files {
                linker.add_file(
                    &file.file_path,
                    admitted_artifact_id(&file.file_path),
                    &file.entities,
                );
            }
            find_calls_edge(
                &link_cross_file_incremental(files, &linker),
                &caller,
                &target,
            )
            .expect("incremental qualified and bare calls should resolve to one logical edge")
            .clone()
        };

        let forward = build(true);
        let reversed = build(false);
        let batch_forward = batch_edge(&forward);
        let batch_reversed = batch_edge(&reversed);
        let incremental_forward = incremental_edge(&forward);
        let incremental_reversed = incremental_edge(&reversed);

        let canonical = serde_json::to_value(&batch_forward).unwrap();
        assert_eq!(canonical, serde_json::to_value(&batch_reversed).unwrap());
        assert_eq!(
            canonical,
            serde_json::to_value(&incremental_forward).unwrap()
        );
        assert_eq!(
            canonical,
            serde_json::to_value(&incremental_reversed).unwrap()
        );
        assert_eq!(batch_forward.confidence, 0.7);
        assert_eq!(batch_forward.origin, RelationOrigin::Inferred);
        assert_eq!(batch_forward.evidence.len(), 1);
        assert_eq!(batch_forward.evidence[0].occurrence_count, 2);
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
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: RelationKind::Calls,
                    src_name: "handler".to_string(),
                    dst_name: "executeTool".to_string(),
                    import_source: None,
                }],
                imports: vec![FileImport {
                    site: synthetic_import_site(),
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
            GraphNodeId::Artifact(admitted_artifact_id("src/routes/api.ts"))
        );
        assert_eq!(
            imports.dst,
            GraphNodeId::Artifact(admitted_artifact_id("src/utils/tools.ts"))
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
                site: None,
                receiver: None,
                call_shape: None,
                kind: RelationKind::Calls,
                src_name: "handler".to_string(),
                dst_name: "executeTool".to_string(),
                import_source: None,
            }],
            imports: vec![FileImport {
                site: synthetic_import_site(),
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
            GraphNodeId::Artifact(admitted_artifact_id("src/routes/api.ts"))
        );
        assert_eq!(
            imports.dst,
            GraphNodeId::Artifact(admitted_artifact_id("src/utils/tools.ts"))
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
                site: None,
                receiver: None,
                call_shape: None,
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
        assert!(
            !forward_result
                .iter()
                .any(|rel| rel.kind == RelationKind::Calls),
            "two same-named targets the caller neither imports nor sits beside \
             leave the call unlinked rather than binding a bucket-order guess"
        );
    }

    #[test]
    fn parallel_resolution_is_byte_identical_to_serial() {
        let calls = |src: &str, dst: &str| ExtractedRelation {
            site: None,
            receiver: None,
            call_shape: None,
            kind: RelationKind::Calls,
            src_name: src.to_string(),
            dst_name: dst.to_string(),
            import_source: None,
        };
        let import = |module: &str, name: &str| FileImport {
            site: synthetic_import_site(),
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
        let artifact_ids = artifact_ids_for(&files, &universe);

        let parallel = link_cross_file_against_entities(&files, &universe);
        let serial = link_cross_file_against_entities_serial(&files, &universe, &artifact_ids);

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
            site: synthetic_import_site(),
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

        let file_refs: Vec<&FileParseData> = files.iter().collect();
        let parallel = build_include_graph(&file_refs, &known_files);
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
            site: synthetic_import_site(),
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
        let universe_refs: Vec<&Entity> = universe.iter().collect();
        let file_refs: Vec<&FileParseData> = files.iter().collect();
        let ctx = build_link_context(&file_refs, &universe_refs);
        let artifact_ids = artifact_ids_for(&files, &universe);

        // resolve_one_file is deterministic, so building the per-file relations
        // twice yields identical inputs for the two merge paths.
        let pfr_parallel: Vec<Vec<Relation>> = files
            .iter()
            .map(|f| resolve_one_file(f, &ctx, None))
            .collect();
        let pfr_serial: Vec<Vec<Relation>> = files
            .iter()
            .map(|f| resolve_one_file(f, &ctx, None))
            .collect();

        let file_refs: Vec<&FileParseData> = files.iter().collect();
        let parallel = merge_resolved(pfr_parallel, &file_refs, &ctx, &artifact_ids, None);
        let serial = merge_resolved_serial(pfr_serial, &files, &ctx, &artifact_ids);

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
                    site: None,
                    receiver: None,
                    call_shape: None,
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
    fn blind_name_inference_does_not_connect_typescript_to_python_same_name() {
        let caller = make_entity("main", "src/app.ts");
        let mut unrelated = make_entity("execute", "tools/worker.py");
        unrelated.language = LanguageId::Python;
        let files = vec![
            FileParseData {
                file_path: "src/app.ts".to_string(),
                entities: vec![caller.clone()],
                relations: vec![ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: RelationKind::Calls,
                    src_name: "main".to_string(),
                    dst_name: "execute".to_string(),
                    import_source: None,
                }],
                imports: vec![],
            },
            FileParseData {
                file_path: "tools/worker.py".to_string(),
                entities: vec![unrelated.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        assert!(
            find_calls_edge(&link_cross_file(&files), &caller, &unrelated).is_none(),
            "a same-name Python symbol is not evidence for a TypeScript call"
        );

        let mut linker = IncrementalLinker::new();
        for file in &files {
            linker.add_file(
                &file.file_path,
                admitted_artifact_id(&file.file_path),
                &file.entities,
            );
        }
        assert!(
            find_calls_edge(
                &link_cross_file_incremental(&files, &linker),
                &caller,
                &unrelated,
            )
            .is_none(),
            "incremental linking must apply the same language gate"
        );
    }

    #[test]
    fn blind_inference_requires_language_evidence_for_both_entities() {
        let src = EntityId::new();
        let dst = EntityId::new();
        let mut languages = HashMap::new();
        assert!(!blind_inference_target_allowed(src, dst, &languages));
        languages.insert(src, LanguageId::Rust);
        assert!(!blind_inference_target_allowed(src, dst, &languages));
    }

    #[test]
    fn blind_name_inference_allows_documented_javascript_typescript_family() {
        let caller = make_entity("main", "src/app.ts");
        let mut target = make_entity("execute", "src/worker.js");
        target.language = LanguageId::JavaScript;
        let files = vec![
            FileParseData {
                file_path: "src/app.ts".to_string(),
                entities: vec![caller.clone()],
                relations: vec![ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: RelationKind::Calls,
                    src_name: "main".to_string(),
                    dst_name: "execute".to_string(),
                    import_source: None,
                }],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/worker.js".to_string(),
                entities: vec![target.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let batch = link_cross_file(&files);
        assert!(find_calls_edge(&batch, &caller, &target).is_some());

        let mut linker = IncrementalLinker::new();
        for file in &files {
            linker.add_file(
                &file.file_path,
                admitted_artifact_id(&file.file_path),
                &file.entities,
            );
        }
        let incremental = link_cross_file_incremental(&files, &linker);
        assert!(find_calls_edge(&incremental, &caller, &target).is_some());
    }

    #[test]
    fn explicit_import_evidence_may_connect_typescript_to_python() {
        let caller = make_entity("handler", "src/routes/api.ts");
        let mut target = make_entity("execute", "src/utils/worker.py");
        target.language = LanguageId::Python;
        let files = vec![
            FileParseData {
                file_path: "src/routes/api.ts".to_string(),
                entities: vec![caller.clone()],
                relations: vec![ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: RelationKind::Calls,
                    src_name: "handler".to_string(),
                    dst_name: "execute".to_string(),
                    import_source: None,
                }],
                imports: vec![FileImport {
                    site: synthetic_import_site(),
                    module_path: "../utils/worker".to_string(),
                    specifiers: vec![kin_parser::ImportedName {
                        local_name: "execute".to_string(),
                        original_name: None,
                        is_default: false,
                    }],
                }],
            },
            FileParseData {
                file_path: "src/utils/worker.py".to_string(),
                entities: vec![target.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let batch = link_cross_file(&files);
        let batch_edge = find_calls_edge(&batch, &caller, &target)
            .expect("explicit module/import evidence may cross languages");
        assert_eq!(batch_edge.confidence, 0.95);

        let mut linker = IncrementalLinker::new();
        for file in &files {
            linker.add_file(
                &file.file_path,
                admitted_artifact_id(&file.file_path),
                &file.entities,
            );
        }
        let incremental = link_cross_file_incremental(&files, &linker);
        let incremental_edge = find_calls_edge(&incremental, &caller, &target)
            .expect("incremental import evidence may cross languages");
        assert_eq!(incremental_edge.confidence, 0.95);
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
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: RelationKind::UsesMacro,
                    src_name: "main".to_string(),
                    dst_name: "JSON_PRIVATE_UNLESS_TESTED".to_string(),
                    import_source: None,
                }],
                imports: vec![FileImport {
                    site: synthetic_import_site(),
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
                    && rel.src == GraphNodeId::Artifact(admitted_artifact_id("src/app.cpp"))
                    && rel.dst
                        == GraphNodeId::Artifact(admitted_artifact_id("include/json/macros.hpp"))
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
                    site: None,
                    receiver: None,
                    call_shape: None,
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
                    Some(admitted_artifact_id(path))
                } else {
                    None
                }
            },
        );

        assert_eq!(relations.len(), 2);
        assert!(relations.iter().all(|rel| {
            rel.kind == RelationKind::DerivedFrom
                && rel.src
                    == GraphNodeId::Artifact(admitted_artifact_id(
                        "single_include/nlohmann/json.hpp",
                    ))
        }));
        let exception_edge = relations
            .iter()
            .find(|rel| {
                rel.dst
                    == GraphNodeId::Artifact(admitted_artifact_id(
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
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: RelationKind::Calls,
                    src_name: "_safeParse".to_string(),
                    dst_name: "util.finalizeIssue".to_string(),
                    import_source: None,
                }],
                imports: vec![FileImport {
                    site: synthetic_import_site(),
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
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: RelationKind::Calls,
                    src_name: "foo".to_string(),
                    dst_name: "bar".to_string(),
                    import_source: None,
                },
                ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: None,
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
                site: None,
                receiver: None,
                call_shape: None,
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
                    site: None,
                    receiver: None,
                    call_shape: None,
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
    fn receiver_method_call_fans_out_to_all_implementors() {
        // A call to bare `new` could target either `Foo::new` or `Bar::new`. The
        // receiver type is unknowable from the name, so rather than drop the edge
        // the resolver fans out to every implementor (bounded by the cap): both
        // `Foo::new` and `Bar::new` link, keeping the caller visible in refs.
        // (Updated from the old refuse-on-ambiguity contract.)
        let caller = make_entity("build", "src/caller.rs");
        let foo_new = make_entity("Foo::new", "src/foo.rs");
        let bar_new = make_entity("Bar::new", "src/bar.rs");

        let files = vec![
            FileParseData {
                file_path: "src/caller.rs".to_string(),
                entities: vec![caller.clone()],
                relations: vec![ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: RelationKind::Calls,
                    src_name: "build".to_string(),
                    dst_name: "new".to_string(),
                    import_source: None,
                }],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/foo.rs".to_string(),
                entities: vec![foo_new.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/bar.rs".to_string(),
                entities: vec![bar_new.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let calls: Vec<&Relation> = result
            .iter()
            .filter(|r| r.kind == RelationKind::Calls && r.src == GraphNodeId::Entity(caller.id))
            .collect();
        let targets: HashSet<GraphNodeId> = calls.iter().map(|r| r.dst).collect();
        assert_eq!(
            targets.len(),
            2,
            "ambiguous bare-name receiver call must fan out to both implementors, got {targets:?}"
        );
        assert!(targets.contains(&GraphNodeId::Entity(foo_new.id)));
        assert!(targets.contains(&GraphNodeId::Entity(bar_new.id)));
        // Fan-out edges keep the ambiguous receiver-method confidence.
        assert!(calls.iter().all(|r| r.confidence == 0.3));
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
        linker.add_file(
            "src/wiring.rs",
            admitted_artifact_id("src/wiring.rs"),
            std::slice::from_ref(&caller),
        );
        linker.add_file(
            "src/reconciler.rs",
            admitted_artifact_id("src/reconciler.rs"),
            std::slice::from_ref(&callee),
        );

        let files = vec![FileParseData {
            file_path: "src/wiring.rs".to_string(),
            entities: vec![caller.clone()],
            relations: vec![ExtractedRelation {
                site: None,
                receiver: None,
                call_shape: None,
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

    fn make_python_entity(name: &str, file_path: &str, kind: EntityKind) -> Entity {
        let mut entity = make_entity(name, file_path);
        entity.language = LanguageId::Python;
        entity.kind = kind;
        entity
    }

    fn python_import(module_path: &str, names: &[&str]) -> FileImport {
        FileImport {
            site: synthetic_import_site(),
            module_path: module_path.to_string(),
            specifiers: names
                .iter()
                .map(|name| ImportedName {
                    local_name: (*name).to_string(),
                    original_name: None,
                    is_default: false,
                })
                .collect(),
        }
    }

    fn bare_call(src_name: &str, dst_name: &str) -> ExtractedRelation {
        ExtractedRelation {
            site: None,
            receiver: None,
            call_shape: None,
            kind: RelationKind::Calls,
            src_name: src_name.to_string(),
            dst_name: dst_name.to_string(),
            import_source: None,
        }
    }

    /// The FIR-2400 shape exactly: `parse_file` opens a path with the builtin
    /// `open`, and a storage module the parsing module never imports defines a
    /// `NoteStore.open` classmethod. The bare-name index held one entry, so it
    /// captured the call and `trace_data_flow` walked a subtree of a module the
    /// file cannot see.
    #[test]
    fn a_bare_python_builtin_call_reaches_no_cross_module_method() {
        let caller =
            make_python_entity("parse_file", "notekeeper/parsing.py", EntityKind::Function);
        let method = make_python_entity(
            "NoteStore.open",
            "notekeeper/storage.py",
            EntityKind::Method,
        );

        let files = vec![
            FileParseData {
                file_path: "notekeeper/parsing.py".to_string(),
                entities: vec![caller.clone()],
                relations: vec![bare_call("parse_file", "open")],
                imports: vec![python_import("os", &["os"]), python_import("re", &["re"])],
            },
            FileParseData {
                file_path: "notekeeper/storage.py".to_string(),
                entities: vec![method.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let calls: Vec<&Relation> = result
            .iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .collect();
        assert!(
            calls.is_empty(),
            "a bare builtin call must not reach a method of an unimported module, got {calls:?}"
        );
    }

    /// The same gate with a module-level function as the decoy. A method needs a
    /// receiver, but a same-named free function does not, so only the builtin
    /// table can refuse this one.
    #[test]
    fn a_bare_python_builtin_call_reaches_no_cross_module_function() {
        let caller =
            make_python_entity("parse_file", "notekeeper/parsing.py", EntityKind::Function);
        let decoy = make_python_entity("open", "notekeeper/storage.py", EntityKind::Function);
        let counted = make_python_entity("len", "notekeeper/metrics.py", EntityKind::Function);

        let files = vec![
            FileParseData {
                file_path: "notekeeper/parsing.py".to_string(),
                entities: vec![caller.clone()],
                relations: vec![
                    bare_call("parse_file", "open"),
                    bare_call("parse_file", "len"),
                ],
                imports: vec![python_import("os", &["os"])],
            },
            FileParseData {
                file_path: "notekeeper/storage.py".to_string(),
                entities: vec![decoy.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "notekeeper/metrics.py".to_string(),
                entities: vec![counted.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let calls: Vec<&Relation> = result
            .iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .collect();
        assert!(
            calls.is_empty(),
            "bare `open`/`len` calls must not reach same-named module functions, got {calls:?}"
        );
    }

    /// The receiver half of the fix, on a name no builtins table contains: a
    /// bare `prune_except(...)` cannot dispatch to `NoteStore.prune_except`,
    /// because a method call needs a receiver and this call site has none.
    #[test]
    fn a_bare_python_call_reaches_no_method_it_has_no_receiver_for() {
        let caller = make_python_entity("run_gc", "notekeeper/cleanup.py", EntityKind::Function);
        let method = make_python_entity(
            "NoteStore.prune_except",
            "notekeeper/storage.py",
            EntityKind::Method,
        );

        let files = vec![
            FileParseData {
                file_path: "notekeeper/cleanup.py".to_string(),
                entities: vec![caller.clone()],
                relations: vec![bare_call("run_gc", "prune_except")],
                imports: vec![],
            },
            FileParseData {
                file_path: "notekeeper/storage.py".to_string(),
                entities: vec![method.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let calls: Vec<&Relation> = result
            .iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .collect();
        assert!(
            calls.is_empty(),
            "a bare call must not dispatch to a method, got {calls:?}"
        );
    }

    /// Recall control for the builtin gate: a module that defines its own
    /// `open` shadows the interpreter's, and the same-file tier must still bind
    /// the call at full confidence.
    #[test]
    fn a_python_module_that_defines_open_still_resolves_its_own_call() {
        let caller =
            make_python_entity("parse_file", "notekeeper/parsing.py", EntityKind::Function);
        let local_open = make_python_entity("open", "notekeeper/parsing.py", EntityKind::Function);

        let files = vec![FileParseData {
            file_path: "notekeeper/parsing.py".to_string(),
            entities: vec![caller.clone(), local_open.clone()],
            relations: vec![bare_call("parse_file", "open")],
            imports: vec![],
        }];

        let result = link_cross_file(&files);
        let call = result
            .iter()
            .find(|r| r.kind == RelationKind::Calls)
            .expect("a same-file `open` must still resolve");
        assert_eq!(call.src, GraphNodeId::Entity(caller.id));
        assert_eq!(call.dst, GraphNodeId::Entity(local_open.id));
        assert_eq!(call.confidence, 1.0);
    }

    /// Recall control for the import half: `from storage import open_store` and
    /// a bare `open_store(...)` is the shape the ticket asks to keep, and an
    /// imported builtin name must keep resolving too.
    #[test]
    fn an_imported_python_name_still_resolves_including_a_builtin_one() {
        let caller =
            make_python_entity("parse_file", "notekeeper/parsing.py", EntityKind::Function);
        let imported =
            make_python_entity("open_store", "notekeeper/storage.py", EntityKind::Function);
        let shadow = make_python_entity("open", "notekeeper/storage.py", EntityKind::Function);

        let files = vec![
            FileParseData {
                file_path: "notekeeper/parsing.py".to_string(),
                entities: vec![caller.clone()],
                relations: vec![
                    bare_call("parse_file", "open_store"),
                    bare_call("parse_file", "open"),
                ],
                imports: vec![python_import("notekeeper.storage", &["open_store", "open"])],
            },
            FileParseData {
                file_path: "notekeeper/storage.py".to_string(),
                entities: vec![imported.clone(), shadow.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let targets: HashSet<GraphNodeId> = result
            .iter()
            .filter(|r| r.kind == RelationKind::Calls && r.src == GraphNodeId::Entity(caller.id))
            .map(|r| r.dst)
            .collect();
        assert!(
            targets.contains(&GraphNodeId::Entity(imported.id)),
            "an imported name must still resolve, got {targets:?}"
        );
        assert!(
            targets.contains(&GraphNodeId::Entity(shadow.id)),
            "an imported symbol that shadows a builtin must still resolve, got {targets:?}"
        );
    }

    /// The receiver path this fix must leave alone: a file that imports the
    /// class and calls `store.open()` reaches `NoteStore.open` through the
    /// receiver-reach narrowing kin#888 added.
    #[test]
    fn a_receiver_call_on_an_imported_class_still_resolves() {
        let caller = make_python_entity("ingest", "notekeeper/ingest.py", EntityKind::Function);
        let method = make_python_entity(
            "NoteStore.open",
            "notekeeper/storage.py",
            EntityKind::Method,
        );

        let files = vec![
            FileParseData {
                file_path: "notekeeper/ingest.py".to_string(),
                entities: vec![caller.clone()],
                relations: vec![ExtractedRelation {
                    site: None,
                    receiver: Some("store".to_string()),
                    call_shape: None,
                    kind: RelationKind::Calls,
                    src_name: "ingest".to_string(),
                    dst_name: "open".to_string(),
                    import_source: None,
                }],
                imports: vec![python_import("notekeeper.storage", &["NoteStore"])],
            },
            FileParseData {
                file_path: "notekeeper/storage.py".to_string(),
                entities: vec![method.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let call = result
            .iter()
            .find(|r| r.kind == RelationKind::Calls)
            .expect("`store.open()` in a file importing NoteStore must still resolve");
        assert_eq!(call.src, GraphNodeId::Entity(caller.id));
        assert_eq!(call.dst, GraphNodeId::Entity(method.id));
    }

    /// A wildcard import records no names, so the file has no answer to "do you
    /// import `open`". The gate stands down rather than dropping an edge it
    /// cannot see the binding for.
    #[test]
    fn a_wildcard_import_stands_the_python_builtin_gate_down() {
        let caller =
            make_python_entity("parse_file", "notekeeper/parsing.py", EntityKind::Function);
        let shadow = make_python_entity("open", "notekeeper/compat.py", EntityKind::Function);

        let files = vec![
            FileParseData {
                file_path: "notekeeper/parsing.py".to_string(),
                entities: vec![caller.clone()],
                relations: vec![bare_call("parse_file", "open")],
                imports: vec![FileImport {
                    site: synthetic_import_site(),
                    module_path: "notekeeper.compat".to_string(),
                    specifiers: Vec::new(),
                }],
            },
            FileParseData {
                file_path: "notekeeper/compat.py".to_string(),
                entities: vec![shadow.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let call = result
            .iter()
            .find(|r| r.kind == RelationKind::Calls)
            .expect("a star import may bind `open`, so the gate must not fire");
        assert_eq!(call.dst, GraphNodeId::Entity(shadow.id));
    }

    /// The gates are Python-scoped because Python is the only adapter that
    /// records a receiver for attribute calls. An adapter that records none
    /// cannot distinguish `x.open()` from `open()`, so reading its missing
    /// receiver as proof of a bare call would drop every receiver-method edge
    /// it resolves.
    #[test]
    fn a_non_python_bare_call_still_reaches_its_method() {
        let mut caller = make_entity("build", "src/wiring.ts");
        caller.language = LanguageId::TypeScript;
        let mut method = make_entity("Store.open", "src/store.ts");
        method.language = LanguageId::TypeScript;
        method.kind = EntityKind::Method;

        let files = vec![
            FileParseData {
                file_path: "src/wiring.ts".to_string(),
                entities: vec![caller.clone()],
                relations: vec![bare_call("build", "open")],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/store.ts".to_string(),
                entities: vec![method.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let call = result
            .iter()
            .find(|r| r.kind == RelationKind::Calls)
            .expect("a TypeScript receiver-method call must still resolve");
        assert_eq!(call.dst, GraphNodeId::Entity(method.id));
    }

    /// Incremental parity: a relink of the caller alone must not re-mint the
    /// edge the batch linker refuses.
    #[test]
    fn incremental_bare_python_builtin_call_reaches_no_cross_module_method() {
        let caller =
            make_python_entity("parse_file", "notekeeper/parsing.py", EntityKind::Function);
        let method = make_python_entity(
            "NoteStore.open",
            "notekeeper/storage.py",
            EntityKind::Method,
        );

        let mut linker = IncrementalLinker::new();
        linker.add_file(
            "notekeeper/parsing.py",
            admitted_artifact_id("notekeeper/parsing.py"),
            std::slice::from_ref(&caller),
        );
        linker.add_file(
            "notekeeper/storage.py",
            admitted_artifact_id("notekeeper/storage.py"),
            std::slice::from_ref(&method),
        );

        let files = vec![FileParseData {
            file_path: "notekeeper/parsing.py".to_string(),
            entities: vec![caller.clone()],
            relations: vec![bare_call("parse_file", "open")],
            imports: vec![python_import("os", &["os"])],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        let calls: Vec<&Relation> = result
            .iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .collect();
        assert!(
            calls.is_empty(),
            "incremental relink must not re-mint the builtin edge, got {calls:?}"
        );
    }

    /// Incremental parity for the receiver half.
    #[test]
    fn incremental_bare_python_call_reaches_no_method_it_has_no_receiver_for() {
        let caller = make_python_entity("run_gc", "notekeeper/cleanup.py", EntityKind::Function);
        let method = make_python_entity(
            "NoteStore.prune_except",
            "notekeeper/storage.py",
            EntityKind::Method,
        );

        let mut linker = IncrementalLinker::new();
        linker.add_file(
            "notekeeper/cleanup.py",
            admitted_artifact_id("notekeeper/cleanup.py"),
            std::slice::from_ref(&caller),
        );
        linker.add_file(
            "notekeeper/storage.py",
            admitted_artifact_id("notekeeper/storage.py"),
            std::slice::from_ref(&method),
        );

        let files = vec![FileParseData {
            file_path: "notekeeper/cleanup.py".to_string(),
            entities: vec![caller.clone()],
            relations: vec![bare_call("run_gc", "prune_except")],
            imports: vec![],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        let calls: Vec<&Relation> = result
            .iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .collect();
        assert!(
            calls.is_empty(),
            "incremental relink must not dispatch a bare call to a method, got {calls:?}"
        );
    }

    #[test]
    fn link_cross_file_incremental_parallel_matches_serial() {
        // Rung-3 oracle for the parallel per-file resolver: exercise enough files,
        // relation tiers, and ambiguous name buckets that any ordering or
        // shared-state hazard in the fan-out would surface, then assert the
        // parallel path is byte-identical to the serial reference and stable
        // across re-runs. Mirrors `link_cross_file_against_entities`'s own
        // parallel-vs-serial guard.
        let mut linker = IncrementalLinker::new();
        let mut files: Vec<FileParseData> = Vec::new();

        // Two cross-file definitions of a shared ambiguous name so callers reach
        // the same-name disambiguation tier (which picks by bucket order — a
        // determinism-sensitive path).
        let common_a = make_entity("common", "src/common_a.ts");
        let common_b = make_entity("common", "src/common_b.ts");
        linker.add_file(
            "src/common_a.ts",
            admitted_artifact_id("src/common_a.ts"),
            std::slice::from_ref(&common_a),
        );
        linker.add_file(
            "src/common_b.ts",
            admitted_artifact_id("src/common_b.ts"),
            std::slice::from_ref(&common_b),
        );

        // A single unambiguous cross-file call target.
        let target = make_entity("shared_target", "src/target.ts");
        linker.add_file(
            "src/target.ts",
            admitted_artifact_id("src/target.ts"),
            std::slice::from_ref(&target),
        );

        // Two receiver-method implementors sharing a bare leaf `work`, so bare
        // `work` calls fan out through `sorted_fanout_targets` (a canonical sort
        // whose stability the parallel pass must preserve).
        let widget_work = make_entity("Widget::work", "src/impl_foo.ts");
        let gadget_work = make_entity("Gadget::work", "src/impl_bar.ts");
        linker.add_file(
            "src/impl_foo.ts",
            admitted_artifact_id("src/impl_foo.ts"),
            std::slice::from_ref(&widget_work),
        );
        linker.add_file(
            "src/impl_bar.ts",
            admitted_artifact_id("src/impl_bar.ts"),
            std::slice::from_ref(&gadget_work),
        );

        // Many caller files spread the parallel pass across worker threads. Each
        // mixes a same-file call, an unambiguous cross-file call, an ambiguous
        // fan-out call, and a bare receiver-method call.
        for i in 0..48 {
            let path = format!("src/caller{i}.ts");
            let a = make_entity(&format!("a{i}"), &path);
            let b = make_entity(&format!("b{i}"), &path);
            linker.add_file(&path, admitted_artifact_id(&path), &[a.clone(), b.clone()]);
            files.push(FileParseData {
                file_path: path,
                entities: vec![a, b],
                relations: vec![
                    ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: RelationKind::Calls,
                        src_name: format!("a{i}"),
                        dst_name: format!("b{i}"),
                        import_source: None,
                    },
                    ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: RelationKind::Calls,
                        src_name: format!("a{i}"),
                        dst_name: "shared_target".to_string(),
                        import_source: None,
                    },
                    ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: RelationKind::Calls,
                        src_name: format!("b{i}"),
                        dst_name: "common".to_string(),
                        import_source: None,
                    },
                    ExtractedRelation {
                        site: None,
                        receiver: None,
                        call_shape: None,
                        kind: RelationKind::Calls,
                        src_name: format!("b{i}"),
                        dst_name: "work".to_string(),
                        import_source: None,
                    },
                ],
                imports: vec![],
            });
        }

        let parallel = link_cross_file_incremental(&files, &linker);
        let serial = link_cross_file_incremental_serial(&files, &linker);
        assert_eq!(
            format!("{parallel:?}"),
            format!("{serial:?}"),
            "parallel incremental linking must produce byte-identical relations to the serial path"
        );

        // Re-running the parallel path must also be byte-stable.
        let parallel_again = link_cross_file_incremental(&files, &linker);
        assert_eq!(
            format!("{parallel:?}"),
            format!("{parallel_again:?}"),
            "parallel incremental linking must be byte-stable across runs"
        );

        // Guard against a vacuous fixture: every caller resolves at least its
        // same-file, cross-file, disambiguated, and fanned-out edges.
        assert!(
            parallel.len() >= 48 * 4,
            "fixture should resolve real cross-file work, got {}",
            parallel.len()
        );
    }

    #[test]
    fn incremental_receiver_method_call_fans_out_to_all_implementors() {
        // Incremental (c2) parity with `receiver_method_call_fans_out_to_all_implementors`:
        // bare `new` could be `Foo::new` or `Bar::new`; both implementors link,
        // matching the batch resolver's fan-out. (Updated from the old
        // refuse-on-ambiguity contract.)
        let caller = make_entity("build", "src/caller.rs");
        let foo_new = make_entity("Foo::new", "src/foo.rs");
        let bar_new = make_entity("Bar::new", "src/bar.rs");

        let mut linker = IncrementalLinker::new();
        linker.add_file(
            "src/caller.rs",
            admitted_artifact_id("src/caller.rs"),
            std::slice::from_ref(&caller),
        );
        linker.add_file(
            "src/foo.rs",
            admitted_artifact_id("src/foo.rs"),
            std::slice::from_ref(&foo_new),
        );
        linker.add_file(
            "src/bar.rs",
            admitted_artifact_id("src/bar.rs"),
            std::slice::from_ref(&bar_new),
        );

        let files = vec![FileParseData {
            file_path: "src/caller.rs".to_string(),
            entities: vec![caller.clone()],
            relations: vec![ExtractedRelation {
                site: None,
                receiver: None,
                call_shape: None,
                kind: RelationKind::Calls,
                src_name: "build".to_string(),
                dst_name: "new".to_string(),
                import_source: None,
            }],
            imports: vec![],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        let targets: HashSet<GraphNodeId> = result
            .iter()
            .filter(|r| r.kind == RelationKind::Calls && r.src == GraphNodeId::Entity(caller.id))
            .map(|r| r.dst)
            .collect();
        assert_eq!(
            targets.len(),
            2,
            "incremental ambiguous bare-name receiver call must fan out to both implementors, got {targets:?}"
        );
        assert!(targets.contains(&GraphNodeId::Entity(foo_new.id)));
        assert!(targets.contains(&GraphNodeId::Entity(bar_new.id)));
    }

    /// The relation kind for an import site is decided once, by
    /// `resolve_import_target`, and handed to both edge builders.
    ///
    /// This is a unit test rather than an end-to-end one on purpose. The C and
    /// C++ adapters emit no module entity, so an entity-level edge cannot
    /// currently be built for a header include at all, and an integration test
    /// asserting "no Imports kind on a header fixture" passes whether the kind
    /// is shared or hardcoded. It was written that way first and a mutant
    /// survived it. This asserts the decision itself, which is the thing that
    /// would otherwise drift the day those adapters do emit module entities.
    #[test]
    fn import_target_resolution_decides_includes_for_headers_and_imports_otherwise() {
        let known: HashSet<&str> = ["src/helper.h", "app/routing.py", "src/main.c"]
            .into_iter()
            .collect();

        let header = FileImport {
            site: synthetic_import_site(),
            module_path: "helper.h".to_string(),
            specifiers: vec![],
        };
        let (path, kind) = resolve_import_target("src/main.c", &header, &known)
            .expect("a repo-local header resolves");
        assert_eq!(path, "src/helper.h");
        assert_eq!(
            kind,
            RelationKind::Includes,
            "a header specifier must resolve to an Includes kind"
        );

        let module = FileImport {
            site: synthetic_import_site(),
            module_path: "app.routing".to_string(),
            specifiers: vec![],
        };
        let (path, kind) = resolve_import_target("app/main.py", &module, &known)
            .expect("a repo-local python module resolves");
        assert_eq!(path, "app/routing.py");
        assert_eq!(
            kind,
            RelationKind::Imports,
            "a non-header specifier must resolve to an Imports kind"
        );
    }

    /// A specifier resolving back to its own file yields nothing, so the rule is
    /// applied once for both builders rather than twice with a chance to differ.
    #[test]
    fn import_target_resolution_refuses_a_self_import() {
        let known: HashSet<&str> = ["lib/index.js"].into_iter().collect();
        let selfref = FileImport {
            site: synthetic_import_site(),
            module_path: ".".to_string(),
            specifiers: vec![],
        };
        assert!(
            resolve_import_target("lib/index.js", &selfref, &known).is_none(),
            "a module resolving to itself must produce no import target"
        );
    }

    /// The two shapes that prove the unit, with the `FileImport` counts the real
    /// adapter produces for them.
    ///
    /// These assert on the LINKER's own per-file count, before anything reaches
    /// a collector, because the collector cannot distinguish them: both produce
    /// one artifact edge and two entity edges.
    #[test]
    fn import_resolution_counts_statements_not_edges() {
        let known: HashSet<&str> = ["app/main.py", "app/storage.py"].into_iter().collect();

        // `from .storage import Store, open_db`: ONE statement, two specifiers.
        let one_statement = vec![FileImport {
            site: synthetic_import_site(),
            module_path: ".storage".to_string(),
            specifiers: vec![
                ImportedName {
                    local_name: "Store".to_string(),
                    original_name: None,
                    is_default: false,
                },
                ImportedName {
                    local_name: "open_db".to_string(),
                    original_name: None,
                    is_default: false,
                },
            ],
        }];
        assert_eq!(
            import_resolution_counts("app/main.py", &one_statement, &known),
            ImportResolutionCounts {
                statements: 1,
                resolved: 1
            },
            "one statement with two specifiers is one statement, resolved once"
        );

        // The same two names on separate lines: TWO statements.
        let two_statements = vec![
            FileImport {
                site: synthetic_import_site(),
                module_path: ".storage".to_string(),
                specifiers: vec![ImportedName {
                    local_name: "Store".to_string(),
                    original_name: None,
                    is_default: false,
                }],
            },
            FileImport {
                site: synthetic_import_site(),
                module_path: ".storage".to_string(),
                specifiers: vec![ImportedName {
                    local_name: "open_db".to_string(),
                    original_name: None,
                    is_default: false,
                }],
            },
        ];
        assert_eq!(
            import_resolution_counts("app/main.py", &two_statements, &known),
            ImportResolutionCounts {
                statements: 2,
                resolved: 2
            },
            "two statements naming one module are two statements, both resolved"
        );
    }

    /// A statement naming something the repository does not hold counts as a
    /// statement and not as a resolution, which is the external count.
    #[test]
    fn import_resolution_counts_an_unresolved_statement_as_external() {
        let known: HashSet<&str> = ["app/main.py", "app/storage.py"].into_iter().collect();
        let mixed = vec![
            FileImport {
                site: synthetic_import_site(),
                module_path: "re".to_string(),
                specifiers: vec![],
            },
            FileImport {
                site: synthetic_import_site(),
                module_path: ".storage".to_string(),
                specifiers: vec![],
            },
        ];
        let ImportResolutionCounts {
            statements,
            resolved,
        } = import_resolution_counts("app/main.py", &mixed, &known);
        assert_eq!(statements, 2, "both lines are statements");
        assert_eq!(
            resolved, 1,
            "the stdlib module resolves to no file this repository holds"
        );
        assert_eq!(
            statements - resolved,
            1,
            "the unresolved remainder is the external count"
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

    /// `require('../..')` from a nested directory names the repository root.
    /// Joining an index filename onto the empty resolved prefix produced the
    /// absolute-looking `/index.js`, which matches no repo-relative path.
    #[test]
    fn resolve_module_path_repository_root_resolves_to_its_index() {
        let known: HashSet<&str> = ["index.js", "lib/express.js"].into_iter().collect();
        assert_eq!(
            resolve_module_path("examples/auth/index.js", "../..", &known),
            Some("index.js".to_string())
        );
        assert_eq!(
            resolve_module_path("examples/mvc/lib/boot.js", "../../..", &known),
            Some("index.js".to_string())
        );
        assert_eq!(
            resolve_module_path("examples/auth/index.js", "../../", &known),
            Some("index.js".to_string()),
            "the trailing-slash spelling names the same directory"
        );
    }

    /// A repository root that holds no index file resolves to nothing rather
    /// than to whatever else sits at the top level.
    #[test]
    fn resolve_module_path_repository_root_without_an_index_resolves_to_nothing() {
        let known: HashSet<&str> = ["lib/express.js"].into_iter().collect();
        assert_eq!(
            resolve_module_path("examples/auth/index.js", "../..", &known),
            None
        );
    }

    #[test]
    fn resolve_module_path_completes_ecmascript_module_extensions() {
        let known: HashSet<&str> = ["src/deep/mod.mjs", "src/legacy.cjs", "src/pkg/index.mjs"]
            .into_iter()
            .collect();
        assert_eq!(
            resolve_module_path("src/a.js", "./deep/mod", &known),
            Some("src/deep/mod.mjs".to_string())
        );
        assert_eq!(
            resolve_module_path("src/a.js", "./legacy", &known),
            Some("src/legacy.cjs".to_string())
        );
        assert_eq!(
            resolve_module_path("src/a.js", "./pkg", &known),
            Some("src/pkg/index.mjs".to_string())
        );
    }

    /// A NodeNext specifier names the emitted `.js`; the repository holds the
    /// `.ts` it was emitted from.
    #[test]
    fn resolve_module_path_substitutes_the_typescript_source_for_emitted_javascript() {
        let known: HashSet<&str> = ["src/util.ts", "src/view.tsx", "src/esm.mts"]
            .into_iter()
            .collect();
        assert_eq!(
            resolve_module_path("src/a.mjs", "./util.js", &known),
            Some("src/util.ts".to_string())
        );
        assert_eq!(
            resolve_module_path("src/a.mjs", "./view.jsx", &known),
            Some("src/view.tsx".to_string())
        );
        assert_eq!(
            resolve_module_path("src/a.mjs", "./esm.mjs", &known),
            Some("src/esm.mts".to_string())
        );
        assert_eq!(
            resolve_module_path("src/a.mjs", "./missing.js", &known),
            None,
            "the substitution only ever names a file the repository holds"
        );
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
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: RelationKind::Calls,
                    src_name: "handler".to_string(),
                    dst_name: "myWork".to_string(),
                    import_source: None,
                }],
                imports: vec![FileImport {
                    site: synthetic_import_site(),
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
            GraphNodeId::Artifact(admitted_artifact_id("src/api.ts"))
        );
        assert_eq!(
            imports.dst,
            GraphNodeId::Artifact(admitted_artifact_id("src/utils.ts"))
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
                    site: synthetic_import_site(),
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
            GraphNodeId::Artifact(admitted_artifact_id("src/routes/api.ts"))
        );
        assert_eq!(
            result[0].dst,
            GraphNodeId::Artifact(admitted_artifact_id("src/utils/tools.ts"))
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
                    site: synthetic_import_site(),
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
            GraphNodeId::Artifact(admitted_artifact_id("src/main.cpp"))
        );
        assert_eq!(
            result[0].dst,
            GraphNodeId::Artifact(admitted_artifact_id(
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
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: RelationKind::Calls,
                    src_name: "handler".to_string(),
                    dst_name: "executeTool".to_string(),
                    import_source: None,
                }],
                imports: vec![FileImport {
                    site: synthetic_import_site(),
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
                    site: synthetic_import_site(),
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
            GraphNodeId::Artifact(admitted_artifact_id("src/api.ts"))
        );
        assert_eq!(
            result[0].dst,
            GraphNodeId::Artifact(admitted_artifact_id("src/util.ts"))
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
                    site: None,
                    receiver: None,
                    call_shape: None,
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

    fn external_reference_fixture(kind: RelationKind) -> (Entity, Relation) {
        let caller = make_entity("run_task", "src/app.rs");
        let mut result = link_cross_file(&[FileParseData {
            file_path: "src/app.rs".to_string(),
            entities: vec![caller.clone()],
            relations: vec![ExtractedRelation {
                site: None,
                receiver: None,
                call_shape: None,
                kind,
                src_name: "run_task".to_string(),
                dst_name: "InMemoryGraph".to_string(),
                import_source: Some("kin_db".to_string()),
            }],
            imports: vec![],
        }]);
        assert_eq!(result.len(), 1, "one cross-repo reference edge expected");
        (caller, result.pop().unwrap())
    }

    #[test]
    fn external_reference_carries_symbol_and_import_source() {
        // A call to a symbol that lives in another repo: the target is absent
        // from this repo's parse universe, but the parser recorded the module it
        // was imported from. The linker must preserve it as a cross-repo edge
        // carrying the lexical symbol (evidence.token) and the module hint
        // (import_source) — exactly what the spine resolver keys on.
        let (caller, edge) = external_reference_fixture(RelationKind::Calls);
        assert_eq!(edge.kind, RelationKind::Calls);
        assert_eq!(edge.src, GraphNodeId::Entity(caller.id));
        // The destination is an external placeholder, never a local entity.
        assert_ne!(edge.dst, GraphNodeId::Entity(caller.id));
        assert_eq!(edge.import_source.as_deref(), Some("kin_db"));
        assert_eq!(edge.origin, RelationOrigin::Inferred);
        assert!(is_external_import_placeholder(&edge));
        assert!(edge.evidence.iter().any(|evidence| {
            evidence.parser_rule.as_deref() == Some(EXTERNAL_IMPORT_REFERENCE_RULE)
        }));
        let token = edge
            .evidence
            .iter()
            .find_map(|ev| ev.token.as_deref())
            .expect("evidence token present");
        assert_eq!(token, "InMemoryGraph");
    }

    #[test]
    fn external_import_placeholder_contract_rejects_mutations() {
        let (_caller, canonical) = external_reference_fixture(RelationKind::Calls);
        assert!(is_external_import_placeholder(&canonical));
        let rejects = |relation: &Relation, mutation: &str| {
            assert!(
                !is_external_import_placeholder(relation),
                "accepted non-canonical mutation: {mutation}"
            );
        };

        let mut relation = canonical.clone();
        relation.dst = GraphNodeId::Entity(EntityId::new());
        rejects(&relation, "arbitrary destination");

        let mut relation = canonical.clone();
        relation.src = GraphNodeId::Entity(EntityId::new());
        rejects(&relation, "arbitrary source");

        let mut relation = canonical.clone();
        relation.id = RelationId::new();
        rejects(&relation, "arbitrary relation id");

        let mut relation = canonical.clone();
        relation.evidence[0].token = None;
        rejects(&relation, "missing symbol token");

        let mut relation = canonical.clone();
        relation.evidence[0].token = Some("  ".to_string());
        rejects(&relation, "blank symbol token");

        let mut relation = canonical.clone();
        relation.evidence[0].token = Some(" InMemoryGraph".to_string());
        rejects(&relation, "untrimmed symbol token");

        let mut relation = canonical.clone();
        relation.evidence[0].source_path = Some("kin_model".to_string());
        rejects(&relation, "source path mismatch");

        let mut relation = canonical.clone();
        relation.origin = RelationOrigin::Parsed;
        rejects(&relation, "wrong origin");

        let mut relation = canonical.clone();
        relation.confidence = 0.3;
        rejects(&relation, "wrong confidence");

        let mut relation = canonical.clone();
        relation.import_source = Some(" kin_db".to_string());
        rejects(&relation, "untrimmed import source");

        let mut relation = canonical.clone();
        relation.import_source = None;
        rejects(&relation, "missing import source");

        let mut relation = canonical.clone();
        relation.import_source = Some("  ".to_string());
        rejects(&relation, "blank import source");

        let mut relation = canonical.clone();
        relation.evidence[0].source_path = None;
        rejects(&relation, "missing evidence source path");

        let mut relation = canonical.clone();
        relation.evidence[0].parser_rule = Some("call_expression".to_string());
        rejects(&relation, "wrong parser rule");

        let mut relation = canonical.clone();
        relation.kind = RelationKind::Imports;
        rejects(&relation, "wrong relation kind");

        let mut relation = canonical.clone();
        relation.evidence[0].resolved_path = Some("src/lib.rs".to_string());
        rejects(&relation, "resolved local path");

        let mut relation = canonical.clone();
        relation.evidence[0].source_span = Some(SourceSpan {
            file: FilePathId::new("src/app.rs"),
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            start_col: 1,
            end_line: 1,
            end_col: 2,
        });
        rejects(&relation, "unexpected source span");

        let mut relation = canonical.clone();
        relation.evidence[0].call_shape = Some(kin_model::CallArgShape::default());
        rejects(&relation, "unexpected call shape");

        let mut relation = canonical.clone();
        relation.evidence[0].occurrence_count = 0;
        rejects(&relation, "zero evidence occurrences");

        let mut relation = canonical;
        relation.evidence.push(RelationEvidence::default());
        rejects(&relation, "extra evidence record");
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
                site: None,
                receiver: None,
                call_shape: None,
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
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: RelationKind::Calls,
                    src_name: "run_task".to_string(),
                    dst_name: "InMemoryGraph".to_string(),
                    import_source: Some("kin_db".to_string()),
                },
                ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: RelationKind::Calls,
                    src_name: "run_task".to_string(),
                    dst_name: "InMemoryGraph".to_string(),
                    import_source: Some("kin_db".to_string()),
                },
                ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: None,
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
        let repeated = first
            .iter()
            .find(|relation| relation.src == GraphNodeId::Entity(caller.id))
            .unwrap();
        assert_eq!(repeated.evidence.len(), 1);
        assert_eq!(repeated.evidence[0].occurrence_count, 2);
        assert!(is_external_import_placeholder(repeated));

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
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: RelationKind::Calls,
                    src_name: "handler".to_string(),
                    dst_name: "executeTool".to_string(),
                    import_source: Some("../utils/tools".to_string()),
                }],
                imports: vec![FileImport {
                    site: synthetic_import_site(),
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
            site: None,
            receiver: None,
            call_shape: None,
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
    fn qualified_leaf_fans_out_to_all_overloads() {
        // Three distinct free fns named `run` in different files (overloads /
        // amalgamated copies of one symbol). The qualified call's leaf cannot be
        // pinned to one, so it fans out to all three rather than dropping the
        // edge. (Updated from the old refuse-on-ambiguity contract.)
        let caller = rust_fn("caller", "src/caller.rs");
        let run_a = rust_fn("run", "src/a.rs");
        let run_b = rust_fn("run", "src/b.rs");
        let run_c = rust_fn("run", "src/c.rs");

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
            FileParseData {
                file_path: "src/c.rs".to_string(),
                entities: vec![run_c.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        for target in [&run_a, &run_b, &run_c] {
            let edge = find_calls_edge(&result, &caller, target)
                .expect("qualified leaf must fan out to every overload");
            assert_eq!(edge.confidence, QUALIFIED_SUFFIX_CONFIDENCE);
        }
        let count = result
            .iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .count();
        assert_eq!(count, 3, "exactly the three overloads should link");
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
        linker.add_file(
            "src/caller.rs",
            admitted_artifact_id("src/caller.rs"),
            std::slice::from_ref(&caller),
        );
        linker.add_file(
            "src/work.rs",
            admitted_artifact_id("src/work.rs"),
            std::slice::from_ref(&target),
        );

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
        linker.add_file(
            "src/caller.rs",
            admitted_artifact_id("src/caller.rs"),
            std::slice::from_ref(&caller),
        );
        linker.add_file(
            "src/model.rs",
            admitted_artifact_id("src/model.rs"),
            std::slice::from_ref(&method),
        );

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
    fn incremental_qualified_leaf_fans_out_to_all_overloads() {
        // Incremental parity with `qualified_leaf_fans_out_to_all_overloads`:
        // the qualified leaf fans out to all three overloads. (Updated from the
        // old refuse-on-ambiguity contract.)
        let caller = rust_fn("caller", "src/caller.rs");
        let run_a = rust_fn("run", "src/a.rs");
        let run_b = rust_fn("run", "src/b.rs");
        let run_c = rust_fn("run", "src/c.rs");

        let mut linker = IncrementalLinker::new();
        linker.add_file(
            "src/caller.rs",
            admitted_artifact_id("src/caller.rs"),
            std::slice::from_ref(&caller),
        );
        linker.add_file(
            "src/a.rs",
            admitted_artifact_id("src/a.rs"),
            std::slice::from_ref(&run_a),
        );
        linker.add_file(
            "src/b.rs",
            admitted_artifact_id("src/b.rs"),
            std::slice::from_ref(&run_b),
        );
        linker.add_file(
            "src/c.rs",
            admitted_artifact_id("src/c.rs"),
            std::slice::from_ref(&run_c),
        );

        let files = vec![FileParseData {
            file_path: "src/caller.rs".to_string(),
            entities: vec![caller.clone()],
            relations: vec![calls_relation("caller", "crate::somewhere::run")],
            imports: vec![],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        for target in [&run_a, &run_b, &run_c] {
            assert!(
                find_calls_edge(&result, &caller, target).is_some(),
                "incremental qualified leaf must fan out to every overload"
            );
        }
        let count = result
            .iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .count();
        assert_eq!(count, 3, "exactly the three overloads should link");
    }

    #[test]
    fn qualified_leaf_fanout_respects_cap() {
        // A qualified call whose leaf `run` has `n` distinct cross-file targets:
        // at the cap every target links; one beyond the cap it stays unresolved.
        let calls_for = |n: usize| -> usize {
            let caller = rust_fn("caller", "src/caller.rs");
            let mut files = vec![FileParseData {
                file_path: "src/caller.rs".to_string(),
                entities: vec![caller],
                relations: vec![calls_relation("caller", "crate::somewhere::run")],
                imports: vec![],
            }];
            for i in 0..n {
                let path = format!("src/t{i}.rs");
                files.push(FileParseData {
                    file_path: path.clone(),
                    entities: vec![rust_fn("run", &path)],
                    relations: vec![],
                    imports: vec![],
                });
            }
            link_cross_file(&files)
                .iter()
                .filter(|r| r.kind == RelationKind::Calls)
                .count()
        };

        assert_eq!(
            calls_for(AMBIGUOUS_CALL_FANOUT_CAP),
            AMBIGUOUS_CALL_FANOUT_CAP,
            "at the cap every distinct target links"
        );
        assert_eq!(
            calls_for(AMBIGUOUS_CALL_FANOUT_CAP + 1),
            0,
            "above the cap the qualified leaf stays unresolved"
        );
    }

    #[test]
    fn receiver_method_fanout_respects_cap() {
        // A bare receiver-method call `make` with `n` distinct implementor
        // methods: at the cap every implementor links; beyond it, none do.
        let calls_for = |n: usize| -> usize {
            let caller = make_entity("build", "src/caller.rs");
            let mut files = vec![FileParseData {
                file_path: "src/caller.rs".to_string(),
                entities: vec![caller],
                relations: vec![calls_relation("build", "make")],
                imports: vec![],
            }];
            for i in 0..n {
                let path = format!("src/impl{i}.rs");
                files.push(FileParseData {
                    file_path: path.clone(),
                    entities: vec![make_entity(&format!("Impl{i}::make"), &path)],
                    relations: vec![],
                    imports: vec![],
                });
            }
            link_cross_file(&files)
                .iter()
                .filter(|r| r.kind == RelationKind::Calls)
                .count()
        };

        assert_eq!(
            calls_for(AMBIGUOUS_CALL_FANOUT_CAP),
            AMBIGUOUS_CALL_FANOUT_CAP,
            "at the cap every implementor links"
        );
        assert_eq!(
            calls_for(AMBIGUOUS_CALL_FANOUT_CAP + 1),
            0,
            "above the cap the receiver-method call stays unresolved"
        );
    }

    #[test]
    fn same_file_prototype_and_cross_file_definition_both_link() {
        // The caller's own file declares a prototype `compute`; the definition
        // lives in another file. (a) links the same-file prototype at full
        // confidence and (D) also fans out to the cross-file definition, so the
        // real definition is not dropped onto the local stub.
        let caller = rust_fn("run_caller", "src/caller.rs");
        let prototype = rust_fn("compute", "src/caller.rs");
        let definition = rust_fn("compute", "src/impl.rs");

        let files = vec![
            FileParseData {
                file_path: "src/caller.rs".to_string(),
                entities: vec![caller.clone(), prototype.clone()],
                relations: vec![calls_relation("run_caller", "compute")],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/impl.rs".to_string(),
                entities: vec![definition.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let same_file = find_calls_edge(&result, &caller, &prototype)
            .expect("same-file prototype must still link");
        assert_eq!(same_file.confidence, 1.0);
        let cross_file = find_calls_edge(&result, &caller, &definition)
            .expect("cross-file definition must also link");
        assert_eq!(cross_file.confidence, 0.7);
    }

    #[test]
    fn incremental_same_file_prototype_and_cross_file_definition_both_link() {
        // Incremental parity with
        // `same_file_prototype_and_cross_file_definition_both_link`.
        let caller = rust_fn("run_caller", "src/caller.rs");
        let prototype = rust_fn("compute", "src/caller.rs");
        let definition = rust_fn("compute", "src/impl.rs");

        let mut linker = IncrementalLinker::new();
        linker.add_file(
            "src/caller.rs",
            admitted_artifact_id("src/caller.rs"),
            &[caller.clone(), prototype.clone()],
        );
        linker.add_file(
            "src/impl.rs",
            admitted_artifact_id("src/impl.rs"),
            std::slice::from_ref(&definition),
        );

        let files = vec![FileParseData {
            file_path: "src/caller.rs".to_string(),
            entities: vec![caller.clone(), prototype.clone()],
            relations: vec![calls_relation("run_caller", "compute")],
            imports: vec![],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        let same_file = find_calls_edge(&result, &caller, &prototype)
            .expect("same-file prototype must still link");
        assert_eq!(same_file.confidence, 1.0);
        let cross_file = find_calls_edge(&result, &caller, &definition)
            .expect("cross-file definition must also link");
        assert_eq!(cross_file.confidence, 0.7);
    }

    #[test]
    fn fanout_relation_order_is_deterministic() {
        // The qualified-leaf fan-out orders targets by EntityId, so repeated runs
        // and a reordered universe both yield identically ordered edges — no
        // HashSet iteration order leaks into the output.
        let caller = rust_fn("caller", "src/caller.rs");
        let run_a = rust_fn("run", "src/a.rs");
        let run_b = rust_fn("run", "src/b.rs");
        let run_c = rust_fn("run", "src/c.rs");

        let make_files = || {
            vec![
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
                FileParseData {
                    file_path: "src/c.rs".to_string(),
                    entities: vec![run_c.clone()],
                    relations: vec![],
                    imports: vec![],
                },
            ]
        };

        let calls_order = |result: &[Relation]| -> Vec<GraphNodeId> {
            result
                .iter()
                .filter(|r| r.kind == RelationKind::Calls)
                .map(|r| r.dst)
                .collect()
        };

        let files = make_files();
        let first = link_cross_file(&files);
        let second = link_cross_file(&files);
        assert_eq!(
            calls_order(&first),
            calls_order(&second),
            "repeated runs must emit fan-out edges in the same order"
        );
        assert_eq!(calls_order(&first).len(), 3, "expected the full fan-out");

        // Same entities, universe presented in reversed order: the EntityId sort
        // makes the emitted order independent of input order.
        let universe = vec![caller.clone(), run_a.clone(), run_b.clone(), run_c.clone()];
        let mut reversed_universe = universe.clone();
        reversed_universe.reverse();
        let forward = link_cross_file_against_entities(&files, &universe);
        let backward = link_cross_file_against_entities(&files, &reversed_universe);
        assert_eq!(
            calls_order(&forward),
            calls_order(&backward),
            "fan-out order must not depend on universe entity order"
        );
    }

    #[test]
    fn borrowed_and_owned_linker_inputs_resolve_identically() {
        // Replaying history links from borrowed parsed files so it does not copy
        // every entity, relation, and import in the repository once per commit.
        // That is only sound if presenting the same files by reference resolves
        // to exactly what presenting them by value did.
        let caller = rust_fn("caller", "src/caller.rs");
        let target = rust_fn("run", "src/target.rs");
        let files = vec![
            FileParseData {
                file_path: "src/caller.rs".to_string(),
                entities: vec![caller.clone()],
                relations: vec![calls_relation("caller", "run")],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/target.rs".to_string(),
                entities: vec![target.clone()],
                relations: vec![],
                imports: vec![],
            },
        ];
        let universe = vec![caller, target];
        let artifact_ids = artifact_ids_for(&files, &universe);
        let completeness = FileParseCompletenessMap::new();

        let render = |relations: &[Relation]| {
            let mut rendered: Vec<String> =
                relations.iter().map(|rel| format!("{rel:?}")).collect();
            rendered.sort();
            rendered
        };

        let owned =
            super::link_cross_file_with_completeness(&files, &artifact_ids, &completeness).unwrap();
        let borrowed_input: Vec<&FileParseData> = files.iter().collect();
        let borrowed = super::link_cross_file_borrowed_with_completeness(
            &borrowed_input,
            &artifact_ids,
            &completeness,
        )
        .unwrap();

        assert!(
            !owned.is_empty(),
            "fixture must resolve at least one relation or the comparison proves nothing"
        );
        assert_eq!(render(&owned), render(&borrowed));

        // The equality above must be able to fail. Linking only the caller drops
        // the file that defines its callee, so a comparison that still matched
        // here would be comparing nothing.
        let caller_only: Vec<&FileParseData> = files.iter().take(1).collect();
        let reduced = super::link_cross_file_borrowed_with_completeness(
            &caller_only,
            &artifact_ids,
            &completeness,
        )
        .unwrap();
        assert_ne!(
            render(&owned),
            render(&reduced),
            "the borrowed path must react to its input, not return a constant"
        );
    }

    #[test]
    fn batch_and_incremental_fanout_are_identical() {
        // Each fan-out scenario must resolve to the same Calls edge set in the
        // batch and incremental linkers. Compares sorted debug renderings so the
        // check needs no `Ord` on graph ids.
        let scenarios: Vec<Vec<FileParseData>> = vec![
            // Qualified-leaf fan-out (three overloads).
            vec![
                FileParseData {
                    file_path: "src/caller.rs".to_string(),
                    entities: vec![rust_fn("caller", "src/caller.rs")],
                    relations: vec![calls_relation("caller", "crate::somewhere::run")],
                    imports: vec![],
                },
                FileParseData {
                    file_path: "src/a.rs".to_string(),
                    entities: vec![rust_fn("run", "src/a.rs")],
                    relations: vec![],
                    imports: vec![],
                },
                FileParseData {
                    file_path: "src/b.rs".to_string(),
                    entities: vec![rust_fn("run", "src/b.rs")],
                    relations: vec![],
                    imports: vec![],
                },
                FileParseData {
                    file_path: "src/c.rs".to_string(),
                    entities: vec![rust_fn("run", "src/c.rs")],
                    relations: vec![],
                    imports: vec![],
                },
            ],
            // Receiver-method fan-out (two implementors).
            vec![
                FileParseData {
                    file_path: "src/caller.rs".to_string(),
                    entities: vec![make_entity("build", "src/caller.rs")],
                    relations: vec![calls_relation("build", "new")],
                    imports: vec![],
                },
                FileParseData {
                    file_path: "src/foo.rs".to_string(),
                    entities: vec![make_entity("Foo::new", "src/foo.rs")],
                    relations: vec![],
                    imports: vec![],
                },
                FileParseData {
                    file_path: "src/bar.rs".to_string(),
                    entities: vec![make_entity("Bar::new", "src/bar.rs")],
                    relations: vec![],
                    imports: vec![],
                },
            ],
            // Same-file prototype + cross-file definition.
            vec![
                FileParseData {
                    file_path: "src/caller.rs".to_string(),
                    entities: vec![
                        rust_fn("run_caller", "src/caller.rs"),
                        rust_fn("compute", "src/caller.rs"),
                    ],
                    relations: vec![calls_relation("run_caller", "compute")],
                    imports: vec![],
                },
                FileParseData {
                    file_path: "src/impl.rs".to_string(),
                    entities: vec![rust_fn("compute", "src/impl.rs")],
                    relations: vec![],
                    imports: vec![],
                },
            ],
        ];

        let calls_set = |rels: &[Relation]| -> Vec<String> {
            let mut v: Vec<String> = rels
                .iter()
                .filter(|r| r.kind == RelationKind::Calls)
                .map(|r| format!("{:?}->{:?}@{}", r.src, r.dst, r.confidence))
                .collect();
            v.sort();
            v
        };

        for files in scenarios {
            let batch = calls_set(&link_cross_file(&files));

            let mut linker = IncrementalLinker::new();
            for file in &files {
                linker.add_file(
                    &file.file_path,
                    admitted_artifact_id(&file.file_path),
                    &file.entities,
                );
            }
            let incremental = calls_set(&link_cross_file_incremental(&files, &linker));

            assert!(
                batch.len() >= 2,
                "scenario should fan out to multiple targets, got {batch:?}"
            );
            assert_eq!(
                batch, incremental,
                "batch and incremental must resolve identical Calls edges"
            );
        }
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
            site: None,
            receiver: None,
            call_shape: None,
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

    /// An ambiguous bucket with no import pin and no locality signal names no
    /// reachable definition. Binding the first bucket entry would attribute
    /// every signal-less caller of a common name to one arbitrary target, so
    /// the call is left unlinked and the gap is logged.
    #[test]
    fn ambiguous_bucket_without_signal_stays_unlinked() {
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
        assert!(find_calls_edge(&result, &caller, &first).is_none());
        assert!(find_calls_edge(&result, &caller, &second).is_none());
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
            admitted_artifact_id("pkg/cmd/project/create/create.go"),
            std::slice::from_ref(&decoy),
        );
        linker.add_file(
            "pkg/cmd/pr/create/create.go",
            admitted_artifact_id("pkg/cmd/pr/create/create.go"),
            std::slice::from_ref(&target),
        );
        linker.add_file(
            "pkg/cmd/pr/pr.go",
            admitted_artifact_id("pkg/cmd/pr/pr.go"),
            std::slice::from_ref(&caller),
        );

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
        linker.add_file(
            "pkg/cmd/label/create.go",
            admitted_artifact_id("pkg/cmd/label/create.go"),
            std::slice::from_ref(&decoy),
        );
        linker.add_file(
            "pkg/cmd/pr/create/create.go",
            admitted_artifact_id("pkg/cmd/pr/create/create.go"),
            std::slice::from_ref(&target),
        );
        linker.add_file(
            "pkg/cmd/pr/create/create_test.go",
            admitted_artifact_id("pkg/cmd/pr/create/create_test.go"),
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
            site: synthetic_import_site(),
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
    /// closure signal. Neither header is reachable from the call site, so the
    /// call stays unlinked instead of binding the first bucket entry.
    #[test]
    fn cpp_closure_ambiguity_without_signal_stays_unlinked() {
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
        assert!(find_calls_edge(&result, &caller, &first).is_none());
        assert!(find_calls_edge(&result, &caller, &second).is_none());
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
            admitted_artifact_id("single_include/catch2/catch.hpp"),
            std::slice::from_ref(&bundled),
        );
        linker.add_file(
            "include/internal/catch_tostring.h",
            admitted_artifact_id("include/internal/catch_tostring.h"),
            std::slice::from_ref(&target),
        );
        linker.add_file(
            "include/catch.hpp",
            admitted_artifact_id("include/catch.hpp"),
            &[],
        );
        linker.add_file(
            "projects/SelfTest/ToStringTests.cpp",
            admitted_artifact_id("projects/SelfTest/ToStringTests.cpp"),
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
            admitted_artifact_id("single_include/catch2/catch.hpp"),
            &[bundled.clone(), bundled_extra_a, bundled_extra_b],
        );
        linker.add_file(
            "include/internal/catch_session.h",
            admitted_artifact_id("include/internal/catch_session.h"),
            std::slice::from_ref(&target),
        );
        linker.add_file(
            "projects/SelfTest/MainTests.cpp",
            admitted_artifact_id("projects/SelfTest/MainTests.cpp"),
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
            admitted_artifact_id("single_include/catch2/catch.hpp"),
            std::slice::from_ref(&bundled),
        );
        linker.add_file(
            "include/internal/catch_tostring.h",
            admitted_artifact_id("include/internal/catch_tostring.h"),
            std::slice::from_ref(&target),
        );
        linker.add_file(
            "include/catch.hpp",
            admitted_artifact_id("include/catch.hpp"),
            &[],
        );
        linker.add_file(
            "projects/SelfTest/ToStringTests.cpp",
            admitted_artifact_id("projects/SelfTest/ToStringTests.cpp"),
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
        assert!(
            find_calls_edge(&after, &caller, &bundled).is_none(),
            "losing the closure signal drops the edge rather than guessing a target"
        );
        assert!(find_calls_edge(&after, &caller, &target).is_none());
    }

    /// The closure walk is depth-bounded: a definition past the bound carries
    /// no signal, so the call stays unlinked instead of an unbounded scan.
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
        assert!(
            find_calls_edge(&result, &caller, &decoy).is_none(),
            "a definition past the closure bound carries no signal, so no target is guessed"
        );
        assert!(find_calls_edge(&result, &caller, &deep).is_none());
    }

    /// Regression for same-name consumer concentration. Five Go packages each
    /// define `NewCmdCreate` and each package's own command constructor calls
    /// it without a resolvable import pin. Binding the first bucket entry
    /// attributed all five callers to one arbitrary package, minting four
    /// consumers that package never had; the name alone proves nothing, so
    /// none of the five is linked.
    #[test]
    fn signal_less_same_name_callers_do_not_concentrate_on_one_target() {
        let pkgs = ["pr", "gist", "issue", "label", "release"];
        let targets: Vec<Entity> = pkgs
            .iter()
            .map(|pkg| go_fn("NewCmdCreate", &format!("pkg/cmd/{pkg}/create/create.go")))
            .collect();
        let callers: Vec<Entity> = pkgs
            .iter()
            .map(|pkg| go_fn(&format!("NewCmd{pkg}"), &format!("pkg/cmd/{pkg}/{pkg}.go")))
            .collect();

        let mut files = Vec::new();
        for (idx, pkg) in pkgs.iter().enumerate() {
            files.push(FileParseData {
                file_path: format!("pkg/cmd/{pkg}/create/create.go"),
                entities: vec![targets[idx].clone()],
                relations: vec![],
                imports: vec![],
            });
            files.push(FileParseData {
                file_path: format!("pkg/cmd/{pkg}/{pkg}.go"),
                entities: vec![callers[idx].clone()],
                relations: vec![calls_relation(&format!("NewCmd{pkg}"), "NewCmdCreate")],
                imports: vec![],
            });
        }

        let result = link_cross_file(&files);
        for target in &targets {
            let inbound = result
                .iter()
                .filter(|rel| {
                    rel.kind == RelationKind::Calls && rel.dst == GraphNodeId::Entity(target.id)
                })
                .count();
            assert_eq!(
                inbound, 0,
                "no target may absorb the signal-less callers of a shared name"
            );
        }
    }

    /// The same shape resolved: each caller imports its own package, so every
    /// call binds to its own definition and no package gains a foreign caller.
    #[test]
    fn import_pinned_same_name_callers_bind_to_their_own_package() {
        let pkgs = ["pr", "gist", "issue"];
        let targets: Vec<Entity> = pkgs
            .iter()
            .map(|pkg| go_fn("NewCmdCreate", &format!("pkg/cmd/{pkg}/create/create.go")))
            .collect();
        let callers: Vec<Entity> = pkgs
            .iter()
            .map(|pkg| go_fn(&format!("NewCmd{pkg}"), &format!("pkg/cmd/{pkg}/{pkg}.go")))
            .collect();

        let mut files = Vec::new();
        for (idx, pkg) in pkgs.iter().enumerate() {
            files.push(FileParseData {
                file_path: format!("pkg/cmd/{pkg}/create/create.go"),
                entities: vec![targets[idx].clone()],
                relations: vec![],
                imports: vec![],
            });
            files.push(FileParseData {
                file_path: format!("pkg/cmd/{pkg}/{pkg}.go"),
                entities: vec![callers[idx].clone()],
                relations: vec![pinned_calls_relation(
                    &format!("NewCmd{pkg}"),
                    "NewCmdCreate",
                    &format!("github.com/cli/cli/v2/pkg/cmd/{pkg}/create"),
                )],
                imports: vec![],
            });
        }

        let result = link_cross_file(&files);
        for (idx, target) in targets.iter().enumerate() {
            let edge = find_calls_edge(&result, &callers[idx], target)
                .expect("a pinned call binds to its own package's definition");
            assert_eq!(edge.confidence, IMPORT_PINNED_CONFIDENCE);
            let inbound = result
                .iter()
                .filter(|rel| {
                    rel.kind == RelationKind::Calls && rel.dst == GraphNodeId::Entity(target.id)
                })
                .count();
            assert_eq!(inbound, 1, "a pinned target gains no foreign caller");
        }
    }

    // ── FIR-2360: call-edge precision ───────────────────────────────────────
    //
    // Every fixture below is drawn from a false edge confirmed against psf/requests
    // on a `kin init` conversion: a call edge resolved by method name with the
    // receiver's type discarded. Each test states which of the three resolution
    // rules it guards so a revert makes exactly one of them fail.

    fn py_entity(name: &str, file_path: &str, kind: EntityKind, role: EntityRole) -> Entity {
        let mut entity = make_entity(name, file_path);
        entity.language = LanguageId::Python;
        entity.kind = kind;
        entity.role = role;
        entity
    }

    fn py_method(name: &str, file_path: &str, role: EntityRole) -> Entity {
        py_entity(name, file_path, EntityKind::Method, role)
    }

    fn py_function(name: &str, file_path: &str, role: EntityRole) -> Entity {
        py_entity(name, file_path, EntityKind::Function, role)
    }

    fn py_receiver_call(src: &str, receiver: &str, method: &str) -> ExtractedRelation {
        ExtractedRelation {
            site: None,
            receiver: Some(receiver.to_string()),
            call_shape: None,
            kind: RelationKind::Calls,
            src_name: src.to_string(),
            dst_name: method.to_string(),
            import_source: None,
        }
    }

    fn import_of(module_path: &str, local_name: &str) -> FileImport {
        FileImport {
            site: synthetic_import_site(),
            module_path: module_path.to_string(),
            specifiers: vec![kin_parser::ImportedName {
                local_name: local_name.to_string(),
                original_name: None,
                is_default: false,
            }],
        }
    }

    // ── An unresolvable member call names no node ─────────────────────────
    //
    // The tier that used to answer here minted a destination entity out of the
    // receiver's own spelling, so `sig_str.join` and `"a.rs".into` became
    // `Module` entities carrying no file. Half of every repository's entity
    // count was that class. `kin-model`'s external-reference module states the
    // rule it broke: parser spelling stays relation evidence until a resolver
    // can bind it, and only a resolver-issued coordinate earns a persisted
    // identity. A receiver this repository cannot resolve has no coordinate, so
    // it gets no node, and with no node it can carry no edge.

    #[test]
    fn a_member_call_this_repository_cannot_resolve_names_no_node() {
        let caller = py_method("app.handle", "lib/application.js", EntityRole::Source);
        let files = vec![FileParseData {
            file_path: "lib/application.js".to_string(),
            entities: vec![caller.clone()],
            relations: vec![py_receiver_call("app.handle", "this.router", "handle")],
            imports: vec![],
        }];

        let result = link_cross_file(&files);

        assert!(
            calls_edges_from(&result, &caller).is_empty(),
            "a receiver nothing here resolves must produce no edge, because the only \
             destination available is the receiver's own spelling: {result:#?}"
        );
    }

    /// The other half of the same claim, and the one that fails if the removal
    /// went too far: a call whose destination this repository really does
    /// define still resolves, to that definition.
    ///
    /// This is the control the entity fix is worth nothing without. Removing
    /// the tier that answered when nothing was found must not touch a call that
    /// had a real answer, so this asserts the edge exists AND that its
    /// destination is the local definition, rather than merely that some edge
    /// appeared.
    #[test]
    fn a_call_this_repository_defines_still_resolves_to_that_definition() {
        let caller = py_method("app.handle", "lib/application.js", EntityRole::Source);
        let local = py_method("route", "lib/router.js", EntityRole::Source);
        let local_id = local.id;
        let files = vec![
            FileParseData {
                file_path: "lib/router.js".to_string(),
                entities: vec![local],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "lib/application.js".to_string(),
                entities: vec![caller.clone()],
                relations: vec![ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: RelationKind::Calls,
                    src_name: "app.handle".to_string(),
                    dst_name: "route".to_string(),
                    import_source: None,
                }],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);

        assert_eq!(
            calls_edges_from(&result, &caller)
                .iter()
                .map(|edge| edge.dst)
                .collect::<Vec<_>>(),
            vec![GraphNodeId::Entity(local_id)],
            "the call must reach the definition this repository holds, and reach \
             nothing beside it: {result:#?}"
        );
    }

    /// The negative control: a function that writes no call gains no edge.
    /// Presence has to come from the source, not from a tier existing.
    ///
    /// It shares its assertion with the unresolvable case above and is not
    /// redundant with it, because the two separate under the mutation that
    /// matters: restoring the placeholder tier turns that one red and leaves
    /// this one green, since there is no call here for a tier to answer.
    #[test]
    fn a_function_that_makes_no_call_gains_no_edge() {
        let caller = py_method("app.listen", "lib/application.js", EntityRole::Source);
        let files = vec![FileParseData {
            file_path: "lib/application.js".to_string(),
            entities: vec![caller.clone()],
            relations: vec![],
            imports: vec![],
        }];

        let result = link_cross_file(&files);

        assert!(
            calls_edges_from(&result, &caller).is_empty(),
            "no call was written, so no step may appear: {result:#?}"
        );
    }

    fn calls_edges_from<'a>(result: &'a [Relation], src: &Entity) -> Vec<&'a Relation> {
        result
            .iter()
            .filter(|rel| rel.kind == RelationKind::Calls && rel.src == GraphNodeId::Entity(src.id))
            .collect()
    }

    /// Rule 1: the marker a response publishes must be the one the tier that
    /// emitted the edge actually proved. The tiers stamp bare confidence
    /// literals, so without this the ladder and the linker drift apart silently
    /// and every downstream filter inherits the drift.
    #[test]
    fn each_resolution_tier_confidence_classifies_as_the_ladder_declares() {
        let declared: HashMap<u32, RelationResolution> = RESOLUTION_TIER_LADDER
            .iter()
            .map(|&(confidence, resolution)| (confidence.to_bits(), resolution))
            .collect();
        for (confidence, expected, tier) in [
            (1.0_f32, RelationResolution::TypeResolved, "same-file"),
            (0.95, RelationResolution::TypeResolved, "import-declared"),
            (
                RECEIVER_TYPE_CONFIDENCE,
                RelationResolution::TypeResolved,
                "declared receiver type",
            ),
            (
                INHERITED_METHOD_CONFIDENCE,
                RelationResolution::TypeResolved,
                "inherited dispatch",
            ),
            (
                IMPORT_PINNED_CONFIDENCE,
                RelationResolution::ImportScoped,
                "parser-pinned module",
            ),
            (
                RECEIVER_MODULE_CONFIDENCE,
                RelationResolution::ImportScoped,
                "receiver module",
            ),
            (
                LOCALITY_DISAMBIGUATED_CONFIDENCE,
                RelationResolution::ImportScoped,
                "locality",
            ),
            (0.7, RelationResolution::NameOnly, "exact name"),
            (
                QUALIFIED_SUFFIX_CONFIDENCE,
                RelationResolution::NameOnly,
                "qualified suffix",
            ),
            (0.3, RelationResolution::NameOnly, "bare-name fan-out"),
            (
                EXTERNAL_REFERENCE_CONFIDENCE,
                RelationResolution::NameOnly,
                "cross-repo placeholder",
            ),
        ] {
            assert_eq!(
                declared.get(&confidence.to_bits()).copied(),
                Some(expected),
                "the {tier} tier emits {confidence} but the ladder does not declare it that way"
            );
        }
    }

    /// Rule 2, narrowest resolution wins. `Store` and `Cache` both define
    /// `save`; the calling file imports only `Store`, so the receiver's binding
    /// names the target module and the call resolves to exactly one edge rather
    /// than fanning out to both.
    #[test]
    fn an_imported_receiver_resolves_to_one_edge_not_a_same_name_fanout() {
        let store_save = py_method("Store.save", "pkg/store.py", EntityRole::Source);
        let cache_save = py_method("Cache.save", "pkg/cache.py", EntityRole::Source);
        let caller = py_function("run", "pkg/app.py", EntityRole::Source);

        let files = vec![
            FileParseData {
                file_path: "pkg/store.py".to_string(),
                entities: vec![store_save.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "pkg/cache.py".to_string(),
                entities: vec![cache_save.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "pkg/app.py".to_string(),
                entities: vec![caller.clone()],
                relations: vec![py_receiver_call("run", "Store", "save")],
                // Python's own relative spelling. One leading dot names a
                // sibling module inside the importer's package, which the
                // module resolver binds to `pkg/store.py`.
                imports: vec![import_of(".store", "Store")],
            },
        ];

        let result = link_cross_file(&files);
        let edges = calls_edges_from(&result, &caller);
        assert_eq!(
            edges.len(),
            1,
            "an imported receiver names one module, so one edge is emitted"
        );
        assert_eq!(edges[0].dst, GraphNodeId::Entity(store_save.id));
        assert_eq!(edges[0].confidence, RECEIVER_MODULE_CONFIDENCE);
        assert_eq!(
            RelationResolution::of(edges[0]),
            RelationResolution::ImportScoped
        );
    }

    /// Rule 3, role tiebreak. A test double shadowing a production method name
    /// must not become a callee of production code while the production
    /// definition exists.
    #[test]
    fn a_test_double_shadowing_a_production_name_gains_no_production_caller() {
        let real_save = py_method("Store.save", "src/store.py", EntityRole::Source);
        let fake_save = py_method("FakeStore.save", "tests/test_store.py", EntityRole::Test);
        let caller = py_method("Service.persist", "src/service.py", EntityRole::Source);

        let files = vec![
            FileParseData {
                file_path: "src/store.py".to_string(),
                entities: vec![real_save.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "tests/test_store.py".to_string(),
                entities: vec![fake_save.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/service.py".to_string(),
                entities: vec![caller.clone()],
                relations: vec![py_receiver_call("Service.persist", "store", "save")],
                // The import the real shape carries: a file calling
                // `store.save(...)` is a file that named `Store`. Without it the
                // receiver has no owner this file reaches and FIR-1552 leaves
                // the call unresolved before role can tie-break anything.
                imports: vec![import_of(".store", "Store")],
            },
        ];

        let result = link_cross_file(&files);
        let edges = calls_edges_from(&result, &caller);
        assert_eq!(edges.len(), 1, "the test double is not a dispatch target");
        assert_eq!(edges[0].dst, GraphNodeId::Entity(real_save.id));
        assert!(
            !result.iter().any(|rel| rel.kind == RelationKind::Calls
                && rel.dst == GraphNodeId::Entity(fake_save.id)),
            "no production caller reaches the test double"
        );
    }

    /// The `adapter.send` shape from psf/requests: `RedirectSession` in the test
    /// tree subclasses a redirect mixin and can never be the receiver at
    /// `adapter.send(request, **kwargs)` in `sessions.py`, yet a bare-name
    /// fan-out reached it. Resolves to the adapter alone.
    #[test]
    fn the_requests_adapter_send_shape_resolves_to_the_adapter_only() {
        let adapter_send = py_method(
            "HTTPAdapter.send",
            "src/requests/adapters.py",
            EntityRole::Source,
        );
        let mixin_send = py_method(
            "SessionRedirectMixin.send",
            "src/requests/sessions.py",
            EntityRole::Source,
        );
        let double_send = py_method(
            "RedirectSession.send",
            "tests/test_requests.py",
            EntityRole::Test,
        );
        let session_send = py_method(
            "Session.send",
            "src/requests/sessions.py",
            EntityRole::Source,
        );

        let files = vec![
            FileParseData {
                file_path: "src/requests/adapters.py".to_string(),
                entities: vec![adapter_send.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/requests/sessions.py".to_string(),
                entities: vec![session_send.clone(), mixin_send.clone()],
                relations: vec![py_receiver_call("Session.send", "adapter", "send")],
                // `from .adapters import HTTPAdapter`, which the real
                // `sessions.py` carries at its head. It is what makes the
                // adapter an owner this file names, and under FIR-1552 that
                // binding is the whole reason the call has a destination.
                imports: vec![import_of(".adapters", "HTTPAdapter")],
            },
            FileParseData {
                file_path: "tests/test_requests.py".to_string(),
                entities: vec![double_send.clone()],
                // The double subclasses the mixin, not the adapter.
                relations: vec![ExtractedRelation {
                    site: None,
                    receiver: None,
                    call_shape: None,
                    kind: RelationKind::Extends,
                    src_name: "RedirectSession".to_string(),
                    dst_name: "SessionRedirectMixin".to_string(),
                    import_source: None,
                }],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        let edges = calls_edges_from(&result, &session_send);
        assert_eq!(
            edges.len(),
            1,
            "adapter.send reaches the adapter, not every send in the repo"
        );
        assert_eq!(edges[0].dst, GraphNodeId::Entity(adapter_send.id));
    }

    /// FIR-1552. Rule 2's other half used to emit every candidate and mark them
    /// `name_only`, on the reasoning that a marked guess costs nothing. It cost
    /// the headline: `find_references(HTTPAdapter.send)` on psf/requests
    /// answered 33 where `git grep` finds two call sites, and all 33 rows were
    /// `name_only`, so the per-row marker could not separate the two true ones
    /// from the 31 invented ones. `req.copy()` in `sessions.py` is the same
    /// shape: three same-named methods on unrelated types, and nothing in the
    /// file names any of them.
    #[test]
    fn a_receiver_the_file_names_no_owner_for_binds_nothing() {
        let prepared_copy = py_method(
            "PreparedRequest.copy",
            "src/requests/models.py",
            EntityRole::Source,
        );
        let jar_copy = py_method(
            "RequestsCookieJar.copy",
            "src/requests/cookies.py",
            EntityRole::Source,
        );
        let dict_copy = py_method(
            "CaseInsensitiveDict.copy",
            "src/requests/structures.py",
            EntityRole::Source,
        );
        let caller = py_method(
            "Session.prepare_request",
            "src/requests/sessions.py",
            EntityRole::Source,
        );

        let files = vec![
            FileParseData {
                file_path: "src/requests/models.py".to_string(),
                entities: vec![prepared_copy.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/requests/cookies.py".to_string(),
                entities: vec![jar_copy.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/requests/structures.py".to_string(),
                entities: vec![dict_copy.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/requests/sessions.py".to_string(),
                entities: vec![caller.clone()],
                relations: vec![py_receiver_call("Session.prepare_request", "req", "copy")],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert!(
            calls_edges_from(&result, &caller).is_empty(),
            "a receiver whose type the file names no candidate owner for has no \
             destination, and three guesses are not one answer: {result:#?}"
        );
    }

    /// The other half of the same rule. Naming one owner is a destination;
    /// naming two is a choice, and nothing at `req.copy()` makes it. This is the
    /// case the fan-out cap used to admit, which is how one call site became
    /// eight inbound edges.
    #[test]
    fn a_receiver_matching_two_named_owners_binds_neither() {
        let store_save = py_method("Store.save", "pkg/store.py", EntityRole::Source);
        let cache_save = py_method("Cache.save", "pkg/cache.py", EntityRole::Source);
        let caller = py_function("run", "pkg/app.py", EntityRole::Source);

        let files = vec![
            FileParseData {
                file_path: "pkg/store.py".to_string(),
                entities: vec![store_save.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "pkg/cache.py".to_string(),
                entities: vec![cache_save.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "pkg/app.py".to_string(),
                entities: vec![caller.clone()],
                relations: vec![py_receiver_call("run", "target", "save")],
                imports: vec![import_of(".store", "Store"), import_of(".cache", "Cache")],
            },
        ];

        let result = link_cross_file(&files);
        assert!(
            calls_edges_from(&result, &caller).is_empty(),
            "two named owners carry `save`, so `target.save()` names neither: {result:#?}"
        );
    }

    /// The founding false edge, kept as a permanent guard:
    /// `Session.merge_environment_settings --Calls--> requests.get`. The body's
    /// only `.get(` sites are `proxies.get("no_proxy")` on a dict and
    /// `os.environ.get(...)` on the stdlib. Neither can reach the public
    /// module-level `get`, because a call through an object never reaches a
    /// module-level function and a call through a stdlib module never reaches a
    /// repo entity at all.
    #[test]
    fn merge_environment_settings_does_not_call_the_public_requests_get() {
        let public_get = py_function("get", "src/requests/api.py", EntityRole::Source);
        let caller = py_method(
            "Session.merge_environment_settings",
            "src/requests/sessions.py",
            EntityRole::Source,
        );

        let files = vec![
            FileParseData {
                file_path: "src/requests/api.py".to_string(),
                entities: vec![public_get.clone()],
                relations: vec![],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/requests/sessions.py".to_string(),
                entities: vec![caller.clone()],
                relations: vec![
                    py_receiver_call("Session.merge_environment_settings", "proxies", "get"),
                    py_receiver_call("Session.merge_environment_settings", "os.environ", "get"),
                ],
                imports: vec![import_of("os", "os")],
            },
        ];

        let result = link_cross_file(&files);
        assert!(
            !result.iter().any(|rel| rel.kind == RelationKind::Calls
                && rel.dst == GraphNodeId::Entity(public_get.id)),
            "settings merging does not call the public API; believing it invents a cycle"
        );
        assert!(
            calls_edges_from(&result, &caller).is_empty(),
            "neither a dict nor a stdlib module is a repo entity"
        );
    }

    /// The incremental linker resolves the same way as the batch linker. A live
    /// edit must not re-mint the edge a full index refused.
    #[test]
    fn the_incremental_linker_applies_the_same_receiver_and_role_rules() {
        let real_save = py_method("Store.save", "src/store.py", EntityRole::Source);
        let fake_save = py_method("FakeStore.save", "tests/test_store.py", EntityRole::Test);
        let public_get = py_function("get", "src/api.py", EntityRole::Source);
        let caller = py_method("Service.persist", "src/service.py", EntityRole::Source);

        let mut linker = IncrementalLinker::new();
        for (path, entities) in [
            ("src/store.py", vec![real_save.clone()]),
            ("tests/test_store.py", vec![fake_save.clone()]),
            ("src/api.py", vec![public_get.clone()]),
            ("src/service.py", vec![caller.clone()]),
        ] {
            linker.add_file(path, admitted_artifact_id(path), &entities);
        }

        let files = vec![FileParseData {
            file_path: "src/service.py".to_string(),
            entities: vec![caller.clone()],
            relations: vec![
                py_receiver_call("Service.persist", "store", "save"),
                py_receiver_call("Service.persist", "cfg", "get"),
            ],
            imports: vec![import_of(".store", "Store")],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        let edges = calls_edges_from(&result, &caller);
        assert_eq!(edges.len(), 1, "the test double stays out on the live path");
        assert_eq!(edges[0].dst, GraphNodeId::Entity(real_save.id));
        assert!(
            !result
                .iter()
                .any(|rel| rel.dst == GraphNodeId::Entity(public_get.id)),
            "an object call reaches no module-level function on the live path either"
        );
    }

    // ── Overrides: the parser's syntactic override fact ─────────────────────
    //
    // `Overrides` had six consumers and no producer: rename follows it,
    // context assembly weights it at 4.0, ranked impact ranks it at 105, and
    // the only code that could emit one asks a language server for a type
    // hierarchy pyright declines to serve. The fixtures below are the
    // psf/requests shape the gap was found on, and each states which half of
    // the rule it guards, so a revert fails exactly one of them.

    fn py_class(name: &str, file_path: &str) -> Entity {
        py_entity(name, file_path, EntityKind::Class, EntityRole::Source)
    }

    fn py_extends(class: &str, base: &str) -> ExtractedRelation {
        ExtractedRelation {
            site: None,
            receiver: None,
            call_shape: None,
            kind: RelationKind::Extends,
            src_name: class.to_string(),
            dst_name: base.to_string(),
            import_source: None,
        }
    }

    fn py_contains(class: &str, member: &str) -> ExtractedRelation {
        ExtractedRelation {
            site: None,
            receiver: None,
            call_shape: None,
            kind: RelationKind::Contains,
            src_name: class.to_string(),
            dst_name: member.to_string(),
            import_source: None,
        }
    }

    fn override_edges<'a>(result: &'a [Relation], src: &Entity) -> Vec<&'a Relation> {
        result
            .iter()
            .filter(|rel| {
                rel.kind == RelationKind::Overrides && rel.src == GraphNodeId::Entity(src.id)
            })
            .collect()
    }

    fn all_override_edges(result: &[Relation]) -> Vec<&Relation> {
        result
            .iter()
            .filter(|rel| rel.kind == RelationKind::Overrides)
            .collect()
    }

    /// The whole point: `class HTTPAdapter(BaseAdapter)` in one file, both
    /// classes declaring `send`, and the base reached through the import the
    /// real `adapters.py` carries. Nothing here needs a language server.
    #[test]
    fn a_resolvable_base_with_a_same_named_method_produces_the_override() {
        let base = py_class("BaseAdapter", "src/requests/adapters.py");
        let base_send = py_method(
            "BaseAdapter.send",
            "src/requests/adapters.py",
            EntityRole::Source,
        );
        let child = py_class("HTTPAdapter", "src/requests/adapters.py");
        let child_send = py_method(
            "HTTPAdapter.send",
            "src/requests/adapters.py",
            EntityRole::Source,
        );

        let files = vec![FileParseData {
            file_path: "src/requests/adapters.py".to_string(),
            entities: vec![
                base.clone(),
                base_send.clone(),
                child.clone(),
                child_send.clone(),
            ],
            relations: vec![
                py_contains("BaseAdapter", "BaseAdapter.send"),
                py_extends("HTTPAdapter", "BaseAdapter"),
                py_contains("HTTPAdapter", "HTTPAdapter.send"),
            ],
            imports: vec![],
        }];

        let result = link_cross_file(&files);
        let edges = override_edges(&result, &child_send);
        assert_eq!(edges.len(), 1, "one override, to the base that declares it");
        assert_eq!(edges[0].dst, GraphNodeId::Entity(base_send.id));
        assert_eq!(
            edges[0].origin,
            RelationOrigin::Parsed,
            "syntax the parser read, not a server's answer"
        );
        assert_eq!(edges[0].confidence, 1.0);
        assert_eq!(
            edges[0].evidence[0].parser_rule.as_deref(),
            Some(OVERRIDE_EVIDENCE_RESOLVED_BASE_V1),
            "the edge names the rule that produced it"
        );
        assert!(
            edges[0].evidence[0].source_span.is_some(),
            "evidence points at the overriding declaration"
        );
        assert!(
            override_edges(&result, &base_send).is_empty(),
            "the base overrides nothing"
        );
    }

    /// The same fact across files, which is the shape the composition needs:
    /// `sessions.py` never sees `adapters.py`'s source, only its import.
    #[test]
    fn an_override_resolves_across_files_through_the_declaring_import() {
        let base = py_class("BaseAdapter", "src/requests/adapters.py");
        let base_send = py_method(
            "BaseAdapter.send",
            "src/requests/adapters.py",
            EntityRole::Source,
        );
        let child = py_class("LoggingAdapter", "src/requests/logging_adapter.py");
        let child_send = py_method(
            "LoggingAdapter.send",
            "src/requests/logging_adapter.py",
            EntityRole::Source,
        );

        let files = vec![
            FileParseData {
                file_path: "src/requests/adapters.py".to_string(),
                entities: vec![base.clone(), base_send.clone()],
                relations: vec![py_contains("BaseAdapter", "BaseAdapter.send")],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/requests/logging_adapter.py".to_string(),
                entities: vec![child.clone(), child_send.clone()],
                relations: vec![
                    py_extends("LoggingAdapter", "BaseAdapter"),
                    py_contains("LoggingAdapter", "LoggingAdapter.send"),
                ],
                imports: vec![import_of(".adapters", "BaseAdapter")],
            },
        ];

        let result = link_cross_file(&files);
        let edges = override_edges(&result, &child_send);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].dst, GraphNodeId::Entity(base_send.id));
    }

    /// FALSIFICATION. A base the repo does not declare is a name and nothing
    /// more. `requests.Session` subclasses nothing kin can see when the base
    /// lives in the standard library, and a name-only base reference is not
    /// evidence that anything was overridden.
    #[test]
    fn an_unresolved_base_produces_no_override() {
        let child = py_class("HTTPAdapter", "src/requests/adapters.py");
        let child_send = py_method(
            "HTTPAdapter.send",
            "src/requests/adapters.py",
            EntityRole::Source,
        );
        // A tempting decoy: an unrelated class declaring the same method
        // name, which a producer matching on names alone would bind to.
        let decoy = py_class("Mailer", "src/mailer.py");
        let decoy_send = py_method("Mailer.send", "src/mailer.py", EntityRole::Source);

        let files = vec![
            FileParseData {
                file_path: "src/requests/adapters.py".to_string(),
                entities: vec![child.clone(), child_send.clone()],
                relations: vec![
                    // `BaseAdapter` is declared nowhere in this universe.
                    py_extends("HTTPAdapter", "BaseAdapter"),
                    py_contains("HTTPAdapter", "HTTPAdapter.send"),
                ],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/mailer.py".to_string(),
                entities: vec![decoy.clone(), decoy_send.clone()],
                relations: vec![py_contains("Mailer", "Mailer.send")],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert!(
            all_override_edges(&result).is_empty(),
            "an unresolvable base mints nothing, decoy or no decoy"
        );
    }

    /// FALSIFICATION. A base name that two files both declare is ambiguous,
    /// and the linker refuses to pick. Django alone carries dozens of
    /// `Command` classes; guessing one would put a false override on every
    /// method they share.
    #[test]
    fn an_ambiguous_base_name_produces_no_override() {
        let one = py_class("Base", "src/one/base.py");
        let one_run = py_method("Base.run", "src/one/base.py", EntityRole::Source);
        let two = py_class("Base", "src/two/base.py");
        let two_run = py_method("Base.run", "src/two/base.py", EntityRole::Source);
        let child = py_class("Worker", "src/worker.py");
        let child_run = py_method("Worker.run", "src/worker.py", EntityRole::Source);

        let files = vec![
            FileParseData {
                file_path: "src/one/base.py".to_string(),
                entities: vec![one.clone(), one_run.clone()],
                relations: vec![py_contains("Base", "Base.run")],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/two/base.py".to_string(),
                entities: vec![two.clone(), two_run.clone()],
                relations: vec![py_contains("Base", "Base.run")],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/worker.py".to_string(),
                entities: vec![child.clone(), child_run.clone()],
                relations: vec![
                    py_extends("Worker", "Base"),
                    py_contains("Worker", "Worker.run"),
                ],
                // No import binding names which `Base` is meant.
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert!(
            all_override_edges(&result).is_empty(),
            "two candidate bases means no proven base"
        );
    }

    /// FALSIFICATION. Subclassing does not make every method an override.
    /// `HTTPAdapter.build_response` has no counterpart on `BaseAdapter`, and
    /// an edge there would tell rename to follow a method that does not exist.
    #[test]
    fn a_method_with_no_base_counterpart_produces_no_override() {
        let base = py_class("BaseAdapter", "src/requests/adapters.py");
        let base_send = py_method(
            "BaseAdapter.send",
            "src/requests/adapters.py",
            EntityRole::Source,
        );
        let child = py_class("HTTPAdapter", "src/requests/adapters.py");
        let child_build = py_method(
            "HTTPAdapter.build_response",
            "src/requests/adapters.py",
            EntityRole::Source,
        );
        // The name exists elsewhere in the repository, on a class the adapter
        // does not descend from. A producer matching on names would take it.
        let decoy = py_class("Renderer", "src/renderer.py");
        let decoy_build = py_method(
            "Renderer.build_response",
            "src/renderer.py",
            EntityRole::Source,
        );

        let files = vec![
            FileParseData {
                file_path: "src/requests/adapters.py".to_string(),
                entities: vec![
                    base.clone(),
                    base_send.clone(),
                    child.clone(),
                    child_build.clone(),
                ],
                relations: vec![
                    py_contains("BaseAdapter", "BaseAdapter.send"),
                    py_extends("HTTPAdapter", "BaseAdapter"),
                    py_contains("HTTPAdapter", "HTTPAdapter.build_response"),
                ],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/renderer.py".to_string(),
                entities: vec![decoy.clone(), decoy_build.clone()],
                relations: vec![py_contains("Renderer", "Renderer.build_response")],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert!(
            all_override_edges(&result).is_empty(),
            "a method the base never declares overrides nothing"
        );
    }

    /// FALSIFICATION. A class that declares no base at all is the common case
    /// in any repository, and it must stay silent even when another class
    /// somewhere shares its method names.
    #[test]
    fn a_class_with_no_declared_base_produces_no_override() {
        let unrelated = py_class("Poller", "src/poller.py");
        let unrelated_send = py_method("Poller.send", "src/poller.py", EntityRole::Source);
        let base = py_class("BaseAdapter", "src/requests/adapters.py");
        let base_send = py_method(
            "BaseAdapter.send",
            "src/requests/adapters.py",
            EntityRole::Source,
        );

        let files = vec![
            FileParseData {
                file_path: "src/poller.py".to_string(),
                entities: vec![unrelated.clone(), unrelated_send.clone()],
                relations: vec![py_contains("Poller", "Poller.send")],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/requests/adapters.py".to_string(),
                entities: vec![base.clone(), base_send.clone()],
                relations: vec![py_contains("BaseAdapter", "BaseAdapter.send")],
                imports: vec![],
            },
        ];

        let result = link_cross_file(&files);
        assert!(
            all_override_edges(&result).is_empty(),
            "a same-named method on an unrelated class is not an override"
        );
    }

    /// The nearest ancestor wins, which is what makes the edge usable for
    /// rename: `C.send` replaces `B.send`, and `B.send` replaces `A.send`.
    /// A direct `C -> A` edge would claim `C` replaces a method `B` already
    /// replaced.
    #[test]
    fn an_override_binds_to_the_nearest_declaring_ancestor() {
        let a = py_class("A", "src/a.py");
        let a_send = py_method("A.send", "src/a.py", EntityRole::Source);
        let b = py_class("B", "src/b.py");
        let b_send = py_method("B.send", "src/b.py", EntityRole::Source);
        let c = py_class("C", "src/c.py");
        let c_send = py_method("C.send", "src/c.py", EntityRole::Source);

        let files = vec![
            FileParseData {
                file_path: "src/a.py".to_string(),
                entities: vec![a.clone(), a_send.clone()],
                relations: vec![py_contains("A", "A.send")],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/b.py".to_string(),
                entities: vec![b.clone(), b_send.clone()],
                relations: vec![py_extends("B", "A"), py_contains("B", "B.send")],
                imports: vec![import_of(".a", "A")],
            },
            FileParseData {
                file_path: "src/c.py".to_string(),
                entities: vec![c.clone(), c_send.clone()],
                relations: vec![py_extends("C", "B"), py_contains("C", "C.send")],
                imports: vec![import_of(".b", "B")],
            },
        ];

        let result = link_cross_file(&files);
        let from_c = override_edges(&result, &c_send);
        assert_eq!(from_c.len(), 1, "one edge, to the nearest declaring base");
        assert_eq!(from_c[0].dst, GraphNodeId::Entity(b_send.id));

        let from_b = override_edges(&result, &b_send);
        assert_eq!(from_b.len(), 1);
        assert_eq!(from_b[0].dst, GraphNodeId::Entity(a_send.id));
    }

    /// A grandparent still counts when the parent is silent: `C` declares
    /// `send`, `B` does not, `A` does. Skipping the walk past a silent parent
    /// would drop the real override.
    #[test]
    fn an_override_walks_past_an_ancestor_that_declares_nothing() {
        let a = py_class("A", "src/a.py");
        let a_send = py_method("A.send", "src/a.py", EntityRole::Source);
        let b = py_class("B", "src/b.py");
        let c = py_class("C", "src/c.py");
        let c_send = py_method("C.send", "src/c.py", EntityRole::Source);

        let files = vec![
            FileParseData {
                file_path: "src/a.py".to_string(),
                entities: vec![a.clone(), a_send.clone()],
                relations: vec![py_contains("A", "A.send")],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/b.py".to_string(),
                entities: vec![b.clone()],
                relations: vec![py_extends("B", "A")],
                imports: vec![import_of(".a", "A")],
            },
            FileParseData {
                file_path: "src/c.py".to_string(),
                entities: vec![c.clone(), c_send.clone()],
                relations: vec![py_extends("C", "B"), py_contains("C", "C.send")],
                imports: vec![import_of(".b", "B")],
            },
        ];

        let result = link_cross_file(&files);
        let edges = override_edges(&result, &c_send);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].dst, GraphNodeId::Entity(a_send.id));
    }

    /// JavaScript `class Child extends Parent` carries the same fact under
    /// different syntax, and the rule reads the parser's own `Contains` edges
    /// rather than a Python naming convention, so it covers both.
    #[test]
    fn a_javascript_extends_clause_produces_the_same_override() {
        let parent = make_entity("Animal", "src/animal.js");
        let mut parent = parent;
        parent.kind = EntityKind::Class;
        parent.language = LanguageId::JavaScript;
        let mut parent_speak = make_entity("Animal.speak", "src/animal.js");
        parent_speak.kind = EntityKind::Method;
        parent_speak.language = LanguageId::JavaScript;
        let mut child = make_entity("Dog", "src/dog.js");
        child.kind = EntityKind::Class;
        child.language = LanguageId::JavaScript;
        let mut child_speak = make_entity("Dog.speak", "src/dog.js");
        child_speak.kind = EntityKind::Method;
        child_speak.language = LanguageId::JavaScript;

        let files = vec![
            FileParseData {
                file_path: "src/animal.js".to_string(),
                entities: vec![parent.clone(), parent_speak.clone()],
                relations: vec![py_contains("Animal", "Animal.speak")],
                imports: vec![],
            },
            FileParseData {
                file_path: "src/dog.js".to_string(),
                entities: vec![child.clone(), child_speak.clone()],
                relations: vec![py_extends("Dog", "Animal"), py_contains("Dog", "Dog.speak")],
                imports: vec![import_of("./animal", "Animal")],
            },
        ];

        let result = link_cross_file(&files);
        let edges = override_edges(&result, &child_speak);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].dst, GraphNodeId::Entity(parent_speak.id));
    }

    /// The incremental linker must answer identically or a warm reindex
    /// silently retires an edge the cold ingest produced.
    #[test]
    fn the_incremental_linker_derives_the_same_override() {
        let base = py_class("BaseAdapter", "src/requests/adapters.py");
        let base_send = py_method(
            "BaseAdapter.send",
            "src/requests/adapters.py",
            EntityRole::Source,
        );
        let child = py_class("LoggingAdapter", "src/requests/logging_adapter.py");
        let child_send = py_method(
            "LoggingAdapter.send",
            "src/requests/logging_adapter.py",
            EntityRole::Source,
        );

        let mut linker = IncrementalLinker::new();
        linker.add_file(
            "src/requests/adapters.py",
            admitted_artifact_id("src/requests/adapters.py"),
            &[base.clone(), base_send.clone()],
        );
        linker.add_file(
            "src/requests/logging_adapter.py",
            admitted_artifact_id("src/requests/logging_adapter.py"),
            &[child.clone(), child_send.clone()],
        );

        let files = vec![FileParseData {
            file_path: "src/requests/logging_adapter.py".to_string(),
            entities: vec![child.clone(), child_send.clone()],
            relations: vec![
                py_extends("LoggingAdapter", "BaseAdapter"),
                py_contains("LoggingAdapter", "LoggingAdapter.send"),
            ],
            imports: vec![import_of(".adapters", "BaseAdapter")],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        let edges = override_edges(&result, &child_send);
        assert_eq!(edges.len(), 1, "the warm path derives it too");
        assert_eq!(edges[0].dst, GraphNodeId::Entity(base_send.id));
        assert_eq!(edges[0].origin, RelationOrigin::Parsed);
    }

    /// FALSIFICATION, incremental half: the warm path must refuse an
    /// unresolvable base for the same reason the cold path does.
    #[test]
    fn the_incremental_linker_refuses_an_unresolved_base() {
        let child = py_class("LoggingAdapter", "src/requests/logging_adapter.py");
        let child_send = py_method(
            "LoggingAdapter.send",
            "src/requests/logging_adapter.py",
            EntityRole::Source,
        );
        // The same decoy the cold path is tested against: a class the adapter
        // does not descend from, declaring the same method name.
        let decoy = py_class("Mailer", "src/mailer.py");
        let decoy_send = py_method("Mailer.send", "src/mailer.py", EntityRole::Source);

        let mut linker = IncrementalLinker::new();
        linker.add_file(
            "src/mailer.py",
            admitted_artifact_id("src/mailer.py"),
            &[decoy.clone(), decoy_send.clone()],
        );
        linker.add_file(
            "src/requests/logging_adapter.py",
            admitted_artifact_id("src/requests/logging_adapter.py"),
            &[child.clone(), child_send.clone()],
        );

        let files = vec![FileParseData {
            file_path: "src/requests/logging_adapter.py".to_string(),
            entities: vec![child.clone(), child_send.clone()],
            relations: vec![
                py_extends("LoggingAdapter", "BaseAdapter"),
                py_contains("LoggingAdapter", "LoggingAdapter.send"),
            ],
            imports: vec![],
        }];

        let result = link_cross_file_incremental(&files, &linker);
        assert!(all_override_edges(&result).is_empty());
    }
}
