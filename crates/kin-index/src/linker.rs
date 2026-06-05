// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use tracing::debug;

use sha2::{Digest, Sha256};

use kin_model::{Entity, EntityId, Relation, RelationId, RelationKind, RelationOrigin, Visibility};
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
const MODULE_EXTENSIONS: &[&str] = &["ts", "tsx", "js", "jsx", "py", "rs", "go"];

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
    // Step 1: Build entity indices
    //   (file_path, entity_name) -> EntityId
    let (entity_by_file_name, entity_by_name, known_files) = {
        let _span = tracing::info_span!(
            "kin.index.link_cross_file.build_entity_indices",
            universe_entities = universe_entities.len()
        )
        .entered();
        let mut entity_by_file_name: HashMap<(&str, &str), EntityId> = HashMap::new();
        let mut entity_by_name: HashMap<&str, Vec<(&str, EntityId)>> = HashMap::new();
        let mut known_files: HashSet<&str> = HashSet::new();

        for entity in universe_entities {
            let Some(file_path) = entity.file_origin.as_ref().map(|path| path.0.as_str()) else {
                continue;
            };
            known_files.insert(file_path);
            entity_by_file_name.insert((file_path, &entity.name), entity.id);
            entity_by_name
                .entry(&*entity.name)
                .or_default()
                .push((file_path, entity.id));
        }

        for file in files {
            known_files.insert(&file.file_path);
        }

        (entity_by_file_name, entity_by_name, known_files)
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
                                resolve_default_export(&target_file, universe_entities)
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
                if let Some(candidates) = entity_by_name.get(rel.dst_name.as_str()) {
                    // Pick the first candidate from a different file
                    let other_file_match = candidates
                        .iter()
                        .find(|(fp, _)| *fp != file.file_path.as_str());

                    if let Some(&(_, dst_id)) = other_file_match {
                        if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                            resolved.push(make_relation(rel.kind, src_id, dst_id, 0.7));
                        }
                        continue;
                    }
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

    // Step 4: Create Imports edges from import declarations.
    //
    // For each import specifier that resolves to a known entity, emit a
    // RelationKind::Imports edge. The source is the first entity in the
    // importing file (acting as a file representative). The import_source
    // field records the module path for qualified cross-repo resolution.
    {
        let _span = tracing::info_span!(
            "kin.index.link_cross_file.build_import_edges",
            files = files.len()
        )
        .entered();
        for file in files {
            // We need a source entity to anchor the import edge.
            let Some(first_entity) = file.entities.first() else {
                continue;
            };
            let src_id = first_entity.id;

            for imp in &file.imports {
                let target_file =
                    resolve_module_path(&file.file_path, &imp.module_path, &known_files);

                for spec in &imp.specifiers {
                    let original = spec.original_name.as_deref().unwrap_or(&spec.local_name);

                    // Skip wildcard imports — they don't resolve to a single entity
                    if original == "*" {
                        continue;
                    }

                    let dst_id = if let Some(ref target) = target_file {
                        // Relative import: resolve via target file + original name
                        let direct = entity_by_file_name
                            .get(&(target.as_str(), original))
                            .copied();
                        if direct.is_some() {
                            direct
                        } else if original == "default" {
                            // Default import: fall back to the first entity in the target file
                            resolve_default_export(target, universe_entities)
                        } else {
                            None
                        }
                    } else {
                        // Non-relative (package) import: try several strategies
                        // (a) Java: combine module_path + specifier to get full
                        //     class path, then resolve to file
                        let java_combined = if imp.module_path.contains('.')
                            && !imp.module_path.contains('/')
                            && original != "*"
                        {
                            let full_path = format!("{}.{}", imp.module_path, original);
                            resolve_java_package_import(&full_path, &known_files).and_then(
                                |file_path| {
                                    entity_by_file_name
                                        .get(&(file_path.as_str(), original))
                                        .copied()
                                        .or_else(|| {
                                            // Try qualified name: Class.Method
                                            let qualified = format!("{}", original);
                                            entity_by_file_name
                                                .get(&(file_path.as_str(), qualified.as_str()))
                                                .copied()
                                        })
                                        .or_else(|| {
                                            // Fall back to first entity in the file
                                            resolve_default_export(&file_path, universe_entities)
                                        })
                                },
                            )
                        } else {
                            None
                        };
                        java_combined.or_else(|| {
                            // (b) Global name fallback for all languages
                            entity_by_name
                                .get(original)
                                .and_then(|candidates| {
                                    candidates
                                        .iter()
                                        .find(|(fp, _)| *fp != file.file_path.as_str())
                                })
                                .map(|(_, id)| *id)
                        })
                    };

                    if let Some(dst_id) = dst_id {
                        if add_deduped(&mut seen, src_id, dst_id, RelationKind::Imports) {
                            let mut rel = make_relation(RelationKind::Imports, src_id, dst_id, 1.0);
                            rel.import_source = Some(imp.module_path.clone());
                            resolved.push(rel);
                        }
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
    }
}

/// Derive a deterministic RelationId from the (src, dst, kind) triple.
fn stable_relation_id(src: &EntityId, dst: &EntityId, kind: &RelationKind) -> RelationId {
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
        // Non-relative (package) import — try monorepo heuristic resolution
        resolve_package_import(module_path, known_files)
            // Java package resolution: com.foo.bar.ClassName → src/main/java/com/foo/bar/ClassName.java
            .or_else(|| resolve_java_package_import(module_path, known_files))
            // Go module resolution: github.com/org/repo/v2/pkg/foo → pkg/foo/*.go
            .or_else(|| resolve_go_module_import(module_path, known_files))
    }
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
    for file in known_files.iter() {
        let file_str = file.borrow();
        if file_str.ends_with(&suffix) {
            return Some(file_str.to_string());
        }
    }

    None
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
        // Look for any .go file in this directory
        for file in known_files.iter() {
            let file_str = file.borrow();
            if file_str.starts_with(&local_path)
                && file_str.ends_with(".go")
                && file_str[local_path.len()..].starts_with('/')
                && !file_str[local_path.len() + 1..].contains('/')
            {
                return Some(file_str.to_string());
            }
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
fn resolve_default_export(target_file: &str, universe_entities: &[Entity]) -> Option<EntityId> {
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
            known_files: HashSet::new(),
            entities_by_file: HashMap::new(),
        }
    }

    /// Remove a file and all its associated entities from the indexes.
    pub fn remove_file(&mut self, file_path: &str) {
        self.known_files.remove(file_path);

        if let Some(file_entities) = self.entity_by_file_name.remove(file_path) {
            for entity_name in file_entities.keys() {
                if let Some(candidates) = self.entity_by_name.get_mut(entity_name) {
                    candidates.retain(|(fp, _)| fp != file_path);
                    if candidates.is_empty() {
                        self.entity_by_name.remove(entity_name);
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

            self.entity_by_name
                .entry(entity.name.clone())
                .or_default()
                .push((file_path.to_string(), entity.id));

            file_entities_list.push((entity.id, entity.visibility));
        }

        if !file_entities_map.is_empty() {
            self.entity_by_file_name.insert(file_path.to_string(), file_entities_map);
        }
        if !file_entities_list.is_empty() {
            self.entities_by_file.insert(file_path.to_string(), file_entities_list);
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
    let _span = tracing::info_span!(
        "kin.index.link_cross_file_incremental",
        files = files.len()
    )
    .entered();

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
            let src_id = linker.entity_by_file_name
                .get(&file.file_path)
                .and_then(|m| m.get(&rel.src_name))
                .copied();
            let dst_same_file = linker.entity_by_file_name
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

            // (a) Same-file resolution
            if let Some(dst_id) = dst_same_file {
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
                        resolve_module_path(&file.file_path, module_path, &linker.known_files)
                    {
                        let direct = linker.entity_by_file_name
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
                            if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                                resolved.push(make_relation(rel.kind, src_id, dst_id, 0.95));
                            }
                            continue;
                        }
                    }
                }

                // (b2) Namespace/package import member resolution
                if let Some((import_name, member_name)) =
                    split_member_access(rel.dst_name.as_str())
                {
                    if let Some(&(module_path, _original_name)) = file_imports.get(import_name)
                    {
                        if let Some(target_file) =
                            resolve_module_path(&file.file_path, module_path, &linker.known_files)
                        {
                            if let Some(&dst_id) = linker.entity_by_file_name
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
                let other_file_match = candidates
                    .iter()
                    .find(|(fp, _)| fp != &file.file_path);

                if let Some((_, dst_id)) = other_file_match {
                    if add_deduped(&mut seen, src_id, *dst_id, rel.kind) {
                        resolved.push(make_relation(rel.kind, src_id, *dst_id, 0.7));
                    }
                }
            }
        }
    }

    // Step 4: Create Imports edges from import declarations.
    for file in files {
        let Some(first_entity) = file.entities.first() else {
            continue;
        };
        let src_id = first_entity.id;

        for imp in &file.imports {
            let target_file =
                resolve_module_path(&file.file_path, &imp.module_path, &linker.known_files);

            for spec in &imp.specifiers {
                let original = spec.original_name.as_deref().unwrap_or(&spec.local_name);

                if original == "*" {
                    continue;
                }

                let dst_id = if let Some(ref target) = target_file {
                    let direct = linker.entity_by_file_name
                        .get(target)
                        .and_then(|m| m.get(original))
                        .copied();
                    if direct.is_some() {
                        direct
                    } else if original == "default" {
                        resolve_default_export_incremental(target, &linker.entities_by_file)
                    } else {
                        None
                    }
                } else {
                    let java_combined = if imp.module_path.contains('.')
                        && !imp.module_path.contains('/')
                        && original != "*"
                    {
                        let full_path = format!("{}.{}", imp.module_path, original);
                        resolve_java_package_import(&full_path, &linker.known_files).and_then(
                            |file_path| {
                                linker.entity_by_file_name
                                    .get(&file_path)
                                    .and_then(|m| m.get(original))
                                    .copied()
                                    .or_else(|| {
                                        let qualified = format!("{}", original);
                                        linker.entity_by_file_name
                                            .get(&file_path)
                                            .and_then(|m| m.get(qualified.as_str()))
                                            .copied()
                                    })
                                    .or_else(|| {
                                        resolve_default_export_incremental(&file_path, &linker.entities_by_file)
                                    })
                            },
                        )
                    } else {
                        None
                    };
                    java_combined.or_else(|| {
                        linker.entity_by_name
                            .get(original)
                            .and_then(|candidates| {
                                candidates
                                    .iter()
                                    .find(|(fp, _)| fp != &file.file_path)
                            })
                            .map(|(_, id)| *id)
                    })
                };

                if let Some(dst_id) = dst_id {
                    if add_deduped(&mut seen, src_id, dst_id, RelationKind::Imports) {
                        let mut rel = make_relation(RelationKind::Imports, src_id, dst_id, 1.0);
                        rel.import_source = Some(imp.module_path.clone());
                        resolved.push(rel);
                    }
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
mod tests {
    use super::*;
    use kin_model::{
        EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm, GraphNodeId,
        Hash256, LanguageId, SemanticFingerprint, SourceSpan, Visibility,
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
        // Step 3b produces a Calls edge; Step 4 produces an Imports edge
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
        assert_eq!(imports.src, GraphNodeId::Entity(caller.id));
        assert_eq!(imports.dst, GraphNodeId::Entity(callee.id));
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
        // Step 3b produces a Calls edge; Step 4 produces an Imports edge
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
        assert_eq!(imports.src, GraphNodeId::Entity(caller.id));
        assert_eq!(imports.dst, GraphNodeId::Entity(callee.id));
        assert_eq!(imports.import_source.as_deref(), Some("../utils/tools"));
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
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].src, GraphNodeId::Entity(caller.id));
        assert_eq!(result[0].dst, GraphNodeId::Entity(callee.id));
        assert_eq!(result[0].confidence, 0.9);
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
        // Step 3b produces a Calls edge; Step 4 produces an Imports edge
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
        assert_eq!(imports.src, GraphNodeId::Entity(caller.id));
        assert_eq!(imports.dst, GraphNodeId::Entity(callee.id));
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
        assert_eq!(result[0].src, kin_model::GraphNodeId::Entity(importer.id));
        assert_eq!(result[0].dst, kin_model::GraphNodeId::Entity(target.id));
        assert_eq!(result[0].import_source.as_deref(), Some("../utils/tools"));
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
    fn wildcard_import_skipped() {
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
        assert_eq!(result.len(), 0, "wildcard imports should not create edges");
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
