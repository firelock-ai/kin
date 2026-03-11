use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use tracing::debug;

use kin_model::{Entity, EntityId, Relation, RelationId, RelationKind, RelationOrigin};
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
    // Step 1: Build entity indices
    //   (file_path, entity_name) -> EntityId
    let mut entity_by_file_name: HashMap<(&str, &str), EntityId> = HashMap::new();
    //   entity_name -> Vec<(file_path, EntityId)>
    let mut entity_by_name: HashMap<&str, Vec<(&str, EntityId)>> = HashMap::new();
    //   Collect all known file paths for module resolution
    let mut known_files: HashSet<&str> = HashSet::new();

    for file in files {
        known_files.insert(&file.file_path);
        for entity in &file.entities {
            entity_by_file_name.insert((&file.file_path, &entity.name), entity.id);
            entity_by_name
                .entry(&*entity.name)
                .or_default()
                .push((&file.file_path, entity.id));
        }
    }

    // Step 2: Build import map per file
    //   file_path -> { local_name -> (module_path, original_name) }
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

    let mut resolved = Vec::new();
    let mut seen: HashSet<(EntityId, EntityId, RelationKind)> = HashSet::new();

    for file in files {
        for rel in &file.relations {
            let src_id = entity_by_file_name.get(&(file.file_path.as_str(), rel.src_name.as_str()));
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
                if let Some(&(module_path, original_name)) = file_imports.get(rel.dst_name.as_str())
                {
                    if let Some(target_file) =
                        resolve_module_path(&file.file_path, module_path, &known_files)
                    {
                        if let Some(&dst_id) =
                            entity_by_file_name.get(&(target_file.as_str(), original_name))
                        {
                            if add_deduped(&mut seen, src_id, dst_id, rel.kind) {
                                resolved.push(make_relation(rel.kind, src_id, dst_id, 0.95));
                            }
                            continue;
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

/// Build a Relation with the given parameters.
fn make_relation(kind: RelationKind, src: EntityId, dst: EntityId, confidence: f32) -> Relation {
    let origin = if confidence >= 1.0 {
        RelationOrigin::Parsed
    } else {
        RelationOrigin::Inferred
    };

    Relation {
        id: RelationId::new(),
        kind,
        src,
        dst,
        confidence,
        origin,
        created_in: None,
    }
}

/// Resolve a module path relative to the importing file's directory.
///
/// For relative paths like `./utils` or `../lib/foo`, tries multiple extensions
/// and index file patterns against the set of known file paths.
///
/// Returns None for non-relative (package) imports like `lodash`.
fn resolve_module_path(
    importer_path: &str,
    module_path: &str,
    known_files: &HashSet<&str>,
) -> Option<String> {
    // Only resolve relative imports
    if !module_path.starts_with('.') {
        return None;
    }

    let importer = Path::new(importer_path);
    let importer_dir = importer.parent().unwrap_or(Path::new(""));

    // Resolve the relative path
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
        EntityKind, EntityMetadata, FilePathId, FingerprintAlgorithm, Hash256, LanguageId,
        SemanticFingerprint, SourceSpan, Visibility,
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
            }],
            imports: vec![],
        }];

        let result = link_cross_file(&files);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].src, e1.id);
        assert_eq!(result[0].dst, e2.id);
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
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].src, caller.id);
        assert_eq!(result[0].dst, callee.id);
        assert_eq!(result[0].confidence, 0.95);
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
        assert_eq!(result[0].src, caller.id);
        assert_eq!(result[0].dst, target.id);
        assert_eq!(result[0].confidence, 0.7);
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
                },
                ExtractedRelation {
                    kind: RelationKind::Calls,
                    src_name: "foo".to_string(),
                    dst_name: "bar".to_string(),
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
    fn resolve_module_path_non_relative() {
        let known: HashSet<&str> = ["node_modules/lodash/index.js"].into_iter().collect();
        let result = resolve_module_path("src/app.ts", "lodash", &known);
        assert_eq!(result, None);
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
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].src, caller.id);
        assert_eq!(result[0].dst, callee.id);
        assert_eq!(result[0].confidence, 0.95);
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
        assert_eq!(result[0].src, e1.id);
        assert_eq!(result[0].dst, e2.id);
    }
}
