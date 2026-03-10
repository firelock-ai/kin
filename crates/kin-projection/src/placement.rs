use std::path::Path;

use kin_model::{Entity, EntityFilter, EntityKind, FilePathId, GraphStore, LanguageId};
use tracing::debug;

use crate::error::{ProjectionError, Result};

/// Decision about where to place a new entity in the working directory.
#[derive(Debug, Clone)]
pub enum PlacementDecision {
    /// Place in an existing file at the given path.
    ExistingFile(FilePathId),
    /// Create a new file at the given path using a language template.
    NewFile(FilePathId),
    /// Multiple valid placements exist; caller must choose.
    Ambiguous(Vec<FilePathId>),
}

/// Determine where a new entity should be placed in the working directory.
///
/// Policy (in priority order):
/// 1. If `file_origin` is set, use that file.
/// 2. If a containing module/class entity exists in the graph, use that module's file.
/// 3. If multiple candidate files exist, return `Ambiguous`.
/// 4. If no match, generate a new file path from the entity's name and language.
pub fn decide_placement<G: GraphStore>(
    entity: &Entity,
    graph: &G,
    working_dir: &Path,
) -> Result<PlacementDecision> {
    // 1. Explicit file_origin
    if let Some(ref file_id) = entity.file_origin {
        let path = working_dir.join(&file_id.0);
        if path.exists() {
            debug!(entity = %entity.name, file = %file_id, "placement: explicit file_origin");
            return Ok(PlacementDecision::ExistingFile(file_id.clone()));
        }
        // File doesn't exist yet but was explicitly set — create it
        debug!(entity = %entity.name, file = %file_id, "placement: new file from file_origin");
        return Ok(PlacementDecision::NewFile(file_id.clone()));
    }

    // 2. Look for containing module/namespace
    if let Some(ref parent_id) = entity.lineage_parent {
        let parent = graph
            .get_entity(parent_id)
            .map_err(|e| ProjectionError::Graph(e.to_string()))?;
        if let Some(parent_entity) = parent {
            if let Some(ref parent_file) = parent_entity.file_origin {
                debug!(
                    entity = %entity.name,
                    parent = %parent_entity.name,
                    file = %parent_file,
                    "placement: parent module's file"
                );
                return Ok(PlacementDecision::ExistingFile(parent_file.clone()));
            }
        }
    }

    // 3. Search for candidate files by language and kind
    let filter = EntityFilter {
        languages: Some(vec![entity.language]),
        kinds: Some(vec![EntityKind::Module]),
        ..Default::default()
    };
    let modules = graph
        .query_entities(&filter)
        .map_err(|e| ProjectionError::Graph(e.to_string()))?;

    let candidate_files: Vec<FilePathId> = modules
        .iter()
        .filter_map(|m| m.file_origin.clone())
        .collect();

    if candidate_files.len() > 1 {
        debug!(
            entity = %entity.name,
            candidates = candidate_files.len(),
            "placement: ambiguous, multiple modules"
        );
        return Ok(PlacementDecision::Ambiguous(candidate_files));
    }

    if candidate_files.len() == 1 {
        debug!(entity = %entity.name, file = %candidate_files[0], "placement: single module match");
        return Ok(PlacementDecision::ExistingFile(candidate_files[0].clone()));
    }

    // 4. Generate new file path
    let new_path = generate_file_path(entity);
    debug!(entity = %entity.name, file = %new_path, "placement: generated new file");
    Ok(PlacementDecision::NewFile(new_path))
}

/// Generate a file path for a new entity based on its name and language.
fn generate_file_path(entity: &Entity) -> FilePathId {
    let ext = language_extension(entity.language);
    let name = entity
        .name
        .to_lowercase()
        .replace("::", "/")
        .replace('.', "/");

    let path = format!("src/{name}.{ext}");
    FilePathId::new(path)
}

/// Get the primary file extension for a language.
fn language_extension(language: LanguageId) -> &'static str {
    match language {
        LanguageId::TypeScript => "ts",
        LanguageId::JavaScript => "js",
        LanguageId::Python => "py",
        LanguageId::Rust => "rs",
        LanguageId::Go => "go",
        LanguageId::Java => "java",
    }
}

/// Generate a new file from a language-specific template.
pub fn generate_file_template(language: LanguageId, entity: &Entity) -> Vec<u8> {
    let content = match language {
        LanguageId::TypeScript | LanguageId::JavaScript => {
            match entity.kind {
                EntityKind::Class => format!(
                    "export class {} {{\n  // TODO: implement\n}}\n",
                    entity.name
                ),
                EntityKind::Interface => format!(
                    "export interface {} {{\n  // TODO: define\n}}\n",
                    entity.name
                ),
                EntityKind::Function => format!(
                    "export function {}() {{\n  // TODO: implement\n}}\n",
                    entity.name
                ),
                _ => format!("// {}\n", entity.name),
            }
        }
        LanguageId::Python => {
            match entity.kind {
                EntityKind::Class => format!(
                    "class {}:\n    \"\"\"TODO: implement\"\"\"\n    pass\n",
                    entity.name
                ),
                EntityKind::Function => format!(
                    "def {}():\n    \"\"\"TODO: implement\"\"\"\n    pass\n",
                    entity.name
                ),
                _ => format!("# {}\n", entity.name),
            }
        }
        LanguageId::Rust => {
            match entity.kind {
                EntityKind::Class => format!(
                    "pub struct {} {{\n    // TODO: add fields\n}}\n",
                    entity.name
                ),
                EntityKind::Function => format!(
                    "pub fn {}() {{\n    // TODO: implement\n}}\n",
                    entity.name
                ),
                EntityKind::TraitDef => format!(
                    "pub trait {} {{\n    // TODO: define methods\n}}\n",
                    entity.name
                ),
                EntityKind::EnumDef => format!(
                    "pub enum {} {{\n    // TODO: add variants\n}}\n",
                    entity.name
                ),
                _ => format!("// {}\n", entity.name),
            }
        }
        LanguageId::Go => {
            match entity.kind {
                EntityKind::Class => format!(
                    "type {} struct {{\n\t// TODO: add fields\n}}\n",
                    entity.name
                ),
                EntityKind::Interface => format!(
                    "type {} interface {{\n\t// TODO: define methods\n}}\n",
                    entity.name
                ),
                EntityKind::Function => format!(
                    "func {}() {{\n\t// TODO: implement\n}}\n",
                    entity.name
                ),
                _ => format!("// {}\n", entity.name),
            }
        }
        LanguageId::Java => {
            match entity.kind {
                EntityKind::Class => format!(
                    "public class {} {{\n    // TODO: implement\n}}\n",
                    entity.name
                ),
                EntityKind::Interface => format!(
                    "public interface {} {{\n    // TODO: define\n}}\n",
                    entity.name
                ),
                _ => format!("// {}\n", entity.name),
            }
        }
    };
    content.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::*;

    fn make_entity(name: &str, kind: EntityKind, language: LanguageId) -> Entity {
        Entity {
            id: EntityId::new(),
            kind,
            name: name.to_string(),
            language,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn generate_file_path_rust() {
        let entity = make_entity("process", EntityKind::Function, LanguageId::Rust);
        let path = generate_file_path(&entity);
        assert_eq!(path, FilePathId::new("src/process.rs"));
    }

    #[test]
    fn generate_file_path_typescript() {
        let entity = make_entity("UserService", EntityKind::Class, LanguageId::TypeScript);
        let path = generate_file_path(&entity);
        assert_eq!(path, FilePathId::new("src/userservice.ts"));
    }

    #[test]
    fn generate_file_path_python() {
        let entity = make_entity("utils", EntityKind::Module, LanguageId::Python);
        let path = generate_file_path(&entity);
        assert_eq!(path, FilePathId::new("src/utils.py"));
    }

    #[test]
    fn generate_file_path_qualified_name() {
        let entity = make_entity("Dog::bark", EntityKind::Method, LanguageId::Rust);
        let path = generate_file_path(&entity);
        assert_eq!(path, FilePathId::new("src/dog/bark.rs"));
    }

    #[test]
    fn template_rust_struct() {
        let entity = make_entity("Config", EntityKind::Class, LanguageId::Rust);
        let content = String::from_utf8(generate_file_template(LanguageId::Rust, &entity)).unwrap();
        assert!(content.contains("pub struct Config"));
        assert!(content.contains("TODO"));
    }

    #[test]
    fn template_typescript_class() {
        let entity = make_entity("UserService", EntityKind::Class, LanguageId::TypeScript);
        let content =
            String::from_utf8(generate_file_template(LanguageId::TypeScript, &entity)).unwrap();
        assert!(content.contains("export class UserService"));
    }

    #[test]
    fn template_python_function() {
        let entity = make_entity("process", EntityKind::Function, LanguageId::Python);
        let content =
            String::from_utf8(generate_file_template(LanguageId::Python, &entity)).unwrap();
        assert!(content.contains("def process()"));
    }

    #[test]
    fn template_go_struct() {
        let entity = make_entity("Server", EntityKind::Class, LanguageId::Go);
        let content = String::from_utf8(generate_file_template(LanguageId::Go, &entity)).unwrap();
        assert!(content.contains("type Server struct"));
    }

    #[test]
    fn template_java_interface() {
        let entity = make_entity("Runnable", EntityKind::Interface, LanguageId::Java);
        let content =
            String::from_utf8(generate_file_template(LanguageId::Java, &entity)).unwrap();
        assert!(content.contains("public interface Runnable"));
    }

    #[test]
    fn language_extensions_correct() {
        assert_eq!(language_extension(LanguageId::TypeScript), "ts");
        assert_eq!(language_extension(LanguageId::JavaScript), "js");
        assert_eq!(language_extension(LanguageId::Python), "py");
        assert_eq!(language_extension(LanguageId::Rust), "rs");
        assert_eq!(language_extension(LanguageId::Go), "go");
        assert_eq!(language_extension(LanguageId::Java), "java");
    }
}
