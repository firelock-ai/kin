use std::collections::HashMap;
use std::path::{Path, PathBuf};

use kin_blobs::BlobStore;
use kin_model::preset::{FormattingPolicy, ProjectionMode};
use kin_model::{EntityId, FileLayout, FilePathId, GraphStore, SourceRegion};
use tracing::{debug, warn};

use crate::error::{ProjectionError, Result};
use crate::splice::{apply_splices, splice_entity, Splice};

/// Tracks FileLayout state for all projected files.
#[derive(Debug, Default)]
pub struct ProjectionState {
    /// FileLayout per file path.
    layouts: HashMap<FilePathId, FileLayout>,
    /// Original file content per path (for splice operations).
    file_contents: HashMap<FilePathId, Vec<u8>>,
}

impl ProjectionState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a file's layout and content.
    pub fn register_file(&mut self, layout: FileLayout, content: Vec<u8>) {
        let file_id = layout.file_id.clone();
        self.layouts.insert(file_id.clone(), layout);
        self.file_contents.insert(file_id, content);
    }

    /// Get the layout for a file.
    pub fn get_layout(&self, file_id: &FilePathId) -> Option<&FileLayout> {
        self.layouts.get(file_id)
    }

    /// Get the current content of a file.
    pub fn get_content(&self, file_id: &FilePathId) -> Option<&[u8]> {
        self.file_contents.get(file_id).map(|v| v.as_slice())
    }

    /// List all tracked file IDs.
    pub fn file_ids(&self) -> Vec<&FilePathId> {
        self.layouts.keys().collect()
    }
}

/// Project a set of entity mutations to the working directory.
///
/// For each mutated entity, finds its file in the projection state,
/// performs surgical byte-range splicing, and writes the result.
///
/// Returns the list of files that were modified.
///
/// Uses default policy (Preserve formatting, Full projection mode).
pub fn project_entity_mutations(
    state: &mut ProjectionState,
    mutations: &HashMap<EntityId, Vec<u8>>,
    working_dir: &Path,
) -> Result<Vec<FilePathId>> {
    project_entity_mutations_with_policy(
        state,
        mutations,
        working_dir,
        FormattingPolicy::Preserve,
        ProjectionMode::Full,
    )
}

/// Project a set of entity mutations to the working directory with policy.
///
/// Applies formatting and projection mode transformations to entity bodies
/// before writing them to disk.
pub fn project_entity_mutations_with_policy(
    state: &mut ProjectionState,
    mutations: &HashMap<EntityId, Vec<u8>>,
    working_dir: &Path,
    formatting: FormattingPolicy,
    mode: ProjectionMode,
) -> Result<Vec<FilePathId>> {
    let mut modified_files = Vec::new();

    // Group mutations by file.
    let mut file_mutations: HashMap<FilePathId, Vec<Splice>> = HashMap::new();

    for (entity_id, new_body) in mutations {
        // Find which file contains this entity.
        let mut found = false;
        for (file_id, layout) in &state.layouts {
            for region in &layout.regions {
                if let SourceRegion::EntityRef {
                    entity_id: ref eid, ..
                } = region
                {
                    if eid == entity_id {
                        let splice = splice_entity(layout, entity_id, new_body)?;
                        file_mutations
                            .entry(file_id.clone())
                            .or_default()
                            .push(splice);
                        found = true;
                        break;
                    }
                }
            }
            if found {
                break;
            }
        }

        if !found {
            debug!(entity_id = %entity_id, "entity not found in any file layout, skipping");
        }
    }

    // Two-phase commit: write all files to temp paths first, then rename
    // them to final paths. This ensures that if any write fails, no final
    // files are touched (all temp files are cleaned up).

    // Phase 1: Prepare — splice, transform, and write to temp paths.
    let mut prepared: Vec<(std::path::PathBuf, std::path::PathBuf, FilePathId, Vec<u8>)> =
        Vec::new();

    for (file_id, splices) in file_mutations {
        let original = state
            .file_contents
            .get(&file_id)
            .ok_or_else(|| ProjectionError::LayoutNotFound(file_id.to_string()))?;

        let spliced = apply_splices(original, splices)?;

        // Apply formatting policy transformations.
        let formatted = apply_formatting_policy(&spliced, formatting);

        // Apply projection mode transformations.
        let new_content = apply_projection_mode(&formatted, mode);

        let file_path = working_dir.join(&file_id.0);
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ProjectionError::io(parent, e))?;
        }

        let tmp_path = projection_tmp_path(&file_path);
        std::fs::write(&tmp_path, &new_content).map_err(|e| {
            // Clean up ALL previously written temp files.
            for (prev_tmp, _, _, _) in &prepared {
                let _ = std::fs::remove_file(prev_tmp);
            }
            let _ = std::fs::remove_file(&tmp_path);
            ProjectionError::io(&tmp_path, e)
        })?;

        prepared.push((tmp_path, file_path, file_id, new_content));
    }

    // Phase 2: Commit — rename all temp files to their final paths.
    // Renames are fast (same-directory metadata ops) and unlikely to fail.
    for (committed, (tmp_path, file_path, file_id, new_content)) in prepared.into_iter().enumerate() {
        if let Err(e) = std::fs::rename(&tmp_path, &file_path) {
            warn!(
                committed,
                remaining = "some temp files may remain",
                "partial commit during projection rename"
            );
            // Best-effort cleanup of this un-renamed temp file.
            let _ = std::fs::remove_file(&tmp_path);
            return Err(ProjectionError::io(&file_path, e));
        }

        // Update cached content.
        state.file_contents.insert(file_id.clone(), new_content);

        debug!(file = %file_id, ?formatting, ?mode, "projected mutations to file");
        modified_files.push(file_id);
    }

    Ok(modified_files)
}

fn projection_tmp_path(file_path: &Path) -> PathBuf {
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(
        file_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("projection")),
    );
    tmp_name.push(".kin-tmp");
    file_path.with_file_name(tmp_name)
}

/// Project a complete file from its FileLayout and entity bodies.
///
/// Used during branch switch: re-renders the entire file from the target
/// branch's entity state.
pub fn project_file_from_entities<G>(
    layout: &FileLayout,
    original_content: &[u8],
    graph: &G,
    blob_store: &BlobStore,
) -> Result<Vec<u8>>
where
    G: GraphStore,
{
    crate::splice::reconstruct_file(original_content, layout, |entity_id| {
        let entity = match graph.get_entity(entity_id) {
            Ok(Some(e)) => e,
            _ => return None,
        };

        // Use the entity's span to extract its body from the original file content.
        if let Some(ref span) = entity.span {
            if span.end_byte <= original_content.len() {
                return Some(original_content[span.start_byte..span.end_byte].to_vec());
            }
        }

        // Span extraction failed (missing span or out-of-bounds). Fall back to
        // blob store lookup using the blob_hash stored in entity metadata.
        if let Some(serde_json::Value::String(hex)) = entity.metadata.extra.get("blob_hash") {
            if let Ok(hash) = kin_blobs::Hash256::from_hex(hex) {
                if let Ok(blob_bytes) = blob_store.read(&hash) {
                    debug!(
                        entity_id = %entity_id,
                        "span extraction failed, retrieved body from blob store"
                    );
                    return Some(blob_bytes);
                }
            }
        }

        debug!(
            entity_id = %entity_id,
            "no body available: span extraction failed and no blob_hash in metadata"
        );
        None
    })
}

/// Apply formatting policy to file content.
///
/// - `Preserve`: no transformation (identity).
/// - `Strip`: remove single-line comments (`//`, `#`), collapse consecutive blank
///   lines to one, and trim trailing whitespace on each line.
/// - `Minimal`: like Strip but also collapse multiple consecutive blank lines to zero
///   (single newline between non-empty lines).
fn apply_formatting_policy(content: &[u8], policy: FormattingPolicy) -> Vec<u8> {
    match policy {
        FormattingPolicy::Preserve => content.to_vec(),
        FormattingPolicy::Strip => {
            let text = String::from_utf8_lossy(content);
            let mut lines: Vec<String> = Vec::new();
            let mut prev_blank = false;
            for line in text.lines() {
                let trimmed = line.trim();
                // Skip pure comment lines.
                if trimmed.starts_with("//") || trimmed.starts_with('#') {
                    continue;
                }
                // Strip inline trailing comments (simple heuristic: " //" not inside strings).
                let cleaned = strip_trailing_comment(line);
                let cleaned = cleaned.trim_end();
                if cleaned.is_empty() {
                    if !prev_blank {
                        lines.push(String::new());
                        prev_blank = true;
                    }
                    // Collapse consecutive blanks to one.
                } else {
                    lines.push(cleaned.to_string());
                    prev_blank = false;
                }
            }
            // Remove trailing blank line.
            while lines.last().is_some_and(|l| l.is_empty()) {
                lines.pop();
            }
            let mut result = lines.join("\n");
            if !result.is_empty() {
                result.push('\n');
            }
            result.into_bytes()
        }
        FormattingPolicy::Minimal => {
            let text = String::from_utf8_lossy(content);
            let mut lines: Vec<String> = Vec::new();
            for line in text.lines() {
                let trimmed = line.trim();
                // Skip comment lines.
                if trimmed.starts_with("//") || trimmed.starts_with('#') {
                    continue;
                }
                // Skip blank lines entirely for minimal output.
                if trimmed.is_empty() {
                    continue;
                }
                let cleaned = strip_trailing_comment(line);
                lines.push(cleaned.trim_end().to_string());
            }
            let mut result = lines.join("\n");
            if !result.is_empty() {
                result.push('\n');
            }
            result.into_bytes()
        }
    }
}

/// Apply projection mode to file content.
///
/// - `Full`: no transformation.
/// - `Compact`: strip metadata comment blocks (`// @kin-meta ...`) and collapse
///   resulting blank lines.
fn apply_projection_mode(content: &[u8], mode: ProjectionMode) -> Vec<u8> {
    match mode {
        ProjectionMode::Full => content.to_vec(),
        ProjectionMode::Compact => {
            let text = String::from_utf8_lossy(content);
            let mut lines: Vec<String> = Vec::new();
            for line in text.lines() {
                let trimmed = line.trim();
                // Skip metadata comment lines.
                if trimmed.starts_with("// @kin-meta") || trimmed.starts_with("# @kin-meta") {
                    continue;
                }
                lines.push(line.to_string());
            }
            // Collapse consecutive blank lines to at most one.
            let mut result_lines: Vec<String> = Vec::new();
            let mut prev_blank = false;
            for line in lines {
                if line.trim().is_empty() {
                    if !prev_blank {
                        result_lines.push(String::new());
                        prev_blank = true;
                    }
                } else {
                    result_lines.push(line);
                    prev_blank = false;
                }
            }
            while result_lines.last().is_some_and(|l| l.is_empty()) {
                result_lines.pop();
            }
            let mut result = result_lines.join("\n");
            if !result.is_empty() {
                result.push('\n');
            }
            result.into_bytes()
        }
    }
}

/// Strip trailing `//` comment from a line (simple heuristic).
fn strip_trailing_comment(line: &str) -> &str {
    // Only strip if " //" appears (space before //) — avoid stripping URLs.
    if let Some(idx) = line.find(" //") {
        // Ensure it's not inside a string literal (very rough check:
        // count quotes before the comment position).
        let before = &line[..idx];
        let double_quotes = before.chars().filter(|&c| c == '"').count();
        if double_quotes % 2 == 0 {
            return &line[..idx];
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{FilePathId, ImportSection, SourceRegion};

    #[test]
    fn projection_state_register_and_get() {
        let mut state = ProjectionState::new();
        let layout = FileLayout {
            file_id: FilePathId::new("src/main.rs"),
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![],
        };
        state.register_file(layout, b"fn main() {}".to_vec());

        assert!(state.get_layout(&FilePathId::new("src/main.rs")).is_some());
        assert_eq!(
            state.get_content(&FilePathId::new("src/main.rs")),
            Some(b"fn main() {}".as_slice())
        );
    }

    #[test]
    fn project_single_entity_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let entity_id = EntityId::new();
        let file_id = FilePathId::new("test.rs");

        // Write original file.
        let original = b"// top\nold_body\n// bot";
        let file_path = dir.path().join("test.rs");
        std::fs::write(&file_path, original).unwrap();

        let layout = FileLayout {
            file_id: file_id.clone(),
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![
                SourceRegion::Trivia { byte_range: 0..7 },
                SourceRegion::EntityRef {
                    entity_id,
                    byte_range: 7..15,
                },
                SourceRegion::Trivia { byte_range: 15..21 },
            ],
        };

        let mut state = ProjectionState::new();
        state.register_file(layout, original.to_vec());

        let mut mutations = HashMap::new();
        mutations.insert(entity_id, b"new_body".to_vec());

        let modified = project_entity_mutations(&mut state, &mutations, dir.path()).unwrap();
        assert_eq!(modified.len(), 1);
        assert_eq!(modified[0], file_id);

        // Verify the file on disk.
        let content = std::fs::read(&file_path).unwrap();
        assert_eq!(content, b"// top\nnew_body\n// bot");
    }

    #[test]
    fn project_entity_not_in_any_layout() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = ProjectionState::new();
        let missing_id = EntityId::new();

        let mut mutations = HashMap::new();
        mutations.insert(missing_id, b"body".to_vec());

        // Should not error, just skip.
        let modified = project_entity_mutations(&mut state, &mutations, dir.path()).unwrap();
        assert!(modified.is_empty());
    }

    // ---------------------------------------------------------------
    // Formatting policy tests
    // ---------------------------------------------------------------

    #[test]
    fn formatting_preserve_is_identity() {
        let content = b"// comment\nfn foo() {}\n\n\n// another\nfn bar() {}\n";
        let result = apply_formatting_policy(content, FormattingPolicy::Preserve);
        assert_eq!(result, content.to_vec());
    }

    #[test]
    fn formatting_strip_removes_comments_and_collapses_blanks() {
        let content = b"// header comment\nfn foo() {}\n\n\n\nfn bar() {}\n// footer\n";
        let result = apply_formatting_policy(content, FormattingPolicy::Strip);
        let text = String::from_utf8(result).unwrap();
        assert!(!text.contains("// header"));
        assert!(!text.contains("// footer"));
        assert!(text.contains("fn foo() {}"));
        assert!(text.contains("fn bar() {}"));
        // Consecutive blanks should be collapsed.
        assert!(!text.contains("\n\n\n"));
    }

    #[test]
    fn formatting_minimal_removes_comments_and_blank_lines() {
        let content = b"// header\n\nfn foo() {}\n\n// mid\n\nfn bar() {}\n\n";
        let result = apply_formatting_policy(content, FormattingPolicy::Minimal);
        let text = String::from_utf8(result).unwrap();
        assert!(!text.contains("//"));
        assert!(!text.contains("\n\n")); // No consecutive blank lines.
        assert!(text.contains("fn foo() {}"));
        assert!(text.contains("fn bar() {}"));
    }

    #[test]
    fn formatting_strip_trims_trailing_whitespace() {
        let content = b"fn foo()   \nfn bar()  \n";
        let result = apply_formatting_policy(content, FormattingPolicy::Strip);
        let text = String::from_utf8(result).unwrap();
        for line in text.lines() {
            assert_eq!(line, line.trim_end(), "trailing whitespace not stripped");
        }
    }

    // ---------------------------------------------------------------
    // Projection mode tests
    // ---------------------------------------------------------------

    #[test]
    fn projection_full_is_identity() {
        let content = b"// @kin-meta entity-id: abc\nfn foo() {}\n";
        let result = apply_projection_mode(content, ProjectionMode::Full);
        assert_eq!(result, content.to_vec());
    }

    #[test]
    fn projection_compact_strips_metadata_comments() {
        let content =
            b"// @kin-meta entity-id: abc\nfn foo() {}\n// @kin-meta hash: def\nfn bar() {}\n";
        let result = apply_projection_mode(content, ProjectionMode::Compact);
        let text = String::from_utf8(result).unwrap();
        assert!(!text.contains("@kin-meta"));
        assert!(text.contains("fn foo() {}"));
        assert!(text.contains("fn bar() {}"));
    }

    #[test]
    fn projection_compact_collapses_resulting_blank_lines() {
        let content = b"fn foo() {}\n// @kin-meta x\n\nfn bar() {}\n";
        let result = apply_projection_mode(content, ProjectionMode::Compact);
        let text = String::from_utf8(result).unwrap();
        // After removing the metadata line, two blank lines would appear;
        // compact should collapse to at most one.
        assert!(!text.contains("\n\n\n"));
    }

    // ---------------------------------------------------------------
    // Policy-aware projection integration test
    // ---------------------------------------------------------------

    #[test]
    fn project_with_strip_formatting() {
        let dir = tempfile::tempdir().unwrap();
        let entity_id = EntityId::new();
        let file_id = FilePathId::new("test.rs");

        // Write original file with comments.
        let original = b"// header\nold_body\n// footer";
        let file_path = dir.path().join("test.rs");
        std::fs::write(&file_path, original).unwrap();

        let layout = FileLayout {
            file_id: file_id.clone(),
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![
                SourceRegion::Trivia { byte_range: 0..10 },
                SourceRegion::EntityRef {
                    entity_id,
                    byte_range: 10..18,
                },
                SourceRegion::Trivia { byte_range: 18..28 },
            ],
        };

        let mut state = ProjectionState::new();
        state.register_file(layout, original.to_vec());

        let mut mutations = HashMap::new();
        mutations.insert(entity_id, b"new_body".to_vec());

        let modified = project_entity_mutations_with_policy(
            &mut state,
            &mutations,
            dir.path(),
            FormattingPolicy::Strip,
            ProjectionMode::Full,
        )
        .unwrap();

        assert_eq!(modified.len(), 1);

        let content = std::fs::read(&file_path).unwrap();
        let text = String::from_utf8(content).unwrap();
        // Strip formatting removes comment lines.
        assert!(!text.contains("// header"));
        assert!(!text.contains("// footer"));
        assert!(text.contains("new_body"));
    }

    #[test]
    fn project_with_compact_mode() {
        let dir = tempfile::tempdir().unwrap();
        let entity_id = EntityId::new();
        let file_id = FilePathId::new("test.rs");

        let original = b"// @kin-meta id: abc\nold_body\ndata\n";
        let file_path = dir.path().join("test.rs");
        std::fs::write(&file_path, original).unwrap();

        let layout = FileLayout {
            file_id: file_id.clone(),
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![
                SourceRegion::Trivia { byte_range: 0..21 },
                SourceRegion::EntityRef {
                    entity_id,
                    byte_range: 21..29,
                },
                SourceRegion::Trivia { byte_range: 29..34 },
            ],
        };

        let mut state = ProjectionState::new();
        state.register_file(layout, original.to_vec());

        let mut mutations = HashMap::new();
        mutations.insert(entity_id, b"new_body".to_vec());

        let modified = project_entity_mutations_with_policy(
            &mut state,
            &mutations,
            dir.path(),
            FormattingPolicy::Preserve,
            ProjectionMode::Compact,
        )
        .unwrap();

        assert_eq!(modified.len(), 1);

        let content = std::fs::read(&file_path).unwrap();
        let text = String::from_utf8(content).unwrap();
        // Compact mode strips @kin-meta comments.
        assert!(!text.contains("@kin-meta"));
        assert!(text.contains("new_body"));
    }

    #[test]
    fn projection_temp_paths_do_not_collide_for_sibling_files_with_same_stem() {
        let dir = tempfile::tempdir().unwrap();
        let first_entity = EntityId::new();
        let second_entity = EntityId::new();
        let first_file = FilePathId::new("foo.ts");
        let second_file = FilePathId::new("foo.js");

        std::fs::write(dir.path().join("foo.ts"), "const first = oldFirst;\n").unwrap();
        std::fs::write(dir.path().join("foo.js"), "const second = oldSecond;\n").unwrap();

        let mut state = ProjectionState::new();
        state.register_file(
            FileLayout {
                file_id: first_file.clone(),
                imports: ImportSection {
                    byte_range: 0..0,
                    items: vec![],
                },
                regions: vec![SourceRegion::EntityRef {
                    entity_id: first_entity,
                    byte_range: 14..22,
                }],
            },
            b"const first = oldFirst;\n".to_vec(),
        );
        state.register_file(
            FileLayout {
                file_id: second_file.clone(),
                imports: ImportSection {
                    byte_range: 0..0,
                    items: vec![],
                },
                regions: vec![SourceRegion::EntityRef {
                    entity_id: second_entity,
                    byte_range: 15..24,
                }],
            },
            b"const second = oldSecond;\n".to_vec(),
        );

        let mut mutations = HashMap::new();
        mutations.insert(first_entity, b"newFirst".to_vec());
        mutations.insert(second_entity, b"newSecond".to_vec());

        let modified = project_entity_mutations_with_policy(
            &mut state,
            &mutations,
            dir.path(),
            FormattingPolicy::Preserve,
            ProjectionMode::Full,
        )
        .unwrap();

        assert_eq!(modified.len(), 2);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("foo.ts")).unwrap(),
            "const first = newFirst;\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("foo.js")).unwrap(),
            "const second = newSecond;\n"
        );
        assert!(!projection_tmp_path(&dir.path().join("foo.ts")).exists());
        assert!(!projection_tmp_path(&dir.path().join("foo.js")).exists());
    }
}
