// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

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

    /// Rebuild projection state from persisted graph truth only.
    ///
    /// This loads each persisted `FileLayout` and its blob-backed base file
    /// content from the graph snapshot, without consulting the working tree.
    pub fn from_graph<G>(graph: &G, blob_store: &BlobStore) -> Result<Self>
    where
        G: GraphStore,
    {
        let mut state = Self::new();
        let layouts = graph
            .list_file_layouts()
            .map_err(|err| ProjectionError::Graph(err.to_string()))?;

        for layout in layouts {
            let Some(file_hash) = graph
                .get_file_hash(&layout.file_id)
                .map_err(|err| ProjectionError::Graph(err.to_string()))?
            else {
                return Err(ProjectionError::BaseContentUnavailable {
                    file_id: layout.file_id.to_string(),
                    reason: "missing persisted file hash".to_string(),
                });
            };

            let content =
                blob_store
                    .read(&file_hash)
                    .map_err(|err| ProjectionError::BaseContentUnavailable {
                        file_id: layout.file_id.to_string(),
                        reason: format!("failed to read blob-backed file content: {err}"),
                    })?;
            state.register_file(layout, content);
        }

        Ok(state)
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
    for (committed, (tmp_path, file_path, file_id, new_content)) in prepared.into_iter().enumerate()
    {
        // RACE CONDITION HARDENING: Before committing the rename, verify
        // the file on disk still matches the content we based our splices
        // on. A concurrent editor could have written new content between
        // the reconcile (which cached the original) and now. Overwriting
        // would silently lose the editor's changes. Skip this file and
        // let the next reconcile tick handle it.
        if file_path.exists() {
            if let Some(original) = state.file_contents.get(&file_id) {
                match std::fs::read(&file_path) {
                    Ok(on_disk) if on_disk != *original => {
                        debug!(
                            file = %file_id,
                            "file modified by concurrent editor during projection, skipping"
                        );
                        let _ = std::fs::remove_file(&tmp_path);
                        continue;
                    }
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                        debug!(
                            file = %file_id,
                            error = %e,
                            "failed to read file for pre-write verification, skipping"
                        );
                        let _ = std::fs::remove_file(&tmp_path);
                        continue;
                    }
                    _ => {
                        // Content matches or file was just deleted — safe to proceed.
                    }
                }
            }
        }

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

fn extract_projected_entity_body<G>(
    entity_id: &EntityId,
    graph: &G,
    original_content: &[u8],
    blob_store: &BlobStore,
) -> Result<Vec<u8>>
where
    G: GraphStore,
{
    let entity = graph
        .get_entity(entity_id)
        .map_err(|err| ProjectionError::Graph(err.to_string()))?
        .ok_or_else(|| ProjectionError::BodyUnavailable {
            entity_id: entity_id.to_string(),
            reason: "entity missing from graph".to_string(),
        })?;

    if let Some(ref span) = entity.span {
        if span.start_byte < span.end_byte && span.end_byte <= original_content.len() {
            return Ok(original_content[span.start_byte..span.end_byte].to_vec());
        }
    }

    if let Some(serde_json::Value::String(hex)) = entity.metadata.extra.get("blob_hash") {
        let hash =
            kin_blobs::Hash256::from_hex(hex).map_err(|_| ProjectionError::BodyUnavailable {
                entity_id: entity_id.to_string(),
                reason: format!("invalid blob_hash metadata `{hex}`"),
            })?;
        return blob_store
            .read(&hash)
            .map_err(|err| ProjectionError::BodyUnavailable {
                entity_id: entity_id.to_string(),
                reason: format!("failed to read blob body: {err}"),
            });
    }

    Err(ProjectionError::BodyUnavailable {
        entity_id: entity_id.to_string(),
        reason: "span extraction failed and no blob_hash in metadata".to_string(),
    })
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
    let mut entity_bodies = HashMap::new();
    for region in &layout.regions {
        if let SourceRegion::EntityRef { entity_id, .. } = region {
            let body =
                extract_projected_entity_body(entity_id, graph, original_content, blob_store)?;
            entity_bodies.insert(*entity_id, body);
        }
    }

    crate::splice::reconstruct_file(original_content, layout, |entity_id| {
        entity_bodies.get(entity_id).cloned()
    })
}

/// Project entity mutations onto base file content, returning the result as bytes.
/// Pure function — no disk I/O, no temp files.
///
/// # Arguments
/// * `base_content` — original file content from blob store
/// * `layout` — FileLayout describing entity regions in the file
/// * `mutations` — map of EntityId → new entity body bytes
///
/// # Returns
/// Projected content with mutations spliced in, or base_content unchanged if no mutations apply.
pub fn project_to_bytes(
    base_content: &[u8],
    layout: &FileLayout,
    mutations: &HashMap<EntityId, Vec<u8>>,
) -> Result<Vec<u8>> {
    let mut splices = Vec::new();

    for region in &layout.regions {
        if let SourceRegion::EntityRef {
            entity_id,
            byte_range,
        } = region
        {
            if let Some(new_body) = mutations.get(entity_id) {
                splices.push(Splice {
                    byte_range: byte_range.clone(),
                    new_content: new_body.clone(),
                });
            }
        }
    }

    if splices.is_empty() {
        return Ok(base_content.to_vec());
    }

    apply_splices(base_content, splices)
}

/// Given a full file's base content, its layout, and overlay entity bodies,
/// compute the projected content. Returns None if no mutations affect this file.
pub fn project_overlay_to_bytes(
    base_content: &[u8],
    layout: &FileLayout,
    overlay_bodies: &HashMap<EntityId, Vec<u8>>,
) -> Result<Option<Vec<u8>>> {
    let has_overlap = layout.regions.iter().any(|region| {
        matches!(region, SourceRegion::EntityRef { entity_id, .. } if overlay_bodies.contains_key(entity_id))
    });

    if !has_overlap {
        return Ok(None);
    }

    project_to_bytes(base_content, layout, overlay_bodies).map(Some)
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
    use kin_blobs::BlobStore;
    use kin_db::InMemoryGraph;
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, EntityStore, FilePathId,
        FingerprintAlgorithm, ImportSection, LanguageId, ParseCompleteness, SemanticFingerprint,
        SourceRegion, SourceSpan, Visibility,
    };

    fn make_entity(
        entity_id: EntityId,
        file: &str,
        signature: &str,
        span: Option<SourceSpan>,
    ) -> Entity {
        Entity {
            id: entity_id,
            kind: EntityKind::Function,
            name: "projected".to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: kin_model::Hash256::from_bytes([1; 32]),
                signature_hash: kin_model::Hash256::from_bytes([2; 32]),
                behavior_hash: kin_model::Hash256::from_bytes([3; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span,
            signature: signature.to_string(),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn projection_state_register_and_get() {
        let mut state = ProjectionState::new();
        let layout = FileLayout {
            file_id: FilePathId::new("src/main.rs"),
            parse_completeness: ParseCompleteness::Full,
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
    fn projection_state_rebuilds_from_graph_truth_without_worktree_files() {
        let graph = InMemoryGraph::new();
        let blob_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(blob_dir.path().to_path_buf()).unwrap();
        let file_id = FilePathId::new("src/main.rs");
        let content = b"fn main() { println!(\"graph truth\"); }\n".to_vec();
        let hash = blob_store.write(&content).unwrap();
        graph.set_file_hash(&file_id.0, hash.0);
        graph
            .upsert_file_layout(&FileLayout {
                file_id: file_id.clone(),
                parse_completeness: ParseCompleteness::Full,
                imports: ImportSection {
                    byte_range: 0..0,
                    items: vec![],
                },
                regions: vec![],
            })
            .unwrap();

        let state = ProjectionState::from_graph(&graph, &blob_store).unwrap();

        assert_eq!(state.file_ids(), vec![&file_id]);
        assert_eq!(state.get_content(&file_id), Some(content.as_slice()));
    }

    #[test]
    fn projection_state_from_graph_errors_when_file_hash_missing() {
        let graph = InMemoryGraph::new();
        let blob_dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(blob_dir.path().to_path_buf()).unwrap();
        let file_id = FilePathId::new("src/missing.rs");
        graph
            .upsert_file_layout(&FileLayout {
                file_id: file_id.clone(),
                parse_completeness: ParseCompleteness::Full,
                imports: ImportSection {
                    byte_range: 0..0,
                    items: vec![],
                },
                regions: vec![],
            })
            .unwrap();

        let err = ProjectionState::from_graph(&graph, &blob_store).unwrap_err();
        assert!(matches!(
            err,
            ProjectionError::BaseContentUnavailable { file_id: missing, .. } if missing == file_id.to_string()
        ));
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
            parse_completeness: ParseCompleteness::Full,
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
            parse_completeness: ParseCompleteness::Full,
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
            parse_completeness: ParseCompleteness::Full,
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
    fn project_file_from_entities_errors_when_body_cannot_be_recovered() {
        let dir = tempfile::tempdir().unwrap();
        let file_name = "switch.rs";
        let entity_id = EntityId::new();
        let layout = FileLayout {
            file_id: FilePathId::new(file_name),
            parse_completeness: ParseCompleteness::Full,
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![SourceRegion::EntityRef {
                entity_id,
                byte_range: 0..10,
            }],
        };
        let original = b"old_body()";
        let graph = InMemoryGraph::default();
        let blob_store = BlobStore::new(dir.path().join("objects")).unwrap();

        let entity = make_entity(entity_id, file_name, "fn projected()", None);
        graph.upsert_entity(&entity).unwrap();

        let err = project_file_from_entities(&layout, original, &graph, &blob_store).unwrap_err();
        assert!(matches!(err, ProjectionError::BodyUnavailable { .. }));
        assert_eq!(
            err.to_string(),
            format!(
                "body unavailable for entity {}: span extraction failed and no blob_hash in metadata",
                entity_id
            )
        );
    }

    #[test]
    fn project_file_from_entities_uses_blob_body_when_span_is_stale() {
        let dir = tempfile::tempdir().unwrap();
        let file_name = "switch.rs";
        let entity_id = EntityId::new();
        let layout = FileLayout {
            file_id: FilePathId::new(file_name),
            parse_completeness: ParseCompleteness::Full,
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![SourceRegion::EntityRef {
                entity_id,
                byte_range: 0..10,
            }],
        };
        let original = b"old_body()";
        let graph = InMemoryGraph::default();
        let blob_store = BlobStore::new(dir.path().join("objects")).unwrap();
        let blob_hash = blob_store.write(b"new_body()").unwrap();

        let mut entity = make_entity(
            entity_id,
            file_name,
            "fn projected()",
            Some(SourceSpan {
                file: FilePathId::new(file_name),
                start_byte: 50,
                end_byte: 60,
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: 10,
            }),
        );
        entity.metadata.extra.insert(
            "blob_hash".into(),
            serde_json::Value::String(blob_hash.to_string()),
        );
        graph.upsert_entity(&entity).unwrap();

        let projected = project_file_from_entities(&layout, original, &graph, &blob_store).unwrap();
        assert_eq!(projected, b"new_body()");
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
                parse_completeness: ParseCompleteness::Full,
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
                parse_completeness: ParseCompleteness::Full,
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

    // ---------------------------------------------------------------
    // project_to_bytes tests
    // ---------------------------------------------------------------

    fn make_test_layout(entity_id: EntityId) -> FileLayout {
        FileLayout {
            file_id: FilePathId::new("test.rs"),
            parse_completeness: ParseCompleteness::Full,
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
        }
    }

    #[test]
    fn project_to_bytes_no_mutations_returns_base() {
        let base = b"// top\nold_body\n// bot";
        let entity_id = EntityId::new();
        let layout = make_test_layout(entity_id);
        let mutations = HashMap::new();

        let result = project_to_bytes(base, &layout, &mutations).unwrap();
        assert_eq!(result, base.to_vec());
    }

    #[test]
    fn project_to_bytes_single_mutation() {
        let base = b"// top\nold_body\n// bot";
        let entity_id = EntityId::new();
        let layout = make_test_layout(entity_id);

        let mut mutations = HashMap::new();
        mutations.insert(entity_id, b"new_body".to_vec());

        let result = project_to_bytes(base, &layout, &mutations).unwrap();
        assert_eq!(result, b"// top\nnew_body\n// bot");
    }

    #[test]
    fn project_to_bytes_multiple_mutations() {
        // "// top\nfirst___\nmiddle\nsecond__\n// bot"
        //  0----7  7-----15 15---23  23----31 31---38
        let base = b"// top\nfirst___\nmiddle\nsecond__\n// bot";
        assert_eq!(base.len(), 38);
        let eid1 = EntityId::new();
        let eid2 = EntityId::new();
        let layout = FileLayout {
            file_id: FilePathId::new("multi.rs"),
            parse_completeness: ParseCompleteness::Full,
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![
                SourceRegion::Trivia { byte_range: 0..7 },
                SourceRegion::EntityRef {
                    entity_id: eid1,
                    byte_range: 7..15,
                },
                SourceRegion::Trivia { byte_range: 15..23 },
                SourceRegion::EntityRef {
                    entity_id: eid2,
                    byte_range: 23..31,
                },
                SourceRegion::Trivia { byte_range: 31..38 },
            ],
        };

        let mut mutations = HashMap::new();
        mutations.insert(eid1, b"FIRST___".to_vec());
        mutations.insert(eid2, b"SECOND__".to_vec());

        let result = project_to_bytes(base, &layout, &mutations).unwrap();
        assert_eq!(result, b"// top\nFIRST___\nmiddle\nSECOND__\n// bot");
    }

    #[test]
    fn project_to_bytes_mutation_not_in_layout_ignored() {
        let base = b"// top\nold_body\n// bot";
        let entity_id = EntityId::new();
        let layout = make_test_layout(entity_id);

        let missing_id = EntityId::new();
        let mut mutations = HashMap::new();
        mutations.insert(missing_id, b"ghost".to_vec());

        let result = project_to_bytes(base, &layout, &mutations).unwrap();
        assert_eq!(result, base.to_vec());
    }

    #[test]
    fn project_to_bytes_empty_base() {
        let base = b"";
        let layout = FileLayout {
            file_id: FilePathId::new("empty.rs"),
            parse_completeness: ParseCompleteness::Full,
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![],
        };
        let mutations = HashMap::new();

        let result = project_to_bytes(base, &layout, &mutations).unwrap();
        assert_eq!(result, b"");
    }

    #[test]
    fn project_to_bytes_mutation_changes_size() {
        let base = b"// top\nold_body\n// bot";
        let entity_id = EntityId::new();
        let layout = make_test_layout(entity_id);

        let mut mutations = HashMap::new();
        mutations.insert(entity_id, b"much_longer_new_body_content".to_vec());

        let result = project_to_bytes(base, &layout, &mutations).unwrap();
        assert_eq!(result, b"// top\nmuch_longer_new_body_content\n// bot");
    }

    #[test]
    fn project_to_bytes_large_file_small_mutation() {
        // 100KB+ file with a small entity mutation.
        let mut base = vec![b' '; 100 * 1024];
        // Place entity body at bytes 50000..50008.
        base[50000..50008].copy_from_slice(b"old_body");

        let entity_id = EntityId::new();
        let layout = FileLayout {
            file_id: FilePathId::new("big.rs"),
            parse_completeness: ParseCompleteness::Full,
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![
                SourceRegion::Trivia {
                    byte_range: 0..50000,
                },
                SourceRegion::EntityRef {
                    entity_id,
                    byte_range: 50000..50008,
                },
                SourceRegion::Trivia {
                    byte_range: 50008..base.len(),
                },
            ],
        };

        let mut mutations = HashMap::new();
        mutations.insert(entity_id, b"new_body".to_vec());

        let result = project_to_bytes(&base, &layout, &mutations).unwrap();
        assert_eq!(result.len(), base.len());
        assert_eq!(&result[50000..50008], b"new_body");
        // Trivia before and after unchanged.
        assert_eq!(&result[0..50000], &base[0..50000]);
        assert_eq!(&result[50008..], &base[50008..]);
    }

    // ---------------------------------------------------------------
    // project_overlay_to_bytes tests
    // ---------------------------------------------------------------

    #[test]
    fn overlay_no_overlap_returns_none() {
        let base = b"// top\nold_body\n// bot";
        let entity_id = EntityId::new();
        let layout = make_test_layout(entity_id);

        let missing_id = EntityId::new();
        let mut overlay = HashMap::new();
        overlay.insert(missing_id, b"ghost".to_vec());

        let result = project_overlay_to_bytes(base, &layout, &overlay).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn overlay_empty_returns_none() {
        let base = b"// top\nold_body\n// bot";
        let entity_id = EntityId::new();
        let layout = make_test_layout(entity_id);
        let overlay = HashMap::new();

        let result = project_overlay_to_bytes(base, &layout, &overlay).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn overlay_with_overlap_returns_projected() {
        let base = b"// top\nold_body\n// bot";
        let entity_id = EntityId::new();
        let layout = make_test_layout(entity_id);

        let mut overlay = HashMap::new();
        overlay.insert(entity_id, b"new_body".to_vec());

        let result = project_overlay_to_bytes(base, &layout, &overlay).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"// top\nnew_body\n// bot");
    }

    #[test]
    fn overlay_partial_overlap() {
        // Overlay has some entities from the layout plus some unrelated ones.
        let base = b"// top\nold_body\n// bot";
        let entity_id = EntityId::new();
        let layout = make_test_layout(entity_id);

        let unrelated_id = EntityId::new();
        let mut overlay = HashMap::new();
        overlay.insert(entity_id, b"new_body".to_vec());
        overlay.insert(unrelated_id, b"irrelevant".to_vec());

        let result = project_overlay_to_bytes(base, &layout, &overlay).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"// top\nnew_body\n// bot");
    }
}
