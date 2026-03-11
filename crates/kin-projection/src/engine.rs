use std::collections::HashMap;
use std::path::Path;

use kin_blobs::BlobStore;
use kin_model::{EntityId, FileLayout, FilePathId, GraphStore, SourceRegion};
use tracing::debug;

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
pub fn project_entity_mutations(
    state: &mut ProjectionState,
    mutations: &HashMap<EntityId, Vec<u8>>,
    working_dir: &Path,
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

    // Apply splices per file and write to disk.
    for (file_id, splices) in file_mutations {
        let original = state
            .file_contents
            .get(&file_id)
            .ok_or_else(|| ProjectionError::LayoutNotFound(file_id.to_string()))?;

        let new_content = apply_splices(original, splices)?;

        // Write to working directory.
        let file_path = working_dir.join(&file_id.0);
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ProjectionError::io(parent, e))?;
        }
        std::fs::write(&file_path, &new_content).map_err(|e| ProjectionError::io(&file_path, e))?;

        // Update cached content.
        state.file_contents.insert(file_id.clone(), new_content);

        debug!(file = %file_id, "projected mutations to file");
        modified_files.push(file_id);
    }

    Ok(modified_files)
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

        let _ = blob_store;
        None
    })
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
}
