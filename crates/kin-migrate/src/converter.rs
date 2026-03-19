// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use std::path::Path;

use kin_blobs::BlobStore;
use kin_git::{import_git_history_with_blobs, ImportOptions, ImportedChange};
use kin_index::IndexPipeline;
use kin_model::SemanticChangeId;
use tracing::info;

use crate::error::{MigrateError, Result};
use crate::strategy::{MigrationPlan, MigrationStrategy};

/// Result of the conversion phase.
#[derive(Debug)]
pub struct ConversionResult {
    /// SemanticChange objects from Git history.
    pub imported_changes: Vec<ImportedChange>,
    /// Number of source files indexed for entities.
    pub files_indexed: usize,
    /// Total entities extracted.
    pub entities_extracted: usize,
    /// Total relations extracted.
    pub relations_extracted: usize,
}

/// Convert a Git repository into Kin's semantic model.
///
/// This phase:
/// 1. Imports Git history as SemanticChange objects (via kin-git)
/// 2. Indexes source files to extract entities and relations (via kin-index)
/// 3. Stores file contents in the blob store (via kin-blobs)
pub fn convert(
    plan: &MigrationPlan,
    genesis_id: SemanticChangeId,
    blob_store: &BlobStore,
) -> Result<ConversionResult> {
    // Step 1: Import Git history.
    let import_opts = ImportOptions {
        shallow: plan.strategy == MigrationStrategy::Shallow,
        max_commits: plan.max_commits,
        branch: plan.branch.clone(),
    };

    let imported =
        import_git_history_with_blobs(&plan.source, genesis_id, &import_opts, Some(blob_store))
            .map_err(|e| MigrateError::GitImport(e.to_string()))?;

    info!(
        changes = imported.len(),
        strategy = ?plan.strategy,
        "imported git history"
    );

    // Step 2: Index source files for entity extraction.
    let pipeline = IndexPipeline::new();
    let mut files_indexed = 0usize;
    let mut entities_extracted = 0usize;
    let mut relations_extracted = 0usize;

    for rel_path in &plan.source_files {
        let abs_path = plan.source.join(rel_path);
        if !abs_path.exists() {
            continue;
        }

        match pipeline.index_file(&abs_path, blob_store) {
            Ok(indexed) => {
                files_indexed += 1;
                entities_extracted += indexed.entities.len();
                relations_extracted += indexed.relations.len();
            }
            Err(e) => {
                // Non-fatal: skip files that can't be parsed.
                tracing::debug!(
                    path = %rel_path.display(),
                    error = %e,
                    "skipping file during migration"
                );
            }
        }
    }

    info!(
        files_indexed = files_indexed,
        entities = entities_extracted,
        relations = relations_extracted,
        "source file indexing complete"
    );

    Ok(ConversionResult {
        imported_changes: imported,
        files_indexed,
        entities_extracted,
        relations_extracted,
    })
}

/// Index a single file and store results in the graph.
///
/// Convenience wrapper for re-indexing individual files after migration.
pub fn index_single_file<G: kin_model::GraphStore>(
    path: &Path,
    blob_store: &BlobStore,
    graph: &G,
) -> Result<()> {
    let pipeline = IndexPipeline::new();
    pipeline
        .index_and_store(path, blob_store, graph)
        .map_err(|e| MigrateError::Index(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_result_tracks_counts() {
        let result = ConversionResult {
            imported_changes: vec![],
            files_indexed: 5,
            entities_extracted: 20,
            relations_extracted: 10,
        };
        assert_eq!(result.files_indexed, 5);
        assert_eq!(result.entities_extracted, 20);
        assert_eq!(result.relations_extracted, 10);
    }
}
