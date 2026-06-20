// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::Path;

use kin_blobs::BlobStore;
use kin_git::{import_git_history_with_blobs, ImportOptions, ImportedChange};
use kin_index::IndexPipeline;
use kin_model::SemanticChangeId;
use rayon::prelude::*;
use tracing::info;

use crate::error::{MigrateError, Result};
use crate::resource_threads::{proof_profile_requested, with_resource_rayon_pool};
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

#[derive(Debug, Default, Clone, Copy)]
struct SourceIndexCounts {
    files_indexed: usize,
    entities_extracted: usize,
    relations_extracted: usize,
}

fn merge_source_index_counts(
    left: SourceIndexCounts,
    right: SourceIndexCounts,
) -> SourceIndexCounts {
    SourceIndexCounts {
        files_indexed: left.files_indexed + right.files_indexed,
        entities_extracted: left.entities_extracted + right.entities_extracted,
        relations_extracted: left.relations_extracted + right.relations_extracted,
    }
}

fn index_source_file_counts(
    plan: &MigrationPlan,
    blob_store: &BlobStore,
    rel_path: &std::path::Path,
) -> SourceIndexCounts {
    let abs_path = plan.source.join(rel_path);
    if !abs_path.exists() {
        return SourceIndexCounts::default();
    }

    let pipeline = IndexPipeline::new();
    match pipeline.index_file(&abs_path, blob_store) {
        Ok(indexed) => SourceIndexCounts {
            files_indexed: 1,
            entities_extracted: indexed.entities.len(),
            relations_extracted: indexed.relations.len(),
        },
        Err(e) => {
            // Non-fatal: skip files that can't be parsed.
            tracing::debug!(
                path = %rel_path.display(),
                error = %e,
                "skipping file during migration"
            );
            SourceIndexCounts::default()
        }
    }
}

fn index_source_files_serial(plan: &MigrationPlan, blob_store: &BlobStore) -> SourceIndexCounts {
    plan.source_files
        .iter()
        .map(|rel_path| index_source_file_counts(plan, blob_store, rel_path))
        .fold(SourceIndexCounts::default(), merge_source_index_counts)
}

fn index_source_files_parallel(
    plan: &MigrationPlan,
    blob_store: &BlobStore,
) -> Result<SourceIndexCounts> {
    with_resource_rayon_pool("convert.index_source_files", || {
        Ok(plan
            .source_files
            .par_iter()
            .map(|rel_path| index_source_file_counts(plan, blob_store, rel_path))
            .reduce(SourceIndexCounts::default, merge_source_index_counts))
    })
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
    let _span = tracing::info_span!(
        "kin.migrate.convert",
        source = %plan.source.display(),
        target = %plan.target.display(),
        strategy = ?plan.strategy,
        files = plan.source_files.len()
    )
    .entered();
    // Step 1: Import Git history.
    let import_opts = ImportOptions {
        shallow: plan.strategy == MigrationStrategy::Shallow,
        max_commits: plan.max_commits,
        branch: plan.branch.clone(),
    };

    let imported = {
        let _span = tracing::info_span!(
            "kin.migrate.convert.import_git_history",
            shallow = import_opts.shallow,
            max_commits = import_opts.max_commits,
            has_branch = import_opts.branch.is_some()
        )
        .entered();
        import_git_history_with_blobs(&plan.source, genesis_id, &import_opts, Some(blob_store))
            .map_err(|e| MigrateError::GitImport(e.to_string()))?
    };

    info!(
        changes = imported.len(),
        strategy = ?plan.strategy,
        "imported git history"
    );

    // Step 2: Index source files for entity extraction.
    let _span = tracing::info_span!(
        "kin.migrate.convert.index_source_files",
        files = plan.source_files.len()
    )
    .entered();
    let counts = if proof_profile_requested()? {
        index_source_files_serial(plan, blob_store)
    } else {
        index_source_files_parallel(plan, blob_store)?
    };

    info!(
        files_indexed = counts.files_indexed,
        entities = counts.entities_extracted,
        relations = counts.relations_extracted,
        "source file indexing complete"
    );

    Ok(ConversionResult {
        imported_changes: imported,
        files_indexed: counts.files_indexed,
        entities_extracted: counts.entities_extracted,
        relations_extracted: counts.relations_extracted,
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
