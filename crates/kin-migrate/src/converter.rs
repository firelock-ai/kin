// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_blobs::BlobStore;
use kin_git::{import_git_history_with_blobs, GitImportMode, ImportOptions, ImportedChange};
use kin_model::SemanticChangeId;
use tracing::info;

use crate::error::{MigrateError, Result};
use crate::strategy::{MigrationPlan, MigrationStrategy};

/// Result of the conversion phase.
#[derive(Debug)]
pub struct ConversionResult {
    /// SemanticChange objects from Git history.
    pub imported_changes: Vec<ImportedChange>,
}

/// Convert a Git repository into Kin's semantic model.
///
/// This phase imports Git history as SemanticChange objects (via kin-git),
/// storing file contents in the blob store (via kin-blobs) as it goes.
///
/// Semantic enrichment is intentionally downstream of this exact import. The
/// executor resolves the admitted head tree and reads its bytes back from the
/// blob store; no workspace file participates in enrichment authority.
pub fn convert(
    plan: &MigrationPlan,
    genesis_id: SemanticChangeId,
    blob_store: &BlobStore,
) -> Result<ConversionResult> {
    let _span = tracing::info_span!(
        "kin.migrate.convert",
        source = %plan.source.display(),
        target = %plan.target.display(),
        strategy = ?plan.strategy
    )
    .entered();
    // Import Git history.
    let import_opts = ImportOptions {
        mode: match plan.strategy {
            MigrationStrategy::Snapshot => GitImportMode::Snapshot,
            MigrationStrategy::Full => GitImportMode::Full,
        },
        branch: plan.branch.clone(),
    };

    let imported = {
        let _span = tracing::info_span!(
            "kin.migrate.convert.import_git_history",
            mode = ?import_opts.mode,
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

    Ok(ConversionResult {
        imported_changes: imported,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_result_tracks_imported_changes() {
        let result = ConversionResult {
            imported_changes: vec![],
        };
        assert!(result.imported_changes.is_empty());
    }
}
