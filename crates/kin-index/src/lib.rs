// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Graph build and update pipeline for Kin.
//!
//! This crate orchestrates file parsing, blob storage, and graph updates.
//! It also provides a file watcher for incremental re-indexing.
//!
//! Key design: the indexer updates the WorkingCopy overlay only. It does NOT
//! create SemanticChange nodes — that is `kin commit`'s job.

pub mod artifacts;
pub mod classifier;
pub mod error;
pub mod fingerprint;
pub mod linker;
pub mod overlay;
pub mod pipeline;
pub mod support;
pub mod watcher;

pub use artifacts::extract_artifact;
pub use classifier::{FileClassification, FileClassifier};
pub use error::{IndexError, Result};
pub use fingerprint::compute_entity_fingerprint;
pub use linker::{
    link_cross_file, CrossFileLinker, FileParseData, LinkingOutcome, UnresolvedRelation,
};
pub use overlay::{apply_file_removal, apply_to_graph, ApplyResult};
pub use pipeline::{normalize_file_path_id, IndexPipeline, IndexedAny, IndexedFile};
pub use support::{compute_coverage_report, CoverageReport};
pub use watcher::{FileEvent, FileWatcher};

use std::path::Path;

use kin_blobs::BlobStore;
use kin_model::GraphStore;
use tracing::debug;

/// Top-level indexer that combines parsing, blob storage, and graph overlay updates.
///
/// This is the primary entry point for the daemon's indexing loop. It wraps
/// `IndexPipeline` and `overlay::apply_to_graph` into a single operation.
pub struct Indexer {
    pipeline: IndexPipeline,
}

impl Indexer {
    pub fn new() -> Self {
        Self {
            pipeline: IndexPipeline::new(),
        }
    }

    /// Index a single file and apply results to the graph.
    ///
    /// Returns the apply result. If the parse was broken (ERROR nodes),
    /// the graph is left unchanged (LKG preserved).
    pub fn index_and_apply<G: GraphStore>(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        graph: &G,
    ) -> Result<ApplyResult> {
        let indexed = self.pipeline.index_file(path, blob_store)?;
        let result = apply_to_graph(graph, &indexed)?;

        debug!(
            path = %path.display(),
            upserted = result.entities_upserted,
            removed = result.entities_removed,
            skipped = result.skipped_lkg,
            "index_and_apply complete"
        );

        Ok(result)
    }

    /// Handle a file removal by clearing its entities from the graph.
    pub fn handle_removal<G: GraphStore>(&self, path: &Path, graph: &G) -> Result<ApplyResult> {
        let file_id = kin_model::FilePathId::new(path.display().to_string());
        apply_file_removal(graph, &file_id)
    }

    /// Get the underlying pipeline for direct use.
    pub fn pipeline(&self) -> &IndexPipeline {
        &self.pipeline
    }
}

impl Default for Indexer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexer_creates() {
        let indexer = Indexer::new();
        let langs = indexer.pipeline().registry().supported_languages();
        assert_eq!(langs.len(), 10);
    }

    #[test]
    fn indexer_default() {
        let indexer = Indexer::default();
        assert_eq!(
            indexer.pipeline().registry().supported_languages().len(),
            10
        );
    }
}
