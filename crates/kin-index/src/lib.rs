// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Graph build and update pipeline for Kin.
//!
//! This crate orchestrates file parsing, blob storage, and graph updates.
//! It also provides a file watcher for incremental re-indexing.
//!
//! Key design: the indexer proposes deltas for an exact graph-owned
//! `WorkspaceState`. It does not create `SemanticChange` history on its own;
//! repository authority commits workspace and history transitions atomically.

#[cfg(all(test, unix))]
#[test]
fn kin_process_group_guardian_worker() {
    let requested = std::env::var_os(kin_daemon_spawn::PROCESS_GROUP_GUARDIAN_MODE_ENV).is_some();
    let dispatched = kin_daemon_spawn::run_process_group_guardian_if_requested()
        .expect("run Kin index fixture process-group guardian");
    assert_eq!(dispatched, requested);
}

pub mod admission;
pub mod artifacts;
pub mod classifier;
pub mod error;
pub mod fingerprint;
pub mod history;
pub mod linker;
pub mod overlay;
pub mod pipeline;
pub mod repository;
pub mod support;
pub mod watcher;

pub use admission::{
    enforce_sensitive_admission, is_intrinsic_repository_control_path, AdmissionCase,
    AdmissionDecision, AdmissionDecisionReason, AdmissionMatcherError, AdmissionRuleProvenance,
    AdmissionRuleSource, ResolvedAdmissionMatcher, ResolvedAdmissionRuleSet,
    SensitiveAdmissionError, SensitiveFindingKind,
};
pub use artifacts::extract_artifact;
pub use classifier::{FileClassification, FileClassifier};
pub use error::{IndexError, Result};
pub use fingerprint::{
    behavior_equivalence_hash, compute_entity_fingerprint, language_supports_equivalence,
};
pub use history::{
    derive_historical_semantic_deltas, is_external_reference_target, HistoricalSemanticDelta,
};
pub use linker::{
    bare_entity_name, build_projection_derived_relations_for_file,
    build_projection_derived_relations_from_markers, extract_projection_source_markers,
    link_cross_file, link_cross_file_against_entities,
    link_cross_file_against_entities_with_completeness, link_cross_file_borrowed_with_completeness,
    link_cross_file_incremental, link_cross_file_incremental_with_completeness,
    link_cross_file_with_completeness, CrossFileLinker, FileParseCompletenessMap, FileParseData,
    IncrementalLinker, IncrementalLinkerCheckpointV1, LinkingOutcome, UnresolvedRelation,
    CALL_SHAPE_EVIDENCE_AGGREGATION_V1, CALL_SHAPE_EVIDENCE_INCOMPLETE_EXTRACTION_V1,
    CALL_SHAPE_EVIDENCE_INCOMPLETE_PARSE_V1, CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1,
    CALL_SHAPE_PARSE_COVERAGE_FULL_V1, CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1,
    INCREMENTAL_LINKER_CHECKPOINT_VERSION, KIN_INDEX_CRATE_VERSION,
};
pub use linker::{is_external_import_placeholder, EXTERNAL_IMPORT_REFERENCE_RULE};
pub use overlay::{apply_file_removal, apply_to_graph, ApplyResult};
pub use pipeline::{
    classify_file_role, normalize_file_path_id, IndexPipeline, IndexedAny, IndexedFile,
    COMMAND_EFFECT_CONTRACT_KEY,
};
pub use repository::{
    host_path_from_repo_path, is_repository_control_path, read_verified_scanned_entry,
    repo_path_from_host_relative, scan_repository, scan_repository_preserving_graph_only,
    should_track_host_relative_path, tracked_paths_covered_by_ignore,
    tracked_paths_retracted_by_ignore, CompleteRepositoryScan, CompleteScanToken,
    IgnoredTrackedPaths, IncompleteRepositoryScan, RepositoryIgnore, RepositoryScanDiagnostics,
    ScannedEntryKind, ScannedRepositoryEntry, DEFAULT_IGNORED_NAMES, PYTHON_VIRTUALENV_MARKER,
};
pub use support::{compute_coverage_report, CoverageReport};
pub use watcher::{FileEvent, FileWatcher};

use std::path::Path;

/// Returns true only for Kin/Git control directories.
pub fn should_skip_dir(name: &str) -> bool {
    kin_model::RepoPath::from_utf8(name)
        .map(|path| is_repository_control_path(&path))
        .unwrap_or(false)
}

/// Returns true when a repo-relative host path is not Kin/Git control metadata.
pub fn should_index_repo_relative_path(path: &Path) -> bool {
    should_track_host_relative_path(path)
}

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
        assert_eq!(langs.len(), 14);
    }

    #[test]
    fn indexer_default() {
        let indexer = Indexer::default();
        assert_eq!(
            indexer.pipeline().registry().supported_languages().len(),
            14
        );
    }
}
