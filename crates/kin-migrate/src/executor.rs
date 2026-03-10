use std::time::Instant;

use chrono::{DateTime, Utc};
use kin_blobs::BlobStore;
use kin_core::{build_genesis_change, init};
use kin_model::GraphStore;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::converter::convert;
use crate::error::{MigrateError, Result};
use crate::scanner::scan_repo;
use crate::strategy::{plan_migration, MigrationPlan, MigrationStrategy};

/// Result of a completed migration.
#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationResult {
    /// Path to the Kin repository root.
    pub kin_root: String,
    /// Migration strategy used.
    pub strategy: MigrationStrategy,
    /// Number of Git commits imported as SemanticChange objects.
    pub commits_imported: usize,
    /// Number of source files indexed.
    pub files_indexed: usize,
    /// Total entities extracted from source files.
    pub entities_extracted: usize,
    /// Total relations extracted.
    pub relations_extracted: usize,
    /// Genesis change ID.
    pub genesis_id: String,
    /// Default branch name.
    pub default_branch: Option<String>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// When the migration was completed.
    pub completed_at: DateTime<Utc>,
}

/// Execute a full migration: scan -> plan -> init -> convert -> commit to graph.
///
/// This is the top-level entry point for `kin migrate`. It orchestrates:
/// 1. Scanning the source Git repo
/// 2. Planning the migration (shallow vs deep)
/// 3. Initializing the .kin/ directory
/// 4. Converting Git history + indexing source files
/// 5. Committing changes and entities to the graph store
pub fn execute_migration<G: GraphStore>(
    plan: &MigrationPlan,
    graph: &G,
) -> Result<MigrationResult> {
    let start = Instant::now();

    // Check target isn't already initialized.
    let kin_dir = plan.target.join(".kin");
    if kin_dir.exists() {
        return Err(MigrateError::AlreadyInitialized(
            plan.target.display().to_string(),
        ));
    }

    // Step 1: Initialize .kin/ directory.
    let init_result = init(&plan.target)
        .map_err(|e| MigrateError::Init(e.to_string()))?;

    info!(
        repo_id = %init_result.manifest.repo_id,
        "kin repository initialized at {}",
        plan.target.display()
    );

    // Step 2: Set up blob store.
    let blob_store = BlobStore::new(init_result.layout.objects_dir())
        .map_err(|e| MigrateError::Blob(e.to_string()))?;

    // Step 3: Build genesis change and write to graph.
    let genesis = build_genesis_change();
    let genesis_id = genesis.id;

    graph
        .create_change(&genesis)
        .map_err(|e| MigrateError::Graph(e.to_string()))?;

    // Create the main branch pointing to genesis.
    let branch_name = plan.branch.as_deref().unwrap_or("main");
    kin_core::init_graph(graph, &genesis, branch_name)
        .map_err(|e| MigrateError::Graph(e.to_string()))?;

    // Step 4: Convert Git history and index source files.
    let conversion = convert(plan, genesis_id, &blob_store)?;

    // Step 5: Write imported changes to the graph.
    for imported in &conversion.imported_changes {
        graph
            .create_change(&imported.change)
            .map_err(|e| MigrateError::Graph(e.to_string()))?;
    }

    // Update branch head to the latest imported change.
    if let Some(last) = conversion.imported_changes.last() {
        let branch = kin_model::BranchName::new(branch_name);
        graph
            .update_branch_head(&branch, &last.change.id)
            .map_err(|e| MigrateError::Graph(e.to_string()))?;
    }

    let elapsed = start.elapsed();

    let result = MigrationResult {
        kin_root: plan.target.display().to_string(),
        strategy: plan.strategy,
        commits_imported: conversion.imported_changes.len(),
        files_indexed: conversion.files_indexed,
        entities_extracted: conversion.entities_extracted,
        relations_extracted: conversion.relations_extracted,
        genesis_id: genesis_id.to_string(),
        default_branch: Some(branch_name.to_string()),
        duration_ms: elapsed.as_millis() as u64,
        completed_at: Utc::now(),
    };

    info!(
        commits = result.commits_imported,
        files = result.files_indexed,
        entities = result.entities_extracted,
        duration_ms = result.duration_ms,
        "migration complete"
    );

    Ok(result)
}

/// Convenience: scan + plan + execute in one call.
pub fn migrate_repo<G: GraphStore>(
    source: &std::path::Path,
    strategy: MigrationStrategy,
    graph: &G,
) -> Result<MigrationResult> {
    let scan = scan_repo(source)?;
    let plan = plan_migration(&scan, strategy, None, 0);
    execute_migration(&plan, graph)
}

impl MigrationResult {
    /// Generate a human-readable summary.
    pub fn summary(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();

        writeln!(out, "=== Kin Migration Complete ===").unwrap();
        writeln!(out, "Repository: {}", self.kin_root).unwrap();
        writeln!(out, "Strategy: {:?}", self.strategy).unwrap();
        writeln!(out, "Commits imported: {}", self.commits_imported).unwrap();
        writeln!(out, "Files indexed: {}", self.files_indexed).unwrap();
        writeln!(out, "Entities extracted: {}", self.entities_extracted).unwrap();
        writeln!(out, "Relations extracted: {}", self.relations_extracted).unwrap();
        writeln!(out, "Duration: {}ms", self.duration_ms).unwrap();
        if let Some(ref branch) = self.default_branch {
            writeln!(out, "Default branch: {}", branch).unwrap();
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_result_serializes() {
        let result = MigrationResult {
            kin_root: "/project".into(),
            strategy: MigrationStrategy::Shallow,
            commits_imported: 1,
            files_indexed: 5,
            entities_extracted: 20,
            relations_extracted: 10,
            genesis_id: "abc123".into(),
            default_branch: Some("main".into()),
            duration_ms: 500,
            completed_at: Utc::now(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: MigrationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.commits_imported, 1);
        assert_eq!(parsed.strategy, MigrationStrategy::Shallow);
    }

    #[test]
    fn migration_result_summary() {
        let result = MigrationResult {
            kin_root: "/project".into(),
            strategy: MigrationStrategy::Deep,
            commits_imported: 50,
            files_indexed: 10,
            entities_extracted: 100,
            relations_extracted: 30,
            genesis_id: "def456".into(),
            default_branch: Some("main".into()),
            duration_ms: 2000,
            completed_at: Utc::now(),
        };
        let summary = result.summary();
        assert!(summary.contains("Migration Complete"));
        assert!(summary.contains("Deep"));
        assert!(summary.contains("50"));
        assert!(summary.contains("100"));
    }

    #[test]
    fn already_initialized_fails() {
        let dir = tempfile::tempdir().unwrap();
        // Create .kin dir to simulate already initialized.
        std::fs::create_dir(dir.path().join(".kin")).unwrap();

        let plan = MigrationPlan {
            source: dir.path().to_path_buf(),
            target: dir.path().to_path_buf(),
            strategy: MigrationStrategy::Shallow,
            branch: None,
            max_commits: 0,
            source_files: vec![],
        };

        // Use a mock graph store.
        let graph = MockGraphStore;
        let err = execute_migration(&plan, &graph).unwrap_err();
        assert!(matches!(err, MigrateError::AlreadyInitialized(_)));
    }
}

// Minimal mock for testing error paths that don't touch the graph.
#[cfg(test)]
struct MockGraphStore;

#[cfg(test)]
impl GraphStore for MockGraphStore {
    type Error = kin_model::ModelError;

    fn get_entity(&self, _: &kin_model::EntityId) -> std::result::Result<Option<kin_model::Entity>, Self::Error> { Ok(None) }
    fn get_relations(&self, _: &kin_model::EntityId, _: &[kin_model::RelationKind]) -> std::result::Result<Vec<kin_model::Relation>, Self::Error> { Ok(vec![]) }
    fn get_all_relations_for_entity(&self, _: &kin_model::EntityId) -> std::result::Result<Vec<kin_model::Relation>, Self::Error> { Ok(vec![]) }
    fn get_downstream_impact(&self, _: &kin_model::EntityId, _: u32) -> std::result::Result<Vec<kin_model::Entity>, Self::Error> { Ok(vec![]) }
    fn get_dependency_neighborhood(&self, _: &kin_model::EntityId, _: u32) -> std::result::Result<kin_model::SubGraph, Self::Error> { Ok(Default::default()) }
    fn find_dead_code(&self) -> std::result::Result<Vec<kin_model::Entity>, Self::Error> { Ok(vec![]) }
    fn get_entity_history(&self, _: &kin_model::EntityId) -> std::result::Result<Vec<kin_model::SemanticChange>, Self::Error> { Ok(vec![]) }
    fn find_merge_bases(&self, _: &kin_model::SemanticChangeId, _: &kin_model::SemanticChangeId) -> std::result::Result<Vec<kin_model::SemanticChangeId>, Self::Error> { Ok(vec![]) }
    fn query_entities(&self, _: &kin_model::EntityFilter) -> std::result::Result<Vec<kin_model::Entity>, Self::Error> { Ok(vec![]) }
    fn list_all_entities(&self) -> std::result::Result<Vec<kin_model::Entity>, Self::Error> { Ok(vec![]) }
    fn upsert_entity(&self, _: &kin_model::Entity) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn upsert_relation(&self, _: &kin_model::Relation) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn remove_entity(&self, _: &kin_model::EntityId) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn remove_relation(&self, _: &kin_model::RelationId) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn create_change(&self, _: &kin_model::SemanticChange) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn get_change(&self, _: &kin_model::SemanticChangeId) -> std::result::Result<Option<kin_model::SemanticChange>, Self::Error> { Ok(None) }
    fn get_changes_since(&self, _: &kin_model::SemanticChangeId, _: &kin_model::SemanticChangeId) -> std::result::Result<Vec<kin_model::SemanticChange>, Self::Error> { Ok(vec![]) }
    fn get_branch(&self, _: &kin_model::BranchName) -> std::result::Result<Option<kin_model::Branch>, Self::Error> { Ok(None) }
    fn create_branch(&self, _: &kin_model::Branch) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn update_branch_head(&self, _: &kin_model::BranchName, _: &kin_model::SemanticChangeId) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn delete_branch(&self, _: &kin_model::BranchName) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn list_branches(&self) -> std::result::Result<Vec<kin_model::Branch>, Self::Error> { Ok(vec![]) }
    fn create_work_item(&self, _: &kin_model::WorkItem) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn get_work_item(&self, _: &kin_model::WorkId) -> std::result::Result<Option<kin_model::WorkItem>, Self::Error> { Ok(None) }
    fn list_work_items(&self, _: &kin_model::WorkFilter) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> { Ok(vec![]) }
    fn update_work_status(&self, _: &kin_model::WorkId, _: kin_model::WorkStatus) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn delete_work_item(&self, _: &kin_model::WorkId) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn create_annotation(&self, _: &kin_model::Annotation) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn get_annotation(&self, _: &kin_model::AnnotationId) -> std::result::Result<Option<kin_model::Annotation>, Self::Error> { Ok(None) }
    fn list_annotations(&self, _: &kin_model::AnnotationFilter) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> { Ok(vec![]) }
    fn update_annotation_staleness(&self, _: &kin_model::AnnotationId, _: kin_model::StalenessState) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn delete_annotation(&self, _: &kin_model::AnnotationId) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn create_work_link(&self, _: &kin_model::WorkLink) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn delete_work_link(&self, _: &kin_model::WorkLink) -> std::result::Result<(), Self::Error> { Ok(()) }
    fn get_work_for_scope(&self, _: &kin_model::WorkScope) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> { Ok(vec![]) }
    fn get_annotations_for_scope(&self, _: &kin_model::WorkScope) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> { Ok(vec![]) }
    fn get_child_work_items(&self, _: &kin_model::WorkId) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> { Ok(vec![]) }
    fn get_implementors(&self, _: &kin_model::WorkId) -> std::result::Result<Vec<kin_model::WorkScope>, Self::Error> { Ok(vec![]) }
}
