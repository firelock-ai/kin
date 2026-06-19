// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::Path;
use std::time::Instant;

use chrono::{DateTime, Utc};
use kin_blobs::BlobStore;
use kin_core::{build_genesis_change, init, KinConfig, KinLayout};
use kin_model::{Branch, BranchName, ChangeStore, GraphStore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::checkpoint::{
    clear_checkpoint, read_checkpoint, should_checkpoint, write_checkpoint, MigrateCheckpoint,
};
use crate::converter::convert;
use crate::error::{MigrateError, Result};
use crate::resource_threads::{proof_profile_requested, with_resource_rayon_pool};
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
    let _span = tracing::info_span!(
        "kin.migrate.execute",
        source = %plan.source.display(),
        target = %plan.target.display(),
        strategy = ?plan.strategy,
        files = plan.source_files.len()
    )
    .entered();
    let start = Instant::now();

    // Check target isn't already initialized.
    let kin_dir = plan.target.join(".kin");
    if kin_dir.exists() {
        return Err(MigrateError::AlreadyInitialized(
            plan.target.display().to_string(),
        ));
    }

    {
        let _span = tracing::info_span!(
            "kin.migrate.materialize_target_workspace",
            source = %plan.source.display(),
            target = %plan.target.display()
        )
        .entered();
        materialize_target_workspace(plan)?;
    }

    // Step 1: Initialize .kin/ directory.
    let init_result = {
        let _span = tracing::info_span!(
            "kin.migrate.init_repo",
            target = %plan.target.display()
        )
        .entered();
        init(&plan.target).map_err(|e| MigrateError::Init(e.to_string()))?
    };

    info!(
        repo_id = %init_result.manifest.repo_id,
        "kin repository initialized at {}",
        plan.target.display()
    );

    // Step 2: Set up blob store.
    let blob_store = {
        let _span = tracing::info_span!(
            "kin.migrate.open_blob_store",
            path = %init_result.layout.objects_dir().display()
        )
        .entered();
        BlobStore::new(init_result.layout.objects_dir())
            .map_err(|e| MigrateError::Blob(e.to_string()))?
    };

    // Step 3: Build genesis change and write to graph.
    let genesis = build_genesis_change();
    let genesis_id = genesis.id;

    // Create the main branch pointing to genesis.
    let branch_name = plan.branch.as_deref().unwrap_or("main");
    kin_core::init_graph(graph, &genesis, branch_name)
        .map_err(|e| MigrateError::Graph(e.to_string()))?;

    // Check for an existing checkpoint to support --resume.
    let checkpoint = read_checkpoint(&plan.target)?;
    let skip_count = checkpoint.as_ref().map_or(0, |cp| cp.total_processed);
    if let Some(ref cp) = checkpoint {
        info!(
            last_commit = %cp.last_commit,
            total_processed = cp.total_processed,
            "resuming migration from checkpoint"
        );
    }

    // Step 4: Convert Git history and index source files.
    let conversion = {
        let _span =
            tracing::info_span!("kin.migrate.convert_plan", files = plan.source_files.len())
                .entered();
        convert(plan, genesis_id, &blob_store)?
    };

    let (files_indexed, entities_extracted, relations_extracted) = {
        let _span = tracing::info_span!(
            "kin.migrate.persist_semantic_index",
            files = plan.source_files.len()
        )
        .entered();
        persist_semantic_index(plan, &blob_store, graph)?
    };

    // Step 5: Write imported changes to the graph.
    let mut commits_processed = skip_count;
    {
        let _span = tracing::info_span!(
            "kin.migrate.persist_changes",
            changes = conversion.imported_changes.len(),
            skip = skip_count
        )
        .entered();
        for (i, imported) in conversion.imported_changes.iter().enumerate() {
            if i < skip_count {
                continue;
            }

            graph
                .create_change(&imported.change)
                .map_err(|e| MigrateError::Graph(e.to_string()))?;

            commits_processed += 1;

            if should_checkpoint(commits_processed) {
                let cp = MigrateCheckpoint::new(
                    imported.change.id.to_string(),
                    commits_processed,
                    entities_extracted,
                    relations_extracted,
                    files_indexed,
                );
                write_checkpoint(&plan.target, &cp)?;
                info!(
                    commits_processed,
                    last_commit = %imported.change.id,
                    "migration checkpoint written"
                );
            }
        }
    }

    // Update branch head to the latest imported change.
    if let Some(last) = conversion.imported_changes.last() {
        let branch = kin_model::BranchName::new(branch_name);
        graph
            .update_branch_head(&branch, &last.change.id)
            .map_err(|e| MigrateError::Graph(e.to_string()))?;
    }

    // Migration succeeded — remove the checkpoint file.
    clear_checkpoint(&plan.target)?;

    let elapsed = start.elapsed();

    let result = MigrationResult {
        kin_root: plan.target.display().to_string(),
        strategy: plan.strategy,
        commits_imported: conversion.imported_changes.len(),
        files_indexed,
        entities_extracted,
        relations_extracted,
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

/// Open a KinDB snapshot, retrying briefly on transient exclusive-lock
/// contention.
///
/// kin-db's `SnapshotManager::open` takes the graph's OS-level lock with a
/// *non-blocking* `flock(LOCK_EX|LOCK_NB)`, so it fails immediately with
/// `EAGAIN` ("Resource temporarily unavailable") if a previous handle on the
/// same graph has not finished releasing yet. A persisted migration opens the
/// freshly-created target graph several times in quick succession (align default
/// branch, main index pass, verify), and these transient self-overlaps would
/// otherwise surface as flaky `LockError`s even though no other process is
/// involved. Retrying with a short bounded backoff turns the non-blocking
/// acquire into an effectively-blocking one without modifying kin-db.
fn open_snapshot_retrying(path: impl AsRef<Path>) -> Result<kin_db::SnapshotManager> {
    // ~5s worst case (200 * 25ms); the uncontended path returns on attempt 1.
    const MAX_ATTEMPTS: u32 = 200;
    const BACKOFF: std::time::Duration = std::time::Duration::from_millis(25);

    let path = path.as_ref();
    let mut attempt: u32 = 1;
    loop {
        match kin_db::SnapshotManager::open(path) {
            Ok(snapshot) => return Ok(snapshot),
            Err(e) => {
                let msg = e.to_string();
                let transient = msg.contains("lock error")
                    || msg.to_lowercase().contains("temporarily unavailable");
                if !transient || attempt >= MAX_ATTEMPTS {
                    return Err(MigrateError::Graph(msg));
                }
                if attempt == 1 {
                    tracing::debug!(
                        path = %path.display(),
                        "graph lock contended on open; retrying with bounded backoff"
                    );
                }
                std::thread::sleep(BACKOFF);
                attempt += 1;
            }
        }
    }
}

/// Execute a migration against a snapshot-backed KinDB and verify that the
/// migrated repository has persisted semantic state before returning success.
pub fn execute_migration_persisted(plan: &MigrationPlan) -> Result<MigrationResult> {
    let _span = tracing::info_span!(
        "kin.migrate.execute_persisted",
        source = %plan.source.display(),
        target = %plan.target.display(),
        strategy = ?plan.strategy,
        files = plan.source_files.len()
    )
    .entered();
    let start = Instant::now();

    let kin_dir = plan.target.join(".kin");
    if kin_dir.exists() {
        return Err(MigrateError::AlreadyInitialized(
            plan.target.display().to_string(),
        ));
    }

    {
        let _span = tracing::info_span!(
            "kin.migrate.materialize_target_workspace",
            source = %plan.source.display(),
            target = %plan.target.display()
        )
        .entered();
        materialize_target_workspace(plan)?;
    }

    let init_result = {
        let _span = tracing::info_span!(
            "kin.migrate.init_repo",
            target = %plan.target.display()
        )
        .entered();
        init(&plan.target).map_err(|e| MigrateError::Init(e.to_string()))?
    };
    let branch_name = {
        let _span = tracing::info_span!(
            "kin.migrate.align_default_branch",
            target = %plan.target.display()
        )
        .entered();
        align_default_branch(
            &init_result.layout,
            &init_result.config,
            init_result.genesis_id,
            plan,
        )?
    };
    let snapshot_path = init_result.layout.kindb_snapshot_path();
    let snapshot = {
        let _span = tracing::info_span!(
            "kin.migrate.open_snapshot",
            path = %snapshot_path.display()
        )
        .entered();
        open_snapshot_retrying(&snapshot_path)?
    };
    let graph = snapshot.graph();

    let blob_store = {
        let _span = tracing::info_span!(
            "kin.migrate.open_blob_store",
            path = %init_result.layout.objects_dir().display()
        )
        .entered();
        BlobStore::new(init_result.layout.objects_dir())
            .map_err(|e| MigrateError::Blob(e.to_string()))?
    };
    let genesis_id = init_result.genesis_id;

    // Check for an existing checkpoint to support --resume.
    let checkpoint = read_checkpoint(&plan.target)?;
    let skip_count = checkpoint.as_ref().map_or(0, |cp| cp.total_processed);
    if let Some(ref cp) = checkpoint {
        info!(
            last_commit = %cp.last_commit,
            total_processed = cp.total_processed,
            "resuming migration from checkpoint"
        );
    }

    let conversion = {
        let _span =
            tracing::info_span!("kin.migrate.convert_plan", files = plan.source_files.len())
                .entered();
        convert(plan, genesis_id, &blob_store)?
    };
    let (files_indexed, entities_extracted, relations_extracted) = {
        let _span = tracing::info_span!(
            "kin.migrate.persist_semantic_index",
            files = plan.source_files.len()
        )
        .entered();
        persist_semantic_index(plan, &blob_store, graph.as_ref())?
    };

    let mut commits_processed = skip_count;
    {
        let _span = tracing::info_span!(
            "kin.migrate.persist_changes",
            changes = conversion.imported_changes.len(),
            skip = skip_count
        )
        .entered();
        for (i, imported) in conversion.imported_changes.iter().enumerate() {
            // Skip commits already processed in a previous run.
            if i < skip_count {
                continue;
            }

            graph
                .create_change(&imported.change)
                .map_err(|e| MigrateError::Graph(e.to_string()))?;

            commits_processed += 1;

            if should_checkpoint(commits_processed) {
                let cp = MigrateCheckpoint::new(
                    imported.change.id.to_string(),
                    commits_processed,
                    entities_extracted,
                    relations_extracted,
                    files_indexed,
                );
                write_checkpoint(&plan.target, &cp)?;
                info!(
                    commits_processed,
                    last_commit = %imported.change.id,
                    "migration checkpoint written"
                );
            }
        }
    }

    if let Some(last) = conversion.imported_changes.last() {
        graph
            .update_branch_head(&BranchName::new(&branch_name), &last.change.id)
            .map_err(|e| MigrateError::Graph(e.to_string()))?;
    }

    // Finalization: build read index before dropping the graph.
    {
        let _span = tracing::info_span!(
            "kin.migrate.build_read_index",
            path = %snapshot_path.display()
        )
        .entered();
        crate::finalize::build_and_save_kidx(&snapshot_path, &graph)?;
    }

    {
        let _span = tracing::info_span!(
            "kin.migrate.save_snapshot",
            path = %snapshot_path.display()
        )
        .entered();
        snapshot
            .save()
            .map_err(|e| MigrateError::Graph(e.to_string()))?;
    }
    drop(graph);
    drop(snapshot);

    // Migration succeeded — remove the checkpoint file.
    clear_checkpoint(&plan.target)?;

    {
        let _span = tracing::info_span!(
            "kin.migrate.verify_persisted_migration",
            path = %snapshot_path.display(),
            branch = %branch_name
        )
        .entered();
        verify_persisted_migration(
            &snapshot_path,
            &branch_name,
            conversion
                .imported_changes
                .last()
                .map(|change| change.change.id),
            plan.source_files.len(),
            files_indexed,
        )?;
    }

    // Finalization: eject snapshot and registry.
    {
        let _span = tracing::info_span!(
            "kin.migrate.ensure_eject_snapshot",
            target = %plan.target.display()
        )
        .entered();
        crate::finalize::ensure_eject_snapshot(&plan.target, &init_result.layout.root())?;
    }
    crate::finalize::update_registry(&plan.target, entities_extracted);

    let elapsed = start.elapsed();
    Ok(MigrationResult {
        kin_root: plan.target.display().to_string(),
        strategy: plan.strategy,
        commits_imported: conversion.imported_changes.len(),
        files_indexed,
        entities_extracted,
        relations_extracted,
        genesis_id: genesis_id.to_string(),
        default_branch: Some(branch_name),
        duration_ms: elapsed.as_millis() as u64,
        completed_at: Utc::now(),
    })
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

fn persist_semantic_index<G: GraphStore>(
    plan: &MigrationPlan,
    blob_store: &BlobStore,
    graph: &G,
) -> Result<(usize, usize, usize)> {
    let workspace_root = materialized_workspace_root(plan);
    let mut files_indexed = 0usize;
    let mut entities_extracted = 0usize;
    let mut relations_extracted = 0usize;
    let mut file_parse_data: Vec<kin_index::linker::FileParseDataWithTests> = Vec::new();

    let indexed_files = if proof_profile_requested()? {
        index_planned_files_serial(plan, blob_store, &workspace_root)?
    } else {
        index_planned_files_parallel(plan, blob_store, &workspace_root)?
    };

    let mut all_entities: Vec<kin_model::Entity> = Vec::new();
    let mut all_relations: Vec<kin_model::Relation> = Vec::new();
    for indexed in indexed_files {
        let entity_count = indexed.indexed_file.entities.len();
        let relation_count = indexed.indexed_file.relations.len();
        all_entities.extend(indexed.indexed_file.entities.iter().cloned());
        all_relations.extend(indexed.indexed_file.relations);

        file_parse_data.push(kin_index::linker::FileParseDataWithTests {
            file_path: indexed.indexed_file.file_id.0.clone(),
            entities: indexed.indexed_file.entities,
            relations: indexed.indexed_file.extracted_relations,
            imports: indexed.indexed_file.imports,
            tests: indexed.tests,
        });

        files_indexed += 1;
        entities_extracted += entity_count;
        relations_extracted += relation_count;
    }

    graph
        .upsert_entities_batch(&all_entities)
        .map_err(|e| MigrateError::Graph(e.to_string()))?;
    graph
        .upsert_relations_batch(&all_relations)
        .map_err(|e| MigrateError::Graph(e.to_string()))?;

    // Cross-file relation linking
    let cross_file_relations = {
        let _span =
            tracing::info_span!("kin.migrate.link_cross_file", files = file_parse_data.len())
                .entered();
        kin_index::linker::link_cross_file_with_tests(&file_parse_data)
    };
    graph
        .upsert_relations_batch(&cross_file_relations)
        .map_err(|e| MigrateError::Graph(e.to_string()))?;
    relations_extracted += cross_file_relations.len();

    Ok((files_indexed, entities_extracted, relations_extracted))
}

fn index_planned_file(
    workspace_root: &Path,
    rel_path: &Path,
    blob_store: &BlobStore,
) -> Result<kin_index::pipeline::IndexedFileWithTests> {
    let abs_path = workspace_root.join(rel_path);
    if !abs_path.exists() {
        return Err(MigrateError::Other(format!(
            "planned source file missing at execution time: {}",
            abs_path.display()
        )));
    }

    let pipeline = kin_index::IndexPipeline::new();
    pipeline
        .index_file_relative_with_tests(&abs_path, blob_store, workspace_root)
        .map_err(|e| MigrateError::Index(e.to_string()))
}

fn index_planned_files_serial(
    plan: &MigrationPlan,
    blob_store: &BlobStore,
    workspace_root: &Path,
) -> Result<Vec<kin_index::pipeline::IndexedFileWithTests>> {
    plan.source_files
        .iter()
        .map(|rel_path| index_planned_file(workspace_root, rel_path, blob_store))
        .collect()
}

fn index_planned_files_parallel(
    plan: &MigrationPlan,
    blob_store: &BlobStore,
    workspace_root: &Path,
) -> Result<Vec<kin_index::pipeline::IndexedFileWithTests>> {
    with_resource_rayon_pool("persist_semantic_index.index_files", || {
        plan.source_files
            .par_iter()
            .map(|rel_path| index_planned_file(workspace_root, rel_path, blob_store))
            .collect::<Result<Vec<_>>>()
    })
}

fn align_default_branch(
    layout: &KinLayout,
    config: &KinConfig,
    genesis_id: kin_model::SemanticChangeId,
    plan: &MigrationPlan,
) -> Result<String> {
    let branch_name = plan
        .branch
        .clone()
        .unwrap_or_else(|| config.default_branch.clone());

    if branch_name == config.default_branch {
        return Ok(branch_name);
    }

    let snapshot = open_snapshot_retrying(layout.kindb_snapshot_path())?;
    let graph = snapshot.graph();
    let new_branch = Branch {
        name: BranchName::new(&branch_name),
        head: genesis_id,
    };
    graph
        .create_branch(&new_branch)
        .map_err(|e| MigrateError::Graph(e.to_string()))?;
    graph
        .delete_branch(&BranchName::new(&config.default_branch))
        .map_err(|e| MigrateError::Graph(e.to_string()))?;
    snapshot
        .save()
        .map_err(|e| MigrateError::Graph(e.to_string()))?;
    drop(graph);
    drop(snapshot);

    let mut updated = config.clone();
    updated.default_branch = branch_name.clone();
    updated
        .save(&layout.config_path())
        .map_err(|e| MigrateError::Init(e.to_string()))?;
    std::fs::write(layout.head_path(), format!("{branch_name}\n"))
        .map_err(|e| MigrateError::Init(e.to_string()))?;

    Ok(branch_name)
}

fn verify_persisted_migration(
    snapshot_path: &std::path::Path,
    branch_name: &str,
    expected_head: Option<kin_model::SemanticChangeId>,
    planned_source_files: usize,
    files_indexed: usize,
) -> Result<()> {
    let snapshot = open_snapshot_retrying(snapshot_path)?;
    let graph = snapshot.graph();

    let branch = graph
        .get_branch(&BranchName::new(branch_name))
        .map_err(|e| MigrateError::Graph(e.to_string()))?
        .ok_or_else(|| {
            MigrateError::Graph(format!(
                "migration smoke check failed: branch '{branch_name}' missing from persisted snapshot"
            ))
        })?;

    if let Some(head) = expected_head {
        if branch.head != head {
            return Err(MigrateError::Graph(format!(
                "migration smoke check failed: branch '{branch_name}' head {} != expected {}",
                branch.head, head
            )));
        }
        let stored = graph
            .get_change(&head)
            .map_err(|e| MigrateError::Graph(e.to_string()))?;
        if stored.is_none() {
            return Err(MigrateError::Graph(format!(
                "migration smoke check failed: imported head change {} missing from persisted snapshot",
                head
            )));
        }
    }

    if planned_source_files > 0 && files_indexed == 0 {
        return Err(MigrateError::Graph(format!(
            "migration smoke check failed: planned {} source files but indexed none",
            planned_source_files
        )));
    }

    if planned_source_files > 0 && graph.entity_count() == 0 {
        return Err(MigrateError::Graph(
            "migration smoke check failed: planned source files but persisted snapshot has no entities"
                .to_string(),
        ));
    }

    Ok(())
}

fn materialized_workspace_root(plan: &MigrationPlan) -> &Path {
    if plan.source == plan.target {
        &plan.source
    } else {
        &plan.target
    }
}

fn materialize_target_workspace(plan: &MigrationPlan) -> Result<()> {
    if plan.source == plan.target {
        return Ok(());
    }

    if plan.target.starts_with(&plan.source) || plan.source.starts_with(&plan.target) {
        return Err(MigrateError::Other(format!(
            "distinct-target migration requires non-nested paths: source={} target={}",
            plan.source.display(),
            plan.target.display()
        )));
    }

    if plan.target.exists() {
        let mut entries =
            std::fs::read_dir(&plan.target).map_err(|e| MigrateError::io(&plan.target, e))?;
        if entries
            .next()
            .transpose()
            .map_err(|e| MigrateError::io(&plan.target, e))?
            .is_some()
        {
            return Err(MigrateError::Other(format!(
                "distinct-target migration requires an empty target directory: {}",
                plan.target.display()
            )));
        }
    } else {
        std::fs::create_dir_all(&plan.target).map_err(|e| MigrateError::io(&plan.target, e))?;
    }

    copy_workspace_tree(&plan.source, &plan.target)
}

fn copy_workspace_tree(source_root: &Path, target_root: &Path) -> Result<()> {
    for entry in std::fs::read_dir(source_root).map_err(|e| MigrateError::io(source_root, e))? {
        let entry = entry.map_err(|e| MigrateError::io(source_root, e))?;
        let file_name = entry.file_name();
        if file_name == ".git" || file_name == ".kin" {
            continue;
        }

        let source_path = entry.path();
        let target_path = target_root.join(&file_name);
        copy_workspace_entry(&source_path, &target_path)?;
    }

    Ok(())
}

fn copy_workspace_entry(source_path: &Path, target_path: &Path) -> Result<()> {
    let file_type = std::fs::symlink_metadata(source_path)
        .map_err(|e| MigrateError::io(source_path, e))?
        .file_type();

    if file_type.is_dir() {
        std::fs::create_dir_all(target_path).map_err(|e| MigrateError::io(target_path, e))?;
        for entry in std::fs::read_dir(source_path).map_err(|e| MigrateError::io(source_path, e))? {
            let entry = entry.map_err(|e| MigrateError::io(source_path, e))?;
            let child_name = entry.file_name();
            if child_name == ".git" || child_name == ".kin" {
                continue;
            }
            copy_workspace_entry(&entry.path(), &target_path.join(child_name))?;
        }
        return Ok(());
    }

    if file_type.is_symlink() {
        return copy_workspace_symlink(source_path, target_path);
    }

    if let Some(parent) = target_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| MigrateError::io(parent, e))?;
    }
    std::fs::copy(source_path, target_path).map_err(|e| MigrateError::io(source_path, e))?;
    Ok(())
}

#[cfg(unix)]
fn copy_workspace_symlink(source_path: &Path, target_path: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    if let Some(parent) = target_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| MigrateError::io(parent, e))?;
    }
    let link_target =
        std::fs::read_link(source_path).map_err(|e| MigrateError::io(source_path, e))?;
    symlink(&link_target, target_path).map_err(|e| MigrateError::io(target_path, e))?;
    Ok(())
}

#[cfg(windows)]
fn copy_workspace_symlink(source_path: &Path, target_path: &Path) -> Result<()> {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    if let Some(parent) = target_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| MigrateError::io(parent, e))?;
    }
    let link_target =
        std::fs::read_link(source_path).map_err(|e| MigrateError::io(source_path, e))?;
    let metadata = std::fs::metadata(source_path).map_err(|e| MigrateError::io(source_path, e))?;
    if metadata.is_dir() {
        symlink_dir(&link_target, target_path).map_err(|e| MigrateError::io(target_path, e))?;
    } else {
        symlink_file(&link_target, target_path).map_err(|e| MigrateError::io(target_path, e))?;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn copy_workspace_symlink(source_path: &Path, _target_path: &Path) -> Result<()> {
    Err(MigrateError::Other(format!(
        "distinct-target migration does not support symlinks on this platform: {}",
        source_path.display()
    )))
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

/// Minimal stub GraphStore for migration tests. Tests in this module validate
/// error paths (e.g., already-initialized checks) that return before any graph
/// access, so no methods need real implementations.
#[cfg(test)]
struct MockGraphStore;

#[cfg(test)]
impl kin_model::EntityStore for MockGraphStore {
    type Error = kin_model::ModelError;

    fn get_entity(
        &self,
        _: &kin_model::EntityId,
    ) -> std::result::Result<Option<kin_model::Entity>, Self::Error> {
        Ok(None)
    }
    fn get_relations(
        &self,
        _: &kin_model::EntityId,
        _: &[kin_model::RelationKind],
    ) -> std::result::Result<Vec<kin_model::Relation>, Self::Error> {
        Ok(vec![])
    }
    fn get_all_relations_for_entity(
        &self,
        _: &kin_model::EntityId,
    ) -> std::result::Result<Vec<kin_model::Relation>, Self::Error> {
        Ok(vec![])
    }
    fn get_downstream_impact(
        &self,
        _: &kin_model::EntityId,
        _: u32,
    ) -> std::result::Result<Vec<kin_model::Entity>, Self::Error> {
        Ok(vec![])
    }
    fn get_dependency_neighborhood(
        &self,
        _: &kin_model::EntityId,
        _: u32,
    ) -> std::result::Result<kin_model::SubGraph, Self::Error> {
        Ok(Default::default())
    }
    fn expand_neighborhood(
        &self,
        _: &[kin_model::EntityId],
        _: &[kin_model::RelationKind],
        _: u32,
    ) -> std::result::Result<kin_model::SubGraph, Self::Error> {
        Ok(Default::default())
    }
    fn find_dead_code(&self) -> std::result::Result<Vec<kin_model::Entity>, Self::Error> {
        Ok(vec![])
    }
    fn has_incoming_relation_kinds(
        &self,
        _: &kin_model::EntityId,
        _: &[kin_model::RelationKind],
        _: bool,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(false)
    }
    fn query_entities(
        &self,
        _: &kin_model::EntityFilter,
    ) -> std::result::Result<Vec<kin_model::Entity>, Self::Error> {
        Ok(vec![])
    }
    fn list_all_entities(&self) -> std::result::Result<Vec<kin_model::Entity>, Self::Error> {
        Ok(vec![])
    }
    fn upsert_entity(&self, _: &kin_model::Entity) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn upsert_relation(&self, _: &kin_model::Relation) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn remove_entity(&self, _: &kin_model::EntityId) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn remove_relation(&self, _: &kin_model::RelationId) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn upsert_shallow_file(
        &self,
        _: &kin_model::ShallowTrackedFile,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn list_shallow_files(
        &self,
    ) -> std::result::Result<Vec<kin_model::ShallowTrackedFile>, Self::Error> {
        Ok(vec![])
    }
    fn upsert_structured_artifact(
        &self,
        _: &kin_model::StructuredArtifact,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn list_structured_artifacts(
        &self,
    ) -> std::result::Result<Vec<kin_model::StructuredArtifact>, Self::Error> {
        Ok(vec![])
    }
    fn delete_structured_artifact(
        &self,
        _: &kin_model::FilePathId,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn upsert_opaque_artifact(
        &self,
        _: &kin_model::OpaqueArtifact,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn list_opaque_artifacts(
        &self,
    ) -> std::result::Result<Vec<kin_model::OpaqueArtifact>, Self::Error> {
        Ok(vec![])
    }
    fn delete_opaque_artifact(
        &self,
        _: &kin_model::FilePathId,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn upsert_file_layout(
        &self,
        _: &kin_model::FileLayout,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_file_layout(
        &self,
        _: &kin_model::FilePathId,
    ) -> std::result::Result<Option<kin_model::FileLayout>, Self::Error> {
        Ok(None)
    }
    fn list_file_layouts(&self) -> std::result::Result<Vec<kin_model::FileLayout>, Self::Error> {
        Ok(vec![])
    }
    fn delete_file_layout(
        &self,
        _: &kin_model::FilePathId,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn traverse(
        &self,
        _: &kin_model::GraphNodeId,
        _: &[kin_model::RelationKind],
        _: u32,
    ) -> std::result::Result<kin_model::SubGraph, Self::Error> {
        Ok(Default::default())
    }
    fn get_shallow_file(
        &self,
        _: &kin_model::FilePathId,
    ) -> std::result::Result<Option<kin_model::ShallowTrackedFile>, Self::Error> {
        Ok(None)
    }
    fn get_structured_artifact(
        &self,
        _: &kin_model::FilePathId,
    ) -> std::result::Result<Option<kin_model::StructuredArtifact>, Self::Error> {
        Ok(None)
    }
    fn get_opaque_artifact(
        &self,
        _: &kin_model::FilePathId,
    ) -> std::result::Result<Option<kin_model::OpaqueArtifact>, Self::Error> {
        Ok(None)
    }
    fn get_file_hash(
        &self,
        _: &kin_model::FilePathId,
    ) -> std::result::Result<Option<kin_model::Hash256>, Self::Error> {
        Ok(None)
    }
}

#[cfg(test)]
impl kin_model::ChangeStore for MockGraphStore {
    type Error = kin_model::ModelError;

    fn get_entity_history(
        &self,
        _: &kin_model::EntityId,
    ) -> std::result::Result<Vec<kin_model::SemanticChange>, Self::Error> {
        Ok(vec![])
    }
    fn find_merge_bases(
        &self,
        _: &kin_model::SemanticChangeId,
        _: &kin_model::SemanticChangeId,
    ) -> std::result::Result<Vec<kin_model::SemanticChangeId>, Self::Error> {
        Ok(vec![])
    }
    fn create_change(&self, _: &kin_model::SemanticChange) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_change(
        &self,
        _: &kin_model::SemanticChangeId,
    ) -> std::result::Result<Option<kin_model::SemanticChange>, Self::Error> {
        Ok(None)
    }
    fn get_changes_since(
        &self,
        _: &kin_model::SemanticChangeId,
        _: &kin_model::SemanticChangeId,
    ) -> std::result::Result<Vec<kin_model::SemanticChange>, Self::Error> {
        Ok(vec![])
    }
    fn get_branch(
        &self,
        _: &kin_model::BranchName,
    ) -> std::result::Result<Option<kin_model::Branch>, Self::Error> {
        Ok(None)
    }
    fn create_branch(&self, _: &kin_model::Branch) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn update_branch_head(
        &self,
        _: &kin_model::BranchName,
        _: &kin_model::SemanticChangeId,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn delete_branch(&self, _: &kin_model::BranchName) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn list_branches(&self) -> std::result::Result<Vec<kin_model::Branch>, Self::Error> {
        Ok(vec![])
    }
}

#[cfg(test)]
impl kin_model::WorkStore for MockGraphStore {
    type Error = kin_model::ModelError;

    fn create_work_item(&self, _: &kin_model::WorkItem) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_work_item(
        &self,
        _: &kin_model::WorkId,
    ) -> std::result::Result<Option<kin_model::WorkItem>, Self::Error> {
        Ok(None)
    }
    fn list_work_items(
        &self,
        _: &kin_model::WorkFilter,
    ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
        Ok(vec![])
    }
    fn update_work_status(
        &self,
        _: &kin_model::WorkId,
        _: kin_model::WorkStatus,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn delete_work_item(&self, _: &kin_model::WorkId) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn create_annotation(&self, _: &kin_model::Annotation) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_annotation(
        &self,
        _: &kin_model::AnnotationId,
    ) -> std::result::Result<Option<kin_model::Annotation>, Self::Error> {
        Ok(None)
    }
    fn list_annotations(
        &self,
        _: &kin_model::AnnotationFilter,
    ) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> {
        Ok(vec![])
    }
    fn update_annotation_staleness(
        &self,
        _: &kin_model::AnnotationId,
        _: kin_model::StalenessState,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn delete_annotation(
        &self,
        _: &kin_model::AnnotationId,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn create_work_link(&self, _: &kin_model::WorkLink) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn delete_work_link(&self, _: &kin_model::WorkLink) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_work_for_scope(
        &self,
        _: &kin_model::WorkScope,
    ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
        Ok(vec![])
    }
    fn get_annotations_for_scope(
        &self,
        _: &kin_model::WorkScope,
    ) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> {
        Ok(vec![])
    }
    fn get_child_work_items(
        &self,
        _: &kin_model::WorkId,
    ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
        Ok(vec![])
    }
    fn get_parent_work_items(
        &self,
        _: &kin_model::WorkId,
    ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
        Ok(vec![])
    }
    fn get_blockers(
        &self,
        _: &kin_model::WorkId,
    ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
        Ok(vec![])
    }
    fn get_blocked_work_items(
        &self,
        _: &kin_model::WorkId,
    ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
        Ok(vec![])
    }
    fn get_implementors(
        &self,
        _: &kin_model::WorkId,
    ) -> std::result::Result<Vec<kin_model::WorkScope>, Self::Error> {
        Ok(vec![])
    }
    fn get_annotations_for_work_item(
        &self,
        _: &kin_model::WorkId,
    ) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> {
        Ok(vec![])
    }
}

#[cfg(test)]
impl kin_model::VerificationStore for MockGraphStore {
    type Error = kin_model::ModelError;

    fn create_test_case(
        &self,
        _: &kin_model::verification::TestCase,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_test_case(
        &self,
        _: &kin_model::verification::TestId,
    ) -> std::result::Result<Option<kin_model::verification::TestCase>, Self::Error> {
        Ok(None)
    }
    fn get_tests_for_entity(
        &self,
        _: &kin_model::EntityId,
    ) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
        Ok(vec![])
    }
    fn delete_test_case(
        &self,
        _: &kin_model::verification::TestId,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn create_assertion(
        &self,
        _: &kin_model::verification::Assertion,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_assertion(
        &self,
        _: &kin_model::verification::AssertionId,
    ) -> std::result::Result<Option<kin_model::verification::Assertion>, Self::Error> {
        Ok(None)
    }
    fn get_coverage_summary(
        &self,
    ) -> std::result::Result<kin_model::verification::CoverageSummary, Self::Error> {
        Ok(kin_model::verification::CoverageSummary {
            total_entities: 0,
            covered_entities: 0,
            coverage_ratio: 0.0,
            missing_proof: vec![],
        })
    }
    fn create_verification_run(
        &self,
        _: &kin_model::verification::VerificationRun,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_verification_run(
        &self,
        _: &kin_model::verification::VerificationRunId,
    ) -> std::result::Result<Option<kin_model::verification::VerificationRun>, Self::Error> {
        Ok(None)
    }
    fn list_runs_for_test(
        &self,
        _: &kin_model::verification::TestId,
    ) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error> {
        Ok(vec![])
    }
    fn create_test_covers_entity(
        &self,
        _: &kin_model::verification::TestId,
        _: &kin_model::EntityId,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn create_test_covers_contract(
        &self,
        _: &kin_model::verification::TestId,
        _: &kin_model::ContractId,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn create_test_verifies_work(
        &self,
        _: &kin_model::verification::TestId,
        _: &kin_model::WorkId,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_tests_covering_contract(
        &self,
        _: &kin_model::ContractId,
    ) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
        Ok(vec![])
    }
    fn get_tests_verifying_work(
        &self,
        _: &kin_model::WorkId,
    ) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
        Ok(vec![])
    }
    fn create_mock_hint(
        &self,
        _: &kin_model::verification::MockHint,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_mock_hints_for_test(
        &self,
        _: &kin_model::verification::TestId,
    ) -> std::result::Result<Vec<kin_model::verification::MockHint>, Self::Error> {
        Ok(vec![])
    }
    fn link_run_proves_entity(
        &self,
        _: &kin_model::verification::VerificationRunId,
        _: &kin_model::EntityId,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn link_run_proves_work(
        &self,
        _: &kin_model::verification::VerificationRunId,
        _: &kin_model::WorkId,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn list_runs_proving_entity(
        &self,
        _: &kin_model::EntityId,
    ) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error> {
        Ok(vec![])
    }
    fn list_runs_proving_work(
        &self,
        _: &kin_model::WorkId,
    ) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error> {
        Ok(vec![])
    }
    fn create_contract(
        &self,
        _: &kin_model::contract::Contract,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_contract(
        &self,
        _: &kin_model::ids::ContractId,
    ) -> std::result::Result<Option<kin_model::contract::Contract>, Self::Error> {
        Ok(None)
    }
    fn list_contracts(
        &self,
    ) -> std::result::Result<Vec<kin_model::contract::Contract>, Self::Error> {
        Ok(vec![])
    }
    fn get_contract_coverage_summary(
        &self,
    ) -> std::result::Result<kin_model::verification::ContractCoverageSummary, Self::Error> {
        Ok(kin_model::verification::ContractCoverageSummary {
            total_contracts: 0,
            covered_contracts: 0,
            coverage_ratio: 0.0,
            uncovered_contract_ids: vec![],
        })
    }
}

#[cfg(test)]
impl kin_model::ProvenanceStore for MockGraphStore {
    type Error = kin_model::ModelError;

    fn create_actor(
        &self,
        _: &kin_model::provenance::Actor,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_actor(
        &self,
        _: &kin_model::provenance::ActorId,
    ) -> std::result::Result<Option<kin_model::provenance::Actor>, Self::Error> {
        Ok(None)
    }
    fn list_actors(&self) -> std::result::Result<Vec<kin_model::provenance::Actor>, Self::Error> {
        Ok(vec![])
    }
    fn create_delegation(
        &self,
        _: &kin_model::provenance::Delegation,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_delegations_for_actor(
        &self,
        _: &kin_model::provenance::ActorId,
    ) -> std::result::Result<Vec<kin_model::provenance::Delegation>, Self::Error> {
        Ok(vec![])
    }
    fn create_approval(
        &self,
        _: &kin_model::provenance::Approval,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_approvals_for_change(
        &self,
        _: &kin_model::SemanticChangeId,
    ) -> std::result::Result<Vec<kin_model::provenance::Approval>, Self::Error> {
        Ok(vec![])
    }
    fn record_audit_event(
        &self,
        _: &kin_model::provenance::AuditEvent,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn query_audit_events(
        &self,
        _: Option<&kin_model::provenance::ActorId>,
        _: usize,
    ) -> std::result::Result<Vec<kin_model::provenance::AuditEvent>, Self::Error> {
        Ok(vec![])
    }
}

#[cfg(test)]
impl kin_model::ReviewStore for MockGraphStore {
    type Error = kin_model::ModelError;

    fn create_review(&self, _: &kin_model::Review) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_review(
        &self,
        _: &kin_model::ReviewId,
    ) -> std::result::Result<Option<kin_model::Review>, Self::Error> {
        Ok(None)
    }
    fn list_reviews(
        &self,
        _: &kin_model::ReviewFilter,
    ) -> std::result::Result<Vec<kin_model::Review>, Self::Error> {
        Ok(vec![])
    }
    fn update_review_state(
        &self,
        _: &kin_model::ReviewId,
        _: kin_model::ReviewDecisionState,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn delete_review(&self, _: &kin_model::ReviewId) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn add_review_decision(
        &self,
        _: &kin_model::ReviewId,
        _: &kin_model::ReviewDecision,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_review_decisions(
        &self,
        _: &kin_model::ReviewId,
    ) -> std::result::Result<Vec<kin_model::ReviewDecision>, Self::Error> {
        Ok(vec![])
    }
    fn add_review_note(&self, _: &kin_model::ReviewNote) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_review_notes(
        &self,
        _: &kin_model::ReviewId,
    ) -> std::result::Result<Vec<kin_model::ReviewNote>, Self::Error> {
        Ok(vec![])
    }
    fn delete_review_note(
        &self,
        _: &kin_model::ReviewNoteId,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn create_review_discussion(
        &self,
        _: &kin_model::ReviewDiscussion,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_review_discussions(
        &self,
        _: &kin_model::ReviewId,
    ) -> std::result::Result<Vec<kin_model::ReviewDiscussion>, Self::Error> {
        Ok(vec![])
    }
    fn add_discussion_comment(
        &self,
        _: &kin_model::ReviewDiscussionId,
        _: &kin_model::ReviewComment,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn set_discussion_state(
        &self,
        _: &kin_model::ReviewDiscussionId,
        _: kin_model::ReviewDiscussionState,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn assign_reviewer(
        &self,
        _: &kin_model::ReviewAssignment,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_review_assignments(
        &self,
        _: &kin_model::ReviewId,
    ) -> std::result::Result<Vec<kin_model::ReviewAssignment>, Self::Error> {
        Ok(vec![])
    }
    fn remove_reviewer(
        &self,
        _: &kin_model::ReviewId,
        _: &str,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
impl kin_model::SessionStore for MockGraphStore {
    type Error = kin_model::ModelError;

    fn upsert_session(
        &self,
        _: &kin_model::session::AgentSession,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_session(
        &self,
        _: &kin_model::SessionId,
    ) -> std::result::Result<Option<kin_model::session::AgentSession>, Self::Error> {
        Ok(None)
    }
    fn delete_session(&self, _: &kin_model::SessionId) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn list_sessions(
        &self,
    ) -> std::result::Result<Vec<kin_model::session::AgentSession>, Self::Error> {
        Ok(vec![])
    }
    fn update_heartbeat(
        &self,
        _: &kin_model::SessionId,
        _: &kin_model::timestamp::Timestamp,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn register_intent(
        &self,
        _: &kin_model::session::Intent,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn get_intent(
        &self,
        _: &kin_model::IntentId,
    ) -> std::result::Result<Option<kin_model::session::Intent>, Self::Error> {
        Ok(None)
    }
    fn delete_intent(&self, _: &kin_model::IntentId) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
    fn list_intents_for_session(
        &self,
        _: &kin_model::SessionId,
    ) -> std::result::Result<Vec<kin_model::session::Intent>, Self::Error> {
        Ok(vec![])
    }
    fn list_all_intents(
        &self,
    ) -> std::result::Result<Vec<kin_model::session::Intent>, Self::Error> {
        Ok(vec![])
    }
}

#[cfg(test)]
impl kin_model::GraphStore for MockGraphStore {
    type Error = kin_model::ModelError;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_git_repo_with_file(root: &Path, branch: &str, rel_path: &str, contents: &str) -> bool {
        if let Some(parent) = Path::new(rel_path).parent() {
            std::fs::create_dir_all(root.join(parent)).unwrap();
        }
        std::fs::write(root.join(rel_path), contents).unwrap();

        let git_init = std::process::Command::new("git")
            .args(["init", "-b", branch])
            .current_dir(root)
            .output();
        match git_init {
            Ok(output) if output.status.success() => {}
            _ => return false,
        }
        let _ = std::process::Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(root)
            .output();
        let _ = std::process::Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(root)
            .output();
        let _ = std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(root)
            .output();
        let commit = std::process::Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(root)
            .output();
        matches!(commit, Ok(output) if output.status.success())
    }

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

    #[test]
    fn persisted_migration_preserves_source_default_branch() {
        let source = tempfile::tempdir().unwrap();
        if !init_git_repo_with_file(
            source.path(),
            "master",
            "src/lib.rs",
            "pub fn migrated() -> &'static str { \"ok\" }\n",
        ) {
            return;
        }

        let plan = MigrationPlan {
            source: source.path().to_path_buf(),
            target: source.path().to_path_buf(),
            strategy: MigrationStrategy::Shallow,
            branch: Some("master".into()),
            max_commits: 0,
            source_files: vec![std::path::PathBuf::from("src/lib.rs")],
        };

        let result = execute_migration_persisted(&plan).unwrap();
        assert_eq!(result.default_branch.as_deref(), Some("master"));

        let layout = kin_core::KinLayout::new(source.path().join(".kin"));
        let config = kin_core::KinConfig::load(&layout.config_path()).unwrap();
        assert_eq!(config.default_branch, "master");
        assert_eq!(
            std::fs::read_to_string(layout.head_path()).unwrap().trim(),
            "master"
        );

        let snapshot = open_snapshot_retrying(layout.kindb_snapshot_path()).unwrap();
        let graph = snapshot.graph();
        let branch = graph.get_branch(&BranchName::new("master")).unwrap();
        assert!(branch.is_some());
        assert!(graph.entity_count() > 0);
    }

    #[test]
    fn persisted_migration_materializes_distinct_target_workspace() {
        let source = tempfile::tempdir().unwrap();
        if !init_git_repo_with_file(
            source.path(),
            "master",
            "src/lib.rs",
            "pub fn migrated() -> &'static str { \"ok\" }\n",
        ) {
            return;
        }

        let target_root = tempfile::tempdir().unwrap();
        let target = target_root.path().join("kin-target");

        let plan = MigrationPlan {
            source: source.path().to_path_buf(),
            target: target.clone(),
            strategy: MigrationStrategy::Shallow,
            branch: Some("master".into()),
            max_commits: 0,
            source_files: vec![std::path::PathBuf::from("src/lib.rs")],
        };

        let result = execute_migration_persisted(&plan).unwrap();
        assert_eq!(result.default_branch.as_deref(), Some("master"));
        assert_eq!(
            std::fs::read_to_string(target.join("src/lib.rs")).unwrap(),
            "pub fn migrated() -> &'static str { \"ok\" }\n"
        );
        assert!(!target.join(".git").exists());
        assert!(target.join(".kin").exists());

        let layout = kin_core::KinLayout::new(target.join(".kin"));
        let snapshot = open_snapshot_retrying(layout.kindb_snapshot_path()).unwrap();
        let graph = snapshot.graph();
        assert!(graph.entity_count() > 0);
    }

    #[test]
    fn persisted_migration_fails_when_planned_file_is_missing_at_execution_time() {
        let source = tempfile::tempdir().unwrap();
        if !init_git_repo_with_file(
            source.path(),
            "master",
            "src/lib.rs",
            "pub fn migrated() -> &'static str { \"ok\" }\n",
        ) {
            return;
        }
        std::fs::remove_file(source.path().join("src/lib.rs")).unwrap();

        let target_root = tempfile::tempdir().unwrap();
        let target = target_root.path().join("kin-target");

        let plan = MigrationPlan {
            source: source.path().to_path_buf(),
            target,
            strategy: MigrationStrategy::Shallow,
            branch: Some("master".into()),
            max_commits: 0,
            source_files: vec![std::path::PathBuf::from("src/lib.rs")],
        };

        let err = execute_migration_persisted(&plan).unwrap_err();
        assert!(err
            .to_string()
            .contains("planned source file missing at execution time"));
    }

    #[test]
    fn persisted_migration_writes_kidx() {
        let source = tempfile::tempdir().unwrap();
        if !init_git_repo_with_file(
            source.path(),
            "main",
            "src/lib.rs",
            "pub fn hello() -> &'static str { \"world\" }\n",
        ) {
            return;
        }

        let plan = MigrationPlan {
            source: source.path().to_path_buf(),
            target: source.path().to_path_buf(),
            strategy: MigrationStrategy::Shallow,
            branch: Some("main".into()),
            max_commits: 0,
            source_files: vec![std::path::PathBuf::from("src/lib.rs")],
        };

        execute_migration_persisted(&plan).unwrap();

        let layout = kin_core::KinLayout::new(source.path().join(".kin"));
        let kidx_path = layout.kindb_snapshot_path().with_extension("kidx");
        assert!(
            kidx_path.exists(),
            ".kidx read index should exist after migration"
        );
    }

    #[test]
    fn persisted_migration_creates_eject_snapshot() {
        let source = tempfile::tempdir().unwrap();
        if !init_git_repo_with_file(
            source.path(),
            "main",
            "src/lib.rs",
            "pub fn hello() -> &'static str { \"world\" }\n",
        ) {
            return;
        }

        let plan = MigrationPlan {
            source: source.path().to_path_buf(),
            target: source.path().to_path_buf(),
            strategy: MigrationStrategy::Shallow,
            branch: Some("main".into()),
            max_commits: 0,
            source_files: vec![std::path::PathBuf::from("src/lib.rs")],
        };

        execute_migration_persisted(&plan).unwrap();

        let snapshot_dir = source.path().join(".kin/snapshot");
        assert!(
            snapshot_dir.exists(),
            "eject snapshot directory should exist"
        );
        let manifest = snapshot_dir.join("manifest.json");
        assert!(manifest.exists(), "snapshot manifest should exist");
        let manifest_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(manifest).unwrap()).unwrap();
        assert!(manifest_json["file_count"].as_u64().unwrap() > 0);
    }
}
