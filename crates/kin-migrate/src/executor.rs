// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use chrono::{DateTime, Utc};
use kin_blobs::BlobStore;
use kin_core::{init, KinConfig, KinLayout};
use kin_model::{
    Branch, BranchName, ChangeStore, Entity, EntityStore, FileLayout, FilePathId, OpaqueArtifact,
    Relation, ResolvedTree, SemanticChangeId, ShallowTrackedFile, StructuredArtifact,
    TransactionDelta, TreeDelta, TreeEntry,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::converter::{convert, ConversionResult};
use crate::error::{MigrateError, Result};
use crate::strategy::{MigrationPlan, MigrationStrategy};

/// Result of a completed graph-authoritative migration.
#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationResult {
    /// Path to the published Kin repository root.
    pub kin_root: String,
    /// Migration strategy used.
    pub strategy: MigrationStrategy,
    /// Number of Git commits imported as exact tree/history changes.
    pub commits_imported: usize,
    /// Number of UTF-8 regular-file paths that received an enrichment facet.
    ///
    /// This is not repository membership. The resolved tree can contain more
    /// entries (non-UTF8 paths, symlinks, and gitlinks) than this count.
    pub files_indexed: usize,
    /// Total entities extracted from graph-owned head blobs.
    pub entities_extracted: usize,
    /// Total relations extracted or linked from graph-owned head blobs.
    pub relations_extracted: usize,
    /// Genesis change ID.
    pub genesis_id: String,
    /// Published branch name.
    pub default_branch: Option<String>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// When publication completed.
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug)]
struct EffectivePlan {
    plan: MigrationPlan,
    same_target: bool,
}

#[derive(Debug)]
struct ImportedHead {
    change_id: SemanticChangeId,
    git_oid: String,
    tree: ResolvedTree,
}

#[derive(Debug, Default)]
struct PreparedEnrichment {
    files_indexed: usize,
    entities: Vec<Entity>,
    relations: Vec<Relation>,
    layouts: Vec<FileLayout>,
    shallow_files: Vec<ShallowTrackedFile>,
    structured_artifacts: Vec<StructuredArtifact>,
    opaque_artifacts: Vec<OpaqueArtifact>,
}

impl PreparedEnrichment {
    fn entity_count(&self) -> usize {
        self.entities.len()
    }

    fn relation_count(&self) -> usize {
        self.relations.len()
    }
}

/// Execute a migration through a hidden, fully verified staging repository.
///
/// The externally visible failure boundary is publication:
///
/// 1. Import exact Git tree/history into a staging blob store.
/// 2. Resolve and validate the imported head without graph mutation.
/// 3. Atomically admit the imported change batch and exact active head tree
///    into the staging graph.
/// 4. Read every referenced blob back by hash and prepare optional enrichment.
/// 5. Persist enrichment, then publish the branch head last.
/// 6. Save and reopen-verify the staging graph.
/// 7. For a distinct target, project the exact resolved tree into a separate
///    staging root, attach the verified `.kin`, and rename the complete root
///    into place. For an in-place migration, recheck Git HEAD/status and rename
///    only the verified `.kin` into place.
///
/// A failed operation before step 7 leaves no `.kin` at the requested target.
/// Registry registration happens after publication and is repairable metadata;
/// failure there is warned without invalidating the already complete repo.
pub fn execute_migration_persisted(plan: &MigrationPlan) -> Result<MigrationResult> {
    let start = Instant::now();
    let effective = preflight_plan(plan)?;
    if effective.same_target {
        verify_same_target_source(&effective.plan, None)?;
    }

    let target_parent = effective.plan.target.parent().ok_or_else(|| {
        MigrateError::Other(format!(
            "migration target has no parent: {}",
            effective.plan.target.display()
        ))
    })?;
    std::fs::create_dir_all(target_parent)
        .map_err(|error| MigrateError::io(target_parent, error))?;
    let transaction = tempfile::Builder::new()
        .prefix(".kin-migrate-transaction-")
        .tempdir_in(target_parent)
        .map_err(|error| MigrateError::io(target_parent, error))?;
    let control_root = transaction.path().join("control");
    std::fs::create_dir(&control_root).map_err(|error| MigrateError::io(&control_root, error))?;

    let init_result = init(&control_root).map_err(|error| MigrateError::Init(error.to_string()))?;
    let snapshot_path = init_result.layout.kindb_snapshot_path();
    let snapshot = open_snapshot_retrying(&snapshot_path)?;
    let graph = snapshot.graph();
    let branch_name = configure_staging_branch(
        graph.as_ref(),
        &init_result.layout,
        &init_result.config,
        init_result.genesis_id,
        effective.plan.branch.as_deref(),
    )?;
    let blob_store = BlobStore::new(init_result.layout.objects_dir())
        .map_err(|error| MigrateError::Blob(error.to_string()))?;

    // Exact Git admission is the first semantic operation. The returned
    // changes and blob objects are canonical staging truth before any parser is
    // allowed to run.
    let conversion = convert(&effective.plan, init_result.genesis_id, &blob_store)?;
    let imported_head = resolve_imported_head(&conversion, init_result.genesis_id)?;
    verify_selected_ref_unchanged(&effective.plan, &imported_head.git_oid)?;

    if !effective.same_target {
        reject_unmaterializable_gitlinks(&imported_head.tree)?;
    }

    // kin-db validates every immutable payload before mutation and admits this
    // batch under one changes lock. The exact active repository head is then
    // admitted through one identity-bearing tree transaction. The branch
    // remains at genesis until every enrichment facet below has persisted.
    graph
        .create_changes(
            conversion
                .imported_changes
                .iter()
                .map(|imported| imported.change.clone())
                .collect(),
        )
        .map_err(|error| MigrateError::Graph(error.to_string()))?;
    admit_resolved_head(graph.as_ref(), &imported_head.tree)?;

    // Enrichment begins only after exact tree/history admission. It is
    // computed solely from the admitted resolved head and bytes read back from
    // the content-addressed store. Missing/corrupt blobs fail loudly inside
    // this hidden transaction and never expose a partial repository.
    let enrichment = prepare_head_enrichment(&imported_head.tree, &blob_store)?;
    persist_enrichment(graph.as_ref(), &enrichment)?;
    graph
        .update_branch_head(&BranchName::new(&branch_name), &imported_head.change_id)
        .map_err(|error| MigrateError::Graph(error.to_string()))?;
    verify_graph_state(
        graph.as_ref(),
        &branch_name,
        imported_head.change_id,
        &imported_head.tree,
    )?;
    crate::finalize::build_and_save_kidx(&snapshot_path, graph.as_ref())?;
    snapshot
        .save()
        .map_err(|error| MigrateError::Graph(error.to_string()))?;
    drop(graph);
    drop(snapshot);
    verify_persisted_graph(
        &snapshot_path,
        &branch_name,
        imported_head.change_id,
        &imported_head.tree,
    )?;

    if effective.same_target {
        // Close the time-of-check/time-of-use window before making `.kin`
        // visible in the source worktree.
        verify_same_target_source(&effective.plan, Some(&imported_head.git_oid))?;
        kin_projection::verify_resolved_tree_materialization(
            &effective.plan.target,
            &imported_head.tree,
            &blob_store,
        )
        .map_err(|error| MigrateError::Projection(error.to_string()))?;
        publish_in_place(&control_root, &effective.plan.target)?;
    } else {
        let publish_root = transaction.path().join("repository");
        kin_projection::materialize_resolved_tree(&publish_root, &imported_head.tree, &blob_store)
            .map_err(|error| MigrateError::Projection(error.to_string()))?;
        attach_staged_kin(&control_root, &publish_root)?;
        publish_distinct_target(&publish_root, &effective.plan.target)?;
    }
    drop(blob_store);

    if let Err(error) =
        crate::finalize::update_registry(&effective.plan.target, enrichment.entity_count())
    {
        warn!(
            target = %effective.plan.target.display(),
            error = %error,
            "migration published successfully but local registry registration needs repair"
        );
    }

    let elapsed = start.elapsed();
    let result = MigrationResult {
        kin_root: effective.plan.target.display().to_string(),
        strategy: effective.plan.strategy,
        commits_imported: conversion.imported_changes.len(),
        files_indexed: enrichment.files_indexed,
        entities_extracted: enrichment.entity_count(),
        relations_extracted: enrichment.relation_count(),
        genesis_id: init_result.genesis_id.to_string(),
        default_branch: Some(branch_name),
        duration_ms: elapsed.as_millis() as u64,
        completed_at: Utc::now(),
    };
    info!(
        commits = result.commits_imported,
        files = result.files_indexed,
        entities = result.entities_extracted,
        relations = result.relations_extracted,
        duration_ms = result.duration_ms,
        "graph-authoritative migration published"
    );
    Ok(result)
}

fn preflight_plan(plan: &MigrationPlan) -> Result<EffectivePlan> {
    let source = plan
        .source
        .canonicalize()
        .map_err(|error| MigrateError::io(&plan.source, error))?;
    let target = if plan.target.exists() {
        plan.target
            .canonicalize()
            .map_err(|error| MigrateError::io(&plan.target, error))?
    } else {
        absolute_normalized(&plan.target)?
    };
    let same_target = source == target;

    if target.join(".kin").exists() {
        return Err(MigrateError::AlreadyInitialized(
            target.display().to_string(),
        ));
    }
    if !same_target && (target.starts_with(&source) || source.starts_with(&target)) {
        return Err(MigrateError::Other(format!(
            "distinct-target migration requires non-nested paths: source={} target={}",
            source.display(),
            target.display()
        )));
    }
    if !same_target {
        ensure_empty_target(&target)?;
    }

    Ok(EffectivePlan {
        plan: MigrationPlan {
            source,
            target,
            strategy: plan.strategy,
            branch: plan.branch.clone(),
        },
        same_target,
    })
}

fn absolute_normalized(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| MigrateError::io(path, error))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::Normal(part) => normalized.push(part),
        }
    }
    Ok(normalized)
}

fn ensure_empty_target(target: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(MigrateError::io(target, error)),
    };
    if !metadata.file_type().is_dir() {
        return Err(MigrateError::Other(format!(
            "distinct-target migration requires an absent or empty directory: {}",
            target.display()
        )));
    }
    let mut entries = std::fs::read_dir(target).map_err(|error| MigrateError::io(target, error))?;
    if entries
        .next()
        .transpose()
        .map_err(|error| MigrateError::io(target, error))?
        .is_some()
    {
        return Err(MigrateError::Other(format!(
            "distinct-target migration requires an empty target directory: {}",
            target.display()
        )));
    }
    Ok(())
}

fn verify_same_target_source(plan: &MigrationPlan, expected_oid: Option<&str>) -> Result<()> {
    let status = git_output(
        &plan.source,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        return Err(MigrateError::Other(
            "in-place migration requires a clean Git worktree with no untracked files".to_string(),
        ));
    }

    let current = git_commit_oid(&plan.source, "HEAD")?;
    let selected = selected_ref_oid(plan)?;
    if current != selected {
        return Err(MigrateError::Other(format!(
            "in-place migration selected Git commit {selected}, but the checked-out worktree is {current}"
        )));
    }
    if let Some(expected) = expected_oid {
        if current != expected {
            return Err(MigrateError::Other(format!(
                "Git HEAD changed during migration: imported {expected}, now {current}"
            )));
        }
    }
    Ok(())
}

fn verify_selected_ref_unchanged(plan: &MigrationPlan, expected_oid: &str) -> Result<()> {
    let actual = selected_ref_oid(plan)?;
    if actual != expected_oid {
        return Err(MigrateError::Other(format!(
            "selected Git ref changed during migration: imported {expected_oid}, now {actual}"
        )));
    }
    Ok(())
}

fn selected_ref_oid(plan: &MigrationPlan) -> Result<String> {
    match &plan.branch {
        Some(branch) => git_commit_oid(&plan.source, &format!("refs/heads/{branch}")),
        None => git_commit_oid(&plan.source, "HEAD"),
    }
}

fn git_commit_oid(repo: &Path, revision: &str) -> Result<String> {
    let peeled = format!("{revision}^{{commit}}");
    let output = git_output(repo, &["rev-parse", "--verify", &peeled])?;
    String::from_utf8(output)
        .map(|value| value.trim().to_string())
        .map_err(|error| MigrateError::Other(format!("Git returned a non-UTF8 object id: {error}")))
}

fn git_output(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|error| MigrateError::io(repo, error))?;
    if !output.status.success() {
        return Err(MigrateError::GitImport(format!(
            "git {} failed in {}: {}",
            args.join(" "),
            repo.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

fn configure_staging_branch(
    graph: &kin_db::InMemoryGraph,
    layout: &KinLayout,
    config: &KinConfig,
    genesis_id: SemanticChangeId,
    requested: Option<&str>,
) -> Result<String> {
    let branch_name = requested.unwrap_or(&config.default_branch).to_string();
    if branch_name != config.default_branch {
        graph
            .create_branch(&Branch {
                name: BranchName::new(&branch_name),
                head: genesis_id,
            })
            .map_err(|error| MigrateError::Graph(error.to_string()))?;
        graph
            .delete_branch(&BranchName::new(&config.default_branch))
            .map_err(|error| MigrateError::Graph(error.to_string()))?;
        let mut updated = config.clone();
        updated.default_branch = branch_name.clone();
        updated
            .save(&layout.config_path())
            .map_err(|error| MigrateError::Init(error.to_string()))?;
        std::fs::write(layout.head_path(), &branch_name)
            .map_err(|error| MigrateError::io(layout.head_path(), error))?;
    }
    Ok(branch_name)
}

fn resolve_imported_head(
    conversion: &ConversionResult,
    genesis_id: SemanticChangeId,
) -> Result<ImportedHead> {
    let last = conversion.imported_changes.last().ok_or_else(|| {
        MigrateError::GitImport("selected Git ref contains no importable commit".to_string())
    })?;
    let mut states = HashMap::new();
    states.insert(genesis_id, ResolvedTree::default());
    let mut seen = HashSet::new();

    for imported in &conversion.imported_changes {
        let change = &imported.change;
        if !seen.insert(change.id) {
            return Err(MigrateError::Graph(format!(
                "imported history contains duplicate change {}",
                change.id
            )));
        }
        if change.parents.is_empty() {
            return Err(MigrateError::Graph(format!(
                "imported change {} has no boundary or Git parent",
                change.id
            )));
        }
        for parent in &change.parents {
            if !states.contains_key(parent) {
                return Err(MigrateError::Graph(format!(
                    "imported change {} references unresolved parent {}",
                    change.id, parent
                )));
            }
        }
        let parent = states
            .get(&change.parents[0])
            .expect("all imported parents were validated");
        let tree = parent.apply(&change.tree_deltas).map_err(|error| {
            MigrateError::Graph(format!(
                "invalid exact tree transition in imported change {}: {error}",
                change.id
            ))
        })?;
        states.insert(change.id, tree);
    }

    let tree = states.remove(&last.change.id).ok_or_else(|| {
        MigrateError::Graph(format!(
            "imported head {} did not resolve to a repository tree",
            last.change.id
        ))
    })?;
    Ok(ImportedHead {
        change_id: last.change.id,
        git_oid: last.git_oid.clone(),
        tree,
    })
}

fn reject_unmaterializable_gitlinks(tree: &ResolvedTree) -> Result<()> {
    if let Some(artifact) = tree
        .artifacts_by_path()
        .find(|artifact| matches!(artifact.entry, TreeEntry::Gitlink { .. }))
    {
        return Err(MigrateError::Projection(format!(
            "distinct-target migration cannot materialize gitlink {} without an admitted submodule tree",
            artifact.path
        )));
    }
    Ok(())
}

fn prepare_head_enrichment(
    tree: &ResolvedTree,
    blob_store: &BlobStore,
) -> Result<PreparedEnrichment> {
    let mut prepared = PreparedEnrichment::default();
    let mut file_parse_data: Vec<kin_index::linker::FileParseDataWithTests> = Vec::new();
    let mut parse_completeness = kin_index::FileParseCompletenessMap::new();
    let mut artifact_ids = kin_index::linker::ArtifactIdentityMap::new();
    let pipeline = kin_index::IndexPipeline::new();

    for artifact in tree.artifacts_by_path() {
        let Some(hash) = artifact.entry.blob_identity() else {
            // Gitlinks are exact tree truth but do not name repository-owned
            // bytes, so they have no file enrichment facet.
            continue;
        };
        let blob_hash = kin_blobs::Hash256::from_bytes(*hash.as_bytes());
        let content = blob_store.read(&blob_hash).map_err(|error| {
            MigrateError::Blob(format!(
                "tree entry {} references unavailable blob {}: {error}",
                artifact.path, hash
            ))
        })?;

        // Symlink bytes are a link target, not source or artifact contents.
        if !matches!(artifact.entry, TreeEntry::Blob { .. }) {
            continue;
        }
        let Some(path) = artifact.path.as_utf8() else {
            // The byte-exact path remains in the resolved tree. Semantic facets
            // are UTF-8 keyed and must never invent a lossy alias.
            continue;
        };
        let file_id = FilePathId::new(path);
        artifact_ids.insert(path.to_string(), artifact.artifact_id);
        prepared.files_indexed += 1;

        let indexed = match pipeline.index_any_content(&file_id, &content, blob_hash) {
            Ok(indexed) => indexed,
            Err(error) => {
                // Parser/structured-adapter support is optional. Exact bytes
                // are already admitted; a failed optional enricher degrades to
                // an opaque facet rather than rejecting repository content.
                warn!(
                    path,
                    error = %error,
                    "optional semantic enrichment failed; retaining opaque facet"
                );
                kin_index::IndexedAny::OpaqueArtifact(OpaqueArtifact {
                    file_id: file_id.clone(),
                    content_hash: hash,
                    mime_type: None,
                    text_preview: None,
                })
            }
        };

        match indexed {
            kin_index::IndexedAny::EntitySource(indexed) => {
                parse_completeness.insert(
                    indexed.file_id.0.clone(),
                    indexed.file_layout.parse_completeness.clone(),
                );
                prepared.layouts.push(indexed.file_layout.clone());
                prepared.entities.extend(indexed.entities.iter().cloned());
                prepared.relations.extend(indexed.relations.iter().cloned());
                file_parse_data.push(kin_index::linker::FileParseDataWithTests {
                    file_path: indexed.file_id.0,
                    entities: indexed.entities,
                    relations: indexed.extracted_relations,
                    imports: indexed.imports,
                    tests: Vec::new(),
                });
            }
            kin_index::IndexedAny::ShallowSyntax(shallow) => {
                prepared.shallow_files.push(shallow_tracked_file(shallow));
            }
            kin_index::IndexedAny::StructuredArtifact(artifact) => {
                prepared.structured_artifacts.push(artifact);
            }
            kin_index::IndexedAny::OpaqueArtifact(artifact) => {
                prepared.opaque_artifacts.push(artifact);
            }
        }
    }

    let linked = kin_index::linker::link_cross_file_with_tests_and_completeness(
        &file_parse_data,
        &artifact_ids,
        &parse_completeness,
    )
    .map_err(|error| MigrateError::Index(error.to_string()))?;
    prepared.relations.extend(linked);
    Ok(prepared)
}

fn admit_resolved_head(graph: &kin_db::InMemoryGraph, tree: &ResolvedTree) -> Result<()> {
    if !graph.resolved_tree().is_empty() {
        return Err(MigrateError::Graph(
            "new migration staging graph unexpectedly contains repository tree state".to_string(),
        ));
    }
    let tree_deltas = tree
        .artifacts_by_path()
        .map(|artifact| TreeDelta::Added {
            artifact_id: artifact.artifact_id,
            new: artifact.located_entry(),
        })
        .collect();
    graph
        .apply_transaction_delta(&TransactionDelta {
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas,
        })
        .map_err(|error| MigrateError::Graph(error.to_string()))
}

fn shallow_tracked_file(shallow: kin_parser::ShallowFile) -> ShallowTrackedFile {
    ShallowTrackedFile {
        file_id: shallow.file_id,
        language_hint: shallow.language_hint.unwrap_or_default(),
        declaration_count: shallow.declarations.len(),
        import_count: shallow.imports.len(),
        syntax_hash: shallow.fingerprint.syntax_hash,
        signature_hash: shallow.fingerprint.signature_hash,
        declaration_names: shallow
            .declarations
            .into_iter()
            .map(|declaration| declaration.name)
            .collect(),
        import_paths: shallow
            .imports
            .into_iter()
            .map(|import| import.raw_path)
            .collect(),
    }
}

fn persist_enrichment(
    graph: &kin_db::InMemoryGraph,
    enrichment: &PreparedEnrichment,
) -> Result<()> {
    for layout in &enrichment.layouts {
        graph
            .upsert_file_layout(layout)
            .map_err(|error| MigrateError::Graph(error.to_string()))?;
    }
    for shallow in &enrichment.shallow_files {
        graph
            .upsert_shallow_file(shallow)
            .map_err(|error| MigrateError::Graph(error.to_string()))?;
    }
    for artifact in &enrichment.structured_artifacts {
        graph
            .upsert_structured_artifact(artifact)
            .map_err(|error| MigrateError::Graph(error.to_string()))?;
    }
    for artifact in &enrichment.opaque_artifacts {
        graph
            .upsert_opaque_artifact(artifact)
            .map_err(|error| MigrateError::Graph(error.to_string()))?;
    }
    graph
        .upsert_entities_batch(&enrichment.entities)
        .map_err(|error| MigrateError::Graph(error.to_string()))?;
    graph
        .upsert_relations_batch(&enrichment.relations)
        .map_err(|error| MigrateError::Graph(error.to_string()))?;
    Ok(())
}

fn verify_graph_state(
    graph: &kin_db::InMemoryGraph,
    branch_name: &str,
    expected_head: SemanticChangeId,
    expected_tree: &ResolvedTree,
) -> Result<()> {
    let branch = graph
        .get_branch(&BranchName::new(branch_name))
        .map_err(|error| MigrateError::Graph(error.to_string()))?
        .ok_or_else(|| {
            MigrateError::Graph(format!(
                "migration verification failed: branch {branch_name:?} is missing"
            ))
        })?;
    if branch.head != expected_head {
        return Err(MigrateError::Graph(format!(
            "migration verification failed: branch {branch_name:?} head {} != {}",
            branch.head, expected_head
        )));
    }
    let tree = graph
        .resolve_tree_at(&expected_head)
        .map_err(|error| MigrateError::Graph(error.to_string()))?;
    if &tree != expected_tree {
        return Err(MigrateError::Graph(
            "migration verification failed: persisted head tree differs from imported tree"
                .to_string(),
        ));
    }
    if &graph.resolved_tree() != expected_tree {
        return Err(MigrateError::Graph(
            "migration verification failed: active repository tree differs from imported head"
                .to_string(),
        ));
    }
    Ok(())
}

fn verify_persisted_graph(
    snapshot_path: &Path,
    branch_name: &str,
    expected_head: SemanticChangeId,
    expected_tree: &ResolvedTree,
) -> Result<()> {
    let snapshot = open_snapshot_retrying(snapshot_path)?;
    let graph = snapshot.graph();
    verify_graph_state(graph.as_ref(), branch_name, expected_head, expected_tree)
}

fn open_snapshot_retrying(path: impl AsRef<Path>) -> Result<kin_db::SnapshotManager> {
    const MAX_ATTEMPTS: u32 = 200;
    const BACKOFF: std::time::Duration = std::time::Duration::from_millis(25);

    let path = path.as_ref();
    let mut attempt = 1;
    loop {
        match kin_db::SnapshotManager::open(path) {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) => {
                let message = error.to_string();
                let transient = message.contains("lock error")
                    || message.to_lowercase().contains("temporarily unavailable");
                if !transient || attempt >= MAX_ATTEMPTS {
                    return Err(MigrateError::Graph(message));
                }
                std::thread::sleep(BACKOFF);
                attempt += 1;
            }
        }
    }
}

fn attach_staged_kin(control_root: &Path, publish_root: &Path) -> Result<()> {
    let staged_kin = control_root.join(".kin");
    let destination = publish_root.join(".kin");
    std::fs::rename(&staged_kin, &destination)
        .map_err(|error| MigrateError::io(&destination, error))
}

fn publish_in_place(control_root: &Path, target: &Path) -> Result<()> {
    let staged_kin = control_root.join(".kin");
    let destination = target.join(".kin");
    if destination.exists() {
        return Err(MigrateError::AlreadyInitialized(
            target.display().to_string(),
        ));
    }
    std::fs::rename(&staged_kin, &destination)
        .map_err(|error| MigrateError::io(&destination, error))
}

fn publish_distinct_target(publish_root: &Path, target: &Path) -> Result<()> {
    // Recheck immediately before publication. A concurrent creator must never
    // be overwritten by a migration that preflighted an empty path earlier.
    ensure_empty_target(target)?;
    if target.exists() {
        std::fs::remove_dir(target).map_err(|error| MigrateError::io(target, error))?;
    }
    std::fs::rename(publish_root, target).map_err(|error| MigrateError::io(target, error))
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
        writeln!(out, "Files enriched: {}", self.files_indexed).unwrap();
        writeln!(out, "Entities extracted: {}", self.entities_extracted).unwrap();
        writeln!(out, "Relations extracted: {}", self.relations_extracted).unwrap();
        writeln!(out, "Duration: {}ms", self.duration_ms).unwrap();
        if let Some(branch) = &self.default_branch {
            writeln!(out, "Default branch: {branch}").unwrap();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard};

    static MIGRATION_ENV_LOCK: Mutex<()> = Mutex::new(());

    struct RegistryIsolation {
        _lock: MutexGuard<'static, ()>,
        previous: Option<OsString>,
    }

    impl RegistryIsolation {
        fn new(path: &Path) -> Self {
            let lock = MIGRATION_ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = std::env::var_os("KIN_REGISTRY_PATH");
            std::env::set_var("KIN_REGISTRY_PATH", path);
            Self {
                _lock: lock,
                previous,
            }
        }
    }

    impl Drop for RegistryIsolation {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var("KIN_REGISTRY_PATH", value),
                None => std::env::remove_var("KIN_REGISTRY_PATH"),
            }
        }
    }

    fn git(root: &Path, args: &[&str]) -> bool {
        Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .is_ok_and(|output| output.status.success())
    }

    fn init_git(root: &Path) -> bool {
        git(root, &["init", "-b", "main"])
            && git(root, &["config", "user.email", "kin-test@example.com"])
            && git(root, &["config", "user.name", "Kin Test"])
    }

    fn commit_all(root: &Path, message: &str) -> bool {
        git(root, &["add", "-A"]) && git(root, &["commit", "-m", message])
    }

    #[cfg(unix)]
    fn add_non_utf8_blob_to_index(root: &Path) -> OsString {
        use std::io::Write;
        use std::os::unix::ffi::OsStringExt;
        use std::process::Stdio;

        let mut hash_object = Command::new("git")
            .args(["hash-object", "-w", "--stdin"])
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        hash_object
            .stdin
            .take()
            .unwrap()
            .write_all(&[0, 0xff, 3])
            .unwrap();
        let output = hash_object.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "git hash-object failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let blob_oid = String::from_utf8(output.stdout).unwrap().trim().to_string();
        let raw_name = OsString::from_vec(b"opaque-\xff.bin".to_vec());
        let mut cache_info = OsString::from("100644,");
        cache_info.push(blob_oid);
        cache_info.push(",");
        cache_info.push(&raw_name);
        assert!(Command::new("git")
            .args(["update-index", "--add", "--cacheinfo"])
            .arg(cache_info)
            .current_dir(root)
            .status()
            .unwrap()
            .success());
        raw_name
    }

    fn plan(source: &Path, target: Option<PathBuf>, strategy: MigrationStrategy) -> MigrationPlan {
        let scan = crate::scan_repo(source).unwrap();
        crate::plan_migration(&scan, strategy, target)
    }

    fn open_published_graph(
        root: &Path,
    ) -> (
        kin_db::SnapshotManager,
        std::sync::Arc<kin_db::InMemoryGraph>,
    ) {
        let layout = KinLayout::new(root.join(".kin"));
        let snapshot = open_snapshot_retrying(layout.kindb_snapshot_path()).unwrap();
        let graph = snapshot.graph();
        (snapshot, graph)
    }

    #[test]
    fn unrelated_compose_lock_binary_and_mixed_languages_share_one_exact_tree() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("source");
        let target = workspace.path().join("target");
        std::fs::create_dir(&source).unwrap();
        if !init_git(&source) {
            return;
        }
        std::fs::create_dir(source.join("src")).unwrap();
        std::fs::write(
            source.join("compose.yaml"),
            "services:\n  api:\n    image: example/api\n",
        )
        .unwrap();
        std::fs::write(source.join("Cargo.lock"), "# exact lock bytes\n").unwrap();
        std::fs::write(source.join("asset.bin"), [0, 1, 2, 0xff]).unwrap();
        std::fs::write(source.join("notes.txt"), "unrelated but tracked\n").unwrap();
        std::fs::write(
            source.join("src/lib.rs"),
            "pub fn rust_value() -> u8 { 7 }\n",
        )
        .unwrap();
        std::fs::write(
            source.join("src/value.py"),
            "def python_value():\n    return 7\n",
        )
        .unwrap();
        assert!(commit_all(&source, "initial"));
        std::fs::write(source.join("untracked.tmp"), "must not migrate\n").unwrap();

        let _registry = RegistryIsolation::new(&workspace.path().join("registry.toml"));
        let result = execute_migration_persisted(&plan(
            &source,
            Some(target.clone()),
            MigrationStrategy::Snapshot,
        ))
        .unwrap();
        assert_eq!(result.commits_imported, 1);
        assert_eq!(result.files_indexed, 6);
        assert!(result.entities_extracted >= 2);

        let (_snapshot, graph) = open_published_graph(&target);
        let branch = graph.get_branch(&BranchName::new("main")).unwrap().unwrap();
        let tree = graph.resolve_tree_at(&branch.head).unwrap();
        assert_eq!(tree.len(), 6);
        assert_eq!(graph.list_structured_artifacts().unwrap().len(), 1);
        assert_eq!(graph.list_opaque_artifacts().unwrap().len(), 3);
        let languages: HashSet<_> = graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .map(|entity| entity.language)
            .collect();
        assert!(languages.contains(&kin_model::LanguageId::Rust));
        assert!(languages.contains(&kin_model::LanguageId::Python));
        assert_eq!(
            std::fs::read(target.join("asset.bin")).unwrap(),
            [0, 1, 2, 0xff]
        );
        assert!(
            !target.join("untracked.tmp").exists(),
            "distinct projection must contain the imported Git tree, not copied worktree state"
        );
    }

    #[test]
    fn clean_in_place_migration_publishes_only_control_state() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("source");
        std::fs::create_dir(&source).unwrap();
        if !init_git(&source) {
            return;
        }
        std::fs::write(source.join("tracked.txt"), "exact bytes\n").unwrap();
        assert!(commit_all(&source, "initial"));
        let before = std::fs::read(source.join("tracked.txt")).unwrap();

        let _registry = RegistryIsolation::new(&workspace.path().join("registry.toml"));
        let result =
            execute_migration_persisted(&plan(&source, None, MigrationStrategy::Snapshot)).unwrap();

        assert_eq!(
            result.kin_root,
            source.canonicalize().unwrap().display().to_string()
        );
        assert!(source.join(".kin").is_dir());
        assert_eq!(std::fs::read(source.join("tracked.txt")).unwrap(), before);
        let (_snapshot, graph) = open_published_graph(&source);
        assert_eq!(graph.resolved_tree().len(), 1);
    }

    #[test]
    fn dirty_or_untracked_in_place_source_is_refused_before_publication() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("source");
        std::fs::create_dir(&source).unwrap();
        if !init_git(&source) {
            return;
        }
        std::fs::write(source.join("tracked.txt"), "committed\n").unwrap();
        assert!(commit_all(&source, "initial"));
        std::fs::write(source.join("untracked.txt"), "not admitted\n").unwrap();

        let error = execute_migration_persisted(&plan(&source, None, MigrationStrategy::Snapshot))
            .unwrap_err();
        assert!(error.to_string().contains("no untracked files"));
        assert!(!source.join(".kin").exists());
    }

    #[test]
    fn hidden_in_place_byte_drift_is_refused_before_publication() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("source");
        std::fs::create_dir(&source).unwrap();
        if !init_git(&source) {
            return;
        }
        std::fs::write(source.join("tracked.txt"), "committed\n").unwrap();
        assert!(commit_all(&source, "initial"));
        assert!(git(
            &source,
            &["update-index", "--assume-unchanged", "tracked.txt"]
        ));
        std::fs::write(source.join("tracked.txt"), "hidden local bytes\n").unwrap();
        assert!(
            git_output(
                &source,
                &["status", "--porcelain=v1", "-z", "--untracked-files=all"]
            )
            .unwrap()
            .is_empty(),
            "fixture must prove Git status hides the byte drift"
        );

        let error = execute_migration_persisted(&plan(&source, None, MigrationStrategy::Snapshot))
            .unwrap_err();
        assert!(error.to_string().contains("file bytes changed"));
        assert!(!source.join(".kin").exists());
    }

    #[test]
    fn snapshot_and_full_are_the_only_history_boundaries() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("source");
        let snapshot_target = workspace.path().join("snapshot-target");
        let full_target = workspace.path().join("full-target");
        std::fs::create_dir(&source).unwrap();
        if !init_git(&source) {
            return;
        }
        std::fs::write(source.join("state.txt"), "one\n").unwrap();
        assert!(commit_all(&source, "one"));
        std::fs::write(source.join("state.txt"), "two\n").unwrap();
        assert!(commit_all(&source, "two"));

        let _registry = RegistryIsolation::new(&workspace.path().join("registry.toml"));
        let snapshot = execute_migration_persisted(&plan(
            &source,
            Some(snapshot_target),
            MigrationStrategy::Snapshot,
        ))
        .unwrap();
        let full =
            execute_migration_persisted(&plan(&source, Some(full_target), MigrationStrategy::Full))
                .unwrap();
        assert_eq!(snapshot.commits_imported, 1);
        assert_eq!(full.commits_imported, 2);
    }

    #[test]
    fn missing_resolved_blob_fails_loud_before_enrichment() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(dir.path().join("objects")).unwrap();
        let missing = kin_model::Hash256::from_bytes([0x5a; 32]);
        let tree = ResolvedTree::from_artifacts([kin_model::ResolvedArtifact::new(
            kin_model::ArtifactId::new(),
            kin_model::RepoPath::from_utf8("missing.bin").unwrap(),
            TreeEntry::blob(missing, false),
        )])
        .unwrap();
        let error = prepare_head_enrichment(&tree, &blobs).unwrap_err();
        assert!(error.to_string().contains("unavailable blob"));
    }

    #[cfg(unix)]
    #[test]
    fn distinct_target_preserves_executable_and_symlink() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{symlink, PermissionsExt};

        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("source");
        let target = workspace.path().join("target");
        std::fs::create_dir(&source).unwrap();
        if !init_git(&source) {
            return;
        }
        let script = source.join("run.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        symlink("run.sh", source.join("run-link")).unwrap();
        assert!(commit_all(&source, "exact entries"));

        let _registry = RegistryIsolation::new(&workspace.path().join("registry.toml"));
        execute_migration_persisted(&plan(
            &source,
            Some(target.clone()),
            MigrationStrategy::Snapshot,
        ))
        .unwrap();

        assert_eq!(
            std::fs::read_link(target.join("run-link"))
                .unwrap()
                .as_os_str()
                .as_bytes(),
            b"run.sh"
        );
        assert_ne!(
            std::fs::metadata(target.join("run.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn distinct_target_preserves_non_utf8_path() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("source");
        let target = workspace.path().join("target");
        std::fs::create_dir(&source).unwrap();
        if !init_git(&source) {
            return;
        }
        let raw_name = add_non_utf8_blob_to_index(&source);
        assert!(git(&source, &["commit", "-m", "raw path"]));

        let _registry = RegistryIsolation::new(&workspace.path().join("registry.toml"));
        execute_migration_persisted(&plan(
            &source,
            Some(target.clone()),
            MigrationStrategy::Snapshot,
        ))
        .unwrap();
        assert_eq!(std::fs::read(target.join(raw_name)).unwrap(), [0, 0xff, 3]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn distinct_target_refuses_non_utf8_path_without_lossy_publication() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("source");
        let target = workspace.path().join("target");
        std::fs::create_dir(&source).unwrap();
        if !init_git(&source) {
            return;
        }
        add_non_utf8_blob_to_index(&source);
        assert!(git(&source, &["commit", "-m", "raw path"]));

        let _registry = RegistryIsolation::new(&workspace.path().join("registry.toml"));
        let error = execute_migration_persisted(&plan(
            &source,
            Some(target.clone()),
            MigrationStrategy::Snapshot,
        ))
        .unwrap_err();
        assert!(error.to_string().contains("cannot be represented exactly"));
        assert!(!target.join(".kin").exists());
    }

    #[test]
    fn distinct_target_gitlink_fails_without_publishing_partial_repo() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("source");
        let target = workspace.path().join("target");
        std::fs::create_dir(&source).unwrap();
        if !init_git(&source) {
            return;
        }
        std::fs::write(source.join("seed.txt"), "seed\n").unwrap();
        assert!(commit_all(&source, "seed"));
        let oid = String::from_utf8(git_output(&source, &["rev-parse", "HEAD"]).unwrap())
            .unwrap()
            .trim()
            .to_string();
        assert!(git(
            &source,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                "160000",
                &oid,
                "vendor/sub"
            ]
        ));
        assert!(git(&source, &["commit", "-m", "gitlink"]));

        let _registry = RegistryIsolation::new(&workspace.path().join("registry.toml"));
        let error = execute_migration_persisted(&plan(
            &source,
            Some(target.clone()),
            MigrationStrategy::Snapshot,
        ))
        .unwrap_err();
        assert!(error.to_string().contains("cannot materialize gitlink"));
        assert!(!target.join(".kin").exists());
    }

    #[test]
    fn migration_result_summary_names_enrichment_not_membership() {
        let result = MigrationResult {
            kin_root: "/project".into(),
            strategy: MigrationStrategy::Snapshot,
            commits_imported: 1,
            files_indexed: 5,
            entities_extracted: 20,
            relations_extracted: 10,
            genesis_id: "abc123".into(),
            default_branch: Some("main".into()),
            duration_ms: 500,
            completed_at: Utc::now(),
        };
        let summary = result.summary();
        assert!(summary.contains("Files enriched: 5"));
        assert!(!summary.contains("Source files"));
    }
}
