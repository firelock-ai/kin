// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[cfg(test)]
use kin_model::{ChangeStore, EntityStore, ProvenanceStore};
#[cfg(test)]
use std::collections::{HashMap, HashSet};
#[cfg(test)]
use std::path::Path;
#[cfg(test)]
use std::time::Instant;

#[cfg(test)]
use anyhow::Context;
use anyhow::Result;
#[cfg(test)]
use kin_index::{FileClassification, FileClassifier};
#[cfg(test)]
use kin_model::{
    relation::GraphNodeId, ArtifactDelta, ArtifactDeltaKind, AuthorId, EntityDelta, FilePathId,
    Hash256, RelationDelta, SemanticChange, ShallowTrackedFile, Timestamp,
};

pub async fn run(message: String, quiet: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?).ok_or_else(|| {
        anyhow::anyhow!(
            "not a Kin repository (no .kin/ found)\nhint: run `kin init .` to initialize a Kin repository here"
        )
    })?;

    let result = try_daemon_command_commit(&layout, &message, quiet).await?;
    if !quiet {
        println!(
            "Created semantic change {} on branch '{}' ({} entities, {} relations, {} files)",
            result.change_id,
            result.branch,
            result.entity_count,
            result.relation_count,
            result.file_count
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
async fn run_local_commit_pipeline_for_tests(
    layout: kin_core::KinLayout,
    message: String,
    quiet: bool,
) -> Result<()> {
    let snap = crate::backend::open_kindb_snapshot(&layout)?;
    let graph = snap.graph();
    let graph = &*graph; // Deref Arc for &InMemoryGraph

    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    let branch_name = kin_core::read_current_branch(&layout)?;
    let ensured_branch =
        crate::commands::branch_bootstrap::ensure_current_branch(graph, &branch_name)?;
    if ensured_branch.bootstrapped && !quiet {
        eprintln!(
            "Bootstrapped semantic branch '{}' at genesis before recording the first commit.",
            branch_name
        );
    }

    let parent_id = ensured_branch.head;
    let genesis = kin_core::build_genesis_change();
    let previous_tree = kin_core::build_file_tree(graph, &genesis.id, &parent_id)?;

    if !quiet {
        eprintln!("Creating semantic commit on branch '{}'...", branch_name);
    }

    // --- Phase: scan ---
    let phase_start = Instant::now();

    // Scan source directory for all files (mode-aware: native → .kin/source-root/, compat → repo root)
    let source_root = kin_core::source_dir(&layout);
    let all_files = collect_all_files(&source_root)?;

    let scan_ms = phase_start.elapsed().as_millis();

    // Parse files and extract entities
    let registry = kin_parser::AdapterRegistry::new();
    let mut entity_deltas = Vec::new();
    let mut artifact_deltas = Vec::new();

    // Accumulate shallow changes for the daemon.
    let mut shallow_upserts = Vec::new();
    let mut shallow_clears = Vec::new();

    // Get existing entities from the graph for comparison
    let existing_entities = graph.list_all_entities()?;
    let mut existing_by_file: HashMap<String, Vec<kin_model::Entity>> = HashMap::new();
    for entity in &existing_entities {
        if let Some(ref file_origin) = entity.file_origin {
            existing_by_file
                .entry(file_origin.0.clone())
                .or_default()
                .push(entity.clone());
        }
    }

    let mut total_files = 0usize;
    let mut file_parse_data: Vec<kin_index::linker::FileParseDataWithTests> = Vec::new();
    // Track which files were successfully parsed for entity reconciliation
    let mut parsed_file_entity_names: HashMap<String, HashSet<String>> = HashMap::new();

    let file_count = all_files.len();
    if !quiet {
        eprintln!("Indexing {} files...", file_count);
    }
    let parse_start = Instant::now();
    let mut total_entity_count = 0usize;
    let mut progress = crate::progress::Progress::stderr();

    for file_path in &all_files {
        let rel_path = file_path
            .strip_prefix(&source_root)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        let source = match std::fs::read(file_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("warning: failed to read {}: {}", rel_path, e);
                continue;
            }
        };

        // Check if this blob already exists (file was previously indexed)
        let content_hash_preview = kin_blobs::digest(&source);
        let previously_stored = blob_store.exists(&content_hash_preview).unwrap_or(false);

        // Store file content in blob store
        let blob_hash = blob_store
            .write(&source)
            .map_err(|e| anyhow::anyhow!("blob write failed: {}", e))?;
        let content_hash = Hash256::from_bytes(blob_hash.0);

        let file_id = FilePathId::new(&rel_path);

        // Determine artifact delta kind: check both entity history and blob existence
        let existing_file_entities = existing_by_file.get(&rel_path);
        let artifact_kind = if existing_file_entities.is_some() || previously_stored {
            ArtifactDeltaKind::Modified
        } else {
            ArtifactDeltaKind::Added
        };

        artifact_deltas.push(ArtifactDelta {
            file_id: file_id.clone(),
            kind: artifact_kind,
            old_hash: None,
            new_hash: Some(content_hash),
        });

        total_files += 1;

        // Print progress every 10 files
        if !quiet && total_files.is_multiple_of(10) {
            let pct = (total_files * 100) / file_count;
            let elapsed = parse_start.elapsed().as_secs_f64();
            progress.update(format_args!(
                "[{}/{}] {}% | {} entities | {:.1}s",
                total_files, file_count, pct, total_entity_count, elapsed
            ));
        }

        // Classify the file and route to the appropriate handler
        let classification = FileClassifier::classify(file_path);

        match classification {
            FileClassification::EntitySource => {
                shallow_clears.push(file_id.clone());
                clear_shallow_tracking(&layout, graph, &file_id)?;

                // Parse the file for entities
                let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

                let adapter = match registry.get_by_extension_and_content(ext, &source) {
                    Some(a) => a,
                    None => {
                        eprintln!(
                            "warning: no parser adapter for extension '{}' ({})",
                            ext, rel_path
                        );
                        continue;
                    }
                };

                let tree = match adapter.parse(&source) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("warning: parse failed for {}: {}", rel_path, e);
                        continue;
                    }
                };

                let parse_output = match adapter.extract(&tree, &source, &file_id) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("warning: entity extraction failed for {}: {}", rel_path, e);
                        continue;
                    }
                };

                // Collect relations and imports for cross-file linking
                let extracted_relations = parse_output.relations;
                let file_imports = parse_output.imports;
                let file_tests = parse_output.tests;

                // Build entity deltas and collect entities for linking
                let language = adapter.language_id();
                let mut file_entities = Vec::new();
                let mut parsed_names = HashSet::new();
                for extracted in parse_output.entities {
                    let mut new_entity =
                        extracted.into_entity_with_source(language, &file_id, Some(&source));
                    new_entity.role = kin_index::classify_file_role(&rel_path);
                    kin_parser::attach_file_context_metadata(
                        std::slice::from_mut(&mut new_entity),
                        &file_id,
                        &file_imports,
                    );
                    if language == kin_model::LanguageId::Go {
                        kin_parser::attach_go_command_effect_contract_metadata(
                            &tree,
                            &source,
                            std::slice::from_mut(&mut new_entity),
                        );
                    }
                    parsed_names.insert(new_entity.name.clone());
                    let existing = existing_file_entities
                        .and_then(|entities| entities.iter().find(|e| e.name == new_entity.name));

                    match existing {
                        Some(old) if super::init::entity_fingerprint_changed(old, &new_entity) => {
                            // Modified — reuse old ID for a true update, not a duplicate insert
                            let mut updated = new_entity.clone();
                            updated.id = old.id;
                            entity_deltas.push(EntityDelta::Modified {
                                old: old.clone(),
                                new: updated.clone(),
                            });
                            graph.upsert_entity(&updated)?;
                            file_entities.push(updated);
                        }
                        Some(old) => {
                            // Unchanged — skip upsert, keep existing graph entry
                            // Use the existing entity to preserve stable identity for cross-file linking
                            file_entities.push(old.clone());
                        }
                        None => {
                            // New entity
                            entity_deltas.push(EntityDelta::Added(new_entity.clone()));
                            graph.upsert_entity(&new_entity)?;
                            file_entities.push(new_entity);
                        }
                    }
                }

                // Record which entity names were parsed for this file
                total_entity_count += file_entities.len();
                parsed_file_entity_names.insert(rel_path.clone(), parsed_names);

                // Collect file parse data for cross-file linking
                file_parse_data.push(kin_index::linker::FileParseDataWithTests {
                    file_path: rel_path,
                    entities: file_entities,
                    relations: extracted_relations,
                    imports: file_imports,
                    tests: file_tests,
                });
            }
            FileClassification::ShallowSyntax { language_hint } => {
                let file_id = FilePathId::new(&rel_path);
                if let Some(shallow) =
                    kin_parser::parse_shallow_file(&source, &file_id, &language_hint)
                {
                    println!(
                        "  C2 shallow: {} ({} decls, {} imports)",
                        rel_path,
                        shallow.declarations.len(),
                        shallow.imports.len()
                    );
                    // Persist ShallowTrackedFile to .kin/shallow/
                    let tracked = ShallowTrackedFile {
                        file_id,
                        language_hint: language_hint.clone(),
                        declaration_count: shallow.declarations.len(),
                        import_count: shallow.imports.len(),
                        syntax_hash: shallow.fingerprint.syntax_hash,
                        signature_hash: shallow.fingerprint.signature_hash,
                        declaration_names: shallow
                            .declarations
                            .iter()
                            .map(|decl| decl.name.clone())
                            .take(12)
                            .collect(),
                        import_paths: shallow
                            .imports
                            .iter()
                            .map(|import| import.raw_path.clone())
                            .take(12)
                            .collect(),
                    };
                    shallow_upserts.push(tracked.clone());
                    persist_shallow_tracking(&layout, graph, &tracked)?;
                }
            }
            FileClassification::StructuredArtifact(_kind) => {
                shallow_clears.push(file_id.clone());
                clear_shallow_tracking(&layout, graph, &file_id)?;
                // Structured artifacts are tracked via artifact deltas (already added above).
                // No entity extraction needed.
            }
            FileClassification::OpaqueArtifact { .. } => {
                shallow_clears.push(file_id.clone());
                clear_shallow_tracking(&layout, graph, &file_id)?;
                // Opaque artifacts are tracked via artifact deltas (already added above).
                // No entity extraction needed.
            }
        }
    }

    // Finish progress line
    if !quiet && file_count > 0 {
        let elapsed = parse_start.elapsed().as_secs_f64();
        progress.finish_with(format_args!(
            "[{}/{}] 100% | {} entities | {:.1}s",
            total_files, file_count, total_entity_count, elapsed
        ));
    }
    let parse_ms = parse_start.elapsed().as_millis();

    // --- Per-file entity reconciliation ---
    // Detect entities that exist in the graph for a file but were NOT produced
    // by the parser (deleted functions, renamed entities, etc.). These are
    // removals that the file-level check below can't catch because the file
    // still exists.
    for (file_path, parsed_names) in &parsed_file_entity_names {
        if let Some(old_entities) = existing_by_file.get(file_path) {
            for old in old_entities {
                if !parsed_names.contains(&old.name) {
                    entity_deltas.push(EntityDelta::Removed(old.id));
                    graph.remove_entity(&old.id)?;
                }
            }
        }
    }

    // Check for removed entities (entities in graph whose files no longer exist)
    let current_files: std::collections::HashSet<String> = all_files
        .iter()
        .filter_map(|p| {
            p.strip_prefix(&source_root)
                .ok()
                .map(|r| r.to_string_lossy().to_string())
        })
        .collect();

    for entity in &existing_entities {
        if let Some(ref file_origin) = entity.file_origin {
            if !current_files.contains(&file_origin.0) {
                entity_deltas.push(EntityDelta::Removed(entity.id));
                graph.remove_entity(&entity.id)?;
            }
        }
    }

    for (file_id, old_hash) in &previous_tree {
        if !current_files.contains(&file_id.0) {
            artifact_deltas.push(ArtifactDelta {
                file_id: file_id.clone(),
                kind: ArtifactDeltaKind::Removed,
                old_hash: Some(*old_hash),
                new_hash: None,
            });
        }
    }

    // Removing source entities is not enough: we also need to drop the
    // file-level tracking state so locate/projection stop surfacing paths that
    // no longer exist in the working tree.
    for file_id in previous_tree
        .keys()
        .filter(|file_id| !current_files.contains(&file_id.0))
    {
        graph.remove_entities_for_file(&file_id.0);
        graph.delete_file_layout(file_id)?;
        graph.delete_structured_artifact(file_id)?;
        graph.delete_opaque_artifact(file_id)?;
    }

    for shallow in graph.list_shallow_files()? {
        if !current_files.contains(&shallow.file_id.0) {
            shallow_clears.push(shallow.file_id.clone());
            clear_shallow_tracking(&layout, graph, &shallow.file_id)?;
        }
    }

    // --- Relation reconciliation ---
    // Capture old outgoing relations before clearing, so we can record
    // removals in the SemanticChange history (not just silently mutate).
    let mut old_relation_ids: HashSet<kin_model::RelationId> = HashSet::new();
    let mut cleared_entity_ids = HashSet::new();
    for file_data in &file_parse_data {
        for entity in &file_data.entities {
            if cleared_entity_ids.insert(entity.id) {
                // Record existing outgoing relations before clearing
                for rel in graph.get_all_relations_for_entity(&entity.id)? {
                    // Only track relations where this entity is the source
                    if rel.src == GraphNodeId::Entity(entity.id) {
                        old_relation_ids.insert(rel.id);
                    }
                }
                graph.remove_outgoing_relations(&entity.id)?;
            }
        }
    }

    // --- Phase: link --- (progress printed by the linker itself)
    let link_start = Instant::now();
    let linked_relations = kin_index::linker::link_cross_file_with_tests(&file_parse_data);
    let mut relation_deltas = Vec::new();
    let mut new_relation_ids: HashSet<kin_model::RelationId> = HashSet::new();

    for rel in &linked_relations {
        graph.upsert_relation(rel)?;
        new_relation_ids.insert(rel.id);
        relation_deltas.push(RelationDelta::Added(rel.clone()));
    }

    // Emit Removed deltas for relations that existed before but weren't re-created
    for old_id in &old_relation_ids {
        if !new_relation_ids.contains(old_id) {
            relation_deltas.push(RelationDelta::Removed(*old_id));
        }
    }

    let link_ms = link_start.elapsed().as_millis();

    // --- Phase: write ---
    if !quiet {
        eprintln!("Writing to graph...");
    }
    let write_start = Instant::now();

    // Build the semantic change
    let content_id =
        kin_core::content_identity_from_deltas(&entity_deltas, &relation_deltas, &artifact_deltas);
    let change_id = kin_core::compute_change_id(&message, &parent_id, &content_id);
    let change = SemanticChange {
        id: change_id,
        parents: vec![parent_id],
        timestamp: Timestamp::now(),
        author: AuthorId::new(kin_core::whoami()),
        message,
        entity_deltas: entity_deltas.clone(),
        relation_deltas,
        artifact_deltas,
        projected_files: vec![],
        spec_link: None,
        evidence: vec![],
        risk_summary: None,
        authored_on: Some(branch_name.clone()),
    };

    let details = Some(format!(
        "branch={}; entities={}; relations={}; files={}",
        branch_name,
        entity_deltas.len(),
        linked_relations.len(),
        total_files
    ));

    let audit_event = kin_model::provenance::AuditEvent {
        event_id: kin_model::provenance::AuditEventId::new(),
        actor_id: crate::provenance::ensure_cli_actor(graph)?,
        action: "commit.create".to_string(),
        target_scope: Some(kin_model::WorkScope::Change(change_id)),
        timestamp: Timestamp::now(),
        details,
    };

    let daemon_payload = serde_json::json!({
        "change": change,
        "branch_name": branch_name,
        "shallow_files": shallow_upserts,
        "shallow_clears": shallow_clears,
        "audit_event": audit_event,
    });

    let reqwest_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Kin daemon is required for commit"))?;
    let resp = reqwest_client
        .post(format!(
            "{}/v1/graph/commit",
            daemon_url.trim_end_matches('/')
        ))
        .json(&daemon_payload)
        .send()
        .await
        .context("send daemon commit request")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("daemon commit failed: HTTP {status}: {body}");
    }

    graph.create_change(&change)?;
    graph.update_branch_head(&branch_name, &change_id)?;
    graph.record_audit_event(&audit_event)?;

    let write_ms = write_start.elapsed().as_millis();

    println!(
        "Created semantic change {} on branch '{}' ({} entities, {} relations, {} files)",
        change_id,
        branch_name,
        entity_deltas.len(),
        linked_relations.len(),
        total_files
    );
    println!(
        "  Phases: scan {}ms | parse {}ms | link {}ms | write {}ms",
        scan_ms, parse_ms, link_ms, write_ms
    );

    let queued_embeddings = pending_embedding_work(graph);

    // The daemon accepted the commit and owns persistence/index refresh.
    let save_ms = 0;
    let idx_ms = 0;

    if queued_embeddings > 0 {
        println!(
            "  Snapshot saved in {}ms, index built in {}ms ({} embeddings queued; run `kin embed`)",
            save_ms, idx_ms, queued_embeddings
        );
    } else {
        println!(
            "  Snapshot saved in {}ms, index built in {}ms (embeddings already current)",
            save_ms, idx_ms
        );
    }

    // Report LSP enrichment status.
    if !quiet {
        let lsp_servers = kin_lsp::discovery::discover_servers();
        if !lsp_servers.is_empty() {
            println!(
                "  LSP enrichment: {} server(s) available (enriching in background)",
                lsp_servers.len()
            );
        }
    }

    // Update the global ~/.kin/registry.toml with current entity count
    if let Ok(mut registry) = kin_core::registry::KinRegistry::load() {
        let cwd = layout.working_dir().to_path_buf();
        let repo_id = crate::commands::remote::resolve_repo_id(&layout)?;
        // Fetch remote repo catalog for cross-repo dependency matching.
        // Checks KIN_REMOTE_URL env var or ~/.kin/remote.toml for a remote spine URL.
        // Returns empty if no remote configured or unreachable (3-second timeout).
        let remote_ids = fetch_remote_catalog();
        registry.upsert_with_remote(
            repo_id,
            cwd.canonicalize().unwrap_or(cwd),
            total_entity_count,
            &remote_ids,
        );
        let _ = registry.save();
    }

    Ok(())
}

// ── Thin-client daemon commit ────────────────────────────────────────────

/// Response from the daemon's `/v1/commands/commit` endpoint.
#[derive(Debug, serde::Deserialize)]
struct DaemonCommitResult {
    change_id: String,
    branch: String,
    entity_count: usize,
    relation_count: usize,
    file_count: usize,
}

/// Try the daemon's thin-client commit endpoint.
/// Returns Ok with the result if the daemon handled the commit.
/// Returns Err if the daemon is unavailable or the endpoint failed.
async fn try_daemon_command_commit(
    layout: &kin_core::KinLayout,
    message: &str,
    _quiet: bool,
) -> Result<DaemonCommitResult> {
    let daemon_url = crate::daemon_client::resolve_daemon_url(layout)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("Kin daemon is required for commit but no daemon endpoint is available")
        })?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_millis(500))
        .build()?;

    let payload = serde_json::json!({
        "message": message,
        "dry_run": false,
    });

    let resp = client
        .post(format!(
            "{}/v1/commands/commit",
            daemon_url.trim_end_matches('/')
        ))
        .json(&payload)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("daemon /commands/commit failed (HTTP {}): {}", status, body);
    }

    let result: DaemonCommitResult = resp.json().await?;
    Ok(result)
}

#[cfg(test)]
fn pending_embedding_work(graph: &kin_db::InMemoryGraph) -> usize {
    graph.pending_embeddings() + graph.pending_artifact_embeddings()
}

#[cfg(test)]
#[allow(dead_code)]
fn persist_shallow_tracking(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    tracked: &ShallowTrackedFile,
) -> Result<()> {
    graph.upsert_shallow_file(tracked)?;

    let shallow_dir = layout.shallow_dir();
    std::fs::create_dir_all(&shallow_dir)?;
    let shallow_path = shallow_sidecar_path(layout, &tracked.file_id);
    std::fs::write(&shallow_path, serde_json::to_string_pretty(tracked)?)?;
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
fn clear_shallow_tracking(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    file_id: &FilePathId,
) -> Result<()> {
    graph.delete_shallow_file(file_id)?;

    let shallow_path = shallow_sidecar_path(layout, file_id);
    if shallow_path.exists() {
        std::fs::remove_file(shallow_path)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
fn shallow_sidecar_path(layout: &kin_core::KinLayout, file_id: &FilePathId) -> std::path::PathBuf {
    let safe_name = file_id.0.replace('/', "__");
    layout.shallow_dir().join(format!("{}.json", safe_name))
}

/// Collect all files from the working directory, skipping .kin/ and hidden dirs.
#[cfg(test)]
fn collect_all_files(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    collect_files_recursive(root, root, &mut files)?;
    Ok(files)
}

#[allow(clippy::only_used_in_recursion)]
#[cfg(test)]
fn collect_files_recursive(
    root: &Path,
    dir: &Path,
    files: &mut Vec<std::path::PathBuf>,
) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if path.is_dir() {
            if kin_index::should_skip_dir(name_str.as_ref()) {
                continue;
            }
            collect_files_recursive(root, &path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }

    Ok(())
}

/// Fetch the remote repo catalog from a KinLab spine, if configured.
/// Returns empty vec if no remote is configured or if the request fails.
/// 3-second timeout to avoid blocking `kin commit`.
///
/// First fetches with no filter to get the full catalog (for small orgs).
/// For large orgs (>1000 repos), the endpoint supports ?q=name1,name2,...
/// filtering which the caller can use to narrow to dependency candidates.
#[cfg(test)]
#[allow(dead_code)]
fn fetch_remote_catalog() -> Vec<String> {
    let remote_url = match kin_core::registry::KinRegistry::remote_url() {
        Some(url) => url,
        None => return Vec::new(),
    };

    let base_url = remote_url.trim_end_matches('/');
    let url = format!("{}/api/repos", base_url);
    let auth_header = super::remote::native_remote_bearer_token(base_url)
        .map(|t| format!("Authorization: Bearer {}", t));

    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-s", "--max-time", "3"]);
    if let Some(ref header) = auth_header {
        cmd.args(["-H", header.as_str()]);
    }
    cmd.arg(&url);

    match cmd.output() {
        Ok(output) if output.status.success() => {
            let body = String::from_utf8_lossy(&output.stdout);
            kin_core::registry::KinRegistry::parse_repo_catalog(&body)
        }
        _ => Vec::new(),
    }
}

/// Fetch only repos matching specific names from the remote catalog.
/// Used when the caller already knows what dependency names to check.
#[allow(dead_code)]
fn fetch_remote_catalog_filtered(names: &[&str]) -> Vec<String> {
    let remote_url = match kin_core::registry::KinRegistry::remote_url() {
        Some(url) => url,
        None => return Vec::new(),
    };

    let base_url = remote_url.trim_end_matches('/');
    let query = names.join(",");
    let url = format!("{}/api/repos?q={}", base_url, query);
    let auth_header = super::remote::native_remote_bearer_token(base_url)
        .map(|t| format!("Authorization: Bearer {}", t));

    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-s", "--max-time", "3"]);
    if let Some(ref header) = auth_header {
        cmd.args(["-H", header.as_str()]);
    }
    cmd.arg(&url);

    match cmd.output() {
        Ok(output) if output.status.success() => {
            let body = String::from_utf8_lossy(&output.stdout);
            kin_core::registry::KinRegistry::parse_repo_catalog(&body)
        }
        _ => Vec::new(),
    }
}

// should_skip_dir moved to kin_index::should_skip_dir (canonical skip list).

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::ArtifactId;

    #[test]
    fn pending_embedding_work_counts_artifact_only_queue() {
        let graph = kin_db::InMemoryGraph::new();
        // Synthetic test ID: empty in-test graph has no artifact_index entry.
        let makefile_id = ArtifactId::seed_from_path("Makefile");
        graph.queue_artifacts_for_embedding(&[makefile_id]);

        assert_eq!(graph.pending_embeddings(), 0);
        assert_eq!(graph.pending_artifact_embeddings(), 1);
        assert_eq!(pending_embedding_work(&graph), 1);
    }

    #[test]
    fn collect_all_files_includes_dotfiles_but_skips_internal_dirs() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path();

        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join(".github/workflows")).unwrap();
        std::fs::create_dir_all(root.join(".kin/internal")).unwrap();
        std::fs::create_dir_all(root.join(".git/hooks")).unwrap();

        std::fs::write(root.join("src/lib.rs"), "pub fn hello() {}\n").unwrap();
        std::fs::write(root.join(".gitignore"), "target/\n").unwrap();
        std::fs::write(root.join(".dockerignore"), ".git/\n").unwrap();
        std::fs::write(root.join(".github/workflows/ci.yml"), "name: ci\n").unwrap();
        std::fs::write(root.join(".kin/internal/state.json"), "{}\n").unwrap();
        std::fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();

        let files = collect_all_files(root).unwrap();
        let collected: std::collections::HashSet<String> = files
            .iter()
            .map(|path| {
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();

        assert!(collected.contains(".gitignore"));
        assert!(collected.contains(".dockerignore"));
        assert!(collected.contains(".github/workflows/ci.yml"));
        assert!(collected.contains("src/lib.rs"));
        assert!(!collected.contains(".kin/internal/state.json"));
        assert!(!collected.contains(".git/HEAD"));
    }

    #[test]
    fn collect_all_files_skips_kin_temporary_dirs() {
        let tempdir = tempfile::tempdir().unwrap();
        let root = tempdir.path();

        std::fs::create_dir_all(root.join(".kin-snapshot-tmp/nested")).unwrap();
        std::fs::create_dir_all(root.join(".kin-export/cache")).unwrap();
        std::fs::write(root.join(".kin-snapshot-tmp/nested/manifest.json"), "{}\n").unwrap();
        std::fs::write(root.join(".kin-export/cache/state.json"), "{}\n").unwrap();
        std::fs::write(root.join("README.md"), "hello\n").unwrap();

        let files = collect_all_files(root).unwrap();
        let collected: std::collections::HashSet<String> = files
            .iter()
            .map(|path| {
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();

        assert!(collected.contains("README.md"));
        assert!(!collected.contains(".kin-snapshot-tmp/nested/manifest.json"));
        assert!(!collected.contains(".kin-export/cache/state.json"));
    }
}
