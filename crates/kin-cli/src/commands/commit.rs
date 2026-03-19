use kin_model::GraphStore;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use kin_index::{FileClassification, FileClassifier};
use kin_model::{
    ArtifactDelta, ArtifactDeltaKind, AuthorId, EntityDelta, FilePathId, Hash256, RelationDelta,
    SemanticChange, SemanticChangeId, ShallowTrackedFile, Timestamp,
};
use sha2::{Digest, Sha256};

pub async fn run(message: String, quiet: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    // Load existing graph from snapshot (init creates it).
    let snap_path = layout.root().join("kindb").join("graph.kndb");
    let snap = kin_db::SnapshotManager::open(&snap_path)?;
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

    use kin_model::GraphStore;
    let parent_id = ensured_branch.head;

    if !quiet {
        eprintln!("Creating semantic commit on branch '{}'...", branch_name);
    }

    // --- Phase: scan ---
    let phase_start = Instant::now();

    // Scan source directory for all files (mode-aware: native → .kin/source-root/, compat → repo root)
    let source_root = kin_core::source_dir(&layout);
    let all_files = collect_all_files(&source_root)?;

    let scan_ms = phase_start.elapsed().as_millis();

    if all_files.is_empty() {
        println!("No files found in working directory.");
        return Ok(());
    }

    // Parse files and extract entities
    let registry = kin_parser::AdapterRegistry::new();
    let mut entity_deltas = Vec::new();
    let mut artifact_deltas = Vec::new();

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
    let mut file_parse_data: Vec<kin_index::FileParseData> = Vec::new();
    // Track which files were successfully parsed for entity reconciliation
    let mut parsed_file_entity_names: HashMap<String, HashSet<String>> = HashMap::new();

    let file_count = all_files.len();
    if !quiet {
        eprintln!("Indexing {} files...", file_count);
    }
    let parse_start = Instant::now();
    let mut total_entity_count = 0usize;

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
        let content_hash_preview = kin_blobs::Hash256::digest(&source);
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
            eprint!(
                "\r  [{}/{}] {}% | {} entities | {:.1}s",
                total_files, file_count, pct, total_entity_count, elapsed
            );
        }

        // Classify the file and route to the appropriate handler
        let classification = FileClassifier::classify(file_path);

        match classification {
            FileClassification::EntitySource => {
                clear_shallow_tracking(&layout, graph, &file_id)?;

                // Parse the file for entities
                let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

                let adapter = match registry.get_by_extension(ext) {
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

                // Build entity deltas and collect entities for linking
                let language = adapter.language_id();
                let mut file_entities = Vec::new();
                let mut parsed_names = HashSet::new();
                for extracted in parse_output.entities {
                    let new_entity = extracted.into_entity(language, &file_id);
                    parsed_names.insert(new_entity.name.clone());
                    let existing = existing_file_entities
                        .and_then(|entities| entities.iter().find(|e| e.name == new_entity.name));

                    match existing {
                        Some(old)
                            if old.fingerprint.ast_hash != new_entity.fingerprint.ast_hash =>
                        {
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
                file_parse_data.push(kin_index::FileParseData {
                    file_path: rel_path,
                    entities: file_entities,
                    relations: extracted_relations,
                    imports: file_imports,
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
                    };
                    persist_shallow_tracking(&layout, graph, &tracked)?;
                }
            }
            FileClassification::StructuredArtifact(_kind) => {
                clear_shallow_tracking(&layout, graph, &file_id)?;
                // Structured artifacts are tracked via artifact deltas (already added above).
                // No entity extraction needed.
            }
            FileClassification::OpaqueArtifact { .. } => {
                clear_shallow_tracking(&layout, graph, &file_id)?;
                // Opaque artifacts are tracked via artifact deltas (already added above).
                // No entity extraction needed.
            }
        }
    }

    // Finish progress line
    if !quiet && file_count > 0 {
        let elapsed = parse_start.elapsed().as_secs_f64();
        eprint!(
            "\r  [{}/{}] 100% | {} entities | {:.1}s",
            total_files, file_count, total_entity_count, elapsed
        );
        eprintln!();
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

    for shallow in graph.list_shallow_files()? {
        if !current_files.contains(&shallow.file_id.0) {
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
                    if rel.src == entity.id {
                        old_relation_ids.insert(rel.id);
                    }
                }
                graph.remove_outgoing_relations(&entity.id)?;
            }
        }
    }

    // --- Phase: link ---
    if !quiet {
        eprintln!("Linking cross-file relations...");
    }
    let link_start = Instant::now();

    // Cross-file relation linking (now with deterministic relation IDs)
    let linked_relations = kin_index::link_cross_file(&file_parse_data);
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
    let change_id = compute_change_id(&message, &parent_id);
    let change = SemanticChange {
        id: change_id,
        parents: vec![parent_id],
        timestamp: Timestamp::now(),
        author: AuthorId::new(whoami()),
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

    graph.create_change(&change)?;
    graph.update_branch_head(&branch_name, &change_id)?;
    crate::provenance::record_cli_audit_event(
        graph,
        "commit.create",
        Some(kin_model::WorkScope::Change(change_id)),
        Some(format!(
            "branch={}; entities={}; relations={}; files={}",
            branch_name,
            entity_deltas.len(),
            linked_relations.len(),
            total_files
        )),
    )?;

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

    // Save the updated graph back to the KinDB snapshot.
    let save_start = std::time::Instant::now();
    snap.save()?;
    let save_ms = save_start.elapsed().as_millis();

    // Build and save the read-only index for fast CLI queries.
    let idx_start = std::time::Instant::now();
    let read_index = kin_db::ReadIndex::from_graph(graph)?;
    let idx_path = snap_path.with_extension("kidx");
    read_index.save(&idx_path)?;
    let idx_ms = idx_start.elapsed().as_millis();

    println!(
        "  Snapshot saved in {}ms, index built in {}ms",
        save_ms, idx_ms
    );

    Ok(())
}

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

fn shallow_sidecar_path(layout: &kin_core::KinLayout, file_id: &FilePathId) -> std::path::PathBuf {
    let safe_name = file_id.0.replace('/', "__");
    layout.shallow_dir().join(format!("{}.json", safe_name))
}

/// Collect all files from the working directory, skipping .kin/ and hidden dirs.
fn collect_all_files(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    collect_files_recursive(root, root, &mut files)?;
    Ok(files)
}

#[allow(clippy::only_used_in_recursion)]
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

        // Skip hidden directories and .kin/
        if name_str.starts_with('.') {
            continue;
        }
        // Skip common non-source directories
        if path.is_dir() {
            if matches!(
                name_str.as_ref(),
                "node_modules" | "target" | "build" | "dist" | "__pycache__" | ".git" | "vendor"
            ) {
                continue;
            }
            collect_files_recursive(root, &path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }

    Ok(())
}

/// Compute a unique change ID from message + parent + timestamp.
///
/// Not deterministic — the timestamp ensures each commit gets a unique ID
/// even with the same message and parent.
fn compute_change_id(message: &str, parent: &SemanticChangeId) -> SemanticChangeId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-change-v1:");
    hasher.update(message.as_bytes());
    hasher.update(b":");
    hasher.update(parent.0.as_bytes());
    hasher.update(b":");
    hasher.update(chrono::Utc::now().to_rfc3339().as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    SemanticChangeId::from_hash(Hash256::from_bytes(bytes))
}

/// Get a human-readable author name.
fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}
