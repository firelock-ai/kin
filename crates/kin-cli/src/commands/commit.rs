use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use kin_index::{FileClassification, FileClassifier};
use kin_model::{
    ArtifactDelta, ArtifactDeltaKind, AuthorId, EntityDelta, FilePathId, Hash256, RelationDelta,
    SemanticChange, SemanticChangeId, ShallowTrackedFile, Timestamp,
};
use sha2::{Digest, Sha256};

pub async fn run(message: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;
    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    let branch_name = kin_core::read_current_branch(&layout)?;

    use kin_model::GraphStore;
    let branch = graph
        .get_branch(&branch_name)?
        .ok_or_else(|| anyhow::anyhow!("branch '{}' not found", branch_name))?;
    let parent_id = branch.head;

    println!("Creating semantic commit on branch '{}'...", branch_name);

    // Scan working directory for all files
    let working_dir = layout.working_dir();
    let all_files = collect_all_files(working_dir)?;

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

    for file_path in &all_files {
        let rel_path = file_path
            .strip_prefix(working_dir)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        let source = match std::fs::read(file_path) {
            Ok(s) => s,
            Err(_) => continue,
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

        // Classify the file and route to the appropriate handler
        let classification = FileClassifier::classify(file_path);

        match classification {
            FileClassification::EntitySource => {
                clear_shallow_tracking(&layout, &graph, &file_id)?;

                // Parse the file for entities
                let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

                let adapter = match registry.get_by_extension(ext) {
                    Some(a) => a,
                    None => continue,
                };

                let tree = match adapter.parse(&source) {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                let parse_output = match adapter.extract(&tree, &source, &file_id) {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Collect relations and imports for cross-file linking
                let extracted_relations = parse_output.relations;
                let file_imports = parse_output.imports;

                // Build entity deltas and collect entities for linking
                let language = adapter.language_id();
                let mut file_entities = Vec::new();
                for extracted in parse_output.entities {
                    let new_entity = extracted.into_entity(language, &file_id);

                    // Check if a matching entity already exists (by name + file)
                    let is_modified = existing_file_entities
                        .map(|entities| entities.iter().any(|e| e.name == new_entity.name))
                        .unwrap_or(false);

                    if is_modified {
                        // Find the old entity for the Modified delta
                        if let Some(old) = existing_file_entities.and_then(|entities| {
                            entities.iter().find(|e| e.name == new_entity.name)
                        }) {
                            // Only record as modified if the fingerprint changed
                            if old.fingerprint.ast_hash != new_entity.fingerprint.ast_hash {
                                entity_deltas.push(EntityDelta::Modified {
                                    old: old.clone(),
                                    new: new_entity.clone(),
                                });
                            }
                        }
                    } else {
                        entity_deltas.push(EntityDelta::Added(new_entity.clone()));
                    }

                    // Upsert entity into graph
                    graph.upsert_entity(&new_entity)?;
                    file_entities.push(new_entity);
                }

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
                    persist_shallow_tracking(&layout, &graph, &tracked)?;
                }
            }
            FileClassification::StructuredArtifact(_kind) => {
                clear_shallow_tracking(&layout, &graph, &file_id)?;
                // Structured artifacts are tracked via artifact deltas (already added above).
                // No entity extraction needed.
            }
            FileClassification::OpaqueArtifact { .. } => {
                clear_shallow_tracking(&layout, &graph, &file_id)?;
                // Opaque artifacts are tracked via artifact deltas (already added above).
                // No entity extraction needed.
            }
        }
    }

    // Check for removed entities (entities in graph whose files no longer exist)
    let current_files: std::collections::HashSet<String> = all_files
        .iter()
        .filter_map(|p| {
            p.strip_prefix(working_dir)
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
            clear_shallow_tracking(&layout, &graph, &shallow.file_id)?;
        }
    }

    // Cross-file relation linking
    let linked_relations = kin_index::link_cross_file(&file_parse_data);
    let mut relation_deltas = Vec::new();

    for rel in &linked_relations {
        graph.upsert_relation(rel)?;
        relation_deltas.push(RelationDelta::Added(rel.clone()));
    }

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

    println!(
        "Created semantic change {} on branch '{}' ({} entities, {} relations, {} files)",
        change_id,
        branch_name,
        entity_deltas.len(),
        linked_relations.len(),
        total_files
    );

    Ok(())
}

fn persist_shallow_tracking(
    layout: &kin_core::KinLayout,
    graph: &kin_graph::KuzuGraphStore,
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
    graph: &kin_graph::KuzuGraphStore,
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
