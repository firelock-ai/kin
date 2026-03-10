use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use kin_model::{
    ArtifactDelta, ArtifactDeltaKind, AuthorId, EntityDelta, FilePathId, Hash256,
    SemanticChange, SemanticChangeId, Timestamp,
};
use sha2::{Digest, Sha256};

/// Known source file extensions that we parse for entities.
const SOURCE_EXTENSIONS: &[&str] = &[
    "ts", "tsx", "js", "jsx", "py", "go", "java", "rs",
];

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

    // Scan working directory for source files
    let working_dir = layout.working_dir();
    let source_files = collect_source_files(working_dir)?;

    if source_files.is_empty() {
        println!("No source files found in working directory.");
        return Ok(());
    }

    // Parse source files and extract entities
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

    for file_path in &source_files {
        let rel_path = file_path
            .strip_prefix(working_dir)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        let ext = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        let adapter = match registry.get_by_extension(ext) {
            Some(a) => a,
            None => continue,
        };

        let source = match std::fs::read(file_path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Store file content in blob store
        let blob_hash = blob_store
            .write(&source)
            .map_err(|e| anyhow::anyhow!("blob write failed: {}", e))?;
        let content_hash = Hash256::from_bytes(blob_hash.0);

        let file_id = FilePathId::new(&rel_path);

        // Determine artifact delta kind
        let existing_file_entities = existing_by_file.get(&rel_path);
        let artifact_kind = if existing_file_entities.is_some() {
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

        // Parse the file and extract entities
        let tree = match adapter.parse(&source) {
            Ok(t) => t,
            Err(_) => continue,
        };

        let parse_output = match adapter.extract(&tree, &source, &file_id) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Build entity deltas
        let language = adapter.language_id();
        for extracted in parse_output.entities {
            let new_entity = extracted.into_entity(language, &file_id);

            // Check if a matching entity already exists (by name + file)
            let is_modified = existing_file_entities
                .map(|entities| entities.iter().any(|e| e.name == new_entity.name))
                .unwrap_or(false);

            if is_modified {
                // Find the old entity for the Modified delta
                if let Some(old) = existing_file_entities
                    .and_then(|entities| entities.iter().find(|e| e.name == new_entity.name))
                {
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
        }
    }

    // Check for removed entities (entities in graph whose files no longer exist)
    let current_files: std::collections::HashSet<String> = source_files
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

    // Build the semantic change
    let change_id = compute_change_id(&message, &parent_id);
    let change = SemanticChange {
        id: change_id,
        parents: vec![parent_id],
        timestamp: Timestamp::now(),
        author: AuthorId::new(whoami()),
        message,
        entity_deltas: entity_deltas.clone(),
        relation_deltas: vec![],
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
        "Created semantic change {} on branch '{}' ({} entities, {} files)",
        change_id, branch_name, entity_deltas.len(), total_files
    );

    Ok(())
}

/// Collect all source files from the working directory, skipping .kin/ and hidden dirs.
fn collect_source_files(root: &Path) -> Result<Vec<std::path::PathBuf>> {
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
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if SOURCE_EXTENSIONS.contains(&ext) {
                    files.push(path);
                }
            }
        }
    }

    Ok(())
}

/// Compute a deterministic change ID from message + parent.
fn compute_change_id(message: &str, parent: &SemanticChangeId) -> SemanticChangeId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-change-v1:");
    hasher.update(message.as_bytes());
    hasher.update(b":");
    hasher.update(parent.0.as_bytes());
    hasher.update(b":");
    // Add timestamp for uniqueness
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
