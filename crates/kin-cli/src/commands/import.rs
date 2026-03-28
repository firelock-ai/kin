// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use kin_index::{FileClassification, FileClassifier};
use kin_model::ChangeStore;
use kin_model::EntityStore;
use kin_model::{AuthorId, FilePathId, Hash256, SemanticChange, SemanticChangeId, Timestamp};
use sha2::{Digest, Sha256};

/// Directories to skip during file collection.
const SKIP_DIRS: &[&str] = &[
    ".kin",
    ".git",
    ".git-export",
    "node_modules",
    "target",
    "__pycache__",
    ".next",
    "dist",
    "build",
    "vendor",
];

/// Determine if the source is a remote URL (http/https/git@) or a local path.
fn is_remote_url(source: &str) -> bool {
    source.starts_with("http://")
        || source.starts_with("https://")
        || source.starts_with("git@")
        || source.starts_with("ssh://")
}

/// Derive a repo name from a URL or path.
fn derive_repo_name(source: &str) -> String {
    source
        .rsplit('/')
        .next()
        .unwrap_or("repo")
        .trim_end_matches(".git")
        .to_string()
}

/// Return the imports directory under ~/.kin/imports/.
fn imports_dir() -> Result<PathBuf> {
    let home = dirs_path()?;
    let imports = home.join("imports");
    fs::create_dir_all(&imports).context("failed to create ~/.kin/imports/")?;
    Ok(imports)
}

fn dirs_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .context("cannot determine home directory")?;
    Ok(PathBuf::from(home).join(".kin"))
}

pub async fn run(url: String) -> Result<()> {
    let repo_name = derive_repo_name(&url);

    let local_path = if is_remote_url(&url) {
        let dest = imports_dir()?.join(&repo_name);

        if dest.exists() {
            // If already cloned, reuse it
            println!("Using existing import at {}", dest.display());
        } else {
            // Use forge detection for authenticated cloning.
            let forge = kin_migrate::detect_forge(&url);
            let clone_url = if let Some(ref forge_info) = forge {
                let token = forge_info.resolve_token_from_env();
                if token.is_some() {
                    println!(
                        "Authenticated {} import via {}",
                        forge_info.kind,
                        forge_info.kind.token_env_var().unwrap_or("token")
                    );
                }
                if forge_info.is_ssh {
                    url.clone()
                } else {
                    forge_info.https_clone_url(token.as_deref())
                }
            } else {
                url.clone()
            };
            let forge_label = forge
                .as_ref()
                .map(|f| f.kind.to_string())
                .unwrap_or_else(|| "Git".to_string());

            println!("Cloning {} repository {}...", forge_label, url);
            let status = Command::new("git")
                .args(["clone", "--depth", "1", &clone_url, &dest.to_string_lossy()])
                .status()
                .context("failed to run git clone")?;

            if !status.success() {
                anyhow::bail!("git clone failed with exit code {}", status);
            }
        }

        dest
    } else {
        // Local path — use directly
        let p = PathBuf::from(&url);
        if !p.exists() {
            anyhow::bail!("path does not exist: {}", url);
        }
        p.canonicalize().context("failed to resolve path")?
    };

    // Check if already initialized
    let kin_dir = local_path.join(".kin");
    if kin_dir.exists() {
        println!("Kin already initialized at {}", local_path.display());
        // Still register it
        register_in_registry(&repo_name, &local_path, 0);
        println!("Imported {}: already initialized", repo_name);
        return Ok(());
    }

    // Initialize Kin repository
    println!("Initializing Kin repository...");
    let result = kin_core::init(&local_path)?;

    // Parse and index source files
    let layout = &result.layout;
    let snap = crate::backend::open_snapshot_daemon_first(layout).await?;
    let graph = snap.graph();
    let graph = &*graph;

    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    let source_root = kin_core::source_dir(layout);
    let all_files = collect_source_files(&source_root)?;

    let mut total_entity_count = 0usize;
    let mut total_relations = 0usize;
    let mut embedded = 0usize;

    if !all_files.is_empty() {
        let (entities, _files, relations) =
            parse_and_index(graph, &blob_store, &source_root, &all_files)?;
        total_entity_count = entities;
        total_relations = relations;

        // Create a semantic change for the import
        let branch_name = kin_core::read_current_branch(layout)?;
        let parent_id = result.genesis_id;
        let change_id = compute_import_change_id(&parent_id, &repo_name);
        let change = SemanticChange {
            id: change_id,
            parents: vec![parent_id],
            timestamp: Timestamp::now(),
            author: AuthorId::new(whoami()),
            message: format!("kin import: {}", repo_name),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: Some(branch_name.clone()),
        };
        graph.create_change(&change)?;
        graph.update_branch_head(&branch_name, &change_id)?;

        embedded = match crate::commands::embed::drain_pending_embeddings(
            graph,
            crate::commands::embed::DEFAULT_BATCH_SIZE,
        ) {
            Ok(count) => count,
            Err(e) => {
                eprintln!("Embeddings skipped: {}", e);
                0
            }
        };
        snap.save()?;

        // Build read-only index
        let read_index = kin_db::ReadIndex::from_graph(graph)?;
        let idx_path = layout.kindb_snapshot_path().with_extension("kidx");
        read_index.save(&idx_path)?;
    }

    // Register in global registry
    register_in_registry(&repo_name, &local_path, total_entity_count);

    println!(
        "Imported {}: {} entities, {} relations",
        repo_name, total_entity_count, total_relations
    );
    println!("Embeddings: {}", embedded);

    Ok(())
}

fn register_in_registry(repo_name: &str, path: &Path, entity_count: usize) {
    if let Ok(mut registry) = kin_core::registry::KinRegistry::load() {
        registry.upsert(repo_name.to_string(), path.to_path_buf(), entity_count);
        let _ = registry.save();
    }
}

/// Parse all source files, extract entities, store blobs, link cross-file relations.
fn parse_and_index(
    graph: &kin_db::InMemoryGraph,
    blob_store: &kin_blobs::BlobStore,
    source_root: &Path,
    all_files: &[PathBuf],
) -> Result<(usize, usize, usize)> {
    let registry = kin_parser::AdapterRegistry::new();
    let mut total_entity_count = 0usize;
    let mut total_files = 0usize;
    let mut file_parse_data: Vec<kin_index::FileParseData> = Vec::new();

    for file_path in all_files {
        let rel_path = file_path
            .strip_prefix(source_root)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        let source = match fs::read(file_path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let _ = blob_store
            .write(&source)
            .map_err(|e| anyhow::anyhow!("blob write failed: {}", e))?;

        let file_id = FilePathId::new(&rel_path);
        total_files += 1;

        let classification = FileClassifier::classify(file_path);
        if !matches!(classification, FileClassification::EntitySource) {
            continue;
        }

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

        let extracted_relations = parse_output.relations;
        let file_imports = parse_output.imports;
        let language = adapter.language_id();
        let mut file_entities = Vec::new();

        for extracted in parse_output.entities {
            let entity = extracted.into_entity_with_source(language, &file_id, Some(&source));
            graph.upsert_entity(&entity)?;
            file_entities.push(entity);
        }

        total_entity_count += file_entities.len();

        file_parse_data.push(kin_index::FileParseData {
            file_path: rel_path,
            entities: file_entities,
            relations: extracted_relations,
            imports: file_imports,
        });
    }

    let linked_relations = kin_index::link_cross_file(&file_parse_data);
    for rel in &linked_relations {
        graph.upsert_relation(rel)?;
    }

    Ok((total_entity_count, total_files, linked_relations.len()))
}

/// Collect all source files, skipping common artifact directories.
fn collect_source_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_source_files_recursive(root, &mut files)?;
    Ok(files)
}

fn collect_source_files_recursive(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if path.is_dir() {
            if SKIP_DIRS.contains(&name_str.as_ref()) {
                continue;
            }
            collect_source_files_recursive(&path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }

    Ok(())
}

fn compute_import_change_id(parent: &SemanticChangeId, repo_name: &str) -> SemanticChangeId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-change-v1:");
    hasher.update(format!("kin import: {}", repo_name).as_bytes());
    hasher.update(b":");
    hasher.update(parent.0.as_bytes());
    hasher.update(b":");
    hasher.update(chrono::Utc::now().to_rfc3339().as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    SemanticChangeId::from_hash(Hash256::from_bytes(bytes))
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_remote_urls() {
        assert!(is_remote_url("https://github.com/user/repo"));
        assert!(is_remote_url("http://example.com/repo.git"));
        assert!(is_remote_url("git@github.com:user/repo.git"));
        assert!(is_remote_url("ssh://git@github.com/user/repo.git"));
    }

    #[test]
    fn detects_local_paths() {
        assert!(!is_remote_url("/home/user/project"));
        assert!(!is_remote_url("./relative/path"));
        assert!(!is_remote_url("../sibling/repo"));
    }

    #[test]
    fn derives_repo_name_from_url() {
        assert_eq!(
            derive_repo_name("https://github.com/user/my-project.git"),
            "my-project"
        );
        assert_eq!(
            derive_repo_name("https://github.com/user/my-project"),
            "my-project"
        );
        assert_eq!(derive_repo_name("git@github.com:user/repo.git"), "repo");
    }

    #[test]
    fn derives_repo_name_from_local_path() {
        assert_eq!(derive_repo_name("/home/user/my-project"), "my-project");
        assert_eq!(derive_repo_name("./my-project"), "my-project");
    }
}
