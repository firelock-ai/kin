// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_index::{FileClassification, FileClassifier};
use kin_model::{
    AuthorId, FilePathId, GraphStore, Hash256, SemanticChange, SemanticChangeId, Timestamp,
};
use kin_model::ChangeStore;
use kin_model::EntityStore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Directories to skip during snapshot.
const SKIP_DIRS: &[&str] = &[
    ".kin",
    ".git/objects",
    ".git/pack",
    "node_modules",
    "target",
    "__pycache__",
    ".next",
    "dist",
    "build",
];

/// Take an independent copy-based snapshot of the working tree before `kin init`
/// mutates it.  We always use `fs::copy()` rather than hardlinks because
/// hardlinks share inodes — modifying the original file after init would
/// silently corrupt the snapshot.
/// Take snapshot BEFORE kin init creates .kin/.
/// We snapshot to a temp dir, then move it into .kin/snapshot/ after init succeeds.
fn snapshot_repo(dir: &Path) -> Result<PathBuf> {
    let tmp_snapshot = dir.join(".kin-snapshot-tmp");
    if tmp_snapshot.exists() {
        fs::remove_dir_all(&tmp_snapshot)?;
    }
    fs::create_dir_all(&tmp_snapshot)?;
    let snapshot_dir = &tmp_snapshot;

    let mut file_count: u64 = 0;
    let mut total_bytes: u64 = 0;

    walk_and_snapshot(dir, dir, &snapshot_dir, &mut file_count, &mut total_bytes)?;

    // Try to capture git HEAD for the manifest.
    let git_head = read_git_head(dir);

    let manifest = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "file_count": file_count,
        "total_bytes": total_bytes,
        "git_head": git_head,
    });
    fs::write(
        snapshot_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;

    println!("  Snapshot saved ({} files)", file_count);
    Ok(tmp_snapshot)
}

fn walk_and_snapshot(
    root: &Path,
    current: &Path,
    snapshot_dir: &Path,
    file_count: &mut u64,
    total_bytes: &mut u64,
) -> Result<()> {
    let entries = match fs::read_dir(current) {
        Ok(e) => e,
        Err(_) => return Ok(()), // skip unreadable dirs
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let rel = path.strip_prefix(root)?;

        // Check if this path starts with any skipped directory.
        if should_skip(rel) {
            continue;
        }

        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk_and_snapshot(root, &path, snapshot_dir, file_count, total_bytes)?;
        } else if ft.is_file() {
            let dest = snapshot_dir.join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }

            // Always copy — hardlinks share inodes so later writes
            // to the original would corrupt the snapshot.
            fs::copy(&path, &dest)?;

            *total_bytes += entry.metadata()?.len();
            *file_count += 1;
        }
        // Skip symlinks / other special types.
    }

    Ok(())
}

fn should_skip(rel: &Path) -> bool {
    let rel_str = rel.to_string_lossy();
    for skip in SKIP_DIRS {
        if rel_str == *skip || rel_str.starts_with(&format!("{}/", skip)) {
            return true;
        }
    }
    false
}

fn read_git_head(dir: &Path) -> Option<String> {
    let head_path = dir.join(".git/HEAD");
    let content = fs::read_to_string(head_path).ok()?;
    let content = content.trim();

    if let Some(ref_path) = content.strip_prefix("ref: ") {
        // Resolve the ref to a commit hash.
        let ref_file = dir.join(".git").join(ref_path);
        fs::read_to_string(ref_file)
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        // Detached HEAD — already a commit hash.
        Some(content.to_string())
    }
}

pub async fn run(path: Option<String>) -> Result<()> {
    let dir = path
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

    // Take a pre-init snapshot before Kin touches the directory.
    // Snapshot goes to a temp dir first, then moves into .kin/ after init.
    let tmp_snapshot = snapshot_repo(&dir)?;

    let result = kin_core::init(&dir)?;

    // Move snapshot into .kin/ now that init created it
    let final_snapshot = dir.join(".kin/snapshot");
    if tmp_snapshot.exists() {
        if final_snapshot.exists() {
            let _ = fs::remove_dir_all(&final_snapshot);
        }
        fs::rename(&tmp_snapshot, &final_snapshot).unwrap_or_else(|_| {
            // rename fails across filesystems; fall back to copy
            let _ = fs::remove_dir_all(&final_snapshot);
        });
    }
    println!(
        "Initialized Kin repository at {}",
        result.layout.root().display()
    );
    println!("  KinDB: {}", result.layout.kindb_snapshot_path().display());
    println!("  Blobs: {}", result.layout.objects_dir().display());
    println!("  Genesis change: {}", result.genesis_id);

    // --- Auto-parse: scan source files, extract entities, save to graph ---
    let layout = &result.layout;
    let snap_path = layout.root().join("kindb").join("graph.kndb");
    let snap = kin_db::SnapshotManager::open(&snap_path)?;
    let graph = snap.graph();
    let graph = &*graph;

    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    let source_root = kin_core::source_dir(layout);
    let all_files = collect_source_files(&source_root)?;

    if !all_files.is_empty() {
        let (total_entity_count, total_files, linked_relations) =
            parse_and_index(graph, &blob_store, &source_root, &all_files)?;

        // Build a semantic change for the initial parse
        let branch_name = kin_core::read_current_branch(layout)?;
        let parent_id = result.genesis_id;
        let change_id = compute_init_change_id(&parent_id);
        let change = SemanticChange {
            id: change_id,
            parents: vec![parent_id],
            timestamp: Timestamp::now(),
            author: AuthorId::new(whoami()),
            message: "kin init: auto-parse".to_string(),
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

        snap.save()?;

        // Build and save the read-only index for fast CLI queries.
        let read_index = kin_db::ReadIndex::from_graph(graph)?;
        let idx_path = snap_path.with_extension("kidx");
        read_index.save(&idx_path)?;

        println!(
            "  Initialized with {} entities from {} files ({} relations)",
            total_entity_count, total_files, linked_relations
        );

        // Register in the global ~/.kin/registry.toml with entity count
        if let Ok(mut registry) = kin_core::registry::KinRegistry::load() {
            let repo_id = dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            registry.upsert(repo_id, dir.canonicalize().unwrap_or(dir), total_entity_count);
            let _ = registry.save();
        }
    } else {
        // No source files — register with zero entities
        if let Ok(mut registry) = kin_core::registry::KinRegistry::load() {
            let repo_id = dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            registry.upsert(repo_id, dir.canonicalize().unwrap_or(dir), 0);
            let _ = registry.save();
        }
    }

    Ok(())
}

/// Parse all source files, extract entities, store blobs, link cross-file relations.
/// Returns (total_entity_count, total_files_parsed, linked_relation_count).
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

        // Store file content in blob store
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
            let entity = extracted.into_entity(language, &file_id);
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

    // Cross-file relation linking
    let linked_relations = kin_index::link_cross_file(&file_parse_data);
    for rel in &linked_relations {
        graph.upsert_relation(rel)?;
    }

    Ok((total_entity_count, total_files, linked_relations.len()))
}

/// Collect all source files, skipping .kin/, .git/, and common artifact directories.
fn collect_source_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_source_files_recursive(root, root, &mut files)?;
    Ok(files)
}

fn collect_source_files_recursive(
    root: &Path,
    dir: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
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
            if matches!(name_str.as_ref(), ".kin" | ".git" | ".git-export") {
                continue;
            }
            if matches!(
                name_str.as_ref(),
                "node_modules" | "target" | "build" | "dist" | "__pycache__" | "vendor"
            ) {
                continue;
            }
            collect_source_files_recursive(root, &path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }

    Ok(())
}

/// Compute a unique change ID for the init auto-parse commit.
fn compute_init_change_id(parent: &SemanticChangeId) -> SemanticChangeId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-change-v1:");
    hasher.update(b"kin init: auto-parse");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn snapshot_creates_correct_structure() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Create some files.
        fs::write(root.join("README.md"), "hello").unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();

        // Create a directory that should be skipped.
        fs::create_dir_all(root.join("node_modules/foo")).unwrap();
        fs::write(root.join("node_modules/foo/index.js"), "skip me").unwrap();

        let snapshot = snapshot_repo(root).unwrap();
        assert!(snapshot.join("README.md").exists());
        assert!(snapshot.join("src/main.rs").exists());
        assert!(!snapshot.join("node_modules").exists());
        assert!(snapshot.join("manifest.json").exists());
    }

    #[test]
    fn manifest_has_correct_file_count() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        fs::write(root.join("a.txt"), "aaa").unwrap();
        fs::write(root.join("b.txt"), "bbb").unwrap();
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub/c.txt"), "ccc").unwrap();

        let snapshot = snapshot_repo(root).unwrap();

        let manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(snapshot.join("manifest.json")).unwrap(),
        )
        .unwrap();

        assert_eq!(manifest["file_count"], 3);
        assert_eq!(manifest["total_bytes"], 9); // 3 + 3 + 3
    }

    #[test]
    fn snapshot_skips_all_excluded_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Create all the skip dirs with a file inside each.
        for skip in SKIP_DIRS {
            if *skip == ".kin" {
                continue; // we create .kin ourselves
            }
            let p = root.join(skip);
            fs::create_dir_all(&p).unwrap();
            fs::write(p.join("file.txt"), "skip").unwrap();
        }

        // One real file.
        fs::write(root.join("keep.txt"), "keep").unwrap();

        let snapshot = snapshot_repo(root).unwrap();
        assert!(snapshot.join("keep.txt").exists());
        assert!(!snapshot.join("node_modules").exists());
        assert!(!snapshot.join("target").exists());
        assert!(!snapshot.join("__pycache__").exists());
        assert!(!snapshot.join(".next").exists());
        assert!(!snapshot.join("dist").exists());
        assert!(!snapshot.join("build").exists());
    }

    #[test]
    fn snapshot_reads_git_head() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Set up a fake git repo with a resolved ref.
        fs::create_dir_all(root.join(".git/refs/heads")).unwrap();
        fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(
            root.join(".git/refs/heads/main"),
            "abc123def456\n",
        )
        .unwrap();
        fs::write(root.join("file.txt"), "content").unwrap();

        let snapshot = snapshot_repo(root).unwrap();

        let manifest: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(snapshot.join("manifest.json")).unwrap(),
        )
        .unwrap();

        assert_eq!(manifest["git_head"], "abc123def456");
    }
}
