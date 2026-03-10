use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::error::{RuntimeError, Result};

/// A workspace represents a working directory managed by Kin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    /// Unique workspace ID.
    pub id: String,
    /// Root path of the workspace.
    pub root: PathBuf,
    /// When the workspace was created.
    pub created_at: DateTime<Utc>,
    /// Current snapshot ID (content hash of workspace state).
    pub snapshot_id: Option<String>,
}

/// A snapshot of workspace state at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSnapshot {
    /// Content-addressed ID for this snapshot.
    pub id: String,
    /// Which workspace this belongs to.
    pub workspace_id: String,
    /// When the snapshot was taken.
    pub timestamp: DateTime<Utc>,
    /// Files included in the snapshot (relative paths).
    pub files: Vec<String>,
    /// Combined content hash.
    pub content_hash: String,
}

/// Create a workspace descriptor for a given directory.
pub fn create_workspace(root: &Path) -> Result<Workspace> {
    if !root.exists() {
        return Err(RuntimeError::WorkspaceNotFound(
            root.display().to_string(),
        ));
    }

    let id = uuid::Uuid::new_v4().to_string();
    info!(workspace_id = %id, root = %root.display(), "created workspace");

    Ok(Workspace {
        id,
        root: root.to_path_buf(),
        created_at: Utc::now(),
        snapshot_id: None,
    })
}

/// Take a snapshot of the workspace by hashing a list of file paths.
///
/// This computes a deterministic content hash from the sorted file list.
/// The actual file contents are stored separately in the blob store.
pub fn snapshot_workspace(
    workspace: &Workspace,
    files: Vec<String>,
) -> Result<WorkspaceSnapshot> {
    let mut sorted_files = files;
    sorted_files.sort();

    let mut hasher = Sha256::new();
    for f in &sorted_files {
        hasher.update(f.as_bytes());
        hasher.update(b"\n");
    }
    let hash_bytes = hasher.finalize();
    let content_hash = hex::encode(hash_bytes);

    let snapshot_id = format!("snap-{}", &content_hash[..16]);

    info!(
        snapshot_id = %snapshot_id,
        workspace_id = %workspace.id,
        file_count = sorted_files.len(),
        "workspace snapshot taken"
    );

    Ok(WorkspaceSnapshot {
        id: snapshot_id,
        workspace_id: workspace.id.clone(),
        timestamp: Utc::now(),
        files: sorted_files,
        content_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_workspace_from_existing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let ws = create_workspace(dir.path()).unwrap();
        assert_eq!(ws.root, dir.path());
        assert!(ws.snapshot_id.is_none());
        assert!(!ws.id.is_empty());
    }

    #[test]
    fn create_workspace_missing_dir_fails() {
        let err = create_workspace(Path::new("/nonexistent/path/xyz")).unwrap_err();
        assert!(matches!(err, RuntimeError::WorkspaceNotFound(_)));
    }

    #[test]
    fn snapshot_deterministic_hash() {
        let dir = tempfile::tempdir().unwrap();
        let ws = create_workspace(dir.path()).unwrap();
        let files = vec!["src/main.rs".to_string(), "Cargo.toml".to_string()];
        let snap1 = snapshot_workspace(&ws, files.clone()).unwrap();
        let snap2 = snapshot_workspace(&ws, files).unwrap();
        assert_eq!(snap1.content_hash, snap2.content_hash);
    }

    #[test]
    fn snapshot_sorts_files() {
        let dir = tempfile::tempdir().unwrap();
        let ws = create_workspace(dir.path()).unwrap();
        let files_a = vec!["b.rs".to_string(), "a.rs".to_string()];
        let files_b = vec!["a.rs".to_string(), "b.rs".to_string()];
        let snap_a = snapshot_workspace(&ws, files_a).unwrap();
        let snap_b = snapshot_workspace(&ws, files_b).unwrap();
        // Same files in different order produce same hash.
        assert_eq!(snap_a.content_hash, snap_b.content_hash);
        assert_eq!(snap_a.files, vec!["a.rs", "b.rs"]);
    }

    #[test]
    fn workspace_serializes() {
        let dir = tempfile::tempdir().unwrap();
        let ws = create_workspace(dir.path()).unwrap();
        let json = serde_json::to_string(&ws).unwrap();
        let parsed: Workspace = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, ws.id);
    }
}
