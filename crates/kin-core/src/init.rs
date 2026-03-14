use std::path::Path;

use kin_blobs::BlobStore;
use kin_model::{
    AuthorId, Branch, BranchName, Hash256, SemanticChange, SemanticChangeId, Timestamp,
};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::config::KinConfig;
use crate::error::{KinError, Result};
use crate::layout::KinLayout;
use crate::manifest::KinManifest;

/// Result of `kin init`.
#[derive(Debug)]
pub struct InitResult {
    pub layout: KinLayout,
    pub config: KinConfig,
    pub manifest: KinManifest,
    pub genesis_id: SemanticChangeId,
}

/// Build the genesis `SemanticChange` — the synthetic root with zero parents.
///
/// Every Kin repo starts with this change. It eliminates `Option<SemanticChangeId>`
/// sprawl throughout the codebase.
pub fn build_genesis_change() -> SemanticChange {
    // Deterministic content hash for the genesis change.
    let mut hasher = Sha256::new();
    hasher.update(b"kin-genesis-v1");
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes(bytes));

    SemanticChange {
        id: genesis_id,
        parents: vec![], // Genesis has zero parents.
        timestamp: Timestamp::now(),
        author: AuthorId::new("kin"),
        message: "kin init".to_string(),
        entity_deltas: vec![],
        relation_deltas: vec![],
        artifact_deltas: vec![],
        projected_files: vec![],
        spec_link: None,
        evidence: vec![],
        risk_summary: None,
        authored_on: Some(BranchName::new("main")),
    }
}

/// Initialize a new Kin repository at `working_dir`.
///
/// Creates the `.kin/` directory structure, writes config and manifest,
/// initializes the blob store, opens the KuzuDB graph, creates the genesis
/// change and default branch, and writes the HEAD file.
///
/// # Errors
///
/// Returns `KinError::AlreadyInitialized` if `.kin/` already exists.
pub fn init(working_dir: &Path) -> Result<InitResult> {
    let kin_dir = working_dir.join(".kin");

    if kin_dir.exists() {
        return Err(KinError::AlreadyInitialized(
            working_dir.display().to_string(),
        ));
    }

    // Create .kin/ root.
    std::fs::create_dir_all(&kin_dir).map_err(|e| KinError::io(&kin_dir, e))?;

    let layout = KinLayout::new(kin_dir);

    // Create all subdirectories.
    for dir in layout.all_dirs() {
        std::fs::create_dir_all(&dir).map_err(|e| KinError::io(&dir, e))?;
    }

    // Write default config.
    let config = KinConfig::default();
    config.save(&layout.config_path())?;

    // Write manifest.
    let manifest = KinManifest::new();
    manifest.save(&layout.manifest_path())?;

    // Initialize blob store (creates root dir, which already exists but that's fine).
    let _blob_store = BlobStore::new(layout.objects_dir()).map_err(|e| KinError::Blob(e))?;

    // Create in-memory graph and save to snapshot.
    let graph = kin_db::InMemoryGraph::new();

    // Build genesis change and initialize graph with genesis + default branch.
    let genesis = build_genesis_change();
    let genesis_id = genesis.id;
    init_graph(&graph, &genesis, &config.default_branch)?;

    // Save the graph to a KinDB snapshot.
    let kindb_dir = layout.root().join("kindb");
    std::fs::create_dir_all(&kindb_dir).map_err(|e| KinError::io(&kindb_dir, e))?;
    let snap_path = kindb_dir.join("graph.kndb");
    let snap = kin_db::SnapshotManager::new(&snap_path);
    snap.swap(graph);
    snap.save().map_err(|e| KinError::Graph(e.to_string()))?;

    // Write HEAD file pointing to the default branch.
    std::fs::write(&layout.head_path(), &config.default_branch)
        .map_err(|e| KinError::io(&layout.head_path(), e))?;

    info!(
        path = %working_dir.display(),
        genesis = %genesis_id,
        "initialized kin repository"
    );

    Ok(InitResult {
        layout,
        config,
        manifest,
        genesis_id,
    })
}

/// Complete graph initialization after `init`.
///
/// Call this with a concrete `GraphStore` implementation to create the
/// genesis SemanticChange and main branch in the graph database.
pub fn init_graph<G>(graph: &G, genesis: &SemanticChange, branch_name: &str) -> Result<()>
where
    G: kin_model::GraphStore,
{
    graph
        .create_change(genesis)
        .map_err(|e| KinError::Graph(e.to_string()))?;

    let branch = Branch {
        name: BranchName::new(branch_name),
        head: genesis.id,
    };
    graph
        .create_branch(&branch)
        .map_err(|e| KinError::Graph(e.to_string()))?;

    info!(branch = branch_name, head = %genesis.id, "created initial branch");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_change_is_deterministic() {
        let g1 = build_genesis_change();
        let g2 = build_genesis_change();
        assert_eq!(g1.id, g2.id);
        assert!(g1.parents.is_empty());
        assert_eq!(g1.message, "kin init");
    }

    #[test]
    fn init_creates_directory_structure() {
        let dir = tempfile::tempdir().unwrap();
        let result = init(dir.path()).unwrap();

        assert!(result.layout.root().exists());
        assert!(result.layout.config_path().exists());
        assert!(result.layout.manifest_path().exists());
        // KinDB snapshot dir is created by init (replaces old KuzuDB graph_dir)
        assert!(result.layout.root().join("kindb").exists());
        assert!(result.layout.objects_dir().exists());
        assert!(result.layout.stashes_dir().exists());
        assert!(result.layout.projections_dir().exists());
        assert!(result.layout.docs_dir().exists());
        assert!(result.layout.bench_dir().exists());
        assert!(result.layout.runs_dir().exists());
        assert!(result.layout.logs_dir().exists());
        assert!(result.layout.adapters_dir().exists());
        // HEAD file points to default branch
        assert!(result.layout.head_path().exists());
        let head_content = std::fs::read_to_string(result.layout.head_path()).unwrap();
        assert_eq!(head_content, "main");
    }

    #[test]
    fn init_writes_valid_config() {
        let dir = tempfile::tempdir().unwrap();
        let result = init(dir.path()).unwrap();

        let loaded = KinConfig::load(&result.layout.config_path()).unwrap();
        assert_eq!(loaded.default_branch, "main");
    }

    #[test]
    fn init_writes_valid_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let result = init(dir.path()).unwrap();

        let loaded = KinManifest::load(&result.layout.manifest_path()).unwrap();
        assert_eq!(loaded.kin_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn init_rejects_already_initialized() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path()).unwrap();

        let err = init(dir.path()).unwrap_err();
        assert!(matches!(err, KinError::AlreadyInitialized(_)));
    }

    #[test]
    fn init_returns_genesis_id() {
        let dir = tempfile::tempdir().unwrap();
        let result = init(dir.path()).unwrap();

        let genesis = build_genesis_change();
        assert_eq!(result.genesis_id, genesis.id);
    }
}
