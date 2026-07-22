// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use anyhow::{Context, Result};
use kin_model::{
    ChangeStore, FilePathId, Hash256, ResolvedSourceEntry, SemanticChangeId, SourceEntryKind,
    SourceTreeResolution,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutRequest {
    pub path: String,
    #[serde(default)]
    pub change_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutResponse {
    #[serde(default)]
    pub lines: Vec<String>,
}

pub async fn run(path: String, change_id: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let response = run_daemon_checkout(&layout, &CheckoutRequest { path, change_id }).await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_checkout(
    layout: &kin_core::KinLayout,
    request: &CheckoutRequest,
) -> Result<CheckoutResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for checkout but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .checkout(request)
        .await
        .context("daemon checkout failed")
}

pub fn execute_checkout_request(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &CheckoutRequest,
) -> Result<CheckoutResponse> {
    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    let target_head = match &request.change_id {
        Some(id) => {
            let hash = Hash256::from_hex(id).map_err(|_| {
                anyhow::anyhow!(
                    "invalid change id '{}': expected a 64-character hex string",
                    id
                )
            })?;
            SemanticChangeId::from_hash(hash)
        }
        None => {
            let branch_name = kin_core::read_current_branch(layout)?;
            let branch = graph.get_branch(&branch_name)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "current branch '{}' not found in graph. Run `kin init` first.",
                    branch_name
                )
            })?;
            branch.head
        }
    };

    let tree = resolve_exact_checkout_tree(graph, &target_head)?;

    let normalized = normalize_checkout_path(&request.path);

    if normalized == "." || normalized == "*" || normalized.is_empty() {
        // Checkout the entire tree!
        // 1. Write/restore all files in the tree
        let entries = load_and_validate_checkout_entries(&blob_store, tree.iter())?;

        let source_root = layout.working_dir();
        kin_core::replace_source_tree(
            source_root,
            entries
                .iter()
                .map(|entry| (&entry.file_id, entry.kind, entry.content.as_slice())),
            should_skip_checkout_clean,
        )
        .map_err(|error| anyhow::anyhow!("failed to materialize exact source tree: {error}"))?;

        return Ok(CheckoutResponse {
            lines: vec![format!("Checked out all files from change {}", target_head)],
        });
    }

    let file_id = FilePathId(normalized.to_string());

    let source = tree.get(&file_id).ok_or_else(|| {
        anyhow::anyhow!(
            "file '{}' not found in the semantic tree at change {}",
            normalized,
            target_head
        )
    })?;
    let prepared = load_and_validate_checkout_entries(&blob_store, [(&file_id, source)])?;
    let entry = prepared
        .first()
        .expect("single-file checkout preflight returns one entry");
    kin_core::materialize_source_tree(
        layout.working_dir(),
        [(&entry.file_id, entry.kind, entry.content.as_slice())],
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "failed to materialize exact source '{}': {}",
            normalized,
            error
        )
    })?;

    Ok(CheckoutResponse {
        lines: vec![format!(
            "Restored '{}' from change {}",
            normalized, target_head
        )],
    })
}

struct PreparedCheckoutEntry {
    file_id: FilePathId,
    kind: SourceEntryKind,
    content: Vec<u8>,
}

/// Resolve and verify every graph-owned source object before checkout mutates
/// the working tree. `BlobStore::read` performs the SHA-256 verification bound
/// to the requested content address; the tree validator then checks the whole
/// path set, entry kinds, UTF-8 link payloads, and link targets without IO.
fn load_and_validate_checkout_entries<'a>(
    blob_store: &kin_blobs::BlobStore,
    entries: impl IntoIterator<Item = (&'a FilePathId, &'a ResolvedSourceEntry)>,
) -> Result<Vec<PreparedCheckoutEntry>> {
    let mut entries: Vec<_> = entries.into_iter().collect();
    entries.sort_by(|left, right| left.0 .0.cmp(&right.0 .0));

    let mut prepared = Vec::with_capacity(entries.len());
    for (file_id, source) in entries {
        let blob_key = kin_blobs::Hash256(*source.hash.as_bytes());
        let content = blob_store.read(&blob_key).map_err(|error| {
            anyhow::anyhow!("failed to read blob for '{}': {}", file_id.0, error)
        })?;
        prepared.push(PreparedCheckoutEntry {
            file_id: file_id.clone(),
            kind: source.kind,
            content,
        });
    }
    kin_core::validate_source_tree(
        prepared
            .iter()
            .map(|entry| (&entry.file_id, entry.kind, entry.content.as_slice())),
    )?;
    Ok(prepared)
}

fn resolve_exact_checkout_tree(
    graph: &kin_db::InMemoryGraph,
    target_head: &SemanticChangeId,
) -> Result<HashMap<FilePathId, ResolvedSourceEntry>> {
    match graph.resolve_source_tree_at(target_head)? {
        SourceTreeResolution::Exact { entries } => Ok(entries),
        SourceTreeResolution::Incomplete { gaps } => {
            let gaps = gaps
                .iter()
                .map(|gap| format!("{}@{}:{:?}", gap.file_id, gap.change_id, gap.reason))
                .collect::<Vec<_>>()
                .join(", ");
            Err(anyhow::anyhow!(
                "checkout requires exact source history at {}, but found unresolved gaps: {}",
                target_head,
                gaps
            ))
        }
    }
}

fn should_skip_checkout_clean(rel: &std::path::Path) -> bool {
    kin_core::should_preserve_checkout_path(rel)
}

fn normalize_checkout_path(path: &str) -> &str {
    path.strip_prefix("./").unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{ArtifactDelta, ArtifactDeltaKind, AuthorId, SemanticChange, Timestamp};

    #[test]
    fn normalizes_relative_path_prefix() {
        assert_eq!(normalize_checkout_path("./src/main.rs"), "src/main.rs");
    }

    #[test]
    fn absolute_path_unchanged_by_normalization() {
        assert_eq!(normalize_checkout_path("src/lib.rs"), "src/lib.rs");
    }

    #[test]
    fn invalid_change_id_produces_helpful_error() {
        let bad_id = "not-a-hex-string";
        let result = Hash256::from_hex(bad_id);
        assert!(result.is_err());
    }

    #[test]
    fn file_path_id_equality() {
        let a = FilePathId("src/main.rs".to_string());
        let b = FilePathId("src/main.rs".to_string());
        assert_eq!(a, b);
    }

    #[test]
    fn checkout_clean_skip_is_component_aware() {
        assert!(should_skip_checkout_clean(std::path::Path::new(".kin")));
        assert!(should_skip_checkout_clean(std::path::Path::new(
            ".git/config"
        )));
        assert!(should_skip_checkout_clean(std::path::Path::new(
            "nested/.KIN-SESSION/base.json"
        )));
        assert!(should_skip_checkout_clean(std::path::Path::new(
            "target/debug/app"
        )));
        assert!(should_skip_checkout_clean(std::path::Path::new(
            "crates/app/target/debug/app"
        )));
        assert!(should_skip_checkout_clean(std::path::Path::new(
            "web/node_modules/pkg/index.js"
        )));
        assert!(!should_skip_checkout_clean(std::path::Path::new(
            "src/lib.rs"
        )));
    }

    #[cfg(unix)]
    #[test]
    fn full_tree_projection_ignores_tracked_and_skip_dirs() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join(".kin")).unwrap();
        std::fs::create_dir_all(root.join(".kin-session")).unwrap();
        std::fs::create_dir_all(root.join("target/debug")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "tracked").unwrap();
        std::fs::write(root.join("src/old.rs"), "delete").unwrap();
        std::fs::write(root.join(".kin/state"), "keep").unwrap();
        std::fs::write(root.join(".kin-session/base.json"), "keep").unwrap();
        std::fs::write(root.join("target/debug/app"), "keep").unwrap();

        let tracked = FilePathId("src/lib.rs".to_string());
        kin_core::replace_source_tree(
            root,
            [(
                &tracked,
                SourceEntryKind::File { executable: false },
                b"new".as_slice(),
            )],
            should_skip_checkout_clean,
        )
        .unwrap();

        assert_eq!(std::fs::read(root.join("src/lib.rs")).unwrap(), b"new");
        assert!(!root.join("src/old.rs").exists());
        assert!(root.join(".kin/state").exists());
        assert!(root.join(".kin-session/base.json").exists());
        assert!(root.join("target/debug/app").exists());
    }

    #[cfg(unix)]
    #[test]
    fn full_tree_projection_leaves_blocking_ancestor_for_tree_preparation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::write(root.join("a-parent"), "blocking file").unwrap();
        std::fs::write(root.join("untracked.txt"), "delete").unwrap();

        let tracked = FilePathId("a-parent/child.txt".to_string());
        kin_core::replace_source_tree(
            root,
            [(
                &tracked,
                SourceEntryKind::File { executable: false },
                b"child".as_slice(),
            )],
            should_skip_checkout_clean,
        )
        .unwrap();

        assert_eq!(
            std::fs::read(root.join("a-parent/child.txt")).unwrap(),
            b"child"
        );
        assert!(!root.join("untracked.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn full_tree_projection_removes_only_untracked_empty_dirs() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("src/empty/nested")).unwrap();
        std::fs::create_dir_all(root.join(".kin/empty")).unwrap();
        std::fs::create_dir_all(root.join("crates/app/target")).unwrap();

        let tracked = FilePathId("tracked.txt".to_string());
        kin_core::replace_source_tree(
            root,
            [(
                &tracked,
                SourceEntryKind::File { executable: false },
                b"tracked".as_slice(),
            )],
            should_skip_checkout_clean,
        )
        .unwrap();

        assert!(!root.join("src/empty").exists());
        assert!(root.join(".kin/empty").exists());
        assert!(root.join("crates/app/target").exists());
    }

    #[test]
    fn late_missing_blob_preserves_destructive_transition_tree() {
        let temp = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(temp.path().join(".kin"));
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();
        let valid_hash = blob_store.write(b"new child\n").unwrap();
        let missing_hash = Hash256::from_bytes([0xf1; 32]);
        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0xa1; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("checkout-test"),
            message: "exact checkout fixture".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![
                ArtifactDelta {
                    file_id: FilePathId("a-parent/child.txt".to_string()),
                    kind: ArtifactDeltaKind::AddedRegularFile,
                    old_hash: None,
                    new_hash: Some(valid_hash),
                },
                ArtifactDelta {
                    file_id: FilePathId("z-missing.txt".to_string()),
                    kind: ArtifactDeltaKind::AddedRegularFile,
                    old_hash: None,
                    new_hash: Some(missing_hash),
                },
            ],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        let graph = kin_db::InMemoryGraph::new();
        graph.create_change(&change).unwrap();

        std::fs::write(temp.path().join("a-parent"), b"old file stays\n").unwrap();
        std::fs::write(temp.path().join("sentinel"), b"untouched\n").unwrap();

        let error = execute_checkout_request(
            &layout,
            &graph,
            &CheckoutRequest {
                path: ".".to_string(),
                change_id: Some(change.id.to_string()),
            },
        )
        .expect_err("all blobs must verify before a file-to-directory transition");

        assert!(error.to_string().contains("z-missing.txt"));
        let metadata = std::fs::symlink_metadata(temp.path().join("a-parent")).unwrap();
        assert!(
            metadata.is_file(),
            "the blocking file shape must be preserved"
        );
        assert_eq!(
            std::fs::read(temp.path().join("a-parent")).unwrap(),
            b"old file stays\n"
        );
        assert_eq!(
            std::fs::read(temp.path().join("sentinel")).unwrap(),
            b"untouched\n"
        );
        assert!(!temp.path().join("a-parent/child.txt").exists());
    }

    #[test]
    fn checkout_replaces_blocking_ancestor_without_redeleting_new_directory() {
        let temp = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(temp.path().join(".kin"));
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();
        let child_hash = blob_store.write(b"new child\n").unwrap();
        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0xa2; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("checkout-test"),
            message: "blocking ancestor fixture".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![ArtifactDelta {
                file_id: FilePathId("a-parent/child.txt".to_string()),
                kind: ArtifactDeltaKind::AddedRegularFile,
                old_hash: None,
                new_hash: Some(child_hash),
            }],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        let graph = kin_db::InMemoryGraph::new();
        graph.create_change(&change).unwrap();

        std::fs::write(temp.path().join("a-parent"), b"old blocking file\n").unwrap();
        std::fs::write(temp.path().join("untracked.txt"), b"remove me\n").unwrap();

        execute_checkout_request(
            &layout,
            &graph,
            &CheckoutRequest {
                path: ".".to_string(),
                change_id: Some(change.id.to_string()),
            },
        )
        .expect("blocking ancestor should be replaced by the tracked tree");

        assert!(temp.path().join("a-parent").is_dir());
        assert_eq!(
            std::fs::read(temp.path().join("a-parent/child.txt")).unwrap(),
            b"new child\n"
        );
        assert!(!temp.path().join("untracked.txt").exists());
    }
}
