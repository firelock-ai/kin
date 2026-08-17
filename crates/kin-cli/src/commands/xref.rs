// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::EntityFilter;
use kin_model::EntityStore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefRequest {
    pub entity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    /// Exact daemon/spine payload behind the human rendering. Keeping it in
    /// the CLI RPC response prevents typed clients from losing incomplete
    /// authority, revision, roots, and anchor information at this boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spine: Option<::kin_spine::SpineXrefResponse>,
}

pub async fn run(entity: String) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let response = run_daemon_xref(&layout, &XrefRequest { entity }).await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_xref(
    layout: &kin_core::KinLayout,
    request: &XrefRequest,
) -> Result<XrefResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url =
        daemon_url.ok_or_else(|| crate::daemon_client::daemon_required_error("xref", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.xref(request).await.context("daemon xref failed")
}

pub async fn build_xref_response(
    graph: &kin_db::InMemoryGraph,
    request: &XrefRequest,
    repo_id: &str,
    graph_root: &str,
    spine_backend: Option<&dyn kin_spine::SpineBackend>,
) -> Result<XrefResponse> {
    // Find the entity by name
    let filter = EntityFilter {
        name_pattern: Some(request.entity.clone()),
        ..Default::default()
    };
    let matches = graph.query_entities(&filter)?;

    if matches.is_empty() {
        return Ok(XrefResponse {
            lines: xref_not_found_guidance(&request.entity),
            spine: None,
        });
    }

    let target = &matches[0];
    let mut lines = vec![format!(
        "Cross-repo references (xrefs) for '{}':",
        target.name
    )];

    let mut spine = None;
    let query = match spine_backend {
        Some(backend) => {
            let response = backend.cross_repo_xref_response(repo_id, &target.id);
            // Same split the MCP surface makes, through the same shared rule: a
            // repository the spine never registered has nothing to mismatch, and
            // reporting it as a root mismatch describes a misconfiguration that
            // does not exist.
            match response.authority_root_state(repo_id, graph_root) {
                ::kin_spine::AuthorityRootState::Matches => {
                    ::kin_spine::SpineQuery::Found(response)
                }
                ::kin_spine::AuthorityRootState::Stale { registered } => {
                    ::kin_spine::SpineQuery::Unavailable(format!(
                        "spine root mismatch for repository {repo_id}: live/session graph root \
                         {graph_root} has advanced past the registered spine root {registered}"
                    ))
                }
                ::kin_spine::AuthorityRootState::Unregistered => {
                    ::kin_spine::SpineQuery::Unavailable(format!(
                        "repository {repo_id} has no registered spine root, so cross-repo \
                         authority cannot answer for it"
                    ))
                }
            }
        }
        None => ::kin_spine::SpineQuery::NotConfigured,
    };
    lines.extend(spine_xref_lines(&query, repo_id, &target.id));
    if let ::kin_spine::SpineQuery::Found(response) = query {
        spine = Some(response);
    }

    Ok(XrefResponse { lines, spine })
}

fn spine_xref_lines(
    query: &::kin_spine::SpineQuery<::kin_spine::SpineXrefResponse>,
    repo_id: &str,
    entity_id: &kin_model::EntityId,
) -> Vec<String> {
    match query {
        ::kin_spine::SpineQuery::Found(response) => {
            let authority_complete = response.authority_complete_for(repo_id, entity_id);
            let mut lines = Vec::new();
            if response.edges.is_empty() {
                if authority_complete {
                    lines.push("  No cross-repo references found in the spine.".to_string());
                } else {
                    lines.push(
                        "  The spine returned no cross-repo edges, but its authority is incomplete — this is not the same as 'no references found'."
                            .to_string(),
                    );
                }
                return lines;
            }

            lines.push(format!(
                "  Found {} cross-repo edges:",
                response.edges.len()
            ));
            for edge in &response.edges {
                lines.push(format!(
                    "    - Impact: [{}] {} depends on us ([{}] {}) (conf: {:.2})",
                    edge.src_repo, edge.src_entity, edge.dst_repo, edge.dst_entity, edge.confidence
                ));
            }
            if !authority_complete {
                lines.push(
                    "  Warning: these are partial results; the spine authority is incomplete and may omit additional references."
                        .to_string(),
                );
            }
            lines
        }
        ::kin_spine::SpineQuery::Unavailable(reason) => vec![format!(
            "  Cross-repo spine unavailable ({reason}) — this is not the same as 'no references found'."
        )],
        ::kin_spine::SpineQuery::NotConfigured => vec![
            "  Cross-repo spine not configured (no daemon endpoint available).".to_string(),
        ],
    }
}

/// Actionable guidance when `kin xref <symbol>` can't resolve the symbol in the
/// current repo's graph.
///
/// `xref` is anchored: it first resolves the symbol to a LOCAL entity, then uses
/// that entity id to query the federated spine for cross-repo edges. With no
/// local match there is no anchor, so the federated lookup can't run. This is
/// also the exact spot `kin refs` hands off to — so a bare "not found" here
/// would dead-end the very path refs points at. Keep the not-found signal but
/// explain the anchor model and the concrete next steps.
fn xref_not_found_guidance(entity: &str) -> Vec<String> {
    vec![
        format!(
            "Entity '{entity}' not found in this repo's graph — xref has no local anchor for the lookup."
        ),
        "hint: `kin xref` finds cross-repo references by first resolving the symbol in THIS repo's"
            .to_string(),
        "      graph, then querying the federated spine for edges to it.".to_string(),
        format!(
            "      If '{entity}' is defined only in a sibling/dependency repo, run xref from the repo"
        ),
        "      that defines it. Use `kin clone URL` for a remote or `kin init PATH` for a clean"
            .to_string(),
        "      existing checkout, then run `kin deps` to refresh dependency discovery."
            .to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        build_xref_response, spine_xref_lines, xref_not_found_guidance, XrefRequest, XrefResponse,
    };
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::graph::EntityStore as _;
    use kin_model::{EntityId, FilePathId, Hash256, LanguageId};
    use kin_spine::SpineBackend as _;

    fn entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: Hash256::from_bytes([4; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/lib.rs")),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn entry(repo_id: &str, entity: &Entity) -> kin_spine::EntityEntry {
        kin_spine::EntityEntry {
            repo_id: repo_id.to_string(),
            entity_id: entity.id,
            name: entity.name.clone(),
            kind: entity.kind,
            signature: entity.signature.clone(),
            fingerprint: entity.fingerprint.clone(),
            file_path: entity.file_origin.as_ref().map(|path| path.0.clone()),
            role: Some(entity.role),
        }
    }

    fn graph_root(graph: &kin_db::InMemoryGraph) -> String {
        hex::encode(graph.compute_root_hash())
    }

    #[test]
    fn xref_not_found_guidance_keeps_signal_and_explains_anchor_model() {
        let lines = xref_not_found_guidance("load_vector_index_into_graph_if_valid");
        // Not-found signal preserved — don't silently swallow the miss.
        assert!(
            lines[0].contains("not found"),
            "first line keeps the not-found signal: {lines:?}"
        );
        let joined = lines.join("\n");
        // Explains why (anchor model) and the concrete next steps.
        assert!(
            joined.contains("anchor"),
            "should explain the anchor model: {joined}"
        );
        assert!(
            joined.contains("kin clone")
                && joined.contains("kin init PATH")
                && joined.contains("kin deps"),
            "should give an actionable next step: {joined}"
        );
    }

    #[test]
    fn incomplete_empty_xref_never_claims_no_references() {
        let entity_id = EntityId::new();
        let response = kin_spine::SpineXrefResponse::new(Vec::new(), Vec::new());
        let query = kin_spine::SpineQuery::Found(response);
        let lines = spine_xref_lines(&query, "provider", &entity_id);
        let joined = lines.join("\n");
        assert!(!joined.contains("No cross-repo references found"));
        assert!(joined.contains("authority is incomplete"));
        assert!(joined.contains("not the same as 'no references found'"));
    }

    #[test]
    fn complete_empty_xref_is_the_only_trustworthy_no_references_control() {
        let entity_id = EntityId::new();
        let encoded = serde_json::to_vec(&serde_json::json!({
            "version": kin_spine::SPINE_PAYLOAD_VERSION,
            "edges": [],
            "authority_anchor": {
                "repo_id": "provider",
                "entity_id": entity_id,
            },
            "authority_complete": true,
            "authority_revision": format!("sha256:{}", "a".repeat(64)),
            "authority_roots": { "provider": "provider-root" },
        }))
        .unwrap();
        let response =
            kin_spine::SpineXrefResponse::from_slice_for(&encoded, "provider", &entity_id).unwrap();
        let query = kin_spine::SpineQuery::Found(response);
        let lines = spine_xref_lines(&query, "provider", &entity_id);
        assert_eq!(
            lines,
            vec!["  No cross-repo references found in the spine."]
        );
    }

    #[test]
    fn xref_rpc_response_preserves_incomplete_spine_authority() {
        let response = XrefResponse {
            lines: vec!["partial".to_string()],
            spine: Some(kin_spine::SpineXrefResponse::new(Vec::new(), Vec::new())),
        };
        let encoded = serde_json::to_vec(&response).unwrap();
        let decoded: XrefResponse = serde_json::from_slice(&encoded).unwrap();
        let spine = decoded.spine.expect("typed spine payload must survive RPC");
        assert!(!spine.authority_complete);
        assert!(spine.authority_revision.is_none());
        assert!(spine.authority_roots.is_empty());
    }

    #[tokio::test]
    async fn daemon_xref_uses_explicit_cached_repo_binding() {
        let graph = kin_db::InMemoryGraph::new();
        let target = entity("target");
        graph.upsert_entity(&target).unwrap();
        let root = graph_root(&graph);
        let spine = kin_spine::InMemorySpineBackend::new();
        spine.register_repo("daemon-X", vec![entry("daemon-X", &target)], &root);
        spine.register_repo("manifest-Y", Vec::new(), "manifest-root");
        let repos = vec!["daemon-X".to_string(), "manifest-Y".to_string()];
        for repo in &repos {
            spine.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }

        let response = build_xref_response(
            &graph,
            &XrefRequest {
                entity: "target".to_string(),
            },
            "daemon-X",
            &root,
            Some(&spine),
        )
        .await
        .unwrap();
        let payload = response.spine.expect("typed spine response");
        assert_eq!(
            payload
                .authority_anchor
                .as_ref()
                .expect("explicit anchor")
                .repo_id,
            "daemon-X"
        );
        assert!(payload.authority_complete_for("daemon-X", &target.id));
    }
}
