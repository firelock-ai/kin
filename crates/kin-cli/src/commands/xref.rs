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
}

pub async fn run(entity: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
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
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for xref but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.xref(request).await.context("daemon xref failed")
}

pub async fn build_xref_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &XrefRequest,
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
        });
    }

    let target = &matches[0];
    let mut lines = vec![format!(
        "Cross-repo references (xrefs) for '{}':",
        target.name
    )];

    let repo_id = crate::commands::remote::resolve_repo_id(layout)?;

    match crate::backend::get_spine_xref(layout, &repo_id, &target.id).await {
        Ok(query) => lines.extend(spine_xref_lines(query, &repo_id, &target.id)),
        Err(e) => {
            lines.push(format!("  Failed to query spine: {}", e));
        }
    }

    Ok(XrefResponse { lines })
}

fn spine_xref_lines(
    query: ::kin_spine::SpineQuery<::kin_spine::SpineXrefResponse>,
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
            for edge in response.edges {
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
        "      that defines it, or import that repo so it joins the spine (`kin import`, `kin deps`)."
            .to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::{spine_xref_lines, xref_not_found_guidance};
    use kin_model::EntityId;

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
            joined.contains("kin import") || joined.contains("kin deps"),
            "should give an actionable next step: {joined}"
        );
    }

    #[test]
    fn incomplete_empty_xref_never_claims_no_references() {
        let entity_id = EntityId::new();
        let response = kin_spine::SpineXrefResponse::new(Vec::new(), Vec::new());
        let lines = spine_xref_lines(
            kin_spine::SpineQuery::Found(response),
            "provider",
            &entity_id,
        );
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
        let lines = spine_xref_lines(
            kin_spine::SpineQuery::Found(response),
            "provider",
            &entity_id,
        );
        assert_eq!(
            lines,
            vec!["  No cross-repo references found in the spine."]
        );
    }
}
