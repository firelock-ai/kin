// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{EntityFilter, EntityId, EntityStore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactRequest {
    pub entity: String,
    pub depth: u32,
    /// Optional stable-identity file qualifier. This is line-independent and
    /// lets automation fail closed instead of choosing an arbitrary same-name
    /// declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Optional stable-identity entity-kind qualifier (serde snake_case name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Optional whitespace-normalized declaration signature. Required to
    /// distinguish same-name/same-file overloads on structured callers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Refuse an ambiguous name match. Structured benchmark clients set this;
    /// the legacy human surface retains its deterministic first-match display.
    #[serde(default)]
    pub require_unique: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactResponse {
    pub lines: Vec<String>,
    pub schema_version: String,
    pub resolution: String,
    pub query: ImpactQuery,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ranked: Option<kin_review::RankedImpactReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactQuery {
    pub entity: String,
    pub file: Option<String>,
    pub kind: Option<String>,
    pub signature: Option<String>,
    pub match_count: usize,
}

pub async fn run(
    entity: String,
    depth: u32,
    file: Option<String>,
    kind: Option<String>,
    signature: Option<String>,
    json: bool,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let response = run_daemon_impact(
        &layout,
        &ImpactRequest {
            entity,
            depth,
            file,
            kind,
            signature,
            require_unique: json,
        },
    )
    .await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        for line in response.lines {
            println!("{line}");
        }
    }
    Ok(())
}

async fn run_daemon_impact(
    layout: &kin_core::KinLayout,
    request: &ImpactRequest,
) -> Result<ImpactResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for impact but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.impact(request).await.context("daemon impact failed")
}

pub async fn build_impact_response(
    _layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &ImpactRequest,
) -> Result<ImpactResponse> {
    let mut matches = resolve_entities(graph, request)?;
    matches.sort_by(|left, right| {
        kin_review::StableEntityIdentity::from_entity(left)
            .cmp(&kin_review::StableEntityIdentity::from_entity(right))
            .then_with(|| left.id.cmp(&right.id))
    });

    let query = ImpactQuery {
        entity: request.entity.clone(),
        file: request.file.clone(),
        kind: request.kind.clone(),
        signature: request.signature.clone(),
        match_count: matches.len(),
    };

    if matches.is_empty() {
        return Ok(ImpactResponse {
            lines: impact_not_found_guidance(&request.entity),
            schema_version: kin_review::RANKED_IMPACT_SCHEMA_VERSION.to_string(),
            resolution: "not_found".to_string(),
            query,
            ranked: None,
        });
    }

    if request.require_unique && matches.len() != 1 {
        return Ok(ImpactResponse {
            lines: vec![format!(
                "Entity query '{}' is ambiguous ({} matches); add --file, --kind, and --signature qualifiers.",
                request.entity,
                matches.len()
            )],
            schema_version: kin_review::RANKED_IMPACT_SCHEMA_VERSION.to_string(),
            resolution: "ambiguous".to_string(),
            query,
            ranked: None,
        });
    }

    let target = &matches[0];
    let mut lines = vec![
        format!("Impact analysis for '{}' ({:?}):", target.name, target.kind),
        format!("  Depth: {}", request.depth),
    ];
    if matches.len() > 1 {
        lines.push(format!(
            "  Note: {} matches; showing the deterministic first match. Use --json with --file/--kind/--signature for fail-closed resolution.",
            matches.len()
        ));
    }

    // 1. Local Impact
    let local_impacted = graph.get_downstream_impact(&target.id, request.depth)?;
    if local_impacted.is_empty() {
        lines.push("  No local downstream impact found.".to_string());
    } else {
        lines.push(format!(
            "  {} local entities impacted:",
            local_impacted.len()
        ));
        for e in &local_impacted {
            lines.push(format!("    - {} ({:?}, {})", e.name, e.kind, e.language));
        }
    }

    let ranked = kin_review::rank_impact(graph, &target.id, request.depth)?;
    Ok(ImpactResponse {
        lines,
        schema_version: kin_review::RANKED_IMPACT_SCHEMA_VERSION.to_string(),
        resolution: "resolved".to_string(),
        query,
        ranked: Some(ranked),
    })
}

fn resolve_entities(
    graph: &kin_db::InMemoryGraph,
    request: &ImpactRequest,
) -> Result<Vec<kin_model::Entity>> {
    if let Ok(uuid) = uuid::Uuid::parse_str(&request.entity) {
        return Ok(graph.get_entity(&EntityId(uuid))?.into_iter().collect());
    }

    let filter = EntityFilter {
        name_pattern: Some(request.entity.clone()),
        ..Default::default()
    };
    let mut matches = graph.query_entities(&filter)?;
    // EntityFilter name matching is intentionally broad for search. Impact
    // identity resolution is exact and fail-closed.
    matches.retain(|entity| entity.name == request.entity);
    if let Some(file) = request.file.as_deref() {
        matches.retain(|entity| kin_review::StableEntityIdentity::from_entity(entity).file == file);
    }
    if let Some(kind) = request.kind.as_deref() {
        matches.retain(|entity| kin_review::StableEntityIdentity::from_entity(entity).kind == kind);
    }
    if let Some(signature) = request.signature.as_deref() {
        let normalized = signature.split_whitespace().collect::<Vec<_>>().join(" ");
        matches.retain(|entity| {
            kin_review::StableEntityIdentity::from_entity(entity).signature == normalized
        });
    }
    Ok(matches)
}

/// Actionable guidance when `kin impact <symbol>` can't resolve the symbol in
/// this repo's graph. Keeps the not-found signal, then offers concrete next
/// steps: a name/semantic search to find the right symbol, and a note that
/// impact analysis is local-graph-scoped (cross-repo dependents live behind
/// `kin xref`). Honest by construction — no claim the symbol exists elsewhere.
fn impact_not_found_guidance(entity: &str) -> Vec<String> {
    vec![
        format!("Entity '{entity}' not found in this repo's graph."),
        format!(
            "hint: try `kin search {entity}` to find the symbol by name, or check the spelling."
        ),
        "      `kin impact` analyzes LOCAL downstream impact; for cross-repo dependents use `kin xref`."
            .to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::{build_impact_response, impact_not_found_guidance, ImpactRequest};
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
        FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, Relation, RelationId, RelationKind,
        RelationOrigin, SemanticFingerprint, Visibility,
    };

    fn entity(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::from_content(file, name, "function", 1),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
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

    #[test]
    fn impact_not_found_guidance_keeps_signal_and_offers_next_steps() {
        let lines = impact_not_found_guidance("frobnicate");
        assert!(
            lines[0].contains("not found"),
            "keeps not-found signal: {lines:?}"
        );
        let joined = lines.join("\n");
        assert!(
            joined.contains("kin search frobnicate"),
            "offers a search next step: {joined}"
        );
        assert!(
            joined.contains("kin xref"),
            "notes cross-repo path: {joined}"
        );
    }

    #[tokio::test]
    async fn json_response_exposes_ranked_graph_path_without_replacing_legacy_lines() {
        let graph = kin_db::InMemoryGraph::new();
        let target = entity("changed", "src/lib.rs");
        let caller = entity("caller", "src/caller.rs");
        graph.upsert_entity(&target).unwrap();
        graph.upsert_entity(&caller).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::from_content(
                    &caller.id.to_string(),
                    &target.id.to_string(),
                    "calls",
                ),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(caller.id),
                dst: GraphNodeId::Entity(target.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let response = build_impact_response(
            &layout,
            &graph,
            &ImpactRequest {
                entity: "changed".to_string(),
                depth: 3,
                file: Some("src/lib.rs".to_string()),
                kind: Some("function".to_string()),
                signature: Some("fn changed()".to_string()),
                require_unique: true,
            },
        )
        .await
        .unwrap();

        assert_eq!(response.resolution, "resolved");
        assert!(response.lines[0].contains("Impact analysis"));
        let ranked = response.ranked.expect("ranked impact report");
        assert_eq!(ranked.candidates.len(), 1);
        assert_eq!(ranked.candidates[0].identity.name, "caller");
        assert_eq!(ranked.candidates[0].path.len(), 1);
        assert!(ranked
            .score_semantics
            .contains("not a calibrated probability"));
    }

    #[tokio::test]
    async fn structured_resolution_fails_closed_on_ambiguous_name() {
        let graph = kin_db::InMemoryGraph::new();
        graph.upsert_entity(&entity("same", "src/a.rs")).unwrap();
        graph.upsert_entity(&entity("same", "src/b.rs")).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let response = build_impact_response(
            &layout,
            &graph,
            &ImpactRequest {
                entity: "same".to_string(),
                depth: 3,
                file: None,
                kind: None,
                signature: None,
                require_unique: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(response.resolution, "ambiguous");
        assert_eq!(response.query.match_count, 2);
        assert!(response.ranked.is_none());
    }

    #[tokio::test]
    async fn signature_qualifier_resolves_same_file_same_name_overload() {
        let graph = kin_db::InMemoryGraph::new();
        let mut first = entity("handle", "src/handlers.rs");
        first.signature = "fn handle(value: u32)".to_string();
        let mut second = entity("handle", "src/handlers.rs");
        second.id = EntityId::from_content("src/handlers.rs", "handle", "function", 20);
        second.signature = "fn handle(value: String)".to_string();
        graph.upsert_entity(&first).unwrap();
        graph.upsert_entity(&second).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let response = build_impact_response(
            &layout,
            &graph,
            &ImpactRequest {
                entity: "handle".to_string(),
                depth: 3,
                file: Some("src/handlers.rs".to_string()),
                kind: Some("function".to_string()),
                signature: Some("fn   handle(value: String)".to_string()),
                require_unique: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(response.resolution, "resolved");
        assert_eq!(response.query.match_count, 1);
        assert_eq!(
            response.ranked.unwrap().root_identity.signature,
            "fn handle(value: String)"
        );
    }
}
