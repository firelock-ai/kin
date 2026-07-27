// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{EntityFilter, EntityId, EntityStore};
use serde::{Deserialize, Serialize};

pub const IMPACT_RESPONSE_SCHEMA_VERSION: &str = "kin-impact-response-v1";

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
    #[serde(default)]
    pub schema_version: String,
    #[serde(default)]
    pub resolution: String,
    #[serde(default)]
    pub query: ImpactQuery,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ranked: Option<kin_review::RankedImpactReport>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
        if response.schema_version.is_empty() {
            anyhow::bail!(
                "the running daemon does not support structured ranked impact; restart it with the current Kin build"
            );
        }
        println!("{}", serde_json::to_string_pretty(&response)?);
        if response.resolution != "resolved" {
            anyhow::bail!("impact resolution failed: {}", response.resolution);
        }
    } else {
        for line in response.lines {
            println!("{}", crate::output_style::paint_impact_line(&line));
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
            schema_version: IMPACT_RESPONSE_SCHEMA_VERSION.to_string(),
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
            schema_version: IMPACT_RESPONSE_SCHEMA_VERSION.to_string(),
            resolution: "ambiguous".to_string(),
            query,
            ranked: None,
        });
    }

    let target = &matches[0];
    let target_at = entity_location(target)
        .map(|loc| format!(" @ {loc}"))
        .unwrap_or_default();
    let mut lines = vec![format!(
        "Impact analysis for '{}' ({:?}){}:",
        target.name, target.kind, target_at
    )];
    if matches.len() > 1 {
        lines.push(format!(
            "  Note: {} matches; showing the deterministic first match. Use --json with --file/--kind/--signature for fail-closed resolution.",
            matches.len()
        ));
    }

    // 1. Local Impact, grouped by traversal distance so a reader can tell the
    // direct callers from the transitive ripple. get_downstream_impact(id, d)
    // is one breadth-first walk capped at d, so the set at hop d minus the set
    // at hop d-1 is exactly the entities first reached at distance d; reusing
    // the same traversal per hop keeps the grouped listing consistent with the
    // flat listing it replaces.
    let local_impacted = graph.get_downstream_impact(&target.id, request.depth)?;
    if local_impacted.is_empty() {
        lines.push("  No local downstream impact found.".to_string());
    } else {
        lines.push(format!(
            "  {} local entities impacted within {} hop{}:",
            local_impacted.len(),
            request.depth,
            if request.depth == 1 { "" } else { "s" }
        ));
        let mut listed: std::collections::HashSet<EntityId> = std::collections::HashSet::new();
        for hop in 1..=request.depth {
            let reached = if hop == request.depth {
                local_impacted.clone()
            } else {
                graph.get_downstream_impact(&target.id, hop)?
            };
            let fresh: Vec<&kin_model::Entity> = reached
                .iter()
                .filter(|entity| !listed.contains(&entity.id))
                .collect();
            if fresh.is_empty() {
                continue;
            }
            lines.push(if hop == 1 {
                "  1 hop (direct callers):".to_string()
            } else {
                format!("  {hop} hops:")
            });
            for entity in fresh {
                listed.insert(entity.id);
                let at = entity_location(entity)
                    .map(|loc| format!(" @ {loc}"))
                    .unwrap_or_default();
                lines.push(format!("    - {} ({:?}){}", entity.name, entity.kind, at));
            }
        }
    }

    let ranked = if request.require_unique {
        Some(kin_review::rank_impact(graph, &target.id, request.depth)?)
    } else {
        None
    };
    Ok(ImpactResponse {
        lines,
        schema_version: IMPACT_RESPONSE_SCHEMA_VERSION.to_string(),
        resolution: "resolved".to_string(),
        query,
        ranked,
    })
}

fn resolve_entities(
    graph: &kin_db::InMemoryGraph,
    request: &ImpactRequest,
) -> Result<Vec<kin_model::Entity>> {
    let mut matches = if let Ok(uuid) = uuid::Uuid::parse_str(&request.entity) {
        graph.get_entity(&EntityId(uuid))?.into_iter().collect()
    } else {
        let filter = EntityFilter {
            name_pattern: Some(request.entity.clone()),
            ..Default::default()
        };
        let mut matches = graph.query_entities(&filter)?;
        // The human surface preserves Kin's broad name matching. Structured
        // callers explicitly opt into exact, fail-closed identity resolution.
        if request.require_unique {
            matches.retain(|entity| entity.name == request.entity);
        } else {
            // Broad matching is for discovery: "resolve" should still find
            // resolve_binary. But when the query names an entity exactly,
            // substring cousins (try_resolve_binary alongside resolve_binary)
            // force an ambiguity note onto an unambiguous ask, so an
            // exact-name hit narrows the set to the exact matches.
            let exact: Vec<kin_model::Entity> = matches
                .iter()
                .filter(|entity| entity.name == request.entity)
                .cloned()
                .collect();
            if !exact.is_empty() {
                matches = exact;
            }
        }
        matches
    };
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

/// `path:line` for an entity, or just the path when the graph carries no span.
///
/// Location is projection metadata for the human reading the listing; the
/// analysis itself is keyed on graph identity, never on paths.
fn entity_location(entity: &kin_model::Entity) -> Option<String> {
    let path = entity.file_origin.as_ref().map(|f| f.0.clone())?;
    Some(match entity.span.as_ref().map(|s| s.start_line) {
        Some(line) => format!("{path}:{line}"),
        None => path,
    })
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
    use super::{build_impact_response, impact_not_found_guidance, ImpactRequest, ImpactResponse};
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

    #[test]
    fn legacy_daemon_response_deserializes_without_structured_fields() {
        let response: ImpactResponse =
            serde_json::from_value(serde_json::json!({ "lines": ["legacy"] })).unwrap();
        assert_eq!(response.lines, vec!["legacy"]);
        assert!(response.schema_version.is_empty());
        assert!(response.resolution.is_empty());
        assert_eq!(response.query.match_count, 0);
        assert!(response.ranked.is_none());
    }

    #[tokio::test]
    async fn legacy_human_resolution_preserves_broad_name_matching_and_skips_ranked_work() {
        let graph = kin_db::InMemoryGraph::new();
        graph
            .upsert_entity(&entity("changed", "src/lib.rs"))
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let response = build_impact_response(
            &layout,
            &graph,
            &ImpactRequest {
                entity: "CHANGED".to_string(),
                depth: 3,
                file: None,
                kind: None,
                signature: None,
                require_unique: false,
            },
        )
        .await
        .unwrap();

        assert_eq!(response.resolution, "resolved");
        assert!(response.ranked.is_none());
    }

    #[tokio::test]
    async fn uuid_resolution_still_enforces_identity_qualifiers() {
        let graph = kin_db::InMemoryGraph::new();
        let target = entity("changed", "src/lib.rs");
        let target_id = target.id;
        graph.upsert_entity(&target).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let response = build_impact_response(
            &layout,
            &graph,
            &ImpactRequest {
                entity: target_id.to_string(),
                depth: 3,
                file: Some("src/other.rs".to_string()),
                kind: None,
                signature: None,
                require_unique: true,
            },
        )
        .await
        .unwrap();

        assert_eq!(response.resolution, "not_found");
        assert!(response.ranked.is_none());
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

    fn entity_at(name: &str, file: &str, line: u32) -> Entity {
        let mut e = entity(name, file);
        e.span = Some(kin_model::SourceSpan {
            file: FilePathId::new(file),
            start_byte: 0,
            end_byte: 0,
            start_line: line,
            start_col: 0,
            end_line: line,
            end_col: 0,
        });
        e
    }

    #[tokio::test]
    async fn exact_name_query_is_not_forced_ambiguous_by_substring_cousins() {
        let graph = kin_db::InMemoryGraph::new();
        graph
            .upsert_entity(&entity("resolve_binary", "src/a.rs"))
            .unwrap();
        graph
            .upsert_entity(&entity("try_resolve_binary", "src/b.rs"))
            .unwrap();
        // Falsification guard: broad name matching really does return both, so
        // without exact-name preference this response would carry the note.
        let broad = graph
            .query_entities(&kin_model::EntityFilter {
                name_pattern: Some("resolve_binary".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(broad.len(), 2, "substring cousin must broad-match");

        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let response = build_impact_response(
            &layout,
            &graph,
            &ImpactRequest {
                entity: "resolve_binary".to_string(),
                depth: 3,
                file: None,
                kind: None,
                signature: None,
                require_unique: false,
            },
        )
        .await
        .unwrap();

        assert_eq!(response.resolution, "resolved");
        assert_eq!(response.query.match_count, 1);
        assert!(
            !response.lines.iter().any(|line| line.contains("Note:")),
            "exact-name query must not carry an ambiguity note: {:?}",
            response.lines
        );
        assert!(response.lines[0].contains("'resolve_binary'"));
    }

    #[tokio::test]
    async fn impact_listing_groups_entities_by_hop_with_locations() {
        let graph = kin_db::InMemoryGraph::new();
        let target = entity_at("changed", "src/lib.rs", 10);
        let direct = entity_at("direct_caller", "src/direct.rs", 20);
        let indirect = entity_at("indirect_caller", "src/indirect.rs", 30);
        for e in [&target, &direct, &indirect] {
            graph.upsert_entity(e).unwrap();
        }
        for (src, dst) in [(&direct, &target), (&indirect, &direct)] {
            graph
                .upsert_relation(&Relation {
                    id: RelationId::from_content(&src.id.to_string(), &dst.id.to_string(), "calls"),
                    kind: RelationKind::Calls,
                    src: GraphNodeId::Entity(src.id),
                    dst: GraphNodeId::Entity(dst.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let response = build_impact_response(
            &layout,
            &graph,
            &ImpactRequest {
                entity: "changed".to_string(),
                depth: 3,
                file: None,
                kind: None,
                signature: None,
                require_unique: false,
            },
        )
        .await
        .unwrap();

        let lines = &response.lines;
        let pos = |needle: &str| {
            lines
                .iter()
                .position(|line| line.contains(needle))
                .unwrap_or_else(|| panic!("missing '{needle}' in {lines:?}"))
        };
        assert!(lines[0].contains("@ src/lib.rs:10"), "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.contains("2 local entities impacted within 3 hops:")),
            "{lines:?}"
        );
        let h1 = pos("1 hop (direct callers):");
        let d = pos("- direct_caller (Function) @ src/direct.rs:20");
        let h2 = pos("2 hops:");
        let i = pos("- indirect_caller (Function) @ src/indirect.rs:30");
        assert!(
            h1 < d && d < h2 && h2 < i,
            "hop groups out of order: {lines:?}"
        );
    }
}
