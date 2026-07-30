// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{EntityFilter, EntityId, EntityStore, GraphNodeId};
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
    let layout = crate::commands::require_repository_layout()?;
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
    // direct callers from the transitive ripple. The walk below records the hop
    // at which each entity is first reached, so the count and every group are
    // read off one traversal of one graph state.
    let local_impacted = downstream_impact_by_hop(graph, &target.id, request.depth)?;
    if local_impacted.is_empty() {
        lines.push("  No local downstream impact found.".to_string());
    } else {
        lines.push(format!(
            "  {} local entities impacted within {} hop{}:",
            local_impacted.len(),
            request.depth,
            if request.depth == 1 { "" } else { "s" }
        ));
        let mut current_hop = 0;
        for (hop, entity) in &local_impacted {
            if *hop != current_hop {
                current_hop = *hop;
                lines.push(if *hop == 1 {
                    "  1 hop (direct callers):".to_string()
                } else {
                    format!("  {hop} hops:")
                });
            }
            let at = entity_location(entity)
                .map(|loc| format!(" @ {loc}"))
                .unwrap_or_default();
            lines.push(format!("    - {} ({:?}){}", entity.name, entity.kind, at));
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

/// One breadth-first walk over inbound entity edges, pairing every reached
/// entity with the hop it was first reached at, in discovery order.
///
/// Breadth-first order reaches a node by a shortest path, so first-reach hop is
/// that entity's minimum distance from the target and the caller can group
/// straight out of this one result. Walking the graph again per hop instead
/// would cost depth times as much and would read a different graph state each
/// time, so a concurrent write between two walks could leave the grouped
/// listing disagreeing with the count printed above it.
///
/// The edge set matches `GraphStore::get_downstream_impact`: entity-to-entity
/// relations pointing at the entity being expanded, with the relation's source
/// as the dependent. `impact_hop_walk_matches_graph_downstream_impact` pins
/// that equivalence.
/// The two graph reads the hop walk performs, named so a test can count them.
trait ImpactWalkGraph {
    /// Entity-to-entity relations that point at `id`.
    fn inbound_relations(&self, id: &EntityId) -> Result<Vec<kin_model::Relation>>;
    fn entity(&self, id: &EntityId) -> Result<Option<kin_model::Entity>>;
}

impl ImpactWalkGraph for kin_db::InMemoryGraph {
    fn inbound_relations(&self, id: &EntityId) -> Result<Vec<kin_model::Relation>> {
        Ok(self
            .get_all_relations_for_entity(id)?
            .into_iter()
            .filter(|relation| relation.dst == GraphNodeId::Entity(*id))
            .collect())
    }

    fn entity(&self, id: &EntityId) -> Result<Option<kin_model::Entity>> {
        Ok(self.get_entity(id)?)
    }
}

fn downstream_impact_by_hop<G: ImpactWalkGraph>(
    graph: &G,
    target: &EntityId,
    depth: u32,
) -> Result<Vec<(u32, kin_model::Entity)>> {
    let mut visited: std::collections::HashSet<EntityId> =
        std::collections::HashSet::from([*target]);
    let mut reached: Vec<(u32, kin_model::Entity)> = Vec::new();
    let mut frontier = vec![*target];

    for hop in 1..=depth {
        let mut next = Vec::new();
        for current in frontier {
            for relation in graph.inbound_relations(&current)? {
                let Some(dependent) = relation.src.as_entity() else {
                    continue;
                };
                if !visited.insert(dependent) {
                    continue;
                }
                // An id carried by a relation whose entity record is missing is
                // still a real step in the walk, so it keeps expanding even
                // though it cannot be listed.
                if let Some(entity) = graph.entity(&dependent)? {
                    reached.push((hop, entity));
                }
                next.push(dependent);
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }

    Ok(reached)
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
        // An external reference target carries the imported symbol's name, so a
        // name query returns it beside the local declaration that shares that
        // name. It is never a subject of impact analysis: this repository holds
        // no definition, no file, and no relations out of it, so nothing can be
        // said about what changing it would reach. Leaving it in the match set
        // inflates the count, and under a structured caller's fail-closed
        // resolution it turns a repository's own `Error` or `Result` into an
        // ambiguous query answered with no analysis at all.
        matches.retain(|entity| !kin_index::is_external_reference_target(entity));
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
    use super::{
        build_impact_response, downstream_impact_by_hop, impact_not_found_guidance, ImpactRequest,
        ImpactResponse, ImpactWalkGraph,
    };
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

    #[test]
    fn impact_hop_walk_matches_graph_downstream_impact() {
        let graph = kin_db::InMemoryGraph::new();
        let target = entity("changed", "src/lib.rs");
        let direct = entity("direct_caller", "src/direct.rs");
        // Reaches the target both directly and through `direct`, so a walk that
        // recorded last-reach rather than first-reach would file it at 2 hops.
        let both_ways = entity("shortcut_caller", "src/shortcut.rs");
        let indirect = entity("indirect_caller", "src/indirect.rs");
        // Sits one hop past the depth cap and must not appear at all.
        let beyond = entity("beyond_depth_caller", "src/beyond.rs");
        // The target's own dependency, reachable only by walking an edge
        // outward. Nothing the target calls is downstream of it, so a walk that
        // followed edges in either direction would pick this up and diverge
        // from the graph's own downstream impact.
        let callee = entity("upstream_callee", "src/callee.rs");
        for e in [&target, &direct, &both_ways, &indirect, &beyond, &callee] {
            graph.upsert_entity(e).unwrap();
        }
        for (src, dst) in [
            (&direct, &target),
            (&both_ways, &target),
            (&both_ways, &direct),
            (&indirect, &direct),
            (&beyond, &indirect),
            (&target, &callee),
        ] {
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

        let depth = 2;
        let walked = downstream_impact_by_hop(&graph, &target.id, depth).unwrap();
        let walked_ids: std::collections::BTreeSet<EntityId> =
            walked.iter().map(|(_, entity)| entity.id).collect();
        let authority_ids: std::collections::BTreeSet<EntityId> = graph
            .get_downstream_impact(&target.id, depth)
            .unwrap()
            .into_iter()
            .map(|entity| entity.id)
            .collect();
        assert_eq!(
            walked_ids, authority_ids,
            "hop walk must reach exactly what the graph's own downstream impact reaches"
        );
        assert!(
            !walked_ids.contains(&beyond.id),
            "depth cap must exclude the entity one hop past it"
        );
        assert!(
            !walked_ids.contains(&callee.id),
            "what the target calls is its dependency, not its downstream impact"
        );

        let hop_of = |id: EntityId| {
            walked
                .iter()
                .find(|(_, entity)| entity.id == id)
                .map(|(hop, _)| *hop)
                .unwrap_or_else(|| panic!("{id} missing from the walk"))
        };
        assert_eq!(hop_of(direct.id), 1);
        assert_eq!(
            hop_of(both_ways.id),
            1,
            "an entity on both a 1-hop and a 2-hop path belongs to the shorter one"
        );
        assert_eq!(hop_of(indirect.id), 2);
        assert!(
            walked.windows(2).all(|pair| pair[0].0 <= pair[1].0),
            "hops must come back in nondecreasing order so the listing can group in one pass"
        );
    }

    /// Counts each graph read so a test can assert the walk's cost.
    struct CountingGraph<'a> {
        inner: &'a kin_db::InMemoryGraph,
        inbound_reads: std::cell::Cell<usize>,
    }

    impl ImpactWalkGraph for CountingGraph<'_> {
        fn inbound_relations(&self, id: &EntityId) -> anyhow::Result<Vec<kin_model::Relation>> {
            self.inbound_reads.set(self.inbound_reads.get() + 1);
            self.inner.inbound_relations(id)
        }

        fn entity(&self, id: &EntityId) -> anyhow::Result<Option<Entity>> {
            self.inner.entity(id)
        }
    }

    fn chain_graph(length: usize) -> (kin_db::InMemoryGraph, Entity) {
        let graph = kin_db::InMemoryGraph::new();
        let entities: Vec<Entity> = (0..length)
            .map(|i| entity(&format!("link_{i}"), &format!("src/link_{i}.rs")))
            .collect();
        for e in &entities {
            graph.upsert_entity(e).unwrap();
        }
        // link_1 calls link_0, link_2 calls link_1, and so on, so link_0 has a
        // chain of dependents exactly `length - 1` hops deep.
        for pair in entities.windows(2) {
            graph
                .upsert_relation(&Relation {
                    id: RelationId::from_content(
                        &pair[1].id.to_string(),
                        &pair[0].id.to_string(),
                        "calls",
                    ),
                    kind: RelationKind::Calls,
                    src: GraphNodeId::Entity(pair[1].id),
                    dst: GraphNodeId::Entity(pair[0].id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }
        let root = entities.into_iter().next().unwrap();
        (graph, root)
    }

    #[test]
    fn impact_walk_reads_each_entity_once_regardless_of_depth() {
        // A chain of four: the target plus three entities that depend on it in
        // sequence.
        let (graph, root) = chain_graph(4);
        let walk_at = |depth: u32| {
            let counted = CountingGraph {
                inner: &graph,
                inbound_reads: std::cell::Cell::new(0),
            };
            let walked = downstream_impact_by_hop(&counted, &root.id, depth).unwrap();
            let ids: Vec<(u32, EntityId)> =
                walked.into_iter().map(|(hop, e)| (hop, e.id)).collect();
            (ids, counted.inbound_reads.get())
        };

        // Each entity is expanded at most once, and entities found at the depth
        // cap are never expanded at all. Three reads covers the whole chain. The
        // shape this replaced ran a complete traversal for each of the three
        // hops instead.
        let (reached, reads) = walk_at(3);
        assert_eq!(reached.len(), 3, "the whole chain is within 3 hops");
        assert_eq!(
            reads, 3,
            "one read per entity expanded, not one traversal per hop"
        );

        // Past the end of the chain the walk expands the last entity once to
        // learn nothing depends on it, then stops. That is the ceiling: raising
        // the cap by an order of magnitude buys no further reads, where the
        // per-hop shape charged for every hop asked for.
        let (deep, deep_reads) = walk_at(32);
        let (deeper, deeper_reads) = walk_at(320);
        assert_eq!(deep_reads, 4, "one read per entity, and the chain has four");
        assert_eq!(
            deep_reads, deeper_reads,
            "cost stops growing once the graph is exhausted"
        );
        assert_eq!(
            reached, deep,
            "a larger depth cap must not change what the walk reports"
        );
        assert_eq!(deep, deeper);
    }

    #[tokio::test]
    async fn impact_listing_lines_are_exact() {
        // Pins the grouped listing verbatim. The rewrite changed how hops are
        // computed and must not have changed a single rendered byte.
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

        assert_eq!(
            response.lines,
            vec![
                "Impact analysis for 'changed' (Function) @ src/lib.rs:10:".to_string(),
                "  2 local entities impacted within 3 hops:".to_string(),
                "  1 hop (direct callers):".to_string(),
                "    - direct_caller (Function) @ src/direct.rs:20".to_string(),
                "  2 hops:".to_string(),
                "    - indirect_caller (Function) @ src/indirect.rs:30".to_string(),
            ]
        );
    }
}
