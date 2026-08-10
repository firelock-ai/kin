// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::EntityStore;
use kin_model::{Entity, EntityFilter, EntityId, EntityKind, TokenBudget};
use serde::{Deserialize, Serialize};

/// Resolve session id from KIN_SESSION_ID env var.
///
/// Optional: returns None if unset/empty (commands behave as if no scope).
fn resolve_session_id_opt() -> Option<String> {
    std::env::var("KIN_SESSION_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

/// If a session id is present, look up its active scope from the daemon and log it.
///
/// Returns the active scope (if any) for downstream observability. The daemon-side
/// consumption of session scope in query handlers is being added in parallel by
/// `daemon-scope-consumer`; until that lands, this surface only logs and does not
/// alter query results.
async fn announce_active_scope(
    layout: &kin_core::KinLayout,
    command: &str,
) -> Result<Option<crate::daemon_client::ScopeResponse>> {
    let Some(session_id) = resolve_session_id_opt() else {
        return Ok(None);
    };
    let Some(daemon_url) = crate::daemon_client::resolve_daemon_url(layout).await? else {
        return Ok(None);
    };
    let client = crate::daemon_client::DaemonClient::from_base_url(daemon_url)?;
    let scope = client.get_scope(&session_id).await?;
    if let Some(ref scope) = scope {
        eprintln!(
            "[kin {}] session={} scope={} (head={}, age={}s)",
            command,
            session_id,
            scope.ref_string,
            &scope.head[..12.min(scope.head.len())],
            scope.created_at_secs_ago
        );
    }
    Ok(scope)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextRequest {
    pub entity: String,
    pub budget: String,
    #[serde(default)]
    pub assistant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextResponse {
    pub lines: Vec<String>,
}

pub async fn run(entity: String, budget: String, assistant: Option<String>) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let _scope = announce_active_scope(&layout, "context").await?;
    let response = run_daemon_context(
        &layout,
        &ContextRequest {
            entity,
            budget,
            assistant,
        },
    )
    .await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_context(
    layout: &kin_core::KinLayout,
    request: &ContextRequest,
) -> Result<ContextResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url =
        daemon_url.ok_or_else(|| crate::daemon_client::daemon_required_error("context", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .context(request)
        .await
        .context("daemon context failed")
}

pub fn build_context_response(
    graph: &kin_db::InMemoryGraph,
    request: &ContextRequest,
) -> Result<ContextResponse> {
    let token_budget = parse_budget(&request.budget)?;

    let assistant_hint =
        request
            .assistant
            .as_deref()
            .and_then(|a| match a.to_lowercase().as_str() {
                "claude" | "claude-code" => Some(kin_context::AssistantHint::ClaudeCode),
                "codex" => Some(kin_context::AssistantHint::Codex),
                "gemini" | "gemini-cli" => Some(kin_context::AssistantHint::GeminiCli),
                _ => None,
            });

    let Some(target) = resolve_context_target(graph, &request.entity)? else {
        return Ok(ContextResponse {
            lines: context_not_found_guidance(&request.entity),
        });
    };
    let opts = kin_context::ContextOptions {
        budget: token_budget,
        max_depth: 2,
        include_tests: true,
        include_contracts: true,
        include_traffic: false,
        assistant_hint,
    };

    let pack = kin_context::build_context_pack(graph, &target.id, &opts)?;

    let mut lines = vec![
        format!("Context pack for '{}' ({:?}):", target.name, target.kind),
        format!(
            "  Budget: {}/{} tokens",
            pack.actual_tokens,
            token_budget.max_tokens()
        ),
        format!("  Focal: {} entries", pack.focal_entities.len()),
        format!(
            "  Dependencies: {} entries",
            pack.dependency_signatures.len()
        ),
        format!("  Transitive: {} entries", pack.transitive_deps.len()),
        format!("  Contracts: {} entries", pack.contracts.len()),
        format!("  Tests: {} entries", pack.tests.len()),
        String::new(),
        "--- Context Pack ---".to_string(),
    ];

    for entry in &pack.focal_entities {
        lines.push(entry.content.clone());
    }
    for entry in &pack.dependency_signatures {
        lines.push(entry.content.clone());
    }
    for entry in &pack.transitive_deps {
        lines.push(entry.content.clone());
    }

    Ok(ContextResponse { lines })
}

fn resolve_context_target(
    graph: &kin_db::InMemoryGraph,
    entity_query: &str,
) -> Result<Option<Entity>> {
    let trimmed = entity_query.trim();
    if let Ok(uuid) = uuid::Uuid::parse_str(trimmed) {
        return Ok(graph.get_entity(&EntityId(uuid))?);
    }

    let filter = EntityFilter {
        name_pattern: Some(trimmed.to_string()),
        ..Default::default()
    };
    // `query_entities` matches names by exact/token/substring and then returns
    // candidates sorted by entity id, so a bare `.next()` would pick an
    // arbitrary match — e.g. `kin context Foo` landing on `Foo.__init__` instead
    // of the class `Foo`. Rank the matches by intent here so the symbol the user
    // typed wins: an exact name beats a partial one, and a type/container
    // declaration beats one of its members.
    Ok(pick_context_target(trimmed, graph.query_entities(&filter)?))
}

/// Choose the entity a `kin context <symbol>` query most likely meant from the
/// name-pattern matches the graph returned.
fn pick_context_target(query: &str, mut candidates: Vec<Entity>) -> Option<Entity> {
    candidates.sort_by(|a, b| {
        name_match_rank(query, a)
            .cmp(&name_match_rank(query, b))
            .then_with(|| kind_rank(a.kind).cmp(&kind_rank(b.kind)))
            // Shorter names are more canonical (`Foo` over `Foo.__init__`).
            .then_with(|| a.name.len().cmp(&b.name.len()))
            // Stable, deterministic final tiebreak.
            .then_with(|| a.id.cmp(&b.id))
    });
    candidates.into_iter().next()
}

/// Lower is a better name match: an exact hit beats a case-insensitive hit,
/// which beats a mere substring/token match.
fn name_match_rank(query: &str, entity: &Entity) -> u8 {
    if entity.name == query {
        0
    } else if entity.name.eq_ignore_ascii_case(query) {
        1
    } else {
        2
    }
}

/// Lower is preferred: a type/container declaration outranks one of its members
/// when both match equally well, so `kin context Foo` resolves to the class
/// rather than `Foo.__init__` or another method.
fn kind_rank(kind: EntityKind) -> u8 {
    match kind {
        EntityKind::Class
        | EntityKind::Interface
        | EntityKind::TraitDef
        | EntityKind::TypeAlias
        | EntityKind::EnumDef
        | EntityKind::Module
        | EntityKind::Package
        | EntityKind::Schema
        | EntityKind::EventContract => 0,
        _ => 1,
    }
}

fn parse_budget(s: &str) -> Result<TokenBudget> {
    match s {
        "8k" => Ok(TokenBudget::Small8k),
        "16k" => Ok(TokenBudget::Medium16k),
        "32k" => Ok(TokenBudget::Large32k),
        _ => {
            let n: usize = s.parse().map_err(|_| {
                anyhow::anyhow!("invalid budget: use '8k', '16k', '32k', or a number")
            })?;
            Ok(TokenBudget::Custom(n))
        }
    }
}

/// Actionable guidance when `kin context <symbol>` can't resolve the symbol in
/// this repo's graph. A context pack is built around a local entity, so a name
/// miss dead-ends; keep the not-found signal and point at discovery commands
/// (`kin search` by name, `kin locate` by description) instead of a bare error.
fn context_not_found_guidance(entity: &str) -> Vec<String> {
    vec![
        format!("Entity '{entity}' not found in this repo's graph."),
        format!(
            "hint: try `kin search {entity}` to find the symbol by name, or `kin locate \"<what it does>\"` to find relevant files."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, Hash256, LanguageId,
        SemanticFingerprint, Visibility,
    };

    #[test]
    fn context_not_found_guidance_keeps_signal_and_offers_discovery() {
        let lines = context_not_found_guidance("frobnicate");
        assert!(
            lines[0].contains("not found"),
            "keeps not-found signal: {lines:?}"
        );
        let joined = lines.join("\n");
        assert!(
            joined.contains("kin search frobnicate"),
            "offers search: {joined}"
        );
        assert!(joined.contains("kin locate"), "offers locate: {joined}");
    }

    fn test_entity(name: &str) -> Entity {
        test_entity_kind(name, EntityKind::Function)
    }

    fn test_entity_kind(name: &str, kind: EntityKind) -> Entity {
        Entity {
            id: EntityId::new(),
            kind,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
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
    fn context_target_accepts_entity_uuid() {
        let graph = kin_db::InMemoryGraph::new();
        let entity = test_entity("checkout");
        let id = entity.id;
        graph.upsert_entity(&entity).unwrap();

        let resolved = resolve_context_target(&graph, &id.to_string()).unwrap();

        assert_eq!(resolved.unwrap().id, id);
    }

    #[test]
    fn context_target_prefers_class_over_constructor_member() {
        // Dogfood wart #10: `kin context Foo` must land on the class, not the
        // `Foo.__init__` constructor that also matches the name pattern. The
        // graph returns both (sorted by id), so resolution has to rank by intent.
        let graph = kin_db::InMemoryGraph::new();
        let class = test_entity_kind("Foo", EntityKind::Class);
        let ctor = test_entity_kind("Foo.__init__", EntityKind::Method);
        let class_id = class.id;
        // Insert the member first so a naive "first match" would pick it.
        graph.upsert_entity(&ctor).unwrap();
        graph.upsert_entity(&class).unwrap();

        let resolved = resolve_context_target(&graph, "Foo").unwrap().unwrap();

        assert_eq!(
            resolved.id, class_id,
            "expected the class, got {}",
            resolved.name
        );
        assert_eq!(resolved.kind, EntityKind::Class);
    }

    #[test]
    fn context_target_exact_name_beats_substring_match() {
        // An exact name must win over a longer name that merely contains the
        // query as a token/substring, regardless of kind.
        let graph = kin_db::InMemoryGraph::new();
        let exact = test_entity_kind("parse", EntityKind::Function);
        let longer = test_entity_kind("parse_config", EntityKind::Function);
        let exact_id = exact.id;
        graph.upsert_entity(&longer).unwrap();
        graph.upsert_entity(&exact).unwrap();

        let resolved = resolve_context_target(&graph, "parse").unwrap().unwrap();

        assert_eq!(
            resolved.id, exact_id,
            "expected exact match, got {}",
            resolved.name
        );
    }
}
